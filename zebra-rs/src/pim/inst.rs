//! PIM-SM instance actor. Owns the raw protocol-103 socket (via
//! spawned read / write tasks), the per-interface table and the
//! neighbor state, and runs the `tokio::select!` event loop over the
//! RIB, config, show and internal message channels.
//!
//! Structure mirrors `crate::nd::inst` with `crate::ospf`'s IPv4
//! socket mechanics. Phase 2 scope: Hello TX/RX, neighbor tracking
//! and DR election — the TIB / Join-Prune engine arrives in later
//! phases (see docs/design/pim-sm-ssm-architecture.md).

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Instant;

use pim_packet::{HelloTlv, IgmpPacket, PimHello, PimPacket, PimPayload};
use socket2::Socket;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::time::sleep_until;

use crate::config::{
    Args, CommandPath, ConfigChannel, ConfigOp, ConfigRequest, DisplayRequest, RibSubscriber,
    ShowChannel, path_from_command, vrf_config_split,
};
use crate::context::{ProtoContext, Task};
use crate::rib::api::RibRx;

use super::af::PimAf;
use super::bsr::{BsrConfig, BsrRun};
use super::config::Callback;
use super::ipv4::Ipv4;
use super::link::{LinkConfig, PIM_OVERRIDE_INTERVAL_MSEC, PIM_PROPAGATION_DELAY_MSEC, PimLink};
use super::mroute::{Mrt4, Upcall};
use super::network::{igmp_read_packet, igmp_write_packet, mroute_read, read_packet, write_packet};
use super::rp::RpSet;
use super::rpf::RpfEntry;
use super::tib::{SgKey, TibEntry};

/// `show pim ...` dispatch handler, mirroring
/// [`crate::nd::inst::ShowCallback`].
pub type ShowCallback<A = Ipv4> = fn(&Pim<A>, Args, bool) -> Result<String, std::fmt::Error>;

/// Internal events: parsed packets from the read task and timer
/// expirations. Every FSM timer is a [`crate::context::Timer`] whose
/// callback sends one of these.
#[derive(Debug)]
pub enum Message<A: PimAf = Ipv4> {
    Recv {
        packet: PimPacket,
        src: A::Addr,
        ifindex: u32,
    },
    Igmp {
        packet: IgmpPacket,
        src: A::Addr,
        ifindex: u32,
    },
    Upcall(Upcall<A>),
    HelloTimer(u32),
    NeighborExpiry(u32, A::Addr),
}

/// Outbound message for the write task: `packet` to `dst`, egress
/// pinned to `ifindex` via `IP_PKTINFO`.
#[derive(Debug)]
pub struct PimSend<A: PimAf = Ipv4> {
    pub packet: PimPacket,
    pub ifindex: u32,
    pub dst: A::Addr,
}

/// Outbound IGMP message (queries) for the IGMP write task.
#[derive(Debug)]
pub struct IgmpSend<A: PimAf = Ipv4> {
    pub packet: IgmpPacket,
    pub ifindex: u32,
    pub dst: A::Addr,
}

pub struct Pim<A: PimAf = Ipv4> {
    pub tx: UnboundedSender<Message<A>>,
    rx: UnboundedReceiver<Message<A>>,
    /// Runtime interface table, keyed by ifindex, built from RibRx
    /// link / address events.
    pub links: BTreeMap<u32, PimLink<A>>,
    /// Desired per-interface config keyed by interface name — the
    /// source of truth the reconciler compares runtime state against.
    pub if_config: BTreeMap<String, LinkConfig>,
    /// The Tree Information Base: (*,G) / (S,G) / (S,G,rpt) state.
    pub tib: BTreeMap<SgKey<A>, TibEntry<A>>,
    /// RPF cache keyed by tracked address (sources and RPs).
    pub rpf: BTreeMap<A::Addr, RpfEntry<A>>,
    /// Static RP mappings.
    pub rp_set: RpSet<A>,
    /// Bootstrap-router config + runtime (RFC 5059).
    pub bsr_config: BsrConfig<A>,
    pub bsr: BsrRun<A>,
    /// Kernel dataplane: mroute socket, VIFs, MFC.
    pub(crate) fp: A::Fp,
    /// Periodic J/P refresh deadlines per (ifindex, upstream nbr).
    pub(crate) jp_refresh: BTreeMap<(u32, A::Addr), std::time::Instant>,
    pub(crate) send_tx: UnboundedSender<PimSend<A>>,
    pub(crate) igmp_send_tx: UnboundedSender<IgmpSend<A>>,
    rib_rx: UnboundedReceiver<RibRx>,
    pub cm: ConfigChannel,
    pub show: ShowChannel,
    pub show_cb: HashMap<String, ShowCallback<A>>,
    pub callbacks: HashMap<String, Callback<A>>,
    pub(crate) sock: Arc<AsyncFd<Socket>>,
    pub(crate) igmp_sock: Arc<AsyncFd<Socket>>,
    /// RIB client context — carries the NHT registrations for RPF.
    pub(crate) ctx: ProtoContext,
    /// `"pim"` for the default instance, `"pim:vrf:<name>"` for a
    /// per-VRF child — namespaces name-keyed RIB registrations.
    pub proto_label: String,
    /// RIB-subscription factory, used by the parent to mint per-VRF
    /// clients; cloned into children.
    pub(crate) rib_subscriber: RibSubscriber,
    /// Sender into the config manager, for (de)registering a child's
    /// `show pim vrf <name>` channel.
    pub(crate) config_tx: mpsc::Sender<crate::config::Message>,
    /// Per-VRF buffered config (parent only), rewritten with the
    /// `vrf <name>` selector stripped; replayed into a child at spawn
    /// and kept so a VrfDel→VrfAdd flap respawns from intent.
    pub(crate) vrf_log: BTreeMap<String, Vec<(Vec<CommandPath>, ConfigOp)>>,
    /// Running per-VRF children (parent only), keyed by VRF name.
    pub(crate) vrf_registry: BTreeMap<String, super::vrf::PimVrfHandle>,
    /// Kernel VRF masters from `RibRx::VrfAdd` (parent only):
    /// name → (table_id, ifindex).
    pub(crate) rib_known_vrfs: BTreeMap<String, (u32, u32)>,
    _read_task: Task<()>,
    _write_task: Task<()>,
    _igmp_read_task: Task<()>,
    _igmp_write_task: Task<()>,
    _mroute_read_task: Task<()>,
}

/// The concrete IPv4 constructor: it wires the IPv4 raw sockets and
/// the `Mrt4` plane and spawns the read/write tasks, so it lives on
/// `Pim<Ipv4>`. Everything else is generic over the address family.
impl Pim<Ipv4> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ctx: ProtoContext,
        sock: AsyncFd<Socket>,
        igmp_sock: AsyncFd<Socket>,
        fp: Mrt4,
        rib_rx: UnboundedReceiver<RibRx>,
        proto_label: String,
        rib_subscriber: RibSubscriber,
        config_tx: mpsc::Sender<crate::config::Message>,
    ) -> Self {
        let sock = Arc::new(sock);
        let igmp_sock = Arc::new(igmp_sock);
        let (tx, rx) = mpsc::unbounded_channel();
        let (send_tx, send_rx) = mpsc::unbounded_channel();
        let (igmp_send_tx, igmp_send_rx) = mpsc::unbounded_channel();

        let read_sock = sock.clone();
        let read_tx = tx.clone();
        let read_task = Task::spawn(async move {
            read_packet(read_sock, read_tx).await;
        });
        let write_sock = sock.clone();
        let write_task = Task::spawn(async move {
            write_packet(write_sock, send_rx).await;
        });
        let igmp_read_sock = igmp_sock.clone();
        let igmp_read_tx = tx.clone();
        let igmp_read_task = Task::spawn(async move {
            igmp_read_packet(igmp_read_sock, igmp_read_tx).await;
        });
        let igmp_write_sock = igmp_sock.clone();
        let igmp_write_task = Task::spawn(async move {
            igmp_write_packet(igmp_write_sock, igmp_send_rx).await;
        });
        let mroute_sock = fp.sock.clone();
        let mroute_tx = tx.clone();
        let mroute_read_task = Task::spawn(async move {
            mroute_read(mroute_sock, mroute_tx).await;
        });

        let mut pim = Self {
            tx,
            rx,
            links: BTreeMap::new(),
            if_config: BTreeMap::new(),
            tib: BTreeMap::new(),
            rpf: BTreeMap::new(),
            rp_set: RpSet::default(),
            bsr_config: BsrConfig::default(),
            bsr: BsrRun::default(),
            fp,
            jp_refresh: BTreeMap::new(),
            send_tx,
            igmp_send_tx,
            rib_rx,
            cm: ConfigChannel::new(),
            show: ShowChannel::new(),
            show_cb: HashMap::new(),
            callbacks: HashMap::new(),
            sock,
            igmp_sock,
            ctx,
            proto_label,
            rib_subscriber,
            config_tx,
            vrf_log: BTreeMap::new(),
            vrf_registry: BTreeMap::new(),
            rib_known_vrfs: BTreeMap::new(),
            _read_task: read_task,
            _write_task: write_task,
            _igmp_read_task: igmp_read_task,
            _igmp_write_task: igmp_write_task,
            _mroute_read_task: mroute_read_task,
        };
        pim.callback_build();
        pim.show_build();
        pim
    }
}

impl<A: PimAf> Pim<A> {
    async fn event_loop(&mut self) {
        // Drain RIB's initial link / address replay up to EoR before
        // serving the other channels, so config callbacks always see
        // the interface table populated.
        while let Some(msg) = self.rib_rx.recv().await {
            if matches!(msg, RibRx::EoR) {
                break;
            }
            self.process_rib_msg(msg);
        }
        loop {
            let wakeup = [
                self.igmp_next_wakeup(),
                self.tib_next_wakeup(),
                self.bsr_next_wakeup(),
            ]
            .into_iter()
            .flatten()
            .min();
            tokio::select! {
                Some(msg) = self.rx.recv() => {
                    self.process_msg(msg);
                }
                Some(msg) = self.rib_rx.recv() => {
                    self.process_rib_msg(msg);
                }
                Some(msg) = self.cm.rx.recv() => {
                    self.process_cm_msg(msg);
                }
                Some(msg) = self.show.rx.recv() => {
                    self.process_show_msg(msg).await;
                }
                _ = sleep_until_opt(wakeup) => {
                    let now = Instant::now();
                    self.igmp_tick(now);
                    self.tib_tick(now);
                    self.bsr_tick(now);
                }
            }
        }
    }

    fn process_msg(&mut self, msg: Message<A>) {
        match msg {
            Message::Recv {
                packet,
                src,
                ifindex,
            } => self.packet_recv(packet, src, ifindex),
            Message::Igmp {
                packet,
                src,
                ifindex,
            } => self.igmp_recv(ifindex, src, packet),
            Message::Upcall(upcall) => self.process_upcall(upcall),
            Message::HelloTimer(ifindex) => self.hello_send(ifindex),
            Message::NeighborExpiry(ifindex, addr) => self.neighbor_expiry(ifindex, addr),
        }
    }

    fn process_rib_msg(&mut self, msg: RibRx) {
        match msg {
            RibRx::LinkAdd(link) => self.link_add(link),
            RibRx::LinkUp(ifindex) => self.link_up_down(ifindex, true),
            RibRx::LinkDown(ifindex) => self.link_up_down(ifindex, false),
            RibRx::LinkDel(ifindex) => self.link_del(ifindex),
            RibRx::AddrAdd(addr) => self.addr_add(addr),
            RibRx::AddrDel(addr) => self.addr_del(addr),
            RibRx::NexthopUpdate { nh, resolution } => {
                self.rpf_nexthop_update(nh, resolution);
                return;
            }
            RibRx::VrfAdd {
                name,
                table_id,
                ifindex,
            } => {
                self.vrf_add(name, table_id, ifindex);
                return;
            }
            RibRx::VrfDel { name } => {
                self.vrf_del(name);
                return;
            }
            _ => return,
        }
        // Any link/address change can flip on-link-ness of tracked
        // sources; re-derive the RPF states.
        self.rpf_recompute_all();
    }

    fn process_cm_msg(&mut self, msg: ConfigRequest) {
        if msg.op == ConfigOp::CommitEnd {
            self.vrf_commit_end();
            return;
        }
        if msg.op == ConfigOp::CommitStart {
            return;
        }
        // `/router/pim/vrf/<name>/…` belongs to a per-VRF child, not
        // this instance: strip the selector, buffer for replay,
        // forward live when the child runs. A child's paths never
        // carry a `vrf` segment, so this is a no-op there.
        if let Some((name, rewritten)) = vrf_config_split("pim", &msg.paths) {
            self.vrf_config_record(name, rewritten, msg.op);
            return;
        }
        let (path, args) = path_from_command(&msg.paths);
        if let Some(f) = self.callbacks.get(&path).copied() {
            f(self, args, msg.op);
        }
    }

    // ---- per-VRF child management (default instance only) ----

    fn vrf_config_record(&mut self, name: String, rewritten: Vec<CommandPath>, op: ConfigOp) {
        if let Some(handle) = self.vrf_registry.get(&name) {
            let _ = handle.cm_tx.send(ConfigRequest::new(rewritten.clone(), op));
        }
        self.vrf_log
            .entry(name.clone())
            .or_default()
            .push((rewritten, op));
        // The kernel VrfAdd may already have arrived before this
        // intent line — spawn from whichever half lands second.
        self.vrf_spawn_if_ready(&name);
    }

    fn vrf_spawn_if_ready(&mut self, name: &str) {
        if self.vrf_registry.contains_key(name) {
            return;
        }
        let Some(&(table_id, _)) = self.rib_known_vrfs.get(name) else {
            return;
        };
        let has_intent = self
            .vrf_log
            .get(name)
            .is_some_and(|log| super::vrf::vrf_log_active(log));
        if !has_intent {
            return;
        }
        let log = self.vrf_log.get(name).cloned().unwrap_or_default();
        if let Some(handle) =
            super::vrf::spawn_pim_vrf(name, table_id, &self.rib_subscriber, &self.config_tx, &log)
        {
            self.vrf_registry.insert(name.to_string(), handle);
        }
    }

    fn vrf_add(&mut self, name: String, table_id: u32, ifindex: u32) {
        if self.proto_label != "pim" {
            return;
        }
        self.rib_known_vrfs
            .insert(name.clone(), (table_id, ifindex));
        self.vrf_spawn_if_ready(&name);
    }

    /// Kernel VRF master removed: despawn the child but KEEP its
    /// config log so a later VrfAdd respawns from intent.
    fn vrf_del(&mut self, name: String) {
        if self.proto_label != "pim" {
            return;
        }
        self.rib_known_vrfs.remove(&name);
        if self.vrf_registry.remove(&name).is_some() {
            super::vrf::despawn_pim_vrf(&name, &self.config_tx, &self.rib_subscriber);
        }
    }

    /// CommitEnd fan-out: tear down children whose `router pim vrf
    /// <name>` block was fully deleted this commit, then forward
    /// CommitEnd to the survivors.
    fn vrf_commit_end(&mut self) {
        let emptied: Vec<String> = self
            .vrf_log
            .iter()
            .filter(|(_, log)| !super::vrf::vrf_log_active(log))
            .map(|(name, _)| name.clone())
            .collect();
        for name in emptied {
            self.vrf_log.remove(&name);
            if self.vrf_registry.remove(&name).is_some() {
                super::vrf::despawn_pim_vrf(&name, &self.config_tx, &self.rib_subscriber);
            }
        }
        for handle in self.vrf_registry.values() {
            let _ = handle
                .cm_tx
                .send(ConfigRequest::new(Vec::new(), ConfigOp::CommitEnd));
        }
    }

    async fn process_show_msg(&self, msg: DisplayRequest) {
        let (path, args) = path_from_command(&msg.paths);
        if let Some(f) = self.show_cb.get(&path) {
            let output = match f(self, args, msg.json) {
                Ok(result) => result,
                Err(e) => format!("Error formatting output: {}", e),
            };
            let _ = msg.resp.send(output).await;
        }
    }

    fn packet_recv(&mut self, packet: PimPacket, src: A::Addr, ifindex: u32) {
        match &packet.payload {
            PimPayload::Hello(hello) => self.hello_recv(ifindex, src, hello),
            PimPayload::JoinPrune(jp) => self.jp_recv(ifindex, src, jp),
            PimPayload::Register(register) => self.register_recv(src, register),
            PimPayload::RegisterStop(stop) => self.register_stop_recv(stop),
            PimPayload::Assert(assert) => self.assert_recv(ifindex, src, assert),
            PimPayload::Bootstrap(bsm) => self.bootstrap_recv(ifindex, src, bsm),
            PimPayload::CandRpAdv(adv) => self.cand_rp_adv_recv(src, adv),
            other => {
                tracing::debug!(
                    "pim: ignoring {} from {} on ifindex {} (not implemented)",
                    packet.typ,
                    src,
                    ifindex
                );
                let _ = other;
            }
        }
    }

    fn hello_packet(&self, link: &PimLink<A>, config: &LinkConfig, holdtime: u16) -> PimPacket {
        let mut tlvs = vec![
            HelloTlv::Holdtime(holdtime),
            HelloTlv::LanPruneDelay {
                t_bit: false,
                propagation_delay: PIM_PROPAGATION_DELAY_MSEC,
                override_interval: PIM_OVERRIDE_INTERVAL_MSEC,
            },
            HelloTlv::DrPriority(config.dr_priority()),
            HelloTlv::GenerationId(link.gen_id),
        ];
        // Address List (RFC 7761 §4.3.4): advertise our non-primary
        // addresses on the link so a neighbor can match an RPF
        // nexthop that resolves to one of them. The primary (hello
        // source) is implicit and omitted.
        let secondary: Vec<pim_packet::EncodedUnicast> = link
            .addrs
            .iter()
            .skip(1)
            .map(|p| pim_packet::EncodedUnicast::new(A::to_ip(A::prefix_addr(p))))
            .collect();
        if !secondary.is_empty() {
            tlvs.push(HelloTlv::AddressList(secondary));
        }
        PimPacket::new(PimPayload::Hello(PimHello { tlvs }))
    }

    pub(crate) fn hello_send(&mut self, ifindex: u32) {
        let Some(link) = self.links.get(&ifindex) else {
            return;
        };
        if !link.enabled {
            return;
        }
        let config = self.link_config(&link.name);
        if config.passive() {
            return;
        }
        let packet = self.hello_packet(link, &config, config.holdtime());
        let _ = self.send_tx.send(PimSend {
            packet,
            ifindex,
            dst: A::ALL_PIM_ROUTERS,
        });
    }

    /// Goodbye hello: holdtime 0 tells neighbors to expire us
    /// immediately (sent on interface disable).
    pub(crate) fn hello_send_holdtime_zero(&mut self, ifindex: u32) {
        let Some(link) = self.links.get(&ifindex) else {
            return;
        };
        if !link.enabled {
            return;
        }
        let config = self.link_config(&link.name);
        if config.passive() {
            return;
        }
        let packet = self.hello_packet(link, &config, 0);
        let _ = self.send_tx.send(PimSend {
            packet,
            ifindex,
            dst: A::ALL_PIM_ROUTERS,
        });
    }
}

pub fn serve<A: PimAf>(mut pim: Pim<A>) -> Task<()> {
    Task::spawn(async move {
        pim.event_loop().await;
    })
}

/// Sleep until `when`, or forever when there is no deadline — parks
/// the select arm without waking (same helper as `crate::nd::inst`).
async fn sleep_until_opt(when: Option<Instant>) {
    match when {
        Some(t) => sleep_until(t.into()).await,
        None => std::future::pending::<()>().await,
    }
}
