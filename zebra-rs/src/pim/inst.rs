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

use pim_packet::{HelloTlv, PimHello, PimPacket, PimPayload};
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
use super::gm::igmp::IgmpCodec;
use super::gm::mld::MldCodec;
use super::gm::{Gm, GmEvent, GmIfCtx, GmInput};
use super::ipv4::Ipv4;
use super::ipv6::Ipv6;
use super::link::{LinkConfig, PIM_OVERRIDE_INTERVAL_MSEC, PIM_PROPAGATION_DELAY_MSEC, PimLink};
use super::mroute::{Mrt4, Mrt6, Upcall};
use super::network::{mroute_read, read_packet, write_packet};
use super::network_v6::{mroute_read_v6, read_packet_v6, write_packet_v6};
use super::rp::RpSet;
use super::rpf::RpfEntry;
use super::tib::{SgKey, TibEntry};
use super::tracing::{PimTracing, TraceCategory};
use crate::pim_trace;

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
    /// Normalized group-membership input from the [`Gm`] codec's read
    /// task (IGMP today; MLD in Phase 4).
    Membership {
        ifindex: u32,
        src: A::Addr,
        input: GmInput<A>,
    },
    Upcall(Upcall<A>),
    HelloTimer(u32),
    NeighborExpiry(u32, A::Addr),
}

/// Outbound message for the write task: `packet` to `dst`, egress
/// pinned to `ifindex` via `IP_PKTINFO` (v4) / `in6_pktinfo` (v6).
/// `src` is the pinned source, required by the IPv6 pseudo-header
/// checksum; the IPv4 write task ignores it (the kernel selects the
/// source and the v4 checksum has no pseudo-header).
#[derive(Debug)]
pub struct PimSend<A: PimAf = Ipv4> {
    pub packet: PimPacket,
    pub ifindex: u32,
    pub dst: A::Addr,
    pub src: Option<A::Addr>,
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
    /// Group-membership engine (IGMP / MLD) with its own transport.
    /// `None` for a family with no membership protocol yet (an IPv6
    /// instance before Phase 4).
    pub(crate) gm: Option<Gm<A>>,
    rib_rx: UnboundedReceiver<RibRx>,
    pub cm: ConfigChannel,
    pub show: ShowChannel,
    pub show_cb: HashMap<String, ShowCallback<A>>,
    pub callbacks: HashMap<String, Callback<A>>,
    pub(crate) sock: Arc<AsyncFd<Socket>>,
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
    /// The default-table IPv6 child (parent only): spawned on the first
    /// `router pim ipv6 …` line, fed the `ipv6`-stripped config, and the
    /// forwarding target for `show pim ipv6 …`.
    pub(crate) af6: Option<super::af6::PimAf6Handle>,
    /// Buffered `router pim ipv6 …` intent, so the child can be despawned
    /// when its block is fully deleted (mirrors `vrf_log`).
    pub(crate) af6_log: Vec<(Vec<CommandPath>, ConfigOp)>,
    /// Conditional-tracing toggles (`router pim tracing`). The default
    /// instance's block is written by config and the same lines are
    /// forwarded live to any running IPv6 / per-VRF child.
    pub(crate) tracing: PimTracing,
    _read_task: Task<()>,
    _write_task: Task<()>,
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
        let (tx, rx) = mpsc::unbounded_channel();
        let (send_tx, send_rx) = mpsc::unbounded_channel();

        let read_sock = sock.clone();
        let read_tx = tx.clone();
        let read_task = Task::spawn(async move {
            read_packet(read_sock, read_tx).await;
        });
        let write_sock = sock.clone();
        let write_task = Task::spawn(async move {
            write_packet(write_sock, send_rx).await;
        });
        // The IGMP membership engine owns its socket, read/write tasks
        // and wire codec; the engine's read task feeds `Message::Membership`.
        let gm = Gm::new(Box::new(IgmpCodec::new(igmp_sock, tx.clone())));
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
            gm: Some(gm),
            rib_rx,
            cm: ConfigChannel::new(),
            show: ShowChannel::new(),
            show_cb: HashMap::new(),
            callbacks: HashMap::new(),
            sock,
            ctx,
            proto_label,
            rib_subscriber,
            config_tx,
            vrf_log: BTreeMap::new(),
            vrf_registry: BTreeMap::new(),
            rib_known_vrfs: BTreeMap::new(),
            af6: None,
            af6_log: Vec::new(),
            tracing: PimTracing::default(),
            _read_task: read_task,
            _write_task: write_task,
            _mroute_read_task: mroute_read_task,
        };
        pim.callback_build();
        pim.show_build();
        pim
    }
}

/// The concrete IPv6 constructor. Wires the PIMv6 raw socket + the
/// `Mrt6` stub, the v6 read/write tasks, and the MLD membership engine
/// (`Gm<Ipv6>` driven by the `MldCodec`). No mroute read task yet (the
/// `Mrt6` datapath is Phase 5).
impl Pim<Ipv6> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ctx: ProtoContext,
        sock: AsyncFd<Socket>,
        mld_sock: AsyncFd<Socket>,
        fp: Mrt6,
        rib_rx: UnboundedReceiver<RibRx>,
        proto_label: String,
        rib_subscriber: RibSubscriber,
        config_tx: mpsc::Sender<crate::config::Message>,
    ) -> Self {
        let sock = Arc::new(sock);
        let (tx, rx) = mpsc::unbounded_channel();
        let (send_tx, send_rx) = mpsc::unbounded_channel();

        let read_sock = sock.clone();
        let read_tx = tx.clone();
        let read_task = Task::spawn(async move {
            read_packet_v6(read_sock, read_tx).await;
        });
        let write_sock = sock.clone();
        let write_task = Task::spawn(async move {
            write_packet_v6(write_sock, send_rx).await;
        });
        // MLD membership engine over its own ICMPv6 socket.
        let gm = Gm::new(Box::new(MldCodec::new(mld_sock, tx.clone())));
        // MRT6 upcalls (NOCACHE / WHOLEPKT / …) drive the same typed FSM.
        let mroute_sock = fp.sock.clone();
        let mroute_tx = tx.clone();
        let mroute_read_task = Task::spawn(async move {
            mroute_read_v6(mroute_sock, mroute_tx).await;
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
            gm: Some(gm),
            rib_rx,
            cm: ConfigChannel::new(),
            show: ShowChannel::new(),
            show_cb: HashMap::new(),
            callbacks: HashMap::new(),
            sock,
            ctx,
            proto_label,
            rib_subscriber,
            config_tx,
            vrf_log: BTreeMap::new(),
            vrf_registry: BTreeMap::new(),
            rib_known_vrfs: BTreeMap::new(),
            af6: None,
            af6_log: Vec::new(),
            tracing: PimTracing::default(),
            _read_task: read_task,
            _write_task: write_task,
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
                self.gm.as_ref().and_then(|g| g.next_wakeup()),
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
                    self.gm_tick(now);
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
            Message::Membership {
                ifindex,
                src,
                input,
            } => self.membership_recv(ifindex, src, input),
            Message::Upcall(upcall) => self.process_upcall(upcall),
            Message::HelloTimer(ifindex) => self.hello_send(ifindex),
            Message::NeighborExpiry(ifindex, addr) => self.neighbor_expiry(ifindex, addr),
        }
    }

    // ---- group-membership (Gm) engine bridge ----

    /// Per-interface context the membership engine needs from the actor.
    pub(crate) fn gm_if_ctx(&self, ifindex: u32) -> Option<GmIfCtx<A>> {
        let link = self.links.get(&ifindex)?;
        Some(GmIfCtx {
            name: link.name.clone(),
            config: self.link_config(&link.name).igmp,
            is_dr: self.i_am_dr(ifindex),
            my_addr: link.primary_addr(),
            trace: self.tracing.should_trace(TraceCategory::Membership),
        })
    }

    /// Apply the engine's TIB-bridge events (only the DR emits any).
    pub(crate) fn apply_gm_events(&mut self, events: Vec<GmEvent<A>>) {
        for ev in events {
            match ev {
                GmEvent::Join { ifindex, key } => self.tib_local_join(key, ifindex),
                GmEvent::Prune { ifindex, key } => self.tib_local_prune(key, ifindex),
            }
        }
    }

    /// Drive the membership engine's timers.
    fn gm_tick(&mut self, now: Instant) {
        let Some(gm) = self.gm.as_ref() else {
            return;
        };
        let ctx: BTreeMap<u32, GmIfCtx<A>> = gm
            .ifindexes()
            .into_iter()
            .filter_map(|i| self.gm_if_ctx(i).map(|c| (i, c)))
            .collect();
        let events = self.gm.as_mut().unwrap().tick(now, &ctx);
        self.apply_gm_events(events);
    }

    /// Feed a received membership message to the engine, ignoring our
    /// own reports and interfaces where membership is not running.
    fn membership_recv(&mut self, ifindex: u32, src: A::Addr, input: GmInput<A>) {
        let Some(link) = self.links.get(&ifindex) else {
            return;
        };
        if !link.enabled || link.is_my_addr(&src) {
            return;
        }
        let Some(ctx) = self.gm_if_ctx(ifindex) else {
            return;
        };
        let Some(gm) = self.gm.as_mut() else {
            return;
        };
        let events = gm.recv(ifindex, src, input, &ctx);
        self.apply_gm_events(events);
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
            self.af6_commit_end();
            return;
        }
        if msg.op == ConfigOp::CommitStart {
            return;
        }
        // `/router/pim/ipv6/…` belongs to the default-table IPv6 child:
        // strip the `ipv6` container and forward. A child's paths never
        // carry an `ipv6` segment (already stripped), so this is a no-op
        // there.
        if let Some(rewritten) = af6_split(&msg.paths) {
            self.af6_config_record(rewritten, msg.op);
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
        } else if path.starts_with("/router/pim/tracing") {
            // Not in the callback table — the category names are YANG
            // presence leaves, so a single subtree dispatcher parses the
            // path tail (mirrors IS-IS's `config_tracing_dispatch`).
            super::tracing::config_tracing_dispatch(self, &path, msg.op);
            // Forward the same line to any running IPv6 / per-VRF child so
            // `router pim tracing` covers every PIM instance, not just the
            // default table. (Children have no children of their own, so
            // this does not recurse.)
            self.tracing_forward_children(&msg.paths, msg.op);
        }
    }

    /// Forward a `/router/pim/tracing/…` line to every running child
    /// (default-table IPv6 and per-VRF), so a single `router pim tracing`
    /// block drives all PIM instances. Live only — a child spawned after
    /// the line was applied starts with tracing off until the next change.
    fn tracing_forward_children(&self, paths: &[CommandPath], op: ConfigOp) {
        if let Some(handle) = &self.af6 {
            let _ = handle.cm_tx.send(ConfigRequest::new(paths.to_vec(), op));
        }
        for handle in self.vrf_registry.values() {
            let _ = handle.cm_tx.send(ConfigRequest::new(paths.to_vec(), op));
        }
    }

    // ---- default-table IPv6 child management (default instance only) ----

    fn af6_config_record(&mut self, rewritten: Vec<CommandPath>, op: ConfigOp) {
        self.af6_spawn_if_ready();
        if let Some(handle) = &self.af6 {
            let _ = handle.cm_tx.send(ConfigRequest::new(rewritten.clone(), op));
        }
        self.af6_log.push((rewritten, op));
    }

    /// Spawn the IPv6 child on first intent. The default multicast table
    /// always exists, so — unlike a VRF child — there is no kernel-event
    /// gating.
    fn af6_spawn_if_ready(&mut self) {
        if self.proto_label != "pim" || self.af6.is_some() {
            return;
        }
        self.af6 = super::af6::spawn_pim_v6(
            &self.rib_subscriber,
            &self.config_tx,
            self.tracing.should_trace(TraceCategory::Event),
        );
    }

    /// CommitEnd: despawn the IPv6 child if its `router pim ipv6` block
    /// was fully deleted this commit, else forward CommitEnd so it
    /// reconciles.
    fn af6_commit_end(&mut self) {
        if self.proto_label != "pim" {
            return;
        }
        if !super::vrf::vrf_log_active(&self.af6_log) {
            self.af6_log.clear();
            if self.af6.take().is_some() {
                self.rib_subscriber
                    .send_proto_cleanup(&super::af6::af6_proto_label());
                pim_trace!(
                    self.tracing,
                    Event,
                    "pim6: default-table IPv6 instance despawned"
                );
            }
            return;
        }
        if let Some(handle) = &self.af6 {
            let _ = handle
                .cm_tx
                .send(ConfigRequest::new(Vec::new(), ConfigOp::CommitEnd));
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
        if let Some(handle) = super::vrf::spawn_pim_vrf(
            name,
            table_id,
            &self.rib_subscriber,
            &self.config_tx,
            &log,
            self.tracing.should_trace(TraceCategory::Event),
        ) {
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
            super::vrf::despawn_pim_vrf(
                &name,
                &self.config_tx,
                &self.rib_subscriber,
                self.tracing.should_trace(TraceCategory::Event),
            );
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
                super::vrf::despawn_pim_vrf(
                    &name,
                    &self.config_tx,
                    &self.rib_subscriber,
                    self.tracing.should_trace(TraceCategory::Event),
                );
            }
        }
        for handle in self.vrf_registry.values() {
            let _ = handle
                .cm_tx
                .send(ConfigRequest::new(Vec::new(), ConfigOp::CommitEnd));
        }
    }

    async fn process_show_msg(&self, msg: DisplayRequest) {
        // `show pim ipv6 …` → forward to the default-table IPv6 child
        // with the `ipv6` container stripped and the response sender
        // passed through, so the child answers the caller directly.
        if let Some(rewritten) = af6_split(&msg.paths) {
            if let Some(handle) = &self.af6 {
                let _ = handle.show_tx.send(DisplayRequest {
                    paths: rewritten,
                    json: msg.json,
                    resp: msg.resp,
                });
            }
            return;
        }
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
            src: link.primary_addr(),
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
            src: link.primary_addr(),
        });
    }
}

/// Split a `router pim ipv6 …` / `show pim ipv6 …` path into the line
/// with the `ipv6` container removed, so the default-table IPv6 child
/// sees a plain `…/pim/…` line. `None` when the path is not under
/// `pim ipv6`. Anchored to `pim` (position 1) so another protocol's
/// `ipv6` subtree is never captured.
fn af6_split(paths: &[CommandPath]) -> Option<Vec<CommandPath>> {
    if paths.len() < 3 || paths[1].name != "pim" || paths[2].name != "ipv6" {
        return None;
    }
    let mut rewritten = Vec::with_capacity(paths.len() - 1);
    rewritten.extend_from_slice(&paths[..2]);
    rewritten.extend_from_slice(&paths[3..]);
    Some(rewritten)
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
