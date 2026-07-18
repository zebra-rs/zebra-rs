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
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Instant;

use pim_packet::{HelloTlv, IgmpPacket, PimHello, PimPacket, PimPayload};
use socket2::Socket;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::time::sleep_until;

use crate::config::{
    Args, ConfigChannel, ConfigRequest, DisplayRequest, ShowChannel, path_from_command,
};
use crate::context::{ProtoContext, Task};
use crate::rib::api::RibRx;

use super::config::Callback;
use super::link::{LinkConfig, PIM_OVERRIDE_INTERVAL_MSEC, PIM_PROPAGATION_DELAY_MSEC, PimLink};
use super::mroute::{ForwardingPlane, Upcall};
use super::network::{igmp_read_packet, igmp_write_packet, mroute_read, read_packet, write_packet};
use super::rpf::RpfEntry;
use super::socket::ALL_PIM_ROUTERS;
use super::tib::{Sg, TibEntry};

/// `show pim ...` dispatch handler, mirroring
/// [`crate::nd::inst::ShowCallback`].
pub type ShowCallback = fn(&Pim, Args, bool) -> Result<String, std::fmt::Error>;

/// Internal events: parsed packets from the read task and timer
/// expirations. Every FSM timer is a [`crate::context::Timer`] whose
/// callback sends one of these.
#[derive(Debug)]
pub enum Message {
    Recv {
        packet: PimPacket,
        src: Ipv4Addr,
        ifindex: u32,
    },
    Igmp {
        packet: IgmpPacket,
        src: Ipv4Addr,
        ifindex: u32,
    },
    Upcall(Upcall),
    HelloTimer(u32),
    NeighborExpiry(u32, Ipv4Addr),
}

/// Outbound message for the write task: `packet` to `dst`, egress
/// pinned to `ifindex` via `IP_PKTINFO`.
#[derive(Debug)]
pub struct PimSend {
    pub packet: PimPacket,
    pub ifindex: u32,
    pub dst: Ipv4Addr,
}

/// Outbound IGMP message (queries) for the IGMP write task.
#[derive(Debug)]
pub struct IgmpSend {
    pub packet: IgmpPacket,
    pub ifindex: u32,
    pub dst: Ipv4Addr,
}

pub struct Pim {
    pub tx: UnboundedSender<Message>,
    rx: UnboundedReceiver<Message>,
    /// Runtime interface table, keyed by ifindex, built from RibRx
    /// link / address events.
    pub links: BTreeMap<u32, PimLink>,
    /// Desired per-interface config keyed by interface name — the
    /// source of truth the reconciler compares runtime state against.
    pub if_config: BTreeMap<String, LinkConfig>,
    /// The Tree Information Base: (S,G) forwarding state.
    pub tib: BTreeMap<Sg, TibEntry>,
    /// RPF cache keyed by source address (NHT-backed).
    pub rpf: BTreeMap<Ipv4Addr, RpfEntry>,
    /// Kernel dataplane: mroute socket, VIFs, MFC.
    pub(crate) fp: ForwardingPlane,
    /// Periodic J/P refresh deadlines per (ifindex, upstream nbr).
    pub(crate) jp_refresh: BTreeMap<(u32, Ipv4Addr), std::time::Instant>,
    pub(crate) send_tx: UnboundedSender<PimSend>,
    pub(crate) igmp_send_tx: UnboundedSender<IgmpSend>,
    rib_rx: UnboundedReceiver<RibRx>,
    pub cm: ConfigChannel,
    pub show: ShowChannel,
    pub show_cb: HashMap<String, ShowCallback>,
    pub callbacks: HashMap<String, Callback>,
    pub(crate) sock: Arc<AsyncFd<Socket>>,
    pub(crate) igmp_sock: Arc<AsyncFd<Socket>>,
    /// RIB client context — carries the NHT registrations for RPF.
    pub(crate) ctx: ProtoContext,
    _read_task: Task<()>,
    _write_task: Task<()>,
    _igmp_read_task: Task<()>,
    _igmp_write_task: Task<()>,
    _mroute_read_task: Task<()>,
}

impl Pim {
    pub fn new(
        ctx: ProtoContext,
        sock: AsyncFd<Socket>,
        igmp_sock: AsyncFd<Socket>,
        fp: ForwardingPlane,
        rib_rx: UnboundedReceiver<RibRx>,
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
            let wakeup = match (self.igmp_next_wakeup(), self.tib_next_wakeup()) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
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
                }
            }
        }
    }

    fn process_msg(&mut self, msg: Message) {
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
            _ => return,
        }
        // Any link/address change can flip on-link-ness of tracked
        // sources; re-derive the RPF states.
        self.rpf_recompute_all();
    }

    fn process_cm_msg(&mut self, msg: ConfigRequest) {
        let (path, args) = path_from_command(&msg.paths);
        if let Some(f) = self.callbacks.get(&path).copied() {
            f(self, args, msg.op);
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

    fn packet_recv(&mut self, packet: PimPacket, src: Ipv4Addr, ifindex: u32) {
        match &packet.payload {
            PimPayload::Hello(hello) => self.hello_recv(ifindex, src, hello),
            PimPayload::JoinPrune(jp) => self.jp_recv(ifindex, src, jp),
            other => {
                // Assert / Register handling arrives with later
                // phases.
                tracing::debug!(
                    "pim: ignoring {} from {} on ifindex {} (not yet implemented)",
                    packet.typ,
                    src,
                    ifindex
                );
                let _ = other;
            }
        }
    }

    fn hello_packet(&self, link: &PimLink, config: &LinkConfig, holdtime: u16) -> PimPacket {
        let hello = PimHello {
            tlvs: vec![
                HelloTlv::Holdtime(holdtime),
                HelloTlv::LanPruneDelay {
                    t_bit: false,
                    propagation_delay: PIM_PROPAGATION_DELAY_MSEC,
                    override_interval: PIM_OVERRIDE_INTERVAL_MSEC,
                },
                HelloTlv::DrPriority(config.dr_priority()),
                HelloTlv::GenerationId(link.gen_id),
            ],
        };
        PimPacket::new(PimPayload::Hello(hello))
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
            dst: ALL_PIM_ROUTERS,
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
            dst: ALL_PIM_ROUTERS,
        });
    }
}

pub fn serve(mut pim: Pim) -> Task<()> {
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
