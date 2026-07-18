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

use pim_packet::{HelloTlv, PimHello, PimPacket, PimPayload};
use socket2::Socket;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use crate::config::{
    Args, ConfigChannel, ConfigRequest, DisplayRequest, ShowChannel, path_from_command,
};
use crate::context::{ProtoContext, Task};
use crate::rib::api::RibRx;

use super::config::Callback;
use super::link::{LinkConfig, PIM_OVERRIDE_INTERVAL_MSEC, PIM_PROPAGATION_DELAY_MSEC, PimLink};
use super::network::{read_packet, write_packet};
use super::socket::ALL_PIM_ROUTERS;

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

pub struct Pim {
    pub tx: UnboundedSender<Message>,
    rx: UnboundedReceiver<Message>,
    /// Runtime interface table, keyed by ifindex, built from RibRx
    /// link / address events.
    pub links: BTreeMap<u32, PimLink>,
    /// Desired per-interface config keyed by interface name — the
    /// source of truth the reconciler compares runtime state against.
    pub if_config: BTreeMap<String, LinkConfig>,
    pub(crate) send_tx: UnboundedSender<PimSend>,
    rib_rx: UnboundedReceiver<RibRx>,
    pub cm: ConfigChannel,
    pub show: ShowChannel,
    pub show_cb: HashMap<String, ShowCallback>,
    pub callbacks: HashMap<String, Callback>,
    pub(crate) sock: Arc<AsyncFd<Socket>>,
    /// RIB client context — unused until the RPF/NHT phase, kept so
    /// the spawn contract already matches the other protocols.
    #[allow(dead_code)]
    ctx: ProtoContext,
    _read_task: Task<()>,
    _write_task: Task<()>,
}

impl Pim {
    pub fn new(ctx: ProtoContext, sock: AsyncFd<Socket>, rib_rx: UnboundedReceiver<RibRx>) -> Self {
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

        let mut pim = Self {
            tx,
            rx,
            links: BTreeMap::new(),
            if_config: BTreeMap::new(),
            send_tx,
            rib_rx,
            cm: ConfigChannel::new(),
            show: ShowChannel::new(),
            show_cb: HashMap::new(),
            callbacks: HashMap::new(),
            sock,
            ctx,
            _read_task: read_task,
            _write_task: write_task,
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
            _ => {}
        }
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
            other => {
                // Join/Prune, Assert, Register handling arrives with
                // the TIB phases.
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
