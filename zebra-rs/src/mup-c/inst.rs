//! MUP controller task: state, BGP-facing types, spawn + event loop.
//!
//! See the [module docs](super) for the architecture. This file owns the
//! [`MupC`] task struct, the config staged from BGP ([`MupCConfig`]), the
//! neutral events reported back to BGP ([`MupCEvent`]) and the read-only
//! snapshot BGP renders from ([`MupCView`]). The PFCP socket and message
//! handling live in [`super::pfcp`].

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use crate::context::{ProtoContext, Task};

use super::assoc::{AssocTable, MupAssocInfo};
use super::session::{MupSession, SessionTable};

/// PFCP default port (3GPP TS 29.244 §4.2.2).
pub const PFCP_PORT: u16 = 8805;

/// Controller config, staged from `router bgp afi-safi mup
/// mup-c { … }` by the BGP config callbacks and applied at `CommitEnd`.
#[derive(Debug, Clone, Default)]
pub struct MupCConfig {
    /// Master switch: spawns / tears down the controller task.
    pub enable: bool,
    /// IPv6 next-hop stamped on originated ST routes (route phase).
    pub controller_address: Option<Ipv6Addr>,
    /// Our PFCP Node ID, used in responses. Falls back to the bind
    /// address / `controller_address` when unset.
    pub node_id: Option<IpAddr>,
    /// PFCP listen address (default `::`).
    pub listen_address: Option<IpAddr>,
    /// PFCP listen port (default 8805).
    pub port: Option<u16>,
    /// SRv6 locator name SIDs are drawn from (route phase).
    pub locator: Option<String>,
    /// Mobile architecture (e.g. `3gpp-5g`); informational for now.
    pub architecture: Option<String>,
}

impl MupCConfig {
    /// The effective PFCP bind address (defaults `[::]:8805`).
    pub fn listen_socket_addr(&self) -> SocketAddr {
        let ip = self
            .listen_address
            .unwrap_or(IpAddr::V6(Ipv6Addr::UNSPECIFIED));
        SocketAddr::new(ip, self.port.unwrap_or(PFCP_PORT))
    }
}

/// Neutral session/association events the controller reports to BGP over
/// the handed-in channel. BGP records them in [`MupCView`] (this slice)
/// and originates / withdraws MUP routes from them (route phase).
#[derive(Debug, Clone)]
pub enum MupCEvent {
    /// PFCP listener (re)bound (`Some`) or down (`None`).
    Listener { bound: Option<SocketAddr> },
    /// Association established with a CP peer.
    AssocUp { peer: SocketAddr, node_id: String },
    /// Association released / lost; its sessions are withdrawn too.
    AssocDown { peer: SocketAddr },
    /// Session created or modified.
    SessionUp(MupSession),
    /// Session deleted.
    SessionDown { seid: u64 },
}

/// Read-only controller snapshot held by the BGP task, fed by
/// [`MupCEvent`]. Renders `show bgp mup mup-c [session |
/// association]`.
#[derive(Debug, Default)]
pub struct MupCView {
    /// The bound PFCP listener address, or `None` while down.
    pub listen: Option<SocketAddr>,
    /// Active associations keyed by CP peer transport address.
    pub associations: BTreeMap<SocketAddr, MupAssocInfo>,
    /// Learned sessions keyed by local SEID.
    pub sessions: BTreeMap<u64, MupSession>,
}

impl MupCView {
    /// Fold one reported event into the snapshot.
    pub fn apply(&mut self, ev: MupCEvent) {
        match ev {
            MupCEvent::Listener { bound } => self.listen = bound,
            MupCEvent::AssocUp { peer, node_id } => {
                self.associations.insert(peer, MupAssocInfo { node_id });
            }
            MupCEvent::AssocDown { peer } => {
                self.associations.remove(&peer);
                self.sessions.retain(|_, s| s.peer != peer);
            }
            MupCEvent::SessionUp(session) => {
                self.sessions.insert(session.seid, session);
            }
            MupCEvent::SessionDown { seid } => {
                self.sessions.remove(&seid);
            }
        }
    }
}

/// BGP → controller control messages. Teardown is by dropping the
/// [`MupCHandle`] (which aborts the task), so the only control message is
/// reconfigure.
#[derive(Debug)]
pub enum MupCCtl {
    /// Config changed while the controller is running: rebind the
    /// listener to the new address/port.
    Reconfig(MupCConfig),
}

/// Handle the BGP task holds for a running controller. Dropping `task`
/// aborts the controller (the VRF-handle idiom); `ctl_tx` pushes
/// reconfigure / shutdown.
#[derive(Debug)]
pub struct MupCHandle {
    pub ctl_tx: UnboundedSender<MupCCtl>,
    // Held only for its `Drop` (aborts the spawned task on teardown);
    // never read. Mirrors how `BgpVrfHandle` keeps its `Task`.
    #[allow(dead_code)]
    task: Task<()>,
}

impl MupCHandle {
    /// Push a new config to the running controller.
    pub fn reconfig(&self, config: MupCConfig) {
        let _ = self.ctl_tx.send(MupCCtl::Reconfig(config));
    }
}

/// Internal controller events (fed by the PFCP recv task).
#[derive(Debug)]
pub enum Message {
    /// A datagram arrived on the PFCP socket.
    PfcpRecv { data: Vec<u8>, src: SocketAddr },
}

/// The controller task state.
pub struct MupC {
    pub(super) config: MupCConfig,
    /// Channel into the BGP task — the same `tx` BGP feeds its own loop.
    pub(super) bgp_tx: mpsc::Sender<crate::bgp::inst::Message>,
    /// Spawn-time runtime context (socket factory + VRF binding).
    pub(super) ctx: ProtoContext,
    /// BGP → controller control channel.
    ctl_rx: UnboundedReceiver<MupCCtl>,
    /// Self events from the PFCP recv task.
    rx: UnboundedReceiver<Message>,
    /// Cloned for each (re)spawned recv task.
    pub(super) main_tx: UnboundedSender<Message>,
    pub(super) sessions: SessionTable,
    pub(super) assoc: AssocTable,
    /// Bound PFCP socket; `None` until the first successful bind.
    pub(super) sock: Option<Arc<UdpSocket>>,
    /// Recv task; replaced (aborting the old) on every rebind.
    pub(super) recv_task: Option<Task<()>>,
    /// Last successfully bound local address.
    pub(super) listen_addr: Option<SocketAddr>,
    /// PFCP Recovery Time Stamp — the instant this controller started.
    /// **Fixed for the controller's lifetime**: per 3GPP TS 29.244 §19.5
    /// the recovery timestamp signals when the node last (re)started, so a
    /// CP peer treats *any* change as a UP restart and tears down every
    /// session (PFCP restoration). Set once here and echoed in every
    /// Heartbeat / Association Setup response; it survives listener
    /// rebinds (a reconfig is not a restart).
    pub(super) recovery_ts: std::time::SystemTime,
}

/// Spawn the controller. Mirrors `spawn_bgp_vrf`: takes the global BGP
/// channel by value. The socket bind happens inside the task (it is
/// async; the BGP-side caller is sync).
pub fn spawn(
    config: MupCConfig,
    bgp_tx: mpsc::Sender<crate::bgp::inst::Message>,
    ctx: ProtoContext,
) -> MupCHandle {
    let (ctl_tx, ctl_rx) = mpsc::unbounded_channel();
    let task = Task::spawn(async move {
        let mut mupc = MupC::new(config, bgp_tx, ctx, ctl_rx);
        mupc.bind().await;
        mupc.event_loop().await;
    });
    MupCHandle { ctl_tx, task }
}

impl MupC {
    fn new(
        config: MupCConfig,
        bgp_tx: mpsc::Sender<crate::bgp::inst::Message>,
        ctx: ProtoContext,
        ctl_rx: UnboundedReceiver<MupCCtl>,
    ) -> Self {
        let (main_tx, rx) = mpsc::unbounded_channel();
        Self {
            config,
            bgp_tx,
            ctx,
            ctl_rx,
            rx,
            main_tx,
            sessions: SessionTable::new(),
            assoc: AssocTable::new(),
            sock: None,
            recv_task: None,
            listen_addr: None,
            recovery_ts: std::time::SystemTime::now(),
        }
    }

    /// Test-only constructor: builds a controller with a dummy BGP
    /// channel and a parked RIB context, so the synchronous PFCP handlers
    /// can be exercised without spawning the task or binding a socket.
    /// Returns the BGP receiver too (kept alive by the caller so a stray
    /// `report` doesn't see a closed channel).
    #[cfg(test)]
    pub(super) fn new_for_test(
        config: MupCConfig,
    ) -> (Self, mpsc::Receiver<crate::bgp::inst::Message>) {
        let (bgp_tx, bgp_rx) = mpsc::channel(64);
        let (_ctl_tx, ctl_rx) = mpsc::unbounded_channel();
        let ctx = ProtoContext::default_table_no_rib();
        (Self::new(config, bgp_tx, ctx, ctl_rx), bgp_rx)
    }

    /// Report an event to the BGP task. Best-effort: if BGP's bounded
    /// channel is gone the controller is about to be torn down anyway.
    pub(super) async fn report(&self, ev: MupCEvent) {
        if self
            .bgp_tx
            .send(crate::bgp::inst::Message::MupC(ev))
            .await
            .is_err()
        {
            tracing::warn!("mup-c: BGP channel closed; dropping event");
        }
    }

    /// Our local address for the PFCP **Node ID / F-SEID** node address in
    /// responses: configured `node-id`, else the bound (non-unspecified)
    /// listen IP, else loopback.
    ///
    /// This is the N4 identity — the address the CP dialed and keys its
    /// session context by — so it must be the listen address, **never**
    /// the SRv6/BGP `controller-address` next-hop (a different plane). A CP
    /// that can't correlate the response Node ID to the UPF it knows fails
    /// the session: free5GC dereferences a nil PFCP context and crashes
    /// (`datapath.go` `PFCPContext[NodeIDtoIP]` with no existence check).
    pub(super) fn local_ip(&self) -> IpAddr {
        self.config
            .node_id
            .or_else(|| {
                self.listen_addr
                    .map(|a| a.ip())
                    .filter(|ip| !ip.is_unspecified())
            })
            .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
    }

    async fn event_loop(&mut self) {
        loop {
            tokio::select! {
                Some(msg) = self.rx.recv() => match msg {
                    Message::PfcpRecv { data, src } => self.handle_pfcp(&data, src).await,
                },
                Some(MupCCtl::Reconfig(cfg)) = self.ctl_rx.recv() => {
                    let rebind = cfg.listen_socket_addr() != self.config.listen_socket_addr();
                    self.config = cfg;
                    if rebind {
                        self.bind().await;
                    }
                }
                else => break,
            }
        }
    }
}
