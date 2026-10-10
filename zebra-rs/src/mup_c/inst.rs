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
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use crate::context::{ProtoContext, Task};

use super::assoc::{AssocTable, MupAssocInfo};
use super::session::{MupSession, SessionTable};

/// PFCP default port (3GPP TS 29.244 §4.2.2).
pub const PFCP_PORT: u16 = 8805;

/// How long a PFCP listener that could not be bound waits before the next
/// attempt (see [`MupC::retry_bind`]).
pub(super) const BIND_RETRY_INTERVAL: Duration = Duration::from_secs(1);

/// Controller config, staged from `router bgp afi-safi mup
/// mup-c { … }` by the BGP config callbacks and applied at `CommitEnd`.
#[derive(Debug, Clone, Default)]
pub struct MupCConfig {
    /// Master switch: spawns / tears down the controller task.
    pub enable: bool,
    /// IPv6 next-hop stamped on originated ST routes (route phase).
    pub controller_address: Option<Ipv6Addr>,
    /// Core (N6) UPF endpoint used as the Type-2 ST route endpoint when a
    /// learned session carries no core-side GTP tunnel (the N6-breakout case).
    /// A session that learns a core F-TEID over PFCP keeps that in preference.
    pub upf_address: Option<IpAddr>,
    /// Core (N6/N9) GTP-U TEID paired with [`Self::upf_address`], used as the
    /// ST2 route TEID when the session carries no learned core-side F-TEID.
    /// When neither is set (or the configured TEID is 0), MUP-U acts as the
    /// anchor UPF and self-allocates its own core receive F-TEID, so an ST2
    /// still originates (a real UPF owns the TEIDs of the tunnels it
    /// terminates).
    pub upf_teid: Option<u32>,
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
/// [`MupCEvent`]. Renders `show bgp mup-c [session |
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
    /// The bind retry timer fired.
    RetryBind,
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
    /// The listen address whose bind is failing, while it is retried.
    pub(super) bind_failing: Option<SocketAddr>,
    /// The one-shot [`Message::RetryBind`] timer, while armed.
    pub(super) bind_retry: Option<Task<()>>,
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
            bind_failing: None,
            bind_retry: None,
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
                    Message::RetryBind => self.retry_bind().await,
                },
                Some(MupCCtl::Reconfig(cfg)) = self.ctl_rx.recv() => self.reconfig(cfg).await,
                else => break,
            }
        }
    }

    /// A new config: rebind the listener if its address or port changed.
    pub(super) async fn reconfig(&mut self, cfg: MupCConfig) {
        let rebind = cfg.listen_socket_addr() != self.config.listen_socket_addr();
        self.config = cfg;
        if rebind {
            self.bind().await;
        }
    }

    /// Arm the one-shot [`Message::RetryBind`] timer unless one is already
    /// running. Dropping the handle (a successful bind, or the controller's
    /// teardown) aborts it.
    pub(super) fn arm_bind_retry(&mut self) {
        if self.bind_retry.is_some() {
            return;
        }
        let tx = self.main_tx.clone();
        self.bind_retry = Some(Task::spawn(async move {
            tokio::time::sleep(BIND_RETRY_INTERVAL).await;
            let _ = tx.send(Message::RetryBind);
        }));
    }

    /// [`Message::RetryBind`]: try the bind again, unless a reconfig has
    /// bound the listener since the timer fired.
    pub(super) async fn retry_bind(&mut self) {
        self.bind_retry = None;
        if self.sock.is_none() {
            self.bind().await;
        }
    }
}

#[cfg(test)]
mod bind_retry_tests {
    use super::*;

    /// TEST-NET-1 (RFC 5737): on no host interface, so binding it fails
    /// with EADDRNOTAVAIL, as a listen address does when it is committed
    /// before its interface has it.
    fn unusable() -> MupCConfig {
        MupCConfig {
            listen_address: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
            port: Some(0),
            ..Default::default()
        }
    }

    fn usable() -> MupCConfig {
        MupCConfig {
            listen_address: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            port: Some(0),
            ..Default::default()
        }
    }

    /// The next listener state reported to BGP, if any.
    fn reported(rx: &mut mpsc::Receiver<crate::bgp::inst::Message>) -> Option<Option<SocketAddr>> {
        match rx.try_recv() {
            Ok(crate::bgp::inst::Message::MupC(MupCEvent::Listener { bound })) => Some(bound),
            Ok(_) => panic!("unexpected message to BGP"),
            Err(_) => None,
        }
    }

    /// A failed bind is reported once and retried while it keeps failing;
    /// a usable address then binds, is reported, and ends the retries.
    #[tokio::test]
    async fn a_failed_bind_is_retried_until_the_listener_is_up() {
        let (mut mupc, mut bgp_rx) = MupC::new_for_test(unusable());
        mupc.bind().await;
        assert!(mupc.sock.is_none());
        assert!(mupc.bind_retry.is_some(), "retry armed");
        assert_eq!(reported(&mut bgp_rx), Some(None), "reported down");

        // The tick finds the address still unusable: still down, the
        // timer armed again, nothing reported again.
        mupc.retry_bind().await;
        assert!(mupc.sock.is_none());
        assert!(mupc.bind_retry.is_some(), "retry armed again");
        assert_eq!(reported(&mut bgp_rx), None);

        mupc.reconfig(usable()).await;
        let bound = mupc.listen_addr.expect("bound");
        assert_eq!(bound.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert!(mupc.bind_retry.is_none(), "retries stopped");
        assert_eq!(mupc.bind_failing, None);
        assert_eq!(reported(&mut bgp_rx), Some(Some(bound)));

        // A tick that fired before the bind does not bind again.
        let sock = mupc.sock.clone().expect("listener");
        mupc.retry_bind().await;
        assert!(Arc::ptr_eq(&sock, mupc.sock.as_ref().expect("listener")));
        assert_eq!(reported(&mut bgp_rx), None);
    }

    /// The armed timer delivers the retry after the interval. The clock
    /// is paused, so it moves only to the next deadline: the timer's, or
    /// the bound on the wait if no timer was armed.
    #[tokio::test(start_paused = true)]
    async fn the_retry_fires_after_the_interval() {
        let (mut mupc, _bgp_rx) = MupC::new_for_test(unusable());
        let start = tokio::time::Instant::now();
        mupc.bind().await;
        let msg = tokio::time::timeout(2 * BIND_RETRY_INTERVAL, mupc.rx.recv()).await;
        assert!(matches!(msg, Ok(Some(Message::RetryBind))), "no retry");
        assert_eq!(start.elapsed(), BIND_RETRY_INTERVAL);
    }

    /// A rebind that fails drops the listener on the old address, which
    /// would otherwise keep serving PFCP while `show` reports it down.
    #[tokio::test]
    async fn a_failed_rebind_drops_the_old_listener() {
        let (mut mupc, mut bgp_rx) = MupC::new_for_test(usable());
        mupc.bind().await;
        assert!(matches!(reported(&mut bgp_rx), Some(Some(_))));

        mupc.reconfig(unusable()).await;
        assert!(mupc.sock.is_none());
        assert!(mupc.recv_task.is_none());
        assert_eq!(mupc.listen_addr, None);
        assert_eq!(reported(&mut bgp_rx), Some(None));
        assert!(mupc.bind_retry.is_some(), "retry armed");
    }
}
