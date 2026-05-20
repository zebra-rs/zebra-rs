use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::sync::Arc;

use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use crate::config::{ConfigChannel, ConfigRequest, path_from_command};
use crate::context::{ProtoContext, Task};

use super::config::{BfdConfig, Callback};
use super::fsm::Event;
use super::network::{WriteRequest, read_packet, write_packet};
use super::session::{Session, SessionKey, SessionParams, SessionTable, StateChange};
use super::socket::{BFD_SINGLE_HOP_PORT, bfd_socket_ipv4};
use super::timer::{InitialParams, TimerCmd, session_timer};

/// Identifier for a BFD subscriber. Conventionally the proto name
/// ("bgp", "ospf", "isis", "static"), plus an optional disambiguator
/// when one process registers more than one logical client per
/// session (rare in Phase 1).
pub type ClientId = String;

/// Top-level BFD instance. Owns the IPv4 single-hop UDP socket, the
/// session table, the committed YANG config mirror, a per-session
/// timer handle map, and the client-subscription registry. Read and
/// write tasks are tokio-spawned at construction and feed the event
/// loop via `main_tx` / `write_tx`. The config-manager subscription
/// drains through `cm.rx`, and external clients (BGP / OSPF / IS-IS
/// / static) submit subscribe/unsubscribe requests through
/// `client_req.rx`.
pub struct Bfd {
    pub rx: UnboundedReceiver<Message>,
    pub sessions: SessionTable,
    /// Local address the recv socket was bound to. Useful to tests
    /// that bind to ephemeral ports — `local_addr.port()` reveals the
    /// kernel-chosen value so the peer can be told where to send.
    pub local_addr: SocketAddrV4,
    /// In-memory mirror of `container bfd` from the committed config.
    /// Populated by per-leaf callbacks registered in
    /// [`Bfd::callback_build`].
    pub config: BfdConfig,
    /// Callback table — path → handler — used by [`Self::process_cm_msg`].
    pub callbacks: HashMap<String, Callback>,
    /// Config-manager subscription endpoints (the receive half drains
    /// in the event loop).
    pub cm: ConfigChannel,
    /// Inbound client request channel — protocol modules send
    /// `ClientReq::Subscribe` / `Unsubscribe` here to attach to BFD
    /// sessions. Clones of the sender half are distributed via
    /// `client_req.tx.clone()` (cf. [`Self::client_req_tx`]).
    pub client_req: ClientReqChannel,
    /// Per-session subscriber registry. The hot demux path uses this
    /// to fan state-change events out to every interested client.
    /// Empty for a session means no client is waiting — the session
    /// is torn down as soon as the last subscriber leaves
    /// ([`Self::unsubscribe`]).
    subscribers: HashMap<SessionKey, BTreeMap<ClientId, UnboundedSender<BfdEvent>>>,
    main_tx: UnboundedSender<Message>,
    write_tx: UnboundedSender<WriteRequest>,
    timer_handles: HashMap<SessionKey, TimerHandle>,
}

/// Sender/receiver pair for the inbound client-request channel.
/// Modelled on [`crate::config::ConfigChannel`] so cloning the sender
/// for distribution to other protocols is the obvious idiom.
#[derive(Debug)]
pub struct ClientReqChannel {
    pub tx: UnboundedSender<ClientReq>,
    pub rx: UnboundedReceiver<ClientReq>,
}

impl ClientReqChannel {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self { tx, rx }
    }
}

impl Default for ClientReqChannel {
    fn default() -> Self {
        Self::new()
    }
}

/// Requests sent to the BFD instance by external clients (BGP / OSPF
/// / IS-IS / static) that want to attach to a BFD session.
#[derive(Debug)]
pub enum ClientReq {
    /// Register interest in `key`. If no session yet exists for that
    /// key, BFD creates one using `params`; otherwise `params` is
    /// ignored and the existing session is reused. State-change
    /// events for the session are forwarded to `notifier` until the
    /// matching [`ClientReq::Unsubscribe`] arrives.
    Subscribe {
        client: ClientId,
        key: SessionKey,
        params: SessionParams,
        notifier: UnboundedSender<BfdEvent>,
    },
    /// Drop `client`'s interest in `key`. When the last subscriber
    /// unsubscribes, BFD tears the session down.
    Unsubscribe { client: ClientId, key: SessionKey },
}

/// Holds the per-session timer task and its command channel. Dropping
/// the `Task` aborts the timer loop; the `cmd_tx` is used to update
/// intervals, reset the detection timer, and request graceful
/// shutdown.
struct TimerHandle {
    cmd_tx: UnboundedSender<TimerCmd>,
    _task: Task<()>,
}

#[derive(Debug)]
pub enum Message {
    /// A parsed, GTSM-validated control packet arrived.
    Recv {
        packet: bfd_packet::ControlPacket,
        src: SocketAddrV4,
        dst: Option<IpAddr>,
        ifindex: u32,
    },
    /// Periodic transmission timer fired for `key`.
    TxTick { key: SessionKey },
    /// Detection timer fired for `key`.
    DetectExpired { key: SessionKey },
}

/// Lifecycle events emitted by the instance for clients (tests today,
/// protocol modules like BGP / OSPF in later PRs) to observe.
#[derive(Debug, Clone, Copy)]
pub enum BfdEvent {
    StateChange {
        key: SessionKey,
        change: StateChange,
    },
}

impl Bfd {
    /// Production constructor — binds to `0.0.0.0:3784`.
    pub fn new(ctx: ProtoContext) -> std::io::Result<Self> {
        Self::new_with(
            ctx,
            SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, BFD_SINGLE_HOP_PORT),
        )
    }

    /// Explicit constructor that lets the caller pick the bind
    /// address (used by the integration test to run two instances on
    /// loopback ephemeral ports). Client event notifications go
    /// through the [`Self::client_req`] channel — see
    /// [`Self::client_req_tx`] for the standard distribution path.
    pub fn new_with(ctx: ProtoContext, bind: SocketAddrV4) -> std::io::Result<Self> {
        let sock = bfd_socket_ipv4(&ctx, bind)?;
        let local_addr = sock
            .local_addr()?
            .as_socket_ipv4()
            .ok_or_else(|| std::io::Error::other("bound socket has no IPv4 local address"))?;
        let sock = Arc::new(AsyncFd::new(sock)?);

        let (main_tx, rx) = mpsc::unbounded_channel::<Message>();
        let (write_tx, write_rx) = mpsc::unbounded_channel::<WriteRequest>();

        let read_sock = sock.clone();
        let read_tx = main_tx.clone();
        tokio::spawn(async move {
            read_packet(read_sock, read_tx).await;
        });

        let write_sock = sock.clone();
        tokio::spawn(async move {
            write_packet(write_sock, write_rx).await;
        });

        let mut bfd = Self {
            rx,
            sessions: SessionTable::new(),
            local_addr,
            config: BfdConfig::default(),
            callbacks: HashMap::new(),
            cm: ConfigChannel::new(),
            client_req: ClientReqChannel::new(),
            subscribers: HashMap::new(),
            main_tx,
            write_tx,
            timer_handles: HashMap::new(),
        };
        bfd.callback_build();
        Ok(bfd)
    }

    /// Clone the inbound client-request sender. Distribute this to
    /// other protocols (BGP / OSPF / IS-IS / static) so they can
    /// submit [`ClientReq::Subscribe`] / [`ClientReq::Unsubscribe`]
    /// after both BFD and the caller have been served.
    pub fn client_req_tx(&self) -> UnboundedSender<ClientReq> {
        self.client_req.tx.clone()
    }

    /// Apply a [`ClientReq`]. Public so pre-`serve` callers (notably
    /// the integration test) can drive the API directly without going
    /// through the channel; production callers go through
    /// `client_req_tx`.
    pub fn process_client_req(&mut self, req: ClientReq) {
        match req {
            ClientReq::Subscribe {
                client,
                key,
                params,
                notifier,
            } => self.subscribe(client, key, params, notifier),
            ClientReq::Unsubscribe { client, key } => self.unsubscribe(&client, &key),
        }
    }

    /// Add `client` as a subscriber on `key`. Creates the underlying
    /// session if it does not yet exist (otherwise `params` is
    /// ignored and the existing session is reused). If the session is
    /// already Up, the new subscriber is informed via an immediate
    /// synthetic [`BfdEvent::StateChange`].
    pub fn subscribe(
        &mut self,
        client: ClientId,
        key: SessionKey,
        params: SessionParams,
        notifier: UnboundedSender<BfdEvent>,
    ) {
        // Lazy create the session on the first subscriber. Subsequent
        // subscribers reuse the existing session — their `params` are
        // ignored on the assumption that the BFD config is the
        // authoritative source of truth.
        if self.sessions.get_by_key(&key).is_none() {
            self.add_session(key, params);
        }
        // Mirror the current state to the new subscriber so it can
        // act on already-Up sessions without waiting for the next
        // transition.
        if let Some(session) = self.sessions.get_by_key(&key) {
            let _ = notifier.send(BfdEvent::StateChange {
                key,
                change: StateChange {
                    from: session.local_state,
                    to: session.local_state,
                    diag: session.local_diag,
                },
            });
        }
        self.subscribers
            .entry(key)
            .or_default()
            .insert(client, notifier);
    }

    /// Drop `client`'s subscription on `key`. Tears down the
    /// underlying session if this was the last subscriber.
    pub fn unsubscribe(&mut self, client: &str, key: &SessionKey) {
        let now_empty = if let Some(subs) = self.subscribers.get_mut(key) {
            subs.remove(client);
            subs.is_empty()
        } else {
            return;
        };
        if now_empty {
            self.subscribers.remove(key);
            self.remove_session(key);
        }
    }

    /// Dispatch a single committed config request through the
    /// per-leaf callback table.
    pub fn process_cm_msg(&mut self, msg: ConfigRequest) {
        let (path, args) = path_from_command(&msg.paths);
        if let Some(f) = self.callbacks.get(&path).copied() {
            f(self, args, msg.op);
        }
    }

    /// Insert a new session and spawn its timer task. Returns the
    /// locally-assigned, non-zero, collision-free discriminator.
    pub fn add_session(&mut self, key: SessionKey, params: SessionParams) -> u32 {
        let disc = self.sessions.insert(key, params);

        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let initial = InitialParams {
            // No peer reply yet → start TX at our desired interval;
            // the negotiated value lands on the first Rx.
            tx_interval_us: params.desired_min_tx_us,
            // No peer reply yet → detection timer is not armed.
            detection_time_us: 0,
            detect_mult: params.detect_mult,
        };
        let main_tx = self.main_tx.clone();
        let task = Task::spawn(session_timer(key, initial, cmd_rx, main_tx));
        self.timer_handles.insert(
            key,
            TimerHandle {
                cmd_tx,
                _task: task,
            },
        );

        disc
    }

    /// Remove a session and shut down its timer task. Returns the
    /// removed session, if any.
    pub fn remove_session(&mut self, key: &SessionKey) -> Option<Session> {
        if let Some(h) = self.timer_handles.remove(key) {
            let _ = h.cmd_tx.send(TimerCmd::Shutdown);
        }
        self.sessions.remove(key)
    }

    pub async fn event_loop(&mut self) {
        loop {
            tokio::select! {
                Some(msg) = self.rx.recv() => match msg {
                    Message::Recv { packet, src, dst, ifindex } =>
                        self.on_recv(packet, src, dst, ifindex),
                    Message::TxTick { key } => self.on_tx_tick(key),
                    Message::DetectExpired { key } => self.on_detect_expired(key),
                },
                Some(msg) = self.cm.rx.recv() => {
                    self.process_cm_msg(msg);
                }
                Some(req) = self.client_req.rx.recv() => {
                    self.process_client_req(req);
                }
            }
        }
    }

    fn on_recv(
        &mut self,
        packet: bfd_packet::ControlPacket,
        src: SocketAddrV4,
        dst: Option<IpAddr>,
        ifindex: u32,
    ) {
        let lookup = if packet.your_disc != 0 {
            self.sessions.get_by_disc(packet.your_disc).map(|s| s.key)
        } else {
            self.bootstrap_lookup(src, ifindex)
        };
        let Some(key) = lookup else {
            tracing::debug!(
                ?src,
                ?dst,
                ifindex,
                your_disc = format_args!("{:#010x}", packet.your_disc),
                "bfd: no session matches received packet",
            );
            return;
        };

        let (change, new_tx_us, new_detect_us, new_detect_mult) = {
            let session = self
                .sessions
                .get_by_key_mut(&key)
                .expect("just looked up by key");
            let change = session.handle_packet(&packet);
            (
                change,
                session.tx_interval_us(),
                session.detection_time_us(),
                session.detect_mult,
            )
        };

        // Every valid Rx must reset the detection timer (RFC 5880
        // §6.8.4). When intervals are also negotiated freshly, the
        // Update command implicitly does the reset as part of arming.
        if let Some(h) = self.timer_handles.get(&key) {
            let _ = h.cmd_tx.send(TimerCmd::Update {
                tx_interval_us: new_tx_us,
                detection_time_us: new_detect_us,
                detect_mult: new_detect_mult,
            });
        }

        if let Some(change) = change {
            self.notify_state_change(key, change);
        }
    }

    /// Find an existing session that matches an incoming packet whose
    /// `Your Discriminator` is zero (RFC 5880 §6.8.6 bootstrap path).
    /// Linear scan — fine for the small session counts a single
    /// process maintains; an explicit (local, remote, ifindex) index
    /// can be added later if it shows up in profiles.
    fn bootstrap_lookup(&self, src: SocketAddrV4, ifindex: u32) -> Option<SessionKey> {
        let src_ip = IpAddr::V4(*src.ip());
        self.sessions.iter().find_map(|(_, s)| {
            let ifindex_match = s.key.ifindex == 0 || s.key.ifindex == ifindex;
            if s.key.remote == src_ip && ifindex_match {
                Some(s.key)
            } else {
                None
            }
        })
    }

    fn on_tx_tick(&self, key: SessionKey) {
        let Some(session) = self.sessions.get_by_key(&key) else {
            return;
        };
        let IpAddr::V4(remote) = session.key.remote else {
            // PR 7 adds IPv6.
            return;
        };
        let dst = SocketAddrV4::new(remote, session.dst_port);
        let ifindex = (session.key.ifindex != 0).then_some(session.key.ifindex);
        let _ = self.write_tx.send(WriteRequest {
            packet: session.build_packet(),
            dst,
            ifindex,
        });
    }

    fn on_detect_expired(&mut self, key: SessionKey) {
        let Some(session) = self.sessions.get_by_key_mut(&key) else {
            return;
        };
        let change = session.handle_event(Event::DetectExpired);
        if let Some(change) = change {
            self.notify_state_change(key, change);
        }
    }

    fn notify_state_change(&self, key: SessionKey, change: StateChange) {
        tracing::info!(
            ?key,
            from = %change.from,
            to = %change.to,
            diag = %change.diag,
            "bfd: session state change",
        );
        if let Some(subs) = self.subscribers.get(&key) {
            for tx in subs.values() {
                let _ = tx.send(BfdEvent::StateChange { key, change });
            }
        }
    }
}

/// Spawn the event loop. Mirrors [`crate::ospf::serve`]. The returned
/// [`Task`] handle owns the spawned future; dropping it aborts the
/// loop (see [`crate::config::bfd::despawn_bfd`]).
pub fn serve(mut bfd: Bfd) -> Task<()> {
    Task::spawn(async move {
        bfd.event_loop().await;
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_bfd() -> Bfd {
        Bfd::new_with(
            ProtoContext::default_table_no_rib(),
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
        )
        .expect("bind loopback")
    }

    fn loopback_key(remote_octet: u8) -> SessionKey {
        SessionKey {
            local: IpAddr::V4(Ipv4Addr::LOCALHOST),
            remote: IpAddr::V4(Ipv4Addr::new(127, 0, 0, remote_octet)),
            ifindex: 0,
            multihop: false,
        }
    }

    /// Single-client subscribe creates the underlying session and
    /// fires an immediate StateChange (Down→Down) so the client can
    /// observe the starting state without waiting for a transition.
    #[tokio::test]
    async fn subscribe_creates_session_and_notifies() {
        let mut bfd = fresh_bfd();
        let key = loopback_key(2);
        let (tx, mut rx) = mpsc::unbounded_channel();

        bfd.subscribe("test".into(), key, SessionParams::default(), tx);
        assert!(bfd.sessions.get_by_key(&key).is_some());

        let event = rx.try_recv().expect("immediate state event");
        let BfdEvent::StateChange { change, .. } = event;
        assert_eq!(change.from, bfd_packet::State::Down);
        assert_eq!(change.to, bfd_packet::State::Down);
    }

    /// Two clients on the same key share one session; neither
    /// observes an extra session creation.
    #[tokio::test]
    async fn two_clients_share_one_session() {
        let mut bfd = fresh_bfd();
        let key = loopback_key(3);

        let (tx_a, _rx_a) = mpsc::unbounded_channel();
        let (tx_b, _rx_b) = mpsc::unbounded_channel();
        bfd.subscribe("bgp".into(), key, SessionParams::default(), tx_a);
        bfd.subscribe("ospf".into(), key, SessionParams::default(), tx_b);

        assert_eq!(bfd.sessions.len(), 1, "subscribers share one session");
        assert_eq!(
            bfd.subscribers
                .get(&key)
                .map(BTreeMap::len)
                .unwrap_or_default(),
            2,
        );
    }

    /// Both subscribers observe a synthetic state-change notification
    /// when the FSM transitions — exercises the broadcast path.
    #[tokio::test]
    async fn broadcast_reaches_every_subscriber() {
        let mut bfd = fresh_bfd();
        let key = loopback_key(4);
        let (tx_a, mut rx_a) = mpsc::unbounded_channel();
        let (tx_b, mut rx_b) = mpsc::unbounded_channel();

        bfd.subscribe("a".into(), key, SessionParams::default(), tx_a);
        bfd.subscribe("b".into(), key, SessionParams::default(), tx_b);

        // Drain the initial Down→Down event from both subscribers.
        let _ = rx_a.recv().await;
        let _ = rx_b.recv().await;

        // Synthesize a transition by feeding handle_event directly.
        let change = bfd
            .sessions
            .get_by_key_mut(&key)
            .unwrap()
            .handle_event(super::super::fsm::Event::Rx {
                remote_state: bfd_packet::State::Down,
            })
            .expect("Down + Rx Down → Init");
        bfd.notify_state_change(key, change);

        let got_a = rx_a.recv().await.expect("a sees Init");
        let got_b = rx_b.recv().await.expect("b sees Init");
        let BfdEvent::StateChange { change: a, .. } = got_a;
        let BfdEvent::StateChange { change: b, .. } = got_b;
        assert_eq!(a.to, bfd_packet::State::Init);
        assert_eq!(b.to, bfd_packet::State::Init);
    }

    /// Unsubscribing one of two clients leaves the session up so the
    /// remaining client keeps receiving events.
    #[tokio::test]
    async fn unsubscribe_one_keeps_session() {
        let mut bfd = fresh_bfd();
        let key = loopback_key(5);

        let (tx_a, _rx_a) = mpsc::unbounded_channel();
        let (tx_b, _rx_b) = mpsc::unbounded_channel();
        bfd.subscribe("a".into(), key, SessionParams::default(), tx_a);
        bfd.subscribe("b".into(), key, SessionParams::default(), tx_b);

        bfd.unsubscribe("a", &key);
        assert!(
            bfd.sessions.get_by_key(&key).is_some(),
            "session must survive while b is still subscribed",
        );
        assert_eq!(
            bfd.subscribers.get(&key).map(BTreeMap::len),
            Some(1),
            "only b remains",
        );
    }

    /// Unsubscribing the last subscriber tears the session down and
    /// removes the per-key subscribers entry.
    #[tokio::test]
    async fn unsubscribe_last_tears_down_session() {
        let mut bfd = fresh_bfd();
        let key = loopback_key(6);

        let (tx, _rx) = mpsc::unbounded_channel();
        bfd.subscribe("solo".into(), key, SessionParams::default(), tx);
        assert!(bfd.sessions.get_by_key(&key).is_some());

        bfd.unsubscribe("solo", &key);
        assert!(bfd.sessions.get_by_key(&key).is_none());
        assert!(!bfd.subscribers.contains_key(&key));
    }

    /// process_client_req dispatches Subscribe / Unsubscribe so
    /// channel-based callers (BGP / OSPF / IS-IS in later PRs)
    /// see the same behaviour as the direct method.
    #[tokio::test]
    async fn process_client_req_dispatches() {
        let mut bfd = fresh_bfd();
        let key = loopback_key(7);
        let (tx, _rx) = mpsc::unbounded_channel();

        bfd.process_client_req(ClientReq::Subscribe {
            client: "x".into(),
            key,
            params: SessionParams::default(),
            notifier: tx,
        });
        assert!(bfd.sessions.get_by_key(&key).is_some());

        bfd.process_client_req(ClientReq::Unsubscribe {
            client: "x".into(),
            key,
        });
        assert!(bfd.sessions.get_by_key(&key).is_none());
    }
}
