use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;

use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use crate::config::{
    Args, ConfigChannel, ConfigRequest, DisplayRequest, ShowChannel, path_from_command,
};
use crate::context::{ProtoContext, Task};

use super::config::{BfdConfig, Callback};
use super::fsm::Event;
use super::network::{WriteRequest, read_packet, read_packet_v6, write_packet, write_packet_v6};
use super::session::{Session, SessionKey, SessionParams, SessionTable, StateChange};
use super::socket::{BFD_MULTI_HOP_PORT, BFD_SINGLE_HOP_PORT, bfd_socket_ipv4, bfd_socket_ipv6};
use super::timer::{InitialParams, TimerCmd, session_timer};

/// Identifier for a BFD subscriber. Conventionally the proto name
/// ("bgp", "ospf", "isis", "static"), plus an optional disambiguator
/// when one process registers more than one logical client per
/// session (rare).
pub type ClientId = String;

/// `show <path>` dispatch handler. Mirrors [`crate::ospf::ShowCallback`]
/// and [`crate::isis`]'s equivalent: given the BFD instance, the parsed
/// trailing [`Args`], and the JSON flag, render the response text.
pub type ShowCallback = fn(&Bfd, Args, bool) -> Result<String, std::fmt::Error>;

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
    /// `show bfd ...` subscription endpoints. The receive half drains
    /// in the event loop and dispatches through [`Self::show_cb`].
    pub show: ShowChannel,
    /// Show callback table — path → handler — populated by
    /// [`Bfd::show_build`] and consulted by [`Self::process_show_msg`].
    pub show_cb: HashMap<String, ShowCallback>,
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
    /// Egress channel for IPv6 sessions, drained by `write_packet_v6`
    /// on the v6 socket. `on_tx_tick` routes by the session's remote
    /// address family. Sends are dropped if the v6 listener never came
    /// up (the receiver is gone) — v6 simply doesn't work in that case.
    write_tx_v6: UnboundedSender<WriteRequest>,
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
    /// A parsed control packet arrived. The received IP TTL is carried
    /// up so [`Bfd::on_recv`] can enforce the per-session TTL floor
    /// (GTSM=255 for single-hop, the configured minimum for multihop)
    /// after the packet is demuxed to a session.
    Recv {
        packet: bfd_packet::ControlPacket,
        src: SocketAddr,
        dst: Option<IpAddr>,
        ifindex: u32,
        ttl: u8,
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
        let (write_tx_v6, write_rx_v6) = mpsc::unbounded_channel::<WriteRequest>();

        let read_sock = sock.clone();
        let read_tx = main_tx.clone();
        tokio::spawn(async move {
            read_packet(read_sock, read_tx).await;
        });

        let write_sock = sock.clone();
        tokio::spawn(async move {
            write_packet(write_sock, write_rx).await;
        });

        // Production instances also listen on the multihop port (4784,
        // RFC 5883) so iBGP / eBGP-multihop neighbours can be tracked.
        // Egress reuses the primary socket — `on_tx_tick` picks the
        // destination port per session — so only a second *receive*
        // socket is needed. Gated on the well-known bind so the
        // ephemeral-port test instances don't fight over 4784. A bind
        // failure here is non-fatal: single-hop still works.
        if bind.port() == BFD_SINGLE_HOP_PORT {
            match bfd_socket_ipv4(
                &ctx,
                SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, BFD_MULTI_HOP_PORT),
            )
            .and_then(AsyncFd::new)
            {
                Ok(mh_sock) => {
                    let mh_sock = Arc::new(mh_sock);
                    let mh_tx = main_tx.clone();
                    tokio::spawn(async move {
                        read_packet(mh_sock, mh_tx).await;
                    });
                }
                Err(e) => tracing::warn!(
                    "bfd: multihop listener on {BFD_MULTI_HOP_PORT} unavailable, \
                     single-hop only: {e}"
                ),
            }
        }

        // IPv6 listeners (RFC 5881/5883 reuse the same ports on the v6
        // transport; `IPV6_V6ONLY` keeps them off the v4 sockets). The
        // 3784 socket is shared TX+RX (drains `write_rx_v6`); 4784 is
        // RX-only. Non-fatal: v4 keeps working if v6 is unavailable.
        // Gated on the well-known bind so ephemeral-port test instances
        // don't open them.
        if bind.port() == BFD_SINGLE_HOP_PORT {
            match bfd_socket_ipv6(
                &ctx,
                SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, BFD_SINGLE_HOP_PORT, 0, 0),
            )
            .and_then(AsyncFd::new)
            {
                Ok(sock6) => {
                    let sock6 = Arc::new(sock6);
                    let read_sock = sock6.clone();
                    let read_tx = main_tx.clone();
                    tokio::spawn(async move {
                        read_packet_v6(read_sock, read_tx).await;
                    });
                    tokio::spawn(async move {
                        write_packet_v6(sock6, write_rx_v6).await;
                    });
                }
                Err(e) => tracing::warn!(
                    "bfd: IPv6 single-hop listener on {BFD_SINGLE_HOP_PORT} unavailable, \
                     IPv4 only: {e}"
                ),
            }
            match bfd_socket_ipv6(
                &ctx,
                SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, BFD_MULTI_HOP_PORT, 0, 0),
            )
            .and_then(AsyncFd::new)
            {
                Ok(mh6) => {
                    let mh6 = Arc::new(mh6);
                    let mh_tx = main_tx.clone();
                    tokio::spawn(async move {
                        read_packet_v6(mh6, mh_tx).await;
                    });
                }
                Err(e) => tracing::warn!(
                    "bfd: IPv6 multihop listener on {BFD_MULTI_HOP_PORT} unavailable: {e}"
                ),
            }
        }

        let mut bfd = Self {
            rx,
            sessions: SessionTable::new(),
            local_addr,
            config: BfdConfig::default(),
            callbacks: HashMap::new(),
            cm: ConfigChannel::new(),
            show: ShowChannel::new(),
            show_cb: HashMap::new(),
            client_req: ClientReqChannel::new(),
            subscribers: HashMap::new(),
            main_tx,
            write_tx,
            write_tx_v6,
            timer_handles: HashMap::new(),
        };
        bfd.callback_build();
        bfd.show_build();
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

    /// Look up the show handler for `msg.paths` and invoke it. Mirrors
    /// [`crate::ospf`]/[`crate::isis`]'s `process_show_msg`.
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

    pub async fn event_loop(&mut self) {
        loop {
            tokio::select! {
                Some(msg) = self.rx.recv() => match msg {
                    Message::Recv { packet, src, dst, ifindex, ttl } =>
                        self.on_recv(packet, src, dst, ifindex, ttl),
                    Message::TxTick { key } => self.on_tx_tick(key),
                    Message::DetectExpired { key } => self.on_detect_expired(key),
                },
                Some(msg) = self.cm.rx.recv() => {
                    self.process_cm_msg(msg);
                }
                Some(msg) = self.show.rx.recv() => {
                    self.process_show_msg(msg).await;
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
        src: SocketAddr,
        dst: Option<IpAddr>,
        ifindex: u32,
        ttl: u8,
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

        // Enforce the TTL floor now that the packet is matched to a
        // session whose hop mode we know. Single-hop sessions carry
        // `min_ttl = 255` (RFC 5881 §5 GTSM), multihop the configured
        // minimum (RFC 5883). A `u8` TTL can't exceed 255, so a single
        // `<` comparison covers both: single-hop accepts only 255.
        {
            let session = self
                .sessions
                .get_by_key_mut(&key)
                .expect("just looked up by key");
            if ttl < session.min_ttl {
                session.stats.rx_invalid_count += 1;
                tracing::debug!(
                    ?src,
                    ?dst,
                    ttl,
                    min_ttl = session.min_ttl,
                    multihop = session.key.multihop,
                    "bfd: received TTL below floor, dropping packet",
                );
                return;
            }
        }

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
    fn bootstrap_lookup(&self, src: SocketAddr, ifindex: u32) -> Option<SessionKey> {
        let src_ip = src.ip();
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
        let dst = SocketAddr::new(session.key.remote, session.dst_port);
        let ifindex = (session.key.ifindex != 0).then_some(session.key.ifindex);
        let req = WriteRequest {
            packet: session.build_packet(),
            dst,
            ifindex,
        };
        // Route to the egress loop matching the destination family.
        match session.key.remote {
            IpAddr::V4(_) => {
                let _ = self.write_tx.send(req);
            }
            IpAddr::V6(_) => {
                let _ = self.write_tx_v6.send(req);
            }
        }
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

    /// A control packet whose received TTL is below a single-hop
    /// session's floor (255, GTSM) is rejected in `on_recv`: the
    /// invalid counter ticks and `handle_packet` never runs.
    #[tokio::test]
    async fn on_recv_drops_below_single_hop_floor() {
        let mut bfd = fresh_bfd();
        let key = loopback_key(8); // multihop: false ⇒ min_ttl 255
        let (tx, _rx) = mpsc::unbounded_channel();
        bfd.subscribe("test".into(), key, SessionParams::default(), tx);
        let disc = bfd.sessions.get_by_key(&key).unwrap().local_disc;

        let packet = bfd_packet::ControlPacket {
            state: bfd_packet::State::Up,
            my_disc: 0x1111_2222,
            your_disc: disc,
            ..bfd_packet::ControlPacket::default()
        };
        let src = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 8), 49152));
        bfd.on_recv(packet, src, None, 0, 254); // single-hop requires 255

        let session = bfd.sessions.get_by_key(&key).unwrap();
        assert_eq!(session.stats.rx_invalid_count, 1);
        assert_eq!(session.stats.rx_count, 0, "rejected before handle_packet");
        assert_eq!(session.remote_disc, 0, "no peer discriminator learned");
    }

    /// A multihop session accepts a packet whose TTL equals its
    /// relaxed floor — `handle_packet` runs and the peer discriminator
    /// is learned.
    #[tokio::test]
    async fn on_recv_multihop_accepts_relaxed_ttl() {
        let mut bfd = fresh_bfd();
        let mut key = loopback_key(9);
        key.multihop = true;
        let params = SessionParams {
            min_ttl: 254,
            ..SessionParams::default()
        };
        let (tx, _rx) = mpsc::unbounded_channel();
        bfd.subscribe("test".into(), key, params, tx);
        let disc = bfd.sessions.get_by_key(&key).unwrap().local_disc;

        let packet = bfd_packet::ControlPacket {
            state: bfd_packet::State::Down,
            my_disc: 0x3333_4444,
            your_disc: disc,
            ..bfd_packet::ControlPacket::default()
        };
        let src = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 9), 49152));
        bfd.on_recv(packet, src, None, 0, 254); // == floor ⇒ accepted

        let session = bfd.sessions.get_by_key(&key).unwrap();
        assert_eq!(session.stats.rx_count, 1, "ttl at floor is accepted");
        assert_eq!(session.stats.rx_invalid_count, 0);
        assert_eq!(session.remote_disc, 0x3333_4444);
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
