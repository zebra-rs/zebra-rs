use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;

use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use crate::config::{
    Args, ConfigChannel, ConfigOp, ConfigRequest, DisplayRequest, ShowChannel, path_from_command,
};
use crate::context::{ProtoContext, Task};

use super::fsm::Event;
use super::network::{WriteRequest, read_packet, read_packet_v6, write_packet, write_packet_v6};
use super::session::{Session, SessionKey, SessionParams, SessionTable, StateChange};
use super::socket::{BFD_MULTI_HOP_PORT, BFD_SINGLE_HOP_PORT, bfd_socket_ipv4, bfd_socket_ipv6};
use super::timer::{InitialParams, TimerCmd, session_timer};
use super::trace::{bfd_debug, bfd_info, bfd_warn};

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
/// session table, a per-session timer handle map, and the
/// client-subscription registry. Read and write tasks are tokio-spawned
/// at construction and feed the event loop via `main_tx` / `write_tx`.
/// BFD's only own config is the top-level `bfd { tracing }` flag (handled
/// via `cm.rx` in [`Self::process_cm_msg`]); every other config-manager
/// broadcast is drained, and external clients (BGP / OSPF / IS-IS /
/// static) submit subscribe/unsubscribe requests through `client_req.rx`.
pub struct Bfd {
    pub rx: UnboundedReceiver<Message>,
    pub sessions: SessionTable,
    /// Local address the recv socket was bound to. Useful to tests
    /// that bind to ephemeral ports — `local_addr.port()` reveals the
    /// kernel-chosen value so the peer can be told where to send.
    pub local_addr: SocketAddrV4,
    /// Config-manager subscription endpoints. BFD's only own config is the
    /// `bfd { tracing }` flag; the receive half is processed in the event
    /// loop ([`Self::process_cm_msg`]) and every other commit is drained.
    /// Registering as a config client also lets the manager see BFD is
    /// already running and avoid a double-spawn.
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
    /// Supervises the per-interface XDP Echo reflector child processes.
    /// Reference-counted by the single-hop echo sessions on each ifindex
    /// ([`Self::add_session`] / [`Self::remove_session`]).
    reflectors: super::reflector::EchoReflectors,
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
    /// key, BFD creates one using `params`; otherwise the existing
    /// session is reused and the Echo-affecting fields of `params` are
    /// applied to it live (`Bfd::update_echo_params`) — so clients
    /// re-send `Subscribe` to push `bfd { echo-* }` config changes.
    /// State-change events for the session are forwarded to `notifier`
    /// until the matching [`ClientReq::Unsubscribe`] arrives.
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
    /// after the packet is demuxed to a session. `multihop` records
    /// which transport the packet arrived on (single-hop port 3784 vs
    /// multihop port 4784) so the demux can refuse to drive a session
    /// of the opposite hop type.
    Recv {
        packet: bfd_packet::ControlPacket,
        src: SocketAddr,
        dst: Option<IpAddr>,
        ifindex: u32,
        ttl: u8,
        multihop: bool,
    },
    /// Periodic transmission timer fired for `key`. `actual_tx_us` is the
    /// jittered interval (RFC 5880 §6.8.7) the timer just scheduled, stored on
    /// the session for `show bfd peers` ("actual with jitter").
    TxTick { key: SessionKey, actual_tx_us: u32 },
    /// Detection timer fired for `key`.
    DetectExpired { key: SessionKey },
    /// The per-interface helper reported that our originated Echo for the
    /// session with this local discriminator stopped returning (Echo detection
    /// timeout). Drives the session Down with `EchoFunctionFailed`.
    EchoDown { discr: u32 },
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
            // Primary socket: single-hop port (3784) in production; an
            // ephemeral port in tests, which only carry single-hop
            // sessions. Either way these are single-hop reads.
            read_packet(read_sock, read_tx, false).await;
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
                        read_packet(mh_sock, mh_tx, true).await;
                    });
                }
                Err(e) => bfd_warn!(
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
                        read_packet_v6(read_sock, read_tx, false).await;
                    });
                    tokio::spawn(async move {
                        write_packet_v6(sock6, write_rx_v6).await;
                    });
                }
                Err(e) => bfd_warn!(
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
                        read_packet_v6(mh6, mh_tx, true).await;
                    });
                }
                Err(e) => bfd_warn!(
                    "bfd: IPv6 multihop listener on {BFD_MULTI_HOP_PORT} unavailable: {e}"
                ),
            }
        }

        let mut bfd = Self {
            rx,
            sessions: SessionTable::new(),
            local_addr,
            cm: ConfigChannel::new(),
            show: ShowChannel::new(),
            show_cb: HashMap::new(),
            client_req: ClientReqChannel::new(),
            subscribers: HashMap::new(),
            main_tx: main_tx.clone(),
            write_tx,
            write_tx_v6,
            timer_handles: HashMap::new(),
            reflectors: super::reflector::EchoReflectors::new(main_tx),
        };
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
    /// session if it does not yet exist; otherwise the session is
    /// reused and the Echo-affecting fields of `params` are applied to
    /// it live (see [`Self::update_echo_params`]) — clients re-drive
    /// `Subscribe` from their `bfd {}` config callbacks, so a commit
    /// that flips `echo-mode` lands here. If the session is already
    /// Up, the new subscriber is informed via an immediate synthetic
    /// [`BfdEvent::StateChange`].
    pub fn subscribe(
        &mut self,
        client: ClientId,
        key: SessionKey,
        params: SessionParams,
        notifier: UnboundedSender<BfdEvent>,
    ) {
        // Lazy create the session on the first subscriber. Subsequent
        // Subscribes reuse the existing session, applying only the Echo
        // params — where several clients share a session the last
        // writer wins (control-plane timing stays create-time-only).
        if self.sessions.get_by_key(&key).is_none() {
            self.add_session(key, params);
        } else {
            self.update_echo_params(&key, &params);
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

    /// Insert a new session and spawn its timer task. Returns the
    /// locally-assigned, non-zero, collision-free discriminator.
    pub fn add_session(&mut self, key: SessionKey, params: SessionParams) -> u32 {
        let disc = self.sessions.insert(key, params);

        // Echo is single-hop only; both IPv4 and IPv6 are handled (the XDP helper
        // reflects either family). Any active Echo role needs the per-interface
        // helper: `receive` reflects a peer's Echo, `transmit` sends + detects
        // ours. Bring it up and mark the session `echo_ready` once the child is
        // confirmed running — until then we advertise 0 (an honest promise to
        // actually loop Echo back).
        if !params.echo_mode.is_off() && !key.multihop {
            self.reflectors.acquire(key.ifindex);
            let ready = self.reflectors.is_ready(key.ifindex);
            if ready && let Some(s) = self.sessions.get_by_key_mut(&key) {
                s.echo_ready = true;
            }
        }

        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let initial = InitialParams {
            // A fresh session starts Down, so the §6.8.3 slow-TX clamp
            // applies: transmit at no faster than 1 s until the session
            // reaches Up. The negotiated rate lands on the first Rx via
            // the Update command (`tx_interval_us`).
            tx_interval_us: params.desired_min_tx_us.max(1_000_000),
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

    /// Apply the Echo-affecting fields of `params` to an existing session —
    /// the runtime path for `bfd { echo-mode | echo-*-interval }` config
    /// changes, which clients re-drive via `Subscribe` on commit. Control
    /// timing (`desired_min_tx_us` / `required_min_rx_us` / `detect_mult`)
    /// stays create-time-only: a live change would need an RFC 5880 §6.8.3
    /// Poll Sequence, and every client wires only the Echo fields today.
    ///
    /// The reflector-helper refcount tracks "Echo configured on this
    /// single-hop session" (the `add_session` / `remove_session` predicate),
    /// so it is adjusted here on every off↔on edge to stay symmetric while
    /// `echo_mode` mutates.
    fn update_echo_params(&mut self, key: &SessionKey, params: &SessionParams) {
        let Some(s) = self.sessions.get_by_key(key) else {
            return;
        };
        if s.echo_mode == params.echo_mode
            && s.required_min_echo_rx_us == params.required_min_echo_rx_us
            && s.echo_transmit_us == params.echo_transmit_us
        {
            return;
        }
        let was_active = !s.echo_mode.is_off() && !key.multihop;
        let now_active = !params.echo_mode.is_off() && !key.multihop;
        // A change to the transmit role or rate invalidates a running
        // originator: stop it now, while the helper is guaranteed alive
        // (originating ⇒ `was_active` ⇒ we still hold a reflector
        // reference), and let the reconcile below re-add it under the new
        // params if it is still wanted.
        let restart = s.echo_originating
            && (s.echo_mode.transmits() != params.echo_mode.transmits()
                || s.echo_transmit_us != params.echo_transmit_us);
        if restart {
            self.reflectors
                .send_command(key.ifindex, format!("echo-del {}", s.local_disc));
        }
        if now_active && !was_active {
            self.reflectors.acquire(key.ifindex);
        }
        // Same honesty gate as `add_session`: advertise a non-zero echo-rx
        // only once the helper is confirmed running.
        let ready = now_active && self.reflectors.is_ready(key.ifindex);
        if let Some(s) = self.sessions.get_by_key_mut(key) {
            s.echo_mode = params.echo_mode;
            s.required_min_echo_rx_us = params.required_min_echo_rx_us;
            s.echo_transmit_us = params.echo_transmit_us;
            s.echo_ready = ready;
            if restart {
                s.echo_originating = false;
            }
        }
        // Re-evaluate the §6.8.9 originate gate under the new params: emits
        // the `echo-add` for a gained or restarted transmit role (a dropped
        // one was already stopped above — originating implies the old mode
        // transmitted, so a role drop always sets `restart`). The new
        // advertised echo-rx goes out on the next periodic control Tx.
        self.echo_originate_reconcile(*key);
        // Release last: if this was the interface's final Echo session the
        // helper is torn down, so any `echo-del` had to precede it.
        if was_active && !now_active {
            self.reflectors.release(key.ifindex);
        }
    }

    /// Remove a session and shut down its timer task. Returns the
    /// removed session, if any.
    pub fn remove_session(&mut self, key: &SessionKey) -> Option<Session> {
        if let Some(h) = self.timer_handles.remove(key) {
            let _ = h.cmd_tx.send(TimerCmd::Shutdown);
        }
        let removed = self.sessions.remove(key);
        // Mirror the `add_session` acquire predicate exactly. `echo_mode` can
        // mutate at runtime (`update_echo_params`), but that path adjusts the
        // reflector refcount on every off↔on edge, so releasing on the
        // *current* mode stays symmetric.
        if let Some(s) = &removed
            && !s.echo_mode.is_off()
            && !s.key.multihop
        {
            // Stop any originator first, while the helper is still alive — the
            // release below may be the last reference and tear the child down.
            if s.echo_originating {
                self.reflectors
                    .send_command(s.key.ifindex, format!("echo-del {}", s.local_disc));
            }
            self.reflectors.release(s.key.ifindex);
        }
        removed
    }

    /// Look up the show handler for `msg.paths` and invoke it. Mirrors
    /// [`crate::ospf`]/[`crate::isis`]'s `process_show_msg`.
    /// BFD's only own config is the top-level `bfd { tracing }` flag, which
    /// toggles the conditional-tracing gate (see [`super::trace`]). Every
    /// other broadcast config line is ignored. The flag is a process-global
    /// atomic so it reaches the spawned socket / reflector tasks too.
    fn process_cm_msg(&mut self, msg: ConfigRequest) {
        if !matches!(msg.op, ConfigOp::Set | ConfigOp::Delete) {
            return;
        }
        let (path, mut args) = path_from_command(&msg.paths);
        if path == "/bfd/tracing" {
            let enabled = msg.op.is_set() && args.boolean().unwrap_or(false);
            super::trace::set(enabled);
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

    pub async fn event_loop(&mut self) {
        loop {
            tokio::select! {
                Some(msg) = self.rx.recv() => match msg {
                    Message::Recv { packet, src, dst, ifindex, ttl, multihop } =>
                        self.on_recv(packet, src, dst, ifindex, ttl, multihop),
                    Message::TxTick { key, actual_tx_us } => self.on_tx_tick(key, actual_tx_us),
                    Message::DetectExpired { key } => self.on_detect_expired(key),
                    Message::EchoDown { discr } => self.on_echo_down(discr),
                },
                // BFD's only config is the top-level `bfd { tracing }` flag;
                // every other commit broadcast is drained here (we register as
                // a config client so the manager knows BFD is running).
                Some(msg) = self.cm.rx.recv() => self.process_cm_msg(msg),
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
        multihop: bool,
    ) {
        let lookup = if packet.your_disc != 0 {
            self.sessions.get_by_disc(packet.your_disc).map(|s| s.key)
        } else {
            self.bootstrap_lookup(src, ifindex, multihop)
        };
        let Some(key) = lookup else {
            bfd_debug!(
                ?src,
                ?dst,
                ifindex,
                multihop,
                your_disc = format_args!("{:#010x}", packet.your_disc),
                "bfd: no session matches received packet",
            );
            return;
        };

        // Hop-type segregation. RFC 5881 (single-hop) and RFC 5883
        // (multihop) use distinct UDP ports precisely so the two never
        // mix; a packet that arrived on the single-hop port must not
        // drive a multihop session and vice versa. The bootstrap path
        // already filtered on this, but the discriminator path resolves
        // purely on the (random) Your Discriminator, so re-check here.
        // Without it a peer's failing single-hop session (which keeps
        // emitting Down packets with `your_disc == 0`) can be matched to
        // our multihop session and knock it down.
        if key.multihop != multihop {
            if let Some(session) = self.sessions.get_by_key_mut(&key) {
                session.stats.rx_invalid_count += 1;
            }
            bfd_debug!(
                ?src,
                ?dst,
                ifindex,
                arrived_multihop = multihop,
                session_multihop = key.multihop,
                "bfd: hop-type mismatch, dropping packet",
            );
            return;
        }

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
                bfd_debug!(
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

        // RFC 5880 §6.8.6: a received Poll (P) MUST be answered with a
        // Final (F) "as soon as practicable", independent of the
        // transmit timer. Without it a peer that changes its timers via
        // a Poll Sequence — e.g. FRR leaving its ≥1s slow-TX state
        // (§6.8.3) and speeding up to its configured rate when the
        // session comes Up — never completes the sequence, so it holds
        // the slow rate while we have already shortened our Detection
        // Time to the advertised fast rate, and we time out
        // (ControlDetectionTimeExpired). A packet with both P and F set
        // is malformed, so only answer a pure Poll.
        if packet.poll
            && !packet.final_bit
            && let Some(session) = self.sessions.get_by_key(&key)
        {
            self.send_control(session, true);
        }

        if let Some(change) = change {
            self.notify_state_change(key, change);
        }

        // (Re)evaluate the §6.8.9 originate gate: a transition to/from Up, or a
        // freshly-learned non-zero peer echo-rx, can start or stop our Echo.
        self.echo_originate_reconcile(key);
    }

    /// Find an existing session that matches an incoming packet whose
    /// `Your Discriminator` is zero (RFC 5880 §6.8.6 bootstrap path).
    /// Linear scan — fine for the small session counts a single
    /// process maintains; an explicit (local, remote, ifindex) index
    /// can be added later if it shows up in profiles.
    fn bootstrap_lookup(
        &self,
        src: SocketAddr,
        ifindex: u32,
        multihop: bool,
    ) -> Option<SessionKey> {
        let src_ip = src.ip();
        self.sessions.iter().find_map(|(_, s)| {
            let ifindex_match = s.key.ifindex == 0 || s.key.ifindex == ifindex;
            if s.key.remote == src_ip && s.key.multihop == multihop && ifindex_match {
                Some(s.key)
            } else {
                None
            }
        })
    }

    fn on_tx_tick(&mut self, key: SessionKey, actual_tx_us: u32) {
        // Record the jittered interval the timer just scheduled so `show bfd
        // peers` can report it ("actual with jitter"). Separate lookups keep
        // the mutable borrow from overlapping the `&self` send below.
        if let Some(session) = self.sessions.get_by_key_mut(&key) {
            session.actual_tx_us = actual_tx_us;
        }
        if let Some(session) = self.sessions.get_by_key(&key) {
            self.send_control(session, false);
        }
    }

    /// Transmit one control packet reflecting `session`'s current
    /// state. `final_bit` sets the Final (F) flag — used only when
    /// answering a peer's Poll (P) per RFC 5880 §6.8.6; the periodic
    /// [`Self::on_tx_tick`] path passes `false`.
    fn send_control(&self, session: &Session, final_bit: bool) {
        let dst = SocketAddr::new(session.key.remote, session.dst_port);
        let ifindex = (session.key.ifindex != 0).then_some(session.key.ifindex);
        // Stamp the configured local address as the packet source (e.g.
        // a BGP neighbor's update-source). The wildcard means "no
        // preference" — let the kernel choose the source per the route.
        let src = match session.key.local {
            IpAddr::V4(a) if a.is_unspecified() => None,
            IpAddr::V6(a) if a.is_unspecified() => None,
            addr => Some(addr),
        };
        let mut packet = session.build_packet();
        // A packet must never carry both Poll and Final (RFC 5880 §6.8.7).
        // When this transmission is a Final answering the peer's Poll,
        // it takes precedence: clear our own Poll bit on this packet
        // (our Poll Sequence, if any, continues on the next periodic Tx).
        if final_bit {
            packet.poll = false;
            packet.final_bit = true;
        }
        let req = WriteRequest {
            packet,
            dst,
            ifindex,
            src,
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

    /// The per-interface helper reported that our originated Echo for the
    /// session with local discriminator `discr` stopped returning (RFC 5880
    /// §6.8.5). Drive the session Down with `EchoFunctionFailed`, then reconcile
    /// the originator — the session is no longer Up, so we stop sending Echo.
    fn on_echo_down(&mut self, discr: u32) {
        let Some(key) = self.sessions.get_by_disc(discr).map(|s| s.key) else {
            return;
        };
        let change = self
            .sessions
            .get_by_key_mut(&key)
            .and_then(|s| s.handle_event(Event::EchoDetectExpired));
        if let Some(change) = change {
            self.notify_state_change(key, change);
        }
        self.echo_originate_reconcile(key);
    }

    /// RFC 5880 §6.8.9 — start or stop *originating* Echo for `key` based on the
    /// session's current gate, emitting `echo-add`/`echo-del` to the
    /// per-interface helper exactly on the edges (tracked by
    /// [`Session::echo_originating`]).
    ///
    /// We originate only while the session is **Up**, our configured Echo mode
    /// transmits (`transmit`/`both`), the peer advertises a non-zero Required Min
    /// Echo RX Interval (it will loop our Echo back), it is single-hop, and both
    /// endpoints carry a concrete address (IPv4, or an IPv6 link-local) — the
    /// helper builds a self-addressed L2 frame and the forwarding plane hairpins
    /// it. The
    /// transmit interval is our configured `echo-transmit-interval`, clamped up
    /// to the peer's advertised floor; detection is `interval × detect_mult`.
    fn echo_originate_reconcile(&mut self, key: SessionKey) {
        let Some(s) = self.sessions.get_by_key(&key) else {
            return;
        };
        // Echo is single-hop only; `local` must be a concrete (non-unspecified)
        // source the helper can stamp as src==dst on the self-addressed frame.
        // Both families are supported — the helper builds a v4 or v6 frame from
        // the addresses (an IPv6 pair uses the two ends' link-locals).
        let pair = match (s.key.local, s.key.remote) {
            (IpAddr::V4(local), IpAddr::V4(peer)) if !s.key.multihop && !local.is_unspecified() => {
                Some((IpAddr::V4(local), IpAddr::V4(peer)))
            }
            (IpAddr::V6(local), IpAddr::V6(peer)) if !s.key.multihop && !local.is_unspecified() => {
                Some((IpAddr::V6(local), IpAddr::V6(peer)))
            }
            _ => None,
        };
        let want = pair.is_some()
            && s.local_state == bfd_packet::State::Up
            && s.echo_mode.transmits()
            && s.remote_min_echo_rx_us > 0;
        if want == s.echo_originating {
            return;
        }
        let ifindex = s.key.ifindex;
        let discr = s.local_disc;
        if want {
            let (local, peer) = pair.expect("want implies a concrete address pair");
            // §6.8.9: the interval MUST NOT be below the peer's advertised
            // Required Min Echo RX Interval. Send at our configured rate, but
            // never faster than the peer's floor.
            let tx_us = s.echo_transmit_us.max(s.remote_min_echo_rx_us).max(1);
            let mult = s.detect_mult.max(1);
            self.reflectors.send_command(
                ifindex,
                format!("echo-add {discr} {local} {peer} {tx_us} {mult}"),
            );
        } else {
            self.reflectors
                .send_command(ifindex, format!("echo-del {discr}"));
        }
        if let Some(s) = self.sessions.get_by_key_mut(&key) {
            s.echo_originating = want;
        }
    }

    fn notify_state_change(&self, key: SessionKey, change: StateChange) {
        bfd_info!(
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
    use super::super::session::EchoMode;
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

    /// A single-hop subscribe carrying a non-zero echo-rx refcounts the
    /// per-interface Echo reflector; unsubscribing the last such session
    /// releases it. The ifindex has no interface name here, so no child is
    /// actually spawned — only the refcount bookkeeping is exercised.
    #[tokio::test]
    async fn echo_subscribe_refcounts_reflector() {
        let mut bfd = fresh_bfd();
        let mut key = loopback_key(20);
        key.ifindex = 0xFFFF_FFF0; // no such interface
        let params = SessionParams {
            echo_mode: EchoMode::Both,
            required_min_echo_rx_us: 50_000,
            ..SessionParams::default()
        };
        let (tx, _rx) = mpsc::unbounded_channel();

        bfd.subscribe("test".into(), key, params, tx);
        assert_eq!(bfd.reflectors.refcount(key.ifindex), 1);

        bfd.unsubscribe("test", &key);
        assert_eq!(bfd.reflectors.refcount(key.ifindex), 0);
    }

    /// Echo is single-hop only (RFC 5883 multihop has no Echo), so a multihop
    /// session never brings up a reflector even with echo-rx configured.
    #[tokio::test]
    async fn echo_multihop_does_not_refcount_reflector() {
        let mut bfd = fresh_bfd();
        let mut key = loopback_key(21);
        key.ifindex = 0xFFFF_FFF1;
        key.multihop = true;
        let params = SessionParams {
            echo_mode: EchoMode::Both,
            required_min_echo_rx_us: 50_000,
            ..SessionParams::default()
        };
        let (tx, _rx) = mpsc::unbounded_channel();

        bfd.subscribe("test".into(), key, params, tx);
        assert_eq!(bfd.reflectors.refcount(key.ifindex), 0);
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
        bfd.on_recv(packet, src, None, 0, 254, false); // single-hop requires 255

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
        bfd.on_recv(packet, src, None, 0, 254, true); // == floor ⇒ accepted

        let session = bfd.sessions.get_by_key(&key).unwrap();
        assert_eq!(session.stats.rx_count, 1, "ttl at floor is accepted");
        assert_eq!(session.stats.rx_invalid_count, 0);
        assert_eq!(session.remote_disc, 0x3333_4444);
    }

    /// Regression: a single-hop control packet must never be demuxed
    /// onto a multihop session. A peer running a failing single-hop
    /// session to us keeps emitting Down packets with `your_disc == 0`;
    /// before the hop-type filter those matched our multihop session by
    /// (remote, ifindex) alone and knocked it Down. With the filter the
    /// stray packet finds no single-hop session and is dropped.
    #[tokio::test]
    async fn single_hop_packet_does_not_disturb_multihop_session() {
        let mut bfd = fresh_bfd();
        let mut key = loopback_key(20);
        key.multihop = true;
        let params = SessionParams {
            min_ttl: 254,
            ..SessionParams::default()
        };
        let (tx, _rx) = mpsc::unbounded_channel();
        bfd.subscribe("bgp".into(), key, params, tx);
        let disc = bfd.sessions.get_by_key(&key).unwrap().local_disc;

        const FRR_MH_DISC: u32 = 0xaaaa_0001;
        const FRR_SH_DISC: u32 = 0xbbbb_0002;
        let src = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 20), 49152));

        // Bring the multihop session Up via two multihop packets.
        let down = bfd_packet::ControlPacket {
            state: bfd_packet::State::Down,
            my_disc: FRR_MH_DISC,
            your_disc: 0,
            ..bfd_packet::ControlPacket::default()
        };
        bfd.on_recv(down, src, None, 0, 254, true);
        let up = bfd_packet::ControlPacket {
            state: bfd_packet::State::Up,
            my_disc: FRR_MH_DISC,
            your_disc: disc,
            ..bfd_packet::ControlPacket::default()
        };
        bfd.on_recv(up, src, None, 0, 254, true);

        let session = bfd.sessions.get_by_key(&key).unwrap();
        assert_eq!(
            session.local_state,
            bfd_packet::State::Up,
            "session came up"
        );
        assert_eq!(session.remote_disc, FRR_MH_DISC);
        assert_eq!(session.stats.rx_count, 2);

        // Stray single-hop Down (your_disc == 0, single-hop transport):
        // no single-hop session exists → dropped, multihop untouched.
        let stray = bfd_packet::ControlPacket {
            state: bfd_packet::State::Down,
            my_disc: FRR_SH_DISC,
            your_disc: 0,
            ..bfd_packet::ControlPacket::default()
        };
        bfd.on_recv(stray, src, None, 0, 255, false);

        let session = bfd.sessions.get_by_key(&key).unwrap();
        assert_eq!(
            session.local_state,
            bfd_packet::State::Up,
            "stray single-hop packet must not knock the multihop session down",
        );
        assert_eq!(
            session.remote_disc, FRR_MH_DISC,
            "remote discriminator must not be corrupted by the stray packet",
        );
        assert_eq!(session.stats.rx_count, 2, "stray packet not processed");

        // Defence in depth: a single-hop packet echoing our discriminator
        // (discriminator demux path) is rejected by the hop-type guard.
        let stray_disc = bfd_packet::ControlPacket {
            state: bfd_packet::State::Down,
            my_disc: FRR_SH_DISC,
            your_disc: disc,
            ..bfd_packet::ControlPacket::default()
        };
        bfd.on_recv(stray_disc, src, None, 0, 255, false);

        let session = bfd.sessions.get_by_key(&key).unwrap();
        assert_eq!(session.local_state, bfd_packet::State::Up);
        assert_eq!(session.remote_disc, FRR_MH_DISC);
        assert_eq!(session.stats.rx_count, 2, "guarded packet not processed");
        assert_eq!(
            session.stats.rx_invalid_count, 1,
            "hop-type mismatch on the discriminator path is counted invalid",
        );
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

    /// A received Poll (P) is answered with a Final (F) on the wire
    /// (RFC 5880 §6.8.6). Without this a peer's timer-change Poll
    /// Sequence never completes, which manifested as a BGP/FRR BFD flap
    /// (ControlDetectionTimeExpired) once intervals dropped to 300 ms.
    /// Multi-threaded runtime so the spawned write task can run while
    /// the test blocks on the peer socket's `recv`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn poll_is_answered_with_final() {
        let peer = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind peer");
        peer.set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let peer_port = peer.local_addr().unwrap().port();

        let mut bfd = fresh_bfd();
        let key = SessionKey {
            local: IpAddr::V4(Ipv4Addr::LOCALHOST),
            remote: IpAddr::V4(Ipv4Addr::LOCALHOST),
            ifindex: 0,
            multihop: false,
        };
        let params = SessionParams {
            dst_port: peer_port,
            min_ttl: 255,
            ..SessionParams::default()
        };
        let (tx, _rx) = mpsc::unbounded_channel();
        bfd.subscribe("test".into(), key, params, tx);
        let disc = bfd.sessions.get_by_key(&key).unwrap().local_disc;

        // A pure Poll (P=1, F=0) from the peer.
        let mut pkt = bfd_packet::ControlPacket {
            state: bfd_packet::State::Down,
            detect_mult: 3,
            my_disc: 0x5151_5151,
            your_disc: disc,
            ..bfd_packet::ControlPacket::default()
        };
        pkt.poll = true;
        let src = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, peer_port));
        bfd.on_recv(pkt, src, None, 0, 255, false);

        // The write task must emit a Final (F=1, P=0) response.
        let mut buf = [0u8; 1500];
        let n = peer.recv(&mut buf).expect("final response received");
        let resp = bfd_packet::ControlPacket::parse(&buf[..n]).expect("parse final");
        assert!(resp.final_bit, "response carries Final");
        assert!(!resp.poll, "response clears Poll");
        assert_eq!(resp.your_disc, 0x5151_5151, "echoes the peer discriminator");
    }

    // ---- runtime Echo param updates (`Bfd::update_echo_params`) -------------

    /// An ifindex with no backing interface: `acquire` tracks the refcount
    /// but the helper child never spawns (`if_indextoname` fails), so these
    /// tests exercise the bookkeeping without launching real XDP processes.
    const ECHO_TEST_IFINDEX: u32 = 0xfff0;

    fn echo_key(remote_octet: u8) -> SessionKey {
        SessionKey {
            ifindex: ECHO_TEST_IFINDEX,
            ..loopback_key(remote_octet)
        }
    }

    fn echo_params(echo_mode: EchoMode, rx_ms: u32, tx_ms: u32) -> SessionParams {
        SessionParams {
            echo_mode,
            required_min_echo_rx_us: rx_ms * 1_000,
            echo_transmit_us: tx_ms * 1_000,
            ..SessionParams::default()
        }
    }

    /// Force the §6.8.9 originate gate open: session Up with a peer that
    /// advertises a non-zero Required Min Echo RX Interval.
    fn force_up_with_peer_echo(bfd: &mut Bfd, key: &SessionKey) {
        let s = bfd.sessions.get_by_key_mut(key).unwrap();
        s.local_state = bfd_packet::State::Up;
        s.remote_min_echo_rx_us = 50_000;
    }

    /// Re-subscribing with Echo off applies to the live session — the
    /// `delete … bfd echo-mode` + commit path. The originator stops, the
    /// advertised echo-rx returns to 0 on the next control Tx, and the
    /// reflector reference is released. (Previously a re-Subscribe ignored
    /// `params`, so Echo kept transmitting until the session was
    /// re-established.)
    #[tokio::test]
    async fn resubscribe_turns_echo_off_live() {
        let mut bfd = fresh_bfd();
        let key = echo_key(8);
        let (tx, _rx) = mpsc::unbounded_channel();
        bfd.subscribe("isis".into(), key, echo_params(EchoMode::Both, 50, 50), tx);
        assert_eq!(bfd.reflectors.refcount(ECHO_TEST_IFINDEX), 1);
        force_up_with_peer_echo(&mut bfd, &key);
        bfd.echo_originate_reconcile(key);
        assert!(bfd.sessions.get_by_key(&key).unwrap().echo_originating);

        let (tx2, _rx2) = mpsc::unbounded_channel();
        bfd.subscribe("isis".into(), key, echo_params(EchoMode::Off, 0, 0), tx2);

        let s = bfd.sessions.get_by_key(&key).unwrap();
        assert_eq!(s.echo_mode, EchoMode::Off);
        assert!(
            !s.echo_originating,
            "originator stopped on the live session"
        );
        assert_eq!(s.build_packet().required_min_echo_rx_interval, 0);
        assert_eq!(
            s.echo_transmit_interval_us(),
            0,
            "show reports Echo disabled"
        );
        assert_eq!(
            bfd.reflectors.refcount(ECHO_TEST_IFINDEX),
            0,
            "helper reference released",
        );
    }

    /// Re-subscribing with Echo newly enabled acquires the reflector and
    /// starts originating on a session that is already Up with a
    /// reflecting peer.
    #[tokio::test]
    async fn resubscribe_turns_echo_on_live() {
        let mut bfd = fresh_bfd();
        let key = echo_key(9);
        let (tx, _rx) = mpsc::unbounded_channel();
        bfd.subscribe("isis".into(), key, SessionParams::default(), tx);
        assert_eq!(bfd.reflectors.refcount(ECHO_TEST_IFINDEX), 0);
        force_up_with_peer_echo(&mut bfd, &key);

        let (tx2, _rx2) = mpsc::unbounded_channel();
        bfd.subscribe(
            "isis".into(),
            key,
            echo_params(EchoMode::Transmit, 0, 50),
            tx2,
        );

        let s = bfd.sessions.get_by_key(&key).unwrap();
        assert_eq!(s.echo_mode, EchoMode::Transmit);
        assert_eq!(s.echo_transmit_us, 50_000);
        assert!(s.echo_originating, "originator started on the live session");
        assert_eq!(bfd.reflectors.refcount(ECHO_TEST_IFINDEX), 1);
    }

    /// A live transmit-interval change restarts the originator at the new
    /// rate (del + add toward the helper) without dropping the reflector
    /// reference.
    #[tokio::test]
    async fn resubscribe_retunes_echo_transmit_rate() {
        let mut bfd = fresh_bfd();
        let key = echo_key(10);
        let (tx, _rx) = mpsc::unbounded_channel();
        bfd.subscribe(
            "isis".into(),
            key,
            echo_params(EchoMode::Transmit, 0, 50),
            tx,
        );
        force_up_with_peer_echo(&mut bfd, &key);
        bfd.echo_originate_reconcile(key);
        assert!(bfd.sessions.get_by_key(&key).unwrap().echo_originating);

        let (tx2, _rx2) = mpsc::unbounded_channel();
        bfd.subscribe(
            "isis".into(),
            key,
            echo_params(EchoMode::Transmit, 0, 100),
            tx2,
        );

        let s = bfd.sessions.get_by_key(&key).unwrap();
        assert!(s.echo_originating, "originator restarted, not stopped");
        assert_eq!(s.echo_transmit_us, 100_000);
        assert_eq!(s.echo_transmit_interval_us(), 100_000, "live rate retuned");
        assert_eq!(
            bfd.reflectors.refcount(ECHO_TEST_IFINDEX),
            1,
            "no refcount churn while Echo stays active",
        );
    }

    /// Identical Echo params on re-subscribe are a no-op: no refcount
    /// churn, the originator keeps running undisturbed.
    #[tokio::test]
    async fn resubscribe_same_echo_params_is_noop() {
        let mut bfd = fresh_bfd();
        let key = echo_key(11);
        let (tx, _rx) = mpsc::unbounded_channel();
        bfd.subscribe("isis".into(), key, echo_params(EchoMode::Both, 50, 50), tx);
        force_up_with_peer_echo(&mut bfd, &key);
        bfd.echo_originate_reconcile(key);

        let (tx2, _rx2) = mpsc::unbounded_channel();
        bfd.subscribe("isis".into(), key, echo_params(EchoMode::Both, 50, 50), tx2);

        let s = bfd.sessions.get_by_key(&key).unwrap();
        assert!(s.echo_originating, "originator untouched");
        assert_eq!(bfd.reflectors.refcount(ECHO_TEST_IFINDEX), 1);
    }

    /// Control-plane timing stays create-time-only on re-subscribe (a live
    /// change would need an RFC 5880 §6.8.3 Poll Sequence); only the Echo
    /// fields are applied.
    #[tokio::test]
    async fn resubscribe_keeps_control_timing() {
        let mut bfd = fresh_bfd();
        let key = echo_key(12);
        let (tx, _rx) = mpsc::unbounded_channel();
        bfd.subscribe("isis".into(), key, SessionParams::default(), tx);

        let retimed = SessionParams {
            desired_min_tx_us: 1_000_000,
            required_min_rx_us: 1_000_000,
            detect_mult: 5,
            ..echo_params(EchoMode::Receive, 50, 0)
        };
        let (tx2, _rx2) = mpsc::unbounded_channel();
        bfd.subscribe("isis".into(), key, retimed, tx2);

        let s = bfd.sessions.get_by_key(&key).unwrap();
        let defaults = SessionParams::default();
        assert_eq!(s.desired_min_tx_us, defaults.desired_min_tx_us);
        assert_eq!(s.required_min_rx_us, defaults.required_min_rx_us);
        assert_eq!(s.detect_mult, defaults.detect_mult);
        assert_eq!(s.echo_mode, EchoMode::Receive, "echo fields did apply");
        assert_eq!(s.required_min_echo_rx_us, 50_000);
    }

    /// Where several clients share one session the last writer's Echo
    /// params win — a second subscriber with Echo off silences the first
    /// subscriber's Echo. (Previously the first writer's params were
    /// frozen for the session's lifetime.)
    #[tokio::test]
    async fn second_subscriber_echo_params_win() {
        let mut bfd = fresh_bfd();
        let key = echo_key(13);
        let (tx_a, _rx_a) = mpsc::unbounded_channel();
        bfd.subscribe(
            "isis".into(),
            key,
            echo_params(EchoMode::Both, 50, 50),
            tx_a,
        );
        assert_eq!(bfd.reflectors.refcount(ECHO_TEST_IFINDEX), 1);

        let (tx_b, _rx_b) = mpsc::unbounded_channel();
        bfd.subscribe("ospf".into(), key, SessionParams::default(), tx_b);

        let s = bfd.sessions.get_by_key(&key).unwrap();
        assert_eq!(s.echo_mode, EchoMode::Off, "last writer wins");
        assert_eq!(bfd.reflectors.refcount(ECHO_TEST_IFINDEX), 0);
        assert_eq!(
            bfd.subscribers.get(&key).map(BTreeMap::len),
            Some(2),
            "both clients stay subscribed",
        );
    }
}
