//! STAMP instance — Session-Sender, implicit Session-Reflector, and
//! the client-subscription registry.
//!
//! One instance per daemon (default VRF), spawned eagerly by the
//! `router isis` / `router ospf` commit arms so the IGPs can pick up
//! `stamp_client_tx` at their own spawn time — the same lifecycle as
//! BFD. The instance owns:
//!
//!   * the wildcard reflector sockets (`0.0.0.0:862` and, when it
//!     binds, `[::]:862`) with their read/write tasks — the **implicit
//!     reflector**: a probe is answered iff its source is the remote of
//!     a registered session (measurement enabled on both ends of the
//!     link, plan §2); the reply is routed back over the write loop of
//!     the probe's address family;
//!   * one connected sender socket + reply-read task + prober task per
//!     session;
//!   * the per-session subscriber registry fanning damped
//!     [`StampEvent::MetricUpdate`]s out to the IGPs.
//!
//! Delay math (plan D1): `delay = ((T4−T1) − (T3−T2)) / 2` — the
//! reflector residence term uses only the peer's clock, so the clock
//! offset between the two systems cancels; no synchronisation is
//! required. Samples that compute negative or over 10 s (a wall-clock
//! step mid-probe) are discarded and counted.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use std::time::Duration;

use stamp_packet::{ErrorEstimate, ReflectorPacket, SenderPacket, StampTimestamp};
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use crate::config::{
    Args, ConfigChannel, ConfigRequest, DisplayRequest, ShowChannel, path_from_command,
};
use crate::context::{ProtoContext, Task};

use super::client::{ClientId, ClientReq, ClientReqChannel, StampEvent, Subscriber};
use super::network::{
    ReflectRequest, reflector_read, reflector_read_v6, reflector_write, reflector_write_v6,
    sender_read,
};
use super::reflector::build_reply;
use super::sender::{ProberCmd, ProberHandle, session_prober};
use super::session::{Session, SessionKey, SessionParams, SessionTable};
use super::socket::{
    stamp_reflector_socket, stamp_reflector_socket_v6, stamp_sender_socket, stamp_sender_socket_v6,
};
use super::timestamp::{delta_micros, now_ntp};

/// `show <path>` dispatch handler — mirrors [`crate::bfd::inst::ShowCallback`].
pub type ShowCallback = fn(&Stamp, Args, bool) -> Result<String, std::fmt::Error>;

/// Discard a computed delay above this (10 s): the wall clock stepped
/// while the probe was in flight.
const MAX_PLAUSIBLE_DELAY_US: i64 = 10_000_000;

/// The Error Estimate this implementation advertises (RFC 8762 §4.2.1):
/// unsynchronised (`S=0`), NTP format (`Z=0`), and the coarsest honest
/// accuracy claim — `Multiplier` must be non-zero per RFC 4656 §4.1.2.
pub fn local_error_estimate() -> ErrorEstimate {
    ErrorEstimate {
        synced: false,
        format: stamp_packet::TimestampFormat::Ntp,
        scale: 0,
        multiplier: 1,
    }
}

/// Reflector-side packet counters for `show stamp statistics`. The
/// per-source halves live on the matching [`Session`]
/// (`reflected_count`) so an XDP helper can substitute per-session map
/// readouts later (offload notes §9b R5).
#[derive(Debug, Default)]
pub struct ReflectorStats {
    /// Parsed probes that reached the event loop.
    pub rx: u64,
    /// Probes answered.
    pub reflected: u64,
    /// Probes dropped by the implicit allow-list (source is not a
    /// registered session's remote).
    pub unauthorized: u64,
    /// Reflected probes whose T2 (receive timestamp echoed to the peer)
    /// came from a kernel `SO_TIMESTAMPING` stamp.
    pub t2_kernel: u64,
    /// Reflected probes whose T2 fell back to a userspace read.
    pub t2_userspace: u64,
}

/// How long a session whose socket could not be created waits before
/// the next creation attempt (see [`Stamp::retry_pending`]).
const SESSION_RETRY_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Debug)]
pub enum Message {
    /// A Session-Sender probe arrived on the reflector socket. `rx_ts`
    /// (T2) was stamped at the socket read; `len` is the UDP payload
    /// length for RFC 6038 symmetric-size replies.
    ProbeRecv {
        probe: SenderPacket,
        src: SocketAddr,
        dst: Option<IpAddr>,
        ifindex: u32,
        ttl: u8,
        rx_ts: StampTimestamp,
        /// `true` when `rx_ts` (T2) is a kernel `SO_TIMESTAMPING` stamp,
        /// `false` when it fell back to a userspace read.
        t2_kernel: bool,
        len: usize,
    },
    /// A reflected reply arrived on `key`'s connected socket; `t4` was
    /// stamped at the socket read.
    ReplyRecv {
        key: SessionKey,
        reply: ReflectorPacket,
        t4: StampTimestamp,
        /// `true` when `t4` is a kernel `SO_TIMESTAMPING` stamp, `false`
        /// when it fell back to a userspace read.
        t4_kernel: bool,
        /// Monotonic time of the socket read — the reply's receive time
        /// for the loss deadline, on the same clock as a probe's send
        /// time. Taken at the read, so event-loop queueing cannot make a
        /// timely reply late.
        rx_at: std::time::Instant,
    },
    /// Probe transmit timer fired for `key`.
    TxTick { key: SessionKey },
    /// Export (damping-period) timer fired for `key`.
    ExportTick { key: SessionKey },
    /// Loss clock fired for `key`: close its current loss bucket. A
    /// separate clock from `ExportTick` (measured-loss design D4).
    LossTick { key: SessionKey },
    /// Retry timer fired: re-attempt every parked session creation.
    RetryPending,
}

/// Top-level STAMP instance.
pub struct Stamp {
    pub rx: UnboundedReceiver<Message>,
    /// Socket factory context, kept for per-session sender sockets
    /// created at subscribe time.
    ctx: ProtoContext,
    pub sessions: SessionTable,
    /// Local address the reflector socket was bound to — tests bind
    /// ephemeral ports and need to learn the kernel's choice.
    pub local_addr: SocketAddrV4,
    /// Local address the IPv6 reflector socket bound to, when one was
    /// requested and the bind succeeded (the `[::]:862` listener is
    /// non-fatal — `None` means v6 sessions can't be reflected).
    pub local_addr_v6: Option<SocketAddrV6>,
    /// Config-manager subscription endpoints. STAMP has no own config;
    /// every commit broadcast is drained (registering as a
    /// config client also lets the manager see the task is running).
    pub cm: ConfigChannel,
    /// `show stamp ...` endpoints, dispatched through [`Self::show_cb`].
    pub show: ShowChannel,
    pub show_cb: HashMap<String, ShowCallback>,
    /// Inbound client request channel — the IGPs send
    /// [`ClientReq::Subscribe`] / `Unsubscribe` here.
    pub client_req: ClientReqChannel,
    subscribers: HashMap<SessionKey, BTreeMap<ClientId, Subscriber>>,
    main_tx: UnboundedSender<Message>,
    reflect_tx: UnboundedSender<ReflectRequest>,
    /// Reply queue for the IPv6 reflector write loop; `None` when no
    /// `[::]:862` listener bound (so v6 probes can't be answered).
    reflect_tx_v6: Option<UnboundedSender<ReflectRequest>>,
    probers: HashMap<SessionKey, ProberHandle>,
    /// Sessions whose creation failed (`add_session` error) while a
    /// subscriber still wants them, with the params to retry with.
    /// Retried on every [`Message::RetryPending`] tick until the socket
    /// comes up or the last subscriber leaves.
    pending: BTreeMap<SessionKey, SessionParams>,
    /// One-shot timer that sends [`Message::RetryPending`]; `None`
    /// while nothing is parked.
    retry_timer: Option<Task<()>>,
    pub reflector_stats: ReflectorStats,
}

impl Stamp {
    /// Production constructor — binds the reflectors to `0.0.0.0:862`
    /// and `[::]:862` (the latter non-fatal).
    pub fn new(ctx: ProtoContext) -> std::io::Result<Self> {
        Self::new_with(
            ctx,
            SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, stamp_packet::STAMP_UDP_PORT),
            Some(SocketAddrV6::new(
                Ipv6Addr::UNSPECIFIED,
                stamp_packet::STAMP_UDP_PORT,
                0,
                0,
            )),
        )
    }

    /// Explicit constructor letting the caller pick the reflector bind
    /// addresses (the integration test runs on loopback ephemeral
    /// ports and aims a session's `dst_port` at one). `bind_v6` is
    /// `None` to skip the IPv6 listener entirely (the v4-only unit
    /// tests); when `Some`, a bind failure is logged and swallowed —
    /// v4 measurement must not depend on v6 being available.
    pub fn new_with(
        ctx: ProtoContext,
        bind: SocketAddrV4,
        bind_v6: Option<SocketAddrV6>,
    ) -> std::io::Result<Self> {
        let sock = stamp_reflector_socket(&ctx, bind)?;
        let local_addr = sock
            .local_addr()?
            .as_socket_ipv4()
            .ok_or_else(|| std::io::Error::other("bound socket has no IPv4 local address"))?;
        let sock = Arc::new(AsyncFd::new(sock)?);

        let (main_tx, rx) = mpsc::unbounded_channel::<Message>();
        let (reflect_tx, reflect_rx) = mpsc::unbounded_channel::<ReflectRequest>();

        let read_sock = sock.clone();
        let read_tx = main_tx.clone();
        tokio::spawn(async move {
            reflector_read(read_sock, read_tx).await;
        });
        tokio::spawn(async move {
            reflector_write(sock, reflect_rx).await;
        });

        // IPv6 reflector: non-fatal. Any failure (bind denied, no v6 in
        // the namespace) just disables v6 reflection; `reflect_tx_v6`
        // stays `None` and v4 keeps working.
        let (reflect_tx_v6, local_addr_v6) = match bind_v6 {
            Some(b6) => match Self::spawn_v6_reflector(&ctx, b6, &main_tx) {
                Ok((tx6, addr6)) => (Some(tx6), Some(addr6)),
                Err(e) => {
                    tracing::warn!(bind = %b6, error = %e, "stamp: IPv6 reflector unavailable; v6 sessions disabled");
                    (None, None)
                }
            },
            None => (None, None),
        };

        let mut stamp = Self {
            rx,
            ctx,
            sessions: SessionTable::new(),
            local_addr,
            local_addr_v6,
            cm: ConfigChannel::new(),
            show: ShowChannel::new(),
            show_cb: HashMap::new(),
            client_req: ClientReqChannel::new(),
            subscribers: HashMap::new(),
            main_tx,
            reflect_tx,
            reflect_tx_v6,
            probers: HashMap::new(),
            pending: BTreeMap::new(),
            retry_timer: None,
            reflector_stats: ReflectorStats::default(),
        };
        stamp.show_build();
        Ok(stamp)
    }

    /// Build the IPv6 reflector socket, spawn its read/write loops, and
    /// return the reply queue plus the bound address. Split out so the
    /// whole v6 setup is one fallible unit `new_with` can treat as
    /// non-fatal.
    fn spawn_v6_reflector(
        ctx: &ProtoContext,
        bind: SocketAddrV6,
        main_tx: &UnboundedSender<Message>,
    ) -> std::io::Result<(UnboundedSender<ReflectRequest>, SocketAddrV6)> {
        let sock = stamp_reflector_socket_v6(ctx, bind)?;
        let local_addr = sock
            .local_addr()?
            .as_socket_ipv6()
            .ok_or_else(|| std::io::Error::other("bound socket has no IPv6 local address"))?;
        let sock = Arc::new(AsyncFd::new(sock)?);

        let (reflect_tx, reflect_rx) = mpsc::unbounded_channel::<ReflectRequest>();
        let read_sock = sock.clone();
        let read_tx = main_tx.clone();
        tokio::spawn(async move {
            reflector_read_v6(read_sock, read_tx).await;
        });
        tokio::spawn(async move {
            reflector_write_v6(sock, reflect_rx).await;
        });
        Ok((reflect_tx, local_addr))
    }

    /// Clone the inbound client-request sender for distribution to the
    /// IGPs (published on the ConfigManager by `spawn_stamp`).
    pub fn client_req_tx(&self) -> UnboundedSender<ClientReq> {
        self.client_req.tx.clone()
    }

    /// Apply a [`ClientReq`]. Public so pre-`serve` callers (the
    /// integration test) can drive the API directly.
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

    /// Add `client` as a subscriber on `key`, creating the session on
    /// the first subscriber and retuning its *timing* on a params
    /// change (last-writer-wins, plan D11). `params.anomaly` is not
    /// shared: it is stored on this subscriber's record, so another
    /// IGP's thresholds can neither disable nor impose this one's.
    ///
    /// The current exported value, if any, is mirrored to the new
    /// subscriber so a late-joining IGP advertises without waiting a
    /// full damping period — evaluated against its own bounds, which
    /// also seeds its hysteresis.
    pub fn subscribe(
        &mut self,
        client: ClientId,
        key: SessionKey,
        params: SessionParams,
        notifier: UnboundedSender<StampEvent>,
    ) {
        if self.sessions.get(&key).is_none() {
            match self.add_session(key, params) {
                Ok(()) => {
                    self.pending.remove(&key);
                }
                Err(e) => {
                    // A transient socket failure must not strand the
                    // subscriber for the life of the adjacency: the IGP
                    // never re-subscribes on its own (its key is stable
                    // while the neighbor stays Up), so a creation that
                    // fails once used to leave the link unmeasured
                    // forever. Seen live as EADDRNOTAVAIL binding a v6
                    // link-local that was still tentative under DAD.
                    // Keep the subscription (unsubscribe stays
                    // symmetric), park the params, and retry on the
                    // pending tick until the socket comes up or the
                    // last subscriber leaves.
                    if self.pending.insert(key, params).is_none() {
                        tracing::warn!(
                            ?key, error = %e,
                            "stamp: cannot create session, will retry"
                        );
                    } else {
                        tracing::debug!(?key, error = %e, "stamp: session retry failed");
                    }
                    self.arm_retry_timer();
                }
            }
        } else {
            self.update_params(&key, params);
        }
        let subs = self.subscribers.entry(key).or_default();
        // Re-subscribe (a config edit) keeps the accumulated
        // hysteresis but adopts the new bounds; a first subscribe
        // starts clean.
        match subs.get_mut(&client) {
            Some(existing) => {
                existing.notifier = notifier;
                existing.thresholds = params.anomaly;
            }
            None => {
                subs.insert(client.clone(), Subscriber::new(notifier, params.anomaly));
            }
        }
        let mirrored = self.sessions.get(&key).and_then(|s| s.last_snapshot);
        if mirrored.is_some()
            && let Some(sub) = self
                .subscribers
                .get_mut(&key)
                .and_then(|m| m.get_mut(&client))
        {
            let snapshot = sub.apply(mirrored);
            if let Some(snap) = snapshot {
                sub.last_flags = snap.anomaly;
            }
            let _ = sub
                .notifier
                .send(StampEvent::MetricUpdate { key, snapshot });
        }
    }

    /// Drop `client`'s subscription on `key`; the last unsubscribe
    /// tears the session down.
    pub fn unsubscribe(&mut self, client: &str, key: &SessionKey) {
        let now_empty = if let Some(subs) = self.subscribers.get_mut(key) {
            subs.remove(client);
            subs.is_empty()
        } else {
            return;
        };
        if now_empty {
            self.subscribers.remove(key);
            self.pending.remove(key);
            self.remove_session(key);
        }
    }

    /// Arm the one-shot [`Message::RetryPending`] timer unless one is
    /// already running. The task handle is held so despawning the
    /// instance aborts it.
    fn arm_retry_timer(&mut self) {
        if self.retry_timer.is_some() {
            return;
        }
        let tx = self.main_tx.clone();
        self.retry_timer = Some(Task::spawn(async move {
            tokio::time::sleep(SESSION_RETRY_INTERVAL).await;
            let _ = tx.send(Message::RetryPending);
        }));
    }

    /// [`Message::RetryPending`]: re-attempt every parked session
    /// creation. Entries whose subscribers have all left (or that got
    /// created meanwhile) are dropped; the timer is re-armed while
    /// anything remains parked.
    fn retry_pending(&mut self) {
        self.retry_timer = None;
        let parked: Vec<(SessionKey, SessionParams)> =
            self.pending.iter().map(|(k, p)| (*k, *p)).collect();
        for (key, params) in parked {
            if !self.subscribers.contains_key(&key) || self.sessions.get(&key).is_some() {
                self.pending.remove(&key);
                continue;
            }
            match self.add_session(key, params) {
                Ok(()) => {
                    self.pending.remove(&key);
                    tracing::info!(?key, "stamp: session created on retry");
                }
                Err(e) => {
                    tracing::debug!(?key, error = %e, "stamp: session retry failed");
                }
            }
        }
        if !self.pending.is_empty() {
            self.arm_retry_timer();
        }
    }

    /// Create the session: connected sender socket, reply-read task,
    /// prober task.
    fn add_session(&mut self, key: SessionKey, params: SessionParams) -> std::io::Result<()> {
        // One connected sender socket, v4 or v6 by the key's family. For
        // v6 the scope id (`key.ifindex`) rides on both endpoints so a
        // link-local 4-tuple is unambiguous across interfaces.
        let sock = match (key.local, key.remote) {
            (IpAddr::V4(local), IpAddr::V4(remote)) => stamp_sender_socket(
                &self.ctx,
                SocketAddrV4::new(local, 0),
                SocketAddrV4::new(remote, params.dst_port),
            )?,
            (IpAddr::V6(local), IpAddr::V6(remote)) => stamp_sender_socket_v6(
                &self.ctx,
                SocketAddrV6::new(local, 0, 0, key.ifindex),
                SocketAddrV6::new(remote, params.dst_port, 0, key.ifindex),
            )?,
            _ => {
                return Err(std::io::Error::other(
                    "stamp: session key mixes IPv4 and IPv6 addresses",
                ));
            }
        };
        let sock = Arc::new(AsyncFd::new(sock)?);

        let read_sock = sock.clone();
        let read_tx = self.main_tx.clone();
        let read_task = Task::spawn(async move {
            sender_read(key, read_sock, read_tx).await;
        });

        let ssid = self.sessions.alloc_ssid();
        self.sessions
            .insert(Session::new(key, params, ssid, sock, read_task));

        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let main_tx = self.main_tx.clone();
        let task = Task::spawn(session_prober(key, params, cmd_rx, main_tx));
        self.probers.insert(
            key,
            ProberHandle {
                cmd_tx,
                _task: task,
            },
        );
        tracing::info!(?key, ssid, "stamp: session created");
        Ok(())
    }

    /// A later `Subscribe` carried different params: retune the live
    /// timers. A `dst_port` change needs a socket reconnect, so that
    /// (test-only) case recreates the session outright — counters and
    /// the current window restart, the exported value survives in the
    /// subscribers' hands.
    fn update_params(&mut self, key: &SessionKey, params: SessionParams) {
        let Some(session) = self.sessions.get_mut(key) else {
            return;
        };
        if session.params == params {
            return;
        }
        if session.params.dst_port != params.dst_port {
            self.remove_session(key);
            if let Err(e) = self.add_session(*key, params) {
                tracing::warn!(?key, error = %e, "stamp: session recreate failed");
            }
            return;
        }
        // Credit the loss buckets with the probes the *old* interval
        // should have produced so far, before the new one takes over.
        if session.params.interval_ms != params.interval_ms {
            session
                .loss
                .advance(std::time::Instant::now(), session.params.interval_ms);
        }
        session.params = params;
        if let Some(h) = self.probers.get(key) {
            let _ = h.cmd_tx.send(ProberCmd::Retune(params));
        }
    }

    fn remove_session(&mut self, key: &SessionKey) {
        if let Some(h) = self.probers.remove(key) {
            let _ = h.cmd_tx.send(ProberCmd::Shutdown);
        }
        if self.sessions.remove(key).is_some() {
            tracing::info!(?key, "stamp: session removed");
        }
    }

    /// Probe transmit timer fired: build and send one Session-Sender
    /// packet. T1 is stamped here — the single T1 build site (offload
    /// notes §9b R3). Direct nonblocking `send` on the connected
    /// socket: a full socket buffer drops the probe (counted), it must
    /// not delay the event loop.
    fn on_tx_tick(&mut self, key: SessionKey) {
        let Some(session) = self.sessions.get_mut(&key) else {
            return;
        };
        // Settle timed-out probes before sending, whether or not this
        // send succeeds, so a probe settles within one interval of its
        // loss deadline.
        let now = std::time::Instant::now();
        session.loss.sweep(now);
        let packet = SenderPacket {
            seq: session.next_seq,
            timestamp: now_ntp(), // T1
            error_estimate: local_error_estimate(),
            ssid: session.ssid,
            tlvs: vec![],
        };
        let mut buf = bytes::BytesMut::new();
        packet.emit(&mut buf);
        use std::os::fd::AsRawFd;
        let sent = nix::sys::socket::send(
            session.sock.get_ref().as_raw_fd(),
            &buf,
            nix::sys::socket::MsgFlags::empty(),
        );
        match sent {
            Ok(_) => {
                session.loss.sent(session.next_seq, now);
                session.next_seq = session.next_seq.wrapping_add(1);
                session.tx_count += 1;
            }
            Err(e) => {
                session.tx_failed_count += 1;
                tracing::debug!(?key, error = %e, "stamp: probe send failed");
            }
        }
    }

    /// A reflected reply came back on `key`'s connected socket: verify
    /// the SSID, compute the two-way delay (plan D1), record it.
    fn on_reply_recv(
        &mut self,
        key: SessionKey,
        reply: ReflectorPacket,
        t4: StampTimestamp,
        t4_kernel: bool,
        rx_at: std::time::Instant,
    ) {
        let Some(session) = self.sessions.get_mut(&key) else {
            return;
        };
        if reply.ssid != session.ssid {
            session.rx_invalid_count += 1;
            tracing::debug!(
                ?key,
                got = reply.ssid,
                want = session.ssid,
                "stamp: reply SSID mismatch"
            );
            return;
        }
        // Loss accounting comes before the delay checks (measured-loss
        // design D2): the reply came back, so its probe was not lost —
        // whatever its timestamps say. A timestamp fault is a delay
        // problem, rejected below as before.
        session.loss.reply(reply.sender_seq, rx_at);
        // delay = ((T4−T1) − (T3−T2)) / 2. T1/T4 are this node's
        // clock, T2/T3 the reflector's — each difference is
        // same-clock, so the inter-node offset cancels.
        let rtt = delta_micros(t4, reply.sender_timestamp);
        let residence = delta_micros(reply.timestamp, reply.receive_timestamp);
        let delay = (rtt - residence) / 2;
        if !(0..=MAX_PLAUSIBLE_DELAY_US).contains(&delay) {
            session.rx_invalid_count += 1;
            tracing::debug!(?key, delay, "stamp: implausible delay sample discarded");
            return;
        }
        session.rx_count += 1;
        // Track the T4 source on accepted samples —
        // the figure of merit for "is kernel timestamping live".
        if t4_kernel {
            session.t4_kernel += 1;
        } else {
            session.t4_userspace += 1;
        }
        session.last_rx = Some(std::time::Instant::now());
        session.window.record_delay(delay as u32);
    }

    /// Loss clock fired: bring the session's loss ledger up to now,
    /// closing every bucket that has ended — more than one if ticks were
    /// skipped. Probe counts, not delay, so this runs regardless of the
    /// export gate.
    fn on_loss_tick(&mut self, key: SessionKey) {
        let Some(session) = self.sessions.get_mut(&key) else {
            return;
        };
        session
            .loss
            .advance(std::time::Instant::now(), session.params.interval_ms);
    }

    /// Export timer fired: snapshot the window, run the shared value
    /// filter, then evaluate each subscriber's Anomalous bits against
    /// its own thresholds and fan out to whoever has something new.
    ///
    /// Two gates, because they answer different questions. The damping
    /// gate asks whether the *values* moved enough to be worth
    /// re-flooding, and is shared — every subscriber sees the same
    /// samples. The flag comparison asks whether *this subscriber's*
    /// advertisement changed, and must be able to fire on its own: a
    /// link that degrades past the bound and then holds steady crosses
    /// the value filter once, so a later set or clear would otherwise
    /// be damped away by the very filter meant to suppress noise.
    fn on_export_tick(&mut self, key: SessionKey) {
        let Some(session) = self.sessions.get_mut(&key) else {
            return;
        };
        let snapshot = session.window.snapshot();
        session.window.reset();
        let values_changed = session.damping.should_export(snapshot);
        // Raw values, cached every tick — a flag-only export delivers
        // newer values than the filter's baseline, and a subscriber
        // that joins afterwards must be seeded from those. Each
        // subscriber's flags are its own, so none are cached here.
        session.last_snapshot = snapshot;
        let Some(subs) = self.subscribers.get_mut(&key) else {
            return;
        };
        for (client, sub) in subs.iter_mut() {
            let stamped = sub.apply(snapshot);
            let flags = stamped.map(|s| s.anomaly).unwrap_or_default();
            if !values_changed && flags == sub.last_flags {
                continue;
            }
            sub.last_flags = flags;
            tracing::info!(
                ?key,
                %client,
                ?stamped,
                "stamp: exporting metric update"
            );
            let _ = sub.notifier.send(StampEvent::MetricUpdate {
                key,
                snapshot: stamped,
            });
        }
    }

    /// Per-client anomaly policy and current flags on `key`, for
    /// `show stamp session`.
    pub(super) fn subscriber_rows(
        &self,
        key: &SessionKey,
    ) -> impl Iterator<Item = (&ClientId, &Subscriber)> {
        self.subscribers.get(key).into_iter().flatten()
    }

    /// A probe hit the reflector socket. Implicit allow-list (plan
    /// §2): reflect iff the source is a registered session's remote.
    /// The reply's source address is forced to the probed address and
    /// egress is pinned to the ingress interface — both required for
    /// the peer's connected-socket demux to accept the reply.
    fn on_probe_recv(
        &mut self,
        probe: SenderPacket,
        src: SocketAddr,
        dst: Option<IpAddr>,
        ifindex: u32,
        ttl: u8,
        rx_ts: StampTimestamp,
        t2_kernel: bool,
        len: usize,
    ) {
        self.reflector_stats.rx += 1;
        let Some(session_key) = self.sessions.reflect_allowed(src.ip(), ifindex) else {
            self.reflector_stats.unauthorized += 1;
            tracing::debug!(?src, "stamp: probe from unregistered source dropped");
            return;
        };
        let reply = build_reply(&probe, rx_ts, ttl, len);
        let req = ReflectRequest {
            reply,
            dst: src,
            src: dst,
            ifindex: (ifindex != 0).then_some(ifindex),
        };
        // Route the reply to the write loop of the probe's family. A v6
        // probe with no `[::]:862` listener (bind failed) can't be
        // answered — drop it without counting a reflection.
        let queued = match src {
            SocketAddr::V4(_) => self.reflect_tx.send(req).is_ok(),
            SocketAddr::V6(_) => match &self.reflect_tx_v6 {
                Some(tx) => tx.send(req).is_ok(),
                None => {
                    tracing::debug!(?src, "stamp: v6 probe but no v6 reflector socket; dropped");
                    false
                }
            },
        };
        if !queued {
            return;
        }
        self.reflector_stats.reflected += 1;
        // The T2 we just echoed is only as good as its source; track it
        // for `show stamp statistics` (helps the peer's numbers).
        if t2_kernel {
            self.reflector_stats.t2_kernel += 1;
        } else {
            self.reflector_stats.t2_userspace += 1;
        }
        if let Some(session) = self.sessions.get_mut(&session_key) {
            session.reflected_count += 1;
        }
    }

    /// STAMP has no own config — drain every broadcast.
    fn process_cm_msg(&mut self, _msg: ConfigRequest) {}

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
                    Message::ProbeRecv { probe, src, dst, ifindex, ttl, rx_ts, t2_kernel, len } =>
                        self.on_probe_recv(probe, src, dst, ifindex, ttl, rx_ts, t2_kernel, len),
                    Message::ReplyRecv { key, reply, t4, t4_kernel, rx_at } =>
                        self.on_reply_recv(key, reply, t4, t4_kernel, rx_at),
                    Message::TxTick { key } => self.on_tx_tick(key),
                    Message::ExportTick { key } => self.on_export_tick(key),
                    Message::LossTick { key } => self.on_loss_tick(key),
                    Message::RetryPending => self.retry_pending(),
                },
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
}

/// Spawn the event loop; dropping the returned [`Task`] aborts it
/// (see [`crate::config::stamp::despawn_stamp`]).
pub fn serve(mut stamp: Stamp) -> Task<()> {
    Task::spawn(async move {
        stamp.event_loop().await;
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_stamp() -> Stamp {
        // v4-only: these tests don't exercise the v6 reflector.
        Stamp::new_with(
            ProtoContext::default_table_no_rib(),
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
            None,
        )
        .expect("bind loopback")
    }

    fn loopback_key(remote_octet: u8) -> SessionKey {
        SessionKey {
            local: IpAddr::V4(Ipv4Addr::LOCALHOST),
            remote: IpAddr::V4(Ipv4Addr::new(127, 0, 0, remote_octet)),
            ifindex: 0,
        }
    }

    fn reply_for(session_ssid: u16, t1: StampTimestamp) -> ReflectorPacket {
        ReflectorPacket {
            ssid: session_ssid,
            sender_timestamp: t1,
            // Zero residence: T2 == T3.
            receive_timestamp: StampTimestamp::default(),
            timestamp: StampTimestamp::default(),
            ..ReflectorPacket::default()
        }
    }

    /// First subscribe creates the session (socket, ssid, prober);
    /// last unsubscribe removes it. A second client shares it.
    #[tokio::test]
    async fn subscribe_lifecycle_shares_session() {
        let mut stamp = fresh_stamp();
        let key = loopback_key(2);
        let (tx_a, _rx_a) = mpsc::unbounded_channel();
        let (tx_b, _rx_b) = mpsc::unbounded_channel();

        stamp.subscribe("isis".into(), key, SessionParams::default(), tx_a);
        assert_eq!(stamp.sessions.len(), 1);
        let ssid = stamp.sessions.get(&key).unwrap().ssid;
        assert_ne!(ssid, 0);

        stamp.subscribe("ospf".into(), key, SessionParams::default(), tx_b);
        assert_eq!(stamp.sessions.len(), 1, "same key shares one session");
        assert_eq!(stamp.sessions.get(&key).unwrap().ssid, ssid);

        stamp.unsubscribe("isis", &key);
        assert_eq!(stamp.sessions.len(), 1, "one subscriber remains");
        stamp.unsubscribe("ospf", &key);
        assert_eq!(stamp.sessions.len(), 0, "last unsubscribe tears down");
        assert!(stamp.probers.is_empty());
    }

    /// A session whose socket can't be created (here a local address
    /// that is on no interface — the shape of a v6 link-local still
    /// tentative under DAD) keeps its subscription and is parked for
    /// retry instead of being dropped; the last unsubscribe clears the
    /// parked entry so nothing retries a session nobody wants.
    #[tokio::test]
    async fn failed_create_is_parked_until_unsubscribe() {
        let mut stamp = fresh_stamp();
        // TEST-NET-1 (RFC 5737): never configured on a host interface,
        // so the sender bind fails with EADDRNOTAVAIL.
        let key = SessionKey {
            local: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            remote: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
            ifindex: 0,
        };
        let (tx, _rx) = mpsc::unbounded_channel();

        stamp.subscribe("isis".into(), key, SessionParams::default(), tx);
        assert!(stamp.sessions.get(&key).is_none(), "no socket, no session");
        assert_eq!(stamp.pending.get(&key), Some(&SessionParams::default()));
        assert!(stamp.subscribers.contains_key(&key), "subscription kept");
        assert!(stamp.retry_timer.is_some(), "retry armed");

        // The tick finds the address still unusable: stays parked,
        // timer re-armed.
        stamp.retry_pending();
        assert!(stamp.sessions.get(&key).is_none());
        assert!(stamp.pending.contains_key(&key));
        assert!(stamp.retry_timer.is_some(), "re-armed while parked");

        // Last unsubscribe drops the parked entry; the next tick has
        // nothing to do and does not re-arm.
        stamp.unsubscribe("isis", &key);
        assert!(stamp.pending.is_empty());
        stamp.retry_pending();
        assert!(stamp.retry_timer.is_none());
    }

    /// A later Subscribe with different timing retunes the stored
    /// params (last-writer-wins, D11).
    #[tokio::test]
    async fn second_subscribe_retunes_params() {
        let mut stamp = fresh_stamp();
        let key = loopback_key(2);
        let (tx_a, _rx_a) = mpsc::unbounded_channel();
        let (tx_b, _rx_b) = mpsc::unbounded_channel();

        stamp.subscribe("isis".into(), key, SessionParams::default(), tx_a);
        let faster = SessionParams {
            interval_ms: 100,
            damping_secs: 2,
            ..SessionParams::default()
        };
        stamp.subscribe("ospf".into(), key, faster, tx_b);
        assert_eq!(stamp.sessions.get(&key).unwrap().params, faster);
    }

    /// A subscriber joining after an export immediately hears the
    /// current value.
    #[tokio::test]
    async fn late_subscriber_gets_mirror() {
        let mut stamp = fresh_stamp();
        let key = loopback_key(2);
        let (tx_a, _rx_a) = mpsc::unbounded_channel();
        stamp.subscribe("isis".into(), key, SessionParams::default(), tx_a);

        // Feed two samples and force an export tick.
        let t1 = StampTimestamp {
            seconds: 100,
            fraction: 0,
        };
        let t4 = StampTimestamp {
            seconds: 100,
            fraction: 4_294_967, // ~1000 µs
        };
        let ssid = stamp.sessions.get(&key).unwrap().ssid;
        stamp.on_reply_recv(
            key,
            reply_for(ssid, t1),
            t4,
            false,
            std::time::Instant::now(),
        );
        stamp.on_export_tick(key);
        assert!(stamp.sessions.get(&key).unwrap().last_snapshot.is_some());

        let (tx_b, mut rx_b) = mpsc::unbounded_channel();
        stamp.subscribe("ospf".into(), key, SessionParams::default(), tx_b);
        let StampEvent::MetricUpdate { snapshot, .. } = rx_b.try_recv().expect("mirrored export");
        assert!(snapshot.is_some());
    }

    /// D1 math: rtt 1000 µs with 400 µs residence → 300 µs one-way
    /// estimate. SSID mismatches and negative delays are counted
    /// invalid and recorded nowhere.
    #[tokio::test]
    async fn reply_validation_and_delay_math() {
        let mut stamp = fresh_stamp();
        let key = loopback_key(2);
        let (tx, _rx) = mpsc::unbounded_channel();
        stamp.subscribe("isis".into(), key, SessionParams::default(), tx);
        let ssid = stamp.sessions.get(&key).unwrap().ssid;

        let us = |micros: u64| StampTimestamp {
            seconds: 100,
            fraction: ((micros << 32) / 1_000_000) as u32,
        };
        // T1=0, T2=200, T3=600, T4=1000 (µs into second 100).
        let reply = ReflectorPacket {
            ssid,
            sender_timestamp: us(0),
            receive_timestamp: us(200),
            timestamp: us(600),
            ..ReflectorPacket::default()
        };
        stamp.on_reply_recv(key, reply, us(1000), true, std::time::Instant::now());
        {
            let s = stamp.sessions.get(&key).unwrap();
            assert_eq!(s.rx_count, 1);
            // The accepted sample's T4 source is tracked (rung 1).
            assert_eq!(s.t4_kernel, 1);
            assert_eq!(s.t4_userspace, 0);
            let snap = s.window.snapshot().unwrap();
            assert!((299..=301).contains(&snap.min), "delay {}", snap.min);
        }

        // Wrong SSID → invalid.
        stamp.on_reply_recv(
            key,
            reply_for(ssid.wrapping_add(1), us(0)),
            us(1000),
            false,
            std::time::Instant::now(),
        );
        // Negative delay (T4 before T1) → invalid.
        stamp.on_reply_recv(
            key,
            reply_for(ssid, us(1000)),
            us(0),
            false,
            std::time::Instant::now(),
        );
        let s = stamp.sessions.get(&key).unwrap();
        assert_eq!(s.rx_invalid_count, 2);
        assert_eq!(s.rx_count, 1);
        // Rejected replies don't move the T4-source counters.
        assert_eq!(s.t4_kernel, 1);
        assert_eq!(s.t4_userspace, 0);
    }

    /// Measured-loss design D2: a reply settles its probe by the copied
    /// Session-Sender sequence number, and counts as received even when
    /// the delay path rejects its timestamps — a clock fault is not
    /// packet loss. A reply carrying another session's SSID settles
    /// nothing, so its probe still times out.
    #[tokio::test]
    async fn a_reply_with_bad_timestamps_still_settles_its_probe() {
        let mut stamp = fresh_stamp();
        let key = loopback_key(2);
        let (tx, _rx) = mpsc::unbounded_channel();
        stamp.subscribe("isis".into(), key, SessionParams::default(), tx);
        let ssid = stamp.sessions.get(&key).unwrap().ssid;
        let t0 = std::time::Instant::now();
        let s = stamp.sessions.get_mut(&key).unwrap();
        s.loss.sent(40, t0);
        s.loss.sent(41, t0);

        // T4 before T1: an implausible delay.
        let mut bad = reply_for(
            ssid,
            StampTimestamp {
                seconds: 200,
                fraction: 0,
            },
        );
        bad.sender_seq = 40;
        stamp.on_reply_recv(
            key,
            bad,
            StampTimestamp {
                seconds: 100,
                fraction: 0,
            },
            false,
            t0 + Duration::from_millis(5),
        );
        // The right sequence number, but not this session's SSID.
        let mut foreign = reply_for(ssid.wrapping_add(1), StampTimestamp::default());
        foreign.sender_seq = 41;
        stamp.on_reply_recv(
            key,
            foreign,
            StampTimestamp::default(),
            false,
            t0 + Duration::from_millis(6),
        );

        let s = stamp.sessions.get_mut(&key).unwrap();
        assert_eq!(s.rx_invalid_count, 2, "the delay path rejected both");
        assert_eq!(s.rx_count, 0);
        let interval = s.params.interval_ms;
        s.loss.advance(t0 + Duration::from_secs(30), interval);
        let w = s.loss.window(1);
        assert_eq!(
            (w.settled, w.lost),
            (2, 1),
            "40 received despite its timestamps; 41 timed out"
        );

        // The deadline is judged at the socket read, not at processing:
        // a reply read 0.5 s after its probe, but processed 10 s later
        // behind a backlog, is still received.
        let now = std::time::Instant::now();
        s.loss.sent(42, now - Duration::from_secs(10));
        let mut queued = reply_for(ssid, StampTimestamp::default());
        queued.sender_seq = 42;
        stamp.on_reply_recv(
            key,
            queued,
            StampTimestamp::default(),
            false,
            now - Duration::from_millis(9_500),
        );
        let s = stamp.sessions.get(&key).unwrap();
        assert_eq!(s.loss.late, 0, "read in time, so not late");
    }

    /// A probe that went out is in the ledger under the sequence number
    /// it carried, and the loss clock advances the ledger to now at the
    /// session's interval — closing every bucket that has ended, here
    /// two on a ledger backdated 61 s.
    #[tokio::test]
    async fn a_sent_probe_enters_the_ledger_and_the_loss_tick_advances_it() {
        use crate::stamp::loss::{LossLedger, ReplyFate};
        let mut stamp = fresh_stamp();
        let key = loopback_key(2);
        let (tx, _rx) = mpsc::unbounded_channel();
        stamp.subscribe("isis".into(), key, SessionParams::default(), tx);
        stamp.on_tx_tick(key);
        let s = stamp.sessions.get_mut(&key).unwrap();
        assert_eq!(
            s.tx_count, 1,
            "probe sent (tx-failed {})",
            s.tx_failed_count
        );
        assert_eq!(
            s.loss.reply(0, std::time::Instant::now()),
            ReplyFate::Received
        );
        s.loss = LossLedger::new(std::time::Instant::now() - Duration::from_secs(61));
        stamp.on_loss_tick(key);
        let w = stamp.sessions.get(&key).unwrap().loss.window(4);
        assert_eq!(w.buckets, 2);
        assert_eq!(
            w.expected_milli, 60_000,
            "two 30 s buckets at the 1 s default"
        );
    }

    /// A probe-interval retune credits the open bucket at the *old* rate
    /// before switching (design D4), and keeps the closed buckets. A
    /// retune that leaves the interval alone accrues nothing.
    #[tokio::test]
    async fn a_retune_accrues_at_the_old_rate_and_keeps_the_buckets() {
        let mut stamp = fresh_stamp();
        let key = loopback_key(2);
        let (tx, _rx) = mpsc::unbounded_channel();
        stamp.subscribe("isis".into(), key, SessionParams::default(), tx.clone());
        // Backdated 31 s, so the tick closes the first bucket.
        stamp.sessions.get_mut(&key).unwrap().loss = crate::stamp::loss::LossLedger::new(
            std::time::Instant::now() - Duration::from_secs(31),
        );
        stamp.on_loss_tick(key);
        let before = stamp.sessions.get(&key).unwrap().loss.mark();
        tokio::time::sleep(Duration::from_millis(2)).await;

        let damping_only = SessionParams {
            damping_secs: 60,
            ..SessionParams::default()
        };
        stamp.subscribe("isis".into(), key, damping_only, tx.clone());
        assert_eq!(stamp.sessions.get(&key).unwrap().loss.mark(), before);

        let faster = SessionParams {
            interval_ms: 100,
            ..damping_only
        };
        stamp.subscribe("isis".into(), key, faster, tx);
        let s = stamp.sessions.get(&key).unwrap();
        assert!(
            s.loss.mark() > before,
            "accrued before the interval changed"
        );
        assert_eq!(s.loss.window(1).buckets, 1, "closed buckets survive");
    }

    /// The implicit reflector only answers registered remotes: an
    /// unknown source bumps `unauthorized`, a registered one
    /// `reflected` plus the session's own counter.
    #[tokio::test]
    async fn reflector_allow_list() {
        let mut stamp = fresh_stamp();
        let key = loopback_key(2);
        let (tx, _rx) = mpsc::unbounded_channel();
        stamp.subscribe("isis".into(), key, SessionParams::default(), tx);

        let probe = SenderPacket::default();
        let unknown = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 99), 5000));
        stamp.on_probe_recv(
            probe.clone(),
            unknown,
            None,
            0,
            255,
            StampTimestamp::default(),
            false,
            stamp_packet::BASE_LEN,
        );
        assert_eq!(stamp.reflector_stats.unauthorized, 1);
        assert_eq!(stamp.reflector_stats.reflected, 0);
        // Dropped (unauthorized) probes don't move the T2-source counters.
        assert_eq!(stamp.reflector_stats.t2_kernel, 0);
        assert_eq!(stamp.reflector_stats.t2_userspace, 0);

        let registered = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 2), 5000));
        stamp.on_probe_recv(
            probe,
            registered,
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            0,
            255,
            StampTimestamp::default(),
            true,
            stamp_packet::BASE_LEN,
        );
        assert_eq!(stamp.reflector_stats.reflected, 1);
        // The echoed T2's source is tracked on the reflected path.
        assert_eq!(stamp.reflector_stats.t2_kernel, 1);
        assert_eq!(stamp.sessions.get(&key).unwrap().reflected_count, 1);
    }

    /// Export ticks respect damping: identical windows export once;
    /// an empty window after an export clears (None) exactly once.
    #[tokio::test]
    async fn export_damping_and_clear() {
        let mut stamp = fresh_stamp();
        let key = loopback_key(2);
        let (tx, mut rx) = mpsc::unbounded_channel();
        stamp.subscribe("isis".into(), key, SessionParams::default(), tx);
        let ssid = stamp.sessions.get(&key).unwrap().ssid;

        let us = |micros: u64| StampTimestamp {
            seconds: 100,
            fraction: ((micros << 32) / 1_000_000) as u32,
        };
        let feed = |stamp: &mut Stamp| {
            stamp.on_reply_recv(
                key,
                reply_for(ssid, us(0)),
                us(1000),
                false,
                std::time::Instant::now(),
            );
        };

        feed(&mut stamp);
        stamp.on_export_tick(key); // first export
        feed(&mut stamp);
        stamp.on_export_tick(key); // same value → damped
        stamp.on_export_tick(key); // empty window → clear
        stamp.on_export_tick(key); // still empty → quiet

        let mut updates = Vec::new();
        while let Ok(StampEvent::MetricUpdate { snapshot, .. }) = rx.try_recv() {
            updates.push(snapshot);
        }
        assert_eq!(updates.len(), 2, "one export + one clear, got {updates:?}");
        assert!(updates[0].is_some());
        assert!(updates[1].is_none());
        assert!(stamp.sessions.get(&key).unwrap().last_snapshot.is_none());
    }

    /// Params carrying an anomaly policy, for the per-subscriber tests.
    fn params_with_threshold(anomaly_us: Option<u32>) -> SessionParams {
        SessionParams {
            anomaly: crate::stamp::anomaly::AnomalyThresholds {
                anomaly_us,
                reuse_us: None,
            },
            ..Default::default()
        }
    }

    /// Two IGPs share one session but configure the anomaly threshold
    /// separately. Neither may impose its policy on, or disable it
    /// for, the other — whichever order they subscribe in.
    #[tokio::test]
    async fn anomaly_policy_is_per_subscriber() {
        for isis_first in [true, false] {
            let mut stamp = fresh_stamp();
            let key = loopback_key(2);
            let (isis_tx, mut isis_rx) = mpsc::unbounded_channel();
            let (ospf_tx, mut ospf_rx) = mpsc::unbounded_channel();

            // IS-IS wants anomalies at 1 us; OSPF configured none.
            let subs: Vec<(&str, SessionParams, _)> = if isis_first {
                vec![
                    ("isis", params_with_threshold(Some(1)), isis_tx),
                    ("ospf", params_with_threshold(None), ospf_tx),
                ]
            } else {
                vec![
                    ("ospf", params_with_threshold(None), ospf_tx),
                    ("isis", params_with_threshold(Some(1)), isis_tx),
                ]
            };
            for (client, params, tx) in subs {
                stamp.subscribe(client.into(), key, params, tx);
            }

            let ssid = stamp.sessions.get(&key).unwrap().ssid;
            let us = |micros: u64| StampTimestamp {
                seconds: 100,
                fraction: ((micros << 32) / 1_000_000) as u32,
            };
            stamp.on_reply_recv(
                key,
                reply_for(ssid, us(0)),
                us(1000),
                false,
                std::time::Instant::now(),
            );
            stamp.on_export_tick(key);

            let isis_snap = match isis_rx.try_recv() {
                Ok(StampEvent::MetricUpdate { snapshot, .. }) => snapshot.expect("value"),
                other => panic!("isis got {other:?}"),
            };
            let ospf_snap = match ospf_rx.try_recv() {
                Ok(StampEvent::MetricUpdate { snapshot, .. }) => snapshot.expect("value"),
                other => panic!("ospf got {other:?}"),
            };

            assert_eq!(
                (isis_snap.min, isis_snap.max),
                (ospf_snap.min, ospf_snap.max),
                "isis_first={isis_first}: the samples are shared"
            );
            assert!(
                isis_snap.anomaly.avg && isis_snap.anomaly.max,
                "isis_first={isis_first}: IS-IS configured a 1us bound"
            );
            assert_eq!(
                ospf_snap.anomaly,
                crate::stamp::anomaly::AnomalyFlags::default(),
                "isis_first={isis_first}: OSPF configured none, so it advertises none"
            );
        }
    }

    /// A flag-only export carries values the numeric filter damped, so
    /// the cache the next subscriber is seeded from has to advance
    /// too. Otherwise a late-joining IGP evaluates its bits against a
    /// stale measurement and advertises a clear bit while its peer
    /// subscriber is advertising a set one.
    #[tokio::test]
    async fn late_subscriber_is_seeded_from_the_current_measurement() {
        let mut stamp = fresh_stamp();
        let key = loopback_key(2);
        let (isis_tx, mut isis_rx) = mpsc::unbounded_channel();
        let policy = params_with_threshold(Some(1_000));
        stamp.subscribe("isis".into(), key, policy, isis_tx);

        let ssid = stamp.sessions.get(&key).unwrap().ssid;
        let us = |micros: u64| StampTimestamp {
            seconds: 100,
            fraction: ((micros << 32) / 1_000_000) as u32,
        };
        // The reply stamps T2 == T3 == 0, so delay = (T4 - T1) / 2 —
        // feed twice the delay the window should record.
        let feed = |stamp: &mut Stamp, delay_us: u64| {
            stamp.on_reply_recv(
                key,
                reply_for(ssid, us(0)),
                us(delay_us * 2),
                false,
                std::time::Instant::now(),
            );
        };

        // Just inside the bound: exported, bits clear.
        feed(&mut stamp, 990);
        stamp.on_export_tick(key);
        // Just outside it. The move is 20 us against a 99 us filter
        // threshold, so the values are damped and only the flag flip
        // pushes this export out.
        feed(&mut stamp, 1_010);
        stamp.on_export_tick(key);

        let mut delivered = Vec::new();
        while let Ok(StampEvent::MetricUpdate { snapshot, .. }) = isis_rx.try_recv() {
            delivered.push(snapshot.expect("value"));
        }
        assert_eq!(delivered.len(), 2, "first export + the flag flip");
        assert!(delivered[1].anomaly.avg, "1010us is over the bound");

        // OSPF joins now, with the identical policy. It must see what
        // IS-IS is advertising, not the pre-crossing sample.
        let (ospf_tx, mut ospf_rx) = mpsc::unbounded_channel();
        stamp.subscribe("ospf".into(), key, policy, ospf_tx);
        let seeded = match ospf_rx.try_recv() {
            Ok(StampEvent::MetricUpdate { snapshot, .. }) => snapshot.expect("mirrored"),
            other => panic!("ospf got {other:?}"),
        };
        // Exactly what IS-IS last saw, not the pre-crossing sample
        // the value filter is still using as its baseline.
        assert_eq!(
            seeded.avg, delivered[1].avg,
            "seeded from the current measurement"
        );
        assert_ne!(seeded.avg, delivered[0].avg);
        assert!(
            seeded.anomaly.avg,
            "and so it reaches the same verdict as IS-IS"
        );
    }

    /// A params-only edit re-subscribes the same client on the same
    /// key. That must keep its hysteresis: a delay sitting in the band
    /// between the bounds holds whatever the bit already was, and a
    /// fresh state would silently resolve that hold to "clear".
    #[tokio::test]
    async fn resubscribe_preserves_hysteresis() {
        let mut stamp = fresh_stamp();
        let key = loopback_key(2);
        let (tx, mut rx) = mpsc::unbounded_channel();
        let banded = |anomaly, reuse| SessionParams {
            anomaly: crate::stamp::anomaly::AnomalyThresholds {
                anomaly_us: Some(anomaly),
                reuse_us: Some(reuse),
            },
            ..Default::default()
        };
        stamp.subscribe("isis".into(), key, banded(1_000, 900), tx);

        let ssid = stamp.sessions.get(&key).unwrap().ssid;
        let us = |micros: u64| StampTimestamp {
            seconds: 100,
            fraction: ((micros << 32) / 1_000_000) as u32,
        };
        // The reply stamps T2 == T3 == 0, so delay = (T4 - T1) / 2 —
        // feed twice the delay the window should record.
        let feed = |stamp: &mut Stamp, delay_us: u64| {
            stamp.on_reply_recv(
                key,
                reply_for(ssid, us(0)),
                us(delay_us * 2),
                false,
                std::time::Instant::now(),
            );
        };

        feed(&mut stamp, 1_100); // over the bound: bit sets
        stamp.on_export_tick(key);
        feed(&mut stamp, 950); // inside the band: bit holds
        stamp.on_export_tick(key);
        while rx.try_recv().is_ok() {}

        // Only the probe interval changes — nothing about the policy.
        let mut retimed = banded(1_000, 900);
        retimed.interval_ms = 250;
        stamp.subscribe("isis".into(), key, retimed, {
            let (tx2, rx2) = mpsc::unbounded_channel();
            drop(rx2);
            tx2
        });

        feed(&mut stamp, 950);
        stamp.on_export_tick(key);
        let flags = stamp
            .subscribers
            .get(&key)
            .unwrap()
            .get("isis")
            .unwrap()
            .last_flags;
        assert!(
            flags.avg,
            "950us is in the hysteresis band; the bit was set and must stay set"
        );
    }

    /// Dropping the subscriber that configured a threshold must not
    /// leave its policy behind on the survivor.
    #[tokio::test]
    async fn unsubscribing_does_not_leak_policy() {
        let mut stamp = fresh_stamp();
        let key = loopback_key(2);
        let (isis_tx, _isis_rx) = mpsc::unbounded_channel();
        let (ospf_tx, mut ospf_rx) = mpsc::unbounded_channel();
        stamp.subscribe("isis".into(), key, params_with_threshold(Some(1)), isis_tx);
        stamp.subscribe("ospf".into(), key, params_with_threshold(None), ospf_tx);
        stamp.unsubscribe("isis", &key);

        let ssid = stamp.sessions.get(&key).unwrap().ssid;
        let us = |micros: u64| StampTimestamp {
            seconds: 100,
            fraction: ((micros << 32) / 1_000_000) as u32,
        };
        stamp.on_reply_recv(
            key,
            reply_for(ssid, us(0)),
            us(1000),
            false,
            std::time::Instant::now(),
        );
        stamp.on_export_tick(key);

        let snap = match ospf_rx.try_recv() {
            Ok(StampEvent::MetricUpdate { snapshot, .. }) => snapshot.expect("value"),
            other => panic!("ospf got {other:?}"),
        };
        assert_eq!(
            snap.anomaly,
            crate::stamp::anomaly::AnomalyFlags::default(),
            "IS-IS left, its threshold must leave with it"
        );
    }

    /// A subscriber's A-bit transition has to escape the shared value
    /// filter: the values are identical period to period, so damping
    /// alone would never re-export and the set would never be flooded.
    #[tokio::test]
    async fn anomaly_transition_exports_through_damping() {
        let mut stamp = fresh_stamp();
        let key = loopback_key(2);
        let (tx, mut rx) = mpsc::unbounded_channel();
        // Bound above the sample: steady and clear to begin with.
        stamp.subscribe("isis".into(), key, params_with_threshold(Some(5_000)), tx);

        let ssid = stamp.sessions.get(&key).unwrap().ssid;
        let us = |micros: u64| StampTimestamp {
            seconds: 100,
            fraction: ((micros << 32) / 1_000_000) as u32,
        };
        let feed = |stamp: &mut Stamp| {
            stamp.on_reply_recv(
                key,
                reply_for(ssid, us(0)),
                us(1000),
                false,
                std::time::Instant::now(),
            );
        };

        feed(&mut stamp);
        stamp.on_export_tick(key); // first export, bit clear
        feed(&mut stamp);
        stamp.on_export_tick(key); // identical window → damped

        // Same measurement, stricter policy: only the bit changes.
        stamp
            .subscribers
            .get_mut(&key)
            .unwrap()
            .get_mut("isis")
            .unwrap()
            .thresholds = crate::stamp::anomaly::AnomalyThresholds {
            anomaly_us: Some(1),
            reuse_us: None,
        };
        feed(&mut stamp);
        stamp.on_export_tick(key);

        let mut updates = Vec::new();
        while let Ok(StampEvent::MetricUpdate { snapshot, .. }) = rx.try_recv() {
            updates.push(snapshot);
        }
        assert_eq!(
            updates.len(),
            2,
            "first export + the A-bit flip, got {updates:?}"
        );
        assert!(!updates[0].unwrap().anomaly.avg);
        assert!(
            updates[1].unwrap().anomaly.avg,
            "the transition must survive the value filter"
        );
    }

    /// Build a Stamp with both reflectors on loopback ephemeral ports.
    fn fresh_stamp_dualstack() -> Stamp {
        Stamp::new_with(
            ProtoContext::default_table_no_rib(),
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
            Some(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0)),
        )
        .expect("bind loopback reflectors")
    }

    // `::1` is the only loopback v6 address (unlike `127.0.0.0/8`), so a
    // v6 self-loop key is local == remote == `::1` — mirrors how the v4
    // integration test loops back through LOCALHOST.
    fn v6_loopback_key() -> SessionKey {
        SessionKey {
            local: IpAddr::V6(Ipv6Addr::LOCALHOST),
            remote: IpAddr::V6(Ipv6Addr::LOCALHOST),
            ifindex: 0,
        }
    }

    /// With a v6 reflector bound, a v6 session key takes the
    /// `add_session` v6 branch — a v6 connected sender socket and a
    /// live session with a real ssid.
    #[tokio::test]
    async fn v6_session_creates_over_loopback() {
        let mut stamp = fresh_stamp_dualstack();
        assert!(stamp.local_addr_v6.is_some(), "v6 reflector bound");

        let key = v6_loopback_key();
        let (tx, _rx) = mpsc::unbounded_channel();
        stamp.subscribe("isis".into(), key, SessionParams::default(), tx);
        assert_eq!(stamp.sessions.len(), 1);
        assert_ne!(stamp.sessions.get(&key).unwrap().ssid, 0);
    }

    /// A probe from a registered v6 remote is reflected over the
    /// v6 write loop; the same probe is dropped (no reflection counted)
    /// when no v6 reflector bound — the family-routing in `on_probe_recv`.
    #[tokio::test]
    async fn v6_probe_routes_to_v6_loop_else_drops() {
        let src = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 5000, 0, 0));

        // With a v6 reflector: the probe is reflected.
        let mut stamp = fresh_stamp_dualstack();
        let key = v6_loopback_key();
        let (tx, _rx) = mpsc::unbounded_channel();
        stamp.subscribe("isis".into(), key, SessionParams::default(), tx);

        stamp.on_probe_recv(
            SenderPacket::default(),
            src,
            Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            0,
            255,
            StampTimestamp::default(),
            false,
            stamp_packet::BASE_LEN,
        );
        assert_eq!(stamp.reflector_stats.reflected, 1);
        assert_eq!(stamp.sessions.get(&key).unwrap().reflected_count, 1);

        // Without a v6 reflector (`bind_v6` = None): the v6 session still
        // creates (the sender socket is independent), but an inbound v6
        // probe can't be answered, so it's dropped — allowed, not
        // reflected, not unauthorized.
        let mut stamp = fresh_stamp(); // v4-only reflector
        let (tx, _rx) = mpsc::unbounded_channel();
        stamp.subscribe("isis".into(), key, SessionParams::default(), tx);
        assert_eq!(
            stamp.sessions.len(),
            1,
            "v6 session creates without a v6 reflector"
        );

        stamp.on_probe_recv(
            SenderPacket::default(),
            src,
            Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            0,
            255,
            StampTimestamp::default(),
            false,
            stamp_packet::BASE_LEN,
        );
        assert_eq!(stamp.reflector_stats.rx, 1);
        assert_eq!(
            stamp.reflector_stats.reflected, 0,
            "no v6 reflector → dropped"
        );
        assert_eq!(
            stamp.reflector_stats.unauthorized, 0,
            "source was registered"
        );
    }
}
