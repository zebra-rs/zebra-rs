//! STAMP instance — Session-Sender, implicit Session-Reflector, and
//! the client-subscription registry.
//!
//! One instance per daemon (default VRF), spawned eagerly by the
//! `router isis` / `router ospf` commit arms so the IGPs can pick up
//! `stamp_client_tx` at their own spawn time — the same lifecycle as
//! BFD. The instance owns:
//!
//!   * the wildcard reflector socket (`0.0.0.0:862`) with its
//!     read/write tasks — the **implicit reflector**: a probe is
//!     answered iff its source is the remote of a registered session
//!     (measurement enabled on both ends of the link, plan §2);
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
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;

use stamp_packet::{ErrorEstimate, ReflectorPacket, SenderPacket, StampTimestamp};
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use crate::config::{
    Args, ConfigChannel, ConfigRequest, DisplayRequest, ShowChannel, path_from_command,
};
use crate::context::{ProtoContext, Task};

use super::client::{ClientId, ClientReq, ClientReqChannel, StampEvent};
use super::network::{ReflectRequest, reflector_read, reflector_write, sender_read};
use super::reflector::build_reply;
use super::sender::{ProberCmd, ProberHandle, session_prober};
use super::session::{Session, SessionKey, SessionParams, SessionTable};
use super::socket::{stamp_reflector_socket, stamp_sender_socket};
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
    },
    /// Probe transmit timer fired for `key`.
    TxTick { key: SessionKey },
    /// Export (damping-period) timer fired for `key`.
    ExportTick { key: SessionKey },
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
    /// Config-manager subscription endpoints. STAMP has no own config
    /// in Phase 1; every commit broadcast is drained (registering as a
    /// config client also lets the manager see the task is running).
    pub cm: ConfigChannel,
    /// `show stamp ...` endpoints, dispatched through [`Self::show_cb`].
    pub show: ShowChannel,
    pub show_cb: HashMap<String, ShowCallback>,
    /// Inbound client request channel — the IGPs send
    /// [`ClientReq::Subscribe`] / `Unsubscribe` here.
    pub client_req: ClientReqChannel,
    subscribers: HashMap<SessionKey, BTreeMap<ClientId, UnboundedSender<StampEvent>>>,
    main_tx: UnboundedSender<Message>,
    reflect_tx: UnboundedSender<ReflectRequest>,
    probers: HashMap<SessionKey, ProberHandle>,
    pub reflector_stats: ReflectorStats,
}

impl Stamp {
    /// Production constructor — binds the reflector to `0.0.0.0:862`.
    pub fn new(ctx: ProtoContext) -> std::io::Result<Self> {
        Self::new_with(
            ctx,
            SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, stamp_packet::STAMP_UDP_PORT),
        )
    }

    /// Explicit constructor letting the caller pick the reflector bind
    /// address (the integration test runs on a loopback ephemeral
    /// port and aims a session's `dst_port` at it).
    pub fn new_with(ctx: ProtoContext, bind: SocketAddrV4) -> std::io::Result<Self> {
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

        let mut stamp = Self {
            rx,
            ctx,
            sessions: SessionTable::new(),
            local_addr,
            cm: ConfigChannel::new(),
            show: ShowChannel::new(),
            show_cb: HashMap::new(),
            client_req: ClientReqChannel::new(),
            subscribers: HashMap::new(),
            main_tx,
            reflect_tx,
            probers: HashMap::new(),
            reflector_stats: ReflectorStats::default(),
        };
        stamp.show_build();
        Ok(stamp)
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
    /// the first subscriber and retuning it on a params change
    /// (last-writer-wins, plan D11). The current exported value, if
    /// any, is mirrored to the new subscriber so a late-joining IGP
    /// advertises without waiting a full damping period.
    pub fn subscribe(
        &mut self,
        client: ClientId,
        key: SessionKey,
        params: SessionParams,
        notifier: UnboundedSender<StampEvent>,
    ) {
        if self.sessions.get(&key).is_none() {
            if let Err(e) = self.add_session(key, params) {
                tracing::warn!(?key, error = %e, "stamp: cannot create session");
                // Keep the subscription anyway: unsubscribe stays
                // symmetric for the IGP, it just never hears updates.
            }
        } else {
            self.update_params(&key, params);
        }
        if let Some(session) = self.sessions.get(&key)
            && session.last_export.is_some()
        {
            let _ = notifier.send(StampEvent::MetricUpdate {
                key,
                snapshot: session.last_export,
            });
        }
        self.subscribers
            .entry(key)
            .or_default()
            .insert(client, notifier);
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
            self.remove_session(key);
        }
    }

    /// Create the session: connected sender socket, reply-read task,
    /// prober task.
    fn add_session(&mut self, key: SessionKey, params: SessionParams) -> std::io::Result<()> {
        let (IpAddr::V4(local), IpAddr::V4(remote)) = (key.local, key.remote) else {
            return Err(std::io::Error::other(
                "stamp: IPv6 sessions are not supported yet",
            ));
        };
        let sock = stamp_sender_socket(
            &self.ctx,
            SocketAddrV4::new(local, 0),
            SocketAddrV4::new(remote, params.dst_port),
        )?;
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
                session.next_seq = session.next_seq.wrapping_add(1);
                session.tx_count += 1;
                session.window.record_sent();
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
        // Track the T4 source on accepted samples (Phase 1.5 rung 1) —
        // the figure of merit for "is kernel timestamping live".
        if t4_kernel {
            session.t4_kernel += 1;
        } else {
            session.t4_userspace += 1;
        }
        session.last_rx = Some(std::time::Instant::now());
        session.window.record_delay(delay as u32);
    }

    /// Export timer fired: snapshot the window, run the damping gate,
    /// fan the update out, start a fresh window.
    fn on_export_tick(&mut self, key: SessionKey) {
        let Some(session) = self.sessions.get_mut(&key) else {
            return;
        };
        let snapshot = session.window.snapshot();
        session.window.reset();
        if !session.damping.should_export(snapshot) {
            return;
        }
        session.last_export = snapshot;
        tracing::info!(?key, ?snapshot, "stamp: exporting metric update");
        if let Some(subs) = self.subscribers.get(&key) {
            for tx in subs.values() {
                let _ = tx.send(StampEvent::MetricUpdate { key, snapshot });
            }
        }
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
        let Some(session_key) = self.sessions.reflect_allowed(src.ip()) else {
            self.reflector_stats.unauthorized += 1;
            tracing::debug!(?src, "stamp: probe from unregistered source dropped");
            return;
        };
        let reply = build_reply(&probe, rx_ts, ttl, len);
        let _ = self.reflect_tx.send(ReflectRequest {
            reply,
            dst: src,
            src: dst,
            ifindex: (ifindex != 0).then_some(ifindex),
        });
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

    /// STAMP has no own config in Phase 1 — drain every broadcast.
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
                    Message::ReplyRecv { key, reply, t4, t4_kernel } =>
                        self.on_reply_recv(key, reply, t4, t4_kernel),
                    Message::TxTick { key } => self.on_tx_tick(key),
                    Message::ExportTick { key } => self.on_export_tick(key),
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
        Stamp::new_with(
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
        stamp.on_reply_recv(key, reply_for(ssid, t1), t4, false);
        stamp.on_export_tick(key);
        assert!(stamp.sessions.get(&key).unwrap().last_export.is_some());

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
        stamp.on_reply_recv(key, reply, us(1000), true);
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
        stamp.on_reply_recv(key, reply_for(ssid.wrapping_add(1), us(0)), us(1000), false);
        // Negative delay (T4 before T1) → invalid.
        stamp.on_reply_recv(key, reply_for(ssid, us(1000)), us(0), false);
        let s = stamp.sessions.get(&key).unwrap();
        assert_eq!(s.rx_invalid_count, 2);
        assert_eq!(s.rx_count, 1);
        // Rejected replies don't move the T4-source counters.
        assert_eq!(s.t4_kernel, 1);
        assert_eq!(s.t4_userspace, 0);
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
            stamp.on_reply_recv(key, reply_for(ssid, us(0)), us(1000), false);
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
        assert!(stamp.sessions.get(&key).unwrap().last_export.is_none());
    }
}
