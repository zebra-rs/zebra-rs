//! TCP client to `fpmsyncd`, with reconnect and full-table replay.
//!
//! Direction matters: `fpmsyncd` is the **server** — it listens on TCP
//! 2620 and the routing daemon dials out (`fpmsyncd/fpmlink.h:29-31`).
//!
//! The handle ([`FpmFib`]) is cheap to clone and never blocks on the
//! network. A background task owns the socket and does the reconnecting;
//! callers hand it encoded messages through a channel. That split is
//! what lets the FIB call sites stay synchronous-ish and never wait on a
//! peer that may be restarting.
//!
//! **The mirror is updated before the send is queued.** Every route the
//! tee programs is recorded in [`Mirror`] first, and only then offered
//! to the connection. So a message dropped because the peer is down
//! costs nothing: the reconnect replays the mirror wholesale, which is
//! also what FPM's own contract demands ("send the FPM a complete copy
//! of the forwarding table(s) when it reconnects", `fpm.h`). It also
//! bounds memory — nothing queues up while disconnected.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use ipnet::IpNet;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

use super::decode::parse_ack;
use super::frame::{FPM_MAX_MSG_LEN, FPM_MSG_HDR_LEN};
use super::mirror::Mirror;
use crate::fib::message::{FibMessage, RouteOffload};

/// Reconnect backoff. Short at first — a `fpmsyncd` restart is quick and
/// the FIB is stale until we are back — then capped so a peer that is
/// gone for good does not spin.
const BACKOFF_START: Duration = Duration::from_millis(200);
const BACKOFF_MAX: Duration = Duration::from_secs(5);

#[derive(Default)]
struct Stats {
    sent: AtomicU64,
    /// Messages dropped because the peer was down. Not an error — the
    /// mirror replay covers them — but a useful signal that the tee is
    /// flapping.
    dropped: AtomicU64,
    acks: AtomicU64,
    reconnects: AtomicU64,
    /// Writes skipped because the peer already holds exactly this
    /// message. Convergence re-installs plenty of unchanged routes, and
    /// under FPM's replace semantics re-sending one is a no-op.
    suppressed: AtomicU64,
}

/// Handle to the FPM tee. Cloning shares one connection.
#[derive(Clone)]
pub struct FpmFib {
    endpoint: SocketAddr,
    /// Where acknowledgements go. The RIB owns route state, so the tee
    /// reports rather than mutates.
    rib_tx: UnboundedSender<FibMessage>,
    tx: UnboundedSender<Vec<u8>>,
    mirror: Arc<Mutex<Mirror>>,
    connected: Arc<AtomicBool>,
    stats: Arc<Stats>,
    /// Set by [`shutdown`](Self::shutdown). The connection task holds a
    /// clone of this handle — including its own `tx` — so `rx.recv()`
    /// alone can never observe the outside world dropping the tee;
    /// without an explicit stop, every `system fpm` repoint or disable
    /// leaked an immortal task that kept reconnecting to the old
    /// endpoint and replaying its frozen mirror over fpmsyncd.
    shutdown: Arc<AtomicBool>,
    shutdown_notify: Arc<tokio::sync::Notify>,
}

impl FpmFib {
    /// Start the tee against `endpoint`, spawning the connection task.
    /// Connecting happens in the background: this never blocks and never
    /// fails, because a `fpmsyncd` that is not up yet is normal at
    /// startup rather than an error.
    pub fn new(endpoint: SocketAddr, rib_tx: UnboundedSender<FibMessage>) -> Self {
        let (tx, rx) = unbounded_channel();
        let fib = Self {
            endpoint,
            rib_tx,
            tx,
            mirror: Arc::new(Mutex::new(Mirror::default())),
            connected: Arc::new(AtomicBool::new(false)),
            stats: Arc::new(Stats::default()),
            shutdown: Arc::new(AtomicBool::new(false)),
            shutdown_notify: Arc::new(tokio::sync::Notify::new()),
        };

        let task = fib.clone();
        tokio::spawn(async move { task.run(rx).await });
        fib
    }

    /// Stop the connection task for good: close the socket, stop
    /// reconnecting. Must be called when the tee is re-pointed or
    /// disabled — dropping the handle is not enough (see `shutdown`
    /// field) — or the orphaned task keeps replaying a frozen mirror
    /// over whatever fpmsyncd it can still reach.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
        self.connected.store(false, Ordering::Relaxed);
        self.shutdown_notify.notify_waiters();
    }

    /// Enable the tee from the environment: `SONIC_FPM=127.0.0.1:2620`.
    ///
    /// A startup fallback, mirroring `CradleFib::from_env`, so the tee
    /// can be exercised before the YANG config plumbing lands. A value
    /// that will not parse is a misconfiguration worth complaining about
    /// rather than silently ignoring.
    pub fn from_env(rib_tx: UnboundedSender<FibMessage>) -> Option<Self> {
        let raw = std::env::var("SONIC_FPM").ok()?;
        match raw.parse::<SocketAddr>() {
            Ok(addr) => {
                tracing::info!("fib: FPM tee enabled -> {addr}");
                Some(Self::new(addr, rib_tx))
            }
            Err(e) => {
                tracing::error!(
                    "fib: SONIC_FPM=\"{raw}\" is not a host:port address ({e}); FPM tee disabled"
                );
                None
            }
        }
    }

    pub fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }

    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }

    /// Record and send a route add. `msg` is a complete framed FPM
    /// message from [`super::encode_route`].
    pub async fn route_add(&self, prefix: IpNet, vrf_ifindex: u32, msg: Vec<u8>) {
        let changed = self
            .mirror
            .lock()
            .await
            .insert(prefix, vrf_ifindex, msg.clone());
        // Nothing to say if the peer already holds this exact message.
        // Measured on a 50k-prefix convergence, the RIB offers each route
        // roughly twice over; FPM's replace semantics make the repeat
        // harmless but it is still a message fpmsyncd has to parse and a
        // Redis write it has to make.
        if !changed {
            self.stats.suppressed.fetch_add(1, Ordering::Relaxed);
            // The peer already holds exactly these bytes from an earlier
            // send, so no fresh acknowledgement is coming for this
            // re-install — synthesize one, or a `suppress-fib-pending`
            // hold armed by an attribute-only re-install waits out its
            // full timeout for the ack of a message that never needed to
            // be sent. Connected only: while down, the reconnect replay
            // re-sends the mirror and the real ack follows.
            if self.is_connected()
                && let Some((ack, _)) = super::decode::parse_route_key(&msg)
            {
                let _ = self.rib_tx.send(FibMessage::RouteOffload(RouteOffload {
                    success: true,
                    ..ack
                }));
            }
            return;
        }
        self.offer(msg);
    }

    /// Send a route delete and drop it from the mirror, so a later
    /// replay does not resurrect it.
    ///
    /// A delete for a route the mirror never held is NOT sent: the peer
    /// never received a SET for it (connected/kernel routes reach the
    /// delete path but never the add path), so the DELROUTE would be an
    /// orphan for a key fpmsyncd does not hold.
    ///
    /// While disconnected (or mid-replay) the delete is recorded as a
    /// tombstone instead of dropped: an ADD dropped while down costs
    /// nothing because the replay re-sends the mirror, but a delete has
    /// no replay row to ride — without the tombstone the peer keeps the
    /// withdrawn route in APPL_DB until the next reconnect, forwarding
    /// into a void indefinitely. The connected check happens under the
    /// mirror lock, which the settle step also holds when it flips
    /// `connected` and drains the tombstones — so a delete either lands
    /// in the drain or sends live, never neither.
    pub async fn route_del(&self, prefix: &IpNet, vrf_ifindex: u32, msg: Vec<u8>) {
        let mut mirror = self.mirror.lock().await;
        if !mirror.remove(prefix, vrf_ifindex) {
            return;
        }
        if self.is_connected() {
            drop(mirror);
            self.offer(msg);
        } else {
            mirror.tombstone(*prefix, vrf_ifindex, msg);
        }
    }

    /// Drop every mirrored route in `vrf_ifindex` and tell the peer.
    /// Called when the VRF is deleted: the kernel flushes its own
    /// routes with the VRF device, but the mirror would otherwise keep
    /// them and every later reconnect would replay the dead VRF's
    /// routes back into APPL_DB — possibly keyed to a recycled ifindex
    /// belonging to something else entirely. The deletes are the
    /// mirrored SET bytes with the message type flipped, so they carry
    /// exactly the key the SET established.
    pub async fn flush_vrf(&self, vrf_ifindex: u32) {
        let mut mirror = self.mirror.lock().await;
        let mut dels = mirror.drain_vrf(vrf_ifindex);
        if dels.is_empty() {
            return;
        }
        for msg in dels.iter_mut() {
            super::encode::set_msg_to_del(msg);
        }
        tracing::info!(
            "fib: FPM flushing {} routes of deleted VRF ifindex {}",
            dels.len(),
            vrf_ifindex
        );
        if self.is_connected() {
            drop(mirror);
            for msg in dels {
                self.offer(msg);
            }
        } else {
            // Ride the tombstone drain on reconnect. Prefix/VRF key is
            // parsed back out of the bytes we just wrote.
            for msg in dels {
                if let Some((key, _)) = super::decode::parse_route_key(&msg) {
                    mirror.tombstone(key.prefix, key.vrf_ifindex, msg);
                }
            }
        }
    }

    /// Queue a message if the peer is up. Dropping while disconnected is
    /// deliberate: the mirror already has the desired state, and the
    /// reconnect replay will carry it.
    fn offer(&self, msg: Vec<u8>) {
        if !self.is_connected() {
            self.stats.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if self.tx.send(msg).is_err() {
            // The connection task is gone; nothing will drain the queue.
            self.stats.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// `(sent, dropped, acks, reconnects, suppressed)`, for `show` output.
    pub fn counters(&self) -> (u64, u64, u64, u64, u64) {
        (
            self.stats.sent.load(Ordering::Relaxed),
            self.stats.dropped.load(Ordering::Relaxed),
            self.stats.acks.load(Ordering::Relaxed),
            self.stats.reconnects.load(Ordering::Relaxed),
            self.stats.suppressed.load(Ordering::Relaxed),
        )
    }

    /// Connection lifecycle: connect, replay, settle, pump, repeat —
    /// until [`shutdown`](Self::shutdown).
    async fn run(self, mut rx: UnboundedReceiver<Vec<u8>>) {
        let mut backoff = BACKOFF_START;
        loop {
            if self.shutdown.load(Ordering::Relaxed) {
                tracing::info!("fib: FPM tee to {} shut down", self.endpoint);
                return;
            }
            let stream = tokio::select! {
                r = TcpStream::connect(self.endpoint) => match r {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::debug!("fib: FPM connect to {} failed ({e})", self.endpoint);
                        tokio::select! {
                            _ = tokio::time::sleep(backoff) => {}
                            _ = self.shutdown_notify.notified() => {}
                        }
                        backoff = (backoff * 2).min(BACKOFF_MAX);
                        continue;
                    }
                },
                _ = self.shutdown_notify.notified() => continue,
            };
            // FPM messages are small and latency matters for
            // convergence; Nagle would batch them behind a 40ms timer.
            stream.set_nodelay(true).ok();
            backoff = BACKOFF_START;
            self.stats.reconnects.fetch_add(1, Ordering::Relaxed);
            tracing::info!("fib: FPM connected to {}", self.endpoint);

            // Drain anything queued from a previous connection before
            // marking us up: the replay below is the authoritative state,
            // and stale queued messages would race ahead of it.
            while rx.try_recv().is_ok() {}

            let (mut rd, mut wr) = stream.into_split();

            // Replay before accepting new traffic. FPM has replace
            // semantics, so re-sending every route is safe and is what
            // the protocol asks for after a reconnect. The snapshot lets
            // the mirror stay unlocked during the writes; whatever
            // changes meanwhile is reconciled by the settle step below.
            let (snapshot, mirrored) = {
                let mirror = self.mirror.lock().await;
                (mirror.snapshot(), mirror.len())
            };
            let mut failed = false;
            if !snapshot.is_empty() {
                tracing::info!("fib: FPM replaying {mirrored} routes");
                for msg in snapshot.values() {
                    if self.shutdown.load(Ordering::Relaxed) {
                        return;
                    }
                    if let Err(e) = wr.write_all(msg.as_slice()).await {
                        tracing::warn!("fib: FPM replay failed ({e})");
                        failed = true;
                        break;
                    }
                    self.stats.sent.fetch_add(1, Ordering::Relaxed);
                }
            }
            if failed {
                continue;
            }

            // Settle: everything that moved while the replay was in
            // flight was recorded in the mirror but dropped by the
            // not-yet-connected send gate — pending deletes (which have
            // no replay row to ride) and adds/changes newer than the
            // snapshot. Flipping `connected` under the same lock is what
            // makes the handoff lossless: a concurrent route_add/del
            // either lands before the drain (and is included here) or
            // observes `connected` and sends through the live channel.
            let settle: Vec<std::sync::Arc<Vec<u8>>> = {
                let mut mirror = self.mirror.lock().await;
                let mut msgs: Vec<std::sync::Arc<Vec<u8>>> = mirror
                    .take_dels()
                    .into_iter()
                    .map(std::sync::Arc::new)
                    .collect();
                msgs.extend(mirror.changed_since(&snapshot));
                self.connected.store(true, Ordering::Relaxed);
                msgs
            };
            let mut failed = false;
            for msg in &settle {
                if let Err(e) = wr.write_all(msg.as_slice()).await {
                    tracing::warn!("fib: FPM settle write failed ({e})");
                    failed = true;
                    break;
                }
                self.stats.sent.fetch_add(1, Ordering::Relaxed);
            }
            if failed {
                self.connected.store(false, Ordering::Relaxed);
                continue;
            }

            // Pump until either side gives up, or the tee is shut down.
            let mut buf = vec![0u8; 64 * 1024];
            let mut pending = Vec::new();
            loop {
                tokio::select! {
                    msg = rx.recv() => {
                        let Some(msg) = msg else { return };
                        if let Err(e) = wr.write_all(&msg).await {
                            tracing::warn!("fib: FPM write failed ({e})");
                            break;
                        }
                        self.stats.sent.fetch_add(1, Ordering::Relaxed);
                    }
                    read = rd.read(&mut buf) => {
                        match read {
                            Ok(0) => {
                                tracing::warn!("fib: FPM peer closed the connection");
                                break;
                            }
                            Ok(n) => {
                                pending.extend_from_slice(&buf[..n]);
                                self.consume_acks(&mut pending);
                            }
                            Err(e) => {
                                tracing::warn!("fib: FPM read failed ({e})");
                                break;
                            }
                        }
                    }
                    _ = self.shutdown_notify.notified() => {
                        self.connected.store(false, Ordering::Relaxed);
                        tracing::info!("fib: FPM tee to {} shut down", self.endpoint);
                        return;
                    }
                }
            }

            self.connected.store(false, Ordering::Relaxed);
            let (sent, dropped, acks, _, suppressed) = self.counters();
            tracing::info!(
                "fib: FPM disconnected ({sent} sent, {acks} acked, \
                 {dropped} dropped while down, {suppressed} unchanged-suppressed)"
            );
            tokio::select! {
                _ = tokio::time::sleep(backoff) => {}
                _ = self.shutdown_notify.notified() => {}
            }
        }
    }

    /// Re-frame the inbound stream and parse whatever acknowledgements
    /// it holds, leaving any partial message buffered.
    fn consume_acks(&self, pending: &mut Vec<u8>) {
        loop {
            if pending.len() < FPM_MSG_HDR_LEN {
                return;
            }
            let msg_len = u16::from_be_bytes([pending[2], pending[3]]) as usize;
            // A length the peer could not legitimately have sent means
            // the stream is desynchronized. There is no sync marker to
            // resynchronize on, so drop the buffer rather than
            // mis-slicing every subsequent message.
            if !(FPM_MSG_HDR_LEN..=FPM_MAX_MSG_LEN).contains(&msg_len) || !msg_len.is_multiple_of(4)
            {
                tracing::warn!("fib: FPM inbound framing lost (msg_len {msg_len}); resetting");
                pending.clear();
                return;
            }
            if pending.len() < msg_len {
                return;
            }
            let msg: Vec<u8> = pending.drain(..msg_len).collect();
            if let Some(ack) = parse_ack(&msg) {
                self.stats.acks.fetch_add(1, Ordering::Relaxed);
                self.on_ack(ack);
            }
        }
    }

    /// Report an acknowledgement to the RIB, which marks the route
    /// offloaded. That flag is what `bgp suppress-fib-pending` will gate
    /// advertisement on.
    fn on_ack(&self, ack: RouteOffload) {
        if ack.success {
            tracing::debug!(
                "fib: FPM offload ack {} vrf {} proto {}",
                ack.prefix,
                ack.vrf_ifindex,
                ack.protocol
            );
        } else {
            tracing::warn!(
                "fib: FPM reported offload FAILED for {} vrf {}",
                ack.prefix,
                ack.vrf_ifindex
            );
        }
        // The RIB owns route state; a send failure just means it is gone.
        let _ = self.rib_tx.send(FibMessage::RouteOffload(ack));
    }
}
