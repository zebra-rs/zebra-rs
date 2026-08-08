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
        };

        let task = fib.clone();
        tokio::spawn(async move { task.run(rx).await });
        fib
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
        self.mirror
            .lock()
            .await
            .insert(prefix, vrf_ifindex, msg.clone());
        self.offer(msg);
    }

    /// Send a route delete and drop it from the mirror, so a later
    /// replay does not resurrect it.
    pub async fn route_del(&self, prefix: &IpNet, vrf_ifindex: u32, msg: Vec<u8>) {
        self.mirror.lock().await.remove(prefix, vrf_ifindex);
        self.offer(msg);
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

    /// `(sent, dropped, acks, reconnects)`, for `show` output.
    pub fn counters(&self) -> (u64, u64, u64, u64) {
        (
            self.stats.sent.load(Ordering::Relaxed),
            self.stats.dropped.load(Ordering::Relaxed),
            self.stats.acks.load(Ordering::Relaxed),
            self.stats.reconnects.load(Ordering::Relaxed),
        )
    }

    /// Connection lifecycle: connect, replay, pump, repeat.
    async fn run(self, mut rx: UnboundedReceiver<Vec<u8>>) {
        let mut backoff = BACKOFF_START;
        loop {
            let stream = match TcpStream::connect(self.endpoint).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!("fib: FPM connect to {} failed ({e})", self.endpoint);
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(BACKOFF_MAX);
                    continue;
                }
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
            // the protocol asks for after a reconnect.
            let (replay, mirrored) = {
                let mirror = self.mirror.lock().await;
                (mirror.messages(), mirror.len())
            };
            let mut failed = false;
            if !replay.is_empty() {
                tracing::info!("fib: FPM replaying {mirrored} routes");
                for msg in &replay {
                    if let Err(e) = wr.write_all(msg).await {
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
            self.connected.store(true, Ordering::Relaxed);

            // Pump until either side gives up.
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
                }
            }

            self.connected.store(false, Ordering::Relaxed);
            let (sent, dropped, acks, _) = self.counters();
            tracing::info!(
                "fib: FPM disconnected ({sent} sent, {acks} acked, {dropped} dropped while down)"
            );
            tokio::time::sleep(backoff).await;
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
