//! Shard worker pool (RIB sharding Phase C — N parallel shards).
//!
//! Each [`BgpShard`] runs end-to-end on its own dedicated OS thread: it
//! blocks on an inbox channel, processes one [`ShardMsg`] at a time via
//! [`BgpShard::handle`], and ships the resulting [`ShardOut`]s back to
//! the main event loop over a shared tokio channel. Shards are CPU-bound
//! (policy walk + best-path per route), so they get real OS threads
//! rather than tokio tasks — that keeps them off the runtime's worker
//! pool and out of the way of the I/O (peer reader/writer) tasks.
//!
//! Routing is by prefix hash ([`shard_of`]): unicast / LU / VPN rows of
//! one prefix co-locate on one shard (the Juniper invariant), so a
//! prefix is owned end-to-end by a single shard with no cross-shard
//! synchronization in the hot path.
//!
//! The worker calls `handle(msg, None)` — it cannot borrow the main
//! task's central label allocator across the thread boundary, so it
//! draws labels from its own [`super::ShardLabelPool`] sub-block;
//! refills become a `LabelBlockLow` round-trip (follow-up).
//!
//! This module is the parallel-execution machinery; wiring the ingest
//! and the event-loop result handler through it lands in later slices.

use std::net::IpAddr;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::thread::JoinHandle;

use tokio::sync::mpsc::UnboundedSender;

use super::{BgpShard, ShardMsg, ShardOut};

/// A shard worker's output for one processed message: the shard index
/// (so main can attribute results) and the best-path deltas it produced.
#[derive(Debug)]
pub struct ShardResult {
    /// Set by the worker for result attribution / debug logging; main
    /// currently processes the deltas without needing the source index.
    #[allow(dead_code)]
    pub shard: usize,
    pub out: Vec<ShardOut>,
}

/// One shard worker: owns a [`BgpShard`], consumes [`ShardMsg`]s from its
/// inbox on a dedicated thread, emits [`ShardResult`]s back to main.
struct ShardWorker {
    idx: usize,
    shard: BgpShard,
    inbox: Receiver<ShardMsg>,
    results: UnboundedSender<ShardResult>,
}

impl ShardWorker {
    fn run(mut self) {
        // Blocking recv on a dedicated thread; the loop ends when every
        // inbox sender is dropped (pool teardown) or on explicit Shutdown.
        while let Ok(msg) = self.inbox.recv() {
            if matches!(msg, ShardMsg::Shutdown) {
                break;
            }
            let out = self.shard.handle(msg, None);
            // Reply to every message (even empty) so main can account
            // per-message; if main is gone, wind the thread down.
            if self
                .results
                .send(ShardResult {
                    shard: self.idx,
                    out,
                })
                .is_err()
            {
                break;
            }
        }
    }
}

/// N shard worker threads plus the channels that drive them. Lives on the
/// main task: dispatch by [`ShardPool::shard_of`]; results funnel into the
/// `UnboundedReceiver` the caller holds (on `Bgp`), which the main event
/// loop `select!`s on.
pub struct ShardPool {
    n: usize,
    inboxes: Vec<Sender<ShardMsg>>,
    /// Joined only by `shutdown`, which the daemon doesn't call (it runs
    /// the pool for its whole lifetime). Held so the handles aren't
    /// dropped, and ready for a graceful-teardown path.
    #[allow(dead_code)]
    handles: Vec<JoinHandle<()>>,
}

impl ShardPool {
    /// Spawn `shards.len()` worker threads, one per [`BgpShard`]. Every
    /// worker's [`ShardResult`]s are funnelled into `results` (the
    /// receiver lives on the main task, drained by its event loop).
    pub fn spawn(shards: Vec<BgpShard>, results: UnboundedSender<ShardResult>) -> Self {
        let n = shards.len();
        assert!(n >= 1, "shard pool needs at least one shard");
        let mut inboxes = Vec::with_capacity(n);
        let mut handles = Vec::with_capacity(n);
        for (idx, shard) in shards.into_iter().enumerate() {
            let (tx, rx) = channel();
            inboxes.push(tx);
            let worker = ShardWorker {
                idx,
                shard,
                inbox: rx,
                results: results.clone(),
            };
            let handle = std::thread::Builder::new()
                .name(format!("bgp-shard-{idx}"))
                .spawn(move || worker.run())
                .expect("spawn bgp shard worker thread");
            handles.push(handle);
        }
        Self {
            n,
            inboxes,
            handles,
        }
    }

    pub fn n(&self) -> usize {
        self.n
    }

    /// Stable prefix-address → shard index. Hashes the address bytes only
    /// (not label / RD), so unicast / LU / VPN rows of one prefix
    /// co-locate on one shard.
    pub fn shard_of(&self, addr: IpAddr) -> usize {
        shard_of(addr, self.n)
    }

    /// Send a message to one shard (by index). Unbounded — `send` only
    /// fails if the worker thread has died, which is a teardown race.
    pub fn dispatch(&self, idx: usize, msg: ShardMsg) {
        let _ = self.inboxes[idx].send(msg);
    }

    /// Send a freshly-built message to **every** shard. Used for control
    /// state that isn't prefix-scoped — notably a peer's inbound policy
    /// snapshot, which every shard needs since one peer's prefixes hash
    /// across all of them. `make` is called once per shard so a per-shard
    /// payload (e.g. an `Arc` clone) stays cheap.
    pub fn broadcast(&self, mut make: impl FnMut() -> ShardMsg) {
        for tx in &self.inboxes {
            let _ = tx.send(make());
        }
    }

    /// Stop every worker and join its thread (clean teardown). Not called
    /// yet — the daemon runs the pool for its whole lifetime; kept for a
    /// future graceful-shutdown path.
    #[allow(dead_code)]
    pub fn shutdown(self) {
        for tx in &self.inboxes {
            let _ = tx.send(ShardMsg::Shutdown);
        }
        drop(self.inboxes);
        for handle in self.handles {
            let _ = handle.join();
        }
    }
}

/// Stable prefix-address → shard index: FNV-1a over the octets, mod `n`.
/// Deterministic across runs (fixed offset/prime, not `RandomState`), so
/// the same prefix always lands on the same shard.
pub fn shard_of(addr: IpAddr, n: usize) -> usize {
    debug_assert!(n >= 1);
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let mut fold = |b: u8| {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    };
    match addr {
        IpAddr::V4(a) => a.octets().into_iter().for_each(&mut fold),
        IpAddr::V6(a) => a.octets().into_iter().for_each(&mut fold),
    }
    (hash % n as u64) as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shard_of_is_stable_and_bounded() {
        let v4: IpAddr = "10.1.2.3".parse().unwrap();
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(shard_of(v4, 4), shard_of(v4, 4)); // deterministic
        for n in 1..=16 {
            assert!(shard_of(v4, n) < n);
            assert!(shard_of(v6, n) < n);
        }
        assert_eq!(shard_of(v4, 1), 0); // n=1 is always shard 0
    }

    #[tokio::test]
    async fn pool_round_trips_a_message() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let pool = ShardPool::spawn(vec![BgpShard::default()], tx);
        assert_eq!(pool.n(), 1);
        // Routing helper: every prefix maps to shard 0 at n=1.
        let idx = pool.shard_of("198.51.100.7".parse().unwrap());
        assert_eq!(idx, 0);
        // A control message round-trips through the worker thread; an
        // empty shard has nothing to clean, so the reply carries no delta.
        pool.dispatch(idx, ShardMsg::PeerDown { ident: 7 });
        let res = rx.recv().await.expect("worker reply");
        assert_eq!(res.shard, 0);
        assert!(res.out.is_empty());
        pool.shutdown();
    }
}
