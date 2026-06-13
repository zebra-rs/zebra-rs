//! STAMP session state and the per-instance session table.
//!
//! One [`Session`] per measured link direction: this node is the
//! Session-Sender, the `remote` end reflects. Sessions are created on
//! the first client [`Subscribe`](super::client::ClientReq::Subscribe)
//! and shared by every IGP measuring the same link (the key carries no
//! protocol). The table also allocates the per-session SSID
//! (RFC 8972 §3) — non-zero so a reply that lost its session context
//! can never validate against a fresh one by accident.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use socket2::Socket;
use tokio::io::unix::AsyncFd;

use crate::context::Task;

use super::damping::Damping;
use super::stats::{MetricSnapshot, StatsWindow};

/// Identifies one measurement session at this system. `ifindex` is the
/// local interface the measured link hangs off — it keys the IGP-side
/// lookup on `MetricUpdate` and any future per-ifindex XDP helper
/// (offload notes §9b).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionKey {
    pub local: IpAddr,
    pub remote: IpAddr,
    pub ifindex: u32,
}

/// Per-session probe/export timing as resolved from config.
/// `PartialEq` so IGP-side reconciles can diff a desired tuple against
/// the tracked one and re-`Subscribe` only on a real change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionParams {
    /// Probe transmit interval.
    pub interval_ms: u32,
    /// Export (damping) period — the stats window length.
    pub damping_secs: u32,
    /// Destination UDP port. Production sessions probe the well-known
    /// STAMP port (862); tests aim at an instance's ephemeral port.
    pub dst_port: u16,
}

impl Default for SessionParams {
    fn default() -> Self {
        Self {
            interval_ms: DEFAULT_INTERVAL_MS,
            damping_secs: DEFAULT_DAMPING_SECS,
            dst_port: stamp_packet::STAMP_UDP_PORT,
        }
    }
}

/// Default probe interval (Cisco SR-PM probes at 3 s, Juniper TWAMP at
/// 1 s; 1 s gives ~30 samples per default export window).
pub const DEFAULT_INTERVAL_MS: u32 = 1000;

/// Default export / damping period.
pub const DEFAULT_DAMPING_SECS: u32 = 30;

/// The `te-metric { measurement {...} }` config block both IGPs embed
/// per interface — the YANG mirror. Leaves are `Option` so "configured
/// vs defaulted" stays visible (matching the sibling static te-metric
/// leaves); [`Self::resolve`] applies the defaults.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MeasurementConfig {
    pub enable: Option<bool>,
    pub interval_ms: Option<u32>,
    pub damping_period_secs: Option<u32>,
}

impl MeasurementConfig {
    pub fn enabled(&self) -> bool {
        self.enable.unwrap_or(false)
    }

    pub fn resolve(&self) -> SessionParams {
        SessionParams {
            interval_ms: self.interval_ms.unwrap_or(DEFAULT_INTERVAL_MS),
            damping_secs: self.damping_period_secs.unwrap_or(DEFAULT_DAMPING_SECS),
            dst_port: stamp_packet::STAMP_UDP_PORT,
        }
    }
}

/// One Session-Sender. The connected UDP socket does the reply demux
/// (the kernel matches the 4-tuple); `ssid` is a cheap integrity check
/// on top. The read task feeds replies to the event loop and dies with
/// the session (dropping [`Task`] aborts it).
#[derive(Debug)]
pub struct Session {
    pub key: SessionKey,
    pub params: SessionParams,
    /// Non-zero STAMP Session Identifier (RFC 8972 §3), allocated by
    /// the table, validated on every reply.
    pub ssid: u16,
    /// Sequence number for the next probe.
    pub next_seq: u32,
    /// Connected sender socket; egress for probes, ingress (via the
    /// per-session read task) for replies.
    pub sock: Arc<AsyncFd<Socket>>,
    pub tx_count: u64,
    pub tx_failed_count: u64,
    pub rx_count: u64,
    /// Replies that failed validation: SSID mismatch, or a delay that
    /// computed negative / absurd (clock step during the probe).
    pub rx_invalid_count: u64,
    /// Accepted samples whose T4 came from a kernel `SO_TIMESTAMPING`
    /// stamp (Phase 1.5 rung 1) vs a userspace fallback read. The ratio
    /// is the figure of merit for whether kernel timestamping is live.
    pub t4_kernel: u64,
    pub t4_userspace: u64,
    /// Probes from `key.remote` answered by the implicit reflector —
    /// the per-session half of the reflector counters.
    pub reflected_count: u64,
    pub window: StatsWindow,
    pub damping: Damping,
    /// Last snapshot actually exported to subscribers (`None` before
    /// the first export or after a clear). Mirrored to late
    /// subscribers and rendered by `show stamp`.
    pub last_export: Option<MetricSnapshot>,
    pub last_rx: Option<Instant>,
    pub created: Instant,
    /// Reply read task; aborted when the session drops.
    _read_task: Task<()>,
}

impl Session {
    pub fn new(
        key: SessionKey,
        params: SessionParams,
        ssid: u16,
        sock: Arc<AsyncFd<Socket>>,
        read_task: Task<()>,
    ) -> Self {
        Self {
            key,
            params,
            ssid,
            next_seq: 0,
            sock,
            tx_count: 0,
            tx_failed_count: 0,
            rx_count: 0,
            rx_invalid_count: 0,
            t4_kernel: 0,
            t4_userspace: 0,
            reflected_count: 0,
            window: StatsWindow::default(),
            damping: Damping::default(),
            last_export: None,
            last_rx: None,
            created: Instant::now(),
            _read_task: read_task,
        }
    }

    /// Sender liveness for `show stamp`: Active while a reply arrived
    /// within the last three probe intervals.
    pub fn is_active(&self) -> bool {
        self.last_rx
            .is_some_and(|t| t.elapsed().as_millis() <= 3 * self.params.interval_ms as u128)
    }
}

/// All sessions, ordered by key for stable show output, plus the SSID
/// allocator.
#[derive(Debug, Default)]
pub struct SessionTable {
    sessions: BTreeMap<SessionKey, Session>,
    next_ssid: u16,
}

impl SessionTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocate a non-zero SSID no live session uses. Wraps at u16;
    /// with realistic session counts (one per measured link) the loop
    /// terminates immediately.
    pub fn alloc_ssid(&mut self) -> u16 {
        loop {
            self.next_ssid = self.next_ssid.wrapping_add(1);
            if self.next_ssid == 0 {
                continue;
            }
            if !self.sessions.values().any(|s| s.ssid == self.next_ssid) {
                return self.next_ssid;
            }
        }
    }

    pub fn insert(&mut self, session: Session) {
        self.sessions.insert(session.key, session);
    }

    pub fn remove(&mut self, key: &SessionKey) -> Option<Session> {
        self.sessions.remove(key)
    }

    pub fn get(&self, key: &SessionKey) -> Option<&Session> {
        self.sessions.get(key)
    }

    pub fn get_mut(&mut self, key: &SessionKey) -> Option<&mut Session> {
        self.sessions.get_mut(key)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&SessionKey, &Session)> {
        self.sessions.iter()
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// The implicit-reflector allow-list (plan §2): a probe is
    /// reflected only when its source is the remote of a registered
    /// session — i.e. measurement is enabled on both ends of the link.
    /// Returns the matching key so the per-session reflected counter
    /// can tick. Kept as plain per-session data so a future XDP
    /// offload can mirror it into a BPF map (offload notes §9b R2).
    pub fn reflect_allowed(&self, src: IpAddr) -> Option<SessionKey> {
        self.sessions.keys().find(|k| k.remote == src).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn measurement_config_resolves_defaults() {
        let c = MeasurementConfig::default();
        assert!(!c.enabled());
        let p = c.resolve();
        assert_eq!(p.interval_ms, DEFAULT_INTERVAL_MS);
        assert_eq!(p.damping_secs, DEFAULT_DAMPING_SECS);
        assert_eq!(p.dst_port, stamp_packet::STAMP_UDP_PORT);

        let c = MeasurementConfig {
            enable: Some(true),
            interval_ms: Some(100),
            damping_period_secs: Some(2),
        };
        assert!(c.enabled());
        let p = c.resolve();
        assert_eq!(p.interval_ms, 100);
        assert_eq!(p.damping_secs, 2);
    }

    #[test]
    fn ssid_allocation_is_nonzero_and_advances() {
        let mut t = SessionTable::new();
        let a = t.alloc_ssid();
        let b = t.alloc_ssid();
        assert_ne!(a, 0);
        assert_ne!(b, 0);
        // Without intervening inserts the allocator just advances; the
        // collision scan only matters once sessions hold SSIDs.
        assert_ne!(a, b);
    }
}
