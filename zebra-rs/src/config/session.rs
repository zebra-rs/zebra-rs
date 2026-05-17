//! VTY session tracking (Phase 1).
//!
//! See `book/src/ch-06-01-session-design.md` for the full design.
//!
//! Phase 1 introduces an in-memory [`SessionTable`] keyed by
//! `(peer_uid, parent_pid)`. Both components are derived from kernel-backed
//! sources (`SO_PEERCRED` plus `/proc/{pid}/status`) and never from
//! client-supplied data. Per-RPC integration lives in `serve.rs`.
//!
//! No proto changes, no behavioral changes for existing RPCs — the table
//! merely observes and records sessions.

use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use dashmap::DashMap;

/// Default idle TTL for VTY sessions. Mirrors the typical Cisco IOS
/// `exec-timeout 10 0` default.
#[cfg(target_os = "linux")]
pub const DEFAULT_IDLE_TTL: Duration = Duration::from_secs(600);

/// Default interval between GC sweeps.
#[cfg(target_os = "linux")]
pub const DEFAULT_GC_INTERVAL: Duration = Duration::from_secs(60);

/// Composite session identifier: `(peer_uid, parent_pid)`.
pub type SessionKey = (u32, u32);

/// Minimal session record. Phase 1 keeps only what is needed to track
/// connections; enable/RBAC fields are added in Phase 4. Fields are written
/// on session create/refresh but not yet consumed outside tests.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct Session {
    pub uid: u32,
    pub bash_pid: u32,
    pub created: Instant,
    pub last_active: Instant,
}

impl Session {
    fn new(uid: u32, bash_pid: u32) -> Self {
        let now = Instant::now();
        Self {
            uid,
            bash_pid,
            created: now,
            last_active: now,
        }
    }
}

/// Errors returned by the session resolver.
///
/// Variants are mapped to `tonic::Status` codes by the caller. Keeping the
/// enum separate from `Status` lets the session module stay testable without
/// pulling tonic into unit tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionError {
    /// Peer is not visible in the daemon's PID namespace (D12).
    CrossPidNamespace,
    /// `/proc/{peer_pid}/status` could not be read.
    ProcReadFailure,
    /// Parent pid is 0 or 1 — the client has been reparented to init,
    /// indicating its shell already died.
    OrphanClient,
    /// Parent process disappeared between the SO_PEERCRED snapshot and the
    /// `/proc` lookup.
    ParentVanished,
    /// Parent process uid does not match the peer uid (PID reuse race or
    /// privilege boundary violation).
    ParentUidMismatch,
}

/// Concurrent table of active sessions.
///
/// Phase 1 only inserts and refreshes entries; no GC yet (Phase 2 adds it).
#[cfg(target_os = "linux")]
#[derive(Debug, Default)]
pub struct SessionTable {
    sessions: DashMap<SessionKey, Session>,
}

#[cfg(target_os = "linux")]
impl SessionTable {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            sessions: DashMap::new(),
        })
    }

    /// Resolve the session for an incoming RPC.
    ///
    /// Fast path (existing session): refresh `last_active` and return the key
    /// without re-validating `/proc`. Slow path (new session): walk `/proc`
    /// for the peer's parent pid, verify the parent uid matches, then create
    /// the session.
    ///
    /// Returns `(key, is_new)` so callers can choose log verbosity.
    pub fn resolve<P: ProcStatusReader>(
        &self,
        reader: &P,
        peer_uid: u32,
        peer_pid: i32,
    ) -> Result<(SessionKey, bool), SessionError> {
        // Guard 0 (D12): peer not visible in our PID namespace.
        if peer_pid <= 0 {
            return Err(SessionError::CrossPidNamespace);
        }

        let ppid = reader
            .read_ppid(peer_pid)
            .map_err(|_| SessionError::ProcReadFailure)?;

        // Guard 1: orphan client (parent died, reparented to init).
        if ppid <= 1 {
            return Err(SessionError::OrphanClient);
        }
        let ppid_u32 = ppid as u32;
        let key = (peer_uid, ppid_u32);

        // Fast path: existing session, just refresh activity.
        if let Some(mut entry) = self.sessions.get_mut(&key) {
            entry.last_active = Instant::now();
            return Ok((key, false));
        }

        // Slow path: validate parent uid matches.
        let parent_uid = reader
            .read_ruid(ppid)
            .map_err(|_| SessionError::ParentVanished)?;
        if parent_uid != peer_uid {
            return Err(SessionError::ParentUidMismatch);
        }

        self.sessions.insert(key, Session::new(peer_uid, ppid_u32));
        Ok((key, true))
    }

    /// Sweep stale sessions in a single pass.
    ///
    /// A session is dropped if either:
    /// - its `last_active` is older than `idle_ttl`, or
    /// - `/proc/{bash_pid}` no longer exists (parent shell has died).
    ///
    /// Returns counts useful for logging/metrics.
    pub fn gc_once<P: ProcStatusReader>(&self, reader: &P, idle_ttl: Duration) -> GcStats {
        let now = Instant::now();
        let mut removed_idle = 0usize;
        let mut removed_gone = 0usize;
        self.sessions.retain(|_key, session| {
            if now.saturating_duration_since(session.last_active) > idle_ttl {
                removed_idle += 1;
                return false;
            }
            if !reader.process_exists(session.bash_pid as i32) {
                removed_gone += 1;
                return false;
            }
            true
        });
        GcStats {
            removed_idle,
            removed_gone,
            remaining: self.sessions.len(),
        }
    }

    /// Number of active sessions.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Get a snapshot of a session for inspection. Cloned to avoid holding
    /// the DashMap shard lock.
    #[cfg(test)]
    pub fn get(&self, key: &SessionKey) -> Option<Session> {
        self.sessions.get(key).map(|s| s.clone())
    }

    /// Test-only constructor for sessions with a controllable `last_active`
    /// timestamp.
    #[cfg(test)]
    pub fn insert_for_test(&self, key: SessionKey, last_active: Instant) {
        self.sessions.insert(
            key,
            Session {
                uid: key.0,
                bash_pid: key.1,
                created: last_active,
                last_active,
            },
        );
    }
}

/// Counts emitted by [`SessionTable::gc_once`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GcStats {
    pub removed_idle: usize,
    pub removed_gone: usize,
    pub remaining: usize,
}

/// Background sweep task. Runs `gc_once` every `interval`, logging activity.
///
/// Intended to be `tokio::spawn`'d from `serve()` and to live for the
/// daemon's lifetime.
#[cfg(target_os = "linux")]
pub async fn run_gc<P>(table: Arc<SessionTable>, reader: P, interval: Duration, idle_ttl: Duration)
where
    P: ProcStatusReader + Send + Sync + 'static,
{
    let mut ticker = tokio::time::interval(interval);
    // Skip the immediate first tick; the table is empty at startup anyway.
    ticker.tick().await;
    loop {
        ticker.tick().await;
        let stats = table.gc_once(&reader, idle_ttl);
        if stats.removed_idle > 0 || stats.removed_gone > 0 {
            tracing::info!(
                removed_idle = stats.removed_idle,
                removed_gone = stats.removed_gone,
                remaining = stats.remaining,
                "vty session GC",
            );
        } else {
            tracing::debug!(remaining = stats.remaining, "vty session GC (no-op)");
        }
    }
}

/// Indirection over `/proc/{pid}/...` reads so unit tests can stub them
/// without spawning real processes.
pub trait ProcStatusReader {
    fn read_ppid(&self, pid: i32) -> Result<i32, std::io::Error>;
    fn read_ruid(&self, pid: i32) -> Result<u32, std::io::Error>;
    /// Lightweight check whether `/proc/{pid}` is still present. Used by
    /// the GC sweep to drop sessions whose parent shell has died.
    fn process_exists(&self, pid: i32) -> bool;
}

#[cfg(target_os = "linux")]
pub struct ProcfsReader;

#[cfg(target_os = "linux")]
impl ProcStatusReader for ProcfsReader {
    fn read_ppid(&self, pid: i32) -> Result<i32, std::io::Error> {
        let proc = procfs::process::Process::new(pid)
            .map_err(|e| std::io::Error::other(format!("open /proc/{pid}: {e}")))?;
        let status = proc
            .status()
            .map_err(|e| std::io::Error::other(format!("read /proc/{pid}/status: {e}")))?;
        Ok(status.ppid)
    }

    fn read_ruid(&self, pid: i32) -> Result<u32, std::io::Error> {
        let proc = procfs::process::Process::new(pid)
            .map_err(|e| std::io::Error::other(format!("open /proc/{pid}: {e}")))?;
        let status = proc
            .status()
            .map_err(|e| std::io::Error::other(format!("read /proc/{pid}/status: {e}")))?;
        Ok(status.ruid)
    }

    fn process_exists(&self, pid: i32) -> bool {
        procfs::process::Process::new(pid).is_ok()
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// Test reader that returns canned values keyed by pid.
    #[derive(Default)]
    struct StubReader {
        ppid: Mutex<HashMap<i32, i32>>,
        ruid: Mutex<HashMap<i32, u32>>,
        /// When set, the named pid returns `NotFound` to simulate a vanished
        /// parent.
        missing: Mutex<Vec<i32>>,
    }

    impl StubReader {
        fn set_ppid(&self, pid: i32, ppid: i32) {
            self.ppid.lock().unwrap().insert(pid, ppid);
        }
        fn set_ruid(&self, pid: i32, ruid: u32) {
            self.ruid.lock().unwrap().insert(pid, ruid);
        }
        fn set_missing(&self, pid: i32) {
            self.missing.lock().unwrap().push(pid);
        }
    }

    impl ProcStatusReader for StubReader {
        fn read_ppid(&self, pid: i32) -> Result<i32, std::io::Error> {
            if self.missing.lock().unwrap().contains(&pid) {
                return Err(std::io::Error::from(std::io::ErrorKind::NotFound));
            }
            self.ppid
                .lock()
                .unwrap()
                .get(&pid)
                .copied()
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))
        }
        fn read_ruid(&self, pid: i32) -> Result<u32, std::io::Error> {
            if self.missing.lock().unwrap().contains(&pid) {
                return Err(std::io::Error::from(std::io::ErrorKind::NotFound));
            }
            self.ruid
                .lock()
                .unwrap()
                .get(&pid)
                .copied()
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))
        }
        fn process_exists(&self, pid: i32) -> bool {
            !self.missing.lock().unwrap().contains(&pid)
        }
    }

    #[test]
    fn cross_pid_namespace_is_rejected() {
        let table = SessionTable::new();
        let reader = StubReader::default();
        let err = table.resolve(&reader, 1000, 0).unwrap_err();
        assert_eq!(err, SessionError::CrossPidNamespace);
        let err = table.resolve(&reader, 1000, -1).unwrap_err();
        assert_eq!(err, SessionError::CrossPidNamespace);
    }

    #[test]
    fn orphan_client_is_rejected() {
        let table = SessionTable::new();
        let reader = StubReader::default();
        // Reparented to init (ppid=1).
        reader.set_ppid(1234, 1);
        let err = table.resolve(&reader, 1000, 1234).unwrap_err();
        assert_eq!(err, SessionError::OrphanClient);
        // ppid=0 should also be rejected (defensive).
        reader.set_ppid(1235, 0);
        let err = table.resolve(&reader, 1000, 1235).unwrap_err();
        assert_eq!(err, SessionError::OrphanClient);
    }

    #[test]
    fn vanished_parent_returns_parent_vanished() {
        let table = SessionTable::new();
        let reader = StubReader::default();
        reader.set_ppid(1234, 1000);
        reader.set_missing(1000);
        let err = table.resolve(&reader, 1000, 1234).unwrap_err();
        assert_eq!(err, SessionError::ParentVanished);
    }

    #[test]
    fn parent_uid_mismatch_is_rejected() {
        let table = SessionTable::new();
        let reader = StubReader::default();
        reader.set_ppid(1234, 1000);
        reader.set_ruid(1000, 999); // parent is uid 999, peer claims 1000
        let err = table.resolve(&reader, 1000, 1234).unwrap_err();
        assert_eq!(err, SessionError::ParentUidMismatch);
    }

    #[test]
    fn new_session_is_created_and_recorded() {
        let table = SessionTable::new();
        let reader = StubReader::default();
        reader.set_ppid(1234, 1000);
        reader.set_ruid(1000, 1000);
        let (key, is_new) = table.resolve(&reader, 1000, 1234).unwrap();
        assert_eq!(key, (1000, 1000));
        assert!(is_new);
        assert_eq!(table.len(), 1);
        let sess = table.get(&key).unwrap();
        assert_eq!(sess.uid, 1000);
        assert_eq!(sess.bash_pid, 1000);
    }

    #[test]
    fn second_rpc_reuses_session_via_fast_path() {
        let table = SessionTable::new();
        let reader = StubReader::default();
        reader.set_ppid(1234, 1000);
        reader.set_ruid(1000, 1000);
        let (_, first_is_new) = table.resolve(&reader, 1000, 1234).unwrap();
        assert!(first_is_new);
        let first_last_active = table.get(&(1000, 1000)).unwrap().last_active;

        // Different peer pid (new vtyhelper invocation), same parent bash.
        reader.set_ppid(1235, 1000);
        std::thread::sleep(std::time::Duration::from_millis(5));
        let (key, second_is_new) = table.resolve(&reader, 1000, 1235).unwrap();
        assert_eq!(key, (1000, 1000));
        assert!(!second_is_new);
        assert_eq!(table.len(), 1);
        let second_last_active = table.get(&(1000, 1000)).unwrap().last_active;
        assert!(second_last_active > first_last_active);
    }

    #[test]
    fn distinct_bash_pids_create_distinct_sessions() {
        let table = SessionTable::new();
        let reader = StubReader::default();
        reader.set_ppid(1234, 2000);
        reader.set_ruid(2000, 1000);
        reader.set_ppid(1235, 2001);
        reader.set_ruid(2001, 1000);
        let (k1, _) = table.resolve(&reader, 1000, 1234).unwrap();
        let (k2, _) = table.resolve(&reader, 1000, 1235).unwrap();
        assert_ne!(k1, k2);
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn fast_path_skips_parent_uid_recheck() {
        // Demonstrates that once a session is established, subsequent RPCs do
        // not re-read parent uid. This is the perf-critical hot path for
        // completion events.
        let table = SessionTable::new();
        let reader = StubReader::default();
        reader.set_ppid(1234, 1000);
        reader.set_ruid(1000, 1000);
        table.resolve(&reader, 1000, 1234).unwrap();

        // Drop the parent uid info — fast path should still succeed because
        // it does not consult ruid for known sessions.
        reader.ruid.lock().unwrap().clear();
        reader.set_ppid(1236, 1000);
        let (key, is_new) = table.resolve(&reader, 1000, 1236).unwrap();
        assert_eq!(key, (1000, 1000));
        assert!(!is_new);
    }

    #[test]
    fn gc_removes_idle_sessions() {
        let table = SessionTable::new();
        let reader = StubReader::default();
        // Live bash pid 1000 — should not be removed for "gone".
        reader.set_ppid(1000, 100);

        let now = Instant::now();
        let old = now - Duration::from_secs(900);
        let fresh = now - Duration::from_secs(60);
        table.insert_for_test((1000, 1000), old);
        table.insert_for_test((2000, 2000), fresh);
        // The fresh session's bash also exists.
        reader.set_ppid(2000, 200);

        let stats = table.gc_once(&reader, Duration::from_secs(600));
        assert_eq!(stats.removed_idle, 1);
        assert_eq!(stats.removed_gone, 0);
        assert_eq!(stats.remaining, 1);
        assert!(table.get(&(1000, 1000)).is_none());
        assert!(table.get(&(2000, 2000)).is_some());
    }

    #[test]
    fn gc_removes_sessions_whose_bash_died() {
        let table = SessionTable::new();
        let reader = StubReader::default();

        let now = Instant::now();
        table.insert_for_test((1000, 1000), now);
        table.insert_for_test((2000, 2000), now);
        // 1000 is alive, 2000 is gone.
        reader.set_ppid(1000, 100);
        reader.set_missing(2000);

        let stats = table.gc_once(&reader, Duration::from_secs(600));
        assert_eq!(stats.removed_idle, 0);
        assert_eq!(stats.removed_gone, 1);
        assert_eq!(stats.remaining, 1);
        assert!(table.get(&(1000, 1000)).is_some());
        assert!(table.get(&(2000, 2000)).is_none());
    }

    #[test]
    fn gc_is_noop_when_everything_is_fresh_and_alive() {
        let table = SessionTable::new();
        let reader = StubReader::default();
        let now = Instant::now();
        table.insert_for_test((1000, 1000), now);
        table.insert_for_test((2000, 2000), now);
        reader.set_ppid(1000, 100);
        reader.set_ppid(2000, 200);

        let stats = table.gc_once(&reader, Duration::from_secs(600));
        assert_eq!(
            stats,
            GcStats {
                removed_idle: 0,
                removed_gone: 0,
                remaining: 2
            }
        );
    }

    #[test]
    fn gc_idle_takes_priority_over_gone() {
        // A session that is BOTH idle and whose bash has died counts as
        // removed_idle (the idle check runs first). This keeps the stats
        // attributable to a single primary cause.
        let table = SessionTable::new();
        let reader = StubReader::default();
        let now = Instant::now();
        table.insert_for_test((1000, 1000), now - Duration::from_secs(900));
        reader.set_missing(1000);

        let stats = table.gc_once(&reader, Duration::from_secs(600));
        assert_eq!(stats.removed_idle, 1);
        assert_eq!(stats.removed_gone, 0);
        assert_eq!(stats.remaining, 0);
    }
}
