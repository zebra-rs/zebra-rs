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

use std::collections::HashSet;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use dashmap::DashMap;

use super::serve::VTY_TRACING;

/// Default idle TTL for VTY sessions. Mirrors the typical Cisco IOS
/// `exec-timeout 10 0` default.
#[cfg(target_os = "linux")]
pub const DEFAULT_IDLE_TTL: Duration = Duration::from_secs(600);

/// Default interval between GC sweeps.
#[cfg(target_os = "linux")]
pub const DEFAULT_GC_INTERVAL: Duration = Duration::from_secs(60);

/// Composite session identifier: `(peer_uid, parent_pid)`.
pub type SessionKey = (u32, u32);

/// VTY authorization role. See decision D18.
///
/// - `View`: read-only access (default for new sessions).
/// - `Operator`: intermediate (clear, restart, ping/traceroute, etc.).
/// - `Admin`: full configuration access; required for configure/commit.
///
/// Sessions start at `View`. The `enable` command (Phase 4-c) authenticates
/// the operator via PAM and promotes them to `Admin` for a bounded window
/// (see [`Session::enable_expires`] / [`Session::enable_hard_deadline`]).
/// Service accounts (Phase 4-d) start at `Admin` permanently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    View,
    Admin,
}

/// Per-request session context attached to `tonic::Request` extensions by
/// `VtyPeerInterceptor` after a successful resolve. Handlers can read it to
/// act on the caller's session (e.g. the Logout handler removes the entry).
///
/// Wrapped in a newtype so the extension lookup is unambiguous — bare
/// tuples would collide with anything else stored as `(u32, u32)`.
#[derive(Debug, Clone, Copy)]
pub struct SessionContext {
    pub key: SessionKey,
}

/// Session record.
///
/// Phase 1 added the identity and timing fields. Phase 4-a added the RBAC
/// (`role`) and enable-state fields. Phase 4-c adds `username` (resolved
/// once at session creation) and wires the consumption logic.
#[derive(Debug, Clone)]
pub struct Session {
    pub bash_pid: u32,
    /// Resolved via `getpwuid_r` at session creation. `None` only when the
    /// lookup failed (uid not in passwd db); in that case enable cannot
    /// run and admin operations fail closed.
    pub username: Option<String>,
    pub last_active: Instant,
    /// Current authorization role. Defaults to `View`.
    pub role: Role,
    /// Whether the session has authenticated via `enable`. When `true`,
    /// both `enable_expires` and `enable_hard_deadline` are `Some`.
    pub enabled: bool,
    /// Sliding deadline (refreshed on each authorized RPC). The session
    /// drops back to disabled when `now >= enable_expires`.
    pub enable_expires: Option<Instant>,
    /// Absolute deadline from the original `enable`. Not extended by
    /// activity (see D2).
    pub enable_hard_deadline: Option<Instant>,
}

/// Default sliding idle TTL for the admin role granted by `enable`.
/// 15 minutes per D2.
#[cfg(target_os = "linux")]
pub const ENABLE_IDLE_TTL: Duration = Duration::from_secs(15 * 60);

/// Default hard cap on the admin role from the original `enable`.
/// 4 hours per D2.
#[cfg(target_os = "linux")]
pub const ENABLE_HARD_CAP: Duration = Duration::from_secs(4 * 60 * 60);

impl Session {
    fn new(bash_pid: u32, username: Option<String>) -> Self {
        let now = Instant::now();
        Self {
            bash_pid,
            username,
            last_active: now,
            role: Role::View,
            enabled: false,
            enable_expires: None,
            enable_hard_deadline: None,
        }
    }
}

/// Errors returned by [`SessionTable::require_admin`].
///
/// Mapped to `tonic::Status` codes by the handler. Kept separate from
/// `Status` so the session module stays testable without pulling tonic in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthzError {
    /// No session is associated with the request (no SessionContext, or
    /// the entry was GC'd between the interceptor and the handler).
    NoSession,
    /// Caller has not run `enable` and is not a permanent admin.
    NotAdmin,
    /// Caller's enable session has expired (idle TTL or hard cap). The
    /// session has been downgraded back to View as a side effect.
    EnableExpired,
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
    /// privilege boundary violation). Only raised for non-root peers; uid 0
    /// is exempt from the parent-uid match by D26 to allow `sudo <cmd>`.
    ParentUidMismatch,
}

/// Concurrent table of active sessions.
///
/// Phase 1 only inserts and refreshes entries; no GC yet (Phase 2 adds it).
#[cfg(target_os = "linux")]
#[derive(Debug, Default)]
pub struct SessionTable {
    sessions: DashMap<SessionKey, Session>,
    /// uids that are permanently Admin via the `ZEBRA_VTY_SERVICE_ACCOUNTS`
    /// env var (D21). Fixed at daemon startup; immutable thereafter.
    env_service_accounts: HashSet<u32>,
    /// uids that are permanently Admin via the YANG config (D25). Mutable
    /// at runtime — `commit_config` updates this set when the operator
    /// adds or removes `vty service-account uid N`.
    yang_service_accounts: Arc<RwLock<HashSet<u32>>>,
}

#[cfg(target_os = "linux")]
impl SessionTable {
    #[cfg(test)]
    pub fn new() -> Arc<Self> {
        Self::with_service_accounts(HashSet::new(), Arc::new(RwLock::new(HashSet::new())))
    }

    /// Construct a SessionTable with the two service-account sources
    /// (env-driven and YANG-driven). uid 0 is always implicitly Admin via
    /// [D20]; passing it in either set is allowed but redundant.
    pub fn with_service_accounts(
        env_service_accounts: HashSet<u32>,
        yang_service_accounts: Arc<RwLock<HashSet<u32>>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            sessions: DashMap::new(),
            env_service_accounts,
            yang_service_accounts,
        })
    }

    /// Whether the given uid is permanently Admin via either of the
    /// service-account sources (env var or YANG). Used by the Enable
    /// handler to short-circuit PAM (a service account that mistakenly
    /// runs `enable` gets fast success instead of a baffling PAM failure).
    pub fn is_service_account(&self, uid: u32) -> bool {
        self.env_service_accounts.contains(&uid)
            || self
                .yang_service_accounts
                .read()
                .map(|s| s.contains(&uid))
                .unwrap_or(false)
    }

    /// Resolve the session for an incoming RPC.
    ///
    /// Fast path (existing session): refresh `last_active` and return the key
    /// without re-validating `/proc`. Slow path (new session): walk `/proc`
    /// for the peer's parent pid, verify the parent uid matches, then create
    /// the session.
    ///
    /// Root short-circuit (D26): when `peer_uid == 0`, the parent-uid check
    /// is skipped. This lets `sudo <cmd>` invocations work (the outer `sudo`
    /// process retains the invoking user's ruid, which would otherwise fail
    /// the match) without weakening the check for non-root peers. The
    /// `ParentVanished` guard still runs so an orphaned uid-0 client is
    /// rejected.
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

        // Slow path: validate parent exists, and (for non-root peers) that
        // its uid matches. Root (D26) is exempt from the uid match so that
        // `sudo <cmd>` works — the outer sudo retains the invoking user's
        // ruid, which would otherwise trip ParentUidMismatch.
        let parent_uid = reader
            .read_ruid(ppid)
            .map_err(|_| SessionError::ParentVanished)?;
        if peer_uid != 0 && parent_uid != peer_uid {
            return Err(SessionError::ParentUidMismatch);
        }

        let username = reader.resolve_username(peer_uid);
        let mut session = Session::new(ppid_u32, username);
        // Permanent-admin uids: root (D20) and any uid in the
        // service-account allow-list (D21/D25). Both bypass enable and
        // have no deadlines. The yang set is consulted via the same
        // is_service_account helper used by the Enable handler.
        if peer_uid == 0 || self.is_service_account(peer_uid) {
            session.role = Role::Admin;
            session.enabled = true;
        }
        self.sessions.insert(key, session);
        Ok((key, true))
    }

    /// Promote a session to Admin after a successful `enable`.
    ///
    /// Sets `role = Admin`, `enabled = true`, and the two deadlines.
    /// Returns true if the session existed (i.e. the promotion landed).
    pub fn promote_to_admin(
        &self,
        key: &SessionKey,
        idle_ttl: Duration,
        hard_cap: Duration,
    ) -> bool {
        let now = Instant::now();
        if let Some(mut s) = self.sessions.get_mut(key) {
            s.role = Role::Admin;
            s.enabled = true;
            s.enable_expires = Some(now + idle_ttl);
            s.enable_hard_deadline = Some(now + hard_cap);
            true
        } else {
            false
        }
    }

    /// Drop a session back to the View role. Idempotent.
    pub fn disable(&self, key: &SessionKey) -> bool {
        if let Some(mut s) = self.sessions.get_mut(key) {
            s.role = Role::View;
            s.enabled = false;
            s.enable_expires = None;
            s.enable_hard_deadline = None;
            true
        } else {
            false
        }
    }

    /// Read the username cached on the session, if present.
    pub fn username(&self, key: &SessionKey) -> Option<String> {
        self.sessions.get(key).and_then(|s| s.username.clone())
    }

    /// Authorize an Admin-required RPC for the given session.
    ///
    /// On success, also extends the sliding idle TTL by `ENABLE_IDLE_TTL`
    /// (D2). For permanent admins (root, service-accounts) deadlines stay
    /// `None` and are not touched. Time-bounded admins whose `expires` or
    /// `hard_deadline` have passed are downgraded to View as a side effect
    /// and `EnableExpired` is returned.
    pub fn require_admin(&self, key: &SessionKey) -> Result<(), AuthzError> {
        let mut s = self.sessions.get_mut(key).ok_or(AuthzError::NoSession)?;
        if !s.enabled {
            return Err(AuthzError::NotAdmin);
        }
        let now = Instant::now();
        match (s.enable_expires, s.enable_hard_deadline) {
            (Some(expires), Some(hard)) => {
                if now >= expires || now >= hard {
                    s.role = Role::View;
                    s.enabled = false;
                    s.enable_expires = None;
                    s.enable_hard_deadline = None;
                    return Err(AuthzError::EnableExpired);
                }
                // Slide the idle deadline forward; the hard cap is fixed.
                s.enable_expires = Some(now + ENABLE_IDLE_TTL);
            }
            (None, None) => {
                // Permanent admin (root or service-account). No deadlines.
            }
            _ => {
                // Defensive: invariant says either both are Some or both
                // None. Treat partial as expired to fail closed.
                s.role = Role::View;
                s.enabled = false;
                s.enable_expires = None;
                s.enable_hard_deadline = None;
                return Err(AuthzError::EnableExpired);
            }
        }
        Ok(())
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

    /// Remove a session by key. Returns true if an entry was present.
    pub fn remove(&self, key: &SessionKey) -> bool {
        self.sessions.remove(key).is_some()
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
                bash_pid: key.1,
                username: None,
                last_active,
                role: Role::View,
                enabled: false,
                enable_expires: None,
                enable_hard_deadline: None,
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

/// Wrapper around the `pidfd_open(2)` syscall (Linux 5.3+). Returns a
/// non-blocking pidfd that becomes readable when the target process exits.
#[cfg(target_os = "linux")]
mod pidfd {
    use std::io;
    use std::os::fd::{FromRawFd, OwnedFd, RawFd};

    pub fn open(pid: i32) -> io::Result<OwnedFd> {
        // PIDFD_NONBLOCK aligns with O_NONBLOCK on Linux. We want
        // non-blocking semantics so tokio AsyncFd readiness is reliable.
        let flags: libc::c_int = libc::O_NONBLOCK;
        // SAFETY: pidfd_open is a single syscall taking (pid, flags) and
        // returning an int fd or -1 with errno set.
        let ret = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, flags) };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            // SAFETY: ret is a valid fd owned by us until close.
            Ok(unsafe { OwnedFd::from_raw_fd(ret as RawFd) })
        }
    }
}

/// Per-session watcher: opens a pidfd for the parent bash and removes the
/// session from the table the moment bash exits (even via `kill -9`).
///
/// Intended to be `tokio::spawn`'d once per new session created by
/// [`SessionTable::resolve`]. If pidfd open fails (bash already dead, or the
/// kernel is < 5.3), the session is removed immediately and the task exits.
#[cfg(target_os = "linux")]
pub async fn watch_bash_death(table: Arc<SessionTable>, key: SessionKey, bash_pid: u32) {
    use tokio::io::Interest;
    use tokio::io::unix::AsyncFd;

    let fd = match pidfd::open(bash_pid as i32) {
        Ok(fd) => fd,
        Err(e) => {
            tracing::warn!(
                uid = key.0,
                bash_pid,
                error = %e,
                "pidfd_open failed; dropping session immediately",
            );
            table.remove(&key);
            return;
        }
    };

    let async_fd = match AsyncFd::with_interest(fd, Interest::READABLE) {
        Ok(a) => a,
        Err(e) => {
            tracing::warn!(
                uid = key.0,
                bash_pid,
                error = %e,
                "AsyncFd registration failed; relying on GC for cleanup",
            );
            return;
        }
    };

    match async_fd.readable().await {
        Ok(_guard) => {
            if table.remove(&key) {
                if VTY_TRACING {
                    tracing::info!(uid = key.0, bash_pid, "vty session removed (bash exited)");
                }
            } else {
                tracing::debug!(
                    uid = key.0,
                    bash_pid,
                    "pidfd fired but session already gone (GC race)",
                );
            }
        }
        Err(e) => {
            tracing::warn!(uid = key.0, bash_pid, error = %e, "pidfd readable() failed");
        }
    }
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
            if VTY_TRACING {
                tracing::info!(
                    removed_idle = stats.removed_idle,
                    removed_gone = stats.removed_gone,
                    remaining = stats.remaining,
                    "vty session GC",
                );
            }
        } else {
            tracing::debug!(remaining = stats.remaining, "vty session GC (no-op)");
        }
    }
}

/// Indirection over `/proc/{pid}/...` and `getpwuid_r` so unit tests can
/// stub them without spawning real processes or relying on local passwd.
pub trait ProcStatusReader {
    fn read_ppid(&self, pid: i32) -> Result<i32, std::io::Error>;
    fn read_ruid(&self, pid: i32) -> Result<u32, std::io::Error>;
    /// Lightweight check whether `/proc/{pid}` is still present. Used by
    /// the GC sweep to drop sessions whose parent shell has died.
    fn process_exists(&self, pid: i32) -> bool;
    /// Resolve uid -> username via the system passwd database. `None` when
    /// the uid has no passwd entry.
    fn resolve_username(&self, uid: u32) -> Option<String>;
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

    fn resolve_username(&self, uid: u32) -> Option<String> {
        use std::ffi::CStr;
        use std::mem::MaybeUninit;

        // 1 KiB covers practical passwd entries. If a name+gecos field is
        // huge, getpwuid_r returns ERANGE and we treat the lookup as a miss.
        let mut buf = vec![0u8; 1024];
        let mut pwd: MaybeUninit<libc::passwd> = MaybeUninit::uninit();
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: We pass our own pwd storage and a writable buf; libc fills
        // both and sets `result` to either &pwd or NULL.
        let rc = unsafe {
            libc::getpwuid_r(
                uid,
                pwd.as_mut_ptr(),
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
                &mut result,
            )
        };
        if rc != 0 || result.is_null() {
            return None;
        }
        // SAFETY: getpwuid_r succeeded and result == &pwd; pw_name points
        // into `buf` which we still own.
        let pwd = unsafe { pwd.assume_init() };
        let name = unsafe { CStr::from_ptr(pwd.pw_name) };
        name.to_str().ok().map(String::from)
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
        fn resolve_username(&self, uid: u32) -> Option<String> {
            // Tests don't care about the real passwd db; synthesize a
            // deterministic name so they can verify the field is populated.
            Some(format!("u{uid}"))
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
    fn root_peer_bypasses_parent_uid_check() {
        // D26: `sudo <cmd>` leaves the outer sudo (ruid = invoking user)
        // as the client's parent. Root peers must accept this — the check
        // is only meaningful for non-root uids.
        let table = SessionTable::new();
        let reader = StubReader::default();
        reader.set_ppid(1234, 1000);
        reader.set_ruid(1000, 1000); // parent shell is uid 1000 (the sudo user)
        let (key, is_new) = table.resolve(&reader, 0, 1234).unwrap();
        assert_eq!(key, (0, 1000));
        assert!(is_new);
        let sess = table.get(&key).unwrap();
        // Root is still implicit Admin (D20) even when arriving via sudo.
        assert_eq!(sess.role, Role::Admin);
        assert!(sess.enabled);
    }

    #[test]
    fn root_peer_still_rejects_vanished_parent() {
        // The D26 bypass only skips the uid match; the ParentVanished
        // guard still fires so an orphaned uid-0 client is refused.
        let table = SessionTable::new();
        let reader = StubReader::default();
        reader.set_ppid(1234, 1000);
        reader.set_missing(1000);
        let err = table.resolve(&reader, 0, 1234).unwrap_err();
        assert_eq!(err, SessionError::ParentVanished);
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
        assert_eq!(sess.bash_pid, 1000);
        // Non-root sessions start as View, not enabled.
        assert_eq!(sess.role, Role::View);
        assert!(!sess.enabled);
    }

    #[test]
    fn service_account_session_starts_as_permanent_admin() {
        // D21: any uid listed in service_accounts is implicit Admin from
        // session creation, with no deadlines (same shape as root).
        let mut accounts = HashSet::new();
        accounts.insert(999);
        let table =
            SessionTable::with_service_accounts(accounts, Arc::new(RwLock::new(HashSet::new())));
        let reader = StubReader::default();
        reader.set_ppid(1234, 2000);
        reader.set_ruid(2000, 999);

        let (key, is_new) = table.resolve(&reader, 999, 1234).unwrap();
        assert_eq!(key, (999, 2000));
        assert!(is_new);
        let sess = table.get(&key).unwrap();
        assert_eq!(sess.role, Role::Admin);
        assert!(sess.enabled);
        assert!(sess.enable_expires.is_none());
        assert!(sess.enable_hard_deadline.is_none());

        // Non-service-account uid on the same table stays View.
        reader.set_ppid(1235, 3000);
        reader.set_ruid(3000, 1000);
        let (other, _) = table.resolve(&reader, 1000, 1235).unwrap();
        let other_sess = table.get(&other).unwrap();
        assert_eq!(other_sess.role, Role::View);
        assert!(!other_sess.enabled);
    }

    #[test]
    fn require_admin_rejects_unknown_session() {
        let table = SessionTable::new();
        assert_eq!(
            table.require_admin(&(1000, 999)).unwrap_err(),
            AuthzError::NoSession
        );
    }

    #[test]
    fn require_admin_rejects_view_session() {
        let table = SessionTable::new();
        table.insert_for_test((1000, 999), Instant::now());
        assert_eq!(
            table.require_admin(&(1000, 999)).unwrap_err(),
            AuthzError::NotAdmin
        );
    }

    #[test]
    fn require_admin_succeeds_for_enabled_session_and_extends_ttl() {
        let table = SessionTable::new();
        table.insert_for_test((1000, 999), Instant::now());
        // Time-bounded promotion (typical enable result).
        table.promote_to_admin(
            &(1000, 999),
            Duration::from_secs(10),
            Duration::from_secs(60),
        );
        let before = table.get(&(1000, 999)).unwrap().enable_expires.unwrap();
        std::thread::sleep(Duration::from_millis(5));
        assert!(table.require_admin(&(1000, 999)).is_ok());
        let after = table.get(&(1000, 999)).unwrap().enable_expires.unwrap();
        assert!(after > before, "sliding TTL should extend on success");
    }

    #[test]
    fn require_admin_downgrades_after_idle_expiry() {
        let table = SessionTable::new();
        table.insert_for_test((1000, 999), Instant::now());
        // 1-ms idle TTL, generous hard cap.
        table.promote_to_admin(
            &(1000, 999),
            Duration::from_millis(1),
            Duration::from_secs(60),
        );
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(
            table.require_admin(&(1000, 999)).unwrap_err(),
            AuthzError::EnableExpired
        );
        let s = table.get(&(1000, 999)).unwrap();
        assert!(!s.enabled, "should have been downgraded");
        assert_eq!(s.role, Role::View);
        assert!(s.enable_expires.is_none());
    }

    #[test]
    fn require_admin_downgrades_after_hard_cap() {
        let table = SessionTable::new();
        table.insert_for_test((1000, 999), Instant::now());
        // Long idle TTL but 1-ms hard cap so the cap fires first.
        table.promote_to_admin(
            &(1000, 999),
            Duration::from_secs(60),
            Duration::from_millis(1),
        );
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(
            table.require_admin(&(1000, 999)).unwrap_err(),
            AuthzError::EnableExpired
        );
    }

    #[test]
    fn require_admin_is_noop_for_permanent_admin() {
        // Root and service-account sessions have no deadlines; require_admin
        // should succeed without touching the (None) deadline fields.
        let mut accounts = HashSet::new();
        accounts.insert(999);
        let table =
            SessionTable::with_service_accounts(accounts, Arc::new(RwLock::new(HashSet::new())));
        let reader = StubReader::default();
        reader.set_ppid(1234, 2000);
        reader.set_ruid(2000, 999);
        table.resolve(&reader, 999, 1234).unwrap();
        assert!(table.require_admin(&(999, 2000)).is_ok());
        let s = table.get(&(999, 2000)).unwrap();
        assert!(s.enabled);
        assert!(s.enable_expires.is_none());
        assert!(s.enable_hard_deadline.is_none());
    }

    #[test]
    fn is_service_account_reports_membership() {
        let mut accounts = HashSet::new();
        accounts.insert(999);
        accounts.insert(1001);
        let table =
            SessionTable::with_service_accounts(accounts, Arc::new(RwLock::new(HashSet::new())));
        assert!(table.is_service_account(999));
        assert!(table.is_service_account(1001));
        assert!(!table.is_service_account(1000));
        assert!(!table.is_service_account(0));
    }

    #[test]
    fn yang_service_accounts_union_with_env() {
        // Env contributes 999. YANG arc is mutated externally to add 1001.
        // is_service_account reports the union.
        let mut env_accounts = HashSet::new();
        env_accounts.insert(999);
        let yang = Arc::new(RwLock::new(HashSet::new()));
        let table = SessionTable::with_service_accounts(env_accounts, yang.clone());

        assert!(table.is_service_account(999));
        assert!(!table.is_service_account(1001));

        // Simulate ConfigManager committing `set vty service-account uid 1001`.
        yang.write().unwrap().insert(1001);

        assert!(table.is_service_account(999));
        assert!(table.is_service_account(1001));
        assert!(!table.is_service_account(2000));

        // Simulate a delete commit.
        yang.write().unwrap().remove(&1001);
        assert!(table.is_service_account(999));
        assert!(!table.is_service_account(1001));
    }

    #[test]
    fn yang_service_account_session_starts_as_permanent_admin() {
        // Mirror of the env-set test, but the uid lives in the YANG arc.
        let yang = Arc::new(RwLock::new(HashSet::new()));
        yang.write().unwrap().insert(1001);
        let table = SessionTable::with_service_accounts(HashSet::new(), yang);
        let reader = StubReader::default();
        reader.set_ppid(1234, 4000);
        reader.set_ruid(4000, 1001);

        let (key, is_new) = table.resolve(&reader, 1001, 1234).unwrap();
        assert!(is_new);
        let sess = table.get(&key).unwrap();
        assert_eq!(sess.role, Role::Admin);
        assert!(sess.enabled);
        assert!(sess.enable_expires.is_none());
    }

    #[test]
    fn root_session_starts_as_permanent_admin() {
        // D20: uid=0 is implicit Admin from session creation, with
        // no deadlines.
        let table = SessionTable::new();
        let reader = StubReader::default();
        reader.set_ppid(1234, 999);
        reader.set_ruid(999, 0);
        let (key, is_new) = table.resolve(&reader, 0, 1234).unwrap();
        assert_eq!(key, (0, 999));
        assert!(is_new);
        let sess = table.get(&key).unwrap();
        assert_eq!(sess.role, Role::Admin);
        assert!(sess.enabled);
        assert!(sess.enable_expires.is_none());
        assert!(sess.enable_hard_deadline.is_none());
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

    #[test]
    fn remove_returns_true_when_session_present() {
        let table = SessionTable::new();
        table.insert_for_test((1000, 1000), Instant::now());
        assert!(table.remove(&(1000, 1000)));
        assert_eq!(table.len(), 0);
        assert!(!table.remove(&(1000, 1000)));
    }

    #[tokio::test]
    async fn watcher_removes_session_when_bash_dies() {
        // Spawn a real child that will live long enough for us to register a
        // pidfd watcher, then kill it and verify the session is removed.
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("60")
            .spawn()
            .expect("spawn /bin/sleep");
        let bash_pid = child.id();
        let key = (1000u32, bash_pid);

        let table = SessionTable::new();
        table.insert_for_test(key, Instant::now());

        let watcher_table = table.clone();
        let watcher = tokio::spawn(async move {
            super::watch_bash_death(watcher_table, key, bash_pid).await;
        });

        // Brief pause so the watcher gets a chance to register the pidfd
        // before the child exits — otherwise we'd be racing the kernel.
        tokio::time::sleep(Duration::from_millis(50)).await;
        child.kill().expect("kill child");
        let _ = child.wait();

        // Watcher should finish within a couple of seconds; allow generous
        // headroom on slow CI runners.
        tokio::time::timeout(Duration::from_secs(5), watcher)
            .await
            .expect("watcher timed out")
            .expect("watcher panicked");

        assert!(table.get(&key).is_none(), "session was not removed");
    }

    #[tokio::test]
    async fn watcher_drops_session_immediately_if_pidfd_open_fails() {
        // PID 0 is invalid for pidfd_open and triggers the open-failure
        // branch, which should remove the session and return.
        let key = (1000u32, 0u32);
        let table = SessionTable::new();
        table.insert_for_test(key, Instant::now());

        super::watch_bash_death(table.clone(), key, 0).await;

        assert!(table.get(&key).is_none());
    }
}
