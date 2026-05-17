//! Per-uid rate limiter for the `enable` RPC (D17).
//!
//! Simple sliding-window counter held in memory. 5 failures within 30 s
//! triggers a 30 s lockout for that uid. A success resets the window.
//! State is in-memory only; it does not survive daemon restart (D3).

use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use dashmap::DashMap;

/// Window length over which failures accumulate.
pub const WINDOW: Duration = Duration::from_secs(30);
/// Failures within `WINDOW` that trigger a lockout.
pub const MAX_FAILURES: u32 = 5;
/// How long the uid stays locked out once `MAX_FAILURES` is reached.
pub const LOCKOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy)]
struct State {
    /// Timestamp of the first failure in the current window.
    window_started: Instant,
    /// Number of failures in the current window.
    failures: u32,
    /// If set, requests are rejected until this instant.
    locked_until: Option<Instant>,
}

impl State {
    fn fresh(now: Instant) -> Self {
        Self {
            window_started: now,
            failures: 0,
            locked_until: None,
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, Default)]
pub struct EnableRateLimiter {
    state: DashMap<u32, State>,
}

#[cfg(target_os = "linux")]
impl EnableRateLimiter {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: DashMap::new(),
        })
    }

    /// Check whether the uid is currently allowed to attempt `enable`.
    /// Returns `Err(remaining)` if currently locked out.
    pub fn check(&self, uid: u32) -> Result<(), Duration> {
        self.check_at(uid, Instant::now())
    }

    /// Record an authentication failure. Returns true if this failure
    /// triggered a lockout.
    pub fn record_failure(&self, uid: u32) -> bool {
        self.record_failure_at(uid, Instant::now())
    }

    /// Reset the uid's failure window after a successful authentication.
    pub fn record_success(&self, uid: u32) {
        self.state.remove(&uid);
    }

    // Testable inner methods that take an explicit `now`.

    fn check_at(&self, uid: u32, now: Instant) -> Result<(), Duration> {
        if let Some(s) = self.state.get(&uid)
            && let Some(until) = s.locked_until
            && now < until
        {
            return Err(until.saturating_duration_since(now));
        }
        Ok(())
    }

    fn record_failure_at(&self, uid: u32, now: Instant) -> bool {
        let mut entry = self.state.entry(uid).or_insert_with(|| State::fresh(now));

        // If the previous window has expired, start a fresh one.
        if now.saturating_duration_since(entry.window_started) > WINDOW {
            *entry = State::fresh(now);
        }
        entry.failures += 1;

        if entry.failures >= MAX_FAILURES {
            entry.locked_until = Some(now + LOCKOUT);
            true
        } else {
            false
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn fresh_uid_is_not_locked() {
        let r = EnableRateLimiter::new();
        assert!(r.check(1000).is_ok());
    }

    #[test]
    fn five_failures_trigger_lockout() {
        let r = EnableRateLimiter::new();
        let t0 = Instant::now();
        for i in 0..(MAX_FAILURES - 1) {
            let triggered = r.record_failure_at(1000, t0 + Duration::from_millis(100 * i as u64));
            assert!(!triggered, "should not lock after {} failures", i + 1);
        }
        let triggered = r.record_failure_at(1000, t0 + Duration::from_secs(1));
        assert!(triggered, "should lock on the 5th failure");
        let err = r
            .check_at(1000, t0 + Duration::from_secs(1))
            .expect_err("locked");
        assert!(err > Duration::from_secs(25));
    }

    #[test]
    fn lockout_expires_after_30s() {
        let r = EnableRateLimiter::new();
        let t0 = Instant::now();
        for i in 0..MAX_FAILURES {
            r.record_failure_at(1000, t0 + Duration::from_millis(100 * i as u64));
        }
        assert!(r.check_at(1000, t0 + Duration::from_secs(10)).is_err());
        assert!(r.check_at(1000, t0 + Duration::from_secs(31)).is_ok());
    }

    #[test]
    fn window_resets_after_30s_of_quiet() {
        // 4 failures, then wait 31 s, then a fresh failure starts a new
        // window — should not trigger lockout.
        let r = EnableRateLimiter::new();
        let t0 = Instant::now();
        for i in 0..(MAX_FAILURES - 1) {
            r.record_failure_at(1000, t0 + Duration::from_millis(100 * i as u64));
        }
        let triggered = r.record_failure_at(1000, t0 + Duration::from_secs(31));
        assert!(!triggered);
        assert!(r.check_at(1000, t0 + Duration::from_secs(31)).is_ok());
    }

    #[test]
    fn record_success_clears_state() {
        let r = EnableRateLimiter::new();
        let t0 = Instant::now();
        r.record_failure_at(1000, t0);
        r.record_failure_at(1000, t0 + Duration::from_millis(100));
        r.record_success(1000);
        // A subsequent failure should be counted from zero again.
        assert!(!r.record_failure_at(1000, t0 + Duration::from_millis(200)));
    }

    #[test]
    fn lockout_is_per_uid() {
        let r = EnableRateLimiter::new();
        let t0 = Instant::now();
        for _ in 0..MAX_FAILURES {
            r.record_failure_at(1000, t0);
        }
        assert!(r.check_at(1000, t0).is_err());
        assert!(r.check_at(1001, t0).is_ok());
    }
}
