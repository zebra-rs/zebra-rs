use std::time::{Duration, Instant};

/// IOS-XR-style exponential-backoff throttle state.
///
/// One instance per "rate-limited thing per level" (one for SPF per
/// level, one for LSP generation per level, etc). The struct holds only
/// the state — the caller owns the actual timer and the work — so the
/// same algorithm can drive different schedulers without coupling them.
///
/// State machine: callers ask `schedule()` for the wait they should use
/// to arm a timer. When the throttled work actually runs, they call
/// `mark_run()`. Subsequent `schedule()` calls within `2 × maximum` of
/// the last run return progressively-doubled waits — initial →
/// secondary → secondary × 2 → ... capped at maximum. After a quiet
/// period longer than `2 × maximum`, the next schedule resets to
/// `initial`.
#[derive(Default, Debug)]
pub struct Throttle {
    pub current_wait_ms: u32,
    pub last_run_at: Option<Instant>,
}

impl Throttle {
    pub fn schedule(&mut self, initial_ms: u32, secondary_ms: u32, maximum_ms: u32) -> u32 {
        let quiet = Duration::from_millis(2u64 * maximum_ms as u64);
        let in_burst = self
            .last_run_at
            .is_some_and(|t| Instant::now().duration_since(t) < quiet);

        let wait_ms = if in_burst {
            self.current_wait_ms
        } else {
            initial_ms
        };

        self.current_wait_ms = if wait_ms == initial_ms {
            secondary_ms.min(maximum_ms)
        } else {
            wait_ms.saturating_mul(2).min(maximum_ms)
        };

        wait_ms
    }

    pub fn mark_run(&mut self) {
        self.last_run_at = Some(Instant::now());
    }
}
