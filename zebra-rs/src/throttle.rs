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

#[cfg(test)]
mod tests {
    use super::*;

    /// A schedule/run alternation (as the OSPF and IS-IS schedulers do)
    /// yields the initial wait first, then the secondary, then doubles
    /// up to — and holds at — the maximum.
    #[test]
    fn backoff_progression_within_burst() {
        let (init, sec, max) = (50, 200, 5000);
        let mut t = Throttle::default();
        let mut seq = Vec::new();
        for _ in 0..9 {
            seq.push(t.schedule(init, sec, max));
            t.mark_run();
        }
        assert_eq!(seq, vec![50, 200, 400, 800, 1600, 3200, 5000, 5000, 5000]);
    }

    /// A quiet period longer than `2 × maximum` resets the next
    /// schedule back to `initial`.
    #[test]
    fn resets_after_quiet_period() {
        // Tiny maximum (>= secondary) so the quiet window (2×max = 6ms)
        // elapses in a short sleep with generous margin.
        let (init, sec, max) = (1, 2, 3);
        let mut t = Throttle::default();
        assert_eq!(t.schedule(init, sec, max), 1); // initial
        t.mark_run();
        assert_eq!(t.schedule(init, sec, max), 2); // secondary (in burst)
        t.mark_run();
        std::thread::sleep(Duration::from_millis(30));
        assert_eq!(t.schedule(init, sec, max), 1); // quiet → back to initial
    }
}
