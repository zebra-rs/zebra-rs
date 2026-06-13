//! Export damping — the gate between measured snapshots and IGP
//! re-origination.
//!
//! Every LSP/LSA re-origination floods domain-wide, so a measured
//! value that wiggles by a few microseconds each period must not be
//! re-advertised each period. The gate exports when:
//!
//!   * this is the first snapshot since (re)start or since a clear, or
//!   * the window produced no samples but a value stands advertised —
//!     exported as a **clear** (`None`) so measured values never go
//!     stale when the peer stops reflecting; the IGP withdraws the
//!     sub-TLVs and metric-type-1 topologies prune the link
//!     (RFC 9350 §15), or
//!   * any field moved by more than `max(old/10, 50 µs)` against the
//!     last exported snapshot.
//!
//! The relative threshold suppresses noise on stable links; the
//! absolute floor stops sub-500 µs links from re-originating on every
//! period's worth of scheduler jitter.

use super::stats::MetricSnapshot;

/// Re-export when a field moves by more than `old / THRESHOLD_DIVISOR`.
const THRESHOLD_DIVISOR: u32 = 10;

/// ... but never require less movement than this many microseconds.
const THRESHOLD_FLOOR_US: u32 = 50;

/// Last exported snapshot, `None` before the first export or after a
/// clear. One per session.
#[derive(Debug, Default)]
pub struct Damping {
    last: Option<MetricSnapshot>,
}

impl Damping {
    /// Decide whether `new` (the period's snapshot; `None` = empty
    /// window) must be exported. On `true` the internal comparison
    /// basis is updated — the caller is expected to actually export.
    pub fn should_export(&mut self, new: Option<MetricSnapshot>) -> bool {
        let export = match (&self.last, &new) {
            (None, None) => false,
            (None, Some(_)) => true, // first value
            (Some(_), None) => true, // clear — withdraw stale value
            (Some(old), Some(new)) => significant(old, new),
        };
        if export {
            self.last = new;
        }
        export
    }

    /// Test-only introspection of the comparison basis (production
    /// readers use `Session::last_export`, which mirrors it).
    #[cfg(test)]
    pub fn last(&self) -> Option<&MetricSnapshot> {
        self.last.as_ref()
    }
}

/// Any field moved by more than `max(old/10, 50 µs)`?
fn significant(old: &MetricSnapshot, new: &MetricSnapshot) -> bool {
    moved(old.min, new.min)
        || moved(old.max, new.max)
        || moved(old.avg, new.avg)
        || moved(old.variation, new.variation)
}

fn moved(old: u32, new: u32) -> bool {
    let threshold = (old / THRESHOLD_DIVISOR).max(THRESHOLD_FLOOR_US);
    old.abs_diff(new) > threshold
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(min: u32, max: u32, avg: u32, variation: u32) -> MetricSnapshot {
        MetricSnapshot {
            min,
            max,
            avg,
            variation,
        }
    }

    #[test]
    fn first_snapshot_exports() {
        let mut d = Damping::default();
        assert!(d.should_export(Some(snap(100, 200, 150, 10))));
        assert_eq!(d.last().unwrap().min, 100);
    }

    #[test]
    fn no_samples_and_nothing_advertised_stays_quiet() {
        let mut d = Damping::default();
        assert!(!d.should_export(None));
        assert!(!d.should_export(None));
    }

    #[test]
    fn small_wiggle_suppressed() {
        let mut d = Damping::default();
        assert!(d.should_export(Some(snap(1000, 2000, 1500, 100))));
        // Every field within 10% of the old value — suppressed.
        assert!(!d.should_export(Some(snap(1050, 2100, 1450, 105))));
        // The comparison basis is the *exported* snapshot, not the
        // suppressed one.
        assert_eq!(d.last().unwrap().min, 1000);
    }

    #[test]
    fn floor_suppresses_microsecond_noise_on_fast_links() {
        let mut d = Damping::default();
        assert!(d.should_export(Some(snap(20, 40, 30, 5))));
        // 10% of 20 µs is 2 µs, but the 50 µs floor applies: a move to
        // 60 µs (Δ40) stays quiet ...
        assert!(!d.should_export(Some(snap(60, 40, 30, 5))));
        // ... while a move past the floor (Δ51) fires.
        assert!(d.should_export(Some(snap(71, 40, 30, 5))));
    }

    #[test]
    fn single_field_move_fires() {
        let mut d = Damping::default();
        assert!(d.should_export(Some(snap(1000, 2000, 1500, 100))));
        // Only `max` moves (>10%): export.
        assert!(d.should_export(Some(snap(1000, 2300, 1500, 100))));
    }

    #[test]
    fn empty_window_clears_then_first_export_again() {
        let mut d = Damping::default();
        assert!(d.should_export(Some(snap(1000, 2000, 1500, 100))));
        // Peer stopped reflecting: clear.
        assert!(d.should_export(None));
        assert!(d.last().is_none());
        // Still nothing: quiet.
        assert!(!d.should_export(None));
        // Peer back: first-export semantics again.
        assert!(d.should_export(Some(snap(1010, 2020, 1510, 101))));
    }
}
