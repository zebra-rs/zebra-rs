//! Anomalous (A) bit evaluation — RFC 8570 §4.1/§4.2 and RFC 7471
//! §4.1/§4.2.
//!
//! The A bit tells receivers "this link's measured delay has crossed
//! the operator's upper bound", so a head-end can steer away from it
//! without waiting for the advertised value itself to make the link
//! unattractive. Clearing it uses a separate, lower *reuse* bound: a
//! link sitting on the threshold would otherwise flap the bit — and
//! with it the LSP/LSA — every export period.
//!
//! Evaluation lives next to, but deliberately outside, the value
//! filter in [`super::damping`]. An anomaly has to reach the LSDB even
//! when the delay barely moved, which is precisely the case the
//! damping gate exists to suppress; the bit therefore travels inside
//! [`MetricSnapshot`](super::stats::MetricSnapshot) and is exported on
//! its own transitions.
//!
//! Each advertised delay value is evaluated separately, because the
//! two RFCs scope the bit differently per sub-TLV. The average-delay
//! sub-TLV sets it when "the measured value of this parameter exceeds
//! its configured maximum threshold" (RFC 8570 §4.1, RFC 7471 §4.1.3)
//! — that parameter being the average. The Min/Max sub-TLV sets it
//! when "one or more measured values exceed a configured maximum
//! threshold" (RFC 8570 §4.2, RFC 7471 §4.2.3) — either bound, not the
//! average of the window. A window of 100 µs and 1500 µs against a
//! 1000 µs bound averages to 800 µs: the average sub-TLV is steady
//! while the Min/Max sub-TLV is advertising an out-of-bounds maximum,
//! and each must say so for itself.
//!
//! Thresholds themselves are *not* evaluated here against one shared
//! policy: they are configured per IGP, so [`DelayAnomaly`] is held per
//! subscriber and fed that subscriber's own bounds.
//!
//! Measured loss (RFC 8570 / RFC 7471 §4.4) reuses [`Anomaly`] with a
//! minimum recovery time on top of the band: see
//! [`Anomaly::evaluate_bounds`] and the measured-loss design, D7.

use std::time::{Duration, Instant};

/// Per-link anomaly bounds in microseconds, resolved from the
/// `te-metric measurement` config block.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AnomalyThresholds {
    /// Delay at or above which the A bit sets. `None` disables
    /// detection — the bit is then never originated, which is the
    /// behaviour of every release before this knob existed.
    pub anomaly_us: Option<u32>,
    /// Delay below which the A bit clears again. Defaults to
    /// `anomaly_us` (no hysteresis band) and is clamped to it: a reuse
    /// bound above the anomaly bound would re-clear the bit in the
    /// same period that set it.
    pub reuse_us: Option<u32>,
}

impl AnomalyThresholds {
    /// The effective `(anomaly, reuse)` pair, or `None` when detection
    /// is off. `reuse <= anomaly` always holds on the way out.
    pub fn bounds(&self) -> Option<(u32, u32)> {
        hysteresis_bounds(self.anomaly_us, self.reuse_us)
    }
}

/// The effective `(anomaly, reuse)` pair from a configured anomaly
/// bound and optional reuse bound, in whatever unit both share: `None`
/// when detection is off, reuse defaulting to the anomaly bound (no
/// band) and clamped to it — a reuse bound above the anomaly bound
/// would clear the bit in the same evaluation that set it.
pub fn hysteresis_bounds(anomaly: Option<u32>, reuse: Option<u32>) -> Option<(u32, u32)> {
    let anomaly = anomaly?;
    Some((anomaly, reuse.unwrap_or(anomaly).min(anomaly)))
}

/// The Anomalous bits for one exported snapshot, one per measured
/// value. Consumers map them onto sub-TLVs: the average drives the
/// average-delay sub-TLV (33 / 27), and the two bounds jointly drive
/// the single A bit of the Min/Max sub-TLV (34 / 28).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct AnomalyFlags {
    pub avg: bool,
    pub min: bool,
    pub max: bool,
}

/// One value's A-bit hysteresis state.
#[derive(Debug, Default)]
pub struct Anomaly {
    anomalous: bool,
    /// When a recovery began: the first evaluation below the reuse bound
    /// while the bit was set. Only a minimum recovery time uses it.
    below_since: Option<Instant>,
}

impl Anomaly {
    /// Fold this period's average delay into the A-bit state and
    /// return the bit to originate.
    ///
    /// At or above the anomaly bound sets, below the reuse bound
    /// clears, and the band between them holds the previous value —
    /// that band is the hysteresis. With detection disabled the state
    /// is forced back to clear, so turning the knob off withdraws a
    /// standing anomaly instead of freezing it into the LSDB.
    ///
    /// The average is the comparison input rather than the min or the
    /// max: min is the Flex-Algo metric and would under-report a link
    /// whose typical delay has degraded, while max reacts to a single
    /// scheduling outlier.
    pub fn evaluate(&mut self, avg_delay_us: u32, thresholds: AnomalyThresholds) -> bool {
        self.evaluate_bounds(avg_delay_us, thresholds.bounds(), None)
    }

    /// The same hysteresis over explicit `(anomaly, reuse)` bounds
    /// (see [`hysteresis_bounds`]), optionally with a minimum recovery
    /// time: `recovery = Some((now, min))`.
    ///
    /// Without one, a value below the reuse bound clears the bit at
    /// once, as delay does: each delay evaluation already averages one
    /// whole advertisement interval. With one, clearing needs every
    /// evaluation to have been below the reuse bound for at least `min`,
    /// timed from the first of them, and any evaluation at or above the
    /// reuse bound restarts the wait. That is RFC 8570 §5's "below …
    /// for one or more advertisement intervals", which the band alone
    /// does not establish: a rolling loss value can dip under the reuse
    /// bound one tick after the loss stops (measured-loss design D7).
    pub fn evaluate_bounds(
        &mut self,
        value: u32,
        bounds: Option<(u32, u32)>,
        recovery: Option<(Instant, Duration)>,
    ) -> bool {
        let Some((anomaly, reuse)) = bounds else {
            self.reset();
            return false;
        };
        if value >= anomaly {
            self.anomalous = true;
            self.below_since = None;
        } else if value >= reuse {
            // The band holds the bit, and interrupts any recovery.
            self.below_since = None;
        } else if self.anomalous {
            match recovery {
                None => self.anomalous = false,
                Some((now, min)) => {
                    let since = *self.below_since.get_or_insert(now);
                    if now.saturating_duration_since(since) >= min {
                        self.reset();
                    }
                }
            }
        }
        self.anomalous
    }

    /// Forget the state. Called when a period produced no samples: the
    /// export that follows withdraws the sub-TLVs outright, so there
    /// is nothing left for the bit to qualify, and a link that comes
    /// back has to earn its anomaly again rather than inherit a stale
    /// one from before the outage.
    pub fn reset(&mut self) {
        self.anomalous = false;
        self.below_since = None;
    }
}

/// Independent hysteresis for each value a snapshot advertises.
///
/// Separate states rather than one shared bit: a window whose average
/// sits inside the bounds while its maximum does not must set the
/// Min/Max sub-TLV's bit and leave the average sub-TLV's clear, and on
/// the way back the average can recover a period before the maximum
/// does.
#[derive(Debug, Default)]
pub struct DelayAnomaly {
    avg: Anomaly,
    min: Anomaly,
    max: Anomaly,
}

impl DelayAnomaly {
    /// Fold one period's values into the per-value states and return
    /// the flags to advertise.
    pub fn evaluate(
        &mut self,
        snapshot: &super::stats::MetricSnapshot,
        thresholds: AnomalyThresholds,
    ) -> AnomalyFlags {
        AnomalyFlags {
            avg: self.avg.evaluate(snapshot.avg, thresholds),
            min: self.min.evaluate(snapshot.min, thresholds),
            max: self.max.evaluate(snapshot.max, thresholds),
        }
    }

    /// Forget every value's state — see [`Anomaly::reset`].
    pub fn reset(&mut self) {
        self.avg.reset();
        self.min.reset();
        self.max.reset();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn thresholds(anomaly: Option<u32>, reuse: Option<u32>) -> AnomalyThresholds {
        AnomalyThresholds {
            anomaly_us: anomaly,
            reuse_us: reuse,
        }
    }

    #[test]
    fn unconfigured_never_reports_anomalous() {
        let mut a = Anomaly::default();
        assert!(!a.evaluate(u32::MAX, AnomalyThresholds::default()));
    }

    #[test]
    fn sets_at_or_above_threshold_clears_below_reuse() {
        let mut a = Anomaly::default();
        let t = thresholds(Some(1_000), Some(800));
        assert!(!a.evaluate(999, t));
        assert!(a.evaluate(1_000, t), "at the bound sets");
        assert!(!a.evaluate(799, t));
    }

    /// The band between reuse and anomaly holds the previous state —
    /// this is what stops a link parked on the bound from flapping the
    /// LSP every export period.
    #[test]
    fn hysteresis_band_holds_previous_state() {
        let mut a = Anomaly::default();
        let t = thresholds(Some(1_000), Some(800));

        // Rising through the band: still clear until the upper bound.
        assert!(!a.evaluate(900, t));
        assert!(a.evaluate(1_200, t));
        // Falling back into the band: stays set until below reuse.
        assert!(a.evaluate(900, t));
        assert!(a.evaluate(800, t), "reuse bound itself still holds");
        assert!(!a.evaluate(799, t));
    }

    /// A reuse bound above the anomaly bound is nonsense config; it
    /// must degenerate to "no hysteresis", not to a bit that clears
    /// itself the instant it sets.
    #[test]
    fn reuse_above_anomaly_is_clamped() {
        let mut a = Anomaly::default();
        let t = thresholds(Some(1_000), Some(5_000));
        assert!(a.evaluate(1_000, t));
        assert!(a.evaluate(1_000, t), "not re-cleared by the bogus reuse");
        assert!(!a.evaluate(999, t));
    }

    /// Unset reuse means no band: the same bound both sets and clears.
    #[test]
    fn reuse_defaults_to_the_anomaly_bound() {
        let mut a = Anomaly::default();
        let t = thresholds(Some(1_000), None);
        assert!(a.evaluate(1_000, t));
        assert!(!a.evaluate(999, t));
    }

    /// Turning detection off must withdraw a standing anomaly, not
    /// leave the last-known bit latched into the LSDB.
    #[test]
    fn disabling_detection_clears_a_standing_anomaly() {
        let mut a = Anomaly::default();
        assert!(a.evaluate(2_000, thresholds(Some(1_000), None)));
        assert!(!a.evaluate(2_000, AnomalyThresholds::default()));
        // And the cleared state persists once the knob comes back.
        assert!(!a.evaluate(999, thresholds(Some(1_000), None)));
    }

    #[test]
    fn reset_drops_the_state() {
        let mut a = Anomaly::default();
        let t = thresholds(Some(1_000), Some(800));
        assert!(a.evaluate(2_000, t));
        a.reset();
        // Without the reset this would hold `true` through the band.
        assert!(!a.evaluate(900, t));
    }

    /// RFC 8570 §4.2 / RFC 7471 §4.2.3: the Min/Max sub-TLV's bit
    /// tracks "one or more measured values", not the window average. A
    /// window of 100 and 1500 us against a 1000 us bound averages to
    /// 800 us — inside the bound — while the advertised maximum is
    /// well outside it, and the two sub-TLVs must disagree.
    #[test]
    fn max_crosses_while_average_stays_inside() {
        use crate::stamp::stats::MetricSnapshot;
        let mut d = DelayAnomaly::default();
        let t = thresholds(Some(1_000), None);
        let snap = MetricSnapshot {
            min: 100,
            max: 1_500,
            avg: 800,
            variation: 0,
            anomaly: AnomalyFlags::default(),
        };
        let flags = d.evaluate(&snap, t);
        assert!(!flags.avg, "average sub-TLV stays steady");
        assert!(!flags.min, "the minimum is inside the bound too");
        assert!(flags.max, "the advertised maximum is not");
    }

    /// Recovery is per value as well: the average can come back inside
    /// the reuse bound a period before the maximum does, and the
    /// Min/Max sub-TLV must keep its bit until its own value recovers.
    #[test]
    fn average_recovers_before_max() {
        use crate::stamp::stats::MetricSnapshot;
        let mut d = DelayAnomaly::default();
        let t = thresholds(Some(1_000), Some(900));
        let snap = |min, max, avg| MetricSnapshot {
            min,
            max,
            avg,
            variation: 0,
            anomaly: AnomalyFlags::default(),
        };

        let flags = d.evaluate(&snap(1_100, 2_000, 1_500), t);
        assert!(flags.avg && flags.min && flags.max, "everything crossed");

        // Average back under the reuse bound, maximum still over.
        let flags = d.evaluate(&snap(100, 2_000, 800), t);
        assert!(!flags.avg, "average sub-TLV clears");
        assert!(!flags.min);
        assert!(flags.max, "Min/Max sub-TLV holds its bit");

        let flags = d.evaluate(&snap(100, 500, 300), t);
        assert!(!flags.max, "and clears once the maximum recovers");
    }

    /// Measured-loss design D7: with a minimum recovery time the bit
    /// clears only once every evaluation for that long has been below
    /// the reuse bound. One evaluation back in the band — not even over
    /// the anomaly bound — restarts the wait.
    #[test]
    fn a_recovery_time_holds_the_bit_until_it_has_elapsed() {
        let t0 = Instant::now();
        let at = |s: u64| t0 + Duration::from_secs(s);
        let min = Duration::from_secs(120);
        let bounds = Some((1_000, 800));
        let mut a = Anomaly::default();
        assert!(a.evaluate_bounds(2_000, bounds, Some((at(0), min))));
        // Below reuse from 30 s: still set at 30 + 90 s.
        for s in [30, 60, 90, 120] {
            assert!(a.evaluate_bounds(100, bounds, Some((at(s), min))), "{s}");
        }
        // Back in the band at 150 s: the wait restarts.
        assert!(a.evaluate_bounds(900, bounds, Some((at(150), min))));
        for s in [180, 210, 240, 270] {
            assert!(a.evaluate_bounds(100, bounds, Some((at(s), min))), "{s}");
        }
        assert!(
            !a.evaluate_bounds(100, bounds, Some((at(300), min))),
            "120 s below reuse since 180 s"
        );
        // A clear bit stays clear below reuse, and sets again at once.
        assert!(!a.evaluate_bounds(100, bounds, Some((at(330), min))));
        assert!(a.evaluate_bounds(1_000, bounds, Some((at(360), min))));
    }

    /// Without a recovery time, `evaluate_bounds` is the delay
    /// hysteresis exactly; a reset also forgets a recovery under way.
    #[test]
    fn no_recovery_time_clears_at_once_and_reset_forgets_a_recovery() {
        let t0 = Instant::now();
        let min = Duration::from_secs(120);
        let bounds = Some((1_000, 800));
        let mut a = Anomaly::default();
        assert!(a.evaluate_bounds(2_000, bounds, None));
        assert!(!a.evaluate_bounds(799, bounds, None));

        assert!(a.evaluate_bounds(2_000, bounds, Some((t0, min))));
        assert!(a.evaluate_bounds(100, bounds, Some((t0, min))));
        a.reset();
        assert!(
            !a.evaluate_bounds(900, bounds, None),
            "the band holds a clear bit"
        );
        assert!(a.evaluate_bounds(2_000, bounds, Some((t0 + min, min))));
        assert!(
            a.evaluate_bounds(100, bounds, Some((t0 + min * 2, min))),
            "a recovery started before the reset does not count"
        );
        assert!(!a.evaluate_bounds(100, None, None), "detection off clears");
    }

    /// An empty window withdraws the sub-TLVs, so every value's state
    /// goes with them rather than leaking into the next adjacency.
    #[test]
    fn reset_clears_every_value() {
        use crate::stamp::stats::MetricSnapshot;
        let mut d = DelayAnomaly::default();
        let t = thresholds(Some(1_000), Some(900));
        let snap = MetricSnapshot {
            min: 2_000,
            max: 2_000,
            avg: 2_000,
            variation: 0,
            anomaly: AnomalyFlags::default(),
        };
        assert_eq!(
            d.evaluate(&snap, t),
            AnomalyFlags {
                avg: true,
                min: true,
                max: true
            }
        );
        d.reset();
        let back = MetricSnapshot {
            min: 950,
            max: 950,
            avg: 950,
            variation: 0,
            anomaly: AnomalyFlags::default(),
        };
        // 950 sits in the hysteresis band: without the reset it would
        // hold `true` for all three.
        assert_eq!(d.evaluate(&back, t), AnomalyFlags::default());
    }
}
