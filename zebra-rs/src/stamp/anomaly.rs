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
//! [`MetricSnapshot`](super::stats::MetricSnapshot) and participates
//! in that gate's comparison as a field of its own.

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
    fn bounds(&self) -> Option<(u32, u32)> {
        let anomaly = self.anomaly_us?;
        let reuse = self.reuse_us.unwrap_or(anomaly).min(anomaly);
        Some((anomaly, reuse))
    }
}

/// One session's A-bit hysteresis state.
#[derive(Debug, Default)]
pub struct Anomaly {
    anomalous: bool,
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
        let Some((anomaly, reuse)) = thresholds.bounds() else {
            self.anomalous = false;
            return false;
        };
        if avg_delay_us >= anomaly {
            self.anomalous = true;
        } else if avg_delay_us < reuse {
            self.anomalous = false;
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
}
