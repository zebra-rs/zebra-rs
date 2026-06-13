//! Per-session delay statistics window.
//!
//! Each STAMP session accumulates one [`StatsWindow`] per damping
//! period. At every export tick the window is condensed into a
//! [`MetricSnapshot`] — the min/max/avg delay and delay variation the
//! IGPs advertise (RFC 8570 / RFC 7471 sub-TLVs) — and then reset, so
//! consecutive periods are independent samples of the link.

use serde::Serialize;

/// One damping period's worth of delay measurements, condensed.
/// All fields are microseconds, matching both the IGP sub-TLV units
/// (RFC 8570 §4 / RFC 7471 §4 advertise 24-bit microsecond values)
/// and the existing static `te-metric` config leaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct MetricSnapshot {
    pub min: u32,
    pub max: u32,
    pub avg: u32,
    /// Average delay variation: mean absolute difference between
    /// consecutive samples in the window (RFC 8570 §4.3's "delay
    /// variation" is implementation-defined; consecutive-difference
    /// is the common interpretation and is robust to slow drift).
    pub variation: u32,
}

/// Accumulates samples between export ticks. `sent` / `received`
/// count probes during the current window for the `show stamp` loss
/// figure; they are *not* exported to the IGP (a one-window sample is
/// too noisy to advertise — parent plan §6).
#[derive(Debug, Default)]
pub struct StatsWindow {
    delays: Vec<u32>,
    pub sent: u32,
    pub received: u32,
}

impl StatsWindow {
    pub fn record_sent(&mut self) {
        self.sent = self.sent.saturating_add(1);
    }

    /// Record one valid two-way delay sample (microseconds). The single
    /// entry point for samples — a future kernel-aggregate mode feeds
    /// pre-reduced `{min,max,sum,count}` through the same seam
    /// (offload notes §9b).
    pub fn record_delay(&mut self, delay_us: u32) {
        self.received = self.received.saturating_add(1);
        self.delays.push(delay_us);
    }

    /// Condense the window. `None` when no sample arrived — the caller
    /// turns that into a "clear" export so stale values never linger.
    pub fn snapshot(&self) -> Option<MetricSnapshot> {
        if self.delays.is_empty() {
            return None;
        }
        let min = *self.delays.iter().min().unwrap();
        let max = *self.delays.iter().max().unwrap();
        let sum: u64 = self.delays.iter().map(|&d| d as u64).sum();
        let avg = (sum / self.delays.len() as u64) as u32;
        let variation = if self.delays.len() < 2 {
            0
        } else {
            let total: u64 = self
                .delays
                .windows(2)
                .map(|w| w[0].abs_diff(w[1]) as u64)
                .sum();
            (total / (self.delays.len() - 1) as u64) as u32
        };
        Some(MetricSnapshot {
            min,
            max,
            avg,
            variation,
        })
    }

    /// Start a fresh window (export tick).
    pub fn reset(&mut self) {
        self.delays.clear();
        self.sent = 0;
        self.received = 0;
    }

    /// Probe loss within the current window, percent. `None` until a
    /// probe has been sent.
    pub fn loss_pct(&self) -> Option<u32> {
        if self.sent == 0 {
            return None;
        }
        let lost = self.sent.saturating_sub(self.received);
        Some(lost * 100 / self.sent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_window_has_no_snapshot() {
        let w = StatsWindow::default();
        assert_eq!(w.snapshot(), None);
        assert_eq!(w.loss_pct(), None);
    }

    #[test]
    fn single_sample_snapshot() {
        let mut w = StatsWindow::default();
        w.record_delay(500);
        let s = w.snapshot().unwrap();
        assert_eq!(s.min, 500);
        assert_eq!(s.max, 500);
        assert_eq!(s.avg, 500);
        assert_eq!(s.variation, 0);
    }

    #[test]
    fn min_max_avg_variation() {
        let mut w = StatsWindow::default();
        for d in [100u32, 200, 150, 250] {
            w.record_delay(d);
        }
        let s = w.snapshot().unwrap();
        assert_eq!(s.min, 100);
        assert_eq!(s.max, 250);
        assert_eq!(s.avg, 175);
        // |100−200| + |200−150| + |150−250| = 250; / 3 = 83.
        assert_eq!(s.variation, 83);
    }

    #[test]
    fn reset_clears_everything() {
        let mut w = StatsWindow::default();
        w.record_sent();
        w.record_delay(100);
        w.reset();
        assert_eq!(w.snapshot(), None);
        assert_eq!(w.sent, 0);
        assert_eq!(w.received, 0);
    }

    #[test]
    fn loss_pct_counts_unanswered_probes() {
        let mut w = StatsWindow::default();
        for _ in 0..4 {
            w.record_sent();
        }
        w.record_delay(100);
        assert_eq!(w.loss_pct(), Some(75));
        w.record_delay(100);
        w.record_delay(100);
        w.record_delay(100);
        assert_eq!(w.loss_pct(), Some(0));
    }
}
