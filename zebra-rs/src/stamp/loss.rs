//! Probe-loss accounting — design D2, D4 and D5 of
//! `docs/design/stamp-measured-loss.md`.
//!
//! Every probe a session sends is **settled exactly once**: *received*
//! when its reply arrives, or *lost* once [`LOSS_WAIT`] passes without
//! one (RFC 7680's waiting time, *Tmax*). The probe is credited to the
//! loss bucket that is open *when it settles*, not the one it was sent
//! in. That removes the window-boundary skew of the counter this
//! replaces, where a probe sent just before a window closed had its
//! reply counted in the next window — one loss too many, then one reply
//! too many, with a `saturating_sub` hiding the negative.
//!
//! A reply is matched by the **copied Session-Sender sequence number**,
//! and it counts as received whatever its timestamps say: the packet
//! came back, so it was not lost. A timestamp fault is a delay problem,
//! and the delay path keeps rejecting it on its own.
//!
//! Loss runs on **its own clock**: fixed [`BUCKET`]s, independent of the
//! delay export period. A loss window is the sum of the last N closed
//! buckets, so the value is literally "the percentage of probes lost
//! over the last N × 30 s". Each bucket also records how many probes the
//! probe rate then in force should have produced, which keeps the
//! integrity check exact across a probe-interval retune.
//!
//! Nothing here reaches an IGP yet; `show stamp` renders it.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// RFC 7680's waiting time: a probe with no reply after this long is
/// lost, and a reply arriving later is *late* — still lost. It must
/// exceed any real one-link round trip by a wide margin and be much
/// shorter than a bucket; 3 s is both at every supported interval.
pub const LOSS_WAIT: Duration = Duration::from_secs(3);

/// The loss clock's bucket length: RFC 8570 §7's default measurement
/// interval.
pub const BUCKET: Duration = Duration::from_secs(30);

/// Buckets kept: the longest loss interval a subscriber may configure
/// (3600 s) divided by [`BUCKET`].
pub const MAX_BUCKETS: usize = 120;

/// The default loss interval in buckets — 120 s, RFC 8570 §7's default
/// announcement periodicity.
pub const DEFAULT_WINDOW_BUCKETS: usize = 4;

/// Settled probes remembered after they leave the pending queue, so a
/// reply for one can still be told apart as late or duplicate.
const RECENT: usize = 64;

/// RFC 8570 §4.4's largest link-loss value, 2²⁴ − 2 (50.331642 %).
/// Larger measurements are encoded as this.
pub const MAX_ENCODED_LOSS: u32 = 16_777_214;

/// Settled counts for one [`BUCKET`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Bucket {
    /// Probes that settled in this bucket, received or lost.
    pub settled: u32,
    /// The settled probes that were lost.
    pub lost: u32,
    /// Probes the probe interval in force should have produced during
    /// this bucket, in thousandths of a probe.
    pub expected_milli: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fate {
    Outstanding,
    Received,
    Lost,
}

#[derive(Debug)]
struct Pending {
    seq: u32,
    sent_at: Instant,
    fate: Fate,
}

/// What a reply turned out to be, for the ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyFate {
    /// It settled an outstanding probe as received.
    Received,
    /// Its probe had already settled as lost. It stays lost (RFC 7680).
    Late,
    /// Its probe had already settled as received.
    Duplicate,
    /// No probe this ledger knows of — for example one sent before the
    /// session was re-created.
    Unmatched,
}

/// Per-session probe-loss ledger.
#[derive(Debug)]
pub struct LossLedger {
    /// Probes in send order, until they settle and reach the front.
    pending: VecDeque<Pending>,
    /// Recently settled probes that have left `pending`, oldest first.
    recent: VecDeque<(u32, Fate)>,
    current: Bucket,
    /// Closed buckets, oldest first; at most [`MAX_BUCKETS`].
    closed: VecDeque<Bucket>,
    /// Expected probes have been accrued up to this instant.
    mark: Instant,
    pub late: u64,
    pub duplicate: u64,
    pub unmatched: u64,
}

impl LossLedger {
    pub fn new(now: Instant) -> Self {
        Self {
            pending: VecDeque::new(),
            recent: VecDeque::new(),
            current: Bucket::default(),
            closed: VecDeque::new(),
            mark: now,
            late: 0,
            duplicate: 0,
            unmatched: 0,
        }
    }

    /// A probe with sequence number `seq` went out.
    pub fn sent(&mut self, seq: u32, now: Instant) {
        self.pending.push_back(Pending {
            seq,
            sent_at: now,
            fate: Fate::Outstanding,
        });
    }

    /// A reply carrying Session-Sender sequence number `sender_seq`
    /// arrived. An outstanding probe settles as received, in the bucket
    /// open now.
    pub fn reply(&mut self, sender_seq: u32) -> ReplyFate {
        if let Some(p) = self.pending.iter_mut().find(|p| p.seq == sender_seq) {
            return match p.fate {
                Fate::Outstanding => {
                    p.fate = Fate::Received;
                    self.current.settled += 1;
                    ReplyFate::Received
                }
                Fate::Received => {
                    self.duplicate += 1;
                    ReplyFate::Duplicate
                }
                Fate::Lost => {
                    self.late += 1;
                    ReplyFate::Late
                }
            };
        }
        match self.recent.iter().rev().find(|(seq, _)| *seq == sender_seq) {
            Some((_, Fate::Lost)) => {
                self.late += 1;
                ReplyFate::Late
            }
            Some(_) => {
                self.duplicate += 1;
                ReplyFate::Duplicate
            }
            None => {
                self.unmatched += 1;
                ReplyFate::Unmatched
            }
        }
    }

    /// Settle every probe that has waited [`LOSS_WAIT`] without a reply
    /// as lost, then retire settled probes from the front of the queue.
    ///
    /// Called often (on every probe, and before a bucket closes), so a
    /// probe settles within one probe interval of its deadline.
    pub fn sweep(&mut self, now: Instant) {
        for p in self.pending.iter_mut() {
            if p.fate == Fate::Outstanding && now.duration_since(p.sent_at) >= LOSS_WAIT {
                p.fate = Fate::Lost;
                self.current.settled += 1;
                self.current.lost += 1;
            }
        }
        // Retire in send order only: a received probe behind an
        // outstanding one waits, so the queue stays in sequence order.
        while self
            .pending
            .front()
            .is_some_and(|p| p.fate != Fate::Outstanding)
        {
            let p = self.pending.pop_front().expect("front checked");
            self.recent.push_back((p.seq, p.fate));
            if self.recent.len() > RECENT {
                self.recent.pop_front();
            }
        }
    }

    /// Credit the open bucket with the probes `interval_ms` should have
    /// produced since the last mark. Called when the interval is about
    /// to change, and when a bucket closes.
    pub fn accrue(&mut self, now: Instant, interval_ms: u32) {
        let elapsed_ms = now.duration_since(self.mark).as_millis() as u64;
        self.current.expected_milli += elapsed_ms * 1000 / u64::from(interval_ms.max(1));
        self.mark = now;
    }

    /// Where expected probes have been accrued up to — for tests that
    /// check a retune accrued before the interval changed.
    #[cfg(test)]
    pub(super) fn mark(&self) -> Instant {
        self.mark
    }

    /// Close the open bucket (the loss clock fired) and start a new one.
    pub fn close_bucket(&mut self, now: Instant, interval_ms: u32) {
        self.sweep(now);
        self.accrue(now, interval_ms);
        self.closed.push_back(self.current);
        if self.closed.len() > MAX_BUCKETS {
            self.closed.pop_front();
        }
        self.current = Bucket::default();
    }

    /// The last `buckets` closed buckets, summed. Fewer are summed while
    /// the session is younger than that; [`LossWindow::is_full`] says
    /// which.
    pub fn window(&self, buckets: usize) -> LossWindow {
        let wanted = buckets.clamp(1, MAX_BUCKETS);
        let mut w = LossWindow {
            buckets: 0,
            wanted,
            settled: 0,
            lost: 0,
            expected_milli: 0,
        };
        for b in self.closed.iter().rev().take(wanted) {
            w.buckets += 1;
            w.settled += u64::from(b.settled);
            w.lost += u64::from(b.lost);
            w.expected_milli += b.expected_milli;
        }
        w
    }
}

/// Loss over a run of closed buckets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LossWindow {
    /// Closed buckets summed.
    pub buckets: usize,
    /// Buckets the window is meant to span.
    pub wanted: usize,
    pub settled: u64,
    pub lost: u64,
    pub expected_milli: u64,
}

impl LossWindow {
    /// Whether the session has been measuring for the whole window. No
    /// measured loss is advertised before this (design D5): a value from
    /// a handful of probes is noise in a unit of 0.000003 %.
    pub fn is_full(&self) -> bool {
        self.buckets >= self.wanted
    }

    /// Window length in seconds.
    pub fn secs(&self) -> u64 {
        self.wanted as u64 * BUCKET.as_secs()
    }

    /// Loss as a percentage, or `None` before any probe has settled.
    pub fn percent(&self) -> Option<f64> {
        (self.settled > 0).then(|| self.lost as f64 * 100.0 / self.settled as f64)
    }

    /// The smallest step this window can express: one probe, as a
    /// percentage. The honest limit of synthetic probing.
    pub fn resolution_percent(&self) -> Option<f64> {
        (self.settled > 0).then(|| 100.0 / self.settled as f64)
    }

    /// Settled probes as a percentage of those the probe rate should
    /// have produced, capped at 100. Settlement trails sending by up to
    /// [`LOSS_WAIT`], so a window can briefly read a little over.
    pub fn integrity_percent(&self) -> Option<u32> {
        (self.expected_milli > 0)
            .then(|| (self.settled * 100_000 / self.expected_milli).min(100) as u32)
    }

    /// RFC 8570 §4.4 / RFC 7471 §4.4 encoding, in units of 0.000003 %,
    /// rounded to nearest and capped at [`MAX_ENCODED_LOSS`] as the RFC
    /// requires.
    pub fn encoded(&self) -> Option<u32> {
        (self.settled > 0).then(|| encode_loss(self.lost, self.settled))
    }
}

/// `lost / settled` in RFC 8570 units: `ratio × 100 / 0.000003`, i.e.
/// `lost × 10⁸ / (3 × settled)`, rounded to nearest.
pub fn encode_loss(lost: u64, settled: u64) -> u32 {
    if settled == 0 {
        return 0;
    }
    let num = u128::from(lost) * 200_000_000 + 3 * u128::from(settled);
    let value = num / (6 * u128::from(settled));
    value.min(u128::from(MAX_ENCODED_LOSS)) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(base: Instant, ms: u64) -> Instant {
        base + Duration::from_millis(ms)
    }

    /// The fault this replaces: a probe sent just before a window
    /// closes, whose reply arrives just after, must count as received
    /// exactly once — never as a loss in the first window plus a spare
    /// reply in the second.
    #[test]
    fn a_reply_across_a_bucket_boundary_counts_once_as_received() {
        let t0 = Instant::now();
        let mut l = LossLedger::new(t0);
        l.sent(7, at(t0, 29_990));
        l.close_bucket(at(t0, 30_000), 1000);
        assert_eq!(l.reply(7), ReplyFate::Received);
        l.close_bucket(at(t0, 60_000), 1000);
        let w = l.window(2);
        assert_eq!((w.settled, w.lost), (1, 0));
        // The probe settled after the first bucket closed, so it is
        // credited to the second.
        assert_eq!(l.window(1).settled, 1);
    }

    #[test]
    fn a_probe_with_no_reply_settles_lost_after_the_waiting_time() {
        let t0 = Instant::now();
        let mut l = LossLedger::new(t0);
        l.sent(1, t0);
        l.sweep(at(t0, 2_999));
        l.close_bucket(at(t0, 2_999), 1000);
        assert_eq!(l.window(1).settled, 0, "still within LOSS_WAIT");
        l.sweep(at(t0, 3_000));
        l.close_bucket(at(t0, 3_000), 1000);
        let w = l.window(1);
        assert_eq!((w.settled, w.lost), (1, 1));
    }

    /// RFC 7680: a reply after the waiting time does not un-lose the
    /// probe; it is counted as late. (A lost probe is always retired in
    /// the sweep that settles it — every older probe has timed out too —
    /// so the late reply is always matched against `recent`.)
    #[test]
    fn a_late_reply_stays_lost() {
        let t0 = Instant::now();
        let mut l = LossLedger::new(t0);
        l.sent(1, t0);
        l.sweep(at(t0, 3_000));
        assert_eq!(l.reply(1), ReplyFate::Late);
        l.sent(2, at(t0, 4_000));
        l.sweep(at(t0, 7_000));
        l.sweep(at(t0, 7_001)); // both retired now
        assert_eq!(l.reply(2), ReplyFate::Late);
        l.close_bucket(at(t0, 8_000), 1000);
        let w = l.window(1);
        assert_eq!((w.settled, w.lost, l.late), (2, 2, 2));
    }

    #[test]
    fn duplicate_and_unmatched_replies_are_not_counted() {
        let t0 = Instant::now();
        let mut l = LossLedger::new(t0);
        l.sent(5, t0);
        assert_eq!(l.reply(5), ReplyFate::Received);
        assert_eq!(l.reply(5), ReplyFate::Duplicate, "while queued");
        l.sweep(at(t0, 10));
        assert_eq!(l.reply(5), ReplyFate::Duplicate, "after retirement");
        assert_eq!(l.reply(99), ReplyFate::Unmatched);
        l.close_bucket(at(t0, 30_000), 1000);
        let w = l.window(1);
        assert_eq!((w.settled, w.lost), (1, 0));
        assert_eq!((l.duplicate, l.unmatched), (2, 1));
    }

    /// Replies can overtake one another. An out-of-order reply settles
    /// its own probe, and an older outstanding one is still waited for.
    #[test]
    fn a_reordered_reply_is_not_a_loss() {
        let t0 = Instant::now();
        let mut l = LossLedger::new(t0);
        for seq in [10, 11, 12] {
            l.sent(seq, t0);
        }
        assert_eq!(l.reply(10), ReplyFate::Received);
        assert_eq!(l.reply(12), ReplyFate::Received);
        l.sweep(at(t0, 1_000));
        assert_eq!(l.reply(11), ReplyFate::Received);
        l.sweep(at(t0, 5_000));
        l.close_bucket(at(t0, 30_000), 1000);
        let w = l.window(1);
        assert_eq!((w.settled, w.lost), (3, 0));
    }

    #[test]
    fn sequence_numbers_match_across_wrap() {
        let t0 = Instant::now();
        let mut l = LossLedger::new(t0);
        l.sent(u32::MAX, t0);
        l.sent(0, t0);
        assert_eq!(l.reply(0), ReplyFate::Received);
        assert_eq!(l.reply(u32::MAX), ReplyFate::Received);
    }

    #[test]
    fn the_window_sums_the_newest_buckets_and_reports_when_it_is_full() {
        let t0 = Instant::now();
        let mut l = LossLedger::new(t0);
        let mut seq = 0;
        for bucket in 0..5u64 {
            // Bucket b loses b of its 10 probes.
            for i in 0..10u64 {
                l.sent(seq, at(t0, bucket * 30_000 + i));
                if i >= bucket {
                    l.reply(seq);
                }
                seq += 1;
            }
            l.close_bucket(at(t0, bucket * 30_000 + 10_000), 1000);
            if bucket < 3 {
                assert!(!l.window(4).is_full());
            }
        }
        let w = l.window(4);
        assert!(w.is_full());
        assert_eq!(w.buckets, 4);
        // Buckets 1..=4: 40 probes, 1 + 2 + 3 + 4 lost.
        assert_eq!((w.settled, w.lost), (40, 10));
        assert_eq!(w.secs(), 120);
        assert_eq!(w.percent(), Some(25.0));
        assert_eq!(w.resolution_percent(), Some(2.5));
    }

    #[test]
    fn the_ring_keeps_at_most_max_buckets() {
        let t0 = Instant::now();
        let mut l = LossLedger::new(t0);
        for i in 0..(MAX_BUCKETS as u64 + 5) {
            l.close_bucket(at(t0, i * 30_000), 1000);
        }
        assert_eq!(l.window(MAX_BUCKETS).buckets, MAX_BUCKETS);
        assert_eq!(l.closed.len(), MAX_BUCKETS);
    }

    /// Each bucket carries its own expected count, so a retune from 1 s
    /// to 100 ms mid-bucket is credited at both rates: 10 s at 1 s plus
    /// 20 s at 100 ms = 10 + 200 probes.
    #[test]
    fn expected_probes_follow_a_retune_within_a_bucket() {
        let t0 = Instant::now();
        let mut l = LossLedger::new(t0);
        l.accrue(at(t0, 10_000), 1000);
        l.close_bucket(at(t0, 30_000), 100);
        assert_eq!(l.window(1).expected_milli, 210_000);
    }

    #[test]
    fn integrity_compares_settled_with_expected() {
        let t0 = Instant::now();
        let mut l = LossLedger::new(t0);
        // 30 probes expected at 1 s; 27 sent and answered.
        for seq in 0..27 {
            l.sent(seq, at(t0, u64::from(seq) * 1000));
            l.reply(seq);
        }
        l.close_bucket(at(t0, 30_000), 1000);
        assert_eq!(l.window(1).integrity_percent(), Some(90));
        // Nothing expected yet: no integrity figure.
        assert_eq!(LossLedger::new(t0).window(1).integrity_percent(), None);
    }

    #[test]
    fn encoding_uses_rfc8570_units_and_caps_at_the_maximum() {
        assert_eq!(encode_loss(0, 120), 0);
        // 10 % = 10 / 0.000003 = 3 333 333.3…
        assert_eq!(encode_loss(1, 10), 3_333_333);
        // One probe in 120 = 0.8333… % = 277 777.7… → rounds up.
        assert_eq!(encode_loss(1, 120), 277_778);
        // 50 % is just inside the field: 16 666 666.6… < 16 777 214.
        assert_eq!(encode_loss(1, 2), 16_666_667);
        // 51 % and 100 % exceed 50.331642 % and are capped.
        assert_eq!(encode_loss(51, 100), MAX_ENCODED_LOSS);
        assert_eq!(encode_loss(10, 10), MAX_ENCODED_LOSS);
        assert_eq!(encode_loss(3, 0), 0);
    }
}
