//! Probe-loss accounting — design D2, D4 and D5 of
//! `docs/design/stamp-measured-loss.md`.
//!
//! Every probe a session sends is **settled exactly once**: *received*
//! when its reply arrives before its deadline, or *lost* once
//! [`LOSS_WAIT`] (RFC 7680's waiting time, *Tmax*) passes without one.
//! The deadline is judged against the reply's **receive time**, taken
//! at the socket read, not against when the event loop gets round to
//! it. A reply after the deadline is *late*, and its probe stays lost.
//!
//! A reply is matched by the **copied Session-Sender sequence number**,
//! and it counts as received whatever its timestamps say: the packet
//! came back, so it was not lost. A timestamp fault is a delay problem,
//! and the delay path keeps rejecting it on its own.
//!
//! **Buckets are time-indexed** from the ledger's creation: bucket *k*
//! covers `[epoch + k·30 s, epoch + (k+1)·30 s)`. Each settlement is
//! booked into the bucket that contains **its own time** — the receive
//! time for a received probe, the deadline for a lost one — whenever
//! the event loop processes it. The loss clock only advances time
//! ([`LossLedger::advance`]): a skipped tick, or a stall of the whole
//! runtime, becomes buckets with no settlements, never one bucket
//! stretched over several periods. So a window of N buckets always spans
//! exactly N × 30 s, and a measurement gap shows up as an integrity dip
//! rather than as old losses kept past their window.
//!
//! Loss runs on this clock alone, independent of the delay export
//! period. Each bucket also records how many probes the probe rate then
//! in force should have produced, which keeps the integrity check exact
//! across a probe-interval retune.
//!
//! Nothing here reaches an IGP yet; `show stamp` renders it.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// RFC 7680's waiting time: a probe with no reply received within this
/// long is lost, and a reply received later is *late* — still lost. It
/// must exceed any real one-link round trip by a wide margin and be much
/// shorter than a bucket; 3 s is both at every supported interval.
pub const LOSS_WAIT: Duration = Duration::from_secs(3);

/// The loss clock's bucket length: RFC 8570 §7's default measurement
/// interval.
pub const BUCKET: Duration = Duration::from_secs(30);

/// Closed buckets kept: the longest loss interval a subscriber may
/// configure (3600 s) divided by [`BUCKET`].
pub const MAX_BUCKETS: usize = 120;

/// The default loss interval in buckets — 120 s, RFC 8570 §7's default
/// announcement periodicity.
pub const DEFAULT_WINDOW_BUCKETS: usize = 4;

/// Settled probes remembered after they leave the pending queue, so a
/// reply for one can still be told apart as late, duplicate, or — if it
/// was received in time but processed after a sweep — received.
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

#[derive(Debug, Clone, Copy)]
struct Probe {
    seq: u32,
    sent_at: Instant,
    fate: Fate,
}

impl Probe {
    fn deadline(&self) -> Instant {
        self.sent_at + LOSS_WAIT
    }
}

/// What a reply turned out to be, for the ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyFate {
    /// It was received before its probe's deadline, so the probe
    /// settles as received.
    Received,
    /// It was received after its probe's deadline. The probe stays lost
    /// (RFC 7680).
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
    /// Bucket 0 starts here.
    epoch: Instant,
    /// Probes in send order, until they settle and reach the front.
    pending: VecDeque<Probe>,
    /// Recently settled probes that have left `pending`, oldest first.
    recent: VecDeque<Probe>,
    /// Buckets by index, starting at `first`. The back is the open
    /// bucket; every other one has closed.
    buckets: VecDeque<Bucket>,
    first: u64,
    /// Expected probes have been accrued up to this instant.
    mark: Instant,
    pub late: u64,
    pub duplicate: u64,
    pub unmatched: u64,
}

impl LossLedger {
    pub fn new(now: Instant) -> Self {
        Self {
            epoch: now,
            pending: VecDeque::new(),
            recent: VecDeque::new(),
            buckets: VecDeque::from([Bucket::default()]),
            first: 0,
            mark: now,
            late: 0,
            duplicate: 0,
            unmatched: 0,
        }
    }

    fn index(&self, at: Instant) -> u64 {
        (at.saturating_duration_since(self.epoch).as_nanos() / BUCKET.as_nanos()) as u64
    }

    fn open_index(&self) -> u64 {
        self.first + self.buckets.len() as u64 - 1
    }

    fn bucket_end(&self, index: u64) -> Instant {
        self.epoch + Duration::from_secs(BUCKET.as_secs() * (index + 1))
    }

    /// Open buckets up to `index`, closing every one before it. Buckets
    /// no settlement reached stay empty — that is what a gap is.
    fn open_to(&mut self, index: u64) {
        while self.open_index() < index {
            self.buckets.push_back(Bucket::default());
            if self.buckets.len() > MAX_BUCKETS + 1 {
                self.buckets.pop_front();
                self.first += 1;
            }
        }
    }

    /// The bucket containing `at`, if it is still kept.
    fn bucket_at(&mut self, at: Instant) -> Option<&mut Bucket> {
        let index = self.index(at);
        self.open_to(index);
        let offset = index.checked_sub(self.first)?;
        self.buckets.get_mut(offset as usize)
    }

    fn book(&mut self, at: Instant, lost: bool) {
        if let Some(b) = self.bucket_at(at) {
            b.settled += 1;
            if lost {
                b.lost += 1;
            }
        }
    }

    fn unbook(&mut self, at: Instant, lost: bool) {
        if let Some(b) = self.bucket_at(at) {
            b.settled = b.settled.saturating_sub(1);
            if lost {
                b.lost = b.lost.saturating_sub(1);
            }
        }
    }

    /// A probe with sequence number `seq` went out.
    pub fn sent(&mut self, seq: u32, now: Instant) {
        self.pending.push_back(Probe {
            seq,
            sent_at: now,
            fate: Fate::Outstanding,
        });
    }

    /// A reply carrying Session-Sender sequence number `sender_seq` was
    /// received at `rx_at` — the socket read, not whenever the event
    /// loop processes it.
    ///
    /// The deadline is judged here, against `rx_at`, not left to the next
    /// sweep: with a 10 s probe interval nothing sweeps for 10 s, and a
    /// reply 4 s late must not settle its probe as received. (The probe
    /// itself is booked lost, at its deadline, by the next sweep.) A
    /// reply received in time for a probe that a *later* sweep already
    /// declared lost — the reply was queued behind that sweep — still
    /// counts, and the probe moves from lost to received.
    pub fn reply(&mut self, sender_seq: u32, rx_at: Instant) -> ReplyFate {
        let found = match self.pending.iter().position(|p| p.seq == sender_seq) {
            Some(i) => Some((true, i)),
            None => self
                .recent
                .iter()
                .rposition(|p| p.seq == sender_seq)
                .map(|i| (false, i)),
        };
        let Some((queued, i)) = found else {
            self.unmatched += 1;
            return ReplyFate::Unmatched;
        };
        let probe = if queued {
            self.pending[i]
        } else {
            self.recent[i]
        };
        let in_time = rx_at < probe.deadline();
        let fate = match (probe.fate, in_time) {
            (Fate::Received, _) => {
                self.duplicate += 1;
                return ReplyFate::Duplicate;
            }
            (Fate::Outstanding, true) => {
                self.book(rx_at, false);
                ReplyFate::Received
            }
            (Fate::Lost, true) => {
                self.unbook(probe.deadline(), true);
                self.book(rx_at, false);
                ReplyFate::Received
            }
            (_, false) => {
                self.late += 1;
                return ReplyFate::Late;
            }
        };
        let slot = if queued {
            &mut self.pending[i]
        } else {
            &mut self.recent[i]
        };
        slot.fate = Fate::Received;
        fate
    }

    /// Settle every probe whose deadline has passed at `now` as lost —
    /// booked at its deadline, not at `now` — then retire settled probes
    /// from the front of the queue.
    pub fn sweep(&mut self, now: Instant) {
        let overdue: Vec<Instant> = self
            .pending
            .iter_mut()
            .filter(|p| p.fate == Fate::Outstanding && now >= p.deadline())
            .map(|p| {
                p.fate = Fate::Lost;
                p.deadline()
            })
            .collect();
        for deadline in overdue {
            self.book(deadline, true);
        }
        // Retire in send order only: a received probe behind an
        // outstanding one waits, so the queue stays in sequence order.
        while self
            .pending
            .front()
            .is_some_and(|p| p.fate != Fate::Outstanding)
        {
            let p = self.pending.pop_front().expect("front checked");
            self.recent.push_back(p);
            if self.recent.len() > RECENT {
                self.recent.pop_front();
            }
        }
    }

    /// Bring the ledger up to `now`: settle what is overdue, credit each
    /// bucket with the probes `interval_ms` should have produced during
    /// its share of the time since the last call, and close every bucket
    /// that has ended. Called by the loss clock, and — with the *old*
    /// interval — just before a probe-interval retune.
    pub fn advance(&mut self, now: Instant, interval_ms: u32) {
        self.sweep(now);
        let interval = u64::from(interval_ms.max(1));
        while self.mark < now {
            let index = self.index(self.mark);
            let end = self.bucket_end(index).min(now);
            let elapsed_ms = end.duration_since(self.mark).as_millis() as u64;
            if let Some(b) = self.bucket_at(self.mark) {
                b.expected_milli += elapsed_ms * 1000 / interval;
            }
            self.mark = end;
        }
        let now_index = self.index(now);
        self.open_to(now_index);
    }

    /// Where expected probes have been accrued up to — for tests that
    /// check a retune accrued before the interval changed.
    #[cfg(test)]
    pub(super) fn mark(&self) -> Instant {
        self.mark
    }

    /// The last `buckets` closed buckets, summed. Fewer are summed while
    /// the session is younger than that; [`LossWindow::is_full`] says
    /// which. The open bucket is never included.
    pub fn window(&self, buckets: usize) -> LossWindow {
        let wanted = buckets.clamp(1, MAX_BUCKETS);
        let mut w = LossWindow {
            buckets: 0,
            wanted,
            settled: 0,
            lost: 0,
            expected_milli: 0,
        };
        for b in self.buckets.iter().rev().skip(1).take(wanted) {
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

    /// The fault the old counter had: a probe sent just before a bucket
    /// closes, whose reply arrives just after, counts as received exactly
    /// once — credited to the bucket its reply arrived in.
    #[test]
    fn a_reply_across_a_bucket_boundary_counts_once_as_received() {
        let t0 = Instant::now();
        let mut l = LossLedger::new(t0);
        l.sent(7, at(t0, 29_990));
        l.advance(at(t0, 30_000), 1000);
        assert_eq!(l.reply(7, at(t0, 30_005)), ReplyFate::Received);
        l.advance(at(t0, 60_000), 1000);
        let w = l.window(2);
        assert_eq!((w.settled, w.lost), (1, 0));
        assert_eq!(l.window(1).settled, 1, "booked in the second bucket");
    }

    #[test]
    fn a_probe_with_no_reply_settles_lost_at_its_deadline() {
        let t0 = Instant::now();
        let mut l = LossLedger::new(t0);
        l.sent(1, at(t0, 1_000));
        l.sweep(at(t0, 3_999));
        l.advance(at(t0, 30_000), 1000);
        // Swept only at the tick, but booked at its deadline (4 s),
        // in the first bucket.
        let w = l.window(1);
        assert_eq!((w.settled, w.lost), (1, 1));
    }

    /// Review finding: the deadline is enforced when the reply arrives,
    /// not only when a sweep happens to run. With a 10 s probe interval
    /// nothing sweeps between a probe and a reply 4 s later.
    #[test]
    fn a_reply_after_the_deadline_is_late_even_with_no_sweep_in_between() {
        let t0 = Instant::now();
        let mut l = LossLedger::new(t0);
        l.sent(1, t0);
        assert_eq!(l.reply(1, at(t0, 4_000)), ReplyFate::Late);
        l.sent(2, at(t0, 10_000));
        assert_eq!(
            l.reply(2, at(t0, 13_000)),
            ReplyFate::Late,
            "at the deadline"
        );
        l.sent(3, at(t0, 20_000));
        assert_eq!(
            l.reply(3, at(t0, 22_999)),
            ReplyFate::Received,
            "just before it"
        );
        l.advance(at(t0, 30_000), 1000);
        let w = l.window(1);
        assert_eq!((w.settled, w.lost, l.late), (3, 2, 2));
    }

    /// The reverse race: a reply received in time but processed after a
    /// sweep that already declared its probe lost still counts, and the
    /// probe moves from lost to received.
    #[test]
    fn a_reply_received_in_time_counts_even_if_processed_after_a_sweep() {
        let t0 = Instant::now();
        let mut l = LossLedger::new(t0);
        l.sent(1, t0);
        l.sweep(at(t0, 5_000));
        assert_eq!(l.reply(1, at(t0, 1_000)), ReplyFate::Received);
        l.advance(at(t0, 30_000), 1000);
        let w = l.window(1);
        assert_eq!((w.settled, w.lost, l.late), (1, 0, 0));
    }

    #[test]
    fn duplicate_and_unmatched_replies_are_not_counted() {
        let t0 = Instant::now();
        let mut l = LossLedger::new(t0);
        l.sent(5, t0);
        assert_eq!(l.reply(5, at(t0, 10)), ReplyFate::Received);
        assert_eq!(l.reply(5, at(t0, 20)), ReplyFate::Duplicate);
        assert_eq!(l.reply(99, at(t0, 30)), ReplyFate::Unmatched);
        l.advance(at(t0, 30_000), 1000);
        let w = l.window(1);
        assert_eq!((w.settled, w.lost), (1, 0));
        assert_eq!((l.duplicate, l.unmatched), (1, 1));
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
        assert_eq!(l.reply(10, at(t0, 10)), ReplyFate::Received);
        assert_eq!(l.reply(12, at(t0, 20)), ReplyFate::Received);
        assert_eq!(l.reply(11, at(t0, 1_000)), ReplyFate::Received);
        l.advance(at(t0, 30_000), 1000);
        let w = l.window(1);
        assert_eq!((w.settled, w.lost), (3, 0));
    }

    #[test]
    fn sequence_numbers_match_across_wrap() {
        let t0 = Instant::now();
        let mut l = LossLedger::new(t0);
        l.sent(u32::MAX, t0);
        l.sent(0, t0);
        assert_eq!(l.reply(0, at(t0, 5)), ReplyFate::Received);
        assert_eq!(l.reply(u32::MAX, at(t0, 6)), ReplyFate::Received);
    }

    #[test]
    fn the_window_sums_the_newest_buckets_and_reports_when_it_is_full() {
        let t0 = Instant::now();
        let mut l = LossLedger::new(t0);
        let mut seq = 0;
        for bucket in 0..5u64 {
            // Bucket b loses b of its 10 probes.
            let base = bucket * 30_000;
            for i in 0..10u64 {
                l.sent(seq, at(t0, base + i));
                if i >= bucket {
                    l.reply(seq, at(t0, base + i + 5));
                }
                seq += 1;
            }
            l.advance(at(t0, base + 30_000), 1000);
            assert_eq!(l.window(4).is_full(), bucket >= 3, "after bucket {bucket}");
        }
        let w = l.window(4);
        assert_eq!(w.buckets, 4);
        // Buckets 1..=4: 40 probes, 1 + 2 + 3 + 4 lost.
        assert_eq!((w.settled, w.lost), (40, 10));
        assert_eq!(w.secs(), 120);
        assert_eq!(w.percent(), Some(25.0));
        assert_eq!(w.resolution_percent(), Some(2.5));
    }

    /// Review finding: a stall that skips loss ticks must not stretch a
    /// bucket over several periods. One tick after 240 s closes eight
    /// buckets, not one, so the 120 s window really covers 120–240 s: the
    /// loss settled at 30.5 s is outside it, and the empty stretch reads
    /// as zero integrity rather than as a clean link.
    #[test]
    fn a_stall_that_skips_ticks_leaves_empty_buckets_not_a_stretched_one() {
        let t0 = Instant::now();
        let mut l = LossLedger::new(t0);
        l.sent(1, at(t0, 27_500)); // deadline 30.5 s → bucket 1
        l.advance(at(t0, 240_000), 1000);
        let w = l.window(4);
        assert_eq!((w.buckets, w.secs()), (4, 120));
        assert_eq!((w.settled, w.lost), (0, 0), "the old loss has aged out");
        assert_eq!(w.expected_milli, 120_000, "120 s at 1 s expected");
        assert_eq!(w.integrity_percent(), Some(0));
        // The loss is still where it happened.
        let all = l.window(8);
        assert_eq!((all.buckets, all.settled, all.lost), (8, 1, 1));
    }

    #[test]
    fn the_ring_keeps_at_most_max_buckets() {
        let t0 = Instant::now();
        let mut l = LossLedger::new(t0);
        l.advance(at(t0, (MAX_BUCKETS as u64 + 5) * 30_000), 1000);
        assert_eq!(l.window(MAX_BUCKETS).buckets, MAX_BUCKETS);
        assert_eq!(l.buckets.len(), MAX_BUCKETS + 1, "closed plus the open one");
    }

    /// Each bucket carries its own expected count: a retune from 1 s to
    /// 100 ms ten seconds into a bucket is credited at both rates —
    /// 10 s at 1 s plus 20 s at 100 ms = 10 + 200 probes. Expected
    /// probes are also split correctly across a boundary.
    #[test]
    fn expected_probes_follow_a_retune_and_split_at_boundaries() {
        let t0 = Instant::now();
        let mut l = LossLedger::new(t0);
        l.advance(at(t0, 10_000), 1000);
        l.advance(at(t0, 30_000), 100);
        assert_eq!(l.window(1).expected_milli, 210_000);
        l.advance(at(t0, 75_000), 1000); // 30 s into bucket 1, 15 s into 2
        assert_eq!(l.window(1).expected_milli, 30_000);
        l.advance(at(t0, 90_000), 1000);
        assert_eq!(l.window(1).expected_milli, 30_000);
    }

    #[test]
    fn integrity_compares_settled_with_expected() {
        let t0 = Instant::now();
        let mut l = LossLedger::new(t0);
        // 30 probes expected at 1 s; 27 sent and answered.
        for seq in 0..27 {
            let sent = at(t0, u64::from(seq) * 1000);
            l.sent(seq, sent);
            l.reply(seq, sent + Duration::from_millis(5));
        }
        l.advance(at(t0, 30_000), 1000);
        assert_eq!(l.window(1).integrity_percent(), Some(90));
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
