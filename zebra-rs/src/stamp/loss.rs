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
//! covers `[epoch + k·30 s, epoch + (k+1)·30 s)`. Every probe is booked
//! in **the bucket it was sent in**, received or lost — RFC 8570's
//! "percentage of the total traffic sent over a configurable interval",
//! literally. A bucket becomes **final** [`LOSS_WAIT`] after it ends,
//! when every probe sent in it has settled, and only final buckets enter
//! a window. Booking at settlement time instead put an outage's last
//! [`LOSS_WAIT`] of probes into the first bucket after it, as losses.
//!
//! The loss clock only advances time ([`LossLedger::advance`]): a
//! skipped tick, or a stall of the whole runtime, becomes buckets with
//! no probes, never one bucket stretched over several periods. So a
//! window of N buckets always spans exactly N × 30 s, and a measurement
//! gap shows up as an integrity dip rather than as old losses kept past
//! their window.
//!
//! Loss runs on this clock alone, independent of the delay export
//! period. Each bucket also records how many probes the probe rate then
//! in force should have produced, which keeps the integrity check exact
//! across a probe-interval retune.
//!
//! **Direction** (design D3) *classifies* settled losses; it never
//! counts them. A lost probe starts unresolved; a gap of lost probes,
//! once closed, moves its members to *forward* or *reverse*, so
//! `forward + reverse + unresolved = lost` always holds. Gaps are formed
//! as probes retire, which is in Session-Sender sequence order and only
//! once settled — so a reply that is merely reordered never forms one.
//! Against a stateful reflector (its own sequence counter in every
//! reply) `d = R_B − R_A − 1` of a gap's `g` members reached it: `d`
//! reverse, `g − d` forward. Anything outside `0 ≤ d ≤ g` — a counter
//! restart, reordering across the gap — stays unresolved. Against a
//! stateless reflector `R = S`, so `d = g` and every loss reads reverse:
//! the mode is declared per subscriber (`peer-reflector`), not
//! detected, and a subscriber that declares nothing advertises
//! round-trip loss and ignores the split.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use super::anomaly::Anomaly;

/// RFC 7680's waiting time: a probe with no reply received within this
/// long is lost, and a reply received later is *late* — still lost. It
/// must exceed any real one-link round trip by a wide margin and be much
/// shorter than a bucket; 3 s is both at every supported interval.
pub const LOSS_WAIT: Duration = Duration::from_secs(3);

/// The loss clock's bucket length: RFC 8570 §7's default measurement
/// interval.
pub const BUCKET: Duration = Duration::from_secs(30);

/// How much earlier than a full loss interval a periodic
/// re-advertisement may go out (design D6). The cadence is judged by the
/// real clock, and two loss ticks run 30 s apart on the grid but not
/// exactly 30 s apart in real time: each runs when the event loop gets
/// to it. Without this allowance, a tick run a few milliseconds sooner
/// after its predecessor than the one before would push roughly every
/// other periodic update out by a whole tick. It is far above timer
/// jitter and far below a bucket.
pub const CADENCE_SLACK: Duration = Duration::from_secs(1);

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

/// The fewest settled probes a bucket needs before "none received"
/// means silence rather than loss. At a slow probe rate a bucket holds
/// only a few probes, and all of them being lost is ordinary loss: at a
/// 10 s interval, 3 probes all lost happens 12.5 % of the time under
/// 50 % loss. At the default 1 s rate, silence is 30 consecutive losses.
pub const SILENT_MIN_SETTLED: u32 = 10;

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
    /// The lost probes classified as lost on the way to the reflector,
    /// and on the way back (design D3). The rest are unresolved:
    /// `forward + reverse <= lost` always.
    pub forward: u32,
    pub reverse: u32,
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
    /// The reflector's sequence number from the reply, once received —
    /// a gap anchor (design D3).
    reflector_seq: u32,
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

/// The open gap, as probes retire in sequence order (design D3). O(1)
/// per gap: an anchor, a count and a per-bucket tally, not a record per
/// probe.
#[derive(Debug, Default)]
struct Gaps {
    /// The last received probe retired: `(sender seq, reflector seq)`,
    /// the lower anchor of the next gap.
    anchor: Option<(u32, u32)>,
    /// The sender sequence number the next retiring probe should carry.
    next: Option<u32>,
    /// Lost probes retired since the anchor: the open gap.
    members: u32,
    /// The buckets they were sent in, as `(bucket index, members)`,
    /// oldest first — only buckets still in the ring. Members from
    /// buckets that have rolled out are only counted, in `expired`: a
    /// silent peer with its adjacency up keeps a gap open indefinitely,
    /// and its history must stay as bounded as the ring.
    tally: VecDeque<(u64, u32)>,
    expired: u32,
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
    /// Buckets by index, starting at `first`, up to the one containing
    /// the latest time seen.
    buckets: VecDeque<Bucket>,
    first: u64,
    /// Buckets with an index below this are **final**: they ended at
    /// least [`LOSS_WAIT`] ago, so every probe sent in them has settled.
    /// Only final buckets enter a window.
    final_index: u64,
    /// Expected probes have been accrued up to this instant.
    mark: Instant,
    gaps: Gaps,
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
            final_index: 0,
            mark: now,
            gaps: Gaps::default(),
            late: 0,
            duplicate: 0,
            unmatched: 0,
        }
    }

    fn index(&self, at: Instant) -> u64 {
        (at.saturating_duration_since(self.epoch).as_nanos() / BUCKET.as_nanos()) as u64
    }

    /// How many buckets are final. Advances by one per 30 s.
    #[cfg(test)]
    pub fn final_index(&self) -> u64 {
        self.final_index
    }

    /// When the latest final bucket became final: LOSS_WAIT after it
    /// ended — the loss tick's place on the 30 s grid.
    #[cfg(test)]
    pub fn final_at(&self) -> Instant {
        self.epoch + Duration::from_secs(BUCKET.as_secs() * self.final_index) + LOSS_WAIT
    }

    fn open_index(&self) -> u64 {
        self.first + self.buckets.len() as u64 - 1
    }

    fn bucket_end(&self, index: u64) -> Instant {
        self.epoch + Duration::from_secs(BUCKET.as_secs() * (index + 1))
    }

    /// Keep buckets up to `index`. Buckets no probe was sent in stay
    /// empty — that is what a gap is. Beyond the [`MAX_BUCKETS`] final
    /// ones, at most two are not yet final: the open bucket, and the one
    /// that ended less than [`LOSS_WAIT`] ago.
    fn open_to(&mut self, index: u64) {
        while self.open_index() < index {
            self.buckets.push_back(Bucket::default());
            if self.buckets.len() > MAX_BUCKETS + 2 {
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

    /// A probe booked lost turned out to be received in time: it stays
    /// settled in the bucket it was sent in, and is no longer lost.
    ///
    /// If it had already retired into a gap, that gap may have counted
    /// it. Its reply came back, so it reached the reflector, which is
    /// what a gap's reverse share counts: the bucket's reverse count
    /// gives way first, to keep `forward + reverse <= lost`. The race —
    /// a reply read in time but processed after the sweep that settled
    /// its probe — costs at most that one probe's attribution.
    fn unlose(&mut self, sent_at: Instant) {
        if let Some(b) = self.bucket_at(sent_at) {
            b.lost = b.lost.saturating_sub(1);
            while b.forward + b.reverse > b.lost {
                if b.reverse > 0 {
                    b.reverse -= 1;
                } else {
                    b.forward -= 1;
                }
            }
        }
    }

    /// A settled probe leaves the pending queue, in sequence order: grow
    /// the open gap, or — a received probe — close it (design D3).
    fn retire(&mut self, p: &Probe) {
        if self.gaps.next.is_some_and(|next| next != p.seq) {
            // Not the next sequence number: the stream broke, and nothing
            // before this probe can anchor a gap after it.
            self.gaps = Gaps::default();
        }
        self.gaps.next = Some(p.seq.wrapping_add(1));
        match p.fate {
            Fate::Lost => {
                let index = self.index(p.sent_at);
                self.gaps.members = self.gaps.members.saturating_add(1);
                match self.gaps.tally.back_mut() {
                    Some((i, n)) if *i == index => *n += 1,
                    _ => self.gaps.tally.push_back((index, 1)),
                }
                self.prune_gap();
            }
            Fate::Received => {
                let members = std::mem::take(&mut self.gaps.members);
                let expired = std::mem::take(&mut self.gaps.expired);
                let tally = std::mem::take(&mut self.gaps.tally);
                if members > 0
                    && let Some((_, anchor)) = self.gaps.anchor
                {
                    // Serial arithmetic: a counter that restarted or moved
                    // backwards wraps far above `members`.
                    let reached = p.reflector_seq.wrapping_sub(anchor).wrapping_sub(1);
                    if reached <= members {
                        self.classify(reached, members, expired, &tally);
                    }
                }
                self.gaps.anchor = Some((p.seq, p.reflector_seq));
            }
            Fate::Outstanding => {}
        }
    }

    /// Fold the open gap's members in buckets that have left the ring
    /// into its `expired` count: their share of a classification has
    /// nowhere to go, but the gap's size still counts.
    fn prune_gap(&mut self) {
        while let Some(&(index, count)) = self.gaps.tally.front()
            && index < self.first
        {
            self.gaps.expired = self.gaps.expired.saturating_add(count);
            self.gaps.tally.pop_front();
        }
    }

    /// A closed gap of `members` lost probes, `reverse` of which reached
    /// the reflector, spread over the buckets in `tally` after `expired`
    /// members in buckets no longer kept. The split is known only for
    /// the gap as a whole, so each bucket gets its proportional share of
    /// it, rounded so the shares add up exactly; the expired members'
    /// share is dropped with their buckets.
    fn classify(&mut self, reverse: u32, members: u32, expired: u32, tally: &VecDeque<(u64, u32)>) {
        let seen0 = u64::from(expired);
        let (mut seen, mut assigned) = (seen0, u64::from(reverse) * seen0 / u64::from(members));
        for &(index, count) in tally {
            seen += u64::from(count);
            let upto = u64::from(reverse) * seen / u64::from(members);
            let rev = (upto - assigned) as u32;
            assigned = upto;
            let Some(b) = index
                .checked_sub(self.first)
                .and_then(|offset| self.buckets.get_mut(offset as usize))
            else {
                continue;
            };
            let open = b.lost.saturating_sub(b.forward + b.reverse);
            let rev = rev.min(open);
            b.reverse += rev;
            b.forward += (count - rev).min(open - rev);
        }
    }

    /// A probe with sequence number `seq` went out.
    pub fn sent(&mut self, seq: u32, now: Instant) {
        self.pending.push_back(Probe {
            seq,
            sent_at: now,
            fate: Fate::Outstanding,
            reflector_seq: 0,
        });
    }

    /// A reply carrying Session-Sender sequence number `sender_seq`, and
    /// the reflector's own sequence number `reflector_seq`, was received
    /// at `rx_at` — the socket read, not whenever the event loop
    /// processes it.
    ///
    /// The deadline is judged here, against `rx_at`, not left to the next
    /// sweep: with a 10 s probe interval nothing sweeps for 10 s, and a
    /// reply 4 s late must not settle its probe as received. (The probe
    /// itself is booked lost, at its deadline, by the next sweep.) A
    /// reply received in time for a probe that a *later* sweep already
    /// declared lost — the reply was queued behind that sweep — still
    /// counts, and the probe moves from lost to received.
    pub fn reply(&mut self, sender_seq: u32, reflector_seq: u32, rx_at: Instant) -> ReplyFate {
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
                self.book(probe.sent_at, false);
                ReplyFate::Received
            }
            (Fate::Lost, true) => {
                self.unlose(probe.sent_at);
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
        slot.reflector_seq = reflector_seq;
        fate
    }

    /// Settle every probe whose deadline has passed at `now` as lost —
    /// booked in the bucket it was sent in — then retire settled probes
    /// from the front of the queue.
    pub fn sweep(&mut self, now: Instant) {
        let overdue: Vec<Instant> = self
            .pending
            .iter_mut()
            .filter(|p| p.fate == Fate::Outstanding && now >= p.deadline())
            .map(|p| {
                p.fate = Fate::Lost;
                p.sent_at
            })
            .collect();
        for sent_at in overdue {
            self.book(sent_at, true);
        }
        // Retire in send order only: a received probe behind an
        // outstanding one waits, so the queue stays in sequence order.
        while self
            .pending
            .front()
            .is_some_and(|p| p.fate != Fate::Outstanding)
        {
            let p = self.pending.pop_front().expect("front checked");
            self.retire(&p);
            self.recent.push_back(p);
            if self.recent.len() > RECENT {
                self.recent.pop_front();
            }
        }
    }

    /// Bring the ledger up to `now`: settle what is overdue, credit each
    /// bucket with the probes `interval_ms` should have produced during
    /// its share of the time since the last call, and make final every
    /// bucket that ended at least [`LOSS_WAIT`] ago — by then every probe
    /// sent in it has settled. Called by the loss clock, and — with the
    /// *old* interval — just before a probe-interval retune.
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
        self.prune_gap();
        let final_index = now
            .checked_sub(LOSS_WAIT)
            .map_or(0, |t| if t < self.epoch { 0 } else { self.index(t) });
        self.final_index = self.final_index.max(final_index);
    }

    /// Where expected probes have been accrued up to — for tests that
    /// check a retune accrued before the interval changed.
    #[cfg(test)]
    pub(super) fn mark(&self) -> Instant {
        self.mark
    }

    /// The last `buckets` final buckets, summed. Fewer are summed while
    /// the session is younger than that; [`LossWindow::is_full`] says
    /// which. A bucket that is not yet final is never included.
    ///
    /// A **silent** bucket — at least [`SILENT_MIN_SETTLED`] probes
    /// settled, not one reply received — is a measurement gap, not loss
    /// (design D8): its probes count as
    /// neither settled nor lost, but still as expected, so a gap lowers
    /// the window's integrity instead of inflating its loss. Otherwise a
    /// window straddling a reflector outage would read as heavy loss
    /// both while the outage begins and for a whole window after it
    /// ends.
    pub fn window(&self, buckets: usize) -> LossWindow {
        let wanted = buckets.clamp(1, MAX_BUCKETS);
        let mut w = LossWindow {
            buckets: 0,
            wanted,
            settled: 0,
            lost: 0,
            forward: 0,
            reverse: 0,
            expected_milli: 0,
            silent: 0,
        };
        let finals = self.final_index.saturating_sub(self.first) as usize;
        for b in self.buckets.iter().take(finals).rev().take(wanted) {
            w.buckets += 1;
            w.expected_milli += b.expected_milli;
            if b.settled >= SILENT_MIN_SETTLED && b.lost >= b.settled {
                w.silent += 1;
                continue;
            }
            w.settled += u64::from(b.settled);
            w.lost += u64::from(b.lost);
            w.forward += u64::from(b.forward);
            w.reverse += u64::from(b.reverse);
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
    /// Of `lost`, those classified forward and reverse (design D3); the
    /// rest are [unresolved](Self::unresolved).
    pub forward: u64,
    pub reverse: u64,
    pub expected_milli: u64,
    /// Buckets in which probes settled but none was received: gaps,
    /// left out of `settled` and `lost` (see [`LossLedger::window`]).
    pub silent: usize,
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
    /// have produced, capped at 100 (timer jitter at a retune can put
    /// one probe more in a bucket than its span strictly allows).
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

    /// Lost probes no gap has classified yet.
    pub fn unresolved(&self) -> u64 {
        self.lost.saturating_sub(self.forward + self.reverse)
    }

    /// The window as a `peer-reflector stateful` subscriber sees it:
    /// forward loss, with unresolved losses counted as forward — the
    /// upper bound, as round-trip loss is for a stateless peer. An open
    /// burst reads high until its gap closes, never low.
    pub fn as_forward(&self) -> LossWindow {
        LossWindow {
            lost: self.lost - self.reverse,
            reverse: 0,
            ..*self
        }
    }

    /// The measured loss in micro-percent (10⁻⁶ %), rounded down, and
    /// neither capped nor in RFC units: what the Anomalous bit is judged
    /// on (design D7). Rounding down loses nothing against a whole
    /// micro-percent bound — `floor(x) >= b` exactly when `x >= b`.
    pub fn micro_percent(&self) -> Option<u32> {
        (self.settled > 0)
            .then(|| (u128::from(self.lost) * 100_000_000 / u128::from(self.settled)) as u32)
    }
}

/// A loss value as one subscriber advertises it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct LossAdvert {
    /// RFC 8570 §4.4 units, 0.000003 % each.
    pub value: u32,
    /// The Anomalous bit (design D7), evaluated on the measurement
    /// `value` encodes — exactly, and above the cap `value` saturates
    /// at. A statically configured loss always originates it clear.
    pub anomalous: bool,
}

/// What a subscriber should do with its loss advertisement at a tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LossDecision {
    /// Leave the advertisement as it is.
    Keep,
    /// Advertise this value.
    Set(LossAdvert),
    /// Stop advertising measured loss.
    Withdraw,
}

/// `w`'s value if it can be trusted, as `(encoded, micro-percent)`: the
/// RFC 8570 value the sub-TLV carries, capped at 50.331642 %, and the
/// exact measurement the A bit is judged on ([`LossWindow::micro_percent`]).
/// `None` when the window is:
/// - not yet full — a value from a handful of probes is noise (D5);
/// - below the integrity threshold — the probe stream had a gap, or
///   silent buckets were left out of it (D5, D8);
/// - nothing received at all.
///
/// A `peer-reflector stateful` subscriber sees the window's forward
/// view ([`LossWindow::as_forward`]); "nothing received" is still judged
/// round-trip.
fn trusted(w: &LossWindow, policy: &super::session::LossPolicy) -> Option<(u32, u32)> {
    if !w.is_full() || w.integrity_percent()? < policy.integrity_pct || w.lost >= w.settled {
        return None;
    }
    let w = if policy.peer_reflector_stateful {
        w.as_forward()
    } else {
        *w
    };
    Some((w.encoded()?, w.micro_percent()?))
}

/// Decide one subscriber's loss advertisement — design D5 (gates), D6
/// (filter and cadence), D7 (Anomalous bit) and D8 (silence).
/// `advertised` is what it currently advertises, `advertised_at` when
/// that was decided, and `now` when this decision is made — both by the
/// real clock, whether on a loss tick or when a subscription is seeded
/// between ticks. `anomaly` is the subscriber's A-bit hysteresis.
///
/// - Disabled, or no trustworthy window: withdraw anything advertised,
///   and forget the A-bit state — a value that comes back earns its
///   anomaly again, as delay's does after an empty window.
/// - The candidate is the rolling window's value, or — when
///   acceleration fires — the latest bucket's. The A bit is evaluated
///   on that candidate, the value it would travel with (D7), and clears
///   only after a whole loss interval below the reuse bound. It is
///   judged on the candidate's exact measurement in micro-percent
///   against bounds kept as configured: the encoded value is capped at
///   50.331642 % and quantised to 0.000003 %, and would miss a bound
///   above the cap, or read a finer one as zero.
/// - Nothing advertised yet: advertise at once. The RFC 8570 §6 cadence
///   limits *re*-advertisement.
/// - Accelerated (opt-in): the latest bucket alone differs from the
///   advertised value by at least the configured step — advertise that
///   bucket's value now.
/// - A flag change advertises its candidate with it, past the cadence
///   and the value filter, so every advertised `(value, A)` pair is one
///   the hysteresis produced from that value.
/// - Periodic: at most once per loss interval, and only for a change of
///   at least `max(threshold % × advertised, minimum-change)`. The
///   minimum change governs the zero crossings, where a relative
///   threshold means nothing. The interval is real time elapsed since
///   the advertisement, less [`CADENCE_SLACK`] for tick jitter. It is
///   not a count of buckets finalised since, nor the time a bucket
///   became final: a value seeded between ticks, or advertised by a
///   tick the event loop ran late, can be followed by the next tick a
///   second later.
pub fn evaluate(
    policy: &super::session::LossPolicy,
    ledger: &LossLedger,
    advertised: Option<LossAdvert>,
    advertised_at: Option<Instant>,
    anomaly: &mut Anomaly,
    now: Instant,
) -> LossDecision {
    let mut withdraw = || {
        anomaly.reset();
        if advertised.is_some() {
            LossDecision::Withdraw
        } else {
            LossDecision::Keep
        }
    };
    if !policy.enabled {
        return withdraw();
    }
    // D8, judged on the latest bucket: 30 s in which probes went out
    // and not one reply came back means the measurement has gone silent
    // *now* — a reflector down, an ACL, a policer. Withdraw at once,
    // whatever older buckets or a lenient integrity setting would allow:
    // the bucket the outage began in still holds replies from before
    // it, and a value built from it reads as near-total loss.
    if ledger.window(1).silent > 0 {
        return withdraw();
    }
    let Some(rolling) = trusted(&ledger.window(policy.window_buckets), policy) else {
        return withdraw();
    };
    let accelerated = advertised.and_then(|current| {
        let step = policy.accelerated?;
        let latest = trusted(&ledger.window(1), policy)?;
        (latest.0 != current.value && latest.0.abs_diff(current.value) >= step).then_some(latest)
    });
    let (value, measured) = accelerated.unwrap_or(rolling);
    let interval = policy.interval();
    let anomalous = anomaly.evaluate_bounds(
        measured,
        policy.anomaly_bounds(),
        Some((now, interval.saturating_sub(CADENCE_SLACK))),
    );
    let set = LossDecision::Set(LossAdvert { value, anomalous });
    let Some(current) = advertised else {
        return set;
    };
    if accelerated.is_some() || anomalous != current.anomalous {
        return set;
    }
    let due = advertised_at
        .is_none_or(|at| now.saturating_duration_since(at) + CADENCE_SLACK >= interval);
    let need = (u64::from(current.value) * u64::from(policy.threshold_pct) / 100)
        .max(u64::from(policy.minimum_change));
    if due && value != current.value && u64::from(value.abs_diff(current.value)) >= need {
        set
    } else {
        LossDecision::Keep
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
    /// ends, whose reply arrives just after, counts as received exactly
    /// once — in the bucket it was sent in, which is not final (and so
    /// not in any window) until its probes have had their wait.
    #[test]
    fn a_reply_across_a_bucket_boundary_counts_once_as_received() {
        let t0 = Instant::now();
        let mut l = LossLedger::new(t0);
        l.sent(7, at(t0, 29_990));
        l.advance(at(t0, 30_000), 1000);
        assert_eq!(l.window(1).buckets, 0, "not final until 33 s");
        assert_eq!(l.reply(7, 7, at(t0, 30_005)), ReplyFate::Received);
        l.advance(at(t0, 63_000), 1000);
        let w = l.window(2);
        assert_eq!((w.buckets, w.settled, w.lost), (2, 1, 0));
        assert_eq!(l.window(1).settled, 0, "nothing was sent in the second");
    }

    #[test]
    fn a_probe_with_no_reply_settles_lost_at_its_deadline() {
        let t0 = Instant::now();
        let mut l = LossLedger::new(t0);
        l.sent(1, at(t0, 1_000));
        l.sweep(at(t0, 3_999));
        l.advance(at(t0, 33_000), 1000);
        // Swept only at the tick, but booked in the bucket it was sent
        // in, the first.
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
        assert_eq!(l.reply(1, 1, at(t0, 4_000)), ReplyFate::Late);
        l.sent(2, at(t0, 10_000));
        assert_eq!(
            l.reply(2, 2, at(t0, 13_000)),
            ReplyFate::Late,
            "at the deadline"
        );
        l.sent(3, at(t0, 20_000));
        assert_eq!(
            l.reply(3, 3, at(t0, 22_999)),
            ReplyFate::Received,
            "just before it"
        );
        l.advance(at(t0, 33_000), 1000);
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
        assert_eq!(l.reply(1, 1, at(t0, 1_000)), ReplyFate::Received);
        l.advance(at(t0, 33_000), 1000);
        let w = l.window(1);
        assert_eq!((w.settled, w.lost, l.late), (1, 0, 0));
    }

    #[test]
    fn duplicate_and_unmatched_replies_are_not_counted() {
        let t0 = Instant::now();
        let mut l = LossLedger::new(t0);
        l.sent(5, t0);
        assert_eq!(l.reply(5, 5, at(t0, 10)), ReplyFate::Received);
        assert_eq!(l.reply(5, 5, at(t0, 20)), ReplyFate::Duplicate);
        assert_eq!(l.reply(99, 99, at(t0, 30)), ReplyFate::Unmatched);
        l.advance(at(t0, 33_000), 1000);
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
        assert_eq!(l.reply(10, 10, at(t0, 10)), ReplyFate::Received);
        assert_eq!(l.reply(12, 12, at(t0, 20)), ReplyFate::Received);
        assert_eq!(l.reply(11, 11, at(t0, 1_000)), ReplyFate::Received);
        l.advance(at(t0, 33_000), 1000);
        let w = l.window(1);
        assert_eq!((w.settled, w.lost), (3, 0));
    }

    #[test]
    fn sequence_numbers_match_across_wrap() {
        let t0 = Instant::now();
        let mut l = LossLedger::new(t0);
        l.sent(u32::MAX, t0);
        l.sent(0, t0);
        assert_eq!(l.reply(0, 0, at(t0, 5)), ReplyFate::Received);
        assert_eq!(l.reply(u32::MAX, u32::MAX, at(t0, 6)), ReplyFate::Received);
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
                    l.reply(seq, seq, at(t0, base + i + 5));
                }
                seq += 1;
            }
            l.advance(at(t0, base + 33_000), 1000);
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
    /// bucket over several periods. One tick at 240 s finalizes seven
    /// buckets (the eighth ended under 3 s ago), not one, so the 120 s
    /// window really covers 90–210 s: the loss sent at 27.5 s is outside
    /// it, and the empty stretch reads as zero integrity rather than as
    /// a clean link.
    #[test]
    fn a_stall_that_skips_ticks_leaves_empty_buckets_not_a_stretched_one() {
        let t0 = Instant::now();
        let mut l = LossLedger::new(t0);
        l.sent(1, at(t0, 27_500)); // sent in bucket 0
        l.advance(at(t0, 240_000), 1000);
        let w = l.window(4);
        assert_eq!((w.buckets, w.secs()), (4, 120));
        assert_eq!((w.settled, w.lost), (0, 0), "the old loss has aged out");
        assert_eq!(w.expected_milli, 120_000, "120 s at 1 s expected");
        assert_eq!(w.integrity_percent(), Some(0));
        // The loss is still where it happened.
        let all = l.window(8);
        assert_eq!((all.buckets, all.settled, all.lost), (7, 1, 1));
    }

    #[test]
    fn the_ring_keeps_at_most_max_buckets() {
        let t0 = Instant::now();
        let mut l = LossLedger::new(t0);
        l.advance(at(t0, (MAX_BUCKETS as u64 + 5) * 30_000), 1000);
        assert_eq!(l.window(MAX_BUCKETS).buckets, MAX_BUCKETS);
        assert_eq!(
            l.buckets.len(),
            MAX_BUCKETS + 2,
            "final, plus two not yet final"
        );
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
        l.advance(at(t0, 33_000), 1000); // bucket 0 final
        assert_eq!(l.window(1).expected_milli, 210_000);
        l.advance(at(t0, 75_000), 1000); // bucket 1 final, 15 s into 2
        assert_eq!(l.window(1).expected_milli, 30_000);
        l.advance(at(t0, 93_000), 1000); // bucket 2 final
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
            l.reply(seq, seq, sent + Duration::from_millis(5));
        }
        l.advance(at(t0, 33_000), 1000);
        assert_eq!(l.window(1).integrity_percent(), Some(90));
        assert_eq!(LossLedger::new(t0).window(1).integrity_percent(), None);
    }

    use crate::stamp::session::{LossPolicy, micro_pct_to_units};

    /// A ledger whose buckets each saw `probes` probes at 1 s, the first
    /// `lost` of them unanswered — closed up to the end of the last one.
    fn ledger(buckets: &[(u32, u32)]) -> LossLedger {
        let t0 = Instant::now();
        let mut l = LossLedger::new(t0);
        let mut seq = 0;
        for (b, &(probes, lost)) in buckets.iter().enumerate() {
            let base = b as u64 * 30_000;
            for i in 0..probes {
                let sent = at(t0, base + u64::from(i) * 1000);
                l.sent(seq, sent);
                if i >= lost {
                    l.reply(seq, seq, sent + Duration::from_millis(5));
                }
                seq += 1;
            }
            l.advance(at(t0, base + 33_000), 1000);
        }
        l
    }

    fn advert(value: u32) -> Option<LossAdvert> {
        Some(LossAdvert {
            value,
            anomalous: false,
        })
    }

    fn set(value: u32) -> LossDecision {
        LossDecision::Set(LossAdvert {
            value,
            anomalous: false,
        })
    }

    /// `evaluate` at the loss tick that finalised `l`'s latest bucket,
    /// the value having been advertised `ago` buckets' time before it.
    fn eval(
        p: &LossPolicy,
        l: &LossLedger,
        advertised: Option<LossAdvert>,
        ago: Option<u32>,
    ) -> LossDecision {
        let now = l.final_at();
        evaluate(
            p,
            l,
            advertised,
            ago.map(|n| now - BUCKET * n),
            &mut Anomaly::default(),
            now,
        )
    }

    const CLEAN: (u32, u32) = (30, 0);
    const TEN_PCT: (u32, u32) = (30, 3);

    #[test]
    fn nothing_is_advertised_until_the_window_is_full() {
        let p = LossPolicy::default();
        let l = ledger(&[CLEAN, CLEAN, CLEAN]);
        assert_eq!(eval(&p, &l, None, None), LossDecision::Keep);
        assert_eq!(eval(&p, &l, advert(0), Some(3)), LossDecision::Withdraw);
    }

    /// Nothing advertised yet: the first trustworthy value goes out at
    /// once — the cadence limits *re*-advertisement.
    #[test]
    fn a_full_trusted_window_is_advertised_at_once() {
        let p = LossPolicy::default();
        let l = ledger(&[TEN_PCT; 4]);
        assert_eq!(eval(&p, &l, None, None), set(encode_loss(12, 120)));
    }

    #[test]
    fn a_window_below_the_integrity_threshold_is_not_trusted() {
        let p = LossPolicy::default(); // 90 %
        let l = ledger(&[(26, 0); 4]); // 86 %
        assert_eq!(eval(&p, &l, None, None), LossDecision::Keep);
        assert_eq!(eval(&p, &l, advert(0), Some(4)), LossDecision::Withdraw);
        let lenient = LossPolicy {
            integrity_pct: 80,
            ..p
        };
        assert_eq!(eval(&lenient, &l, None, None), set(0));
    }

    /// Design D8: every probe vanished is a measurement problem, not
    /// 100 % loss on a link whose adjacency is up. Withdraw; never
    /// advertise the 50.33 % cap.
    #[test]
    fn total_silence_withdraws_rather_than_advertising_the_cap() {
        let p = LossPolicy::default();
        let l = ledger(&[(30, 30); 4]);
        assert_eq!(eval(&p, &l, None, None), LossDecision::Keep);
        assert_eq!(
            eval(&p, &l, advert(encode_loss(1, 120)), Some(4)),
            LossDecision::Withdraw
        );
        // Silent buckets are gaps, not loss: one reply in the latest
        // bucket does not make three silent ones count as 100 % loss.
        // They lower integrity to 25 %, so nothing is advertised.
        let l = ledger(&[(30, 30), (30, 30), (30, 30), (30, 29)]);
        assert_eq!(l.window(4).silent, 3);
        assert_eq!(eval(&p, &l, None, None), LossDecision::Keep);
    }

    /// Review of PR 2's BDD run: a reflector outage must be withdrawn as
    /// soon as one whole bucket is silent — not once the whole window
    /// is. The bucket the outage began in still holds replies, and a
    /// value built from it reads as near-total loss. Holds even under a
    /// lenient integrity setting.
    #[test]
    fn a_silent_latest_bucket_withdraws_at_once() {
        let lenient = LossPolicy {
            integrity_pct: 50,
            ..LossPolicy::default()
        };
        let l = ledger(&[CLEAN, CLEAN, CLEAN, (30, 30)]);
        assert_eq!(l.window(4).integrity_percent(), Some(75));
        assert_eq!(
            eval(&lenient, &l, advert(0), Some(4)),
            LossDecision::Withdraw
        );
        assert_eq!(eval(&lenient, &l, None, None), LossDecision::Keep);
    }

    /// The other side of the outage: once replies return, the silent
    /// buckets still in the window must not be read as loss. They are
    /// gaps, so the window is untrusted until it refills. And because a
    /// probe is booked in the bucket it was sent in, none of the
    /// outage's probes spill into the first recovery bucket: with a
    /// lenient integrity setting it reads a clean 0 %. (Booked at their
    /// deadline, the outage's last 3 s of probes landed there as 3 of 33
    /// lost.)
    #[test]
    fn recovery_does_not_advertise_the_outage() {
        let l = ledger(&[(30, 30), (30, 30), (30, 30), CLEAN]);
        let w = l.window(4);
        assert_eq!((w.settled, w.lost, w.silent), (30, 0, 3));
        assert_eq!(
            eval(&LossPolicy::default(), &l, None, None),
            LossDecision::Keep
        );
        let lenient = LossPolicy {
            integrity_pct: 20,
            ..LossPolicy::default()
        };
        assert_eq!(eval(&lenient, &l, None, None), set(0));
    }

    /// A thin bucket is never called silent: at a slow probe rate, every
    /// probe being lost is ordinary loss, and counts as such.
    #[test]
    fn a_bucket_below_the_silence_floor_counts_as_loss() {
        let l = ledger(&[(3, 3)]);
        let w = l.window(1);
        assert_eq!((w.settled, w.lost, w.silent), (3, 3, 0));
        let l = ledger(&[(10, 10)]);
        assert_eq!(l.window(1).silent, 1, "at the floor it is silence");
    }

    #[test]
    fn a_disabled_policy_withdraws() {
        let p = LossPolicy {
            enabled: false,
            ..LossPolicy::default()
        };
        let l = ledger(&[CLEAN; 4]);
        assert_eq!(eval(&p, &l, None, None), LossDecision::Keep);
        assert_eq!(eval(&p, &l, advert(0), Some(0)), LossDecision::Withdraw);
    }

    /// RFC 8570 §6: a change is re-advertised at most once per loss
    /// interval, 120 s by default. Two ticks after the advertisement it
    /// waits; four ticks is the interval.
    #[test]
    fn a_change_waits_for_the_interval() {
        let p = LossPolicy::default();
        let l = ledger(&[
            CLEAN, CLEAN, CLEAN, CLEAN, TEN_PCT, TEN_PCT, TEN_PCT, TEN_PCT,
        ]);
        assert_eq!(l.final_index(), 8);
        assert_eq!(eval(&p, &l, advert(0), Some(2)), LossDecision::Keep);
        assert_eq!(eval(&p, &l, advert(0), Some(4)), set(encode_loss(12, 120)));
    }

    /// The cadence is real time, and ticks do not run exactly 30 s
    /// apart: a tick run 5 ms sooner after the advertising one than the
    /// grid spacing still counts as an interval later. Anything sooner
    /// than the slack allows does not.
    #[test]
    fn the_cadence_absorbs_tick_jitter_and_nothing_more() {
        let p = LossPolicy::default();
        let l = ledger(&[
            CLEAN, CLEAN, CLEAN, CLEAN, TEN_PCT, TEN_PCT, TEN_PCT, TEN_PCT,
        ]);
        let now = l.final_at();
        let ago = |d: Duration| Some(now - d);
        let interval = Duration::from_secs(120);
        let jittered = interval - Duration::from_millis(5);
        assert_eq!(
            evaluate(
                &p,
                &l,
                advert(0),
                ago(jittered),
                &mut Anomaly::default(),
                now
            ),
            set(encode_loss(12, 120))
        );
        assert_eq!(
            evaluate(
                &p,
                &l,
                advert(0),
                ago(interval - CADENCE_SLACK),
                &mut Anomaly::default(),
                now
            ),
            set(encode_loss(12, 120))
        );
        let too_soon = interval - CADENCE_SLACK - Duration::from_millis(1);
        assert_eq!(
            evaluate(
                &p,
                &l,
                advert(0),
                ago(too_soon),
                &mut Anomaly::default(),
                now
            ),
            LossDecision::Keep
        );
    }

    /// Review of PR 2: the cadence is time since the advertisement, not
    /// buckets finalised since. A value advertised at 152 s — by a
    /// subscriber joining between ticks, or by the 123 s tick run late —
    /// is the bucket final then, 10 %. The tick at 153 s finalises a
    /// 20 % bucket one second later; counting buckets, or timing the
    /// first advertisement at 123 s when its bucket became final, that
    /// one was "an interval later" and went out at once. It waits until
    /// 183 s.
    #[test]
    fn a_value_seeded_between_ticks_waits_a_full_interval() {
        let p = LossPolicy {
            window_buckets: 1,
            ..LossPolicy::default()
        };
        let t0 = Instant::now();
        let mut l = LossLedger::new(t0);
        let mut seq = 0;
        for (b, lost) in [3, 3, 3, 3, 6, 6].into_iter().enumerate() {
            for i in 0..30 {
                let sent = at(t0, b as u64 * 30_000 + i * 1000);
                l.sent(seq, sent);
                if i >= lost {
                    l.reply(seq, seq, sent + Duration::from_millis(5));
                }
                seq += 1;
            }
        }
        let (ten, twenty) = (encode_loss(3, 30), encode_loss(6, 30));

        let joined = at(t0, 152_000);
        l.advance(joined, 1000);
        assert_eq!(l.final_index(), 4);
        assert_eq!(
            evaluate(&p, &l, None, None, &mut Anomaly::default(), joined),
            set(ten)
        );

        l.advance(at(t0, 153_000), 1000);
        assert_eq!(l.final_at(), at(t0, 153_000));
        assert_eq!(l.window(1).encoded(), Some(twenty));
        assert_eq!(
            evaluate(
                &p,
                &l,
                advert(ten),
                Some(joined),
                &mut Anomaly::default(),
                l.final_at()
            ),
            LossDecision::Keep,
            "one second after the last advertisement"
        );

        l.advance(at(t0, 183_000), 1000);
        assert_eq!(
            evaluate(
                &p,
                &l,
                advert(ten),
                Some(joined),
                &mut Anomaly::default(),
                l.final_at()
            ),
            set(twenty)
        );
    }

    /// The filter: a change must be at least `max(threshold % of the
    /// advertised value, minimum-change)`. From 10 %, that is 1.0 point.
    #[test]
    fn small_changes_are_suppressed_and_large_ones_advertised() {
        let p = LossPolicy::default();
        let ten = encode_loss(12, 120);
        // 13 of 120 = 10.83 %: 0.83 points, under the minimum change.
        let l = ledger(&[(30, 4), TEN_PCT, TEN_PCT, TEN_PCT]);
        assert_eq!(eval(&p, &l, advert(ten), Some(4)), LossDecision::Keep);
        // 15 of 120 = 12.5 %: 2.5 points.
        let l = ledger(&[(30, 6), TEN_PCT, TEN_PCT, TEN_PCT]);
        assert_eq!(
            eval(&p, &l, advert(ten), Some(4)),
            set(encode_loss(15, 120))
        );
    }

    /// From zero a relative threshold means nothing: the minimum change
    /// (1.0 point by default) decides. One stray probe in 120 is 0.83 %
    /// and stays suppressed; two is 1.67 % and goes out.
    #[test]
    fn the_minimum_change_governs_the_zero_crossings() {
        let p = LossPolicy::default();
        let one = ledger(&[(30, 1), CLEAN, CLEAN, CLEAN]);
        assert_eq!(eval(&p, &one, advert(0), Some(4)), LossDecision::Keep);
        let two = ledger(&[(30, 2), CLEAN, CLEAN, CLEAN]);
        assert_eq!(eval(&p, &two, advert(0), Some(4)), set(encode_loss(2, 120)));
        // And back to zero from 1.67 %: over the minimum change.
        let clean = ledger(&[CLEAN; 4]);
        assert_eq!(
            eval(&p, &clean, advert(encode_loss(2, 120)), Some(4)),
            set(0)
        );
    }

    /// Acceleration (opt-in): the latest bucket alone differing by the
    /// configured step advertises that bucket's value at once, before
    /// the interval is due. Without it the same window waits.
    #[test]
    fn acceleration_advertises_the_latest_bucket_early() {
        let l = ledger(&[CLEAN, CLEAN, CLEAN, CLEAN, CLEAN, CLEAN, CLEAN, TEN_PCT]);
        let plain = LossPolicy::default();
        assert_eq!(eval(&plain, &l, advert(0), Some(2)), LossDecision::Keep);
        let accel = LossPolicy {
            accelerated: Some(micro_pct_to_units(5_000_000)),
            ..plain
        };
        assert_eq!(
            eval(&accel, &l, advert(0), Some(2)),
            set(encode_loss(3, 30)),
            "the latest bucket's 10 %, not the rolling 2.5 %"
        );
        // Under the step: no early advertisement.
        let small = ledger(&[CLEAN, CLEAN, CLEAN, CLEAN, CLEAN, CLEAN, CLEAN, (30, 1)]);
        assert_eq!(eval(&accel, &small, advert(0), Some(2)), LossDecision::Keep);
    }

    /// One subscriber driven tick by tick over a ledger fed one 30 s
    /// bucket of 30 probes at a time: the state `evaluate` is given
    /// back at every tick, the way `Subscriber::apply_loss` keeps it.
    struct Sim {
        t0: Instant,
        ledger: LossLedger,
        seq: u32,
        buckets: u64,
        advertised: Option<LossAdvert>,
        advertised_at: Option<Instant>,
        anomaly: Anomaly,
    }

    impl Sim {
        fn new() -> Self {
            let t0 = Instant::now();
            Self {
                t0,
                ledger: LossLedger::new(t0),
                seq: 0,
                buckets: 0,
                advertised: None,
                advertised_at: None,
                anomaly: Anomaly::default(),
            }
        }

        /// A bucket with `lost` of its 30 probes unanswered, then the
        /// loss tick 3 s after it ends: its decision, as applied.
        fn tick(&mut self, p: &LossPolicy, lost: u32) -> LossDecision {
            self.tick_early(p, lost, 0)
        }

        /// [`Self::tick`] with the tick run `early_ms` before its place
        /// on the grid, as timer jitter can.
        fn tick_early(&mut self, p: &LossPolicy, lost: u32, early_ms: u64) -> LossDecision {
            let base = self.buckets * 30_000;
            for i in 0..30 {
                let sent = at(self.t0, base + u64::from(i) * 1000);
                self.ledger.sent(self.seq, sent);
                if i >= lost {
                    self.ledger
                        .reply(self.seq, self.seq, sent + Duration::from_millis(5));
                }
                self.seq += 1;
            }
            self.buckets += 1;
            let now = at(self.t0, base + 33_000 - early_ms);
            self.ledger.advance(now, 1000);
            self.decide(p, now)
        }

        /// A decision between ticks, as when a subscription is seeded.
        fn decide(&mut self, p: &LossPolicy, now: Instant) -> LossDecision {
            let d = evaluate(
                p,
                &self.ledger,
                self.advertised,
                self.advertised_at,
                &mut self.anomaly,
                now,
            );
            match d {
                LossDecision::Keep => {}
                LossDecision::Set(a) => {
                    self.advertised = Some(a);
                    self.advertised_at = Some(now);
                }
                LossDecision::Withdraw => {
                    self.advertised = None;
                    self.advertised_at = None;
                }
            }
            d
        }
    }

    fn set_a(value: u32, anomalous: bool) -> LossDecision {
        LossDecision::Set(LossAdvert { value, anomalous })
    }

    /// Retained PR 3 review probe: the configured range includes 60 %,
    /// so 80 % measured loss must cross that bound even though the
    /// advertised numeric field saturates at about 50.33 %.
    #[test]
    fn a_loss_bound_above_the_wire_cap_still_detects_measured_loss() {
        let p = bounded(
            LossPolicy {
                window_buckets: 1,
                ..LossPolicy::default()
            },
            60,
            40,
        );
        let mut sim = Sim::new();
        assert_eq!(sim.tick(&p, 24), set_a(MAX_ENCODED_LOSS, true));
    }

    /// Retained PR 3 review probe: a positive, valid six-decimal bound
    /// must not become a zero bound that marks a lossless link anomalous.
    #[test]
    fn a_positive_sub_unit_loss_bound_does_not_flag_a_clean_link() {
        let p = LossPolicy {
            window_buckets: 1,
            anomaly_micro_pct: Some(1), // configured 0.000001 %
            ..LossPolicy::default()
        };
        let mut sim = Sim::new();
        assert_eq!(sim.tick(&p, 0), set_a(0, false));
    }

    /// The bound is compared with the measurement exactly: 3 of 30 is
    /// 10 % on the dot, which meets a 10 % bound and misses 10.000001 %.
    /// In RFC units both bounds truncate to the unit 10 % encodes to,
    /// and the finer one would set the bit too.
    #[test]
    fn the_a_bit_compares_the_measurement_exactly() {
        let window = |micro| LossPolicy {
            window_buckets: 1,
            anomaly_micro_pct: Some(micro),
            ..LossPolicy::default()
        };
        assert_eq!(
            micro_pct_to_units(10_000_001),
            encode_loss(3, 30),
            "indistinguishable in RFC units"
        );
        let mut sim = Sim::new();
        assert_eq!(
            sim.tick(&window(10_000_000), 3),
            set_a(encode_loss(3, 30), true)
        );
        let mut sim = Sim::new();
        assert_eq!(
            sim.tick(&window(10_000_001), 3),
            set_a(encode_loss(3, 30), false)
        );
        // Rounded down, a third is 33.333333 %: floor never crosses a
        // whole micro-percent bound it should not.
        let w = LossWindow {
            buckets: 1,
            wanted: 1,
            settled: 3,
            lost: 1,
            forward: 0,
            reverse: 0,
            expected_milli: 3_000,
            silent: 0,
        };
        assert_eq!(w.micro_percent(), Some(33_333_333));
    }

    /// `anomaly` / `reuse` in percent, as configured.
    fn bounded(p: LossPolicy, anomaly: u32, reuse: u32) -> LossPolicy {
        LossPolicy {
            anomaly_micro_pct: Some(anomaly * 1_000_000),
            reuse_micro_pct: Some(reuse * 1_000_000),
            ..p
        }
    }

    /// D7 (review round 1, finding 4): the A bit is evaluated on the
    /// value it travels with. After three clean buckets, one at 10 %
    /// accelerates out as 10 % — and carries A against a 5 % bound,
    /// although the rolling value it replaced is only 2.5 %.
    #[test]
    fn an_accelerated_value_carries_its_own_a_bit() {
        let p = bounded(
            LossPolicy {
                accelerated: Some(micro_pct_to_units(5_000_000)),
                ..LossPolicy::default()
            },
            5,
            1,
        );
        let mut sim = Sim::new();
        for _ in 0..3 {
            sim.tick(&p, 0);
        }
        assert_eq!(sim.tick(&p, 0), set_a(0, false), "the first full window");
        assert_eq!(sim.tick(&p, 3), set_a(encode_loss(3, 30), true));
    }

    /// D7: a flag change advertises its candidate with it, past the
    /// cadence and the value filter. Advertised clear at 4.17 %, the
    /// rolling value rises to 5.0 % one tick later — 0.83 points, under
    /// the 1.0-point minimum change, and a whole interval early — and
    /// goes out at once, with A. Never 4.17 % with A.
    #[test]
    fn a_flag_change_advertises_its_candidate_at_once() {
        let p = bounded(LossPolicy::default(), 5, 1);
        let mut sim = Sim::new();
        for lost in [1, 1, 2, 1] {
            sim.tick(&p, lost);
        }
        assert_eq!(
            sim.advertised,
            Some(LossAdvert {
                value: encode_loss(5, 120),
                anomalous: false
            })
        );
        assert_eq!(
            sim.tick(&p, 2),
            set_a(encode_loss(6, 120), true),
            "4.17 % to 5.0 %: the bound is crossed"
        );
    }

    /// D7 (review round 1, finding 6): A clears only once the value has
    /// been below the reuse bound for a whole loss interval, and one
    /// evaluation back in the band restarts that wait. A 30 s interval
    /// keeps the rolling value to one bucket.
    #[test]
    fn a_clears_only_after_a_whole_interval_below_reuse() {
        let p = bounded(
            LossPolicy {
                window_buckets: 1,
                ..LossPolicy::default()
            },
            5,
            1,
        );
        let ten = encode_loss(3, 30);
        let mut sim = Sim::new();
        assert_eq!(sim.tick(&p, 3), set_a(ten, true));
        // Below reuse from here: the value goes out, A stays.
        assert_eq!(sim.tick(&p, 0), set_a(0, true));
        // A tick in the band (3.3 %) holds A and restarts the wait.
        assert_eq!(sim.tick(&p, 1), set_a(encode_loss(1, 30), true));
        assert_eq!(sim.tick(&p, 0), set_a(0, true), "the wait starts again");
        assert_eq!(
            sim.tick(&p, 0),
            set_a(0, false),
            "a whole 30 s interval below reuse"
        );
    }

    /// The recovery wait allows the same tick jitter as the cadence: a
    /// tick run 5 ms short of an interval after the recovery began still
    /// clears the bit, rather than holding it for another whole tick.
    #[test]
    fn the_recovery_wait_absorbs_tick_jitter() {
        let p = bounded(
            LossPolicy {
                window_buckets: 1,
                ..LossPolicy::default()
            },
            5,
            1,
        );
        let mut sim = Sim::new();
        assert_eq!(sim.tick(&p, 3), set_a(encode_loss(3, 30), true));
        assert_eq!(sim.tick(&p, 0), set_a(0, true), "the recovery begins");
        assert_eq!(sim.tick_early(&p, 0, 5), set_a(0, false));
    }

    /// With the default 120 s interval a recovery takes 120 s, whatever
    /// the rolling value did first: it falls under the reuse bound only
    /// once the lossy bucket has left the window, and the wait starts
    /// then.
    #[test]
    fn a_default_interval_recovery_waits_120_s() {
        let p = bounded(LossPolicy::default(), 5, 1);
        let mut sim = Sim::new();
        for _ in 0..3 {
            sim.tick(&p, 0);
        }
        assert_eq!(sim.tick(&p, 9), set_a(encode_loss(9, 120), true));
        let mut cleared = None;
        for t in 1..=10 {
            if let LossDecision::Set(a) = sim.tick(&p, 0)
                && !a.anomalous
            {
                cleared = Some(t);
                break;
            }
        }
        // Ticks 1–3 still hold the 30 % bucket, 7.5 % over the window;
        // from tick 4 it is clean, and 120 s later — tick 8 — A clears.
        assert_eq!(cleared, Some(8));
    }

    /// A withdrawal forgets the A-bit state: after a silent bucket the
    /// value comes back and has to earn its anomaly again. Removing the
    /// bounds clears a standing A at once — a flag change, so past the
    /// cadence.
    #[test]
    fn a_withdrawal_or_removed_bounds_clears_the_bit() {
        let p = bounded(
            LossPolicy {
                window_buckets: 1,
                integrity_pct: 1,
                ..LossPolicy::default()
            },
            5,
            1,
        );
        let mut sim = Sim::new();
        assert_eq!(sim.tick(&p, 3), set_a(encode_loss(3, 30), true));
        assert_eq!(sim.tick(&p, 30), LossDecision::Withdraw, "silent");
        // 3.3 % is in the band: held only by a standing bit, and there
        // is none any more.
        assert_eq!(sim.tick(&p, 1), set_a(encode_loss(1, 30), false));

        assert_eq!(sim.tick(&p, 3), set_a(encode_loss(3, 30), true));
        let unbounded = LossPolicy {
            anomaly_micro_pct: None,
            reuse_micro_pct: None,
            ..p
        };
        let now = at(sim.t0, sim.buckets * 30_000 + 5_000);
        assert_eq!(
            sim.decide(&unbounded, now),
            set_a(encode_loss(3, 30), false),
            "seconds after the last advertisement"
        );
    }

    /// What happens to one probe on a link to a stateful reflector.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Path {
        /// Reflected, and the reply is back in 5 ms.
        Ok,
        /// Lost on the way to the reflector: it never counts it.
        Fwd,
        /// Reflected — counted — and the reply lost.
        Rev,
        /// Reflected, and the reply back after the waiting time.
        Late,
    }

    /// A session against a stateful reflector: probes at 1 s from `t0`,
    /// sender sequence numbers from `s`, the reflector's counter from
    /// `r`. Each probe's reply, if any, is processed as it arrives, and
    /// the ledger is swept at every send, as the probe tick does.
    struct Link {
        t0: Instant,
        ledger: LossLedger,
        s: u32,
        r: u32,
        sent: u64,
    }

    impl Link {
        fn new(s: u32, r: u32) -> Self {
            let t0 = Instant::now();
            Self {
                t0,
                ledger: LossLedger::new(t0),
                s,
                r,
                sent: 0,
            }
        }

        fn send(&mut self, path: Path) {
            let sent = at(self.t0, self.sent * 1000);
            self.ledger.sweep(sent);
            self.ledger.sent(self.s, sent);
            if path != Path::Fwd {
                let reply_at = match path {
                    Path::Late => sent + LOSS_WAIT + Duration::from_millis(500),
                    _ => sent + Duration::from_millis(5),
                };
                if path != Path::Rev {
                    self.ledger.reply(self.s, self.r, reply_at);
                }
                self.r = self.r.wrapping_add(1);
            }
            self.s = self.s.wrapping_add(1);
            self.sent += 1;
        }

        fn run(&mut self, paths: &[Path]) {
            for &p in paths {
                self.send(p);
            }
        }

        /// Advance to the loss tick after second `secs`, and the window
        /// of every final bucket.
        fn window_at(&mut self, secs: u64) -> LossWindow {
            self.ledger.advance(at(self.t0, secs * 1000), 1000);
            self.ledger.window(MAX_BUCKETS)
        }
    }

    fn split(w: &LossWindow) -> (u64, u64, u64, u64) {
        (w.lost, w.forward, w.reverse, w.unresolved())
    }

    /// D3, the invariant: whatever the mix of paths, `forward + reverse +
    /// unresolved = lost` after every operation, never more. With no
    /// reordering and every gap closed, the split is exact: forward the
    /// probes lost outbound, reverse those lost inbound or answered late.
    #[test]
    fn direction_classifies_losses_and_never_counts_them() {
        let mut link = Link::new(100, 5_000);
        let (mut fwd, mut rev) = (0, 0);
        let mut state = 0x2545_f491u32;
        for i in 0..90 {
            // A cheap deterministic mix, with runs: xorshift.
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            let path = match (i, state % 10) {
                (0, _) | (89, _) => Path::Ok,
                (_, 0) => Path::Fwd,
                (_, 1) => Path::Rev,
                (_, 2) => Path::Late,
                _ => Path::Ok,
            };
            match path {
                Path::Fwd => fwd += 1,
                Path::Rev | Path::Late => rev += 1,
                Path::Ok => {}
            }
            link.send(path);
            let w = link.ledger.window(MAX_BUCKETS);
            assert!(w.forward + w.reverse <= w.lost, "after probe {i}: {w:?}");
        }
        let w = link.window_at(123);
        assert_eq!((w.lost, w.forward, w.reverse), (fwd + rev, fwd, rev));
        assert!(fwd > 0 && rev > 0, "the mix exercised both directions");
    }

    /// Return-path reordering: replies 10, 12, 11. Probe 11 is still
    /// outstanding when 12's reply arrives, and received before it could
    /// settle, so no gap forms and no loss appears in either direction.
    /// Forward-path reordering (the reflector sees 10, 12, 11) likewise.
    #[test]
    fn reordering_without_loss_forms_no_gap() {
        for reflector in [[10, 12, 11], [10, 11, 12]] {
            let t0 = Instant::now();
            let mut l = LossLedger::new(t0);
            for s in 10..13 {
                l.sent(s, at(t0, u64::from(s) * 100));
            }
            // Replies in the order 10, 12, 11.
            for (s, r) in [(10, reflector[0]), (12, reflector[2]), (11, reflector[1])] {
                assert_eq!(l.reply(s, r, at(t0, 1_400)), ReplyFate::Received);
            }
            l.advance(at(t0, 33_000), 1000);
            let w = l.window(1);
            assert_eq!(split(&w), (0, 0, 0, 0), "{reflector:?}");
        }
    }

    /// A reverse-path burst longer than the waiting time: its probes
    /// settle lost and stay unresolved while it lasts — read as forward,
    /// the upper bound — then all move to reverse once the first reply
    /// after it closes the gap, including those in an already-final
    /// bucket. A forward-path burst closes all forward.
    #[test]
    fn a_long_burst_is_unresolved_until_its_gap_closes() {
        for (path, forward) in [(Path::Rev, false), (Path::Fwd, true)] {
            let mut link = Link::new(0, 0);
            link.run(&[Path::Ok; 25]);
            link.run(&[path; 20]); // 25 s to 44 s
            let w = link.window_at(33);
            assert_eq!(split(&w), (5, 0, 0, 5), "{path:?}: open at 33 s");
            assert_eq!(w.as_forward().lost, 5, "unresolved reads as forward");
            link.run(&[Path::Ok; 20]);
            let w = link.window_at(63);
            let want = if forward {
                (20, 20, 0, 0)
            } else {
                (20, 0, 20, 0)
            };
            assert_eq!(split(&w), want, "{path:?}: closed");
        }
    }

    /// Retained PR 4 review probe: a peer can remain silent while its
    /// IGP adjacency stays up. The open gap must not retain one tally
    /// entry per bucket forever after those buckets leave the ring.
    #[test]
    fn an_open_gap_keeps_only_bounded_bucket_history() {
        let t0 = Instant::now();
        let mut l = LossLedger::new(t0);
        // One probe per 30 s is a supported rate; all replies disappear.
        for seq in 0..(MAX_BUCKETS as u32 * 3) {
            let sent = t0 + BUCKET * seq;
            l.sent(seq, sent);
            l.advance(sent + LOSS_WAIT, 30_000);
        }
        assert!(
            l.gaps.tally.len() <= MAX_BUCKETS + 2,
            "open gap retained {} bucket records for a {}-bucket ring",
            l.gaps.tally.len(),
            l.buckets.len()
        );
    }

    /// A gap that outlived the ring still classifies what is left of it.
    /// A silent return path for 150 buckets, one probe each; the oldest
    /// members' buckets roll out and are only counted. When the reply
    /// comes, the 120-bucket window ends at the reply's own bucket, so it
    /// holds 119 members. Reflected in full, all 119 read reverse;
    /// reflected by a third, they take exactly their proportional share,
    /// ⌊50·150/150⌋ − ⌊50·31/150⌋ = 40, with the 31 older members'
    /// share dropped along with their buckets. (Counting the kept
    /// members from zero instead would give 39.)
    #[test]
    fn a_gap_longer_than_the_ring_classifies_what_is_kept() {
        for (reached, kept_reverse) in [(150u32, 119u64), (50, 40)] {
            let t0 = Instant::now();
            let mut l = LossLedger::new(t0);
            l.sent(0, t0);
            l.reply(0, 0, t0 + Duration::from_millis(5));
            for seq in 1..=150u32 {
                let sent = t0 + BUCKET * seq;
                l.sent(seq, sent);
                l.advance(sent + LOSS_WAIT, 30_000);
            }
            assert_eq!(l.gaps.members, 150);
            assert!(l.gaps.tally.len() <= MAX_BUCKETS + 2);
            let sent = t0 + BUCKET * 151;
            l.sent(151, sent);
            l.reply(151, reached + 1, sent + Duration::from_millis(5));
            l.advance(sent + BUCKET + LOSS_WAIT, 30_000);
            let w = l.window(MAX_BUCKETS);
            assert_eq!(w.reverse, kept_reverse, "reached {reached}");
            assert!(w.forward + w.reverse <= w.lost);
        }
    }

    /// A reply after the waiting time leaves its probe lost (RFC 7680)
    /// and anchors nothing; the reflector counted the probe, so the gap
    /// classifies it reverse.
    #[test]
    fn a_late_reply_stays_lost_and_classifies_reverse() {
        let mut link = Link::new(0, 0);
        link.run(&[Path::Ok, Path::Late, Path::Ok, Path::Ok]);
        let w = link.window_at(33);
        assert_eq!(split(&w), (1, 0, 1, 0));
        assert_eq!(link.ledger.late, 1);
    }

    /// A reflector counter restart inside a gap — the peer rebooted, or
    /// toggled `reflector stateful` — leaves the gap unresolved. Serial
    /// arithmetic sends the "negative" count far above the gap size, and
    /// nothing goes negative or wraps into a count.
    #[test]
    fn a_reflector_counter_restart_leaves_the_gap_unresolved() {
        let mut link = Link::new(0, 1_000);
        link.run(&[Path::Ok, Path::Ok, Path::Fwd, Path::Rev]);
        link.r = 0; // the restart
        link.run(&[Path::Ok, Path::Ok]);
        let w = link.window_at(33);
        assert_eq!(split(&w), (2, 0, 0, 2));
        // And the next gap, anchored in the new counter, classifies.
        link.run(&[Path::Rev, Path::Ok]);
        let w = link.window_at(63);
        assert_eq!(split(&w), (3, 0, 1, 2));
    }

    /// Both counters wrap at 2³² in the middle of a gap.
    #[test]
    fn sequence_numbers_wrap_across_a_gap() {
        let mut link = Link::new(u32::MAX - 1, u32::MAX);
        link.run(&[Path::Ok, Path::Fwd, Path::Rev, Path::Fwd, Path::Ok]);
        let w = link.window_at(33);
        assert_eq!(split(&w), (3, 2, 1, 0));
    }

    /// The mode is declared, not detected. A stateless peer declared
    /// `peer-reflector stateful` copies the sender's sequence number, so
    /// `R = S` and every loss — forward ones too — classifies reverse:
    /// the configured-not-detected hazard, pinned.
    #[test]
    fn a_stateless_peer_reads_as_all_reverse() {
        let t0 = Instant::now();
        let mut l = LossLedger::new(t0);
        for s in 0..6u32 {
            l.sent(s, at(t0, u64::from(s) * 1000));
            if ![2, 3].contains(&s) {
                l.reply(s, s, at(t0, u64::from(s) * 1000 + 5));
            }
        }
        l.advance(at(t0, 33_000), 1000);
        assert_eq!(split(&l.window(1)), (2, 0, 2, 0));
    }

    /// A gap over a bucket boundary: the split is known only for the gap
    /// as a whole, so each bucket gets its proportional share, and the
    /// shares add up exactly.
    #[test]
    fn a_gap_across_buckets_is_split_in_proportion() {
        let mut link = Link::new(0, 0);
        link.run(&[Path::Ok; 27]);
        // 27–29 s in bucket 0, 30 s in bucket 1: 3 + 1 members, 2 reverse.
        link.run(&[Path::Fwd, Path::Rev, Path::Fwd, Path::Rev, Path::Ok]);
        link.run(&[Path::Ok; 28]);
        link.ledger.advance(at(link.t0, 63_000), 1000);
        let (b0, b1) = (link.ledger.buckets[0], link.ledger.buckets[1]);
        assert_eq!((b0.lost, b0.forward, b0.reverse), (3, 2, 1));
        assert_eq!((b1.lost, b1.forward, b1.reverse), (1, 0, 1));
    }

    /// The race `unlose` guards: a reply read in time but processed after
    /// the sweep that settled — and retired and classified — its probe.
    /// The probe is received after all. Its reply came back, so it
    /// reached the reflector: it was one of the gap's reverse share, and
    /// the bucket's reverse count gives way, not its forward one.
    #[test]
    fn a_reply_processed_after_its_gap_closed_keeps_the_invariant() {
        let t0 = Instant::now();
        let mut l = LossLedger::new(t0);
        for s in 0..5u32 {
            l.sent(s, at(t0, u64::from(s) * 1000));
        }
        // Probe 1 never reached the reflector; 2 and 3 did (counter 1
        // and 2) and their replies went missing.
        l.reply(0, 0, at(t0, 5));
        l.reply(4, 3, at(t0, 4_005));
        l.sweep(at(t0, 6_500));
        l.advance(at(t0, 33_000), 1000);
        assert_eq!(split(&l.window(1)), (3, 1, 2, 0));
        // Probe 3's reply had been read at 5.9 s, before its deadline.
        assert_eq!(l.reply(3, 2, at(t0, 5_900)), ReplyFate::Received);
        assert_eq!(split(&l.window(1)), (2, 1, 1, 0));
    }

    /// The same race while the gap is still open: the probe had retired
    /// into it as lost, and is received after all before the gap closes.
    /// The gap still counts it, so its classification is clamped to what
    /// the bucket has left — `forward + reverse <= lost` — rather than
    /// running past it (and the forward view underflowing).
    #[test]
    fn a_reply_processed_while_its_gap_is_open_is_clamped() {
        let t0 = Instant::now();
        let mut l = LossLedger::new(t0);
        for s in 0..4u32 {
            l.sent(s, at(t0, u64::from(s) * 1000));
        }
        l.reply(0, 0, at(t0, 5));
        l.sweep(at(t0, 5_500)); // probes 1 and 2 settle lost and retire
        assert_eq!(l.reply(1, 1, at(t0, 3_900)), ReplyFate::Received);
        l.reply(3, 3, at(t0, 3_005));
        l.advance(at(t0, 33_000), 1000);
        let w = l.window(1);
        assert_eq!(split(&w), (1, 0, 1, 0));
        assert_eq!(w.as_forward().lost, 0);
    }

    /// A break in the sender's sequence — the ledger never saw the
    /// probes in between — cannot anchor a gap across it: the losses
    /// before it stay unresolved, even though the reflector's counter
    /// (0, then 2: one probe reached it in between) would classify the
    /// one lost probe the ledger knows of as reverse.
    #[test]
    fn a_break_in_the_sequence_leaves_the_gap_unresolved() {
        let t0 = Instant::now();
        let mut l = LossLedger::new(t0);
        for (i, s) in [0u32, 1, 5, 6].into_iter().enumerate() {
            l.sent(s, at(t0, i as u64 * 1000));
        }
        l.reply(0, 0, at(t0, 5));
        l.reply(5, 2, at(t0, 2_005));
        l.reply(6, 3, at(t0, 3_005));
        l.advance(at(t0, 33_000), 1000);
        assert_eq!(split(&l.window(1)), (1, 0, 0, 1));
    }

    /// Design D3: a `peer-reflector stateful` subscriber advertises
    /// forward loss, `(forward + unresolved) / settled`; the default one
    /// round-trip. Reverse-only loss reads 10 % round-trip and 0 %
    /// forward.
    #[test]
    fn a_stateful_peer_advertises_forward_loss() {
        let mut link = Link::new(0, 0);
        for _ in 0..3 {
            link.run(&[Path::Ok, Path::Ok, Path::Ok, Path::Ok, Path::Rev]);
            link.run(&[Path::Ok, Path::Ok, Path::Ok, Path::Ok, Path::Ok]);
        }
        link.ledger.advance(at(link.t0, 33_000), 1000);
        let round_trip = LossPolicy {
            window_buckets: 1,
            ..LossPolicy::default()
        };
        let forward = LossPolicy {
            peer_reflector_stateful: true,
            ..round_trip
        };
        let now = at(link.t0, 33_000);
        let decide =
            |p: &LossPolicy| evaluate(p, &link.ledger, None, None, &mut Anomaly::default(), now);
        assert_eq!(decide(&round_trip), set(encode_loss(3, 30)));
        assert_eq!(decide(&forward), set(0));
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
