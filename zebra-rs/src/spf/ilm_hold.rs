//! Make-before-break for Prefix-SID labels that move
//! (docs/design/mpls-label-allocation.md §6.1).
//!
//! A Prefix-SID's label is its originator's SRGB start plus the index, so
//! when a router changes its SRGB every router's ILM entry for its
//! prefixes moves to a new label, each as it processes the new
//! advertisement. A router that has moved keeps the old label forwarding
//! for [`SID_MOVE_HOLD`], so an upstream that has not moved yet is not
//! dropped. The reverse window — an upstream already sending the new
//! label to a router that has not installed it yet — is not covered; RFC
//! 8660 labels close it (the design's §1).
//!
//! An IGP folds an [`IlmHold`] into each ILM table it rebuilds, before
//! diffing the table against the installed one: a held label stays in the
//! table, so the diff neither withdraws it nor needs to know about holds.

use std::collections::BTreeMap;
use std::time::Duration;

use ipnet::IpNet;
use tokio::time::Instant;

/// How long a moved Prefix-SID's old label keeps forwarding: ample for
/// the new advertisement to flood and every router to recompute.
pub const SID_MOVE_HOLD: Duration = Duration::from_secs(60);

/// What a Prefix-SID ILM entry forwards for: the prefix, under its
/// algorithm. The same FEC under two labels means the SID moved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SidFec {
    pub algo: u8,
    pub prefix: IpNet,
}

/// An ILM table entry, which carries a Prefix-SID or does not
/// (an Adjacency-SID never moves this way: its label is allocated).
pub trait SidIlm: Clone {
    fn fec(&self) -> Option<SidFec>;
}

/// The old labels of one ILM table's moved Prefix-SIDs.
#[derive(Debug, Default)]
pub struct IlmHold {
    held: BTreeMap<u32, (SidFec, Instant)>,
}

impl IlmHold {
    /// Fold the held labels into `next`, the table just built to replace
    /// `prev`:
    /// - a label `prev` gives a FEC that `next` gives another label is
    ///   held from `now`;
    /// - a held label `next` uses itself stops being held: the new entry
    ///   replaces the old at once;
    /// - a held label whose FEC `next` no longer has, or whose time is up,
    ///   stops being held, so the diff withdraws it;
    /// - every other held label carries its FEC's current entry, so it
    ///   follows the FEC's path rather than a stale one.
    pub fn apply<V: SidIlm>(
        &mut self,
        prev: &BTreeMap<u32, V>,
        next: &mut BTreeMap<u32, V>,
        now: Instant,
    ) {
        let labels: BTreeMap<SidFec, u32> = next
            .iter()
            .filter_map(|(label, entry)| entry.fec().map(|fec| (fec, *label)))
            .collect();
        for (label, entry) in prev {
            if self.held.contains_key(label) || next.contains_key(label) {
                continue;
            }
            if let Some(fec) = entry.fec()
                && labels.contains_key(&fec)
            {
                self.held.insert(*label, (fec, now + SID_MOVE_HOLD));
            }
        }
        self.held.retain(|label, (fec, until)| {
            *until > now && !next.contains_key(label) && labels.contains_key(fec)
        });
        for (label, (fec, _)) in &self.held {
            if let Some(entry) = labels.get(fec).and_then(|l| next.get(l)).cloned() {
                next.insert(*label, entry);
            }
        }
    }

    /// `table` as [`Self::apply`] would leave it at `now`: its own
    /// entries, with the held labels that are still due. For a hold
    /// running out with no new table to fold it into.
    pub fn refresh<V: SidIlm>(
        &mut self,
        table: &BTreeMap<u32, V>,
        now: Instant,
    ) -> BTreeMap<u32, V> {
        let mut next = table
            .iter()
            .filter(|(label, _)| !self.held.contains_key(label))
            .map(|(label, entry)| (*label, entry.clone()))
            .collect();
        self.apply(table, &mut next, now);
        next
    }

    /// When the first held label runs out, if any is held.
    pub fn due(&self) -> Option<Instant> {
        self.held.values().map(|(_, until)| *until).min()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, PartialEq)]
    struct Entry {
        fec: Option<SidFec>,
        via: u8,
    }

    impl SidIlm for Entry {
        fn fec(&self) -> Option<SidFec> {
            self.fec
        }
    }

    fn fec(prefix: &str) -> SidFec {
        SidFec {
            algo: 0,
            prefix: prefix.parse().unwrap(),
        }
    }

    fn sid(prefix: &str, via: u8) -> Entry {
        Entry {
            fec: Some(fec(prefix)),
            via,
        }
    }

    fn adj(via: u8) -> Entry {
        Entry { fec: None, via }
    }

    fn table(entries: &[(u32, Entry)]) -> BTreeMap<u32, Entry> {
        entries.iter().cloned().collect()
    }

    /// Fold `next` in after `prev` at `now`, as an IGP does.
    fn step(
        hold: &mut IlmHold,
        prev: &BTreeMap<u32, Entry>,
        next: &[(u32, Entry)],
        now: Instant,
    ) -> BTreeMap<u32, Entry> {
        let mut next = table(next);
        hold.apply(prev, &mut next, now);
        next
    }

    /// A moved Prefix-SID keeps its old label, with its current entry,
    /// until the hold runs out.
    #[test]
    fn a_moved_sid_keeps_its_old_label_for_the_hold() {
        let t0 = Instant::now();
        let mut hold = IlmHold::default();
        let before = table(&[(16001, sid("10.0.0.1/32", 1))]);
        let after = step(&mut hold, &before, &[(17001, sid("10.0.0.1/32", 1))], t0);
        assert_eq!(
            after,
            table(&[
                (16001, sid("10.0.0.1/32", 1)),
                (17001, sid("10.0.0.1/32", 1))
            ])
        );
        assert_eq!(hold.due(), Some(t0 + SID_MOVE_HOLD));

        let t1 = t0 + SID_MOVE_HOLD - Duration::from_secs(1);
        assert_eq!(hold.refresh(&after, t1), after, "still due");
        let t2 = t0 + SID_MOVE_HOLD;
        assert_eq!(
            hold.refresh(&after, t2),
            table(&[(17001, sid("10.0.0.1/32", 1))])
        );
        assert_eq!(hold.due(), None);
    }

    /// The old label follows the FEC's path, so it does not forward on a
    /// stale one while held.
    #[test]
    fn a_held_label_follows_its_sid() {
        let t0 = Instant::now();
        let mut hold = IlmHold::default();
        let before = table(&[(16001, sid("10.0.0.1/32", 1))]);
        let moved = step(&mut hold, &before, &[(17001, sid("10.0.0.1/32", 1))], t0);
        let rerouted = step(&mut hold, &moved, &[(17001, sid("10.0.0.1/32", 2))], t0);
        assert_eq!(rerouted.get(&16001), Some(&sid("10.0.0.1/32", 2)));
    }

    /// A Prefix-SID that goes away takes its held label with it: nothing
    /// is left to forward to.
    #[test]
    fn a_held_label_goes_with_its_sid() {
        let t0 = Instant::now();
        let mut hold = IlmHold::default();
        let before = table(&[(16001, sid("10.0.0.1/32", 1))]);
        let moved = step(&mut hold, &before, &[(17001, sid("10.0.0.1/32", 1))], t0);
        assert_eq!(step(&mut hold, &moved, &[], t0), table(&[]));
        assert_eq!(hold.due(), None);
    }

    /// A new entry at a held label replaces the old at once (the old and
    /// new ranges overlap).
    #[test]
    fn a_new_entry_at_a_held_label_replaces_it() {
        let t0 = Instant::now();
        let mut hold = IlmHold::default();
        let before = table(&[
            (16001, sid("10.0.0.1/32", 1)),
            (16002, sid("10.0.0.2/32", 1)),
        ]);
        // The SRGB moved up by one: 10.0.0.1 now sits at 16002.
        let moved = step(
            &mut hold,
            &before,
            &[
                (16002, sid("10.0.0.1/32", 1)),
                (16003, sid("10.0.0.2/32", 1)),
            ],
            t0,
        );
        assert_eq!(moved.get(&16002), Some(&sid("10.0.0.1/32", 1)));
        assert_eq!(moved.get(&16001), Some(&sid("10.0.0.1/32", 1)));
        assert_eq!(moved.len(), 3);
        // A later move back: 16001 is 10.0.0.1's own label again, so it is
        // no longer held, and running the clock out keeps it.
        let back = step(
            &mut hold,
            &moved,
            &[
                (16001, sid("10.0.0.1/32", 1)),
                (16002, sid("10.0.0.2/32", 1)),
            ],
            t0,
        );
        assert_eq!(
            hold.refresh(&back, t0 + SID_MOVE_HOLD),
            table(&[
                (16001, sid("10.0.0.1/32", 1)),
                (16002, sid("10.0.0.2/32", 1))
            ])
        );
    }

    /// Only Prefix-SIDs are held: a label without a FEC, or whose FEC is
    /// gone, is withdrawn as before.
    #[test]
    fn only_a_moved_sid_is_held() {
        let t0 = Instant::now();
        let mut hold = IlmHold::default();
        let before = table(&[(15000, adj(1)), (16001, sid("10.0.0.1/32", 1))]);
        assert_eq!(
            step(&mut hold, &before, &[(15001, adj(1))], t0),
            table(&[(15001, adj(1))])
        );
        assert_eq!(hold.due(), None);
    }

    /// A SID that moves twice holds both old labels, each for its own time.
    #[test]
    fn a_second_move_holds_both_old_labels() {
        let t0 = Instant::now();
        let mut hold = IlmHold::default();
        let first = table(&[(16001, sid("10.0.0.1/32", 1))]);
        let second = step(&mut hold, &first, &[(17001, sid("10.0.0.1/32", 1))], t0);
        let t1 = t0 + Duration::from_secs(10);
        let third = step(&mut hold, &second, &[(18001, sid("10.0.0.1/32", 1))], t1);
        assert_eq!(third.len(), 3);
        assert_eq!(
            hold.refresh(&third, t0 + SID_MOVE_HOLD)
                .keys()
                .collect::<Vec<_>>(),
            vec![&17001, &18001]
        );
        assert_eq!(hold.due(), Some(t1 + SID_MOVE_HOLD));
    }
}
