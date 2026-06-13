//! Per-AFI/SAFI membership index over Established peers.
//!
//! Every advertise fan-out asks the same three questions of every
//! peer: is the session Established, is the family negotiated, and is
//! AddPath Send on. All three are session constants — they change
//! only when a session enters or leaves Established (the capability
//! intersection is fixed by the OPEN exchange, and RFC 7911 has no
//! mid-session AddPath renegotiation). This index answers them once,
//! at the FSM chokepoint, instead of per-prefix in every fan-out.
//!
//! Ownership: the index lives inside `PeerMap` so peer removal purges
//! membership by construction — a freed ident can never linger here
//! and be inherited by the next peer that reuses the slot (`PeerMap`
//! reuses indices on same-key re-insert, so a stale ident is an ABA
//! hazard, not just a leak). The update-groups structure lives outside
//! `PeerMap` and needs an explicit `update_group::detach` at every
//! removal site instead.
//!
//! See `docs/design/bgp-peer-list.md` (Option B) for the full design.

use std::collections::{BTreeMap, BTreeSet};

use bgp_packet::{Afi, AfiSafi, Safi};

/// The Established peers of one address family, split by negotiated
/// AddPath Send. The split mirrors the two advertise pipelines — the
/// per-candidate fan-out that stamps allocated path-ids on every NLRI
/// (RFC 7911) versus best-path-only — so a fan-out walks exactly the
/// set whose wire contract it implements.
#[derive(Debug, Default, Clone)]
pub struct FamilyMembers {
    /// AddPath Send negotiated: every NLRI of this family sent to
    /// these peers must carry a path identifier.
    pub addpath_tx: BTreeSet<usize>,
    /// Best-path-only peers — no path-id field on the wire.
    pub plain: BTreeSet<usize>,
}

impl FamilyMembers {
    pub fn is_empty(&self) -> bool {
        self.addpath_tx.is_empty() && self.plain.is_empty()
    }

    /// `Some(true)` if `ident` is enrolled in the AddPath-send half,
    /// `Some(false)` if in the plain half, `None` if absent.
    pub fn classification(&self, ident: usize) -> Option<bool> {
        if self.addpath_tx.contains(&ident) {
            Some(true)
        } else if self.plain.contains(&ident) {
            Some(false)
        } else {
            None
        }
    }

    /// Every member of the family — the AddPath-send half first, then
    /// plain, each ascending by ident.
    pub fn iter_all(&self) -> impl Iterator<Item = usize> + '_ {
        self.addpath_tx.iter().chain(self.plain.iter()).copied()
    }
}

/// AFI/SAFI → Established members. Maintained exclusively by
/// `PeerMap` (`membership_enroll` / `membership_withdraw` at the FSM
/// Established boundary, auto-purge on removal); fan-outs read it via
/// `PeerMap::membership`.
#[derive(Debug, Default)]
pub struct PeerMembership {
    families: BTreeMap<AfiSafi, FamilyMembers>,
}

impl PeerMembership {
    /// Enroll `ident` into `(afi, safi)` under the given AddPath-send
    /// classification. Re-enrolling moves the ident between halves
    /// when the classification differs, so a stale entry cannot
    /// survive a re-enroll.
    pub fn enroll(&mut self, afi_safi: AfiSafi, ident: usize, addpath_tx: bool) {
        let fam = self.families.entry(afi_safi).or_default();
        if addpath_tx {
            fam.plain.remove(&ident);
            fam.addpath_tx.insert(ident);
        } else {
            fam.addpath_tx.remove(&ident);
            fam.plain.insert(ident);
        }
    }

    /// Remove `ident` from every family; emptied families are
    /// dropped. Idempotent.
    pub fn withdraw(&mut self, ident: usize) {
        self.families.retain(|_, fam| {
            fam.addpath_tx.remove(&ident);
            fam.plain.remove(&ident);
            !fam.is_empty()
        });
    }

    /// The members of one family, or `None` when no Established peer
    /// has it negotiated.
    pub fn family(&self, afi: Afi, safi: Safi) -> Option<&FamilyMembers> {
        self.families.get(&AfiSafi::new(afi, safi))
    }

    pub fn iter(&self) -> impl Iterator<Item = (&AfiSafi, &FamilyMembers)> {
        self.families.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enroll_splits_addpath_and_plain() {
        let mut m = PeerMembership::default();
        let v4 = AfiSafi::new(Afi::Ip, Safi::Unicast);
        m.enroll(v4, 1, true);
        m.enroll(v4, 2, false);

        let fam = m.family(Afi::Ip, Safi::Unicast).expect("family exists");
        assert_eq!(fam.classification(1), Some(true));
        assert_eq!(fam.classification(2), Some(false));
        assert_eq!(fam.classification(3), None);
        assert_eq!(fam.iter_all().collect::<Vec<_>>(), vec![1, 2]);
    }

    #[test]
    fn re_enroll_moves_between_halves() {
        let mut m = PeerMembership::default();
        let v4 = AfiSafi::new(Afi::Ip, Safi::Unicast);
        m.enroll(v4, 1, false);
        m.enroll(v4, 1, true);

        let fam = m.family(Afi::Ip, Safi::Unicast).expect("family exists");
        assert_eq!(
            fam.classification(1),
            Some(true),
            "re-enroll must not leave the ident in both halves"
        );
        assert_eq!(fam.iter_all().count(), 1);
    }

    #[test]
    fn withdraw_purges_every_family_and_drops_empty() {
        let mut m = PeerMembership::default();
        let v4 = AfiSafi::new(Afi::Ip, Safi::Unicast);
        let v6 = AfiSafi::new(Afi::Ip6, Safi::Unicast);
        m.enroll(v4, 1, true);
        m.enroll(v6, 1, false);
        m.enroll(v6, 2, false);

        m.withdraw(1);
        assert!(
            m.family(Afi::Ip, Safi::Unicast).is_none(),
            "emptied family must be dropped"
        );
        let fam = m.family(Afi::Ip6, Safi::Unicast).expect("v6 still has 2");
        assert_eq!(fam.classification(1), None);
        assert_eq!(fam.classification(2), Some(false));

        // Idempotent.
        m.withdraw(1);
        assert_eq!(m.iter().count(), 1);
    }
}
