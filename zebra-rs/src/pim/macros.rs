//! RFC 7761 state-summarization predicates as named pure functions
//! over the TIB (the ZebOS `pim_route.c` pattern). They take the
//! whole table because the (S,G) inherited olist folds in same-group
//! (*,G) and (S,G,rpt) state.

use std::collections::{BTreeMap, BTreeSet};

use super::tib::{DsState, SgKey, TibEntry};

/// `immediate_olist(key)`: interfaces with local (IGMP) membership
/// or downstream Join state on this entry. A PrunePending interface
/// still forwards until its timer fires (RFC 7761 §4.5.2).
pub fn immediate_olist(tib: &BTreeMap<SgKey, TibEntry>, key: SgKey) -> BTreeSet<u32> {
    let Some(entry) = tib.get(&key) else {
        return BTreeSet::new();
    };
    let mut olist: BTreeSet<u32> = entry.local.iter().copied().collect();
    for (ifindex, ds) in entry.downstream.iter() {
        match ds.state {
            DsState::Join | DsState::PrunePending { .. } => {
                olist.insert(*ifindex);
            }
        }
    }
    olist
}

/// `inherited_olist(S,G)`: the source tree's effective forwarding
/// set — immediate (S,G) state plus the shared tree's olist minus
/// interfaces holding an (S,G,rpt) prune. For non-(S,G) keys it is
/// the immediate olist.
pub fn inherited_olist(tib: &BTreeMap<SgKey, TibEntry>, key: SgKey) -> BTreeSet<u32> {
    let SgKey::Sg { src, grp } = key else {
        return immediate_olist(tib, key);
    };
    let mut olist = immediate_olist(tib, key);
    let mut shared = immediate_olist(tib, SgKey::StarG { grp });
    if let Some(rpt) = tib.get(&SgKey::SgRpt { src, grp }) {
        for ifindex in rpt.downstream.keys() {
            shared.remove(ifindex);
        }
    }
    olist.extend(shared);
    olist
}

/// `JoinDesired(key)` — someone wants the traffic on this tree.
/// Whether a Join can actually be *sent* additionally requires an
/// upstream PIM neighbor (and, for (*,G), a known RP) — those gates
/// live in the upstream FSM, not here.
pub fn join_desired(tib: &BTreeMap<SgKey, TibEntry>, key: SgKey) -> bool {
    !immediate_olist(tib, key).is_empty()
}

/// The (S,G) MFC outgoing set: the inherited olist minus the
/// incoming interface (loop-free guard — never emit OIF == IIF).
pub fn mfc_oifs(tib: &BTreeMap<SgKey, TibEntry>, key: SgKey) -> BTreeSet<u32> {
    let mut oifs = inherited_olist(tib, key);
    if let Some(iif) = tib.get(&key).and_then(|e| e.rpf.ifindex()) {
        oifs.remove(&iif);
    }
    oifs
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::{Duration, Instant};

    use super::*;
    use crate::pim::rpf::RpfState;
    use crate::pim::tib::Downstream;

    fn sg() -> SgKey {
        SgKey::Sg {
            src: Ipv4Addr::new(10, 0, 0, 2),
            grp: Ipv4Addr::new(239, 1, 1, 1),
        }
    }

    fn star() -> SgKey {
        SgKey::StarG {
            grp: Ipv4Addr::new(239, 1, 1, 1),
        }
    }

    fn rpt() -> SgKey {
        SgKey::SgRpt {
            src: Ipv4Addr::new(10, 0, 0, 2),
            grp: Ipv4Addr::new(239, 1, 1, 1),
        }
    }

    fn ds_join() -> Downstream {
        Downstream {
            state: DsState::Join,
            expires: Instant::now() + Duration::from_secs(210),
        }
    }

    #[test]
    fn olist_combines_local_and_downstream() {
        let mut tib = BTreeMap::new();
        let mut e = TibEntry::new();
        e.local.insert(3);
        e.downstream.insert(5, ds_join());
        tib.insert(sg(), e);
        assert_eq!(
            immediate_olist(&tib, sg()).into_iter().collect::<Vec<_>>(),
            vec![3, 5]
        );
        assert!(join_desired(&tib, sg()));
        assert!(!join_desired(&tib, star()));
    }

    #[test]
    fn prune_pending_still_forwards() {
        let mut tib = BTreeMap::new();
        let mut e = TibEntry::new();
        e.downstream.insert(
            5,
            Downstream {
                state: DsState::PrunePending {
                    until: Instant::now() + Duration::from_secs(3),
                },
                expires: Instant::now() + Duration::from_secs(210),
            },
        );
        tib.insert(sg(), e);
        assert!(join_desired(&tib, sg()));
    }

    #[test]
    fn inherited_folds_shared_tree_minus_rpt_prunes() {
        let mut tib = BTreeMap::new();
        // (S,G): downstream on 5.
        let mut e = TibEntry::new();
        e.downstream.insert(5, ds_join());
        tib.insert(sg(), e);
        // (*,G): downstream on 6 and 7.
        let mut se = TibEntry::new();
        se.downstream.insert(6, ds_join());
        se.downstream.insert(7, ds_join());
        tib.insert(star(), se);
        // (S,G,rpt): pruned on 7.
        let mut re = TibEntry::new();
        re.downstream.insert(7, ds_join());
        tib.insert(rpt(), re);

        let inherited = inherited_olist(&tib, sg());
        assert!(inherited.contains(&5));
        assert!(inherited.contains(&6));
        assert!(!inherited.contains(&7));
    }

    #[test]
    fn mfc_excludes_iif() {
        let mut tib = BTreeMap::new();
        let mut e = TibEntry::new();
        e.local.insert(3);
        e.local.insert(7);
        e.rpf = RpfState::Connected { ifindex: 7 };
        tib.insert(sg(), e);
        let oifs = mfc_oifs(&tib, sg());
        assert!(oifs.contains(&3));
        assert!(!oifs.contains(&7));
    }
}
