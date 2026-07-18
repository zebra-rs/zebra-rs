//! RFC 7761 state-summarization predicates as named pure functions
//! over a TIB entry (the ZebOS `pim_route.c` pattern). This phase
//! carries the (S,G) subset the SSM slice needs; the rpt/star
//! variants arrive with the ASM phase.

use std::collections::BTreeSet;

use super::tib::{DsState, TibEntry};

/// `immediate_olist(S,G)`: interfaces with local (IGMP) membership or
/// downstream Join state. A PrunePending interface still forwards
/// until its timer fires (RFC 7761 §4.5.2 — the downstream state
/// machine stays in the forwarding set during PrunePending).
pub fn immediate_olist(entry: &TibEntry) -> BTreeSet<u32> {
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

/// `JoinDesired(S,G)`: someone downstream (or local) wants the
/// traffic. Whether a Join can actually be *sent* additionally
/// requires an upstream PIM neighbor — that gate lives in the
/// upstream FSM, not here.
pub fn join_desired(entry: &TibEntry) -> bool {
    !immediate_olist(entry).is_empty()
}

/// The MFC outgoing set: the olist minus the incoming interface
/// (loop-free guard — never emit OIF == IIF).
pub fn mfc_oifs(entry: &TibEntry, rpf_ifindex: Option<u32>) -> BTreeSet<u32> {
    let mut oifs = immediate_olist(entry);
    if let Some(iif) = rpf_ifindex {
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
    use crate::pim::tib::{Downstream, Sg, TibEntry};

    fn entry() -> TibEntry {
        TibEntry::new(Sg {
            src: Ipv4Addr::new(10, 0, 0, 2),
            grp: Ipv4Addr::new(232, 1, 1, 1),
        })
    }

    #[test]
    fn olist_combines_local_and_downstream() {
        let mut e = entry();
        assert!(!join_desired(&e));
        e.local.insert(3);
        e.downstream.insert(
            5,
            Downstream {
                state: DsState::Join,
                expires: Instant::now() + Duration::from_secs(210),
            },
        );
        assert_eq!(
            immediate_olist(&e).into_iter().collect::<Vec<_>>(),
            vec![3, 5]
        );
        assert!(join_desired(&e));
    }

    #[test]
    fn prune_pending_still_forwards() {
        let mut e = entry();
        e.downstream.insert(
            5,
            Downstream {
                state: DsState::PrunePending {
                    until: Instant::now() + Duration::from_secs(3),
                },
                expires: Instant::now() + Duration::from_secs(210),
            },
        );
        assert!(join_desired(&e));
        assert_eq!(immediate_olist(&e).len(), 1);
    }

    #[test]
    fn mfc_excludes_iif() {
        let mut e = entry();
        e.local.insert(3);
        e.local.insert(7);
        e.rpf = RpfState::Connected { ifindex: 7 };
        let oifs = mfc_oifs(&e, e.rpf.ifindex());
        assert!(oifs.contains(&3));
        assert!(!oifs.contains(&7));
    }
}
