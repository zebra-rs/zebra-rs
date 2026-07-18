//! RP set: static RP configuration with group-prefix longest-match,
//! the SSM range predicate, and re-targeting of (*,G) state when the
//! mapping changes. Provenance is static-only until the BSR phase.

use std::collections::BTreeMap;

use super::af::PimAf;
use super::inst::Pim;
use super::ipv4::Ipv4;
use super::tib::SgKey;

/// Static RP table: RP address → served group range.
#[derive(Debug, Clone)]
pub struct RpSet<A: PimAf = Ipv4> {
    pub statics: BTreeMap<A::Addr, A::Prefix>,
}

impl<A: PimAf> Default for RpSet<A> {
    fn default() -> Self {
        Self {
            statics: BTreeMap::new(),
        }
    }
}

impl<A: PimAf> Pim<A> {
    /// RP(G): longest-prefix match across the static entries; when
    /// no static range covers the group, fall back to the
    /// BSR-learned set (static beats BSR). SSM groups never map to
    /// an RP.
    pub(crate) fn rp_lookup(&self, grp: A::Addr) -> Option<A::Addr> {
        if A::is_ssm(grp) || !A::is_multicast(grp) {
            return None;
        }
        self.rp_set
            .statics
            .iter()
            .filter(|(_, range)| A::prefix_contains(range, &grp))
            .max_by_key(|(_, range)| A::prefix_len(range))
            .map(|(rp, _)| *rp)
            .or_else(|| self.bsr_rp_lookup(grp))
    }

    /// I_am_RP(G): the mapped RP address is one of our interface
    /// addresses.
    pub(crate) fn i_am_rp(&self, grp: A::Addr) -> bool {
        let Some(rp) = self.rp_lookup(grp) else {
            return false;
        };
        self.links.values().any(|l| l.is_my_addr(&rp))
    }

    /// The static RP table changed: every (*,G) whose mapped RP
    /// differs from the one it is built on gets re-targeted — prune
    /// the old upstream, move the RPF tracking, re-evaluate.
    pub(crate) fn rp_reevaluate(&mut self) {
        let stars: Vec<(SgKey<A>, Option<A::Addr>)> = self
            .tib
            .iter()
            .filter_map(|(key, entry)| match key {
                SgKey::StarG { grp } => {
                    let want = self.rp_lookup(*grp);
                    if want != entry.rpf_target {
                        Some((*key, want))
                    } else {
                        None
                    }
                }
                _ => None,
            })
            .collect();
        for (key, want) in stars {
            self.tib_retarget(key, want);
        }
    }
}
