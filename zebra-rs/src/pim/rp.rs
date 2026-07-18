//! RP set: static RP configuration with group-prefix longest-match,
//! the SSM range predicate, and re-targeting of (*,G) state when the
//! mapping changes. Provenance is static-only until the BSR phase.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use super::af::PimAf;
use super::inst::Pim;
use super::ipv4::Ipv4;
use super::tib::SgKey;

/// Default SSM range (RFC 4607): no RP, no register, (S,G) only.
/// Concrete-IPv4 wrapper over [`Ipv4::is_ssm`] kept for the existing
/// call sites in `register.rs`/`igmp`.
pub fn is_ssm(grp: Ipv4Addr) -> bool {
    Ipv4::is_ssm(grp)
}

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

impl Pim {
    /// RP(G): longest-prefix match across the static entries; when
    /// no static range covers the group, fall back to the
    /// BSR-learned set (static beats BSR). SSM groups never map to
    /// an RP.
    pub(crate) fn rp_lookup(&self, grp: Ipv4Addr) -> Option<Ipv4Addr> {
        if Ipv4::is_ssm(grp) || !Ipv4::is_multicast(grp) {
            return None;
        }
        self.rp_set
            .statics
            .iter()
            .filter(|(_, range)| Ipv4::prefix_contains(range, &grp))
            .max_by_key(|(_, range)| Ipv4::prefix_len(range))
            .map(|(rp, _)| *rp)
            .or_else(|| self.bsr_rp_lookup(grp))
    }

    /// I_am_RP(G): the mapped RP address is one of our interface
    /// addresses.
    pub(crate) fn i_am_rp(&self, grp: Ipv4Addr) -> bool {
        let Some(rp) = self.rp_lookup(grp) else {
            return false;
        };
        self.links.values().any(|l| l.is_my_addr(&rp))
    }

    /// The static RP table changed: every (*,G) whose mapped RP
    /// differs from the one it is built on gets re-targeted — prune
    /// the old upstream, move the RPF tracking, re-evaluate.
    pub(crate) fn rp_reevaluate(&mut self) {
        let stars: Vec<(SgKey, Option<Ipv4Addr>)> = self
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
