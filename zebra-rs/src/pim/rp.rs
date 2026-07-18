//! RP set: static RP configuration with group-prefix longest-match,
//! the SSM range predicate, and re-targeting of (*,G) state when the
//! mapping changes. Provenance is static-only until the BSR phase.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

use super::inst::Pim;
use super::tib::SgKey;

/// Default SSM range (RFC 4607): no RP, no register, (S,G) only.
fn ssm_range() -> Ipv4Net {
    Ipv4Net::new(Ipv4Addr::new(232, 0, 0, 0), 8).unwrap()
}

pub fn is_ssm(grp: Ipv4Addr) -> bool {
    ssm_range().contains(&grp)
}

/// Static RP table: RP address → served group range.
#[derive(Debug, Clone, Default)]
pub struct RpSet {
    pub statics: BTreeMap<Ipv4Addr, Ipv4Net>,
}

impl Pim {
    /// RP(G): longest-prefix match across the static entries. SSM
    /// groups never map to an RP.
    pub(crate) fn rp_lookup(&self, grp: Ipv4Addr) -> Option<Ipv4Addr> {
        if is_ssm(grp) || !grp.is_multicast() {
            return None;
        }
        self.rp_set
            .statics
            .iter()
            .filter(|(_, range)| range.contains(&grp))
            .max_by_key(|(_, range)| range.prefix_len())
            .map(|(rp, _)| *rp)
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
