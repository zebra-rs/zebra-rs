use std::collections::BTreeMap;
use std::net::IpAddr;

use crate::rib::inst::IlmEntry;
use crate::rib::nexthop::NexthopUni;
use crate::rib::{Nexthop, NexthopMulti, RibType};

#[derive(Debug, Default, Clone)]
pub struct MplsNexthop {
    pub out_label: Option<u32>,
    /// Explicit egress interface — opts the pop onto the eBPF XDP fast
    /// path (see `IlmEntry::nexthop_ifname`).
    pub interface: Option<String>,
}

#[derive(Debug, Default, Clone)]
pub struct MplsRoute {
    pub nexthops: BTreeMap<IpAddr, MplsNexthop>,
    pub delete: bool,
}

impl MplsRoute {
    pub fn to_ilm(&self) -> Option<IlmEntry> {
        if self.nexthops.is_empty() {
            return None;
        }

        let mut ilm = IlmEntry::new(RibType::Static);

        if self.nexthops.len() == 1 {
            let (&addr, n) = self.nexthops.iter().next()?;
            let mut nhop = NexthopUni {
                addr,
                ..Default::default()
            };
            if let Some(out_label) = n.out_label {
                nhop.mpls_label.push(out_label);
            }
            ilm.nexthop_ifname = n.interface.clone();
            ilm.nexthop = Nexthop::Uni(nhop);
            return Some(ilm);
        }

        let mut multi = NexthopMulti::default();
        for (&addr, n) in self.nexthops.iter() {
            let mut nhop = NexthopUni {
                addr,
                ..Default::default()
            };
            if let Some(out_label) = n.out_label {
                nhop.mpls_label.push(out_label);
            }
            multi.nexthops.push(nhop);
        }
        ilm.nexthop = Nexthop::Multi(multi);
        Some(ilm)
    }
}
