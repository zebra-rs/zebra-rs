use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use netlink_packet_route::route::MplsLabel;

use crate::rib::entry::RibEntry;
use crate::rib::inst::IlmEntry;
use crate::rib::nexthop::NexthopUni;
use crate::rib::{Nexthop, NexthopList, NexthopMulti, RibType};

#[derive(Debug, Default, Clone)]
pub struct MplsNexthop {
    pub out_label: Option<u32>,
}

#[derive(Debug, Default, Clone)]
pub struct MplsRoute {
    pub nexthops: BTreeMap<Ipv4Addr, MplsNexthop>,
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
                addr: std::net::IpAddr::V4(addr),
                ..Default::default()
            };
            if let Some(out_label) = n.out_label {
                nhop.mpls_label.push(out_label);
            }
            ilm.nexthop = Nexthop::Uni(nhop);
            return Some(ilm);
        }

        let mut multi = NexthopMulti::default();
        for (&addr, n) in self.nexthops.iter() {
            let mut nhop = NexthopUni {
                addr: std::net::IpAddr::V4(addr),
                ..Default::default()
            };
            if let Some(out_label) = n.out_label {
                nhop.mpls_label.push(out_label);
            }
            multi.nexthops.push(nhop);
        }
        ilm.nexthop = Nexthop::Multi(multi);
        return Some(ilm);
    }
}
