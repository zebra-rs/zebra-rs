use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use crate::rib::entry::RibEntry;
use crate::rib::nexthop::NexthopUni;
use crate::rib::{Nexthop, NexthopList, NexthopMulti, RibType};

#[derive(Debug, Default, Clone)]
pub struct StaticNexthop {
    pub metric: Option<u32>,
    pub weight: Option<u8>,
}

#[derive(Debug, Default, Clone)]
pub struct StaticRoute {
    pub distance: Option<u8>,
    pub metric: Option<u32>,
    pub nexthops: BTreeMap<Ipv4Addr, StaticNexthop>,
    pub delete: bool,
}

impl StaticRoute {
    pub fn to_entry(&self) -> Option<RibEntry> {
        if self.nexthops.is_empty() {
            return None;
        }

        let mut entry = RibEntry::new(RibType::Static);
        entry.distance = self.distance.unwrap_or(1);

        let metric = self.metric.unwrap_or(0);

        if self.nexthops.len() == 1 {
            let (p, n) = self.nexthops.iter().next()?;
            let nhop = NexthopUni {
                addr: std::net::IpAddr::V4(*p),
                metric: n.metric.unwrap_or(metric),
                weight: n.weight.unwrap_or(1),
                ..Default::default()
            };
            entry.nexthop = Nexthop::Uni(nhop);
            entry.metric = metric;
            return Some(entry);
        }

        let mut map: BTreeMap<u32, Vec<(Ipv4Addr, StaticNexthop)>> = BTreeMap::new();
        for (p, n) in self.nexthops.clone().iter() {
            let metric = n.metric.unwrap_or(metric);
            let e = map.entry(metric).or_default();
            e.push((*p, n.clone()));
        }

        // ECMP/UCMP case.
        if map.len() == 1 {
            let (metric, set) = map.pop_first()?;
            entry.metric = metric;
            let mut multi = NexthopMulti {
                metric,
                ..Default::default()
            };
            for (p, n) in set.iter() {
                let nhop = NexthopUni {
                    addr: std::net::IpAddr::V4(*p),
                    metric: n.metric.unwrap_or(metric),
                    weight: n.weight.unwrap_or(1),
                    ..Default::default()
                };
                multi.nexthops.push(nhop);
            }
            entry.nexthop = Nexthop::Multi(multi);
        } else {
            let mut pro = NexthopList::default();
            for (index, (metric, set)) in map.iter_mut().enumerate() {
                if index == 0 {
                    entry.metric = *metric;
                }
                let (p, n) = set.first()?;
                let nhop = NexthopUni {
                    addr: std::net::IpAddr::V4(*p),
                    metric: *metric,
                    weight: n.weight.unwrap_or(1),
                    ..Default::default()
                };
                pro.nexthops.push(nhop);
            }
            entry.nexthop = Nexthop::List(pro);
        }
        Some(entry)
    }
}
