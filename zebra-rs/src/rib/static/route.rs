// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2025-2026 Kunihiro Ishiguro

use std::collections::BTreeMap;
use std::net::Ipv6Addr;

use isis_packet::srv6::EncapType;

use crate::rib::entry::RibEntry;
use crate::rib::nexthop::{Label, NexthopUni};
use crate::rib::{Nexthop, NexthopList, NexthopMulti, RibType};

use super::config::StaticFamily;

#[derive(Debug, Default, Clone)]
pub struct StaticNexthop {
    pub metric: Option<u32>,
    pub weight: Option<u8>,
    pub labels: Vec<u32>,
}

pub struct StaticRoute<F: StaticFamily> {
    pub distance: Option<u8>,
    pub metric: Option<u32>,
    pub nexthops: BTreeMap<F::Addr, StaticNexthop>,
    pub segs: Vec<Ipv6Addr>,
    pub encap_type: Option<EncapType>,
    pub delete: bool,
}

impl<F: StaticFamily> Default for StaticRoute<F> {
    fn default() -> Self {
        Self {
            distance: None,
            metric: None,
            nexthops: BTreeMap::new(),
            segs: Vec::new(),
            encap_type: None,
            delete: false,
        }
    }
}

impl<F: StaticFamily> Clone for StaticRoute<F> {
    fn clone(&self) -> Self {
        Self {
            distance: self.distance,
            metric: self.metric,
            nexthops: self.nexthops.clone(),
            segs: self.segs.clone(),
            encap_type: self.encap_type,
            delete: self.delete,
        }
    }
}

impl<F: StaticFamily> std::fmt::Debug for StaticRoute<F>
where
    F::Addr: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StaticRoute")
            .field("distance", &self.distance)
            .field("metric", &self.metric)
            .field("nexthops", &self.nexthops)
            .field("segs", &self.segs)
            .field("encap_type", &self.encap_type)
            .field("delete", &self.delete)
            .finish()
    }
}

impl<F: StaticFamily> StaticRoute<F> {
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
                addr: F::to_ip_addr(*p),
                metric: n.metric.unwrap_or(metric),
                weight: n.weight.unwrap_or(1),
                mpls: n.labels.iter().map(|&l| Label::Explicit(l)).collect(),
                mpls_label: n.labels.clone(),
                ..Default::default()
            };
            entry.nexthop = Nexthop::Uni(nhop);
            entry.metric = metric;
            return Some(entry);
        }

        let mut map: BTreeMap<u32, Vec<(F::Addr, StaticNexthop)>> = BTreeMap::new();
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
                    addr: F::to_ip_addr(*p),
                    metric: n.metric.unwrap_or(metric),
                    weight: n.weight.unwrap_or(1),
                    mpls: n.labels.iter().map(|&l| Label::Explicit(l)).collect(),
                    mpls_label: n.labels.clone(),
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
                    addr: F::to_ip_addr(*p),
                    metric: *metric,
                    weight: n.weight.unwrap_or(1),
                    mpls: n.labels.iter().map(|&l| Label::Explicit(l)).collect(),
                    mpls_label: n.labels.clone(),
                    ..Default::default()
                };
                pro.nexthops.push(nhop);
            }
            entry.nexthop = Nexthop::List(pro);
        }
        Some(entry)
    }
}

#[cfg(test)]
mod tests {
    use super::super::config::V4;
    use super::*;
    use std::net::Ipv4Addr;

    fn nh(labels: Vec<u32>, metric: Option<u32>) -> StaticNexthop {
        StaticNexthop {
            metric,
            weight: None,
            labels,
        }
    }

    fn as_uni(entry: &RibEntry) -> &crate::rib::nexthop::NexthopUni {
        match &entry.nexthop {
            Nexthop::Uni(u) => u,
            _ => panic!("expected Nexthop::Uni"),
        }
    }

    fn as_multi(entry: &RibEntry) -> &crate::rib::NexthopMulti {
        match &entry.nexthop {
            Nexthop::Multi(m) => m,
            _ => panic!("expected Nexthop::Multi"),
        }
    }

    #[test]
    fn single_nexthop_with_labels() {
        let mut r = StaticRoute::<V4>::default();
        r.nexthops.insert(
            Ipv4Addr::new(192, 168, 100, 2),
            nh(vec![16200, 16300], None),
        );
        let entry = r.to_entry().expect("entry built");
        let uni = as_uni(&entry);
        assert_eq!(uni.mpls_label, vec![16200, 16300]);
        assert_eq!(
            uni.mpls,
            vec![Label::Explicit(16200), Label::Explicit(16300)]
        );
    }

    #[test]
    fn ecmp_distinct_stacks_per_leg() {
        let mut r = StaticRoute::<V4>::default();
        r.nexthops
            .insert(Ipv4Addr::new(192, 168, 100, 2), nh(vec![100, 200], None));
        r.nexthops
            .insert(Ipv4Addr::new(192, 168, 100, 3), nh(vec![300], None));
        let entry = r.to_entry().expect("entry built");
        let multi = as_multi(&entry);
        assert_eq!(multi.nexthops.len(), 2);
        let leg_a = multi
            .nexthops
            .iter()
            .find(|u| u.addr == std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 100, 2)))
            .expect("leg A");
        let leg_b = multi
            .nexthops
            .iter()
            .find(|u| u.addr == std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 100, 3)))
            .expect("leg B");
        assert_eq!(leg_a.mpls_label, vec![100, 200]);
        assert_eq!(leg_b.mpls_label, vec![300]);
    }

    #[test]
    fn ecmp_one_leg_labeled_one_bare() {
        let mut r = StaticRoute::<V4>::default();
        r.nexthops
            .insert(Ipv4Addr::new(192, 168, 100, 2), nh(vec![100], None));
        r.nexthops
            .insert(Ipv4Addr::new(192, 168, 100, 3), nh(vec![], None));
        let entry = r.to_entry().expect("entry built");
        let multi = as_multi(&entry);
        let labeled = multi
            .nexthops
            .iter()
            .find(|u| u.addr == std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 100, 2)))
            .expect("labeled leg");
        let bare = multi
            .nexthops
            .iter()
            .find(|u| u.addr == std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 100, 3)))
            .expect("bare leg");
        assert_eq!(labeled.mpls_label, vec![100]);
        assert!(bare.mpls_label.is_empty());
        assert!(bare.mpls.is_empty());
    }
}
