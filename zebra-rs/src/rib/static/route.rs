// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2025-2026 Kunihiro Ishiguro

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv6Addr};

use isis_packet::srv6::EncapType;

use crate::rib::entry::RibEntry;
use crate::rib::nexthop::{Label, NexthopUni};
use crate::rib::{Nexthop, NexthopList, NexthopMulti, RibType, SidBehavior};

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
    /// SRv6 terminal action (`seg6local`) bound to this prefix —
    /// e.g. End.DT6 for an inner-IPv6 decap-and-lookup. Mutually
    /// exclusive with `segs`/`nexthops`; when set, `to_entry`
    /// produces a Uni nexthop that the FIB installs as a kernel
    /// `seg6local` route on the sr0 dummy.
    pub seg6local_action: Option<SidBehavior>,
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
            seg6local_action: None,
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
            seg6local_action: self.seg6local_action,
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
            .field("seg6local_action", &self.seg6local_action)
            .field("delete", &self.delete)
            .finish()
    }
}

impl<F: StaticFamily> StaticRoute<F> {
    pub fn to_entry(&self) -> Option<RibEntry> {
        if self.nexthops.is_empty() && self.segs.is_empty() && self.seg6local_action.is_none() {
            return None;
        }

        let mut entry = RibEntry::new(RibType::Static);
        entry.distance = self.distance.unwrap_or(1);

        let metric = self.metric.unwrap_or(0);

        if let Some(action) = self.seg6local_action {
            // Terminal seg6local action (End.DT6 etc.). The address
            // doesn't matter for End/uN/EndDT4/EndDT6 — the action
            // doesn't forward, it just decaps + looks up. End.X /
            // uA also need a per-adjacency nh6, which the YANG
            // doesn't model yet; the YANG enum description warns
            // operators away from those for now.
            //
            // ifindex_origin is left None here; the RIB sets it to
            // the sr0 dummy in `Rib::ipv6_route_add` once the
            // request lands on the RIB-side processor (which has
            // access to the link table). Doing it here would need
            // a separate shared-state reference into the static
            // commit pipeline, which isn't worth it for a one-line
            // fill-in.
            let nhop = NexthopUni {
                addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                metric,
                weight: 1,
                seg6local_action: Some(action),
                ..Default::default()
            };
            entry.nexthop = Nexthop::Uni(nhop);
            entry.metric = metric;
            return Some(entry);
        }

        if !self.segs.is_empty() {
            // SRv6 H.Encap (RFC 8986 §5.1): outer destination is the first
            // segment; the SRH carries every configured segment. We default
            // to plain H.Encap so the FIB reflects the operator's exact
            // segment list — `ip -6 route show` will report `segs N [...]`
            // for N configured segments. Operators who want the SRH-reduced
            // form (H.Encap.Red, RFC 8986 §5.2) can opt in via the explicit
            // encap-type leaf.
            let first = self.segs[0];
            let encap_type = self.encap_type.unwrap_or(EncapType::HEncap);
            let nhop = NexthopUni {
                addr: IpAddr::V6(first),
                metric,
                weight: 1,
                segs: self.segs.clone(),
                encap_type: Some(encap_type),
                ..Default::default()
            };
            entry.nexthop = Nexthop::Uni(nhop);
            entry.metric = metric;
            return Some(entry);
        }

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

    fn seg(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    #[test]
    fn srv6_segs_build_uni_with_first_segment_as_addr() {
        let segs = vec![seg("fd00:c::"), seg("fd00:b::"), seg("3001:2003::2")];
        let r = StaticRoute::<V4> {
            segs: segs.clone(),
            encap_type: Some(EncapType::HEncapRed),
            ..Default::default()
        };
        let entry = r.to_entry().expect("entry built");
        let uni = as_uni(&entry);
        assert_eq!(uni.addr, IpAddr::V6(seg("fd00:c::")));
        assert_eq!(uni.segs, segs);
        assert_eq!(uni.encap_type, Some(EncapType::HEncapRed));
    }

    #[test]
    fn srv6_segs_default_to_h_encap_when_unspecified() {
        // Default policy: with no explicit encap-type, install full H.Encap
        // (RFC 8986 §5.1) so every configured segment lands in the SRH and
        // the kernel `ip -6 route show` reflects exactly what the operator
        // configured. H.Encap.Red is opt-in via explicit encap-type.
        let r = StaticRoute::<V4> {
            segs: vec![seg("fd00:c::"), seg("fd00:b::")],
            ..Default::default()
        };
        let entry = r.to_entry().expect("entry built");
        let uni = as_uni(&entry);
        assert_eq!(uni.encap_type, Some(EncapType::HEncap));
    }

    #[test]
    fn srv6_single_segment_default_is_h_encap() {
        let r = StaticRoute::<V4> {
            segs: vec![seg("fd00:c::")],
            ..Default::default()
        };
        let entry = r.to_entry().expect("entry built");
        let uni = as_uni(&entry);
        assert_eq!(uni.encap_type, Some(EncapType::HEncap));
    }

    #[test]
    fn srv6_segs_only_no_nexthops_returns_some() {
        // Pre-Step-1 the absence of nexthops short-circuited to None;
        // segs alone must now be sufficient to produce a RibEntry.
        let r = StaticRoute::<V4> {
            segs: vec![seg("fd00:c::")],
            ..Default::default()
        };
        assert!(r.to_entry().is_some());
    }

    #[test]
    fn srv6_segs_take_priority_over_nexthops() {
        // v1 design: when both segs and nexthops are configured, segs win.
        let mut nexthops = BTreeMap::new();
        nexthops.insert(Ipv4Addr::new(192, 168, 100, 2), nh(vec![], None));
        let r = StaticRoute::<V4> {
            nexthops,
            segs: vec![seg("fd00:c::")],
            ..Default::default()
        };
        let entry = r.to_entry().expect("entry built");
        let uni = as_uni(&entry);
        assert_eq!(uni.addr, IpAddr::V6(seg("fd00:c::")));
        assert!(!uni.segs.is_empty());
    }

    #[test]
    fn seg6local_action_alone_produces_entry() {
        // No nexthops, no segs — just an action. Must still build a
        // RibEntry (the FIB will install a kernel seg6local route).
        let r = StaticRoute::<V4> {
            seg6local_action: Some(SidBehavior::EndDT6),
            ..Default::default()
        };
        let entry = r.to_entry().expect("entry built");
        let uni = as_uni(&entry);
        assert_eq!(uni.seg6local_action, Some(SidBehavior::EndDT6));
        assert_eq!(uni.addr, IpAddr::V6(Ipv6Addr::UNSPECIFIED));
        assert!(uni.segs.is_empty());
        assert_eq!(uni.ifindex_origin, None); // RIB fills sr0 in ipv6_route_add
    }

    #[test]
    fn seg6local_action_takes_priority_over_segs() {
        // If both action and segs are configured, action wins —
        // they're alternative encap models on the same prefix.
        let r = StaticRoute::<V4> {
            seg6local_action: Some(SidBehavior::EndDT6),
            segs: vec![seg("fd00:c::")],
            ..Default::default()
        };
        let entry = r.to_entry().expect("entry built");
        let uni = as_uni(&entry);
        assert_eq!(uni.seg6local_action, Some(SidBehavior::EndDT6));
        assert!(uni.segs.is_empty());
    }
}
