// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2025-2026 Kunihiro Ishiguro

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv6Addr};

use Group::*;
use ipnet::{Ipv4Net, Ipv6Net};
use isis_packet::srv6::EncapType;
use prefix_trie::PrefixMap;

use crate::rib::entry::RibEntries;
use crate::rib::resolve::{Resolve, ResolveOpt, rib_resolve, rib_resolve_v6};

use super::NexthopUni;

// Flip to true to re-enable IPv6 nexthop resolution diagnostic prints.
const DEBUG_V6: bool = false;

#[derive(Debug)]
pub enum Group {
    Uni(GroupUni),
    Multi(GroupMulti),
}

#[derive(Default, Debug, Clone)]
pub struct GroupCommon {
    gid: usize,
    valid: bool,
    installed: bool,
    refcnt: usize,
}

impl GroupCommon {
    pub fn new(gid: usize) -> Self {
        Self {
            gid,
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone)]
pub struct GroupUni {
    common: GroupCommon,
    pub addr: IpAddr,
    pub ifindex: u32,
    pub labels: Vec<u32>,

    /// SRv6 H.Encap segment list (RFC 8986). Non-empty indicates this is an
    /// SRv6-encapsulated nexthop and `addr` is the outer destination (= the
    /// first segment). NexthopMap dedupes SRv6 nexthops by (addr, segs,
    /// encap_type) so multiple routes with the same SRv6 policy share one
    /// kernel nexthop-table entry.
    pub segs: Vec<Ipv6Addr>,

    /// SRv6 endpoint behavior chosen for this encap (e.g. H.Encap,
    /// H.Encap.Red). None when segs is empty (non-SRv6 nexthop).
    pub encap_type: Option<EncapType>,

    /// SRv6 seg6local action — set when this group represents a local
    /// SID install (End / End.X). NexthopMap keys these separately from
    /// plain unicast / encap nexthops via `fetch_seg6local`.
    pub seg6local_action: Option<crate::rib::SidBehavior>,
}

impl GroupUni {
    pub fn new(gid: usize, uni: &NexthopUni) -> Self {
        // For seg6local nexthops the ifindex is pre-determined by the
        // caller (loopback for End, the link's ifindex for End.X) and
        // there's no IGP path to resolve through; for plain unicast we
        // start at 0 and let `resolve`/`resolve_v6` fill it in.
        let ifindex = if uni.seg6local_action.is_some() {
            uni.ifindex
        } else {
            0
        };
        Self {
            common: GroupCommon::new(gid),
            addr: uni.addr,
            ifindex,
            labels: uni.mpls_label.clone(),
            segs: uni.segs.clone(),
            encap_type: uni.encap_type,
            seg6local_action: uni.seg6local_action,
        }
    }

    pub fn resolve(&mut self, table: &PrefixMap<Ipv4Net, RibEntries>) {
        match self.addr {
            IpAddr::V4(ipv4_addr) => {
                let resolve = rib_resolve(table, ipv4_addr, &ResolveOpt::default());
                // Both arms carry a real egress ifindex — Onlink came from a
                // directly-connected route, Recursive from walking through an
                // IGP/static covering route. The Group only needs the ifindex,
                // not the path category.
                if let Resolve::Onlink(ifindex) | Resolve::Recursive(ifindex) = resolve {
                    self.ifindex = ifindex;
                    self.set_valid(true);
                }
            }
            IpAddr::V6(_) => {
                // IPv6 nexthops resolve against the v6 table via resolve_v6.
            }
        }
    }

    pub fn resolve_v6(&mut self, table: &PrefixMap<Ipv6Net, RibEntries>) {
        if let IpAddr::V6(ipv6_addr) = self.addr {
            let resolve = rib_resolve_v6(table, ipv6_addr, &ResolveOpt::default());
            match &resolve {
                // Onlink came from a directly-connected route; Recursive came
                // from walking through an IGP/static covering route. Both
                // produce a real egress ifindex; the Group cares about that,
                // not the path category.
                Resolve::Onlink(ifindex) | Resolve::Recursive(ifindex) => {
                    if DEBUG_V6 {
                        println!(
                            "[GroupUni::resolve_v6] {} -> ifindex={}",
                            ipv6_addr, ifindex
                        );
                    }
                    self.ifindex = *ifindex;
                    self.set_valid(true);
                }
                Resolve::NotFound => {
                    if DEBUG_V6 {
                        println!("[GroupUni::resolve_v6] {} -> NotFound", ipv6_addr);
                    }
                }
            }
        }
    }

    pub fn set_ifindex(&mut self, ifindex: u32) {
        self.ifindex = ifindex
    }
}

impl GroupTrait for GroupUni {
    fn common(&self) -> &GroupCommon {
        &self.common
    }

    fn common_mut(&mut self) -> &mut GroupCommon {
        &mut self.common
    }
}

#[derive(Debug, Clone)]
pub struct GroupMulti {
    common: GroupCommon,
    pub set: BTreeSet<(usize, u8)>,
    pub valid: BTreeSet<(usize, u8)>,
}

impl GroupMulti {
    pub fn new(gid: usize) -> Self {
        Self {
            common: GroupCommon::new(gid),
            set: BTreeSet::new(),
            valid: BTreeSet::new(),
        }
    }
}

impl GroupTrait for GroupMulti {
    fn common(&self) -> &GroupCommon {
        &self.common
    }

    fn common_mut(&mut self) -> &mut GroupCommon {
        &mut self.common
    }
}

pub trait GroupTrait {
    fn common(&self) -> &GroupCommon;

    fn common_mut(&mut self) -> &mut GroupCommon;

    fn gid(&self) -> usize {
        self.common().gid
    }

    fn is_valid(&self) -> bool {
        self.common().valid
    }

    fn set_valid(&mut self, valid: bool) {
        self.common_mut().valid = valid;
    }

    fn is_installed(&self) -> bool {
        self.common().installed
    }

    fn set_installed(&mut self, installed: bool) {
        self.common_mut().installed = installed;
    }

    fn refcnt(&self) -> usize {
        self.common().refcnt
    }

    fn refcnt_mut(&mut self) -> &mut usize {
        &mut self.common_mut().refcnt
    }

    fn refcnt_inc(&mut self) {
        let refcnt = self.refcnt_mut();
        *refcnt += 1;
    }

    fn refcnt_dec(&mut self) {
        let refcnt = self.refcnt_mut();
        if *refcnt > 0 {
            *refcnt -= 1;
        }
    }
}

impl GroupTrait for Group {
    fn common(&self) -> &GroupCommon {
        match self {
            Uni(uni) => &uni.common,
            Multi(multi) => &multi.common,
        }
    }

    fn common_mut(&mut self) -> &mut GroupCommon {
        match self {
            Uni(uni) => &mut uni.common,
            Multi(multi) => &mut multi.common,
        }
    }

    fn refcnt(&self) -> usize {
        match self {
            Group::Uni(uni) => uni.refcnt(),
            Group::Multi(multi) => multi.refcnt(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rib::Nexthop;
    use crate::rib::entry::RibEntry;
    use crate::rib::types::RibType;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    fn group_uni_at(addr: IpAddr) -> GroupUni {
        let uni = NexthopUni {
            addr,
            ..Default::default()
        };
        GroupUni::new(0, &uni)
    }

    fn connected_v6(ifindex: u32) -> RibEntry {
        let mut e = RibEntry::new(RibType::Connected);
        e.ifindex = ifindex;
        e
    }

    fn isis_v6(addr: Ipv6Addr, ifindex: u32) -> RibEntry {
        let mut e = RibEntry::new(RibType::Isis);
        e.nexthop = Nexthop::Uni(NexthopUni {
            addr: IpAddr::V6(addr),
            ifindex,
            ..Default::default()
        });
        e
    }

    fn connected_v4(ifindex: u32) -> RibEntry {
        let mut e = RibEntry::new(RibType::Connected);
        e.ifindex = ifindex;
        e
    }

    fn isis_v4(addr: Ipv4Addr, ifindex: u32) -> RibEntry {
        let mut e = RibEntry::new(RibType::Isis);
        e.nexthop = Nexthop::Uni(NexthopUni {
            addr: IpAddr::V4(addr),
            ifindex,
            ..Default::default()
        });
        e
    }

    #[test]
    fn resolve_v6_through_isis_recursive_sets_ifindex() {
        // The SRv6 first-segment scenario: GroupUni's address is covered by an
        // IS-IS-learned aggregate. rib_resolve_v6 returns Resolve::Recursive
        // carrying the IS-IS route's ifindex; the Group must adopt it.
        let mut table = PrefixMap::<Ipv6Net, RibEntries>::new();
        table.insert(
            Ipv6Net::from_str("fcbb:bbbb:2::/48").unwrap(),
            vec![isis_v6("fe80::21c:42ff:fee8:c23".parse().unwrap(), 42)],
        );

        let mut group = group_uni_at(IpAddr::V6("fcbb:bbbb:2:3:2::".parse().unwrap()));
        assert_eq!(group.ifindex, 0);
        assert!(!group.is_valid());

        group.resolve_v6(&table);

        assert_eq!(group.ifindex, 42);
        assert!(group.is_valid());
    }

    #[test]
    fn resolve_v6_onlink_sets_ifindex() {
        let mut table = PrefixMap::<Ipv6Net, RibEntries>::new();
        table.insert(
            Ipv6Net::from_str("2001:db8::/64").unwrap(),
            vec![connected_v6(7)],
        );

        let mut group = group_uni_at(IpAddr::V6("2001:db8::1".parse().unwrap()));
        group.resolve_v6(&table);

        assert_eq!(group.ifindex, 7);
        assert!(group.is_valid());
    }

    #[test]
    fn resolve_v6_not_found_leaves_group_invalid() {
        let table = PrefixMap::<Ipv6Net, RibEntries>::new();
        let mut group = group_uni_at(IpAddr::V6("2001:db8::1".parse().unwrap()));
        group.resolve_v6(&table);
        assert_eq!(group.ifindex, 0);
        assert!(!group.is_valid());
    }

    #[test]
    fn resolve_v6_with_v4_addr_is_noop() {
        // resolve_v6 is supposed to skip groups whose addr is IPv4. Even with
        // a bogus matching entry in the v6 table, the v4-addressed Group
        // should not get its ifindex updated.
        let mut table = PrefixMap::<Ipv6Net, RibEntries>::new();
        table.insert(Ipv6Net::default(), vec![connected_v6(99)]);

        let mut group = group_uni_at(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        group.resolve_v6(&table);

        assert_eq!(group.ifindex, 0);
        assert!(!group.is_valid());
    }

    #[test]
    fn resolve_v4_through_isis_recursive_sets_ifindex() {
        let mut table = PrefixMap::<Ipv4Net, RibEntries>::new();
        table.insert(
            Ipv4Net::from_str("10.0.0.0/8").unwrap(),
            vec![isis_v4(Ipv4Addr::new(192, 0, 2, 1), 17)],
        );

        let mut group = group_uni_at(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)));
        group.resolve(&table);

        assert_eq!(group.ifindex, 17);
        assert!(group.is_valid());
    }

    #[test]
    fn resolve_v4_onlink_sets_ifindex() {
        let mut table = PrefixMap::<Ipv4Net, RibEntries>::new();
        table.insert(
            Ipv4Net::from_str("192.168.0.0/24").unwrap(),
            vec![connected_v4(5)],
        );

        let mut group = group_uni_at(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 10)));
        group.resolve(&table);

        assert_eq!(group.ifindex, 5);
        assert!(group.is_valid());
    }

    #[test]
    fn resolve_v4_with_v6_addr_is_noop() {
        let mut table = PrefixMap::<Ipv4Net, RibEntries>::new();
        table.insert(Ipv4Net::default(), vec![connected_v4(99)]);

        let mut group = group_uni_at(IpAddr::V6("2001:db8::1".parse().unwrap()));
        group.resolve(&table);

        assert_eq!(group.ifindex, 0);
        assert!(!group.is_valid());
    }

    #[test]
    fn group_uni_carries_segs_and_encap_type_through_new() {
        // Construct a NexthopUni with SRv6 fields populated and verify
        // GroupUni::new copies them — required so NexthopMap can later
        // dedupe SRv6 nexthops by (addr, segs, encap_type).
        let segs = vec![
            "fcbb:bbbb:2:3:2::".parse().unwrap(),
            "fcbb:bbbb:2:3:3::".parse().unwrap(),
        ];
        let uni = NexthopUni {
            addr: IpAddr::V6("fcbb:bbbb:2:3:2::".parse().unwrap()),
            segs: segs.clone(),
            encap_type: Some(EncapType::HEncap),
            ..Default::default()
        };
        let group = GroupUni::new(7, &uni);
        assert_eq!(group.segs, segs);
        assert_eq!(group.encap_type, Some(EncapType::HEncap));
    }

    #[test]
    fn group_uni_no_segs_when_nexthop_uni_is_plain() {
        // Non-SRv6 NexthopUni produces a GroupUni with empty segs and
        // None encap_type — the dedupe key for plain nexthops stays
        // unaffected by the SRv6 fields.
        let uni = NexthopUni {
            addr: IpAddr::V6("2001:db8::1".parse().unwrap()),
            ..Default::default()
        };
        let group = GroupUni::new(3, &uni);
        assert!(group.segs.is_empty());
        assert_eq!(group.encap_type, None);
    }
}
