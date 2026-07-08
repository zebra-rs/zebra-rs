//! Recursive nexthop resolution for static routes (NHT).
//!
//! A static route configured as `via 10.0.0.1` must forward through the
//! underlay's SR-MPLS transport label stack, not as a plain IP nexthop to
//! the remote loopback. BGP already solves this via `rib::nht`; static
//! applies the same resolver at FIB-install time.

use std::net::IpAddr;

use ipnet::{Ipv4Net, Ipv6Net};
use prefix_trie::PrefixMap;

use crate::rib::entry::RibEntries;
use crate::rib::nexthop::group::GroupTrait;
use crate::rib::nexthop::{Label, NexthopMap, NexthopUni};
use crate::rib::nht::{self, ResolvedNexthop};

/// Drop a static route's prior nexthop-group membership before re-fetching
/// after an underlay change.
pub fn release_nexthop_gid(uni: &mut NexthopUni, nmap: &mut NexthopMap) {
    if uni.gid == 0 {
        return;
    }
    if let Some(group) = nmap.get_mut(uni.gid) {
        group.refcnt_dec();
    }
    uni.gid = 0;
}

/// Resolve a static gateway against the IPv4 RIB, stamping `addr`,
/// `mpls_label`, and `ifindex_origin` from the underlay path.
pub fn apply_nht_v4(uni: &mut NexthopUni, table: &PrefixMap<Ipv4Net, RibEntries>) -> bool {
    let gateway = match uni.addr_origin {
        Some(IpAddr::V4(g)) => g,
        _ => return false,
    };
    let resolution = nht::resolve_v4(table, gateway);
    if !resolution.reachable {
        return false;
    }
    apply_resolved(uni, &resolution.nexthops)
}

/// IPv6 sibling of [`apply_nht_v4`].
pub fn apply_nht_v6(uni: &mut NexthopUni, table: &PrefixMap<Ipv6Net, RibEntries>) -> bool {
    let gateway = match uni.addr_origin {
        Some(IpAddr::V6(g)) => g,
        _ => return false,
    };
    let resolution = nht::resolve_v6(table, gateway);
    if !resolution.reachable {
        return false;
    }
    apply_resolved(uni, &resolution.nexthops)
}

fn apply_resolved(uni: &mut NexthopUni, egresses: &[ResolvedNexthop]) -> bool {
    let Some(egress) = egresses.first() else {
        return false;
    };
    uni.addr = egress.addr;
    uni.mpls_label = egress.labels.clone();
    uni.mpls = egress.labels.iter().copied().map(Label::Explicit).collect();
    uni.ifindex_origin = (egress.ifindex != 0).then_some(egress.ifindex);
    uni.ifindex_resolved = None;
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    use crate::rib::entry::RibEntry;
    use crate::rib::nexthop::{Nexthop, NexthopUni};
    use crate::rib::types::RibType;

    fn isis_mpls_via(addr: Ipv4Addr, label: u32, ifindex: u32) -> RibEntry {
        let mut e = RibEntry::new(RibType::Isis);
        e.valid = true;
        e.nexthop = Nexthop::Uni(NexthopUni {
            addr: IpAddr::V4(addr),
            ifindex_origin: Some(ifindex),
            mpls_label: vec![label],
            mpls: vec![Label::Explicit(label)],
            valid: true,
            ..Default::default()
        });
        e
    }

    #[test]
    fn static_gateway_inherits_mpls_transport() {
        let mut table: PrefixMap<Ipv4Net, RibEntries> = PrefixMap::new();
        table.insert(
            "10.0.0.1/32".parse().unwrap(),
            vec![isis_mpls_via("192.168.2.1".parse().unwrap(), 16100, 11)],
        );

        let mut uni = NexthopUni {
            addr: "10.0.0.1".parse::<IpAddr>().unwrap(),
            addr_origin: Some("10.0.0.1".parse::<IpAddr>().unwrap()),
            ..Default::default()
        };
        assert!(apply_nht_v4(&mut uni, &table));
        assert_eq!(uni.addr, "192.168.2.1".parse::<IpAddr>().unwrap());
        assert_eq!(uni.mpls_label, vec![16100]);
        assert_eq!(uni.ifindex_origin, Some(11));
        assert_eq!(uni.display_addr(), "10.0.0.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn static_gateway_unreachable_marks_invalid() {
        let table: PrefixMap<Ipv4Net, RibEntries> = PrefixMap::new();
        let mut uni = NexthopUni {
            addr: "10.0.0.1".parse::<IpAddr>().unwrap(),
            addr_origin: Some("10.0.0.1".parse::<IpAddr>().unwrap()),
            ..Default::default()
        };
        assert!(!apply_nht_v4(&mut uni, &table));
    }
}
