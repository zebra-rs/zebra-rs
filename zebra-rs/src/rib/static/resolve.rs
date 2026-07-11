//! Recursive nexthop resolution for static routes (NHT).
//!
//! A static route configured as `via 10.0.0.1` must forward through the
//! underlay's transport — the SR-MPLS label stack, or the SRv6 H.Encap
//! segment list when the covering route is SRv6-encapsulated (e.g. a
//! BGP-over-SRv6 service route) — not as a plain IP nexthop to the
//! remote address. BGP already solves this via `rib::nht`; static
//! applies the same resolver at FIB-install time.

use std::net::IpAddr;

use ipnet::{Ipv4Net, Ipv6Net};
use isis_packet::srv6::EncapType;
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
    // SRv6 transport inherited from the covering route (a BGP-over-SRv6
    // service route, an SRv6 TI-LFA promoted repair, ...). Mirrors the
    // explicit `route <prefix> segments ...` shape — the nexthop group
    // installs the same seg6 H.Encap — with the H.Encap default applied
    // here the same way `StaticRoute::to_entry` applies it.
    uni.segs = egress.segs.clone();
    uni.encap_type =
        (!egress.segs.is_empty()).then(|| egress.seg_encap.unwrap_or(EncapType::HEncap));
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

    #[test]
    fn static_gateway_inherits_srv6_segs() {
        use std::net::Ipv6Addr;

        // The gateway is covered by a BGP-over-SRv6 service route; the
        // static nexthop must come out shaped like an explicit
        // `segments` route — SID address, inherited segment list, and
        // the H.Encap default.
        let sid: Ipv6Addr = "fcbb:bbbb:3:40::".parse().unwrap();
        let mut e = RibEntry::new(RibType::Bgp);
        e.valid = true;
        e.nexthop = Nexthop::Uni(NexthopUni {
            addr: IpAddr::V6(sid),
            segs: vec![sid],
            encap_type: Some(EncapType::HEncap),
            ifindex_origin: Some(2),
            valid: true,
            ..Default::default()
        });
        let mut table: PrefixMap<Ipv6Net, RibEntries> = PrefixMap::new();
        table.insert("2001:db8:200::/64".parse().unwrap(), vec![e]);

        let gw: IpAddr = "2001:db8:200::1".parse().unwrap();
        let mut uni = NexthopUni {
            addr: gw,
            addr_origin: Some(gw),
            ..Default::default()
        };
        assert!(apply_nht_v6(&mut uni, &table));
        assert_eq!(uni.addr, IpAddr::V6(sid));
        assert_eq!(uni.segs, vec![sid]);
        assert_eq!(uni.encap_type, Some(EncapType::HEncap));
        assert_eq!(uni.ifindex_origin, Some(2));
        assert!(uni.mpls_label.is_empty());
        // The configured gateway is preserved for display.
        assert_eq!(uni.display_addr(), gw);
    }
}
