use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::{Ipv4Net, Ipv6Net};
use prefix_trie::PrefixMap;

use super::entry::RibEntry;
use super::nexthop::NexthopUni;
use super::{Nexthop, RibEntries, RibType};

// Default cap on recursive RIB lookups during nexthop resolution. Cycles can
// arise legitimately (a static route via an address that itself resolves
// through another protocol route), and we want to bail before chasing them
// indefinitely. ResolveOpt::limit can override per-call.
const DEFAULT_RESOLVE_DEPTH: u8 = 4;

pub enum Resolve {
    Onlink(u32),
    Recursive(u32),
    NotFound,
}

impl Resolve {
    pub fn is_valid(&self) -> u32 {
        match self {
            Self::Onlink(v) | Self::Recursive(v) => *v,
            Self::NotFound => 0,
        }
    }
}

#[derive(Default)]
pub struct ResolveOpt {
    allow_default: bool,
    /// Maximum recursive lookup depth. 0 means use DEFAULT_RESOLVE_DEPTH.
    limit: u8,
}

impl ResolveOpt {
    // Use default route for recursive lookup.
    pub fn allow_default(&self) -> bool {
        self.allow_default
    }

    fn depth_limit(&self) -> u8 {
        if self.limit == 0 {
            DEFAULT_RESOLVE_DEPTH
        } else {
            self.limit
        }
    }
}

// Pull a usable ifindex out of a RibEntry's nexthop. Connected entries store
// it on the entry itself; protocol entries (IGP / static / BGP) carry it on
// the resolved NexthopUni — IGP routes get this populated by SPF; static
// routes only have it after recursive resolution has stamped it.
fn entry_nexthop_ifindex(entry: &RibEntry) -> Option<u32> {
    if entry.is_connected() {
        if entry.ifindex != 0 {
            return Some(entry.ifindex);
        }
        return None;
    }
    match &entry.nexthop {
        Nexthop::Uni(uni) if uni.ifindex().is_some() => uni.ifindex(),
        Nexthop::Multi(multi) => first_ifindex(&multi.nexthops),
        Nexthop::List(list) => list.iter_unis().find_map(|u| u.ifindex()),
        Nexthop::Protect(pro) => pro.iter_unis().find_map(|u| u.ifindex()),
        _ => None,
    }
}

fn first_ifindex(nexthops: &[NexthopUni]) -> Option<u32> {
    nexthops.iter().find_map(|u| u.ifindex())
}

// Pull the unicast next-hop address out of a RibEntry whose ifindex is not
// yet populated, so we can recurse to find the underlying egress interface.
fn entry_nexthop_addr(entry: &RibEntry) -> Option<IpAddr> {
    match &entry.nexthop {
        Nexthop::Uni(uni) if uni.ifindex().is_none() => Some(uni.addr),
        Nexthop::Multi(multi) => multi
            .nexthops
            .first()
            .filter(|u| u.ifindex().is_none())
            .map(|u| u.addr),
        Nexthop::List(list) => list
            .iter_unis()
            .next()
            .filter(|u| u.ifindex().is_none())
            .map(|u| u.addr),
        Nexthop::Protect(pro) => pro
            .iter_unis()
            .next()
            .filter(|u| u.ifindex().is_none())
            .map(|u| u.addr),
        _ => None,
    }
}

// Whether `entry`'s nexthop carries an MPLS label stack — i.e. it is a BGP
// Labeled-Unicast (SAFI 4) transport route rather than plain BGP unicast.
fn entry_has_mpls(entry: &RibEntry) -> bool {
    match &entry.nexthop {
        Nexthop::Uni(uni) => !uni.mpls.is_empty(),
        Nexthop::Multi(multi) => multi.nexthops.iter().any(|u| !u.mpls.is_empty()),
        _ => false,
    }
}

// Whether an entry is allowed to act as a resolver target during recursive
// nexthop lookup. Connected and IGP routes are always trusted; static is
// trusted up to the depth cap. Plain BGP unicast is excluded — BGP
// next-hops should resolve over the underlay (IGP / connected), not over
// BGP itself, and allowing it would risk recursive loops. The one BGP
// exception is a *labeled* (BGP Labeled-Unicast, SAFI 4) route: Inter-AS
// MPLS/VPN Option C (RFC 4364 §10c) resolves a VPN next-hop — the remote
// PE loopback — over the BGP-LU LSP that carries it across the AS boundary,
// stacking the LU + transport labels under the VPN service label. The
// recursion depth cap still bounds any loop. The validity check skips
// entries that are still in the table but no longer reachable — e.g. an
// IS-IS route whose group went invalid because its egress link is down.
// Without this filter a recursive static would resolve through the dead
// route and look reachable when it isn't.
pub(crate) fn entry_resolvable(entry: &RibEntry) -> bool {
    entry.is_valid()
        && (matches!(
            entry.rtype,
            RibType::Connected | RibType::Static | RibType::Ospf | RibType::Isis
        ) || (entry.rtype == RibType::Bgp && entry_has_mpls(entry)))
}

pub fn rib_resolve(
    table: &PrefixMap<Ipv4Net, RibEntries>,
    p: Ipv4Addr,
    opt: &ResolveOpt,
) -> Resolve {
    rib_resolve_v4_inner(table, p, opt, 0)
}

fn rib_resolve_v4_inner(
    table: &PrefixMap<Ipv4Net, RibEntries>,
    p: Ipv4Addr,
    opt: &ResolveOpt,
    depth: u8,
) -> Resolve {
    if depth >= opt.depth_limit() {
        return Resolve::NotFound;
    }
    let Ok(key) = Ipv4Net::new(p, Ipv4Addr::BITS as u8) else {
        return Resolve::NotFound;
    };
    let Some((prefix, entries)) = table.get_lpm(&key) else {
        return Resolve::NotFound;
    };
    if !opt.allow_default() && prefix.prefix_len() == 0 {
        return Resolve::NotFound;
    }

    for entry in entries.iter() {
        if !entry_resolvable(entry) {
            continue;
        }
        if entry.is_connected() {
            if let Some(ifindex) = entry_nexthop_ifindex(entry) {
                return Resolve::Onlink(ifindex);
            }
            continue;
        }
        if let Some(ifindex) = entry_nexthop_ifindex(entry) {
            return Resolve::Recursive(ifindex);
        }
        if let Some(IpAddr::V4(addr)) = entry_nexthop_addr(entry) {
            let inner = rib_resolve_v4_inner(table, addr, opt, depth + 1);
            if inner.is_valid() != 0 {
                return inner;
            }
        }
    }
    Resolve::NotFound
}

pub fn rib_resolve_v6(
    table: &PrefixMap<Ipv6Net, RibEntries>,
    p: Ipv6Addr,
    opt: &ResolveOpt,
) -> Resolve {
    rib_resolve_v6_inner(table, p, opt, 0)
}

fn rib_resolve_v6_inner(
    table: &PrefixMap<Ipv6Net, RibEntries>,
    p: Ipv6Addr,
    opt: &ResolveOpt,
    depth: u8,
) -> Resolve {
    if depth >= opt.depth_limit() {
        return Resolve::NotFound;
    }
    let Ok(key) = Ipv6Net::new(p, Ipv6Addr::BITS as u8) else {
        return Resolve::NotFound;
    };
    let Some((prefix, entries)) = table.get_lpm(&key) else {
        return Resolve::NotFound;
    };
    if !opt.allow_default() && prefix.prefix_len() == 0 {
        return Resolve::NotFound;
    }

    for entry in entries.iter() {
        if !entry_resolvable(entry) {
            continue;
        }
        if entry.is_connected() {
            if let Some(ifindex) = entry_nexthop_ifindex(entry) {
                return Resolve::Onlink(ifindex);
            }
            continue;
        }
        if let Some(ifindex) = entry_nexthop_ifindex(entry) {
            return Resolve::Recursive(ifindex);
        }
        if let Some(IpAddr::V6(addr)) = entry_nexthop_addr(entry) {
            let inner = rib_resolve_v6_inner(table, addr, opt, depth + 1);
            if inner.is_valid() != 0 {
                return inner;
            }
        }
    }
    Resolve::NotFound
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn connected_v6(ifindex: u32) -> RibEntry {
        let mut e = RibEntry::new(RibType::Connected);
        e.ifindex = ifindex;
        e.set_valid(true);
        e
    }

    fn protocol_v6(rtype: RibType, addr: Ipv6Addr, ifindex: u32) -> RibEntry {
        let mut e = RibEntry::new(rtype);
        e.nexthop = Nexthop::Uni(NexthopUni {
            addr: IpAddr::V6(addr),
            ifindex_origin: Some(ifindex),
            ..Default::default()
        });
        e.set_valid(true);
        e
    }

    fn protocol_v6_unresolved(rtype: RibType, addr: Ipv6Addr) -> RibEntry {
        let mut e = RibEntry::new(rtype);
        e.nexthop = Nexthop::Uni(NexthopUni {
            addr: IpAddr::V6(addr),
            ifindex_origin: None,
            ..Default::default()
        });
        e.set_valid(true);
        e
    }

    #[test]
    fn srv6_first_segment_resolves_through_isis_route() {
        // The original SRv6 nexthop bug: a static route's nexthop (the first
        // SRv6 segment) is covered by an IS-IS-learned aggregate. The
        // resolver must surface the IS-IS route's egress ifindex so the
        // SRv6 install pushes Oif(enp0s5) instead of falling back to lo.
        let mut table = PrefixMap::<Ipv6Net, RibEntries>::new();
        table.insert(
            Ipv6Net::from_str("fcbb:bbbb:2::/48").unwrap(),
            vec![protocol_v6(
                RibType::Isis,
                "fe80::21c:42ff:fee8:c23".parse().unwrap(),
                42,
            )],
        );
        let target: Ipv6Addr = "fcbb:bbbb:2:3:2::".parse().unwrap();
        let resolve = rib_resolve_v6(&table, target, &ResolveOpt::default());
        assert!(matches!(resolve, Resolve::Recursive(42)));
    }

    #[test]
    fn ospf_routes_also_resolve() {
        let mut table = PrefixMap::<Ipv6Net, RibEntries>::new();
        table.insert(
            Ipv6Net::from_str("2001:db8:abcd::/48").unwrap(),
            vec![protocol_v6(RibType::Ospf, "fe80::1".parse().unwrap(), 17)],
        );
        let resolve = rib_resolve_v6(
            &table,
            "2001:db8:abcd:1::1".parse().unwrap(),
            &ResolveOpt::default(),
        );
        assert!(matches!(resolve, Resolve::Recursive(17)));
    }

    #[test]
    fn connected_wins_over_protocol_routes() {
        let mut table = PrefixMap::<Ipv6Net, RibEntries>::new();
        table.insert(
            Ipv6Net::from_str("2001:db8::/64").unwrap(),
            vec![
                connected_v6(7),
                protocol_v6(RibType::Isis, "fe80::1".parse().unwrap(), 42),
            ],
        );
        let resolve = rib_resolve_v6(
            &table,
            "2001:db8::1".parse().unwrap(),
            &ResolveOpt::default(),
        );
        assert!(matches!(resolve, Resolve::Onlink(7)));
    }

    #[test]
    fn bgp_routes_are_skipped() {
        // BGP next-hops should resolve over the underlay, not over BGP itself.
        let mut table = PrefixMap::<Ipv6Net, RibEntries>::new();
        table.insert(
            Ipv6Net::from_str("2001:db8:abcd::/48").unwrap(),
            vec![protocol_v6(RibType::Bgp, "fe80::1".parse().unwrap(), 17)],
        );
        let resolve = rib_resolve_v6(
            &table,
            "2001:db8:abcd::1".parse().unwrap(),
            &ResolveOpt::default(),
        );
        assert!(matches!(resolve, Resolve::NotFound));
    }

    #[test]
    fn unresolved_static_recurses_through_underlying_route() {
        // A static route whose nexthop hasn't yet been resolved (ifindex=0)
        // must walk one more level to find the egress interface via
        // a covering connected/IGP route.
        let mut table = PrefixMap::<Ipv6Net, RibEntries>::new();
        // A static route to 2001:db8:1::/64 via 2001:db8:0:1::1 (no ifindex).
        table.insert(
            Ipv6Net::from_str("2001:db8:1::/64").unwrap(),
            vec![protocol_v6_unresolved(
                RibType::Static,
                "2001:db8:0:1::1".parse().unwrap(),
            )],
        );
        // The static's nexthop is covered by a connected /64.
        table.insert(
            Ipv6Net::from_str("2001:db8:0:1::/64").unwrap(),
            vec![connected_v6(9)],
        );
        let resolve = rib_resolve_v6(
            &table,
            "2001:db8:1::5".parse().unwrap(),
            &ResolveOpt::default(),
        );
        assert!(matches!(resolve, Resolve::Onlink(9)));
    }

    #[test]
    fn no_match_returns_not_found() {
        let table = PrefixMap::<Ipv6Net, RibEntries>::new();
        let resolve = rib_resolve_v6(
            &table,
            "2001:db8::1".parse().unwrap(),
            &ResolveOpt::default(),
        );
        assert!(matches!(resolve, Resolve::NotFound));
    }

    #[test]
    fn default_route_skipped_unless_allowed() {
        let mut table = PrefixMap::<Ipv6Net, RibEntries>::new();
        table.insert(Ipv6Net::default(), vec![connected_v6(11)]);
        let target: Ipv6Addr = "2001:db8::1".parse().unwrap();

        // Default opt: ::/0 must not resolve.
        let resolve = rib_resolve_v6(&table, target, &ResolveOpt::default());
        assert!(matches!(resolve, Resolve::NotFound));

        // Allowed: ::/0 resolves.
        let opt = ResolveOpt {
            allow_default: true,
            limit: 0,
        };
        let resolve = rib_resolve_v6(&table, target, &opt);
        assert!(matches!(resolve, Resolve::Onlink(11)));
    }
}
