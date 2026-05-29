//! BGP-side Next-Hop Tracking cache.
//!
//! Deduplicates per-nexthop registrations against the RIB NHT service
//! ([`crate::rib::nht`]): one registration per distinct BGP next-hop,
//! with the set of dependent routes recorded so a `RibRx::NexthopUpdate`
//! can re-evaluate exactly the affected prefixes. The cached
//! `reachable` flag feeds the best-path gate via `BgpRib.nexthop_reachable`.
//!
//! Scope: the global `Bgp` instance (it owns the `rib_rx` stream);
//! per-VRF tasks pass `None` and don't gate (their CE next-hops resolve
//! directly in the VRF). Cache cleanup on route withdrawal (untrack) is
//! a follow-up — registrations persist for the life of the process,
//! bounded by the number of distinct next-hops seen.

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;

use bgp_packet::{BgpAttr, BgpNexthop, RouteDistinguisher};
use ipnet::{Ipv4Net, Ipv6Net};

/// A route that depends on a tracked next-hop — enough to locate its
/// candidates and re-run best-path on a resolution change.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum NhtDep {
    V4(Ipv4Net),
    V6(Ipv6Net),
    V4vpn(RouteDistinguisher, Ipv4Net),
    V6vpn(RouteDistinguisher, Ipv6Net),
}

#[derive(Debug, Default)]
pub struct NhtCacheEntry {
    pub reachable: bool,
    pub deps: BTreeSet<NhtDep>,
}

/// Per-instance BGP next-hop cache.
#[derive(Debug, Default)]
pub struct NexthopCache {
    pub entries: HashMap<IpAddr, NhtCacheEntry>,
}

impl NexthopCache {
    /// Record that `dep` uses `nh`. Returns `(needs_register,
    /// reachable_now)`: `needs_register` is true on the first sighting
    /// of `nh` (the caller registers it with the RIB), and
    /// `reachable_now` is the current cached reachability (`false`
    /// while a fresh registration is pending — register-then-gate).
    pub fn track(&mut self, nh: IpAddr, dep: NhtDep) -> (bool, bool) {
        use std::collections::hash_map::Entry;
        match self.entries.entry(nh) {
            Entry::Occupied(mut e) => {
                e.get_mut().deps.insert(dep);
                (false, e.get().reachable)
            }
            Entry::Vacant(v) => {
                let mut deps = BTreeSet::new();
                deps.insert(dep);
                v.insert(NhtCacheEntry {
                    reachable: false,
                    deps,
                });
                (true, false)
            }
        }
    }

    /// Apply a resolution update. Returns the dependent routes to
    /// re-evaluate — empty when `nh` isn't tracked or its reachability
    /// is unchanged (so a no-op update costs nothing downstream).
    pub fn update(&mut self, nh: IpAddr, reachable: bool) -> Vec<NhtDep> {
        match self.entries.get_mut(&nh) {
            Some(e) if e.reachable != reachable => {
                e.reachable = reachable;
                e.deps.iter().cloned().collect()
            }
            _ => Vec::new(),
        }
    }
}

/// The IPv4/IPv6 address of a BGP attribute's next-hop, for tracking.
/// `None` when the attribute carries no next-hop.
pub fn bgp_nexthop_ip(attr: &BgpAttr) -> Option<IpAddr> {
    match attr.nexthop.as_ref()? {
        BgpNexthop::Ipv4(a) => Some(IpAddr::V4(*a)),
        BgpNexthop::Ipv6(a) => Some(IpAddr::V6(*a)),
        BgpNexthop::Vpnv4(v) => Some(IpAddr::V4(v.nhop)),
        BgpNexthop::Vpnv6(v) => Some(IpAddr::V6(v.nhop)),
        BgpNexthop::Evpn(ip) => Some(*ip),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn track_dedups_and_reports_register_on_first_sight() {
        let mut c = NexthopCache::default();
        let nh: IpAddr = "10.0.0.8".parse().unwrap();
        let p1: Ipv4Net = "1.0.0.0/24".parse().unwrap();
        let p2: Ipv4Net = "2.0.0.0/24".parse().unwrap();

        // First sighting → register, pending-unreachable.
        assert_eq!(c.track(nh, NhtDep::V4(p1)), (true, false));
        // Second route, same nexthop → no re-register, still pending.
        assert_eq!(c.track(nh, NhtDep::V4(p2)), (false, false));
    }

    #[test]
    fn update_returns_deps_only_on_change() {
        let mut c = NexthopCache::default();
        let nh: IpAddr = "10.0.0.8".parse().unwrap();
        let p1: Ipv4Net = "1.0.0.0/24".parse().unwrap();
        c.track(nh, NhtDep::V4(p1));

        // pending(false) -> reachable(true): change, deps returned.
        let deps = c.update(nh, true);
        assert_eq!(deps, vec![NhtDep::V4(p1)]);
        // same value again: no change, no deps.
        assert!(c.update(nh, true).is_empty());
        // unknown nexthop: no deps.
        assert!(c.update("9.9.9.9".parse().unwrap(), false).is_empty());
    }
}
