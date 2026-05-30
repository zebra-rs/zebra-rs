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

use crate::rib::nht::{NexthopResolution, ResolvedNexthop};

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
    /// Resolved transport egress(es) for this next-hop, from the last
    /// `RibRx::NexthopUpdate`. Consumed by the VPN dataplane install to
    /// build the `{service-label, transport-labels}` stack. Empty while
    /// a registration is pending or the next-hop is unreachable.
    pub nexthops: Vec<ResolvedNexthop>,
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
                    nexthops: Vec::new(),
                    deps,
                });
                (true, false)
            }
        }
    }

    /// Apply a resolution update. Always refreshes the stored resolved
    /// transport (`nexthops`) so a later re-eval installs against
    /// current data. Returns the dependent routes to re-evaluate — only
    /// on a reachability flip; a transport-only change (still reachable)
    /// refreshes the cache but doesn't itself trigger re-eval (matching
    /// the gate's reachability semantics; transport-reroute re-install
    /// is a deferred refinement).
    pub fn update(&mut self, nh: IpAddr, resolution: &NexthopResolution) -> Vec<NhtDep> {
        match self.entries.get_mut(&nh) {
            Some(e) => {
                let flipped = e.reachable != resolution.reachable;
                e.reachable = resolution.reachable;
                e.nexthops = resolution.nexthops.clone();
                if flipped {
                    e.deps.iter().cloned().collect()
                } else {
                    Vec::new()
                }
            }
            None => Vec::new(),
        }
    }

    /// The resolved transport egress(es) for `nh` — what the VPN
    /// dataplane install pushes the service label over. Empty slice
    /// when `nh` isn't tracked or hasn't resolved yet.
    pub fn transport_for(&self, nh: IpAddr) -> &[ResolvedNexthop] {
        self.entries
            .get(&nh)
            .map(|e| e.nexthops.as_slice())
            .unwrap_or(&[])
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

    fn reachable(labels: Vec<u32>) -> NexthopResolution {
        NexthopResolution {
            reachable: true,
            metric: 10,
            nexthops: vec![ResolvedNexthop {
                addr: "172.16.0.2".parse().unwrap(),
                ifindex: 3,
                labels,
            }],
        }
    }

    #[test]
    fn update_returns_deps_only_on_change_and_stores_transport() {
        let mut c = NexthopCache::default();
        let nh: IpAddr = "10.0.0.8".parse().unwrap();
        let p1: Ipv4Net = "1.0.0.0/24".parse().unwrap();
        c.track(nh, NhtDep::V4(p1));

        // pending(false) -> reachable(true): change, deps returned, and
        // the resolved transport is now retrievable.
        let deps = c.update(nh, &reachable(vec![16800]));
        assert_eq!(deps, vec![NhtDep::V4(p1)]);
        assert_eq!(c.transport_for(nh).len(), 1);
        assert_eq!(c.transport_for(nh)[0].labels, vec![16800]);
        assert_eq!(c.transport_for(nh)[0].ifindex, 3);

        // still reachable, transport label changed: no reachability
        // flip → no deps, but the stored transport refreshes.
        assert!(c.update(nh, &reachable(vec![16801])).is_empty());
        assert_eq!(c.transport_for(nh)[0].labels, vec![16801]);

        // unknown nexthop: no deps, empty transport.
        let unknown: IpAddr = "9.9.9.9".parse().unwrap();
        assert!(c.update(unknown, &NexthopResolution::default()).is_empty());
        assert!(c.transport_for(unknown).is_empty());
    }
}
