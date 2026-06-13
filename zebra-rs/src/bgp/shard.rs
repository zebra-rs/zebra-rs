//! Shard-owned BGP state (RIB sharding plan B.1, first slice).
//!
//! [`BgpShard`] holds exactly the state a future shard task will own
//! end-to-end: the Loc-RIB tables that partition by prefix hash. Per
//! the plan's D3 ruling (`docs/design/bgp-rib-sharding-plan.md` §8),
//! that scope is v4/v6 unicast, v4/v6 labeled-unicast, and VPNv4/v6 —
//! EVPN, flowspec, SR-Policy, BGP-LS, RTC, and table-map stay
//! main-owned in [`super::route::LocalRib`] (small tables; EVPN MAC
//! routes don't even hash by IP prefix).
//!
//! Today `BgpShard` is a plain field on `Bgp` / `BgpVrf`, mutated
//! inline by the single event loop — no behavior change. The
//! shard-side `BgpAttrStore` lands as a later B.1 slice; Phase B.3
//! gives the shard its own task.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use bgp_packet::RouteDistinguisher;
use ipnet::{Ipv4Net, Ipv6Net};

use bgp_packet::{Afi, Safi};

use super::adj_rib::ShardAdjIn;
use super::route::{BgpRib, LocalRibTable};

#[derive(Debug, Default)]
pub struct BgpShard {
    pub v4: LocalRibTable<Ipv4Net>,

    pub v6: LocalRibTable<Ipv6Net>,

    /// IPv4 / IPv6 Labeled-Unicast (SAFI 4) Loc-RIB. Same prefix key as
    /// unicast; each `BgpRib` carries the per-prefix label.
    pub v4lu: LocalRibTable<Ipv4Net>,

    pub v6lu: LocalRibTable<Ipv6Net>,

    pub v4vpn: BTreeMap<RouteDistinguisher, LocalRibTable<Ipv4Net>>,

    pub v6vpn: BTreeMap<RouteDistinguisher, LocalRibTable<Ipv6Net>>,

    /// Per-peer Adj-RIB-In slices for the sharded families, keyed by
    /// peer `ident` ([`super::peer::Peer`] stays main-owned). The
    /// main-only families' adj-in stays on the peer as
    /// [`super::adj_rib::MainAdjIn`].
    pub adj_in: BTreeMap<usize, ShardAdjIn>,
}

impl BgpShard {
    /// The peer's Adj-RIB-In slice, if it has ever stored a route.
    pub fn adj_in(&self, ident: usize) -> Option<&ShardAdjIn> {
        self.adj_in.get(&ident)
    }

    /// The peer's Adj-RIB-In slice, created on first use.
    pub fn adj_in_mut(&mut self, ident: usize) -> &mut ShardAdjIn {
        self.adj_in.entry(ident).or_default()
    }

    /// Drop the peer's entire Adj-RIB-In slice (peer-down sweep).
    pub fn adj_in_drop(&mut self, ident: usize) {
        self.adj_in.remove(&ident);
    }

    /// Received-prefix count for a sharded AFI/SAFI (0 for main-owned
    /// families and for peers with no slice — disjoint with
    /// [`super::adj_rib::MainAdjIn::count`], so show paths sum both).
    pub fn adj_in_count(&self, ident: usize, afi: Afi, safi: Safi) -> usize {
        self.adj_in
            .get(&ident)
            .map(|a| a.count(afi, safi))
            .unwrap_or(0)
    }

    // Update LocalRIB route.
    pub fn update(
        &mut self,
        rd: Option<RouteDistinguisher>,
        prefix: Ipv4Net,
        rib: BgpRib,
    ) -> (Vec<BgpRib>, Vec<BgpRib>, u32) {
        match rd {
            Some(rd) => self.v4vpn.entry(rd).or_default().update(prefix, rib),
            None => self.v4.update(prefix, rib),
        }
    }

    pub fn remove(
        &mut self,
        rd: Option<RouteDistinguisher>,
        prefix: Ipv4Net,
        id: u32,
        ident: usize,
    ) -> Vec<BgpRib> {
        match rd {
            Some(rd) => self.v4vpn.entry(rd).or_default().remove(prefix, id, ident),
            None => self.v4.remove(prefix, id, ident),
        }
    }

    // Return selected best path, not the change history.
    pub fn select_best_path(&mut self, prefix: Ipv4Net) -> Vec<BgpRib> {
        self.v4.select_best_path(prefix)
    }

    // Return selected best path, not the change history.
    pub fn select_best_path_vpn(
        &mut self,
        rd: &RouteDistinguisher,
        prefix: Ipv4Net,
    ) -> Vec<BgpRib> {
        self.v4vpn.entry(*rd).or_default().select_best_path(prefix)
    }

    // IPv6 unicast accessors. VPNv6 (`v6vpn`) lands with layer 2c, so
    // these take no RD — the global/default v6 unicast Loc-RIB only.
    pub fn update_v6(&mut self, prefix: Ipv6Net, rib: BgpRib) -> (Vec<BgpRib>, Vec<BgpRib>, u32) {
        self.v6.update(prefix, rib)
    }

    pub fn remove_v6(&mut self, prefix: Ipv6Net, id: u32, ident: usize) -> Vec<BgpRib> {
        self.v6.remove(prefix, id, ident)
    }

    pub fn select_best_path_v6(&mut self, prefix: Ipv6Net) -> Vec<BgpRib> {
        self.v6.select_best_path(prefix)
    }

    // IPv4 / IPv6 Labeled-Unicast (SAFI 4) accessors. Same Loc-RIB
    // engine as unicast; the per-prefix label travels on each `BgpRib`.
    pub fn update_v4lu(&mut self, prefix: Ipv4Net, rib: BgpRib) -> (Vec<BgpRib>, Vec<BgpRib>, u32) {
        self.v4lu.update(prefix, rib)
    }

    pub fn remove_v4lu(&mut self, prefix: Ipv4Net, id: u32, ident: usize) -> Vec<BgpRib> {
        self.v4lu.remove(prefix, id, ident)
    }

    pub fn select_best_path_v4lu(&mut self, prefix: Ipv4Net) -> Vec<BgpRib> {
        self.v4lu.select_best_path(prefix)
    }

    pub fn update_v6lu(&mut self, prefix: Ipv6Net, rib: BgpRib) -> (Vec<BgpRib>, Vec<BgpRib>, u32) {
        self.v6lu.update(prefix, rib)
    }

    pub fn remove_v6lu(&mut self, prefix: Ipv6Net, id: u32, ident: usize) -> Vec<BgpRib> {
        self.v6lu.remove(prefix, id, ident)
    }

    pub fn select_best_path_v6lu(&mut self, prefix: Ipv6Net) -> Vec<BgpRib> {
        self.v6lu.select_best_path(prefix)
    }

    // VPNv6 accessors — per-RD `v6vpn` tables, mirroring the v4vpn
    // ones. (Best-path-for-advertise of VPNv6 winners lands in 2c-ii.)
    pub fn update_v6vpn(
        &mut self,
        rd: RouteDistinguisher,
        prefix: Ipv6Net,
        rib: BgpRib,
    ) -> (Vec<BgpRib>, Vec<BgpRib>, u32) {
        self.v6vpn.entry(rd).or_default().update(prefix, rib)
    }

    pub fn remove_v6vpn(
        &mut self,
        rd: RouteDistinguisher,
        prefix: Ipv6Net,
        id: u32,
        ident: usize,
    ) -> Vec<BgpRib> {
        self.v6vpn.entry(rd).or_default().remove(prefix, id, ident)
    }

    pub fn select_best_path_vpn_v6(
        &mut self,
        rd: &RouteDistinguisher,
        prefix: Ipv6Net,
    ) -> Vec<BgpRib> {
        self.v6vpn.entry(*rd).or_default().select_best_path(prefix)
    }

    /// Distinct BGP next-hops still in use by surviving candidates for a
    /// v4 (`rd == None`) / VPNv4 (`rd == Some`) prefix — for NHT untrack
    /// to avoid releasing a next-hop another path still needs.
    pub fn candidate_nexthops_v4(
        &self,
        rd: Option<RouteDistinguisher>,
        prefix: Ipv4Net,
    ) -> BTreeSet<IpAddr> {
        let cands = match rd {
            Some(rd) => self.v4vpn.get(&rd).map(|t| t.candidates(prefix)),
            None => Some(self.v4.candidates(prefix)),
        };
        cands
            .into_iter()
            .flatten()
            .filter_map(|r| super::nht::bgp_nexthop_ip(&r.attr))
            .collect()
    }

    /// IPv6 counterpart of [`Self::candidate_nexthops_v4`].
    pub fn candidate_nexthops_v6(
        &self,
        rd: Option<RouteDistinguisher>,
        prefix: Ipv6Net,
    ) -> BTreeSet<IpAddr> {
        let cands = match rd {
            Some(rd) => self.v6vpn.get(&rd).map(|t| t.candidates(prefix)),
            None => Some(self.v6.candidates(prefix)),
        };
        cands
            .into_iter()
            .flatten()
            .filter_map(|r| super::nht::bgp_nexthop_ip(&r.attr))
            .collect()
    }

    /// Labeled-Unicast (SAFI 4) counterparts: the distinct BGP next-hops
    /// among the `v4lu` / `v6lu` candidates for `prefix` (for NHT untrack
    /// after a displaced path).
    pub fn candidate_nexthops_v4lu(&self, prefix: Ipv4Net) -> BTreeSet<IpAddr> {
        self.v4lu
            .candidates(prefix)
            .iter()
            .filter_map(|r| super::nht::bgp_nexthop_ip(&r.attr))
            .collect()
    }

    pub fn candidate_nexthops_v6lu(&self, prefix: Ipv6Net) -> BTreeSet<IpAddr> {
        self.v6lu
            .candidates(prefix)
            .iter()
            .filter_map(|r| super::nht::bgp_nexthop_ip(&r.attr))
            .collect()
    }
}
