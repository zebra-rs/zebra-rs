use std::collections::BTreeMap;
use std::marker::PhantomData;

use bgp_packet::*;
use ipnet::{Ipv4Net, Ipv6Net};

use super::BgpRib;

// Direction marker types for compile-time type safety
#[derive(Debug, Clone, Copy)]
pub struct In;

#[derive(Debug, Clone, Copy)]
pub struct Out;

// Trait to specify which ID field to use based on direction
pub trait RibDirection {
    fn get_id(rib: &BgpRib) -> u32;

    /// Whether a `remove(prefix, 0)` that finds no exact-id match falls
    /// back to clearing every candidate for the prefix.
    ///
    /// `Out` needs it: a non-AddPath advertisement stores its
    /// Adj-RIB-Out row under the Loc-RIB `local_id` (always ≥ 1) but is
    /// withdrawn with the on-wire id 0, so the fallback is the only way
    /// to reach it.
    ///
    /// `In` must NOT have it (review finding #11): the wire path-id is
    /// parsed unvalidated, and a non-AddPath peer's row already carries
    /// `remote_id == 0` (matched exactly), so the fallback is dead
    /// weight in the honest case and a wildcard wipe in the hostile
    /// one — an AddPath peer that announced ids 1 and 2 then sends a
    /// withdraw with the never-announced id 0 would clear BOTH
    /// candidates, desyncing the Adj-RIB-In from the Loc-RIB (which
    /// matches `remote_id == id` exactly). Exact-match here keeps the
    /// two in lockstep.
    const ZERO_ID_WILDCARD: bool;
}

impl RibDirection for In {
    fn get_id(rib: &BgpRib) -> u32 {
        rib.remote_id
    }
    const ZERO_ID_WILDCARD: bool = false;
}

impl RibDirection for Out {
    fn get_id(rib: &BgpRib) -> u32 {
        rib.local_id
    }
    const ZERO_ID_WILDCARD: bool = true;
}

/// Per-AFI Adj-RIB table, generic over the prefix type `P` (defaults
/// to `Ipv4Net` so existing `AdjRibTable<D>` uses are unchanged). The
/// direction marker `D` selects which path-id field disambiguates
/// AddPath candidates; both are independent of `P`.
#[derive(Debug)]
pub struct AdjRibTable<D: RibDirection, P = Ipv4Net>(pub BTreeMap<P, Vec<BgpRib>>, PhantomData<D>);

impl<D: RibDirection, P: Ord> AdjRibTable<D, P> {
    pub fn new() -> Self {
        Self(BTreeMap::new(), PhantomData)
    }

    // Add a route using the direction-specific ID field
    pub fn add(&mut self, prefix: P, route: BgpRib) -> Option<BgpRib> {
        let candidates = self.0.entry(prefix).or_default();

        let route_id = D::get_id(&route);
        // Find existing route with same ID (for AddPath support)
        if let Some(pos) = candidates.iter().position(|r| D::get_id(r) == route_id) {
            // Replace existing route with same ID and return the old one
            let old_route = candidates[pos].clone();
            candidates[pos] = route;
            Some(old_route)
        } else {
            // No existing route with this ID, insert new route
            candidates.push(route);
            None
        }
    }

    // Remove a route using the direction-specific ID field
    pub fn remove(&mut self, prefix: P, id: u32) -> Option<BgpRib> {
        let candidates = self.0.get_mut(&prefix)?;

        // Find and remove route with matching ID
        if let Some(pos) = candidates.iter().position(|r| D::get_id(r) == id) {
            let removed_route = candidates.remove(pos);

            // Clean up empty vector
            if candidates.is_empty() {
                self.0.remove(&prefix);
            }

            Some(removed_route)
        } else if id == 0 && D::ZERO_ID_WILDCARD {
            self.0.remove(&prefix);
            None
        } else {
            None
        }
    }
}

impl<P: Ord> AdjRibTable<Out, P> {
    /// Record an outbound best path, returning the prior best (for the
    /// caller's re-send dedup). In non-AddPath mode a prefix carries exactly
    /// one advertised path, so replace the whole entry: `add` keys Out rows by
    /// the Loc-RIB local-id, so a best-path change to a route with a different
    /// local-id would otherwise append a second row and leave the superseded
    /// path as a phantom Adj-RIB-Out entry. Under Add-Path every path-id is a
    /// distinct row that coexists, so defer to `add`.
    pub fn record_out(&mut self, prefix: P, route: BgpRib, add_path: bool) -> Option<BgpRib> {
        if add_path {
            self.add(prefix, route)
        } else {
            let previous = self.0.get(&prefix).and_then(|rows| rows.first()).cloned();
            self.0.insert(prefix, vec![route]);
            previous
        }
    }
}

/// Per-RD Adj-RIB-In/Out table for EVPN routes.
///
/// Mirrors `AdjRibTable<D>` but keyed on `EvpnPrefix` (exact match) instead
/// of `Ipv4Net`. The `D` type parameter selects which path-id field to use
/// for AddPath disambiguation, exactly as for the IPv4 table.
#[derive(Debug)]
pub struct AdjRibEvpnTable<D: RibDirection>(pub BTreeMap<EvpnPrefix, Vec<BgpRib>>, PhantomData<D>);

impl<D: RibDirection> AdjRibEvpnTable<D> {
    pub fn new() -> Self {
        Self(BTreeMap::new(), PhantomData)
    }

    pub fn add(&mut self, prefix: EvpnPrefix, route: BgpRib) -> Option<BgpRib> {
        let candidates = self.0.entry(prefix).or_default();

        let route_id = D::get_id(&route);
        if let Some(pos) = candidates.iter().position(|r| D::get_id(r) == route_id) {
            let old_route = candidates[pos].clone();
            candidates[pos] = route;
            Some(old_route)
        } else {
            candidates.push(route);
            None
        }
    }

    pub fn remove(&mut self, prefix: &EvpnPrefix, id: u32) -> Option<BgpRib> {
        let candidates = self.0.get_mut(prefix)?;

        if let Some(pos) = candidates.iter().position(|r| D::get_id(r) == id) {
            let removed_route = candidates.remove(pos);

            if candidates.is_empty() {
                self.0.remove(prefix);
            }

            Some(removed_route)
        } else if id == 0 && D::ZERO_ID_WILDCARD {
            self.0.remove(prefix);
            None
        } else {
            None
        }
    }
}

impl<D: RibDirection> Default for AdjRibEvpnTable<D> {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-RD Adj-RIB table for MUP (SAFI 85) routes, keyed on the RD-free
/// `MupPrefix` (exact match). The RD is the outer
/// `BTreeMap<RouteDistinguisher, AdjRibMupTable<D>>` key, mirroring
/// `AdjRibEvpnTable<D>`; the `D` marker selects the path-id field for
/// AddPath disambiguation.
#[derive(Debug)]
pub struct AdjRibMupTable<D: RibDirection>(pub BTreeMap<MupPrefix, Vec<BgpRib>>, PhantomData<D>);

impl<D: RibDirection> AdjRibMupTable<D> {
    pub fn new() -> Self {
        Self(BTreeMap::new(), PhantomData)
    }

    pub fn add(&mut self, prefix: MupPrefix, route: BgpRib) -> Option<BgpRib> {
        let candidates = self.0.entry(prefix).or_default();

        let route_id = D::get_id(&route);
        if let Some(pos) = candidates.iter().position(|r| D::get_id(r) == route_id) {
            let old_route = candidates[pos].clone();
            candidates[pos] = route;
            Some(old_route)
        } else {
            candidates.push(route);
            None
        }
    }

    pub fn remove(&mut self, prefix: &MupPrefix, id: u32) -> Option<BgpRib> {
        let candidates = self.0.get_mut(prefix)?;

        if let Some(pos) = candidates.iter().position(|r| D::get_id(r) == id) {
            let removed_route = candidates.remove(pos);

            if candidates.is_empty() {
                self.0.remove(prefix);
            }

            Some(removed_route)
        } else if id == 0 && D::ZERO_ID_WILDCARD {
            self.0.remove(prefix);
            None
        } else {
            None
        }
    }
}

impl<D: RibDirection> Default for AdjRibMupTable<D> {
    fn default() -> Self {
        Self::new()
    }
}

/// Adj-RIB-In/Out table for Flow Specification routes, keyed on
/// `FlowspecNlri` (exact match — overlapping flow specs coexist, so no
/// prefix trie). Mirrors `AdjRibEvpnTable<D>`; the `D` marker selects
/// the path-id field for AddPath disambiguation.
#[derive(Debug)]
pub struct AdjRibFlowspecTable<D: RibDirection>(
    pub BTreeMap<FlowspecNlri, Vec<BgpRib>>,
    PhantomData<D>,
);

impl<D: RibDirection> AdjRibFlowspecTable<D> {
    pub fn new() -> Self {
        Self(BTreeMap::new(), PhantomData)
    }

    pub fn add(&mut self, nlri: FlowspecNlri, route: BgpRib) -> Option<BgpRib> {
        let candidates = self.0.entry(nlri).or_default();

        let route_id = D::get_id(&route);
        if let Some(pos) = candidates.iter().position(|r| D::get_id(r) == route_id) {
            let old_route = candidates[pos].clone();
            candidates[pos] = route;
            Some(old_route)
        } else {
            candidates.push(route);
            None
        }
    }

    pub fn remove(&mut self, nlri: &FlowspecNlri, id: u32) -> Option<BgpRib> {
        let candidates = self.0.get_mut(nlri)?;

        if let Some(pos) = candidates.iter().position(|r| D::get_id(r) == id) {
            let removed_route = candidates.remove(pos);

            if candidates.is_empty() {
                self.0.remove(nlri);
            }

            Some(removed_route)
        } else if id == 0 && D::ZERO_ID_WILDCARD {
            self.0.remove(nlri);
            None
        } else {
            None
        }
    }
}

impl<D: RibDirection> Default for AdjRibFlowspecTable<D> {
    fn default() -> Self {
        Self::new()
    }
}

/// Adj-RIB-In/Out table for BGP Link-State routes (RFC 9552, AFI 16388 /
/// SAFI 71), keyed on `BgpLsNlri` (exact match — every Node/Link/Prefix
/// object is a distinct key). Mirrors `AdjRibFlowspecTable<D>`. BGP-LS has
/// no AddPath, so the path-id is always 0 and there is one candidate per
/// NLRI per peer.
#[derive(Debug)]
pub struct AdjRibBgpLsTable<D: RibDirection>(pub BTreeMap<BgpLsNlri, Vec<BgpRib>>, PhantomData<D>);

impl<D: RibDirection> AdjRibBgpLsTable<D> {
    pub fn new() -> Self {
        Self(BTreeMap::new(), PhantomData)
    }

    pub fn add(&mut self, nlri: BgpLsNlri, route: BgpRib) -> Option<BgpRib> {
        let candidates = self.0.entry(nlri).or_default();

        let route_id = D::get_id(&route);
        if let Some(pos) = candidates.iter().position(|r| D::get_id(r) == route_id) {
            let old_route = candidates[pos].clone();
            candidates[pos] = route;
            Some(old_route)
        } else {
            candidates.push(route);
            None
        }
    }

    pub fn remove(&mut self, nlri: &BgpLsNlri, id: u32) -> Option<BgpRib> {
        let candidates = self.0.get_mut(nlri)?;

        if let Some(pos) = candidates.iter().position(|r| D::get_id(r) == id) {
            let removed_route = candidates.remove(pos);

            if candidates.is_empty() {
                self.0.remove(nlri);
            }

            Some(removed_route)
        } else if id == 0 && D::ZERO_ID_WILDCARD {
            self.0.remove(nlri);
            None
        } else {
            None
        }
    }
}

impl<D: RibDirection> Default for AdjRibBgpLsTable<D> {
    fn default() -> Self {
        Self::new()
    }
}

// BGP Adj-RIB - stores routes with direction-specific ID handling
#[derive(Debug)]
pub struct AdjRib<D: RibDirection> {
    // IPv4 unicast
    pub v4: AdjRibTable<D>,
    // IPv6 unicast
    pub v6: AdjRibTable<D, Ipv6Net>,
    // IPv4 Labeled-Unicast (SAFI 4)
    pub v4lu: AdjRibTable<D>,
    // IPv6 Labeled-Unicast (SAFI 4)
    pub v6lu: AdjRibTable<D, Ipv6Net>,
    // IPv4 VPN
    pub v4vpn: BTreeMap<RouteDistinguisher, AdjRibTable<D>>,
    // IPv6 VPN
    pub v6vpn: BTreeMap<RouteDistinguisher, AdjRibTable<D, Ipv6Net>>,
    // EVPN, per Route Distinguisher
    pub evpn: BTreeMap<RouteDistinguisher, AdjRibEvpnTable<D>>,
    // MUP (SAFI 85), per Route Distinguisher
    pub mup: BTreeMap<RouteDistinguisher, AdjRibMupTable<D>>,
    // IPv4 Flow Specification (AFI 1, SAFI 133)
    pub flowspec_v4: AdjRibFlowspecTable<D>,
    // IPv6 Flow Specification (AFI 2, SAFI 133)
    pub flowspec_v6: AdjRibFlowspecTable<D>,
    // BGP Link-State (AFI 16388, SAFI 71)
    pub bgp_ls: AdjRibBgpLsTable<D>,
}

impl<D: RibDirection> AdjRib<D> {
    pub fn new() -> Self {
        Self {
            v4: AdjRibTable::new(),
            v6: AdjRibTable::new(),
            v4lu: AdjRibTable::new(),
            v6lu: AdjRibTable::new(),
            v4vpn: BTreeMap::new(),
            v6vpn: BTreeMap::new(),
            evpn: BTreeMap::new(),
            mup: BTreeMap::new(),
            flowspec_v4: AdjRibFlowspecTable::new(),
            flowspec_v6: AdjRibFlowspecTable::new(),
            bgp_ls: AdjRibBgpLsTable::new(),
        }
    }
}

// Default implementation for AdjRibTable<D, P> - needed for or_default()
impl<D: RibDirection, P: Ord> Default for AdjRibTable<D, P> {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-peer Adj-RIB-In slice for the shard-scope families (RIB
/// sharding plan B.1 / D3): v4/v6 unicast, v4/v6 labeled-unicast,
/// VPNv4/v6. Lives in [`super::shard::BgpShard::adj_in`] keyed by
/// peer `ident` — `Peer` stays main-owned, so its received routes
/// for the sharded tables are stored beside the Loc-RIB tables a
/// future shard task will own. The main-only families stay on the
/// peer in [`MainAdjIn`].
#[derive(Debug, Default)]
pub struct ShardAdjIn {
    // IPv4 unicast
    pub v4: AdjRibTable<In>,
    // IPv6 unicast
    pub v6: AdjRibTable<In, Ipv6Net>,
    // IPv4 Labeled-Unicast (SAFI 4)
    pub v4lu: AdjRibTable<In>,
    // IPv6 Labeled-Unicast (SAFI 4)
    pub v6lu: AdjRibTable<In, Ipv6Net>,
    // IPv4 VPN
    pub v4vpn: BTreeMap<RouteDistinguisher, AdjRibTable<In>>,
    // IPv6 VPN
    pub v6vpn: BTreeMap<RouteDistinguisher, AdjRibTable<In, Ipv6Net>>,
}

impl ShardAdjIn {
    // Add a route to Adj-RIB-In
    pub fn add(
        &mut self,
        rd: Option<RouteDistinguisher>,
        prefix: Ipv4Net,
        route: BgpRib,
    ) -> Option<BgpRib> {
        match rd {
            Some(rd) => self.v4vpn.entry(rd).or_default().add(prefix, route),
            None => self.v4.add(prefix, route),
        }
    }

    // Add a route to Adj-RIB-In
    pub fn remove(
        &mut self,
        rd: Option<RouteDistinguisher>,
        prefix: Ipv4Net,
        id: u32,
    ) -> Option<BgpRib> {
        match rd {
            Some(rd) => self.v4vpn.entry(rd).or_default().remove(prefix, id),
            None => self.v4.remove(prefix, id),
        }
    }

    // IPv6 unicast add/remove (no VPN table yet — VPNv6 lands with 2c)

    pub fn add_v6(&mut self, prefix: Ipv6Net, route: BgpRib) -> Option<BgpRib> {
        self.v6.add(prefix, route)
    }

    pub fn remove_v6(&mut self, prefix: Ipv6Net, id: u32) -> Option<BgpRib> {
        self.v6.remove(prefix, id)
    }

    // IPv4 / IPv6 Labeled-Unicast (SAFI 4) add/remove.

    pub fn add_v4lu(&mut self, prefix: Ipv4Net, route: BgpRib) -> Option<BgpRib> {
        self.v4lu.add(prefix, route)
    }

    pub fn remove_v4lu(&mut self, prefix: Ipv4Net, id: u32) -> Option<BgpRib> {
        self.v4lu.remove(prefix, id)
    }

    pub fn add_v6lu(&mut self, prefix: Ipv6Net, route: BgpRib) -> Option<BgpRib> {
        self.v6lu.add(prefix, route)
    }

    pub fn remove_v6lu(&mut self, prefix: Ipv6Net, id: u32) -> Option<BgpRib> {
        self.v6lu.remove(prefix, id)
    }

    pub fn add_v6vpn(
        &mut self,
        rd: RouteDistinguisher,
        prefix: Ipv6Net,
        route: BgpRib,
    ) -> Option<BgpRib> {
        self.v6vpn.entry(rd).or_default().add(prefix, route)
    }

    pub fn remove_v6vpn(
        &mut self,
        rd: RouteDistinguisher,
        prefix: Ipv6Net,
        id: u32,
    ) -> Option<BgpRib> {
        self.v6vpn.entry(rd).or_default().remove(prefix, id)
    }

    /// Received-prefix count for a sharded AFI/SAFI; 0 for families
    /// owned by [`MainAdjIn`] (the two counts are disjoint, so show
    /// paths may sum them for any AFI/SAFI).
    pub fn count(&self, afi: Afi, safi: Safi) -> usize {
        match (afi, safi) {
            (Afi::Ip, Safi::Unicast) => self.v4.0.len(),
            (Afi::Ip6, Safi::Unicast) => self.v6.0.len(),
            (Afi::Ip, Safi::MplsLabel) => self.v4lu.0.len(),
            (Afi::Ip6, Safi::MplsLabel) => self.v6lu.0.len(),
            (Afi::Ip, Safi::MplsVpn) => self.v4vpn.values().map(|table| table.0.len()).sum(),
            (Afi::Ip6, Safi::MplsVpn) => self.v6vpn.values().map(|table| table.0.len()).sum(),
            (_, _) => 0,
        }
    }
}

/// Per-peer Adj-RIB-In for the main-owned families (RIB sharding
/// plan D3): EVPN, flowspec, BGP-LS. Stays on [`super::peer::Peer`];
/// the sharded families live in [`ShardAdjIn`] under
/// `BgpShard::adj_in`.
#[derive(Debug, Default)]
pub struct MainAdjIn {
    // EVPN, per Route Distinguisher
    pub evpn: BTreeMap<RouteDistinguisher, AdjRibEvpnTable<In>>,
    // MUP (SAFI 85), per Route Distinguisher
    pub mup: BTreeMap<RouteDistinguisher, AdjRibMupTable<In>>,
    // IPv4 Flow Specification (AFI 1, SAFI 133)
    pub flowspec_v4: AdjRibFlowspecTable<In>,
    // IPv6 Flow Specification (AFI 2, SAFI 133)
    pub flowspec_v6: AdjRibFlowspecTable<In>,
    // BGP Link-State (AFI 16388, SAFI 71)
    pub bgp_ls: AdjRibBgpLsTable<In>,
}

impl MainAdjIn {
    pub fn new() -> Self {
        Self::default()
    }

    // EVPN add/remove ---------------------------------------------------------

    pub fn add_evpn(
        &mut self,
        rd: RouteDistinguisher,
        prefix: EvpnPrefix,
        route: BgpRib,
    ) -> Option<BgpRib> {
        self.evpn.entry(rd).or_default().add(prefix, route)
    }

    pub fn remove_evpn(
        &mut self,
        rd: RouteDistinguisher,
        prefix: &EvpnPrefix,
        id: u32,
    ) -> Option<BgpRib> {
        self.evpn.entry(rd).or_default().remove(prefix, id)
    }

    // MUP add/remove ---------------------------------------------------------

    pub fn add_mup(
        &mut self,
        rd: RouteDistinguisher,
        prefix: MupPrefix,
        route: BgpRib,
    ) -> Option<BgpRib> {
        self.mup.entry(rd).or_default().add(prefix, route)
    }

    pub fn remove_mup(
        &mut self,
        rd: RouteDistinguisher,
        prefix: &MupPrefix,
        id: u32,
    ) -> Option<BgpRib> {
        self.mup.entry(rd).or_default().remove(prefix, id)
    }

    // Flow Specification add/remove ------------------------------------------

    pub fn add_flowspec(&mut self, afi: Afi, nlri: FlowspecNlri, route: BgpRib) -> Option<BgpRib> {
        match afi {
            Afi::Ip6 => self.flowspec_v6.add(nlri, route),
            _ => self.flowspec_v4.add(nlri, route),
        }
    }

    pub fn remove_flowspec(&mut self, afi: Afi, nlri: &FlowspecNlri, id: u32) -> Option<BgpRib> {
        match afi {
            Afi::Ip6 => self.flowspec_v6.remove(nlri, id),
            _ => self.flowspec_v4.remove(nlri, id),
        }
    }

    // BGP Link-State add/remove ----------------------------------------------

    pub fn add_bgpls(&mut self, nlri: BgpLsNlri, route: BgpRib) -> Option<BgpRib> {
        self.bgp_ls.add(nlri, route)
    }

    pub fn remove_bgpls(&mut self, nlri: &BgpLsNlri, id: u32) -> Option<BgpRib> {
        self.bgp_ls.remove(nlri, id)
    }

    /// Received-prefix count for a main-owned AFI/SAFI; 0 for the
    /// sharded families (see [`ShardAdjIn::count`]).
    pub fn count(&self, afi: Afi, safi: Safi) -> usize {
        match (afi, safi) {
            (Afi::L2vpn, Safi::Evpn) => self.evpn.values().map(|table| table.0.len()).sum(),
            // Per-RD MUP tables; counted under IPv4-MUP to avoid double-count
            // in a combined v4+v6 summary.
            (Afi::Ip, Safi::Mup) => self.mup.values().map(|table| table.0.len()).sum(),
            (Afi::Ip, Safi::Flowspec) => self.flowspec_v4.0.len(),
            (Afi::Ip6, Safi::Flowspec) => self.flowspec_v6.0.len(),
            (Afi::LinkState, Safi::LinkState) => self.bgp_ls.0.len(),
            (_, _) => 0,
        }
    }
}

impl AdjRib<Out> {
    // Add a route to Adj-RIB-Out
    pub fn add(
        &mut self,
        rd: Option<RouteDistinguisher>,
        prefix: Ipv4Net,
        route: BgpRib,
    ) -> Option<BgpRib> {
        match rd {
            Some(rd) => self.v4vpn.entry(rd).or_default().add(prefix, route),
            None => self.v4.add(prefix, route),
        }
    }

    // Add a route to Adj-RIB-Out
    pub fn remove(
        &mut self,
        rd: Option<RouteDistinguisher>,
        prefix: Ipv4Net,
        id: u32,
    ) -> Option<BgpRib> {
        match rd {
            Some(rd) => self.v4vpn.entry(rd).or_default().remove(prefix, id),
            None => self.v4.remove(prefix, id),
        }
    }

    pub fn count(&self, afi: Afi, safi: Safi) -> usize {
        match (afi, safi) {
            (Afi::Ip, Safi::Unicast) => self.v4.0.len(),
            (Afi::Ip6, Safi::Unicast) => self.v6.0.len(),
            (Afi::Ip, Safi::MplsLabel) => self.v4lu.0.len(),
            (Afi::Ip6, Safi::MplsLabel) => self.v6lu.0.len(),
            (Afi::Ip, Safi::MplsVpn) => self.v4vpn.values().map(|table| table.0.len()).sum(),
            (Afi::Ip6, Safi::MplsVpn) => self.v6vpn.values().map(|table| table.0.len()).sum(),
            (Afi::L2vpn, Safi::Evpn) => self.evpn.values().map(|table| table.0.len()).sum(),
            // Per-RD MUP tables; counted under IPv4-MUP to avoid double-count.
            (Afi::Ip, Safi::Mup) => self.mup.values().map(|table| table.0.len()).sum(),
            (Afi::Ip, Safi::Flowspec) => self.flowspec_v4.0.len(),
            (Afi::Ip6, Safi::Flowspec) => self.flowspec_v6.0.len(),
            (Afi::LinkState, Safi::LinkState) => self.bgp_ls.0.len(),
            (_, _) => 0,
        }
    }

    // Check table has prefix.
    pub fn contains_key(&mut self, rd: Option<RouteDistinguisher>, prefix: &Ipv4Net) -> bool {
        match rd {
            Some(rd) => self.v4vpn.entry(rd).or_default().0.contains_key(prefix),
            None => self.v4.0.contains_key(prefix),
        }
    }

    pub fn add_evpn(
        &mut self,
        rd: RouteDistinguisher,
        prefix: EvpnPrefix,
        route: BgpRib,
    ) -> Option<BgpRib> {
        self.evpn.entry(rd).or_default().add(prefix, route)
    }

    pub fn remove_evpn(
        &mut self,
        rd: RouteDistinguisher,
        prefix: &EvpnPrefix,
        id: u32,
    ) -> Option<BgpRib> {
        self.evpn.entry(rd).or_default().remove(prefix, id)
    }

    pub fn add_mup(
        &mut self,
        rd: RouteDistinguisher,
        prefix: MupPrefix,
        route: BgpRib,
    ) -> Option<BgpRib> {
        self.mup.entry(rd).or_default().add(prefix, route)
    }

    pub fn remove_mup(
        &mut self,
        rd: RouteDistinguisher,
        prefix: &MupPrefix,
        id: u32,
    ) -> Option<BgpRib> {
        self.mup.entry(rd).or_default().remove(prefix, id)
    }

    pub fn add_flowspec(&mut self, afi: Afi, nlri: FlowspecNlri, route: BgpRib) -> Option<BgpRib> {
        match afi {
            Afi::Ip6 => self.flowspec_v6.add(nlri, route),
            _ => self.flowspec_v4.add(nlri, route),
        }
    }

    pub fn remove_flowspec(&mut self, afi: Afi, nlri: &FlowspecNlri, id: u32) -> Option<BgpRib> {
        match afi {
            Afi::Ip6 => self.flowspec_v6.remove(nlri, id),
            _ => self.flowspec_v4.remove(nlri, id),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::route::{BgpRib, BgpRibType};
    use std::net::Ipv4Addr;

    /// AddPath-In candidate carrying `remote_id`.
    fn in_rib(remote_id: u32) -> BgpRib {
        BgpRib::new(
            0,
            Ipv4Addr::new(10, 0, 0, 1),
            BgpRibType::EBGP,
            remote_id,
            0,
            &bgp_packet::BgpAttr::default(),
            None,
            None,
            false,
        )
    }

    /// Adj-RIB-Out row carrying `local_id` (set on the row after
    /// construction, as the advertise path does).
    fn out_rib(local_id: u32) -> BgpRib {
        let mut r = in_rib(0);
        r.local_id = local_id;
        r
    }

    fn prefix() -> Ipv4Net {
        "10.9.0.0/24".parse().unwrap()
    }

    /// Review finding #11: an AddPath-In peer announced path-ids 1 and 2;
    /// a withdraw with the never-announced id 0 (wire-legal, parsed
    /// unvalidated) must remove NOTHING — not wildcard-wipe both
    /// candidates, which would desync the Adj-RIB-In from the Loc-RIB.
    #[test]
    fn adj_in_pathid0_withdraw_does_not_wildcard_wipe() {
        let mut t: AdjRibTable<In> = AdjRibTable::new();
        t.add(prefix(), in_rib(1));
        t.add(prefix(), in_rib(2));

        assert!(t.remove(prefix(), 0).is_none(), "id 0 matches no candidate");
        let remaining: Vec<u32> =
            t.0.get(&prefix())
                .unwrap()
                .iter()
                .map(|r| r.remote_id)
                .collect();
        assert_eq!(remaining, vec![1, 2], "both announced paths survive");
    }

    /// A non-AddPath-In peer's row carries `remote_id == 0`, so an id-0
    /// withdraw still removes it by exact match — the honest case is
    /// unaffected by dropping the wildcard.
    #[test]
    fn adj_in_non_addpath_withdraw_removes_exact() {
        let mut t: AdjRibTable<In> = AdjRibTable::new();
        t.add(prefix(), in_rib(0));
        assert!(t.remove(prefix(), 0).is_some(), "the id-0 row is removed");
        assert!(!t.0.contains_key(&prefix()), "prefix is now empty");
    }

    /// An exact AddPath-In withdraw still removes just its own path.
    #[test]
    fn adj_in_addpath_exact_withdraw_removes_one() {
        let mut t: AdjRibTable<In> = AdjRibTable::new();
        t.add(prefix(), in_rib(1));
        t.add(prefix(), in_rib(2));
        assert!(t.remove(prefix(), 1).is_some());
        let remaining: Vec<u32> =
            t.0.get(&prefix())
                .unwrap()
                .iter()
                .map(|r| r.remote_id)
                .collect();
        assert_eq!(remaining, vec![2], "only path-id 1 left");
    }

    /// The Out direction keeps the id-0 wildcard: a non-AddPath
    /// advertisement stores its row under the Loc-RIB `local_id` (≥ 1)
    /// but is withdrawn with the on-wire id 0, so the fallback is the
    /// only way to reach it. Regression guard so the finding-#11 change
    /// didn't break the withdraw path it shares code with.
    #[test]
    fn adj_out_pathid0_withdraw_clears_the_row() {
        let mut t: AdjRibTable<Out> = AdjRibTable::new();
        t.add(prefix(), out_rib(5));
        assert!(t.remove(prefix(), 0).is_none(), "no exact id-0 match…");
        assert!(!t.0.contains_key(&prefix()), "…but the wildcard cleared it");
    }
}
