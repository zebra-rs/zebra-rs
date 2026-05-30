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
}

impl RibDirection for In {
    fn get_id(rib: &BgpRib) -> u32 {
        rib.remote_id
    }
}

impl RibDirection for Out {
    fn get_id(rib: &BgpRib) -> u32 {
        rib.local_id
    }
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
        } else if id == 0 {
            self.0.remove(&prefix);
            None
        } else {
            None
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
        } else if id == 0 {
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
        } else if id == 0 {
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
        } else if id == 0 {
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

impl AdjRib<In> {
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

    pub fn count(&self, afi: Afi, safi: Safi) -> usize {
        match (afi, safi) {
            (Afi::Ip, Safi::Unicast) => self.v4.0.len(),
            (Afi::Ip6, Safi::Unicast) => self.v6.0.len(),
            (Afi::Ip, Safi::MplsLabel) => self.v4lu.0.len(),
            (Afi::Ip6, Safi::MplsLabel) => self.v6lu.0.len(),
            (Afi::Ip, Safi::MplsVpn) => self.v4vpn.values().map(|table| table.0.len()).sum(),
            (Afi::Ip6, Safi::MplsVpn) => self.v6vpn.values().map(|table| table.0.len()).sum(),
            (Afi::L2vpn, Safi::Evpn) => self.evpn.values().map(|table| table.0.len()).sum(),
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
