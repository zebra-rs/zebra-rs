use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::net::{IpAddr, Ipv4Addr};

use bgp_packet::*;
use bytes::BytesMut;
use ipnet::Ipv4Net;
use prefix_trie::PrefixMap;

use super::BgpRib;
use super::cap::CapAfiMap;
use super::peer::{ConfigRef, Peer, PeerType};

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

#[derive(Debug)]
pub struct AdjRibTable<D: RibDirection>(pub PrefixMap<Ipv4Net, Vec<BgpRib>>, PhantomData<D>);

impl<D: RibDirection> AdjRibTable<D> {
    pub fn new() -> Self {
        Self(PrefixMap::new(), PhantomData)
    }

    // Add a route using the direction-specific ID field
    pub fn add(&mut self, prefix: Ipv4Net, route: BgpRib) -> Option<BgpRib> {
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
    pub fn remove(&mut self, prefix: Ipv4Net, id: u32) -> Option<BgpRib> {
        let candidates = self.0.get_mut(&prefix)?;

        // Find and remove route with matching ID
        if let Some(pos) = candidates.iter().position(|r| D::get_id(r) == id) {
            let removed_route = candidates.remove(pos);

            // Clean up empty vector
            if candidates.is_empty() {
                self.0.remove(&prefix);
            }

            Some(removed_route)
        } else {
            None
        }
    }
}

// BGP Adj-RIB - stores routes with direction-specific ID handling
#[derive(Debug)]
pub struct AdjRib<D: RibDirection> {
    // IPv4 unicast
    pub v4: AdjRibTable<D>,
    // IPv4 VPN
    pub v4vpn: BTreeMap<RouteDistinguisher, AdjRibTable<D>>,
    // Phantom data for direction.
    _phantom: PhantomData<D>,
}

impl<D: RibDirection> AdjRib<D> {
    pub fn new() -> Self {
        Self {
            v4: AdjRibTable::new(),
            v4vpn: BTreeMap::new(),
            _phantom: PhantomData,
        }
    }
}

// Default implementation for AdjRibTable<D> - needed for or_default()
impl<D: RibDirection> Default for AdjRibTable<D> {
    fn default() -> Self {
        Self::new()
    }
}

impl<D: RibDirection> AdjRib<D> {
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

    pub fn count(&self, afi: Afi, safi: Safi) -> usize {
        match (afi, safi) {
            (Afi::Ip, Safi::Unicast) => self.v4.0.len(),
            (Afi::Ip, Safi::MplsVpn) => self.v4vpn.values().map(|table| table.0.len()).sum(),
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
}
