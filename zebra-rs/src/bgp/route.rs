use bgp_packet::{Attr, UpdatePacket};
use ipnet::Ipv4Net;
use prefix_trie::PrefixMap;
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Instant;

use super::peer::{ConfigRef, Peer};
use crate::rib::{Nexthop, NexthopUni, RibSubType, RibType, api::RibTx, entry::RibEntry};
use ipnet::IpNet;
use tokio::sync::mpsc::UnboundedSender;

/// BGP route origin types as defined in RFC 4271
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum BgpOrigin {
    Igp = 0,        // IGP (lowest preference)
    Egp = 1,        // EGP
    Incomplete = 2, // Incomplete (highest preference)
}

impl From<u8> for BgpOrigin {
    fn from(value: u8) -> Self {
        match value {
            0 => BgpOrigin::Igp,
            1 => BgpOrigin::Egp,
            _ => BgpOrigin::Incomplete,
        }
    }
}

/// BGP peer type for route advertisement rules
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::upper_case_acronyms)]
pub enum PeerType {
    IBGP,
    EBGP,
}

/// Enhanced BGP route structure for proper path selection
#[derive(Clone, Debug)]
pub struct BgpRoute {
    /// Source peer IP address
    pub peer_addr: IpAddr,
    /// BGP peer AS number
    pub peer_as: u32,
    /// Local AS number
    pub local_as: u32,
    /// Peer type (IBGP/EBGP)
    pub peer_type: PeerType,
    /// Route prefix
    pub prefix: Ipv4Net,
    /// Next hop address
    pub next_hop: Ipv4Addr,
    /// All BGP path attributes
    pub attrs: Vec<Attr>,
    /// AS path length (for best path selection)
    pub as_path_len: u32,
    /// Multi-Exit Discriminator
    pub med: Option<u32>,
    /// Local preference (IBGP only)
    pub local_pref: Option<u32>,
    /// Origin type
    pub origin: BgpOrigin,
    /// Weight (Cisco-style, highest priority)
    pub weight: u32,
    /// Route installation time
    pub installed: Instant,
    /// Whether this route is selected as best path
    pub best_path: bool,
    /// Whether this route is valid
    pub valid: bool,
}

impl BgpRoute {
    pub fn new(
        peer_addr: IpAddr,
        peer_as: u32,
        local_as: u32,
        peer_type: PeerType,
        prefix: Ipv4Net,
        attrs: Vec<Attr>,
    ) -> Self {
        let mut route = Self {
            peer_addr,
            peer_as,
            local_as,
            peer_type,
            prefix,
            next_hop: Ipv4Addr::UNSPECIFIED,
            attrs: attrs.clone(),
            as_path_len: 0,
            med: None,
            local_pref: None,
            origin: BgpOrigin::Incomplete,
            weight: 0,
            installed: Instant::now(),
            best_path: false,
            valid: true,
        };

        // Parse attributes
        route.parse_attributes(&attrs);
        route
    }

    /// Parse BGP attributes to extract key path selection attributes
    fn parse_attributes(&mut self, attrs: &[Attr]) {
        for attr in attrs {
            match attr {
                Attr::Origin(origin) => {
                    // Convert Origin to u8 value first, then to BgpOrigin
                    self.origin = BgpOrigin::from(origin.origin);
                }
                Attr::As4Path(as_path) => {
                    // Calculate AS path length for path selection (use As4Path for 4-byte ASN support)
                    self.as_path_len = as_path
                        .segs
                        .iter()
                        .map(|segment| segment.asn.len() as u32)
                        .sum();
                }
                Attr::As2Path(as_path) => {
                    // Fallback to 2-byte AS path if As4Path not present
                    if self.as_path_len == 0 {
                        self.as_path_len = as_path
                            .segs
                            .iter()
                            .map(|segment| segment.asn.len() as u32)
                            .sum();
                    }
                }
                Attr::NextHop(nh) => {
                    self.next_hop = nh.next_hop;
                }
                Attr::Med(med) => {
                    self.med = Some(med.med);
                }
                Attr::LocalPref(local_pref) => {
                    self.local_pref = Some(local_pref.local_pref);
                }
                _ => {
                    // Handle other attributes as needed
                }
            }
        }

        // Set default local preference for IBGP routes
        if self.peer_type == PeerType::IBGP && self.local_pref.is_none() {
            self.local_pref = Some(100); // Default local preference
        }
    }
}

/// BGP Adj-RIB-In - stores routes received from a specific peer before policy application
#[derive(Debug, Default)]
pub struct BgpAdjRibIn {
    /// Routes received from peer (before policy application)
    pub routes: PrefixMap<Ipv4Net, BgpRoute>,
}

impl BgpAdjRibIn {
    pub fn new() -> Self {
        Self {
            routes: PrefixMap::new(),
        }
    }

    /// Add a route to Adj-RIB-In
    pub fn add_route(&mut self, route: BgpRoute) -> Option<BgpRoute> {
        self.routes.insert(route.prefix, route)
    }

    /// Remove a route from Adj-RIB-In
    pub fn remove_route(&mut self, prefix: Ipv4Net) -> Option<BgpRoute> {
        self.routes.remove(&prefix)
    }

    /// Get all routes
    pub fn get_routes(&self) -> impl Iterator<Item = (&Ipv4Net, &BgpRoute)> {
        self.routes.iter()
    }

    /// Get route count
    pub fn route_count(&self) -> usize {
        self.routes.len()
    }

    /// Clear all routes from Adj-RIB-In (used when peer session goes down)
    pub fn clear_all_routes(&mut self) -> Vec<BgpRoute> {
        let removed_routes: Vec<BgpRoute> =
            self.routes.iter().map(|(_, route)| route.clone()).collect();
        self.routes.clear();
        removed_routes
    }
}

/// BGP Adj-RIB-Out - stores routes to be advertised to a specific peer after policy application
#[derive(Debug, Default)]
pub struct BgpAdjRibOut {
    /// Routes to be advertised to peer (after policy application)
    pub routes: PrefixMap<Ipv4Net, BgpRoute>,
}

impl BgpAdjRibOut {
    pub fn new() -> Self {
        Self {
            routes: PrefixMap::new(),
        }
    }

    /// Add a route to Adj-RIB-Out
    pub fn add_route(&mut self, route: BgpRoute) -> Option<BgpRoute> {
        self.routes.insert(route.prefix, route)
    }

    /// Remove a route from Adj-RIB-Out
    pub fn remove_route(&mut self, prefix: Ipv4Net) -> Option<BgpRoute> {
        self.routes.remove(&prefix)
    }

    /// Get all routes to be advertised
    pub fn get_routes(&self) -> impl Iterator<Item = (&Ipv4Net, &BgpRoute)> {
        self.routes.iter()
    }

    /// Get route count
    pub fn route_count(&self) -> usize {
        self.routes.len()
    }

    /// Clear all routes from Adj-RIB-Out (used when peer session goes down)
    pub fn clear_all_routes(&mut self) -> Vec<BgpRoute> {
        let removed_routes: Vec<BgpRoute> =
            self.routes.iter().map(|(_, route)| route.clone()).collect();
        self.routes.clear();
        removed_routes
    }
}

/// BGP Local RIB (Loc-RIB) - stores best paths selected from all Adj-RIB-In
#[derive(Debug, Default)]
pub struct BgpLocalRib {
    /// Best path routes per prefix
    pub routes: PrefixMap<Ipv4Net, BgpRoute>,
    /// All candidate routes per prefix (for show commands)
    pub candidates: PrefixMap<Ipv4Net, Vec<BgpRoute>>,
}

impl BgpLocalRib {
    pub fn new() -> Self {
        Self {
            routes: PrefixMap::new(),
            candidates: PrefixMap::new(),
        }
    }

    /// Add or update a route in the Local RIB and perform best path selection
    pub fn update_route(&mut self, route: BgpRoute) -> Option<BgpRoute> {
        let prefix = route.prefix;

        // Add to candidates
        let candidates = self.candidates.entry(prefix).or_default();

        // Remove existing route from same peer if present
        candidates.retain(|r| r.peer_addr != route.peer_addr);
        candidates.push(route.clone());

        // Perform best path selection
        self.select_best_path(prefix)
    }

    /// Remove a route from the Local RIB
    pub fn remove_route(&mut self, prefix: Ipv4Net, peer_addr: IpAddr) -> Option<BgpRoute> {
        let mut removed_best = false;

        // Remove from candidates
        if let Some(candidates) = self.candidates.get_mut(&prefix) {
            let original_len = candidates.len();
            candidates.retain(|r| r.peer_addr != peer_addr);

            if candidates.is_empty() {
                self.candidates.remove(&prefix);
                removed_best = self.routes.remove(&prefix).is_some();
                return if removed_best {
                    Some(BgpRoute::new(
                        peer_addr,
                        0,
                        0,
                        PeerType::EBGP,
                        prefix,
                        vec![],
                    ))
                } else {
                    None
                };
            } else if original_len != candidates.len() {
                // Check if we removed the current best path
                if let Some(current_best) = self.routes.get(&prefix) {
                    if current_best.peer_addr == peer_addr {
                        removed_best = true;
                    }
                }
            }
        }

        // If we removed the best path, reselect
        if removed_best {
            self.select_best_path(prefix)
        } else {
            None
        }
    }

    /// BGP best path selection algorithm per RFC 4271
    pub fn select_best_path(&mut self, prefix: Ipv4Net) -> Option<BgpRoute> {
        let candidates = match self.candidates.get(&prefix) {
            Some(candidates) if !candidates.is_empty() => candidates,
            _ => {
                self.routes.remove(&prefix);
                return None;
            }
        };

        // If only one candidate, it's the best
        if candidates.len() == 1 {
            let mut best = candidates[0].clone();
            best.best_path = true;
            let old_best = self.routes.insert(prefix, best.clone());
            return if old_best.is_some() && old_best.as_ref().unwrap().peer_addr != best.peer_addr {
                Some(best)
            } else {
                None
            };
        }

        // BGP best path selection algorithm
        let mut best = &candidates[0];

        for candidate in candidates.iter().skip(1) {
            best = self.compare_routes(best, candidate);
        }

        let mut best_route = best.clone();
        best_route.best_path = true;

        let old_best = self.routes.insert(prefix, best_route.clone());

        // Return the new best path if it changed
        if old_best.is_none() || old_best.as_ref().unwrap().peer_addr != best_route.peer_addr {
            Some(best_route)
        } else {
            None
        }
    }

    /// Compare two BGP routes according to RFC 4271 best path selection
    fn compare_routes<'a>(&self, route1: &'a BgpRoute, route2: &'a BgpRoute) -> &'a BgpRoute {
        // 1. Prefer route with higher weight (Cisco-specific)
        if route1.weight != route2.weight {
            return if route1.weight > route2.weight {
                route1
            } else {
                route2
            };
        }

        // 2. Prefer route with higher local preference
        let lp1 = route1.local_pref.unwrap_or(100);
        let lp2 = route2.local_pref.unwrap_or(100);
        if lp1 != lp2 {
            return if lp1 > lp2 { route1 } else { route2 };
        }

        // 3. Prefer locally originated routes (not implemented yet)

        // 4. Prefer route with shorter AS path
        if route1.as_path_len != route2.as_path_len {
            return if route1.as_path_len < route2.as_path_len {
                route1
            } else {
                route2
            };
        }

        // 5. Prefer route with lower origin (IGP < EGP < Incomplete)
        if route1.origin != route2.origin {
            return if route1.origin < route2.origin {
                route1
            } else {
                route2
            };
        }

        // 6. Prefer route with lower MED (only compare if from same AS)
        if route1.peer_as == route2.peer_as {
            let med1 = route1.med.unwrap_or(0);
            let med2 = route2.med.unwrap_or(0);
            if med1 != med2 {
                return if med1 < med2 { route1 } else { route2 };
            }
        }

        // 7. Prefer EBGP over IBGP
        match (&route1.peer_type, &route2.peer_type) {
            (PeerType::EBGP, PeerType::IBGP) => return route1,
            (PeerType::IBGP, PeerType::EBGP) => return route2,
            _ => {}
        }

        // 8. Prefer route with lower IGP metric to next hop (not implemented)

        // 9. Prefer older route (route1 installed first if times are equal)
        if route1.installed != route2.installed {
            return if route1.installed < route2.installed {
                route1
            } else {
                route2
            };
        }

        // 10. Prefer route from peer with lower router ID
        route1 // Default to first route
    }

    /// Get the best path for a prefix
    pub fn get_best_path(&self, prefix: &Ipv4Net) -> Option<&BgpRoute> {
        self.routes.get(prefix)
    }

    /// Get all candidate routes for a prefix
    pub fn get_candidates(&self, prefix: &Ipv4Net) -> Option<&Vec<BgpRoute>> {
        self.candidates.get(prefix)
    }

    /// Get all best paths
    pub fn get_all_best_paths(&self) -> impl Iterator<Item = (&Ipv4Net, &BgpRoute)> {
        self.routes.iter()
    }

    /// Get total number of routes in Local RIB
    pub fn route_count(&self) -> usize {
        self.routes.len()
    }

    /// Remove all routes from a specific peer (used when peer session goes down)
    pub fn remove_peer_routes(&mut self, peer_addr: IpAddr) -> Vec<BgpRoute> {
        let mut removed_routes = Vec::new();
        let mut prefixes_to_reselect = Vec::new();

        // Find all prefixes that have routes from this peer
        for (prefix, candidates) in self.candidates.iter_mut() {
            let original_len = candidates.len();
            candidates.retain(|r| r.peer_addr != peer_addr);

            if candidates.is_empty() {
                // No more candidates, remove best path too
                if let Some(removed_best) = self.routes.remove(prefix) {
                    removed_routes.push(removed_best);
                }
            } else if original_len != candidates.len() {
                // We removed route(s) from this peer, check if best path changed
                if let Some(current_best) = self.routes.get(prefix) {
                    if current_best.peer_addr == peer_addr {
                        prefixes_to_reselect.push(*prefix);
                    }
                }
            }
        }

        // Remove empty candidate entries
        self.candidates
            .retain(|_, candidates| !candidates.is_empty());

        // Reselect best paths for affected prefixes
        for prefix in prefixes_to_reselect {
            if let Some(new_best) = self.select_best_path(prefix) {
                removed_routes.push(new_best);
            }
        }

        removed_routes
    }
}

/// Send a BGP route to the main RIB for installation
pub fn send_route_to_rib(
    bgp_route: &BgpRoute,
    rib_tx: &UnboundedSender<RibTx>,
    install: bool,
) -> Result<(), anyhow::Error> {
    // Create RIB entry for BGP route
    let mut rib_entry = RibEntry::new(RibType::Bgp);
    rib_entry.rsubtype = RibSubType::Default;
    rib_entry.valid = bgp_route.valid;
    rib_entry.selected = bgp_route.best_path;
    rib_entry.distance = 20; // BGP administrative distance
    rib_entry.metric = bgp_route.med.unwrap_or(0);

    // Create nexthop - convert IPv4 nexthop to IpAddr
    let nexthop_uni = NexthopUni {
        addr: IpAddr::V4(bgp_route.next_hop),
        metric: bgp_route.med.unwrap_or(0),
        weight: bgp_route.weight as u8,
        ifindex: 0, // TODO: Resolve interface index from nexthop
        valid: true,
        mpls: Vec::new(),
        mpls_label: Vec::new(),
        gid: 0, // Will be assigned by RIB
    };
    rib_entry.nexthop = Nexthop::Uni(nexthop_uni);

    // Convert prefix to IpNet
    let prefix = IpNet::V4(bgp_route.prefix);

    // Send appropriate message to RIB
    let msg = if install {
        RibTx::RouteAdd {
            prefix,
            entry: rib_entry,
        }
    } else {
        RibTx::RouteDel {
            prefix,
            entry: rib_entry,
        }
    };

    rib_tx
        .send(msg)
        .map_err(|e| anyhow::anyhow!("Failed to send route to RIB: {}", e))?;
    Ok(())
}

// Maintain backward compatibility
#[allow(dead_code)]
pub struct Route {
    pub from: IpAddr,
    pub attrs: Vec<Attr>,
    pub origin: u8,
    pub typ: PeerType,
    pub selected: bool,
}

#[allow(dead_code)]
fn attr_check() {
    //
}

pub fn route_from_peer(peer: &mut Peer, packet: UpdatePacket, bgp: &mut ConfigRef) {
    // Determine peer type based on AS numbers
    let peer_type = if peer.local_as == peer.peer_as {
        super::route::PeerType::IBGP
    } else {
        super::route::PeerType::EBGP
    };

    // Process route announcements
    for ipv4 in packet.ipv4_update.iter() {
        let bgp_route = BgpRoute::new(
            peer.address,
            peer.peer_as,
            peer.local_as,
            peer_type.clone(),
            *ipv4,
            packet.attrs.clone(),
        );

        // 1. Store route in peer's Adj-RIB-In
        peer.adj_rib_in.add_route(bgp_route.clone());

        // 2. Add route to Local RIB and get the new best path if any
        if let Some(new_best) = bgp.local_rib.update_route(bgp_route) {
            // 3. Install new best path into main RIB
            if let Err(e) = send_route_to_rib(&new_best, bgp.rib_tx, true) {
                eprintln!("Failed to install BGP route {} to RIB: {}", ipv4, e);
            } else {
                println!(
                    "Installed new best path for {}: {:?}",
                    ipv4, new_best.peer_addr
                );
            }
        }
    }

    // Process route withdrawals
    for ipv4 in packet.ipv4_withdraw.iter() {
        // 1. Remove from peer's Adj-RIB-In
        peer.adj_rib_in.remove_route(*ipv4);

        // 2. Remove from Local RIB and check if best path changed
        if let Some(removed_best) = bgp.local_rib.remove_route(*ipv4, peer.address) {
            // 3. Remove old best path from main RIB
            if let Err(e) = send_route_to_rib(&removed_best, bgp.rib_tx, false) {
                eprintln!("Failed to remove BGP route {} from RIB: {}", ipv4, e);
            } else {
                println!("Removed route for {} from peer {}", ipv4, peer.address);
            }

            // 4. Install new best path if available
            if let Some(new_best) = bgp.local_rib.get_best_path(ipv4) {
                if let Err(e) = send_route_to_rib(new_best, bgp.rib_tx, true) {
                    eprintln!("Failed to install new BGP route {} to RIB: {}", ipv4, e);
                } else {
                    println!("Installed new best path for {} after withdrawal", ipv4);
                }
            }
        }
    }

    // Legacy code for backward compatibility
    for ipv4 in packet.ipv4_update.iter() {
        let route = Route {
            from: peer.address,
            attrs: packet.attrs.clone(),
            origin: 0u8,
            typ: PeerType::IBGP,
            selected: false,
        };
        bgp.ptree.entry(*ipv4).or_default().push(route);
    }
}
