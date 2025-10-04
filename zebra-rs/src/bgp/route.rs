use bgp_packet::{As4Path, Attr, Community, ExtCommunity, Origin, UpdatePacket, Vpnv4Nexthop};
use ipnet::Ipv4Net;
use prefix_trie::PrefixMap;
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Instant;

use super::peer::{ConfigRef, Peer};
use crate::rib;
use crate::rib::{Nexthop, NexthopUni, RibSubType, RibType, api::RibTx, entry::RibEntry};
use ipnet::IpNet;
use tokio::sync::mpsc::UnboundedSender;

/// BGP peer type for route advertisement rules
#[derive(Clone, Debug, PartialEq, Eq, Copy)]
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
    pub nexthop: Ipv4Addr,
    /// All BGP path attributes
    pub attrs: Vec<Attr>,
    /// AS path length (for best path selection)
    pub as_path_len: u32,
    /// Multi-Exit Discriminator
    pub med: Option<u32>,
    /// Local preference (IBGP only)
    pub local_pref: Option<u32>,
    /// Origin type
    pub origin: Origin,
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
            nexthop: Ipv4Addr::UNSPECIFIED,
            attrs: attrs.clone(),
            as_path_len: 0,
            med: None,
            local_pref: None,
            origin: Origin::Incomplete,
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
                    self.origin = *origin;
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
                    self.nexthop = nh.nexthop;
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
    pub entries: PrefixMap<Ipv4Net, Vec<BgpRoute>>,
}

impl BgpLocalRib {
    pub fn new() -> Self {
        Self {
            routes: PrefixMap::new(),
            entries: PrefixMap::new(),
        }
    }

    /// Add or update a route in the Local RIB and perform best path selection
    pub fn update_route(&mut self, route: BgpRoute) -> Option<BgpRoute> {
        let prefix = route.prefix;

        // Add to candidates
        let candidates = self.entries.entry(prefix).or_default();

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
        if let Some(candidates) = self.entries.get_mut(&prefix) {
            let original_len = candidates.len();
            candidates.retain(|r| r.peer_addr != peer_addr);

            if candidates.is_empty() {
                self.entries.remove(&prefix);
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
        // First, find the best route index
        let (best_idx, should_update) = {
            let candidates = match self.entries.get(&prefix) {
                Some(candidates) if !candidates.is_empty() => candidates,
                _ => {
                    self.routes.remove(&prefix);
                    return None;
                }
            };

            // If only one candidate, it's the best
            if candidates.len() == 1 {
                (0, true)
            } else {
                // BGP best path selection algorithm
                let mut best_idx = 0;
                let mut best = &candidates[0];

                for (idx, candidate) in candidates.iter().enumerate().skip(1) {
                    if std::ptr::eq(self.compare_routes(best, candidate), candidate) {
                        best = candidate;
                        best_idx = idx;
                    }
                }
                (best_idx, true)
            }
        };

        // Now update the candidates with mutable access
        if should_update {
            let candidates = self.entries.get_mut(&prefix).unwrap();

            // Clear best_path flag for all candidates
            for candidate in candidates.iter_mut() {
                candidate.best_path = false;
            }

            // Mark the best route
            candidates[best_idx].best_path = true;
            let best_route = candidates[best_idx].clone();

            let old_best = self.routes.insert(prefix, best_route.clone());

            // Return the new best path if it changed
            if old_best.is_none() || old_best.as_ref().unwrap().peer_addr != best_route.peer_addr {
                Some(best_route)
            } else {
                None
            }
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
        self.entries.get(prefix)
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
    /// Returns list of prefixes that had their best path removed and need main RIB updates
    pub fn remove_peer_routes(
        &mut self,
        peer_addr: IpAddr,
    ) -> Vec<(Ipv4Net, Option<BgpRoute>, Option<BgpRoute>)> {
        let mut rib_changes = Vec::new();
        let mut prefixes_to_remove = Vec::new();
        let mut prefixes_to_reselect = Vec::new();

        // Find all prefixes that have routes from this peer
        for (prefix, candidates) in self.entries.iter_mut() {
            let original_len = candidates.len();

            // Get current best path before removing routes
            let old_best = self.routes.get(prefix).cloned();
            let was_best_from_peer = old_best
                .as_ref()
                .map_or(false, |route| route.peer_addr == peer_addr);

            // Remove routes from this peer
            candidates.retain(|r| r.peer_addr != peer_addr);

            if candidates.is_empty() {
                // No more candidates for this prefix
                prefixes_to_remove.push(*prefix);
                if let Some(removed_best) = self.routes.remove(prefix) {
                    // Prefix completely removed: (prefix, old_best, None)
                    rib_changes.push((*prefix, Some(removed_best), None));
                }
            } else if original_len != candidates.len() && was_best_from_peer {
                // We removed route(s) from this peer and it was the best path
                // Need to reselect best path after the iteration
                prefixes_to_reselect.push((*prefix, old_best));
            }
        }

        // Remove empty candidate entries
        for prefix in prefixes_to_remove {
            self.entries.remove(&prefix);
        }

        // Reselect best paths for affected prefixes
        for (prefix, old_best) in prefixes_to_reselect {
            if let Some(new_best) = self.select_best_path(prefix) {
                // Best path changed: (prefix, old_best, new_best)
                rib_changes.push((prefix, old_best, Some(new_best)));
            } else if let Some(old) = old_best {
                // Only removal: (prefix, old_best, None)
                rib_changes.push((prefix, Some(old), None));
            }
        }

        rib_changes
    }
}

/// Send a BGP route to the main RIB for installation
pub fn send_route_to_rib(
    bgp_route: &BgpRoute,
    rib_tx: &UnboundedSender<rib::Message>,
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
        addr: IpAddr::V4(bgp_route.nexthop),
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
    let prefix = bgp_route.prefix.clone();

    // Send appropriate message to RIB
    let msg = if install {
        rib::Message::Ipv4Add {
            prefix,
            rib: rib_entry,
        }
    } else {
        rib::Message::Ipv4Del {
            prefix,
            rib: rib_entry,
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

pub fn route_from_peer_orig(peer: &mut Peer, packet: UpdatePacket, bgp: &mut ConfigRef) {
    // Determine peer type based on AS numbers
    let peer_type = if peer.local_as == peer.peer_as {
        PeerType::IBGP
    } else {
        PeerType::EBGP
    };

    // Process route announcements
    for ipv4 in packet.ipv4_update.iter() {
        let bgp_route = BgpRoute::new(
            peer.address,
            peer.peer_as,
            peer.local_as,
            peer_type,
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
                // println!(
                //     "Installed new best path for {}: {:?}",
                //     ipv4, new_best.peer_addr
                // );
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
}

#[derive(Debug, Clone)]
pub enum BgpNexthop {
    Ipv4(Ipv4Addr),
    Vpnv4(Vpnv4Nexthop),
}

// BGP Attribute for quick access to each attribute. This would be used for
// consolidating route advertisement.
#[derive(Clone, Debug, Default)]
pub struct BgpAttr {
    /// Origin type
    pub origin: Origin,
    /// AS Path
    pub aspath: Option<As4Path>,
    /// Nexthop
    pub nexthop: Option<BgpNexthop>,
    /// Multi-Exit Discriminator
    pub med: Option<u32>,
    /// Local preference (IBGP only)
    pub local_pref: Option<u32>,
    /// Community
    pub com: Option<Community>,
    /// Community
    pub ecom: Option<ExtCommunity>,
}

impl BgpAttr {
    fn from(attrs: &[Attr]) -> Self {
        let mut target = BgpAttr::default();

        for attr in attrs.iter() {
            match attr {
                Attr::Origin(v) => {
                    target.origin = *v;
                }
                Attr::As2Path(v) => {
                    // TODO: Convert As2Path to As4Path.
                }
                Attr::As4Path(v) => {
                    target.aspath = Some(v.clone());
                }
                Attr::NextHop(v) => {}
                Attr::Med(v) => {
                    target.med = Some(v.med);
                }
                Attr::LocalPref(v) => {
                    target.local_pref = Some(v.local_pref);
                }
                // Attr::AtomicAggregate(atomic_aggregate) => todo!(),
                // Attr::Aggregator2(aggregator2) => todo!(),
                // Attr::Aggregator4(aggregator4) => todo!(),
                Attr::Community(v) => {
                    target.com = Some(v.clone());
                }
                // Attr::OriginatorId(originator_id) => todo!(),
                // Attr::ClusterList(cluster_list) => todo!(),
                // Attr::MpReachNlri(mp_nlri_reach_attr) => todo!(),
                // Attr::MpUnreachNlri(mp_nlri_unreach_attr) => todo!(),
                Attr::ExtendedCom(v) => {
                    target.ecom = Some(v.clone());
                }
                // Attr::PmsiTunnel(pmsi_tunnel) => todo!(),
                // Attr::Aigp(aigp) => todo!(),
                // Attr::LargeCom(large_community) => todo!(),
                _ => {
                    //
                }
            }
        }

        target
    }
}

pub fn route_from_peer(peer: &mut Peer, packet: UpdatePacket, bgp: &mut ConfigRef) {
    // Convert Vec<Attr> to BgpAttr.
    let attr = BgpAttr::from(&packet.attrs);

    // Create BgpRoutes.
    // let rib = BgpRib::new();
}
