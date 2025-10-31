use std::collections::VecDeque;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Instant;

use bgp_packet::*;
use bytes::BytesMut;
use ipnet::Ipv4Net;
use prefix_trie::PrefixMap;
use tokio::sync::mpsc::UnboundedSender;

use super::peer::{ConfigRef, Peer, PeerType};
use super::{Bgp, InOut};
use crate::rib::{self, Nexthop, NexthopUni, RibSubType, RibType, entry::RibEntry};

/// BGP Adj-RIB-In - stores routes received from a specific peer before policy application
#[derive(Debug, Default)]
pub struct AdjRib {
    /// Routes received from peer (before policy application)
    pub routes: PrefixMap<Ipv4Net, Vec<BgpRib>>,
}

impl AdjRib {
    pub fn new() -> Self {
        Self {
            routes: PrefixMap::new(),
        }
    }

    // Add a route to Adj-RIB-In
    pub fn add_route(&mut self, prefix: Ipv4Net, route: BgpRib) -> Option<BgpRib> {
        let candidates = self.routes.entry(prefix).or_default();

        // Find existing route with same ID (for AddPath support)
        if let Some(pos) = candidates.iter().position(|r| r.id == route.id) {
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

    // Remove a route from Adj-RIB-In
    pub fn remove_route(&mut self, prefix: Ipv4Net, id: u32) -> Option<BgpRib> {
        let candidates = self.routes.get_mut(&prefix)?;

        // Find and remove route with matching ID
        if let Some(pos) = candidates.iter().position(|r| r.id == id) {
            let removed_route = candidates.remove(pos);

            // Clean up empty vector
            if candidates.is_empty() {
                self.routes.remove(&prefix);
            }

            Some(removed_route)
        } else {
            None
        }
    }

    // /// Get all routes
    // pub fn get_routes(&self) -> impl Iterator<Item = (&Ipv4Net, &BgpRib)> {
    //     self.routes.iter()
    // }

    // /// Get route count
    // pub fn route_count(&self) -> usize {
    //     self.routes.len()
    // }

    // /// Clear all routes from Adj-RIB-In (used when peer session goes down)
    // pub fn clear_all_routes(&mut self) -> Vec<BgpRib> {
    //     let removed_routes: Vec<BgpRib> =
    //         self.routes.iter().map(|(_, route)| route.clone()).collect();
    //     self.routes.clear();
    //     removed_routes
    // }
}

// impl BgpLocalRibOrig {
//     pub fn new() -> Self {
//         Self {
//             routes: PrefixMap::new(),
//             entries: PrefixMap::new(),
//         }
//     }

//     /// Add or update a route in the Local RIB and perform best path selection
//     pub fn update_route(&mut self, route: BgpRib) -> Option<BgpRib> {
//         let prefix = route.prefix.prefix;

//         // Add to candidates
//         let candidates = self.entries.entry(prefix).or_default();

//         // Remove existing route from same peer if present
//         candidates.retain(|r| r.peer_addr != route.peer_addr);
//         candidates.push(route.clone());

//         // Perform best path selection
//         self.select_best_path(prefix)
//     }

//     /// Remove a route from the Local RIB
//     pub fn remove_route(&mut self, prefix: Ipv4Net, peer_addr: IpAddr) -> Option<BgpRib> {
//         let mut removed_best = false;

//         // Remove from candidates
//         if let Some(candidates) = self.entries.get_mut(&prefix) {
//             let original_len = candidates.len();
//             candidates.retain(|r| r.peer_addr != peer_addr);

//             if candidates.is_empty() {
//                 self.entries.remove(&prefix);
//                 removed_best = self.routes.remove(&prefix).is_some();
//                 return if removed_best {
//                     Some(BgpRib::new(
//                         peer_addr,
//                         0,
//                         0,
//                         Ipv4Nlri { id: 0, prefix },
//                         vec![],
//                     ))
//                 } else {
//                     None
//                 };
//             } else if original_len != candidates.len() {
//                 // Check if we removed the current best path
//                 if let Some(current_best) = self.routes.get(&prefix) {
//                     if current_best.peer_addr == peer_addr {
//                         removed_best = true;
//                     }
//                 }
//             }
//         }

//         // If we removed the best path, reselect
//         if removed_best {
//             self.select_best_path(prefix)
//         } else {
//             None
//         }
//     }

//     /// BGP best path selection algorithm per RFC 4271
//     pub fn select_best_path(&mut self, prefix: Ipv4Net) -> Option<BgpRib> {
//         // First, find the best route index
//         let (best_idx, should_update) = {
//             let candidates = match self.entries.get(&prefix) {
//                 Some(candidates) if !candidates.is_empty() => candidates,
//                 _ => {
//                     self.routes.remove(&prefix);
//                     return None;
//                 }
//             };

//             // If only one candidate, it's the best
//             if candidates.len() == 1 {
//                 (0, true)
//             } else {
//                 // BGP best path selection algorithm
//                 let mut best_idx = 0;
//                 let mut best = &candidates[0];

//                 for (idx, candidate) in candidates.iter().enumerate().skip(1) {
//                     if std::ptr::eq(self.compare_routes(best, candidate), candidate) {
//                         best = candidate;
//                         best_idx = idx;
//                     }
//                 }
//                 (best_idx, true)
//             }
//         };

//         // Now update the candidates with mutable access
//         if should_update {
//             let candidates = self.entries.get_mut(&prefix).unwrap();

//             // Clear best_path flag for all candidates
//             for candidate in candidates.iter_mut() {
//                 candidate.best_path = false;
//             }

//             // Mark the best route
//             candidates[best_idx].best_path = true;
//             let best_route = candidates[best_idx].clone();

//             let old_best = self.routes.insert(prefix, best_route.clone());

//             // Return the new best path if it changed
//             if old_best.is_none() || old_best.as_ref().unwrap().peer_addr != best_route.peer_addr {
//                 Some(best_route)
//             } else {
//                 None
//             }
//         } else {
//             None
//         }
//     }

//     /// Compare two BGP routes according to RFC 4271 best path selection
//     fn compare_routes<'a>(&self, route1: &'a BgpRib, route2: &'a BgpRib) -> &'a BgpRib {
//         // 1. Prefer route with higher weight (Cisco-specific)
//         if route1.weight != route2.weight {
//             return if route1.weight > route2.weight {
//                 route1
//             } else {
//                 route2
//             };
//         }

//         // 2. Prefer route with higher local preference
//         let lp1 = route1.local_pref.unwrap_or(100);
//         let lp2 = route2.local_pref.unwrap_or(100);
//         if lp1 != lp2 {
//             return if lp1 > lp2 { route1 } else { route2 };
//         }

//         // 3. Prefer locally originated routes (not implemented yet)

//         // 4. Prefer route with shorter AS path
//         if route1.as_path_len != route2.as_path_len {
//             return if route1.as_path_len < route2.as_path_len {
//                 route1
//             } else {
//                 route2
//             };
//         }

//         // 5. Prefer route with lower origin (IGP < EGP < Incomplete)
//         if route1.origin != route2.origin {
//             return if route1.origin < route2.origin {
//                 route1
//             } else {
//                 route2
//             };
//         }

//         // 6. Prefer route with lower MED (only compare if from same AS)
//         if route1.peer_as == route2.peer_as {
//             let med1 = route1.med.unwrap_or(0);
//             let med2 = route2.med.unwrap_or(0);
//             if med1 != med2 {
//                 return if med1 < med2 { route1 } else { route2 };
//             }
//         }

//         // 7. Prefer EBGP over IBGP
//         // match (&route1.peer_type, &route2.peer_type) {
//         //     (PeerType::EBGP, PeerType::IBGP) => return route1,
//         //     (PeerType::IBGP, PeerType::EBGP) => return route2,
//         //     _ => {}
//         // }

//         // 8. Prefer route with lower IGP metric to next hop (not implemented)

//         // 9. Prefer older route (route1 installed first if times are equal)
//         if route1.installed != route2.installed {
//             return if route1.installed < route2.installed {
//                 route1
//             } else {
//                 route2
//             };
//         }

//         // 10. Prefer route from peer with lower router ID
//         route1 // Default to first route
//     }

//     /// Get the best path for a prefix
//     pub fn get_best_path(&self, prefix: &Ipv4Net) -> Option<&BgpRib> {
//         self.routes.get(prefix)
//     }

//     /// Get all candidate routes for a prefix
//     pub fn get_candidates(&self, prefix: &Ipv4Net) -> Option<&Vec<BgpRib>> {
//         self.entries.get(prefix)
//     }

//     /// Get all best paths
//     pub fn get_all_best_paths(&self) -> impl Iterator<Item = (&Ipv4Net, &BgpRib)> {
//         self.routes.iter()
//     }

//     /// Get total number of routes in Local RIB
//     pub fn route_count(&self) -> usize {
//         self.routes.len()
//     }

//     /// Remove all routes from a specific peer (used when peer session goes down)
//     /// Returns list of prefixes that had their best path removed and need main RIB updates
//     pub fn remove_peer_routes(
//         &mut self,
//         peer_addr: IpAddr,
//     ) -> Vec<(Ipv4Net, Option<BgpRib>, Option<BgpRib>)> {
//         let mut rib_changes = Vec::new();
//         let mut prefixes_to_remove = Vec::new();
//         let mut prefixes_to_reselect = Vec::new();

//         // Find all prefixes that have routes from this peer
//         for (prefix, candidates) in self.entries.iter_mut() {
//             let original_len = candidates.len();

//             // Get current best path before removing routes
//             let old_best = self.routes.get(prefix).cloned();
//             let was_best_from_peer = old_best
//                 .as_ref()
//                 .map_or(false, |route| route.peer_addr == peer_addr);

//             // Remove routes from this peer
//             candidates.retain(|r| r.peer_addr != peer_addr);

//             if candidates.is_empty() {
//                 // No more candidates for this prefix
//                 prefixes_to_remove.push(*prefix);
//                 if let Some(removed_best) = self.routes.remove(prefix) {
//                     // Prefix completely removed: (prefix, old_best, None)
//                     rib_changes.push((*prefix, Some(removed_best), None));
//                 }
//             } else if original_len != candidates.len() && was_best_from_peer {
//                 // We removed route(s) from this peer and it was the best path
//                 // Need to reselect best path after the iteration
//                 prefixes_to_reselect.push((*prefix, old_best));
//             }
//         }

//         // Remove empty candidate entries
//         for prefix in prefixes_to_remove {
//             self.entries.remove(&prefix);
//         }

//         // Reselect best paths for affected prefixes
//         for (prefix, old_best) in prefixes_to_reselect {
//             if let Some(new_best) = self.select_best_path(prefix) {
//                 // Best path changed: (prefix, old_best, new_best)
//                 rib_changes.push((prefix, old_best, Some(new_best)));
//             } else if let Some(old) = old_best {
//                 // Only removal: (prefix, old_best, None)
//                 rib_changes.push((prefix, Some(old), None));
//             }
//         }

//         rib_changes
//     }
// }

/// Send a BGP route to the main RIB for installation
// pub fn send_route_to_rib(
//     bgp_route: &BgpRib,
//     rib_tx: &UnboundedSender<rib::Message>,
//     install: bool,
// ) -> Result<(), anyhow::Error> {
//     // Create RIB entry for BGP route
//     let mut rib_entry = RibEntry::new(RibType::Bgp);
//     rib_entry.rsubtype = RibSubType::Default;
//     rib_entry.valid = bgp_route.valid;
//     rib_entry.selected = bgp_route.best_path;
//     rib_entry.distance = 20; // BGP administrative distance
//     rib_entry.metric = bgp_route.med.unwrap_or(0);

//     // Create nexthop - convert IPv4 nexthop to IpAddr
//     let nexthop_uni = NexthopUni {
//         addr: IpAddr::V4(bgp_route.nexthop),
//         metric: bgp_route.med.unwrap_or(0),
//         weight: bgp_route.weight as u8,
//         ifindex: 0, // TODO: Resolve interface index from nexthop
//         valid: true,
//         mpls: Vec::new(),
//         mpls_label: Vec::new(),
//         gid: 0, // Will be assigned by RIB
//     };
//     rib_entry.nexthop = Nexthop::Uni(nexthop_uni);

//     // Convert prefix to IpNet
//     let prefix = bgp_route.prefix.clone();

//     // Send appropriate message to RIB
//     let msg = if install {
//         rib::Message::Ipv4Add {
//             prefix: prefix.prefix,
//             rib: rib_entry,
//         }
//     } else {
//         rib::Message::Ipv4Del {
//             prefix: prefix.prefix,
//             rib: rib_entry,
//         }
//     };

//     rib_tx
//         .send(msg)
//         .map_err(|e| anyhow::anyhow!("Failed to send route to RIB: {}", e))?;
//     Ok(())
// }

// Maintain backward compatibility
#[allow(dead_code)]
pub struct Route {
    pub from: IpAddr,
    pub attrs: Vec<Attr>,
    pub origin: u8,
    pub typ: PeerType,
    pub selected: bool,
}

#[derive(Default)]
struct Ipv4NlriVec {
    pub eor: bool,
    pub update: Vec<Ipv4Nlri>,
    pub withdraw: Vec<Ipv4Nlri>,
}

#[derive(Default)]
struct Vpnv4NlriVec {
    pub eor: bool,
    pub update: Vec<Vpnv4Net>,
    pub withdraw: Vec<Vpnv4Net>,
}

enum BgpNlri {
    Ipv4(Ipv4NlriVec),
    Vpnv4(Vpnv4NlriVec),
    Empty,
}

impl BgpNlri {
    fn from(packet: &UpdatePacket) -> Self {
        // IPv4 End of RIB.
        if packet.attrs.is_empty() {
            if packet.ipv4_update.is_empty() && packet.ipv4_withdraw.is_empty() {
                let eor = Ipv4NlriVec {
                    eor: true,
                    ..Default::default()
                };
                return BgpNlri::Ipv4(eor);
            }
        }
        // IPv4 updates.
        if !packet.ipv4_update.is_empty() {
            let update = Ipv4NlriVec {
                update: packet.ipv4_update.clone(),
                ..Default::default()
            };
            return BgpNlri::Ipv4(update);
        }
        if !packet.ipv4_withdraw.is_empty() {
            let withdraw = Ipv4NlriVec {
                withdraw: packet.ipv4_withdraw.clone(),
                ..Default::default()
            };
            return BgpNlri::Ipv4(withdraw);
        }
        BgpNlri::Empty
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Copy)]
pub enum BgpRibType {
    IBGP,
    EBGP,
    Originated,
}

impl BgpRibType {
    pub fn is_originated(&self) -> bool {
        *self == BgpRibType::Originated
    }
}

#[derive(Debug, Clone)]
pub struct BgpRib {
    // AddPath ID.
    pub id: u32,
    // BGP Attribute.
    pub attr: BgpAttr,
    // Peer ID.
    pub ident: IpAddr,
    // Peer router id.
    pub router_id: Ipv4Addr,
    // Weight
    pub weight: u32,
    // Route type.
    pub typ: BgpRibType,
    // Whether this candidate is currently the best path.
    pub best_path: bool,
}

impl BgpRib {
    pub fn new(
        ident: IpAddr,
        router_id: Ipv4Addr,
        rib_type: BgpRibType,
        id: u32,
        weight: u32,
        attr: &BgpAttr,
    ) -> Self {
        BgpRib {
            id,
            ident,
            router_id,
            attr: attr.clone(),
            weight,
            typ: rib_type,
            best_path: false,
        }
    }

    pub fn is_originated(&self) -> bool {
        self.typ.is_originated()
    }
}

#[derive(Debug, Default)]
pub struct LocalRib {
    // Best path routes per prefix
    pub routes: PrefixMap<Ipv4Net, BgpRib>,

    // All candidate routes per prefix (for show commands)
    pub entries: PrefixMap<Ipv4Net, Vec<BgpRib>>,
}

impl LocalRib {
    pub fn update_route(&mut self, prefix: Ipv4Net, rib: BgpRib) -> (Vec<BgpRib>, Vec<BgpRib>) {
        let candidates = self.entries.entry(prefix).or_default();
        let replaced: Vec<BgpRib> = candidates
            .extract_if(.., |r| r.ident == rib.ident && r.id == rib.id)
            .collect();
        candidates.push(rib.clone());

        let selected = self.select_best_path(prefix);

        (replaced, selected)
    }

    pub fn remove_route(&mut self, prefix: Ipv4Net, id: u32, ident: IpAddr) -> Vec<BgpRib> {
        let candidates = self.entries.entry(prefix).or_default();
        let removed: Vec<BgpRib> = candidates
            .extract_if(.., |r| r.ident == ident && r.id == id)
            .collect();
        removed
    }

    pub fn remove_peer_routes(&mut self, ident: IpAddr) -> Vec<BgpRib> {
        let mut all_removed: Vec<BgpRib> = Vec::new();
        for (prefix, candidates) in self.entries.iter_mut() {
            let mut removed: Vec<BgpRib> =
                candidates.extract_if(.., |r| r.ident == ident).collect();
            all_removed.append(&mut removed);
        }
        all_removed
    }

    pub fn select_best_path(&mut self, prefix: Ipv4Net) -> Vec<BgpRib> {
        let mut changes = Vec::new();
        let old_best = self.routes.get(&prefix).cloned();

        if !self.entries.contains_key(&prefix) {
            if let Some(mut removed_best) = self.routes.remove(&prefix) {
                removed_best.best_path = false;
                changes.push(removed_best);
            }
            return changes;
        }

        let is_empty = self
            .entries
            .get(&prefix)
            .map(|candidates| candidates.is_empty())
            .unwrap_or(true);

        if is_empty {
            self.entries.remove(&prefix);
            if let Some(mut removed_best) = self.routes.remove(&prefix) {
                removed_best.best_path = false;
                changes.push(removed_best);
            }
            return changes;
        }

        let best = {
            let candidates = self.entries.get_mut(&prefix).expect("prefix checked above");

            let mut best_index = 0usize;
            for index in 1..candidates.len() {
                if Self::is_better(&candidates[index], &candidates[best_index]) {
                    best_index = index;
                }
            }

            for rib in candidates.iter_mut() {
                rib.best_path = false;
            }
            candidates[best_index].best_path = true;
            candidates[best_index].clone()
        };

        let changed = match &old_best {
            Some(old) => old.ident != best.ident || old.id != best.id,
            None => true,
        };

        if changed {
            if let Some(mut previous) = old_best {
                previous.best_path = false;
                changes.push(previous);
            }
            self.routes.insert(prefix, best.clone());
            changes.push(best);
        } else {
            self.routes.insert(prefix, best);
        }

        changes
    }

    fn is_better(candidate: &BgpRib, incumbent: &BgpRib) -> bool {
        if candidate.weight != incumbent.weight {
            return candidate.weight > incumbent.weight;
        }

        let candidate_lp = Self::effective_local_pref(candidate);
        let incumbent_lp = Self::effective_local_pref(incumbent);
        if candidate_lp != incumbent_lp {
            return candidate_lp > incumbent_lp;
        }

        let candidate_local = matches!(candidate.typ, BgpRibType::Originated);
        let incumbent_local = matches!(incumbent.typ, BgpRibType::Originated);
        if candidate_local != incumbent_local {
            return candidate_local;
        }

        let candidate_as_len = Self::as_path_len(candidate);
        let incumbent_as_len = Self::as_path_len(incumbent);
        if candidate_as_len != incumbent_as_len {
            return candidate_as_len < incumbent_as_len;
        }

        let candidate_origin_rank = Self::origin_rank(candidate.attr.origin);
        let incumbent_origin_rank = Self::origin_rank(incumbent.attr.origin);
        if candidate_origin_rank != incumbent_origin_rank {
            return candidate_origin_rank < incumbent_origin_rank;
        }

        if candidate.ident == incumbent.ident {
            let candidate_med = candidate.attr.med.clone().unwrap_or(Med::default());
            let incumbent_med = incumbent.attr.med.clone().unwrap_or(Med::default());
            if candidate_med != incumbent_med {
                return candidate_med < incumbent_med;
            }
        }

        let candidate_type_rank = Self::route_type_rank(candidate.typ);
        let incumbent_type_rank = Self::route_type_rank(incumbent.typ);
        if candidate_type_rank != incumbent_type_rank {
            return candidate_type_rank < incumbent_type_rank;
        }

        if candidate.ident != incumbent.ident {
            return candidate.ident < incumbent.ident;
        }

        if candidate.id != incumbent.id {
            return candidate.id < incumbent.id;
        }

        false
    }

    fn effective_local_pref(rib: &BgpRib) -> u32 {
        if let Some(ref attr) = rib.attr.local_pref {
            attr.local_pref
        } else {
            LocalPref::DEFAULT
        }
    }

    fn as_path_len(rib: &BgpRib) -> u32 {
        rib.attr
            .aspath
            .as_ref()
            .map(|path| path.length)
            .unwrap_or(0)
    }

    fn origin_rank(origin: Option<Origin>) -> u8 {
        match origin.unwrap_or(Origin::Incomplete) {
            Origin::Igp => 0,
            Origin::Egp => 1,
            Origin::Incomplete => 2,
        }
    }

    fn route_type_rank(typ: BgpRibType) -> u8 {
        match typ {
            BgpRibType::Originated => 0,
            BgpRibType::EBGP => 1,
            BgpRibType::IBGP => 2,
        }
    }
}

// RIB update from peer.
pub fn route_ipv4_update(peer: &mut Peer, nlri: &Ipv4Nlri, attr: &BgpAttr, bgp: &mut ConfigRef) {
    // RFC 4271: Drop update if local AS appears in AS_PATH (loop detection for EBGP)
    // This prevents routing loops by detecting if the route has already passed through this AS
    if let Some(ref aspath) = attr.aspath {
        for segment in &aspath.segs {
            if segment.asn.contains(&peer.local_as) {
                eprintln!(
                    "Dropping update for {} from peer {} - local AS {} found in AS_PATH",
                    nlri.prefix, peer.address, peer.local_as
                );
                return;
            }
        }
    }

    // RFC 4456: Drop update if ORIGINATOR_ID matches local router ID. This
    // prevents routing loops in route reflection scenarios. This happens before
    // the route store in AdjRibIn.
    if let Some(ref originator_id) = attr.originator_id {
        if originator_id.id == *bgp.router_id {
            eprintln!(
                "Dropping update for {} from peer {} - ORIGINATOR_ID {} matches local router ID",
                nlri.prefix, peer.address, originator_id.id
            );
            return;
        }
    }

    // Identify peer_type
    let typ = if peer.is_ibgp() {
        BgpRibType::IBGP
    } else {
        BgpRibType::EBGP
    };
    // Create BGP RIB with weight value 0.
    let rib = BgpRib::new(peer.ident, peer.router_id, typ, nlri.id, 0, attr);

    // Register to peer's AdjRibIn.
    peer.adj_rib_in.add_route(nlri.prefix, rib.clone());

    // Perform BGP Path selection.
    let (replaced, selected) = bgp.local_rib.update_route(nlri.prefix, rib);
    if replaced.is_empty() {
        peer.stat.rx_inc(Afi::Ip, Safi::Unicast);
    }

    // Need to advertise to peers.
}

pub fn route_ipv4_withdraw(peer: &mut Peer, nlri: &Ipv4Nlri, bgp: &mut ConfigRef) {
    // Remove from AdjRibIn.
    peer.adj_rib_in.remove_route(nlri.prefix, nlri.id);

    // BGP Path selection.
    let removed = bgp.local_rib.remove_route(nlri.prefix, nlri.id, peer.ident);
    if !removed.is_empty() {
        peer.stat.rx_dec(Afi::Ip, Safi::Unicast);
    }
}

pub fn route_from_peer(peer: &mut Peer, packet: UpdatePacket, bgp: &mut ConfigRef) {
    // Convert UpdatePacket to BgpAttr.
    let attr = BgpAttr::from(&packet.attrs);
    // print!("{}", attr);

    // Convert UpdatePacket to BgpNlri.
    let nlri = BgpNlri::from(&packet);

    // Process NLRI.
    use BgpNlri::*;
    match nlri {
        Ipv4(nlri) => {
            if nlri.eor {
                println!("IPv4 EoR");
            }
            for update in nlri.update.iter() {
                println!("IPv4 Update: {}", update.prefix);
                route_ipv4_update(peer, update, &attr, bgp);
            }
            for withdraw in nlri.withdraw.iter() {
                println!("IPv4 Withdraw: {}", withdraw.prefix);
                route_ipv4_withdraw(peer, withdraw, bgp);
            }
        }
        _ => {
            //
        }
    }
}

pub fn route_clean(peer: &mut Peer, bgp: &mut ConfigRef) {
    // IPv4 Unicast.
    bgp.local_rib.remove_peer_routes(peer.ident);
    // IPv4 Unicast AdjIn/AdjOut.
    peer.adj_rib_in.routes.clear();
    peer.adj_rib_out.routes.clear();
}

pub fn route_update_ipv4(
    peer: &mut Peer,
    prefix: &Ipv4Net,
    rib: &BgpRib,
    bgp: &mut ConfigRef,
) -> Option<(Ipv4Nlri, BgpAttr)> {
    // Split-horizon: Don't send route back to the peer that sent it
    if rib.ident == peer.ident {
        return None;
    }

    // IBGP to IBGP: Don't advertise IBGP-learned routes.
    if peer.peer_type == PeerType::IBGP && rib.typ == BgpRibType::IBGP {
        return None;
    }

    // Check if we should use add-path
    let mp = CapMultiProtocol::new(&Afi::Ip, &Safi::Unicast);
    let use_addpath = peer.cap_map.entries.get(&mp).map_or(false, |cap| cap.send);

    // Create NLRI with optional path ID
    let nlri = Ipv4Nlri {
        id: if use_addpath { rib.id } else { 0 },
        prefix: *prefix,
    };

    // Build attributes
    let mut attrs = rib.attr.clone();

    // 1. Origin.  Pass through

    // 2. AS_PATH
    if peer.is_ebgp() {
        if let Some(ref mut aspath) = attrs.aspath {
            let local_as_path = As4Path::from(vec![peer.local_as]);
            aspath.prepend_mut(local_as_path.clone());
        }
    }

    // 3. NEXT_HOP
    if peer.is_ebgp() || rib.is_originated() {
        let nexthop = if let Some(ref local_addr) = peer.param.local_addr
            && let IpAddr::V4(local_addr) = local_addr.ip()
        {
            local_addr
        } else {
            *bgp.router_id
        };
        attrs.nexthop = Some(BgpNexthop::Ipv4(nexthop));
    };

    // 4. MED - Pass through.

    // 5. Local Preference (for IBGP only)
    if peer.is_ibgp() {
        if attrs.local_pref.is_none() {
            attrs.local_pref = Some(LocalPref::default());
        }
    }

    // // 9. Originator ID (for IBGP)
    // if peer.peer_type == PeerType::IBGP {
    //     if let Some(ref originator_id) = rib.attr.originator_id {
    //         attrs.push(Attr::OriginatorId(originator_id.clone()));
    //     }
    // }

    // // 10. Cluster List (for IBGP)
    // if peer.peer_type == PeerType::IBGP {
    //     if let Some(ref cluster_list) = rib.attr.cluster_list {
    //         attrs.push(Attr::ClusterList(cluster_list.clone()));
    //     }
    // }

    Some((nlri, attrs))
}

pub fn route_send_ipv4(peer: &mut Peer, nlri: Ipv4Nlri, bgp_attr: BgpAttr) {
    let mut update = UpdatePacket::new();
    let attrs = bgp_attr.to();
    update.attrs = attrs;
    update.ipv4_update.push(nlri);

    // Convert to bytes and send
    let bytes: BytesMut = update.into();

    if let Some(ref packet_tx) = peer.packet_tx {
        if let Err(e) = packet_tx.send(bytes) {
            eprintln!("Failed to send BGP Update to {}: {}", peer.address, e);
        } else {
            // Update statistics
            peer.stat.tx_inc(Afi::Ip, Safi::Unicast);
        }
    }
}

pub fn route_apply_policy_out(
    peer: &mut Peer,
    nlri: &Ipv4Nlri,
    bgp_attr: BgpAttr,
) -> Option<BgpAttr> {
    // Apply prefix-set out.
    let config = peer.prefix_set.get(&InOut::Output);
    if let Some(name) = &config.name {
        let Some(prefix_set) = &config.prefix else {
            return None;
        };
        if !prefix_set.matches(nlri.prefix) {
            return None;
        }
    }
    Some(bgp_attr)
}

pub fn route_sync_ipv4(peer: &mut Peer, bgp: &mut ConfigRef) {
    // Collect all routes first to avoid borrow checker issues
    let routes: Vec<(Ipv4Net, BgpRib)> = bgp
        .local_rib
        .routes
        .iter()
        .map(|(prefix, rib)| (*prefix, rib.clone()))
        .collect();

    // Advertise all best paths to the peer
    for (prefix, mut rib) in routes {
        let Some((nlri, attr)) = route_update_ipv4(peer, &prefix, &rib, bgp) else {
            continue;
        };

        let Some(attr) = route_apply_policy_out(peer, &nlri, attr) else {
            continue;
        };

        // Register to AdjOut.
        rib.attr = attr.clone();
        peer.adj_rib_out.add_route(nlri.prefix, rib);

        // Send the routes.
        route_send_ipv4(peer, nlri, attr);
    }

    // Send End-of-RIB marker for IPv4 Unicast
    send_eor_ipv4_unicast(peer);
}

/// Send End-of-RIB marker for IPv4 Unicast
fn send_eor_ipv4_unicast(peer: &mut Peer) {
    // End-of-RIB is an empty Update packet (no attributes, no NLRI, no withdrawals)
    let update = UpdatePacket::new();
    let bytes: BytesMut = update.into();

    if let Some(ref packet_tx) = peer.packet_tx {
        if let Err(e) = packet_tx.send(bytes) {
            eprintln!("Failed to send End-of-RIB to {}: {}", peer.address, e);
        }
    }
}

// Called when peer has been established.
pub fn route_sync(peer: &mut Peer, bgp: &mut ConfigRef) {
    // Advertize.
    let afi = CapMultiProtocol::new(&Afi::Ip, &Safi::Unicast);
    if let Some(cap) = peer.cap_map.entries.get(&afi) {
        if cap.send && cap.recv {
            route_sync_ipv4(peer, bgp);
        }
    }
    let afi = CapMultiProtocol::new(&Afi::Ip, &Safi::MplsVpn);
    if let Some(cap) = peer.cap_map.entries.get(&afi) {
        if cap.send && cap.recv {
            // route_sync_vpnv4(peer, bgp);
        }
    }
}

impl Bgp {
    pub fn route_add(&mut self, prefix: Ipv4Net) {
        let ident = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        let attr = BgpAttr::new();
        let rib = BgpRib::new(
            ident,
            Ipv4Addr::UNSPECIFIED,
            BgpRibType::Originated,
            0,
            32768,
            &attr,
        );
        let (replaced, selected) = self.local_rib.update_route(prefix, rib);
        // XXX
    }

    pub fn route_del(&mut self, prefix: Ipv4Net) {
        let ident = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        let removed = self.local_rib.remove_route(prefix, 0, ident);
    }
}
