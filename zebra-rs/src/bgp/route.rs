use std::collections::{BTreeMap, VecDeque};
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

    // Return selected best path, not the change history.
    pub fn select_best_path(&mut self, prefix: Ipv4Net) -> Vec<BgpRib> {
        let mut selected = Vec::new();

        if !self.entries.contains_key(&prefix) {
            self.routes.remove(&prefix);
            return selected;
        }

        let is_empty = self
            .entries
            .get(&prefix)
            .map(|candidates| candidates.is_empty())
            .unwrap_or(true);

        if is_empty {
            self.entries.remove(&prefix);
            self.routes.remove(&prefix);
            return selected;
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

        self.routes.insert(prefix, best.clone());
        selected.push(best);

        selected
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

        // RFC 4456: Prefer path with shorter CLUSTER_LIST length (fewer route reflector hops)
        // let candidate_cluster_len = candidate
        //     .attr
        //     .cluster_list
        //     .as_ref()
        //     .map_or(0, |cl| cl.list.len());
        // let incumbent_cluster_len = incumbent
        //     .attr
        //     .cluster_list
        //     .as_ref()
        //     .map_or(0, |cl| cl.list.len());
        // if candidate_cluster_len != incumbent_cluster_len {
        //     return candidate_cluster_len < incumbent_cluster_len;
        // }

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
pub fn route_ipv4_update(
    peer_id: IpAddr,
    nlri: &Ipv4Nlri,
    attr: &BgpAttr,
    bgp: &mut ConfigRef,
    peers: &mut BTreeMap<IpAddr, Peer>,
) {
    // Validate and extract peer information in a separate scope to release the borrow
    let (peer_ident, peer_router_id, typ, should_process) = {
        let peer = peers.get_mut(&peer_id).expect("peer must exist");

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

        // RFC 4456: Drop update if local router ID is in CLUSTER_LIST. This
        // prevents routing loops in route reflection scenarios when the route
        // has already passed through this route reflector.
        if let Some(ref cluster_list) = attr.cluster_list {
            if cluster_list.list.contains(&bgp.router_id) {
                eprintln!(
                    "Dropping update for {} from peer {} - local router ID {} found in CLUSTER_LIST",
                    nlri.prefix, peer.address, bgp.router_id
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

        (peer.ident, peer.remote_id, typ, true)
    };

    if !should_process {
        return;
    }

    // Create BGP RIB with weight value 0.
    let rib = BgpRib::new(peer_ident, peer_router_id, typ, nlri.id, 0, attr);

    // Register to peer's AdjRibIn and update stats
    {
        let peer = peers.get_mut(&peer_id).expect("peer must exist");
        peer.adj_rib_in.add_route(nlri.prefix, rib.clone());
    }

    // Perform BGP Path selection.
    let (replaced, selected) = bgp.local_rib.update_route(nlri.prefix, rib);

    // Advertise to peers if best path changed.
    if !selected.is_empty() {
        route_advertise_to_peers(nlri.prefix, &selected, peer_ident, bgp, peers);
    }
}

/// Advertise route changes to all appropriate peers
fn route_advertise_to_peers(
    prefix: Ipv4Net,
    selected: &[BgpRib],
    source_peer: IpAddr,
    bgp: &mut ConfigRef,
    peers: &mut BTreeMap<IpAddr, Peer>,
) {
    // Get the new best path (last entry in selected vector)
    let new_best = selected.last();

    // Collect peer addresses that need updates to avoid borrow checker issues
    let peer_addrs: Vec<IpAddr> = peers
        .iter()
        .filter(|(_, p)| p.state.is_established())
        .map(|(addr, _)| *addr)
        .collect();

    for peer_addr in peer_addrs {
        // Build the update/withdrawal for this peer
        let (nlri_opt, attr_opt) = {
            let peer = peers.get_mut(&peer_addr).expect("peer exists");

            if let Some(best) = new_best {
                // Try to advertise the new best path
                if let Some((nlri, attr)) = route_update_ipv4(peer, &prefix, best, bgp) {
                    // Apply outbound policy
                    if let Some(attr) = route_apply_policy_out(peer, &nlri, attr) {
                        (Some(nlri), Some(attr))
                    } else {
                        (Some(nlri), None) // Policy denied - will send withdrawal
                    }
                } else {
                    (None, None) // Filtered by split-horizon, etc.
                }
            } else {
                (None, None) // No best path
            }
        };

        // Now apply the update/withdrawal
        let peer = peers.get_mut(&peer_addr).expect("peer exists");

        match (nlri_opt, attr_opt) {
            (Some(nlri), Some(attr)) => {
                // Send update
                if let Some(best) = new_best {
                    let mut rib = best.clone();
                    rib.attr = attr.clone();
                    peer.adj_rib_out.add_route(nlri.prefix, rib);
                }
                route_send_ipv4(peer, nlri, attr);
            }
            _ => {
                // Send withdrawal if we had previously advertised
                if peer.adj_rib_out.routes.contains_key(&prefix) {
                    route_withdraw_ipv4(peer, prefix, 0);
                    peer.adj_rib_out.remove_route(prefix, 0);
                }
            }
        }
    }
}

/// Send BGP withdrawal for a prefix
fn route_withdraw_ipv4(peer: &mut Peer, prefix: Ipv4Net, id: u32) {
    let mut update = UpdatePacket::new();

    // Check if we should use add-path
    let mp = CapMultiProtocol::new(&Afi::Ip, &Safi::Unicast);
    let use_addpath = peer.cap_map.entries.get(&mp).map_or(false, |cap| cap.send);

    let nlri = Ipv4Nlri {
        id: if use_addpath { id } else { 0 },
        prefix,
    };
    update.ipv4_withdraw.push(nlri);

    // Convert to bytes and send
    let bytes: BytesMut = update.into();

    if let Some(ref packet_tx) = peer.packet_tx {
        if let Err(e) = packet_tx.send(bytes) {
            eprintln!("Failed to send BGP Withdrawal to {}: {}", peer.address, e);
        }
    }
}

pub fn route_ipv4_withdraw(
    peer_id: IpAddr,
    nlri: &Ipv4Nlri,
    bgp: &mut ConfigRef,
    peers: &mut BTreeMap<IpAddr, Peer>,
) {
    let peer_ident = {
        let peer = peers.get_mut(&peer_id).expect("peer must exist");
        // Remove from AdjRibIn.
        peer.adj_rib_in.remove_route(nlri.prefix, nlri.id);
        peer.ident
    };

    // BGP Path selection - this may select a new best path
    let removed = bgp.local_rib.remove_route(nlri.prefix, nlri.id, peer_ident);

    // Re-run best path selection and advertise changes
    let selected = bgp.local_rib.select_best_path(nlri.prefix);
    if !selected.is_empty() || !removed.is_empty() {
        route_advertise_to_peers(nlri.prefix, &selected, peer_ident, bgp, peers);
    }
}

pub fn route_from_peer(
    peer_id: IpAddr,
    packet: UpdatePacket,
    bgp: &mut ConfigRef,
    peers: &mut BTreeMap<IpAddr, Peer>,
) {
    // Convert UpdatePacket to BgpAttr.
    let attr = BgpAttr::from(&packet.attrs);

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
                route_ipv4_update(peer_id, update, &attr, bgp, peers);
            }
            for withdraw in nlri.withdraw.iter() {
                println!("IPv4 Withdraw: {}", withdraw.prefix);
                route_ipv4_withdraw(peer_id, withdraw, bgp, peers);
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

    // iBGP to iBGP: Don't advertise iBGP-learned routes except the peer is
    // route reflector client.
    if peer.peer_type == PeerType::IBGP
        && rib.typ == BgpRibType::IBGP
        && !peer.is_reflector_client()
    {
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

    // 6. Originator ID (for IBGP route reflection)
    // RFC 4456: A route reflector SHOULD NOT create an ORIGINATOR_ID if one already
    // exists. ORIGINATOR_ID is set only once by the first route reflector and preserved
    // thereafter to identify the original route source within the AS.
    if peer.peer_type == PeerType::IBGP && rib.typ == BgpRibType::IBGP {
        if attrs.originator_id.is_none() {
            // Set ORIGINATOR_ID to the router ID of the peer that originated this route
            attrs.originator_id = Some(OriginatorId::new(rib.router_id));
        }
        // If ORIGINATOR_ID already exists, preserve it (don't overwrite)
    }

    // 7. Cluster List (for IBGP route reflection)
    // RFC 4456: When a route reflector reflects a route, it must prepend the local
    // CLUSTER_ID to the CLUSTER_LIST. By default, the CLUSTER_ID is the router ID.
    if peer.peer_type == PeerType::IBGP && rib.typ == BgpRibType::IBGP {
        if let Some(ref mut cluster_list) = attrs.cluster_list {
            // Prepend local router ID to existing cluster list
            cluster_list.list.insert(0, *bgp.router_id);
        } else {
            // Create new cluster list with local router ID
            let mut cluster_list = ClusterList::new();
            cluster_list.list.push(*bgp.router_id);
            attrs.cluster_list = Some(cluster_list);
        }
    }

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

        let mut bgp_ref = ConfigRef {
            router_id: &self.router_id,
            local_rib: &mut self.local_rib,
            rib_tx: &self.rib_tx,
        };

        if !selected.is_empty() {
            let mut peer_map = std::mem::take(&mut self.peers);
            route_advertise_to_peers(prefix, &selected, ident, &mut bgp_ref, &mut peer_map);
            self.peers = peer_map;
        }
    }

    pub fn route_del(&mut self, prefix: Ipv4Net) {
        let ident = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        let id = 0;
        let removed = self.local_rib.remove_route(prefix, id, ident);

        let mut bgp_ref = ConfigRef {
            router_id: &self.router_id,
            local_rib: &mut self.local_rib,
            rib_tx: &self.rib_tx,
        };

        let selected = bgp_ref.local_rib.select_best_path(prefix);
        if !selected.is_empty() || !removed.is_empty() {
            let mut peer_map = std::mem::take(&mut self.peers);
            route_advertise_to_peers(prefix, &selected, ident, &mut bgp_ref, &mut peer_map);
            self.peers = peer_map;
        }
    }
}
