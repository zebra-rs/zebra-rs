use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::net::{IpAddr, Ipv4Addr};

use bgp_packet::*;
use bytes::BytesMut;
use ipnet::Ipv4Net;
use prefix_trie::PrefixMap;

use super::cap::CapAfiMap;
use super::peer::{ConfigRef, Peer, PeerType};
use super::{Bgp, InOut};

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
    // AddPath ID from peer.
    pub remote_id: u32,
    // AddPath ID from peer.
    pub local_id: u32,
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
    // Label.
    pub label: Option<Label>,
    // Nexthop.
    pub nexthop: Option<Vpnv4Nexthop>,
}

impl BgpRib {
    pub fn new(
        ident: IpAddr,
        router_id: Ipv4Addr,
        rib_type: BgpRibType,
        id: u32,
        weight: u32,
        attr: &BgpAttr,
        label: Option<Label>,
        nexthop: Option<Vpnv4Nexthop>,
    ) -> Self {
        BgpRib {
            remote_id: id,
            local_id: 0, // Will be assigned in LocalRibTable::update_route()
            ident,
            router_id,
            attr: attr.clone(),
            weight,
            typ: rib_type,
            best_path: false,
            label,
            nexthop,
        }
    }

    pub fn is_originated(&self) -> bool {
        self.typ.is_originated()
    }
}

#[derive(Debug, Default)]
pub struct LocalRibTable(
    pub PrefixMap<Ipv4Net, Vec<BgpRib>>, // Candidates.
    pub PrefixMap<Ipv4Net, BgpRib>,      // Selected.
);

impl LocalRibTable {
    pub fn update_route(
        &mut self,
        prefix: Ipv4Net,
        rib: BgpRib,
    ) -> (Vec<BgpRib>, Vec<BgpRib>, u32) {
        let candidates = self.0.entry(prefix).or_default();

        // Find if we're replacing an existing route (same peer ident and path ID)
        let existing_local_id = candidates
            .iter()
            .find(|r| r.ident == rib.ident && r.remote_id == rib.remote_id)
            .map(|r| r.local_id);

        // Extract routes being replaced
        let replaced: Vec<BgpRib> = candidates
            .extract_if(.., |r| r.ident == rib.ident && r.remote_id == rib.remote_id)
            .collect();

        // Allocate local_id for the new/updated rib
        let mut next_id = 1u32;
        let mut new_rib = rib.clone();
        if let Some(local_id) = existing_local_id {
            // Reuse the local_id from the replaced route
            new_rib.local_id = local_id;
        } else {
            // Allocate a new local_id - find smallest unused positive integer
            let used_ids: std::collections::HashSet<u32> =
                candidates.iter().map(|r| r.local_id).collect();

            while used_ids.contains(&next_id) {
                next_id += 1;
            }
            new_rib.local_id = next_id;
        }

        candidates.push(new_rib);

        let selected = self.select_best_path(prefix);

        (replaced, selected, next_id)
    }

    pub fn remove_route(&mut self, prefix: Ipv4Net, id: u32, ident: IpAddr) -> Vec<BgpRib> {
        let candidates = self.0.entry(prefix).or_default();
        let removed: Vec<BgpRib> = candidates
            .extract_if(.., |r| r.ident == ident && r.remote_id == id)
            .collect();
        removed
    }

    pub fn remove_peer_routes(&mut self, ident: IpAddr) -> Vec<BgpRib> {
        let mut all_removed: Vec<BgpRib> = Vec::new();
        for (_prefix, candidates) in self.0.iter_mut() {
            let mut removed: Vec<BgpRib> =
                candidates.extract_if(.., |r| r.ident == ident).collect();
            all_removed.append(&mut removed);
        }
        all_removed
    }

    // Return selected best path, not the change history.
    pub fn select_best_path(&mut self, prefix: Ipv4Net) -> Vec<BgpRib> {
        let mut selected = Vec::new();

        if !self.0.contains_key(&prefix) {
            self.1.remove(&prefix);
            return selected;
        }

        let is_empty = self
            .0
            .get(&prefix)
            .map(|candidates| candidates.is_empty())
            .unwrap_or(true);

        if is_empty {
            self.0.remove(&prefix);
            self.1.remove(&prefix);
            return selected;
        }

        let best = {
            let candidates = self.0.get_mut(&prefix).expect("prefix checked above");

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

        self.1.insert(prefix, best.clone());
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

        if candidate.remote_id != incumbent.remote_id {
            return candidate.remote_id < incumbent.remote_id;
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

#[derive(Debug, Default)]
pub struct LocalRib {
    pub v4: LocalRibTable,

    pub v4vpn: BTreeMap<RouteDistinguisher, LocalRibTable>,
}

impl LocalRib {
    pub fn update_route(
        &mut self,
        prefix: Ipv4Net,
        rib: BgpRib,
    ) -> (Vec<BgpRib>, Vec<BgpRib>, u32) {
        self.v4.update_route(prefix, rib)
    }

    pub fn remove_route(&mut self, prefix: Ipv4Net, id: u32, ident: IpAddr) -> Vec<BgpRib> {
        self.v4.remove_route(prefix, id, ident)
    }

    pub fn remove_peer_routes(&mut self, ident: IpAddr) -> Vec<BgpRib> {
        self.v4.remove_peer_routes(ident)
    }

    // Return selected best path, not the change history.
    pub fn select_best_path(&mut self, prefix: Ipv4Net) -> Vec<BgpRib> {
        self.v4.select_best_path(prefix)
    }

    // VRF update.
    pub fn update_route_vpn(
        &mut self,
        rd: &RouteDistinguisher,
        prefix: Ipv4Net,
        rib: BgpRib,
    ) -> (Vec<BgpRib>, Vec<BgpRib>, u32) {
        self.v4vpn
            .entry(rd.clone())
            .or_default()
            .update_route(prefix, rib)
    }

    pub fn remove_route_vpn(
        &mut self,
        rd: &RouteDistinguisher,
        prefix: Ipv4Net,
        id: u32,
        ident: IpAddr,
    ) -> Vec<BgpRib> {
        self.v4vpn
            .entry(rd.clone())
            .or_default()
            .remove_route(prefix, id, ident)
    }

    // Return selected best path, not the change history.
    pub fn select_best_path_vpn(
        &mut self,
        rd: &RouteDistinguisher,
        prefix: Ipv4Net,
    ) -> Vec<BgpRib> {
        self.v4vpn
            .entry(rd.clone())
            .or_default()
            .select_best_path(prefix)
    }
}

// RIB update from peer.
pub fn route_ipv4_update(
    peer_id: IpAddr,
    nlri: &Ipv4Nlri,
    rd: Option<RouteDistinguisher>,
    label: Option<Label>,
    attr: &BgpAttr,
    nexthop: Option<Vpnv4Nexthop>,
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

    // Create BGP RIB with weight value 0. XXX We are going to include
    // BgpNexthop as part of BgpAttr. Since we want to consolidate BGP updates.
    let mut rib = BgpRib::new(
        peer_ident,
        peer_router_id,
        typ,
        nlri.id,
        0,
        attr,
        label,
        nexthop,
    );

    // Register to peer's AdjRibIn and update stats
    {
        let peer = peers.get_mut(&peer_id).expect("peer must exist");
        peer.adj_in.add(rd, nlri.prefix, rib.clone());
    }

    // Perform BGP Path selection.
    let (_replaced, selected, next_id) = if let Some(ref rd) = rd {
        bgp.local_rib.update_route_vpn(rd, nlri.prefix, rib.clone())
    } else {
        bgp.local_rib.update_route(nlri.prefix, rib.clone())
    };

    // Advertise to peers if best path changed.
    if !selected.is_empty() {
        route_advertise_to_peers(rd.clone(), nlri.prefix, &selected, peer_ident, bgp, peers);
    }
    rib.local_id = next_id;
    route_advertise_to_addpath(rd, nlri.prefix, &rib, peer_ident, bgp, peers);
}

fn route_advertise_to_addpath(
    rd: Option<RouteDistinguisher>,
    prefix: Ipv4Net,
    rib: &BgpRib,
    _source_peer: IpAddr,
    bgp: &mut ConfigRef,
    peers: &mut BTreeMap<IpAddr, Peer>,
) {
    let (afi, safi) = if rd.is_some() {
        (Afi::Ip, Safi::MplsVpn)
    } else {
        (Afi::Ip, Safi::Unicast)
    };

    let peer_addrs: Vec<IpAddr> = peers
        .iter()
        .filter(|(_, p)| p.state.is_established())
        .filter(|(_, p)| p.is_afi_safi(afi, safi))
        .filter(|(_, p)| p.opt.is_add_path_send(afi, safi))
        .map(|(addr, _)| *addr)
        .collect();

    for peer_addr in peer_addrs {
        let peer = peers.get_mut(&peer_addr).expect("peer exists");

        if let Some((nlri, attr)) = route_update_ipv4(peer, &prefix, rib, bgp, true) {
            if let Some(attr) = route_apply_policy_out(peer, &nlri, attr) {
                let mut rib = rib.clone();
                rib.attr = attr.clone();

                peer.adj_out.add(rd, nlri.prefix, rib);
                if let Some(ref rd) = rd {
                    let vpnv4_nlri = Vpnv4Nlri {
                        label: Label::default(),
                        rd: rd.clone(),
                        nlri,
                    };
                    route_send_vpnv4(peer, vpnv4_nlri, attr);
                } else {
                    route_send_ipv4(peer, nlri, attr);
                }
            }
        }
    }
}

fn route_withdraw_from_addpath(
    rd: Option<RouteDistinguisher>,
    prefix: Ipv4Net,
    removed: &BgpRib,
    _source_peer: IpAddr,
    _bgp: &mut ConfigRef,
    peers: &mut BTreeMap<IpAddr, Peer>,
) {
    let (afi, safi) = if rd.is_some() {
        (Afi::Ip, Safi::MplsVpn)
    } else {
        (Afi::Ip, Safi::Unicast)
    };

    let peer_addrs: Vec<IpAddr> = peers
        .iter()
        .filter(|(_, p)| p.state.is_established())
        .filter(|(_, p)| p.is_afi_safi(afi, safi))
        .filter(|(_, p)| p.opt.is_add_path_send(afi, safi))
        .map(|(addr, _)| *addr)
        .collect();

    for peer_addr in peer_addrs {
        let peer = peers.get_mut(&peer_addr).expect("peer exists");

        if let Some(ref rd) = rd {
            route_withdraw_ipv4(peer, Some(rd.clone()), prefix, removed.local_id);
        } else {
            route_withdraw_ipv4(peer, None, prefix, removed.local_id);
        }
        peer.adj_out.remove(rd, prefix, removed.local_id);
    }
}

/// Advertise route changes to all appropriate peers
fn route_advertise_to_peers(
    rd: Option<RouteDistinguisher>,
    prefix: Ipv4Net,
    selected: &[BgpRib],
    _source_peer: IpAddr,
    bgp: &mut ConfigRef,
    peers: &mut BTreeMap<IpAddr, Peer>,
) {
    // Get the new best path (last entry in selected vector)
    let new_best = selected.last();

    // Collect peer addresses that need updates to avoid borrow checker issues
    let (afi, safi) = if rd.is_some() {
        (Afi::Ip, Safi::MplsVpn)
    } else {
        (Afi::Ip, Safi::Unicast)
    };

    let peer_addrs: Vec<IpAddr> = peers
        .iter()
        .filter(|(_, p)| p.state.is_established())
        .filter(|(_, p)| p.is_afi_safi(afi, safi))
        .filter(|(_, p)| !p.opt.is_add_path_send(afi, safi))
        .map(|(addr, _)| *addr)
        .collect();

    for peer_addr in peer_addrs {
        let peer = peers.get_mut(&peer_addr).expect("peer exists");

        let add_path = peer.opt.is_add_path_send(afi, safi);

        // Build the update/withdrawal for this peer
        let (nlri_opt, attr_opt) = {
            if let Some(best) = new_best {
                // Try to advertise the new best path
                if let Some((nlri, attr)) = route_update_ipv4(peer, &prefix, best, bgp, add_path) {
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
        match (nlri_opt, attr_opt) {
            (Some(nlri), Some(attr)) => {
                // Send update
                if let Some(best) = new_best {
                    let mut rib = best.clone();
                    rib.attr = attr.clone();
                    peer.adj_out.add(rd, nlri.prefix, rib);
                }
                if let Some(ref rd) = rd {
                    let vpnv4_nlri = Vpnv4Nlri {
                        label: Label::default(),
                        rd: rd.clone(),
                        nlri,
                    };
                    route_send_vpnv4(peer, vpnv4_nlri, attr);
                } else {
                    route_send_ipv4(peer, nlri, attr);
                }
            }
            _ => {
                // Send withdrawal if we had previously advertised
                if peer.adj_out.contains_key(rd, &prefix) {
                    route_withdraw_ipv4(peer, rd, prefix, 0);
                    peer.adj_out.remove(rd, prefix, 0);
                }
            }
        }
    }
}

// Send BGP withdrawal for a prefix
fn route_withdraw_ipv4(peer: &mut Peer, rd: Option<RouteDistinguisher>, prefix: Ipv4Net, id: u32) {
    let mut update = UpdatePacket::new();

    match rd {
        Some(rd) => {
            let vpnv4_nlri = Vpnv4Nlri {
                label: Label::default(),
                rd,
                nlri: Ipv4Nlri { id, prefix },
            };
            let mp_withdraw = MpNlriUnreachAttr::Vpnv4(vec![vpnv4_nlri]);
            update.mp_withdraw = Some(mp_withdraw);
        }
        None => {
            let nlri = Ipv4Nlri { id, prefix };
            update.ipv4_withdraw.push(nlri);
        }
    }

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
    rd: Option<RouteDistinguisher>,
    _label: Option<Label>,
    bgp: &mut ConfigRef,
    peers: &mut BTreeMap<IpAddr, Peer>,
) {
    // TODO: fill in data.
    let peer_ident = {
        let peer = peers.get_mut(&peer_id).expect("peer must exist");
        peer.adj_in.remove(rd, nlri.prefix, nlri.id);
        peer.ident
    };

    // BGP Path selection - this may select a new best path
    let mut removed = if let Some(ref rd) = rd {
        bgp.local_rib
            .remove_route_vpn(rd, nlri.prefix, nlri.id, peer_ident)
    } else {
        bgp.local_rib.remove_route(nlri.prefix, nlri.id, peer_ident)
    };

    // Re-run best path selection and advertise changes
    let selected = if let Some(ref rd) = rd {
        bgp.local_rib.select_best_path_vpn(rd, nlri.prefix)
    } else {
        bgp.local_rib.select_best_path(nlri.prefix)
    };
    if !selected.is_empty() || !removed.is_empty() {
        route_advertise_to_peers(rd.clone(), nlri.prefix, &selected, peer_ident, bgp, peers);
    }
    if let Some(removed) = removed.pop() {
        route_withdraw_from_addpath(rd, nlri.prefix, &removed, peer_ident, bgp, peers);
    }
}

pub fn route_from_peer(
    peer_id: IpAddr,
    packet: UpdatePacket,
    bgp: &mut ConfigRef,
    peers: &mut BTreeMap<IpAddr, Peer>,
) {
    // Convert UpdatePacket to BgpAttr.
    // let attr = BgpAttr::from(&packet.attrs);

    // Convert UpdatePacket to BgpNlri.
    // let nlri = BgpNlriAttr::from(&packet);
    if let Some(bgp_attr) = &packet.bgp_attr {
        for update in packet.ipv4_update.iter() {
            route_ipv4_update(peer_id, update, None, None, bgp_attr, None, bgp, peers);
        }
    }

    for withdraw in packet.ipv4_withdraw.iter() {
        route_ipv4_withdraw(peer_id, withdraw, None, None, bgp, peers);
    }
    if let Some(mp_updates) = packet.mp_update
        && let Some(bgp_attr) = &packet.bgp_attr
    {
        match mp_updates {
            MpNlriReachAttr::Vpnv4 {
                snpa: _,
                nhop,
                updates,
            } => {
                for update in updates.iter() {
                    route_ipv4_update(
                        peer_id,
                        &update.nlri,
                        Some(update.rd.clone()),
                        Some(update.label),
                        bgp_attr,
                        Some(nhop.clone()),
                        bgp,
                        peers,
                    )
                }
            }
            _ => {
                //
            }
        }
    }
    if let Some(mp_withdrawals) = packet.mp_withdraw {
        match mp_withdrawals {
            MpNlriUnreachAttr::Vpnv4(withdrawals) => {
                for withdraw in withdrawals.iter() {
                    route_ipv4_withdraw(
                        peer_id,
                        &withdraw.nlri,
                        Some(withdraw.rd.clone()),
                        Some(withdraw.label),
                        bgp,
                        peers,
                    );
                }
            }
            _ => {
                //
            }
        }
    }
}

pub fn route_clean(peer_id: IpAddr, bgp: &mut ConfigRef, peers: &mut BTreeMap<IpAddr, Peer>) {
    // IPv4 unicast.
    let withdrawn = {
        let mut withdrawn: Vec<Ipv4Nlri> = vec![];
        let peer = peers.get_mut(&peer_id).expect("peer must exist");

        for (prefix, ribs) in peer.adj_in.v4.0.iter() {
            for rib in ribs.iter() {
                let withdraw = Ipv4Nlri {
                    id: rib.remote_id,
                    prefix: *prefix,
                };
                withdrawn.push(withdraw);
            }
        }
        withdrawn
    };
    for withdraw in withdrawn.iter() {
        route_ipv4_withdraw(peer_id, &withdraw, None, None, bgp, peers);
    }
    let peer = peers.get_mut(&peer_id).expect("peer must exist");
    peer.adj_in.v4.0.clear();
    peer.adj_out.v4.0.clear();

    // IPv4 VPN.
    let withdrawn = {
        let mut withdrawn: Vec<Vpnv4Nlri> = vec![];
        let peer = peers.get_mut(&peer_id).expect("peer must exist");

        for (rd, table) in peer.adj_in.v4vpn.iter() {
            for (prefix, ribs) in table.0.iter() {
                for rib in ribs.iter() {
                    let withdraw = Vpnv4Nlri {
                        label: rib.label.unwrap_or(Label::default()),
                        rd: rd.clone(),
                        nlri: Ipv4Nlri {
                            id: rib.remote_id,
                            prefix: *prefix,
                        },
                    };
                    withdrawn.push(withdraw);
                }
            }
        }
        withdrawn
    };
    for withdraw in withdrawn.iter() {
        route_ipv4_withdraw(
            peer_id,
            &withdraw.nlri,
            Some(withdraw.rd.clone()),
            Some(withdraw.label),
            bgp,
            peers,
        );
    }

    let peer = peers.get_mut(&peer_id).expect("peer must exist");
    peer.adj_in.v4vpn.clear();
    peer.adj_out.v4vpn.clear();

    peer.cap_map = CapAfiMap::new();
    peer.cap_recv = BgpCap::default();
    peer.opt.clear();
}

pub fn route_update_ipv4(
    peer: &mut Peer,
    prefix: &Ipv4Net,
    rib: &BgpRib,
    bgp: &mut ConfigRef,
    add_path: bool,
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

    // Create NLRI with optional path ID
    let nlri = Ipv4Nlri {
        id: if add_path { rib.local_id } else { 0 },
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
    // let attrs = bgp_attr.to();
    update.bgp_attr = Some(bgp_attr);
    update.ipv4_update.push(nlri);

    // Convert to bytes and send
    let bytes: BytesMut = update.into();

    if let Some(ref packet_tx) = peer.packet_tx {
        if let Err(e) = packet_tx.send(bytes) {
            eprintln!("Failed to send BGP Update to {}: {}", peer.address, e);
        }
    }
}

pub fn route_send_vpnv4(peer: &mut Peer, nlri: Vpnv4Nlri, bgp_attr: BgpAttr) {
    let mut update = UpdatePacket::new();
    if let Some(BgpNexthop::Vpnv4(nhop)) = bgp_attr.nexthop.as_ref() {
        let mp_update = MpNlriReachAttr::Vpnv4 {
            snpa: 0,
            nhop: nhop.clone(),
            updates: vec![nlri],
        };
        update.mp_update = Some(mp_update);
    }
    update.bgp_attr = Some(bgp_attr);

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
    if let Some(_name) = &config.name {
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
        .v4
        .1
        .iter()
        .map(|(prefix, rib)| (*prefix, rib.clone()))
        .collect();

    let add_path = peer.opt.is_add_path_send(Afi::Ip, Safi::Unicast);

    // Advertise all best paths to the peer
    for (prefix, mut rib) in routes {
        let Some((nlri, attr)) = route_update_ipv4(peer, &prefix, &rib, bgp, add_path) else {
            continue;
        };

        let Some(attr) = route_apply_policy_out(peer, &nlri, attr) else {
            continue;
        };

        // Register to AdjOut.
        rib.attr = attr.clone();
        peer.adj_out.add(None, nlri.prefix, rib);

        // Send the routes.
        route_send_ipv4(peer, nlri, attr);
    }

    // Send End-of-RIB marker for IPv4 Unicast
    send_eor_ipv4_unicast(peer);
}

pub fn route_sync_vpnv4(peer: &mut Peer, bgp: &mut ConfigRef) {
    // Collect all VPNv4 routes first to avoid borrow checker issues
    let all_routes: Vec<(RouteDistinguisher, Vec<(Ipv4Net, BgpRib)>)> = bgp
        .local_rib
        .v4vpn
        .iter()
        .map(|(rd, table)| {
            let routes: Vec<(Ipv4Net, BgpRib)> = table
                .1
                .iter()
                .map(|(prefix, rib)| (*prefix, rib.clone()))
                .collect();
            (rd.clone(), routes)
        })
        .collect();

    let add_path = peer.opt.is_add_path_send(Afi::Ip, Safi::MplsVpn);

    // Advertise all best paths to the peer
    for (rd, routes) in all_routes {
        for (prefix, mut rib) in routes {
            let Some((nlri, attr)) = route_update_ipv4(peer, &prefix, &rib, bgp, add_path) else {
                continue;
            };

            let Some(attr) = route_apply_policy_out(peer, &nlri, attr) else {
                continue;
            };

            // Register to AdjOut.
            rib.attr = attr.clone();
            peer.adj_out.add(Some(rd.clone()), nlri.prefix, rib);

            let vpnv4_nlri = Vpnv4Nlri {
                label: Label::default(),
                rd: rd.clone(),
                nlri,
            };

            // Send the routes.
            route_send_vpnv4(peer, vpnv4_nlri, attr);
        }
    }
    // Send End-of-RIB marker for IPv4 VPN
    send_eor_vpnv4_unicast(peer);
}

// Send End-of-RIB marker for IPv4 Unicast
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

// Send End-of-RIB marker for VPNv4 Unicast
fn send_eor_vpnv4_unicast(peer: &mut Peer) {
    // End-of-RIB is an empty Update packet (no attributes, no NLRI, no withdrawals)
    let mut update = UpdatePacket::new();
    let mp_withdraw = MpNlriUnreachAttr::Vpnv4Eor;
    update.mp_withdraw = Some(mp_withdraw);
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
    if peer.is_afi_safi(Afi::Ip, Safi::Unicast) {
        route_sync_ipv4(peer, bgp);
    }
    if peer.is_afi_safi(Afi::Ip, Safi::MplsVpn) {
        route_sync_vpnv4(peer, bgp);
    }
}

impl Bgp {
    pub fn route_add(&mut self, prefix: Ipv4Net) {
        let ident = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        let attr = BgpAttr::new();
        let mut rib = BgpRib::new(
            ident,
            Ipv4Addr::UNSPECIFIED,
            BgpRibType::Originated,
            0,
            32768,
            &attr,
            None,
            None,
        );
        let (_replaced, selected, next_id) = self.local_rib.update_route(prefix, rib.clone());
        rib.local_id = next_id;

        let mut bgp_ref = ConfigRef {
            router_id: &self.router_id,
            local_rib: &mut self.local_rib,
            rib_tx: &self.rib_tx,
        };

        if !selected.is_empty() {
            let mut peer_map = std::mem::take(&mut self.peers);
            route_advertise_to_peers(None, prefix, &selected, ident, &mut bgp_ref, &mut peer_map);
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
            route_advertise_to_peers(None, prefix, &selected, ident, &mut bgp_ref, &mut peer_map);
            self.peers = peer_map;
        }
    }
}
