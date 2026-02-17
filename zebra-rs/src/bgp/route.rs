use std::collections::{BTreeMap, BTreeSet};
use std::marker::PhantomData;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use bgp_packet::*;
use bytes::BytesMut;
use ipnet::Ipv4Net;
use prefix_trie::PrefixMap;

use crate::bgp::timer::start_stale_timer;
use crate::policy::PolicyList;

use super::cap::CapAfiMap;
use super::peer::{ConfigRef, Event, Peer, PeerType, State};
use super::timer::{start_adv_timer_ipv4, start_adv_timer_vpnv4};
use super::{Bgp, InOut, Message};

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
    pub attr: Arc<BgpAttr>,
    // Peer ID.
    pub ident: IpAddr,
    // Peer router id.
    pub router_id: Ipv4Addr,
    // Weight
    pub weight: u32,
    // Route type.
    pub typ: BgpRibType,
    // Whether this cand is currently the best path.
    pub best_path: bool,
    // Label.
    pub best_reason: Reason,
    // Label.
    pub label: Option<Label>,
    // Nexthop.
    pub nexthop: Option<Vpnv4Nexthop>,
    // Stale.
    pub stale: bool,
}

#[derive(Debug, Clone, Copy)]
pub enum Reason {
    Default,
    Llgr,
    Weight,
    Originated,
    Origin,
    AsPath,
    LocalPref,
    Med,
    RouterId,
    NotSelected,
}

impl std::fmt::Display for Reason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Reason::Default => write!(f, "Default selection (no other candidate)"),
            Reason::Llgr => write!(f, "llgr-stale"),
            Reason::Weight => write!(f, "weight"),
            Reason::Originated => write!(f, "self originated route"),
            Reason::Origin => write!(f, "origin attribute"),
            Reason::AsPath => write!(f, "AS Path length"),
            Reason::LocalPref => write!(f, "Local preference"),
            Reason::Med => write!(f, "MED attribute"),
            Reason::RouterId => write!(f, "Router ID"),
            Reason::NotSelected => write!(f, "Not selected"),
        }
    }
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
        stale: bool,
    ) -> Self {
        BgpRib {
            remote_id: id,
            local_id: 0, // Will be assigned in LocalRibTable::update_route()
            ident,
            router_id,
            attr: Arc::new(attr.clone()),
            weight,
            typ: rib_type,
            best_path: false,
            best_reason: Reason::NotSelected,
            label,
            nexthop,
            stale,
        }
    }

    pub fn is_originated(&self) -> bool {
        self.typ.is_originated()
    }
}

#[derive(Debug, Default)]
pub struct LocalRibTable(
    pub PrefixMap<Ipv4Net, Vec<BgpRib>>, // Cands.
    pub PrefixMap<Ipv4Net, BgpRib>,      // Selected.
);

impl LocalRibTable {
    pub fn update(&mut self, prefix: Ipv4Net, rib: BgpRib) -> (Vec<BgpRib>, Vec<BgpRib>, u32) {
        let cands = self.0.entry(prefix).or_default();

        // Find if we're replacing an existing route (same peer ident and path ID)
        let existing_local_id = cands
            .iter()
            .find(|r| r.ident == rib.ident && r.remote_id == rib.remote_id)
            .map(|r| r.local_id);

        // Extract routes being replaced
        let replaced: Vec<BgpRib> = cands
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
                cands.iter().map(|r| r.local_id).collect();

            while used_ids.contains(&next_id) {
                next_id += 1;
            }
            new_rib.local_id = next_id;
        }

        next_id = new_rib.local_id;

        cands.push(new_rib);

        let selected = self.select_best_path(prefix);

        (replaced, selected, next_id)
    }

    pub fn remove(&mut self, prefix: Ipv4Net, id: u32, ident: IpAddr) -> Vec<BgpRib> {
        let cands = self.0.entry(prefix).or_default();
        let removed: Vec<BgpRib> = cands
            .extract_if(.., |r| r.ident == ident && r.remote_id == id)
            .collect();
        removed
    }

    pub fn remove_peer_routes(&mut self, ident: IpAddr) -> Vec<BgpRib> {
        let mut all_removed: Vec<BgpRib> = Vec::new();
        for (_prefix, cands) in self.0.iter_mut() {
            let mut removed: Vec<BgpRib> = cands.extract_if(.., |r| r.ident == ident).collect();
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
            .map(|cands| cands.is_empty())
            .unwrap_or(true);

        if is_empty {
            self.0.remove(&prefix);
            self.1.remove(&prefix);
            return selected;
        }

        let best = {
            let cands = self.0.get_mut(&prefix).expect("prefix checked above");

            let mut best_index = 0usize;
            let mut best_reason = Reason::Default;
            for index in 1..cands.len() {
                let (better, reason) = Self::is_better(&cands[index], &cands[best_index]);
                if better {
                    best_index = index;
                }
                best_reason = reason;
            }

            for rib in cands.iter_mut() {
                rib.best_path = false;
                rib.best_reason = Reason::NotSelected;
            }
            cands[best_index].best_path = true;
            cands[best_index].best_reason = best_reason;
            cands[best_index].clone()
        };

        self.1.insert(prefix, best.clone());
        selected.push(best);

        selected
    }

    fn is_better(cand: &BgpRib, incb: &BgpRib) -> (bool, Reason) {
        if cand.stale != incb.stale {
            return (!cand.stale, Reason::Llgr);
        }

        if cand.weight != incb.weight {
            return (cand.weight > incb.weight, Reason::Weight);
        }

        let cand_lp = Self::effective_local_pref(cand);
        let incb_lp = Self::effective_local_pref(incb);
        if cand_lp != incb_lp {
            return (cand_lp > incb_lp, Reason::LocalPref);
        }

        // RFC 4456: Prefer path with shorter CLUSTER_LIST length (fewer route reflector hops)
        // let cand_cluster_len = cand
        //     .attr
        //     .cluster_list
        //     .as_ref()
        //     .map_or(0, |cl| cl.list.len());
        // let incb_cluster_len = incb
        //     .attr
        //     .cluster_list
        //     .as_ref()
        //     .map_or(0, |cl| cl.list.len());
        // if cand_cluster_len != incb_cluster_len {
        //     return cand_cluster_len < incb_cluster_len;
        // }

        let cand_local = matches!(cand.typ, BgpRibType::Originated);
        let incb_local = matches!(incb.typ, BgpRibType::Originated);
        if cand_local != incb_local {
            return (cand_local, Reason::Originated);
        }

        let cand_as_len = Self::as_path_len(cand);
        let incb_as_len = Self::as_path_len(incb);
        if cand_as_len != incb_as_len {
            return (cand_as_len < incb_as_len, Reason::AsPath);
        }

        let cand_origin_rank = Self::origin_rank(cand.attr.origin);
        let incb_origin_rank = Self::origin_rank(incb.attr.origin);
        if cand_origin_rank != incb_origin_rank {
            return (cand_origin_rank < incb_origin_rank, Reason::Origin);
        }

        // By default, MED is only compared between routes learned from the neighboring AS.
        // let cand_nei_as = cand.attr.aspath
        let cand_neigh_as = cand.attr.neighboring_as();
        let incb_neigh_as = incb.attr.neighboring_as();

        if cand_neigh_as == incb_neigh_as {
            let cand_med = cand.attr.med.clone().unwrap_or(Med::default());
            let incb_med = incb.attr.med.clone().unwrap_or(Med::default());
            if cand_med != incb_med {
                return (cand_med < incb_med, Reason::Med);
            }
        }

        let cand_type_rank = Self::route_type_rank(cand.typ);
        let incb_type_rank = Self::route_type_rank(incb.typ);
        if cand_type_rank != incb_type_rank {
            return (cand_type_rank < incb_type_rank, Reason::Origin);
        }

        if cand.ident != incb.ident {
            return (cand.ident < incb.ident, Reason::RouterId);
        }

        if cand.remote_id != incb.remote_id {
            return (cand.remote_id < incb.remote_id, Reason::RouterId);
        }

        (false, Reason::NotSelected)
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
        ident: IpAddr,
    ) -> Vec<BgpRib> {
        match rd {
            Some(rd) => self.v4vpn.entry(rd).or_default().remove(prefix, id, ident),
            None => self.v4.remove(prefix, id, ident),
        }
    }

    pub fn remove_peer_routes(&mut self, ident: IpAddr) -> Vec<BgpRib> {
        self.v4.remove_peer_routes(ident)
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
        self.v4vpn
            .entry(rd.clone())
            .or_default()
            .select_best_path(prefix)
    }
}

// RIB update from peer.
pub fn route_apply_policy_in(
    peer: &mut Peer,
    nlri: &Ipv4Nlri,
    bgp_attr: BgpAttr,
) -> Option<BgpAttr> {
    let config = peer.prefix_set.get(&InOut::Input);
    if config.name.is_some() {
        let Some(prefix_set) = &config.prefix_set else {
            return None;
        };
        if !prefix_set.matches(nlri.prefix) {
            return None;
        }
    }
    let config = peer.policy_list.get(&InOut::Input);
    if config.name.is_some() {
        let Some(policy_list) = &config.policy_list else {
            return None;
        };
        return policy_list_apply(policy_list, nlri, bgp_attr);
    }
    Some(bgp_attr)
}

pub fn route_apply_policy_out(
    peer: &mut Peer,
    nlri: &Ipv4Nlri,
    bgp_attr: BgpAttr,
) -> Option<BgpAttr> {
    let config = peer.prefix_set.get(&InOut::Output);
    if config.name.is_some() {
        let Some(prefix_set) = &config.prefix_set else {
            return None;
        };
        if !prefix_set.matches(nlri.prefix) {
            return None;
        }
    }
    let config = peer.policy_list.get(&InOut::Output);
    if config.name.is_some() {
        let Some(policy_list) = &config.policy_list else {
            return None;
        };
        return policy_list_apply(policy_list, nlri, bgp_attr);
    } else {
        // Temporary comment out.
        // return None;
    }
    Some(bgp_attr)
}

pub fn route_ipv4_update(
    ident: IpAddr,
    nlri: &Ipv4Nlri,
    rd: Option<RouteDistinguisher>,
    label: Option<Label>,
    attr: &BgpAttr,
    nexthop: Option<Vpnv4Nexthop>,
    bgp: &mut ConfigRef,
    peers: &mut BTreeMap<IpAddr, Peer>,
    stale: bool,
) {
    // Validate and extract peer information in a separate scope to release the borrow
    let (peer_ident, peer_router_id, typ, should_process) = {
        let peer = peers.get_mut(&ident).expect("peer must exist");

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

    // Create BGP RIB with weight value 0. We are going to include BgpNexthop as
    // part of BgpAttr. Since we want to consolidate BGP updates.
    let mut rib = BgpRib::new(
        peer_ident,
        peer_router_id,
        typ,
        nlri.id,
        0,
        attr,
        label,
        nexthop,
        stale,
    );

    // Register to peer's AdjRibIn and update stats
    let attr = {
        let peer = peers.get_mut(&ident).expect("peer must exist");
        peer.adj_in.add(rd, nlri.prefix, rib.clone());

        // Apply policy.
        route_apply_policy_in(peer, nlri, attr.clone())
    };

    // Perform BGP Path selection.
    let Some(attr) = attr else {
        route_ipv4_withdraw(ident, nlri, rd, None, bgp, peers, false);
        return;
    };
    rib.attr = bgp.attr_store.intern(attr);
    let (_, selected, next_id) = bgp.local_rib.update(rd, nlri.prefix, rib.clone());

    // Advertise to peers if best path changed.
    if !selected.is_empty() {
        route_advertise_to_peers(rd, nlri.prefix, &selected, peer_ident, bgp, peers);
    }
    rib.local_id = next_id;
    route_advertise_to_addpath(rd, nlri.prefix, &rib, peer_ident, bgp, peers);
}

fn rtc_match(rtc: &BTreeSet<ExtCommunityValue>, ecom: &Option<ExtCommunity>) -> bool {
    if let Some(ecom) = ecom {
        // Extended community value in RIB.
        for eval in ecom.0.iter() {
            // When the value matches one of RTC, return true;
            for rt in rtc.iter() {
                if eval == rt {
                    return true;
                }
            }
        }
    }
    false
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
                // RTC match.
                if let Some(ref rd) = rd {
                    if !peer.rtcv4.is_empty() {
                        if !rtc_match(&peer.rtcv4, &attr.ecom) {
                            continue;
                        }
                    }
                }
                let attr = bgp.attr_store.intern(attr);
                let mut rib = rib.clone();
                rib.attr = attr.clone();

                peer.adj_out.add(rd, nlri.prefix, rib);
                if let Some(ref rd) = rd {
                    let vpnv4_nlri = Vpnv4Nlri {
                        label: Label::default(),
                        rd: rd.clone(),
                        nlri,
                    };
                    peer.send_vpnv4(vpnv4_nlri, attr, true);
                } else {
                    peer.send_ipv4(nlri, attr, true);
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
            peer.cache_remove_vpnv4(rd.clone(), prefix, removed.local_id);
        } else {
            peer.cache_remove_ipv4(prefix, removed.local_id);
        }
        route_withdraw_ipv4(peer, rd, prefix, removed.local_id);
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
                if let Some(ref rd) = rd {
                    // RTC match.
                    if !peer.rtcv4.is_empty() {
                        if !rtc_match(&peer.rtcv4, &attr.ecom) {
                            continue;
                        }
                    }
                }
                // Send update
                let attr = bgp.attr_store.intern(attr);
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
                    peer.send_vpnv4(vpnv4_nlri, attr, true);
                } else {
                    peer.send_ipv4(nlri, attr, true);
                }
            }
            _ => {
                // We remove the cache.
                if let Some(ref rd) = rd {
                    peer.cache_remove_vpnv4(rd.clone(), prefix, 0);
                } else {
                    peer.cache_remove_ipv4(prefix, 0);
                }
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
            let mp_withdraw = MpUnreachAttr::Vpnv4(vec![vpnv4_nlri]);
            update.mp_withdraw = Some(mp_withdraw);
        }
        None => {
            let nlri = Ipv4Nlri { id, prefix };
            update.ipv4_withdraw.push(nlri);
        }
    }

    peer.send_packet(update.into());
}

pub fn route_ipv4_withdraw(
    ident: IpAddr,
    nlri: &Ipv4Nlri,
    rd: Option<RouteDistinguisher>,
    _label: Option<Label>,
    bgp: &mut ConfigRef,
    peers: &mut BTreeMap<IpAddr, Peer>,
    rib_in: bool,
) {
    {
        if rib_in {
            let peer = peers.get_mut(&ident).expect("peer must exist");
            peer.adj_in.remove(rd, nlri.prefix, nlri.id);
        }
    }

    // BGP Path selection - this may select a new best path
    let mut removed = bgp.local_rib.remove(rd, nlri.prefix, nlri.id, ident);

    // Re-run best path selection and advertise changes
    let selected = if let Some(ref rd) = rd {
        bgp.local_rib.select_best_path_vpn(rd, nlri.prefix)
    } else {
        bgp.local_rib.select_best_path(nlri.prefix)
    };
    if !selected.is_empty() || !removed.is_empty() {
        route_advertise_to_peers(rd.clone(), nlri.prefix, &selected, ident, bgp, peers);
    }
    if let Some(removed) = removed.pop() {
        route_withdraw_from_addpath(rd, nlri.prefix, &removed, ident, bgp, peers);
    }
}

pub fn route_ipv4_rtc_update(peer_id: IpAddr, rtcv4: &Rtcv4, peers: &mut BTreeMap<IpAddr, Peer>) {
    let Some(peer) = peers.get_mut(&peer_id) else {
        return;
    };
    peer.rtcv4.insert(rtcv4.rt.clone());
}

pub fn route_ipv4_rtc_withdraw(peer_id: IpAddr, rtcv4: &Rtcv4, peers: &mut BTreeMap<IpAddr, Peer>) {
    let Some(peer) = peers.get_mut(&peer_id) else {
        return;
    };
    peer.rtcv4.remove(&rtcv4.rt);
}

pub fn route_rtcv4_sync(peer_id: IpAddr, bgp: &mut ConfigRef, peers: &mut BTreeMap<IpAddr, Peer>) {
    let Some(peer) = peers.get_mut(&peer_id) else {
        return;
    };
    let key = AfiSafi::new(Afi::Ip, Safi::Rtc);
    if peer.eor.get(&key).is_some() {
        route_sync_vpnv4(peer, bgp);
    }
    peer.eor.clear();
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
            route_ipv4_update(
                peer_id, update, None, None, bgp_attr, None, bgp, peers, false,
            );
        }
    }

    for withdraw in packet.ipv4_withdraw.iter() {
        route_ipv4_withdraw(peer_id, withdraw, None, None, bgp, peers, true);
    }
    if let Some(mp_updates) = packet.mp_update
        && let Some(bgp_attr) = &packet.bgp_attr
    {
        match mp_updates {
            MpReachAttr::Vpnv4(nlri) => {
                for update in nlri.updates.iter() {
                    route_ipv4_update(
                        peer_id,
                        &update.nlri,
                        Some(update.rd.clone()),
                        Some(update.label),
                        bgp_attr,
                        Some(nlri.nhop.clone()),
                        bgp,
                        peers,
                        false,
                    )
                }
            }
            MpReachAttr::Rtcv4(nlri) => {
                for update in nlri.updates.iter() {
                    route_ipv4_rtc_update(peer_id, update, peers);
                }
            }
            _ => {
                //
            }
        }
    }
    if let Some(mp_withdrawals) = packet.mp_withdraw {
        match mp_withdrawals {
            MpUnreachAttr::Vpnv4(withdrawals) => {
                for withdraw in withdrawals.iter() {
                    route_ipv4_withdraw(
                        peer_id,
                        &withdraw.nlri,
                        Some(withdraw.rd.clone()),
                        Some(withdraw.label),
                        bgp,
                        peers,
                        true,
                    );
                }
            }
            MpUnreachAttr::Vpnv4Eor => {
                let afi_safi = AfiSafi::new(Afi::Ip, Safi::MplsVpn);
                let _ = bgp
                    .tx
                    .send(Message::Event(peer_id, Event::StaleTimerExipires(afi_safi)));
            }
            MpUnreachAttr::Rtcv4Eor => {
                // If peer's EoR is true.
                route_rtcv4_sync(peer_id, bgp, peers);
            }
            _ => {
                //
            }
        }
    }
}

pub fn route_clean(
    peer_id: IpAddr,
    bgp: &mut ConfigRef,
    peers: &mut BTreeMap<IpAddr, Peer>,
    force: bool,
) {
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
        route_ipv4_withdraw(peer_id, &withdraw, None, None, bgp, peers, true);
    }
    let peer = peers.get_mut(&peer_id).expect("peer must exist");
    peer.adj_in.v4.0.clear();
    peer.adj_out.v4.0.clear();

    peer.cache_ipv4.clear();
    peer.cache_vpnv4.clear();

    // IPv4 VPN.
    let afi_safi = AfiSafi::new(Afi::Ip, Safi::MplsVpn);
    if let Some(_) = peer.cap_send.llgr.get(&afi_safi)
        && let Some(llgr) = peer.cap_recv.llgr.get(&afi_safi)
    {
        // Start stale timer.
        peer.timer.stale_timer.insert(
            afi_safi,
            start_stale_timer(peer, afi_safi, llgr.stale_time()),
        );

        for (rd, table) in peer.adj_in.v4vpn.iter_mut() {
            for (prefix, ribs) in table.0.iter_mut() {
                for rib in ribs.iter_mut() {
                    rib.stale = true;
                    let mut new_attr = (*rib.attr).clone();
                    match &mut new_attr.com {
                        Some(com) => {
                            com.push(CommunityValue::LLGR_STALE.value());
                        }
                        None => {
                            let mut com = Community::new();
                            com.push(CommunityValue::LLGR_STALE.value());
                            new_attr.com = Some(com);
                        }
                    }
                    rib.attr = bgp.attr_store.intern(new_attr);
                }
            }
        }

        // Collect stale routes to update in LocalRib.
        let stale_updates: Vec<(
            RouteDistinguisher,
            Ipv4Nlri,
            Option<Label>,
            BgpAttr,
            Option<Vpnv4Nexthop>,
        )> = {
            let mut updates = Vec::new();
            for (rd, table) in peer.adj_in.v4vpn.iter() {
                for (prefix, ribs) in table.0.iter() {
                    for rib in ribs.iter() {
                        let nlri = Ipv4Nlri {
                            id: rib.remote_id,
                            prefix: *prefix,
                        };
                        updates.push((
                            rd.clone(),
                            nlri,
                            rib.label,
                            (*rib.attr).clone(),
                            rib.nexthop.clone(),
                        ));
                    }
                }
            }
            updates
        };

        // Update LocalRib with stale routes.
        for (rd, nlri, label, attr, nexthop) in stale_updates {
            route_ipv4_update(
                peer_id,
                &nlri,
                Some(rd),
                label,
                &attr,
                nexthop,
                bgp,
                peers,
                true,
            );
        }
    } else {
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
                true,
            );
        }
        let peer = peers.get_mut(&peer_id).expect("peer must exist");
        peer.adj_in.v4vpn.clear();
    }

    let peer = peers.get_mut(&peer_id).expect("peer must exist");
    peer.adj_out.v4vpn.clear();

    peer.cap_map = CapAfiMap::new();
    peer.cap_recv = BgpCap::default();
    peer.opt.clear();

    // IPv4 RTC.
    peer.rtcv4.clear();
    peer.eor.clear();
}

pub fn stale_timer_expire(
    peer_id: IpAddr,
    afi_safi: AfiSafi,
    bgp: &mut ConfigRef,
    peers: &mut BTreeMap<IpAddr, Peer>,
) -> State {
    let peer = peers.get_mut(&peer_id).expect("peer must exist");
    peer.timer.stale_timer.remove(&afi_safi);

    // Fetch all of route which as stale flag.
    let withdrawn = {
        let mut withdrawn: Vec<Vpnv4Nlri> = vec![];

        for (rd, table) in peer.adj_in.v4vpn.iter() {
            for (prefix, ribs) in table.0.iter() {
                for rib in ribs.iter() {
                    if rib.stale {
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
        }
        withdrawn
    };

    // Withdraw routes.
    for withdraw in withdrawn.iter() {
        route_ipv4_withdraw(
            peer_id,
            &withdraw.nlri,
            Some(withdraw.rd.clone()),
            Some(withdraw.label),
            bgp,
            peers,
            true,
        );
    }

    let peer = peers.get(&peer_id).expect("peer must exist");
    peer.state
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
    let mut attrs = (*rib.attr).clone();

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
    update.bgp_attr = Some(bgp_attr);
    update.ipv4_update.push(nlri);
    peer.send_packet(update.into());
}

impl Peer {
    pub fn send_packet(&self, bytes: BytesMut) {
        if let Some(ref packet_tx) = self.packet_tx {
            if let Err(e) = packet_tx.send(bytes) {
                eprintln!("Failed to send BGP packet to {}: {}", self.address, e);
            }
        }
    }

    pub fn send_ipv4(&mut self, nlri: Ipv4Nlri, attr: Arc<BgpAttr>, timer: bool) {
        self.cache_ipv4
            .entry(attr.clone())
            .or_default()
            .insert(nlri.clone());
        self.cache_ipv4_rev.insert(nlri, attr);
        if timer && self.cache_ipv4_timer.is_none() {
            self.cache_ipv4_timer = Some(start_adv_timer_ipv4(self));
        }
    }

    pub fn cache_remove_ipv4(&mut self, prefix: Ipv4Net, id: u32) {
        let nlri = Ipv4Nlri { id, prefix };
        if let Some(attr) = self.cache_ipv4_rev.remove(&nlri) {
            if let Some(set) = self.cache_ipv4.get_mut(&attr) {
                set.remove(&nlri);
                if set.is_empty() {
                    self.cache_ipv4.remove(&attr);
                }
            }
        }
    }

    // Flush BGP update.
    pub fn flush_ipv4(&mut self) {
        let packet_tx = self.packet_tx.clone();
        for (attr, nlris) in self.cache_ipv4.drain() {
            let mut update = UpdatePacket::new();
            update.bgp_attr = Some((*attr).clone());
            update.ipv4_update = nlris.into_iter().collect();

            while let Some(bytes) = update.pop_ipv4() {
                if let Some(ref tx) = packet_tx {
                    let _ = tx.send(bytes);
                }
            }
        }
        self.cache_ipv4_rev.clear();
    }

    pub fn send_vpnv4(&mut self, nlri: Vpnv4Nlri, attr: Arc<BgpAttr>, timer: bool) {
        self.cache_vpnv4
            .entry(attr.clone())
            .or_default()
            .insert(nlri.clone());
        self.cache_vpnv4_rev.insert(nlri, attr);
        if timer && self.cache_vpnv4_timer.is_none() {
            self.cache_vpnv4_timer = Some(start_adv_timer_vpnv4(self));
        }
    }

    pub fn cache_remove_vpnv4(&mut self, rd: RouteDistinguisher, prefix: Ipv4Net, id: u32) {
        let nlri = Vpnv4Nlri {
            label: Label::default(),
            rd,
            nlri: Ipv4Nlri { id, prefix },
        };
        if let Some(attr) = self.cache_vpnv4_rev.remove(&nlri) {
            if let Some(set) = self.cache_vpnv4.get_mut(&attr) {
                set.remove(&nlri);
                if set.is_empty() {
                    self.cache_vpnv4.remove(&attr);
                }
            }
        }
    }

    // Flush BGP update.
    pub fn flush_vpnv4(&mut self) {
        let packet_tx = self.packet_tx.clone();
        for (attr, nlris) in self.cache_vpnv4.drain() {
            let mut update = UpdatePacket::new();

            if let Some(BgpNexthop::Vpnv4(nhop)) = attr.nexthop.as_ref() {
                let vpnv4reach = Vpnv4Reach {
                    snpa: 0,
                    nhop: nhop.clone(),
                    updates: nlris.into_iter().collect(),
                };
                update.mp_update = Some(MpReachAttr::Vpnv4(vpnv4reach));
            }
            update.bgp_attr = Some((*attr).clone());

            while let Some(bytes) = update.pop_vpnv4() {
                if let Some(ref tx) = packet_tx {
                    let _ = tx.send(bytes);
                }
            }
        }
        self.cache_vpnv4_rev.clear();
    }
}

pub fn route_send_vpnv4(peer: &mut Peer, nlri: Vpnv4Nlri, bgp_attr: BgpAttr) {
    let mut update = UpdatePacket::new();
    if let Some(BgpNexthop::Vpnv4(nhop)) = bgp_attr.nexthop.as_ref() {
        let nlri = Vpnv4Reach {
            snpa: 0,
            nhop: nhop.clone(),
            updates: vec![nlri],
        };
        let mp_update = MpReachAttr::Vpnv4(nlri);
        update.mp_update = Some(mp_update);
    }
    update.bgp_attr = Some(bgp_attr);
    peer.send_packet(update.into());
}

pub fn policy_list_apply(
    policy_list: &PolicyList,
    nlri: &Ipv4Nlri,
    mut bgp_attr: BgpAttr,
) -> Option<BgpAttr> {
    for (_, entry) in policy_list.entry.iter() {
        let mut prefix_matched: Option<bool> = None;
        if let Some(prefix_set) = &entry.prefix_set {
            if prefix_set.matches(nlri.prefix) {
                prefix_matched = Some(true);
            } else {
                prefix_matched = Some(false);
            }
        }
        let mut community_matched: Option<bool> = None;
        if let Some(community_set) = &entry.community_set {
            if community_set.matches(&bgp_attr) {
                community_matched = Some(true);
            } else {
                community_matched = Some(false);
            }
        }
        // If we matched to the statement or no match statement at all.
        match (prefix_matched, community_matched) {
            (None | Some(true), None | Some(true)) => {
                if let Some(med) = &entry.med {
                    bgp_attr.med = Some(Med { med: *med });
                }
                return Some(bgp_attr);
            }
            (_, _) => {
                //
            }
        }
    }
    None
}

pub fn route_sync_ipv4(peer: &mut Peer, bgp: &mut ConfigRef) {
    let add_path = peer.opt.is_add_path_send(Afi::Ip, Safi::Unicast);

    // Collect all routes first to avoid borrow checker issues
    let routes: Vec<(Ipv4Net, BgpRib)> = if add_path {
        bgp.local_rib
            .v4
            .0
            .iter()
            .flat_map(|(prefix, ribs)| ribs.iter().map(move |rib| (*prefix, rib.clone())))
            .collect()
    } else {
        bgp.local_rib
            .v4
            .1
            .iter()
            .map(|(prefix, rib)| (*prefix, rib.clone()))
            .collect()
    };

    // Advertise all best paths to the peer
    for (prefix, mut rib) in routes {
        let Some((nlri, attr)) = route_update_ipv4(peer, &prefix, &rib, bgp, add_path) else {
            continue;
        };

        let Some(attr) = route_apply_policy_out(peer, &nlri, attr) else {
            continue;
        };

        // Register to AdjOut.
        rib.attr = bgp.attr_store.intern(attr);
        let arc_attr = rib.attr.clone();
        peer.adj_out.add(None, nlri.prefix, rib);

        // Send the routes.
        peer.send_ipv4(nlri, arc_attr, false);
    }

    peer.flush_ipv4();

    // Send End-of-RIB marker for IPv4 Unicast
    send_eor_ipv4_unicast(peer);
}

pub fn route_sync_vpnv4(peer: &mut Peer, bgp: &mut ConfigRef) {
    let add_path = peer.opt.is_add_path_send(Afi::Ip, Safi::MplsVpn);

    // Collect all VPNv4 routes first to avoid borrow checker issues
    let all_routes: Vec<(RouteDistinguisher, Vec<(Ipv4Net, BgpRib)>)> = if add_path {
        bgp.local_rib
            .v4vpn
            .iter()
            .map(|(rd, table)| {
                let routes: Vec<(Ipv4Net, BgpRib)> = table
                    .0
                    .iter()
                    .flat_map(|(prefix, ribs)| ribs.iter().map(move |rib| (*prefix, rib.clone())))
                    .collect();
                (rd.clone(), routes)
            })
            .collect()
    } else {
        bgp.local_rib
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
            .collect()
    };

    // Advertise all best paths to the peer
    for (rd, routes) in all_routes {
        for (prefix, mut rib) in routes {
            let Some((nlri, attr)) = route_update_ipv4(peer, &prefix, &rib, bgp, add_path) else {
                continue;
            };

            let Some(attr) = route_apply_policy_out(peer, &nlri, attr) else {
                continue;
            };

            // RTC
            if !peer.rtcv4.is_empty() {
                if !rtc_match(&peer.rtcv4, &attr.ecom) {
                    continue;
                }
            }

            // Register to AdjOut.
            rib.attr = bgp.attr_store.intern(attr);
            let arc_attr = rib.attr.clone();
            peer.adj_out.add(Some(rd.clone()), nlri.prefix, rib);

            let vpnv4_nlri = Vpnv4Nlri {
                label: Label::default(),
                rd: rd.clone(),
                nlri,
            };

            // Send the routes.
            peer.send_vpnv4(vpnv4_nlri, arc_attr, false);
        }
    }

    peer.flush_vpnv4();

    // Send End-of-RIB marker for IPv4 VPN
    send_eor_vpnv4_unicast(peer);
}

// Send End-of-RIB marker for IPv4 Unicast.
fn send_eor_ipv4_unicast(peer: &mut Peer) {
    let update = UpdatePacket::new();
    peer.send_packet(update.into());
}

// Send End-of-RIB marker for VPNv4 Unicast.
fn send_eor_vpnv4_unicast(peer: &mut Peer) {
    let mut update = UpdatePacket::new();
    update.mp_withdraw = Some(MpUnreachAttr::Vpnv4Eor);
    peer.send_packet(update.into());
}

// Send wildcard RTCv4.
fn send_default_rtcv4_unicast(peer: &mut Peer) {
    let mut update = UpdatePacket::new();

    let mut attrs = BgpAttr::new();
    if peer.is_ibgp() {
        attrs.local_pref = Some(LocalPref::default());
    }
    update.bgp_attr = Some(attrs);

    let nlri = Rtcv4Reach {
        snpa: 0,
        nhop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        updates: vec![],
    };
    update.mp_update = Some(MpReachAttr::Rtcv4(nlri));
    peer.send_packet(update.into());
}

// Send End-of-RIB marker for RTCv4.
fn send_eor_rtcv4_unicast(peer: &mut Peer) {
    let mut update = UpdatePacket::new();
    update.mp_withdraw = Some(MpUnreachAttr::Rtcv4Eor);
    peer.send_packet(update.into());
}

// Called when peer has been established.
pub fn route_sync(peer: &mut Peer, bgp: &mut ConfigRef) {
    // Advertize.
    if peer.is_afi_safi(Afi::Ip, Safi::Unicast) {
        route_sync_ipv4(peer, bgp);
    }
    // We want all RTC.
    if peer.is_afi_safi(Afi::Ip, Safi::Rtc) {
        let key = AfiSafi::new(Afi::Ip, Safi::Rtc);
        peer.eor.insert(key, true);
        send_default_rtcv4_unicast(peer);
        send_eor_rtcv4_unicast(peer);
    }
    if peer.is_afi_safi(Afi::Ip, Safi::MplsVpn) {
        let key = AfiSafi::new(Afi::Ip, Safi::Rtc);
        if peer.eor.get(&key).is_none() {
            route_sync_vpnv4(peer, bgp);
        }
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
            false,
        );
        let (_replaced, selected, next_id) = self.local_rib.update(None, prefix, rib.clone());
        rib.local_id = next_id;

        let mut bgp_ref = ConfigRef {
            router_id: &self.router_id,
            local_rib: &mut self.local_rib,
            tx: &self.tx,
            rib_tx: &self.rib_tx,
            attr_store: &mut self.attr_store,
        };

        if !selected.is_empty() {
            route_advertise_to_peers(
                None,
                prefix,
                &selected,
                ident,
                &mut bgp_ref,
                &mut self.peers,
            );
        }
    }

    pub fn route_del(&mut self, prefix: Ipv4Net) {
        let ident = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        let id = 0;
        let removed = self.local_rib.remove(None, prefix, id, ident);

        let mut bgp_ref = ConfigRef {
            router_id: &self.router_id,
            local_rib: &mut self.local_rib,
            tx: &self.tx,
            rib_tx: &self.rib_tx,
            attr_store: &mut self.attr_store,
        };

        let selected = bgp_ref.local_rib.select_best_path(prefix);
        if !selected.is_empty() || !removed.is_empty() {
            route_advertise_to_peers(
                None,
                prefix,
                &selected,
                ident,
                &mut bgp_ref,
                &mut self.peers,
            );
        }
    }
}
