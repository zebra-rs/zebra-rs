use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use bgp_packet::*;
use bytes::BytesMut;
use ipnet::Ipv4Net;
use prefix_trie::PrefixMap;

use crate::bgp::timer::{start_adv_timer_evpn, start_stale_timer};
use crate::policy::PolicyList;
use crate::rib::{self, MacAddr, api::FdbEntry};

use super::cap::CapAfiMap;
use super::peer::{BgpTop, Event, Peer, PeerType};
use super::peer_map::PeerMap;
use super::timer::{start_adv_timer_ipv4, start_adv_timer_vpnv4};
use super::{Bgp, InOut, Message};

pub const ORIGINATED_PEER: usize = usize::MAX;

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
    pub ident: usize,
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
    // Phase 4D: EVPN ESI (Ethernet Segment Identifier) for multi-homing
    pub esi: Option<[u8; 10]>,
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
        ident: usize,
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
            esi: None,
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

    pub fn remove(&mut self, prefix: Ipv4Net, id: u32, ident: usize) -> Vec<BgpRib> {
        let cands = self.0.entry(prefix).or_default();
        let removed: Vec<BgpRib> = cands
            .extract_if(.., |r| r.ident == ident && r.remote_id == id)
            .collect();
        removed
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
            let cand_med = cand.attr.med.clone().unwrap_or_default();
            let incb_med = incb.attr.med.clone().unwrap_or_default();
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

/// Per-RD Loc-RIB table for EVPN routes.
///
/// Mirrors `LocalRibTable` but uses an exact-match `BTreeMap<EvpnPrefix, _>`
/// rather than `prefix-trie`'s `PrefixMap`, since EVPN keys are not subject
/// to longest-prefix matching.
#[derive(Debug, Default)]
pub struct LocalRibEvpnTable {
    /// Candidate paths per prefix.
    pub cands: BTreeMap<EvpnPrefix, Vec<BgpRib>>,
    /// Selected best path per prefix.
    pub selected: BTreeMap<EvpnPrefix, BgpRib>,
}

impl LocalRibEvpnTable {
    pub fn update(&mut self, prefix: EvpnPrefix, rib: BgpRib) -> (Vec<BgpRib>, Vec<BgpRib>, u32) {
        let cands = self.cands.entry(prefix.clone()).or_default();

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
            new_rib.local_id = local_id;
        } else {
            let used_ids: std::collections::HashSet<u32> =
                cands.iter().map(|r| r.local_id).collect();
            while used_ids.contains(&next_id) {
                next_id += 1;
            }
            new_rib.local_id = next_id;
        }

        next_id = new_rib.local_id;

        cands.push(new_rib);

        let selected = self.select_best_path(&prefix);

        (replaced, selected, next_id)
    }

    pub fn remove(&mut self, prefix: &EvpnPrefix, id: u32, ident: usize) -> Vec<BgpRib> {
        let cands = self.cands.entry(prefix.clone()).or_default();
        cands
            .extract_if(.., |r| r.ident == ident && r.remote_id == id)
            .collect()
    }

    pub fn select_best_path(&mut self, prefix: &EvpnPrefix) -> Vec<BgpRib> {
        let mut selected = Vec::new();

        if !self.cands.contains_key(prefix) {
            self.selected.remove(prefix);
            return selected;
        }

        let is_empty = self
            .cands
            .get(prefix)
            .map(|cands| cands.is_empty())
            .unwrap_or(true);

        if is_empty {
            self.cands.remove(prefix);
            self.selected.remove(prefix);
            return selected;
        }

        let best = {
            let cands = self.cands.get_mut(prefix).expect("prefix checked above");

            let mut best_index = 0usize;
            let mut best_reason = Reason::Default;
            for index in 1..cands.len() {
                // Reuse the IPv4 best-path comparator — it operates only on
                // BgpRib fields and is NLRI-agnostic.
                let (better, reason) = LocalRibTable::is_better(&cands[index], &cands[best_index]);
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

        self.selected.insert(prefix.clone(), best.clone());
        selected.push(best);

        selected
    }
}

#[derive(Debug, Default)]
pub struct LocalRib {
    pub v4: LocalRibTable,

    pub v4vpn: BTreeMap<RouteDistinguisher, LocalRibTable>,

    /// Per-RD EVPN Loc-RIB tables.
    pub evpn: BTreeMap<RouteDistinguisher, LocalRibEvpnTable>,
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

    // EVPN dispatch ----------------------------------------------------------

    pub fn update_evpn(
        &mut self,
        rd: RouteDistinguisher,
        prefix: EvpnPrefix,
        rib: BgpRib,
    ) -> (Vec<BgpRib>, Vec<BgpRib>, u32) {
        self.evpn.entry(rd).or_default().update(prefix, rib)
    }

    pub fn remove_evpn(
        &mut self,
        rd: RouteDistinguisher,
        prefix: &EvpnPrefix,
        id: u32,
        ident: usize,
    ) -> Vec<BgpRib> {
        self.evpn.entry(rd).or_default().remove(prefix, id, ident)
    }

    pub fn select_best_path_evpn(
        &mut self,
        rd: &RouteDistinguisher,
        prefix: &EvpnPrefix,
    ) -> Vec<BgpRib> {
        self.evpn.entry(*rd).or_default().select_best_path(prefix)
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
    ident: usize,
    nlri: &Ipv4Nlri,
    rd: Option<RouteDistinguisher>,
    label: Option<Label>,
    attr: &BgpAttr,
    nexthop: Option<Vpnv4Nexthop>,
    bgp: &mut BgpTop,
    peers: &mut PeerMap,
    stale: bool,
) {
    // Validate and extract peer information in a separate scope to release the borrow
    let (peer_ident, peer_router_id, typ, should_process) = {
        let peer = peers.get_mut_by_idx(ident).expect("peer must exist");

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
        if let Some(ref originator_id) = attr.originator_id
            && originator_id.id == *bgp.router_id
        {
            eprintln!(
                "Dropping update for {} from peer {} - ORIGINATOR_ID {} matches local router ID",
                nlri.prefix, peer.address, originator_id.id
            );
            return;
        }

        // RFC 4456: Drop update if local router ID is in CLUSTER_LIST. This
        // prevents routing loops in route reflection scenarios when the route
        // has already passed through this route reflector.
        if let Some(ref cluster_list) = attr.cluster_list
            && cluster_list.list.contains(bgp.router_id)
        {
            eprintln!(
                "Dropping update for {} from peer {} - local router ID {} found in CLUSTER_LIST",
                nlri.prefix, peer.address, bgp.router_id
            );
            return;
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
        let peer = peers.get_mut_by_idx(ident).expect("peer must exist");
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
    _source_peer: usize,
    bgp: &mut BgpTop,
    peers: &mut PeerMap,
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

        if let Some((nlri, attr)) = route_update_ipv4(peer, &prefix, rib, bgp, true)
            && let Some(attr) = route_apply_policy_out(peer, &nlri, attr)
        {
            // RTC match.
            if let Some(_rd) = rd
                && !peer.rtcv4.is_empty()
                && !rtc_match(&peer.rtcv4, &attr.ecom)
            {
                continue;
            }
            let attr = bgp.attr_store.intern(attr);
            let mut rib = rib.clone();
            rib.attr = attr.clone();

            peer.adj_out.add(rd, nlri.prefix, rib);
            if let Some(ref rd) = rd {
                let vpnv4_nlri = Vpnv4Nlri {
                    label: Label::default(),
                    rd: *rd,
                    nlri,
                };
                peer.send_vpnv4(vpnv4_nlri, attr, true);
            } else {
                peer.send_ipv4(nlri, attr, true);
            }
        }
    }
}

fn route_withdraw_from_addpath(
    rd: Option<RouteDistinguisher>,
    prefix: Ipv4Net,
    removed: &BgpRib,
    _source_peer: usize,
    _bgp: &mut BgpTop,
    peers: &mut PeerMap,
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
            peer.cache_remove_vpnv4(*rd, prefix, removed.local_id);
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
    _source_peer: usize,
    bgp: &mut BgpTop,
    peers: &mut PeerMap,
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
                if let Some(_rd) = rd {
                    // RTC match.
                    if !peer.rtcv4.is_empty() && !rtc_match(&peer.rtcv4, &attr.ecom) {
                        continue;
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
                        rd: *rd,
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
                    peer.cache_remove_vpnv4(*rd, prefix, 0);
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

/// Per-peer EVPN advertise builder. Mirrors `route_update_ipv4`:
/// applies split-horizon, the iBGP-iBGP / route-reflector filter,
/// and fixes up AS_PATH / NEXT_HOP / LOCAL_PREF for the outgoing
/// direction. Returns `(EvpnRoute, BgpAttr)` if the peer should
/// receive an advertisement, `None` otherwise.
///
/// VNI is sourced from the RT extended community on the inbound
/// attribute (per RFC 8365 §5.1.2.4). For locally-originated routes
/// `evpn_originate_macip` attaches the RT first, so the lookup
/// always succeeds; for re-advertised routes the upstream RT is
/// preserved.
pub fn route_update_evpn(
    peer: &mut Peer,
    rd: &RouteDistinguisher,
    prefix: &EvpnPrefix,
    rib: &BgpRib,
    bgp: &mut BgpTop,
    add_path: bool,
) -> Option<(EvpnRoute, BgpAttr)> {
    if rib.ident == peer.ident {
        return None;
    }
    if peer.peer_type == PeerType::IBGP
        && rib.typ == BgpRibType::IBGP
        && !peer.is_reflector_client()
    {
        return None;
    }

    let id = if add_path { rib.local_id } else { 0 };

    let route = match prefix {
        EvpnPrefix::MacIp { eth_tag, mac, .. } => {
            let vni = extract_vni_from_attr(&rib.attr).unwrap_or(0);
            EvpnRoute::Mac(EvpnMac {
                id,
                rd: *rd,
                esi: rib.esi.unwrap_or([0; 10]),
                ether_tag: *eth_tag,
                mac: *mac,
                vni,
            })
        }
        EvpnPrefix::InclusiveMulticast { eth_tag, orig } => EvpnRoute::Multicast(EvpnMulticast {
            id,
            rd: *rd,
            ether_tag: *eth_tag,
            addr: *orig,
        }),
    };

    let mut attrs = (*rib.attr).clone();

    if peer.is_ebgp()
        && let Some(ref mut aspath) = attrs.aspath
    {
        let local_as_path = As4Path::from(vec![peer.local_as]);
        aspath.prepend_mut(local_as_path);
    }

    if peer.is_ebgp() || rib.is_originated() {
        let nexthop: IpAddr = if let Some(ref local_addr) = peer.param.local_addr {
            local_addr.ip()
        } else {
            IpAddr::V4(*bgp.router_id)
        };
        attrs.nexthop = Some(BgpNexthop::Evpn(nexthop));
    }

    if peer.is_ibgp() && attrs.local_pref.is_none() {
        attrs.local_pref = Some(LocalPref::default());
    }

    Some((route, attrs))
}

/// Send a single EVPN withdraw to one peer. Mirrors
/// `route_withdraw_ipv4` — no caching, straight to the wire as a
/// one-NLRI MP_UNREACH UPDATE. The receiver removes the route from
/// its adj-RIB-in and re-runs best-path; an empty selection at the
/// peer triggers `route_evpn_export_selected` which sends
/// `Message::MacDel` / `MdbDel` and the kernel FDB row goes away.
fn route_withdraw_evpn(peer: &mut Peer, route: EvpnRoute) {
    let mut update = UpdatePacket::with_max_packet_size(peer.max_packet_size());
    update.mp_withdraw = Some(MpUnreachAttr::Evpn(vec![route]));
    peer.send_packet(update.into());
}

/// Fan out a withdraw to every peer with `(L2vpn, Evpn)` Established.
/// Also drains any pending advertise from each peer's `cache_evpn` —
/// without this, a quick add/remove cycle would leave a stale
/// announce in the cache that fires after the withdraw wins on the
/// wire.
pub fn route_withdraw_evpn_to_peers(
    rd: RouteDistinguisher,
    prefix: EvpnPrefix,
    peers: &mut PeerMap,
) {
    let peer_addrs: Vec<IpAddr> = peers
        .iter()
        .filter(|(_, p)| p.state.is_established())
        .filter(|(_, p)| p.is_afi_safi(Afi::L2vpn, Safi::Evpn))
        .map(|(addr, _)| *addr)
        .collect();

    for peer_addr in peer_addrs {
        let peer = peers.get_mut(&peer_addr).expect("peer exists");
        let route = evpn_route_from_prefix(&rd, &prefix, 0);
        // Drop a queued advertise for the same route from the peer's
        // cache so flush_evpn doesn't ship a now-stale add after we
        // ship the withdraw.
        if let Some(attr) = peer.cache_evpn_rev.remove(&route)
            && let Some(set) = peer.cache_evpn.get_mut(&attr)
        {
            set.remove(&route);
            if set.is_empty() {
                peer.cache_evpn.remove(&attr);
            }
        }
        route_withdraw_evpn(peer, route);
    }
}

/// Build an `EvpnRoute` (Mac/Multicast) from an `(rd, prefix)` pair
/// — needed both at advertise time (in `route_update_evpn` via the
/// inbound BgpRib's attr) and at withdraw time, where there's no
/// inbound attr to consult and the VNI is recovered from the RD's
/// trailing 2 bytes (Type-1 form). ESI defaults to zero, eth-tag
/// passes through.
fn evpn_route_from_prefix(rd: &RouteDistinguisher, prefix: &EvpnPrefix, id: u32) -> EvpnRoute {
    match prefix {
        EvpnPrefix::MacIp { eth_tag, mac, .. } => {
            // RD type 1 (IPv4 + 2-byte assigned-number) is the form
            // we emit at origination — the assigned-number bytes
            // [4..6] carry the low 16 bits of the VNI.
            let vni = u16::from_be_bytes([rd.val[4], rd.val[5]]) as u32;
            EvpnRoute::Mac(EvpnMac {
                id,
                rd: *rd,
                esi: [0; 10],
                ether_tag: *eth_tag,
                mac: *mac,
                vni,
            })
        }
        EvpnPrefix::InclusiveMulticast { eth_tag, orig } => EvpnRoute::Multicast(EvpnMulticast {
            id,
            rd: *rd,
            ether_tag: *eth_tag,
            addr: *orig,
        }),
    }
}

/// Fan out an EVPN best-path selection to every peer with the
/// `(L2vpn, Evpn)` AFI/SAFI established. Skips peers filtered by
/// split-horizon / iBGP rules inside `route_update_evpn`. Pairs with
/// `route_withdraw_evpn_to_peers` for the inverse direction.
pub fn route_advertise_evpn_to_peers(
    rd: RouteDistinguisher,
    prefix: EvpnPrefix,
    selected: &[BgpRib],
    bgp: &mut BgpTop,
    peers: &mut PeerMap,
) {
    let Some(new_best) = selected.last() else {
        return;
    };

    let peer_addrs: Vec<IpAddr> = peers
        .iter()
        .filter(|(_, p)| p.state.is_established())
        .filter(|(_, p)| p.is_afi_safi(Afi::L2vpn, Safi::Evpn))
        .map(|(addr, _)| *addr)
        .collect();

    for peer_addr in peer_addrs {
        let peer = peers.get_mut(&peer_addr).expect("peer exists");
        let add_path = peer.opt.is_add_path_send(Afi::L2vpn, Safi::Evpn);

        let Some((route, attr)) = route_update_evpn(peer, &rd, &prefix, new_best, bgp, add_path)
        else {
            continue;
        };

        let attr = bgp.attr_store.intern(attr);
        peer.send_evpn(route, attr, true);
    }
}

// Send BGP withdrawal for a prefix
fn route_withdraw_ipv4(peer: &mut Peer, rd: Option<RouteDistinguisher>, prefix: Ipv4Net, id: u32) {
    let mut update = UpdatePacket::with_max_packet_size(peer.max_packet_size());

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
    ident: usize,
    nlri: &Ipv4Nlri,
    rd: Option<RouteDistinguisher>,
    _label: Option<Label>,
    bgp: &mut BgpTop,
    peers: &mut PeerMap,
    rib_in: bool,
) {
    {
        if rib_in {
            let peer = peers.get_mut_by_idx(ident).expect("peer must exist");
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
        route_advertise_to_peers(rd, nlri.prefix, &selected, ident, bgp, peers);
    }
    if let Some(removed) = removed.pop() {
        route_withdraw_from_addpath(rd, nlri.prefix, &removed, ident, bgp, peers);
    }
}

pub fn route_ipv4_rtc_update(peer_id: usize, rtcv4: &Rtcv4, peers: &mut PeerMap) {
    let Some(peer) = peers.get_mut_by_idx(peer_id) else {
        return;
    };
    peer.rtcv4.insert(rtcv4.rt.clone());
}

pub fn route_rtcv4_sync(peer_id: usize, bgp: &mut BgpTop, peers: &mut PeerMap) {
    let Some(peer) = peers.get_mut_by_idx(peer_id) else {
        return;
    };
    let key = AfiSafi::new(Afi::Ip, Safi::Rtc);
    if peer.eor.contains_key(&key) {
        route_sync_vpnv4(peer, bgp);
    }
    peer.eor.clear();
}

/// Extract VNI from Route Distinguisher
/// For EVPN routes, VNI is typically encoded in the lower 3 bytes of the RD value.
/// RFC 7432 uses RD Type 0 (ASN) with format: [2 bytes ASN][3 bytes VNI][1 byte index]
///
/// Extract VNI from Route Target (RT) extended community
///
/// RFC 8365 Section 5.1: "Each VXLAN EVPN instance is associated with a VXLAN VNI.
/// The VNI is encoded in the Route Target extended community."
///
/// RFC 4360: Route Target Type 0x0002 (transitive)
/// Value format: [2 bytes ASN][4 bytes value]
/// VNI = lower 3 bytes of value (24-bit, bytes [2:5])
///
/// Example: RT 65501:550
///   - ASN: 65501 (0xFF8D)
///   - Value: 550 (0x000226)
///   - Bytes [2:5]: [0x02, 0x26, 0x00] → VNI 550
fn extract_vni_from_attr(attr: &BgpAttr) -> Option<u32> {
    if let Some(ecom) = &attr.ecom {
        for ec in &ecom.0 {
            // RFC 4360 Two-Octet AS Specific Route Target: high 0x00,
            // low 0x02. Wire layout of the 6-byte value:
            //   val[0..2] = Global Administrator (2-byte ASN)
            //   val[2..6] = Local Administrator (4 bytes)
            // RFC 8365 §5.1.2.4 places the VNI in the *lower 3 bytes*
            // of the 4-byte Local Administrator — i.e. val[3..6]. The
            // earlier code read val[2..5] which is offset by one byte
            // and grabbed the high (always-zero for ≤24-bit VNIs)
            // byte, producing values 256× too small. For RT 65501:550
            // the buggy read returned 2; for any 24-bit VNI < 0x100
            // it returned 0 and skipped the route entirely.
            if ec.high_type == 0x00 && ec.low_type == 0x02 {
                let vni =
                    ((ec.val[3] as u32) << 16) | ((ec.val[4] as u32) << 8) | (ec.val[5] as u32);

                if vni > 0 && vni < 0x1000000 {
                    tracing::info!("extract_vni_from_attr: RT yields VNI {}", vni);
                    return Some(vni);
                }
            }
        }
    }
    None
}

/// Extract flags (sticky, gateway, router) from extended communities
fn extract_flags_from_attr(attr: &BgpAttr) -> u8 {
    let mut flags = 0u8;

    if let Some(ecom) = &attr.ecom {
        for ec in &ecom.0 {
            // Check for Sticky MAC (Type 0x09, Sub-type 0x00)
            if ec.high_type == 0x09 && ec.low_type == 0x00 {
                // Sticky MAC flag
                flags |= 0x01;
            }
            // Check for Gateway MAC (Type 0x09, Sub-type 0x01)
            if ec.high_type == 0x09 && ec.low_type == 0x01 {
                // Gateway MAC flag
                flags |= 0x02;
            }
            // Check for Router flag (Type 0x09, Sub-type 0x03)
            if ec.high_type == 0x09 && ec.low_type == 0x03 {
                // Router flag
                flags |= 0x04;
            }
        }
    }

    flags
}

/// Extract MAC mobility sequence number from extended communities
fn extract_mac_mobility_seq(attr: &BgpAttr) -> u32 {
    if let Some(ecom) = &attr.ecom {
        for ec in &ecom.0 {
            // Check for MAC Mobility (Type 0x06, Sub-type 0x00)
            if ec.high_type == 0x06 && ec.low_type == 0x00 {
                // Sequence number is in bytes 4-5
                return u32::from_be_bytes([ec.val[2], ec.val[3], ec.val[4], ec.val[5]]);
            }
        }
    }
    0
}

/// Extract the remote VTEP IP for a received EVPN route. The VTEP
/// is the BGP nexthop, but EVPN routes carry it in
/// `BgpAttr::nexthop` as `BgpNexthop::Evpn(IpAddr)` — populated from
/// the MP_REACH_NLRI nexthop field on receive (`bgp/route.rs:960`).
///
/// `BgpRib::nexthop` is the VPNv4-specific `Vpnv4Nexthop` slot and
/// is always None for EVPN; the previous code read that field and
/// produced `tunnel_endpoint = None` for every received Type-2,
/// which made `mac_add` build an FDB row with no NDA_DST and the
/// kernel rejected the install with EINVAL.
fn extract_tunnel_endpoint(rib: &BgpRib) -> Option<IpAddr> {
    match rib.attr.nexthop.as_ref()? {
        BgpNexthop::Evpn(addr) => Some(*addr),
        _ => None,
    }
}

/// Export selected EVPN MAC entry to RIB for kernel installation
/// Called after best path selection to send MACs to the RIB layer.
///
/// `withdrawn` carries the path that was just removed from the
/// candidate set (when called from the withdraw flow). It exists
/// because the VNI lives in the path's RT extended community per
/// RFC 8365 §5.1.2.4 — and once `selected` is empty (no remaining
/// path on this prefix), there's no candidate to read the RT from.
/// Reading it from the withdrawn path's attr is the only correct
/// source. On the announce flow `withdrawn` is `None`; the empty-
/// selected case is unreachable there.
fn route_evpn_export_selected(
    rd: &RouteDistinguisher,
    prefix: &EvpnPrefix,
    selected: &[BgpRib],
    withdrawn: Option<&BgpRib>,
    bgp: &mut BgpTop,
) {
    // If no selected path exists, send delete using the withdrawn
    // path's attr as the RT/VNI source.
    if selected.is_empty() {
        let Some(wd) = withdrawn else {
            // Withdraw of a non-existent path — nothing was removed,
            // nothing to delete in kernel state. Silent no-op.
            return;
        };
        match prefix {
            EvpnPrefix::MacIp { mac, .. } => {
                // Match the announce-side filter: never installed
                // multicast MAC entries → nothing to delete.
                let mac_addr = MacAddr::from(*mac);
                if mac_addr.is_multicast() {
                    return;
                }
                if let Some(vni) = extract_vni_from_attr(&wd.attr) {
                    let msg = rib::Message::MacDel { vni, mac: mac_addr };
                    let _ = bgp.rib_tx.send(msg);
                } else {
                    eprintln!(
                        "[ERROR] EVPN Type 2 withdraw: removed path has no Route Target. \
                         RD: {:?}",
                        rd
                    );
                }
            }
            EvpnPrefix::InclusiveMulticast { orig, .. } => {
                if let Some(vni) = extract_vni_from_attr(&wd.attr) {
                    let msg = rib::Message::MdbDel {
                        vni,
                        group: *orig,
                        source: None,
                        ifindex: 0,
                    };
                    let _ = bgp.rib_tx.send(msg);
                } else {
                    eprintln!(
                        "[ERROR] EVPN Type 3 withdraw: removed path has no Route Target. \
                         RD: {:?}",
                        rd
                    );
                }
            }
        }
        return;
    }

    // Extract best path (last entry in selected vector)
    let best = &selected[selected.len() - 1];

    match prefix {
        EvpnPrefix::MacIp { mac, .. } => {
            // Defensive: the local FDB->BGP origination path skips
            // multicast MACs in `fdb_entry_from_neighbor`, but a peer
            // running different software may still have advertised
            // one. Don't try to install — there is no remote host
            // behind a multicast MAC and the kernel FDB rows for
            // these are local-reception filters owned by the OS.
            let mac_addr = MacAddr::from(*mac);
            if mac_addr.is_multicast() {
                return;
            }
            // RFC 8365: VNI must come from Route Target extended community
            if let Some(vni) = extract_vni_from_attr(&best.attr) {
                let msg = rib::Message::MacAdd {
                    vni,
                    mac: mac_addr,
                    tunnel_endpoint: extract_tunnel_endpoint(best),
                    flags: extract_flags_from_attr(&best.attr),
                    seq: extract_mac_mobility_seq(&best.attr),
                    esi: best.esi, // Phase 4D: Extracted from EVPN route
                };
                let _ = bgp.rib_tx.send(msg);
            } else {
                eprintln!(
                    "[ERROR] EVPN Type 2 route missing Route Target (RFC 8365). \
                     VNI required from RT extended community. RD: {:?}",
                    rd
                );
            }
        }
        EvpnPrefix::InclusiveMulticast { orig, .. } => {
            // Phase 4B: Type 3 Inclusive Multicast route installation
            // This route indicates that a multicast group (*,G) should be replicated to
            // all VTEPs that have advertised this route.
            // RFC 8365: VNI must come from Route Target extended community
            if let Some(vni) = extract_vni_from_attr(&best.attr) {
                let msg = rib::Message::MdbAdd {
                    vni,
                    group: *orig,
                    source: None,
                    ifindex: 0,
                    seq: extract_mac_mobility_seq(&best.attr),
                };
                let _ = bgp.rib_tx.send(msg);
            } else {
                eprintln!(
                    "[ERROR] EVPN Type 3 route missing Route Target (RFC 8365). \
                     VNI required from RT extended community. RD: {:?}",
                    rd
                );
            }
        }
    }
}

/// Install one EVPN route received in an MP_REACH_NLRI into Adj-RIB-In and
/// the Loc-RIB. Mirrors `route_ipv4_update` but takes the parsed
/// `EvpnRoute` directly.
///
/// The `_nhop` parameter (the per-MpReach EVPN nexthop) is currently
/// unused: `BgpRib::new` only carries a `Vpnv4Nexthop`, which is IPv4-only
/// and RD-bound. The EVPN nexthop is recoverable from `peer.address` for
/// display purposes; threading it through `BgpRib` is a follow-up tied to
/// the show command (Step 5).
pub fn route_evpn_update(
    ident: usize,
    route: &EvpnRoute,
    _nhop: IpAddr,
    attr: &BgpAttr,
    bgp: &mut BgpTop,
    peers: &mut PeerMap,
    stale: bool,
) {
    let (rd, prefix) = EvpnPrefix::from_route(route);
    let id = match route {
        EvpnRoute::Mac(m) => m.id,
        EvpnRoute::Multicast(m) => m.id,
    };

    // Loop detection mirrors route_ipv4_update — drop the route silently
    // (no eprintln) on local-AS / ORIGINATOR_ID / CLUSTER_LIST hits.
    let (peer_ident, peer_router_id, typ) = {
        let peer = peers.get_mut_by_idx(ident).expect("peer must exist");

        if let Some(ref aspath) = attr.aspath {
            for segment in &aspath.segs {
                if segment.asn.contains(&peer.local_as) {
                    return;
                }
            }
        }
        if let Some(ref originator_id) = attr.originator_id
            && originator_id.id == *bgp.router_id
        {
            return;
        }
        if let Some(ref cluster_list) = attr.cluster_list
            && cluster_list.list.contains(bgp.router_id)
        {
            return;
        }

        let typ = if peer.is_ibgp() {
            BgpRibType::IBGP
        } else {
            BgpRibType::EBGP
        };

        (peer.ident, peer.remote_id, typ)
    };

    let mut rib = BgpRib::new(
        peer_ident,
        peer_router_id,
        typ,
        id,
        0, // weight
        attr,
        None, // label (not applicable to EVPN at this layer)
        None, // nexthop — see function doc
        stale,
    );

    // Phase 4D: Extract ESI from EVPN Type 2 route for multi-homing support
    if let EvpnRoute::Mac(m) = route {
        rib.esi = Some(m.esi);
    }

    {
        let peer = peers.get_mut_by_idx(ident).expect("peer must exist");
        peer.adj_in.add_evpn(rd, prefix.clone(), rib.clone());
    }

    let _ = bgp.local_rib.update_evpn(rd, prefix.clone(), rib);

    // After updating Loc-RIB, re-run best path selection and export to RIB.
    // No `withdrawn` source on the announce path — selected is non-empty by
    // construction (we just inserted the path).
    let selected = bgp.local_rib.select_best_path_evpn(&rd, &prefix);
    route_evpn_export_selected(&rd, &prefix, &selected, None, bgp);
}

/// Withdraw one EVPN route advertised in an MP_UNREACH_NLRI from Adj-RIB-In
/// and the Loc-RIB, then re-run best-path selection.
pub fn route_evpn_withdraw(ident: usize, route: &EvpnRoute, bgp: &mut BgpTop, peers: &mut PeerMap) {
    let (rd, prefix) = EvpnPrefix::from_route(route);
    let id = match route {
        EvpnRoute::Mac(m) => m.id,
        EvpnRoute::Multicast(m) => m.id,
    };

    {
        let peer = peers.get_mut_by_idx(ident).expect("peer must exist");
        peer.adj_in.remove_evpn(rd, &prefix, id);
    }

    // Capture the removed path so the export below can read its
    // RT-derived VNI when the prefix has no remaining selected path.
    // `remove_evpn` returns every candidate that matched
    // `(ident, remote_id)`; in normal operation that's a single path,
    // and `.first()` is fine. If the prefix wasn't in the RIB the
    // vec is empty and the export becomes a no-op.
    let removed = bgp.local_rib.remove_evpn(rd, &prefix, id, ident);
    let selected = bgp.local_rib.select_best_path_evpn(&rd, &prefix);

    route_evpn_export_selected(&rd, &prefix, &selected, removed.first(), bgp);
}

pub fn route_from_peer(
    peer_id: usize,
    packet: UpdatePacket,
    bgp: &mut BgpTop,
    peers: &mut PeerMap,
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
                        Some(update.rd),
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
            MpReachAttr::Evpn {
                snpa: _,
                nhop,
                updates,
            } => {
                for route in updates.iter() {
                    route_evpn_update(peer_id, route, nhop, bgp_attr, bgp, peers, false);
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
                        Some(withdraw.rd),
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
            MpUnreachAttr::Evpn(withdrawals) => {
                for route in withdrawals.iter() {
                    route_evpn_withdraw(peer_id, route, bgp, peers);
                }
            }
            MpUnreachAttr::EvpnEor => {
                let afi_safi = AfiSafi::new(Afi::L2vpn, Safi::Evpn);
                let _ = bgp
                    .tx
                    .send(Message::Event(peer_id, Event::StaleTimerExipires(afi_safi)));
            }
            _ => {
                //
            }
        }
    }
}

pub fn route_clean(peer_id: usize, bgp: &mut BgpTop, peers: &mut PeerMap) {
    // IPv4 unicast.
    let withdrawn = {
        let mut withdrawn: Vec<Ipv4Nlri> = vec![];
        let peer = peers.get_mut_by_idx(peer_id).expect("peer must exist");

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
        route_ipv4_withdraw(peer_id, withdraw, None, None, bgp, peers, true);
    }
    let peer = peers.get_mut_by_idx(peer_id).expect("peer must exist");
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

        for (_rd, table) in peer.adj_in.v4vpn.iter_mut() {
            for (_prefix, ribs) in table.0.iter_mut() {
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
                            *rd,
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
            let peer = peers.get_mut_by_idx(peer_id).expect("peer must exist");

            for (rd, table) in peer.adj_in.v4vpn.iter() {
                for (prefix, ribs) in table.0.iter() {
                    for rib in ribs.iter() {
                        let withdraw = Vpnv4Nlri {
                            label: rib.label.unwrap_or(Label::default()),
                            rd: *rd,
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
                Some(withdraw.rd),
                Some(withdraw.label),
                bgp,
                peers,
                true,
            );
        }
        let peer = peers.get_mut_by_idx(peer_id).expect("peer must exist");
        peer.adj_in.v4vpn.clear();
    }

    let peer = peers.get_mut_by_idx(peer_id).expect("peer must exist");
    peer.adj_out.v4vpn.clear();

    // EVPN. Same shape as the VPNv4 block above:
    //   * If both ends advertised LLGR for L2VPN/EVPN, retain the
    //     adj-in entries marked stale (with the LLGR_STALE community
    //     attached) and re-import them into the local-RIB so best
    //     path selection still considers them; the stale timer
    //     evicts them later.
    //   * Otherwise, withdraw every route the peer had given us.
    //     `route_evpn_withdraw` removes from adj-in + local-RIB and
    //     fans out MP_UNREACH to other peers (covering any kernel
    //     install/withdraw via `route_evpn_export_selected`).
    let afi_safi_evpn = AfiSafi::new(Afi::L2vpn, Safi::Evpn);
    let llgr_evpn = peer.cap_send.llgr.contains_key(&afi_safi_evpn)
        && peer.cap_recv.llgr.contains_key(&afi_safi_evpn);
    if llgr_evpn {
        let stale_time = peer
            .cap_recv
            .llgr
            .get(&afi_safi_evpn)
            .expect("checked above")
            .stale_time();
        peer.timer.stale_timer.insert(
            afi_safi_evpn,
            start_stale_timer(peer, afi_safi_evpn, stale_time),
        );
        for (_rd, table) in peer.adj_in.evpn.iter_mut() {
            for (_prefix, ribs) in table.0.iter_mut() {
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

        // Re-import the now-stale entries into local-RIB so best-path
        // re-evaluation includes the stale attr+community.
        let stale_updates: Vec<(EvpnRoute, BgpAttr, IpAddr)> = {
            let mut updates = Vec::new();
            for (rd, table) in peer.adj_in.evpn.iter() {
                for (prefix, ribs) in table.0.iter() {
                    for rib in ribs.iter() {
                        if let Some(route) = build_evpn_route(rd, prefix, rib) {
                            let nhop = match rib.attr.nexthop.as_ref() {
                                Some(BgpNexthop::Evpn(addr)) => *addr,
                                _ => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                            };
                            updates.push((route, (*rib.attr).clone(), nhop));
                        }
                    }
                }
            }
            updates
        };
        for (route, attr, nhop) in stale_updates {
            route_evpn_update(peer_id, &route, nhop, &attr, bgp, peers, true);
        }
    } else {
        let withdrawn: Vec<EvpnRoute> = {
            let peer = peers.get_mut_by_idx(peer_id).expect("peer must exist");
            let mut out = Vec::new();
            for (rd, table) in peer.adj_in.evpn.iter() {
                for (prefix, ribs) in table.0.iter() {
                    for rib in ribs.iter() {
                        if let Some(route) = build_evpn_route(rd, prefix, rib) {
                            out.push(route);
                        }
                    }
                }
            }
            out
        };
        for route in withdrawn.iter() {
            route_evpn_withdraw(peer_id, route, bgp, peers);
        }
        let peer = peers.get_mut_by_idx(peer_id).expect("peer must exist");
        peer.adj_in.evpn.clear();
    }

    let peer = peers.get_mut_by_idx(peer_id).expect("peer must exist");
    peer.adj_out.evpn.clear();
    peer.cache_evpn.clear();
    peer.cache_evpn_rev.clear();
    peer.cache_evpn_timer = None;

    peer.cap_map = CapAfiMap::new();
    peer.cap_recv = BgpCap::default();
    peer.opt.clear();

    // IPv4 RTC.
    peer.rtcv4.clear();
    peer.eor.clear();
}

/// Reconstruct the wire `EvpnRoute` from a Loc-RIB / Adj-RIB entry,
/// re-deriving the per-NLRI fields (path-id, ESI, VNI) from the
/// stored `BgpRib`. Used by the peer-down cleanup path to feed
/// `route_evpn_withdraw`.
fn build_evpn_route(
    rd: &RouteDistinguisher,
    prefix: &EvpnPrefix,
    rib: &BgpRib,
) -> Option<EvpnRoute> {
    match prefix {
        EvpnPrefix::MacIp { eth_tag, mac, .. } => {
            let vni = extract_vni_from_attr(&rib.attr).unwrap_or(0);
            Some(EvpnRoute::Mac(EvpnMac {
                id: rib.remote_id,
                rd: *rd,
                esi: rib.esi.unwrap_or([0; 10]),
                ether_tag: *eth_tag,
                mac: *mac,
                vni,
            }))
        }
        EvpnPrefix::InclusiveMulticast { eth_tag, orig } => {
            Some(EvpnRoute::Multicast(EvpnMulticast {
                id: rib.remote_id,
                rd: *rd,
                ether_tag: *eth_tag,
                addr: *orig,
            }))
        }
    }
}

pub fn stale_route_withdraw(peer_id: usize, bgp: &mut BgpTop, peers: &mut PeerMap) {
    // Fetch all of route which has stale flag.
    let withdrawn = {
        let peer = peers.get_by_idx(peer_id).expect("peer must exist");
        let mut withdrawn: Vec<Vpnv4Nlri> = vec![];

        for (rd, table) in peer.adj_in.v4vpn.iter() {
            for (prefix, ribs) in table.0.iter() {
                for rib in ribs.iter() {
                    if rib.stale {
                        let withdraw = Vpnv4Nlri {
                            label: rib.label.unwrap_or(Label::default()),
                            rd: *rd,
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
            Some(withdraw.rd),
            Some(withdraw.label),
            bgp,
            peers,
            true,
        );
    }
}

pub fn route_update_ipv4(
    peer: &mut Peer,
    prefix: &Ipv4Net,
    rib: &BgpRib,
    bgp: &mut BgpTop,
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
    if peer.is_ebgp()
        && let Some(ref mut aspath) = attrs.aspath
    {
        let local_as_path = As4Path::from(vec![peer.local_as]);
        aspath.prepend_mut(local_as_path.clone());
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
    if peer.is_ibgp() && attrs.local_pref.is_none() {
        attrs.local_pref = Some(LocalPref::default());
    }

    // 6. Originator ID (for IBGP route reflection)
    // RFC 4456: A route reflector SHOULD NOT create an ORIGINATOR_ID if one already
    // exists. ORIGINATOR_ID is set only once by the first route reflector and preserved
    // thereafter to identify the original route source within the AS.
    if peer.peer_type == PeerType::IBGP
        && rib.typ == BgpRibType::IBGP
        && attrs.originator_id.is_none()
    {
        // Set ORIGINATOR_ID to the router ID of the peer that originated this route
        attrs.originator_id = Some(OriginatorId::new(rib.router_id));
    }
    // If ORIGINATOR_ID already exists, preserve it (don't overwrite)

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

impl Peer {
    pub fn send_packet(&self, bytes: BytesMut) {
        if let Some(ref packet_tx) = self.packet_tx
            && let Err(e) = packet_tx.send(bytes)
        {
            eprintln!("Failed to send BGP packet to {}: {}", self.address, e);
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
        if let Some(attr) = self.cache_ipv4_rev.remove(&nlri)
            && let Some(set) = self.cache_ipv4.get_mut(&attr)
        {
            set.remove(&nlri);
            if set.is_empty() {
                self.cache_ipv4.remove(&attr);
            }
        }
    }

    // Flush BGP update.
    pub fn flush_ipv4(&mut self) {
        let packet_tx = self.packet_tx.clone();
        let max_size = self.max_packet_size();
        for (attr, nlris) in self.cache_ipv4.drain() {
            let mut update = UpdatePacket::with_max_packet_size(max_size);
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
        if let Some(attr) = self.cache_vpnv4_rev.remove(&nlri)
            && let Some(set) = self.cache_vpnv4.get_mut(&attr)
        {
            set.remove(&nlri);
            if set.is_empty() {
                self.cache_vpnv4.remove(&attr);
            }
        }
    }

    /// Cache an EVPN route for advertisement, grouped by attribute.
    /// Mirrors `send_vpnv4`: same timer-debounce shape, same
    /// per-attribute batching so a single MP_REACH UPDATE can carry
    /// every route that shares an attribute set.
    pub fn send_evpn(&mut self, route: EvpnRoute, attr: Arc<BgpAttr>, timer: bool) {
        self.cache_evpn
            .entry(attr.clone())
            .or_default()
            .insert(route.clone());
        self.cache_evpn_rev.insert(route, attr);
        if timer && self.cache_evpn_timer.is_none() {
            self.cache_evpn_timer = Some(start_adv_timer_evpn(self));
        }
    }

    /// Drain `cache_evpn` and emit one BGP UPDATE per attribute
    /// group via `pop_evpn`. Pagination across multiple UPDATEs is a
    /// follow-up; the encoder currently emits all NLRIs from a
    /// single attr group in one packet.
    pub fn flush_evpn(&mut self) {
        let packet_tx = self.packet_tx.clone();
        let max_size = self.max_packet_size();
        for (attr, routes) in self.cache_evpn.drain() {
            let mut update = UpdatePacket::with_max_packet_size(max_size);

            // Nexthop comes from the cached attribute. EVPN allows
            // either an IPv4 or IPv6 nexthop; if neither was set on
            // the attr (shouldn't happen for locally-originated
            // routes), default to 0.0.0.0 — the receiver will
            // notice and drop, which is the right behavior.
            let nhop = match attr.nexthop.as_ref() {
                Some(BgpNexthop::Evpn(addr)) => *addr,
                _ => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            };
            update.mp_update = Some(MpReachAttr::Evpn {
                snpa: 0,
                nhop,
                updates: routes.into_iter().collect(),
            });
            update.bgp_attr = Some((*attr).clone());

            if let Some(bytes) = update.pop_evpn()
                && let Some(ref tx) = packet_tx
            {
                let _ = tx.send(bytes);
            }
        }
        self.cache_evpn_rev.clear();
    }

    // Flush BGP update.
    pub fn flush_vpnv4(&mut self) {
        let packet_tx = self.packet_tx.clone();
        let max_size = self.max_packet_size();
        for (attr, nlris) in self.cache_vpnv4.drain() {
            let mut update = UpdatePacket::with_max_packet_size(max_size);

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

pub fn route_sync_ipv4(peer: &mut Peer, bgp: &mut BgpTop) {
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

pub fn route_sync_vpnv4(peer: &mut Peer, bgp: &mut BgpTop) {
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
                (*rd, routes)
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
                (*rd, routes)
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
            if !peer.rtcv4.is_empty() && !rtc_match(&peer.rtcv4, &attr.ecom) {
                continue;
            }

            // Register to AdjOut.
            rib.attr = bgp.attr_store.intern(attr);
            let arc_attr = rib.attr.clone();
            peer.adj_out.add(Some(rd), nlri.prefix, rib);

            let vpnv4_nlri = Vpnv4Nlri {
                label: Label::default(),
                rd,
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
    let update = UpdatePacket::with_max_packet_size(peer.max_packet_size());
    peer.send_packet(update.into());
}

// Send End-of-RIB marker for VPNv4 Unicast.
fn send_eor_vpnv4_unicast(peer: &mut Peer) {
    let mut update = UpdatePacket::with_max_packet_size(peer.max_packet_size());
    update.mp_withdraw = Some(MpUnreachAttr::Vpnv4Eor);
    peer.send_packet(update.into());
}

// Send wildcard RTCv4.
fn send_default_rtcv4_unicast(peer: &mut Peer) {
    let mut update = UpdatePacket::with_max_packet_size(peer.max_packet_size());

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
    let mut update = UpdatePacket::with_max_packet_size(peer.max_packet_size());
    update.mp_withdraw = Some(MpUnreachAttr::Rtcv4Eor);
    peer.send_packet(update.into());
}

// Send End-of-RIB marker for L2VPN/EVPN. RFC 4724 §2 represents EoR
// as an empty UPDATE; the multiprotocol form (RFC 7606 §3) carries
// it as an MP_UNREACH with empty NLRI for the AFI/SAFI in question.
fn send_eor_evpn(peer: &mut Peer) {
    let mut update = UpdatePacket::with_max_packet_size(peer.max_packet_size());
    update.mp_withdraw = Some(MpUnreachAttr::EvpnEor);
    peer.send_packet(update.into());
}

/// Replay every selected EVPN route from the local-RIB to a peer
/// that just transitioned to Established. Mirrors `route_sync_ipv4`:
/// per-RD walk over `LocalRib::evpn[rd].selected`, push through
/// `route_update_evpn` (which handles split-horizon and iBGP gating),
/// batch into the per-peer EVPN cache, then flush a single batched
/// MP_REACH and finish with the EVPN EoR.
///
/// Called from `route_sync` only when the peer negotiated the
/// `(L2vpn, Evpn)` capability — without that gate the receiver would
/// reject the UPDATE.
pub fn route_sync_evpn(peer: &mut Peer, bgp: &mut BgpTop) {
    let add_path = peer.opt.is_add_path_send(Afi::L2vpn, Safi::Evpn);

    // Snapshot first to dodge the borrow checker — `route_update_evpn`
    // takes `&mut Peer` and `&mut BgpTop`, both of which alias the
    // RIB we're walking.
    let snapshot: Vec<(RouteDistinguisher, EvpnPrefix, BgpRib)> = bgp
        .local_rib
        .evpn
        .iter()
        .flat_map(|(rd, table)| {
            table
                .selected
                .iter()
                .map(move |(prefix, rib)| (*rd, prefix.clone(), rib.clone()))
        })
        .collect();

    for (rd, prefix, rib) in snapshot {
        let Some((route, attr)) = route_update_evpn(peer, &rd, &prefix, &rib, bgp, add_path) else {
            continue;
        };
        let attr = bgp.attr_store.intern(attr);
        // `false`: don't arm the per-peer advertise timer — we flush
        // synchronously at end-of-sync so the new peer sees one
        // batched MP_REACH (or several, one per attribute group)
        // followed immediately by EoR, rather than waiting for the
        // debounce.
        peer.send_evpn(route, attr, false);
    }

    peer.flush_evpn();
    send_eor_evpn(peer);
}

// Called when peer has been established.
pub fn route_sync(peer: &mut Peer, bgp: &mut BgpTop) {
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
        if !peer.eor.contains_key(&key) {
            route_sync_vpnv4(peer, bgp);
        }
    }
    if peer.is_afi_safi(Afi::L2vpn, Safi::Evpn) {
        route_sync_evpn(peer, bgp);
    }
}

impl Bgp {
    pub fn route_add(&mut self, prefix: Ipv4Net) {
        let ident = ORIGINATED_PEER;
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

        let mut bgp_ref = BgpTop {
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
        let ident = ORIGINATED_PEER;
        let id = 0;
        let removed = self.local_rib.remove(None, prefix, id, ident);

        let mut bgp_ref = BgpTop {
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

    /// Originate an EVPN Type-2 (MAC/IP Advertisement) route from a
    /// kernel-learned bridge FDB entry.
    ///
    /// Inserts into `Bgp::local_rib.evpn` only — wire transmission
    /// (route_advertise_evpn_to_peers + send_evpn) lands in a follow-up.
    /// Verification target this PR: `show bgp l2vpn evpn` lists the
    /// route after a local FDB learn.
    ///
    /// Gates:
    ///   - `advertise_all_vni` must be true (FRR-style global enable).
    ///   - `NTF_EXT_LEARNED` must be clear in the FDB flags. Set bits
    ///     mark FDB rows that arrived via netlink from another speaker
    ///     (typically zebra-rs's own `mac_add` path installing a
    ///     remote VTEP MAC); re-advertising them would loop.
    ///
    /// Hardcodes (per RFC 8365 single-homed VLAN-Based service):
    ///   - ESI = 0 (no multi-homing)
    ///   - Ethernet Tag = 0 (one bridge per VNI)
    ///   - IP component absent (MAC-only Type-2; MAC+IP needs ARP/NDP
    ///     correlation, follow-up).
    ///   - RD = `<router-id>:<VNI>` (Type-1, IPv4 + 2-byte). VNIs
    ///     above 65535 are skipped — Type-0 ASN-format RD support
    ///     for big VNIs is a follow-up.
    pub fn evpn_originate_macip(&mut self, entry: &FdbEntry) {
        if !self.advertise_all_vni {
            return;
        }
        if entry.flags & NTF_EXT_LEARNED != 0 {
            return;
        }
        // Defer until router-id is set. The `local_fdb` cache holds
        // the entry; `set_router_id` replays the cache when the
        // router-id transitions from unspecified to a real value
        // (auto-derived from interface addrs or set by operator
        // config). Without this gate, a cold-boot race would emit
        // routes under RD `0.0.0.0:VNI`, peers would accept them,
        // and the subsequent router-id update would leave the
        // 0.0.0.0 RD orphaned (no path withdraws it).
        if self.router_id.is_unspecified() {
            return;
        }
        let Some(rd) = rd_from_router_id_vni(self.router_id, entry.vni) else {
            tracing::warn!(
                "evpn_originate_macip: VNI {} > 65535, RD encoding not yet supported; \
                 dropping local origination for {}",
                entry.vni,
                entry.mac
            );
            return;
        };
        let prefix = EvpnPrefix::MacIp {
            eth_tag: 0,
            mac: entry.mac.octets(),
            ip: None,
        };

        // Build the BGP attributes for this origination. RFC 8365
        // §5.1.2.4 requires both:
        //   - RT (Route Target) carrying the VNI so receivers can
        //     install into the right L2VPN (auto-derived
        //     <local-AS>:<VNI>, two-octet ASN form for now).
        //   - Encapsulation extended community = VXLAN (8) so the
        //     receiver knows which data plane to use.
        // Nexthop = local VTEP source IP (RFC 8365 §5.1.3 — the
        // egress PE for VXLAN is the VTEP). RIB resolved this from
        // the VXLAN slave's `IFLA_VXLAN_LOCAL` / `LOCAL6` and stuck
        // it on the FdbEntry. Falling back to router-id keeps an
        // older configuration where the VXLAN was created without
        // an explicit `local` from emitting a 0.0.0.0 nexthop, but
        // operators with an actual VTEP IP set will get the right
        // family in the wire encoding (v4 → 4-byte nexthop, v6 →
        // 16-byte nexthop). Per-peer NEXT_HOP rewrite for eBGP
        // still happens inside `route_update_evpn`.
        let mut attr = BgpAttr::new();
        attr.ecom = Some(ExtCommunity(vec![
            evpn_route_target(self.asn, entry.vni),
            evpn_encap_vxlan(),
        ]));
        let nexthop = entry.vxlan_local.unwrap_or(IpAddr::V4(self.router_id));
        if entry.vxlan_local.is_none() {
            tracing::warn!(
                "evpn_originate_macip: VXLAN for VNI {} has no local IP; \
                 falling back to router-id {} as nexthop",
                entry.vni,
                self.router_id,
            );
        }
        attr.nexthop = Some(BgpNexthop::Evpn(nexthop));

        let mut rib = BgpRib::new(
            ORIGINATED_PEER,
            Ipv4Addr::UNSPECIFIED,
            BgpRibType::Originated,
            0, // remote_id — fixed at 0 for locally-originated; the
            // withdraw path matches against the same value.
            32768,
            &attr,
            None,
            None,
            false,
        );
        let (_replaced, selected, next_id) =
            self.local_rib.update_evpn(rd, prefix.clone(), rib.clone());
        rib.local_id = next_id;

        let mut bgp_ref = BgpTop {
            router_id: &self.router_id,
            local_rib: &mut self.local_rib,
            tx: &self.tx,
            rib_tx: &self.rib_tx,
            attr_store: &mut self.attr_store,
        };

        if !selected.is_empty() {
            route_advertise_evpn_to_peers(rd, prefix, &selected, &mut bgp_ref, &mut self.peers);
        }
    }

    /// Inverse of `evpn_originate_macip`. No-op when
    /// `advertise_all_vni` is false (we never originated anything to
    /// withdraw) or when the entry's VNI exceeds the Type-1 RD
    /// encoding range.
    pub fn evpn_withdraw_macip(&mut self, entry: &FdbEntry) {
        if !self.advertise_all_vni {
            return;
        }
        let Some(rd) = rd_from_router_id_vni(self.router_id, entry.vni) else {
            return;
        };
        let prefix = EvpnPrefix::MacIp {
            eth_tag: 0,
            mac: entry.mac.octets(),
            ip: None,
        };
        let _ = self.local_rib.remove_evpn(rd, &prefix, 0, ORIGINATED_PEER);
        // `remove_evpn` only edits `cands`; the per-prefix `selected`
        // map (the one `show ip bgp l2vpn evpn` iterates) is updated
        // by `select_best_path_evpn`, which evicts the entry when no
        // candidate remains. Without this call the withdrawn route
        // stays visible in `show` and orphan RDs accumulate after
        // every router-id change. Don't route the result through
        // `route_evpn_export_selected` — that path triggers kernel
        // FDB del via `MacDel`, which is appropriate for received
        // EVPN routes but wrong for locally-originated ones (the
        // kernel row is the operator's local MAC, not something we
        // installed via mac_add).
        let _ = self.local_rib.select_best_path_evpn(&rd, &prefix);
        // Tell every EVPN peer the route is gone. No best-path
        // re-evaluation here — for a locally-originated route there
        // is no other path that would replace it; the peers can
        // figure it out when they see the MP_UNREACH.
        route_withdraw_evpn_to_peers(rd, prefix, &mut self.peers);
    }

    /// Originate a Type-3 (Inclusive Multicast Ethernet Tag) route
    /// for one local VTEP×VNI pair (RFC 7432 §4.3, §11.3 + RFC 8365
    /// §5.1.3). One IMET per VNI tells remote PEs "send your BUM
    /// traffic for this VNI to me, encapsulated with VXLAN at this
    /// IP". Receivers install a zero-MAC FDB row whose `dst` = the
    /// nexthop, used for ingress-replication of broadcast / unknown
    /// unicast / multicast.
    ///
    /// Required attributes:
    ///   - RT (Two-Octet AS Specific) carrying VNI in low 3 bytes
    ///     of Local Admin (same as Type-2).
    ///   - Encapsulation extended community = VXLAN (8) per RFC 9012.
    ///   - PMSI Tunnel attribute (RFC 6514 §5) — Tunnel Type 6
    ///     (Ingress Replication), Label = VNI, Tunnel Identifier =
    ///     local VTEP IP. Without it, peers won't know which tunnel
    ///     mechanism to use and will reject the route.
    ///   - Nexthop = local VTEP IP. Same as Type-2 origination.
    ///
    /// Same gates as `evpn_originate_macip`: `advertise_all_vni` on
    /// AND a valid router-id. RD = `<router-id>:<VNI>`.
    pub fn evpn_originate_imet(&mut self, vni: u32, vtep_local: IpAddr) {
        if !self.advertise_all_vni {
            return;
        }
        if self.router_id.is_unspecified() {
            return;
        }
        let Some(rd) = rd_from_router_id_vni(self.router_id, vni) else {
            tracing::warn!(
                "evpn_originate_imet: VNI {} > 65535, RD encoding not yet supported",
                vni
            );
            return;
        };
        let prefix = EvpnPrefix::InclusiveMulticast {
            eth_tag: 0,
            orig: vtep_local,
        };
        let mut attr = BgpAttr::new();
        attr.ecom = Some(ExtCommunity(vec![
            evpn_route_target(self.asn, vni),
            evpn_encap_vxlan(),
        ]));
        attr.pmsi_tunnel = Some(PmsiTunnel {
            // Flags = 0 (no leaf info required, per RFC 6514 §5).
            flags: 0,
            // Tunnel Type 6 = Ingress Replication.
            tunnel_type: 6,
            vni,
            endpoint: vtep_local,
        });
        attr.nexthop = Some(BgpNexthop::Evpn(vtep_local));

        let mut rib = BgpRib::new(
            ORIGINATED_PEER,
            Ipv4Addr::UNSPECIFIED,
            BgpRibType::Originated,
            0,
            32768,
            &attr,
            None,
            None,
            false,
        );
        let (_replaced, selected, next_id) =
            self.local_rib.update_evpn(rd, prefix.clone(), rib.clone());
        rib.local_id = next_id;

        let mut bgp_ref = BgpTop {
            router_id: &self.router_id,
            local_rib: &mut self.local_rib,
            tx: &self.tx,
            rib_tx: &self.rib_tx,
            attr_store: &mut self.attr_store,
        };

        if !selected.is_empty() {
            route_advertise_evpn_to_peers(rd, prefix, &selected, &mut bgp_ref, &mut self.peers);
        }
    }

    /// Inverse of `evpn_originate_imet`. Mirrors `evpn_withdraw_macip`:
    /// remove from candidate set, evict the per-prefix `selected`
    /// entry via `select_best_path_evpn`, fan out MP_UNREACH to peers.
    pub fn evpn_withdraw_imet(&mut self, vni: u32, vtep_local: IpAddr) {
        if !self.advertise_all_vni {
            return;
        }
        let Some(rd) = rd_from_router_id_vni(self.router_id, vni) else {
            return;
        };
        let prefix = EvpnPrefix::InclusiveMulticast {
            eth_tag: 0,
            orig: vtep_local,
        };
        let _ = self.local_rib.remove_evpn(rd, &prefix, 0, ORIGINATED_PEER);
        let _ = self.local_rib.select_best_path_evpn(&rd, &prefix);
        route_withdraw_evpn_to_peers(rd, prefix, &mut self.peers);
    }
}

/// `NTF_EXT_LEARNED` from `<linux/neighbour.h>` — bit 0x10. Set on
/// FDB entries learned from external sources (e.g. another EVPN
/// speaker that installed via netlink). Must be filtered out of
/// origination to avoid advertise loops.
const NTF_EXT_LEARNED: u8 = 0x10;

/// Build a Type-1 RD (4-byte IPv4 + 2-byte assigned number) from
/// the local router-id and VNI per RFC 8365 §5.1.2. Returns None
/// when the VNI exceeds 16 bits — Type-1 only has 2 bytes for the
/// assigned-number field; supporting VNIs above 65535 needs the
/// Type-0 (ASN) format and is a follow-up.
fn rd_from_router_id_vni(router_id: Ipv4Addr, vni: u32) -> Option<RouteDistinguisher> {
    let vni_short: u16 = vni.try_into().ok()?;
    let mut rd = RouteDistinguisher::new(RouteDistinguisherType::IP);
    rd.val[0..4].copy_from_slice(&router_id.octets());
    rd.val[4..6].copy_from_slice(&vni_short.to_be_bytes());
    Some(rd)
}

/// Build the auto-derived Route Target extended community for an EVPN
/// route per RFC 8365 §5.1.2.4: type 0x00 / sub 0x02 (Two-Octet AS
/// Specific Route Target) carrying `<local-AS>:<VNI>`. The 2-byte
/// ASN sits in the first two octets; the VNI fills the remaining
/// four (24-bit VNI naturally encoded big-endian into the low 3 of
/// 4 bytes; 32-bit values would clobber the high byte but VNIs are
/// 24-bit per RFC 7348).
fn evpn_route_target(asn: u32, vni: u32) -> ExtCommunityValue {
    let mut rt = ExtCommunityValue {
        high_type: 0x00,
        low_type: 0x02,
        val: [0; 6],
    };
    let asn16 = asn as u16;
    rt.val[0..2].copy_from_slice(&asn16.to_be_bytes());
    rt.val[2..6].copy_from_slice(&vni.to_be_bytes());
    rt
}

/// Build the Tunnel Encapsulation extended community for VXLAN per
/// RFC 9012 §6.1: type 0x03 (Transitive Opaque) / sub 0x0c
/// (Encapsulation), value = encapsulation type 8 (VXLAN) in the low
/// two octets. Without this community a Type-2 receiver that
/// understands EVPN but supports multiple data planes can't tell
/// which encap to install, so RFC 8365 §5.1.2.4 makes it mandatory.
fn evpn_encap_vxlan() -> ExtCommunityValue {
    let mut encap = ExtCommunityValue {
        high_type: 0x03,
        low_type: 0x0c,
        val: [0; 6],
    };
    // Encapsulation type 8 = VXLAN, occupies the trailing 2 octets.
    encap.val[5] = 8;
    encap
}
