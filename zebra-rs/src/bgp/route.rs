use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use bgp_packet::*;
use bytes::BytesMut;
use ipnet::{Ipv4Net, Ipv6Net};
use prefix_trie::{Prefix, PrefixMap};

use crate::bgp::timer::{start_adv_timer_evpn, start_stale_timer};
use crate::policy::{AsPathPrependConfig, CommunityMatcher, PolicyList, StandardMatcher};
use crate::rib::route::DEBUG_EVPN;
use crate::rib::{self, MacAddr, api::FdbEntry};

use super::cap::CapAfiMap;
use super::peer::{BgpTop, Event, Peer, PeerType};
use super::peer_map::PeerMap;
use super::timer::start_adv_timer_vpnv4;
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

/// Build a `rib::entry::RibEntry` from the BGP best-path winner for an
/// IPv4 unicast prefix. Returns `None` when the BGP route has no
/// installable next-hop — VPNv4 / EVPN have their own install paths,
/// and a 0.0.0.0 next-hop (originated routes that never got a self
/// next-hop rewrite) shouldn't reach the kernel FIB.
///
/// When the route was received via RFC 8950 ENHE (MP_REACH with an
/// IPv6 next-hop for an IPv4 prefix), the kernel install uses
/// `Nexthop::Link(ifindex)` — the route is on-link via the
/// already-discovered IPv6 onlink on that interface, and the v4
/// NEXT_HOP attribute (which RFC 8950 §4 says the receiver MUST
/// ignore) is irrelevant.
fn make_bgp_rib_entry_v4(best: &BgpRib) -> Option<rib::entry::RibEntry> {
    // Administrative distance per Cisco / FRR convention. eBGP=20,
    // iBGP=200; originated paths take the iBGP value since they're
    // local-precedence work and we don't currently expose a knob.
    let distance = match best.typ {
        BgpRibType::EBGP => 20,
        BgpRibType::IBGP | BgpRibType::Originated => 200,
    };
    let metric = best.attr.med.as_ref().map(|m| m.med).unwrap_or(0);

    let nexthop = if let Some(ifindex) = best.egress_ifindex_v6 {
        rib::Nexthop::Link(ifindex)
    } else {
        let nh = match best.attr.nexthop.as_ref()? {
            BgpNexthop::Ipv4(addr) => *addr,
            // VPNv4 / EVPN nexthops are handled by their own per-AFI
            // install paths; the plain v4 Loc-RIB shouldn't be carrying
            // them but be defensive.
            _ => return None,
        };
        if nh.is_unspecified() {
            return None;
        }
        rib::Nexthop::Uni(rib::NexthopUni {
            addr: IpAddr::V4(nh),
            metric,
            weight: 1,
            valid: true,
            ..Default::default()
        })
    };

    let mut entry = rib::entry::RibEntry::new(rib::RibType::Bgp);
    entry.distance = distance;
    entry.metric = metric;
    entry.valid = true;
    entry.nexthop = nexthop;
    Some(entry)
}

/// Reconcile the kernel FIB state for `prefix` with the BGP best-path
/// outcome. `selected` is the `select_best_path` return: at most one
/// `BgpRib` after best-path selection. Empty means every candidate
/// just disappeared — emit a withdraw.
///
/// VPNv4 / EVPN take their own install paths; this helper is for
/// plain IPv4 unicast only.
fn fib_install_v4(bgp: &super::peer::BgpTop, prefix: Ipv4Net, selected: &[BgpRib]) {
    let installable = selected.first().and_then(make_bgp_rib_entry_v4);
    match installable {
        Some(mut rib_entry) => {
            // Colour-aware Flex-Algo label push. When the route
            // carries a Color extcomm bound to a configured IS-IS
            // Flex-Algorithm, append the per-algo outer MPLS label
            // IS-IS published via RIB.
            if let Some(best) = selected.first()
                && let Some(BgpNexthop::Ipv4(nh)) = best.attr.nexthop.as_ref()
                && let Some(label) = resolve_flex_algo_label(bgp, &best.attr, *nh)
                && let rib::Nexthop::Uni(ref mut uni) = rib_entry.nexthop
            {
                uni.mpls.push(rib::Label::Explicit(label));
            }
            let _ = bgp.rib_client.send(rib::Message::Ipv4Add {
                prefix,
                rib: rib_entry,
            });
        }
        None => {
            // Either selected is empty or the best path lacks a
            // usable v4 next-hop. Either way, the prefix should not
            // be in the FIB. The RIB layer ignores a Del for an
            // entry it never installed, so this is safe to fire
            // unconditionally.
            let mut stub = rib::entry::RibEntry::new(rib::RibType::Bgp);
            stub.valid = false;
            let _ = bgp
                .rib_client
                .send(rib::Message::Ipv4Del { prefix, rib: stub });
        }
    }
}

/// IPv6 counterpart of [`make_bgp_rib_entry_v4`]. Reads the IPv6
/// next-hop from `attr.nexthop` (`BgpNexthop::Ipv6`); there's no
/// RFC 8950 ENHE case for native v6 unicast. Returns `None` when the
/// best path lacks a usable v6 next-hop.
fn make_bgp_rib_entry_v6(best: &BgpRib) -> Option<rib::entry::RibEntry> {
    let distance = match best.typ {
        BgpRibType::EBGP => 20,
        BgpRibType::IBGP | BgpRibType::Originated => 200,
    };
    let metric = best.attr.med.as_ref().map(|m| m.med).unwrap_or(0);

    let nh = match best.attr.nexthop.as_ref()? {
        BgpNexthop::Ipv6(addr) => *addr,
        // VPNv6 / VPNv4 / EVPN nexthops install via their own paths;
        // the plain v6 Loc-RIB shouldn't carry them.
        _ => return None,
    };
    if nh.is_unspecified() {
        return None;
    }
    let nexthop = rib::Nexthop::Uni(rib::NexthopUni {
        addr: IpAddr::V6(nh),
        metric,
        weight: 1,
        valid: true,
        ..Default::default()
    });

    let mut entry = rib::entry::RibEntry::new(rib::RibType::Bgp);
    entry.distance = distance;
    entry.metric = metric;
    entry.valid = true;
    entry.nexthop = nexthop;
    Some(entry)
}

/// IPv6 counterpart of [`fib_install_v4`]: reconcile the kernel FIB
/// for an IPv6 unicast prefix against the best-path outcome. Plain v6
/// unicast only — VPNv6 will take its own install path (layer 2c+).
fn fib_install_v6(bgp: &super::peer::BgpTop, prefix: Ipv6Net, selected: &[BgpRib]) {
    match selected.first().and_then(make_bgp_rib_entry_v6) {
        Some(rib_entry) => {
            let _ = bgp.rib_client.send(rib::Message::Ipv6Add {
                prefix,
                rib: rib_entry,
            });
        }
        None => {
            let mut stub = rib::entry::RibEntry::new(rib::RibType::Bgp);
            stub.valid = false;
            let _ = bgp
                .rib_client
                .send(rib::Message::Ipv6Del { prefix, rib: stub });
        }
    }
}

/// Walk the route's Color extcomms in order, look each up in
/// `color_policy`, LPM the next-hop against the matching per-algo
/// shadow, return the first hit's outer label.
fn resolve_flex_algo_label(bgp: &super::peer::BgpTop, attr: &BgpAttr, nh: Ipv4Addr) -> Option<u32> {
    resolve_flex_algo_label_inner(bgp.color_policy?, bgp.flex_algo_routes?, attr, nh)
}

/// Pure-function inner for `resolve_flex_algo_label` — testable
/// without a full `BgpTop`. Same algorithm: walk the Color extcomms
/// in attribute order, return the first one bound to an algo whose
/// per-algo shadow has a covering route for `nh`.
fn resolve_flex_algo_label_inner(
    color_policy: &super::color_policy::ColorPolicy,
    flex_algo_routes: &std::collections::BTreeMap<
        u8,
        prefix_trie::PrefixMap<Ipv4Net, crate::rib::api::FlexAlgoNexthop>,
    >,
    attr: &BgpAttr,
    nh: Ipv4Addr,
) -> Option<u32> {
    let host = Ipv4Net::new(nh, 32).ok()?;
    for color in attr.colors() {
        let Some(algo) = color_policy.flex_algo_for(color.color) else {
            // Color unbound — try the next one rather than bailing,
            // so a route with both an "unbound colour" and a "bound
            // colour" still resolves on the bound one.
            continue;
        };
        if let Some(table) = flex_algo_routes.get(&algo)
            && let Some((_, entry)) = table.get_lpm(&host)
        {
            return Some(entry.label);
        }
    }
    None
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
    /// RFC 8950 IPv4-over-IPv6: when the route was received via
    /// MP_REACH(AFI=1) with an IPv6 next-hop, this is the local egress
    /// ifindex (the interface where we received the UPDATE). FIB
    /// install reads this and uses `Nexthop::Link(ifindex)` instead of
    /// the v4 NEXT_HOP attribute, which RFC 8950 §4 says the receiver
    /// MUST ignore for these routes. `None` for normal v4 routes.
    pub egress_ifindex_v6: Option<u32>,
    // Stale.
    pub stale: bool,
    // EVPN ESI (Ethernet Segment Identifier) for multi-homing.
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
            egress_ifindex_v6: None,
            stale,
            esi: None,
        }
    }

    pub fn is_originated(&self) -> bool {
        self.typ.is_originated()
    }
}

/// AFI-generic Loc-RIB table: candidate paths and the selected
/// best path per prefix, both keyed by the prefix type `P`
/// (`Ipv4Net` today; `Ipv6Net` once the v6 ingest path lands). The
/// best-path machinery below is NLRI-agnostic — it compares only
/// `BgpRib` fields — so the same engine serves every unicast AFI.
///
/// `Debug`/`Default` are hand-written rather than derived: `PrefixMap`
/// derives neither for an arbitrary `P` (its `Debug` needs
/// `P: Prefix + Debug`, and `derive` would instead demand the wrong
/// `P: Debug`/`P: Default` bounds on `LocalRibTable`).
pub struct LocalRibTable<P>(
    pub PrefixMap<P, Vec<BgpRib>>, // Cands.
    pub PrefixMap<P, BgpRib>,      // Selected.
);

impl<P> Default for LocalRibTable<P> {
    fn default() -> Self {
        LocalRibTable(PrefixMap::default(), PrefixMap::default())
    }
}

impl<P: Prefix> std::fmt::Debug for LocalRibTable<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("LocalRibTable")
            .field(&self.0)
            .field(&self.1)
            .finish()
    }
}

impl<P: Prefix + Copy> LocalRibTable<P> {
    pub fn update(&mut self, prefix: P, rib: BgpRib) -> (Vec<BgpRib>, Vec<BgpRib>, u32) {
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

    pub fn remove(&mut self, prefix: P, id: u32, ident: usize) -> Vec<BgpRib> {
        let cands = self.0.entry(prefix).or_default();
        let removed: Vec<BgpRib> = cands
            .extract_if(.., |r| r.ident == ident && r.remote_id == id)
            .collect();
        removed
    }

    // Return selected best path, not the change history.
    pub fn select_best_path(&mut self, prefix: P) -> Vec<BgpRib> {
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
                // Reuse the best-path comparator — it operates only on
                // BgpRib fields and is NLRI-agnostic. The type parameter
                // is irrelevant (the fn ignores it); name a concrete one.
                let (better, reason) =
                    LocalRibTable::<Ipv4Net>::is_better(&cands[index], &cands[best_index]);
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
    pub v4: LocalRibTable<Ipv4Net>,

    pub v6: LocalRibTable<Ipv6Net>,

    pub v4vpn: BTreeMap<RouteDistinguisher, LocalRibTable<Ipv4Net>>,

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

    // IPv6 unicast accessors. VPNv6 (`v6vpn`) lands with layer 2c, so
    // these take no RD — the global/default v6 unicast Loc-RIB only.
    pub fn update_v6(&mut self, prefix: Ipv6Net, rib: BgpRib) -> (Vec<BgpRib>, Vec<BgpRib>, u32) {
        self.v6.update(prefix, rib)
    }

    pub fn remove_v6(&mut self, prefix: Ipv6Net, id: u32, ident: usize) -> Vec<BgpRib> {
        self.v6.remove(prefix, id, ident)
    }

    pub fn select_best_path_v6(&mut self, prefix: Ipv6Net) -> Vec<BgpRib> {
        self.v6.select_best_path(prefix)
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
    weight: u32,
) -> Option<PolicyDecision> {
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
        return policy_list_apply(policy_list, nlri, bgp_attr, weight, peer.router_id);
    }
    Some(PolicyDecision {
        attr: bgp_attr,
        weight,
    })
}

/// Inbound policy entry point for an EVPN route. Mirrors
/// `route_apply_policy_in` but skips the per-direction prefix-set
/// (no IPv4 prefix on EVPN NLRIs) and dispatches to
/// `policy_list_apply_evpn`. When no input policy-list is bound
/// to the peer the route passes through unmodified.
pub fn route_apply_policy_in_evpn(
    peer: &mut Peer,
    route: &EvpnRoute,
    bgp_attr: BgpAttr,
    weight: u32,
) -> Option<PolicyDecision> {
    let config = peer.policy_list.get(&InOut::Input);
    if config.name.is_some() {
        let Some(policy_list) = &config.policy_list else {
            return None;
        };
        return policy_list_apply_evpn(policy_list, route, bgp_attr, weight, peer.router_id);
    }
    Some(PolicyDecision {
        attr: bgp_attr,
        weight,
    })
}

/// Outbound policy entry point for an EVPN route. Mirrors
/// `route_apply_policy_out` but skips the per-direction prefix-set
/// (no IPv4 prefix on EVPN NLRIs) and dispatches to
/// `policy_list_apply_evpn`. Default-permit when no output
/// policy-list is bound, same as the IPv4 outbound path.
pub fn route_apply_policy_out_evpn(
    peer: &mut Peer,
    route: &EvpnRoute,
    bgp_attr: BgpAttr,
    weight: u32,
) -> Option<PolicyDecision> {
    let config = peer.policy_list.get(&InOut::Output);
    if config.name.is_some() {
        let Some(policy_list) = &config.policy_list else {
            return None;
        };
        return policy_list_apply_evpn(policy_list, route, bgp_attr, weight, peer.router_id);
    }
    Some(PolicyDecision {
        attr: bgp_attr,
        weight,
    })
}

pub fn route_apply_policy_out(
    peer: &mut Peer,
    nlri: &Ipv4Nlri,
    bgp_attr: BgpAttr,
    weight: u32,
) -> Option<PolicyDecision> {
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
        // For `set next-hop self` on an outbound advertisement,
        // the local-router-id of the session is the natural
        // "self" anchor. We pass `peer.router_id` here for
        // both directions; outbound is the typical use case.
        return policy_list_apply(policy_list, nlri, bgp_attr, weight, peer.router_id);
    } else {
        // Temporary comment out.
        // return None;
    }
    Some(PolicyDecision {
        attr: bgp_attr,
        weight,
    })
}

pub fn route_ipv4_update(
    ident: usize,
    nlri: &Ipv4Nlri,
    rd: Option<RouteDistinguisher>,
    label: Option<Label>,
    attr: &BgpAttr,
    nexthop: Option<Vpnv4Nexthop>,
    egress_ifindex_v6: Option<u32>,
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
    rib.egress_ifindex_v6 = egress_ifindex_v6;

    // Register to peer's AdjRibIn and update stats
    let decision = {
        let peer = peers.get_mut_by_idx(ident).expect("peer must exist");
        peer.adj_in.add(rd, nlri.prefix, rib.clone());

        // Apply policy. Carry the rib's current weight (0 here,
        // since this is the first time the route enters the local
        // RIB) so any `set weight NUM` clause in the in-policy can
        // override it.
        route_apply_policy_in(peer, nlri, attr.clone(), rib.weight)
    };

    // Perform BGP Path selection.
    let Some(decision) = decision else {
        route_ipv4_withdraw(ident, nlri, rd, None, bgp, peers, false);
        return;
    };
    rib.attr = bgp.attr_store.intern(decision.attr);
    rib.weight = decision.weight;
    let (_, selected, next_id) = bgp.local_rib.update(rd, nlri.prefix, rib.clone());

    // Per-VRF best-path → global VPNv4 export. The hook only
    // fires for IPv4 unicast (rd==None) inside a VRF task
    // (`vrf_export` is Some). Empty `selected` after an update
    // means the new candidate didn't survive best-path and there
    // are no remaining winners — translate to a WithdrawExport so
    // the global instance drops the row.
    if rd.is_none()
        && let Some(exporter) = bgp.vrf_export
    {
        if let Some(winner) = selected.first() {
            super::vrf::vrf_emit_export(exporter, nlri.prefix, &winner.attr);
        } else {
            super::vrf::vrf_emit_withdraw(exporter, nlri.prefix);
        }
    }

    // Global v4vpn best-path → per-VRF import. Inverse of the
    // export hook above: when an incoming VPNv4 route becomes the
    // global best-path winner, fan out to every VRF whose
    // `import_rts_v4` intersects the route's RT extcomms.
    // `vrf_import` is `Some(...)` only in the global Bgp task;
    // per-VRF runtimes never receive VPNv4 NLRI directly.
    if let Some(rd) = rd
        && let Some(dispatcher) = bgp.vrf_import
    {
        if let Some(winner) = selected.first() {
            super::vrf::dispatch_import_v4(dispatcher, rd, nlri.prefix, &winner.attr, 0, None);
        } else {
            // best-path stripped the candidate; flood withdraw
            // using the *new* attr (the one just rejected) so
            // the matching-VRF set still resolves the same way.
            super::vrf::dispatch_withdraw_import_v4(dispatcher, rd, nlri.prefix, &rib.attr, None);
        }
    }

    // Plain IPv4 unicast best-path winners are installed to the kernel
    // FIB via RIB. VPNv4 lives in `local_rib.v4vpn` and has its own
    // (still-deferred) install path, so gate on rd==None.
    if rd.is_none() {
        fib_install_v4(bgp, nlri.prefix, &selected);
    }

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
    let afi_safi = AfiSafi::new(afi, safi);

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
            && let Some(decision) = route_apply_policy_out(peer, &nlri, attr, rib.weight)
        {
            let attr = decision.attr;
            // RTC match.
            if let Some(_rd) = rd
                && !peer.rtcv4.is_empty()
                && !rtc_match(&peer.rtcv4, &attr.ecom)
            {
                continue;
            }
            let attr = bgp.attr_store.intern(attr);
            let mut rib_clone = rib.clone();
            rib_clone.attr = attr.clone();

            peer.adj_out.add(rd, nlri.prefix, rib_clone);
            if let Some(ref rd) = rd {
                let vpnv4_nlri = Vpnv4Nlri {
                    label: Label::default(),
                    rd: *rd,
                    nlri,
                };
                peer.send_vpnv4(vpnv4_nlri, attr, true);
            } else {
                // IPv4 unicast addpath: bucket into the group cache.
                // All addpath-enabled peers share the same
                // `addpath_send: true` signature, so the group
                // contains only addpath peers — fan-out at flush
                // time goes only to other addpath peers.
                let group_id = peer.update_group_id.get(&afi_safi).cloned();
                if let Some(gid) = group_id
                    && let Some(af) = bgp.update_groups.get_mut(&afi_safi)
                    && let Some(group) = af.group_by_id_mut(&gid)
                {
                    super::update_group::send_ipv4(group, nlri, attr, rib.ident, bgp.tx, true);
                } else {
                    tracing::warn!(
                        peer = %peer.address,
                        prefix = %prefix,
                        "IPv4 addpath advertise: peer Established but not in any update-group; advertise skipped"
                    );
                }
            }
        }
    }
}

fn route_withdraw_from_addpath(
    rd: Option<RouteDistinguisher>,
    prefix: Ipv4Net,
    removed: &BgpRib,
    _source_peer: usize,
    bgp: &mut BgpTop,
    peers: &mut PeerMap,
) {
    let (afi, safi) = if rd.is_some() {
        (Afi::Ip, Safi::MplsVpn)
    } else {
        (Afi::Ip, Safi::Unicast)
    };
    let afi_safi = AfiSafi::new(afi, safi);

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
            // Group cache cleanup. Idempotent across the peer
            // iteration: first peer in the group cleans the bucket;
            // subsequent peers find it gone.
            let group_id = peer.update_group_id.get(&afi_safi).cloned();
            if let Some(gid) = group_id
                && let Some(af) = bgp.update_groups.get_mut(&afi_safi)
                && let Some(group) = af.group_by_id_mut(&gid)
            {
                super::update_group::cache_remove_ipv4(group, prefix, removed.local_id);
            }
        }
        route_withdraw_ipv4(peer, rd, prefix, removed.local_id);
        peer.adj_out.remove(rd, prefix, removed.local_id);
    }
}

/// Advertise route changes to all appropriate peers
/// Outcome of running the canonical-member transform + outbound
/// policy for a route. Identical for every member of an
/// `update-group` for a given (route, AFI/SAFI), modulo per-peer
/// split-horizon (handled before cache lookup) and per-peer RTC
/// (applied after).
#[derive(Clone)]
enum AdvertiseOutcome {
    Advertise(Ipv4Nlri, BgpAttr),
    Withdraw,
}

/// Run `route_update_ipv4` + `route_apply_policy_out` for `peer`.
/// Caller has already verified split-horizon does NOT fire for this
/// peer (`best.ident != peer.ident`); other filters inside
/// `route_update_ipv4` (notably the iBGP-iBGP rule) depend only on
/// signature fields, so the result is identical for every other
/// non-source member of the same update-group.
fn compute_advertise_outcome(
    peer: &mut Peer,
    prefix: &Ipv4Net,
    best: &BgpRib,
    bgp: &mut BgpTop,
    add_path: bool,
) -> AdvertiseOutcome {
    if let Some((nlri, attr)) = route_update_ipv4(peer, prefix, best, bgp, add_path) {
        if let Some(decision) = route_apply_policy_out(peer, &nlri, attr, best.weight) {
            AdvertiseOutcome::Advertise(nlri, decision.attr)
        } else {
            AdvertiseOutcome::Withdraw
        }
    } else {
        AdvertiseOutcome::Withdraw
    }
}

/// Bump per-group counters for one cache miss. `denied` is true when
/// the computed outcome was `Withdraw` because the outbound policy
/// returned None — distinguishes deny-by-policy from skip-by-no-best.
fn bump_group_counters_on_miss(
    bgp: &mut BgpTop,
    afi_safi: AfiSafi,
    id: &super::update_group::UpdateGroupId,
    denied: bool,
) {
    let Some(af) = bgp.update_groups.get_mut(&afi_safi) else {
        return;
    };
    let Some(group) = af.group_by_id_mut(id) else {
        return;
    };
    group.counters.policy_runs += 1;
    if denied {
        group.counters.policy_denials += 1;
    }
}

pub(super) fn route_advertise_to_peers(
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
    let afi_safi = AfiSafi::new(afi, safi);

    let peer_addrs: Vec<IpAddr> = peers
        .iter()
        .filter(|(_, p)| p.state.is_established())
        .filter(|(_, p)| p.is_afi_safi(afi, safi))
        .filter(|(_, p)| !p.opt.is_add_path_send(afi, safi))
        .map(|(addr, _)| *addr)
        .collect();

    // Per-call memo: outcome cached per update-group id for the
    // span of this advertisement only. Members of the same group
    // share the post-policy outcome (modulo split-horizon, which is
    // checked per-peer before lookup so the canonical computation
    // is always run on a non-source peer).
    let mut memo: BTreeMap<super::update_group::UpdateGroupId, AdvertiseOutcome> = BTreeMap::new();

    for peer_addr in peer_addrs {
        let peer = peers.get_mut(&peer_addr).expect("peer exists");

        let add_path = peer.opt.is_add_path_send(afi, safi);
        let group_id = peer.update_group_id.get(&afi_safi).cloned();

        let outcome = match new_best {
            None => AdvertiseOutcome::Withdraw,
            Some(best) if best.ident == peer.ident => {
                // Split-horizon: source peer does not receive its own
                // route back. Cache must not be poisoned by this
                // outcome — fall through directly.
                AdvertiseOutcome::Withdraw
            }
            Some(best) => match group_id.as_ref() {
                Some(gid) => {
                    if let Some(cached) = memo.get(gid) {
                        cached.clone()
                    } else {
                        let outcome = compute_advertise_outcome(peer, &prefix, best, bgp, add_path);
                        let denied = matches!(outcome, AdvertiseOutcome::Withdraw);
                        memo.insert(gid.clone(), outcome.clone());
                        bump_group_counters_on_miss(bgp, afi_safi, gid, denied);
                        outcome
                    }
                }
                None => compute_advertise_outcome(peer, &prefix, best, bgp, add_path),
            },
        };

        match outcome {
            AdvertiseOutcome::Advertise(nlri, attr) => {
                if rd.is_some() && !peer.rtcv4.is_empty() && !rtc_match(&peer.rtcv4, &attr.ecom) {
                    // RTC: per-peer; varies independently of group
                    // signature. Skip without withdrawing.
                    continue;
                }
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
                    // IPv4 unicast: bucket into the group's pending
                    // cache. Source ident comes from the selected
                    // best path so split-horizon pruning at flush
                    // time can drop NLRIs from their originator.
                    let source_ident = new_best.map(|b| b.ident).unwrap_or(peer.ident);
                    let group_id = peer.update_group_id.get(&afi_safi).cloned();
                    if let Some(gid) = group_id
                        && let Some(af) = bgp.update_groups.get_mut(&afi_safi)
                        && let Some(group) = af.group_by_id_mut(&gid)
                    {
                        super::update_group::send_ipv4(
                            group,
                            nlri,
                            attr,
                            source_ident,
                            bgp.tx,
                            true,
                        );
                    } else {
                        // Established peer with no IPv4 unicast
                        // group is a bug — `update_group::attach`
                        // is supposed to enroll every peer that
                        // reaches Established. Skip the advertise
                        // rather than silently dropping it on the
                        // floor or panicking.
                        tracing::warn!(
                            peer = %peer.address,
                            prefix = %prefix,
                            "IPv4 advertise: peer is Established but not in any update-group; advertise skipped"
                        );
                    }
                }
            }
            AdvertiseOutcome::Withdraw => {
                if let Some(ref rd) = rd {
                    peer.cache_remove_vpnv4(*rd, prefix, 0);
                } else {
                    // Group cache cleanup. Skipped for split-horizon
                    // Withdraws: the source peer never contributed
                    // an entry, but other group members may have.
                    // Removing here would clobber theirs.
                    let is_split_horizon = new_best.map(|b| b.ident == peer.ident).unwrap_or(false);
                    if !is_split_horizon
                        && let Some(gid) = peer.update_group_id.get(&afi_safi).cloned()
                        && let Some(af) = bgp.update_groups.get_mut(&afi_safi)
                        && let Some(group) = af.group_by_id_mut(&gid)
                    {
                        super::update_group::cache_remove_ipv4(group, prefix, 0);
                    }
                }
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
        // Drop the Adj-RIB-Out entry so soft-out's baseline reflects
        // reality — without this a follow-up policy change would
        // think the route is still advertised and emit a redundant
        // withdraw.
        peer.adj_out.remove_evpn(rd, &prefix, 0);
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

        let Some(decision) = route_apply_policy_out_evpn(peer, &route, attr, new_best.weight)
        else {
            continue;
        };

        let attr = bgp.attr_store.intern(decision.attr);
        // Record what we advertised so a later policy change can
        // diff the Adj-RIB-Out against the Loc-RIB and withdraw
        // anything that the new policy now denies.
        let mut adj = new_best.clone();
        adj.attr = attr.clone();
        peer.adj_out.add_evpn(rd, prefix.clone(), adj);
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

// Soft-reconfiguration outbound: walk Loc-RIB for the AFI/SAFIs the
// peer has negotiated, run each prefix through the per-peer advertise
// builder + outbound policy, and either re-send the UPDATE or withdraw
// (when a previously-advertised prefix newly fails policy or filtering).
// Caller is responsible for ensuring the peer is established.
//
// Covers IPv4 unicast, IPv4 MPLS-VPN, and EVPN. Soft-in (replay of
// stored Adj-RIB-In through the new inbound policy) remains a
// separate path — see `route_soft_in_peer`.
pub fn route_soft_out_peer(peer_idx: usize, bgp: &mut BgpTop, peers: &mut PeerMap) {
    let (do_v4, vpn_rds, evpn_rds) = {
        let Some(peer) = peers.get_by_idx(peer_idx) else {
            return;
        };
        if !peer.state.is_established() {
            return;
        }
        let do_v4 = peer.is_afi_safi(Afi::Ip, Safi::Unicast);
        let do_vpn = peer.is_afi_safi(Afi::Ip, Safi::MplsVpn);
        let do_evpn = peer.is_afi_safi(Afi::L2vpn, Safi::Evpn);
        let v4vpn_rds: Vec<RouteDistinguisher> = if do_vpn {
            bgp.local_rib.v4vpn.keys().copied().collect()
        } else {
            Vec::new()
        };
        // Union the Loc-RIB RD set with the peer's Adj-RIB-Out RD
        // set so a policy change that purges every Loc-RIB entry
        // under an RD still drives a withdraw for whatever the peer
        // currently has under that RD.
        let evpn_rds: Vec<RouteDistinguisher> = if do_evpn {
            let mut s: BTreeSet<RouteDistinguisher> = bgp.local_rib.evpn.keys().copied().collect();
            s.extend(peer.adj_out.evpn.keys().copied());
            s.into_iter().collect()
        } else {
            Vec::new()
        };
        (do_v4, v4vpn_rds, evpn_rds)
    };

    if do_v4 {
        route_soft_out_peer_table(peer_idx, None, bgp, peers);
    }
    for rd in vpn_rds {
        route_soft_out_peer_table(peer_idx, Some(rd), bgp, peers);
    }
    for rd in evpn_rds {
        route_soft_out_peer_table_evpn(peer_idx, rd, bgp, peers);
    }
}

fn route_soft_out_peer_table(
    peer_idx: usize,
    rd: Option<RouteDistinguisher>,
    bgp: &mut BgpTop,
    peers: &mut PeerMap,
) {
    let (afi, safi) = if rd.is_some() {
        (Afi::Ip, Safi::MplsVpn)
    } else {
        (Afi::Ip, Safi::Unicast)
    };

    // Snapshot Loc-RIB selected so the iteration outlives later
    // mutable borrows of `bgp` (attr_store.intern, send paths).
    let selected: Vec<(Ipv4Net, BgpRib)> = match rd {
        Some(rd) => bgp
            .local_rib
            .v4vpn
            .get(&rd)
            .map(|t| t.1.iter().map(|(p, r)| (p, r.clone())).collect())
            .unwrap_or_default(),
        None => bgp
            .local_rib
            .v4
            .1
            .iter()
            .map(|(p, r)| (p, r.clone()))
            .collect(),
    };

    // Snapshot what's currently in this peer's Adj-RIB-Out so we can
    // detect which previously-advertised prefixes need a withdraw.
    let was_advertised: BTreeSet<Ipv4Net> = {
        let peer = peers.get_mut_by_idx(peer_idx).expect("peer exists");
        match rd {
            Some(rd) => peer
                .adj_out
                .v4vpn
                .get(&rd)
                .map(|t| t.0.keys().copied().collect())
                .unwrap_or_default(),
            None => peer.adj_out.v4.0.keys().copied().collect(),
        }
    };

    let mut newly_advertised: BTreeSet<Ipv4Net> = BTreeSet::new();
    // Soft-out targets a single peer; the per-group cache would
    // fan out to every member. Accumulate IPv4 unicast entries
    // and emit via `send_ipv4_direct` at the end so encoding
    // stays per-attr-batched without touching the group cache.
    let mut ipv4_entries: Vec<(Arc<BgpAttr>, Ipv4Nlri)> = Vec::new();

    for (prefix, rib) in &selected {
        let peer = peers.get_mut_by_idx(peer_idx).expect("peer exists");
        let add_path = peer.opt.is_add_path_send(afi, safi);

        let Some((nlri, attr)) = route_update_ipv4(peer, prefix, rib, bgp, add_path) else {
            continue;
        };
        let Some(decision) = route_apply_policy_out(peer, &nlri, attr, rib.weight) else {
            continue;
        };
        let attr = decision.attr;
        if rd.is_some() && !peer.rtcv4.is_empty() && !rtc_match(&peer.rtcv4, &attr.ecom) {
            continue;
        }

        let attr = bgp.attr_store.intern(attr);
        let mut adj = rib.clone();
        adj.attr = attr.clone();
        peer.adj_out.add(rd, nlri.prefix, adj);

        if let Some(rd_val) = rd {
            let vpnv4_nlri = Vpnv4Nlri {
                label: Label::default(),
                rd: rd_val,
                nlri,
            };
            peer.send_vpnv4(vpnv4_nlri, attr, true);
        } else {
            ipv4_entries.push((attr, nlri));
        }

        newly_advertised.insert(*prefix);
    }

    // Direct-emit IPv4 unicast batch (no group fan-out). When the
    // peer negotiated RFC 8950 ENHE for IPv4 unicast, pass the
    // per-interface next-hop so the encoder emits MP_REACH instead
    // of the legacy inline-NLRI form. `compose_enhe_next_hop`
    // selects 32-octet dual when the egress interface also has a
    // global v6, else 16-octet link-local-only.
    if rd.is_none()
        && let Some(peer) = peers.get_by_idx(peer_idx)
    {
        let enhe_v6 = peer
            .is_enhe_v4_negotiated()
            .then(|| super::update_group::compose_enhe_next_hop(peer, bgp.interface_addrs))
            .flatten();
        super::update_group::send_ipv4_direct(peer, ipv4_entries, enhe_v6);
    }

    let to_withdraw: Vec<Ipv4Net> = was_advertised
        .difference(&newly_advertised)
        .copied()
        .collect();
    for prefix in to_withdraw {
        let peer = peers.get_mut_by_idx(peer_idx).expect("peer exists");
        if let Some(rd) = rd {
            peer.cache_remove_vpnv4(rd, prefix, 0);
        }
        // No IPv4 cache to remove from — direct-encode means there
        // was never a pending bucket to drop. adj_out + the on-wire
        // withdraw still happen.
        peer.adj_out.remove(rd, prefix, 0);
        route_withdraw_ipv4(peer, rd, prefix, 0);
    }
}

/// Soft-reconfiguration outbound for one EVPN Route Distinguisher.
/// Mirrors `route_soft_out_peer_table` for IPv4/VPN: walk the
/// per-RD Loc-RIB EVPN table through `route_update_evpn` +
/// `route_apply_policy_out_evpn`, re-emit anything the (possibly
/// new) policy still permits, and withdraw entries that the peer
/// previously had in its Adj-RIB-Out but that now fall out.
///
/// Without this path, a `match evpn …` policy change only affects
/// *new* routes — previously-advertised routes remain in the peer's
/// table until the peer drops the session or the originating
/// speaker withdraws the route. Operator-triggered soft-out (or a
/// peer-initiated Route Refresh) flows through here.
fn route_soft_out_peer_table_evpn(
    peer_idx: usize,
    rd: RouteDistinguisher,
    bgp: &mut BgpTop,
    peers: &mut PeerMap,
) {
    // Snapshot Loc-RIB selected EVPN routes for this RD so iteration
    // outlives later mutable borrows of `bgp` (attr_store.intern,
    // send paths).
    let selected: Vec<(EvpnPrefix, BgpRib)> = bgp
        .local_rib
        .evpn
        .get(&rd)
        .map(|t| {
            t.selected
                .iter()
                .map(|(p, r)| (p.clone(), r.clone()))
                .collect()
        })
        .unwrap_or_default();

    // What's currently in this peer's Adj-RIB-Out for the RD —
    // anything in here but missing from the post-policy newly-
    // advertised set needs a withdraw.
    let was_advertised: BTreeSet<EvpnPrefix> = {
        let peer = peers.get_mut_by_idx(peer_idx).expect("peer exists");
        peer.adj_out
            .evpn
            .get(&rd)
            .map(|t| t.0.keys().cloned().collect())
            .unwrap_or_default()
    };

    let mut newly_advertised: BTreeSet<EvpnPrefix> = BTreeSet::new();

    for (prefix, rib) in &selected {
        let peer = peers.get_mut_by_idx(peer_idx).expect("peer exists");
        let add_path = peer.opt.is_add_path_send(Afi::L2vpn, Safi::Evpn);

        let Some((route, attr)) = route_update_evpn(peer, &rd, prefix, rib, bgp, add_path) else {
            continue;
        };
        let Some(decision) = route_apply_policy_out_evpn(peer, &route, attr, rib.weight) else {
            continue;
        };
        let attr = bgp.attr_store.intern(decision.attr);
        let mut adj = rib.clone();
        adj.attr = attr.clone();
        peer.adj_out.add_evpn(rd, prefix.clone(), adj);
        peer.send_evpn(route, attr, true);
        newly_advertised.insert(prefix.clone());
    }

    let to_withdraw: Vec<EvpnPrefix> = was_advertised
        .difference(&newly_advertised)
        .cloned()
        .collect();
    for prefix in to_withdraw {
        let peer = peers.get_mut_by_idx(peer_idx).expect("peer exists");
        let route = evpn_route_from_prefix(&rd, &prefix, 0);
        // Drop any queued advertise so flush_evpn doesn't ship a
        // stale add after the withdraw; mirrors the same cache
        // drain in route_withdraw_evpn_to_peers.
        if let Some(attr) = peer.cache_evpn_rev.remove(&route)
            && let Some(set) = peer.cache_evpn.get_mut(&attr)
        {
            set.remove(&route);
            if set.is_empty() {
                peer.cache_evpn.remove(&attr);
            }
        }
        peer.adj_out.remove_evpn(rd, &prefix, 0);
        route_withdraw_evpn(peer, route);
    }
}

// Soft-reconfiguration inbound (stored mode): replay the peer's
// pre-policy Adj-RIB-In through the current inbound policy and
// reconcile Loc-RIB. The caller must have already verified
// `peer.config.soft_reconfig_in` and that the peer is established.
//
// For each stored entry: re-apply inbound policy. If accepted, refresh
// the Loc-RIB candidate with the (possibly new) post-policy attrs and
// fan out best-path changes via the normal advertise paths. If denied,
// withdraw from Loc-RIB only — the Adj-RIB-In entry stays so the next
// replay (e.g., after another policy edit) still has it.
//
// Covers IPv4 unicast and IPv4 MPLS-VPN. EVPN soft-in is left
// for a follow-up, mirroring the EVPN soft-out gap.
pub fn route_soft_in_peer(peer_idx: usize, bgp: &mut BgpTop, peers: &mut PeerMap) {
    let (do_v4, vpn_rds) = {
        let Some(peer) = peers.get_by_idx(peer_idx) else {
            return;
        };
        if !peer.state.is_established() {
            return;
        }
        let do_v4 = peer.is_afi_safi(Afi::Ip, Safi::Unicast);
        let do_vpn = peer.is_afi_safi(Afi::Ip, Safi::MplsVpn);
        let rds: Vec<RouteDistinguisher> = if do_vpn {
            peer.adj_in.v4vpn.keys().copied().collect()
        } else {
            Vec::new()
        };
        (do_v4, rds)
    };

    if do_v4 {
        route_soft_in_peer_table(peer_idx, None, bgp, peers);
    }
    for rd in vpn_rds {
        route_soft_in_peer_table(peer_idx, Some(rd), bgp, peers);
    }
}

fn route_soft_in_peer_table(
    peer_idx: usize,
    rd: Option<RouteDistinguisher>,
    bgp: &mut BgpTop,
    peers: &mut PeerMap,
) {
    // Snapshot stored Adj-RIB-In entries so subsequent mutable borrows
    // of `peers` / `bgp` (policy apply, Loc-RIB update, advertise
    // fan-out) don't conflict with the iteration.
    let entries: Vec<(Ipv4Net, Vec<BgpRib>)> = {
        let peer = peers.get_mut_by_idx(peer_idx).expect("peer exists");
        match rd {
            Some(rd) => peer
                .adj_in
                .v4vpn
                .get(&rd)
                .map(|t| t.0.iter().map(|(p, ribs)| (*p, ribs.clone())).collect())
                .unwrap_or_default(),
            None => peer
                .adj_in
                .v4
                .0
                .iter()
                .map(|(p, ribs)| (*p, ribs.clone()))
                .collect(),
        }
    };

    for (prefix, ribs) in entries {
        for stored in ribs {
            let nlri = Ipv4Nlri {
                id: stored.remote_id,
                prefix,
            };

            // Re-run inbound policy against the stored pre-policy
            // attributes. The Adj-RIB-In keeps the original attr; only
            // the Loc-RIB candidate gets the post-policy version.
            let pre_attr: BgpAttr = (*stored.attr).clone();
            let pre_weight = stored.weight;
            let post_attr_opt = {
                let peer = peers.get_mut_by_idx(peer_idx).expect("peer exists");
                route_apply_policy_in(peer, &nlri, pre_attr, pre_weight)
            };

            match post_attr_opt {
                None => {
                    // Policy denies this route under the new rules.
                    // rib_in=false leaves the Adj-RIB-In entry in
                    // place so subsequent replays still see it.
                    route_ipv4_withdraw(peer_idx, &nlri, rd, None, bgp, peers, false);
                }
                Some(decision) => {
                    let mut new_rib = stored.clone();
                    new_rib.attr = bgp.attr_store.intern(decision.attr);
                    new_rib.weight = decision.weight;
                    let (_, selected, next_id) = bgp.local_rib.update(rd, prefix, new_rib.clone());

                    // Policy-in change may have shifted the best path
                    // for this prefix; reconcile the FIB so the kernel
                    // tracks whatever Loc-RIB now considers best.
                    if rd.is_none() {
                        fib_install_v4(bgp, prefix, &selected);
                    }

                    if !selected.is_empty() {
                        route_advertise_to_peers(rd, prefix, &selected, peer_idx, bgp, peers);
                    }
                    new_rib.local_id = next_id;
                    route_advertise_to_addpath(rd, prefix, &new_rib, peer_idx, bgp, peers);
                }
            }
        }
    }
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
    // Reconcile FIB after the withdraw: empty `selected` means the
    // last candidate just disappeared and we should withdraw from
    // the kernel; non-empty means a replacement path is now best
    // and a fresh Ipv4Add carries the new attrs.
    if rd.is_none() {
        fib_install_v4(bgp, nlri.prefix, &selected);
    }

    // VRF export — symmetric with `route_update_ipv4`. After a
    // withdraw, either a replacement winner exists (emit a fresh
    // Export so the global v4vpn row carries the new attrs) or
    // `selected` is empty (emit WithdrawExport to drop the row).
    if rd.is_none()
        && let Some(exporter) = bgp.vrf_export
    {
        if let Some(winner) = selected.first() {
            super::vrf::vrf_emit_export(exporter, nlri.prefix, &winner.attr);
        } else {
            super::vrf::vrf_emit_withdraw(exporter, nlri.prefix);
        }
    }

    // Global v4vpn withdraw → per-VRF import dispatch. If a
    // replacement winner survives best-path, that VPNv4 row now
    // carries a different attr; re-import with the new attr. If
    // `selected` is empty, the route truly went away — flood a
    // WithdrawImport using the *removed* row's attr to resolve the
    // matching-VRF set (we no longer have the new attr).
    if let Some(rd) = rd
        && let Some(dispatcher) = bgp.vrf_import
    {
        if let Some(winner) = selected.first() {
            super::vrf::dispatch_import_v4(dispatcher, rd, nlri.prefix, &winner.attr, 0, None);
        } else if let Some(gone) = removed.first() {
            super::vrf::dispatch_withdraw_import_v4(dispatcher, rd, nlri.prefix, &gone.attr, None);
        }
    }
    if !selected.is_empty() || !removed.is_empty() {
        route_advertise_to_peers(rd, nlri.prefix, &selected, ident, bgp, peers);
    }
    if let Some(removed) = removed.pop() {
        route_withdraw_from_addpath(rd, nlri.prefix, &removed, ident, bgp, peers);
    }
}

/// IPv6 unicast receive path — the v6 counterpart of
/// [`route_ipv4_update`]. The MP_REACH next-hop is carried in
/// `attr.nexthop` as `BgpNexthop::Ipv6` (stamped by the dispatch
/// site), drives the FIB install, and the route lands in
/// `local_rib.v6`.
///
/// Scope (layer 2b-i): receive → Adj-RIB-In → Loc-RIB → FIB. Inbound
/// policy is **not** applied yet (the policy engine is IPv4-typed),
/// peer re-advertisement is layer 2b-ii, and the per-VRF export/import
/// hooks are layer 3. None of those are wired here.
pub fn route_ipv6_update(
    ident: usize,
    nlri: &Ipv6Nlri,
    attr: &BgpAttr,
    bgp: &mut BgpTop,
    peers: &mut PeerMap,
    stale: bool,
) {
    let (peer_ident, peer_router_id, typ) = {
        let peer = peers.get_mut_by_idx(ident).expect("peer must exist");

        // RFC 4271 / 4456 loop detection — identical to the v4 path.
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
        nlri.id,
        0,
        attr,
        None, // no label (labeled-unicast / VPN out of scope here)
        None, // Vpnv4Nexthop slot unused for v6 unicast
        stale,
    );

    // Adj-RIB-In, so session teardown and future soft-reconfig can
    // sweep these. (No inbound policy yet — see the doc comment.)
    {
        let peer = peers.get_mut_by_idx(ident).expect("peer must exist");
        peer.adj_in.add_v6(nlri.prefix, rib.clone());
    }

    rib.attr = bgp.attr_store.intern(attr.clone());
    let (_, selected, _next_id) = bgp.local_rib.update_v6(nlri.prefix, rib);

    fib_install_v6(bgp, nlri.prefix, &selected);
}

/// IPv6 unicast withdraw — the v6 counterpart of
/// [`route_ipv4_withdraw`], reduced to the 2b-i surface (no VRF
/// hooks, no peer re-advertisement).
pub fn route_ipv6_withdraw(
    ident: usize,
    nlri: &Ipv6Nlri,
    bgp: &mut BgpTop,
    peers: &mut PeerMap,
    rib_in: bool,
) {
    if rib_in {
        let peer = peers.get_mut_by_idx(ident).expect("peer must exist");
        peer.adj_in.remove_v6(nlri.prefix, nlri.id);
    }

    let _removed = bgp.local_rib.remove_v6(nlri.prefix, nlri.id, ident);
    let selected = bgp.local_rib.select_best_path_v6(nlri.prefix);
    fib_install_v6(bgp, nlri.prefix, &selected);
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
                    if DEBUG_EVPN {
                        tracing::info!("extract_vni_from_attr: RT yields VNI {}", vni);
                    }
                    return Some(vni);
                }
            }
        }
    }
    None
}

/// Map a parsed `EvpnRoute` to the policy-side `EvpnRouteType`
/// discriminator. Only Type-2 (MAC-IP) and Type-3 (Inclusive
/// Multicast) parse into `EvpnRoute` today; Type-1/4/5 NLRIs are
/// either dropped at parse or never reach this evaluator, so they
/// are not represented here.
fn evpn_route_type_of(route: &EvpnRoute) -> crate::policy::EvpnRouteType {
    use crate::policy::EvpnRouteType;
    match route {
        EvpnRoute::Mac(_) => EvpnRouteType::MacIp,
        EvpnRoute::Multicast(_) => EvpnRouteType::Multicast,
    }
}

/// Derive the VNI carried by an EVPN route. For Type-2 (MAC-IP)
/// the VNI lives directly in the NLRI's MPLS-label1 field
/// (`EvpnMac.vni`). For Type-3 (Inclusive Multicast) the NLRI
/// carries no VNI, so we fall back to the Route Target extended
/// community per RFC 8365 §5.1.2.4 via `extract_vni_from_attr`.
/// Returns `None` when neither source yields a non-zero VNI.
fn evpn_vni_of(route: &EvpnRoute, attr: &BgpAttr) -> Option<u32> {
    match route {
        EvpnRoute::Mac(m) => (m.vni != 0).then_some(m.vni),
        EvpnRoute::Multicast(_) => extract_vni_from_attr(attr),
    }
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
                    let _ = bgp.rib_client.send(msg);
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
                    let _ = bgp.rib_client.send(msg);
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
                    esi: best.esi, // Extracted from EVPN route.
                };
                let _ = bgp.rib_client.send(msg);
            } else {
                eprintln!(
                    "[ERROR] EVPN Type 2 route missing Route Target (RFC 8365). \
                     VNI required from RT extended community. RD: {:?}",
                    rd
                );
            }
        }
        EvpnPrefix::InclusiveMulticast { orig, .. } => {
            // Type 3 Inclusive Multicast route installation.
            // This route indicates that a multicast group (*,G) should be replicated to
            // all VTEPs that have advertised this route.
            // RFC 8365: VNI must come from Route Target extended community.
            if let Some(vni) = extract_vni_from_attr(&best.attr) {
                let msg = rib::Message::MdbAdd {
                    vni,
                    group: *orig,
                    source: None,
                    ifindex: 0,
                    seq: extract_mac_mobility_seq(&best.attr),
                };
                let _ = bgp.rib_client.send(msg);
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
/// the show command.
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

    // Extract ESI from EVPN Type 2 route for multi-homing support.
    if let EvpnRoute::Mac(m) = route {
        rib.esi = Some(m.esi);
    }

    // Apply input policy *after* the route is registered in
    // Adj-RIB-In (raw, pre-policy view) but *before* it enters
    // Loc-RIB / best-path. On deny, treat the receive as an
    // implicit withdrawal so any stale path is also pulled.
    let decision = {
        let peer = peers.get_mut_by_idx(ident).expect("peer must exist");
        peer.adj_in.add_evpn(rd, prefix.clone(), rib.clone());
        route_apply_policy_in_evpn(peer, route, attr.clone(), rib.weight)
    };
    let Some(decision) = decision else {
        route_evpn_withdraw(ident, route, bgp, peers);
        return;
    };
    rib.attr = bgp.attr_store.intern(decision.attr);
    rib.weight = decision.weight;

    let _ = bgp.local_rib.update_evpn(rd, prefix.clone(), rib);

    // After updating Loc-RIB, re-run best path selection and export to RIB.
    // No `withdrawn` source on the announce path — selected is non-empty by
    // construction (we just inserted the path).
    let selected = bgp.local_rib.select_best_path_evpn(&rd, &prefix);
    route_evpn_export_selected(&rd, &prefix, &selected, None, bgp);
    if !selected.is_empty() {
        route_advertise_evpn_to_peers(rd, prefix, &selected, bgp, peers);
    }
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
                peer_id, update, None, None, bgp_attr, None, None, bgp, peers, false,
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
                        None,
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
            MpReachAttr::Ipv4 {
                snpa: _,
                nhop,
                updates,
            } => {
                // RFC 8950 IPv4-over-IPv6: install the prefix into
                // Loc-RIB and the FIB. The v6 next-hop in `nhop` is
                // the remote's link-local; the receiver doesn't need
                // it for forwarding (kernel uses the v6 onlink already
                // discovered via ND), so we route the install via the
                // egress ifindex of the peer that delivered the
                // UPDATE. ENHE on a non-interface peer is unexpected —
                // ENHE is currently only negotiated by unnumbered
                // peers; log and drop in that case rather than fall
                // back to a bogus install.
                let egress_ifindex = peers.get_by_idx(peer_id).and_then(|p| p.scope_id);
                if let Some(ifindex) = egress_ifindex {
                    for update in updates.iter() {
                        route_ipv4_update(
                            peer_id,
                            update,
                            None,
                            None,
                            bgp_attr,
                            None,
                            Some(ifindex),
                            bgp,
                            peers,
                            false,
                        );
                    }
                } else {
                    tracing::warn!(
                        "RFC 8950: dropping IPv4 routes from peer {} via v6 next-hop {} — peer has no egress ifindex",
                        peer_id,
                        nhop,
                    );
                }
            }
            MpReachAttr::Ipv6 {
                snpa: _,
                nhop,
                updates,
            } => {
                // Native IPv6 unicast: the MP_REACH next-hop replaces
                // the (unused) v4 NEXT_HOP attribute. Stamp it into the
                // attr so best-path / FIB read a v6 next-hop.
                if let IpAddr::V6(nh6) = nhop {
                    let mut attr_v6 = bgp_attr.clone();
                    attr_v6.nexthop = Some(BgpNexthop::Ipv6(nh6));
                    for update in updates.iter() {
                        route_ipv6_update(peer_id, update, &attr_v6, bgp, peers, false);
                    }
                } else {
                    tracing::warn!(
                        "IPv6 unicast MP_REACH from peer {} carried a non-v6 next-hop {} — dropping",
                        peer_id,
                        nhop,
                    );
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
            MpUnreachAttr::Ipv6Nlri(withdrawals) => {
                for withdraw in withdrawals.iter() {
                    route_ipv6_withdraw(peer_id, withdraw, bgp, peers, true);
                }
            }
            MpUnreachAttr::Ipv6Eor => {
                let afi_safi = AfiSafi::new(Afi::Ip6, Safi::Unicast);
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
                None,
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
    //
    // eBGP and self-originated routes always get a v4 rewrite. ENHE-
    // sourced routes (`egress_ifindex_v6.is_some()`) join that set
    // unconditionally: the inbound NEXT_HOP for such a route is
    // 0.0.0.0 (RFC 8950 §4) — preserving it for iBGP-iBGP, the way
    // RFC 4271 normally prescribes, would forward a black-hole. The
    // rewrite is harmless for ENHE-aware peers (they ignore the v4
    // NEXT_HOP attribute and read the LL from MP_REACH per RFC 8950
    // §4) and necessary for non-ENHE peers (they're the ones who
    // can't decode an MP_REACH with a v6 next-hop in the first place).
    let needs_v4_rewrite = peer.is_ebgp() || rib.is_originated() || rib.egress_ifindex_v6.is_some();
    if needs_v4_rewrite {
        let nexthop = if let Some(ref local_addr) = peer.param.local_addr
            && let IpAddr::V4(local_addr) = local_addr.ip()
        {
            local_addr
        } else {
            *bgp.router_id
        };
        // VPNv4 rows carry the `Vpnv4Nexthop` slot (it holds the
        // route's RD); emit an MP_REACH-shaped next-hop so
        // `flush_vpnv4` picks it up — writing a bare `BgpNexthop::Ipv4`
        // here would be ignored at flush time and the MP_REACH would
        // ship with no next-hop. The address is the local end of this
        // peer's (i)BGP session (next-hop-self toward the remote PE,
        // identical to the v4-unicast rule), falling back to the
        // router-id when that local address isn't IPv4. Plain
        // v4-unicast rows (`rib.nexthop == None`) keep the bare IPv4
        // next-hop.
        attrs.nexthop = match rib.nexthop {
            Some(ref vpn_nh) => Some(BgpNexthop::Vpnv4(Vpnv4Nexthop {
                rd: vpn_nh.rd,
                nhop: nexthop,
            })),
            None => Some(BgpNexthop::Ipv4(nexthop)),
        };
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

/// Apply a policy to a route. Walks entries in numeric-key order;
/// on each match consults the entry's terminal action:
///
/// - **`permit`**: apply any `set` clauses, return the modified
///   attribute (the route is accepted).
/// - **`next`**: apply any `set` clauses, then continue to the
///   next entry. Lets one entry decorate a route while another
///   later entry decides the verdict.
/// - **`deny`**: do NOT apply any `set` clauses; return `None`
///   (the route is dropped).
///
/// Default-deny when no entry matches (or all matching entries
/// fall through with `next` and the policy ends): returns `None`.
/// Operators express "default permit" by appending an
/// unconditional final entry with `action: permit`.
/// Outcome of applying a policy-list to a route. `attr` is the
/// (possibly modified) BGP attribute set; `weight` is the local
/// per-router BGP weight. `weight` is not on the wire — it lives
/// on `BgpRib::weight` and is used in best-path tie-breaking.
#[derive(Debug, Clone)]
pub struct PolicyDecision {
    pub attr: BgpAttr,
    pub weight: u32,
}

pub fn policy_list_apply(
    policy_list: &PolicyList,
    nlri: &Ipv4Nlri,
    bgp_attr: BgpAttr,
    weight: u32,
    local_addr: Ipv4Addr,
) -> Option<PolicyDecision> {
    use crate::policy::{PolicyAction, SetNextHop};
    let mut decision = PolicyDecision {
        attr: bgp_attr,
        weight,
    };
    for (_, entry) in policy_list.entry.iter() {
        if !entry_matches(entry, nlri, &decision.attr, decision.weight) {
            continue;
        }
        match entry.action {
            PolicyAction::Deny => {
                // Drop the route without applying any set clauses.
                return None;
            }
            PolicyAction::Permit | PolicyAction::Next => {
                // Apply the entry's set clauses to the working
                // attribute, then either return (Permit) or fall
                // through to the next entry (Next).
                if let Some(action) = &entry.local_pref {
                    let current = decision
                        .attr
                        .local_pref
                        .as_ref()
                        .map(|l| l.local_pref)
                        .unwrap_or(0);
                    decision.attr.local_pref = Some(LocalPref::new(action.apply(current)));
                }
                if let Some(action) = &entry.med {
                    let current = decision.attr.med.as_ref().map(|m| m.med).unwrap_or(0);
                    decision.attr.med = Some(Med {
                        med: action.apply(current),
                    });
                }
                if let Some(w) = entry.weight {
                    decision.weight = w;
                }
                if let Some(cfg) = &entry.set_community {
                    apply_set_community(&mut decision.attr, cfg);
                }
                if let Some(prepend) = &entry.set_as_path_prepend {
                    apply_set_as_path_prepend(&mut decision.attr, prepend);
                }
                if let Some(nh) = &entry.set_next_hop {
                    match nh {
                        SetNextHop::Address(IpAddr::V4(addr)) => {
                            decision.attr.nexthop = Some(BgpNexthop::Ipv4(*addr));
                        }
                        SetNextHop::Address(IpAddr::V6(_)) => {
                            // BgpNexthop is IPv4-only today; an
                            // IPv6 target parses but has no
                            // effect. Phase H follow-up wires
                            // BgpNexthop::Ipv6 + the emit path.
                        }
                        SetNextHop::SelfAddr => {
                            decision.attr.nexthop = Some(BgpNexthop::Ipv4(local_addr));
                        }
                    }
                }
                if let Some(origin) = entry.set_origin {
                    decision.attr.origin = Some(origin);
                }
                apply_color_and_prefix_sid(&mut decision.attr, entry);
                if entry.action == PolicyAction::Permit {
                    return Some(decision);
                }
                // Next: continue with the modified attribute.
            }
        }
    }
    // End of list reached without a permit verdict — default deny.
    None
}

fn entry_matches(
    entry: &crate::policy::PolicyEntry,
    nlri: &Ipv4Nlri,
    bgp_attr: &BgpAttr,
    weight: u32,
) -> bool {
    if let Some(prefix_set) = &entry.prefix_set
        && !prefix_set.matches(nlri.prefix)
    {
        return false;
    }
    if let Some(community_set) = &entry.community_set
        && !community_set.matches(bgp_attr)
    {
        return false;
    }
    if let Some(set) = &entry.ext_community_set
        && !set.matches(bgp_attr)
    {
        return false;
    }
    if let Some(set) = &entry.large_community_set
        && !set.matches(bgp_attr)
    {
        return false;
    }
    if let Some(as_path_set) = &entry.as_path_set
        && !as_path_set.matches(bgp_attr)
    {
        return false;
    }
    if let Some(want) = &entry.match_next_hop {
        // Exact equality. BgpAttr.nexthop is currently IPv4-only,
        // so an IPv6 entry never matches today; that's acceptable
        // until v6 nexthop is plumbed through.
        let std::net::IpAddr::V4(want_v4) = want else {
            return false;
        };
        let Some(BgpNexthop::Ipv4(have_v4)) = bgp_attr.nexthop.as_ref() else {
            return false;
        };
        if want_v4 != have_v4 {
            return false;
        }
    }
    if let Some(med_match) = &entry.match_med {
        let med = bgp_attr.med.as_ref().map(|m| m.med).unwrap_or(0);
        if !med_match.matches(med) {
            return false;
        }
    }
    if let Some(m) = &entry.match_as_path_len {
        let len = bgp_attr.aspath.as_ref().map(|p| p.length()).unwrap_or(0);
        if !m.matches(len) {
            return false;
        }
    }
    if let Some(m) = &entry.match_as_path_len_uniq {
        let uniq = bgp_attr
            .aspath
            .as_ref()
            .map(|p| p.unique_length())
            .unwrap_or(0);
        if !m.matches(uniq) {
            return false;
        }
    }
    if let Some(m) = &entry.match_local_pref {
        let lp = bgp_attr
            .local_pref
            .as_ref()
            .map(|l| l.local_pref)
            .unwrap_or(0);
        if !m.matches(lp) {
            return false;
        }
    }
    if let Some(m) = &entry.match_weight
        && !m.matches(weight)
    {
        return false;
    }
    if let Some(want) = entry.match_origin {
        let Some(have) = bgp_attr.origin else {
            return false;
        };
        if have != want {
            return false;
        }
    }
    if !matches_color(entry, bgp_attr) {
        return false;
    }
    true
}

/// Color (RFC 9012 §4.3) match shared between the IPv4 and EVPN
/// apply paths. Returns true when the entry has no `match color`
/// predicate, or when at least one Color extcomm on the route
/// matches the configured value. CO bits are not compared in v1.
fn matches_color(entry: &crate::policy::PolicyEntry, bgp_attr: &BgpAttr) -> bool {
    let Some(want) = entry.match_color else {
        return true;
    };
    let Some(ecom) = bgp_attr.ecom.as_ref() else {
        return false;
    };
    ecom.0
        .iter()
        .filter_map(|v| v.as_color())
        .any(|c| c.color == want)
}

/// Apply `set color N` and `set prefix-sid label-index N` to a
/// working route attribute. Shared between the IPv4 and EVPN apply
/// loops so a future `set color` semantic change lands once.
fn apply_color_and_prefix_sid(attr: &mut BgpAttr, entry: &crate::policy::PolicyEntry) {
    if let Some(color) = entry.set_color {
        let ecom = attr.ecom.get_or_insert_with(ExtCommunity::default);
        ecom.0.push(ExtCommunityValue::from_color(0, color));
    }
    if let Some(idx) = entry.set_prefix_sid_label_index {
        attr.prefix_sid = Some(PrefixSid {
            tlvs: vec![PrefixSidTlv::LabelIndex {
                flags: 0,
                label_index: idx,
            }],
        });
    }
}

/// EVPN counterpart of `policy_list_apply`. Same Permit/Deny/Next
/// state machine and same `set` clauses; the matcher swaps to
/// `entry_matches_evpn`, which skips IPv4-prefix-only conditions
/// (`prefix_set`, `match_next_hop`) and adds the EVPN-specific
/// `match_evpn_route_type` and `match_evpn_vni` checks.
pub fn policy_list_apply_evpn(
    policy_list: &PolicyList,
    route: &EvpnRoute,
    bgp_attr: BgpAttr,
    weight: u32,
    local_addr: Ipv4Addr,
) -> Option<PolicyDecision> {
    use crate::policy::{PolicyAction, SetNextHop};
    let mut decision = PolicyDecision {
        attr: bgp_attr,
        weight,
    };
    for (_, entry) in policy_list.entry.iter() {
        if !entry_matches_evpn(entry, route, &decision.attr, decision.weight) {
            continue;
        }
        match entry.action {
            PolicyAction::Deny => return None,
            PolicyAction::Permit | PolicyAction::Next => {
                if let Some(action) = &entry.local_pref {
                    let current = decision
                        .attr
                        .local_pref
                        .as_ref()
                        .map(|l| l.local_pref)
                        .unwrap_or(0);
                    decision.attr.local_pref = Some(LocalPref::new(action.apply(current)));
                }
                if let Some(action) = &entry.med {
                    let current = decision.attr.med.as_ref().map(|m| m.med).unwrap_or(0);
                    decision.attr.med = Some(Med {
                        med: action.apply(current),
                    });
                }
                if let Some(w) = entry.weight {
                    decision.weight = w;
                }
                if let Some(cfg) = &entry.set_community {
                    apply_set_community(&mut decision.attr, cfg);
                }
                if let Some(prepend) = &entry.set_as_path_prepend {
                    apply_set_as_path_prepend(&mut decision.attr, prepend);
                }
                // `set next-hop` writes BgpAttr.nexthop (IPv4-only).
                // For EVPN the real nexthop travels in MP_REACH_NLRI,
                // so the mutation has no visible effect on the wire
                // today; we still honor it for parity with IPv4.
                if let Some(nh) = &entry.set_next_hop {
                    match nh {
                        SetNextHop::Address(IpAddr::V4(addr)) => {
                            decision.attr.nexthop = Some(BgpNexthop::Ipv4(*addr));
                        }
                        SetNextHop::Address(IpAddr::V6(_)) => {}
                        SetNextHop::SelfAddr => {
                            decision.attr.nexthop = Some(BgpNexthop::Ipv4(local_addr));
                        }
                    }
                }
                if let Some(origin) = entry.set_origin {
                    decision.attr.origin = Some(origin);
                }
                apply_color_and_prefix_sid(&mut decision.attr, entry);
                if entry.action == PolicyAction::Permit {
                    return Some(decision);
                }
            }
        }
    }
    None
}

/// EVPN match evaluator. Same shape as `entry_matches` minus the
/// IPv4-specific clauses: `prefix_set` (no IP prefix on EVPN
/// NLRIs) and `match_next_hop` (BgpAttr.nexthop is IPv4-only and
/// is not the EVPN nexthop). Common BGP attribute matches
/// (community/ext-community/large-community/as-path-set,
/// med/as-path-len/local-pref/weight/origin) carry over verbatim.
/// EVPN-specific clauses (`match_evpn_route_type`, `match_evpn_vni`)
/// pull from the route discriminator and the per-type VNI source.
fn entry_matches_evpn(
    entry: &crate::policy::PolicyEntry,
    route: &EvpnRoute,
    bgp_attr: &BgpAttr,
    weight: u32,
) -> bool {
    if let Some(community_set) = &entry.community_set
        && !community_set.matches(bgp_attr)
    {
        return false;
    }
    if let Some(set) = &entry.ext_community_set
        && !set.matches(bgp_attr)
    {
        return false;
    }
    if let Some(set) = &entry.large_community_set
        && !set.matches(bgp_attr)
    {
        return false;
    }
    if let Some(as_path_set) = &entry.as_path_set
        && !as_path_set.matches(bgp_attr)
    {
        return false;
    }
    if let Some(med_match) = &entry.match_med {
        let med = bgp_attr.med.as_ref().map(|m| m.med).unwrap_or(0);
        if !med_match.matches(med) {
            return false;
        }
    }
    if let Some(m) = &entry.match_as_path_len {
        let len = bgp_attr.aspath.as_ref().map(|p| p.length()).unwrap_or(0);
        if !m.matches(len) {
            return false;
        }
    }
    if let Some(m) = &entry.match_as_path_len_uniq {
        let uniq = bgp_attr
            .aspath
            .as_ref()
            .map(|p| p.unique_length())
            .unwrap_or(0);
        if !m.matches(uniq) {
            return false;
        }
    }
    if let Some(m) = &entry.match_local_pref {
        let lp = bgp_attr
            .local_pref
            .as_ref()
            .map(|l| l.local_pref)
            .unwrap_or(0);
        if !m.matches(lp) {
            return false;
        }
    }
    if let Some(m) = &entry.match_weight
        && !m.matches(weight)
    {
        return false;
    }
    if let Some(want) = entry.match_origin {
        let Some(have) = bgp_attr.origin else {
            return false;
        };
        if have != want {
            return false;
        }
    }
    if let Some(want) = entry.match_evpn_route_type
        && evpn_route_type_of(route) != want
    {
        return false;
    }
    if let Some(want) = entry.match_evpn_vni {
        let Some(have) = evpn_vni_of(route, bgp_attr) else {
            return false;
        };
        if have != want {
            return false;
        }
    }
    if !matches_color(entry, bgp_attr) {
        return false;
    }
    true
}

/// Apply a `set community <community-set> [additive]` action to `bgp_attr`.
///
/// Only `Standard::Exact` matchers contribute concrete values; regex and
/// extended-community matchers are skipped (extended communities live in
/// a separate BGP attribute, and regex patterns are not concrete values).
/// With `additive = false` the existing community list is replaced; with
/// `additive = true` the new values are merged in. The result is always
/// sorted and deduplicated.
fn apply_set_community(bgp_attr: &mut BgpAttr, cfg: &crate::policy::SetCommunityConfig) {
    // Unresolved name (community-set was deleted or never defined):
    // skip silently rather than touch the attribute. policy_entry_sync
    // re-resolves on changes.
    let Some(set) = cfg.resolved.as_ref() else {
        return;
    };
    let new_vals: Vec<u32> = set
        .vals
        .iter()
        .filter_map(|m| match m {
            CommunityMatcher::Standard(StandardMatcher::Exact(v)) => Some(v.0),
            _ => None,
        })
        .collect();

    use crate::policy::SetCommunityMode;
    match cfg.mode {
        SetCommunityMode::Replace => {
            if new_vals.is_empty() {
                bgp_attr.com = None;
                return;
            }
            let mut com = Community::new();
            for v in new_vals {
                com.push(v);
            }
            com.sort_uniq();
            bgp_attr.com = Some(com);
        }
        SetCommunityMode::Additive => {
            let mut com = bgp_attr.com.clone().unwrap_or_default();
            for v in new_vals {
                com.push(v);
            }
            com.sort_uniq();
            bgp_attr.com = Some(com);
        }
        SetCommunityMode::Delete => {
            // Set difference: drop matching values from existing
            // community attribute. No-op if attribute absent.
            let Some(mut com) = bgp_attr.com.clone() else {
                return;
            };
            let drop: std::collections::HashSet<u32> = new_vals.into_iter().collect();
            com.0.retain(|v| !drop.contains(v));
            bgp_attr.com = if com.0.is_empty() { None } else { Some(com) };
        }
    }
}

/// Apply a `set as-path-prepend ASN repeat NUM` action by prepending
/// `cfg.asn` `cfg.repeat` times onto the existing AS-path (or
/// installing a new one if absent). `repeat` is bounded `1..=255` by
/// the YANG schema; a zero would be a no-op anyway.
fn apply_set_as_path_prepend(bgp_attr: &mut BgpAttr, cfg: &AsPathPrependConfig) {
    if cfg.repeat == 0 {
        return;
    }
    let prepend_path = As4Path::from(vec![cfg.asn; cfg.repeat as usize]);
    match bgp_attr.aspath.as_mut() {
        Some(existing) => existing.prepend_mut(prepend_path),
        None => bgp_attr.aspath = Some(prepend_path),
    }
}

pub fn route_sync_ipv4(peer: &mut Peer, bgp: &mut BgpTop) {
    let add_path = peer.opt.is_add_path_send(Afi::Ip, Safi::Unicast);

    // Collect all routes first to avoid borrow checker issues
    let routes: Vec<(Ipv4Net, BgpRib)> = if add_path {
        bgp.local_rib
            .v4
            .0
            .iter()
            .flat_map(|(prefix, ribs)| ribs.iter().map(move |rib| (prefix, rib.clone())))
            .collect()
    } else {
        bgp.local_rib
            .v4
            .1
            .iter()
            .map(|(prefix, rib)| (prefix, rib.clone()))
            .collect()
    };

    // Sync targets a single peer; the per-group cache would fan
    // out to every member, double-sending to peers that already
    // have these routes. Accumulate locally and emit via
    // `send_ipv4_direct`, which preserves the per-attr batching
    // (one MP_REACH UPDATE per shared attr-set).
    let mut entries: Vec<(Arc<BgpAttr>, Ipv4Nlri)> = Vec::new();
    for (prefix, mut rib) in routes {
        let Some((nlri, attr)) = route_update_ipv4(peer, &prefix, &rib, bgp, add_path) else {
            continue;
        };

        let Some(decision) = route_apply_policy_out(peer, &nlri, attr, rib.weight) else {
            continue;
        };

        // Register to AdjOut.
        rib.attr = bgp.attr_store.intern(decision.attr);
        let arc_attr = rib.attr.clone();
        peer.adj_out.add(None, nlri.prefix, rib);

        entries.push((arc_attr, nlri));
    }

    let enhe_v6 = peer
        .is_enhe_v4_negotiated()
        .then(|| super::update_group::compose_enhe_next_hop(peer, bgp.interface_addrs))
        .flatten();
    super::update_group::send_ipv4_direct(peer, entries, enhe_v6);

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
                    .flat_map(|(prefix, ribs)| ribs.iter().map(move |rib| (prefix, rib.clone())))
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
                    .map(|(prefix, rib)| (prefix, rib.clone()))
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

            let Some(decision) = route_apply_policy_out(peer, &nlri, attr, rib.weight) else {
                continue;
            };
            let attr = decision.attr;

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
        let Some(decision) = route_apply_policy_out_evpn(peer, &route, attr, rib.weight) else {
            continue;
        };
        let attr = bgp.attr_store.intern(decision.attr);
        // Record in Adj-RIB-Out so a subsequent soft-out can detect
        // which routes were synced and withdraw any that fail the
        // new policy.
        let mut adj = rib.clone();
        adj.attr = attr.clone();
        peer.adj_out.add_evpn(rd, prefix, adj);
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
            rib_client: &self.ctx.rib,
            attr_store: &mut self.attr_store,
            update_groups: &mut self.update_groups,
            interface_addrs: &self.interface_addrs,
            vrf_export: None,
            color_policy: Some(&self.color_policy),
            flex_algo_routes: Some(&self.flex_algo_routes),
            vrf_import: None,
        };

        // An originated route lacks a v4 NEXT_HOP attribute, so when
        // it wins best by weight=32768 `fib_install_v4` will emit an
        // `Ipv4Del` for any BGP-typed FIB entry that a peer route
        // previously installed for the same prefix. That's correct:
        // the underlying source (Static / Connected / IGP) owns the
        // forwarding entry now, and BGP shouldn't shadow it.
        fib_install_v4(&bgp_ref, prefix, &selected);

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
            rib_client: &self.ctx.rib,
            attr_store: &mut self.attr_store,
            update_groups: &mut self.update_groups,
            interface_addrs: &self.interface_addrs,
            vrf_export: None,
            color_policy: Some(&self.color_policy),
            flex_algo_routes: Some(&self.flex_algo_routes),
            vrf_import: None,
        };

        let selected = bgp_ref.local_rib.select_best_path(prefix);
        // When the originated route disappears, a peer route may now
        // be the best (or no path may remain). Reconcile so the FIB
        // matches Loc-RIB.
        fib_install_v4(&bgp_ref, prefix, &selected);

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

    // ---- redistribute injection -----------------------------------
    //
    // `route_redist_inject` / `route_redist_withdraw` are siblings of
    // `route_add` / `route_del`, but
    //   - carry a `metric` (lowered to MED on the originated route),
    //   - tag the originator with a per-rtype `remote_id` discriminator
    //     so a redistributed Connected route and a `network`
    //     statement for the same prefix do NOT collide in the
    //     LocalRibTable — both look like `ORIGINATED_PEER` to the
    //     update path, and same-prefix-same-(ident,remote_id) keys
    //     replace one another.
    //
    // IPv6 redistribution stays storage-only on `Bgp.redist_v6` until
    // a follow-up adds the LocalRib v6 path; today `LocalRib` only
    // holds v4 / VPNv4 / EVPN.

    /// Per-rtype remote_id discriminator, so distinct redistribute
    /// sources (and the `network` statement at id=0) coexist for the
    /// same prefix without overwriting one another. Values are local
    /// and never appear on the wire.
    pub(super) fn redist_remote_id(rtype: crate::rib::RibType) -> u32 {
        match rtype {
            crate::rib::RibType::Connected => 1,
            crate::rib::RibType::Static => 2,
            crate::rib::RibType::Ospf => 3,
            crate::rib::RibType::Isis => 4,
            crate::rib::RibType::Kernel => 5,
            crate::rib::RibType::Bgp => 0, // self-loop prevented upstream
            _ => 0,
        }
    }

    pub fn route_redist_inject(
        &mut self,
        rtype: crate::rib::RibType,
        prefix: Ipv4Net,
        metric: u32,
    ) {
        let ident = ORIGINATED_PEER;
        let remote_id = Self::redist_remote_id(rtype);
        let mut attr = BgpAttr::new();
        attr.med = Some(bgp_packet::Med::new(metric));
        let mut rib = BgpRib::new(
            ident,
            Ipv4Addr::UNSPECIFIED,
            BgpRibType::Originated,
            remote_id,
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
            rib_client: &self.ctx.rib,
            attr_store: &mut self.attr_store,
            update_groups: &mut self.update_groups,
            interface_addrs: &self.interface_addrs,
            vrf_export: None,
            color_policy: Some(&self.color_policy),
            flex_algo_routes: Some(&self.flex_algo_routes),
            vrf_import: None,
        };

        // Same logic as `route_add`: the redistributed BGP route has
        // no v4 NEXT_HOP, so winning best causes BGP to withdraw any
        // peer-installed FIB entry for this prefix and let the source
        // protocol's own RIB entry handle forwarding.
        fib_install_v4(&bgp_ref, prefix, &selected);

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

    pub fn route_redist_withdraw(&mut self, rtype: crate::rib::RibType, prefix: Ipv4Net) {
        let ident = ORIGINATED_PEER;
        let remote_id = Self::redist_remote_id(rtype);
        let removed = self.local_rib.remove(None, prefix, remote_id, ident);

        let mut bgp_ref = BgpTop {
            router_id: &self.router_id,
            local_rib: &mut self.local_rib,
            tx: &self.tx,
            rib_client: &self.ctx.rib,
            attr_store: &mut self.attr_store,
            update_groups: &mut self.update_groups,
            interface_addrs: &self.interface_addrs,
            vrf_export: None,
            color_policy: Some(&self.color_policy),
            flex_algo_routes: Some(&self.flex_algo_routes),
            vrf_import: None,
        };

        let selected = bgp_ref.local_rib.select_best_path(prefix);
        // A peer route may now be best again (or nothing's left);
        // reconcile the FIB.
        fib_install_v4(&bgp_ref, prefix, &selected);

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
            rib_client: &self.ctx.rib,
            attr_store: &mut self.attr_store,
            update_groups: &mut self.update_groups,
            interface_addrs: &self.interface_addrs,
            vrf_export: None,
            color_policy: Some(&self.color_policy),
            flex_algo_routes: Some(&self.flex_algo_routes),
            vrf_import: None,
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
            rib_client: &self.ctx.rib,
            attr_store: &mut self.attr_store,
            update_groups: &mut self.update_groups,
            interface_addrs: &self.interface_addrs,
            vrf_export: None,
            color_policy: Some(&self.color_policy),
            flex_algo_routes: Some(&self.flex_algo_routes),
            vrf_import: None,
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

#[cfg(test)]
mod policy_apply_tests {
    use std::str::FromStr;

    use bgp_packet::{As4Path, BgpNexthop, Med, Origin};
    use ipnet::Ipv4Net;

    use super::*;
    use crate::policy::{AsPathMatcher, AsPathSet, NumericMatch, PolicyList};

    /// Test wrapper that preserves the legacy `Option<BgpAttr>`
    /// shape — weight defaults to 0, local_addr defaults to
    /// 0.0.0.0, and both are dropped from the result. Tests that
    /// need to assert on weight or `set next-hop self` call
    /// `super::policy_list_apply` directly with explicit
    /// arguments.
    fn policy_list_apply(list: &PolicyList, nlri: &Ipv4Nlri, attr: BgpAttr) -> Option<BgpAttr> {
        super::policy_list_apply(list, nlri, attr, 0, std::net::Ipv4Addr::UNSPECIFIED)
            .map(|d| d.attr)
    }

    fn nlri(prefix: &str) -> Ipv4Nlri {
        Ipv4Nlri {
            id: 0,
            prefix: Ipv4Net::from_str(prefix).unwrap(),
        }
    }

    fn attr_with(path: &str, med: Option<u32>, origin: Option<Origin>) -> BgpAttr {
        let mut attr = BgpAttr::new();
        attr.aspath = Some(As4Path::from_str(path).unwrap());
        attr.med = med.map(|m| Med { med: m });
        attr.origin = origin;
        attr
    }

    #[test]
    fn match_as_path_set() {
        let mut set = AsPathSet::default();
        set.vals
            .insert(AsPathMatcher::from_str("\\b65001\\b").unwrap());

        let mut list = PolicyList::default();
        let entry = list.entry(10);
        entry.as_path_set = Some(set);

        let attr_match = attr_with("65001 65002 65003", None, None);
        let attr_miss = attr_with("65010 65020", None, None);

        assert!(policy_list_apply(&list, &nlri("10.0.0.0/8"), attr_match).is_some());
        assert!(policy_list_apply(&list, &nlri("10.0.0.0/8"), attr_miss).is_none());
    }

    #[test]
    fn match_med_ge() {
        let mut list = PolicyList::default();
        list.entry(10).match_med = Some(NumericMatch::Ge(100));

        assert!(
            policy_list_apply(&list, &nlri("10.0.0.0/8"), attr_with("1", Some(150), None))
                .is_some()
        );
        assert!(
            policy_list_apply(&list, &nlri("10.0.0.0/8"), attr_with("1", Some(100), None))
                .is_some(),
            "ge accepts equality"
        );
        assert!(
            policy_list_apply(&list, &nlri("10.0.0.0/8"), attr_with("1", Some(50), None)).is_none()
        );
    }

    #[test]
    fn match_med_le() {
        let mut list = PolicyList::default();
        list.entry(10).match_med = Some(NumericMatch::Le(200));

        assert!(
            policy_list_apply(&list, &nlri("10.0.0.0/8"), attr_with("1", Some(150), None))
                .is_some()
        );
        assert!(
            policy_list_apply(&list, &nlri("10.0.0.0/8"), attr_with("1", Some(200), None))
                .is_some(),
            "le accepts equality"
        );
        assert!(
            policy_list_apply(&list, &nlri("10.0.0.0/8"), attr_with("1", Some(250), None))
                .is_none()
        );
    }

    #[test]
    fn match_med_eq() {
        let mut list = PolicyList::default();
        list.entry(10).match_med = Some(NumericMatch::Eq(100));

        assert!(
            policy_list_apply(&list, &nlri("10.0.0.0/8"), attr_with("1", Some(100), None))
                .is_some()
        );
        assert!(
            policy_list_apply(&list, &nlri("10.0.0.0/8"), attr_with("1", Some(101), None))
                .is_none()
        );
    }

    #[test]
    fn match_origin() {
        let mut list = PolicyList::default();
        let entry = list.entry(10);
        entry.match_origin = Some(Origin::Egp);

        assert!(
            policy_list_apply(
                &list,
                &nlri("10.0.0.0/8"),
                attr_with("1", None, Some(Origin::Egp))
            )
            .is_some()
        );
        assert!(
            policy_list_apply(
                &list,
                &nlri("10.0.0.0/8"),
                attr_with("1", None, Some(Origin::Igp))
            )
            .is_none()
        );
    }

    #[test]
    fn match_next_hop_exact() {
        let mut list = PolicyList::default();
        let entry = list.entry(10);
        entry.match_next_hop = Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 1, 1, 1)));

        let mut attr_match = attr_with("1", None, None);
        attr_match.nexthop = Some(BgpNexthop::Ipv4(std::net::Ipv4Addr::new(10, 1, 1, 1)));

        let mut attr_diff = attr_with("1", None, None);
        attr_diff.nexthop = Some(BgpNexthop::Ipv4(std::net::Ipv4Addr::new(10, 1, 1, 2)));

        let attr_none = attr_with("1", None, None);

        assert!(policy_list_apply(&list, &nlri("10.0.0.0/8"), attr_match).is_some());
        assert!(policy_list_apply(&list, &nlri("10.0.0.0/8"), attr_diff).is_none());
        assert!(
            policy_list_apply(&list, &nlri("10.0.0.0/8"), attr_none).is_none(),
            "absent nexthop should not match"
        );
    }

    #[test]
    fn match_next_hop_v6_never_matches_v4_attr() {
        // BgpAttr.nexthop is IPv4-only today. An IPv6 next-hop in
        // the entry is accepted by YANG/parse but never matches
        // the route. Locks that contract.
        let mut list = PolicyList::default();
        list.entry(10).match_next_hop = Some(std::net::IpAddr::V6("2001:db8::1".parse().unwrap()));

        let mut attr = attr_with("1", None, None);
        attr.nexthop = Some(BgpNexthop::Ipv4(std::net::Ipv4Addr::new(10, 1, 1, 1)));

        assert!(policy_list_apply(&list, &nlri("10.0.0.0/8"), attr).is_none());
    }

    #[test]
    fn multiple_match_clauses_all_required() {
        let mut set = AsPathSet::default();
        set.vals
            .insert(AsPathMatcher::from_str("^65001\\b").unwrap());

        let mut list = PolicyList::default();
        let entry = list.entry(10);
        entry.as_path_set = Some(set);
        entry.match_origin = Some(Origin::Igp);
        entry.match_med = Some(NumericMatch::Le(50));

        let pass = attr_with("65001 65002", Some(40), Some(Origin::Igp));
        let bad_origin = attr_with("65001 65002", Some(40), Some(Origin::Egp));
        let bad_med = attr_with("65001 65002", Some(60), Some(Origin::Igp));
        let bad_path = attr_with("65010 65002", Some(40), Some(Origin::Igp));

        assert!(policy_list_apply(&list, &nlri("10.0.0.0/8"), pass).is_some());
        assert!(policy_list_apply(&list, &nlri("10.0.0.0/8"), bad_origin).is_none());
        assert!(policy_list_apply(&list, &nlri("10.0.0.0/8"), bad_med).is_none());
        assert!(policy_list_apply(&list, &nlri("10.0.0.0/8"), bad_path).is_none());
    }

    #[test]
    fn match_as_path_len() {
        // `1 2 3 4 5` -> length 5.
        let mut list = PolicyList::default();
        list.entry(10).match_as_path_len = Some(NumericMatch::Eq(5));
        assert!(
            policy_list_apply(
                &list,
                &nlri("10.0.0.0/8"),
                attr_with("1 2 3 4 5", None, None)
            )
            .is_some()
        );
        assert!(
            policy_list_apply(&list, &nlri("10.0.0.0/8"), attr_with("1 2 3 4", None, None))
                .is_none()
        );

        let mut list = PolicyList::default();
        list.entry(10).match_as_path_len = Some(NumericMatch::Ge(3));
        assert!(
            policy_list_apply(&list, &nlri("10.0.0.0/8"), attr_with("1 2 3", None, None)).is_some()
        );
        assert!(
            policy_list_apply(&list, &nlri("10.0.0.0/8"), attr_with("1 2", None, None)).is_none()
        );
    }

    #[test]
    fn match_as_path_len_uniq() {
        // `1 2 1 2 1` -> length 5, unique 2.
        let mut list = PolicyList::default();
        list.entry(10).match_as_path_len_uniq = Some(NumericMatch::Eq(2));
        assert!(
            policy_list_apply(
                &list,
                &nlri("10.0.0.0/8"),
                attr_with("1 2 1 2 1", None, None)
            )
            .is_some()
        );
        // `1 2 3 4 5` -> length 5, unique 5: `eq 2` should miss.
        assert!(
            policy_list_apply(
                &list,
                &nlri("10.0.0.0/8"),
                attr_with("1 2 3 4 5", None, None)
            )
            .is_none()
        );

        let mut list = PolicyList::default();
        list.entry(10).match_as_path_len_uniq = Some(NumericMatch::Le(3));
        assert!(
            policy_list_apply(
                &list,
                &nlri("10.0.0.0/8"),
                attr_with("1 2 1 2 1", None, None)
            )
            .is_some()
        );
        assert!(
            policy_list_apply(
                &list,
                &nlri("10.0.0.0/8"),
                attr_with("1 2 3 4 5", None, None)
            )
            .is_none()
        );
    }

    #[test]
    fn match_local_preference() {
        use bgp_packet::LocalPref;
        let mut list = PolicyList::default();
        list.entry(10).match_local_pref = Some(NumericMatch::Ge(100));

        let mut attr_hi = attr_with("1", None, None);
        attr_hi.local_pref = Some(LocalPref::new(150));
        let mut attr_eq = attr_with("1", None, None);
        attr_eq.local_pref = Some(LocalPref::new(100));
        let mut attr_lo = attr_with("1", None, None);
        attr_lo.local_pref = Some(LocalPref::new(50));

        assert!(policy_list_apply(&list, &nlri("10.0.0.0/8"), attr_hi).is_some());
        assert!(
            policy_list_apply(&list, &nlri("10.0.0.0/8"), attr_eq).is_some(),
            "ge accepts equality"
        );
        assert!(policy_list_apply(&list, &nlri("10.0.0.0/8"), attr_lo).is_none());
    }

    #[test]
    fn match_weight_default_zero() {
        // The test wrapper passes weight=0; verify default-zero
        // semantics — `eq 0` matches, `ge 1` does not.
        let mut list = PolicyList::default();
        list.entry(10).match_weight = Some(NumericMatch::Eq(0));
        assert!(
            policy_list_apply(&list, &nlri("10.0.0.0/8"), attr_with("1", None, None)).is_some()
        );

        let mut list = PolicyList::default();
        list.entry(10).match_weight = Some(NumericMatch::Ge(1));
        assert!(
            policy_list_apply(&list, &nlri("10.0.0.0/8"), attr_with("1", None, None)).is_none()
        );
    }

    #[test]
    fn match_weight_with_incoming_weight() {
        // When the caller passes a non-zero weight, the matcher
        // must read that value, not 0.
        let mut list = PolicyList::default();
        list.entry(10).match_weight = Some(NumericMatch::Eq(500));
        let attr = attr_with("1", None, None);
        let local = std::net::Ipv4Addr::UNSPECIFIED;
        let d = super::policy_list_apply(&list, &nlri("10.0.0.0/8"), attr.clone(), 500, local);
        assert!(d.is_some(), "weight=500 should match Eq(500)");
        let d = super::policy_list_apply(&list, &nlri("10.0.0.0/8"), attr, 0, local);
        assert!(d.is_none(), "weight=0 should not match Eq(500)");
    }

    #[test]
    fn set_next_hop_self_uses_local_addr() {
        // `set next-hop self` resolves at apply time to the
        // `local_addr` argument passed to `policy_list_apply`.
        let mut list = PolicyList::default();
        list.entry(10).set_next_hop = Some(crate::policy::SetNextHop::SelfAddr);

        let local = std::net::Ipv4Addr::new(192, 0, 2, 7);
        let attr = attr_with("1", None, None);
        let d =
            super::policy_list_apply(&list, &nlri("10.0.0.0/8"), attr, 0, local).expect("permit");
        match d.attr.nexthop.expect("nexthop set") {
            BgpNexthop::Ipv4(a) => assert_eq!(a, local),
            other => panic!("expected Ipv4 nexthop, got {:?}", other),
        }
    }

    #[test]
    fn set_next_hop_v4_address() {
        let mut list = PolicyList::default();
        list.entry(10).set_next_hop = Some(crate::policy::SetNextHop::Address(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 1, 1, 1)),
        ));
        let attr = attr_with("1", None, None);
        let out = policy_list_apply(&list, &nlri("10.0.0.0/8"), attr).expect("permit");
        match out.nexthop.expect("nexthop set") {
            BgpNexthop::Ipv4(a) => assert_eq!(a, std::net::Ipv4Addr::new(10, 1, 1, 1)),
            other => panic!("expected Ipv4 nexthop, got {:?}", other),
        }
    }

    #[test]
    fn set_next_hop_v6_is_inert_today() {
        // BgpNexthop is IPv4-only. An IPv6 target on the entry
        // parses cleanly but does not modify the route's nexthop
        // — locked in until BgpNexthop::Ipv6 is plumbed.
        let mut list = PolicyList::default();
        list.entry(10).set_next_hop = Some(crate::policy::SetNextHop::Address(
            std::net::IpAddr::V6("2001:db8::1".parse().unwrap()),
        ));
        let mut attr = attr_with("1", None, None);
        attr.nexthop = Some(BgpNexthop::Ipv4(std::net::Ipv4Addr::new(192, 0, 2, 1)));
        let out = policy_list_apply(&list, &nlri("10.0.0.0/8"), attr).expect("permit");
        match out.nexthop.expect("untouched") {
            BgpNexthop::Ipv4(a) => assert_eq!(a, std::net::Ipv4Addr::new(192, 0, 2, 1)),
            other => panic!("expected Ipv4 nexthop, got {:?}", other),
        }
    }

    #[test]
    fn set_origin_overrides_incoming() {
        let mut list = PolicyList::default();
        list.entry(10).set_origin = Some(Origin::Egp);

        let attr = attr_with("1", None, Some(Origin::Igp));
        let out = policy_list_apply(&list, &nlri("10.0.0.0/8"), attr).expect("permit");
        assert_eq!(out.origin, Some(Origin::Egp));
    }

    #[test]
    fn set_origin_on_absent() {
        // Originating an ORIGIN attribute on a route that didn't
        // carry one previously.
        let mut list = PolicyList::default();
        list.entry(10).set_origin = Some(Origin::Incomplete);

        let attr = attr_with("1", None, None);
        let out = policy_list_apply(&list, &nlri("10.0.0.0/8"), attr).expect("permit");
        assert_eq!(out.origin, Some(Origin::Incomplete));
    }

    #[test]
    fn set_weight_overrides_incoming() {
        // `set weight 999` makes the decision carry that value
        // regardless of the incoming weight.
        let mut list = PolicyList::default();
        list.entry(10).weight = Some(999);
        let d = super::policy_list_apply(
            &list,
            &nlri("10.0.0.0/8"),
            attr_with("1", None, None),
            7,
            std::net::Ipv4Addr::UNSPECIFIED,
        )
        .expect("permit");
        assert_eq!(d.weight, 999);
    }

    #[test]
    fn match_color_present_in_ext_communities_permits() {
        let mut list = PolicyList::default();
        list.entry(10).match_color = Some(100);

        let mut attr = attr_with("1", None, None);
        attr.ecom = Some(ExtCommunity(vec![ExtCommunityValue::from_color(0, 100)]));
        assert!(policy_list_apply(&list, &nlri("10.0.0.0/8"), attr).is_some());
    }

    #[test]
    fn match_color_wrong_value_denies() {
        let mut list = PolicyList::default();
        list.entry(10).match_color = Some(100);

        let mut attr = attr_with("1", None, None);
        attr.ecom = Some(ExtCommunity(vec![ExtCommunityValue::from_color(0, 200)]));
        assert!(policy_list_apply(&list, &nlri("10.0.0.0/8"), attr).is_none());
    }

    #[test]
    fn match_color_absent_ext_communities_denies() {
        // Predicate is set but the route has no EXT_COMMUNITIES at
        // all — must not match.
        let mut list = PolicyList::default();
        list.entry(10).match_color = Some(100);
        let attr = attr_with("1", None, None);
        assert!(policy_list_apply(&list, &nlri("10.0.0.0/8"), attr).is_none());
    }

    #[test]
    fn match_color_picks_one_from_many() {
        // Route carries two color extcomms (100 and 200); the
        // predicate for 200 must succeed.
        let mut list = PolicyList::default();
        list.entry(10).match_color = Some(200);
        let mut attr = attr_with("1", None, None);
        attr.ecom = Some(ExtCommunity(vec![
            ExtCommunityValue::from_color(0, 100),
            ExtCommunityValue::from_color(0, 200),
        ]));
        assert!(policy_list_apply(&list, &nlri("10.0.0.0/8"), attr).is_some());
    }

    #[test]
    fn set_color_appends_color_ext_community() {
        let mut list = PolicyList::default();
        list.entry(10).set_color = Some(128);

        let attr = attr_with("1", None, None);
        let out = policy_list_apply(&list, &nlri("10.0.0.0/8"), attr).expect("permit");
        let ecom = out.ecom.expect("ecom appended");
        assert_eq!(ecom.0.len(), 1);
        let c = ecom.0[0].as_color().expect("Color extcomm");
        assert_eq!(c.color, 128);
        assert_eq!(c.co_bits(), 0);
    }

    #[test]
    fn set_color_merges_with_existing_ext_communities() {
        let mut list = PolicyList::default();
        list.entry(10).set_color = Some(128);

        let mut attr = attr_with("1", None, None);
        attr.ecom = Some(ExtCommunity::from_str("rt:65001:100").unwrap());
        let out = policy_list_apply(&list, &nlri("10.0.0.0/8"), attr).expect("permit");
        let ecom = out.ecom.expect("ecom retained");
        assert_eq!(ecom.0.len(), 2, "RT + Color");
        assert!(ecom.0.iter().any(|v| v.as_color().is_some()));
    }

    #[test]
    fn set_prefix_sid_label_index_installs_attr_40() {
        let mut list = PolicyList::default();
        list.entry(10).set_prefix_sid_label_index = Some(128);
        let attr = attr_with("1", None, None);
        let out = policy_list_apply(&list, &nlri("10.0.0.0/8"), attr).expect("permit");
        let sid = out.prefix_sid.expect("prefix_sid set");
        assert_eq!(sid.tlvs.len(), 1);
        match &sid.tlvs[0] {
            bgp_packet::PrefixSidTlv::LabelIndex { flags, label_index } => {
                assert_eq!(*flags, 0);
                assert_eq!(*label_index, 128);
            }
            other => panic!("expected LabelIndex TLV, got {:?}", other),
        }
    }

    #[test]
    fn set_prefix_sid_label_index_overwrites_existing_attr() {
        // Operator-set label-index is authoritative — any existing
        // Originator-SRGB or SRv6 service TLVs are dropped to match
        // the documented "route-map is authoritative" semantics.
        let mut list = PolicyList::default();
        list.entry(10).set_prefix_sid_label_index = Some(42);
        let mut attr = attr_with("1", None, None);
        attr.prefix_sid = Some(bgp_packet::PrefixSid {
            tlvs: vec![bgp_packet::PrefixSidTlv::OriginatorSrgb {
                flags: 0,
                srgbs: vec![bgp_packet::SrgbRange {
                    base: 16000,
                    range: 8000,
                }],
            }],
        });
        let out = policy_list_apply(&list, &nlri("10.0.0.0/8"), attr).expect("permit");
        let sid = out.prefix_sid.expect("prefix_sid set");
        assert_eq!(sid.tlvs.len(), 1, "SRGB dropped, only LabelIndex remains");
        assert!(matches!(
            sid.tlvs[0],
            bgp_packet::PrefixSidTlv::LabelIndex {
                label_index: 42,
                ..
            }
        ));
    }

    #[test]
    fn match_ext_community_exact() {
        use bgp_packet::ExtCommunity;
        use std::collections::BTreeSet;
        let mut set = crate::policy::ExtCommunitySet::default();
        set.vals.insert(
            crate::policy::ExtCommunityMatcher::from_str("rt:65001:100")
                .expect("parses rt:65001:100"),
        );
        let _: &BTreeSet<_> = &set.vals; // type sanity

        let mut list = PolicyList::default();
        list.entry(10).ext_community_set = Some(set);

        let mut attr_match = attr_with("1", None, None);
        attr_match.ecom = Some(ExtCommunity::from_str("rt:65001:100").unwrap());
        let mut attr_miss = attr_with("1", None, None);
        attr_miss.ecom = Some(ExtCommunity::from_str("rt:65001:200").unwrap());

        assert!(policy_list_apply(&list, &nlri("10.0.0.0/8"), attr_match).is_some());
        assert!(policy_list_apply(&list, &nlri("10.0.0.0/8"), attr_miss).is_none());
        // Absent ecom => no match
        assert!(
            policy_list_apply(&list, &nlri("10.0.0.0/8"), attr_with("1", None, None)).is_none()
        );
    }

    #[test]
    fn match_ext_community_regex() {
        use bgp_packet::ExtCommunity;
        let mut set = crate::policy::ExtCommunitySet::default();
        set.vals
            .insert(crate::policy::ExtCommunityMatcher::from_str("rt:^65001:.*").unwrap());

        let mut list = PolicyList::default();
        list.entry(10).ext_community_set = Some(set);

        let mut attr_match = attr_with("1", None, None);
        attr_match.ecom = Some(ExtCommunity::from_str("rt:65001:100 rt:65002:200").unwrap());
        let mut attr_miss = attr_with("1", None, None);
        attr_miss.ecom = Some(ExtCommunity::from_str("rt:65003:100").unwrap());

        assert!(policy_list_apply(&list, &nlri("10.0.0.0/8"), attr_match).is_some());
        assert!(policy_list_apply(&list, &nlri("10.0.0.0/8"), attr_miss).is_none());
    }

    #[test]
    fn match_large_community_exact_and_regex() {
        use bgp_packet::LargeCommunity;
        let mut set = crate::policy::LargeCommunitySet::default();
        set.vals
            .insert(crate::policy::LargeCommunityMatcher::from_str("65001:100:200").unwrap());

        let mut list = PolicyList::default();
        list.entry(10).large_community_set = Some(set);

        let mut attr_match = attr_with("1", None, None);
        attr_match.lcom = Some(LargeCommunity::from_str("65001:100:200 65002:300:400").unwrap());
        let mut attr_miss = attr_with("1", None, None);
        attr_miss.lcom = Some(LargeCommunity::from_str("65001:100:201").unwrap());

        assert!(policy_list_apply(&list, &nlri("10.0.0.0/8"), attr_match).is_some());
        assert!(policy_list_apply(&list, &nlri("10.0.0.0/8"), attr_miss).is_none());

        // Regex variant
        let mut set = crate::policy::LargeCommunitySet::default();
        set.vals
            .insert(crate::policy::LargeCommunityMatcher::from_str("^65001:.*:.*$").unwrap());
        let mut list = PolicyList::default();
        list.entry(10).large_community_set = Some(set);

        let mut attr_regex = attr_with("1", None, None);
        attr_regex.lcom = Some(LargeCommunity::from_str("65001:9:9").unwrap());
        assert!(policy_list_apply(&list, &nlri("10.0.0.0/8"), attr_regex).is_some());
    }

    fn evpn_mac(vni: u32) -> EvpnRoute {
        EvpnRoute::Mac(EvpnMac {
            id: 0,
            rd: RouteDistinguisher::new(RouteDistinguisherType::IP),
            esi: [0; 10],
            ether_tag: 0,
            mac: [0x02, 0, 0, 0, 0, 1],
            vni,
        })
    }

    fn evpn_multicast() -> EvpnRoute {
        EvpnRoute::Multicast(EvpnMulticast {
            id: 0,
            rd: RouteDistinguisher::new(RouteDistinguisherType::IP),
            ether_tag: 0,
            addr: std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        })
    }

    /// `attr_with(...)` augmented with a Route Target extended
    /// community carrying the supplied VNI. Mirrors how an EVPN
    /// Type-3 peer advertises VNI per RFC 8365 §5.1.2.4.
    fn attr_with_rt_vni(asn: u32, vni: u32) -> BgpAttr {
        let mut attr = attr_with("1", None, None);
        attr.ecom = Some(ExtCommunity(vec![evpn_route_target(asn, vni)]));
        attr
    }

    fn evpn_apply(list: &PolicyList, route: &EvpnRoute, attr: BgpAttr) -> Option<BgpAttr> {
        super::policy_list_apply_evpn(list, route, attr, 0, Ipv4Addr::UNSPECIFIED).map(|d| d.attr)
    }

    #[test]
    fn match_evpn_route_type_macip_matches_mac() {
        use crate::policy::EvpnRouteType;
        let mut list = PolicyList::default();
        list.entry(10).match_evpn_route_type = Some(EvpnRouteType::MacIp);

        assert!(evpn_apply(&list, &evpn_mac(100), attr_with("1", None, None)).is_some());
        assert!(evpn_apply(&list, &evpn_multicast(), attr_with("1", None, None)).is_none());
    }

    #[test]
    fn match_evpn_route_type_multicast_matches_multicast() {
        use crate::policy::EvpnRouteType;
        let mut list = PolicyList::default();
        list.entry(10).match_evpn_route_type = Some(EvpnRouteType::Multicast);

        assert!(evpn_apply(&list, &evpn_multicast(), attr_with("1", None, None)).is_some());
        assert!(evpn_apply(&list, &evpn_mac(100), attr_with("1", None, None)).is_none());
    }

    #[test]
    fn match_evpn_route_type_unmatched_yields_default_deny() {
        use crate::policy::EvpnRouteType;
        // Looking for Ead — the parser never produces this variant
        // today, so no `EvpnRoute` will satisfy it. Default-deny
        // applies when the only entry fails to match.
        let mut list = PolicyList::default();
        list.entry(10).match_evpn_route_type = Some(EvpnRouteType::Ead);

        assert!(evpn_apply(&list, &evpn_mac(100), attr_with("1", None, None)).is_none());
        assert!(evpn_apply(&list, &evpn_multicast(), attr_with("1", None, None)).is_none());
    }

    #[test]
    fn match_evpn_vni_type2_uses_nlri_vni() {
        let mut list = PolicyList::default();
        list.entry(10).match_evpn_vni = Some(100);

        // Type-2 carries VNI in the NLRI; the RT-EC is irrelevant.
        assert!(evpn_apply(&list, &evpn_mac(100), attr_with("1", None, None)).is_some());
        assert!(evpn_apply(&list, &evpn_mac(200), attr_with("1", None, None)).is_none());
        // VNI=0 means "absent" per evpn_vni_of — should not match.
        assert!(evpn_apply(&list, &evpn_mac(0), attr_with("1", None, None)).is_none());
    }

    #[test]
    fn match_evpn_vni_type3_uses_rt_ec_vni() {
        let mut list = PolicyList::default();
        list.entry(10).match_evpn_vni = Some(550);

        // Type-3 has no NLRI VNI; VNI comes from the RT extended
        // community per RFC 8365 §5.1.2.4.
        let attr_match = attr_with_rt_vni(65501, 550);
        let attr_miss = attr_with_rt_vni(65501, 551);
        let attr_no_rt = attr_with("1", None, None);

        assert!(evpn_apply(&list, &evpn_multicast(), attr_match).is_some());
        assert!(evpn_apply(&list, &evpn_multicast(), attr_miss).is_none());
        assert!(
            evpn_apply(&list, &evpn_multicast(), attr_no_rt).is_none(),
            "absent RT-EC yields no VNI, so the match fails"
        );
    }

    #[test]
    fn match_evpn_route_type_and_vni_compose() {
        use crate::policy::EvpnRouteType;
        let mut list = PolicyList::default();
        let entry = list.entry(10);
        entry.match_evpn_route_type = Some(EvpnRouteType::MacIp);
        entry.match_evpn_vni = Some(100);

        // Both conditions must hold (AND-semantics, same as the
        // rest of `entry_matches_evpn`).
        assert!(evpn_apply(&list, &evpn_mac(100), attr_with("1", None, None)).is_some());
        assert!(
            evpn_apply(&list, &evpn_mac(200), attr_with("1", None, None)).is_none(),
            "route-type matches but VNI differs"
        );
        assert!(
            evpn_apply(&list, &evpn_multicast(), attr_with_rt_vni(65501, 100)).is_none(),
            "VNI matches but route-type differs"
        );
    }
}

#[cfg(test)]
mod color_aware_nht_tests {
    use std::net::Ipv4Addr;

    use bgp_packet::{BgpAttr, ExtCommunity, ExtCommunityValue};
    use ipnet::Ipv4Net;
    use prefix_trie::PrefixMap;

    use super::resolve_flex_algo_label_inner;
    use crate::bgp::color_policy::ColorPolicy;
    use crate::rib::api::FlexAlgoNexthop;

    fn attr_with_colors(colors: &[u32]) -> BgpAttr {
        let entries: Vec<ExtCommunityValue> = colors
            .iter()
            .map(|c| ExtCommunityValue::from_color(0, *c))
            .collect();
        BgpAttr {
            ecom: Some(ExtCommunity(entries)),
            ..Default::default()
        }
    }

    fn shadow_with(
        algo: u8,
        prefix: &str,
        label: u32,
    ) -> std::collections::BTreeMap<u8, PrefixMap<Ipv4Net, FlexAlgoNexthop>> {
        let mut table = PrefixMap::new();
        table.insert(
            prefix.parse().unwrap(),
            FlexAlgoNexthop {
                addr: Ipv4Addr::new(10, 0, 0, 1),
                ifindex: 1,
                label,
            },
        );
        let mut map = std::collections::BTreeMap::new();
        map.insert(algo, table);
        map
    }

    #[test]
    fn no_color_returns_none() {
        let cp = ColorPolicy::new();
        let shadow = std::collections::BTreeMap::new();
        let attr = BgpAttr::default();
        assert!(
            resolve_flex_algo_label_inner(&cp, &shadow, &attr, "10.0.0.5".parse().unwrap())
                .is_none()
        );
    }

    #[test]
    fn unbound_color_returns_none() {
        let cp = ColorPolicy::new();
        let shadow = std::collections::BTreeMap::new();
        let attr = attr_with_colors(&[100]);
        assert!(
            resolve_flex_algo_label_inner(&cp, &shadow, &attr, "10.0.0.5".parse().unwrap())
                .is_none()
        );
    }

    #[test]
    fn bound_color_with_matching_route_returns_label() {
        let mut cp = ColorPolicy::new();
        cp.bindings.insert(100, 128);
        let shadow = shadow_with(128, "10.0.0.0/24", 17128);
        let attr = attr_with_colors(&[100]);
        assert_eq!(
            resolve_flex_algo_label_inner(&cp, &shadow, &attr, "10.0.0.5".parse().unwrap()),
            Some(17128)
        );
    }

    #[test]
    fn bound_color_without_route_falls_through() {
        // Algo 128 is bound but the shadow has no covering route for
        // the next-hop. Should return None (strict, no fallback yet).
        let mut cp = ColorPolicy::new();
        cp.bindings.insert(100, 128);
        let shadow = shadow_with(128, "192.0.2.0/24", 17128);
        let attr = attr_with_colors(&[100]);
        assert!(
            resolve_flex_algo_label_inner(&cp, &shadow, &attr, "10.0.0.5".parse().unwrap())
                .is_none()
        );
    }

    #[test]
    fn unbound_color_then_bound_color_resolves_bound_one() {
        // First Color (200) is unbound; second (100) is bound and has
        // a route — the second one must win, not abort on the first.
        let mut cp = ColorPolicy::new();
        cp.bindings.insert(100, 128);
        let shadow = shadow_with(128, "10.0.0.0/24", 17128);
        let attr = attr_with_colors(&[200, 100]);
        assert_eq!(
            resolve_flex_algo_label_inner(&cp, &shadow, &attr, "10.0.0.5".parse().unwrap()),
            Some(17128)
        );
    }

    #[test]
    fn first_bound_color_wins() {
        // Two bound colours, both with covering routes — attribute
        // order decides (no preference/fallback semantics yet).
        let mut cp = ColorPolicy::new();
        cp.bindings.insert(100, 128);
        cp.bindings.insert(200, 129);
        let mut shadow = shadow_with(128, "10.0.0.0/24", 17128);
        let mut algo_129 = PrefixMap::new();
        algo_129.insert(
            "10.0.0.0/24".parse().unwrap(),
            FlexAlgoNexthop {
                addr: Ipv4Addr::new(10, 0, 0, 1),
                ifindex: 1,
                label: 17129,
            },
        );
        shadow.insert(129, algo_129);
        let attr = attr_with_colors(&[100, 200]);
        assert_eq!(
            resolve_flex_algo_label_inner(&cp, &shadow, &attr, "10.0.0.5".parse().unwrap()),
            Some(17128)
        );
    }

    #[test]
    fn lpm_picks_longest_covering_prefix() {
        // Both /24 and /16 cover 10.0.0.5; resolver picks /24's label.
        let mut cp = ColorPolicy::new();
        cp.bindings.insert(100, 128);
        let mut table = PrefixMap::new();
        table.insert(
            "10.0.0.0/24".parse().unwrap(),
            FlexAlgoNexthop {
                addr: Ipv4Addr::new(10, 0, 0, 1),
                ifindex: 1,
                label: 17128,
            },
        );
        table.insert(
            "10.0.0.0/16".parse().unwrap(),
            FlexAlgoNexthop {
                addr: Ipv4Addr::new(10, 0, 0, 1),
                ifindex: 1,
                label: 99999,
            },
        );
        let mut shadow = std::collections::BTreeMap::new();
        shadow.insert(128, table);
        let attr = attr_with_colors(&[100]);
        assert_eq!(
            resolve_flex_algo_label_inner(&cp, &shadow, &attr, "10.0.0.5".parse().unwrap()),
            Some(17128)
        );
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use std::net::{IpAddr, Ipv4Addr};

    use bgp_packet::{
        As4Path, BgpAttr, BgpNexthop, Community, CommunityValue, Ipv4Nlri, LocalPref,
    };
    use ipnet::Ipv4Net;

    use crate::policy::prefix::set::PrefixSetEntry;
    use crate::policy::{
        AsPathPrependConfig, CommunityMatcher, CommunitySet, NumericSet, PolicyList, PrefixSet,
        SetCommunityConfig, SetCommunityMode, SetNextHop,
    };

    /// Test wrapper that preserves the legacy `Option<BgpAttr>`
    /// shape; weight defaults to 0, local_addr to 0.0.0.0.
    /// Weight-aware / next-hop-self tests call
    /// `super::policy_list_apply` directly.
    fn policy_list_apply(list: &PolicyList, nlri: &Ipv4Nlri, attr: BgpAttr) -> Option<BgpAttr> {
        super::policy_list_apply(list, nlri, attr, 0, std::net::Ipv4Addr::UNSPECIFIED)
            .map(|d| d.attr)
    }

    fn set_community_cfg(members: &[&str], mode: SetCommunityMode) -> SetCommunityConfig {
        SetCommunityConfig {
            name: "test".into(),
            mode,
            resolved: Some(community_set(members)),
        }
    }

    fn nlri(s: &str) -> Ipv4Nlri {
        Ipv4Nlri {
            id: 0,
            prefix: Ipv4Net::from_str(s).unwrap(),
        }
    }

    fn community_set(members: &[&str]) -> CommunitySet {
        let mut set = CommunitySet::default();
        for m in members {
            set.vals
                .insert(CommunityMatcher::from_str(m).unwrap_or_else(|_| panic!("parse {m}")));
        }
        set
    }

    fn com_val(s: &str) -> u32 {
        CommunityValue::from_readable_str(s)
            .unwrap_or_else(|| panic!("parse {s}"))
            .0
    }

    #[test]
    fn policy_list_apply_sets_local_pref() {
        let mut list = PolicyList::default();
        list.entry(10).local_pref = Some(NumericSet::Set(250));

        let out = policy_list_apply(&list, &nlri("10.0.0.0/24"), BgpAttr::default())
            .expect("entry with no match clause should apply");
        assert_eq!(out.local_pref.expect("local_pref applied").local_pref, 250);
    }

    #[test]
    fn policy_list_apply_sets_local_pref_and_med() {
        let mut list = PolicyList::default();
        let entry = list.entry(10);
        entry.local_pref = Some(NumericSet::Set(150));
        entry.med = Some(NumericSet::Set(42));

        let out = policy_list_apply(&list, &nlri("10.0.0.0/24"), BgpAttr::default()).unwrap();
        assert_eq!(out.local_pref.unwrap().local_pref, 150);
        assert_eq!(out.med.unwrap().med, 42);
    }

    #[test]
    fn policy_list_apply_local_pref_overrides_existing() {
        let mut list = PolicyList::default();
        list.entry(10).local_pref = Some(NumericSet::Set(200));

        let attr = BgpAttr {
            local_pref: Some(LocalPref::new(100)),
            ..Default::default()
        };

        let out = policy_list_apply(&list, &nlri("10.0.0.0/24"), attr).unwrap();
        assert_eq!(out.local_pref.unwrap().local_pref, 200);
    }

    #[test]
    fn policy_list_apply_local_pref_add_to_existing() {
        let mut list = PolicyList::default();
        list.entry(10).local_pref = Some(NumericSet::Add(50));

        let attr = BgpAttr {
            local_pref: Some(LocalPref::new(100)),
            ..Default::default()
        };
        let out = policy_list_apply(&list, &nlri("10.0.0.0/24"), attr).unwrap();
        assert_eq!(out.local_pref.unwrap().local_pref, 150);
    }

    #[test]
    fn policy_list_apply_local_pref_add_to_absent_treats_as_zero() {
        let mut list = PolicyList::default();
        list.entry(10).local_pref = Some(NumericSet::Add(75));

        let out = policy_list_apply(&list, &nlri("10.0.0.0/24"), BgpAttr::default()).unwrap();
        assert_eq!(out.local_pref.unwrap().local_pref, 75);
    }

    #[test]
    fn policy_list_apply_local_pref_sub_saturates_at_zero() {
        let mut list = PolicyList::default();
        list.entry(10).local_pref = Some(NumericSet::Sub(200));

        let attr = BgpAttr {
            local_pref: Some(LocalPref::new(100)),
            ..Default::default()
        };
        let out = policy_list_apply(&list, &nlri("10.0.0.0/24"), attr).unwrap();
        assert_eq!(
            out.local_pref.unwrap().local_pref,
            0,
            "underflow saturates at 0"
        );
    }

    #[test]
    fn policy_list_apply_med_add_saturates_at_max() {
        let mut list = PolicyList::default();
        list.entry(10).med = Some(NumericSet::Add(10));

        let attr = BgpAttr {
            med: Some(bgp_packet::Med { med: u32::MAX - 5 }),
            ..Default::default()
        };
        let out = policy_list_apply(&list, &nlri("10.0.0.0/24"), attr).unwrap();
        assert_eq!(
            out.med.unwrap().med,
            u32::MAX,
            "overflow saturates at u32::MAX"
        );
    }

    #[test]
    fn policy_list_apply_med_sub_clamps_to_zero() {
        let mut list = PolicyList::default();
        list.entry(10).med = Some(NumericSet::Sub(100));

        let attr = BgpAttr {
            med: Some(bgp_packet::Med { med: 30 }),
            ..Default::default()
        };
        let out = policy_list_apply(&list, &nlri("10.0.0.0/24"), attr).unwrap();
        assert_eq!(out.med.unwrap().med, 0);
    }

    #[test]
    fn policy_list_apply_community_replace() {
        let mut list = PolicyList::default();
        let entry = list.entry(10);
        entry.set_community = Some(set_community_cfg(
            &["100:200", "no-export"],
            SetCommunityMode::Replace,
        ));

        // Existing community 999:999 must be wiped on replace.
        let attr = BgpAttr {
            com: Some(Community(vec![com_val("999:999")])),
            ..Default::default()
        };

        let out = policy_list_apply(&list, &nlri("10.0.0.0/24"), attr).unwrap();
        let com = out.com.expect("community attribute set");
        assert!(com.contains(&com_val("100:200")));
        assert!(com.contains(&CommunityValue::NO_EXPORT.value()));
        assert!(!com.contains(&com_val("999:999")));
        assert_eq!(com.0.len(), 2);
    }

    #[test]
    fn policy_list_apply_community_additive() {
        let mut list = PolicyList::default();
        let entry = list.entry(10);
        entry.set_community = Some(set_community_cfg(&["100:200"], SetCommunityMode::Additive));

        let attr = BgpAttr {
            com: Some(Community(vec![com_val("999:999")])),
            ..Default::default()
        };

        let out = policy_list_apply(&list, &nlri("10.0.0.0/24"), attr).unwrap();
        let com = out.com.expect("community attribute set");
        assert!(com.contains(&com_val("100:200")));
        assert!(com.contains(&com_val("999:999")));
        assert_eq!(com.0.len(), 2);
    }

    #[test]
    fn policy_list_apply_community_additive_dedups() {
        let mut list = PolicyList::default();
        let entry = list.entry(10);
        entry.set_community = Some(set_community_cfg(&["100:200"], SetCommunityMode::Additive));

        // 100:200 already present — additive should not duplicate.
        let attr = BgpAttr {
            com: Some(Community(vec![com_val("100:200")])),
            ..Default::default()
        };

        let out = policy_list_apply(&list, &nlri("10.0.0.0/24"), attr).unwrap();
        let com = out.com.expect("community attribute set");
        assert_eq!(com.0, vec![com_val("100:200")]);
    }

    #[test]
    fn policy_list_apply_community_replace_skips_regex() {
        let mut list = PolicyList::default();
        let entry = list.entry(10);
        // Mix concrete + regex; only 100:200 is materializable.
        entry.set_community = Some(set_community_cfg(
            &["100:200", "^65000:.*"],
            SetCommunityMode::Replace,
        ));

        let out = policy_list_apply(&list, &nlri("10.0.0.0/24"), BgpAttr::default()).unwrap();
        let com = out.com.expect("community attribute set");
        assert_eq!(com.0, vec![com_val("100:200")]);
    }

    #[test]
    fn policy_list_apply_community_delete_removes_matching() {
        let mut list = PolicyList::default();
        let entry = list.entry(10);
        entry.set_community = Some(set_community_cfg(
            &["100:200", "no-export"],
            SetCommunityMode::Delete,
        ));

        // Existing has both targets and a non-target — only the
        // targets are removed; non-target survives.
        let attr = BgpAttr {
            com: Some(Community(vec![
                com_val("100:200"),
                com_val("999:999"),
                CommunityValue::NO_EXPORT.value(),
            ])),
            ..Default::default()
        };

        let out = policy_list_apply(&list, &nlri("10.0.0.0/24"), attr).unwrap();
        let com = out.com.expect("community attribute survives");
        assert_eq!(com.0, vec![com_val("999:999")]);
    }

    #[test]
    fn policy_list_apply_community_delete_drops_attr_when_empty() {
        let mut list = PolicyList::default();
        let entry = list.entry(10);
        entry.set_community = Some(set_community_cfg(&["100:200"], SetCommunityMode::Delete));

        // Single value matches the deletion → attribute should be
        // None rather than an empty Community vec.
        let attr = BgpAttr {
            com: Some(Community(vec![com_val("100:200")])),
            ..Default::default()
        };

        let out = policy_list_apply(&list, &nlri("10.0.0.0/24"), attr).unwrap();
        assert!(out.com.is_none());
    }

    #[test]
    fn policy_list_apply_as_path_prepend_onto_empty() {
        let mut list = PolicyList::default();
        list.entry(10).set_as_path_prepend = Some(AsPathPrependConfig {
            asn: 65001,
            repeat: 2,
        });

        let out = policy_list_apply(&list, &nlri("10.0.0.0/24"), BgpAttr::default()).unwrap();
        let path = out.aspath.expect("aspath set");
        assert_eq!(path.length(), 2);
        assert_eq!(path.as_path_display(), "65001 65001");
    }

    #[test]
    fn policy_list_apply_as_path_prepend_onto_existing() {
        let mut list = PolicyList::default();
        list.entry(10).set_as_path_prepend = Some(AsPathPrependConfig::new(65001));

        // Existing path: 100 200 (origin AS at the right).
        let attr = BgpAttr {
            aspath: Some(As4Path::from(vec![100, 200])),
            ..Default::default()
        };

        let out = policy_list_apply(&list, &nlri("10.0.0.0/24"), attr).unwrap();
        let path = out.aspath.expect("aspath set");
        assert_eq!(path.as_path_display(), "65001 100 200");
        assert_eq!(path.length(), 3);
    }

    #[test]
    fn policy_list_apply_as_path_prepend_repeat_three_onto_existing() {
        let mut list = PolicyList::default();
        list.entry(10).set_as_path_prepend = Some(AsPathPrependConfig {
            asn: 65001,
            repeat: 3,
        });

        let attr = BgpAttr {
            aspath: Some(As4Path::from(vec![100])),
            ..Default::default()
        };

        let out = policy_list_apply(&list, &nlri("10.0.0.0/24"), attr).unwrap();
        let path = out.aspath.expect("aspath set");
        assert_eq!(path.as_path_display(), "65001 65001 65001 100");
        assert_eq!(path.length(), 4);
    }

    #[test]
    fn policy_list_apply_sets_next_hop() {
        let mut list = PolicyList::default();
        list.entry(10).set_next_hop =
            Some(SetNextHop::Address(IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1))));

        let out = policy_list_apply(&list, &nlri("10.0.0.0/24"), BgpAttr::default()).unwrap();
        match out.nexthop.expect("nexthop set") {
            BgpNexthop::Ipv4(a) => assert_eq!(a, Ipv4Addr::new(10, 1, 1, 1)),
            other => panic!("expected Ipv4 nexthop, got {:?}", other),
        }
    }

    #[test]
    fn policy_list_apply_next_hop_overrides_existing() {
        let mut list = PolicyList::default();
        list.entry(10).set_next_hop =
            Some(SetNextHop::Address(IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1))));

        let attr = BgpAttr {
            nexthop: Some(BgpNexthop::Ipv4(Ipv4Addr::new(192, 0, 2, 1))),
            ..Default::default()
        };

        let out = policy_list_apply(&list, &nlri("10.0.0.0/24"), attr).unwrap();
        match out.nexthop.unwrap() {
            BgpNexthop::Ipv4(a) => assert_eq!(a, Ipv4Addr::new(10, 1, 1, 1)),
            other => panic!("expected Ipv4 nexthop, got {:?}", other),
        }
    }

    // ── Phase A: control-flow semantics for permit / next / deny ──

    #[test]
    fn policy_action_deny_drops_route_and_skips_set() {
        let mut list = PolicyList::default();
        let entry = list.entry(10);
        entry.local_pref = Some(NumericSet::Set(999));
        entry.action = crate::policy::PolicyAction::Deny;

        // Match clause empty → entry matches every route.
        let out = policy_list_apply(&list, &nlri("10.0.0.0/24"), BgpAttr::default());
        assert!(out.is_none(), "deny must drop the route");
    }

    #[test]
    fn policy_action_next_applies_set_and_falls_through() {
        let mut list = PolicyList::default();
        list.entry(10).local_pref = Some(NumericSet::Set(150));
        list.entry(10).action = crate::policy::PolicyAction::Next;
        // Entry 20 takes the verdict.
        list.entry(20).med = Some(NumericSet::Set(42));
        list.entry(20).action = crate::policy::PolicyAction::Permit;

        let out = policy_list_apply(&list, &nlri("10.0.0.0/24"), BgpAttr::default()).unwrap();
        // Both decorations applied: entry 10's local_pref AND
        // entry 20's med.
        assert_eq!(out.local_pref.unwrap().local_pref, 150);
        assert_eq!(out.med.unwrap().med, 42);
    }

    #[test]
    fn policy_action_default_deny_when_no_entry_matches() {
        let mut list = PolicyList::default();
        // Entry only matches a non-default prefix.
        let entry = list.entry(10);
        let mut pset = PrefixSet::default();
        pset.insert(
            Ipv4Net::from_str("192.168.0.0/16").unwrap().into(),
            PrefixSetEntry::default(),
        );
        entry.prefix_set = Some(pset);
        entry.action = crate::policy::PolicyAction::Permit;

        let out = policy_list_apply(&list, &nlri("10.0.0.0/24"), BgpAttr::default());
        assert!(out.is_none(), "no match → default deny");
    }

    #[test]
    fn policy_action_next_falling_through_to_end_of_list_is_default_deny() {
        let mut list = PolicyList::default();
        list.entry(10).local_pref = Some(NumericSet::Set(150));
        list.entry(10).action = crate::policy::PolicyAction::Next;
        // No further entries — fall-through past the end of the
        // policy is default-deny.

        let out = policy_list_apply(&list, &nlri("10.0.0.0/24"), BgpAttr::default());
        assert!(
            out.is_none(),
            "next falling through end of policy → default deny"
        );
    }

    #[test]
    fn policy_action_default_permit_via_unconditional_final_entry() {
        // The "default permit" idiom: a final entry with no match
        // clauses and action=permit accepts everything that fell
        // through.
        let mut list = PolicyList::default();
        let mut pset = PrefixSet::default();
        pset.insert(
            Ipv4Net::from_str("10.0.0.0/8").unwrap().into(),
            PrefixSetEntry::default(),
        );
        let entry = list.entry(10);
        entry.prefix_set = Some(pset);
        entry.action = crate::policy::PolicyAction::Deny;

        // Final unconditional permit — the "default permit" idiom.
        list.entry(20).action = crate::policy::PolicyAction::Permit;

        // 10.0.0.0/24 hits entry 10 (deny).
        let denied = policy_list_apply(&list, &nlri("10.0.0.0/24"), BgpAttr::default());
        assert!(denied.is_none());

        // 192.168.0.0/24 falls through to entry 20 (permit).
        let permitted = policy_list_apply(&list, &nlri("192.168.0.0/24"), BgpAttr::default());
        assert!(permitted.is_some());
    }

    // FIB install translation: `make_bgp_rib_entry_v4` produces an
    // installable RibEntry only when the BGP best-path has a usable
    // IPv4 next-hop. The four cases below cover the decision matrix.

    fn bgp_rib_with_nexthop(nh: Option<BgpNexthop>, typ: super::BgpRibType) -> super::BgpRib {
        let attr = BgpAttr {
            nexthop: nh,
            ..BgpAttr::default()
        };
        super::BgpRib::new(
            42, // ident
            Ipv4Addr::new(10, 0, 0, 1),
            typ,
            0,
            0,
            &attr,
            None,
            None,
            false,
        )
    }

    #[test]
    fn fib_entry_built_for_v4_ebgp_route() {
        let rib = bgp_rib_with_nexthop(
            Some(BgpNexthop::Ipv4(Ipv4Addr::new(192, 0, 2, 1))),
            super::BgpRibType::EBGP,
        );
        let entry = super::make_bgp_rib_entry_v4(&rib).expect("must build");
        assert_eq!(entry.distance, 20);
        assert!(entry.valid);
        match entry.nexthop {
            crate::rib::Nexthop::Uni(ref uni) => {
                assert_eq!(uni.addr, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
            }
            _ => panic!("expected NexthopUni"),
        }
    }

    #[test]
    fn fib_entry_uses_ibgp_distance_for_ibgp() {
        let rib = bgp_rib_with_nexthop(
            Some(BgpNexthop::Ipv4(Ipv4Addr::new(192, 0, 2, 1))),
            super::BgpRibType::IBGP,
        );
        let entry = super::make_bgp_rib_entry_v4(&rib).expect("must build");
        assert_eq!(entry.distance, 200);
    }

    #[test]
    fn fib_entry_skipped_for_unspecified_nexthop() {
        let rib = bgp_rib_with_nexthop(
            Some(BgpNexthop::Ipv4(Ipv4Addr::UNSPECIFIED)),
            super::BgpRibType::EBGP,
        );
        assert!(super::make_bgp_rib_entry_v4(&rib).is_none());
    }

    #[test]
    fn fib_entry_skipped_when_nexthop_missing() {
        let rib = bgp_rib_with_nexthop(None, super::BgpRibType::EBGP);
        assert!(super::make_bgp_rib_entry_v4(&rib).is_none());
    }

    #[test]
    fn fib_entry_uses_link_install_when_enhe_egress_set() {
        // RFC 8950 path: even with no v4 NEXT_HOP attribute, the
        // route is installable as `dev <ifindex>` because the
        // receiver knows the egress interface.
        let mut rib = bgp_rib_with_nexthop(None, super::BgpRibType::EBGP);
        rib.egress_ifindex_v6 = Some(7);
        let entry = super::make_bgp_rib_entry_v4(&rib).expect("must build");
        assert_eq!(entry.distance, 20);
        match entry.nexthop {
            crate::rib::Nexthop::Link(ifindex) => assert_eq!(ifindex, 7),
            other => panic!("expected Nexthop::Link, got {:?}", other),
        }
    }

    #[test]
    fn fib_entry_enhe_ignores_v4_nexthop_attribute() {
        // RFC 8950 §4: receiver MUST ignore the NEXT_HOP attribute
        // when MP_REACH carries an IPv6 next-hop. A stale 0.0.0.0
        // (or anything else) in the v4 NEXT_HOP must not perturb
        // the install — egress_ifindex_v6 wins.
        let mut rib = bgp_rib_with_nexthop(
            Some(BgpNexthop::Ipv4(Ipv4Addr::UNSPECIFIED)),
            super::BgpRibType::EBGP,
        );
        rib.egress_ifindex_v6 = Some(11);
        let entry = super::make_bgp_rib_entry_v4(&rib).expect("must build");
        match entry.nexthop {
            crate::rib::Nexthop::Link(ifindex) => assert_eq!(ifindex, 11),
            other => panic!("expected Nexthop::Link, got {:?}", other),
        }
    }

    // IPv6 counterpart: `make_bgp_rib_entry_v6` installs only when the
    // best-path carries a usable `BgpNexthop::Ipv6`.

    #[test]
    fn fib_entry_v6_built_for_ebgp_route() {
        let nh: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        let rib = bgp_rib_with_nexthop(Some(BgpNexthop::Ipv6(nh)), super::BgpRibType::EBGP);
        let entry = super::make_bgp_rib_entry_v6(&rib).expect("must build");
        assert_eq!(entry.distance, 20);
        assert!(entry.valid);
        match entry.nexthop {
            crate::rib::Nexthop::Uni(ref uni) => assert_eq!(uni.addr, IpAddr::V6(nh)),
            _ => panic!("expected NexthopUni"),
        }
    }

    #[test]
    fn fib_entry_v6_uses_ibgp_distance() {
        let nh: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        let rib = bgp_rib_with_nexthop(Some(BgpNexthop::Ipv6(nh)), super::BgpRibType::IBGP);
        let entry = super::make_bgp_rib_entry_v6(&rib).expect("must build");
        assert_eq!(entry.distance, 200);
    }

    #[test]
    fn fib_entry_v6_skipped_for_unspecified() {
        let rib = bgp_rib_with_nexthop(
            Some(BgpNexthop::Ipv6(std::net::Ipv6Addr::UNSPECIFIED)),
            super::BgpRibType::EBGP,
        );
        assert!(super::make_bgp_rib_entry_v6(&rib).is_none());
    }

    #[test]
    fn fib_entry_v6_skipped_for_v4_nexthop() {
        // A v4 next-hop on a row reaching the v6 installer is a bug
        // upstream; the builder defensively declines rather than
        // install a mismatched entry.
        let rib = bgp_rib_with_nexthop(
            Some(BgpNexthop::Ipv4(Ipv4Addr::new(192, 0, 2, 1))),
            super::BgpRibType::EBGP,
        );
        assert!(super::make_bgp_rib_entry_v6(&rib).is_none());
    }

    #[test]
    fn fib_entry_v6_skipped_when_nexthop_missing() {
        let rib = bgp_rib_with_nexthop(None, super::BgpRibType::EBGP);
        assert!(super::make_bgp_rib_entry_v6(&rib).is_none());
    }
}
