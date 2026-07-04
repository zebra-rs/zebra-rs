//! OSPFv2 TI-LFA (Topology-Independent Loop-Free Alternate, RFC 9490)
//! repair-path resolution.
//!
//! The post-convergence repair *list* (a sequence of Node-SID /
//! Adj-SID segments) is computed graph-only by [`tilfa_repair_path`]
//! on the SPF worker — it mirrors the IS-IS path and reuses the
//! protocol-agnostic [`crate::spf::tilfa_compute`] scheduler (serial
//! by default; `fast-reroute ti-lfa compute-mode` fans it out on the
//! rayon pool). Turning those segments into an installable SR-MPLS
//! label stack ([`build_repair_path_mpls`]) needs the LSDB (peer
//! SRGBs, Extended-Prefix / Extended-Link Opaque LSAs) and so runs on
//! the main task during RIB build.
//!
//! Unlike IS-IS, OSPF collapses a transit network into a direct mesh
//! of router→router edges (there is no pseudonode vertex in the SPF
//! graph), so there is no LAN-pseudonode handling and every Adj-SID
//! segment is a plain `(from, to)` pair.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use ospf_packet::{
    Algo, ExtLinkSubTlv, ExtPrefixSubTlv, OSPFV3_E_INTRA_AREA_PREFIX_LSA_TYPE,
    OSPFV3_E_ROUTER_LSA_TYPE, OspfLsType, OspfLsp, Ospfv3ExtTlv, Ospfv3LsBody,
    Ospfv3RouterLinkType, Ospfv3SubTlv, SidLabelTlv,
};

use crate::rib;
use crate::spf;
use crate::spf::label_block::LabelConfig;

use super::area::OspfArea;
use super::inst::Ospf;
use super::lsdb::OSPF_MAX_AGE;
use super::version::Ospfv3;

/// TI-LFA SR-MPLS repair path: the post-convergence first-hop egress
/// (ifindex + neighbor address) plus the MPLS label stack that steers
/// the packet along the repair. Stamped onto `SpfNexthop.backup`.
#[derive(Debug, Clone, PartialEq)]
pub struct RepairPathMpls {
    pub ifindex: u32,
    pub addr: Ipv4Addr,
    pub labels: Vec<rib::Label>,
}

/// Plan the TI-LFA targets from the primary SPF result: every
/// destination other than the source with a single primary first-hop
/// (SPF-level ECMP is skipped — the remaining legs already protect
/// the prefix), paired with the protected vertex X (the first-hop
/// node). Pure planning — the SPF work happens in
/// `spf::tilfa_compute`. No pseudonode handling: OSPF collapses
/// transit networks into a direct router→router mesh.
pub(super) fn tilfa_targets(
    source: usize,
    spf_result: &BTreeMap<usize, spf::Path>,
) -> Vec<spf::TilfaTarget> {
    let mut targets = Vec::new();
    for (d, path) in spf_result.iter() {
        if *d == source {
            continue;
        }
        // ECMP at the SPF level is skipped. Under `SpfOpt::default()`
        // the per-destination `nexthops` set holds one `[first_hop]`
        // entry per equal-cost first hop, so a length != 1 means ECMP
        // (or an unreachable destination with an empty set).
        if path.nexthops.len() != 1 {
            continue;
        }
        // X — the protected element: the single primary first-hop node.
        // The `d == x` case (destination *is* the protected neighbor)
        // self-skips downstream: the x-excluded SPF can't reach d, so
        // the repair list comes back empty and the destination is
        // omitted from the result map.
        let Some(&x) = path.nexthops.iter().next().and_then(|seq| seq.first()) else {
            continue;
        };
        targets.push(spf::TilfaTarget { d: *d, x });
    }
    targets
}

/// Per-destination TI-LFA repair computation (graph-only): plan the
/// targets, then hand them to `spf::tilfa_compute`, which schedules
/// the Q/PC SPF jobs per the configured compute mode (serial by
/// default). The returned map is keyed by destination vertex id;
/// destinations with no computable repair are absent.
///
/// Unlike IS-IS, OSPF's primary SPF runs in nexthop mode
/// (`SpfOpt::default()`), and the P-space filter inside
/// `tilfa_compute` needs full paths — so one extra full-path SPF on
/// the unmodified graph is run here. It is independent of the
/// protected node, so a single run is shared across every target
/// (the design doc's `N + |X| + 1` count for OSPF).
///
/// Runs on the SPF worker, so it borrows nothing but the graph and the
/// SPF result. The graph must carry `ilinks` (reverse edges) — the
/// OSPF graph builder populates them for exactly this Q-space step.
pub(super) fn tilfa_repair_path(
    graph: &spf::Graph,
    source: usize,
    spf_result: &BTreeMap<usize, spf::Path>,
    mode: spf::TilfaComputeMode,
) -> (BTreeMap<usize, Vec<spf::RepairPath>>, spf::TilfaStats) {
    let targets = tilfa_targets(source, spf_result);
    if targets.is_empty() {
        // Skip the full-path SPF when there is nothing to protect.
        let stats = spf::TilfaStats {
            mode,
            width: 1,
            ..spf::TilfaStats::default()
        };
        return (BTreeMap::new(), stats);
    }
    let full_path_spf = spf::spf(graph, source, &spf::SpfOpt::full_path());
    spf::tilfa_compute(graph, source, &full_path_spf, &targets, mode)
}

/// Translate a graph-level `spf::RepairPath` into the FIB-ready
/// `RepairPathMpls`: resolve the SR segment list to an absolute MPLS
/// label stack and pin the post-convergence first-hop's local egress
/// (ifindex from `first_hop_link_id`, address from the link's neighbor
/// table). Returns `None` when any segment fails to resolve or when
/// the first-hop has no usable address — a partial stack is refused
/// because a divergent label path would silently misroute.
pub(super) fn build_repair_path_mpls(
    top: &Ospf,
    area: &OspfArea,
    rp: &spf::RepairPath,
) -> Option<RepairPathMpls> {
    let labels = repair_segments_to_mpls_labels(top, area, &rp.segs)?;

    let first_hop_router = *top.lsp_map.resolve(rp.first_hop)?;
    let (ifindex, addr) = resolve_first_hop_egress(top, rp.first_hop_link_id, first_hop_router)?;

    Some(RepairPathMpls {
        ifindex,
        addr,
        labels,
    })
}

/// Resolve the repair's first-hop egress to (ifindex, neighbor addr).
/// The post-convergence SPF stamped the chosen edge's `link_id` (our
/// local ifindex) onto `first_hop_link_id`; we look up that link and
/// find the neighbor whose router-id is the first-hop router. Falls
/// back to scanning every link when `first_hop_link_id` is 0 (the edge
/// carried no ifindex — e.g. the first hop wasn't reached over one of
/// our own stamped edges).
fn resolve_first_hop_egress(
    top: &Ospf,
    first_hop_link_id: u32,
    first_hop_router: Ipv4Addr,
) -> Option<(u32, Ipv4Addr)> {
    if first_hop_link_id != 0
        && let Some(link) = top.links.get(&first_hop_link_id)
        && let Some(addr) = link
            .nbrs
            .values()
            .find(|n| n.ident.router_id == first_hop_router)
            .map(|n| n.ident.prefix.addr())
    {
        return Some((first_hop_link_id, addr));
    }
    top.links.iter().find_map(|(ifindex, link)| {
        link.nbrs
            .values()
            .find(|n| n.ident.router_id == first_hop_router)
            .map(|n| (*ifindex, n.ident.prefix.addr()))
    })
}

/// Resolve a TI-LFA repair list into an MPLS label stack. Returns
/// `None` when any segment fails to resolve — a partial stack is
/// refused, matching IS-IS.
fn repair_segments_to_mpls_labels(
    top: &Ospf,
    area: &OspfArea,
    segments: &[spf::SrSegment],
) -> Option<Vec<rib::Label>> {
    let mut labels = Vec::with_capacity(segments.len());
    for seg in segments {
        let resolved = match seg {
            spf::SrSegment::NodeSid(v) => node_sid_label_for_vertex(top, area, *v),
            // OSPF has no LAN pseudonode in the SPF graph, so `via` is
            // always None and an Adj-SID is a plain (from, to) lookup.
            spf::SrSegment::AdjSid(from, to, _via) => adj_sid_label_for_link(top, area, *from, *to),
        };
        labels.push(rib::Label::Explicit(resolved?));
    }
    Some(labels)
}

/// Resolve a peer-advertised SID to an absolute MPLS label. `Label`
/// SIDs are absolute on the wire; `Index` SIDs resolve against the
/// originator's SRGB (`global.start + index`).
fn resolve_sid(sid: &SidLabelTlv, srgb: Option<&LabelConfig>) -> Option<u32> {
    match sid {
        SidLabelTlv::Label(v) => Some(*v),
        SidLabelTlv::Index(idx) => srgb?.global.start.checked_add(*idx),
    }
}

/// Look up `vertex`'s base-algo (SPF) Prefix-SID as an absolute MPLS
/// label. Scans the Extended-Prefix Opaque LSAs originated by the
/// vertex's router for an algo-0 Prefix-SID, preferring a host (/32)
/// prefix (the node's loopback / Node-SID). Resolves Index-form SIDs
/// against that router's SRGB held in `Lsdb::label_map`.
fn node_sid_label_for_vertex(top: &Ospf, area: &OspfArea, vertex: usize) -> Option<u32> {
    let router_id = *top.lsp_map.resolve(vertex)?;
    let srgb = area.lsdb.label_map.get(&router_id);

    let mut fallback: Option<u32> = None;
    for (_, lsa) in area.lsdb.iter_by_type(OspfLsType::OpaqueAreaLocal) {
        if lsa.data.h.ls_age >= OSPF_MAX_AGE || lsa.data.h.adv_router != router_id {
            continue;
        }
        let OspfLsp::OpaqueAreaExtPrefix(ref ep) = lsa.data.lsp else {
            continue;
        };
        for tlv in &ep.tlvs {
            for sub in &tlv.subs {
                let ExtPrefixSubTlv::PrefixSid(ps) = sub else {
                    continue;
                };
                if ps.algo != Algo::Spf {
                    continue;
                }
                let Some(label) = resolve_sid(&ps.sid, srgb) else {
                    continue;
                };
                // Prefer the host route (loopback /32) — that's the
                // Node-SID. Keep the first resolvable algo-0 SID as a
                // fallback for advertisers that don't tag a /32.
                if tlv.prefix.prefix_len() == 32 {
                    return Some(label);
                }
                fallback.get_or_insert(label);
            }
        }
    }
    fallback
}

/// Look up the Adjacency-SID `from` advertises for the link toward
/// `to`, as an absolute MPLS label. Scans `from`'s Extended-Link
/// Opaque LSAs: P2P links (link_type 1) match on `link_id == to`'s
/// router-id; LAN links (link_type 2) match a LanAdjSid whose
/// `neighbor_id == to`'s router-id.
fn adj_sid_label_for_link(
    top: &Ospf,
    area: &OspfArea,
    from_vertex: usize,
    to_vertex: usize,
) -> Option<u32> {
    let from_router = *top.lsp_map.resolve(from_vertex)?;
    let to_router = *top.lsp_map.resolve(to_vertex)?;
    let srgb = area.lsdb.label_map.get(&from_router);

    for (_, lsa) in area.lsdb.iter_by_type(OspfLsType::OpaqueAreaLocal) {
        if lsa.data.h.ls_age >= OSPF_MAX_AGE || lsa.data.h.adv_router != from_router {
            continue;
        }
        let OspfLsp::OpaqueAreaExtLink(ref el) = lsa.data.lsp else {
            continue;
        };
        for tlv in &el.tlvs {
            match tlv.link_type {
                // P2P: link_id is the neighbor's router-id.
                1 => {
                    if tlv.link_id != to_router {
                        continue;
                    }
                    for sub in &tlv.subs {
                        if let ExtLinkSubTlv::AdjSid(adj) = sub {
                            return resolve_sid(&adj.sid, srgb);
                        }
                    }
                }
                // Broadcast / NBMA: one LanAdjSid sub-TLV per neighbor.
                2 => {
                    for sub in &tlv.subs {
                        if let ExtLinkSubTlv::LanAdjSid(lan) = sub
                            && lan.neighbor_id == to_router
                        {
                            return resolve_sid(&lan.sid, srgb);
                        }
                    }
                }
                _ => {}
            }
        }
    }
    None
}

// =====================================================================
// OSPFv3 (RFC 5340) — SR-MPLS repair resolution.
//
// Same shape as the v2 functions above, but the SR data lives in v3's
// extended LSAs: Node-SIDs in E-Intra-Area-Prefix LSAs (RFC 8362 §3.7 /
// RFC 8666), Adj-SIDs in E-Router-LSA RouterLink TLVs. Next-hops are
// IPv6 link-locals resolved by neighbor router-id (mirrors
// `collect_v3_nexthops`). The graph-level `tilfa_repair_path` above is
// protocol-agnostic and reused for v3 unchanged.
// =====================================================================

/// v3 sibling of [`RepairPathMpls`]: the post-convergence first-hop
/// egress (ifindex + neighbor link-local) plus the SR-MPLS label stack.
#[derive(Debug, Clone, PartialEq)]
pub struct RepairPathMplsV3 {
    pub ifindex: u32,
    pub addr: Ipv6Addr,
    pub labels: Vec<rib::Label>,
}

/// v3 sibling of [`build_repair_path_mpls`]. Resolves the SR segment
/// list to an MPLS label stack from v3's extended LSAs and pins the
/// post-convergence first-hop's IPv6 link-local egress.
pub(super) fn build_repair_path_mpls_v3(
    top: &Ospf<Ospfv3>,
    area: &OspfArea<Ospfv3>,
    rp: &spf::RepairPath,
) -> Option<RepairPathMplsV3> {
    let labels = repair_segments_to_mpls_labels_v3(top, area, &rp.segs)?;
    let first_hop_router = *top.lsp_map.resolve(rp.first_hop)?;
    let (ifindex, addr) = resolve_first_hop_egress_v3(top, first_hop_router)?;
    Some(RepairPathMplsV3 {
        ifindex,
        addr,
        labels,
    })
}

/// Resolve the repair's first-hop egress to (ifindex, link-local addr).
/// v3 keys neighbors by router-id and learns the egress from the
/// adjacency, so — unlike v2 — `first_hop_link_id` isn't consulted;
/// this mirrors `collect_v3_nexthops`.
fn resolve_first_hop_egress_v3(
    top: &Ospf<Ospfv3>,
    first_hop_router: Ipv4Addr,
) -> Option<(u32, Ipv6Addr)> {
    for link in top.links.values() {
        if let Some(nbr) = link.nbrs.get(&first_hop_router) {
            let ll = nbr.ident.prefix.addr();
            if !ll.is_unspecified() {
                return Some((nbr.ifindex, ll));
            }
        }
    }
    None
}

fn repair_segments_to_mpls_labels_v3(
    top: &Ospf<Ospfv3>,
    area: &OspfArea<Ospfv3>,
    segments: &[spf::SrSegment],
) -> Option<Vec<rib::Label>> {
    let mut labels = Vec::with_capacity(segments.len());
    for seg in segments {
        let resolved = match seg {
            spf::SrSegment::NodeSid(v) => node_sid_label_for_vertex_v3(top, area, *v),
            spf::SrSegment::AdjSid(from, to, _via) => {
                adj_sid_label_for_link_v3(top, area, *from, *to)
            }
        };
        labels.push(rib::Label::Explicit(resolved?));
    }
    Some(labels)
}

/// v3 Node-SID lookup: scan the vertex router's E-Intra-Area-Prefix
/// LSAs for a base-algo (SPF) Prefix-SID, preferring a host (/128)
/// prefix (the loopback / Node-SID). Index-form SIDs resolve against
/// the advertiser's SRGB.
fn node_sid_label_for_vertex_v3(
    top: &Ospf<Ospfv3>,
    area: &OspfArea<Ospfv3>,
    vertex: usize,
) -> Option<u32> {
    let router_id = *top.lsp_map.resolve(vertex)?;
    let srgb = area.lsdb.label_map.get(&router_id);

    let mut fallback: Option<u32> = None;
    for ((_ls_id, adv_router), lsa) in area
        .lsdb
        .iter_by_raw_type(OSPFV3_E_INTRA_AREA_PREFIX_LSA_TYPE)
    {
        if lsa.data.h.ls_age >= OSPF_MAX_AGE || adv_router != router_id {
            continue;
        }
        let Ospfv3LsBody::EIntraAreaPrefix(ref body) = lsa.data.body else {
            continue;
        };
        for tlv in &body.tlvs {
            let Ospfv3ExtTlv::IntraAreaPrefix(prefix_tlv) = tlv else {
                continue;
            };
            for sub in &prefix_tlv.subs {
                let Ospfv3SubTlv::PrefixSid(ps) = sub else {
                    continue;
                };
                if ps.algo != Algo::Spf {
                    continue;
                }
                let Some(label) = resolve_sid(&ps.sid, srgb) else {
                    continue;
                };
                if prefix_tlv.prefix_length == 128 {
                    return Some(label);
                }
                fallback.get_or_insert(label);
            }
        }
    }
    fallback
}

/// v3 Adj-SID lookup: scan `from`'s E-Router-LSAs (one per interface)
/// for the RouterLink toward `to` and take its Adj-SID / LAN-Adj-SID.
fn adj_sid_label_for_link_v3(
    top: &Ospf<Ospfv3>,
    area: &OspfArea<Ospfv3>,
    from_vertex: usize,
    to_vertex: usize,
) -> Option<u32> {
    let from_router = *top.lsp_map.resolve(from_vertex)?;
    let to_router = *top.lsp_map.resolve(to_vertex)?;
    let srgb = area.lsdb.label_map.get(&from_router);

    for ((_ls_id, adv_router), lsa) in area.lsdb.iter_by_raw_type(OSPFV3_E_ROUTER_LSA_TYPE) {
        if lsa.data.h.ls_age >= OSPF_MAX_AGE || adv_router != from_router {
            continue;
        }
        let Ospfv3LsBody::ERouter(ref body) = lsa.data.body else {
            continue;
        };
        for tlv in &body.tlvs {
            let Ospfv3ExtTlv::RouterLink(rl) = tlv else {
                continue;
            };
            match rl.link.link_type {
                Ospfv3RouterLinkType::PointToPoint => {
                    if rl.link.neighbor_router_id != to_router {
                        continue;
                    }
                    for sub in &rl.subs {
                        if let Ospfv3SubTlv::AdjSid(adj) = sub {
                            return resolve_sid(&adj.sid, srgb);
                        }
                    }
                }
                Ospfv3RouterLinkType::Transit => {
                    for sub in &rl.subs {
                        if let Ospfv3SubTlv::LanAdjSid(lan) = sub
                            && lan.neighbor_router_id == to_router
                        {
                            return resolve_sid(&lan.sid, srgb);
                        }
                    }
                }
                _ => {}
            }
        }
    }
    None
}

// ---------------------------------------------------------------------
// SRv6 TI-LFA repairs (RFC 9513) — Part of
// docs/design/ospfv3-srv6-plan.md.
// ---------------------------------------------------------------------

/// A resolved v3 TI-LFA repair, in whichever encoding the instance's
/// dataplane runs: an SR-MPLS label stack or an SRv6 SID list. The
/// route builder picks SRv6 whenever the locator is active, else
/// MPLS — the two modes can in principle coexist, but a repair only
/// needs one encoding.
#[derive(Debug, Clone, PartialEq)]
pub enum RepairBackupV3 {
    Mpls(RepairPathMplsV3),
    Srv6(RepairPathSrv6V3),
}

/// SRv6 TI-LFA repair for one v3 route — the OSPFv3 sibling of
/// `isis::tilfa::RepairPathSrv6`. The SID list is SRH-inserted
/// (H.Insert): repair segments are transit End/End.X SIDs with no
/// decap terminator, so the original destination must stay the SRH's
/// final segment (H.Encap would blackhole at the last SID).
#[derive(Debug, Clone, PartialEq)]
pub struct RepairPathSrv6V3 {
    pub ifindex: u32,
    pub addr: Ipv6Addr,
    pub segs: Vec<Ipv6Addr>,
    pub encap: isis_packet::srv6::EncapType,
}

/// Resolve a graph-level repair to an SRv6 SID list from the v3 LSDB
/// and pack it into NEXT-C-SID carriers — the OSPFv3 sibling of
/// `isis::tilfa::build_repair_path_srv6`. NodeSids resolve to the
/// vertex router's End SID (its SRv6 Locator LSA), AdjSids to the
/// advertiser's End.X SID (sub-TLV 31/32 on its E-Router-LSA
/// Router-Link TLVs). Returns `None` when any segment fails to
/// resolve — a partial SID list would diverge from the
/// post-convergence path.
pub(super) fn build_repair_path_srv6_v3(
    top: &Ospf<Ospfv3>,
    area: &OspfArea<Ospfv3>,
    rp: &spf::RepairPath,
) -> Option<RepairPathSrv6V3> {
    use crate::spf::srv6::{RepairSeg, pack_carriers};

    let mut parts: Vec<RepairSeg> = Vec::with_capacity(rp.segs.len());
    for seg in &rp.segs {
        let part = match seg {
            spf::SrSegment::NodeSid(v) => {
                let info = srv6_end_sid_for_vertex_v3(top, area, *v)?;
                // REPLACE-C-SID SIDs are only valid inside packed C-SID
                // containers (RFC 9800 §6.4) — unprotectable as plain
                // repair segments (same guard as the IS-IS builder).
                if isis_packet::Behavior::from(info.behavior).is_end_replace_csid() {
                    return None;
                }
                RepairSeg {
                    sid: info.sid,
                    landing: *v,
                    csid: csid_bits_end_v3(&info),
                }
            }
            spf::SrSegment::AdjSid(from, to, _via) => {
                let info = srv6_endx_sid_for_link_v3(top, area, *from, *to)?;
                if isis_packet::Behavior::from(info.behavior).is_endx_replace_csid() {
                    return None;
                }
                RepairSeg {
                    sid: info.sid,
                    landing: *to,
                    csid: csid_bits_endx_v3(&info, *from),
                }
            }
        };
        parts.push(part);
    }
    let segs = pack_carriers(&parts);

    let first_hop_router = *top.lsp_map.resolve(rp.first_hop)?;
    let (ifindex, addr) = resolve_first_hop_egress_v3(top, first_hop_router)?;
    Some(RepairPathSrv6V3 {
        ifindex,
        addr,
        segs,
        encap: isis_packet::srv6::EncapType::HInsert,
    })
}

/// An SRv6 SID with its endpoint behavior and structure, as resolved
/// from the v3 LSDB for repair encoding.
struct Srv6SidInfoV3 {
    sid: Ipv6Addr,
    behavior: u16,
    structure: Option<ospf_packet::Ospfv3Srv6SidStructure>,
}

/// The vertex router's End SID from its SRv6 Locator LSA (algo-0
/// Locator TLV → End SID sub-TLV, structure from the locator-registry
/// SID Structure sub-TLV).
fn srv6_end_sid_for_vertex_v3(
    top: &Ospf<Ospfv3>,
    area: &OspfArea<Ospfv3>,
    vertex: usize,
) -> Option<Srv6SidInfoV3> {
    use ospf_packet::{
        OSPFV3_SRV6_LOCATOR_LSA_TYPE, Ospfv3LsBody, Ospfv3Srv6LocatorLsaTlv,
        Ospfv3Srv6LocatorSubTlv,
    };
    let router_id = *top.lsp_map.resolve(vertex)?;
    for ((_ls_id, adv_router), lsa) in area.lsdb.iter_by_raw_type(OSPFV3_SRV6_LOCATOR_LSA_TYPE) {
        if lsa.data.h.ls_age >= OSPF_MAX_AGE || adv_router != router_id {
            continue;
        }
        let Ospfv3LsBody::Srv6Locator(ref body) = lsa.data.body else {
            continue;
        };
        for tlv in &body.tlvs {
            let Ospfv3Srv6LocatorLsaTlv::Locator(loc) = tlv else {
                continue;
            };
            if loc.algorithm != 0 {
                continue;
            }
            for sub in &loc.subs {
                let Ospfv3Srv6LocatorSubTlv::EndSid(end) = sub else {
                    continue;
                };
                let structure = end.subs.iter().find_map(|s| {
                    if let Ospfv3Srv6LocatorSubTlv::SidStructure(st) = s {
                        Some(*st)
                    } else {
                        None
                    }
                });
                return Some(Srv6SidInfoV3 {
                    sid: end.sid,
                    behavior: end.behavior,
                    structure,
                });
            }
        }
    }
    None
}

/// `from`'s End.X SID toward `to`, from the Router-Link TLVs of its
/// per-link E-Router-LSAs — the SRv6 sibling of
/// `adj_sid_label_for_link_v3`. P2P links carry sub-TLV 31; LAN
/// links sub-TLV 32 qualified by the Neighbor Router-ID.
fn srv6_endx_sid_for_link_v3(
    top: &Ospf<Ospfv3>,
    area: &OspfArea<Ospfv3>,
    from_vertex: usize,
    to_vertex: usize,
) -> Option<Srv6SidInfoV3> {
    use ospf_packet::{OSPFV3_E_ROUTER_LSA_TYPE, Ospfv3ExtTlv, Ospfv3LsBody, Ospfv3SubTlv};
    let from_router = *top.lsp_map.resolve(from_vertex)?;
    let to_router = *top.lsp_map.resolve(to_vertex)?;

    fn nested_structure(subs: &[Ospfv3SubTlv]) -> Option<ospf_packet::Ospfv3Srv6SidStructure> {
        subs.iter().find_map(|s| {
            if let Ospfv3SubTlv::Srv6SidStructure(st) = s {
                Some(*st)
            } else {
                None
            }
        })
    }

    for ((_ls_id, adv_router), lsa) in area.lsdb.iter_by_raw_type(OSPFV3_E_ROUTER_LSA_TYPE) {
        if lsa.data.h.ls_age >= OSPF_MAX_AGE || adv_router != from_router {
            continue;
        }
        let Ospfv3LsBody::ERouter(ref body) = lsa.data.body else {
            continue;
        };
        for tlv in &body.tlvs {
            let Ospfv3ExtTlv::RouterLink(rl) = tlv else {
                continue;
            };
            if rl.link.neighbor_router_id != to_router {
                continue;
            }
            for sub in &rl.subs {
                match sub {
                    Ospfv3SubTlv::Srv6EndXSid(endx) => {
                        return Some(Srv6SidInfoV3 {
                            sid: endx.sid,
                            behavior: endx.behavior,
                            structure: nested_structure(&endx.subs),
                        });
                    }
                    Ospfv3SubTlv::Srv6LanEndXSid(lan) if lan.neighbor_router_id == to_router => {
                        return Some(Srv6SidInfoV3 {
                            sid: lan.sid,
                            behavior: lan.behavior,
                            structure: nested_structure(&lan.subs),
                        });
                    }
                    _ => {}
                }
            }
        }
    }
    None
}

/// Carrier metadata for a v3-advertised End/uN SID — identifier is
/// the locator-node portion. `None` (full-SID fallback) for classic
/// behaviors or missing/degenerate structures.
fn csid_bits_end_v3(info: &Srv6SidInfoV3) -> Option<crate::spf::srv6::CsidBits> {
    use crate::spf::srv6::{CsidBits, sid_bits, sid_block};
    if !isis_packet::Behavior::from(info.behavior).is_end_next_csid() {
        return None;
    }
    let st = info.structure.as_ref()?;
    let (lb, ln) = (st.lb_len as u32, st.ln_len as u32);
    if ln == 0 || lb + ln > 128 {
        return None;
    }
    Some(CsidBits {
        block: sid_block(info.sid, st.lb_len),
        lb: st.lb_len,
        id: sid_bits(info.sid, lb, ln),
        width: st.ln_len,
        lib_owner: None,
    })
}

/// Carrier metadata for a v3-advertised End.X/uA SID — identifier is
/// the function portion, locally significant to `owner`.
fn csid_bits_endx_v3(info: &Srv6SidInfoV3, owner: usize) -> Option<crate::spf::srv6::CsidBits> {
    use crate::spf::srv6::{CsidBits, sid_bits, sid_block};
    if !isis_packet::Behavior::from(info.behavior).is_endx_next_csid() {
        return None;
    }
    let st = info.structure.as_ref()?;
    let (lb, ln, fun) = (st.lb_len as u32, st.ln_len as u32, st.fun_len as u32);
    if fun == 0 || lb + ln + fun > 128 {
        return None;
    }
    Some(CsidBits {
        block: sid_block(info.sid, st.lb_len),
        lb: st.lb_len,
        id: sid_bits(info.sid, lb + ln, fun),
        width: st.fun_len,
        lib_owner: Some(owner),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spf::calc::fixtures::tilfa_graph;

    /// The OSPF pipeline equals the legacy per-destination
    /// `spf::tilfa` loop. OSPF's primary SPF runs in nexthop mode, so
    /// this specifically pins the full-path-SPF substitution inside
    /// `tilfa_repair_path` (the P-space filter must see the same tree
    /// `p_space_vertices` computed internally), on top of the mode
    /// equivalence already pinned in `spf::tilfa_par`.
    #[test]
    fn repair_path_matches_reference_loop() {
        let graph = tilfa_graph();
        let source = 0;
        // Nexthop mode — exactly what OSPF's `compute_spf` passes.
        let primary = spf::spf(&graph, source, &spf::SpfOpt::default());
        let targets = tilfa_targets(source, &primary);
        assert!(!targets.is_empty(), "fixture must produce targets");

        let mut want = BTreeMap::new();
        for t in &targets {
            let repairs = spf::tilfa(&graph, source, t.d, &[t.x]);
            if !repairs.is_empty() {
                want.insert(t.d, repairs);
            }
        }

        for mode in [
            spf::TilfaComputeMode::Serial,
            spf::TilfaComputeMode::Conservative,
            spf::TilfaComputeMode::Aggressive,
            spf::TilfaComputeMode::Sharding(2),
        ] {
            let (got, stats) = tilfa_repair_path(&graph, source, &primary, mode);
            assert_eq!(got, want, "mode {mode:?}");
            assert_eq!(stats.targets, targets.len(), "mode {mode:?}");
        }
    }

    /// A topology with nothing to protect (single router) short-
    /// circuits before the extra full-path SPF and returns empty
    /// zeroed stats.
    #[test]
    fn empty_targets_skip_compute() {
        let mut graph: spf::Graph = BTreeMap::new();
        graph.insert(0, spf::Vertex::new_node("S", 0));
        let primary = spf::spf(&graph, 0, &spf::SpfOpt::default());
        let (got, stats) = tilfa_repair_path(&graph, 0, &primary, spf::TilfaComputeMode::Serial);
        assert!(got.is_empty());
        assert_eq!(stats.targets, 0);
        assert_eq!(stats.q_spf, 0);
    }
}
