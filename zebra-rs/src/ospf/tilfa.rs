//! OSPFv2 TI-LFA (Topology-Independent Loop-Free Alternate, RFC 9490)
//! repair-path resolution.
//!
//! The post-convergence repair *list* (a sequence of Node-SID /
//! Adj-SID segments) is computed graph-only by [`tilfa_repair_path`]
//! on the SPF worker — it mirrors the IS-IS path and reuses the
//! protocol-agnostic [`crate::spf::tilfa`]. Turning those segments
//! into an installable SR-MPLS label stack ([`build_repair_path_mpls`])
//! needs the LSDB (peer SRGBs, Extended-Prefix / Extended-Link Opaque
//! LSAs) and so runs on the main task during RIB build.
//!
//! Unlike IS-IS, OSPF collapses a transit network into a direct mesh
//! of router→router edges (there is no pseudonode vertex in the SPF
//! graph), so there is no LAN-pseudonode handling and every Adj-SID
//! segment is a plain `(from, to)` pair.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use ospf_packet::{Algo, ExtLinkSubTlv, ExtPrefixSubTlv, OspfLsType, OspfLsp, SidLabelTlv};

use crate::rib;
use crate::spf;
use crate::spf::label_block::LabelConfig;

use super::area::OspfArea;
use super::inst::Ospf;
use super::lsdb::OSPF_MAX_AGE;

/// TI-LFA SR-MPLS repair path: the post-convergence first-hop egress
/// (ifindex + neighbor address) plus the MPLS label stack that steers
/// the packet along the repair. Stamped onto `SpfNexthop.backup`.
#[derive(Debug, Clone, PartialEq)]
pub struct RepairPathMpls {
    pub ifindex: u32,
    pub addr: Ipv4Addr,
    pub labels: Vec<rib::Label>,
}

/// Per-destination TI-LFA repair computation (graph-only). For every
/// destination in `spf_result` other than the source that has a single
/// primary first-hop (SPF-level ECMP is skipped — the remaining legs
/// already protect the prefix), call [`spf::tilfa`] to compute the
/// post-convergence repair list, protecting against the first-hop node
/// (`X`). The returned map is keyed by destination vertex id.
///
/// Runs on the SPF worker, so it borrows nothing but the graph and the
/// SPF result. The graph must carry `ilinks` (reverse edges) — the
/// OSPF graph builder populates them for exactly this Q-space step.
pub(super) fn tilfa_repair_path(
    graph: &spf::Graph,
    source: usize,
    spf_result: &BTreeMap<usize, spf::Path>,
) -> BTreeMap<usize, Vec<spf::RepairPath>> {
    let mut tilfa_result = BTreeMap::new();
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
        // `spf::tilfa` returns an empty vec when `d == x` (the
        // destination *is* the protected neighbor), so that case
        // self-skips below.
        let Some(&x) = path.nexthops.iter().next().and_then(|seq| seq.first()) else {
            continue;
        };
        let repair_paths = spf::tilfa(graph, source, *d, &[x]);
        if !repair_paths.is_empty() {
            tilfa_result.insert(*d, repair_paths);
        }
    }
    tilfa_result
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
