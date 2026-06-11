use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use isis_packet::neigh;
use isis_packet::srv6::EncapType;
use isis_packet::{IsisNeighborId, IsisSysId, IsisTlv, SidLabelValue};

use crate::rib;
use crate::spf;

use super::graph::LspMap;
use super::inst::IsisTop;
use super::level::Level;
use super::link::Afi;

/// TI-LFA SR-MPLS repair path. Today's repair-path computation is not
/// wired in yet — once `ti_lfa_compute` lands, `SpfNexthop.backup`
/// will be populated with the egress info and the SR-MPLS label stack
/// (typically `[prefix-SID(P), adj-SID(P→Q)]` for the 2-label case).
#[derive(Debug, Clone, PartialEq)]
pub struct RepairPathMpls {
    pub ifindex: u32,
    pub addr: Ipv4Addr,
    pub labels: Vec<rib::Label>,
}

/// TI-LFA SRv6 repair path. The segment list expresses the post-
/// convergence path as IPv6 endpoint SIDs — typically
/// `[End(P), End.X(P→Q)]` for the 2-segment case — in forwarding
/// order. The encap is `HInsert` (SRH insertion): the repair segments
/// are transit End / End.X SIDs with no decapsulating terminator, so
/// the original destination must ride along as the SRH's final
/// segment; H.Encap would blackhole at the last SID (Linux drops
/// End / End.X at SL=0 without USD-flavor support).
#[derive(Debug, Clone, PartialEq)]
pub struct RepairPathSrv6 {
    pub ifindex: u32,
    pub addr: Ipv6Addr,
    pub segs: Vec<Ipv6Addr>,
    pub encap: EncapType,
}

/// Vertex id of the first non-pseudonode hop on `path`, skipping any
/// leading pseudonode hops. Returns `None` when the path is empty or
/// consists entirely of pseudonodes — both cases mean there's no
/// real router to install as the first-hop. RIB-builders use this to
/// land on the actual nexthop router (whose adjacency carries the
/// peer addresses) rather than on the LAN's transit-only PN vertex.
pub(super) fn first_router_hop_id(lsp_map: &LspMap, path: &[usize]) -> Option<usize> {
    let mut idx = 0;
    while idx < path.len() && lsp_map.is_pseudo(path[idx]) {
        idx += 1;
    }
    (idx < path.len()).then_some(path[idx])
}

/// Translate a graph-level `spf::RepairPath` into the FIB-ready
/// `RepairPathMpls`: resolve the SR segment list to an absolute MPLS
/// label stack and pin the post-conv first-hop's local egress
/// (ifindex from `first_hop_link_id`; addr from the link's neighbor
/// table). Returns `None` when any segment fails to resolve or when
/// the first-hop has no usable IPv4 address — partial stacks are
/// refused because a divergent label path would silently misroute.
///
/// LAN trivial-repair (empty label stack, first_hop is a pseudonode)
/// is skipped: picking an arbitrary LAN member for an un-steered
/// repair can loop, and the per-path "real router after the PN" is
/// not carried on `RepairPath` today. SR-steered LAN repairs are
/// fine — the labels drive forwarding independent of which LAN
/// member receives the packet first.
pub(super) fn build_repair_path_mpls(
    top: &IsisTop,
    level: Level,
    rp: &spf::RepairPath,
) -> Option<RepairPathMpls> {
    let labels = repair_segments_to_mpls_labels(top, level, &rp.segs)?;

    let ifindex = (rp.first_hop_link_id != 0).then_some(rp.first_hop_link_id)?;
    let link = top.links.get(&ifindex)?;
    let lsp_map = top.lsp_map.get(&level);

    let addr = if lsp_map.is_pseudo(rp.first_hop) {
        if labels.is_empty() {
            return None;
        }
        link.state
            .nbrs
            .get(&level)
            .values()
            .find_map(|nbr| nbr.addr4.keys().next().copied())?
    } else {
        let sys_id = lsp_map.resolve(rp.first_hop)?;
        link.state
            .nbrs
            .get(&level)
            .get(sys_id)?
            .addr4
            .keys()
            .next()
            .copied()?
    };

    Some(RepairPathMpls {
        ifindex,
        addr,
        labels,
    })
}

/// SRv6 sibling of `build_repair_path_mpls`. Resolves the SR segment
/// list to IPv6 SIDs — NodeSids to the originator's End SID (from
/// `top.srv6_end_map`), AdjSids to the advertiser's End.X SID (from
/// its IS-reach sub-TLVs, RFC 9352 §8) — and pins the post-conv
/// first-hop's IPv6 link-local egress. Returns `None` when any
/// segment fails to resolve: a partial SID list would diverge from
/// the post-convergence path the algorithm computed. The encap is
/// `HInsert` — see `RepairPathSrv6` for why insertion rather than
/// H.Encap.
///
/// LAN trivial-repair (empty segs, first_hop is a pseudonode) is
/// skipped for the same reason as in the MPLS sibling — `RepairPath`
/// doesn't carry the specific post-PN router today.
pub(super) fn build_repair_path_srv6(
    top: &IsisTop,
    level: Level,
    rp: &spf::RepairPath,
) -> Option<RepairPathSrv6> {
    let lsp_map = top.lsp_map.get(&level);
    let mut segs: Vec<Ipv6Addr> = Vec::with_capacity(rp.segs.len());
    for (idx, seg) in rp.segs.iter().enumerate() {
        let resolved = match seg {
            spf::SrSegment::NodeSid(v) => lsp_map
                .resolve(*v)
                .and_then(|sys_id| top.srv6_end_map.get(&level).get(sys_id).copied()),
            spf::SrSegment::AdjSid(from, to, via) => {
                srv6_endx_sid_for_link(top, level, *from, *to, *via)
            }
        };
        let Some(sid) = resolved else {
            tracing::debug!(
                "[tilfa] {level:?} repair segment[{idx}] {seg:?} failed to resolve to an SRv6 \
                 SID; dropping repair list (partial: {segs:?})"
            );
            return None;
        };
        segs.push(sid);
    }

    let ifindex = (rp.first_hop_link_id != 0).then_some(rp.first_hop_link_id)?;
    let link = top.links.get(&ifindex)?;

    let addr = if lsp_map.is_pseudo(rp.first_hop) {
        if segs.is_empty() {
            return None;
        }
        link.state
            .nbrs
            .get(&level)
            .values()
            .find_map(|nbr| nbr.addr6l.first().copied())?
    } else {
        let sys_id = lsp_map.resolve(rp.first_hop)?;
        link.state
            .nbrs
            .get(&level)
            .get(sys_id)?
            .addr6l
            .first()
            .copied()?
    };

    Some(RepairPathSrv6 {
        ifindex,
        addr,
        segs,
        encap: EncapType::HInsert,
    })
}

/// Look up the SRv6 End.X SID `from` advertises for the link to `to`
/// — the SRv6 sibling of `adj_sid_label_for_link`. For LAN
/// adjacencies (`via_pseudonode = Some(pn)`) the IS Reach entry's
/// neighbor_id matches the pseudonode and the LAN End.X sub-TLV's
/// `system_id` field identifies the LAN member; for P2P adjacencies
/// the neighbor_id is `(to_sys, 0)` and any End.X sub-TLV under it
/// qualifies (RFC 9352 §8.1 / §8.2).
fn srv6_endx_sid_for_link(
    top: &IsisTop,
    level: Level,
    from_vertex: usize,
    to_vertex: usize,
    via_pseudonode: Option<usize>,
) -> Option<Ipv6Addr> {
    let from_sys = *top.lsp_map.get(&level).resolve(from_vertex)?;
    let target_neighbor_id = if let Some(via_v) = via_pseudonode {
        *top.lsp_map.get(&level).resolve_neighbor(via_v)?
    } else {
        let to_sys = *top.lsp_map.get(&level).resolve(to_vertex)?;
        IsisNeighborId::from_sys_id(&to_sys, 0)
    };

    // Walk every non-pseudonode fragment originated by `from_sys` at
    // this level — with send-side LSP fragmentation the IS-reach
    // entry carrying the End.X can live in any fragment (same rule
    // as adj_sid_label_for_link).
    for (lsp_id, lsa) in top.lsdb.get(&level).iter() {
        if lsp_id.sys_id() != from_sys || lsp_id.is_pseudo() {
            continue;
        }
        for tlv in &lsa.lsp.tlvs {
            let IsisTlv::ExtIsReach(reach) = tlv else {
                continue;
            };
            for entry in &reach.entries {
                if entry.neighbor_id != target_neighbor_id {
                    continue;
                }
                for sub in &entry.subs {
                    match sub {
                        neigh::IsisSubTlv::Srv6EndXSid(endx) => {
                            return Some(endx.sid);
                        }
                        neigh::IsisSubTlv::Srv6LanEndXSid(lan_endx) => {
                            let Some(to_sys) = top.lsp_map.get(&level).resolve(to_vertex) else {
                                continue;
                            };
                            if &lan_endx.system_id == to_sys {
                                return Some(lan_endx.sid);
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    None
}

/// Resolve a peer-advertised SID to an absolute MPLS label, using
/// the originator's SR block when the SID is Index-encoded.
/// `block_kind` picks the global SRGB (prefix-SIDs) or the local
/// SRLB (adjacency-SIDs).
enum SrBlockKind {
    Global,
    Local,
}

fn resolve_sid_to_label(
    top: &IsisTop,
    level: Level,
    originator: &IsisSysId,
    sid: &SidLabelValue,
    block_kind: SrBlockKind,
) -> Option<u32> {
    match sid {
        SidLabelValue::Label(l) => Some(*l),
        SidLabelValue::Index(idx) => {
            let block = top.label_map.get(&level).get(originator)?;
            match block_kind {
                SrBlockKind::Global => Some(block.global.start + idx),
                SrBlockKind::Local => Some(block.local.as_ref()?.start + idx),
            }
        }
    }
}

/// Look up `vertex`'s prefix-SID (NodeSID) as an absolute MPLS label.
/// Walks the vertex's IPv4 reach entries (typically the loopback)
/// for the first prefix-SID sub-TLV, then resolves Index against the
/// originator's SRGB.
fn node_sid_label_for_vertex(top: &IsisTop, level: Level, vertex: usize) -> Option<u32> {
    let Some(sys_id) = top.lsp_map.get(&level).resolve(vertex).copied() else {
        tracing::debug!(
            "[tilfa] node_sid {level:?} vertex={vertex}: no sys_id in lsp_map (vertex not in LSDB?)"
        );
        return None;
    };
    let Some(entries) = top.reach_map.get(&level).get(&Afi::Ip).get(&sys_id) else {
        tracing::debug!(
            "[tilfa] node_sid {level:?} vertex={vertex} sys_id={sys_id}: \
             reach_map has no IPv4 entries (peer didn't advertise TLV 135?)"
        );
        return None;
    };
    let mut saw_prefix_sid = false;
    for entry in entries.iter() {
        let Some(prefix_sid) = entry.prefix_sid() else {
            continue;
        };
        saw_prefix_sid = true;
        if let Some(label) =
            resolve_sid_to_label(top, level, &sys_id, &prefix_sid.sid, SrBlockKind::Global)
        {
            return Some(label);
        }
        tracing::debug!(
            "[tilfa] node_sid {level:?} vertex={vertex} sys_id={sys_id}: \
             prefix={:?} prefix_sid={:?} could not resolve against SRGB \
             (peer's label_map block missing or index out of range)",
            entry.prefix,
            prefix_sid.sid,
        );
    }
    if !saw_prefix_sid {
        tracing::debug!(
            "[tilfa] node_sid {level:?} vertex={vertex} sys_id={sys_id}: \
             {} IPv4 reach entries scanned, none carry a Prefix-SID sub-TLV \
             (peer not advertising prefix-SID for any loopback?)",
            entries.len(),
        );
    }
    None
}

/// Look up the adjacency-SID `from` advertises for the link to `to`.
/// For LAN adjacencies (`via_pseudonode = Some(pn)`) the IS Reach
/// entry's neighbor_id matches the pseudonode and the LanAdjSid
/// sub-TLV's `system_id` field identifies the LAN member. For P2P
/// adjacencies the neighbor_id is `(to_sys, 0)` and any AdjSid
/// sub-TLV under it qualifies. Index-encoded SIDs resolve against
/// the originator's SRLB.
fn adj_sid_label_for_link(
    top: &IsisTop,
    level: Level,
    from_vertex: usize,
    to_vertex: usize,
    via_pseudonode: Option<usize>,
) -> Option<u32> {
    let from_sys = *top.lsp_map.get(&level).resolve(from_vertex)?;
    let target_neighbor_id = if let Some(via_v) = via_pseudonode {
        *top.lsp_map.get(&level).resolve_neighbor(via_v)?
    } else {
        let to_sys = *top.lsp_map.get(&level).resolve(to_vertex)?;
        IsisNeighborId::from_sys_id(&to_sys, 0)
    };

    // Walk every non-pseudonode fragment originated by `from_sys` at
    // this level. With send-side LSP fragmentation a router spreads
    // its TLV 22 (ExtIsReach) entries across fragments 0..N, so the
    // adjacency carrying the adj-SID can live in any of them. Frag-0-
    // only would miss SIDs for any adjacency whose IS-reach entry the
    // packer placed in a higher fragment.
    for (lsp_id, lsa) in top.lsdb.get(&level).iter() {
        if lsp_id.sys_id() != from_sys || lsp_id.is_pseudo() {
            continue;
        }
        for tlv in &lsa.lsp.tlvs {
            let IsisTlv::ExtIsReach(reach) = tlv else {
                continue;
            };
            for entry in &reach.entries {
                if entry.neighbor_id != target_neighbor_id {
                    continue;
                }
                for sub in &entry.subs {
                    match sub {
                        neigh::IsisSubTlv::AdjSid(adj) => {
                            if let Some(l) = resolve_sid_to_label(
                                top,
                                level,
                                &from_sys,
                                &adj.sid,
                                SrBlockKind::Local,
                            ) {
                                return Some(l);
                            }
                        }
                        neigh::IsisSubTlv::LanAdjSid(lan_adj) => {
                            let Some(to_sys) = top.lsp_map.get(&level).resolve(to_vertex) else {
                                continue;
                            };
                            if &lan_adj.system_id == to_sys
                                && let Some(l) = resolve_sid_to_label(
                                    top,
                                    level,
                                    &from_sys,
                                    &lan_adj.sid,
                                    SrBlockKind::Local,
                                )
                            {
                                return Some(l);
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    None
}

/// Translate a TI-LFA repair list from `spf::tilfa()` into an
/// MPLS label stack. Returns None when any segment fails to resolve
/// — we refuse to install a partial stack since the resulting label
/// path would diverge from the post-convergence path the algorithm
/// computed.
fn repair_segments_to_mpls_labels(
    top: &IsisTop,
    level: Level,
    segments: &[spf::SrSegment],
) -> Option<Vec<rib::Label>> {
    let mut labels = Vec::with_capacity(segments.len());
    for (idx, seg) in segments.iter().enumerate() {
        let resolved = match seg {
            spf::SrSegment::NodeSid(v) => node_sid_label_for_vertex(top, level, *v),
            spf::SrSegment::AdjSid(from, to, via) => {
                adj_sid_label_for_link(top, level, *from, *to, *via)
            }
        };
        let Some(label) = resolved else {
            tracing::debug!(
                "[tilfa] {level:?} repair segment[{idx}] {seg:?} failed to resolve to MPLS label; \
                 dropping repair stack (partial: {labels:?})"
            );
            return None;
        };
        labels.push(rib::Label::Explicit(label));
    }
    tracing::debug!("[tilfa] {level:?} repair segments resolved: {segments:?} -> {labels:?}");
    Some(labels)
}

/// Per-destination TI-LFA repair computation. For every destination
/// in `spf_result` that isn't `source` and has a single primary
/// first-hop (ECMP at the SPF level is skipped — see PR #547 for the
/// design rationale), call `spf::tilfa()` to compute the post-conv
/// repair list. The returned map is keyed by destination vertex id.
pub(super) fn tilfa_repair_path(
    graph: &spf::Graph,
    lsp_map: &LspMap,
    source: usize,
    spf_result: &BTreeMap<usize, spf::Path>,
) -> BTreeMap<usize, Vec<spf::RepairPath>> {
    let mut tilfa_result = BTreeMap::new();

    for (d, path) in spf_result.iter() {
        // Source is skipped.
        if *d == source {
            continue;
        }
        // ECMP is skipped.
        if path.paths.len() > 1 {
            continue;
        }
        // Pseudonode is skipped — no destination prefix to install.
        if lsp_map.is_pseudo(*d) {
            continue;
        }

        // X — the protected element. For a P2P first-hop this is the
        // physical neighbor router. For a LAN first-hop the primary
        // path is `[PN, N, ...]`; the pseudonode is just a modeling
        // artifact for the LAN segment, and excluding it alone gives
        // (LAN-)link-protection (N keeps every physical edge to R1/R2/
        // etc., so P-space and Q-space collapse and the repair list
        // ends up shorter than P2P's). Advance past the pseudonode to
        // `first[1]` so LAN matches P2P's node-protection model, and
        // so that a destination equal to the physical neighbor is
        // skipped via the empty-modified-SPF path (same as P2P, where
        // `d == x` makes `spf::tilfa` return `vec![]`).
        let first = &path.paths[0];
        if first.is_empty() {
            continue;
        }
        let x = if graph.get(&first[0]).is_some_and(|v| v.is_pseudo_node()) {
            // `[PN]` alone (destination is the pseudonode itself)
            // shouldn't happen for a real destination, but fall back
            // to the pseudonode so we don't index past the end.
            first.get(1).copied().unwrap_or(first[0])
        } else {
            first[0]
        };

        let repair_paths = spf::tilfa(graph, source, *d, &[x]);
        if !repair_paths.is_empty() {
            tilfa_result.insert(*d, repair_paths);
        }
    }
    tilfa_result
}
