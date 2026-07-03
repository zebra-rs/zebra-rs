use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use isis_packet::neigh;
use isis_packet::srv6::EncapType;
use isis_packet::{Algo, IsisNeighborId, IsisSysId, IsisTlv, SidLabelValue};

use crate::rib;
use crate::spf;
use crate::spf::srv6::{CsidBits, RepairSeg, pack_carriers, sid_bits, sid_block};

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
    algo: Option<u8>,
    rp: &spf::RepairPath,
) -> Option<RepairPathSrv6> {
    let lsp_map = top.lsp_map.get(&level);
    let mut parts: Vec<RepairSeg> = Vec::with_capacity(rp.segs.len());
    for (idx, seg) in rp.segs.iter().enumerate() {
        let resolved = match seg {
            spf::SrSegment::NodeSid(v) => {
                // REPLACE-C-SID SIDs are only valid inside packed C-SID
                // containers (RFC 9800 §6.4) — as a plain 128-bit repair
                // segment the endpoint would misread the neighbouring
                // list entries as containers. No compression-aware
                // repair encoder exists, so such a hop is unprotectable.
                node_sid_info(top, level, *v, algo)
                    .filter(|info| !info.behavior.is_end_replace_csid())
                    .map(|info| RepairSeg {
                        sid: info.sid,
                        landing: *v,
                        csid: csid_bits_end(&info),
                    })
            }
            spf::SrSegment::AdjSid(from, to, via) => {
                srv6_endx_sid_for_link(top, level, *from, *to, *via, algo)
                    .filter(|endx| !endx.behavior.is_endx_replace_csid())
                    .map(|endx| RepairSeg {
                        sid: endx.sid,
                        landing: *to,
                        csid: csid_bits_endx(&endx, *from),
                    })
            }
        };
        let Some(part) = resolved else {
            tracing::debug!(
                "[tilfa] {level:?} repair segment[{idx}] {seg:?} failed to resolve to an SRv6 \
                 SID; dropping repair list (partial: {parts:?})"
            );
            return None;
        };
        parts.push(part);
    }
    let segs = pack_carriers(&parts);

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

/// Resolve `vertex`'s SRv6 node (End) SID for `algo`: the base
/// (algo-0) End SID from `srv6_end_map` when `algo` is `None`, or the
/// per-Flex-Algorithm End SID from `peer_algo_srv6` when `Some(n)`.
///
/// Per-algo node segments are what keep a Flex-Algo TI-LFA repair list
/// inside the algo-N topology: each node-SID hop routes to that node's
/// algo-N locator (installed by the per-algo IPv6 RIB build), so the
/// repair traffic follows the algo-N constrained paths rather than the
/// unconstrained algo-0 ones. Adjacency (End.X) segments prefer the
/// peer's algo-N End.X (see `srv6_endx_sid_for_link`) and fall back to
/// the algo-0 End.X — the final single hop into the repair link.
fn node_sid_info(
    top: &IsisTop,
    level: Level,
    vertex: usize,
    algo: Option<u8>,
) -> Option<super::srv6::Srv6EndSidInfo> {
    let sys_id = top.lsp_map.get(&level).resolve(vertex)?;
    match algo {
        None => top.srv6_end_map.get(&level).get(sys_id).cloned(),
        Some(n) => top
            .peer_algo_srv6
            .get(&level)
            .get(sys_id)
            .and_then(|m| m.get(&n))
            .map(|loc| loc.end.clone()),
    }
}

/// SRv6 End.X SID as advertised in an IS-reach sub-TLV: the SID plus
/// the endpoint behavior and SID structure the carrier packer needs.
#[derive(Debug, Clone)]
struct Srv6EndXInfo {
    sid: Ipv6Addr,
    behavior: isis_packet::Behavior,
    structure: Option<isis_packet::IsisSub2SidStructure>,
}

fn endx_structure(sub2s: &[isis_packet::IsisSub2Tlv]) -> Option<isis_packet::IsisSub2SidStructure> {
    sub2s.iter().find_map(|s2| {
        if let isis_packet::IsisSub2Tlv::SidStructure(st) = s2 {
            Some(st.clone())
        } else {
            None
        }
    })
}

/// Look up the SRv6 End.X SID `from` advertises for the link to `to`
/// — the SRv6 sibling of `adj_sid_label_for_link`. For LAN
/// adjacencies (`via_pseudonode = Some(pn)`) the IS Reach entry's
/// neighbor_id matches the pseudonode and the LAN End.X sub-TLV's
/// `system_id` field identifies the LAN member; for P2P adjacencies
/// the neighbor_id is `(to_sys, 0)` and any End.X sub-TLV under it
/// qualifies (RFC 9352 §8.1 / §8.2).
///
/// `want` selects the algorithm: `None` (or no per-algo match found)
/// returns the algo-0 (`Spf`) End.X; `Some(n)` prefers the
/// Algorithm-`n` End.X and falls back to algo-0 when the advertiser
/// hasn't originated a per-algo End.X (older peer). The advertiser now
/// emits one End.X per algo, so this must filter by algo rather than
/// taking the first.
fn srv6_endx_sid_for_link(
    top: &IsisTop,
    level: Level,
    from_vertex: usize,
    to_vertex: usize,
    via_pseudonode: Option<usize>,
    want: Option<u8>,
) -> Option<Srv6EndXInfo> {
    let from_sys = *top.lsp_map.get(&level).resolve(from_vertex)?;
    let target_neighbor_id = if let Some(via_v) = via_pseudonode {
        *top.lsp_map.get(&level).resolve_neighbor(via_v)?
    } else {
        let to_sys = *top.lsp_map.get(&level).resolve(to_vertex)?;
        IsisNeighborId::from_sys_id(&to_sys, 0)
    };
    let to_sys = top.lsp_map.get(&level).resolve(to_vertex).copied();

    // Preferred (algo-N) and fallback (algo-0) matches, collected over
    // the whole walk so the order of End.X sub-TLVs doesn't matter.
    let mut algo_n: Option<Srv6EndXInfo> = None;
    let mut algo_0: Option<Srv6EndXInfo> = None;
    let want = want.map(Algo::FlexAlgo);

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
                    let (algo, info) = match sub {
                        neigh::IsisSubTlv::Srv6EndXSid(endx) => (
                            endx.algo,
                            Srv6EndXInfo {
                                sid: endx.sid,
                                behavior: endx.behavior,
                                structure: endx_structure(&endx.sub2s),
                            },
                        ),
                        neigh::IsisSubTlv::Srv6LanEndXSid(lan_endx) => {
                            // LAN End.X identifies its member by system_id.
                            if to_sys.as_ref() != Some(&lan_endx.system_id) {
                                continue;
                            }
                            (
                                lan_endx.algo,
                                Srv6EndXInfo {
                                    sid: lan_endx.sid,
                                    behavior: lan_endx.behavior,
                                    structure: endx_structure(&lan_endx.sub2s),
                                },
                            )
                        }
                        _ => continue,
                    };
                    if Some(algo) == want && algo_n.is_none() {
                        algo_n = Some(info);
                    } else if algo == Algo::Spf && algo_0.is_none() {
                        algo_0 = Some(info);
                    }
                }
            }
        }
    }
    algo_n.or(algo_0)
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

/// Plan the TI-LFA targets from the primary SPF result: every
/// destination that isn't `source`, has a single primary first-hop
/// (ECMP at the SPF level is skipped — see PR #547 for the design
/// rationale), and isn't a pseudonode, paired with the protected
/// vertex X. Pure planning — the SPF work happens in
/// `spf::tilfa_compute`.
pub(super) fn tilfa_targets(
    graph: &spf::Graph,
    lsp_map: &LspMap,
    source: usize,
    spf_result: &BTreeMap<usize, spf::Path>,
) -> Vec<spf::TilfaTarget> {
    let mut targets = Vec::new();

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
        // `d == x` yields no PC path and an empty repair list).
        let Some(first) = path.paths.first() else {
            continue;
        };
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

        targets.push(spf::TilfaTarget { d: *d, x });
    }
    targets
}

/// Per-destination TI-LFA repair computation: plan the targets, then
/// hand them to `spf::tilfa_compute`, which schedules the P/Q/PC SPF
/// jobs per the configured compute mode (serial by default). The
/// returned map is keyed by destination vertex id; destinations with
/// no computable repair are absent.
pub(super) fn tilfa_repair_path(
    graph: &spf::Graph,
    lsp_map: &LspMap,
    source: usize,
    spf_result: &BTreeMap<usize, spf::Path>,
    mode: spf::TilfaComputeMode,
) -> (BTreeMap<usize, Vec<spf::RepairPath>>, spf::TilfaStats) {
    let targets = tilfa_targets(graph, lsp_map, source, spf_result);
    spf::tilfa_compute(graph, source, spf_result, &targets, mode)
}

/// Carrier metadata for a uN: the identifier is the locator-node
/// portion (bits `[lb, lb+ln)`).
fn csid_bits_end(info: &super::srv6::Srv6EndSidInfo) -> Option<CsidBits> {
    if !info.behavior.is_end_next_csid() {
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

/// Carrier metadata for a uA: the identifier is the function portion
/// (bits `[lb+ln, lb+ln+fun)`); the node bits are implicit because a
/// packed uA only becomes active once the packet sits on its owner.
fn csid_bits_endx(endx: &Srv6EndXInfo, owner: usize) -> Option<CsidBits> {
    if !endx.behavior.is_endx_next_csid() {
        return None;
    }
    let st = endx.structure.as_ref()?;
    let (lb, ln, fun) = (st.lb_len as u32, st.ln_len as u32, st.fun_len as u32);
    if fun == 0 || lb + ln + fun > 128 {
        return None;
    }
    Some(CsidBits {
        block: sid_block(endx.sid, st.lb_len),
        lb: st.lb_len,
        id: sid_bits(endx.sid, lb + ln, fun),
        width: st.fun_len,
        lib_owner: Some(owner),
    })
}

#[cfg(test)]
mod carrier_tests {
    use super::*;

    fn st(lb: u8, ln: u8, fun: u8) -> isis_packet::IsisSub2SidStructure {
        isis_packet::IsisSub2SidStructure {
            lb_len: lb,
            ln_len: ln,
            fun_len: fun,
            arg_len: 0,
        }
    }

    fn un(sid: &str, landing: usize) -> RepairSeg {
        let info = crate::isis::srv6::Srv6EndSidInfo {
            sid: sid.parse().unwrap(),
            behavior: isis_packet::Behavior::EndCSID,
            structure: Some(st(32, 16, 16)),
        };
        RepairSeg {
            sid: info.sid,
            landing,
            csid: csid_bits_end(&info),
        }
    }

    fn ua(sid: &str, owner: usize, landing: usize) -> RepairSeg {
        let endx = Srv6EndXInfo {
            sid: sid.parse().unwrap(),
            behavior: isis_packet::Behavior::EndXCSID,
            structure: Some(st(32, 16, 16)),
        };
        RepairSeg {
            sid: endx.sid,
            landing,
            csid: csid_bits_endx(&endx, owner),
        }
    }

    fn classic(sid: &str, landing: usize) -> RepairSeg {
        RepairSeg {
            sid: sid.parse().unwrap(),
            landing,
            csid: None,
        }
    }

    // The observed @tilfa_srv6 repair: uN(r1) + uA(r1->r2) + uA(r2->r3)
    // collapses into one carrier — block, node id, two functions.
    #[test]
    fn packs_un_ua_ua_into_one_carrier() {
        let parts = [
            un("fcbb:bbbb:5::", 1),
            ua("fcbb:bbbb:5:e003::", 1, 2),
            ua("fcbb:bbbb:6:e002::", 2, 3),
        ];
        let segs = pack_carriers(&parts);
        assert_eq!(
            segs,
            vec!["fcbb:bbbb:5:e003:e002::".parse::<Ipv6Addr>().unwrap()]
        );
    }

    // A classic segment splits the list: carrier, full SID, and the
    // trailing uA can't pack (its owner isn't where the previous
    // segment lands the packet for LIB purposes — it is, actually, so
    // it opens a fresh single-id carrier and re-emits its full SID).
    #[test]
    fn classic_segment_breaks_the_carrier() {
        let parts = [
            un("fcbb:bbbb:5::", 1),
            ua("fcbb:bbbb:5:e003::", 1, 2),
            classic("2001:db8:9::1", 3),
            ua("fcbb:bbbb:7:e001::", 3, 4),
        ];
        let segs = pack_carriers(&parts);
        assert_eq!(
            segs,
            vec![
                "fcbb:bbbb:5:e003::".parse::<Ipv6Addr>().unwrap(),
                "2001:db8:9::1".parse().unwrap(),
                "fcbb:bbbb:7:e001::".parse().unwrap(),
            ]
        );
    }

    // A lone uN stays in its advertised full form (identical bytes for
    // a single-id carrier, but the rule also covers the lone-uA case).
    #[test]
    fn single_segment_is_emitted_as_full_sid() {
        let parts = [un("fcbb:bbbb:5::", 1)];
        assert_eq!(
            pack_carriers(&parts),
            vec!["fcbb:bbbb:5::".parse::<Ipv6Addr>().unwrap()]
        );
    }

    // A uA whose owner is NOT where the previous segment lands cannot
    // be packed (its LIB identifier would be looked up on the wrong
    // node) — it falls back to the full, globally-routable SID.
    #[test]
    fn ua_without_continuity_falls_back_to_full_sid() {
        let parts = [un("fcbb:bbbb:5::", 1), ua("fcbb:bbbb:7:e001::", 3, 4)];
        let segs = pack_carriers(&parts);
        assert_eq!(
            segs,
            vec![
                "fcbb:bbbb:5::".parse::<Ipv6Addr>().unwrap(),
                "fcbb:bbbb:7:e001::".parse().unwrap(),
            ]
        );
    }

    // A leading uA (no predecessor) must stay full-SID: the initial DA
    // is routed by the IGP and a LIB identifier is not routable.
    #[test]
    fn leading_ua_stays_full_sid() {
        let parts = [ua("fcbb:bbbb:5:e003::", 1, 2), un("fcbb:bbbb:6::", 2)];
        let segs = pack_carriers(&parts);
        assert_eq!(
            segs,
            vec![
                "fcbb:bbbb:5:e003::".parse::<Ipv6Addr>().unwrap(),
                "fcbb:bbbb:6::".parse().unwrap(),
            ]
        );
    }

    // A different locator block starts a new carrier.
    #[test]
    fn block_change_splits_carriers() {
        let parts = [
            un("fcbb:bbbb:5::", 1),
            un("fcbb:bbbb:6::", 2),
            un("fcbb:cccc:7::", 3),
            un("fcbb:cccc:8::", 4),
        ];
        let segs = pack_carriers(&parts);
        assert_eq!(
            segs,
            vec![
                "fcbb:bbbb:5:6::".parse::<Ipv6Addr>().unwrap(),
                "fcbb:cccc:7:8::".parse().unwrap(),
            ]
        );
    }

    // Capacity: a 32-bit block fits six 16-bit identifiers; the
    // seventh spills into a second carrier.
    #[test]
    fn full_carrier_spills_into_a_second() {
        let parts: Vec<RepairSeg> = (1..=7)
            .map(|i| un(&format!("fcbb:bbbb:{i}::"), i))
            .collect();
        let segs = pack_carriers(&parts);
        assert_eq!(
            segs,
            vec![
                "fcbb:bbbb:1:2:3:4:5:6".parse::<Ipv6Addr>().unwrap(),
                "fcbb:bbbb:7::".parse().unwrap(),
            ]
        );
    }

    // Zero identifiers would read as end-of-carrier on the wire; they
    // are never packed.
    #[test]
    fn zero_identifier_is_never_packed() {
        let parts = [un("fcbb:bbbb:5::", 1), un("fcbb:bbbb::", 2)];
        let segs = pack_carriers(&parts);
        assert_eq!(
            segs,
            vec![
                "fcbb:bbbb:5::".parse::<Ipv6Addr>().unwrap(),
                "fcbb:bbbb::".parse().unwrap(),
            ]
        );
    }

    // Classic behaviors (no NEXT-C-SID) never produce carrier bits, so
    // the classic-SID feature keeps its one-SID-per-segment encoding.
    #[test]
    fn classic_behavior_yields_no_csid_bits() {
        let info = crate::isis::srv6::Srv6EndSidInfo {
            sid: "fcbb:bbbb:5::".parse().unwrap(),
            behavior: isis_packet::Behavior::End,
            structure: Some(st(40, 8, 16)),
        };
        assert_eq!(csid_bits_end(&info), None);
        let endx = Srv6EndXInfo {
            sid: "fcbb:bbbb:5:e003::".parse().unwrap(),
            behavior: isis_packet::Behavior::EndX,
            structure: Some(st(40, 8, 16)),
        };
        assert_eq!(csid_bits_endx(&endx, 1), None);
    }
}
