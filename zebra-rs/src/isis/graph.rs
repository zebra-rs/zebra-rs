use std::collections::{BTreeMap, BTreeSet};

use isis_packet::neigh;
use isis_packet::{
    IsisLsp, IsisLspId, IsisNeighborId, IsisSysId, IsisTlv, IsisTlvExtIpReachEntry,
    IsisTlvExtIsReachEntry, IsisTlvIpv6ReachEntry, SidLabelValue,
};

use crate::spf;

use crate::flex_algo::local_link_affinity;

use super::affinity_map::AffinityMap;
use super::config::MtId;
use super::flex_algo::{
    FadConstraints, FadMetricType, LinkAttrs, Pruned, advertised_link_attrs, link_prune_reason,
};
use super::inst::IsisTop;
use super::level::Level;
use super::link::{IsisLink, IsisLinks};
use super::lsdb::{Lsa, Lsdb};

pub struct ReachMap<E> {
    map: BTreeMap<IsisSysId, Vec<E>>,
}

impl<E> Default for ReachMap<E> {
    fn default() -> Self {
        Self {
            map: BTreeMap::new(),
        }
    }
}

impl<E> ReachMap<E> {
    pub fn get(&self, key: &IsisSysId) -> Option<&Vec<E>> {
        self.map.get(key)
    }

    pub fn insert(&mut self, key: IsisSysId, value: Vec<E>) -> Option<Vec<E>> {
        self.map.insert(key, value)
    }

    pub fn remove(&mut self, key: &IsisSysId) -> Option<Vec<E>> {
        self.map.remove(key)
    }
}

pub type ReachMapV4 = ReachMap<IsisTlvExtIpReachEntry>;
pub type ReachMapV6 = ReachMap<IsisTlvIpv6ReachEntry>;

/// Stable mapping between IS-IS LSP identities and the integer
/// vertex ids used by the SPF graph. Keyed by `IsisNeighborId`
/// (sys_id + pseudo_id) so router LSPs and pseudonode LSPs from
/// the same DIS get distinct ids; LSP fragments collapse to the
/// same vertex because the fragment byte is not part of the key.
///
/// A parallel `val_sys` Vec keeps the existing `resolve(id) ->
/// &IsisSysId` accessor working — every entry in `val` has its
/// sys-id portion mirrored at the same index. Pseudonode-aware
/// consumers should use `resolve_neighbor` to see the full
/// `IsisNeighborId` (sys_id + pseudo_id).
#[derive(Default, Clone)]
pub struct LspMap {
    map: BTreeMap<IsisNeighborId, usize>,
    val: Vec<IsisNeighborId>,
    val_sys: Vec<IsisSysId>,
}

impl LspMap {
    /// Allocate or fetch the vertex id for a (sys_id, pseudo_id)
    /// tuple. Use `get_sys` for the common real-router case.
    pub fn get(&mut self, neighbor_id: &IsisNeighborId) -> usize {
        if let Some(index) = self.map.get(neighbor_id) {
            *index
        } else {
            let index = self.val.len();
            self.map.insert(*neighbor_id, index);
            self.val.push(*neighbor_id);
            self.val_sys.push(neighbor_id.sys_id());
            index
        }
    }

    /// Allocate or fetch the vertex id for a real router (the
    /// pseudo_id = 0 case). Pseudonode LSPs must use `get` with
    /// the full neighbor id.
    pub fn get_sys(&mut self, sys_id: &IsisSysId) -> usize {
        self.get(&IsisNeighborId::from_sys_id(sys_id, 0))
    }

    /// Resolve the vertex id back to its sys-id portion. For
    /// pseudonode entries this returns the DIS's sys-id (the
    /// pseudo_id byte is discarded); use `resolve_neighbor` if
    /// you need to distinguish.
    pub fn resolve(&self, id: usize) -> Option<&IsisSysId> {
        self.val_sys.get(id)
    }

    /// Pseudonode-aware resolve. Returns the full neighbor id
    /// (sys_id + pseudo_id). Real router entries have pseudo_id
    /// == 0.
    pub fn resolve_neighbor(&self, id: usize) -> Option<&IsisNeighborId> {
        self.val.get(id)
    }

    /// True if `id` corresponds to an IS-IS pseudonode entry.
    /// Used by RIB walks to skip transit-only vertices.
    pub fn is_pseudo(&self, id: usize) -> bool {
        self.val.get(id).is_some_and(|n| n.pseudo_id() != 0)
    }
}

/// Build SPF graph from IS-IS LSDB
pub fn graph(
    top: &mut IsisTop,
    level: Level,
) -> (spf::Graph, Option<usize>, BTreeMap<u32, IsisSysId>) {
    let mut graph = spf::Graph::new();
    let mut source_node = None;
    let mut adjacency_sids = BTreeMap::new();

    // Collect every LSP (router and pseudonode) — pseudonode LSPs
    // become VertexType::PseudoNode entries in the SPF graph so
    // TI-LFA can surface LAN identity. Fragments collapse into one
    // entry because LspMap keys by IsisNeighborId (no fragment byte).
    let mut nodes_to_process = Vec::new();
    for (_, lsa) in top.lsdb.get(&level).iter() {
        // RFC 9666 §6.1: Inside Routers MUST ignore the Proxy LSP in
        // their own SPF — they see the area's real topology, and
        // consuming the abstraction alongside it could loop. (The
        // Proxy LSP only exists at L2; the check is inert at L1.)
        if top.config.area_proxy && top.area_proxy.proxy_sys_id == Some(lsa.lsp.lsp_id.sys_id()) {
            continue;
        }
        let neighbor_id = lsa.lsp.lsp_id.neighbor_id();
        let is_originated = lsa.originated;
        let lsp = lsa.lsp.clone();
        nodes_to_process.push((neighbor_id, is_originated, lsp));
    }

    // Now process the nodes without holding an immutable borrow on LSDB
    for (neighbor_id, is_originated, lsp) in nodes_to_process.iter() {
        let node_id = top.lsp_map.get_mut(&level).get(neighbor_id);

        // Figure out source id.
        if *is_originated && !lsp.lsp_id.is_pseudo() {
            source_node = Some(node_id);
            collect_adjacency_sids(lsp, &mut adjacency_sids);
        }

        // Create graph vertex
        let vertex = create_graph_vertex(top, level, node_id, neighbor_id, lsp);
        graph.insert(node_id, vertex);
    }

    // Build a local-adjacency → ifindex map for this level. Each
    // entry corresponds to one of our own ExtIsReach edges; the key
    // is the IsisNeighborId carried in that edge's TLV. For P2P
    // adjacencies the key is (peer_sys_id, 0); for LAN adjacencies
    // it is the (DIS_sys_id, pseudo_id) of the LAN's pseudonode. The
    // graph builder uses this to stamp link_id = ifindex onto edges
    // emitted from our own router LSP, so the rib-builder can resolve
    // back to a specific local interface instead of iterating every
    // top.links entry.
    //
    // Case P4 (two NICs on the same LAN) collapses both interfaces to
    // a single key here — only the last-inserted ifindex survives, and
    // SPF installs one nexthop. Accepted per the design decision.
    let mut local_adj_to_ifindex: BTreeMap<IsisNeighborId, u32> = BTreeMap::new();
    for (ifindex, link) in top.links.iter() {
        if let Some((adj, _)) = link.state.adj.get(&level) {
            local_adj_to_ifindex.insert(*adj, *ifindex);
        }
    }

    // RFC 9666 §3.2 context for an Inside Router's L2 SPF: the inside
    // set (live L1 router LSPs) classifies every edge as intra- or
    // inter-area for the packed-metric precedence, and the Proxy
    // System ID marks outside routers' proxy-pointing adjacencies for
    // resolution. None when Area Proxy isn't shaping this SPF (the
    // Proxy LSP vertex itself is already excluded above).
    let proxy_ctx: Option<(std::collections::BTreeSet<IsisSysId>, IsisSysId)> = if level
        == Level::L2
        && top.config.area_proxy
        && let Some(proxy_id) = top.area_proxy.proxy_sys_id
    {
        Some((
            super::area_proxy::inside_routers(top.lsdb.get(&Level::L1)),
            proxy_id,
        ))
    } else {
        None
    };

    // Outside routers advertise their boundary adjacency toward the
    // Proxy System ID, not toward the Inside Edge Router that actually
    // holds it — which would fail the two-way check in our (inside)
    // SPF. Pre-collect, per outside neighbor id, the inside vertices
    // advertising an adjacency to it, so those proxy-pointing edges
    // can be resolved back to the real edge routers below.
    let mut boundary_rev: BTreeMap<IsisNeighborId, Vec<usize>> = BTreeMap::new();
    if let Some((inside, proxy_id)) = proxy_ctx.as_ref() {
        for (neighbor_id, _, lsp) in nodes_to_process.iter() {
            if !inside.contains(&neighbor_id.sys_id()) {
                continue;
            }
            let from_id = top.lsp_map.get_mut(&level).get(neighbor_id);
            for tlv in &lsp.tlvs {
                if let IsisTlv::ExtIsReach(ext_reach) = tlv {
                    for entry in &ext_reach.entries {
                        let to_sys = entry.neighbor_id.sys_id();
                        if !inside.contains(&to_sys) && to_sys != *proxy_id {
                            boundary_rev
                                .entry(entry.neighbor_id)
                                .or_default()
                                .push(from_id);
                        }
                    }
                }
            }
        }
    }

    // Process links.
    for (neighbor_id, is_originated, lsp) in nodes_to_process.iter() {
        let node_id = top.lsp_map.get_mut(&level).get(neighbor_id);

        // link_id is meaningful only for edges that came out of our
        // own router LSP — that's the SPF's "first-hop" slot. Edges
        // from other routers' LSPs (and from our own pseudonode LSP)
        // carry link_id = 0; SPF propagates it untouched but the
        // rib-builder only consumes first_hop_links anyway.
        let own_router_lsp = *is_originated && !lsp.lsp_id.is_pseudo();

        for tlv in &lsp.tlvs {
            if let IsisTlv::ExtIsReach(ext_reach) = tlv {
                for entry in &ext_reach.entries {
                    let neighbor_lsp_id: IsisLspId = entry.neighbor_id.into();

                    // RFC 9666 §3.2: classify the edge and resolve
                    // proxy-pointing adjacencies.
                    let mut metric = entry.metric;
                    if let Some((inside, proxy_id)) = proxy_ctx.as_ref() {
                        if entry.neighbor_id.sys_id() == *proxy_id {
                            // An outside router's adjacency toward the
                            // proxy: materialize an inter-area edge to
                            // every Inside Edge Router advertising this
                            // outside router, restoring two-way
                            // connectivity for the inside SPF.
                            let cost = super::area_proxy::encode_inter_metric(entry.metric);
                            for &edge_id in boundary_rev.get(neighbor_id).into_iter().flatten() {
                                let link = spf::Link::with_id(node_id, edge_id, cost, 0);
                                if let Some(from) = graph.get_mut(&node_id) {
                                    from.olinks.push(link.clone());
                                }
                                if let Some(to) = graph.get_mut(&edge_id) {
                                    to.ilinks.push(link);
                                }
                            }
                            continue;
                        }
                        let from_inside = inside.contains(&neighbor_id.sys_id());
                        let to_inside = inside.contains(&entry.neighbor_id.sys_id());
                        metric = if from_inside && to_inside {
                            super::area_proxy::encode_intra_metric(metric)
                        } else {
                            super::area_proxy::encode_inter_metric(metric)
                        };
                    }

                    if top.lsdb.get(&level).get(&neighbor_lsp_id).is_none() {
                        continue;
                    }
                    let to_id = top
                        .lsp_map
                        .get_mut(&level)
                        .get(&neighbor_lsp_id.neighbor_id());

                    let link_id = if own_router_lsp {
                        local_adj_to_ifindex
                            .get(&entry.neighbor_id)
                            .copied()
                            .unwrap_or(0)
                    } else {
                        0
                    };

                    let link = spf::Link::with_id(node_id, to_id, metric, link_id);
                    if let Some(from_id) = graph.get_mut(&node_id) {
                        from_id.olinks.push(link.clone());
                    }
                    if let Some(to_id) = graph.get_mut(&to_id) {
                        to_id.ilinks.push(link);
                    }
                }
            }
        }
    }

    (graph, source_node, adjacency_sids)
}

/// Create a graph vertex from an LSP
fn create_graph_vertex(
    top: &mut IsisTop,
    level: Level,
    node_id: usize,
    neighbor_id: &IsisNeighborId,
    lsp: &IsisLsp,
) -> spf::Vertex {
    let sys_id = neighbor_id.sys_id();
    let is_pseudo = lsp.lsp_id.is_pseudo();

    let hostname = top
        .hostname
        .get(&level)
        .get(&sys_id)
        .map(|(hostname, _)| hostname.clone())
        .unwrap_or_else(|| sys_id.to_string());

    let hostname = if is_pseudo {
        format!("{}.{}", hostname, neighbor_id.pseudo_id())
    } else {
        hostname
    };

    spf::Vertex {
        id: node_id,
        name: hostname,
        sys_id: sys_id.to_string(),
        vtype: if is_pseudo {
            spf::VertexType::PseudoNode
        } else {
            spf::VertexType::Node
        },
        ..Default::default()
    }
}

/// Collect adjacency SIDs from our originated LSP
fn collect_adjacency_sids(lsp: &IsisLsp, sids: &mut BTreeMap<u32, IsisSysId>) {
    for tlv in &lsp.tlvs {
        if let IsisTlv::ExtIsReach(ext_reach) = tlv {
            for entry in &ext_reach.entries {
                for sub in &entry.subs {
                    if let neigh::IsisSubTlv::LanAdjSid(adj_sid) = sub
                        && let SidLabelValue::Label(label) = adj_sid.sid
                    {
                        sids.insert(label, adj_sid.system_id);
                    }
                    if let neigh::IsisSubTlv::AdjSid(adj_sid) = sub
                        && let SidLabelValue::Label(label) = adj_sid.sid
                    {
                        sids.insert(label, entry.neighbor_id.sys_id());
                    }
                }
            }
        }
    }
}

/// Build the MT 2 (IPv6 unicast) SPF graph. Mirrors `graph()` but
/// walks `IsisTlv::MtIsReach` entries with mt=2 and includes only
/// peers whose TLV 229 named MT 2. Our own originated LSP is always
/// included — local config gates whether this function is even
/// called.
pub fn graph_mt2(
    top: &mut IsisTop,
    level: Level,
) -> (spf::Graph, Option<usize>, BTreeMap<u32, IsisSysId>) {
    let mut graph = spf::Graph::new();
    let mut source_node = None;
    let adjacency_sids = BTreeMap::new(); // SR-MPLS adj SIDs are MT 0 only

    let mut nodes_to_process = Vec::new();
    for (_, lsa) in top.lsdb.get(&level).iter() {
        // Same RFC 9666 §6.1 Proxy-LSP exclusion as `graph()`.
        if top.config.area_proxy && top.area_proxy.proxy_sys_id == Some(lsa.lsp.lsp_id.sys_id()) {
            continue;
        }
        let neighbor_id = lsa.lsp.lsp_id.neighbor_id();
        let is_originated = lsa.originated;
        let is_pseudo = lsa.lsp.lsp_id.is_pseudo();

        // MT 2 capability is a per-router attribute (TLV 229);
        // pseudonodes don't carry it. Include all pseudonode LSPs
        // unconditionally — their attached-router participation is
        // already gated when the link emission picks neighbours.
        // Real router peers still gate by mt2 capability.
        if !is_originated && !is_pseudo {
            let sys_id = neighbor_id.sys_id();
            let mt2_capable = top
                .mt_membership
                .get(&level)
                .get(&sys_id)
                .map(|set| set.contains(&MtId::Ipv6Unicast))
                .unwrap_or(false);
            if !mt2_capable {
                continue;
            }
        }
        let lsp = lsa.lsp.clone();
        nodes_to_process.push((neighbor_id, is_originated, lsp));
    }

    // Same local-adjacency → ifindex map as graph(). Used to stamp
    // link_id = ifindex onto the first-hop edges emitted from our own
    // router LSP so build_rib_from_spf_v6 can resolve each MT 2 nexthop
    // back to a local interface. Without it every MT 2 edge would carry
    // link_id = 0, which the v6 rib-builder skips — leaving the MT 2
    // IPv6 RIB empty. For LAN adjacencies the key is the
    // (DIS_sys_id, pseudo_id) of the pseudonode.
    let mut local_adj_to_ifindex: BTreeMap<IsisNeighborId, u32> = BTreeMap::new();
    for (ifindex, link) in top.links.iter() {
        if let Some((adj, _)) = link.state.adj.get(&level) {
            local_adj_to_ifindex.insert(*adj, *ifindex);
        }
    }

    for (neighbor_id, is_originated, lsp) in nodes_to_process {
        let node_id = top.lsp_map.get_mut(&level).get(&neighbor_id);
        // Same source rule as graph(): only set when our own router
        // LSP is processed, never a pseudonode we may have originated.
        let own_router_lsp = is_originated && !lsp.lsp_id.is_pseudo();
        if own_router_lsp {
            source_node = Some(node_id);
        }
        let vertex = create_graph_vertex_mt2(
            top,
            level,
            node_id,
            &neighbor_id,
            &lsp,
            own_router_lsp,
            &local_adj_to_ifindex,
        );
        graph.insert(node_id, vertex);
    }

    (graph, source_node, adjacency_sids)
}

fn create_graph_vertex_mt2(
    top: &mut IsisTop,
    level: Level,
    node_id: usize,
    neighbor_id: &IsisNeighborId,
    lsp: &IsisLsp,
    own_router_lsp: bool,
    local_adj_to_ifindex: &BTreeMap<IsisNeighborId, u32>,
) -> spf::Vertex {
    let sys_id = neighbor_id.sys_id();
    let is_pseudo = lsp.lsp_id.is_pseudo();

    let vertex_name = if is_pseudo {
        let dis = top
            .hostname
            .get(&level)
            .get(&sys_id)
            .map(|(hostname, _)| hostname.clone())
            .unwrap_or_else(|| sys_id.to_string());
        format!("PN_{}_{}", dis, neighbor_id.pseudo_id())
    } else {
        top.hostname
            .get(&level)
            .get(&sys_id)
            .map(|(hostname, _)| hostname.clone())
            .unwrap_or_else(|| sys_id.to_string())
    };

    let mut vertex = spf::Vertex {
        id: node_id,
        name: vertex_name,
        sys_id: sys_id.to_string(),
        vtype: if is_pseudo {
            spf::VertexType::PseudoNode
        } else {
            spf::VertexType::Node
        },
        ..Default::default()
    };

    process_outgoing_links_mt2(
        top,
        level,
        node_id,
        lsp,
        own_router_lsp,
        local_adj_to_ifindex,
        &mut vertex.olinks,
    );

    vertex
}

fn process_outgoing_links_mt2(
    top: &mut IsisTop,
    level: Level,
    from_id: usize,
    lsp: &IsisLsp,
    own_router_lsp: bool,
    local_adj_to_ifindex: &BTreeMap<IsisNeighborId, u32>,
    links: &mut Vec<spf::Link>,
) {
    if lsp.lsp_id.is_pseudo() {
        // Pseudonode LSPs do not advertise MtIsReach. Their TLV 22
        // entries list every attached router; in MT 2 we want one
        // edge per attached router that participates in MT 2.
        for tlv in &lsp.tlvs {
            let IsisTlv::ExtIsReach(ext_reach) = tlv else {
                continue;
            };
            for entry in &ext_reach.entries {
                let neighbor_id = entry.neighbor_id;
                let to_sys_id = neighbor_id.sys_id();
                let mt2_capable = top
                    .mt_membership
                    .get(&level)
                    .get(&to_sys_id)
                    .map(|set| set.contains(&MtId::Ipv6Unicast))
                    .unwrap_or(false);
                if !mt2_capable {
                    continue;
                }
                let to_id = top.lsp_map.get_mut(&level).get(&neighbor_id);
                links.push(spf::Link {
                    from: from_id,
                    to: to_id,
                    cost: entry.metric,
                    link_id: 0,
                });
            }
        }
        return;
    }

    // Real router source: walk the MT 2 reach TLVs and emit one
    // edge per entry, no flattening.
    for tlv in &lsp.tlvs {
        if let IsisTlv::MtIsReach(mt_reach) = tlv
            && mt_reach.mt.id() == 2
        {
            for entry in &mt_reach.entries {
                process_neighbor_link_mt2(
                    top,
                    level,
                    from_id,
                    entry,
                    own_router_lsp,
                    local_adj_to_ifindex,
                    links,
                );
            }
        }
    }
}

fn process_neighbor_link_mt2(
    top: &mut IsisTop,
    level: Level,
    from_id: usize,
    entry: &IsisTlvExtIsReachEntry,
    own_router_lsp: bool,
    local_adj_to_ifindex: &BTreeMap<IsisNeighborId, u32>,
    links: &mut Vec<spf::Link>,
) {
    let neighbor_lsp_id: IsisLspId = entry.neighbor_id.into();

    if top.lsdb.get(&level).get(&neighbor_lsp_id).is_none() {
        return;
    }

    // Edge gating differs by neighbour kind:
    //   - Pseudonode targets are unconditional. Pseudonodes do not
    //     advertise MT 2 capability themselves; their attached-router
    //     gating happens above when the PN's olinks are built.
    //   - Real router targets must advertise MT 2; non-MT-2 routers
    //     are not in the MT 2 graph, so emitting an edge to them
    //     would be a dangling reference.
    if !neighbor_lsp_id.is_pseudo() {
        let to_sys_id = neighbor_lsp_id.sys_id();
        let mt2_capable = top
            .mt_membership
            .get(&level)
            .get(&to_sys_id)
            .map(|set| set.contains(&MtId::Ipv6Unicast))
            .unwrap_or(false);
        if !mt2_capable {
            return;
        }
    }

    // link_id is meaningful only for edges out of our own router LSP —
    // the SPF's first-hop slot the v6 rib-builder resolves to a local
    // interface. Edges from other routers' LSPs carry link_id = 0.
    // Mirrors graph()'s legacy ExtIsReach handling.
    let link_id = if own_router_lsp {
        local_adj_to_ifindex
            .get(&entry.neighbor_id)
            .copied()
            .unwrap_or(0)
    } else {
        0
    };

    let to_id = top
        .lsp_map
        .get_mut(&level)
        .get(&neighbor_lsp_id.neighbor_id());
    links.push(spf::Link {
        from: from_id,
        to: to_id,
        cost: entry.metric,
        link_id,
    });
}

/// Build a per-algorithm SPF graph for Flex-Algo `algo`, computed with
/// `constraints`: the *winning* Flexible Algorithm Definition's (RFC 9350
/// §5.3), which every participant selects from the same LSDB — never this
/// router's own configuration, which another router may not share. The
/// result has the same shape as `graph()` so existing `spf::spf`
/// consumers work unchanged.
///
/// Filtering vs the legacy graph:
///   - **Peer participation gate (§5.2):** vertices from non-self
///     LSPs are dropped when the source sys-id is missing from
///     `peer_algos` or has not listed `algo`. The local router is
///     always included — `flex_algo.config[algo]` is the participation
///     signal on our side, and SPF is only called for algos in that
///     map.
///   - **Per-link pruning (§13 and the link-loss rule):** every
///     ExtIsReach edge is filtered through `link_prune_reason` against
///     its affinity and loss as RFC 9479 §4.2 selects them from that
///     edge's own reach entry — ours included, so parallel links are
///     judged each by its own advertisement, as every other router
///     judges them.
///   - **Metric type (§5.1):** `MinUnidirLinkDelay` (metric-type 1)
///     routes on per-link Min delay — local links from
///     `LinkConfig::te_metric.min_delay`, peer links from the Min/Max
///     Link Delay sub-TLV in the link's flex-algo ASLA. A link that
///     advertises no delay is pruned (RFC 9350 §15). IGP uses the reach
///     entry's IGP metric.
///   - Anything the winning definition asks for that this router cannot
///     compute — SRLG exclusion, TE-default, the M flag — never reaches
///     here: selection stops participation instead.
pub fn graph_flex_algo(
    top: &mut IsisTop,
    level: Level,
    algo: u8,
    constraints: &FadConstraints,
) -> (spf::Graph, Option<usize>, BTreeMap<u32, IsisSysId>) {
    let mut graph = spf::Graph::new();
    let mut source_node = None;
    let mut adjacency_sids = BTreeMap::new();
    let self_sys_id = top.config.net.sys_id();

    // First pass: clone every LSP we plan to walk. Mirrors `graph()`
    // so the borrow of `top.lsdb` releases before we start mutating
    // `top.lsp_map` in the second pass. Same fragment-collapse
    // behaviour applies (LspMap keys on IsisNeighborId).
    //
    // Peer-participation filter happens here: drop non-self real
    // routers that haven't listed `algo` in SR-Algorithms. Pseudonode
    // LSPs are always kept — they belong to a real router whose
    // participation is already gated by this filter.
    let peer_algos_at_level = top.peer_algos.get(&level);
    let mut nodes_to_process = Vec::new();
    for (_, lsa) in top.lsdb.get(&level).iter() {
        if !flex_algo_node_included(lsa, peer_algos_at_level, algo) {
            continue;
        }
        let neighbor_id = lsa.lsp.lsp_id.neighbor_id();
        let lsp = lsa.lsp.clone();
        nodes_to_process.push((neighbor_id, lsa.originated, lsp));
    }

    // Vertex construction — identical to graph().
    for (neighbor_id, is_originated, lsp) in nodes_to_process.iter() {
        let node_id = top.lsp_map.get_mut(&level).get(neighbor_id);
        if *is_originated && !lsp.lsp_id.is_pseudo() {
            source_node = Some(node_id);
            collect_adjacency_sids(lsp, &mut adjacency_sids);
        }
        let vertex = create_graph_vertex(top, level, node_id, neighbor_id, lsp);
        graph.insert(node_id, vertex);
    }

    // Our own reach entries, each paired with the interface it advertises:
    // the edge's link_id (its outgoing interface) and its delay.
    let own_ifindex = own_entry_interfaces(
        nodes_to_process
            .iter()
            .filter(|(_, originated, lsp)| *originated && !lsp.lsp_id.is_pseudo())
            .map(|(_, _, lsp)| lsp),
        top.links,
        top.affinity_map,
        level,
    );

    // Edge construction with per-link affinity filtering.
    for (neighbor_id, is_originated, lsp) in nodes_to_process.iter() {
        let node_id = top.lsp_map.get_mut(&level).get(neighbor_id);
        let own_router_lsp = *is_originated && !lsp.lsp_id.is_pseudo();
        let source_sys_id = neighbor_id.sys_id();

        let mut position = 0;
        for tlv in &lsp.tlvs {
            let IsisTlv::ExtIsReach(ext_reach) = tlv else {
                continue;
            };
            for entry_reach in &ext_reach.entries {
                let own_ifx = if own_router_lsp {
                    own_ifindex.get(&(lsp.lsp_id, position)).copied()
                } else {
                    None
                };
                position += 1;
                let neighbor_lsp_id: IsisLspId = entry_reach.neighbor_id.into();

                if top.lsdb.get(&level).get(&neighbor_lsp_id).is_none() {
                    continue;
                }

                if link_prune_reason(&advertised_link_attrs(entry_reach), constraints).is_some() {
                    continue;
                }

                // Edge cost per the FAD metric-type (RFC 9350 §5.1).
                // metric-type 1 routes on the link's Min delay: local
                // links from current config, peer links as RFC 9479 §4.2
                // selects them (`peer_min_delay`) — never a legacy inline
                // value the applicable ASLA did not point to. A link that
                // advertises no delay is pruned (RFC 9350 §15).
                // Everything else uses the IGP metric.
                let cost = if constraints.metric_type == FadMetricType::MinUnidirLinkDelay {
                    let delay = if source_sys_id == self_sys_id {
                        own_ifx
                            .and_then(|ifx| top.links.get(&ifx))
                            .and_then(|link| link.te_metric_effective().min_delay)
                    } else {
                        super::flex_algo::peer_min_delay(entry_reach)
                    };
                    match delay {
                        Some(d) => d,
                        None => continue,
                    }
                } else {
                    entry_reach.metric
                };

                let to_id = top
                    .lsp_map
                    .get_mut(&level)
                    .get(&neighbor_lsp_id.neighbor_id());

                let link_id = own_ifx.unwrap_or(0);

                let link = spf::Link::with_id(node_id, to_id, cost, link_id);
                if let Some(from) = graph.get_mut(&node_id) {
                    from.olinks.push(link.clone());
                }
                if let Some(to) = graph.get_mut(&to_id) {
                    to.ilinks.push(link);
                }
            }
        }
    }

    (graph, source_node, adjacency_sids)
}

/// This router's own reach entries, each paired with the interface that
/// produced it, keyed by fragment and position among the fragment's
/// IS-reach entries. Parallel links to one neighbour share its neighbour
/// ID, so the neighbour alone cannot say which interface an entry is —
/// and the interface is the edge's forwarding identity: stamp a clean
/// edge with its pruned twin's interface and the algorithm's traffic
/// leaves over the pruned link. Each entry takes an unused interface
/// adjacent to its neighbour, preferring the one whose metric and current
/// attributes are what the entry advertises; parallel links that differ
/// therefore pair exactly, and identical ones still get one interface
/// each.
fn own_entry_interfaces<'a>(
    own: impl Iterator<Item = &'a IsisLsp>,
    links: &IsisLinks,
    am: &AffinityMap,
    level: Level,
) -> BTreeMap<(IsisLspId, usize), u32> {
    let mut used = BTreeSet::new();
    let mut out = BTreeMap::new();
    for lsp in own {
        let entries = lsp
            .tlvs
            .iter()
            .filter_map(|tlv| match tlv {
                IsisTlv::ExtIsReach(reach) => Some(&reach.entries),
                _ => None,
            })
            .flatten();
        for (position, entry) in entries.enumerate() {
            let candidates: Vec<(u32, &IsisLink)> = links
                .iter()
                .filter(|(ifindex, link)| {
                    !used.contains(*ifindex)
                        && link
                            .state
                            .adj
                            .get(&level)
                            .as_ref()
                            .is_some_and(|(adj, _)| *adj == entry.neighbor_id)
                })
                .map(|(ifindex, link)| (*ifindex, link))
                .collect();
            let advertised = advertised_link_attrs(entry);
            let chosen = candidates
                .iter()
                .find(|(_, link)| {
                    link.config.metric() == entry.metric && own_link_attrs(link, am) == advertised
                })
                .or(candidates.first())
                .map(|(ifindex, _)| *ifindex);
            if let Some(ifindex) = chosen {
                used.insert(ifindex);
                out.insert((lsp.lsp_id, position), ifindex);
            }
        }
    }
    out
}

/// The attributes this router advertises for one of its links — the ASLA
/// `build_link_asla` builds — in the form the reader returns them.
fn own_link_attrs(link: &IsisLink, am: &AffinityMap) -> LinkAttrs {
    let affinity = local_link_affinity(&link.config.affinity, am);
    LinkAttrs {
        affinity: (!affinity.words.is_empty()).then_some(affinity),
        loss: link.te_metric_effective().loss,
    }
}

/// Whether an LSP's router is in a Flexible Algorithm's graph (RFC 9350
/// §5.2): ours always — SPF is only computed for algorithms we
/// participate in — and a pseudonode always, its real router being gated
/// on its own; any other only when it lists the algorithm in its
/// SR-Algorithm sub-TLV.
fn flex_algo_node_included(
    lsa: &Lsa,
    peer_algos: &BTreeMap<IsisSysId, BTreeSet<u8>>,
    algo: u8,
) -> bool {
    lsa.originated
        || lsa.lsp.lsp_id.is_pseudo()
        || peer_algos
            .get(&lsa.lsp.lsp_id.sys_id())
            .is_some_and(|s| s.contains(&algo))
}

/// One edge a Flexible Algorithm's graph leaves out, and why.
#[derive(Debug, Clone, PartialEq)]
pub struct PrunedEdge {
    pub from: IsisNeighborId,
    pub to: IsisNeighborId,
    pub why: Pruned,
}

/// Every edge [`graph_flex_algo`] prunes for `constraints` — the same
/// walk over the same routers, the same attributes, the same rules — so
/// `show` can say which links an algorithm left out and why.
pub(super) fn flex_algo_pruned_edges(
    lsdb: &Lsdb,
    peer_algos: &BTreeMap<IsisSysId, BTreeSet<u8>>,
    algo: u8,
    constraints: &FadConstraints,
) -> Vec<PrunedEdge> {
    let mut out = Vec::new();
    for (_, lsa) in lsdb.iter() {
        if !flex_algo_node_included(lsa, peer_algos, algo) {
            continue;
        }
        let from = lsa.lsp.lsp_id.neighbor_id();
        for tlv in &lsa.lsp.tlvs {
            let IsisTlv::ExtIsReach(ext_reach) = tlv else {
                continue;
            };
            for entry in &ext_reach.entries {
                if lsdb.get(&entry.neighbor_id.into()).is_none() {
                    continue;
                }
                if let Some(why) = link_prune_reason(&advertised_link_attrs(entry), constraints) {
                    out.push(PrunedEdge {
                        from,
                        to: entry.neighbor_id,
                        why,
                    });
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use isis_packet::neigh::IsisSubTlv as NeighSubTlv;
    use isis_packet::{IsisLsp, IsisSubAsla, IsisSubLinkLoss, IsisTlvExtIsReach};

    use super::*;
    use crate::isis::flex_algo::LinkAttrs;

    fn sys(n: u8) -> IsisSysId {
        IsisSysId {
            id: [0, 0, 0, 0, 0, n],
        }
    }

    fn lossy_edge(to: u8, loss: u32) -> IsisTlvExtIsReachEntry {
        IsisTlvExtIsReachEntry {
            neighbor_id: IsisNeighborId::from_sys_id(&sys(to), 0),
            metric: 10,
            subs: vec![NeighSubTlv::Asla(IsisSubAsla {
                l_flag: false,
                sabm: vec![0x10],
                udabm: vec![],
                subs: vec![NeighSubTlv::LinkLoss(IsisSubLinkLoss {
                    anomalous: false,
                    loss,
                })],
            })],
        }
    }

    fn lsa(from: u8, originated: bool, entries: Vec<IsisTlvExtIsReachEntry>) -> (IsisLspId, Lsa) {
        let lsp = IsisLsp {
            lsp_id: IsisLspId::new(sys(from), 0, 0),
            hold_time: 1200,
            tlvs: vec![IsisTlv::ExtIsReach(IsisTlvExtIsReach { entries })],
            ..Default::default()
        };
        let mut lsa = Lsa::new(lsp);
        lsa.originated = originated;
        (lsa.lsp.lsp_id, lsa)
    }

    /// Two parallel point-to-point links to one neighbour share its
    /// neighbour ID. Each must be judged by its own advertisement — here
    /// 0 % and 10 % against a 5 % maximum — for our own LSP as for a
    /// peer's: pruning the clean one too would give this router a topology
    /// every other router lacks.
    #[test]
    fn parallel_links_are_pruned_each_by_its_own_loss() {
        let max = 1_666_667; // 5 %
        let clean = lossy_edge(2, 0);
        let lossy = lossy_edge(2, 3_333_333); // 10 %
        assert_eq!(
            advertised_link_attrs(&lossy),
            LinkAttrs {
                affinity: None,
                loss: Some(3_333_333),
            }
        );
        let constraints = FadConstraints {
            max_link_loss: Some(max),
            ..Default::default()
        };
        for own in [true, false] {
            let mut lsdb = Lsdb::default();
            let (id, a) = lsa(1, own, vec![clean.clone(), lossy.clone()]);
            lsdb.map.insert(id, a);
            let (id, b) = lsa(2, false, vec![lossy_edge(1, 0)]);
            lsdb.map.insert(id, b);
            let peer_algos = BTreeMap::from([
                (sys(1), BTreeSet::from([128])),
                (sys(2), BTreeSet::from([128])),
            ]);
            let pruned = flex_algo_pruned_edges(&lsdb, &peer_algos, 128, &constraints);
            assert_eq!(
                pruned,
                vec![PrunedEdge {
                    from: IsisNeighborId::from_sys_id(&sys(1), 0),
                    to: IsisNeighborId::from_sys_id(&sys(2), 0),
                    why: Pruned::LinkLoss {
                        loss: 3_333_333,
                        max
                    },
                }],
                "own: {own}"
            );
        }
    }
}
