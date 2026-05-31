use std::collections::BTreeMap;

use isis_packet::neigh;
use isis_packet::{
    IsisLsp, IsisLspId, IsisNeighborId, IsisSysId, IsisTlv, IsisTlvExtIpReachEntry,
    IsisTlvExtIsReachEntry, IsisTlvIpv6ReachEntry, SidLabelValue,
};

use crate::spf;

use super::config::MtId;
use super::flex_algo::{FadMetricType, FlexAlgoEntry, link_passes_fad, local_link_affinity};
use super::inst::IsisTop;
use super::level::Level;

#[derive(Default)]
pub struct ReachMap {
    map: BTreeMap<IsisSysId, Vec<IsisTlvExtIpReachEntry>>,
}

impl ReachMap {
    pub fn get(&self, key: &IsisSysId) -> Option<&Vec<IsisTlvExtIpReachEntry>> {
        self.map.get(key)
    }

    pub fn insert(
        &mut self,
        key: IsisSysId,
        value: Vec<IsisTlvExtIpReachEntry>,
    ) -> Option<Vec<IsisTlvExtIpReachEntry>> {
        self.map.insert(key, value)
    }

    pub fn remove(&mut self, key: &IsisSysId) -> Option<Vec<IsisTlvExtIpReachEntry>> {
        self.map.remove(key)
    }
}

#[derive(Default)]
pub struct ReachMapV6 {
    map: BTreeMap<IsisSysId, Vec<IsisTlvIpv6ReachEntry>>,
}

impl ReachMapV6 {
    pub fn get(&self, key: &IsisSysId) -> Option<&Vec<IsisTlvIpv6ReachEntry>> {
        self.map.get(key)
    }

    pub fn insert(
        &mut self,
        key: IsisSysId,
        value: Vec<IsisTlvIpv6ReachEntry>,
    ) -> Option<Vec<IsisTlvIpv6ReachEntry>> {
        self.map.insert(key, value)
    }

    pub fn remove(&mut self, key: &IsisSysId) -> Option<Vec<IsisTlvIpv6ReachEntry>> {
        self.map.remove(key)
    }
}

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

                    let link = spf::Link::with_id(node_id, to_id, entry.metric, link_id);
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

    for (neighbor_id, is_originated, lsp) in nodes_to_process {
        let node_id = top.lsp_map.get_mut(&level).get(&neighbor_id);
        // Same source rule as graph(): only set when our own router
        // LSP is processed, never a pseudonode we may have originated.
        if is_originated && !lsp.lsp_id.is_pseudo() {
            source_node = Some(node_id);
        }
        let vertex = create_graph_vertex_mt2(top, level, node_id, &neighbor_id, &lsp);
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

    process_outgoing_links_mt2(top, level, node_id, lsp, &mut vertex.olinks);

    vertex
}

fn process_outgoing_links_mt2(
    top: &mut IsisTop,
    level: Level,
    from_id: usize,
    lsp: &IsisLsp,
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
                process_neighbor_link_mt2(top, level, from_id, entry, links);
            }
        }
    }
}

fn process_neighbor_link_mt2(
    top: &mut IsisTop,
    level: Level,
    from_id: usize,
    entry: &IsisTlvExtIsReachEntry,
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

    let to_id = top
        .lsp_map
        .get_mut(&level)
        .get(&neighbor_lsp_id.neighbor_id());
    links.push(spf::Link {
        from: from_id,
        to: to_id,
        cost: entry.metric,
        link_id: 0,
    });
}

/// Build a per-algorithm SPF graph for Flex-Algo `algo` using `entry`
/// as the Flexible Algorithm Definition (RFC 9350 §5). The result has
/// the same shape as `graph()` so existing `spf::spf` consumers work
/// unchanged.
///
/// Filtering vs the legacy graph:
///   - **Peer participation gate (§5.2):** vertices from non-self
///     LSPs are dropped when the source sys-id is missing from
///     `peer_algos` or has not listed `algo`. The local router is
///     always included — `flex_algo.config[algo]` is the participation
///     signal on our side, and SPF is only called for algos in that
///     map.
///   - **Per-link affinity gate (§6):** every ExtIsReach edge is
///     filtered through `link_passes_fad`. Our own edges resolve
///     local `LinkConfig::affinity` via `affinity_map`; peer edges
///     read `peer_link_affinity[source_sys][neighbor_id]`.
///   - **SRLG exclude:** *not* enforced — peer SRLG state is not yet
///     cached. `entry.srlg_exclude` is read but produces no effect; a
///     `tracing::warn` would be reasonable but is left to the
///     scheduler layer.
///   - **Metric type (§5.1):** `MinUnidirLinkDelay` (metric-type 1)
///     routes on per-link Min delay — local links from
///     `LinkConfig::te_metric.min_delay`, peer links from the Min/Max
///     Link Delay sub-TLV in the link's flex-algo ASLA. A link that
///     advertises no delay is pruned (RFC 9350 §15). IGP (and the
///     not-yet-supported TeDefault) use the reach entry's IGP metric.
pub fn graph_flex_algo(
    top: &mut IsisTop,
    level: Level,
    algo: u8,
    entry: &FlexAlgoEntry,
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
        let neighbor_id = lsa.lsp.lsp_id.neighbor_id();
        let is_originated = lsa.originated;
        let is_pseudo = lsa.lsp.lsp_id.is_pseudo();

        if !is_originated && !is_pseudo {
            let participates = peer_algos_at_level
                .get(&neighbor_id.sys_id())
                .is_some_and(|s| s.contains(&algo));
            if !participates {
                continue;
            }
        }
        let lsp = lsa.lsp.clone();
        nodes_to_process.push((neighbor_id, is_originated, lsp));
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

    // Same local-adj → ifindex map as graph(); used both for link_id
    // stamping and for resolving the local link's affinity.
    let mut local_adj_to_ifindex: BTreeMap<IsisNeighborId, u32> = BTreeMap::new();
    for (ifindex, link) in top.links.iter() {
        if let Some((adj, _)) = link.state.adj.get(&level) {
            local_adj_to_ifindex.insert(*adj, *ifindex);
        }
    }

    // Edge construction with per-link affinity filtering.
    for (neighbor_id, is_originated, lsp) in nodes_to_process.iter() {
        let node_id = top.lsp_map.get_mut(&level).get(neighbor_id);
        let own_router_lsp = *is_originated && !lsp.lsp_id.is_pseudo();
        let source_sys_id = neighbor_id.sys_id();

        for tlv in &lsp.tlvs {
            let IsisTlv::ExtIsReach(ext_reach) = tlv else {
                continue;
            };
            for entry_reach in &ext_reach.entries {
                let neighbor_lsp_id: IsisLspId = entry_reach.neighbor_id.into();

                if top.lsdb.get(&level).get(&neighbor_lsp_id).is_none() {
                    continue;
                }

                // Resolve the link's affinity bitmap for the FAD
                // predicate. Local LSPs are not in
                // `peer_link_affinity` (rebuild skips self), so own
                // edges go through `LinkConfig::affinity` + the
                // configured `affinity_map`.
                let local_affinity;
                let affinity: Option<&isis_packet::ExtAdminGroup> = if source_sys_id == self_sys_id
                {
                    let ifindex = local_adj_to_ifindex.get(&entry_reach.neighbor_id).copied();
                    if let Some(ifx) = ifindex
                        && let Some(link) = top.links.get(&ifx)
                    {
                        local_affinity =
                            local_link_affinity(&link.config.affinity, top.affinity_map);
                        Some(&local_affinity)
                    } else {
                        None
                    }
                } else {
                    top.peer_link_affinity
                        .get(&level)
                        .get(&source_sys_id)
                        .and_then(|m| m.get(&entry_reach.neighbor_id))
                };

                if !link_passes_fad(affinity, entry, top.affinity_map) {
                    continue;
                }

                // Edge cost per the FAD metric-type (RFC 9350 §5.1).
                // metric-type 1 routes on the link's Min delay: local
                // links from current config, peer links from the
                // flex-algo ASLA's Min/Max Link Delay sub-TLV. A link
                // that advertises no delay is pruned (RFC 9350 §15).
                // Everything else uses the reach entry's IGP metric.
                let cost = if entry.metric_type == Some(FadMetricType::MinUnidirLinkDelay) {
                    let delay = if source_sys_id == self_sys_id {
                        local_adj_to_ifindex
                            .get(&entry_reach.neighbor_id)
                            .and_then(|ifx| top.links.get(ifx))
                            .and_then(|link| link.config.te_metric.min_delay)
                    } else {
                        entry_reach.subs.iter().find_map(|sub| match sub {
                            neigh::IsisSubTlv::Asla(asla) => {
                                super::flex_algo::parse_asla_min_delay(asla)
                            }
                            _ => None,
                        })
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

                let link_id = if own_router_lsp {
                    local_adj_to_ifindex
                        .get(&entry_reach.neighbor_id)
                        .copied()
                        .unwrap_or(0)
                } else {
                    0
                };

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
