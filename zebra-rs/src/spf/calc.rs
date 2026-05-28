use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

pub type Graph = BTreeMap<usize, Vertex>;

#[derive(Default)]
pub struct SpfOpt {
    pub full_path: bool,
    pub path_max: Option<usize>,
    pub _srmpls: bool,
    pub _srv6: bool,
}

impl SpfOpt {
    pub fn full_path() -> Self {
        Self {
            full_path: true,
            ..Self::default()
        }
    }
}

/// Whether this Vertex represents a real routing system or an
/// IS-IS LAN pseudonode. Pseudonodes are transit-only — they do
/// not own a Node-SID and must not be selected as a TI-LFA repair
/// segment endpoint.
#[derive(Debug, Default, Eq, PartialEq, Clone)]
pub enum VertexType {
    #[default]
    Node,
    PseudoNode,
}

#[derive(Debug, Default, Eq, PartialEq, Clone)]
pub struct Vertex {
    pub id: usize,
    pub name: String,
    pub sys_id: String,
    pub vtype: VertexType,
    pub olinks: Vec<Link>,
    pub ilinks: Vec<Link>,
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum SpfDirect {
    Normal,
    Reverse,
}

impl Vertex {
    /// Construct a Vertex representing a real routing system
    /// (IS-IS Node / OSPF router). `sys_id` defaults to `name` —
    /// callers with distinct hostname vs sys-id should use a
    /// struct literal instead. Test-only today; production code
    /// (isis/graph.rs) builds vertices via struct literals.
    #[allow(dead_code)]
    pub fn new_node(name: &str, id: usize) -> Self {
        Self {
            id,
            name: name.into(),
            sys_id: name.into(),
            vtype: VertexType::Node,
            olinks: Vec::new(),
            ilinks: Vec::new(),
        }
    }

    /// Construct a Vertex representing an IS-IS LAN pseudonode.
    /// Test-only today.
    #[allow(dead_code)]
    pub fn new_pseudo_node(name: &str, id: usize) -> Self {
        Self {
            id,
            name: name.into(),
            sys_id: name.into(),
            vtype: VertexType::PseudoNode,
            olinks: Vec::new(),
            ilinks: Vec::new(),
        }
    }

    pub fn is_pseudo_node(&self) -> bool {
        self.vtype == VertexType::PseudoNode
    }

    pub fn links(&self, direct: &SpfDirect) -> &Vec<Link> {
        if *direct == SpfDirect::Normal {
            &self.olinks
        } else {
            &self.ilinks
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Link {
    pub from: usize,
    pub to: usize,
    pub cost: u32,
    /// Opaque first-hop identifier propagated through `Path::first_hop_links`.
    /// For IS-IS graph edges originated by the local router this is the
    /// local ifindex of the physical interface that produced the
    /// ExtIsReach entry, so the rib-builder can install the exact link
    /// SPF chose. For edges from other routers' LSPs the value is 0 —
    /// the SPF relaxation propagates the field unchanged but only the
    /// first-hop slot is meaningful at install time.
    pub link_id: u32,
}

impl Link {
    /// Test-only constructor with implicit `link_id = 0`. Production
    /// graph builders call [`Self::with_id`] directly so the rib-builder
    /// can resolve back to a specific ifindex.
    #[allow(dead_code)]
    pub fn new(from: usize, to: usize, cost: u32) -> Self {
        Self {
            from,
            to,
            cost,
            link_id: 0,
        }
    }

    pub fn with_id(from: usize, to: usize, cost: u32, link_id: u32) -> Self {
        Self {
            from,
            to,
            cost,
            link_id,
        }
    }

    pub fn id(&self, direct: &SpfDirect) -> usize {
        if *direct == SpfDirect::Normal {
            self.to
        } else {
            self.from
        }
    }
}

impl Ord for Path {
    fn cmp(&self, other: &Self) -> Ordering {
        other.cost.cmp(&self.cost)
    }
}

impl PartialOrd for Path {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Eq, PartialEq, Clone)] // Added Clone for easier conversion
pub struct Path {
    pub id: usize,
    pub cost: u32,
    pub paths: Vec<Vec<usize>>,
    pub nexthops: HashSet<Vec<usize>>,
    /// Set of (first_hop_vertex_id, link_id) pairs that reach this
    /// vertex. Independent of `full_path` mode — populated by relaxation
    /// from `Link::link_id` when a path is established from the SPF
    /// root, and propagated unchanged on deeper relaxations. The
    /// IS-IS rib-builder consumes this to resolve which exact local
    /// interface SPF chose (vs. iterating every `top.links` entry and
    /// installing all interfaces with the destination as a neighbor).
    pub first_hop_links: HashSet<(usize, u32)>,
    pub registered: bool,
}

impl Path {
    pub fn new(id: usize) -> Self {
        Self {
            id,
            cost: 0,
            paths: Vec::new(),
            nexthops: HashSet::new(),
            first_hop_links: HashSet::new(),
            registered: false,
        }
    }
}

pub fn spf_calc(
    graph: &Graph,
    root: usize,
    x: &[usize],
    opt: &SpfOpt,
    direct: &SpfDirect,
) -> BTreeMap<usize, Path> {
    let mut paths = HashMap::<usize, Path>::new();
    let mut bt = BTreeMap::<(u32, usize), Path>::new();

    let mut c = Path::new(root);
    c.paths.push(vec![]);
    c.nexthops.insert(vec![]);

    paths.insert(root, c.clone());
    bt.insert((c.cost, root), c);

    while let Some((_, v)) = bt.pop_first() {
        let Some(edge) = graph.get(&v.id) else {
            continue;
        };

        // For TI-LFA / SRLG, skip any excluded vertex (do not relax
        // edges out of it).
        if x.contains(&edge.id) {
            continue;
        }

        for link in edge.links(direct).iter() {
            // Skip links that connect to an excluded vertex.
            if x.contains(&link.id(direct)) {
                continue;
            }

            let c = paths
                .entry(link.id(direct))
                .or_insert_with(|| Path::new(link.id(direct)));

            let ocost = c.cost;

            if c.id == root {
                continue;
            }

            if c.cost != 0 && c.cost < v.cost + link.cost {
                continue;
            }

            if c.cost != 0 && c.cost == v.cost + link.cost {
                // Fall through for ECMP.
            }

            if c.cost == 0 || c.cost > v.cost + link.cost {
                c.cost = v.cost.saturating_add(link.cost);
                c.paths.clear();
                // Strictly better path replaces everything; old
                // first-hop set was from a worse-cost relaxation.
                c.first_hop_links.clear();
            }

            if v.id == root {
                let path = vec![c.id];

                if opt.full_path {
                    c.paths.push(path);
                } else {
                    c.nexthops.insert(path);
                }
                // c is a direct neighbour of root — this relaxation
                // is itself the first hop. Record it with the link's
                // identifier so the rib-builder can resolve back to
                // a specific local interface.
                c.first_hop_links.insert((c.id, link.link_id));
            } else if opt.full_path {
                for path in &v.paths {
                    if opt.path_max.is_none_or(|max| c.paths.len() < max) {
                        let mut newpath = path.clone();
                        newpath.push(c.id);
                        c.paths.push(newpath);
                    }
                }
                // Deeper hop — propagate v's first-hop set unchanged.
                c.first_hop_links.extend(v.first_hop_links.iter().copied());
            } else {
                for nhop in &v.nexthops {
                    if opt.path_max.is_none_or(|max| c.paths.len() < max) {
                        let mut newnhop = nhop.clone();
                        if nhop.is_empty() {
                            newnhop.push(c.id);
                        }
                        c.nexthops.insert(newnhop);
                    }
                }
                c.first_hop_links.extend(v.first_hop_links.iter().copied());
            }

            if !c.registered {
                c.registered = true;
                bt.insert((c.cost, c.id), c.clone());
            } else if ocost == c.cost {
                if let Some(v) = bt.get_mut(&(c.cost, c.id)) {
                    if opt.full_path {
                        v.paths = c.paths.clone();
                    } else {
                        v.nexthops = c.nexthops.clone();
                    }
                    v.first_hop_links = c.first_hop_links.clone();
                }
            } else {
                bt.remove(&(ocost, c.id));
                bt.insert((c.cost, c.id), c.clone());
            }
        }
    }

    // Materialise the result from `paths` rather than snapshotting
    // each vertex at pop time. When two equal-cost predecessors
    // contribute ECMP paths to a vertex V whose id sorts between
    // them in the (cost, id) priority queue, V is popped between
    // the two relaxations — the second contribution lands in
    // `paths` but its bt-update silently drops because V is no
    // longer in bt. Reading from `paths` at the end picks up the
    // final state regardless of pop ordering.
    paths.into_iter().collect()
}

pub fn spf(graph: &Graph, root: usize, opt: &SpfOpt) -> BTreeMap<usize, Path> {
    spf_calc(graph, root, &[], opt, &SpfDirect::Normal)
}

pub fn spf_reverse(graph: &Graph, root: usize, opt: &SpfOpt) -> BTreeMap<usize, Path> {
    spf_calc(graph, root, &[], opt, &SpfDirect::Reverse)
}

/// True if `path` contains any of the excluded vertices in `x`.
pub fn path_has_x(path: &[usize], x: &[usize]) -> bool {
    path.iter().any(|p| x.contains(p))
}

pub fn p_space_vertices(graph: &Graph, s: usize, x: &[usize]) -> BTreeSet<usize> {
    let spf = spf(graph, s, &SpfOpt::full_path());

    spf.iter()
        .filter_map(|(vertex, path)| {
            if *vertex == s {
                return None; // Skip the source vertex
            }
            let has_valid_paths = path.paths.iter().any(|p| !path_has_x(p, x));
            if has_valid_paths { Some(*vertex) } else { None }
        })
        .collect::<BTreeSet<_>>()
}

/// Compute the post-convergence paths from `s` to `d` while excluding
/// every vertex in `x`. Test-only today; the TI-LFA repair-path
/// builder consumes `spf_calc` directly.
#[allow(dead_code)]
pub fn pc_paths(graph: &Graph, s: usize, d: usize, x: &[usize]) -> Vec<Vec<usize>> {
    spf_calc(graph, s, x, &SpfOpt::full_path(), &SpfDirect::Normal)
        .remove(&d)
        .map_or_else(Vec::new, |data| data.paths)
}

pub fn q_space_vertices(graph: &Graph, d: usize, x: &[usize]) -> BTreeSet<usize> {
    let spf = spf_reverse(graph, d, &SpfOpt::full_path());

    spf.iter()
        .filter_map(|(vertex, path)| {
            if *vertex == d {
                return None; // Skip the source vertex
            }
            let has_valid_paths = path.paths.iter().any(|p| !path_has_x(p, x));
            if has_valid_paths { Some(*vertex) } else { None }
        })
        .collect::<BTreeSet<_>>()
}

#[derive(Debug, Default, Clone)]
pub struct Intersect {
    pub id: usize,
    pub p: bool,
    pub q: bool,
}

// Intersect with P and Q.
pub fn intersect(
    pc_path: &Vec<usize>,
    p_nodes: &BTreeSet<usize>,
    q_nodes: &BTreeSet<usize>,
) -> Vec<Intersect> {
    let mut intersects = Vec::new();

    for id in pc_path {
        let intersect = Intersect {
            id: *id,
            p: p_nodes.contains(id),
            q: q_nodes.contains(id),
        };
        intersects.push(intersect);
    }

    intersects
}

#[derive(Debug)]
pub enum SrSegment {
    NodeSid(usize),
    /// Adjacency SID. `via` carries the IS-IS LAN pseudonode that
    /// the adjacency traverses, when applicable; `None` for a P2P
    /// link. Encoders are expected to resolve `(from, to, via)`
    /// to the correct LAN-Adj-SID at label allocation time.
    AdjSid(usize, usize, Option<usize>),
}

/// Walk the PC-path intersect sequence and emit an SR repair list
/// per RFC 9855 §6.
///
/// The PC path is monotonic in P/Q membership: a (possibly empty)
/// P-space prefix, then a middle that is neither P nor Q, then a
/// (possibly empty) Q-space suffix. The repair list collapses the
/// P prefix to one NodeSid (the deepest P-node) and walks the
/// middle with AdjSids until Q is reached, after which the Q-node's
/// natural forwarding carries the packet to D.
///
/// IS-IS LAN pseudonodes own no Node-SID; they are folded into the
/// `via` of the surrounding adjacency. The most recently traversed
/// pseudonode is cached in `pending_via` and consumed (and reset)
/// by the next AdjSid emission.
pub fn make_repair_list(pc_inter: &[Intersect], s: usize, graph: &Graph) -> Vec<SrSegment> {
    enum State {
        LookingForFirst,
        InP,
        Walking,
        InQ,
    }

    let mut sr_segments = Vec::new();
    let mut state = State::LookingForFirst;
    let mut prev: Option<usize> = None;
    let mut deepest_p: Option<usize> = None;
    let mut pending_via: Option<usize> = None;

    for inter in pc_inter {
        if graph.get(&inter.id).is_some_and(|v| v.is_pseudo_node()) {
            pending_via = Some(inter.id);
            continue;
        }

        match state {
            State::LookingForFirst => {
                if inter.p {
                    deepest_p = Some(inter.id);
                    // The pseudonode hop into this P-vertex is folded
                    // into the NodeSid prefix — its natural forwarding
                    // already crosses the LAN. Drop the cached via so a
                    // later AdjSid emission doesn't inherit it.
                    pending_via = None;
                    state = State::InP;
                } else {
                    sr_segments.push(SrSegment::AdjSid(s, inter.id, pending_via));
                    pending_via = None;
                    state = if inter.q { State::InQ } else { State::Walking };
                }
            }
            State::InP => {
                if inter.p {
                    deepest_p = Some(inter.id);
                    // Same as the LookingForFirst → InP transition: a
                    // pseudonode preceding this P-vertex is absorbed by
                    // the NodeSid prefix, so the via cache is stale.
                    pending_via = None;
                } else {
                    if let Some(p) = deepest_p {
                        sr_segments.push(SrSegment::NodeSid(p));
                    }
                    if inter.q {
                        state = State::InQ;
                    } else {
                        let from = deepest_p.unwrap_or(s);
                        sr_segments.push(SrSegment::AdjSid(from, inter.id, pending_via));
                        pending_via = None;
                        state = State::Walking;
                    }
                }
            }
            State::Walking => {
                let from = prev.unwrap_or(s);
                sr_segments.push(SrSegment::AdjSid(from, inter.id, pending_via));
                pending_via = None;
                if inter.q {
                    state = State::InQ;
                }
            }
            State::InQ => {
                // Q-space reached; the remaining hops are taken by
                // the Q-node's natural forwarding (X-free by
                // construction). No more segments to emit.
            }
        }

        prev = Some(inter.id);
    }

    // Close out the repair list when the loop ends mid-flight.
    // D is included in `pc_inter` (callers must not pop it), so the
    // AdjSid(prev, d) emission already happened inside the loop on
    // the last iteration — re-emitting here would produce a spurious
    // AdjSid(d, d) self-edge.
    if let State::InP = state {
        // Whole PC path stayed in P-space — a single NodeSid is
        // enough; the deepest P-node naturally reaches D.
        if let Some(p) = deepest_p {
            sr_segments.push(SrSegment::NodeSid(p));
        }
    }

    sr_segments
}

#[derive(Debug)]
pub struct RepairPath {
    /// Immediate nexthop node id on the post-convergence path —
    /// what the FIB needs to look up the local egress (ifindex /
    /// next-hop address) for the repair route.
    pub first_hop: usize,
    /// link_id of the SPF edge into `first_hop`, propagated from
    /// `Link::link_id` on the modified-graph SPF. For IS-IS this
    /// is the local ifindex of the physical interface that produced
    /// the underlying ExtIsReach entry, letting the rib-builder
    /// install the exact link the post-conv SPF chose without
    /// re-deriving it. `0` when the chosen first-hop edge has no
    /// link_id (remote-origin edges, test fixtures that use
    /// `Link::new`).
    pub first_hop_link_id: u32,
    /// Repair path segments (Node-SID / Adj-SID sequence) applied
    /// on top of the immediate nexthop.
    pub segs: Vec<SrSegment>,
}

pub fn tilfa(graph: &Graph, s: usize, d: usize, x: &[usize]) -> Vec<RepairPath> {
    let p_vertices = p_space_vertices(graph, s, x);
    let q_vertices = q_space_vertices(graph, d, x);

    // Run the modified SPF inline so we have access to D's
    // `first_hop_links` alongside `paths`. Going through
    // `pc_paths()` would discard that information.
    let modified_spf = spf_calc(graph, s, x, &SpfOpt::full_path(), &SpfDirect::Normal);
    let Some(d_path) = modified_spf.get(&d) else {
        return vec![];
    };
    let first_hop_links = d_path.first_hop_links.clone();
    let mut pc_paths = d_path.paths.clone();

    // PCPaths.
    let mut repair_paths = vec![];

    // PC Paths could be ECMP.
    for path in &mut pc_paths {
        // Skip empty PC Paths.
        if path.is_empty() {
            continue;
        }
        // First hop as RepairPath's nhop.
        let nhop = path[0];

        // Look up the link_id chosen by the modified SPF for this
        // first-hop. `first_hop_links` is a set of (vertex, link_id)
        // pairs; for ECMP-via-parallel-links on the same first-hop
        // there may be multiple entries — any of them is a valid
        // post-conv egress so we take the first match. `0` if the
        // edge carries no link_id (e.g., the test fixtures built
        // with `Link::new`).
        let first_hop_link_id = first_hop_links
            .iter()
            .find(|(v, _)| *v == nhop)
            .map(|(_, lid)| *lid)
            .unwrap_or(0);

        // Intersect over the full PCPath including pseudonodes and D.
        // make_repair_list folds each pseudonode into the `via`
        // field of the surrounding adjacency and emits AdjSid(prev, d)
        // for the final hop as part of the loop; the caller must not
        // strip D from the path or that emission is lost.
        let pc_inter = intersect(path, &p_vertices, &q_vertices);

        // Convert PC intersects into repair list.
        let segs = make_repair_list(&pc_inter, s, graph);

        let repair_path = RepairPath {
            first_hop: nhop,
            first_hop_link_id,
            segs,
        };

        repair_paths.push(repair_path);
    }
    repair_paths
}

use std::fmt::Write;

pub fn disp_out(buf: &mut String, spf: &BTreeMap<usize, Path>, full_path: bool) {
    if full_path {
        for (vertex, path) in spf {
            let _ = writeln!(buf, "vertex: {} nexthops: {}", vertex, path.paths.len());
            for p in &path.paths {
                let _ = writeln!(buf, "  metric {} path {:?}", path.cost, p);
            }
            write_first_hop_links(buf, &path.first_hop_links);
        }
    } else {
        for (vertex, nhops) in spf {
            let _ = writeln!(buf, "vertex: {} nexthops: {}", vertex, nhops.nexthops.len());
            for p in &nhops.nexthops {
                let _ = writeln!(buf, "  metric {} path {:?}", nhops.cost, p);
            }
            write_first_hop_links(buf, &nhops.first_hop_links);
        }
    }
}

/// Render `first_hop_links` sorted by (vertex_id, link_id) so the
/// output is stable across runs — `HashSet` iteration order isn't.
fn write_first_hop_links(buf: &mut String, links: &HashSet<(usize, u32)>) {
    if links.is_empty() {
        return;
    }
    let mut sorted: Vec<(usize, u32)> = links.iter().copied().collect();
    sorted.sort();
    let _ = writeln!(buf, "  first_hop_links: {:?}", sorted);
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    // RFC 9855 §5 TI-LFA topology, modelled as all-LAN. Each
    // router-pair becomes a pseudonode (router → PN cost = the
    // router's interface metric; PN → router cost = 0). SPF cost
    // from S to every router must match `tilfa_graph()` — the
    // pseudonode hops are zero-cost, so totals are preserved.
    //
    // Sys-id mapping (cosmetic only; the algorithm uses the usize id):
    //   S : 49.0000.0000.0000.0001.00
    //   N1: 49.0000.0000.0000.0002.00
    //   N2: 49.0000.0000.0000.0003.00
    //   N3: 49.0000.0000.0000.0004.00
    //   R1: 49.0000.0000.0000.0005.00
    //   R2: 49.0000.0000.0000.0006.00
    //   R3: 49.0000.0000.0000.0007.00
    //   D : 49.0000.0000.0000.0008.00
    #[test]
    fn isis_lan() {
        let lan = isis_lan_graph();
        let p2p = tilfa_graph();

        let opt = SpfOpt::full_path();
        let lan_tree = spf(&lan, 0, &opt);
        let p2p_tree = spf(&p2p, 0, &opt);

        // Cost to every router (id 0..=7) must match the P2P model
        // exactly — LAN pseudonodes add path length but no cost.
        for rtr in 0..=7 {
            let lan_cost = lan_tree.get(&rtr).map(|p| p.cost);
            let p2p_cost = p2p_tree.get(&rtr).map(|p| p.cost);
            assert_eq!(
                lan_cost, p2p_cost,
                "router {rtr}: LAN cost {lan_cost:?} != P2P cost {p2p_cost:?}"
            );
        }

        // All 11 pseudonodes (ids 8..=18) must appear in the SPF
        // tree — confirms they are actually traversed, not orphaned.
        // Each must also carry VertexType::PseudoNode so the
        // (forthcoming) pseudonode-aware repair-list logic can
        // distinguish them from real routers.
        for pn in 8..=18 {
            assert!(
                lan_tree.contains_key(&pn),
                "pseudonode {pn} missing from SPF tree"
            );
            assert!(
                lan.get(&pn).unwrap().is_pseudo_node(),
                "vertex {pn} should be tagged VertexType::PseudoNode"
            );
        }
        for rtr in 0..=7 {
            assert!(
                !lan.get(&rtr).unwrap().is_pseudo_node(),
                "vertex {rtr} should be tagged VertexType::Node"
            );
        }

        // S → D shortest path: S → PN_S_N1(8) → N1(1) → PN_N1_D(13) → D(7),
        // total cost 1 + 0 + 1 + 0 = 2 (same as P2P).
        let d = lan_tree.get(&7).expect("D reachable from S");
        assert_eq!(d.cost, 2);
        assert_eq!(d.paths.len(), 1, "no ECMP expected at D");
        assert_eq!(d.paths[0], vec![8, 1, 13, 7]);
    }

    #[test]
    fn ecmp() {
        let mut graph = BTreeMap::new();

        // First, insert all vertices
        let vertices = vec![
            Vertex::new_node("N1", 0),
            Vertex::new_node("N2", 1),
            Vertex::new_node("N3", 2),
            Vertex::new_node("N4", 3),
            Vertex::new_node("N5", 4),
        ];

        for vertex in vertices {
            graph.insert(vertex.id, vertex);
        }

        // Define links between vertices
        let links = vec![
            (0, 1, 10),
            (0, 2, 10),
            (1, 0, 10),
            (1, 2, 5),
            (1, 3, 10),
            (2, 0, 10),
            (2, 1, 5),
            (2, 3, 10),
            (3, 1, 10),
            (3, 2, 10),
            (3, 4, 10),
            (4, 3, 10),
        ];

        // Now add links to the respective vertices stored in our BTreeMap
        for (from, to, cost) in links {
            graph
                .get_mut(&from)
                .unwrap()
                .olinks
                .push(Link::new(from, to, cost));
        }

        // SPF with nexthop tracking mode.
        let mut opt = SpfOpt::default();
        let tree = spf(&graph, 0, &opt);

        // vertex:0 nexthops: 1
        //   metric 0 path []
        // vertex:1 nexthops: 1
        //   metric 10 path [1]
        // vertex:2 nexthops: 1
        //   metric 10 path [2]
        // vertex:3 nexthops: 2
        //   metric 20 path [2]
        //   metric 20 path [1]
        // vertex:4 nexthops: 2
        //   metric 30 path [1]
        //   metric 30 path [2]

        // Verify source vertex has only one nexthop with metric = 0 and empty
        // path.
        let Some(s) = tree.get(&0) else {
            panic!("SPF does not have source vertex");
        };
        assert_eq!(s.cost, 0);
        assert_eq!(s.nexthops.len(), 1);
        assert!(s.nexthops.iter().next().unwrap().is_empty());

        // Verify ECMP vertex.
        let Some(n) = tree.get(&3) else {
            panic!("SPF vertex 3 does not exist");
        };
        assert_eq!(n.cost, 20);
        assert_eq!(n.nexthops.len(), 2);
        let nhops: BTreeSet<usize> = n.nexthops.iter().flatten().copied().collect();
        assert_eq!(nhops, BTreeSet::from([1, 2]));

        // SPF with full path tracking mode.
        opt.full_path = true;
        let tree = spf(&graph, 0, &opt);

        // vertex:0 nexthops: 1
        //   metric 0 path []
        // vertex:1 nexthops: 1
        //   metric 10 path [1]
        // vertex:2 nexthops: 1
        //   metric 10 path [2]
        // vertex:3 nexthops: 2
        //   metric 20 path [1, 3]
        //   metric 20 path [2, 3]
        // vertex:4 nexthops: 2
        //   metric 30 path [1, 3, 4]
        //   metric 30 path [2, 3, 4]

        // Source vertex.
        let Some(s) = tree.get(&0) else {
            panic!("SPF does not have source vertex");
        };
        assert_eq!(s.cost, 0);
        assert_eq!(s.nexthops.len(), 1);
        assert!(s.nexthops.iter().next().unwrap().is_empty());

        // Vertex 4.
        let Some(n) = tree.get(&4) else {
            panic!("SPF vertex 4 does not exist");
        };
        assert_eq!(n.cost, 30);
        assert_eq!(n.paths.len(), 2);
        assert_eq!(*n.paths.first().unwrap(), vec![1, 3, 4]);
        assert_eq!(*n.paths.get(1).unwrap(), vec![2, 3, 4]);

        // SPF with full path and path max = 1.
        opt.full_path = true;
        opt.path_max = Some(1);
        let tree = spf(&graph, 0, &opt);

        // vertex:0 nexthops: 1
        //   metric 0 path []
        // vertex:1 nexthops: 1
        //   metric 10 path [1]
        // vertex:2 nexthops: 1
        //   metric 10 path [2]
        // vertex:3 nexthops: 1
        //   metric 20 path [1, 3]
        // vertex:4 nexthops: 1
        //   metric 30 path [1, 3, 4]

        // Vertex 3.
        let Some(n) = tree.get(&3) else {
            panic!("SPF vertex 3 does not exist");
        };
        assert_eq!(n.cost, 20);
        assert_eq!(n.paths.len(), 1);
        assert_eq!(*n.paths.first().unwrap(), vec![1, 3]);
    }

    fn tilfa_graph() -> Graph {
        let mut graph = BTreeMap::new();

        // Insert vertices
        let vertices = [
            Vertex::new_node("S", 0),
            Vertex::new_node("N1", 1),
            Vertex::new_node("N2", 2),
            Vertex::new_node("N3", 3),
            Vertex::new_node("R1", 4),
            Vertex::new_node("R2", 5),
            Vertex::new_node("R3", 6),
            Vertex::new_node("D", 7),
        ];

        for vertex in vertices.iter() {
            graph.insert(vertex.id, vertex.clone());
        }

        // Define links
        let links = vec![
            // S
            (0, 1, 1),    // N1
            (0, 2, 1),    // N2
            (0, 3, 1000), // N3
            // N1
            (1, 0, 1), // S
            (1, 4, 1), // R1
            (1, 5, 1), // R2
            (1, 7, 1), // D
            // N2
            (2, 0, 1), // S
            (2, 4, 1), // R1
            // N3
            (3, 0, 1000), // S
            (3, 4, 1000), // R1
            // R1
            (4, 1, 1),    // N1
            (4, 2, 1),    // N2
            (4, 3, 1000), // N3
            (4, 5, 1000), // R2
            // R2
            (5, 1, 1),    // N1
            (5, 4, 1000), // R1
            (5, 6, 1000), // R3
            // R3
            (6, 5, 1000), // R2
            (6, 7, 1),    // D
            // D
            (7, 1, 1), // N1
            (7, 6, 1), // R3
        ];

        // Insert links into vertices
        for (from, to, cost) in links {
            graph
                .get_mut(&from)
                .unwrap()
                .olinks
                .push(Link::new(from, to, cost));
            graph
                .get_mut(&to)
                .unwrap()
                .ilinks
                .push(Link::new(from, to, cost));
        }
        graph
    }

    /// Attach a pseudonode (one per IS-IS LAN) to the graph.
    ///
    /// `members` is a list of (router_id, router-side cost). For each
    /// member the helper appends:
    ///   router → PN  with the router's interface cost
    ///   PN     → router  with cost 0  (always — IS-IS LAN modelling)
    /// olinks/ilinks stay symmetric so reverse SPF (used by Q-space)
    /// works the same as for P2P links.
    fn add_lan(graph: &mut Graph, pn_id: usize, name: &str, members: &[(usize, u32)]) {
        graph.insert(pn_id, Vertex::new_pseudo_node(name, pn_id));
        for &(rtr, cost) in members {
            graph
                .get_mut(&rtr)
                .unwrap()
                .olinks
                .push(Link::new(rtr, pn_id, cost));
            graph
                .get_mut(&pn_id)
                .unwrap()
                .ilinks
                .push(Link::new(rtr, pn_id, cost));
            graph
                .get_mut(&pn_id)
                .unwrap()
                .olinks
                .push(Link::new(pn_id, rtr, 0));
            graph
                .get_mut(&rtr)
                .unwrap()
                .ilinks
                .push(Link::new(pn_id, rtr, 0));
        }
    }

    /// Same systems as `tilfa_graph()`, but each underlying point-to-point
    /// link is rebuilt as an IS-IS LAN with one pseudonode (ids 8..=18).
    /// SPF cost between any two routers is preserved by construction.
    fn isis_lan_graph() -> Graph {
        let mut graph = BTreeMap::new();

        for r in [
            Vertex::new_node("S", 0),
            Vertex::new_node("N1", 1),
            Vertex::new_node("N2", 2),
            Vertex::new_node("N3", 3),
            Vertex::new_node("R1", 4),
            Vertex::new_node("R2", 5),
            Vertex::new_node("R3", 6),
            Vertex::new_node("D", 7),
        ] {
            graph.insert(r.id, r);
        }

        // 11 LANs, one pseudonode each. Costs mirror tilfa_graph().
        add_lan(&mut graph, 8, "PN_S_N1", &[(0, 1), (1, 1)]);
        add_lan(&mut graph, 9, "PN_S_N2", &[(0, 1), (2, 1)]);
        add_lan(&mut graph, 10, "PN_S_N3", &[(0, 1000), (3, 1000)]);
        add_lan(&mut graph, 11, "PN_N1_R1", &[(1, 1), (4, 1)]);
        add_lan(&mut graph, 12, "PN_N1_R2", &[(1, 1), (5, 1)]);
        add_lan(&mut graph, 13, "PN_N1_D", &[(1, 1), (7, 1)]);
        add_lan(&mut graph, 14, "PN_N2_R1", &[(2, 1), (4, 1)]);
        add_lan(&mut graph, 15, "PN_N3_R1", &[(3, 1000), (4, 1000)]);
        add_lan(&mut graph, 16, "PN_R1_R2", &[(4, 1000), (5, 1000)]);
        add_lan(&mut graph, 17, "PN_R2_R3", &[(5, 1000), (6, 1000)]);
        add_lan(&mut graph, 18, "PN_R3_D", &[(6, 1), (7, 1)]);

        graph
    }

    fn seg_disp(graph: &Graph, seg: &SrSegment) -> String {
        let name = |id: &usize| graph.get(id).map(|n| n.name.clone()).unwrap();
        match seg {
            SrSegment::NodeSid(id) => format!("NodeSid({})", name(id)),
            SrSegment::AdjSid(from, to, None) => {
                format!("AdjSid({}, {})", name(from), name(to))
            }
            SrSegment::AdjSid(from, to, Some(via)) => {
                format!("AdjSid({}, {}, via {})", name(from), name(to), name(via))
            }
        }
    }

    #[test]
    fn tilfa_test() {
        let graph = tilfa_graph();

        let vertex_name =
            |graph: &Graph, id: usize| graph.get(&id).map(|n| &n.name).unwrap().clone();

        // D=R2 test for first NodeSID.
        let s = 0;
        let d = 5;
        let x: &[usize] = &[1];

        // P space.
        let p = p_space_vertices(&graph, s, x);
        let mut p_vertices = BTreeSet::<String>::new();
        for n in p.iter() {
            let name = vertex_name(&graph, *n);
            p_vertices.insert(name);
        }
        assert_eq!(
            p_vertices,
            BTreeSet::from(["N3".into(), "N2".into(), "R1".into()])
        );

        let q = q_space_vertices(&graph, d, x);
        let mut q_vertices = BTreeSet::<String>::new();
        for n in q.iter() {
            let name = vertex_name(&graph, *n);
            q_vertices.insert(name);
        }
        assert_eq!(q_vertices, BTreeSet::from([]));

        let pc = pc_paths(&graph, s, d, x);
        let pc = pc.first().unwrap();
        let mut pc_vertices = Vec::<String>::new();
        for n in pc.iter() {
            let name = vertex_name(&graph, *n);
            pc_vertices.push(name);
        }
        assert_eq!(pc_vertices, vec!["N2", "R1", "R2"]);

        let mut pc = pc_paths(&graph, s, d, x);
        for path in &mut pc {
            // PC path keeps D as the final vertex; make_repair_list
            // emits AdjSid(deepest_p, d) for that hop while walking
            // the intersect, so no manual pop is needed.
            let pc_inter = intersect(path, &p, &q);

            // Convert PC intersects into repair list.
            let repair_list = make_repair_list(&pc_inter, s, &graph);

            // Whole P-prefix (N2, R1) collapses to NodeSid(R1), then
            // AdjSid(R1, R2=D) reaches the destination. Q-space here
            // is empty so the trailing hop into D must be explicit.
            assert_eq!(repair_list.len(), 2);
            assert_eq!(seg_disp(&graph, &repair_list[0]), "NodeSid(R1)");
            assert_eq!(seg_disp(&graph, &repair_list[1]), "AdjSid(R1, R2)");
        }

        // *  First, P(S, N1) is computed and results in [N3, N2, R1].
        let s = 0;
        let d = 7;
        let x: &[usize] = &[1];

        let p = p_space_vertices(&graph, s, x);
        let mut p_vertices = BTreeSet::<String>::new();
        for n in p.iter() {
            let name = vertex_name(&graph, *n);
            p_vertices.insert(name);
        }
        assert_eq!(
            p_vertices,
            BTreeSet::from(["N3".into(), "N2".into(), "R1".into()])
        );

        // Then, Q(D, N1) is computed and results in [R3].
        let q = q_space_vertices(&graph, d, x);
        let mut q_vertices = BTreeSet::<String>::new();
        for n in q.iter() {
            let name = vertex_name(&graph, *n);
            q_vertices.insert(name);
        }
        assert_eq!(q_vertices, BTreeSet::from(["R3".into()]));

        // *  The expected post-convergence path from S to D considering the
        // failure of N1 is <N2 -> R1 -> R2 -> R3 -> D> (we are naming it
        // PCPath in this example).
        let mut pc_paths = pc_paths(&graph, s, d, x);
        assert_eq!(pc_paths.len(), 1);
        let pc_path = pc_paths.first().unwrap();
        let mut pc_vertices = Vec::<String>::new();
        for n in pc_path.iter() {
            let name = vertex_name(&graph, *n);
            pc_vertices.push(name);
        }
        assert_eq!(pc_vertices, vec!["N2", "R1", "R2", "R3", "D"]);

        // * P(S, N1) intersection with PCPath is [N2, R1], R1 being the deeper
        // downstream node in PCPath, it can be assumed to be used as P node
        // (this is an example and an implementation could use a different
        // strategy to choose the P node).
        //
        // * Q(D, N1) intersection with PCPath is [R3], so R3 is picked as Q
        // node. An SR explicit path is then computed from R1 (P node) to R3 (Q
        // node) following PCPath (R1 -> R2 -> R3): <Adj-Sid(R1-R2),
        // Adj-Sid(R2-R3)>.
        for path in &mut pc_paths {
            // Keep D as the final vertex; make_repair_list emits the
            // closing hop while walking the intersect.
            let pc_inter = intersect(path, &p, &q);

            print!("  ");
            for i in pc_inter.iter() {
                let name = vertex_name(&graph, i.id);
                print!(" {}", name);
            }
            println!();

            print!("P ");
            for i in pc_inter.iter() {
                print!(" {} ", if i.p { "o" } else { "x" });
            }
            println!();

            print!("Q ");
            for i in pc_inter.iter() {
                print!(" {} ", if i.q { "o" } else { "x" });
            }
            println!();

            // Asssert P(S, N1)
            let mut p_inter = Vec::<String>::new();
            for i in pc_inter.iter() {
                if i.p {
                    let name = vertex_name(&graph, i.id);
                    p_inter.push(name);
                };
            }
            assert_eq!(p_inter, vec!["N2", "R1"]);

            // Assert Q(D, N1)
            let mut q_inter = Vec::<String>::new();
            for i in pc_inter.iter().rev() {
                if i.q {
                    let name = vertex_name(&graph, i.id);
                    q_inter.push(name);
                };
            }
            assert_eq!(q_inter, vec!["R3"]);

            // As a result, the TI-LFA repair list of S for destination D considering the
            // failure of node N1 is: <Node-SID(R1), Adj-Sid(R1-R2), Adj-Sid(R2-R3)>.

            // Make repair list.
            let repair_list = make_repair_list(&pc_inter, s, &graph);

            assert_eq!(repair_list.len(), 3);
            let first_segment = repair_list.first().unwrap();
            let second_segment = repair_list.get(1).unwrap();
            let third_segment = repair_list.get(2).unwrap();

            let first_disp = seg_disp(&graph, first_segment);
            assert_eq!(first_disp, "NodeSid(R1)");

            let second_disp = seg_disp(&graph, second_segment);
            assert_eq!(second_disp, "AdjSid(R1, R2)");

            let third_disp = seg_disp(&graph, third_segment);
            assert_eq!(third_disp, "AdjSid(R2, R3)");
        }
    }

    #[test]
    fn tilfa_api() {
        let graph = tilfa_graph();

        let s = 0;
        let d = 7;
        let x: &[usize] = &[1];

        let repair_paths = tilfa(&graph, s, d, x);
        assert_eq!(repair_paths.len(), 1);
        let repair = repair_paths.first().unwrap();

        // Immediate nexthop on the post-convergence path is N2 (id 2):
        // S→N2 replaces the failed S→N1 first hop.
        assert_eq!(repair.first_hop, 2, "expected first-hop = N2 (id 2)");

        assert_eq!(repair.segs.len(), 3);
        let first_segment = repair.segs.first().unwrap();
        let second_segment = repair.segs.get(1).unwrap();
        let third_segment = repair.segs.get(2).unwrap();

        let first_disp = seg_disp(&graph, first_segment);
        assert_eq!(first_disp, "NodeSid(R1)");

        let second_disp = seg_disp(&graph, second_segment);
        assert_eq!(second_disp, "AdjSid(R1, R2)");

        let third_disp = seg_disp(&graph, third_segment);
        assert_eq!(third_disp, "AdjSid(R2, R3)");
    }

    /// Same TI-LFA scenario as `tilfa_api`, run against the all-LAN
    /// topology. The router-level segments are identical to the
    /// P2P case but each AdjSid carries a `via` referencing the
    /// IS-IS LAN pseudonode that the adjacency traverses:
    ///   <NodeSid(R1), AdjSid(R1, R2, via PN_R1_R2),
    ///                 AdjSid(R2, R3, via PN_R2_R3)>
    #[test]
    fn tilfa_lan_api() {
        let graph = isis_lan_graph();
        let s = 0;
        let d = 7;
        let x: &[usize] = &[1]; // failed vertex N1

        let repair_paths = tilfa(&graph, s, d, x);
        assert_eq!(repair_paths.len(), 1);
        let repair = repair_paths.first().unwrap();

        // In the all-LAN topology the first vertex on the PC path is
        // the pseudonode PN_S_N2 (id 9); leading-pseudonode skipping
        // is the IS-IS caller's job (see `find_local_nhop_v4`).
        assert_eq!(repair.first_hop, 9, "expected first-hop = PN_S_N2 (id 9)");

        assert_eq!(repair.segs.len(), 3);
        assert_eq!(seg_disp(&graph, &repair.segs[0]), "NodeSid(R1)");
        assert_eq!(
            seg_disp(&graph, &repair.segs[1]),
            "AdjSid(R1, R2, via PN_R1_R2)"
        );
        assert_eq!(
            seg_disp(&graph, &repair.segs[2]),
            "AdjSid(R2, R3, via PN_R2_R3)"
        );
    }

    /// Direct-neighbor case: D is a direct neighbor of S in the
    /// modified graph, so the PC path is `[D]` only. D itself is
    /// reachable from S without crossing X, so it lands in P-space
    /// and the algorithm collapses the path to a single `NodeSid(D)`
    /// — the post-conv first-hop's natural forwarding for D's
    /// prefix-SID carries the packet.
    ///
    /// Scenario: S→N2 is a direct link cost 1; excluding N1 doesn't
    /// touch it, so PC(S, N2, x=[N1]) = [[N2]].
    #[test]
    fn tilfa_direct_neighbor_yields_nodesid_d() {
        let graph = tilfa_graph();
        let s = 0;
        let d = 2; // N2
        let x: &[usize] = &[1]; // exclude N1 — irrelevant to S→N2

        let repair_paths = tilfa(&graph, s, d, x);
        assert_eq!(repair_paths.len(), 1);
        let repair = repair_paths.first().unwrap();

        assert_eq!(repair.first_hop, 2, "expected first-hop = N2 (id 2)");
        assert_eq!(repair.segs.len(), 1);
        assert_eq!(seg_disp(&graph, &repair.segs[0]), "NodeSid(N2)");
    }

    /// Case P1 (symmetric parallel links, equal metric): SPF must
    /// propagate every parallel link's `link_id` into the destination's
    /// `first_hop_links` so the rib-builder can install ECMP across
    /// all of them.
    #[test]
    fn first_hop_links_captures_parallel_equal_metric() {
        let mut graph = BTreeMap::new();
        graph.insert(0, Vertex::new_node("S", 0));
        graph.insert(1, Vertex::new_node("A", 1));

        // Two parallel S→A links, equal cost, distinct link_ids.
        graph
            .get_mut(&0)
            .unwrap()
            .olinks
            .push(Link::with_id(0, 1, 5, 10));
        graph
            .get_mut(&0)
            .unwrap()
            .olinks
            .push(Link::with_id(0, 1, 5, 11));

        let tree = spf(&graph, 0, &SpfOpt::full_path());
        let a = tree.get(&1).expect("A reachable");
        assert_eq!(a.cost, 5);

        let got: BTreeSet<(usize, u32)> = a.first_hop_links.iter().copied().collect();
        assert_eq!(
            got,
            BTreeSet::from([(1, 10), (1, 11)]),
            "both parallel link_ids must reach A's first_hop_links"
        );
    }

    /// Case P2 (asymmetric parallel links): SPF picks the cheaper
    /// link and discards the expensive one; only the chosen link_id
    /// must appear in `first_hop_links`.
    #[test]
    fn first_hop_links_picks_cheaper_of_asymmetric_parallels() {
        let mut graph = BTreeMap::new();
        graph.insert(0, Vertex::new_node("S", 0));
        graph.insert(1, Vertex::new_node("A", 1));

        graph
            .get_mut(&0)
            .unwrap()
            .olinks
            .push(Link::with_id(0, 1, 1, 10)); // cheap
        graph
            .get_mut(&0)
            .unwrap()
            .olinks
            .push(Link::with_id(0, 1, 1000, 11)); // expensive

        let tree = spf(&graph, 0, &SpfOpt::full_path());
        let a = tree.get(&1).expect("A reachable");
        assert_eq!(a.cost, 1, "SPF picks metric-1 link");

        let got: BTreeSet<(usize, u32)> = a.first_hop_links.iter().copied().collect();
        assert_eq!(
            got,
            BTreeSet::from([(1, 10)]),
            "only the cheap link_id must survive; expensive parallel must be discarded"
        );
    }

    /// `tilfa()` must propagate the chosen first-hop's `link_id`
    /// from the modified SPF into `RepairPath.first_hop_link_id`,
    /// so the rib-builder can install the exact local egress
    /// without re-deriving it.
    #[test]
    fn tilfa_repair_path_carries_first_hop_link_id() {
        let mut graph = BTreeMap::new();
        graph.insert(0, Vertex::new_node("S", 0));
        graph.insert(1, Vertex::new_node("D", 1));
        graph.insert(2, Vertex::new_node("X", 2));

        // S→D direct with a non-zero link_id (the value we expect
        // to see surfaced on the repair path). S→X is the failed
        // edge we exclude in tilfa; its link_id is irrelevant.
        graph
            .get_mut(&0)
            .unwrap()
            .olinks
            .push(Link::with_id(0, 1, 1, 42));
        graph
            .get_mut(&1)
            .unwrap()
            .ilinks
            .push(Link::with_id(0, 1, 1, 42));
        graph.get_mut(&0).unwrap().olinks.push(Link::new(0, 2, 1));
        graph.get_mut(&2).unwrap().ilinks.push(Link::new(0, 2, 1));

        let repair_paths = tilfa(&graph, 0, 1, &[2]); // exclude X
        assert_eq!(repair_paths.len(), 1);
        let repair = &repair_paths[0];
        assert_eq!(repair.first_hop, 1, "first_hop = D");
        assert_eq!(
            repair.first_hop_link_id, 42,
            "first_hop_link_id must come from the chosen S→D edge"
        );
    }

    /// Deeper-hop propagation: a destination reached via an intermediate
    /// inherits the intermediate's `first_hop_links` set unchanged.
    #[test]
    fn first_hop_links_propagates_through_intermediates() {
        let mut graph = BTreeMap::new();
        graph.insert(0, Vertex::new_node("S", 0));
        graph.insert(1, Vertex::new_node("A", 1));
        graph.insert(2, Vertex::new_node("B", 2));

        graph
            .get_mut(&0)
            .unwrap()
            .olinks
            .push(Link::with_id(0, 1, 1, 10));
        graph
            .get_mut(&1)
            .unwrap()
            .olinks
            .push(Link::with_id(1, 2, 1, 99)); // link_id on non-root edge is irrelevant

        let tree = spf(&graph, 0, &SpfOpt::full_path());
        let b = tree.get(&2).expect("B reachable");
        assert_eq!(b.cost, 2);
        // B's first-hop is A (vertex 1), via link_id 10 — the root edge.
        let got: BTreeSet<(usize, u32)> = b.first_hop_links.iter().copied().collect();
        assert_eq!(
            got,
            BTreeSet::from([(1, 10)]),
            "B must inherit A's first_hop_links (root→A link_id), not the A→B link's id"
        );
    }

    /// Mixed LAN/P2P topology drawn from a live IS-IS LSDB
    /// ("TI-LFA Draft with Link#"). Reproduces the scenario where the
    /// only LANs sit between {s,n2}, {s,n1}, {n2,r1}, {r1,n1}, and the
    /// r1↔r2 / r2↔r3 / r3↔d links are point-to-point. SPF cost from s:
    /// every LAN crossing costs s=10 / others=1; P2P r1↔r2 and r2↔r3
    /// are metric 1000; n1↔r2, n1↔d, r3↔d are metric 1. With X=n1,
    /// r1 has equal-cost paths from s with and without n1 — required
    /// to land r1 in P-space and trigger the pending_via leak below.
    fn mixed_lan_p2p_graph() -> Graph {
        let mut graph = BTreeMap::new();
        for v in [
            Vertex::new_node("s", 0),
            Vertex::new_node("n1", 1),
            Vertex::new_node("n2", 2),
            Vertex::new_node("r1", 3),
            Vertex::new_node("r2", 4),
            Vertex::new_node("r3", 5),
            Vertex::new_node("d", 6),
        ] {
            graph.insert(v.id, v);
        }

        // LANs (DIS-based pseudonode naming matches the LSDB).
        add_lan(&mut graph, 7, "s.04", &[(0, 10), (2, 1)]);
        add_lan(&mut graph, 8, "n1.03", &[(1, 1), (0, 10)]);
        add_lan(&mut graph, 9, "n2.04", &[(2, 1), (3, 1)]);
        add_lan(&mut graph, 10, "r1.04", &[(3, 1), (1, 1)]);

        // P2P links (symmetric metric in both directions).
        let p2p = [(1, 4, 1), (1, 6, 1), (3, 4, 1000), (4, 5, 1000), (5, 6, 1)];
        for &(a, b, cost) in &p2p {
            graph
                .get_mut(&a)
                .unwrap()
                .olinks
                .push(Link::new(a, b, cost));
            graph
                .get_mut(&b)
                .unwrap()
                .ilinks
                .push(Link::new(a, b, cost));
            graph
                .get_mut(&b)
                .unwrap()
                .olinks
                .push(Link::new(b, a, cost));
            graph
                .get_mut(&a)
                .unwrap()
                .ilinks
                .push(Link::new(b, a, cost));
        }
        graph
    }

    /// Regression: `make_repair_list` used to leak `pending_via`
    /// across a P-space real-router vertex. With X=n1, the modified
    /// SPF path from s to r3 is
    /// `s → s.04 → n2 → n2.04 → r1 → r2 → r3`. Both n2 and r1 are in
    /// P-space (r1 has an equal-cost path via s.04 that avoids n1),
    /// so `make_repair_list` enters InP at n2, observes the n2.04
    /// pseudonode, then stays in InP at r1 — at which point n2.04's
    /// LAN crossing is already absorbed into the NodeSid(r1) prefix.
    /// Pre-fix, `pending_via=n2.04` survived past r1 and got stamped
    /// onto the unrelated `AdjSid(r1, r2)` emission for the r1↔r2
    /// P2P link, producing `AdjSid(r1, r2, via n2.04)`. Post-fix, the
    /// via cache is cleared on every "stay in P" step, so the
    /// AdjSid emits with `via = None`.
    #[test]
    fn tilfa_pending_via_does_not_leak_past_p_router() {
        let graph = mixed_lan_p2p_graph();
        let s = 0; // s
        let d = 5; // r3
        let x: &[usize] = &[1]; // exclude n1

        let repair_paths = tilfa(&graph, s, d, x);
        assert_eq!(repair_paths.len(), 1, "single PC path expected");
        let repair = repair_paths.first().unwrap();

        assert_eq!(repair.segs.len(), 3, "expected NodeSid + 2 AdjSids");
        assert_eq!(seg_disp(&graph, &repair.segs[0]), "NodeSid(r1)");
        assert_eq!(
            seg_disp(&graph, &repair.segs[1]),
            "AdjSid(r1, r2)",
            "r1↔r2 is P2P — via must be None, not the absorbed n2.04 LAN"
        );
        assert_eq!(seg_disp(&graph, &repair.segs[2]), "AdjSid(r2, r3)");
    }
}
