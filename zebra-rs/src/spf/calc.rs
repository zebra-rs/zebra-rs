#![allow(dead_code)]
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap, HashSet};

pub type Graph = BTreeMap<usize, Node>;

#[derive(Default)]
pub struct SpfOpt {
    pub full_path: bool,
    pub path_max: Option<usize>,
    pub _srmpls: bool,
    pub _srv6: bool,
}

#[allow(dead_code)]
impl SpfOpt {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn full_path() -> Self {
        let mut opt = Self::default();
        opt.full_path = true;
        opt
    }
}

#[derive(Debug, Default, Eq, PartialEq, Clone)]
pub struct Node {
    pub id: usize,
    pub name: String,
    pub sys_id: String,
    pub olinks: Vec<Link>,
    pub ilinks: Vec<Link>,
}

#[allow(dead_code)]
#[derive(Debug, Eq, PartialEq, Clone)]
pub enum SpfDirect {
    Normal,
    Reverse,
}

impl Node {
    #[allow(dead_code)]
    pub fn new(name: &str, id: usize) -> Self {
        Self {
            id,
            name: name.into(),
            sys_id: name.into(), // Default to name for backward compatibility
            olinks: Vec::new(),
            ilinks: Vec::new(),
        }
    }

    pub fn links(&self, direct: &SpfDirect) -> &Vec<Link> {
        if *direct == SpfDirect::Normal {
            &self.olinks
        } else {
            &self.ilinks
        }
    }

    #[allow(dead_code)]
    pub fn is_disabled(&self) -> bool {
        false
    }
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Link {
    pub from: usize,
    pub to: usize,
    pub cost: u32,
}

impl Link {
    #[allow(dead_code)]
    pub fn new(from: usize, to: usize, cost: u32) -> Self {
        Self { from, to, cost }
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

#[allow(dead_code)]
#[derive(Debug, Eq, PartialEq, Clone)] // Added Clone for easier conversion
pub enum Paths {
    Full(Vec<Vec<usize>>),
    Nexthop(HashSet<Vec<usize>>),
}

#[derive(Debug, Eq, PartialEq, Clone)] // Added Clone for easier conversion
pub struct Path {
    pub id: usize,
    pub cost: u32,
    pub paths: Vec<Vec<usize>>,
    pub nexthops: HashSet<Vec<usize>>,
    pub registered: bool,
}

impl Path {
    pub fn new(id: usize) -> Self {
        Self {
            id,
            cost: 0,
            paths: Vec::new(),
            nexthops: HashSet::new(),
            registered: false,
        }
    }
}

pub fn spf_calc(
    graph: &Graph,
    root: usize,
    x: Option<usize>,
    opt: &SpfOpt,
    direct: &SpfDirect,
) -> BTreeMap<usize, Path> {
    let mut spf = BTreeMap::<usize, Path>::new();
    let mut paths = HashMap::<usize, Path>::new();
    let mut bt = BTreeMap::<(u32, usize), Path>::new();

    let mut c = Path::new(root);
    c.paths.push(vec![]);
    c.nexthops.insert(vec![]);

    paths.insert(root, c.clone());
    bt.insert((c.cost, root), c);

    while let Some((_, v)) = bt.pop_first() {
        spf.insert(v.id, v.clone());

        let Some(edge) = graph.get(&v.id) else {
            continue;
        };

        // For TI-LFA, we skip down node.
        if let Some(x) = x
            && edge.id == x
        {
            continue;
        }

        for link in edge.links(direct).iter() {
            // For TI-LFA, we skip a link which connects to down node.
            if let Some(x) = x
                && let Some(next) = graph.get(&link.id(direct))
                && next.id == x
            {
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
            }

            if v.id == root {
                let path = vec![c.id];

                if opt.full_path {
                    c.paths.push(path);
                } else {
                    c.nexthops.insert(path);
                }
            } else if opt.full_path {
                for path in &v.paths {
                    if opt.path_max.map_or(true, |max| c.paths.len() < max) {
                        let mut newpath = path.clone();
                        newpath.push(c.id);
                        c.paths.push(newpath);
                    }
                }
            } else {
                for nhop in &v.nexthops {
                    if opt.path_max.map_or(true, |max| c.paths.len() < max) {
                        let mut newnhop = nhop.clone();
                        if nhop.is_empty() {
                            newnhop.push(c.id);
                        }
                        c.nexthops.insert(newnhop);
                    }
                }
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
                }
            } else {
                bt.remove(&(ocost, c.id));
                bt.insert((c.cost, c.id), c.clone());
            }
        }
    }
    spf
}

pub fn spf(graph: &Graph, root: usize, opt: &SpfOpt) -> BTreeMap<usize, Path> {
    spf_calc(graph, root, None, opt, &SpfDirect::Normal)
}

pub fn spf_reverse(graph: &Graph, root: usize, opt: &SpfOpt) -> BTreeMap<usize, Path> {
    spf_calc(graph, root, None, opt, &SpfDirect::Reverse)
}

pub fn path_has_x(path: &[usize], x: usize) -> bool {
    path.contains(&x)
}

pub fn p_space_nodes(graph: &Graph, s: usize, x: usize) -> HashSet<usize> {
    let spf = spf(graph, s, &SpfOpt::full_path());

    spf.iter()
        .filter_map(|(node, path)| {
            if *node == s {
                return None; // Skip the source node
            }
            let has_valid_paths = path.paths.iter().any(|p| !path_has_x(p, x));
            if has_valid_paths { Some(*node) } else { None }
        })
        .collect::<HashSet<_>>() // Collect into HashSet instead of Vec
}

pub fn q_space_nodes(graph: &Graph, d: usize, x: usize) -> HashSet<usize> {
    let spf = spf_reverse(graph, d, &SpfOpt::full_path());

    spf.iter()
        .filter_map(|(node, path)| {
            if *node == d {
                return None; // Skip the source node
            }
            let has_valid_paths = path.paths.iter().any(|p| !path_has_x(p, x));
            if has_valid_paths { Some(*node) } else { None }
        })
        .collect::<HashSet<_>>()
}

pub fn pc_paths(graph: &Graph, s: usize, d: usize, x: usize) -> Vec<Vec<usize>> {
    spf_calc(&graph, s, Some(x), &SpfOpt::full_path(), &SpfDirect::Normal)
        .remove(&d)
        .map_or_else(Vec::new, |data| data.paths)
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
    p_nodes: &HashSet<usize>,
    q_nodes: &HashSet<usize>,
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
    AdjSid(usize, usize),
}

pub fn make_repair_list(pc_inter: &[Intersect], s: usize, d: usize) -> Vec<SrSegment> {
    let mut sr_segments = Vec::new();

    let mut prev_id = None;
    let mut p_mode = false;
    let mut q_mode = false;

    for (index, inter) in pc_inter.iter().enumerate() {
        if index == 0 {
            if inter.p {
                p_mode = true;
            } else {
                sr_segments.push(SrSegment::AdjSid(s, inter.id));
            }
        } else if p_mode {
            if !inter.p {
                if let Some(prev_id) = prev_id {
                    sr_segments.push(SrSegment::NodeSid(prev_id));
                }
                if !q_mode {
                    sr_segments.push(SrSegment::AdjSid(prev_id.unwrap(), inter.id));
                }
                p_mode = false;
            }
        } else if let Some(prev_id) = prev_id {
            if !q_mode {
                sr_segments.push(SrSegment::AdjSid(prev_id, inter.id));
            }
        }

        if inter.q {
            q_mode = true;
        }
        prev_id = Some(inter.id);
    }

    if !q_mode {
        if let Some(prev_id) = prev_id {
            sr_segments.push(SrSegment::AdjSid(prev_id, d));
        }
    }

    sr_segments
}

pub fn repair_list_print(graph: &Graph, repair_list: &Vec<SrSegment>) {
    for list in repair_list {
        match list {
            SrSegment::NodeSid(nid) => {
                print!("NodeSid({}) ", graph.get(nid).map(|n| &n.name).unwrap());
            }
            SrSegment::AdjSid(from, to) => {
                print!(
                    "AdjSid({}, {}) ",
                    graph.get(from).map(|n| &n.name).unwrap(),
                    graph.get(to).map(|n| &n.name).unwrap()
                );
            }
        }
    }
}

pub fn tilfa(graph: &Graph, s: usize, d: usize, x: usize) -> Vec<Vec<SrSegment>> {
    let p_nodes = p_space_nodes(graph, s, x);
    let q_nodes = q_space_nodes(graph, d, x);
    let mut pc_paths = pc_paths(graph, s, d, x);

    // PCPaths.
    let mut repair_lists = vec![];
    for path in &mut pc_paths {
        // Remove D.
        path.pop();

        // Intersect.
        let pc_inter = intersect(path, &p_nodes, &q_nodes);

        // Convert PC intersects into repair list.
        let repair_list = make_repair_list(&pc_inter, s, d);

        repair_lists.push(repair_list);
    }
    repair_lists
}

pub fn disp(spf: &BTreeMap<usize, Path>, full_path: bool) {
    if full_path {
        for (node, path) in spf {
            println!("node: {} nexthops: {}", node, path.paths.len());
            for p in &path.paths {
                println!("  metric {} path {:?}", path.cost, p);
            }
        }
    } else {
        for (node, nhops) in spf {
            println!("node: {} nexthops: {}", node, nhops.nexthops.len());
            for p in &nhops.nexthops {
                println!("  metric {} path {:?}", nhops.cost, p);
            }
        }
    }
}

use std::fmt::Write;

pub fn disp_out(buf: &mut String, spf: &BTreeMap<usize, Path>, full_path: bool) {
    if full_path {
        for (node, path) in spf {
            writeln!(buf, "node: {} nexthops: {}", node, path.paths.len());
            for p in &path.paths {
                writeln!(buf, "  metric {} path {:?}", path.cost, p);
            }
        }
    } else {
        for (node, nhops) in spf {
            writeln!(buf, "node: {} nexthops: {}", node, nhops.nexthops.len());
            for p in &nhops.nexthops {
                writeln!(buf, "  metric {} path {:?}", nhops.cost, p);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn ecmp() {
        let mut graph = BTreeMap::new();

        // First, insert all nodes
        let nodes = vec![
            Node::new("N1", 0),
            Node::new("N2", 1),
            Node::new("N3", 2),
            Node::new("N4", 3),
            Node::new("N5", 4),
        ];

        for node in nodes {
            graph.insert(node.id, node);
        }

        // Define links between nodes
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

        // Now add links to the respective nodes stored in our BTreeMap
        for (from, to, cost) in links {
            graph
                .get_mut(&from)
                .unwrap()
                .olinks
                .push(Link::new(from, to, cost));
        }

        // SPF with nexthop tracking mode.
        let mut opt = SpfOpt::new();
        let tree = spf(&graph, 0, &opt);

        // node: 0 nexthops: 1
        //   metric 0 path []
        // node: 1 nexthops: 1
        //   metric 10 path [1]
        // node: 2 nexthops: 1
        //   metric 10 path [2]
        // node: 3 nexthops: 2
        //   metric 20 path [2]
        //   metric 20 path [1]
        // node: 4 nexthops: 2
        //   metric 30 path [1]
        //   metric 30 path [2]

        // Verify source node has only one nexthop with metric = 0 and empty
        // path.
        let Some(s) = tree.get(&0) else {
            panic!("SPF does not have source node");
        };
        assert_eq!(s.cost, 0);
        assert_eq!(s.nexthops.len(), 1);
        assert!(s.nexthops.iter().next().unwrap().is_empty());

        // Verify ECMP node.
        let Some(n) = tree.get(&3) else {
            panic!("SPF node 3 does not exist");
        };
        assert_eq!(n.cost, 20);
        assert_eq!(n.nexthops.len(), 2);
        let nhops: BTreeSet<usize> = n.nexthops.iter().flatten().copied().collect();
        assert_eq!(nhops, BTreeSet::from([1, 2]));

        // SPF with full path tracking mode.
        opt.full_path = true;
        let tree = spf(&graph, 0, &opt);

        // node: 0 nexthops: 1
        //   metric 0 path []
        // node: 1 nexthops: 1
        //   metric 10 path [1]
        // node: 2 nexthops: 1
        //   metric 10 path [2]
        // node: 3 nexthops: 2
        //   metric 20 path [1, 3]
        //   metric 20 path [2, 3]
        // node: 4 nexthops: 2
        //   metric 30 path [1, 3, 4]
        //   metric 30 path [2, 3, 4]

        // Source node.
        let Some(s) = tree.get(&0) else {
            panic!("SPF does not have source node");
        };
        assert_eq!(s.cost, 0);
        assert_eq!(s.nexthops.len(), 1);
        assert!(s.nexthops.iter().next().unwrap().is_empty());

        // Node 4.
        let Some(n) = tree.get(&4) else {
            panic!("SPF node 4 does not exist");
        };
        assert_eq!(n.cost, 30);
        assert_eq!(n.paths.len(), 2);
        assert_eq!(*n.paths.get(0).unwrap(), vec![1, 3, 4]);
        assert_eq!(*n.paths.get(1).unwrap(), vec![2, 3, 4]);

        // SPF with full path and path max = 1.
        opt.full_path = true;
        opt.path_max = Some(1);
        let tree = spf(&graph, 0, &opt);

        // node: 0 nexthops: 1
        //   metric 0 path []
        // node: 1 nexthops: 1
        //   metric 10 path [1]
        // node: 2 nexthops: 1
        //   metric 10 path [2]
        // node: 3 nexthops: 1
        //   metric 20 path [1, 3]
        // node: 4 nexthops: 1
        //   metric 30 path [1, 3, 4]

        // Node 3.
        let Some(n) = tree.get(&3) else {
            panic!("SPF node 3 does not exist");
        };
        assert_eq!(n.cost, 20);
        assert_eq!(n.paths.len(), 1);
        assert_eq!(*n.paths.get(0).unwrap(), vec![1, 3]);
    }

    fn tilfa_graph() -> Graph {
        let mut graph = BTreeMap::new();

        // Insert nodes
        let nodes = vec![
            Node::new("S", 0),
            Node::new("N1", 1),
            Node::new("N2", 2),
            Node::new("N3", 3),
            Node::new("R1", 4),
            Node::new("R2", 5),
            Node::new("R3", 6),
            Node::new("D", 7),
        ];

        for node in nodes.iter() {
            graph.insert(node.id, node.clone());
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

        // Insert links into nodes
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

    fn seg_disp(graph: &Graph, seg: &SrSegment) -> String {
        match seg {
            SrSegment::NodeSid(id) => {
                format!("NodeSid({})", graph.get(&id).map(|n| &n.name).unwrap())
            }
            SrSegment::AdjSid(from, to) => {
                format!(
                    "AdjSid({}, {})",
                    graph.get(&from).map(|n| &n.name).unwrap(),
                    graph.get(&to).map(|n| &n.name).unwrap()
                )
            }
        }
    }

    #[test]
    fn tilfa_test() {
        let mut graph = tilfa_graph();

        let node_name = |graph: &Graph, id: usize| graph.get(&id).map(|n| &n.name).unwrap().clone();

        // TI-LFA draft
        // *  First, P(S, N1) is computed and results in [N3, N2, R1].
        let s = 0;
        let d = 7;
        let x = 1;

        let p = p_space_nodes(&graph, s, x);
        let mut p_nodes = BTreeSet::<String>::new();
        for n in p.iter() {
            let name = node_name(&graph, *n);
            p_nodes.insert(name);
        }
        assert_eq!(
            p_nodes,
            BTreeSet::from(["N3".into(), "N2".into(), "R1".into()])
        );

        // Then, Q(D, N1) is computed and results in [R3].
        let q = q_space_nodes(&graph, d, x);
        let mut q_nodes = BTreeSet::<String>::new();
        for n in q.iter() {
            let name = node_name(&graph, *n);
            q_nodes.insert(name);
        }
        assert_eq!(q_nodes, BTreeSet::from(["R3".into()]));

        // *  The expected post-convergence path from S to D considering the
        // failure of N1 is <N2 -> R1 -> R2 -> R3 -> D> (we are naming it
        // PCPath in this example).
        let mut pc_paths = pc_paths(&graph, s, d, x);
        assert_eq!(pc_paths.len(), 1);
        let pc_path = pc_paths.get(0).unwrap();
        let mut pc_nodes = Vec::<String>::new();
        for n in pc_path.iter() {
            let name = node_name(&graph, *n);
            pc_nodes.push(name);
        }
        assert_eq!(pc_nodes, vec!["N2", "R1", "R2", "R3", "D"]);

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
            // Remove D from path.
            path.pop();

            let pc_inter = intersect(path, &p, &q);

            print!("  ");
            for i in pc_inter.iter() {
                let name = node_name(&graph, i.id);
                print!(" {}", name);
            }
            println!("");

            print!("P ");
            for i in pc_inter.iter() {
                print!(" {} ", if i.p { "o" } else { "x" });
            }
            println!("");

            print!("Q ");
            for i in pc_inter.iter() {
                print!(" {} ", if i.q { "o" } else { "x" });
            }
            println!("");

            // Asssert P(S, N1)
            let mut p_inter = Vec::<String>::new();
            for i in pc_inter.iter() {
                if i.p {
                    let name = node_name(&graph, i.id);
                    p_inter.push(name);
                };
            }
            assert_eq!(p_inter, vec!["N2", "R1"]);

            // Assert Q(D, N1)
            let mut q_inter = Vec::<String>::new();
            for i in pc_inter.iter().rev() {
                if i.q {
                    let name = node_name(&graph, i.id);
                    q_inter.push(name);
                };
            }
            assert_eq!(q_inter, vec!["R3"]);

            // As a result, the TI-LFA repair list of S for destination D considering the
            // failure of node N1 is: <Node-SID(R1), Adj-Sid(R1-R2), Adj-Sid(R2-R3)>.

            // Make repair list.
            let repair_list = make_repair_list(&pc_inter, s, d);

            assert_eq!(repair_list.len(), 3);
            let first_segment = repair_list.get(0).unwrap();
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
        let x = 1;

        let repair_paths = tilfa(&graph, s, d, x);
        assert_eq!(repair_paths.len(), 1);
        let repair_list = repair_paths.get(0).unwrap();

        assert_eq!(repair_list.len(), 3);
        let first_segment = repair_list.get(0).unwrap();
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
