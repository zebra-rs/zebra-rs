use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap, HashSet};

pub type Graph = BTreeMap<usize, Node>;

#[derive(Default)]
pub struct SpfOpt {
    pub full_path: bool,
    pub path_max: usize,
    pub srmpls: bool,
    pub srv6: bool,
}

impl SpfOpt {
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Node {
    pub id: usize,
    pub name: String,
    pub olinks: Vec<Link>,
    pub ilinks: Vec<Link>,
    //pub is_disabled: bool,
    //pub is_srv6: bool,
    //pub is_srmpls: bool,
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum SpfDirect {
    Normal,
    Reverse,
}

impl Node {
    pub fn new(name: &str, id: usize) -> Self {
        Self {
            id,
            name: name.into(),
            olinks: Vec::new(),
            ilinks: Vec::new(),
            // is_disabled: false,
            // is_srv6: true,
            // is_srmpls: true,
        }
    }

    pub fn links(&self, direct: &SpfDirect) -> &Vec<Link> {
        if *direct == SpfDirect::Normal {
            &self.olinks
        } else {
            &self.ilinks
        }
    }

    // pub fn is_srv6_capable(&self) -> bool {
    //     self.is_srv6
    // }

    // pub fn is_srmpls(&self) -> bool {
    //     self.is_srmpls
    // }
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Link {
    pub from: usize,
    pub to: usize,
    pub cost: u32,
}

impl Link {
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
    opt: &SpfOpt,
    direct: &SpfDirect,
) -> BTreeMap<usize, Path> {
    let mut spf = BTreeMap::<usize, Path>::new();
    let mut paths = HashMap::<usize, Path>::new();
    let mut bt = BTreeMap::<(u32, usize), Path>::new();

    let mut c = Path::new(root);
    c.paths.push(vec![root]);
    c.nexthops.insert(vec![root]);

    paths.insert(root, c.clone());
    bt.insert((c.cost, root), c);

    while let Some((_, v)) = bt.pop_first() {
        spf.insert(v.id, v.clone());

        let Some(edge) = graph.get(&v.id) else {
            continue;
        };

        // if edge.is_disabled {
        //     continue;
        // }

        for link in edge.links(direct).iter() {
            if let Some(x) = graph.get(&link.id(direct)) {
                // if x.is_disabled {
                //     continue;
                // }
            };

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
                let path = vec![root, c.id];

                if opt.full_path {
                    c.paths.push(path);
                } else {
                    c.nexthops.insert(path);
                }
            } else if opt.full_path {
                for path in &v.paths {
                    if opt.path_max == 0 || c.paths.len() < opt.path_max {
                        let mut newpath = path.clone();
                        newpath.push(c.id);
                        c.paths.push(newpath);
                    }
                }
            } else {
                for nhop in &v.nexthops {
                    if opt.path_max == 0 || c.nexthops.len() < opt.path_max {
                        let mut newnhop = nhop.clone();
                        if nhop.len() < 2 {
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
    spf_calc(graph, root, opt, &SpfDirect::Normal)
}

pub fn spf_reverse(graph: &Graph, root: usize, opt: &SpfOpt) -> BTreeMap<usize, Path> {
    spf_calc(graph, root, opt, &SpfDirect::Reverse)
}

pub fn path_has_x(path: &[usize], x: usize) -> bool {
    path.contains(&x)
}

pub fn p_space_nodes(graph: &Graph, s: usize, x: usize) -> HashSet<usize> {
    let spf = spf(graph, s, &SpfOpt::default());

    spf.iter()
        .filter_map(|(node, path)| {
            if *node == s {
                return None; // Skip the source node
            }
            let has_valid_paths = path.paths.iter().any(|p| !path_has_x(p, x));
            if has_valid_paths {
                Some(*node)
            } else {
                None
            }
        })
        .collect::<HashSet<_>>() // Collect into HashSet instead of Vec
}

pub fn q_space_nodes(graph: &Graph, d: usize, x: usize) -> HashSet<usize> {
    let spf = spf_reverse(graph, d, &SpfOpt::default());

    spf.iter()
        .filter_map(|(node, path)| {
            if *node == d {
                return None; // Skip the source node
            }
            let has_valid_paths = path.paths.iter().any(|p| !path_has_x(p, x));
            if has_valid_paths {
                Some(*node)
            } else {
                None
            }
        })
        .collect::<HashSet<_>>()
}

pub fn pc_paths(graph: &Graph, s: usize, d: usize, x: usize) -> Vec<Vec<usize>> {
    let mut pc_graph: Graph = graph.to_owned(); // Clone only when necessary

    if let Some(x_node) = pc_graph.get_mut(&x) {
        // x_node.is_disabled = true;
    }

    spf(&pc_graph, s, &SpfOpt::default())
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

pub fn tilfa(graph: &Graph, s: usize, d: usize, x: usize) {
    let p_nodes = p_space_nodes(graph, s, x);
    let q_nodes = q_space_nodes(graph, d, x);
    let mut pc_paths = pc_paths(graph, s, d, x);

    // P
    print!("P:");
    for name in p_nodes.iter().filter_map(|p| graph.get(p).map(|n| &n.name)) {
        print!(" {}", name);
    }
    println!();

    // Q
    print!("Q:");
    for name in q_nodes.iter().filter_map(|q| graph.get(q).map(|n| &n.name)) {
        print!(" {}", name);
    }
    println!();

    // PCPath.
    for path in &mut pc_paths {
        // Remove S and D.
        path.remove(0);
        path.pop();

        // Display PCPath.
        print!("PCPath:");
        for name in path.iter().filter_map(|q| graph.get(q).map(|n| &n.name)) {
            print!(" {}", name);
        }
        println!();

        // Intersect
        let pc_inter = intersect(path, &p_nodes, &q_nodes);

        // Display PCPath & P intersect.
        print!("Pinter:");
        for inter in &pc_inter {
            if inter.p {
                print!(" o ");
            } else {
                print!(" x ");
            }
        }
        println!();

        // Display PCPath & Q intersect.
        print!("Qinter:");
        for inter in &pc_inter {
            if inter.q {
                print!(" o ");
            } else {
                print!(" x ");
            }
        }
        println!();

        // Convert PC intersects into repair list.
        let repair_list = make_repair_list(&pc_inter, s, d);
        repair_list_print(graph, &repair_list);
        //println!("{:?}", repair_list);
    }
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
