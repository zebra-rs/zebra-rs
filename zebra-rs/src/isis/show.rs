use std::fmt::Write;

use isis_packet::{nlpid_str, IsisHello, IsisTlv, IsisTlvProtoSupported};
use serde::Serialize;

use super::{inst::ShowCallback, neigh::Neighbor, Isis};

use crate::isis::{hostname, link, neigh, Level};
use crate::{config::Args, rib::MacAddr, spf};

impl Isis {
    fn show_add(&mut self, path: &str, cb: ShowCallback) {
        self.show_cb.insert(path.to_string(), cb);
    }

    pub fn show_build(&mut self) {
        self.show_add("/show/isis", show_isis);
        self.show_add("/show/isis/summary", show_isis_summary);
        self.show_add("/show/isis/route", show_isis_route);
        self.show_add("/show/isis/interface", link::show);
        self.show_add("/show/isis/interface/detail", link::show_detail);
        self.show_add("/show/isis/dis/statistics", link::show_dis_statistics);
        self.show_add("/show/isis/dis/history", link::show_dis_history);
        self.show_add("/show/isis/neighbor", neigh::show);
        self.show_add("/show/isis/neighbor/detail", neigh::show_detail);
        self.show_add("/show/isis/adjacency", show_isis_adjacency);
        self.show_add("/show/isis/database", show_isis_database);
        self.show_add("/show/isis/database/detail", show_isis_database_detail);
        self.show_add("/show/isis/hostname", hostname::show);
        self.show_add("/show/isis/graph", show_isis_graph);
    }
}

fn show_isis(isis: &Isis, _args: Args, _json: bool) -> String {
    String::from("show isis")
}

fn show_isis_summary(_isis: &Isis, _args: Args, _json: bool) -> String {
    String::from("show isis summary")
}

// JSON structures for ISIS graph
#[derive(Serialize)]
struct GraphJson {
    pub level: String,
    pub nodes: Vec<NodeJson>,
}

#[derive(Serialize)]
struct NodeJson {
    pub id: usize,
    pub name: String,
    pub links: Vec<LinkJson>,
}

#[derive(Serialize)]
struct LinkJson {
    pub to_id: usize,
    pub to_name: String,
    pub cost: u32,
}

fn show_isis_graph(isis: &Isis, _args: Args, json: bool) -> String {
    let mut graphs = Vec::new();

    // Process Level 1 graph
    if let Some(graph) = isis.graph.get(&Level::L1) {
        if let Some(graph_json) = format_graph(graph, "L1") {
            graphs.push(graph_json);
        }
    }

    // Process Level 2 graph
    if let Some(graph) = isis.graph.get(&Level::L2) {
        if let Some(graph_json) = format_graph(graph, "L2") {
            graphs.push(graph_json);
        }
    }

    if json {
        // Return JSON formatted output
        serde_json::to_string_pretty(&graphs)
            .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialize graph: {}\"}}", e))
    } else {
        // Return text formatted output
        let mut buf = String::new();

        for graph_data in graphs {
            writeln!(buf, "\n{} IS-IS Graph:", graph_data.level).unwrap();
            writeln!(buf, "\nNodes:").unwrap();
            for node in &graph_data.nodes {
                writeln!(buf, "  {} (id: {})", node.name, node.id).unwrap();
                if !node.links.is_empty() {
                    writeln!(buf, "    Links:").unwrap();
                    for link in &node.links {
                        writeln!(
                            buf,
                            "      -> {} (cost: {})",
                            link.to_name, link.cost
                        )
                        .unwrap();
                    }
                }
            }

        }

        if buf.is_empty() {
            String::from("No IS-IS graph data available")
        } else {
            buf
        }
    }
}

// Helper function to format a graph into the JSON structure
fn format_graph(graph: &spf::Graph, level: &str) -> Option<GraphJson> {
    let mut nodes = Vec::new();

    // Collect all nodes with their links
    for (id, node) in graph.iter() {
        let mut node_links = Vec::new();
        
        // Collect all outgoing links from this node
        for link in &node.olinks {
            // Get the destination node name
            if let Some(to_node) = graph.get(&link.to) {
                node_links.push(LinkJson {
                    to_id: link.to,
                    to_name: to_node.name.clone(),
                    cost: link.cost,
                });
            }
        }
        
        nodes.push(NodeJson {
            id: *id,
            name: node.name.clone(),
            links: node_links,
        });
    }

    if nodes.is_empty() {
        None
    } else {
        Some(GraphJson {
            level: level.to_string(),
            nodes,
        })
    }
}

fn show_isis_route(isis: &Isis, _args: Args, _json: bool) -> String {
    let mut buf = String::new();

    // Helper closure to format and write out routes for a given level
    let mut write_routes = |level: &Level| {
        for (prefix, route) in isis.rib.get(level).iter() {
            let mut shown = false;
            for (addr, nhop) in route.nhops.iter() {
                let sid = if let Some(sid) = route.sid {
                    if nhop.adjacency {
                        format!(", label {} implicit null", sid)
                    } else {
                        format!(", label {}", sid)
                    }
                } else {
                    String::from("")
                };
                if !shown {
                    writeln!(
                        buf,
                        "{:<20} [{}] via {}, {}{}",
                        prefix.to_string(),
                        route.metric,
                        addr,
                        isis.ifname(nhop.ifindex),
                        sid
                    )
                    .unwrap();
                    shown = true;
                } else {
                    writeln!(
                        buf,
                        "                     [{}] via {}, {}{}",
                        route.metric,
                        addr,
                        isis.ifname(nhop.ifindex),
                        sid
                    )
                    .unwrap();
                }
            }
        }
    };

    write_routes(&Level::L1);
    write_routes(&Level::L2);

    buf
}

fn show_isis_database(isis: &Isis, _args: Args, _json: bool) -> String {
    let mut buf = String::new();

    for (lsp_id, lsa) in isis.lsdb.l1.iter() {
        let rem = lsa.hold_timer.as_ref().map_or(0, |timer| timer.rem_sec());
        let originated = if lsa.originated { "*" } else { " " };
        let att_bit = if lsa.lsp.types.att_bits() != 0 { 1 } else { 0 };
        let p_bit = if lsa.lsp.types.p_bits() { 1 } else { 0 };
        let ol_bit = if lsa.lsp.types.ol_bits() { 1 } else { 0 };
        let types = format!("{}/{}/{}", att_bit, p_bit, ol_bit);
        let system_id =
            if let Some((hostname, _)) = isis.hostname.get(&Level::L1).get(&lsp_id.sys_id()) {
                format!(
                    "{}.{:02x}-{:02x}",
                    hostname.clone(),
                    lsp_id.pseudo_id(),
                    lsp_id.fragment_id()
                )
            } else {
                lsp_id.to_string()
            };
        writeln!(
            buf,
            "{:25} {} {:>8}  0x{:08x}  0x{:04x} {:9}  {}",
            system_id.to_string(),
            originated,
            lsa.lsp.pdu_len.to_string(),
            lsa.lsp.seq_number,
            lsa.lsp.checksum,
            rem,
            types,
        )
        .unwrap();
    }

    for (lsp_id, lsa) in isis.lsdb.l2.iter() {
        let rem = lsa.hold_timer.as_ref().map_or(0, |timer| timer.rem_sec());
        let originated = if lsa.originated { "*" } else { " " };
        let att_bit = if lsa.lsp.types.att_bits() != 0 { 1 } else { 0 };
        let p_bit = if lsa.lsp.types.p_bits() { 1 } else { 0 };
        let ol_bit = if lsa.lsp.types.ol_bits() { 1 } else { 0 };
        let types = format!("{}/{}/{}", att_bit, p_bit, ol_bit);
        let system_id =
            if let Some((hostname, _)) = isis.hostname.get(&Level::L2).get(&lsp_id.sys_id()) {
                format!(
                    "{}.{:02x}-{:02x}",
                    hostname.clone(),
                    lsp_id.pseudo_id(),
                    lsp_id.fragment_id()
                )
            } else {
                lsp_id.to_string()
            };
        writeln!(
            buf,
            "{:25} {} {:>8}  0x{:08x}  0x{:04x} {:9}  {}",
            system_id.to_string(),
            originated,
            lsa.lsp.pdu_len.to_string(),
            lsa.lsp.seq_number,
            lsa.lsp.checksum,
            rem,
            types,
        )
        .unwrap();
    }

    buf
}

fn show_isis_database_detail(isis: &Isis, _args: Args, json: bool) -> String {
    if json {
        // Use serde to serialize both L1 and L2 databases
        let mut all_lsps = Vec::new();
        all_lsps.extend(isis.lsdb.l1.values().map(|x| &x.lsp));
        all_lsps.extend(isis.lsdb.l2.values().map(|x| &x.lsp));
        serde_json::to_string_pretty(&all_lsps).unwrap()
    } else {
        // Generate a nicely formatted string for human-readable format
        let mut result = String::new();

        // Helper closure to format LSPs for a given level
        let format_level = |level: &Level, lsdb: &crate::isis::lsdb::Lsdb| -> String {
            // Check if LSDB has any entries
            if lsdb.iter().count() == 0 {
                return String::new();
            }

            let mut level_output = String::new();
            level_output.push_str(&format!("\n{} Link State Database:\n", level));
            level_output.push_str(
                "LSP ID                        PduLen  SeqNumber   Chksum  Holdtime  ATT/P/OL\n",
            );

            for (lsp_id, lsa) in lsdb.iter() {
                let rem = lsa.hold_timer.as_ref().map_or(0, |timer| timer.rem_sec());
                let originated = if lsa.originated { "*" } else { " " };
                let att_bit = if lsa.lsp.types.att_bits() != 0 { 1 } else { 0 };
                let p_bit = if lsa.lsp.types.p_bits() { 1 } else { 0 };
                let ol_bit = if lsa.lsp.types.ol_bits() { 1 } else { 0 };
                let types = format!("{}/{}/{}", att_bit, p_bit, ol_bit);
                let system_id =
                    if let Some((hostname, _)) = isis.hostname.get(level).get(&lsp_id.sys_id()) {
                        format!(
                            "{}.{:02x}-{:02x}",
                            hostname.clone(),
                            lsp_id.pseudo_id(),
                            lsp_id.fragment_id()
                        )
                    } else {
                        lsp_id.to_string()
                    };

                level_output.push_str(&format!(
                    "{:25} {} {:>8}  0x{:08x}  0x{:04x} {:9}  {}{}\n\n",
                    system_id,
                    originated,
                    lsa.lsp.pdu_len.to_string(),
                    lsa.lsp.seq_number,
                    lsa.lsp.checksum,
                    rem,
                    types,
                    lsa.lsp
                ));
            }
            level_output
        };

        // Add L1 database
        result.push_str(&format_level(&Level::L1, &isis.lsdb.l1));

        // Add L2 database
        result.push_str(&format_level(&Level::L2, &isis.lsdb.l2));

        result
    }
}

fn show_isis_adjacency(top: &Isis, _args: Args, _json: bool) -> String {
    let mut buf = String::new();

    for (_, link) in top.links.iter() {
        if let Some(dis) = &link.state.dis.l2 {
            writeln!(buf, "Interface: {}", top.ifname(link.state.ifindex)).unwrap();
            writeln!(buf, "  DIS: {}", dis);
            if let Some(adj) = &link.state.adj.get(&Level::L2) {
                writeln!(buf, "  Adj: {}", adj).unwrap();
            } else {
                writeln!(buf, "  Adj: N/A").unwrap();
            }
        }
    }
    buf
}
