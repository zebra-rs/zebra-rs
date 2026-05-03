// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2025-2026 Kunihiro Ishiguro

use std::collections::BTreeSet;
use std::fmt::Write;

use isis_packet::{IsisProto, IsisSysId, IsisTlv, Nsap};
use serde::Serialize;

use super::{Isis, inst::ShowCallback};

use crate::config::Args;
use crate::isis::link::Afi;
use crate::isis::{Level, hostname, link, neigh};
// use spf_rs as spf;
use crate::spf;

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
        self.show_add("/show/isis/spf", show_isis_spf);
        self.show_add("/show/isis/topology", show_isis_topology);
    }
}

fn show_isis(
    _isis: &Isis,
    _args: Args,
    _json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    Ok(String::from("show isis"))
}

fn show_isis_summary(
    isis: &Isis,
    _args: Args,
    _json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    let mut buf = String::new();

    // SRv6 Locator section. Only present when the operator has
    // configured a locator name under `segment-routing/srv6/locator`;
    // an unconfigured node has nothing useful to show here.
    if let Some(name) = isis.watched_locator.as_ref() {
        writeln!(buf, "SRv6 Locator:")?;
        writeln!(
            buf,
            "{:<20} {:<24} {:<8} Status",
            "Name", "Prefix", "Behavior"
        )?;
        writeln!(buf, "{:-<20} {:-<24} {:-<8} {:-<7}", "", "", "", "")?;
        let row = render_locator_row(name, isis.sr_locator.as_ref());
        writeln!(buf, "{row}")?;
    }

    Ok(buf)
}

// Build the single locator row. Pulled out so a future test can pin
// the column widths without spinning up the full Isis fixture.
fn render_locator_row(name: &str, locator: Option<&crate::rib::Locator>) -> String {
    use crate::rib::LocatorBehavior;
    // The locator is "Up" only when the RIB pushed a snapshot AND that
    // snapshot has a usable prefix. A name configured under IS-IS but
    // not yet matched by a global `/segment-routing/locator` entry
    // shows as Down with empty prefix / behavior.
    let (prefix, behavior, status) = match locator {
        Some(loc) => match loc.prefix {
            Some(p) => {
                let beh = match loc.behavior {
                    Some(LocatorBehavior::Usid) => "uSID",
                    None => "Classic",
                };
                (p.to_string(), beh.to_string(), "Up")
            }
            None => (String::new(), String::new(), "Down"),
        },
        None => (String::new(), String::new(), "Down"),
    };
    format!("{name:<20} {prefix:<24} {behavior:<8} {status}")
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
    pub sys_id: String,
    pub links: Vec<LinkJson>,
}

#[derive(Serialize)]
struct LinkJson {
    pub to_id: usize,
    pub to_name: String,
    pub cost: u32,
}

fn show_isis_graph(
    isis: &Isis,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    let mut graphs = Vec::new();

    // Process Level 1 graph
    if let Some(graph) = isis.graph.get(&Level::L1)
        && let Some(graph_json) = format_graph(graph, "L1")
    {
        graphs.push(graph_json);
    }

    // Process Level 2 graph
    if let Some(graph) = isis.graph.get(&Level::L2)
        && let Some(graph_json) = format_graph(graph, "L2")
    {
        graphs.push(graph_json);
    }

    if json {
        // Return JSON formatted output
        Ok(serde_json::to_string_pretty(&graphs)
            .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialize graph: {}\"}}", e)))
    } else {
        // Return text formatted output
        let mut buf = String::new();

        for graph_data in graphs {
            writeln!(buf, "\n{} IS-IS Graph:", graph_data.level)?;
            writeln!(buf, "\nNodes:")?;
            for node in &graph_data.nodes {
                if node.name != node.sys_id {
                    writeln!(buf, "  {} [{}] (id: {})", node.name, node.sys_id, node.id)?;
                } else {
                    writeln!(buf, "  {} (id: {})", node.sys_id, node.id)?;
                }
                if !node.links.is_empty() {
                    writeln!(buf, "    Links:")?;
                    for link in &node.links {
                        writeln!(buf, "      -> {} (cost: {})", link.to_name, link.cost)?;
                    }
                }
            }
        }

        if buf.is_empty() {
            Ok(String::from("No IS-IS graph data available"))
        } else {
            Ok(buf)
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
            sys_id: node.sys_id.clone(),
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

// JSON structures for ISIS routes
#[derive(Serialize)]
struct RouteJson {
    prefix: String,
    metric: u32,
    nexthops: Vec<NexthopJson>,
}

#[derive(Serialize)]
struct NexthopJson {
    address: String,
    interface: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<u32>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    implicit_null: bool,
}

#[derive(Serialize)]
struct RoutesJson {
    level_1: Vec<RouteJson>,
    level_2: Vec<RouteJson>,
}

fn show_isis_route(
    isis: &Isis,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    if json {
        // JSON output
        let mut routes_json = RoutesJson {
            level_1: Vec::new(),
            level_2: Vec::new(),
        };

        // Helper closure to collect routes for a given level
        let collect_routes = |level: &Level| -> Vec<RouteJson> {
            let mut routes = Vec::new();

            for (prefix, route) in isis.rib.get(level).iter() {
                let mut nexthops = Vec::new();

                for (addr, nhop) in route.nhops.iter() {
                    let nexthop_json = NexthopJson {
                        address: addr.to_string(),
                        interface: isis.ifname(nhop.ifindex),
                        label: route.sid,
                        implicit_null: route.sid.is_some() && nhop.adjacency,
                    };
                    nexthops.push(nexthop_json);
                }

                routes.push(RouteJson {
                    prefix: prefix.to_string(),
                    metric: route.metric,
                    nexthops,
                });
            }

            routes
        };

        routes_json.level_1 = collect_routes(&Level::L1);
        routes_json.level_2 = collect_routes(&Level::L2);

        Ok(serde_json::to_string_pretty(&routes_json)
            .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialize routes: {}\"}}", e)))
    } else {
        write_show_isis_route_text(isis)
    }
}

// `show isis topology` — per-level, per-AFI SPF tree without the RIB
// tables that `show isis route` adds. PR 2 of the multi-topology
// series; the renderer is the existing single-topology one. PR 5 will
// extend it to discriminate per-MT view + add a `<topology-id>` filter.
fn show_isis_topology(
    isis: &Isis,
    _args: Args,
    _json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    let mut buf = String::new();
    let local_sys_id = isis.config.net.sys_id();
    writeln!(buf, "Area {}:", format_area_id(&isis.config.net))?;

    let mut wrote_any_level = false;
    for level in &[Level::L1, Level::L2] {
        let Some(spf_result) = isis.spf_result.get(level).as_ref() else {
            continue;
        };
        if spf_result.is_empty() {
            continue;
        }
        wrote_any_level = true;

        let level_long = match level {
            Level::L1 => "level-1",
            Level::L2 => "level-2",
        };

        // IPv4 SPF tree.
        writeln!(buf)?;
        writeln!(buf, "IS-IS paths to {} routers that speak IP", level_long)?;
        write_spf_tree(
            &mut buf,
            isis,
            level,
            &local_sys_id,
            spf_result,
            false,
            false,
        )?;

        // IPv6 SPF tree. When MT 2 is enabled, render from the MT 2
        // SPF result (matches what's actually installed in the v6
        // RIB); otherwise the legacy NLPID-gated single-topology
        // tree.
        let mt2 = mt2_v6_active(isis);
        writeln!(buf)?;
        if mt2 {
            writeln!(
                buf,
                "IS-IS paths to {} routers in MT 2 (IPv6 unicast)",
                level_long
            )?;
            if let Some(mt2_spf) = isis.mt2_spf_result.get(level).as_ref() {
                write_spf_tree(&mut buf, isis, level, &local_sys_id, mt2_spf, true, true)?;
            } else {
                writeln!(buf, "  (MT 2 SPF not computed yet)")?;
            }
        } else {
            writeln!(buf, "IS-IS paths to {} routers that speak IPv6", level_long)?;
            write_spf_tree(
                &mut buf,
                isis,
                level,
                &local_sys_id,
                spf_result,
                true,
                false,
            )?;
        }
    }

    if !wrote_any_level {
        writeln!(buf, "(no SPF result yet)")?;
    }
    Ok(buf)
}

fn write_show_isis_route_text(isis: &Isis) -> std::result::Result<String, std::fmt::Error> {
    let mut buf = String::new();
    let local_sys_id = isis.config.net.sys_id();
    writeln!(buf, "Area {}:", format_area_id(&isis.config.net))?;

    let mut wrote_any_level = false;
    for level in &[Level::L1, Level::L2] {
        let Some(spf_result) = isis.spf_result.get(level).as_ref() else {
            continue;
        };
        if spf_result.is_empty() {
            continue;
        }
        wrote_any_level = true;

        let level_long = match level {
            Level::L1 => "level-1",
            Level::L2 => "level-2",
        };
        let level_short = match level {
            Level::L1 => "L1",
            Level::L2 => "L2",
        };

        // IPv4 SPF tree
        writeln!(buf)?;
        writeln!(buf, "IS-IS paths to {} routers that speak IP", level_long)?;
        write_spf_tree(
            &mut buf,
            isis,
            level,
            &local_sys_id,
            spf_result,
            false,
            false,
        )?;

        // IPv4 RIB
        writeln!(buf)?;
        writeln!(buf, "IS-IS {} IPv4 routing table:", level_short)?;
        writeln!(buf)?;
        write_rib_v4(&mut buf, isis, level)?;

        // IPv6 SPF tree. MT 2 enabled → MT 2 SPF; legacy otherwise.
        let mt2 = mt2_v6_active(isis);
        writeln!(buf)?;
        if mt2 {
            writeln!(
                buf,
                "IS-IS paths to {} routers in MT 2 (IPv6 unicast)",
                level_long
            )?;
            if let Some(mt2_spf) = isis.mt2_spf_result.get(level).as_ref() {
                write_spf_tree(&mut buf, isis, level, &local_sys_id, mt2_spf, true, true)?;
            } else {
                writeln!(buf, "  (MT 2 SPF not computed yet)")?;
            }
        } else {
            writeln!(buf, "IS-IS paths to {} routers that speak IPv6", level_long)?;
            write_spf_tree(
                &mut buf,
                isis,
                level,
                &local_sys_id,
                spf_result,
                true,
                false,
            )?;
        }

        // IPv6 RIB
        writeln!(buf)?;
        writeln!(buf, "IS-IS {} IPv6 routing table:", level_short)?;
        writeln!(buf)?;
        write_rib_v6(&mut buf, isis, level)?;
    }

    if !wrote_any_level {
        writeln!(buf, "(no SPF result yet)")?;
    }

    write_local_sids(&mut buf, isis)?;

    Ok(buf)
}

/// Append a "Local SRv6 SIDs" section. Pulls the data from existing
/// IS-IS state — the End/uN SID off `sr_end_sid` (paired with the
/// locator for behavior + structure) and each per-adjacency End.X/uA
/// SID off the link's neighbor table — so we don't keep a duplicate
/// registry on `Isis`. Empty section is suppressed entirely.
fn write_local_sids(buf: &mut String, isis: &Isis) -> std::fmt::Result {
    use std::net::Ipv6Addr;
    let mut rows: Vec<LocalSidRow> = Vec::new();

    // End / uN — at most one entry, derived from the configured locator.
    if let (Some(addr), Some(locator)) = (isis.sr_end_sid, isis.sr_locator.as_ref()) {
        let (behavior, prefix_len) = match locator.behavior {
            Some(crate::rib::LocatorBehavior::Usid) => {
                let plen = locator
                    .sid_structure()
                    .map(|s| s.lb_bits.saturating_add(s.ln_bits))
                    .unwrap_or(128);
                ("uN", plen)
            }
            None => ("End", 128),
        };
        let masked = mask_v6(addr, prefix_len);
        // End / uN SIDs install on the sr0 dummy in the FIB. IS-IS
        // doesn't track that device directly, so look it up by name in
        // the link table — falls back to the dummy's canonical name if
        // the netlink listener hasn't surfaced it yet.
        let iface = isis
            .links
            .values()
            .find(|l| l.state.name == crate::rib::inst::SR0_DUMMY_NAME)
            .map(|l| l.state.name.clone())
            .unwrap_or_else(|| crate::rib::inst::SR0_DUMMY_NAME.to_string());
        rows.push(LocalSidRow {
            prefix: format!("{}/{}", masked, prefix_len),
            interface: iface,
            nexthop: "-".to_string(),
            action: behavior.to_string(),
            nh6: None,
        });
    }

    // End.X / uA — one per Up adjacency that has carved a function.
    for level in &[Level::L1, Level::L2] {
        for (ifindex, link) in isis.links.iter() {
            for (_sys_id, nbr) in link.state.nbrs.get(level).iter() {
                let Some((_, addr)) = nbr.endx_sid else {
                    continue;
                };
                let behavior = match isis.sr_locator.as_ref().and_then(|l| l.behavior.as_ref()) {
                    Some(crate::rib::LocatorBehavior::Usid) => "uA",
                    _ => "End.X",
                };
                rows.push(LocalSidRow {
                    prefix: format!("{}/128", addr),
                    interface: isis.ifname(*ifindex),
                    nexthop: nbr
                        .addr6l
                        .first()
                        .map(|a: &Ipv6Addr| a.to_string())
                        .unwrap_or_else(|| "-".to_string()),
                    action: behavior.to_string(),
                    nh6: nbr.addr6l.first().copied(),
                });
            }
        }
    }

    if rows.is_empty() {
        return Ok(());
    }

    const W_PREFIX: usize = 22;
    const W_INTERFACE: usize = 10;
    const W_NEXTHOP: usize = 26;

    writeln!(buf)?;
    writeln!(buf, "Local SRv6 SIDs:")?;
    writeln!(buf)?;
    writeln!(
        buf,
        " {:<wp$} {:<wi$} {:<wn$} Action",
        "Prefix",
        "Interface",
        "Nexthop",
        wp = W_PREFIX,
        wi = W_INTERFACE,
        wn = W_NEXTHOP,
    )?;
    let total = 1 + W_PREFIX + 1 + W_INTERFACE + 1 + W_NEXTHOP + 1 + 6;
    writeln!(buf, " {}", "-".repeat(total - 2))?;

    for row in rows {
        let action = if let Some(nh6) = row.nh6 {
            format!("seg6local {} nh6 {}", row.action, nh6)
        } else {
            format!("seg6local {}", row.action)
        };
        writeln!(
            buf,
            " {:<wp$} {:<wi$} {:<wn$} {}",
            row.prefix,
            row.interface,
            row.nexthop,
            action,
            wp = W_PREFIX,
            wi = W_INTERFACE,
            wn = W_NEXTHOP,
        )?;
    }

    Ok(())
}

struct LocalSidRow {
    prefix: String,
    interface: String,
    nexthop: String,
    action: String,
    nh6: Option<std::net::Ipv6Addr>,
}

/// Zero the lower (128 - prefix_len) bits of an IPv6 address. Mirrors
/// the helper in `rib::segment_routing::sid` so this section stays
/// readable without pulling that helper into the public surface.
fn mask_v6(addr: std::net::Ipv6Addr, prefix_len: u8) -> std::net::Ipv6Addr {
    if prefix_len >= 128 {
        return addr;
    }
    let bits = u128::from(addr);
    let shift = 128 - u32::from(prefix_len);
    let mask = !0u128 << shift;
    std::net::Ipv6Addr::from(bits & mask)
}

/// True when local config has MT 2 (IPv6 unicast) enabled. The IPv6
/// section of the topology / route show output should pull from the
/// MT 2 SPF + reach caches in this case so the rendered tree matches
/// what build_rib_from_spf_v6 actually installed.
fn mt2_v6_active(isis: &Isis) -> bool {
    use crate::isis::config::MtId;
    isis.config.mt_enabled && isis.config.mt_topologies.contains(&MtId::Ipv6Unicast)
}

fn format_area_id(net: &Nsap) -> String {
    // Render as <afi>.<area_id_bytes_hex_pairs>, the standard IS-IS area form.
    let mut s = format!("{:02x}", net.afi);
    for (i, b) in net.area_id.iter().enumerate() {
        if i % 2 == 0 {
            s.push('.');
        }
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn hostname_for(isis: &Isis, level: &Level, sys_id: &IsisSysId) -> String {
    isis.hostname
        .get(level)
        .get(sys_id)
        .map(|(name, _)| name.clone())
        .unwrap_or_else(|| sys_id.to_string())
}

// Find the local interface name for a directly-adjacent SysId at the given
// level, by walking link state. Returns "-" if no adjacency is found.
fn ifname_for_neighbor(isis: &Isis, level: &Level, sys_id: &IsisSysId) -> String {
    for (ifindex, link) in isis.links.iter() {
        if link.state.nbrs.get(level).get(sys_id).is_some() {
            return isis.ifname(*ifindex);
        }
    }
    String::from("-")
}

fn ipv6_capable_set_show(isis: &Isis, level: &Level) -> BTreeSet<IsisSysId> {
    let ipv6_proto: u8 = IsisProto::Ipv6.into();
    let mut set = BTreeSet::new();
    for (lsp_id, lsa) in isis.lsdb.get(level).iter() {
        for tlv in &lsa.lsp.tlvs {
            if let IsisTlv::ProtoSupported(ps) = tlv
                && ps.nlpids.contains(&ipv6_proto)
            {
                set.insert(lsp_id.sys_id());
            }
        }
    }
    set
}

#[allow(clippy::too_many_arguments)]
fn write_spf_tree(
    buf: &mut String,
    isis: &Isis,
    level: &Level,
    local_sys_id: &IsisSysId,
    spf_result: &std::collections::BTreeMap<usize, spf::Path>,
    ipv6: bool,
    mt2_mode: bool,
) -> std::fmt::Result {
    // Column widths chosen to fit the typical reference output.
    const W_VERTEX: usize = 22;
    const W_TYPE: usize = 13;
    const W_METRIC: usize = 7;
    const W_NEXTHOP: usize = 9;
    const W_INTERFACE: usize = 10;

    writeln!(
        buf,
        " {:<wv$} {:<wt$} {:<wm$} {:<wn$} {:<wi$} Parent",
        "Vertex",
        "Type",
        "Metric",
        "Next-Hop",
        "Interface",
        wv = W_VERTEX,
        wt = W_TYPE,
        wm = W_METRIC,
        wn = W_NEXTHOP,
        wi = W_INTERFACE,
    )?;
    let total = 1 + W_VERTEX + 1 + W_TYPE + 1 + W_METRIC + 1 + W_NEXTHOP + 1 + W_INTERFACE + 1 + 8;
    writeln!(buf, " {}", "-".repeat(total - 2))?;

    // For IPv6 trees in legacy single-topology mode, gate by NLPID-
    // capable set per RFC 1195 §5 so the tree mirrors what
    // build_rib_from_spf_v6 installs. In MT 2 mode the SPF graph is
    // already filtered to MT-2-capable peers (TLV 229 is the
    // stricter signal), so the NLPID gate is redundant — skip it.
    let ipv6_capable = if ipv6 && !mt2_mode {
        Some(ipv6_capable_set_show(isis, level))
    } else {
        None
    };

    let mut nodes: Vec<(usize, &spf::Path)> = spf_result.iter().map(|(k, v)| (*k, v)).collect();
    nodes.sort_by_key(|(_, p)| (p.cost, p.id));

    let local_hostname = hostname_for(isis, level, local_sys_id);

    for (node_id, path) in &nodes {
        let Some(node_sys_id) = isis.lsp_map.get(level).resolve(*node_id) else {
            continue;
        };
        let node_sys_id = *node_sys_id;
        let is_self = node_sys_id == *local_sys_id;
        if let Some(set) = &ipv6_capable
            && !set.contains(&node_sys_id)
        {
            continue;
        }
        let node_hostname = hostname_for(isis, level, &node_sys_id);

        // First-hop hostname / interface (blank for self).
        let (nexthop_str, iface_str, parent_str) = if is_self {
            (String::new(), String::new(), String::new())
        } else {
            // Each path = [first_hop, ..., destination]; take the first as
            // first-hop and the previous-to-last as parent. For a direct
            // neighbor (path len 1), parent is the local node.
            let p = path.paths.first().cloned().unwrap_or_default();
            if p.is_empty() {
                (String::new(), String::new(), local_hostname.clone())
            } else {
                let first_hop_sys_id = isis
                    .lsp_map
                    .get(level)
                    .resolve(p[0])
                    .copied()
                    .unwrap_or(node_sys_id);
                let parent_sys_id = if p.len() <= 1 {
                    *local_sys_id
                } else {
                    isis.lsp_map
                        .get(level)
                        .resolve(p[p.len() - 2])
                        .copied()
                        .unwrap_or(*local_sys_id)
                };
                (
                    hostname_for(isis, level, &first_hop_sys_id),
                    ifname_for_neighbor(isis, level, &first_hop_sys_id),
                    hostname_for(isis, level, &parent_sys_id),
                )
            }
        };

        // Vertex row for the node itself.
        if is_self {
            // Match reference: just the hostname, all other columns blank.
            writeln!(buf, " {}", node_hostname)?;
        } else {
            writeln!(
                buf,
                " {:<wv$} {:<wt$} {:<wm$} {:<wn$} {:<wi$} {}(0)",
                node_hostname,
                "TE-IS",
                path.cost,
                nexthop_str,
                iface_str,
                parent_str,
                wv = W_VERTEX,
                wt = W_TYPE,
                wm = W_METRIC,
                wn = W_NEXTHOP,
                wi = W_INTERFACE,
            )?;
        }

        // Prefix rows hanging off this node.
        if !ipv6 {
            if let Some(entries) = isis.reach_map.get(level).get(&Afi::Ip).get(&node_sys_id) {
                for entry in entries.iter() {
                    let type_str = if is_self { "IP internal" } else { "IP TE" };
                    let total_metric = path.cost + entry.metric;
                    let (nh, iface) = if is_self {
                        (String::new(), String::new())
                    } else {
                        (nexthop_str.clone(), iface_str.clone())
                    };
                    writeln!(
                        buf,
                        " {:<wv$} {:<wt$} {:<wm$} {:<wn$} {:<wi$} {}(0)",
                        entry.prefix.trunc().to_string(),
                        type_str,
                        total_metric,
                        nh,
                        iface,
                        node_hostname,
                        wv = W_VERTEX,
                        wt = W_TYPE,
                        wm = W_METRIC,
                        wn = W_NEXTHOP,
                        wi = W_INTERFACE,
                    )?;
                }
            }
        } else if let Some(entries) = (if mt2_mode {
            isis.mt2_reach_map_v6.get(level)
        } else {
            isis.reach_map_v6.get(level)
        })
        .get(&node_sys_id)
        {
            for entry in entries.iter() {
                let total_metric = path.cost + entry.metric;
                let (nh, iface) = if is_self {
                    (String::new(), String::new())
                } else {
                    (nexthop_str.clone(), iface_str.clone())
                };
                writeln!(
                    buf,
                    " {:<wv$} {:<wt$} {:<wm$} {:<wn$} {:<wi$} {}(0)",
                    entry.prefix.trunc().to_string(),
                    "IP6 internal",
                    total_metric,
                    nh,
                    iface,
                    node_hostname,
                    wv = W_VERTEX,
                    wt = W_TYPE,
                    wm = W_METRIC,
                    wn = W_NEXTHOP,
                    wi = W_INTERFACE,
                )?;
            }
        }
    }

    Ok(())
}

fn write_rib_v4(buf: &mut String, isis: &Isis, level: &Level) -> std::fmt::Result {
    const W_PREFIX: usize = 18;
    const W_METRIC: usize = 7;
    const W_INTERFACE: usize = 10;
    const W_NEXTHOP: usize = 16;

    writeln!(
        buf,
        " {:<wp$} {:<wm$} {:<wi$} {:<wn$} Label(s)",
        "Prefix",
        "Metric",
        "Interface",
        "Nexthop",
        wp = W_PREFIX,
        wm = W_METRIC,
        wi = W_INTERFACE,
        wn = W_NEXTHOP,
    )?;
    let total = 1 + W_PREFIX + 1 + W_METRIC + 1 + W_INTERFACE + 1 + W_NEXTHOP + 1 + 9;
    writeln!(buf, " {}", "-".repeat(total - 2))?;

    let mut entries: Vec<_> = isis.rib.get(level).iter().collect();
    entries.sort_by_key(|(p, _)| **p);

    for (prefix, route) in entries {
        if route.nhops.is_empty() {
            // Locally connected / no nexthop.
            let label = route
                .sid
                .map(|s| s.to_string())
                .unwrap_or_else(|| "-".into());
            writeln!(
                buf,
                " {:<wp$} {:<wm$} {:<wi$} {:<wn$} {}",
                prefix.to_string(),
                route.metric,
                "-",
                "-",
                label,
                wp = W_PREFIX,
                wm = W_METRIC,
                wi = W_INTERFACE,
                wn = W_NEXTHOP,
            )?;
            continue;
        }
        for (addr, nhop) in route.nhops.iter() {
            let label = if let Some(sid) = route.sid {
                if nhop.adjacency {
                    format!("{} (impl-null)", sid)
                } else {
                    sid.to_string()
                }
            } else {
                "-".into()
            };
            writeln!(
                buf,
                " {:<wp$} {:<wm$} {:<wi$} {:<wn$} {}",
                prefix.to_string(),
                route.metric,
                isis.ifname(nhop.ifindex),
                addr,
                label,
                wp = W_PREFIX,
                wm = W_METRIC,
                wi = W_INTERFACE,
                wn = W_NEXTHOP,
            )?;
        }
    }
    Ok(())
}

fn write_rib_v6(buf: &mut String, isis: &Isis, level: &Level) -> std::fmt::Result {
    const W_PREFIX: usize = 22;
    const W_METRIC: usize = 7;
    const W_INTERFACE: usize = 10;
    const W_NEXTHOP: usize = 26;

    writeln!(
        buf,
        " {:<wp$} {:<wm$} {:<wi$} {:<wn$} Label(s)",
        "Prefix",
        "Metric",
        "Interface",
        "Nexthop",
        wp = W_PREFIX,
        wm = W_METRIC,
        wi = W_INTERFACE,
        wn = W_NEXTHOP,
    )?;
    let total = 1 + W_PREFIX + 1 + W_METRIC + 1 + W_INTERFACE + 1 + W_NEXTHOP + 1 + 9;
    writeln!(buf, " {}", "-".repeat(total - 2))?;

    let mut entries: Vec<_> = isis.rib_v6.get(level).iter().collect();
    entries.sort_by_key(|(p, _)| **p);

    for (prefix, route) in entries {
        if route.nhops.is_empty() {
            writeln!(
                buf,
                " {:<wp$} {:<wm$} {:<wi$} {:<wn$} -",
                prefix.to_string(),
                route.metric,
                "-",
                "-",
                wp = W_PREFIX,
                wm = W_METRIC,
                wi = W_INTERFACE,
                wn = W_NEXTHOP,
            )?;
            continue;
        }
        for (addr, nhop) in route.nhops.iter() {
            writeln!(
                buf,
                " {:<wp$} {:<wm$} {:<wi$} {:<wn$} -",
                prefix.to_string(),
                route.metric,
                isis.ifname(nhop.ifindex),
                addr,
                wp = W_PREFIX,
                wm = W_METRIC,
                wi = W_INTERFACE,
                wn = W_NEXTHOP,
            )?;
        }
    }
    Ok(())
}

// JSON structures for ISIS database
#[derive(Serialize)]
struct DatabaseJson {
    level_1: Vec<LspEntryJson>,
    level_2: Vec<LspEntryJson>,
}

#[derive(Serialize)]
struct LspEntryJson {
    lsp_id: String,
    system_id: String,
    originated: bool,
    pdu_len: u16,
    seq_number: u32,
    checksum: u16,
    holdtime: u64,
    att_bit: u8,
    p_bit: u8,
    ol_bit: u8,
}

fn show_isis_database(
    isis: &Isis,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    if json {
        // JSON output
        let mut database_json = DatabaseJson {
            level_1: Vec::new(),
            level_2: Vec::new(),
        };

        // Helper closure to collect LSP entries for a given level
        let collect_lsp_entries = |level: &Level,
                                   lsdb: &crate::isis::lsdb::Lsdb|
         -> Vec<LspEntryJson> {
            let mut entries = Vec::new();

            for (lsp_id, lsa) in lsdb.iter() {
                let rem = lsa.hold_timer.as_ref().map_or(0, |timer| timer.rem_sec());
                let att_bit = if lsa.lsp.types.att_bits() != 0 { 1 } else { 0 };
                let p_bit = if lsa.lsp.types.p_bits() { 1 } else { 0 };
                let ol_bit = if lsa.lsp.types.ol_bits() { 1 } else { 0 };

                let system_id =
                    if let Some((hostname, _)) = isis.hostname.get(level).get(&lsp_id.sys_id()) {
                        format!(
                            "{}.{:02x}-{:02x}",
                            hostname,
                            lsp_id.pseudo_id(),
                            lsp_id.fragment_id()
                        )
                    } else {
                        lsp_id.to_string()
                    };

                entries.push(LspEntryJson {
                    lsp_id: lsp_id.to_string(),
                    system_id,
                    originated: lsa.originated,
                    pdu_len: lsa.lsp.pdu_len,
                    seq_number: lsa.lsp.seq_number,
                    checksum: lsa.lsp.checksum,
                    holdtime: rem,
                    att_bit,
                    p_bit,
                    ol_bit,
                });
            }

            entries
        };

        database_json.level_1 = collect_lsp_entries(&Level::L1, &isis.lsdb.l1);
        database_json.level_2 = collect_lsp_entries(&Level::L2, &isis.lsdb.l2);

        Ok(serde_json::to_string_pretty(&database_json)
            .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialize database: {}\"}}", e)))
    } else {
        // Text output (existing implementation)
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
            )?;
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
            )?;
        }

        Ok(buf)
    }
}

fn show_isis_database_detail(
    isis: &Isis,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    if json {
        // Use serde to serialize both L1 and L2 databases
        let mut all_lsps = Vec::new();
        all_lsps.extend(isis.lsdb.l1.values().map(|x| &x.lsp));
        all_lsps.extend(isis.lsdb.l2.values().map(|x| &x.lsp));
        Ok(serde_json::to_string_pretty(&all_lsps).unwrap())
    } else {
        // Generate a nicely formatted string for human-readable format
        let mut result = String::new();

        // Helper closure to format LSPs for a given level
        let format_level = |level: &Level, lsdb: &crate::isis::lsdb::Lsdb| -> String {
            // Check if LSDB has any entries
            if lsdb.iter().count() == 0 {
                return String::new();
            }

            let mut level_output = String::with_capacity(1024 + (lsdb.iter().count() * 100));
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
                            hostname,
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

        Ok(result)
    }
}

fn show_isis_adjacency(
    top: &Isis,
    _args: Args,
    _json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    let mut buf = String::new();

    for (_, link) in top.links.iter() {
        writeln!(buf, "Interface: {}", top.ifname(link.ifindex))?;
        if let Some((adj, _)) = &link.state.adj.get(&Level::L1) {
            writeln!(buf, "  Adj: {}", adj)?;
        } else {
            writeln!(buf, "  Adj: N/A")?;
        }

        writeln!(buf, "Interface: {}", top.ifname(link.ifindex)).unwrap();
        if let Some((adj, _)) = &link.state.adj.get(&Level::L2) {
            writeln!(buf, "  Adj: {}", adj).unwrap();
        } else {
            writeln!(buf, "  Adj: N/A").unwrap();
        }
    }
    Ok(buf)
}

fn show_isis_spf(
    isis: &Isis,
    _args: Args,
    _json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    let mut buf = String::new();

    // Legacy single-topology SPF — drives IPv4 RIB always, plus
    // IPv6 RIB when MT 2 is off. Print L1 then L2.
    if let Some(spf) = isis.spf_result.get(&Level::L1) {
        let _ = writeln!(buf, "L1 SPF (single-topology / MT 0)");
        spf::disp_out(&mut buf, spf, false);
    }
    if let Some(spf) = isis.spf_result.get(&Level::L2) {
        let _ = writeln!(buf, "L2 SPF (single-topology / MT 0)");
        spf::disp_out(&mut buf, spf, false);
    }

    // MT 2 SPF — only computed when local config has MT 2 in
    // mt_topologies. We print the raw tree from mt2_spf_result here
    // regardless of whether the legacy SPF is also present so
    // operators can compare metrics across topologies.
    if let Some(spf) = isis.mt2_spf_result.get(&Level::L1) {
        let _ = writeln!(buf, "L1 SPF (MT 2 / IPv6 unicast)");
        spf::disp_out(&mut buf, spf, false);
    }
    if let Some(spf) = isis.mt2_spf_result.get(&Level::L2) {
        let _ = writeln!(buf, "L2 SPF (MT 2 / IPv6 unicast)");
        spf::disp_out(&mut buf, spf, false);
    }

    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rib::{Locator, LocatorBehavior};

    #[test]
    fn locator_row_classic_when_resolved_with_no_behavior() {
        let loc = Locator {
            name: "LOC_N1".into(),
            prefix: Some("2001:db8:a:2::/64".parse().unwrap()),
            behavior: None,
        };
        let row = render_locator_row("LOC_N1", Some(&loc));
        assert!(row.contains("LOC_N1"));
        assert!(row.contains("2001:db8:a:2::/64"));
        assert!(row.contains("Classic"));
        assert!(row.trim_end().ends_with("Up"));
    }

    #[test]
    fn locator_row_usid_when_resolved_with_usid_behavior() {
        let loc = Locator {
            name: "LOC_N1".into(),
            prefix: Some("2001:db8:a:2::/64".parse().unwrap()),
            behavior: Some(LocatorBehavior::Usid),
        };
        let row = render_locator_row("LOC_N1", Some(&loc));
        assert!(row.contains("uSID"));
        assert!(row.trim_end().ends_with("Up"));
    }

    #[test]
    fn locator_row_down_when_unresolved() {
        // The configured name still shows so operators can tell which
        // locator they're waiting on; prefix and behavior columns are
        // blank because the RIB hasn't pushed a snapshot.
        let row = render_locator_row("LOC_N1", None);
        assert!(row.starts_with("LOC_N1"));
        assert!(row.trim_end().ends_with("Down"));
        assert!(!row.contains("uSID"));
        assert!(!row.contains("Classic"));
    }

    #[test]
    fn locator_row_down_when_resolved_without_prefix() {
        // Locator entry exists in the global config but has no prefix
        // leaf yet. Same Down treatment as fully unresolved.
        let loc = Locator {
            name: "LOC_N1".into(),
            prefix: None,
            behavior: None,
        };
        let row = render_locator_row("LOC_N1", Some(&loc));
        assert!(row.trim_end().ends_with("Down"));
    }
}
