use std::collections::BTreeSet;
use std::fmt::Write;

use ipnet::{Ipv4Net, Ipv6Net};
use isis_packet::{IsisProto, IsisSysId, IsisTlv, Nsap};
use prefix_trie::PrefixMap;
use serde::Serialize;

use super::inst::{RepairPathMpls, RepairPathSrv6, SpfNexthop, SpfNexthopV6, SpfRoute, SpfRouteV6};
use super::{Isis, inst::ShowCallback};

use crate::config::Args;
use crate::isis::link::Afi;
use crate::isis::{Level, hostname, link, neigh};
use crate::rib;
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
        self.show_add("/show/isis/route/detail", show_isis_route_detail);
        self.show_add(
            "/show/isis/fast-reroute/summary",
            show_isis_fast_reroute_summary,
        );
        self.show_add(
            "/show/isis/fast-reroute/prefix/detail",
            show_isis_fast_reroute_prefix_detail,
        );
        self.show_add("/show/isis/interface", link::show);
        self.show_add("/show/isis/interface/detail", link::show_detail);
        self.show_add("/show/isis/dis/statistics", link::show_dis_statistics);
        self.show_add("/show/isis/dis/history", link::show_dis_history);
        self.show_add("/show/isis/neighbor", neigh::show);
        self.show_add("/show/isis/neighbor/detail", neigh::show_detail);
        self.show_add("/show/isis/database", show_isis_database);
        self.show_add("/show/isis/database/detail", show_isis_database_detail);
        self.show_add("/show/isis/hostname", hostname::show);
        self.show_add("/show/isis/graph", show_isis_graph);
        self.show_add("/show/isis/spf", show_isis_spf);
        self.show_add("/show/isis/spf/detail", show_isis_spf_detail);
        self.show_add("/show/isis/repair-list", show_isis_repair_list);
        self.show_add(
            "/show/isis/repair-list/detail",
            show_isis_repair_list_detail,
        );
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
    pub olinks: Vec<LinkJson>,
    pub ilinks: Vec<LinkJson>,
}

#[derive(Serialize)]
struct LinkJson {
    pub id: usize,
    pub name: String,
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
                if !node.olinks.is_empty() || !node.ilinks.is_empty() {
                    writeln!(buf, "    Links:")?;
                    for link in &node.olinks {
                        writeln!(buf, "      -> {} (cost: {})", link.name, link.cost)?;
                    }
                    for link in &node.ilinks {
                        writeln!(buf, "      <- {} (cost: {})", link.name, link.cost)?;
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
        // Collect all outgoing olinks from this node
        let mut node_olinks = Vec::new();

        for link in &node.olinks {
            // Get the destination node name
            if let Some(to_node) = graph.get(&link.to) {
                node_olinks.push(LinkJson {
                    id: link.to,
                    name: to_node.name.clone(),
                    cost: link.cost,
                });
            }
        }

        // Collect all outgoing ilinks from this node
        let mut node_ilinks = Vec::new();

        for link in &node.ilinks {
            // Get the destination node name
            if let Some(from_node) = graph.get(&link.from) {
                node_ilinks.push(LinkJson {
                    id: link.from,
                    name: from_node.name.clone(),
                    cost: link.cost,
                });
            }
        }

        nodes.push(NodeJson {
            id: *id,
            name: node.name.clone(),
            sys_id: node.sys_id.clone(),
            olinks: node_olinks,
            ilinks: node_ilinks,
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

/// `show isis route detail` — per-prefix RIB view that surfaces
/// TI-LFA backup paths and SR-MPLS / SRv6 segment information that
/// the one-line `show isis route` view doesn't have room for.
/// JSON path falls through to the one-line JSON for now.
fn show_isis_route_detail(
    isis: &Isis,
    args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    if json {
        return show_isis_route(isis, args, json);
    }
    write_show_isis_route_text_detail(isis)
}

/// Per-level TI-LFA protection tallies. Counts are per-route, not
/// per-nexthop: a route is "Protected" when at least one of its
/// SpfNexthop entries has a `backup` stamped. Within Protected,
/// trivial / 1-segment / N-segment classify the FIRST stamped
/// backup's label-stack length (subsequent backups on the same
/// route currently match by construction — tilfa_repair_path emits
/// one repair per dest today).
#[derive(Default, Debug, PartialEq, Eq)]
struct FrrSummary {
    total: usize,
    protected: usize,
    unprotected: usize,
    trivial: usize,
    one_segment: usize,
    multi_segment: usize,
}

/// Tally TI-LFA protection state across the IPv4 RIB at one level.
fn summarize_frr_v4(isis: &Isis, level: &Level) -> FrrSummary {
    let mut s = FrrSummary::default();
    for (_, route) in isis.rib.get(level).iter() {
        s.total += 1;
        let first_backup = route.nhops.values().find_map(|n| n.backup.as_ref());
        match first_backup {
            None => s.unprotected += 1,
            Some(b) => {
                s.protected += 1;
                match b.labels.len() {
                    0 => s.trivial += 1,
                    1 => s.one_segment += 1,
                    _ => s.multi_segment += 1,
                }
            }
        }
    }
    s
}

/// IPv6 sibling — label-stack length test is replaced by SRv6
/// `segs` length since that's the SR steering dimension in the SRv6
/// dataplane.
fn summarize_frr_v6(isis: &Isis, level: &Level) -> FrrSummary {
    let mut s = FrrSummary::default();
    for (_, route) in isis.rib_v6.get(level).iter() {
        s.total += 1;
        let first_backup = route.nhops.values().find_map(|n| n.backup.as_ref());
        match first_backup {
            None => s.unprotected += 1,
            Some(b) => {
                s.protected += 1;
                match b.segs.len() {
                    0 => s.trivial += 1,
                    1 => s.one_segment += 1,
                    _ => s.multi_segment += 1,
                }
            }
        }
    }
    s
}

fn write_frr_summary_block(buf: &mut String, label: &str, s: &FrrSummary) -> std::fmt::Result {
    writeln!(buf, "    {}", label)?;
    writeln!(buf, "      Total prefixes:   {:>6}", s.total)?;
    writeln!(buf, "      Protected:        {:>6}", s.protected)?;
    if s.protected > 0 {
        writeln!(buf, "        Trivial repair: {:>6}", s.trivial)?;
        writeln!(buf, "        1-segment SR:   {:>6}", s.one_segment)?;
        writeln!(buf, "        N-segment SR:   {:>6}", s.multi_segment)?;
    }
    writeln!(buf, "      Unprotected:      {:>6}", s.unprotected)?;
    Ok(())
}

/// `show isis fast-reroute summary` — per-area, per-level tallies of
/// TI-LFA protection state. Reports IPv4 and IPv6 separately so the
/// numbers stay legible when one AF has SR enabled and the other
/// doesn't.
fn show_isis_fast_reroute_summary(
    isis: &Isis,
    _args: Args,
    _json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    let mut buf = String::new();
    writeln!(buf, "Area {}:", format_area_id(&isis.config.net))?;
    let mut wrote_any = false;
    for level in &[Level::L1, Level::L2] {
        let v4 = summarize_frr_v4(isis, level);
        let v6 = summarize_frr_v6(isis, level);
        if v4.total == 0 && v6.total == 0 {
            continue;
        }
        wrote_any = true;
        let level_long = match level {
            Level::L1 => "Level-1",
            Level::L2 => "Level-2",
        };
        writeln!(buf)?;
        writeln!(buf, "  {}:", level_long)?;
        if v4.total > 0 {
            write_frr_summary_block(&mut buf, "IPv4:", &v4)?;
        }
        if v6.total > 0 {
            write_frr_summary_block(&mut buf, "IPv6:", &v6)?;
        }
    }
    if !wrote_any {
        writeln!(buf, "  (no IS-IS RIB entries yet)")?;
    }
    Ok(buf)
}

/// `show isis fast-reroute prefix A.B.C.D/N detail` — per-prefix
/// view focused on the TI-LFA repair info for one prefix. Tries v4
/// across both levels first; v6 not supported via this command path
/// today (prefix arg is constrained to inet:ipv4-prefix in the
/// grammar — IPv6 fast-reroute is reachable via `show isis route
/// detail`).
fn show_isis_fast_reroute_prefix_detail(
    isis: &Isis,
    mut args: Args,
    _json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    let Some(prefix) = args.v4net() else {
        return Ok("% Invalid IPv4 prefix\n".to_string());
    };

    let mut buf = String::new();
    let mut found = false;
    for level in &[Level::L1, Level::L2] {
        let Some(route) = isis.rib.get(level).get(&prefix) else {
            continue;
        };
        found = true;
        let level_short = match level {
            Level::L1 => "L1",
            Level::L2 => "L2",
        };
        writeln!(buf, "{} {} [metric {}]", level_short, prefix, route.metric)?;

        // Surface protection state up-front so an operator scanning
        // the output knows whether a backup is even present.
        let any_backup = route.nhops.values().any(|n| n.backup.is_some());
        if any_backup {
            writeln!(buf, "  Protected by TI-LFA")?;
        } else {
            writeln!(buf, "  Unprotected (no TI-LFA backup stamped)")?;
        }

        for (addr, nhop) in route.nhops.iter() {
            write_isis_nhop_v4_detail(&mut buf, isis, level, route, addr, nhop)?;
        }
    }
    if !found {
        return Ok(format!("% No route for {prefix} in IS-IS RIB\n"));
    }
    Ok(buf)
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

/// Extract the numeric value of an `rib::Label` regardless of
/// implicit-null vs explicit. Useful for "first label in the repair
/// stack" lookups where the distinction doesn't matter.
fn label_value(l: &rib::Label) -> u32 {
    match l {
        rib::Label::Implicit(n) | rib::Label::Explicit(n) => *n,
    }
}

/// Resolve an MPLS label to a symbolic node name, when the label is
/// a prefix-SID (Node-SID) inside some peer's SRGB. Returns `None`
/// for labels outside any peer's SRGB — typically Adj-SIDs (which
/// fall in the SRLB or local label range), or labels owned by a peer
/// we don't yet know about.
///
/// Fallback chain (per design decision): hostname → sys-id string.
/// Router-id mapping is a follow-up (would require an LSDB walk for
/// the TE-router-id sub-TLV).
fn label_to_node_symbol(isis: &Isis, level: &Level, label: u32) -> Option<String> {
    for (sys_id, cfg) in isis.label_map.get(level).iter() {
        if label >= cfg.global.start && label < cfg.global.end {
            return Some(hostname_for(isis, level, sys_id));
        }
    }
    None
}

/// SRGB base label for a peer's prefix-SIDs. `None` when the peer
/// has not yet advertised an SR Capability.
fn srgb_base_for(isis: &Isis, level: &Level, sys_id: &IsisSysId) -> Option<u32> {
    isis.label_map
        .get(level)
        .get(sys_id)
        .map(|c| c.global.start)
}

/// Render the MPLS label stack of a backup path in `{ L1 L2 L3 }`
/// notation (push order, matching the RIB-side `Labels imposed`
/// format). Empty stack means trivial repair — caller renders a
/// separate `(trivial repair)` line.
fn fmt_isis_label_stack(labels: &[rib::Label]) -> String {
    let parts: Vec<String> = labels.iter().map(|l| label_value(l).to_string()).collect();
    format!("{{ {} }}", parts.join(" "))
}

/// Render an SRv6 segment list in `{ addr, addr }` notation.
fn fmt_isis_srv6_segs(segs: &[std::net::Ipv6Addr]) -> String {
    let parts: Vec<String> = segs.iter().map(|a| a.to_string()).collect();
    format!("{{ {} }}", parts.join(", "))
}

/// Emit one nhop block for the IPv4 detail view. Walks the primary
/// (addr + iface + neighbor hostname + SRGB), the route's
/// prefix-SID if present, and the backup path when stamped.
fn write_isis_nhop_v4_detail(
    buf: &mut String,
    isis: &Isis,
    level: &Level,
    route: &SpfRoute,
    addr: &std::net::Ipv4Addr,
    nhop: &SpfNexthop,
) -> std::fmt::Result {
    let nbr_hostname = nhop
        .sys_id
        .map(|s| hostname_for(isis, level, &s))
        .unwrap_or_else(|| "-".into());
    write!(
        buf,
        "  via {}, {}, {}",
        addr,
        isis.ifname(nhop.ifindex),
        nbr_hostname
    )?;
    if let Some(srgb) = nhop.sys_id.and_then(|s| srgb_base_for(isis, level, &s)) {
        write!(buf, ", SRGB Base: {}", srgb)?;
    }
    writeln!(buf)?;

    if let Some(sid) = route.sid {
        let tag = if nhop.adjacency { " (impl-null)" } else { "" };
        writeln!(buf, "    Prefix-SID: {}{}", sid, tag)?;
    }

    if let Some(backup) = &nhop.backup {
        write_isis_backup_v4_detail(buf, isis, level, backup)?;
    }
    Ok(())
}

/// Emit the `Backup path:` stanza for a stamped MPLS repair.
fn write_isis_backup_v4_detail(
    buf: &mut String,
    isis: &Isis,
    level: &Level,
    backup: &RepairPathMpls,
) -> std::fmt::Result {
    // Repair-nbr hostname comes from the first label's SRGB owner
    // when the label resolves; otherwise the per-link nbr name is
    // not directly known from RepairPathMpls (the local egress
    // ifindex is, but not the peer's sys-id). Best-effort lookup.
    let first_label = backup.labels.first().map(label_value);
    let p_node = first_label.and_then(|n| label_to_node_symbol(isis, level, n));
    let nbr_label = p_node.clone().unwrap_or_else(|| "-".into());

    writeln!(
        buf,
        "    Backup path: TI-LFA, via {}, {} {}",
        backup.addr,
        isis.ifname(backup.ifindex),
        nbr_label,
    )?;
    if backup.labels.is_empty() {
        writeln!(buf, "      (trivial repair, no SR segments)")?;
    } else {
        writeln!(
            buf,
            "      Labels imposed {}",
            fmt_isis_label_stack(&backup.labels)
        )?;
        if let (Some(label), Some(name)) = (first_label, p_node) {
            writeln!(buf, "      P node: {}, Label: {}", name, label)?;
        } else if let Some(label) = first_label {
            writeln!(buf, "      P node: label {}", label)?;
        }
    }
    Ok(())
}

/// IPv6 sibling — same shape but SRH segments instead of MPLS
/// labels.
fn write_isis_nhop_v6_detail(
    buf: &mut String,
    isis: &Isis,
    level: &Level,
    _route: &SpfRouteV6,
    addr: &std::net::Ipv6Addr,
    nhop: &SpfNexthopV6,
) -> std::fmt::Result {
    let nbr_hostname = nhop
        .sys_id
        .map(|s| hostname_for(isis, level, &s))
        .unwrap_or_else(|| "-".into());
    writeln!(
        buf,
        "  via {}, {}, {}",
        addr,
        isis.ifname(nhop.ifindex),
        nbr_hostname
    )?;

    if let Some(backup) = &nhop.backup {
        write_isis_backup_v6_detail(buf, isis, level, backup)?;
    }
    Ok(())
}

fn write_isis_backup_v6_detail(
    buf: &mut String,
    _isis: &Isis,
    _level: &Level,
    backup: &RepairPathSrv6,
) -> std::fmt::Result {
    writeln!(
        buf,
        "    Backup path: TI-LFA, via {}, {}",
        backup.addr,
        _isis.ifname(backup.ifindex),
    )?;
    if backup.segs.is_empty() {
        writeln!(buf, "      (trivial repair, no SR segments)")?;
    } else {
        writeln!(
            buf,
            "      SID list {}, Encap: {:?}",
            fmt_isis_srv6_segs(&backup.segs),
            backup.encap,
        )?;
    }
    Ok(())
}

/// `show isis route detail` per-level IPv4 RIB renderer. Replaces
/// the columnar `write_rib_v4` layout with per-prefix blocks that
/// surface TI-LFA backup paths.
fn write_rib_v4_detail(buf: &mut String, isis: &Isis, level: &Level) -> std::fmt::Result {
    let level_short = match level {
        Level::L1 => "L1",
        Level::L2 => "L2",
    };

    let mut entries: Vec<_> = isis.rib.get(level).iter().collect();
    entries.sort_by_key(|(p, _)| **p);

    for (prefix, route) in entries {
        writeln!(buf, "{} {} [metric {}]", level_short, prefix, route.metric)?;
        if route.nhops.is_empty() {
            writeln!(buf, "  (directly connected / no nexthop)")?;
            continue;
        }
        for (addr, nhop) in route.nhops.iter() {
            write_isis_nhop_v4_detail(buf, isis, level, route, addr, nhop)?;
        }
    }
    Ok(())
}

fn write_rib_v6_detail(buf: &mut String, isis: &Isis, level: &Level) -> std::fmt::Result {
    let level_short = match level {
        Level::L1 => "L1",
        Level::L2 => "L2",
    };

    let mut entries: Vec<_> = isis.rib_v6.get(level).iter().collect();
    entries.sort_by_key(|(p, _)| **p);

    for (prefix, route) in entries {
        writeln!(buf, "{} {} [metric {}]", level_short, prefix, route.metric)?;
        if route.nhops.is_empty() {
            writeln!(buf, "  (directly connected / no nexthop)")?;
            continue;
        }
        for (addr, nhop) in route.nhops.iter() {
            write_isis_nhop_v6_detail(buf, isis, level, route, addr, nhop)?;
        }
    }
    Ok(())
}

/// Top-level orchestrator for `show isis route detail`. Mirrors
/// `write_show_isis_route_text` (per-area, per-level) but skips the
/// SPF-tree section since the detail view is RIB-centric.
fn write_show_isis_route_text_detail(isis: &Isis) -> std::result::Result<String, std::fmt::Error> {
    let mut buf = String::new();
    writeln!(buf, "Area {}:", format_area_id(&isis.config.net))?;

    let mut wrote_any = false;
    for level in &[Level::L1, Level::L2] {
        let v4_empty = isis.rib.get(level).iter().next().is_none();
        let v6_empty = isis.rib_v6.get(level).iter().next().is_none();
        if v4_empty && v6_empty {
            continue;
        }
        wrote_any = true;
        let level_short = match level {
            Level::L1 => "L1",
            Level::L2 => "L2",
        };

        writeln!(buf)?;
        writeln!(buf, "IS-IS {} IPv4 routing table:", level_short)?;
        writeln!(buf)?;
        write_rib_v4_detail(&mut buf, isis, level)?;

        writeln!(buf)?;
        writeln!(buf, "IS-IS {} IPv6 routing table:", level_short)?;
        writeln!(buf)?;
        write_rib_v6_detail(&mut buf, isis, level)?;
    }

    if !wrote_any {
        writeln!(buf, "(no IS-IS RIB entries yet)")?;
    }
    Ok(buf)
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

fn show_isis_spf(
    isis: &Isis,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    if json {
        return Ok(spf_json(isis, /* detail = */ false));
    }
    let mut buf = String::new();
    write_spf_brief(isis, &mut buf);
    Ok(buf)
}

fn show_isis_spf_detail(
    isis: &Isis,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    if json {
        return Ok(spf_json(isis, /* detail = */ true));
    }
    let mut buf = String::new();
    write_spf_status_banner(isis, &mut buf);
    write_spf_brief(isis, &mut buf);
    // Per-destination repair-path detail is rendered here once
    // SpfNexthop.backup lands (Step 2 of the TI-LFA branch plan).
    // The CLI surface and JSON shape are locked now so downstream
    // tooling can wire against the path/keys without churn.
    let _ = writeln!(
        buf,
        "(per-destination TI-LFA repair-path detail not yet implemented)"
    );
    Ok(buf)
}

// ---- show isis repair-list / repair-list detail ----------------------
//
// Walks isis.rib (IPv4 / SR-MPLS) and isis.rib_v6 (IPv6 / SRv6) for
// nhops whose `backup` is populated by TI-LFA, and renders one row per
// (prefix, primary nhop) with the repair next-hop and label / segment
// stack. Detail mode adds a NodeSID/AdjSID breakdown per segment.

#[derive(Serialize)]
struct RepairListJson {
    routes: Vec<RepairRowJson>,
}

#[derive(Serialize)]
struct RepairRowJson {
    level: String,
    family: &'static str,
    prefix: String,
    primary_nexthop: String,
    primary_ifindex: u32,
    primary_metric: u32,
    repair_nexthop: String,
    repair_ifindex: u32,
    repair_metric: u32,
    segments: Vec<RepairSegmentJson>,
}

#[derive(Serialize)]
struct RepairSegmentJson {
    /// "NodeSID" / "AdjSID" for SR-MPLS, "End" / "End.X" for SRv6.
    kind: &'static str,
    /// MPLS label value as a number, or SRv6 segment address as a string.
    value: String,
}

/// First segment is conventionally the prefix-SID of the P-node
/// (1-label / 1-segment repair → that's the destination itself);
/// any subsequent segment is the AdjSID / End.X bridging P→Q.
fn mpls_segment_kind(idx: usize) -> &'static str {
    if idx == 0 { "NodeSID" } else { "AdjSID" }
}

fn srv6_segment_kind(idx: usize) -> &'static str {
    if idx == 0 { "End" } else { "End.X" }
}

fn label_value_str(label: &crate::rib::Label) -> String {
    match label {
        crate::rib::Label::Implicit(l) => format!("{l} (implicit-null)"),
        crate::rib::Label::Explicit(l) => format!("{l}"),
    }
}

fn collect_repair_rows(isis: &Isis) -> Vec<RepairRowJson> {
    let mut rows = Vec::new();
    for level in [Level::L1, Level::L2] {
        let v4: &PrefixMap<Ipv4Net, SpfRoute> = isis.rib.get(&level);
        for (prefix, route) in v4.iter() {
            for (addr, nhop) in route.nhops.iter() {
                let Some(backup) = nhop.backup.as_ref() else {
                    continue;
                };
                let segments = backup
                    .labels
                    .iter()
                    .enumerate()
                    .map(|(idx, label)| RepairSegmentJson {
                        kind: mpls_segment_kind(idx),
                        value: label_value_str(label),
                    })
                    .collect();
                rows.push(RepairRowJson {
                    level: format!("{level:?}"),
                    family: "ipv4",
                    prefix: prefix.to_string(),
                    primary_nexthop: addr.to_string(),
                    primary_ifindex: nhop.ifindex,
                    primary_metric: route.metric,
                    repair_nexthop: backup.addr.to_string(),
                    repair_ifindex: backup.ifindex,
                    repair_metric: route.metric.saturating_add(1),
                    segments,
                });
            }
        }
        let v6: &PrefixMap<Ipv6Net, SpfRouteV6> = isis.rib_v6.get(&level);
        for (prefix, route) in v6.iter() {
            for (addr, nhop) in route.nhops.iter() {
                let Some(backup) = nhop.backup.as_ref() else {
                    continue;
                };
                let segments = backup
                    .segs
                    .iter()
                    .enumerate()
                    .map(|(idx, seg)| RepairSegmentJson {
                        kind: srv6_segment_kind(idx),
                        value: seg.to_string(),
                    })
                    .collect();
                rows.push(RepairRowJson {
                    level: format!("{level:?}"),
                    family: "ipv6",
                    prefix: prefix.to_string(),
                    primary_nexthop: addr.to_string(),
                    primary_ifindex: nhop.ifindex,
                    primary_metric: route.metric,
                    repair_nexthop: backup.addr.to_string(),
                    repair_ifindex: backup.ifindex,
                    repair_metric: route.metric.saturating_add(1),
                    segments,
                });
            }
        }
    }
    rows
}

fn show_isis_repair_list(
    isis: &Isis,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    let rows = collect_repair_rows(isis);
    if json {
        return Ok(
            serde_json::to_string_pretty(&RepairListJson { routes: rows })
                .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}")),
        );
    }
    let mut buf = String::new();
    if rows.is_empty() {
        let _ = writeln!(buf, "(no TI-LFA repair-list entries)");
        return Ok(buf);
    }
    writeln!(
        buf,
        "{:<5} {:<5} {:<22} {:<22} {:<22} Segments",
        "Level", "AFI", "Prefix", "Primary via", "Repair via",
    )?;
    for row in &rows {
        let segs: Vec<String> = row.segments.iter().map(|s| s.value.clone()).collect();
        writeln!(
            buf,
            "{:<5} {:<5} {:<22} {:<22} {:<22} [{}]",
            row.level,
            row.family,
            row.prefix,
            row.primary_nexthop,
            row.repair_nexthop,
            segs.join(", "),
        )?;
    }
    Ok(buf)
}

fn show_isis_repair_list_detail(
    isis: &Isis,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    let rows = collect_repair_rows(isis);
    if json {
        return Ok(
            serde_json::to_string_pretty(&RepairListJson { routes: rows })
                .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}")),
        );
    }
    let mut buf = String::new();
    write_spf_status_banner(isis, &mut buf);
    if rows.is_empty() {
        let _ = writeln!(buf, "(no TI-LFA repair-list entries)");
        return Ok(buf);
    }
    for row in &rows {
        writeln!(buf, "{} {} {}", row.level, row.family, row.prefix)?;
        writeln!(
            buf,
            "  Primary: via {} (ifindex {}), metric {}",
            row.primary_nexthop, row.primary_ifindex, row.primary_metric,
        )?;
        writeln!(
            buf,
            "  Repair:  via {} (ifindex {}), metric {}",
            row.repair_nexthop, row.repair_ifindex, row.repair_metric,
        )?;
        for seg in &row.segments {
            writeln!(buf, "    {} {}", seg.kind, seg.value)?;
        }
    }
    Ok(buf)
}

fn write_spf_status_banner(isis: &Isis, buf: &mut String) {
    let ti_lfa = isis.config.ti_lfa_enabled;
    let sr_mpls = isis.config.sr_mpls_enabled;
    let sr_srv6 = isis.config.sr_srv6_enabled;
    let _ = writeln!(
        buf,
        "TI-LFA: {} (sr-mpls: {}, srv6: {})",
        if ti_lfa { "enabled" } else { "disabled" },
        if sr_mpls { "on" } else { "off" },
        if sr_srv6 { "on" } else { "off" },
    );
}

fn write_spf_brief(isis: &Isis, buf: &mut String) {
    // Legacy single-topology SPF — drives IPv4 RIB always, plus
    // IPv6 RIB when MT 2 is off. Print L1 then L2.
    if let Some(spf) = isis.spf_result.get(&Level::L1) {
        let _ = writeln!(buf, "L1 SPF (single-topology / MT 0)");
        spf::disp_out(buf, spf, true);
    }
    if let Some(spf) = isis.spf_result.get(&Level::L2) {
        let _ = writeln!(buf, "L2 SPF (single-topology / MT 0)");
        spf::disp_out(buf, spf, true);
    }

    // MT 2 SPF — only computed when local config has MT 2 in
    // mt_topologies. We print the raw tree from mt2_spf_result here
    // regardless of whether the legacy SPF is also present so
    // operators can compare metrics across topologies.
    if let Some(spf) = isis.mt2_spf_result.get(&Level::L1) {
        let _ = writeln!(buf, "L1 SPF (MT 2 / IPv6 unicast)");
        spf::disp_out(buf, spf, true);
    }
    if let Some(spf) = isis.mt2_spf_result.get(&Level::L2) {
        let _ = writeln!(buf, "L2 SPF (MT 2 / IPv6 unicast)");
        spf::disp_out(buf, spf, true);
    }
}

fn spf_json(isis: &Isis, detail: bool) -> String {
    // Minimal JSON skeleton — keys are stable now so downstream
    // tooling can lock against them. `levels[*].vertices` and
    // `levels[*].destinations` fill in once the SPF result and the
    // per-destination repair view are serialized; for now the
    // counts give operators something to assert against.
    let view = SpfShowJson {
        ti_lfa_enabled: isis.config.ti_lfa_enabled,
        sr_mpls_enabled: isis.config.sr_mpls_enabled,
        sr_srv6_enabled: isis.config.sr_srv6_enabled,
        detail,
        levels: [
            ("L1-single", isis.spf_result.get(&Level::L1)),
            ("L2-single", isis.spf_result.get(&Level::L2)),
            ("L1-mt2", isis.mt2_spf_result.get(&Level::L1)),
            ("L2-mt2", isis.mt2_spf_result.get(&Level::L2)),
        ]
        .into_iter()
        .filter_map(|(name, spf)| {
            spf.as_ref().map(|s| {
                (
                    name.to_string(),
                    SpfLevelJson {
                        vertex_count: s.len(),
                    },
                )
            })
        })
        .collect(),
    };
    serde_json::to_string_pretty(&view)
        .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialize SPF view: {}\"}}", e))
}

#[derive(Serialize)]
struct SpfShowJson {
    ti_lfa_enabled: bool,
    sr_mpls_enabled: bool,
    sr_srv6_enabled: bool,
    detail: bool,
    levels: std::collections::BTreeMap<String, SpfLevelJson>,
}

#[derive(Serialize)]
struct SpfLevelJson {
    vertex_count: usize,
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

    #[test]
    fn mpls_segment_kind_first_is_node_rest_is_adj() {
        // Convention: index 0 is the P-node's prefix-SID (NodeSID),
        // any subsequent label is an AdjSID bridging P->Q.
        assert_eq!(mpls_segment_kind(0), "NodeSID");
        assert_eq!(mpls_segment_kind(1), "AdjSID");
        assert_eq!(mpls_segment_kind(7), "AdjSID");
    }

    #[test]
    fn srv6_segment_kind_first_is_end_rest_is_endx() {
        // SRv6 analogue: End first, then End.X for adjacency hops.
        assert_eq!(srv6_segment_kind(0), "End");
        assert_eq!(srv6_segment_kind(1), "End.X");
    }

    #[test]
    fn label_value_str_marks_implicit_null() {
        assert_eq!(
            label_value_str(&crate::rib::Label::Implicit(3)),
            "3 (implicit-null)"
        );
        assert_eq!(
            label_value_str(&crate::rib::Label::Explicit(16002)),
            "16002"
        );
    }

    #[test]
    fn label_value_extracts_numeric_value_regardless_of_kind() {
        // For label-to-symbol lookups, implicit-null vs explicit
        // doesn't matter — only the underlying number.
        assert_eq!(label_value(&crate::rib::Label::Implicit(3)), 3);
        assert_eq!(label_value(&crate::rib::Label::Explicit(16005)), 16005);
    }

    #[test]
    fn fmt_isis_label_stack_renders_braced_push_order() {
        // Single label still braced.
        assert_eq!(
            fmt_isis_label_stack(&[crate::rib::Label::Explicit(17003)]),
            "{ 17003 }"
        );
        // Multi: push order (top-of-stack first); matches the RIB-
        // side `Labels imposed` format and IOS-XR convention.
        assert_eq!(
            fmt_isis_label_stack(&[
                crate::rib::Label::Explicit(17010),
                crate::rib::Label::Explicit(24001),
                crate::rib::Label::Explicit(17003),
            ]),
            "{ 17010 24001 17003 }"
        );
    }

    #[test]
    fn fmt_isis_srv6_segs_renders_braced_comma_separated() {
        let one: std::net::Ipv6Addr = "fcbb:bb00:1::".parse().unwrap();
        assert_eq!(fmt_isis_srv6_segs(&[one]), "{ fcbb:bb00:1:: }");
        let two: std::net::Ipv6Addr = "fcbb:bb00:2::".parse().unwrap();
        assert_eq!(
            fmt_isis_srv6_segs(&[one, two]),
            "{ fcbb:bb00:1::, fcbb:bb00:2:: }"
        );
    }

    #[test]
    fn frr_summary_default_is_all_zero() {
        // An empty RIB / fresh summary tallies to zeros across the
        // board — the formatter relies on this to suppress the
        // sub-counts when nothing is protected.
        let s = FrrSummary::default();
        assert_eq!(s.total, 0);
        assert_eq!(s.protected, 0);
        assert_eq!(s.unprotected, 0);
        assert_eq!(s.trivial, 0);
        assert_eq!(s.one_segment, 0);
        assert_eq!(s.multi_segment, 0);
    }

    #[test]
    fn write_frr_summary_block_includes_subcounts_only_when_protected() {
        // All-unprotected: no Trivial/1-segment/N-segment lines —
        // those rows are noise when nobody's protected.
        let unprotected = FrrSummary {
            total: 3,
            unprotected: 3,
            ..Default::default()
        };
        let mut buf = String::new();
        write_frr_summary_block(&mut buf, "IPv4:", &unprotected).unwrap();
        assert!(buf.contains("Total prefixes:"));
        assert!(buf.contains("Protected:"));
        assert!(buf.contains("Unprotected:"));
        assert!(!buf.contains("Trivial repair"));
        assert!(!buf.contains("1-segment"));
        assert!(!buf.contains("N-segment"));

        // With protection, the sub-count rows appear.
        let protected = FrrSummary {
            total: 10,
            protected: 7,
            unprotected: 3,
            trivial: 2,
            one_segment: 3,
            multi_segment: 2,
        };
        let mut buf2 = String::new();
        write_frr_summary_block(&mut buf2, "IPv4:", &protected).unwrap();
        assert!(buf2.contains("Trivial repair"));
        assert!(buf2.contains("1-segment SR"));
        assert!(buf2.contains("N-segment SR"));
    }
}
