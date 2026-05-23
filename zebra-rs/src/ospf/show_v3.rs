//! OSPFv3 `show ipv6 ospf ...` command handlers.
//!
//! Sibling of v2's `show.rs`. Mirrors the v2 dispatch shape — one
//! handler per `/show/ipv6/ospf/...` path, registered through
//! `Ospf<Ospfv3>::show_build`, dispatched by the v3 event loop's
//! `process_show_msg` arm. Output formatting is plain text by
//! default; the `json` flag carried by `ShowCallback` produces a
//! JSON document instead.

use std::fmt::Write;

use serde::Serialize;

use super::lsdb::OSPF_MAX_AGE;
use super::version::Ospfv3;
use super::{Ospf, ShowCallback};

use crate::config::Args;

const SHOW_OSPFV3: &str = "/show/ipv6/ospf";

impl Ospf<Ospfv3> {
    /// Register the v3 show-path dispatch table. Mirrors v2's
    /// `show_build` shape and command set, minus `segment-routing`
    /// (no v3 SR wiring yet).
    pub fn show_build(&mut self) {
        let prefix = SHOW_OSPFV3;
        let entries: &[(&str, ShowCallback<Ospfv3>)] = &[
            ("", show_ospfv3_summary),
            ("/interface", show_ospfv3_interface),
            ("/neighbor", show_ospfv3_neighbor),
            ("/neighbor/detail", show_ospfv3_neighbor_detail),
            ("/database", show_ospfv3_database),
            ("/database/detail", show_ospfv3_database_detail),
            ("/route", show_ospfv3_route),
            ("/spf", show_ospfv3_spf),
            ("/graph", show_ospfv3_graph),
        ];
        for (path, cb) in entries {
            self.show_cb.insert(format!("{}{}", prefix, path), *cb);
        }
    }
}

// ---- helpers ----------------------------------------------------

fn render_or<T: serde::Serialize>(
    json: bool,
    value: &T,
    text: String,
) -> Result<String, std::fmt::Error> {
    if json {
        Ok(serde_json::to_string_pretty(value).unwrap_or_else(|_| String::from("{}")))
    } else {
        Ok(text)
    }
}

fn ls_type_name(ls_type: u16) -> &'static str {
    use ospf_packet::{
        OSPFV3_AS_EXTERNAL_LSA_TYPE, OSPFV3_INTER_AREA_PREFIX_LSA_TYPE,
        OSPFV3_INTER_AREA_ROUTER_LSA_TYPE, OSPFV3_INTRA_AREA_PREFIX_LSA_TYPE, OSPFV3_LINK_LSA_TYPE,
        OSPFV3_NETWORK_LSA_TYPE, OSPFV3_ROUTER_LSA_TYPE,
    };
    match ls_type {
        OSPFV3_ROUTER_LSA_TYPE => "Router-LSA",
        OSPFV3_NETWORK_LSA_TYPE => "Network-LSA",
        OSPFV3_INTER_AREA_PREFIX_LSA_TYPE => "Inter-Area-Prefix-LSA",
        OSPFV3_INTER_AREA_ROUTER_LSA_TYPE => "Inter-Area-Router-LSA",
        OSPFV3_AS_EXTERNAL_LSA_TYPE => "AS-External-LSA",
        OSPFV3_LINK_LSA_TYPE => "Link-LSA",
        OSPFV3_INTRA_AREA_PREFIX_LSA_TYPE => "Intra-Area-Prefix-LSA",
        _ => "Unknown",
    }
}

// ---- show ipv6 ospf (instance summary) --------------------------

#[derive(Serialize)]
struct Ospfv3SummaryJson {
    router_id: String,
    area_count: usize,
    link_count: usize,
    spf_last_ms_ago: Option<u128>,
    spf_duration_us: Option<u128>,
}

fn show_ospfv3_summary(
    top: &Ospf<Ospfv3>,
    _args: Args,
    json: bool,
) -> Result<String, std::fmt::Error> {
    let summary = Ospfv3SummaryJson {
        router_id: top.router_id.to_string(),
        area_count: top.areas.iter().count(),
        link_count: top.links.len(),
        spf_last_ms_ago: top.spf_last.map(|t| t.elapsed().as_millis()),
        spf_duration_us: top.spf_duration.map(|d| d.as_micros()),
    };
    let mut text = String::new();
    writeln!(text, "OSPFv3 Routing Process")?;
    writeln!(text, "  Router ID:    {}", summary.router_id)?;
    writeln!(text, "  Areas:        {}", summary.area_count)?;
    writeln!(text, "  Interfaces:   {}", summary.link_count)?;
    if let Some(ms) = summary.spf_last_ms_ago {
        writeln!(text, "  Last SPF run: {} ms ago", ms)?;
    }
    if let Some(us) = summary.spf_duration_us {
        writeln!(text, "  SPF duration: {} us", us)?;
    }
    render_or(json, &summary, text)
}

// ---- show ipv6 ospf interface -----------------------------------

#[derive(Serialize)]
struct Ospfv3InterfaceJson {
    name: String,
    ifindex: u32,
    interface_id: u32,
    enabled: bool,
    area_id: String,
    state: String,
    d_router: String,
    bd_router: String,
    priority: u8,
    hello_interval: u16,
    dead_interval: u32,
    neighbor_count: usize,
}

fn show_ospfv3_interface(
    top: &Ospf<Ospfv3>,
    _args: Args,
    json: bool,
) -> Result<String, std::fmt::Error> {
    let entries: Vec<Ospfv3InterfaceJson> = top
        .links
        .values()
        .map(|link| Ospfv3InterfaceJson {
            name: link.name.clone(),
            ifindex: link.index,
            interface_id: link.interface_id,
            enabled: link.enabled,
            area_id: link.area_id.to_string(),
            state: link.state.to_string(),
            d_router: link.ident.d_router.to_string(),
            bd_router: link.ident.bd_router.to_string(),
            priority: link.priority(),
            hello_interval: link.hello_interval(),
            dead_interval: link.dead_interval(),
            neighbor_count: link.nbrs.len(),
        })
        .collect();
    let mut text = String::new();
    for e in &entries {
        writeln!(
            text,
            "{} (ifindex {}, area {}, state {}, neighbors {})",
            e.name, e.ifindex, e.area_id, e.state, e.neighbor_count
        )?;
        writeln!(
            text,
            "  Interface ID: {}  Priority: {}  Hello {}s  Dead {}s",
            e.interface_id, e.priority, e.hello_interval, e.dead_interval
        )?;
        writeln!(text, "  DR: {}  BDR: {}", e.d_router, e.bd_router)?;
    }
    render_or(json, &entries, text)
}

// ---- show ipv6 ospf neighbor ------------------------------------

#[derive(Serialize)]
struct Ospfv3NeighborJson {
    router_id: String,
    interface: String,
    interface_id: u32,
    state: String,
    priority: u8,
    d_router: String,
    bd_router: String,
}

fn collect_neighbors(top: &Ospf<Ospfv3>) -> Vec<Ospfv3NeighborJson> {
    let mut out = Vec::new();
    for link in top.links.values() {
        for nbr in link.nbrs.values() {
            out.push(Ospfv3NeighborJson {
                router_id: nbr.ident.router_id.to_string(),
                interface: link.name.clone(),
                interface_id: nbr.interface_id,
                state: nbr.state.to_string(),
                priority: nbr.ident.priority,
                d_router: nbr.ident.d_router.to_string(),
                bd_router: nbr.ident.bd_router.to_string(),
            });
        }
    }
    out
}

fn show_ospfv3_neighbor(
    top: &Ospf<Ospfv3>,
    _args: Args,
    json: bool,
) -> Result<String, std::fmt::Error> {
    let entries = collect_neighbors(top);
    let mut text = String::new();
    writeln!(
        text,
        "{:<16} {:<10} {:<10} {:<10}",
        "Router-ID", "Iface", "State", "DR"
    )?;
    for n in &entries {
        writeln!(
            text,
            "{:<16} {:<10} {:<10} {:<10}",
            n.router_id, n.interface, n.state, n.d_router
        )?;
    }
    render_or(json, &entries, text)
}

fn show_ospfv3_neighbor_detail(
    top: &Ospf<Ospfv3>,
    _args: Args,
    json: bool,
) -> Result<String, std::fmt::Error> {
    let entries = collect_neighbors(top);
    let mut text = String::new();
    for n in &entries {
        writeln!(text, "Neighbor {}", n.router_id)?;
        writeln!(
            text,
            "  Interface:    {} (id {})",
            n.interface, n.interface_id
        )?;
        writeln!(text, "  State:        {}", n.state)?;
        writeln!(text, "  Priority:     {}", n.priority)?;
        writeln!(text, "  DR / BDR:     {} / {}", n.d_router, n.bd_router)?;
    }
    render_or(json, &entries, text)
}

// ---- show ipv6 ospf database ------------------------------------

#[derive(Serialize)]
struct Ospfv3LsaHeaderJson {
    ls_type: String,
    ls_type_raw: u16,
    link_state_id: u32,
    advertising_router: String,
    ls_seq_number: String,
    ls_age: u16,
    length: u16,
    scope: String,
}

#[derive(Serialize, Default)]
struct Ospfv3DatabaseJson {
    area: Vec<Ospfv3LsaHeaderJson>,
    as_scope: Vec<Ospfv3LsaHeaderJson>,
    link: Vec<Ospfv3LsaHeaderJson>,
}

fn ls_type_scope_label(ls_type: u16) -> &'static str {
    match (ls_type >> 13) & 0x3 {
        0 => "Link",
        1 => "Area",
        2 => "AS",
        _ => "Reserved",
    }
}

fn hdr_to_json(h: &ospf_packet::Ospfv3LsaHeader) -> Ospfv3LsaHeaderJson {
    Ospfv3LsaHeaderJson {
        ls_type: ls_type_name(h.ls_type).to_string(),
        ls_type_raw: h.ls_type,
        link_state_id: h.link_state_id,
        advertising_router: h.advertising_router.to_string(),
        ls_seq_number: format!("0x{:08x}", h.ls_seq_number),
        ls_age: h.ls_age,
        length: h.length,
        scope: ls_type_scope_label(h.ls_type).to_string(),
    }
}

fn collect_database(top: &Ospf<Ospfv3>) -> Ospfv3DatabaseJson {
    let mut db = Ospfv3DatabaseJson::default();
    for (_, area) in top.areas.iter() {
        for (_, lsa) in area.lsdb.tables.iter() {
            if lsa.data.h.ls_age >= OSPF_MAX_AGE {
                continue;
            }
            db.area.push(hdr_to_json(&lsa.data.h));
        }
    }
    for (_, lsa) in top.lsdb_as.tables.iter() {
        if lsa.data.h.ls_age >= OSPF_MAX_AGE {
            continue;
        }
        db.as_scope.push(hdr_to_json(&lsa.data.h));
    }
    for link in top.links.values() {
        for (_, lsa) in link.lsdb.tables.iter() {
            if lsa.data.h.ls_age >= OSPF_MAX_AGE {
                continue;
            }
            db.link.push(hdr_to_json(&lsa.data.h));
        }
    }
    db
}

fn show_ospfv3_database(
    top: &Ospf<Ospfv3>,
    _args: Args,
    json: bool,
) -> Result<String, std::fmt::Error> {
    let db = collect_database(top);
    let mut text = String::new();
    for (label, entries) in [
        ("Area-scope", &db.area),
        ("AS-scope", &db.as_scope),
        ("Link-scope", &db.link),
    ] {
        if entries.is_empty() {
            continue;
        }
        writeln!(text, "{}:", label)?;
        writeln!(
            text,
            "  {:<22} {:<16} {:<16} {:<10} Age",
            "Type", "LS-ID", "Adv-Router", "Seq#"
        )?;
        for h in entries {
            writeln!(
                text,
                "  {:<22} {:<16} {:<16} {:<10} {}",
                h.ls_type, h.link_state_id, h.advertising_router, h.ls_seq_number, h.ls_age
            )?;
        }
    }
    render_or(json, &db, text)
}

fn show_ospfv3_database_detail(
    top: &Ospf<Ospfv3>,
    args: Args,
    json: bool,
) -> Result<String, std::fmt::Error> {
    // For now `detail` produces the same output as the non-detail
    // form — the v3 LSA-body printers will land alongside more
    // detailed renderings of each scope's contents. JSON output is
    // identical to the summary case.
    show_ospfv3_database(top, args, json)
}

// ---- show ipv6 ospf route ---------------------------------------

#[derive(Serialize)]
struct Ospfv3RouteNexthopJson {
    nexthop: String,
    ifindex: u32,
}

#[derive(Serialize)]
struct Ospfv3RouteJson {
    prefix: String,
    metric: u32,
    nexthops: Vec<Ospfv3RouteNexthopJson>,
}

fn show_ospfv3_route(
    top: &Ospf<Ospfv3>,
    _args: Args,
    json: bool,
) -> Result<String, std::fmt::Error> {
    let entries: Vec<Ospfv3RouteJson> = top
        .rib6
        .iter()
        .map(|(prefix, route)| Ospfv3RouteJson {
            prefix: prefix.to_string(),
            metric: route.metric,
            nexthops: route
                .nhops
                .iter()
                .map(|(addr, nhop)| Ospfv3RouteNexthopJson {
                    nexthop: addr.to_string(),
                    ifindex: nhop.ifindex,
                })
                .collect(),
        })
        .collect();

    let mut text = String::new();
    writeln!(text, "OSPFv3 routes ({})", entries.len())?;
    for r in &entries {
        let nhops = if r.nexthops.is_empty() {
            String::from("(none)")
        } else {
            r.nexthops
                .iter()
                .map(|n| {
                    if n.ifindex != 0 {
                        format!("{}%{}", n.nexthop, n.ifindex)
                    } else {
                        n.nexthop.clone()
                    }
                })
                .collect::<Vec<_>>()
                .join(", ")
        };
        writeln!(text, "  {} metric {} via {}", r.prefix, r.metric, nhops)?;
    }
    render_or(json, &entries, text)
}

// ---- show ipv6 ospf spf -----------------------------------------

#[derive(Serialize)]
struct Ospfv3SpfPathJson {
    vertex_id: usize,
    router_id: String,
    cost: u32,
    first_hop_routers: Vec<String>,
}

fn show_ospfv3_spf(top: &Ospf<Ospfv3>, _args: Args, json: bool) -> Result<String, std::fmt::Error> {
    let entries: Vec<Ospfv3SpfPathJson> = top
        .spf_result
        .as_ref()
        .map(|paths| {
            paths
                .iter()
                .map(|(id, path)| {
                    let router_id = top
                        .lsp_map
                        .resolve(*id)
                        .map_or_else(|| String::from("?"), |r| r.to_string());
                    let first_hop_routers: Vec<String> = path
                        .first_hop_links
                        .iter()
                        .filter_map(|(vid, _)| top.lsp_map.resolve(*vid).map(|r| r.to_string()))
                        .collect();
                    Ospfv3SpfPathJson {
                        vertex_id: *id,
                        router_id,
                        cost: path.cost,
                        first_hop_routers,
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    let mut text = String::new();
    writeln!(text, "OSPFv3 SPF tree ({} vertices)", entries.len())?;
    for p in &entries {
        writeln!(
            text,
            "  {} cost {} via {}",
            p.router_id,
            p.cost,
            if p.first_hop_routers.is_empty() {
                "(self)".to_string()
            } else {
                p.first_hop_routers.join(", ")
            }
        )?;
    }
    render_or(json, &entries, text)
}

// ---- show ipv6 ospf graph ---------------------------------------

#[derive(Serialize)]
struct Ospfv3GraphLinkJson {
    from: String,
    to: String,
    cost: u32,
}

#[derive(Serialize)]
struct Ospfv3GraphVertexJson {
    id: usize,
    name: String,
    links: Vec<Ospfv3GraphLinkJson>,
}

fn show_ospfv3_graph(
    top: &Ospf<Ospfv3>,
    _args: Args,
    json: bool,
) -> Result<String, std::fmt::Error> {
    let entries: Vec<Ospfv3GraphVertexJson> = top
        .graph
        .as_ref()
        .map(|g| {
            g.iter()
                .map(|(id, vertex)| Ospfv3GraphVertexJson {
                    id: *id,
                    name: vertex.name.clone(),
                    links: vertex
                        .olinks
                        .iter()
                        .map(|l| Ospfv3GraphLinkJson {
                            from: vertex.name.clone(),
                            to: top
                                .lsp_map
                                .resolve(l.to)
                                .map_or_else(|| l.to.to_string(), |r| r.to_string()),
                            cost: l.cost,
                        })
                        .collect(),
                })
                .collect()
        })
        .unwrap_or_default();

    let mut text = String::new();
    writeln!(text, "OSPFv3 area graph ({} vertices)", entries.len())?;
    for v in &entries {
        writeln!(text, "  {} (id {})", v.name, v.id)?;
        for l in &v.links {
            writeln!(text, "    -> {} cost {}", l.to, l.cost)?;
        }
    }
    render_or(json, &entries, text)
}
