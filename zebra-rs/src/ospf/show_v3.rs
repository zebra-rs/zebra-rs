//! OSPFv3 `show ospfv3 ...` command handlers.
//!
//! Sibling of v2's `show.rs`. Mirrors the v2 dispatch shape — one
//! handler per `/show/ospfv3/...` path, registered through
//! `Ospf<Ospfv3>::show_build`, dispatched by the v3 event loop's
//! `process_show_msg` arm. Output formatting is plain text by
//! default; the `json` flag carried by `ShowCallback` produces a
//! JSON document instead.

use std::fmt::Write;
use std::net::Ipv4Addr;

use serde::Serialize;

use ospf_packet::{
    OSPFV3_AS_EXTERNAL_FLAG_E, OSPFV3_AS_EXTERNAL_FLAG_F, OSPFV3_AS_EXTERNAL_FLAG_T,
    OSPFV3_AS_EXTERNAL_LSA_TYPE, OSPFV3_INTER_AREA_PREFIX_LSA_TYPE,
    OSPFV3_INTER_AREA_ROUTER_LSA_TYPE, OSPFV3_INTRA_AREA_PREFIX_LSA_TYPE, OSPFV3_LINK_LSA_TYPE,
    OSPFV3_NETWORK_LSA_TYPE, OSPFV3_ROUTER_LSA_FLAG_B, OSPFV3_ROUTER_LSA_FLAG_E,
    OSPFV3_ROUTER_LSA_FLAG_V, OSPFV3_ROUTER_LSA_FLAG_W, OSPFV3_ROUTER_LSA_TYPE, Ospfv3LsBody,
    Ospfv3Options, Ospfv3PrefixOptions, Ospfv3RouterLinkType,
};

use super::lsdb::{Lsa, OSPF_MAX_AGE};
use super::version::Ospfv3;
use super::{Ospf, ShowCallback};

use crate::config::{Args, Builder};

impl Ospf<Ospfv3> {
    /// Register the v3 show-path dispatch table. Mirrors v2's
    /// `show_build` shape and command set.
    pub fn show_build(&mut self) {
        self.show_cb = Builder::<ShowCallback<Ospfv3>>::default()
            .path("/show/ospfv3")
            .set(show_ospfv3_summary)
            .path("/show/ospfv3/interface")
            .set(show_ospfv3_interface)
            .path("/show/ospfv3/neighbor")
            .set(show_ospfv3_neighbor)
            .path("/show/ospfv3/neighbor/detail")
            .set(show_ospfv3_neighbor_detail)
            .path("/show/ospfv3/database")
            .set(show_ospfv3_database)
            .path("/show/ospfv3/database/detail")
            .set(show_ospfv3_database_detail)
            .path("/show/ospfv3/route")
            .set(show_ospfv3_route)
            .path("/show/ospfv3/spf")
            .set(show_ospfv3_spf)
            .path("/show/ospfv3/graph")
            .set(show_ospfv3_graph)
            .path("/show/ospfv3/ti-lfa")
            .set(show_ospfv3_tilfa)
            .path("/show/ospfv3/repair-list")
            .set(show_ospfv3_repair_list)
            .path("/show/ospfv3/repair-list/detail")
            .set(show_ospfv3_repair_list_detail)
            .path("/show/ospfv3/segment-routing")
            .set(show_ospfv3_segment_routing)
            .path("/show/ospfv3/srv6")
            .set(show_ospfv3_srv6)
            .path("/show/ospfv3/flex-algo")
            .set(show_ospfv3_flex_algo)
            .map();
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
        OSPFV3_AS_EXTERNAL_LSA_TYPE, OSPFV3_E_AS_EXTERNAL_LSA_TYPE,
        OSPFV3_E_INTER_AREA_PREFIX_LSA_TYPE, OSPFV3_E_INTER_AREA_ROUTER_LSA_TYPE,
        OSPFV3_E_INTRA_AREA_PREFIX_LSA_TYPE, OSPFV3_E_LINK_LSA_TYPE, OSPFV3_E_NETWORK_LSA_TYPE,
        OSPFV3_E_ROUTER_LSA_TYPE, OSPFV3_GRACE_LSA_TYPE, OSPFV3_INTER_AREA_PREFIX_LSA_TYPE,
        OSPFV3_INTER_AREA_ROUTER_LSA_TYPE, OSPFV3_INTRA_AREA_PREFIX_LSA_TYPE, OSPFV3_LINK_LSA_TYPE,
        OSPFV3_NETWORK_LSA_TYPE, OSPFV3_NSSA_LSA_TYPE, OSPFV3_ROUTER_LSA_TYPE,
        OSPFV3_SRV6_LOCATOR_LSA_TYPE,
    };
    match ls_type {
        OSPFV3_ROUTER_LSA_TYPE => "Router-LSA",
        OSPFV3_NETWORK_LSA_TYPE => "Network-LSA",
        OSPFV3_INTER_AREA_PREFIX_LSA_TYPE => "Inter-Area-Prefix-LSA",
        OSPFV3_INTER_AREA_ROUTER_LSA_TYPE => "Inter-Area-Router-LSA",
        OSPFV3_AS_EXTERNAL_LSA_TYPE => "AS-External-LSA",
        OSPFV3_NSSA_LSA_TYPE => "NSSA-LSA",
        OSPFV3_LINK_LSA_TYPE => "Link-LSA",
        OSPFV3_INTRA_AREA_PREFIX_LSA_TYPE => "Intra-Area-Prefix-LSA",
        OSPFV3_GRACE_LSA_TYPE => "Grace-LSA",
        OSPFV3_E_ROUTER_LSA_TYPE => "E-Router-LSA",
        OSPFV3_SRV6_LOCATOR_LSA_TYPE => "SRv6-Locator-LSA",
        OSPFV3_E_NETWORK_LSA_TYPE => "E-Network-LSA",
        OSPFV3_E_INTER_AREA_PREFIX_LSA_TYPE => "E-Inter-Area-Prefix-LSA",
        OSPFV3_E_INTER_AREA_ROUTER_LSA_TYPE => "E-Inter-Area-Router-LSA",
        OSPFV3_E_AS_EXTERNAL_LSA_TYPE => "E-AS-External-LSA",
        OSPFV3_E_LINK_LSA_TYPE => "E-Link-LSA",
        OSPFV3_E_INTRA_AREA_PREFIX_LSA_TYPE => "E-Intra-Area-Prefix-LSA",
        _ => "Unknown",
    }
}

// ---- TI-LFA (RFC 9490) ------------------------------------------
// `show ospfv3 ti-lfa` (graph-level per-destination repair lists)
// and `show ospfv3 repair-list` (repair backups installed on the
// v6 RIB). v3 siblings of the v2 handlers in `show.rs`.

fn label_value_str_v3(label: &crate::rib::Label) -> String {
    match label {
        crate::rib::Label::Implicit(l) => format!("{l} (implicit-null)"),
        crate::rib::Label::Explicit(l) => format!("{l}"),
    }
}

fn vertex_name_v3(graph: &crate::spf::Graph, id: usize) -> String {
    graph
        .get(&id)
        .map(|v| v.name.clone())
        .unwrap_or_else(|| format!("v{id}"))
}

fn format_sr_segment_v3(graph: &crate::spf::Graph, seg: &crate::spf::SrSegment) -> String {
    match seg {
        crate::spf::SrSegment::NodeSid(v) => {
            format!("Node-SID {} (vertex {})", vertex_name_v3(graph, *v), v)
        }
        crate::spf::SrSegment::AdjSid(from, to, _via) => format!(
            "Adj-SID {} -> {} (vertex {} -> {})",
            vertex_name_v3(graph, *from),
            vertex_name_v3(graph, *to),
            from,
            to,
        ),
    }
}

#[derive(Serialize)]
struct RepairSegmentV3Json {
    kind: &'static str,
    value: String,
}

#[derive(Serialize)]
struct RepairRowV3Json {
    prefix: String,
    primary_nexthop: String,
    primary_ifindex: u32,
    primary_metric: u32,
    repair_nexthop: String,
    repair_ifindex: u32,
    repair_metric: u32,
    segments: Vec<RepairSegmentV3Json>,
}

#[derive(Serialize)]
struct RepairListV3Json {
    routes: Vec<RepairRowV3Json>,
}

fn collect_ospfv3_repair_rows(top: &Ospf<Ospfv3>) -> Vec<RepairRowV3Json> {
    let mut rows = Vec::new();
    for (prefix, route) in top.rib6.iter() {
        for (addr, nhop) in route.nhops.iter() {
            let Some(backup) = nhop.backup.as_ref() else {
                continue;
            };
            use crate::ospf::tilfa::RepairBackupV3;
            let (segments, repair_nexthop, repair_ifindex) = match backup {
                RepairBackupV3::Mpls(b) => (
                    b.labels
                        .iter()
                        .map(|label| RepairSegmentV3Json {
                            kind: "sr-mpls",
                            value: label_value_str_v3(label),
                        })
                        .collect(),
                    b.addr.to_string(),
                    b.ifindex,
                ),
                RepairBackupV3::Srv6(b) => (
                    b.segs
                        .iter()
                        .map(|sid| RepairSegmentV3Json {
                            kind: "srv6",
                            value: sid.to_string(),
                        })
                        .collect(),
                    b.addr.to_string(),
                    b.ifindex,
                ),
            };
            rows.push(RepairRowV3Json {
                prefix: prefix.to_string(),
                primary_nexthop: addr.to_string(),
                primary_ifindex: nhop.ifindex,
                primary_metric: route.metric,
                repair_nexthop,
                repair_ifindex,
                repair_metric: route
                    .metric
                    .saturating_add(super::inst::BACKUP_METRIC_OFFSET),
                segments,
            });
        }
    }
    rows
}

fn show_ospfv3_repair_list(
    top: &Ospf<Ospfv3>,
    _args: Args,
    json: bool,
) -> Result<String, std::fmt::Error> {
    let rows = collect_ospfv3_repair_rows(top);
    if json {
        return Ok(
            serde_json::to_string_pretty(&RepairListV3Json { routes: rows })
                .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}")),
        );
    }
    let mut buf = String::new();
    if rows.is_empty() {
        writeln!(buf, "(no TI-LFA repair-list entries)")?;
        return Ok(buf);
    }
    writeln!(
        buf,
        "{:<30} {:<26} {:<26} Segments",
        "Prefix", "Primary via", "Repair via",
    )?;
    for row in &rows {
        let segs: Vec<String> = row.segments.iter().map(|s| s.value.clone()).collect();
        writeln!(
            buf,
            "{:<30} {:<26} {:<26} [{}]",
            row.prefix,
            row.primary_nexthop,
            row.repair_nexthop,
            segs.join(", "),
        )?;
    }
    Ok(buf)
}

fn show_ospfv3_repair_list_detail(
    top: &Ospf<Ospfv3>,
    _args: Args,
    json: bool,
) -> Result<String, std::fmt::Error> {
    let rows = collect_ospfv3_repair_rows(top);
    if json {
        return Ok(
            serde_json::to_string_pretty(&RepairListV3Json { routes: rows })
                .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}")),
        );
    }
    let mut buf = String::new();
    if rows.is_empty() {
        writeln!(buf, "(no TI-LFA repair-list entries)")?;
        return Ok(buf);
    }
    for row in &rows {
        writeln!(buf, "{}", row.prefix)?;
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
        if row.segments.is_empty() {
            writeln!(buf, "    (trivial repair, no SR segments)")?;
        } else {
            for seg in &row.segments {
                writeln!(buf, "    {} {}", seg.kind, seg.value)?;
            }
        }
    }
    Ok(buf)
}

#[derive(Serialize)]
struct TilfaV3SegmentJson {
    kind: &'static str,
    description: String,
}

#[derive(Serialize)]
struct TilfaV3RepairJson {
    first_hop: String,
    first_hop_vertex: usize,
    first_hop_link_id: u32,
    segments: Vec<TilfaV3SegmentJson>,
}

#[derive(Serialize)]
struct TilfaV3DestJson {
    destination: String,
    destination_vertex: usize,
    repairs: Vec<TilfaV3RepairJson>,
}

#[derive(Serialize)]
struct TilfaV3Json {
    destinations: Vec<TilfaV3DestJson>,
}

fn show_ospfv3_tilfa(
    top: &Ospf<Ospfv3>,
    _args: Args,
    json: bool,
) -> Result<String, std::fmt::Error> {
    let graph = top.graph.as_ref();
    let tilfa = top.tilfa_result.as_ref();

    if json {
        let destinations = match (graph, tilfa) {
            (Some(g), Some(t)) => t
                .iter()
                .map(|(dest, repairs)| TilfaV3DestJson {
                    destination: vertex_name_v3(g, *dest),
                    destination_vertex: *dest,
                    repairs: repairs
                        .iter()
                        .map(|rp| TilfaV3RepairJson {
                            first_hop: vertex_name_v3(g, rp.first_hop),
                            first_hop_vertex: rp.first_hop,
                            first_hop_link_id: rp.first_hop_link_id,
                            segments: rp
                                .segs
                                .iter()
                                .map(|seg| TilfaV3SegmentJson {
                                    kind: match seg {
                                        crate::spf::SrSegment::NodeSid(_) => "node-sid",
                                        crate::spf::SrSegment::AdjSid(..) => "adj-sid",
                                    },
                                    description: format_sr_segment_v3(g, seg),
                                })
                                .collect(),
                        })
                        .collect(),
                })
                .collect(),
            _ => Vec::new(),
        };
        return Ok(serde_json::to_string_pretty(&TilfaV3Json { destinations })
            .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}")));
    }

    let mut buf = String::new();
    let (Some(graph), Some(tilfa)) = (graph, tilfa) else {
        writeln!(buf, "(no TI-LFA repair paths computed)")?;
        return Ok(buf);
    };
    if tilfa.is_empty() {
        writeln!(buf, "(no TI-LFA repair paths computed)")?;
        return Ok(buf);
    }
    writeln!(buf, "OSPFv3 TI-LFA repair paths:")?;
    for (dest, repairs) in tilfa.iter() {
        writeln!(
            buf,
            "  Destination {} (vertex {})",
            vertex_name_v3(graph, *dest),
            dest,
        )?;
        for (i, rp) in repairs.iter().enumerate() {
            writeln!(
                buf,
                "    [{}] first-hop {} (vertex {}, link_id {})",
                i,
                vertex_name_v3(graph, rp.first_hop),
                rp.first_hop,
                rp.first_hop_link_id,
            )?;
            if rp.segs.is_empty() {
                writeln!(buf, "        segments: (none — direct repair)")?;
            } else {
                writeln!(buf, "        segments:")?;
                for seg in &rp.segs {
                    writeln!(buf, "          {}", format_sr_segment_v3(graph, seg))?;
                }
            }
        }
    }
    Ok(buf)
}

// ---- show ospfv3 (instance summary) --------------------------

#[derive(Serialize)]
struct Ospfv3AreaGateJson {
    area_id: String,
    spf_inflight: bool,
    spf_pending: bool,
}

#[derive(Serialize)]
struct Ospfv3SummaryJson {
    router_id: String,
    area_count: usize,
    link_count: usize,
    spf_last_ms_ago: Option<u128>,
    spf_duration_us: Option<u128>,
    /// TI-LFA compute telemetry for the most-recent run, preformatted
    /// (`targets=… mode=… workers=… spf{…} took … us`). None until
    /// TI-LFA runs (and cleared when it is disabled).
    tilfa_compute: Option<String>,
    /// Per-area SPF-offload gates. The instance-level
    /// `spf_last_ms_ago` / `spf_duration_us` reflect the most-recent
    /// area's run; these tell automation which area's worker is still
    /// in `spawn_blocking` and which has a coalesced follow-up.
    spf_offload_gates: Vec<Ospfv3AreaGateJson>,
}

fn show_ospfv3_summary(
    top: &Ospf<Ospfv3>,
    _args: Args,
    json: bool,
) -> Result<String, std::fmt::Error> {
    let spf_offload_gates: Vec<_> = top
        .areas
        .iter()
        .map(|(area_id, area)| Ospfv3AreaGateJson {
            area_id: area_id.to_string(),
            spf_inflight: area.spf_inflight,
            spf_pending: area.spf_pending,
        })
        .collect();
    let summary = Ospfv3SummaryJson {
        router_id: top.router_id.to_string(),
        area_count: top.areas.iter().count(),
        link_count: top.links.len(),
        spf_last_ms_ago: top.spf_last.map(|t| t.elapsed().as_millis()),
        spf_duration_us: top.spf_duration.map(|d| d.as_micros()),
        tilfa_compute: top.tilfa_stats.as_ref().map(|s| {
            format!(
                "targets={} mode={} workers={} spf{{q={} pc={} dedup-saved={}}} took {} us",
                s.targets,
                s.mode,
                s.width,
                s.q_spf,
                s.pc_spf,
                s.pc_deduped,
                s.duration.as_micros(),
            )
        }),
        spf_offload_gates,
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
    if let Some(tilfa) = &summary.tilfa_compute {
        writeln!(text, "  TI-LFA compute: {}", tilfa)?;
    }
    if !summary.spf_offload_gates.is_empty() {
        writeln!(text, "  SPF offload gates:")?;
        for gate in &summary.spf_offload_gates {
            writeln!(
                text,
                "    area {}: inflight={}, pending={}",
                gate.area_id, gate.spf_inflight, gate.spf_pending,
            )?;
        }
    }
    render_or(json, &summary, text)
}

// ---- show ospfv3 interface -----------------------------------

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
    cost: u32,
    hello_interval: u16,
    dead_interval: u32,
    neighbor_count: usize,
}

fn show_ospfv3_interface(
    top: &Ospf<Ospfv3>,
    _args: Args,
    json: bool,
) -> Result<String, std::fmt::Error> {
    // Only list interfaces the operator enabled v3 on — matches v2's
    // `show_ospf_interface` filter (`if !oi.enabled { continue; }`).
    // Without this filter every kernel link the RIB has surfaced
    // shows up, which is noisy and inconsistent with v2.
    let entries: Vec<Ospfv3InterfaceJson> = top
        .links
        .values()
        .filter(|link| link.enabled)
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
            cost: link.output_cost,
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
            "  Interface ID: {}  Priority: {}  Cost: {}  Hello {}s  Dead {}s",
            e.interface_id, e.priority, e.cost, e.hello_interval, e.dead_interval
        )?;
        writeln!(text, "  DR: {}  BDR: {}", e.d_router, e.bd_router)?;
    }
    render_or(json, &entries, text)
}

// ---- show ospfv3 neighbor ------------------------------------

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

// ---- show ospfv3 database ------------------------------------

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
            "  {:<24} {:<16} {:<16} {:<10} Age",
            "Type", "LS-ID", "Adv-Router", "Seq#"
        )?;
        for h in entries {
            writeln!(
                text,
                "  {:<24} {:<16} {:<16} {:<10} {}",
                h.ls_type, h.link_state_id, h.advertising_router, h.ls_seq_number, h.ls_age
            )?;
        }
    }
    render_or(json, &db, text)
}

/// FRR-style detail output. Walks each area / AS / per-link LSDB,
/// groups by LS-Type, and prints the full body of every non-MaxAge
/// LSA. JSON output reuses the summary shape (header-only) for now —
/// per-body JSON serializers belong to a follow-up.
fn show_ospfv3_database_detail(
    top: &Ospf<Ospfv3>,
    args: Args,
    json: bool,
) -> Result<String, std::fmt::Error> {
    if json {
        return show_ospfv3_database(top, args, json);
    }

    let mut out = String::new();
    writeln!(out)?;
    writeln!(out, "       OSPFv3 Router with ID ({})", top.router_id)?;
    writeln!(out)?;

    const AREA_TYPES: &[u16] = &[
        OSPFV3_ROUTER_LSA_TYPE,
        OSPFV3_NETWORK_LSA_TYPE,
        OSPFV3_INTER_AREA_PREFIX_LSA_TYPE,
        OSPFV3_INTER_AREA_ROUTER_LSA_TYPE,
        OSPFV3_INTRA_AREA_PREFIX_LSA_TYPE,
        ospf_packet::OSPFV3_E_ROUTER_LSA_TYPE,
        ospf_packet::OSPFV3_E_NETWORK_LSA_TYPE,
        ospf_packet::OSPFV3_E_INTER_AREA_PREFIX_LSA_TYPE,
        ospf_packet::OSPFV3_E_INTER_AREA_ROUTER_LSA_TYPE,
        ospf_packet::OSPFV3_E_INTRA_AREA_PREFIX_LSA_TYPE,
        // RFC 9513 SRv6 Locator LSA — area scope, own function code.
        ospf_packet::OSPFV3_SRV6_LOCATOR_LSA_TYPE,
    ];

    for (area_id, area) in top.areas.iter() {
        for &ls_type in AREA_TYPES {
            let mut section_printed = false;
            for ((ls_id, adv_router), lsa) in area.lsdb.iter_by_raw_type(ls_type) {
                if lsa.data.h.ls_age >= OSPF_MAX_AGE {
                    continue;
                }
                if !section_printed {
                    writeln!(
                        out,
                        "                {} (Area {})",
                        ls_type_name(ls_type),
                        area_id
                    )?;
                    writeln!(out)?;
                    section_printed = true;
                }
                write_lsa_detail(&mut out, lsa, ls_id, adv_router)?;
                writeln!(out)?;
            }
        }
    }

    const AS_TYPES: &[u16] = &[
        OSPFV3_AS_EXTERNAL_LSA_TYPE,
        ospf_packet::OSPFV3_E_AS_EXTERNAL_LSA_TYPE,
    ];

    for &ls_type in AS_TYPES {
        let mut section_printed = false;
        for ((ls_id, adv_router), lsa) in top.lsdb_as.iter_by_raw_type(ls_type) {
            if lsa.data.h.ls_age >= OSPF_MAX_AGE {
                continue;
            }
            if !section_printed {
                writeln!(out, "                {} (AS-Scope)", ls_type_name(ls_type))?;
                writeln!(out)?;
                section_printed = true;
            }
            write_lsa_detail(&mut out, lsa, ls_id, adv_router)?;
            writeln!(out)?;
        }
    }

    const LINK_TYPES: &[u16] = &[
        OSPFV3_LINK_LSA_TYPE,
        ospf_packet::OSPFV3_GRACE_LSA_TYPE,
        ospf_packet::OSPFV3_E_LINK_LSA_TYPE,
    ];

    for link in top.links.values() {
        for &ls_type in LINK_TYPES {
            let mut section_printed = false;
            for ((ls_id, adv_router), lsa) in link.lsdb.iter_by_raw_type(ls_type) {
                if lsa.data.h.ls_age >= OSPF_MAX_AGE {
                    continue;
                }
                if !section_printed {
                    writeln!(
                        out,
                        "                {} (Interface {})",
                        ls_type_name(ls_type),
                        link.name
                    )?;
                    writeln!(out)?;
                    section_printed = true;
                }
                write_lsa_detail(&mut out, lsa, ls_id, adv_router)?;
                writeln!(out)?;
            }
        }
    }

    Ok(out)
}

fn write_lsa_detail(
    out: &mut String,
    lsa: &Lsa<Ospfv3>,
    ls_id: u32,
    adv_router: Ipv4Addr,
) -> Result<(), std::fmt::Error> {
    let h = &lsa.data.h;
    writeln!(out, "  Age: {}", lsa.current_age())?;
    writeln!(
        out,
        "  Type: 0x{:04x} ({})",
        h.ls_type,
        ls_type_name(h.ls_type)
    )?;
    writeln!(out, "  Link State ID: {}", ls_id)?;
    writeln!(out, "  Advertising Router: {}", adv_router)?;
    writeln!(out, "  LS Sequence Number: 0x{:08x}", lsa.ls_seq_number())?;
    writeln!(out, "  Checksum: 0x{:04x}", lsa.ls_checksum())?;
    writeln!(out, "  Length: {}", lsa.length())?;
    match lsa.hold_remaining() {
        Some(s) => writeln!(out, "  Hold remaining: {}s", s)?,
        None => writeln!(out, "  Hold remaining: <unarmed>")?,
    }
    if lsa.originated {
        match lsa.refresh_remaining() {
            Some(s) => writeln!(out, "  Refresh remaining: {}s", s)?,
            None => writeln!(out, "  Refresh remaining: <unarmed>")?,
        }
    }

    match &lsa.data.body {
        Ospfv3LsBody::Router(b) => {
            writeln!(
                out,
                "  Flags: 0x{:02x} : {}",
                b.flags,
                format_router_flags(b.flags)
            )?;
            writeln!(out, "  Options: {}", format_options(b.options))?;
            for link in &b.links {
                writeln!(out)?;
                writeln!(out, "    Type: {}", router_link_type_name(link.link_type))?;
                writeln!(out, "    Metric: {}", link.metric)?;
                writeln!(out, "    Interface ID: {}", link.interface_id)?;
                writeln!(
                    out,
                    "    Neighbor Interface ID: {}",
                    link.neighbor_interface_id
                )?;
                writeln!(out, "    Neighbor Router ID: {}", link.neighbor_router_id)?;
            }
        }
        Ospfv3LsBody::Network(b) => {
            writeln!(out, "  Options: {}", format_options(b.options))?;
            for r in &b.attached_routers {
                writeln!(out, "    Attached Router: {}", r)?;
            }
        }
        Ospfv3LsBody::InterAreaPrefix(b) => {
            writeln!(out, "  Metric: {}", b.metric)?;
            writeln!(
                out,
                "  Prefix: {} (Options: {})",
                format_v3_prefix(b.prefix_length, &b.address_prefix),
                format_prefix_options(b.prefix_options)
            )?;
        }
        Ospfv3LsBody::InterAreaRouter(b) => {
            writeln!(out, "  Options: {}", format_options(b.options))?;
            writeln!(out, "  Metric: {}", b.metric)?;
            writeln!(
                out,
                "  Destination Router ID: {}",
                Ipv4Addr::from(b.destination_router_id)
            )?;
        }
        // NSSA-LSA shares the AS-External body shape per RFC 5340
        // §A.4.9; render identical fields. The LSA-Type header line
        // above already differentiates them ("NSSA-LSA" vs
        // "AS-External-LSA"), and consumption semantics (P-bit /
        // FA rules) read the same body fields.
        Ospfv3LsBody::AsExternal(b) | Ospfv3LsBody::Nssa(b) => {
            writeln!(
                out,
                "  Flags: 0x{:02x} : {}",
                b.flags,
                format_external_flags(b.flags)
            )?;
            writeln!(out, "  Metric: {}", b.metric)?;
            writeln!(
                out,
                "  Prefix: {} (Options: {})",
                format_v3_prefix(b.prefix_length, &b.address_prefix),
                format_prefix_options(b.prefix_options)
            )?;
            if let Some(fwd) = b.forwarding_address {
                writeln!(out, "  Forwarding Address: {}", fwd)?;
            }
            if let Some(tag) = b.external_route_tag {
                writeln!(out, "  External Route Tag: {}", tag)?;
            }
            if let Some(rls_id) = b.referenced_link_state_id {
                writeln!(
                    out,
                    "  Referenced LS Type: 0x{:04x} ({}), LS ID: {}",
                    b.referenced_ls_type,
                    ls_type_name(b.referenced_ls_type),
                    rls_id
                )?;
            }
        }
        Ospfv3LsBody::Link(b) => {
            writeln!(out, "  Priority: {}", b.priority)?;
            writeln!(out, "  Options: {}", format_options(b.options))?;
            writeln!(out, "  Link-Local Address: {}", b.link_local_address)?;
            writeln!(out, "  Number of Prefixes: {}", b.prefixes.len())?;
            for p in &b.prefixes {
                writeln!(
                    out,
                    "    Prefix: {} (Options: {})",
                    format_v3_prefix(p.prefix_length, &p.address_prefix),
                    format_prefix_options(p.prefix_options)
                )?;
            }
        }
        Ospfv3LsBody::IntraAreaPrefix(b) => {
            writeln!(out, "  Number of Prefixes: {}", b.prefixes.len())?;
            writeln!(
                out,
                "  Reference: {} Id: {} Adv: {}",
                ls_type_name(b.referenced_ls_type),
                b.referenced_link_state_id,
                b.referenced_advertising_router
            )?;
            for p in &b.prefixes {
                writeln!(
                    out,
                    "    Prefix: {} (Metric: {}, Options: {})",
                    format_v3_prefix(p.prefix_length, &p.address_prefix),
                    p.metric,
                    format_prefix_options(p.prefix_options)
                )?;
            }
        }
        // RFC 8362 Extended LSAs — full per-TLV / sub-TLV rendering,
        // mirroring v2's Opaque-LSA detail (`show_ext_link_detail` /
        // `show_router_info_detail` in show.rs).
        Ospfv3LsBody::ERouter(b)
        | Ospfv3LsBody::ENetwork(b)
        | Ospfv3LsBody::EInterAreaPrefix(b)
        | Ospfv3LsBody::EInterAreaRouter(b)
        | Ospfv3LsBody::EAsExternal(b)
        | Ospfv3LsBody::ELink(b)
        | Ospfv3LsBody::EIntraAreaPrefix(b) => {
            write_ext_lsa_body(out, b)?;
        }
        Ospfv3LsBody::Grace(b) => {
            if let Some(secs) = b.grace_period() {
                writeln!(out, "  Grace Period: {}s", secs)?;
            }
            if let Some(reason) = b.reason() {
                writeln!(out, "  Restart Reason: {:?}", reason)?;
            }
        }
        Ospfv3LsBody::Srv6Locator(b) => {
            write_srv6_locator_body(out, b)?;
        }
        Ospfv3LsBody::Unknown(bytes) => {
            writeln!(out, "  (Unrecognized LSA body, {} bytes)", bytes.len())?;
        }
    }
    Ok(())
}

/// Clean algorithm name (the `Algo` Display impl appends the numeric
/// value, e.g. "SPF(0)", which reads doubled next to the number we
/// already print).
fn format_algo(algo: &ospf_packet::Algo) -> String {
    use ospf_packet::Algo;
    match algo {
        Algo::Spf => "SPF".to_string(),
        Algo::StrictSpf => "Strict SPF".to_string(),
        Algo::FlexAlgo(n) => format!("Flex-Algo {}", n),
        Algo::Unknown(n) => format!("Unknown {}", n),
    }
}

/// "Label: N" / "Index: N" — v2's SID rendering convention.
fn format_sid_label(sid: &ospf_packet::SidLabelTlv) -> String {
    match sid {
        ospf_packet::SidLabelTlv::Label(v) => format!("Label: {}", v),
        ospf_packet::SidLabelTlv::Index(v) => format!("Index: {}", v),
    }
}

/// Hex byte plus decoded letters, e.g. "0x60 : V|L" (RFC 8666 §6.1).
fn format_adj_sid_flags(flags: &ospf_packet::AdjSidFlags) -> String {
    let mut names = Vec::new();
    if flags.b_flag() {
        names.push("B");
    }
    if flags.v_flag() {
        names.push("V");
    }
    if flags.l_flag() {
        names.push("L");
    }
    if flags.g_flag() {
        names.push("G");
    }
    if flags.p_flag() {
        names.push("P");
    }
    let joined = if names.is_empty() {
        "-".to_string()
    } else {
        names.join("|")
    };
    format!("0x{:02x} : {}", u8::from(*flags), joined)
}

/// Hex byte plus decoded letters, e.g. "0x20 : NP" (RFC 8666 §5).
fn format_prefix_sid_flags(flags: &ospf_packet::PrefixSidFlags) -> String {
    let mut names = Vec::new();
    if flags.np_flag() {
        names.push("NP");
    }
    if flags.m_flag() {
        names.push("M");
    }
    if flags.e_flag() {
        names.push("E");
    }
    if flags.v_flag() {
        names.push("V");
    }
    if flags.l_flag() {
        names.push("L");
    }
    let joined = if names.is_empty() {
        "-".to_string()
    } else {
        names.join("|")
    };
    format!("0x{:02x} : {}", u8::from(*flags), joined)
}

fn write_v3_asla_sub(
    out: &mut String,
    asla: &ospf_packet::Ospfv3AslaSubTlv,
) -> Result<(), std::fmt::Error> {
    use ospf_packet::Ospfv3AslaSubSubTlv;
    writeln!(out, "    Application-Specific Link Attributes Sub-TLV:")?;
    writeln!(out, "      SABM: {:02x?}", asla.sabm)?;
    if !asla.udabm.is_empty() {
        writeln!(out, "      UDABM: {:02x?}", asla.udabm)?;
    }
    for sub in &asla.subs {
        match sub {
            Ospfv3AslaSubSubTlv::ExtAdminGroup(g) => {
                writeln!(out, "      Extended Admin Group = {:08x?}", g.words)?;
            }
            Ospfv3AslaSubSubTlv::Unknown { typ, value } => {
                writeln!(
                    out,
                    "      Unknown Sub-sub-TLV: type={} len={}",
                    typ,
                    value.len()
                )?;
            }
        }
    }
    Ok(())
}

/// Render an RFC 9513 SRv6 Locator LSA body TLV-by-TLV.
fn write_srv6_locator_body(
    out: &mut String,
    body: &ospf_packet::Ospfv3Srv6LocatorLsa,
) -> Result<(), std::fmt::Error> {
    use ospf_packet::{Ospfv3Srv6LocatorLsaTlv, Ospfv3Srv6LocatorSubTlv};
    for tlv in &body.tlvs {
        match tlv {
            Ospfv3Srv6LocatorLsaTlv::Locator(loc) => {
                writeln!(
                    out,
                    "  SRv6 Locator TLV: {}/{}",
                    loc.locator, loc.locator_length
                )?;
                writeln!(out, "    Route Type: {}", loc.route_type)?;
                writeln!(out, "    Algorithm: {}", loc.algorithm)?;
                writeln!(out, "    Metric: {}", loc.metric)?;
                for sub in &loc.subs {
                    match sub {
                        Ospfv3Srv6LocatorSubTlv::EndSid(es) => {
                            writeln!(out, "    SRv6 End SID Sub-TLV:")?;
                            writeln!(out, "      Endpoint Behavior: {}", es.behavior)?;
                            writeln!(out, "      SID: {}", es.sid)?;
                            for s2 in &es.subs {
                                if let Ospfv3Srv6LocatorSubTlv::SidStructure(st) = s2 {
                                    writeln!(
                                        out,
                                        "      SID Structure: LB {} LN {} Fun {} Arg {}",
                                        st.lb_len, st.ln_len, st.fun_len, st.arg_len
                                    )?;
                                }
                            }
                        }
                        Ospfv3Srv6LocatorSubTlv::SidStructure(st) => {
                            writeln!(
                                out,
                                "    SID Structure Sub-TLV: LB {} LN {} Fun {} Arg {}",
                                st.lb_len, st.ln_len, st.fun_len, st.arg_len
                            )?;
                        }
                        Ospfv3Srv6LocatorSubTlv::Unknown { typ, value } => {
                            writeln!(out, "    Unknown Sub-TLV: type={} len={}", typ, value.len())?;
                        }
                    }
                }
            }
            Ospfv3Srv6LocatorLsaTlv::Unknown { typ, value } => {
                writeln!(out, "  Unknown TLV: type={} len={}", typ, value.len())?;
            }
        }
    }
    Ok(())
}

/// Render one RFC 8362 sub-TLV nested under a Router-Link or
/// Intra-Area-Prefix TLV.
fn write_v3_sub_tlv(
    out: &mut String,
    sub: &ospf_packet::Ospfv3SubTlv,
) -> Result<(), std::fmt::Error> {
    use ospf_packet::Ospfv3SubTlv;
    match sub {
        Ospfv3SubTlv::PrefixSid(sid) => {
            writeln!(out, "    Prefix-SID Sub-TLV:")?;
            writeln!(out, "      Flags: {}", format_prefix_sid_flags(&sid.flags))?;
            writeln!(
                out,
                "      Algorithm: {} ({})",
                u8::from(sid.algo),
                format_algo(&sid.algo)
            )?;
            writeln!(out, "      SID/Label: {}", format_sid_label(&sid.sid))?;
        }
        Ospfv3SubTlv::AdjSid(adj) => {
            writeln!(out, "    Adj-SID Sub-TLV:")?;
            writeln!(out, "      Flags: {}", format_adj_sid_flags(&adj.flags))?;
            writeln!(out, "      Weight: {}", adj.weight)?;
            writeln!(out, "      SID/Label: {}", format_sid_label(&adj.sid))?;
        }
        Ospfv3SubTlv::LanAdjSid(lan) => {
            writeln!(out, "    LAN Adj-SID Sub-TLV:")?;
            writeln!(out, "      Flags: {}", format_adj_sid_flags(&lan.flags))?;
            writeln!(out, "      Weight: {}", lan.weight)?;
            writeln!(out, "      Neighbor Router ID: {}", lan.neighbor_router_id)?;
            writeln!(out, "      SID/Label: {}", format_sid_label(&lan.sid))?;
        }
        Ospfv3SubTlv::Asla(asla) => {
            write_v3_asla_sub(out, asla)?;
        }
        Ospfv3SubTlv::Srv6EndXSid(endx) => {
            writeln!(out, "    SRv6 End.X SID Sub-TLV:")?;
            writeln!(out, "      Endpoint Behavior: {}", endx.behavior)?;
            writeln!(out, "      Flags: 0x{:02x}", endx.flags)?;
            writeln!(out, "      Algorithm: {}", endx.algo)?;
            writeln!(out, "      Weight: {}", endx.weight)?;
            writeln!(out, "      SID: {}", endx.sid)?;
            for sub in &endx.subs {
                write_v3_sub_tlv(out, sub)?;
            }
        }
        Ospfv3SubTlv::Srv6LanEndXSid(lan) => {
            writeln!(out, "    SRv6 LAN End.X SID Sub-TLV:")?;
            writeln!(out, "      Endpoint Behavior: {}", lan.behavior)?;
            writeln!(out, "      Flags: 0x{:02x}", lan.flags)?;
            writeln!(out, "      Algorithm: {}", lan.algo)?;
            writeln!(out, "      Weight: {}", lan.weight)?;
            writeln!(out, "      Neighbor Router ID: {}", lan.neighbor_router_id)?;
            writeln!(out, "      SID: {}", lan.sid)?;
            for sub in &lan.subs {
                write_v3_sub_tlv(out, sub)?;
            }
        }
        Ospfv3SubTlv::Srv6SidStructure(st) => {
            writeln!(
                out,
                "    SRv6 SID Structure Sub-TLV: LB {} LN {} Fun {} Arg {}",
                st.lb_len, st.ln_len, st.fun_len, st.arg_len
            )?;
        }
        Ospfv3SubTlv::Unknown { typ, value } => {
            writeln!(out, "    Unknown Sub-TLV: type={} len={}", typ, value.len())?;
        }
    }
    Ok(())
}

/// Render an RFC 8362 Extended LSA body TLV-by-TLV — the v3 analogue
/// of v2's `show_ext_link_detail` / `show_router_info_detail`.
fn write_ext_lsa_body(
    out: &mut String,
    body: &ospf_packet::Ospfv3ELsaBody,
) -> Result<(), std::fmt::Error> {
    use ospf_packet::{Ospfv3ExtTlv, Ospfv3FadSubTlv};
    for tlv in &body.tlvs {
        match tlv {
            Ospfv3ExtTlv::RouterLink(rl) => {
                writeln!(
                    out,
                    "  Router-Link TLV: Type: {}",
                    router_link_type_name(rl.link.link_type)
                )?;
                writeln!(out, "    Metric: {}", rl.link.metric)?;
                writeln!(out, "    Interface ID: {}", rl.link.interface_id)?;
                writeln!(
                    out,
                    "    Neighbor Interface ID: {}",
                    rl.link.neighbor_interface_id
                )?;
                writeln!(
                    out,
                    "    Neighbor Router ID: {}",
                    rl.link.neighbor_router_id
                )?;
                for sub in &rl.subs {
                    write_v3_sub_tlv(out, sub)?;
                }
            }
            Ospfv3ExtTlv::IntraAreaPrefix(p) => {
                writeln!(out, "  Intra-Area-Prefix TLV:")?;
                writeln!(out, "    Metric: {}", p.metric)?;
                writeln!(
                    out,
                    "    Prefix: {} (Options: {})",
                    format_v3_prefix(p.prefix_length, &p.address_prefix),
                    format_prefix_options(p.prefix_options)
                )?;
                writeln!(
                    out,
                    "    Reference: {} Id: {} Adv: {}",
                    ls_type_name(p.referenced_ls_type as u16),
                    p.referenced_link_state_id,
                    p.referenced_advertising_router
                )?;
                for sub in &p.subs {
                    write_v3_sub_tlv(out, sub)?;
                }
            }
            Ospfv3ExtTlv::SrAlgorithm(a) => {
                writeln!(out, "  SR-Algorithm TLV:")?;
                for algo in &a.algos {
                    writeln!(
                        out,
                        "    Algorithm {}: {}",
                        u8::from(*algo),
                        format_algo(algo)
                    )?;
                }
            }
            Ospfv3ExtTlv::SidLabelRange(r) => {
                writeln!(out, "  SID/Label Range TLV (SRGB):")?;
                writeln!(out, "    Range Size: {}", r.range)?;
                writeln!(out, "    SID/Label: {}", format_sid_label(&r.sid_label))?;
            }
            Ospfv3ExtTlv::SrLocalBlock(lb) => {
                writeln!(out, "  SR Local Block TLV (SRLB):")?;
                writeln!(out, "    Range Size: {}", lb.range)?;
                writeln!(out, "    SID/Label: {}", format_sid_label(&lb.sid_label))?;
            }
            Ospfv3ExtTlv::Fad(fad) => {
                writeln!(out, "  Flexible Algorithm Definition TLV:")?;
                writeln!(out, "    Flex-Algorithm = {}", fad.flex_algorithm)?;
                let metric = match fad.metric_type {
                    0 => "IGP",
                    1 => "Min Unidirectional Link Delay",
                    2 => "TE Default",
                    _ => "Unknown",
                };
                writeln!(out, "    Metric-Type = {} ({})", fad.metric_type, metric)?;
                writeln!(out, "    Calc-Type = {}", fad.calc_type)?;
                writeln!(out, "    Priority = {}", fad.priority)?;
                for sub in &fad.subs {
                    match sub {
                        Ospfv3FadSubTlv::ExcludeAg(g) => {
                            writeln!(out, "    Exclude Admin Group = {:08x?}", g.words)?;
                        }
                        Ospfv3FadSubTlv::IncludeAnyAg(g) => {
                            writeln!(out, "    Include-Any Admin Group = {:08x?}", g.words)?;
                        }
                        Ospfv3FadSubTlv::IncludeAllAg(g) => {
                            writeln!(out, "    Include-All Admin Group = {:08x?}", g.words)?;
                        }
                        Ospfv3FadSubTlv::Flags(fl) => {
                            writeln!(out, "    Flags: M-flag = {}", fl.m_flag)?;
                        }
                        Ospfv3FadSubTlv::ExcludeSrlg(s) => {
                            writeln!(out, "    Exclude SRLG = {:?}", s.srlgs)?;
                        }
                        Ospfv3FadSubTlv::Unknown { typ, value } => {
                            writeln!(out, "    Unknown Sub-TLV: type={} len={}", typ, value.len())?;
                        }
                    }
                }
            }
            Ospfv3ExtTlv::Srv6Capabilities(cap) => {
                writeln!(out, "  SRv6 Capabilities TLV: Flags: 0x{:04x}", cap.flags)?;
            }
            Ospfv3ExtTlv::Unknown { typ, value } => {
                writeln!(out, "  Unknown TLV: type={} len={}", typ, value.len())?;
            }
        }
    }
    Ok(())
}

fn format_options(opts: Ospfv3Options) -> String {
    let mut flags = Vec::new();
    if opts.v6() {
        flags.push("V6");
    }
    if opts.e() {
        flags.push("E");
    }
    if opts.mc() {
        flags.push("MC");
    }
    if opts.n() {
        flags.push("N");
    }
    if opts.r() {
        flags.push("R");
    }
    if opts.dc() {
        flags.push("DC");
    }
    if flags.is_empty() {
        "-".to_string()
    } else {
        flags.join("|")
    }
}

fn format_prefix_options(opts: Ospfv3PrefixOptions) -> String {
    let mut flags = Vec::new();
    if opts.nu() {
        flags.push("NU");
    }
    if opts.la() {
        flags.push("LA");
    }
    if opts.mc() {
        flags.push("MC");
    }
    if opts.p() {
        flags.push("P");
    }
    if flags.is_empty() {
        "-".to_string()
    } else {
        flags.join("|")
    }
}

fn format_router_flags(flags: u8) -> String {
    let mut s = Vec::new();
    if flags & OSPFV3_ROUTER_LSA_FLAG_W != 0 {
        s.push("W");
    }
    if flags & OSPFV3_ROUTER_LSA_FLAG_V != 0 {
        s.push("V");
    }
    if flags & OSPFV3_ROUTER_LSA_FLAG_E != 0 {
        s.push("E");
    }
    if flags & OSPFV3_ROUTER_LSA_FLAG_B != 0 {
        s.push("B");
    }
    if s.is_empty() {
        "-".to_string()
    } else {
        s.join("|")
    }
}

fn format_external_flags(flags: u8) -> String {
    let mut s = Vec::new();
    if flags & OSPFV3_AS_EXTERNAL_FLAG_E != 0 {
        s.push("E");
    }
    if flags & OSPFV3_AS_EXTERNAL_FLAG_F != 0 {
        s.push("F");
    }
    if flags & OSPFV3_AS_EXTERNAL_FLAG_T != 0 {
        s.push("T");
    }
    if s.is_empty() {
        "-".to_string()
    } else {
        s.join("|")
    }
}

fn router_link_type_name(t: Ospfv3RouterLinkType) -> &'static str {
    match t {
        Ospfv3RouterLinkType::PointToPoint => "Point-to-Point",
        Ospfv3RouterLinkType::Transit => "Transit Network",
        Ospfv3RouterLinkType::VirtualLink => "Virtual Link",
    }
}

fn format_v3_prefix(prefix_length: u8, bytes: &[u8]) -> String {
    if prefix_length > 128 {
        return format!("(invalid /{})", prefix_length);
    }
    let mut padded = [0u8; 16];
    let n = bytes.len().min(16);
    padded[..n].copy_from_slice(&bytes[..n]);
    let addr = std::net::Ipv6Addr::from(padded);
    match ipnet::Ipv6Net::new(addr, prefix_length) {
        Ok(net) => net.trunc().to_string(),
        Err(_) => format!("{}/{}", addr, prefix_length),
    }
}

// ---- show ospfv3 route ---------------------------------------

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
                    // `::` nexthops mark directly-attached prefixes
                    // (self-originated Intra-Area-Prefix-LSAs, per
                    // RFC 5340 §3.8.1 self-vertex handling); render
                    // them by interface name where we have it.
                    if n.nexthop == "::" {
                        let ifname = top
                            .links
                            .get(&n.ifindex)
                            .map(|l| l.name.as_str())
                            .unwrap_or("unknown");
                        format!("directly attached via {}", ifname)
                    } else if n.ifindex != 0 {
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

// ---- show ospfv3 spf -----------------------------------------

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

/// `show ospfv3 flex-algo` — for each configured Flexible Algorithm
/// (RFC 9350): its local definition plus the FAD-filtered per-algo SPF
/// tree (the routers reachable under that algorithm's constraints).
/// v3 sibling of v2's `show_ospf_flex_algo`. Per-algo v6 routes land
/// with the v6 RIB slice.
#[derive(Serialize)]
struct Ospfv3FlexAlgoSpfNodeJson {
    router_id: String,
    cost: u32,
    /// Resolved router-ids of the first-hop links to this node; empty
    /// for the source vertex itself.
    via: Vec<String>,
}

#[derive(Serialize)]
struct Ospfv3FlexAlgoRouteJson {
    prefix: String,
    metric: u32,
    /// Resolved absolute MPLS label for the per-algo Prefix-SID, when
    /// derivable (mirror of v2's `FlexAlgoRouteJson::label`).
    label: Option<u32>,
    nexthops: Vec<String>,
}

#[derive(Serialize)]
struct Ospfv3FlexAlgoJson {
    algorithm: u8,
    metric_type: String,
    priority: u8,
    advertise_definition: bool,
    include_any: Vec<String>,
    include_all: Vec<String>,
    exclude_any: Vec<String>,
    srlg_exclude: Vec<String>,
    /// `computed` | `no-source-vertex` | `not-computed`.
    spf_status: String,
    spf_nodes: Vec<Ospfv3FlexAlgoSpfNodeJson>,
    routes: Vec<Ospfv3FlexAlgoRouteJson>,
}

fn show_ospfv3_flex_algo(
    top: &Ospf<Ospfv3>,
    _args: Args,
    json: bool,
) -> Result<String, std::fmt::Error> {
    use crate::flex_algo::FadMetricType;

    let metric_name = |m: FadMetricType| match m {
        FadMetricType::Igp => "igp",
        FadMetricType::MinUnidirLinkDelay => "min-unidir-link-delay",
        FadMetricType::TeDefault => "te-default",
    };
    let names =
        |s: &std::collections::BTreeSet<String>| s.iter().cloned().collect::<Vec<_>>().join(" ");
    let set_vec = |s: &std::collections::BTreeSet<String>| s.iter().cloned().collect::<Vec<_>>();

    let mut algos: Vec<Ospfv3FlexAlgoJson> = Vec::new();
    let mut buf = String::new();
    if top.flex_algo.config.is_empty() {
        writeln!(buf, "No Flexible Algorithms configured")?;
        return render_or(json, &algos, buf);
    }

    for (algo, entry) in &top.flex_algo.config {
        writeln!(buf, "Flex-Algorithm {algo}")?;
        let metric = metric_name(entry.metric_type.unwrap_or(FadMetricType::Igp));
        writeln!(buf, "  Metric-Type: {metric}")?;
        writeln!(buf, "  Priority: {}", entry.priority.unwrap_or(128))?;
        writeln!(
            buf,
            "  Advertise-Definition: {}",
            entry.advertise_definition.unwrap_or(false)
        )?;
        if !entry.include_any.is_empty() {
            writeln!(buf, "  Affinity Include-Any: {}", names(&entry.include_any))?;
        }
        if !entry.include_all.is_empty() {
            writeln!(buf, "  Affinity Include-All: {}", names(&entry.include_all))?;
        }
        if !entry.exclude_any.is_empty() {
            writeln!(buf, "  Affinity Exclude-Any: {}", names(&entry.exclude_any))?;
        }
        if !entry.srlg_exclude.is_empty() {
            writeln!(buf, "  SRLG Exclude: {}", names(&entry.srlg_exclude))?;
        }

        let (spf_status, spf_nodes) = match top.spf_flex_algo.get(algo) {
            Some(Some(spf_res)) => {
                writeln!(buf, "  SPF: {} reachable node(s)", spf_res.len())?;
                let mut nodes = Vec::new();
                for (id, path) in spf_res {
                    let router_id = top
                        .lsp_map
                        .resolve(*id)
                        .map_or_else(|| String::from("?"), |r| r.to_string());
                    let via: Vec<String> = path
                        .first_hop_links
                        .iter()
                        .filter_map(|(vid, _)| top.lsp_map.resolve(*vid).map(|r| r.to_string()))
                        .collect();
                    let via_disp = if via.is_empty() {
                        "(self)".to_string()
                    } else {
                        via.join(", ")
                    };
                    writeln!(buf, "    {router_id} cost {} via {via_disp}", path.cost)?;
                    nodes.push(Ospfv3FlexAlgoSpfNodeJson {
                        router_id,
                        cost: path.cost,
                        via,
                    });
                }
                ("computed", nodes)
            }
            Some(None) => {
                writeln!(buf, "  SPF: no source vertex in per-algo topology")?;
                ("no-source-vertex", Vec::new())
            }
            None => {
                writeln!(buf, "  SPF: not yet computed")?;
                ("not-computed", Vec::new())
            }
        };

        // Per-algo v6 RIB: prefixes forwardable under this algo (those
        // carrying a per-algo Prefix-SID), with the resolved MPLS label
        // and the per-algo nexthops.
        let mut routes = Vec::new();
        if let Some(rib) = top.rib6_flex_algo.get(algo) {
            if rib.iter().next().is_none() {
                writeln!(buf, "  Routes: none (no per-algo Prefix-SIDs reachable)")?;
            } else {
                writeln!(buf, "  Routes:")?;
                for (prefix, route) in rib.iter() {
                    let label = route
                        .sid
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "-".to_string());
                    let nh = route
                        .nhops
                        .keys()
                        .map(|a| a.to_string())
                        .collect::<Vec<_>>()
                        .join(",");
                    writeln!(
                        buf,
                        "    {prefix}  metric {}  label {label}  via {nh}",
                        route.metric
                    )?;
                    routes.push(Ospfv3FlexAlgoRouteJson {
                        prefix: prefix.to_string(),
                        metric: route.metric,
                        label: route.sid,
                        nexthops: route.nhops.keys().map(|a| a.to_string()).collect(),
                    });
                }
            }
        }
        writeln!(buf)?;

        algos.push(Ospfv3FlexAlgoJson {
            algorithm: *algo,
            metric_type: metric_name(entry.metric_type.unwrap_or(FadMetricType::Igp)).to_string(),
            priority: entry.priority.unwrap_or(128),
            advertise_definition: entry.advertise_definition.unwrap_or(false),
            include_any: set_vec(&entry.include_any),
            include_all: set_vec(&entry.include_all),
            exclude_any: set_vec(&entry.exclude_any),
            srlg_exclude: set_vec(&entry.srlg_exclude),
            spf_status: spf_status.to_string(),
            spf_nodes,
            routes,
        });
    }
    render_or(json, &algos, buf)
}

// ---- show ospfv3 graph ---------------------------------------

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

// ---- show ospfv3 segment-routing -----------------------------

#[derive(Serialize)]
struct Ospfv3SrLanAdjSidJson {
    neighbor_router_id: String,
    label: u32,
}

#[derive(Serialize)]
struct Ospfv3SrInterfaceJson {
    name: String,
    network_type: String,
    prefix_sid: Option<String>,
    adjacency_sid: Option<String>,
    lan_adj_sids: Vec<Ospfv3SrLanAdjSidJson>,
}

#[derive(Serialize)]
struct Ospfv3SrIlmJson {
    label: u32,
    ilm_type: String,
    via: String,
    interface: String,
}

#[derive(Serialize)]
struct Ospfv3SrRemotePrefixRowJson {
    prefix: String,
    sid_form: String,
    label_op: String,
    interface: String,
    nexthop: String,
}

#[derive(Serialize)]
struct Ospfv3SrRemoteRouterJson {
    advertising_router: String,
    area: String,
    /// Peer's SRGB block as `[start/end]`, formatted from the
    /// `Ospfv3` LSDB's `label_map` (populated by the SR-info ingest
    /// path -- see `Lsdb<Ospfv3>::update_lsa_v3`). `None` when the
    /// peer's SR-info LSA has not arrived yet or carried no
    /// SID/Label Range TLV; in that case Index-form Prefix-SIDs are
    /// not resolved into absolute labels and `label_op` stays empty.
    srgb: Option<String>,
    srlb: Option<String>,
    prefixes: Vec<Ospfv3SrRemotePrefixRowJson>,
}

#[derive(Serialize)]
struct Ospfv3SegmentRoutingJson {
    enabled: bool,
    router_id: String,
    srgb_start: u32,
    srgb_end: u32,
    srlb_start: u32,
    srlb_end: u32,
    interfaces: Vec<Ospfv3SrInterfaceJson>,
    ilm: Vec<Ospfv3SrIlmJson>,
    remote_routers: Vec<Ospfv3SrRemoteRouterJson>,
}

fn fmt_prefix_sid(p: &super::link::PrefixSid) -> String {
    match p {
        super::link::PrefixSid::Index(idx) => format!("idx {}", idx),
        super::link::PrefixSid::Absolute(label) => format!("lbl {}", label),
    }
}

fn fmt_adj_sid(a: &super::link::AdjacencySid) -> String {
    match a {
        super::link::AdjacencySid::Index(idx) => format!("idx {}", idx),
        super::link::AdjacencySid::Absolute(label) => format!("lbl {}", label),
    }
}

fn fmt_ilm_type(t: &crate::rib::inst::IlmType) -> String {
    match t {
        crate::rib::inst::IlmType::None => "-".to_string(),
        crate::rib::inst::IlmType::Node(idx) => format!("Pop SR Pfx (idx {})", idx),
        crate::rib::inst::IlmType::Adjacency(idx) => format!("Pop SR Adj (idx {})", idx),
        crate::rib::inst::IlmType::DecapVrf { table_id, .. } => {
            format!("Pop DecapVrf (table {})", table_id)
        }
        crate::rib::inst::IlmType::ContextLabel { table_id, .. } => {
            format!("Pop Mirror Ctx (table {})", table_id)
        }
        crate::rib::inst::IlmType::Swap => "Swap LU".to_string(),
    }
}

fn show_ospfv3_segment_routing(
    top: &Ospf<Ospfv3>,
    _args: Args,
    json: bool,
) -> Result<String, std::fmt::Error> {
    use super::srmpls::{SRGB_RANGE, SRGB_START, SRLB_RANGE, SRLB_START, SegmentRoutingMode};

    let enabled = top.segment_routing == SegmentRoutingMode::Mpls;

    // Per-interface SR view. Iterate stable ifindex order so output
    // is deterministic between runs (BTreeMap already orders).
    let interfaces: Vec<Ospfv3SrInterfaceJson> = top
        .links
        .iter()
        .filter(|(_, link)| link.enabled)
        .map(|(ifindex, link)| {
            let lan_adj_sids: Vec<Ospfv3SrLanAdjSidJson> = top
                .lan_adj_sids
                .iter()
                .filter(|((idx, _), _)| idx == ifindex)
                .map(|((_, rid), label)| Ospfv3SrLanAdjSidJson {
                    neighbor_router_id: rid.to_string(),
                    label: *label,
                })
                .collect();
            Ospfv3SrInterfaceJson {
                name: link.name.clone(),
                network_type: link.network_type.to_string(),
                prefix_sid: link.config.prefix_sid.as_ref().map(fmt_prefix_sid),
                adjacency_sid: link.config.adjacency_sid.as_ref().map(fmt_adj_sid),
                lan_adj_sids,
            }
        })
        .collect();

    // ILM view sourced from the v3 LFIB shadow. Render via address as
    // a string (link-local IPv6 unless an unspecified placeholder).
    let ilm: Vec<Ospfv3SrIlmJson> = top
        .ilm6
        .iter()
        .map(|(label, entry)| {
            let (via, ifname) = entry
                .nhops
                .iter()
                .next()
                .map(|(addr, nh)| {
                    let via_s = if addr.is_unspecified() {
                        String::new()
                    } else {
                        addr.to_string()
                    };
                    (via_s, top.ifname(nh.ifindex))
                })
                .unwrap_or_default();
            Ospfv3SrIlmJson {
                label: *label,
                ilm_type: fmt_ilm_type(&entry.ilm_type),
                via,
                interface: ifname,
            }
        })
        .collect();

    // Remote SR view: walk every area's E-Intra-Area-Prefix-LSAs
    // (LS Type 0xA029, RFC 8362 §3.7) advertised by *other* routers,
    // pulling out each `PrefixSid` sub-TLV (RFC 8666 §5). Nexthop /
    // interface come from the resolved RIB so the operator sees what
    // forwarding will actually use; the resolved label comes from
    // `SpfRouteV3.sid` populated by `add_prefix_sids_v3` -- single
    // source of truth shared with the install path. Per-router SRGB
    // / SRLB metadata comes from the LSDB's `label_map`, populated
    // by `Lsdb<Ospfv3>::update_lsa_v3`.
    let remote_routers = collect_remote_routers(top);

    let summary = Ospfv3SegmentRoutingJson {
        enabled,
        router_id: top.router_id.to_string(),
        srgb_start: SRGB_START,
        srgb_end: SRGB_START + SRGB_RANGE - 1,
        srlb_start: SRLB_START,
        srlb_end: SRLB_START + SRLB_RANGE - 1,
        interfaces,
        ilm,
        remote_routers,
    };

    let mut text = String::new();
    writeln!(text)?;
    writeln!(
        text,
        "  OSPFv3 Segment Routing database for ID {}",
        summary.router_id
    )?;
    writeln!(
        text,
        "  State: {}",
        if enabled { "enabled" } else { "disabled" }
    )?;
    writeln!(
        text,
        "  Local SRGB: [{}/{}]   SRLB: [{}/{}]",
        summary.srgb_start, summary.srgb_end, summary.srlb_start, summary.srlb_end
    )?;
    writeln!(text)?;
    writeln!(
        text,
        "  {:<12}  {:<14}  {:<14}  {:<14}  Adj-SID",
        "Interface", "Network", "Prefix-SID", "Adj-SID"
    )?;
    writeln!(text, "  {}", "-".repeat(74))?;
    for iface in &summary.interfaces {
        writeln!(
            text,
            "  {:<12}  {:<14}  {:<14}  {:<14}",
            iface.name,
            iface.network_type,
            iface.prefix_sid.as_deref().unwrap_or("-"),
            iface.adjacency_sid.as_deref().unwrap_or("-"),
        )?;
        // Dynamically allocated per-adjacency labels — LAN Adj-SIDs
        // on broadcast/NBMA segments, plain Adj-SIDs on P2P links
        // with no configured `adjacency-sid`; don't tag them "LAN".
        for lan in &iface.lan_adj_sids {
            writeln!(
                text,
                "  {:<12}  {:<14}  {:<14}  nbr={} lbl={}",
                "", "", "", lan.neighbor_router_id, lan.label
            )?;
        }
    }

    writeln!(text)?;
    writeln!(text, "  Local ILM (v3): {} entries", summary.ilm.len())?;
    writeln!(
        text,
        "  {:<8}  {:<22}  {:<32}  Iface",
        "Label", "Type", "Via"
    )?;
    writeln!(text, "  {}", "-".repeat(72))?;
    for e in &summary.ilm {
        writeln!(
            text,
            "  {:<8}  {:<22}  {:<32}  {}",
            e.label, e.ilm_type, e.via, e.interface
        )?;
    }

    if !summary.remote_routers.is_empty() {
        writeln!(text)?;
        writeln!(text, "  Remote Prefix-SIDs:")?;
        for router in &summary.remote_routers {
            writeln!(text)?;
            writeln!(
                text,
                "  SR-Node: {}    Area: {}    SRGB: {}    SRLB: {}",
                router.advertising_router,
                router.area,
                router.srgb.as_deref().unwrap_or("(unknown)"),
                router.srlb.as_deref().unwrap_or("(unknown)"),
            )?;
            writeln!(
                text,
                "    {:<32}  {:<18}  {:<14}  {:<9}  Nexthop",
                "Prefix", "Prefix-SID", "Label Op", "Iface"
            )?;
            writeln!(text, "    {}", "-".repeat(82))?;
            for row in &router.prefixes {
                writeln!(
                    text,
                    "    {:<32}  {:<18}  {:<14}  {:<9}  {}",
                    row.prefix, row.sid_form, row.label_op, row.interface, row.nexthop
                )?;
            }
        }
    }
    writeln!(text)?;

    render_or(json, &summary, text)
}

/// Walk every area's E-Intra-Area-Prefix-LSAs advertised by *other*
/// routers and return one entry per `PrefixSid` sub-TLV. Filters out
/// MaxAge LSAs and self-originated ones (those are already in the
/// local section). Grouped by `(area_id, advertising_router)` so the
/// per-router header (SRGB / SRLB from `label_map`) can render once.
/// Within a group, prefixes are sorted lexicographically by string
/// form (good enough for human-readable display).
fn collect_remote_routers(top: &Ospf<Ospfv3>) -> Vec<Ospfv3SrRemoteRouterJson> {
    use std::collections::BTreeMap;

    use ipnet::Ipv6Net;
    use ospf_packet::{
        OSPFV3_E_INTRA_AREA_PREFIX_LSA_TYPE, Ospfv3ExtTlv, Ospfv3LsBody, Ospfv3SubTlv, SidLabelTlv,
        ospfv3_prefix_wire_len,
    };

    type RouterKey = (Ipv4Addr, Ipv4Addr); // (area_id, advertising_router)
    let mut buckets: BTreeMap<RouterKey, Vec<Ospfv3SrRemotePrefixRowJson>> = BTreeMap::new();
    // Track the LSDB instance per area so we can resolve SRGB/SRLB
    // for each router after the prefix loop completes.
    let mut srgb_lookup: BTreeMap<RouterKey, (Option<String>, Option<String>)> = BTreeMap::new();

    let fmt_block = |b: &crate::spf::label_block::LabelBlock| -> String {
        format!("[{}/{}]", b.start, b.end.saturating_sub(1))
    };

    for (area_id, area) in top.areas.iter() {
        for ((_ls_id, _adv), lsa) in area
            .lsdb
            .iter_by_raw_type(OSPFV3_E_INTRA_AREA_PREFIX_LSA_TYPE)
        {
            if lsa.data.h.ls_age >= OSPF_MAX_AGE {
                continue;
            }
            let advertising = lsa.data.h.advertising_router;
            if advertising == top.router_id {
                continue;
            }
            let Ospfv3LsBody::EIntraAreaPrefix(ref body) = lsa.data.body else {
                continue;
            };

            // Resolve peer's SRGB / SRLB from the LSDB's label_map.
            // Populated by `Lsdb<Ospfv3>::update_lsa_v3` when the
            // peer's SR-info E-Router-LSA arrives. Same key used by
            // `add_prefix_sids_v3` for Index→Label resolution.
            let key = (*area_id, advertising);
            srgb_lookup.entry(key).or_insert_with(|| {
                if let Some(cfg) = area.lsdb.label_map.get(&advertising) {
                    let srgb = fmt_block(&cfg.global);
                    let srlb = cfg.local.as_ref().map(&fmt_block);
                    (Some(srgb), srlb)
                } else {
                    (None, None)
                }
            });

            for tlv in &body.tlvs {
                let Ospfv3ExtTlv::IntraAreaPrefix(prefix_tlv) = tlv else {
                    continue;
                };
                let wire_len = ospfv3_prefix_wire_len(prefix_tlv.prefix_length);
                if prefix_tlv.address_prefix.len() < wire_len {
                    continue;
                }
                let mut bytes = [0u8; 16];
                let copy = wire_len.min(16);
                bytes[..copy].copy_from_slice(&prefix_tlv.address_prefix[..copy]);
                let addr = std::net::Ipv6Addr::from(bytes);
                let Ok(prefix) = Ipv6Net::new(addr, prefix_tlv.prefix_length) else {
                    continue;
                };
                let prefix = prefix.trunc();
                for sub in &prefix_tlv.subs {
                    let Ospfv3SubTlv::PrefixSid(ps) = sub else {
                        continue;
                    };
                    let sid_form = match ps.sid {
                        SidLabelTlv::Index(idx) => format!("SR Pfx (idx {})", idx),
                        SidLabelTlv::Label(lbl) => format!("SR Pfx (lbl {})", lbl),
                    };
                    let (label_op, interface, nexthop) = match top.rib6.get(&prefix) {
                        Some(route) => {
                            let label_op =
                                route.sid.map(|l| format!("Push {}", l)).unwrap_or_default();
                            let (ifname, nh) = route
                                .nhops
                                .iter()
                                .next()
                                .map(|(via, nh)| {
                                    let via_s = if via.is_unspecified() {
                                        String::new()
                                    } else {
                                        via.to_string()
                                    };
                                    (top.ifname(nh.ifindex), via_s)
                                })
                                .unwrap_or_default();
                            (label_op, ifname, nh)
                        }
                        None => (String::new(), String::new(), String::new()),
                    };
                    buckets
                        .entry(key)
                        .or_default()
                        .push(Ospfv3SrRemotePrefixRowJson {
                            prefix: prefix.to_string(),
                            sid_form,
                            label_op,
                            interface,
                            nexthop,
                        });
                }
            }
        }
    }

    let mut out: Vec<Ospfv3SrRemoteRouterJson> = buckets
        .into_iter()
        .map(|((area_id, adv), mut prefixes)| {
            prefixes.sort_by(|a, b| a.prefix.cmp(&b.prefix));
            let (srgb, srlb) = srgb_lookup
                .get(&(area_id, adv))
                .cloned()
                .unwrap_or((None, None));
            Ospfv3SrRemoteRouterJson {
                advertising_router: adv.to_string(),
                area: area_id.to_string(),
                srgb,
                srlb,
                prefixes,
            }
        })
        .collect();
    out.sort_by(|a, b| {
        a.advertising_router
            .cmp(&b.advertising_router)
            .then_with(|| a.area.cmp(&b.area))
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin the LS-Type → display-name map for every codepoint we
    /// originate or parse, so `show ospfv3 database` never falls
    /// back to "Unknown" for our own LSAs again (the RFC 8362 E-LSA
    /// family regressed this way once: SR-enabled LSDBs listed 38
    /// "Unknown" entries).
    #[test]
    fn ls_type_name_covers_extended_lsas() {
        use ospf_packet::{
            OSPFV3_E_AS_EXTERNAL_LSA_TYPE, OSPFV3_E_INTER_AREA_PREFIX_LSA_TYPE,
            OSPFV3_E_INTER_AREA_ROUTER_LSA_TYPE, OSPFV3_E_INTRA_AREA_PREFIX_LSA_TYPE,
            OSPFV3_E_LINK_LSA_TYPE, OSPFV3_E_NETWORK_LSA_TYPE, OSPFV3_E_ROUTER_LSA_TYPE,
            OSPFV3_GRACE_LSA_TYPE, OSPFV3_NSSA_LSA_TYPE, OSPFV3_SRV6_LOCATOR_LSA_TYPE,
        };
        assert_eq!(ls_type_name(OSPFV3_ROUTER_LSA_TYPE), "Router-LSA");
        assert_eq!(ls_type_name(OSPFV3_NETWORK_LSA_TYPE), "Network-LSA");
        assert_eq!(
            ls_type_name(OSPFV3_INTER_AREA_PREFIX_LSA_TYPE),
            "Inter-Area-Prefix-LSA"
        );
        assert_eq!(
            ls_type_name(OSPFV3_INTER_AREA_ROUTER_LSA_TYPE),
            "Inter-Area-Router-LSA"
        );
        assert_eq!(ls_type_name(OSPFV3_AS_EXTERNAL_LSA_TYPE), "AS-External-LSA");
        assert_eq!(ls_type_name(OSPFV3_NSSA_LSA_TYPE), "NSSA-LSA");
        assert_eq!(ls_type_name(OSPFV3_LINK_LSA_TYPE), "Link-LSA");
        assert_eq!(
            ls_type_name(OSPFV3_INTRA_AREA_PREFIX_LSA_TYPE),
            "Intra-Area-Prefix-LSA"
        );
        assert_eq!(ls_type_name(OSPFV3_GRACE_LSA_TYPE), "Grace-LSA");
        assert_eq!(ls_type_name(OSPFV3_E_ROUTER_LSA_TYPE), "E-Router-LSA");
        assert_eq!(
            ls_type_name(OSPFV3_SRV6_LOCATOR_LSA_TYPE),
            "SRv6-Locator-LSA"
        );
        assert_eq!(ls_type_name(OSPFV3_E_NETWORK_LSA_TYPE), "E-Network-LSA");
        assert_eq!(
            ls_type_name(OSPFV3_E_INTER_AREA_PREFIX_LSA_TYPE),
            "E-Inter-Area-Prefix-LSA"
        );
        assert_eq!(
            ls_type_name(OSPFV3_E_INTER_AREA_ROUTER_LSA_TYPE),
            "E-Inter-Area-Router-LSA"
        );
        assert_eq!(
            ls_type_name(OSPFV3_E_AS_EXTERNAL_LSA_TYPE),
            "E-AS-External-LSA"
        );
        assert_eq!(ls_type_name(OSPFV3_E_LINK_LSA_TYPE), "E-Link-LSA");
        assert_eq!(
            ls_type_name(OSPFV3_E_INTRA_AREA_PREFIX_LSA_TYPE),
            "E-Intra-Area-Prefix-LSA"
        );
        assert_eq!(ls_type_name(0x1FFF), "Unknown");
    }

    fn render_ext_body(lsa: &ospf_packet::Ospfv3Lsa) -> String {
        let mut out = String::new();
        match &lsa.body {
            Ospfv3LsBody::ERouter(b) | Ospfv3LsBody::EIntraAreaPrefix(b) => {
                write_ext_lsa_body(&mut out, b).unwrap();
            }
            other => panic!("unexpected body: {:?}", other),
        }
        out
    }

    /// The SR-capabilities E-Router-LSA must render the SRGB / SRLB
    /// ranges and the algorithm list — `show ospfv3 database
    /// detail` regressed to bare TLV names once; these pin the
    /// field-level output.
    #[test]
    fn ext_lsa_detail_renders_sr_capabilities() {
        use crate::ospf::srmpls::{
            SRGB_RANGE, SRGB_START, SRLB_RANGE, SRLB_START, e_router_v3_sr_info_lsa_build,
        };
        use ospf_packet::Algo;

        let lsa = e_router_v3_sr_info_lsa_build(
            "10.0.0.1".parse().unwrap(),
            vec![Algo::Spf],
            Vec::new(),
            false,
        );
        let out = render_ext_body(&lsa);
        assert!(out.contains("SR-Algorithm TLV:"), "{out}");
        assert!(out.contains("Algorithm 0: SPF"), "{out}");
        assert!(out.contains("SID/Label Range TLV (SRGB):"), "{out}");
        assert!(
            out.contains(&format!("Range Size: {}", SRGB_RANGE)),
            "{out}"
        );
        assert!(
            out.contains(&format!("SID/Label: Label: {}", SRGB_START)),
            "{out}"
        );
        assert!(out.contains("SR Local Block TLV (SRLB):"), "{out}");
        assert!(
            out.contains(&format!("Range Size: {}", SRLB_RANGE)),
            "{out}"
        );
        assert!(
            out.contains(&format!("SID/Label: Label: {}", SRLB_START)),
            "{out}"
        );
    }

    #[test]
    fn ext_lsa_detail_renders_adj_sid() {
        use crate::ospf::link::AdjacencySid;
        use crate::ospf::srmpls::{build_v3_p2p_adj_sub, e_router_v3_lsa_build};
        use ospf_packet::Ospfv3RouterLinkType;

        let lsa = e_router_v3_lsa_build(
            "10.0.0.1".parse().unwrap(),
            Ospfv3RouterLinkType::PointToPoint,
            10,
            1648,
            1647,
            "10.0.0.2".parse().unwrap(),
            vec![build_v3_p2p_adj_sub(&AdjacencySid::Absolute(15003))],
            1648,
        );
        let out = render_ext_body(&lsa);
        assert!(
            out.contains("Router-Link TLV: Type: Point-to-Point"),
            "{out}"
        );
        assert!(out.contains("Metric: 10"), "{out}");
        assert!(out.contains("Neighbor Router ID: 10.0.0.2"), "{out}");
        assert!(out.contains("Adj-SID Sub-TLV:"), "{out}");
        // Absolute label => V|L set (RFC 8666 §6.1) — the dynamic
        // SRLB Adj-SIDs advertise in exactly this form.
        assert!(out.contains("Flags: 0x60 : V|L"), "{out}");
        assert!(out.contains("SID/Label: Label: 15003"), "{out}");
    }

    #[test]
    fn ext_lsa_detail_renders_prefix_sid() {
        use crate::ospf::link::PrefixSid;
        use crate::ospf::srmpls::ext_intra_area_prefix_v3_lsa_build;
        use std::collections::BTreeMap;

        let lsa = ext_intra_area_prefix_v3_lsa_build(
            "10.0.0.1".parse().unwrap(),
            "2001:db8::1/128".parse().unwrap(),
            Some(&PrefixSid::Index(100)),
            &BTreeMap::new(),
            1,
            0,
        );
        let out = render_ext_body(&lsa);
        assert!(out.contains("Intra-Area-Prefix TLV:"), "{out}");
        assert!(out.contains("Prefix: 2001:db8::1/128"), "{out}");
        assert!(
            out.contains("Reference: Router-LSA Id: 0 Adv: 10.0.0.1"),
            "{out}"
        );
        assert!(out.contains("Prefix-SID Sub-TLV:"), "{out}");
        // Index form carries NP (no-PHP) per the v3 origination
        // path; NP is the top bit of the flags octet.
        assert!(out.contains("Flags: 0x80 : NP"), "{out}");
        assert!(out.contains("Algorithm: 0 (SPF)"), "{out}");
        assert!(out.contains("SID/Label: Index: 100"), "{out}");
    }
}

// ---- show ospfv3 srv6 ------------------------------------------------

#[derive(Serialize)]
struct Ospfv3Srv6LocatorJson {
    name: String,
    prefix: Option<String>,
    behavior: Option<&'static str>,
}

#[derive(Serialize)]
struct Ospfv3Srv6EndSidJson {
    sid: String,
    behavior: &'static str,
}

#[derive(Serialize)]
struct Ospfv3Srv6EndXJson {
    interface: String,
    neighbor_router_id: String,
    sid: String,
    behavior: &'static str,
    nexthop: Option<String>,
    lib_sid: Option<String>,
}

#[derive(Serialize)]
struct Ospfv3Srv6Json {
    locator: Option<Ospfv3Srv6LocatorJson>,
    end_sid: Option<Ospfv3Srv6EndSidJson>,
    end_x_sids: Vec<Ospfv3Srv6EndXJson>,
}

/// Pure text layout for `show ospfv3 srv6`, split out so the format
/// can be pinned by a unit test without constructing an instance.
fn render_ospfv3_srv6_text(v: &Ospfv3Srv6Json) -> Result<String, std::fmt::Error> {
    let mut out = String::new();
    writeln!(out, "OSPFv3 SRv6:")?;
    match &v.locator {
        None => writeln!(out, "  Locator: (not configured)")?,
        Some(loc) => match (&loc.prefix, loc.behavior) {
            (Some(prefix), Some(behavior)) => {
                writeln!(out, "  Locator: {} ({}, {})", loc.name, prefix, behavior)?
            }
            _ => writeln!(out, "  Locator: {} (unresolved)", loc.name)?,
        },
    }
    if let Some(end) = &v.end_sid {
        writeln!(out, "  End SID: {} ({})", end.sid, end.behavior)?;
    }
    if v.end_x_sids.is_empty() {
        return Ok(out);
    }
    writeln!(out)?;
    writeln!(out, "Local SRv6 End.X SIDs:")?;
    writeln!(
        out,
        " {:<10} {:<15} {:<24} {:<8} {:<24} LIB",
        "Interface", "Neighbor", "SID", "Behavior", "Nexthop"
    )?;
    for row in &v.end_x_sids {
        writeln!(
            out,
            " {:<10} {:<15} {:<24} {:<8} {:<24} {}",
            row.interface,
            row.neighbor_router_id,
            row.sid,
            row.behavior,
            row.nexthop.as_deref().unwrap_or("-"),
            row.lib_sid.as_deref().unwrap_or("-"),
        )?;
    }
    Ok(out)
}

/// `show ospfv3 srv6` — the operational SRv6 view: the configured /
/// resolved locator, the End/uN SID, and one row per adjacency End.X
/// with the *installed* nexthop (the neighbor's global once its
/// Link-LSA delivered one — the #1361 kernel constraint makes this
/// the column operators check first) and the uA(LIB) twin.
fn show_ospfv3_srv6(
    top: &Ospf<Ospfv3>,
    _args: Args,
    json: bool,
) -> Result<String, std::fmt::Error> {
    use crate::rib::LocatorBehavior;

    let usid = matches!(
        top.sr_locator.as_ref().and_then(|l| l.behavior.as_ref()),
        Some(LocatorBehavior::Usid)
    );
    let locator = top
        .srv6_locator_name
        .as_ref()
        .map(|name| Ospfv3Srv6LocatorJson {
            name: name.clone(),
            prefix: top
                .sr_locator
                .as_ref()
                .and_then(|l| l.prefix)
                .map(|p| p.to_string()),
            behavior: top
                .sr_locator
                .as_ref()
                .and_then(|l| l.prefix)
                .map(|_| if usid { "usid" } else { "classic" }),
        });
    let end_sid = top.sr_end_sid.map(|sid| Ospfv3Srv6EndSidJson {
        sid: sid.to_string(),
        behavior: if usid { "uN" } else { "End" },
    });
    let end_x_sids: Vec<Ospfv3Srv6EndXJson> = top
        .endx_sids
        .iter()
        .map(|((ifindex, rid), state)| Ospfv3Srv6EndXJson {
            interface: top
                .links
                .get(ifindex)
                .map(|l| l.name.clone())
                .unwrap_or_else(|| ifindex.to_string()),
            neighbor_router_id: rid.to_string(),
            sid: state.addr.to_string(),
            behavior: if usid { "uA" } else { "End.X" },
            nexthop: state.nh6.map(|a| a.to_string()),
            lib_sid: state.lib_addr.map(|a| a.to_string()),
        })
        .collect();

    let v = Ospfv3Srv6Json {
        locator,
        end_sid,
        end_x_sids,
    };
    if json {
        return Ok(serde_json::to_string_pretty(&v).unwrap_or_else(|_| String::from("{}")));
    }
    render_ospfv3_srv6_text(&v)
}

#[cfg(test)]
mod srv6_show_tests {
    use super::*;

    // Pin the text layout: locator line, End SID line, and the End.X
    // table with the installed (global) nexthop and LIB twin.
    #[test]
    fn srv6_show_renders_locator_end_and_endx_rows() {
        let v = Ospfv3Srv6Json {
            locator: Some(Ospfv3Srv6LocatorJson {
                name: "LOC1".into(),
                prefix: Some("fcbb:bbbb:1::/48".into()),
                behavior: Some("usid"),
            }),
            end_sid: Some(Ospfv3Srv6EndSidJson {
                sid: "fcbb:bbbb:1::".into(),
                behavior: "uN",
            }),
            end_x_sids: vec![Ospfv3Srv6EndXJson {
                interface: "i2".into(),
                neighbor_router_id: "10.0.0.2".into(),
                sid: "fcbb:bbbb:1:e000::".into(),
                behavior: "uA",
                nexthop: Some("2001:db8:12::2".into()),
                lib_sid: Some("fcbb:bbbb:e000::".into()),
            }],
        };
        let text = render_ospfv3_srv6_text(&v).unwrap();
        assert!(text.contains("Locator: LOC1 (fcbb:bbbb:1::/48, usid)"));
        assert!(text.contains("End SID: fcbb:bbbb:1:: (uN)"));
        assert!(text.contains("Local SRv6 End.X SIDs:"));
        assert!(text.contains("fcbb:bbbb:1:e000::"));
        assert!(text.contains("2001:db8:12::2"));
        assert!(text.contains("fcbb:bbbb:e000::"));
    }

    // The unconfigured / unresolved degradations.
    #[test]
    fn srv6_show_degrades_without_locator() {
        let none = Ospfv3Srv6Json {
            locator: None,
            end_sid: None,
            end_x_sids: vec![],
        };
        assert!(
            render_ospfv3_srv6_text(&none)
                .unwrap()
                .contains("Locator: (not configured)")
        );

        let unresolved = Ospfv3Srv6Json {
            locator: Some(Ospfv3Srv6LocatorJson {
                name: "LOC1".into(),
                prefix: None,
                behavior: None,
            }),
            end_sid: None,
            end_x_sids: vec![],
        };
        assert!(
            render_ospfv3_srv6_text(&unresolved)
                .unwrap()
                .contains("Locator: LOC1 (unresolved)")
        );
    }
}
