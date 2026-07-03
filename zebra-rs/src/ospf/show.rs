use std::fmt::Write;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use netlink_packet_route::link::LinkFlags;
use ospf_packet::*;
use serde::Serialize;

use crate::config::{Args, Builder};
use crate::rib::LinkFlagsExt;
use crate::spf;

use super::ifsm::IfsmState;
use super::{AREA0, Neighbor, NfsmState, Ospf, OspfLink, ShowCallback};

// JSON output structs for show ospf interface.
#[derive(Serialize)]
struct OspfInterfaceJson {
    name: String,
    status: String,
    ifindex: u32,
    mtu: u32,
    address: String,
    broadcast: String,
    area: String,
    router_id: String,
    network_type: String,
    cost: u32,
    transmit_delay: u16,
    state: String,
    priority: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    dr_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dr_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bdr_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bdr_address: Option<String>,
    hello_interval: u16,
    dead_interval: u32,
    retransmit_interval: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    hello_due: Option<String>,
    neighbor_count: usize,
    adjacent_count: usize,
}

// JSON output structs for show ospf neighbor.
#[derive(Serialize)]
struct OspfNeighborJson {
    neighbor_id: String,
    priority: u8,
    state: String,
    up_time: String,
    dead_time: String,
    address: String,
    interface: String,
    retransmit_list: usize,
    request_list: usize,
    db_summary_list: usize,
}

// JSON output structs for show ospf neighbor detail.
#[derive(Serialize)]
struct OspfNeighborDetailJson {
    neighbor_id: String,
    interface_address: String,
    area: String,
    interface: String,
    local_interface_ip: String,
    priority: u8,
    state: String,
    role: String,
    state_changes: usize,
    lsa_retransmissions: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_progressive_change: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_regressive_change: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_regressive_reason: Option<String>,
    dr: String,
    bdr: String,
    options: String,
    dead_timer: String,
    db_summary_list: usize,
    ls_request_list: usize,
    ls_retransmission_list: usize,
}

// JSON output structs for show ospf database.
#[derive(Serialize)]
struct OspfDatabaseJson {
    router_id: String,
    areas: Vec<OspfAreaDatabaseJson>,
}

#[derive(Serialize)]
struct OspfAreaDatabaseJson {
    area_id: String,
    router_lsas: Vec<OspfLsaSummaryJson>,
    network_lsas: Vec<OspfLsaSummaryJson>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    opaque_area_lsas: Vec<OspfLsaSummaryJson>,
}

#[derive(Serialize)]
struct OspfLsaSummaryJson {
    link_id: String,
    adv_router: String,
    age: u16,
    seq_number: String,
    checksum: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    link_count: Option<usize>,
}

// JSON output structs for show ospf database detail.
#[derive(Serialize)]
struct OspfDatabaseDetailJson {
    router_id: String,
    areas: Vec<OspfAreaDatabaseDetailJson>,
}

#[derive(Serialize)]
struct OspfAreaDatabaseDetailJson {
    area_id: String,
    router_lsas: Vec<OspfRouterLsaDetailJson>,
    network_lsas: Vec<OspfNetworkLsaDetailJson>,
}

#[derive(Serialize)]
struct OspfRouterLsaDetailJson {
    ls_age: u16,
    options: String,
    link_state_id: String,
    advertising_router: String,
    ls_seq_number: String,
    checksum: String,
    length: u16,
    num_links: usize,
    links: Vec<OspfRouterLinkDetailJson>,
}

#[derive(Serialize)]
struct OspfRouterLinkDetailJson {
    link_type: String,
    link_id: String,
    link_data: String,
    num_tos: u8,
    tos_0_metric: u16,
}

#[derive(Serialize)]
struct OspfNetworkLsaDetailJson {
    ls_age: u16,
    options: String,
    link_state_id: String,
    advertising_router: String,
    ls_seq_number: String,
    checksum: String,
    length: u16,
    network_mask: String,
    attached_routers: Vec<String>,
}

impl Ospf {
    pub fn show_build(&mut self) {
        self.show_cb = Builder::<ShowCallback>::default()
            .path("/show/ospf")
            .set(show_ospf)
            .path("/show/ospf/interface")
            .set(show_ospf_interface)
            .path("/show/ospf/neighbor")
            .set(show_ospf_neighbor)
            .path("/show/ospf/neighbor/detail")
            .set(show_ospf_neighbor_detail)
            .path("/show/ospf/database")
            .set(show_ospf_database)
            .path("/show/ospf/database/detail")
            .set(show_ospf_database_detail)
            .path("/show/ospf/route")
            .set(show_ospf_route)
            .path("/show/ospf/spf")
            .set(show_ospf_spf)
            .path("/show/ospf/flex-algo")
            .set(show_ospf_flex_algo)
            .path("/show/ospf/graph")
            .set(show_ospf_graph)
            .path("/show/ospf/ti-lfa")
            .set(show_ospf_tilfa)
            .path("/show/ospf/repair-list")
            .set(show_ospf_repair_list)
            .path("/show/ospf/repair-list/detail")
            .set(show_ospf_repair_list_detail)
            .path("/show/ospf/segment-routing")
            .set(show_ospf_segment_routing)
            .path("/show/ospf/graceful-restart")
            .set(show_ospf_graceful_restart)
            .path("/show/ospf/checkpoint")
            .set(show_ospf_checkpoint)
            .map();
    }
}

fn format_link_flags(flags: &LinkFlags) -> String {
    let mut parts = Vec::new();
    if (*flags & LinkFlags::Up) == LinkFlags::Up {
        parts.push("UP");
    }
    if (*flags & LinkFlags::LowerUp) == LinkFlags::LowerUp {
        parts.push("LOWER_UP");
    }
    if (*flags & LinkFlags::Broadcast) == LinkFlags::Broadcast {
        parts.push("BROADCAST");
    }
    if (*flags & LinkFlags::Running) == LinkFlags::Running {
        parts.push("RUNNING");
    }
    if (*flags & LinkFlags::Multicast) == LinkFlags::Multicast {
        parts.push("MULTICAST");
    }
    if (*flags & LinkFlags::Loopback) == LinkFlags::Loopback {
        parts.push("LOOPBACK");
    }
    if (*flags & LinkFlags::Pointopoint) == LinkFlags::Pointopoint {
        parts.push("POINTOPOINT");
    }
    format!("<{}>", parts.join(","))
}

fn find_nbr_router_id(oi: &OspfLink, addr: Ipv4Addr) -> Option<Ipv4Addr> {
    for nbr in oi.nbrs.values() {
        if nbr.ident.prefix.addr() == addr {
            return Some(nbr.ident.router_id);
        }
    }
    None
}

fn render_link(out: &mut String, oi: &OspfLink, ospf: &Ospf) {
    // Line 1: Interface name and status.
    let status = if oi.link_flags.is_up() { "up" } else { "down" };
    writeln!(out, "{} is {}", oi.name, status).unwrap();

    // Line 2: ifindex, MTU, BW, flags.
    writeln!(
        out,
        "  ifindex {}, MTU {} bytes, BW 0 Mbit {}",
        oi.index,
        oi.mtu,
        format_link_flags(&oi.link_flags)
    )
    .unwrap();

    // Line 3: Internet Address, Broadcast, Area.
    writeln!(
        out,
        "  Internet Address {}, Broadcast {}, Area {}",
        oi.ident.prefix,
        oi.ident.prefix.broadcast(),
        oi.area_id
    )
    .unwrap();

    // Line 4: MTU mismatch detection.
    writeln!(out, "  MTU mismatch detection: enabled").unwrap();

    // Line 5: Router ID, Network Type, Cost.
    writeln!(
        out,
        "  Router ID {}, Network Type {}, Cost: {}",
        oi.ident.router_id, oi.network_type, oi.output_cost
    )
    .unwrap();

    // Line 6: Transmit Delay, State, Priority.
    writeln!(
        out,
        "  Transmit Delay is {} sec, State {}, Priority {}",
        oi.transmit_delay(),
        oi.state,
        oi.priority()
    )
    .unwrap();

    // Line 7: Designated Router.
    if !oi.ident.d_router.is_unspecified() {
        let dr_router_id = if oi.ident.prefix.addr() == oi.ident.d_router {
            oi.ident.router_id
        } else {
            find_nbr_router_id(oi, oi.ident.d_router).unwrap_or(Ipv4Addr::UNSPECIFIED)
        };
        let dr_prefix = oi
            .nbrs
            .values()
            .find(|nbr| nbr.ident.prefix.addr() == oi.ident.d_router)
            .map(|nbr| nbr.ident.prefix)
            .unwrap_or(oi.ident.prefix);
        writeln!(
            out,
            "  Designated Router (ID) {} Interface Address {}",
            dr_router_id, dr_prefix
        )
        .unwrap();
    }

    // Line 8: Backup Designated Router.
    if !oi.ident.bd_router.is_unspecified() {
        let bdr_router_id = if oi.ident.prefix.addr() == oi.ident.bd_router {
            oi.ident.router_id
        } else {
            find_nbr_router_id(oi, oi.ident.bd_router).unwrap_or(Ipv4Addr::UNSPECIFIED)
        };
        let bdr_prefix = oi
            .nbrs
            .values()
            .find(|nbr| nbr.ident.prefix.addr() == oi.ident.bd_router)
            .map(|nbr| nbr.ident.prefix)
            .unwrap_or(oi.ident.prefix);
        writeln!(
            out,
            "  Backup Designated Router (ID) {}, Interface Address {}",
            bdr_router_id, bdr_prefix
        )
        .unwrap();
    }

    // Line 9: Network-LSA sequence number (only when DR).
    if oi.state == IfsmState::DR
        && let Some(area) = ospf.areas.get(oi.area_id)
        && let Some(lsa) =
            area.lsdb
                .lookup_lsa(OspfLsType::Network, oi.ident.prefix.addr(), ospf.router_id)
    {
        writeln!(
            out,
            "  Saved Network-LSA sequence number 0x{:08x}",
            lsa.ls_seq_number()
        )
        .unwrap();
    }

    // Line 10: Multicast group memberships.
    let mut groups = Vec::new();
    if oi.multicast_memberships.all_routers() {
        groups.push("OSPFAllRouters");
    }
    if oi.multicast_memberships.all_drouters() {
        groups.push("OSPFDesignatedRouters");
    }
    if !groups.is_empty() {
        writeln!(out, "  Multicast group memberships: {}", groups.join(" ")).unwrap();
    }

    // Line 11: Timer intervals.
    writeln!(
        out,
        "  Timer intervals configured, Hello {}s, Dead {}s, Wait {}s, Retransmit {}",
        oi.hello_interval(),
        oi.dead_interval(),
        oi.dead_interval(),
        oi.retransmit_interval(),
    )
    .unwrap();

    // Line 12: Hello due.
    if oi.is_passive() {
        writeln!(out, "    No Hellos (Passive interface)").unwrap();
    } else if let Some(ref hello_timer) = oi.timer.hello {
        let remaining = hello_timer.remaining();
        let secs = remaining.as_secs_f64();
        writeln!(out, "    Hello due in {:.3}s", secs).unwrap();
    }

    // Line 13: Neighbor counts.
    let nbr_count = oi.nbrs.len();
    let adj_count = oi
        .nbrs
        .values()
        .filter(|nbr| nbr.state == NfsmState::Full)
        .count();
    writeln!(
        out,
        "  Neighbor Count is {}, Adjacent neighbor count is {}",
        nbr_count, adj_count
    )
    .unwrap();

    // Line 14: Graceful Restart hello delay.
    writeln!(out, "  Graceful Restart hello delay: 10s").unwrap();

    // Line 15: LSA retransmissions.
    let rxmt_count: usize = oi.nbrs.values().map(|nbr| nbr.ls_rxmt.len()).sum();
    writeln!(out, "  LSA retransmissions: {}", rxmt_count).unwrap();
}

fn show_ospf_interface(
    ospf: &Ospf,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    if json {
        let mut ifaces: Vec<OspfInterfaceJson> = Vec::new();
        for (_, oi) in ospf.links.iter() {
            if !oi.enabled {
                continue;
            }
            let status = if oi.link_flags.is_up() { "up" } else { "down" }.to_string();

            let (dr_id, dr_address) = if !oi.ident.d_router.is_unspecified() {
                let rid = if oi.ident.prefix.addr() == oi.ident.d_router {
                    oi.ident.router_id
                } else {
                    find_nbr_router_id(oi, oi.ident.d_router).unwrap_or(Ipv4Addr::UNSPECIFIED)
                };
                let addr = oi
                    .nbrs
                    .values()
                    .find(|nbr| nbr.ident.prefix.addr() == oi.ident.d_router)
                    .map(|nbr| nbr.ident.prefix)
                    .unwrap_or(oi.ident.prefix);
                (Some(rid.to_string()), Some(addr.to_string()))
            } else {
                (None, None)
            };

            let (bdr_id, bdr_address) = if !oi.ident.bd_router.is_unspecified() {
                let rid = if oi.ident.prefix.addr() == oi.ident.bd_router {
                    oi.ident.router_id
                } else {
                    find_nbr_router_id(oi, oi.ident.bd_router).unwrap_or(Ipv4Addr::UNSPECIFIED)
                };
                let addr = oi
                    .nbrs
                    .values()
                    .find(|nbr| nbr.ident.prefix.addr() == oi.ident.bd_router)
                    .map(|nbr| nbr.ident.prefix)
                    .unwrap_or(oi.ident.prefix);
                (Some(rid.to_string()), Some(addr.to_string()))
            } else {
                (None, None)
            };

            let hello_due = if oi.is_passive() {
                None
            } else {
                oi.timer
                    .hello
                    .as_ref()
                    .map(|t| format!("{:.3}s", t.remaining().as_secs_f64()))
            };

            let nbr_count = oi.nbrs.len();
            let adj_count = oi
                .nbrs
                .values()
                .filter(|nbr| nbr.state == NfsmState::Full)
                .count();

            ifaces.push(OspfInterfaceJson {
                name: oi.name.clone(),
                status,
                ifindex: oi.index,
                mtu: oi.mtu,
                address: oi.ident.prefix.to_string(),
                broadcast: oi.ident.prefix.broadcast().to_string(),
                area: oi.area_id.to_string(),
                router_id: oi.ident.router_id.to_string(),
                network_type: oi.network_type.to_string(),
                cost: oi.output_cost,
                transmit_delay: oi.transmit_delay(),
                state: oi.state.to_string(),
                priority: oi.priority(),
                dr_id,
                dr_address,
                bdr_id,
                bdr_address,
                hello_interval: oi.hello_interval(),
                dead_interval: oi.dead_interval(),
                retransmit_interval: oi.retransmit_interval(),
                hello_due,
                neighbor_count: nbr_count,
                adjacent_count: adj_count,
            });
        }
        return Ok(serde_json::to_string_pretty(&ifaces)
            .unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e)));
    }

    let mut buf = String::new();

    for (_, oi) in ospf.links.iter() {
        if oi.enabled {
            render_link(&mut buf, oi, ospf);
        }
    }
    Ok(buf)
}

#[derive(Serialize)]
struct OspfAreaGateJson {
    area_id: String,
    spf_inflight: bool,
    spf_pending: bool,
}

#[derive(Serialize)]
struct OspfSummaryJson {
    router_id: String,
    area_count: usize,
    link_count: usize,
    spf_last_ms_ago: Option<u128>,
    spf_duration_us: Option<u128>,
    /// TI-LFA compute telemetry for the most-recent run, preformatted.
    /// `None` until TI-LFA runs (and cleared when it is disabled). Same
    /// shape as the OSPFv3 summary's `tilfa_compute`.
    tilfa_compute: Option<String>,
    /// Per-area SPF-offload gates. The instance-level `spf_*` fields
    /// reflect the most-recent area's run; these tell automation which
    /// area's worker is still in `spawn_blocking` and which has a
    /// coalesced follow-up.
    spf_offload_gates: Vec<OspfAreaGateJson>,
}

fn show_ospf(ospf: &Ospf, _args: Args, json: bool) -> std::result::Result<String, std::fmt::Error> {
    if json {
        let spf_offload_gates: Vec<_> = ospf
            .areas
            .iter()
            .map(|(area_id, area)| OspfAreaGateJson {
                area_id: area_id.to_string(),
                spf_inflight: area.spf_inflight,
                spf_pending: area.spf_pending,
            })
            .collect();
        let summary = OspfSummaryJson {
            router_id: ospf.router_id.to_string(),
            area_count: ospf.areas.iter().count(),
            link_count: ospf.links.len(),
            spf_last_ms_ago: ospf
                .spf_last
                .map(|t| Instant::now().duration_since(t).as_millis()),
            spf_duration_us: ospf.spf_duration.map(|d| d.as_micros()),
            tilfa_compute: ospf.tilfa_stats.as_ref().map(|s| {
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
        return Ok(serde_json::to_string_pretty(&summary)
            .unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e)));
    }
    let mut buf = String::new();
    writeln!(buf, " OSPF Routing Process, Router ID: {}", ospf.router_id)?;
    if let Some(spf_last) = ospf.spf_last {
        let elapsed = Instant::now().duration_since(spf_last);
        writeln!(
            buf,
            " SPF algorithm last executed {} ago",
            format_uptime(elapsed)
        )?;
    }
    if let Some(spf_duration) = ospf.spf_duration {
        writeln!(buf, " Last SPF duration {} usecs", spf_duration.as_micros())?;
    }
    writeln!(
        buf,
        " SPF timers: initial {} ms, secondary {} ms, maximum {} ms",
        ospf.spf_interval.initial_wait_ms,
        ospf.spf_interval.secondary_wait_ms,
        ospf.spf_interval.maximum_wait_ms,
    )?;
    writeln!(
        buf,
        " MinLSInterval (self-LSA re-origination): {} ms",
        ospf.min_ls_interval_ms,
    )?;
    writeln!(
        buf,
        " MinLSArrival (received-LSA rate limit): {} ms",
        ospf.min_ls_arrival_ms,
    )?;
    // RFC 6987 stub router — only shown while active, mirroring FRR.
    if ospf.stub_router_admin {
        writeln!(
            buf,
            " Stub router: administrative (transit links at max-metric)"
        )?;
    } else if ospf.stub_router_startup_active {
        let remaining = ospf
            .stub_router_startup_timer
            .as_ref()
            .map(|t| t.remaining().as_secs())
            .unwrap_or(0);
        writeln!(
            buf,
            " Stub router: on-startup ({}s remaining, transit links at max-metric)",
            remaining
        )?;
    }
    // TI-LFA compute telemetry for the same run (last-area-wins, like
    // `spf_duration`). None while TI-LFA is disabled.
    if let Some(stats) = &ospf.tilfa_stats {
        writeln!(
            buf,
            " TI-LFA compute: targets={} mode={} workers={} spf{{q={} pc={} dedup-saved={}}} took {} usecs",
            stats.targets,
            stats.mode,
            stats.width,
            stats.q_spf,
            stats.pc_spf,
            stats.pc_deduped,
            stats.duration.as_micros(),
        )?;
    }
    // Per-area offload gates. The instance-level `spf_last` /
    // `spf_duration` above reflect the most-recent area's run
    // (`apply_spf_result` stamps the instance fields unconditionally);
    // the per-area inflight / pending flags below tell you which
    // area's worker is still running and which has a queued
    // follow-up. Always emitted (matching IS-IS's `show isis spf`
    // banner) so the absence of inflight state is visible too.
    if ospf.areas.iter().next().is_some() {
        writeln!(buf, " SPF offload gates:")?;
        for (area_id, area) in ospf.areas.iter() {
            writeln!(
                buf,
                "   area {}: inflight={}, pending={}",
                area_id, area.spf_inflight, area.spf_pending,
            )?;
        }
    }
    Ok(buf)
}

fn nbr_state_string(
    nbr_state: &NfsmState,
    nbr_addr: &Ipv4Addr,
    d_router: &Ipv4Addr,
    bd_router: &Ipv4Addr,
) -> String {
    let role = if nbr_addr == d_router {
        "DR"
    } else if nbr_addr == bd_router {
        "Backup"
    } else {
        "DROther"
    };
    format!("{}/{}", nbr_state, role)
}

fn format_uptime(elapsed: Duration) -> String {
    let total_secs = elapsed.as_secs();
    let days = total_secs / 86400;
    let hours = (total_secs % 86400) / 3600;
    let mins = (total_secs % 3600) / 60;
    let secs = total_secs % 60;
    if days > 0 {
        format!("{}d{:02}h{:02}m", days, hours, mins)
    } else if hours > 0 {
        format!("{}h{:02}m{:02}s", hours, mins, secs)
    } else {
        format!("{}m{:02}s", mins, secs)
    }
}

fn format_dead_time(remaining: Duration) -> String {
    let secs = remaining.as_secs_f64();
    format!("{:.3}s", secs)
}

fn show_ospf_neighbor(
    ospf: &Ospf,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    if json {
        let mut nbrs_json: Vec<OspfNeighborJson> = Vec::new();
        for (_, oi) in ospf.links.iter() {
            if !oi.enabled {
                continue;
            }
            for (_, nbr) in oi.nbrs.iter() {
                let state = nbr_state_string(
                    &nbr.state,
                    &nbr.ident.prefix.addr(),
                    &oi.ident.d_router,
                    &oi.ident.bd_router,
                );
                let uptime = format_uptime(nbr.uptime.elapsed());
                let dead_time = match nbr.timer.inactivity {
                    Some(ref timer) => format_dead_time(timer.remaining()),
                    None => "-".to_string(),
                };
                let iface = format!("{}:{}", oi.name, oi.ident.prefix.addr());
                nbrs_json.push(OspfNeighborJson {
                    neighbor_id: nbr.ident.router_id.to_string(),
                    priority: nbr.ident.priority,
                    state,
                    up_time: uptime,
                    dead_time,
                    address: nbr.ident.prefix.addr().to_string(),
                    interface: iface,
                    retransmit_list: nbr.ls_rxmt.len(),
                    request_list: nbr.ls_req.len(),
                    db_summary_list: nbr.db_sum.len(),
                });
            }
        }
        return Ok(serde_json::to_string_pretty(&nbrs_json)
            .unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e)));
    }

    let mut buf = String::new();

    writeln!(
        buf,
        "{:<15} {:>3} {:<15} {:>15} {:>10} {:<15} {:<32} {:>5} {:>5} {:>5}",
        "Neighbor ID",
        "Pri",
        "State",
        "Up Time",
        "Dead Time",
        "Address",
        "Interface",
        "RXmtL",
        "RqstL",
        "DBsmL"
    )?;

    for (_, oi) in ospf.links.iter() {
        if !oi.enabled {
            continue;
        }
        for (_, nbr) in oi.nbrs.iter() {
            let state = nbr_state_string(
                &nbr.state,
                &nbr.ident.prefix.addr(),
                &oi.ident.d_router,
                &oi.ident.bd_router,
            );

            let uptime = format_uptime(nbr.uptime.elapsed());

            let dead_time = match nbr.timer.inactivity {
                Some(ref timer) => format_dead_time(timer.remaining()),
                None => "-".to_string(),
            };

            let iface = format!("{}:{}", oi.name, oi.ident.prefix.addr());

            writeln!(
                buf,
                "{:<15} {:>3} {:<15} {:>15} {:>10} {:<15} {:<32} {:>5} {:>5} {:>5}",
                nbr.ident.router_id,
                nbr.ident.priority,
                state,
                uptime,
                dead_time,
                nbr.ident.prefix.addr(),
                iface,
                nbr.ls_rxmt.len(),
                nbr.ls_req.len(),
                nbr.db_sum.len(),
            )?;
        }
    }
    Ok(buf)
}

fn format_options_flags(options: &OspfOptions) -> String {
    let dn = if options.dn() { "DN" } else { "*" };
    let o = if options.o() { "O" } else { "-" };
    let dc = if options.demand_circuits() { "DC" } else { "-" };
    let l = if options.lls_data() { "L" } else { "-" };
    let np = if options.nssa() { "N/P" } else { "-" };
    let mc = if options.multicast() { "MC" } else { "-" };
    let e = if options.external() { "E" } else { "-" };
    let mt = if options.multi_toplogy() { "MT" } else { "-" };
    format!("{}|{}|{}|{}|{}|{}|{}|{}", dn, o, dc, l, np, mc, e, mt)
}

fn format_options(options: &OspfOptions) -> String {
    let raw = u8::from(*options);
    format!("{} {}", raw, format_options_flags(options))
}

fn nbr_role(nbr_addr: &Ipv4Addr, d_router: &Ipv4Addr, bd_router: &Ipv4Addr) -> &'static str {
    if nbr_addr == d_router {
        "DR"
    } else if nbr_addr == bd_router {
        "Backup"
    } else {
        "DROther"
    }
}

fn find_router_id_by_addr(oi: &OspfLink, addr: Ipv4Addr) -> Ipv4Addr {
    if addr == oi.ident.prefix.addr() {
        return oi.ident.router_id;
    }
    for nbr in oi.nbrs.values() {
        if nbr.ident.prefix.addr() == addr {
            return nbr.ident.router_id;
        }
    }
    Ipv4Addr::UNSPECIFIED
}

fn render_nbr_detail(out: &mut String, oi: &OspfLink, nbr: &Neighbor) {
    // Line 1: Neighbor ID and interface address.
    writeln!(
        out,
        " Neighbor {}, interface address {}",
        nbr.ident.router_id,
        nbr.ident.prefix.addr()
    )
    .unwrap();

    // Line 2: Area, interface name, local IP.
    writeln!(
        out,
        "    In the area {} via interface {} local interface IP {}",
        oi.area_id,
        oi.name,
        oi.ident.prefix.addr()
    )
    .unwrap();

    // Line 3: Priority, state/role, state changes.
    let role = nbr_role(
        &nbr.ident.prefix.addr(),
        &oi.ident.d_router,
        &oi.ident.bd_router,
    );
    writeln!(
        out,
        "    Neighbor priority is {}, State is {}/{}, Role is {}, {} state changes",
        nbr.ident.priority, nbr.state, role, role, nbr.state_change
    )
    .unwrap();

    // Line 4: LSA retransmissions.
    writeln!(out, "    {} LSA retransmissions", nbr.ls_rxmt.len()).unwrap();

    // Lines 5-7: State change statistics (only if we have data).
    if nbr.last_progressive.is_some() || nbr.last_regressive.is_some() {
        writeln!(out, "    Most recent state change statistics:").unwrap();
        if let Some(ref progressive) = nbr.last_progressive {
            let elapsed = progressive.elapsed();
            writeln!(
                out,
                "      Progressive change {} ago",
                format_uptime(elapsed)
            )
            .unwrap();
        }
        if let Some(ref regressive) = nbr.last_regressive {
            let elapsed = regressive.elapsed();
            let reason = nbr
                .last_regressive_reason
                .map(|e| format!(", due to {}", e))
                .unwrap_or_default();
            writeln!(
                out,
                "      Regressive change {} ago{}",
                format_uptime(elapsed),
                reason
            )
            .unwrap();
        }
    }

    // Line 8: DR and BDR.
    let dr_rid = find_router_id_by_addr(oi, oi.ident.d_router);
    let bdr_rid = find_router_id_by_addr(oi, oi.ident.bd_router);
    writeln!(out, "    DR is {}, BDR is {}", dr_rid, bdr_rid).unwrap();

    // Line 9: Options.
    writeln!(out, "    Options {}", format_options(&nbr.options)).unwrap();

    // Line 10: Dead timer.
    match nbr.timer.inactivity {
        Some(ref timer) => {
            let remaining = timer.remaining();
            writeln!(out, "    Dead timer due in {:.3}s", remaining.as_secs_f64()).unwrap();
        }
        None => {
            writeln!(out, "    Dead timer due in -").unwrap();
        }
    }

    // Line 11-13: List counts.
    writeln!(out, "    Database Summary List {}", nbr.db_sum.len()).unwrap();
    writeln!(out, "    Link State Request List {}", nbr.ls_req.len()).unwrap();
    writeln!(
        out,
        "    Link State Retransmission List {}",
        nbr.ls_rxmt.len()
    )
    .unwrap();

    // Blank line between neighbors.
    writeln!(out).unwrap();
}

fn show_ospf_neighbor_detail(
    ospf: &Ospf,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    if json {
        let mut nbrs_json: Vec<OspfNeighborDetailJson> = Vec::new();
        for (_, oi) in ospf.links.iter() {
            if !oi.enabled {
                continue;
            }
            for (_, nbr) in oi.nbrs.iter() {
                let role = nbr_role(
                    &nbr.ident.prefix.addr(),
                    &oi.ident.d_router,
                    &oi.ident.bd_router,
                )
                .to_string();
                let dr_rid = find_router_id_by_addr(oi, oi.ident.d_router);
                let bdr_rid = find_router_id_by_addr(oi, oi.ident.bd_router);
                let dead_timer = match nbr.timer.inactivity {
                    Some(ref timer) => {
                        format!("{:.3}s", timer.remaining().as_secs_f64())
                    }
                    None => "-".to_string(),
                };
                let last_progressive_change = nbr
                    .last_progressive
                    .as_ref()
                    .map(|t| format_uptime(t.elapsed()));
                let last_regressive_change = nbr
                    .last_regressive
                    .as_ref()
                    .map(|t| format_uptime(t.elapsed()));
                let last_regressive_reason = nbr.last_regressive_reason.map(|e| format!("{}", e));
                nbrs_json.push(OspfNeighborDetailJson {
                    neighbor_id: nbr.ident.router_id.to_string(),
                    interface_address: nbr.ident.prefix.addr().to_string(),
                    area: oi.area_id.to_string(),
                    interface: oi.name.clone(),
                    local_interface_ip: oi.ident.prefix.addr().to_string(),
                    priority: nbr.ident.priority,
                    state: format!("{}/{}", nbr.state, role),
                    role: role.clone(),
                    state_changes: nbr.state_change,
                    lsa_retransmissions: nbr.ls_rxmt.len(),
                    last_progressive_change,
                    last_regressive_change,
                    last_regressive_reason,
                    dr: dr_rid.to_string(),
                    bdr: bdr_rid.to_string(),
                    options: format_options(&nbr.options),
                    dead_timer,
                    db_summary_list: nbr.db_sum.len(),
                    ls_request_list: nbr.ls_req.len(),
                    ls_retransmission_list: nbr.ls_rxmt.len(),
                });
            }
        }
        return Ok(serde_json::to_string_pretty(&nbrs_json)
            .unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e)));
    }

    let mut buf = String::new();

    for (_, oi) in ospf.links.iter() {
        if !oi.enabled {
            continue;
        }
        for (_, nbr) in oi.nbrs.iter() {
            render_nbr_detail(&mut buf, oi, nbr);
        }
    }
    Ok(buf)
}

fn show_ospf_database(
    ospf: &Ospf,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    if json {
        if ospf.router_id.is_unspecified() {
            return Ok(serde_json::to_string_pretty(
                &serde_json::json!({"error": "OSPF router ID is not specified"}),
            )
            .unwrap_or_default());
        }
        let mut areas = Vec::new();
        if let Some(area) = ospf.areas.get(AREA0) {
            let mut router_lsas = Vec::new();
            for ((lsa_id, adv_router), lsa) in area.lsdb.iter_by_type(OspfLsType::Router) {
                let link_count = if let OspfLsp::Router(ref lsp) = lsa.data.lsp {
                    Some(lsp.links.len())
                } else {
                    None
                };
                router_lsas.push(OspfLsaSummaryJson {
                    link_id: lsa_id.to_string(),
                    adv_router: adv_router.to_string(),
                    age: lsa.current_age(),
                    seq_number: format!("0x{:08x}", lsa.ls_seq_number()),
                    checksum: format!("0x{:04x}", lsa.ls_checksum()),
                    link_count,
                });
            }
            let mut network_lsas = Vec::new();
            for ((lsa_id, adv_router), lsa) in area.lsdb.iter_by_type(OspfLsType::Network) {
                network_lsas.push(OspfLsaSummaryJson {
                    link_id: lsa_id.to_string(),
                    adv_router: adv_router.to_string(),
                    age: lsa.current_age(),
                    seq_number: format!("0x{:08x}", lsa.ls_seq_number()),
                    checksum: format!("0x{:04x}", lsa.ls_checksum()),
                    link_count: None,
                });
            }
            let mut opaque_area_lsas = Vec::new();
            for ((lsa_id, adv_router), lsa) in area.lsdb.iter_by_type(OspfLsType::OpaqueAreaLocal) {
                opaque_area_lsas.push(OspfLsaSummaryJson {
                    link_id: lsa_id.to_string(),
                    adv_router: adv_router.to_string(),
                    age: lsa.current_age(),
                    seq_number: format!("0x{:08x}", lsa.ls_seq_number()),
                    checksum: format!("0x{:04x}", lsa.ls_checksum()),
                    link_count: None,
                });
            }
            areas.push(OspfAreaDatabaseJson {
                area_id: area.id.to_string(),
                router_lsas,
                network_lsas,
                opaque_area_lsas,
            });
        }
        let db = OspfDatabaseJson {
            router_id: ospf.router_id.to_string(),
            areas,
        };
        return Ok(serde_json::to_string_pretty(&db)
            .unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e)));
    }

    let mut out = String::new();

    if ospf.router_id.is_unspecified() {
        return Ok(String::from("OSPF router ID is not sepcified"));
    }

    let _ = writeln!(out);
    writeln!(out, "       OSPF Router with ID ({})", ospf.router_id)?;
    let _ = writeln!(out);

    if let Some(area) = ospf.areas.get(AREA0) {
        writeln!(out, "Router Link States (Area {})", area.id)?;
        let _ = writeln!(out);

        let mut header = true;
        for ((lsa_id, adv_router), lsa) in area.lsdb.iter_by_type(OspfLsType::Router) {
            if header {
                header = false;
                writeln!(
                    out,
                    "Link ID         ADV Router      Age  Seq#       CkSum  Link count  Hold"
                )?;
            }
            let OspfLsp::Router(ref lsp) = lsa.data.lsp else {
                continue;
            };
            let _ = writeln!(
                out,
                "{:15} {:15} {:4} 0x{:08x} 0x{:04x} {:10}  {}",
                lsa_id,
                adv_router,
                lsa.current_age(),
                lsa.ls_seq_number(),
                lsa.ls_checksum(),
                lsp.links.len(),
                fmt_hold(lsa),
            );
        }

        writeln!(out)?;
        writeln!(out, "Net Link States (Area {})", area.id)?;
        writeln!(out)?;

        let mut header = true;
        for ((lsa_id, adv_router), lsa) in area.lsdb.iter_by_type(OspfLsType::Network) {
            if header {
                header = false;
                writeln!(
                    out,
                    "Link ID         ADV Router      Age  Seq#       CkSum   Hold"
                )?;
            }
            let _ = writeln!(
                out,
                "{:15} {:15} {:4} 0x{:08x} 0x{:04x}  {}",
                lsa_id,
                adv_router,
                lsa.current_age(),
                lsa.ls_seq_number(),
                lsa.ls_checksum(),
                fmt_hold(lsa),
            );
        }

        let mut opaque_iter = area
            .lsdb
            .iter_by_type(OspfLsType::OpaqueAreaLocal)
            .peekable();
        if opaque_iter.peek().is_some() {
            writeln!(out)?;
            writeln!(
                out,
                "                Area-Local Opaque-LSA (Area {})",
                area.id
            )?;
            writeln!(out)?;
            writeln!(
                out,
                "Opaque-Type/Id  ADV Router      Age  Seq#       CkSum   Hold"
            )?;
            for ((lsa_id, adv_router), lsa) in opaque_iter {
                let _ = writeln!(
                    out,
                    "{:15} {:15} {:4} 0x{:08x} 0x{:04x}  {}",
                    lsa_id,
                    adv_router,
                    lsa.current_age(),
                    lsa.ls_seq_number(),
                    lsa.ls_checksum(),
                    fmt_hold(lsa),
                );
            }
        }
    }

    Ok(out)
}

fn show_ospf_database_detail(
    ospf: &Ospf,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    if json {
        if ospf.router_id.is_unspecified() {
            return Ok(serde_json::to_string_pretty(
                &serde_json::json!({"error": "OSPF router ID is not specified"}),
            )
            .unwrap_or_default());
        }
        let mut areas = Vec::new();
        if let Some(area) = ospf.areas.get(AREA0) {
            let mut router_lsas = Vec::new();
            for ((_lsa_id, _adv_router), lsa) in area.lsdb.iter_by_type(OspfLsType::Router) {
                let opts = OspfOptions::from(lsa.data.h.options);
                let OspfLsp::Router(ref lsp) = lsa.data.lsp else {
                    continue;
                };
                let links: Vec<OspfRouterLinkDetailJson> = lsp
                    .links
                    .iter()
                    .map(|link| {
                        let link_type = match link.link_type {
                            OspfLinkType::P2p => "Point-to-Point",
                            OspfLinkType::Transit => "Transit Network",
                            OspfLinkType::Stub => "Stub Network",
                            OspfLinkType::VirtualLink => "Virtual Link",
                        }
                        .to_string();
                        OspfRouterLinkDetailJson {
                            link_type,
                            link_id: link.link_id.to_string(),
                            link_data: link.link_data.to_string(),
                            num_tos: link.num_tos,
                            tos_0_metric: link.tos_0_metric,
                        }
                    })
                    .collect();
                router_lsas.push(OspfRouterLsaDetailJson {
                    ls_age: lsa.current_age(),
                    options: format_options_flags(&opts),
                    link_state_id: lsa.data.h.ls_id.to_string(),
                    advertising_router: lsa.adv_router().to_string(),
                    ls_seq_number: format!("0x{:08x}", lsa.ls_seq_number()),
                    checksum: format!("0x{:04x}", lsa.ls_checksum()),
                    length: lsa.length(),
                    num_links: lsp.links.len(),
                    links,
                });
            }
            let mut network_lsas = Vec::new();
            for ((_lsa_id, _adv_router), lsa) in area.lsdb.iter_by_type(OspfLsType::Network) {
                let opts = OspfOptions::from(lsa.data.h.options);
                let OspfLsp::Network(ref lsp) = lsa.data.lsp else {
                    continue;
                };
                let attached_routers: Vec<String> =
                    lsp.attached_routers.iter().map(|r| r.to_string()).collect();
                network_lsas.push(OspfNetworkLsaDetailJson {
                    ls_age: lsa.current_age(),
                    options: format_options_flags(&opts),
                    link_state_id: lsa.data.h.ls_id.to_string(),
                    advertising_router: lsa.adv_router().to_string(),
                    ls_seq_number: format!("0x{:08x}", lsa.ls_seq_number()),
                    checksum: format!("0x{:04x}", lsa.ls_checksum()),
                    length: lsa.length(),
                    network_mask: format!("/{}", u32::from(lsp.netmask).leading_ones()),
                    attached_routers,
                });
            }
            areas.push(OspfAreaDatabaseDetailJson {
                area_id: area.id.to_string(),
                router_lsas,
                network_lsas,
            });
        }
        let db = OspfDatabaseDetailJson {
            router_id: ospf.router_id.to_string(),
            areas,
        };
        return Ok(serde_json::to_string_pretty(&db)
            .unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e)));
    }

    let mut out = String::new();

    if ospf.router_id.is_unspecified() {
        return Ok(String::from("OSPF router ID is not specified"));
    }

    writeln!(out)?;
    writeln!(out, "       OSPF Router with ID ({})", ospf.router_id)?;
    writeln!(out)?;

    if let Some(area) = ospf.areas.get(AREA0) {
        writeln!(out, "                Router Link States (Area {})", area.id)?;
        writeln!(out)?;

        for ((lsa_id, adv_router), lsa) in area.lsdb.iter_by_type(OspfLsType::Router) {
            writeln!(out, "  LS age: {}", lsa.current_age())?;
            let opts = OspfOptions::from(lsa.data.h.options);
            writeln!(
                out,
                "  Options: 0x{:x}  : {}",
                lsa.data.h.options,
                format_options_flags(&opts)
            )?;
            writeln!(out, "  LS Type: Router Links")?;
            writeln!(out, "  Link State ID: {}", lsa_id)?;
            writeln!(out, "  Advertising Router: {}", adv_router)?;
            writeln!(out, "  LS Seq Number: 0x{:08x}", lsa.ls_seq_number())?;
            writeln!(out, "  Checksum: 0x{:04x}", lsa.ls_checksum())?;
            writeln!(out, "  Length: {}", lsa.length())?;
            write_timer_remaining(&mut out, lsa)?;

            let OspfLsp::Router(ref lsp) = lsa.data.lsp else {
                continue;
            };

            writeln!(out, "  Number of Links: {}", lsp.links.len())?;
            writeln!(out)?;

            for link in &lsp.links {
                let link_type_str = match link.link_type {
                    OspfLinkType::P2p => "Point-to-Point",
                    OspfLinkType::Transit => "Transit Network",
                    OspfLinkType::Stub => "Stub Network",
                    OspfLinkType::VirtualLink => "Virtual Link",
                };
                writeln!(out, "    Link connected to: {}", link_type_str)?;
                match link.link_type {
                    OspfLinkType::P2p | OspfLinkType::VirtualLink => {
                        writeln!(
                            out,
                            "     (Link ID) Neighboring Router ID: {}",
                            link.link_id
                        )?;
                        writeln!(
                            out,
                            "     (Link Data) Router Interface address: {}",
                            link.link_data
                        )?;
                    }
                    OspfLinkType::Transit => {
                        writeln!(
                            out,
                            "     (Link ID) Designated Router address: {}",
                            link.link_id
                        )?;
                        writeln!(
                            out,
                            "     (Link Data) Router Interface address: {}",
                            link.link_data
                        )?;
                    }
                    OspfLinkType::Stub => {
                        writeln!(
                            out,
                            "     (Link ID) Network/subnet number: {}",
                            link.link_id
                        )?;
                        writeln!(out, "     (Link Data) Network Mask: {}", link.link_data)?;
                    }
                }
                writeln!(out, "      Number of TOS metrics: {}", link.num_tos)?;
                writeln!(out, "       TOS 0 Metric: {}", link.tos_0_metric)?;
                writeln!(out)?;
            }
        }

        writeln!(out, "                Net Link States (Area {})", area.id)?;
        writeln!(out)?;

        for ((lsa_id, adv_router), lsa) in area.lsdb.iter_by_type(OspfLsType::Network) {
            writeln!(out, "  LS age: {}", lsa.current_age())?;
            let opts = OspfOptions::from(lsa.data.h.options);
            writeln!(
                out,
                "  Options: 0x{:x}  : {}",
                lsa.data.h.options,
                format_options_flags(&opts)
            )?;
            writeln!(out, "  LS Type: Network Links")?;
            writeln!(
                out,
                "  Link State ID: {} (address of Designated Router)",
                lsa_id
            )?;
            writeln!(out, "  Advertising Router: {}", adv_router)?;
            writeln!(out, "  LS Seq Number: 0x{:08x}", lsa.ls_seq_number())?;
            writeln!(out, "  Checksum: 0x{:04x}", lsa.ls_checksum())?;
            writeln!(out, "  Length: {}", lsa.length())?;
            write_timer_remaining(&mut out, lsa)?;

            let OspfLsp::Network(ref lsp) = lsa.data.lsp else {
                continue;
            };

            writeln!(
                out,
                "  Network Mask: /{}",
                u32::from(lsp.netmask).leading_ones()
            )?;
            for router in &lsp.attached_routers {
                writeln!(out, "        Attached Router: {}", router)?;
            }
            writeln!(out)?;
        }

        let mut opaque_iter = area
            .lsdb
            .iter_by_type(OspfLsType::OpaqueAreaLocal)
            .peekable();
        if opaque_iter.peek().is_some() {
            writeln!(
                out,
                "                Area-Local Opaque-LSA (Area {})",
                area.id
            )?;
            writeln!(out)?;

            for ((lsa_id, adv_router), lsa) in opaque_iter {
                let octets = lsa_id.octets();
                let opaque_type = octets[0];
                let opaque_id =
                    ((octets[1] as u32) << 16) | ((octets[2] as u32) << 8) | (octets[3] as u32);

                writeln!(out, "  LS age: {}", lsa.current_age())?;
                let opts = OspfOptions::from(lsa.data.h.options);
                writeln!(
                    out,
                    "  Options: 0x{:x}  : {}",
                    lsa.data.h.options,
                    format_options_flags(&opts)
                )?;
                let opaque_type_name = match opaque_type {
                    4 => "Router Information LSA",
                    7 => "Extended Prefix LSA",
                    8 => "Extended Link LSA",
                    _ => "Unknown",
                };
                writeln!(
                    out,
                    "  LS Type: Area-Local Opaque-LSA (Opaque Type {})",
                    opaque_type
                )?;
                writeln!(out, "  Opaque-Type {} ({})", opaque_type, opaque_type_name)?;
                writeln!(out, "  Opaque-ID   0x{:x}", opaque_id)?;
                writeln!(out, "  Advertising Router: {}", adv_router)?;
                writeln!(out, "  LS Seq Number: 0x{:08x}", lsa.ls_seq_number())?;
                writeln!(out, "  Checksum: 0x{:04x}", lsa.ls_checksum())?;
                writeln!(out, "  Length: {}", lsa.length())?;
                write_timer_remaining(&mut out, lsa)?;

                let payload_len = lsa.length().saturating_sub(20);
                writeln!(out, "  Opaque-Info: {} octets of data", payload_len)?;

                match &lsa.data.lsp {
                    OspfLsp::OpaqueAreaRouterInfo(ri) => {
                        show_router_info_detail(&mut out, ri)?;
                    }
                    OspfLsp::OpaqueAreaExtPrefix(ep) => {
                        show_ext_prefix_detail(&mut out, ep)?;
                    }
                    OspfLsp::OpaqueAreaExtLink(el) => {
                        show_ext_link_detail(&mut out, el)?;
                    }
                    _ => {}
                }
                writeln!(out)?;
            }
        }
    }

    Ok(out)
}

/// Brief-format hold-remaining cell. For self-originated entries
/// the refresh-remaining is appended in parentheses, e.g.
/// `3581s (1781s)`. Reads the actual `Timer::remaining()` so a
/// missing or wrong timer surfaces in `show ospf database`
/// rather than being masked by a derived value.
fn fmt_hold(lsa: &super::lsdb::Lsa) -> String {
    let hold = match lsa.hold_remaining() {
        Some(s) => format!("{}s", s),
        None => "-".to_string(),
    };
    if lsa.originated {
        let refresh = match lsa.refresh_remaining() {
            Some(s) => format!("{}s", s),
            None => "-".to_string(),
        };
        format!("{} ({})", hold, refresh)
    } else {
        hold
    }
}

/// Render the actual LSDB timer state for an LSA — hold timer
/// remaining (every entry) and refresh timer remaining (only
/// self-originated entries). Reads `Timer::remaining()` directly
/// so any miscalculation or missing-timer bug surfaces in
/// `show ospf database` instead of being silently masked.
fn write_timer_remaining(
    out: &mut String,
    lsa: &super::lsdb::Lsa,
) -> std::result::Result<(), std::fmt::Error> {
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
    Ok(())
}

fn show_router_info_detail(
    out: &mut String,
    ri: &RouterInfoLsa,
) -> std::result::Result<(), std::fmt::Error> {
    for tlv in &ri.tlvs {
        match tlv {
            RouterInfoTlv::RouterInfo(cap) => {
                writeln!(out, "  Router Capabilities: 0x{:08x}", u32::from(cap.caps))?;
                let bits: [(bool, &str); 6] = [
                    (cap.caps.gr_capable(), "Graceful Restart capable"),
                    (cap.caps.gr_helper(), "Graceful Restart helper"),
                    (cap.caps.stub(), "Stub Router support"),
                    (cap.caps.te(), "Traffic Engineering support"),
                    (cap.caps.p2p_lan(), "Point-to-point over LAN"),
                    (cap.caps.exp(), "Experimental TE"),
                ];
                for (bit, (set, name)) in bits.iter().enumerate() {
                    if *set {
                        writeln!(out, "    Bit {}: {}", bit, name)?;
                    }
                }
            }
            RouterInfoTlv::Algo(algo_tlv) => {
                writeln!(out, "  Segment Routing Algorithm TLV:")?;
                for algo in &algo_tlv.algos {
                    let algo_name = match algo {
                        Algo::Spf => "SPF",
                        Algo::StrictSpf => "Strict SPF",
                        _ => "Unknown",
                    };
                    writeln!(out, "    Algorithm {}: {}", u8::from(*algo), algo_name)?;
                }
            }
            RouterInfoTlv::SidLabelRnage(range) => {
                writeln!(out, "  Segment Routing Global Range TLV:")?;
                writeln!(out, "    Range Size = {}", range.range)?;
                let sid_val = match &range.sid_label {
                    SidLabelTlv::Label(v) => *v,
                    SidLabelTlv::Index(v) => *v,
                };
                writeln!(out, "    SID Label = {}", sid_val)?;
            }
            RouterInfoTlv::LocalBlock(lb) => {
                writeln!(out, "  Segment Routing Local Range TLV:")?;
                writeln!(out, "    Range Size = {}", lb.range)?;
                let sid_val = match &lb.sid_label {
                    SidLabelTlv::Label(v) => *v,
                    SidLabelTlv::Index(v) => *v,
                };
                writeln!(out, "    SID Label = {}", sid_val)?;
            }
            RouterInfoTlv::Fad(fad) => {
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
                        OspfFadSubTlv::ExcludeAg(g) => {
                            writeln!(out, "    Exclude Admin Group = {:08x?}", g.words)?;
                        }
                        OspfFadSubTlv::IncludeAnyAg(g) => {
                            writeln!(out, "    Include-Any Admin Group = {:08x?}", g.words)?;
                        }
                        OspfFadSubTlv::IncludeAllAg(g) => {
                            writeln!(out, "    Include-All Admin Group = {:08x?}", g.words)?;
                        }
                        OspfFadSubTlv::Flags(fl) => {
                            writeln!(out, "    Flags: M-flag = {}", fl.m_flag)?;
                        }
                        OspfFadSubTlv::ExcludeSrlg(s) => {
                            writeln!(out, "    Exclude SRLG = {:?}", s.srlgs)?;
                        }
                        OspfFadSubTlv::Unknown(_) => {}
                    }
                }
            }
            RouterInfoTlv::Unknown(_) => {}
        }
    }
    Ok(())
}

fn show_ext_prefix_detail(
    out: &mut String,
    ep: &ExtPrefixLsa,
) -> std::result::Result<(), std::fmt::Error> {
    for tlv in &ep.tlvs {
        let route_type_name = match tlv.route_type {
            1 => "Intra-Area",
            3 => "Inter-Area",
            5 => "External",
            7 => "NSSA External",
            _ => "Unknown",
        };
        writeln!(
            out,
            "  Extended Prefix TLV: Route Type: {} ({})",
            tlv.route_type, route_type_name
        )?;
        writeln!(out, "    Prefix: {}", tlv.prefix)?;
        writeln!(out, "    AF: {}", tlv.af)?;
        writeln!(out, "    Flags: 0x{:02x}", tlv.flags)?;

        for sub in &tlv.subs {
            match sub {
                ExtPrefixSubTlv::PrefixSid(sid) => {
                    writeln!(out, "    Prefix SID Sub-TLV:")?;
                    writeln!(out, "      Algorithm: {}", sid.algo)?;
                    let sid_val = match &sid.sid {
                        SidLabelTlv::Label(v) => format!("Label: {}", v),
                        SidLabelTlv::Index(v) => format!("Index: {}", v),
                    };
                    writeln!(out, "      SID/Label: {}", sid_val)?;
                    writeln!(out, "      Flags: 0x{:02x}", u8::from(sid.flags))?;
                    writeln!(out, "      MT-ID: {}", sid.mt_id)?;
                }
                ExtPrefixSubTlv::Unknown(u) => {
                    writeln!(out, "    Unknown Sub-TLV: type={} len={}", u.typ, u.len)?;
                }
            }
        }
    }
    Ok(())
}

fn show_ext_link_detail(
    out: &mut String,
    el: &ExtLinkLsa,
) -> std::result::Result<(), std::fmt::Error> {
    for tlv in &el.tlvs {
        let link_type_name = match tlv.link_type {
            1 => "Point-to-Point",
            2 => "Transit Network",
            3 => "Stub Network",
            4 => "Virtual Link",
            _ => "Unknown",
        };
        writeln!(
            out,
            "  Extended Link TLV: Link Type: {} ({})",
            tlv.link_type, link_type_name
        )?;
        writeln!(out, "    Link ID: {}", tlv.link_id)?;
        writeln!(out, "    Link Data: {}", tlv.link_data)?;

        for sub in &tlv.subs {
            match sub {
                ExtLinkSubTlv::AdjSid(adj) => {
                    writeln!(out, "    Adj-SID Sub-TLV:")?;
                    writeln!(out, "      Flags: 0x{:02x}", u8::from(adj.flags))?;
                    writeln!(out, "      MT-ID: {}", adj.mt_id)?;
                    writeln!(out, "      Weight: {}", adj.weight)?;
                    let sid_val = match &adj.sid {
                        SidLabelTlv::Label(v) => format!("Label: {}", v),
                        SidLabelTlv::Index(v) => format!("Index: {}", v),
                    };
                    writeln!(out, "      SID/Label: {}", sid_val)?;
                }
                ExtLinkSubTlv::LanAdjSid(lan) => {
                    writeln!(out, "    LAN Adj-SID Sub-TLV:")?;
                    writeln!(out, "      Flags: 0x{:02x}", u8::from(lan.flags))?;
                    writeln!(out, "      MT-ID: {}", lan.mt_id)?;
                    writeln!(out, "      Weight: {}", lan.weight)?;
                    writeln!(out, "      Neighbor ID: {}", lan.neighbor_id)?;
                    let sid_val = match &lan.sid {
                        SidLabelTlv::Label(v) => format!("Label: {}", v),
                        SidLabelTlv::Index(v) => format!("Index: {}", v),
                    };
                    writeln!(out, "      SID/Label: {}", sid_val)?;
                }
                ExtLinkSubTlv::RemoteItfAddr(addr) => {
                    writeln!(out, "    Remote Interface Address Sub-TLV:")?;
                    writeln!(out, "      Address: {}", addr)?;
                }
                ExtLinkSubTlv::RemoteItfAddrCisco(addr) => {
                    writeln!(
                        out,
                        "    Remote Interface Address Sub-TLV (Cisco experimental):"
                    )?;
                    writeln!(out, "      Address: {}", addr)?;
                }
                ExtLinkSubTlv::Asla(asla) => {
                    writeln!(out, "    Application-Specific Link Attributes Sub-TLV:")?;
                    writeln!(
                        out,
                        "      SABM: {:02x?}{}",
                        asla.sabm,
                        if asla.is_flex_algo() {
                            " (Flex-Algo)"
                        } else {
                            ""
                        }
                    )?;
                    if !asla.udabm.is_empty() {
                        writeln!(out, "      UDABM: {:02x?}", asla.udabm)?;
                    }
                    for sub in &asla.subs {
                        match sub {
                            OspfAslaSubSubTlv::ExtAdminGroup(g) => {
                                writeln!(out, "      Extended Admin Group = {:08x?}", g.words)?;
                            }
                            OspfAslaSubSubTlv::UniLinkDelay(v) => {
                                writeln!(
                                    out,
                                    "      Unidirectional Link Delay: {} usec{}",
                                    v.delay,
                                    if v.anomalous { " (Anomalous)" } else { "" }
                                )?;
                            }
                            OspfAslaSubSubTlv::MinMaxLinkDelay(v) => {
                                writeln!(
                                    out,
                                    "      Min/Max Unidirectional Link Delay: {}/{} usec{}",
                                    v.min_delay,
                                    v.max_delay,
                                    if v.anomalous { " (Anomalous)" } else { "" }
                                )?;
                            }
                            OspfAslaSubSubTlv::DelayVariation(v) => {
                                writeln!(
                                    out,
                                    "      Unidirectional Delay Variation: {} usec",
                                    v.variation
                                )?;
                            }
                            OspfAslaSubSubTlv::LinkLoss(v) => {
                                // RFC 7471 §4.4: value in units of 0.000003 %.
                                writeln!(
                                    out,
                                    "      Unidirectional Link Loss: {:.6} %{}",
                                    v.loss as f64 * 0.000003,
                                    if v.anomalous { " (Anomalous)" } else { "" }
                                )?;
                            }
                            OspfAslaSubSubTlv::Unknown(u) => {
                                writeln!(
                                    out,
                                    "      Unknown Sub-sub-TLV: type={} len={}",
                                    u.typ, u.len
                                )?;
                            }
                        }
                    }
                }
                ExtLinkSubTlv::Unknown(u) => {
                    writeln!(out, "    Unknown Sub-TLV: type={} len={}", u.typ, u.len)?;
                }
            }
        }
    }
    Ok(())
}

#[derive(Serialize)]
struct OspfRouteNexthopJson {
    /// Nexthop address, or `null` for a directly-attached prefix
    /// (the self-attached marker stamped by `attached_nhops`).
    via: Option<String>,
    directly_attached: bool,
    interface: String,
    ifindex: u32,
}

#[derive(Serialize)]
struct OspfRouteJson {
    prefix: String,
    metric: u32,
    path_type: String,
    nexthops: Vec<OspfRouteNexthopJson>,
}

fn show_ospf_route(
    ospf: &Ospf,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    if json {
        let entries: Vec<OspfRouteJson> = ospf
            .rib
            .iter()
            .map(|(prefix, route)| OspfRouteJson {
                prefix: prefix.to_string(),
                metric: route.metric,
                path_type: format!("{:?}", route.path_type),
                nexthops: route
                    .nhops
                    .iter()
                    .map(|(addr, nhop)| {
                        let attached = addr.is_unspecified();
                        OspfRouteNexthopJson {
                            via: (!attached).then(|| addr.to_string()),
                            directly_attached: attached,
                            interface: ospf.ifname(nhop.ifindex),
                            ifindex: nhop.ifindex,
                        }
                    })
                    .collect(),
            })
            .collect();
        return Ok(serde_json::to_string_pretty(&entries)
            .unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e)));
    }
    let mut buf = String::new();

    for (prefix, route) in ospf.rib.iter() {
        let mut shown = false;
        for (addr, nhop) in route.nhops.iter() {
            // let sid = if let Some(sid) = route.sid {
            //     if nhop.adjacency {
            //         format!(", label {} implicit null", sid)
            //     } else {
            //         format!(", label {}", sid)
            //     }
            // } else {
            //     String::from("")
            // };
            let sid = String::from("");
            // UNSPECIFIED nexthop is the self-attached marker stamped by
            // `attached_nhops` in inst.rs; render it FRR-style as
            // "directly attached to <ifname>".
            let via = if addr.is_unspecified() {
                format!("directly attached to {}", ospf.ifname(nhop.ifindex))
            } else {
                format!("via {}, {}", addr, ospf.ifname(nhop.ifindex))
            };
            if !shown {
                writeln!(
                    buf,
                    "{:<20} [{}] {}{}",
                    prefix.to_string(),
                    route.metric,
                    via,
                    sid
                )?;
                shown = true;
            } else {
                writeln!(
                    buf,
                    "                     [{}] {}{}",
                    route.metric, via, sid
                )?;
            }
        }
    }

    Ok(buf)
}

#[derive(Serialize)]
struct SpfFirstHopJson {
    vertex_id: usize,
    link_id: u32,
}

#[derive(Serialize)]
struct SpfPathJson {
    vertex_id: usize,
    cost: u32,
    /// Equal-cost nexthop vertex-id chains to this destination (mirrors
    /// `disp_out`'s non-full view, which lists `path.nexthops`).
    nexthops: Vec<Vec<usize>>,
    first_hop_links: Vec<SpfFirstHopJson>,
}

fn show_ospf_spf(
    ospf: &Ospf,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    if json {
        let entries: Vec<SpfPathJson> = ospf
            .spf_result
            .as_ref()
            .map(|spf| {
                spf.iter()
                    .map(|(vertex, path)| SpfPathJson {
                        vertex_id: *vertex,
                        cost: path.cost,
                        nexthops: path.nexthops.iter().cloned().collect(),
                        first_hop_links: path
                            .first_hop_links
                            .iter()
                            .map(|(vid, link_id)| SpfFirstHopJson {
                                vertex_id: *vid,
                                link_id: *link_id,
                            })
                            .collect(),
                    })
                    .collect()
            })
            .unwrap_or_default();
        return Ok(serde_json::to_string_pretty(&entries)
            .unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e)));
    }
    let mut buf = String::new();
    if let Some(spf) = &ospf.spf_result {
        spf::disp_out(&mut buf, spf, false);
    }
    Ok(buf)
}

/// `show ospf flex-algo` — for each configured Flexible Algorithm
/// (RFC 9350): its local definition plus the FAD-filtered per-algo SPF
/// tree (the routers reachable under that algorithm's constraints).
#[derive(Serialize)]
struct FlexAlgoRouteJson {
    prefix: String,
    metric: u32,
    label: Option<u32>,
    nexthops: Vec<String>,
}

#[derive(Serialize)]
struct FlexAlgoJson {
    algorithm: u8,
    metric_type: String,
    priority: u8,
    advertise_definition: bool,
    include_any: Vec<String>,
    include_all: Vec<String>,
    exclude_any: Vec<String>,
    srlg_exclude: Vec<String>,
    /// Reachable-node count when the per-algo SPF has a result; `None`
    /// when there is no source vertex or it has not run yet (see
    /// `spf_status`).
    spf_reachable_nodes: Option<usize>,
    spf_status: String,
    routes: Vec<FlexAlgoRouteJson>,
}

fn show_ospf_flex_algo(
    ospf: &Ospf,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    use crate::flex_algo::FadMetricType;
    use std::fmt::Write;

    let metric_name = |m: FadMetricType| match m {
        FadMetricType::Igp => "igp",
        FadMetricType::MinUnidirLinkDelay => "min-unidir-link-delay",
        FadMetricType::TeDefault => "te-default",
    };

    if json {
        let mut algos = Vec::new();
        for (algo, entry) in &ospf.flex_algo.config {
            let set_vec =
                |s: &std::collections::BTreeSet<String>| s.iter().cloned().collect::<Vec<_>>();
            let (spf_reachable_nodes, spf_status) = match ospf.spf_flex_algo.get(algo) {
                Some(Some(spf_res)) => (Some(spf_res.len()), "computed"),
                Some(None) => (None, "no-source-vertex"),
                None => (None, "not-computed"),
            };
            let routes = ospf
                .rib_flex_algo
                .get(algo)
                .map(|rib| {
                    rib.iter()
                        .map(|(prefix, route)| FlexAlgoRouteJson {
                            prefix: prefix.to_string(),
                            metric: route.metric,
                            label: route.sid,
                            nexthops: route.nhops.keys().map(|a| a.to_string()).collect(),
                        })
                        .collect()
                })
                .unwrap_or_default();
            algos.push(FlexAlgoJson {
                algorithm: *algo,
                metric_type: metric_name(entry.metric_type.unwrap_or(FadMetricType::Igp))
                    .to_string(),
                priority: entry.priority.unwrap_or(128),
                advertise_definition: entry.advertise_definition.unwrap_or(false),
                include_any: set_vec(&entry.include_any),
                include_all: set_vec(&entry.include_all),
                exclude_any: set_vec(&entry.exclude_any),
                srlg_exclude: set_vec(&entry.srlg_exclude),
                spf_reachable_nodes,
                spf_status: spf_status.to_string(),
                routes,
            });
        }
        return Ok(serde_json::to_string_pretty(&algos)
            .unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e)));
    }

    let mut buf = String::new();
    if ospf.flex_algo.config.is_empty() {
        writeln!(buf, "No Flexible Algorithms configured")?;
        return Ok(buf);
    }

    let names =
        |s: &std::collections::BTreeSet<String>| s.iter().cloned().collect::<Vec<_>>().join(" ");

    for (algo, entry) in &ospf.flex_algo.config {
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

        match ospf.spf_flex_algo.get(algo) {
            Some(Some(spf_res)) => {
                writeln!(buf, "  SPF: {} reachable node(s)", spf_res.len())?;
                spf::disp_out(&mut buf, spf_res, false);
            }
            Some(None) => writeln!(buf, "  SPF: no source vertex in per-algo topology")?,
            None => writeln!(buf, "  SPF: not yet computed")?,
        }

        // Per-algo RIB: prefixes forwardable under this algo (those
        // carrying a per-algo Prefix-SID), with the resolved MPLS label
        // and the per-algo nexthops.
        if let Some(rib) = ospf.rib_flex_algo.get(algo) {
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
                }
            }
        }
        writeln!(buf)?;
    }
    Ok(buf)
}

// JSON structures for OSPF graph.
#[derive(Serialize)]
struct GraphJson {
    pub area: String,
    pub nodes: Vec<GraphNodeJson>,
}

#[derive(Serialize)]
struct GraphNodeJson {
    pub id: usize,
    pub name: String,
    pub links: Vec<GraphLinkJson>,
}

#[derive(Serialize)]
struct GraphLinkJson {
    pub to_id: usize,
    pub to_name: String,
    pub cost: u32,
}

fn format_ospf_graph(graph: &spf::Graph) -> Option<GraphJson> {
    let mut nodes = Vec::new();

    for (id, node) in graph.iter() {
        let mut node_links = Vec::new();
        for link in &node.olinks {
            if let Some(to_node) = graph.get(&link.to) {
                node_links.push(GraphLinkJson {
                    to_id: link.to,
                    to_name: to_node.name.clone(),
                    cost: link.cost,
                });
            }
        }
        nodes.push(GraphNodeJson {
            id: *id,
            name: node.name.clone(),
            links: node_links,
        });
    }

    if nodes.is_empty() {
        None
    } else {
        Some(GraphJson {
            area: "0.0.0.0".to_string(),
            nodes,
        })
    }
}

fn format_algo_list(ri: &RouterInfoLsa) -> String {
    for tlv in &ri.tlvs {
        if let RouterInfoTlv::Algo(a) = tlv {
            let names: Vec<&str> = a
                .algos
                .iter()
                .map(|algo| match algo {
                    Algo::Spf => "SPF",
                    Algo::StrictSpf => "StrictSPF",
                    _ => "Unknown",
                })
                .collect();
            return names.join(", ");
        }
    }
    String::new()
}

#[derive(Serialize)]
struct SrPrefixSidJson {
    prefix: String,
    /// `index` (SRGB-relative) or `label` (absolute).
    sid_type: String,
    sid_value: u32,
    /// Resolved MPLS label pushed for this prefix, when derivable.
    label_operation: Option<u32>,
    interface: String,
    nexthop: Option<String>,
}

#[derive(Serialize)]
struct SrNodeJson {
    router_id: String,
    srgb_start: u32,
    srgb_end: u32,
    srlb_start: Option<u32>,
    srlb_end: Option<u32>,
    algorithms: String,
    prefix_sids: Vec<SrPrefixSidJson>,
}

#[derive(Serialize)]
struct SegmentRoutingJson {
    router_id: String,
    nodes: Vec<SrNodeJson>,
}

fn show_ospf_segment_routing(
    ospf: &Ospf,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    if json {
        let mut nodes = Vec::new();
        for (_, area) in ospf.areas.iter() {
            let lsdb = &area.lsdb;
            for (router_id, label_config) in lsdb.label_map.iter() {
                let algorithms = lsdb
                    .values_by_type(OspfLsType::OpaqueAreaLocal)
                    .find_map(|lsa| {
                        if lsa.adv_router() == *router_id
                            && let OspfLsp::OpaqueAreaRouterInfo(ref ri) = lsa.data.lsp
                        {
                            return Some(format_algo_list(ri));
                        }
                        None
                    })
                    .unwrap_or_default();
                let srgb = &label_config.global;
                let (srlb_start, srlb_end) = match &label_config.local {
                    Some(lb) => (Some(lb.start), Some(lb.end)),
                    None => (None, None),
                };
                let mut prefix_sids = Vec::new();
                for (_, lsa) in lsdb.iter_by_type(OspfLsType::OpaqueAreaLocal) {
                    if lsa.adv_router() != *router_id {
                        continue;
                    }
                    if let OspfLsp::OpaqueAreaExtPrefix(ref ep) = lsa.data.lsp {
                        for tlv in &ep.tlvs {
                            for sub in &tlv.subs {
                                if let ExtPrefixSubTlv::PrefixSid(sid) = sub {
                                    let (sid_type, sid_value, label_operation) = match sid.sid {
                                        SidLabelTlv::Index(idx) => {
                                            ("index", idx, srgb.start.checked_add(idx))
                                        }
                                        SidLabelTlv::Label(label) => ("label", label, Some(label)),
                                    };
                                    let (interface, nexthop) = ospf
                                        .rib
                                        .get(&tlv.prefix)
                                        .and_then(|r| r.nhops.iter().next())
                                        .map(|(addr, nh)| {
                                            let nexthop =
                                                (!addr.is_unspecified()).then(|| addr.to_string());
                                            (ospf.ifname(nh.ifindex), nexthop)
                                        })
                                        .unwrap_or_default();
                                    prefix_sids.push(SrPrefixSidJson {
                                        prefix: tlv.prefix.to_string(),
                                        sid_type: sid_type.to_string(),
                                        sid_value,
                                        label_operation,
                                        interface,
                                        nexthop,
                                    });
                                }
                            }
                        }
                    }
                }
                nodes.push(SrNodeJson {
                    router_id: router_id.to_string(),
                    srgb_start: srgb.start,
                    srgb_end: srgb.end,
                    srlb_start,
                    srlb_end,
                    algorithms,
                    prefix_sids,
                });
            }
        }
        let out = SegmentRoutingJson {
            router_id: ospf.router_id.to_string(),
            nodes,
        };
        return Ok(serde_json::to_string_pretty(&out)
            .unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e)));
    }
    let mut buf = String::new();
    writeln!(buf)?;
    writeln!(
        buf,
        "        OSPF Segment Routing database for ID {}",
        ospf.router_id
    )?;

    for (_, area) in ospf.areas.iter() {
        let lsdb = &area.lsdb;

        for (router_id, label_config) in lsdb.label_map.iter() {
            writeln!(buf)?;
            writeln!(buf)?;

            // Look up Router Info LSA for this router to get algorithm info.
            let algo_str = lsdb
                .values_by_type(OspfLsType::OpaqueAreaLocal)
                .find_map(|lsa| {
                    if lsa.adv_router() == *router_id
                        && let OspfLsp::OpaqueAreaRouterInfo(ref ri) = lsa.data.lsp
                    {
                        return Some(format_algo_list(ri));
                    }
                    None
                })
                .unwrap_or_default();

            let srgb = &label_config.global;
            let srlb_str = if let Some(ref lb) = label_config.local {
                format!("    SRLB: [{}/{}]", lb.start, lb.end - 1)
            } else {
                String::new()
            };

            writeln!(
                buf,
                "SR-Node: {}    SRGB: [{}/{}]{}    Algo.(s): {}",
                router_id, srgb.start, srgb.end, srlb_str, algo_str
            )?;

            writeln!(buf)?;
            writeln!(
                buf,
                "    {:>18}  {:>21}  {:>20}  {:>9}  {:>15}",
                "Prefix or Link", "Node or Adj. SID", "Label Operation", "Interface", "Nexthop"
            )?;
            writeln!(
                buf,
                "{}  {}  {}  {}  {}",
                "-".repeat(18),
                "-".repeat(21),
                "-".repeat(20),
                "-".repeat(9),
                "-".repeat(15)
            )?;

            // Find Extended Prefix LSAs from this router.
            for (_, lsa) in lsdb.iter_by_type(OspfLsType::OpaqueAreaLocal) {
                if lsa.adv_router() != *router_id {
                    continue;
                }
                if let OspfLsp::OpaqueAreaExtPrefix(ref ep) = lsa.data.lsp {
                    for tlv in &ep.tlvs {
                        for sub in &tlv.subs {
                            if let ExtPrefixSubTlv::PrefixSid(sid) = sub {
                                let (sid_str, resolved_label) = match sid.sid {
                                    SidLabelTlv::Index(idx) => (
                                        format!("SR Pfx (idx {})", idx),
                                        srgb.start.checked_add(idx),
                                    ),
                                    SidLabelTlv::Label(label) => {
                                        (format!("SR Pfx (lbl {})", label), Some(label))
                                    }
                                };
                                let label_op = match resolved_label {
                                    Some(label) => format!("Push {}", label),
                                    None => String::new(),
                                };
                                let (iface, nh_addr) = ospf
                                    .rib
                                    .get(&tlv.prefix)
                                    .and_then(|r| r.nhops.iter().next())
                                    .map(|(addr, nh)| {
                                        let nh_str = if addr.is_unspecified() {
                                            String::new()
                                        } else {
                                            addr.to_string()
                                        };
                                        (ospf.ifname(nh.ifindex), nh_str)
                                    })
                                    .unwrap_or_default();
                                writeln!(
                                    buf,
                                    "    {:>14}  {:>21}  {:>20}  {:>9}  {:>15}",
                                    format!("{}", tlv.prefix),
                                    sid_str,
                                    label_op,
                                    iface,
                                    nh_addr
                                )?;
                            }
                        }
                    }
                }
            }
        }
    }

    writeln!(buf)?;
    Ok(buf)
}

fn show_ospf_graph(
    ospf: &Ospf,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    let graph_data = ospf.graph.as_ref().and_then(format_ospf_graph);

    if json {
        match graph_data {
            Some(data) => Ok(serde_json::to_string_pretty(&data)
                .unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e))),
            None => Ok("{}".to_string()),
        }
    } else {
        let Some(data) = graph_data else {
            return Ok(String::from("No OSPF graph data available"));
        };
        let mut buf = String::new();
        writeln!(buf, "\nOSPF Graph (Area {}):", data.area)?;
        writeln!(buf, "\nNodes:")?;
        for node in &data.nodes {
            writeln!(buf, "  {} (id: {})", node.name, node.id)?;
            if !node.links.is_empty() {
                writeln!(buf, "    Links:")?;
                for link in &node.links {
                    writeln!(buf, "      -> {} (cost: {})", link.to_name, link.cost)?;
                }
            }
        }
        Ok(buf)
    }
}

// ---------------------------------------------------------------------
// TI-LFA (RFC 9490) show commands: `show ospf ti-lfa` (graph-level
// per-destination repair lists) and `show ospf repair-list` (the
// repair backups actually stamped onto the installed RIB).
// ---------------------------------------------------------------------

fn label_value_str(label: &crate::rib::Label) -> String {
    match label {
        crate::rib::Label::Implicit(l) => format!("{l} (implicit-null)"),
        crate::rib::Label::Explicit(l) => format!("{l}"),
    }
}

fn ospf_vertex_name(graph: &spf::Graph, id: usize) -> String {
    graph
        .get(&id)
        .map(|v| v.name.clone())
        .unwrap_or_else(|| format!("v{id}"))
}

fn format_ospf_sr_segment(graph: &spf::Graph, seg: &spf::SrSegment) -> String {
    match seg {
        spf::SrSegment::NodeSid(v) => {
            format!("Node-SID {} (vertex {})", ospf_vertex_name(graph, *v), v)
        }
        // OSPF has no LAN pseudonode in the graph, so `via` is always None.
        spf::SrSegment::AdjSid(from, to, _via) => format!(
            "Adj-SID {} -> {} (vertex {} -> {})",
            ospf_vertex_name(graph, *from),
            ospf_vertex_name(graph, *to),
            from,
            to,
        ),
    }
}

#[derive(Serialize)]
struct RepairSegmentJson {
    kind: &'static str,
    value: String,
}

#[derive(Serialize)]
struct RepairRowJson {
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
struct RepairListJson {
    routes: Vec<RepairRowJson>,
}

/// Walk the installed v4 RIB and collect every prefix whose primary
/// nexthop carries a stamped TI-LFA repair backup. One row per
/// (prefix, backed-up nexthop).
fn collect_ospf_repair_rows(ospf: &Ospf) -> Vec<RepairRowJson> {
    let mut rows = Vec::new();
    for (prefix, route) in ospf.rib.iter() {
        for (addr, nhop) in route.nhops.iter() {
            let Some(backup) = nhop.backup.as_ref() else {
                continue;
            };
            let segments = backup
                .labels
                .iter()
                .map(|label| RepairSegmentJson {
                    kind: "sr-mpls",
                    value: label_value_str(label),
                })
                .collect();
            rows.push(RepairRowJson {
                prefix: prefix.to_string(),
                primary_nexthop: addr.to_string(),
                primary_ifindex: nhop.ifindex,
                primary_metric: route.metric,
                repair_nexthop: backup.addr.to_string(),
                repair_ifindex: backup.ifindex,
                repair_metric: route
                    .metric
                    .saturating_add(super::inst::BACKUP_METRIC_OFFSET),
                segments,
            });
        }
    }
    rows
}

/// `show ospf repair-list` — the TI-LFA repair backups installed on
/// the RIB, one line per protected prefix with its primary and repair
/// next-hops and the SR-MPLS repair label stack.
fn show_ospf_repair_list(
    ospf: &Ospf,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    let rows = collect_ospf_repair_rows(ospf);
    if json {
        return Ok(
            serde_json::to_string_pretty(&RepairListJson { routes: rows })
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
        "{:<22} {:<18} {:<18} Segments",
        "Prefix", "Primary via", "Repair via",
    )?;
    for row in &rows {
        let segs: Vec<String> = row.segments.iter().map(|s| s.value.clone()).collect();
        writeln!(
            buf,
            "{:<22} {:<18} {:<18} [{}]",
            row.prefix,
            row.primary_nexthop,
            row.repair_nexthop,
            segs.join(", "),
        )?;
    }
    Ok(buf)
}

/// `show ospf repair-list detail` — same rows as `repair-list`, but
/// expanded with per-segment label breakdown and the egress ifindex /
/// metric of each leg.
fn show_ospf_repair_list_detail(
    ospf: &Ospf,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    let rows = collect_ospf_repair_rows(ospf);
    if json {
        return Ok(
            serde_json::to_string_pretty(&RepairListJson { routes: rows })
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
struct TilfaSegmentJson {
    kind: &'static str,
    description: String,
}

#[derive(Serialize)]
struct TilfaRepairJson {
    first_hop: String,
    first_hop_vertex: usize,
    first_hop_link_id: u32,
    segments: Vec<TilfaSegmentJson>,
}

#[derive(Serialize)]
struct TilfaDestJson {
    destination: String,
    destination_vertex: usize,
    repairs: Vec<TilfaRepairJson>,
}

#[derive(Serialize)]
struct TilfaJson {
    destinations: Vec<TilfaDestJson>,
}

/// `show ospf ti-lfa` — the graph-level per-destination repair
/// paths from the most recent SPF (before RIB stamping), each as a
/// first-hop plus the SR segment list. Useful for confirming the
/// algorithm produced a repair even when label resolution later
/// dropped it (e.g. a peer not advertising the needed Prefix-SID).
fn show_ospf_tilfa(
    ospf: &Ospf,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    let graph = ospf.graph.as_ref();
    let tilfa = ospf.tilfa_result.as_ref();

    if json {
        let destinations = match (graph, tilfa) {
            (Some(g), Some(t)) => t
                .iter()
                .map(|(dest, repairs)| TilfaDestJson {
                    destination: ospf_vertex_name(g, *dest),
                    destination_vertex: *dest,
                    repairs: repairs
                        .iter()
                        .map(|rp| TilfaRepairJson {
                            first_hop: ospf_vertex_name(g, rp.first_hop),
                            first_hop_vertex: rp.first_hop,
                            first_hop_link_id: rp.first_hop_link_id,
                            segments: rp
                                .segs
                                .iter()
                                .map(|seg| TilfaSegmentJson {
                                    kind: match seg {
                                        spf::SrSegment::NodeSid(_) => "node-sid",
                                        spf::SrSegment::AdjSid(..) => "adj-sid",
                                    },
                                    description: format_ospf_sr_segment(g, seg),
                                })
                                .collect(),
                        })
                        .collect(),
                })
                .collect(),
            _ => Vec::new(),
        };
        return Ok(serde_json::to_string_pretty(&TilfaJson { destinations })
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
    writeln!(buf, "OSPF TI-LFA repair paths:")?;
    for (dest, repairs) in tilfa.iter() {
        writeln!(
            buf,
            "  Destination {} (vertex {})",
            ospf_vertex_name(graph, *dest),
            dest,
        )?;
        for (i, rp) in repairs.iter().enumerate() {
            writeln!(
                buf,
                "    [{}] first-hop {} (vertex {}, link_id {})",
                i,
                ospf_vertex_name(graph, rp.first_hop),
                rp.first_hop,
                rp.first_hop_link_id,
            )?;
            if rp.segs.is_empty() {
                writeln!(buf, "        segments: (none — direct repair)")?;
            } else {
                writeln!(buf, "        segments:")?;
                for seg in &rp.segs {
                    writeln!(buf, "          {}", format_ospf_sr_segment(graph, seg))?;
                }
            }
        }
    }
    Ok(buf)
}

/// `show ospf graceful-restart` (RFC 3623 helper status).
/// Renders the instance-wide policy followed by a per-neighbor
/// table of currently-active helper sessions. Plain-text only
/// for now — the JSON shape can land in 2c-iii alongside
/// helper-history.
#[derive(Serialize)]
struct GrHelperJson {
    neighbor_id: String,
    ifindex: u32,
    restart_reason: String,
    grace_period_secs: u32,
    remaining_secs: u32,
}

#[derive(Serialize)]
struct GrRestartingJson {
    grace_period_secs: u32,
    reason: String,
    age_secs: u64,
}

#[derive(Serialize)]
struct GracefulRestartJson {
    helper_enabled: bool,
    max_grace_period_secs: u32,
    strict_lsa_checking: bool,
    drain_time_ms: u32,
    restarting: Option<GrRestartingJson>,
    helpers: Vec<GrHelperJson>,
}

fn show_ospf_graceful_restart(
    ospf: &Ospf,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    let cfg = &ospf.gr_config;
    if json {
        let mut helpers = Vec::new();
        for (ifindex, link) in ospf.links.iter() {
            for nbr in link.nbrs.values() {
                let Some(helper) = nbr.gr_helper.as_ref() else {
                    continue;
                };
                let elapsed = helper.entered_at.elapsed().as_secs() as u32;
                helpers.push(GrHelperJson {
                    neighbor_id: nbr.ident.router_id.to_string(),
                    ifindex: *ifindex,
                    restart_reason: format!("{:?}", helper.reason),
                    grace_period_secs: helper.grace_period,
                    remaining_secs: helper.grace_period.saturating_sub(elapsed),
                });
            }
        }
        let out = GracefulRestartJson {
            helper_enabled: cfg.helper_enabled,
            max_grace_period_secs: cfg.max_grace_period,
            strict_lsa_checking: cfg.helper_strict_lsa_checking,
            drain_time_ms: cfg.drain_time_ms,
            restarting: ospf.restarting.as_ref().map(|state| GrRestartingJson {
                grace_period_secs: state.grace_period,
                reason: format!("{:?}", state.reason),
                age_secs: state.entered_at.elapsed().as_secs(),
            }),
            helpers,
        };
        return Ok(serde_json::to_string_pretty(&out)
            .unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e)));
    }
    let mut buf = String::new();

    writeln!(buf, "Graceful-restart configuration:")?;
    writeln!(buf, "  Helper enabled: {}", cfg.helper_enabled)?;
    writeln!(buf, "  Max grace period: {}s", cfg.max_grace_period)?;
    writeln!(
        buf,
        "  Strict LSA checking: {}",
        cfg.helper_strict_lsa_checking
    )?;
    writeln!(buf, "  Drain time: {}ms", cfg.drain_time_ms)?;
    if let Some(ref state) = ospf.restarting {
        writeln!(
            buf,
            "  Restart staged: grace={}s, reason={:?}, age={:?}",
            state.grace_period,
            state.reason,
            state.entered_at.elapsed()
        )?;
    }
    writeln!(buf)?;

    let mut any = false;
    writeln!(
        buf,
        "{:<15} {:<10} {:<22} {:<14} {:<10}",
        "Neighbor ID", "Interface", "Restart Reason", "Grace Period", "Remaining"
    )?;
    for (ifindex, link) in ospf.links.iter() {
        for nbr in link.nbrs.values() {
            let Some(helper) = nbr.gr_helper.as_ref() else {
                continue;
            };
            any = true;
            let elapsed = helper.entered_at.elapsed().as_secs() as u32;
            let remaining = helper.grace_period.saturating_sub(elapsed);
            writeln!(
                buf,
                "{:<15} {:<10} {:<22} {:<14} {:<10}",
                nbr.ident.router_id.to_string(),
                format!("if{}", ifindex),
                format!("{:?}", helper.reason),
                format!("{}s", helper.grace_period),
                format!("{}s", remaining),
            )?;
        }
    }
    if !any {
        writeln!(buf, "  (no active helpers)")?;
    }
    Ok(buf)
}

/// `show ospf checkpoint` — debug entry for the
/// graceful-restart storage layer. Reads the on-disk checkpoint
/// at the default path and pretty-prints a summary so operators
/// / tests can verify the write side without unpacking CBOR
/// manually.
#[derive(Serialize)]
struct CheckpointNeighborJson {
    router_id: String,
    interface_addr: String,
    was_full: bool,
}

#[derive(Serialize)]
struct CheckpointLinkJson {
    ifindex: u32,
    ifname: String,
    area_id: String,
    neighbors: Vec<CheckpointNeighborJson>,
}

#[derive(Serialize)]
struct CheckpointAreaJson {
    area_id: String,
    area_type: String,
    lsa_count: usize,
}

#[derive(Serialize)]
struct CheckpointAdjSidJson {
    ifindex: u32,
    address: String,
    label: u32,
}

#[derive(Serialize)]
struct CheckpointJson {
    path: String,
    present: bool,
    /// Set only when a read error other than not-found occurred.
    error: Option<String>,
    format_version: Option<u32>,
    written_at: Option<String>,
    grace_period_secs: Option<u32>,
    restart_reason: Option<String>,
    router_id: Option<String>,
    areas: Vec<CheckpointAreaJson>,
    links: Vec<CheckpointLinkJson>,
    adj_sid_labels: Vec<CheckpointAdjSidJson>,
}

fn show_ospf_checkpoint(
    _ospf: &Ospf,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    use super::checkpoint::{OspfCheckpoint, default_path};

    let path = default_path("ospf");

    if json {
        let mut out = CheckpointJson {
            path: path.display().to_string(),
            present: false,
            error: None,
            format_version: None,
            written_at: None,
            grace_period_secs: None,
            restart_reason: None,
            router_id: None,
            areas: Vec::new(),
            links: Vec::new(),
            adj_sid_labels: Vec::new(),
        };
        match OspfCheckpoint::read_from_path(&path) {
            Ok(cp) => {
                out.present = true;
                out.format_version = Some(cp.format_version);
                out.written_at = Some(format!("{:?}", cp.written_at));
                out.grace_period_secs = Some(cp.grace_period_secs);
                out.restart_reason = Some(cp.restart_reason.to_string());
                out.router_id = Some(cp.router_id.to_string());
                out.areas = cp
                    .areas
                    .iter()
                    .map(|area| CheckpointAreaJson {
                        area_id: area.area_id.to_string(),
                        area_type: format!("{:?}", area.area_type_kind),
                        lsa_count: area.lsas.len(),
                    })
                    .collect();
                out.links = cp
                    .links
                    .iter()
                    .map(|link| CheckpointLinkJson {
                        ifindex: link.ifindex,
                        ifname: link.ifname.clone(),
                        area_id: link.area_id.to_string(),
                        neighbors: link
                            .neighbors
                            .iter()
                            .map(|nbr| CheckpointNeighborJson {
                                router_id: nbr.router_id.to_string(),
                                interface_addr: nbr.interface_addr.to_string(),
                                was_full: nbr.was_full,
                            })
                            .collect(),
                    })
                    .collect();
                out.adj_sid_labels = cp
                    .lan_adj_sids
                    .iter()
                    .map(|((ifindex, addr), label)| CheckpointAdjSidJson {
                        ifindex: *ifindex,
                        address: addr.to_string(),
                        label: *label,
                    })
                    .collect();
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => out.error = Some(e.to_string()),
        }
        return Ok(serde_json::to_string_pretty(&out)
            .unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e)));
    }

    let mut buf = String::new();
    writeln!(buf, "Checkpoint path: {}", path.display())?;
    let cp = match OspfCheckpoint::read_from_path(&path) {
        Ok(cp) => cp,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            writeln!(buf, "  (no checkpoint on disk)")?;
            return Ok(buf);
        }
        Err(e) => {
            writeln!(buf, "  read error: {}", e)?;
            return Ok(buf);
        }
    };
    writeln!(buf, "  Format version: {}", cp.format_version)?;
    writeln!(
        buf,
        "  Written at: {:?} (grace period {}s, reason {})",
        cp.written_at, cp.grace_period_secs, cp.restart_reason
    )?;
    writeln!(buf, "  Router-ID: {}", cp.router_id)?;
    writeln!(buf, "  Areas: {}", cp.areas.len())?;
    for area in &cp.areas {
        writeln!(
            buf,
            "    {} (type: {:?}, {} LSAs)",
            area.area_id,
            area.area_type_kind,
            area.lsas.len()
        )?;
    }
    writeln!(buf, "  Links: {}", cp.links.len())?;
    for link in &cp.links {
        writeln!(
            buf,
            "    ifindex {} ({}) area {} — {} neighbor(s)",
            link.ifindex,
            link.ifname,
            link.area_id,
            link.neighbors.len()
        )?;
        for nbr in &link.neighbors {
            writeln!(
                buf,
                "      {} via {} (was_full: {})",
                nbr.router_id, nbr.interface_addr, nbr.was_full
            )?;
        }
    }
    writeln!(buf, "  Adj-SID labels: {}", cp.lan_adj_sids.len())?;
    for ((ifindex, addr), label) in &cp.lan_adj_sids {
        writeln!(buf, "    if{} {} -> label {}", ifindex, addr, label)?;
    }
    Ok(buf)
}
