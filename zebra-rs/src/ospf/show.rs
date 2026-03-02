use std::fmt::Write;
use std::net::Ipv4Addr;
use std::time::Duration;

use netlink_packet_route::link::LinkFlags;
use ospf_packet::*;

use crate::config::Args;
use crate::rib::LinkFlagsExt;

use super::ifsm::IfsmState;
use super::{AREA0, Neighbor, NfsmState, Ospf, OspfLink, ShowCallback};

impl Ospf {
    fn show_add(&mut self, path: &str, cb: ShowCallback) {
        self.show_cb.insert(path.to_string(), cb);
    }

    pub fn show_build(&mut self) {
        self.show_add("/show/ip/ospf", show_ospf);
        self.show_add("/show/ip/ospf/interface", show_ospf_interface);
        self.show_add("/show/ip/ospf/neighbor", show_ospf_neighbor);
        self.show_add("/show/ip/ospf/neighbor/detail", show_ospf_neighbor_detail);
        self.show_add("/show/ip/ospf/database", show_ospf_database);
        self.show_add("/show/ip/ospf/database/detail", show_ospf_database_detail);
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
    if oi.state == IfsmState::DR {
        if let Some(area) = ospf.areas.get(oi.area_id) {
            if let Some(lsa) =
                area.lsdb
                    .lookup_lsa(OspfLsType::Network, oi.ident.prefix.addr(), ospf.router_id)
            {
                writeln!(
                    out,
                    "  Saved Network-LSA sequence number 0x{:08x}",
                    lsa.data.h.ls_seq_number
                )
                .unwrap();
            }
        }
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
    _json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    let mut buf = String::new();

    for (_, oi) in ospf.links.iter() {
        if oi.enabled {
            render_link(&mut buf, oi, ospf);
        }
    }
    Ok(buf)
}

fn show_ospf(
    _ospf: &Ospf,
    _args: Args,
    _json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    Ok(String::from("show ospf"))
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
    _json: bool,
) -> std::result::Result<String, std::fmt::Error> {
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

fn format_options(options: &OspfOptions) -> String {
    let raw = u8::from(*options);
    let dn = if options.dn() { "DN" } else { "*" };
    let o = if options.o() { "O" } else { "-" };
    let dc = if options.demand_circuits() { "DC" } else { "-" };
    let l = if options.lls_data() { "L" } else { "-" };
    let np = if options.nssa() { "N/P" } else { "-" };
    let mc = if options.multicast() { "MC" } else { "-" };
    let e = if options.external() { "E" } else { "-" };
    let mt = if options.multi_toplogy() { "MT" } else { "-" };
    format!(
        "{} {}|{}|{}|{}|{}|{}|{}|{}",
        raw, dn, o, dc, l, np, mc, e, mt
    )
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
    writeln!(out, "    DR is {},     BDR is {}", dr_rid, bdr_rid).unwrap();

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
    _json: bool,
) -> std::result::Result<String, std::fmt::Error> {
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
    _json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    let mut out = String::new();

    if ospf.router_id.is_unspecified() {
        return Ok(String::from("OSPF router ID is not sepcified"));
    }

    writeln!(out, "");
    writeln!(out, "       OSPF Router with ID ({})", ospf.router_id)?;
    writeln!(out, "");

    if let Some(area) = ospf.areas.get(AREA0) {
        writeln!(out, "Router Link States (Area {})", area.id)?;
        writeln!(out, "");

        let mut header = true;
        for ((lsa_id, adv_router), lsa) in area.lsdb.tables.get(&OspfLsType::Router).iter() {
            if header {
                header = false;
                writeln!(
                    out,
                    "Link ID         ADV Router      Age  Seq#       CkSum  Link count"
                )?;
            }
            let OspfLsp::Router(ref lsp) = lsa.data.lsp else {
                continue;
            };
            writeln!(
                out,
                "{:15} {:15} {:4} 0x{:08x} 0x{:04x} {}",
                lsa_id,
                adv_router,
                lsa.current_age(),
                lsa.data.h.ls_seq_number,
                lsa.data.h.ls_checksum,
                lsp.links.len(),
            );
        }

        writeln!(out)?;
        writeln!(out, "Net Link States (Area {})", area.id)?;
        writeln!(out)?;

        let mut header = true;
        for ((lsa_id, adv_router), lsa) in area.lsdb.tables.get(&OspfLsType::Network).iter() {
            if header {
                header = false;
                writeln!(out, "Link ID         ADV Router      Age  Seq#       CkSum")?;
            }
            writeln!(
                out,
                "{:15} {:15} {:4} 0x{:08x} 0x{:04x}",
                lsa_id,
                adv_router,
                lsa.current_age(),
                lsa.data.h.ls_seq_number,
                lsa.data.h.ls_checksum,
            );
        }
    }

    Ok(out)
}

fn show_ospf_database_detail(
    ospf: &Ospf,
    _args: Args,
    _json: bool,
) -> std::result::Result<String, std::fmt::Error> {
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

        for ((lsa_id, adv_router), lsa) in area.lsdb.tables.get(&OspfLsType::Router).iter() {
            writeln!(out, "  LS age: {}", lsa.current_age())?;
            writeln!(out, "  Options: 0x{:02x}", lsa.data.h.options)?;
            writeln!(out, "  LS Type: Router Links")?;
            writeln!(out, "  Link State ID: {}", lsa_id)?;
            writeln!(out, "  Advertising Router: {}", adv_router)?;
            writeln!(out, "  LS Seq Number: 0x{:08x}", lsa.data.h.ls_seq_number)?;
            writeln!(out, "  Checksum: 0x{:04x}", lsa.data.h.ls_checksum)?;
            writeln!(out, "  Length: {}", lsa.data.h.length)?;

            let OspfLsp::Router(ref lsp) = lsa.data.lsp else {
                continue;
            };

            writeln!(out, "  Number of Links: {}", lsp.links.len())?;
            writeln!(out)?;

            for link in &lsp.links {
                let link_type_str = match link.link_type {
                    1 => "Point-to-Point",
                    2 => "Transit Network",
                    3 => "Stub Network",
                    4 => "Virtual Link",
                    _ => "Unknown",
                };
                writeln!(out, "    Link connected to: {}", link_type_str)?;
                match link.link_type {
                    1 => {
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
                    2 => {
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
                    3 => {
                        writeln!(
                            out,
                            "     (Link ID) Network/subnet number: {}",
                            link.link_id
                        )?;
                        writeln!(out, "     (Link Data) Network Mask: {}", link.link_data)?;
                    }
                    4 => {
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
                    _ => {
                        writeln!(out, "     (Link ID) {}", link.link_id)?;
                        writeln!(out, "     (Link Data) {}", link.link_data)?;
                    }
                }
                writeln!(out, "      Number of TOS metrics: {}", link.num_tos)?;
                writeln!(out, "       TOS 0 Metric: {}", link.tos_0_metric)?;
                writeln!(out)?;
            }
        }

        writeln!(out, "                Net Link States (Area {})", area.id)?;
        writeln!(out)?;

        for ((lsa_id, adv_router), lsa) in area.lsdb.tables.get(&OspfLsType::Network).iter() {
            writeln!(out, "  LS age: {}", lsa.current_age())?;
            writeln!(out, "  Options: 0x{:02x}", lsa.data.h.options)?;
            writeln!(out, "  LS Type: Network Links")?;
            writeln!(
                out,
                "  Link State ID: {} (address of Designated Router)",
                lsa_id
            )?;
            writeln!(out, "  Advertising Router: {}", adv_router)?;
            writeln!(out, "  LS Seq Number: 0x{:08x}", lsa.data.h.ls_seq_number)?;
            writeln!(out, "  Checksum: 0x{:04x}", lsa.data.h.ls_checksum)?;
            writeln!(out, "  Length: {}", lsa.data.h.length)?;

            let OspfLsp::Network(ref lsp) = lsa.data.lsp else {
                continue;
            };

            writeln!(
                out,
                "  Network Mask: /{}",
                u32::from(lsp.netmask).leading_ones()
            )?;
            writeln!(out, "        Attached Router: {}", adv_router)?;
            for router in &lsp.attached_routers {
                writeln!(out, "        Attached Router: {}", router)?;
            }
            writeln!(out)?;
        }
    }

    Ok(out)
}
