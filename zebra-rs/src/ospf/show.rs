use std::fmt::Write;
use std::net::Ipv4Addr;
use std::time::Duration;

use ospf_packet::*;

use crate::config::Args;

use super::{AREA0, Neighbor, NfsmState, Ospf, OspfLink, ShowCallback};

impl Ospf {
    fn show_add(&mut self, path: &str, cb: ShowCallback) {
        self.show_cb.insert(path.to_string(), cb);
    }

    pub fn show_build(&mut self) {
        self.show_add("/show/ip/ospf", show_ospf);
        self.show_add("/show/ip/ospf/interface", show_ospf_interface);
        self.show_add("/show/ip/ospf/neighbor", show_ospf_neighbor);
        self.show_add("/show/ip/ospf/database", show_ospf_database);
        self.show_add("/show/ip/ospf/database/detail", show_ospf_database_detail);
    }
}

fn render_link(out: &mut String, oi: &OspfLink) {
    writeln!(out, "{}", oi.name).unwrap();
    writeln!(
        out,
        " {} {} {} DR: {} BDR: {}",
        oi.ident.prefix, oi.state, oi.ident.priority, oi.ident.bd_router, oi.ident.bd_router
    )
    .unwrap();
    writeln!(
        out,
        "   Timer intervals configured, Hello {}s, Dead {}s, Wait {}s, Retransmit {}s",
        oi.hello_interval(),
        oi.dead_interval(),
        oi.dead_interval(),
        oi.retransmit_interval(),
    )
    .unwrap();
    if let Some(ref hello_timer) = oi.timer.hello {
        let remaining = hello_timer.remaining();
        let secs = remaining.as_secs_f64();
        writeln!(out, "    Hello due in {:.3}s", secs).unwrap();
    }
}

fn show_ospf_interface(
    ospf: &Ospf,
    _args: Args,
    _json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    let mut buf = String::new();

    for (_, oi) in ospf.links.iter() {
        if oi.enabled {
            render_link(&mut buf, oi);
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

#[allow(dead_code)]
fn render_nbr_detail(out: &mut String, _src: &Ipv4Addr, nbr: &Neighbor) {
    writeln!(
        out,
        r#" Neighbor {}, interface address {}
    In the area XX via interface xx local interface IP xx
    Neighbor priority is {}, state is {}
    DR is {} BDR is {}"#,
        nbr.ident.router_id,
        nbr.ident.prefix.addr(),
        nbr.ident.priority,
        nbr.state,
        nbr.ident.d_router,
        nbr.ident.bd_router
    )
    .unwrap();
}

#[allow(dead_code)]
fn show_ospf_neighbor_detail(
    ospf: &Ospf,
    _args: Args,
    _json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    let mut buf = String::new();

    for (_, oi) in ospf.links.iter() {
        if oi.enabled {
            for (src, nbr) in oi.nbrs.iter() {
                render_nbr_detail(&mut buf, src, nbr);
            }
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
