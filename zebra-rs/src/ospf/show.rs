use std::{fmt::Write, net::Ipv4Addr};

use ospf_packet::*;

use crate::config::Args;

use super::{AREA0, Neighbor, Ospf, OspfLink, ShowCallback};

impl Ospf {
    fn show_add(&mut self, path: &str, cb: ShowCallback) {
        self.show_cb.insert(path.to_string(), cb);
    }

    pub fn show_build(&mut self) {
        self.show_add("/show/ip/ospf", show_ospf);
        self.show_add("/show/ip/ospf/interface", show_ospf_interface);
        self.show_add("/show/ip/ospf/neighbor", show_ospf_neighbor_detail);
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

fn render_nbr(out: &mut String, router_id: &Ipv4Addr, nbr: &Neighbor) {
    writeln!(
        out,
        "{} {} {} {} DR: {} BDR: {}",
        router_id,
        nbr.ident.prefix,
        nbr.ident.priority,
        nbr.state,
        nbr.ident.d_router,
        nbr.ident.bd_router
    )
    .unwrap();
}

fn show_ospf_neighbor(ospf: &Ospf, _args: Args, _json: bool) -> String {
    let mut buf = String::new();

    for (_, oi) in ospf.links.iter() {
        if oi.enabled {
            for (router_id, nbr) in oi.nbrs.iter() {
                render_nbr(&mut buf, router_id, nbr);
            }
        }
    }
    buf
}

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
            let OspfLsp::Router(ref lsp) = lsa.lsp else {
                continue;
            };
            writeln!(
                out,
                "{:15} {:15} 0x{:08x} 0x{:04x} {}",
                lsa_id,
                adv_router,
                lsa.h.ls_seq_number,
                lsa.h.ls_checksum,
                lsp.links.len(),
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
            writeln!(out, "  LS age: {}", lsa.h.ls_age)?;
            writeln!(out, "  Options: 0x{:02x}", lsa.h.options)?;
            writeln!(out, "  LS Type: Router Links")?;
            writeln!(out, "  Link State ID: {}", lsa_id)?;
            writeln!(out, "  Advertising Router: {}", adv_router)?;
            writeln!(out, "  LS Seq Number: 0x{:08x}", lsa.h.ls_seq_number)?;
            writeln!(out, "  Checksum: 0x{:04x}", lsa.h.ls_checksum)?;
            writeln!(out, "  Length: {}", lsa.h.length)?;

            let OspfLsp::Router(ref lsp) = lsa.lsp else {
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
    }

    Ok(out)
}
