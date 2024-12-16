use std::{fmt::Write, net::Ipv4Addr};

use crate::config::Args;

use super::{neigh::OspfNeighbor, Ospf, OspfLink, ShowCallback};

impl Ospf {
    fn show_add(&mut self, path: &str, cb: ShowCallback) {
        self.show_cb.insert(path.to_string(), cb);
    }

    pub fn show_build(&mut self) {
        self.show_add("/show/ip/ospf", show_ospf);
        self.show_add("/show/ip/ospf/interface", show_ospf_interface);
        self.show_add("/show/ip/ospf/neighbor", show_ospf_neighbor);
        self.show_add("/show/ip/opsf/database", show_ospf_database);
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

fn show_ospf_interface(ospf: &Ospf, args: Args, _json: bool) -> String {
    let mut buf = String::new();

    for (_, oi) in ospf.links.iter() {
        if oi.enabled {
            render_link(&mut buf, oi);
        }
    }
    buf
}

fn show_ospf(ospf: &Ospf, args: Args, _json: bool) -> String {
    String::from("show ospf")
}

fn render_nbr(out: &mut String, router_id: &Ipv4Addr, nbr: &OspfNeighbor) {
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

fn show_ospf_neighbor(ospf: &Ospf, args: Args, _json: bool) -> String {
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

fn show_ospf_database(ospf: &Ospf, args: Args, _json: bool) -> String {
    String::from("show ospf database")
}
