use std::{fmt::Write, net::Ipv4Addr};

use crate::config::Args;

use super::{Neighbor, Ospf, OspfLink, ShowCallback};

impl Ospf {
    fn show_add(&mut self, path: &str, cb: ShowCallback) {
        self.show_cb.insert(path.to_string(), cb);
    }

    pub fn show_build(&mut self) {
        self.show_add("/show/ip/ospf", show_ospf);
        self.show_add("/show/ip/ospf/interface", show_ospf_interface);
        self.show_add("/show/ip/ospf/neighbor", show_ospf_neighbor_detail);
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

fn show_ospf_interface(ospf: &Ospf, _args: Args, _json: bool) -> String {
    let mut buf = String::new();

    for (_, oi) in ospf.links.iter() {
        if oi.enabled {
            render_link(&mut buf, oi);
        }
    }
    buf
}

fn show_ospf(_ospf: &Ospf, _args: Args, _json: bool) -> String {
    String::from("show ospf")
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

fn render_nbr_detail(out: &mut String, src: &Ipv4Addr, nbr: &Neighbor) {
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

fn show_ospf_neighbor_detail(ospf: &Ospf, _args: Args, _json: bool) -> String {
    let mut buf = String::new();

    for (_, oi) in ospf.links.iter() {
        if oi.enabled {
            for (src, nbr) in oi.nbrs.iter() {
                render_nbr_detail(&mut buf, src, nbr);
            }
        }
    }
    buf
}

fn show_ospf_database(_ospf: &Ospf, _args: Args, _json: bool) -> String {
    String::from("show ospf database")
}
