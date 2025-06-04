use ipnet::Ipv4Net;
use serde::Serialize;

use crate::{config::Args, rib::Nexthop};

use super::{entry::RibEntry, inst::ShowCallback, link::link_show, nexthop_show, Group, Rib};
use std::fmt::Write;

// JSON-serializable structures for route display
#[derive(Serialize)]
pub struct RouteEntry {
    pub prefix: String,
    pub protocol: String,
    pub subtype: String,
    pub selected: bool,
    pub fib: bool,
    pub valid: bool,
    pub distance: u8,
    pub metric: u32,
    pub nexthops: Vec<NexthopJson>,
    pub interface_name: Option<String>,
}

#[derive(Serialize)]
pub struct NexthopJson {
    pub address: Option<String>,
    pub interface: String,
    pub weight: Option<u8>,
    pub metric: Option<u32>,
    pub mpls_labels: Vec<u32>,
}

#[derive(Serialize)]
pub struct RouteTable {
    pub routes: Vec<RouteEntry>,
}

// Helper function to convert RibEntry to JSON format
fn rib_entry_to_json(rib: &Rib, prefix: &Ipv4Net, e: &RibEntry) -> RouteEntry {
    let protocol = format!("{:?}", e.rtype).to_lowercase();
    let subtype = format!("{:?}", e.rsubtype).to_lowercase();

    let nexthops = match &e.nexthop {
        Nexthop::Link(ifindex) => {
            vec![NexthopJson {
                address: None,
                interface: rib.link_name(*ifindex),
                weight: None,
                metric: None,
                mpls_labels: vec![],
            }]
        }
        Nexthop::Uni(uni) => {
            let grp = rib.nmap.get(uni.gid);
            let ifindex: u32 = if let Some(grp) = grp {
                if let Group::Uni(grp) = grp {
                    grp.ifindex
                } else {
                    0
                }
            } else {
                uni.ifindex
            };

            vec![NexthopJson {
                address: Some(uni.addr.to_string()),
                interface: rib.link_name(ifindex),
                weight: Some(uni.weight),
                metric: Some(uni.metric),
                mpls_labels: uni.mpls_label.clone(),
            }]
        }
        Nexthop::Multi(multi) => multi
            .nexthops
            .iter()
            .map(|uni| NexthopJson {
                address: Some(uni.addr.to_string()),
                interface: rib.link_name(uni.ifindex),
                weight: Some(uni.weight),
                metric: Some(uni.metric),
                mpls_labels: uni.mpls_label.clone(),
            })
            .collect(),
        Nexthop::List(pro) => pro
            .nexthops
            .iter()
            .map(|uni| NexthopJson {
                address: Some(uni.addr.to_string()),
                interface: rib.link_name(uni.ifindex),
                weight: Some(uni.weight),
                metric: Some(uni.metric),
                mpls_labels: uni.mpls_label.clone(),
            })
            .collect(),
    };

    let interface_name = if e.is_connected() {
        Some(rib.link_name(e.ifindex))
    } else {
        None
    };

    RouteEntry {
        prefix: prefix.to_string(),
        protocol,
        subtype,
        selected: e.selected,
        fib: e.fib,
        valid: e.valid,
        distance: e.distance,
        metric: e.metric,
        nexthops,
        interface_name,
    }
}

// Rendering.

static SHOW_IPV4_HEADER: &str = r#"Codes: K - kernel, C - connected, S - static, R - RIP, B - BGP
       O - OSPF, IA - OSPF inter area, N1/N2 - OSPF NSSA external type 1/2
       E1/E2 - OSPF external type 1/2 D - DHCP route
       i - IS-IS, L1/L2 - IS-IS level-1/2, ia - IS-IS inter area
       > - selected route, * - FIB route, S - Stale route

"#;

pub fn rib_entry_show(
    rib: &Rib,
    prefix: &Ipv4Net,
    e: &RibEntry,
    _json: bool,
) -> anyhow::Result<String> {
    let mut buf = String::new();

    // All type route.
    write!(
        buf,
        "{} {} {} {}",
        e.rtype.abbrev(),
        e.rsubtype.abbrev(),
        e.selected(),
        prefix,
    )?;

    if !e.is_connected() {
        write!(buf, " [{}/{}]", &e.distance, &e.metric).unwrap();
    }

    let offset = buf.len();

    if e.is_connected() {
        writeln!(buf, " directly connected {}", rib.link_name(e.ifindex)).unwrap();
    } else {
        match &e.nexthop {
            Nexthop::Link(_) => {
                //
            }
            Nexthop::Uni(uni) => {
                let grp = rib.nmap.get(uni.gid);

                let ifindex: u32 = if let Some(grp) = grp {
                    if let Group::Uni(grp) = grp {
                        grp.ifindex
                    } else {
                        0
                    }
                } else {
                    uni.ifindex
                };
                writeln!(buf, " via {}, {}", uni.addr, rib.link_name(ifindex)).unwrap();
            }
            Nexthop::Multi(multi) => {
                for (i, uni) in multi.nexthops.iter().enumerate() {
                    if i != 0 {
                        buf.push_str(&" ".repeat(offset).to_string());
                    }
                    writeln!(
                        buf,
                        " via {}, {}, weight {}",
                        uni.addr,
                        rib.link_name(uni.ifindex),
                        uni.weight
                    )
                    .unwrap();
                }
            }
            Nexthop::List(pro) => {
                for (i, uni) in pro.nexthops.iter().enumerate() {
                    if i != 0 {
                        buf.push_str(&" ".repeat(offset).to_string());
                    }
                    writeln!(
                        buf,
                        " via {}, {}, metric {}",
                        uni.addr,
                        rib.link_name(uni.ifindex),
                        uni.metric
                    )
                    .unwrap();
                }
            }
        }
    }
    Ok(buf)
}

pub fn rib_show(rib: &Rib, _args: Args, json: bool) -> String {
    if json {
        let mut routes = Vec::new();

        for (prefix, entries) in rib.table.iter() {
            for entry in entries.iter() {
                routes.push(rib_entry_to_json(rib, prefix, entry));
            }
        }

        let route_table = RouteTable { routes };
        serde_json::to_string_pretty(&route_table)
            .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialize routes: {}\"}}", e))
    } else {
        let mut buf = String::new();
        buf.push_str(SHOW_IPV4_HEADER);

        for (prefix, entries) in rib.table.iter() {
            for entry in entries.iter() {
                write!(buf, "{}", rib_entry_show(rib, prefix, entry, json).unwrap()).unwrap();
            }
        }
        buf
    }
}

pub fn rib6_show(rib: &Rib, _args: Args, json: bool) -> String {
    if json {
        let mut routes = Vec::new();

        for (prefix, entries) in rib.table.iter() {
            for entry in entries.iter() {
                routes.push(rib_entry_to_json(rib, prefix, entry));
            }
        }

        let route_table = RouteTable { routes };
        serde_json::to_string_pretty(&route_table)
            .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialize routes: {}\"}}", e))
    } else {
        let mut buf = String::new();
        buf.push_str(SHOW_IPV4_HEADER);

        for (prefix, entries) in rib.table.iter() {
            for entry in entries.iter() {
                write!(buf, "{}", rib_entry_show(rib, prefix, entry, json).unwrap()).unwrap();
            }
        }
        buf
    }
}

pub fn ilm_show(rib: &Rib, _args: Args, json: bool) -> String {
    let mut buf = String::new();

    for (label, ilm) in rib.ilm.iter() {
        match &ilm.nexthop {
            Nexthop::Uni(uni) => {
                writeln!(buf, "{:<8} {}", label.to_string(), ilm.nexthop).unwrap();
            }
            Nexthop::Multi(multi) => {
                for uni in multi.nexthops.iter() {
                    writeln!(buf, "{:<8} {}", label.to_string(), ilm.nexthop).unwrap();
                }
            }
            _ => {}
        }
    }
    buf
}

impl Rib {
    fn show_add(&mut self, path: &str, cb: ShowCallback) {
        self.show_cb.insert(path.to_string(), cb);
    }

    pub fn show_build(&mut self) {
        self.show_add("/show/interface", link_show);
        self.show_add("/show/ip/route", rib_show);
        self.show_add("/show/ipv6/route", rib6_show);
        self.show_add("/show/nexthop", nexthop_show);
        self.show_add("/show/mpls/ilm", ilm_show);
    }
}
