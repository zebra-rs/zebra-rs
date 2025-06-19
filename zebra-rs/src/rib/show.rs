use ipnet::{Ipv4Net, Ipv6Net};
use serde::Serialize;
use serde_json::Value;

use crate::{
    config::Args,
    rib::{Label, Nexthop},
};

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
    pub mpls_labels: Vec<Value>,
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
                mpls_labels: uni
                    .mpls
                    .iter()
                    .map(|label| match label {
                        Label::Implicit(l) => serde_json::json!({
                            "label": l,
                            "label_type": "implicit"
                        }),
                        Label::Explicit(l) => serde_json::json!({
                            "label": l
                        }),
                    })
                    .collect(),
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
                mpls_labels: uni
                    .mpls
                    .iter()
                    .map(|label| match label {
                        Label::Implicit(l) => serde_json::json!({
                            "label": l,
                            "label_type": "implicit"
                        }),
                        Label::Explicit(l) => serde_json::json!({
                            "label": l
                        }),
                    })
                    .collect(),
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
                mpls_labels: uni
                    .mpls
                    .iter()
                    .map(|label| match label {
                        Label::Implicit(l) => serde_json::json!({
                            "label": l,
                            "label_type": "implicit"
                        }),
                        Label::Explicit(l) => serde_json::json!({
                            "label": l
                        }),
                    })
                    .collect(),
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

// Helper function to convert IPv6 RibEntry to JSON format
fn rib_entry_to_json_v6(rib: &Rib, prefix: &Ipv6Net, e: &RibEntry) -> RouteEntry {
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
                mpls_labels: uni
                    .mpls
                    .iter()
                    .map(|label| match label {
                        Label::Implicit(l) => serde_json::json!({
                            "label": l,
                            "label_type": "implicit"
                        }),
                        Label::Explicit(l) => serde_json::json!({
                            "label": l
                        }),
                    })
                    .collect(),
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
                mpls_labels: uni
                    .mpls
                    .iter()
                    .map(|label| match label {
                        Label::Implicit(l) => serde_json::json!({
                            "label": l,
                            "label_type": "implicit"
                        }),
                        Label::Explicit(l) => serde_json::json!({
                            "label": l
                        }),
                    })
                    .collect(),
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
                mpls_labels: uni
                    .mpls
                    .iter()
                    .map(|label| match label {
                        Label::Implicit(l) => serde_json::json!({
                            "label": l,
                            "label_type": "implicit"
                        }),
                        Label::Explicit(l) => serde_json::json!({
                            "label": l
                        }),
                    })
                    .collect(),
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

static SHOW_IPV6_HEADER: &str = r#"Codes: K - kernel, C - connected, S - static, R - RIP, B - BGP
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
            Nexthop::Link(_ifindex) => {
                writeln!(buf, " via {}", rib.link_name(e.ifindex));
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
                write!(buf, " via {}, {}", uni.addr, rib.link_name(ifindex)).unwrap();
                if !uni.mpls.is_empty() {
                    for mpls in uni.mpls.iter() {
                        match mpls {
                            Label::Implicit(label) => {
                                write!(buf, ", label {} implicit-null", label).unwrap();
                            }
                            Label::Explicit(label) => {
                                write!(buf, ", label {}", label).unwrap();
                            }
                        }
                    }
                }
                writeln!(buf, "").unwrap();
            }
            Nexthop::Multi(multi) => {
                for (i, uni) in multi.nexthops.iter().enumerate() {
                    if i != 0 {
                        buf.push_str(&" ".repeat(offset));
                    }
                    write!(buf, " via {}, {}", uni.addr, rib.link_name(uni.ifindex),).unwrap();
                    if !uni.mpls.is_empty() {
                        for mpls in uni.mpls.iter() {
                            match mpls {
                                Label::Implicit(label) => {
                                    write!(buf, ", label {} implicit-null", label).unwrap();
                                }
                                Label::Explicit(label) => {
                                    write!(buf, ", label {}", label).unwrap();
                                }
                            }
                        }
                    }
                    writeln!(buf, ", weight {}", uni.weight).unwrap();
                }
            }
            Nexthop::List(pro) => {
                for (i, uni) in pro.nexthops.iter().enumerate() {
                    if i != 0 {
                        buf.push_str(&" ".repeat(offset));
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

// IPv6 route entry display function
pub fn rib_entry_show_v6(
    rib: &Rib,
    prefix: &Ipv6Net,
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
            Nexthop::Link(_ifindex) => {
                writeln!(buf, " via {}", rib.link_name(e.ifindex));
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
                write!(buf, " via {}, {}", uni.addr, rib.link_name(ifindex)).unwrap();
                if !uni.mpls.is_empty() {
                    for mpls in uni.mpls.iter() {
                        match mpls {
                            Label::Implicit(label) => {
                                write!(buf, ", label {} implicit-null", label).unwrap();
                            }
                            Label::Explicit(label) => {
                                write!(buf, ", label {}", label).unwrap();
                            }
                        }
                    }
                }
                writeln!(buf, "").unwrap();
            }
            Nexthop::Multi(multi) => {
                for (i, uni) in multi.nexthops.iter().enumerate() {
                    if i != 0 {
                        buf.push_str(&" ".repeat(offset));
                    }
                    write!(buf, " via {}, {}", uni.addr, rib.link_name(uni.ifindex),).unwrap();
                    if !uni.mpls.is_empty() {
                        for mpls in uni.mpls.iter() {
                            match mpls {
                                Label::Implicit(label) => {
                                    write!(buf, ", label {} implicit-null", label).unwrap();
                                }
                                Label::Explicit(label) => {
                                    write!(buf, ", label {}", label).unwrap();
                                }
                            }
                        }
                    }
                    writeln!(buf, ", weight {}", uni.weight).unwrap();
                }
            }
            Nexthop::List(pro) => {
                for (i, uni) in pro.nexthops.iter().enumerate() {
                    if i != 0 {
                        buf.push_str(&" ".repeat(offset));
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

        for (prefix, entries) in rib.table_v6.iter() {
            for entry in entries.iter() {
                routes.push(rib_entry_to_json_v6(rib, prefix, entry));
            }
        }

        let route_table = RouteTable { routes };
        serde_json::to_string_pretty(&route_table)
            .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialize routes: {}\"}}", e))
    } else {
        let mut buf = String::new();
        buf.push_str(SHOW_IPV6_HEADER);

        for (prefix, entries) in rib.table_v6.iter() {
            for entry in entries.iter() {
                write!(
                    buf,
                    "{}",
                    rib_entry_show_v6(rib, prefix, entry, json).unwrap()
                )
                .unwrap();
            }
        }
        buf
    }
}

// JSON structures for MPLS ILM display
#[derive(Serialize)]
pub struct IlmJson {
    pub local_label: u32,
    pub outgoing_label: String,
    pub prefix_or_id: String,
    pub outgoing_interface: String,
    pub next_hop: String,
}

#[derive(Serialize)]
pub struct IlmTable {
    pub entries: Vec<IlmJson>,
}

pub fn ilm_show(rib: &Rib, _args: Args, json: bool) -> String {
    if json {
        let mut entries = Vec::new();

        for (label, ilm) in rib.ilm.iter() {
            match &ilm.nexthop {
                Nexthop::Uni(uni) => {
                    entries.push(ilm_to_json(rib, *label, ilm, uni));
                }
                Nexthop::Multi(multi) => {
                    for uni in multi.nexthops.iter() {
                        entries.push(ilm_to_json(rib, *label, ilm, uni));
                    }
                }
                _ => {}
            }
        }

        let ilm_table = IlmTable { entries };
        serde_json::to_string_pretty(&ilm_table)
            .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialize ILM: {}\"}}", e))
    } else {
        let mut buf = String::new();

        // Add header
        writeln!(
            buf,
            "Local  Outgoing    Prefix             Outgoing     Next Hop"
        )
        .unwrap();
        writeln!(buf, "Label  Label       or ID              Interface").unwrap();
        writeln!(
            buf,
            "------ ----------- ------------------ ------------ ---------------"
        )
        .unwrap();

        for (label, ilm) in rib.ilm.iter() {
            match &ilm.nexthop {
                Nexthop::Uni(uni) => {
                    write_ilm_entry(&mut buf, rib, *label, ilm, uni);
                }
                Nexthop::Multi(multi) => {
                    for uni in multi.nexthops.iter() {
                        write_ilm_entry(&mut buf, rib, *label, ilm, uni);
                    }
                }
                _ => {}
            }
        }

        buf
    }
}

// Helper function to format an ILM entry
fn write_ilm_entry(
    buf: &mut String,
    rib: &Rib,
    label: u32,
    ilm: &super::inst::IlmEntry,
    uni: &super::NexthopUni,
) {
    let local_label = format!("{:<6}", label);

    // Determine outgoing label
    let outgoing_label = if uni.addr.is_unspecified() && uni.ifindex == 0 {
        format!("{:<11}", "Aggregate")
    } else if uni.mpls_label.is_empty() {
        format!("{:<11}", "Pop")
    } else if uni.mpls_label.len() == 1 && uni.mpls_label[0] == label {
        format!("{:<11}", label)
    } else {
        format!("{:<11}", uni.mpls_label[0])
    };

    // Determine prefix or ID based on IlmType
    let prefix_or_id = match &ilm.ilm_type {
        super::inst::IlmType::Node(idx) => format!("SR Pfx (idx {:<3})", idx),
        super::inst::IlmType::Adjacency(idx) => format!("SR Adj (idx {:<3})", idx),
        super::inst::IlmType::None => {
            // Try to find a matching route for this nexthop
            if let Some((prefix, _)) = find_route_for_nexthop(rib, uni) {
                prefix.to_string()
            } else {
                "Unknown".to_string()
            }
        }
    };

    let interface = if uni.addr.is_unspecified() && uni.ifindex == 0 {
        "default".to_string()
    } else {
        rib.link_name(uni.ifindex)
    };

    let next_hop = if uni.addr.is_unspecified() {
        String::new()
    } else {
        uni.addr.to_string()
    };

    writeln!(
        buf,
        "{} {} {:<18} {:<12} {}",
        local_label, outgoing_label, prefix_or_id, interface, next_hop
    )
    .unwrap();
}

// Helper function to convert ILM entry to JSON
fn ilm_to_json(
    rib: &Rib,
    label: u32,
    ilm: &super::inst::IlmEntry,
    uni: &super::NexthopUni,
) -> IlmJson {
    let outgoing_label = if uni.addr.is_unspecified() && uni.ifindex == 0 {
        "Aggregate".to_string()
    } else if uni.mpls_label.is_empty() {
        "Pop".to_string()
    } else if uni.mpls_label.len() == 1 && uni.mpls_label[0] == label {
        label.to_string()
    } else {
        uni.mpls_label[0].to_string()
    };

    let prefix_or_id = match &ilm.ilm_type {
        super::inst::IlmType::Node(idx) => format!("SR Pfx (idx {})", idx),
        super::inst::IlmType::Adjacency(idx) => format!("SR Adj (idx {})", idx),
        super::inst::IlmType::None => {
            if let Some((prefix, _)) = find_route_for_nexthop(rib, uni) {
                prefix.to_string()
            } else {
                "Unknown".to_string()
            }
        }
    };

    let outgoing_interface = if uni.addr.is_unspecified() && uni.ifindex == 0 {
        "default".to_string()
    } else {
        rib.link_name(uni.ifindex)
    };

    let next_hop = if uni.addr.is_unspecified() {
        String::new()
    } else {
        uni.addr.to_string()
    };

    IlmJson {
        local_label: label,
        outgoing_label,
        prefix_or_id,
        outgoing_interface,
        next_hop,
    }
}

// Helper function to find a route that uses this nexthop
fn find_route_for_nexthop<'a>(
    rib: &'a Rib,
    target_uni: &super::NexthopUni,
) -> Option<(&'a Ipv4Net, &'a RibEntry)> {
    for (prefix, entries) in rib.table.iter() {
        for entry in entries.iter() {
            match &entry.nexthop {
                Nexthop::Uni(uni) if uni.addr == target_uni.addr => {
                    return Some((prefix, entry));
                }
                Nexthop::Multi(multi) => {
                    for uni in &multi.nexthops {
                        if uni.addr == target_uni.addr {
                            return Some((prefix, entry));
                        }
                    }
                }
                _ => {}
            }
        }
    }
    None
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
