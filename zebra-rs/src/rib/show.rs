use ipnet::{Ipv4Net, Ipv6Net};
use serde::Serialize;
use serde_json::Value;

use crate::{
    config::Args,
    rib::{Label, Nexthop, nexthop::NexthopMember, nexthop::NexthopUni},
};

use super::{Group, Rib, entry::RibEntry, inst::ShowCallback, link::link_show, nexthop_show};
use std::fmt::Write;
use std::net::IpAddr;
use std::time::Duration;

/// Format a route's age the way `show ip route` lines render it:
/// `HH:MM:SS` for sub-day, `Nd Nh Nm` for ≥ 24 hours. Matches the
/// quagga / FRR convention operators are used to.
fn format_uptime(d: Duration) -> String {
    let secs = d.as_secs();
    let days = secs / 86_400;
    let hours = (secs % 86_400) / 3_600;
    let minutes = (secs % 3_600) / 60;
    let seconds = secs % 60;
    if days > 0 {
        format!("{days}d{hours}h{minutes}m")
    } else {
        format!("{hours:02}:{minutes:02}:{seconds:02}")
    }
}

// Column widths for `show segment-routing srv6 sid`. Sized to fit the
// example output in the design doc (longest realistic SID, "End.X",
// "Interface 'enp0s7'", "isis(0)", a typical locator name, "explicit").
// IPv6 addresses can in principle stretch up to 39 chars; the format
// strings use `width$` so a wider value just shifts the next column
// rather than truncating.
const SID_COL: usize = 18;
const BEHAVIOR_COL: usize = 11;
const CONTEXT_COL: usize = 21;
const OWNER_COL: usize = 18;
const LOCATOR_COL: usize = 10;
const ALLOC_COL: usize = 16;

// "via" word prefix in show output. SRv6-encapsulated nexthops surface as
// "via seg6 <segments>" to match the iproute2 / FRR convention; plain
// nexthops keep the bare "via".
fn via_word(uni: &NexthopUni) -> &'static str {
    if uni.segs.is_empty() {
        "via"
    } else {
        "via seg6"
    }
}

// Render the address that follows the "via" word. SRv6 nexthops always
// surface their segment list inside square brackets (matching iproute2's
// `encap seg6 ... segs N [ ... ]` shape), even for a single segment, so the
// operator can tell at a glance which routes are policy-encapsulated.
// Non-SRv6 nexthops render the bare address.
fn via_addr(uni: &NexthopUni) -> String {
    if uni.segs.is_empty() {
        uni.addr.to_string()
    } else {
        let parts: Vec<String> = uni.segs.iter().map(|s| s.to_string()).collect();
        format!("[{}]", parts.join(", "))
    }
}

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
    /// True when this nexthop is a backup entry inside a
    /// `Nexthop::List`: anything in the list beyond the first
    /// member (the primary at the lowest metric) is a TI-LFA-style
    /// repair path. Omitted from JSON when false so non-FRR routes
    /// keep their pre-flag schema.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub backup: bool,
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
                backup: false,
            }]
        }
        Nexthop::Uni(uni) => {
            let grp = rib.nmap.get(uni.gid);
            // Prefer the group's view (post-resolution) but fall back
            // to the NexthopUni's own accessor when no group is around
            // — both honor origin over resolved.
            let ifindex: u32 = if let Some(Group::Uni(grp)) = grp {
                grp.ifindex().unwrap_or(0)
            } else {
                uni.ifindex().unwrap_or(0)
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
                backup: false,
            }]
        }
        Nexthop::Multi(multi) => multi
            .nexthops
            .iter()
            .map(|uni| NexthopJson {
                address: Some(uni.addr.to_string()),
                interface: rib.link_name(uni.ifindex().unwrap_or(0)),
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
                backup: false,
            })
            .collect(),
        Nexthop::List(pro) => pro
            .nexthops
            .iter()
            .enumerate()
            .flat_map(|(idx, member)| {
                let is_backup = idx > 0;
                let unis: Vec<&NexthopUni> = match member {
                    NexthopMember::Uni(u) => vec![u],
                    NexthopMember::Multi(m) => m.nexthops.iter().collect(),
                };
                unis.into_iter().map(move |uni| NexthopJson {
                    address: Some(uni.addr.to_string()),
                    interface: rib.link_name(uni.ifindex().unwrap_or(0)),
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
                    backup: is_backup,
                })
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
                backup: false,
            }]
        }
        Nexthop::Uni(uni) => {
            let grp = rib.nmap.get(uni.gid);
            // Prefer the group's view (post-resolution) but fall back
            // to the NexthopUni's own accessor when no group is around
            // — both honor origin over resolved.
            let ifindex: u32 = if let Some(Group::Uni(grp)) = grp {
                grp.ifindex().unwrap_or(0)
            } else {
                uni.ifindex().unwrap_or(0)
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
                backup: false,
            }]
        }
        Nexthop::Multi(multi) => multi
            .nexthops
            .iter()
            .map(|uni| NexthopJson {
                address: Some(uni.addr.to_string()),
                interface: rib.link_name(uni.ifindex().unwrap_or(0)),
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
                backup: false,
            })
            .collect(),
        Nexthop::List(pro) => pro
            .nexthops
            .iter()
            .enumerate()
            .flat_map(|(idx, member)| {
                let is_backup = idx > 0;
                let unis: Vec<&NexthopUni> = match member {
                    NexthopMember::Uni(u) => vec![u],
                    NexthopMember::Multi(m) => m.nexthops.iter().collect(),
                };
                unis.into_iter().map(move |uni| NexthopJson {
                    address: Some(uni.addr.to_string()),
                    interface: rib.link_name(uni.ifindex().unwrap_or(0)),
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
                    backup: is_backup,
                })
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
    let uptime = format_uptime(e.time.elapsed());

    if e.is_connected() {
        writeln!(
            buf,
            " is directly connected, {}, {}",
            rib.link_name(e.ifindex),
            uptime,
        )
        .unwrap();
    } else {
        match &e.nexthop {
            Nexthop::Link(_ifindex) => {
                let _ = writeln!(buf, " via {}, {}", rib.link_name(e.ifindex), uptime);
            }
            Nexthop::Uni(uni) => {
                let grp = rib.nmap.get(uni.gid);

                let ifindex: u32 = if let Some(Group::Uni(grp)) = grp {
                    grp.ifindex().unwrap_or(0)
                } else {
                    uni.ifindex().unwrap_or(0)
                };
                write!(
                    buf,
                    " {} {}, {}",
                    via_word(uni),
                    via_addr(uni),
                    rib.link_name(ifindex)
                )
                .unwrap();
                if !uni.mpls.is_empty() {
                    write!(buf, ", label").unwrap();
                    for mpls in uni.mpls.iter() {
                        match mpls {
                            Label::Implicit(label) => {
                                write!(buf, " {} (implicit-null)", label).unwrap();
                            }
                            Label::Explicit(label) => {
                                write!(buf, " {}", label).unwrap();
                            }
                        }
                    }
                }
                // Single nexthop — `weight` is an ECMP-only column,
                // so we omit it here. Multi prints it per leg below.
                writeln!(buf, ", {}", uptime).unwrap();
            }
            Nexthop::Multi(multi) => {
                for (i, uni) in multi.nexthops.iter().enumerate() {
                    if i != 0 {
                        buf.push_str(&" ".repeat(offset));
                    }
                    write!(
                        buf,
                        " {} {}, {}",
                        via_word(uni),
                        via_addr(uni),
                        rib.link_name(uni.ifindex().unwrap_or(0)),
                    )
                    .unwrap();
                    if !uni.mpls.is_empty() {
                        write!(buf, ", label").unwrap();
                        for mpls in uni.mpls.iter() {
                            match mpls {
                                Label::Implicit(label) => {
                                    write!(buf, " {} implicit-null", label).unwrap();
                                }
                                Label::Explicit(label) => {
                                    write!(buf, " {}", label).unwrap();
                                }
                            }
                        }
                    }
                    // ECMP — weight per leg, then the route's age.
                    writeln!(buf, ", weight {}, {}", uni.weight, uptime).unwrap();
                }
            }
            Nexthop::List(pro) => {
                // Walk members so we can distinguish primaries (first
                // member, idx == 0) from TI-LFA backups (idx > 0).
                let mut row = 0;
                for (member_idx, member) in pro.nexthops.iter().enumerate() {
                    let is_backup = member_idx > 0;
                    let unis: Vec<&NexthopUni> = match member {
                        NexthopMember::Uni(u) => vec![u],
                        NexthopMember::Multi(m) => m.nexthops.iter().collect(),
                    };
                    for uni in unis {
                        if row != 0 {
                            buf.push_str(&" ".repeat(offset));
                        }
                        row += 1;
                        write!(
                            buf,
                            " {} {}, {}, metric {}",
                            via_word(uni),
                            via_addr(uni),
                            rib.link_name(uni.ifindex().unwrap_or(0)),
                            uni.metric,
                        )
                        .unwrap();
                        if !uni.mpls.is_empty() {
                            write!(buf, ", label").unwrap();
                            for mpls in uni.mpls.iter() {
                                match mpls {
                                    Label::Implicit(label) => {
                                        write!(buf, " {} implicit-null", label).unwrap();
                                    }
                                    Label::Explicit(label) => {
                                        write!(buf, " {}", label).unwrap();
                                    }
                                }
                            }
                        }
                        if is_backup {
                            write!(buf, ", backup").unwrap();
                        }
                        writeln!(buf, ", {}", uptime).unwrap();
                    }
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
    let uptime = format_uptime(e.time.elapsed());

    if e.is_connected() {
        writeln!(
            buf,
            " is directly connected, {}, {}",
            rib.link_name(e.ifindex),
            uptime,
        )
        .unwrap();
    } else {
        match &e.nexthop {
            Nexthop::Link(_ifindex) => {
                let _ = writeln!(buf, " via {}, {}", rib.link_name(e.ifindex), uptime);
            }
            Nexthop::Uni(uni) => {
                let grp = rib.nmap.get(uni.gid);

                let ifindex: u32 = if let Some(Group::Uni(grp)) = grp {
                    grp.ifindex().unwrap_or(0)
                } else {
                    uni.ifindex().unwrap_or(0)
                };

                if let Some(action) = uni.seg6local_action {
                    // SRv6 SID install. End / uN have no via address —
                    // they're "directly connected" to the dummy device
                    // that hosts the seg6local action. End.X / uA also
                    // print as "directly connected" but trail with the
                    // adjacency's link-local address as `nh6 ...` and
                    // repeat the egress link, matching FRR.
                    let iface = rib.link_name(ifindex);
                    write!(
                        buf,
                        " is directly connected, {}, seg6local {}",
                        iface, action
                    )
                    .unwrap();
                    if let IpAddr::V6(nh6) = uni.addr
                        && !nh6.is_unspecified()
                    {
                        write!(buf, " nh6 {}, {}", nh6, iface).unwrap();
                    }
                    writeln!(buf, ", {}", uptime).unwrap();
                } else {
                    write!(
                        buf,
                        " {} {}, {}",
                        via_word(uni),
                        via_addr(uni),
                        rib.link_name(ifindex)
                    )
                    .unwrap();
                    if !uni.mpls.is_empty() {
                        write!(buf, ", label").unwrap();
                        for mpls in uni.mpls.iter() {
                            match mpls {
                                Label::Implicit(label) => {
                                    write!(buf, " {} implicit-null", label).unwrap();
                                }
                                Label::Explicit(label) => {
                                    write!(buf, " {}", label).unwrap();
                                }
                            }
                        }
                    }
                    // Single nexthop — no `weight` column. ECMP prints it
                    // per leg below.
                    writeln!(buf, ", {}", uptime).unwrap();
                }
            }
            Nexthop::Multi(multi) => {
                for (i, uni) in multi.nexthops.iter().enumerate() {
                    if i != 0 {
                        buf.push_str(&" ".repeat(offset));
                    }
                    write!(
                        buf,
                        " {} {}, {}",
                        via_word(uni),
                        via_addr(uni),
                        rib.link_name(uni.ifindex().unwrap_or(0)),
                    )
                    .unwrap();
                    if !uni.mpls.is_empty() {
                        write!(buf, ", label").unwrap();
                        for mpls in uni.mpls.iter() {
                            match mpls {
                                Label::Implicit(label) => {
                                    write!(buf, " {} implicit-null", label).unwrap();
                                }
                                Label::Explicit(label) => {
                                    write!(buf, " {}", label).unwrap();
                                }
                            }
                        }
                    }
                    writeln!(buf, ", weight {}, {}", uni.weight, uptime).unwrap();
                }
            }
            Nexthop::List(pro) => {
                // Walk members so we can distinguish primaries (first
                // member, idx == 0) from TI-LFA backups (idx > 0).
                let mut row = 0;
                for (member_idx, member) in pro.nexthops.iter().enumerate() {
                    let is_backup = member_idx > 0;
                    let unis: Vec<&NexthopUni> = match member {
                        NexthopMember::Uni(u) => vec![u],
                        NexthopMember::Multi(m) => m.nexthops.iter().collect(),
                    };
                    for uni in unis {
                        if row != 0 {
                            buf.push_str(&" ".repeat(offset));
                        }
                        row += 1;
                        write!(
                            buf,
                            " {} {}, {}, metric {}",
                            via_word(uni),
                            via_addr(uni),
                            rib.link_name(uni.ifindex().unwrap_or(0)),
                            uni.metric,
                        )
                        .unwrap();
                        if !uni.mpls.is_empty() {
                            write!(buf, ", label").unwrap();
                            for mpls in uni.mpls.iter() {
                                match mpls {
                                    Label::Implicit(label) => {
                                        write!(buf, " {} implicit-null", label).unwrap();
                                    }
                                    Label::Explicit(label) => {
                                        write!(buf, " {}", label).unwrap();
                                    }
                                }
                            }
                        }
                        if is_backup {
                            write!(buf, ", backup").unwrap();
                        }
                        writeln!(buf, ", {}", uptime).unwrap();
                    }
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
    let outgoing_label = if uni.addr.is_unspecified() && uni.ifindex().is_none() {
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

    let interface = if uni.addr.is_unspecified() && uni.ifindex().is_none() {
        "default".to_string()
    } else {
        rib.link_name(uni.ifindex().unwrap_or(0))
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
    let outgoing_label = if uni.addr.is_unspecified() && uni.ifindex().is_none() {
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

    let outgoing_interface = if uni.addr.is_unspecified() && uni.ifindex().is_none() {
        "default".to_string()
    } else {
        rib.link_name(uni.ifindex().unwrap_or(0))
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

#[derive(Serialize)]
pub struct MacJson {
    pub vni: u32,
    pub mac: String,
    pub tunnel_endpoint: Option<String>,
    pub flags: String,
    pub seq: u32,
    pub installed: bool,
}

#[derive(Serialize)]
pub struct MacTable {
    pub entries: Vec<MacJson>,
}

pub fn mac_show(rib: &Rib, _args: Args, json: bool) -> String {
    if json {
        let mut entries = Vec::new();

        for ((vni, mac), entry) in rib.mac_table.iter() {
            entries.push(MacJson {
                vni: *vni,
                mac: mac.to_string(),
                tunnel_endpoint: entry.tunnel_endpoint.map(|addr| addr.to_string()),
                flags: format_mac_flags(entry.flags),
                seq: entry.seq,
                installed: entry.installed,
            });
        }

        let mac_table = MacTable { entries };
        serde_json::to_string_pretty(&mac_table)
            .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialize MAC table: {}\"}}", e))
    } else {
        let mut buf = String::new();

        if rib.mac_table.is_empty() {
            writeln!(buf, "No MAC entries").unwrap();
            return buf;
        }

        // Add header
        writeln!(
            buf,
            "VNI    MAC Address       Tunnel Endpoint       Flags Seq    Installed"
        )
        .unwrap();
        writeln!(
            buf,
            "------ ------------------- --------------------- ----- ------ ---------",
        )
        .unwrap();

        for ((vni, mac), entry) in rib.mac_table.iter() {
            let tunnel_endpoint = entry
                .tunnel_endpoint
                .map(|addr| addr.to_string())
                .unwrap_or_else(|| "-".to_string());
            let flags = format_mac_flags(entry.flags);
            let installed = if entry.installed { "Yes" } else { "No" };

            writeln!(
                buf,
                "{:<6} {:<19} {:<21} {:<5} {:<6} {}",
                vni, mac, tunnel_endpoint, flags, entry.seq, installed
            )
            .unwrap();
        }

        buf
    }
}

fn format_mac_flags(flags: u8) -> String {
    let mut flag_str = String::new();
    if (flags & 0x01) != 0 {
        flag_str.push('S'); // Sticky
    }
    if (flags & 0x02) != 0 {
        flag_str.push('G'); // Gateway
    }
    if (flags & 0x04) != 0 {
        flag_str.push('R'); // Router
    }
    if (flags & 0x08) != 0 {
        flag_str.push('Y'); // sYnc
    }
    if flag_str.is_empty() {
        flag_str.push('-');
    }
    flag_str
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
        self.show_add("/show/l2/mac/table", mac_show);
        self.show_add("/show/l2/neighbor", l2_neighbor_show);
        self.show_add("/show/segment-routing/srv6/sid", sid_show);
        self.show_add("/show/vrf", vrf_show);
        self.show_add("/show/hostname", hostname_show);
    }
}

pub fn hostname_show(_rib: &Rib, _args: Args, _json: bool) -> String {
    hostname::get()
        .ok()
        .and_then(|s| s.into_string().ok())
        .filter(|s| !s.is_empty())
        .map(|s| format!("{s}\n"))
        .unwrap_or_else(|| "unknown\n".to_string())
}

pub fn vrf_show(rib: &Rib, _args: Args, _json: bool) -> String {
    let mut buf = String::new();
    writeln!(buf, " {:<24}{:>10}  Members", "Name", "Table-ID").unwrap();
    writeln!(buf, " {:-<24}  {:-<10}  {:-<32}", "", "", "").unwrap();
    for vrf in rib.vrfs.values() {
        let members: Vec<&str> = rib
            .links
            .values()
            .filter(|l| l.master == Some(vrf.ifindex))
            .map(|l| l.name.as_str())
            .collect();
        writeln!(
            buf,
            " {:<24}{:>10}  {}",
            vrf.name,
            vrf.table_id,
            members.join(", ")
        )
        .unwrap();
    }
    buf
}

/// Render the bridge FDB slice of `rib.neighbors` (the AF_BRIDGE entries).
/// Modelled on `bridge fdb show` — one row per (ifindex, mac, vlan)
/// triple, with the resolved interface name and any per-FDB-entry
/// attributes (VLAN, VNI, remote VTEP IP) the kernel supplied. ARP/NDP
/// (AF_INET / AF_INET6) lives in the same map but isn't shown here —
/// `show ip arp` / `show ipv6 neighbor` will surface those separately.
pub fn l2_neighbor_show(rib: &Rib, _args: Args, _json: bool) -> String {
    use super::inst::NeighborKey;
    let mut buf = String::new();
    writeln!(
        buf,
        " {mac:<18} {ifname:<16} {vlan:>5}  {vni:>10}  {dst:<40} {state:<14} {flags:<10}",
        mac = "MAC",
        ifname = "Interface",
        vlan = "VLAN",
        vni = "VNI",
        dst = "Dst",
        state = "State",
        flags = "Flags",
    )
    .unwrap();
    writeln!(
        buf,
        " {:-<18} {:-<16} {:->5}  {:->10}  {:-<40} {:-<14} {:-<10}",
        "", "", "", "", "", "", "",
    )
    .unwrap();
    for (key, nbr) in rib.neighbors.iter() {
        let NeighborKey::Bridge { ifindex, mac, vlan } = key else {
            continue;
        };
        let ifname = rib
            .links
            .get(ifindex)
            .map(|l| l.name.clone())
            .unwrap_or_else(|| format!("if#{ifindex}"));
        let vlan_s = vlan.map(|v| v.to_string()).unwrap_or_else(|| "-".into());
        let vni_s = nbr.vni.map(|v| v.to_string()).unwrap_or_else(|| "-".into());
        let dst_s = nbr.dst.map(|d| d.to_string()).unwrap_or_else(|| "-".into());
        // Format `flags` via `.bits()` rather than Debug so the field
        // counts as a real read for dead-code analysis (CI runs with
        // `-D warnings`); the hex form is also more compact than the
        // bitflags Debug rendering and keeps the column width stable.
        writeln!(
            buf,
            " {:<18} {:<16} {:>5}  {:>10}  {:<40} {:<14?} 0x{:02x}",
            mac.to_string(),
            ifname,
            vlan_s,
            vni_s,
            dst_s,
            nbr.state,
            nbr.flags.bits(),
        )
        .unwrap();
    }
    buf
}

/// Render `show segment-routing srv6 sid`. Always emits the header row
/// (matches FRR-style output where an empty body still tells the
/// operator the command is wired and they're just not allocating any
/// SIDs yet).
pub fn sid_show(rib: &Rib, _args: Args, json: bool) -> String {
    if json {
        let entries: Vec<SidJson> = rib.sids.values().map(SidJson::from).collect();
        return serde_json::to_string_pretty(&SidTable { entries })
            .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialize SIDs: {}\"}}", e));
    }
    sid_show_text(&rib.sids)
}

fn sid_show_text(sids: &std::collections::BTreeMap<std::net::Ipv6Addr, super::Sid>) -> String {
    let mut buf = String::new();
    writeln!(
        buf,
        " {sid:<sid_w$}{behavior:<beh_w$}{context:<ctx_w$}{owner:<own_w$}{loc:<loc_w$}{alloc:<alloc_w$}",
        sid = "SID",
        behavior = "Behavior",
        context = "Context",
        owner = "Daemon/Instance",
        loc = "Locator",
        alloc = "AllocationType",
        sid_w = SID_COL,
        beh_w = BEHAVIOR_COL,
        ctx_w = CONTEXT_COL,
        own_w = OWNER_COL,
        loc_w = LOCATOR_COL,
        alloc_w = ALLOC_COL,
    )
    .unwrap();
    writeln!(
        buf,
        " {sid:-<sid_w$}  {ctx:-<ctx_w$}  {own:-<own_w$}  {loc:-<loc_w$}  {alloc:-<alloc_w$}",
        sid = "",
        ctx = "",
        own = "",
        loc = "",
        alloc = "",
        // Header underlines run SID+Behavior together, then a 2-space
        // gap before each remaining column, matching the design doc
        // sample.
        sid_w = SID_COL + BEHAVIOR_COL - 1,
        ctx_w = CONTEXT_COL - 2,
        own_w = OWNER_COL - 2,
        loc_w = LOCATOR_COL - 2,
        alloc_w = ALLOC_COL,
    )
    .unwrap();
    for sid in sids.values() {
        writeln!(
            buf,
            " {addr:<sid_w$}{behavior:<beh_w$}{context:<ctx_w$}{owner:<own_w$}{loc:<loc_w$}{alloc:<alloc_w$}",
            addr = sid.addr.to_string(),
            behavior = sid.behavior.to_string(),
            context = sid.context.to_string(),
            owner = sid.owner.to_string(),
            loc = sid.locator,
            alloc = sid.allocation_type.to_string(),
            sid_w = SID_COL,
            beh_w = BEHAVIOR_COL,
            ctx_w = CONTEXT_COL,
            own_w = OWNER_COL,
            loc_w = LOCATOR_COL,
            alloc_w = ALLOC_COL,
        )
        .unwrap();
    }
    buf
}

#[derive(Serialize)]
struct SidTable {
    entries: Vec<SidJson>,
}

#[derive(Serialize)]
struct SidJson {
    sid: String,
    behavior: String,
    context: String,
    owner: String,
    locator: String,
    allocation_type: String,
}

impl From<&super::Sid> for SidJson {
    fn from(s: &super::Sid) -> Self {
        Self {
            sid: s.addr.to_string(),
            behavior: s.behavior.to_string(),
            context: s.context.to_string(),
            owner: s.owner.to_string(),
            locator: s.locator.clone(),
            allocation_type: s.allocation_type.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv6Addr};

    fn uni_with_segs(segs: Vec<Ipv6Addr>) -> NexthopUni {
        let addr = segs.first().copied().unwrap_or(Ipv6Addr::UNSPECIFIED);
        NexthopUni {
            addr: IpAddr::V6(addr),
            segs,
            ..Default::default()
        }
    }

    #[test]
    fn format_uptime_sub_day_renders_hh_mm_ss() {
        // Sub-day routes use HH:MM:SS so operators can read elapsed
        // time the same way ip / FRR show it.
        assert_eq!(format_uptime(Duration::from_secs(0)), "00:00:00");
        assert_eq!(format_uptime(Duration::from_secs(59)), "00:00:59");
        assert_eq!(format_uptime(Duration::from_secs(60)), "00:01:00");
        assert_eq!(
            format_uptime(Duration::from_secs(2 * 3600 + 41 * 60 + 3)),
            "02:41:03"
        );
        assert_eq!(format_uptime(Duration::from_secs(86_399)), "23:59:59");
    }

    #[test]
    fn format_uptime_multi_day_renders_dd_hh_mm() {
        // ≥ 24 hours flips to NdNhNm; matches the FRR convention. We
        // drop seconds at this scale because operators don't care.
        assert_eq!(format_uptime(Duration::from_secs(86_400)), "1d0h0m");
        assert_eq!(
            format_uptime(Duration::from_secs(2 * 86_400 + 18 * 3600 + 29 * 60 + 7)),
            "2d18h29m"
        );
    }

    #[test]
    fn via_word_picks_seg6_only_when_segments_present() {
        let plain = NexthopUni::default();
        assert_eq!(via_word(&plain), "via");

        let one = uni_with_segs(vec!["fcbb:bbbb:2:3:2::".parse().unwrap()]);
        assert_eq!(via_word(&one), "via seg6");

        let two = uni_with_segs(vec![
            "fcbb:bbbb:2:3:2::".parse().unwrap(),
            "fcbb:bbbb:2:3:3::".parse().unwrap(),
        ]);
        assert_eq!(via_word(&two), "via seg6");
    }

    #[test]
    fn via_addr_single_segment_renders_bracketed_list() {
        // Even a single-segment policy is rendered as "[seg]" to match the
        // iproute2 "segs 1 [ ... ]" convention and stay consistent with the
        // multi-segment case.
        let one = uni_with_segs(vec!["fcbb:bbbb:2:3:2::".parse().unwrap()]);
        assert_eq!(via_addr(&one), "[fcbb:bbbb:2:3:2::]");
    }

    #[test]
    fn via_addr_multi_segment_renders_bracketed_list() {
        let two = uni_with_segs(vec![
            "fcbb:bbbb:2:3:2::".parse().unwrap(),
            "fcbb:bbbb:2:3:3::".parse().unwrap(),
        ]);
        assert_eq!(via_addr(&two), "[fcbb:bbbb:2:3:2::, fcbb:bbbb:2:3:3::]");

        let three = uni_with_segs(vec![
            "fcbb:bbbb:2:3:2::".parse().unwrap(),
            "fcbb:bbbb:2:3:3::".parse().unwrap(),
            "fcbb:bbbb:2:3:4::".parse().unwrap(),
        ]);
        assert_eq!(
            via_addr(&three),
            "[fcbb:bbbb:2:3:2::, fcbb:bbbb:2:3:3::, fcbb:bbbb:2:3:4::]"
        );
    }

    #[test]
    fn via_addr_no_segments_renders_underlying_addr() {
        let plain = NexthopUni {
            addr: IpAddr::V6("2001:db8::1".parse().unwrap()),
            ..Default::default()
        };
        assert_eq!(via_addr(&plain), "2001:db8::1");
    }

    use super::super::{Sid, SidAllocationType, SidBehavior, SidContext, SidOwner};
    use std::collections::BTreeMap;

    fn sid(addr: &str, behavior: SidBehavior, ctx: SidContext) -> Sid {
        Sid {
            addr: addr.parse().unwrap(),
            behavior,
            context: ctx,
            owner: SidOwner::new("isis", 0),
            locator: "LOC_N1".to_string(),
            allocation_type: SidAllocationType::Dynamic,
            ifindex: 0,
            nh6: None,
            structure: None,
        }
    }

    #[test]
    fn sid_show_empty_emits_header_only() {
        // An empty registry must still produce a header so operators
        // can tell the command is wired and they just aren't allocating
        // anything yet — silence would look like a broken handler.
        let out = sid_show_text(&BTreeMap::new());
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("SID"));
        assert!(lines[0].contains("Behavior"));
        assert!(lines[0].contains("AllocationType"));
        assert!(lines[1].starts_with(" -"));
    }

    #[test]
    fn sid_show_renders_end_and_endx_rows() {
        let mut sids: BTreeMap<Ipv6Addr, Sid> = BTreeMap::new();
        let end = sid("2001:db8:a:2::", SidBehavior::End, SidContext::None);
        let endx = sid(
            "2001:db8:a:2:1::",
            SidBehavior::EndX,
            SidContext::Interface("enp0s7".into()),
        );
        sids.insert(end.addr, end);
        sids.insert(endx.addr, endx);

        let out = sid_show_text(&sids);
        // BTreeMap iterates by key — End sorts before End.X, matching
        // the design-doc example ordering.
        let body: Vec<&str> = out.lines().skip(2).collect();
        assert_eq!(body.len(), 2);
        assert!(
            body[0].contains("2001:db8:a:2::") && body[0].contains("End ") && body[0].contains("-"),
            "End row: {}",
            body[0]
        );
        assert!(
            body[1].contains("2001:db8:a:2:1::")
                && body[1].contains("End.X")
                && body[1].contains("Interface 'enp0s7'"),
            "End.X row: {}",
            body[1]
        );
        for line in &body {
            assert!(line.contains("isis(0)"));
            assert!(line.contains("LOC_N1"));
            assert!(line.contains("dynamic"));
        }
    }

    #[test]
    fn nexthop_json_omits_backup_when_false() {
        // Default (primary) entries shouldn't carry a `backup` key —
        // keeps the schema unchanged for non-FRR routes.
        let nh = NexthopJson {
            address: Some("10.0.0.1".to_string()),
            interface: "eth0".to_string(),
            weight: Some(1),
            metric: Some(20),
            mpls_labels: vec![],
            backup: false,
        };
        let json = serde_json::to_string(&nh).unwrap();
        assert!(
            !json.contains("backup"),
            "primary nhop should not emit backup field: {json}"
        );
    }

    #[test]
    fn nexthop_json_emits_backup_when_true() {
        // TI-LFA repair entries inside Nexthop::List carry backup=true.
        let nh = NexthopJson {
            address: Some("10.0.0.5".to_string()),
            interface: "eth1".to_string(),
            weight: Some(1),
            metric: Some(21),
            mpls_labels: vec![],
            backup: true,
        };
        let json = serde_json::to_string(&nh).unwrap();
        assert!(
            json.contains("\"backup\":true"),
            "expected backup flag: {json}"
        );
    }
}
