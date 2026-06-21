use ipnet::{Ipv4Net, Ipv6Net};
use serde::Serialize;
use serde_json::Value;

use crate::{
    config::{Args, Builder},
    rib::{
        Label, Nexthop,
        nexthop::{NexthopList, NexthopMember, NexthopProtect, NexthopUni},
    },
};

use super::{
    Group, Rib, entry::RibEntry, inst::ShowCallback, link::link_show, nexthop_show,
    types::RibSubType, types::RibType, vrf::Vrf,
};
use std::fmt::Write;
use std::net::IpAddr;
use std::time::Duration;

// Two-char tag column used in `show ip route` lines. When the route has
// a meaningful sub-type (OSPF inter-area, IS-IS L1/L2, …) we show that
// two-letter tag; otherwise we show the protocol letter padded with one
// space so the `*>` FIB-mark column lines up across both forms:
//   `D  *> 0.0.0.0/0 …`
//   `O IA *> 10.0.0.0/24 …`
fn route_tag(rtype: &RibType, rsubtype: &RibSubType) -> String {
    let sub = rsubtype.abbrev();
    if sub.is_empty() {
        format!("{} ", rtype.abbrev())
    } else {
        sub
    }
}

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
    /// True when this nexthop is a repair path: the `backup` member
    /// of a `Nexthop::Protect`, or anything beyond the first member
    /// (the primary at the lowest metric) in a `Nexthop::List`.
    /// Omitted from JSON when false so non-FRR routes keep their
    /// pre-flag schema.
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
    let subtype = e.rsubtype.name();

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
                member
                    .iter_unis()
                    .map(move |uni| nexthop_uni_to_json(rib, uni, is_backup))
            })
            .collect(),
        Nexthop::Protect(pro) => pro
            .roles()
            .into_iter()
            .flat_map(|(member, is_backup)| {
                member
                    .iter_unis()
                    .map(move |uni| nexthop_uni_to_json(rib, uni, is_backup))
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

/// One `NexthopUni` leaf as JSON, with its protection role. Shared by
/// the `Nexthop::List` and `Nexthop::Protect` arms of the IPv4 / IPv6
/// JSON converters.
fn nexthop_uni_to_json(rib: &Rib, uni: &NexthopUni, is_backup: bool) -> NexthopJson {
    NexthopJson {
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
    }
}

// Helper function to convert IPv6 RibEntry to JSON format
fn rib_entry_to_json_v6(rib: &Rib, prefix: &Ipv6Net, e: &RibEntry) -> RouteEntry {
    let protocol = format!("{:?}", e.rtype).to_lowercase();
    let subtype = e.rsubtype.name();

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
                member
                    .iter_unis()
                    .map(move |uni| nexthop_uni_to_json(rib, uni, is_backup))
            })
            .collect(),
        Nexthop::Protect(pro) => pro
            .roles()
            .into_iter()
            .flat_map(|(member, is_backup)| {
                member
                    .iter_unis()
                    .map(move |uni| nexthop_uni_to_json(rib, uni, is_backup))
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

static SHOW_HEADER: &str = r#"Codes: K - kernel, D - DHCP route, C - connected, S - static
       O - OSPF, IA - OSPF inter area, N1/N2 - OSPF NSSA external type 1/2
       E1/E2 - OSPF external type 1/2
       L1/L2 - IS-IS level-1/2, ia - IS-IS inter area, B - BGP
       > - selected route, * - FIB route, S - Stale route, ? - backup route

"#;

pub fn rib_entry_show(
    rib: &Rib,
    prefix: &Ipv4Net,
    e: &RibEntry,
    _json: bool,
) -> anyhow::Result<String> {
    let mut buf = String::new();

    // All type route. Capture the FIB-marker and `[distance/metric]`
    // bracket columns so the `Nexthop::List` arm can align each repair
    // path's own bracket (and `>>` marker) underneath the first line.
    write!(buf, "{} ", route_tag(&e.rtype, &e.rsubtype))?;
    let marker_col = buf.len();
    write!(buf, "{} {}", e.selected(), prefix)?;
    let bracket_col = buf.len() + 1;

    // `Nexthop::List` / `Nexthop::Protect` print a per-path bracket in
    // their own arm (each repair path can carry a different metric),
    // so skip the shared route-level bracket for them.
    if !e.is_connected() && !matches!(e.nexthop, Nexthop::List(_) | Nexthop::Protect(_)) {
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
                write_mpls_labels(&mut buf, uni);
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
                    write_mpls_labels(&mut buf, uni);
                    // ECMP — weight per leg, then the route's age.
                    writeln!(buf, ", weight {}, {}", uni.weight, uptime).unwrap();
                }
            }
            Nexthop::List(pro) => {
                write_nexthop_list(&mut buf, rib, e, pro, marker_col, bracket_col, &uptime);
            }
            Nexthop::Protect(pro) => {
                write_nexthop_protect(&mut buf, rib, e, pro, marker_col, bracket_col, &uptime);
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

    // All type route. Capture the FIB-marker and `[distance/metric]`
    // bracket columns so the `Nexthop::List` arm can align each repair
    // path's own bracket (and `>>` marker) underneath the first line.
    write!(buf, "{} ", route_tag(&e.rtype, &e.rsubtype))?;
    let marker_col = buf.len();
    write!(buf, "{} {}", e.selected(), prefix)?;
    let bracket_col = buf.len() + 1;

    // `Nexthop::List` / `Nexthop::Protect` print a per-path bracket in
    // their own arm (each repair path can carry a different metric),
    // so skip the shared route-level bracket for them.
    if !e.is_connected() && !matches!(e.nexthop, Nexthop::List(_) | Nexthop::Protect(_)) {
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
                    write_mpls_labels(&mut buf, uni);
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
                    write_mpls_labels(&mut buf, uni);
                    writeln!(buf, ", weight {}, {}", uni.weight, uptime).unwrap();
                }
            }
            Nexthop::List(pro) => {
                write_nexthop_list(&mut buf, rib, e, pro, marker_col, bracket_col, &uptime);
            }
            Nexthop::Protect(pro) => {
                write_nexthop_protect(&mut buf, rib, e, pro, marker_col, bracket_col, &uptime);
            }
        }
    }
    Ok(buf)
}

/// Render the `Nexthop::List` arm shared by the IPv4 and IPv6 one-line
/// route views: every member past the first is a backup.
fn write_nexthop_list(
    buf: &mut String,
    rib: &Rib,
    e: &RibEntry,
    pro: &NexthopList,
    marker_col: usize,
    bracket_col: usize,
    uptime: &str,
) {
    let members: Vec<(&NexthopMember, bool)> = pro
        .nexthops
        .iter()
        .enumerate()
        .map(|(idx, m)| (m, idx > 0))
        .collect();
    write_protected_paths(buf, rib, e, &members, marker_col, bracket_col, uptime);
}

/// `Nexthop::Protect` sibling: the roles come off the struct's fields
/// instead of the sort position.
fn write_nexthop_protect(
    buf: &mut String,
    rib: &Rib,
    e: &RibEntry,
    pro: &NexthopProtect,
    marker_col: usize,
    bracket_col: usize,
    uptime: &str,
) {
    write_protected_paths(buf, rib, e, &pro.roles(), marker_col, bracket_col, uptime);
}

/// Render a primary-plus-repair path set in the one-line route views.
/// Each path prints on its own line carrying its own
/// `[distance/metric]` bracket — the metric is per-nexthop, so a TI-LFA
/// repair path can advertise a higher cost than the primary. Backup
/// paths drop the FIB `*>` marker for a `?` repair marker in the same
/// column, e.g.:
///   L2 *> 10.0.0.0/24 [0/100] via 10.211.55.1, enp0s5, 00:04:15
///      *?             [0/1002] via 10.211.55.1, enp0s5, 00:04:15
fn write_protected_paths(
    buf: &mut String,
    rib: &Rib,
    e: &RibEntry,
    members: &[(&NexthopMember, bool)],
    marker_col: usize,
    bracket_col: usize,
    uptime: &str,
) {
    // Backups keep the route's FIB state in the marker column and add a
    // `?` to flag the repair path: `*? ` (FIB) or ` ? ` (not).
    let backup_marker = if e.fib { "*? " } else { " ? " };
    let mut row = 0;
    for (member, is_backup) in members {
        for uni in member.iter_unis() {
            if row == 0 {
                // First path shares the line already carrying the tag,
                // FIB marker and prefix; just append its bracket.
                write!(buf, " [{}/{}]", e.distance, uni.metric).unwrap();
            } else {
                // Continuation path: rebuild the marker and bracket
                // columns so each line shows its own [distance/metric]
                // aligned under the first, with backups marked by `?`.
                let marker = if *is_backup { backup_marker } else { "" };
                buf.push_str(&list_continuation_prefix(
                    marker_col,
                    bracket_col,
                    marker,
                    e.distance,
                    uni.metric,
                ));
            }
            row += 1;
            write!(
                buf,
                " {} {}, {}",
                via_word(uni),
                via_addr(uni),
                rib.link_name(uni.ifindex().unwrap_or(0)),
            )
            .unwrap();
            write_mpls_labels(buf, uni);
            writeln!(buf, ", {}", uptime).unwrap();
        }
    }
}

/// Leading whitespace + repair marker + `[distance/metric]` bracket for a
/// `Nexthop::List` continuation line. `marker` is placed in the FIB-marker
/// column (`*? ` for backups, empty for extra primary ECMP legs) and the
/// bracket is padded to align under the first line's. Kept `Rib`-free so the
/// column math stays unit-testable.
fn list_continuation_prefix(
    marker_col: usize,
    bracket_col: usize,
    marker: &str,
    distance: u8,
    metric: u32,
) -> String {
    let mut s = " ".repeat(marker_col);
    s.push_str(marker);
    s.push_str(&" ".repeat(bracket_col.saturating_sub(marker_col + marker.len())));
    write!(s, "[{}/{}]", distance, metric).unwrap();
    s
}

/// Append the `, label …` suffix describing a nexthop's MPLS label
/// stack to a one-line text route entry. Implicit (implicit-null)
/// labels render parenthesized, explicit labels bare; no-op when the
/// stack is empty. Shared by the IPv4 and IPv6 one-line renderers
/// across their Uni / Multi / List nexthop arms.
fn write_mpls_labels(buf: &mut String, uni: &NexthopUni) {
    if uni.mpls.is_empty() {
        return;
    }
    write!(buf, ", label").unwrap();
    for mpls in uni.mpls.iter() {
        match mpls {
            Label::Implicit(label) => write!(buf, " ({})", label).unwrap(),
            Label::Explicit(label) => write!(buf, " {}", label).unwrap(),
        }
    }
}

/// Render an MPLS label stack in IOS-XR's `{ L1 L2 L3 }` notation.
/// The stack is written in push order (top of stack first), matching
/// the order our `Vec<Label>` already carries (see
/// `repair_segments_to_mpls_labels`). Implicit-null renders as the
/// label number in parentheses; otherwise it's a bare number.
fn fmt_label_stack(labels: &[Label]) -> String {
    let parts: Vec<String> = labels
        .iter()
        .map(|l| match l {
            Label::Implicit(n) => format!("({n})"),
            Label::Explicit(n) => n.to_string(),
        })
        .collect();
    format!("{{ {} }}", parts.join(" "))
}

/// Render an SRv6 segment list in `{ addr, addr }` notation. Always
/// braced for parity with the MPLS form even when there's only one
/// segment.
fn fmt_srv6_segs(segs: &[std::net::Ipv6Addr]) -> String {
    let parts: Vec<String> = segs.iter().map(|a| a.to_string()).collect();
    format!("{{ {} }}", parts.join(", "))
}

/// Protection role for a `Nexthop::List` member at position `idx`.
/// Index 0 is the primary (lowest metric); anything beyond is a
/// TI-LFA-style repair stamped by `make_rib_entry` via the metric-
/// offset convention. Plain `Nexthop::Uni` / `Multi` callers always
/// pass index 0.
fn fmt_protection_role(idx: usize) -> &'static str {
    protection_role(idx > 0)
}

/// Protection role from an explicit backup flag — the `Nexthop::
/// Protect` form, where the role is a field rather than a position.
fn protection_role(is_backup: bool) -> &'static str {
    if is_backup {
        "Backup (TI-LFA)"
    } else {
        "Protected"
    }
}

/// Long-form protocol name for the `Known via "..."` line. IOS-XR
/// uses lowercase tokens here (`"isis 111"` etc.); we drop the
/// instance suffix since zebra-rs doesn't model multiple instances
/// per protocol today.
fn protocol_long_name(t: super::types::RibType) -> &'static str {
    use super::types::RibType;
    match t {
        RibType::Kernel => "kernel",
        RibType::Connected => "connected",
        RibType::Static => "static",
        RibType::Ospf => "ospf",
        RibType::Isis => "isis",
        RibType::Bgp => "bgp",
        RibType::Dhcp => "dhcp",
        RibType::Other(_) => "unknown",
    }
}

/// Long-form subtype tag for the `type ...` suffix on the
/// `Known via` line. Returns `None` for the default subtype (no
/// suffix); otherwise an IOS-XR-style descriptor.
fn subtype_long_name(s: &super::types::RibSubType) -> Option<&'static str> {
    use super::types::RibSubType;
    match s {
        RibSubType::Default => None,
        RibSubType::OspfIa => Some("inter-area"),
        RibSubType::OspfNssa1 => Some("NSSA external type 1"),
        RibSubType::OspfNssa2 => Some("NSSA external type 2"),
        RibSubType::OspfExternal1 => Some("external type 1"),
        RibSubType::OspfExternal2 => Some("external type 2"),
        RibSubType::IsisLevel1 => Some("level-1"),
        RibSubType::IsisLevel2 => Some("level-2"),
        RibSubType::IsisIntraArea => Some("intra-area"),
        RibSubType::Other(_) => None,
    }
}

/// True when any nexthop in `e` carries an MPLS label stack — used
/// to add the `labeled SR` tag to the `Known via` line.
fn entry_has_mpls(e: &RibEntry) -> bool {
    fn uni_has(u: &NexthopUni) -> bool {
        !u.mpls.is_empty()
    }
    match &e.nexthop {
        Nexthop::Uni(u) => uni_has(u),
        Nexthop::Multi(m) => m.nexthops.iter().any(uni_has),
        Nexthop::List(l) => l.nexthops.iter().any(|m| match m {
            NexthopMember::Uni(u) => uni_has(u),
            NexthopMember::Multi(mm) => mm.nexthops.iter().any(uni_has),
        }),
        Nexthop::Protect(p) => p.iter_unis().any(uni_has),
        Nexthop::Link(_) => false,
    }
}

/// True when any nexthop in `e` carries an SRv6 segment list — used
/// to add the `SRv6` tag to the `Known via` line in the v6 view.
fn entry_has_srv6(e: &RibEntry) -> bool {
    fn uni_has(u: &NexthopUni) -> bool {
        !u.segs.is_empty()
    }
    match &e.nexthop {
        Nexthop::Uni(u) => uni_has(u),
        Nexthop::Multi(m) => m.nexthops.iter().any(uni_has),
        Nexthop::List(l) => l.nexthops.iter().any(|m| match m {
            NexthopMember::Uni(u) => uni_has(u),
            NexthopMember::Multi(mm) => mm.nexthops.iter().any(uni_has),
        }),
        Nexthop::Protect(p) => p.iter_unis().any(uni_has),
        Nexthop::Link(_) => false,
    }
}

/// Emit one `Routing Descriptor Block` for an IPv4 nexthop. The
/// `role` field gates the `Repair Node(s)` line — backups print the
/// first MPLS label (the NodeSID of the post-conv P-node); symbolic
/// resolution to hostname/sys-id is the IS-IS-view's job (PR C).
fn write_descriptor_block_v4(buf: &mut String, rib: &Rib, uni: &NexthopUni, role: &str) {
    let iface = rib.link_name(uni.ifindex().unwrap_or(0));
    let _ = writeln!(buf, "    {}, via {}, {}", uni.addr, iface, role);
    let _ = writeln!(
        buf,
        "      Route metric is {}, weight {}",
        uni.metric, uni.weight
    );
    if !uni.mpls.is_empty() {
        let _ = writeln!(buf, "      Labels imposed {}", fmt_label_stack(&uni.mpls));
        if role.starts_with("Backup")
            && let Some(first) = uni.mpls.first()
        {
            let label_n = match first {
                Label::Implicit(n) | Label::Explicit(n) => n,
            };
            let _ = writeln!(buf, "      Repair Node(s): label {label_n}");
        }
    }
}

/// IPv6 sibling: same shape, but with SRv6 segment list + encap mode
/// when present. MPLS labels can still appear on a v6 nexthop (e.g.
/// 6PE) so we render them too.
fn write_descriptor_block_v6(buf: &mut String, rib: &Rib, uni: &NexthopUni, role: &str) {
    let iface = rib.link_name(uni.ifindex().unwrap_or(0));
    let _ = writeln!(buf, "    {}, via {}, {}", uni.addr, iface, role);
    let _ = writeln!(
        buf,
        "      Route metric is {}, weight {}",
        uni.metric, uni.weight
    );
    if !uni.segs.is_empty() {
        let _ = writeln!(buf, "      SID list {}", fmt_srv6_segs(&uni.segs));
        if let Some(encap) = uni.encap_type {
            let _ = writeln!(buf, "      Encap: {:?}", encap);
        }
        if role.starts_with("Backup")
            && let Some(first) = uni.segs.first()
        {
            let _ = writeln!(buf, "      Repair Node(s): SID {first}");
        }
    }
    if !uni.mpls.is_empty() {
        let _ = writeln!(buf, "      Labels imposed {}", fmt_label_stack(&uni.mpls));
        if role.starts_with("Backup")
            && uni.segs.is_empty()
            && let Some(first) = uni.mpls.first()
        {
            let label_n = match first {
                Label::Implicit(n) | Label::Explicit(n) => n,
            };
            let _ = writeln!(buf, "      Repair Node(s): label {label_n}");
        }
    }
}

/// Walk a `Nexthop` and emit one descriptor block per leg. Handles
/// the `List` case so backups get the right role tag.
fn write_nexthop_blocks_v4(buf: &mut String, rib: &Rib, nh: &Nexthop) {
    match nh {
        Nexthop::Link(ifindex) => {
            let _ = writeln!(buf, "    directly attached via {}", rib.link_name(*ifindex));
        }
        Nexthop::Uni(uni) => write_descriptor_block_v4(buf, rib, uni, "Protected"),
        Nexthop::Multi(multi) => {
            for uni in multi.nexthops.iter() {
                write_descriptor_block_v4(buf, rib, uni, "Protected");
            }
        }
        Nexthop::List(list) => {
            for (idx, member) in list.nexthops.iter().enumerate() {
                let role = fmt_protection_role(idx);
                for u in member.iter_unis() {
                    write_descriptor_block_v4(buf, rib, u, role);
                }
            }
        }
        Nexthop::Protect(pro) => {
            for (member, is_backup) in pro.roles() {
                let role = protection_role(is_backup);
                for u in member.iter_unis() {
                    write_descriptor_block_v4(buf, rib, u, role);
                }
            }
        }
    }
}

fn write_nexthop_blocks_v6(buf: &mut String, rib: &Rib, nh: &Nexthop) {
    match nh {
        Nexthop::Link(ifindex) => {
            let _ = writeln!(buf, "    directly attached via {}", rib.link_name(*ifindex));
        }
        Nexthop::Uni(uni) => write_descriptor_block_v6(buf, rib, uni, "Protected"),
        Nexthop::Multi(multi) => {
            for uni in multi.nexthops.iter() {
                write_descriptor_block_v6(buf, rib, uni, "Protected");
            }
        }
        Nexthop::List(list) => {
            for (idx, member) in list.nexthops.iter().enumerate() {
                let role = fmt_protection_role(idx);
                for u in member.iter_unis() {
                    write_descriptor_block_v6(buf, rib, u, role);
                }
            }
        }
        Nexthop::Protect(pro) => {
            for (member, is_backup) in pro.roles() {
                let role = protection_role(is_backup);
                for u in member.iter_unis() {
                    write_descriptor_block_v6(buf, rib, u, role);
                }
            }
        }
    }
}

/// IOS-XR-style detail block for one IPv4 RIB entry.
///
/// ```text
/// Routing entry for 10.1.1.3/32
///   Known via "isis", distance 115, metric 30, labeled SR, type level-2
///   Last update 00:42:11 ago
///   Routing Descriptor Blocks
///     10.0.0.2, via enp0s7, Protected
///       Route metric is 30, weight 0
///       Labels imposed { 17003 }
///     10.0.0.21, via enp0s8, Backup (TI-LFA)
///       Route metric is 50, weight 0
///       Labels imposed { 17010 24001 17003 }
///       Repair Node(s): label 17010
/// ```
pub fn rib_entry_show_detail(rib: &Rib, prefix: &Ipv4Net, e: &RibEntry) -> String {
    let mut buf = String::new();
    let _ = writeln!(buf, "Routing entry for {prefix}");

    let labeled_tag = if entry_has_mpls(e) {
        ", labeled SR"
    } else {
        ""
    };
    let subtype_tag = subtype_long_name(&e.rsubtype)
        .map(|s| format!(", type {s}"))
        .unwrap_or_default();
    let _ = writeln!(
        buf,
        "  Known via \"{}\", distance {}, metric {}{}{}",
        protocol_long_name(e.rtype),
        e.distance,
        e.metric,
        labeled_tag,
        subtype_tag
    );
    let _ = writeln!(buf, "  Last update {} ago", format_uptime(e.time.elapsed()));

    if e.is_connected() {
        let _ = writeln!(buf, "  Directly connected via {}", rib.link_name(e.ifindex));
        return buf;
    }

    let _ = writeln!(buf, "  Routing Descriptor Blocks");
    write_nexthop_blocks_v4(&mut buf, rib, &e.nexthop);
    buf
}

/// IPv6 sibling of `rib_entry_show_detail`. Adds the `SRv6` tag on
/// the `Known via` line when any nexthop carries a segment list.
pub fn rib_entry_show_v6_detail(rib: &Rib, prefix: &Ipv6Net, e: &RibEntry) -> String {
    let mut buf = String::new();
    let _ = writeln!(buf, "Routing entry for {prefix}");

    let mut tags = String::new();
    if entry_has_srv6(e) {
        tags.push_str(", SRv6");
    }
    if entry_has_mpls(e) {
        tags.push_str(", labeled SR");
    }
    let subtype_tag = subtype_long_name(&e.rsubtype)
        .map(|s| format!(", type {s}"))
        .unwrap_or_default();
    let _ = writeln!(
        buf,
        "  Known via \"{}\", distance {}, metric {}{}{}",
        protocol_long_name(e.rtype),
        e.distance,
        e.metric,
        tags,
        subtype_tag
    );
    let _ = writeln!(buf, "  Last update {} ago", format_uptime(e.time.elapsed()));

    if e.is_connected() {
        let _ = writeln!(buf, "  Directly connected via {}", rib.link_name(e.ifindex));
        return buf;
    }

    let _ = writeln!(buf, "  Routing Descriptor Blocks");
    write_nexthop_blocks_v6(&mut buf, rib, &e.nexthop);
    buf
}

pub fn rib_show(rib: &Rib, _args: Args, json: bool) -> String {
    if json {
        let mut routes = Vec::new();

        for (prefix, entries) in rib.table.iter() {
            for entry in entries.iter() {
                routes.push(rib_entry_to_json(rib, &prefix, entry));
            }
        }

        let route_table = RouteTable { routes };
        serde_json::to_string_pretty(&route_table)
            .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialize routes: {}\"}}", e))
    } else {
        let mut buf = String::new();
        buf.push_str(SHOW_HEADER);

        for (prefix, entries) in rib.table.iter() {
            for entry in entries.iter() {
                write!(
                    buf,
                    "{}",
                    rib_entry_show(rib, &prefix, entry, json).unwrap()
                )
                .unwrap();
            }
        }
        buf
    }
}

/// `show ip route detail` — IOS-XR-style routing-descriptor-block
/// view across the whole IPv4 RIB. JSON path is unchanged from the
/// one-line view (`backup` flag on `NexthopJson` already conveys
/// primary/backup); text path emits one block per entry.
pub fn rib_show_detail(rib: &Rib, args: Args, json: bool) -> String {
    if json {
        return rib_show(rib, args, json);
    }
    let mut buf = String::new();
    for (prefix, entries) in rib.table.iter() {
        for entry in entries.iter() {
            buf.push_str(&rib_entry_show_detail(rib, &prefix, entry));
        }
    }
    buf
}

/// `show ip route prefix A.B.C.D/N` — single-prefix filter, one-line
/// layout.
pub fn rib_show_prefix(rib: &Rib, mut args: Args, json: bool) -> String {
    let Some(prefix) = args.v4net() else {
        return "% Invalid IPv4 prefix\n".to_string();
    };
    rib_show_one(rib, &prefix, json, false)
}

/// `show ip route prefix A.B.C.D/N detail` — single-prefix block.
pub fn rib_show_prefix_detail(rib: &Rib, mut args: Args, json: bool) -> String {
    let Some(prefix) = args.v4net() else {
        return "% Invalid IPv4 prefix\n".to_string();
    };
    rib_show_one(rib, &prefix, json, true)
}

fn rib_show_one(rib: &Rib, prefix: &Ipv4Net, json: bool, detail: bool) -> String {
    let Some(entries) = rib.table.get(prefix) else {
        return if json {
            "{\"routes\": []}\n".to_string()
        } else {
            format!("% No route for {prefix}\n")
        };
    };

    if json {
        let routes: Vec<RouteEntry> = entries
            .iter()
            .map(|e| rib_entry_to_json(rib, prefix, e))
            .collect();
        return serde_json::to_string_pretty(&RouteTable { routes })
            .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialize routes: {}\"}}", e));
    }

    let mut buf = String::new();
    if detail {
        for entry in entries.iter() {
            buf.push_str(&rib_entry_show_detail(rib, prefix, entry));
        }
    } else {
        buf.push_str(SHOW_HEADER);
        for entry in entries.iter() {
            let _ = write!(buf, "{}", rib_entry_show(rib, prefix, entry, json).unwrap());
        }
    }
    buf
}

/// Resolve the VRFs a `... route vrf [NAME]` command targets: a single
/// named VRF, or all configured VRFs when no name is given. Returns
/// `Err` with the already-formatted (json/text) response to emit
/// verbatim when the named VRF doesn't exist.
fn vrf_targets<'a>(
    rib: &'a Rib,
    name: &Option<String>,
    json: bool,
) -> Result<Vec<&'a Vrf>, String> {
    if let Some(n) = name
        && !rib.vrfs.contains_key(n)
    {
        return Err(if json {
            "{\"routes\": []}\n".to_string()
        } else {
            format!("% No such VRF: {n}\n")
        });
    }
    Ok(rib
        .vrfs
        .values()
        .filter(|v| match name {
            Some(n) => &v.name == n,
            None => true,
        })
        .collect())
}

/// IPv4 `show ip route vrf [NAME] [detail]` core. The entry formatters
/// resolve nexthops/interfaces against the global `rib`, so per-VRF
/// output matches the default table; only the source table differs
/// (`rib.vrf_tables[table_id].table` instead of `rib.table`).
fn rib_vrf_render(rib: &Rib, name: Option<String>, json: bool, detail: bool) -> String {
    let selected = match vrf_targets(rib, &name, json) {
        Ok(s) => s,
        Err(e) => return e,
    };
    if json {
        let mut routes = Vec::new();
        for vrf in &selected {
            if let Some(tables) = rib.vrf_tables.get(&vrf.table_id) {
                for (prefix, entries) in tables.table.iter() {
                    for entry in entries.iter() {
                        routes.push(rib_entry_to_json(rib, &prefix, entry));
                    }
                }
            }
        }
        return serde_json::to_string_pretty(&RouteTable { routes })
            .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialize routes: {}\"}}", e));
    }
    if selected.is_empty() {
        return "% No VRFs configured\n".to_string();
    }
    let mut buf = String::new();
    for vrf in &selected {
        writeln!(buf, "VRF {} (table {}):", vrf.name, vrf.table_id).unwrap();
        let Some(tables) = rib.vrf_tables.get(&vrf.table_id) else {
            continue;
        };
        if detail {
            for (prefix, entries) in tables.table.iter() {
                for entry in entries.iter() {
                    buf.push_str(&rib_entry_show_detail(rib, &prefix, entry));
                }
            }
        } else {
            buf.push_str(SHOW_HEADER);
            for (prefix, entries) in tables.table.iter() {
                for entry in entries.iter() {
                    write!(
                        buf,
                        "{}",
                        rib_entry_show(rib, &prefix, entry, json).unwrap()
                    )
                    .unwrap();
                }
            }
        }
    }
    buf
}

/// IPv6 counterpart of [`rib_vrf_render`].
fn rib6_vrf_render(rib: &Rib, name: Option<String>, json: bool, detail: bool) -> String {
    let selected = match vrf_targets(rib, &name, json) {
        Ok(s) => s,
        Err(e) => return e,
    };
    if json {
        let mut routes = Vec::new();
        for vrf in &selected {
            if let Some(tables) = rib.vrf_tables.get(&vrf.table_id) {
                for (prefix, entries) in tables.table_v6.iter() {
                    for entry in entries.iter() {
                        routes.push(rib_entry_to_json_v6(rib, &prefix, entry));
                    }
                }
            }
        }
        return serde_json::to_string_pretty(&RouteTable { routes })
            .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialize routes: {}\"}}", e));
    }
    if selected.is_empty() {
        return "% No VRFs configured\n".to_string();
    }
    let mut buf = String::new();
    for vrf in &selected {
        writeln!(buf, "VRF {} (table {}):", vrf.name, vrf.table_id).unwrap();
        let Some(tables) = rib.vrf_tables.get(&vrf.table_id) else {
            continue;
        };
        if detail {
            for (prefix, entries) in tables.table_v6.iter() {
                for entry in entries.iter() {
                    buf.push_str(&rib_entry_show_v6_detail(rib, &prefix, entry));
                }
            }
        } else {
            buf.push_str(SHOW_HEADER);
            for (prefix, entries) in tables.table_v6.iter() {
                for entry in entries.iter() {
                    write!(
                        buf,
                        "{}",
                        rib_entry_show_v6(rib, &prefix, entry, json).unwrap()
                    )
                    .unwrap();
                }
            }
        }
    }
    buf
}

/// `show ip route vrf [NAME]` — one-line layout.
pub fn rib_show_vrf(rib: &Rib, mut args: Args, json: bool) -> String {
    rib_vrf_render(rib, args.string(), json, false)
}

/// `show ip route vrf [NAME] detail` — IOS-XR-style block layout.
pub fn rib_show_vrf_detail(rib: &Rib, mut args: Args, json: bool) -> String {
    rib_vrf_render(rib, args.string(), json, true)
}

/// `show ipv6 route vrf [NAME]` — one-line layout.
pub fn rib6_show_vrf(rib: &Rib, mut args: Args, json: bool) -> String {
    rib6_vrf_render(rib, args.string(), json, false)
}

/// `show ipv6 route vrf [NAME] detail` — IOS-XR-style block layout.
pub fn rib6_show_vrf_detail(rib: &Rib, mut args: Args, json: bool) -> String {
    rib6_vrf_render(rib, args.string(), json, true)
}

pub fn rib6_show(rib: &Rib, _args: Args, json: bool) -> String {
    if json {
        let mut routes = Vec::new();

        for (prefix, entries) in rib.table_v6.iter() {
            for entry in entries.iter() {
                routes.push(rib_entry_to_json_v6(rib, &prefix, entry));
            }
        }

        let route_table = RouteTable { routes };
        serde_json::to_string_pretty(&route_table)
            .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialize routes: {}\"}}", e))
    } else {
        let mut buf = String::new();
        buf.push_str(SHOW_HEADER);

        for (prefix, entries) in rib.table_v6.iter() {
            for entry in entries.iter() {
                write!(
                    buf,
                    "{}",
                    rib_entry_show_v6(rib, &prefix, entry, json).unwrap()
                )
                .unwrap();
            }
        }
        buf
    }
}

/// `show ipv6 route detail` — IOS-XR-style block view across the
/// whole IPv6 RIB.
pub fn rib6_show_detail(rib: &Rib, args: Args, json: bool) -> String {
    if json {
        return rib6_show(rib, args, json);
    }
    let mut buf = String::new();
    for (prefix, entries) in rib.table_v6.iter() {
        for entry in entries.iter() {
            buf.push_str(&rib_entry_show_v6_detail(rib, &prefix, entry));
        }
    }
    buf
}

/// `show ipv6 route prefix X::Y/N` — single-prefix, one-line layout.
pub fn rib6_show_prefix(rib: &Rib, mut args: Args, json: bool) -> String {
    let Some(prefix) = args.v6net() else {
        return "% Invalid IPv6 prefix\n".to_string();
    };
    rib6_show_one(rib, &prefix, json, false)
}

/// `show ipv6 route prefix X::Y/N detail` — single-prefix block.
pub fn rib6_show_prefix_detail(rib: &Rib, mut args: Args, json: bool) -> String {
    let Some(prefix) = args.v6net() else {
        return "% Invalid IPv6 prefix\n".to_string();
    };
    rib6_show_one(rib, &prefix, json, true)
}

fn rib6_show_one(rib: &Rib, prefix: &Ipv6Net, json: bool, detail: bool) -> String {
    let Some(entries) = rib.table_v6.get(prefix) else {
        return if json {
            "{\"routes\": []}\n".to_string()
        } else {
            format!("% No route for {prefix}\n")
        };
    };

    if json {
        let routes: Vec<RouteEntry> = entries
            .iter()
            .map(|e| rib_entry_to_json_v6(rib, prefix, e))
            .collect();
        return serde_json::to_string_pretty(&RouteTable { routes })
            .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialize routes: {}\"}}", e));
    }

    let mut buf = String::new();
    if detail {
        for entry in entries.iter() {
            buf.push_str(&rib_entry_show_v6_detail(rib, prefix, entry));
        }
    } else {
        buf.push_str(SHOW_HEADER);
        for entry in entries.iter() {
            let _ = write!(
                buf,
                "{}",
                rib_entry_show_v6(rib, prefix, entry, json).unwrap()
            );
        }
    }
    buf
}

// JSON structures for MPLS ILM display
#[derive(Serialize)]
pub struct IlmJson {
    pub protocol: String,
    pub distance: u8,
    pub selected: bool,
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

        for (label, ilms) in rib.ilm.iter() {
            for ilm in ilms.iter() {
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
        }

        let ilm_table = IlmTable { entries };
        serde_json::to_string_pretty(&ilm_table)
            .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialize ILM: {}\"}}", e))
    } else {
        let mut buf = String::new();

        // Add header
        writeln!(
            buf,
            "   P Dist Local  Outgoing    Prefix             Outgoing     Next Hop"
        )
        .unwrap();
        writeln!(
            buf,
            "          Label  Label       or ID              Interface"
        )
        .unwrap();
        writeln!(
            buf,
            "-- - ---- ------ ----------- ------------------ ------------ ---------------"
        )
        .unwrap();

        for (label, ilms) in rib.ilm.iter() {
            for ilm in ilms.iter() {
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
    let marker = if ilm.selected { "*>" } else { "" };
    let protocol = ilm.rtype.abbrev();
    let distance = format!("{:<4}", ilm.distance);
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
        super::inst::IlmType::DecapVrf {
            table_id,
            vrf_ifindex: _,
        } => format!("VPN Decap (tbl {:<3})", table_id),
        super::inst::IlmType::ContextLabel {
            table_id,
            vrf_ifindex: _,
        } => format!("Mirror Ctx (tbl {:<3})", table_id),
        super::inst::IlmType::Swap => "LU Swap".to_string(),
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
        "{:<2} {} {} {} {} {:<18} {:<12} {}",
        marker, protocol, distance, local_label, outgoing_label, prefix_or_id, interface, next_hop
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
        super::inst::IlmType::DecapVrf {
            table_id,
            vrf_ifindex: _,
        } => format!("VPN Decap (tbl {})", table_id),
        super::inst::IlmType::ContextLabel {
            table_id,
            vrf_ifindex: _,
        } => format!("Mirror Ctx (tbl {})", table_id),
        super::inst::IlmType::Swap => "LU Swap".to_string(),
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
        protocol: protocol_long_name(ilm.rtype).to_string(),
        distance: ilm.distance,
        selected: ilm.selected,
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
) -> Option<(Ipv4Net, &'a RibEntry)> {
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
    pub fn show_build(&mut self) {
        self.show_cb = Builder::<ShowCallback>::default()
            .path("/show/interface")
            .set(link_show)
            .path("/show/ip/route")
            .set(rib_show)
            .path("/show/ip/route/detail")
            .set(rib_show_detail)
            .path("/show/ip/route/prefix")
            .set(rib_show_prefix)
            .path("/show/ip/route/prefix/detail")
            .set(rib_show_prefix_detail)
            .path("/show/ip/route/vrf")
            .set(rib_show_vrf)
            .path("/show/ip/route/vrf/detail")
            .set(rib_show_vrf_detail)
            .path("/show/ipv6/route")
            .set(rib6_show)
            .path("/show/ipv6/route/detail")
            .set(rib6_show_detail)
            .path("/show/ipv6/route/prefix")
            .set(rib6_show_prefix)
            .path("/show/ipv6/route/prefix/detail")
            .set(rib6_show_prefix_detail)
            .path("/show/ipv6/route/vrf")
            .set(rib6_show_vrf)
            .path("/show/ipv6/route/vrf/detail")
            .set(rib6_show_vrf_detail)
            .path("/show/nexthop")
            .set(nexthop_show)
            .path("/show/mpls/ilm")
            .set(ilm_show)
            .path("/show/l2/mac/table")
            .set(mac_show)
            .path("/show/l2/neighbor")
            .set(l2_neighbor_show)
            .path("/show/segment-routing/srv6/sid")
            .set(sid_show)
            .path("/show/vrf")
            .set(vrf_show)
            .path("/show/hostname")
            .set(hostname_show)
            .path("/show/router-id")
            .set(router_id_show)
            .map();
    }
}

pub fn router_id_show(rib: &Rib, _args: Args, json: bool) -> String {
    let selected = !rib.router_id.is_unspecified();
    let source = if rib.router_id_config.is_some() {
        "configured"
    } else {
        "automatic"
    };
    if json {
        let value = if selected {
            serde_json::json!({
                "routerId": rib.router_id.to_string(),
                "source": source,
            })
        } else {
            serde_json::json!({ "routerId": Value::Null })
        };
        return value.to_string();
    }
    if !selected {
        return "Router ID is not yet selected\n".to_string();
    }
    format!("Router ID: {} ({})\n", rib.router_id, source)
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
    writeln!(
        buf,
        " {:<24}{:>10}  {:<17}Members",
        "Name", "Table-ID", "Router-ID"
    )
    .unwrap();
    writeln!(buf, " {:-<24}  {:-<10}  {:-<15}  {:-<32}", "", "", "", "").unwrap();
    for vrf in rib.vrfs.values() {
        let members: Vec<&str> = rib
            .links
            .values()
            .filter(|l| l.master == Some(vrf.ifindex))
            .map(|l| l.name.as_str())
            .collect();
        let router_id = if vrf.router_id.is_unspecified() {
            "-".to_string()
        } else {
            vrf.router_id.to_string()
        };
        writeln!(
            buf,
            " {:<24}{:>10}  {:<17}{}",
            vrf.name,
            vrf.table_id,
            router_id,
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
        owner = "Protocol",
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
            table_id: 0,
            segs: Vec::new(),
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
            // Protocol name only — no `isis(0)` instance suffix.
            assert!(line.contains("isis"));
            assert!(!line.contains("isis(0)"));
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

    #[test]
    fn fmt_label_stack_renders_braced_push_order() {
        // Single label: still braced for parity with multi-label.
        assert_eq!(fmt_label_stack(&[Label::Explicit(17003)]), "{ 17003 }");
        // Multi-label: order preserved (push order, top of stack
        // first — matches IOS-XR `labels imposed {L1 L2 L3}`).
        assert_eq!(
            fmt_label_stack(&[
                Label::Explicit(17010),
                Label::Explicit(24001),
                Label::Explicit(17003),
            ]),
            "{ 17010 24001 17003 }"
        );
        // Implicit-null renders as the label number in parentheses.
        assert_eq!(fmt_label_stack(&[Label::Implicit(3)]), "{ (3) }");
    }

    #[test]
    fn fmt_srv6_segs_renders_braced_comma_separated() {
        let one: Ipv6Addr = "fcbb:bb00:1::".parse().unwrap();
        assert_eq!(fmt_srv6_segs(&[one]), "{ fcbb:bb00:1:: }");
        let two: Ipv6Addr = "fcbb:bb00:2::".parse().unwrap();
        assert_eq!(
            fmt_srv6_segs(&[one, two]),
            "{ fcbb:bb00:1::, fcbb:bb00:2:: }"
        );
    }

    #[test]
    fn fmt_protection_role_distinguishes_primary_and_backup() {
        assert_eq!(fmt_protection_role(0), "Protected");
        assert_eq!(fmt_protection_role(1), "Backup (TI-LFA)");
        assert_eq!(fmt_protection_role(7), "Backup (TI-LFA)");
    }

    #[test]
    fn list_continuation_prefix_aligns_bracket_and_backup_marker() {
        // Columns taken from the `L2 *> 10.0.0.0/24 [0/100] …` first line:
        // tag+space = 3 (`L2 `), `[` opens at column 18.
        let marker_col = "L2 ".len(); // 3
        let bracket_col = "L2 *> 10.0.0.0/24 ".len(); // 18

        // A backup path: `*? ` sits in the FIB-marker column, the bracket
        // re-aligns under the first line, and the metric is the path's own.
        let backup = list_continuation_prefix(marker_col, bracket_col, "*? ", 0, 1002);
        assert_eq!(backup, "   *?             [0/1002]");
        assert_eq!(backup.find('[').unwrap(), bracket_col);

        // An extra primary ECMP leg carries no marker, just an aligned
        // bracket.
        let primary = list_continuation_prefix(marker_col, bracket_col, "", 0, 100);
        assert_eq!(primary, "                  [0/100]");
        assert_eq!(primary.find('[').unwrap(), bracket_col);
    }

    #[test]
    fn protocol_long_name_covers_routing_daemons() {
        use super::super::types::RibType;
        assert_eq!(protocol_long_name(RibType::Isis), "isis");
        assert_eq!(protocol_long_name(RibType::Bgp), "bgp");
        assert_eq!(protocol_long_name(RibType::Ospf), "ospf");
        assert_eq!(protocol_long_name(RibType::Connected), "connected");
        assert_eq!(protocol_long_name(RibType::Static), "static");
        assert_eq!(protocol_long_name(RibType::Other(42)), "unknown");
    }

    #[test]
    fn subtype_long_name_renders_ios_xr_descriptors() {
        use super::super::types::RibSubType;
        assert_eq!(subtype_long_name(&RibSubType::IsisLevel1), Some("level-1"));
        assert_eq!(subtype_long_name(&RibSubType::IsisLevel2), Some("level-2"));
        assert_eq!(subtype_long_name(&RibSubType::OspfIa), Some("inter-area"));
        assert_eq!(
            subtype_long_name(&RibSubType::OspfNssa1),
            Some("NSSA external type 1")
        );
        // Default + unrecognized: no suffix, so the `Known via` line
        // omits the `type ...` trailer.
        assert_eq!(subtype_long_name(&RibSubType::Default), None);
        assert_eq!(subtype_long_name(&RibSubType::Other(99)), None);
    }

    #[test]
    fn json_subtype_name_drops_isis_prefix() {
        use super::super::types::RibSubType;
        // IS-IS levels render bare in the JSON `subtype` field.
        assert_eq!(RibSubType::IsisLevel1.name(), "level1");
        assert_eq!(RibSubType::IsisLevel2.name(), "level2");
        // Other variants keep their lowercased debug name.
        assert_eq!(RibSubType::Default.name(), "default");
    }
}
