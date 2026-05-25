//! OSPFv3 `show ipv6 ospf ...` command handlers.
//!
//! Sibling of v2's `show.rs`. Mirrors the v2 dispatch shape — one
//! handler per `/show/ipv6/ospf/...` path, registered through
//! `Ospf<Ospfv3>::show_build`, dispatched by the v3 event loop's
//! `process_show_msg` arm. Output formatting is plain text by
//! default; the `json` flag carried by `ShowCallback` produces a
//! JSON document instead.

use std::fmt::Write;
use std::net::Ipv4Addr;

use serde::Serialize;

use ospf_packet::{
    OSPFV3_AS_EXTERNAL_FLAG_E, OSPFV3_AS_EXTERNAL_FLAG_F, OSPFV3_AS_EXTERNAL_FLAG_T,
    OSPFV3_AS_EXTERNAL_LSA_TYPE, OSPFV3_INTER_AREA_PREFIX_LSA_TYPE,
    OSPFV3_INTER_AREA_ROUTER_LSA_TYPE, OSPFV3_INTRA_AREA_PREFIX_LSA_TYPE, OSPFV3_LINK_LSA_TYPE,
    OSPFV3_NETWORK_LSA_TYPE, OSPFV3_ROUTER_LSA_FLAG_B, OSPFV3_ROUTER_LSA_FLAG_E,
    OSPFV3_ROUTER_LSA_FLAG_V, OSPFV3_ROUTER_LSA_FLAG_W, OSPFV3_ROUTER_LSA_TYPE, Ospfv3LsBody,
    Ospfv3Options, Ospfv3PrefixOptions, Ospfv3RouterLinkType,
};

use super::lsdb::{Lsa, OSPF_MAX_AGE};
use super::version::Ospfv3;
use super::{Ospf, ShowCallback};

use crate::config::Args;

const SHOW_OSPFV3: &str = "/show/ipv6/ospf";

impl Ospf<Ospfv3> {
    /// Register the v3 show-path dispatch table. Mirrors v2's
    /// `show_build` shape and command set, minus `segment-routing`
    /// (no v3 SR wiring yet).
    pub fn show_build(&mut self) {
        let prefix = SHOW_OSPFV3;
        let entries: &[(&str, ShowCallback<Ospfv3>)] = &[
            ("", show_ospfv3_summary),
            ("/interface", show_ospfv3_interface),
            ("/neighbor", show_ospfv3_neighbor),
            ("/neighbor/detail", show_ospfv3_neighbor_detail),
            ("/database", show_ospfv3_database),
            ("/database/detail", show_ospfv3_database_detail),
            ("/route", show_ospfv3_route),
            ("/spf", show_ospfv3_spf),
            ("/graph", show_ospfv3_graph),
        ];
        for (path, cb) in entries {
            self.show_cb.insert(format!("{}{}", prefix, path), *cb);
        }
    }
}

// ---- helpers ----------------------------------------------------

fn render_or<T: serde::Serialize>(
    json: bool,
    value: &T,
    text: String,
) -> Result<String, std::fmt::Error> {
    if json {
        Ok(serde_json::to_string_pretty(value).unwrap_or_else(|_| String::from("{}")))
    } else {
        Ok(text)
    }
}

fn ls_type_name(ls_type: u16) -> &'static str {
    use ospf_packet::{
        OSPFV3_AS_EXTERNAL_LSA_TYPE, OSPFV3_INTER_AREA_PREFIX_LSA_TYPE,
        OSPFV3_INTER_AREA_ROUTER_LSA_TYPE, OSPFV3_INTRA_AREA_PREFIX_LSA_TYPE, OSPFV3_LINK_LSA_TYPE,
        OSPFV3_NETWORK_LSA_TYPE, OSPFV3_ROUTER_LSA_TYPE,
    };
    match ls_type {
        OSPFV3_ROUTER_LSA_TYPE => "Router-LSA",
        OSPFV3_NETWORK_LSA_TYPE => "Network-LSA",
        OSPFV3_INTER_AREA_PREFIX_LSA_TYPE => "Inter-Area-Prefix-LSA",
        OSPFV3_INTER_AREA_ROUTER_LSA_TYPE => "Inter-Area-Router-LSA",
        OSPFV3_AS_EXTERNAL_LSA_TYPE => "AS-External-LSA",
        OSPFV3_LINK_LSA_TYPE => "Link-LSA",
        OSPFV3_INTRA_AREA_PREFIX_LSA_TYPE => "Intra-Area-Prefix-LSA",
        _ => "Unknown",
    }
}

// ---- show ipv6 ospf (instance summary) --------------------------

#[derive(Serialize)]
struct Ospfv3SummaryJson {
    router_id: String,
    area_count: usize,
    link_count: usize,
    spf_last_ms_ago: Option<u128>,
    spf_duration_us: Option<u128>,
}

fn show_ospfv3_summary(
    top: &Ospf<Ospfv3>,
    _args: Args,
    json: bool,
) -> Result<String, std::fmt::Error> {
    let summary = Ospfv3SummaryJson {
        router_id: top.router_id.to_string(),
        area_count: top.areas.iter().count(),
        link_count: top.links.len(),
        spf_last_ms_ago: top.spf_last.map(|t| t.elapsed().as_millis()),
        spf_duration_us: top.spf_duration.map(|d| d.as_micros()),
    };
    let mut text = String::new();
    writeln!(text, "OSPFv3 Routing Process")?;
    writeln!(text, "  Router ID:    {}", summary.router_id)?;
    writeln!(text, "  Areas:        {}", summary.area_count)?;
    writeln!(text, "  Interfaces:   {}", summary.link_count)?;
    if let Some(ms) = summary.spf_last_ms_ago {
        writeln!(text, "  Last SPF run: {} ms ago", ms)?;
    }
    if let Some(us) = summary.spf_duration_us {
        writeln!(text, "  SPF duration: {} us", us)?;
    }
    render_or(json, &summary, text)
}

// ---- show ipv6 ospf interface -----------------------------------

#[derive(Serialize)]
struct Ospfv3InterfaceJson {
    name: String,
    ifindex: u32,
    interface_id: u32,
    enabled: bool,
    area_id: String,
    state: String,
    d_router: String,
    bd_router: String,
    priority: u8,
    hello_interval: u16,
    dead_interval: u32,
    neighbor_count: usize,
}

fn show_ospfv3_interface(
    top: &Ospf<Ospfv3>,
    _args: Args,
    json: bool,
) -> Result<String, std::fmt::Error> {
    // Only list interfaces the operator enabled v3 on — matches v2's
    // `show_ospf_interface` filter (`if !oi.enabled { continue; }`).
    // Without this filter every kernel link the RIB has surfaced
    // shows up, which is noisy and inconsistent with v2.
    let entries: Vec<Ospfv3InterfaceJson> = top
        .links
        .values()
        .filter(|link| link.enabled)
        .map(|link| Ospfv3InterfaceJson {
            name: link.name.clone(),
            ifindex: link.index,
            interface_id: link.interface_id,
            enabled: link.enabled,
            area_id: link.area_id.to_string(),
            state: link.state.to_string(),
            d_router: link.ident.d_router.to_string(),
            bd_router: link.ident.bd_router.to_string(),
            priority: link.priority(),
            hello_interval: link.hello_interval(),
            dead_interval: link.dead_interval(),
            neighbor_count: link.nbrs.len(),
        })
        .collect();
    let mut text = String::new();
    for e in &entries {
        writeln!(
            text,
            "{} (ifindex {}, area {}, state {}, neighbors {})",
            e.name, e.ifindex, e.area_id, e.state, e.neighbor_count
        )?;
        writeln!(
            text,
            "  Interface ID: {}  Priority: {}  Hello {}s  Dead {}s",
            e.interface_id, e.priority, e.hello_interval, e.dead_interval
        )?;
        writeln!(text, "  DR: {}  BDR: {}", e.d_router, e.bd_router)?;
    }
    render_or(json, &entries, text)
}

// ---- show ipv6 ospf neighbor ------------------------------------

#[derive(Serialize)]
struct Ospfv3NeighborJson {
    router_id: String,
    interface: String,
    interface_id: u32,
    state: String,
    priority: u8,
    d_router: String,
    bd_router: String,
}

fn collect_neighbors(top: &Ospf<Ospfv3>) -> Vec<Ospfv3NeighborJson> {
    let mut out = Vec::new();
    for link in top.links.values() {
        for nbr in link.nbrs.values() {
            out.push(Ospfv3NeighborJson {
                router_id: nbr.ident.router_id.to_string(),
                interface: link.name.clone(),
                interface_id: nbr.interface_id,
                state: nbr.state.to_string(),
                priority: nbr.ident.priority,
                d_router: nbr.ident.d_router.to_string(),
                bd_router: nbr.ident.bd_router.to_string(),
            });
        }
    }
    out
}

fn show_ospfv3_neighbor(
    top: &Ospf<Ospfv3>,
    _args: Args,
    json: bool,
) -> Result<String, std::fmt::Error> {
    let entries = collect_neighbors(top);
    let mut text = String::new();
    writeln!(
        text,
        "{:<16} {:<10} {:<10} {:<10}",
        "Router-ID", "Iface", "State", "DR"
    )?;
    for n in &entries {
        writeln!(
            text,
            "{:<16} {:<10} {:<10} {:<10}",
            n.router_id, n.interface, n.state, n.d_router
        )?;
    }
    render_or(json, &entries, text)
}

fn show_ospfv3_neighbor_detail(
    top: &Ospf<Ospfv3>,
    _args: Args,
    json: bool,
) -> Result<String, std::fmt::Error> {
    let entries = collect_neighbors(top);
    let mut text = String::new();
    for n in &entries {
        writeln!(text, "Neighbor {}", n.router_id)?;
        writeln!(
            text,
            "  Interface:    {} (id {})",
            n.interface, n.interface_id
        )?;
        writeln!(text, "  State:        {}", n.state)?;
        writeln!(text, "  Priority:     {}", n.priority)?;
        writeln!(text, "  DR / BDR:     {} / {}", n.d_router, n.bd_router)?;
    }
    render_or(json, &entries, text)
}

// ---- show ipv6 ospf database ------------------------------------

#[derive(Serialize)]
struct Ospfv3LsaHeaderJson {
    ls_type: String,
    ls_type_raw: u16,
    link_state_id: u32,
    advertising_router: String,
    ls_seq_number: String,
    ls_age: u16,
    length: u16,
    scope: String,
}

#[derive(Serialize, Default)]
struct Ospfv3DatabaseJson {
    area: Vec<Ospfv3LsaHeaderJson>,
    as_scope: Vec<Ospfv3LsaHeaderJson>,
    link: Vec<Ospfv3LsaHeaderJson>,
}

fn ls_type_scope_label(ls_type: u16) -> &'static str {
    match (ls_type >> 13) & 0x3 {
        0 => "Link",
        1 => "Area",
        2 => "AS",
        _ => "Reserved",
    }
}

fn hdr_to_json(h: &ospf_packet::Ospfv3LsaHeader) -> Ospfv3LsaHeaderJson {
    Ospfv3LsaHeaderJson {
        ls_type: ls_type_name(h.ls_type).to_string(),
        ls_type_raw: h.ls_type,
        link_state_id: h.link_state_id,
        advertising_router: h.advertising_router.to_string(),
        ls_seq_number: format!("0x{:08x}", h.ls_seq_number),
        ls_age: h.ls_age,
        length: h.length,
        scope: ls_type_scope_label(h.ls_type).to_string(),
    }
}

fn collect_database(top: &Ospf<Ospfv3>) -> Ospfv3DatabaseJson {
    let mut db = Ospfv3DatabaseJson::default();
    for (_, area) in top.areas.iter() {
        for (_, lsa) in area.lsdb.tables.iter() {
            if lsa.data.h.ls_age >= OSPF_MAX_AGE {
                continue;
            }
            db.area.push(hdr_to_json(&lsa.data.h));
        }
    }
    for (_, lsa) in top.lsdb_as.tables.iter() {
        if lsa.data.h.ls_age >= OSPF_MAX_AGE {
            continue;
        }
        db.as_scope.push(hdr_to_json(&lsa.data.h));
    }
    for link in top.links.values() {
        for (_, lsa) in link.lsdb.tables.iter() {
            if lsa.data.h.ls_age >= OSPF_MAX_AGE {
                continue;
            }
            db.link.push(hdr_to_json(&lsa.data.h));
        }
    }
    db
}

fn show_ospfv3_database(
    top: &Ospf<Ospfv3>,
    _args: Args,
    json: bool,
) -> Result<String, std::fmt::Error> {
    let db = collect_database(top);
    let mut text = String::new();
    for (label, entries) in [
        ("Area-scope", &db.area),
        ("AS-scope", &db.as_scope),
        ("Link-scope", &db.link),
    ] {
        if entries.is_empty() {
            continue;
        }
        writeln!(text, "{}:", label)?;
        writeln!(
            text,
            "  {:<22} {:<16} {:<16} {:<10} Age",
            "Type", "LS-ID", "Adv-Router", "Seq#"
        )?;
        for h in entries {
            writeln!(
                text,
                "  {:<22} {:<16} {:<16} {:<10} {}",
                h.ls_type, h.link_state_id, h.advertising_router, h.ls_seq_number, h.ls_age
            )?;
        }
    }
    render_or(json, &db, text)
}

/// FRR-style detail output. Walks each area / AS / per-link LSDB,
/// groups by LS-Type, and prints the full body of every non-MaxAge
/// LSA. JSON output reuses the summary shape (header-only) for now —
/// per-body JSON serializers belong to a follow-up.
fn show_ospfv3_database_detail(
    top: &Ospf<Ospfv3>,
    args: Args,
    json: bool,
) -> Result<String, std::fmt::Error> {
    if json {
        return show_ospfv3_database(top, args, json);
    }

    let mut out = String::new();
    writeln!(out)?;
    writeln!(out, "       OSPFv3 Router with ID ({})", top.router_id)?;
    writeln!(out)?;

    const AREA_TYPES: &[u16] = &[
        OSPFV3_ROUTER_LSA_TYPE,
        OSPFV3_NETWORK_LSA_TYPE,
        OSPFV3_INTER_AREA_PREFIX_LSA_TYPE,
        OSPFV3_INTER_AREA_ROUTER_LSA_TYPE,
        OSPFV3_INTRA_AREA_PREFIX_LSA_TYPE,
    ];

    for (area_id, area) in top.areas.iter() {
        for &ls_type in AREA_TYPES {
            let mut section_printed = false;
            for ((ls_id, adv_router), lsa) in area.lsdb.iter_by_raw_type(ls_type) {
                if lsa.data.h.ls_age >= OSPF_MAX_AGE {
                    continue;
                }
                if !section_printed {
                    writeln!(
                        out,
                        "                {} (Area {})",
                        ls_type_name(ls_type),
                        area_id
                    )?;
                    writeln!(out)?;
                    section_printed = true;
                }
                write_lsa_detail(&mut out, lsa, ls_id, adv_router)?;
                writeln!(out)?;
            }
        }
    }

    let mut section_printed = false;
    for ((ls_id, adv_router), lsa) in top.lsdb_as.iter_by_raw_type(OSPFV3_AS_EXTERNAL_LSA_TYPE) {
        if lsa.data.h.ls_age >= OSPF_MAX_AGE {
            continue;
        }
        if !section_printed {
            writeln!(
                out,
                "                {} (AS-Scope)",
                ls_type_name(OSPFV3_AS_EXTERNAL_LSA_TYPE)
            )?;
            writeln!(out)?;
            section_printed = true;
        }
        write_lsa_detail(&mut out, lsa, ls_id, adv_router)?;
        writeln!(out)?;
    }

    for link in top.links.values() {
        let mut section_printed = false;
        for ((ls_id, adv_router), lsa) in link.lsdb.iter_by_raw_type(OSPFV3_LINK_LSA_TYPE) {
            if lsa.data.h.ls_age >= OSPF_MAX_AGE {
                continue;
            }
            if !section_printed {
                writeln!(
                    out,
                    "                {} (Interface {})",
                    ls_type_name(OSPFV3_LINK_LSA_TYPE),
                    link.name
                )?;
                writeln!(out)?;
                section_printed = true;
            }
            write_lsa_detail(&mut out, lsa, ls_id, adv_router)?;
            writeln!(out)?;
        }
    }

    Ok(out)
}

fn write_lsa_detail(
    out: &mut String,
    lsa: &Lsa<Ospfv3>,
    ls_id: u32,
    adv_router: Ipv4Addr,
) -> Result<(), std::fmt::Error> {
    let h = &lsa.data.h;
    writeln!(out, "  Age: {}", lsa.current_age())?;
    writeln!(
        out,
        "  Type: 0x{:04x} ({})",
        h.ls_type,
        ls_type_name(h.ls_type)
    )?;
    writeln!(out, "  Link State ID: {}", ls_id)?;
    writeln!(out, "  Advertising Router: {}", adv_router)?;
    writeln!(out, "  LS Sequence Number: 0x{:08x}", lsa.ls_seq_number())?;
    writeln!(out, "  Checksum: 0x{:04x}", lsa.ls_checksum())?;
    writeln!(out, "  Length: {}", lsa.length())?;

    match &lsa.data.body {
        Ospfv3LsBody::Router(b) => {
            writeln!(
                out,
                "  Flags: 0x{:02x} : {}",
                b.flags,
                format_router_flags(b.flags)
            )?;
            writeln!(out, "  Options: {}", format_options(b.options))?;
            for link in &b.links {
                writeln!(out)?;
                writeln!(out, "    Type: {}", router_link_type_name(link.link_type))?;
                writeln!(out, "    Metric: {}", link.metric)?;
                writeln!(out, "    Interface ID: {}", link.interface_id)?;
                writeln!(
                    out,
                    "    Neighbor Interface ID: {}",
                    link.neighbor_interface_id
                )?;
                writeln!(out, "    Neighbor Router ID: {}", link.neighbor_router_id)?;
            }
        }
        Ospfv3LsBody::Network(b) => {
            writeln!(out, "  Options: {}", format_options(b.options))?;
            for r in &b.attached_routers {
                writeln!(out, "    Attached Router: {}", r)?;
            }
        }
        Ospfv3LsBody::InterAreaPrefix(b) => {
            writeln!(out, "  Metric: {}", b.metric)?;
            writeln!(
                out,
                "  Prefix: {} (Options: {})",
                format_v3_prefix(b.prefix_length, &b.address_prefix),
                format_prefix_options(b.prefix_options)
            )?;
        }
        Ospfv3LsBody::InterAreaRouter(b) => {
            writeln!(out, "  Options: {}", format_options(b.options))?;
            writeln!(out, "  Metric: {}", b.metric)?;
            writeln!(
                out,
                "  Destination Router ID: {}",
                Ipv4Addr::from(b.destination_router_id)
            )?;
        }
        Ospfv3LsBody::AsExternal(b) => {
            writeln!(
                out,
                "  Flags: 0x{:02x} : {}",
                b.flags,
                format_external_flags(b.flags)
            )?;
            writeln!(out, "  Metric: {}", b.metric)?;
            writeln!(
                out,
                "  Prefix: {} (Options: {})",
                format_v3_prefix(b.prefix_length, &b.address_prefix),
                format_prefix_options(b.prefix_options)
            )?;
            if let Some(fwd) = b.forwarding_address {
                writeln!(out, "  Forwarding Address: {}", fwd)?;
            }
            if let Some(tag) = b.external_route_tag {
                writeln!(out, "  External Route Tag: {}", tag)?;
            }
            if let Some(rls_id) = b.referenced_link_state_id {
                writeln!(
                    out,
                    "  Referenced LS Type: 0x{:04x} ({}), LS ID: {}",
                    b.referenced_ls_type,
                    ls_type_name(b.referenced_ls_type),
                    rls_id
                )?;
            }
        }
        Ospfv3LsBody::Link(b) => {
            writeln!(out, "  Priority: {}", b.priority)?;
            writeln!(out, "  Options: {}", format_options(b.options))?;
            writeln!(out, "  Link-Local Address: {}", b.link_local_address)?;
            writeln!(out, "  Number of Prefixes: {}", b.prefixes.len())?;
            for p in &b.prefixes {
                writeln!(
                    out,
                    "    Prefix: {} (Options: {})",
                    format_v3_prefix(p.prefix_length, &p.address_prefix),
                    format_prefix_options(p.prefix_options)
                )?;
            }
        }
        Ospfv3LsBody::IntraAreaPrefix(b) => {
            writeln!(out, "  Number of Prefixes: {}", b.prefixes.len())?;
            writeln!(
                out,
                "  Reference: {} Id: {} Adv: {}",
                ls_type_name(b.referenced_ls_type),
                b.referenced_link_state_id,
                b.referenced_advertising_router
            )?;
            for p in &b.prefixes {
                writeln!(
                    out,
                    "    Prefix: {} (Metric: {}, Options: {})",
                    format_v3_prefix(p.prefix_length, &p.address_prefix),
                    p.metric,
                    format_prefix_options(p.prefix_options)
                )?;
            }
        }
        // RFC 8362 Extended LSAs — for now we only know the TLV
        // count. Top-level TLV decoders (Router-Link, Intra-Area-Prefix,
        // …) land in the SR-MPLS consumption follow-up; render a brief
        // summary until then.
        Ospfv3LsBody::ERouter(b)
        | Ospfv3LsBody::ENetwork(b)
        | Ospfv3LsBody::EInterAreaPrefix(b)
        | Ospfv3LsBody::EInterAreaRouter(b)
        | Ospfv3LsBody::EAsExternal(b)
        | Ospfv3LsBody::ELink(b)
        | Ospfv3LsBody::EIntraAreaPrefix(b) => {
            writeln!(
                out,
                "  Extended LSA body, {} top-level TLV(s)",
                b.tlvs.len()
            )?;
        }
        Ospfv3LsBody::Grace(b) => {
            if let Some(secs) = b.grace_period() {
                writeln!(out, "  Grace Period: {}s", secs)?;
            }
            if let Some(reason) = b.reason() {
                writeln!(out, "  Restart Reason: {:?}", reason)?;
            }
        }
        Ospfv3LsBody::Unknown(bytes) => {
            writeln!(out, "  (Unrecognized LSA body, {} bytes)", bytes.len())?;
        }
    }
    Ok(())
}

fn format_options(opts: Ospfv3Options) -> String {
    let mut flags = Vec::new();
    if opts.v6() {
        flags.push("V6");
    }
    if opts.e() {
        flags.push("E");
    }
    if opts.mc() {
        flags.push("MC");
    }
    if opts.n() {
        flags.push("N");
    }
    if opts.r() {
        flags.push("R");
    }
    if opts.dc() {
        flags.push("DC");
    }
    if flags.is_empty() {
        "-".to_string()
    } else {
        flags.join("|")
    }
}

fn format_prefix_options(opts: Ospfv3PrefixOptions) -> String {
    let mut flags = Vec::new();
    if opts.nu() {
        flags.push("NU");
    }
    if opts.la() {
        flags.push("LA");
    }
    if opts.mc() {
        flags.push("MC");
    }
    if opts.p() {
        flags.push("P");
    }
    if flags.is_empty() {
        "-".to_string()
    } else {
        flags.join("|")
    }
}

fn format_router_flags(flags: u8) -> String {
    let mut s = Vec::new();
    if flags & OSPFV3_ROUTER_LSA_FLAG_W != 0 {
        s.push("W");
    }
    if flags & OSPFV3_ROUTER_LSA_FLAG_V != 0 {
        s.push("V");
    }
    if flags & OSPFV3_ROUTER_LSA_FLAG_E != 0 {
        s.push("E");
    }
    if flags & OSPFV3_ROUTER_LSA_FLAG_B != 0 {
        s.push("B");
    }
    if s.is_empty() {
        "-".to_string()
    } else {
        s.join("|")
    }
}

fn format_external_flags(flags: u8) -> String {
    let mut s = Vec::new();
    if flags & OSPFV3_AS_EXTERNAL_FLAG_E != 0 {
        s.push("E");
    }
    if flags & OSPFV3_AS_EXTERNAL_FLAG_F != 0 {
        s.push("F");
    }
    if flags & OSPFV3_AS_EXTERNAL_FLAG_T != 0 {
        s.push("T");
    }
    if s.is_empty() {
        "-".to_string()
    } else {
        s.join("|")
    }
}

fn router_link_type_name(t: Ospfv3RouterLinkType) -> &'static str {
    match t {
        Ospfv3RouterLinkType::PointToPoint => "Point-to-Point",
        Ospfv3RouterLinkType::Transit => "Transit Network",
        Ospfv3RouterLinkType::VirtualLink => "Virtual Link",
    }
}

fn format_v3_prefix(prefix_length: u8, bytes: &[u8]) -> String {
    if prefix_length > 128 {
        return format!("(invalid /{})", prefix_length);
    }
    let mut padded = [0u8; 16];
    let n = bytes.len().min(16);
    padded[..n].copy_from_slice(&bytes[..n]);
    let addr = std::net::Ipv6Addr::from(padded);
    match ipnet::Ipv6Net::new(addr, prefix_length) {
        Ok(net) => net.trunc().to_string(),
        Err(_) => format!("{}/{}", addr, prefix_length),
    }
}

// ---- show ipv6 ospf route ---------------------------------------

#[derive(Serialize)]
struct Ospfv3RouteNexthopJson {
    nexthop: String,
    ifindex: u32,
}

#[derive(Serialize)]
struct Ospfv3RouteJson {
    prefix: String,
    metric: u32,
    nexthops: Vec<Ospfv3RouteNexthopJson>,
}

fn show_ospfv3_route(
    top: &Ospf<Ospfv3>,
    _args: Args,
    json: bool,
) -> Result<String, std::fmt::Error> {
    let entries: Vec<Ospfv3RouteJson> = top
        .rib6
        .iter()
        .map(|(prefix, route)| Ospfv3RouteJson {
            prefix: prefix.to_string(),
            metric: route.metric,
            nexthops: route
                .nhops
                .iter()
                .map(|(addr, nhop)| Ospfv3RouteNexthopJson {
                    nexthop: addr.to_string(),
                    ifindex: nhop.ifindex,
                })
                .collect(),
        })
        .collect();

    let mut text = String::new();
    writeln!(text, "OSPFv3 routes ({})", entries.len())?;
    for r in &entries {
        let nhops = if r.nexthops.is_empty() {
            String::from("(none)")
        } else {
            r.nexthops
                .iter()
                .map(|n| {
                    // `::` nexthops mark directly-attached prefixes
                    // (self-originated Intra-Area-Prefix-LSAs, per
                    // RFC 5340 §3.8.1 self-vertex handling); render
                    // them by interface name where we have it.
                    if n.nexthop == "::" {
                        let ifname = top
                            .links
                            .get(&n.ifindex)
                            .map(|l| l.name.as_str())
                            .unwrap_or("unknown");
                        format!("directly attached via {}", ifname)
                    } else if n.ifindex != 0 {
                        format!("{}%{}", n.nexthop, n.ifindex)
                    } else {
                        n.nexthop.clone()
                    }
                })
                .collect::<Vec<_>>()
                .join(", ")
        };
        writeln!(text, "  {} metric {} via {}", r.prefix, r.metric, nhops)?;
    }
    render_or(json, &entries, text)
}

// ---- show ipv6 ospf spf -----------------------------------------

#[derive(Serialize)]
struct Ospfv3SpfPathJson {
    vertex_id: usize,
    router_id: String,
    cost: u32,
    first_hop_routers: Vec<String>,
}

fn show_ospfv3_spf(top: &Ospf<Ospfv3>, _args: Args, json: bool) -> Result<String, std::fmt::Error> {
    let entries: Vec<Ospfv3SpfPathJson> = top
        .spf_result
        .as_ref()
        .map(|paths| {
            paths
                .iter()
                .map(|(id, path)| {
                    let router_id = top
                        .lsp_map
                        .resolve(*id)
                        .map_or_else(|| String::from("?"), |r| r.to_string());
                    let first_hop_routers: Vec<String> = path
                        .first_hop_links
                        .iter()
                        .filter_map(|(vid, _)| top.lsp_map.resolve(*vid).map(|r| r.to_string()))
                        .collect();
                    Ospfv3SpfPathJson {
                        vertex_id: *id,
                        router_id,
                        cost: path.cost,
                        first_hop_routers,
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    let mut text = String::new();
    writeln!(text, "OSPFv3 SPF tree ({} vertices)", entries.len())?;
    for p in &entries {
        writeln!(
            text,
            "  {} cost {} via {}",
            p.router_id,
            p.cost,
            if p.first_hop_routers.is_empty() {
                "(self)".to_string()
            } else {
                p.first_hop_routers.join(", ")
            }
        )?;
    }
    render_or(json, &entries, text)
}

// ---- show ipv6 ospf graph ---------------------------------------

#[derive(Serialize)]
struct Ospfv3GraphLinkJson {
    from: String,
    to: String,
    cost: u32,
}

#[derive(Serialize)]
struct Ospfv3GraphVertexJson {
    id: usize,
    name: String,
    links: Vec<Ospfv3GraphLinkJson>,
}

fn show_ospfv3_graph(
    top: &Ospf<Ospfv3>,
    _args: Args,
    json: bool,
) -> Result<String, std::fmt::Error> {
    let entries: Vec<Ospfv3GraphVertexJson> = top
        .graph
        .as_ref()
        .map(|g| {
            g.iter()
                .map(|(id, vertex)| Ospfv3GraphVertexJson {
                    id: *id,
                    name: vertex.name.clone(),
                    links: vertex
                        .olinks
                        .iter()
                        .map(|l| Ospfv3GraphLinkJson {
                            from: vertex.name.clone(),
                            to: top
                                .lsp_map
                                .resolve(l.to)
                                .map_or_else(|| l.to.to_string(), |r| r.to_string()),
                            cost: l.cost,
                        })
                        .collect(),
                })
                .collect()
        })
        .unwrap_or_default();

    let mut text = String::new();
    writeln!(text, "OSPFv3 area graph ({} vertices)", entries.len())?;
    for v in &entries {
        writeln!(text, "  {} (id {})", v.name, v.id)?;
        for l in &v.links {
            writeln!(text, "    -> {} cost {}", l.to, l.cost)?;
        }
    }
    render_or(json, &entries, text)
}
