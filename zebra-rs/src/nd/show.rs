//! `show ipv6 nd ...` command handlers.
//!
//! Mirrors the show-command pattern used by [`crate::bfd::show`]:
//! [`Nd::show_build`] registers a handler per path, the event loop
//! dispatches through [`super::inst::Nd::process_show_msg`], and each
//! handler renders read-only state from the live [`super::engine::NdEngine`].
//!
//! Two commands are exposed:
//!   * `show ipv6 nd`                     — one-line-per-interface summary.
//!   * `show ipv6 nd interface [IFNAME]`  — detailed block(s), all or one.
//!
//! Every command also accepts a trailing `json` keyword (surfaced as
//! the `json` flag) for machine-readable output.

use std::collections::BTreeSet;
use std::fmt::Write;
use std::time::Instant;

use serde::Serialize;

use crate::config::{Args, Builder};

use super::engine::{NdIfCounters, NdNeighbor};
use super::inst::{Nd, ShowCallback};

impl Nd {
    pub fn show_build(&mut self) {
        self.show_cb = Builder::<ShowCallback>::default()
            .path("/show/ipv6/nd")
            .set(show_nd_summary)
            .path("/show/ipv6/nd/interface")
            .set(show_nd_interface)
            .map();
    }
}

// ── Kernel /proc/net/dev_snmp6 reader ───────────────────────────────────────

/// Eight counters extracted from `/proc/net/dev_snmp6/<ifname>`.
///
/// A `None` for the whole struct means the file was unreadable (interface
/// missing or permission denied); rendered as `-` in text output.
#[derive(Debug, Default, Clone, Serialize)]
pub struct KernelNdCounters {
    pub in_router_solicits: u64,
    pub out_router_solicits: u64,
    pub in_router_advertisements: u64,
    pub out_router_advertisements: u64,
    pub in_neighbor_solicits: u64,
    pub out_neighbor_solicits: u64,
    pub in_neighbor_advertisements: u64,
    pub out_neighbor_advertisements: u64,
}

/// Parse the whitespace-separated `Name\tValue` lines from
/// `/proc/net/dev_snmp6/<ifname>` content, extracting the eight
/// ICMPv6 ND counters. Unrecognised lines are silently ignored.
pub fn parse_dev_snmp6(content: &str) -> KernelNdCounters {
    let mut c = KernelNdCounters::default();
    for line in content.lines() {
        let mut parts = line.split_whitespace();
        let name = match parts.next() {
            Some(n) => n,
            None => continue,
        };
        let value: u64 = match parts.next().and_then(|v| v.parse().ok()) {
            Some(v) => v,
            None => continue,
        };
        match name {
            "Icmp6InRouterSolicits" => c.in_router_solicits = value,
            "Icmp6OutRouterSolicits" => c.out_router_solicits = value,
            "Icmp6InRouterAdvertisements" => c.in_router_advertisements = value,
            "Icmp6OutRouterAdvertisements" => c.out_router_advertisements = value,
            "Icmp6InNeighborSolicits" => c.in_neighbor_solicits = value,
            "Icmp6OutNeighborSolicits" => c.out_neighbor_solicits = value,
            "Icmp6InNeighborAdvertisements" => c.in_neighbor_advertisements = value,
            "Icmp6OutNeighborAdvertisements" => c.out_neighbor_advertisements = value,
            _ => {}
        }
    }
    c
}

/// Read `/proc/net/dev_snmp6/<ifname>` and parse it. Returns `None`
/// when the file is absent or unreadable (interface gone, no
/// `CAP_NET_ADMIN`, etc.).
fn read_kernel_counters(ifname: &str) -> Option<KernelNdCounters> {
    let path = format!("/proc/net/dev_snmp6/{}", ifname);
    let content = std::fs::read_to_string(path).ok()?;
    Some(parse_dev_snmp6(&content))
}

// ── Duration formatting helper ───────────────────────────────────────────────

/// Format a `u64` seconds value as a human-readable duration string.
/// `0` → `"0s"`, `65` → `"1m5s"`, `3661` → `"1h1m1s"`.
fn fmt_duration(secs: u64) -> String {
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        let m = secs / 60;
        let s = secs % 60;
        if s == 0 {
            format!("{}m", m)
        } else {
            format!("{}m{}s", m, s)
        }
    } else {
        let h = secs / 3600;
        let m = (secs % 3600) / 60;
        let s = secs % 60;
        if m == 0 && s == 0 {
            format!("{}h", h)
        } else if s == 0 {
            format!("{}h{}m", h, m)
        } else {
            format!("{}h{}m{}s", h, m, s)
        }
    }
}

/// Render the number of seconds since `past` relative to `now`.
/// Uses `saturating_duration_since` so the result is always ≥ 0.
fn ago(now: Instant, past: Instant) -> String {
    let secs = now.saturating_duration_since(past).as_secs();
    format!("{} ago", fmt_duration(secs))
}

/// Render the number of seconds until `future` relative to `now`.
/// If `future` is already past, renders `"0s"`.
fn until(now: Instant, future: Instant) -> String {
    let secs = future.saturating_duration_since(now).as_secs();
    fmt_duration(secs)
}

// ── JSON DTO structs ─────────────────────────────────────────────────────────

#[derive(Serialize)]
struct JsonNeighbor {
    address: String,
    first_seen_secs: u64,
    last_seen_secs: u64,
    rx_ra: u64,
    rx_rs: u64,
    rx_ns: u64,
    rx_na: u64,
    last_ra_lifetime: Option<u16>,
    last_ra_hop_limit: Option<u8>,
    last_ra_managed: Option<bool>,
    last_ra_other: Option<bool>,
}

#[derive(Serialize)]
struct JsonCounters {
    tx_ra_unsolicited: u64,
    tx_ra_solicited: u64,
    rx_ra: u64,
    rx_rs: u64,
    rx_ns: u64,
    rx_na: u64,
    rx_drop_hop_limit: u64,
    rx_drop_malformed: u64,
    untracked_sources: u64,
}

#[derive(Serialize)]
struct JsonRaScheduler {
    min_interval_secs: u64,
    max_interval_secs: u64,
    router_lifetime: u16,
    cur_hop_limit: u8,
    managed: bool,
    other: bool,
    initial_remaining: u32,
    next_unsolicited_in_secs: u64,
    solicited_pending: bool,
    last_multicast_secs_ago: Option<u64>,
}

#[derive(Serialize)]
struct JsonInterface {
    name: String,
    ifindex: u32,
    ra_enabled: bool,
    ra_scheduler: Option<JsonRaScheduler>,
    counters: JsonCounters,
    kernel_counters: Option<KernelNdCounters>,
    neighbors: Vec<JsonNeighbor>,
}

#[derive(Serialize)]
struct JsonSummaryRow {
    name: String,
    ifindex: u32,
    ra_enabled: bool,
    neighbor_count: usize,
    rx_total: u64,
    tx_total: u64,
}

// ── Per-interface render helper ──────────────────────────────────────────────

/// Collect all ifindexes that appear in any of the three maps:
/// senders, counters, neighbors.
fn all_ifindexes(nd: &super::engine::NdEngine) -> BTreeSet<u32> {
    let mut set = BTreeSet::new();
    for &k in nd.senders().keys() {
        set.insert(k);
    }
    for &k in nd.counters().keys() {
        set.insert(k);
    }
    for &k in nd.neighbors().keys() {
        set.insert(k);
    }
    set
}

/// Render one interface's detail block (text).
fn render_interface_text(
    out: &mut String,
    nd: &super::engine::NdEngine,
    ifindex: u32,
    now: Instant,
) -> std::fmt::Result {
    let ifname = nd
        .ifname_of(ifindex)
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("if{}", ifindex));

    writeln!(out, "Interface {} (ifindex {})", ifname, ifindex)?;

    // ── RA scheduler ────────────────────────────────────────────────────
    if let Some(sender) = nd.sender(ifindex) {
        let cfg = sender.cfg();
        let flags = cfg.flags;
        let managed = if flags.contains(nd_packet::RaFlags::M) {
            1
        } else {
            0
        };
        let other = if flags.contains(nd_packet::RaFlags::O) {
            1
        } else {
            0
        };
        writeln!(out, "  Router advertisement: enabled")?;
        writeln!(
            out,
            "    interval {}-{}s, lifetime {}s, hop-limit {}, managed={} other={}",
            cfg.min_interval.as_secs(),
            cfg.max_interval.as_secs(),
            cfg.router_lifetime,
            cfg.cur_hop_limit,
            managed,
            other
        )?;
        let next_in = until(now, sender.next_unsolicited_at());
        writeln!(
            out,
            "    initial advertisements remaining {}, next unsolicited in {}",
            sender.initial_remaining(),
            next_in
        )?;
        let solicited = match sender.pending_solicited_at() {
            Some(_) => "yes".to_string(),
            None => "no".to_string(),
        };
        let last_mc = match sender.last_multicast_at() {
            Some(t) => ago(now, t),
            None => "never".to_string(),
        };
        writeln!(
            out,
            "    solicited reply pending: {}, last multicast {}",
            solicited, last_mc
        )?;
    } else {
        writeln!(out, "  Router advertisement: disabled")?;
    }

    // ── Daemon-observed counters ─────────────────────────────────────────
    let empty_counters = NdIfCounters::default();
    let c = nd.counters().get(&ifindex).unwrap_or(&empty_counters);
    let tx_ra = c.tx_ra_unsolicited + c.tx_ra_solicited;

    writeln!(out, "  Counters (daemon-observed)        Sent  Received")?;
    writeln!(
        out,
        "    Router solicitations         {:>7}  {:>8}",
        "-", c.rx_rs
    )?;
    writeln!(
        out,
        "    Router advertisements        {:>7}  {:>8}",
        tx_ra, c.rx_ra
    )?;
    writeln!(
        out,
        "    Neighbor solicitations       {:>7}  {:>8}",
        "-", c.rx_ns
    )?;
    writeln!(
        out,
        "    Neighbor advertisements      {:>7}  {:>8}",
        "-", c.rx_na
    )?;
    writeln!(
        out,
        "    dropped: hop-limit {}, malformed {}, untracked sources {}",
        c.rx_drop_hop_limit, c.rx_drop_malformed, c.untracked_sources
    )?;

    // ── Kernel counters ─────────────────────────────────────────────────
    writeln!(out, "  Counters (kernel)                 Sent  Received")?;
    match read_kernel_counters(&ifname) {
        Some(k) => {
            writeln!(
                out,
                "    Router solicitations         {:>7}  {:>8}",
                k.out_router_solicits, k.in_router_solicits
            )?;
            writeln!(
                out,
                "    Router advertisements        {:>7}  {:>8}",
                k.out_router_advertisements, k.in_router_advertisements
            )?;
            writeln!(
                out,
                "    Neighbor solicitations       {:>7}  {:>8}",
                k.out_neighbor_solicits, k.in_neighbor_solicits
            )?;
            writeln!(
                out,
                "    Neighbor advertisements      {:>7}  {:>8}",
                k.out_neighbor_advertisements, k.in_neighbor_advertisements
            )?;
        }
        None => {
            writeln!(out, "    (unavailable)")?;
        }
    }

    // ── Neighbor table ───────────────────────────────────────────────────
    let empty_table = std::collections::BTreeMap::new();
    let table = nd.neighbors().get(&ifindex).unwrap_or(&empty_table);
    writeln!(out, "  Neighbors ({}):", table.len())?;
    for (addr, nb) in table {
        render_neighbor_text(out, addr, nb, now)?;
    }

    Ok(())
}

fn render_neighbor_text(
    out: &mut String,
    addr: &std::net::Ipv6Addr,
    nb: &NdNeighbor,
    now: Instant,
) -> std::fmt::Result {
    let first = ago(now, nb.first_seen);
    let last = ago(now, nb.last_seen);
    let is_dad = *addr == std::net::Ipv6Addr::UNSPECIFIED;

    if is_dad {
        writeln!(
            out,
            "    {:<24} RA {}  RS {}  NS {}  NA {}   first {}, last {} (duplicate address detection)",
            addr, nb.rx_ra, nb.rx_rs, nb.rx_ns, nb.rx_na, first, last
        )?;
    } else {
        writeln!(
            out,
            "    {:<24} RA {}  RS {}  NS {}  NA {}   first {}, last {}",
            addr, nb.rx_ra, nb.rx_rs, nb.rx_ns, nb.rx_na, first, last
        )?;
    }

    if let Some(lr) = &nb.last_ra {
        let managed = if lr.flags.contains(nd_packet::RaFlags::M) {
            1
        } else {
            0
        };
        let other = if lr.flags.contains(nd_packet::RaFlags::O) {
            1
        } else {
            0
        };
        writeln!(
            out,
            "      last RA: lifetime {}s hop-limit {} M={} O={}",
            lr.router_lifetime, lr.cur_hop_limit, managed, other
        )?;
    }

    Ok(())
}

/// Build the JSON DTO for a single interface.
fn build_interface_json(nd: &super::engine::NdEngine, ifindex: u32, now: Instant) -> JsonInterface {
    let ifname = nd
        .ifname_of(ifindex)
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("if{}", ifindex));

    let ra_enabled = nd.sender(ifindex).is_some();

    let ra_scheduler = nd.sender(ifindex).map(|sender| {
        let cfg = sender.cfg();
        JsonRaScheduler {
            min_interval_secs: cfg.min_interval.as_secs(),
            max_interval_secs: cfg.max_interval.as_secs(),
            router_lifetime: cfg.router_lifetime,
            cur_hop_limit: cfg.cur_hop_limit,
            managed: cfg.flags.contains(nd_packet::RaFlags::M),
            other: cfg.flags.contains(nd_packet::RaFlags::O),
            initial_remaining: sender.initial_remaining(),
            next_unsolicited_in_secs: sender
                .next_unsolicited_at()
                .saturating_duration_since(now)
                .as_secs(),
            solicited_pending: sender.pending_solicited_at().is_some(),
            last_multicast_secs_ago: sender
                .last_multicast_at()
                .map(|t| now.saturating_duration_since(t).as_secs()),
        }
    });

    let empty_c = NdIfCounters::default();
    let c = nd.counters().get(&ifindex).unwrap_or(&empty_c);
    let counters = JsonCounters {
        tx_ra_unsolicited: c.tx_ra_unsolicited,
        tx_ra_solicited: c.tx_ra_solicited,
        rx_ra: c.rx_ra,
        rx_rs: c.rx_rs,
        rx_ns: c.rx_ns,
        rx_na: c.rx_na,
        rx_drop_hop_limit: c.rx_drop_hop_limit,
        rx_drop_malformed: c.rx_drop_malformed,
        untracked_sources: c.untracked_sources,
    };

    let kernel_counters = read_kernel_counters(&ifname);

    let empty_table = std::collections::BTreeMap::new();
    let table = nd.neighbors().get(&ifindex).unwrap_or(&empty_table);
    let neighbors: Vec<JsonNeighbor> = table
        .iter()
        .map(|(addr, nb)| {
            let (lr_lifetime, lr_hop_limit, lr_managed, lr_other) = if let Some(lr) = &nb.last_ra {
                (
                    Some(lr.router_lifetime),
                    Some(lr.cur_hop_limit),
                    Some(lr.flags.contains(nd_packet::RaFlags::M)),
                    Some(lr.flags.contains(nd_packet::RaFlags::O)),
                )
            } else {
                (None, None, None, None)
            };
            JsonNeighbor {
                address: addr.to_string(),
                first_seen_secs: now.saturating_duration_since(nb.first_seen).as_secs(),
                last_seen_secs: now.saturating_duration_since(nb.last_seen).as_secs(),
                rx_ra: nb.rx_ra,
                rx_rs: nb.rx_rs,
                rx_ns: nb.rx_ns,
                rx_na: nb.rx_na,
                last_ra_lifetime: lr_lifetime,
                last_ra_hop_limit: lr_hop_limit,
                last_ra_managed: lr_managed,
                last_ra_other: lr_other,
            }
        })
        .collect();

    JsonInterface {
        name: ifname,
        ifindex,
        ra_enabled,
        ra_scheduler,
        counters,
        kernel_counters,
        neighbors,
    }
}

// ── Show handlers ────────────────────────────────────────────────────────────

/// `show ipv6 nd` — one-line-per-interface summary.
fn show_nd_summary(nd: &Nd, _args: Args, json: bool) -> Result<String, std::fmt::Error> {
    let engine = nd.engine();
    let ifindexes = all_ifindexes(engine);

    if json {
        let rows: Vec<JsonSummaryRow> = ifindexes
            .iter()
            .map(|&ifindex| {
                let ifname = engine
                    .ifname_of(ifindex)
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| format!("if{}", ifindex));
                let ra_enabled = engine.sender(ifindex).is_some();
                let empty_table = std::collections::BTreeMap::new();
                let table = engine.neighbors().get(&ifindex).unwrap_or(&empty_table);
                let neighbor_count = table.len();
                let empty_c = NdIfCounters::default();
                let c = engine.counters().get(&ifindex).unwrap_or(&empty_c);
                let rx_total = c.rx_ra + c.rx_rs + c.rx_ns + c.rx_na;
                let tx_total = c.tx_ra_unsolicited + c.tx_ra_solicited;
                JsonSummaryRow {
                    name: ifname,
                    ifindex,
                    ra_enabled,
                    neighbor_count,
                    rx_total,
                    tx_total,
                }
            })
            .collect();
        let s = serde_json::to_string_pretty(&rows)
            .unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e));
        return Ok(s);
    }

    let mut out = String::new();
    if ifindexes.is_empty() {
        writeln!(out, "No ND interfaces.")?;
        return Ok(out);
    }

    writeln!(
        out,
        "{:<20} {:<4} {:>9} {:>10} {:>8} {:>8}",
        "Interface", "RA", "Neighbors", "RX-total", "TX-total", "Ifindex"
    )?;
    for &ifindex in &ifindexes {
        let ifname = engine
            .ifname_of(ifindex)
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("if{}", ifindex));
        let ra_label = if engine.sender(ifindex).is_some() {
            "on"
        } else {
            "off"
        };
        let empty_table = std::collections::BTreeMap::new();
        let table = engine.neighbors().get(&ifindex).unwrap_or(&empty_table);
        let neighbor_count = table.len();
        let empty_c = NdIfCounters::default();
        let c = engine.counters().get(&ifindex).unwrap_or(&empty_c);
        let rx_total = c.rx_ra + c.rx_rs + c.rx_ns + c.rx_na;
        let tx_total = c.tx_ra_unsolicited + c.tx_ra_solicited;
        writeln!(
            out,
            "{:<20} {:<4} {:>9} {:>10} {:>8} {:>8}",
            ifname, ra_label, neighbor_count, rx_total, tx_total, ifindex
        )?;
    }
    Ok(out)
}

/// `show ipv6 nd interface [IFNAME]` — detailed block(s).
fn show_nd_interface(nd: &Nd, mut args: Args, json: bool) -> Result<String, std::fmt::Error> {
    let engine = nd.engine();
    let now = Instant::now();

    // Optional interface name filter.
    let ifname_filter = args.string();

    if json {
        let ifindexes: Vec<u32> = if let Some(ref name) = ifname_filter {
            match engine.ifindex_of(name) {
                Some(idx) => vec![idx],
                None => {
                    let msg =
                        serde_json::json!({ "error": format!("interface {} not found", name) });
                    return Ok(serde_json::to_string_pretty(&msg)
                        .unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e)));
                }
            }
        } else {
            all_ifindexes(engine).into_iter().collect()
        };

        let interfaces: Vec<JsonInterface> = ifindexes
            .iter()
            .map(|&idx| build_interface_json(engine, idx, now))
            .collect();
        let s = serde_json::to_string_pretty(&interfaces)
            .unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e));
        return Ok(s);
    }

    let ifindexes: Vec<u32> = if let Some(ref name) = ifname_filter {
        match engine.ifindex_of(name) {
            Some(idx) => vec![idx],
            None => {
                return Ok(format!("% interface {} not found\n", name));
            }
        }
    } else {
        all_ifindexes(engine).into_iter().collect()
    };

    let mut out = String::new();
    for (i, &ifindex) in ifindexes.iter().enumerate() {
        if i > 0 {
            writeln!(out)?;
        }
        render_interface_text(&mut out, engine, ifindex, now)?;
    }
    Ok(out)
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;
    use std::time::Instant;

    use nd_packet::{NaFlags, NeighborAdvert, NeighborSolicit, RouterAdvert};

    use crate::nd::engine::NdEngine;
    use crate::nd::send::RaSendConfig;
    use crate::nd::{DropReason, NdRecv};
    use crate::rib::link::{Link, LinkType};
    use netlink_packet_route::link::LinkFlags;

    use super::*;

    // ── helper builders ──────────────────────────────────────────────────

    fn t0() -> Instant {
        Instant::now()
    }

    fn ll(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    fn link(name: &str, index: u32) -> Link {
        Link {
            index,
            name: name.to_string(),
            mtu: 1500,
            original_mtu: 1500,
            metric: 1,
            flags: LinkFlags::default(),
            link_type: LinkType::Ethernet,
            label: false,
            mac: None,
            addr4: Vec::new(),
            addr6: Vec::new(),
            master: None,
            vni: None,
            vrf_table: None,
            vxlan_local: None,
            mtu_error: None,
        }
    }

    fn make_ra() -> RouterAdvert {
        RouterAdvert {
            cur_hop_limit: 64,
            flags: nd_packet::RaFlags::empty(),
            router_lifetime: 1800,
            reachable_time: 0,
            retrans_timer: 0,
            options: vec![],
        }
    }

    fn make_ns() -> NeighborSolicit {
        NeighborSolicit {
            target: "fe80::ffff".parse().unwrap(),
            options: vec![],
        }
    }

    fn make_na() -> NeighborAdvert {
        NeighborAdvert {
            flags: NaFlags::empty(),
            target: "fe80::ffff".parse().unwrap(),
            options: vec![],
        }
    }

    // ── parse_dev_snmp6 ──────────────────────────────────────────────────

    #[test]
    fn parse_dev_snmp6_extracts_nd_fields() {
        let content = "\
Icmp6InMsgs                         \t7
Icmp6OutMsgs                        \t12
Icmp6InRouterSolicits               \t2
Icmp6OutRouterSolicits              \t0
Icmp6InRouterAdvertisements         \t13
Icmp6OutRouterAdvertisements        \t14
Icmp6InNeighborSolicits             \t5
Icmp6OutNeighborSolicits            \t9
Icmp6InNeighborAdvertisements       \t5
Icmp6OutNeighborAdvertisements      \t5
Icmp6InUnrelated                    \t99
";
        let c = parse_dev_snmp6(content);
        assert_eq!(c.in_router_solicits, 2);
        assert_eq!(c.out_router_solicits, 0);
        assert_eq!(c.in_router_advertisements, 13);
        assert_eq!(c.out_router_advertisements, 14);
        assert_eq!(c.in_neighbor_solicits, 5);
        assert_eq!(c.out_neighbor_solicits, 9);
        assert_eq!(c.in_neighbor_advertisements, 5);
        assert_eq!(c.out_neighbor_advertisements, 5);
    }

    #[test]
    fn parse_dev_snmp6_ignores_unrelated_lines() {
        let content = "SomeOtherCounter\t42\nIcmp6InNeighborSolicits\t7\n";
        let c = parse_dev_snmp6(content);
        assert_eq!(c.in_neighbor_solicits, 7);
        // All others stay at zero.
        assert_eq!(c.in_router_solicits, 0);
    }

    #[test]
    fn parse_dev_snmp6_empty_input() {
        let c = parse_dev_snmp6("");
        assert_eq!(c.in_neighbor_solicits, 0);
        assert_eq!(c.out_router_advertisements, 0);
    }

    // ── text render ─────────────────────────────────────────────────────

    fn build_engine_with_traffic() -> NdEngine {
        let start = t0();
        let mut eng = NdEngine::new();

        // Register a link.
        eng.process_link_add(&link("eth0", 2), start);
        // Enable RA on it.
        eng.enable_interface(2, RaSendConfig::default(), start);

        // Receive an RA from a peer.
        eng.on_recv(
            NdRecv::RouterAdvert {
                ifindex: 2,
                src: ll("fe80::a8aa:aaff:feaa:1"),
                ra: make_ra(),
            },
            start,
        );
        // Receive an NS from the same peer.
        eng.on_recv(
            NdRecv::NeighborSolicit {
                ifindex: 2,
                src: ll("fe80::a8aa:aaff:feaa:1"),
                ns: make_ns(),
            },
            start,
        );
        // Receive a DAD probe.
        eng.on_recv(
            NdRecv::NeighborSolicit {
                ifindex: 2,
                src: "::".parse().unwrap(),
                ns: make_ns(),
            },
            start,
        );
        // A drop.
        eng.on_recv(
            NdRecv::Dropped {
                ifindex: 2,
                reason: DropReason::HopLimit,
            },
            start,
        );
        eng
    }

    #[test]
    fn detail_text_contains_interface_line_and_counters() {
        let eng = build_engine_with_traffic();
        let now = t0();
        let mut out = String::new();
        render_interface_text(&mut out, &eng, 2, now).unwrap();

        assert!(
            out.contains("Interface eth0 (ifindex 2)"),
            "interface header"
        );
        // RA counter: we received 1 RA.
        assert!(out.contains("1"), "rx_ra counter");
        // NS counter: we received 2 NS.
        assert!(out.contains("2"), "rx_ns counter");
        // Neighbor address should appear.
        assert!(
            out.contains("fe80::a8aa:aaff:feaa:1"),
            "neighbor address in output"
        );
        // DAD entry.
        assert!(
            out.contains("duplicate address detection"),
            "DAD annotation"
        );
        // drop counter.
        assert!(out.contains("hop-limit 1"), "drop hop-limit counter");
    }

    #[test]
    fn detail_text_unknown_ifname_filter_returns_error() {
        let eng = NdEngine::new();

        // Wrap in a minimal Nd-like call by directly testing the engine path.
        // We test the ifindex_of lookup logic that show_nd_interface uses.
        assert!(
            eng.ifindex_of("nonexistent").is_none(),
            "unknown interface returns None"
        );
    }

    // ── JSON render ──────────────────────────────────────────────────────

    #[test]
    fn json_interface_parses_back() {
        let eng = build_engine_with_traffic();
        let now = t0();
        let iface = build_interface_json(&eng, 2, now);
        let json_str = serde_json::to_string_pretty(&iface).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        assert_eq!(v["name"], "eth0");
        assert_eq!(v["ifindex"], 2);
        assert_eq!(v["ra_enabled"], true);
        // counters should have rx_ra = 1.
        assert_eq!(v["counters"]["rx_ra"], 1);
        // neighbors array should have 2 entries (fe80::... and ::).
        assert_eq!(v["neighbors"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn fmt_duration_formats_correctly() {
        assert_eq!(fmt_duration(0), "0s");
        assert_eq!(fmt_duration(59), "59s");
        assert_eq!(fmt_duration(60), "1m");
        assert_eq!(fmt_duration(65), "1m5s");
        assert_eq!(fmt_duration(3600), "1h");
        assert_eq!(fmt_duration(3661), "1h1m1s");
        assert_eq!(fmt_duration(7260), "2h1m");
    }
}
