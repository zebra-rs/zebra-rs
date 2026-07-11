//! `show ebpf <table>` / `show ebpf stats` rendering: the engine's gRPC
//! responses are already structured (typed `DumpEntry` / `StatEntry`
//! protobuf), so both the terminal tables and the `json` form render from
//! the same data here — the text output mirrors cradle's own
//! `cradle dump` / `cradle stats` CLI column-for-column.

use std::fmt::Write;

use crate::fib::cradle::pb;

// Data-plane ABI flag mirrors (`cradle_common::FDB_F_*` / `FIB_F_*` /
// `NH_F_*`), kept local like `fib/cradle.rs`'s `FIB_F_ECMP` so this file
// has no dependency on the cradle crates.
const FDB_F_LOCAL: u32 = 1 << 0;
const FDB_F_REMOTE: u32 = 1 << 1;
const FIB_F_BLACKHOLE: u32 = 1 << 0;
const FIB_F_LOCAL: u32 = 1 << 1;
const FIB_F_CONNECTED: u32 = 1 << 2;
const FIB_F_ECMP: u32 = 1 << 3;
const NH_F_V6: u32 = 1 << 0;
const NH_F_ONLINK: u32 = 1 << 1;
const NH_F_MPLS: u32 = 1 << 2;
const NH_F_SRV6: u32 = 1 << 3;
const NH_F_GTP: u32 = 1 << 4;

/// Human-readable `FDB_F_*` summary (mirrors cradle's `ctl` output:
/// no flag bit = a datapath-learned entry).
fn fdb_flags(flags: u32) -> String {
    let mut v = Vec::new();
    if flags & FDB_F_LOCAL != 0 {
        v.push("local");
    }
    if flags & FDB_F_REMOTE != 0 {
        v.push("remote");
    }
    if v.is_empty() {
        "learned".to_string()
    } else {
        v.join(",")
    }
}

fn fib_flag_names(flags: u32) -> Vec<&'static str> {
    let mut v = Vec::new();
    if flags & FIB_F_BLACKHOLE != 0 {
        v.push("blackhole");
    }
    if flags & FIB_F_LOCAL != 0 {
        v.push("local");
    }
    if flags & FIB_F_CONNECTED != 0 {
        v.push("connected");
    }
    if flags & FIB_F_ECMP != 0 {
        v.push("ecmp");
    }
    v
}

fn fib_flags(flags: u32) -> String {
    let v = fib_flag_names(flags);
    if v.is_empty() {
        "-".to_string()
    } else {
        v.join(",")
    }
}

fn nh_flag_names(flags: u32) -> Vec<&'static str> {
    let mut v = Vec::new();
    if flags & NH_F_V6 != 0 {
        v.push("v6");
    }
    if flags & NH_F_ONLINK != 0 {
        v.push("onlink");
    }
    if flags & NH_F_MPLS != 0 {
        v.push("mpls");
    }
    if flags & NH_F_SRV6 != 0 {
        v.push("srv6");
    }
    if flags & NH_F_GTP != 0 {
        v.push("gtp");
    }
    v
}

fn nh_flags(flags: u32) -> String {
    let v = nh_flag_names(flags);
    if v.is_empty() {
        "-".to_string()
    } else {
        v.join(",")
    }
}

/// Format a resolved nexthop as `via <gw> dev if<oif> [labels …]`.
fn nh_str(nh: &Option<pb::NexthopInfo>) -> String {
    let Some(n) = nh else {
        return String::new();
    };
    let mut s = String::new();
    if !n.gateway.is_empty() {
        s.push_str(&format!("via {} ", n.gateway));
    }
    s.push_str(&format!("dev if{}", n.oif));
    if !n.labels.is_empty() {
        s.push_str(&format!(" labels {:?}", n.labels));
    }
    s
}

/// A resolved nexthop as a JSON object (`null` when unresolved / ECMP id).
fn nh_json(nh: &Option<pb::NexthopInfo>) -> serde_json::Value {
    match nh {
        Some(n) => serde_json::json!({
            "id": n.id,
            "gateway": if n.gateway.is_empty() { None } else { Some(&n.gateway) },
            "oif": n.oif,
            "labels": n.labels,
            "flags": nh_flag_names(n.flags),
        }),
        None => serde_json::Value::Null,
    }
}

/// Render a `Dump` stream. Text mirrors `cradle dump <table>`; `json` is an
/// array of typed entry objects.
pub(super) fn render_dump(entries: &[pb::DumpEntry], json: bool) -> String {
    use pb::dump_entry::Entry;

    if json {
        let items: Vec<serde_json::Value> = entries
            .iter()
            .filter_map(|e| e.entry.as_ref())
            .map(|e| match e {
                Entry::Fdb(f) => serde_json::json!({
                    "type": "fdb",
                    "mac": f.mac,
                    "vlan": f.vlan,
                    "oif": f.oif,
                    "flags": if f.flags == 0 { vec!["learned"] } else {
                        let mut v = Vec::new();
                        if f.flags & FDB_F_LOCAL != 0 { v.push("local"); }
                        if f.flags & FDB_F_REMOTE != 0 { v.push("remote"); }
                        v
                    },
                    "remoteSid": if f.remote_sid.is_empty() { None } else { Some(&f.remote_sid) },
                    "ageMs": f.age_ms,
                }),
                Entry::Fib(r) => serde_json::json!({
                    "type": "fib",
                    "prefix": r.prefix,
                    "vrf": r.vrf,
                    "nexthopId": r.nexthop_id,
                    "flags": fib_flag_names(r.flags),
                    "nexthop": nh_json(&r.nh),
                }),
                Entry::Mpls(m) => serde_json::json!({
                    "type": "mpls",
                    "label": m.label,
                    "op": m.op,
                    "nexthopId": m.nexthop_id,
                    "vrf": m.vrf,
                    "nexthop": nh_json(&m.nh),
                }),
                Entry::Srv6Localsid(s) => serde_json::json!({
                    "type": "srv6LocalSid",
                    "sid": s.sid,
                    "prefixLen": s.prefix_len,
                    "behavior": s.behavior,
                    "flavors": s.flavors,
                    "vrf": s.vrf,
                    "nexthopId": s.nexthop_id,
                    "nexthop": nh_json(&s.nh),
                }),
                Entry::Srv6Encap(en) => serde_json::json!({
                    "type": "srv6Encap",
                    "nexthopId": en.nexthop_id,
                    "mode": en.mode,
                    "segs": en.segs,
                }),
                Entry::Nexthop(n) => {
                    if n.group.is_empty() {
                        serde_json::json!({
                            "type": "nexthop",
                            "id": n.id,
                            "gateway": if n.gateway.is_empty() { None } else { Some(&n.gateway) },
                            "oif": n.oif,
                            "flags": nh_flag_names(n.flags),
                            "labels": n.labels,
                            "backupId": n.backup_id,
                        })
                    } else {
                        serde_json::json!({
                            "type": "nexthopGroup",
                            "id": n.id,
                            "members": n.group,
                        })
                    }
                }
            })
            .collect();
        return serde_json::Value::Array(items).to_string();
    }

    let mut out = String::new();
    let mut header = false;
    for entry in entries {
        let Some(e) = entry.entry.as_ref() else {
            continue;
        };
        match e {
            Entry::Fdb(f) => {
                if !header {
                    writeln!(
                        out,
                        "{:<18} {:>5} {:>8} {:<8} {:>9} remote_sid",
                        "mac", "vlan", "oif", "flags", "age_ms"
                    )
                    .unwrap();
                    header = true;
                }
                writeln!(
                    out,
                    "{:<18} {:>5} {:>8} {:<8} {:>9} {}",
                    f.mac,
                    f.vlan,
                    f.oif,
                    fdb_flags(f.flags),
                    f.age_ms,
                    f.remote_sid
                )
                .unwrap();
            }
            Entry::Fib(r) => {
                if !header {
                    writeln!(
                        out,
                        "{:<20} {:>4} {:>7} {:<10} nexthop",
                        "prefix", "vrf", "nh_id", "flags"
                    )
                    .unwrap();
                    header = true;
                }
                writeln!(
                    out,
                    "{:<20} {:>4} {:>7} {:<10} {}",
                    r.prefix,
                    r.vrf,
                    r.nexthop_id,
                    fib_flags(r.flags),
                    nh_str(&r.nh)
                )
                .unwrap();
            }
            Entry::Mpls(m) => {
                if !header {
                    writeln!(
                        out,
                        "{:>8} {:<7} {:>7} {:>4} nexthop",
                        "label", "op", "nh_id", "vrf"
                    )
                    .unwrap();
                    header = true;
                }
                writeln!(
                    out,
                    "{:>8} {:<7} {:>7} {:>4} {}",
                    m.label,
                    m.op,
                    m.nexthop_id,
                    m.vrf,
                    nh_str(&m.nh)
                )
                .unwrap();
            }
            Entry::Srv6Localsid(s) => {
                writeln!(
                    out,
                    "localsid {}/{:<3} {:<14} flavors={} vrf={} nh_id={} {}",
                    s.sid,
                    s.prefix_len,
                    s.behavior,
                    s.flavors,
                    s.vrf,
                    s.nexthop_id,
                    nh_str(&s.nh)
                )
                .unwrap();
            }
            Entry::Srv6Encap(en) => {
                writeln!(
                    out,
                    "encap    nh_id={} mode={} segs=[{}]",
                    en.nexthop_id,
                    en.mode,
                    en.segs.join(", ")
                )
                .unwrap();
            }
            Entry::Nexthop(n) => {
                if !header {
                    writeln!(
                        out,
                        "{:>7} {:<26} {:>5} {:<14} {:>7} labels",
                        "nh_id", "gateway", "oif", "flags", "backup"
                    )
                    .unwrap();
                    header = true;
                }
                if !n.group.is_empty() {
                    writeln!(out, "{:>7} group members {:?}", n.id, n.group).unwrap();
                } else {
                    writeln!(
                        out,
                        "{:>7} {:<26} {:>5} {:<14} {:>7} {}",
                        n.id,
                        if n.gateway.is_empty() {
                            "-"
                        } else {
                            n.gateway.as_str()
                        },
                        n.oif,
                        nh_flags(n.flags),
                        n.backup_id,
                        if n.labels.is_empty() {
                            String::new()
                        } else {
                            format!("{:?}", n.labels)
                        },
                    )
                    .unwrap();
                }
            }
        }
    }
    if entries.is_empty() {
        out.push_str("(empty)\n");
    }
    out
}

/// Render `GetStats`. Text mirrors `cradle stats` (`name packets` per
/// line); `json` is an object keyed by counter name.
pub(super) fn render_stats(entries: &[pb::StatEntry], json: bool) -> String {
    if json {
        let map: serde_json::Map<String, serde_json::Value> = entries
            .iter()
            .map(|e| (e.name.clone(), serde_json::json!(e.packets)))
            .collect();
        return serde_json::Value::Object(map).to_string();
    }
    let mut out = String::new();
    for e in entries {
        writeln!(out, "{:<14} {}", e.name, e.packets).unwrap();
    }
    out
}
