//! Redistribute filter registry and walk-and-replay.
//!
//! Owns the per-(proto, AFI, rtype) subtype filter sets, the one-shot
//! FIB walker that pushes the current matching set at subscription
//! time, and the steady-state delta hook that fires from
//! `ipv{4,6}_route_{add,del}` after a mutation flips the selected
//! entry. Self-route filtering is enforced unconditionally — a
//! subscription whose `proto` maps to its own `rtype` is silently
//! dropped at registration time.
//!
//! Known gap: nexthop-resolution-driven selection changes that don't
//! flow through `ipv{4,6}_route_{add,del}` (e.g. the debounced
//! `ipv4_route_resolve` path) are not yet hooked. The initial walk
//! at subscription time still covers those, but they won't update
//! in steady state until a follow-up generalizes the hook.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use ipnet::{Ipv4Net, Ipv6Net};
use prefix_trie::PrefixMap;
use tokio::sync::mpsc::UnboundedSender;

use super::api::RibRx;
use super::client::ClientRegistry;
use super::entry::{RibEntries, RibEntry};
use super::nexthop::Nexthop;
use super::types::{
    BulkPhase, REDIST_BATCH_MAX, RedistAfi, RibSubType, RibType, RouteBatch, RouteEntryV4,
    RouteEntryV6,
};

/// Per-(AFI, rtype) subtype filter. Empty set = wildcard (match every
/// subtype under `rtype`).
pub type FilterMap = BTreeMap<(RedistAfi, RibType), BTreeSet<RibSubType>>;

/// Map a `RibType` back to the protocol identifier that owns it.
/// Used for the unconditional self-route filter — a subscriber whose
/// proto matches a route's owning protocol never receives that route.
/// Returns `None` for rtypes that aren't owned by a registerable
/// protocol (kernel, connected, static, dhcp, other) — those are
/// always deliverable.
pub fn proto_for_rtype(rtype: RibType) -> Option<&'static str> {
    match rtype {
        RibType::Bgp => Some("bgp"),
        RibType::Isis => Some("isis"),
        RibType::Ospf => Some("ospf"),
        _ => None,
    }
}

/// Whether a route owned by `rtype` is deliverable to a subscriber
/// running under `proto`. Self-route filter — unconditional, never
/// configurable.
pub fn deliverable(proto: &str, rtype: RibType) -> bool {
    proto_for_rtype(rtype).is_none_or(|owner| owner != proto)
}

/// Whether a route with the given `subtype` matches a filter row.
/// Empty filter set is wildcard.
pub fn subtype_matches(filter: &BTreeSet<RibSubType>, subtype: &RibSubType) -> bool {
    filter.is_empty() || filter.contains(subtype)
}

/// Direction of the bulk push — produces either `RouteAdd` or
/// `RouteDel` for each batched chunk.
#[derive(Debug, Clone, Copy)]
pub enum WalkOp {
    Add,
    Del,
}

/// Walk the IPv4 FIB and push every matching route to `tx`. Sends one
/// or more `RouteAdd`/`RouteDel { bulk: More }` messages of up to
/// `REDIST_BATCH_MAX` entries, then a final `{ bulk: Eor }` (even if
/// the last chunk would otherwise be empty) so the consumer knows the
/// replay is done.
pub fn walk_v4(
    table: &PrefixMap<Ipv4Net, RibEntries>,
    proto: &str,
    rtype: RibType,
    subtype_filter: &BTreeSet<RibSubType>,
    op: WalkOp,
    tx: &UnboundedSender<RibRx>,
) {
    let mut buf: Vec<RouteEntryV4> = Vec::with_capacity(REDIST_BATCH_MAX);
    for (prefix, entries) in table.iter() {
        let Some(entry) = pick_entry(entries, rtype, subtype_filter) else {
            continue;
        };
        if !deliverable(proto, entry.rtype) {
            continue;
        }
        let Some(nh4) = first_v4_nexthop(&entry.nexthop) else {
            continue;
        };
        buf.push(RouteEntryV4 {
            prefix: *prefix,
            nexthop: nh4,
            subtype: entry.rsubtype.clone(),
            metric: entry.metric,
            tag: 0,
            ifindex: entry.ifindex,
        });
        if buf.len() >= REDIST_BATCH_MAX {
            flush_v4(&mut buf, rtype, op, BulkPhase::More, tx);
        }
    }
    // Final flush carrying Eor. Even an empty residual buf needs an
    // Eor marker so the consumer can complete its replay state.
    flush_v4(&mut buf, rtype, op, BulkPhase::Eor, tx);
}

/// IPv6 sibling of `walk_v4`. Same chunking + EoR semantics.
pub fn walk_v6(
    table: &PrefixMap<Ipv6Net, RibEntries>,
    proto: &str,
    rtype: RibType,
    subtype_filter: &BTreeSet<RibSubType>,
    op: WalkOp,
    tx: &UnboundedSender<RibRx>,
) {
    let mut buf: Vec<RouteEntryV6> = Vec::with_capacity(REDIST_BATCH_MAX);
    for (prefix, entries) in table.iter() {
        let Some(entry) = pick_entry(entries, rtype, subtype_filter) else {
            continue;
        };
        if !deliverable(proto, entry.rtype) {
            continue;
        }
        let Some(nh6) = first_v6_nexthop(&entry.nexthop) else {
            continue;
        };
        buf.push(RouteEntryV6 {
            prefix: *prefix,
            nexthop: nh6,
            subtype: entry.rsubtype.clone(),
            metric: entry.metric,
            tag: 0,
            ifindex: entry.ifindex,
        });
        if buf.len() >= REDIST_BATCH_MAX {
            flush_v6(&mut buf, rtype, op, BulkPhase::More, tx);
        }
    }
    flush_v6(&mut buf, rtype, op, BulkPhase::Eor, tx);
}

/// Pick the first `RibEntries` row that's both selected (so the
/// replay reflects FIB-installed state, not shadowed alternates) and
/// matches the `(rtype, subtype-filter)` predicate.
fn pick_entry<'a>(
    entries: &'a RibEntries,
    rtype: RibType,
    subtype_filter: &BTreeSet<RibSubType>,
) -> Option<&'a super::entry::RibEntry> {
    entries.iter().find(|e| {
        e.is_selected() && e.rtype == rtype && subtype_matches(subtype_filter, &e.rsubtype)
    })
}

/// Resolve the first IPv4 nexthop address from a Nexthop. Returns
/// `None` for Link-only (connected) or empty / non-v4 Multi/List —
/// callers skip the route in that case rather than emit a malformed
/// entry.
fn first_v4_nexthop(nh: &Nexthop) -> Option<std::net::Ipv4Addr> {
    match nh {
        Nexthop::Uni(uni) => match uni.addr {
            std::net::IpAddr::V4(a) => Some(a),
            _ => None,
        },
        Nexthop::Multi(m) => m.nexthops.first().and_then(|u| match u.addr {
            std::net::IpAddr::V4(a) => Some(a),
            _ => None,
        }),
        Nexthop::List(l) => l.nexthops.first().and_then(|m| match m {
            super::nexthop::NexthopMember::Uni(u) => match u.addr {
                std::net::IpAddr::V4(a) => Some(a),
                _ => None,
            },
            super::nexthop::NexthopMember::Multi(mm) => {
                mm.nexthops.first().and_then(|u| match u.addr {
                    std::net::IpAddr::V4(a) => Some(a),
                    _ => None,
                })
            }
        }),
        Nexthop::Link(_) => None,
    }
}

fn first_v6_nexthop(nh: &Nexthop) -> Option<std::net::Ipv6Addr> {
    match nh {
        Nexthop::Uni(uni) => match uni.addr {
            std::net::IpAddr::V6(a) => Some(a),
            _ => None,
        },
        Nexthop::Multi(m) => m.nexthops.first().and_then(|u| match u.addr {
            std::net::IpAddr::V6(a) => Some(a),
            _ => None,
        }),
        Nexthop::List(l) => l.nexthops.first().and_then(|m| match m {
            super::nexthop::NexthopMember::Uni(u) => match u.addr {
                std::net::IpAddr::V6(a) => Some(a),
                _ => None,
            },
            super::nexthop::NexthopMember::Multi(mm) => {
                mm.nexthops.first().and_then(|u| match u.addr {
                    std::net::IpAddr::V6(a) => Some(a),
                    _ => None,
                })
            }
        }),
        Nexthop::Link(_) => None,
    }
}

fn flush_v4(
    buf: &mut Vec<RouteEntryV4>,
    rtype: RibType,
    op: WalkOp,
    bulk: BulkPhase,
    tx: &UnboundedSender<RibRx>,
) {
    let routes = RouteBatch::V4(std::mem::take(buf));
    let msg = match op {
        WalkOp::Add => RibRx::RouteAdd {
            rtype,
            routes,
            bulk,
        },
        WalkOp::Del => RibRx::RouteDel {
            rtype,
            routes,
            bulk,
        },
    };
    let _ = tx.send(msg);
}

fn flush_v6(
    buf: &mut Vec<RouteEntryV6>,
    rtype: RibType,
    op: WalkOp,
    bulk: BulkPhase,
    tx: &UnboundedSender<RibRx>,
) {
    let routes = RouteBatch::V6(std::mem::take(buf));
    let msg = match op {
        WalkOp::Add => RibRx::RouteAdd {
            rtype,
            routes,
            bulk,
        },
        WalkOp::Del => RibRx::RouteDel {
            rtype,
            routes,
            bulk,
        },
    };
    let _ = tx.send(msg);
}

// ---- steady-state delta notification --------------------------------
//
// Called from the route_{add,del} entry points after a FIB mutation
// has updated the selected entry. Compares the before/after selected
// entries per subscriber and emits single-entry RouteAdd / RouteDel
// messages for each filter row that's affected.
//
// Known gap: nexthop-resolution-driven selection changes that don't
// flow through `ipv{4,6}_route_{add,del}` (e.g. the debounced
// `ipv4_route_resolve` path) are not yet hooked. The initial walk
// at subscription time still covers those, but they won't update
// in steady state until step 4 generalizes the hook.

fn build_v4_entry(prefix: &Ipv4Net, e: &RibEntry) -> Option<RouteEntryV4> {
    let nh = first_v4_nexthop(&e.nexthop)?;
    Some(RouteEntryV4 {
        prefix: *prefix,
        nexthop: nh,
        subtype: e.rsubtype.clone(),
        metric: e.metric,
        tag: 0,
        ifindex: e.ifindex,
    })
}

fn build_v6_entry(prefix: &Ipv6Net, e: &RibEntry) -> Option<RouteEntryV6> {
    let nh = first_v6_nexthop(&e.nexthop)?;
    Some(RouteEntryV6 {
        prefix: *prefix,
        nexthop: nh,
        subtype: e.rsubtype.clone(),
        metric: e.metric,
        tag: 0,
        ifindex: e.ifindex,
    })
}

/// Notify every default-VRF subscriber whose filter matches the
/// before/after transition of the selected entry at `prefix`. Single-
/// entry batches, `bulk: More`. EoR is reserved for initial walk /
/// `Redist{Add,Update,Del}` replays — steady-state never emits Eor.
///
/// VRF-attached subscribers (`vrf_id != 0`) are skipped here because
/// `notify_v*_delta` is called from the default-VRF route paths
/// (`Rib::ipv*_route_{add,del}` on `self.table` / `self.table_v6`).
/// The per-VRF resolve + select pipeline that lands in step 18 will
/// install a sibling hook that walks `vrf_tables[vrf_id]` and pushes
/// to subscribers bound to that VRF.
pub fn notify_v4_delta(
    filters: &HashMap<String, FilterMap>,
    registry: &ClientRegistry,
    prefix: &Ipv4Net,
    before: Option<&RibEntry>,
    after: Option<&RibEntry>,
) {
    if before.is_none() && after.is_none() {
        return;
    }
    for (proto, filter_map) in filters {
        let Some(sub) = registry.subscriber_for_proto(proto) else {
            continue;
        };
        if sub.vrf_id != 0 {
            continue;
        }
        let tx = &sub.rib_rx_tx;
        // For each (afi, rtype) row this proto has — only IPv4 rows
        // apply here, and only those whose rtype matches at least one
        // side of the transition.
        for ((afi, rtype), subtypes) in filter_map {
            if *afi != RedistAfi::Ipv4 {
                continue;
            }
            let old = entry_for_subscriber_v4(prefix, before, *rtype, subtypes, proto);
            let new = entry_for_subscriber_v4(prefix, after, *rtype, subtypes, proto);
            emit_v4_diff(tx, *rtype, old, new);
        }
    }
}

pub fn notify_v6_delta(
    filters: &HashMap<String, FilterMap>,
    registry: &ClientRegistry,
    prefix: &Ipv6Net,
    before: Option<&RibEntry>,
    after: Option<&RibEntry>,
) {
    if before.is_none() && after.is_none() {
        return;
    }
    for (proto, filter_map) in filters {
        let Some(sub) = registry.subscriber_for_proto(proto) else {
            continue;
        };
        if sub.vrf_id != 0 {
            continue;
        }
        let tx = &sub.rib_rx_tx;
        for ((afi, rtype), subtypes) in filter_map {
            if *afi != RedistAfi::Ipv6 {
                continue;
            }
            let old = entry_for_subscriber_v6(prefix, before, *rtype, subtypes, proto);
            let new = entry_for_subscriber_v6(prefix, after, *rtype, subtypes, proto);
            emit_v6_diff(tx, *rtype, old, new);
        }
    }
}

/// Build the delivered `RouteEntryV4` only when the source entry
/// matches the subscriber's filter row (rtype, subtype, deliverable).
/// Returns `None` when no entry should be delivered.
fn entry_for_subscriber_v4(
    prefix: &Ipv4Net,
    entry: Option<&RibEntry>,
    rtype: RibType,
    subtypes: &BTreeSet<RibSubType>,
    proto: &str,
) -> Option<RouteEntryV4> {
    let e = entry?;
    if e.rtype != rtype {
        return None;
    }
    if !deliverable(proto, e.rtype) {
        return None;
    }
    if !subtype_matches(subtypes, &e.rsubtype) {
        return None;
    }
    build_v4_entry(prefix, e)
}

fn entry_for_subscriber_v6(
    prefix: &Ipv6Net,
    entry: Option<&RibEntry>,
    rtype: RibType,
    subtypes: &BTreeSet<RibSubType>,
    proto: &str,
) -> Option<RouteEntryV6> {
    let e = entry?;
    if e.rtype != rtype {
        return None;
    }
    if !deliverable(proto, e.rtype) {
        return None;
    }
    if !subtype_matches(subtypes, &e.rsubtype) {
        return None;
    }
    build_v6_entry(prefix, e)
}

fn emit_v4_diff(
    tx: &UnboundedSender<RibRx>,
    rtype: RibType,
    old: Option<RouteEntryV4>,
    new: Option<RouteEntryV4>,
) {
    match (old, new) {
        (None, None) => {}
        (Some(o), None) => send_v4_one(tx, rtype, WalkOp::Del, o),
        (None, Some(n)) => send_v4_one(tx, rtype, WalkOp::Add, n),
        (Some(o), Some(n)) if o == n => {}
        (Some(o), Some(n)) => {
            send_v4_one(tx, rtype, WalkOp::Del, o);
            send_v4_one(tx, rtype, WalkOp::Add, n);
        }
    }
}

fn emit_v6_diff(
    tx: &UnboundedSender<RibRx>,
    rtype: RibType,
    old: Option<RouteEntryV6>,
    new: Option<RouteEntryV6>,
) {
    match (old, new) {
        (None, None) => {}
        (Some(o), None) => send_v6_one(tx, rtype, WalkOp::Del, o),
        (None, Some(n)) => send_v6_one(tx, rtype, WalkOp::Add, n),
        (Some(o), Some(n)) if o == n => {}
        (Some(o), Some(n)) => {
            send_v6_one(tx, rtype, WalkOp::Del, o);
            send_v6_one(tx, rtype, WalkOp::Add, n);
        }
    }
}

fn send_v4_one(tx: &UnboundedSender<RibRx>, rtype: RibType, op: WalkOp, entry: RouteEntryV4) {
    let routes = RouteBatch::V4(vec![entry]);
    let msg = match op {
        WalkOp::Add => RibRx::RouteAdd {
            rtype,
            routes,
            bulk: BulkPhase::More,
        },
        WalkOp::Del => RibRx::RouteDel {
            rtype,
            routes,
            bulk: BulkPhase::More,
        },
    };
    let _ = tx.send(msg);
}

fn send_v6_one(tx: &UnboundedSender<RibRx>, rtype: RibType, op: WalkOp, entry: RouteEntryV6) {
    let routes = RouteBatch::V6(vec![entry]);
    let msg = match op {
        WalkOp::Add => RibRx::RouteAdd {
            rtype,
            routes,
            bulk: BulkPhase::More,
        },
        WalkOp::Del => RibRx::RouteDel {
            rtype,
            routes,
            bulk: BulkPhase::More,
        },
    };
    let _ = tx.send(msg);
}
