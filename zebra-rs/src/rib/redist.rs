//! Redistribute filter registry and walk-and-replay.
//!
//! Owns the per-(proto, AFI, rtype) subtype filter sets and the
//! one-shot FIB walker that pushes matching routes to a subscriber.
//! Self-route filtering is enforced here unconditionally — a
//! subscription whose `proto` maps to its own `rtype` is silently
//! dropped at registration time.
//!
//! Sender side only; the steady-state delta hook that fires on
//! FIB churn is a follow-up.

use std::collections::{BTreeMap, BTreeSet};

use ipnet::{Ipv4Net, Ipv6Net};
use prefix_trie::PrefixMap;
use tokio::sync::mpsc::UnboundedSender;

use super::api::RibRx;
use super::entry::RibEntries;
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
