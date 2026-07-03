//! Redistribute filter registry and walk-and-replay.
//!
//! Owns the per-(proto, AFI, rtype) subtype filter sets, the one-shot
//! FIB walker that pushes the current matching set at subscription
//! time, and the steady-state delta hook. Self-route filtering is
//! enforced unconditionally — a subscription whose `proto` maps to its
//! own `rtype` is silently dropped at registration time.
//!
//! Two triggers feed the steady-state delta hook, both via
//! `notify_v{4,6}_delta`:
//!   - explicit route add/del — `ipv{4,6}_route_{add,del}` snapshot the
//!     selected entry before/after the mutation;
//!   - resolution / topology change — `ipv{4,6}_route_sync_collect`
//!     reports per-prefix selected-entry transitions, which
//!     `Rib::ipv{4,6}_default_sync` forwards. This closes the former
//!     gap where a redistributed route stranded in the advertisement
//!     after its nexthop became (un)resolvable via the debounced
//!     resolve / link up-down / address add-del paths.
//!
//! Both the default table and per-VRF tables feed the hook:
//! `notify_v{4,6}_delta` takes a `target_vrf_id` and delivers only to
//! subscribers bound to that VRF. The default-VRF route paths pass
//! `0`; the per-VRF paths (`ipv{4,6}_route_{add,del}_vrf` /
//! `ipv{4,6}_vrf_sync` on `vrf_tables[table_id]`) pass that table id.
//! The initial walk-and-replay (`redist_walk`) likewise selects the
//! subscriber's table from its recorded `vrf_id`.

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
        if !redistributable_v4(&prefix) {
            continue;
        }
        // Connected (directly-attached) routes carry an interface-only
        // nexthop with no gateway IP, so `first_v4_nexthop` yields None.
        // Redistribution still wants the prefix — the consumer
        // re-originates it with its own nexthop / forwarding address —
        // so deliver with a 0.0.0.0 placeholder instead of dropping.
        let nh4 = first_v4_nexthop(&entry.nexthop).unwrap_or(std::net::Ipv4Addr::UNSPECIFIED);
        buf.push(RouteEntryV4 {
            prefix,
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
        if !redistributable_v6(&prefix) {
            continue;
        }
        // See `walk_v4`: connected routes have no gateway IP; deliver
        // them with a :: placeholder rather than dropping the prefix.
        let nh6 = first_v6_nexthop(&entry.nexthop).unwrap_or(std::net::Ipv6Addr::UNSPECIFIED);
        buf.push(RouteEntryV6 {
            prefix,
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

/// True when a prefix is eligible for redistribution into a routing
/// protocol. Loopback (127.0.0.0/8) and link-local (169.254.0.0/16)
/// addresses appear as connected routes but must never be advertised —
/// they're not routable beyond the local host. Mirrors the Router-LSA
/// builder's 127.x skip, but here it also guards Type-5 / NSSA Type-7
/// origination and every other redistribute consumer.
fn redistributable_v4(prefix: &Ipv4Net) -> bool {
    let a = prefix.addr();
    !a.is_loopback() && !a.is_link_local()
}

/// IPv6 sibling of [`redistributable_v4`]: excludes loopback (::1/128)
/// and link-local (fe80::/10). Every interface carries an fe80::/64
/// connected route, so skipping link-local also keeps a flood of
/// per-interface junk out of redistribution.
fn redistributable_v6(prefix: &Ipv6Net) -> bool {
    let a = prefix.addr();
    let o = a.octets();
    let link_local = o[0] == 0xfe && (o[1] & 0xc0) == 0x80;
    !a.is_loopback() && !link_local
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
        // Redistribute the protected (primary) path, never the repair.
        Nexthop::Protect(p) => p.primary.iter_unis().next().and_then(|u| match u.addr {
            std::net::IpAddr::V4(a) => Some(a),
            _ => None,
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
        // Redistribute the protected (primary) path, never the repair.
        Nexthop::Protect(p) => p.primary.iter_unis().next().and_then(|u| match u.addr {
            std::net::IpAddr::V6(a) => Some(a),
            _ => None,
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
// has updated the selected entry, and from the resolve/sync paths via
// `selected_changed_v{4,6}` + `Rib::ipv{4,6}_default_sync`. Compares the
// before/after selected entries per subscriber and emits single-entry
// RouteAdd / RouteDel messages for each filter row that's affected.

fn build_v4_entry(prefix: &Ipv4Net, e: &RibEntry) -> Option<RouteEntryV4> {
    if !redistributable_v4(prefix) {
        return None;
    }
    // Connected routes have no gateway IP (see `walk_v4`): deliver them
    // with a 0.0.0.0 placeholder rather than dropping the prefix.
    let nh = first_v4_nexthop(&e.nexthop).unwrap_or(std::net::Ipv4Addr::UNSPECIFIED);
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
    if !redistributable_v6(prefix) {
        return None;
    }
    // Connected routes have no gateway IP (see `walk_v4`): deliver them
    // with a :: placeholder rather than dropping the prefix.
    let nh = first_v6_nexthop(&e.nexthop).unwrap_or(std::net::Ipv6Addr::UNSPECIFIED);
    Some(RouteEntryV6 {
        prefix: *prefix,
        nexthop: nh,
        subtype: e.rsubtype.clone(),
        metric: e.metric,
        tag: 0,
        ifindex: e.ifindex,
    })
}

/// Whether the redistribute-relevant projection of the selected entry
/// at `prefix` differs between `before` and `after`. The resolve/sync
/// notify hook uses this to skip no-op selection passes: it compares
/// the owning `rtype` plus the delivered `RouteEntryV4` (the exact
/// inputs a subscriber filter keys on — nexthop, metric, subtype,
/// ifindex), so a recursive nexthop churn that leaves the delivered
/// form unchanged produces no spurious withdraw/re-add, while a real
/// select/deselect, rtype swap, or metric change does.
pub(super) fn selected_changed_v4(
    prefix: &Ipv4Net,
    before: Option<&RibEntry>,
    after: Option<&RibEntry>,
) -> bool {
    fn key(prefix: &Ipv4Net, e: Option<&RibEntry>) -> Option<(RibType, RouteEntryV4)> {
        let e = e?;
        Some((e.rtype, build_v4_entry(prefix, e)?))
    }
    key(prefix, before) != key(prefix, after)
}

pub(super) fn selected_changed_v6(
    prefix: &Ipv6Net,
    before: Option<&RibEntry>,
    after: Option<&RibEntry>,
) -> bool {
    fn key(prefix: &Ipv6Net, e: Option<&RibEntry>) -> Option<(RibType, RouteEntryV6)> {
        let e = e?;
        Some((e.rtype, build_v6_entry(prefix, e)?))
    }
    key(prefix, before) != key(prefix, after)
}

/// Notify every subscriber bound to `target_vrf_id` whose filter
/// matches the before/after transition of the selected entry at
/// `prefix`. Single-entry batches, `bulk: More`. EoR is reserved for
/// initial walk / `Redist{Add,Update,Del}` replays — steady-state
/// never emits Eor.
///
/// `target_vrf_id` scopes delivery to the table the transition came
/// from: the default-VRF route paths (`Rib::ipv*_route_{add,del}` /
/// `ipv*_default_sync` on `self.table` / `self.table_v6`) pass `0`,
/// and the per-VRF paths (`ipv*_route_{add,del}_vrf` /
/// `ipv*_vrf_sync` on `vrf_tables[table_id]`) pass that VRF's kernel
/// table id. A subscriber whose `vrf_id` doesn't match is skipped so
/// a default-table change never leaks to a VRF subscriber and vice
/// versa.
pub fn notify_v4_delta(
    filters: &HashMap<String, FilterMap>,
    default_watch: &HashMap<String, BTreeSet<super::RedistAfi>>,
    registry: &ClientRegistry,
    prefix: &Ipv4Net,
    before: Option<&RibEntry>,
    after: Option<&RibEntry>,
    target_vrf_id: u32,
) {
    if before.is_none() && after.is_none() {
        return;
    }
    notify_default_v4(
        default_watch,
        registry,
        prefix,
        before,
        after,
        target_vrf_id,
    );
    for (proto, filter_map) in filters {
        let Some(sub) = registry.subscriber_for_proto(proto) else {
            continue;
        };
        if sub.vrf_id != target_vrf_id {
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

/// IPv6 sibling of [`notify_v4_delta`]; see its docstring for the
/// `target_vrf_id` scoping rules.
pub fn notify_v6_delta(
    filters: &HashMap<String, FilterMap>,
    default_watch: &HashMap<String, BTreeSet<super::RedistAfi>>,
    registry: &ClientRegistry,
    prefix: &Ipv6Net,
    before: Option<&RibEntry>,
    after: Option<&RibEntry>,
    target_vrf_id: u32,
) {
    if before.is_none() && after.is_none() {
        return;
    }
    notify_default_v6(
        default_watch,
        registry,
        prefix,
        before,
        after,
        target_vrf_id,
    );
    for (proto, filter_map) in filters {
        let Some(sub) = registry.subscriber_for_proto(proto) else {
            continue;
        };
        if sub.vrf_id != target_vrf_id {
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

/// Default-prefix watch: like the per-rtype rows but matching only
/// the default route (0.0.0.0/0), any rtype, self-routes excluded.
/// Feeds `default-information originate` tracking — the consumer
/// learns whether a non-self default exists without subscribing to
/// whole routing tables. Deliveries ride the ordinary RouteAdd /
/// RouteDel channel with the route's real rtype.
fn notify_default_v4(
    default_watch: &HashMap<String, BTreeSet<super::RedistAfi>>,
    registry: &ClientRegistry,
    prefix: &Ipv4Net,
    before: Option<&RibEntry>,
    after: Option<&RibEntry>,
    target_vrf_id: u32,
) {
    if prefix.prefix_len() != 0 {
        return;
    }
    for (proto, afis) in default_watch {
        if !afis.contains(&super::RedistAfi::Ipv4) {
            continue;
        }
        let Some(sub) = registry.subscriber_for_proto(proto) else {
            continue;
        };
        if sub.vrf_id != target_vrf_id {
            continue;
        }
        let old = entry_for_default_v4(prefix, before, proto);
        let new = entry_for_default_v4(prefix, after, proto);
        emit_default_v4(&sub.rib_rx_tx, old, new);
    }
}

/// IPv6 sibling of [`notify_default_v4`] (::/0).
fn notify_default_v6(
    default_watch: &HashMap<String, BTreeSet<super::RedistAfi>>,
    registry: &ClientRegistry,
    prefix: &Ipv6Net,
    before: Option<&RibEntry>,
    after: Option<&RibEntry>,
    target_vrf_id: u32,
) {
    if prefix.prefix_len() != 0 {
        return;
    }
    for (proto, afis) in default_watch {
        if !afis.contains(&super::RedistAfi::Ipv6) {
            continue;
        }
        let Some(sub) = registry.subscriber_for_proto(proto) else {
            continue;
        };
        if sub.vrf_id != target_vrf_id {
            continue;
        }
        let old = entry_for_default_v6(prefix, before, proto);
        let new = entry_for_default_v6(prefix, after, proto);
        emit_default_v6(&sub.rib_rx_tx, old, new);
    }
}

/// Watch-entry builder: any rtype accepted (the watch is per-prefix,
/// not per-source), self-routes still excluded via `deliverable`.
pub(super) fn entry_for_default_v4(
    prefix: &Ipv4Net,
    entry: Option<&RibEntry>,
    proto: &str,
) -> Option<(RibType, RouteEntryV4)> {
    let e = entry?;
    if !deliverable(proto, e.rtype) {
        return None;
    }
    build_v4_entry(prefix, e).map(|b| (e.rtype, b))
}

/// IPv6 sibling of [`entry_for_default_v4`].
pub(super) fn entry_for_default_v6(
    prefix: &Ipv6Net,
    entry: Option<&RibEntry>,
    proto: &str,
) -> Option<(RibType, RouteEntryV6)> {
    let e = entry?;
    if !deliverable(proto, e.rtype) {
        return None;
    }
    build_v6_entry(prefix, e).map(|b| (e.rtype, b))
}

/// Diff-emit for the default watch. Unlike `emit_v4_diff` the rtype
/// can change across the transition (default moved from static to
/// bgp), so a changed entry is a Del under the old rtype followed by
/// an Add under the new one.
pub(super) fn emit_default_v4(
    tx: &UnboundedSender<RibRx>,
    old: Option<(RibType, RouteEntryV4)>,
    new: Option<(RibType, RouteEntryV4)>,
) {
    match (old, new) {
        (None, None) => {}
        (Some((rt, o)), None) => send_v4_one(tx, rt, WalkOp::Del, o),
        (None, Some((rt, n))) => send_v4_one(tx, rt, WalkOp::Add, n),
        (Some((ort, o)), Some((nrt, n))) if ort == nrt && o == n => {}
        (Some((ort, o)), Some((nrt, n))) => {
            send_v4_one(tx, ort, WalkOp::Del, o);
            send_v4_one(tx, nrt, WalkOp::Add, n);
        }
    }
}

/// IPv6 sibling of [`emit_default_v4`].
pub(super) fn emit_default_v6(
    tx: &UnboundedSender<RibRx>,
    old: Option<(RibType, RouteEntryV6)>,
    new: Option<(RibType, RouteEntryV6)>,
) {
    match (old, new) {
        (None, None) => {}
        (Some((rt, o)), None) => send_v6_one(tx, rt, WalkOp::Del, o),
        (None, Some((rt, n))) => send_v6_one(tx, rt, WalkOp::Add, n),
        (Some((ort, o)), Some((nrt, n))) if ort == nrt && o == n => {}
        (Some((ort, o)), Some((nrt, n))) => {
            send_v6_one(tx, ort, WalkOp::Del, o);
            send_v6_one(tx, nrt, WalkOp::Add, n);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rib::client::ProtoId;
    use crate::rib::nexthop::NexthopUni;
    use std::net::IpAddr;
    use tokio::sync::mpsc::unbounded_channel;

    fn static_uni(addr: &str, metric: u32) -> RibEntry {
        let mut e = RibEntry::new(RibType::Static);
        e.metric = metric;
        e.nexthop = Nexthop::Uni(NexthopUni::new(
            addr.parse::<IpAddr>().unwrap(),
            metric,
            vec![],
        ));
        e
    }

    fn p() -> Ipv4Net {
        "1.2.3.4/32".parse().unwrap()
    }

    #[test]
    fn no_change_when_both_unselected() {
        assert!(!selected_changed_v4(&p(), None, None));
    }

    #[test]
    fn deselect_is_a_change() {
        // The resolve-path strand: a redistributed route that was
        // selected becomes unselected (nexthop unresolvable) — must be
        // seen as a change so the withdraw reaches subscribers.
        let before = static_uni("10.0.0.2", 0);
        assert!(selected_changed_v4(&p(), Some(&before), None));
    }

    #[test]
    fn select_is_a_change() {
        let after = static_uni("10.0.0.2", 0);
        assert!(selected_changed_v4(&p(), None, Some(&after)));
    }

    #[test]
    fn identical_selection_is_no_change() {
        // A no-op resolve pass over an unchanged selected route must not
        // emit a spurious withdraw/re-add.
        let a = static_uni("10.0.0.2", 0);
        let b = static_uni("10.0.0.2", 0);
        assert!(!selected_changed_v4(&p(), Some(&a), Some(&b)));
    }

    #[test]
    fn metric_change_is_a_change() {
        let a = static_uni("10.0.0.2", 10);
        let b = static_uni("10.0.0.2", 20);
        assert!(selected_changed_v4(&p(), Some(&a), Some(&b)));
    }

    #[test]
    fn rtype_swap_is_a_change() {
        // Same delivered nexthop/metric but a different owning protocol
        // — subscribers filter on rtype, so this must register.
        let a = static_uni("10.0.0.2", 10);
        let mut b = static_uni("10.0.0.2", 10);
        b.rtype = RibType::Ospf;
        assert!(selected_changed_v4(&p(), Some(&a), Some(&b)));
    }

    #[test]
    fn nexthop_change_is_a_change() {
        let a = static_uni("10.0.0.2", 0);
        let b = static_uni("10.0.0.3", 0);
        assert!(selected_changed_v4(&p(), Some(&a), Some(&b)));
    }

    #[test]
    fn connected_link_nexthop_is_delivered_with_unspecified() {
        // A directly-attached route (a connected route, or a static
        // pointing out an interface) carries a Link nexthop with no
        // gateway IP. Redistribution must still deliver the prefix —
        // with a 0.0.0.0 placeholder nexthop — so a consumer can
        // re-originate it. Regression guard: these routes used to be
        // dropped, which is why `redistribute connected` produced no
        // external LSAs (OSPF Type-5 / NSSA Type-7).
        let mut conn = RibEntry::new(RibType::Connected);
        conn.nexthop = Nexthop::Link(7);
        conn.ifindex = 7;

        let built = build_v4_entry(&p(), &conn).expect("connected route must be delivered");
        assert_eq!(built.nexthop, std::net::Ipv4Addr::UNSPECIFIED);
        assert_eq!(built.ifindex, 7);

        // Gaining or losing it is therefore a redistribute change.
        assert!(selected_changed_v4(&p(), Some(&conn), None));
        assert!(selected_changed_v4(&p(), None, Some(&conn)));
    }

    #[test]
    fn loopback_and_link_local_are_not_redistributed() {
        // Loopback (127/8) and link-local (169.254/16) appear as
        // connected routes but must never be redistributed — they are
        // not routable beyond the local host.
        let mut conn = RibEntry::new(RibType::Connected);
        conn.nexthop = Nexthop::Link(1);
        conn.ifindex = 1;

        let lo: Ipv4Net = "127.0.0.0/8".parse().unwrap();
        let ll: Ipv4Net = "169.254.0.0/16".parse().unwrap();
        assert!(build_v4_entry(&lo, &conn).is_none());
        assert!(build_v4_entry(&ll, &conn).is_none());
        assert!(!selected_changed_v4(&lo, None, Some(&conn)));

        // A normal connected prefix is still delivered.
        let ok: Ipv4Net = "203.0.113.0/24".parse().unwrap();
        assert!(build_v4_entry(&ok, &conn).is_some());
    }

    #[test]
    fn v6_loopback_and_link_local_are_not_redistributed() {
        assert!(!redistributable_v6(&"::1/128".parse().unwrap()));
        assert!(!redistributable_v6(&"fe80::/64".parse().unwrap()));
        assert!(redistributable_v6(&"2001:db8::/64".parse().unwrap()));
    }

    /// Build a `(filters, registry)` pair with one default-VRF
    /// subscriber (`vrf_id 0`) and one VRF subscriber (`vrf_id 100`),
    /// each carrying a wildcard Connected/IPv4 filter row, returning
    /// their receivers so a test can assert who heard a delta.
    fn two_subscribers() -> (
        HashMap<String, FilterMap>,
        ClientRegistry,
        tokio::sync::mpsc::UnboundedReceiver<RibRx>,
        tokio::sync::mpsc::UnboundedReceiver<RibRx>,
    ) {
        let mut reg = ClientRegistry::new();
        let (tx_def, rx_def) = unbounded_channel();
        let (tx_vrf, rx_vrf) = unbounded_channel();
        reg.register_with_id(ProtoId::from_raw(0), "bgp", tx_def, 0);
        reg.register_with_id(ProtoId::from_raw(1), "bgp:vrf:N3", tx_vrf, 100);

        let mut filters: HashMap<String, FilterMap> = HashMap::new();
        for proto in ["bgp", "bgp:vrf:N3"] {
            let mut fm = FilterMap::new();
            fm.insert((RedistAfi::Ipv4, RibType::Connected), BTreeSet::new());
            filters.insert(proto.to_string(), fm);
        }
        (filters, reg, rx_def, rx_vrf)
    }

    fn connected_link(ifindex: u32) -> RibEntry {
        let mut e = RibEntry::new(RibType::Connected);
        e.nexthop = Nexthop::Link(ifindex);
        e.ifindex = ifindex;
        e
    }

    #[test]
    fn notify_v4_delta_scopes_to_target_vrf() {
        // The crux of per-VRF redistribution: a selection change in a
        // VRF table must reach only the subscriber bound to that VRF,
        // and a default-table change must reach only the default
        // subscriber. Cross-delivery would advertise a VRF's CE prefix
        // into the global table (and vice versa).
        let (filters, reg, mut rx_def, mut rx_vrf) = two_subscribers();
        let prefix: Ipv4Net = "203.0.113.0/24".parse().unwrap();
        let conn = connected_link(7);

        // Connected route appears in VRF 100 → only the VRF subscriber.
        notify_v4_delta(
            &filters,
            &HashMap::new(),
            &reg,
            &prefix,
            None,
            Some(&conn),
            100,
        );
        assert!(
            matches!(rx_vrf.try_recv(), Ok(RibRx::RouteAdd { .. })),
            "VRF subscriber must hear the VRF-100 add"
        );
        assert!(
            rx_def.try_recv().is_err(),
            "default subscriber must not hear a VRF-100 change"
        );

        // Same prefix appears in the default table → only the default
        // subscriber.
        notify_v4_delta(
            &filters,
            &HashMap::new(),
            &reg,
            &prefix,
            None,
            Some(&conn),
            0,
        );
        assert!(
            matches!(rx_def.try_recv(), Ok(RibRx::RouteAdd { .. })),
            "default subscriber must hear the default-table add"
        );
        assert!(
            rx_vrf.try_recv().is_err(),
            "VRF subscriber must not hear a default-table change"
        );
    }

    #[test]
    fn notify_v4_delta_unknown_vrf_reaches_nobody() {
        // A transition tagged with a table id no subscriber is bound to
        // is silently dropped — no spurious delivery to the default or
        // any other VRF.
        let (filters, reg, mut rx_def, mut rx_vrf) = two_subscribers();
        let prefix: Ipv4Net = "203.0.113.0/24".parse().unwrap();
        let conn = connected_link(7);

        notify_v4_delta(
            &filters,
            &HashMap::new(),
            &reg,
            &prefix,
            None,
            Some(&conn),
            777,
        );
        assert!(rx_def.try_recv().is_err());
        assert!(rx_vrf.try_recv().is_err());
    }
}
