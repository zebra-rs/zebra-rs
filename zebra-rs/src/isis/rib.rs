use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, Ipv6Addr};

use ipnet::{Ipv4Net, Ipv6Net};
use isis_packet::*;
use prefix_trie::PrefixMap;
use tokio::sync::mpsc::UnboundedSender;

use super::config::IsisConfig;
use super::level::Levels;
use super::throttle::Throttle;
use crate::context::Timer;
use crate::rib::inst::{IlmEntry, IlmType};
use crate::rib::{self, Nexthop, NexthopMulti, NexthopUni, RibType};
use crate::spf;
// EncapType is only used by `make_rib_entry_v6` test fixture below;
// production code paths route through `tilfa::build_repair_path_srv6`.
#[cfg(test)]
use isis_packet::srv6::EncapType;

use super::config::MtId;
use super::flex_algo::FlexAlgoEntry;
use super::graph::{LspMap, graph, graph_flex_algo, graph_mt2};
use super::inst::{IsisTop, Message};
use super::level::Level;
use super::link::{Afi, LinkTop};
use super::lsdb::Lsdb;
use super::srmpls::LabelConfig;
use super::tilfa::{
    RepairPathMpls, RepairPathSrv6, build_repair_path_mpls, build_repair_path_srv6,
    first_router_hop_id, tilfa_repair_path,
};

fn spf_timer_ms(tx: &UnboundedSender<Message>, level: Level, ms: u64) -> Timer {
    let tx = tx.clone();
    Timer::once_ms(ms, move || {
        let tx = tx.clone();
        async move {
            let msg = Message::SpfCalc(level);
            tx.send(msg).unwrap();
        }
    })
}

fn spf_schedule_inner(
    spf_timer: &mut Levels<Option<Timer>>,
    spf_throttle: &mut Levels<Throttle>,
    tx: &UnboundedSender<Message>,
    config: &IsisConfig,
    level: Level,
) {
    if spf_timer.get(&level).is_some() {
        return;
    }

    let wait_ms = spf_throttle.get_mut(&level).schedule(
        config.spf_initial_wait(),
        config.spf_secondary_wait(),
        config.spf_maximum_wait(),
    );
    *spf_timer.get_mut(&level) = Some(spf_timer_ms(tx, level, wait_ms as u64));
}

pub fn spf_schedule(top: &mut LinkTop, level: Level) {
    spf_schedule_inner(
        top.spf_timer,
        top.spf_throttle,
        top.tx,
        top.up_config,
        level,
    );
}

pub fn spf_schedule_top(top: &mut IsisTop, level: Level) {
    spf_schedule_inner(top.spf_timer, top.spf_throttle, top.tx, top.config, level);
}

#[derive(Debug, PartialEq)]
pub struct SpfRoute {
    pub metric: u32,
    pub nhops: BTreeMap<Ipv4Addr, SpfNexthop>,
    pub sid: Option<u32>,
    pub prefix_sid: Option<(SidLabelValue, LabelConfig)>,
    /// SPF vertex id this route was built from. Set by
    /// `build_rib_from_spf`; used by TI-LFA Step 4c to join routes
    /// with per-destination repair candidates from Step 4b.
    pub dest_vertex: Option<usize>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SpfNexthop {
    pub ifindex: u32,
    pub adjacency: bool,
    pub sys_id: Option<IsisSysId>,
    /// TI-LFA post-convergence repair for this primary nexthop. Empty
    /// (None) until ti_lfa_compute runs and fills it in; for now no
    /// caller sets it. Sorted-after-primary install is handled by
    /// `build_rib_nexthop` via the metric-offset convention.
    pub backup: Option<RepairPathMpls>,
}

// IPv6 single-topology mirror of SpfRoute / SpfNexthop. Nexthop key is the
// peer's IPv6 link-local address (TLV 232 from IIH); ECMP is supported by
// keying multiple link-locals into the same SpfRouteV6.
#[derive(Debug, PartialEq)]
pub struct SpfRouteV6 {
    pub metric: u32,
    pub nhops: BTreeMap<Ipv6Addr, SpfNexthopV6>,
    pub sid: Option<u32>,
    pub prefix_sid: Option<(SidLabelValue, LabelConfig)>,
    /// Same role as `SpfRoute.dest_vertex` — populated by
    /// `build_rib_from_spf_v6` for Step 4d's repair-path join.
    pub dest_vertex: Option<usize>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SpfNexthopV6 {
    pub ifindex: u32,
    pub adjacency: bool,
    pub sys_id: Option<IsisSysId>,
    /// TI-LFA post-convergence repair for this primary nexthop. The
    /// SRv6 form carries an SRH segment list + encap mode instead of
    /// an MPLS label stack.
    pub backup: Option<RepairPathSrv6>,
}

/// Sort offset between the primary nhop's metric and its TI-LFA
/// backup's metric inside a `NexthopList`. The value is RIB-internal
/// and never reaches the wire — it only governs the metric-sort that
/// puts the primary at `.nexthops[0]`. See the design discussion that
/// landed PR #489: blanket `+1` keeps show output legible and avoids
/// `u32::MAX` sentinels.
pub const BACKUP_METRIC_OFFSET: u32 = 1;

pub type DiffResult<'a> = spf::TableDiffResult<'a, Ipv4Net, SpfRoute>;
pub type DiffResultV6<'a> = spf::TableDiffResult<'a, Ipv6Net, SpfRouteV6>;
pub type DiffIlmResult<'a> = spf::TableDiffResult<'a, u32, SpfIlm>;

fn nhop_to_nexthop_uni(key: &Ipv4Addr, route: &SpfRoute, value: &SpfNexthop) -> rib::NexthopUni {
    let mut mpls = vec![];
    if let Some(sid) = route.sid {
        mpls.push(if value.adjacency {
            rib::Label::Implicit(sid)
        } else {
            rib::Label::Explicit(sid)
        });
    }
    let mut nhop = rib::NexthopUni::from(*key, route.metric, mpls);
    // IS-IS knows the egress link from the adjacency state machine —
    // record it as the origin so the RIB resolver doesn't re-derive
    // (and potentially mis-derive) the link via a recursive table
    // walk. 0 means "no usable adjacency ifindex"; treat as None.
    nhop.ifindex_origin = (value.ifindex != 0).then_some(value.ifindex);
    nhop
}

fn make_rib_entry(route: &SpfRoute) -> rib::entry::RibEntry {
    let mut rib = rib::entry::RibEntry::new(RibType::Isis);
    rib.distance = 115;
    rib.metric = route.metric;
    // Flatten primaries and (when present) their TI-LFA repair backups
    // into a single Vec at distinct metrics; build_rib_nexthop groups
    // them by metric and routes Multi-vs-List dispatch from there.
    let backup_metric = route.metric.saturating_add(BACKUP_METRIC_OFFSET);
    let nhops: Vec<rib::NexthopUni> = route
        .nhops
        .iter()
        .flat_map(|(key, value)| {
            let primary = nhop_to_nexthop_uni(key, route, value);
            let backup = value
                .backup
                .as_ref()
                .map(|b| backup_to_nexthop_uni(b, backup_metric));
            std::iter::once(primary).chain(backup)
        })
        .collect();
    rib.nexthop = build_rib_nexthop(nhops);
    rib
}

fn backup_to_nexthop_uni(backup: &RepairPathMpls, metric: u32) -> rib::NexthopUni {
    let mut nhop = rib::NexthopUni::new(
        std::net::IpAddr::V4(backup.addr),
        metric,
        backup.labels.clone(),
    );
    nhop.ifindex_origin = (backup.ifindex != 0).then_some(backup.ifindex);
    nhop
}

// Dispatch a flat list of NexthopUni into the right rib::Nexthop
// variant. Group nhops by metric (BTreeMap iter is ascending), then:
//
//   - 0 groups          -> Nexthop::default()
//   - 1 group, 1 nhop   -> Nexthop::Uni
//   - 1 group, N nhops  -> Nexthop::Multi (ECMP)
//   - >1 groups         -> Nexthop::List, one member per metric:
//                            * single-nhop group -> NexthopMember::Uni
//                            * multi-nhop group  -> NexthopMember::Multi
//
// Today every caller passes all primaries at route.metric, so only
// the first three arms fire. The grouped-List arm is the slot TI-LFA
// repair install will populate when it appends backup nhops at
// primary.metric + 1; ECMP-primary + ECMP-backup naturally collapses
// to a List of two Multi members.
fn build_rib_nexthop(nhops: Vec<rib::NexthopUni>) -> rib::Nexthop {
    if nhops.is_empty() {
        return rib::Nexthop::default();
    }
    let mut groups: BTreeMap<u32, Vec<rib::NexthopUni>> = BTreeMap::new();
    for n in nhops {
        groups.entry(n.metric).or_default().push(n);
    }
    if groups.len() == 1 {
        let (metric, mut grp) = groups.into_iter().next().unwrap();
        if grp.len() == 1 {
            rib::Nexthop::Uni(grp.pop().unwrap())
        } else {
            rib::Nexthop::Multi(rib::NexthopMulti {
                metric,
                nexthops: grp,
                ..Default::default()
            })
        }
    } else {
        let members: Vec<_> = groups
            .into_iter()
            .map(|(metric, mut grp)| {
                if grp.len() == 1 {
                    rib::NexthopMember::Uni(grp.pop().unwrap())
                } else {
                    rib::NexthopMember::Multi(rib::NexthopMulti {
                        metric,
                        nexthops: grp,
                        ..Default::default()
                    })
                }
            })
            .collect();
        rib::Nexthop::List(rib::NexthopList { nexthops: members })
    }
}

/// Convert one entry of IS-IS's internal `SpfRoute` shape into the
/// public `rib::api::FlexAlgoRoute` snapshot. Returns `None` when
/// the route lacks a resolved per-algo SID or has no usable
/// nexthops — both signal "no forwarding plane for this prefix in
/// algo-N" and downstream callers should treat it as a delete.
fn make_flex_algo_route(
    algo: u8,
    prefix: Ipv4Net,
    route: &SpfRoute,
) -> Option<crate::rib::api::FlexAlgoRoute> {
    let outer_label = route.sid?;
    let nexthops: Vec<crate::rib::api::FlexAlgoNexthop> = route
        .nhops
        .iter()
        .map(|(addr, nhop)| crate::rib::api::FlexAlgoNexthop {
            addr: *addr,
            ifindex: nhop.ifindex,
            label: outer_label,
        })
        .collect();
    if nexthops.is_empty() {
        return None;
    }
    Some(crate::rib::api::FlexAlgoRoute {
        algo,
        prefix,
        metric: route.metric,
        nexthops,
    })
}

/// Diff per-algo IPv4 RIB snapshots and emit `Message::FlexAlgoRoute
/// Add` / `Del` messages so RIB's shadow tracks the live state.
///
/// Iteration covers every algo present in either side so an algo
/// dropped from `flex_algo.config` (and therefore absent from `next`)
/// yields one Del per prefix that used to be there.
///
/// Within an algo we use `spf::table_diff` for the same `only_curr /
/// different / only_next` split the IPv4 and IPv6 diff helpers use,
/// so the semantics of "route changed under the hood but same
/// prefix" match what RIB already sees from algo-0.
pub fn diff_apply_flex_algo(
    rib_client: &crate::rib::client::RibClient,
    prev: &BTreeMap<u8, PrefixMap<Ipv4Net, SpfRoute>>,
    next: &BTreeMap<u8, PrefixMap<Ipv4Net, SpfRoute>>,
) {
    let all_algos: BTreeSet<u8> = prev.keys().chain(next.keys()).copied().collect();
    let empty: PrefixMap<Ipv4Net, SpfRoute> = PrefixMap::new();
    for algo in all_algos {
        let prev_table = prev.get(&algo).unwrap_or(&empty);
        let next_table = next.get(&algo).unwrap_or(&empty);
        let diff = spf::table_diff(prev_table.iter(), next_table.iter());

        for (prefix, _) in diff.only_curr.iter() {
            let msg = rib::Message::FlexAlgoRouteDel {
                algo,
                prefix: **prefix,
            };
            rib_client.send(msg).unwrap();
        }
        for (prefix, _, route) in diff.different.iter() {
            // A changed route that no longer has a usable forwarding
            // plane (lost SID or lost all nhops) collapses to a Del.
            match make_flex_algo_route(algo, **prefix, route) {
                Some(r) => {
                    let msg = rib::Message::FlexAlgoRouteAdd { route: r };
                    rib_client.send(msg).unwrap();
                }
                None => {
                    let msg = rib::Message::FlexAlgoRouteDel {
                        algo,
                        prefix: **prefix,
                    };
                    rib_client.send(msg).unwrap();
                }
            }
        }
        for (prefix, route) in diff.only_next.iter() {
            if let Some(r) = make_flex_algo_route(algo, **prefix, route) {
                let msg = rib::Message::FlexAlgoRouteAdd { route: r };
                rib_client.send(msg).unwrap();
            }
        }
    }
}

pub fn diff_apply(rib_client: &crate::rib::client::RibClient, diff: &DiffResult) {
    // Delete.
    for (prefix, route) in diff.only_curr.iter() {
        if !route.nhops.is_empty() {
            let rib = make_rib_entry(route);
            let msg = rib::Message::Ipv4Del {
                prefix: **prefix,
                rib,
            };
            rib_client.send(msg).unwrap();
        }
    }
    // Add (changed).
    for (prefix, _, route) in diff.different.iter() {
        if !route.nhops.is_empty() {
            let rib = make_rib_entry(route);
            let msg = rib::Message::Ipv4Add {
                prefix: **prefix,
                rib,
            };
            rib_client.send(msg).unwrap();
        }
    }
    // Add (new).
    for (prefix, route) in diff.only_next.iter() {
        if !route.nhops.is_empty() {
            let rib = make_rib_entry(route);
            let msg = rib::Message::Ipv4Add {
                prefix: **prefix,
                rib,
            };
            rib_client.send(msg).unwrap();
        }
    }
}

fn nhop_to_nexthop_uni_v6(
    key: &Ipv6Addr,
    route: &SpfRouteV6,
    value: &SpfNexthopV6,
) -> rib::NexthopUni {
    let mut mpls = vec![];
    if let Some(sid) = route.sid {
        mpls.push(if value.adjacency {
            rib::Label::Implicit(sid)
        } else {
            rib::Label::Explicit(sid)
        });
    }
    let mut nhop = rib::NexthopUni::new(std::net::IpAddr::V6(*key), route.metric, mpls);
    // IPv6 link-local nexthops can't be disambiguated by table
    // lookup — every interface advertises fe80::/64. The adjacency
    // already pinned the egress link, so record it as the origin.
    nhop.ifindex_origin = (value.ifindex != 0).then_some(value.ifindex);
    nhop
}

fn make_rib_entry_v6(route: &SpfRouteV6) -> rib::entry::RibEntry {
    let mut rib = rib::entry::RibEntry::new(RibType::Isis);
    rib.distance = 115;
    rib.metric = route.metric;
    let backup_metric = route.metric.saturating_add(BACKUP_METRIC_OFFSET);
    let nhops: Vec<rib::NexthopUni> = route
        .nhops
        .iter()
        .flat_map(|(key, value)| {
            let primary = nhop_to_nexthop_uni_v6(key, route, value);
            let backup = value
                .backup
                .as_ref()
                .map(|b| backup_to_nexthop_uni_v6(b, backup_metric));
            std::iter::once(primary).chain(backup)
        })
        .collect();
    rib.nexthop = build_rib_nexthop(nhops);
    rib
}

fn backup_to_nexthop_uni_v6(backup: &RepairPathSrv6, metric: u32) -> rib::NexthopUni {
    let mut nhop = rib::NexthopUni::new(std::net::IpAddr::V6(backup.addr), metric, vec![]);
    nhop.ifindex_origin = (backup.ifindex != 0).then_some(backup.ifindex);
    nhop.segs = backup.segs.clone();
    nhop.encap_type = Some(backup.encap);
    nhop
}

pub fn diff_apply_v6(rib_client: &crate::rib::client::RibClient, diff: &DiffResultV6) {
    for (prefix, route) in diff.only_curr.iter() {
        if !route.nhops.is_empty() {
            let rib = make_rib_entry_v6(route);
            let msg = rib::Message::Ipv6Del {
                prefix: **prefix,
                rib,
            };
            rib_client.send(msg).unwrap();
        }
    }
    for (prefix, _, route) in diff.different.iter() {
        if !route.nhops.is_empty() {
            let rib = make_rib_entry_v6(route);
            let msg = rib::Message::Ipv6Add {
                prefix: **prefix,
                rib,
            };
            rib_client.send(msg).unwrap();
        }
    }
    for (prefix, route) in diff.only_next.iter() {
        if !route.nhops.is_empty() {
            let rib = make_rib_entry_v6(route);
            let msg = rib::Message::Ipv6Add {
                prefix: **prefix,
                rib,
            };
            rib_client.send(msg).unwrap();
        }
    }
}

fn make_ilm_entry(label: u32, ilm: &SpfIlm) -> IlmEntry {
    if ilm.nhops.len() == 1
        && let Some((&addr, nhop)) = ilm.nhops.iter().next()
    {
        let mut uni = NexthopUni {
            addr: std::net::IpAddr::V4(addr),
            ifindex_origin: (nhop.ifindex != 0).then_some(nhop.ifindex),
            ..Default::default()
        };
        if !nhop.adjacency {
            uni.mpls_label.push(label);
        }
        return IlmEntry {
            rtype: RibType::Isis,
            ilm_type: ilm.ilm_type.clone(),
            nexthop: Nexthop::Uni(uni),
        };
    }
    let mut multi = NexthopMulti::default();
    for (&addr, nhop) in ilm.nhops.iter() {
        let mut uni = NexthopUni {
            addr: std::net::IpAddr::V4(addr),
            ifindex_origin: (nhop.ifindex != 0).then_some(nhop.ifindex),
            ..Default::default()
        };
        if !nhop.adjacency {
            uni.mpls_label.push(label);
        }
        multi.nexthops.push(uni);
    }
    IlmEntry {
        rtype: RibType::Isis,
        ilm_type: ilm.ilm_type.clone(),
        nexthop: Nexthop::Multi(multi),
    }
}

pub fn diff_ilm_apply(rib_client: &crate::rib::client::RibClient, diff: &DiffIlmResult) {
    // Delete.
    for (label, ilm) in diff.only_curr.iter() {
        if !ilm.nhops.is_empty() {
            let ilm_entry = make_ilm_entry(**label, ilm);
            let msg = rib::Message::IlmDel {
                label: **label,
                ilm: ilm_entry,
            };
            rib_client.send(msg).unwrap();
        }
    }
    // Add (changed).
    for (label, _, ilm) in diff.different.iter() {
        if !ilm.nhops.is_empty() {
            let ilm_entry = make_ilm_entry(**label, ilm);
            let msg = rib::Message::IlmAdd {
                label: **label,
                ilm: ilm_entry,
            };
            rib_client.send(msg).unwrap();
        }
    }
    // Add (new).
    for (label, ilm) in diff.only_next.iter() {
        if !ilm.nhops.is_empty() {
            let ilm_entry = make_ilm_entry(**label, ilm);
            let msg = rib::Message::IlmAdd {
                label: **label,
                ilm: ilm_entry,
            };
            rib_client.send(msg).unwrap();
        }
    }
}
#[derive(Debug, PartialEq)]
pub struct SpfIlm {
    pub nhops: BTreeMap<Ipv4Addr, SpfNexthop>,
    pub ilm_type: IlmType,
}

/// Build ILM table with adjacency labels from SIDs
fn build_adjacency_ilm(
    top: &mut IsisTop,
    level: Level,
    sids: &BTreeMap<u32, IsisSysId>,
) -> BTreeMap<u32, SpfIlm> {
    let mut ilm = BTreeMap::new();

    for (&label, nhop_id) in sids.iter() {
        let mut nhops = BTreeMap::new();

        for (ifindex, link) in top.links.iter() {
            if let Some(nbr) = link.state.nbrs.get(&level).get(nhop_id) {
                for (addr, _) in nbr.addr4.iter() {
                    let nhop = SpfNexthop {
                        ifindex: *ifindex,
                        adjacency: true,
                        sys_id: Some(*nhop_id),
                        backup: None,
                    };
                    nhops.insert(*addr, nhop);
                }
            }
        }

        // TODO: Need to check local-block in RIB configuration.
        let adj_index = label.saturating_sub(15000);
        let spf_ilm = SpfIlm {
            nhops,
            ilm_type: IlmType::Adjacency(adj_index),
        };
        ilm.insert(label, spf_ilm);
    }

    ilm
}

/// Build RIB from SPF calculation results
fn build_rib_from_spf(
    top: &mut IsisTop,
    level: Level,
    source: usize,
    spf_result: &BTreeMap<usize, spf::Path>,
    tilfa_result: &BTreeMap<usize, Vec<spf::RepairPath>>,
) -> PrefixMap<Ipv4Net, SpfRoute> {
    let mut rib = PrefixMap::<Ipv4Net, SpfRoute>::new();

    // Process each node in the SPF result
    for (node, nhops) in spf_result {
        // Skip self node
        if *node == source {
            continue;
        }

        // Skip pseudonode entries — they are transit-only and do not
        // own a destination prefix to install.
        if top.lsp_map.get(&level).is_pseudo(*node) {
            continue;
        }

        // Resolve node to system ID
        let Some(sys_id) = top.lsp_map.get(&level).resolve(*node) else {
            continue;
        };

        // Build nexthop map. SPF runs in full-path mode (see
        // perform_spf_calculation), so each `p` is the full path
        // [first_hop, ..., destination]. With pseudonodes in the graph,
        // p[0] may be a PN whose sys-id resolves to the DIS — skip
        // leading PN hops to land on the actual nexthop *router* before
        // looking up neighbours.
        //
        // SPF stamps the chosen first-hop link's ifindex into
        // `Path::first_hop_links` during relaxation (see spf::Link::link_id).
        // For each path, we look up all (first_hop_vertex, link_id) entries
        // that match p[0] — usually one, but parallel equal-cost links to
        // the same neighbour (case P1) produce multiple, and parallel
        // ECMP-via-different-neighbours produces one per path. This
        // replaces the old "iterate every top.links entry and match by
        // sys-id" loop, which silently misrouted in cases P2/P3 (parallel
        // asymmetric metrics and P2P+LAN mix).
        let mut spf_nhops = BTreeMap::new();
        for p in &nhops.paths {
            let Some(nhop_id) = first_router_hop_id(top.lsp_map.get(&level), p) else {
                continue;
            };

            let Some(nhop_sys_id) = top.lsp_map.get(&level).resolve(nhop_id) else {
                continue;
            };
            let nhop_sys_id = *nhop_sys_id;

            // p[0] could be pseudonode.
            for (_, link_id) in nhops.first_hop_links.iter().filter(|(v, _)| *v == p[0]) {
                if *link_id == 0 {
                    continue;
                }
                let Some(link) = top.links.get(link_id) else {
                    continue;
                };
                let Some(nbr) = link.state.nbrs.get(&level).get(&nhop_sys_id) else {
                    continue;
                };
                for (addr, _) in nbr.addr4.iter() {
                    let nhop = SpfNexthop {
                        ifindex: *link_id,
                        adjacency: *node == nhop_id,
                        sys_id: Some(nhop_sys_id),
                        backup: None,
                    };
                    spf_nhops.insert(*addr, nhop);
                }
            }
        }

        // TI-LFA backup stamping is deferred to a second pass after
        // the per-destination loop completes — see the post-loop
        // block below. Per-destination stamping was racy with the
        // equal-metric merge: a prefix advertised by multiple
        // destinations would end up with primary nexthops from all
        // of them but a backup attached to only one, and that
        // backup is useless for the multi-primary case (the remaining
        // ECMP legs already provide protection).

        // Process reachability entries for this node.
        if let Some(entries) = top.reach_map.get(&level).get(&Afi::Ip).get(sys_id) {
            for entry in entries.iter() {
                let sid = if let Some(prefix_sid) = entry.prefix_sid() {
                    match prefix_sid.sid {
                        // Prefix SID label.
                        SidLabelValue::Index(index) => top
                            .label_map
                            .get(&level)
                            .get(sys_id)
                            .map(|block| block.global.start + index),
                        SidLabelValue::Label(label) => Some(label),
                    }
                } else {
                    None
                };

                let prefix_sid = if let Some(prefix_sid) = entry.prefix_sid()
                    && let Some(block) = top.label_map.get(&level).get(sys_id)
                {
                    Some((prefix_sid.sid.clone(), block.clone()))
                } else {
                    None
                };

                let route = SpfRoute {
                    metric: nhops.cost + entry.metric,
                    nhops: spf_nhops.clone(),
                    sid,
                    prefix_sid,
                    dest_vertex: Some(*node),
                };

                if let Some(curr) = rib.get_mut(&entry.prefix.trunc()) {
                    if curr.metric > route.metric {
                        // New route has better metric, replace the existing one
                        *curr = route;
                    } else if curr.metric == route.metric {
                        // Equal metric: the same prefix is advertised
                        // by multiple destinations at equal SPF cost —
                        // anycast / shared loopback / sibling routes.
                        // Merging their primaries here makes this an
                        // ECMP route at the RIB / prefix level —
                        // distinct from intra-route ECMP within one
                        // destination, which `spf_nhops` already
                        // collapsed above.
                        //
                        // The post-loop TI-LFA backup pass skips
                        // routes with multi-primary nhops (the typical
                        // anycast outcome), so a backup attached to
                        // only one sibling can't leak into the merged
                        // RIB entry the way it did before deferral.
                        //
                        // Remaining metadata-merge limitations:
                        //   - sid / prefix_sid first-wins. Index-
                        //     encoded SIDs resolve against the
                        //     advertising router's SRGB (see line
                        //     ~2595); siblings with divergent SRGBs
                        //     end up with different absolute labels
                        //     and the subsequent labels are silently
                        //     dropped. RFC 8667 §4 recommends anycast
                        //     SR groups share an Index, but SRGBs
                        //     aren't required to match across
                        //     siblings.
                        //   - `dest_vertex` stays at the first-merged
                        //     node. The post-loop backup pass uses it
                        //     to look up the repair; this is only
                        //     load-bearing when an RIB route ends up
                        //     single-primary (siblings whose nhops
                        //     collapsed to one peer address via a
                        //     shared first-hop neighbor), in which
                        //     case every collapsed sibling protects
                        //     against the same primary so picking
                        //     the first sibling's repair is fine.
                        for (addr, nhop) in route.nhops {
                            curr.nhops.insert(addr, nhop);
                        }
                        if curr.sid.is_none() && route.sid.is_some() {
                            curr.sid = route.sid;
                        }
                        if curr.prefix_sid.is_none() && route.prefix_sid.is_some() {
                            curr.prefix_sid = route.prefix_sid;
                        }
                    }
                    // If curr.metric < route.metric, do nothing (keep better route)
                } else {
                    // No existing route, insert the new one
                    rib.insert(entry.prefix.trunc(), route);
                }
            }
        }
    }

    // Second pass: TI-LFA backup stamping.
    //
    // Defer until the equal-metric merge has stabilized. A prefix
    // with multiple primary nexthops (ECMP at the RIB level)
    // shouldn't carry a backup — the remaining ECMP legs already
    // provide protection, and a metric-offset backup at one leg's
    // repair address just wastes a FIB entry without adding value
    // (the typical backup steers around the same link the surviving
    // ECMP leg already avoids).
    //
    // For single-primary routes we look up the repair by
    // `dest_vertex`. tilfa_repair_path already skips destinations
    // with SPF-level ECMP, so the lookup either returns a repair
    // built against a single protected first-hop (the only valid
    // case for stamping) or nothing.
    for (_, route) in rib.iter_mut() {
        if route.nhops.len() != 1 {
            continue;
        }
        let Some(dest) = route.dest_vertex else {
            continue;
        };
        let Some(repair_paths) = tilfa_result.get(&dest) else {
            continue;
        };
        let Some(repair) = repair_paths.first() else {
            continue;
        };
        let Some(backup) = build_repair_path_mpls(top, level, repair) else {
            continue;
        };
        if let Some(nhop) = route.nhops.values_mut().next() {
            nhop.backup = Some(backup);
        }
    }

    rib
}

// IPv6 RIB builder. Walks the chosen SPF tree and joins each reached
// node's IPv6 reach entries to a nexthop map keyed by the first-hop
// neighbor's link-local IPv6 (Neighbor::addr6l).
//
// `mt2_mode` controls which inputs to consume:
//   - false (legacy / single-topology): SPF over the legacy graph,
//     prefixes from `top.reach_map_v6` (TLV 236), with strict NLPID
//     gating per RFC 1195 §5 — every transit node must advertise the
//     IPv6 NLPID or its Ipv6Reach is unreachable.
//   - true (MT 2 / RFC 5120 §3.4): SPF over the MT 2 graph
//     (already filtered to MT-2-capable peers at graph-build time),
//     prefixes from `top.mt2_reach_map_v6` (TLV 237). NLPID gating
//     is redundant here — TLV 229 with MT 2 is the stricter signal —
//     so we skip it.
//
// Prefix-SID / SR plumbing for IPv6 is intentionally deferred — sid
// and prefix_sid are left None for now and can be added when SRv6
// IS-IS support lands as a follow-up.
fn build_rib_from_spf_v6(
    top: &mut IsisTop,
    level: Level,
    source: usize,
    spf_result: &BTreeMap<usize, spf::Path>,
    tilfa_result: &BTreeMap<usize, Vec<spf::RepairPath>>,
    mt2_mode: bool,
) -> PrefixMap<Ipv6Net, SpfRouteV6> {
    let mut rib = PrefixMap::<Ipv6Net, SpfRouteV6>::new();

    // NLPID gate set — only used in legacy mode.
    let ipv6_capable = if mt2_mode {
        BTreeSet::new()
    } else {
        ipv6_capable_set(top.lsdb.get(&level))
    };

    for (node, nhops) in spf_result {
        if *node == source {
            continue;
        }

        // Skip pseudonode entries — transit-only, no IPv6 prefixes.
        if top.lsp_map.get(&level).is_pseudo(*node) {
            continue;
        }

        let Some(sys_id) = top.lsp_map.get(&level).resolve(*node) else {
            continue;
        };

        // Strict NLPID gating per RFC 1195 §5 — only in legacy mode.
        if !mt2_mode && !ipv6_capable.contains(sys_id) {
            continue;
        }
        // Capture SysId so later borrows of top.lsp_map don't conflict.
        let dest_sys_id = *sys_id;

        // Build nexthop map keyed by the first-hop neighbor's link-local IPv6.
        // Iterate `paths` (full path from first-hop to destination) so we can
        // strict-gate every transit node, not just the first hop.
        let mut spf_nhops = BTreeMap::new();
        'next_path: for p in &nhops.paths {
            // In legacy mode, every node on the path must advertise IPv6.
            // In MT 2 mode the graph itself is pre-filtered, so we skip.
            // Pseudonode hops bypass the IPv6 NLPID check — they don't
            // advertise capabilities of their own; the gating is on the
            // attached routers.
            if !mt2_mode {
                for &hop in p {
                    if top.lsp_map.get(&level).is_pseudo(hop) {
                        continue;
                    }
                    let Some(hop_sys_id) = top.lsp_map.get(&level).resolve(hop) else {
                        continue 'next_path;
                    };
                    if !ipv6_capable.contains(hop_sys_id) {
                        continue 'next_path;
                    }
                }
            }

            // Skip leading pseudonode hops to land on the actual nexthop
            // router whose adjacency carries the link-local v6 address.
            let Some(nhop_id) = first_router_hop_id(top.lsp_map.get(&level), p) else {
                continue;
            };
            let Some(nhop_sys_id) = top.lsp_map.get(&level).resolve(nhop_id) else {
                continue;
            };
            let nhop_sys_id = *nhop_sys_id;
            let is_adjacency = nhop_id == *node;
            // Same first_hop_links-driven resolution as the IPv4 builder.
            // See build_rib_from_spf for the design rationale.
            for (_, link_id) in nhops.first_hop_links.iter().filter(|(v, _)| *v == p[0]) {
                if *link_id == 0 {
                    continue;
                }
                let Some(link) = top.links.get(link_id) else {
                    continue;
                };
                let Some(nbr) = link.state.nbrs.get(&level).get(&nhop_sys_id) else {
                    continue;
                };
                for addr in nbr.addr6l.iter() {
                    let nhop = SpfNexthopV6 {
                        ifindex: *link_id,
                        adjacency: is_adjacency,
                        sys_id: Some(nhop_sys_id),
                        backup: None,
                    };
                    spf_nhops.insert(*addr, nhop);
                }
            }
        }

        // No surviving paths after gating → don't install anything for this dest.
        if spf_nhops.is_empty() {
            continue;
        }

        // TI-LFA SRv6 backup stamping is deferred to a second pass
        // after the per-destination loop — see the post-loop block
        // below, and `build_rib_from_spf`'s sibling comment for the
        // rationale.

        let reach = if mt2_mode {
            top.mt2_reach_map_v6.get(&level).get(&dest_sys_id)
        } else {
            top.reach_map_v6.get(&level).get(&dest_sys_id)
        };
        if let Some(entries) = reach {
            for entry in entries.iter() {
                let route = SpfRouteV6 {
                    metric: nhops.cost + entry.metric,
                    nhops: spf_nhops.clone(),
                    sid: None,
                    prefix_sid: None,
                    dest_vertex: Some(*node),
                };

                if let Some(curr) = rib.get_mut(&entry.prefix.trunc()) {
                    if curr.metric > route.metric {
                        *curr = route;
                    } else if curr.metric == route.metric {
                        for (addr, nhop) in route.nhops {
                            curr.nhops.insert(addr, nhop);
                        }
                    }
                } else {
                    rib.insert(entry.prefix.trunc(), route);
                }
            }
        }
    }

    // Second pass: TI-LFA SRv6 backup stamping. Mirror of the v4
    // post-loop pass — skip ECMP-at-prefix routes, stamp the
    // dest_vertex's repair on single-primary routes.
    for (_, route) in rib.iter_mut() {
        if route.nhops.len() != 1 {
            continue;
        }
        let Some(dest) = route.dest_vertex else {
            continue;
        };
        let Some(repair_paths) = tilfa_result.get(&dest) else {
            continue;
        };
        let Some(repair) = repair_paths.first() else {
            continue;
        };
        let Some(backup) = build_repair_path_srv6(top, level, repair) else {
            continue;
        };
        if let Some(nhop) = route.nhops.values_mut().next() {
            nhop.backup = Some(backup);
        }
    }

    rib
}

// Walk the LSDB and collect SysIds whose Protocols-Supported TLV (TLV 129)
// includes the IPv6 NLPID (0x8E). Used by strict NLPID gating in
// build_rib_from_spf_v6.
fn ipv6_capable_set(lsdb: &Lsdb) -> BTreeSet<IsisSysId> {
    let ipv6_proto: u8 = IsisProto::Ipv6.into();
    let mut set = BTreeSet::new();
    for (lsp_id, lsa) in lsdb.iter() {
        for tlv in &lsa.lsp.tlvs {
            if let IsisTlv::ProtoSupported(ps) = tlv
                && ps.nlpids.contains(&ipv6_proto)
            {
                set.insert(lsp_id.sys_id());
            }
        }
    }
    set
}

/// Apply routing updates to RIB subsystem
fn apply_routing_updates(
    top: &mut IsisTop,
    level: Level,
    rib: PrefixMap<Ipv4Net, SpfRoute>,
    rib_v6: PrefixMap<Ipv6Net, SpfRouteV6>,
    ilm: BTreeMap<u32, SpfIlm>,
) {
    // Update MPLS ILM
    if top.config.distribute.rib {
        let diff = spf::table_diff(top.ilm.get(&level).iter(), ilm.iter());
        diff_ilm_apply(top.rib_client, &diff);
    }
    *top.ilm.get_mut(&level) = ilm;

    // Update IPv4 RIB
    if top.config.distribute.rib {
        let diff = spf::table_diff(top.rib.get(&level).iter(), rib.iter());
        diff_apply(top.rib_client, &diff);
    }
    *top.rib.get_mut(&level) = rib;

    // Update IPv6 RIB
    if top.config.distribute.rib {
        let diff = spf::table_diff(top.rib_v6.get(&level).iter(), rib_v6.iter());
        diff_apply_v6(top.rib_client, &diff);
    }
    *top.rib_v6.get_mut(&level) = rib_v6;
}

/// Owned, `Send`-able inputs to a single IS-IS SPF run for one level.
///
/// Built on the main task by [`build_spf_input`], which reads
/// `IsisTop` to construct the legacy + optional MT 2 + per-algo SPF
/// graphs. The resulting value carries no borrow on `IsisTop`, so
/// [`compute_spf`] can later be dispatched onto
/// `tokio::task::spawn_blocking` without touching shared state.
pub(super) struct SpfInput {
    level: Level,
    graph: spf::Graph,
    source: usize,
    adjacency_sids: BTreeMap<u32, IsisSysId>,
    /// Snapshot of `top.lsp_map[level]` taken after every graph build
    /// has completed for this cycle. TI-LFA looks up pseudonode-ness
    /// and sys-id resolution against this; cloning it lets the worker
    /// run without borrowing `IsisTop`.
    lsp_map: LspMap,
    ti_lfa_enabled: bool,
    mt2: Option<Mt2Input>,
    flex_algos: Vec<FlexAlgoInput>,
}

struct Mt2Input {
    graph: spf::Graph,
    source: Option<usize>,
}

struct FlexAlgoInput {
    algo: u8,
    graph: spf::Graph,
    source: Option<usize>,
}

/// Result of a single IS-IS SPF run, ready to be applied back to
/// `IsisTop` by [`apply_spf_result`] on the main task.
pub(super) struct SpfOutput {
    level: Level,
    source: usize,
    adjacency_sids: BTreeMap<u32, IsisSysId>,
    spf_result: BTreeMap<usize, spf::Path>,
    tilfa_result: BTreeMap<usize, Vec<spf::RepairPath>>,
    mt2: Option<Mt2Output>,
    flex_algos: Vec<FlexAlgoOutput>,
}

struct Mt2Output {
    source: Option<usize>,
    spf: Option<BTreeMap<usize, spf::Path>>,
    tilfa: BTreeMap<usize, Vec<spf::RepairPath>>,
}

struct FlexAlgoOutput {
    algo: u8,
    graph: spf::Graph,
    source: Option<usize>,
    spf: Option<BTreeMap<usize, spf::Path>>,
}

/// Build the SPF graphs for `level` and snapshot the data the worker
/// needs to run Dijkstra + TI-LFA off the main task.
///
/// Always builds the legacy single-topology graph (drives IPv4 RIB
/// and IPv6 RIB in non-MT mode). When MT 2 (IPv6 unicast) is locally
/// enabled, additionally builds an MT 2 graph from TLV 222 entries
/// (filtered to MT-2-capable peers via `mt_membership`) per RFC 5120
/// §3.4 strict-MT semantics. Also builds one graph per configured
/// Flex-Algo (RFC 9350).
///
/// Returns `None` if the legacy graph has no source node — matches
/// the previous early-return in `perform_spf_calculation`.
///
/// Side effects on `top` (preserved verbatim from the pre-refactor
/// code so behavior is unchanged):
///   - `top.graph[level]` is replaced with the new legacy graph.
///   - `top.mt2_graph[level]` is replaced with the new MT 2 graph if
///     MT 2 is enabled, otherwise cleared (and `top.mt2_spf_result`
///     also cleared).
pub(super) fn build_spf_input(top: &mut IsisTop, level: Level) -> Option<SpfInput> {
    // Legacy graph + SPF — drives IPv4 RIB and IPv6 in non-MT mode.
    let (legacy_graph, source_node, adjacency_sids) = graph(top, level);
    *top.graph.get_mut(&level) = Some(legacy_graph.clone());

    // Source node check and early return.
    let source = source_node?;

    let mt2_enabled =
        top.config.mt_enabled && top.config.mt_topologies.contains(&MtId::Ipv6Unicast);
    let mt2 = if mt2_enabled {
        // Separate MT 2 graph, fed into the v6 RIB build via
        // mt2_reach_map_v6 (TLV 237 entries) once SPF returns.
        let (mt2_graph, mt2_source, _) = graph_mt2(top, level);
        *top.mt2_graph.get_mut(&level) = Some(mt2_graph.clone());
        Some(Mt2Input {
            graph: mt2_graph,
            source: mt2_source,
        })
    } else {
        // No MT 2: clear any stale MT 2 caches so the v6 RIB build
        // falls back to the legacy graph + reach_map_v6.
        *top.mt2_graph.get_mut(&level) = None;
        *top.mt2_spf_result.get_mut(&level) = None;
        None
    };

    // Per-algorithm graphs (RFC 9350). Entries are cloned out of
    // `top.flex_algo.config` because `graph_flex_algo` takes
    // `&mut top` and we'd otherwise hold a read borrow on
    // `top.flex_algo` across the call.
    let configured_algos: Vec<(u8, FlexAlgoEntry)> = top
        .flex_algo
        .config
        .iter()
        .map(|(k, v)| (*k, v.clone()))
        .collect();
    let mut flex_algos = Vec::with_capacity(configured_algos.len());
    for (algo, entry) in &configured_algos {
        let (algo_graph, algo_source, _) = graph_flex_algo(top, level, *algo, entry);
        flex_algos.push(FlexAlgoInput {
            algo: *algo,
            graph: algo_graph,
            source: algo_source,
        });
    }

    // Snapshot lsp_map after every graph build so the worker can run
    // TI-LFA without borrowing `top`. LspMap is monotonically growing
    // and the legacy `graph()` already iterates every LSDB entry, so
    // this snapshot matches what TI-LFA reads in the pre-refactor code.
    let lsp_map = top.lsp_map.get(&level).clone();

    Some(SpfInput {
        level,
        graph: legacy_graph,
        source,
        adjacency_sids,
        lsp_map,
        ti_lfa_enabled: top.config.ti_lfa_enabled,
        mt2,
        flex_algos,
    })
}

/// Pure compute: runs Dijkstra (legacy + optional MT 2 + per
/// Flex-Algo) and TI-LFA. Holds no reference to `IsisTop` so it can
/// move to a blocking worker without touching shared state.
pub(super) fn compute_spf(input: SpfInput) -> SpfOutput {
    let SpfInput {
        level,
        graph: legacy_graph,
        source,
        adjacency_sids,
        lsp_map,
        ti_lfa_enabled,
        mt2,
        flex_algos,
    } = input;

    // Legacy SPF. Full-path mode so the legacy v6 builder can apply
    // RFC 1195 §5 strict NLPID gating across every transit node.
    let spf_result = spf::spf(&legacy_graph, source, &spf::SpfOpt::full_path());

    // TI-LFA repair path. Gated on `fast-reroute ti-lfa` — when the
    // knob is off we still install the primary RIB built from
    // `spf_result`, just without the per-destination repair list.
    let tilfa_result = if ti_lfa_enabled {
        tilfa_repair_path(&legacy_graph, &lsp_map, source, &spf_result)
    } else {
        BTreeMap::new()
    };

    // MT 2 SPF + TI-LFA.
    let mt2 = mt2.map(|Mt2Input { graph, source }| {
        let (spf, tilfa) = match source {
            Some(src) => {
                let mt2_spf = spf::spf(&graph, src, &spf::SpfOpt::full_path());
                let mt2_tilfa = if ti_lfa_enabled {
                    tilfa_repair_path(&graph, &lsp_map, src, &mt2_spf)
                } else {
                    BTreeMap::new()
                };
                (Some(mt2_spf), mt2_tilfa)
            }
            None => (None, BTreeMap::new()),
        };
        Mt2Output { source, spf, tilfa }
    });

    // Per-algo SPF. No TI-LFA for Flex-Algo (the FAD topology may
    // not admit the algo-0 repair anyway — deferred).
    let flex_algos = flex_algos
        .into_iter()
        .map(
            |FlexAlgoInput {
                 algo,
                 graph,
                 source,
             }| {
                let spf = source.map(|src| spf::spf(&graph, src, &spf::SpfOpt::full_path()));
                FlexAlgoOutput {
                    algo,
                    graph,
                    source,
                    spf,
                }
            },
        )
        .collect();

    SpfOutput {
        level,
        source,
        adjacency_sids,
        spf_result,
        tilfa_result,
        mt2,
        flex_algos,
    }
}

/// Apply a completed SPF run: build the IPv4/IPv6/per-algo RIBs and
/// the ILM table, diff against the previous cycle, and publish to
/// the RIB subsystem. Must run on the main task — every helper
/// called from here borrows `IsisTop` and emits on `top.rib_client`.
pub(super) fn apply_spf_result(top: &mut IsisTop, output: SpfOutput) {
    let SpfOutput {
        level,
        source,
        adjacency_sids,
        spf_result,
        tilfa_result,
        mt2,
        flex_algos,
    } = output;

    // Build Adjacency ILM seed from the SIDs collected during graph build.
    let mut ilm = build_adjacency_ilm(top, level, &adjacency_sids);

    // IPv4 RIB.
    let rib = build_rib_from_spf(top, level, source, &spf_result, &tilfa_result);

    // IPv6 RIB — either MT 2 (when enabled) or the legacy single-topology path.
    let rib_v6 = match mt2 {
        Some(Mt2Output {
            source: Some(mt2_src),
            spf: Some(mt2_spf),
            tilfa: mt2_tilfa,
        }) => {
            let rib_v6 = build_rib_from_spf_v6(top, level, mt2_src, &mt2_spf, &mt2_tilfa, true);
            *top.mt2_spf_result.get_mut(&level) = Some(mt2_spf);
            rib_v6
        }
        Some(_) => {
            // MT 2 enabled but no source — clear and install nothing.
            *top.mt2_spf_result.get_mut(&level) = None;
            PrefixMap::new()
        }
        None => {
            // No MT 2: fall back to legacy graph + reach_map_v6 (and
            // the legacy TI-LFA result) for IPv6.
            build_rib_from_spf_v6(top, level, source, &spf_result, &tilfa_result, false)
        }
    };

    // Per-algorithm RIB build (RFC 9350). For every algo:
    //   1. Walk the per-algo SPF result against `peer_algo_sid` to
    //      produce a per-algo IPv4 RIB snapshot (in-memory only — see
    //      `Isis::rib_flex_algo`).
    //   2. Fold the per-algo Prefix-SID labels into the combined
    //      `ilm` map. Labels are globally unique, so per-algo entries
    //      coexist with algo-0 entries in the kernel MPLS LFIB
    //      without an algorithm dimension at the RIB API layer.
    //
    // Algos no longer in config are purged from every level snapshot
    // so stale graphs / SPFs / RIBs don't survive a delete.
    let mut new_flex_algo_graphs: BTreeMap<u8, Option<spf::Graph>> = BTreeMap::new();
    let mut new_flex_algo_spfs: BTreeMap<u8, Option<BTreeMap<usize, spf::Path>>> = BTreeMap::new();
    let mut new_flex_algo_rib: BTreeMap<u8, PrefixMap<Ipv4Net, SpfRoute>> = BTreeMap::new();
    for FlexAlgoOutput {
        algo,
        graph: algo_graph,
        source: algo_source,
        spf: algo_spf,
    } in flex_algos
    {
        // Build the per-algo IPv4 RIB iff we have both a source and
        // an SPF result. Empty PrefixMap for the algo otherwise so
        // the show command and downstream consumers still see a
        // well-formed (if empty) snapshot.
        let algo_rib = match (algo_source, algo_spf.as_ref()) {
            (Some(src), Some(spf_res)) => {
                let r = build_rib_from_flex_algo(top, level, algo, src, spf_res);
                mpls_route(&r, &mut ilm);
                r
            }
            _ => PrefixMap::<Ipv4Net, SpfRoute>::new(),
        };

        new_flex_algo_graphs.insert(algo, Some(algo_graph));
        new_flex_algo_spfs.insert(algo, algo_spf);
        new_flex_algo_rib.insert(algo, algo_rib);
    }
    // Per-algo route diff → RIB publish (Phase 3). The shadow on
    // `Rib::flex_algo_routes` is the colour-aware nexthop resolver's
    // source of truth for the outer MPLS label per (algo, prefix).
    if top.config.distribute.rib {
        diff_apply_flex_algo(
            top.rib_client,
            top.rib_flex_algo.get(&level),
            &new_flex_algo_rib,
        );
    }

    // Swap the new state in. The retain that used to live above is
    // implicit: any algo present in the old map but absent from the
    // new one yielded `FlexAlgoRouteDel` messages above; the swap
    // drops the old entry entirely.
    *top.graph_flex_algo.get_mut(&level) = new_flex_algo_graphs;
    *top.spf_flex_algo.get_mut(&level) = new_flex_algo_spfs;
    *top.rib_flex_algo.get_mut(&level) = new_flex_algo_rib;

    *top.spf_result.get_mut(&level) = Some(spf_result);
    *top.tilfa_result.get_mut(&level) = Some(tilfa_result);
    mpls_route(&rib, &mut ilm);
    apply_routing_updates(top, level, rib, rib_v6, ilm);
}

/// Perform SPF calculation and update routing tables.
///
/// Orchestrates the three-phase pipeline:
///
///   1. [`build_spf_input`] — main task. Builds the legacy graph,
///      the optional MT 2 graph, and per Flex-Algo graphs; snapshots
///      `lsp_map[level]`. Returns `None` if the legacy graph has no
///      source.
///   2. [`compute_spf`] — pure compute. Runs Dijkstra + TI-LFA on
///      all graphs. Today this is called inline; PR-2 moves it to
///      `tokio::task::spawn_blocking`.
///   3. [`apply_spf_result`] — main task. Builds the RIBs, diffs
///      against the previous cycle, and publishes to the RIB
///      subsystem.
pub(super) fn perform_spf_calculation(top: &mut IsisTop, level: Level) {
    // Turn off SPF calculation timer.
    *top.spf_timer.get_mut(&level) = None;
    // Stamp completion time so spf_schedule can tell whether the next
    // scheduling event lands inside or outside the burst window.
    top.spf_throttle.get_mut(&level).mark_run();

    let Some(input) = build_spf_input(top, level) else {
        return;
    };
    let output = compute_spf(input);
    apply_spf_result(top, output);
}

/// Build the per-algorithm IPv4 RIB from a Flex-Algo SPF result.
/// Mirrors `build_rib_from_spf` but with two differences:
///
///   - **Prefix-SIDs come from `peer_algo_sid[origin][(algo, prefix)]`**
///     instead of the algo-0 Prefix-SID on the reach entry. Resolution
///     against the origin's SRGB (`label_map[origin]`) is identical to
///     the legacy path — Flex-Algo uses the same label space as algo
///     0, just at different indices (RFC 9350 §7).
///   - **No TI-LFA backup stamping.** Per-algo fast-reroute is
///     deferred; the FAD topology may not admit the algo-0 TI-LFA
///     repair anyway.
///
/// Prefixes that the origin advertised without a per-algo Prefix-SID
/// are silently skipped — algo-N SR-MPLS forwarding requires a label
/// at every step. The algo-0 (legacy) RIB still installs the prefix
/// via `build_rib_from_spf`, so reachability is not lost.
fn build_rib_from_flex_algo(
    top: &mut IsisTop,
    level: Level,
    algo: u8,
    source: usize,
    spf_result: &BTreeMap<usize, spf::Path>,
) -> PrefixMap<Ipv4Net, SpfRoute> {
    let mut rib = PrefixMap::<Ipv4Net, SpfRoute>::new();

    for (node, nhops) in spf_result {
        if *node == source {
            continue;
        }
        if top.lsp_map.get(&level).is_pseudo(*node) {
            continue;
        }
        let Some(sys_id) = top.lsp_map.get(&level).resolve(*node).copied() else {
            continue;
        };

        // Build spf_nhops — same first-router-hop walk as the legacy
        // builder. Pseudonodes appear as p[0] for LAN edges; the
        // helper drops leading PN hops to land on a real router.
        let mut spf_nhops = BTreeMap::new();
        for p in &nhops.paths {
            let Some(nhop_id) = first_router_hop_id(top.lsp_map.get(&level), p) else {
                continue;
            };
            let Some(nhop_sys_id) = top.lsp_map.get(&level).resolve(nhop_id).copied() else {
                continue;
            };
            for (_, link_id) in nhops.first_hop_links.iter().filter(|(v, _)| *v == p[0]) {
                if *link_id == 0 {
                    continue;
                }
                let Some(link) = top.links.get(link_id) else {
                    continue;
                };
                let Some(nbr) = link.state.nbrs.get(&level).get(&nhop_sys_id) else {
                    continue;
                };
                for (addr, _) in nbr.addr4.iter() {
                    let nhop = SpfNexthop {
                        ifindex: *link_id,
                        adjacency: *node == nhop_id,
                        sys_id: Some(nhop_sys_id),
                        backup: None,
                    };
                    spf_nhops.insert(*addr, nhop);
                }
            }
        }

        let Some(reach_entries) = top.reach_map.get(&level).get(&Afi::Ip).get(&sys_id) else {
            continue;
        };
        for entry in reach_entries.iter() {
            // Look up the per-algo Prefix-SID advertised by this
            // origin for this prefix. `peer_algo_sid` is keyed on
            // the raw (non-trunc) prefix as parsed off the wire,
            // matching how `lsdb::rebuild_sys_state` inserts.
            let Some(algo_sid) = top
                .peer_algo_sid
                .get(&level)
                .get(&sys_id)
                .and_then(|m| m.get(&(algo, entry.prefix)))
                .cloned()
            else {
                continue;
            };

            let label_block = top.label_map.get(&level).get(&sys_id).cloned();
            let sid = match &algo_sid {
                SidLabelValue::Index(idx) => label_block.as_ref().map(|b| b.global.start + idx),
                SidLabelValue::Label(label) => Some(*label),
            };
            let prefix_sid = label_block.as_ref().map(|b| (algo_sid.clone(), b.clone()));

            let route = SpfRoute {
                metric: nhops.cost + entry.metric,
                nhops: spf_nhops.clone(),
                sid,
                prefix_sid,
                dest_vertex: Some(*node),
            };

            if let Some(curr) = rib.get_mut(&entry.prefix.trunc()) {
                if curr.metric > route.metric {
                    *curr = route;
                } else if curr.metric == route.metric {
                    // Same anycast / sibling merge as the legacy
                    // builder. Metadata first-wins; new primaries
                    // merge in.
                    for (addr, nhop) in route.nhops {
                        curr.nhops.insert(addr, nhop);
                    }
                    if curr.sid.is_none() && route.sid.is_some() {
                        curr.sid = route.sid;
                    }
                    if curr.prefix_sid.is_none() && route.prefix_sid.is_some() {
                        curr.prefix_sid = route.prefix_sid;
                    }
                }
            } else {
                rib.insert(entry.prefix.trunc(), route);
            }
        }
    }

    rib
}

pub fn mpls_route(rib: &PrefixMap<Ipv4Net, SpfRoute>, ilm: &mut BTreeMap<u32, SpfIlm>) {
    for (_prefix, route) in rib.iter() {
        if let Some(sid) = route.sid {
            // Calculate prefix index from SID (assuming 16000 is base)
            let pfx_index = if (16000..24000).contains(&sid) {
                sid - 16000
            } else {
                0
            };
            let spf_ilm = SpfIlm {
                nhops: route.nhops.clone(),
                ilm_type: IlmType::Node(pfx_index),
            };
            ilm.insert(sid, spf_ilm);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_uni(addr: &str, metric: u32) -> rib::NexthopUni {
        rib::NexthopUni::new(addr.parse().unwrap(), metric, vec![])
    }

    fn spf_route(metric: u32, sid: Option<u32>, nhops: &[(&str, u32)]) -> SpfRoute {
        let mut nh = BTreeMap::new();
        for (addr, ifindex) in nhops {
            nh.insert(
                addr.parse::<Ipv4Addr>().unwrap(),
                super::SpfNexthop {
                    ifindex: *ifindex,
                    adjacency: false,
                    sys_id: None,
                    backup: None,
                },
            );
        }
        SpfRoute {
            metric,
            nhops: nh,
            sid,
            prefix_sid: None,
            dest_vertex: None,
        }
    }

    fn pfx(s: &str) -> Ipv4Net {
        s.parse().unwrap()
    }

    fn rib_client_for_test() -> (
        crate::rib::client::RibClient,
        tokio::sync::mpsc::UnboundedReceiver<crate::rib::client::RibInbound>,
    ) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        (
            crate::rib::client::RibClient::new(tx, crate::rib::client::ProtoId::from_raw(u32::MAX)),
            rx,
        )
    }

    fn drain(
        rx: &mut tokio::sync::mpsc::UnboundedReceiver<crate::rib::client::RibInbound>,
    ) -> Vec<crate::rib::inst::Message> {
        let mut out = Vec::new();
        while let Ok(m) = rx.try_recv() {
            out.push(m.msg);
        }
        out
    }

    #[test]
    fn make_flex_algo_route_skips_route_with_no_sid() {
        let r = spf_route(10, None, &[("10.0.0.1", 7)]);
        assert!(make_flex_algo_route(128, pfx("192.0.2.0/24"), &r).is_none());
    }

    #[test]
    fn make_flex_algo_route_skips_route_with_no_nhops() {
        let r = spf_route(10, Some(17128), &[]);
        assert!(make_flex_algo_route(128, pfx("192.0.2.0/24"), &r).is_none());
    }

    #[test]
    fn make_flex_algo_route_flattens_multiple_nhops() {
        let r = spf_route(10, Some(17128), &[("10.0.0.1", 7), ("10.0.0.2", 8)]);
        let fr = make_flex_algo_route(128, pfx("192.0.2.0/24"), &r).expect("Some");
        assert_eq!(fr.algo, 128);
        assert_eq!(fr.metric, 10);
        assert_eq!(fr.nexthops.len(), 2);
        for n in &fr.nexthops {
            assert_eq!(n.label, 17128);
        }
    }

    #[test]
    fn diff_apply_flex_algo_emits_add_for_new_route() {
        let (client, mut rx) = rib_client_for_test();
        let mut next: BTreeMap<u8, PrefixMap<Ipv4Net, SpfRoute>> = BTreeMap::new();
        let mut t = PrefixMap::new();
        t.insert(
            pfx("10.0.0.1/32"),
            spf_route(20, Some(17128), &[("10.0.0.5", 9)]),
        );
        next.insert(128, t);

        diff_apply_flex_algo(&client, &BTreeMap::new(), &next);
        let msgs = drain(&mut rx);
        assert_eq!(msgs.len(), 1);
        assert!(matches!(
            msgs[0],
            crate::rib::inst::Message::FlexAlgoRouteAdd { ref route }
                if route.algo == 128 && route.prefix == pfx("10.0.0.1/32")
        ));
    }

    #[test]
    fn diff_apply_flex_algo_emits_del_for_removed_algo() {
        let (client, mut rx) = rib_client_for_test();
        let mut prev: BTreeMap<u8, PrefixMap<Ipv4Net, SpfRoute>> = BTreeMap::new();
        let mut t = PrefixMap::new();
        t.insert(
            pfx("10.0.0.1/32"),
            spf_route(20, Some(17128), &[("10.0.0.5", 9)]),
        );
        t.insert(
            pfx("10.0.0.2/32"),
            spf_route(20, Some(17129), &[("10.0.0.5", 9)]),
        );
        prev.insert(128, t);

        diff_apply_flex_algo(&client, &prev, &BTreeMap::new());
        let msgs = drain(&mut rx);
        assert_eq!(msgs.len(), 2);
        for m in &msgs {
            assert!(matches!(
                m,
                crate::rib::inst::Message::FlexAlgoRouteDel { algo: 128, .. }
            ));
        }
    }

    #[test]
    fn diff_apply_flex_algo_changed_route_emits_single_add() {
        let (client, mut rx) = rib_client_for_test();
        let mut prev: BTreeMap<u8, PrefixMap<Ipv4Net, SpfRoute>> = BTreeMap::new();
        let mut p = PrefixMap::new();
        p.insert(
            pfx("10.0.0.1/32"),
            spf_route(20, Some(17128), &[("10.0.0.5", 9)]),
        );
        prev.insert(128, p);

        let mut next: BTreeMap<u8, PrefixMap<Ipv4Net, SpfRoute>> = BTreeMap::new();
        let mut n = PrefixMap::new();
        // Same prefix, different metric → counts as `different`.
        n.insert(
            pfx("10.0.0.1/32"),
            spf_route(30, Some(17128), &[("10.0.0.5", 9)]),
        );
        next.insert(128, n);

        diff_apply_flex_algo(&client, &prev, &next);
        let msgs = drain(&mut rx);
        assert_eq!(msgs.len(), 1);
        assert!(matches!(
            msgs[0],
            crate::rib::inst::Message::FlexAlgoRouteAdd { ref route }
                if route.metric == 30
        ));
    }

    #[test]
    fn diff_apply_flex_algo_changed_route_losing_sid_collapses_to_del() {
        let (client, mut rx) = rib_client_for_test();
        let mut prev: BTreeMap<u8, PrefixMap<Ipv4Net, SpfRoute>> = BTreeMap::new();
        let mut p = PrefixMap::new();
        p.insert(
            pfx("10.0.0.1/32"),
            spf_route(20, Some(17128), &[("10.0.0.5", 9)]),
        );
        prev.insert(128, p);

        let mut next: BTreeMap<u8, PrefixMap<Ipv4Net, SpfRoute>> = BTreeMap::new();
        let mut n = PrefixMap::new();
        // Lost SID — no per-algo forwarding plane, must be a Del.
        n.insert(pfx("10.0.0.1/32"), spf_route(30, None, &[("10.0.0.5", 9)]));
        next.insert(128, n);

        diff_apply_flex_algo(&client, &prev, &next);
        let msgs = drain(&mut rx);
        assert_eq!(msgs.len(), 1);
        assert!(matches!(
            msgs[0],
            crate::rib::inst::Message::FlexAlgoRouteDel { algo: 128, .. }
        ));
    }

    #[test]
    fn build_rib_nexthop_empty_yields_default() {
        let nh = build_rib_nexthop(vec![]);
        assert_eq!(nh, rib::Nexthop::default());
    }

    #[test]
    fn build_rib_nexthop_single_yields_uni() {
        let only = mk_uni("10.0.0.1", 20);
        let nh = build_rib_nexthop(vec![only.clone()]);
        assert!(matches!(nh, rib::Nexthop::Uni(ref u) if u == &only));
    }

    #[test]
    fn build_rib_nexthop_same_metric_yields_multi() {
        // ECMP: every primary at the IGP metric — Multi is the
        // existing pre-TI-LFA shape.
        let a = mk_uni("10.0.0.1", 20);
        let b = mk_uni("10.0.0.2", 20);
        let nh = build_rib_nexthop(vec![a, b]);
        let rib::Nexthop::Multi(m) = nh else {
            panic!("expected Multi, got {nh:?}");
        };
        assert_eq!(m.metric, 20);
        assert_eq!(m.nexthops.len(), 2);
    }

    #[test]
    fn build_rib_nexthop_mixed_metric_yields_list_sorted() {
        // Mixed metrics signal primary + backup — Nexthop::List is
        // the FRR slot TI-LFA fills, sorted ascending so .nexthops[0]
        // is the primary. Singleton-per-metric groups become Uni
        // members.
        let primary = mk_uni("10.0.0.1", 20);
        let backup = mk_uni("10.0.0.5", 21);
        // Insert backup first to exercise sort.
        let nh = build_rib_nexthop(vec![backup.clone(), primary.clone()]);
        let rib::Nexthop::List(list) = nh else {
            panic!("expected List, got {nh:?}");
        };
        assert_eq!(list.nexthops.len(), 2);
        assert_eq!(list.nexthops[0], rib::NexthopMember::Uni(primary));
        assert_eq!(list.nexthops[1], rib::NexthopMember::Uni(backup));
    }

    #[test]
    fn build_rib_nexthop_ecmp_primary_plus_ecmp_backup_yields_list_of_multi() {
        // Two ECMP primaries at metric 20 + two backups at metric 21
        // collapse into a List of two Multi members: one per metric
        // group, ECMP-aware. This is the shape TI-LFA emits when
        // both the primary and the post-convergence path are
        // multi-pathed.
        let p1 = mk_uni("10.0.0.1", 20);
        let p2 = mk_uni("10.0.0.2", 20);
        let b1 = mk_uni("10.0.0.5", 21);
        let b2 = mk_uni("10.0.0.6", 21);
        // Insert mixed order to exercise BTreeMap grouping + sort.
        let nh = build_rib_nexthop(vec![b1.clone(), p1.clone(), b2.clone(), p2.clone()]);
        let rib::Nexthop::List(list) = nh else {
            panic!("expected List, got {nh:?}");
        };
        assert_eq!(list.nexthops.len(), 2);

        let rib::NexthopMember::Multi(primary_grp) = &list.nexthops[0] else {
            panic!("expected Multi primary, got {:?}", list.nexthops[0]);
        };
        assert_eq!(primary_grp.metric, 20);
        assert_eq!(primary_grp.nexthops.len(), 2);

        let rib::NexthopMember::Multi(backup_grp) = &list.nexthops[1] else {
            panic!("expected Multi backup, got {:?}", list.nexthops[1]);
        };
        assert_eq!(backup_grp.metric, 21);
        assert_eq!(backup_grp.nexthops.len(), 2);
    }

    #[test]
    fn make_rib_entry_without_backup_yields_uni() {
        // Identity check: today every SpfNexthop has backup=None, so
        // make_rib_entry still emits a Nexthop::Uni for a 1-nhop route.
        let mut nhops = BTreeMap::new();
        nhops.insert(
            "10.0.0.1".parse().unwrap(),
            SpfNexthop {
                ifindex: 10,
                adjacency: true,
                sys_id: None,
                backup: None,
            },
        );
        let route = SpfRoute {
            metric: 20,
            nhops,
            sid: None,
            prefix_sid: None,
            dest_vertex: None,
        };
        let entry = make_rib_entry(&route);
        assert!(matches!(entry.nexthop, rib::Nexthop::Uni(_)));
    }

    #[test]
    fn make_rib_entry_with_mpls_backup_yields_list_at_metric_plus_one() {
        // SpfNexthop with backup -> List([primary at 20, backup at 21]).
        // Verifies BACKUP_METRIC_OFFSET + the flat_map plumbing in
        // make_rib_entry feed build_rib_nexthop a mixed-metric Vec
        // that collapses to a sorted List.
        let primary_addr: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let backup_addr: Ipv4Addr = "10.0.0.5".parse().unwrap();
        let mut nhops = BTreeMap::new();
        nhops.insert(
            primary_addr,
            SpfNexthop {
                ifindex: 10,
                adjacency: true,
                sys_id: None,
                backup: Some(RepairPathMpls {
                    ifindex: 20,
                    addr: backup_addr,
                    labels: vec![rib::Label::Implicit(16002), rib::Label::Explicit(24007)],
                }),
            },
        );
        let route = SpfRoute {
            metric: 20,
            nhops,
            sid: None,
            prefix_sid: None,
            dest_vertex: None,
        };
        let entry = make_rib_entry(&route);

        let rib::Nexthop::List(list) = &entry.nexthop else {
            panic!("expected List, got {:?}", entry.nexthop);
        };
        assert_eq!(list.nexthops.len(), 2);

        let rib::NexthopMember::Uni(p) = &list.nexthops[0] else {
            panic!("expected Uni primary, got {:?}", list.nexthops[0]);
        };
        assert_eq!(p.metric, 20);
        assert_eq!(p.addr, std::net::IpAddr::V4(primary_addr));

        let rib::NexthopMember::Uni(b) = &list.nexthops[1] else {
            panic!("expected Uni backup, got {:?}", list.nexthops[1]);
        };
        assert_eq!(b.metric, 21);
        assert_eq!(b.addr, std::net::IpAddr::V4(backup_addr));
        assert_eq!(b.mpls.len(), 2);
        assert_eq!(b.ifindex_origin, Some(20));
    }

    #[test]
    fn make_rib_entry_v6_with_srv6_backup_carries_segs_and_encap() {
        // The IPv6 mirror: SpfNexthopV6 with an SRv6 repair populates
        // the backup NexthopUni's segs + encap_type. The label stack
        // stays empty — SRv6 doesn't use MPLS.
        let primary_addr: Ipv6Addr = "fe80::a:2".parse().unwrap();
        let backup_addr: Ipv6Addr = "fe80::a:5".parse().unwrap();
        let end_sid: Ipv6Addr = "2001:db8:a:2::".parse().unwrap();
        let endx_sid: Ipv6Addr = "2001:db8:a:2:c000::".parse().unwrap();
        let mut nhops = BTreeMap::new();
        nhops.insert(
            primary_addr,
            SpfNexthopV6 {
                ifindex: 10,
                adjacency: true,
                sys_id: None,
                backup: Some(RepairPathSrv6 {
                    ifindex: 20,
                    addr: backup_addr,
                    segs: vec![end_sid, endx_sid],
                    encap: EncapType::HEncap,
                }),
            },
        );
        let route = SpfRouteV6 {
            metric: 20,
            nhops,
            sid: None,
            prefix_sid: None,
            dest_vertex: None,
        };
        let entry = make_rib_entry_v6(&route);

        let rib::Nexthop::List(list) = &entry.nexthop else {
            panic!("expected List, got {:?}", entry.nexthop);
        };
        assert_eq!(list.nexthops.len(), 2);
        let rib::NexthopMember::Uni(b) = &list.nexthops[1] else {
            panic!("expected Uni backup, got {:?}", list.nexthops[1]);
        };
        assert_eq!(b.metric, 21);
        assert_eq!(b.segs, vec![end_sid, endx_sid]);
        assert_eq!(b.encap_type, Some(EncapType::HEncap));
        assert!(b.mpls.is_empty());
    }
}
