use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use isis_packet::*;
use prefix_trie::PrefixMap;
use tokio::sync::mpsc::UnboundedSender;

use super::config::IsisConfig;
use super::level::Levels;
use crate::context::Timer;
use crate::rib::inst::{IlmEntry, IlmType};
use crate::rib::link_ext::LinkFlagsExt;
use crate::rib::{self, Nexthop, NexthopMulti, NexthopUni, RibSubType, RibType};
use crate::spf;
use crate::throttle::Throttle;
// EncapType: TI-LFA repairs route through `tilfa::build_repair_path_srv6`,
// but the Mirror SID egress-protection backup builds an H.Encaps repair
// here directly (`inject_mirror_sid_backups`).
use isis_packet::srv6::EncapType;

use super::config::MtId;
use super::flex_algo::FlexAlgoEntry;
use super::graph::{LspMap, graph, graph_flex_algo, graph_mt2};
use super::inst::{Isis, IsisTop, Message};
use super::level::Level;
use super::link::{Afi, LinkTop};
use super::lsdb::Lsdb;
use super::neigh::Neighbor;
use super::srmpls::LabelConfig;
use super::tilfa::{
    RepairPathMpls, RepairPathSrv6, build_repair_path_mpls, build_repair_path_srv6,
    first_router_hop_id, tilfa_repair_path,
};

/// Address-family marker — ties together the address type, prefix type, and
/// TI-LFA backup-path type for a single IS-IS RIB family (IPv4 or IPv6).
/// Mirrors the `StaticFamily` pattern in `rib/static/config.rs`.
pub trait IsisRibFamily: Sized + 'static {
    type Addr: Ord + Copy + std::fmt::Debug + PartialEq;
    type Prefix: Ord + Copy + prefix_trie::Prefix;
    type Backup: std::fmt::Debug + Clone + PartialEq;
    /// Concrete reach-entry type (IPv4: `IsisTlvExtIpReachEntry`,
    /// IPv6: `IsisTlvIpv6ReachEntry`).
    type Entry;

    fn addr_to_ip(addr: Self::Addr) -> IpAddr;
    fn backup_to_nexthop_uni(backup: &Self::Backup, metric: u32) -> rib::NexthopUni;
    fn rib_add(prefix: Self::Prefix, entry: crate::rib::entry::RibEntry) -> crate::rib::Message;
    fn rib_del(prefix: Self::Prefix, entry: crate::rib::entry::RibEntry) -> crate::rib::Message;
    /// Number of SR steering segments in `backup` — MPLS label stack
    /// depth for V4, SRv6 segment-list length for V6.  Used to bucket
    /// TI-LFA protection into trivial / 1-segment / N-segment tallies.
    fn backup_sr_len(backup: &Self::Backup) -> usize;

    /// Collect nexthop addresses for this family from one neighbor record.
    fn nhop_addrs(nbr: &Neighbor) -> Vec<Self::Addr>;

    /// Look up the family's reach entries for `sys_id`.
    /// `mt2_mode` selects `mt2_reach_map_v6` vs `reach_map_v6` for V6;
    /// ignored by V4 which always reads `reach_map`.
    fn reach_entries<'a>(
        top: &'a IsisTop,
        level: &Level,
        sys_id: &IsisSysId,
        mt2_mode: bool,
    ) -> Option<&'a Vec<Self::Entry>>;

    /// Extract the network prefix from a reach entry.
    fn entry_prefix(e: &Self::Entry) -> Self::Prefix;

    /// Extract the metric from a reach entry.
    fn entry_metric(e: &Self::Entry) -> u32;

    /// Resolve the Prefix-SID (if present) for a reach entry.
    /// Returns `(sid_label, prefix_sid_tuple, no_php)`.
    /// V6 always returns `(None, None, false)` until SRv6 Prefix-SID lands.
    fn resolve_sid(
        top: &IsisTop,
        level: &Level,
        sys_id: &IsisSysId,
        e: &Self::Entry,
    ) -> (Option<u32>, Option<(SidLabelValue, LabelConfig)>, bool);

    /// Build the TI-LFA repair path for this family.
    fn build_repair(
        top: &mut IsisTop,
        level: Level,
        repair: &spf::RepairPath,
    ) -> Option<Self::Backup>;

    /// Append the destination's own prefix-SID label below the repair
    /// segments, for transports where that closes the repair into a
    /// full SR path to the destination node (SR-MPLS). Default no-op
    /// for families whose repair encapsulation already names its
    /// endpoint (SRv6). See the backup-stamping pass in
    /// `build_rib_from_spf`.
    fn backup_append_prefix_sid(_backup: &mut Self::Backup, _sid: u32) {}

    /// Return the canonical (host-bits-masked) form of `p`.
    fn trunc_prefix(p: Self::Prefix) -> Self::Prefix;
}

pub struct V4;
impl IsisRibFamily for V4 {
    type Addr = Ipv4Addr;
    type Prefix = Ipv4Net;
    type Backup = RepairPathMpls;
    type Entry = IsisTlvExtIpReachEntry;

    fn addr_to_ip(addr: Ipv4Addr) -> IpAddr {
        IpAddr::V4(addr)
    }

    fn backup_to_nexthop_uni(backup: &RepairPathMpls, metric: u32) -> rib::NexthopUni {
        let mut nhop = rib::NexthopUni::new(IpAddr::V4(backup.addr), metric, backup.labels.clone());
        nhop.ifindex_origin = (backup.ifindex != 0).then_some(backup.ifindex);
        nhop
    }

    fn rib_add(prefix: Ipv4Net, entry: crate::rib::entry::RibEntry) -> crate::rib::Message {
        crate::rib::Message::Ipv4Add { prefix, rib: entry }
    }

    fn rib_del(prefix: Ipv4Net, entry: crate::rib::entry::RibEntry) -> crate::rib::Message {
        crate::rib::Message::Ipv4Del { prefix, rib: entry }
    }

    fn backup_sr_len(backup: &RepairPathMpls) -> usize {
        backup.labels.len()
    }

    fn backup_append_prefix_sid(backup: &mut RepairPathMpls, sid: u32) {
        backup.labels.push(rib::Label::Explicit(sid));
    }

    fn nhop_addrs(nbr: &Neighbor) -> Vec<Ipv4Addr> {
        nbr.addr4.keys().copied().collect()
    }

    fn reach_entries<'a>(
        top: &'a IsisTop,
        level: &Level,
        sys_id: &IsisSysId,
        _mt2_mode: bool,
    ) -> Option<&'a Vec<IsisTlvExtIpReachEntry>> {
        top.reach_map.get(level).get(&Afi::Ip).get(sys_id)
    }

    fn entry_prefix(e: &IsisTlvExtIpReachEntry) -> Ipv4Net {
        e.prefix
    }

    fn entry_metric(e: &IsisTlvExtIpReachEntry) -> u32 {
        e.metric
    }

    fn resolve_sid(
        top: &IsisTop,
        level: &Level,
        sys_id: &IsisSysId,
        e: &IsisTlvExtIpReachEntry,
    ) -> (Option<u32>, Option<(SidLabelValue, LabelConfig)>, bool) {
        let sid = if let Some(prefix_sid) = e.prefix_sid() {
            match prefix_sid.sid {
                SidLabelValue::Index(index) => top
                    .label_map
                    .get(level)
                    .get(sys_id)
                    .map(|block| block.global.start + index),
                SidLabelValue::Label(label) => Some(label),
            }
        } else {
            None
        };
        let prefix_sid = if let Some(ps) = e.prefix_sid()
            && let Some(block) = top.label_map.get(level).get(sys_id)
        {
            Some((ps.sid.clone(), block.clone()))
        } else {
            None
        };
        let no_php = e.prefix_sid().map(|ps| ps.flags.p_flag()).unwrap_or(false);
        (sid, prefix_sid, no_php)
    }

    fn build_repair(
        top: &mut IsisTop,
        level: Level,
        repair: &spf::RepairPath,
    ) -> Option<RepairPathMpls> {
        build_repair_path_mpls(top, level, repair)
    }

    fn trunc_prefix(p: Ipv4Net) -> Ipv4Net {
        p.trunc()
    }
}

pub struct V6;
impl IsisRibFamily for V6 {
    type Addr = Ipv6Addr;
    type Prefix = Ipv6Net;
    type Backup = RepairPathSrv6;
    type Entry = IsisTlvIpv6ReachEntry;

    fn addr_to_ip(addr: Ipv6Addr) -> IpAddr {
        IpAddr::V6(addr)
    }

    fn backup_to_nexthop_uni(backup: &RepairPathSrv6, metric: u32) -> rib::NexthopUni {
        let mut nhop = rib::NexthopUni::new(IpAddr::V6(backup.addr), metric, vec![]);
        nhop.ifindex_origin = (backup.ifindex != 0).then_some(backup.ifindex);
        nhop.segs = backup.segs.clone();
        nhop.encap_type = Some(backup.encap);
        nhop
    }

    fn rib_add(prefix: Ipv6Net, entry: crate::rib::entry::RibEntry) -> crate::rib::Message {
        crate::rib::Message::Ipv6Add { prefix, rib: entry }
    }

    fn rib_del(prefix: Ipv6Net, entry: crate::rib::entry::RibEntry) -> crate::rib::Message {
        crate::rib::Message::Ipv6Del { prefix, rib: entry }
    }

    fn backup_sr_len(backup: &RepairPathSrv6) -> usize {
        backup.segs.len()
    }

    fn nhop_addrs(nbr: &Neighbor) -> Vec<Ipv6Addr> {
        nbr.addr6l.clone()
    }

    fn reach_entries<'a>(
        top: &'a IsisTop,
        level: &Level,
        sys_id: &IsisSysId,
        mt2_mode: bool,
    ) -> Option<&'a Vec<IsisTlvIpv6ReachEntry>> {
        if mt2_mode {
            top.mt2_reach_map_v6.get(level).get(sys_id)
        } else {
            top.reach_map_v6.get(level).get(sys_id)
        }
    }

    fn entry_prefix(e: &IsisTlvIpv6ReachEntry) -> Ipv6Net {
        e.prefix
    }

    fn entry_metric(e: &IsisTlvIpv6ReachEntry) -> u32 {
        e.metric
    }

    fn resolve_sid(
        _top: &IsisTop,
        _level: &Level,
        _sys_id: &IsisSysId,
        _e: &IsisTlvIpv6ReachEntry,
    ) -> (Option<u32>, Option<(SidLabelValue, LabelConfig)>, bool) {
        // Prefix-SID plumbing for IPv6 is deferred until SRv6 IS-IS lands.
        (None, None, false)
    }

    fn build_repair(
        top: &mut IsisTop,
        level: Level,
        repair: &spf::RepairPath,
    ) -> Option<RepairPathSrv6> {
        // Algo-0 (legacy) repair: node segments resolve to base End SIDs.
        build_repair_path_srv6(top, level, None, repair)
    }

    fn trunc_prefix(p: Ipv6Net) -> Ipv6Net {
        p.trunc()
    }
}

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

/// Per-destination IS-IS route produced by SPF. Generic over the address
/// family via `F: IsisRibFamily`. `SpfRoute<V4>` uses `Ipv4Addr` nexthop
/// keys and MPLS TI-LFA backups; `SpfRoute<V6>` uses `Ipv6Addr` keys and
/// SRv6 TI-LFA backups. All other fields are address-family-independent.
pub struct SpfRoute<F: IsisRibFamily> {
    pub metric: u32,
    pub nhops: BTreeMap<F::Addr, SpfNexthop<F>>,
    pub sid: Option<u32>,
    pub prefix_sid: Option<(SidLabelValue, LabelConfig)>,
    /// RFC 8667 §2.1.1 P (no-PHP) flag copied from the destination's
    /// received Prefix-SID sub-TLV. When set, the penultimate hop (the
    /// nexthop whose `adjacency` is true) must keep the node-SID label
    /// instead of popping it, so `make_ilm_entry` installs a swap rather
    /// than a pop. Part of `PartialEq` so a P-flag flip re-installs the
    /// ILM through `table_diff`. Always `false` for IPv6 (SR-MPLS is
    /// IPv4-only today).
    pub no_php: bool,
    /// SPF vertex id this route was built from. Set by
    /// `build_rib_from_spf`; used by TI-LFA to join routes with
    /// per-destination repair candidates.
    pub dest_vertex: Option<usize>,
    /// Value of `fast-reroute backup-as-primary` at the time this
    /// route was built. Carried here — rather than read globally at
    /// install time — so it participates in the `PartialEq` that
    /// `spf::table_diff` uses to gate RIB updates. The flag flips the
    /// primary/backup metric in `make_rib_entry`, so two routes with
    /// identical SPF output but different flag values install
    /// *differently*; without this field a toggle-then-recompute
    /// would diff clean and never reach the RIB.
    pub backup_as_primary: bool,
}

impl<F: IsisRibFamily> std::fmt::Debug for SpfRoute<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpfRoute")
            .field("metric", &self.metric)
            .field("nhops", &self.nhops)
            .field("sid", &self.sid)
            .field("prefix_sid", &self.prefix_sid)
            .field("no_php", &self.no_php)
            .field("dest_vertex", &self.dest_vertex)
            .field("backup_as_primary", &self.backup_as_primary)
            .finish()
    }
}

impl<F: IsisRibFamily> PartialEq for SpfRoute<F> {
    fn eq(&self, other: &Self) -> bool {
        self.metric == other.metric
            && self.nhops == other.nhops
            && self.sid == other.sid
            && self.prefix_sid == other.prefix_sid
            && self.no_php == other.no_php
            && self.dest_vertex == other.dest_vertex
            && self.backup_as_primary == other.backup_as_primary
    }
}

/// Per-nexthop IS-IS state produced by SPF. `F::Backup` is
/// `RepairPathMpls` for IPv4 and `RepairPathSrv6` for IPv6.
pub struct SpfNexthop<F: IsisRibFamily> {
    pub ifindex: u32,
    pub adjacency: bool,
    pub sys_id: Option<IsisSysId>,
    /// TI-LFA post-convergence repair for this primary nexthop. `None`
    /// until the TI-LFA post-loop pass fills it in for single-primary
    /// routes. Sorted-after-primary install is handled by
    /// `build_rib_nexthop` via the metric-offset convention.
    pub backup: Option<F::Backup>,
}

impl<F: IsisRibFamily> std::fmt::Debug for SpfNexthop<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpfNexthop")
            .field("ifindex", &self.ifindex)
            .field("adjacency", &self.adjacency)
            .field("sys_id", &self.sys_id)
            .field("backup", &self.backup)
            .finish()
    }
}

impl<F: IsisRibFamily> Clone for SpfNexthop<F> {
    fn clone(&self) -> Self {
        Self {
            ifindex: self.ifindex,
            adjacency: self.adjacency,
            sys_id: self.sys_id,
            backup: self.backup.clone(),
        }
    }
}

impl<F: IsisRibFamily> PartialEq for SpfNexthop<F> {
    fn eq(&self, other: &Self) -> bool {
        self.ifindex == other.ifindex
            && self.adjacency == other.adjacency
            && self.sys_id == other.sys_id
            && self.backup == other.backup
    }
}

/// Sort offset between the primary nhop's metric and its TI-LFA
/// backup's metric inside a `NexthopProtect`. The value is RIB-internal
/// and never reaches the wire — it only governs the metric grouping
/// that makes the lower-metric group the `primary` member. See the
/// design rationale: blanket `+1` keeps show
/// output legible and avoids `u32::MAX` sentinels.
pub const BACKUP_METRIC_OFFSET: u32 = 1;

pub type DiffResult<'a, F> = spf::TableDiffResult<'a, <F as IsisRibFamily>::Prefix, SpfRoute<F>>;
pub type DiffIlmResult<'a> = spf::TableDiffResult<'a, u32, SpfIlm>;

fn nhop_to_nexthop_uni<F: IsisRibFamily>(
    key: &F::Addr,
    route: &SpfRoute<F>,
    value: &SpfNexthop<F>,
    metric: u32,
) -> rib::NexthopUni {
    let mut mpls = vec![];
    if let Some(sid) = route.sid {
        mpls.push(if value.adjacency {
            rib::Label::Implicit(sid)
        } else {
            rib::Label::Explicit(sid)
        });
    }
    let mut nhop = rib::NexthopUni::new(F::addr_to_ip(*key), metric, mpls);
    // IS-IS knows the egress link from the adjacency state machine —
    // record it as the origin so the RIB resolver doesn't re-derive
    // (and potentially mis-derive) the link via a recursive table
    // walk. 0 means "no usable adjacency ifindex"; treat as None.
    nhop.ifindex_origin = (value.ifindex != 0).then_some(value.ifindex);
    nhop
}

/// Map the IS-IS level a route was computed at onto the RIB subtype the
/// `show ip route` / `show ipv6 route` renderers display as `L1` / `L2`.
fn level_subtype(level: Level) -> RibSubType {
    match level {
        Level::L1 => RibSubType::IsisLevel1,
        Level::L2 => RibSubType::IsisLevel2,
    }
}

fn make_rib_entry<F: IsisRibFamily>(route: &SpfRoute<F>, level: Level) -> rib::entry::RibEntry {
    let mut rib = rib::entry::RibEntry::new(RibType::Isis);
    rib.rsubtype = level_subtype(level);
    rib.distance = 115;
    rib.metric = route.metric;
    // Flatten primaries and (when present) their TI-LFA repair backups
    // into a single Vec at distinct metrics; build_rib_nexthop groups
    // them by metric and routes Multi-vs-Protect dispatch from there.
    //
    // `backup_as_primary` flips the metric-sort offset: when set, the
    // repair installs at route.metric (sorted first) and the SPF
    // primary installs at route.metric + BACKUP_METRIC_OFFSET. The
    // flag is read from the route (stamped at build time) so the
    // value used to render is the same one `table_diff` compared.
    let offset_metric = route.metric.saturating_add(BACKUP_METRIC_OFFSET);
    let (primary_metric, backup_metric) = if route.backup_as_primary {
        (offset_metric, route.metric)
    } else {
        (route.metric, offset_metric)
    };
    let nhops: Vec<rib::NexthopUni> = route
        .nhops
        .iter()
        .flat_map(|(key, value)| {
            let primary = nhop_to_nexthop_uni::<F>(key, route, value, primary_metric);
            let backup = value
                .backup
                .as_ref()
                .map(|b| F::backup_to_nexthop_uni(b, backup_metric));
            std::iter::once(primary).chain(backup)
        })
        .collect();
    rib.nexthop = build_rib_nexthop(nhops);
    rib
}

// Dispatch a flat list of NexthopUni into the right rib::Nexthop
// variant. Group nhops by metric (BTreeMap iter is ascending), then:
//
//   - 0 groups          -> Nexthop::default()
//   - 1 group, 1 nhop   -> Nexthop::Uni
//   - 1 group, N nhops  -> Nexthop::Multi (ECMP)
//   - 2 groups          -> Nexthop::Protect, the lower-metric group as
//                          the primary and the offset group as the
//                          TI-LFA backup:
//                            * single-nhop group -> NexthopMember::Uni
//                            * multi-nhop group  -> NexthopMember::Multi
//
// Without TI-LFA every nhop sits at route.metric, so only the first
// three arms fire. A stamped backup adds the second metric group
// (primary.metric + BACKUP_METRIC_OFFSET, or swapped under
// backup-as-primary); ECMP-primary + ECMP-backup naturally collapses
// to a Protect of two Multi members. The caller only ever feeds two
// distinct metrics, so >2 groups can't happen — the List fallback is
// defensive.
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
        let mut members: Vec<_> = groups
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
        if members.len() == 2 {
            let backup = members.pop().unwrap();
            let primary = members.pop().unwrap();
            rib::Nexthop::Protect(rib::NexthopProtect {
                primary,
                backup,
                gid: 0,
            })
        } else {
            rib::Nexthop::List(rib::NexthopList { nexthops: members })
        }
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
    route: &SpfRoute<V4>,
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
/// Diff per-algo IPv6 RIB snapshots (SRv6 dataplane) and install the
/// per-algo locator routes into the kernel FIB as real IPv6 routes.
///
/// Unlike `diff_apply_flex_algo` (SR-MPLS), which feeds the colour-aware
/// nexthop resolver an outer-label-per-(algo, prefix) shadow, SRv6
/// per-algo reachability is plain longest-prefix IPv6 to each node's
/// distinct per-algo locator. So we reuse the ordinary IPv6 install path
/// (`diff_apply::<V6>` → `Ipv6Add` / `Ipv6Del`) per algorithm; the
/// per-algo locator prefixes never collide with algo-0 reachability.
fn diff_apply_flex_algo6(
    rib_client: &crate::rib::client::RibClient,
    level: Level,
    prev: &BTreeMap<u8, PrefixMap<Ipv6Net, SpfRoute<V6>>>,
    next: &BTreeMap<u8, PrefixMap<Ipv6Net, SpfRoute<V6>>>,
) {
    let all_algos: BTreeSet<u8> = prev.keys().chain(next.keys()).copied().collect();
    let empty: PrefixMap<Ipv6Net, SpfRoute<V6>> = PrefixMap::new();
    for algo in all_algos {
        let prev_table = prev.get(&algo).unwrap_or(&empty);
        let next_table = next.get(&algo).unwrap_or(&empty);
        let diff = spf::table_diff(prev_table.iter(), next_table.iter());
        diff_apply::<V6>(rib_client, &diff, level);
    }
}

pub fn diff_apply_flex_algo(
    rib_client: &crate::rib::client::RibClient,
    prev: &BTreeMap<u8, PrefixMap<Ipv4Net, SpfRoute<V4>>>,
    next: &BTreeMap<u8, PrefixMap<Ipv4Net, SpfRoute<V4>>>,
) {
    let all_algos: BTreeSet<u8> = prev.keys().chain(next.keys()).copied().collect();
    let empty: PrefixMap<Ipv4Net, SpfRoute<V4>> = PrefixMap::new();
    for algo in all_algos {
        let prev_table = prev.get(&algo).unwrap_or(&empty);
        let next_table = next.get(&algo).unwrap_or(&empty);
        let diff = spf::table_diff(prev_table.iter(), next_table.iter());

        for (prefix, _) in diff.only_curr.iter() {
            let msg = rib::Message::FlexAlgoRouteDel {
                algo,
                prefix: *prefix,
            };
            rib_client.send(msg).unwrap();
        }
        for (prefix, _, route) in diff.different.iter() {
            // A changed route that no longer has a usable forwarding
            // plane (lost SID or lost all nhops) collapses to a Del.
            match make_flex_algo_route(algo, *prefix, route) {
                Some(r) => {
                    let msg = rib::Message::FlexAlgoRouteAdd { route: r };
                    rib_client.send(msg).unwrap();
                }
                None => {
                    let msg = rib::Message::FlexAlgoRouteDel {
                        algo,
                        prefix: *prefix,
                    };
                    rib_client.send(msg).unwrap();
                }
            }
        }
        for (prefix, route) in diff.only_next.iter() {
            if let Some(r) = make_flex_algo_route(algo, *prefix, route) {
                let msg = rib::Message::FlexAlgoRouteAdd { route: r };
                rib_client.send(msg).unwrap();
            }
        }
    }
}

pub fn diff_apply<F: IsisRibFamily>(
    rib_client: &crate::rib::client::RibClient,
    diff: &DiffResult<'_, F>,
    level: Level,
) {
    // Mirrors `diff_apply_flex_algo`: a prefix that left the table, or
    // changed to a route with no forwarding plane, must always be
    // withdrawn. `rib_del` is keyed on RibType, so it is a harmless
    // no-op when nothing is installed — but skipping it leaks a
    // previously-installed route whose nexthops were later cleared.
    // (An earlier V4 builder could cache empty-nexthop entries; guarding
    // the delete on `!nhops.is_empty()` then dropped their withdrawal and
    // orphaned the kernel FIB route.)
    for (prefix, route) in diff.only_curr.iter() {
        let entry = make_rib_entry::<F>(route, level);
        rib_client.send(F::rib_del(*prefix, entry)).unwrap();
    }
    for (prefix, _, route) in diff.different.iter() {
        let entry = make_rib_entry::<F>(route, level);
        if route.nhops.is_empty() {
            // Lost all nexthops: collapse the change to a withdrawal so
            // the stale install is removed rather than left behind.
            rib_client.send(F::rib_del(*prefix, entry)).unwrap();
        } else {
            rib_client.send(F::rib_add(*prefix, entry)).unwrap();
        }
    }
    for (prefix, route) in diff.only_next.iter() {
        // A brand-new prefix with no nexthops has nothing to install and
        // no prior FIB state to withdraw, so it is simply skipped.
        if !route.nhops.is_empty() {
            let entry = make_rib_entry::<F>(route, level);
            rib_client.send(F::rib_add(*prefix, entry)).unwrap();
        }
    }
}

fn make_ilm_entry(label: u32, ilm: &SpfIlm) -> IlmEntry {
    if ilm.nhops.len() == 1
        && let Some((&addr, nhop)) = ilm.nhops.iter().next()
    {
        let mut uni = NexthopUni {
            addr: IpAddr::V4(addr),
            ifindex_origin: (nhop.ifindex != 0).then_some(nhop.ifindex),
            ..Default::default()
        };
        // Penultimate hop (`adjacency`) pops by default (PHP); a no-PHP
        // Prefix-SID keeps the label (swap label->label) so the SID owner
        // receives it intact.
        if !nhop.adjacency || ilm.no_php {
            uni.mpls_label.push(label);
        }
        return IlmEntry {
            ilm_type: ilm.ilm_type.clone(),
            nexthop: Nexthop::Uni(uni),
            ..IlmEntry::new(RibType::Isis)
        };
    }
    let mut multi = NexthopMulti::default();
    for (&addr, nhop) in ilm.nhops.iter() {
        let mut uni = NexthopUni {
            addr: IpAddr::V4(addr),
            ifindex_origin: (nhop.ifindex != 0).then_some(nhop.ifindex),
            ..Default::default()
        };
        // See the single-nexthop arm: no-PHP keeps the label even on a
        // penultimate-hop adjacency.
        if !nhop.adjacency || ilm.no_php {
            uni.mpls_label.push(label);
        }
        multi.nexthops.push(uni);
    }
    IlmEntry {
        ilm_type: ilm.ilm_type.clone(),
        nexthop: Nexthop::Multi(multi),
        ..IlmEntry::new(RibType::Isis)
    }
}

pub fn diff_ilm_apply(rib_client: &crate::rib::client::RibClient, diff: &DiffIlmResult) {
    // Delete.
    for (label, ilm) in diff.only_curr.iter() {
        if !ilm.nhops.is_empty() {
            let ilm_entry = make_ilm_entry(*label, ilm);
            let msg = rib::Message::IlmDel {
                label: *label,
                ilm: ilm_entry,
            };
            rib_client.send(msg).unwrap();
        }
    }
    // Add (changed).
    for (label, _, ilm) in diff.different.iter() {
        if !ilm.nhops.is_empty() {
            let ilm_entry = make_ilm_entry(*label, ilm);
            let msg = rib::Message::IlmAdd {
                label: *label,
                ilm: ilm_entry,
            };
            rib_client.send(msg).unwrap();
        }
    }
    // Add (new).
    for (label, ilm) in diff.only_next.iter() {
        if !ilm.nhops.is_empty() {
            let ilm_entry = make_ilm_entry(*label, ilm);
            let msg = rib::Message::IlmAdd {
                label: *label,
                ilm: ilm_entry,
            };
            rib_client.send(msg).unwrap();
        }
    }
}
#[derive(Debug, PartialEq)]
pub struct SpfIlm {
    pub nhops: BTreeMap<Ipv4Addr, SpfNexthop<V4>>,
    pub ilm_type: IlmType,
    /// RFC 8667 §2.1.1 P (no-PHP) flag. When true, `make_ilm_entry`
    /// keeps the label (swap) even for a penultimate-hop (`adjacency`)
    /// nexthop instead of installing a pop, so the SID owner receives
    /// the label intact. Only set for remote Prefix-SID ILMs whose
    /// origin advertised P; adjacency-SID and self-SID ILMs leave it
    /// false (PHP / local-pop semantics are unchanged).
    pub no_php: bool,
}

/// Build ILM table with adjacency labels from SIDs
fn build_adjacency_ilm(
    top: &mut IsisTop,
    level: Level,
    sids: &BTreeMap<u32, IsisSysId>,
) -> BTreeMap<u32, SpfIlm> {
    let mut ilm = BTreeMap::new();

    // Adjacency-SID labels are carved from the SRLB of the watched
    // SR-MPLS block (the same pool `local_pool` allocates from in
    // `nbr_hello_interpret`). The index used as `IlmType::Adjacency`
    // is the label's offset within that SRLB. Without a snapshot the
    // pool can't have handed out labels in the first place, so any
    // labels here are stale — fall back to 0 instead of subtracting a
    // bogus base.
    let local_base = top
        .sr_block
        .as_ref()
        .and_then(|b| b.local.as_ref())
        .map(|lb| lb.start)
        .unwrap_or(0);

    for (&label, nhop_id) in sids.iter() {
        let mut nhops = BTreeMap::new();

        for (ifindex, link) in top.links.iter() {
            if let Some(nbr) = link.state.nbrs.get(&level).get(nhop_id) {
                for addr in nbr.addr4.keys() {
                    let nhop = SpfNexthop::<V4> {
                        ifindex: *ifindex,
                        adjacency: true,
                        sys_id: Some(*nhop_id),
                        backup: None,
                    };
                    nhops.insert(*addr, nhop);
                }
            }
        }

        let adj_index = label.saturating_sub(local_base);
        let spf_ilm = SpfIlm {
            nhops,
            ilm_type: IlmType::Adjacency(adj_index),
            // Adjacency-SID semantics are unaffected by the prefix no-PHP flag.
            no_php: false,
        };
        ilm.insert(label, spf_ilm);
    }

    ilm
}

/// Build RIB from SPF calculation results
/// Generic SPF → RIB builder.  Handles both address families through the
/// `IsisRibFamily` trait.
///
/// `capability_set` gates path/node eligibility in the V6 legacy mode
/// (RFC 1195 §5 strict NLPID check).  Pass an empty set for V4 and for
/// V6 in MT 2 mode — an empty set disables all gating.
///
/// `mt2_mode` selects which reach map V6 reads (`mt2_reach_map_v6` vs
/// `reach_map_v6`).  Ignored by V4.
fn build_rib_from_spf<F: IsisRibFamily>(
    top: &mut IsisTop,
    level: Level,
    source: usize,
    spf_result: &BTreeMap<usize, spf::Path>,
    tilfa_result: &BTreeMap<usize, Vec<spf::RepairPath>>,
    capability_set: &BTreeSet<IsisSysId>,
    mt2_mode: bool,
) -> PrefixMap<F::Prefix, SpfRoute<F>> {
    let mut rib: PrefixMap<F::Prefix, SpfRoute<F>> = PrefixMap::new();

    for (node, nhops) in spf_result {
        if *node == source {
            continue;
        }

        // Skip pseudonode entries — they are transit-only and do not
        // own a destination prefix to install.
        if top.lsp_map.get(&level).is_pseudo(*node) {
            continue;
        }

        let Some(sys_id) = top.lsp_map.get(&level).resolve(*node) else {
            continue;
        };

        // NLPID gating (V6 legacy mode only; set is empty for V4 and V6 MT2).
        if !capability_set.is_empty() && !capability_set.contains(sys_id) {
            continue;
        }

        // Capture SysId so later borrows of top.lsp_map don't conflict.
        let dest_sys_id = *sys_id;

        // Build nexthop map keyed by the family's first-hop address type.
        //
        // SPF runs in full-path mode, so each `p` is the full path
        // [first_hop, ..., destination].  With pseudonodes in the graph,
        // p[0] may be a PN — skip leading PN hops to land on the actual
        // nexthop router.  SPF stamps the chosen first-hop link's ifindex
        // into `Path::first_hop_links` during relaxation; we look up all
        // (first_hop_vertex, link_id) entries matching p[0].
        //
        // In V6 legacy mode every transit node must advertise the IPv6
        // NLPID (RFC 1195 §5).  An empty `capability_set` disables the
        // check (V4 and V6 MT2 always pass an empty set).
        let mut spf_nhops = BTreeMap::new();
        'next_path: for p in &nhops.paths {
            // Per-path NLPID gating (V6 legacy mode only).
            if !capability_set.is_empty() {
                for &hop in p {
                    if top.lsp_map.get(&level).is_pseudo(hop) {
                        continue;
                    }
                    let Some(hop_sys_id) = top.lsp_map.get(&level).resolve(hop) else {
                        continue 'next_path;
                    };
                    if !capability_set.contains(hop_sys_id) {
                        continue 'next_path;
                    }
                }
            }

            let Some(nhop_id) = first_router_hop_id(top.lsp_map.get(&level), p) else {
                continue;
            };
            let Some(nhop_sys_id) = top.lsp_map.get(&level).resolve(nhop_id) else {
                continue;
            };
            let nhop_sys_id = *nhop_sys_id;
            let is_adjacency = nhop_id == *node;

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
                for addr in F::nhop_addrs(nbr) {
                    spf_nhops.insert(
                        addr,
                        SpfNexthop::<F> {
                            ifindex: *link_id,
                            adjacency: is_adjacency,
                            sys_id: Some(nhop_sys_id),
                            backup: None,
                        },
                    );
                }
            }
        }

        // No surviving paths after gating — skip this destination.
        if spf_nhops.is_empty() {
            continue;
        }

        // TI-LFA backup stamping is deferred to the second pass below
        // so it sees the stabilised equal-metric merge.
        if let Some(entries) = F::reach_entries(top, &level, &dest_sys_id, mt2_mode) {
            for entry in entries.iter() {
                let prefix = F::entry_prefix(entry);
                let (sid, prefix_sid, no_php) = F::resolve_sid(top, &level, &dest_sys_id, entry);
                let route = SpfRoute::<F> {
                    metric: nhops.cost + F::entry_metric(entry),
                    nhops: spf_nhops.clone(),
                    sid,
                    prefix_sid,
                    no_php,
                    dest_vertex: Some(*node),
                    backup_as_primary: top.config.fast_reroute_backup_as_primary,
                };

                let tprefix = F::trunc_prefix(prefix);
                if let Some(curr) = rib.get_mut(&tprefix) {
                    if curr.metric > route.metric {
                        *curr = route;
                    } else if curr.metric == route.metric {
                        // Equal metric: anycast / shared loopback / sibling
                        // routes.  Merge primaries for ECMP at the RIB level.
                        // The post-loop backup pass skips multi-primary routes
                        // so a stamped backup can't leak across the merge.
                        //
                        // sid / prefix_sid: first-wins (see original V4
                        // comment for the anycast SR caveats).
                        for (addr, nhop) in route.nhops {
                            curr.nhops.insert(addr, nhop);
                        }
                        if curr.sid.is_none() && route.sid.is_some() {
                            curr.sid = route.sid;
                        }
                        if curr.prefix_sid.is_none() && route.prefix_sid.is_some() {
                            curr.prefix_sid = route.prefix_sid;
                            curr.no_php = route.no_php;
                        }
                    }
                } else {
                    rib.insert(tprefix, route);
                }
            }
        }
    }

    // Second pass: TI-LFA backup stamping.
    //
    // Deferred until the equal-metric merge has stabilised.  Skip ECMP
    // routes (the surviving legs already provide protection).
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
        let Some(mut backup) = F::build_repair(top, level, repair) else {
            continue;
        };
        // A repair list only steers the packet to its release point
        // (the last segment's target); from there the inner packet is
        // IP-routed. That suffices for traffic addressed inside the
        // protected prefix itself, but not for traffic tunneled
        // through this route — a recursive static/BGP nexthop that
        // resolved onto it carries an inner destination the release
        // point may not know. When the destination advertises a
        // prefix SID, append its node-SID label below the repair
        // segments so the repair label-switches all the way to the
        // destination node.
        if let Some(sid) = route.sid {
            F::backup_append_prefix_sid(&mut backup, sid);
        }
        if let Some(nhop) = route.nhops.values_mut().next() {
            nhop.backup = Some(backup);
        }
    }

    rib
}

// Walk the LSDB and collect SysIds whose Protocols-Supported TLV (TLV 129)
// includes the IPv6 NLPID (0x8E). Used by strict NLPID gating in
// build_rib_from_spf_v6 and by show.rs to mirror that gate in the
// SPF-tree renderers.
pub(super) fn ipv6_capable_set(lsdb: &Lsdb) -> BTreeSet<IsisSysId> {
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
    rib: PrefixMap<Ipv4Net, SpfRoute<V4>>,
    rib_v6: PrefixMap<Ipv6Net, SpfRoute<V6>>,
    ilm: BTreeMap<u32, SpfIlm>,
) {
    // Update MPLS ILM
    if top.config.distribute.rib {
        let diff = spf::table_diff(
            top.ilm.get(&level).iter().map(|(&k, v)| (k, v)),
            ilm.iter().map(|(&k, v)| (k, v)),
        );
        diff_ilm_apply(top.rib_client, &diff);
    }
    *top.ilm.get_mut(&level) = ilm;

    // The `fast-reroute backup-as-primary` flag is stamped onto each
    // `SpfRoute` at build time and read back in `make_rib_entry`, so
    // the metric ordering is decided by the route, not a separate
    // arg here. A toggle changes every route's stamped flag, which
    // `table_diff` sees as a value change → re-render; the cache
    // stays the delete baseline so withdrawn prefixes still get
    // `only_curr` deletes.

    // Update IPv4 RIB
    if top.config.distribute.rib {
        let diff = spf::table_diff(top.rib.get(&level).iter(), rib.iter());
        diff_apply(top.rib_client, &diff, level);
    }
    *top.rib.get_mut(&level) = rib;

    // Update IPv6 RIB
    if top.config.distribute.rib {
        let diff = spf::table_diff(top.rib_v6.get(&level).iter(), rib_v6.iter());
        diff_apply::<V6>(top.rib_client, &diff, level);
        // Mirror SID node protection: pre-install a high-distance seg6
        // H.Encaps floating backup to the Mirror SID for each protected
        // locator, so best-path promotes it when the failed egress's
        // native route is withdrawn — surviving SPF reconvergence.
        reconcile_retained_locators(top, level, &rib_v6);
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
    /// How the TI-LFA computation is scheduled
    /// (`fast-reroute ti-lfa compute-mode [sharding shards <N>]`),
    /// snapshotted from config at build time so a mid-run change
    /// cleanly applies to the next run.
    tilfa_mode: spf::TilfaComputeMode,
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
    /// Run per-algo TI-LFA in this algo's constrained graph. Set only
    /// for SRv6-dataplane algos with the per-algo `fast-reroute ti-lfa`
    /// toggle — Flex-Algo TI-LFA is an SRv6 feature here.
    ti_lfa: bool,
}

/// Result of a single IS-IS SPF run, ready to be applied back to
/// `IsisTop` by [`apply_spf_result`] on the main task. Public so it
/// can ride on `Message::SpfDone` through the channel.
pub struct SpfOutput {
    pub(super) level: Level,
    source: usize,
    adjacency_sids: BTreeMap<u32, IsisSysId>,
    spf_result: BTreeMap<usize, spf::Path>,
    tilfa_result: BTreeMap<usize, Vec<spf::RepairPath>>,
    /// TI-LFA compute telemetry (legacy + MT2 merged), None when
    /// TI-LFA is disabled. Stashed on `IsisTop::tilfa_stats[level]`
    /// for `show isis spf`.
    tilfa_stats: Option<spf::TilfaStats>,
    mt2: Option<Mt2Output>,
    flex_algos: Vec<FlexAlgoOutput>,
    /// Wall-clock time `compute_spf` spent running Dijkstra + TI-LFA.
    /// Sampled with `Instant::now()` before / after the work; carries
    /// across the channel to `apply_spf_result`, which stashes it on
    /// `IsisTop::spf_duration[level]` for `show isis spf`.
    duration: Duration,
    /// `Instant` at which the SPF run finished (end of `compute_spf`).
    /// Used by `show isis spf` to render "Last SPF: N s ago".
    last: Instant,
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
    /// Per-algo TI-LFA repair paths keyed by destination vertex (empty
    /// when this algo's `ti_lfa` was false). Consumed by the per-algo
    /// IPv6 (SRv6) RIB build to stamp backups; resolved to algo-N End
    /// SIDs so the repair stays in the algo-N topology.
    tilfa: BTreeMap<usize, Vec<spf::RepairPath>>,
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
/// Returns `None` if the legacy graph has no source node — the
/// `Message::SpfCalc` handler treats this as a no-op cycle (no
/// worker is dispatched and `spf_inflight` is not set).
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
            // Per-algo TI-LFA is an SRv6 feature here: compute it only
            // for SRv6-dataplane algos whose per-algo `fast-reroute
            // ti-lfa` toggle is set, so we don't pay the cost for algos
            // whose repair we'd never install.
            ti_lfa: entry.ti_lfa && entry.dataplane_srv6 == Some(true),
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
        tilfa_mode: top.config.tilfa_compute_mode(),
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
        tilfa_mode,
        mt2,
        flex_algos,
    } = input;
    // Wall-clock window spans every Dijkstra + every TI-LFA call, so
    // the figure reflects the cost the offload worker actually paid —
    // not just the legacy SPF. `apply_spf_result` runs on the main
    // task and is *not* counted; that's RIB-publish work, not compute.
    let start = Instant::now();

    // Legacy SPF. Full-path mode so the legacy v6 builder can apply
    // RFC 1195 §5 strict NLPID gating across every transit node.
    let spf_result = spf::spf(&legacy_graph, source, &spf::SpfOpt::full_path());

    // TI-LFA repair path. Gated on `fast-reroute ti-lfa` — when the
    // knob is off we still install the primary RIB built from
    // `spf_result`, just without the per-destination repair list.
    let mut tilfa_stats: Option<spf::TilfaStats> = None;
    let tilfa_result = if ti_lfa_enabled {
        let (result, stats) =
            tilfa_repair_path(&legacy_graph, &lsp_map, source, &spf_result, tilfa_mode);
        tilfa_stats = Some(stats);
        result
    } else {
        BTreeMap::new()
    };

    // MT 2 SPF + TI-LFA.
    let mt2 = mt2.map(|Mt2Input { graph, source }| {
        let (spf, tilfa) = match source {
            Some(src) => {
                let mt2_spf = spf::spf(&graph, src, &spf::SpfOpt::full_path());
                let mt2_tilfa = if ti_lfa_enabled {
                    let (result, stats) =
                        tilfa_repair_path(&graph, &lsp_map, src, &mt2_spf, tilfa_mode);
                    tilfa_stats = Some(tilfa_stats.map_or(stats, |prev| prev.merge(stats)));
                    result
                } else {
                    BTreeMap::new()
                };
                (Some(mt2_spf), mt2_tilfa)
            }
            None => (None, BTreeMap::new()),
        };
        Mt2Output { source, spf, tilfa }
    });

    // Per-algo SPF + (SRv6) TI-LFA. The repair is computed in this
    // algo's *constrained* graph so it never leaves the algo-N
    // topology. Per-algo TI-LFA stats are intentionally not merged into
    // `tilfa_stats` (which `show isis spf` reports) so the legacy + MT2
    // figures stay comparable across releases.
    let flex_algos = flex_algos
        .into_iter()
        .map(
            |FlexAlgoInput {
                 algo,
                 graph,
                 source,
                 ti_lfa,
             }| {
                let spf = source.map(|src| spf::spf(&graph, src, &spf::SpfOpt::full_path()));
                let tilfa = match (ti_lfa, source, spf.as_ref()) {
                    (true, Some(src), Some(spf_res)) => {
                        tilfa_repair_path(&graph, &lsp_map, src, spf_res, tilfa_mode).0
                    }
                    _ => BTreeMap::new(),
                };
                FlexAlgoOutput {
                    algo,
                    graph,
                    source,
                    spf,
                    tilfa,
                }
            },
        )
        .collect();

    let last = Instant::now();
    let duration = last.duration_since(start);

    SpfOutput {
        level,
        source,
        adjacency_sids,
        spf_result,
        tilfa_result,
        tilfa_stats,
        mt2,
        flex_algos,
        duration,
        last,
    }
}

/// Apply a completed SPF run: build the IPv4/IPv6/per-algo RIBs and
/// the ILM table, diff against the previous cycle, and publish to
/// the RIB subsystem. Must run on the main task — every helper
/// called from here borrows `IsisTop` and emits on `top.rib_client`.
/// Longest-prefix-match `mirror_sid` in the v6 RIB to find the route to
/// the *protector's* locator, returning its first primary nexthop
/// (address + egress ifindex) — the H.Encaps next-hop the PLR uses to
/// reach the protector. `None` when the protector isn't reachable (no
/// covering route) or that route has no nexthop.
fn nexthop_toward_protector(
    rib_v6: &PrefixMap<Ipv6Net, SpfRoute<V6>>,
    mirror_sid: Ipv6Addr,
) -> Option<(Ipv6Addr, u32)> {
    let host = Ipv6Net::new(mirror_sid, 128).ok()?;
    let (_, route) = rib_v6.get_lpm(&host)?;
    let (addr, nhop) = route.nhops.iter().next()?;
    Some((*addr, nhop.ifindex))
}

/// Attach a Mirror SID egress-protection backup to every route whose
/// destination is a protected egress locator that a peer advertised a
/// Mirror SID for. The backup H.Encaps the packet to the protector's
/// Mirror SID (End.M), so a BFD-driven `protect_switch` on the failed
/// egress adjacency reroutes the traffic to the protector. Skips a route
/// nexthop that already carries a TI-LFA backup (transit protection wins)
/// and a protector that isn't reachable from here.
fn inject_mirror_sid_backups(
    top: &IsisTop,
    level: Level,
    rib_v6: &mut PrefixMap<Ipv6Net, SpfRoute<V6>>,
) {
    let received = super::egress_protection::collect_received_mirror_sids(top.lsdb.get(&level));
    apply_mirror_sid_backups(rib_v6, &received);
}

/// Pure core of [`inject_mirror_sid_backups`] (the LSDB scan factored
/// out so this is testable without an `IsisTop`).
fn apply_mirror_sid_backups(
    rib_v6: &mut PrefixMap<Ipv6Net, SpfRoute<V6>>,
    received: &[super::egress_protection::ReceivedMirrorSid],
) {
    for entry in received {
        let Some((addr, ifindex)) = nexthop_toward_protector(rib_v6, entry.mirror_sid) else {
            continue;
        };
        let Some(route) = rib_v6.get_mut(&entry.protected_locator) else {
            continue;
        };
        let backup = RepairPathSrv6 {
            ifindex,
            addr,
            segs: vec![entry.mirror_sid],
            encap: EncapType::HEncap,
        };
        for nhop in route.nhops.values_mut() {
            if nhop.backup.is_none() {
                nhop.backup = Some(backup.clone());
            }
        }
    }
}

/// Above IS-IS (115) so the native locator route wins while the egress is
/// up; the retained backup is promoted by best-path only once it is gone.
const RETAIN_DISTANCE: u8 = 250;

/// Per-locator node-protection retention state (see
/// [`reconcile_retained_locators`]).
pub struct RetainEntry {
    /// Whether the seg6 backup is currently in the FIB. Cleared once the
    /// hold-down withdraws it; re-set when the egress returns.
    pub installed: bool,
    /// Armed hold-down timer — `Some` while the egress is down and the
    /// hold-down is counting; dropped (cancelled) on recovery. `None` when
    /// the egress is up, the hold-down is disabled, or it already expired.
    pub holddown: Option<crate::context::Timer>,
}

/// Install the seg6 H.Encaps retained backup for `loc` toward the Mirror
/// SID. A distinct `RibType` (Static, not Isis) is required so it coexists
/// with the native locator route under the RIB's per-rtype replacement
/// (same-rtype would orphan one in the kernel); the high distance keeps it
/// unselected until the native route is withdrawn.
fn install_retain_backup(
    rib_client: &crate::rib::client::RibClient,
    loc: Ipv6Net,
    mirror_sid: Ipv6Addr,
    addr: Ipv6Addr,
    ifindex: u32,
) {
    let mut nhop = rib::NexthopUni::new(IpAddr::V6(addr), 0, vec![]);
    nhop.ifindex_origin = (ifindex != 0).then_some(ifindex);
    nhop.segs = vec![mirror_sid];
    nhop.encap_type = Some(EncapType::HEncap);
    nhop.valid = true;
    let mut entry = rib::entry::RibEntry::new(RibType::Static);
    entry.distance = RETAIN_DISTANCE;
    entry.nexthop = rib::Nexthop::Uni(nhop);
    let _ = rib_client.send(crate::rib::Message::Ipv6Add {
        prefix: loc,
        rib: entry,
    });
}

fn withdraw_retain_backup(rib_client: &crate::rib::client::RibClient, loc: Ipv6Net) {
    let entry = rib::entry::RibEntry::new(RibType::Static);
    let _ = rib_client.send(crate::rib::Message::Ipv6Del {
        prefix: loc,
        rib: entry,
    });
}

/// Arm a one-shot hold-down timer that fires `EgressRetentionExpire` for
/// `loc` after `secs`. Held in `RetainEntry::holddown`; dropping it cancels.
fn arm_holddown_timer(
    tx: &super::inst::MsgSender,
    level: Level,
    loc: Ipv6Net,
    secs: u64,
) -> crate::context::Timer {
    let tx = tx.clone();
    crate::context::Timer::once(secs, move || {
        let tx = tx.clone();
        async move {
            let _ = tx.send(super::Message::EgressRetentionExpire {
                level,
                locator: loc,
            });
        }
    })
}

/// Mirror SID node-protection stale-route retention. The `inject_mirror_
/// sid_backups` repair above protects a route to a protected egress
/// locator *while that route still exists* — but once the protected
/// egress's node fails and its LSP ages out, the locator drops out of the
/// SPF result and the diff withdraws it, taking the repair with it.
///
/// This pre-installs a **floating backup**: for every protected locator
/// whose protector is reachable, a seg6 H.Encaps route to the Mirror SID
/// at a high administrative distance (250). The native locator route
/// (distance 115) wins while the egress is up, so the backup sits in the
/// RIB unselected; when the egress's node fails and the native route is
/// withdrawn, best-path promotes the backup — carrying locator-bound
/// traffic to the protector (PEB's End.M) and surviving SPF
/// reconvergence — and demotes it when the egress returns.
///
/// **Hold-down** (`egress-protection hold-down`): when configured non-zero,
/// the backup forwards only for that many seconds after the egress fails,
/// then `EgressRetentionExpire` withdraws it so a genuinely-decommissioned
/// egress is not masked toward the protector forever. The backup is
/// re-installed if the egress later returns. Hold-down `0`/unset keeps the
/// historical float-forever behavior.
///
/// Reconciled every SPF against `top.retained_locators`.
fn reconcile_retained_locators(
    top: &mut IsisTop,
    level: Level,
    rib_v6: &PrefixMap<Ipv6Net, SpfRoute<V6>>,
) {
    // Our own SRv6 locator — never back ourselves up (we *are* the egress
    // for it; a remote protector's offer for our own locator is not ours
    // to retain). `Ipv6Net` is `Copy`, so this releases the `top` borrow.
    let my_locator: Option<Ipv6Net> = top.sr_locator.as_ref().and_then(|l| l.prefix);
    let hold_secs = top.config.egress_protection_holddown.unwrap_or(0) as u64;

    // Desired backups: protected locators whose protector is reachable.
    // locator -> (mirror_sid, nexthop addr, ifindex).
    let mut desired: BTreeMap<Ipv6Net, (Ipv6Addr, Ipv6Addr, u32)> = BTreeMap::new();
    for entry in super::egress_protection::collect_received_mirror_sids(top.lsdb.get(&level)) {
        if my_locator.is_some_and(|my| my.contains(&entry.protected_locator)) {
            continue; // our own locator.
        }
        let Some((addr, ifindex)) = nexthop_toward_protector(rib_v6, entry.mirror_sid) else {
            continue; // protector unreachable — can't back it up.
        };
        desired.insert(entry.protected_locator, (entry.mirror_sid, addr, ifindex));
    }

    // `&RibClient` and the message sender are `Copy`/clonable out, so the
    // `retained` mutable borrow below does not conflict with using them.
    let rib_client = top.rib_client;
    let tx = top.tx.clone();
    let retained = top.retained_locators.get_mut(&level);

    // Withdraw backups no longer desired (protector gone / unprotected).
    let stale: Vec<Ipv6Net> = retained
        .keys()
        .filter(|k| !desired.contains_key(k))
        .copied()
        .collect();
    for loc in stale {
        if let Some(e) = retained.remove(&loc)
            && e.installed
        {
            withdraw_retain_backup(rib_client, loc);
        }
    }

    // Drive each desired backup's state machine off the egress's presence
    // in the SPF result and the hold-down.
    for (loc, (mirror_sid, addr, ifindex)) in desired {
        let egress_up = rib_v6.get(&loc).is_some();
        match retained.get_mut(&loc) {
            None => {
                install_retain_backup(rib_client, loc, mirror_sid, addr, ifindex);
                // First-seen while already down arms the hold-down at once.
                let holddown = (!egress_up && hold_secs > 0)
                    .then(|| arm_holddown_timer(&tx, level, loc, hold_secs));
                retained.insert(
                    loc,
                    RetainEntry {
                        installed: true,
                        holddown,
                    },
                );
            }
            Some(e) => {
                if egress_up {
                    // Up (or recovered): cancel any hold-down; re-install if
                    // a prior hold-down had withdrawn it.
                    e.holddown = None;
                    if !e.installed {
                        install_retain_backup(rib_client, loc, mirror_sid, addr, ifindex);
                        e.installed = true;
                    }
                } else if e.installed && e.holddown.is_none() && hold_secs > 0 {
                    // Egress just went down and the backup is live: start
                    // the hold-down. (Already-armed / expired / hold-down-
                    // disabled entries are left as-is.)
                    e.holddown = Some(arm_holddown_timer(&tx, level, loc, hold_secs));
                }
            }
        }
    }
}

/// Handle a fired node-protection hold-down (`EgressRetentionExpire`): if
/// the egress is still down and the backup is still armed, withdraw it so
/// the failed egress is no longer masked toward the protector. A recovered
/// egress (the reconcile already cancelled the timer) is a no-op.
pub(super) fn egress_retention_expire(top: &mut IsisTop, level: Level, locator: Ipv6Net) {
    let egress_up = top.rib_v6.get(&level).get(&locator).is_some();
    let rib_client = top.rib_client;
    if let Some(e) = top.retained_locators.get_mut(&level).get_mut(&locator) {
        if e.installed && e.holddown.is_some() && !egress_up {
            withdraw_retain_backup(rib_client, locator);
            e.installed = false;
            tracing::info!(
                "[egress-protect] hold-down expired for {} ({}) — withdrew retained Mirror SID backup",
                locator,
                level
            );
        }
        e.holddown = None;
    }
}

/// Recompute and push the node's Mirror SID egress-protection
/// registrations to the RIB: every received `(protected_locator,
/// mirror_sid)` from both levels. The RIB filters to the locators that
/// cover one of *its own* End.DT46 service SIDs, so sending the full set
/// untouched is correct — a transit node that holds no service SID inside
/// any advertised locator redirects nothing. Idempotent reset.
fn register_egress_protections(top: &mut IsisTop) {
    use std::collections::{BTreeMap, BTreeSet};
    // Current LSDB scan: every advertised `(protected_locator ->
    // (mirror_sid, protector))`, plus the set of nodes whose LSPs are
    // present (so we can tell a withdrawn protector apart from an absent
    // one).
    let mut current: BTreeMap<Ipv6Net, (std::net::Ipv6Addr, IsisSysId)> = BTreeMap::new();
    let mut live_nodes: BTreeSet<IsisSysId> = BTreeSet::new();
    for level in [Level::L1, Level::L2] {
        let lsdb = top.lsdb.get(&level);
        for (id, _) in lsdb.iter() {
            if !id.is_pseudo() {
                live_nodes.insert(id.sys_id());
            }
        }
        for e in super::egress_protection::collect_received_mirror_sids(lsdb) {
            current.insert(e.protected_locator, (e.mirror_sid, e.protector));
        }
    }

    // Degenerate-LSDB guard: a link event can momentarily collapse the
    // SPF's LSDB view to just the local node. With no neighbors there are
    // no Mirror SID advertisements to read, so the scan reads empty — but
    // that is a convergence transient, not a withdrawal. Skip the update
    // so the last-known registration survives (the genuine-withdrawal
    // logic below only ever runs against a healthy multi-node LSDB, which
    // is the only state in which a protector can be "present but silent").
    if live_nodes.len() <= 1 {
        return;
    }
    let authoritative =
        authoritative_protections(current, top.egress_protect_registered, &live_nodes);
    *top.egress_protect_registered = authoritative.clone();

    let protections: Vec<(Ipv6Net, std::net::Ipv6Addr)> = authoritative
        .into_iter()
        .map(|(l, (s, _))| (l, s))
        .collect();
    let _ = top
        .rib_client
        .send(crate::rib::Message::EgressProtectSet { protections });
}

/// Proper withdrawal vs. PIC-sticky, factored out for testing. Start from
/// what is advertised now (`current`), then carry forward a
/// previously-registered protection (`prior`) ONLY when its protector's
/// LSP is *absent* from `live_nodes` (a convergence transient — the SPF
/// can momentarily read a partial LSDB, and disarming protection right as
/// a link fails is exactly wrong). A protector whose LSP is present but no
/// longer carries the Mirror SID has genuinely withdrawn it, so it is
/// dropped.
fn authoritative_protections(
    current: std::collections::BTreeMap<Ipv6Net, (Ipv6Addr, IsisSysId)>,
    prior: &std::collections::BTreeMap<Ipv6Net, (Ipv6Addr, IsisSysId)>,
    live_nodes: &std::collections::BTreeSet<IsisSysId>,
) -> std::collections::BTreeMap<Ipv6Net, (Ipv6Addr, IsisSysId)> {
    let mut authoritative = current;
    for (loc, (sid, protector)) in prior.iter() {
        if !authoritative.contains_key(loc) && !live_nodes.contains(protector) {
            authoritative.insert(*loc, (*sid, *protector));
        }
    }
    authoritative
}

/// SR-MPLS counterpart of [`register_egress_protections`]: tell the RIB
/// which context label to redirect *this* node's VPN traffic to if its
/// PE-CE link fails. We are protected when a received Mirror Context
/// binding's FEC covers our own loopback (`te-router-id`); the protector
/// (carried only as a sys-id) is resolved to its loopback via its
/// TE Router-ID so the RIB can build the transport LSP. The RIB does the
/// VPN-label-ILM override on link state. Idempotent reset.
fn register_mpls_protections(top: &IsisTop) {
    use std::net::{IpAddr, Ipv4Addr};
    let Some(my_loopback) = top.config.te_router_id else {
        let _ = top
            .rib_client
            .send(crate::rib::Message::EgressMplsProtectSet {
                protections: Vec::new(),
            });
        return;
    };
    let my_sys_id = top.config.net.sys_id();
    // context_label -> protector loopback.
    let mut set: std::collections::BTreeMap<u32, Ipv4Addr> = std::collections::BTreeMap::new();
    for level in [Level::L1, Level::L2] {
        let lsdb = top.lsdb.get(&level);
        for b in super::egress_protection::collect_received_mpls_bindings(lsdb) {
            // Protected when the binding's FEC covers our own loopback,
            // and the binding came from someone else.
            if b.protector == my_sys_id || !b.protected_fec.contains(&IpAddr::V4(my_loopback)) {
                continue;
            }
            if let Some(protector_lo) =
                super::egress_protection::node_te_router_id(lsdb, b.protector)
            {
                set.insert(b.context_label, protector_lo);
            }
        }
    }
    let protections: Vec<(u32, Ipv4Addr)> = set.into_iter().collect();
    let _ = top
        .rib_client
        .send(crate::rib::Message::EgressMplsProtectSet { protections });
}

pub(super) fn apply_spf_result(top: &mut IsisTop, output: SpfOutput) {
    let SpfOutput {
        level,
        source,
        adjacency_sids,
        spf_result,
        tilfa_result,
        tilfa_stats,
        mt2,
        flex_algos,
        duration,
        last,
    } = output;

    // Stash the compute window on `IsisTop` so `show isis spf` can
    // render "Last SPF: N s ago, took M μs" per level. Done early so
    // the stamps reflect "SPF finished" not "RIB-publish finished" —
    // the RIB-publish work below isn't counted in `duration`.
    *top.spf_duration.get_mut(&level) = Some(duration);
    *top.spf_last.get_mut(&level) = Some(last);
    // TI-LFA compute telemetry rides the same path; None (TI-LFA
    // disabled) clears any stale stats from a previous enable.
    *top.tilfa_stats.get_mut(&level) = tilfa_stats;

    // Build Adjacency ILM seed from the SIDs collected during graph build.
    let mut ilm = build_adjacency_ilm(top, level, &adjacency_sids);

    // Our own SRGB — used to derive `IlmType::Node(index)` for prefix-
    // SID labels we install. None when SR-MPLS is off, the watched
    // block is unset, or the RIB hasn't delivered the snapshot yet.
    let srgb = top.sr_block.as_ref().and_then(|b| b.global.as_ref());

    // IPv4 RIB.
    let rib = build_rib_from_spf::<V4>(
        top,
        level,
        source,
        &spf_result,
        &tilfa_result,
        &BTreeSet::new(),
        false,
    );

    // IPv6 RIB — either MT 2 (when enabled) or the legacy single-topology path.
    let mut rib_v6 = match mt2 {
        Some(Mt2Output {
            source: Some(mt2_src),
            spf: Some(mt2_spf),
            tilfa: mt2_tilfa,
        }) => {
            let rib_v6 = build_rib_from_spf::<V6>(
                top,
                level,
                mt2_src,
                &mt2_spf,
                &mt2_tilfa,
                &BTreeSet::new(),
                true,
            );
            *top.mt2_spf_result.get_mut(&level) = Some(mt2_spf);
            rib_v6
        }
        Some(_) => {
            // MT 2 enabled but no source — clear and install nothing.
            *top.mt2_spf_result.get_mut(&level) = None;
            PrefixMap::<Ipv6Net, SpfRoute<V6>>::new()
        }
        None => {
            // No MT 2: fall back to legacy graph + reach_map_v6 (and
            // the legacy TI-LFA result) for IPv6.
            let cap_set = ipv6_capable_set(top.lsdb.get(&level));
            build_rib_from_spf::<V6>(
                top,
                level,
                source,
                &spf_result,
                &tilfa_result,
                &cap_set,
                false,
            )
        }
    };

    // Mirror SID egress protection (draft-ietf-rtgwg-srv6-egress-
    // protection): for any route to a protected egress locator that a
    // peer advertised a Mirror SID for, install an H.Encaps-to-the-
    // Mirror-SID backup so a BFD-driven `protect_switch` reroutes to the
    // protector when the protected egress fails.
    inject_mirror_sid_backups(top, level, &mut rib_v6);

    // Egress *link* protection (same draft): push every received
    // `(protected_locator, mirror_sid)` to the RIB. The RIB redirects a
    // *local* End.DT46 service SID inside a protected locator to the
    // Mirror SID when its PE-CE link goes down (the protected egress acts
    // as its own PLR). Recomputed per-SPF so it tracks LSDB changes.
    register_egress_protections(top);
    register_mpls_protections(top);

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
    let mut new_flex_algo_rib: BTreeMap<u8, PrefixMap<Ipv4Net, SpfRoute<V4>>> = BTreeMap::new();
    let mut new_flex_algo_rib6: BTreeMap<u8, PrefixMap<Ipv6Net, SpfRoute<V6>>> = BTreeMap::new();
    let mut new_flex_algo_srv6_export: BTreeMap<u8, BTreeMap<IpNet, Ipv6Addr>> = BTreeMap::new();
    for FlexAlgoOutput {
        algo,
        graph: algo_graph,
        source: algo_source,
        spf: algo_spf,
        tilfa: algo_tilfa,
    } in flex_algos
    {
        // Per-algo dataplane participation (RFC 9350 §6). Build the
        // SR-MPLS IPv4 RIB when the algo enables sr-mpls, and the SRv6
        // IPv6 RIB when it enables srv6. The flag block is scoped so the
        // immutable `top.flex_algo` borrow ends before the `&mut top`
        // RIB builders run. Default (no dataplane flag, or only `ip`)
        // keeps the historical SR-MPLS behavior; an algo that enables
        // *only* srv6 skips the SR-MPLS build.
        let (mpls_on, srv6_on) = {
            let entry = top.flex_algo.config.get(&algo);
            let srv6_on = entry
                .map(|e| e.dataplane_srv6 == Some(true))
                .unwrap_or(false);
            let mpls_on = entry
                .map(|e| e.dataplane_sr_mpls == Some(true) || e.dataplane_srv6 != Some(true))
                .unwrap_or(true);
            (mpls_on, srv6_on)
        };

        // The per-algo SPF graph is address-family-independent, so both
        // dataplanes reuse the same `spf_res`. Empty PrefixMaps when the
        // algo lacks a source/SPF or doesn't enable that dataplane, so
        // the show command and the route diff still see a well-formed
        // (if empty) snapshot.
        let algo_rib = match (mpls_on, algo_source, algo_spf.as_ref()) {
            (true, Some(src), Some(spf_res)) => {
                let r = build_rib_from_flex_algo(top, level, algo, src, spf_res);
                mpls_route(&r, &mut ilm, srgb);
                r
            }
            _ => PrefixMap::<Ipv4Net, SpfRoute<V4>>::new(),
        };
        let algo_rib6 = match (srv6_on, algo_source, algo_spf.as_ref()) {
            (true, Some(src), Some(spf_res)) => {
                // Colour-steering export: (prefix → node End SID) for the
                // BGP resolver. Built only when this algo runs SRv6.
                let export = build_flex_algo_srv6_export(top, level, algo, src, spf_res);
                if !export.is_empty() {
                    new_flex_algo_srv6_export.insert(algo, export);
                }
                build_rib6_from_flex_algo(top, level, algo, src, spf_res, &algo_tilfa)
            }
            _ => PrefixMap::<Ipv6Net, SpfRoute<V6>>::new(),
        };

        new_flex_algo_graphs.insert(algo, Some(algo_graph));
        new_flex_algo_spfs.insert(algo, algo_spf);
        new_flex_algo_rib.insert(algo, algo_rib);
        new_flex_algo_rib6.insert(algo, algo_rib6);
    }
    // Per-algo route diff → RIB publish. SR-MPLS feeds the colour-aware
    // nexthop resolver (shadow on `Rib::flex_algo_routes`, outer MPLS
    // label per (algo, prefix)); SRv6 installs per-algo locator routes
    // straight into the kernel FIB as plain IPv6 routes.
    if top.config.distribute.rib {
        diff_apply_flex_algo(
            top.rib_client,
            top.rib_flex_algo.get(&level),
            &new_flex_algo_rib,
        );
        diff_apply_flex_algo6(
            top.rib_client,
            level,
            top.rib6_flex_algo.get(&level),
            &new_flex_algo_rib6,
        );
        // SRv6 colour-steering export → RIB → BGP colour-aware resolver.
        diff_apply_flex_algo_srv6(
            top.rib_client,
            top.flex_algo_srv6_export.get(&level),
            &new_flex_algo_srv6_export,
        );
    }

    // Swap the new state in. The retain that used to live above is
    // implicit: any algo present in the old map but absent from the
    // new one yielded route Del messages above; the swap drops the old
    // entry entirely.
    *top.graph_flex_algo.get_mut(&level) = new_flex_algo_graphs;
    *top.spf_flex_algo.get_mut(&level) = new_flex_algo_spfs;
    *top.rib_flex_algo.get_mut(&level) = new_flex_algo_rib;
    *top.rib6_flex_algo.get_mut(&level) = new_flex_algo_rib6;
    *top.flex_algo_srv6_export.get_mut(&level) = new_flex_algo_srv6_export;

    *top.spf_result.get_mut(&level) = Some(spf_result);
    *top.tilfa_result.get_mut(&level) = Some(tilfa_result);
    mpls_route(&rib, &mut ilm, srgb);
    // SR-MPLS forwarding gates the whole MPLS LFIB. Prefix-SID labels
    // resolve from peers' advertisements (`label_map` / reach-map),
    // independent of our own SR state, so without this an SPF pass after
    // `no segment-routing mpls` would happily re-install remote
    // prefix-SID and adjacency-SID entries. Dropping the desired set
    // here makes `apply_routing_updates` withdraw every ILM entry.
    if !top.config.sr_mpls_enabled {
        ilm.clear();
    }
    apply_routing_updates(top, level, rib, rib_v6, ilm);
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
/// Build the per-algorithm IPv6 RIB (SRv6 dataplane) from a Flex-Algo
/// SPF result. Unlike the SR-MPLS path, SRv6 Flex-Algo does not push a
/// per-prefix SID: each node advertises a *distinct* per-algo SRv6
/// locator (RFC 9352 §7.1, Algorithm = N), so reaching that node "in
/// algo N" is plain longest-prefix IPv6 to its locator over the algo-N
/// constrained topology. This routes each participating origin's
/// per-algo locator prefix (`peer_algo_srv6[origin][algo]`) with the
/// algo-N SPF nexthop(s) — no SID push for transit.
///
/// When `tilfa` is non-empty (the algo's per-algo `fast-reroute ti-lfa`
/// toggle was set), each single-nexthop locator route also gets a TI-LFA
/// backup computed in the algo-N constrained graph and resolved to
/// algo-N node End SIDs (so the repair stays in the algo-N topology).
///
/// Nodes that did not advertise a per-algo locator are skipped: they do
/// not participate in algo-N SRv6 forwarding. The algo-0 IPv6 RIB still
/// covers ordinary reachability, so nothing is lost.
fn build_rib6_from_flex_algo(
    top: &mut IsisTop,
    level: Level,
    algo: u8,
    source: usize,
    spf_result: &BTreeMap<usize, spf::Path>,
    tilfa: &BTreeMap<usize, Vec<spf::RepairPath>>,
) -> PrefixMap<Ipv6Net, SpfRoute<V6>> {
    let mut rib = PrefixMap::<Ipv6Net, SpfRoute<V6>>::new();

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
        // The per-algo SRv6 locator this origin advertised. Absent → the
        // node doesn't participate in algo-N SRv6; skip it.
        let Some(locator) = top
            .peer_algo_srv6
            .get(&level)
            .get(&sys_id)
            .and_then(|m| m.get(&algo))
            .map(|l| l.locator)
        else {
            continue;
        };

        // First-router-hop walk, identical to the IPv4 builder, but the
        // nexthop addresses are the neighbor's link-local IPv6 (SRv6
        // transit is plain IPv6 forwarding over the egress link).
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
                for addr in nbr.addr6l.iter() {
                    spf_nhops.insert(
                        *addr,
                        SpfNexthop::<V6> {
                            ifindex: *link_id,
                            adjacency: *node == nhop_id,
                            sys_id: Some(nhop_sys_id),
                            backup: None,
                        },
                    );
                }
            }
        }
        if spf_nhops.is_empty() {
            continue;
        }

        let mut route = SpfRoute::<V6> {
            metric: nhops.cost,
            nhops: spf_nhops,
            sid: None,
            prefix_sid: None,
            no_php: false,
            dest_vertex: Some(*node),
            backup_as_primary: top.config.fast_reroute_backup_as_primary,
        };

        // Per-algo TI-LFA backup. Single-nexthop only (an ECMP route is
        // already self-protecting), mirroring `build_rib_from_spf`. Node
        // segments resolve to algo-N End SIDs so the repair stays in the
        // algo-N topology; adjacency segments prefer the peer's algo-N
        // End.X (falling back to algo-0). A repair whose segments can't
        // all resolve (e.g. the origin hasn't advertised an algo-N End
        // SID for a node hop) is dropped rather than installed partial.
        if route.nhops.len() == 1
            && let Some(repair) = tilfa.get(node).and_then(|paths| paths.first())
            && let Some(backup) = build_repair_path_srv6(top, level, Some(algo), repair)
            && let Some(nhop) = route.nhops.values_mut().next()
        {
            nhop.backup = Some(backup);
        }

        rib.insert(locator.trunc(), route);
    }

    rib
}

/// Build the per-algorithm SRv6 colour-steering export for one algo: for
/// every node reachable in algo-N that advertises an algo-N End SID, map
/// each of that node's advertised IPv4 / IPv6 prefixes to that node's End
/// SID. The BGP colour-aware resolver LPMs a coloured service route's
/// next-hop against this and H.Encaps toward the End SID. Mirrors the
/// reach-entry walk in `build_rib_from_flex_algo`, but the value is the
/// node End SID (one per node, since SRv6 has no per-prefix SID) rather
/// than a per-prefix label.
fn build_flex_algo_srv6_export(
    top: &IsisTop,
    level: Level,
    algo: u8,
    source: usize,
    spf_result: &BTreeMap<usize, spf::Path>,
) -> BTreeMap<IpNet, Ipv6Addr> {
    let mut out = BTreeMap::new();
    for node in spf_result.keys() {
        if *node == source {
            continue;
        }
        if top.lsp_map.get(&level).is_pseudo(*node) {
            continue;
        }
        let Some(sys_id) = top.lsp_map.get(&level).resolve(*node).copied() else {
            continue;
        };
        let Some(end_sid) = top
            .peer_algo_srv6
            .get(&level)
            .get(&sys_id)
            .and_then(|m| m.get(&algo))
            .map(|l| l.end.sid)
        else {
            continue;
        };
        if let Some(entries) = top.reach_map.get(&level).get(&Afi::Ip).get(&sys_id) {
            for e in entries.iter() {
                out.insert(IpNet::V4(e.prefix.trunc()), end_sid);
            }
        }
        if let Some(entries) = top.reach_map_v6.get(&level).get(&sys_id) {
            for e in entries.iter() {
                out.insert(IpNet::V6(e.prefix.trunc()), end_sid);
            }
        }
    }
    out
}

/// Diff per-algo SRv6 colour-steering exports and emit
/// `Message::FlexAlgoSrv6RouteAdd/Del` so RIB (→ BGP colour resolver)
/// tracks the live (prefix → node End SID) state. An add is emitted for
/// a new or changed End SID; a del when a prefix leaves algo-N.
fn diff_apply_flex_algo_srv6(
    rib_client: &crate::rib::client::RibClient,
    prev: &BTreeMap<u8, BTreeMap<IpNet, Ipv6Addr>>,
    next: &BTreeMap<u8, BTreeMap<IpNet, Ipv6Addr>>,
) {
    let all_algos: BTreeSet<u8> = prev.keys().chain(next.keys()).copied().collect();
    let empty: BTreeMap<IpNet, Ipv6Addr> = BTreeMap::new();
    for algo in all_algos {
        let prev_t = prev.get(&algo).unwrap_or(&empty);
        let next_t = next.get(&algo).unwrap_or(&empty);
        for prefix in prev_t.keys() {
            if !next_t.contains_key(prefix) {
                rib_client
                    .send(rib::Message::FlexAlgoSrv6RouteDel {
                        algo,
                        prefix: *prefix,
                    })
                    .unwrap();
            }
        }
        for (prefix, end_sid) in next_t {
            if prev_t.get(prefix) != Some(end_sid) {
                rib_client
                    .send(rib::Message::FlexAlgoSrv6RouteAdd {
                        route: crate::rib::api::FlexAlgoSrv6Route {
                            algo,
                            prefix: *prefix,
                            end_sid: *end_sid,
                        },
                    })
                    .unwrap();
            }
        }
    }
}

fn build_rib_from_flex_algo(
    top: &mut IsisTop,
    level: Level,
    algo: u8,
    source: usize,
    spf_result: &BTreeMap<usize, spf::Path>,
) -> PrefixMap<Ipv4Net, SpfRoute<V4>> {
    let mut rib = PrefixMap::<Ipv4Net, SpfRoute<V4>>::new();

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
                for addr in nbr.addr4.keys() {
                    let nhop = SpfNexthop::<V4> {
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
                // `peer_algo_sid` stores only the SID value, not the
                // Prefix-SID flags, so per-algo no-PHP isn't carried yet.
                no_php: false,
                dest_vertex: Some(*node),
                backup_as_primary: top.config.fast_reroute_backup_as_primary,
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

/// Resolve a configured Prefix-SID value to `(label, index)` against
/// our own SRGB. Index SIDs need the SRGB snapshot (return `None`
/// without it); absolute-label SIDs resolve directly and derive the
/// index for `IlmType::Node` / show output.
fn resolve_self_sid(
    sid: &SidLabelValue,
    srgb: Option<&crate::spf::label_block::LabelBlock>,
) -> Option<(u32, u32)> {
    match sid {
        SidLabelValue::Index(index) => srgb.map(|b| (b.start + index, *index)),
        SidLabelValue::Label(label) => {
            let index = srgb.map(|b| label.saturating_sub(b.start)).unwrap_or(0);
            Some((*label, index))
        }
    }
}

/// Reconcile the local (self-originated) Prefix-SID ILM entries against
/// the kernel LFIB. This is **independent of per-level SPF**: the label
/// is derived from interface config + the global SR block, so it lives
/// in a single map (`Isis::self_sid_ilm`), not `Levels<_>`.
///
/// For every loopback interface (`flags.is_loopback()`) that has IPv4
/// enabled, a configured Prefix-SID, and a routable (non-127.0.0.0/8)
/// address, install a **pop** entry (`adjacency: true`) so traffic that
/// arrives carrying this node's own node-SID label is delivered locally
/// — matching IOS-XR / SR-OS. Gated on `segment-routing mpls` and the
/// absence of the `no-local-prefix-sid` knob; when SR-MPLS is off or
/// `no-local-prefix-sid` is set the desired set is empty and any
/// previously-installed self entries are withdrawn.
///
/// Idempotent: safe to call on every SPF publish. `table_diff` only
/// emits `IlmAdd`/`IlmDel` when the set actually changes.
pub(super) fn update_self_sid_ilm(isis: &mut Isis) {
    let mut desired: BTreeMap<u32, SpfIlm> = BTreeMap::new();

    if isis.config.sr_mpls_enabled && !isis.config.sr_no_local_prefix_sid {
        let srgb = isis.sr_block.as_ref().and_then(|b| b.global.as_ref());
        for (&ifindex, link) in isis.links.iter() {
            if !link.flags.is_loopback() || !link.config.enable.v4 {
                continue;
            }
            let Some(sid) = link.config.prefix_sid.as_ref() else {
                continue;
            };
            let Some((label, index)) = resolve_self_sid(sid, srgb) else {
                continue;
            };
            // The local delivery nexthop is the loopback's own routable
            // IPv4 address; skip the 127.0.0.0/8 literal range.
            let Some(addr) = link
                .state
                .v4addr
                .iter()
                .map(|p| p.addr())
                .find(|a| !a.is_loopback())
            else {
                continue;
            };
            let mut nhops = BTreeMap::new();
            nhops.insert(
                addr,
                SpfNexthop::<V4> {
                    ifindex,
                    adjacency: true,
                    sys_id: None,
                    backup: None,
                },
            );
            desired.insert(
                label,
                SpfIlm {
                    nhops,
                    ilm_type: IlmType::Node(index),
                    // Self-SID ILM is always a local pop; no-PHP is about
                    // the penultimate hop, not the owner.
                    no_php: false,
                },
            );
        }
    }

    let diff = spf::table_diff(
        isis.self_sid_ilm.iter().map(|(&k, v)| (k, v)),
        desired.iter().map(|(&k, v)| (k, v)),
    );
    diff_ilm_apply(&isis.ctx.rib, &diff);
    isis.self_sid_ilm = desired;
}

pub fn mpls_route(
    rib: &PrefixMap<Ipv4Net, SpfRoute<V4>>,
    ilm: &mut BTreeMap<u32, SpfIlm>,
    srgb: Option<&crate::spf::label_block::LabelBlock>,
) {
    for (_prefix, route) in rib.iter() {
        if let Some(sid) = route.sid {
            // Prefix-SID labels live inside our own SRGB; the Node
            // index is the label's offset from `global.start`. Labels
            // outside the SRGB (or with no SRGB snapshot at all) get
            // index 0 — the previous hardcoded `16000..24000` window
            // silently misindexed any operator-configured SRGB the
            // same way.
            let pfx_index = srgb
                .filter(|gb| (gb.start..gb.end).contains(&sid))
                .map(|gb| sid - gb.start)
                .unwrap_or(0);
            let spf_ilm = SpfIlm {
                nhops: route.nhops.clone(),
                ilm_type: IlmType::Node(pfx_index),
                // Carry the destination's no-PHP request so the
                // penultimate-hop ILM swaps instead of popping.
                no_php: route.no_php,
            };
            ilm.insert(sid, spf_ilm);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authoritative_protections_withdraws_only_when_protector_present() {
        use std::collections::{BTreeMap, BTreeSet};
        let loc = |s: &str| s.parse::<Ipv6Net>().unwrap();
        let sid = |s: &str| s.parse::<Ipv6Addr>().unwrap();
        let peb = IsisSysId {
            id: [0, 0, 0, 0, 0, 4],
        };
        let pec = IsisSysId {
            id: [0, 0, 0, 0, 0, 5],
        };

        let l_keep = loc("2001:db8:a::/48"); // still advertised
        let l_withdrawn_live = loc("2001:db8:b::/48"); // protector live, stopped advertising
        let l_withdrawn_absent = loc("2001:db8:c::/48"); // protector LSP absent (transient)

        let prior: BTreeMap<Ipv6Net, (Ipv6Addr, IsisSysId)> = [
            (l_keep, (sid("2001:db8:4::1"), peb)),
            (l_withdrawn_live, (sid("2001:db8:4::2"), peb)),
            (l_withdrawn_absent, (sid("2001:db8:4::3"), pec)),
        ]
        .into_iter()
        .collect();

        // Only `l_keep` is still advertised; peb's LSP is present, pec's is not.
        let current: BTreeMap<Ipv6Net, (Ipv6Addr, IsisSysId)> =
            [(l_keep, (sid("2001:db8:4::1"), peb))]
                .into_iter()
                .collect();
        let live_nodes: BTreeSet<IsisSysId> = [peb].into_iter().collect();

        let out = authoritative_protections(current, &prior, &live_nodes);

        // Still advertised → kept.
        assert!(out.contains_key(&l_keep));
        // Protector live but no longer advertising → genuine withdrawal, dropped.
        assert!(!out.contains_key(&l_withdrawn_live));
        // Protector's LSP absent → convergence transient, kept (PIC-like).
        assert!(out.contains_key(&l_withdrawn_absent));
    }

    #[test]
    fn resolve_self_sid_index_and_label() {
        use crate::spf::label_block::LabelBlock;
        let srgb = LabelBlock {
            start: 16000,
            end: 24000,
        };
        // Index form: label = SRGB.start + index.
        assert_eq!(
            resolve_self_sid(&SidLabelValue::Index(100), Some(&srgb)),
            Some((16100, 100))
        );
        // Index without an SRGB snapshot can't resolve to a label.
        assert_eq!(resolve_self_sid(&SidLabelValue::Index(100), None), None);
        // Absolute label resolves directly; index derived from SRGB.
        assert_eq!(
            resolve_self_sid(&SidLabelValue::Label(16100), Some(&srgb)),
            Some((16100, 100))
        );
        // Absolute label with no SRGB → index 0 (label still installs).
        assert_eq!(
            resolve_self_sid(&SidLabelValue::Label(16100), None),
            Some((16100, 0))
        );
    }

    fn mk_uni(addr: &str, metric: u32) -> rib::NexthopUni {
        rib::NexthopUni::new(addr.parse().unwrap(), metric, vec![])
    }

    fn spf_route(metric: u32, sid: Option<u32>, nhops: &[(&str, u32)]) -> SpfRoute<V4> {
        let mut nh = BTreeMap::new();
        for (addr, ifindex) in nhops {
            nh.insert(
                addr.parse::<Ipv4Addr>().unwrap(),
                super::SpfNexthop::<V4> {
                    ifindex: *ifindex,
                    adjacency: false,
                    sys_id: None,
                    backup: None,
                },
            );
        }
        SpfRoute::<V4> {
            metric,
            nhops: nh,
            sid,
            prefix_sid: None,
            no_php: false,
            dest_vertex: None,
            backup_as_primary: false,
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
        let mut next: BTreeMap<u8, PrefixMap<Ipv4Net, SpfRoute<V4>>> = BTreeMap::new();
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
        let mut prev: BTreeMap<u8, PrefixMap<Ipv4Net, SpfRoute<V4>>> = BTreeMap::new();
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
        let mut prev: BTreeMap<u8, PrefixMap<Ipv4Net, SpfRoute<V4>>> = BTreeMap::new();
        let mut p = PrefixMap::new();
        p.insert(
            pfx("10.0.0.1/32"),
            spf_route(20, Some(17128), &[("10.0.0.5", 9)]),
        );
        prev.insert(128, p);

        let mut next: BTreeMap<u8, PrefixMap<Ipv4Net, SpfRoute<V4>>> = BTreeMap::new();
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
        let mut prev: BTreeMap<u8, PrefixMap<Ipv4Net, SpfRoute<V4>>> = BTreeMap::new();
        let mut p = PrefixMap::new();
        p.insert(
            pfx("10.0.0.1/32"),
            spf_route(20, Some(17128), &[("10.0.0.5", 9)]),
        );
        prev.insert(128, p);

        let mut next: BTreeMap<u8, PrefixMap<Ipv4Net, SpfRoute<V4>>> = BTreeMap::new();
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
    fn build_rib_nexthop_mixed_metric_yields_protect() {
        // Mixed metrics signal primary + backup — Nexthop::Protect
        // with the lower-metric group as the primary member.
        // Singleton-per-metric groups become Uni members.
        let primary = mk_uni("10.0.0.1", 20);
        let backup = mk_uni("10.0.0.5", 21);
        // Insert backup first to exercise the metric grouping.
        let nh = build_rib_nexthop(vec![backup.clone(), primary.clone()]);
        let rib::Nexthop::Protect(pro) = nh else {
            panic!("expected Protect, got {nh:?}");
        };
        assert_eq!(pro.primary, rib::NexthopMember::Uni(primary));
        assert_eq!(pro.backup, rib::NexthopMember::Uni(backup));
    }

    #[test]
    fn build_rib_nexthop_ecmp_primary_plus_ecmp_backup_yields_protect_of_multi() {
        // Two ECMP primaries at metric 20 + two backups at metric 21
        // collapse into a Protect of two Multi members: one per metric
        // group, ECMP-aware. This is the shape TI-LFA emits when
        // both the primary and the post-convergence path are
        // multi-pathed.
        let p1 = mk_uni("10.0.0.1", 20);
        let p2 = mk_uni("10.0.0.2", 20);
        let b1 = mk_uni("10.0.0.5", 21);
        let b2 = mk_uni("10.0.0.6", 21);
        // Insert mixed order to exercise BTreeMap grouping + sort.
        let nh = build_rib_nexthop(vec![b1.clone(), p1.clone(), b2.clone(), p2.clone()]);
        let rib::Nexthop::Protect(pro) = nh else {
            panic!("expected Protect, got {nh:?}");
        };

        let rib::NexthopMember::Multi(primary_grp) = &pro.primary else {
            panic!("expected Multi primary, got {:?}", pro.primary);
        };
        assert_eq!(primary_grp.metric, 20);
        assert_eq!(primary_grp.nexthops.len(), 2);

        let rib::NexthopMember::Multi(backup_grp) = &pro.backup else {
            panic!("expected Multi backup, got {:?}", pro.backup);
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
            SpfNexthop::<V4> {
                ifindex: 10,
                adjacency: true,
                sys_id: None,
                backup: None,
            },
        );
        let route = SpfRoute::<V4> {
            metric: 20,
            nhops,
            sid: None,
            prefix_sid: None,
            no_php: false,
            dest_vertex: None,
            backup_as_primary: false,
        };
        let entry = make_rib_entry(&route, Level::L2);
        assert!(matches!(entry.nexthop, rib::Nexthop::Uni(_)));
    }

    // Collect the prefixes `diff_apply` withdraws (Ipv4Del) and installs
    // (Ipv4Add) when fed `curr`→`next`, so the empty-nexthop tests can
    // assert on the exact messages without a live RIB task.
    fn run_diff_apply(
        curr: &PrefixMap<Ipv4Net, SpfRoute<V4>>,
        next: &PrefixMap<Ipv4Net, SpfRoute<V4>>,
    ) -> (Vec<Ipv4Net>, Vec<Ipv4Net>) {
        use crate::rib::client::{ProtoId, RibClient};

        let diff = spf::table_diff(curr.iter(), next.iter());
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let client = RibClient::new(tx, ProtoId::from_raw(1));
        diff_apply::<V4>(&client, &diff, Level::L1);
        drop(client); // close the channel so the drain terminates

        let (mut dels, mut adds) = (vec![], vec![]);
        while let Ok(env) = rx.try_recv() {
            match env.msg {
                crate::rib::Message::Ipv4Del { prefix, .. } => dels.push(prefix),
                crate::rib::Message::Ipv4Add { prefix, .. } => adds.push(prefix),
                _ => panic!("unexpected message variant"),
            }
        }
        (dels, adds)
    }

    #[test]
    fn diff_apply_withdraws_empty_nexthop_route() {
        // A cached route whose nexthops were cleared still has to be
        // withdrawn when the prefix leaves the table. Guarding the delete
        // on `!nhops.is_empty()` once leaked the kernel FIB route here.
        let prefix: Ipv4Net = "10.0.0.2/32".parse().unwrap();
        let mut curr = PrefixMap::new();
        curr.insert(prefix, spf_route(10, None, &[])); // empty nexthops
        let next = PrefixMap::new();

        let (dels, adds) = run_diff_apply(&curr, &next);
        assert_eq!(
            dels,
            vec![prefix],
            "withdrawal must fire for empty-nhop route"
        );
        assert!(adds.is_empty());
    }

    #[test]
    fn diff_apply_collapses_emptied_route_to_del() {
        // A route that changes to a no-nexthop state (in both tables, so
        // it lands in `different`) must collapse to a withdrawal, not be
        // skipped — otherwise the prior install lingers in the FIB.
        let prefix: Ipv4Net = "10.0.0.2/32".parse().unwrap();
        let mut curr = PrefixMap::new();
        curr.insert(prefix, spf_route(10, None, &[("10.0.1.2", 2)])); // had a nexthop
        let mut next = PrefixMap::new();
        next.insert(prefix, spf_route(20, None, &[])); // now empty -> "different"

        let (dels, adds) = run_diff_apply(&curr, &next);
        assert_eq!(
            dels,
            vec![prefix],
            "emptied route must collapse to a delete"
        );
        assert!(adds.is_empty(), "must not re-add a nexthop-less route");
    }

    #[test]
    fn make_rib_entry_with_mpls_backup_yields_protect_at_metric_plus_one() {
        // SpfNexthop with backup -> Protect(primary at 20, backup at
        // 21). Verifies BACKUP_METRIC_OFFSET + the flat_map plumbing
        // in make_rib_entry feed build_rib_nexthop a mixed-metric Vec
        // that collapses to a Protect.
        let primary_addr: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let backup_addr: Ipv4Addr = "10.0.0.5".parse().unwrap();
        let mut nhops = BTreeMap::new();
        nhops.insert(
            primary_addr,
            SpfNexthop::<V4> {
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
        let route = SpfRoute::<V4> {
            metric: 20,
            nhops,
            sid: None,
            prefix_sid: None,
            no_php: false,
            dest_vertex: None,
            backup_as_primary: false,
        };
        let entry = make_rib_entry(&route, Level::L2);

        let rib::Nexthop::Protect(pro) = &entry.nexthop else {
            panic!("expected Protect, got {:?}", entry.nexthop);
        };

        let rib::NexthopMember::Uni(p) = &pro.primary else {
            panic!("expected Uni primary, got {:?}", pro.primary);
        };
        assert_eq!(p.metric, 20);
        assert_eq!(p.addr, std::net::IpAddr::V4(primary_addr));

        let rib::NexthopMember::Uni(b) = &pro.backup else {
            panic!("expected Uni backup, got {:?}", pro.backup);
        };
        assert_eq!(b.metric, 21);
        assert_eq!(b.addr, std::net::IpAddr::V4(backup_addr));
        assert_eq!(b.mpls.len(), 2);
        assert_eq!(b.ifindex_origin, Some(20));
    }

    #[test]
    fn make_rib_entry_with_backup_as_primary_inverts_metric_order() {
        // backup-as-primary=true swaps the metric offset: the repair
        // installs at route.metric (sorted first) and the SPF primary
        // installs at route.metric + BACKUP_METRIC_OFFSET.
        let primary_addr: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let backup_addr: Ipv4Addr = "10.0.0.5".parse().unwrap();
        let mut nhops = BTreeMap::new();
        nhops.insert(
            primary_addr,
            SpfNexthop::<V4> {
                ifindex: 10,
                adjacency: true,
                sys_id: None,
                backup: Some(RepairPathMpls {
                    ifindex: 20,
                    addr: backup_addr,
                    labels: vec![rib::Label::Implicit(16002)],
                }),
            },
        );
        let route = SpfRoute::<V4> {
            metric: 20,
            nhops,
            sid: None,
            prefix_sid: None,
            no_php: false,
            dest_vertex: None,
            backup_as_primary: true,
        };
        let entry = make_rib_entry(&route, Level::L2);

        let rib::Nexthop::Protect(pro) = &entry.nexthop else {
            panic!("expected Protect, got {:?}", entry.nexthop);
        };

        // The repair takes the primary slot (now at the lower metric).
        let rib::NexthopMember::Uni(b) = &pro.primary else {
            panic!("expected Uni repair, got {:?}", pro.primary);
        };
        assert_eq!(b.metric, 20);
        assert_eq!(b.addr, std::net::IpAddr::V4(backup_addr));

        // The SPF primary takes the backup slot (at metric+offset).
        let rib::NexthopMember::Uni(p) = &pro.backup else {
            panic!("expected Uni SPF-primary, got {:?}", pro.backup);
        };
        assert_eq!(p.metric, 21);
        assert_eq!(p.addr, std::net::IpAddr::V4(primary_addr));
    }

    /// Regression for the `fast-reroute backup-as-primary` toggle:
    /// two routes whose SPF output is otherwise byte-identical but
    /// whose stamped `backup_as_primary` differs must compare
    /// unequal, so `spf::table_diff` lands the prefix in the
    /// `different` bucket and the new metric ordering reaches the
    /// RIB. Before the flag was carried on `SpfRoute`, the diff saw
    /// them as identical and pushed no update.
    #[test]
    fn backup_as_primary_toggle_is_detected_by_table_diff() {
        use std::collections::BTreeMap;

        let prefix: Ipv4Net = "10.0.0.0/24".parse().unwrap();

        let mut prev: BTreeMap<Ipv4Net, SpfRoute<V4>> = BTreeMap::new();
        let mut next: BTreeMap<Ipv4Net, SpfRoute<V4>> = BTreeMap::new();

        let off = spf_route(20, None, &[("10.0.0.1", 10)]);
        let mut on = spf_route(20, None, &[("10.0.0.1", 10)]);
        on.backup_as_primary = true;

        // Sanity: the only difference is the flag.
        assert_eq!(off.metric, on.metric);
        assert_ne!(off, on, "flag flip must make SpfRoutes compare unequal");

        prev.insert(prefix, off);
        next.insert(prefix, on);

        let diff = crate::spf::table_diff(
            prev.iter().map(|(&k, v)| (k, v)),
            next.iter().map(|(&k, v)| (k, v)),
        );
        assert_eq!(diff.different.len(), 1, "toggle must be a `different`");
        assert!(diff.identical.is_empty(), "toggle must not be `identical`");
        assert!(diff.only_curr.is_empty());
        assert!(diff.only_next.is_empty());
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
            SpfNexthop::<V6> {
                ifindex: 10,
                adjacency: true,
                sys_id: None,
                backup: Some(RepairPathSrv6 {
                    ifindex: 20,
                    addr: backup_addr,
                    segs: vec![end_sid, endx_sid],
                    encap: EncapType::HInsert,
                }),
            },
        );
        let route = SpfRoute::<V6> {
            metric: 20,
            nhops,
            sid: None,
            prefix_sid: None,
            no_php: false,
            dest_vertex: None,
            backup_as_primary: false,
        };
        let entry = make_rib_entry::<V6>(&route, Level::L1);

        let rib::Nexthop::Protect(pro) = &entry.nexthop else {
            panic!("expected Protect, got {:?}", entry.nexthop);
        };
        let rib::NexthopMember::Uni(b) = &pro.backup else {
            panic!("expected Uni backup, got {:?}", pro.backup);
        };
        assert_eq!(b.metric, 21);
        assert_eq!(b.segs, vec![end_sid, endx_sid]);
        assert_eq!(b.encap_type, Some(EncapType::HInsert));
        assert!(b.mpls.is_empty());
    }

    #[test]
    fn apply_mirror_sid_backups_hencaps_to_protector() {
        use crate::isis::egress_protection::ReceivedMirrorSid;
        use isis_packet::IsisSysId;

        fn v6route(nh_addr: Ipv6Addr, ifindex: u32) -> SpfRoute<V6> {
            let mut nhops = BTreeMap::new();
            nhops.insert(
                nh_addr,
                SpfNexthop::<V6> {
                    ifindex,
                    adjacency: true,
                    sys_id: None,
                    backup: None,
                },
            );
            SpfRoute::<V6> {
                metric: 10,
                nhops,
                sid: None,
                prefix_sid: None,
                no_php: false,
                dest_vertex: None,
                backup_as_primary: false,
            }
        }

        let protected: Ipv6Net = "2001:db8:a3:1::/64".parse().unwrap();
        let protector_loc: Ipv6Net = "2001:db8:a4:1::/64".parse().unwrap();
        let mirror_sid: Ipv6Addr = "2001:db8:a4:1::3".parse().unwrap();
        let toward_pea: Ipv6Addr = "fe80::3".parse().unwrap();
        let toward_peb: Ipv6Addr = "fe80::4".parse().unwrap();

        let mut rib: PrefixMap<Ipv6Net, SpfRoute<V6>> = PrefixMap::new();
        rib.insert(protected, v6route(toward_pea, 3));
        rib.insert(protector_loc, v6route(toward_peb, 4));

        let received = vec![ReceivedMirrorSid {
            protector: IsisSysId {
                id: [0, 0, 0, 0, 0, 4],
            },
            mirror_sid,
            protected_locator: protected,
        }];
        apply_mirror_sid_backups(&mut rib, &received);

        // The protected egress's route gains an H.Encaps-to-Mirror-SID
        // backup whose first hop points toward the protector (PEB).
        let b = rib.get(&protected).unwrap().nhops[&toward_pea]
            .backup
            .clone()
            .unwrap();
        assert_eq!(b.segs, vec![mirror_sid]);
        assert_eq!(b.encap, EncapType::HEncap);
        assert_eq!(b.addr, toward_peb);
        assert_eq!(b.ifindex, 4);

        // The protector's own locator route stays unprotected.
        assert!(
            rib.get(&protector_loc).unwrap().nhops[&toward_peb]
                .backup
                .is_none()
        );
    }

    #[test]
    fn make_rib_entry_stamps_isis_level_subtype() {
        // The level a route was computed at is mirrored into the RIB
        // subtype so `show ip route` can tag the entry L1 / L2.
        assert_eq!(level_subtype(Level::L1), RibSubType::IsisLevel1);
        assert_eq!(level_subtype(Level::L2), RibSubType::IsisLevel2);

        let route = spf_route(20, None, &[("10.0.0.1", 10)]);
        assert_eq!(
            make_rib_entry(&route, Level::L1).rsubtype,
            RibSubType::IsisLevel1
        );
        assert_eq!(
            make_rib_entry(&route, Level::L2).rsubtype,
            RibSubType::IsisLevel2
        );
    }

    #[test]
    fn make_rib_entry_v6_stamps_isis_level_subtype() {
        let mut nhops = BTreeMap::new();
        nhops.insert(
            "fe80::a:2".parse().unwrap(),
            SpfNexthop::<V6> {
                ifindex: 10,
                adjacency: true,
                sys_id: None,
                backup: None,
            },
        );
        let route = SpfRoute::<V6> {
            metric: 20,
            nhops,
            sid: None,
            prefix_sid: None,
            no_php: false,
            dest_vertex: None,
            backup_as_primary: false,
        };
        assert_eq!(
            make_rib_entry::<V6>(&route, Level::L1).rsubtype,
            RibSubType::IsisLevel1
        );
        assert_eq!(
            make_rib_entry::<V6>(&route, Level::L2).rsubtype,
            RibSubType::IsisLevel2
        );
    }

    fn ilm_uni_labels(label: u32, adjacency: bool, no_php: bool) -> Vec<u32> {
        let mut nhops = BTreeMap::new();
        nhops.insert(
            "10.0.0.1".parse::<Ipv4Addr>().unwrap(),
            SpfNexthop::<V4> {
                ifindex: 10,
                adjacency,
                sys_id: None,
                backup: None,
            },
        );
        let ilm = SpfIlm {
            nhops,
            ilm_type: IlmType::Node(7),
            no_php,
        };
        let entry = make_ilm_entry(label, &ilm);
        let rib::Nexthop::Uni(uni) = &entry.nexthop else {
            panic!("expected Uni, got {:?}", entry.nexthop);
        };
        uni.mpls_label.clone()
    }

    #[test]
    fn make_ilm_entry_no_php_keeps_label_on_adjacency() {
        // Penultimate hop (adjacency=true) pops by default: no out-label.
        assert!(ilm_uni_labels(16800, true, false).is_empty());
        // ...but a no-PHP Prefix-SID keeps the label (swap label->label).
        assert_eq!(ilm_uni_labels(16800, true, true), vec![16800]);
        // Transit hop (adjacency=false) always swaps, no-PHP or not.
        assert_eq!(ilm_uni_labels(16800, false, false), vec![16800]);
        assert_eq!(ilm_uni_labels(16800, false, true), vec![16800]);
    }
}
