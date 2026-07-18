//! Group-membership engine: the address-family-neutral core shared by
//! IGMP (IPv4) and MLD (IPv6). Querier election, per-interface group
//! and source tables, INCLUDE/EXCLUDE modes and the deadline-driven
//! expiry are all identical between the two protocols (RFC 3376 / RFC
//! 3810); only the wire format and transport differ, and those live
//! behind [`GmCodec`].
//!
//! The engine is decoupled from [`Pim`](super::inst::Pim): it holds
//! its own per-interface state, is driven by normalized [`GmInput`]
//! events (the codec parses the wire into these), and reports back
//! [`GmEvent`]s that the actor bridges into the TIB. `Pim<A>` owns an
//! `Option<Gm<A>>` — a family with no membership protocol yet (an IPv6
//! instance before Phase 4) simply carries `None`.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use super::af::PimAf;
use super::tib::SgKey;

pub mod igmp;

pub use pim_packet::IgmpRecordType as GmRecordType;

/// Robustness Variable (RFC 3376 §8.1 / RFC 3810 §9.1).
pub const GM_ROBUSTNESS: u32 = 2;

/// Last Member Query Time: LMQC (= robustness) × LMQI (1 s).
const LAST_MEMBER_QUERY_TIME: Duration = Duration::from_secs(2);

/// Per-interface membership configuration, carried inside
/// [`super::link::LinkConfig`]. Named `IgmpConfig` still because the
/// YANG/CLI surface is IGMP-flavoured; the MLD knobs share it.
#[derive(Debug, Clone, Default)]
pub struct IgmpConfig {
    pub enabled: Option<bool>,
    pub version: Option<u8>,
    pub query_interval: Option<u16>,
    pub query_max_resp: Option<u16>,
}

impl IgmpConfig {
    pub fn enabled(&self) -> bool {
        self.enabled.unwrap_or(false)
    }

    pub fn version(&self) -> u8 {
        self.version.unwrap_or(3)
    }

    /// Query Interval, seconds (RFC 3376 §8.2).
    pub fn query_interval(&self) -> u16 {
        self.query_interval.unwrap_or(125)
    }

    /// Query Response Interval, seconds (RFC 3376 §8.3).
    pub fn query_max_resp(&self) -> u16 {
        self.query_max_resp.unwrap_or(10)
    }

    /// Group Membership Interval: RV × QI + QRI (RFC 3376 §8.4).
    pub fn gmi(&self) -> Duration {
        Duration::from_secs(
            GM_ROBUSTNESS as u64 * self.query_interval() as u64 + self.query_max_resp() as u64,
        )
    }

    /// Other Querier Present Interval: RV × QI + QRI/2 (RFC 3376 §8.5).
    pub fn oqpi(&self) -> Duration {
        Duration::from_secs(
            GM_ROBUSTNESS as u64 * self.query_interval() as u64 + self.query_max_resp() as u64 / 2,
        )
    }

    /// Startup Query Interval: QI/4 (RFC 3376 §8.6).
    pub fn startup_interval(&self) -> Duration {
        Duration::from_secs((self.query_interval() as u64 / 4).max(1))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterMode {
    Include,
    Exclude,
}

/// One group's membership state on one interface.
pub struct GmGroup<A: PimAf> {
    pub filter_mode: FilterMode,
    /// Group timer — EXCLUDE mode only (RFC 3376 §6.5).
    pub expires: Option<Instant>,
    /// INCLUDE sources with their source timers.
    pub sources: BTreeMap<A::Addr, Instant>,
    /// Older-version-host-present: a v1/v2 report was heard; while
    /// running, v3 source semantics are suspended for the group.
    pub v2_host_until: Option<Instant>,
    pub last_reporter: Option<A::Addr>,
    pub uptime: Instant,
    /// Sources currently reflected into the TIB as local (S,G)
    /// membership — the diff base for [`Gm::sync`].
    synced: BTreeSet<A::Addr>,
    /// Any-source (EXCLUDE) membership currently reflected into the
    /// TIB as local (*,G) state.
    asm_synced: bool,
}

impl<A: PimAf> GmGroup<A> {
    fn new(now: Instant, filter_mode: FilterMode) -> Self {
        Self {
            filter_mode,
            expires: None,
            sources: BTreeMap::new(),
            v2_host_until: None,
            last_reporter: None,
            uptime: now,
            synced: BTreeSet::new(),
            asm_synced: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuerierState<A: PimAf> {
    Querier,
    NonQuerier { querier: A::Addr, until: Instant },
}

/// Per-interface membership state, present while the protocol is
/// enabled and the interface is usable.
pub struct GmIf<A: PimAf> {
    pub querier: QuerierState<A>,
    /// Startup general queries left to send at the startup interval.
    startup_remaining: u8,
    /// Next general-query transmission (meaningful as Querier only).
    next_query: Instant,
    pub groups: BTreeMap<A::Addr, GmGroup<A>>,
}

impl<A: PimAf> GmIf<A> {
    fn new(now: Instant) -> Self {
        Self {
            querier: QuerierState::Querier,
            startup_remaining: GM_ROBUSTNESS as u8,
            next_query: now,
            groups: BTreeMap::new(),
        }
    }
}

/// One normalized group record (v3 report record / MLDv2 record). The
/// codec converts wire addresses into `A::Addr` (rejecting the other
/// family) before handing records to the engine.
#[derive(Debug)]
pub struct GmRecord<A: PimAf> {
    pub rec_type: GmRecordType,
    pub group: A::Addr,
    pub sources: Vec<A::Addr>,
}

/// A membership message normalized by the codec. `src` is the packet's
/// IP source, carried alongside on the [`Message`](super::inst::Message).
#[derive(Debug)]
pub enum GmInput<A: PimAf> {
    /// A general or group-specific query was heard (querier election).
    Query,
    /// A v1/v2 report (MLDv1 report): EXCLUDE {} for the group.
    V2Report(A::Addr),
    /// A v2 leave (MLDv1 done) for the group.
    V2Leave(A::Addr),
    /// A v3 (MLDv2) report's records.
    V3Report(Vec<GmRecord<A>>),
}

/// What the engine asks the actor to do after processing input/time:
/// reflect (or withdraw) local membership on `ifindex` into the TIB.
pub enum GmEvent<A: PimAf> {
    Join { ifindex: u32, key: SgKey<A> },
    Prune { ifindex: u32, key: SgKey<A> },
}

/// Per-interface context the engine needs from the actor: the
/// configuration, DR status (only the DR reflects membership into the
/// TIB, RFC 7761 §4.3.2) and our primary address (querier tiebreak).
pub struct GmIfCtx<A: PimAf> {
    pub name: String,
    pub config: IgmpConfig,
    pub is_dr: bool,
    pub my_addr: Option<A::Addr>,
}

/// The transport + wire seam. One implementor per address family
/// (`IgmpCodec` for IPv4; an MLD codec in Phase 4). It owns the raw
/// socket and the read/write tasks; its read task parses the wire into
/// [`GmInput`] and feeds the actor, and [`send_query`](GmCodec::send_query)
/// builds and queues the family's query PDU.
pub trait GmCodec<A: PimAf>: Send + Sync + 'static {
    fn send_query(&self, cfg: &IgmpConfig, ifindex: u32, group: Option<A::Addr>);
    fn join_if(&self, ifindex: u32);
    fn leave_if(&self, ifindex: u32);
}

/// The membership engine: per-interface state plus the codec that
/// carries it on the wire.
pub struct Gm<A: PimAf> {
    ifs: BTreeMap<u32, GmIf<A>>,
    codec: Box<dyn GmCodec<A>>,
}

impl<A: PimAf> Gm<A> {
    pub fn new(codec: Box<dyn GmCodec<A>>) -> Self {
        Self {
            ifs: BTreeMap::new(),
            codec,
        }
    }

    /// Whether membership is running on `ifindex`.
    pub fn has_if(&self, ifindex: u32) -> bool {
        self.ifs.contains_key(&ifindex)
    }

    /// The interfaces membership is currently running on.
    pub fn ifindexes(&self) -> Vec<u32> {
        self.ifs.keys().copied().collect()
    }

    /// Read-only view of an interface's state (for show output).
    pub fn get_if(&self, ifindex: u32) -> Option<&GmIf<A>> {
        self.ifs.get(&ifindex)
    }

    /// Enable membership on an interface: create state and join the
    /// fixed report-destination groups. The startup general query goes
    /// out on the next tick (`next_query == now`).
    pub fn enable_if(&mut self, ifindex: u32, now: Instant) {
        self.codec.join_if(ifindex);
        self.ifs.insert(ifindex, GmIf::new(now));
    }

    /// Disable membership on an interface: leave the groups, drop the
    /// state, and emit prunes for everything it had synced.
    pub fn disable_if(&mut self, ifindex: u32) -> Vec<GmEvent<A>> {
        self.codec.leave_if(ifindex);
        let mut events = Vec::new();
        if let Some(gmif) = self.ifs.remove(&ifindex) {
            for (grp, group) in gmif.groups {
                for src in group.synced {
                    events.push(GmEvent::Prune {
                        ifindex,
                        key: SgKey::Sg { src, grp },
                    });
                }
                if group.asm_synced {
                    events.push(GmEvent::Prune {
                        ifindex,
                        key: SgKey::StarG { grp },
                    });
                }
            }
        }
        events
    }

    /// Re-run the TIB sync for every group on an interface. Called after
    /// a DR transition — only the DR reflects membership into the TIB, so
    /// gaining/losing DR withdraws or re-adds everything through the diff.
    pub fn resync_if(&mut self, ifindex: u32, ctx: &GmIfCtx<A>) -> Vec<GmEvent<A>> {
        let groups: Vec<A::Addr> = match self.ifs.get(&ifindex) {
            Some(gmif) => gmif.groups.keys().copied().collect(),
            None => return Vec::new(),
        };
        let mut events = Vec::new();
        for grp in groups {
            events.extend(self.sync(ifindex, grp, ctx));
        }
        events
    }

    /// Earliest deadline across all interfaces — the event loop's sleep
    /// target. `None` parks the arm forever.
    pub fn next_wakeup(&self) -> Option<Instant> {
        let mut earliest: Option<Instant> = None;
        let mut consider = |t: Instant| {
            earliest = Some(earliest.map_or(t, |e| e.min(t)));
        };
        for gmif in self.ifs.values() {
            match gmif.querier {
                QuerierState::Querier => consider(gmif.next_query),
                QuerierState::NonQuerier { until, .. } => consider(until),
            }
            for group in gmif.groups.values() {
                if let Some(t) = group.expires {
                    consider(t);
                }
                if let Some(t) = group.v2_host_until {
                    consider(t);
                }
                for t in group.sources.values() {
                    consider(*t);
                }
            }
        }
        earliest
    }

    /// Process every deadline due at or before `now`, across the
    /// interfaces present in `ctx`. Must leave no due deadline behind
    /// or the sleep arm busy-loops.
    pub fn tick(&mut self, now: Instant, ctx: &BTreeMap<u32, GmIfCtx<A>>) -> Vec<GmEvent<A>> {
        let mut events = Vec::new();
        let ifindexes: Vec<u32> = self.ifs.keys().copied().collect();
        for ifindex in ifindexes {
            let Some(ifctx) = ctx.get(&ifindex) else {
                continue;
            };
            let cfg = &ifctx.config;
            let Some(gmif) = self.ifs.get_mut(&ifindex) else {
                continue;
            };

            if let QuerierState::NonQuerier { until, .. } = gmif.querier
                && until <= now
            {
                tracing::info!("gm: {} other querier expired, taking over", ifctx.name);
                gmif.querier = QuerierState::Querier;
                gmif.next_query = now;
            }

            if gmif.querier == QuerierState::Querier && gmif.next_query <= now {
                self.codec.send_query(cfg, ifindex, None);
                let interval = if gmif.startup_remaining > 0 {
                    gmif.startup_remaining -= 1;
                    cfg.startup_interval()
                } else {
                    Duration::from_secs(cfg.query_interval() as u64)
                };
                gmif.next_query = now + interval;
            }

            let mut expired: Vec<A::Addr> = vec![];
            let mut sync: Vec<A::Addr> = vec![];
            for (group_addr, group) in gmif.groups.iter_mut() {
                if let Some(t) = group.v2_host_until
                    && t <= now
                {
                    group.v2_host_until = None;
                }
                let sources_before = group.sources.len();
                group.sources.retain(|_, exp| *exp > now);
                let mut changed = group.sources.len() != sources_before;
                if group.filter_mode == FilterMode::Exclude
                    && let Some(exp) = group.expires
                    && exp <= now
                {
                    if group.sources.is_empty() {
                        expired.push(*group_addr);
                        continue;
                    }
                    // RFC 3376 §6.5: EXCLUDE timer expiry with live
                    // sources reverts the group to INCLUDE.
                    group.filter_mode = FilterMode::Include;
                    group.expires = None;
                    changed = true;
                }
                if group.filter_mode == FilterMode::Include && group.sources.is_empty() {
                    expired.push(*group_addr);
                    continue;
                }
                if changed {
                    sync.push(*group_addr);
                }
            }
            for group_addr in expired {
                if let Some(group) = gmif.groups.remove(&group_addr) {
                    for src in group.synced {
                        events.push(GmEvent::Prune {
                            ifindex,
                            key: SgKey::Sg {
                                src,
                                grp: group_addr,
                            },
                        });
                    }
                    if group.asm_synced {
                        events.push(GmEvent::Prune {
                            ifindex,
                            key: SgKey::StarG { grp: group_addr },
                        });
                    }
                }
                tracing::info!("gm: group {} expired on {}", group_addr, ifctx.name);
            }
            for group_addr in sync {
                events.extend(self.sync(ifindex, group_addr, ifctx));
            }
        }
        events
    }

    /// Process one normalized membership message on an interface.
    pub fn recv(
        &mut self,
        ifindex: u32,
        src: A::Addr,
        input: GmInput<A>,
        ctx: &GmIfCtx<A>,
    ) -> Vec<GmEvent<A>> {
        if !self.ifs.contains_key(&ifindex) {
            return Vec::new();
        }
        let now = Instant::now();
        match input {
            GmInput::Query => {
                self.other_querier(ifindex, src, ctx, now);
                Vec::new()
            }
            GmInput::V2Report(grp) => {
                self.v2_report(ifindex, src, grp, ctx, now);
                // A v2 report flips the group to EXCLUDE — any
                // previously synced INCLUDE sources leave the TIB.
                self.sync(ifindex, grp, ctx)
            }
            GmInput::V2Leave(grp) => {
                self.leave(ifindex, grp, ctx, now);
                Vec::new()
            }
            GmInput::V3Report(records) => {
                let mut events = Vec::new();
                for record in records {
                    let grp = record.group;
                    self.apply_record(ifindex, src, &record, ctx, now);
                    events.extend(self.sync(ifindex, grp, ctx));
                }
                events
            }
        }
    }

    /// Reflect a group's membership into the TIB, diffing against what
    /// was previously synced. INCLUDE source sets become local (S,G)
    /// state; EXCLUDE (any-source) membership becomes local (*,G) state
    /// (SSM-range groups never get (*,G)). Only the elected DR reflects
    /// membership; a non-DR keeps full state but presents an empty view,
    /// so a DR transition withdraws/re-adds everything through the diff.
    fn sync(&mut self, ifindex: u32, grp: A::Addr, ctx: &GmIfCtx<A>) -> Vec<GmEvent<A>> {
        let Some(gmif) = self.ifs.get_mut(&ifindex) else {
            return Vec::new();
        };
        let Some(group) = gmif.groups.get_mut(&grp) else {
            return Vec::new();
        };
        let current: BTreeSet<A::Addr> = if ctx.is_dr && group.filter_mode == FilterMode::Include {
            group.sources.keys().copied().collect()
        } else {
            BTreeSet::new()
        };
        let added: Vec<A::Addr> = current.difference(&group.synced).copied().collect();
        let removed: Vec<A::Addr> = group.synced.difference(&current).copied().collect();
        group.synced = current;
        let asm_desired = ctx.is_dr && group.filter_mode == FilterMode::Exclude && !A::is_ssm(grp);
        let asm_was = group.asm_synced;
        group.asm_synced = asm_desired;

        let mut events = Vec::new();
        for src in added {
            events.push(GmEvent::Join {
                ifindex,
                key: SgKey::Sg { src, grp },
            });
        }
        for src in removed {
            events.push(GmEvent::Prune {
                ifindex,
                key: SgKey::Sg { src, grp },
            });
        }
        match (asm_desired, asm_was) {
            (true, false) => events.push(GmEvent::Join {
                ifindex,
                key: SgKey::StarG { grp },
            }),
            (false, true) => events.push(GmEvent::Prune {
                ifindex,
                key: SgKey::StarG { grp },
            }),
            _ => {}
        }
        events
    }

    /// Querier election (RFC 3376 §6.6.2): a query from a lower address
    /// demotes us / refreshes the other-querier timer.
    fn other_querier(&mut self, ifindex: u32, src: A::Addr, ctx: &GmIfCtx<A>, now: Instant) {
        let Some(my_addr) = ctx.my_addr else {
            return;
        };
        if A::is_unspecified(src) || src >= my_addr {
            return;
        }
        let Some(gmif) = self.ifs.get_mut(&ifindex) else {
            return;
        };
        if gmif.querier == QuerierState::Querier {
            tracing::info!("gm: {} lost querier election to {}", ctx.name, src);
        }
        gmif.querier = QuerierState::NonQuerier {
            querier: src,
            until: now + ctx.config.oqpi(),
        };
    }

    /// v1/v2 membership report (MLDv1 report): EXCLUDE {} semantics plus
    /// the older-version-host-present marker.
    fn v2_report(
        &mut self,
        ifindex: u32,
        src: A::Addr,
        grp: A::Addr,
        ctx: &GmIfCtx<A>,
        now: Instant,
    ) {
        if !A::is_multicast(grp) {
            return;
        }
        let Some(gmif) = self.ifs.get_mut(&ifindex) else {
            return;
        };
        let group = gmif
            .groups
            .entry(grp)
            .or_insert_with(|| GmGroup::new(now, FilterMode::Exclude));
        group.filter_mode = FilterMode::Exclude;
        group.expires = Some(now + ctx.config.gmi());
        group.v2_host_until = Some(now + ctx.config.gmi());
        if !A::is_unspecified(src) {
            group.last_reporter = Some(src);
        }
    }

    /// v2 Leave (MLDv1 done, RFC 2236 §4): as querier, lower the group
    /// timer to LMQT and send a group-specific query.
    fn leave(&mut self, ifindex: u32, grp: A::Addr, ctx: &GmIfCtx<A>, now: Instant) {
        let mut query = false;
        if let Some(gmif) = self.ifs.get_mut(&ifindex) {
            let is_querier = gmif.querier == QuerierState::Querier;
            if let Some(group) = gmif.groups.get_mut(&grp)
                && group.filter_mode == FilterMode::Exclude
            {
                let lmqt = now + LAST_MEMBER_QUERY_TIME;
                group.expires = Some(group.expires.map_or(lmqt, |e| e.min(lmqt)));
                query = is_querier;
            }
        }
        if query {
            self.codec.send_query(&ctx.config, ifindex, Some(grp));
        }
    }

    /// Apply one v3 (MLDv2) group record (RFC 3376 §6.4, reduced to the
    /// state this phase tracks: membership presence and INCLUDE sources;
    /// retransmission schedules simplified to a single group-specific
    /// query).
    fn apply_record(
        &mut self,
        ifindex: u32,
        src: A::Addr,
        record: &GmRecord<A>,
        ctx: &GmIfCtx<A>,
        now: Instant,
    ) {
        let grp = record.group;
        if !A::is_multicast(grp) {
            return;
        }
        let gmi = ctx.config.gmi();
        let lmqt = now + LAST_MEMBER_QUERY_TIME;
        let mut query = false;
        if let Some(gmif) = self.ifs.get_mut(&ifindex) {
            let is_querier = gmif.querier == QuerierState::Querier;
            use GmRecordType::*;
            match record.rec_type {
                ModeIsExclude | ChangeToExclude => {
                    let group = gmif
                        .groups
                        .entry(grp)
                        .or_insert_with(|| GmGroup::new(now, FilterMode::Exclude));
                    group.filter_mode = FilterMode::Exclude;
                    group.expires = Some(now + gmi);
                    if !A::is_unspecified(src) {
                        group.last_reporter = Some(src);
                    }
                }
                ModeIsInclude | AllowNewSources => {
                    if record.sources.is_empty() {
                        return;
                    }
                    let group = gmif
                        .groups
                        .entry(grp)
                        .or_insert_with(|| GmGroup::new(now, FilterMode::Include));
                    for source in &record.sources {
                        group.sources.insert(*source, now + gmi);
                    }
                    if !A::is_unspecified(src) {
                        group.last_reporter = Some(src);
                    }
                }
                ChangeToInclude => {
                    let group = gmif
                        .groups
                        .entry(grp)
                        .or_insert_with(|| GmGroup::new(now, FilterMode::Include));
                    for source in &record.sources {
                        group.sources.insert(*source, now + gmi);
                    }
                    if !A::is_unspecified(src) {
                        group.last_reporter = Some(src);
                    }
                    if record.sources.is_empty() {
                        // TO_IN {} is the v3 leave. In EXCLUDE mode lower
                        // the group timer; in INCLUDE mode age the
                        // remaining sources out at LMQT.
                        match group.filter_mode {
                            FilterMode::Exclude => {
                                group.expires = Some(group.expires.map_or(lmqt, |e| e.min(lmqt)));
                            }
                            FilterMode::Include => {
                                for exp in group.sources.values_mut() {
                                    *exp = (*exp).min(lmqt);
                                }
                            }
                        }
                        query = is_querier;
                    }
                }
                BlockOldSources => {
                    let Some(group) = gmif.groups.get_mut(&grp) else {
                        return;
                    };
                    if group.filter_mode == FilterMode::Include {
                        for source in &record.sources {
                            if let Some(exp) = group.sources.get_mut(source) {
                                *exp = (*exp).min(lmqt);
                            }
                        }
                        query = is_querier;
                    }
                }
                Unknown(t) => {
                    tracing::debug!("gm: unknown v3 record type {} ignored", t);
                }
            }
        }
        if query {
            self.codec.send_query(&ctx.config, ifindex, Some(grp));
        }
    }
}
