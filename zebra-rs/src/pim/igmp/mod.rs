//! IGMP v2/v3 router-side membership tracking (RFC 2236 / RFC 3376):
//! querier election, per-interface group and source tables, query
//! transmission. Expiry is deadline-driven: every timed state stores
//! an `Instant`, [`Pim::igmp_next_wakeup`] feeds the event loop's
//! sleep arm, and [`Pim::igmp_tick`] processes everything due — no
//! per-source timer tasks. Membership feeds the TIB bridge from the
//! SSM phase on.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use pim_packet::{IgmpGroupMessage, IgmpGroupRecord, IgmpPacket, IgmpRecordType, IgmpV3Query};
use tokio::sync::mpsc::UnboundedSender;

use super::inst::{IgmpSend, Pim};
use super::link::LinkConfig;
use super::socket::IGMP_ALL_HOSTS;
use super::tib::SgKey;

/// Robustness Variable (RFC 3376 §8.1). Fixed at the protocol
/// default; a config knob can arrive later.
pub const IGMP_ROBUSTNESS: u32 = 2;

/// Last Member Query Time: LMQC (= robustness) × LMQI (1 s).
const LAST_MEMBER_QUERY_TIME: Duration = Duration::from_secs(2);

/// Per-interface IGMP configuration, carried inside
/// [`super::link::LinkConfig`].
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
            IGMP_ROBUSTNESS as u64 * self.query_interval() as u64 + self.query_max_resp() as u64,
        )
    }

    /// Other Querier Present Interval: RV × QI + QRI/2 (RFC 3376 §8.5).
    pub fn oqpi(&self) -> Duration {
        Duration::from_secs(
            IGMP_ROBUSTNESS as u64 * self.query_interval() as u64
                + self.query_max_resp() as u64 / 2,
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

pub struct IgmpGroup {
    pub filter_mode: FilterMode,
    /// Group timer — EXCLUDE mode only (RFC 3376 §6.5).
    pub expires: Option<Instant>,
    /// INCLUDE sources with their source timers.
    pub sources: BTreeMap<Ipv4Addr, Instant>,
    /// Older-version-host-present: a v1/v2 report was heard; while
    /// running, v3 source semantics are suspended for the group.
    pub v2_host_until: Option<Instant>,
    pub last_reporter: Option<Ipv4Addr>,
    pub uptime: Instant,
    /// Sources currently reflected into the TIB as local (S,G)
    /// membership — the diff base for [`Pim::igmp_tib_sync`].
    pub synced: BTreeSet<Ipv4Addr>,
    /// Any-source (EXCLUDE) membership currently reflected into the
    /// TIB as local (*,G) state.
    pub asm_synced: bool,
}

impl IgmpGroup {
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
pub enum QuerierState {
    Querier,
    NonQuerier { querier: Ipv4Addr, until: Instant },
}

/// Runtime IGMP state for one interface, present while IGMP is
/// enabled and the interface is usable.
pub struct IgmpIf {
    pub querier: QuerierState,
    /// Startup general queries left to send at the startup interval.
    startup_remaining: u8,
    /// Next general-query transmission (meaningful as Querier only).
    next_query: Instant,
    pub groups: BTreeMap<Ipv4Addr, IgmpGroup>,
}

impl IgmpIf {
    pub fn new(now: Instant) -> Self {
        Self {
            querier: QuerierState::Querier,
            startup_remaining: IGMP_ROBUSTNESS as u8,
            next_query: now,
            groups: BTreeMap::new(),
        }
    }
}

/// Build and queue a general (group `None`) or group-specific query.
fn send_query(
    tx: &UnboundedSender<IgmpSend>,
    cfg: &LinkConfig,
    ifindex: u32,
    group: Option<Ipv4Addr>,
) {
    // Max Resp is in units of 1/10 s in both v2 and v3; group-specific
    // queries use the Last Member Query Interval (1 s).
    let max_resp = match group {
        None => (cfg.igmp.query_max_resp() as u32 * 10).min(250) as u8,
        Some(_) => 10,
    };
    let dst = group.unwrap_or(IGMP_ALL_HOSTS);
    let packet = if cfg.igmp.version() == 2 {
        IgmpPacket::QueryV2(IgmpGroupMessage {
            max_resp,
            group: group.unwrap_or(Ipv4Addr::UNSPECIFIED),
        })
    } else {
        IgmpPacket::QueryV3(IgmpV3Query {
            max_resp_code: max_resp,
            group: group.unwrap_or(Ipv4Addr::UNSPECIFIED),
            suppress: false,
            qrv: IGMP_ROBUSTNESS as u8,
            // QQIC values >= 128 use exponential encoding; clamp
            // instead until large intervals are needed.
            qqic: cfg.igmp.query_interval().min(127) as u8,
            sources: vec![],
        })
    };
    let _ = tx.send(IgmpSend {
        packet,
        ifindex,
        dst,
    });
}

impl Pim {
    /// Earliest IGMP deadline across all interfaces — the event
    /// loop's sleep target. `None` parks the arm forever.
    pub(crate) fn igmp_next_wakeup(&self) -> Option<Instant> {
        let mut earliest: Option<Instant> = None;
        let mut consider = |t: Instant| {
            earliest = Some(earliest.map_or(t, |e| e.min(t)));
        };
        for link in self.links.values() {
            let Some(igmp) = link.igmp.as_ref() else {
                continue;
            };
            match igmp.querier {
                QuerierState::Querier => consider(igmp.next_query),
                QuerierState::NonQuerier { until, .. } => consider(until),
            }
            for group in igmp.groups.values() {
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

    /// Process every deadline that is due. Must leave no deadline at
    /// or before `now` behind, or the sleep arm busy-loops.
    pub(crate) fn igmp_tick(&mut self, now: Instant) {
        let targets: Vec<(u32, String)> = self
            .links
            .values()
            .filter(|l| l.igmp.is_some())
            .map(|l| (l.ifindex, l.name.clone()))
            .collect();
        for (ifindex, name) in targets {
            let cfg = self.link_config(&name);
            let Some(link) = self.links.get_mut(&ifindex) else {
                continue;
            };
            let Some(igmp) = link.igmp.as_mut() else {
                continue;
            };

            if let QuerierState::NonQuerier { until, .. } = igmp.querier
                && until <= now
            {
                tracing::info!("igmp: {} other querier expired, taking over", name);
                igmp.querier = QuerierState::Querier;
                igmp.next_query = now;
            }

            if igmp.querier == QuerierState::Querier && igmp.next_query <= now {
                send_query(&self.igmp_send_tx, &cfg, ifindex, None);
                let interval = if igmp.startup_remaining > 0 {
                    igmp.startup_remaining -= 1;
                    cfg.igmp.startup_interval()
                } else {
                    Duration::from_secs(cfg.igmp.query_interval() as u64)
                };
                igmp.next_query = now + interval;
            }

            let mut expired: Vec<Ipv4Addr> = vec![];
            let mut sync: Vec<Ipv4Addr> = vec![];
            for (group_addr, group) in igmp.groups.iter_mut() {
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
            let mut prune: Vec<SgKey> = vec![];
            for group_addr in expired {
                if let Some(group) = igmp.groups.remove(&group_addr) {
                    for src in group.synced {
                        prune.push(SgKey::Sg {
                            src,
                            grp: group_addr,
                        });
                    }
                    if group.asm_synced {
                        prune.push(SgKey::StarG { grp: group_addr });
                    }
                }
                tracing::info!("igmp: group {} expired on {}", group_addr, name);
            }
            for group_addr in sync {
                self.igmp_tib_sync(ifindex, group_addr);
            }
            for key in prune {
                self.tib_local_prune(key, ifindex);
            }
        }
    }

    /// Reflect a group's membership into the TIB, diffing against
    /// what was previously synced: INCLUDE source sets become local
    /// (S,G) state; EXCLUDE (any-source) membership becomes local
    /// (*,G) state (SSM-range groups never get (*,G)).
    ///
    /// Only the elected DR reflects membership into the TIB (RFC 7761
    /// §4.3.2). A non-DR keeps full `IgmpIf` state so failover is
    /// immediate, but presents an empty view here — so a DR→non-DR
    /// transition withdraws everything and non-DR→DR re-adds it, both
    /// through the same diff.
    pub(crate) fn igmp_tib_sync(&mut self, ifindex: u32, grp: Ipv4Addr) {
        let is_dr = self.i_am_dr(ifindex);
        let Some(link) = self.links.get_mut(&ifindex) else {
            return;
        };
        let Some(igmp) = link.igmp.as_mut() else {
            return;
        };
        let Some(group) = igmp.groups.get_mut(&grp) else {
            return;
        };
        let current: BTreeSet<Ipv4Addr> = if is_dr && group.filter_mode == FilterMode::Include {
            group.sources.keys().copied().collect()
        } else {
            BTreeSet::new()
        };
        let added: Vec<Ipv4Addr> = current.difference(&group.synced).copied().collect();
        let removed: Vec<Ipv4Addr> = group.synced.difference(&current).copied().collect();
        group.synced = current;
        let asm_desired =
            is_dr && group.filter_mode == FilterMode::Exclude && !super::rp::is_ssm(grp);
        let asm_was = group.asm_synced;
        group.asm_synced = asm_desired;
        for src in added {
            self.tib_local_join(SgKey::Sg { src, grp }, ifindex);
        }
        for src in removed {
            self.tib_local_prune(SgKey::Sg { src, grp }, ifindex);
        }
        match (asm_desired, asm_was) {
            (true, false) => self.tib_local_join(SgKey::StarG { grp }, ifindex),
            (false, true) => self.tib_local_prune(SgKey::StarG { grp }, ifindex),
            _ => {}
        }
    }

    pub(crate) fn igmp_recv(&mut self, ifindex: u32, src: Ipv4Addr, packet: IgmpPacket) {
        let Some(link) = self.links.get(&ifindex) else {
            return;
        };
        if link.igmp.is_none() || link.is_my_addr(&src) {
            return;
        }
        let name = link.name.clone();
        let cfg = self.link_config(&name);
        let now = Instant::now();
        match packet {
            IgmpPacket::QueryV2(_) | IgmpPacket::QueryV3(_) => {
                self.igmp_other_querier(ifindex, &name, src, &cfg, now);
            }
            IgmpPacket::ReportV1(msg) | IgmpPacket::ReportV2(msg) => {
                self.igmp_v2_report(ifindex, src, msg.group, &cfg, now);
                // A v2 report flips the group to EXCLUDE — any
                // previously synced INCLUDE sources leave the TIB.
                self.igmp_tib_sync(ifindex, msg.group);
            }
            IgmpPacket::LeaveV2(msg) => {
                self.igmp_leave(ifindex, msg.group, &cfg, now);
            }
            IgmpPacket::ReportV3(report) => {
                for record in report.records {
                    self.igmp_apply_record(ifindex, src, &record, &cfg, now);
                    self.igmp_tib_sync(ifindex, record.group);
                }
            }
            IgmpPacket::Unknown { typ, .. } => {
                tracing::debug!("igmp: unknown type {:#04x} from {} ignored", typ, src);
            }
        }
    }

    /// Querier election (RFC 3376 §6.6.2): a query from a lower
    /// address demotes us / refreshes the other-querier timer.
    fn igmp_other_querier(
        &mut self,
        ifindex: u32,
        name: &str,
        src: Ipv4Addr,
        cfg: &LinkConfig,
        now: Instant,
    ) {
        let Some(link) = self.links.get_mut(&ifindex) else {
            return;
        };
        let Some(my_addr) = link.primary_addr() else {
            return;
        };
        if src.is_unspecified() || src >= my_addr {
            return;
        }
        let Some(igmp) = link.igmp.as_mut() else {
            return;
        };
        if igmp.querier == QuerierState::Querier {
            tracing::info!("igmp: {} lost querier election to {}", name, src);
        }
        igmp.querier = QuerierState::NonQuerier {
            querier: src,
            until: now + cfg.igmp.oqpi(),
        };
    }

    /// v1/v2 membership report: EXCLUDE {} semantics plus the
    /// older-version-host-present marker.
    fn igmp_v2_report(
        &mut self,
        ifindex: u32,
        src: Ipv4Addr,
        group_addr: Ipv4Addr,
        cfg: &LinkConfig,
        now: Instant,
    ) {
        if !group_addr.is_multicast() {
            return;
        }
        let Some(igmp) = self.link_igmp_mut(ifindex) else {
            return;
        };
        let group = igmp
            .groups
            .entry(group_addr)
            .or_insert_with(|| IgmpGroup::new(now, FilterMode::Exclude));
        group.filter_mode = FilterMode::Exclude;
        group.expires = Some(now + cfg.igmp.gmi());
        group.v2_host_until = Some(now + cfg.igmp.gmi());
        if !src.is_unspecified() {
            group.last_reporter = Some(src);
        }
    }

    /// v2 Leave (RFC 2236 §4): as querier, lower the group timer to
    /// LMQT and send a group-specific query.
    fn igmp_leave(&mut self, ifindex: u32, group_addr: Ipv4Addr, cfg: &LinkConfig, now: Instant) {
        let mut query = false;
        {
            let Some(igmp) = self.link_igmp_mut(ifindex) else {
                return;
            };
            let is_querier = igmp.querier == QuerierState::Querier;
            let Some(group) = igmp.groups.get_mut(&group_addr) else {
                return;
            };
            if group.filter_mode == FilterMode::Exclude {
                let lmqt = now + LAST_MEMBER_QUERY_TIME;
                group.expires = Some(group.expires.map_or(lmqt, |e| e.min(lmqt)));
                query = is_querier;
            }
        }
        if query {
            send_query(&self.igmp_send_tx, cfg, ifindex, Some(group_addr));
        }
    }

    /// Apply one IGMPv3 group record (RFC 3376 §6.4, reduced to the
    /// state this phase tracks: membership presence and INCLUDE
    /// sources; retransmission schedules are simplified to a single
    /// group-specific query).
    fn igmp_apply_record(
        &mut self,
        ifindex: u32,
        src: Ipv4Addr,
        record: &IgmpGroupRecord,
        cfg: &LinkConfig,
        now: Instant,
    ) {
        if !record.group.is_multicast() {
            return;
        }
        let gmi = cfg.igmp.gmi();
        let lmqt = now + LAST_MEMBER_QUERY_TIME;
        let mut query = false;
        {
            let Some(igmp) = self.link_igmp_mut(ifindex) else {
                return;
            };
            let is_querier = igmp.querier == QuerierState::Querier;
            use IgmpRecordType::*;
            match record.rec_type {
                ModeIsExclude | ChangeToExclude => {
                    let group = igmp
                        .groups
                        .entry(record.group)
                        .or_insert_with(|| IgmpGroup::new(now, FilterMode::Exclude));
                    group.filter_mode = FilterMode::Exclude;
                    group.expires = Some(now + gmi);
                    if !src.is_unspecified() {
                        group.last_reporter = Some(src);
                    }
                }
                ModeIsInclude | AllowNewSources => {
                    if record.sources.is_empty() {
                        return;
                    }
                    let group = igmp
                        .groups
                        .entry(record.group)
                        .or_insert_with(|| IgmpGroup::new(now, FilterMode::Include));
                    for source in &record.sources {
                        group.sources.insert(*source, now + gmi);
                    }
                    if !src.is_unspecified() {
                        group.last_reporter = Some(src);
                    }
                }
                ChangeToInclude => {
                    let group = igmp
                        .groups
                        .entry(record.group)
                        .or_insert_with(|| IgmpGroup::new(now, FilterMode::Include));
                    for source in &record.sources {
                        group.sources.insert(*source, now + gmi);
                    }
                    if !src.is_unspecified() {
                        group.last_reporter = Some(src);
                    }
                    if record.sources.is_empty() {
                        // TO_IN {} is the v3 leave. In EXCLUDE mode
                        // lower the group timer; in INCLUDE mode age
                        // the remaining sources out at LMQT.
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
                    let Some(group) = igmp.groups.get_mut(&record.group) else {
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
                    tracing::debug!("igmp: unknown v3 record type {} ignored", t);
                }
            }
        }
        if query {
            send_query(&self.igmp_send_tx, cfg, ifindex, Some(record.group));
        }
    }

    fn link_igmp_mut(&mut self, ifindex: u32) -> Option<&mut IgmpIf> {
        self.links.get_mut(&ifindex)?.igmp.as_mut()
    }
}
