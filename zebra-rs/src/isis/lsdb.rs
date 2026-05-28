use std::collections::btree_map::{Iter, Values};
use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv6Addr;
use std::time::{Duration, Instant};

use ipnet::Ipv4Net;
use isis_packet::*;

use crate::isis_database_trace;

use crate::context::Timer;
use crate::isis::{
    Message,
    srmpls::{IsisLabelMap, LabelBlock, LabelConfig},
};

use super::config::MtId;
use super::graph::{ReachMap, ReachMapV6};
use super::hostname::Hostname;
use super::inst::MsgSender;
use super::link::LinkTop;
use super::{
    Level, LspFlood,
    inst::IsisTop,
    link::Afi,
    lsp::{lsp_emit, lsp_flood},
    rib::{spf_schedule, spf_schedule_top},
};

#[derive(Default)]
pub struct Lsdb {
    pub map: BTreeMap<IsisLspId, Lsa>,
    pub adj: BTreeMap<u32, LspFlood>,
}

/// ISO 10589 §7.3.16.4 ZeroAgeLifetime. A purged LSP (Remaining
/// Lifetime == 0) must stay in the LSDB for this long before being
/// evicted, so the SRM/SSN machinery has time to flood it to peers
/// and acknowledge it. Arming `hold_timer` for `hold_time == 0`
/// directly would otherwise evict the entry before `srm_advertise`
/// could read its bytes.
const ZERO_AGE_LIFETIME: u16 = 60;

/// Number of seconds the LSDB should hold an entry whose
/// Remaining Lifetime came across the wire as 0. Returns the
/// ZeroAgeLifetime safety window so the LSP survives long enough
/// to reach peers; otherwise returns the value untouched.
fn hold_timer_secs(hold_time: u16) -> u16 {
    if hold_time == 0 {
        ZERO_AGE_LIFETIME
    } else {
        hold_time
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum LsdbEvent {
    RefreshTimerExpire,
    HoldTimerExpire,
}

pub struct Lsa {
    pub lsp: IsisLsp,
    pub originated: bool,
    pub hold_timer: Option<Timer>,
    pub refresh_timer: Option<Timer>,
    pub ifindex: u32,
    pub bytes: Vec<u8>,
    // When this entry was inserted via the receive path. None for
    // self-originated LSPs and as the pre-fill on fresh entries.
    // Used by `insert_lsp` to enforce min-lsp-arrival-time.
    pub last_received: Option<Instant>,
}

impl Lsa {
    pub fn new(lsp: IsisLsp) -> Self {
        Self {
            lsp,
            originated: false,
            hold_timer: None,
            refresh_timer: None,
            ifindex: 0,
            bytes: vec![],
            last_received: None,
        }
    }
}

impl Lsdb {
    pub fn get(&self, key: &IsisLspId) -> Option<&Lsa> {
        self.map.get(key)
    }

    pub fn remove(&mut self, key: &IsisLspId) -> Option<Lsa> {
        self.map.remove(key)
    }

    pub fn values(&self) -> Values<'_, IsisLspId, Lsa> {
        self.map.values()
    }

    pub fn iter(&self) -> Iter<'_, IsisLspId, Lsa> {
        self.map.iter()
    }
}

fn lsdb_timer(tx: &MsgSender, level: Level, key: IsisLspId, tick: u16, ev: LsdbEvent) -> Timer {
    let tx = tx.clone();
    Timer::once(tick.into(), move || {
        let tx = tx.clone();
        let msg = Message::Lsdb(ev, level, key);
        async move {
            let _ = tx.send(msg);
        }
    })
}

fn refresh_timer(tx: &MsgSender, level: Level, key: IsisLspId, refresh_time: u16) -> Timer {
    let ev = LsdbEvent::RefreshTimerExpire;
    lsdb_timer(tx, level, key, refresh_time, ev)
}

fn hold_timer(tx: &MsgSender, level: Level, key: IsisLspId, hold_time: u16) -> Timer {
    let ev = LsdbEvent::HoldTimerExpire;
    lsdb_timer(tx, level, key, hold_time, ev)
}

pub fn lsp_cap_view<'a>(tlv: &'a IsisTlvRouterCap) -> LspCapView<'a> {
    let mut view = LspCapView::default();
    for sub in &tlv.subs {
        match &sub {
            cap::IsisSubTlv::SegmentRoutingCap(cap) => {
                view.cap = Some(cap);
            }
            cap::IsisSubTlv::SegmentRoutingAlgo(algo) => {
                view.algo = Some(algo);
            }
            cap::IsisSubTlv::SegmentRoutingLB(lb) => {
                view.lb = Some(lb);
            }
            cap::IsisSubTlv::NodeMaxSidDepth(sid_depth) => {
                view.sid_depth = Some(sid_depth);
            }
            cap::IsisSubTlv::Srv6(srv6) => {
                view.srv6 = Some(srv6);
            }
            cap::IsisSubTlv::FlexAlgoDef(fad) => {
                view.fads.push(fad);
            }
            cap::IsisSubTlv::Unknown(_) => {
                // Simpply ignore unknown sub tlv.
            }
        }
    }
    view
}

#[derive(Default)]
pub struct LspCapView<'a> {
    pub cap: Option<&'a IsisSubSegmentRoutingCap>,
    pub algo: Option<&'a IsisSubSegmentRoutingAlgo>,
    pub lb: Option<&'a IsisSubSegmentRoutingLB>,
    pub sid_depth: Option<&'a IsisSubNodeMaxSidDepth>,
    pub srv6: Option<&'a IsisSubSrv6>,
    /// Flex-Algorithm Definitions (RFC 9350 §5.1) advertised by this
    /// peer. One entry per FAD sub-TLV; multiple FADs for distinct
    /// algorithms are allowed in a single Router Capability TLV.
    pub fads: Vec<&'a IsisSubFlexAlgoDef>,
}

/// References to every per-sys-id map that depends on TLV content
/// inside a peer's LSP. Bundled here so `rebuild_sys_state` can be
/// called from both the receive path (`LinkTop`) and the hold-expire
/// path (`IsisTop`) without a 7-positional-arg signature.
pub(super) struct SysStateRefs<'a> {
    pub hostname: &'a mut Hostname,
    pub label_map: &'a mut IsisLabelMap,
    pub reach_v4: &'a mut ReachMap,
    pub reach_v6: &'a mut ReachMapV6,
    pub mt_membership: &'a mut BTreeMap<IsisSysId, BTreeSet<MtId>>,
    pub mt2_reach_v6: &'a mut ReachMapV6,
    pub srv6_end_map: &'a mut BTreeMap<IsisSysId, Ipv6Addr>,
    /// Per-peer Flex-Algorithm Definition store. Outer key is peer
    /// sys-id, inner key is the FAD's `flex_algorithm` field
    /// (128..=255). RFC 9350 §5.1 places FADs inside Router
    /// Capability TLV 242, which is a fragment-0-only TLV, so the
    /// rebuild only inspects fragment 0 for FAD content.
    pub peer_fad: &'a mut BTreeMap<IsisSysId, BTreeMap<u8, IsisSubFlexAlgoDef>>,

    /// Per-peer per-link affinity bitmaps. Inner key is the IS-reach
    /// neighbor identifier (6-byte sys-id + 1-byte circuit/pseudo
    /// id). Populated from ASLA sub-TLVs on Ext IS-Reach (TLV 22)
    /// and MT IS-Reach (TLV 222) entries whose SABM has the
    /// Flex-Algorithm X-bit set (RFC 9479 §4.2). Union across
    /// fragments — later fragments' entries overwrite earlier ones
    /// for the same neighbor_id.
    pub peer_link_affinity: &'a mut BTreeMap<IsisSysId, BTreeMap<IsisNeighborId, ExtAdminGroup>>,

    /// Per-peer per-algorithm Prefix-SIDs keyed by (algo, prefix).
    /// Populated from Ext IP-Reach (TLV 135) sub-TLVs with
    /// Algorithm in 128..=255 (RFC 9350 §7). Union across
    /// fragments.
    pub peer_algo_sid: &'a mut BTreeMap<IsisSysId, BTreeMap<(u8, Ipv4Net), SidLabelValue>>,

    /// Per-peer SR algorithm participation sets. Populated from the
    /// SR-Algorithms sub-TLV (RFC 8667 §3.2, sub-TLV 19) inside Router
    /// Capability TLV 242 — fragment-0-only, like the FAD store.
    /// Consumers (per-algo SPF gating, `show isis flex-algo`) read
    /// this instead of re-walking the LSDB; missing entry means the
    /// peer is not a candidate for any non-default algo.
    pub peer_algos: &'a mut BTreeMap<IsisSysId, BTreeSet<u8>>,
}

/// Recompute the per-sys-id consumer maps from the union of every
/// fragment currently in the LSDB for `sys_id` at this level.
///
/// IS-IS lets a router originate up to 256 LSP fragments per node
/// identity (LSP Number = 0..=255 in the LSPID). Fragment 0 is the
/// anchor for scalar/per-node TLVs (hostname, Router Capability,
/// MT capability); fragments 1..=255 may carry additional
/// distributable TLVs (TLV 135 / 236 / MT-IPv6 reach, SRv6 locators).
/// A single-LSP "overwrite the map on each receive" strategy
/// corrupts state the moment a peer fragments — the second fragment
/// lacking hostname or MT capability would clobber what fragment 0
/// installed, and reach maps would lose entries from prior fragments.
/// This rebuild scans every fragment from `sys_id` and applies the
/// per-TLV rule:
///
///   - hostname, SR capability, MT capability → fragment 0 only.
///     Missing fragment 0 (or fragment 0 lacking the TLV) clears
///     the corresponding scalar map entry.
///   - TLV 135 (ExtIpReach), TLV 236 (Ipv6Reach), TLV 237
///     (MtIpv6Reach mt=2) → union across all fragments.
///   - SRv6 End SID → first encountered across all fragments.
///
/// Skipped when `sys_id` is the local origin: self-originated maps
/// are managed by `lsp_generate` with the `originate=true` flag on
/// the hostname entry, and we don't want a peer-state rebuild to
/// trample it.
pub(super) fn rebuild_sys_state(
    lsdb_level: &Lsdb,
    self_sys_id: &IsisSysId,
    sys_id: &IsisSysId,
    s: SysStateRefs<'_>,
) {
    if sys_id == self_sys_id {
        return;
    }

    // Pull non-pseudonode fragments for this sys_id, sorted by
    // fragment number so the "first SRv6 End SID wins" rule has
    // deterministic ordering.
    let mut frags: Vec<&IsisLsp> = lsdb_level
        .iter()
        .filter(|(id, _)| id.sys_id() == *sys_id && !id.is_pseudo())
        .map(|(_, lsa)| &lsa.lsp)
        .collect();
    frags.sort_by_key(|l| l.lsp_id.fragment_id());

    if frags.is_empty() {
        s.hostname.remove(sys_id);
        s.label_map.remove(sys_id);
        s.reach_v4.remove(sys_id);
        s.reach_v6.remove(sys_id);
        s.mt_membership.remove(sys_id);
        s.mt2_reach_v6.remove(sys_id);
        s.srv6_end_map.remove(sys_id);
        s.peer_fad.remove(sys_id);
        s.peer_link_affinity.remove(sys_id);
        s.peer_algo_sid.remove(sys_id);
        s.peer_algos.remove(sys_id);
        return;
    }

    let frag0 = frags.iter().find(|f| f.lsp_id.fragment_id() == 0).copied();

    // --- Scalar (fragment 0 only) -----------------------------------
    // Hostname.
    let frag0_hostname = frag0.and_then(|f| {
        f.tlvs.iter().find_map(|t| match t {
            IsisTlv::Hostname(h) => Some(h),
            _ => None,
        })
    });
    if let Some(h) = frag0_hostname {
        s.hostname.insert(*sys_id, h.hostname.clone());
    } else {
        s.hostname.remove(sys_id);
    }

    // SR capability → label_map.
    let frag0_cap = frag0.and_then(|f| {
        f.tlvs.iter().find_map(|t| match t {
            IsisTlv::RouterCap(c) => Some(c),
            _ => None,
        })
    });
    let mut label_inserted = false;
    if let Some(cap_tlv) = frag0_cap {
        let cap_view = lsp_cap_view(cap_tlv);
        if let Some(cap) = cap_view.cap
            && let SidLabelTlv::Label(start) = cap.sid_label
        {
            let mut label_config = LabelConfig {
                global: LabelBlock::new(start, cap.range),
                local: None,
            };
            if let Some(lb) = cap_view.lb
                && let SidLabelTlv::Label(local_start) = lb.sid_label
            {
                label_config.local = Some(LabelBlock::new(local_start, lb.range));
            }
            s.label_map.insert(*sys_id, label_config);
            label_inserted = true;
        }
    }
    if !label_inserted {
        s.label_map.remove(sys_id);
    }

    // MT capability.
    let mut mt_set: BTreeSet<MtId> = BTreeSet::new();
    if let Some(f0) = frag0 {
        for tlv in &f0.tlvs {
            if let IsisTlv::MultiTopology(mt_tlv) = tlv {
                for entry in &mt_tlv.entries {
                    if let Some(id) = mt_id_from_wire(entry.id()) {
                        mt_set.insert(id);
                    }
                }
            }
        }
    }
    if mt_set.is_empty() {
        s.mt_membership.remove(sys_id);
    } else {
        s.mt_membership.insert(*sys_id, mt_set);
    }

    // Flex-Algorithm Definitions (RFC 9350 §5.1). Live inside Router
    // Capability TLV 242, which is fragment-0-only — so the existing
    // `frag0_cap` lookup above is the right source. Multiple FADs
    // for distinct algorithms can appear in a single Router
    // Capability; if a peer (incorrectly) emits two FADs for the
    // same algo, last-wins via BTreeMap::insert.
    let mut fad_map: BTreeMap<u8, IsisSubFlexAlgoDef> = BTreeMap::new();
    if let Some(cap_tlv) = frag0_cap {
        for fad in lsp_cap_view(cap_tlv).fads {
            fad_map.insert(fad.flex_algorithm, fad.clone());
        }
    }
    if fad_map.is_empty() {
        s.peer_fad.remove(sys_id);
    } else {
        s.peer_fad.insert(*sys_id, fad_map);
    }

    // SR algorithm participation (RFC 8667 §3.2, sub-TLV 19). Like
    // FADs, this lives inside Router Capability TLV 242 — fragment-0-
    // only. The wire enum maps to a byte via `Algo::to_byte()`; we
    // store the byte form so consumers can compare against per-algo
    // computation requests without round-tripping through the enum.
    let mut algo_set: BTreeSet<u8> = BTreeSet::new();
    if let Some(cap_tlv) = frag0_cap
        && let Some(algo_tlv) = lsp_cap_view(cap_tlv).algo
    {
        for a in &algo_tlv.algo {
            algo_set.insert(a.to_byte());
        }
    }
    if algo_set.is_empty() {
        s.peer_algos.remove(sys_id);
    } else {
        s.peer_algos.insert(*sys_id, algo_set);
    }

    // Per-link affinity bitmaps from peer-advertised ASLA sub-TLVs
    // (RFC 9479). Walk every fragment's Ext IS-Reach (TLV 22) and
    // MT IS-Reach (TLV 222) entries; for each entry's IsisSubAsla
    // sub-TLV whose SABM marks Flex-Algorithm application, extract
    // the nested IsisSubAdminGrp bitmap and stash it keyed by the
    // neighbor_id. Multiple entries for the same neighbor_id across
    // fragments (or across TLV 22 / TLV 222 for the same link) yield
    // last-wins via BTreeMap::insert — by construction the producer
    // emits the same bytes on both topologies (PR #613), so any
    // duplication is benign.
    let mut link_affinity: BTreeMap<IsisNeighborId, ExtAdminGroup> = BTreeMap::new();
    for f in &frags {
        for tlv in &f.tlvs {
            let entries: &[IsisTlvExtIsReachEntry] = match tlv {
                IsisTlv::ExtIsReach(t) => &t.entries,
                IsisTlv::MtIsReach(t) => &t.entries,
                _ => continue,
            };
            for entry in entries {
                for sub in &entry.subs {
                    if let isis_packet::neigh::IsisSubTlv::Asla(asla) = sub
                        && let Some(bitmap) = super::flex_algo::parse_asla_flex_algo_bitmap(asla)
                    {
                        link_affinity.insert(entry.neighbor_id, bitmap);
                    }
                }
            }
        }
    }
    if link_affinity.is_empty() {
        s.peer_link_affinity.remove(sys_id);
    } else {
        s.peer_link_affinity.insert(*sys_id, link_affinity);
    }

    // Per-algorithm Prefix-SIDs from peer Ext IP-Reach (TLV 135)
    // entries (RFC 8667 §2.1 + RFC 9350 §7). One entry per
    // (peer, algo, prefix); for the same key across fragments,
    // last-wins via BTreeMap::insert.
    let mut algo_sids: BTreeMap<(u8, ipnet::Ipv4Net), SidLabelValue> = BTreeMap::new();
    for f in &frags {
        for tlv in &f.tlvs {
            if let IsisTlv::ExtIpReach(t) = tlv {
                for entry in &t.entries {
                    for (algo, sid) in super::flex_algo::parse_per_algo_prefix_sids(entry) {
                        algo_sids.insert((algo, entry.prefix), sid);
                    }
                }
            }
        }
    }
    if algo_sids.is_empty() {
        s.peer_algo_sid.remove(sys_id);
    } else {
        s.peer_algo_sid.insert(*sys_id, algo_sids);
    }

    // --- Distributable (union across fragments) ---------------------
    let mut v4_entries: Vec<IsisTlvExtIpReachEntry> = Vec::new();
    let mut v6_entries: Vec<IsisTlvIpv6ReachEntry> = Vec::new();
    let mut mt2_v6_entries: Vec<IsisTlvIpv6ReachEntry> = Vec::new();
    let mut end_sid: Option<Ipv6Addr> = None;

    for f in &frags {
        for tlv in &f.tlvs {
            match tlv {
                IsisTlv::ExtIpReach(t) => v4_entries.extend(t.entries.iter().cloned()),
                IsisTlv::Ipv6Reach(t) => v6_entries.extend(t.entries.iter().cloned()),
                IsisTlv::MtIpv6Reach(t) if t.mt.id() == 2 => {
                    mt2_v6_entries.extend(t.entries.iter().cloned());
                }
                IsisTlv::Srv6(t) if end_sid.is_none() => {
                    'outer: for locator in &t.locators {
                        for sub in &locator.subs {
                            if let prefix::IsisSubTlv::Srv6EndSid(es) = sub {
                                end_sid = Some(es.sid);
                                break 'outer;
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    if v4_entries.is_empty() {
        s.reach_v4.remove(sys_id);
    } else {
        s.reach_v4.insert(*sys_id, v4_entries);
    }
    if v6_entries.is_empty() {
        s.reach_v6.remove(sys_id);
    } else {
        s.reach_v6.insert(*sys_id, v6_entries);
    }
    if mt2_v6_entries.is_empty() {
        s.mt2_reach_v6.remove(sys_id);
    } else {
        s.mt2_reach_v6.insert(*sys_id, mt2_v6_entries);
    }
    if let Some(sid) = end_sid {
        s.srv6_end_map.insert(*sys_id, sid);
    } else {
        s.srv6_end_map.remove(sys_id);
    }
}

/// Map a 12-bit wire MT ID to the local enum. Multicast variants and
/// unknown values fall through to None — they parse but we don't act
/// on them.
fn mt_id_from_wire(wire: u16) -> Option<crate::isis::config::MtId> {
    use crate::isis::config::MtId;
    match wire {
        0 => Some(MtId::Standard),
        2 => Some(MtId::Ipv6Unicast),
        _ => None,
    }
}

pub fn insert_lsp(top: &mut LinkTop, level: Level, lsp: IsisLsp, bytes: Vec<u8>) -> Option<Lsa> {
    let key = lsp.lsp_id;

    if top.up_config.net.sys_id() == key.sys_id() {
        isis_database_trace!(top.tracing, Lsdb, &level, "Self originated LSP?");
        return None;
    }

    // Sequence-number and min-lsp-arrival-time gating against the
    // existing entry. RFC 4444 §3.1: storm-protect by ignoring new
    // versions that arrive within the arrival window after the last
    // accepted version of the same LSP.
    let tlvs_changed = if let Some(lsa) = top.lsdb.get(&level).get(&lsp.lsp_id) {
        if lsp.seq_number <= lsa.lsp.seq_number {
            isis_database_trace!(
                top.tracing,
                Lsdb,
                &level,
                "Same or smaller seq_number, no need of updating LSDB"
            );
            return None;
        }
        let window = Duration::from_millis(top.up_config.min_lsp_arrival_time() as u64);
        if let Some(last) = lsa.last_received
            && last.elapsed() < window
        {
            isis_database_trace!(
                top.tracing,
                Lsdb,
                &level,
                "Within min-lsp-arrival-time window, dropping"
            );
            return None;
        }
        lsa.lsp.tlvs != lsp.tlvs
    } else {
        true
    };

    let hold_time = lsp.hold_time;
    let mut lsa = Lsa::new(lsp);
    lsa.ifindex = top.ifindex;
    lsa.bytes = bytes;
    // Purges (hold_time == 0) must linger for ZeroAgeLifetime so the
    // SRM flood can read their bytes before the entry is evicted —
    // see `hold_timer_secs`.
    lsa.hold_timer = Some(hold_timer(top.tx, level, key, hold_timer_secs(hold_time)));
    lsa.last_received = Some(Instant::now());

    let prev = top.lsdb.get_mut(&level).map.insert(key, lsa);

    // Pseudonode LSPs are consumed only by the SPF graph builder
    // (see `graph::graph` / `graph::graph_mt2`); they don't carry
    // hostname / cap / reach TLVs that feed the per-sys-id maps,
    // so skip the rebuild on those keys.
    if !key.is_pseudo() && tlvs_changed {
        let self_sys_id = top.up_config.net.sys_id();
        let sys_id = key.sys_id();
        rebuild_sys_state(
            top.lsdb.get(&level),
            &self_sys_id,
            &sys_id,
            SysStateRefs {
                hostname: top.hostname.get_mut(&level),
                label_map: top.label_map.get_mut(&level),
                reach_v4: top.reach_map.get_mut(&level).get_mut(&Afi::Ip),
                reach_v6: top.reach_map_v6.get_mut(&level),
                mt_membership: top.mt_membership.get_mut(&level),
                mt2_reach_v6: top.mt2_reach_map_v6.get_mut(&level),
                srv6_end_map: top.srv6_end_map.get_mut(&level),
                peer_fad: top.peer_fad.get_mut(&level),
                peer_link_affinity: top.peer_link_affinity.get_mut(&level),
                peer_algo_sid: top.peer_algo_sid.get_mut(&level),
                peer_algos: top.peer_algos.get_mut(&level),
            },
        );
    }

    spf_schedule(top, level);

    prev
}

pub fn insert_self_originate(
    top: &mut IsisTop,
    level: Level,
    lsp: IsisLsp,
    bytes: Option<Vec<u8>>,
) -> Option<Lsa> {
    let key = lsp.lsp_id;
    let mut lsa = Lsa::new(lsp);
    lsa.originated = true;

    // Same ZeroAgeLifetime treatment as `insert_lsp` for self-
    // originated purges — `process_lsp_purge` calls in here with
    // hold_time == 0, and the entry must survive long enough for
    // `srm_advertise` to flood its bytes to peers.
    lsa.hold_timer = Some(hold_timer(
        top.tx,
        level,
        key,
        hold_timer_secs(lsa.lsp.hold_time),
    ));

    let mut refresh_time = top.config.refresh_time();

    const MIN_LSP_TRANS_INTERVAL: u16 = 5;
    const DEFAULT_REFRESH_TIME: u16 = 15 * 60;

    // Remaining lifetime.
    let rl = lsa.lsp.hold_time;
    let safety_margin = ZERO_AGE_LIFETIME + MIN_LSP_TRANS_INTERVAL;
    if rl < DEFAULT_REFRESH_TIME {
        if rl > safety_margin {
            refresh_time = rl - safety_margin;
        } else {
            refresh_time = 1;
        }
    }

    lsa.refresh_timer = Some(refresh_timer(top.tx, level, key, refresh_time));
    if let Some(bytes) = bytes {
        lsa.bytes = bytes;
    }
    let prev = top.lsdb.get_mut(&level).map.insert(key, lsa);
    // Schedule SPF on self-origination too. The regular receive
    // path (`insert_lsp`) does this via `spf_schedule(LinkTop)`;
    // without it here, an LSP we just regenerated (router LSP
    // after adjacency UP, pseudonode LSP after we (re-)become DIS)
    // would not refresh the graph until some peer LSP arrives.
    // After a link bounce the graph could stay stale — z1's TLV
    // pointing at z1.NN-00 sees the PN LSP missing from the LSDB
    // at SPF time and drops the edge.
    spf_schedule_top(top, level);
    prev
}

pub fn remove_lsp(top: &mut IsisTop, level: Level, key: IsisLspId) {
    if top.lsdb.get_mut(&level).remove(&key).is_none() {
        return;
    }

    // Pseudonode LSP removals don't touch the per-sys-id maps; they
    // disappear from the SPF graph naturally on the next graph build.
    if key.is_pseudo() {
        return;
    }

    // Refresh the per-sys-id maps from whatever fragments remain.
    // When the removed entry was fragment 0 this clears scalar
    // attributes (hostname, SR cap, MT capability); when it was a
    // higher fragment the union'd reach maps shrink accordingly.
    let self_sys_id = top.config.net.sys_id();
    let sys_id = key.sys_id();
    rebuild_sys_state(
        top.lsdb.get(&level),
        &self_sys_id,
        &sys_id,
        SysStateRefs {
            hostname: top.hostname.get_mut(&level),
            label_map: top.label_map.get_mut(&level),
            reach_v4: top.reach_map.get_mut(&level).get_mut(&Afi::Ip),
            reach_v6: top.reach_map_v6.get_mut(&level),
            mt_membership: top.mt_membership.get_mut(&level),
            mt2_reach_v6: top.mt2_reach_map_v6.get_mut(&level),
            srv6_end_map: top.srv6_end_map.get_mut(&level),
            peer_fad: top.peer_fad.get_mut(&level),
            peer_link_affinity: top.peer_link_affinity.get_mut(&level),
            peer_algo_sid: top.peer_algo_sid.get_mut(&level),
            peer_algos: top.peer_algos.get_mut(&level),
        },
    );
}

fn lsp_clone_with_seqno_inc(lsp: &IsisLsp) -> IsisLsp {
    let mut lsp = lsp.clone();
    lsp.seq_number += 1;
    lsp.checksum = 0;
    lsp
}

pub fn refresh_lsp(top: &mut IsisTop, level: Level, key: IsisLspId) {
    if let Some(lsa) = top.lsdb.get(&level).get(&key) {
        let mut lsp = lsp_clone_with_seqno_inc(&lsa.lsp);
        let auth_cfg = crate::isis::lsp::level_auth_cfg(top.config, level).clone();
        let resolved =
            crate::isis::auth::resolve_send(&auth_cfg, top.key_chains, chrono::Utc::now());
        let buf = lsp_emit(&mut lsp, level, resolved.as_ref());
        let lsp_id = lsp.lsp_id;
        insert_self_originate(top, level, lsp, Some(buf.to_vec()));
        lsp_flood(top, level, &lsp_id);
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use ipnet::Ipv4Net;
    use isis_packet::prefix::Ipv4ControlInfo;

    use super::*;

    /// ISO 10589 §7.3.16.4: a purge (Remaining Lifetime == 0) must
    /// linger in the LSDB for ZeroAgeLifetime so the SRM flood can
    /// read its bytes before eviction. Without this, `hold_timer`
    /// armed at 0 fires before `srm_advertise` and the purge is
    /// silently dropped.
    #[test]
    fn purge_hold_timer_uses_zero_age_lifetime() {
        assert_eq!(
            hold_timer_secs(0),
            ZERO_AGE_LIFETIME,
            "hold_time == 0 must be remapped to ZeroAgeLifetime"
        );
        assert_eq!(
            hold_timer_secs(900),
            900,
            "non-zero hold_time must pass through untouched"
        );
        assert_eq!(
            hold_timer_secs(1),
            1,
            "tiny non-zero hold_time must pass through untouched"
        );
    }

    fn sys(b: u8) -> IsisSysId {
        IsisSysId {
            id: [0, 0, 0, 0, 0, b],
        }
    }

    fn frag(sys_id: IsisSysId, frag_id: u8) -> IsisLsp {
        IsisLsp {
            lsp_id: IsisLspId::new(sys_id, 0, frag_id),
            ..Default::default()
        }
    }

    fn v4_entry(octet: u8) -> IsisTlvExtIpReachEntry {
        let prefix = Ipv4Net::new(Ipv4Addr::new(10, 0, 0, octet), 32).unwrap();
        let flags = Ipv4ControlInfo::new()
            .with_prefixlen(32)
            .with_sub_tlv(false)
            .with_distribution(false);
        IsisTlvExtIpReachEntry {
            metric: 10,
            flags,
            prefix,
            subs: vec![],
        }
    }

    /// Two fragments from one peer: fragment 0 carries the scalar
    /// Hostname plus one IPv4 reach; fragment 1 carries a second
    /// IPv4 reach. The rebuild must keep both reach entries (union)
    /// and install the hostname. Then dropping fragment 0 must
    /// clear the hostname and leave only fragment 1's entry.
    #[test]
    fn rebuild_unions_distributable_and_anchors_scalars() {
        let mut lsdb = Lsdb::default();
        let peer = sys(1);

        let mut f0 = frag(peer, 0);
        f0.tlvs.push(
            IsisTlvHostname {
                hostname: "peer".to_string(),
            }
            .into(),
        );
        f0.tlvs.push(
            IsisTlvExtIpReach {
                entries: vec![v4_entry(1)],
            }
            .into(),
        );

        let mut f1 = frag(peer, 1);
        f1.tlvs.push(
            IsisTlvExtIpReach {
                entries: vec![v4_entry(2)],
            }
            .into(),
        );

        lsdb.map.insert(f0.lsp_id, Lsa::new(f0));
        lsdb.map.insert(f1.lsp_id, Lsa::new(f1));

        let mut hostname = Hostname::default();
        let mut label_map = IsisLabelMap::default();
        let mut reach_v4 = ReachMap::default();
        let mut reach_v6 = ReachMapV6::default();
        let mut mt_membership: BTreeMap<IsisSysId, BTreeSet<MtId>> = BTreeMap::new();
        let mut mt2_reach_v6 = ReachMapV6::default();
        let mut srv6_end_map: BTreeMap<IsisSysId, Ipv6Addr> = BTreeMap::new();
        let mut peer_fad: BTreeMap<IsisSysId, BTreeMap<u8, IsisSubFlexAlgoDef>> = BTreeMap::new();
        let mut peer_link_affinity: BTreeMap<IsisSysId, BTreeMap<IsisNeighborId, ExtAdminGroup>> =
            BTreeMap::new();
        let mut peer_algo_sid: BTreeMap<IsisSysId, BTreeMap<(u8, Ipv4Net), SidLabelValue>> =
            BTreeMap::new();
        let mut peer_algos: BTreeMap<IsisSysId, BTreeSet<u8>> = BTreeMap::new();

        rebuild_sys_state(
            &lsdb,
            &sys(0xFF), // self sys-id distinct from the peer
            &peer,
            SysStateRefs {
                hostname: &mut hostname,
                label_map: &mut label_map,
                reach_v4: &mut reach_v4,
                reach_v6: &mut reach_v6,
                mt_membership: &mut mt_membership,
                mt2_reach_v6: &mut mt2_reach_v6,
                srv6_end_map: &mut srv6_end_map,
                peer_fad: &mut peer_fad,
                peer_link_affinity: &mut peer_link_affinity,
                peer_algo_sid: &mut peer_algo_sid,
                peer_algos: &mut peer_algos,
            },
        );

        assert_eq!(
            hostname.get(&peer).map(|(h, _)| h.as_str()),
            Some("peer"),
            "fragment 0's hostname must be installed"
        );
        let v4 = reach_v4.get(&peer).expect("v4 reach must exist");
        assert_eq!(v4.len(), 2, "reach is union of both fragments");
        let octets: Vec<u8> = v4.iter().map(|e| e.prefix.addr().octets()[3]).collect();
        assert!(octets.contains(&1) && octets.contains(&2));

        // Drop fragment 0 and rebuild again.
        lsdb.map.remove(&IsisLspId::new(peer, 0, 0));
        rebuild_sys_state(
            &lsdb,
            &sys(0xFF),
            &peer,
            SysStateRefs {
                hostname: &mut hostname,
                label_map: &mut label_map,
                reach_v4: &mut reach_v4,
                reach_v6: &mut reach_v6,
                mt_membership: &mut mt_membership,
                mt2_reach_v6: &mut mt2_reach_v6,
                srv6_end_map: &mut srv6_end_map,
                peer_fad: &mut peer_fad,
                peer_link_affinity: &mut peer_link_affinity,
                peer_algo_sid: &mut peer_algo_sid,
                peer_algos: &mut peer_algos,
            },
        );
        assert!(
            hostname.get(&peer).is_none(),
            "hostname must clear when fragment 0 leaves the LSDB"
        );
        let v4 = reach_v4.get(&peer).expect("v4 reach still has fragment 1");
        assert_eq!(v4.len(), 1);
        assert_eq!(v4[0].prefix.addr().octets()[3], 2);

        // Drop fragment 1 too; the peer should disappear entirely.
        lsdb.map.remove(&IsisLspId::new(peer, 0, 1));
        rebuild_sys_state(
            &lsdb,
            &sys(0xFF),
            &peer,
            SysStateRefs {
                hostname: &mut hostname,
                label_map: &mut label_map,
                reach_v4: &mut reach_v4,
                reach_v6: &mut reach_v6,
                mt_membership: &mut mt_membership,
                mt2_reach_v6: &mut mt2_reach_v6,
                srv6_end_map: &mut srv6_end_map,
                peer_fad: &mut peer_fad,
                peer_link_affinity: &mut peer_link_affinity,
                peer_algo_sid: &mut peer_algo_sid,
                peer_algos: &mut peer_algos,
            },
        );
        assert!(reach_v4.get(&peer).is_none());
        assert!(hostname.get(&peer).is_none());
    }

    /// The self sys-id is exempt from the rebuild because the
    /// origination path manages those maps directly (with the
    /// `originate=true` flag on the hostname entry). A receive-time
    /// rebuild that walked self fragments would clobber that flag.
    #[test]
    fn rebuild_skips_self_sys_id() {
        let mut lsdb = Lsdb::default();
        let me = sys(7);
        let mut f0 = frag(me, 0);
        f0.tlvs.push(
            IsisTlvHostname {
                hostname: "spoof".to_string(),
            }
            .into(),
        );
        lsdb.map.insert(f0.lsp_id, Lsa::new(f0));

        let mut hostname = Hostname::default();
        hostname.insert_originate(me, "real".to_string());

        let mut label_map = IsisLabelMap::default();
        let mut reach_v4 = ReachMap::default();
        let mut reach_v6 = ReachMapV6::default();
        let mut mt_membership: BTreeMap<IsisSysId, BTreeSet<MtId>> = BTreeMap::new();
        let mut mt2_reach_v6 = ReachMapV6::default();
        let mut srv6_end_map: BTreeMap<IsisSysId, Ipv6Addr> = BTreeMap::new();
        let mut peer_fad: BTreeMap<IsisSysId, BTreeMap<u8, IsisSubFlexAlgoDef>> = BTreeMap::new();
        let mut peer_link_affinity: BTreeMap<IsisSysId, BTreeMap<IsisNeighborId, ExtAdminGroup>> =
            BTreeMap::new();
        let mut peer_algo_sid: BTreeMap<IsisSysId, BTreeMap<(u8, Ipv4Net), SidLabelValue>> =
            BTreeMap::new();
        let mut peer_algos: BTreeMap<IsisSysId, BTreeSet<u8>> = BTreeMap::new();

        rebuild_sys_state(
            &lsdb,
            &me,
            &me,
            SysStateRefs {
                hostname: &mut hostname,
                label_map: &mut label_map,
                reach_v4: &mut reach_v4,
                reach_v6: &mut reach_v6,
                mt_membership: &mut mt_membership,
                mt2_reach_v6: &mut mt2_reach_v6,
                srv6_end_map: &mut srv6_end_map,
                peer_fad: &mut peer_fad,
                peer_link_affinity: &mut peer_link_affinity,
                peer_algo_sid: &mut peer_algo_sid,
                peer_algos: &mut peer_algos,
            },
        );

        let (host, originate) = hostname.get(&me).expect("self entry must survive");
        assert_eq!(host, "real");
        assert!(originate, "originate flag must not be cleared by rebuild");
    }

    /// A peer LSP fragment 0 carrying a Router Capability TLV with
    /// two FADs must populate `peer_fad[sys_id]` with one entry per
    /// FAD, keyed by the algorithm id. Dropping the fragment must
    /// clear the entry. Mirrors the hostname / SR capability rebuild
    /// pattern.
    #[test]
    fn rebuild_populates_and_clears_peer_fad() {
        let mut lsdb = Lsdb::default();
        let peer = sys(42);

        let fad_128 = IsisSubFlexAlgoDef {
            flex_algorithm: 128,
            metric_type: 1, // min-unidir-link-delay
            calc_type: 0,
            priority: 200,
            subs: vec![],
        };
        let fad_129 = IsisSubFlexAlgoDef {
            flex_algorithm: 129,
            metric_type: 0,
            calc_type: 0,
            priority: 128,
            subs: vec![],
        };
        let cap = IsisTlvRouterCap {
            router_id: Ipv4Addr::new(2, 2, 2, 2),
            flags: 0u8.into(),
            subs: vec![
                cap::IsisSubTlv::FlexAlgoDef(fad_128.clone()),
                cap::IsisSubTlv::FlexAlgoDef(fad_129.clone()),
            ],
        };
        let mut f0 = frag(peer, 0);
        f0.tlvs.push(IsisTlv::RouterCap(cap));
        lsdb.map.insert(f0.lsp_id, Lsa::new(f0));

        let mut hostname = Hostname::default();
        let mut label_map = IsisLabelMap::default();
        let mut reach_v4 = ReachMap::default();
        let mut reach_v6 = ReachMapV6::default();
        let mut mt_membership: BTreeMap<IsisSysId, BTreeSet<MtId>> = BTreeMap::new();
        let mut mt2_reach_v6 = ReachMapV6::default();
        let mut srv6_end_map: BTreeMap<IsisSysId, Ipv6Addr> = BTreeMap::new();
        let mut peer_fad: BTreeMap<IsisSysId, BTreeMap<u8, IsisSubFlexAlgoDef>> = BTreeMap::new();
        let mut peer_link_affinity: BTreeMap<IsisSysId, BTreeMap<IsisNeighborId, ExtAdminGroup>> =
            BTreeMap::new();
        let mut peer_algo_sid: BTreeMap<IsisSysId, BTreeMap<(u8, Ipv4Net), SidLabelValue>> =
            BTreeMap::new();
        let mut peer_algos: BTreeMap<IsisSysId, BTreeSet<u8>> = BTreeMap::new();

        rebuild_sys_state(
            &lsdb,
            &sys(0xFF),
            &peer,
            SysStateRefs {
                hostname: &mut hostname,
                label_map: &mut label_map,
                reach_v4: &mut reach_v4,
                reach_v6: &mut reach_v6,
                mt_membership: &mut mt_membership,
                mt2_reach_v6: &mut mt2_reach_v6,
                srv6_end_map: &mut srv6_end_map,
                peer_fad: &mut peer_fad,
                peer_link_affinity: &mut peer_link_affinity,
                peer_algo_sid: &mut peer_algo_sid,
                peer_algos: &mut peer_algos,
            },
        );

        let entries = peer_fad
            .get(&peer)
            .expect("FADs must populate after fragment 0 ingest");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries.get(&128), Some(&fad_128));
        assert_eq!(entries.get(&129), Some(&fad_129));

        // Drop fragment 0 — peer_fad must clear the peer entry.
        lsdb.map.remove(&IsisLspId::new(peer, 0, 0));
        rebuild_sys_state(
            &lsdb,
            &sys(0xFF),
            &peer,
            SysStateRefs {
                hostname: &mut hostname,
                label_map: &mut label_map,
                reach_v4: &mut reach_v4,
                reach_v6: &mut reach_v6,
                mt_membership: &mut mt_membership,
                mt2_reach_v6: &mut mt2_reach_v6,
                srv6_end_map: &mut srv6_end_map,
                peer_fad: &mut peer_fad,
                peer_link_affinity: &mut peer_link_affinity,
                peer_algo_sid: &mut peer_algo_sid,
                peer_algos: &mut peer_algos,
            },
        );
        assert!(
            !peer_fad.contains_key(&peer),
            "FADs must clear when the fragment 0 / Router Capability TLV disappears"
        );
    }

    /// A peer Ext IS-Reach entry with an ASLA Flex-Algo bitmap must
    /// populate `peer_link_affinity[sys_id][neighbor_id]`. An entry
    /// without the X-bit set must be ignored. Dropping the fragment
    /// must clear the peer entry.
    #[test]
    fn rebuild_populates_and_clears_peer_link_affinity() {
        let mut lsdb = Lsdb::default();
        let peer = sys(7);
        let nbr_a = IsisNeighborId {
            id: [1, 1, 1, 1, 1, 1, 0],
        };
        let nbr_b = IsisNeighborId {
            id: [2, 2, 2, 2, 2, 2, 0],
        };

        // Entry A: ASLA with Flex-Algo X-bit (0x10) + AdminGrp.
        let asla_flex = IsisSubAsla {
            l_flag: false,
            sabm: vec![0x10],
            udabm: vec![],
            subs: vec![isis_packet::neigh::IsisSubTlv::AdminGrp(IsisSubAdminGrp {
                groups: vec![0b1001], // bits 0 and 3 set
            })],
        };
        // Entry B: ASLA with only R-bit (0x80) — must be ignored.
        let asla_rsvp = IsisSubAsla {
            l_flag: false,
            sabm: vec![0x80],
            udabm: vec![],
            subs: vec![isis_packet::neigh::IsisSubTlv::AdminGrp(IsisSubAdminGrp {
                groups: vec![0xFF],
            })],
        };
        let ext_is_reach = IsisTlvExtIsReach {
            entries: vec![
                IsisTlvExtIsReachEntry {
                    neighbor_id: nbr_a,
                    metric: 10,
                    subs: vec![isis_packet::neigh::IsisSubTlv::Asla(asla_flex)],
                },
                IsisTlvExtIsReachEntry {
                    neighbor_id: nbr_b,
                    metric: 10,
                    subs: vec![isis_packet::neigh::IsisSubTlv::Asla(asla_rsvp)],
                },
            ],
        };
        let mut f0 = frag(peer, 0);
        f0.tlvs.push(IsisTlv::ExtIsReach(ext_is_reach));
        lsdb.map.insert(f0.lsp_id, Lsa::new(f0));

        let mut hostname = Hostname::default();
        let mut label_map = IsisLabelMap::default();
        let mut reach_v4 = ReachMap::default();
        let mut reach_v6 = ReachMapV6::default();
        let mut mt_membership: BTreeMap<IsisSysId, BTreeSet<MtId>> = BTreeMap::new();
        let mut mt2_reach_v6 = ReachMapV6::default();
        let mut srv6_end_map: BTreeMap<IsisSysId, Ipv6Addr> = BTreeMap::new();
        let mut peer_fad: BTreeMap<IsisSysId, BTreeMap<u8, IsisSubFlexAlgoDef>> = BTreeMap::new();
        let mut peer_link_affinity: BTreeMap<IsisSysId, BTreeMap<IsisNeighborId, ExtAdminGroup>> =
            BTreeMap::new();
        let mut peer_algo_sid: BTreeMap<IsisSysId, BTreeMap<(u8, Ipv4Net), SidLabelValue>> =
            BTreeMap::new();
        let mut peer_algos: BTreeMap<IsisSysId, BTreeSet<u8>> = BTreeMap::new();

        rebuild_sys_state(
            &lsdb,
            &sys(0xFF),
            &peer,
            SysStateRefs {
                hostname: &mut hostname,
                label_map: &mut label_map,
                reach_v4: &mut reach_v4,
                reach_v6: &mut reach_v6,
                mt_membership: &mut mt_membership,
                mt2_reach_v6: &mut mt2_reach_v6,
                srv6_end_map: &mut srv6_end_map,
                peer_fad: &mut peer_fad,
                peer_link_affinity: &mut peer_link_affinity,
                peer_algo_sid: &mut peer_algo_sid,
                peer_algos: &mut peer_algos,
            },
        );

        let entries = peer_link_affinity
            .get(&peer)
            .expect("affinity map must populate for the Flex-Algo entry");
        assert_eq!(entries.len(), 1, "RSVP-only entry must not be cached");
        let bitmap = entries.get(&nbr_a).expect("nbr_a bitmap");
        assert_eq!(bitmap.words, vec![0b1001]);
        assert!(!entries.contains_key(&nbr_b));

        // Drop the fragment — affinity map must clear.
        lsdb.map.remove(&IsisLspId::new(peer, 0, 0));
        rebuild_sys_state(
            &lsdb,
            &sys(0xFF),
            &peer,
            SysStateRefs {
                hostname: &mut hostname,
                label_map: &mut label_map,
                reach_v4: &mut reach_v4,
                reach_v6: &mut reach_v6,
                mt_membership: &mut mt_membership,
                mt2_reach_v6: &mut mt2_reach_v6,
                srv6_end_map: &mut srv6_end_map,
                peer_fad: &mut peer_fad,
                peer_link_affinity: &mut peer_link_affinity,
                peer_algo_sid: &mut peer_algo_sid,
                peer_algos: &mut peer_algos,
            },
        );
        assert!(!peer_link_affinity.contains_key(&peer));
    }

    /// A peer Ext IP-Reach entry with mixed algo-0 + flex-algo
    /// Prefix-SID sub-TLVs must populate
    /// `peer_algo_sid[sys_id][(algo, prefix)]` with only the
    /// flex-algo entries. Dropping the fragment clears the peer.
    #[test]
    fn rebuild_populates_and_clears_peer_algo_sid() {
        use isis_packet::PrefixSidFlags;
        use isis_packet::prefix::{Ipv4ControlInfo, IsisSubTlv as PrefixSubTlv};

        let mut lsdb = Lsdb::default();
        let peer = sys(11);
        let prefix: Ipv4Net = "10.0.0.1/32".parse().unwrap();
        let entry = IsisTlvExtIpReachEntry {
            metric: 10,
            flags: Ipv4ControlInfo::new(),
            prefix,
            subs: vec![
                PrefixSubTlv::PrefixSid(isis_packet::IsisSubPrefixSid {
                    flags: PrefixSidFlags::from(0u8),
                    algo: Algo::Spf,
                    sid: SidLabelValue::Index(1),
                }),
                PrefixSubTlv::PrefixSid(isis_packet::IsisSubPrefixSid {
                    flags: PrefixSidFlags::from(0u8),
                    algo: Algo::FlexAlgo(128),
                    sid: SidLabelValue::Index(1128),
                }),
            ],
        };
        let mut f0 = frag(peer, 0);
        f0.tlvs.push(IsisTlv::ExtIpReach(IsisTlvExtIpReach {
            entries: vec![entry],
        }));
        lsdb.map.insert(f0.lsp_id, Lsa::new(f0));

        let mut hostname = Hostname::default();
        let mut label_map = IsisLabelMap::default();
        let mut reach_v4 = ReachMap::default();
        let mut reach_v6 = ReachMapV6::default();
        let mut mt_membership: BTreeMap<IsisSysId, BTreeSet<MtId>> = BTreeMap::new();
        let mut mt2_reach_v6 = ReachMapV6::default();
        let mut srv6_end_map: BTreeMap<IsisSysId, Ipv6Addr> = BTreeMap::new();
        let mut peer_fad: BTreeMap<IsisSysId, BTreeMap<u8, IsisSubFlexAlgoDef>> = BTreeMap::new();
        let mut peer_link_affinity: BTreeMap<IsisSysId, BTreeMap<IsisNeighborId, ExtAdminGroup>> =
            BTreeMap::new();
        let mut peer_algo_sid: BTreeMap<IsisSysId, BTreeMap<(u8, Ipv4Net), SidLabelValue>> =
            BTreeMap::new();
        let mut peer_algos: BTreeMap<IsisSysId, BTreeSet<u8>> = BTreeMap::new();

        rebuild_sys_state(
            &lsdb,
            &sys(0xFF),
            &peer,
            SysStateRefs {
                hostname: &mut hostname,
                label_map: &mut label_map,
                reach_v4: &mut reach_v4,
                reach_v6: &mut reach_v6,
                mt_membership: &mut mt_membership,
                mt2_reach_v6: &mut mt2_reach_v6,
                srv6_end_map: &mut srv6_end_map,
                peer_fad: &mut peer_fad,
                peer_link_affinity: &mut peer_link_affinity,
                peer_algo_sid: &mut peer_algo_sid,
                peer_algos: &mut peer_algos,
            },
        );

        let entries = peer_algo_sid
            .get(&peer)
            .expect("peer_algo_sid must populate");
        // Algo-0 entry must be skipped; only flex-algo 128 cached.
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries.get(&(128, prefix)),
            Some(&SidLabelValue::Index(1128))
        );

        lsdb.map.remove(&IsisLspId::new(peer, 0, 0));
        rebuild_sys_state(
            &lsdb,
            &sys(0xFF),
            &peer,
            SysStateRefs {
                hostname: &mut hostname,
                label_map: &mut label_map,
                reach_v4: &mut reach_v4,
                reach_v6: &mut reach_v6,
                mt_membership: &mut mt_membership,
                mt2_reach_v6: &mut mt2_reach_v6,
                srv6_end_map: &mut srv6_end_map,
                peer_fad: &mut peer_fad,
                peer_link_affinity: &mut peer_link_affinity,
                peer_algo_sid: &mut peer_algo_sid,
                peer_algos: &mut peer_algos,
            },
        );
        assert!(!peer_algo_sid.contains_key(&peer));
    }

    /// A peer LSP fragment 0 carrying a Router Capability TLV with an
    /// SR-Algorithms sub-TLV (RFC 8667 §3.2, sub-TLV 19) must populate
    /// `peer_algos[sys_id]` with the byte form of every advertised
    /// algorithm — algo 0 (SPF), 1 (Strict SPF), and any Flex-Algo
    /// identifiers in 128..=255. Dropping the fragment must clear the
    /// entry, since SR-Algorithms is fragment-0-only.
    #[test]
    fn rebuild_populates_and_clears_peer_algos() {
        let mut lsdb = Lsdb::default();
        let peer = sys(43);

        let algo_sub = isis_packet::IsisSubSegmentRoutingAlgo {
            algo: vec![Algo::Spf, Algo::FlexAlgo(128), Algo::FlexAlgo(129)],
        };
        let cap = IsisTlvRouterCap {
            router_id: Ipv4Addr::new(3, 3, 3, 3),
            flags: 0u8.into(),
            subs: vec![cap::IsisSubTlv::SegmentRoutingAlgo(algo_sub)],
        };
        let mut f0 = frag(peer, 0);
        f0.tlvs.push(IsisTlv::RouterCap(cap));
        lsdb.map.insert(f0.lsp_id, Lsa::new(f0));

        let mut hostname = Hostname::default();
        let mut label_map = IsisLabelMap::default();
        let mut reach_v4 = ReachMap::default();
        let mut reach_v6 = ReachMapV6::default();
        let mut mt_membership: BTreeMap<IsisSysId, BTreeSet<MtId>> = BTreeMap::new();
        let mut mt2_reach_v6 = ReachMapV6::default();
        let mut srv6_end_map: BTreeMap<IsisSysId, Ipv6Addr> = BTreeMap::new();
        let mut peer_fad: BTreeMap<IsisSysId, BTreeMap<u8, IsisSubFlexAlgoDef>> = BTreeMap::new();
        let mut peer_link_affinity: BTreeMap<IsisSysId, BTreeMap<IsisNeighborId, ExtAdminGroup>> =
            BTreeMap::new();
        let mut peer_algo_sid: BTreeMap<IsisSysId, BTreeMap<(u8, Ipv4Net), SidLabelValue>> =
            BTreeMap::new();
        let mut peer_algos: BTreeMap<IsisSysId, BTreeSet<u8>> = BTreeMap::new();

        rebuild_sys_state(
            &lsdb,
            &sys(0xFF),
            &peer,
            SysStateRefs {
                hostname: &mut hostname,
                label_map: &mut label_map,
                reach_v4: &mut reach_v4,
                reach_v6: &mut reach_v6,
                mt_membership: &mut mt_membership,
                mt2_reach_v6: &mut mt2_reach_v6,
                srv6_end_map: &mut srv6_end_map,
                peer_fad: &mut peer_fad,
                peer_link_affinity: &mut peer_link_affinity,
                peer_algo_sid: &mut peer_algo_sid,
                peer_algos: &mut peer_algos,
            },
        );

        let advertised = peer_algos
            .get(&peer)
            .expect("peer_algos must populate after fragment 0 ingest");
        assert_eq!(
            advertised,
            &BTreeSet::from([0u8, 128, 129]),
            "SR-Algorithms byte-form must round-trip Spf + FlexAlgo IDs"
        );

        // Drop fragment 0 — peer_algos must clear since the cap TLV
        // is fragment-0-only.
        lsdb.map.remove(&IsisLspId::new(peer, 0, 0));
        rebuild_sys_state(
            &lsdb,
            &sys(0xFF),
            &peer,
            SysStateRefs {
                hostname: &mut hostname,
                label_map: &mut label_map,
                reach_v4: &mut reach_v4,
                reach_v6: &mut reach_v6,
                mt_membership: &mut mt_membership,
                mt2_reach_v6: &mut mt2_reach_v6,
                srv6_end_map: &mut srv6_end_map,
                peer_fad: &mut peer_fad,
                peer_link_affinity: &mut peer_link_affinity,
                peer_algo_sid: &mut peer_algo_sid,
                peer_algos: &mut peer_algos,
            },
        );
        assert!(!peer_algos.contains_key(&peer));
    }
}
