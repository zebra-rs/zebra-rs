use std::collections::btree_map::{Iter, Values};
use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv6Addr;
use std::time::{Duration, Instant};

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
            cap::IsisSubTlv::FlexAlgoDef(_) => {
                // FAD consumers (peer FAD store, SPF gating) land in
                // a follow-up PR; for now we round-trip the sub-TLV
                // but don't surface it through the cap view.
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
    lsa.hold_timer = Some(hold_timer(top.tx, level, key, hold_time));
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

    lsa.hold_timer = Some(hold_timer(top.tx, level, key, lsa.lsp.hold_time));

    let mut refresh_time = top.config.refresh_time();

    const ZERO_AGE_LIFETIME: u16 = 60;
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
        let buf = lsp_emit(&mut lsp, level);
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
            },
        );

        let (host, originate) = hostname.get(&me).expect("self entry must survive");
        assert_eq!(host, "real");
        assert!(originate, "originate flag must not be cleared by rebuild");
    }
}
