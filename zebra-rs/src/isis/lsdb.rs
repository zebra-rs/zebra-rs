use std::collections::BTreeMap;
use std::collections::btree_map::{Iter, Values};

use isis_packet::*;

use crate::isis_database_trace;

use crate::context::Timer;
use crate::isis::{
    Message,
    srmpls::{LabelBlock, LabelConfig},
};

use super::inst::MsgSender;
use super::link::LinkTop;
use super::{
    Level, LspFlood,
    inst::{IsisTop, spf_schedule},
    link::Afi,
    lsp::{lsp_emit, lsp_flood},
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

fn update_pseudo() {
    // TODO.
}

#[derive(Default)]
pub struct LspView<'a> {
    pub cap: Option<&'a IsisTlvRouterCap>,
    pub hostname: Option<&'a IsisTlvHostname>,
    pub ip_reach: Option<&'a IsisTlvExtIpReach>,
    pub ipv6_reach: Option<&'a IsisTlvIpv6Reach>,
    /// MT capability TLV (229) — lists the MT IDs the originator
    /// participates in. Used to populate `mt_membership`.
    pub multi_topology: Option<&'a IsisTlvMultiTopology>,
    /// MT IPv6 Reach TLVs (237). One per MT id the originator
    /// emitted; vec because in principle a peer could advertise more
    /// than one (multicast variants etc.). PR 4 only consumes mt=2.
    pub mt_ipv6_reach: Vec<&'a IsisTlvMtIpv6Reach>,
    /// SRv6 locator TLV — carries the originator's locator(s) and
    /// the End SID sub-TLV inside each one. Used to populate
    /// `srv6_end_map` for TI-LFA SRv6 repair-path assembly.
    pub srv6: Option<&'a IsisTlvSrv6>,
}

pub fn lsp_view<'a>(lsp: &'a IsisLsp) -> LspView<'a> {
    let mut view = LspView::default();
    for tlv in &lsp.tlvs {
        match &tlv {
            IsisTlv::RouterCap(cap) => {
                view.cap = Some(cap);
            }
            IsisTlv::Hostname(hostname) => {
                view.hostname = Some(hostname);
            }
            IsisTlv::ExtIpReach(ip_reach) => {
                view.ip_reach = Some(ip_reach);
            }
            IsisTlv::Ipv6Reach(ipv6_reach) => {
                view.ipv6_reach = Some(ipv6_reach);
            }
            IsisTlv::MultiTopology(mt) => {
                view.multi_topology = Some(mt);
            }
            IsisTlv::MtIpv6Reach(mt_v6) => {
                view.mt_ipv6_reach.push(mt_v6);
            }
            IsisTlv::Srv6(srv6) => {
                view.srv6 = Some(srv6);
            }
            _ => {
                //
            }
        }
    }
    view
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

fn update_lsp(top: &mut LinkTop, level: Level, key: IsisLspId, lsp: &IsisLsp) {
    if let Some(prev) = top.lsdb.get(&level).get(&key)
        && prev.lsp.tlvs == lsp.tlvs
    {
        return;
    }

    let lsp = lsp_view(lsp);

    // Update hostname.
    if let Some(tlv) = lsp.hostname {
        top.hostname
            .get_mut(&level)
            .insert(key.sys_id(), tlv.hostname.clone());
    }

    if let Some(tlv) = lsp.cap {
        let cap_view = lsp_cap_view(tlv);

        if let Some(cap) = cap_view.cap {
            // Register global block.
            if let SidLabelTlv::Label(start) = cap.sid_label {
                // println!("Global block start: {}, end: {}", start, start + cap.range);
                let mut label_config = LabelConfig {
                    global: LabelBlock::new(start, cap.range),
                    local: None,
                };
                if let Some(lb) = cap_view.lb
                    && let SidLabelTlv::Label(start) = lb.sid_label
                {
                    label_config.local = Some(LabelBlock::new(start, lb.range));
                }
                top.label_map
                    .get_mut(&level)
                    .insert(key.sys_id(), label_config);
            }
        }
    } else {
        // No cap.
    }

    if let Some(tlv) = lsp.ip_reach {
        top.reach_map
            .get_mut(&level)
            .get_mut(&Afi::Ip)
            .insert(key.sys_id(), tlv.entries.clone());
    }

    if let Some(tlv) = lsp.ipv6_reach {
        top.reach_map_v6
            .get_mut(&level)
            .insert(key.sys_id(), tlv.entries.clone());
    }

    // MT capability — record which MT IDs the peer participates in.
    // Empty set = absent / single-topology peer (preserves the
    // "no key" sentinel that future graph builders use).
    if let Some(mt_tlv) = lsp.multi_topology {
        let mut ids = std::collections::BTreeSet::new();
        for entry in &mt_tlv.entries {
            if let Some(id) = mt_id_from_wire(entry.id()) {
                ids.insert(id);
            }
        }
        if !ids.is_empty() {
            top.mt_membership.get_mut(&level).insert(key.sys_id(), ids);
        } else {
            top.mt_membership.get_mut(&level).remove(&key.sys_id());
        }
    } else {
        top.mt_membership.get_mut(&level).remove(&key.sys_id());
    }

    // MT 2 IPv6 Reach (TLV 237 mt=2). Stored separately from
    // reach_map_v6 so a future per-MT v6 RIB build can pull the
    // MT 2 view in isolation without absorbing legacy TLV 236.
    let mut mt2_v6_entries: Vec<isis_packet::IsisTlvIpv6ReachEntry> = Vec::new();
    for tlv in &lsp.mt_ipv6_reach {
        if tlv.mt.id() == 2 {
            mt2_v6_entries.extend(tlv.entries.iter().cloned());
        }
    }
    if !mt2_v6_entries.is_empty() {
        top.mt2_reach_map_v6
            .get_mut(&level)
            .insert(key.sys_id(), mt2_v6_entries);
    } else {
        top.mt2_reach_map_v6.get_mut(&level).remove(&key.sys_id());
    }

    // SRv6 End SID — first one across all locators wins. Empty /
    // absent TLV removes any stale entry for this peer so the map
    // stays in sync with the LSDB.
    let mut end_sid = None;
    if let Some(srv6_tlv) = lsp.srv6 {
        'outer: for locator in &srv6_tlv.locators {
            for sub in &locator.subs {
                if let prefix::IsisSubTlv::Srv6EndSid(es) = sub {
                    end_sid = Some(es.sid);
                    break 'outer;
                }
            }
        }
    }
    if let Some(sid) = end_sid {
        top.srv6_end_map.get_mut(&level).insert(key.sys_id(), sid);
    } else {
        top.srv6_end_map.get_mut(&level).remove(&key.sys_id());
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

    // Check sequence number.
    if let Some(lsa) = top.lsdb.get(&level).get(&lsp.lsp_id)
        && lsp.seq_number <= lsa.lsp.seq_number
    {
        isis_database_trace!(
            top.tracing,
            Lsdb,
            &level,
            "Same or smaller seq_number, no need of updating LSDB"
        );
        return None;
    }

    if key.is_pseudo() {
        update_pseudo();
    } else {
        update_lsp(top, level, key, &lsp);
    }
    spf_schedule(top, level);

    let hold_time = lsp.hold_time;
    let mut lsa = Lsa::new(lsp);
    lsa.ifindex = top.ifindex;
    lsa.bytes = bytes;
    lsa.hold_timer = Some(hold_timer(top.tx, level, key, hold_time));

    top.lsdb.get_mut(&level).map.insert(key, lsa)
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
    // at SPF time and drops the edge. Inlined here because IsisTop
    // and LinkTop both expose spf_timer/tx but spf_schedule's
    // signature is over LinkTop.
    if top.spf_timer.get(&level).is_none() {
        *top.spf_timer.get_mut(&level) = Some(crate::isis::inst::spf_timer(top.tx, level));
    }
    prev
}

pub fn remove_lsp(top: &mut IsisTop, level: Level, key: IsisLspId) {
    if let Some(lsa) = top.lsdb.get_mut(&level).remove(&key)
        && let Some(_tlv) = lsa.lsp.hostname_tlv()
    {
        top.hostname.get_mut(&level).remove(&key.sys_id());
    }
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
