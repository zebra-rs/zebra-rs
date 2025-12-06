use std::collections::BTreeMap;
use std::collections::btree_map::{Iter, Values};

use bytes::BytesMut;
use isis_packet::*;
use tokio::sync::mpsc::UnboundedSender;

use crate::isis::psnp_send_pdu;
use crate::isis_database_trace;

use crate::context::Timer;
use crate::isis::{
    Message,
    srmpls::{LabelBlock, LabelConfig},
};

use super::inst::{MsgSender, Packet, PacketMessage};
use super::link::LinkTop;
use super::{
    Level, LsaFlood,
    inst::{IsisTop, lsp_emit, lsp_flood, spf_schedule},
    link::Afi,
};

#[derive(Default)]
pub struct Lsdb {
    pub map: BTreeMap<IsisLspId, Lsa>,
    pub adj: BTreeMap<u32, LsaFlood>,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum LsdbEvent {
    RefreshTimerExpire,
    HoldTimerExpire,
}

pub struct Lsa {
    pub lsp: IsisLsp,
    pub originated: bool,
    pub from: Option<u32>,
    pub hold_timer: Option<Timer>,
    pub refresh_timer: Option<Timer>,
    pub csnp_timer: Option<Timer>,
    pub ifindex: u32,
    pub bytes: Vec<u8>,
}

impl Lsa {
    pub fn new(lsp: IsisLsp) -> Self {
        Self {
            lsp,
            originated: false,
            from: None,
            hold_timer: None,
            refresh_timer: None,
            csnp_timer: None,
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

    pub fn contains_key(&self, key: &IsisLspId) -> bool {
        self.map.contains_key(key)
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
            tx.send(msg);
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

fn csnp_timer(top: &mut IsisTop, level: Level, key: IsisLspId) -> Timer {
    let tx = top.tx.clone();
    Timer::once(3, move || {
        let tx = tx.clone();
        async move {
            use LsdbEvent::*;
            let msg = Message::Lsdb(RefreshTimerExpire, level, key);
            tx.send(msg);
        }
    })
}

fn update_pseudo() {
    // TODO.
}

#[derive(Default)]
pub struct LspView<'a> {
    pub cap: Option<&'a IsisTlvRouterCap>,
    pub hostname: Option<&'a IsisTlvHostname>,
    pub ip_reach: Option<&'a IsisTlvExtIpReach>,
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

enum MplsLabel {
    ImplicitNull(u32),
    Label(u32),
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
    if let Some(prev) = top.lsdb.get(&level).get(&key) {
        if prev.lsp.tlvs == lsp.tlvs {
            return;
        }
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
                if let Some(lb) = cap_view.lb {
                    if let SidLabelTlv::Label(start) = lb.sid_label {
                        label_config.local = Some(LabelBlock::new(start, lb.range));
                    }
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
}

pub fn insert_lsp(top: &mut LinkTop, level: Level, lsp: IsisLsp, bytes: Vec<u8>) -> Option<Lsa> {
    let key = lsp.lsp_id.clone();

    if top.up_config.net.sys_id() == key.sys_id() {
        isis_database_trace!(top.tracing, Lsdb, &level, "Self originated LSP?");
        return None;
    }

    // Check sequence number.
    if let Some(lsa) = top.lsdb.get(&level).get(&lsp.lsp_id) {
        if lsp.seq_number <= lsa.lsp.seq_number {
            isis_database_trace!(
                top.tracing,
                Lsdb,
                &level,
                "Same or smaller seq_number, no need of updating LSDB"
            );
            return None;
        }
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

    let lsa = top.lsdb.get_mut(&level).map.insert(key, lsa);

    lsa
}

pub fn insert_self_originate(
    top: &mut IsisTop,
    level: Level,
    lsp: IsisLsp,
    bytes: Option<Vec<u8>>,
) -> Option<Lsa> {
    let key = lsp.lsp_id.clone();
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
    top.lsdb.get_mut(&level).map.insert(key, lsa)
}

pub fn insert_self_originate_link(
    top: &mut LinkTop,
    level: Level,
    lsp: IsisLsp,
    bytes: Option<Vec<u8>>,
) -> Option<Lsa> {
    let key = lsp.lsp_id.clone();
    let mut lsa = Lsa::new(lsp);
    lsa.originated = true;

    lsa.hold_timer = Some(hold_timer(top.tx, level, key, lsa.lsp.hold_time));

    let mut refresh_time = top.up_config.refresh_time();

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
    top.lsdb.get_mut(&level).map.insert(key, lsa)
}

pub fn remove_lsp(top: &mut IsisTop, level: Level, key: IsisLspId) {
    if let Some(lsa) = top.lsdb.get_mut(&level).remove(&key) {
        if let Some(_tlv) = lsa.lsp.hostname_tlv() {
            top.hostname.get_mut(&level).remove(&key.sys_id());
        }
    }
}

pub fn remove_lsp_link(top: &mut LinkTop, level: Level, key: IsisLspId) {
    if let Some(lsa) = top.lsdb.get_mut(&level).remove(&key) {
        if let Some(_tlv) = lsa.lsp.hostname_tlv() {
            top.hostname.get_mut(&level).remove(&key.sys_id());
        }
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
