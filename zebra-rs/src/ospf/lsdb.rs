use std::time::Duration;
use std::{collections::BTreeMap, net::Ipv4Addr};

use ospf_packet::*;
use tokio::sync::mpsc::UnboundedSender;

use crate::spf::label_block::{LabelBlock, LabelConfig, LabelMap};

use super::ReachMap;
use super::inst::Message;
use super::task::{Timer, TimerType};
use super::version::{OspfVersion, Ospfv2};

pub type OspfLabelMap = LabelMap<Ipv4Addr>;

pub const OSPF_MAX_AGE: u16 = 3600;
pub const OSPF_MAX_AGE_DIFF: u16 = 900; // 15 minutes (RFC 2328 Section 13.1)
pub const OSPF_LS_REFRESH_TIME: u64 = 1800;
pub const OSPF_MAX_LSA_SEQ: u32 = 0x7FFFFFFF;
pub const OSPF_MIN_LS_ARRIVAL: u64 = 1; // 1 second (RFC 2328)

/// Flat LSDB storage: a single BTreeMap keyed by the full
/// `(LS-Type, LS-ID, Advertising-Router)` triple. Replaces the
/// earlier per-LS-type bucket layout (`LsTypes<LsTable>`).
///
/// The flat shape is friendlier to the v3 generification arc — v3's
/// LSA types (RFC 5340 §A.4.2.1, 0x2001 / 0x2002 / 0x2003 / …)
/// don't map cleanly onto v2's named buckets (Router / Network /
/// Summary / SummaryAsbr / AsExternal / OpaqueAreaLocal /
/// Unknown). Iterating per-type now goes through
/// [`Lsdb::iter_by_type`].
pub type LsTable<V = Ospfv2> = BTreeMap<OspfLsaKey, Lsa<V>>;

/// LSDB key: `(LS-Type, LS-ID, Advertising-Router)`.
///
/// Still v2-shaped — uses `OspfLsType` (v2's u8 enum). v3 LS-Types
/// are 16-bit numeric per RFC 5340 §A.4.2.1; a unified key (or a
/// `V::LsType` associated type) lands when the v3 LSDB consumer
/// materializes.
pub type OspfLsaKey = (OspfLsType, Ipv4Addr, Ipv4Addr);

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum LsdbEvent {
    RefreshTimerExpire,
    HoldTimerExpire,
    SelfOriginatedReceived,
}

/// Per-area (or AS-scope) Link State Database.
///
/// Parameterized over `V: OspfVersion`. The storage layout
/// (`tables: LsTable<V>`) is generic; the methods that
/// manipulate LSAs live in `impl Lsdb<Ospfv2>` for now because they
/// destructure v2-specific header / body types
/// (`OspfLsType` enum match, `OspfLsp::OpaqueAreaRouterInfo` body
/// shape). Those move into a generic impl when the `OspfVersion`
/// trait grows accessor methods (`fn ls_type(&Lsa) -> u16`,
/// `fn ls_id(&Lsa) -> Ipv4Addr`, etc.) — PR 7b.
pub struct Lsdb<V: OspfVersion = Ospfv2> {
    pub tables: LsTable<V>,
    pub label_map: OspfLabelMap,
    pub reach_map: ReachMap,
}

/// One LSDB entry — the parsed LSA plus the bookkeeping the LSDB
/// needs (origination flag, install/refresh timestamps, age and
/// refresh timer handles).
///
/// `data: V::Lsa` is the concrete wire-LSA type for the version
/// (e.g. `OspfLsa` for v2, `Ospfv3Lsa` for v3).
pub struct Lsa<V: OspfVersion = Ospfv2> {
    pub data: V::Lsa,
    pub originated: bool,
    pub birth_time: tokio::time::Instant,
    pub install_time: tokio::time::Instant,
    pub hold_timer: Option<Timer>,
    pub refresh_timer: Option<Timer>,
}

impl<V: OspfVersion> Lsa<V> {
    pub fn new(data: V::Lsa) -> Self {
        let now = tokio::time::Instant::now();
        Self {
            data,
            originated: false,
            birth_time: now,
            install_time: now,
            hold_timer: None,
            refresh_timer: None,
        }
    }

    /// Compute the current LSA age: original ls_age plus elapsed
    /// time since install, capped at MaxAge. Now generic — reads
    /// the header via `V::lsa_header` and `V::ls_age`, which both
    /// `Ospfv2` and `Ospfv3` impl identically (the field has the
    /// same semantics in RFC 2328 §A.4.1 and RFC 5340 §A.4.2.1).
    pub fn current_age(&self) -> u16 {
        let header = V::lsa_header(&self.data);
        let initial_age = V::ls_age(header);
        let elapsed = self.birth_time.elapsed().as_secs() as u16;
        let age = initial_age.saturating_add(elapsed);
        age.min(OSPF_MAX_AGE)
    }
}

fn lsdb_timer(
    tx: &UnboundedSender<Message>,
    area_id: Option<Ipv4Addr>,
    key: OspfLsaKey,
    secs: u64,
    ev: LsdbEvent,
) -> Timer {
    let tx = tx.clone();
    Timer::new(Duration::from_secs(secs), TimerType::Once, move || {
        let tx = tx.clone();
        let msg = Message::Lsdb(ev, area_id, key);
        async move {
            let _ = tx.send(msg);
        }
    })
}

fn hold_timer(
    tx: &UnboundedSender<Message>,
    area_id: Option<Ipv4Addr>,
    key: OspfLsaKey,
    ls_age: u16,
) -> Timer {
    let remaining = (OSPF_MAX_AGE - ls_age).max(1) as u64;
    lsdb_timer(tx, area_id, key, remaining, LsdbEvent::HoldTimerExpire)
}

fn refresh_timer(
    tx: &UnboundedSender<Message>,
    area_id: Option<Ipv4Addr>,
    key: OspfLsaKey,
) -> Timer {
    lsdb_timer(
        tx,
        area_id,
        key,
        OSPF_LS_REFRESH_TIME,
        LsdbEvent::RefreshTimerExpire,
    )
}

impl<V: OspfVersion> Lsdb<V> {
    pub fn new() -> Self {
        Self {
            tables: LsTable::<V>::default(),
            label_map: OspfLabelMap::default(),
            reach_map: ReachMap::default(),
        }
    }

    /// Iterate the LSAs of a particular LS-Type. Yields the
    /// historic `(ls_id, adv_router)` 2-tuple key shape so existing
    /// callsites that destructure `((ls_id, adv_router), lsa)`
    /// keep working unchanged after the storage flattening.
    pub fn iter_by_type(
        &self,
        ls_type: OspfLsType,
    ) -> impl Iterator<Item = ((Ipv4Addr, Ipv4Addr), &Lsa<V>)> {
        self.tables
            .iter()
            .filter(move |((t, _, _), _)| *t == ls_type)
            .map(|((_, id, adv), lsa)| ((*id, *adv), lsa))
    }

    /// Iterate just the LSA values of a particular LS-Type. Convenience
    /// over `iter_by_type` for callers that don't need the key.
    pub fn values_by_type(&self, ls_type: OspfLsType) -> impl Iterator<Item = &Lsa<V>> {
        self.tables
            .iter()
            .filter(move |((t, _, _), _)| *t == ls_type)
            .map(|(_, lsa)| lsa)
    }

    /// Drop the LSA at the given key. Key-only operation — no
    /// header field access, so trivially generic.
    pub fn remove_lsa(&mut self, ls_type: OspfLsType, ls_id: Ipv4Addr, adv_router: Ipv4Addr) {
        self.tables.remove(&(ls_type, ls_id, adv_router));
    }

    /// Flush an LSA by setting its age to MaxAge and returning a
    /// clone for re-flooding. The refresh timer is cancelled, and
    /// a new hold timer is set. Now generic — header mutation goes
    /// through `V::lsa_header_mut` + `V::set_ls_age`.
    pub fn flush_lsa(
        &mut self,
        ls_type: OspfLsType,
        ls_id: Ipv4Addr,
        adv_router: Ipv4Addr,
        tx: &UnboundedSender<Message>,
        area_id: Option<Ipv4Addr>,
    ) -> Option<V::Lsa> {
        let lsa_key: OspfLsaKey = (ls_type, ls_id, adv_router);
        if let Some(lsa) = self.tables.get_mut(&lsa_key) {
            V::set_ls_age(V::lsa_header_mut(&mut lsa.data), OSPF_MAX_AGE);
            lsa.birth_time = tokio::time::Instant::now();
            lsa.refresh_timer = None;
            lsa.hold_timer = Some(hold_timer(tx, area_id, lsa_key, OSPF_MAX_AGE));
            Some(lsa.data.clone())
        } else {
            None
        }
    }

    /// Look up an LSA's payload by key. Returns a reference into
    /// the LSDB. Now generic — no header field access.
    pub fn lookup_by_id(
        &self,
        ls_type: OspfLsType,
        ls_id: Ipv4Addr,
        adv_router: Ipv4Addr,
    ) -> Option<&V::Lsa> {
        self.tables
            .get(&(ls_type, ls_id, adv_router))
            .map(|lsa| &lsa.data)
    }

    /// Look up the full LSDB entry (including bookkeeping) by key.
    /// Now generic.
    pub fn lookup_lsa(
        &self,
        ls_type: OspfLsType,
        ls_id: Ipv4Addr,
        adv_router: Ipv4Addr,
    ) -> Option<&Lsa<V>> {
        self.tables.get(&(ls_type, ls_id, adv_router))
    }

    /// Return the install timestamp of an LSA, if present. Now
    /// generic.
    pub fn lookup_install_time(
        &self,
        ls_type: OspfLsType,
        ls_id: Ipv4Addr,
        adv_router: Ipv4Addr,
    ) -> Option<tokio::time::Instant> {
        self.lookup_lsa(ls_type, ls_id, adv_router)
            .map(|lsa| lsa.install_time)
    }
}

impl<V: OspfVersion> Default for Lsdb<V> {
    fn default() -> Self {
        Self::new()
    }
}

impl Lsdb<Ospfv2> {
    pub fn insert_self_originated(
        &mut self,
        mut ospf_lsa: OspfLsa,
        tx: &UnboundedSender<Message>,
        area_id: Option<Ipv4Addr>,
    ) {
        use OspfLsType::*;
        let ls_type = ospf_lsa.h.ls_type;
        match ls_type {
            Router | Network | Summary | SummaryAsbr | AsExternal | NssaAsExternal
            | OpaqueAreaLocal => {
                ospf_lsa.update();
                let lsa_key: OspfLsaKey = (ls_type, ospf_lsa.h.ls_id, ospf_lsa.h.adv_router);
                let mut lsa = Lsa::<Ospfv2>::new(ospf_lsa);
                lsa.originated = true;
                lsa.hold_timer = Some(hold_timer(tx, area_id, lsa_key, lsa.data.h.ls_age));
                lsa.refresh_timer = Some(refresh_timer(tx, area_id, lsa_key));
                self.tables.insert(lsa_key, lsa);
            }
            _ => {}
        }
    }

    pub fn insert_received(
        &mut self,
        ospf_lsa: OspfLsa,
        tx: &UnboundedSender<Message>,
        area_id: Option<Ipv4Addr>,
    ) {
        let ls_type = ospf_lsa.h.ls_type;
        let lsa_key: OspfLsaKey = (ls_type, ospf_lsa.h.ls_id, ospf_lsa.h.adv_router);

        self.update_lsa(&ospf_lsa);

        let mut lsa = Lsa::<Ospfv2>::new(ospf_lsa);
        lsa.hold_timer = Some(hold_timer(tx, area_id, lsa_key, lsa.data.h.ls_age));

        self.tables.insert(lsa_key, lsa);
    }

    pub fn update_lsa(&mut self, lsa: &OspfLsa) {
        if let OspfLsp::OpaqueAreaRouterInfo(ref ri) = lsa.lsp {
            if lsa.h.ls_age == OSPF_MAX_AGE {
                self.label_map.remove(&lsa.h.adv_router);
                return;
            }
            let mut global = None;
            let mut local = None;
            for tlv in &ri.tlvs {
                match tlv {
                    RouterInfoTlv::SidLabelRnage(r) => {
                        if let SidLabelTlv::Label(start) = r.sid_label {
                            global = Some(LabelBlock::new(start, r.range));
                        }
                    }
                    RouterInfoTlv::LocalBlock(lb) => {
                        if let SidLabelTlv::Label(start) = lb.sid_label {
                            local = Some(LabelBlock::new(start, lb.range));
                        }
                    }
                    _ => {}
                }
            }
            if let Some(global) = global {
                let label_config = LabelConfig { global, local };
                self.label_map.insert(lsa.h.adv_router, label_config);
            }
        }
        if let OspfLsp::OpaqueAreaExtPrefix(ref lsp) = lsa.lsp {
            for tlv in lsp.tlvs.iter() {
                self.reach_map.insert(tlv.prefix, tlv.subs.clone());
            }
        }
    }

    pub fn refresh_lsa(
        &mut self,
        ls_type: OspfLsType,
        ls_id: Ipv4Addr,
        adv_router: Ipv4Addr,
        tx: &UnboundedSender<Message>,
        area_id: Option<Ipv4Addr>,
    ) {
        let lsa_key: OspfLsaKey = (ls_type, ls_id, adv_router);
        if let Some(old_lsa) = self.tables.get(&lsa_key) {
            let mut new_data = old_lsa.data.clone();
            new_data.h.ls_seq_number += 1;
            new_data.h.ls_age = 0;
            new_data.update();
            let mut lsa = Lsa::<Ospfv2>::new(new_data);
            lsa.originated = true;
            lsa.hold_timer = Some(hold_timer(tx, area_id, lsa_key, 0));
            lsa.refresh_timer = Some(refresh_timer(tx, area_id, lsa_key));
            self.tables.insert(lsa_key, lsa);
        }
    }

    pub fn refresh_lsa_with_seq(
        &mut self,
        ls_type: OspfLsType,
        ls_id: Ipv4Addr,
        adv_router: Ipv4Addr,
        min_seq: u32,
        tx: &UnboundedSender<Message>,
        area_id: Option<Ipv4Addr>,
    ) {
        let lsa_key: OspfLsaKey = (ls_type, ls_id, adv_router);
        if let Some(old_lsa) = self.tables.get(&lsa_key) {
            let mut new_data = old_lsa.data.clone();
            let next_seq = old_lsa.data.h.ls_seq_number.max(min_seq) + 1;
            new_data.h.ls_seq_number = next_seq;
            new_data.h.ls_age = 0;
            new_data.update();
            let mut lsa = Lsa::<Ospfv2>::new(new_data);
            lsa.originated = true;
            lsa.hold_timer = Some(hold_timer(tx, area_id, lsa_key, 0));
            lsa.refresh_timer = Some(refresh_timer(tx, area_id, lsa_key));
            self.tables.insert(lsa_key, lsa);
        }
    }
}
