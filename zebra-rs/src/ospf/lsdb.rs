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

/// Per-LSA-type storage indexed by `(LS-ID, Advertising-Router)`.
///
/// Generic over `V: OspfVersion` so v3's LSDB can wrap `Ospfv3Lsa`
/// when its consumers materialize. Default `V = Ospfv2` keeps all
/// existing references resolving to the v2 shape.
pub type LsTable<V = Ospfv2> = BTreeMap<(Ipv4Addr, Ipv4Addr), Lsa<V>>;

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
/// (`tables: LsTypes<LsTable<V>>`) is generic; the methods that
/// manipulate LSAs live in `impl Lsdb<Ospfv2>` for now because they
/// destructure v2-specific header / body types
/// (`OspfLsType` enum match, `OspfLsp::OpaqueAreaRouterInfo` body
/// shape). Those move into a generic impl when the `OspfVersion`
/// trait grows accessor methods (`fn ls_type(&Lsa) -> u16`,
/// `fn ls_id(&Lsa) -> Ipv4Addr`, etc.).
pub struct Lsdb<V: OspfVersion = Ospfv2> {
    pub tables: LsTypes<LsTable<V>>,
    pub label_map: OspfLabelMap,
    pub reach_map: ReachMap,
}

#[derive(Default, Debug)]
pub struct LsTypes<T> {
    pub router: T,
    pub network: T,
    pub summary: T,
    pub summary_asbr: T,
    pub as_external: T,
    pub opaque_area: T,
    pub unknown: T,
}

impl<T> LsTypes<T> {
    pub fn get(&self, ls_type: &OspfLsType) -> &T {
        match ls_type {
            OspfLsType::Router => &self.router,
            OspfLsType::Network => &self.network,
            OspfLsType::Summary => &self.summary,
            OspfLsType::SummaryAsbr => &self.summary_asbr,
            OspfLsType::AsExternal => &self.as_external,
            OspfLsType::OpaqueAreaLocal => &self.opaque_area,
            _ => &self.unknown,
        }
    }

    pub fn get_mut(&mut self, ls_type: &OspfLsType) -> &mut T {
        match ls_type {
            OspfLsType::Router => &mut self.router,
            OspfLsType::Network => &mut self.network,
            OspfLsType::Summary => &mut self.summary,
            OspfLsType::SummaryAsbr => &mut self.summary_asbr,
            OspfLsType::AsExternal => &mut self.as_external,
            OspfLsType::OpaqueAreaLocal => &mut self.opaque_area,
            _ => &mut self.unknown,
        }
    }
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
}

impl Lsa<Ospfv2> {
    /// Compute the current LSA age: original ls_age plus elapsed
    /// time since install, capped at MaxAge. v2-specific because
    /// it reads `self.data.h.ls_age` — the v3 LsaHeader has the
    /// same field but no shared trait method yet exposes it.
    pub fn current_age(&self) -> u16 {
        let initial_age = self.data.h.ls_age;
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
            tables: LsTypes::<LsTable<V>>::default(),
            label_map: OspfLabelMap::default(),
            reach_map: ReachMap::default(),
        }
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
                let key = (ospf_lsa.h.ls_id, ospf_lsa.h.adv_router);
                let lsa_key: OspfLsaKey = (ls_type, ospf_lsa.h.ls_id, ospf_lsa.h.adv_router);
                let mut lsa = Lsa::<Ospfv2>::new(ospf_lsa);
                lsa.originated = true;
                lsa.hold_timer = Some(hold_timer(tx, area_id, lsa_key, lsa.data.h.ls_age));
                lsa.refresh_timer = Some(refresh_timer(tx, area_id, lsa_key));
                self.tables.get_mut(&ls_type).insert(key, lsa);
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
        let key = (ospf_lsa.h.ls_id, ospf_lsa.h.adv_router);
        let lsa_key: OspfLsaKey = (ls_type, ospf_lsa.h.ls_id, ospf_lsa.h.adv_router);

        self.update_lsa(&ospf_lsa);

        let mut lsa = Lsa::<Ospfv2>::new(ospf_lsa);
        lsa.hold_timer = Some(hold_timer(tx, area_id, lsa_key, lsa.data.h.ls_age));

        self.tables.get_mut(&lsa.data.h.ls_type).insert(key, lsa);
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

    pub fn remove_lsa(&mut self, ls_type: OspfLsType, ls_id: Ipv4Addr, adv_router: Ipv4Addr) {
        let table = self.tables.get_mut(&ls_type);
        table.remove(&(ls_id, adv_router));
    }

    /// Flush an LSA by setting its age to MaxAge and returning a clone for reflooding.
    /// The refresh timer is cancelled, and a new hold timer is set.
    pub fn flush_lsa(
        &mut self,
        ls_type: OspfLsType,
        ls_id: Ipv4Addr,
        adv_router: Ipv4Addr,
        tx: &UnboundedSender<Message>,
        area_id: Option<Ipv4Addr>,
    ) -> Option<OspfLsa> {
        let table = self.tables.get_mut(&ls_type);
        let key = (ls_id, adv_router);
        if let Some(lsa) = table.get_mut(&key) {
            lsa.data.h.ls_age = OSPF_MAX_AGE;
            lsa.birth_time = tokio::time::Instant::now();
            lsa.refresh_timer = None;
            let lsa_key: OspfLsaKey = (ls_type, ls_id, adv_router);
            lsa.hold_timer = Some(hold_timer(tx, area_id, lsa_key, OSPF_MAX_AGE));
            Some(lsa.data.clone())
        } else {
            None
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
        let table = self.tables.get_mut(&ls_type);
        let key = (ls_id, adv_router);
        if let Some(old_lsa) = table.get(&key) {
            let mut new_data = old_lsa.data.clone();
            new_data.h.ls_seq_number += 1;
            new_data.h.ls_age = 0;
            new_data.update();
            let lsa_key: OspfLsaKey = (ls_type, ls_id, adv_router);
            let mut lsa = Lsa::<Ospfv2>::new(new_data);
            lsa.originated = true;
            lsa.hold_timer = Some(hold_timer(tx, area_id, lsa_key, 0));
            lsa.refresh_timer = Some(refresh_timer(tx, area_id, lsa_key));
            table.insert(key, lsa);
        }
    }

    pub fn lookup_by_id(
        &self,
        ls_type: OspfLsType,
        ls_id: Ipv4Addr,
        adv_router: Ipv4Addr,
    ) -> Option<&OspfLsa> {
        let table = self.tables.get(&ls_type);
        table.get(&(ls_id, adv_router)).map(|lsa| &lsa.data)
    }

    pub fn lookup_lsa(
        &self,
        ls_type: OspfLsType,
        ls_id: Ipv4Addr,
        adv_router: Ipv4Addr,
    ) -> Option<&Lsa> {
        let table = self.tables.get(&ls_type);
        table.get(&(ls_id, adv_router))
    }

    pub fn lookup_install_time(
        &self,
        ls_type: OspfLsType,
        ls_id: Ipv4Addr,
        adv_router: Ipv4Addr,
    ) -> Option<tokio::time::Instant> {
        self.lookup_lsa(ls_type, ls_id, adv_router)
            .map(|lsa| lsa.install_time)
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
        let table = self.tables.get_mut(&ls_type);
        let key = (ls_id, adv_router);
        if let Some(old_lsa) = table.get(&key) {
            let mut new_data = old_lsa.data.clone();
            let next_seq = old_lsa.data.h.ls_seq_number.max(min_seq) + 1;
            new_data.h.ls_seq_number = next_seq;
            new_data.h.ls_age = 0;
            new_data.update();
            let lsa_key: OspfLsaKey = (ls_type, ls_id, adv_router);
            let mut lsa = Lsa::<Ospfv2>::new(new_data);
            lsa.originated = true;
            lsa.hold_timer = Some(hold_timer(tx, area_id, lsa_key, 0));
            lsa.refresh_timer = Some(refresh_timer(tx, area_id, lsa_key));
            table.insert(key, lsa);
        }
    }
}
