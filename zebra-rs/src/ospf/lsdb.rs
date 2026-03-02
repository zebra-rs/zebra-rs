use std::time::Duration;
use std::{collections::BTreeMap, net::Ipv4Addr};

use ospf_packet::*;
use tokio::sync::mpsc::UnboundedSender;

use super::inst::Message;
use super::task::{Timer, TimerType};

pub const OSPF_MAX_AGE: u16 = 3600;
pub const OSPF_MAX_AGE_DIFF: u16 = 900; // 15 minutes (RFC 2328 Section 13.1)
pub const OSPF_LS_REFRESH_TIME: u64 = 1800;
pub const OSPF_MAX_LSA_SEQ: u32 = 0x7FFFFFFF;

pub type LsTable = BTreeMap<(Ipv4Addr, Ipv4Addr), Lsa>;
pub type OspfLsaKey = (OspfLsType, Ipv4Addr, Ipv4Addr);

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum LsdbEvent {
    RefreshTimerExpire,
    HoldTimerExpire,
    SelfOriginatedReceived,
}

pub struct Lsdb {
    pub tables: LsTypes<LsTable>,
}

#[derive(Default, Debug)]
pub struct LsTypes<T> {
    pub router: T,
    pub network: T,
    pub summary: T,
    pub summary_asbr: T,
    pub as_external: T,
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
            _ => &mut self.unknown,
        }
    }
}

pub struct Lsa {
    pub data: OspfLsa,
    pub originated: bool,
    pub birth_time: tokio::time::Instant,
    pub hold_timer: Option<Timer>,
    pub refresh_timer: Option<Timer>,
}

impl Lsa {
    pub fn new(ospf_lsa: OspfLsa) -> Self {
        Self {
            data: ospf_lsa,
            originated: false,
            birth_time: tokio::time::Instant::now(),
            hold_timer: None,
            refresh_timer: None,
        }
    }

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
            tx.send(msg);
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

impl Lsdb {
    pub fn new() -> Self {
        Self {
            tables: LsTypes::<LsTable>::default(),
        }
    }

    pub fn insert_self_originated(
        &mut self,
        mut ospf_lsa: OspfLsa,
        tx: &UnboundedSender<Message>,
        area_id: Option<Ipv4Addr>,
    ) {
        use OspfLsType::*;
        let ls_type = ospf_lsa.h.ls_type;
        let key = (ospf_lsa.h.ls_id, ospf_lsa.h.adv_router);
        let lsa_key: OspfLsaKey = (ls_type, ospf_lsa.h.ls_id, ospf_lsa.h.adv_router);
        match ls_type {
            Router => {
                ospf_lsa.update();
                let mut lsa = Lsa::new(ospf_lsa);
                lsa.originated = true;
                lsa.hold_timer = Some(hold_timer(tx, area_id, lsa_key, lsa.data.h.ls_age));
                lsa.refresh_timer = Some(refresh_timer(tx, area_id, lsa_key));
                self.tables.get_mut(&Router).insert(key, lsa);
            }
            Network | Summary | SummaryAsbr | AsExternal | NssaAsExternal => {
                let mut lsa = Lsa::new(ospf_lsa);
                lsa.originated = true;
                lsa.hold_timer = Some(hold_timer(tx, area_id, lsa_key, lsa.data.h.ls_age));
                lsa.refresh_timer = Some(refresh_timer(tx, area_id, lsa_key));
                self.tables.get_mut(&lsa.data.h.ls_type).insert(key, lsa);
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
        let mut lsa = Lsa::new(ospf_lsa);
        lsa.hold_timer = Some(hold_timer(tx, area_id, lsa_key, lsa.data.h.ls_age));
        self.tables.get_mut(&lsa.data.h.ls_type).insert(key, lsa);
    }

    pub fn remove_lsa(&mut self, ls_type: OspfLsType, ls_id: Ipv4Addr, adv_router: Ipv4Addr) {
        let table = self.tables.get_mut(&ls_type);
        table.remove(&(ls_id, adv_router));
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
            let mut lsa = Lsa::new(new_data);
            lsa.originated = true;
            lsa.hold_timer = Some(hold_timer(tx, area_id, lsa_key, 0));
            lsa.refresh_timer = Some(refresh_timer(tx, area_id, lsa_key));
            table.insert(key, lsa);
        }
    }

    pub fn is_empty(&self) -> bool {
        false
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
            let mut lsa = Lsa::new(new_data);
            lsa.originated = true;
            lsa.hold_timer = Some(hold_timer(tx, area_id, lsa_key, 0));
            lsa.refresh_timer = Some(refresh_timer(tx, area_id, lsa_key));
            table.insert(key, lsa);
        }
    }
}
