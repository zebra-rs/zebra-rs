use std::{
    collections::{
        btree_map::{Iter, Values},
        BTreeMap,
    },
    default,
};

use isis_packet::{IsisLsp, IsisLspId};

use crate::isis::Message;

use super::{
    inst::{lsp_emit, lsp_flood, IsisTop},
    task::Timer,
    Level,
};

#[derive(Default)]
pub struct Lsdb {
    map: BTreeMap<IsisLspId, Lsa>,
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
}

impl Lsa {
    pub fn new(lsp: IsisLsp) -> Self {
        Self {
            lsp,
            originated: false,
            from: None,
            hold_timer: None,
            refresh_timer: None,
        }
    }
}

impl Lsdb {
    pub fn get(&self, key: &IsisLspId) -> Option<&Lsa> {
        self.map.get(key)
    }

    pub fn insert(&mut self, key: IsisLspId, value: IsisLsp) -> Option<Lsa> {
        let lsa = Lsa::new(value);
        self.map.insert(key, lsa)
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

pub fn lsp_fan_out(top: &mut IsisTop, _level: Level, _lsp: &IsisLsp) {
    for _link in top.links.iter() {
        // link.fan_out(level, lsp);
    }
}

fn refresh_timer(top: &mut IsisTop, level: Level, key: IsisLspId) -> Timer {
    let tx = top.tx.clone();
    Timer::once(3, move || {
        let tx = tx.clone();
        async move {
            use LsdbEvent::*;
            let msg = Message::Lsdb(RefreshTimerExpire, level, key.clone());
            tx.send(msg).unwrap();
        }
    })
}

fn hold_timer(top: &mut IsisTop, level: Level, key: IsisLspId, hold_time: u64) -> Timer {
    let tx = top.tx.clone();
    Timer::once(hold_time, move || {
        let tx = tx.clone();
        async move {
            use LsdbEvent::*;
            let msg = Message::Lsdb(HoldTimerExpire, level, key.clone());
            tx.send(msg).unwrap();
        }
    })
}

pub fn lsp_self_originate(_top: &mut IsisTop, _level: Level) {
    // LSP generate for the level.

    // Fanout.
    // lsp_fan_out(top)

    // Insert LSP.
    //insert_self_originate(top, level, key, lsp);
}

pub fn lsp_self_originate_stop(_top: &mut IsisTop, _level: Level) {
    // LSP generate for the level.

    // Fanout.
    // lsp_fan_out(top)

    // Insert LSP.
    //insert_self_originate(top, level, key, lsp);
}

fn update_pseudo() {
    //
}

fn update_lsp(top: &mut IsisTop, level: Level, key: IsisLspId, lsp: &IsisLsp) {
    if let Some(tlv) = lsp.hostname_tlv() {
        top.hostname
            .get_mut(&level)
            .insert(key.sys_id(), tlv.hostname.clone());
    } else {
        top.hostname.get_mut(&level).remove(&key.sys_id());
    }
}

pub fn insert_lsp(top: &mut IsisTop, level: Level, key: IsisLspId, lsp: IsisLsp) -> Option<Lsa> {
    if top.config.net.sys_id() == key.sys_id() {
        println!("Self originated LSP?");
        return None;
    }

    if key.is_pseudo() {
        update_pseudo();
    } else {
        update_lsp(top, level, key, &lsp);
    }
    let hold_time = lsp.hold_time as u64;
    let mut lsa = Lsa::new(lsp);
    lsa.hold_timer = Some(hold_timer(top, level, key, hold_time));
    top.lsdb.get_mut(&level).map.insert(key, lsa)
}

pub fn insert_self_originate(top: &mut IsisTop, level: Level, lsp: IsisLsp) -> Option<Lsa> {
    let key = lsp.lsp_id.clone();
    let mut lsa = Lsa::new(lsp);
    lsa.originated = true;
    lsa.refresh_timer = Some(refresh_timer(top, level, key));
    lsa.hold_timer = Some(hold_timer(top, level, key, 1200));
    top.lsdb.get_mut(&level).map.insert(key, lsa)
}

pub fn remove_lsp(top: &mut IsisTop, level: Level, key: IsisLspId) {
    if let Some(lsa) = top.lsdb.get_mut(&level).remove(&key) {
        if let Some(tlv) = lsa.lsp.hostname_tlv() {
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
        lsp_flood(top, level, &buf);
        insert_self_originate(top, level, lsp);
    }
}
