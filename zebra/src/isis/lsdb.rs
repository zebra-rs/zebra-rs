use std::collections::{
    btree_map::{Iter, Values},
    BTreeMap,
};

use isis_packet::{IsisLsp, IsisLspId};

use crate::isis::Message;

use super::{
    inst::IsisTop,
    task::{Timer, TimerType},
    Level,
};

#[derive(Default)]
pub struct Lsdb {
    map: BTreeMap<IsisLspId, Lsa>,
}

pub struct Lsa {
    pub lsp: IsisLsp,
    pub hold_timer: Option<Timer>,
    pub refresh_timer: Option<Timer>,
}

impl Lsa {
    pub fn new(lsp: IsisLsp) -> Self {
        Self {
            lsp,
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
        let mut lsa = Lsa::new(value);

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

pub fn lsp_fan_out(top: &mut IsisTop, level: Level, lsp: &IsisLsp) {
    for link in top.links.iter() {
        // link.fan_out(level, lsp);
    }
}

pub fn refresh_lsp(top: &mut IsisTop, level: Level, key: IsisLspId) {
    if let Some(lsa) = top.lsdb.get(&level).get(&key) {
        let lsp = lsa.lsp.clone_with_seqno_inc();
        lsp_fan_out(top, level, &lsp);
        insert_self_originate(top, level, key, lsp);
    }
}

pub fn refresh_timer(top: &mut IsisTop, level: Level, key: &IsisLspId) -> Timer {
    let tx = top.tx.clone();
    let key = key.clone();
    Timer::once(top.config.refresh_time(), move || {
        let tx = tx.clone();
        let key = key.clone();
        async move {
            let msg = Message::Refresh(level, key.clone());
            tx.send(msg).unwrap();
        }
    })
}

pub fn hold_timer(top: &mut IsisTop, level: Level, key: &IsisLspId, hold_time: u64) -> Timer {
    let tx = top.tx.clone();
    let key = key.clone();
    Timer::once(hold_time, move || {
        let tx = tx.clone();
        let key = key.clone();
        async move {
            let msg = Message::HoldTimeExpire(level, key.clone());
            tx.send(msg).unwrap();
        }
    })
}

pub fn lsp_self_originate(top: &mut IsisTop, level: Level) {
    // LSP generate for the level.

    // Fanout.
    // lsp_fan_out(top)

    // Insert LSP.
    //insert_self_originate(top, level, key, lsp);
}

pub fn insert_self_originate(
    top: &mut IsisTop,
    level: Level,
    key: IsisLspId,
    lsp: IsisLsp,
) -> Option<Lsa> {
    let mut lsa = Lsa::new(lsp);
    lsa.refresh_timer = Some(refresh_timer(top, level, &key));
    top.lsdb.get_mut(&level).map.insert(key, lsa)
}

pub fn insert_lsp(top: &mut IsisTop, level: Level, key: IsisLspId, lsp: IsisLsp) -> Option<Lsa> {
    let hold_time = lsp.hold_time as u64;
    let mut lsa = Lsa::new(lsp);
    lsa.hold_timer = Some(hold_timer(top, level, &key, hold_time));
    top.lsdb.get_mut(&level).map.insert(key, lsa)
}
