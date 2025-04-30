use std::collections::{
    btree_map::{Iter, Values},
    BTreeMap,
};

use isis_packet::{IsisLsp, IsisLspId};

use super::{
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
    pub fn insert(&mut self, key: IsisLspId, value: IsisLsp) -> Option<Lsa> {
        let mut lsa = Lsa::new(value);

        self.map.insert(key, lsa)
    }

    pub fn insert_self_originate(
        &mut self,
        key: IsisLspId,
        value: IsisLsp,
        level: Level,
        refresh_timer: u64,
    ) -> Option<Lsa> {
        let mut lsa = Lsa::new(value);
        let refresh_timer = Timer::new(
            Timer::second(refresh_timer),
            TimerType::Once,
            || async move {
                println!("Refresh timer expire");
            },
        );
        lsa.refresh_timer = Some(refresh_timer);
        self.map.insert(key, lsa)
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
