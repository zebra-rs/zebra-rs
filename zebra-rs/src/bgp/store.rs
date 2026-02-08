use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};

use bgp_packet::BgpAttr;

#[derive(Debug)]
pub struct BgpAttrStore {
    store: Mutex<HashMap<BgpAttr, Weak<BgpAttr>>>,
}

impl Default for BgpAttrStore {
    fn default() -> Self {
        Self::new()
    }
}

impl BgpAttrStore {
    pub fn new() -> Self {
        Self {
            store: Mutex::new(HashMap::new()),
        }
    }

    pub fn intern(&self, attr: BgpAttr) -> Arc<BgpAttr> {
        let mut store = self.store.lock().unwrap();
        if let Some(weak) = store.get(&attr)
            && let Some(arc) = weak.upgrade()
        {
            return arc;
        }
        let arc = Arc::new(attr.clone());
        store.insert(attr, Arc::downgrade(&arc));
        arc
    }

    pub fn gc(&self) {
        self.store
            .lock()
            .unwrap()
            .retain(|_, weak| weak.strong_count() > 0);
    }

    pub fn len(&self) -> usize {
        self.store.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.store.lock().unwrap().is_empty()
    }

    pub fn refcnt(&self, attr: &BgpAttr) -> usize {
        self.store
            .lock()
            .unwrap()
            .get(attr)
            .map(Weak::strong_count)
            .unwrap_or(0)
    }

    pub fn live_count_all(&self) -> usize {
        self.store
            .lock()
            .unwrap()
            .values()
            .filter(|w| w.strong_count() > 0)
            .count()
    }
}
