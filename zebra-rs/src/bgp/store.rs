use std::collections::HashMap;
use std::rc::{Rc, Weak};

use bgp_packet::BgpAttr;

#[derive(Debug)]
pub struct BgpAttrStore {
    store: HashMap<BgpAttr, Weak<BgpAttr>>,
}

impl Default for BgpAttrStore {
    fn default() -> Self {
        Self::new()
    }
}

impl BgpAttrStore {
    pub fn new() -> Self {
        Self {
            store: HashMap::new(),
        }
    }

    pub fn intern(&mut self, attr: BgpAttr) -> Rc<BgpAttr> {
        if let Some(weak) = self.store.get(&attr)
            && let Some(rc) = weak.upgrade()
        {
            return rc;
        }
        let rc = Rc::new(attr.clone());
        self.store.insert(attr, Rc::downgrade(&rc));
        rc
    }

    pub fn gc(&mut self) {
        self.store.retain(|_, weak| weak.strong_count() > 0);
    }

    pub fn len(&self) -> usize {
        self.store.len()
    }

    pub fn is_empty(&self) -> bool {
        self.store.is_empty()
    }

    pub fn refcnt(&self, attr: &BgpAttr) -> usize {
        self.store.get(attr).map(Weak::strong_count).unwrap_or(0)
    }

    pub fn refcnt_all(&self) -> usize {
        self.store.values().filter(|w| w.strong_count() > 0).count()
    }
}
