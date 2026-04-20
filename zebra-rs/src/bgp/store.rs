// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2025-2026 Kunihiro Ishiguro

use std::collections::HashMap;
use std::sync::{Arc, Weak};

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

    pub fn intern(&mut self, attr: BgpAttr) -> Arc<BgpAttr> {
        if let Some(weak) = self.store.get(&attr)
            && let Some(rc) = weak.upgrade()
        {
            return rc;
        }
        let rc = Arc::new(attr.clone());
        self.store.insert(attr, Arc::downgrade(&rc));
        rc
    }

    pub fn len(&self) -> usize {
        self.store.len()
    }

    pub fn refcnt_all(&self) -> usize {
        self.store.values().filter(|w| w.strong_count() > 0).count()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&BgpAttr, &Weak<BgpAttr>)> {
        self.store.iter()
    }
}
