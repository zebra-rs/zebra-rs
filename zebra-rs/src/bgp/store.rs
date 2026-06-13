use std::collections::HashMap;
use std::sync::{Arc, Weak};

use bgp_packet::BgpAttr;

/// The interning store hashes the whole `BgpAttr` (AS_PATH, communities,
/// …) on every received update — a profile of an 8×500k convergence put
/// the default SipHash at ~24% of daemon CPU. `BgpAttr` keys are
/// internal dedup keys, not attacker-chosen hash-table indices, so a
/// fast non-cryptographic hasher (ahash) is the right trade here.
type AttrHasher = ahash::RandomState;

#[derive(Debug)]
pub struct BgpAttrStore {
    store: HashMap<BgpAttr, Weak<BgpAttr>, AttrHasher>,
}

impl Default for BgpAttrStore {
    fn default() -> Self {
        Self::new()
    }
}

impl BgpAttrStore {
    pub fn new() -> Self {
        Self {
            store: HashMap::with_hasher(AttrHasher::default()),
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
