use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// The node's local labels in use: the Adjacency-SID (and IS-IS Mirror
/// Context) labels every protocol instance holds. The node has one MPLS
/// label table, which forwards a label one way only, and instances
/// allocating from overlapping SRLBs on their own (OSPFv2, OSPFv3 and
/// IS-IS all start at 15000) handed out the same label for different
/// adjacencies. Each instance draws from this shared set through its
/// [`LocalLabelPool`].
#[derive(Clone, Debug, Default)]
pub struct LocalLabels(Arc<Mutex<BTreeSet<u32>>>);

impl LocalLabels {
    /// An instance's pool over its SRLB, the inclusive range
    /// `[begin, end]`.
    pub fn pool(&self, begin: u32, end: u32) -> LocalLabelPool {
        LocalLabelPool {
            used: self.clone(),
            begin,
            end,
            held: BTreeSet::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, BTreeSet<u32>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// One instance's Adjacency-SID labels, drawn from the node's
/// [`LocalLabels`]: the lowest label of its range that no instance
/// holds. What it holds goes back when it is dropped, as the instance
/// stops or disables SR-MPLS.
#[derive(Debug)]
pub struct LocalLabelPool {
    used: LocalLabels,
    begin: u32,
    end: u32,
    held: BTreeSet<u32>,
}

impl LocalLabelPool {
    /// The pool's labels, `(first, last)`.
    pub fn range(&self) -> (u32, u32) {
        (self.begin, self.end)
    }

    pub fn allocate(&mut self) -> Option<u32> {
        let mut used = self.used.lock();
        let label = (self.begin..=self.end).find(|label| !used.contains(label))?;
        used.insert(label);
        self.held.insert(label);
        Some(label)
    }

    /// Give back `label`, if this pool holds it.
    pub fn release(&mut self, label: u32) {
        if self.held.remove(&label) {
            self.used.lock().remove(&label);
        }
    }
}

impl Drop for LocalLabelPool {
    fn drop(&mut self) {
        let mut used = self.used.lock();
        for label in &self.held {
            used.remove(label);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two instances over the same SRLB never hold the same label, and
    /// what one gives back, or holds when dropped, the other can take.
    #[test]
    fn instances_share_the_nodes_local_labels() {
        let node = LocalLabels::default();
        let mut v2 = node.pool(15000, 15999);
        let mut v3 = node.pool(15000, 15999);
        assert_eq!(v2.allocate(), Some(15000));
        assert_eq!(v3.allocate(), Some(15001));
        assert_eq!(v2.allocate(), Some(15002));
        v3.release(15000); // not v3's: a no-op
        assert_eq!(v3.allocate(), Some(15003));
        v2.release(15000);
        assert_eq!(v3.allocate(), Some(15000));
        drop(v2);
        assert_eq!(v3.allocate(), Some(15002));
    }

    /// A pool allocates only within its own range, and none once the
    /// range is taken.
    #[test]
    fn a_pool_stays_in_its_range() {
        let node = LocalLabels::default();
        let mut wide = node.pool(15000, 15001);
        let mut narrow = node.pool(15001, 15001);
        assert_eq!(narrow.allocate(), Some(15001));
        assert_eq!(wide.allocate(), Some(15000));
        assert_eq!(wide.allocate(), None);
        assert_eq!(narrow.allocate(), None);
    }
}
