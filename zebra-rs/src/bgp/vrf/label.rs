//! Per-VRF MPLS label allocator (step 19a of the BGP MPLS/VPN
//! refactor).
//!
//! Hands out a single label per VRF at spawn time and reclaims it
//! at despawn. The pool is a counter starting at 16 (the first
//! non-reserved MPLS label per RFC 3032 §2.1) plus a free-list of
//! reclaimed labels so cycling VRFs in / out doesn't burn through
//! the 20-bit label space.
//!
//! The allocator lives on `Bgp` (one per global instance — labels
//! are a global resource), and the allocated value is mirrored
//! onto `BgpVrf::label` for the per-VRF runtime to stamp onto
//! `BgpGlobalMsg::Export`. Step 19b's ILM Decap install consumes
//! the same label to bind the netlink AF_MPLS route.
//!
//! Today the pool is unconstrained — there's no operator-visible
//! reservation YANG. A future PR can layer that on by injecting a
//! `(min, max)` range at `Bgp::new` and treating `min` as the
//! initial counter.

use std::collections::BTreeSet;

/// First non-reserved MPLS label per RFC 3032 §2.1. Labels 0..=15
/// are reserved (IPv4 / IPv6 Explicit Null, Implicit Null,
/// Router Alert, OAM Alert, Entropy Label Indicator, etc.).
pub const FIRST_USABLE_LABEL: u32 = 16;

/// Maximum valid MPLS label per RFC 3032 — labels are 20 bits.
pub const LAST_USABLE_LABEL: u32 = 0x000F_FFFF;

/// Counter-based allocator that hands out one label per VRF.
/// Released labels are queued back onto `free` so churned VRFs
/// don't bleed the space.
#[derive(Debug)]
pub struct VrfLabelAllocator {
    /// Next never-allocated label. Bumped on each fresh alloc;
    /// the free list is preferred so the counter only grows when
    /// every freed label has already been re-issued.
    next: u32,
    /// Released labels, sorted so the lowest-numbered ones come
    /// out first — predictable for tests and operator readability.
    free: BTreeSet<u32>,
}

impl VrfLabelAllocator {
    pub fn new() -> Self {
        Self {
            next: FIRST_USABLE_LABEL,
            free: BTreeSet::new(),
        }
    }

    /// Hand out the next available label. Returns `None` only
    /// when the entire 20-bit space is exhausted, which would
    /// mean ~1M live VRFs — well past any deployment ceiling.
    /// Callers can `expect("label space exhausted")` if they
    /// want to assert that bound.
    pub fn alloc(&mut self) -> Option<u32> {
        if let Some(reused) = self.free.pop_first() {
            return Some(reused);
        }
        if self.next > LAST_USABLE_LABEL {
            return None;
        }
        let label = self.next;
        self.next += 1;
        Some(label)
    }

    /// Return `label` to the pool. Idempotent — double-frees are
    /// silently ignored (the second insert into `BTreeSet` is a
    /// no-op). Reserved labels (`< FIRST_USABLE_LABEL`) are
    /// rejected because they were never ours to start with.
    pub fn free(&mut self, label: u32) {
        if !(FIRST_USABLE_LABEL..=LAST_USABLE_LABEL).contains(&label) {
            return;
        }
        self.free.insert(label);
    }
}

impl Default for VrfLabelAllocator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_allocator_starts_at_first_usable_label() {
        let mut a = VrfLabelAllocator::new();
        assert_eq!(a.alloc(), Some(FIRST_USABLE_LABEL));
    }

    #[test]
    fn allocs_are_sequential_when_nothing_is_freed() {
        let mut a = VrfLabelAllocator::new();
        let l1 = a.alloc().unwrap();
        let l2 = a.alloc().unwrap();
        let l3 = a.alloc().unwrap();
        assert_eq!(l1, FIRST_USABLE_LABEL);
        assert_eq!(l2, FIRST_USABLE_LABEL + 1);
        assert_eq!(l3, FIRST_USABLE_LABEL + 2);
    }

    #[test]
    fn free_then_alloc_reuses_lowest_freed_label() {
        // Operator churns VRFs: vrf1=16, vrf2=17, vrf3=18.
        // Deleting vrf2 returns 17; the next vrf to spawn should
        // pick up 17 rather than bumping the counter to 19.
        let mut a = VrfLabelAllocator::new();
        let l1 = a.alloc().unwrap();
        let l2 = a.alloc().unwrap();
        let l3 = a.alloc().unwrap();
        assert_eq!((l1, l2, l3), (16, 17, 18));

        a.free(l2);
        a.free(l1);
        assert_eq!(a.alloc(), Some(16), "lowest freed first");
        assert_eq!(a.alloc(), Some(17));
        assert_eq!(
            a.alloc(),
            Some(19),
            "counter resumes after free pool drained"
        );
    }

    #[test]
    fn free_reserved_label_is_ignored() {
        // Caller can't poison the pool with reserved values.
        let mut a = VrfLabelAllocator::new();
        a.free(0);
        a.free(15);
        // First alloc still comes from the counter.
        assert_eq!(a.alloc(), Some(FIRST_USABLE_LABEL));
    }

    #[test]
    fn double_free_is_a_noop() {
        let mut a = VrfLabelAllocator::new();
        let l = a.alloc().unwrap();
        a.free(l);
        a.free(l);
        assert_eq!(a.alloc(), Some(l));
        // No third return; counter resumes.
        assert_eq!(a.alloc(), Some(l + 1));
    }
}
