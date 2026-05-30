//! Per-VRF MPLS label allocator.
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
//! `BgpGlobalMsg::Export`. The ILM Decap install consumes the
//! same label to bind the netlink AF_MPLS route.
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
/// One contiguous dynamic block the RIB label manager handed BGP.
#[derive(Debug)]
struct Block {
    /// Inclusive lower bound.
    start: u32,
    /// Next never-allocated label in this block.
    next: u32,
    /// Exclusive upper bound.
    end: u32,
}

#[derive(Debug)]
pub struct VrfLabelAllocator {
    /// The dynamic blocks this allocator draws from, in grant order.
    /// More are appended via [`Self::extend`] when BGP outgrows the
    /// first block (an on-demand request to the RIB label manager).
    blocks: Vec<Block>,
    /// Released labels, sorted so the lowest-numbered ones come
    /// out first — predictable for tests and operator readability.
    free: BTreeSet<u32>,
}

impl VrfLabelAllocator {
    /// Allocator seeded with the half-open block `[start, end)` — the
    /// first dynamic block the RIB label manager reserved for BGP.
    pub fn bounded(start: u32, end: u32) -> Self {
        Self {
            blocks: vec![Block {
                start,
                next: start,
                end,
            }],
            free: BTreeSet::new(),
        }
    }

    /// Append another granted block `[start, end)` (on-demand
    /// extension when the existing blocks are spent).
    pub fn extend(&mut self, start: u32, end: u32) {
        self.blocks.push(Block {
            start,
            next: start,
            end,
        });
    }

    /// Unbounded over the whole usable label space — kept for tests
    /// and as a fallback; the running BGP instance uses [`Self::bounded`]
    /// with the RIB-allocated block.
    pub fn new() -> Self {
        Self::bounded(FIRST_USABLE_LABEL, LAST_USABLE_LABEL + 1)
    }

    /// Hand out the next available label, preferring reclaimed ones,
    /// then the first block with room. `None` when every block is spent.
    pub fn alloc(&mut self) -> Option<u32> {
        if let Some(reused) = self.free.pop_first() {
            return Some(reused);
        }
        for block in self.blocks.iter_mut() {
            if block.next < block.end {
                let label = block.next;
                block.next += 1;
                return Some(label);
            }
        }
        None
    }

    /// Return `label` to the pool. Idempotent. Labels outside every
    /// block are rejected — they were never ours.
    pub fn free(&mut self, label: u32) {
        if self
            .blocks
            .iter()
            .any(|b| (b.start..b.end).contains(&label))
        {
            self.free.insert(label);
        }
    }

    /// Reclaim and return every fully-unused block (one whose carved
    /// labels are all freed), so BGP can return them to the RIB label
    /// manager when its VRF count shrinks. Always keeps at least one
    /// block so the allocator stays usable without an immediate
    /// re-request. Returned `(start, end)` pairs are half-open.
    pub fn reclaim_free_blocks(&mut self) -> Vec<(u32, u32)> {
        let mut reclaimed = Vec::new();
        let mut i = 0;
        while i < self.blocks.len() {
            // Keep at least one block — don't churn down to empty.
            if self.blocks.len() <= 1 {
                break;
            }
            let (start, next, end) = {
                let b = &self.blocks[i];
                (b.start, b.next, b.end)
            };
            // Fully unused iff every carved label is freed (an
            // untouched block has an empty carved range → true).
            if (start..next).all(|l| self.free.contains(&l)) {
                self.blocks.remove(i);
                // The released labels are no longer ours.
                self.free.retain(|&l| !(start..end).contains(&l));
                reclaimed.push((start, end));
            } else {
                i += 1;
            }
        }
        reclaimed
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

    #[test]
    fn bounded_allocator_stays_within_its_block() {
        // [100, 103) — three labels.
        let mut a = VrfLabelAllocator::bounded(100, 103);
        assert_eq!(a.alloc(), Some(100));
        assert_eq!(a.alloc(), Some(101));
        assert_eq!(a.alloc(), Some(102));
        assert_eq!(a.alloc(), None, "block exhausted");
        a.free(101);
        assert_eq!(a.alloc(), Some(101), "freed label reused");
        // A label outside the block was never ours — rejected.
        a.free(200);
        assert_eq!(a.alloc(), None);
    }

    #[test]
    fn extend_appends_a_second_block() {
        let mut a = VrfLabelAllocator::bounded(100, 102); // [100, 102)
        assert_eq!(a.alloc(), Some(100));
        assert_eq!(a.alloc(), Some(101));
        assert_eq!(a.alloc(), None, "first block spent");
        // On-demand extension with a fresh, disjoint block.
        a.extend(500, 502); // [500, 502)
        assert_eq!(a.alloc(), Some(500), "allocs from the new block");
        assert_eq!(a.alloc(), Some(501));
        assert_eq!(a.alloc(), None);
        // Free works across both blocks; lowest freed comes out first.
        a.free(100);
        a.free(501);
        assert_eq!(a.alloc(), Some(100));
        assert_eq!(a.alloc(), Some(501));
    }

    #[test]
    fn reclaim_returns_fully_free_extra_blocks() {
        let mut a = VrfLabelAllocator::bounded(100, 102); // [100, 102)
        a.extend(500, 502); // [500, 502)
        let l0 = a.alloc().unwrap(); // 100 (block 0)
        let _l1 = a.alloc().unwrap(); // 101 (block 0 now spent, in use)
        let l2 = a.alloc().unwrap(); // 500 (block 1)

        // Both blocks have in-use labels → nothing to reclaim.
        assert!(a.reclaim_free_blocks().is_empty());

        // Free block 1's only carved label → block 1 is fully free and
        // gets reclaimed (block 0 still in use, kept).
        a.free(l2);
        assert_eq!(a.reclaim_free_blocks(), vec![(500, 502)]);
        // The released labels are no longer allocatable.
        assert_eq!(a.alloc(), None);

        // Freeing block 0's labels leaves it fully free, but it's the
        // only block left → kept (no churn), and its labels stay reusable.
        a.free(l0);
        a.free(101);
        assert!(a.reclaim_free_blocks().is_empty());
        assert_eq!(a.alloc(), Some(100));
    }
}
