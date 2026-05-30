//! Central dynamic MPLS label-block manager.
//!
//! Owns the dynamic label pool — the band above the SR-MPLS ranges
//! (SRGB default 16000..23999, SRLB 15000..15099, configured in
//! [`crate::rib::segment_routing::block`]) — and hands out reserved
//! blocks to protocols that need dynamically-allocated labels (BGP
//! L3VPN per-VRF labels today; LDP and others later). A block is
//! reserved until released; a released block is reused for a later
//! request of the same size before the high-water mark advances.
//! Per-protocol bookkeeping lets `proto_cleanup` reclaim every block a
//! disabled/crashed protocol held.
//!
//! Keeping BGP/LDP dynamic labels in a band clear of the SR ranges
//! avoids cross-protocol label collisions in the kernel MPLS table —
//! something the previous per-VRF allocator (which counted up from 16)
//! could violate at scale.

use std::collections::BTreeMap;

use crate::spf::label_block::LabelBlock;

/// First label of the dynamic pool. Chosen well above the SR-MPLS
/// default ranges so dynamic (BGP/LDP) labels never collide with
/// prefix-/adjacency-SIDs. Operators configuring custom SR blocks must
/// keep them below this floor.
pub const DYNAMIC_START: u32 = 100_000;

/// One past the last usable 20-bit MPLS label (labels are 20 bits, so
/// `0..=0x000F_FFFF`; this exclusive end is `0x000F_FFFF + 1`).
pub const DYNAMIC_END: u32 = 0x0010_0000;

/// Hands out non-overlapping label blocks from the dynamic pool.
#[derive(Debug)]
pub struct LabelManager {
    /// High-water mark — the next never-allocated label.
    next: u32,
    /// Released blocks, available for exact-size reuse before `next`
    /// advances.
    free: Vec<LabelBlock>,
    /// Outstanding blocks per requesting protocol, for bulk release on
    /// `proto_cleanup`.
    by_proto: BTreeMap<String, Vec<LabelBlock>>,
}

impl Default for LabelManager {
    fn default() -> Self {
        Self::new()
    }
}

impl LabelManager {
    pub fn new() -> Self {
        Self {
            next: DYNAMIC_START,
            free: Vec::new(),
            by_proto: BTreeMap::new(),
        }
    }

    /// Reserve a block of `size` labels for `proto`. A freed block of
    /// the same size is reused before fresh space is carved off the
    /// high-water mark. Returns `None` for a zero size or when the
    /// dynamic pool is exhausted.
    pub fn alloc(&mut self, proto: &str, size: u32) -> Option<LabelBlock> {
        if size == 0 {
            return None;
        }
        let block = if let Some(pos) = self.free.iter().position(|b| b.end - b.start == size) {
            self.free.swap_remove(pos)
        } else {
            if self.next.checked_add(size)? > DYNAMIC_END {
                return None;
            }
            let block = LabelBlock {
                start: self.next,
                end: self.next + size,
            };
            self.next += size;
            block
        };
        self.by_proto
            .entry(proto.to_string())
            .or_default()
            .push(block.clone());
        Some(block)
    }

    /// Release one block previously handed to `proto`. A no-op if the
    /// block isn't one we gave that protocol.
    pub fn release(&mut self, proto: &str, start: u32, size: u32) {
        let block = LabelBlock {
            start,
            end: start + size,
        };
        if let Some(blocks) = self.by_proto.get_mut(proto) {
            if let Some(pos) = blocks.iter().position(|b| *b == block) {
                blocks.swap_remove(pos);
                self.free.push(block);
            }
            if blocks.is_empty() {
                self.by_proto.remove(proto);
            }
        }
    }

    /// Release every block held by `proto` (the protocol was torn
    /// down). The blocks return to the free list for reuse.
    pub fn release_all(&mut self, proto: &str) {
        if let Some(blocks) = self.by_proto.remove(proto) {
            self.free.extend(blocks);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocs_carve_from_the_dynamic_pool_above_sr() {
        let mut m = LabelManager::new();
        let a = m.alloc("bgp", 1024).unwrap();
        assert_eq!(a.start, DYNAMIC_START);
        assert_eq!(a.end, DYNAMIC_START + 1024);
        // Second block starts where the first ended — no overlap.
        let b = m.alloc("bgp", 16).unwrap();
        assert_eq!(b.start, DYNAMIC_START + 1024);
        // Whole pool sits clear of the SR default ceiling (SRGB 23999).
        assert!(a.start > 23999);
    }

    #[test]
    fn release_makes_a_same_size_block_reusable() {
        let mut m = LabelManager::new();
        let a = m.alloc("bgp", 256).unwrap();
        let b = m.alloc("bgp", 256).unwrap();
        assert_ne!(a.start, b.start);
        m.release("bgp", a.start, 256);
        // A new 256-block reuses the freed one rather than bumping the
        // high-water mark.
        let c = m.alloc("bgp", 256).unwrap();
        assert_eq!(c.start, a.start);
        // A different size doesn't match the freed block.
        let d = m.alloc("bgp", 128).unwrap();
        assert_eq!(d.start, b.end);
    }

    #[test]
    fn release_all_reclaims_every_block_of_a_proto() {
        let mut m = LabelManager::new();
        let a = m.alloc("bgp", 100).unwrap();
        let _b = m.alloc("bgp", 100).unwrap();
        m.alloc("ldp", 100).unwrap();
        m.release_all("bgp");
        // Both bgp blocks are now free; the next two 100-allocs reuse
        // them (lowest-by-swap order aside, they come from `free`).
        let c = m.alloc("isis", 100).unwrap();
        let e = m.alloc("isis", 100).unwrap();
        assert!([c.start, e.start].contains(&a.start));
        // ldp's block was untouched by bgp's release_all.
        m.release_all("ldp");
    }

    #[test]
    fn zero_size_and_exhaustion_return_none() {
        let mut m = LabelManager::new();
        assert!(m.alloc("bgp", 0).is_none());
        // A request larger than the whole pool fails.
        assert!(m.alloc("bgp", DYNAMIC_END).is_none());
    }
}
