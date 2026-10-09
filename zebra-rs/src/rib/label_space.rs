//! The node's dynamic MPLS label space, as the RIB hands it out.
//!
//! Phase 1 of `docs/design/mpls-label-allocation.md`: label blocks for
//! protocols that allocate their own labels (BGP's per-VRF, per-EVI, ESI,
//! VPWS and transit labels today) come from the dynamic region, which
//! starts at 24000 like IOS XR's and never overlaps a configured SR block.
//! Below 24000 sit the IANA-reserved labels (0..=15), static bindings, and
//! the default SRLB (15000..) and SRGB (16000..23999).
//!
//! Blocks are owned by the requesting protocol's name, as before; ownership
//! by subscription is a later phase.

use std::collections::BTreeMap;
use std::ops::Range;

use crate::spf::label_block::LabelBlock;

/// Labels the kernel accepts are `0..PLATFORM_LABELS`.
/// `net.mpls.platform_labels` is capped at 2^20 - 1 (`label_limit` in
/// net/mpls/af_mpls.c) and an ILM's label must be below it, so 1048575, the
/// last 20-bit label, can never be installed. `fib/netlink/sysctl.rs` sets the
/// sysctl to this value.
pub const PLATFORM_LABELS: u32 = (1 << 20) - 1;

/// First dynamic label, IOS XR's default: above the default SRGB
/// (16000..23999), so the SR blocks stay clear even before SR is enabled.
pub const DYNAMIC_START: u32 = 24000;

/// A block handed to a protocol.
#[derive(Debug, Clone, PartialEq)]
struct Held {
    end: u32,
    proto: String,
}

/// Hands out non-overlapping label blocks from the dynamic region, stepping
/// around every configured SR block.
#[derive(Debug)]
pub struct LabelSpace {
    /// Labels blocks are handed out from.
    dynamic: Range<u32>,
    /// Handed-out blocks, keyed by start label.
    held: BTreeMap<u32, Held>,
    /// SRGB and SRLB of every configured `segment-routing block`. Never
    /// handed out, even where they fall inside the dynamic region.
    reserved: Vec<LabelBlock>,
}

impl Default for LabelSpace {
    fn default() -> Self {
        Self::new()
    }
}

impl LabelSpace {
    pub fn new() -> Self {
        Self {
            dynamic: DYNAMIC_START..PLATFORM_LABELS,
            held: BTreeMap::new(),
            reserved: Vec::new(),
        }
    }

    /// Reserve a block of `size` labels for `proto`: the lowest stretch of
    /// the dynamic region that is neither handed out nor inside an SR
    /// block. Returns `None` for a zero size or when no stretch is large
    /// enough.
    pub fn alloc(&mut self, proto: &str, size: u32) -> Option<LabelBlock> {
        if size == 0 {
            return None;
        }
        let mut taken: Vec<(u32, u32)> = self
            .held
            .iter()
            .map(|(start, h)| (*start, h.end))
            .chain(self.reserved.iter().map(|b| (b.start, b.end)))
            .collect();
        taken.sort_unstable();
        let mut start = self.dynamic.start;
        for (s, e) in taken {
            if e <= start {
                continue;
            }
            if start.checked_add(size)? <= s {
                break;
            }
            start = e;
        }
        let end = start.checked_add(size)?;
        if end > self.dynamic.end {
            return None;
        }
        self.held.insert(
            start,
            Held {
                end,
                proto: proto.to_string(),
            },
        );
        Some(LabelBlock { start, end })
    }

    /// Release one block previously handed to `proto`. A no-op unless
    /// `[start, start+size)` is exactly such a block.
    pub fn release(&mut self, proto: &str, start: u32, size: u32) {
        if let Some(h) = self.held.get(&start)
            && h.proto == proto
            && Some(h.end) == start.checked_add(size)
        {
            self.held.remove(&start);
        }
    }

    /// Release every block held by `proto` (the protocol was torn down).
    pub fn release_all(&mut self, proto: &str) {
        self.held.retain(|_, h| h.proto != proto);
    }

    /// Replace the reserved SR blocks. Returns the handed-out blocks a new
    /// reservation overlaps, with their owners: they stay in use until
    /// released, and the caller says so.
    pub fn set_reserved(
        &mut self,
        blocks: impl IntoIterator<Item = LabelBlock>,
    ) -> Vec<(LabelBlock, String)> {
        self.reserved = blocks.into_iter().filter(|b| b.start < b.end).collect();
        self.held
            .iter()
            .filter(|(start, h)| {
                self.reserved
                    .iter()
                    .any(|r| r.start < h.end && **start < r.end)
            })
            .map(|(start, h)| {
                (
                    LabelBlock {
                        start: *start,
                        end: h.end,
                    },
                    h.proto.clone(),
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(start: u32, end: u32) -> LabelBlock {
        LabelBlock { start, end }
    }

    #[test]
    fn blocks_start_at_24000_and_do_not_overlap() {
        let mut s = LabelSpace::new();
        assert_eq!(s.alloc("bgp", 1024), Some(block(24000, 25024)));
        assert_eq!(s.alloc("bgp", 16), Some(block(25024, 25040)));
    }

    #[test]
    fn a_released_block_is_reused_lowest_first() {
        let mut s = LabelSpace::new();
        let a = s.alloc("bgp", 256).unwrap();
        let b = s.alloc("bgp", 256).unwrap();
        s.release("bgp", a.start, 256);
        // A smaller block fits in the hole a left, below b.
        assert_eq!(s.alloc("bgp", 128), Some(block(a.start, a.start + 128)));
        // A larger one does not fit there and goes above b.
        assert_eq!(s.alloc("bgp", 512), Some(block(b.end, b.end + 512)));
    }

    #[test]
    fn release_needs_the_owner_and_the_exact_block() {
        let mut s = LabelSpace::new();
        let a = s.alloc("bgp", 256).unwrap();
        s.release("ldp", a.start, 256);
        s.release("bgp", a.start, 128);
        // Still held, so the next block goes above it.
        assert_eq!(s.alloc("bgp", 256), Some(block(a.end, a.end + 256)));
    }

    #[test]
    fn release_all_frees_only_that_protocols_blocks() {
        let mut s = LabelSpace::new();
        s.alloc("bgp", 100).unwrap();
        let ldp = s.alloc("ldp", 100).unwrap();
        s.alloc("bgp", 100).unwrap();
        s.release_all("bgp");
        assert_eq!(s.alloc("isis", 100), Some(block(24000, 24100)));
        assert_eq!(s.alloc("isis", 100), Some(block(ldp.end, ldp.end + 100)));
    }

    #[test]
    fn a_configured_sr_block_in_the_dynamic_region_is_skipped() {
        let mut s = LabelSpace::new();
        // An SRGB moved up into the dynamic region, plus the default
        // blocks below it, which the region never reaches.
        s.set_reserved([
            block(16000, 24000),
            block(15000, 15100),
            block(24500, 25500),
        ]);
        assert_eq!(s.alloc("bgp", 400), Some(block(24000, 24400)));
        // 24400..25424 would cross the SRGB.
        assert_eq!(s.alloc("bgp", 1024), Some(block(25500, 26524)));
        // The 100-label gap below the SRGB is still usable.
        assert_eq!(s.alloc("bgp", 100), Some(block(24400, 24500)));
    }

    #[test]
    fn a_reservation_over_a_handed_out_block_is_reported() {
        let mut s = LabelSpace::new();
        let a = s.alloc("bgp", 1024).unwrap();
        let overlaps = s.set_reserved([block(24500, 25500)]);
        assert_eq!(overlaps, vec![(a.clone(), "bgp".to_string())]);
        // Clearing the reservation reports nothing.
        assert!(s.set_reserved([]).is_empty());
    }

    #[test]
    fn the_kernels_last_label_is_never_handed_out() {
        let mut s = LabelSpace::new();
        let whole = PLATFORM_LABELS - DYNAMIC_START;
        assert_eq!(s.alloc("bgp", whole + 1), None);
        let all = s.alloc("bgp", whole).unwrap();
        assert_eq!(all.end, PLATFORM_LABELS);
        assert_eq!(all.end - 1, 1_048_574);
        assert_eq!(s.alloc("bgp", 1), None);
    }

    #[test]
    fn zero_and_overflowing_sizes_are_refused() {
        let mut s = LabelSpace::new();
        assert_eq!(s.alloc("bgp", 0), None);
        assert_eq!(s.alloc("bgp", u32::MAX), None);
    }

    /// Retained review probe: compare mixed allocation, release and SR
    /// reservation changes with a label-by-label oracle. Reservations can
    /// overlap, nest, cross the dynamic bounds or cover existing grants.
    #[test]
    fn review_probe_mixed_operations_match_label_by_label_oracle() {
        for seed in 0..32_u64 {
            let mut rng = seed + 1;
            let mut next = || {
                rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
                (rng >> 32) as u32
            };
            let mut s = LabelSpace::new();
            s.dynamic = 24000..24064;
            let mut grants: Vec<(&str, LabelBlock)> = Vec::new();
            let mut reserved: Vec<LabelBlock> = Vec::new();
            for step in 0..300 {
                let owner = if next() % 2 == 0 { "bgp" } else { "ldp" };
                match next() % 4 {
                    0 => {
                        reserved = (0..next() % 6)
                            .map(|_| {
                                let start = 23990 + next() % 84;
                                block(start, start + next() % 30)
                            })
                            .collect();
                        let mut expected: Vec<_> = grants
                            .iter()
                            .filter(|(_, b)| {
                                (b.start..b.end).any(|label| {
                                    reserved.iter().any(|r| (r.start..r.end).contains(&label))
                                })
                            })
                            .map(|(p, b)| (b.clone(), p.to_string()))
                            .collect();
                        expected.sort_by_key(|(b, _)| b.start);
                        assert_eq!(s.set_reserved(reserved.clone()), expected);
                    }
                    1 if !grants.is_empty() => {
                        let i = next() as usize % grants.len();
                        let (p, b) = &grants[i];
                        s.release(owner, b.start, b.end - b.start);
                        if *p == owner {
                            grants.remove(i);
                        }
                    }
                    2 => {
                        s.release_all(owner);
                        grants.retain(|(p, _)| *p != owner);
                    }
                    _ => {
                        let size = next() % 18;
                        let expected = (24000..24064)
                            .find(|&start| {
                                size > 0
                                    && start + size <= 24064
                                    && (start..start + size).all(|label| {
                                        !grants
                                            .iter()
                                            .any(|(_, b)| (b.start..b.end).contains(&label))
                                            && !reserved
                                                .iter()
                                                .any(|r| (r.start..r.end).contains(&label))
                                    })
                            })
                            .map(|start| block(start, start + size));
                        let actual = s.alloc(owner, size);
                        assert_eq!(actual, expected, "seed {seed}, step {step}");
                        if let Some(b) = actual {
                            grants.push((owner, b));
                        }
                    }
                }
            }
        }
    }
}
