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
//!
//! Phase 3: the IGPs' local labels, their dynamic Adjacency-SIDs and IS-IS's
//! Mirror Context labels, come from here too, one label at a time through
//! each instance's [`LocalLabelPool`] over its SRLB. The structure is shared
//! ([`SharedLabelSpace`]): the RIB hands out blocks through it, and a
//! protocol task allocates a label inline without a round trip to the RIB.
//! One structure means a block is never handed out over a label an IGP holds,
//! and the RIB sees every label in use.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::{Range, RangeInclusive};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::rib::client::{ProtoId, RibClient};
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

/// A local label's state.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Local {
    /// Held by a pool.
    Held(u64),
    /// Given back by its owner's pool; the RIB has not handled the release
    /// yet, which travels behind the owner's earlier ILM messages. No one
    /// may take it, and none of those earlier messages frees it: a
    /// withdrawal queued ahead of the release can be followed by an
    /// install that re-adds the owner's entry.
    Releasing(ProtoId),
    /// The RIB handled the release while the owner still had an ILM entry
    /// at the label: free once that entry is withdrawn. Reallocating it
    /// sooner would let the owner's withdrawal remove the next holder's
    /// entry, or its entry outrank it.
    Draining(ProtoId),
}

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
    /// Single labels of IGP instances' pools, held or on their way back.
    local: BTreeMap<u32, Local>,
    /// Owners whose pool found no free label: told when labels are freed
    /// (`take_starved`), so they can try again.
    starved: BTreeSet<ProtoId>,
    /// The next pool's id.
    next_pool: u64,
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
            local: BTreeMap::new(),
            starved: BTreeSet::new(),
            next_pool: 0,
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
            .chain(self.local.keys().map(|l| (*l, l + 1)))
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

    /// A new pool's id, for [`LocalLabelPool`].
    fn new_pool(&mut self) -> u64 {
        self.next_pool += 1;
        self.next_pool
    }

    /// The lowest label in `range` that no pool holds or is giving back
    /// and no handed-out block covers, now held by `pool`.
    fn alloc_local(
        &mut self,
        pool: u64,
        owner: Option<ProtoId>,
        range: RangeInclusive<u32>,
    ) -> Option<u32> {
        let found = range
            .into_iter()
            .find(|label| !self.local.contains_key(label) && !self.in_held_block(*label));
        let Some(label) = found else {
            // A label on its way back may be freed soon; say so then.
            if let Some(owner) = owner {
                self.starved.insert(owner);
            }
            return None;
        };
        self.local.insert(label, Local::Held(pool));
        Some(label)
    }

    /// Whether a handed-out block covers `label`.
    fn in_held_block(&self, label: u32) -> bool {
        self.held
            .range(..=label)
            .next_back()
            .is_some_and(|(_, h)| label < h.end)
    }

    /// Give back `label`, if `pool` holds it: free at once for a pool
    /// without an owner, `Releasing` for one with.
    fn release_local(&mut self, pool: u64, owner: Option<ProtoId>, label: u32) -> bool {
        if self.local.get(&label) != Some(&Local::Held(pool)) {
            return false;
        }
        match owner {
            Some(owner) => self.local.insert(label, Local::Releasing(owner)),
            None => self.local.remove(&label),
        };
        true
    }

    /// Give back every label `pool` holds, as `release_local` does. The
    /// labels given back.
    fn release_pool(&mut self, pool: u64, owner: Option<ProtoId>) -> Vec<u32> {
        let labels: Vec<u32> = self
            .local
            .iter()
            .filter(|(_, l)| **l == Local::Held(pool))
            .map(|(label, _)| *label)
            .collect();
        for label in &labels {
            self.release_local(pool, owner, *label);
        }
        labels
    }

    /// Change `pool`'s range to `[first, last]`: the labels it holds there
    /// stay, the rest are given back as `release_local` does. The labels
    /// given back.
    fn retarget_pool(
        &mut self,
        pool: u64,
        owner: Option<ProtoId>,
        first: u32,
        last: u32,
    ) -> Vec<u32> {
        let outside: Vec<u32> = self
            .local
            .iter()
            .filter(|(label, l)| **l == Local::Held(pool) && !(first..=last).contains(*label))
            .map(|(label, _)| *label)
            .collect();
        for label in &outside {
            self.release_local(pool, owner, *label);
        }
        outside
    }

    /// The RIB handled `owner`'s release of `label`, every ILM message the
    /// owner sent before it included: free if the owner has no entry at
    /// the label (`installed`), else `Draining` until it goes. Whether the
    /// label was freed.
    pub fn release_handled(&mut self, owner: ProtoId, label: u32, installed: bool) -> bool {
        if self.local.get(&label) != Some(&Local::Releasing(owner)) {
            return false;
        }
        if installed {
            self.local.insert(label, Local::Draining(owner));
            return false;
        }
        self.local.remove(&label);
        true
    }

    /// `owner`'s ILM entry at `label` was withdrawn: free if the label was
    /// `Draining`. A `Releasing` label is not: the owner may still re-add
    /// its entry before the release. Whether the label was freed.
    pub fn entry_withdrawn(&mut self, owner: ProtoId, label: u32) -> bool {
        if self.local.get(&label) != Some(&Local::Draining(owner)) {
            return false;
        }
        self.local.remove(&label);
        true
    }

    /// `owner`'s label on its way back is free, `Releasing` or `Draining`:
    /// its instance was cleaned up, its ILM entries withdrawn. Whether the
    /// label was freed.
    pub fn free_releasing(&mut self, owner: ProtoId, label: u32) -> bool {
        match self.local.get(&label) {
            Some(Local::Releasing(o) | Local::Draining(o)) if *o == owner => {
                self.local.remove(&label);
                true
            }
            _ => false,
        }
    }

    /// Every label `owners` were giving back is free: they never
    /// registered with the RIB, so they installed no ILM entry, and their
    /// releases will never be handled. Whether any was freed.
    pub fn free_releasing_of(&mut self, owners: &[ProtoId]) -> bool {
        let before = self.local.len();
        self.local.retain(
            |_, l| !matches!(l, Local::Releasing(o) | Local::Draining(o) if owners.contains(o)),
        );
        self.local.len() != before
    }

    /// The owners whose pool found no free label since the last call:
    /// labels have been freed, so they can try again.
    pub fn take_starved(&mut self) -> BTreeSet<ProtoId> {
        std::mem::take(&mut self.starved)
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

/// The label space, shared: the RIB hands out blocks through it, and every
/// IGP instance's [`LocalLabelPool`] draws single labels from it. Cloning
/// shares it.
#[derive(Clone, Debug, Default)]
pub struct SharedLabelSpace(Arc<Mutex<LabelSpace>>);

impl SharedLabelSpace {
    pub fn lock(&self) -> MutexGuard<'_, LabelSpace> {
        // A panic while holding the lock leaves the map consistent (every
        // method updates it in one step), so carry on with it.
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A pool over the inclusive range `[first, last]` with no owner: a
    /// label it gives back is free at once. For tests; instances use
    /// [`Self::pool_for`].
    #[cfg(test)]
    pub fn pool(&self, first: u32, last: u32) -> LocalLabelPool {
        self.new_pool(first, last, None)
    }

    /// An instance's pool over its SRLB, the inclusive range
    /// `[first, last]`, owned by the subscription behind `rib`. A label it
    /// gives back stays `Releasing` until the RIB has seen the instance's
    /// ILM entry at it go: the release travels on `rib`, behind the
    /// instance's earlier installs, and the RIB frees the label once it
    /// knows none is left.
    pub fn pool_for(&self, first: u32, last: u32, rib: &RibClient) -> LocalLabelPool {
        self.new_pool(first, last, Some(rib.clone()))
    }

    fn new_pool(&self, first: u32, last: u32, rib: Option<RibClient>) -> LocalLabelPool {
        let id = self.lock().new_pool();
        LocalLabelPool {
            space: self.clone(),
            id,
            first,
            last,
            rib,
        }
    }
}

/// One IGP instance's local labels (its dynamic Adjacency-SIDs, and IS-IS's
/// Mirror Context labels), drawn one at a time from the node's
/// [`SharedLabelSpace`]: the lowest label of its range that no instance
/// holds and no block covers. The node has one MPLS label table, which
/// forwards a label one way only, so no two instances may hold one label.
/// What a pool holds goes back when it is dropped, as the instance stops,
/// disables SR-MPLS, or moves to another SRLB.
#[derive(Debug)]
pub struct LocalLabelPool {
    space: SharedLabelSpace,
    id: u64,
    first: u32,
    last: u32,
    /// The owner's RIB channel, which releases travel on.
    rib: Option<RibClient>,
}

impl LocalLabelPool {
    /// The pool's labels, `(first, last)`.
    pub fn range(&self) -> (u32, u32) {
        (self.first, self.last)
    }

    pub fn allocate(&mut self) -> Option<u32> {
        let owner = self.owner();
        self.space
            .lock()
            .alloc_local(self.id, owner, self.first..=self.last)
    }

    /// Move the pool to `[first, last]`. The labels it holds there stay,
    /// so an overlapping SRLB change keeps the allocations it can; the rest
    /// are given back. The labels given back, for the caller to forget.
    pub fn retarget(&mut self, first: u32, last: u32) -> Vec<u32> {
        let owner = self.owner();
        let gone = self.space.lock().retarget_pool(self.id, owner, first, last);
        (self.first, self.last) = (first, last);
        for label in &gone {
            self.tell_rib(*label);
        }
        gone
    }

    /// Give back `label`, if this pool holds it.
    pub fn release(&mut self, label: u32) {
        let owner = self.owner();
        if self.space.lock().release_local(self.id, owner, label) {
            self.tell_rib(label);
        }
    }

    fn owner(&self) -> Option<ProtoId> {
        self.rib.as_ref().map(|rib| rib.proto_id())
    }

    /// Tell the RIB `label` was given back, behind the owner's earlier
    /// ILM installs, so it can free the label once none is left at it.
    fn tell_rib(&self, label: u32) {
        if let Some(rib) = &self.rib {
            let _ = rib.send(crate::rib::Message::LocalLabelRelease { label });
        }
    }
}

impl Drop for LocalLabelPool {
    fn drop(&mut self) {
        let owner = self.owner();
        let labels = self.space.lock().release_pool(self.id, owner);
        for label in labels {
            self.tell_rib(label);
        }
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

    /// Two instances over the same SRLB never hold the same label, and
    /// what one gives back, or holds when dropped, the other can take.
    #[test]
    fn instances_share_the_local_labels() {
        let node = SharedLabelSpace::default();
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

    /// Retargeting a pool keeps the labels still inside its new range and
    /// gives back only the others.
    #[test]
    fn retarget_keeps_labels_still_in_range() {
        let node = SharedLabelSpace::default();
        let mut pool = node.pool(15000, 15009);
        assert_eq!(pool.allocate(), Some(15000));
        assert_eq!(pool.allocate(), Some(15001));
        assert_eq!(pool.retarget(15000, 15000), vec![15001]);
        assert_eq!(pool.range(), (15000, 15000));
        let mut other = node.pool(15000, 15001);
        assert_eq!(other.allocate(), Some(15001), "15000 stays with the pool");
        assert_eq!(pool.allocate(), None);
    }

    /// A pool allocates only within its own range, and none once the
    /// range is taken.
    #[test]
    fn a_pool_stays_in_its_range() {
        let node = SharedLabelSpace::default();
        let mut wide = node.pool(15000, 15001);
        let mut narrow = node.pool(15001, 15001);
        assert_eq!(narrow.allocate(), Some(15001));
        assert_eq!(wide.allocate(), Some(15000));
        assert_eq!(wide.allocate(), None);
        assert_eq!(narrow.allocate(), None);
    }

    /// Blocks and local labels come from one structure: a block is never
    /// handed out over a label a pool holds, nor a label inside a block.
    #[test]
    fn blocks_and_local_labels_never_overlap() {
        let node = SharedLabelSpace::default();
        // A pool over part of the dynamic region (an SRLB configured there
        // and not yet reserved, say).
        let mut pool = node.pool(24000, 24009);
        assert_eq!(pool.allocate(), Some(24000));
        assert_eq!(node.lock().alloc("bgp", 16), Some(block(24001, 24017)));
        // The pool steps over the block.
        assert_eq!(pool.allocate(), None, "24001..24009 lie in bgp's block");
        node.lock().release_all("bgp");
        assert_eq!(pool.allocate(), Some(24001));
    }
}
