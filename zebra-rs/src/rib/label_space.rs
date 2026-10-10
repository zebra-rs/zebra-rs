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
//!
//! Phase 3b: a configured local SID (an absolute Adjacency-SID) claims its
//! label through its instance's pool, and takes precedence over a dynamic
//! holder (§5.1). A free label is the claimant's at once; one another
//! instance holds dynamically, or that is on its way back, is the
//! claimant's once freed: its holder is told to let it go
//! ([`LabelSpace::take_revoked`]), and the claimant is told when it has it
//! ([`LabelSpace::take_granted`]). One another configured SID holds is
//! refused.

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
    /// Claimed by a pool for a configured SID.
    Claimed(u64),
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
    /// The owner of each pool that has one.
    pools: BTreeMap<u64, ProtoId>,
    /// Claims waiting for their label to be freed, by the claiming pool.
    claims: BTreeMap<u32, u64>,
    /// Holders to tell to let a claimed label go (`take_revoked`).
    revoked: Vec<(ProtoId, u32)>,
    /// Claimants to tell they have their label (`take_granted`).
    granted: Vec<(ProtoId, u32)>,
    /// The next pool's id.
    next_pool: u64,
}

/// The outcome of a pool's claim on a label for a configured SID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Claim {
    /// The claimant has the label. If one of its own dynamic SIDs had it,
    /// that one needs another label.
    Granted,
    /// Another instance holds the label dynamically, or it is on its way
    /// back: the claimant gets it once it is freed.
    Pending,
    /// Another configured SID has the label, or a handed-out block covers
    /// it.
    Refused,
    /// The label is outside the pool's range, the SRLB: not claimed.
    Outside,
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
            pools: BTreeMap::new(),
            claims: BTreeMap::new(),
            revoked: Vec::new(),
            granted: Vec::new(),
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
    fn new_pool(&mut self, owner: Option<ProtoId>) -> u64 {
        self.next_pool += 1;
        if let Some(owner) = owner {
            self.pools.insert(self.next_pool, owner);
        }
        self.next_pool
    }

    /// `label` is no one's any more: a claim waiting for it gets it, else
    /// it is free.
    fn free(&mut self, label: u32) {
        match self.claims.remove(&label) {
            Some(pool) => {
                self.local.insert(label, Local::Claimed(pool));
                if let Some(owner) = self.pools.get(&pool) {
                    self.granted.push((*owner, label));
                }
            }
            None => {
                self.local.remove(&label);
            }
        }
    }

    /// `pool` claims `label`, in its `range`, for a configured SID.
    fn claim_local(&mut self, pool: u64, range: RangeInclusive<u32>, label: u32) -> Claim {
        if !range.contains(&label) {
            return Claim::Outside;
        }
        if self.claims.get(&label).is_some_and(|p| *p != pool) {
            return Claim::Refused;
        }
        match self.local.get(&label).copied() {
            None if self.in_held_block(label) => Claim::Refused,
            None => {
                self.local.insert(label, Local::Claimed(pool));
                Claim::Granted
            }
            Some(Local::Claimed(p)) if p == pool => Claim::Granted,
            Some(Local::Claimed(_)) => Claim::Refused,
            // The claimant's own dynamic SID: it relabels that one.
            Some(Local::Held(p)) if p == pool => {
                self.local.insert(label, Local::Claimed(pool));
                Claim::Granted
            }
            Some(Local::Held(p)) => {
                if self.claims.insert(label, pool).is_none()
                    && let Some(holder) = self.pools.get(&p)
                {
                    self.revoked.push((*holder, label));
                }
                Claim::Pending
            }
            Some(Local::Releasing(_) | Local::Draining(_)) => {
                self.claims.insert(label, pool);
                Claim::Pending
            }
        }
    }

    /// `pool` drops its claim on `label`: a waiting claim is withdrawn; a
    /// held one goes back as `release_local` does. Whether the RIB must be
    /// told of the release.
    fn unclaim_local(&mut self, pool: u64, owner: Option<ProtoId>, label: u32) -> bool {
        if self.claims.get(&label) == Some(&pool) {
            self.claims.remove(&label);
            return false;
        }
        if self.local.get(&label) != Some(&Local::Claimed(pool)) {
            return false;
        }
        match owner {
            Some(owner) => {
                self.local.insert(label, Local::Releasing(owner));
                true
            }
            None => {
                self.free(label);
                false
            }
        }
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
            Some(owner) => {
                self.local.insert(label, Local::Releasing(owner));
            }
            None => self.free(label),
        }
        true
    }

    /// Give back every label `pool` holds or has claimed, as
    /// `release_local` does, and withdraw its waiting claims; the pool is
    /// gone. The labels given back.
    fn release_pool(&mut self, pool: u64, owner: Option<ProtoId>) -> Vec<u32> {
        let held: Vec<u32> = self
            .local
            .iter()
            .filter(|(_, l)| **l == Local::Held(pool))
            .map(|(label, _)| *label)
            .collect();
        let claimed: Vec<u32> = self
            .local
            .iter()
            .filter(|(_, l)| **l == Local::Claimed(pool))
            .map(|(label, _)| *label)
            .collect();
        self.claims.retain(|_, p| *p != pool);
        for label in &held {
            self.release_local(pool, owner, *label);
        }
        let mut told = held;
        for label in claimed {
            if self.unclaim_local(pool, owner, label) {
                told.push(label);
            }
        }
        self.pools.remove(&pool);
        told
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
        // A configured SID's label left outside goes back too; the instance
        // finds it outside on its next claim.
        let claimed: Vec<u32> = self
            .local
            .iter()
            .filter(|(label, l)| **l == Local::Claimed(pool) && !(first..=last).contains(*label))
            .map(|(label, _)| *label)
            .collect();
        let waiting: Vec<u32> = self
            .claims
            .iter()
            .filter(|(label, p)| **p == pool && !(first..=last).contains(*label))
            .map(|(label, _)| *label)
            .collect();
        for label in waiting {
            self.claims.remove(&label);
        }
        let mut told = outside;
        for label in claimed {
            if self.unclaim_local(pool, owner, label) {
                told.push(label);
            }
        }
        told
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
        self.free(label);
        true
    }

    /// `owner`'s ILM entry at `label` was withdrawn: free if the label was
    /// `Draining`. A `Releasing` label is not: the owner may still re-add
    /// its entry before the release. Whether the label was freed.
    pub fn entry_withdrawn(&mut self, owner: ProtoId, label: u32) -> bool {
        if self.local.get(&label) != Some(&Local::Draining(owner)) {
            return false;
        }
        self.free(label);
        true
    }

    /// `owner`'s label on its way back is free, `Releasing` or `Draining`:
    /// its instance was cleaned up, its ILM entries withdrawn. Whether the
    /// label was freed.
    pub fn free_releasing(&mut self, owner: ProtoId, label: u32) -> bool {
        match self.local.get(&label) {
            Some(Local::Releasing(o) | Local::Draining(o)) if *o == owner => {
                self.free(label);
                true
            }
            _ => false,
        }
    }

    /// Every label `owners` were giving back is free: they never
    /// registered with the RIB, so they installed no ILM entry, and their
    /// releases will never be handled. Whether any was freed.
    pub fn free_releasing_of(&mut self, owners: &[ProtoId]) -> bool {
        let labels: Vec<u32> = self
            .local
            .iter()
            .filter(|(_, l)| {
                matches!(l, Local::Releasing(o) | Local::Draining(o) if owners.contains(o))
            })
            .map(|(label, _)| *label)
            .collect();
        for label in &labels {
            self.free(*label);
        }
        !labels.is_empty()
    }

    /// The owners whose pool found no free label since the last call:
    /// labels have been freed, so they can try again.
    pub fn take_starved(&mut self) -> BTreeSet<ProtoId> {
        std::mem::take(&mut self.starved)
    }

    /// Holders to tell to let a label go: a configured SID claimed it.
    pub fn take_revoked(&mut self) -> Vec<(ProtoId, u32)> {
        std::mem::take(&mut self.revoked)
    }

    /// Claimants to tell they now have the label they claimed.
    pub fn take_granted(&mut self) -> Vec<(ProtoId, u32)> {
        std::mem::take(&mut self.granted)
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
        let id = self.lock().new_pool(rib.as_ref().map(|rib| rib.proto_id()));
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

    /// Claim `label` for a configured SID, with precedence over dynamic
    /// holders. A `Pending` claim asks the RIB to tell the holder; the
    /// instance learns it has the label from `RibRx::LabelGranted`.
    pub fn claim(&mut self, label: u32) -> Claim {
        let claim = self
            .space
            .lock()
            .claim_local(self.id, self.first..=self.last, label);
        if claim == Claim::Pending
            && let Some(rib) = &self.rib
        {
            let _ = rib.send(crate::rib::Message::LocalLabelClaimed);
        }
        claim
    }

    /// Whether this pool has `label` for a configured SID now. A
    /// `RibRx::LabelGranted` can be stale (the claim it answered was
    /// dropped, and a new one is waiting again), so the instance checks.
    pub fn holds_claim(&self, label: u32) -> bool {
        self.space.lock().local.get(&label) == Some(&Local::Claimed(self.id))
    }

    /// Drop the claim on `label`: a held one goes back as `release` does,
    /// a waiting one is withdrawn.
    pub fn unclaim(&mut self, label: u32) {
        let owner = self.owner();
        if self.space.lock().unclaim_local(self.id, owner, label) {
            self.tell_rib(label);
        }
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

#[cfg(test)]
mod claim_tests {
    use tokio::sync::mpsc;

    use super::*;
    use crate::rib::client::RibInbound;

    /// An instance's pool over 15000..=15009, with the RIB messages it
    /// sends.
    fn instance(
        space: &SharedLabelSpace,
        id: u32,
    ) -> (LocalLabelPool, mpsc::UnboundedReceiver<RibInbound>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let rib = RibClient::new(tx, ProtoId::from_raw(id));
        (space.pool_for(15000, 15009, &rib), rx)
    }

    /// The local-label messages sent so far.
    fn sent(rx: &mut mpsc::UnboundedReceiver<RibInbound>) -> Vec<&'static str> {
        std::iter::from_fn(|| rx.try_recv().ok())
            .filter_map(|env| match env.msg {
                crate::rib::Message::LocalLabelRelease { .. } => Some("release"),
                crate::rib::Message::LocalLabelClaimed => Some("claimed"),
                _ => None,
            })
            .collect()
    }

    /// A free label is the claimant's at once, and no dynamic allocation
    /// takes it.
    #[test]
    fn a_free_label_is_granted() {
        let space = SharedLabelSpace::default();
        let (mut a, _rx) = instance(&space, 1);
        assert_eq!(a.claim(15000), Claim::Granted);
        assert_eq!(a.claim(15000), Claim::Granted, "claiming again is harmless");
        assert_eq!(a.allocate(), Some(15001));
    }

    /// A label outside the SRLB is not claimed.
    #[test]
    fn a_label_outside_the_srlb_is_not_claimed() {
        let space = SharedLabelSpace::default();
        let (mut a, _rx) = instance(&space, 1);
        assert_eq!(a.claim(16000), Claim::Outside);
    }

    /// Two configured SIDs cannot share a label: the first keeps it.
    #[test]
    fn a_label_another_configured_sid_holds_is_refused() {
        let space = SharedLabelSpace::default();
        let (mut a, _ra) = instance(&space, 1);
        let (mut b, _rb) = instance(&space, 2);
        assert_eq!(a.claim(15000), Claim::Granted);
        assert_eq!(b.claim(15000), Claim::Refused);
    }

    /// The claimant's own dynamic SID gives way at once; the instance
    /// relabels it.
    #[test]
    fn the_claimants_own_dynamic_label_is_granted_at_once() {
        let space = SharedLabelSpace::default();
        let (mut a, mut rx) = instance(&space, 1);
        assert_eq!(a.allocate(), Some(15000));
        assert_eq!(a.claim(15000), Claim::Granted);
        assert_eq!(sent(&mut rx), Vec::<&str>::new(), "nothing to tell anyone");
        assert_eq!(a.allocate(), Some(15001));
    }

    /// Another instance's dynamic label: its holder is told to let it go,
    /// and once the RIB has seen the holder's entry go the claimant has it.
    #[test]
    fn another_instances_dynamic_label_moves_to_the_claimant() {
        let space = SharedLabelSpace::default();
        let (mut holder, mut holder_rx) = instance(&space, 1);
        let (mut claimant, mut claimant_rx) = instance(&space, 2);
        assert_eq!(holder.allocate(), Some(15000));

        assert_eq!(claimant.claim(15000), Claim::Pending);
        assert_eq!(sent(&mut claimant_rx), vec!["claimed"]);
        assert_eq!(
            space.lock().take_revoked(),
            vec![(ProtoId::from_raw(1), 15000)]
        );
        assert_eq!(holder.allocate(), Some(15001), "15000 is not handed out");

        // The holder lets it go; its entry is still installed when the RIB
        // handles the release, and goes after.
        holder.release(15000);
        assert_eq!(sent(&mut holder_rx), vec!["release"]);
        assert!(
            !space
                .lock()
                .release_handled(ProtoId::from_raw(1), 15000, true)
        );
        assert!(
            space.lock().take_granted().is_empty(),
            "the entry is still there"
        );
        assert!(space.lock().entry_withdrawn(ProtoId::from_raw(1), 15000));
        assert_eq!(
            space.lock().take_granted(),
            vec![(ProtoId::from_raw(2), 15000)]
        );
        assert_eq!(claimant.claim(15000), Claim::Granted);
        assert_eq!(holder.allocate(), Some(15002));
    }

    /// A label on its way back goes to the claimant, not back to the pool.
    #[test]
    fn a_label_on_its_way_back_goes_to_the_claimant() {
        let space = SharedLabelSpace::default();
        let (mut holder, _hrx) = instance(&space, 1);
        let (mut claimant, _crx) = instance(&space, 2);
        assert_eq!(holder.allocate(), Some(15000));
        holder.release(15000);
        assert_eq!(claimant.claim(15000), Claim::Pending);
        assert!(space.lock().take_revoked().is_empty(), "already let go");
        assert!(
            space
                .lock()
                .release_handled(ProtoId::from_raw(1), 15000, false)
        );
        assert_eq!(
            space.lock().take_granted(),
            vec![(ProtoId::from_raw(2), 15000)]
        );
    }

    /// Dropping a waiting claim: the label is freed, not granted.
    #[test]
    fn a_withdrawn_claim_is_not_granted() {
        let space = SharedLabelSpace::default();
        let (mut holder, _hrx) = instance(&space, 1);
        let (mut claimant, _crx) = instance(&space, 2);
        assert_eq!(holder.allocate(), Some(15000));
        assert_eq!(claimant.claim(15000), Claim::Pending);
        claimant.unclaim(15000);
        holder.release(15000);
        space
            .lock()
            .release_handled(ProtoId::from_raw(1), 15000, false);
        assert!(space.lock().take_granted().is_empty());
        assert_eq!(claimant.allocate(), Some(15000));
    }

    /// A configured SID's label goes back like a dynamic one: through the
    /// RIB, once its entry is gone.
    #[test]
    fn an_unclaimed_label_goes_back_through_the_rib() {
        let space = SharedLabelSpace::default();
        let (mut a, mut rx) = instance(&space, 1);
        let (mut b, _rb) = instance(&space, 2);
        assert_eq!(a.claim(15000), Claim::Granted);
        a.unclaim(15000);
        assert_eq!(sent(&mut rx), vec!["release"]);
        assert_eq!(b.allocate(), Some(15001), "15000 is on its way back");
        space
            .lock()
            .release_handled(ProtoId::from_raw(1), 15000, false);
        assert_eq!(b.allocate(), Some(15000));
    }

    /// A pool that goes gives back what it claimed and withdraws what it
    /// waits for.
    #[test]
    fn a_dropped_pool_gives_back_its_claims() {
        let space = SharedLabelSpace::default();
        let (mut holder, _hrx) = instance(&space, 1);
        let (mut claimant, mut rx) = instance(&space, 2);
        assert_eq!(claimant.claim(15005), Claim::Granted);
        assert_eq!(holder.allocate(), Some(15000));
        assert_eq!(claimant.claim(15000), Claim::Pending);
        let _ = sent(&mut rx);
        drop(claimant);
        assert_eq!(sent(&mut rx), vec!["release"], "15005 goes back");
        holder.release(15000);
        space
            .lock()
            .release_handled(ProtoId::from_raw(1), 15000, false);
        assert!(
            space.lock().take_granted().is_empty(),
            "nobody waits for it"
        );
    }

    /// An SRLB change that leaves a claimed label outside gives it back.
    #[test]
    fn a_retarget_gives_back_a_claim_left_outside() {
        let space = SharedLabelSpace::default();
        let (mut a, _rx) = instance(&space, 1);
        assert_eq!(a.claim(15009), Claim::Granted);
        assert_eq!(a.retarget(15000, 15004), vec![15009]);
        assert_eq!(a.claim(15009), Claim::Outside);
    }
}
