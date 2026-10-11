//! Shard-owned BGP state (RIB sharding plan B.1, first slice).
//!
//! [`BgpShard`] holds exactly the state a future shard task will own
//! end-to-end: the Loc-RIB tables that partition by prefix hash. Per
//! the plan's D3 ruling (`docs/design/bgp-rib-sharding-plan.md` §8),
//! that scope is v4/v6 unicast, v4/v6 labeled-unicast, and VPNv4/v6 —
//! EVPN, flowspec, SR-Policy, BGP-LS, RTC, and table-map stay
//! main-owned in [`super::route::LocalRib`] (small tables; EVPN MAC
//! routes don't even hash by IP prefix).
//!
//! Today `BgpShard` is a plain field on `Bgp` / `BgpVrf`, mutated
//! inline by the single event loop — no behavior change. Phase B.3
//! gives the shard its own task.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::Arc;

use bgp_packet::RouteDistinguisher;
use ipnet::{Ipv4Net, Ipv6Net};

use bgp_packet::{Afi, BgpAttr, Safi};

use super::adj_rib::ShardAdjIn;
use super::label_chunks::LabelChunks;
use super::route::{BgpRib, LocalRibTable};
use super::store::BgpAttrStore;
use crate::spf::label_block::LabelBlock;

pub mod msg;
pub use msg::{ShardMsg, ShardOut};

pub mod dispatch;
pub mod pool;

/// A shard's local MPLS label allocator for the families that mint a
/// per-route *local* label in the hot path: Labeled-Unicast (v4/v6,
/// next-hop-self) and the Inter-AS Option B VPNv4/v6 transit case.
/// Labels come from chunks of the RIB's label space
/// ([`LabelChunks`], docs/design/mpls-label-allocation.md §5.2), taken
/// synchronously, so a shard mints without asking the main task. An
/// allocator with no label space (pool workers, per-VRF shards) mints
/// nothing.
#[derive(Debug, Default)]
pub struct ShardLabelPool {
    /// Chunks of the label space, and the labels handed out in them.
    pool: LabelChunks,
    /// Per-prefix IPv4 / IPv6 Labeled-Unicast local labels
    /// (allocate-on-first-use, freed on withdraw).
    lu_v4: BTreeMap<Ipv4Net, u32>,
    lu_v6: BTreeMap<Ipv6Net, u32>,
    /// Per-`(RD, prefix)` VPNv4 transit local labels (Inter-AS
    /// Option B): the swap ILM forwards `our label → received label`.
    vpn_v4: BTreeMap<(RouteDistinguisher, Ipv4Net), u32>,
    /// [`Self::vpn_v4`] for VPNv6 (review finding #8: the VPNv6 transit
    /// advertised the received label behind its own next-hop).
    vpn_v6: BTreeMap<(RouteDistinguisher, Ipv6Net), u32>,
}

impl ShardLabelPool {
    /// A pool minting from `pool`'s chunks.
    pub fn new(pool: LabelChunks) -> Self {
        Self {
            pool,
            ..Self::default()
        }
    }

    /// The chunks whose labels are all free, for the caller to return to
    /// the RIB behind its ILM deletions for them
    /// ([`LabelChunks::take_drained`]).
    pub fn take_drained(&mut self) -> Vec<LabelBlock> {
        self.pool.take_drained()
    }

    /// The chunks held, for tests.
    #[cfg(test)]
    pub fn chunks(&self) -> Vec<LabelBlock> {
        self.pool.chunks()
    }

    /// A pool over a label space of its own whose dynamic range starts at
    /// `first`, for tests.
    #[cfg(test)]
    pub fn with_test_space(first: u32) -> Self {
        let space = crate::rib::label_space::SharedLabelSpace::default();
        space.lock().set_dynamic(first, first + 99_999);
        Self::new(LabelChunks::new(space, "bgp"))
    }

    /// Local label for an IPv4 LU prefix, allocating on first use.
    /// `None` if no label can be had (the caller advertises the received
    /// label as a fallback).
    pub fn label_lu_v4(&mut self, prefix: Ipv4Net) -> Option<u32> {
        if let Some(l) = self.lu_v4.get(&prefix) {
            return Some(*l);
        }
        let label = self.pool.alloc()?;
        self.lu_v4.insert(prefix, label);
        Some(label)
    }

    /// Local label for an IPv6 LU prefix; mirrors [`label_lu_v4`](Self::label_lu_v4).
    pub fn label_lu_v6(&mut self, prefix: Ipv6Net) -> Option<u32> {
        if let Some(l) = self.lu_v6.get(&prefix) {
            return Some(*l);
        }
        let label = self.pool.alloc()?;
        self.lu_v6.insert(prefix, label);
        Some(label)
    }

    /// Local label for a received VPNv4 `(RD, prefix)`, allocating on
    /// first use (Inter-AS Option B transit).
    pub fn label_vpn_v4(&mut self, rd: RouteDistinguisher, prefix: Ipv4Net) -> Option<u32> {
        if let Some(l) = self.vpn_v4.get(&(rd, prefix)) {
            return Some(*l);
        }
        let label = self.pool.alloc()?;
        self.vpn_v4.insert((rd, prefix), label);
        Some(label)
    }

    /// Release the label for a withdrawn IPv4 LU prefix; returns it so
    /// the caller can tear down the swap ILM.
    pub fn free_lu_v4(&mut self, prefix: Ipv4Net) -> Option<u32> {
        let label = self.lu_v4.remove(&prefix)?;
        self.pool.free(label);
        Some(label)
    }

    /// Release the label for a withdrawn IPv6 LU prefix.
    pub fn free_lu_v6(&mut self, prefix: Ipv6Net) -> Option<u32> {
        let label = self.lu_v6.remove(&prefix)?;
        self.pool.free(label);
        Some(label)
    }

    /// Release the label for a withdrawn VPNv4 `(RD, prefix)`.
    pub fn free_vpn_v4(&mut self, rd: RouteDistinguisher, prefix: Ipv4Net) -> Option<u32> {
        let label = self.vpn_v4.remove(&(rd, prefix))?;
        self.pool.free(label);
        Some(label)
    }

    pub fn label_vpn_v6(&mut self, rd: RouteDistinguisher, prefix: Ipv6Net) -> Option<u32> {
        if let Some(l) = self.vpn_v6.get(&(rd, prefix)) {
            return Some(*l);
        }
        let label = self.pool.alloc()?;
        self.vpn_v6.insert((rd, prefix), label);
        Some(label)
    }

    pub fn free_vpn_v6(&mut self, rd: RouteDistinguisher, prefix: Ipv6Net) -> Option<u32> {
        let label = self.vpn_v6.remove(&(rd, prefix))?;
        self.pool.free(label);
        Some(label)
    }
}

/// A peer's inbound policy snapshot, replicated from the main task into
/// the shard(s) via [`ShardMsg::PolicyReplace`] so the shard applies the
/// operator's real route-map / prefix-list in `compute_policy` rather
/// than default-permit. Built on the main task from the peer's resolved
/// inbound policy whenever the policy actor pushes a fresh `PolicyRx`.
#[derive(Debug, Default, Clone)]
pub struct InPolicy {
    pub prefix_set: super::policy::PrefixSetValue,
    pub policy_list: super::policy::PolicyListValue,
}

#[derive(Debug, Default)]
pub struct BgpShard {
    pub v4: LocalRibTable<Ipv4Net>,

    pub v6: LocalRibTable<Ipv6Net>,

    /// IPv4 / IPv6 Labeled-Unicast (SAFI 4) Loc-RIB. Same prefix key as
    /// unicast; each `BgpRib` carries the per-prefix label.
    pub v4lu: LocalRibTable<Ipv4Net>,

    pub v6lu: LocalRibTable<Ipv6Net>,

    pub v4vpn: BTreeMap<RouteDistinguisher, LocalRibTable<Ipv4Net>>,

    pub v6vpn: BTreeMap<RouteDistinguisher, LocalRibTable<Ipv6Net>>,

    /// Per-peer Adj-RIB-In slices for the sharded families, keyed by
    /// peer `ident` ([`super::peer::Peer`] stays main-owned). The
    /// main-only families' adj-in stays on the peer as
    /// [`super::adj_rib::MainAdjIn`].
    pub adj_in: BTreeMap<usize, ShardAdjIn>,

    /// Attribute-interning store for the sharded families' RIBs. The
    /// `Arc<BgpAttr>` held by every entry in the tables and adj-in
    /// slices above is interned here, so when the shard becomes a
    /// task (B.3) it interns its own RIB attributes without touching
    /// the main [`super::store::BgpAttrStore`]. The egress / advertise
    /// path and the main-only families (EVPN, flowspec, BGP-LS, VRF
    /// re-tag) keep using the main store; an `Arc` is valid regardless
    /// of which store interned it, so the split is purely about which
    /// store owns the dedup entry.
    pub attr_store: BgpAttrStore,

    /// Per-route local-label allocator + caches for the sharded
    /// families that mint labels in the hot path (LU v4/v6, VPNv4
    /// transit). Draws from chunks of the RIB's label space on the
    /// global instance's inline shard only; per-VRF shards and pool
    /// workers have no label space — the LU/VPN label path is
    /// global-instance-only today.
    pub labels: ShardLabelPool,
    /// Whether this instance re-advertises received VPNv4 routes with the
    /// next-hop rewritten to itself on at least one peer — eBGP without
    /// `next-hop-unchanged`, or iBGP with `next-hop-self` — i.e. it is an
    /// Inter-AS Option B transit ASBR. Only then does a received VPNv4
    /// route mint a per-`(RD, prefix)` local label and program a swap ILM
    /// (`handle_update_v4`); a route reflector that passes next-hop and
    /// label through untouched (the default iBGP case) must not touch the
    /// MPLS data plane at all. Derived by main from the peer config at
    /// `CommitEnd` (`Bgp::reconcile_transit_labels`), which also brings
    /// the rows already in the table in step when the value flips. Only
    /// the inline (N=1) shard is ever set: pool workers have no label
    /// space (`pool.rs`) and cannot mint regardless.
    pub vpn_v4_transit: bool,
    /// [`Self::vpn_v4_transit`] for VPNv6: gates the per-`(RD, prefix)`
    /// mint in `handle_update_v6` and the VPNv6 arm of
    /// `Bgp::reconcile_transit_labels` (review finding #8).
    pub vpn_v6_transit: bool,
    /// [`Self::vpn_v4_transit`] for IPv4 Labeled-Unicast (SAFI 4): true
    /// when a `label-v4` peer is sent routes with next-hop-self (eBGP
    /// always rewrites for LU; iBGP only with `next-hop-self` — the
    /// Inter-AS Option C ASBR → PE leg). Gates the per-prefix mint in
    /// `handle_update_lu` and the inline `route_labelv4_update`.
    pub lu_v4_transit: bool,
    /// [`Self::lu_v4_transit`] for IPv6 Labeled-Unicast / 6PE.
    pub lu_v6_transit: bool,

    /// Per-peer inbound policy snapshots, replicated from the main task
    /// via [`ShardMsg::PolicyReplace`]. Looked up by source `ident` in
    /// `compute_policy`; absent ⇒ default-permit. Closes the Phase C
    /// default-permit placeholder so the shard applies real inbound
    /// route-maps / prefix-lists at N>1.
    pub in_policy: BTreeMap<usize, Arc<InPolicy>>,
}

impl BgpShard {
    /// Install or clear a peer's replicated inbound policy snapshot
    /// ([`ShardMsg::PolicyReplace`]). `None` removes it (policy unset or
    /// peer gone) so the shard falls back to default-permit.
    pub fn set_in_policy(&mut self, ident: usize, policy: Option<Arc<InPolicy>>) {
        match policy {
            Some(p) => {
                self.in_policy.insert(ident, p);
            }
            None => {
                self.in_policy.remove(&ident);
            }
        }
    }
    /// Intern a sharded-family RIB attribute. Delegates to the
    /// shard's own [`BgpAttrStore`] — see the field doc for why
    /// sharded RIB storage interns here rather than in the main store.
    pub fn intern(&mut self, attr: BgpAttr) -> Arc<BgpAttr> {
        self.attr_store.intern(attr)
    }

    /// The peer's Adj-RIB-In slice, if it has ever stored a route.
    pub fn adj_in(&self, ident: usize) -> Option<&ShardAdjIn> {
        self.adj_in.get(&ident)
    }

    /// The peer's Adj-RIB-In slice, created on first use.
    pub fn adj_in_mut(&mut self, ident: usize) -> &mut ShardAdjIn {
        self.adj_in.entry(ident).or_default()
    }

    /// Drop the peer's entire Adj-RIB-In slice (peer-down sweep).
    pub fn adj_in_drop(&mut self, ident: usize) {
        self.adj_in.remove(&ident);
    }

    /// Received-prefix count for a sharded AFI/SAFI (0 for main-owned
    /// families and for peers with no slice — disjoint with
    /// [`super::adj_rib::MainAdjIn::count`], so show paths sum both).
    pub fn adj_in_count(&self, ident: usize, afi: Afi, safi: Safi) -> usize {
        self.adj_in
            .get(&ident)
            .map(|a| a.count(afi, safi))
            .unwrap_or(0)
    }

    // Update LocalRIB route.
    pub fn update(
        &mut self,
        rd: Option<RouteDistinguisher>,
        prefix: Ipv4Net,
        rib: BgpRib,
    ) -> (Vec<BgpRib>, Vec<BgpRib>, u32) {
        match rd {
            Some(rd) => self.v4vpn.entry(rd).or_default().update(prefix, rib),
            None => self.v4.update(prefix, rib),
        }
    }

    pub fn remove(
        &mut self,
        rd: Option<RouteDistinguisher>,
        prefix: Ipv4Net,
        id: u32,
        ident: usize,
    ) -> Vec<BgpRib> {
        match rd {
            Some(rd) => self.v4vpn.entry(rd).or_default().remove(prefix, id, ident),
            None => self.v4.remove(prefix, id, ident),
        }
    }

    // Return selected best path, not the change history.
    pub fn select_best_path(&mut self, prefix: Ipv4Net) -> Vec<BgpRib> {
        self.v4.select_best_path(prefix)
    }

    // Return selected best path, not the change history.
    pub fn select_best_path_vpn(
        &mut self,
        rd: &RouteDistinguisher,
        prefix: Ipv4Net,
    ) -> Vec<BgpRib> {
        self.v4vpn.entry(*rd).or_default().select_best_path(prefix)
    }

    // IPv6 unicast accessors. VPNv6 (`v6vpn`) lands with layer 2c, so
    // these take no RD — the global/default v6 unicast Loc-RIB only.
    pub fn update_v6(&mut self, prefix: Ipv6Net, rib: BgpRib) -> (Vec<BgpRib>, Vec<BgpRib>, u32) {
        self.v6.update(prefix, rib)
    }

    pub fn remove_v6(&mut self, prefix: Ipv6Net, id: u32, ident: usize) -> Vec<BgpRib> {
        self.v6.remove(prefix, id, ident)
    }

    pub fn select_best_path_v6(&mut self, prefix: Ipv6Net) -> Vec<BgpRib> {
        self.v6.select_best_path(prefix)
    }

    // IPv4 / IPv6 Labeled-Unicast (SAFI 4) accessors. Same Loc-RIB
    // engine as unicast; the per-prefix label travels on each `BgpRib`.
    pub fn update_v4lu(&mut self, prefix: Ipv4Net, rib: BgpRib) -> (Vec<BgpRib>, Vec<BgpRib>, u32) {
        self.v4lu.update(prefix, rib)
    }

    pub fn remove_v4lu(&mut self, prefix: Ipv4Net, id: u32, ident: usize) -> Vec<BgpRib> {
        self.v4lu.remove(prefix, id, ident)
    }

    pub fn select_best_path_v4lu(&mut self, prefix: Ipv4Net) -> Vec<BgpRib> {
        self.v4lu.select_best_path(prefix)
    }

    pub fn update_v6lu(&mut self, prefix: Ipv6Net, rib: BgpRib) -> (Vec<BgpRib>, Vec<BgpRib>, u32) {
        self.v6lu.update(prefix, rib)
    }

    pub fn remove_v6lu(&mut self, prefix: Ipv6Net, id: u32, ident: usize) -> Vec<BgpRib> {
        self.v6lu.remove(prefix, id, ident)
    }

    pub fn select_best_path_v6lu(&mut self, prefix: Ipv6Net) -> Vec<BgpRib> {
        self.v6lu.select_best_path(prefix)
    }

    // VPNv6 accessors — per-RD `v6vpn` tables, mirroring the v4vpn
    // ones. (Best-path-for-advertise of VPNv6 winners lands in 2c-ii.)
    pub fn update_v6vpn(
        &mut self,
        rd: RouteDistinguisher,
        prefix: Ipv6Net,
        rib: BgpRib,
    ) -> (Vec<BgpRib>, Vec<BgpRib>, u32) {
        self.v6vpn.entry(rd).or_default().update(prefix, rib)
    }

    pub fn remove_v6vpn(
        &mut self,
        rd: RouteDistinguisher,
        prefix: Ipv6Net,
        id: u32,
        ident: usize,
    ) -> Vec<BgpRib> {
        self.v6vpn.entry(rd).or_default().remove(prefix, id, ident)
    }

    pub fn select_best_path_vpn_v6(
        &mut self,
        rd: &RouteDistinguisher,
        prefix: Ipv6Net,
    ) -> Vec<BgpRib> {
        self.v6vpn.entry(*rd).or_default().select_best_path(prefix)
    }

    /// Distinct BGP next-hops still in use by surviving candidates for a
    /// v4 (`rd == None`) / VPNv4 (`rd == Some`) prefix — for NHT untrack
    /// to avoid releasing a next-hop another path still needs.
    pub fn candidate_nexthops_v4(
        &self,
        rd: Option<RouteDistinguisher>,
        prefix: Ipv4Net,
    ) -> BTreeSet<IpAddr> {
        let cands = match rd {
            Some(rd) => self.v4vpn.get(&rd).map(|t| t.candidates(prefix)),
            None => Some(self.v4.candidates(prefix)),
        };
        cands
            .into_iter()
            .flatten()
            .filter_map(|r| super::nht::nht_target(&r.attr))
            .collect()
    }

    /// IPv6 counterpart of [`Self::candidate_nexthops_v4`].
    pub fn candidate_nexthops_v6(
        &self,
        rd: Option<RouteDistinguisher>,
        prefix: Ipv6Net,
    ) -> BTreeSet<IpAddr> {
        let cands = match rd {
            Some(rd) => self.v6vpn.get(&rd).map(|t| t.candidates(prefix)),
            None => Some(self.v6.candidates(prefix)),
        };
        cands
            .into_iter()
            .flatten()
            .filter_map(|r| super::nht::nht_target(&r.attr))
            .collect()
    }

    /// Labeled-Unicast (SAFI 4) counterparts: the distinct BGP next-hops
    /// among the `v4lu` / `v6lu` candidates for `prefix` (for NHT untrack
    /// after a displaced path).
    pub fn candidate_nexthops_v4lu(&self, prefix: Ipv4Net) -> BTreeSet<IpAddr> {
        self.v4lu
            .candidates(prefix)
            .iter()
            .filter_map(|r| super::nht::nht_target(&r.attr))
            .collect()
    }

    pub fn candidate_nexthops_v6lu(&self, prefix: Ipv6Net) -> BTreeSet<IpAddr> {
        self.v6lu
            .candidates(prefix)
            .iter()
            .filter_map(|r| super::nht::nht_target(&r.attr))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rib::label_space::SharedLabelSpace;

    #[test]
    fn intern_dedups_within_shard_store() {
        let mut shard = BgpShard::default();
        let a = shard.intern(BgpAttr::default());
        let b = shard.intern(BgpAttr::default());
        assert!(Arc::ptr_eq(&a, &b), "same content interns to one Arc");
        assert_eq!(shard.attr_store.len(), 1);
    }

    fn v4(s: &str) -> Ipv4Net {
        s.parse().unwrap()
    }

    /// A pool over a label space, as `Bgp::new` builds the global one.
    fn pool_with_space() -> (SharedLabelSpace, ShardLabelPool) {
        let space = SharedLabelSpace::default();
        let pool = ShardLabelPool::new(LabelChunks::new(space.clone(), "bgp"));
        (space, pool)
    }

    #[test]
    fn label_pool_mints_from_a_chunk_then_dedups() {
        let (space, mut pool) = pool_with_space();
        // The first label takes a 128-label chunk from the label space.
        assert_eq!(pool.label_lu_v4(v4("10.0.0.0/24")), Some(24000));
        assert_eq!(
            space.lock().held_blocks(),
            vec![(LabelBlock::new(24000, 128), "bgp".to_string())]
        );
        // Same prefix → cache hit, same label.
        assert_eq!(pool.label_lu_v4(v4("10.0.0.0/24")), Some(24000));
        // New prefix → next label from the chunk already held.
        assert_eq!(pool.label_lu_v4(v4("10.0.1.0/24")), Some(24001));
        assert_eq!(pool.chunks(), vec![LabelBlock::new(24000, 128)]);
    }

    #[test]
    fn label_pool_and_other_holders_never_collide() {
        let (space, mut pool) = pool_with_space();
        // Another holder (the main task's block, an IGP's chunk) takes
        // labels first; the shard's chunk comes after them.
        let other = space.lock().alloc("isis", 1024).unwrap();
        assert_eq!(other.start, 24000);
        assert_eq!(pool.label_lu_v4(v4("10.0.0.0/24")), Some(25024));
    }

    #[test]
    fn label_pool_free_returns_label_for_reuse() {
        let (_space, mut pool) = pool_with_space();
        let l = pool.label_lu_v4(v4("10.0.0.0/24")).unwrap();
        pool.label_lu_v4(v4("10.0.1.0/24")).unwrap();
        assert_eq!(pool.free_lu_v4(v4("10.0.0.0/24")), Some(l));
        assert_eq!(
            pool.label_lu_v4(v4("10.9.9.0/24")),
            Some(l),
            "freed label reused from the chunk"
        );
    }

    #[test]
    fn label_pool_hands_back_a_drained_chunk() {
        let (_space, mut pool) = pool_with_space();
        let l = pool.label_vpn_v4(RouteDistinguisher::default(), v4("10.0.0.0/24"));
        assert_eq!(l, Some(24000));
        assert!(pool.take_drained().is_empty(), "label in use");
        pool.free_vpn_v4(RouteDistinguisher::default(), v4("10.0.0.0/24"));
        assert_eq!(pool.take_drained(), vec![LabelBlock::new(24000, 128)]);
        assert!(pool.chunks().is_empty());
    }

    #[test]
    fn label_pool_without_space_is_none() {
        let mut pool = ShardLabelPool::default();
        // No label space (pool worker, per-VRF shard) → no label (the
        // caller falls back to advertising the received label).
        assert_eq!(pool.label_lu_v4(v4("10.0.0.0/24")), None);
    }

    #[test]
    fn shard_stores_are_independent() {
        // Two shards intern the same attr into distinct Arcs — the
        // split is per-store dedup, which is exactly why an Arc's
        // validity never depends on which store interned it (so
        // classifying a site to the "wrong" store can't break
        // correctness, only dedup locality / accounting).
        let mut a = BgpShard::default();
        let mut b = BgpShard::default();
        let ra = a.intern(BgpAttr::default());
        let rb = b.intern(BgpAttr::default());
        assert!(!Arc::ptr_eq(&ra, &rb));
        assert_eq!(a.attr_store.len(), 1);
        assert_eq!(b.attr_store.len(), 1);
    }
}
