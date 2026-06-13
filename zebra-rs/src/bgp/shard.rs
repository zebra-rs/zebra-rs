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
use super::route::{BgpRib, LocalRibTable};
use super::store::BgpAttrStore;
use super::vrf::VrfLabelAllocator;

/// Labels a shard carves from the central allocator per refill (RIB
/// sharding B.2). A shard mints local labels in the per-route hot
/// path, so it can't ask the main task per label; it draws a chunk
/// up front and refills when spent. The 20-bit space is vast, so the
/// chunk only trades a little frontier headroom for far fewer carves.
const SHARD_LABEL_CHUNK: u32 = 1024;

/// A shard's local MPLS label allocator for the families that mint a
/// per-route *local* label in the hot path: Labeled-Unicast (v4/v6,
/// next-hop-self) and the Inter-AS Option B VPNv4 transit case. The
/// pool starts empty and is filled by carving sub-ranges from the
/// central [`VrfLabelAllocator`] on `Bgp` (which still serves the
/// per-VRF-spawn labels); a carve leaves the central frontier, so the
/// two never collide. This is the inline (N=1) form of the plan's
/// per-shard sub-block; at B.3 the carve becomes a `LabelBlockLow`
/// request to the main task.
#[derive(Debug)]
pub struct ShardLabelPool {
    /// Sub-block allocator — seeded empty, grown by [`carve`] refills.
    ///
    /// [`carve`]: VrfLabelAllocator::carve
    pool: VrfLabelAllocator,
    /// Per-prefix IPv4 / IPv6 Labeled-Unicast local labels
    /// (allocate-on-first-use, freed on withdraw).
    lu_v4: BTreeMap<Ipv4Net, u32>,
    lu_v6: BTreeMap<Ipv6Net, u32>,
    /// Per-`(RD, prefix)` VPNv4 transit local labels (Inter-AS
    /// Option B): the swap ILM forwards `our label → received label`.
    vpn_v4: BTreeMap<(RouteDistinguisher, Ipv4Net), u32>,
}

impl Default for ShardLabelPool {
    fn default() -> Self {
        Self {
            pool: VrfLabelAllocator::empty(),
            lu_v4: BTreeMap::new(),
            lu_v6: BTreeMap::new(),
            vpn_v4: BTreeMap::new(),
        }
    }
}

impl ShardLabelPool {
    /// Allocate one label, refilling the sub-block from `central`
    /// (a [`carve`](VrfLabelAllocator::carve)) when it runs dry.
    /// `None` if `central` is absent or can't grant more.
    fn alloc(&mut self, central: Option<&mut VrfLabelAllocator>) -> Option<u32> {
        if let Some(label) = self.pool.alloc() {
            return Some(label);
        }
        let central = central?;
        let (start, end) = central.carve(SHARD_LABEL_CHUNK)?;
        self.pool.extend(start, end);
        self.pool.alloc()
    }

    /// Local label for an IPv4 LU prefix, allocating on first use.
    /// `None` if the dynamic pool is exhausted (the caller advertises
    /// the received label as a fallback until a block is granted).
    pub fn label_lu_v4(
        &mut self,
        central: Option<&mut VrfLabelAllocator>,
        prefix: Ipv4Net,
    ) -> Option<u32> {
        if let Some(l) = self.lu_v4.get(&prefix) {
            return Some(*l);
        }
        let label = self.alloc(central)?;
        self.lu_v4.insert(prefix, label);
        Some(label)
    }

    /// Local label for an IPv6 LU prefix; mirrors [`label_lu_v4`](Self::label_lu_v4).
    pub fn label_lu_v6(
        &mut self,
        central: Option<&mut VrfLabelAllocator>,
        prefix: Ipv6Net,
    ) -> Option<u32> {
        if let Some(l) = self.lu_v6.get(&prefix) {
            return Some(*l);
        }
        let label = self.alloc(central)?;
        self.lu_v6.insert(prefix, label);
        Some(label)
    }

    /// Local label for a received VPNv4 `(RD, prefix)`, allocating on
    /// first use (Inter-AS Option B transit).
    pub fn label_vpn_v4(
        &mut self,
        central: Option<&mut VrfLabelAllocator>,
        rd: RouteDistinguisher,
        prefix: Ipv4Net,
    ) -> Option<u32> {
        if let Some(l) = self.vpn_v4.get(&(rd, prefix)) {
            return Some(*l);
        }
        let label = self.alloc(central)?;
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
    /// transit). Draws from a sub-block carved out of the central
    /// [`VrfLabelAllocator`] on `Bgp`. Empty on per-VRF shards — the
    /// LU/VPN label path is global-instance-only today.
    pub labels: ShardLabelPool,
}

impl BgpShard {
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
            .filter_map(|r| super::nht::bgp_nexthop_ip(&r.attr))
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
            .filter_map(|r| super::nht::bgp_nexthop_ip(&r.attr))
            .collect()
    }

    /// Labeled-Unicast (SAFI 4) counterparts: the distinct BGP next-hops
    /// among the `v4lu` / `v6lu` candidates for `prefix` (for NHT untrack
    /// after a displaced path).
    pub fn candidate_nexthops_v4lu(&self, prefix: Ipv4Net) -> BTreeSet<IpAddr> {
        self.v4lu
            .candidates(prefix)
            .iter()
            .filter_map(|r| super::nht::bgp_nexthop_ip(&r.attr))
            .collect()
    }

    pub fn candidate_nexthops_v6lu(&self, prefix: Ipv6Net) -> BTreeSet<IpAddr> {
        self.v6lu
            .candidates(prefix)
            .iter()
            .filter_map(|r| super::nht::bgp_nexthop_ip(&r.attr))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn label_pool_refills_from_central_then_dedups() {
        let mut central = VrfLabelAllocator::bounded(1000, 1_000_000);
        let mut pool = ShardLabelPool::default();
        // First alloc carves a chunk from central and hands out its start.
        let l1 = pool
            .label_lu_v4(Some(&mut central), v4("10.0.0.0/24"))
            .unwrap();
        assert_eq!(l1, 1000);
        // Same prefix → cache hit, same label.
        assert_eq!(
            pool.label_lu_v4(Some(&mut central), v4("10.0.0.0/24")),
            Some(1000)
        );
        // New prefix → next label from the already-carved chunk (no re-carve).
        assert_eq!(
            pool.label_lu_v4(Some(&mut central), v4("10.0.1.0/24")),
            Some(1001)
        );
    }

    #[test]
    fn label_pool_and_central_never_collide() {
        let mut central = VrfLabelAllocator::bounded(1000, 1_000_000);
        let mut pool = ShardLabelPool::default();
        // Central mints a per-VRF-spawn label; the shard mints a route
        // label — disjoint, because the carve advanced central's frontier.
        let vrf_label = central.alloc().unwrap();
        let route_label = pool
            .label_lu_v4(Some(&mut central), v4("10.0.0.0/24"))
            .unwrap();
        assert_eq!(vrf_label, 1000);
        assert_eq!(route_label, 1001, "carved from the frontier after 1000");
        // Central resumes past the whole carved chunk.
        assert_eq!(central.alloc(), Some(1001 + SHARD_LABEL_CHUNK));
    }

    #[test]
    fn label_pool_free_returns_label_for_reuse() {
        let mut central = VrfLabelAllocator::bounded(1000, 1_000_000);
        let mut pool = ShardLabelPool::default();
        let l = pool
            .label_lu_v4(Some(&mut central), v4("10.0.0.0/24"))
            .unwrap();
        assert_eq!(pool.free_lu_v4(v4("10.0.0.0/24")), Some(l));
        // The freed label comes back out of the shard pool — no central
        // touch needed (pass None to prove it).
        assert_eq!(
            pool.label_lu_v4(None, v4("10.9.9.0/24")),
            Some(l),
            "freed label reused from the shard sub-block"
        );
    }

    #[test]
    fn label_pool_without_central_is_none_when_empty() {
        let mut pool = ShardLabelPool::default();
        // Empty sub-block and no central to carve from → no label (the
        // caller falls back to advertising the received label).
        assert_eq!(pool.label_lu_v4(None, v4("10.0.0.0/24")), None);
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
