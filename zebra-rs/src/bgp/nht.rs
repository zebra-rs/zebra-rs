//! BGP-side Next-Hop Tracking cache.
//!
//! Deduplicates per-nexthop registrations against the RIB NHT service
//! ([`crate::rib::nht`]): one registration per distinct BGP next-hop,
//! with the set of dependent routes recorded so a `RibRx::NexthopUpdate`
//! can re-evaluate exactly the affected prefixes. The cached
//! `reachable` flag feeds the best-path gate via `BgpRib.nexthop_reachable`.
//!
//! Scope: the global `Bgp` instance (it owns the `rib_rx` stream);
//! per-VRF tasks pass `None` and don't gate (their CE next-hops resolve
//! directly in the VRF). Cache cleanup on route withdrawal (untrack) is
//! a follow-up — registrations persist for the life of the process,
//! bounded by the number of distinct next-hops seen.

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;

use bgp_packet::{BgpAttr, BgpNexthop, EvpnPrefix, RouteDistinguisher};
use ipnet::{Ipv4Net, Ipv6Net};

use crate::rib::nht::{NexthopResolution, ResolvedNexthop};

/// A route that depends on a tracked next-hop — enough to locate its
/// candidates and re-run best-path on a resolution change.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum NhtDep {
    V4(Ipv4Net),
    V6(Ipv6Net),
    /// IPv4 / IPv6 Labeled-Unicast (SAFI 4) route in `shard.v4lu` /
    /// `v6lu`. The BGP next-hop is tracked so the FIB label-push entry
    /// re-installs (and best-path re-gates) when the next-hop's
    /// reachability or transport changes — like the VPN deps, but the
    /// route stays in the global table rather than a VRF.
    V4lu(Ipv4Net),
    V6lu(Ipv6Net),
    V4vpn(RouteDistinguisher, Ipv4Net),
    V6vpn(RouteDistinguisher, Ipv6Net),
    /// EVPN Type-5 (IP Prefix) route in `local_rib.evpn`. Like the
    /// VPN deps, the PE next-hop is tracked so the VRF import re-runs
    /// when the underlay resolves or reroutes. The `EvpnPrefix` is the
    /// RD-stripped key (its `IpPrefix` variant carries the v4/v6 net).
    Evpn(RouteDistinguisher, EvpnPrefix),
    /// SR Policy (SAFI 73) in `local_rib.sr_policy`. The policy endpoint
    /// is tracked so the SR-MPLS Binding-SID ILM (re)installs toward the
    /// resolved next-hop, or is torn down, when the endpoint's
    /// reachability or transport changes. Keyed by `<color, endpoint>`.
    SrPolicy {
        color: u32,
        endpoint: IpAddr,
    },
    /// MUP (SAFI 85) Direct Segment Discovery (DSD) route in
    /// `local_rib.mup`. A *received* DSD's next-hop is tracked so the
    /// per-VRF ST2→DSD encap install re-runs when the underlay resolves
    /// or reroutes: on a change the DSD is re-dispatched to importing
    /// VRFs with the freshly-resolved transport, so each ST2 whose
    /// Direct-segment id matches re-programs its endpoint encap. Keyed by
    /// the DSD's `(rd, MupPrefix)` like the VPN deps.
    Mup(RouteDistinguisher, bgp_packet::MupPrefix),
    /// MUP (SAFI 85) Type-1 ST route's GTP **endpoint** (gNB) in
    /// `local_rib.mup`. Unlike [`Self::Mup`] (which tracks the BGP next-hop),
    /// this tracks the ST1's `st1.endpoint` address so the `dataplane gtp`
    /// downlink `GTP4.E` encap re-resolves its outer v4 underlay when the gNB's
    /// reachability or route changes: on a change the ST1 is re-dispatched to
    /// importing VRFs with the freshly-resolved endpoint transport. Keyed by
    /// the ST1's `(rd, MupPrefix)`.
    MupEndpoint(RouteDistinguisher, bgp_packet::MupPrefix),
}

/// How a tracked next-hop's resolution changed, returned by
/// [`NexthopCache::update`]. Lets the caller react proportionally —
/// a full re-evaluation on a reachability flip, but only a dataplane
/// re-install on a transport-only reroute (no peer re-advertisement).
#[derive(Debug, PartialEq, Eq)]
pub enum CacheChange {
    Unchanged,
    Reachability(Vec<NhtDep>),
    Transport(Vec<NhtDep>),
}

#[derive(Debug, Default)]
pub struct NhtCacheEntry {
    pub reachable: bool,
    /// Resolved transport egress(es) for this next-hop, from the last
    /// `RibRx::NexthopUpdate`. Consumed by the VPN dataplane install to
    /// build the `{service-label, transport-labels}` stack. Empty while
    /// a registration is pending or the next-hop is unreachable.
    pub nexthops: Vec<ResolvedNexthop>,
    pub deps: BTreeSet<NhtDep>,
}

/// Per-instance BGP next-hop cache. Entries are keyed `(vrf_id, address)`
/// — the table the RIB registration named (0 = global) — because the same
/// address may be tracked in several tables with independent resolutions
/// (a gNB inside an interwork VRF, overlapping slice address spaces).
/// Every pre-existing user tracks in the global table and passes `0`; only
/// the MUP ST1 endpoint path resolves a table (`mup_endpoint_table`).
#[derive(Debug, Default)]
pub struct NexthopCache {
    pub entries: HashMap<(u32, IpAddr), NhtCacheEntry>,
    /// Interwork-segment prefixes → kernel table, mirrored from the MUP
    /// segment catalog by `Bgp::push_mup_segment_catalog`. Consulted by
    /// [`Self::mup_endpoint_table`] to pick the registration table for
    /// `NhtDep::MupEndpoint` deps — kept on the cache itself so the
    /// track/untrack helpers resolve it without threading the catalog
    /// through every `BgpTop`.
    mup_interwork: Vec<(ipnet::IpNet, u32)>,
}

impl NexthopCache {
    /// Record that `dep` uses `nh` in table `vrf_id`. Returns
    /// `(needs_register, reachable_now)`: `needs_register` is true on the
    /// first sighting of `(vrf_id, nh)` (the caller registers it with the
    /// RIB), and `reachable_now` is the current cached reachability
    /// (`false` while a fresh registration is pending — register-then-gate).
    pub fn track(&mut self, vrf_id: u32, nh: IpAddr, dep: NhtDep) -> (bool, bool) {
        use std::collections::hash_map::Entry;
        match self.entries.entry((vrf_id, nh)) {
            Entry::Occupied(mut e) => {
                e.get_mut().deps.insert(dep);
                (false, e.get().reachable)
            }
            Entry::Vacant(v) => {
                let mut deps = BTreeSet::new();
                deps.insert(dep);
                v.insert(NhtCacheEntry {
                    reachable: false,
                    nexthops: Vec::new(),
                    deps,
                });
                (true, false)
            }
        }
    }

    /// Apply a resolution update, refreshing the stored reachability +
    /// resolved transport. Classifies the change so the caller can react
    /// proportionally:
    /// - [`CacheChange::Reachability`] — the gate flipped; best-path,
    ///   peer advertisement and the dataplane all need re-evaluation.
    /// - [`CacheChange::Transport`] — still reachable, but the resolved
    ///   egress/labels changed (an IGP reroute of the PE). Best-path is
    ///   unchanged, so only the fully-resolved VPN FIB entry needs
    ///   re-installing — no peer re-advertisement (which for VPNv4 isn't
    ///   deduped and would flood PEs).
    /// - [`CacheChange::Unchanged`] — nothing moved; a no-op.
    pub fn update(
        &mut self,
        vrf_id: u32,
        nh: IpAddr,
        resolution: &NexthopResolution,
    ) -> CacheChange {
        match self.entries.get_mut(&(vrf_id, nh)) {
            Some(e) => {
                let reachability_flipped = e.reachable != resolution.reachable;
                let transport_changed = e.nexthops != resolution.nexthops;
                e.reachable = resolution.reachable;
                e.nexthops = resolution.nexthops.clone();
                if reachability_flipped {
                    CacheChange::Reachability(e.deps.iter().cloned().collect())
                } else if transport_changed {
                    CacheChange::Transport(e.deps.iter().cloned().collect())
                } else {
                    CacheChange::Unchanged
                }
            }
            None => CacheChange::Unchanged,
        }
    }

    /// Drop `dep`'s interest in `nh` (a withdrawal). Returns `true` when
    /// that was the last dep for `nh` — the entry is removed and the
    /// caller should send `Message::NexthopUnregister` so the RIB drops
    /// its watcher. Callers must only untrack a next-hop no surviving
    /// route still uses (a `NhtDep` can be tracked under several
    /// next-hops via multiple paths). A no-op for an untracked `nh`.
    pub fn untrack(&mut self, vrf_id: u32, nh: IpAddr, dep: &NhtDep) -> bool {
        if let Some(e) = self.entries.get_mut(&(vrf_id, nh)) {
            e.deps.remove(dep);
            if e.deps.is_empty() {
                self.entries.remove(&(vrf_id, nh));
                return true;
            }
        }
        false
    }

    /// The resolved transport egress(es) for `nh` in table `vrf_id` — what
    /// the VPN dataplane install pushes the service label over. Empty slice
    /// when the entry isn't tracked or hasn't resolved yet.
    pub fn transport_for(&self, vrf_id: u32, nh: IpAddr) -> &[ResolvedNexthop] {
        self.entries
            .get(&(vrf_id, nh))
            .map(|e| e.nexthops.as_slice())
            .unwrap_or(&[])
    }

    /// Replace the interwork-prefix view ([`Self::mup_endpoint_table`]'s
    /// input). Called by `Bgp::push_mup_segment_catalog` whenever the MUP
    /// segment catalog changes.
    pub fn set_mup_interwork(&mut self, interwork: Vec<(ipnet::IpNet, u32)>) {
        self.mup_interwork = interwork;
    }

    /// The table a MUP ST1 GTP endpoint (gNB) resolves in: the most-specific
    /// interwork-segment prefix containing it, else the global table — the
    /// design's downlink rule (endpoint ∈ ISD prefix → that segment's VRF).
    pub fn mup_endpoint_table(&self, endpoint: &IpAddr) -> u32 {
        self.mup_interwork
            .iter()
            .filter(|(p, _)| p.contains(endpoint))
            .max_by_key(|(p, _)| p.prefix_len())
            .map(|(_, table)| *table)
            .unwrap_or(0)
    }

    /// `MupEndpoint` registrations whose table no longer matches the
    /// interwork view — computed after [`Self::set_mup_interwork`] so the
    /// caller can migrate them (untrack the old key, retrack + register
    /// under the new one). Each move is `(old_vrf, new_vrf, endpoint,
    /// the MupEndpoint deps to carry over)`; non-endpoint deps sharing the
    /// entry stay where they are.
    pub fn mup_endpoint_moves(&self) -> Vec<(u32, u32, IpAddr, Vec<NhtDep>)> {
        let mut moves = Vec::new();
        for ((vrf_id, nh), entry) in &self.entries {
            let deps: Vec<NhtDep> = entry
                .deps
                .iter()
                .filter(|d| matches!(d, NhtDep::MupEndpoint(..)))
                .cloned()
                .collect();
            if deps.is_empty() {
                continue;
            }
            let want = self.mup_endpoint_table(nh);
            if want != *vrf_id {
                moves.push((*vrf_id, want, *nh, deps));
            }
        }
        moves
    }
}

/// The IPv4/IPv6 address of a BGP attribute's next-hop, for tracking.
/// `None` when the attribute carries no next-hop.
pub fn bgp_nexthop_ip(attr: &BgpAttr) -> Option<IpAddr> {
    match attr.nexthop.as_ref()? {
        BgpNexthop::Ipv4(a) => Some(IpAddr::V4(*a)),
        BgpNexthop::Ipv6(a) => Some(IpAddr::V6(*a)),
        BgpNexthop::Vpnv4(v) => Some(v.nhop),
        BgpNexthop::Vpnv6(v) => Some(IpAddr::V6(v.nhop)),
        BgpNexthop::Evpn(ip) => Some(*ip),
    }
}

/// The address a route's reachability and transport should track. For an
/// SRv6 L3VPN route this is the **End.DT46 service SID** (resolved via its
/// locator), not the egress PE's next-hop loopback: the SID is the actual
/// forwarding dependency, so the route follows the locator's reachability
/// — including a Mirror SID egress-protection redirect, and surviving a
/// node failure that withdraws the loopback but whose locator the PLR
/// retains. Everything else (SR-MPLS VPN, plain unicast) keeps tracking
/// the BGP next-hop. All of a route's NHT sites — register, transport
/// lookup, re-eval, untrack — must agree, so they all call this.
///
/// Known limitation: for a split End.DT4 + End.DT6 pair this tracks the
/// FIRST SID regardless of the destination family the FIB steers into
/// (`srv6_l3_sid_for_dest` there). Both SIDs of one route come from the
/// same PE's locator in practice, so reachability is equivalent; making
/// this family-aware would require threading the family through every
/// register/untrack site in lockstep (a mismatch desyncs the NHT
/// refcounts), which is not worth it for a same-locator distinction.
pub fn nht_target(attr: &BgpAttr) -> Option<IpAddr> {
    if let Some((sid, _behavior)) = attr.srv6_l3_sid() {
        return Some(IpAddr::V6(sid));
    }
    bgp_nexthop_ip(attr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn track_dedups_and_reports_register_on_first_sight() {
        let mut c = NexthopCache::default();
        let nh: IpAddr = "10.0.0.8".parse().unwrap();
        let p1: Ipv4Net = "1.0.0.0/24".parse().unwrap();
        let p2: Ipv4Net = "2.0.0.0/24".parse().unwrap();

        // First sighting → register, pending-unreachable.
        assert_eq!(c.track(0, nh, NhtDep::V4(p1)), (true, false));
        // Second route, same nexthop → no re-register, still pending.
        assert_eq!(c.track(0, nh, NhtDep::V4(p2)), (false, false));
    }

    #[test]
    fn same_address_in_two_tables_is_two_entries() {
        // The faithful-MUP identity: a gNB address inside an interwork VRF
        // and the same literal address in the global table are independent
        // registrations with independent resolutions.
        let mut c = NexthopCache::default();
        let nh: IpAddr = "10.0.1.2".parse().unwrap();
        let p1: Ipv4Net = "1.0.0.0/24".parse().unwrap();

        assert_eq!(c.track(0, nh, NhtDep::V4(p1)), (true, false), "global");
        assert_eq!(c.track(7, nh, NhtDep::V4(p1)), (true, false), "vrf 7");

        // Resolving the VRF-7 entry leaves the global one untouched.
        assert_eq!(
            c.update(7, nh, &reachable(vec![])),
            CacheChange::Reachability(vec![NhtDep::V4(p1)])
        );
        assert!(c.transport_for(0, nh).is_empty());
        assert!(!c.transport_for(7, nh).is_empty());

        // Untracking one table's last dep unregisters only that table.
        assert!(c.untrack(0, nh, &NhtDep::V4(p1)));
        assert!(c.entries.contains_key(&(7, nh)));
    }

    #[test]
    fn mup_endpoint_table_picks_most_specific_interwork_prefix() {
        let mut c = NexthopCache::default();
        let ep: IpAddr = "10.0.1.2".parse().unwrap();
        assert_eq!(c.mup_endpoint_table(&ep), 0, "no interwork view → global");
        c.set_mup_interwork(vec![
            ("10.0.0.0/8".parse().unwrap(), 5),
            ("10.0.1.0/24".parse().unwrap(), 7),
        ]);
        assert_eq!(c.mup_endpoint_table(&ep), 7, "most-specific wins");
        let outside: IpAddr = "192.0.2.1".parse().unwrap();
        assert_eq!(c.mup_endpoint_table(&outside), 0, "uncovered → global");
    }

    #[test]
    fn mup_endpoint_moves_reports_only_stale_endpoint_registrations() {
        let mut c = NexthopCache::default();
        let ep: IpAddr = "10.0.1.2".parse().unwrap();
        let rd: RouteDistinguisher = "65000:6".parse().unwrap();
        let ue: Ipv4Net = "10.60.1.0/24".parse().unwrap();
        let dep = NhtDep::MupEndpoint(
            rd,
            bgp_packet::MupPrefix::T1st {
                prefix: ipnet::IpNet::V4(ue),
            },
        );
        // Registered under the global table before any interwork existed;
        // a plain unicast dep shares the address and must NOT move.
        c.track(0, ep, dep.clone());
        c.track(0, ep, NhtDep::V4(ue));
        assert!(c.mup_endpoint_moves().is_empty());

        // The endpoint becomes covered by an interwork segment → exactly
        // the MupEndpoint dep is reported as a (0 → 7) move.
        c.set_mup_interwork(vec![("10.0.1.0/24".parse().unwrap(), 7)]);
        let moves = c.mup_endpoint_moves();
        assert_eq!(moves.len(), 1);
        let (old_vrf, new_vrf, nh, deps) = &moves[0];
        assert_eq!((*old_vrf, *new_vrf, *nh), (0, 7, ep));
        assert_eq!(deps.as_slice(), &[dep]);
    }

    fn reachable(labels: Vec<u32>) -> NexthopResolution {
        NexthopResolution {
            reachable: true,
            metric: 10,
            nexthops: vec![ResolvedNexthop {
                addr: "172.16.0.2".parse().unwrap(),
                ifindex: 3,
                labels,
                segs: vec![],
                seg_encap: None,
            }],
        }
    }

    #[test]
    fn update_classifies_reachability_vs_transport_vs_unchanged() {
        let mut c = NexthopCache::default();
        let nh: IpAddr = "10.0.0.8".parse().unwrap();
        let p1: Ipv4Net = "1.0.0.0/24".parse().unwrap();
        c.track(0, nh, NhtDep::V4(p1));

        // pending(false) -> reachable(true): reachability flip → full
        // re-eval, and the resolved transport is now retrievable.
        assert_eq!(
            c.update(0, nh, &reachable(vec![16800])),
            CacheChange::Reachability(vec![NhtDep::V4(p1)])
        );
        assert_eq!(c.transport_for(0, nh)[0].labels, vec![16800]);
        assert_eq!(c.transport_for(0, nh)[0].ifindex, 3);

        // still reachable, transport label changed (IGP reroute of the
        // PE): transport-only → re-install, no advertise. Cache refreshed.
        assert_eq!(
            c.update(0, nh, &reachable(vec![16801])),
            CacheChange::Transport(vec![NhtDep::V4(p1)])
        );
        assert_eq!(c.transport_for(0, nh)[0].labels, vec![16801]);

        // identical resolution again: nothing moved.
        assert_eq!(
            c.update(0, nh, &reachable(vec![16801])),
            CacheChange::Unchanged
        );

        // unknown nexthop: unchanged, empty transport.
        let unknown: IpAddr = "9.9.9.9".parse().unwrap();
        assert_eq!(
            c.update(0, unknown, &NexthopResolution::default()),
            CacheChange::Unchanged
        );
        assert!(c.transport_for(0, unknown).is_empty());
    }

    #[test]
    fn untrack_unregisters_only_on_last_dep() {
        let mut c = NexthopCache::default();
        let nh: IpAddr = "10.0.0.8".parse().unwrap();
        let p1: Ipv4Net = "1.0.0.0/24".parse().unwrap();
        let p2: Ipv4Net = "2.0.0.0/24".parse().unwrap();
        c.track(0, nh, NhtDep::V4(p1));
        c.track(0, nh, NhtDep::V4(p2));

        // First withdrawal: a dep remains, so the next-hop stays tracked.
        assert!(!c.untrack(0, nh, &NhtDep::V4(p1)));
        assert!(c.entries.contains_key(&(0, nh)));

        // Last dep gone: entry dropped, caller should unregister.
        assert!(c.untrack(0, nh, &NhtDep::V4(p2)));
        assert!(!c.entries.contains_key(&(0, nh)));

        // Untracking an already-gone next-hop is a no-op (not "last").
        assert!(!c.untrack(0, nh, &NhtDep::V4(p1)));
    }
}
