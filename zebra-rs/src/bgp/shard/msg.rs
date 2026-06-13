//! Message protocol between the main `Bgp` task and the shard task
//! (RIB sharding plan B.2/B.3), modeled on [`super::super::vrf::msg`].
//!
//! # The split (N=1)
//!
//! Main keeps the peer-dependent work it already does: UPDATE parse,
//! the inbound loop / enforce-first-as / route-reflection checks,
//! inbound policy (`route_apply_policy_in`), NHT registration against
//! the RIB-facing `nexthop_cache`, the advertise fan-out, and FIB
//! install. The shard task owns the data-structure operations it now
//! holds state for — Adj-RIB-In, attribute interning, the sharded
//! Loc-RIB tables, best-path selection, and the per-route label
//! sub-block.
//!
//! So a received route flows: main parses + checks + runs policy-in →
//! sends the shard a [`ShardMsg::UpdateV4`] (pre-policy attr for
//! Adj-RIB-In, the post-policy [`decision`] for the Loc-RIB) → the
//! shard stores it and selects best path → replies with a
//! [`ShardOut::BestPathV4`] → main runs NHT / FIB / advertise on the
//! delta. Moving inbound policy itself into the shard (so it
//! parallelises across shards) is deferred to C.1; at N=1 it stays in
//! main, which keeps this step a pure relocation of the table ops.
//!
//! [`decision`]: ShardUpdateV4::decision
//!
//! # Ordering contract (plan §7)
//!
//! One shard, one inbound channel, one outbound channel — so messages
//! from main are processed in send order and `ShardOut` replies are
//! produced in processing order. Main must therefore apply a route's
//! `ShardOut` delta (advertise / FIB / NHT) before it acts on a later
//! message that depends on it, and the shard must not reorder work
//! across the channel. A withdraw for a prefix sent after an announce
//! for the same prefix is processed after it; the per-prefix Loc-RIB
//! state stays consistent because the shard is the single writer.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};

use bgp_packet::{Ipv4Nlri, Ipv6Nlri, Label, RouteDistinguisher};

use super::super::route::{BgpRib, BgpRibType, PolicyDecision, VpnNexthop};

/// Main → shard. Each variant is one unit of work the shard applies to
/// its owned state; route-bearing variants reply with a [`ShardOut`].
///
/// Only the IPv4 (unicast + VPNv4) reference path is modeled so far;
/// the v6 / labeled-unicast / VPNv6 variants land as their receive
/// paths are rerouted onto the channel (same shape, different NLRI /
/// table).
#[derive(Debug)]
pub enum ShardMsg {
    /// A received IPv4-unicast (`rd = None`) or VPNv4 (`rd = Some`)
    /// route, after main's inbound checks + policy-in. The shard
    /// stores Adj-RIB-In (pre-policy) and the Loc-RIB candidate
    /// (post-policy), runs best-path, and replies with
    /// [`ShardOut::BestPathV4`].
    UpdateV4(ShardUpdateV4),

    /// Explicit withdraw of an IPv4 / VPNv4 prefix the peer no longer
    /// advertises (or that failed a re-check). The shard removes the
    /// Adj-RIB-In + Loc-RIB entry and replies with the best-path delta.
    WithdrawV4 {
        ident: usize,
        rd: Option<RouteDistinguisher>,
        nlri: Ipv4Nlri,
    },

    /// A received IPv6-unicast (`rd = None`) or VPNv6 (`rd = Some`)
    /// route. Unlike v4 there is no inbound-policy stage (the v6
    /// ingest path has none today), so the carried `attr` is final:
    /// the shard stores it in Adj-RIB-In + Loc-RIB and replies with
    /// [`ShardOut::BestPathV6`].
    UpdateV6(ShardUpdateV6),

    /// Withdraw of an IPv6 / VPNv6 prefix.
    WithdrawV6 {
        ident: usize,
        rd: Option<RouteDistinguisher>,
        nlri: Ipv6Nlri,
    },

    /// A peer left Established: the shard drops the peer's Adj-RIB-In
    /// slice across every sharded family and replies with a
    /// [`ShardOut::BestPathV4`] per contributed prefix — re-electing
    /// any surviving path (another peer may now win) or signalling a
    /// withdraw (empty winners). Centralizing the sweep here closes the
    /// "new SAFI forgot a route_clean block" bug-class (#1329).
    PeerDown { ident: usize },

    /// Render a sharded Loc-RIB table for a `show` command — the
    /// scatter-gather half of the show split. The reply travels on the
    /// request's own oneshot channel, not [`ShardOut`].
    Show(crate::config::DisplayRequest),

    /// Tear the shard task down; its event loop exits on the next
    /// iteration. Used at daemon shutdown.
    Shutdown,
}

/// Payload of [`ShardMsg::UpdateV4`]. Mirrors the arguments of
/// `route_ipv4_update` minus the parts main computed before sending
/// (the peer checks) — `attr` is the pre-policy attribute for
/// Adj-RIB-In; `decision` is the post-policy result (`None` = inbound
/// policy denied the route, so the shard withdraws any prior Loc-RIB
/// entry). Attributes travel by value; the shard interns them into its
/// own [`super::BgpShard::attr_store`].
#[derive(Debug)]
pub struct ShardUpdateV4 {
    pub ident: usize,
    pub rd: Option<RouteDistinguisher>,
    pub nlri: Ipv4Nlri,
    pub peer_router_id: Ipv4Addr,
    pub typ: BgpRibType,
    pub attr: bgp_packet::BgpAttr,
    pub label: Option<Label>,
    pub nexthop: Option<VpnNexthop>,
    pub enhe_egress: Option<(std::net::Ipv6Addr, u32)>,
    pub stale: bool,
    /// Next-hop reachability main resolved via NHT before sending (it
    /// owns `nexthop_cache`); the shard gates the Loc-RIB row with it
    /// before best-path. `true` when main has no NHT view (matches
    /// `BgpRib::new`'s default).
    pub nexthop_reachable: bool,
    /// Inter-AS Option AB: main computed (against its VRF-import view)
    /// that an `inter-as-hybrid` VRF imports this VPNv4 route, so the
    /// shard marks the Loc-RIB row transit-only. Always `false` for
    /// unicast (`rd = None`).
    pub vrf_transit_only: bool,
    pub decision: Option<PolicyDecision>,
}

/// Payload of [`ShardMsg::UpdateV6`]. The v6 ingest path has no inbound
/// policy, so `attr` is the final attribute (stored both in Adj-RIB-In,
/// un-interned via `BgpRib::new`, and — re-interned — in the Loc-RIB).
#[derive(Debug)]
pub struct ShardUpdateV6 {
    pub ident: usize,
    pub rd: Option<RouteDistinguisher>,
    pub nlri: Ipv6Nlri,
    pub peer_router_id: Ipv4Addr,
    pub typ: BgpRibType,
    pub attr: bgp_packet::BgpAttr,
    /// VPNv6 service label (`None` for plain v6 unicast).
    pub label: Option<Label>,
    pub nexthop: Option<VpnNexthop>,
    pub stale: bool,
    /// See [`ShardUpdateV4::nexthop_reachable`].
    pub nexthop_reachable: bool,
    /// Inter-AS Option AB for VPNv6 (see [`ShardUpdateV4::vrf_transit_only`]).
    pub vrf_transit_only: bool,
}

/// Shard → main. The result of applying a [`ShardMsg`]: the best-path
/// delta main needs to drive NHT, FIB install, and the advertise
/// fan-out. Attributes ride as `Arc<BgpAttr>` inside [`BgpRib`] — an
/// `Arc` is `Send`, so it crosses the channel without a re-intern.
#[derive(Debug)]
pub enum ShardOut {
    /// Best-path outcome for an IPv4 / VPNv4 prefix after an
    /// [`ShardMsg::UpdateV4`], [`ShardMsg::WithdrawV4`], or a
    /// [`ShardMsg::PeerDown`] sweep. `selected` are the new winners
    /// (empty ⇒ the prefix is gone — main withdraws); `replaced` are
    /// the rows displaced, for NHT untrack.
    BestPathV4 {
        ident: usize,
        rd: Option<RouteDistinguisher>,
        prefix: Ipv4Nlri,
        selected: Vec<BgpRib>,
        replaced: Vec<BgpRib>,
        /// Distinct BGP next-hops still in use by surviving candidates
        /// after the update — read by main's NHT untrack so it doesn't
        /// release a next-hop another path still needs. Computed by the
        /// shard (it owns the Loc-RIB) since main can't see the table.
        survivor_nexthops: BTreeSet<IpAddr>,
    },

    /// IPv6 / VPNv6 counterpart of [`Self::BestPathV4`].
    BestPathV6 {
        ident: usize,
        rd: Option<RouteDistinguisher>,
        prefix: Ipv6Nlri,
        selected: Vec<BgpRib>,
        replaced: Vec<BgpRib>,
        survivor_nexthops: BTreeSet<IpAddr>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> Ipv4Nlri {
        Ipv4Nlri {
            id: 0,
            prefix: s.parse().unwrap(),
        }
    }

    #[test]
    fn update_v4_carries_pre_and_post_policy() {
        // A permitted route: pre-policy attr for Adj-RIB-In + a
        // post-policy decision for the Loc-RIB.
        let msg = ShardMsg::UpdateV4(ShardUpdateV4 {
            ident: 3,
            rd: None,
            nlri: v4("10.0.0.0/24"),
            peer_router_id: Ipv4Addr::new(10, 0, 0, 1),
            typ: BgpRibType::EBGP,
            attr: bgp_packet::BgpAttr::default(),
            label: None,
            nexthop: None,
            enhe_egress: None,
            stale: false,
            nexthop_reachable: true,
            vrf_transit_only: false,
            decision: Some(PolicyDecision {
                attr: bgp_packet::BgpAttr::default(),
                weight: 100,
            }),
        });
        match msg {
            ShardMsg::UpdateV4(u) => {
                assert_eq!(u.ident, 3);
                assert!(u.decision.is_some(), "permitted route keeps a decision");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn peer_down_and_shutdown_are_control() {
        // Control variants carry no route payload.
        assert!(matches!(ShardMsg::PeerDown { ident: 1 }, ShardMsg::PeerDown { .. }));
        assert!(matches!(ShardMsg::Shutdown, ShardMsg::Shutdown));
    }

    #[test]
    fn best_path_v4_delta_separates_winners_from_displaced() {
        let out = ShardOut::BestPathV4 {
            ident: 2,
            rd: None,
            prefix: v4("10.0.0.0/24"),
            selected: vec![],
            replaced: vec![],
            survivor_nexthops: BTreeSet::new(),
        };
        let ShardOut::BestPathV4 { selected, .. } = out else {
            panic!("expected BestPathV4");
        };
        assert!(selected.is_empty(), "empty winners ⇒ withdraw");
    }
}
