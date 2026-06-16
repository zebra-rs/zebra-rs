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

use bgp_packet::{Ipv4MpReachNextHop, Ipv4Nlri, Ipv6Nlri, Label, RouteDistinguisher};

use super::super::route::{BgpRib, BgpRibType, PolicyDecision, SyncCtx, VpnNexthop};

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

    /// A batch of IPv4-unicast prefixes from one UPDATE that hash to this
    /// shard, carrying the shared attribute once (RIB sharding RouteBatch
    /// — the per-shard ingest fan-out). The shard processes each NLRI like
    /// an [`Self::UpdateV4`] with `compute_policy`, replying with one
    /// [`ShardOut::BestPathV4`] per NLRI. Sending one batch per shard per
    /// UPDATE instead of one message per prefix collapses 4M futex
    /// wake-ups to ~N and moves the per-prefix attr clone off main onto
    /// the parallel shards.
    RouteBatchV4(ShardRouteBatchV4),

    /// Explicit withdraw of an IPv4 / VPNv4 prefix the peer no longer
    /// advertises (or that failed a re-check). The shard drops the
    /// Adj-RIB-In row (when `rib_in`) and the Loc-RIB row, then replies
    /// with the best-path delta. Dispatched to the owning pool shard for
    /// v4-unicast at N>1; VPNv4 stays on the synchronous shard.
    WithdrawV4 {
        ident: usize,
        rd: Option<RouteDistinguisher>,
        nlri: Ipv4Nlri,
        /// Mirrors `route_ipv4_withdraw`'s `rib_in`: when set the
        /// withdraw came from the peer, so the shard must also drop the
        /// Adj-RIB-In row (else a soft-reconfig replay re-injects the
        /// route). `false` for internal re-evaluations.
        rib_in: bool,
    },

    /// A received IPv6-unicast (`rd = None`) or VPNv6 (`rd = Some`)
    /// route. Unlike v4 there is no inbound-policy stage (the v6
    /// ingest path has none today), so the carried `attr` is final:
    /// the shard stores it in Adj-RIB-In + Loc-RIB and replies with
    /// [`ShardOut::BestPathV6`].
    UpdateV6(ShardUpdateV6),

    /// Withdraw of an IPv6 / VPNv6 prefix.
    #[allow(dead_code)] // reserved: v6 / VPN aren't pooled (synchronous shard at every N)
    WithdrawV6 {
        ident: usize,
        rd: Option<RouteDistinguisher>,
        nlri: Ipv6Nlri,
    },

    /// A received IPv4 / IPv6 Labeled-Unicast (SAFI 4) route. Like v6
    /// there is no inbound policy; additionally the shard mints a
    /// per-prefix *local* label (from its own sub-block) so a
    /// next-hop-self re-advertisement forwards via a swap ILM. Main
    /// has already stamped the MP_REACH next-hop onto `attr`.
    #[allow(dead_code)] // reserved: LU isn't pooled (synchronous shard at every N)
    UpdateLu(ShardUpdateLu),

    /// Withdraw of a Labeled-Unicast prefix (v4 or v6, per `nlri`).
    #[allow(dead_code)] // reserved: LU isn't pooled (synchronous shard at every N)
    WithdrawLu { ident: usize, nlri: LuNlri },

    /// A peer left Established: the shard drops the peer's Adj-RIB-In
    /// slice across every sharded family and replies with a
    /// [`ShardOut::BestPathV4`] per contributed prefix — re-electing
    /// any surviving path (another peer may now win) or signalling a
    /// withdraw (empty winners). Centralizing the sweep here closes the
    /// "new SAFI forgot a route_clean block" bug-class (#1329). At N>1
    /// `route_clean` dispatches this to every pool shard so each sweeps
    /// the peer's v4-unicast slice.
    PeerDown { ident: usize },

    /// Re-apply the peer's current inbound policy (the replicated
    /// `in_policy` snapshot) to its stored v4-unicast Adj-RIB-In and
    /// report the best-path deltas — the shard half of
    /// `route_soft_in_peer_table`. At N>1 `apply_soft_in_peer` dispatches
    /// this to every pool shard right after a `PolicyReplace`, so a policy
    /// change (or `clear … soft in`) re-converges the pool-owned Loc-RIB
    /// without the peer re-sending. v4-unicast only; VPNv4 soft-in stays
    /// on the synchronous shard.
    SoftInV4 { ident: usize },

    /// Render a sharded Loc-RIB table for a `show` command — the
    /// scatter-gather half of the show split. The reply travels on the
    /// request's own oneshot channel, not [`ShardOut`].
    #[allow(dead_code)] // reserved: the sharded show scatter-gather is not yet wired
    Show(crate::config::DisplayRequest),

    /// Replace (or clear, `policy = None`) a peer's inbound policy
    /// snapshot so the shard applies the operator's real route-map /
    /// prefix-list in `compute_policy` instead of default-permit. Pushed
    /// by main whenever the policy actor resolves a peer's inbound policy
    /// ([`crate::bgp::inst::Bgp::shard_replace_in_policy`]); broadcast to
    /// every shard since a peer's prefixes hash across all of them.
    PolicyReplace {
        ident: usize,
        policy: Option<std::sync::Arc<super::InPolicy>>,
    },

    /// Re-evaluate a batch of IPv4-unicast prefixes that share a next-hop,
    /// after that next-hop's reachability flipped (`RibRx::NexthopUpdate`).
    /// All of the next-hop's dependent prefixes hashing to this shard ride
    /// one message (RouteBatch-style) rather than one dispatch per prefix —
    /// collapsing the futex storm when a first-seen next-hop resolves and
    /// releases a whole table's worth of held routes at once. The shard
    /// refreshes each row's gate flag and re-runs best-path WITHOUT
    /// removing it, replying with one [`ShardOut::BestPathV4`] per prefix
    /// so the reduce reconciles the FIB + re-advertises. v4-unicast only —
    /// v6 / LU / VPN re-evals stay on the synchronous shard.
    NexthopReachableBatchV4 {
        nlris: Vec<Ipv4Nlri>,
        nh: IpAddr,
        reachable: bool,
    },

    /// A2 step ① — fan a session-up IPv4-unicast dump across the pool.
    /// Broadcast to every shard for one peer; `req_id` correlates the
    /// per-shard acks. Each shard builds + filters + encodes + sends its
    /// own v4-unicast slice directly to the peer from the shared
    /// `Arc<SyncCtx>` (the `&Peer`-free egress snapshot — step ②), parking
    /// on the Tier-1b gauge, then replies with [`ShardOut::DumpDoneV4`].
    /// Main counts the N acks (a per-`req_id` barrier) and emits EoR on the
    /// last (step ③/④). The shard handler is a stub ack at step ①.
    /// v4-unicast only; N=1 uses the resumable cursor, not this.
    DumpV4 {
        req_id: u64,
        ctx: std::sync::Arc<SyncCtx>,
        params: DumpParamsV4,
    },

    /// A2 ⑤ — scatter-gather one peer's IPv4-unicast Adj-RIB-In for a
    /// `show … received-routes` at N>1, where the authoritative adj_in
    /// lives in the pool shards (not main's Loc-RIB mirror). Each shard
    /// replies on the request's own oneshot with its slice of peer
    /// `ident`'s received v4 routes (one `(prefix, paths)` per prefix it
    /// owns); main merges the N replies and renders. Read-only, so it
    /// returns no [`ShardOut`].
    DumpAdjInV4 {
        ident: usize,
        reply: tokio::sync::oneshot::Sender<Vec<(ipnet::Ipv4Net, Vec<BgpRib>)>>,
    },

    /// Tear the shard task down; its event loop exits on the next
    /// iteration. Used at daemon shutdown.
    Shutdown,
}

/// Per-dump egress params a [`ShardMsg::DumpV4`] carries — the peer-derived
/// inputs a shard can't reconstruct without the `Peer`, resolved on main in
/// `broadcast_dump_v4`: AddPath-send, the LLGR capability (for the
/// stale-route gate, RFC 9494 §4.3), the RFC 8950 ENHE next-hop (`Some`
/// only on an IPv4-over-IPv6 session), and the Tier-1b egress high-water
/// mark the shard parks against. All `Copy`, so the broadcast closure
/// stamps each shard's message cheaply.
#[derive(Debug, Clone, Copy)]
pub struct DumpParamsV4 {
    pub add_path: bool,
    pub llgr_v4: bool,
    pub enhe_v6: Option<Ipv4MpReachNextHop>,
    pub egress_high_water: usize,
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
    /// RIB sharding Phase C: when `true`, the shard applies inbound policy
    /// itself (on `attr`) instead of using `decision` — moving the policy
    /// walk off the main task into the parallel shard. Set by the N>1
    /// ingest; `false` on the synchronous (N=1) path, where main already
    /// computed `decision`.
    pub compute_policy: bool,
}

/// Payload of [`ShardMsg::RouteBatchV4`]: the IPv4-unicast NLRIs from one
/// UPDATE that hash to a single shard, plus the attribute they share
/// (cloned once per shard, not per prefix). The shard expands each NLRI
/// into the same work an [`ShardUpdateV4`] with `compute_policy` does.
#[derive(Debug)]
pub struct ShardRouteBatchV4 {
    pub ident: usize,
    pub peer_router_id: Ipv4Addr,
    pub typ: BgpRibType,
    pub attr: bgp_packet::BgpAttr,
    pub nlris: Vec<Ipv4Nlri>,
    pub enhe_egress: Option<(std::net::Ipv6Addr, u32)>,
    pub stale: bool,
    pub nexthop_reachable: bool,
    pub compute_policy: bool,
}

/// Payload of [`ShardMsg::UpdateV6`]. Mirrors [`ShardUpdateV4`]: `attr`
/// is the pre-policy attribute for Adj-RIB-In; `decision` is the
/// post-policy result (`None` = inbound policy denied the route, so the
/// shard withdraws any prior Loc-RIB entry).
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
    pub decision: Option<PolicyDecision>,
}

/// IPv4-or-IPv6 Labeled-Unicast NLRI — lets one `UpdateLu` /
/// `WithdrawLu` / `BestPathLu` cover both LU families.
#[derive(Debug, Clone)]
pub enum LuNlri {
    V4(Ipv4Nlri),
    V6(Ipv6Nlri),
}

impl LuNlri {
    /// The NLRI's AddPath / remote path id (the `BgpRib::remote_id`).
    pub fn id(&self) -> u32 {
        match self {
            LuNlri::V4(n) => n.id,
            LuNlri::V6(n) => n.id,
        }
    }
}

/// Payload of [`ShardMsg::UpdateLu`]. `attr` is final (LU has no
/// inbound policy) with the MP_REACH next-hop already stamped by main;
/// `received_label` is the label the peer advertised (stored on the
/// row), distinct from the local label the shard mints.
#[derive(Debug)]
pub struct ShardUpdateLu {
    pub ident: usize,
    pub nlri: LuNlri,
    pub peer_router_id: Ipv4Addr,
    pub typ: BgpRibType,
    pub attr: bgp_packet::BgpAttr,
    pub received_label: Label,
    pub stale: bool,
    /// See [`ShardUpdateV4::nexthop_reachable`].
    pub nexthop_reachable: bool,
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
        /// The row just added to the Loc-RIB, with its assigned
        /// `local_id` — `Some` on an accepted update, `None` on a
        /// withdraw / policy-deny. AddPath advertises this specific
        /// path (best or not); a `None` with non-empty `replaced` is a
        /// path removal that AddPath peers must be withdrawn from.
        added: Option<BgpRib>,
        /// Distinct BGP next-hops still in use by surviving candidates
        /// after the update — read by main's NHT untrack so it doesn't
        /// release a next-hop another path still needs. Computed by the
        /// shard (it owns the Loc-RIB) since main can't see the table.
        survivor_nexthops: BTreeSet<IpAddr>,
    },

    /// IPv6 / VPNv6 counterpart of [`Self::BestPathV4`].
    BestPathV6 {
        // Symmetric with `BestPathV4.ident`; the v6 reduce derives
        // split-horizon from the surviving path, so it isn't read here.
        #[allow(dead_code)]
        ident: usize,
        rd: Option<RouteDistinguisher>,
        prefix: Ipv6Nlri,
        selected: Vec<BgpRib>,
        replaced: Vec<BgpRib>,
        /// VPNv6 AddPath: the just-updated candidate path with its
        /// allocated `local_id`, advertised as one of several paths
        /// (independent of whether it won best-path). `None` for
        /// v6-unicast and for withdraw / peer-down deltas.
        added: Option<BgpRib>,
        survivor_nexthops: BTreeSet<IpAddr>,
    },

    /// Labeled-Unicast (v4 or v6, per `prefix`) best-path delta.
    /// Constructed by `handle_update_lu` but not yet consumed — LU runs the
    /// synchronous-shard path, so the reduce reads BestPathV4/V6, not this.
    /// Reserved for when LU dispatches through the pool.
    #[allow(dead_code)]
    BestPathLu {
        ident: usize,
        prefix: LuNlri,
        selected: Vec<BgpRib>,
        replaced: Vec<BgpRib>,
        survivor_nexthops: BTreeSet<IpAddr>,
    },

    /// One shard's acknowledgement that it finished its slice of a
    /// [`ShardMsg::DumpV4`] for peer `ident`. `sent` is the number of
    /// UPDATEs this shard enqueued; `advertised` are the `(nlri, rib)`
    /// rows it sent — main records them into the peer's Adj-RIB-Out (step
    /// ③) so a later withdraw reaches a peer that learned the prefix via
    /// this dump. Main also decrements the `req_id`'s outstanding-ack
    /// count and, on the last ack, emits EoR (step ③/④). The rows carry
    /// the post-policy attr interned in the *shard's* store; main records
    /// them as-is (adj_out's withdraw gate is presence-keyed, so the Arc
    /// identity only costs an occasional duplicate UPDATE if the
    /// event-driven path races the dump — never correctness).
    DumpDoneV4 {
        req_id: u64,
        ident: usize,
        sent: usize,
        advertised: Vec<(Ipv4Nlri, BgpRib)>,
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
            compute_policy: false,
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
        assert!(matches!(
            ShardMsg::PeerDown { ident: 1 },
            ShardMsg::PeerDown { .. }
        ));
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
            added: None,
            survivor_nexthops: BTreeSet::new(),
        };
        let ShardOut::BestPathV4 { selected, .. } = out else {
            panic!("expected BestPathV4");
        };
        assert!(selected.is_empty(), "empty winners ⇒ withdraw");
    }
}
