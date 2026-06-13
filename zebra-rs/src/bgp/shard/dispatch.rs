//! [`BgpShard::handle`] — the shard's message dispatcher (RIB sharding
//! plan B.3, sync-dispatch form).
//!
//! The route pipeline applies ingest to the shard-scope Loc-RIB by
//! building a [`ShardMsg`], calling [`BgpShard::handle`] synchronously,
//! and acting on the returned [`ShardOut`] delta — instead of poking
//! the tables inline. `handle` is the *shard half* of the pipeline:
//! Adj-RIB-In store, attribute intern, Loc-RIB update + best-path, and
//! the per-route label. The peer checks, inbound policy, NHT
//! registration, advertise fan-out, and FIB install stay in main and
//! run off the delta (see [`super::msg`]).
//!
//! This keeps the table ops behind the same protocol a future shard
//! *task* would speak, so C.1 (real N>1 parallelism) is a mechanical
//! cutover — `shard.handle(msg)` becomes `shard_handle.request(msg)
//! .await` — without re-deriving the pipeline split.

use std::sync::Arc;

use bgp_packet::{Ipv4Nlri, Ipv6Nlri, RouteDistinguisher};

use super::super::route::BgpRib;
use super::super::vrf::VrfLabelAllocator;
use super::BgpShard;
use super::msg::{LuNlri, ShardMsg, ShardOut, ShardUpdateLu, ShardUpdateV4, ShardUpdateV6};

impl BgpShard {
    /// Apply one message to the shard's owned state, returning the
    /// deltas main must act on. `central` is the central MPLS label
    /// allocator, borrowed for the Labeled-Unicast label-mint refill
    /// (`None` on paths that mint no label). `Show` / `Shutdown` carry
    /// no table op and return nothing here.
    pub fn handle(
        &mut self,
        msg: ShardMsg,
        central: Option<&mut VrfLabelAllocator>,
    ) -> Vec<ShardOut> {
        match msg {
            ShardMsg::UpdateV4(u) => self.handle_update_v4(u),
            ShardMsg::WithdrawV4 { ident, rd, nlri } => {
                vec![self.best_path_delta_v4(ident, rd, nlri, Vec::new())]
            }
            ShardMsg::UpdateV6(u) => self.handle_update_v6(u),
            ShardMsg::WithdrawV6 { ident, rd, nlri } => {
                vec![self.best_path_delta_v6(ident, rd, nlri, Vec::new())]
            }
            ShardMsg::UpdateLu(u) => self.handle_update_lu(u, central),
            ShardMsg::WithdrawLu { ident, nlri } => {
                vec![self.best_path_delta_lu(ident, nlri, Vec::new())]
            }
            ShardMsg::PeerDown { ident } => self.handle_peer_down(ident),
            ShardMsg::Show(_) | ShardMsg::Shutdown => Vec::new(),
        }
    }

    /// Shard half of `route_ipv4_update`: store Adj-RIB-In (pre-policy,
    /// un-interned like `BgpRib::new`), and — if main's policy-in
    /// permitted the route — intern the post-policy attribute, mint the
    /// VPNv4 transit label, update the Loc-RIB, and report the
    /// best-path delta. A denied route (`decision == None`) keeps its
    /// Adj-RIB-In entry but withdraws any prior Loc-RIB row.
    fn handle_update_v4(&mut self, u: ShardUpdateV4) -> Vec<ShardOut> {
        let ShardUpdateV4 {
            ident,
            rd,
            nlri,
            peer_router_id,
            typ,
            attr,
            label,
            nexthop,
            enhe_egress,
            stale,
            nexthop_reachable,
            vrf_transit_only,
            decision,
        } = u;

        // The message owns the pre-policy attr; move it straight into
        // the row's `Arc` (no deep clone) — it only feeds Adj-RIB-In
        // here, since the Loc-RIB row gets the interned post-policy attr.
        let mut rib = BgpRib::new_arc(
            ident,
            peer_router_id,
            typ,
            nlri.id,
            0,
            Arc::new(attr),
            label,
            nexthop,
            stale,
        );
        rib.enhe_egress = enhe_egress;
        // Adj-RIB-In keeps the pre-policy attribute (soft-reconfig replay).
        self.adj_in_mut(ident).add(rd, nlri.prefix, rib.clone());

        let Some(decision) = decision else {
            // Inbound policy denied: drop any Loc-RIB row from this peer.
            let removed = self.remove(rd, nlri.prefix, nlri.id, ident);
            return vec![self.best_path_delta_v4(ident, rd, nlri, removed)];
        };

        rib.attr = self.intern(decision.attr);
        rib.weight = decision.weight;
        // Main resolved next-hop reachability via NHT; gate the row with
        // it before best-path (it's a tiebreaker / FIB-eligibility input).
        rib.nexthop_reachable = nexthop_reachable;
        rib.vrf_transit_only = vrf_transit_only;
        if let Some(rd) = rd {
            // VPNv4 transit local label (Inter-AS Option B). Drawn from
            // the shard's own sub-block; `None` central refill until
            // LabelBlockLow lands (B.3 follow-up).
            rib.local_label = self.labels.label_vpn_v4(None, rd, nlri.prefix);
        }
        // Snapshot the row (for AddPath advertise) and stamp the
        // `local_id` the update assigns to it.
        let mut added = rib.clone();
        let (replaced, selected, next_id) = self.update(rd, nlri.prefix, rib);
        added.local_id = next_id;
        // Survivors are only read by main's NHT untrack, which runs
        // only when a row was displaced — skip the candidate walk
        // otherwise (the common add-a-candidate case), matching the
        // inline path's gating.
        let survivor_nexthops = if replaced.is_empty() {
            std::collections::BTreeSet::new()
        } else {
            self.candidate_nexthops_v4(rd, nlri.prefix)
        };
        vec![ShardOut::BestPathV4 {
            ident,
            rd,
            prefix: nlri,
            selected,
            replaced,
            added: Some(added),
            survivor_nexthops,
        }]
    }

    /// Build a [`ShardOut::BestPathV4`] after removing a prefix from
    /// the Loc-RIB: re-select the winners and report the displaced
    /// rows + surviving next-hops. `extra_replaced` folds in rows the
    /// caller already removed (the policy-deny path).
    fn best_path_delta_v4(
        &mut self,
        ident: usize,
        rd: Option<RouteDistinguisher>,
        nlri: Ipv4Nlri,
        mut extra_replaced: Vec<BgpRib>,
    ) -> ShardOut {
        // For an explicit withdraw the caller passes an empty
        // `extra_replaced`; remove this peer's contribution here.
        if extra_replaced.is_empty() {
            extra_replaced = self.remove(rd, nlri.prefix, nlri.id, ident);
        }
        let selected = match rd {
            Some(rd) => self.select_best_path_vpn(&rd, nlri.prefix),
            None => self.select_best_path(nlri.prefix),
        };
        let survivor_nexthops = self.candidate_nexthops_v4(rd, nlri.prefix);
        ShardOut::BestPathV4 {
            ident,
            rd,
            prefix: nlri,
            selected,
            replaced: extra_replaced,
            added: None,
            survivor_nexthops,
        }
    }

    /// Shard half of `route_ipv6_update`. Mirrors `handle_update_v4`:
    /// store the pre-policy attribute in Adj-RIB-In (un-interned, for
    /// soft-reconfig), then — if inbound policy permitted the route —
    /// intern the post-policy attribute into the Loc-RIB, gate with
    /// main's NHT result, update, and report the best-path delta. A
    /// denied route (`decision == None`) withdraws any prior Loc-RIB row.
    fn handle_update_v6(&mut self, u: ShardUpdateV6) -> Vec<ShardOut> {
        let ShardUpdateV6 {
            ident,
            rd,
            nlri,
            peer_router_id,
            typ,
            attr,
            label,
            nexthop,
            stale,
            nexthop_reachable,
            vrf_transit_only,
            decision,
        } = u;

        // Adj-RIB-In keeps the pre-policy attribute (soft-reconfig
        // replay); move it straight into the row's `Arc` (no deep clone)
        // since the Loc-RIB row gets the interned post-policy attr.
        let mut rib = BgpRib::new_arc(
            ident,
            peer_router_id,
            typ,
            nlri.id,
            0,
            Arc::new(attr),
            label,
            nexthop,
            stale,
        );
        match rd {
            Some(rd) => self
                .adj_in_mut(ident)
                .add_v6vpn(rd, nlri.prefix, rib.clone()),
            None => self.adj_in_mut(ident).add_v6(nlri.prefix, rib.clone()),
        };

        let Some(decision) = decision else {
            // Inbound policy denied: drop any Loc-RIB row from this peer.
            let removed = match rd {
                Some(rd) => self.remove_v6vpn(rd, nlri.prefix, nlri.id, ident),
                None => self.remove_v6(nlri.prefix, nlri.id, ident),
            };
            return vec![self.best_path_delta_v6(ident, rd, nlri, removed)];
        };

        rib.attr = self.intern(decision.attr);
        rib.weight = decision.weight;
        rib.nexthop_reachable = nexthop_reachable;
        rib.vrf_transit_only = vrf_transit_only;
        let (replaced, selected, _next_id) = match rd {
            Some(rd) => self.update_v6vpn(rd, nlri.prefix, rib),
            None => self.update_v6(nlri.prefix, rib),
        };
        let survivor_nexthops = if replaced.is_empty() {
            std::collections::BTreeSet::new()
        } else {
            self.candidate_nexthops_v6(rd, nlri.prefix)
        };
        vec![ShardOut::BestPathV6 {
            ident,
            rd,
            prefix: nlri,
            selected,
            replaced,
            survivor_nexthops,
        }]
    }

    /// v6 counterpart of [`Self::best_path_delta_v4`].
    fn best_path_delta_v6(
        &mut self,
        ident: usize,
        rd: Option<RouteDistinguisher>,
        nlri: Ipv6Nlri,
        mut extra_replaced: Vec<BgpRib>,
    ) -> ShardOut {
        if extra_replaced.is_empty() {
            extra_replaced = match rd {
                Some(rd) => self.remove_v6vpn(rd, nlri.prefix, nlri.id, ident),
                None => self.remove_v6(nlri.prefix, nlri.id, ident),
            };
        }
        let selected = match rd {
            Some(rd) => self.select_best_path_vpn_v6(&rd, nlri.prefix),
            None => self.select_best_path_v6(nlri.prefix),
        };
        let survivor_nexthops = self.candidate_nexthops_v6(rd, nlri.prefix);
        ShardOut::BestPathV6 {
            ident,
            rd,
            prefix: nlri,
            selected,
            replaced: extra_replaced,
            survivor_nexthops,
        }
    }

    /// Shard half of `route_labelv4_update` / `route_labelv6_update`.
    /// No inbound policy; the shard mints a per-prefix local label from
    /// its own sub-block (`None` central refill until LabelBlockLow).
    fn handle_update_lu(
        &mut self,
        u: ShardUpdateLu,
        central: Option<&mut VrfLabelAllocator>,
    ) -> Vec<ShardOut> {
        let ShardUpdateLu {
            ident,
            nlri,
            peer_router_id,
            typ,
            attr,
            received_label,
            stale,
            nexthop_reachable,
        } = u;
        // No inbound policy (like v6): Adj-RIB-In and Loc-RIB share one
        // interned attr.
        let attr = self.intern(attr);
        let mut rib = BgpRib::new_arc(
            ident,
            peer_router_id,
            typ,
            nlri.id(),
            0,
            attr,
            Some(received_label),
            None,
            stale,
        );
        match &nlri {
            LuNlri::V4(n) => self.adj_in_mut(ident).add_v4lu(n.prefix, rib.clone()),
            LuNlri::V6(n) => self.adj_in_mut(ident).add_v6lu(n.prefix, rib.clone()),
        };
        rib.nexthop_reachable = nexthop_reachable;
        let (replaced, selected, survivor_nexthops) = match &nlri {
            LuNlri::V4(n) => {
                rib.local_label = self.labels.label_lu_v4(central, n.prefix);
                let (replaced, selected, _) = self.update_v4lu(n.prefix, rib);
                (replaced, selected, self.candidate_nexthops_v4lu(n.prefix))
            }
            LuNlri::V6(n) => {
                rib.local_label = self.labels.label_lu_v6(central, n.prefix);
                let (replaced, selected, _) = self.update_v6lu(n.prefix, rib);
                (replaced, selected, self.candidate_nexthops_v6lu(n.prefix))
            }
        };
        vec![ShardOut::BestPathLu {
            ident,
            prefix: nlri,
            selected,
            replaced,
            survivor_nexthops,
        }]
    }

    /// LU counterpart of [`Self::best_path_delta_v4`].
    fn best_path_delta_lu(
        &mut self,
        ident: usize,
        nlri: LuNlri,
        mut extra_replaced: Vec<BgpRib>,
    ) -> ShardOut {
        if extra_replaced.is_empty() {
            extra_replaced = match &nlri {
                LuNlri::V4(n) => self.remove_v4lu(n.prefix, n.id, ident),
                LuNlri::V6(n) => self.remove_v6lu(n.prefix, n.id, ident),
            };
        }
        let (selected, survivor_nexthops) = match &nlri {
            LuNlri::V4(n) => (
                self.select_best_path_v4lu(n.prefix),
                self.candidate_nexthops_v4lu(n.prefix),
            ),
            LuNlri::V6(n) => (
                self.select_best_path_v6lu(n.prefix),
                self.candidate_nexthops_v6lu(n.prefix),
            ),
        };
        ShardOut::BestPathLu {
            ident,
            prefix: nlri,
            selected,
            replaced: extra_replaced,
            survivor_nexthops,
        }
    }

    /// Drop a departed peer's Adj-RIB-In slice and withdraw every IPv4
    /// route it contributed — the shard half of `route_clean` for the
    /// v4 families. Returns one withdrawal per affected prefix for main
    /// to fan out + tear down in the FIB.
    fn handle_peer_down(&mut self, ident: usize) -> Vec<ShardOut> {
        let mut out = Vec::new();
        // Collect the peer's received v4 prefixes from its Adj-RIB-In
        // slice (unicast + VPNv4), then withdraw each from the Loc-RIB.
        let (v4, v4vpn): (Vec<Ipv4Nlri>, Vec<(RouteDistinguisher, Ipv4Nlri)>) =
            match self.adj_in(ident) {
                Some(a) => {
                    let v4 =
                        a.v4.0
                            .iter()
                            .flat_map(|(p, ribs)| {
                                ribs.iter().map(move |r| Ipv4Nlri {
                                    id: r.remote_id,
                                    prefix: *p,
                                })
                            })
                            .collect();
                    let v4vpn = a
                        .v4vpn
                        .iter()
                        .flat_map(|(rd, t)| {
                            t.0.iter().flat_map(move |(p, ribs)| {
                                ribs.iter().map(move |r| {
                                    (
                                        *rd,
                                        Ipv4Nlri {
                                            id: r.remote_id,
                                            prefix: *p,
                                        },
                                    )
                                })
                            })
                        })
                        .collect();
                    (v4, v4vpn)
                }
                None => (Vec::new(), Vec::new()),
            };
        let (v6, v6vpn): (Vec<Ipv6Nlri>, Vec<(RouteDistinguisher, Ipv6Nlri)>) =
            match self.adj_in(ident) {
                Some(a) => {
                    let v6 =
                        a.v6.0
                            .iter()
                            .flat_map(|(p, ribs)| {
                                ribs.iter().map(move |r| Ipv6Nlri {
                                    id: r.remote_id,
                                    prefix: *p,
                                })
                            })
                            .collect();
                    let v6vpn = a
                        .v6vpn
                        .iter()
                        .flat_map(|(rd, t)| {
                            t.0.iter().flat_map(move |(p, ribs)| {
                                ribs.iter().map(move |r| {
                                    (
                                        *rd,
                                        Ipv6Nlri {
                                            id: r.remote_id,
                                            prefix: *p,
                                        },
                                    )
                                })
                            })
                        })
                        .collect();
                    (v6, v6vpn)
                }
                None => (Vec::new(), Vec::new()),
            };
        for nlri in v4 {
            // Re-select after removing this peer's row: another peer may
            // now win the prefix (then main re-advertises), or the
            // prefix is gone (empty winners ⇒ main withdraws).
            out.push(self.best_path_delta_v4(ident, None, nlri, Vec::new()));
        }
        for (rd, nlri) in v4vpn {
            out.push(self.best_path_delta_v4(ident, Some(rd), nlri, Vec::new()));
        }
        for nlri in v6 {
            out.push(self.best_path_delta_v6(ident, None, nlri, Vec::new()));
        }
        for (rd, nlri) in v6vpn {
            out.push(self.best_path_delta_v6(ident, Some(rd), nlri, Vec::new()));
        }
        // Labeled-Unicast (v4lu / v6lu).
        let lu: Vec<LuNlri> = match self.adj_in(ident) {
            Some(a) => a
                .v4lu
                .0
                .iter()
                .flat_map(|(p, ribs)| {
                    ribs.iter().map(move |r| {
                        LuNlri::V4(Ipv4Nlri {
                            id: r.remote_id,
                            prefix: *p,
                        })
                    })
                })
                .chain(a.v6lu.0.iter().flat_map(|(p, ribs)| {
                    ribs.iter().map(move |r| {
                        LuNlri::V6(Ipv6Nlri {
                            id: r.remote_id,
                            prefix: *p,
                        })
                    })
                }))
                .collect(),
            None => Vec::new(),
        };
        for nlri in lu {
            out.push(self.best_path_delta_lu(ident, nlri, Vec::new()));
        }
        self.adj_in_drop(ident);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::route::{BgpRibType, PolicyDecision};
    use super::*;
    use bgp_packet::{BgpAttr, BgpNexthop};

    fn v4(s: &str) -> Ipv4Nlri {
        Ipv4Nlri {
            id: 0,
            prefix: s.parse().unwrap(),
        }
    }

    fn attr_with_nh(nh: &str) -> BgpAttr {
        let mut a = BgpAttr::default();
        a.nexthop = Some(BgpNexthop::Ipv4(nh.parse().unwrap()));
        a
    }

    fn update_v4(ident: usize, prefix: &str, nh: &str, permit: bool) -> ShardMsg {
        let attr = attr_with_nh(nh);
        ShardMsg::UpdateV4(ShardUpdateV4 {
            ident,
            rd: None,
            nlri: v4(prefix),
            peer_router_id: std::net::Ipv4Addr::new(10, 0, 0, 1),
            typ: BgpRibType::EBGP,
            attr: attr.clone(),
            label: None,
            nexthop: None,
            enhe_egress: None,
            stale: false,
            nexthop_reachable: true,
            vrf_transit_only: false,
            decision: permit.then(|| PolicyDecision { attr, weight: 100 }),
        })
    }

    fn v6(s: &str) -> Ipv6Nlri {
        Ipv6Nlri {
            id: 0,
            prefix: s.parse().unwrap(),
        }
    }

    fn update_v6(ident: usize, prefix: &str) -> ShardMsg {
        let mut attr = BgpAttr::default();
        attr.nexthop = Some(BgpNexthop::Ipv6("2001:db8::1".parse().unwrap()));
        ShardMsg::UpdateV6(ShardUpdateV6 {
            ident,
            rd: None,
            nlri: v6(prefix),
            peer_router_id: std::net::Ipv4Addr::new(10, 0, 0, 1),
            typ: BgpRibType::EBGP,
            attr: attr.clone(),
            label: None,
            nexthop: None,
            stale: false,
            nexthop_reachable: true,
            vrf_transit_only: false,
            decision: Some(PolicyDecision { attr, weight: 100 }),
        })
    }

    fn update_lu_v4(ident: usize, prefix: &str, recv_label: u32) -> ShardMsg {
        ShardMsg::UpdateLu(ShardUpdateLu {
            ident,
            nlri: LuNlri::V4(v4(prefix)),
            peer_router_id: std::net::Ipv4Addr::new(10, 0, 0, 1),
            typ: BgpRibType::EBGP,
            attr: attr_with_nh("192.0.2.1"),
            received_label: bgp_packet::Label::new(recv_label, 0, true),
            stale: false,
            nexthop_reachable: true,
        })
    }

    #[test]
    fn update_lu_v4_installs_and_mints_local_label() {
        let mut shard = BgpShard::default();
        // The shard mints a local label by carving a chunk from the
        // central pool (>= SHARD_LABEL_CHUNK so the carve succeeds).
        let mut central = VrfLabelAllocator::bounded(1000, 5000);
        let out = shard.handle(update_lu_v4(2, "10.0.0.0/24", 50), Some(&mut central));
        assert_eq!(shard.v4lu.0.len(), 1);
        // The Loc-RIB row carries a local label minted from the pool.
        let row = shard.v4lu.0.values().next().unwrap().first().unwrap();
        assert_eq!(row.local_label, Some(1000), "minted from the central pool");
        assert!(matches!(&out[..], [ShardOut::BestPathLu { selected, .. }] if selected.len() == 1));
        // Peer down withdraws it (and re-elects if another peer had it).
        let down = shard.handle(ShardMsg::PeerDown { ident: 2 }, None);
        assert!(
            matches!(&down[..], [ShardOut::BestPathLu { selected, .. }] if selected.is_empty())
        );
        assert!(shard.v4lu.0.is_empty());
    }

    #[test]
    fn update_v6_installs_and_peer_down_withdraws() {
        let mut shard = BgpShard::default();
        // v6 has no inbound policy — the route always installs.
        let out = shard.handle(update_v6(4, "2001:db8:1::/64"), None);
        assert_eq!(shard.v6.0.len(), 1);
        assert_eq!(shard.adj_in(4).unwrap().v6.0.len(), 1);
        assert!(matches!(&out[..], [ShardOut::BestPathV6 { selected, .. }] if selected.len() == 1));
        // Peer down sweeps the v6 route too (handle_peer_down covers v6).
        let down = shard.handle(ShardMsg::PeerDown { ident: 4 }, None);
        assert_eq!(down.len(), 1);
        assert!(
            matches!(&down[..], [ShardOut::BestPathV6 { selected, .. }] if selected.is_empty())
        );
        assert!(shard.v6.0.is_empty());
        assert!(shard.adj_in(4).is_none());
    }

    #[test]
    fn update_v4_installs_and_reports_best_path() {
        let mut shard = BgpShard::default();
        let out = shard.handle(update_v4(1, "10.0.0.0/24", "192.0.2.1", true), None);
        // Loc-RIB got the route.
        assert_eq!(shard.v4.0.len(), 1);
        // Adj-RIB-In stored the received route under the peer.
        assert_eq!(shard.adj_in(1).unwrap().v4.0.len(), 1);
        // The delta names the winner.
        match &out[..] {
            [ShardOut::BestPathV4 { selected, .. }] => {
                assert_eq!(selected.len(), 1, "one best path");
            }
            _ => panic!("expected one BestPathV4, got {out:?}"),
        }
    }

    #[test]
    fn denied_update_keeps_adj_in_but_withdraws_loc_rib() {
        let mut shard = BgpShard::default();
        // First a permitted route from peer 1.
        shard.handle(update_v4(1, "10.0.0.0/24", "192.0.2.1", true), None);
        assert_eq!(shard.v4.0.len(), 1);
        // Peer 1 re-sends the same prefix but policy now denies it.
        let out = shard.handle(update_v4(1, "10.0.0.0/24", "192.0.2.1", false), None);
        // Adj-RIB-In still holds it (for soft-reconfig); Loc-RIB drops it.
        assert_eq!(shard.adj_in(1).unwrap().v4.0.len(), 1);
        assert!(shard.v4.0.is_empty(), "denied route left no Loc-RIB winner");
        match &out[..] {
            [ShardOut::BestPathV4 { selected, .. }] => {
                assert!(selected.is_empty(), "no winner ⇒ main withdraws");
            }
            _ => panic!("expected BestPathV4 withdraw, got {out:?}"),
        }
    }

    #[test]
    fn peer_down_withdraws_all_its_routes_and_drops_slice() {
        let mut shard = BgpShard::default();
        shard.handle(update_v4(7, "10.0.0.0/24", "192.0.2.1", true), None);
        shard.handle(update_v4(7, "10.0.1.0/24", "192.0.2.1", true), None);
        assert_eq!(shard.v4.0.len(), 2);
        let out = shard.handle(ShardMsg::PeerDown { ident: 7 }, None);
        // One BestPathV4 per contributed prefix, each an empty-winner
        // withdraw (peer 7 was the only contributor).
        assert_eq!(out.len(), 2, "one delta per contributed prefix");
        assert!(
            out.iter().all(|o| matches!(
                o,
                ShardOut::BestPathV4 { selected, .. } if selected.is_empty()
            )),
            "every prefix withdrawn (no surviving winner)"
        );
        // select_best_path pruned the now-empty Loc-RIB keys.
        assert!(shard.v4.0.is_empty(), "Loc-RIB emptied");
        assert!(shard.adj_in(7).is_none(), "peer's adj-in slice dropped");
    }
}
