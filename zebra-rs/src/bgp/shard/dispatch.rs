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
use ipnet::Ipv4Net;

use super::super::route::BgpRib;
use super::super::vrf::VrfLabelAllocator;
use super::BgpShard;
use super::msg::{
    LuNlri, ShardMsg, ShardOut, ShardRouteBatchV4, ShardUpdateLu, ShardUpdateV4, ShardUpdateV6,
};

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
            ShardMsg::RouteBatchV4(b) => self.handle_route_batch_v4(b),
            ShardMsg::WithdrawV4 {
                ident,
                rd,
                nlri,
                rib_in,
            } => {
                // Drop the Adj-RIB-In row first, exactly as the
                // synchronous `route_ipv4_withdraw` does on `bgp.shard`,
                // then re-run best-path off the Loc-RIB removal.
                if rib_in {
                    self.adj_in_mut(ident).remove(rd, nlri.prefix, nlri.id);
                }
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
            ShardMsg::SoftInV4 { ident } => self.handle_soft_in_v4(ident),
            ShardMsg::PolicyReplace { ident, policy } => {
                self.set_in_policy(ident, policy);
                Vec::new()
            }
            ShardMsg::NexthopReachableBatchV4 {
                nlris,
                nh,
                reachable,
            } => {
                let mut outs = Vec::with_capacity(nlris.len());
                for nlri in nlris {
                    outs.push(self.reeval_nexthop_v4(nlri, nh, reachable));
                }
                outs
            }
            ShardMsg::DumpV4 { req_id, ctx } => self.handle_dump_v4(req_id, ctx),
            ShardMsg::Show(_) | ShardMsg::Shutdown => Vec::new(),
        }
    }

    /// A2 step ① stub for [`ShardMsg::DumpV4`]: acknowledge the request so
    /// main's per-`req_id` barrier can count this shard. The real work —
    /// walk this shard's v4-unicast Loc-RIB slice, build each row via the
    /// shared `SyncCtx` (the `&Peer`-free egress snapshot), intern locally,
    /// encode, and enqueue on `ctx.packet_tx` with the Tier-1b park while
    /// accumulating `adj_out` deltas — lands in step ②, where `sent`
    /// becomes the per-shard UPDATE count.
    fn handle_dump_v4(
        &mut self,
        req_id: u64,
        _ctx: std::sync::Arc<super::super::route::SyncCtx>,
    ) -> Vec<ShardOut> {
        vec![ShardOut::DumpDoneV4 { req_id, sent: 0 }]
    }

    /// Mirror one pool best-path delta into THIS shard's v4-unicast
    /// Loc-RIB, keeping it a read replica of the pool-owned table.
    ///
    /// At N>1, v4-unicast ingest + best-path run on the worker pool, so
    /// the main shard's `v4` is otherwise empty — and the synchronous
    /// main-task read paths (`route_sync_ipv4` reads `v4.1`; `show bgp
    /// ipv4` reads `v4.0`) would see nothing. The pool reduce, which
    /// already runs on main per delta, calls this to keep both the
    /// candidate (`v4.0`) and best-path (`v4.1`) tables in step, applying
    /// exactly the add / remove the owning pool shard applied — keyed by
    /// `(ident, remote_id)` (source peer + path-id), the same identity
    /// `LocalRibTable::update` uses.
    pub fn mirror_v4(
        &mut self,
        prefix: Ipv4Net,
        added: Option<&BgpRib>,
        replaced: &[BgpRib],
        best: Option<&BgpRib>,
    ) {
        if !replaced.is_empty() || added.is_some() {
            let cands = self.v4.0.entry(prefix).or_default();
            if !replaced.is_empty() {
                cands.retain(|r| {
                    !replaced
                        .iter()
                        .any(|rr| rr.ident == r.ident && rr.remote_id == r.remote_id)
                });
            }
            if let Some(a) = added {
                cands.retain(|r| !(r.ident == a.ident && r.remote_id == a.remote_id));
                cands.push(a.clone());
            }
            if cands.is_empty() {
                self.v4.0.remove(&prefix);
            }
        }
        match best {
            Some(b) => {
                self.v4.1.insert(prefix, b.clone());
            }
            None => {
                self.v4.1.remove(&prefix);
            }
        }
    }

    /// Expand a [`ShardMsg::RouteBatchV4`] into per-NLRI table ops. The
    /// shared attribute is cloned per prefix here — on the worker thread,
    /// in parallel across shards — instead of per prefix on the main task.
    fn handle_route_batch_v4(&mut self, b: ShardRouteBatchV4) -> Vec<ShardOut> {
        let mut outs = Vec::with_capacity(b.nlris.len());
        for nlri in b.nlris {
            outs.extend(self.handle_update_v4(ShardUpdateV4 {
                ident: b.ident,
                rd: None,
                nlri,
                peer_router_id: b.peer_router_id,
                typ: b.typ,
                attr: b.attr.clone(),
                label: None,
                nexthop: None,
                enhe_egress: b.enhe_egress,
                stale: b.stale,
                nexthop_reachable: b.nexthop_reachable,
                vrf_transit_only: false,
                decision: None,
                compute_policy: b.compute_policy,
            }));
        }
        outs
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
            compute_policy,
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

        // RIB sharding Phase C: at N>1 the shard applies inbound policy
        // itself, off the main task — against the peer's replicated
        // snapshot ([`ShardMsg::PolicyReplace`]), falling back to
        // default-permit when none is present (no inbound policy bound, or
        // not yet replicated).
        let decision = if compute_policy {
            match self.in_policy.get(&ident) {
                Some(p) => crate::bgp::route::apply_policy_net(
                    &p.prefix_set,
                    &p.policy_list,
                    peer_router_id,
                    ipnet::IpNet::V4(nlri.prefix),
                    (*rib.attr).clone(),
                    0,
                ),
                None => crate::bgp::route::apply_policy_net(
                    &Default::default(),
                    &Default::default(),
                    peer_router_id,
                    ipnet::IpNet::V4(nlri.prefix),
                    (*rib.attr).clone(),
                    0,
                ),
            }
        } else {
            decision
        };

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

    /// Re-evaluate one IPv4-unicast prefix after its next-hop's
    /// reachability flipped: refresh the gate flag and re-run best-path
    /// WITHOUT removing the row, then report the delta (RIB sharding — the
    /// pool-shard half of `Bgp::nht_reeval_dep` at N>1). `ident` is unused
    /// by the reduce's advertise (it keys split-horizon off the surviving
    /// path), so it is left 0.
    fn reeval_nexthop_v4(
        &mut self,
        nlri: Ipv4Nlri,
        nh: std::net::IpAddr,
        reachable: bool,
    ) -> ShardOut {
        self.v4.set_nexthop_reachable(nlri.prefix, nh, reachable);
        let selected = self.select_best_path(nlri.prefix);
        let survivor_nexthops = self.candidate_nexthops_v4(None, nlri.prefix);
        ShardOut::BestPathV4 {
            ident: 0,
            rd: None,
            prefix: nlri,
            selected,
            replaced: Vec::new(),
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
        // VPNv6 AddPath: clone the candidate before it moves into the
        // table, then stamp its allocated `local_id` after the update so
        // main can advertise it as one of several paths.
        let rib_addpath = rd.is_some().then(|| rib.clone());
        let (replaced, selected, next_id) = match rd {
            Some(rd) => self.update_v6vpn(rd, nlri.prefix, rib),
            None => self.update_v6(nlri.prefix, rib),
        };
        let added = rib_addpath.map(|mut r| {
            r.local_id = next_id;
            r
        });
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
            added,
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
            added: None,
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

    /// Shard half of `route_soft_in_peer_table` (v4-unicast soft-reconfig):
    /// re-apply the peer's current inbound policy — the replicated
    /// `in_policy` snapshot, identical to what `compute_policy` consults —
    /// to every stored v4-unicast Adj-RIB-In row, and report the best-path
    /// deltas so a policy change re-converges the pool-owned Loc-RIB
    /// without the peer re-sending. Mirrors the synchronous path: a
    /// now-denied route drops its Loc-RIB row (Adj-RIB-In kept for the
    /// next replay), a permitted route re-interns + re-runs best-path; the
    /// async reduce drives FIB + advertise (incl. AddPath via `added`).
    /// v4-unicast only — VPNv4 soft-in stays on the synchronous shard.
    fn handle_soft_in_v4(&mut self, ident: usize) -> Vec<ShardOut> {
        // Snapshot the stored rows so the per-row Loc-RIB mutation below
        // doesn't alias the Adj-RIB-In iteration.
        let entries: Vec<(Ipv4Net, Vec<BgpRib>)> = match self.adj_in(ident) {
            Some(a) => a.v4.0.iter().map(|(p, ribs)| (*p, ribs.clone())).collect(),
            None => return Vec::new(),
        };
        let mut outs = Vec::with_capacity(entries.len());
        for (prefix, ribs) in entries {
            for stored in ribs {
                let nlri = Ipv4Nlri {
                    id: stored.remote_id,
                    prefix,
                };
                // Re-run inbound policy against the pre-policy attr kept in
                // Adj-RIB-In, off the replicated snapshot (default-permit
                // when none is bound) — the same call `compute_policy` makes.
                let pre = (*stored.attr).clone();
                let decision = match self.in_policy.get(&ident) {
                    Some(p) => crate::bgp::route::apply_policy_net(
                        &p.prefix_set,
                        &p.policy_list,
                        stored.router_id,
                        ipnet::IpNet::V4(prefix),
                        pre,
                        0,
                    ),
                    None => crate::bgp::route::apply_policy_net(
                        &Default::default(),
                        &Default::default(),
                        stored.router_id,
                        ipnet::IpNet::V4(prefix),
                        pre,
                        0,
                    ),
                };
                match decision {
                    None => {
                        // Denied under the new policy: drop any Loc-RIB row
                        // from this peer (Adj-RIB-In stays for a later replay).
                        outs.push(self.best_path_delta_v4(ident, None, nlri, Vec::new()));
                    }
                    Some(d) => {
                        let mut new_rib = stored.clone();
                        new_rib.attr = self.intern(d.attr);
                        new_rib.weight = d.weight;
                        let mut added = new_rib.clone();
                        let (replaced, selected, next_id) = self.update(None, prefix, new_rib);
                        added.local_id = next_id;
                        let survivor_nexthops = if replaced.is_empty() {
                            std::collections::BTreeSet::new()
                        } else {
                            self.candidate_nexthops_v4(None, prefix)
                        };
                        outs.push(ShardOut::BestPathV4 {
                            ident,
                            rd: None,
                            prefix: nlri,
                            selected,
                            replaced,
                            added: Some(added),
                            survivor_nexthops,
                        });
                    }
                }
            }
        }
        outs
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
        BgpAttr {
            nexthop: Some(BgpNexthop::Ipv4(nh.parse().unwrap())),
            ..Default::default()
        }
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
            decision: permit.then_some(PolicyDecision { attr, weight: 100 }),
            compute_policy: false,
        })
    }

    /// An UPDATE that asks the shard to compute inbound policy itself
    /// (`compute_policy: true`, no pre-computed `decision`) — the N>1 /
    /// RouteBatch path that consults the replicated `PolicyReplace`
    /// snapshot.
    fn update_v4_compute(ident: usize, prefix: &str, nh: &str) -> ShardMsg {
        let attr = attr_with_nh(nh);
        ShardMsg::UpdateV4(ShardUpdateV4 {
            ident,
            rd: None,
            nlri: v4(prefix),
            peer_router_id: std::net::Ipv4Addr::new(10, 0, 0, 1),
            typ: BgpRibType::EBGP,
            attr,
            label: None,
            nexthop: None,
            enhe_egress: None,
            stale: false,
            nexthop_reachable: true,
            vrf_transit_only: false,
            decision: None,
            compute_policy: true,
        })
    }

    fn v6(s: &str) -> Ipv6Nlri {
        Ipv6Nlri {
            id: 0,
            prefix: s.parse().unwrap(),
        }
    }

    fn update_v6(ident: usize, prefix: &str) -> ShardMsg {
        let attr = BgpAttr {
            nexthop: Some(BgpNexthop::Ipv6("2001:db8::1".parse().unwrap())),
            ..Default::default()
        };
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

    #[test]
    fn compute_policy_consults_replicated_snapshot() {
        use super::super::InPolicy;
        use crate::bgp::policy::{PolicyListValue, PrefixSetValue};

        let mut shard = BgpShard::default();

        // No snapshot ⇒ compute_policy falls back to default-permit.
        let out = shard.handle(update_v4_compute(7, "10.0.0.0/24", "192.0.2.1"), None);
        assert!(
            matches!(&out[..], [ShardOut::BestPathV4 { selected, .. }] if selected.len() == 1),
            "no snapshot ⇒ default-permit, route enters Loc-RIB"
        );

        // Replicate a deny: a prefix-set bound by name but unresolved
        // denies every prefix (apply_policy_net: name set + object None).
        let deny = std::sync::Arc::new(InPolicy {
            prefix_set: PrefixSetValue {
                name: Some("deny".into()),
                prefix_set: None,
            },
            policy_list: PolicyListValue::default(),
        });
        shard.set_in_policy(7, Some(deny));
        let out = shard.handle(update_v4_compute(7, "10.0.2.0/24", "192.0.2.1"), None);
        assert!(
            matches!(&out[..], [ShardOut::BestPathV4 { selected, .. }] if selected.is_empty()),
            "replicated deny ⇒ route rejected from Loc-RIB"
        );

        // A peer with no snapshot is unaffected (lookup is per-ident).
        let out = shard.handle(update_v4_compute(9, "10.0.3.0/24", "192.0.2.1"), None);
        assert!(
            matches!(&out[..], [ShardOut::BestPathV4 { selected, .. }] if selected.len() == 1),
            "other peer still default-permits"
        );

        // Clearing the snapshot restores default-permit for peer 7.
        shard.set_in_policy(7, None);
        let out = shard.handle(update_v4_compute(7, "10.0.4.0/24", "192.0.2.1"), None);
        assert!(
            matches!(&out[..], [ShardOut::BestPathV4 { selected, .. }] if selected.len() == 1),
            "cleared snapshot ⇒ default-permit again"
        );
    }

    #[test]
    fn dump_v4_stub_acks_with_req_id() {
        // A2 step ① — the shard acks a DumpV4 so main's barrier can count
        // it; the per-slice build + send is step ②, so `sent` is 0 here.
        let mut shard = BgpShard::default();
        let ctx = std::sync::Arc::new(super::super::super::route::SyncCtx::for_test());
        let out = shard.handle(ShardMsg::DumpV4 { req_id: 42, ctx }, None);
        assert!(matches!(
            out.as_slice(),
            [ShardOut::DumpDoneV4 {
                req_id: 42,
                sent: 0
            }]
        ));
    }
}
