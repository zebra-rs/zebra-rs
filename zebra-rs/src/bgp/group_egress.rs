//! Per-update-group egress task — **the engine (not yet reduce-wired)**.
//!
//! Plan: `docs/design/bgp-egress-group-task-migration.md`. One persistent task
//! per [`UpdateGroup`](super::update_group::UpdateGroup) that — at the end of
//! the migration — owns the group's adj-out + encode and fans bytes to its
//! member peers: **M tasks (groups), not N (peers)**, coalescing *and*
//! off-main-parallel. A per-peer egress task (PET) is the M=1 case.
//!
//! The lifecycle shell (member tracking, idle) came first. This step adds
//! the [`Engine`]: it captures each member's [`SyncCtx`] and can build one
//! best-path advertisement **once** (the shared group transform), record it in
//! the group's `adj_out`, encode it **once**, and **fan** the bytes to every
//! member except the path's source (split-horizon). It is the per-group twin
//! of the PET `Engine` — `send_ipv4_direct` fanned across members.
//!
//! The engine is **not wired into the reduce yet**: `attach`/`detach` feed the member
//! set live (so the engine holds real `SyncCtx`s at gate-on), but no
//! `Advertise`/`Withdraw` delta is routed to it — those land later. So
//! gate-on egress is unchanged; the engine is exercised by the unit tests.
//! Default off; gate-off is byte-identical.

use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, OnceLock};

use bgp_packet::{Ipv4Nlri, UpdatePacket};
use bytes::BytesMut;
use ipnet::Ipv4Net;
use tokio::sync::mpsc::{self, UnboundedSender};
use tokio::time::{Duration, Instant, sleep_until};

/// How long a queued withdrawal waits for the rest of its burst before the
/// engine flushes — the group twin of the PET's delay and of the main-task
/// queue's 1 ms `FlushWithdraw` marker. Lets a peer-down / RR-sweep burst
/// accumulate on the delta channel so it packs into as few UPDATEs as the
/// message size allows, rather than the partial flushes the main-task/engine
/// race would otherwise produce.
const WITHDRAW_FLUSH_DELAY: Duration = Duration::from_millis(1);

use crate::context::task::Task;

use super::adj_rib::{AdjRibTable, Out};
use super::route::{BgpRib, SyncCtx};
use super::store::BgpAttrStore;
use super::update_group::{UpdateGroupId, encode_ipv4_update};

/// `ZEBRA_BGP_EGRESS_GROUP_TASK=1` opts into the per-update-group egress task
/// (the group-task migration). Default off: egress stays on the update-group
/// flush / the per-peer PET, unchanged. Read once — the egress model is fixed
/// for the instance lifetime, like the other sharding gates.
pub fn egress_group_task_enabled() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| {
        std::env::var("ZEBRA_BGP_EGRESS_GROUP_TASK")
            .ok()
            .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
    })
}

/// One egress operation the `attach`/`detach` (and, later, the reduce)
/// machinery forwards to a group's task. `AddMember` carries the member's
/// `SyncCtx` (its packet sink and the shared egress identity) so the engine can
/// build and fan, plus the group's `add_path` flag. `Advertise` and `Withdraw`
/// carry the path's `source_ident` for split-horizon.
#[derive(Debug)]
pub enum GroupEgressDeltaV4 {
    AddMember {
        ident: usize,
        ctx: Box<SyncCtx>,
        add_path: bool,
    },
    RemoveMember {
        ident: usize,
    },
    /// The new best path for `prefix`. The split-horizon source is the path's
    /// own origin (`rib.ident`), derived in the engine — no separate field.
    Advertise {
        prefix: Ipv4Net,
        rib: BgpRib,
    },
    /// A route the session-up sync (`route_sync_ipv4`) already sent to a NEW
    /// member directly — record it in the group `adj_out` *without* re-sending,
    /// so the group's later withdraws reach that member (a late peer that is
    /// the first of a new group would otherwise be invisible to the group).
    /// Mirrors the PET's DumpV4 ③ `RecordAdjOut`.
    RecordAdjOut {
        prefix: Ipv4Net,
        rib: BgpRib,
    },
    /// `prefix` is gone; `source_ident` is the withdrawing peer (excluded from
    /// the fan — it never received the advertisement under split-horizon).
    Withdraw {
        prefix: Ipv4Net,
        id: u32,
        source_ident: usize,
    },
    /// A `show … advertised-routes` request at gate-on: reply with the group's
    /// whole `adj_out` (the caller filters split-horizon per queried peer and
    /// renders). The group adj-out lives here, not on the peer.
    DumpAdjOut {
        reply: tokio::sync::oneshot::Sender<Vec<(Ipv4Net, Vec<BgpRib>)>>,
    },
    /// A `show … summary` PfxSnt request at gate-on: the group `adj_out` is
    /// shared and split-horizon is applied at fan time (not stored), so reply
    /// with the COUNTS needed to derive each member's sent count —
    /// `(total prefix count, {ident → prefixes solely-sourced-by-that-ident})`.
    /// A member M never receives a prefix whose paths it ALL sourced, so
    /// `PfxSnt(M) = total − sole_source[M]`; in the usual case (the path
    /// sources are non-members) the map is empty and every member's PfxSnt is
    /// `total`. Counts only — no prefixes or attributes cross the channel
    /// (unlike [`Self::DumpAdjOut`]).
    CountAdjOut {
        reply: tokio::sync::oneshot::Sender<(usize, BTreeMap<usize, usize>)>,
    },
}

/// Handle main keeps on each [`UpdateGroup`](super::update_group::UpdateGroup)
/// for its egress task. Dropping it — when the group empties in `detach`, or
/// when the whole map is torn down — aborts the task (abort-on-drop) and
/// closes the channel.
#[derive(Debug)]
pub struct GroupEgressTask {
    /// `attach` / `detach` (and, later, the reduce) push deltas here.
    delta_tx: UnboundedSender<GroupEgressDeltaV4>,
    // Held only for its abort-on-drop teardown; the task is driven entirely by
    // the channel, so the handle is never read after spawn.
    #[allow(dead_code)]
    task: Task<()>,
}

impl GroupEgressTask {
    /// Spawn a group's egress task. The [`Engine`] starts empty and fills its
    /// member set from `AddMember` deltas. Exits when `delta_tx` is dropped
    /// (the group emptied).
    pub fn spawn(id: UpdateGroupId) -> Self {
        let (delta_tx, delta_rx) = mpsc::unbounded_channel::<GroupEgressDeltaV4>();
        // `spawn` is a plain constructor with no `BgpTracing` in reach, so
        // both this and the "exited" line below ride the process-global
        // `sharding` gate (see `bgp::tracing::TRACE_SHARDING`). Read once
        // here so the spawned task carries the decision instead of
        // re-reading the global after an unrelated config edit.
        let trace = crate::bgp::tracing::trace_sharding();
        if trace {
            tracing::info!(
                proto = "bgp",
                category = "sharding",
                "BGP egress group task: spawned (group {id:?})"
            );
        }
        let task = Task::spawn(async move {
            let mut engine = Engine::default();
            engine.run(delta_rx).await;
            if trace {
                tracing::info!(
                    proto = "bgp",
                    category = "sharding",
                    "BGP egress group task: exited (group {id:?})"
                );
            }
        });
        GroupEgressTask { delta_tx, task }
    }

    /// Push a delta to the task. A send failure means the task has already
    /// gone (the group is tearing down), which is harmless here.
    pub fn send(&self, delta: GroupEgressDeltaV4) {
        let _ = self.delta_tx.send(delta);
    }

    /// Request the group's adj-out over a oneshot (for `show advertised-routes`
    /// at gate-on). Returns the receiver so the caller can drop any borrow of
    /// the task before awaiting.
    pub fn request_adj_out(&self) -> tokio::sync::oneshot::Receiver<Vec<(Ipv4Net, Vec<BgpRib>)>> {
        let (reply, rx) = tokio::sync::oneshot::channel();
        self.send(GroupEgressDeltaV4::DumpAdjOut { reply });
        rx
    }

    /// Request the group's adj-out COUNTS over a oneshot (for `show … summary`
    /// PfxSnt at gate-on): `(total, {ident → solely-sourced prefix count})`,
    /// from which the caller derives each member's split-horizoned sent count.
    /// Returns the receiver so the caller can drop the task borrow before
    /// awaiting.
    pub fn request_count(&self) -> tokio::sync::oneshot::Receiver<(usize, BTreeMap<usize, usize>)> {
        let (reply, rx) = tokio::sync::oneshot::channel();
        self.send(GroupEgressDeltaV4::CountAdjOut { reply });
        rx
    }

    /// Clone of the delta channel — lets a caller hand the sender off (e.g.
    /// record DumpV4 ③ rows in a loop) without holding a borrow of the task.
    pub fn delta_tx(&self) -> UnboundedSender<GroupEgressDeltaV4> {
        self.delta_tx.clone()
    }
}

/// A group's owned v4-unicast egress state + per-delta logic, run inside the
/// task. The build / out-policy / intern / `adj_out` dedup are identical to
/// the PET `Engine`; the only difference is the **send**: it encodes one
/// best-path advertisement once and fans the bytes to every member except the
/// path's source (split-horizon), instead of to a single peer.
#[derive(Default)]
struct Engine {
    /// Member peer → its `SyncCtx` (the packet sink; the egress-transform
    /// fields are shared across the group, so any member's ctx builds the
    /// canonical bytes).
    members: BTreeMap<usize, SyncCtx>,
    add_path: bool,
    adj_out: AdjRibTable<Out>,
    attr_store: BgpAttrStore,
    /// IPv4 withdrawals accumulated during the current channel-drain batch,
    /// keyed by the path's source peer (the split-horizon target excluded
    /// from that withdrawal's fan). Each source's set is packed into as few
    /// UPDATEs as the message size allows at
    /// [`flush_withdraws`](Self::flush_withdraws) and fanned to the members
    /// that are not that source. Grouping by source keeps a mixed-source
    /// burst correct — a member that sourced one withdrawn path still
    /// receives the withdrawals it did not source.
    pending_withdraw: BTreeMap<usize, HashSet<Ipv4Nlri>>,
}

impl Engine {
    /// Drive the engine off its delta channel, coalescing withdrawal bursts —
    /// the group twin of the PET's `run`. Advertises fan immediately in
    /// [`handle`](Self::handle); withdrawals queue per source and flush once
    /// the burst settles (a `WITHDRAW_FLUSH_DELAY` timer armed when the first
    /// withdrawal queues, re-used for the whole burst). `biased` prefers
    /// draining new deltas over flushing so a burst accumulates into one
    /// flush. Exits when the channel closes (the group emptied); any queued
    /// withdrawal is dropped with it.
    async fn run(&mut self, mut rx: mpsc::UnboundedReceiver<GroupEgressDeltaV4>) {
        let mut flush_at: Option<Instant> = None;
        loop {
            tokio::select! {
                biased;
                maybe = rx.recv() => {
                    let Some(delta) = maybe else { break };
                    self.handle(delta);
                    while let Ok(delta) = rx.try_recv() {
                        self.handle(delta);
                    }
                    if !self.pending_withdraw.is_empty() && flush_at.is_none() {
                        flush_at = Some(Instant::now() + WITHDRAW_FLUSH_DELAY);
                    }
                }
                _ = async { sleep_until(flush_at.unwrap()).await }, if flush_at.is_some() => {
                    self.flush_withdraws();
                    flush_at = None;
                }
            }
        }
    }

    fn handle(&mut self, delta: GroupEgressDeltaV4) {
        match delta {
            GroupEgressDeltaV4::AddMember {
                ident,
                ctx,
                add_path,
            } => {
                self.add_path = add_path;
                self.members.insert(ident, *ctx);
            }
            GroupEgressDeltaV4::RemoveMember { ident } => {
                self.members.remove(&ident);
            }
            GroupEgressDeltaV4::Advertise { prefix, rib } => self.advertise(prefix, rib),
            GroupEgressDeltaV4::RecordAdjOut { prefix, rib } => self.record_adj_out(prefix, rib),
            GroupEgressDeltaV4::Withdraw {
                prefix,
                id,
                source_ident,
            } => self.withdraw(prefix, id, source_ident),
            GroupEgressDeltaV4::DumpAdjOut { reply } => {
                let entries = self
                    .adj_out
                    .0
                    .iter()
                    .map(|(prefix, ribs)| (*prefix, ribs.clone()))
                    .collect();
                let _ = reply.send(entries);
            }
            GroupEgressDeltaV4::CountAdjOut { reply } => {
                // Counts for the summary's PfxSnt. `adj_out.0` is keyed by
                // prefix, so its len is the total prefix count. A prefix is
                // excluded from member M only when EVERY path is from M (fan
                // time drops just the member's own paths, split-horizon), so
                // tally the single-source prefixes per ident — the caller does
                // PfxSnt(M) = total − sole_source[M].
                let total = self.adj_out.0.len();
                let mut sole_source: BTreeMap<usize, usize> = BTreeMap::new();
                for ribs in self.adj_out.0.values() {
                    let mut idents = ribs.iter().map(|r| r.ident);
                    if let Some(first) = idents.next()
                        && idents.all(|id| id == first)
                    {
                        *sole_source.entry(first).or_default() += 1;
                    }
                }
                let _ = reply.send((total, sole_source));
            }
        }
    }

    /// Build one best path for the group's shared egress identity, record it
    /// in `adj_out` (dedup'd by interned-attr pointer identity), encode it
    /// once, and fan to every member except `source_ident`. A build / policy
    /// filter (split-horizon at the source, policy-deny) becomes a withdraw,
    /// exactly as the PET / gate-off `Withdraw` outcome.
    fn advertise(&mut self, prefix: Ipv4Net, mut rib: BgpRib) {
        // Split-horizon target is the path's own source peer.
        let source = rib.ident;
        // Build with a NON-source member's ctx: `route_update_ipv4` drops the
        // advertise when `ctx.ident == rib.ident`, so the source member's ctx
        // would wrongly collapse the whole group advertise into a withdraw.
        // The transform is otherwise group-shared, so any non-source member
        // yields the canonical bytes.
        let Some(ctx) = self
            .members
            .iter()
            .find(|(id, _)| **id != source)
            .map(|(_, c)| c.clone())
        else {
            // Nobody is eligible to receive this route. Do not create a
            // phantom Adj-RIB-Out row: a later session join receives the
            // current Loc-RIB through its direct initial dump.
            return;
        };
        let built = super::route::route_update_ipv4(&ctx, &prefix, &rib, self.add_path).and_then(
            |(nlri, attr)| {
                super::route::route_apply_policy_out(&ctx, &nlri, attr, rib.weight, rib.tag)
                    .map(|d| (nlri, d))
            },
        );
        let Some((nlri, decision)) = built else {
            self.withdraw(prefix, if self.add_path { rib.local_id } else { 0 }, source);
            return;
        };
        let arc = self.attr_store.intern(decision.attr);
        rib.attr = arc.clone();
        let prev = self.adj_out.record_out(prefix, rib, self.add_path);
        let already_sent = prev.is_some_and(|p| Arc::ptr_eq(&p.attr, &arc));
        if !already_sent {
            let bytes_list =
                encode_ipv4_update(&arc, &[nlri], ctx.max_packet_size(), ctx.as4, None);
            self.fan(&bytes_list, source);
        }
    }

    /// Record a session-up-sync row in `adj_out` **without** sending — sync
    /// already delivered the bytes to the new member directly. Re-intern the
    /// (already post-policy) attr in the group's store so the dedup against
    /// the event-driven path stays pointer-consistent. The PET's `record_adj_out`
    /// twin.
    fn record_adj_out(&mut self, prefix: Ipv4Net, mut rib: BgpRib) {
        rib.attr = self.attr_store.intern((*rib.attr).clone());
        self.adj_out.add(prefix, rib);
    }

    /// Drop a path from `adj_out` and, if it had been advertised, fan one
    /// MP_UNREACH to every member except `source_ident`. `id == 0` is the
    /// non-AddPath / whole-prefix withdraw (the wire carries id 0); `id != 0`
    /// is an AddPath per-path withdraw — remove just that path (`adj_out` keys
    /// by the Out local-id), leaving the prefix's other paths advertised.
    fn withdraw(&mut self, prefix: Ipv4Net, id: u32, source_ident: usize) {
        let removed = if id == 0 {
            self.adj_out.0.remove(&prefix).is_some()
        } else {
            self.adj_out.remove(prefix, id).is_some()
        };
        if removed {
            // Queue rather than fan: the batch's withdrawals pack together in
            // `flush_withdraws`. Removing the `adj_out` row here (not at flush)
            // keeps the reconcile authoritative — a re-advertise later in the
            // same batch re-adds the row and cancels this withdrawal.
            self.pending_withdraw
                .entry(source_ident)
                .or_default()
                .insert(Ipv4Nlri { id, prefix });
        }
    }

    /// Drain the batch's queued IPv4 withdrawals. Each source peer's set is
    /// packed into as few UPDATEs as the negotiated message size allows and
    /// fanned to every member except that source (split-horizon — the source
    /// never received the advertisement). A queued NLRI whose `(prefix, id)`
    /// is back in `adj_out` was re-advertised within the batch (`fan` already
    /// put the announcement on the wire), so it is dropped: sending it would
    /// tear down a route the members now hold.
    fn flush_withdraws(&mut self) {
        if self.pending_withdraw.is_empty() {
            return;
        }
        let max = self
            .members
            .values()
            .next()
            .map(|c| c.max_packet_size())
            .unwrap_or(4096);
        let pending = std::mem::take(&mut self.pending_withdraw);
        for (source_ident, queued) in pending {
            let withdraws: Vec<Ipv4Nlri> = queued
                .into_iter()
                .filter(|n| !super::pending_withdraw::adj_out_has(&self.adj_out, &n.prefix, n.id))
                .collect();
            if withdraws.is_empty() {
                continue;
            }
            let mut update = UpdatePacket::with_max_packet_size(max);
            update.ipv4_withdraw = withdraws;
            while let Some(bytes) = update.pop_ipv4_withdraw() {
                self.fan(&[bytes], source_ident);
            }
        }
    }

    /// Fan pre-encoded UPDATE bytes to every member except the path's source.
    /// The encode happened once; this is a cheap per-member buffer clone +
    /// enqueue (the per-member backpressure rides each ctx's `send_packet`).
    fn fan(&self, bytes_list: &[BytesMut], source_ident: usize) {
        for (ident, ctx) in &self.members {
            if *ident == source_ident {
                continue;
            }
            for buf in bytes_list {
                ctx.send_packet(buf.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::route::BgpRibType;
    use super::*;
    use bgp_packet::{BgpAttr, BgpNexthop};

    /// A best-path row from peer `ident`, next-hop `nh` (mirrors the PET
    /// test's `rib`).
    fn rib(ident: usize, nh: &str) -> BgpRib {
        let attr = BgpAttr {
            nexthop: Some(BgpNexthop::Ipv4(nh.parse().unwrap())),
            ..Default::default()
        };
        BgpRib::new_arc(
            ident,
            "10.0.0.1".parse().unwrap(),
            BgpRibType::EBGP,
            0,
            100,
            Arc::new(attr),
            None,
            None,
            false,
        )
    }

    /// Add a member with a readable packet channel via the real `AddMember`
    /// delta (so the protocol path is exercised end to end).
    fn member(engine: &mut Engine, ident: usize) -> mpsc::UnboundedReceiver<BytesMut> {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut ctx = SyncCtx::for_test();
        ctx.packet_tx = Some(tx);
        engine.handle(GroupEgressDeltaV4::AddMember {
            ident,
            ctx: Box::new(ctx),
            add_path: false,
        });
        rx
    }

    /// `src` becomes the path's source (`rib.ident`) — the split-horizon
    /// target the engine derives.
    fn advertise(engine: &mut Engine, prefix: &str, src: usize) {
        engine.handle(GroupEgressDeltaV4::Advertise {
            prefix: prefix.parse().unwrap(),
            rib: rib(src, "192.0.2.1"),
        });
    }

    #[test]
    fn advertise_encodes_once_and_fans_to_all_members_when_source_is_external() {
        let mut engine = Engine::default();
        let mut rx1 = member(&mut engine, 1);
        let mut rx2 = member(&mut engine, 2);
        // source 99 is not a member, so both members receive the advertisement.
        advertise(&mut engine, "10.10.10.0/24", 99);
        assert!(rx1.try_recv().is_ok(), "member 1 receives the advertise");
        assert!(rx2.try_recv().is_ok(), "member 2 receives the advertise");
    }

    #[test]
    fn advertise_excludes_the_source_member_split_horizon() {
        let mut engine = Engine::default();
        let mut rx1 = member(&mut engine, 1);
        let mut rx2 = member(&mut engine, 2);
        // The path's source is member 1 — it must NOT be advertised back to it.
        advertise(&mut engine, "10.10.10.0/24", 1);
        assert!(rx1.try_recv().is_err(), "source member 1 is excluded");
        assert!(rx2.try_recv().is_ok(), "member 2 still receives it");
    }

    #[test]
    fn sole_source_without_recipient_never_becomes_phantom_wire_state() {
        let source = 7;
        let prefix: Ipv4Net = "10.77.0.0/24".parse().unwrap();
        let mut engine = Engine::default();
        let mut source_rx = member(&mut engine, source);

        engine.handle(GroupEgressDeltaV4::Advertise {
            prefix,
            rib: rib(source, "192.0.2.7"),
        });

        assert!(source_rx.try_recv().is_err(), "split horizon sends nothing");
        assert!(
            !engine.adj_out.0.contains_key(&prefix),
            "a route received by no member is not actual Adj-RIB-Out"
        );
    }

    #[test]
    fn re_advertise_same_attr_dedups() {
        let mut engine = Engine::default();
        let mut rx1 = member(&mut engine, 1);
        advertise(&mut engine, "10.10.10.0/24", 99);
        assert!(rx1.try_recv().is_ok(), "first advertise sends");
        // Same path again: recorded but not re-sent (interned-attr ptr_eq).
        advertise(&mut engine, "10.10.10.0/24", 99);
        assert!(rx1.try_recv().is_err(), "identical re-advertise dedups");
    }

    #[test]
    fn removed_member_is_dropped_from_the_fan() {
        let mut engine = Engine::default();
        let mut rx1 = member(&mut engine, 1);
        engine.handle(GroupEgressDeltaV4::RemoveMember { ident: 1 });
        advertise(&mut engine, "10.10.10.0/24", 99);
        assert!(rx1.try_recv().is_err(), "removed member receives nothing");
    }

    #[test]
    fn withdraw_fans_to_non_source_members() {
        let mut engine = Engine::default();
        let mut rx1 = member(&mut engine, 1);
        let mut rx2 = member(&mut engine, 2);
        advertise(&mut engine, "10.10.10.0/24", 99);
        let _ = rx1.try_recv();
        let _ = rx2.try_recv();
        // Withdraw of an advertised prefix reaches the non-source members
        // once the batch flushes.
        engine.handle(GroupEgressDeltaV4::Withdraw {
            prefix: "10.10.10.0/24".parse().unwrap(),
            id: 0,
            source_ident: 99,
        });
        engine.flush_withdraws();
        assert!(rx1.try_recv().is_ok(), "member 1 receives the withdraw");
        assert!(rx2.try_recv().is_ok(), "member 2 receives the withdraw");
    }

    #[test]
    fn withdraws_pack_into_few_updates() {
        // A burst of withdrawals from an external source fans to the member
        // packed into far fewer UPDATEs than one per route: 1000 /24
        // withdrawals fit the default 4096-octet message in a single UPDATE.
        let mut engine = Engine::default();
        let mut rx = member(&mut engine, 1);
        let prefixes: Vec<Ipv4Net> = (0..1000)
            .map(|i| format!("10.{}.{}.0/24", i / 256, i % 256).parse().unwrap())
            .collect();
        for p in &prefixes {
            engine.handle(GroupEgressDeltaV4::Advertise {
                prefix: *p,
                rib: rib(99, "192.0.2.1"),
            });
        }
        let _ = std::iter::from_fn(|| rx.try_recv().ok()).count();

        for p in &prefixes {
            engine.handle(GroupEgressDeltaV4::Withdraw {
                prefix: *p,
                id: 0,
                source_ident: 99,
            });
        }
        engine.flush_withdraws();
        let updates: usize = std::iter::from_fn(|| rx.try_recv().ok()).count();
        assert!(updates >= 1, "the batch is flushed");
        assert!(
            updates <= 2,
            "1000 /24 withdrawals pack into at most two UPDATEs (got {updates})"
        );
    }

    #[test]
    fn mixed_source_withdraws_fan_per_source() {
        // Two member-sourced prefixes withdrawn in one batch: split-horizon
        // is per withdrawal, so grouping by source must hold. Member 1 sees
        // only the prefix it did NOT source, and member 2 the same — a
        // single packed UPDATE cannot suppress a withdrawal a member should
        // receive just because another member sourced a different one.
        let mut engine = Engine::default();
        let mut rx1 = member(&mut engine, 1);
        let mut rx2 = member(&mut engine, 2);
        let p1: Ipv4Net = "10.11.0.0/24".parse().unwrap(); // sourced by member 1
        let p2: Ipv4Net = "10.22.0.0/24".parse().unwrap(); // sourced by member 2

        // Advertise each: split-horizon fans p1 to member 2, p2 to member 1,
        // and both are recorded in the group adj_out.
        engine.handle(GroupEgressDeltaV4::Advertise {
            prefix: p1,
            rib: rib(1, "192.0.2.1"),
        });
        engine.handle(GroupEgressDeltaV4::Advertise {
            prefix: p2,
            rib: rib(2, "192.0.2.2"),
        });
        let _ = std::iter::from_fn(|| rx1.try_recv().ok()).count();
        let _ = std::iter::from_fn(|| rx2.try_recv().ok()).count();

        // Withdraw both in one batch, then flush.
        engine.handle(GroupEgressDeltaV4::Withdraw {
            prefix: p1,
            id: 0,
            source_ident: 1,
        });
        engine.handle(GroupEgressDeltaV4::Withdraw {
            prefix: p2,
            id: 0,
            source_ident: 2,
        });
        engine.flush_withdraws();

        // A /24 withdraw NLRI is `plen(24)` then the three significant
        // octets. Member 1 must see p2's withdraw but not p1's (it sourced
        // p1); member 2 the reverse.
        let p1_nlri = [24u8, 10, 11, 0];
        let p2_nlri = [24u8, 10, 22, 0];
        let to_1: Vec<_> = std::iter::from_fn(|| rx1.try_recv().ok()).collect();
        let to_2: Vec<_> = std::iter::from_fn(|| rx2.try_recv().ok()).collect();
        let carries = |frames: &[bytes::BytesMut], nlri: [u8; 4]| {
            frames.iter().any(|f| f.windows(4).any(|w| w == nlri))
        };
        assert!(carries(&to_1, p2_nlri), "member 1 receives p2's withdraw");
        assert!(
            !carries(&to_1, p1_nlri),
            "member 1 does not receive its own sourced p1"
        );
        assert!(carries(&to_2, p1_nlri), "member 2 receives p1's withdraw");
        assert!(
            !carries(&to_2, p2_nlri),
            "member 2 does not receive its own sourced p2"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn run_coalesces_a_withdraw_burst_into_few_updates() {
        // The group twin of the PET coalescing test: a burst arriving across
        // several channel wakes packs into one UPDATE after the deferred
        // flush, not one flush per wake. Paused time makes the delay
        // deterministic.
        let (pkt_tx, mut pkt_rx) = mpsc::unbounded_channel();
        let mut member_ctx = SyncCtx::for_test();
        member_ctx.packet_tx = Some(pkt_tx);
        let (delta_tx, delta_rx) = mpsc::unbounded_channel();
        let mut engine = Engine::default();
        // The engine must hold the member before the run loop starts driving,
        // so seed it directly, then hand the receiver to `run`.
        engine.handle(GroupEgressDeltaV4::AddMember {
            ident: 1,
            ctx: Box::new(member_ctx),
            add_path: false,
        });
        let task = tokio::spawn(async move { engine.run(delta_rx).await });

        let prefixes: Vec<Ipv4Net> = (0..200)
            .map(|i| format!("10.{}.{}.0/24", i / 256, i % 256).parse().unwrap())
            .collect();
        // Advertise from an external source (99) so member 1 receives and the
        // group adj_out records each row; drain those advertise frames.
        for p in &prefixes {
            delta_tx
                .send(GroupEgressDeltaV4::Advertise {
                    prefix: *p,
                    rib: rib(99, "192.0.2.1"),
                })
                .unwrap();
        }
        tokio::task::yield_now().await;
        let _ = std::iter::from_fn(|| pkt_rx.try_recv().ok()).count();

        for p in &prefixes {
            delta_tx
                .send(GroupEgressDeltaV4::Withdraw {
                    prefix: *p,
                    id: 0,
                    source_ident: 99,
                })
                .unwrap();
            tokio::task::yield_now().await;
        }
        assert!(
            pkt_rx.try_recv().is_err(),
            "withdrawals wait for the flush delay"
        );

        tokio::time::advance(WITHDRAW_FLUSH_DELAY * 2).await;
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        let updates: usize = std::iter::from_fn(|| pkt_rx.try_recv().ok()).count();
        assert!(updates >= 1, "the burst is flushed after the delay");
        assert!(
            updates <= 2,
            "the deferred burst packs into at most two UPDATEs (got {updates})"
        );
        task.abort();
    }

    #[test]
    fn addpath_filter_withdraws_only_the_local_path_id() {
        let mut engine = Engine::default();
        let mut rx = member(&mut engine, 1);
        engine.add_path = true;
        let prefix: Ipv4Net = "10.10.10.0/24".parse().unwrap();
        let mut path1 = rib(99, "192.0.2.1");
        path1.local_id = 11;
        let mut path2 = rib(98, "192.0.2.2");
        path2.local_id = 12;
        engine.advertise(prefix, path1.clone());
        engine.advertise(prefix, path2);
        let _ = std::iter::from_fn(|| rx.try_recv().ok()).count();

        // Every test SyncCtx has ident 0. Changing only the source makes
        // route_update_ipv4 filter path 1; remote-id is still zero, so this
        // exercises the local-id used by Add-Path Adj-RIB-Out and withdraw.
        path1.ident = 0;
        engine.advertise(prefix, path1);
        engine.flush_withdraws();

        let packet = rx.try_recv().expect("filtered Add-Path row is withdrawn");
        assert_eq!(engine.adj_out.0[&prefix].len(), 1);
        assert_eq!(engine.adj_out.0[&prefix][0].local_id, 12);
        assert!(packet.windows(4).any(|bytes| bytes == 11_u32.to_be_bytes()));
    }

    /// Non-AddPath: a best-path change to a route under a different Loc-RIB
    /// local-id must replace the advertised row, not append. `add` keys Out
    /// rows by local-id, so before `record_out` the superseded local-id 1 row
    /// lingered as a phantom Adj-RIB-Out entry (two rows for one non-AddPath
    /// prefix).
    #[test]
    fn non_addpath_best_change_replaces_stale_adj_out_row() {
        let mut engine = Engine::default();
        let mut rx = member(&mut engine, 1);
        let prefix: Ipv4Net = "10.20.0.0/24".parse().unwrap();

        let mut first = rib(9, "192.0.2.1");
        first.local_id = 1;
        engine.advertise(prefix, first);
        let _ = std::iter::from_fn(|| rx.try_recv().ok()).count();

        // The best path changes to a route carrying a fresh Loc-RIB local-id.
        let mut second = rib(9, "192.0.2.2");
        second.local_id = 2;
        engine.advertise(prefix, second);

        // Exactly one advertised path remains — the new best. The old `add`
        // (keyed by local-id) left the superseded local-id 1 row behind.
        let rows = &engine.adj_out.0[&prefix];
        assert_eq!(
            rows.len(),
            1,
            "non-AddPath keeps exactly one advertised path"
        );
        assert_eq!(
            rows[0].local_id, 2,
            "the surviving row is the new best path"
        );
    }

    #[test]
    fn record_adj_out_makes_a_synced_route_withdrawable() {
        // The first member of a new group is sync'd directly by route_sync_ipv4
        // (no send via the task); RecordAdjOut puts the route in the group
        // adj_out so a later group withdraw still reaches that member.
        let mut engine = Engine::default();
        let mut rx1 = member(&mut engine, 1);
        engine.handle(GroupEgressDeltaV4::RecordAdjOut {
            prefix: "10.10.10.0/24".parse().unwrap(),
            rib: rib(5, "192.0.2.1"),
        });
        assert!(rx1.try_recv().is_err(), "record_adj_out sends nothing");
        engine.handle(GroupEgressDeltaV4::Withdraw {
            prefix: "10.10.10.0/24".parse().unwrap(),
            id: 0,
            source_ident: 99,
        });
        engine.flush_withdraws();
        assert!(
            rx1.try_recv().is_ok(),
            "the withdraw reaches the sync-recorded member"
        );
    }

    #[test]
    fn count_adj_out_tallies_total_and_solely_sourced_prefixes() {
        // The summary's PfxSnt at group-gate-on: the engine reports the total
        // prefix count and, per ident, how many prefixes that ident SOLELY
        // sources — the ones split-horizon drops from that member's fan. The
        // caller derives PfxSnt(member) = total − sole_source[member].
        let mut engine = Engine::default();
        // Two prefixes solely from peer 5, one solely from peer 7.
        for p in ["10.0.0.0/24", "10.0.1.0/24"] {
            engine.handle(GroupEgressDeltaV4::RecordAdjOut {
                prefix: p.parse().unwrap(),
                rib: rib(5, "192.0.2.1"),
            });
        }
        engine.handle(GroupEgressDeltaV4::RecordAdjOut {
            prefix: "10.0.2.0/24".parse().unwrap(),
            rib: rib(7, "192.0.2.1"),
        });
        // A fourth prefix with paths from BOTH 5 and 7 (distinct local-ids so
        // they accumulate) — mixed-source, so it is NOT solely-sourced by
        // either: both members still receive the other's path.
        let mut a = rib(5, "192.0.2.1");
        a.local_id = 1;
        let mut b = rib(7, "192.0.2.1");
        b.local_id = 2;
        for r in [a, b] {
            engine.handle(GroupEgressDeltaV4::RecordAdjOut {
                prefix: "10.0.3.0/24".parse().unwrap(),
                rib: r,
            });
        }

        let (reply, mut reply_rx) = tokio::sync::oneshot::channel();
        engine.handle(GroupEgressDeltaV4::CountAdjOut { reply });
        let (total, sole) = reply_rx.try_recv().expect("CountAdjOut replied");

        assert_eq!(total, 4, "four prefixes in the group adj_out");
        assert_eq!(sole.get(&5), Some(&2), "peer 5 solely sources two prefixes");
        assert_eq!(
            sole.get(&7),
            Some(&1),
            "peer 7 solely sources one — the mixed prefix is excluded"
        );
        // Derived PfxSnt: source-5 member gets 4−2=2, source-7 gets 4−1=3, a
        // non-sourcing member gets all 4.
        let pfx_snt = |ident: usize| total - sole.get(&ident).copied().unwrap_or(0);
        assert_eq!(pfx_snt(5), 2);
        assert_eq!(pfx_snt(7), 3);
        assert_eq!(pfx_snt(9), 4);
    }
}
