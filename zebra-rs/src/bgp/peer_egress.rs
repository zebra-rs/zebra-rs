//! Per-peer egress task (PET) — A2 ⑥, the (a′) inter-peer-parallelism path.
//! Design + implementation findings: `docs/design/bgp-peer-egress-task.md`.
//!
//! At gate-on (`ZEBRA_BGP_PEER_TASK=1`) each peer gets a task that will own
//! its v4-unicast Adj-RIB-Out and run the per-peer egress — build +
//! out-policy + encode + send — off the main loop and in parallel across
//! peers (the GoBGP per-goroutine model). Main sequences the v4 egress
//! operations to it as an ordered [`EgressDeltaV4`] stream (so per-prefix
//! ordering is preserved); the task does the work and feeds the current
//! connection's `packet_tx`, which the unchanged per-connection writer
//! drains.
//!
//! **Phase 0 (this file) is lifecycle only:** the task is spawned at
//! Established and dropped on session end, and it drains its delta channel
//! without acting. `adj_out` and the egress work move into it in Phase 1.
//! Gate-off (the default) is untouched — the egress stays on the main task
//! via update-groups.

use std::sync::Arc;

use bgp_packet::{Ipv4Nlri, UpdatePacket};
use ipnet::Ipv4Net;
use tokio::sync::mpsc::{self, UnboundedSender};

use crate::context::task::Task;

use super::adj_rib::{AdjRibTable, Out};
use super::route::{BgpRib, SyncCtx};
use super::store::BgpAttrStore;

/// `ZEBRA_BGP_PEER_TASK=1` opts peers into the per-peer egress task at
/// Established. Default off: the v4 egress stays on the main task
/// (update-groups), exactly as today. Read once (the pool is sized at
/// startup), like `ZEBRA_BGP_SHARDS` / `ZEBRA_BGP_SYNC_CHUNK`.
pub fn peer_egress_task_enabled() -> bool {
    use std::sync::OnceLock;
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| {
        std::env::var("ZEBRA_BGP_PEER_TASK")
            .ok()
            .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
    })
}

/// One v4-unicast egress operation main forwards to a peer's task — the
/// ordered delta stream (main sequences for per-prefix ordering; the PET
/// does the work). Phase 0 defines the protocol; Phase 1 sends + handles it.
#[derive(Debug)]
pub enum EgressDeltaV4 {
    /// A best path won for `prefix` (the event-driven advertise, or a
    /// session-up dump row): build + out-policy + `adj_out.add` + encode +
    /// send — or skip on split-horizon / policy-deny. `send` is `false` for
    /// a DumpV4 ③ record, where the shard already put the bytes on the wire
    /// and only `adj_out` needs the row.
    Advertise {
        prefix: Ipv4Net,
        rib: BgpRib,
        send: bool,
    },
    /// `prefix` / path `id` is gone: `adj_out.remove`, and if it had been
    /// advertised, encode a withdraw + send.
    Withdraw { prefix: Ipv4Net, id: u32 },
}

/// Handle main keeps for a peer's egress task: the delta channel plus the
/// task itself. Dropping it (`peer.pet = None` on session end) aborts the
/// task (abort-on-drop) and closes the channel — either ends the task.
#[derive(Debug)]
pub struct PeerEgressTask {
    /// Main forwards v4 egress deltas here (the reduce / withdraw paths).
    pub delta_tx: UnboundedSender<EgressDeltaV4>,
    // Held only for its abort-on-drop teardown; the task is driven entirely
    // by the channel, so the handle is never read after spawn.
    #[allow(dead_code)]
    task: Task<()>,
}

impl PeerEgressTask {
    /// Spawn a peer's egress task with its initial egress snapshot. **Phase
    /// 1a: the advertise engine** — owns `adj_out` + a per-peer attr
    /// interner and processes [`EgressDeltaV4::Advertise`] (build +
    /// out-policy + intern + `adj_out` dedup + send). Withdraw / dump /
    /// reads land in 1c–1e; the live wiring from main's reduce is 1b, so
    /// until then the engine is exercised only by the unit test. `ctx` will
    /// be refreshed by a `Refresh` delta on policy / connection change.
    /// Exits when `delta_tx` is dropped at teardown.
    pub fn spawn(ctx: SyncCtx, add_path: bool) -> Self {
        let (delta_tx, mut delta_rx) = mpsc::unbounded_channel::<EgressDeltaV4>();
        let task = Task::spawn(async move {
            let mut engine = Engine {
                ctx,
                add_path,
                adj_out: AdjRibTable::new(),
                attr_store: BgpAttrStore::new(),
            };
            while let Some(delta) = delta_rx.recv().await {
                engine.handle(delta);
            }
        });
        PeerEgressTask { delta_tx, task }
    }
}

/// A peer's owned v4-unicast egress state + per-delta logic, run inside the
/// task. Build / policy / send reuse the `&SyncCtx` primitives (A2 Phase 0),
/// so this is the per-peer, off-main twin of `compute_advertise_outcome` +
/// `send_ipv4_direct` — no update-groups (gate-on is the GoBGP model).
struct Engine {
    ctx: SyncCtx,
    add_path: bool,
    adj_out: AdjRibTable<Out>,
    attr_store: BgpAttrStore,
}

impl Engine {
    fn handle(&mut self, delta: EgressDeltaV4) {
        match delta {
            EgressDeltaV4::Advertise { prefix, rib, send } => self.advertise(prefix, rib, send),
            EgressDeltaV4::Withdraw { prefix, id } => self.withdraw(prefix, id),
        }
    }

    /// The per-peer egress for one best path: build + out-policy + intern +
    /// record `adj_out` (dedup'd) + send. If the build / out-policy filters
    /// it out — split-horizon (the best is from this peer) or policy-deny —
    /// it becomes a **withdraw** of any prior advertisement, exactly as the
    /// gate-off `Withdraw` outcome. `send` is false for a dump-③ record (the
    /// shard already sent the bytes; only `adj_out` needs the row).
    fn advertise(&mut self, prefix: Ipv4Net, mut rib: BgpRib, send: bool) {
        let built = super::route::route_update_ipv4(&self.ctx, &prefix, &rib, self.add_path)
            .and_then(|(nlri, attr)| {
                super::route::route_apply_policy_out(&self.ctx, &nlri, attr, rib.weight)
                    .map(|d| (nlri, d))
            });
        let Some((nlri, decision)) = built else {
            // Filtered: withdraw any prior advertisement of this path.
            self.withdraw(prefix, rib.remote_id);
            return;
        };
        let arc = self.attr_store.intern(decision.attr);
        rib.attr = arc.clone();
        // Record in adj_out and dedup against the prior interned attr
        // (pointer identity) exactly as the cursor / event-driven path does:
        // a re-advertise of the same attr records but does not re-send.
        let prev = self.adj_out.add(prefix, rib);
        let already_sent = prev.is_some_and(|p| Arc::ptr_eq(&p.attr, &arc));
        if send && !already_sent {
            super::update_group::send_ipv4_direct(&self.ctx, vec![(arc, nlri)], None);
        }
    }

    /// Remove `prefix` / path `id` from `adj_out` and, if it had actually
    /// been advertised, send a withdraw — the per-peer twin of
    /// `route_withdraw_ipv4`.
    fn withdraw(&mut self, prefix: Ipv4Net, id: u32) {
        if self.adj_out.remove(prefix, id).is_some() {
            let mut update = UpdatePacket::with_max_packet_size(self.ctx.max_packet_size());
            update.ipv4_withdraw.push(Ipv4Nlri { id, prefix });
            self.ctx.send_packet(update.into());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::route::BgpRibType;
    use super::*;
    use bgp_packet::{BgpAttr, BgpNexthop};

    /// A best-path row from peer `ident`, next-hop `nh`.
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

    /// Drive the engine synchronously (it is a plain `&mut self` method —
    /// no async needed) so the send + dedup are observed without task
    /// scheduling races. `for_test`'s `packet_tx` is swapped for a readable
    /// channel.
    #[test]
    fn engine_advertise_sends_then_dedups() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut ctx = SyncCtx::for_test();
        ctx.packet_tx = Some(tx);
        let mut engine = Engine {
            ctx,
            add_path: false,
            adj_out: AdjRibTable::new(),
            attr_store: BgpAttrStore::new(),
        };
        let prefix: Ipv4Net = "10.10.10.0/24".parse().unwrap();

        // A best path from a different peer (ident 5 ≠ the ctx's ident 0, so
        // split-horizon keeps it) is built, recorded, and sent.
        engine.advertise(prefix, rib(5, "192.0.2.1"), true);
        let first = std::iter::from_fn(|| rx.try_recv().ok()).count();
        assert!(first >= 1, "the advertise builds + sends an UPDATE");

        // The same path again: the attr interns to the same Arc, so the
        // adj_out dedup suppresses the resend (records, doesn't re-send).
        engine.advertise(prefix, rib(5, "192.0.2.1"), true);
        assert!(
            rx.try_recv().is_err(),
            "a re-advertise of the same attr is deduped (no resend)"
        );
    }

    #[test]
    fn engine_split_horizon_advertise_withdraws_prior() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut ctx = SyncCtx::for_test(); // ctx ident = 0
        ctx.packet_tx = Some(tx);
        let mut engine = Engine {
            ctx,
            add_path: false,
            adj_out: AdjRibTable::new(),
            attr_store: BgpAttrStore::new(),
        };
        let prefix: Ipv4Net = "10.10.10.0/24".parse().unwrap();

        // Advertise a path from peer 5 → built + sent + recorded.
        engine.advertise(prefix, rib(5, "192.0.2.1"), true);
        let _ = std::iter::from_fn(|| rx.try_recv().ok()).count();

        // The best is now from peer 0 (== the ctx's own ident) →
        // `route_update_ipv4` returns None (split-horizon), so the prior
        // advertisement is withdrawn (gate-off's `Withdraw` outcome).
        engine.advertise(prefix, rib(0, "192.0.2.2"), true);
        assert!(
            rx.try_recv().is_ok(),
            "split-horizon withdraws the prior advertisement"
        );
    }

    #[test]
    fn engine_withdraw_only_sends_if_advertised() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut ctx = SyncCtx::for_test();
        ctx.packet_tx = Some(tx);
        let mut engine = Engine {
            ctx,
            add_path: false,
            adj_out: AdjRibTable::new(),
            attr_store: BgpAttrStore::new(),
        };
        let prefix: Ipv4Net = "10.10.10.0/24".parse().unwrap();

        // Withdraw of a never-advertised prefix → nothing on the wire.
        engine.withdraw(prefix, 0);
        assert!(
            rx.try_recv().is_err(),
            "withdraw of an unadvertised prefix sends nothing"
        );

        // Advertise, then withdraw → the withdraw is sent.
        engine.advertise(prefix, rib(5, "192.0.2.1"), true);
        let _ = std::iter::from_fn(|| rx.try_recv().ok()).count();
        engine.withdraw(prefix, 0);
        assert!(
            rx.try_recv().is_ok(),
            "withdraw of an advertised prefix sends an UPDATE"
        );
    }

    #[tokio::test]
    async fn pet_lifecycle_spawn_send_teardown() {
        // The task spawns, accepts a delta on the live channel, and exits on
        // drop (abort-on-drop / channel close) without panicking.
        let pet = PeerEgressTask::spawn(SyncCtx::for_test(), false);
        pet.delta_tx
            .send(EgressDeltaV4::Withdraw {
                prefix: "10.0.0.0/24".parse().unwrap(),
                id: 0,
            })
            .expect("delta channel is open while the task lives");
        drop(pet);
        tokio::task::yield_now().await;
    }
}
