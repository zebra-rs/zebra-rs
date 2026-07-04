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
//! **This file is lifecycle only:** the task is spawned at
//! Established and dropped on session end, and it drains its delta channel
//! without acting. `adj_out` and the egress work move into it later.
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

/// Process-global per-peer-egress-task flag, frozen once at BGP instance
/// spawn by [`init_peer_task`]. A `OnceLock` (not a per-call env read) so the
/// egress model chosen at startup is consistent across the ~8 gate sites for
/// the instance's lifetime — the PET and update-group models are
/// alternatives, never interleaved.
static PEER_TASK: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

/// The `ZEBRA_BGP_PEER_TASK` environment variable (the pre-knob form, now the
/// fallback when the YANG `peer-task` leaf is unset). `None` if unset;
/// `Some(true)` for `1` / `true` (case-insensitive), `Some(false)` otherwise.
fn peer_task_env() -> Option<bool> {
    std::env::var("ZEBRA_BGP_PEER_TASK")
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}

/// Pure resolution policy (unit-tested): the YANG `router bgp peer-task` leaf
/// wins over the env var, which wins over the default `false` (update-group
/// egress, unchanged).
fn resolve_peer_task(config: Option<bool>, env: Option<bool>) -> bool {
    config.or(env).unwrap_or(false)
}

/// Freeze the per-peer-egress-task model at instance spawn from the YANG
/// `peer-task` leaf (else `ZEBRA_BGP_PEER_TASK`, else off). Called once from
/// `spawn_bgp` before the instance processes any peer; the result is stored
/// process-globally so [`peer_egress_task_enabled`] returns it at every gate
/// site. Idempotent — `spawn_bgp` short-circuits a re-spawn, first value wins.
pub fn init_peer_task(config: Option<bool>) -> bool {
    let _ = PEER_TASK.set(resolve_peer_task(config, peer_task_env()));
    let on = peer_egress_task_enabled();
    let source = if config.is_some() {
        "config"
    } else if peer_task_env().is_some() {
        "ZEBRA_BGP_PEER_TASK"
    } else {
        "default"
    };
    if on {
        tracing::info!("BGP per-peer egress task: enabled (from {source})");
    } else {
        // Disable default logging.
        // tracing::info!("BGP per-peer egress task: disabled (from {source})");
    }
    on
}

/// `true` opts peers into the per-peer egress task (the GoBGP per-peer model)
/// at Established; `false` (default) keeps the v4 egress on the main task
/// (update-groups). Returns the value frozen at spawn by [`init_peer_task`]
/// (YANG `peer-task` leaf or `ZEBRA_BGP_PEER_TASK`); before any instance
/// spawns (unit tests) it falls back to the env var, then `false`. The two
/// egress models are alternatives, fixed for the instance lifetime.
pub fn peer_egress_task_enabled() -> bool {
    PEER_TASK
        .get()
        .copied()
        .unwrap_or_else(|| resolve_peer_task(None, peer_task_env()))
}

/// One v4-unicast egress operation main forwards to a peer's task — the
/// ordered delta stream (main sequences for per-prefix ordering; the PET
/// does the work). This defines the protocol; sending + handling come later.
#[derive(Debug)]
pub enum EgressDeltaV4 {
    /// A best path won for `prefix` (the event-driven advertise): build +
    /// out-policy + `adj_out.add` + encode + send — or, on split-horizon /
    /// policy-deny, withdraw any prior advertisement. The carried `rib` is
    /// the *Loc-RIB* row (pre-egress-attr); the PET builds the egress attr.
    Advertise { prefix: Ipv4Net, rib: BgpRib },
    /// A DumpV4 ③ record: the shard already built the egress attr and put
    /// the bytes on the wire, so just record the row in `adj_out` (no
    /// rebuild — `rib.attr` is already post-policy). Keeps a dump-learned
    /// prefix in `adj_out` so a later withdraw reaches the peer.
    RecordAdjOut { prefix: Ipv4Net, rib: BgpRib },
    /// `prefix` / path `id` is gone: `adj_out.remove`, and if it had been
    /// advertised, encode a withdraw + send.
    Withdraw { prefix: Ipv4Net, id: u32 },
    /// Replace the PET's egress snapshot (out-policy / caps / next-hop /
    /// AddPath) after a policy or config change. Main sends this before
    /// re-fanning the Loc-RIB on soft-out, so the re-evaluation uses the new
    /// policy. `Box`ed to keep the enum small.
    Refresh { ctx: Box<SyncCtx>, add_path: bool },
    /// A `show … advertised-routes` request at gate-on: reply with the PET's
    /// v4 Adj-RIB-Out (one `(prefix, paths)` per prefix) on the oneshot,
    /// since `adj_out` lives here, not on the peer.
    DumpAdjOut {
        reply: tokio::sync::oneshot::Sender<Vec<(Ipv4Net, Vec<BgpRib>)>>,
    },
    /// A `show … summary` PfxSnt request at gate-on: reply with the PET's v4
    /// Adj-RIB-Out prefix count. Counts only — the summary row prints the
    /// number, not the routes (unlike [`Self::DumpAdjOut`]).
    CountAdjOut {
        reply: tokio::sync::oneshot::Sender<usize>,
    },
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
/// task. Build / policy / send reuse the `&SyncCtx` primitives,
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
            EgressDeltaV4::Advertise { prefix, rib } => self.advertise(prefix, rib),
            EgressDeltaV4::RecordAdjOut { prefix, rib } => self.record_adj_out(prefix, rib),
            EgressDeltaV4::Withdraw { prefix, id } => self.withdraw(prefix, id),
            EgressDeltaV4::Refresh { ctx, add_path } => {
                self.ctx = *ctx;
                self.add_path = add_path;
            }
            EgressDeltaV4::DumpAdjOut { reply } => {
                let entries = self
                    .adj_out
                    .0
                    .iter()
                    .map(|(prefix, ribs)| (*prefix, ribs.clone()))
                    .collect();
                let _ = reply.send(entries);
            }
            EgressDeltaV4::CountAdjOut { reply } => {
                // Count-only twin of `DumpAdjOut`: the v4 Adj-RIB-Out prefix
                // count for the summary's PfxSnt. `adj_out.0` is keyed by
                // prefix, so `len` matches `peer.adj_out.count` semantics.
                let _ = reply.send(self.adj_out.0.len());
            }
        }
    }

    /// The per-peer egress for one best path: build + out-policy + intern +
    /// record `adj_out` (dedup'd) + send. If the build / out-policy filters
    /// it out — split-horizon (the best is from this peer) or policy-deny —
    /// it becomes a **withdraw** of any prior advertisement, exactly as the
    /// gate-off `Withdraw` outcome.
    fn advertise(&mut self, prefix: Ipv4Net, mut rib: BgpRib) {
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
        if !already_sent {
            super::update_group::send_ipv4_direct(&self.ctx, vec![(arc, nlri)], None);
        }
    }

    /// Record a DumpV4 ③ row in `adj_out` **without rebuilding** — `rib.attr`
    /// is already the post-policy egress attr the shard built + sent, so a
    /// rebuild would double-apply next-hop-self / AS_PATH. Re-intern it in
    /// the PET's own store so the dedup against the event-driven path
    /// (interned there too) stays pointer-consistent.
    fn record_adj_out(&mut self, prefix: Ipv4Net, mut rib: BgpRib) {
        rib.attr = self.attr_store.intern((*rib.attr).clone());
        self.adj_out.add(prefix, rib);
    }

    /// Drop `prefix`'s advertised path(s) from `adj_out` and, if it had
    /// actually been advertised, send a withdraw — the per-peer twin of
    /// `route_withdraw_ipv4`. Matches by **prefix**, not exact `id`: the
    /// withdraw fan-out only knows the prefix (the path is gone), while
    /// `adj_out` is keyed by the Loc-RIB `local_id`, so an id match would
    /// miss. Non-AddPath has one entry per prefix; the wire withdraw carries
    /// `id` (0 for non-AddPath). Per-path AddPath withdraw is a follow-on.
    fn withdraw(&mut self, prefix: Ipv4Net, id: u32) {
        if self.adj_out.0.remove(&prefix).is_some() {
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

    #[test]
    fn peer_task_resolution_policy() {
        use super::resolve_peer_task;
        // The YANG `peer-task` leaf wins over the env var...
        assert!(resolve_peer_task(Some(true), Some(false)));
        assert!(!resolve_peer_task(Some(false), Some(true)));
        // ...the env var is the fallback when the leaf is unset...
        assert!(resolve_peer_task(None, Some(true)));
        assert!(!resolve_peer_task(None, Some(false)));
        // ...and off (update-group egress) is the default when neither is set.
        assert!(!resolve_peer_task(None, None));
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
        engine.advertise(prefix, rib(5, "192.0.2.1"));
        let first = std::iter::from_fn(|| rx.try_recv().ok()).count();
        assert!(first >= 1, "the advertise builds + sends an UPDATE");

        // The same path again: the attr interns to the same Arc, so the
        // adj_out dedup suppresses the resend (records, doesn't re-send).
        engine.advertise(prefix, rib(5, "192.0.2.1"));
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
        engine.advertise(prefix, rib(5, "192.0.2.1"));
        let _ = std::iter::from_fn(|| rx.try_recv().ok()).count();

        // The best is now from peer 0 (== the ctx's own ident) →
        // `route_update_ipv4` returns None (split-horizon), so the prior
        // advertisement is withdrawn (gate-off's `Withdraw` outcome).
        engine.advertise(prefix, rib(0, "192.0.2.2"));
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
        engine.advertise(prefix, rib(5, "192.0.2.1"));
        let _ = std::iter::from_fn(|| rx.try_recv().ok()).count();
        engine.withdraw(prefix, 0);
        assert!(
            rx.try_recv().is_ok(),
            "withdraw of an advertised prefix sends an UPDATE"
        );
    }

    #[test]
    fn engine_record_adj_out_keeps_dump_row_withdrawable() {
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

        // A DumpV4 ③ record (post-policy rib) puts the row in adj_out
        // WITHOUT sending — the shard already sent the bytes. The Loc-RIB
        // assigns a NON-ZERO local_id (adj_out is keyed by it), which the
        // withdraw fan-out — knowing only the prefix — does not carry.
        let mut dump_rib = rib(5, "192.0.2.1");
        dump_rib.local_id = 7;
        engine.record_adj_out(prefix, dump_rib);
        assert!(
            rx.try_recv().is_err(),
            "record_adj_out sends nothing (the shard already did)"
        );

        // A later withdraw with wire id 0 must still reach the peer — it
        // matches by prefix, not the local_id (the gate-on bug 1f caught).
        engine.withdraw(prefix, 0);
        assert!(
            rx.try_recv().is_ok(),
            "a dump-learned prefix can be withdrawn"
        );
    }

    #[test]
    fn engine_refresh_swaps_the_ctx() {
        let (tx1, mut rx1) = mpsc::unbounded_channel();
        let mut ctx1 = SyncCtx::for_test();
        ctx1.packet_tx = Some(tx1);
        let mut engine = Engine {
            ctx: ctx1,
            add_path: false,
            adj_out: AdjRibTable::new(),
            attr_store: BgpAttrStore::new(),
        };

        // Refresh to a new snapshot whose writer is a different channel.
        let (tx2, mut rx2) = mpsc::unbounded_channel();
        let mut ctx2 = SyncCtx::for_test();
        ctx2.packet_tx = Some(tx2);
        engine.handle(EgressDeltaV4::Refresh {
            ctx: Box::new(ctx2),
            add_path: false,
        });

        // Subsequent egress uses the refreshed snapshot's writer.
        let prefix: Ipv4Net = "10.10.10.0/24".parse().unwrap();
        engine.advertise(prefix, rib(5, "192.0.2.1"));
        assert!(rx1.try_recv().is_err(), "the old snapshot's writer is idle");
        assert!(
            rx2.try_recv().is_ok(),
            "egress now goes to the refreshed snapshot's writer"
        );
    }

    #[test]
    fn engine_dump_adj_out_returns_advertised() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut ctx = SyncCtx::for_test();
        ctx.packet_tx = Some(tx);
        let mut engine = Engine {
            ctx,
            add_path: false,
            adj_out: AdjRibTable::new(),
            attr_store: BgpAttrStore::new(),
        };
        let prefix: Ipv4Net = "10.10.10.0/24".parse().unwrap();
        engine.advertise(prefix, rib(5, "192.0.2.1"));

        // The show gather: DumpAdjOut replies with the PET's adj_out.
        let (reply_tx, mut reply_rx) = tokio::sync::oneshot::channel();
        engine.handle(EgressDeltaV4::DumpAdjOut { reply: reply_tx });
        let entries = reply_rx.try_recv().expect("DumpAdjOut replied");
        assert_eq!(entries.len(), 1, "the advertised prefix is in the dump");
        assert_eq!(entries[0].0, prefix);
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
