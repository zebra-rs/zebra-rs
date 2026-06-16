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

use ipnet::Ipv4Net;
use tokio::sync::mpsc::{self, UnboundedSender};

use crate::context::task::Task;

use super::route::BgpRib;

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
#[allow(dead_code)] // constructed (main) + matched (PET) in Phase 1
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
    /// Main forwards v4 egress deltas here in Phase 1; unused at Phase 0.
    #[allow(dead_code)]
    pub delta_tx: UnboundedSender<EgressDeltaV4>,
    // Held only for its abort-on-drop teardown; the task is driven entirely
    // by the channel, so the handle is never read after spawn.
    #[allow(dead_code)]
    task: Task<()>,
}

impl PeerEgressTask {
    /// Spawn a peer's egress task. **Phase 0: idle** — it drains the delta
    /// channel without acting (Phase 1 fills in `adj_out` + build + send).
    /// Exits when `delta_tx` is dropped at teardown.
    pub fn spawn() -> Self {
        let (delta_tx, mut delta_rx) = mpsc::unbounded_channel::<EgressDeltaV4>();
        let task = Task::spawn(async move {
            while let Some(_delta) = delta_rx.recv().await {
                // Phase 0: no-op. Phase 1 processes the delta here.
            }
        });
        PeerEgressTask { delta_tx, task }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pet_lifecycle_spawn_send_teardown() {
        // Phase 0 lifecycle: the idle task drains deltas without acting.
        // Confirm spawn + send (the channel is live) + drop (abort-on-drop
        // / channel close ends the task) don't panic.
        let pet = PeerEgressTask::spawn();
        pet.delta_tx
            .send(EgressDeltaV4::Withdraw {
                prefix: "10.0.0.0/24".parse().unwrap(),
                id: 0,
            })
            .expect("delta channel is open while the task lives");
        drop(pet);
        // Let the runtime reap the aborted/closed task.
        tokio::task::yield_now().await;
    }
}
