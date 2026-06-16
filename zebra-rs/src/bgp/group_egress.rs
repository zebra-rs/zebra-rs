//! Per-update-group egress task — **Phase 0 (the lifecycle shell)**.
//!
//! Plan: `docs/design/bgp-egress-group-task-migration.md`. The end state is
//! one persistent task per [`UpdateGroup`](super::update_group::UpdateGroup)
//! that owns the group's coalescing cache + the encode and fans bytes to its
//! member peers — **M tasks (groups), not N (peers)**, coalescing *and*
//! off-main-parallel. A per-peer egress task (PET) is the M=1 case.
//!
//! Phase 0 is only the lifecycle: env-gated, spawned when a group is created
//! (`attach`) and dropped when it empties (`detach`), tracking its member set
//! from the membership machinery. It is **idle** — no egress is routed through
//! it yet (Phase 1). Default off; gate-off is byte-identical (no task is
//! created and the member sends are `if let Some` no-ops).

use std::collections::BTreeSet;
use std::sync::OnceLock;

use tokio::sync::mpsc::{self, UnboundedSender};

use crate::context::task::Task;

use super::update_group::UpdateGroupId;

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

/// A member-set change the `attach` / `detach` machinery pushes to a group's
/// task. Phase 0 carries identity only; the member's `packet_tx` (for the
/// fan-out) and the egress deltas arrive in Phase 1.
#[derive(Debug)]
pub enum GroupMemberDelta {
    Add(usize),
    Remove(usize),
}

/// Handle main keeps on each [`UpdateGroup`](super::update_group::UpdateGroup)
/// for its egress task. Dropping it — when the group empties in `detach`, or
/// when the whole map is torn down — aborts the task (abort-on-drop) and
/// closes the channel.
#[derive(Debug)]
pub struct GroupEgressTask {
    /// `attach` / `detach` push member add/remove here.
    member_tx: UnboundedSender<GroupMemberDelta>,
    // Held only for its abort-on-drop teardown; the task is driven entirely by
    // the channel, so the handle is never read after spawn.
    #[allow(dead_code)]
    task: Task<()>,
}

impl GroupEgressTask {
    /// Spawn a group's egress task. **Phase 0 — idle**: it maintains its
    /// member set from [`GroupMemberDelta`]s and otherwise does nothing.
    /// Phase 1 adds the egress delta channel and the encode/fan. Exits when
    /// `member_tx` is dropped (the group emptied).
    pub fn spawn(id: UpdateGroupId) -> Self {
        let (member_tx, mut member_rx) = mpsc::unbounded_channel::<GroupMemberDelta>();
        tracing::info!("BGP egress group task: spawned (group {id:?})");
        let task = Task::spawn(async move {
            let mut members: BTreeSet<usize> = BTreeSet::new();
            while let Some(delta) = member_rx.recv().await {
                match delta {
                    GroupMemberDelta::Add(ident) => {
                        members.insert(ident);
                    }
                    GroupMemberDelta::Remove(ident) => {
                        members.remove(&ident);
                    }
                }
                // Phase 0: membership tracked (the `members.len()` read keeps
                // the set live for Phase 1), but no egress is routed yet.
                tracing::debug!("BGP egress group {id:?}: {} member(s)", members.len());
            }
            tracing::debug!("BGP egress group task: exited (group {id:?})");
        });
        GroupEgressTask { member_tx, task }
    }

    /// Push a member-set change to the task. A send failure means the task has
    /// already gone (the group is tearing down), which is harmless here.
    pub fn member_delta(&self, delta: GroupMemberDelta) {
        let _ = self.member_tx.send(delta);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bgp_packet::{Afi, Safi};

    #[tokio::test]
    async fn spawn_accepts_member_deltas_and_aborts_on_drop() {
        let task = GroupEgressTask::spawn(UpdateGroupId::new(Afi::Ip, Safi::Unicast, 0));
        // Member add/remove are accepted without panicking (Phase 0 is idle).
        task.member_delta(GroupMemberDelta::Add(1));
        task.member_delta(GroupMemberDelta::Add(2));
        task.member_delta(GroupMemberDelta::Remove(1));
        // Dropping the handle closes the channel and aborts the task; the
        // task observes the closed channel on the next poll and exits.
        drop(task);
        tokio::task::yield_now().await;
    }
}
