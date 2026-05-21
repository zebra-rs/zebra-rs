//! Spawn / despawn of [`BgpVrf`] tasks driven by the global Bgp's
//! `CommitEnd` diff (step 14 of the BGP MPLS/VPN refactor).
//!
//! The committed intent lives in [`crate::bgp::Bgp::vrfs`] (a
//! `BTreeMap<String, BgpVrfConfig>` populated by step 12's
//! callbacks). The running task set lives in
//! [`crate::bgp::Bgp::vrf_registry`]. After every commit the
//! diff between the two maps is computed, new VRF names get a
//! fresh [`BgpVrf`] + [`serve_vrf`], deleted names get a
//! [`BgpVrfMsg::Shutdown`].
//!
//! The current cut deliberately uses a placeholder
//! [`ProtoContext::default_table_no_rib`] for the per-VRF runtime:
//! step 14 doesn't open any per-VRF sockets, and the
//! `SO_BINDTODEVICE` plumbing only matters once peers exist
//! (step 15). The same step 15 lifts the placeholder to a real
//! [`ProtoContext::for_vrf`] built from a fresh per-VRF
//! `RibClient` subscription that carries the kernel `table_id`
//! through to [`crate::rib::client::ClientRegistry`].

use std::collections::BTreeMap;

use tokio::sync::mpsc::UnboundedSender;

use crate::context::{ProtoContext, Task};

use super::super::inst::RibKnownVrf;
use super::super::vrf_config::BgpVrfConfig;
use super::inst::{BgpVrf, BgpVrfInbox, serve_vrf};
use super::msg::{BgpGlobalMsg, BgpVrfMsg};

/// Per-VRF task handle stashed on [`crate::bgp::Bgp::vrf_registry`].
/// Holds the inbound sender so the global task can dispatch
/// `Shutdown` / `Accept` / import deliveries, plus the spawned
/// [`Task`] so dropping the handle aborts the runtime cleanly.
pub struct BgpVrfHandle {
    pub inbox: BgpVrfInbox,
    /// Held so dropping the handle aborts the spawned event loop
    /// even if `despawn_bgp_vrf` was never called (defence in
    /// depth — a clean teardown sends `Shutdown` first). Not
    /// read directly anywhere; `Task` already runs its
    /// `AbortHandle` via `Drop`.
    #[allow(dead_code)]
    pub task: Task<()>,
}

/// Pure diff: which VRF names need to be spawned (in `desired`
/// but not `running`) and which need to be despawned (in
/// `running` but not `desired`). Names that appear in both are
/// considered unchanged at this step — step 14 doesn't yet detect
/// edits to `rd` / `router-id` / `label-mode`; step 15 layers
/// edit detection on top by hashing the cfg.
pub fn compute_vrf_diff(
    desired: &BTreeMap<String, BgpVrfConfig>,
    running: &BTreeMap<String, BgpVrfHandle>,
) -> (Vec<String>, Vec<String>) {
    let to_spawn: Vec<String> = desired
        .keys()
        .filter(|name| !running.contains_key(*name))
        .cloned()
        .collect();
    let to_despawn: Vec<String> = running
        .keys()
        .filter(|name| !desired.contains_key(*name))
        .cloned()
        .collect();
    (to_spawn, to_despawn)
}

/// Build + spawn a per-VRF task. Returns the handle the caller
/// stashes on `vrf_registry`. `kernel` carries the matching
/// kernel VRF master info if RIB has already told us about it
/// (step 15); when `None`, the spawn falls back to a placeholder
/// `ProtoContext::default_table_no_rib()` and the per-VRF runtime
/// won't bind sockets to a VRF master until the global Bgp task
/// re-spawns via [`super::super::inst::Bgp::maybe_respawn_vrf_with_kernel_ctx`].
///
/// `global_tx` is the shared sender every VRF task uses to push
/// back to the global runtime (one channel, fanned in from every
/// VRF).
pub fn spawn_bgp_vrf(
    name: String,
    cfg: &BgpVrfConfig,
    router_id: std::net::Ipv4Addr,
    kernel: Option<RibKnownVrf>,
    global_tx: UnboundedSender<BgpGlobalMsg>,
) -> BgpVrfHandle {
    let ctx = match kernel {
        Some(k) => ProtoContext::for_vrf_no_rib(k.table_id, name.clone()),
        None => {
            tracing::debug!(
                vrf = %name,
                "bgp: spawning per-VRF task with placeholder context (kernel VRF not yet known)",
            );
            ProtoContext::default_table_no_rib()
        }
    };
    // Per-VRF override on router-id wins over the global one. An
    // operator edit to router-id post-spawn doesn't bubble through
    // yet — a follow-up adds the respawn-on-edit detection.
    let effective_router_id = cfg.router_id.unwrap_or(router_id);
    let (vrf, inbox) = BgpVrf::new(name.clone(), ctx, cfg.rd, effective_router_id, global_tx);
    let task = serve_vrf(vrf);
    tracing::info!(
        vrf = %name,
        rd = ?cfg.rd,
        router_id = %effective_router_id,
        table_id = ?kernel.map(|k| k.table_id),
        "bgp: spawned per-VRF task",
    );
    BgpVrfHandle { inbox, task }
}

/// Send `Shutdown` to the per-VRF task. Caller drops the handle
/// from `vrf_registry` *after* this returns; dropping the handle
/// without sending `Shutdown` first would leak a final
/// `BgpVrfMsg` send window — the FSM might miss state it needs to
/// flush. The handle's `Task` aborts on drop regardless, so a
/// failure path here doesn't strand the runtime.
pub fn despawn_bgp_vrf(name: &str, handle: &BgpVrfHandle) {
    if handle.inbox.send(BgpVrfMsg::Shutdown).is_err() {
        // Receiver already gone — the task exited on its own
        // (e.g. inbox-drop path). Nothing left to do.
        tracing::debug!(
            vrf = %name,
            "bgp: despawn target already exited; cleanup is a no-op",
        );
        return;
    }
    tracing::info!(vrf = %name, "bgp: sent Shutdown to per-VRF task");
}

#[cfg(test)]
mod tests {
    //! Pure-function tests on [`compute_vrf_diff`]. Spawn /
    //! despawn themselves need a `Bgp` to drive end-to-end, which
    //! is exercised by the BDD scenarios in step 14's follow-up;
    //! the diff function is the part that's worth unit-testing in
    //! isolation because it's where the spawn / despawn decision
    //! actually lives.
    use std::net::Ipv4Addr;

    use tokio::sync::mpsc::unbounded_channel;

    use super::*;

    fn handle(name: &str) -> BgpVrfHandle {
        let (global_tx, _global_rx) = unbounded_channel::<BgpGlobalMsg>();
        let cfg = BgpVrfConfig::default();
        // Pass `None` for the kernel info — the diff tests don't
        // need the per-VRF `SO_BINDTODEVICE` binding; the
        // placeholder context is enough for lifecycle testing.
        spawn_bgp_vrf(
            name.to_string(),
            &cfg,
            Ipv4Addr::UNSPECIFIED,
            None,
            global_tx,
        )
    }

    #[tokio::test]
    async fn diff_with_no_running_yields_all_as_spawn() {
        let mut desired = BTreeMap::new();
        desired.insert("v1".to_string(), BgpVrfConfig::default());
        desired.insert("v2".to_string(), BgpVrfConfig::default());
        let running: BTreeMap<String, BgpVrfHandle> = BTreeMap::new();

        let (to_spawn, to_despawn) = compute_vrf_diff(&desired, &running);
        assert_eq!(to_spawn, vec!["v1".to_string(), "v2".to_string()]);
        assert!(to_despawn.is_empty());
    }

    #[tokio::test]
    async fn diff_with_no_desired_yields_all_as_despawn() {
        let desired: BTreeMap<String, BgpVrfConfig> = BTreeMap::new();
        let mut running: BTreeMap<String, BgpVrfHandle> = BTreeMap::new();
        running.insert("v1".to_string(), handle("v1"));
        running.insert("v2".to_string(), handle("v2"));

        let (to_spawn, to_despawn) = compute_vrf_diff(&desired, &running);
        assert!(to_spawn.is_empty());
        assert_eq!(to_despawn, vec!["v1".to_string(), "v2".to_string()]);
    }

    #[tokio::test]
    async fn diff_mixed_returns_only_deltas() {
        let mut desired = BTreeMap::new();
        desired.insert("v1".to_string(), BgpVrfConfig::default());
        desired.insert("v3".to_string(), BgpVrfConfig::default()); // new
        let mut running: BTreeMap<String, BgpVrfHandle> = BTreeMap::new();
        running.insert("v1".to_string(), handle("v1")); // unchanged
        running.insert("v2".to_string(), handle("v2")); // removed

        let (to_spawn, to_despawn) = compute_vrf_diff(&desired, &running);
        assert_eq!(to_spawn, vec!["v3".to_string()]);
        assert_eq!(to_despawn, vec!["v2".to_string()]);
    }

    #[tokio::test]
    async fn diff_with_matching_sets_is_empty() {
        let mut desired = BTreeMap::new();
        desired.insert("v1".to_string(), BgpVrfConfig::default());
        let mut running: BTreeMap<String, BgpVrfHandle> = BTreeMap::new();
        running.insert("v1".to_string(), handle("v1"));

        let (to_spawn, to_despawn) = compute_vrf_diff(&desired, &running);
        assert!(to_spawn.is_empty());
        assert!(to_despawn.is_empty());
    }
}
