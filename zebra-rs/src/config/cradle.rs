use super::ConfigManager;

/// Spawn the cradle engine-supervisor task. Triggered by [`commit_config`]
/// on the first config line under `system ebpf`, `system cradle`, or an
/// `interface … ebpf` leaf, so the task sees every relevant leaf of that
/// same commit — including a `system cradle grpc-endpoint` or a port
/// membership committed before (or without) the `system ebpf enabled`
/// switch itself.
///
/// Mirrors `spawn_nd`: hosts that never touch these subtrees don't run the
/// task. The FIB tee (`system cradle enabled`) stays with the RIB task and
/// needs no spawn here; this task manages the engine process and its port
/// set (default-VRF links — the RIB subscription is bound to the default
/// VRF, matching the `SetPort` vrf 0 scope).
///
/// [`commit_config`]: crate::config::ConfigManager::commit_config
pub fn spawn_cradle(config: &ConfigManager) {
    #[cfg(target_os = "linux")]
    {
        // Idempotent — commit_config seeds its `cradle` flag from
        // `protocol_tasks`, and re-spawning would drop the live supervisor
        // (killing a managed engine with it).
        if config.protocol_tasks.borrow().contains_key("cradle") {
            return;
        }
        let (_rib_client, rib_rx) = config.subscribe_to_rib("cradle");
        let cradle = crate::cradle::Cradle::new(rib_rx);
        config.subscribe("cradle", cradle.cm.tx.clone());
        let task = crate::cradle::serve(cradle);
        config
            .protocol_tasks
            .borrow_mut()
            .insert("cradle".to_string(), task);
    }
    #[cfg(not(target_os = "linux"))]
    let _ = config;
}
