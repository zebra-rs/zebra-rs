use super::ConfigManager;

/// Spawn the cradle engine-supervisor task. Triggered by [`commit_config`]
/// on the first config line under `system ebpf` or `system cradle`, so the
/// task sees every relevant leaf of that same commit — including a
/// `system cradle grpc-endpoint` committed before (or without) the
/// `system ebpf enabled` switch itself.
///
/// Mirrors `spawn_nd`: hosts that never touch either subtree don't run the
/// task. The task is idle until `system ebpf enabled true` commits; the FIB
/// tee (`system cradle enabled`) stays with the RIB task and needs no
/// spawn here.
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
        let cradle = crate::cradle::Cradle::new();
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
