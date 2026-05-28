use crate::bgp::inst;
use crate::rib;

use super::ConfigManager;

pub fn spawn_bgp(config: &ConfigManager) {
    // Capture BFD / ND client handles so per-neighbor `bfd { enable }`
    // and IPv6 unnumbered RA hand-off can submit requests later. Both
    // are guaranteed to be populated when BGP is spawned via
    // `commit_config`: the BGP arm there pre-spawns ND eagerly, and
    // pre-spawns BFD when the same commit will set `bfd { … }`.
    // Code paths that bypass `commit_config` and call `spawn_bgp`
    // directly may still see `None` here; the captured-by-value
    // contract has not changed.
    let bfd_client_tx = config.bfd_client_tx.borrow().clone();
    let nd_client_tx = config.nd_client_tx.borrow().clone();
    let (rib_client, rib_rx) = config.subscribe_to_rib("bgp");
    let ctx = crate::context::ProtoContext::default_table(rib_client);
    let bgp = inst::Bgp::new(
        ctx,
        rib_rx,
        config.rib_subscriber(),
        config.policy_tx.clone(),
        bfd_client_tx,
        nd_client_tx,
        config.tx.clone(),
    );
    config.subscribe("bgp", bgp.cm.tx.clone());
    config.subscribe_show("bgp", bgp.show.tx.clone());
    let task = inst::serve(bgp);
    config
        .protocol_tasks
        .borrow_mut()
        .insert("bgp".to_string(), task);
}

pub fn despawn_bgp(config: &ConfigManager) {
    config.cm_clients.borrow_mut().remove("bgp");
    config.show_clients.borrow_mut().remove("bgp");
    config.protocol_tasks.borrow_mut().remove("bgp");
    let _ = config.rib_tx.send(rib::Message::ProtoCleanup {
        proto: "bgp".to_string(),
    });
}
