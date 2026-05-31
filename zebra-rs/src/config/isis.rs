use crate::context::ProtoContext;
use crate::isis::inst;
use crate::rib;

use super::ConfigManager;

pub fn spawn_isis(config: &ConfigManager) {
    // Capture BFD's client handle so per-interface `isis bfd` can later
    // submit Subscribe / Unsubscribe. `commit_config` spawns BFD
    // eagerly before IS-IS, so the handle is always live here —
    // independent of commit order and of whether a top-level
    // `bfd { … }` block exists. Callers that bypass `commit_config`
    // may still see `None`.
    let bfd_client_tx = config.bfd_client_tx.borrow().clone();
    // BGP-LS producer (RFC 9552): the IS-IS task pushes Link-State routes
    // to BGP over this sender. Captured by value — `None` if `router bgp`
    // is committed after `router isis` (cross-commit), matching the
    // `bfd_client_tx` limitation; `commit_config` pre-spawns BGP first
    // within a single commit.
    let bgp_tx = config.bgp_tx.borrow().clone();
    let (rib_client, rib_rx) = config.subscribe_to_rib("isis");
    let ctx = ProtoContext::default_table(rib_client);
    // `"isis"` is the default-instance proto label. Per-VRF children
    // get `"isis:vrf:<name>"` labels when the IS-IS task spawns them.
    // `rib_subscriber` + `config.tx` let the default task mint per-VRF
    // RIB subscriptions and (de)register `show isis vrf <name>`.
    let isis = inst::Isis::new(
        ctx,
        rib_rx,
        bfd_client_tx,
        bgp_tx,
        config.policy_tx.clone(),
        "isis".to_string(),
        config.rib_subscriber(),
        config.tx.clone(),
    );
    config.subscribe("isis", isis.cm.tx.clone());
    config.subscribe_show("isis", isis.show.tx.clone());
    let task = inst::serve(isis);
    config
        .protocol_tasks
        .borrow_mut()
        .insert("isis".to_string(), task);
}

pub fn despawn_isis(config: &ConfigManager) {
    config.cm_clients.borrow_mut().remove("isis");
    config.show_clients.borrow_mut().remove("isis");
    config.protocol_tasks.borrow_mut().remove("isis");
    let _ = config.rib_tx.send(rib::Message::ProtoCleanup {
        proto: "isis".to_string(),
    });
}
