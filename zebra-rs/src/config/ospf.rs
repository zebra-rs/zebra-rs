use crate::context::ProtoContext;
use crate::ospf::inst;
use crate::rib;

use super::ConfigManager;

pub fn spawn_ospf(config: &ConfigManager) {
    // Idempotent — see `spawn_ospfv3`. `commit_config` calls this on
    // every commit whose diff touches `router ospf`; re-spawning would
    // replace the live task and discard its LSDB / translator state.
    // Config reaches the running instance via its `cm` subscription.
    if config.protocol_tasks.borrow().contains_key("ospf") {
        return;
    }
    let (rib_client, rib_rx) = config.subscribe_to_rib("ospf");
    let ctx = ProtoContext::default_table(rib_client);
    // `"ospf"` is the default-instance proto label; per-VRF children
    // get `"ospf:vrf:<name>"`. `rib_subscriber` + `config.tx` let the
    // default task mint per-VRF RIB subscriptions and (de)register
    // `show ip ospf vrf <name>`.
    // BFD is eager-spawned before OSPF in `commit_config`, so this
    // handle is live; threaded in so per-interface `bfd` can subscribe.
    let bfd_client_tx = config.bfd_client_tx.borrow().clone();
    let ospf = inst::Ospf::<crate::ospf::Ospfv2>::new(
        ctx,
        rib_rx,
        config.policy_tx.clone(),
        "ospf".to_string(),
        config.rib_subscriber(),
        config.tx.clone(),
        bfd_client_tx,
    );
    config.subscribe("ospf", ospf.cm.tx.clone());
    config.subscribe_show("ospf", ospf.show.tx.clone());
    let task = inst::serve(ospf);
    config
        .protocol_tasks
        .borrow_mut()
        .insert("ospf".to_string(), task);
}

pub fn despawn_ospf(config: &ConfigManager) {
    config.cm_clients.borrow_mut().remove("ospf");
    config.show_clients.borrow_mut().remove("ospf");
    config.protocol_tasks.borrow_mut().remove("ospf");
    let _ = config.rib_tx.send(rib::Message::ProtoCleanup {
        proto: "ospf".to_string(),
    });
}

/// Spawn an OSPFv3 instance. Mirrors [`spawn_ospf`] but constructs
/// `Ospf<Ospfv3>` instead of the default-typed `Ospf<Ospfv2>` and
/// uses the `"ospfv3"` proto-name across the rib client / config
/// manager / protocol-tasks tables so it doesn't collide with a
/// concurrent OSPFv2 instance.
pub fn spawn_ospfv3(config: &ConfigManager) {
    // Idempotent: `commit_config` calls this on every commit whose diff
    // touches `router ospfv3` (a leaf change emits a `router ospfv3 …`
    // line), but the instance must be spawned only once. Re-spawning
    // would replace the live task — discarding its LSDB and translator
    // state, and orphaning self-originated AS-scoped LSAs on neighbors
    // (a translated Type-5 never gets a MaxAge). Config changes reach
    // the running instance through its `cm` subscription, so a respawn
    // is never needed to apply them.
    if config.protocol_tasks.borrow().contains_key("ospfv3") {
        return;
    }
    let (rib_client, rib_rx) = config.subscribe_to_rib("ospfv3");
    let ctx = ProtoContext::default_table(rib_client);
    // `"ospfv3"` default label; per-VRF children get
    // `"ospfv3:vrf:<name>"`. See `spawn_ospf` for the rationale.
    let bfd_client_tx = config.bfd_client_tx.borrow().clone();
    let ospf = inst::Ospf::<crate::ospf::Ospfv3>::new(
        ctx,
        rib_rx,
        config.policy_tx.clone(),
        "ospfv3".to_string(),
        config.rib_subscriber(),
        config.tx.clone(),
        bfd_client_tx,
    );
    config.subscribe("ospfv3", ospf.cm.tx.clone());
    config.subscribe_show("ospfv3", ospf.show.tx.clone());
    let task = inst::serve_v3(ospf);
    config
        .protocol_tasks
        .borrow_mut()
        .insert("ospfv3".to_string(), task);
}

pub fn despawn_ospfv3(config: &ConfigManager) {
    config.cm_clients.borrow_mut().remove("ospfv3");
    config.show_clients.borrow_mut().remove("ospfv3");
    config.protocol_tasks.borrow_mut().remove("ospfv3");
    let _ = config.rib_tx.send(rib::Message::ProtoCleanup {
        proto: "ospfv3".to_string(),
    });
}
