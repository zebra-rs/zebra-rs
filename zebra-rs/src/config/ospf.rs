use crate::context::ProtoContext;
use crate::ospf::inst;
use crate::rib;

use super::ConfigManager;

pub fn spawn_ospf(config: &ConfigManager) {
    let (rib_client, rib_rx) = config.subscribe_to_rib("ospf");
    let ctx = ProtoContext::default_table(rib_client);
    let ospf = inst::Ospf::<crate::ospf::Ospfv2>::new(ctx, rib_rx);
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
    let (rib_client, rib_rx) = config.subscribe_to_rib("ospfv3");
    let ctx = ProtoContext::default_table(rib_client);
    let ospf = inst::Ospf::<crate::ospf::Ospfv3>::new(ctx, rib_rx);
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
