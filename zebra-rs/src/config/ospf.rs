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
