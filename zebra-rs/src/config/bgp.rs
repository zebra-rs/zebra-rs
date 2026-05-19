use crate::bgp::inst;
use crate::rib;

use super::ConfigManager;

pub fn spawn_bgp(config: &ConfigManager) {
    let bgp = inst::Bgp::new(config.rib_tx.clone(), config.policy_tx.clone());
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
