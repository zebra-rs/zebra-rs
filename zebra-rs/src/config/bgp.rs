use crate::bgp::inst;
use crate::rib;

use super::ConfigManager;

pub fn spawn_bgp(config: &ConfigManager) {
    // Capture BFD's client handle (if BFD is already spawned) so per-
    // neighbor `bfd { enable }` can later submit Subscribe / Unsubscribe.
    // If `bfd { ... }` is configured *after* `router bgp`, BGP's handle
    // stays None and the BFD attach is a no-op — PR 5d adds a refresh
    // path for that ordering.
    let bfd_client_tx = config.bfd_client_tx.borrow().clone();
    let bgp = inst::Bgp::new(
        config.rib_tx.clone(),
        config.policy_tx.clone(),
        bfd_client_tx,
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
