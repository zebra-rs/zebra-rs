use crate::context::Context;
use crate::isis::inst;
use crate::rib;

use super::ConfigManager;

pub fn spawn_isis(config: &ConfigManager) {
    let ctx = Context::default();
    // Capture BFD's client handle (if BFD is already spawned) so per-
    // interface `bfd { enable }` can later submit Subscribe /
    // Unsubscribe. If `bfd { ... }` is configured *after* IS-IS, the
    // handle stays None and the BFD attach is a no-op — late-binding
    // refresh is a follow-up.
    let bfd_client_tx = config.bfd_client_tx.borrow().clone();
    let isis = inst::Isis::new(ctx, config.rib_tx.clone(), bfd_client_tx);
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
