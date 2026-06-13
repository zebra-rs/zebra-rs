use crate::context::ProtoContext;
use crate::rib;
use crate::stamp::inst;

use super::ConfigManager;

/// Spawn the STAMP instance. Mirrors [`super::bfd::spawn_bfd`]:
/// eager-spawned by the `router ospf` / `router isis` arms in
/// `commit_config` (those protocols capture `stamp_client_tx` by value
/// at their own spawn), so it must be idempotent. A bind failure on
/// the well-known reflector port (862 already taken by an external
/// TWAMP/STAMP daemon) is non-fatal: warn and leave the task out —
/// consumers see a `None` handle and skip measurement.
pub fn spawn_stamp(config: &ConfigManager) {
    if config.protocol_tasks.borrow().contains_key("stamp") {
        return;
    }
    match inst::Stamp::new(ProtoContext::default_table_no_rib()) {
        Ok(stamp) => {
            config.subscribe("stamp", stamp.cm.tx.clone());
            config.subscribe_show("stamp", stamp.show.tx.clone());
            *config.stamp_client_tx.borrow_mut() = Some(stamp.client_req_tx());
            let task = inst::serve(stamp);
            config
                .protocol_tasks
                .borrow_mut()
                .insert("stamp".to_string(), task);
        }
        Err(e) => tracing::warn!("stamp: failed to start instance: {e}"),
    }
}

/// Tear the STAMP instance down once neither consumer protocol
/// (OSPF / IS-IS) remains in the candidate config. Dropping the task
/// aborts the event loop and with it every prober / read task.
pub fn despawn_stamp(config: &ConfigManager) {
    config.cm_clients.borrow_mut().remove("stamp");
    config.show_clients.borrow_mut().remove("stamp");
    config.protocol_tasks.borrow_mut().remove("stamp");
    *config.stamp_client_tx.borrow_mut() = None;
    let _ = config.rib_tx.send(rib::Message::ProtoCleanup {
        proto: "stamp".to_string(),
    });
}
