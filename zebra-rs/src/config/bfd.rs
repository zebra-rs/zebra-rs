use crate::bfd::inst;
use crate::context::Context;
use crate::rib;

use super::ConfigManager;

/// Spawn the BFD instance the first time `bfd` configuration appears.
/// Mirrors [`super::ospf::spawn_ospf`] / [`super::isis::spawn_isis`] /
/// [`super::bgp::spawn_bgp`]. Registers the per-instance config
/// channel so committed `/bfd/*` leaves reach the callback
/// dispatcher.
pub fn spawn_bfd(config: &ConfigManager) {
    match inst::Bfd::new(Context::default()) {
        Ok(bfd) => {
            config.subscribe("bfd", bfd.cm.tx.clone());
            let task = inst::serve(bfd);
            config
                .protocol_tasks
                .borrow_mut()
                .insert("bfd".to_string(), task);
        }
        Err(e) => tracing::warn!("bfd: failed to start instance: {e}"),
    }
}

/// Tear down the BFD instance when its top-level `bfd` block has been
/// removed from the candidate config. Dropping the [`Task`] aborts
/// the event loop; [`rib::Message::ProtoCleanup`] withdraws any
/// future BFD-installed routes.
pub fn despawn_bfd(config: &ConfigManager) {
    config.cm_clients.borrow_mut().remove("bfd");
    config.show_clients.borrow_mut().remove("bfd");
    config.protocol_tasks.borrow_mut().remove("bfd");
    let _ = config.rib_tx.send(rib::Message::ProtoCleanup {
        proto: "bfd".to_string(),
    });
}
