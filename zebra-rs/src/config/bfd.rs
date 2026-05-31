use crate::bfd::inst;
use crate::context::ProtoContext;
use crate::rib;

use super::ConfigManager;

/// Spawn the BFD instance the first time `bfd` configuration appears.
/// Mirrors [`super::ospf::spawn_ospf`] / [`super::isis::spawn_isis`] /
/// [`super::bgp::spawn_bgp`]. Registers the per-instance config
/// channel so committed `/bfd/*` leaves reach the callback
/// dispatcher.
pub fn spawn_bfd(config: &ConfigManager) {
    // BFD doesn't subscribe to RIB today — the `default_table_no_rib`
    // constructor builds a parked `RibClient` so the ctx still has
    // a `rib` field for uniformity with the other protocols.
    let _ = config; // borrow ConfigManager only when needed.
    match inst::Bfd::new(ProtoContext::default_table_no_rib()) {
        Ok(bfd) => {
            config.subscribe("bfd", bfd.cm.tx.clone());
            config.subscribe_show("bfd", bfd.show.tx.clone());
            // Publish the inbound client-request handle on the
            // ConfigManager so protocol modules (BGP / OSPF / IS-IS /
            // static) can pick it up at *their* spawn time and later
            // submit ClientReq::Subscribe / Unsubscribe against this
            // BFD instance.
            *config.bfd_client_tx.borrow_mut() = Some(bfd.client_req_tx());
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
/// future BFD-installed routes. The published client_req_tx handle
/// is also cleared so a respawn produces a fresh channel.
pub fn despawn_bfd(config: &ConfigManager) {
    config.cm_clients.borrow_mut().remove("bfd");
    config.show_clients.borrow_mut().remove("bfd");
    config.protocol_tasks.borrow_mut().remove("bfd");
    *config.bfd_client_tx.borrow_mut() = None;
    let _ = config.rib_tx.send(rib::Message::ProtoCleanup {
        proto: "bfd".to_string(),
    });
}
