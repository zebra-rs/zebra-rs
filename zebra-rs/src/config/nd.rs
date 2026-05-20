use crate::nd::inst;

use super::ConfigManager;

/// Spawn the ND instance at zebra-rs startup.
///
/// Unlike `spawn_ospf` / `spawn_bgp` / `spawn_bfd` this is unconditional
/// — called once from [`ConfigManager`] init regardless of whether
/// any config has been loaded yet. Reason: ND is the receive substrate
/// for IPv6 unnumbered BGP, and we want incoming Router Advertisements
/// to be observable as soon as the daemon is up. Sending RAs requires
/// an explicit operator opt-in via the `send-advertisements` YANG
/// leaf — the per-leaf callback is registered by `Nd::new` itself
/// (see [`crate::nd::config`]).
///
/// If `CAP_NET_RAW` is missing the raw ICMPv6 socket cannot be opened;
/// we log a `warn!` and continue. The daemon stays functional, just
/// without ND.
pub fn spawn_nd(config: &ConfigManager) {
    let (_rib_client, rib_rx) = config.subscribe_to_rib("nd");
    match inst::Nd::new(rib_rx) {
        Ok(nd) => {
            config.subscribe("nd", nd.cm.tx.clone());
            // Publish the ND client-request channel so other protocol
            // modules (BGP unnumbered) can attach a subscriber for
            // `NeighborDiscovered` events at their own spawn time.
            *config.nd_client_tx.borrow_mut() = Some(nd.client_tx());
            let task = inst::serve(nd);
            config
                .protocol_tasks
                .borrow_mut()
                .insert("nd".to_string(), task);
        }
        Err(e) => {
            tracing::warn!("nd: not started ({e}); IPv6 RA send / receive disabled");
        }
    }
}
