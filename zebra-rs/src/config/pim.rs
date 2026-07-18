use crate::context::ProtoContext;
use crate::pim::inst;
use crate::pim::mroute::ForwardingPlane;
use crate::pim::socket::{igmp_socket, pim_socket};
use crate::rib;

use super::ConfigManager;

/// Spawn the PIM instance the first time `router pim` configuration
/// appears. Mirrors [`super::isis::spawn_isis`].
pub fn spawn_pim(config: &ConfigManager) {
    // Idempotent — see `spawn_ospfv3`. `commit_config` calls this on
    // every commit whose diff touches `router pim`; re-spawning would
    // replace the live task and drop every neighbor.
    if config.protocol_tasks.borrow().contains_key("pim") {
        return;
    }
    // Open both raw sockets (protocol 103 + IGMP) before
    // `subscribe_to_rib` so a socket failure (missing CAP_NET_RAW)
    // doesn't leave a dead RibRx receiver queued in RIB's inbox — see
    // `spawn_nd`. The probe context is default-table, so no VRF
    // binding is involved.
    let probe = ProtoContext::default_table_no_rib();
    let sock = match pim_socket(&probe) {
        Ok(sock) => sock,
        Err(e) => {
            tracing::warn!("pim: not started ({e}); PIM disabled");
            return;
        }
    };
    let igmp_sock = match igmp_socket(&probe) {
        Ok(sock) => sock,
        Err(e) => {
            tracing::warn!("pim: not started (igmp socket: {e}); PIM disabled");
            return;
        }
    };
    // The mroute socket claims the kernel's multicast-routing
    // instance (MRT_INIT) — EADDRINUSE means another multicast
    // daemon owns it on this host.
    let fp = match ForwardingPlane::new(&probe) {
        Ok(fp) => fp,
        Err(e) => {
            tracing::warn!("pim: not started (mroute socket: {e}); PIM disabled");
            return;
        }
    };
    let (rib_client, rib_rx) = config.subscribe_to_rib("pim");
    let ctx = ProtoContext::default_table(rib_client);
    let pim = inst::Pim::new(ctx, sock, igmp_sock, fp, rib_rx);
    config.subscribe("pim", pim.cm.tx.clone());
    config.subscribe_show("pim", pim.show.tx.clone());
    let task = inst::serve(pim);
    config
        .protocol_tasks
        .borrow_mut()
        .insert("pim".to_string(), task);
}

/// Tear down the PIM instance when its `router pim` block has been
/// removed from the candidate config. Dropping the task aborts the
/// event loop, which closes the packet channels and so ends the
/// read / write tasks; `ProtoCleanup` keeps the despawn contract
/// uniform with the other protocols (PIM installs no unicast routes
/// yet).
pub fn despawn_pim(config: &ConfigManager) {
    config.cm_clients.borrow_mut().remove("pim");
    config.show_clients.borrow_mut().remove("pim");
    config.protocol_tasks.borrow_mut().remove("pim");
    let _ = config.rib_tx.send(rib::Message::ProtoCleanup {
        proto: "pim".to_string(),
    });
}
