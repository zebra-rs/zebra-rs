use crate::nd::inst;
use crate::nd::socket::nd_socket;

use super::ConfigManager;

/// Spawn the ND instance on first commit that mentions
/// `ipv6 router-advertisements`.
///
/// Mirrors `spawn_ospf` / `spawn_bgp` / `spawn_bfd`: the dispatch in
/// [`crate::config::ConfigManager::commit_config`] gates the call so
/// hosts that never configure RAs don't pay the cost of opening a
/// raw ICMPv6 socket (and don't see a startup `warn!` if the kernel
/// rejects one of the socket options or `CAP_NET_RAW` is missing).
///
/// BGP unnumbered also depends on ND — `spawn_bgp` captures
/// `nd_client_tx` at spawn time. If `router bgp` is committed before
/// any RA-touching line, BGP's handle stays `None`; that ordering
/// caveat is identical to the BFD case noted in `spawn_bgp`.
///
/// If `CAP_NET_RAW` is missing the raw ICMPv6 socket cannot be opened;
/// we log a `warn!` and continue. The daemon stays functional, just
/// without ND.
///
/// The socket is opened *before* `subscribe_to_rib` so that a socket
/// failure doesn't leave a dead `RibRx` receiver queued in RIB's
/// inbox — RIB would panic on the link-dump send in that case.
pub fn spawn_nd(config: &ConfigManager) {
    let socket = match nd_socket() {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("nd: not started ({e}); IPv6 RA send / receive disabled");
            return;
        }
    };
    let (_rib_client, rib_rx) = config.subscribe_to_rib("nd");
    let nd = inst::Nd::new(socket, rib_rx);
    config.subscribe("nd", nd.cm.tx.clone());
    // Publish the ND client-request channel so other protocol modules
    // (BGP unnumbered) can attach a subscriber for `NeighborDiscovered`
    // events at their own spawn time.
    *config.nd_client_tx.borrow_mut() = Some(nd.client_tx());
    let task = inst::serve(nd);
    config
        .protocol_tasks
        .borrow_mut()
        .insert("nd".to_string(), task);
}
