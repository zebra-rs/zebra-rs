use crate::nd::inst;
use crate::nd::socket::nd_socket;

use super::ConfigManager;

/// Spawn the ND instance. Triggered by [`commit_config`] in two
/// places:
///
///   * the first config line that contains
///     `ipv6 router-advertisements`, or
///   * the first `router bgp` line — eagerly, so BGP unnumbered's
///     `spawn_bgp` (which captures `nd_client_tx` by value) gets a
///     live handle regardless of whether the operator wrote the RA
///     line first.
///
/// Mirrors `spawn_ospf` / `spawn_isis` / `spawn_bfd`: hosts that
/// never configure either of those subtrees don't pay the cost of
/// opening a raw ICMPv6 socket (and don't see a startup `warn!` if
/// the kernel rejects one of the socket options or `CAP_NET_RAW` is
/// missing).
///
/// [`commit_config`]: crate::config::ConfigManager::commit_config
///
/// If `CAP_NET_RAW` is missing the raw ICMPv6 socket cannot be opened;
/// we log a `warn!` and continue. The daemon stays functional, just
/// without ND.
///
/// The socket is opened *before* the RIB subscription so that a socket
/// failure doesn't leave a dead `RibRx` receiver queued in RIB's
/// inbox — RIB would panic on the link-dump send in that case.
pub fn spawn_nd(config: &ConfigManager) {
    // Idempotent — see `spawn_ospfv3`. Eager-spawned by the BGP arm in
    // `commit_config`; re-spawning would replace the live task and drop
    // ND / RA state. A socket failure below returns early without
    // inserting the task, so a later commit retries.
    if config.protocol_tasks.borrow().contains_key("nd") {
        return;
    }
    let socket = match nd_socket() {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("nd: not started ({e}); IPv6 RA send / receive disabled");
            return;
        }
    };
    // `global_links`, not the default vrf-0 subscription: ND is a
    // single process-wide instance, so it has to follow interfaces
    // across VRF boundaries itself rather than being re-spawned per
    // VRF the way OSPF / IS-IS / BGP are.
    //
    // A plain `subscribe_to_rib("nd")` binds to vrf_id 0, and
    // `Rib::iter_link_subs` only delivers a link event to subscribers
    // whose `vrf_id` matches the link's VRF (or who asked for
    // `global_links`). Two consequences, both of which cost the
    // operator their RAs:
    //
    //   * The subscribe-time link dump skips every enslaved
    //     interface, so `send-advertisements` on a VRF interface
    //     never resolves its name → ifindex and never starts.
    //   * RIB reports a live cross-VRF move as
    //     `api_link_del_vrf(ifindex, old)` + `api_link_add_vrf(link,
    //     new)`. A vrf-0 subscriber sees only the `LinkDel` half, so
    //     `interface eth1 vrf blue` released ND's sender and nothing
    //     ever put it back.
    let (_rib_client, rib_rx) = config.subscribe_to_rib_global_links("nd");
    let nd = inst::Nd::new(socket, rib_rx);
    config.subscribe("nd", nd.cm.tx.clone());
    config.subscribe_show("nd", nd.show.tx.clone());
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
