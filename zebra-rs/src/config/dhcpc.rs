use crate::dhcpc::inst;

use super::ConfigManager;
use super::resolver::spawn_resolver;

/// Spawn the DHCP client task. Triggered by [`commit_config`] on the
/// first `interface <if> ipv4 address dhcp` or `… ipv4 dhcp-options …`
/// line, so a host that never asks for a lease opens no sockets for one.
/// The options count too: committed before `address dhcp`, they would
/// otherwise never reach a task spawned later.
///
/// The task is one process-wide instance following interfaces across
/// VRFs, so it subscribes to the RIB with `global_links` (see
/// `spawn_nd`). It opens its sockets per interface as leases need them;
/// nothing here can fail.
///
/// `system hostname` is sent as the DHCP host name. Its configuration
/// line reaches the task only if committed after the spawn, so the
/// running value is handed over here.
///
/// The leases' name servers go to the resolver task, which gives them to
/// the host's resolver and is spawned here, with its first source.
///
/// [`commit_config`]: crate::config::ConfigManager::commit_config
pub fn spawn_dhcpc(config: &ConfigManager) {
    if config.protocol_tasks.borrow().contains_key("dhcpc") {
        return;
    }
    let (rib_client, rib_rx) = config.subscribe_to_rib_global_links("dhcpc");
    let mut dhcpc = inst::Dhcpc::new(rib_client, rib_rx, config.running_hostname());
    dhcpc.set_resolver(spawn_resolver(config));
    config.subscribe("dhcpc", dhcpc.cm.tx.clone());
    config.subscribe_show("dhcpc", dhcpc.show.tx.clone());
    let task = inst::serve(dhcpc);
    config
        .protocol_tasks
        .borrow_mut()
        .insert("dhcpc".to_string(), task);
}
