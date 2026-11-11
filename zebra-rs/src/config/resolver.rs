use crate::resolver::ResolverTx;
use crate::resolver::inst;
use crate::resolver::resolvectl::Resolvectl;

use super::ConfigManager;

/// Spawn the resolver task, or find the one there is, and give the
/// sender its sources report to. Triggered by whoever spawns a source of
/// name servers (`spawn_dhcpc`, `spawn_nd`): a source takes the sender
/// at its own spawn, so the task must be there first, whichever the
/// operator configures first.
///
/// The task has no configuration and subscribes to none: what a source
/// reports is the host's to use, and whether an interface's name servers
/// are reported is the source's configuration (`interface <if> ipv4
/// dhcp-options no-name-server`, `interface <if> ipv6 ra-options
/// no-name-server`).
///
/// It opens nothing and runs nothing until an interface has learned a
/// name server.
pub fn spawn_resolver(config: &ConfigManager) -> ResolverTx {
    if let Some(tx) = config.resolver_tx.borrow().as_ref() {
        return tx.clone();
    }
    let resolver = inst::Resolver::new(Resolvectl::from_env());
    let tx = resolver.tx();
    *config.resolver_tx.borrow_mut() = Some(tx.clone());
    let task = inst::serve(resolver);
    config
        .protocol_tasks
        .borrow_mut()
        .insert("resolver".to_string(), task);
    tx
}
