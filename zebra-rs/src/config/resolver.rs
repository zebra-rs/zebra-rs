use crate::resolver::ResolverTx;
use crate::resolver::inst;
use crate::resolver::resolvectl::Resolvectl;

use super::ConfigManager;

/// Spawn the resolver task, or find the one there is, and give the
/// sender its sources report to. Triggered by [`commit_config`] on the
/// first `system name-server …` line, and by whoever spawns a source
/// (`spawn_dhcpc`, `spawn_nd`): a source takes the sender at its own
/// spawn, so the task must be there first, whichever the operator
/// configures first.
///
/// The task opens nothing and runs nothing until an interface it is
/// configured for has learned a name server.
///
/// [`commit_config`]: crate::config::ConfigManager::commit_config
pub fn spawn_resolver(config: &ConfigManager) -> ResolverTx {
    if let Some(tx) = config.resolver_tx.borrow().as_ref() {
        return tx.clone();
    }
    let resolver = inst::Resolver::new(Resolvectl::from_env());
    let tx = resolver.tx();
    config.subscribe("resolver", resolver.cm.tx.clone());
    *config.resolver_tx.borrow_mut() = Some(tx.clone());
    let task = inst::serve(resolver);
    config
        .protocol_tasks
        .borrow_mut()
        .insert("resolver".to_string(), task);
    tx
}
