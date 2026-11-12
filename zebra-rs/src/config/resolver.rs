use std::path::PathBuf;

use crate::resolver::ResolverTx;
use crate::resolver::inst;
use crate::resolver::record::{self, Record};
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
/// It runs nothing until an interface has learned a name server, or the
/// wait is over for one that a run before this one left set
/// ([`resume_resolver`]).
pub fn spawn_resolver(config: &ConfigManager) -> ResolverTx {
    if let Some(tx) = config.resolver_tx.borrow().as_ref() {
        return tx.clone();
    }
    spawn_with(config, host_record())
}

/// What the run before this one left on this host. A unit test is not
/// a run of this host's zebra-rs and takes over nothing: whatever a
/// record there names is not a test's to take back.
fn host_record() -> Record {
    if cfg!(test) {
        Record::default()
    } else {
        Record::load(record_path(), record::boot_id())
    }
}

/// The task, taking over from the run that left `record`.
fn spawn_with(config: &ConfigManager, record: Record) -> ResolverTx {
    let mut resolver = inst::Resolver::new(Resolvectl::from_env());
    resolver.resume(record, config.leftover_sweep_time.get());
    let tx = resolver.tx();
    *config.resolver_tx.borrow_mut() = Some(tx.clone());
    let task = inst::serve(resolver);
    config
        .protocol_tasks
        .borrow_mut()
        .insert("resolver".to_string(), task);
    tx
}

/// The task's record of the interfaces that hold something of ours,
/// beside the DHCP client's leases.
fn record_path() -> PathBuf {
    crate::dhcpc::lease::default_dir().join(record::FILE)
}

/// At startup, before the configuration is read: spawn the resolver task
/// if a run before this one left name servers set.
///
/// Otherwise the task comes with its first source, and a configuration
/// that has none any more (`address dhcp` deleted while zebra-rs was not
/// running) would leave nobody to take them back.
pub fn resume_resolver(config: &ConfigManager) {
    resume_from(config, host_record());
}

pub(super) fn resume_from(config: &ConfigManager, record: Record) {
    if !record.links().is_empty() && config.resolver_tx.borrow().is_none() {
        spawn_with(config, record);
    }
}
