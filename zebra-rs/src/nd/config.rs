//! YANG callback dispatch for the per-interface RA send opt-in
//! (`interface X ipv6 router-advertisements send-advertisements …`),
//! and for the RA host (`interface X ipv6 address autoconf`,
//! `interface X ipv6 ra-options …`).
//!
//! Modelled on `bfd::config` — each leaf gets a free-standing callback
//! that mutates the engine's state directly. The RA host's leaves are
//! the exception: a callback only notes them, and they take effect
//! together at the end of the commit ([`RaHosts::stage_config`]), so
//! that a host never runs under half of what a commit says of it.
//!
//! [`callbacks`] is the table, built once at [`super::inst::Nd::new`]
//! time, and [`dispatch`] routes a `ConfigRequest` to its callback by
//! path. Both work on the engine and not on the task, which owns a raw
//! socket and cannot be built in a test.
//!
//! [`RaHosts::stage_config`]: super::host::RaHosts::stage_config

use std::collections::HashMap;
use std::time::Instant;

use crate::config::{Args, ConfigOp, ConfigRequest, path_from_command};

use super::engine::NdEngine;
use super::host::DEFAULT_DISTANCE;
use super::send::RaSendConfig;

pub type Callback = fn(&mut NdEngine, Args, ConfigOp) -> Option<()>;

/// The RA sender's leaves are under this. Keeping it as a constant
/// matches the OSPF / BFD pattern in this repo and makes additions easier
/// to spot.
const ND_IF: &str = "/interface/ipv6/router-advertisements";

/// The RA host's options.
const RA_OPTIONS: &str = "/interface/ipv6/ra-options";

/// Every path the `nd` task takes configuration from, and its callback.
pub fn callbacks() -> HashMap<String, Callback> {
    let mut callbacks: HashMap<String, Callback> = HashMap::new();
    callbacks.insert(
        format!("{ND_IF}/send-advertisements"),
        config_send_advertisements,
    );
    callbacks.insert("/interface/ipv6/address".to_string(), config_address);
    callbacks.insert("/interface/ipv6/dhcpv6-options/pd".to_string(), config_pd);
    let options: [(&str, Callback); 3] = [
        ("/default-route-distance", config_distance),
        ("/no-default-route", config_no_default_route),
        ("/no-name-server", config_no_name_server),
    ];
    for (leaf, callback) in options {
        callbacks.insert(format!("{RA_OPTIONS}{leaf}"), callback);
    }
    callbacks
}

/// One message of a commit: a leaf goes to its callback, and the end of
/// the commit puts the RA host's leaves into force, all at once.
pub fn dispatch(
    engine: &mut NdEngine,
    callbacks: &HashMap<String, Callback>,
    msg: ConfigRequest,
    now: Instant,
) {
    if msg.op == ConfigOp::CommitEnd {
        engine.hosts_mut().commit_config(now);
        return;
    }
    let (path, args) = path_from_command(&msg.paths);
    if let Some(f) = callbacks.get(&path) {
        f(engine, args, msg.op);
    }
}

fn config_send_advertisements(engine: &mut NdEngine, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    // A delete may arrive without the leaf value — default to false
    // so it still lands in the unset branch.
    let enable = args.boolean().unwrap_or(false);

    // The engine stores the config keyed by interface name, so it
    // survives the race against RIB's link dump (which arrives on a
    // separate channel and may not have populated the name → ifindex
    // map yet) and applies when the link appears.
    if op.is_set() && enable {
        engine.set_ra_config(name, RaSendConfig::default(), Instant::now());
    } else {
        engine.unset_ra_config(&name);
    }
    Some(())
}

/// `interface <if> ipv6 address …`: the `autoconf` and `dhcpv6` values
/// are ours, each of them running the RA host; the RIB handles the
/// prefixes, and the DHCP client the lease `dhcpv6` asks for. A delete
/// with no value removes every address, these two included.
fn config_address(engine: &mut NdEngine, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let mut values = Vec::new();
    while let Some(value) = args.string() {
        values.push(value);
    }
    let enabled = match op {
        ConfigOp::Set => true,
        ConfigOp::Delete => false,
        _ => return Some(()),
    };
    let all = !enabled && values.is_empty();
    let autoconf = all || values.iter().any(|v| v == "autoconf");
    let dhcpv6 = all || values.iter().any(|v| v == "dhcpv6");
    if !autoconf && !dhcpv6 {
        return Some(());
    }
    engine.hosts_mut().stage_config(&name, |cfg| {
        if autoconf {
            cfg.autoconf = enabled;
        }
        if dhcpv6 {
            cfg.dhcpv6 = enabled;
        }
    });
    Some(())
}

/// `interface <if> ipv6 dhcpv6-options pd <id>`: the DHCP client asks for
/// a delegated prefix, and the RA host runs for the default route its
/// traffic leaves by.
fn config_pd(engine: &mut NdEngine, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let id = args.u32()?;
    let set = match op {
        ConfigOp::Set => true,
        ConfigOp::Delete => false,
        _ => return Some(()),
    };
    engine.hosts_mut().stage_config(&name, |cfg| {
        if set {
            cfg.pd.insert(id);
        } else {
            cfg.pd.remove(&id);
        }
    });
    Some(())
}

fn config_distance(engine: &mut NdEngine, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let distance = if op.is_set() {
        args.u8()?
    } else {
        DEFAULT_DISTANCE
    };
    engine
        .hosts_mut()
        .stage_config(&name, |cfg| cfg.distance = distance);
    Some(())
}

fn config_no_default_route(engine: &mut NdEngine, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    engine
        .hosts_mut()
        .stage_config(&name, |cfg| cfg.no_default_route = op.is_set());
    Some(())
}

fn config_no_name_server(engine: &mut NdEngine, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    engine
        .hosts_mut()
        .stage_config(&name, |cfg| cfg.no_name_server = op.is_set());
    Some(())
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, VecDeque};

    use super::*;

    /// `dhcpv6-options pd <id>` is one more thing that asks for the RA
    /// host, counted by its id: the host is wanted until the last
    /// delegation of the interface is deleted.
    #[test]
    fn a_delegation_asks_for_the_ra_host() {
        let mut engine = NdEngine::new();
        let callback = callbacks()["/interface/ipv6/dhcpv6-options/pd"];
        let line = |engine: &mut NdEngine, id: &str, op: ConfigOp| {
            let args = Args(VecDeque::from(["wan0".to_string(), id.to_string()]));
            callback(engine, args, op);
            engine.hosts_mut().commit_config(Instant::now());
        };
        line(&mut engine, "1", ConfigOp::Set);
        line(&mut engine, "7", ConfigOp::Set);
        assert_eq!(engine.hosts().config("wan0").pd, BTreeSet::from([1, 7]));
        assert!(engine.hosts().config("wan0").enabled());
        line(&mut engine, "1", ConfigOp::Delete);
        assert_eq!(engine.hosts().config("wan0").pd, BTreeSet::from([7]));
        assert!(engine.hosts().config("wan0").enabled());
        // Another interface's delegation is not this one's.
        assert!(!engine.hosts().config("wan1").enabled());
        line(&mut engine, "7", ConfigOp::Delete);
        assert!(!engine.hosts().config("wan0").enabled());
    }
}
