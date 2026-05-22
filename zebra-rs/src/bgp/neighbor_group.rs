//! IOS-XR-style BGP `neighbor-group` (zebra-bgp-neighbor-group.yang).
//!
//! Storage + the resolver shared by every peer-materialization path
//! that may inherit from a group: static peers (`config_peer_neighbor_group`),
//! IPv6 unnumbered (`interface_neighbor::resolve_remote_as`), and dynamic
//! peers (`peer::try_dynamic_accept`). The v1 surface inherits only
//! `remote-as`; per-peer overrides win via the
//! [`super::peer::PeerConfig::remote_as_inherited`] flag.
//!
//! Naming-wise this sits alongside the existing
//! `peer-groups/peer-group` schema, not on top of it: a peer can
//! reference exactly one of (neighbor-group, peer-group) — for now
//! the runtime ignores `peer-group` here, and a future mutual-exclusion
//! pass will pick one.

use std::collections::BTreeMap;

use super::Bgp;
use crate::config::{Args, ConfigOp};

#[derive(Debug, Default, Clone)]
pub struct NeighborGroup {
    pub remote_as: Option<u32>,
}

/// `set router bgp neighbor-groups neighbor-group <name>` — list-key
/// callback. Creates the entry on `Set` and removes it on `Delete`.
pub fn config_neighbor_group(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    match op {
        ConfigOp::Set => {
            bgp.neighbor_groups.entry(name).or_default();
        }
        ConfigOp::Delete => {
            bgp.neighbor_groups.remove(&name);
        }
        _ => {}
    }
    Some(())
}

/// `set router bgp neighbor-groups neighbor-group <name> remote-as <asn>`.
pub fn config_neighbor_group_remote_as(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let group = bgp.neighbor_groups.entry(name).or_default();
    match op {
        ConfigOp::Set => {
            group.remote_as = Some(args.u32()?);
        }
        ConfigOp::Delete => {
            group.remote_as = None;
        }
        _ => {}
    }
    Some(())
}

/// Empty initialiser for the per-Bgp neighbor-group map. Centralised
/// so `Bgp::new` doesn't need to know the storage type.
pub fn empty_map() -> BTreeMap<String, NeighborGroup> {
    BTreeMap::new()
}

/// Look up the `remote-as` advertised by the named neighbor-group, if
/// any. Returns `None` when the group is absent or has no `remote-as`
/// set — both cases mean "the referring peer cannot start yet" and
/// the caller is expected to leave the peer dormant.
pub fn group_remote_as(bgp: &Bgp, name: &str) -> Option<u32> {
    bgp.neighbor_groups.get(name)?.remote_as
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_as_present() {
        let mut map: BTreeMap<String, NeighborGroup> = BTreeMap::new();
        map.insert(
            "RR".into(),
            NeighborGroup {
                remote_as: Some(65000),
            },
        );
        assert_eq!(map.get("RR").and_then(|g| g.remote_as), Some(65000));
    }

    #[test]
    fn remote_as_absent_when_group_missing() {
        let map: BTreeMap<String, NeighborGroup> = BTreeMap::new();
        assert!(!map.contains_key("RR"));
    }

    #[test]
    fn remote_as_absent_when_group_has_no_asn() {
        let mut map: BTreeMap<String, NeighborGroup> = BTreeMap::new();
        map.insert("RR".into(), NeighborGroup { remote_as: None });
        assert_eq!(map.get("RR").and_then(|g| g.remote_as), None);
    }
}
