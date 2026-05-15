//! IOS-XR-style BGP `neighbor-group` (zebra-bgp-neighbor-group.yang).
//!
//! Phase 1 (this commit): schema + storage only. Each
//! `set router bgp neighbor-groups neighbor-group <name> remote-as <asn>`
//! lands here; each `set router bgp neighbor <addr> neighbor-group <g>`
//! records the per-peer reference. The runtime does NOT yet resolve
//! field-level inheritance — peers continue to use values set
//! explicitly on the neighbor (and zero / default for the rest).
//! Field-level override resolution is a follow-up.
//!
//! Naming-wise this sits alongside the existing
//! `peer-groups/peer-group` schema, not on top of it: a peer can
//! reference exactly one of (neighbor-group, peer-group) — for now
//! the runtime ignores both, and the future resolver will pick
//! one.

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
