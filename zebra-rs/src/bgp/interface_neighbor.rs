//! BGP interface-keyed neighbor runtime (IPv6 unnumbered).
//!
//! Stores the operator-typed `interface-neighbor` config and the
//! ifindex-resolution machinery. Peer materialization on RA arrival
//! is driven by [`super::inst::Bgp`]'s NdEvent subscription arm.

use std::collections::BTreeMap;
use std::net::Ipv6Addr;

use super::Bgp;
use super::peer::Peer;
use super::peer_key::{PeerKey, PeerOrigin};
use crate::config::{Args, ConfigOp};

/// `remote-as` may be a numeric AS or one of the FRR-style
/// shortcuts `external` / `internal`. The shortcuts are resolved at
/// materialization time against the local ASN (for `internal`); the
/// `external` case is materialized with `remote_as = 0` and the
/// actual peer AS is learned from the OPEN — strict
/// same-AS-rejection validation lands in a follow-up.
#[derive(Debug, Default, Clone, PartialEq, Eq, Copy)]
pub enum RemoteAsSpec {
    #[default]
    Unset,
    Asn(u32),
    External,
    Internal,
}

impl RemoteAsSpec {
    /// Materialize the spec against the local ASN. Returns `None` if
    /// the spec is `Unset` — the caller defers peer creation until
    /// the operator types `remote-as` (or a referenced
    /// `neighbor-group` carries one).
    pub fn materialize(&self, local_as: u32) -> Option<u32> {
        match self {
            Self::Unset => None,
            Self::Asn(a) => Some(*a),
            Self::Internal => Some(local_as),
            // External: actual remote AS is learned from OPEN. Use 0
            // as the placeholder; fsm_bgp_open backfills.
            Self::External => Some(0),
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct InterfaceNeighborCfg {
    pub neighbor_group: Option<String>,
    pub remote_as: RemoteAsSpec,
}

/// Look up the resolved remote AS for an interface-neighbor against
/// its referenced neighbor-group fallback.
pub fn resolve_remote_as(bgp: &Bgp, cfg: &InterfaceNeighborCfg) -> Option<u32> {
    if let Some(asn) = cfg.remote_as.materialize(bgp.asn) {
        return Some(asn);
    }
    let group_name = cfg.neighbor_group.as_ref()?;
    let group = bgp.neighbor_groups.get(group_name)?;
    group.remote_as
}

/// Materialize a Peer for `interface-neighbor IFNAME` once an RA has
/// surfaced its link-local. Returns the index assigned by PeerMap
/// (or `None` if config gates aren't satisfied — silent so the caller
/// can simply retry on the next RA).
pub fn materialize_peer(
    bgp: &mut Bgp,
    name: &str,
    ifindex: u32,
    link_local: Ipv6Addr,
) -> Option<usize> {
    let cfg = bgp.interface_neighbors.get(name)?.clone();
    let remote_as = resolve_remote_as(bgp, &cfg)?;

    // Already materialized? Refresh address (the peer's link-local
    // can change if the kernel reassigns it) but otherwise leave the
    // FSM alone.
    if let Some(existing) = bgp.peers.get_mut_by_key(&PeerKey::Interface(ifindex)) {
        existing.address = link_local.into();
        return Some(existing.ident);
    }

    let mut peer = Peer::new(
        0,
        bgp.asn,
        bgp.router_id,
        remote_as,
        link_local.into(),
        bgp.hostname(),
        bgp.tx.clone(),
    );
    peer.origin = PeerOrigin::Interface { ifindex };
    bgp.peers.insert_with_key(PeerKey::Interface(ifindex), peer);
    bgp.peers
        .get_by_key(&PeerKey::Interface(ifindex))
        .map(|p| p.ident)
}

/// `set router bgp interface-neighbor <name>` — list-key callback.
pub fn config_interface_neighbor(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    match op {
        ConfigOp::Set => {
            bgp.interface_neighbors.entry(name).or_default();
        }
        ConfigOp::Delete => {
            // Take the cfg out first so we can tear the peer (if any)
            // down without holding a borrow.
            bgp.interface_neighbors.remove(&name);
            if let Some(&ifindex) = bgp.link_index_by_name.get(&name) {
                bgp.peers.remove_by_key(&PeerKey::Interface(ifindex));
            }
        }
        _ => {}
    }
    Some(())
}

/// `set router bgp interface-neighbor <name> neighbor-group <group>`.
pub fn config_interface_neighbor_neighbor_group(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let name = args.string()?;
    let entry = bgp.interface_neighbors.entry(name).or_default();
    match op {
        ConfigOp::Set => entry.neighbor_group = Some(args.string()?),
        ConfigOp::Delete => entry.neighbor_group = None,
        _ => {}
    }
    Some(())
}

/// `set router bgp interface-neighbor <name> remote-as <ASN|external|internal>`.
pub fn config_interface_neighbor_remote_as(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let name = args.string()?;
    let entry = bgp.interface_neighbors.entry(name).or_default();
    match op {
        ConfigOp::Set => {
            let raw = args.string()?;
            entry.remote_as = match raw.as_str() {
                "external" => RemoteAsSpec::External,
                "internal" => RemoteAsSpec::Internal,
                numeric => RemoteAsSpec::Asn(numeric.parse().ok()?),
            };
        }
        ConfigOp::Delete => entry.remote_as = RemoteAsSpec::Unset,
        _ => {}
    }
    Some(())
}

/// Empty initialiser for the per-Bgp interface-neighbor map.
pub fn empty_map() -> BTreeMap<String, InterfaceNeighborCfg> {
    BTreeMap::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn materialize_asn_returns_numeric() {
        assert_eq!(RemoteAsSpec::Asn(65001).materialize(64512), Some(65001));
    }

    #[test]
    fn materialize_internal_returns_local_as() {
        assert_eq!(RemoteAsSpec::Internal.materialize(64512), Some(64512));
    }

    #[test]
    fn materialize_external_returns_zero_placeholder() {
        // OPEN backfills the real value; 0 keeps the peer at
        // `remote_as = 0` until then.
        assert_eq!(RemoteAsSpec::External.materialize(64512), Some(0));
    }

    #[test]
    fn materialize_unset_returns_none() {
        assert_eq!(RemoteAsSpec::Unset.materialize(64512), None);
    }
}
