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

/// Resolved remote-as for an interface-neighbor plus a hint about
/// where the value came from. The provenance bit lets
/// [`materialize_peer`] stamp the inheritance flag on the synthesized
/// peer so the reactive sweep in
/// [`super::neighbor_group::config_neighbor_group_remote_as`] picks
/// it up later.
struct ResolvedRemoteAs {
    asn: u32,
    inherited_from_group: bool,
}

/// Resolve the interface-neighbor's remote-as with provenance. Returns
/// `None` when neither the per-cfg spec nor the referenced group
/// supplies one.
fn resolve_remote_as_with_source(
    bgp: &Bgp,
    cfg: &InterfaceNeighborCfg,
) -> Option<ResolvedRemoteAs> {
    if let Some(asn) = cfg.remote_as.materialize(bgp.asn) {
        return Some(ResolvedRemoteAs {
            asn,
            inherited_from_group: false,
        });
    }
    let asn = super::neighbor_group::group_remote_as(bgp, cfg.neighbor_group.as_ref()?)?;
    Some(ResolvedRemoteAs {
        asn,
        inherited_from_group: true,
    })
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
    let resolved = resolve_remote_as_with_source(bgp, &cfg)?;

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
        resolved.asn,
        link_local.into(),
        bgp.hostname(),
        bgp.tx.clone(),
        bgp.ctx.clone(),
    );
    peer.origin = PeerOrigin::Interface { ifindex };
    // Required for the kernel connect(2) to a fe80:: target —
    // SocketAddrV6 without a scope_id returns EINVAL. The connect
    // path in `peer_start_connection` reads this back out and
    // builds the SocketAddrV6 accordingly.
    peer.scope_id = Some(ifindex);
    // When the remote-as came off the group rather than the per-cfg
    // spec, stamp the back-reference so the reactive sweep on
    // `neighbor-group remote-as` changes can find this peer.
    if resolved.inherited_from_group {
        peer.config.neighbor_group = cfg.neighbor_group.clone();
        peer.config.remote_as_inherited = true;
    }
    bgp.peers.insert_with_key(PeerKey::Interface(ifindex), peer);

    // Kick the FSM. `peer.start()` arms the idle-hold timer which
    // fires Event::Start → fsm_start → peer_start_connection. The
    // timer captures `peer.ident`, so it must run AFTER insert (which
    // assigns the real ident). The gate inside start() also requires
    // `remote_as != 0`, so peers materialized from a `RemoteAsSpec::
    // External` (which yields 0 as a placeholder until OPEN backfill)
    // remain dormant — that case lands in a follow-up alongside the
    // OPEN-side validation.
    let peer = bgp.peers.get_mut_by_key(&PeerKey::Interface(ifindex))?;
    peer.start();
    Some(peer.ident)
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
