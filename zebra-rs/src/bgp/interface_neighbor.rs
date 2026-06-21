//! BGP interface-keyed neighbor runtime (IPv6 unnumbered).
//!
//! Stores the operator-typed `interface-neighbor` config and the
//! ifindex-resolution machinery. Peer materialization on RA arrival
//! is driven by [`super::inst::Bgp`]'s NdEvent subscription arm.

use std::collections::BTreeMap;
use std::net::Ipv6Addr;
use std::time::Instant;

use super::Bgp;
use super::peer::{Peer, PeerType};
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
    materialize(bgp, name, ifindex, Some(link_local))
}

/// Materialize a dormant Peer for `interface-neighbor IFNAME` before
/// any RA has surfaced the remote link-local. The address stays
/// unspecified and the FSM is left alone (`peer.start()` gates on a
/// dialable address), so the peer is operator-visible state only:
/// `show bgp summary` / `show bgp neighbor` list the configured
/// neighbor as Idle even when the remote node has never been up,
/// matching FRR. The RA path ([`materialize_peer`]) upgrades it in
/// place. `None` when the interface is unknown to RIB yet or the
/// config gates (resolvable remote-as) aren't satisfied — callers
/// simply retry on the next config/link event.
pub fn materialize_dormant(bgp: &mut Bgp, name: &str) -> Option<usize> {
    let ifindex = *bgp.link_index_by_name.get(name)?;
    materialize(bgp, name, ifindex, None)
}

fn materialize(
    bgp: &mut Bgp,
    name: &str,
    ifindex: u32,
    link_local: Option<Ipv6Addr>,
) -> Option<usize> {
    let cfg = bgp.interface_neighbors.get(name)?.clone();
    let resolved = resolve_remote_as_with_source(bgp, &cfg)?;

    // Already materialized? Refresh address (the peer's link-local
    // can change if the kernel reassigns it) but otherwise leave the
    // FSM alone — except a dormant peer (materialized at config time,
    // address still unspecified), which gets its first kick here.
    if let Some(existing) = bgp.peers.get_mut_by_key(&PeerKey::Interface(ifindex)) {
        if let Some(link_local) = link_local {
            existing.address = link_local.into();
            nd_mark_refreshed(existing, Instant::now());
            // No-op on a running peer (`start()` gates on `!active`);
            // a dormant one leaves Idle now that it can dial.
            existing.start();
        }
        return Some(existing.ident);
    }

    let address: std::net::IpAddr = match link_local {
        Some(link_local) => link_local.into(),
        None => Ipv6Addr::UNSPECIFIED.into(),
    };
    let mut peer = Peer::new(
        0,
        bgp.asn,
        bgp.router_id,
        resolved.asn,
        address,
        bgp.hostname(),
        bgp.tx.clone(),
        bgp.ctx.clone(),
    );
    peer.tracing_instance = bgp.tracing.clone();
    // `Peer::new` defaults to IBGP; derive the session type from the
    // resolved remote-as like the addressed-neighbor and group-sweep
    // paths do — it drives admin distance (20 vs 200), the eBGP
    // AS_PATH egress rules, and the TTL convention. An `external`
    // placeholder (asn 0 until OPEN backfill) is eBGP by definition.
    peer.peer_type = if resolved.asn == bgp.asn {
        PeerType::IBGP
    } else {
        PeerType::EBGP
    };
    peer.origin = PeerOrigin::Interface { ifindex };
    // The operator-facing identity for show/clear output and lookups
    // (`show bgp summary`, `show bgp neighbor i1`, …) — the
    // link-local in `address` is not something the operator can name.
    peer.ifname = Some(name.to_string());
    // Required for the kernel connect(2) to a fe80:: target —
    // SocketAddrV6 without a scope_id returns EINVAL. The connect
    // path in `peer_start_connection` reads this back out and
    // builds the SocketAddrV6 accordingly.
    peer.scope_id = Some(ifindex);
    // Record the ND discovery timestamp only when an RA-learned
    // link-local is being set (not for dormant pre-RA peers).
    if link_local.is_some() {
        nd_mark_discovered(&mut peer, Instant::now());
    }
    // Stamp the group back-reference whenever the cfg carries one —
    // it drives every inheritable attribute (afi-safi today), not just
    // remote-as, so the reactive sweeps on group changes can find this
    // peer. `remote_as_inherited` still records which side supplied
    // the ASN: the remote-as sweep must leave a per-cfg spec alone
    // (it additionally consults the interface-neighbor cfg for the
    // `external`-placeholder case — see `sweep_peers_for_group`).
    peer.config.neighbor_group = cfg.neighbor_group.clone();
    if resolved.inherited_from_group {
        peer.config.remote_as_inherited = true;
    }
    bgp.peers.insert_with_key(PeerKey::Interface(ifindex), peer);

    // Resolve everything the group supplies (the MP family set for
    // the first OPEN — e.g. `afi-safi ipv6 enabled true` for an
    // unnumbered IPv6 session — plus the whole-session knobs). Runs
    // AFTER insert because the apply ritual may arm timers that
    // capture `peer.ident`; the bounce flag is irrelevant for a
    // freshly materialized Idle peer.
    let peer = bgp.peers.get_mut_by_key(&PeerKey::Interface(ifindex))?;
    let _ = super::neighbor_group::apply_inherited(&bgp.neighbor_groups, &bgp.policy_tx, peer);

    // Kick the FSM. `peer.start()` arms the idle-hold timer which
    // fires Event::Start → fsm_start → peer_start_connection. The
    // timer captures `peer.ident`, so it must run AFTER insert (which
    // assigns the real ident). The gates inside start() also require
    // `remote_as != 0` and a specified address, so two kinds of peer
    // remain dormant in Idle here: ones materialized from a
    // `RemoteAsSpec::External` (which yields 0 as a placeholder until
    // OPEN backfill — that case lands in a follow-up alongside the
    // OPEN-side validation) and ones materialized without a link-local
    // (no RA yet — the RA path upgrades them in place).
    peer.start();
    Some(peer.ident)
}

/// Stamp the initial ND discovery fields on a freshly created
/// interface-keyed peer. Called exactly once — on the create path
/// when a link-local is available (`link_local.is_some()`).
///
/// Extracted so unit tests can exercise the field-update semantics
/// on a plain `Peer` without constructing a full `Bgp`.
fn nd_mark_discovered(peer: &mut super::peer::Peer, now: Instant) {
    peer.nd_discovered_at = Some(now);
    peer.nd_refreshed_at = Some(now);
    peer.nd_event_count = 1;
}

/// Update the ND refresh timestamp on an already-materialized
/// interface-keyed peer when a subsequent RA arrives with a
/// (possibly new) link-local.
///
/// `nd_discovered_at` is intentionally left unchanged — it records
/// the first event only.
fn nd_mark_refreshed(peer: &mut super::peer::Peer, now: Instant) {
    // If the peer was created dormant (no RA yet), treat this first
    // RA as the discovery event so both timestamps are set.
    if peer.nd_discovered_at.is_none() {
        peer.nd_discovered_at = Some(now);
    }
    peer.nd_refreshed_at = Some(now);
    peer.nd_event_count = peer.nd_event_count.saturating_add(1);
}

/// `set router bgp interface-neighbor <name>` — list-key callback.
pub fn config_interface_neighbor(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    match op {
        ConfigOp::Set => {
            bgp.interface_neighbors.entry(name.clone()).or_default();
            // Become operator-visible right away when the interface
            // already exists and a remote-as resolves (via a group
            // bound before this key arrived) — no RA required for the
            // neighbor to appear in `show bgp summary`.
            materialize_dormant(bgp, &name);
        }
        ConfigOp::Delete => {
            // Take the cfg out first so we can tear the peer (if any)
            // down without holding a borrow.
            bgp.interface_neighbors.remove(&name);
            if let Some(&ifindex) = bgp.link_index_by_name.get(&name) {
                // Withdraw everything the peer contributed (Loc-RIB,
                // main RIB / kernel FIB, MP_UNREACH fan-out to other
                // peers) before dropping it — mirrors the addressed
                // `neighbor <addr>` delete path in `config.rs`.
                // Without this the peer's ENHE-installed v4 routes
                // outlive the neighbor in the kernel.
                let peer_idx = bgp
                    .peers
                    .get_by_key(&PeerKey::Interface(ifindex))
                    .map(|p| p.ident);
                if let Some(peer_idx) = peer_idx {
                    let mut bgp_ref = super::peer::BgpTop {
                        router_id: &bgp.router_id,
                        srv6_ipv6_export: bgp.srv6_ipv6_export.as_ref(),
                        local_rib: &mut bgp.local_rib,
                        shard: &mut bgp.shard,
                        tx: &bgp.tx,
                        rib_client: &bgp.ctx.rib,
                        attr_store: &mut bgp.attr_store,
                        update_groups: &mut bgp.update_groups,
                        interface_addrs: &bgp.interface_addrs,
                        vrf_export: None,
                        color_policy: Some(&bgp.color_policy),
                        flex_algo_routes: Some(&bgp.flex_algo_routes),
                        flex_algo_srv6_routes: Some(&bgp.flex_algo_srv6_routes),
                        vrf_import: None,
                        nexthop_cache: None,
                        vrf_transport_v4: None,
                        vrf_transport_v6: None,
                        central_label_alloc: None,
                    };
                    super::route::route_clean(
                        peer_idx,
                        &mut bgp_ref,
                        &mut bgp.peers,
                        bgp.shards.as_ref(),
                    );
                    // Update-groups live outside `PeerMap`: the
                    // removal below purges the membership index by
                    // construction, but the group member sets need an
                    // explicit detach or the freed ident lingers and a
                    // future slot reuse inherits the group.
                    super::update_group::detach(&mut bgp.update_groups, &mut bgp.peers, peer_idx);
                }
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
    let new_ref = match op {
        ConfigOp::Set => Some(args.string()?),
        ConfigOp::Delete => None,
        _ => return Some(()),
    };
    bgp.interface_neighbors
        .entry(name.clone())
        .or_default()
        .neighbor_group = new_ref.clone();

    // Propagate the (re)binding to an already-materialized peer so the
    // group-driven attributes re-resolve against the new reference.
    // Scope: the inheritable attribute set only — the peer's remote-as
    // keeps its materialization-time value, matching how a per-cfg
    // `remote-as` change is also picked up only on the next
    // materialization.
    let mut stop: Option<usize> = None;
    if let Some(&ifindex) = bgp.link_index_by_name.get(&name)
        && let Some(peer) = bgp.peers.get_mut_by_key(&PeerKey::Interface(ifindex))
    {
        peer.config.neighbor_group = new_ref;
        let outcome =
            super::neighbor_group::apply_inherited(&bgp.neighbor_groups, &bgp.policy_tx, peer);
        if outcome.bounce {
            stop = Some(peer.ident);
        }
    }
    if let Some(ident) = stop {
        let _ = bgp
            .tx
            .try_send(super::inst::Message::Event(ident, super::peer::Event::Stop));
    }
    // The (re)bound group may supply the remote-as this neighbor was
    // missing — an unmaterialized cfg becomes a dormant peer now. A
    // no-op when the peer above already exists or the gates still
    // aren't satisfied.
    materialize_dormant(bgp, &name);
    Some(())
}

/// `set router bgp interface-neighbor <name> remote-as <ASN|external|internal>`.
pub fn config_interface_neighbor_remote_as(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let name = args.string()?;
    let entry = bgp.interface_neighbors.entry(name.clone()).or_default();
    match op {
        ConfigOp::Set => {
            let raw = args.string()?;
            entry.remote_as = match raw.as_str() {
                "external" => RemoteAsSpec::External,
                "internal" => RemoteAsSpec::Internal,
                numeric => RemoteAsSpec::Asn(numeric.parse().ok()?),
            };
            // remote-as usually completes the config (it arrives after
            // the list-key callback in a commit) — surface the dormant
            // peer so the neighbor shows up before any RA.
            materialize_dormant(bgp, &name);
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

    /// Build a minimal Peer suitable for testing nd_mark_* helpers.
    /// Uses a parked channel and a no-RIB context — no sockets are
    /// opened and no timers fire during these synchronous tests.
    fn make_peer() -> super::super::peer::Peer {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        Box::leak(Box::new(rx));
        super::super::peer::Peer::new(
            0,
            65001,
            "1.1.1.1".parse().unwrap(),
            65002,
            "fe80::1".parse::<std::net::IpAddr>().unwrap(),
            None,
            tx,
            crate::context::ProtoContext::default_table_no_rib(),
        )
    }

    /// After `nd_mark_discovered`: count == 1, both timestamps set
    /// and equal.
    #[test]
    fn nd_mark_discovered_sets_all_three_fields() {
        let mut peer = make_peer();
        assert!(peer.nd_discovered_at.is_none());
        assert_eq!(peer.nd_event_count, 0);

        let t0 = Instant::now();
        nd_mark_discovered(&mut peer, t0);

        assert_eq!(peer.nd_event_count, 1);
        assert_eq!(peer.nd_discovered_at, Some(t0));
        assert_eq!(peer.nd_refreshed_at, Some(t0));
    }

    /// After a subsequent `nd_mark_refreshed`: count increments,
    /// `nd_refreshed_at` advances, `nd_discovered_at` stays.
    #[test]
    fn nd_mark_refreshed_increments_count_and_updates_refresh_only() {
        let mut peer = make_peer();
        let t0 = Instant::now();
        nd_mark_discovered(&mut peer, t0);

        // Simulate a later RA arriving.
        let t1 = t0 + std::time::Duration::from_secs(60);
        nd_mark_refreshed(&mut peer, t1);

        assert_eq!(peer.nd_event_count, 2);
        // Discovery timestamp must not change.
        assert_eq!(peer.nd_discovered_at, Some(t0));
        // Refresh timestamp must advance.
        assert_eq!(peer.nd_refreshed_at, Some(t1));
    }

    /// A dormant peer (created at config time, no RA yet) has all
    /// three fields at their zero values. When its first RA arrives
    /// via `nd_mark_refreshed`, both timestamps are set (treating
    /// the first refresh as discovery).
    #[test]
    fn nd_mark_refreshed_on_dormant_peer_sets_discovered_at() {
        let mut peer = make_peer();
        // Dormant: no RA yet.
        assert!(peer.nd_discovered_at.is_none());
        assert_eq!(peer.nd_event_count, 0);

        let t0 = Instant::now();
        nd_mark_refreshed(&mut peer, t0);

        assert_eq!(peer.nd_event_count, 1);
        assert_eq!(peer.nd_discovered_at, Some(t0));
        assert_eq!(peer.nd_refreshed_at, Some(t0));
    }
}
