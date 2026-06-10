//! IOS-XR-style BGP `neighbor-group` (zebra-bgp-neighbor-group.yang).
//!
//! Storage + the resolver shared by every peer-materialization path
//! that may inherit from a group: static peers (`config_peer_neighbor_group`),
//! IPv6 unnumbered (`interface_neighbor::materialize_peer`), and dynamic
//! peers (`peer::try_dynamic_accept`). The surface inherits `remote-as`
//! and per-family `afi-safi <name> enabled` toggles; per-peer overrides
//! win — via the [`super::peer::PeerConfig::remote_as_inherited`] flag
//! for `remote-as`, and via the explicit-statement record
//! [`super::peer::PeerConfig::mp_explicit`] for `afi-safi`.
//!
//! Group mutations are reactive, but the two attributes propagate
//! differently:
//! - `remote-as` changes sweep every peer with a matching
//!   `config.neighbor_group` reference and bounce affected sessions
//!   (the FSM must renegotiate with the new ASN) — see
//!   [`config_neighbor_group_remote_as`].
//! - `afi-safi` changes recompute the peers' effective MP set
//!   ([`effective_mp`]) without touching the FSM: like the per-neighbor
//!   `afi-safi <name> enabled` knob, the new set is advertised when
//!   capabilities are next negotiated (`clear bgp …`).
//!
//! Naming-wise this sits alongside the existing
//! `peer-groups/peer-group` schema, not on top of it: a peer can
//! reference exactly one of (neighbor-group, peer-group) — for now
//! the runtime ignores `peer-group` here, and a future mutual-exclusion
//! pass will pick one.

use std::collections::BTreeMap;

use bgp_packet::{Afi, AfiSafi, AfiSafis, Safi};

use super::Bgp;
use super::inst::Message;
use super::peer::{Event, PeerConfig, PeerType};
use super::peer_key::PeerOrigin;
use crate::config::{Args, ConfigOp};

#[derive(Debug, Default, Clone)]
pub struct NeighborGroup {
    pub remote_as: Option<u32>,
    /// Per-family `afi-safi <name> enabled <bool>` opinions. Tri-state
    /// per family: `true` forces the family on for inheriting peers,
    /// `false` forces it off (overriding the implicit IPv4-unicast
    /// default), absent means "no opinion" (the peer's own default /
    /// explicit setting stands).
    pub afi_safi: BTreeMap<AfiSafi, bool>,
}

/// `set router bgp neighbor-group <name>` — list-key callback.
/// Creates the entry on `Set`; on `Delete` cascades through the sweep
/// helpers (so any peers that inherited from the group are torn down /
/// reset even when libyang's commit path skips the per-leaf delete
/// callbacks) and then removes the entry.
pub fn config_neighbor_group(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    match op {
        ConfigOp::Set => {
            bgp.neighbor_groups.entry(name).or_default();
        }
        ConfigOp::Delete => {
            // Same shape as a remote-as Delete: any inherited peer
            // resets to `remote_as = 0` and is sent `Event::Stop`.
            // Idempotent if the per-leaf delete already ran — the
            // second pass finds peers with `remote_as_inherited =
            // false` and returns `SweepAction::Ignore`.
            sweep_peers_for_group(bgp, &name, None);
            bgp.neighbor_groups.remove(&name);
            // With the group gone its afi-safi opinions are gone too:
            // members fall back to default + their own explicit
            // statements (the reference leaf on the peer still stands
            // and re-resolves if the group is re-created).
            sweep_group_afi_safi(bgp, &name);
        }
        _ => {}
    }
    Some(())
}

/// `set router bgp neighbor-group <name> remote-as <asn>`.
///
/// Mutates the stored value and then reactively sweeps every peer that
/// references the group with an inherited (or absent) `remote-as`:
/// - On `Set` the new value is propagated; dormant peers start, and
///   peers whose remote-as actually changed bounce so the FSM
///   renegotiates with the new value.
/// - On `Delete` inherited peers are reset to `remote_as = 0` and
///   sent `Event::Stop`. Peers with an explicit per-peer remote-as
///   are left alone.
pub fn config_neighbor_group_remote_as(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let new_asn = match op {
        ConfigOp::Set => Some(args.u32()?),
        ConfigOp::Delete => None,
        _ => return Some(()),
    };

    bgp.neighbor_groups
        .entry(name.clone())
        .or_default()
        .remote_as = new_asn;

    sweep_peers_for_group(bgp, &name, new_asn);
    Some(())
}

/// `set router bgp neighbor-group <name> afi-safi <family>` — list-key
/// callback. `Set` just materializes the group entry (the meaningful
/// state arrives with the mandatory `enabled` leaf); `Delete` drops the
/// family opinion and re-resolves members — needed because a
/// whole-entry delete skips the per-leaf delete callbacks (same
/// libyang-commit behavior the group-level Delete works around).
pub fn config_neighbor_group_afi_safi(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let family: AfiSafi = args.afi_safi()?;
    match op {
        ConfigOp::Set => {
            bgp.neighbor_groups.entry(name).or_default();
        }
        ConfigOp::Delete => {
            if let Some(group) = bgp.neighbor_groups.get_mut(&name) {
                group.afi_safi.remove(&family);
            }
            sweep_group_afi_safi(bgp, &name);
        }
        _ => {}
    }
    Some(())
}

/// `set router bgp neighbor-group <name> afi-safi <family> enabled <bool>`.
///
/// Stores the opinion and recomputes the effective MP set of every
/// member peer. Deliberately no FSM bounce: exactly like the
/// per-neighbor `afi-safi <name> enabled` knob, the new family set is
/// advertised when capabilities are next negotiated — the operator
/// issues `clear bgp …` to apply it to an established session.
pub fn config_neighbor_group_afi_safi_enabled(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let name = args.string()?;
    let family: AfiSafi = args.afi_safi()?;
    let group = bgp.neighbor_groups.entry(name.clone()).or_default();
    match op {
        ConfigOp::Set => {
            let enabled = args.boolean()?;
            group.afi_safi.insert(family, enabled);
        }
        ConfigOp::Delete => {
            group.afi_safi.remove(&family);
        }
        _ => return Some(()),
    }
    sweep_group_afi_safi(bgp, &name);
    Some(())
}

/// Compute a peer's effective MP (multiprotocol) family set from the
/// three layers, lowest precedence first:
///
/// 1. the built-in default (IPv4 unicast on — every peer is born with
///    it, see `Peer::new`),
/// 2. the referenced neighbor-group's `afi-safi` opinions,
/// 3. the per-peer explicit `afi-safi <name> enabled` statements
///    ([`super::peer::PeerConfig::mp_explicit`]) — "any field set
///    explicitly on the neighbor wins".
///
/// Presence in the returned set means enabled — the same invariant
/// `PeerConfig::mp` always had.
pub fn effective_mp(
    group: Option<&BTreeMap<AfiSafi, bool>>,
    explicit: &BTreeMap<AfiSafi, bool>,
) -> AfiSafis<bool> {
    let mut mp = AfiSafis::new();
    mp.insert(AfiSafi::new(Afi::Ip, Safi::Unicast), true);
    for (family, enabled) in group.into_iter().flatten() {
        if *enabled {
            mp.insert(*family, true);
        } else {
            mp.remove(family);
        }
    }
    for (family, enabled) in explicit.iter() {
        if *enabled {
            mp.insert(*family, true);
        } else {
            mp.remove(family);
        }
    }
    mp
}

/// Re-resolve one peer's `config.mp` from its group reference and
/// explicit statements. Takes the group map (not `&Bgp`) so callers
/// holding a `&mut` borrow into `bgp.peers` can still pass
/// `&bgp.neighbor_groups` alongside.
pub fn recompute_peer_mp(groups: &BTreeMap<String, NeighborGroup>, config: &mut PeerConfig) {
    let opinions = config
        .neighbor_group
        .as_ref()
        .and_then(|name| groups.get(name))
        .map(|group| &group.afi_safi);
    config.mp = effective_mp(opinions, &config.mp_explicit);
}

/// Recompute the effective MP set of every peer referencing `name`.
/// Called after any change to the group's `afi-safi` opinions (and
/// after group deletion, where the lookup misses and members fall back
/// to default + explicit). `iter_mut_all` so interface-keyed (IPv6
/// unnumbered) members are swept too — `iter_mut` silently skips them.
fn sweep_group_afi_safi(bgp: &mut Bgp, name: &str) {
    for (_, peer) in bgp.peers.iter_mut_all() {
        if peer.config.neighbor_group.as_deref() != Some(name) {
            continue;
        }
        recompute_peer_mp(&bgp.neighbor_groups, &mut peer.config);
    }
}

/// Decide what to do with one peer that references the group whose
/// `remote-as` just changed. Pure function so the (small) sweep logic
/// is unit-testable without standing up a full [`Bgp`] instance.
///
/// `peer_remote_as` / `peer_inherited` describe the peer's current
/// state; `new_asn` is the group's new value (`None` = removed).
/// Returns the action the sweep should take.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum SweepAction {
    /// Peer is unaffected — either it doesn't reference this group's
    /// remote-as for its own (explicit per-peer override wins), or
    /// the value didn't actually change.
    Ignore,
    /// Adopt the new asn. Caller must rewrite `peer.remote_as`,
    /// mark `remote_as_inherited = true`, refresh `peer_type` and
    /// kick `peer.start()`.
    Adopt(u32),
    /// Peer was inherited and its asn changed — caller must rewrite
    /// the new asn, then bounce the session via `Event::Stop` so the
    /// FSM renegotiates.
    Rebounce(u32),
    /// Group's remote-as was deleted while this peer was inherited —
    /// caller must reset `remote_as = 0`, clear inheritance, deactivate
    /// the peer and send `Event::Stop`.
    TearDown,
}

pub(super) fn sweep_action(
    peer_remote_as: u32,
    peer_inherited: bool,
    peer_active: bool,
    new_asn: Option<u32>,
) -> SweepAction {
    // Explicit per-peer remote-as always wins.
    if !peer_inherited && peer_remote_as != 0 {
        return SweepAction::Ignore;
    }
    match new_asn {
        Some(asn) => {
            if peer_remote_as == asn {
                SweepAction::Ignore
            } else if peer_active {
                SweepAction::Rebounce(asn)
            } else {
                SweepAction::Adopt(asn)
            }
        }
        None if peer_inherited => SweepAction::TearDown,
        None => SweepAction::Ignore,
    }
}

/// Apply [`sweep_action`] to every peer whose `config.neighbor_group`
/// matches `name`. Collects FSM stop signals to send after the
/// peer-iteration borrow ends.
fn sweep_peers_for_group(bgp: &mut Bgp, name: &str, new_asn: Option<u32>) {
    let local_asn = bgp.asn;
    let mut stops: Vec<usize> = Vec::new();

    // Interface-keyed peers carry the group back-reference even when
    // their remote-as came from the interface-neighbor cfg itself (the
    // reference also drives afi-safi inheritance). The remote-as sweep
    // must not adopt over such an explicit spec — `remote-as external`
    // materializes as the 0 placeholder, which the zero-means-unset
    // heuristic in [`sweep_action`] would otherwise treat as
    // group-eligible.
    let explicit_ifnames: std::collections::BTreeSet<&str> = bgp
        .interface_neighbors
        .iter()
        .filter(|(_, cfg)| cfg.remote_as != super::interface_neighbor::RemoteAsSpec::Unset)
        .map(|(ifname, _)| ifname.as_str())
        .collect();

    // `iter_mut_all` so interface-keyed (IPv6 unnumbered) members are
    // swept too — `iter_mut` silently skips them, which left an
    // unnumbered peer's inherited remote-as frozen across group edits.
    for (_, peer) in bgp.peers.iter_mut_all() {
        if peer.config.neighbor_group.as_deref() != Some(name) {
            continue;
        }
        if matches!(peer.origin, PeerOrigin::Interface { .. })
            && peer
                .ifname
                .as_deref()
                .is_some_and(|ifname| explicit_ifnames.contains(ifname))
        {
            continue;
        }
        match sweep_action(
            peer.remote_as,
            peer.config.remote_as_inherited,
            peer.active,
            new_asn,
        ) {
            SweepAction::Ignore => {}
            SweepAction::Adopt(asn) => {
                peer.remote_as = asn;
                peer.config.remote_as_inherited = true;
                peer.peer_type = if asn == local_asn {
                    PeerType::IBGP
                } else {
                    PeerType::EBGP
                };
                peer.start();
            }
            SweepAction::Rebounce(asn) => {
                peer.remote_as = asn;
                peer.config.remote_as_inherited = true;
                peer.peer_type = if asn == local_asn {
                    PeerType::IBGP
                } else {
                    PeerType::EBGP
                };
                peer.active = false;
                stops.push(peer.ident);
            }
            SweepAction::TearDown => {
                peer.remote_as = 0;
                peer.config.remote_as_inherited = false;
                peer.active = false;
                stops.push(peer.ident);
            }
        }
    }

    for ident in stops {
        let _ = bgp.tx.try_send(Message::Event(ident, Event::Stop));
    }
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
                ..Default::default()
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
        map.insert("RR".into(), NeighborGroup::default());
        assert_eq!(map.get("RR").and_then(|g| g.remote_as), None);
    }

    // Sweep-decision matrix. Inputs: (peer_remote_as, peer_inherited,
    // peer_active, new_asn). The pure helper keeps the decision logic
    // in [`sweep_peers_for_group`] testable without standing up a
    // full Bgp instance.

    #[test]
    fn sweep_ignores_explicit_per_peer_override() {
        // Peer has its own explicit asn — group change must not touch
        // it regardless of Set/Delete.
        assert_eq!(
            sweep_action(65001, false, false, Some(65000)),
            SweepAction::Ignore
        );
        assert_eq!(sweep_action(65001, false, false, None), SweepAction::Ignore);
    }

    #[test]
    fn sweep_adopts_when_dormant_inherited_peer_gets_asn() {
        assert_eq!(
            sweep_action(0, true, false, Some(65000)),
            SweepAction::Adopt(65000),
        );
    }

    #[test]
    fn sweep_adopts_when_peer_has_no_remote_as_at_all() {
        // Static peer with only `neighbor-group X` reference — the
        // inheritance flag may not yet be flipped (e.g. peer created
        // before the group was). `remote_as == 0` is the trigger.
        assert_eq!(
            sweep_action(0, false, false, Some(65000)),
            SweepAction::Adopt(65000),
        );
    }

    #[test]
    fn sweep_rebounces_when_active_inherited_peers_asn_changes() {
        assert_eq!(
            sweep_action(65000, true, true, Some(65001)),
            SweepAction::Rebounce(65001),
        );
    }

    #[test]
    fn sweep_ignores_no_op_change() {
        assert_eq!(
            sweep_action(65000, true, true, Some(65000)),
            SweepAction::Ignore,
        );
    }

    #[test]
    fn sweep_tears_down_inherited_peer_on_delete() {
        assert_eq!(sweep_action(65000, true, true, None), SweepAction::TearDown);
        assert_eq!(
            sweep_action(65000, true, false, None),
            SweepAction::TearDown
        );
    }

    #[test]
    fn sweep_ignores_delete_when_peer_has_no_asn_anyway() {
        // Peer was never inherited and never got an explicit asn —
        // Delete on the group is a no-op from the sweep's perspective.
        assert_eq!(sweep_action(0, false, false, None), SweepAction::Ignore);
    }

    // [`effective_mp`] precedence matrix: built-in default (IPv4
    // unicast on) < group opinions < per-peer explicit statements.

    fn v4() -> AfiSafi {
        AfiSafi::new(Afi::Ip, Safi::Unicast)
    }

    fn v6() -> AfiSafi {
        AfiSafi::new(Afi::Ip6, Safi::Unicast)
    }

    fn families(mp: &AfiSafis<bool>) -> Vec<AfiSafi> {
        mp.keys().copied().collect()
    }

    #[test]
    fn effective_mp_default_is_ipv4_unicast_only() {
        let mp = effective_mp(None, &BTreeMap::new());
        assert_eq!(families(&mp), vec![v4()]);
    }

    #[test]
    fn effective_mp_group_enables_extra_family() {
        let group = BTreeMap::from([(v6(), true)]);
        let mp = effective_mp(Some(&group), &BTreeMap::new());
        assert_eq!(families(&mp), vec![v4(), v6()]);
    }

    #[test]
    fn effective_mp_group_disables_the_ipv4_default() {
        let group = BTreeMap::from([(v4(), false), (v6(), true)]);
        let mp = effective_mp(Some(&group), &BTreeMap::new());
        assert_eq!(families(&mp), vec![v6()]);
    }

    #[test]
    fn effective_mp_explicit_wins_over_group() {
        // Group switches v4 off, but the peer's own `afi-safi ipv4
        // enabled true` stands; group's v6 opinion is unopposed.
        let group = BTreeMap::from([(v4(), false), (v6(), true)]);
        let explicit = BTreeMap::from([(v4(), true)]);
        let mp = effective_mp(Some(&group), &explicit);
        assert_eq!(families(&mp), vec![v4(), v6()]);

        // ... and the mirror: group on, explicit off.
        let group = BTreeMap::from([(v6(), true)]);
        let explicit = BTreeMap::from([(v6(), false)]);
        let mp = effective_mp(Some(&group), &explicit);
        assert_eq!(families(&mp), vec![v4()]);
    }

    #[test]
    fn effective_mp_explicit_without_group() {
        let explicit = BTreeMap::from([(v4(), false), (v6(), true)]);
        let mp = effective_mp(None, &explicit);
        assert_eq!(families(&mp), vec![v6()]);
    }

    #[test]
    fn effective_mp_group_gone_restores_default() {
        // Same shape the group-delete cascade produces: reference
        // still set on the peer, lookup misses → opinions = None.
        let mp = effective_mp(None, &BTreeMap::new());
        assert!(mp.has(&v4()));
        assert!(!mp.has(&v6()));
    }
}
