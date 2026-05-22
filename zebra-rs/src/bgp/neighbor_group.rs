//! IOS-XR-style BGP `neighbor-group` (zebra-bgp-neighbor-group.yang).
//!
//! Storage + the resolver shared by every peer-materialization path
//! that may inherit from a group: static peers (`config_peer_neighbor_group`),
//! IPv6 unnumbered (`interface_neighbor::materialize_peer`), and dynamic
//! peers (`peer::try_dynamic_accept`). The v1 surface inherits only
//! `remote-as`; per-peer overrides win via the
//! [`super::peer::PeerConfig::remote_as_inherited`] flag.
//!
//! Group mutations are reactive: `config_neighbor_group_remote_as`
//! mutates the stored value and then sweeps every peer with a matching
//! `config.neighbor_group` reference to propagate the change (or tear
//! the inherited peer down on Delete) — see
//! [`config_neighbor_group_remote_as`].
//!
//! Naming-wise this sits alongside the existing
//! `peer-groups/peer-group` schema, not on top of it: a peer can
//! reference exactly one of (neighbor-group, peer-group) — for now
//! the runtime ignores `peer-group` here, and a future mutual-exclusion
//! pass will pick one.

use std::collections::BTreeMap;

use super::Bgp;
use super::inst::Message;
use super::peer::{Event, PeerType};
use crate::config::{Args, ConfigOp};

#[derive(Debug, Default, Clone)]
pub struct NeighborGroup {
    pub remote_as: Option<u32>,
}

/// `set router bgp neighbor-groups neighbor-group <name>` — list-key
/// callback. Creates the entry on `Set`; on `Delete` cascades through
/// the sweep helper (so any peers that inherited from the group are
/// torn down even when libyang's commit path skips the per-leaf
/// delete callbacks) and then removes the entry.
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
        }
        _ => {}
    }
    Some(())
}

/// `set router bgp neighbor-groups neighbor-group <name> remote-as <asn>`.
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

    for (_, peer) in bgp.peers.iter_mut() {
        if peer.config.neighbor_group.as_deref() != Some(name) {
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
}
