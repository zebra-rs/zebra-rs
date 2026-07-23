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
//!   ([`effective_mp`]) and bounce any Established member — an AFI/SAFI is
//!   a Multiprotocol capability fixed at OPEN time, so the FSM must
//!   renegotiate (the same `Event::Stop` `clear bgp … hard` uses). Like
//!   the per-neighbor `afi-safi <name> enabled` knob; a member still
//!   coming up carries the change in its first OPEN.
//!
//! Naming-wise this sits alongside the existing
//! `peer-groups/peer-group` schema, not on top of it: a peer can
//! reference exactly one of (neighbor-group, peer-group) — for now
//! the runtime ignores `peer-group` here, and a future mutual-exclusion
//! pass will pick one.

use std::collections::BTreeMap;
use std::net::IpAddr;

use bgp_packet::{Afi, AfiSafi, AfiSafis, Safi};

use super::Bgp;
use super::inst::Message;
use super::peer::{
    ALLOWAS_IN_DEFAULT_COUNT, AllowAsIn, Event, Peer, PeerConfig, PeerType, RemovePrivateAs, State,
};
use super::peer_key::PeerOrigin;
use crate::config::{Args, ConfigOp};

/// The per-neighbor knobs a `neighbor-group` can supply. One struct
/// serves both sides of the inheritance:
///
/// - [`NeighborGroup::knobs`] — the group's opinions,
/// - [`super::peer::PeerConfig::knobs_explicit`] — the verbatim
///   statements made on the neighbor itself.
///
/// Every field is `Option`: `None` means "no statement" (group: no
/// opinion / peer: not explicitly configured). Resolution is
/// field-wise `explicit.or(group)` via [`resolve_knob`]; when both are
/// `None` the per-knob default applies. Presence-style knobs
/// (`ttl-security`, `as-override`, `remove-private-as`,
/// `enforce-first-as`, `disable-connected-check`, `ip-transparent`,
/// `allowas-in`) can only be stated "on" — exactly the expressiveness
/// the per-neighbor YANG has.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct InheritableKnobs {
    pub passive: Option<bool>,
    pub update_source: Option<IpAddr>,
    pub port: Option<u16>,
    pub ttl_security: Option<bool>,
    pub ebgp_multihop: Option<u8>,
    pub tcp_mss: Option<u16>,
    pub password: Option<String>,
    /// TCP-AO (RFC 5925) key-chain reference inherited by members —
    /// and, when the group is bound to a `dynamic-neighbors`
    /// listen-range, installed on the listener as a prefix-scoped MKT
    /// for the whole range.
    pub ao_config: Option<super::auth::AoConfig>,
    pub disable_connected_check: Option<bool>,
    pub ip_transparent: Option<bool>,
    pub policy_in: Option<String>,
    pub policy_out: Option<String>,
    pub prefix_set_in: Option<String>,
    pub prefix_set_out: Option<String>,
    pub allowas_in: Option<AllowAsIn>,
    pub as_override: Option<bool>,
    pub remove_private_as: Option<RemovePrivateAs>,
    pub enforce_first_as: Option<bool>,
    pub route_reflector_client: Option<bool>,
    /// RFC 9572 §6.1 region identifier — the 8-octet, EC-formatted Region ID
    /// (`region_id_from_asn`). A peer-group carrying this *is* a region; a
    /// Regional Border Router uses it to aggregate the region's IMET into a
    /// Per-Region I-PMSI (Type-9) route and to suppress per-PE IMET across
    /// the boundary. Read at route-processing time via `resolve_knob`, not
    /// applied to per-peer session state.
    pub region_id: Option<[u8; 8]>,
}

impl InheritableKnobs {
    /// Staging state machines for the two structured knobs, factored so
    /// the per-neighbor callbacks (`config.rs`) and the per-VRF-neighbor
    /// callbacks (`vrf_config.rs`) share one definition rather than each
    /// re-deriving the get-or-insert / revert-to-default dance. They
    /// mutate only the *verbatim* record; resolving the effective value
    /// (explicit-wins over the group) and applying it stays with each
    /// caller, which differ in whether a live peer exists.
    ///
    /// `allowas-in` presence: the bare container enables the default
    /// count budget; a modifier that landed first is preserved.
    pub fn stage_allowas_in_presence(&mut self, set: bool) {
        if set {
            self.allowas_in
                .get_or_insert(AllowAsIn::Count(ALLOWAS_IN_DEFAULT_COUNT));
        } else {
            self.allowas_in = None;
        }
    }

    /// `allowas-in count`: `Some(n)` sets the budget; `None` (leaf
    /// delete) reverts to the default budget only if a count is what is
    /// currently held, leaving an `origin` selection untouched.
    pub fn stage_allowas_in_count(&mut self, count: Option<u8>) {
        match count {
            Some(n) => self.allowas_in = Some(AllowAsIn::Count(n)),
            None if matches!(self.allowas_in, Some(AllowAsIn::Count(_))) => {
                self.allowas_in = Some(AllowAsIn::Count(ALLOWAS_IN_DEFAULT_COUNT));
            }
            None => {}
        }
    }

    /// `allowas-in origin`: select origin-only; a leaf delete reverts to
    /// the default count budget only if origin is what is held.
    pub fn stage_allowas_in_origin(&mut self, set: bool) {
        if set {
            self.allowas_in = Some(AllowAsIn::Origin);
        } else if matches!(self.allowas_in, Some(AllowAsIn::Origin)) {
            self.allowas_in = Some(AllowAsIn::Count(ALLOWAS_IN_DEFAULT_COUNT));
        }
    }

    /// `remove-private-as` presence: enable with the conditional
    /// (all-private-only) default, preserving a modifier that arrived
    /// first.
    pub fn stage_remove_private_as_presence(&mut self, set: bool) {
        if set {
            self.remove_private_as
                .get_or_insert_with(RemovePrivateAs::default);
        } else {
            self.remove_private_as = None;
        }
    }

    /// `remove-private-as all`: act on a mixed path. A leaf delete clears
    /// the flag while the container stays enabled.
    pub fn stage_remove_private_as_all(&mut self, set: bool) {
        if set {
            self.remove_private_as
                .get_or_insert_with(RemovePrivateAs::default)
                .all = true;
        } else if let Some(rpa) = self.remove_private_as.as_mut() {
            rpa.all = false;
        }
    }

    /// `remove-private-as replace-as`: rewrite stripped ASNs to the local
    /// AS. A leaf delete clears the flag while the container stays
    /// enabled.
    pub fn stage_remove_private_as_replace_as(&mut self, set: bool) {
        if set {
            self.remove_private_as
                .get_or_insert_with(RemovePrivateAs::default)
                .replace_as = true;
        } else if let Some(rpa) = self.remove_private_as.as_mut() {
            rpa.replace_as = false;
        }
    }
}

/// One group `afi-safi <family>` entry: the mandatory `enabled`
/// toggle plus optional per-family opinions.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct GroupAfiSafi {
    pub enabled: bool,
    pub next_hop_self: Option<bool>,
}

#[derive(Debug, Default, Clone)]
pub struct NeighborGroup {
    pub remote_as: Option<u32>,
    /// Per-family `afi-safi <name>` opinions. Tri-state per family:
    /// an entry with `enabled true` forces the family on for
    /// inheriting peers, `enabled false` forces it off (overriding
    /// the implicit IPv4-unicast default), absent means "no opinion"
    /// (the peer's own default / explicit setting stands). The entry
    /// also carries the optional per-family `next-hop-self` opinion.
    pub afi_safi: BTreeMap<AfiSafi, GroupAfiSafi>,
    /// Whole-session knobs inheritable by members.
    pub knobs: InheritableKnobs,
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
            // Drop the group's key-chain watch with the group itself —
            // the per-leaf delete may never fire on a whole-group
            // delete, and a leaked watch keeps the policy actor pushing
            // updates for a binding that no longer exists.
            if let Some(chain) = bgp
                .neighbor_groups
                .get(&name)
                .and_then(|g| g.knobs.ao_config.as_ref())
                .map(|ao| ao.key_chain.clone())
                .filter(|s| !s.is_empty())
            {
                let ident = group_keychain_ident(bgp, &name);
                super::config::policy_attach_msgs(
                    &bgp.policy_tx,
                    ident,
                    crate::policy::PolicyType::KeyChain(
                        crate::policy::KeyChainScope::BgpNeighborGroup,
                    ),
                    Some(chain),
                    None,
                );
            }
            bgp.neighbor_groups.remove(&name);
            // With the group gone every opinion it carried is gone
            // too: members fall back to defaults + their own explicit
            // statements (the reference leaf on the peer still stands
            // and re-resolves if the group is re-created).
            sweep_members_inherit(bgp, &name);
        }
        _ => {}
    }
    // The group's password / tcp-ao are the source of any listen-range
    // prefix key bound to it — creating or deleting the group changes
    // what the listener should be authenticating.
    super::dynamic_neighbors::reconcile_listener_md5(bgp);
    super::dynamic_neighbors::reconcile_listener_ao(bgp);
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

    // The group's remote-as can be the missing gate for an
    // interface-neighbor that references this group but has no peer
    // yet (interface known, no RA, no per-cfg remote-as) — the sweep
    // above only reaches already-materialized peers. Surface those
    // members as dormant peers so `show bgp summary` lists them.
    if new_asn.is_some() {
        let members: Vec<String> = bgp
            .interface_neighbors
            .iter()
            .filter(|(_, cfg)| cfg.neighbor_group.as_deref() == Some(name.as_str()))
            .map(|(ifname, _)| ifname.clone())
            .collect();
        for ifname in members {
            super::interface_neighbor::materialize_dormant(bgp, &ifname);
        }
    }
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
            // `mup` toggles both MUP families at once (draft-ietf-bess-mup-safi).
            for fam in mp_family_expand(family) {
                group.afi_safi.entry(fam).or_default().enabled = enabled;
            }
        }
        ConfigOp::Delete => {
            // `enabled` is the entry's mandatory core: dropping it
            // drops the family opinion. A surviving `next-hop-self`
            // opinion would be unreachable config (the schema requires
            // `enabled` on the entry), so remove the whole entry.
            for fam in mp_family_expand(family) {
                group.afi_safi.remove(&fam);
            }
        }
        _ => return Some(()),
    }
    sweep_group_afi_safi(bgp, &name);
    Some(())
}

/// `set router bgp neighbor-group <name> afi-safi <family> next-hop-self <bool>`.
///
/// Stores the per-family opinion and re-resolves every member's
/// effective `next-hop-self` for that family. Like the per-neighbor
/// leaf, no session bounce and no replay: the new value applies to
/// routes advertised after the change.
pub fn config_neighbor_group_afi_safi_next_hop_self(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let name = args.string()?;
    let family: AfiSafi = args.afi_safi()?;
    let group = bgp.neighbor_groups.entry(name.clone()).or_default();
    match op {
        ConfigOp::Set => {
            let value = args.boolean()?;
            group.afi_safi.entry(family).or_default().next_hop_self = Some(value);
        }
        ConfigOp::Delete => {
            if let Some(entry) = group.afi_safi.get_mut(&family) {
                entry.next_hop_self = None;
            }
        }
        _ => return Some(()),
    }
    sweep_members(bgp, &name, |groups, peer| {
        let value = resolve_next_hop_self(groups, &peer.config, family);
        peer.config.sub.entry(family).or_default().next_hop_self = value;
        false
    });
    Some(())
}

/// Resolve a member's effective per-family `next-hop-self`: the
/// explicit per-neighbor statement wins, else the group's opinion,
/// else the default (`false`).
pub fn resolve_next_hop_self(
    groups: &BTreeMap<String, NeighborGroup>,
    config: &PeerConfig,
    family: AfiSafi,
) -> bool {
    config
        .nhs_explicit
        .get(&family)
        .copied()
        .or_else(|| {
            config
                .neighbor_group
                .as_deref()
                .and_then(|name| groups.get(name))
                .and_then(|group| group.afi_safi.get(&family))
                .and_then(|entry| entry.next_hop_self)
        })
        .unwrap_or(false)
}

/// `set router bgp neighbor-group <name> ttl-security` (presence container).
///
/// Stores the opinion and re-resolves every member through the same
/// apply ritual as the per-neighbor callback (mutual-exclusion guard,
/// diff-gate, start, bounce-if-live).
pub fn config_neighbor_group_ttl_security(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let name = args.string()?;
    bgp.neighbor_groups
        .entry(name.clone())
        .or_default()
        .knobs
        .ttl_security = op.is_set().then_some(true);
    sweep_members(bgp, &name, |groups, peer| {
        let want = resolve_knob(groups, &peer.config, |k| k.ttl_security).unwrap_or(false);
        super::config::apply_ttl_security(peer, want)
    });
    Some(())
}

/// `set router bgp neighbor-group <name> port <1-65535>`.
///
/// Stores the opinion and re-resolves every member through the same
/// apply ritual as the per-neighbor callback (diff-gate, start,
/// bounce-if-live).
pub fn config_neighbor_group_port(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let value = match op {
        ConfigOp::Set => Some(args.u16()?),
        ConfigOp::Delete => None,
        _ => return Some(()),
    };
    bgp.neighbor_groups
        .entry(name.clone())
        .or_default()
        .knobs
        .port = value;
    sweep_members(bgp, &name, |groups, peer| {
        let want = resolve_knob(groups, &peer.config, |k| k.port);
        super::config::apply_port(peer, want)
    });
    Some(())
}

/// `set router bgp neighbor-group <name> ebgp-multihop <1-255>`.
///
/// Stores the opinion and re-resolves every member through the same
/// apply ritual as the per-neighbor callback (mutual-exclusion guard
/// vs ttl-security, diff-gate, start, bounce-if-live).
pub fn config_neighbor_group_ebgp_multihop(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let name = args.string()?;
    let value = match op {
        ConfigOp::Set => Some(args.u8()?),
        ConfigOp::Delete => None,
        _ => return Some(()),
    };
    bgp.neighbor_groups
        .entry(name.clone())
        .or_default()
        .knobs
        .ebgp_multihop = value;
    sweep_members(bgp, &name, |groups, peer| {
        let want = resolve_knob(groups, &peer.config, |k| k.ebgp_multihop);
        super::config::apply_ebgp_multihop(peer, want)
    });
    Some(())
}

/// `set router bgp neighbor-group <name> disable-connected-check`
/// (presence container).
///
/// Stores the opinion and re-resolves every member through the same
/// apply ritual as the per-neighbor callback (diff-gate, start,
/// bounce-if-live).
pub fn config_neighbor_group_disable_connected_check(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let name = args.string()?;
    bgp.neighbor_groups
        .entry(name.clone())
        .or_default()
        .knobs
        .disable_connected_check = op.is_set().then_some(true);
    sweep_members(bgp, &name, |groups, peer| {
        let want =
            resolve_knob(groups, &peer.config, |k| k.disable_connected_check).unwrap_or(false);
        super::config::apply_disable_connected_check(peer, want)
    });
    Some(())
}

/// `set router bgp neighbor-group <name> ip-transparent`
/// (presence container).
///
/// Stores the opinion and re-resolves every member through the same
/// apply ritual as the per-neighbor callback (diff-gate, start,
/// bounce-if-live), then reconciles the listener flag — the group
/// opinion alone counts toward the per-AF union so a dynamic
/// (listen-range) member finds IP_TRANSPARENT on the listener before
/// it materializes.
pub fn config_neighbor_group_ip_transparent(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let name = args.string()?;
    bgp.neighbor_groups
        .entry(name.clone())
        .or_default()
        .knobs
        .ip_transparent = op.is_set().then_some(true);
    sweep_members(bgp, &name, |groups, peer| {
        let want = resolve_knob(groups, &peer.config, |k| k.ip_transparent).unwrap_or(false);
        super::config::apply_ip_transparent(peer, want)
    });
    super::config::apply_ip_transparent_refresh_all(bgp);
    Some(())
}

/// `set router bgp neighbor-group <name> passive <bool>` — the flat
/// boolean spelling of the per-neighbor `transport passive-mode` leaf.
///
/// Stores the opinion and re-resolves every member through the same
/// apply ritual as the per-neighbor callback (no bounce; dynamic
/// members stay forced-passive inside the apply fn).
pub fn config_neighbor_group_passive(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let value = match op {
        ConfigOp::Set => Some(args.boolean()?),
        ConfigOp::Delete => None,
        _ => return Some(()),
    };
    bgp.neighbor_groups
        .entry(name.clone())
        .or_default()
        .knobs
        .passive = value;
    sweep_members(bgp, &name, |groups, peer| {
        let want = resolve_knob(groups, &peer.config, |k| k.passive).unwrap_or(false);
        super::config::apply_passive(peer, want)
    });
    Some(())
}

/// `set router bgp neighbor-group <name> allowas-in` — the presence
/// container. Mirrors the per-neighbor `config_allowas_in`
/// `get_or_insert` logic onto the group's opinion, then re-resolves
/// every member.
pub fn config_neighbor_group_allowas_in(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let knobs = &mut bgp.neighbor_groups.entry(name.clone()).or_default().knobs;
    if op.is_set() {
        knobs
            .allowas_in
            .get_or_insert(AllowAsIn::Count(ALLOWAS_IN_DEFAULT_COUNT));
    } else {
        knobs.allowas_in = None;
    }
    sweep_members(bgp, &name, |groups, peer| {
        let want = resolve_knob(groups, &peer.config, |k| k.allowas_in);
        super::config::apply_allowas_in(peer, want)
    });
    Some(())
}

/// `set router bgp neighbor-group <name> allowas-in count <1-10>`.
/// Mirrors the per-neighbor `config_allowas_in_count` logic onto the
/// group's opinion.
pub fn config_neighbor_group_allowas_in_count(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let name = args.string()?;
    if op.is_set() {
        let count = args.u8()?;
        let knobs = &mut bgp.neighbor_groups.entry(name.clone()).or_default().knobs;
        knobs.allowas_in = Some(AllowAsIn::Count(count));
    } else {
        let knobs = &mut bgp.neighbor_groups.entry(name.clone()).or_default().knobs;
        if matches!(knobs.allowas_in, Some(AllowAsIn::Count(_))) {
            knobs.allowas_in = Some(AllowAsIn::Count(ALLOWAS_IN_DEFAULT_COUNT));
        }
    }
    sweep_members(bgp, &name, |groups, peer| {
        let want = resolve_knob(groups, &peer.config, |k| k.allowas_in);
        super::config::apply_allowas_in(peer, want)
    });
    Some(())
}

/// `set router bgp neighbor-group <name> allowas-in origin`. Mirrors
/// the per-neighbor `config_allowas_in_origin` logic onto the group's
/// opinion.
pub fn config_neighbor_group_allowas_in_origin(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let name = args.string()?;
    let knobs = &mut bgp.neighbor_groups.entry(name.clone()).or_default().knobs;
    if op.is_set() {
        knobs.allowas_in = Some(AllowAsIn::Origin);
    } else if matches!(knobs.allowas_in, Some(AllowAsIn::Origin)) {
        knobs.allowas_in = Some(AllowAsIn::Count(ALLOWAS_IN_DEFAULT_COUNT));
    }
    sweep_members(bgp, &name, |groups, peer| {
        let want = resolve_knob(groups, &peer.config, |k| k.allowas_in);
        super::config::apply_allowas_in(peer, want)
    });
    Some(())
}

/// `set router bgp neighbor-group <name> as-override` — presence
/// container. Stores the opinion and re-resolves every member.
pub fn config_neighbor_group_as_override(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let name = args.string()?;
    bgp.neighbor_groups
        .entry(name.clone())
        .or_default()
        .knobs
        .as_override = op.is_set().then_some(true);
    sweep_members(bgp, &name, |groups, peer| {
        let want = resolve_knob(groups, &peer.config, |k| k.as_override).unwrap_or(false);
        super::config::apply_as_override(peer, want)
    });
    Some(())
}

/// `set router bgp neighbor-group <name> remove-private-as` — presence
/// container. Mirrors the per-neighbor `config_remove_private_as`
/// `get_or_insert_with` logic onto the group's opinion, then
/// re-resolves every member.
pub fn config_neighbor_group_remove_private_as(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let name = args.string()?;
    let knobs = &mut bgp.neighbor_groups.entry(name.clone()).or_default().knobs;
    if op.is_set() {
        knobs
            .remove_private_as
            .get_or_insert_with(RemovePrivateAs::default);
    } else {
        knobs.remove_private_as = None;
    }
    sweep_members(bgp, &name, |groups, peer| {
        let want = resolve_knob(groups, &peer.config, |k| k.remove_private_as);
        super::config::apply_remove_private_as(peer, want)
    });
    Some(())
}

/// `set router bgp neighbor-group <name> remove-private-as all`.
/// Mirrors the per-neighbor `config_remove_private_as_all` logic onto
/// the group's opinion.
pub fn config_neighbor_group_remove_private_as_all(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let name = args.string()?;
    let knobs = &mut bgp.neighbor_groups.entry(name.clone()).or_default().knobs;
    if op.is_set() {
        knobs
            .remove_private_as
            .get_or_insert_with(RemovePrivateAs::default)
            .all = true;
    } else if let Some(rpa) = knobs.remove_private_as.as_mut() {
        rpa.all = false;
    }
    sweep_members(bgp, &name, |groups, peer| {
        let want = resolve_knob(groups, &peer.config, |k| k.remove_private_as);
        super::config::apply_remove_private_as(peer, want)
    });
    Some(())
}

/// `set router bgp neighbor-group <name> remove-private-as replace-as`.
/// Mirrors the per-neighbor `config_remove_private_as_replace_as` logic
/// onto the group's opinion.
pub fn config_neighbor_group_remove_private_as_replace_as(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let name = args.string()?;
    let knobs = &mut bgp.neighbor_groups.entry(name.clone()).or_default().knobs;
    if op.is_set() {
        knobs
            .remove_private_as
            .get_or_insert_with(RemovePrivateAs::default)
            .replace_as = true;
    } else if let Some(rpa) = knobs.remove_private_as.as_mut() {
        rpa.replace_as = false;
    }
    sweep_members(bgp, &name, |groups, peer| {
        let want = resolve_knob(groups, &peer.config, |k| k.remove_private_as);
        super::config::apply_remove_private_as(peer, want)
    });
    Some(())
}

/// `set router bgp neighbor-group <name> enforce-first-as` — presence
/// container. Stores the opinion and re-resolves every member.
pub fn config_neighbor_group_enforce_first_as(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let name = args.string()?;
    bgp.neighbor_groups
        .entry(name.clone())
        .or_default()
        .knobs
        .enforce_first_as = op.is_set().then_some(true);
    sweep_members(bgp, &name, |groups, peer| {
        let want = resolve_knob(groups, &peer.config, |k| k.enforce_first_as).unwrap_or(false);
        super::config::apply_enforce_first_as(peer, want)
    });
    Some(())
}

/// `set router bgp neighbor-group <name> route-reflector client <bool>`.
///
/// Stores the opinion and re-resolves every member. The effective
/// value lands on `peer.reflector_client` (a `Peer` field, not
/// `PeerConfig`); no session bounce.
pub fn config_neighbor_group_route_reflector_client(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let name = args.string()?;
    let value = match op {
        ConfigOp::Set => Some(args.boolean()?),
        ConfigOp::Delete => None,
        _ => return Some(()),
    };
    bgp.neighbor_groups
        .entry(name.clone())
        .or_default()
        .knobs
        .route_reflector_client = value;
    sweep_members(bgp, &name, |groups, peer| {
        let want =
            resolve_knob(groups, &peer.config, |k| k.route_reflector_client).unwrap_or(false);
        super::config::apply_route_reflector_client(peer, want)
    });
    Some(())
}

/// `set router bgp neighbor-group <name> region-id <asn>` (RFC 9572 §6.1).
///
/// Marks the group as a *region*: stores the 8-octet, EC-formatted Region ID
/// (Source-AS form via [`bgp_packet::region_id_from_asn`]) so a Regional
/// Border Router can aggregate the region's IMET into a Per-Region I-PMSI
/// (Type-9) route and suppress per-PE IMET across the boundary. The value is
/// read at advertise/receive time via [`resolve_knob`]; there is no session
/// bounce and no per-peer apply (region membership is not a session
/// parameter).
pub fn config_neighbor_group_region_id(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let value = match op {
        ConfigOp::Set => Some(bgp_packet::region_id_from_asn(args.u32()? as u16)),
        ConfigOp::Delete => None,
        _ => return Some(()),
    };
    bgp.neighbor_groups
        .entry(name.clone())
        .or_default()
        .knobs
        .region_id = value;
    // Re-resolve members already bound to this group so the region-id
    // (RFC 9572 §6.1 RBR gate) reaches an existing neighbor regardless of
    // config order. Without this, a neighbor bound before the region-id
    // leaf is applied keeps `region_id = None` and never re-originates the
    // Type-9 Per-Region I-PMSI — every other neighbor-group knob sweeps.
    sweep_members_inherit(bgp, &name);
    Some(())
}

/// `set router bgp neighbor-group <name> update-source <addr>`.
///
/// Like the per-neighbor knob: no bounce (the source is read at dial
/// time) and a per-member address-family guard — a v4 source applies
/// only to v4 members, a v6 source only to v6 members (the apply fn
/// skips mismatches with a warning). Changed members get their BFD
/// session re-keyed, mirroring the per-neighbor callback's
/// `bfd_apply` reconcile.
pub fn config_neighbor_group_update_source(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let name = args.string()?;
    let value = match op {
        ConfigOp::Set => Some(args.addr()?),
        ConfigOp::Delete => None,
        _ => return Some(()),
    };
    bgp.neighbor_groups
        .entry(name.clone())
        .or_default()
        .knobs
        .update_source = value;
    sweep_members_inherit(bgp, &name);
    Some(())
}

/// `set router bgp neighbor-group <name> tcp-mss <1-65535>`.
///
/// Like the per-neighbor knob: no bounce (the clamp is read at
/// connect time; `clear bgp` for immediate effect), and one listener
/// reconcile after the sweep so the shared socket re-derives its
/// per-AF minimum.
pub fn config_neighbor_group_tcp_mss(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let value = match op {
        ConfigOp::Set => Some(args.u16()?),
        ConfigOp::Delete => None,
        _ => return Some(()),
    };
    bgp.neighbor_groups
        .entry(name.clone())
        .or_default()
        .knobs
        .tcp_mss = value;
    sweep_members_inherit(bgp, &name);
    Some(())
}

/// `set router bgp neighbor-group <name> tcp-ao key-chain <name>`.
///
/// Deleting the leaf clears the whole `tcp-ao` opinion: `key-chain` is
/// mandatory inside the presence container, so a group with no chain
/// has no AO to inherit.
pub fn config_neighbor_group_tcp_ao_key_chain(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let name = args.string()?;
    let knobs = &mut bgp.neighbor_groups.entry(name.clone()).or_default().knobs;
    let prior = knobs
        .ao_config
        .as_ref()
        .map(|ao| ao.key_chain.clone())
        .filter(|s| !s.is_empty());
    let new = match op {
        ConfigOp::Set => {
            let key_chain = args.string()?;
            // Preserve an `include-tcp-options` that arrived first —
            // leaf callback order within one commit is not guaranteed.
            let include_tcp_options = knobs
                .ao_config
                .as_ref()
                .map(|ao| ao.include_tcp_options)
                .unwrap_or(true);
            knobs.ao_config = Some(super::auth::AoConfig {
                key_chain: key_chain.clone(),
                include_tcp_options,
            });
            Some(key_chain)
        }
        ConfigOp::Delete => {
            knobs.ao_config = None;
            None
        }
        _ => return Some(()),
    };
    // Subscribe the group's interest in the chain. Without this the
    // policy actor never pushes the chain's content to BGP, so
    // `resolve()` finds nothing and the listener's prefix MKT is never
    // installed — the kernel then drops every AO-signed SYN from the
    // range with TCPAOKeyNotFound. A group is not a peer, so it needs a
    // watch ident of its own (see `group_keychain_watch`).
    let ident = group_keychain_ident(bgp, &name);
    super::config::policy_attach_msgs(
        &bgp.policy_tx,
        ident,
        crate::policy::PolicyType::KeyChain(crate::policy::KeyChainScope::BgpNeighborGroup),
        prior,
        new,
    );
    sweep_members_inherit(bgp, &name);
    super::dynamic_neighbors::reconcile_listener_ao(bgp);
    Some(())
}

/// Stable per-group watch ident for key-chain subscriptions, minted on
/// first use and kept for the lifetime of the process. Deliberately
/// never recycled: a recycled ident could unregister a watch belonging
/// to a since-deleted group that shared the chain.
fn group_keychain_ident(bgp: &mut Bgp, name: &str) -> usize {
    if let Some(ident) = bgp.group_keychain_watch.get(name) {
        return *ident;
    }
    let ident = bgp.group_keychain_watch_next;
    bgp.group_keychain_watch_next += 1;
    bgp.group_keychain_watch.insert(name.to_string(), ident);
    ident
}

/// `set router bgp neighbor-group <name> tcp-ao include-tcp-options <bool>`.
///
/// A no-op when the group has no `key-chain` yet: without one there is
/// no MKT to qualify, and the value is re-derived (defaulting to true)
/// when the chain does arrive.
pub fn config_neighbor_group_tcp_ao_include_tcp_options(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let name = args.string()?;
    let want = match op {
        ConfigOp::Set => args.boolean()?,
        // RFC 5925 §3.1 default, matching the YANG `default "true"`.
        ConfigOp::Delete => true,
        _ => return Some(()),
    };
    let knobs = &mut bgp.neighbor_groups.entry(name.clone()).or_default().knobs;
    if let Some(ao) = knobs.ao_config.as_mut() {
        ao.include_tcp_options = want;
    } else {
        // Chain not configured yet: stash the opinion so a later
        // `key-chain` in the same commit adopts it.
        knobs.ao_config = Some(super::auth::AoConfig {
            key_chain: String::new(),
            include_tcp_options: want,
        });
    }
    sweep_members_inherit(bgp, &name);
    super::dynamic_neighbors::reconcile_listener_ao(bgp);
    Some(())
}

/// `set router bgp neighbor-group <name> password <string>`.
///
/// Like the per-neighbor knob: no bounce (a live session keeps its
/// key until it resets); every changed member's listener key is
/// re-installed so passively-accepted reconnects authenticate under
/// the inherited password.
pub fn config_neighbor_group_password(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let value = match op {
        ConfigOp::Set => Some(args.string()?),
        ConfigOp::Delete => None,
        _ => return Some(()),
    };
    bgp.neighbor_groups
        .entry(name.clone())
        .or_default()
        .knobs
        .password = value;
    sweep_members_inherit(bgp, &name);
    // A listen-range bound to this group authenticates its whole
    // prefix with the group password, so the listener's prefix key
    // has to follow the knob.
    super::dynamic_neighbors::reconcile_listener_md5(bgp);
    Some(())
}

/// `set router bgp neighbor-group <name> policy {in|out} <name>` and
/// `… prefix-set {in|out} <name>` — four callbacks sharing one shape.
///
/// Like the per-neighbor knobs: the member's direction slot is
/// re-bound and the policy actor (un)registered; the actor's reply
/// resolves the name and soft-replays the direction. No bounce.
pub fn config_neighbor_group_policy_in(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    config_neighbor_group_policy_ref(bgp, args.string()?, args, op, |knobs| &mut knobs.policy_in)
}

pub fn config_neighbor_group_policy_out(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    config_neighbor_group_policy_ref(bgp, args.string()?, args, op, |knobs| &mut knobs.policy_out)
}

pub fn config_neighbor_group_prefix_set_in(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    config_neighbor_group_policy_ref(bgp, args.string()?, args, op, |knobs| {
        &mut knobs.prefix_set_in
    })
}

pub fn config_neighbor_group_prefix_set_out(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    config_neighbor_group_policy_ref(bgp, args.string()?, args, op, |knobs| {
        &mut knobs.prefix_set_out
    })
}

fn config_neighbor_group_policy_ref(
    bgp: &mut Bgp,
    name: String,
    mut args: Args,
    op: ConfigOp,
    slot: impl Fn(&mut InheritableKnobs) -> &mut Option<String>,
) -> Option<()> {
    let value = match op {
        ConfigOp::Set => Some(args.string()?),
        ConfigOp::Delete => None,
        _ => return Some(()),
    };
    *slot(&mut bgp.neighbor_groups.entry(name.clone()).or_default().knobs) = value;
    sweep_members_inherit(bgp, &name);
    Some(())
}

/// Resolve one whole-session inheritable knob for a peer: the explicit
/// per-peer statement wins, else the referenced group's opinion, else
/// `None` (the per-knob default applies). `pick` selects the field
/// from either [`InheritableKnobs`] record.
pub fn resolve_knob<T>(
    groups: &BTreeMap<String, NeighborGroup>,
    config: &PeerConfig,
    pick: impl Fn(&InheritableKnobs) -> Option<T>,
) -> Option<T> {
    pick(&config.knobs_explicit).or_else(|| {
        config
            .neighbor_group
            .as_deref()
            .and_then(|name| groups.get(name))
            .and_then(|group| pick(&group.knobs))
    })
}

/// Run `apply` for every member of group `name`, then queue an FSM
/// stop for each member whose apply asked for one (a knob whose new
/// value needs a reconnect on a live session — the same `Event::Stop`
/// ritual the per-neighbor callbacks use). `iter_mut_all` so
/// interface-keyed (IPv6 unnumbered) and dynamic members are swept
/// too.
pub(super) fn sweep_members(
    bgp: &mut Bgp,
    name: &str,
    mut apply: impl FnMut(&BTreeMap<String, NeighborGroup>, &mut Peer) -> bool,
) {
    let mut stops: Vec<usize> = Vec::new();
    for (_, peer) in bgp.peers.iter_mut_all() {
        if peer.config.neighbor_group.as_deref() != Some(name) {
            continue;
        }
        if apply(&bgp.neighbor_groups, peer) && !matches!(peer.state, State::Idle) {
            stops.push(peer.ident);
        }
    }
    for ident in stops {
        let _ = bgp.tx.try_send(Message::Event(ident, Event::Stop));
    }
}

/// MUP (draft-ietf-bess-mup-safi) is exposed through a single `mup` config
/// name that enables *both* the IPv4 (AFI 1) and IPv6 (AFI 2) MUP
/// families at once. Every other family is one config name → one
/// `(AFI, SAFI)`. Expand a parsed family into the concrete set of
/// `(AFI, SAFI)` tuples it toggles, so the `enabled` handlers, the MP
/// capability set, and the resolver all see ordinary per-family entries.
pub fn mp_family_expand(key: AfiSafi) -> Vec<AfiSafi> {
    if key.safi == Safi::Mup {
        vec![
            AfiSafi::new(Afi::Ip, Safi::Mup),
            AfiSafi::new(Afi::Ip6, Safi::Mup),
        ]
    } else {
        vec![key]
    }
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
    group: Option<&BTreeMap<AfiSafi, GroupAfiSafi>>,
    explicit: &BTreeMap<AfiSafi, bool>,
) -> AfiSafis<bool> {
    let mut mp = AfiSafis::new();
    mp.insert(AfiSafi::new(Afi::Ip, Safi::Unicast), true);
    for (family, entry) in group.into_iter().flatten() {
        if entry.enabled {
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

/// Recompute the per-family inherited state (MP set + next-hop-self)
/// of every peer referencing `name`. Called after any change to the
/// group's `afi-safi` opinions (and after group deletion, where the
/// lookup misses and members fall back to default + explicit).
fn sweep_group_afi_safi(bgp: &mut Bgp, name: &str) {
    sweep_members(bgp, name, |groups, peer| {
        // An AFI/SAFI is a Multiprotocol capability fixed at OPEN time, so a
        // change to a member's effective family set only takes effect on a
        // session that renegotiates. Bounce an Established member whose set
        // actually changed (mirrors the per-peer `config_afi_safi`); a member
        // still coming up carries the new family in its first OPEN, and an
        // unchanged set never bounces.
        let before: std::collections::BTreeSet<AfiSafi> =
            peer.config.mp.0.keys().copied().collect();
        recompute_peer_mp(groups, &mut peer.config);
        recompute_peer_nhs(groups, peer);
        let after: std::collections::BTreeSet<AfiSafi> = peer.config.mp.0.keys().copied().collect();
        before != after && matches!(peer.state, State::Established)
    });
}

/// Re-resolve the effective per-family `next-hop-self` of one peer for
/// every family either side mentions. Families with no statement left
/// on either side fall back to the off default — the union sweep is
/// what clears a removed opinion.
fn recompute_peer_nhs(groups: &BTreeMap<String, NeighborGroup>, peer: &mut Peer) {
    let mut families: Vec<AfiSafi> = peer.config.sub.keys().copied().collect();
    families.extend(peer.config.nhs_explicit.keys().copied());
    if let Some(group) = peer
        .config
        .neighbor_group
        .as_deref()
        .and_then(|name| groups.get(name))
    {
        families.extend(group.afi_safi.keys().copied());
    }
    families.sort_unstable();
    families.dedup();
    for family in families {
        let value = resolve_next_hop_self(groups, &peer.config, family);
        peer.config.sub.entry(family).or_default().next_hop_self = value;
    }
}

/// Re-resolve EVERYTHING a neighbor-group can supply for one peer: the
/// MP family set, per-family next-hop-self, and the whole-session
/// knobs — each through the same diff-gated apply ritual its
/// per-neighbor callback uses. Returns `true` when a live session must
/// bounce for some knob to take effect (the caller owns the
/// `Event::Stop` send).
///
/// Used by every path where the peer↔group binding itself changes:
/// peer materialization (static attach, interface RA, dynamic accept),
/// `interface-neighbor … neighbor-group` rebinding, and the
/// group-delete cascade.
/// Cross-borrow side-effect jobs an [`apply_inherited`] pass asks its
/// caller to run once the peer borrow ends. Each maps to the same
/// bgp-level reconciler the corresponding per-neighbor callback uses.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct InheritOutcome {
    /// A knob whose new value needs the session to reconnect — send
    /// `Event::Stop` (skip for Idle peers; the apply fns already
    /// account for that in their bounce decision).
    pub bounce: bool,
    /// `tcp-mss` changed — run `apply_tcp_mss_refresh_all` so the
    /// shared listener re-derives its per-AF minimum clamp.
    pub mss_refresh: bool,
    /// The MD5 password changed — run `apply_md5_refresh_for` with
    /// this peer's address to re-key the listener.
    pub md5_refresh: bool,
    /// The inherited TCP-AO config changed — run
    /// `apply_ao_refresh_all` so the listener MKT follows. Unlike
    /// MD5 there is no per-peer variant: AO resolution reads the
    /// key-chain table, which the whole-instance sweep already has.
    pub ao_refresh: bool,
    /// `update-source` changed — run `bfd_apply` so an attached BFD
    /// session re-keys to the new local address.
    pub bfd_reapply: bool,
}

/// Resolve and apply the inheritable *session* knobs onto a freshly
/// materialized peer, for a caller that does its own `mp` / next-hop-self
/// resolution and has no live session to reconcile.
///
/// This is the per-VRF counterpart to [`apply_inherited`]. It cannot use
/// that function directly for two reasons:
///
///   * [`apply_inherited`] calls [`recompute_peer_mp`], whose base family
///     is a *forced* IPv4 unicast ([`effective_mp`]). A per-VRF CE peer
///     derives its base from its own address instead — a bare IPv6 CE
///     must negotiate IPv6 unicast only — so `materialize_peers` resolves
///     `mp` itself and this helper leaves `config.mp` alone.
///   * The auth / MSS / BFD knobs return cross-borrow *refresh* outcomes
///     that a live global neighbor reconciles against its shared listener
///     and BFD client. A CE peer is built before it dials and (today) has
///     no such shared state, so those knobs are handled in their own
///     phases; this helper covers only the knobs that are a pure mutation
///     of peer state.
///
/// Returns nothing: every knob here applies at (re)spawn, and a bounce is
/// meaningless for a peer that has not started. The knobs it does NOT yet
/// cover (`password`, `ao_config`, `tcp_mss`, `update_source`'s BFD
/// re-arm) are the auth / BFD follow-ups.
pub(super) fn apply_inherited_session_knobs(
    groups: &BTreeMap<String, NeighborGroup>,
    peer: &mut Peer,
) {
    // ebgp-multihop before ttl-security: the two are mutually exclusive
    // and each guard observes the other, so the order must match
    // `apply_inherited`.
    let ebgp_multihop = resolve_knob(groups, &peer.config, |k| k.ebgp_multihop);
    super::config::apply_ebgp_multihop(peer, ebgp_multihop);
    let ttl_security = resolve_knob(groups, &peer.config, |k| k.ttl_security).unwrap_or(false);
    super::config::apply_ttl_security(peer, ttl_security);
    let port = resolve_knob(groups, &peer.config, |k| k.port);
    super::config::apply_port(peer, port);
    let dcc = resolve_knob(groups, &peer.config, |k| k.disable_connected_check).unwrap_or(false);
    super::config::apply_disable_connected_check(peer, dcc);
    let ipt = resolve_knob(groups, &peer.config, |k| k.ip_transparent).unwrap_or(false);
    super::config::apply_ip_transparent(peer, ipt);
    let passive = resolve_knob(groups, &peer.config, |k| k.passive).unwrap_or(false);
    super::config::apply_passive(peer, passive);
    let allowas_in = resolve_knob(groups, &peer.config, |k| k.allowas_in);
    super::config::apply_allowas_in(peer, allowas_in);
    let as_override = resolve_knob(groups, &peer.config, |k| k.as_override).unwrap_or(false);
    super::config::apply_as_override(peer, as_override);
    let remove_private_as = resolve_knob(groups, &peer.config, |k| k.remove_private_as);
    super::config::apply_remove_private_as(peer, remove_private_as);
    let enforce_first_as =
        resolve_knob(groups, &peer.config, |k| k.enforce_first_as).unwrap_or(false);
    super::config::apply_enforce_first_as(peer, enforce_first_as);
    let rr_client =
        resolve_knob(groups, &peer.config, |k| k.route_reflector_client).unwrap_or(false);
    super::config::apply_route_reflector_client(peer, rr_client);
    let update_source = resolve_knob(groups, &peer.config, |k| k.update_source);
    // The BFD re-arm this returns is only meaningful for a live session.
    let _ = super::config::apply_update_source(peer, update_source);
    // TCP-MD5 password: resolve the verbatim statement over the group
    // and write the effective value onto `config.transport.md5_password`.
    // The shared FSM connect path (`peer_start_connection`) reads it and
    // applies it to this peer's VRF-bound *connect* socket, so the PE's
    // outbound dial to the CE is authenticated. The listener (passive)
    // side is not keyed here — per-VRF passive-side auth needs a
    // per-VRF listener (see the FRR model); the `_refresh` outcome is
    // therefore discarded.
    let password = resolve_knob(groups, &peer.config, |k| k.password.clone());
    let _ = super::config::apply_md5_password(peer, password);
}

pub(super) fn apply_inherited(
    groups: &BTreeMap<String, NeighborGroup>,
    policy_tx: &tokio::sync::mpsc::UnboundedSender<crate::policy::Message>,
    peer: &mut Peer,
) -> InheritOutcome {
    recompute_peer_mp(groups, &mut peer.config);
    recompute_peer_nhs(groups, peer);

    // Resolve every knob up front by constructing the full record —
    // the struct literal names each field, so adding a knob to
    // `InheritableKnobs` refuses to compile until this site decides
    // how to apply it.
    let resolved = InheritableKnobs {
        passive: resolve_knob(groups, &peer.config, |k| k.passive),
        update_source: resolve_knob(groups, &peer.config, |k| k.update_source),
        port: resolve_knob(groups, &peer.config, |k| k.port),
        ttl_security: resolve_knob(groups, &peer.config, |k| k.ttl_security),
        ebgp_multihop: resolve_knob(groups, &peer.config, |k| k.ebgp_multihop),
        tcp_mss: resolve_knob(groups, &peer.config, |k| k.tcp_mss),
        password: resolve_knob(groups, &peer.config, |k| k.password.clone()),
        ao_config: resolve_knob(groups, &peer.config, |k| k.ao_config.clone()),
        disable_connected_check: resolve_knob(groups, &peer.config, |k| k.disable_connected_check),
        ip_transparent: resolve_knob(groups, &peer.config, |k| k.ip_transparent),
        policy_in: resolve_knob(groups, &peer.config, |k| k.policy_in.clone()),
        policy_out: resolve_knob(groups, &peer.config, |k| k.policy_out.clone()),
        prefix_set_in: resolve_knob(groups, &peer.config, |k| k.prefix_set_in.clone()),
        prefix_set_out: resolve_knob(groups, &peer.config, |k| k.prefix_set_out.clone()),
        allowas_in: resolve_knob(groups, &peer.config, |k| k.allowas_in),
        as_override: resolve_knob(groups, &peer.config, |k| k.as_override),
        remove_private_as: resolve_knob(groups, &peer.config, |k| k.remove_private_as),
        enforce_first_as: resolve_knob(groups, &peer.config, |k| k.enforce_first_as),
        route_reflector_client: resolve_knob(groups, &peer.config, |k| k.route_reflector_client),
        region_id: resolve_knob(groups, &peer.config, |k| k.region_id),
    };
    // Destructure so an unapplied field is a compile error, not a
    // silently-ignored knob. Fields whose apply lands in a follow-up
    // batch are discarded explicitly below — remove the discard when
    // wiring the knob.
    let InheritableKnobs {
        passive,
        update_source,
        port,
        ttl_security,
        ebgp_multihop,
        tcp_mss,
        password,
        ao_config,
        disable_connected_check,
        ip_transparent,
        policy_in,
        policy_out,
        prefix_set_in,
        prefix_set_out,
        allowas_in,
        as_override,
        remove_private_as,
        enforce_first_as,
        route_reflector_client,
        region_id,
    } = resolved;

    // `region_id` (RFC 9572 §6.1) is not a session parameter — no FSM
    // bounce — but the EVPN receive / advertise paths can't reach
    // `neighbor_groups` to resolve it, so cache the resolved value on the
    // peer. Read by cross-region IMET suppression and Type-9 re-origination.
    peer.region_id = region_id;

    let mut outcome = InheritOutcome::default();
    let mut bounce = false;
    // ebgp-multihop before ttl-security: the two are mutually
    // exclusive and each apply fn refuses to override the other, so
    // applying ebgp-multihop first lets `apply_ttl_security`'s guard
    // observe it — matching a per-neighbor commit where both leaves'
    // callbacks fire and the guard keeps whichever landed first.
    bounce |= super::config::apply_ebgp_multihop(peer, ebgp_multihop);
    bounce |= super::config::apply_ttl_security(peer, ttl_security.unwrap_or(false));
    bounce |= super::config::apply_port(peer, port);
    bounce |= super::config::apply_disable_connected_check(
        peer,
        disable_connected_check.unwrap_or(false),
    );
    // No listener-refresh outcome flag needed: the listener union folds
    // group opinions in directly, so a peer↔group binding change alone
    // never alters it — only the knob callbacks / group delete do, and
    // those reconcile the listeners themselves.
    bounce |= super::config::apply_ip_transparent(peer, ip_transparent.unwrap_or(false));
    super::config::apply_passive(peer, passive.unwrap_or(false));
    super::config::apply_allowas_in(peer, allowas_in);
    super::config::apply_as_override(peer, as_override.unwrap_or(false));
    super::config::apply_remove_private_as(peer, remove_private_as);
    super::config::apply_enforce_first_as(peer, enforce_first_as.unwrap_or(false));
    super::config::apply_route_reflector_client(peer, route_reflector_client.unwrap_or(false));
    outcome.bfd_reapply = super::config::apply_update_source(peer, update_source);
    outcome.mss_refresh = super::config::apply_tcp_mss(peer, tcp_mss);
    outcome.md5_refresh = super::config::apply_md5_password(peer, password);
    outcome.ao_refresh = super::config::apply_ao_config(peer, ao_config);
    // Same reasoning as the password: the MKT is consulted at
    // handshake time, so a live session under the old key must bounce
    // to pick up the new one.
    bounce |= outcome.ao_refresh;
    // A password change must reset the session, like the per-neighbor
    // path: the listener / connect-socket key only takes effect on a
    // fresh connection, so a live session under the old key must bounce.
    // (`tcp-mss` is a clamp on new segments and does not break auth, so
    // it stays out of the bounce set.)
    bounce |= outcome.md5_refresh;
    super::config::apply_peer_policy_ref(
        policy_tx,
        peer,
        crate::policy::PolicyType::PolicyListIn,
        policy_in,
    );
    super::config::apply_peer_policy_ref(
        policy_tx,
        peer,
        crate::policy::PolicyType::PolicyListOut,
        policy_out,
    );
    super::config::apply_peer_policy_ref(
        policy_tx,
        peer,
        crate::policy::PolicyType::PrefixSetIn,
        prefix_set_in,
    );
    super::config::apply_peer_policy_ref(
        policy_tx,
        peer,
        crate::policy::PolicyType::PrefixSetOut,
        prefix_set_out,
    );
    outcome.bounce = bounce;
    outcome
}

/// Re-resolve the full inherited attribute set for every member of
/// group `name` and run the cross-borrow jobs each apply asked for.
/// The full-resolution sibling of [`sweep_members`], used by the
/// knobs whose side effects need `&mut Bgp` (listener clamps, MD5
/// re-keys, BFD reconciles) and by the group-delete cascade.
pub(super) fn sweep_members_inherit(bgp: &mut Bgp, name: &str) {
    let policy_tx = bgp.policy_tx.clone();
    let mut stops: Vec<usize> = Vec::new();
    let mut mss_refresh = false;
    let mut ao_refresh = false;
    // Collect idents, not addresses: the MD5 / BFD reconcilers must be
    // able to reach an interface-keyed (unnumbered) member, whose
    // link-local is not a map key (`get(&peer.address)` would miss it).
    let mut md5_idents: Vec<usize> = Vec::new();
    let mut bfd_idents: Vec<usize> = Vec::new();
    for (_, peer) in bgp.peers.iter_mut_all() {
        if peer.config.neighbor_group.as_deref() != Some(name) {
            continue;
        }
        let outcome = apply_inherited(&bgp.neighbor_groups, &policy_tx, peer);
        if outcome.bounce && !matches!(peer.state, State::Idle) {
            stops.push(peer.ident);
        }
        mss_refresh |= outcome.mss_refresh;
        ao_refresh |= outcome.ao_refresh;
        if outcome.md5_refresh {
            md5_idents.push(peer.ident);
        }
        if outcome.bfd_reapply {
            bfd_idents.push(peer.ident);
        }
    }
    for ident in stops {
        let _ = bgp.tx.try_send(Message::Event(ident, Event::Stop));
    }
    if mss_refresh {
        super::config::apply_tcp_mss_refresh_all(bgp);
    }
    if ao_refresh {
        super::config::apply_ao_refresh_all(bgp);
    }
    // Unconditional (cheap, idempotent): this sweep also serves the
    // group-delete cascade, where a deleted `ip-transparent` opinion
    // must drop out of the listener union.
    super::config::apply_ip_transparent_refresh_all(bgp);
    for ident in md5_idents {
        super::config::apply_md5_refresh_for_ident(bgp, ident);
    }
    for ident in bfd_idents {
        let _ = super::config::bfd_apply_ident(bgp, ident);
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

    #[test]
    fn mp_family_expand_fans_out_mup_to_both_afis() {
        // `mup` enables both IPv4-MUP and IPv6-MUP (draft-ietf-bess-mup-safi).
        assert_eq!(
            mp_family_expand(AfiSafi::new(Afi::Ip, Safi::Mup)),
            vec![
                AfiSafi::new(Afi::Ip, Safi::Mup),
                AfiSafi::new(Afi::Ip6, Safi::Mup),
            ]
        );
        // Every other family passes through unchanged.
        let v4 = AfiSafi::new(Afi::Ip, Safi::Unicast);
        assert_eq!(mp_family_expand(v4), vec![v4]);
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

    /// Group `afi-safi <family> enabled <bool>` entry shorthand.
    fn entry(enabled: bool) -> GroupAfiSafi {
        GroupAfiSafi {
            enabled,
            ..Default::default()
        }
    }

    #[test]
    fn effective_mp_default_is_ipv4_unicast_only() {
        let mp = effective_mp(None, &BTreeMap::new());
        assert_eq!(families(&mp), vec![v4()]);
    }

    #[test]
    fn effective_mp_group_enables_extra_family() {
        let group = BTreeMap::from([(v6(), entry(true))]);
        let mp = effective_mp(Some(&group), &BTreeMap::new());
        assert_eq!(families(&mp), vec![v4(), v6()]);
    }

    #[test]
    fn effective_mp_group_disables_the_ipv4_default() {
        let group = BTreeMap::from([(v4(), entry(false)), (v6(), entry(true))]);
        let mp = effective_mp(Some(&group), &BTreeMap::new());
        assert_eq!(families(&mp), vec![v6()]);
    }

    #[test]
    fn effective_mp_explicit_wins_over_group() {
        // Group switches v4 off, but the peer's own `afi-safi ipv4
        // enabled true` stands; group's v6 opinion is unopposed.
        let group = BTreeMap::from([(v4(), entry(false)), (v6(), entry(true))]);
        let explicit = BTreeMap::from([(v4(), true)]);
        let mp = effective_mp(Some(&group), &explicit);
        assert_eq!(families(&mp), vec![v4(), v6()]);

        // ... and the mirror: group on, explicit off.
        let group = BTreeMap::from([(v6(), entry(true))]);
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
