//! IOS-XR-style BGP **update-groups** — Phase 1 (signature + grouping
//! skeleton, observability only).
//!
//! Two peers belong to the same update-group for a given `(afi, safi)`
//! iff every input that drives `route_update_ipv4` and
//! `route_apply_policy_out` is identical, plus every negotiated
//! capability that changes UPDATE wire format. See
//! `docs/design/bgp-update-groups.md` §3.1 for the full signature.
//!
//! Phase 1 only computes signatures and tracks membership — the
//! advertise pipeline is unchanged. Sharing the attribute transform,
//! outbound policy, and encoded UPDATE bytes lands in Phase 2/3.
//!
//! Conservatism rule: any outbound knob that the signature does not
//! yet model forces the peer into a singleton group. Silent data leak
//! between peers is the worst-case bug. The signature carries
//! `signature_version` so stale views are detectable.
//!
//! Scope of AFI/SAFIs in v1: IPv4 unicast, VPNv4 unicast (MplsVpn),
//! L2VPN EVPN — the three families the advertise pipeline currently
//! handles.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::time::Instant;

use bgp_packet::{Afi, AfiSafi, Safi};

use super::peer::{Peer, PeerType};
use super::peer_map::PeerMap;
use crate::bgp::InOut;

/// Bumped whenever a new field is added to `UpdateGroupSig`. Surfaced
/// in `show bgp update-group` so a stale view is detectable.
pub const SIGNATURE_VERSION: u32 = 1;

/// Address families the v1 grouping logic considers. The advertise
/// pipeline today only fans out to these three.
pub const TRACKED_AFI_SAFIS: [(Afi, Safi); 3] = [
    (Afi::Ip, Safi::Unicast),
    (Afi::Ip, Safi::MplsVpn),
    (Afi::L2vpn, Safi::Evpn),
];

/// Stable per-AFI/SAFI identifier — IOS-XR-style "ipv4-unicast.0".
/// Allocated on first appearance of a signature, never reused after a
/// group empties.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UpdateGroupId {
    pub afi: Afi,
    pub safi: Safi,
    pub seq: u32,
}

impl UpdateGroupId {
    pub fn new(afi: Afi, safi: Safi, seq: u32) -> Self {
        Self { afi, safi, seq }
    }

    pub fn afi_safi_tag(afi: Afi, safi: Safi) -> &'static str {
        match (afi, safi) {
            (Afi::Ip, Safi::Unicast) => "ipv4-unicast",
            (Afi::Ip, Safi::MplsVpn) => "vpnv4",
            (Afi::L2vpn, Safi::Evpn) => "evpn",
            _ => "other",
        }
    }
}

impl std::fmt::Display for UpdateGroupId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}.{}",
            Self::afi_safi_tag(self.afi, self.safi),
            self.seq
        )
    }
}

/// What makes two peers eligible to share Adj-RIB-Out work.
///
/// All fields here either drive the attribute transform / outbound
/// policy (the policy-identity block) or change the on-wire encoding
/// of UPDATEs (the negotiated-capability block). RTC, GR, LLGR,
/// route-refresh and FQDN are intentionally absent — see the design
/// doc §3.1 for why.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UpdateGroupSig {
    // Policy / transform identity:
    pub peer_type: PeerType,
    pub reflector_client: bool,
    pub local_as: u32,
    pub local_addr: Option<IpAddr>,
    pub policy_out_name: Option<String>,
    pub prefix_set_out_name: Option<String>,
    // Negotiated wire-format capabilities (intersection of cap_send
    // and cap_recv on the peer). Anything that changes encoded
    // UPDATE bytes belongs here.
    pub as4_negotiated: bool,
    pub extended_message: bool,
    pub addpath_send: bool,
    pub extended_next_hop: bool,
    pub multiple_labels: bool,
    pub signature_version: u32,
}

#[derive(Debug, Default, Clone)]
pub struct UpdateGroupCounters {
    pub policy_runs: u64,
    pub policy_denials: u64,
    pub messages_formatted: u64,
    pub messages_replicated: u64,
    pub bytes_formatted: u64,
    pub split_horizon_excluded: u64,
    pub last_format_us: Option<u64>,
    pub last_replicate_us: Option<u64>,
}

/// One update-group: a signature and the peers currently sharing it.
#[derive(Debug, Clone)]
pub struct UpdateGroup {
    pub id: UpdateGroupId,
    pub sig: UpdateGroupSig,
    /// Peer idents (PeerMap key) — small, easily cloned, and cheap to
    /// look up against `Bgp::peers` when rendering the show command.
    pub members: BTreeSet<usize>,
    pub created_at: Instant,
    pub counters: UpdateGroupCounters,
}

/// Per-AFI/SAFI bookkeeping: the active groups plus a monotonic seq
/// counter for ID allocation. Sequence numbers are not reused after a
/// group empties so log correlation stays stable.
#[derive(Debug, Default)]
pub struct UpdateGroupAf {
    pub groups: BTreeMap<UpdateGroupSig, UpdateGroup>,
    pub next_seq: u32,
}

impl UpdateGroupAf {
    /// Look up a mutable reference to the group with the given id.
    /// Linear search; group counts per AFI/SAFI are bounded.
    pub fn group_by_id_mut(&mut self, id: &UpdateGroupId) -> Option<&mut UpdateGroup> {
        self.groups.values_mut().find(|g| &g.id == id)
    }
}

/// Top-level container on `Bgp`.
pub type UpdateGroupMap = BTreeMap<AfiSafi, UpdateGroupAf>;

pub fn empty_map() -> UpdateGroupMap {
    BTreeMap::new()
}

/// Compute the signature for `peer` in `(afi, safi)`. Returns `None`
/// if the peer is not active in this AFI/SAFI (capability not
/// negotiated by both sides). Established-state is **not** checked
/// here — caller (attach/detach hook) is responsible.
pub fn signature_of(peer: &Peer, afi: Afi, safi: Safi) -> Option<UpdateGroupSig> {
    if !peer.is_afi_safi(afi, safi) {
        return None;
    }

    let policy_out_name = peer.policy_list.get(&InOut::Output).name.clone();
    let prefix_set_out_name = peer.prefix_set.get(&InOut::Output).name.clone();

    Some(UpdateGroupSig {
        peer_type: match peer.peer_type {
            PeerType::IBGP => PeerType::IBGP,
            PeerType::EBGP => PeerType::EBGP,
        },
        reflector_client: peer.reflector_client,
        local_as: peer.local_as,
        local_addr: peer.param.local_addr.map(|s| s.ip()),
        policy_out_name,
        prefix_set_out_name,
        as4_negotiated: peer.as4,
        extended_message: peer.opt.extended_message,
        addpath_send: peer.opt.is_add_path_send(afi, safi),
        // RFC 8950 / RFC 8277 are not yet negotiated by zebra-rs;
        // hardcoded false until those capabilities land. The fields
        // exist so the signature is forward-compatible.
        extended_next_hop: false,
        multiple_labels: false,
        signature_version: SIGNATURE_VERSION,
    })
}

/// Add `peer_idx` to its update-group for every tracked AFI/SAFI it
/// participates in. Idempotent — calling twice on an already-attached
/// peer is a no-op.
///
/// Takes split borrows on `update_groups` and `peers` so the caller
/// can be the FSM (which holds a `BgpTop` separately from the
/// `PeerMap`).
pub fn attach(update_groups: &mut UpdateGroupMap, peers: &mut PeerMap, peer_idx: usize) {
    let Some(peer) = peers.get_by_idx(peer_idx) else {
        return;
    };

    // Snapshot signatures so we can mutate update_groups + peer
    // without overlapping borrows.
    let mut sigs: Vec<(AfiSafi, UpdateGroupSig)> = Vec::new();
    for (afi, safi) in TRACKED_AFI_SAFIS {
        if let Some(sig) = signature_of(peer, afi, safi) {
            sigs.push((AfiSafi::new(afi, safi), sig));
        }
    }

    for (afi_safi, sig) in sigs {
        let af = update_groups.entry(afi_safi).or_default();
        let entry = af.groups.entry(sig.clone()).or_insert_with(|| {
            let id = UpdateGroupId::new(afi_safi.afi, afi_safi.safi, af.next_seq);
            af.next_seq += 1;
            UpdateGroup {
                id,
                sig: sig.clone(),
                members: BTreeSet::new(),
                created_at: Instant::now(),
                counters: UpdateGroupCounters::default(),
            }
        });
        entry.members.insert(peer_idx);

        let id = entry.id.clone();
        if let Some(peer) = peers.get_mut_by_idx(peer_idx) {
            peer.update_group_id.insert(afi_safi, id);
        }
    }
}

/// Remove `peer_idx` from every update-group it currently belongs to.
/// Empty groups are dropped, but `next_seq` is **not** rolled back —
/// a future signature gets a fresh ID rather than reusing a retired
/// one, so log correlation across the lifetime of the daemon stays
/// stable.
pub fn detach(update_groups: &mut UpdateGroupMap, peers: &mut PeerMap, peer_idx: usize) {
    let memberships: Vec<(AfiSafi, UpdateGroupId)> = {
        let Some(peer) = peers.get_mut_by_idx(peer_idx) else {
            return;
        };
        let ms = peer
            .update_group_id
            .iter()
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        peer.update_group_id.clear();
        ms
    };

    for (afi_safi, id) in memberships {
        let Some(af) = update_groups.get_mut(&afi_safi) else {
            continue;
        };
        let key = af
            .groups
            .iter()
            .find(|(_, g)| g.id == id)
            .map(|(k, _)| k.clone());
        if let Some(key) = key {
            let drop_group = {
                let group = af.groups.get_mut(&key).expect("just located");
                group.members.remove(&peer_idx);
                group.members.is_empty()
            };
            if drop_group {
                af.groups.remove(&key);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_sig() -> UpdateGroupSig {
        UpdateGroupSig {
            peer_type: PeerType::EBGP,
            reflector_client: false,
            local_as: 65001,
            local_addr: None,
            policy_out_name: None,
            prefix_set_out_name: None,
            as4_negotiated: true,
            extended_message: true,
            addpath_send: false,
            extended_next_hop: false,
            multiple_labels: false,
            signature_version: SIGNATURE_VERSION,
        }
    }

    /// Two structurally identical signatures must hash and compare equal.
    #[test]
    fn signature_equality_baseline() {
        assert_eq!(base_sig(), base_sig());
    }

    /// Each signature field, when changed, must produce a distinct
    /// signature — proves no field is silently dropped from the key.
    #[test]
    fn signature_fields_each_distinguish() {
        let base = base_sig();

        let mut a = base.clone();
        a.peer_type = PeerType::IBGP;
        assert_ne!(base, a);

        let mut a = base.clone();
        a.reflector_client = true;
        assert_ne!(base, a);

        let mut a = base.clone();
        a.local_as = 65002;
        assert_ne!(base, a);

        let mut a = base.clone();
        a.local_addr = Some("10.0.0.1".parse().unwrap());
        assert_ne!(base, a);

        let mut a = base.clone();
        a.policy_out_name = Some("export".into());
        assert_ne!(base, a);

        let mut a = base.clone();
        a.prefix_set_out_name = Some("denylist".into());
        assert_ne!(base, a);

        let mut a = base.clone();
        a.as4_negotiated = false;
        assert_ne!(base, a);

        let mut a = base.clone();
        a.extended_message = false;
        assert_ne!(base, a);

        let mut a = base.clone();
        a.addpath_send = true;
        assert_ne!(base, a);

        let mut a = base.clone();
        a.extended_next_hop = true;
        assert_ne!(base, a);

        let mut a = base.clone();
        a.multiple_labels = true;
        assert_ne!(base, a);
    }

    #[test]
    fn id_format_matches_iosxr_style() {
        let id = UpdateGroupId::new(Afi::Ip, Safi::Unicast, 0);
        assert_eq!(id.to_string(), "ipv4-unicast.0");
        let id = UpdateGroupId::new(Afi::Ip, Safi::MplsVpn, 7);
        assert_eq!(id.to_string(), "vpnv4.7");
        let id = UpdateGroupId::new(Afi::L2vpn, Safi::Evpn, 2);
        assert_eq!(id.to_string(), "evpn.2");
    }

    /// Phase 2 hook: the counter-bump path uses `group_by_id_mut`
    /// to find the group from a peer's back-reference id. Verifies
    /// the lookup finds the group and that mutating returned
    /// reference persists.
    #[test]
    fn group_by_id_mut_finds_and_mutates() {
        let mut af = UpdateGroupAf::default();
        let sig = base_sig();
        let id = UpdateGroupId::new(Afi::Ip, Safi::Unicast, 0);
        af.groups.insert(
            sig.clone(),
            UpdateGroup {
                id: id.clone(),
                sig,
                members: BTreeSet::new(),
                created_at: std::time::Instant::now(),
                counters: UpdateGroupCounters::default(),
            },
        );
        af.next_seq = 1;

        // Lookup hit
        let group = af.group_by_id_mut(&id).expect("group exists");
        group.counters.policy_runs = 5;
        group.counters.policy_denials = 2;

        // Reload via lookup, verify the mutation persisted.
        let again = af.group_by_id_mut(&id).expect("group still exists");
        assert_eq!(again.counters.policy_runs, 5);
        assert_eq!(again.counters.policy_denials, 2);

        // Lookup miss: unknown id returns None.
        let missing = UpdateGroupId::new(Afi::Ip, Safi::Unicast, 99);
        assert!(af.group_by_id_mut(&missing).is_none());
    }
}
