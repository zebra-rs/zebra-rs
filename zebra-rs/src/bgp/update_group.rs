//! IOS-XR-style BGP **update-groups** — signature + grouping
//! skeleton, observability only.
//!
//! Two peers belong to the same update-group for a given `(afi, safi)`
//! iff every input that drives `route_update_ipv4` and
//! `route_apply_policy_out` is identical, plus every negotiated
//! capability that changes UPDATE wire format. See
//! `docs/design/bgp-update-groups.md` §3.1 for the full signature.
//!
//! Today this only computes signatures and tracks membership — the
//! advertise pipeline is unchanged. Sharing the attribute transform,
//! outbound policy, and encoded UPDATE bytes is a follow-up.
//!
//! Conservatism rule: any outbound knob that the signature does not
//! yet model forces the peer into a singleton group. Silent data leak
//! between peers is the worst-case bug. The signature carries
//! `signature_version` so stale views are detectable.
//!
//! Scope of AFI/SAFIs in v1: IPv4 unicast, VPNv4 unicast (MplsVpn),
//! L2VPN EVPN — the three families the advertise pipeline currently
//! handles.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Instant;

use bgp_packet::{
    Afi, AfiSafi, BgpAttr, BgpNexthop, CapExtendedNextHop, Ipv4MpReachNextHop, Ipv4Nlri, Ipv6Nlri,
    MpReachAttr, Safi, UnknownAttr, UpdatePacket,
};
use tokio::sync::mpsc;

use super::inst::Message;
use super::peer::{Peer, PeerType};
use super::peer_map::PeerMap;
use super::timer::AdvInterval;
use crate::bgp::InOut;
use crate::context::Timer;

/// Bumped whenever a new field is added to `UpdateGroupSig`. Surfaced
/// in `show bgp update-group` so a stale view is detectable.
pub const SIGNATURE_VERSION: u32 = 5;

/// Address families the grouping logic considers — every family whose
/// advertise pipeline consults `peer.update_group_id`. IPv6 unicast
/// joined late: the v6 advertise path (`route_advertise_to_peers_v6`)
/// has bucketed reach into the per-group `cache_ipv6` since it was
/// built, but the family was never enrolled here, so the group lookup
/// always missed and incremental v6 reach was silently dropped.
pub const TRACKED_AFI_SAFIS: [(Afi, Safi); 4] = [
    (Afi::Ip, Safi::Unicast),
    (Afi::Ip6, Safi::Unicast),
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
            (Afi::Ip6, Safi::Unicast) => "ipv6-unicast",
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

/// Per-neighbor `remove-private-as` egress key
/// (zebra-bgp-remove-private-as.yang). Folded into the update-group
/// signature because the feature rewrites the egress AS_PATH and its
/// output depends on per-peer state: the two FRR modifiers (`all`,
/// `replace_as`) and the neighbor's own AS (`keep_as` = remote_as),
/// which the strip preserves for loop prevention. Two eBGP peers may
/// therefore share canonical UPDATE bytes only when they strip the same
/// way *and* keep the same AS — otherwise the canonical-member transform
/// would leak one peer's stripped path to the others. `None` (the common
/// case) means the feature is off, with no effect on the transform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RemovePrivateAsKey {
    pub all: bool,
    pub replace_as: bool,
    pub keep_as: u32,
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
    /// Per-neighbor `as-override` target (zebra-bgp-as-override.yang).
    /// `None` when off (the common case — no effect on the egress
    /// transform). `Some(remote_as)` when on: the egress AS_PATH has
    /// `remote_as` rewritten to `local_as` before the prepend, so two
    /// peers may only share canonical bytes when they override the
    /// *same* remote AS. Without this, two eBGP peers with distinct
    /// remote-AS in one group would share a single (wrongly-overridden)
    /// AS_PATH — the canonical-member transform assumes its output
    /// depends only on signature fields.
    pub as_override_target: Option<u32>,
    /// Per-neighbor `remove-private-as` key (eBGP only). `None` when off
    /// (the common case). See [`RemovePrivateAsKey`] for why the mode
    /// and the kept AS must shard the group.
    pub remove_private_as: Option<RemovePrivateAsKey>,
    /// Per-neighbor `local-as` substitute active on the session (eBGP
    /// only; `None` when off or while the dual-as fallback presents
    /// the global AS). The egress prepend becomes `substitute, real`
    /// — or just `substitute` with `replace_as` — so peers under a
    /// different substitute (or none) cannot share canonical UPDATE
    /// bytes. `(substitute, replace_as)`.
    pub local_as_substitute: Option<(u32, bool)>,
    // Negotiated wire-format capabilities (intersection of cap_send
    // and cap_recv on the peer). Anything that changes encoded
    // UPDATE bytes belongs here.
    pub as4_negotiated: bool,
    pub extended_message: bool,
    pub addpath_send: bool,
    pub extended_next_hop: bool,
    pub multiple_labels: bool,
    /// Bound egress (Adj-RIB-Out) Lua script identity for this family, or
    /// `None`. A bound egress script is an arbitrary black-box attribute
    /// transform, so it cannot ride the canonical-member "encode once,
    /// replicate" path safely. [`EgressScriptKey`] includes a peer-unique
    /// key, so a scripted peer lands in its OWN singleton update-group and
    /// the transform runs per-peer with full peer context (the egress
    /// design note's Model B). The `generation` makes a script hot-reload
    /// bump the signature → regroup + re-encode.
    pub egress_script: Option<EgressScriptKey>,
    /// Debug/test knob: a synthetic unrecognized attribute attached on
    /// egress (zebra-bgp-unknown-attr.yang). It changes the encoded
    /// UPDATE bytes for this peer, so two peers attaching different
    /// attributes (or only one attaching) must not share canonical
    /// bytes — fold it into the key. `None` when off (the common case).
    pub attach_unknown_attr: Option<UnknownAttr>,
    pub signature_version: u32,
}

/// Identity of a per-peer egress Lua script in [`UpdateGroupSig`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EgressScriptKey {
    /// Bound script name.
    pub name: String,
    /// Script-registry generation (a hot-reload bumps it).
    pub generation: u64,
    /// Peer address — makes the signature unique per peer (singleton
    /// group), so the black-box transform never replicates one peer's
    /// bytes to another.
    pub peer: IpAddr,
}

#[derive(Debug, Default, Clone)]
pub struct UpdateGroupCounters {
    pub policy_runs: u64,
    pub policy_denials: u64,
    pub messages_formatted: u64,
    pub messages_replicated: u64,
    pub bytes_formatted: u64,
    pub split_horizon_excluded: u64,
    /// Member sends skipped because the bucket carried LLGR_STALE and
    /// the member never advertised the LLGR capability (RFC 9494 §4.3).
    pub llgr_excluded: u64,
    pub last_format_us: Option<u64>,
    pub last_replicate_us: Option<u64>,
}

impl UpdateGroupCounters {
    /// Fold a [`FlushJob`]'s counter deltas into the group's live
    /// counters. Additive fields accumulate; the timing fields
    /// overwrite when the delta carries a value.
    pub(super) fn merge(&mut self, delta: &UpdateGroupCounters) {
        self.policy_runs += delta.policy_runs;
        self.policy_denials += delta.policy_denials;
        self.messages_formatted += delta.messages_formatted;
        self.messages_replicated += delta.messages_replicated;
        self.bytes_formatted += delta.bytes_formatted;
        self.split_horizon_excluded += delta.split_horizon_excluded;
        self.llgr_excluded += delta.llgr_excluded;
        if delta.last_format_us.is_some() {
            self.last_format_us = delta.last_format_us;
        }
        if delta.last_replicate_us.is_some() {
            self.last_replicate_us = delta.last_replicate_us;
        }
    }
}

/// One update-group: a signature and the peers currently sharing it.
#[derive(Debug)]
pub struct UpdateGroup {
    pub id: UpdateGroupId,
    pub sig: UpdateGroupSig,
    /// Peer idents (PeerMap key) — small, easily cloned, and cheap to
    /// look up against `Bgp::peers` when rendering the show command.
    pub members: BTreeSet<usize>,
    pub created_at: Instant,
    pub counters: UpdateGroupCounters,

    // ── IPv4 unicast pending advertisement cache ──
    //
    // Buckets pending advertisements by attribute so a single
    // MP_REACH UPDATE can carry every NLRI sharing one attr-set.
    // Per (attr → NLRI → source-ident); split-horizon uses the
    // source-ident at flush time to prune NLRIs from the
    // member-peer that originated them.
    pub cache_ipv4: HashMap<Arc<BgpAttr>, HashMap<Ipv4Nlri, usize>>,
    /// Reverse map for O(1) cache_remove. NLRI → bucket key.
    pub cache_ipv4_rev: HashMap<Ipv4Nlri, Arc<BgpAttr>>,
    /// Adv-debounce timer. Started on first send; on fire,
    /// `Bgp::serve` drains the cache and ships UPDATEs to members.
    pub cache_ipv4_timer: Option<Timer>,

    // ── IPv6 unicast pending advertisement cache ──
    //
    // Same shape as the IPv4 cache above. IPv6 unicast has no legacy
    // NLRI field, so every advert is an MP_REACH(AFI=2, SAFI=1); the
    // next-hop rides in the bucket key attr (`BgpNexthop::Ipv6`).
    pub cache_ipv6: HashMap<Arc<BgpAttr>, HashMap<Ipv6Nlri, usize>>,
    pub cache_ipv6_rev: HashMap<Ipv6Nlri, Arc<BgpAttr>>,
    pub cache_ipv6_timer: Option<Timer>,

    /// Snapshot of `Bgp::adv_interval` captured at group creation
    /// (`attach`) and refreshed by the global config callback. Used
    /// by `start_adv_timer_ipv4` to arm the debounce — the
    /// peer-type→seconds lookup happens against this snapshot, not a
    /// hard-coded 5/30.
    pub adv_interval: AdvInterval,

    // ── Flush-offload state (sharding plan Phase A.2) ──
    //
    // One flush job per AFI cache may be on the worker at a time; a
    // second concurrent job could interleave its UPDATEs with the
    // first's on the members' writer channels. A timer that fires
    // mid-flight latches `flush_pending_*`; `flush_done_*` re-runs
    // the flush. Per-peer withdraws that would race the in-flight
    // announces are parked in `deferred_withdraw_*` and replayed by
    // `flush_done_*` after every job byte is enqueued.
    /// An IPv4 flush job is running on the blocking pool.
    pub flush_inflight_ipv4: bool,
    /// The IPv4 debounce timer fired while a job was in flight.
    pub flush_pending_ipv4: bool,
    /// `(ident, nlri)` withdraws parked during an IPv4 flight.
    pub deferred_withdraw_ipv4: Vec<(usize, Ipv4Nlri)>,
    /// IPv6 twins of the three fields above.
    pub flush_inflight_ipv6: bool,
    pub flush_pending_ipv6: bool,
    pub deferred_withdraw_ipv6: Vec<(usize, Ipv6Nlri)>,
    /// Per-update-group egress task (see
    /// `docs/design/bgp-egress-group-task-migration.md`). `Some` only at
    /// gate-on (`ZEBRA_BGP_EGRESS_GROUP_TASK`); spawned when the group is
    /// created, dropped (abort-on-drop) when it empties. For now it is idle —
    /// it tracks the member set and routes no egress yet.
    pub task: Option<super::group_egress::GroupEgressTask>,
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

    /// Shared-reference twin of [`group_by_id_mut`](Self::group_by_id_mut).
    pub fn group_by_id(&self, id: &UpdateGroupId) -> Option<&UpdateGroup> {
        self.groups.values().find(|g| &g.id == id)
    }
}

/// Top-level container on `Bgp`.
pub type UpdateGroupMap = BTreeMap<AfiSafi, UpdateGroupAf>;

pub fn empty_map() -> UpdateGroupMap {
    BTreeMap::new()
}

/// IOS-XR-style IDs ("ipv4-unicast.0", "ipv6-unicast.0", …) of every
/// live update-group across all AFI/SAFIs. Backs the `bgp:update-group`
/// dynamic completion (`show bgp update-group <id>`) and matches the IDs
/// `show bgp update-group` renders. Iteration order follows the
/// `BTreeMap` keys: AFI/SAFI, then signature.
pub fn id_comps(update_groups: &UpdateGroupMap) -> Vec<String> {
    update_groups
        .values()
        .flat_map(|af| af.groups.values())
        .map(|group| group.id.to_string())
        .collect()
}

/// Compute the signature for `peer` in `(afi, safi)`. Returns `None`
/// if the peer is not active in this AFI/SAFI (capability not
/// negotiated by both sides). Established-state is **not** checked
/// here — caller (attach/detach hook) is responsible.
pub fn signature_of(peer: &Peer, afi: Afi, safi: Safi) -> Option<UpdateGroupSig> {
    if !peer.is_afi_safi(afi, safi) {
        return None;
    }

    // The update-group is per-(afi,safi), so its egress policy is that
    // family's effective outbound binding (per-AFI override, else the
    // legacy peer-wide fallback).
    let afi_safi = AfiSafi::new(afi, safi);
    let policy_out_name = peer.policy_list_at(afi_safi, InOut::Output).name.clone();
    let prefix_set_out_name = peer.prefix_set_at(afi_safi, InOut::Output).name.clone();

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
        // as-override rewrites the peer's own AS to ours on egress; the
        // result depends on the peer's remote-as, so fold it into the
        // key (eBGP only — iBGP never prepends, so the override is a
        // no-op there and must not split iBGP groups).
        as_override_target: if peer.is_ebgp() && peer.config.as_override {
            Some(peer.remote_as)
        } else {
            None
        },
        // remove-private-as strips/rewrites the egress AS_PATH; its
        // result depends on the mode and on the kept AS (this peer's
        // remote-as), so fold both into the key (eBGP only — iBGP never
        // prepends, so the strip is a no-op and must not split groups).
        remove_private_as: if peer.is_ebgp() {
            peer.config.remove_private_as.map(|rpa| RemovePrivateAsKey {
                all: rpa.all,
                replace_as: rpa.replace_as,
                keep_as: peer.remote_as,
            })
        } else {
            None
        },
        // local-as changes what the egress prepend writes; fold the
        // active substitute and the replace-as modifier into the key
        // (eBGP only — iBGP never prepends, so the substitute is a
        // no-op there and must not split iBGP groups).
        local_as_substitute: if peer.is_ebgp() {
            peer.change_local_as()
                .map(|asn| (asn, peer.config.local_as.is_some_and(|la| la.replace_as)))
        } else {
            None
        },
        as4_negotiated: peer.as4,
        extended_message: peer.opt.extended_message,
        addpath_send: peer.opt.is_add_path_send(afi, safi),
        // RFC 8950 Extended Next Hop Encoding for IPv4 unicast over
        // IPv6 next-hop is negotiated when both directions advertise
        // the matching tuple. Only meaningful for the IPv4-unicast
        // update-group; other AFI/SAFI groups stay at false until
        // the codec / wire format extends.
        extended_next_hop: enhe_negotiated(peer, afi, safi),
        // RFC 8277 multiple-labels is still not negotiated by zebra-rs;
        // the field is forward-compatible for the day it lands.
        multiple_labels: false,
        egress_script: egress_script_key(peer, afi, safi),
        // The egress attach knob (debug/test) stamps an extra attribute
        // onto every advertised route, so peers with different attach
        // specs encode different bytes and must shard the group.
        attach_unknown_attr: peer.config.attach_unknown_attr.clone(),
        signature_version: SIGNATURE_VERSION,
    })
}

/// The bound egress Lua script for `(afi, safi)`, keyed per peer so a
/// scripted peer becomes its own singleton update-group (Model B). `None`
/// when no egress script is bound for the family (the common case — no
/// effect on grouping). Always compiled; the bindings are empty without
/// the `lua` feature.
fn egress_script_key(peer: &Peer, afi: Afi, safi: Safi) -> Option<EgressScriptKey> {
    let name = match (afi, safi) {
        (Afi::Ip, Safi::Unicast) => crate::script::egress_binding_v4(),
        (Afi::L2vpn, Safi::Evpn) => crate::script::egress_binding_evpn(),
        _ => None,
    }?;
    Some(EgressScriptKey {
        name,
        generation: crate::script::generation(),
        peer: peer.address,
    })
}

/// True iff both sides advertised the ENHE capability with an entry
/// for (IPv4-Unicast, IPv6 next-hop), and the local update-group's
/// AFI/SAFI is IPv4 unicast. The check is symmetric — a one-sided
/// advertisement is treated as "not negotiated" per RFC 8950 §3.
fn enhe_negotiated(peer: &Peer, afi: Afi, safi: Safi) -> bool {
    enhe_negotiated_for(
        peer.cap_send.extended_nexthop.as_ref(),
        peer.cap_recv.extended_nexthop.as_ref(),
        afi,
        safi,
    )
}

fn enhe_negotiated_for(
    send: Option<&CapExtendedNextHop>,
    recv: Option<&CapExtendedNextHop>,
    afi: Afi,
    safi: Safi,
) -> bool {
    if afi != Afi::Ip || safi != Safi::Unicast {
        return false;
    }
    let sent = send.is_some_and(|c| c.supports_v6_nexthop_for_ipv4_unicast());
    let received = recv.is_some_and(|c| c.supports_v6_nexthop_for_ipv4_unicast());
    sent && received
}

/// Add `peer_idx` to its update-group for every tracked AFI/SAFI it
/// participates in. Idempotent — calling twice on an already-attached
/// peer is a no-op.
///
/// Takes split borrows on `update_groups` and `peers` so the caller
/// can be the FSM (which holds a `BgpTop` separately from the
/// `PeerMap`).
pub fn attach(
    update_groups: &mut UpdateGroupMap,
    peers: &mut PeerMap,
    peer_idx: usize,
    router_id: Ipv4Addr,
    as_sets_withdraw: bool,
) {
    let Some(peer) = peers.get_by_idx(peer_idx) else {
        return;
    };

    // Snapshot signatures so we can mutate update_groups + peer
    // without overlapping borrows. The adv_interval snapshot rides
    // along onto every freshly-created group so the IPv4 adv-timer
    // can read its cadence without reaching back into `Bgp`.
    let adv_interval = peer.adv_interval;
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
            // Spawn the per-group egress task at gate-on for
            // v4-unicast (the family being migrated); dropped (abort-on-drop)
            // when this group is removed in `detach`.
            let task = (afi_safi.afi == Afi::Ip
                && afi_safi.safi == Safi::Unicast
                && super::group_egress::egress_group_task_enabled())
            .then(|| super::group_egress::GroupEgressTask::spawn(id.clone()));
            UpdateGroup {
                id,
                sig: sig.clone(),
                members: BTreeSet::new(),
                created_at: Instant::now(),
                counters: UpdateGroupCounters::default(),
                cache_ipv4: HashMap::new(),
                cache_ipv4_rev: HashMap::new(),
                cache_ipv4_timer: None,
                cache_ipv6: HashMap::new(),
                cache_ipv6_rev: HashMap::new(),
                cache_ipv6_timer: None,
                adv_interval,
                flush_inflight_ipv4: false,
                flush_pending_ipv4: false,
                deferred_withdraw_ipv4: Vec::new(),
                flush_inflight_ipv6: false,
                flush_pending_ipv6: false,
                deferred_withdraw_ipv6: Vec::new(),
                task,
            }
        });
        entry.members.insert(peer_idx);
        // Mirror the membership into the group's egress task with the
        // member's SyncCtx (its packet sink + the shared egress identity) so the
        // engine can build + fan once advertises are routed there (later).
        if let Some(t) = &entry.task
            && let Some(peer) = peers.get_by_idx(peer_idx)
        {
            let add_path = peer.opt.is_add_path_send(afi_safi.afi, afi_safi.safi);
            t.send(super::group_egress::GroupEgressDeltaV4::AddMember {
                ident: peer_idx,
                ctx: Box::new(peer.sync_ctx(router_id, as_sets_withdraw)),
                add_path,
            });
        }

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
                // Mirror the removal into the group's egress task (the task
                // itself is dropped + aborted below if the group empties).
                if let Some(t) = &group.task {
                    t.send(super::group_egress::GroupEgressDeltaV4::RemoveMember {
                        ident: peer_idx,
                    });
                }
                group.members.is_empty()
            };
            if drop_group {
                af.groups.remove(&key);
            }
        }
    }
}

// ── IPv4 unicast send / cache_remove / flush ──
//
// Owns the per-attr-bucket batching that used to live on `Peer`
// (cache_ipv4 + cache_ipv4_rev + cache_ipv4_timer). Moving the
// state here lets one encoded UPDATE serve every non-source
// member of a group, with per-member split-horizon pruning at
// flush time. Per-peer paths that target a single peer
// (`route_sync_ipv4`, `route_soft_out_peer_table`) bypass the
// group cache via `send_ipv4_direct` — encoding stays per-attr-
// batched without fanning out to the whole group.

/// Bucket the (nlri, attr, source_ident) into the group's IPv4
/// pending-advert cache. Also kicks the adv-debounce timer if not
/// already running. The `tx` channel is the global Bgp tx (every
/// peer carries a clone of it); on fire it delivers
/// `Message::FlushUpdateGroupIpv4` back to `Bgp::serve`.
pub fn send_ipv4(
    group: &mut UpdateGroup,
    nlri: Ipv4Nlri,
    attr: Arc<BgpAttr>,
    source_ident: usize,
    tx: &mpsc::Sender<Message>,
    kick_timer: bool,
) {
    group
        .cache_ipv4
        .entry(attr.clone())
        .or_default()
        .insert(nlri.clone(), source_ident);
    group.cache_ipv4_rev.insert(nlri, attr);
    if kick_timer && group.cache_ipv4_timer.is_none() {
        let secs = group.adv_interval.secs_for(group.sig.peer_type);
        group.cache_ipv4_timer = Some(start_adv_timer_ipv4(tx, &group.id, secs));
    }
}

/// Remove an NLRI from the group's IPv4 pending-advert cache. The
/// flush timer keeps running; an empty bucket is dropped.
/// Idempotent — calling on an absent NLRI is a no-op.
///
/// `id` is the AddPath path-id (zero for non-AddPath). Bucket entries
/// are keyed by the full `Ipv4Nlri`, so AddPath and non-AddPath
/// withdrawals must pass distinct ids when both modes are mixed.
pub fn cache_remove_ipv4(group: &mut UpdateGroup, prefix: ipnet::Ipv4Net, id: u32) {
    let nlri = Ipv4Nlri { id, prefix };
    if let Some(attr) = group.cache_ipv4_rev.remove(&nlri)
        && let Some(bucket) = group.cache_ipv4.get_mut(&attr)
    {
        bucket.remove(&nlri);
        if bucket.is_empty() {
            group.cache_ipv4.remove(&attr);
        }
    }
}

fn start_adv_timer_ipv4(tx: &mpsc::Sender<Message>, id: &UpdateGroupId, secs: u64) -> Timer {
    let tx = tx.clone();
    let id = id.clone();
    Timer::once(secs, move || {
        let tx = tx.clone();
        let id = id.clone();
        async move {
            let _ = tx.send(Message::FlushUpdateGroupIpv4(id)).await;
        }
    })
}

/// One member's send context, snapshotted out of `PeerMap` while
/// building a [`FlushJob`]. Detached from peer state so the job can
/// run without borrowing the instance (and, in Phase A.2 of the
/// sharding plan, off the main task entirely).
pub(super) struct FlushMember {
    pub ident: usize,
    pub tx: Option<mpsc::UnboundedSender<bytes::BytesMut>>,
    /// RFC 8950 per-member v6 next-hop. `Some` only on IPv4-unicast
    /// jobs whose group negotiated ENHE — the next-hop derives from
    /// each peer's egress ifindex (`scope_id`), so it varies per
    /// member even within one update-group and forces per-member
    /// encoding; the canonical-bytes sharing cannot apply.
    pub enhe_v6: Option<Ipv4MpReachNextHop>,
    /// Member advertised the LLGR capability for this AFI/SAFI —
    /// only such members may receive LLGR_STALE-tagged buckets
    /// (RFC 9494 §4.3). Per-peer state, hence resolved here and
    /// not part of the group signature.
    pub llgr_ok: bool,
}

/// NLRI families a [`FlushJob`] can encode. `enhe_v6` carries the
/// RFC 8950 per-member next-hop and is meaningful only for IPv4;
/// the IPv6 impl ignores it (v6 unicast next-hops are native and
/// ride on the bucket-key attr).
pub(super) trait FlushNlri: Clone {
    fn encode(
        attr: &Arc<BgpAttr>,
        nlris: &[Self],
        max_packet_size: usize,
        enhe_v6: Option<Ipv4MpReachNextHop>,
    ) -> Vec<bytes::BytesMut>;
}

impl FlushNlri for Ipv4Nlri {
    fn encode(
        attr: &Arc<BgpAttr>,
        nlris: &[Self],
        max_packet_size: usize,
        enhe_v6: Option<Ipv4MpReachNextHop>,
    ) -> Vec<bytes::BytesMut> {
        encode_ipv4_update(attr, nlris, max_packet_size, enhe_v6)
    }
}

impl FlushNlri for Ipv6Nlri {
    fn encode(
        attr: &Arc<BgpAttr>,
        nlris: &[Self],
        max_packet_size: usize,
        _enhe_v6: Option<Ipv4MpReachNextHop>,
    ) -> Vec<bytes::BytesMut> {
        encode_ipv6_update(attr, nlris, max_packet_size)
    }
}

/// Everything one update-group flush needs, snapshotted away from
/// instance state: the drained attr buckets, the member send
/// contexts, and the sig-derived encode parameters. [`Self::run`] is
/// self-contained — it borrows nothing from `Bgp` — so the flush can
/// execute inline today and on a worker in Phase A.2 of the sharding
/// plan (`docs/design/bgp-rib-sharding-plan.md`).
pub(super) struct FlushJob<N> {
    /// Bucket shape is `(attr, [(nlri, source_ident)])`.
    pub buckets: Vec<(Arc<BgpAttr>, Vec<(N, usize)>)>,
    pub members: Vec<FlushMember>,
    pub max_packet_size: usize,
    /// Group negotiated RFC 8950 ENHE (IPv4 unicast only): every
    /// bucket is encoded per-member with that member's v6 next-hop.
    pub enhe: bool,
}

impl<N: FlushNlri> FlushJob<N> {
    /// Encode and send every bucket; returns the counter deltas for
    /// the caller to merge into the group. Per attr-bucket we encode
    /// at most:
    /// - one **canonical** UPDATE containing every NLRI in the bucket
    ///   (sent to members whose ident does not appear as a
    ///   source-ident in the bucket — split-horizon clean for them);
    /// - one **pruned** UPDATE per source-member, with that member's
    ///   sourced NLRIs removed;
    /// - under ENHE, one UPDATE per member (per-member next-hop).
    ///
    /// `messages_formatted` increments per encoded variant;
    /// `messages_replicated` per (UPDATE, member) pair sent;
    /// `bytes_formatted` accumulates the encoded byte counts.
    pub fn run(self) -> UpdateGroupCounters {
        let mut counters = UpdateGroupCounters::default();
        for (attr, entries) in self.buckets {
            // Members that need split-horizon pruning: any whose
            // ident appears as a source-ident in this bucket. Common
            // case is empty (group has no source-members for this
            // bucket), in which case every member shares the
            // canonical UPDATE.
            let source_idents: BTreeSet<usize> = entries.iter().map(|(_, src)| *src).collect();
            let pruned_members: Vec<usize> = self
                .members
                .iter()
                .map(|m| m.ident)
                .filter(|m| source_idents.contains(m))
                .collect();

            // RFC 9494 §4.3: an LLGR_STALE-tagged bucket reaches only
            // the members that advertised the LLGR capability. The
            // advertise path gates per-peer too, but the cache fans
            // out per-GROUP, so a bucket enqueued for capable members
            // must be filtered here for the rest.
            let llgr_stale_bucket = super::route::attr_has_llgr_stale(&attr);

            if self.enhe {
                // Per-member encode: each member's v6 next-hop is its
                // own interface link-local; canonical-bytes sharing
                // across members would force every member onto the
                // same LL, which would break ENHE for everyone but
                // one peer.
                for ctx in &self.members {
                    if llgr_stale_bucket && !ctx.llgr_ok {
                        counters.llgr_excluded += 1;
                        continue;
                    }
                    let Some(tx) = ctx.tx.as_ref() else { continue };
                    let Some(nh) = ctx.enhe_v6 else {
                        // ND hasn't observed any link-local on this
                        // peer's egress interface yet; the
                        // operator-side address-add events haven't
                        // reached BGP. Skip this member's flush —
                        // we'll re-cache on the next event arrival
                        // rather than emit a garbage next-hop.
                        continue;
                    };
                    let nlris: Vec<N> = entries
                        .iter()
                        .filter(|(_, src)| *src != ctx.ident)
                        .map(|(n, _)| n.clone())
                        .collect();
                    if nlris.is_empty() {
                        if pruned_members.contains(&ctx.ident) {
                            counters.split_horizon_excluded += 1;
                        }
                        continue;
                    }
                    let bytes_list = N::encode(&attr, &nlris, self.max_packet_size, Some(nh));
                    let byte_total: usize = bytes_list.iter().map(|b| b.len()).sum();
                    for bytes in &bytes_list {
                        let _ = tx.send(bytes.clone());
                    }
                    counters.messages_formatted += bytes_list.len() as u64;
                    counters.messages_replicated += bytes_list.len() as u64;
                    counters.bytes_formatted += byte_total as u64;
                    if pruned_members.contains(&ctx.ident) {
                        counters.split_horizon_excluded += 1;
                    }
                }
                continue;
            }

            // Canonical UPDATE: every NLRI in the bucket.
            let canonical: Vec<N> = entries.iter().map(|(n, _)| n.clone()).collect();
            let canonical_bytes = N::encode(&attr, &canonical, self.max_packet_size, None);
            let canonical_byte_total: usize = canonical_bytes.iter().map(|b| b.len()).sum();

            // Bump per-attr-bucket counters: one formatted variant
            // (canonical), bytes summed.
            counters.messages_formatted += canonical_bytes.len() as u64;
            counters.bytes_formatted += canonical_byte_total as u64;

            // Send canonical to every non-pruned member.
            for ctx in &self.members {
                if pruned_members.contains(&ctx.ident) {
                    continue;
                }
                if llgr_stale_bucket && !ctx.llgr_ok {
                    counters.llgr_excluded += 1;
                    continue;
                }
                if let Some(tx) = ctx.tx.as_ref() {
                    for bytes in &canonical_bytes {
                        let _ = tx.send(bytes.clone());
                    }
                    counters.messages_replicated += canonical_bytes.len() as u64;
                }
            }

            // Per pruned member: encode bucket minus its sourced
            // NLRIs, then send.
            for prune_ident in pruned_members {
                if llgr_stale_bucket
                    && !self
                        .members
                        .iter()
                        .find(|c| c.ident == prune_ident)
                        .is_some_and(|c| c.llgr_ok)
                {
                    counters.llgr_excluded += 1;
                    continue;
                }
                let nlris: Vec<N> = entries
                    .iter()
                    .filter(|(_, src)| *src != prune_ident)
                    .map(|(n, _)| n.clone())
                    .collect();
                if nlris.is_empty() {
                    counters.split_horizon_excluded += 1;
                    continue;
                }
                let pruned_bytes = N::encode(&attr, &nlris, self.max_packet_size, None);
                let pruned_byte_total: usize = pruned_bytes.iter().map(|b| b.len()).sum();
                counters.messages_formatted += pruned_bytes.len() as u64;
                counters.bytes_formatted += pruned_byte_total as u64;
                counters.split_horizon_excluded += 1;
                if let Some(tx) = self
                    .members
                    .iter()
                    .find(|c| c.ident == prune_ident)
                    .and_then(|c| c.tx.as_ref())
                {
                    for bytes in &pruned_bytes {
                        let _ = tx.send(bytes.clone());
                    }
                    counters.messages_replicated += pruned_bytes.len() as u64;
                }
            }
        }
        counters
    }
}

/// Drain the group's IPv4 pending cache into a [`FlushJob`]: clears
/// the debounce timer slot (the next `send_ipv4` re-arms it), drains
/// both forward and reverse maps, and snapshots member send contexts
/// — packet_tx clones, per-member ENHE next-hops, LLGR capability —
/// so the job needs no peer borrow. `None` when there is nothing to
/// flush.
pub(super) fn build_flush_job_ipv4(
    group: &mut UpdateGroup,
    peers: &PeerMap,
    interface_addrs: &super::interface_addrs::InterfaceAddrs,
) -> Option<FlushJob<Ipv4Nlri>> {
    let afi_safi = AfiSafi::new(Afi::Ip, Safi::Unicast);
    group.cache_ipv4_timer = None;
    let buckets: Vec<(Arc<BgpAttr>, Vec<(Ipv4Nlri, usize)>)> = group
        .cache_ipv4
        .drain()
        .map(|(attr, set)| (attr, set.into_iter().collect()))
        .collect();
    group.cache_ipv4_rev.clear();
    if buckets.is_empty() {
        return None;
    }
    let max_packet_size = if group.sig.extended_message {
        bgp_packet::BGP_EXTENDED_PACKET_LEN
    } else {
        bgp_packet::BGP_PACKET_LEN
    };
    let enhe = group.sig.extended_next_hop;
    let members: Vec<FlushMember> = group
        .members
        .iter()
        .map(|ident| {
            let peer = peers.get_by_idx(*ident);
            FlushMember {
                ident: *ident,
                tx: peer.and_then(|p| p.packet_tx.clone()),
                enhe_v6: if enhe {
                    peer.and_then(|p| compose_enhe_next_hop(p, interface_addrs))
                } else {
                    None
                },
                llgr_ok: peer.is_some_and(|p| p.cap_recv.llgr.contains_key(&afi_safi)),
            }
        })
        .collect();
    Some(FlushJob {
        buckets,
        members,
        max_packet_size,
        enhe,
    })
}

/// Flush the IPv4 cache: drain it into a [`FlushJob`] and run the
/// encode + send on the blocking pool (sharding plan Phase A.2).
/// Called from `Bgp::serve` on `Message::FlushUpdateGroupIpv4`.
///
/// At most one job per group is in flight: a timer that fires while
/// one is running latches `flush_pending_ipv4` instead (a second
/// concurrent job could interleave its UPDATEs with the first's on
/// the members' writer channels), and [`flush_done_ipv4`] re-runs
/// the flush when the worker reports back.
pub fn flush_ipv4(
    update_groups: &mut UpdateGroupMap,
    peers: &mut PeerMap,
    tx: &mpsc::Sender<Message>,
    id: &UpdateGroupId,
    interface_addrs: &super::interface_addrs::InterfaceAddrs,
) {
    let afi_safi = AfiSafi::new(Afi::Ip, Safi::Unicast);
    let Some(af) = update_groups.get_mut(&afi_safi) else {
        return;
    };
    let Some(group) = af.group_by_id_mut(id) else {
        return;
    };
    if group.flush_inflight_ipv4 {
        group.flush_pending_ipv4 = true;
        return;
    }
    let Some(job) = build_flush_job_ipv4(group, peers, interface_addrs) else {
        return;
    };
    group.flush_inflight_ipv4 = true;
    let tx = tx.clone();
    let id = id.clone();
    let _ = tokio::task::spawn_blocking(move || {
        let deltas = job.run();
        // blocking_send is correct here — this runs on a blocking-pool
        // thread, not in async context. Failure means the BGP instance
        // is shutting down; the deltas die with it.
        let _ = tx.blocking_send(Message::FlushDoneIpv4(id, deltas));
    });
}

/// Worker completion for an IPv4 flush: merge the counter deltas,
/// release the in-flight latch, replay the withdraws parked during
/// the flight, and re-run the flush if the debounce timer fired
/// while the job was out.
///
/// The replay is ordered-safe by construction: the worker sends
/// `FlushDoneIpv4` only after [`FlushJob::run`] returned, so every
/// announce byte is already on the members' writer channels and a
/// replayed withdraw lands strictly after the announce it must
/// override.
pub fn flush_done_ipv4(
    update_groups: &mut UpdateGroupMap,
    peers: &mut PeerMap,
    tx: &mpsc::Sender<Message>,
    id: &UpdateGroupId,
    deltas: UpdateGroupCounters,
    interface_addrs: &super::interface_addrs::InterfaceAddrs,
) {
    let afi_safi = AfiSafi::new(Afi::Ip, Safi::Unicast);
    let Some(af) = update_groups.get_mut(&afi_safi) else {
        return;
    };
    let Some(group) = af.group_by_id_mut(id) else {
        return;
    };
    group.counters.merge(&deltas);
    group.flush_inflight_ipv4 = false;
    let deferred = std::mem::take(&mut group.deferred_withdraw_ipv4);
    let rerun = std::mem::take(&mut group.flush_pending_ipv4);
    let members = group.members.clone();
    for (ident, nlri) in deferred {
        // Skip members that left the group during the flight (a
        // session bounce re-syncs the table from scratch) and peers
        // whose Adj-RIB-Out re-acquired the prefix (a newer announce
        // superseded this withdraw; it is sitting in the pending
        // cache and the next flush carries it).
        if !members.contains(&ident) {
            continue;
        }
        let Some(peer) = peers.get_mut_by_idx(ident) else {
            continue;
        };
        if !peer.state.is_established() {
            continue;
        }
        if nlri.id == 0 && peer.adj_out.contains_key(None, &nlri.prefix) {
            continue;
        }
        super::route::route_withdraw_ipv4(peer, None, nlri.prefix, nlri.id);
    }
    if rerun {
        flush_ipv4(update_groups, peers, tx, id, interface_addrs);
    }
}

/// Per-peer batched encode + send. Used by the route_sync_ipv4 and
/// route_soft_out_peer_table paths that target a SINGLE peer — the
/// group cache would fan-out to every member, so those callers
/// bypass it and use this direct path instead.
///
/// Builds local per-attr buckets, encodes once per bucket via
/// `encode_ipv4_update`, and ships every UPDATE byte buffer to the
/// peer's `packet_tx`. Per-attr clustering preserves the wire-level
/// efficiency the cache provided (one MP_REACH UPDATE per shared
/// attr-set rather than one per NLRI).
///
/// `extended_next_hop_v6` is the IPv6 next-hop to emit in MP_REACH
/// for RFC 8950 IPv4-over-IPv6; `None` keeps the legacy
/// `pop_ipv4` / inline-NLRI emit. Callers compute this via
/// [`compose_enhe_next_hop`] which picks the 32-octet dual form when
/// the egress interface also has a global v6, else the 16-octet
/// link-local-only form.
pub(super) fn send_ipv4_direct(
    ctx: &super::route::SyncCtx,
    entries: Vec<(Arc<BgpAttr>, Ipv4Nlri)>,
    extended_next_hop_v6: Option<Ipv4MpReachNextHop>,
) {
    if entries.is_empty() {
        return;
    }
    let mut buckets: HashMap<Arc<BgpAttr>, Vec<Ipv4Nlri>> = HashMap::new();
    for (attr, nlri) in entries {
        buckets.entry(attr).or_default().push(nlri);
    }
    let max_packet_size = ctx.max_packet_size();
    for (attr, nlris) in buckets {
        let bytes_list = encode_ipv4_update(&attr, &nlris, max_packet_size, extended_next_hop_v6);
        for buf in bytes_list {
            ctx.send_packet(buf);
        }
    }
}

/// Encode one or more UPDATE PDUs carrying `nlris` under `attr`.
///
/// When `extended_next_hop_v6` is `Some(...)`, NLRIs are emitted via
/// `UpdatePacket::pop_ipv4_mp_reach` — MP_REACH(AFI=1, SAFI=1) with
/// an IPv6 next-hop, per RFC 8950. The `Ipv4MpReachNextHop` variant
/// selects the 16-octet link-local-only form or the 32-octet
/// `global || link-local` form. `None` keeps the legacy `pop_ipv4`
/// path (NLRI inline, NEXT_HOP attribute carries the v4 next-hop).
pub(super) fn encode_ipv4_update(
    attr: &Arc<BgpAttr>,
    nlris: &[Ipv4Nlri],
    max_packet_size: usize,
    extended_next_hop_v6: Option<Ipv4MpReachNextHop>,
) -> Vec<bytes::BytesMut> {
    let mut update = UpdatePacket::with_max_packet_size(max_packet_size);
    update.bgp_attr = Some((**attr).clone());
    update.ipv4_update = nlris.to_vec();
    let mut out = Vec::new();
    match extended_next_hop_v6 {
        Some(nh) => {
            while let Some(bytes) = update.pop_ipv4_mp_reach(nh) {
                out.push(bytes);
            }
        }
        None => {
            while let Some(bytes) = update.pop_ipv4() {
                out.push(bytes);
            }
        }
    }
    out
}

// ── IPv6 unicast send / cache_remove / flush ──
//
// Mirror of the IPv4 block above. IPv6 unicast has no legacy NLRI
// field, so the encode path is always MP_REACH(AFI=2, SAFI=1) and
// there is no RFC 8950 ENHE special-case — the next-hop is a native
// v6 address carried on the bucket-key attr.

/// Bucket the `(nlri, attr, source_ident)` into the group's IPv6
/// pending-advert cache, kicking the debounce timer if idle.
pub fn send_ipv6(
    group: &mut UpdateGroup,
    nlri: Ipv6Nlri,
    attr: Arc<BgpAttr>,
    source_ident: usize,
    tx: &mpsc::Sender<Message>,
    kick_timer: bool,
) {
    group
        .cache_ipv6
        .entry(attr.clone())
        .or_default()
        .insert(nlri.clone(), source_ident);
    group.cache_ipv6_rev.insert(nlri, attr);
    if kick_timer && group.cache_ipv6_timer.is_none() {
        let secs = group.adv_interval.secs_for(group.sig.peer_type);
        group.cache_ipv6_timer = Some(start_adv_timer_ipv6(tx, &group.id, secs));
    }
}

/// Remove an NLRI from the group's IPv6 pending-advert cache.
/// Idempotent; the flush timer keeps running.
pub fn cache_remove_ipv6(group: &mut UpdateGroup, prefix: ipnet::Ipv6Net, id: u32) {
    let nlri = Ipv6Nlri { id, prefix };
    if let Some(attr) = group.cache_ipv6_rev.remove(&nlri)
        && let Some(bucket) = group.cache_ipv6.get_mut(&attr)
    {
        bucket.remove(&nlri);
        if bucket.is_empty() {
            group.cache_ipv6.remove(&attr);
        }
    }
}

fn start_adv_timer_ipv6(tx: &mpsc::Sender<Message>, id: &UpdateGroupId, secs: u64) -> Timer {
    let tx = tx.clone();
    let id = id.clone();
    Timer::once(secs, move || {
        let tx = tx.clone();
        let id = id.clone();
        async move {
            let _ = tx.send(Message::FlushUpdateGroupIpv6(id)).await;
        }
    })
}

/// IPv6 counterpart of [`build_flush_job_ipv4`]. No ENHE step — v6
/// unicast next-hops are native and ride on the bucket-key attr — so
/// `enhe` is always false and members carry no per-member next-hop.
pub(super) fn build_flush_job_ipv6(
    group: &mut UpdateGroup,
    peers: &PeerMap,
) -> Option<FlushJob<Ipv6Nlri>> {
    let afi_safi = AfiSafi::new(Afi::Ip6, Safi::Unicast);
    group.cache_ipv6_timer = None;
    let buckets: Vec<(Arc<BgpAttr>, Vec<(Ipv6Nlri, usize)>)> = group
        .cache_ipv6
        .drain()
        .map(|(attr, set)| (attr, set.into_iter().collect()))
        .collect();
    group.cache_ipv6_rev.clear();
    if buckets.is_empty() {
        return None;
    }
    let max_packet_size = if group.sig.extended_message {
        bgp_packet::BGP_EXTENDED_PACKET_LEN
    } else {
        bgp_packet::BGP_PACKET_LEN
    };
    let members: Vec<FlushMember> = group
        .members
        .iter()
        .map(|ident| {
            let peer = peers.get_by_idx(*ident);
            FlushMember {
                ident: *ident,
                tx: peer.and_then(|p| p.packet_tx.clone()),
                enhe_v6: None,
                llgr_ok: peer.is_some_and(|p| p.cap_recv.llgr.contains_key(&afi_safi)),
            }
        })
        .collect();
    Some(FlushJob {
        buckets,
        members,
        max_packet_size,
        enhe: false,
    })
}

/// Flush the IPv6 cache on the blocking pool — the v6 twin of
/// [`flush_ipv4`], same single-flight latch, minus the ENHE step.
pub fn flush_ipv6(
    update_groups: &mut UpdateGroupMap,
    peers: &mut PeerMap,
    tx: &mpsc::Sender<Message>,
    id: &UpdateGroupId,
) {
    let afi_safi = AfiSafi::new(Afi::Ip6, Safi::Unicast);
    let Some(af) = update_groups.get_mut(&afi_safi) else {
        return;
    };
    let Some(group) = af.group_by_id_mut(id) else {
        return;
    };
    if group.flush_inflight_ipv6 {
        group.flush_pending_ipv6 = true;
        return;
    }
    let Some(job) = build_flush_job_ipv6(group, peers) else {
        return;
    };
    group.flush_inflight_ipv6 = true;
    let tx = tx.clone();
    let id = id.clone();
    let _ = tokio::task::spawn_blocking(move || {
        let deltas = job.run();
        let _ = tx.blocking_send(Message::FlushDoneIpv6(id, deltas));
    });
}

/// Worker completion for an IPv6 flush — the v6 twin of
/// [`flush_done_ipv4`]; see there for the ordering argument.
pub fn flush_done_ipv6(
    update_groups: &mut UpdateGroupMap,
    peers: &mut PeerMap,
    tx: &mpsc::Sender<Message>,
    id: &UpdateGroupId,
    deltas: UpdateGroupCounters,
) {
    let afi_safi = AfiSafi::new(Afi::Ip6, Safi::Unicast);
    let Some(af) = update_groups.get_mut(&afi_safi) else {
        return;
    };
    let Some(group) = af.group_by_id_mut(id) else {
        return;
    };
    group.counters.merge(&deltas);
    group.flush_inflight_ipv6 = false;
    let deferred = std::mem::take(&mut group.deferred_withdraw_ipv6);
    let rerun = std::mem::take(&mut group.flush_pending_ipv6);
    let members = group.members.clone();
    for (ident, nlri) in deferred {
        if !members.contains(&ident) {
            continue;
        }
        let Some(peer) = peers.get_mut_by_idx(ident) else {
            continue;
        };
        if !peer.state.is_established() {
            continue;
        }
        super::route::route_withdraw_ipv6(peer, nlri.prefix, nlri.id);
    }
    if rerun {
        flush_ipv6(update_groups, peers, tx, id);
    }
}

/// Encode one or more UPDATE PDUs carrying `nlris` under `attr` as
/// MP_REACH(AFI=2, SAFI=1). The next-hop is read from `attr.nexthop`
/// (`BgpNexthop::Ipv6`); a non-v6 next-hop degrades to the
/// unspecified address, which the receiver drops. NLRIs are chunked
/// so each PDU stays within `max_packet_size`.
fn encode_ipv6_update(
    attr: &Arc<BgpAttr>,
    nlris: &[Ipv6Nlri],
    max_packet_size: usize,
) -> Vec<bytes::BytesMut> {
    if nlris.is_empty() {
        return Vec::new();
    }
    let nhop = match attr.nexthop.as_ref() {
        Some(BgpNexthop::Ipv6(v6)) => IpAddr::V6(*v6),
        _ => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
    };

    // Chunk by a conservative per-NLRI worst case (4 AddPath + 1 plen
    // + 16 prefix = 21 octets) against the packet budget minus a fixed
    // reserve for the BGP header, path attributes, and MP_REACH fixed
    // fields. Errs toward smaller PDUs rather than risking overflow.
    let per_nlri_max = 21usize;
    let reserve = 256usize;
    let budget = max_packet_size.saturating_sub(reserve).max(per_nlri_max);
    let chunk = (budget / per_nlri_max).max(1);

    let mut out = Vec::new();
    for nlri_chunk in nlris.chunks(chunk) {
        let mut update = UpdatePacket::with_max_packet_size(max_packet_size);
        update.bgp_attr = Some((**attr).clone());
        update.mp_update = Some(MpReachAttr::Ipv6 {
            snpa: 0,
            nhop,
            updates: nlri_chunk.to_vec(),
        });
        // The chunking above keeps each PDU inside the budget, so a length
        // overflow here would mean the reserve no longer covers the attributes.
        // Drop that chunk rather than emit a frame whose header contradicts its
        // body.
        match update.try_emit() {
            Ok(bytes) => out.push(bytes),
            Err(e) => tracing::warn!("dropping IPv6 UPDATE chunk: {}", e),
        }
    }
    out
}

/// Single-peer IPv6-unicast send, the v6 counterpart of
/// [`send_ipv4_direct`]. Used by `route_sync_ipv6` on session establish:
/// the per-group cache would fan out to every member and double-send to
/// peers that already hold these routes, so the sync accumulates per
/// shared attr-set and emits straight to the one new peer. The next-hop
/// rides on the bucket-key attr (set to next-hop-self by
/// `route_update_ipv6`), so there is no ENHE step.
pub(super) fn send_ipv6_direct(peer: &Peer, entries: Vec<(Arc<BgpAttr>, Ipv6Nlri)>) {
    if entries.is_empty() {
        return;
    }
    let mut buckets: HashMap<Arc<BgpAttr>, Vec<Ipv6Nlri>> = HashMap::new();
    for (attr, nlri) in entries {
        buckets.entry(attr).or_default().push(nlri);
    }
    let max_packet_size = if peer.opt.extended_message {
        bgp_packet::BGP_EXTENDED_PACKET_LEN
    } else {
        bgp_packet::BGP_PACKET_LEN
    };
    for (attr, nlris) in buckets {
        let bytes_list = encode_ipv6_update(&attr, &nlris, max_packet_size);
        for buf in bytes_list {
            peer.send_packet(buf);
        }
    }
}

/// Build the `Ipv4MpReachNextHop` to advertise to `peer` for an
/// RFC 8950 IPv4-over-IPv6 UPDATE. Returns `None` when the peer
/// has no link-local on its egress interface — without a link-local
/// the dual form is malformed and the speaker can't emit either
/// MP_REACH variant. When both an LL and a global are registered on
/// the egress ifindex, returns the 32-octet `Dual` form; otherwise
/// the 16-octet `LinkLocal` form.
pub(super) fn compose_enhe_next_hop(
    peer: &Peer,
    addrs: &super::interface_addrs::InterfaceAddrs,
) -> Option<Ipv4MpReachNextHop> {
    let link_local = peer.next_hop_v6(addrs)?;
    match peer.next_hop_v6_global(addrs) {
        Some(global) => Some(Ipv4MpReachNextHop::Dual { global, link_local }),
        None => Some(Ipv4MpReachNextHop::LinkLocal(link_local)),
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
            as_override_target: None,
            remove_private_as: None,
            local_as_substitute: None,
            as4_negotiated: true,
            extended_message: true,
            addpath_send: false,
            extended_next_hop: false,
            multiple_labels: false,
            egress_script: None,
            attach_unknown_attr: None,
            signature_version: SIGNATURE_VERSION,
        }
    }

    /// A bound egress Lua script must shard the update-group per peer
    /// (Model B): two peers under the same script land in DIFFERENT groups
    /// (distinct signatures), so the black-box transform never replicates
    /// one peer's bytes to another. A reload (generation bump) also
    /// re-shards. Without an egress script, grouping is unchanged.
    #[test]
    fn egress_script_shards_group_per_peer() {
        use std::net::{IpAddr, Ipv4Addr};

        let a = base_sig();
        let b = base_sig();
        assert_eq!(a, b, "no egress script ⇒ identical sigs share a group");

        let key = |peer: [u8; 4], generation: u64| EgressScriptKey {
            name: "gbp".into(),
            generation,
            peer: IpAddr::V4(Ipv4Addr::from(peer)),
        };

        // Same script + generation, different peers ⇒ singleton groups.
        let mut p1 = base_sig();
        p1.egress_script = Some(key([10, 0, 0, 1], 1));
        let mut p2 = base_sig();
        p2.egress_script = Some(key([10, 0, 0, 2], 1));
        assert_ne!(p1, p2, "scripted peers get their own groups");

        // Same peer, a reload (generation bump) ⇒ new sig (regroup).
        let mut p1_reloaded = base_sig();
        p1_reloaded.egress_script = Some(key([10, 0, 0, 1], 2));
        assert_ne!(p1, p1_reloaded, "a script reload re-forms the group");

        // Binding vs unbound also differ.
        assert_ne!(a, p1, "binding an egress script changes the sig");
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
        a.as_override_target = Some(65002);
        assert_ne!(base, a);

        let mut a = base.clone();
        a.remove_private_as = Some(RemovePrivateAsKey {
            all: false,
            replace_as: false,
            keep_as: 65002,
        });
        assert_ne!(base, a);

        // Same on/off state but a different mode or kept AS is still a
        // distinct group — the egress AS_PATH would differ.
        let mut b = a.clone();
        b.remove_private_as = Some(RemovePrivateAsKey {
            all: true,
            replace_as: false,
            keep_as: 65002,
        });
        assert_ne!(a, b);
        let mut c = a.clone();
        c.remove_private_as = Some(RemovePrivateAsKey {
            all: false,
            replace_as: false,
            keep_as: 65003,
        });
        assert_ne!(a, c);

        let mut a = base.clone();
        a.local_as_substitute = Some((64999, false));
        assert_ne!(base, a);

        // A different substitute, or the same substitute with
        // replace-as flipped, writes a different egress AS_PATH and
        // must shard the group.
        let mut b = a.clone();
        b.local_as_substitute = Some((64998, false));
        assert_ne!(a, b);
        let mut c = a.clone();
        c.local_as_substitute = Some((64999, true));
        assert_ne!(a, c);

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

        // The egress attach knob (debug/test) appends an attribute to the
        // encoded UPDATE, so two peers attaching different attributes —
        // or only one attaching — must shard the group.
        let mut a = base.clone();
        a.attach_unknown_attr = Some(UnknownAttr::new(0xC0, 250, vec![0xde, 0xad]));
        assert_ne!(base, a);
        let mut b = a.clone();
        b.attach_unknown_attr = Some(UnknownAttr::new(0xC0, 251, vec![0xde, 0xad]));
        assert_ne!(a, b);
    }

    #[test]
    fn id_format_matches_iosxr_style() {
        let id = UpdateGroupId::new(Afi::Ip, Safi::Unicast, 0);
        assert_eq!(id.to_string(), "ipv4-unicast.0");
        let id = UpdateGroupId::new(Afi::Ip6, Safi::Unicast, 1);
        assert_eq!(id.to_string(), "ipv6-unicast.1");
        let id = UpdateGroupId::new(Afi::Ip, Safi::MplsVpn, 7);
        assert_eq!(id.to_string(), "vpnv4.7");
        let id = UpdateGroupId::new(Afi::L2vpn, Safi::Evpn, 2);
        assert_eq!(id.to_string(), "evpn.2");
    }

    /// `id_comps` lists every live group's IOS-XR ID across all
    /// AFI/SAFIs — the candidate set behind the `bgp:update-group`
    /// dynamic completion, matching what `show bgp update-group`
    /// renders (e.g. "ipv4-unicast.0", "ipv6-unicast.0").
    #[test]
    fn id_comps_lists_all_group_ids() {
        let mut groups = empty_map();

        let (_, g4) = test_group(0);
        groups
            .entry(AfiSafi::new(Afi::Ip, Safi::Unicast))
            .or_default()
            .groups
            .insert(g4.sig.clone(), g4);

        // Same base signature, but a distinct AFI/SAFI bucket and an
        // IPv6-tagged ID.
        let (_, mut g6) = test_group(0);
        g6.id = UpdateGroupId::new(Afi::Ip6, Safi::Unicast, 0);
        groups
            .entry(AfiSafi::new(Afi::Ip6, Safi::Unicast))
            .or_default()
            .groups
            .insert(g6.sig.clone(), g6);

        let mut got = id_comps(&groups);
        got.sort();
        assert_eq!(got, vec!["ipv4-unicast.0", "ipv6-unicast.0"]);

        // No groups ⇒ no candidates (the dynamic key contributes
        // nothing rather than a placeholder).
        assert!(id_comps(&empty_map()).is_empty());
    }

    fn attach_test_peer(addr: std::net::IpAddr) -> Peer {
        let (tx, _rx) = mpsc::channel(1);
        // The attach path never touches sockets; a parked ProtoContext
        // over a leaked inbound channel is enough (mirrors the PeerMap
        // test scaffolding).
        let (inbound_tx, inbound_rx) = tokio::sync::mpsc::unbounded_channel();
        Box::leak(Box::new(inbound_rx));
        let rib = crate::rib::client::RibClient::new(
            inbound_tx,
            crate::rib::client::ProtoId::from_raw(0),
        );
        let ctx = crate::context::ProtoContext::default_table(rib);
        Peer::new(
            0,
            65000,
            std::net::Ipv4Addr::new(1, 1, 1, 1),
            65000,
            addr,
            None,
            tx,
            ctx,
        )
    }

    fn negotiate(peer: &mut Peer, afi: Afi, safi: Safi) {
        let key = bgp_packet::CapMultiProtocol::new(&afi, &safi);
        let entry = peer
            .cap_map
            .entries
            .get_mut(&key)
            .expect("family pre-seeded in CapAfiMap");
        entry.send = true;
        entry.recv = true;
    }

    /// `attach` must enroll a peer into one group per *negotiated*
    /// tracked family — pinning IPv6 unicast in particular, whose
    /// missing enrollment silently killed incremental v6 reach (the
    /// advertise path gates on `update_group_id[(Ip6, Unicast)]`).
    #[test]
    fn attach_enrolls_negotiated_v6_unicast() {
        let mut peers = PeerMap::new();

        // Dual-stack peer: v4 + v6 unicast negotiated.
        let dual: IpAddr = std::net::Ipv4Addr::new(10, 0, 0, 1).into();
        let mut peer = attach_test_peer(dual);
        negotiate(&mut peer, Afi::Ip, Safi::Unicast);
        negotiate(&mut peer, Afi::Ip6, Safi::Unicast);
        peers.insert(dual, peer);
        let dual_idx = peers.get(&dual).unwrap().ident;

        // v4-only peer: must not be enrolled in a v6 group.
        let v4only: IpAddr = std::net::Ipv4Addr::new(10, 0, 0, 2).into();
        let mut peer = attach_test_peer(v4only);
        negotiate(&mut peer, Afi::Ip, Safi::Unicast);
        peers.insert(v4only, peer);
        let v4only_idx = peers.get(&v4only).unwrap().ident;

        let mut groups = empty_map();
        let rid = "1.1.1.1".parse().unwrap();
        attach(&mut groups, &mut peers, dual_idx, rid, true);
        attach(&mut groups, &mut peers, v4only_idx, rid, true);

        let v4_key = AfiSafi::new(Afi::Ip, Safi::Unicast);
        let v6_key = AfiSafi::new(Afi::Ip6, Safi::Unicast);

        let dual_peer = peers.get(&dual).unwrap();
        assert!(dual_peer.update_group_id.contains_key(&v4_key));
        let v6_id = dual_peer
            .update_group_id
            .get(&v6_key)
            .expect("v6-unicast must be enrolled — its advertise path is group-gated");
        assert_eq!(v6_id.to_string(), "ipv6-unicast.0");
        assert!(
            groups
                .get(&v6_key)
                .and_then(|af| af.groups.values().find(|g| g.members.contains(&dual_idx)))
                .is_some(),
            "dual-stack peer must be a member of an ipv6-unicast group"
        );

        let v4only_peer = peers.get(&v4only).unwrap();
        assert!(v4only_peer.update_group_id.contains_key(&v4_key));
        assert!(
            !v4only_peer.update_group_id.contains_key(&v6_key),
            "non-negotiated family must not be enrolled"
        );

        // detach must clear both memberships symmetrically.
        detach(&mut groups, &mut peers, dual_idx);
        let dual_peer = peers.get(&dual).unwrap();
        assert!(dual_peer.update_group_id.is_empty());
        assert!(
            groups
                .get(&v6_key)
                .map(|af| af.groups.is_empty())
                .unwrap_or(true),
            "emptied v6 group must be dropped"
        );
    }

    /// The counter-bump path uses `group_by_id_mut` to find the
    /// group from a peer's back-reference id. Verifies the lookup
    /// finds the group and that mutating the returned reference
    /// persists.
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
                cache_ipv4: HashMap::new(),
                cache_ipv4_rev: HashMap::new(),
                cache_ipv4_timer: None,
                cache_ipv6: HashMap::new(),
                cache_ipv6_rev: HashMap::new(),
                cache_ipv6_timer: None,
                adv_interval: AdvInterval::default(),
                flush_inflight_ipv4: false,
                flush_pending_ipv4: false,
                deferred_withdraw_ipv4: Vec::new(),
                flush_inflight_ipv6: false,
                flush_pending_ipv6: false,
                deferred_withdraw_ipv6: Vec::new(),
                task: None,
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

    fn enhe_v4_over_v6() -> CapExtendedNextHop {
        use bgp_packet::ExtendedNextHopValue;
        CapExtendedNextHop::new(vec![ExtendedNextHopValue::new(
            Afi::Ip,
            Safi::Unicast,
            Afi::Ip6,
        )])
    }

    #[test]
    fn enhe_negotiated_requires_both_sides() {
        let cap = enhe_v4_over_v6();

        // Both sides advertised → true.
        assert!(enhe_negotiated_for(
            Some(&cap),
            Some(&cap),
            Afi::Ip,
            Safi::Unicast
        ));

        // One side missing → false (no agreement).
        assert!(!enhe_negotiated_for(
            Some(&cap),
            None,
            Afi::Ip,
            Safi::Unicast
        ));
        assert!(!enhe_negotiated_for(
            None,
            Some(&cap),
            Afi::Ip,
            Safi::Unicast
        ));
        assert!(!enhe_negotiated_for(None, None, Afi::Ip, Safi::Unicast));
    }

    #[test]
    fn enhe_negotiated_only_for_ipv4_unicast() {
        let cap = enhe_v4_over_v6();

        // Wrong AFI / SAFI — the cap is irrelevant.
        assert!(!enhe_negotiated_for(
            Some(&cap),
            Some(&cap),
            Afi::Ip6,
            Safi::Unicast
        ));
        assert!(!enhe_negotiated_for(
            Some(&cap),
            Some(&cap),
            Afi::Ip,
            Safi::Multicast
        ));
    }

    #[test]
    fn enhe_negotiated_ignores_unrelated_tuples() {
        use bgp_packet::ExtendedNextHopValue;
        // An ENHE cap that advertises only (IPv4-MplsVpn, IPv6) does
        // NOT satisfy IPv4-unicast.
        let cap = CapExtendedNextHop::new(vec![ExtendedNextHopValue::new(
            Afi::Ip,
            Safi::MplsVpn,
            Afi::Ip6,
        )]);
        assert!(!enhe_negotiated_for(
            Some(&cap),
            Some(&cap),
            Afi::Ip,
            Safi::Unicast
        ));
    }

    // ── FlushJob goldens (sharding plan Phase A.1) ──
    //
    // The job is constructed directly — no PeerMap / Bgp needed — and
    // run() executes synchronously, so the exact bytes each member's
    // writer channel receives are pinned against the module's own
    // encode functions. These goldens must survive A.2 (worker
    // offload) byte-for-byte.

    use std::net::Ipv4Addr;

    use bgp_packet::{As4Path, BgpNexthop, Community, CommunityValue, Med, Origin};

    fn test_attr(med: u32) -> Arc<BgpAttr> {
        let mut attr = BgpAttr::new();
        attr.origin = Some(Origin::Igp);
        attr.aspath = Some(As4Path::from(vec![65001]));
        attr.nexthop = Some(BgpNexthop::Ipv4(Ipv4Addr::new(192, 0, 2, 1)));
        attr.med = Some(Med::new(med));
        Arc::new(attr)
    }

    fn nlri(s: &str) -> Ipv4Nlri {
        Ipv4Nlri {
            id: 0,
            prefix: s.parse().unwrap(),
        }
    }

    fn flush_member(ident: usize) -> (FlushMember, mpsc::UnboundedReceiver<bytes::BytesMut>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (
            FlushMember {
                ident,
                tx: Some(tx),
                enhe_v6: None,
                llgr_ok: false,
            },
            rx,
        )
    }

    fn recv_all(rx: &mut mpsc::UnboundedReceiver<bytes::BytesMut>) -> Vec<bytes::BytesMut> {
        let mut out = Vec::new();
        while let Ok(b) = rx.try_recv() {
            out.push(b);
        }
        out
    }

    /// Canonical sharing: a bucket with no member sources produces one
    /// encoded variant whose exact bytes reach every member.
    #[test]
    fn flush_job_canonical_shared_bytes() {
        let attr = test_attr(0);
        let entries = vec![(nlri("10.0.0.1/32"), 99), (nlri("10.0.0.2/32"), 99)];
        let (m1, mut rx1) = flush_member(1);
        let (m2, mut rx2) = flush_member(2);
        let job = FlushJob {
            buckets: vec![(attr.clone(), entries.clone())],
            members: vec![m1, m2],
            max_packet_size: bgp_packet::BGP_PACKET_LEN,
            enhe: false,
        };
        let counters = job.run();

        let nlris: Vec<Ipv4Nlri> = entries.iter().map(|(n, _)| n.clone()).collect();
        let golden = encode_ipv4_update(&attr, &nlris, bgp_packet::BGP_PACKET_LEN, None);
        assert!(!golden.is_empty());
        assert_eq!(recv_all(&mut rx1), golden);
        assert_eq!(recv_all(&mut rx2), golden);

        assert_eq!(counters.messages_formatted, golden.len() as u64);
        assert_eq!(counters.messages_replicated, 2 * golden.len() as u64);
        assert_eq!(
            counters.bytes_formatted,
            golden.iter().map(|b| b.len() as u64).sum::<u64>()
        );
        assert_eq!(counters.split_horizon_excluded, 0);
        assert_eq!(counters.llgr_excluded, 0);
    }

    /// Split-horizon: a member that sourced an NLRI gets the pruned
    /// variant (its own NLRI removed); the other member gets the
    /// canonical bytes.
    #[test]
    fn flush_job_split_horizon_prunes_source() {
        let attr = test_attr(0);
        let entries = vec![(nlri("10.0.0.1/32"), 1), (nlri("10.0.0.2/32"), 7)];
        let (m1, mut rx1) = flush_member(1);
        let (m2, mut rx2) = flush_member(2);
        let job = FlushJob {
            buckets: vec![(attr.clone(), entries)],
            members: vec![m1, m2],
            max_packet_size: bgp_packet::BGP_PACKET_LEN,
            enhe: false,
        };
        let counters = job.run();

        let canonical = encode_ipv4_update(
            &attr,
            &[nlri("10.0.0.1/32"), nlri("10.0.0.2/32")],
            bgp_packet::BGP_PACKET_LEN,
            None,
        );
        let pruned = encode_ipv4_update(
            &attr,
            &[nlri("10.0.0.2/32")],
            bgp_packet::BGP_PACKET_LEN,
            None,
        );
        assert_eq!(recv_all(&mut rx1), pruned);
        assert_eq!(recv_all(&mut rx2), canonical);
        assert_eq!(counters.split_horizon_excluded, 1);
        assert_eq!(
            counters.messages_formatted,
            (canonical.len() + pruned.len()) as u64
        );
    }

    /// RFC 9494 §4.3: an LLGR_STALE bucket reaches only members that
    /// advertised the LLGR capability.
    #[test]
    fn flush_job_llgr_stale_gates_incapable() {
        let mut attr = BgpAttr::new();
        attr.origin = Some(Origin::Igp);
        attr.aspath = Some(As4Path::from(vec![65001]));
        attr.nexthop = Some(BgpNexthop::Ipv4(Ipv4Addr::new(192, 0, 2, 1)));
        attr.com = Some(Community([CommunityValue::LLGR_STALE.value()].into()));
        let attr = Arc::new(attr);

        let (capable, mut rx_ok) = flush_member(1);
        let capable = FlushMember {
            llgr_ok: true,
            ..capable
        };
        let (incapable, mut rx_no) = flush_member(2);

        let job = FlushJob {
            buckets: vec![(attr.clone(), vec![(nlri("10.0.0.1/32"), 99)])],
            members: vec![capable, incapable],
            max_packet_size: bgp_packet::BGP_PACKET_LEN,
            enhe: false,
        };
        let counters = job.run();
        assert!(!recv_all(&mut rx_ok).is_empty());
        assert!(recv_all(&mut rx_no).is_empty());
        assert_eq!(counters.llgr_excluded, 1);
    }

    /// ENHE: per-member encode with that member's own v6 next-hop; a
    /// member with no link-local yet is skipped entirely.
    #[test]
    fn flush_job_enhe_per_member_next_hops() {
        let attr = test_attr(0);
        let nh1 = Ipv4MpReachNextHop::LinkLocal("fe80::1".parse().unwrap());
        let nh2 = Ipv4MpReachNextHop::LinkLocal("fe80::2".parse().unwrap());
        let (m1, mut rx1) = flush_member(1);
        let m1 = FlushMember {
            enhe_v6: Some(nh1),
            ..m1
        };
        let (m2, mut rx2) = flush_member(2);
        let m2 = FlushMember {
            enhe_v6: Some(nh2),
            ..m2
        };
        let (m3, mut rx3) = flush_member(3); // no link-local yet → skipped

        let entries = vec![(nlri("10.0.0.1/32"), 99)];
        let job = FlushJob {
            buckets: vec![(attr.clone(), entries.clone())],
            members: vec![m1, m2, m3],
            max_packet_size: bgp_packet::BGP_PACKET_LEN,
            enhe: true,
        };
        let counters = job.run();

        let nlris: Vec<Ipv4Nlri> = entries.iter().map(|(n, _)| n.clone()).collect();
        let golden1 = encode_ipv4_update(&attr, &nlris, bgp_packet::BGP_PACKET_LEN, Some(nh1));
        let golden2 = encode_ipv4_update(&attr, &nlris, bgp_packet::BGP_PACKET_LEN, Some(nh2));
        assert_ne!(golden1, golden2);
        assert_eq!(recv_all(&mut rx1), golden1);
        assert_eq!(recv_all(&mut rx2), golden2);
        assert!(recv_all(&mut rx3).is_empty());
        assert_eq!(
            counters.messages_formatted,
            (golden1.len() + golden2.len()) as u64
        );
        assert_eq!(counters.messages_replicated, counters.messages_formatted);
    }

    /// IPv6 jobs run the same engine; canonical bytes match the direct
    /// MP_REACH encode.
    #[test]
    fn flush_job_ipv6_canonical() {
        let mut attr = BgpAttr::new();
        attr.origin = Some(Origin::Igp);
        attr.aspath = Some(As4Path::from(vec![65001]));
        attr.nexthop = Some(BgpNexthop::Ipv6("2001:db8::1".parse().unwrap()));
        let attr = Arc::new(attr);
        let entries = vec![(
            Ipv6Nlri {
                id: 0,
                prefix: "2001:db8:1::/48".parse().unwrap(),
            },
            99,
        )];
        let (m1, mut rx1) = flush_member(1);
        let job = FlushJob {
            buckets: vec![(attr.clone(), entries.clone())],
            members: vec![m1],
            max_packet_size: bgp_packet::BGP_PACKET_LEN,
            enhe: false,
        };
        let counters = job.run();
        let nlris: Vec<Ipv6Nlri> = entries.iter().map(|(n, _)| n.clone()).collect();
        let golden = encode_ipv6_update(&attr, &nlris, bgp_packet::BGP_PACKET_LEN);
        assert_eq!(recv_all(&mut rx1), golden);
        assert_eq!(counters.messages_formatted, golden.len() as u64);
    }

    // ── Flush-offload latch tests (sharding plan Phase A.2) ──

    /// Bare group for the offload state-machine tests; fields beyond
    /// id/sig are all empty defaults.
    fn test_group(seq: u32) -> (UpdateGroupId, UpdateGroup) {
        let id = UpdateGroupId::new(Afi::Ip, Safi::Unicast, seq);
        let group = UpdateGroup {
            id: id.clone(),
            sig: base_sig(),
            members: BTreeSet::new(),
            created_at: std::time::Instant::now(),
            counters: UpdateGroupCounters::default(),
            cache_ipv4: HashMap::new(),
            cache_ipv4_rev: HashMap::new(),
            cache_ipv4_timer: None,
            cache_ipv6: HashMap::new(),
            cache_ipv6_rev: HashMap::new(),
            cache_ipv6_timer: None,
            adv_interval: AdvInterval::default(),
            flush_inflight_ipv4: false,
            flush_pending_ipv4: false,
            deferred_withdraw_ipv4: Vec::new(),
            flush_inflight_ipv6: false,
            flush_pending_ipv6: false,
            deferred_withdraw_ipv6: Vec::new(),
            task: None,
        };
        (id, group)
    }

    fn groups_with(group: UpdateGroup) -> UpdateGroupMap {
        let mut groups = empty_map();
        let af = groups
            .entry(AfiSafi::new(Afi::Ip, Safi::Unicast))
            .or_default();
        af.groups.insert(group.sig.clone(), group);
        af.next_seq = 1;
        groups
    }

    /// A timer that fires while a job is in flight must latch
    /// `flush_pending_ipv4` and leave the cache untouched — running a
    /// second job concurrently could interleave UPDATEs on the
    /// members' writer channels.
    #[test]
    fn flush_ipv4_latches_when_inflight() {
        let (id, mut group) = test_group(0);
        group.flush_inflight_ipv4 = true;
        group
            .cache_ipv4
            .entry(test_attr(0))
            .or_default()
            .insert(nlri("10.0.0.1/32"), 99);
        let mut groups = groups_with(group);
        let mut peers = PeerMap::new();
        let (tx, _rx) = mpsc::channel(8);
        let addrs = super::super::interface_addrs::InterfaceAddrs::default();

        flush_ipv4(&mut groups, &mut peers, &tx, &id, &addrs);

        let af = groups
            .get_mut(&AfiSafi::new(Afi::Ip, Safi::Unicast))
            .unwrap();
        let group = af.group_by_id_mut(&id).unwrap();
        assert!(group.flush_inflight_ipv4);
        assert!(group.flush_pending_ipv4);
        assert_eq!(
            group.cache_ipv4.len(),
            1,
            "cache must not drain while latched"
        );
    }

    /// FlushDone merges the worker's deltas, releases the latch, and
    /// consumes the pending flag (empty cache ⇒ the rerun no-ops).
    /// Deferred withdraws whose peers left the group are dropped.
    #[test]
    fn flush_done_ipv4_releases_latch_and_drops_departed() {
        let (id, mut group) = test_group(0);
        group.flush_inflight_ipv4 = true;
        group.flush_pending_ipv4 = true;
        // ident 7 is NOT a member: its parked withdraw must be dropped
        // (a session bounce re-syncs the table from scratch).
        group.deferred_withdraw_ipv4.push((7, nlri("10.0.0.1/32")));
        let mut groups = groups_with(group);
        let mut peers = PeerMap::new();
        let (tx, _rx) = mpsc::channel(8);
        let addrs = super::super::interface_addrs::InterfaceAddrs::default();

        let deltas = UpdateGroupCounters {
            messages_formatted: 2,
            bytes_formatted: 100,
            ..Default::default()
        };
        flush_done_ipv4(&mut groups, &mut peers, &tx, &id, deltas, &addrs);

        let af = groups
            .get_mut(&AfiSafi::new(Afi::Ip, Safi::Unicast))
            .unwrap();
        let group = af.group_by_id_mut(&id).unwrap();
        assert!(!group.flush_inflight_ipv4);
        assert!(!group.flush_pending_ipv4);
        assert!(group.deferred_withdraw_ipv4.is_empty());
        assert_eq!(group.counters.messages_formatted, 2);
        assert_eq!(group.counters.bytes_formatted, 100);
    }

    /// End-to-end offload: flush spawns the job on the blocking pool,
    /// the worker reports back via `FlushDoneIpv4` with the encode
    /// deltas, and the in-flight latch is set in between. (Members are
    /// absent from the PeerMap, so the job encodes without sending —
    /// the byte goldens above already pin the send path.)
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn flush_ipv4_offload_roundtrip() {
        let (id, mut group) = test_group(0);
        group.members.insert(1);
        let attr = test_attr(0);
        group
            .cache_ipv4
            .entry(attr.clone())
            .or_default()
            .insert(nlri("10.0.0.1/32"), 99);
        group.cache_ipv4_rev.insert(nlri("10.0.0.1/32"), attr);
        let mut groups = groups_with(group);
        let mut peers = PeerMap::new();
        let (tx, mut rx) = mpsc::channel(8);
        let addrs = super::super::interface_addrs::InterfaceAddrs::default();

        flush_ipv4(&mut groups, &mut peers, &tx, &id, &addrs);
        {
            let af = groups
                .get_mut(&AfiSafi::new(Afi::Ip, Safi::Unicast))
                .unwrap();
            let group = af.group_by_id_mut(&id).unwrap();
            assert!(group.flush_inflight_ipv4, "latch set while job is out");
            assert!(group.cache_ipv4.is_empty(), "cache drained into the job");
        }

        let Some(Message::FlushDoneIpv4(done_id, deltas)) = rx.recv().await else {
            panic!("expected FlushDoneIpv4 from the worker");
        };
        assert_eq!(done_id, id);
        assert_eq!(deltas.messages_formatted, 1);
        assert!(deltas.bytes_formatted > 0);

        flush_done_ipv4(&mut groups, &mut peers, &tx, &id, deltas, &addrs);
        let af = groups
            .get_mut(&AfiSafi::new(Afi::Ip, Safi::Unicast))
            .unwrap();
        let group = af.group_by_id_mut(&id).unwrap();
        assert!(!group.flush_inflight_ipv4);
        assert_eq!(group.counters.messages_formatted, 1);
    }

    /// Counter merge accumulates additive fields and overwrites the
    /// timing fields only when the delta carries one.
    #[test]
    fn counters_merge_accumulates() {
        let mut base = UpdateGroupCounters {
            messages_formatted: 1,
            last_format_us: Some(10),
            ..Default::default()
        };
        let delta = UpdateGroupCounters {
            messages_formatted: 2,
            messages_replicated: 3,
            bytes_formatted: 4,
            split_horizon_excluded: 5,
            llgr_excluded: 6,
            ..Default::default()
        };
        base.merge(&delta);
        assert_eq!(base.messages_formatted, 3);
        assert_eq!(base.messages_replicated, 3);
        assert_eq!(base.bytes_formatted, 4);
        assert_eq!(base.split_horizon_excluded, 5);
        assert_eq!(base.llgr_excluded, 6);
        assert_eq!(base.last_format_us, Some(10));
    }
}
