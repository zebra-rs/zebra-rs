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
pub const SIGNATURE_VERSION: u32 = 9;

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
    /// RFC 9234 `otc-local-role` (eBGP only; `None` when unset or iBGP).
    /// The egress procedures depend on it: toward a Customer / Peer /
    /// RS-Client the OTC attribute is added (ER1), toward a Provider /
    /// Peer / RS an OTC-marked route is suppressed (ER2). Two peers under
    /// different roles must therefore never share canonical UPDATE bytes.
    pub otc_local_role: Option<bgp_packet::BgpRole>,
    /// RFC 7947 `route-server-client` (eBGP only). The egress AS_PATH is
    /// left untouched and the forwarded next-hop preserved toward such a
    /// peer, so it must never share canonical bytes with an ordinary
    /// eBGP neighbor that gets the prepended / rewritten form.
    pub route_server_client: bool,
    // Negotiated wire-format capabilities (intersection of cap_send
    // and cap_recv on the peer). Anything that changes encoded
    // UPDATE bytes belongs here.
    pub as4_negotiated: bool,
    pub extended_message: bool,
    pub addpath_send: bool,
    pub extended_next_hop: bool,
    pub multiple_labels: bool,
    /// Per-peer `afi-safi ipv6 encapsulation-type`, stamped only for
    /// the IPv6-unicast group (`None` elsewhere — sigs are compared
    /// within one AFI/SAFI map, so the collapse is harmless). The v6
    /// egress transform strips the SRv6 Prefix-SID for `srv6-relax`
    /// members and suppresses SID-less routes for `srv6` (strict)
    /// members, so peers with different modes must not share the
    /// memoized canonical outcome: a plain CE handed an SRv6 PE's
    /// canonical bytes would keep the provider service SID — the CE
    /// then tracks an unresolvable provider locator and blackholes.
    pub ipv6_encap_type: Option<super::peer::AfiSafiEncapType>,
    /// Per-peer `afi-safi vpnv4 next-hop-self` / `next-hop-unchanged`,
    /// stamped only for the `(Ip, MplsVpn)` group. They select the
    /// egress NEXT_HOP of VPNv4 advertisements (via the per-peer
    /// `sync_ctx`), so an Inter-AS Option-B ASBR with `next-hop-self`
    /// toward one PE but not another must not let the two share
    /// canonical bytes — one of them would be sent the wrong NEXT_HOP
    /// and blackhole VPN traffic.
    pub vpnv4_next_hop_self: bool,
    pub vpnv4_next_hop_unchanged: bool,
    /// Per-peer `afi-safi ipv4|ipv6 next-hop-self` / `next-hop-unchanged`,
    /// stamped only for the `(Ip, Unicast)` and `(Ip6, Unicast)` groups
    /// from that family's own knob. The unicast egress builders
    /// (`route_update_ipv4` via `SyncCtx`, `route_update_ipv6` straight
    /// from the peer) select the NEXT_HOP with them, so two neighbors that
    /// differ only in a knob must not share canonical bytes: a reflector's
    /// plain client would be handed the reflector as next-hop (or the
    /// `next-hop-self` client the far eBGP neighbor), and an IXP peer with
    /// `next-hop-unchanged` would get the rewritten form. `next-hop-self`
    /// is stamped for iBGP only — eBGP always rewrites unless unchanged,
    /// so the knob is a no-op there and must not split eBGP groups.
    pub unicast_next_hop_self: bool,
    pub unicast_next_hop_unchanged: bool,
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
    /// Per-neighbor `advertisement-interval` override (MRAI in seconds),
    /// or `None` to inherit the instance-level `router bgp timer
    /// adv-interval` cadence via `adv_interval`. Unlike the fields
    /// above it does NOT change the encoded UPDATE bytes — it only sets
    /// how long the advertise debounce waits before flushing. It still
    /// belongs in the signature: a group owns a single debounce timer,
    /// so two peers with different advertise cadences must not share one
    /// group (the slower peer's interval would otherwise pace the
    /// faster one, or vice versa). `Some(0)` disables the MRAI — the
    /// group flushes on the next tick (see `start_adv_timer_ipv4`).
    pub adv_interval_override: Option<u16>,
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
    /// With `adv_interval` 0 this is a ~1 ms next-tick timer (see
    /// `start_adv_timer_ipv4`) rather than the usual multi-second one.
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
    /// Members whose signature changed while this group still had a flush
    /// in flight or advertisements queued: `regroup_if_stale` parks them
    /// here instead of moving them, and `flush_done_*` moves them once the
    /// group is idle, after its deferred withdraws went out — so the wire
    /// order announce-then-withdraw of the in-flight job is preserved and
    /// nothing queued for the mover is lost.
    pub regroup_pending: BTreeSet<usize>,
    /// Per-update-group egress task (see
    /// `docs/design/bgp-egress-group-task-migration.md`). `Some` only at
    /// gate-on (`ZEBRA_BGP_EGRESS_GROUP_TASK`); spawned when the group is
    /// created, dropped (abort-on-drop) when it empties. For now it is idle —
    /// it tracks the member set and routes no egress yet.
    pub task: Option<super::group_egress::GroupEgressTask>,
}

impl UpdateGroup {
    /// Seconds the advertise debounce should wait before flushing this
    /// group's cache. A per-neighbor `advertisement-interval` override
    /// (folded into the signature, so every member shares it) wins over
    /// the instance-level `router bgp timer adv-interval` cadence held
    /// in `adv_interval`. `0` disables the MRAI — `start_adv_timer_*`
    /// arms a next-tick (~1 ms) timer rather than the multi-second one.
    pub fn effective_adv_interval_secs(&self) -> u64 {
        match self.sig.adv_interval_override {
            Some(secs) => secs as u64,
            None => self.adv_interval.secs_for(self.sig.peer_type),
        }
    }
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
        // RFC 9234 egress procedures are keyed by the local role (eBGP
        // only — roles are undefined on iBGP and must not split groups).
        otc_local_role: if peer.is_ebgp() {
            peer.config.otc_local_role.map(|r| r.role)
        } else {
            None
        },
        // route-server-client makes the egress AS_PATH transparent and
        // keeps the forwarded next-hop (eBGP only — iBGP never prepends).
        route_server_client: peer.is_ebgp() && peer.config.route_server_client,
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
        // Family-gated per-peer egress knobs — see the field docs. Only
        // the family they transform stamps the real value, so a knob
        // difference cannot shard an unrelated family's group.
        ipv6_encap_type: if afi == Afi::Ip6 && safi == Safi::Unicast {
            peer.ipv6_srv6_encap()
        } else {
            None
        },
        vpnv4_next_hop_self: afi == Afi::Ip
            && safi == Safi::MplsVpn
            && peer.next_hop_self(Afi::Ip, Safi::MplsVpn),
        vpnv4_next_hop_unchanged: afi == Afi::Ip
            && safi == Safi::MplsVpn
            && peer.next_hop_unchanged(Afi::Ip, Safi::MplsVpn),
        // The unicast twins, keyed by this group's own family so the
        // ipv4 knob cannot shard the ipv6 group or vice versa. (iBGP only
        // for next-hop-self — see the field doc.)
        unicast_next_hop_self: safi == Safi::Unicast
            && matches!(afi, Afi::Ip | Afi::Ip6)
            && peer.is_ibgp()
            && peer.next_hop_self(afi, Safi::Unicast),
        unicast_next_hop_unchanged: safi == Safi::Unicast
            && matches!(afi, Afi::Ip | Afi::Ip6)
            && peer.next_hop_unchanged(afi, Safi::Unicast),
        egress_script: egress_script_key(peer, afi, safi),
        // The egress attach knob (debug/test) stamps an extra attribute
        // onto every advertised route, so peers with different attach
        // specs encode different bytes and must shard the group.
        attach_unknown_attr: peer.config.attach_unknown_attr.clone(),
        // Per-neighbor `advertisement-interval` (all AFI/SAFIs — a
        // timing knob, not a per-family transform). `None` inherits the
        // instance-level `router bgp timer adv-interval` cadence.
        adv_interval_override: peer.config.timer.min_adv_interval,
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
    // without overlapping borrows.
    let mut sigs: Vec<(AfiSafi, UpdateGroupSig)> = Vec::new();
    for (afi, safi) in TRACKED_AFI_SAFIS {
        if let Some(sig) = signature_of(peer, afi, safi) {
            sigs.push((AfiSafi::new(afi, safi), sig));
        }
    }

    for (afi_safi, sig) in sigs {
        attach_family(
            update_groups,
            peers,
            peer_idx,
            afi_safi,
            sig,
            router_id,
            as_sets_withdraw,
        );
    }
}

/// [`attach`] for one AFI/SAFI: file `peer_idx` under the group whose
/// signature is `sig` (creating it if needed). `regroup_if_stale` uses
/// this per family so a change in one family never touches another's
/// membership, pending cache or in-flight flush.
fn attach_family(
    update_groups: &mut UpdateGroupMap,
    peers: &mut PeerMap,
    peer_idx: usize,
    afi_safi: AfiSafi,
    sig: UpdateGroupSig,
    router_id: Ipv4Addr,
    as_sets_withdraw: bool,
) {
    // The adv_interval snapshot rides along onto a freshly-created group
    // so the IPv4 adv-timer can read its cadence without reaching back
    // into `Bgp`.
    let Some(adv_interval) = peers.get_by_idx(peer_idx).map(|p| p.adv_interval) else {
        return;
    };
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
            regroup_pending: BTreeSet::new(),
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

/// Remove `peer_idx` from every update-group it currently belongs to.
/// Empty groups are dropped, but `next_seq` is **not** rolled back —
/// a future signature gets a fresh ID rather than reusing a retired
/// one, so log correlation across the lifetime of the daemon stays
/// stable.
pub fn detach(update_groups: &mut UpdateGroupMap, peers: &mut PeerMap, peer_idx: usize) {
    let memberships: Vec<(AfiSafi, UpdateGroupId)> = {
        let Some(peer) = peers.get_by_idx(peer_idx) else {
            return;
        };
        peer.update_group_id
            .iter()
            .map(|(k, v)| (*k, v.clone()))
            .collect()
    };
    for (afi_safi, id) in memberships {
        detach_family(update_groups, peers, peer_idx, afi_safi, &id);
    }
}

/// [`detach`] for one AFI/SAFI: remove `peer_idx` from group `id` of that
/// family (and drop the group if it empties), leaving the peer's other
/// families untouched.
fn detach_family(
    update_groups: &mut UpdateGroupMap,
    peers: &mut PeerMap,
    peer_idx: usize,
    afi_safi: AfiSafi,
    id: &UpdateGroupId,
) {
    if let Some(peer) = peers.get_mut_by_idx(peer_idx) {
        peer.update_group_id.remove(&afi_safi);
        peer.regroup_frozen.remove(&afi_safi);
    }
    let Some(af) = update_groups.get_mut(&afi_safi) else {
        return;
    };
    let key = af
        .groups
        .iter()
        .find(|(_, g)| g.id == *id)
        .map(|(k, _)| k.clone());
    if let Some(key) = key {
        let drop_group = {
            let group = af.groups.get_mut(&key).expect("just located");
            group.members.remove(&peer_idx);
            group.regroup_pending.remove(&peer_idx);
            // Mirror the removal into the group's egress task (the task
            // itself is dropped + aborted below if the group empties).
            if let Some(t) = &group.task {
                t.send(super::group_egress::GroupEgressDeltaV4::RemoveMember { ident: peer_idx });
            }
            group.members.is_empty()
        };
        if drop_group {
            af.groups.remove(&key);
        }
    }
}

/// Re-form `peer_idx`'s update-group membership when a signature-bearing
/// input changed on the live session (review finding #4). For every
/// tracked AFI/SAFI a fresh [`signature_of`] is compared with the
/// signature of the group the peer sits in; on a mismatch the peer is
/// moved, family by family, to the group matching it now. The Established
/// edge is otherwise the only attach point, so without this an outbound
/// policy bound (or any egress knob toggled) on an Established peer left
/// it in a group whose canonical member no longer transforms the way it
/// does — and the memoized canonical outcome was replayed to it, or its
/// own outcome to its group-mates.
///
/// Only the families whose signature changed are touched: a VPNv4 policy
/// edit must not detach the peer's IPv6-unicast group and lose the
/// advertisements queued there (nothing replays IPv6).
///
/// A family whose current group has a flush job IN FLIGHT is not moved
/// yet: the job holds the peer's sender and will still announce, so a
/// withdraw sent now would precede it on the wire and never be repeated,
/// and the peer's deferred withdraws must follow the job. Instead the
/// peer is FROZEN in that family (`Peer::regroup_frozen`, parked in the
/// group's `regroup_pending`): it keeps its membership so `flush_done_*`
/// still sends its deferred withdraws, but every advertise fan-out skips
/// it meanwhile — it is neither the canonical member (its changed
/// settings must not be memoized for its group-mates) nor a recipient of
/// the shared cache (their outcome must not be replayed to it), and no
/// job built after the freeze snapshots its sender. `flush_done_*` moves
/// it as soon as the job that pinned it completes and hands it to the
/// caller for a full outbound re-sync, which replaces everything it was
/// skipped for. Anything merely QUEUED in a group (no job in flight) is no
/// reason to wait: the peer moves at once and the re-sync that follows
/// every move (the policy resolve's, the commit-end sweep's, or the
/// `flush_done_*` caller's) re-sends it — for IPv6 too, since
/// `route_soft_out_peer` now covers the v6 family.
///
/// Returns `true` when any family moved or was parked for a move. Peers
/// that are not Established are never touched — they attach on the
/// Established edge.
pub fn regroup_if_stale(
    update_groups: &mut UpdateGroupMap,
    peers: &mut PeerMap,
    peer_idx: usize,
    router_id: Ipv4Addr,
    as_sets_withdraw: bool,
) -> bool {
    enum Plan {
        Move(Option<UpdateGroupId>, Option<UpdateGroupSig>),
        Park(UpdateGroupId),
    }
    let plans: Vec<(AfiSafi, Plan)> = {
        let Some(peer) = peers.get_by_idx(peer_idx) else {
            return false;
        };
        if !peer.state.is_established() {
            return false;
        }
        let mut plans = Vec::new();
        for (afi, safi) in TRACKED_AFI_SAFIS {
            let afi_safi = AfiSafi::new(afi, safi);
            let fresh = signature_of(peer, afi, safi);
            let current_id = peer.update_group_id.get(&afi_safi);
            let current = current_id.and_then(|id| {
                update_groups
                    .get(&afi_safi)?
                    .groups
                    .values()
                    .find(|g| g.id == *id)
            });
            let stale = match (fresh.as_ref(), current) {
                (None, None) => false,
                (Some(fresh), Some(group)) => *fresh != group.sig,
                _ => true,
            };
            if !stale {
                continue;
            }
            // Only an in-flight job pins the peer (see the doc above).
            let busy = current.is_some_and(|g| match (afi, safi) {
                (Afi::Ip, Safi::Unicast) => g.flush_inflight_ipv4,
                (Afi::Ip6, Safi::Unicast) => g.flush_inflight_ipv6,
                // VPNv4 / EVPN advertise per peer; the group only carries
                // membership and the memo, so a move is always safe.
                _ => false,
            });
            let plan = if busy {
                Plan::Park(current_id.cloned().expect("busy implies a current group"))
            } else {
                Plan::Move(current_id.cloned(), fresh)
            };
            plans.push((afi_safi, plan));
        }
        plans
    };
    if plans.is_empty() {
        return false;
    }
    for (afi_safi, plan) in plans {
        match plan {
            Plan::Park(id) => {
                if let Some(group) = update_groups
                    .get_mut(&afi_safi)
                    .and_then(|af| af.group_by_id_mut(&id))
                {
                    group.regroup_pending.insert(peer_idx);
                    // The gate-on engine fans to its own member list: take
                    // the frozen peer out of it too, until it moves (a new
                    // group re-adds it) or settles (`flush_done_*` re-adds
                    // it here).
                    if let Some(t) = &group.task {
                        t.send(super::group_egress::GroupEgressDeltaV4::RemoveMember {
                            ident: peer_idx,
                        });
                    }
                }
                if let Some(peer) = peers.get_mut_by_idx(peer_idx) {
                    peer.regroup_frozen.insert(afi_safi);
                }
            }
            Plan::Move(current_id, fresh) => {
                if let Some(id) = current_id {
                    detach_family(update_groups, peers, peer_idx, afi_safi, &id);
                }
                if let Some(sig) = fresh {
                    attach_family(
                        update_groups,
                        peers,
                        peer_idx,
                        afi_safi,
                        sig,
                        router_id,
                        as_sets_withdraw,
                    );
                }
            }
        }
    }
    true
}

/// [`regroup_if_stale`] over every Established peer; returns the idents
/// that moved. The commit-end sweep and the neighbor-group inheritance
/// sweep use it so a knob toggled on a live session takes effect in the
/// group structure within the same commit (review finding #21).
pub fn regroup_stale_peers(
    update_groups: &mut UpdateGroupMap,
    peers: &mut PeerMap,
    router_id: Ipv4Addr,
    as_sets_withdraw: bool,
) -> Vec<usize> {
    let idents: Vec<usize> = peers
        .iter_all()
        .filter(|(_, peer)| peer.state.is_established())
        .map(|(_, peer)| peer.ident)
        .collect();
    idents
        .into_iter()
        .filter(|&ident| regroup_if_stale(update_groups, peers, ident, router_id, as_sets_withdraw))
        .collect()
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
        let secs = group.effective_adv_interval_secs();
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
    let cb = move || {
        let tx = tx.clone();
        let id = id.clone();
        async move {
            let _ = tx.send(Message::FlushUpdateGroupIpv4(id)).await;
        }
    };
    // adv-interval 0 fires on the next tick (~1 ms) instead of letting
    // `Timer::once` clamp 0 s up to its 1 s floor. `cache_ipv4_timer`
    // stays `Some` until the flush drains it, so a same-batch burst
    // still coalesces into one flush. See `start_adv_timer!` in
    // timer.rs for the per-peer twin of this.
    if secs == 0 {
        Timer::once_ms(1, cb)
    } else {
        Timer::once(secs, cb)
    }
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
        as4: bool,
        enhe_v6: Option<Ipv4MpReachNextHop>,
    ) -> Vec<bytes::BytesMut>;
}

impl FlushNlri for Ipv4Nlri {
    fn encode(
        attr: &Arc<BgpAttr>,
        nlris: &[Self],
        max_packet_size: usize,
        as4: bool,
        enhe_v6: Option<Ipv4MpReachNextHop>,
    ) -> Vec<bytes::BytesMut> {
        encode_ipv4_update(attr, nlris, max_packet_size, as4, enhe_v6)
    }
}

impl FlushNlri for Ipv6Nlri {
    fn encode(
        attr: &Arc<BgpAttr>,
        nlris: &[Self],
        max_packet_size: usize,
        as4: bool,
        _enhe_v6: Option<Ipv4MpReachNextHop>,
    ) -> Vec<bytes::BytesMut> {
        encode_ipv6_update(attr, nlris, max_packet_size, as4)
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
    /// Group negotiated 4-octet AS encoding (RFC 6793) — sig field, so
    /// it is uniform across members by construction.
    pub as4: bool,
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
                    let bytes_list =
                        N::encode(&attr, &nlris, self.max_packet_size, self.as4, Some(nh));
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
            let canonical_bytes =
                N::encode(&attr, &canonical, self.max_packet_size, self.as4, None);
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
                let pruned_bytes = N::encode(&attr, &nlris, self.max_packet_size, self.as4, None);
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
        // A member frozen for a pending move gets nothing new from this
        // group: it moves as soon as the job that was in flight when it
        // froze completes, and is re-synced then.
        .filter(|ident| !group.regroup_pending.contains(ident))
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
        as4: group.sig.as4_negotiated,
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
    router_id: Ipv4Addr,
    as_sets_withdraw: bool,
) -> Vec<usize> {
    let afi_safi = AfiSafi::new(Afi::Ip, Safi::Unicast);
    let Some(af) = update_groups.get_mut(&afi_safi) else {
        return Vec::new();
    };
    let Some(group) = af.group_by_id_mut(id) else {
        return Vec::new();
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
    // Members frozen for a pending move: the job that pinned them has
    // completed and their deferred withdraws went out above, so move them
    // now — before any re-run, whose job must not snapshot their senders
    // — and hand them back for the outbound re-sync that replaces
    // whatever they were skipped for while frozen. A member whose
    // signature settled back meanwhile is not moved but is re-synced too.
    let frozen: Vec<usize> = update_groups
        .get_mut(&afi_safi)
        .and_then(|af| af.group_by_id_mut(id))
        .map(|group| {
            std::mem::take(&mut group.regroup_pending)
                .into_iter()
                .collect()
        })
        .unwrap_or_default();
    for &ident in &frozen {
        if let Some(peer) = peers.get_mut_by_idx(ident) {
            peer.regroup_frozen.remove(&afi_safi);
        }
        let moved = regroup_if_stale(update_groups, peers, ident, router_id, as_sets_withdraw);
        if !moved
            && let Some(group) = update_groups
                .get_mut(&afi_safi)
                .and_then(|af| af.group_by_id_mut(id))
            && let Some(t) = &group.task
            && let Some(peer) = peers.get_by_idx(ident)
        {
            // Settled back without moving: put it back on the gate-on
            // engine's member list it was taken off when it froze.
            t.send(super::group_egress::GroupEgressDeltaV4::AddMember {
                ident,
                ctx: Box::new(peer.sync_ctx(router_id, as_sets_withdraw)),
                add_path: peer.opt.is_add_path_send(afi_safi.afi, afi_safi.safi),
            });
        }
    }
    if rerun {
        flush_ipv4(update_groups, peers, tx, id, interface_addrs);
    }
    frozen
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
        let bytes_list = encode_ipv4_update(
            &attr,
            &nlris,
            max_packet_size,
            ctx.as4,
            extended_next_hop_v6,
        );
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
    as4: bool,
    extended_next_hop_v6: Option<Ipv4MpReachNextHop>,
) -> Vec<bytes::BytesMut> {
    let mut update = UpdatePacket::with_max_packet_size(max_packet_size);
    update.as4 = as4;
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
        let secs = group.effective_adv_interval_secs();
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
    let cb = move || {
        let tx = tx.clone();
        let id = id.clone();
        async move {
            let _ = tx.send(Message::FlushUpdateGroupIpv6(id)).await;
        }
    };
    // See `start_adv_timer_ipv4` for why 0 fires on the next tick.
    if secs == 0 {
        Timer::once_ms(1, cb)
    } else {
        Timer::once(secs, cb)
    }
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
        // A member frozen for a pending move gets nothing new from this
        // group: it moves as soon as the job that was in flight when it
        // froze completes, and is re-synced then.
        .filter(|ident| !group.regroup_pending.contains(ident))
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
        as4: group.sig.as4_negotiated,
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
    router_id: Ipv4Addr,
    as_sets_withdraw: bool,
) -> Vec<usize> {
    let afi_safi = AfiSafi::new(Afi::Ip6, Safi::Unicast);
    let Some(af) = update_groups.get_mut(&afi_safi) else {
        return Vec::new();
    };
    let Some(group) = af.group_by_id_mut(id) else {
        return Vec::new();
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
    // Members frozen for a pending move: the job that pinned them has
    // completed and their deferred withdraws went out above, so move them
    // now — before any re-run, whose job must not snapshot their senders
    // — and hand them back for the outbound re-sync that replaces
    // whatever they were skipped for while frozen. A member whose
    // signature settled back meanwhile is not moved but is re-synced too.
    let frozen: Vec<usize> = update_groups
        .get_mut(&afi_safi)
        .and_then(|af| af.group_by_id_mut(id))
        .map(|group| {
            std::mem::take(&mut group.regroup_pending)
                .into_iter()
                .collect()
        })
        .unwrap_or_default();
    for &ident in &frozen {
        if let Some(peer) = peers.get_mut_by_idx(ident) {
            peer.regroup_frozen.remove(&afi_safi);
        }
        let moved = regroup_if_stale(update_groups, peers, ident, router_id, as_sets_withdraw);
        if !moved
            && let Some(group) = update_groups
                .get_mut(&afi_safi)
                .and_then(|af| af.group_by_id_mut(id))
            && let Some(t) = &group.task
            && let Some(peer) = peers.get_by_idx(ident)
        {
            // Settled back without moving: put it back on the gate-on
            // engine's member list it was taken off when it froze.
            t.send(super::group_egress::GroupEgressDeltaV4::AddMember {
                ident,
                ctx: Box::new(peer.sync_ctx(router_id, as_sets_withdraw)),
                add_path: peer.opt.is_add_path_send(afi_safi.afi, afi_safi.safi),
            });
        }
    }
    if rerun {
        flush_ipv6(update_groups, peers, tx, id);
    }
    frozen
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
    as4: bool,
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
        update.as4 = as4;
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
        let bytes_list = encode_ipv6_update(&attr, &nlris, max_packet_size, peer.as4);
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
            otc_local_role: None,
            route_server_client: false,
            as4_negotiated: true,
            extended_message: true,
            addpath_send: false,
            extended_next_hop: false,
            multiple_labels: false,
            ipv6_encap_type: None,
            vpnv4_next_hop_self: false,
            vpnv4_next_hop_unchanged: false,
            unicast_next_hop_self: false,
            unicast_next_hop_unchanged: false,
            egress_script: None,
            attach_unknown_attr: None,
            adv_interval_override: None,
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

    /// Established-ish peer with `(Ip6, Unicast)` and `(Ip, MplsVpn)`
    /// negotiated, for driving `signature_of` end-to-end.
    fn sig_peer(addr: &str) -> super::super::peer::Peer {
        use bgp_packet::CapMultiProtocol;
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        Box::leak(Box::new(rx));
        let mut peer = super::super::peer::Peer::new(
            0,
            65001,
            std::net::Ipv4Addr::new(10, 0, 0, 9),
            65002,
            addr.parse().unwrap(),
            None,
            tx,
            crate::context::ProtoContext::default_table_no_rib(),
        );
        for (afi, safi) in [(Afi::Ip6, Safi::Unicast), (Afi::Ip, Safi::MplsVpn)] {
            let key = CapMultiProtocol::new(&afi, &safi);
            let entry = peer.cap_map.entries.get_mut(&key).expect("pre-seeded");
            entry.send = true;
            entry.recv = true;
        }
        peer
    }

    /// Review findings #7/#8 regression, at the `signature_of` level:
    /// the per-peer egress knobs must shard exactly the family they
    /// transform. Pre-fix, two peers differing only in
    /// `afi-safi ipv6 encapsulation-type` (or vpnv4 next-hop-self /
    /// next-hop-unchanged) produced IDENTICAL signatures, so they
    /// shared one update-group and the first-iterated member's
    /// memoized canonical bytes leaked to the other.
    #[test]
    fn egress_knobs_shard_only_their_family() {
        use super::super::peer::AfiSafiEncapType;

        let plain = sig_peer("10.0.0.1");
        let mut srv6 = sig_peer("10.0.0.2");
        srv6.config
            .sub
            .entry(AfiSafi::new(Afi::Ip6, Safi::Unicast))
            .or_default()
            .encapsulation_type = Some(AfiSafiEncapType::Srv6);

        let a = signature_of(&plain, Afi::Ip6, Safi::Unicast).unwrap();
        let b = signature_of(&srv6, Afi::Ip6, Safi::Unicast).unwrap();
        assert_ne!(a, b, "encap-type must shard the ipv6-unicast group");
        let a = signature_of(&plain, Afi::Ip, Safi::MplsVpn).unwrap();
        let b = signature_of(&srv6, Afi::Ip, Safi::MplsVpn).unwrap();
        assert_eq!(a, b, "an ipv6 knob must not shard the vpnv4 group");

        let mut nhs = sig_peer("10.0.0.3");
        nhs.config
            .sub
            .entry(AfiSafi::new(Afi::Ip, Safi::MplsVpn))
            .or_default()
            .next_hop_self = true;
        let a = signature_of(&plain, Afi::Ip, Safi::MplsVpn).unwrap();
        let b = signature_of(&nhs, Afi::Ip, Safi::MplsVpn).unwrap();
        assert_ne!(a, b, "vpnv4 next-hop-self must shard the vpnv4 group");
        let a = signature_of(&plain, Afi::Ip6, Safi::Unicast).unwrap();
        let b = signature_of(&nhs, Afi::Ip6, Safi::Unicast).unwrap();
        assert_eq!(a, b, "a vpnv4 knob must not shard the ipv6 group");

        let mut nhu = sig_peer("10.0.0.4");
        nhu.config
            .sub
            .entry(AfiSafi::new(Afi::Ip, Safi::MplsVpn))
            .or_default()
            .next_hop_unchanged = true;
        let a = signature_of(&nhs, Afi::Ip, Safi::MplsVpn).unwrap();
        let b = signature_of(&nhu, Afi::Ip, Safi::MplsVpn).unwrap();
        assert_ne!(a, b, "next-hop-self and next-hop-unchanged differ");
    }

    /// Review finding #3: the unicast `next-hop-self` / `next-hop-unchanged`
    /// knobs select the NEXT_HOP of IPv4- and IPv6-unicast advertisements
    /// but were missing from the signature, so an iBGP peer with
    /// `next-hop-self` shared its group (and the memoized canonical
    /// UPDATE) with a plain iBGP peer on the same local address. Each knob
    /// must shard exactly its own family's unicast group.
    #[test]
    fn unicast_next_hop_knobs_shard_only_their_family() {
        use bgp_packet::CapMultiProtocol;
        // `sig_peer` negotiates ipv6-unicast and vpnv4; add ipv4-unicast.
        let unicast_peer = |addr: &str| {
            let mut peer = sig_peer(addr);
            let key = CapMultiProtocol::new(&Afi::Ip, &Safi::Unicast);
            let entry = peer.cap_map.entries.get_mut(&key).expect("pre-seeded");
            entry.send = true;
            entry.recv = true;
            peer
        };
        let plain = unicast_peer("10.0.0.1");

        let mut nhs4 = unicast_peer("10.0.0.2");
        nhs4.config
            .sub
            .entry(AfiSafi::new(Afi::Ip, Safi::Unicast))
            .or_default()
            .next_hop_self = true;
        let a = signature_of(&plain, Afi::Ip, Safi::Unicast).unwrap();
        let b = signature_of(&nhs4, Afi::Ip, Safi::Unicast).unwrap();
        assert_ne!(a, b, "ipv4 next-hop-self must shard the ipv4-unicast group");
        for (afi, safi) in [(Afi::Ip6, Safi::Unicast), (Afi::Ip, Safi::MplsVpn)] {
            let a = signature_of(&plain, afi, safi).unwrap();
            let b = signature_of(&nhs4, afi, safi).unwrap();
            assert_eq!(
                a, b,
                "an ipv4 knob must not shard the {afi:?}/{safi:?} group"
            );
        }

        let mut nhu6 = unicast_peer("10.0.0.3");
        nhu6.config
            .sub
            .entry(AfiSafi::new(Afi::Ip6, Safi::Unicast))
            .or_default()
            .next_hop_unchanged = true;
        let a = signature_of(&plain, Afi::Ip6, Safi::Unicast).unwrap();
        let b = signature_of(&nhu6, Afi::Ip6, Safi::Unicast).unwrap();
        assert_ne!(
            a, b,
            "ipv6 next-hop-unchanged must shard the ipv6-unicast group"
        );
        for (afi, safi) in [(Afi::Ip, Safi::Unicast), (Afi::Ip, Safi::MplsVpn)] {
            let a = signature_of(&plain, afi, safi).unwrap();
            let b = signature_of(&nhu6, afi, safi).unwrap();
            assert_eq!(
                a, b,
                "an ipv6 knob must not shard the {afi:?}/{safi:?} group"
            );
        }

        // The two knobs are distinct transforms, so they are distinct groups.
        let mut nhu4 = unicast_peer("10.0.0.4");
        nhu4.config
            .sub
            .entry(AfiSafi::new(Afi::Ip, Safi::Unicast))
            .or_default()
            .next_hop_unchanged = true;
        let a = signature_of(&nhs4, Afi::Ip, Safi::Unicast).unwrap();
        let b = signature_of(&nhu4, Afi::Ip, Safi::Unicast).unwrap();
        assert_ne!(a, b, "unicast next-hop-self and next-hop-unchanged differ");

        // eBGP always rewrites the next-hop unless unchanged, so
        // `next-hop-self` is a no-op there and must not split eBGP groups;
        // `next-hop-unchanged` is not a no-op on eBGP and must.
        let mut ebgp_plain = unicast_peer("10.0.0.5");
        ebgp_plain.peer_type = PeerType::EBGP;
        ebgp_plain.remote_as = 65002;
        let mut ebgp_nhs = unicast_peer("10.0.0.6");
        ebgp_nhs.peer_type = PeerType::EBGP;
        ebgp_nhs.remote_as = 65002;
        ebgp_nhs
            .config
            .sub
            .entry(AfiSafi::new(Afi::Ip, Safi::Unicast))
            .or_default()
            .next_hop_self = true;
        let mut ebgp_nhu = unicast_peer("10.0.0.7");
        ebgp_nhu.peer_type = PeerType::EBGP;
        ebgp_nhu.remote_as = 65002;
        ebgp_nhu
            .config
            .sub
            .entry(AfiSafi::new(Afi::Ip, Safi::Unicast))
            .or_default()
            .next_hop_unchanged = true;
        let a = signature_of(&ebgp_plain, Afi::Ip, Safi::Unicast).unwrap();
        let b = signature_of(&ebgp_nhs, Afi::Ip, Safi::Unicast).unwrap();
        assert_eq!(a, b, "next-hop-self is a no-op on eBGP and must not shard");
        let c = signature_of(&ebgp_nhu, Afi::Ip, Safi::Unicast).unwrap();
        assert_ne!(a, c, "next-hop-unchanged must shard eBGP groups");
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

        // RFC 9234: the role selects whether OTC is added or the route
        // suppressed on egress — every role is its own group.
        let mut a = base.clone();
        a.otc_local_role = Some(bgp_packet::BgpRole::Provider);
        assert_ne!(base, a);
        let mut b = a.clone();
        b.otc_local_role = Some(bgp_packet::BgpRole::Customer);
        assert_ne!(a, b);

        // RFC 7947: a route-server client gets the untouched AS_PATH and
        // next-hop — its own group.
        let mut a = base.clone();
        a.route_server_client = true;
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

        // The two per-peer egress knobs of review findings #7/#8: each
        // must shard the group for its family.
        let mut a = base.clone();
        a.ipv6_encap_type = Some(super::super::peer::AfiSafiEncapType::Srv6);
        assert_ne!(base, a);
        let mut b = a.clone();
        b.ipv6_encap_type = Some(super::super::peer::AfiSafiEncapType::Srv6Relax);
        assert_ne!(a, b, "strict and relax encode differently");

        let mut a = base.clone();
        a.vpnv4_next_hop_self = true;
        assert_ne!(base, a);

        let mut a = base.clone();
        a.vpnv4_next_hop_unchanged = true;
        assert_ne!(base, a);

        // Review finding #3: the unicast twins of the two VPNv4 knobs.
        let mut a = base.clone();
        a.unicast_next_hop_self = true;
        assert_ne!(base, a);

        let mut a = base.clone();
        a.unicast_next_hop_unchanged = true;
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

    /// Review finding #4: a signature field changed on an Established
    /// peer (here the outbound policy name) must move exactly that peer
    /// into the group matching its new signature; a fresh peer and a
    /// second call are no-ops, and a non-Established peer is left alone.
    #[test]
    fn regroup_if_stale_moves_only_the_peer_whose_signature_changed() {
        use super::super::peer::State;
        let v6u = AfiSafi::new(Afi::Ip6, Safi::Unicast);
        let mut peers = PeerMap::new();
        for addr in ["10.0.0.1", "10.0.0.2"] {
            let mut peer = sig_peer(addr);
            peer.state = State::Established;
            peers.insert(addr.parse().unwrap(), peer);
        }
        let mut groups = empty_map();
        let router_id = std::net::Ipv4Addr::new(10, 0, 0, 9);
        for ident in 0..2 {
            attach(&mut groups, &mut peers, ident, router_id, false);
        }
        let gid = |peers: &PeerMap, ident: usize| {
            peers
                .get_by_idx(ident)
                .unwrap()
                .update_group_id
                .get(&v6u)
                .cloned()
                .expect("attached")
        };
        assert_eq!(gid(&peers, 0), gid(&peers, 1), "same signature, one group");
        assert!(
            !regroup_if_stale(&mut groups, &mut peers, 0, router_id, false),
            "nothing changed: no move"
        );

        // Bind an outbound policy on peer 0 the way the config handler
        // does (slot name only; the policy actor resolves later).
        peers
            .get_mut_by_idx(0)
            .unwrap()
            .policy_list_slot(v6u, InOut::Output)
            .name = Some("DENY".to_string());
        assert!(
            regroup_if_stale(&mut groups, &mut peers, 0, router_id, false),
            "a changed signature field must move the peer"
        );
        assert_ne!(
            gid(&peers, 0),
            gid(&peers, 1),
            "peer 0 left the shared group"
        );
        let sig_of = |groups: &UpdateGroupMap, id: &UpdateGroupId| {
            groups[&v6u]
                .groups
                .values()
                .find(|g| g.id == *id)
                .map(|g| g.sig.clone())
                .expect("group exists")
        };
        assert_eq!(
            sig_of(&groups, &gid(&peers, 0)).policy_out_name.as_deref(),
            Some("DENY"),
            "peer 0 sits in the group of its NEW signature"
        );
        assert_eq!(sig_of(&groups, &gid(&peers, 1)).policy_out_name, None);
        assert_eq!(groups[&v6u].groups.len(), 2);
        assert!(
            !regroup_if_stale(&mut groups, &mut peers, 0, router_id, false),
            "already in the matching group: no move"
        );
        assert!(
            !regroup_if_stale(&mut groups, &mut peers, 1, router_id, false),
            "the untouched group-mate must not move"
        );

        // Unbinding merges the peer back into its group-mate's group.
        peers
            .get_mut_by_idx(0)
            .unwrap()
            .policy_list_slot(v6u, InOut::Output)
            .name = None;
        assert!(regroup_if_stale(
            &mut groups,
            &mut peers,
            0,
            router_id,
            false
        ));
        assert_eq!(gid(&peers, 0), gid(&peers, 1), "back in one group");
        assert_eq!(groups[&v6u].groups.len(), 1, "the singleton was dropped");

        // A peer that is not Established is never touched.
        peers.get_mut_by_idx(0).unwrap().state = State::Idle;
        peers
            .get_mut_by_idx(0)
            .unwrap()
            .policy_list_slot(v6u, InOut::Output)
            .name = Some("DENY".to_string());
        assert!(!regroup_if_stale(
            &mut groups,
            &mut peers,
            0,
            router_id,
            false
        ));
    }

    /// Review follow-ups (P1 ×2): a family whose group has a flush job in
    /// flight is not moved yet — the job holds the peer's sender, so a
    /// withdraw parked behind it must go out after the job — but the peer
    /// must not keep taking part in the group either: frozen, it is skipped
    /// by the fan-out audience (neither canonical nor a recipient) and by
    /// any job built meanwhile. `flush_done_ipv4` sends the deferred
    /// withdraw, moves the peer and hands it back for a re-sync.
    #[test]
    fn regroup_freezes_a_member_of_a_group_with_a_flush_in_flight_until_flush_done() {
        use super::super::peer::State;
        use bgp_packet::CapMultiProtocol;
        let v4u = AfiSafi::new(Afi::Ip, Safi::Unicast);
        let mut peers = PeerMap::new();
        let mut rx = Vec::new();
        for addr in ["10.0.0.1", "10.0.0.2"] {
            let mut peer = sig_peer(addr);
            peer.state = State::Established;
            let key = CapMultiProtocol::new(&Afi::Ip, &Safi::Unicast);
            let entry = peer.cap_map.entries.get_mut(&key).expect("pre-seeded");
            entry.send = true;
            entry.recv = true;
            let (ptx, prx) = tokio::sync::mpsc::unbounded_channel();
            peer.packet_tx = Some(ptx);
            rx.push(prx);
            peers.insert(addr.parse().unwrap(), peer);
        }
        peers.membership_enroll(0);
        peers.membership_enroll(1);
        let mut groups = empty_map();
        let router_id = std::net::Ipv4Addr::new(10, 0, 0, 9);
        for ident in 0..2 {
            attach(&mut groups, &mut peers, ident, router_id, false);
        }
        let gid = |peers: &PeerMap, ident: usize| {
            peers.get_by_idx(ident).unwrap().update_group_id[&v4u].clone()
        };
        let shared = gid(&peers, 0);
        assert_eq!(shared, gid(&peers, 1));
        assert_eq!(
            peers.established_plain_idents(Afi::Ip, Safi::Unicast),
            vec![0, 1]
        );

        // A flush is in flight and peer 0's withdraw is parked behind it.
        let nlri = Ipv4Nlri {
            id: 0,
            prefix: "10.9.0.0/24".parse().unwrap(),
        };
        {
            let g = groups
                .get_mut(&v4u)
                .unwrap()
                .group_by_id_mut(&shared)
                .unwrap();
            g.flush_inflight_ipv4 = true;
            g.deferred_withdraw_ipv4.push((0, nlri));
        }
        peers
            .get_mut_by_idx(0)
            .unwrap()
            .policy_list_slot(v4u, InOut::Output)
            .name = Some("DENY".to_string());
        assert!(
            regroup_if_stale(&mut groups, &mut peers, 0, router_id, false),
            "stale: frozen for a move"
        );
        assert_eq!(
            gid(&peers, 0),
            shared,
            "membership stays while the job is in flight"
        );
        assert!(peers.get_by_idx(0).unwrap().regroup_frozen.contains(&v4u));
        assert_eq!(
            peers.established_plain_idents(Afi::Ip, Safi::Unicast),
            vec![1],
            "the frozen member is out of the fan-out audience"
        );
        assert!(
            rx[0].try_recv().is_err(),
            "nothing sent before the in-flight job"
        );
        {
            let g = groups
                .get_mut(&v4u)
                .unwrap()
                .group_by_id_mut(&shared)
                .unwrap();
            assert!(g.regroup_pending.contains(&0));
            assert_eq!(
                g.deferred_withdraw_ipv4.len(),
                1,
                "the withdraw stays parked"
            );
            // A job built now must not snapshot the frozen member's sender.
            let attr = Arc::new(BgpAttr::new());
            let queued = Ipv4Nlri {
                id: 0,
                prefix: "10.9.1.0/24".parse().unwrap(),
            };
            g.cache_ipv4
                .entry(attr.clone())
                .or_default()
                .insert(queued.clone(), 7);
            g.cache_ipv4_rev.insert(queued.clone(), attr);
            let addrs = super::super::interface_addrs::InterfaceAddrs::default();
            let job = build_flush_job_ipv4(g, &peers, &addrs).expect("one bucket");
            let recipients: Vec<usize> = job.members.iter().map(|m| m.ident).collect();
            assert_eq!(recipients, vec![1], "the frozen member is not a recipient");
        }

        // The pinning job completes: the deferred withdraw goes out, the
        // frozen member moves and is handed back for a re-sync.
        let (tx, _rx) = mpsc::channel(8);
        let addrs = super::super::interface_addrs::InterfaceAddrs::default();
        let resync = flush_done_ipv4(
            &mut groups,
            &mut peers,
            &tx,
            &shared,
            UpdateGroupCounters::default(),
            &addrs,
            router_id,
            false,
        );
        assert_eq!(resync, vec![0], "handed back for the outbound re-sync");
        let mut sent = 0;
        while rx[0].try_recv().is_ok() {
            sent += 1;
        }
        assert_eq!(sent, 1, "the parked withdraw was sent after the job");
        assert_ne!(gid(&peers, 0), shared, "and the peer moved");
        assert_eq!(gid(&peers, 1), shared);
        assert!(!peers.get_by_idx(0).unwrap().regroup_frozen.contains(&v4u));
        assert_eq!(
            peers.established_plain_idents(Afi::Ip, Safi::Unicast),
            vec![0, 1]
        );
        let g = groups
            .get_mut(&v4u)
            .unwrap()
            .group_by_id_mut(&shared)
            .unwrap();
        assert!(g.regroup_pending.is_empty());
        assert!(g.deferred_withdraw_ipv4.is_empty());
        assert!(rx[1].try_recv().is_err(), "the group-mate was sent nothing");
    }

    /// Review follow-up (P2): only the family whose signature changed is
    /// touched. A VPNv4 policy edit on a peer that is alone in its
    /// IPv6-unicast group must leave that group — and the IPv6
    /// advertisements queued in it, which nothing replays — untouched;
    /// and an IPv6 change while those advertisements are queued parks the
    /// peer instead of dropping them.
    #[test]
    fn regroup_touches_only_the_family_whose_signature_changed() {
        use super::super::peer::State;
        let v6u = AfiSafi::new(Afi::Ip6, Safi::Unicast);
        let vpn4 = AfiSafi::new(Afi::Ip, Safi::MplsVpn);
        let mut peers = PeerMap::new();
        let mut peer = sig_peer("10.0.0.1");
        peer.state = State::Established;
        peers.insert("10.0.0.1".parse().unwrap(), peer);
        let mut groups = empty_map();
        let router_id = std::net::Ipv4Addr::new(10, 0, 0, 9);
        attach(&mut groups, &mut peers, 0, router_id, false);
        let gid = |peers: &PeerMap, fam: AfiSafi| {
            peers.get_by_idx(0).unwrap().update_group_id[&fam].clone()
        };
        let v6_id = gid(&peers, v6u);
        let vpn_id = gid(&peers, vpn4);

        // An IPv6 advertisement queued for the next flush.
        let attr = Arc::new(BgpAttr::new());
        let nlri = Ipv6Nlri {
            id: 0,
            prefix: "2001:db8:9::/64".parse().unwrap(),
        };
        {
            let g = groups
                .get_mut(&v6u)
                .unwrap()
                .group_by_id_mut(&v6_id)
                .unwrap();
            g.cache_ipv6
                .entry(attr.clone())
                .or_default()
                .insert(nlri.clone(), 7);
            g.cache_ipv6_rev.insert(nlri.clone(), attr.clone());
        }

        // VPNv4 policy edit: the VPNv4 group changes, the IPv6 one does not.
        peers
            .get_mut_by_idx(0)
            .unwrap()
            .policy_list_slot(vpn4, InOut::Output)
            .name = Some("VPN-OUT".to_string());
        assert!(regroup_if_stale(
            &mut groups,
            &mut peers,
            0,
            router_id,
            false
        ));
        assert_ne!(gid(&peers, vpn4), vpn_id, "the VPNv4 membership moved");
        assert_eq!(gid(&peers, v6u), v6_id, "the IPv6 membership is untouched");
        {
            let g = groups
                .get_mut(&v6u)
                .unwrap()
                .group_by_id_mut(&v6_id)
                .unwrap();
            assert!(
                g.cache_ipv6
                    .get(&attr)
                    .is_some_and(|b| b.contains_key(&nlri)),
                "the queued IPv6 advertisement survived"
            );
            assert!(g.regroup_pending.is_empty());
        }

        // IPv6 policy edit while the advertisement is still queued (no job
        // in flight): the peer moves at once — the queue is the re-sync's
        // business — and the emptied singleton group is dropped.
        peers
            .get_mut_by_idx(0)
            .unwrap()
            .policy_list_slot(v6u, InOut::Output)
            .name = Some("V6-OUT".to_string());
        assert!(regroup_if_stale(
            &mut groups,
            &mut peers,
            0,
            router_id,
            false
        ));
        assert_ne!(gid(&peers, v6u), v6_id, "moved at once");
        assert!(!peers.get_by_idx(0).unwrap().regroup_frozen.contains(&v6u));
        assert_eq!(groups[&v6u].groups.len(), 1, "only the new group remains");
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
                regroup_pending: BTreeSet::new(),
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
            as4: true,
            max_packet_size: bgp_packet::BGP_PACKET_LEN,
            enhe: false,
        };
        let counters = job.run();

        let nlris: Vec<Ipv4Nlri> = entries.iter().map(|(n, _)| n.clone()).collect();
        let golden = encode_ipv4_update(&attr, &nlris, bgp_packet::BGP_PACKET_LEN, true, None);
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
            as4: true,
            max_packet_size: bgp_packet::BGP_PACKET_LEN,
            enhe: false,
        };
        let counters = job.run();

        let canonical = encode_ipv4_update(
            &attr,
            &[nlri("10.0.0.1/32"), nlri("10.0.0.2/32")],
            bgp_packet::BGP_PACKET_LEN,
            true,
            None,
        );
        let pruned = encode_ipv4_update(
            &attr,
            &[nlri("10.0.0.2/32")],
            bgp_packet::BGP_PACKET_LEN,
            true,
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
            as4: true,
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
            as4: true,
            max_packet_size: bgp_packet::BGP_PACKET_LEN,
            enhe: true,
        };
        let counters = job.run();

        let nlris: Vec<Ipv4Nlri> = entries.iter().map(|(n, _)| n.clone()).collect();
        let golden1 =
            encode_ipv4_update(&attr, &nlris, bgp_packet::BGP_PACKET_LEN, true, Some(nh1));
        let golden2 =
            encode_ipv4_update(&attr, &nlris, bgp_packet::BGP_PACKET_LEN, true, Some(nh2));
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
            as4: true,
            max_packet_size: bgp_packet::BGP_PACKET_LEN,
            enhe: false,
        };
        let counters = job.run();
        let nlris: Vec<Ipv6Nlri> = entries.iter().map(|(n, _)| n.clone()).collect();
        let golden = encode_ipv6_update(&attr, &nlris, bgp_packet::BGP_PACKET_LEN, true);
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
            regroup_pending: BTreeSet::new(),
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
        flush_done_ipv4(
            &mut groups,
            &mut peers,
            &tx,
            &id,
            deltas,
            &addrs,
            std::net::Ipv4Addr::new(10, 0, 0, 9),
            false,
        );

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

        flush_done_ipv4(
            &mut groups,
            &mut peers,
            &tx,
            &id,
            deltas,
            &addrs,
            std::net::Ipv4Addr::new(10, 0, 0, 9),
            false,
        );
        let af = groups
            .get_mut(&AfiSafi::new(Afi::Ip, Safi::Unicast))
            .unwrap();
        let group = af.group_by_id_mut(&id).unwrap();
        assert!(!group.flush_inflight_ipv4);
        assert_eq!(group.counters.messages_formatted, 1);
    }

    // ── adv-interval 0: sub-second flush, no 1 s floor ──

    /// adv-interval 0 must arm a *next-tick* (~1 ms) timer, not the
    /// 1 s-clamped `Timer::once(0, …)`. `duration_sec() == 0` is the
    /// regression guard: the old clamp produced a 1 s timer
    /// (`duration_sec() == 1`). The flush must also land on the channel
    /// well under the old 1 s floor.
    #[tokio::test]
    async fn send_ipv4_zero_adv_interval_flushes_under_one_second_floor() {
        let (id, mut group) = test_group(0);
        group.adv_interval = AdvInterval { ibgp: 0, ebgp: 0 };
        let (tx, mut rx) = mpsc::channel(8);

        send_ipv4(&mut group, nlri("10.0.0.1/32"), test_attr(0), 99, &tx, true);

        let timer = group
            .cache_ipv4_timer
            .as_ref()
            .expect("adv-interval 0 must still arm a debounce timer");
        assert_eq!(
            timer.duration_sec(),
            0,
            "adv-interval 0 must arm a sub-second timer, not the 1 s-clamped one"
        );
        let msg = tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv())
            .await
            .expect("flush must fire well under the old 1 s floor")
            .expect("channel open");
        let Message::FlushUpdateGroupIpv4(got) = msg else {
            panic!("expected FlushUpdateGroupIpv4, got {msg:?}");
        };
        assert_eq!(got, id);
    }

    /// A burst of sends within one synchronous batch (before the
    /// executor runs the ~1 ms timer) must still coalesce into a single
    /// flush message — adv-interval 0 shortens the debounce, it doesn't
    /// remove the batching.
    #[tokio::test]
    async fn send_ipv4_zero_adv_interval_coalesces_batch_into_one_flush() {
        let (_id, mut group) = test_group(0);
        group.adv_interval = AdvInterval { ibgp: 0, ebgp: 0 };
        let (tx, mut rx) = mpsc::channel(8);

        send_ipv4(&mut group, nlri("10.0.0.1/32"), test_attr(0), 99, &tx, true);
        send_ipv4(&mut group, nlri("10.0.0.2/32"), test_attr(0), 99, &tx, true);
        send_ipv4(&mut group, nlri("10.0.0.3/32"), test_attr(1), 99, &tx, true);

        assert_eq!(
            group.cache_ipv4.values().map(|b| b.len()).sum::<usize>(),
            3,
            "all three sends must land in the cache"
        );
        tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv())
            .await
            .expect("one flush message must be queued")
            .expect("channel open");
        assert!(
            rx.try_recv().is_err(),
            "a same-batch burst must coalesce into a single flush message"
        );
    }

    /// Non-zero adv-interval (the default) must keep debouncing via a
    /// multi-second timer exactly as before — no flush message before
    /// it fires.
    #[tokio::test]
    async fn send_ipv4_nonzero_adv_interval_still_arms_timer() {
        let (_id, mut group) = test_group(0);
        assert_eq!(group.adv_interval, AdvInterval::default());
        let (tx, mut rx) = mpsc::channel(8);

        send_ipv4(&mut group, nlri("10.0.0.1/32"), test_attr(0), 99, &tx, true);

        let timer = group
            .cache_ipv4_timer
            .as_ref()
            .expect("non-zero interval must debounce via a timer");
        assert!(
            timer.duration_sec() >= 1,
            "non-zero interval must arm a multi-second timer, not the next-tick one"
        );
        assert!(
            rx.try_recv().is_err(),
            "flush must not fire before the debounce timer elapses"
        );
    }

    /// IPv6 twin of `send_ipv4_zero_adv_interval_flushes_under_one_second_floor`
    /// — catches a copy-paste mistake in the mirrored wiring.
    #[tokio::test]
    async fn send_ipv6_zero_adv_interval_flushes_under_one_second_floor() {
        let (id, mut group) = test_group(0);
        group.adv_interval = AdvInterval { ibgp: 0, ebgp: 0 };
        let (tx, mut rx) = mpsc::channel(8);
        let attr = {
            let mut attr = BgpAttr::new();
            attr.origin = Some(Origin::Igp);
            attr.aspath = Some(As4Path::from(vec![65001]));
            attr.nexthop = Some(BgpNexthop::Ipv6("2001:db8::1".parse().unwrap()));
            Arc::new(attr)
        };
        let nlri6 = Ipv6Nlri {
            id: 0,
            prefix: "2001:db8:1::/48".parse().unwrap(),
        };

        send_ipv6(&mut group, nlri6, attr, 99, &tx, true);

        let timer = group
            .cache_ipv6_timer
            .as_ref()
            .expect("adv-interval 0 must still arm a debounce timer");
        assert_eq!(timer.duration_sec(), 0);
        let msg = tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv())
            .await
            .expect("flush must fire well under the old 1 s floor")
            .expect("channel open");
        let Message::FlushUpdateGroupIpv6(got) = msg else {
            panic!("expected FlushUpdateGroupIpv6, got {msg:?}");
        };
        assert_eq!(got, id);
    }

    /// IPv6 twin of `send_ipv4_nonzero_adv_interval_still_arms_timer`.
    #[tokio::test]
    async fn send_ipv6_nonzero_adv_interval_still_arms_timer() {
        let (_id, mut group) = test_group(0);
        assert_eq!(group.adv_interval, AdvInterval::default());
        let (tx, mut rx) = mpsc::channel(8);
        let attr = {
            let mut attr = BgpAttr::new();
            attr.origin = Some(Origin::Igp);
            attr.aspath = Some(As4Path::from(vec![65001]));
            attr.nexthop = Some(BgpNexthop::Ipv6("2001:db8::1".parse().unwrap()));
            Arc::new(attr)
        };
        let nlri6 = Ipv6Nlri {
            id: 0,
            prefix: "2001:db8:1::/48".parse().unwrap(),
        };

        send_ipv6(&mut group, nlri6, attr, 99, &tx, true);

        let timer = group
            .cache_ipv6_timer
            .as_ref()
            .expect("non-zero interval must debounce via a timer");
        assert!(timer.duration_sec() >= 1);
        assert!(rx.try_recv().is_err());
    }

    // ── per-neighbor advertisement-interval override ──

    /// `effective_adv_interval_secs` prefers the signature override
    /// (per-neighbor `advertisement-interval`) over the instance-level
    /// `adv_interval` snapshot.
    #[test]
    fn effective_adv_interval_prefers_the_signature_override() {
        let (_id, mut group) = test_group(0);
        // Instance default is non-zero (30s eBGP for the test sig).
        assert!(group.effective_adv_interval_secs() >= 1);
        group.sig.adv_interval_override = Some(0);
        assert_eq!(group.effective_adv_interval_secs(), 0);
        group.sig.adv_interval_override = Some(7);
        assert_eq!(group.effective_adv_interval_secs(), 7);
    }

    /// A per-neighbor `advertisement-interval 0` override (as a VRF CE
    /// neighbor sets) must arm the next-tick (~1 ms) debounce even when
    /// the instance-level `adv_interval` is the multi-second default —
    /// this is the VRF-neighbor path, where the instance knob never
    /// reaches the peer.
    #[tokio::test]
    async fn send_ipv4_neighbor_override_zero_flushes_under_one_second_floor() {
        let (id, mut group) = test_group(0);
        assert_eq!(group.adv_interval, AdvInterval::default());
        group.sig.adv_interval_override = Some(0);
        let (tx, mut rx) = mpsc::channel(8);

        send_ipv4(&mut group, nlri("10.0.0.1/32"), test_attr(0), 99, &tx, true);

        let timer = group
            .cache_ipv4_timer
            .as_ref()
            .expect("override 0 must still arm a debounce timer");
        assert_eq!(
            timer.duration_sec(),
            0,
            "per-neighbor advertisement-interval 0 must arm a sub-second timer"
        );
        let msg = tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv())
            .await
            .expect("flush must fire well under the old 1 s floor")
            .expect("channel open");
        let Message::FlushUpdateGroupIpv4(got) = msg else {
            panic!("expected FlushUpdateGroupIpv4, got {msg:?}");
        };
        assert_eq!(got, id);
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
