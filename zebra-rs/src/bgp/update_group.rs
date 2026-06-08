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
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use bgp_packet::{
    Afi, AfiSafi, BgpAttr, BgpNexthop, CapExtendedNextHop, Ipv4MpReachNextHop, Ipv4Nlri, Ipv6Nlri,
    MpReachAttr, Safi, UpdatePacket,
};
use tokio::sync::mpsc;

use super::BgpAttrStore;
use super::inst::Message;
use super::peer::{Peer, PeerType};
use super::peer_map::PeerMap;
use super::timer::AdvInterval;
use crate::bgp::InOut;
use crate::context::Timer;

/// Bumped whenever a new field is added to `UpdateGroupSig`. Surfaced
/// in `show bgp update-group` so a stale view is detectable.
pub const SIGNATURE_VERSION: u32 = 3;

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
        signature_version: SIGNATURE_VERSION,
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
pub fn attach(update_groups: &mut UpdateGroupMap, peers: &mut PeerMap, peer_idx: usize) {
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

/// Drain the IPv4 cache and ship UPDATEs to every member. Called
/// from `Bgp::serve` on `Message::FlushUpdateGroupIpv4`. The flush
/// is at-most-once per timer fire — we clear the timer slot here so
/// the next `send_ipv4` re-arms it.
///
/// Per attr-bucket we encode at most:
/// - one **canonical** UPDATE containing every NLRI in the bucket
///   (sent to members whose ident does not appear as a source-ident
///   in the bucket — split-horizon clean for them);
/// - one **pruned** UPDATE per source-member, with that member's
///   sourced NLRIs removed.
///
/// `messages_formatted` increments per encoded variant;
/// `messages_replicated` per (UPDATE, member) pair sent;
/// `bytes_formatted` accumulates the encoded byte counts.
pub fn flush_ipv4(
    update_groups: &mut UpdateGroupMap,
    peers: &mut PeerMap,
    _attr_store: &mut BgpAttrStore,
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

    // Snapshot the cache and clear the timer slot so the next send
    // re-arms it. Drains both forward and reverse maps; the bucket
    // shape is `(attr, [(nlri, source_ident)])`.
    group.cache_ipv4_timer = None;
    let buckets: Vec<(Arc<BgpAttr>, Vec<(Ipv4Nlri, usize)>)> = group
        .cache_ipv4
        .drain()
        .map(|(attr, set)| (attr, set.into_iter().collect()))
        .collect();
    group.cache_ipv4_rev.clear();

    if buckets.is_empty() {
        return;
    }

    // Snapshot member idents + their packet_tx + max-packet-size
    // before mutating peer state; downstream sends only need the
    // cloned tx and the size, not a peer borrow.
    let max_packet_size = if group.sig.extended_message {
        bgp_packet::BGP_EXTENDED_PACKET_LEN
    } else {
        bgp_packet::BGP_PACKET_LEN
    };
    let enhe = group.sig.extended_next_hop;
    let member_idents: Vec<usize> = group.members.iter().copied().collect();

    // Resolve packet_tx and (when ENHE) per-member v6 next-hop up
    // front. The next-hop derives from each peer's egress ifindex
    // (`scope_id`), so it varies per member even within one
    // update-group; the canonical-bytes sharing the legacy path
    // relies on cannot apply.
    struct MemberCtx {
        ident: usize,
        tx: Option<mpsc::UnboundedSender<bytes::BytesMut>>,
        enhe_v6: Option<Ipv4MpReachNextHop>,
    }
    let members: Vec<MemberCtx> = member_idents
        .iter()
        .map(|ident| {
            let peer = peers.get_by_idx(*ident);
            let tx = peer.and_then(|p| p.packet_tx.clone());
            let enhe_v6 = if enhe {
                peer.and_then(|p| compose_enhe_next_hop(p, interface_addrs))
            } else {
                None
            };
            MemberCtx {
                ident: *ident,
                tx,
                enhe_v6,
            }
        })
        .collect();

    for (attr, entries) in buckets {
        // Members that need split-horizon pruning: any whose ident
        // appears as a source-ident in this bucket. Common case is
        // empty (group has no source-members for this bucket), in
        // which case every member shares the canonical UPDATE.
        let source_idents: BTreeSet<usize> = entries.iter().map(|(_, src)| *src).collect();
        let pruned_members: Vec<usize> = member_idents
            .iter()
            .copied()
            .filter(|m| source_idents.contains(m))
            .collect();

        if enhe {
            // Per-member encode: each member's v6 next-hop is its own
            // interface link-local; canonical-bytes sharing across
            // members would force every member onto the same LL,
            // which would break ENHE for everyone but one peer.
            for ctx in &members {
                let Some(tx) = ctx.tx.as_ref() else { continue };
                let Some(nh) = ctx.enhe_v6 else {
                    // ND hasn't observed any link-local on this
                    // peer's egress interface yet; the operator-side
                    // address-add events haven't reached BGP. Skip
                    // this member's flush — we'll re-cache on the
                    // next event arrival rather than emit a
                    // garbage next-hop.
                    continue;
                };
                let nlris: Vec<Ipv4Nlri> = entries
                    .iter()
                    .filter(|(_, src)| *src != ctx.ident)
                    .map(|(n, _)| n.clone())
                    .collect();
                if nlris.is_empty() {
                    if pruned_members.contains(&ctx.ident)
                        && let Some(group) = af.group_by_id_mut(id)
                    {
                        group.counters.split_horizon_excluded += 1;
                    }
                    continue;
                }
                let bytes_list = encode_ipv4_update(&attr, &nlris, max_packet_size, Some(nh));
                let byte_total: usize = bytes_list.iter().map(|b| b.len()).sum();
                for bytes in &bytes_list {
                    let _ = tx.send(bytes.clone());
                }
                if let Some(group) = af.group_by_id_mut(id) {
                    group.counters.messages_formatted += bytes_list.len() as u64;
                    group.counters.messages_replicated += bytes_list.len() as u64;
                    group.counters.bytes_formatted += byte_total as u64;
                    if pruned_members.contains(&ctx.ident) {
                        group.counters.split_horizon_excluded += 1;
                    }
                }
            }
            continue;
        }

        // Canonical UPDATE: every NLRI in the bucket.
        let canonical: Vec<Ipv4Nlri> = entries.iter().map(|(n, _)| n.clone()).collect();
        let canonical_bytes = encode_ipv4_update(&attr, &canonical, max_packet_size, None);
        let canonical_byte_total: usize = canonical_bytes.iter().map(|b| b.len()).sum();

        // Bump per-attr-bucket counters: one formatted variant
        // (canonical), bytes summed.
        if let Some(group) = af.group_by_id_mut(id) {
            group.counters.messages_formatted += canonical_bytes.len() as u64;
            group.counters.bytes_formatted += canonical_byte_total as u64;
        }

        // Send canonical to every non-pruned member.
        for ctx in &members {
            if pruned_members.contains(&ctx.ident) {
                continue;
            }
            if let Some(tx) = ctx.tx.as_ref() {
                for bytes in &canonical_bytes {
                    let _ = tx.send(bytes.clone());
                }
                if let Some(group) = af.group_by_id_mut(id) {
                    group.counters.messages_replicated += canonical_bytes.len() as u64;
                }
            }
        }

        // Per pruned member: encode bucket minus its sourced
        // NLRIs, then send.
        for prune_ident in pruned_members {
            let nlris: Vec<Ipv4Nlri> = entries
                .iter()
                .filter(|(_, src)| *src != prune_ident)
                .map(|(n, _)| n.clone())
                .collect();
            if nlris.is_empty() {
                if let Some(group) = af.group_by_id_mut(id) {
                    group.counters.split_horizon_excluded += 1;
                }
                continue;
            }
            let pruned_bytes = encode_ipv4_update(&attr, &nlris, max_packet_size, None);
            let pruned_byte_total: usize = pruned_bytes.iter().map(|b| b.len()).sum();
            if let Some(group) = af.group_by_id_mut(id) {
                group.counters.messages_formatted += pruned_bytes.len() as u64;
                group.counters.bytes_formatted += pruned_byte_total as u64;
                group.counters.split_horizon_excluded += 1;
            }
            if let Some(tx) = members
                .iter()
                .find(|c| c.ident == prune_ident)
                .and_then(|c| c.tx.as_ref())
            {
                for bytes in &pruned_bytes {
                    let _ = tx.send(bytes.clone());
                }
                if let Some(group) = af.group_by_id_mut(id) {
                    group.counters.messages_replicated += pruned_bytes.len() as u64;
                }
            }
        }
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
    peer: &Peer,
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
    let max_packet_size = if peer.opt.extended_message {
        bgp_packet::BGP_EXTENDED_PACKET_LEN
    } else {
        bgp_packet::BGP_PACKET_LEN
    };
    for (attr, nlris) in buckets {
        let bytes_list = encode_ipv4_update(&attr, &nlris, max_packet_size, extended_next_hop_v6);
        for buf in bytes_list {
            peer.send_packet(buf);
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
fn encode_ipv4_update(
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

/// Drain the IPv6 cache and ship UPDATEs to every member. Called from
/// `Bgp::serve` on `Message::FlushUpdateGroupIpv6`. Same canonical /
/// split-horizon-pruned encoding as [`flush_ipv4`], minus the ENHE
/// per-member next-hop step (v6 unicast next-hops are native and ride
/// on the bucket-key attr).
pub fn flush_ipv6(update_groups: &mut UpdateGroupMap, peers: &mut PeerMap, id: &UpdateGroupId) {
    let afi_safi = AfiSafi::new(Afi::Ip6, Safi::Unicast);
    let Some(af) = update_groups.get_mut(&afi_safi) else {
        return;
    };
    let Some(group) = af.group_by_id_mut(id) else {
        return;
    };

    group.cache_ipv6_timer = None;
    let buckets: Vec<(Arc<BgpAttr>, Vec<(Ipv6Nlri, usize)>)> = group
        .cache_ipv6
        .drain()
        .map(|(attr, set)| (attr, set.into_iter().collect()))
        .collect();
    group.cache_ipv6_rev.clear();
    if buckets.is_empty() {
        return;
    }

    let max_packet_size = if group.sig.extended_message {
        bgp_packet::BGP_EXTENDED_PACKET_LEN
    } else {
        bgp_packet::BGP_PACKET_LEN
    };
    let member_idents: Vec<usize> = group.members.iter().copied().collect();

    struct MemberCtx {
        ident: usize,
        tx: Option<mpsc::UnboundedSender<bytes::BytesMut>>,
    }
    let members: Vec<MemberCtx> = member_idents
        .iter()
        .map(|ident| MemberCtx {
            ident: *ident,
            tx: peers.get_by_idx(*ident).and_then(|p| p.packet_tx.clone()),
        })
        .collect();

    for (attr, entries) in buckets {
        let source_idents: BTreeSet<usize> = entries.iter().map(|(_, src)| *src).collect();
        let pruned_members: Vec<usize> = member_idents
            .iter()
            .copied()
            .filter(|m| source_idents.contains(m))
            .collect();

        // Canonical UPDATE: every NLRI in the bucket, sent to members
        // that did not source any of them.
        let canonical: Vec<Ipv6Nlri> = entries.iter().map(|(n, _)| n.clone()).collect();
        let canonical_bytes = encode_ipv6_update(&attr, &canonical, max_packet_size);
        let canonical_byte_total: usize = canonical_bytes.iter().map(|b| b.len()).sum();
        if let Some(group) = af.group_by_id_mut(id) {
            group.counters.messages_formatted += canonical_bytes.len() as u64;
            group.counters.bytes_formatted += canonical_byte_total as u64;
        }
        for ctx in &members {
            if pruned_members.contains(&ctx.ident) {
                continue;
            }
            if let Some(tx) = ctx.tx.as_ref() {
                for bytes in &canonical_bytes {
                    let _ = tx.send(bytes.clone());
                }
                if let Some(group) = af.group_by_id_mut(id) {
                    group.counters.messages_replicated += canonical_bytes.len() as u64;
                }
            }
        }

        // Per pruned member: the bucket minus its own sourced NLRIs.
        for prune_ident in pruned_members {
            let nlris: Vec<Ipv6Nlri> = entries
                .iter()
                .filter(|(_, src)| *src != prune_ident)
                .map(|(n, _)| n.clone())
                .collect();
            if nlris.is_empty() {
                if let Some(group) = af.group_by_id_mut(id) {
                    group.counters.split_horizon_excluded += 1;
                }
                continue;
            }
            let pruned_bytes = encode_ipv6_update(&attr, &nlris, max_packet_size);
            let pruned_byte_total: usize = pruned_bytes.iter().map(|b| b.len()).sum();
            if let Some(group) = af.group_by_id_mut(id) {
                group.counters.messages_formatted += pruned_bytes.len() as u64;
                group.counters.bytes_formatted += pruned_byte_total as u64;
                group.counters.split_horizon_excluded += 1;
            }
            if let Some(tx) = members
                .iter()
                .find(|c| c.ident == prune_ident)
                .and_then(|c| c.tx.as_ref())
            {
                for bytes in &pruned_bytes {
                    let _ = tx.send(bytes.clone());
                }
                if let Some(group) = af.group_by_id_mut(id) {
                    group.counters.messages_replicated += pruned_bytes.len() as u64;
                }
            }
        }
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
        out.push(update.into());
    }
    out
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
}
