use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use bytes::BytesMut;
use ipnet::{Ipv4Net, Ipv6Net};
use isis_packet::neigh::{self, IsisSubAdjSid};
use isis_packet::prefix::{self, Ipv4ControlInfo, Ipv6ControlInfo};
use isis_packet::*;

use crate::context::Timer;
use crate::isis::config::{
    IsisRedistAfi, IsisRedistLevel, IsisRedistMetricType, IsisRedistSource, IsisRedistribute,
};
use crate::isis_event_trace;
use crate::rib::util::IpNetExt;
use crate::rib::{DEFAULT_BLOCK_NAME, Locator, LocatorBehavior, MacAddr};

/// Per ISO 10589 §7.3.16.4, the additional grace beyond MaxAge a
/// purged LSP needs before any surviving copy is fully evicted from
/// every LSDB. Cisco treats this as a non-configurable constant.
const ZERO_AGE_LIFETIME: u16 = 60;

/// LSP PDU fixed-header overhead on the wire: the outer
/// `IsisPacket` header (8 bytes) plus the `IsisLsp` body's fixed
/// fields (pdu_len + hold_time + lsp_id + seq_number + checksum +
/// types = 19 bytes). Matches ISO 10589 length_indicator(L1Lsp) =
/// 27. The bin-packer subtracts this from the configured
/// originatingLSPBufferSize to get the per-fragment TLV byte budget.
const LSP_PDU_OVERHEAD: usize = 27;

/// Maximum TLV on-wire size (2-byte TL header + 255-byte value).
/// The 8-bit Length field silently wraps for larger TLVs, so the
/// per-instance splitter shards distributable TLVs whose entry
/// list overflows this boundary into multiple TLV instances of
/// the same type before the packer ever sees them.
const TLV_WIRE_MAX: usize = 257;

/// Stable identity for a single-entry distributable TLV instance.
/// Lets the packer place this TLV in the same fragment it lived in
/// last time we originated — so adding or removing a neighbor only
/// shifts that one TLV instead of reshuffling the whole set.
///
/// Multi-entry TLVs (TLV 135 / 236 / 237 / 222 with more than one
/// entry per instance) are not keyed in this first cut; the
/// splitter shards them and each shard's identity depends on entry
/// ordering, so per-entry stability needs a different model. Those
/// TLVs go through the greedy fall-back path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TlvKey {
    /// TLV 22 instance with exactly one neighbor entry. Our LSP
    /// builder emits one such instance per local adjacency, so the
    /// key uniquely identifies a per-adjacency TLV.
    ExtIsReach(IsisNeighborId),
}

/// Return the stable key for a TLV instance, if one is defined.
/// Used both for "where did this TLV go last time?" lookups and
/// for "record where this TLV ended up this time" writes.
pub(super) fn key_for_tlv(tlv: &IsisTlv) -> Option<TlvKey> {
    match tlv {
        IsisTlv::ExtIsReach(t) if t.entries.len() == 1 => {
            Some(TlvKey::ExtIsReach(t.entries[0].neighbor_id))
        }
        _ => None,
    }
}

use super::auth;
use super::config::{IsisAuthConfig, IsisAuthType, IsisConfig, MtId};
use super::ifsm::has_level;
use super::inst::{IsisTop, Message};
use super::level::Level;
use super::link::{IsisLinks, LinkTop};
use super::nfsm::NfsmState;

/// Decide which block this IS-IS instance should subscribe to.
///
/// `segment-routing mpls` enabled subscribes to the canonical "default"
/// block seeded by the RIB. When SR-MPLS is disabled there is no
/// subscription.
pub(super) fn target_block_name(cfg: &IsisConfig) -> Option<String> {
    if !cfg.sr_mpls_enabled {
        return None;
    }
    Some(DEFAULT_BLOCK_NAME.to_string())
}

/// Decide which locator this IS-IS instance should subscribe to.
///
/// SRv6 has no default locator: an enabled `segment-routing srv6` without
/// a `locator` selection means "no SRv6 SID TLV will be originated", so
/// no watch is registered.
pub(super) fn target_locator_name(cfg: &IsisConfig) -> Option<String> {
    if !cfg.sr_srv6_enabled {
        return None;
    }
    cfg.sr_srv6_locator.clone()
}

/// Resolve a pseudonode `neighbor_id` (sys_id + pseudo_id) back to the
/// local `ifindex` of the link where we currently hold the matching
/// DIS adjacency at `level`. Returns `None` when no link owns that
/// pseudonode — in that case the caller must skip origination, since
/// emitting an LSP without a real DIS link produces a corrupt
/// self-LSP (historical bug: invalid lsp_id, see issue tracking
/// `0000.0000.0000.00-00` injection).
pub fn resolve_dis_ifindex(
    links: &IsisLinks,
    level: Level,
    neighbor_id: IsisNeighborId,
) -> Option<u32> {
    links
        .iter()
        .find_map(|(idx, link)| match link.state.adj.get(&level) {
            Some((adj, _)) if *adj == neighbor_id => Some(*idx),
            _ => None,
        })
}

/// Entry-bearing TLV the splitter below can shard into multiple
/// instances of the same TLV type. `fresh` clones the per-instance
/// header (the 2-byte MT ID on TLV 222/237) with an empty entry
/// list.
trait SplittableTlv: Clone + Into<IsisTlv> {
    type Entry;
    fn fresh(&self) -> Self;
    fn entries_mut(&mut self) -> &mut Vec<Self::Entry>;
    fn into_entries(self) -> Vec<Self::Entry>;
}

impl SplittableTlv for IsisTlvExtIpReach {
    type Entry = IsisTlvExtIpReachEntry;
    fn fresh(&self) -> Self {
        Self::default()
    }
    fn entries_mut(&mut self) -> &mut Vec<Self::Entry> {
        &mut self.entries
    }
    fn into_entries(self) -> Vec<Self::Entry> {
        self.entries
    }
}

impl SplittableTlv for IsisTlvIpv6Reach {
    type Entry = IsisTlvIpv6ReachEntry;
    fn fresh(&self) -> Self {
        Self::default()
    }
    fn entries_mut(&mut self) -> &mut Vec<Self::Entry> {
        &mut self.entries
    }
    fn into_entries(self) -> Vec<Self::Entry> {
        self.entries
    }
}

impl SplittableTlv for IsisTlvMtIsReach {
    type Entry = IsisTlvExtIsReachEntry;
    fn fresh(&self) -> Self {
        Self {
            mt: self.mt,
            entries: Vec::new(),
        }
    }
    fn entries_mut(&mut self) -> &mut Vec<Self::Entry> {
        &mut self.entries
    }
    fn into_entries(self) -> Vec<Self::Entry> {
        self.entries
    }
}

impl SplittableTlv for IsisTlvMtIpv6Reach {
    type Entry = IsisTlvIpv6ReachEntry;
    fn fresh(&self) -> Self {
        Self {
            mt: self.mt,
            entries: Vec::new(),
        }
    }
    fn entries_mut(&mut self) -> &mut Vec<Self::Entry> {
        &mut self.entries
    }
    fn into_entries(self) -> Vec<Self::Entry> {
        self.entries
    }
}

/// Split a TLV whose serialized value would overflow the 8-bit
/// Length field into multiple TLV instances of the same type, each
/// ≤ 255 value-bytes. Entries are distributed left-to-right;
/// placement is stable per entry order. Covers TLV 135 (Extended IP
/// Reachability), 236 (IPv6 Reachability), 222 (MT IS Reachability)
/// and 237 (MT IPv6 Reachability); the MT variants keep their MT ID
/// prefix on every output instance.
fn split_tlv_entries<T: SplittableTlv>(t: T) -> Vec<IsisTlv> {
    let template = t.fresh();
    let mut out: Vec<IsisTlv> = Vec::new();
    let mut current = template.clone();
    for entry in t.into_entries() {
        current.entries_mut().push(entry);
        let probe: IsisTlv = current.clone().into();
        if probe.wire_len() > TLV_WIRE_MAX {
            let latest = current.entries_mut().pop().expect("just pushed");
            if !current.entries_mut().is_empty() {
                out.push(current.into());
            }
            current = template.clone();
            current.entries_mut().push(latest);
        }
    }
    if !current.entries_mut().is_empty() {
        out.push(current.into());
    }
    out
}

/// Shard any distributable TLV whose on-wire size exceeds the
/// 257-byte TLV-instance ceiling into multiple instances of the
/// same TLV type. TLVs already within budget pass through
/// unchanged. Variants without an entry-list (e.g. `IsisTlv::Srv6`
/// carrying a single locator) cannot be split below the TLV level
/// without changing protocol semantics and so pass through; the
/// caller must keep those locator sub-TLVs small enough on its own.
fn split_distributable_at_255(tlv: IsisTlv) -> Vec<IsisTlv> {
    if tlv.wire_len() <= TLV_WIRE_MAX {
        return vec![tlv];
    }
    match tlv {
        IsisTlv::ExtIpReach(t) => split_tlv_entries(t),
        IsisTlv::Ipv6Reach(t) => split_tlv_entries(t),
        IsisTlv::MtIsReach(t) => split_tlv_entries(t),
        IsisTlv::MtIpv6Reach(t) => split_tlv_entries(t),
        other => vec![other],
    }
}

/// Greedy first-fit bin-packing of a self-originated TLV set into
/// LSP fragments. Fragment 0 always exists and carries the anchor
/// TLVs (area address, hostname, capability, etc. — TLVs that the
/// IS-IS spec permits in fragment 0 only). Distributable TLVs
/// (reach entries, SRv6 locators, ...) flow into the lowest-numbered
/// fragment that has room; a new fragment opens when no existing
/// one can hold the next TLV.
///
/// Each fragment's `seq_number` is left at 0 on return; the caller
/// resolves seq per fragment ID against the LSDB (with the per-frag
/// wrap-detection rules) before emit. Likewise the caller stamps
/// OL/ATT bits on `types`; today those bits ride identically on
/// every fragment because we don't expose them yet.
///
/// LSPDBOverflow (RFC 5311 territory — > 256 fragments) is logged
/// and the trailing TLVs are dropped. A future extension via RFC
/// 5311 virtual sys-IDs will widen the namespace.
fn pack_into_fragments(
    anchors: Vec<IsisTlv>,
    distributable: Vec<IsisTlv>,
    base: IsisNeighborId,
    types: IsisLspTypes,
    hold_time: u16,
    lsp_mtu_size: u16,
    memory: Option<&BTreeMap<TlvKey, u8>>,
) -> Vec<IsisLsp> {
    let mtu = lsp_mtu_size as usize;
    let budget = mtu.saturating_sub(LSP_PDU_OVERHEAD);

    let mut frags: Vec<IsisLsp> = Vec::new();
    let mut frag_bytes: Vec<usize> = Vec::new();

    // Fragment 0 starts with the anchor TLVs. If they alone exceed
    // the budget the originator is misconfigured (lsp-mtu-size too
    // small to even carry the per-node attributes); proceed anyway
    // and let the wire emit silently truncate — operators will see
    // it immediately in `show isis database`.
    let anchor_bytes: usize = anchors.iter().map(|t| t.wire_len()).sum();
    frags.push(IsisLsp {
        hold_time,
        lsp_id: IsisLspId::from_neighbor_id(base, 0),
        types,
        tlvs: anchors,
        ..Default::default()
    });
    frag_bytes.push(anchor_bytes);

    // Pre-open any non-zero fragments that the memory expects to
    // exist, so a hint pointing at frag 5 finds a slot even if
    // earlier-in-iteration TLVs haven't filled up frags 1..4 yet.
    // Empty fragments at the tail are valid wire output — receivers
    // accept them — and the tail-purge logic in
    // `process_lsp_originate` retires any that go unused.
    if let Some(m) = memory
        && let Some(&max_hint) = m.values().max()
        && max_hint > 0
    {
        for i in 1..=max_hint as usize {
            if i >= frags.len() {
                let frag_id = i as u8;
                frags.push(IsisLsp {
                    hold_time,
                    lsp_id: IsisLspId::from_neighbor_id(base, frag_id),
                    types,
                    tlvs: Vec::new(),
                    ..Default::default()
                });
                frag_bytes.push(0);
            }
        }
    }

    for tlv in distributable {
        let n = tlv.wire_len();

        // Honor the placement memory first: if this TLV has a stable
        // key and the remembered fragment still has room, slot it
        // there. Falls through to greedy when the hint is stale (no
        // remembered fragment, fragment gone, or doesn't fit).
        let hint = memory
            .and_then(|m| key_for_tlv(&tlv).and_then(|k| m.get(&k)))
            .copied();
        let target = hint
            .filter(|&h| (h as usize) < frags.len() && frag_bytes[h as usize] + n <= budget)
            .map(|h| h as usize)
            .or_else(|| (0..frags.len()).find(|&i| frag_bytes[i] + n <= budget));

        match target {
            Some(i) => {
                frags[i].tlvs.push(tlv);
                frag_bytes[i] += n;
            }
            None => {
                if frags.len() >= 256 {
                    tracing::warn!(
                        "[LspPack] LSPDBOverflow: cannot fit TLV (wire_len={}) in any of 256 fragments; dropping",
                        n
                    );
                    break;
                }
                let frag_id = frags.len() as u8;
                frags.push(IsisLsp {
                    hold_time,
                    lsp_id: IsisLspId::from_neighbor_id(base, frag_id),
                    types,
                    tlvs: vec![tlv],
                    ..Default::default()
                });
                frag_bytes.push(n);
            }
        }
    }

    // Drop trailing empty fragments — these are pre-opened slots
    // for hints that turned out to be stale (or never reached).
    // Keeping them would emit empty LSPs and trigger tail-purge
    // unnecessarily on the very next origination.
    while frags.len() > 1 && frag_bytes.last() == Some(&0) {
        frags.pop();
        frag_bytes.pop();
    }

    frags
}

pub fn dis_generate(
    top: &mut IsisTop,
    level: Level,
    ifindex: u32,
    base: Option<u32>,
) -> Vec<IsisLsp> {
    let neighbor_id = if let Some(link) = top.links.get(&ifindex)
        && let Some((adj, _)) = link.state.adj.get(&level)
    {
        *adj
    } else {
        return Vec::new();
    };

    let frag0_id = IsisLspId::from_neighbor_id(neighbor_id, 0);
    // Pseudonode LSPs ride the same overload posture as the DIS's
    // own router LSP — when we're flagged overloaded post-restart
    // (RFC 5306 §3.1 exit-failure), the LAN's pseudonode is too.
    let types = IsisLspTypes::from(level.digit()).with_ol_bits(top.overloaded);

    // Build the single TLV 22 listing the DIS itself plus every Up
    // neighbor on this LAN, then defer to the same splitter/packer
    // used by router LSPs. Pseudonode LSPs carry no anchor TLVs
    // (no hostname / cap / OL bit lives here — those belong to the
    // DIS's own router LSP).
    let mut is_reach = IsisTlvExtIsReach::default();
    is_reach.entries.push(IsisTlvExtIsReachEntry {
        neighbor_id: IsisNeighborId::from_sys_id(&top.config.net.sys_id(), 0),
        metric: 0,
        subs: vec![],
    });
    if let Some(link) = top.links.get(&ifindex) {
        for (sys_id, nbr) in link.state.nbrs.get(&level).iter() {
            if nbr.state == NfsmState::Up {
                is_reach.entries.push(IsisTlvExtIsReachEntry {
                    neighbor_id: IsisNeighborId::from_sys_id(sys_id, 0),
                    metric: 0,
                    subs: vec![],
                });
            }
        }
    }

    let distributable: Vec<IsisTlv> = if is_reach.entries.is_empty() {
        Vec::new()
    } else {
        split_distributable_at_255(IsisTlv::ExtIsReach(is_reach))
    };

    // Pseudonode LSPs don't use placement memory today — see
    // `Isis::lsp_placement_memory`. The LAN's neighbor list rarely
    // churns once DIS election settles, so the cost-benefit of a
    // per-pseudonode memory map isn't there yet.
    let mut fragments = pack_into_fragments(
        Vec::new(),
        distributable,
        neighbor_id,
        types,
        top.config.hold_time(),
        top.config.lsp_mtu_size(),
        None,
    );

    // Resolve seq numbers per fragment. Fragment 0 honors `base`
    // (the seq we saw a peer reflect at us, ISO 10589 §7.3.16.4) in
    // addition to the existing LSDB seq. Higher fragments derive
    // from their own LSDB entries with saturating_add. Per-fragment
    // seq-wrap detection mirrors the router-LSP behaviour: only
    // fragment 0's wrap freezes origination of the whole pseudonode
    // LSP set (a receiver with frag 0 missing can't enumerate the
    // LAN's members at all), so for higher fragments we fall back
    // to the simple existing+1 rule without arming a freeze. A
    // dedicated per-fragment pseudonode freeze would mirror the
    // router-LSP path; deferred until the wrap actually fires here.
    for frag in fragments.iter_mut() {
        if frag.lsp_id.fragment_id() == 0 {
            let existing = top
                .lsdb
                .get(&level)
                .get(&frag0_id)
                .map(|x| x.lsp.seq_number);
            frag.seq_number = match (existing, base) {
                (Some(e), Some(b)) => e.max(b).saturating_add(1),
                (Some(e), None) => e.saturating_add(1),
                (None, Some(b)) => b.saturating_add(1),
                (None, None) => 0x0001,
            };
        } else {
            let existing = top
                .lsdb
                .get(&level)
                .get(&frag.lsp_id)
                .map(|x| x.lsp.seq_number);
            frag.seq_number = existing.map(|e| e.saturating_add(1)).unwrap_or(0x0001);
        }
    }

    fragments
}

/// SID Structure sub-sub-TLV (RFC 9352 §9) for one locator: the
/// locator's behavior plus `[structure]` when it has a prefix, `None`
/// when it doesn't (no structure to advertise). Geometry comes from
/// `Locator::sid_structure()` — the same source the FIB installs from —
/// so the wire and the data plane can't drift. Note REPLACE-C-SID
/// advertises a non-zero argument length (AL = 128-LBL-LNFL): that is
/// how RFC 9800 §6.4 receivers infer the compression scheme.
fn srv6_sid_structure(locator: &Locator) -> Option<(Option<LocatorBehavior>, Vec<IsisSub2Tlv>)> {
    let st = locator.sid_structure()?;
    let structure = IsisSub2Tlv::SidStructure(IsisSub2SidStructure {
        lb_len: st.lb_bits,
        ln_len: st.ln_bits,
        fun_len: st.fun_bits,
        arg_len: st.arg_bits,
    });
    Some((locator.behavior.clone(), vec![structure]))
}

/// Fold a locator's configured RFC 8986 §4.16 flavor mask into a base
/// endpoint behavior — the advertised codepoint must carry the flavors
/// the data plane executes.
fn flavored(base: Behavior, mask: u8) -> Behavior {
    base.with_flavors(
        mask & crate::rib::FLAVOR_PSP != 0,
        mask & crate::rib::FLAVOR_USP != 0,
        mask & crate::rib::FLAVOR_USD != 0,
    )
}

/// SRv6 End-SID endpoint behavior + SID Structure for one locator
/// (RFC 9352 §9). Classic → `End`; uSID → `EndCSID` (uN); REPLACE →
/// `EndRep`; each folded with the locator's flavors. Per-locator so
/// each per-Flex-Algorithm locator gets its own structure.
fn srv6_end_structure(locator: &Locator) -> (Behavior, Vec<IsisSub2Tlv>) {
    // A VRF-bound locator advertises its node SID as End.T / uT
    // (RFC 8986 §4.3): the End walk's egress lookup is table-scoped.
    let table_bound = locator.table_id != 0;
    let (base, subs) = match srv6_sid_structure(locator) {
        Some((Some(LocatorBehavior::Usid), subs)) if table_bound => (Behavior::EndTCSID, subs),
        Some((Some(LocatorBehavior::Usid), subs)) => (Behavior::EndCSID, subs),
        Some((Some(LocatorBehavior::Replace), subs)) => (Behavior::EndRep, subs),
        Some((None, subs)) if table_bound => (Behavior::EndT, subs),
        Some((None, subs)) => (Behavior::End, subs),
        None => (Behavior::End, Vec::new()),
    };
    (flavored(base, locator.flavors), subs)
}

/// SRv6 End.X SID endpoint behavior + SID Structure for one locator
/// (RFC 9352 §8/§9). Classic → `EndX`; uSID → `EndXCSID` (uA); REPLACE
/// → `EndXRep`. The End.X sibling of `srv6_end_structure`. Adjacency
/// SIDs fold only the PSP flavor — their USP/USD variants are not
/// implemented in the data plane, so they must not be advertised
/// either.
fn srv6_endx_structure(locator: &Locator) -> (Behavior, Vec<IsisSub2Tlv>) {
    let (base, subs) = match srv6_sid_structure(locator) {
        Some((Some(LocatorBehavior::Usid), subs)) => (Behavior::EndXCSID, subs),
        Some((Some(LocatorBehavior::Replace), subs)) => (Behavior::EndXRep, subs),
        Some((None, subs)) => (Behavior::EndX, subs),
        None => (Behavior::EndX, Vec::new()),
    };
    (
        flavored(base, locator.flavors & crate::rib::FLAVOR_PSP),
        subs,
    )
}

/// SRv6 Mirror SID sub-TLVs to advertise inside the base SRv6 Locator
/// TLV (draft-ietf-rtgwg-srv6-egress-protection). For each configured
/// egress-protection entry on the SRv6 dataplane whose Mirror SID is
/// explicitly set and falls within `local_prefix` (this node's own
/// locator — the End.M SID is hosted here and inherits the locator's
/// topology/algorithm), emit one End.M sub-TLV carrying the protected
/// egress's locator in a Protected Locators sub-sub-TLV.
///
/// Entries without an explicit `mirror-sid`, or whose SID falls outside
/// the local locator, are skipped: auto-allocation is a follow-up, and a
/// SID outside the locator can't be instantiated here.
fn mirror_sid_subs(
    entries: &super::egress_protection::MirrorProtectMap,
    local_prefix: Ipv6Net,
) -> Vec<prefix::IsisSubTlv> {
    use super::egress_protection::MirrorDataplane;
    let mut subs = Vec::new();
    for entry in entries.values() {
        if entry.dataplane != MirrorDataplane::Srv6 {
            continue;
        }
        let Some(sid) = entry.mirror_sid else {
            continue;
        };
        if !local_prefix.contains(&sid) {
            continue;
        }
        // SRv6 protected locators are always IPv6.
        let ipnet::IpNet::V6(protected_locator) = entry.protected_locator else {
            continue;
        };
        subs.push(prefix::IsisSubTlv::Srv6MirrorSid(IsisSubSrv6MirrorSid {
            flags: 0,
            behavior: Behavior::EndM,
            sid,
            sub2s: vec![IsisMirrorSub2Tlv::ProtectedLocators(
                IsisSub2ProtectedLocators {
                    locator: protected_locator,
                },
            )],
        }));
    }
    subs
}

/// Build the SR-MPLS Mirror Context Binding TLVs (149) for this node's
/// `dataplane: mpls` egress-protection entries. One TLV per entry whose
/// context label is allocated (`mirror_labels`), with the M-flag set
/// (Mirror Context, RFC 8679), the protected egress's loopback as the
/// FEC (IPv4 for the SR-MPLS transport, or IPv6), and the context label
/// in a SID/Label sub-TLV. Entries without an allocated label (SR-MPLS
/// not yet up) are skipped — they re-emit once `update_mirror_labels`
/// allocates from the SRLB.
fn mirror_binding_tlvs(
    entries: &super::egress_protection::MirrorProtectMap,
    labels: &std::collections::BTreeMap<ipnet::IpNet, u32>,
) -> Vec<IsisTlv> {
    use super::egress_protection::MirrorDataplane;
    use isis_packet::{
        BindingFlags, BindingPrefix, IsisBindingSubTlv, IsisTlvSidLabelBinding, SidLabelValue,
    };
    let mut tlvs = Vec::new();
    for entry in entries.values() {
        if entry.dataplane != MirrorDataplane::Mpls {
            continue;
        }
        let Some(&label) = labels.get(&entry.protected_locator) else {
            continue;
        };
        // F-flag selects the FEC address family (0 = IPv4, 1 = IPv6).
        let (prefix, f_flag) = match entry.protected_locator {
            ipnet::IpNet::V4(p) => (BindingPrefix::V4(p), false),
            ipnet::IpNet::V6(p) => (BindingPrefix::V6(p), true),
        };
        tlvs.push(IsisTlv::SidLabelBinding(IsisTlvSidLabelBinding {
            flags: BindingFlags::new().with_m_flag(true).with_f_flag(f_flag),
            weight: 0,
            range: 1,
            prefix,
            subs: vec![IsisBindingSubTlv::SidLabel(SidLabelValue::Label(label))],
        }));
    }
    tlvs
}

/// Per-Flexible-Algorithm SRv6 End.X (adjacency) sub-TLVs for one
/// neighbor (RFC 9352 §8, Algorithm = N). One per entry in
/// `nbr.algo_endx_sids` whose per-algo locator is still resolved; the
/// behavior / structure come from that algo's locator. P2P emits
/// `Srv6EndXSid`, LAN emits `Srv6LanEndXSid`.
fn srv6_algo_endx_subs(
    nbr: &super::neigh::Neighbor,
    flex_algo_locators: &std::collections::BTreeMap<u8, Locator>,
) -> Vec<neigh::IsisSubTlv> {
    let mut subs = Vec::new();
    for (algo, endx) in nbr.algo_endx_sids.iter() {
        let Some(locator) = flex_algo_locators.get(algo) else {
            continue;
        };
        let (behavior, sub2s) = srv6_endx_structure(locator);
        if nbr.network_type.is_p2p() {
            subs.push(neigh::IsisSubTlv::Srv6EndXSid(IsisSubSrv6EndXSid {
                flags: 0,
                algo: Algo::FlexAlgo(*algo),
                weight: 0,
                behavior,
                sid: endx.addr,
                sub2s,
            }));
        } else {
            subs.push(neigh::IsisSubTlv::Srv6LanEndXSid(IsisSubSrv6LanEndXSid {
                system_id: nbr.sys_id,
                flags: 0,
                algo: Algo::FlexAlgo(*algo),
                weight: 0,
                behavior,
                sid: endx.addr,
                sub2s,
            }));
        }
    }
    subs
}

pub fn lsp_generate(top: &mut IsisTop, level: Level, seq_floor: Option<u32>) -> Vec<IsisLsp> {
    // Fragment 0 is the anchor for the originator's per-node attributes
    // (hostname, area, capability, OL/ATT) and the only LSP whose seq is
    // gated by `seq_floor` and the seq-wrap-up freeze. Higher fragments
    // exist only when distributable TLVs spill past `lsp_mtu_size` and
    // get their own seq from the LSDB at emit time.
    let frag0_id = IsisLspId::new(top.config.net.sys_id(), 0, 0);

    // ISO 10589 §7.3.16.4: when fragment 0's previous origination's
    // seq hit 0xFFFFFFFF we sent a purge and armed a freeze. While
    // that freeze is active we must not emit any of the LSP set —
    // receivers treat a router whose fragment 0 is absent as missing
    // its node-wide attributes (hostname, capability, OL bit) and
    // drop it from SPF, so refreshing higher fragments while frag 0
    // is in zero-age limbo would just churn the network. Higher
    // fragments' freezes are scoped to that one fragment and handled
    // post-pack below.
    if top.lsp_seq_wrap_wait.get(&level).contains_key(&0) {
        isis_event_trace!(
            top.tracing,
            LspOriginate,
            &level,
            "[LspOriginate] suppressed — fragment 0 seq-wrap freeze in effect"
        );
        return Vec::new();
    }

    // ISO 10589 §7.3.16.4: when a peer floods our own LSP back at us
    // with `recv_seq > existing_seq`, we have to bump the next
    // emission past `recv_seq` so the network converges on our
    // authoritative copy. `seq_floor` carries that signal. Applied
    // only to fragment 0 here — the only LSP whose ID the trigger
    // path currently observes. Per-fragment floor handling is a
    // follow-up alongside per-fragment seq-wrap.
    //
    // `saturating_add` guards every arm — the wrap-detection branch
    // below sees u32::MAX whether we got there from existing == MAX
    // (post-purge LSDB entry) or from existing == MAX - 1 (first
    // bump that trips the boundary).
    let frag0_existing = top
        .lsdb
        .get(&level)
        .get(&frag0_id)
        .map(|x| x.lsp.seq_number);
    let frag0_seq = match (frag0_existing, seq_floor) {
        (Some(e), Some(f)) => e.max(f).saturating_add(1),
        (Some(e), None) => e.saturating_add(1),
        (None, Some(f)) => f.saturating_add(1),
        (None, None) => 0x0001,
    };

    isis_event_trace!(
        top.tracing,
        LspOriginate,
        &level,
        "[LspOriginate] Seq:0x{:08x} Self Originate",
        frag0_seq
    );

    // ISO 10589 §7.3.16.4: sequence-number wrap-up for fragment 0.
    //
    // Emit one final LSP at seq = 0xFFFFFFFF with RemainingLifetime
    // = 0 (the purge), then freeze origination for
    // `lsp_hold_time + ZeroAgeLifetime` so any surviving copy in any
    // peer's LSDB has fully aged out. When the freeze clears, the
    // LSDB entry is dropped and the next origination computes
    // seq = 1 from scratch. Fragment 0's freeze is special — its
    // absence makes the whole node unusable for SPF — so it short-
    // circuits the entire origination. Higher fragments wrap
    // independently and only suppress their own re-emission.
    if frag0_seq == u32::MAX {
        isis_event_trace!(
            top.tracing,
            LspOriginate,
            &level,
            "[LspSeqWrap] fragment 0 hit u32::MAX — purging and freezing origination"
        );
        arm_seq_wrap_freeze(top, level, frag0_id);
        return Vec::new();
    }

    // From here on, TLVs are collected into two buckets:
    //   - `anchors` — frag-0-only attributes (area, hostname, proto
    //     supported, lsp-buffer-size, capability, MT capability,
    //     TE router-id);
    //   - `distributable` — TLVs that may be spread across frags 0..N
    //     (SRv6 locators, IS-Reach, MT IS-Reach, IP-Reach, IPv6-Reach,
    //     MT IPv6-Reach).
    // The packer then bin-packs them into fragments under `lsp_mtu_size`.
    // OL bit reflects `top.overloaded` — set by `gr_restart_expire` when
    // the GR exit-failure path fires; cleared 30s later by
    // `Message::ClearOverload` (RFC 5306 §3.1).
    let types = IsisLspTypes::from(level.digit()).with_ol_bits(top.overloaded);
    let mut anchors: Vec<IsisTlv> = Vec::new();
    let mut distributable: Vec<IsisTlv> = Vec::new();

    // Area address.
    let area_addr = top.config.net.area_id.clone();
    anchors.push(IsisTlvAreaAddr { area_addr }.into());

    // Supported protocol.
    let mut nlpids = vec![];
    if top.config.enable.v4 > 0 {
        nlpids.push(IsisProto::Ipv4.into());
    }
    if top.config.enable.v6 > 0 {
        nlpids.push(IsisProto::Ipv6.into());
    }
    if !nlpids.is_empty() {
        anchors.push(IsisTlvProtoSupported { nlpids }.into());
    }

    // Originating LSP Buffer Size (TLV 14, RFC 1195). Advertises the
    // PDU size we accept on this link; peers cap their own fragments
    // against this value when sending to us. Frag-0 only — receivers
    // ignore TLV 14 outside fragment 0.
    anchors.push(
        IsisTlvLspBufferSize {
            size: top.config.lsp_mtu_size(),
        }
        .into(),
    );

    // Hostname (RFC 5301). Configured value wins, then the OS hostname.
    // If neither is available, skip the TLV entirely and clear any
    // stale entry from the local hostname map so show output falls
    // back to the system ID instead of advertising "default".
    if let Some(hostname) = top.config.hostname() {
        top.hostname
            .get_mut(&level)
            .insert_originate(top.config.net.sys_id(), hostname.clone());
        anchors.push(IsisTlvHostname { hostname }.into());
    } else {
        top.hostname
            .get_mut(&level)
            .remove(&top.config.net.sys_id());
    }

    // SR Capability.
    if top.config.sr_enabled() {
        // Effective router-id: configured te_router_id wins, else fall back to the
        // RIB-derived id, else 0.0.0.0.
        let router_id: Ipv4Addr = top
            .config
            .te_router_id
            .or(top.config.rib_router_id)
            .unwrap_or(Ipv4Addr::UNSPECIFIED);

        // Router Capability.
        let mut cap = IsisTlvRouterCap {
            router_id,
            flags: 0.into(),
            subs: Vec::new(),
        };

        // SR-MPLS Capability sub-TLVs. Pulled from the RIB-side block
        // snapshot (kept fresh via SrSubscribe / SrBlockWatch). When the
        // configured block name doesn't resolve in the RIB the snapshot
        // is None and we skip emitting the sub-TLVs entirely — better to
        // advertise nothing than stale or fabricated values.
        if top.config.sr_mpls_enabled
            && let Some(block) = top.sr_block.as_ref()
        {
            if let Some(global) = block.global.as_ref() {
                let mut flags = SegmentRoutingCapFlags::default();
                flags.set_i_flag(true);
                flags.set_v_flag(true);
                let sid_label = SidLabelTlv::Label(global.start);
                let sr_cap = IsisSubSegmentRoutingCap {
                    flags,
                    range: global.end - global.start,
                    sid_label,
                };
                cap.subs.push(sr_cap.into());
            }

            // Sub: SR Algorithms — Algo::Spf plus every flex-algo
            // we participate in (RFC 9350 §5.2 requires participants
            // to advertise here, not just FAD originators).
            let algo = IsisSubSegmentRoutingAlgo {
                algo: super::flex_algo::sr_algorithms(top.flex_algo),
            };
            cap.subs.push(algo.into());

            // Sub: SR Local Block
            if let Some(local) = block.local.as_ref() {
                let sid_label = SidLabelTlv::Label(local.start);
                let lb = IsisSubSegmentRoutingLB {
                    flags: 0,
                    range: local.end - local.start,
                    sid_label,
                };
                cap.subs.push(lb.into());
            }
        }

        // SRv6 Capability sub-TLV. Only advertise when at least one
        // locator (the algo-0 base or any per-Flex-Algorithm locator)
        // actually resolved in the RIB; an `srv6` container with no
        // usable locator means we have nothing to derive a SID from, so
        // we don't claim SRv6 capability. Including the per-algo
        // locators here lets an SRv6-only Flex-Algo config advertise its
        // SR-Algorithm participation even without a base locator.
        if top.config.sr_srv6_enabled
            && (top.sr_locator.is_some() || !top.sr_flex_algo_locators.is_empty())
        {
            let srv6 = IsisSubSrv6::default();
            cap.subs.push(srv6.into());

            // SR-MPLS already pushed Algorithms; for an SRv6-only config
            // we still need to advertise the algorithm list once.
            if !top.config.sr_mpls_enabled {
                let algo = IsisSubSegmentRoutingAlgo {
                    algo: super::flex_algo::sr_algorithms(top.flex_algo),
                };
                cap.subs.push(algo.into());
            }
        }

        // Flex-Algorithm Definitions (RFC 9350 §5.1). One sub-TLV per
        // entry the operator marked `advertise-definition true`;
        // entries without the flag stay purely local (the router
        // computes for them using a FAD learned from another node).
        // Per-algo SR Algorithm sub-TLV participation extension and
        // per-link ASLA admin-group emit land in follow-up PRs.
        for fad in
            super::flex_algo::build_fad_subs(top.flex_algo, top.affinity_map, top.srlg_groups)
        {
            cap.subs.push(fad.into());
        }

        anchors.push(cap.into());
    }

    // SRv6 endpoint behavior + SID Structure SubSub TLV (RFC 9352 §9,
    // type 1), keyed off the locator's behavior. Computed once per LSP
    // and reused by every End / End.X SID we emit, since they all share
    // the locator and the same fixed 16-bit function space.
    //
    //   classic (no behavior leaf): End / End.X codepoints, LB caps
    //     at 40 (IPv6 DOC / SR block size most deployments use). For a
    //     /64 → LB=40, LN=24; /48 → LB=40, LN=8.
    //   uSID (RFC 9800 NEXT-C-SID): uN / uA codepoints, LB caps at 32
    //     (the typical uSID block size). /32 → LB=32, LN=0; /48 →
    //     LB=32, LN=16.
    //
    // Function is 16 bits — the width function_addr() places into the
    // SID. Argument is 0; we don't allocate argument-bearing SIDs.
    let (end_behavior, endx_behavior, sid_structure_subs) = match top.sr_locator.as_ref() {
        Some(loc) if loc.prefix.is_some() => {
            let (end_behavior, subs) = srv6_end_structure(loc);
            let (endx_behavior, _) = srv6_endx_structure(loc);
            (end_behavior, endx_behavior, subs)
        }
        _ => (Behavior::End, Behavior::EndX, Vec::new()),
    };

    // SRv6 Locators TLV (RFC 9352 §7.1, type 27). One sub-locator for
    // the base (algo-0) locator plus one per Flexible-Algorithm locator
    // binding, each carrying its node End SID (RFC 9352 §7.2). Per-algo
    // locators are advertised ONLY here (Algorithm field = N) — never as
    // plain IPv6 Reachability TLVs — so receivers route each one in its
    // own algorithm's constrained topology rather than over the
    // unconstrained algo-0 SPF.
    let mut srv6_locators: Vec<Srv6Locator> = Vec::new();
    if let Some(locator) = top.sr_locator.as_ref()
        && let Some(end_sid) = *top.sr_end_sid
        && let Some(prefix) = locator.prefix
    {
        let mut subs = vec![prefix::IsisSubTlv::Srv6EndSid(IsisSubSrv6EndSid {
            flags: 0,
            behavior: end_behavior,
            sid: end_sid,
            sub2s: sid_structure_subs.clone(),
        })];
        // Mirror SID sub-TLVs (draft-ietf-rtgwg-srv6-egress-protection):
        // one End.M per configured SRv6 egress-protection entry whose
        // Mirror SID falls within this (the protector's) locator. The SID
        // inherits the locator's topology/algorithm; the protected
        // egress's locator rides in a Protected Locators sub-sub-TLV.
        subs.extend(mirror_sid_subs(&top.config.egress_protections, prefix));
        srv6_locators.push(Srv6Locator {
            metric: 0,
            flags: 0,
            algo: Algo::Spf,
            locator: prefix,
            subs,
        });
    }
    for (&algo, locator) in top.sr_flex_algo_locators.iter() {
        let Some(end_sid) = top.sr_flex_algo_end_sid.get(&algo).copied() else {
            continue;
        };
        let Some(prefix) = locator.prefix else {
            continue;
        };
        let (behavior, sub2s) = srv6_end_structure(locator);
        srv6_locators.push(Srv6Locator {
            metric: 0,
            flags: 0,
            algo: Algo::FlexAlgo(algo),
            locator: prefix,
            subs: vec![prefix::IsisSubTlv::Srv6EndSid(IsisSubSrv6EndSid {
                flags: 0,
                behavior,
                sid: end_sid,
                sub2s,
            })],
        });
    }
    if !srv6_locators.is_empty() {
        distributable.push(IsisTlv::Srv6(IsisTlvSrv6 {
            flags: Default::default(),
            locators: srv6_locators,
        }));
    }

    // SR-MPLS Mirror Context bindings (RFC 8667 §2.4 + RFC 8679): one
    // SID/Label Binding TLV (149) with the M-flag per `dataplane: mpls`
    // egress-protection entry whose context label is allocated.
    distributable.extend(mirror_binding_tlvs(
        &top.config.egress_protections,
        top.mirror_labels,
    ));

    // Multi-Topology TLV (229) — RFC 5120 §7.1. Lists the MT IDs
    // this router participates in. Receivers use it to decide which
    // MT-keyed TLVs to expect (TLV 222 / 235 / 237) and which graphs
    // we belong to. Only emitted when MT is enabled and at least one
    // topology is configured.
    if top.config.mt_enabled && !top.config.mt_topologies.is_empty() {
        let entries: Vec<MultiTopologyId> = top
            .config
            .mt_topologies
            .iter()
            .map(|id| MultiTopologyId::from(id.wire_id()))
            .collect();
        let mt_tlv = IsisTlvMultiTopology { entries };
        anchors.push(mt_tlv.into());
    }

    // TE Router ID. Prefer configured value, fall back to RIB-derived.
    if top.config.sr_enabled()
        && let Some(router_id) = top.config.te_router_id.or(top.config.rib_router_id)
    {
        let te_router_id = IsisTlvTeRouterId { router_id };
        anchors.push(te_router_id.into());
    }

    // IS Reachability.
    for (_, link) in top.links.iter() {
        let Some((adj, _)) = &link.state.adj.get(&level) else {
            continue;
        };

        // Ext IS Reach.
        let mut ext_is_reach = IsisTlvExtIsReach::default();
        let mut is_reach = IsisTlvExtIsReachEntry {
            neighbor_id: *adj,
            metric: link.config.metric(),
            subs: Vec::new(),
        };
        // Per-link ASLA sub-TLV (RFC 9479) carrying the Extended Admin
        // Group bitmap and the RFC 8570 TE metrics, scoped to flex-algo
        // path computation. Receivers intersect the bitmap with any
        // FAD's include-any/include-all/exclude-any constraint and read
        // the delay metrics for metric-type-1 SPF (RFC 9350 §6.3). Only
        // emitted when affinity or a TE metric is present. The metrics
        // are the static-over-measured merge: STAMP measurement fills
        // any field the operator left unconfigured.
        let te_metric = link.te_metric_effective();
        if let Some(asla) = super::flex_algo::build_link_asla(
            &link.config.affinity,
            top.affinity_map,
            te_metric.sub_tlvs(),
        ) {
            is_reach.subs.push(neigh::IsisSubTlv::Asla(asla));
        }
        // Per-link RFC 8570 TE metrics (unidirectional / min-max delay,
        // delay variation, link loss), also advertised inline for
        // general TE visibility (non-flex-algo consumers).
        is_reach.subs.extend(te_metric.sub_tlvs());
        // Neighbor
        for (_, nbr) in link.state.nbrs.get(&level).iter() {
            for (_key, value) in nbr.addr4.iter() {
                if let Some(label) = value.label {
                    // RFC 8667 §2.2.1 B-flag: "Adj-SID is eligible for
                    // protection." We flip it on whenever TI-LFA is
                    // enabled on this instance — i.e. we're asserting
                    // a TI-LFA repair has been (or will be) computed
                    // for this adjacency. Per-adjacency truthfulness
                    // (B=0 on islands where no repair exists) is a
                    // follow-up once the repair-path SPF lands.
                    let flags =
                        AdjSidFlags::lan_adj_flag_ipv4().with_b_flag(top.config.ti_lfa_enabled);
                    if nbr.network_type.is_p2p() {
                        let sub = IsisSubAdjSid {
                            flags,
                            weight: 0,
                            sid: SidLabelValue::Label(label),
                        };
                        is_reach.subs.push(neigh::IsisSubTlv::AdjSid(sub));
                    } else {
                        let sub = IsisSubLanAdjSid {
                            flags,
                            weight: 0,
                            system_id: nbr.sys_id,
                            sid: SidLabelValue::Label(label),
                        };
                        is_reach.subs.push(neigh::IsisSubTlv::LanAdjSid(sub));
                    }
                }
            }

            // SRv6 End.X (adjacency) sub-TLV — RFC 9352 §8.1 (P2P) /
            // §8.2 (LAN). One per up adjacency, only when an End.X
            // SID has been allocated against the resolved locator.
            if let Some((_, sid_addr)) = nbr.endx_sid {
                if nbr.network_type.is_p2p() {
                    let sub = IsisSubSrv6EndXSid {
                        flags: 0,
                        algo: Algo::Spf,
                        weight: 0,
                        behavior: endx_behavior,
                        sid: sid_addr,
                        sub2s: sid_structure_subs.clone(),
                    };
                    is_reach.subs.push(neigh::IsisSubTlv::Srv6EndXSid(sub));
                } else {
                    let sub = IsisSubSrv6LanEndXSid {
                        system_id: nbr.sys_id,
                        flags: 0,
                        algo: Algo::Spf,
                        weight: 0,
                        behavior: endx_behavior,
                        sid: sid_addr,
                        sub2s: sid_structure_subs.clone(),
                    };
                    is_reach.subs.push(neigh::IsisSubTlv::Srv6LanEndXSid(sub));
                }
            }

            // Per-Flex-Algorithm End.X (adjacency) SIDs (RFC 9352 §8,
            // Algorithm = N) — derived from the algo-0 function under
            // each per-algo locator; lets a peer's per-algo TI-LFA use
            // algo-N adjacency segments.
            is_reach
                .subs
                .extend(srv6_algo_endx_subs(nbr, top.sr_flex_algo_locators));
        }

        ext_is_reach.entries.push(is_reach);

        distributable.push(ext_is_reach.into());

        // Shared Risk Link Group TLVs (138 / 139) — per-adjacency,
        // RFC 5307 (v4) / RFC 6119 (v6). Resolve the link's SRLG
        // names against the cached global table; names that don't
        // (yet) resolve to a value are skipped silently — that's the
        // staging-before-commit case the docs in /srlg/group call
        // out. Empty value list = no TLV. SRLG TLVs are distributable
        // so the packer may pack them across fragments.
        if !link.config.srlg_groups.is_empty() {
            let values: Vec<u32> = link
                .config
                .srlg_groups
                .iter()
                .filter_map(|name| top.srlg_groups.get(name).map(|g| g.value))
                .collect();
            if !values.is_empty() {
                // Local v4 address: first interface address on the
                // link. Remote v4 address: first known neighbor v4
                // (best-effort — for LAN there's no single "remote"
                // endpoint, so any peer address suffices as the
                // disambiguator together with the neighbor sys-id +
                // psn carried in the TLV).
                let local_v4 = link
                    .state
                    .v4addr
                    .first()
                    .map(|p| p.addr())
                    .unwrap_or(Ipv4Addr::UNSPECIFIED);
                let remote_v4 = link
                    .state
                    .nbrs
                    .get(&level)
                    .values()
                    .flat_map(|nbr| nbr.addr4.keys().copied())
                    .next()
                    .unwrap_or(Ipv4Addr::UNSPECIFIED);
                // T-bit (numbered link) when we have a real local
                // address. Unnumbered case (T=0, Link Local/Remote
                // IDs in the addr fields) is not modelled here — we
                // don't track per-link 32-bit IDs separately.
                let flags = if local_v4.is_unspecified() {
                    0
                } else {
                    SRLG_FLAG_T
                };
                for chunk in values.chunks(IsisTlvSrlg::MAX_VALUES_PER_TLV) {
                    let tlv = IsisTlvSrlg {
                        neighbor: *adj,
                        flags,
                        local_addr: local_v4,
                        remote_addr: remote_v4,
                        values: chunk.to_vec(),
                    };
                    distributable.push(IsisTlv::Srlg(tlv));
                }

                // IPv6 SRLG TLV 139 — only when the link has both a
                // global IPv6 address and an IPv6-capable adjacency
                // (peer v6 address known). Skipped on v4-only links
                // even if the v4 TLV above was emitted; the two TLVs
                // are independent per RFC 6119.
                let local_v6 = link.state.v6addr.first().map(|p| p.addr());
                let remote_v6 = link
                    .state
                    .nbrs
                    .get(&level)
                    .values()
                    .flat_map(|nbr| nbr.addr6.iter().copied())
                    .next();
                if let (Some(local_v6), Some(remote_v6)) = (local_v6, remote_v6) {
                    for chunk in values.chunks(IsisTlvIpv6Srlg::MAX_VALUES_PER_TLV) {
                        let tlv = IsisTlvIpv6Srlg {
                            neighbor: *adj,
                            flags: 0,
                            local_addr: local_v6,
                            remote_addr: remote_v6,
                            values: chunk.to_vec(),
                        };
                        distributable.push(IsisTlv::Ipv6Srlg(tlv));
                    }
                }
            }
        }
    }

    // MT IS Reach (TLV 222) for MT 2 — RFC 5120 §7.2. Mirrors the
    // adjacencies in TLV 22 above, but only for IPv6-enabled links
    // and only when MT 2 is configured. SRv6 End.X / LAN-End.X SIDs
    // ride here per RFC 8667 §2 (SR sub-TLVs nest inside the
    // MT-specific IS Reach for the MT they belong to). The IPv4
    // SR-MPLS AdjSid stays on TLV 22 only — that's MT 0.
    if top.config.mt_enabled && top.config.mt_topologies.contains(&MtId::Ipv6Unicast) {
        let mt2_id = MultiTopologyId::from(MtId::Ipv6Unicast.wire_id());
        let mut mt2_entries: Vec<IsisTlvExtIsReachEntry> = Vec::new();
        for (_, link) in top.links.iter() {
            if !link.config.enable.v6 {
                continue;
            }
            let Some((adj, _)) = &link.state.adj.get(&level) else {
                continue;
            };
            // Per-MT metric override falls back to the link's plain
            // metric leaf. Future PR can layer per-MT defaults too.
            let metric = link
                .config
                .mt_metrics
                .get(&MtId::Ipv6Unicast)
                .copied()
                .unwrap_or_else(|| link.config.metric());
            let mut entry = IsisTlvExtIsReachEntry {
                neighbor_id: *adj,
                metric,
                subs: Vec::new(),
            };
            // Per-link ASLA carries the same affinity bitmap and TE
            // metrics on the MT IS-reach entry as on the legacy TLV 22
            // entry — both are MT-agnostic in the YANG model. Same
            // static-over-measured merge as TLV 22.
            let te_metric = link.te_metric_effective();
            if let Some(asla) = super::flex_algo::build_link_asla(
                &link.config.affinity,
                top.affinity_map,
                te_metric.sub_tlvs(),
            ) {
                entry.subs.push(neigh::IsisSubTlv::Asla(asla));
            }
            // Same RFC 8570 TE metrics as the legacy TLV 22 entry above,
            // also advertised inline for general TE visibility — link
            // delay/loss are MT-agnostic physical properties.
            entry.subs.extend(te_metric.sub_tlvs());
            for (_, nbr) in link.state.nbrs.get(&level).iter() {
                if let Some((_, sid_addr)) = nbr.endx_sid {
                    if nbr.network_type.is_p2p() {
                        let sub = IsisSubSrv6EndXSid {
                            flags: 0,
                            algo: Algo::Spf,
                            weight: 0,
                            behavior: endx_behavior,
                            sid: sid_addr,
                            sub2s: sid_structure_subs.clone(),
                        };
                        entry.subs.push(neigh::IsisSubTlv::Srv6EndXSid(sub));
                    } else {
                        let sub = IsisSubSrv6LanEndXSid {
                            system_id: nbr.sys_id,
                            flags: 0,
                            algo: Algo::Spf,
                            weight: 0,
                            behavior: endx_behavior,
                            sid: sid_addr,
                            sub2s: sid_structure_subs.clone(),
                        };
                        entry.subs.push(neigh::IsisSubTlv::Srv6LanEndXSid(sub));
                    }
                }

                // Per-Flex-Algorithm End.X (adjacency) SIDs (Algorithm = N).
                entry
                    .subs
                    .extend(srv6_algo_endx_subs(nbr, top.sr_flex_algo_locators));
            }
            mt2_entries.push(entry);
        }
        if !mt2_entries.is_empty() {
            let mt_is_reach = IsisTlvMtIsReach {
                mt: mt2_id,
                entries: mt2_entries,
            };
            distributable.push(mt_is_reach.into());
        }
    }

    // IPv4 Reachability.
    let mut ext_ip_reach = IsisTlvExtIpReach::default();
    for (_, link) in top.links.iter() {
        if link.config.enable.v4 && has_level(link.state.level(), level) {
            for ifaddr in link.state.v4addr.iter() {
                let prefix = ifaddr.apply_mask();
                if !prefix.addr().is_loopback() {
                    let sub_tlv = if let Some(sid) = &link.config.prefix_sid {
                        let prefix_sid = IsisSubPrefixSid {
                            // RFC 8667 §2.1.1: N (Node-SID) flag for a host
                            // prefix (loopback /32) — it identifies the
                            // originating router; P (no-PHP) flag when the
                            // operator asks the penultimate hop to keep the
                            // node-SID label rather than pop it.
                            flags: PrefixSidFlags::new()
                                .with_n_flag(prefix.prefix_len() == 32)
                                .with_p_flag(link.config.prefix_sid_no_php),
                            algo: Algo::Spf,
                            sid: sid.clone(),
                        };
                        Some(prefix::IsisSubTlv::PrefixSid(prefix_sid))
                    } else {
                        None
                    };
                    // Per-algo Prefix-SID sub-TLVs (RFC 8667 §2.1 +
                    // RFC 9350 §7). One additional Prefix-SID per
                    // configured algo with Algorithm=N, attached to
                    // the same IP-reach entry as the algo-0 SID so a
                    // receiver can resolve any of {0, N1, N2, ...}
                    // for this prefix from a single TLV.
                    let per_algo_sids = super::flex_algo::build_per_algo_prefix_sids(
                        &link.config.ipv4_flex_algo_prefix_sids,
                        prefix.prefix_len() == 32,
                    );
                    let has_subs = sub_tlv.is_some() || !per_algo_sids.is_empty();
                    let flags = Ipv4ControlInfo::new()
                        .with_prefixlen(prefix.prefix_len() as usize)
                        .with_sub_tlv(has_subs)
                        .with_distribution(false);
                    let mut entry = IsisTlvExtIpReachEntry {
                        metric: 10,
                        flags,
                        prefix,
                        subs: vec![],
                    };
                    if let Some(sub_tlv) = sub_tlv {
                        entry.subs.push(sub_tlv);
                    }
                    for sid in per_algo_sids {
                        entry.subs.push(prefix::IsisSubTlv::PrefixSid(sid));
                    }
                    ext_ip_reach.entries.push(entry);
                }
            }
        }
    }
    // Operator-configured `network` prefixes — BGP-style. Default
    // metric 10, matching the per-interface metric we advertise for
    // local connected prefixes above (`metric: 10` in the link loop),
    // so a `network` entry looks like an interface route in receivers'
    // RIBs rather than a zero-cost shortcut.
    ext_ip_reach.entries.extend(
        top.config
            .networks_v4
            .iter()
            .map(|prefix| ext_ip_reach_entry(*prefix, 10)),
    );
    // Redistributed IPv4 prefixes (`router isis / afi-safi ipv4 /
    // redistribute / <source>`). For each route delivered by RIB into
    // `top.redist_v4`, look up the per-(afi, source) override in
    // `top.config.redistribute`; respect `level` (target-side
    // filter), `metric` (static override), and `metric-type`
    // (rib-metric-as-* uses the RIB cost; internal/external set is
    // for the IPv6 X-bit / legacy TLV split — TLV 135 has no I/E bit
    // so the type only affects metric source for IPv4).
    ext_ip_reach.entries.extend(collect_redist_entries(
        top.redist_v4,
        &top.config.redistribute,
        IsisRedistAfi::Ipv4,
        level,
        |route| route.metric,
        |prefix, metric, _| ext_ip_reach_entry(prefix, metric),
    ));
    if !ext_ip_reach.entries.is_empty() {
        distributable.push(ext_ip_reach.into());
    }

    // IPv6 Reachability.
    let mut ipv6_reach = IsisTlvIpv6Reach::default();
    for (_, link) in top.links.iter() {
        if link.config.enable.v6 && has_level(link.state.level(), level) {
            for v6addr in link.state.v6addr.iter() {
                if !v6addr.addr().is_loopback() {
                    ipv6_reach
                        .entries
                        .push(ipv6_reach_entry(*v6addr, 10, false));
                }
            }
        }
    }
    // Advertise the configured SRv6 locator as an IPv6 Reachability TLV
    // (RFC 5308) with metric 0 so receivers learn the locator prefix
    // purely from their IS-reach metric to us — the originator adds
    // nothing extra. Gated on the locator having actually resolved in
    // the RIB; a configured-but-unresolved locator means no prefix yet.
    if top.config.sr_srv6_enabled
        && let Some(locator) = top.sr_locator.as_ref()
        && let Some(prefix) = locator.prefix
    {
        ipv6_reach.entries.push(ipv6_reach_entry(prefix, 0, false));
    }
    // Operator-configured IPv6 `network` prefixes — sibling of the
    // IPv4 path above. Same metric-10 default for the same reason.
    ipv6_reach.entries.extend(
        top.config
            .networks_v6
            .iter()
            .map(|prefix| ipv6_reach_entry(*prefix, 10, false)),
    );
    // Redistributed IPv6 prefixes — sibling of the IPv4 path above.
    // `metric-type external | rib-metric-as-external` sets the X bit
    // (RFC 5308 §2) so receivers can tell the prefix originated from
    // a different routing protocol.
    ipv6_reach.entries.extend(collect_redist_entries(
        top.redist_v6,
        &top.config.redistribute,
        IsisRedistAfi::Ipv6,
        level,
        |route| route.metric,
        |prefix, metric, metric_type| {
            ipv6_reach_entry(prefix, metric, redist_external_bit(metric_type))
        },
    ));
    if !ipv6_reach.entries.is_empty() {
        if top.config.mt_enabled && top.config.mt_topologies.contains(&MtId::Ipv6Unicast) {
            // MT 2 mode: same entries, MT-keyed TLV 237 instead of
            // TLV 236. RFC 5120 §7.3.
            let mt_ipv6_reach = IsisTlvMtIpv6Reach {
                mt: MultiTopologyId::from(MtId::Ipv6Unicast.wire_id()),
                entries: ipv6_reach.entries,
            };
            distributable.push(mt_ipv6_reach.into());
        } else {
            distributable.push(ipv6_reach.into());
        }
    }

    // Shard any distributable TLV whose serialized value would
    // overflow the 8-bit TLV length field (255 value-bytes ceiling)
    // into multiple instances of the same TLV type. This is the only
    // place where a single logical "TLV instance" from the collection
    // phase becomes multiple wire TLV instances; the packer below
    // treats each post-split instance as atomic.
    let distributable: Vec<IsisTlv> = distributable
        .into_iter()
        .flat_map(split_distributable_at_255)
        .collect();

    // Bin-pack into fragments under the configured originatingLSPBufferSize.
    // Pass the stable-placement memory so per-adjacency TLV 22
    // instances land in the same fragment they previously occupied
    // (when they still fit), avoiding cascade reshuffles when one
    // adjacency joins or leaves.
    let mut fragments = pack_into_fragments(
        anchors,
        distributable,
        IsisNeighborId::from_sys_id(&top.config.net.sys_id(), 0),
        types,
        top.config.hold_time(),
        top.config.lsp_mtu_size(),
        Some(top.lsp_placement_memory.get(&level)),
    );

    // Resolve seq numbers per fragment. Fragment 0 uses the seq we
    // computed above (with seq_floor + wrap detection already
    // applied). Higher fragments derive their seq from the LSDB
    // (existing+1 or 1) and run wrap detection independently — if a
    // fragment's seq would hit u32::MAX we purge that fragment,
    // arm its own freeze timer, and drop it from the emit set. The
    // rest of the LSP set continues to refresh normally.
    let mut emit_set: Vec<IsisLsp> = Vec::with_capacity(fragments.len());
    for mut frag in fragments.drain(..) {
        let frag_id = frag.lsp_id.fragment_id();
        if frag_id == 0 {
            frag.seq_number = frag0_seq;
            emit_set.push(frag);
            continue;
        }

        // Per-fragment freeze suppresses this fragment's re-emission
        // until its `MaxAge + safety` timer fires; other fragments
        // continue refreshing.
        if top.lsp_seq_wrap_wait.get(&level).contains_key(&frag_id) {
            isis_event_trace!(
                top.tracing,
                LspOriginate,
                &level,
                "[LspOriginate] fragment {} suppressed — seq-wrap freeze in effect",
                frag_id
            );
            continue;
        }

        let existing = top
            .lsdb
            .get(&level)
            .get(&frag.lsp_id)
            .map(|x| x.lsp.seq_number);
        let seq = existing.map(|e| e.saturating_add(1)).unwrap_or(0x0001);
        if seq == u32::MAX {
            isis_event_trace!(
                top.tracing,
                LspOriginate,
                &level,
                "[LspSeqWrap] fragment {} hit u32::MAX — purging and freezing this fragment",
                frag_id
            );
            arm_seq_wrap_freeze(top, level, frag.lsp_id);
            continue;
        }
        frag.seq_number = seq;
        emit_set.push(frag);
    }

    // Refresh the stable-placement memory from this emission's
    // actual placements. Built from scratch — only TLVs that
    // survived (frag 0 always; higher fragments unless frozen)
    // are recorded, so memory entries for dropped TLVs naturally
    // age out. Frozen-fragment placements are intentionally
    // forgotten — next emit will re-place those TLVs greedy.
    let new_memory = {
        let mut m: BTreeMap<TlvKey, u8> = BTreeMap::new();
        for frag in &emit_set {
            let frag_id = frag.lsp_id.fragment_id();
            for tlv in &frag.tlvs {
                if let Some(key) = key_for_tlv(tlv) {
                    m.insert(key, frag_id);
                }
            }
        }
        m
    };
    *top.lsp_placement_memory.get_mut(&level) = new_memory;

    emit_set
}

/// Schedule the seq-wrap purge + freeze timer for one specific
/// fragment. Sends `Message::LspPurge` so the standard purge path
/// emits a `RemainingLifetime = 0` LSP at the wrapping seq, then
/// installs a `MaxAge + ZeroAgeLifetime` timer that fires
/// `Message::LspSeqWrapClear(level, frag_id)`; the clear handler
/// drops the LSDB entry and re-triggers origination, allowing the
/// next emit to compute seq = 1 from scratch.
fn arm_seq_wrap_freeze(top: &mut IsisTop, level: Level, lsp_id: IsisLspId) {
    let _ = top.tx.send(Message::LspPurge(level, lsp_id));

    let wait_secs = top.config.hold_time().saturating_add(ZERO_AGE_LIFETIME);
    let frag_id = lsp_id.fragment_id();
    let tx = top.tx.clone();
    let timer = Timer::once(wait_secs as u64, move || {
        let tx = tx.clone();
        async move {
            let _ = tx.send(Message::LspSeqWrapClear(level, frag_id));
        }
    });
    top.lsp_seq_wrap_wait.get_mut(&level).insert(frag_id, timer);
}

pub fn lsp_emit(
    lsp: &mut IsisLsp,
    level: Level,
    resolved: Option<&auth::ResolvedAuth>,
) -> BytesMut {
    // Auth TLV sits at the end of the LSP's TLV section.
    // For HMAC-MD5 it's a zero-filled placeholder that the post-emit
    // sign step patches in place; for cleartext it carries the
    // password bytes directly. Append before `IsisPacket::from` so
    // the serialized fragment size — and the Fletcher checksum
    // `IsisPacket::emit` stamps — already accounts for the TLV.
    auth::append_auth_tlv(&mut lsp.tlvs, resolved);

    let packet = match level {
        Level::L1 => IsisPacket::from(IsisType::L1Lsp, IsisPdu::L1Lsp(lsp.clone())),
        Level::L2 => IsisPacket::from(IsisType::L2Lsp, IsisPdu::L2Lsp(lsp.clone())),
    };

    let mut buf = BytesMut::new();
    packet.emit(&mut buf);

    // HMAC sign (md5 or RFC 5310 SHA family): hash the buffer with
    // Remaining Lifetime + Checksum + Auth Value all set to the
    // placeholder fill (zero for md5, Apad for RFC 5310), patch the
    // digest into place, then re-stamp Fletcher (which
    // `IsisPacket::emit` already wrote covering the placeholder —
    // we redo it with the real digest in place).
    if let Some(r) = resolved
        && (matches!(r.auth_type, IsisAuthType::Md5) || r.auth_type.is_generic_crypto())
    {
        auth::sign_lsp_inplace(&mut buf, r.auth_type, &r.key);
    }

    // Offset for pdu_len and checksum.
    const PDU_LEN_OFFSET: usize = 8;
    const CKSUM_OFFSET: usize = 24;

    // Set pdu_len and checksum.
    lsp.pdu_len = u16::from_be_bytes(buf[PDU_LEN_OFFSET..PDU_LEN_OFFSET + 2].try_into().unwrap());
    lsp.checksum = u16::from_be_bytes(buf[CKSUM_OFFSET..CKSUM_OFFSET + 2].try_into().unwrap());

    buf
}

pub fn csnp_generate(link: &LinkTop, level: Level) -> Vec<IsisCsnp> {
    // Interface MTU.
    let mtu = link.state.mtu as usize;

    // SNPs are signed with the per-level area/domain password
    // (RFC 5304 §3). The Auth TLV is appended after the LspEntries
    // TLV in each CSNP, so its on-wire size shrinks the per-fragment
    // entry budget below.
    let auth_cfg = level_auth_cfg(link.up_config, level);
    let resolved = auth::resolve_send(auth_cfg, link.key_chains, chrono::Utc::now());
    let auth_size = auth::auth_tlv_wire_size(resolved.as_ref());

    // For the record, we will try to encode the packet length.
    let available_len = {
        let mut buf = BytesMut::new();

        let csnp = IsisCsnp {
            source_id: IsisSysId::default(),
            source_id_circuit: 0,
            start: IsisLspId::start(),
            end: IsisLspId::end(),
            ..Default::default()
        };

        let packet = IsisPacket::from(IsisType::L1Csnp, IsisPdu::L1Csnp(csnp.clone()));
        packet.emit(&mut buf);
        if parse(&buf).is_err() {
            return vec![];
        }

        let packet_len = buf.len();
        let base_len = 3;
        let tlv_header_len = 2;

        let total_base_len = packet_len + base_len + tlv_header_len + auth_size;
        if mtu <= total_base_len {
            return vec![];
        }
        mtu - total_base_len
    };
    // tracing::info!("[CSNP:Gen] available_len {}", available_len);

    let entry_size_max = available_len / 16;

    // tracing::info!("[CSNP:Gen] entry_len {}", entry_size_max);

    let mut csnps: Vec<IsisCsnp> = vec![];
    let mut tlvs = IsisTlvLspEntries::default();

    let mut start: Option<IsisLspId> = Some(IsisLspId::start());

    let mut entry_size = 0;
    for (_lsp_id, lsa) in link.lsdb.get(&level).iter() {
        if start.is_none() {
            start = Some(lsa.lsp.lsp_id);
        }
        let entry = IsisLspEntry::from_lsp(&lsa.lsp);
        tlvs.entries.push(entry);

        entry_size += 1;
        if entry_size == entry_size_max {
            let mut csnp_tlvs: Vec<IsisTlv> = vec![tlvs.clone().into()];
            auth::append_auth_tlv(&mut csnp_tlvs, resolved.as_ref());
            let csnp = IsisCsnp {
                pdu_len: 0,
                source_id: link.up_config.net.sys_id(),
                source_id_circuit: 0,
                start: start.unwrap_or(IsisLspId::start()),
                end: lsa.lsp.lsp_id,
                tlvs: csnp_tlvs,
            };
            csnps.push(csnp);

            tlvs.entries.clear();
            entry_size = 0;
            start = None;
        }
    }
    if !tlvs.entries.is_empty() {
        let mut csnp_tlvs: Vec<IsisTlv> = vec![tlvs.into()];
        auth::append_auth_tlv(&mut csnp_tlvs, resolved.as_ref());
        let csnp = IsisCsnp {
            pdu_len: 0,
            source_id: link.up_config.net.sys_id(),
            source_id_circuit: 0,
            start: start.unwrap_or(IsisLspId::start()),
            end: IsisLspId::end(),
            tlvs: csnp_tlvs,
        };
        csnps.push(csnp);
    }

    csnps
}

/// Per-level auth config for SNPs and LSPs. RFC 5304 §3 pins L1
/// SNPs to the area-wide string and L2 SNPs to the domain-wide
/// string — same keys the LSPs at that level use. Takes
/// `&IsisConfig` (not `&LinkTop`) so callers that hold a disjoint
/// mutable borrow of `link.lsdb` / `link.state` can still pull the
/// config out via `link.up_config`.
pub fn level_auth_cfg(up_config: &IsisConfig, level: Level) -> &IsisAuthConfig {
    match level {
        Level::L1 => &up_config.area_password,
        Level::L2 => &up_config.domain_password,
    }
}

pub enum PacketMessage {
    Send(Packet, u32, Level, Option<MacAddr>),
}

pub enum Packet {
    Packet(IsisPacket),
    Bytes(BytesMut),
}

pub fn lsp_flood(top: &mut IsisTop, level: Level, lsp_id: &IsisLspId) {
    top.lsdb.get_mut(&level).srm_set_all(top.tx, level, lsp_id);
}

// ---- redistribute emission helpers ---------------------------------
//
// Used by `lsp_generate` to convert a route delivered into
// `top.redist_v{4,6}` by RIB into a TLV 135 / 236 / MT 237 entry,
// applying the per-(afi, source) override knobs from
// `top.config.redistribute`.

fn redist_source_from_rtype(rtype: crate::rib::RibType) -> Option<IsisRedistSource> {
    match rtype {
        crate::rib::RibType::Connected => Some(IsisRedistSource::Connected),
        crate::rib::RibType::Static => Some(IsisRedistSource::Static),
        crate::rib::RibType::Bgp => Some(IsisRedistSource::Bgp),
        crate::rib::RibType::Ospf => Some(IsisRedistSource::Ospf),
        _ => None,
    }
}

/// Whether the redistribute row's `level` filter (defaults to
/// `level-2` per IOS-XR) includes the level being generated.
fn redist_level_matches(cfg_level: Option<IsisRedistLevel>, gen_level: Level) -> bool {
    let lvl = cfg_level.unwrap_or(IsisRedistLevel::L2);
    matches!(
        (lvl, gen_level),
        (IsisRedistLevel::L1, Level::L1)
            | (IsisRedistLevel::L2, Level::L2)
            | (IsisRedistLevel::L1L2, _)
    )
}

/// Metric placed on the originated reachability entry:
///   - `rib-metric-as-internal | rib-metric-as-external` always uses
///     the RIB cost (override ignored when present).
///   - `internal | external` uses the static override if set, falling
///     back to the RIB metric. No implicit default — IOS-XR also
///     says "no implicit metric without rib-metric-as-* or override",
///     but falling back to the RIB cost is the most useful behavior
///     in practice.
fn redist_metric(
    cfg_metric: Option<u32>,
    metric_type: Option<IsisRedistMetricType>,
    rib_metric: u32,
) -> u32 {
    match metric_type {
        Some(IsisRedistMetricType::RibAsInternal) | Some(IsisRedistMetricType::RibAsExternal) => {
            rib_metric
        }
        _ => cfg_metric.unwrap_or(rib_metric),
    }
}

/// X-bit value for IPv6 TLV 236 / MT 237 (RFC 5308 §2). Set when the
/// prefix is being advertised as external — either `external` or
/// `rib-metric-as-external`. IPv4 TLV 135 has no equivalent bit;
/// callers ignore the result for v4.
fn redist_external_bit(metric_type: Option<IsisRedistMetricType>) -> bool {
    matches!(
        metric_type,
        Some(IsisRedistMetricType::External) | Some(IsisRedistMetricType::RibAsExternal)
    )
}

/// TLV 135 entry of the plain shape shared by `network` statements
/// and redistributed prefixes: metric + prefix, no sub-TLVs. TLV 135
/// has no I/E bit, so external-ness never shows on the wire for
/// IPv4.
fn ext_ip_reach_entry(prefix: Ipv4Net, metric: u32) -> IsisTlvExtIpReachEntry {
    let flags = Ipv4ControlInfo::new()
        .with_prefixlen(prefix.prefix_len() as usize)
        .with_sub_tlv(false)
        .with_distribution(false);
    IsisTlvExtIpReachEntry {
        metric,
        flags,
        prefix,
        subs: vec![],
    }
}

/// TLV 236 entry sibling of `ext_ip_reach_entry`. `external` sets
/// the RFC 5308 §2 X bit so receivers can tell the prefix originated
/// in another routing protocol; connected / `network` / locator
/// entries pass false.
fn ipv6_reach_entry(prefix: Ipv6Net, metric: u32, external: bool) -> IsisTlvIpv6ReachEntry {
    let flags = Ipv6ControlInfo::new()
        .with_sub_tlv(false)
        .with_dist_internal(external);
    IsisTlvIpv6ReachEntry {
        metric,
        flags,
        prefix,
        subs: Vec::new(),
    }
}

/// Walk a per-family redistributed-route map and build one reach
/// entry per route whose (afi, source) has redistribution configured
/// at this generation level, resolving the metric from the
/// per-source override / metric-type. `make` builds the family's
/// entry from (prefix, resolved metric, configured metric-type).
fn collect_redist_entries<P, R, E>(
    redist: &BTreeMap<(crate::rib::RibType, P), R>,
    redistribute: &BTreeMap<(IsisRedistAfi, IsisRedistSource), IsisRedistribute>,
    afi: IsisRedistAfi,
    level: Level,
    rib_metric: impl Fn(&R) -> u32,
    make: impl Fn(P, u32, Option<IsisRedistMetricType>) -> E,
) -> Vec<E>
where
    P: Copy,
{
    let mut out = Vec::new();
    for ((rtype, prefix), route) in redist.iter() {
        let Some(source) = redist_source_from_rtype(*rtype) else {
            continue;
        };
        let Some(cfg) = redistribute.get(&(afi, source)) else {
            continue;
        };
        if !redist_level_matches(cfg.level, level) {
            continue;
        }
        let metric = redist_metric(cfg.metric, cfg.metric_type, rib_metric(route));
        out.push(make(*prefix, metric, cfg.metric_type));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_block_is_default_when_enabled() {
        // SR-MPLS enabled subscribes to the canonical "default" block.
        let cfg = IsisConfig {
            sr_mpls_enabled: true,
            ..Default::default()
        };
        assert_eq!(target_block_name(&cfg), Some("default".to_string()));
    }

    #[test]
    fn target_block_returns_none_when_mpls_disabled() {
        let cfg = IsisConfig::default();
        assert_eq!(target_block_name(&cfg), None);
    }

    #[test]
    fn target_locator_returns_none_when_unset() {
        // SRv6 enabled with no locator: no default exists, so we must
        // not subscribe — IS-IS will not originate the SRv6 SID TLV.
        let cfg = IsisConfig {
            sr_srv6_enabled: true,
            ..Default::default()
        };
        assert_eq!(target_locator_name(&cfg), None);
    }

    #[test]
    fn target_locator_uses_explicit_name_when_set() {
        let cfg = IsisConfig {
            sr_srv6_enabled: true,
            sr_srv6_locator: Some("loc1".into()),
            ..Default::default()
        };
        assert_eq!(target_locator_name(&cfg), Some("loc1".to_string()));
    }

    #[test]
    fn target_locator_returns_none_when_srv6_disabled() {
        let cfg = IsisConfig {
            sr_srv6_locator: Some("loc1".into()),
            ..Default::default()
        };
        assert_eq!(target_locator_name(&cfg), None);
    }

    #[test]
    fn mirror_sid_subs_emits_only_in_locator_srv6_entries() {
        use crate::isis::egress_protection::{MirrorDataplane, MirrorProtect, MirrorProtectMap};

        let local: Ipv6Net = "2001:db8:a4:1::/64".parse().unwrap();
        let mut map = MirrorProtectMap::new();

        // In-locator SRv6 entry with an explicit Mirror SID → emitted.
        let mut ok = MirrorProtect::new("2001:db8:a3:1::/64".parse().unwrap());
        ok.mirror_sid = Some("2001:db8:a4:1::3".parse().unwrap());
        map.insert(ok.protected_locator, ok);

        // No explicit Mirror SID → skipped (auto-alloc is a follow-up).
        map.insert(
            "2001:db8:b3:1::/64".parse().unwrap(),
            MirrorProtect::new("2001:db8:b3:1::/64".parse().unwrap()),
        );

        // Mirror SID outside the local locator → skipped.
        let mut outside = MirrorProtect::new("2001:db8:c3:1::/64".parse().unwrap());
        outside.mirror_sid = Some("2001:db8:ffff::9".parse().unwrap());
        map.insert(outside.protected_locator, outside);

        // MPLS dataplane → skipped (SRv6 emit only).
        let mut mpls = MirrorProtect::new("2001:db8:d3:1::/64".parse().unwrap());
        mpls.mirror_sid = Some("2001:db8:a4:1::4".parse().unwrap());
        mpls.dataplane = MirrorDataplane::Mpls;
        map.insert(mpls.protected_locator, mpls);

        let subs = mirror_sid_subs(&map, local);
        assert_eq!(subs.len(), 1, "only the in-locator SRv6 entry emits");

        let prefix::IsisSubTlv::Srv6MirrorSid(m) = &subs[0] else {
            panic!("expected Srv6MirrorSid, got {:?}", subs[0]);
        };
        assert_eq!(m.behavior, Behavior::EndM);
        assert_eq!(
            m.sid,
            "2001:db8:a4:1::3".parse::<std::net::Ipv6Addr>().unwrap()
        );
        assert_eq!(m.sub2s.len(), 1);
        let IsisMirrorSub2Tlv::ProtectedLocators(pl) = &m.sub2s[0] else {
            panic!("expected ProtectedLocators sub-sub-TLV");
        };
        assert_eq!(pl.locator, "2001:db8:a3:1::/64".parse::<Ipv6Net>().unwrap());
    }

    #[test]
    fn mirror_binding_tlvs_emits_only_mpls_with_label() {
        use crate::isis::egress_protection::{MirrorDataplane, MirrorProtect, MirrorProtectMap};
        use isis_packet::{BindingPrefix, IsisBindingSubTlv, SidLabelValue};

        use ipnet::IpNet;
        let mut map = MirrorProtectMap::new();

        // MPLS entry with an allocated context label, IPv4 loopback FEC
        // (the SR-MPLS transport) → emitted with the F-flag clear.
        let mut mpls = MirrorProtect::new("1.1.1.3/32".parse().unwrap());
        mpls.dataplane = MirrorDataplane::Mpls;
        map.insert(mpls.protected_locator, mpls);

        // MPLS entry without an allocated label (SR-MPLS not up) → skipped.
        let mut mpls_no_label = MirrorProtect::new("1.1.1.4/32".parse().unwrap());
        mpls_no_label.dataplane = MirrorDataplane::Mpls;
        map.insert(mpls_no_label.protected_locator, mpls_no_label);

        // SRv6 entry → skipped (Binding TLV emit is MPLS-only).
        let mut srv6 = MirrorProtect::new("2001:db8:a3:1::/64".parse().unwrap());
        srv6.mirror_sid = Some("2001:db8:a4:1::3".parse().unwrap());
        map.insert(srv6.protected_locator, srv6);

        let mut labels = std::collections::BTreeMap::new();
        labels.insert("1.1.1.3/32".parse::<IpNet>().unwrap(), 16001u32);

        let tlvs = mirror_binding_tlvs(&map, &labels);
        assert_eq!(tlvs.len(), 1, "only the MPLS entry with a label emits");

        let IsisTlv::SidLabelBinding(b) = &tlvs[0] else {
            panic!("expected SidLabelBinding, got {:?}", tlvs[0]);
        };
        assert!(b.flags.m_flag(), "Mirror Context M-flag set");
        assert!(!b.flags.f_flag(), "IPv4 FEC ⇒ F-flag clear");
        assert_eq!(b.prefix, BindingPrefix::V4("1.1.1.3/32".parse().unwrap()));
        assert!(matches!(
            b.subs[0],
            IsisBindingSubTlv::SidLabel(SidLabelValue::Label(16001))
        ));
    }

    #[test]
    fn resolve_dis_ifindex_returns_none_on_empty_links() {
        // Regression for the `0000.0000.0000.00-00` self-LSP injection
        // bug: when a peer reflects our pseudonode LSP back at higher
        // seq and we no longer own that DIS adjacency, the §7.3.16.4
        // self-bump path must skip rather than fabricate an LSP at a
        // bogus lsp_id.
        let links = IsisLinks::default();
        let neighbor_id = IsisNeighborId::default();
        assert!(resolve_dis_ifindex(&links, Level::L1, neighbor_id).is_none());
        assert!(resolve_dis_ifindex(&links, Level::L2, neighbor_id).is_none());
    }

    fn v4_entry(octet: u8) -> IsisTlvExtIpReachEntry {
        use std::net::Ipv4Addr;
        let prefix = ipnet::Ipv4Net::new(Ipv4Addr::new(10, 0, 0, octet), 32).unwrap();
        let flags = Ipv4ControlInfo::new()
            .with_prefixlen(32)
            .with_sub_tlv(false)
            .with_distribution(false);
        IsisTlvExtIpReachEntry {
            metric: 10,
            flags,
            prefix,
            subs: vec![],
        }
    }

    /// The 8-bit TLV length silently wraps for any TLV whose value
    /// exceeds 255 bytes, so the packer pre-shards entry-bearing
    /// TLVs. Verify each shard fits within the 257-byte (TL header +
    /// value) wire ceiling and the entry total is preserved.
    #[test]
    fn split_ext_ip_reach_shards_at_255_byte_value() {
        let tlv = IsisTlvExtIpReach {
            entries: (0..40).map(v4_entry).collect(),
        };
        let expected = tlv.entries.len();
        let shards = split_tlv_entries(tlv);
        assert!(
            shards.len() >= 2,
            "40 entries × ~9B exceed the 255-byte TLV value ceiling — expected ≥ 2 shards"
        );
        for shard in &shards {
            assert!(
                shard.wire_len() <= TLV_WIRE_MAX,
                "shard wire_len {} exceeds {}",
                shard.wire_len(),
                TLV_WIRE_MAX
            );
        }
        let total: usize = shards
            .iter()
            .map(|t| match t {
                IsisTlv::ExtIpReach(r) => r.entries.len(),
                _ => 0,
            })
            .sum();
        assert_eq!(total, expected, "no entries lost across the split");
    }

    /// Packer must keep anchor TLVs in fragment 0 even when an
    /// already-placed distributable would have fit. Validates the
    /// "fragment 0 is the scalar attribute anchor" rule that
    /// receivers depend on (hostname / cap / OL only come from
    /// frag 0).
    #[test]
    fn pack_keeps_anchors_in_fragment_zero() {
        let area = IsisTlv::AreaAddr(IsisTlvAreaAddr {
            area_addr: vec![0x49, 0x00, 0x01],
        });
        let hostname = IsisTlv::Hostname(IsisTlvHostname {
            hostname: "r1".to_string(),
        });
        let reach = IsisTlv::ExtIpReach(IsisTlvExtIpReach {
            entries: (0..5).map(v4_entry).collect(),
        });

        let base = IsisNeighborId::from_sys_id(&IsisSysId::default(), 0);
        let frags = pack_into_fragments(
            vec![area.clone(), hostname.clone()],
            vec![reach.clone()],
            base,
            IsisLspTypes::from(2),
            1200,
            1492,
            None,
        );
        assert_eq!(frags.len(), 1, "everything fits in one fragment under 1492");
        let f0 = &frags[0];
        assert_eq!(f0.lsp_id.fragment_id(), 0);
        assert!(f0.tlvs.iter().any(|t| matches!(t, IsisTlv::AreaAddr(_))));
        assert!(f0.tlvs.iter().any(|t| matches!(t, IsisTlv::Hostname(_))));
    }

    /// With a tight buffer size, a single per-link TLV 22 plus a
    /// chunky ExtIpReach forces a new fragment. Verify the packer
    /// opens fragment 1, anchors stay in 0, and the seq is left at
    /// 0 (caller fills it from the LSDB).
    #[test]
    fn pack_spills_into_fragment_one_when_budget_tight() {
        let area = IsisTlv::AreaAddr(IsisTlvAreaAddr {
            area_addr: vec![0x49, 0x00, 0x01],
        });
        // ~30 entries × ~9 bytes ≈ 270B value — already exceeds
        // 255, so the splitter will produce two TLV 135 instances.
        let big_reach = IsisTlv::ExtIpReach(IsisTlvExtIpReach {
            entries: (0..30).map(v4_entry).collect(),
        });
        let distributable: Vec<IsisTlv> = split_distributable_at_255(big_reach);
        assert!(
            distributable.len() >= 2,
            "expected splitter to produce ≥ 2 TLV instances"
        );

        let base = IsisNeighborId::from_sys_id(&IsisSysId::default(), 0);
        // mtu = LSP_PDU_OVERHEAD + anchors + just enough for one
        // distributable instance — second must spill.
        let mtu = (LSP_PDU_OVERHEAD + 5 + 200) as u16; // anchors small, room for ~1 reach
        let frags = pack_into_fragments(
            vec![area],
            distributable,
            base,
            IsisLspTypes::from(2),
            1200,
            mtu,
            None,
        );
        assert!(frags.len() >= 2, "expected packer to open fragment 1");
        assert_eq!(frags[0].lsp_id.fragment_id(), 0);
        assert_eq!(frags[1].lsp_id.fragment_id(), 1);
        for f in &frags {
            assert_eq!(f.seq_number, 0, "packer leaves seq=0 for caller to fill");
        }
        // Anchor lives only in fragment 0.
        let anchor_in_one = frags[1]
            .tlvs
            .iter()
            .any(|t| matches!(t, IsisTlv::AreaAddr(_)));
        assert!(!anchor_in_one, "anchors must not leak into fragment 1");
    }

    fn ext_is_reach_for(b: u8) -> IsisTlv {
        IsisTlv::ExtIsReach(IsisTlvExtIsReach {
            entries: vec![IsisTlvExtIsReachEntry {
                neighbor_id: IsisNeighborId::from_sys_id(
                    &IsisSysId {
                        id: [0, 0, 0, 0, 0, b],
                    },
                    0,
                ),
                metric: 10,
                subs: vec![],
            }],
        })
    }

    fn frag_id_for(frags: &[IsisLsp], key: TlvKey) -> Option<u8> {
        for f in frags {
            for tlv in &f.tlvs {
                if key_for_tlv(tlv) == Some(key) {
                    return Some(f.lsp_id.fragment_id());
                }
            }
        }
        None
    }

    /// Greedy first-fit reshuffles when a TLV is removed mid-set:
    /// downstream TLVs slide forward into the gap. With placement
    /// memory the survivors stay in their previous fragment. Build
    /// 5 ExtIsReach TLVs under a tight mtu so they span 2 fragments,
    /// remember the placement, then re-pack with one removed and
    /// verify nobody else moved.
    #[test]
    fn placement_memory_preserves_survivors_after_removal() {
        let area = IsisTlv::AreaAddr(IsisTlvAreaAddr {
            area_addr: vec![0x49, 0x00, 0x01],
        });
        let tlvs: Vec<IsisTlv> = (1..=5).map(ext_is_reach_for).collect();
        let base = IsisNeighborId::from_sys_id(&IsisSysId::default(), 0);

        // Tight mtu — anchors (3-byte area + 2-byte header) + 3 of
        // these single-entry TLV 22 instances fit; the 4th spills.
        // Each TLV 22 instance is ~16 bytes wire (2 header + 11
        // entry + 1 sublen + 0 subs = 14, near the lower bound).
        let mtu = (LSP_PDU_OVERHEAD + 5 + 3 * 18) as u16;

        let frags = pack_into_fragments(
            vec![area.clone()],
            tlvs.clone(),
            base,
            IsisLspTypes::from(2),
            1200,
            mtu,
            None,
        );
        assert!(
            frags.len() >= 2,
            "tight mtu should force at least 2 fragments"
        );

        // Snapshot every TLV's fragment id.
        let mut memory: BTreeMap<TlvKey, u8> = BTreeMap::new();
        let mut original: BTreeMap<TlvKey, u8> = BTreeMap::new();
        for f in &frags {
            for tlv in &f.tlvs {
                if let Some(key) = key_for_tlv(tlv) {
                    memory.insert(key, f.lsp_id.fragment_id());
                    original.insert(key, f.lsp_id.fragment_id());
                }
            }
        }

        // Drop the third TLV (the one most likely to be at the
        // boundary between fragments under tight budget) and re-pack
        // with the memory in hand.
        let mut tlvs_after = tlvs.clone();
        let dropped_key = key_for_tlv(&tlvs[2]).expect("third TLV has a stable key");
        tlvs_after.remove(2);
        let frags_after = pack_into_fragments(
            vec![area],
            tlvs_after,
            base,
            IsisLspTypes::from(2),
            1200,
            mtu,
            Some(&memory),
        );

        // Every survivor must be in the fragment it occupied before.
        for (key, &was) in &original {
            if *key == dropped_key {
                continue;
            }
            let now = frag_id_for(&frags_after, *key);
            assert_eq!(
                now,
                Some(was),
                "TLV {:?} moved: was frag {} now frag {:?}",
                key,
                was,
                now
            );
        }
    }
}
