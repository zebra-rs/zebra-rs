use std::net::Ipv4Addr;

use bytes::BytesMut;
use isis_packet::neigh::{self, IsisSubAdjSid};
use isis_packet::prefix::{self, Ipv4ControlInfo, Ipv6ControlInfo};
use isis_packet::*;

use crate::context::Timer;
use crate::isis_event_trace;
use crate::rib::util::IpNetExt;
use crate::rib::{DEFAULT_BLOCK_NAME, LocatorBehavior, MacAddr};

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

use super::config::{IsisConfig, MtId};
use super::ifsm::has_level;
use super::inst::{IsisTop, Message};
use super::level::Level;
use super::link::{IsisLinks, LinkTop};
use super::nfsm::NfsmState;

/// Decide which block this IS-IS instance should subscribe to.
///
/// `segment-routing mpls` enabled with no explicit `block` falls back to
/// the canonical "default" block seeded by the RIB; an explicit name takes
/// precedence. When SR-MPLS is disabled we want no subscription at all.
pub(super) fn target_block_name(cfg: &IsisConfig) -> Option<String> {
    if !cfg.sr_mpls_enabled {
        return None;
    }
    Some(
        cfg.sr_mpls_block
            .clone()
            .unwrap_or_else(|| DEFAULT_BLOCK_NAME.to_string()),
    )
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

/// Split a TLV 135 (Extended IP Reachability) whose serialized
/// value would overflow the 8-bit Length field into multiple TLV
/// instances of type 135, each ≤ 255 value-bytes. Entries are
/// distributed left-to-right; placement is stable per entry order.
fn split_ext_ip_reach(t: IsisTlvExtIpReach) -> Vec<IsisTlv> {
    let mut out: Vec<IsisTlv> = Vec::new();
    let mut current = IsisTlvExtIpReach::default();
    for entry in t.entries.into_iter() {
        current.entries.push(entry);
        let probe: IsisTlv = current.clone().into();
        if probe.wire_len() > TLV_WIRE_MAX {
            let latest = current.entries.pop().expect("just pushed");
            if !current.entries.is_empty() {
                out.push(current.into());
            }
            current = IsisTlvExtIpReach::default();
            current.entries.push(latest);
        }
    }
    if !current.entries.is_empty() {
        out.push(current.into());
    }
    out
}

/// Same split as `split_ext_ip_reach` but for TLV 236 (IPv6
/// Reachability).
fn split_ipv6_reach(t: IsisTlvIpv6Reach) -> Vec<IsisTlv> {
    let mut out: Vec<IsisTlv> = Vec::new();
    let mut current = IsisTlvIpv6Reach::default();
    for entry in t.entries.into_iter() {
        current.entries.push(entry);
        let probe: IsisTlv = current.clone().into();
        if probe.wire_len() > TLV_WIRE_MAX {
            let latest = current.entries.pop().expect("just pushed");
            if !current.entries.is_empty() {
                out.push(current.into());
            }
            current = IsisTlvIpv6Reach::default();
            current.entries.push(latest);
        }
    }
    if !current.entries.is_empty() {
        out.push(current.into());
    }
    out
}

/// Same split as above, for TLV 222 (MT IS Reachability). The 2-byte
/// MT ID prefix is preserved on every output instance.
fn split_mt_is_reach(t: IsisTlvMtIsReach) -> Vec<IsisTlv> {
    let mt = t.mt;
    let mut out: Vec<IsisTlv> = Vec::new();
    let mut current = IsisTlvMtIsReach {
        mt,
        entries: Vec::new(),
    };
    for entry in t.entries.into_iter() {
        current.entries.push(entry);
        let probe: IsisTlv = current.clone().into();
        if probe.wire_len() > TLV_WIRE_MAX {
            let latest = current.entries.pop().expect("just pushed");
            if !current.entries.is_empty() {
                out.push(current.into());
            }
            current = IsisTlvMtIsReach {
                mt,
                entries: Vec::new(),
            };
            current.entries.push(latest);
        }
    }
    if !current.entries.is_empty() {
        out.push(current.into());
    }
    out
}

/// Same split, for TLV 237 (MT IPv6 Reachability).
fn split_mt_ipv6_reach(t: IsisTlvMtIpv6Reach) -> Vec<IsisTlv> {
    let mt = t.mt;
    let mut out: Vec<IsisTlv> = Vec::new();
    let mut current = IsisTlvMtIpv6Reach {
        mt,
        entries: Vec::new(),
    };
    for entry in t.entries.into_iter() {
        current.entries.push(entry);
        let probe: IsisTlv = current.clone().into();
        if probe.wire_len() > TLV_WIRE_MAX {
            let latest = current.entries.pop().expect("just pushed");
            if !current.entries.is_empty() {
                out.push(current.into());
            }
            current = IsisTlvMtIpv6Reach {
                mt,
                entries: Vec::new(),
            };
            current.entries.push(latest);
        }
    }
    if !current.entries.is_empty() {
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
        IsisTlv::ExtIpReach(t) => split_ext_ip_reach(t),
        IsisTlv::Ipv6Reach(t) => split_ipv6_reach(t),
        IsisTlv::MtIsReach(t) => split_mt_is_reach(t),
        IsisTlv::MtIpv6Reach(t) => split_mt_ipv6_reach(t),
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
/// and the trailing TLVs are dropped. Phase 5 / RFC 5311 will
/// extend the namespace via virtual sys-IDs.
fn pack_into_fragments(
    anchors: Vec<IsisTlv>,
    distributable: Vec<IsisTlv>,
    base: IsisNeighborId,
    types: IsisLspTypes,
    hold_time: u16,
    lsp_mtu_size: u16,
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

    for tlv in distributable {
        let n = tlv.wire_len();
        let target = (0..frags.len()).find(|&i| frag_bytes[i] + n <= budget);
        if let Some(i) = target {
            frags[i].tlvs.push(tlv);
            frag_bytes[i] += n;
        } else {
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

    frags
}

pub fn dis_generate(
    top: &mut IsisTop,
    level: Level,
    ifindex: u32,
    base: Option<u32>,
) -> Option<IsisLsp> {
    let neighbor_id = if let Some(link) = top.links.get(&ifindex)
        && let Some((adj, _)) = link.state.adj.get(&level)
    {
        *adj
    } else {
        return None;
    };

    let lsp_id = IsisLspId::from_neighbor_id(neighbor_id, 0);

    // Determine sequence number based on base parameter and existing LSDB
    let seq_number = if let Some(base_seq) = base {
        // When base is provided, compare with existing LSDB sequence number
        let lsdb_seq = top.lsdb.get(&level).get(&lsp_id).map(|x| x.lsp.seq_number);

        match lsdb_seq {
            None => base_seq + 1, // No existing LSP, use base + 1
            Some(existing_seq) if base_seq >= existing_seq => base_seq + 1, // Base is larger or equal, use base + 1
            Some(existing_seq) => existing_seq + 1, // Existing is larger, use existing + 1
        }
    } else {
        // No base provided, use existing sequence number + 1 or start at 1
        top.lsdb
            .get(&level)
            .get(&lsp_id)
            .map(|x| x.lsp.seq_number + 1)
            .unwrap_or(0x0001)
    };
    let types = IsisLspTypes::from(level.digit());
    let mut lsp = IsisLsp {
        hold_time: top.config.hold_time(),
        lsp_id,
        seq_number,
        types,
        ..Default::default()
    };

    let mut is_reach = IsisTlvExtIsReach::default();
    let entry = IsisTlvExtIsReachEntry {
        neighbor_id: IsisNeighborId::from_sys_id(&top.config.net.sys_id(), 0),
        metric: 0,
        subs: vec![],
    };
    is_reach.entries.push(entry);

    if let Some(link) = top.links.get(&ifindex) {
        for (sys_id, nbr) in link.state.nbrs.get(&level).iter() {
            if nbr.state == NfsmState::Up {
                let neighbor_id = IsisNeighborId::from_sys_id(sys_id, 0);
                let entry = IsisTlvExtIsReachEntry {
                    neighbor_id,
                    metric: 0,
                    subs: vec![],
                };
                is_reach.entries.push(entry);
            }
        }
    }
    if !is_reach.entries.is_empty() {
        lsp.tlvs.push(IsisTlv::ExtIsReach(is_reach));
    }

    Some(lsp)
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
    let types = IsisLspTypes::from(level.digit());
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

            // Sub: SR Algorithms
            let algo = IsisSubSegmentRoutingAlgo {
                algo: vec![Algo::Spf],
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

        // SRv6 Capability sub-TLV. Only advertise when the configured
        // locator actually resolved in the RIB; an `srv6` container with
        // no usable locator means we have nothing to derive a SID from,
        // so we don't claim SRv6 capability.
        if top.config.sr_srv6_enabled && top.sr_locator.is_some() {
            let srv6 = IsisSubSrv6::default();
            cap.subs.push(srv6.into());

            // SR-MPLS already pushed Algorithms; for an SRv6-only config
            // we still need to advertise the algorithm list once.
            if !top.config.sr_mpls_enabled {
                let algo = IsisSubSegmentRoutingAlgo {
                    algo: vec![Algo::Spf],
                };
                cap.subs.push(algo.into());
            }
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
    let (end_behavior, endx_behavior, sid_structure_subs) = match top
        .sr_locator
        .as_ref()
        .and_then(|loc| loc.prefix.map(|p| (loc.behavior.as_ref(), p)))
    {
        Some((Some(LocatorBehavior::Usid), prefix)) => {
            let plen = prefix.prefix_len();
            let lb_len = plen.min(32);
            let structure = IsisSub2Tlv::SidStructure(IsisSub2SidStructure {
                lb_len,
                ln_len: plen.saturating_sub(lb_len),
                fun_len: 16,
                arg_len: 0,
            });
            (Behavior::EndCSID, Behavior::EndXCSID, vec![structure])
        }
        Some((None, prefix)) => {
            let plen = prefix.prefix_len();
            let lb_len = plen.min(40);
            let structure = IsisSub2Tlv::SidStructure(IsisSub2SidStructure {
                lb_len,
                ln_len: plen.saturating_sub(lb_len),
                fun_len: 16,
                arg_len: 0,
            });
            (Behavior::End, Behavior::EndX, vec![structure])
        }
        None => (Behavior::End, Behavior::EndX, Vec::new()),
    };

    // SRv6 Locators TLV (RFC 9352 §7.1, type 27). One sub-locator per
    // active locator; today we only carry one. The contained End SID
    // sub-TLV (RFC 9352 §7.2) advertises the Node SID we registered
    // with the RIB. Both `sr_locator` and `sr_end_sid` must be set —
    // sr_end_sid is only populated when the locator's prefix produced
    // a usable address.
    if let Some(locator) = top.sr_locator.as_ref()
        && let Some(end_sid) = *top.sr_end_sid
        && let Some(prefix) = locator.prefix
    {
        let end_sub = IsisSubSrv6EndSid {
            flags: 0,
            behavior: end_behavior,
            sid: end_sid,
            sub2s: sid_structure_subs.clone(),
        };
        let sub_locator = Srv6Locator {
            metric: 0,
            flags: 0,
            algo: Algo::Spf,
            locator: prefix,
            subs: vec![prefix::IsisSubTlv::Srv6EndSid(end_sub)],
        };
        let srv6_tlv = IsisTlvSrv6 {
            flags: Default::default(),
            locators: vec![sub_locator],
        };
        distributable.push(IsisTlv::Srv6(srv6_tlv));
    }

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
                    .flat_map(|nbr| nbr.addr6.keys().copied())
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
                            flags: 0.into(),
                            algo: Algo::Spf,
                            sid: sid.clone(),
                        };
                        Some(prefix::IsisSubTlv::PrefixSid(prefix_sid))
                    } else {
                        None
                    };
                    let flags = Ipv4ControlInfo::new()
                        .with_prefixlen(prefix.prefix_len() as usize)
                        .with_sub_tlv(sub_tlv.is_some())
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
                    ext_ip_reach.entries.push(entry);
                }
            }
        }
    }
    // Operator-configured `network` prefixes — BGP-style. Metric 0 so
    // receivers add only their own IS-reach metric to us, matching the
    // SRv6-locator advertise pattern below.
    for prefix in top.config.networks_v4.iter() {
        let flags = Ipv4ControlInfo::new()
            .with_prefixlen(prefix.prefix_len() as usize)
            .with_sub_tlv(false)
            .with_distribution(false);
        ext_ip_reach.entries.push(IsisTlvExtIpReachEntry {
            metric: 0,
            flags,
            prefix: *prefix,
            subs: vec![],
        });
    }
    if !ext_ip_reach.entries.is_empty() {
        distributable.push(ext_ip_reach.into());
    }

    // IPv6 Reachability.
    let mut ipv6_reach = IsisTlvIpv6Reach::default();
    for (_, link) in top.links.iter() {
        if link.config.enable.v6 && has_level(link.state.level(), level) {
            for v6addr in link.state.v6addr.iter() {
                if !v6addr.addr().is_loopback() {
                    let sub_tlv = false;
                    let flags = Ipv6ControlInfo::new().with_sub_tlv(sub_tlv);
                    let entry = IsisTlvIpv6ReachEntry {
                        metric: 10,
                        flags,
                        prefix: *v6addr,
                        subs: Vec::new(),
                    };
                    ipv6_reach.entries.push(entry);
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
        let flags = Ipv6ControlInfo::new().with_sub_tlv(false);
        ipv6_reach.entries.push(IsisTlvIpv6ReachEntry {
            metric: 0,
            flags,
            prefix,
            subs: Vec::new(),
        });
    }
    // Operator-configured IPv6 `network` prefixes — sibling of the
    // IPv4 path above. Same metric-0 rationale.
    for prefix in top.config.networks_v6.iter() {
        let flags = Ipv6ControlInfo::new().with_sub_tlv(false);
        ipv6_reach.entries.push(IsisTlvIpv6ReachEntry {
            metric: 0,
            flags,
            prefix: *prefix,
            subs: Vec::new(),
        });
    }
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
    let mut fragments = pack_into_fragments(
        anchors,
        distributable,
        IsisNeighborId::from_sys_id(&top.config.net.sys_id(), 0),
        types,
        top.config.hold_time(),
        top.config.lsp_mtu_size(),
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

pub fn lsp_emit(lsp: &mut IsisLsp, level: Level) -> BytesMut {
    let packet = match level {
        Level::L1 => IsisPacket::from(IsisType::L1Lsp, IsisPdu::L1Lsp(lsp.clone())),
        Level::L2 => IsisPacket::from(IsisType::L2Lsp, IsisPdu::L2Lsp(lsp.clone())),
    };

    let mut buf = BytesMut::new();
    packet.emit(&mut buf);

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

        let total_base_len = packet_len + base_len + tlv_header_len;

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
            let csnp = IsisCsnp {
                pdu_len: 0,
                source_id: link.up_config.net.sys_id(),
                source_id_circuit: 0,
                start: start.unwrap_or(IsisLspId::start()),
                end: lsa.lsp.lsp_id,
                tlvs: vec![tlvs.clone().into()],
            };
            csnps.push(csnp);

            tlvs.entries.clear();
            entry_size = 0;
            start = None;
        }
    }
    if !tlvs.entries.is_empty() {
        let csnp = IsisCsnp {
            pdu_len: 0,
            source_id: link.up_config.net.sys_id(),
            source_id_circuit: 0,
            start: start.unwrap_or(IsisLspId::start()),
            end: IsisLspId::end(),
            tlvs: vec![tlvs.into()],
        };
        csnps.push(csnp);
    }

    csnps
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_block_falls_back_to_default_when_unset() {
        // SR-MPLS enabled but no explicit block configured: should
        // subscribe to the canonical "default" block.
        let cfg = IsisConfig {
            sr_mpls_enabled: true,
            ..Default::default()
        };
        assert_eq!(target_block_name(&cfg), Some("default".to_string()));
    }

    #[test]
    fn target_block_uses_explicit_name_when_set() {
        let cfg = IsisConfig {
            sr_mpls_enabled: true,
            sr_mpls_block: Some("custom".into()),
            ..Default::default()
        };
        assert_eq!(target_block_name(&cfg), Some("custom".to_string()));
    }

    #[test]
    fn target_block_returns_none_when_mpls_disabled() {
        // The block name on its own should never produce a watch when
        // SR-MPLS isn't enabled — otherwise we'd subscribe to stale
        // config left behind after disabling the container.
        let cfg = IsisConfig {
            sr_mpls_block: Some("custom".into()),
            ..Default::default()
        };
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
        let shards = split_ext_ip_reach(tlv);
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
}
