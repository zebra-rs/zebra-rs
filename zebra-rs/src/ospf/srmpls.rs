use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use ospf_packet::*;

use super::link::{AdjacencySid, PrefixSid};

#[derive(Debug, Default, PartialEq, Clone, Copy)]
pub enum SegmentRoutingMode {
    #[default]
    None,
    Mpls,
}

/// Default SRGB (Segment Routing Global Block).
pub(super) const SRGB_START: u32 = 16000;
const SRGB_RANGE: u32 = 2001;

/// Default SRLB (Segment Routing Local Block).
pub(super) const SRLB_START: u32 = 15000;
pub(super) const SRLB_RANGE: u32 = 1000;

/// Build a Router Information Opaque LSA for SR-MPLS.
pub fn router_info_lsa_build(router_id: Ipv4Addr) -> OspfLsa {
    let mut tlvs = Vec::new();

    // Router Capabilities TLV (type 1): TE support (bit 3).
    let caps = RouterCapability::new().with_te(true);
    tlvs.push(RouterInfoTlv::RouterInfo(RouterInfoTlvCap { caps }));

    // SR Algorithm TLV (type 8): SPF (algorithm 0).
    tlvs.push(RouterInfoTlv::Algo(RouterInfoTlvAlgo {
        algos: vec![Algo::Spf],
    }));

    // SID/Label Range TLV (type 9): Global block.
    tlvs.push(RouterInfoTlv::SidLabelRnage(RouterInfoTlvSidLabelRange {
        range: SRGB_RANGE,
        sid_label: SidLabelTlv::Label(SRGB_START),
    }));

    // SR Local Block TLV (type 14): Local block.
    tlvs.push(RouterInfoTlv::LocalBlock(RouterInfoTlvLocalBlock {
        range: SRLB_RANGE,
        sid_label: SidLabelTlv::Label(SRLB_START),
    }));

    let ri_lsa = RouterInfoLsa { tlvs };

    // Opaque Area LSA: ls_id encodes opaque type (4=RouterInfo) in first byte,
    // opaque ID (0) in remaining 3 bytes.
    let ls_id = Ipv4Addr::from((OpaqueLsaType::ROUTER_INFO as u32) << 24);
    let mut lsah = OspfLsaHeader::new(OspfLsType::OpaqueAreaLocal, ls_id, router_id);
    lsah.options = 0x42; // O-bit (Opaque capable) + E-bit.

    let mut lsa = OspfLsa::from(lsah, OspfLsp::OpaqueAreaRouterInfo(ri_lsa));
    lsa.update();
    lsa
}

/// Build an Extended Prefix Opaque LSA for a prefix with Prefix SID.
pub fn ext_prefix_lsa_build(
    router_id: Ipv4Addr,
    prefix: Ipv4Net,
    prefix_sid: &PrefixSid,
    opaque_id: u32,
) -> OspfLsa {
    let (sid, flags) = match prefix_sid {
        PrefixSid::Index(idx) => (
            SidLabelTlv::Index(*idx),
            PrefixSidFlags::new().with_np_flag(true),
        ),
        PrefixSid::Absolute(label) => (
            SidLabelTlv::Label(*label),
            PrefixSidFlags::new().with_v_flag(true).with_l_flag(true),
        ),
    };

    let sid_sub = ExtPrefixSidSubTlv {
        flags,
        mt_id: 0,
        algo: Algo::Spf,
        sid,
    };

    let tlv = ExtPrefixTlv {
        route_type: 1, // Intra-area.
        prefix,
        af: 0, // IPv4 unicast.
        flags: 0,
        subs: vec![ExtPrefixSubTlv::PrefixSid(sid_sub)],
    };

    let ep_lsa = ExtPrefixLsa { tlvs: vec![tlv] };

    let ls_id =
        Ipv4Addr::from(((OpaqueLsaType::EXT_PREFIX as u32) << 24) | (opaque_id & 0x00FF_FFFF));
    let mut lsah = OspfLsaHeader::new(OspfLsType::OpaqueAreaLocal, ls_id, router_id);
    lsah.options = 0x42; // O-bit + E-bit.

    let mut lsa = OspfLsa::from(lsah, OspfLsp::OpaqueAreaExtPrefix(ep_lsa));
    lsa.update();
    lsa
}

/// Build an Extended Link Opaque LSA (RFC 7684 §3) for a single link
/// with caller-supplied sub-TLVs.
///
/// `link_type` matches the OSPFv2 Router-LSA link_type encoding (1 =
/// P2P, 2 = Transit broadcast / NBMA, 4 = Virtual). `subs` is the
/// full sub-TLV list to embed: one `AdjSidSubTlv` for P2P, or one
/// `LanAdjSidSubTlv` per Full neighbor on broadcast / NBMA per
/// RFC 8665 §6.
///
/// The `_build_p2p_adj_sub` / `_build_lan_adj_sub` helpers below
/// take the more common Adj-SID flag conventions off the caller's
/// hands.
pub fn ext_link_lsa_build(
    router_id: Ipv4Addr,
    link_type: u8,
    link_id: Ipv4Addr,
    link_data: Ipv4Addr,
    subs: Vec<ExtLinkSubTlv>,
    opaque_id: u32,
) -> OspfLsa {
    let tlv = ExtLinkTlv {
        link_type,
        link_id,
        link_data,
        subs,
    };

    let el_lsa = ExtLinkLsa { tlvs: vec![tlv] };

    let ls_id =
        Ipv4Addr::from(((OpaqueLsaType::EXT_LINK as u32) << 24) | (opaque_id & 0x00FF_FFFF));
    let mut lsah = OspfLsaHeader::new(OspfLsType::OpaqueAreaLocal, ls_id, router_id);
    lsah.options = 0x42; // O-bit + E-bit.

    let mut lsa = OspfLsa::from(lsah, OspfLsp::OpaqueAreaExtLink(el_lsa));
    lsa.update();
    lsa
}

/// Construct an `AdjSidSubTlv` from a configured Adjacency-SID (P2P
/// case). Flag semantics mirror the Prefix-SID build: Index-form
/// carries no value/local flags (the index is resolved against the
/// peer's SRGB); Absolute Label sets V (Value) + L (Local) per
/// RFC 8665 §5.
pub fn build_p2p_adj_sub(adjacency_sid: &AdjacencySid) -> ExtLinkSubTlv {
    let (sid, flags) = match adjacency_sid {
        AdjacencySid::Index(idx) => (SidLabelTlv::Index(*idx), AdjSidFlags::new()),
        AdjacencySid::Absolute(label) => (
            SidLabelTlv::Label(*label),
            AdjSidFlags::new().with_v_flag(true).with_l_flag(true),
        ),
    };
    ExtLinkSubTlv::AdjSid(AdjSidSubTlv {
        flags,
        mt_id: 0,
        weight: 0,
        sid,
    })
}

/// Construct a `LanAdjSidSubTlv` (RFC 8665 §6) for a single Full
/// neighbor on a broadcast / NBMA segment. `label` is the absolute
/// SRLB-allocated value held in `Ospf::lan_adj_sids`. V + L flags
/// are set unconditionally — LAN Adj-SIDs we originate are always
/// in raw-Label form (drawn from our local SRLB).
pub fn build_lan_adj_sub(neighbor_id: Ipv4Addr, label: u32) -> ExtLinkSubTlv {
    ExtLinkSubTlv::LanAdjSid(LanAdjSidSubTlv {
        flags: AdjSidFlags::new().with_v_flag(true).with_l_flag(true),
        mt_id: 0,
        weight: 0,
        neighbor_id,
        sid: SidLabelTlv::Label(label),
    })
}
