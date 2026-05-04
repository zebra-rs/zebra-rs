use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use ospf_packet::*;

use super::link::PrefixSid;

#[derive(Debug, Default, PartialEq, Clone, Copy)]
pub enum SegmentRoutingMode {
    #[default]
    None,
    Mpls,
}

/// Default SRGB (Segment Routing Global Block).
const SRGB_START: u32 = 16000;
const SRGB_RANGE: u32 = 2001;

/// Default SRLB (Segment Routing Local Block).
const SRLB_START: u32 = 15000;
const SRLB_RANGE: u32 = 1000;

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
