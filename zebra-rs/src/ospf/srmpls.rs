use std::net::Ipv4Addr;

use ipnet::{Ipv4Net, Ipv6Net};
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

    // Router Capabilities TLV (type 1, RFC 7770 §2.1):
    //   - bit 3 (te)         — Traffic Engineering support.
    //   - bit 4 (gr_helper)  — Graceful Restart helper-mode capable
    //                          (RFC 3623). zebra-rs supports helper
    //                          unconditionally today; Phase 4 will
    //                          gate this on the YANG knob
    //                          `graceful-restart/helper-enabled`.
    // `gr_capable` (bit 5) stays clear — we do not yet originate
    // Grace LSAs as a restarter (Phase 5 deferred).
    let caps = RouterCapability::new().with_te(true).with_gr_helper(true);
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

/// Build an OSPFv3 E-Router-LSA (RFC 8362 §3.1) carrying one
/// Router-Link TLV (P2P) whose sub-TLV is an Adj-SID (RFC 8666
/// §6.1) for a single Full neighbor.
///
/// Flag semantics mirror the v2 path: Index form leaves V + L
/// clear (the index resolves against the peer's SRGB); Absolute
/// Label sets V + L per RFC 8666 §6.1. `link_state_id` is the
/// caller-supplied per-LSA key (ifindex by convention).
pub fn e_router_v3_lsa_build(
    router_id: Ipv4Addr,
    metric: u16,
    our_interface_id: u32,
    neighbor_interface_id: u32,
    neighbor_router_id: Ipv4Addr,
    adjacency_sid: &AdjacencySid,
    link_state_id: u32,
) -> Ospfv3Lsa {
    let (sid, flags) = match adjacency_sid {
        AdjacencySid::Index(idx) => (SidLabelTlv::Index(*idx), AdjSidFlags::new()),
        AdjacencySid::Absolute(label) => (
            SidLabelTlv::Label(*label),
            AdjSidFlags::new().with_v_flag(true).with_l_flag(true),
        ),
    };

    let adj_sub = Ospfv3SubTlv::AdjSid(Ospfv3AdjSidSubTlv {
        flags,
        weight: 0,
        sid,
    });

    let link = Ospfv3RouterLsaLink::new(
        Ospfv3RouterLinkType::PointToPoint,
        metric,
        our_interface_id,
        neighbor_interface_id,
        neighbor_router_id,
    );

    let router_link_tlv = Ospfv3ExtTlv::RouterLink(Ospfv3RouterLinkTlv {
        link,
        subs: vec![adj_sub],
    });

    let body = Ospfv3ELsaBody {
        tlvs: vec![router_link_tlv],
    };

    let mut lsa = Ospfv3Lsa {
        h: Ospfv3LsaHeader {
            ls_age: 0,
            ls_type: OSPFV3_E_ROUTER_LSA_TYPE,
            link_state_id,
            advertising_router: router_id,
            ls_seq_number: 0x8000_0001,
            ls_checksum: 0,
            length: 0,
        },
        body: Ospfv3LsBody::ERouter(body),
    };
    lsa.update();
    lsa
}

/// Build an OSPFv3 E-Intra-Area-Prefix-LSA (RFC 8362 §3.7) carrying
/// one Intra-Area-Prefix TLV whose sub-TLV is a Prefix-SID (RFC 8666
/// §5) for the given IPv6 prefix.
///
/// `link_state_id` is the LSA's per-router ID -- mirrors the v2
/// opaque-id convention of deriving from the interface ifindex so a
/// per-link LSA gets a stable key across re-originations.
///
/// Flag semantics mirror the v2 path: Index-form SID carries the NP
/// (No-PHP) flag so the upstream does not pop; Absolute-Label SID
/// carries V (Value) + L (Local) per RFC 8666 §5.
pub fn ext_intra_area_prefix_v3_lsa_build(
    router_id: Ipv4Addr,
    prefix: Ipv6Net,
    prefix_sid: &PrefixSid,
    link_state_id: u32,
    metric: u16,
) -> Ospfv3Lsa {
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

    let prefix_sid_sub = Ospfv3SubTlv::PrefixSid(Ospfv3PrefixSidSubTlv {
        flags,
        algo: Algo::Spf,
        sid,
    });

    // Encode the prefix bytes padded to a 4-byte boundary per
    // RFC 5340 §A.4.1.1, matching the existing v3 codec convention.
    let prefix_length = prefix.prefix_len();
    let wire_len = ospfv3_prefix_wire_len(prefix_length);
    let mut address_prefix = vec![0u8; wire_len];
    let bytes = prefix.addr().octets();
    let copy_len = (prefix_length as usize).div_ceil(8);
    address_prefix[..copy_len].copy_from_slice(&bytes[..copy_len]);

    let prefix_tlv = Ospfv3ExtTlv::IntraAreaPrefix(Ospfv3IntraAreaPrefixTlv {
        metric,
        prefix_length,
        prefix_options: Ospfv3PrefixOptions::default(),
        // Reference our own Router-LSA -- this is a self-originated
        // Router-LSA-referenced Intra-Area-Prefix per RFC 5340 §A.4.10
        // (mirroring the standard LSA's convention). Network-LSA-
        // referenced variants land alongside the DR-only flow.
        referenced_ls_type: OSPFV3_ROUTER_LSA_TYPE as u32,
        referenced_link_state_id: 0,
        referenced_advertising_router: router_id,
        address_prefix,
        subs: vec![prefix_sid_sub],
    });

    let body = Ospfv3ELsaBody {
        tlvs: vec![prefix_tlv],
    };

    let mut lsa = Ospfv3Lsa {
        h: Ospfv3LsaHeader {
            ls_age: 0,
            ls_type: OSPFV3_E_INTRA_AREA_PREFIX_LSA_TYPE,
            link_state_id,
            advertising_router: router_id,
            ls_seq_number: 0x8000_0001,
            ls_checksum: 0,
            length: 0,
        },
        body: Ospfv3LsBody::EIntraAreaPrefix(body),
    };
    lsa.update();
    lsa
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7770 §2.1 capability bits in the originated Router-Info
    /// Opaque LSA: TE (bit 3) and GR-helper (bit 4) set;
    /// GR-capable (bit 5) clear because zebra-rs is helper-only
    /// (Phase 5 deferred).
    #[test]
    fn router_info_lsa_advertises_te_and_gr_helper() {
        let lsa = router_info_lsa_build(Ipv4Addr::new(10, 0, 0, 1));
        let OspfLsp::OpaqueAreaRouterInfo(ref ri) = lsa.lsp else {
            panic!("expected OpaqueAreaRouterInfo, got {:?}", lsa.lsp);
        };
        let cap = ri
            .tlvs
            .iter()
            .find_map(|t| match t {
                RouterInfoTlv::RouterInfo(c) => Some(c.caps),
                _ => None,
            })
            .expect("Router Capabilities TLV must be present");
        assert!(cap.te(), "TE bit must be set");
        assert!(cap.gr_helper(), "GR helper bit must be set");
        assert!(!cap.gr_capable(), "GR restarter bit must remain clear");
        assert!(!cap.stub(), "stub bit must remain clear");
    }
}
