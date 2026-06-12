use std::collections::BTreeMap;
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
pub(super) const SRGB_RANGE: u32 = 2001;

/// Default SRLB (Segment Routing Local Block).
pub(super) const SRLB_START: u32 = 15000;
pub(super) const SRLB_RANGE: u32 = 1000;

/// Build a Router Information Opaque LSA for SR-MPLS.
///
/// `gr_capable` reflects whether we are currently advertising
/// restarting-router capability (RFC 3623 / RFC 7770 §2.1 bit 5).
/// Set to `true` while `Ospf::restarting.is_some()` so helpers
/// see us as a planned-restart originator; clear otherwise.
pub fn router_info_lsa_build(
    router_id: Ipv4Addr,
    gr_capable: bool,
    algos: Vec<Algo>,
    fads: Vec<RouterInfoTlvFad>,
) -> OspfLsa {
    let mut tlvs = Vec::new();

    // Router Capabilities TLV (type 1, RFC 7770 §2.1):
    //   - bit 3 (te)         — Traffic Engineering support.
    //   - bit 4 (gr_helper)  — Graceful Restart helper-mode capable
    //                          (RFC 3623).
    //   - bit 5 (gr_capable) — Restarter capable; toggles on while
    //                          we're staged for a planned restart.
    let caps = RouterCapability::new()
        .with_te(true)
        .with_gr_helper(true)
        .with_gr_capable(gr_capable);
    tlvs.push(RouterInfoTlv::RouterInfo(RouterInfoTlvCap { caps }));

    // SR Algorithm TLV (type 8, RFC 8665 §3.1): SPF (algorithm 0) plus
    // every configured Flexible Algorithm (RFC 9350 §6). The caller
    // passes `flex_algo::sr_algorithms(&ospf.flex_algo)`.
    tlvs.push(RouterInfoTlv::Algo(RouterInfoTlvAlgo { algos }));

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

    // Flexible Algorithm Definition TLVs (type 16, RFC 9350 §6.1): one
    // per algo this router originates a FAD for (advertise-definition).
    for fad in fads {
        tlvs.push(RouterInfoTlv::Fad(fad));
    }

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

/// Build one Prefix-SID sub-TLV (RFC 8665 §5 / RFC 9350 §7) for the
/// given algorithm from a configured Prefix-SID.
fn ext_prefix_sid_sub(algo: Algo, prefix_sid: &PrefixSid) -> ExtPrefixSubTlv {
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
    ExtPrefixSubTlv::PrefixSid(ExtPrefixSidSubTlv {
        flags,
        mt_id: 0,
        algo,
        sid,
    })
}

/// Build an Extended Prefix Opaque LSA for a prefix, carrying the
/// algo-0 Prefix-SID (if configured) plus a per-Flex-Algorithm
/// Prefix-SID sub-TLV for every entry in `flex_algo_sids` (RFC 9350
/// §7, Algorithm = FlexAlgo(N)).
pub fn ext_prefix_lsa_build(
    router_id: Ipv4Addr,
    prefix: Ipv4Net,
    prefix_sid: Option<&PrefixSid>,
    flex_algo_sids: &BTreeMap<u8, PrefixSid>,
    opaque_id: u32,
) -> OspfLsa {
    let mut subs = Vec::new();
    if let Some(ps) = prefix_sid {
        subs.push(ext_prefix_sid_sub(Algo::Spf, ps));
    }
    for (algo, sid) in flex_algo_sids {
        subs.push(ext_prefix_sid_sub(Algo::FlexAlgo(*algo), sid));
    }

    let tlv = ExtPrefixTlv {
        route_type: 1, // Intra-area.
        prefix,
        af: 0, // IPv4 unicast.
        flags: 0,
        subs,
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
/// Router-Link TLV with caller-supplied sub-TLVs.
///
/// `link_type` matches the v3 Router-LSA link encoding
/// (PointToPoint, Transit, VirtualLink). `subs` is the full sub-TLV
/// list to embed: one `AdjSid` for P2P, or one `LanAdjSid` per Full
/// neighbor on broadcast / NBMA per RFC 8666 §6.
///
/// `link_state_id` is the caller-supplied per-LSA key (ifindex by
/// convention).
pub fn e_router_v3_lsa_build(
    router_id: Ipv4Addr,
    link_type: Ospfv3RouterLinkType,
    metric: u16,
    our_interface_id: u32,
    neighbor_interface_id: u32,
    neighbor_router_id: Ipv4Addr,
    subs: Vec<Ospfv3SubTlv>,
    link_state_id: u32,
) -> Ospfv3Lsa {
    let link = Ospfv3RouterLsaLink::new(
        link_type,
        metric,
        our_interface_id,
        neighbor_interface_id,
        neighbor_router_id,
    );

    let router_link_tlv = Ospfv3ExtTlv::RouterLink(Ospfv3RouterLinkTlv { link, subs });

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
        raw: None,
    };
    lsa.update();
    lsa
}

/// Build an OSPFv3 E-Router-LSA carrying only the RFC 8666 §3 SR
/// capability TLVs (SR-Algorithm, SID/Label Range = SRGB, SR Local
/// Block = SRLB) and no Router-Link TLV. One per area; peers read it
/// to translate Index-form SIDs we advertise into absolute labels.
///
/// `link_state_id` is reserved as `SR_INFO_LSID` so it cannot collide
/// with the per-link LSAs (whose LS-ID is the interface ifindex, ≥ 1
/// on Linux). RFC 5340 §3.4 treats the Link State ID as router-local
/// per LS-Type, so we own the namespace.
///
/// The SRGB / SRLB are advertised as absolute Label blocks (the V/L
/// equivalent in the Sub-TLV length discriminator), matching how
/// `srmpls.rs` already pins the local pool to hardcoded constants.
/// When configurable SRGB / SRLB land, the builder will read the
/// configured range here.
pub const SR_INFO_LSID: u32 = 0;

/// `algos` lists every algorithm this router participates in (regular
/// SPF + configured flex-algos), advertised in the SR-Algorithm TLV
/// (RFC 8666 §3.1). `fads` carries the Flexible Algorithm Definitions
/// (RFC 9350 §7.1) this router originates — one `Ospfv3ExtTlv::Fad`
/// each, appended after the SR capability TLVs in the same per-router
/// E-Router-LSA (the v3 home of the FAD, mirroring how the v2 FAD rides
/// the Router Information Opaque LSA).
pub fn e_router_v3_sr_info_lsa_build(
    router_id: Ipv4Addr,
    algos: Vec<Algo>,
    fads: Vec<Ospfv3FadTlv>,
    srv6: bool,
) -> Ospfv3Lsa {
    let sr_algo = Ospfv3ExtTlv::SrAlgorithm(Ospfv3SrAlgorithmTlv { algos });
    let sid_range = Ospfv3ExtTlv::SidLabelRange(Ospfv3SidLabelRangeTlv {
        range: SRGB_RANGE,
        sid_label: SidLabelTlv::Label(SRGB_START),
    });
    let local_block = Ospfv3ExtTlv::SrLocalBlock(Ospfv3SrLocalBlockTlv {
        range: SRLB_RANGE,
        sid_label: SidLabelTlv::Label(SRLB_START),
    });

    let mut tlvs = vec![sr_algo, sid_range, local_block];
    tlvs.extend(fads.into_iter().map(Ospfv3ExtTlv::Fad));
    if srv6 {
        // RFC 9513 §2 SRv6 Capabilities (RI TLV 20), riding this
        // SR-info E-Router-LSA like the other RI-style TLVs. No O-bit
        // support, no sub-TLVs — flags 0.
        tlvs.push(Ospfv3ExtTlv::Srv6Capabilities(
            ospf_packet::Ospfv3Srv6CapabilitiesTlv { flags: 0 },
        ));
    }

    let body = Ospfv3ELsaBody { tlvs };

    let mut lsa = Ospfv3Lsa {
        h: Ospfv3LsaHeader {
            ls_age: 0,
            ls_type: OSPFV3_E_ROUTER_LSA_TYPE,
            link_state_id: SR_INFO_LSID,
            advertising_router: router_id,
            ls_seq_number: 0x8000_0001,
            ls_checksum: 0,
            length: 0,
        },
        body: Ospfv3LsBody::ERouter(body),
        raw: None,
    };
    lsa.update();
    lsa
}

/// Construct an OSPFv3 `Ospfv3AdjSidSubTlv` from a configured
/// Adjacency-SID (P2P case). Flag semantics mirror the v2 path's
/// `build_p2p_adj_sub`: Index form leaves V + L clear; Absolute
/// Label sets V + L per RFC 8666 §6.1.
pub fn build_v3_p2p_adj_sub(adjacency_sid: &AdjacencySid) -> Ospfv3SubTlv {
    let (sid, flags) = match adjacency_sid {
        AdjacencySid::Index(idx) => (SidLabelTlv::Index(*idx), AdjSidFlags::new()),
        AdjacencySid::Absolute(label) => (
            SidLabelTlv::Label(*label),
            AdjSidFlags::new().with_v_flag(true).with_l_flag(true),
        ),
    };
    Ospfv3SubTlv::AdjSid(Ospfv3AdjSidSubTlv {
        flags,
        weight: 0,
        sid,
    })
}

/// Construct an OSPFv3 `Ospfv3LanAdjSidSubTlv` (RFC 8666 §6.2) for
/// a single Full neighbor on a broadcast / NBMA segment. `label` is
/// the absolute SRLB-allocated value held in `Ospf::lan_adj_sids`.
/// V + L flags are set unconditionally — LAN Adj-SIDs we originate
/// are always raw labels from the local SRLB.
pub fn build_v3_lan_adj_sub(neighbor_router_id: Ipv4Addr, label: u32) -> Ospfv3SubTlv {
    Ospfv3SubTlv::LanAdjSid(Ospfv3LanAdjSidSubTlv {
        flags: AdjSidFlags::new().with_v_flag(true).with_l_flag(true),
        weight: 0,
        neighbor_router_id,
        sid: SidLabelTlv::Label(label),
    })
}

/// Build one OSPFv3 Prefix-SID sub-TLV (RFC 8666 §5) for `algo`. Flag
/// semantics mirror the v2 path: Index-form SID carries the NP (No-PHP)
/// flag so the upstream does not pop; Absolute-Label SID carries V
/// (Value) + L (Local).
fn ext_prefix_sid_sub_v3(algo: Algo, prefix_sid: &PrefixSid) -> Ospfv3SubTlv {
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
    Ospfv3SubTlv::PrefixSid(Ospfv3PrefixSidSubTlv { flags, algo, sid })
}

/// Build an OSPFv3 E-Intra-Area-Prefix-LSA (RFC 8362 §3.7) carrying
/// one Intra-Area-Prefix TLV for the given IPv6 prefix, with the algo-0
/// Prefix-SID (if configured) plus a per-Flexible-Algorithm Prefix-SID
/// sub-TLV for every entry in `flex_algo_sids` (RFC 9350 §7,
/// Algorithm = FlexAlgo(N)). OSPFv3 analog of `ext_prefix_lsa_build`.
///
/// `link_state_id` is the LSA's per-router ID -- mirrors the v2
/// opaque-id convention of deriving from the interface ifindex so a
/// per-link LSA gets a stable key across re-originations.
pub fn ext_intra_area_prefix_v3_lsa_build(
    router_id: Ipv4Addr,
    prefix: Ipv6Net,
    prefix_sid: Option<&PrefixSid>,
    flex_algo_sids: &BTreeMap<u8, PrefixSid>,
    link_state_id: u32,
    metric: u16,
) -> Ospfv3Lsa {
    let mut subs = Vec::new();
    if let Some(ps) = prefix_sid {
        subs.push(ext_prefix_sid_sub_v3(Algo::Spf, ps));
    }
    for (algo, sid) in flex_algo_sids {
        subs.push(ext_prefix_sid_sub_v3(Algo::FlexAlgo(*algo), sid));
    }

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
        subs,
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
        raw: None,
    };
    lsa.update();
    lsa
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wire roundtrip of the RFC 8666 §5 E-Intra-Area-Prefix-LSA: the
    /// receiver must reconstruct the exact prefix bytes the originator
    /// advertised. Guards the BDD-found bug where every received
    /// Prefix-SID stamped onto a mangled prefix instead of the
    /// advertised loopback.
    #[test]
    fn ext_intra_area_prefix_v3_lsa_roundtrip() {
        use bytes::BytesMut;
        use packet_utils::ParseBe;
        use std::net::Ipv6Addr;

        let prefix: Ipv6Net = "2001:db8::5/128".parse().unwrap();
        let sid = PrefixSid::Index(500);
        let lsa = ext_intra_area_prefix_v3_lsa_build(
            Ipv4Addr::new(10, 0, 0, 5),
            prefix,
            Some(&sid),
            &BTreeMap::new(),
            1,
            0,
        );

        let mut buf = BytesMut::new();
        lsa.emit(&mut buf);
        let (_, parsed) = Ospfv3Lsa::parse_be(&buf).expect("LSA must parse");

        assert_eq!(parsed.h.ls_type, OSPFV3_E_INTRA_AREA_PREFIX_LSA_TYPE);
        let Ospfv3LsBody::EIntraAreaPrefix(ref body) = parsed.body else {
            panic!("expected EIntraAreaPrefix body, got {:?}", parsed.body);
        };
        let Ospfv3ExtTlv::IntraAreaPrefix(ref tlv) = body.tlvs[0] else {
            panic!("expected IntraAreaPrefix TLV, got {:?}", body.tlvs[0]);
        };
        assert_eq!(tlv.prefix_length, 128);
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&tlv.address_prefix[..16]);
        assert_eq!(
            Ipv6Addr::from(bytes),
            "2001:db8::5".parse::<Ipv6Addr>().unwrap(),
            "address_prefix must survive the wire roundtrip"
        );
        assert!(
            tlv.subs.iter().any(
                |s| matches!(s, Ospfv3SubTlv::PrefixSid(p) if p.sid == SidLabelTlv::Index(500))
            ),
            "Prefix-SID sub-TLV must survive the wire roundtrip"
        );
    }

    fn extract_caps(lsa: &OspfLsa) -> RouterCapability {
        let OspfLsp::OpaqueAreaRouterInfo(ref ri) = lsa.lsp else {
            panic!("expected OpaqueAreaRouterInfo, got {:?}", lsa.lsp);
        };
        ri.tlvs
            .iter()
            .find_map(|t| match t {
                RouterInfoTlv::RouterInfo(c) => Some(c.caps),
                _ => None,
            })
            .expect("Router Capabilities TLV must be present")
    }

    /// RFC 7770 §2.1 capability bits in steady state: TE (bit 3)
    /// and GR-helper (bit 4) set; GR-capable (bit 5) clear.
    #[test]
    fn router_info_lsa_steady_state_caps() {
        let lsa = router_info_lsa_build(Ipv4Addr::new(10, 0, 0, 1), false, vec![Algo::Spf], vec![]);
        let cap = extract_caps(&lsa);
        assert!(cap.te(), "TE bit must be set");
        assert!(cap.gr_helper(), "GR helper bit must be set");
        assert!(
            !cap.gr_capable(),
            "GR restarter bit must remain clear in steady state"
        );
        assert!(!cap.stub(), "stub bit must remain clear");
    }

    /// While the restarter is staged (`gr_restart_begin`),
    /// GR-capable (bit 5) is set to advertise the planned restart
    /// to helpers.
    #[test]
    fn router_info_lsa_restarting_sets_gr_capable() {
        let lsa = router_info_lsa_build(Ipv4Addr::new(10, 0, 0, 1), true, vec![Algo::Spf], vec![]);
        let cap = extract_caps(&lsa);
        assert!(cap.te(), "TE bit must remain set");
        assert!(cap.gr_helper(), "GR helper bit must remain set");
        assert!(
            cap.gr_capable(),
            "GR restarter bit must be set while restarting"
        );
    }

    /// The SR-Algorithm TLV (type 8) carries the configured Flexible
    /// Algorithms after SPF (RFC 9350 §6).
    #[test]
    fn router_info_lsa_advertises_configured_flex_algos() {
        let lsa = router_info_lsa_build(
            Ipv4Addr::new(10, 0, 0, 1),
            false,
            vec![Algo::Spf, Algo::FlexAlgo(128), Algo::FlexAlgo(200)],
            vec![],
        );
        let OspfLsp::OpaqueAreaRouterInfo(ri) = &lsa.lsp else {
            panic!("expected RouterInfo opaque LSA");
        };
        let algos = ri
            .tlvs
            .iter()
            .find_map(|tlv| match tlv {
                RouterInfoTlv::Algo(a) => Some(a.algos.clone()),
                _ => None,
            })
            .expect("SR-Algorithm TLV present");
        assert_eq!(
            algos,
            vec![Algo::Spf, Algo::FlexAlgo(128), Algo::FlexAlgo(200)]
        );
    }

    /// FAD TLVs passed to the builder ride in the RI LSA (RFC 9350 §6.1).
    #[test]
    fn router_info_lsa_carries_fad_tlvs() {
        let fad = RouterInfoTlvFad {
            flex_algorithm: 128,
            metric_type: 0,
            calc_type: 0,
            priority: 128,
            subs: Vec::new(),
        };
        let lsa = router_info_lsa_build(
            Ipv4Addr::new(10, 0, 0, 1),
            false,
            vec![Algo::Spf, Algo::FlexAlgo(128)],
            vec![fad.clone()],
        );
        let OspfLsp::OpaqueAreaRouterInfo(ri) = &lsa.lsp else {
            panic!("expected RouterInfo opaque LSA");
        };
        let fads: Vec<_> = ri
            .tlvs
            .iter()
            .filter_map(|tlv| match tlv {
                RouterInfoTlv::Fad(f) => Some(f.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(fads, vec![fad]);
    }

    /// The Extended-Prefix LSA carries the algo-0 Prefix-SID plus one
    /// per-Flex-Algorithm Prefix-SID sub-TLV (RFC 9350 §7).
    #[test]
    fn ext_prefix_lsa_emits_per_algo_prefix_sids() {
        use super::PrefixSid;
        let prefix = "10.0.0.1/32".parse::<Ipv4Net>().unwrap();
        let mut flex = BTreeMap::new();
        flex.insert(128u8, PrefixSid::Index(1128));
        flex.insert(200u8, PrefixSid::Absolute(20200));

        let lsa = ext_prefix_lsa_build(
            Ipv4Addr::new(10, 0, 0, 1),
            prefix,
            Some(&PrefixSid::Index(16)),
            &flex,
            0,
        );
        let OspfLsp::OpaqueAreaExtPrefix(ep) = &lsa.lsp else {
            panic!("expected Extended-Prefix opaque LSA");
        };
        let algos: Vec<Algo> = ep.tlvs[0]
            .subs
            .iter()
            .filter_map(|s| match s {
                ExtPrefixSubTlv::PrefixSid(p) => Some(p.algo),
                _ => None,
            })
            .collect();
        // algo-0 (Spf) first, then the flex-algos in sorted order.
        assert_eq!(
            algos,
            vec![Algo::Spf, Algo::FlexAlgo(128), Algo::FlexAlgo(200)]
        );
    }

    /// With no algo-0 Prefix-SID, only the flex-algo sub-TLVs appear.
    #[test]
    fn ext_prefix_lsa_flex_algo_only() {
        use super::PrefixSid;
        let prefix = "10.0.0.1/32".parse::<Ipv4Net>().unwrap();
        let mut flex = BTreeMap::new();
        flex.insert(128u8, PrefixSid::Index(1128));

        let lsa = ext_prefix_lsa_build(Ipv4Addr::new(10, 0, 0, 1), prefix, None, &flex, 0);
        let OspfLsp::OpaqueAreaExtPrefix(ep) = &lsa.lsp else {
            panic!("expected Extended-Prefix opaque LSA");
        };
        let algos: Vec<Algo> = ep.tlvs[0]
            .subs
            .iter()
            .filter_map(|s| match s {
                ExtPrefixSubTlv::PrefixSid(p) => Some(p.algo),
                _ => None,
            })
            .collect();
        assert_eq!(algos, vec![Algo::FlexAlgo(128)]);
    }

    /// The OSPFv3 per-router SR-info E-Router-LSA advertises every
    /// participating algo in the SR-Algorithm TLV and carries each
    /// passed FAD as an `Ospfv3ExtTlv::Fad` (RFC 9350 §7.1).
    #[test]
    fn e_router_v3_sr_info_lsa_advertises_flex_algos_and_fads() {
        let fad = Ospfv3FadTlv {
            flex_algorithm: 128,
            metric_type: 0,
            calc_type: 0,
            priority: 128,
            subs: Vec::new(),
        };
        let lsa = e_router_v3_sr_info_lsa_build(
            Ipv4Addr::new(10, 0, 0, 1),
            vec![Algo::Spf, Algo::FlexAlgo(128), Algo::FlexAlgo(200)],
            vec![fad.clone()],
            false,
        );
        let Ospfv3LsBody::ERouter(body) = &lsa.body else {
            panic!("expected ERouter body");
        };
        let algos = body
            .tlvs
            .iter()
            .find_map(|t| match t {
                Ospfv3ExtTlv::SrAlgorithm(a) => Some(a.algos.clone()),
                _ => None,
            })
            .expect("SR-Algorithm TLV present");
        assert_eq!(
            algos,
            vec![Algo::Spf, Algo::FlexAlgo(128), Algo::FlexAlgo(200)]
        );
        let fads: Vec<_> = body
            .tlvs
            .iter()
            .filter_map(|t| match t {
                Ospfv3ExtTlv::Fad(f) => Some(f.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(fads, vec![fad]);
    }

    /// The OSPFv3 E-Intra-Area-Prefix-LSA carries the algo-0 Prefix-SID
    /// plus one per-Flex-Algorithm Prefix-SID sub-TLV (RFC 9350 §7).
    #[test]
    fn ext_intra_area_prefix_v3_lsa_emits_per_algo_prefix_sids() {
        use super::PrefixSid;
        let prefix = "2001:db8::1/128".parse::<Ipv6Net>().unwrap();
        let mut flex = BTreeMap::new();
        flex.insert(128u8, PrefixSid::Index(1128));
        flex.insert(200u8, PrefixSid::Absolute(16200));

        let lsa = ext_intra_area_prefix_v3_lsa_build(
            Ipv4Addr::new(10, 0, 0, 1),
            prefix,
            Some(&PrefixSid::Index(100)),
            &flex,
            7,
            10,
        );
        let Ospfv3LsBody::EIntraAreaPrefix(body) = &lsa.body else {
            panic!("expected EIntraAreaPrefix body");
        };
        let Ospfv3ExtTlv::IntraAreaPrefix(tlv) = &body.tlvs[0] else {
            panic!("expected IntraAreaPrefix TLV");
        };
        let algos: Vec<Algo> = tlv
            .subs
            .iter()
            .filter_map(|s| match s {
                Ospfv3SubTlv::PrefixSid(p) => Some(p.algo),
                _ => None,
            })
            .collect();
        assert_eq!(
            algos,
            vec![Algo::Spf, Algo::FlexAlgo(128), Algo::FlexAlgo(200)]
        );
    }

    /// With no algo-0 Prefix-SID, only the flex-algo SID is emitted.
    #[test]
    fn ext_intra_area_prefix_v3_lsa_flex_algo_only() {
        use super::PrefixSid;
        let prefix = "2001:db8::1/128".parse::<Ipv6Net>().unwrap();
        let mut flex = BTreeMap::new();
        flex.insert(128u8, PrefixSid::Index(1128));

        let lsa = ext_intra_area_prefix_v3_lsa_build(
            Ipv4Addr::new(10, 0, 0, 1),
            prefix,
            None,
            &flex,
            7,
            10,
        );
        let Ospfv3LsBody::EIntraAreaPrefix(body) = &lsa.body else {
            panic!("expected EIntraAreaPrefix body");
        };
        let Ospfv3ExtTlv::IntraAreaPrefix(tlv) = &body.tlvs[0] else {
            panic!("expected IntraAreaPrefix TLV");
        };
        let algos: Vec<Algo> = tlv
            .subs
            .iter()
            .filter_map(|s| match s {
                Ospfv3SubTlv::PrefixSid(p) => Some(p.algo),
                _ => None,
            })
            .collect();
        assert_eq!(algos, vec![Algo::FlexAlgo(128)]);
    }
}
