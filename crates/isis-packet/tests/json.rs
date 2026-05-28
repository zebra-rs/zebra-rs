use isis_packet::*;

#[test]
pub fn json_test() {
    let prefix = prefix::IsisSubPrefixSid {
        flags: 0.into(),
        algo: 0.into(),
        sid: SidLabelValue::Index(100),
    };
    let tlv = prefix::IsisSubTlv::PrefixSid(prefix);
    let serialized = serde_json::to_string(&tlv).unwrap();
    println!("{}", serialized);
}

#[test]
pub fn json_round_trip_test() {
    // Test round-trip serialization/deserialization for various types

    // Test IsisType
    let isis_type = IsisType::L2Hello;
    let serialized = serde_json::to_string(&isis_type).unwrap();
    let deserialized: IsisType = serde_json::from_str(&serialized).unwrap();
    assert_eq!(isis_type, deserialized);

    // Test IsisTlvType
    let tlv_type = IsisTlvType::RouterCap;
    let serialized = serde_json::to_string(&tlv_type).unwrap();
    let deserialized: IsisTlvType = serde_json::from_str(&serialized).unwrap();
    assert_eq!(tlv_type, deserialized);

    // Test Algo
    let algo = Algo::FlexAlgo(200);
    let serialized = serde_json::to_string(&algo).unwrap();
    let deserialized: Algo = serde_json::from_str(&serialized).unwrap();
    assert_eq!(algo, deserialized);

    // Test SidLabelValue
    let sid_value = SidLabelValue::Index(100);
    let serialized = serde_json::to_string(&sid_value).unwrap();
    let deserialized: SidLabelValue = serde_json::from_str(&serialized).unwrap();
    assert_eq!(sid_value, deserialized);

    let sid_value = SidLabelValue::Label(2000);
    let serialized = serde_json::to_string(&sid_value).unwrap();
    let deserialized: SidLabelValue = serde_json::from_str(&serialized).unwrap();
    assert_eq!(sid_value, deserialized);

    // Test IsLevel
    let level = IsLevel::L1L2;
    let serialized = serde_json::to_string(&level).unwrap();
    let deserialized: IsLevel = serde_json::from_str(&serialized).unwrap();
    assert_eq!(level, deserialized);

    // Test prefix::IsisSubPrefixSid
    let prefix_sid = prefix::IsisSubPrefixSid {
        flags: 0.into(),
        algo: Algo::Spf,
        sid: SidLabelValue::Index(100),
    };
    let serialized = serde_json::to_string(&prefix_sid).unwrap();
    let deserialized: prefix::IsisSubPrefixSid = serde_json::from_str(&serialized).unwrap();
    assert_eq!(prefix_sid, deserialized);

    // Test prefix::IsisSubTlv
    let prefix_tlv = prefix::IsisSubTlv::PrefixSid(prefix_sid);
    let serialized = serde_json::to_string(&prefix_tlv).unwrap();
    let deserialized: prefix::IsisSubTlv = serde_json::from_str(&serialized).unwrap();
    assert_eq!(prefix_tlv, deserialized);

    // Test Behavior
    let behavior = srv6::Behavior::EndX;
    let serialized = serde_json::to_string(&behavior).unwrap();
    let deserialized: srv6::Behavior = serde_json::from_str(&serialized).unwrap();
    assert_eq!(behavior, deserialized);

    let behavior = srv6::Behavior::Resv(1234);
    let serialized = serde_json::to_string(&behavior).unwrap();
    let deserialized: srv6::Behavior = serde_json::from_str(&serialized).unwrap();
    assert_eq!(behavior, deserialized);

    // Test packet_utils::SidLabelTlv
    let sid_label = packet_utils::SidLabelTlv::Label(16001);
    let serialized = serde_json::to_string(&sid_label).unwrap();
    let deserialized: packet_utils::SidLabelTlv = serde_json::from_str(&serialized).unwrap();
    assert_eq!(sid_label, deserialized);

    let sid_label = packet_utils::SidLabelTlv::Index(1000);
    let serialized = serde_json::to_string(&sid_label).unwrap();
    let deserialized: packet_utils::SidLabelTlv = serde_json::from_str(&serialized).unwrap();
    assert_eq!(sid_label, deserialized);

    // Test complex structure: IsisTlvAreaAddr
    let area_addr = IsisTlvAreaAddr {
        area_addr: vec![0x49, 0x00, 0x01],
    };
    let serialized = serde_json::to_string(&area_addr).unwrap();
    let deserialized: IsisTlvAreaAddr = serde_json::from_str(&serialized).unwrap();
    assert_eq!(area_addr, deserialized);

    // Test IsisSysId
    let sys_id = IsisSysId {
        id: [0x00, 0x01, 0x02, 0x03, 0x04, 0x05],
    };
    let serialized = serde_json::to_string(&sys_id).unwrap();
    let deserialized: IsisSysId = serde_json::from_str(&serialized).unwrap();
    assert_eq!(sys_id, deserialized);

    // Test RFC 7794 Source Router ID sub-TLVs.
    let v4_src = prefix::IsisSubIpv4SourceRouterId {
        router_id: "10.0.0.1".parse().unwrap(),
    };
    let v4_tlv = prefix::IsisSubTlv::Ipv4SourceRouterId(v4_src);
    let serialized = serde_json::to_string(&v4_tlv).unwrap();
    let deserialized: prefix::IsisSubTlv = serde_json::from_str(&serialized).unwrap();
    assert_eq!(v4_tlv, deserialized);

    let v6_src = prefix::IsisSubIpv6SourceRouterId {
        router_id: "2001:db8::1".parse().unwrap(),
    };
    let v6_tlv = prefix::IsisSubTlv::Ipv6SourceRouterId(v6_src);
    let serialized = serde_json::to_string(&v6_tlv).unwrap();
    let deserialized: prefix::IsisSubTlv = serde_json::from_str(&serialized).unwrap();
    assert_eq!(v6_tlv, deserialized);

    println!("All round-trip JSON serialization/deserialization tests passed!");
}

/// Wire round-trip for the RFC 6232 Purge Originator Identification
/// TLV. Covers both the originator-only form (Number == 1, 7-octet
/// value) and the (originator, received-from) form (Number == 2,
/// 13-octet value), plus the malformed Number == 3 case.
#[test]
pub fn rfc6232_poi_round_trip() {
    use bytes::BytesMut;
    use isis_packet::{IsisSysId, IsisTlv, IsisTlvPurgeOrigId, IsisTlvType};

    let orig = IsisSysId {
        id: [0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
    };

    // Originator-only purge.
    let tlv = IsisTlvPurgeOrigId {
        originator: orig,
        received_from: None,
    };
    let mut buf = BytesMut::new();
    IsisTlv::PurgeOrigId(tlv.clone()).emit(&mut buf);
    // <type=13><length=7><num=1><6-octet sys-id>
    assert_eq!(buf[0], u8::from(IsisTlvType::PurgeOrigId));
    assert_eq!(buf[1], 7);
    assert_eq!(buf[2], 1);
    assert_eq!(&buf[3..9], &orig.id);
    let (rest, parsed) = IsisTlv::parse_be(&buf[2..], IsisTlvType::PurgeOrigId).unwrap();
    assert!(rest.is_empty());
    assert!(matches!(parsed, IsisTlv::PurgeOrigId(_)));
    if let IsisTlv::PurgeOrigId(p) = parsed {
        assert_eq!(p, tlv);
    }

    // Forwarded purge: includes upstream system-id.
    let upstream = IsisSysId {
        id: [0x00, 0x00, 0x00, 0x00, 0x00, 0x02],
    };
    let tlv = IsisTlvPurgeOrigId {
        originator: orig,
        received_from: Some(upstream),
    };
    let mut buf = BytesMut::new();
    IsisTlv::PurgeOrigId(tlv.clone()).emit(&mut buf);
    assert_eq!(buf[1], 13);
    assert_eq!(buf[2], 2);
    assert_eq!(&buf[3..9], &orig.id);
    assert_eq!(&buf[9..15], &upstream.id);
    let (rest, parsed) = IsisTlv::parse_be(&buf[2..], IsisTlvType::PurgeOrigId).unwrap();
    assert!(rest.is_empty());
    if let IsisTlv::PurgeOrigId(p) = parsed {
        assert_eq!(p, tlv);
    } else {
        panic!("expected PurgeOrigId");
    }

    // Malformed Number byte must be rejected. RFC 6232 §3 only
    // defines values 1 and 2; anything else means "don't trust the
    // rest of the buffer" — return a parse error rather than guess.
    let raw_bad = [3u8, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 2];
    assert!(IsisTlv::parse_be(&raw_bad, IsisTlvType::PurgeOrigId).is_err());

    // JSON round-trip with received_from omitted (verifies the
    // skip_serializing_if guard on the Option).
    let serialized = serde_json::to_string(&IsisTlvPurgeOrigId {
        originator: orig,
        received_from: None,
    })
    .unwrap();
    assert!(
        !serialized.contains("received-from"),
        "received-from must be elided when None; got: {serialized}"
    );
    let deserialized: IsisTlvPurgeOrigId = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized.received_from, None);
}

/// Wire round-trip for the RFC 8570 Performance Metric sub-TLVs.
/// Confirms every code (33–39) survives emit → parse with its
/// fields intact and the expected on-wire size, including the
/// 24-bit packing of delay/loss values and the A-flag bit.
#[test]
pub fn rfc8570_perf_metric_round_trip() {
    use bytes::BytesMut;
    use isis_packet::neigh::{
        IsisSubAvailableBw, IsisSubBandwidthMetric, IsisSubDelayVariation, IsisSubLinkLoss,
        IsisSubMinMaxLinkDelay, IsisSubResidualBw, IsisSubTlv, IsisSubUniLinkDelay,
        IsisSubUtilizedBw,
    };

    // Sub-TLV 33 — Unidirectional Link Delay (A flag + 24-bit delay).
    let v = IsisSubTlv::UniLinkDelay(IsisSubUniLinkDelay {
        anomalous: true,
        delay: 0x00_12_34_56, // < 24 bits
    });
    let mut buf = BytesMut::new();
    v.emit(&mut buf);
    assert_eq!(buf[0], 33, "type code 33");
    assert_eq!(buf[1], 4, "length 4");
    // High bit of value-byte 0 carries the A flag.
    assert_eq!(buf[2] & 0x80, 0x80);
    let (rest, parsed) = IsisSubTlv::parse_subs(&buf).expect("parse 33");
    assert!(rest.is_empty());
    assert_eq!(parsed, v);

    // Sub-TLV 34 — Min/Max Unidirectional Link Delay.
    let v = IsisSubTlv::MinMaxLinkDelay(IsisSubMinMaxLinkDelay {
        anomalous: false,
        min_delay: 100,
        max_delay: 500,
    });
    let mut buf = BytesMut::new();
    v.emit(&mut buf);
    assert_eq!(buf[0], 34);
    assert_eq!(buf[1], 8, "length 8");
    let (rest, parsed) = IsisSubTlv::parse_subs(&buf).expect("parse 34");
    assert!(rest.is_empty());
    assert_eq!(parsed, v);

    // Sub-TLV 35 — Unidirectional Delay Variation (no A flag).
    let v = IsisSubTlv::DelayVariation(IsisSubDelayVariation { variation: 42 });
    let mut buf = BytesMut::new();
    v.emit(&mut buf);
    assert_eq!(buf[0], 35);
    assert_eq!(buf[1], 4);
    // High bit must NOT be set for sub-TLV 35.
    assert_eq!(buf[2] & 0x80, 0);
    let (rest, parsed) = IsisSubTlv::parse_subs(&buf).expect("parse 35");
    assert!(rest.is_empty());
    assert_eq!(parsed, v);

    // Sub-TLV 36 — Unidirectional Link Loss.
    let v = IsisSubTlv::LinkLoss(IsisSubLinkLoss {
        anomalous: true,
        loss: 0x00_FF_FF_FE, // RFC 8570 §4.4 ceiling that still represents a measured value.
    });
    let mut buf = BytesMut::new();
    v.emit(&mut buf);
    assert_eq!(buf[0], 36);
    assert_eq!(buf[1], 4);
    assert_eq!(buf[2] & 0x80, 0x80);
    let (rest, parsed) = IsisSubTlv::parse_subs(&buf).expect("parse 36");
    assert!(rest.is_empty());
    assert_eq!(parsed, v);

    // Sub-TLVs 37/38/39 — bandwidth metrics, IEEE float B/s.
    let cases: [(u8, IsisSubTlv); 3] = [
        (
            37,
            IsisSubTlv::ResidualBw(IsisSubResidualBw {
                bw: IsisSubBandwidthMetric { bw_bps: 1.25e9 },
            }),
        ),
        (
            38,
            IsisSubTlv::AvailableBw(IsisSubAvailableBw {
                bw: IsisSubBandwidthMetric { bw_bps: 9.5e8 },
            }),
        ),
        (
            39,
            IsisSubTlv::UtilizedBw(IsisSubUtilizedBw {
                bw: IsisSubBandwidthMetric { bw_bps: 5.0e7 },
            }),
        ),
    ];
    for (code, v) in &cases {
        let mut buf = BytesMut::new();
        v.emit(&mut buf);
        assert_eq!(buf[0], *code, "type code {code}");
        assert_eq!(buf[1], 4, "length 4 for code {code}");
        let (rest, parsed) = IsisSubTlv::parse_subs(&buf).expect("parse bw");
        assert!(rest.is_empty());
        assert_eq!(&parsed, v, "round-trip for code {code}");
    }

    // Reserved bits in code-33/-34/-35/-36 must NOT be reflected
    // back as part of the parsed value — the parser must mask the
    // top 8 bits when extracting the 24-bit metric.
    let raw = [33u8, 4, 0x7F, 0xAB, 0xCD, 0xEF];
    let (_, parsed) = IsisSubTlv::parse_subs(&raw).expect("parse with reserved bits set");
    if let IsisSubTlv::UniLinkDelay(d) = parsed {
        assert!(!d.anomalous);
        assert_eq!(d.delay, 0x00AB_CDEF);
    } else {
        panic!("expected UniLinkDelay");
    }
}

/// Wire round-trip for the RFC 7794 Source Router ID sub-TLVs.
/// `IsisSubTlv::emit` writes <code, length, value>; `parse_subs` reads
/// the same shape back. The new variants must come back as themselves,
/// not as `IsisSubTlv::Unknown`.
#[test]
pub fn source_router_id_wire_round_trip() {
    use bytes::BytesMut;
    use isis_packet::prefix::{IsisSubIpv4SourceRouterId, IsisSubIpv6SourceRouterId, IsisSubTlv};

    let v4 = IsisSubTlv::Ipv4SourceRouterId(IsisSubIpv4SourceRouterId {
        router_id: "10.1.2.3".parse().unwrap(),
    });
    let mut buf = BytesMut::new();
    v4.emit(&mut buf);
    // <code=11><len=4><4 octets>
    assert_eq!(&buf[..2], &[11, 4]);
    let (rest, parsed) = IsisSubTlv::parse_subs(&buf).expect("parse v4 source router id");
    assert!(rest.is_empty());
    assert_eq!(parsed, v4);

    let v6 = IsisSubTlv::Ipv6SourceRouterId(IsisSubIpv6SourceRouterId {
        router_id: "2001:db8::1".parse().unwrap(),
    });
    let mut buf = BytesMut::new();
    v6.emit(&mut buf);
    // <code=12><len=16><16 octets>
    assert_eq!(&buf[..2], &[12, 16]);
    let (rest, parsed) = IsisSubTlv::parse_subs(&buf).expect("parse v6 source router id");
    assert!(rest.is_empty());
    assert_eq!(parsed, v6);
}
