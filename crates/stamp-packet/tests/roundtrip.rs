//! Wire round-trip and structural-validation tests for the STAMP codec.

use std::net::{IpAddr, Ipv6Addr};

use bytes::BytesMut;
use hex_literal::hex;
use stamp_packet::{
    BASE_LEN, ErrorEstimate, MplsLabelEntry, ParseError, REPLY_REQUESTED_SAME_LINK,
    ReflectorPacket, ReturnPath, ReturnPathSubTlv, ReturnPathSubTlvValue, SenderPacket,
    StampTimestamp, StampTlv, StampTlvValue, TimestampFormat,
};

fn emit_sender(p: &SenderPacket) -> BytesMut {
    let mut buf = BytesMut::new();
    p.emit(&mut buf);
    buf
}

fn emit_reflector(p: &ReflectorPacket) -> BytesMut {
    let mut buf = BytesMut::new();
    p.emit(&mut buf);
    buf
}

#[test]
fn sender_base_roundtrip() {
    let p = SenderPacket {
        seq: 0x0102_0304,
        timestamp: StampTimestamp {
            seconds: 0xAABB_CCDD,
            fraction: 0x1122_3344,
        },
        error_estimate: ErrorEstimate {
            synced: true,
            format: TimestampFormat::Ntp,
            scale: 1,
            multiplier: 2,
        },
        ssid: 0x0005,
        tlvs: vec![],
    };
    let buf = emit_sender(&p);
    assert_eq!(
        buf.len(),
        BASE_LEN,
        "base Session-Sender packet is 44 octets"
    );
    assert_eq!(SenderPacket::parse(&buf).unwrap(), p);
}

#[test]
fn reflector_base_roundtrip() {
    let p = ReflectorPacket {
        seq: 7,
        timestamp: StampTimestamp {
            seconds: 0x1111_1111,
            fraction: 0x2222_2222,
        },
        error_estimate: ErrorEstimate {
            synced: true,
            format: TimestampFormat::Ptpv2,
            scale: 0x3F,
            multiplier: 0xFF,
        },
        ssid: 0xBEEF,
        receive_timestamp: StampTimestamp {
            seconds: 0x3333_3333,
            fraction: 0x4444_4444,
        },
        sender_seq: 6,
        sender_timestamp: StampTimestamp {
            seconds: 0x5555_5555,
            fraction: 0x6666_6666,
        },
        sender_error_estimate: ErrorEstimate::default(),
        sender_ttl: 64,
        tlvs: vec![],
    };
    let buf = emit_reflector(&p);
    assert_eq!(
        buf.len(),
        BASE_LEN,
        "base Session-Reflector packet is 44 octets"
    );
    assert_eq!(ReflectorPacket::parse(&buf).unwrap(), p);
}

#[test]
fn sender_base_known_bytes() {
    // seq | timestamp(8) | error-estimate | ssid, then the 28-octet MBZ
    // field padded with zeros up to the 44-octet base.
    let mut bytes = hex!("01020304 aabbccdd11223344 8102 0005").to_vec();
    bytes.resize(BASE_LEN, 0);
    let p = SenderPacket::parse(&bytes).unwrap();
    assert_eq!(p.seq, 0x0102_0304);
    assert_eq!(p.timestamp.seconds, 0xAABB_CCDD);
    assert_eq!(p.timestamp.fraction, 0x1122_3344);
    assert!(p.error_estimate.synced);
    assert_eq!(p.error_estimate.format, TimestampFormat::Ntp);
    assert_eq!(p.error_estimate.scale, 1);
    assert_eq!(p.error_estimate.multiplier, 2);
    assert_eq!(p.ssid, 5);
    assert!(p.tlvs.is_empty());
}

#[test]
fn sender_with_tlvs_roundtrip() {
    let return_path = ReturnPath {
        sub_tlvs: vec![
            ReturnPathSubTlv::new(ReturnPathSubTlvValue::ControlCode(
                REPLY_REQUESTED_SAME_LINK,
            )),
            ReturnPathSubTlv::new(ReturnPathSubTlvValue::SrMplsLabelStack(vec![
                MplsLabelEntry {
                    label: 16000,
                    tc: 0,
                    bos: false,
                    ttl: 255,
                },
                MplsLabelEntry {
                    label: 16010,
                    tc: 5,
                    bos: true,
                    ttl: 64,
                },
            ])),
            ReturnPathSubTlv::new(ReturnPathSubTlvValue::ReturnAddress(IpAddr::V6(
                "2001:db8::1".parse::<Ipv6Addr>().unwrap(),
            ))),
        ],
    };
    let p = SenderPacket {
        seq: 42,
        timestamp: StampTimestamp::default(),
        error_estimate: ErrorEstimate::default(),
        ssid: 1,
        tlvs: vec![
            StampTlv::new(StampTlvValue::ExtraPadding(vec![0u8; 18])),
            StampTlv::new(StampTlvValue::DestinationNodeAddress(
                "203.0.113.9".parse().unwrap(),
            )),
            StampTlv::new(StampTlvValue::ReturnPath(return_path)),
        ],
    };
    let buf = emit_sender(&p);
    assert!(buf.len() > BASE_LEN, "TLVs follow the 44-octet base");
    let back = SenderPacket::parse(&buf).unwrap();
    assert_eq!(back, p);
}

#[test]
fn srv6_segment_list_roundtrip() {
    let rp = ReturnPath {
        sub_tlvs: vec![ReturnPathSubTlv::new(
            ReturnPathSubTlvValue::Srv6SegmentList(vec![
                "2001:db8:a::1".parse::<Ipv6Addr>().unwrap(),
                "2001:db8:b::2".parse::<Ipv6Addr>().unwrap(),
            ]),
        )],
    };
    let mut buf = BytesMut::new();
    rp.emit(&mut buf);
    // Two 16-octet segments + one 4-octet sub-TLV header.
    assert_eq!(buf.len(), 4 + 32);
    assert_eq!(ReturnPath::parse(&buf).unwrap(), rp);
}

#[test]
fn mpls_label_entry_packs_all_fields() {
    // Round-trip a label entry through a Return Path sub-TLV and confirm
    // every field survives the 4-octet packing.
    let entry = MplsLabelEntry {
        label: 0xABCDE,
        tc: 0b101,
        bos: true,
        ttl: 0x7F,
    };
    let rp = ReturnPath {
        sub_tlvs: vec![ReturnPathSubTlv::new(
            ReturnPathSubTlvValue::SrMplsLabelStack(vec![entry]),
        )],
    };
    let mut buf = BytesMut::new();
    rp.emit(&mut buf);
    let back = ReturnPath::parse(&buf).unwrap();
    match &back.sub_tlvs[0].value {
        ReturnPathSubTlvValue::SrMplsLabelStack(stack) => assert_eq!(stack[0], entry),
        other => panic!("unexpected sub-TLV: {other:?}"),
    }
}

#[test]
fn unknown_tlv_preserved() {
    // A TLV type we do not model must round-trip byte-for-byte.
    let p = SenderPacket {
        tlvs: vec![StampTlv::new(StampTlvValue::Unknown {
            typ: 200,
            data: vec![0xDE, 0xAD, 0xBE, 0xEF],
        })],
        ..Default::default()
    };
    let buf = emit_sender(&p);
    assert_eq!(SenderPacket::parse(&buf).unwrap(), p);
}

#[test]
fn short_packet_rejected() {
    assert_eq!(
        SenderPacket::parse(&[0u8; 43]),
        Err(ParseError::TooShort {
            need: BASE_LEN,
            got: 43
        })
    );
}

#[test]
fn truncated_tlv_rejected() {
    // Base packet plus a TLV header claiming 8 value octets but with none.
    let mut bytes = vec![0u8; BASE_LEN];
    bytes.extend_from_slice(&[0x00, 0x01, 0x00, 0x08]); // flags=0, type=1, len=8
    let err = SenderPacket::parse(&bytes).unwrap_err();
    assert_eq!(
        err,
        ParseError::TlvTruncated {
            typ: 1,
            declared: 8,
            got: 0
        }
    );
}

#[test]
fn bad_destination_address_length_rejected() {
    // Destination Node Address (type 9) with an illegal 6-octet value.
    let mut bytes = vec![0u8; BASE_LEN];
    bytes.extend_from_slice(&[0x00, 0x09, 0x00, 0x06]);
    bytes.extend_from_slice(&[1, 2, 3, 4, 5, 6]);
    let err = SenderPacket::parse(&bytes).unwrap_err();
    assert_eq!(err, ParseError::BadAddressLength { typ: 9, len: 6 });
}
