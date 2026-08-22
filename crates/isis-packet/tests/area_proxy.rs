//! RFC 9666 Area Proxy TLV (20) and RFC 9667 Area Leader sub-TLV (242/27)
//! codec tests: wire-byte layouts, round-trips, and malformed-value
//! degradation.

use bytes::BytesMut;
use ipnet::{Ipv4Net, Ipv6Net};
use isis_packet::*;
use std::net::{Ipv4Addr, Ipv6Addr};

fn round_trip_tlv(tlv: &IsisTlv) -> IsisTlv {
    let mut buf = BytesMut::new();
    tlv.emit(&mut buf);
    let (rest, parsed) = IsisTlv::parse_tlv(&buf).expect("parse");
    assert!(rest.is_empty(), "leftover bytes: {rest:?}");
    parsed
}

/// The readiness signal every Inside Router advertises is an *empty*
/// Area Proxy TLV — two bytes on the wire.
#[test]
fn empty_area_proxy_tlv_round_trips() {
    let tlv: IsisTlv = IsisTlvAreaProxy::default().into();
    let mut buf = BytesMut::new();
    tlv.emit(&mut buf);
    assert_eq!(&buf[..], &[20, 0]);
    assert_eq!(tlv.wire_len(), 2);
    assert_eq!(round_trip_tlv(&tlv), tlv);
}

#[test]
fn proxy_system_id_sub_wire_layout() {
    let tlv: IsisTlv = IsisTlvAreaProxy {
        subs: vec![
            IsisSubProxySystemId {
                sys_id: IsisSysId {
                    id: [0, 0, 0, 0, 0, 1],
                },
            }
            .into(),
        ],
    }
    .into();
    let mut buf = BytesMut::new();
    tlv.emit(&mut buf);
    // TLV 20, len 8; sub-TLV 1, len 6, system ID.
    assert_eq!(&buf[..], &[20, 8, 1, 6, 0, 0, 0, 0, 0, 1]);
    assert_eq!(round_trip_tlv(&tlv), tlv);
}

/// Area SID in the label form: V=L=1 with a 3-octet label, IPv4 prefix
/// (F clear). RFC 9666 §4.3.2 flags are F=0x80, V=0x40, L=0x20.
#[test]
fn area_sid_label_v4_wire_layout() {
    let area_sid = IsisSubAreaSid {
        flags: AreaSidFlags::new(),
        sid: SidLabelValue::Label(16000),
        prefix: AreaSidPrefix::V4(Ipv4Net::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap()),
    };
    let tlv: IsisTlv = IsisTlvAreaProxy {
        subs: vec![area_sid.into()],
    }
    .into();
    let mut buf = BytesMut::new();
    tlv.emit(&mut buf);
    // Sub-TLV 2, len 6: flags V|L=0x60, label 16000 = 0x003E80,
    // prefix length 8, one packed prefix octet.
    assert_eq!(&buf[..], &[20, 8, 2, 6, 0x60, 0x00, 0x3E, 0x80, 8, 10]);
    let parsed = round_trip_tlv(&tlv);
    let IsisTlv::AreaProxy(ap) = &parsed else {
        panic!("expected AreaProxy TLV, got {parsed:?}");
    };
    let IsisAreaProxySub::AreaSid(sid) = &ap.subs[0] else {
        panic!("expected AreaSid sub-TLV");
    };
    assert!(sid.flags.v_flag() && sid.flags.l_flag() && !sid.flags.f_flag());
    assert_eq!(sid.sid, SidLabelValue::Label(16000));
    assert_eq!(
        sid.prefix,
        AreaSidPrefix::V4(Ipv4Net::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap())
    );
}

/// Area SID in the index form: V=L=0 with a 4-octet index, IPv6 prefix
/// (F set).
#[test]
fn area_sid_index_v6_round_trips() {
    let prefix = Ipv6Net::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), 48).unwrap();
    let tlv: IsisTlv = IsisTlvAreaProxy {
        subs: vec![
            IsisSubAreaSid {
                // Emit derives V/L from the SID form and F from the
                // prefix family; construct the flags to match so the
                // parsed value compares equal to the original.
                flags: AreaSidFlags::new().with_f_flag(true),
                sid: SidLabelValue::Index(100),
                prefix: AreaSidPrefix::V6(prefix),
            }
            .into(),
        ],
    }
    .into();
    let mut buf = BytesMut::new();
    tlv.emit(&mut buf);
    // Flags F=0x80; index 100 as 4 octets; prefix length 48 packs to 6
    // octets. Sub value length = 1 + 4 + 1 + 6 = 12.
    assert_eq!(buf[2], 2);
    assert_eq!(buf[3], 12);
    assert_eq!(buf[4], 0x80);
    let parsed = round_trip_tlv(&tlv);
    assert_eq!(parsed, tlv);
}

/// RFC 8667 §2.1.1.1: V=1/L=0 is an invalid flag combination — the
/// sub-TLV degrades to Unknown with its bytes preserved instead of
/// aborting the TLV.
#[test]
fn area_sid_flag_width_mismatch_degrades_to_unknown() {
    let bytes: &[u8] = &[
        20,   // Area Proxy TLV
        8,    // length
        2,    // Area SID sub-TLV
        6,    // length
        0x40, // V=1, L=0: invalid
        0x00, 0x3E, 0x80, // would-be label
        8, 10, // prefix
    ];
    let (rest, parsed) = IsisTlv::parse_tlv(bytes).expect("parse");
    assert!(rest.is_empty());
    let IsisTlv::AreaProxy(ap) = &parsed else {
        panic!("expected AreaProxy TLV, got {parsed:?}");
    };
    let IsisAreaProxySub::Unknown(u) = &ap.subs[0] else {
        panic!("expected Unknown sub-TLV, got {:?}", ap.subs[0]);
    };
    assert_eq!(u.code, 2);
    assert_eq!(u.len, 6);
    let mut buf = BytesMut::new();
    parsed.emit(&mut buf);
    assert_eq!(&buf[..], bytes);
}

#[test]
fn unknown_area_proxy_sub_preserved_on_round_trip() {
    let bytes: &[u8] = &[20, 5, 99, 3, 0xDE, 0xAD, 0xBE];
    let (rest, parsed) = IsisTlv::parse_tlv(bytes).expect("parse");
    assert!(rest.is_empty());
    let IsisTlv::AreaProxy(ap) = &parsed else {
        panic!("expected AreaProxy TLV, got {parsed:?}");
    };
    assert!(matches!(&ap.subs[0], IsisAreaProxySub::Unknown(u) if u.code == 99));
    let mut buf = BytesMut::new();
    parsed.emit(&mut buf);
    assert_eq!(&buf[..], bytes);
}

/// A TLV run containing TLV 20 dispatches to the typed variant — before
/// RFC 9666 support it round-tripped as Unknown — and neighbors in the
/// run still parse.
#[test]
fn area_proxy_parses_typed_within_tlv_run() {
    let bytes: &[u8] = &[
        20, 0, // empty Area Proxy TLV
        137, 2, b'r', b'1', // Dynamic Hostname
    ];
    let (rest, tlvs) = IsisTlv::parse_tlvs(bytes).expect("parse");
    assert!(rest.is_empty());
    assert_eq!(tlvs.len(), 2);
    assert!(matches!(&tlvs[0], IsisTlv::AreaProxy(ap) if ap.subs.is_empty()));
    assert!(matches!(&tlvs[1], IsisTlv::Hostname(h) if h.hostname == "r1"));
}

/// RFC 9667 §5.1.1 Area Leader sub-TLV inside Router Capability TLV 242:
/// type 27, length 2, priority then algorithm.
#[test]
fn area_leader_sub_wire_layout_and_round_trip() {
    let cap = IsisTlvRouterCap {
        router_id: Ipv4Addr::new(1, 1, 1, 1),
        flags: 0u8.into(),
        subs: vec![
            IsisSubAreaLeader {
                priority: 200,
                algorithm: 0,
            }
            .into(),
        ],
    };
    let tlv: IsisTlv = cap.into();
    let mut buf = BytesMut::new();
    tlv.emit(&mut buf);
    // TLV 242, len 9: router-id(4) + flags(1) + sub 27 len 2.
    assert_eq!(&buf[..], &[242, 9, 1, 1, 1, 1, 0, 27, 2, 200, 0]);
    let parsed = round_trip_tlv(&tlv);
    let IsisTlv::RouterCap(cap) = &parsed else {
        panic!("expected RouterCap TLV, got {parsed:?}");
    };
    match &cap.subs[0] {
        IsisSubTlv::AreaLeader(v) => {
            assert_eq!(v.priority, 200);
            assert_eq!(v.algorithm, 0);
        }
        other => panic!("expected AreaLeader variant, got {other:?}"),
    }
}
