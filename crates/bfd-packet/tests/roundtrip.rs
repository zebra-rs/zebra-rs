//! Bit-exact round-trip tests for the BFD packet codec.
//!
//! Each fixture is hand-encoded from RFC 5880 §4.1 (and §4.2–§4.4 for auth)
//! and validated against both `parse` and `emit` paths.

use bfd_packet::{AuthSection, ControlPacket, Diag, ParseError, State};
use bytes::BytesMut;
use hex_literal::hex;

fn assert_roundtrip(bytes: &[u8]) -> ControlPacket {
    let pkt = ControlPacket::parse(bytes).expect("parse should succeed");
    let mut buf = BytesMut::new();
    pkt.emit(&mut buf);
    assert_eq!(&buf[..], bytes, "encoded bytes must match input exactly");
    let pkt2 = ControlPacket::parse(&buf).expect("re-parse should succeed");
    assert_eq!(pkt, pkt2, "two parses must be equal");
    pkt
}

/// Minimal Down-state packet, no auth, no echo, mult=3, 1-second intervals.
/// First packet a system sends when bringing up a session.
#[test]
fn down_state_initial() {
    const PKT: &[u8] = &hex!(
        "20 40 03 18"            // V=1, Diag=0, State=Down, no flags, mult=3, len=24
        "01 02 03 04"            // My Disc = 0x01020304
        "00 00 00 00"            // Your Disc = 0
        "00 0f 42 40"            // Desired Min TX = 1_000_000 us
        "00 0f 42 40"            // Required Min RX = 1_000_000 us
        "00 00 00 00"            // Required Min Echo RX = 0
    );
    let pkt = assert_roundtrip(PKT);
    assert_eq!(pkt.version, 1);
    assert_eq!(pkt.state, State::Down);
    assert_eq!(pkt.diag, Diag::None);
    assert_eq!(pkt.detect_mult, 3);
    assert_eq!(pkt.my_disc, 0x01020304);
    assert_eq!(pkt.your_disc, 0);
    assert_eq!(pkt.desired_min_tx_interval, 1_000_000);
    assert_eq!(pkt.required_min_rx_interval, 1_000_000);
    assert_eq!(pkt.required_min_echo_rx_interval, 0);
    assert!(!pkt.poll);
    assert!(!pkt.final_bit);
    assert!(!pkt.auth_present);
    assert!(pkt.auth.is_none());
}

/// Up-state packet with Poll bit set, fast timers (50ms = 50000us).
#[test]
fn up_state_with_poll() {
    const PKT: &[u8] = &hex!(
        "20 e0 03 18"            // V=1, State=Up (3<<6=0xc0), P=1 (0x20) → 0xe0; mult=3, len=24
        "de ad be ef"
        "ca fe 12 34"
        "00 00 c3 50"            // 50_000 us
        "00 00 c3 50"
        "00 00 00 00"
    );
    let pkt = assert_roundtrip(PKT);
    assert_eq!(pkt.state, State::Up);
    assert!(pkt.poll);
    assert!(!pkt.final_bit);
    assert_eq!(pkt.my_disc, 0xdeadbeef);
    assert_eq!(pkt.your_disc, 0xcafe1234);
    assert_eq!(pkt.desired_min_tx_interval, 50_000);
}

/// Up-state Final reply (F bit), 300ms intervals, multiplier 5.
#[test]
fn up_state_with_final() {
    const PKT: &[u8] = &hex!(
        "20 d0 05 18"            // State=Up (0xc0), F=1 (0x10) → 0xd0; mult=5
        "00 11 22 33"
        "44 55 66 77"
        "00 04 93 e0"            // 300_000 us
        "00 04 93 e0"
        "00 00 00 00"
    );
    let pkt = assert_roundtrip(PKT);
    assert!(!pkt.poll);
    assert!(pkt.final_bit);
    assert_eq!(pkt.detect_mult, 5);
}

/// AdminDown with diagnostic = AdministrativelyDown (7).
#[test]
fn admin_down() {
    const PKT: &[u8] = &hex!(
        "27 00 03 18"            // V=1, Diag=7 (AdminDown), State=AdminDown (0), no flags
        "11 11 11 11"
        "00 00 00 00"
        "00 0f 42 40"
        "00 0f 42 40"
        "00 00 00 00"
    );
    let pkt = assert_roundtrip(PKT);
    assert_eq!(pkt.state, State::AdminDown);
    assert_eq!(pkt.diag, Diag::AdministrativelyDown);
}

/// Up state with all stable-state flags except auth/poll/final.
#[test]
fn up_state_with_cpi_and_demand() {
    const PKT: &[u8] = &hex!(
        "20 ca 03 18"            // State=Up (0xc0), C=1 (0x08), D=1 (0x02) → 0xca
        "ab cd 12 34"
        "12 34 ab cd"
        "00 0f 42 40"
        "00 0f 42 40"
        "00 00 00 00"
    );
    let pkt = assert_roundtrip(PKT);
    assert!(pkt.cpi);
    assert!(pkt.demand);
    assert!(!pkt.auth_present);
}

// -----------------------------------------------------------------------
// Structural validation (RFC 5880 §6.8.6)
// -----------------------------------------------------------------------

#[test]
fn reject_too_short() {
    let buf = [0u8; 23];
    assert_eq!(ControlPacket::parse(&buf), Err(ParseError::TooShort));
}

#[test]
fn reject_bad_version() {
    let mut buf = [0u8; 24];
    buf[0] = 0x40; // version=2
    buf[2] = 3; // mult
    buf[3] = 24;
    buf[4..8].copy_from_slice(&[0, 0, 0, 1]); // non-zero my_disc
    assert_eq!(ControlPacket::parse(&buf), Err(ParseError::BadVersion(2)));
}

#[test]
fn reject_zero_detect_mult() {
    let mut buf = [0u8; 24];
    buf[0] = 0x20; // version=1
    buf[2] = 0;
    buf[3] = 24;
    buf[4..8].copy_from_slice(&[0, 0, 0, 1]);
    assert_eq!(ControlPacket::parse(&buf), Err(ParseError::ZeroDetectMult));
}

#[test]
fn reject_zero_my_disc() {
    let mut buf = [0u8; 24];
    buf[0] = 0x20;
    buf[2] = 3;
    buf[3] = 24;
    // my_disc left as zero
    assert_eq!(ControlPacket::parse(&buf), Err(ParseError::ZeroMyDisc));
}

#[test]
fn reject_bad_length() {
    let mut buf = [0u8; 24];
    buf[0] = 0x20;
    buf[2] = 3;
    buf[3] = 20; // < MIN_LEN
    buf[4..8].copy_from_slice(&[0, 0, 0, 1]);
    assert_eq!(ControlPacket::parse(&buf), Err(ParseError::BadLength(20)));
}

#[test]
fn reject_truncated() {
    let mut buf = [0u8; 24];
    buf[0] = 0x20;
    buf[2] = 3;
    buf[3] = 32; // claims 32 bytes, buffer is 24
    buf[4..8].copy_from_slice(&[0, 0, 0, 1]);
    assert_eq!(
        ControlPacket::parse(&buf),
        Err(ParseError::Truncated {
            declared: 32,
            actual: 24
        })
    );
}

#[test]
fn reject_multipoint() {
    let mut buf = [0u8; 24];
    buf[0] = 0x20;
    buf[1] = 0x01; // M bit set
    buf[2] = 3;
    buf[3] = 24;
    buf[4..8].copy_from_slice(&[0, 0, 0, 1]);
    assert_eq!(ControlPacket::parse(&buf), Err(ParseError::MultipointSet));
}

#[test]
fn reject_extra_data_no_auth() {
    let mut buf = [0u8; 32];
    buf[0] = 0x20;
    buf[2] = 3;
    buf[3] = 32; // longer than 24 but A=0
    buf[4..8].copy_from_slice(&[0, 0, 0, 1]);
    assert_eq!(ControlPacket::parse(&buf), Err(ParseError::ExtraDataNoAuth));
}

// -----------------------------------------------------------------------
// Authentication
// -----------------------------------------------------------------------

#[test]
fn parse_simple_password() {
    let mut buf = Vec::new();
    // Header — A bit set, length = 24 + 3 + 6 = 33
    buf.extend_from_slice(&hex!("20 44 03 21")); // A=1 (0x04) on byte 1
    buf.extend_from_slice(&hex!("00 00 00 01")); // my_disc
    buf.extend_from_slice(&hex!("00 00 00 00")); // your_disc
    buf.extend_from_slice(&hex!("00 0f 42 40 00 0f 42 40 00 00 00 00"));
    // Auth section: SimplePassword
    //   Type=1, Len=9 (2+1+6), KeyID=42, Password="secret"
    buf.extend_from_slice(&hex!("01 09 2a"));
    buf.extend_from_slice(b"secret");

    let pkt = assert_roundtrip(&buf);
    assert!(pkt.auth_present);
    match pkt.auth.unwrap() {
        AuthSection::SimplePassword { key_id, password } => {
            assert_eq!(key_id, 42);
            assert_eq!(password, b"secret");
        }
        other => panic!("expected SimplePassword, got {other:?}"),
    }
}

#[test]
fn parse_keyed_md5() {
    let mut buf = Vec::new();
    // Header — A=1, length = 24 + 24 = 48
    buf.extend_from_slice(&hex!("20 44 03 30"));
    buf.extend_from_slice(&hex!("00 00 00 01"));
    buf.extend_from_slice(&hex!("00 00 00 00"));
    buf.extend_from_slice(&hex!("00 0f 42 40 00 0f 42 40 00 00 00 00"));
    // Auth: KeyedMd5 (Type=2, Len=24, KeyID=7, Reserved=0, Seq=0x12345678, 16-byte digest)
    buf.extend_from_slice(&hex!("02 18 07 00"));
    buf.extend_from_slice(&hex!("12 34 56 78"));
    buf.extend_from_slice(&hex!("00010203 04050607 08090a0b 0c0d0e0f"));

    let pkt = assert_roundtrip(&buf);
    match pkt.auth.unwrap() {
        AuthSection::KeyedMd5 {
            meticulous,
            key_id,
            seq_num,
            digest,
        } => {
            assert!(!meticulous);
            assert_eq!(key_id, 7);
            assert_eq!(seq_num, 0x12345678);
            assert_eq!(digest, hex!("00010203 04050607 08090a0b 0c0d0e0f"));
        }
        other => panic!("expected KeyedMd5, got {other:?}"),
    }
}

#[test]
fn parse_meticulous_keyed_sha1() {
    let mut buf = Vec::new();
    // Header — A=1, length = 24 + 28 = 52
    buf.extend_from_slice(&hex!("20 44 03 34"));
    buf.extend_from_slice(&hex!("00 00 00 01"));
    buf.extend_from_slice(&hex!("00 00 00 00"));
    buf.extend_from_slice(&hex!("00 0f 42 40 00 0f 42 40 00 00 00 00"));
    // Auth: MeticulousKeyedSha1 (Type=5, Len=28, KeyID=9, Reserved=0, Seq=1, 20-byte digest)
    buf.extend_from_slice(&hex!("05 1c 09 00"));
    buf.extend_from_slice(&hex!("00 00 00 01"));
    buf.extend_from_slice(&hex!("00112233 44556677 8899aabb ccddeeff 00112233"));

    let pkt = assert_roundtrip(&buf);
    match pkt.auth.unwrap() {
        AuthSection::KeyedSha1 {
            meticulous,
            key_id,
            seq_num,
            digest,
        } => {
            assert!(meticulous);
            assert_eq!(key_id, 9);
            assert_eq!(seq_num, 1);
            assert_eq!(digest, hex!("00112233 44556677 8899aabb ccddeeff 00112233"));
        }
        other => panic!("expected KeyedSha1, got {other:?}"),
    }
}

#[test]
fn reject_auth_truncated() {
    let mut buf = [0u8; 25];
    buf[0] = 0x20;
    buf[1] = 0x04; // A bit set
    buf[2] = 3;
    buf[3] = 25; // claims auth byte, but only 1 byte present (need at least 2 for type+len)
    buf[4..8].copy_from_slice(&[0, 0, 0, 1]);
    assert_eq!(ControlPacket::parse(&buf), Err(ParseError::AuthTruncated));
}

#[test]
fn unknown_auth_type_preserved() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&hex!("20 44 03 1c")); // A=1, length=28
    buf.extend_from_slice(&hex!("00 00 00 01"));
    buf.extend_from_slice(&hex!("00 00 00 00"));
    buf.extend_from_slice(&hex!("00 0f 42 40 00 0f 42 40 00 00 00 00"));
    // Unknown Auth Type 99, length 4, two payload bytes
    buf.extend_from_slice(&hex!("63 04 aa bb"));

    let pkt = assert_roundtrip(&buf);
    match pkt.auth.unwrap() {
        AuthSection::Unknown { auth_type, data } => {
            assert_eq!(auth_type, 99);
            assert_eq!(data, vec![0xaa, 0xbb]);
        }
        other => panic!("expected Unknown, got {other:?}"),
    }
}

// -----------------------------------------------------------------------
// Default & emit sanity
// -----------------------------------------------------------------------

#[test]
fn emit_default_is_well_formed_after_disc_set() {
    let pkt = ControlPacket {
        my_disc: 0xdeadbeef,
        ..ControlPacket::default()
    };
    let mut buf = BytesMut::new();
    pkt.emit(&mut buf);
    assert_eq!(buf.len(), 24);
    let reparsed = ControlPacket::parse(&buf).expect("default packet must round-trip");
    assert_eq!(reparsed.state, State::Down);
    assert_eq!(reparsed.my_disc, 0xdeadbeef);
}

#[test]
fn diag_reserved_round_trips() {
    let pkt = ControlPacket {
        my_disc: 1,
        diag: Diag::Reserved(20),
        ..ControlPacket::default()
    };
    let mut buf = BytesMut::new();
    pkt.emit(&mut buf);
    let reparsed = ControlPacket::parse(&buf).unwrap();
    assert_eq!(reparsed.diag, Diag::Reserved(20));
}
