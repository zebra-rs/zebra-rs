use bytes::BytesMut;
use hex_literal::hex;
use isis_packet::*;

fn parse_emit(buf: &[u8]) {
    let packet = parse(buf);
    assert!(packet.is_ok());

    let (_, packet) = packet.unwrap();
    println!("{}", packet);
    let mut buf = BytesMut::new();
    packet.emit(&mut buf);

    let packet = parse(&buf);
    assert!(packet.is_ok());

    let (_, packet) = packet.unwrap();
    println!("{}", packet);
}

#[test]
pub fn parse_l1lsp_test_1() {
    const PACKET: &[u8] = &hex!(
        "
        01 80 C2 00 00 14 00 1C 42 E5 C4 21 00 CE FE
        FE 03 83 1B 01 00 12 01 00 00 00 CB 04 8F 00
        00 00 00 00 01 00 00 00 00 00 9A 0F 44 01 81
        01 CC 01 04 03 49 00 00 89 07 75 62 75 6E 74
        75 31 F2 22 AC 13 00 01 00 02 09 C0 00 1F 40
        01 03 00 3E 80 13 01 00 16 09 00 00 03 E8 01
        03 00 3A 98 17 02 01 08 86 04 01 01 01 01 16
        48 00 00 00 00 00 01 03 00 00 0A 19 06 04 0B
        00 00 01 08 04 0B 00 00 02 20 0B 30 00 00 00
        00 00 00 02 00 3A 98 00 00 00 00 00 01 04 00
        00 0A 19 06 04 0A 00 00 01 08 04 0A 00 00 03
        20 0B 30 00 00 00 00 00 00 03 00 3A 99 84 04
        AC 13 00 01 87 22 00 00 00 0A 60 01 01 01 01
        08 03 06 00 00 00 00 00 64 00 00 00 0A 18 0B
        00 00 00 00 00 0A 18 0A 00 00
        "
    );
    parse_emit(&PACKET[17..]);
}

#[test]
pub fn parse_l1lsp_test2() {
    const PACKET: &[u8] = &hex!(
        "
        01 80 c2 00 00 14 00 1c 42 e8 0c 23 00 9e fe fe
        03 83 1b 01 00 12 01 00 00 00 9b 02 2b 00 00 00
        00 00 02 00 00 00 00 00 04 c9 f3 01 81 01 cc 01
        04 03 49 00 00 89 07 75 62 75 6e 74 75 32 f2 22
        0a 0a 00 01 00 02 09 c0 00 1f 40 01 03 00 3e 80
        13 01 00 16 09 00 00 03 e8 01 03 00 3a 98 17 02
        01 08 86 04 02 02 02 02 16 18 00 00 00 00 00 01
        04 00 00 0a 0d 20 0b 30 00 00 00 00 00 00 01 00
        3a 98 84 04 0a 0a 00 01 87 22 00 00 00 0a 60 02
        02 02 02 08 03 06 00 00 00 00 00 c8 00 00 00 0a
        18 0a 00 00 00 00 00 0a 18 0a 0a 00
        "
    );
    parse_emit(&PACKET[17..]);
}

#[test]
pub fn parse_l1lsp_multi_is_reach() {
    const PACKET: &[u8] = &hex!(
        "
        01 80 c2 00 00 14 00 1c 42 e8 0c 23 00 36 fe fe
        03 83 1b 01 00 12 01 00 00 00 33 04 a0 00 00 00
        00 00 01 03 00 00 00 00 01 95 34 01 16 16 00 00
        00 00 00 01 00 00 00 00 00 00 00 00 00 00 03 00
        00 00 00 00
        "
    );
    parse_emit(&PACKET[17..]);
}

#[test]
pub fn parse_l1lsp_ipv6_reach() {
    const PACKET: &[u8] = &hex!(
        "
        01 80 c2 00 00 14 00 1c 42 e8 0c 23 00 b5 fe fe
        03 83 1b 01 00 12 01 00 00 00 b2 04 7f 00 00 00
        00 00 01 00 00 00 00 00 32 2d 9d 01 81 02 cc 8e
        01 04 03 49 00 00 89 07 75 62 75 6e 74 75 31 f2
        22 0b 00 00 01 00 02 09 c0 00 1f 40 01 03 00 3e
        80 13 01 00 16 09 00 00 03 e8 01 03 00 3a 98 17
        02 01 08 86 04 01 01 01 01 16 1e 00 00 00 00 00
        01 04 00 00 0a 13 08 04 0a 00 00 02 20 0b 30 00
        00 00 00 00 00 02 00 3a 98 84 04 0b 00 00 01 87
        22 00 00 00 0a 60 01 01 01 01 08 03 06 00 00 00
        00 00 64 00 00 00 0a 18 0b 00 00 00 00 00 0a 18
        0a 00 00 ec 0e 00 00 00 0a 00 40 30 01 20 03 00
        00 00 00
     "
    );
    parse_emit(&PACKET[17..]);
}

#[test]
pub fn parse_l1hello_test() {
    const PACKET: &[u8] = &hex!(
        "
        01 80 c2 00 00 14 00 00 00 00 00 00 05 dc fe fe
        03 83 1b 01 00 0f 01 00 00 01 00 00 00 00 00 03
        00 1e 05 d9 00 00 00 00 00 00 01 03 01 04 03 49
        00 00 06 06 00 1c 42 e8 0c 23 81 01 cc 84 04 0b
        00 00 02 08 ff 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 08 ff 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 08 ff 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 08 ff 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 08 ff 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 08 a0 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00
        "
    );
    parse_emit(&PACKET[17..]);
}

#[test]
pub fn parse_csnp() {
    const PACKET: &[u8] = &hex!(
        "
        01 80 c2 00 00 14 00 1c 42 e8 0c 23 00 86 fe fe
        03 83 21 01 00 18 01 00 00 00 83 00 00 00 00 00
        01 00 00 00 00 00 00 00 00 00 ff ff ff ff ff ff
        ff ff 09 60 04 81 00 00 00 00 00 01 00 00 00 00
        00 32 2d 9d 04 97 00 00 00 00 00 01 03 00 00 00
        00 01 95 34 04 62 00 00 00 00 00 01 04 00 00 00
        00 22 38 70 04 8e 00 00 00 00 00 02 00 00 00 00
        00 29 b5 9d 04 9e 00 00 00 00 00 03 00 00 00 00
        00 01 45 70 04 a9 00 00 00 00 00 03 00 01 00 00
        00 02 1d 26
        "
    );
    parse_emit(&PACKET[17..]);
}

#[test]
pub fn parse_psnp() {
    const PACKET: &[u8] = &hex!(
        "
        01 80 c2 00 00 14 00 00 00 00 00 00 00 46 fe fe
        03 83 11 01 00 1a 01 00 00 00 43 00 00 00 00 00
        03 00 09 30 04 8e 00 00 00 00 00 02 00 00 00 00
        00 00 b5 9d 04 62 00 00 00 00 00 01 04 00 00 00
        00 00 38 70 04 81 00 00 00 00 00 01 00 00 00 00
        00 00 2d 9d
        "
    );
    parse_emit(&PACKET[17..]);
}

#[test]
pub fn parse_l2() {
    const PACKET: &[u8] = &hex!(
        "
83 1b 01 00 14 01 00 00 01 1f 01 5a 00 00 00 00
00 01 00 00 00 00 1a 05 05 08 03 81 02 cc 8e 01
04 03 49 00 00 89 07 75 62 75 6e 74 75 31 f2 22
0b 00 00 01 00 02 09 c0 00 1f 40 01 03 00 3e 80
13 01 00 16 09 00 00 03 e8 01 03 00 3a 98 17 02
01 08 86 04 01 01 01 01 16 8b 00 00 00 00 00 01
03 00 00 0a 2b 06 04 0b 00 00 01 08 04 0b 00 00
02 0c 10 20 11 00 00 00 00 00 00 00 00 00 00 00
00 00 01 20 0b 30 00 00 00 00 00 00 02 00 3a 9a
00 00 00 00 00 01 04 00 00 0a 4a 06 04 0a 00 00
01 08 04 0a 00 00 02 0c 10 20 10 00 00 00 00 00
00 00 00 00 00 00 00 00 01 0d 10 20 10 00 00 00
00 00 00 00 00 00 00 00 00 00 02 20 0b 30 00 00
00 00 00 00 03 00 3a 98 20 0b b0 00 00 00 00 00
00 03 00 3a 99 84 04 0b 00 00 01 87 22 00 00 00
0a 60 01 01 01 01 08 03 06 00 00 00 00 00 64 00
00 00 0a 18 0b 00 00 00 00 00 0a 18 0a 00 00 ec
0e 00 00 00 0a 00 40 20 10 00 00 00 00 00 00
"
    );
    parse_emit(PACKET);
}

#[ignore]
#[test]
pub fn parse_sid() {
    const PACKET: &[u8] = &hex!(
        "
83 1b 01 00 14 01 00 00 01 5c 04 ae 00 00 00 00
00 01 00 00 00 00 02 d9 d8 bc 03 81 02 cc 8e 01
04 03 49 00 00 89 07 75 62 75 6e 74 75 31 f2 30
ac 13 00 01 00 02 09 c0 00 1f 40 01 03 00 3e 80
13 01 00 16 09 00 00 03 e8 01 03 00 3a 98 17 02
01 08 19 02 00 00 17 08 29 03 2a 03 2c 02 2d 05
86 04 01 01 01 01 16 6e 00 00 00 00 00 01 04 00
00 0a 63 08 04 0a 00 00 03 0d 10 20 10 00 00 00
00 00 00 00 00 00 00 00 00 00 02 20 0b 30 00 00
00 00 00 00 03 00 3a 99 20 0b b0 00 00 00 00 00
00 03 00 3a 9a 20 0b 30 00 00 00 00 00 00 04 00
3a 9b 2c 22 00 00 00 00 00 03 00 00 00 00 05 20
01 de ad 00 01 00 00 00 01 00 00 00 00 00 00 06
01 04 28 18 10 00 84 04 ac 13 00 01 87 22 00 00
00 0a 60 01 01 01 01 08 03 06 00 00 00 00 00 64
00 00 00 0a 18 0b 00 00 00 00 00 0a 18 0a 00 00
ec 2a 00 00 00 00 00 40 20 01 de ad 00 01 00 00
00 00 00 0a 00 40 20 11 00 00 00 00 00 00 00 00
00 0a 00 40 20 10 00 00 00 00 00 00 1b 2e 00 00
00 00 00 00 00 00 40 20 01 de ad 00 01 00 00 1c
05 1a 00 00 01 20 01 de ad 00 01 00 00 00 00 00
00 00 00 00 00 06 01 04 28 18 10 00
"
    );
    parse_emit(PACKET);
}

#[test]
pub fn parse_srv6() {
    const PACKET: &[u8] = &hex!(
        "
83 1b 01 00 14 01 00 00 01 9d 01 4f 00 00 00 00
00 01 00 00 00 00 0e 7d ae a3 03 81 02 cc 8e 01
04 03 49 00 00 89 07 75 62 75 6e 74 75 31 f2 30
0b 00 00 01 00 02 09 c0 00 1f 40 01 03 00 3e 80
13 01 00 16 09 00 00 03 e8 01 03 00 3a 98 17 02
01 08 19 02 00 00 17 08 29 03 2a 03 2c 02 2d 05
86 04 01 01 01 01 16 af 00 00 00 00 00 01 03 00
00 0a 2b 06 04 0b 00 00 01 08 04 0b 00 00 02 0c
10 20 11 00 00 00 00 00 00 00 00 00 00 00 00 00
01 20 0b 30 00 00 00 00 00 00 02 00 3a 9a 00 00
00 00 00 01 04 00 00 0a 6e 06 04 0a 00 00 01 08
04 0a 00 00 03 0c 10 20 10 00 00 00 00 00 00 00
00 00 00 00 00 00 01 0d 10 20 10 00 00 00 00 00
00 00 00 00 00 00 00 00 02 20 0b 30 00 00 00 00
00 00 03 00 3a 98 20 0b b0 00 00 00 00 00 00 03
00 3a 99 2c 22 00 00 00 00 00 03 00 00 00 00 05
20 01 de ad 00 01 00 00 00 01 00 00 00 00 00 00
06 01 04 28 18 10 00 84 04 0b 00 00 01 87 22 00
00 00 0a 60 01 01 01 01 08 03 06 00 00 00 00 00
01 00 00 00 0a 18 0b 00 00 00 00 00 0a 18 0a 00
00 ec 2a 00 00 00 00 00 40 20 01 de ad 00 01 00
00 00 00 00 0a 00 40 20 11 00 00 00 00 00 00 00
00 00 0a 00 40 20 10 00 00 00 00 00 00 1b 2e 00
00 00 00 00 00 00 00 40 20 01 de ad 00 01 00 00
1c 05 1a 00 00 01 20 01 de ad 00 01 00 00 00 00
00 00 00 00 00 00 06 01 04 28 18 10 00
"
    );
    parse_emit(PACKET);
}

/// draft-ietf-rtgwg-srv6-egress-protection — build an SRv6 Locator TLV
/// carrying a Mirror SID sub-TLV (End.M / behavior 74) with one
/// Protected Locators sub-sub-TLV, emit it through the top-level
/// `IsisTlv`, re-parse, and assert the structure survives byte-for-byte.
#[test]
fn srv6_mirror_sid_round_trips_through_isis_tlv() {
    use std::net::Ipv6Addr;
    // The crate-root `IsisSubTlv` glob-resolves to the Router Capability
    // variant; the SRv6 Locator TLV uses the prefix-scoped one.
    use isis_packet::prefix::IsisSubTlv as PrefixSubTlv;

    let mirror = IsisSubSrv6MirrorSid {
        flags: 0,
        behavior: Behavior::EndM,
        sid: "2001:db8:a4:1::3".parse::<Ipv6Addr>().unwrap(),
        sub2s: vec![IsisMirrorSub2Tlv::ProtectedLocators(
            IsisSub2ProtectedLocators {
                locator: "2001:db8:a3:1::/64".parse().unwrap(),
            },
        )],
    };

    let locator = Srv6Locator {
        metric: 0,
        flags: 0,
        algo: Algo::Spf,
        locator: "2001:db8:a4:1::/64".parse().unwrap(),
        subs: vec![PrefixSubTlv::Srv6MirrorSid(mirror)],
    };

    let original = IsisTlv::Srv6(IsisTlvSrv6 {
        flags: 0u16.into(),
        locators: vec![locator],
    });

    let mut buf = BytesMut::new();
    original.emit(&mut buf);

    let (rest, tlvs) = IsisTlv::parse_tlvs(&buf).expect("parse must succeed");
    assert!(rest.is_empty());
    assert_eq!(tlvs.len(), 1);
    assert_eq!(tlvs[0], original, "round-trip must preserve the TLV");

    let IsisTlv::Srv6(srv6) = &tlvs[0] else {
        panic!("expected Srv6 TLV, got {:?}", tlvs[0]);
    };
    let sub = &srv6.locators[0].subs[0];
    let PrefixSubTlv::Srv6MirrorSid(m) = sub else {
        panic!("expected Srv6MirrorSid sub-TLV, got {:?}", sub);
    };
    assert_eq!(m.behavior, Behavior::EndM);
    assert_eq!(u16::from(m.behavior), 74);
    assert_eq!(m.sid, "2001:db8:a4:1::3".parse::<Ipv6Addr>().unwrap());
    assert_eq!(m.sub2s.len(), 1);
    let IsisMirrorSub2Tlv::ProtectedLocators(pl) = &m.sub2s[0] else {
        panic!(
            "expected ProtectedLocators sub-sub-TLV, got {:?}",
            m.sub2s[0]
        );
    };
    assert_eq!(pl.locator, "2001:db8:a3:1::/64".parse().unwrap());
}

#[test]
fn sid_label_binding_mirror_context_round_trips() {
    use ipnet::Ipv4Net;

    // SID/Label Binding TLV (149) with the M-flag set: a Mirror Context
    // binding (RFC 8679 egress protection) for the protected egress's
    // loopback 10.0.0.3/32, carrying the context label 16003 in a
    // SID/Label sub-TLV (type 1).
    let original = IsisTlv::SidLabelBinding(IsisTlvSidLabelBinding {
        flags: BindingFlags::new().with_m_flag(true),
        weight: 0,
        range: 1,
        prefix: BindingPrefix::V4("10.0.0.3/32".parse::<Ipv4Net>().unwrap()),
        subs: vec![IsisBindingSubTlv::SidLabel(SidLabelValue::Label(16003))],
    });

    let mut buf = BytesMut::new();
    original.emit(&mut buf);

    let (rest, tlvs) = IsisTlv::parse_tlvs(&buf).expect("parse must succeed");
    assert!(rest.is_empty());
    assert_eq!(tlvs.len(), 1);
    assert_eq!(tlvs[0], original, "round-trip must preserve the TLV");

    let IsisTlv::SidLabelBinding(b) = &tlvs[0] else {
        panic!("expected SidLabelBinding TLV, got {:?}", tlvs[0]);
    };
    assert!(b.flags.m_flag(), "M-flag must survive the round-trip");
    assert!(!b.flags.f_flag(), "IPv4 binding ⇒ F-flag clear");
    assert_eq!(b.prefix, BindingPrefix::V4("10.0.0.3/32".parse().unwrap()));
    assert_eq!(b.subs.len(), 1);
    let IsisBindingSubTlv::SidLabel(SidLabelValue::Label(label)) = &b.subs[0] else {
        panic!(
            "expected SID/Label sub-TLV with a label, got {:?}",
            b.subs[0]
        );
    };
    assert_eq!(*label, 16003);
}

#[test]
fn sid_label_binding_ipv6_index_round_trips() {
    use ipnet::Ipv6Net;

    // IPv6 prefix (F-flag set) + a 32-bit SID index sub-TLV (len 4).
    let original = IsisTlv::SidLabelBinding(IsisTlvSidLabelBinding {
        flags: BindingFlags::new().with_f_flag(true),
        weight: 5,
        range: 4,
        prefix: BindingPrefix::V6("2001:db8::3/128".parse::<Ipv6Net>().unwrap()),
        subs: vec![IsisBindingSubTlv::SidLabel(SidLabelValue::Index(42))],
    });

    let mut buf = BytesMut::new();
    original.emit(&mut buf);

    let (rest, tlvs) = IsisTlv::parse_tlvs(&buf).expect("parse must succeed");
    assert!(rest.is_empty());
    assert_eq!(tlvs[0], original, "round-trip must preserve the TLV");

    let IsisTlv::SidLabelBinding(b) = &tlvs[0] else {
        panic!("expected SidLabelBinding TLV");
    };
    assert!(b.flags.f_flag());
    assert!(!b.flags.m_flag());
    assert_eq!(b.weight, 5);
    assert_eq!(b.range, 4);
    assert!(matches!(
        b.subs[0],
        IsisBindingSubTlv::SidLabel(SidLabelValue::Index(42))
    ));
}

#[test]
pub fn parse_p2p_hello() {
    const PACKET: &[u8] = &hex!(
        "
83 14 01 00 11 01 00 00 02 00 00 00 00 00 02 00
1E 05 D9 00 81 02 CC 8E 01 04 03 49 00 00 F0 0F
00 00 00 00 01 00 00 00 00 00 01 00 00 00 00 84
04 C0 A8 0A 02 E8 10 FE 80 00 00 00 00 00 00 02
1C 42 FF FE E8 0C 23 E9 10 20 01 0D B8 00 01 00
00 00 00 00 00 00 00 00 02 08 FF 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 08 FF 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 08 FF 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 08 FF 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 08 FF 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 79
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00"
    );
    parse_emit(PACKET);
}

/// Classic Cisco IOS sends the P2P three-way TLV (240) in the legacy
/// 1-octet form: only the Adjacency Three-Way State, no Extended Local
/// Circuit ID and no neighbor fields (all optional per RFC 5303 §3.2).
/// This P2P IIH mirrors a real IOS capture, including the TLV order —
/// Restart(211), P2p3Way(240), ProtSupported(129), AreaAddr(1),
/// Ipv4IfAddr(132). Every TLV after 240 must survive: a parse failure
/// on 240 used to make many0-based parse_tlvs stop there and silently
/// drop the rest of the PDU's TLVs.
#[test]
pub fn parse_p2p_hello_cisco_state_only_three_way() {
    const PACKET: &[u8] = &hex!(
        "
        83 14 01 00 11 01 00 00
        02
        00 00 00 00 00 01
        00 1e
        00 2b
        00
        d3 03 00 00 00
        f0 01 00
        81 01 cc
        01 04 03 49 00 00
        84 04 c0 a8 00 02
        "
    );
    let (_, packet) = parse(PACKET).expect("Cisco IOS P2P IIH must parse");
    let IsisPdu::P2pHello(hello) = &packet.pdu else {
        panic!("expected P2P Hello, got {:?}", packet.pdu_type);
    };

    assert_eq!(
        hello.tlvs.len(),
        5,
        "no TLV may be dropped: {:?}",
        hello.tlvs
    );

    let three_way = hello
        .tlvs
        .iter()
        .find_map(|tlv| match tlv {
            IsisTlv::P2p3Way(v) => Some(v),
            _ => None,
        })
        .expect("1-octet three-way TLV must parse as P2p3Way");
    assert_eq!(three_way.state, 0); // Up
    assert_eq!(three_way.circuit_id, None);
    assert_eq!(three_way.neighbor_id, None);
    assert_eq!(three_way.neighbor_circuit_id, None);

    // TLVs after 240 must be present.
    assert!(
        hello.tlvs.iter().any(
            |tlv| matches!(tlv, IsisTlv::Ipv4IfAddr(v) if v.addr.octets() == [192, 168, 0, 2])
        )
    );
    assert!(
        hello
            .tlvs
            .iter()
            .any(|tlv| matches!(tlv, IsisTlv::ProtoSupported(_)))
    );

    // And the whole PDU still round-trips.
    let mut buf = BytesMut::new();
    packet.emit(&mut buf);
    assert_eq!(&buf[..], PACKET);
}

/// RFC 5303 allows TLV 240 at value lengths 1 (state only), 5 (+ circuit
/// id), 11 (+ neighbor sys-id) and 15 (+ neighbor circuit id). Each form
/// must round-trip emit -> parse unchanged.
#[test]
pub fn three_way_tlv_round_trips_all_lengths() {
    let sys_id = IsisSysId {
        id: [0, 0, 0, 0, 0, 0x10],
    };
    let cases = [
        (
            IsisTlvP2p3Way {
                state: 2,
                circuit_id: None,
                neighbor_id: None,
                neighbor_circuit_id: None,
            },
            3usize, // TL header + 1
        ),
        (
            IsisTlvP2p3Way {
                state: 1,
                circuit_id: Some(2),
                neighbor_id: None,
                neighbor_circuit_id: None,
            },
            7,
        ),
        (
            IsisTlvP2p3Way {
                state: 1,
                circuit_id: Some(2),
                neighbor_id: Some(sys_id),
                neighbor_circuit_id: None,
            },
            13,
        ),
        (
            IsisTlvP2p3Way {
                state: 0,
                circuit_id: Some(2),
                neighbor_id: Some(sys_id),
                neighbor_circuit_id: Some(3),
            },
            17,
        ),
    ];
    for (original, wire_len) in cases {
        let tlv: IsisTlv = original.clone().into();
        let mut buf = BytesMut::new();
        tlv.emit(&mut buf);
        assert_eq!(buf.len(), wire_len);
        let (rest, parsed) = IsisTlv::parse_tlvs(&buf).expect("round-trip parse");
        assert!(rest.is_empty());
        assert_eq!(parsed, vec![IsisTlv::P2p3Way(original)]);
    }
}

/// A known TLV whose value fails its inner parser must degrade to
/// IsisTlvUnknown (bytes preserved) instead of aborting the TLV stream:
/// under many0 an inner error silently truncates every following TLV.
#[test]
pub fn malformed_known_tlv_degrades_to_unknown() {
    // Ipv4IfAddr (132) with a 3-byte value: too short for an IPv4
    // address, so the typed parser fails. Followed by ProtSupported.
    const TLVS: &[u8] = &hex!("84 03 c0 a8 00  81 01 cc");
    let (rest, tlvs) = IsisTlv::parse_tlvs(TLVS).expect("stream must parse");
    assert!(rest.is_empty());
    assert_eq!(tlvs.len(), 2);
    let IsisTlv::Unknown(unknown) = &tlvs[0] else {
        panic!("malformed TLV must become Unknown, got {:?}", tlvs[0]);
    };
    assert_eq!(unknown.values, vec![0xc0, 0xa8, 0x00]);
    assert!(matches!(tlvs[1], IsisTlv::ProtoSupported(_)));
}
