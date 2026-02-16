use bgp_packet::*;
use hex_literal::hex;

fn test1(buf: &[u8]) {
    // Parse with AS4 = truue.
    let packet = BgpPacket::parse_packet(buf, true, None);
    assert!(packet.is_ok());

    let (_, packet) = packet.unwrap();
    if let BgpPacket::Update(update) = packet {
        if let Some(MpUnreachAttr::Evpn(evpn_routes)) = update.mp_withdraw {
            assert!(evpn_routes.len() == 1);
        }
    } else {
        panic!("Packet must be Update");
    }
}

fn test2(buf: &[u8]) {
    // Parse with AS4 = truue.
    let packet = BgpPacket::parse_packet(buf, true, None);
    assert!(packet.is_ok());

    let (_, packet) = packet.unwrap();
    if let BgpPacket::Update(update) = packet {
        println!("{:?}", update);
        if let Some(MpUnreachAttr::Evpn(evpn_routes)) = update.mp_withdraw {
            assert!(evpn_routes.len() == 2);
        }
    } else {
        panic!("Packet must be Update");
    }
}

#[test]
pub fn parse_evpn_test_1() {
    const PACKET: &[u8] = &hex!(
        "
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
00 41 02 00 00 00 2a 90 0f 00 26 00 19 46 02 21
00 01 01 02 03 04 00 02 00 00 00 00 00 00 00 00
00 00 00 00 00 00 30 5e e9 1e 08 4d 68 00 00 00
00
"
    );
    test1(PACKET);
}

#[test]
pub fn parse_evpn_test_2() {
    const PACKET: &[u8] = &hex!(
        "
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
00 98 02 00 00 00 81 90 0e 00 5b 00 19 46 10 20
01 0d b8 00 00 00 01 00 00 00 00 00 00 00 11 00
02 21 00 01 01 02 03 04 00 02 00 00 00 00 00 00
00 00 00 00 00 00 00 00 30 00 1c 42 1d 71 53 00
00 02 26 02 21 00 01 01 02 03 04 00 02 00 00 00
00 00 00 00 00 00 00 00 00 00 00 30 00 1c 42 e5
c4 21 00 00 02 26 40 01 01 00 50 02 00 00 40 05
04 00 00 00 64 c0 10 10 03 0c 00 00 00 00 00 08
00 02 fc 00 00 00 02 26
"
    );
    test2(PACKET);
}

#[test]
pub fn parse_evpn_test_3() {
    const PACKET: &[u8] = &hex!(
        "
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
00 7d 02 00 00 00 66 90 0e 00 34 00 19 46 10 20
01 0d b8 00 00 00 01 00 00 00 00 00 00 00 11 00
03 1d 00 01 01 02 03 04 00 02 00 00 00 00 80 20
01 0d b8 00 00 00 01 00 00 00 00 00 00 00 11 40
01 01 00 50 02 00 00 40 05 04 00 00 00 64 c0 10
10 03 0c 00 00 00 00 00 08 00 02 fc 00 00 00 02
26 c0 16 09 00 06 00 02 26 00 00 00 00
"
    );
    test2(PACKET);
}

#[test]
pub fn parse_evpn_test_4() {
    const PACKET: &[u8] = &hex!(
        "
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
00 6a 02 00 00 00 4e 40 01 01 00 40 02 06 02 01
00 00 00 64 40 03 04 0a d3 37 02 80 04 04 00 00
00 7b 40 05 04 00 00 00 64 40 06 00 c0 07 08 00
00 00 01 0a d3 37 02 c0 08 08 00 64 00 0a 00 64
00 14 c0 10 10 00 02 00 7b 00 00 00 64 01 03 01
01 01 01 00 0c 20 01 01 01 01
"
    );
    let packet = BgpPacket::parse_packet(PACKET, true, None);
    assert!(packet.is_ok());
    let (_, packet) = packet.unwrap();
    if let BgpPacket::Update(update) = packet {
        println!("XXX {:?}", update);
    } else {
        panic!("Mut be Update packet");
    }
}
