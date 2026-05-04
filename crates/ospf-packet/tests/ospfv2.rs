use bytes::BytesMut;
use hex_literal::hex;
use nom_derive::Parse;
use ospf_packet::*;

fn parse_emit(buf: &[u8]) {
    let packet = parse(buf);
    assert!(packet.is_ok());

    let (rem, packet) = packet.unwrap();
    assert!(rem.is_empty());
    println!("{}", packet);

    let mut buf = BytesMut::new();
    packet.emit(&mut buf);
    println!("Buf len {}", buf.len());

    let packet = parse(&buf);
    assert!(packet.is_ok());

    let (_, packet) = packet.unwrap();
    println!("{}", packet);
}

#[test]
pub fn parse_hello() {
    const PACKET: &[u8] = &hex!(
        "
        02 01 00 2c c0 a8 aa 08 00 00 00 01 27 3b 00 00
        00 00 00 00 00 00 00 00 ff ff ff 00 00 0a 02 01
        00 00 00 28 c0 a8 aa 08 00 00 00 00
        "
    );
    parse_emit(PACKET);
}

#[test]
pub fn parse_unknown() {
    const PACKET: &[u8] = &hex!(
        "
        02 06 00 2c c0 a8 aa 08 00 00 00 01 27 3b 00 00
        00 00 00 00 00 00 00 00 ff ff ff 00 00 0a 02 01
        00 00 00 28 c0 a8 aa 08 00 00 00 00
        "
    );
    let packet = parse(PACKET);
    println!("{:?}", packet);
    // assert!(packet.is_ok());

    // let (rem, packet) = packet.unwrap();
    // assert!(rem.is_empty());
    // println!("{}", packet);
}

#[test]
pub fn parse_hello_with_neighbor() {
    const PACKET: &[u8] = &hex!(
        "
        01 00 5e 00 00 05 00 1c 42 d3 17 49 08 00 45 c0
        00 44 bb a1 00 00 01 59 11 f8 0b 00 00 03 e0 00
        00 05 02 01 00 30 0b 00 00 03 00 00 00 00 d9 91
        00 00 00 00 00 00 00 00 00 00 ff ff ff 00 00 0a
        02 01 00 00 00 28 0b 00 00 01 0b 00 00 03 01 01
        01 01
        "
    );
    parse_emit(&PACKET[34..]);
}

#[test]
pub fn parse_db_desc() {
    const PACKET: &[u8] = &hex!(
        "
        02 02 00 20 c0 a8 aa 08 00 00 00 01 a0 52 00 00
        00 00 00 00 00 00 00 00 05 dc 02 07 41 77 a9 7e
        "
    );
    parse_emit(PACKET);
}

#[test]
pub fn parse_db_desc_lsa() {
    const PACKET: &[u8] = &hex!(
        "
        02 02 00 ac c0 a8 aa 03 00 00 00 01 f0 67 00 00
        00 00 00 00 00 00 00 00 05 dc 02 02 41 77 a9 7e
        00 01 02 01 c0 a8 aa 03 c0 a8 aa 03 80 00 00 01
        3a 9c 00 30 00 02 02 05 50 d4 10 00 c0 a8 aa 02
        80 00 00 01 2a 49 00 24 00 02 02 05 94 79 ab 00
        c0 a8 aa 02 80 00 00 01 34 a5 00 24 00 02 02 05
        c0 82 78 00 c0 a8 aa 02 80 00 00 01 d3 19 00 24
        00 02 02 05 c0 a8 00 00 c0 a8 aa 02 80 00 00 01
        37 08 00 24 00 02 02 05 c0 a8 01 00 c0 a8 aa 02
        80 00 00 01 2c 12 00 24 00 02 02 05 c0 a8 ac 00
        c0 a8 aa 02 80 00 00 01 33 41 00 24
        "
    );
    parse_emit(PACKET);
}

#[test]
pub fn parse_ls_request() {
    const PACKET: &[u8] = &hex!(
        "
        02 03 00 24 c0 a8 aa 03 00 00 00 01 bd c7 00 00
        00 00 00 00 00 00 00 00 00 00 00 01 c0 a8 aa 08
        c0 a8 aa 08
        "
    );
    parse_emit(PACKET);
}

#[test]
pub fn parse_ls_request_multi() {
    const PACKET: &[u8] = &hex!(
        "
        02 03 00 6c c0 a8 aa 08 00 00 00 01 75 95 00 00
        00 00 00 00 00 00 00 00 00 00 00 01 c0 a8 aa 03
        c0 a8 aa 03 00 00 00 05 50 d4 10 00 c0 a8 aa 02
        00 00 00 05 94 79 ab 00 c0 a8 aa 02 00 00 00 05
        c0 82 78 00 c0 a8 aa 02 00 00 00 05 c0 a8 00 00
        c0 a8 aa 02 00 00 00 05 c0 a8 01 00 c0 a8 aa 02
        00 00 00 05 c0 a8 ac 00 c0 a8 aa 02
        "
    );
    parse_emit(PACKET);
}

#[test]
pub fn parse_ls_upd() {
    const PACKET: &[u8] = &hex!(
        "
        02 04 00 40 c0 a8 aa 08 00 00 00 01 96 1f 00 00
        00 00 00 00 00 00 00 00 00 00 00 01 03 e2 02 01
        c0 a8 aa 08 c0 a8 aa 08 80 00 0d c3 25 06 00 24
        02 00 00 01 c0 a8 aa 00 ff ff ff 00 03 00 00 0a
        "
    );
    let (rem, packet) = parse(PACKET).unwrap();
    assert_eq!(rem.len(), 0);
    println!("{}", packet);
    println!("rem len: {:?}", rem.len());
}

#[test]
pub fn parse_ls_upd_multi() {
    const PACKET: &[u8] = &hex!(
        "
        02 04 01 24 c0 a8 aa 03 00 00 00 01 36 6b 00 00
        00 00 00 00 00 00 00 00 00 00 00 07 00 02 02 01
        c0 a8 aa 03 c0 a8 aa 03 80 00 00 01 3a 9c 00 30
        02 00 00 02 c0 a8 aa 00 ff ff ff 00 03 00 00 0a
        c0 a8 aa 00 ff ff ff 00 03 00 00 0a 00 03 02 05
        50 d4 10 00 c0 a8 aa 02 80 00 00 01 2a 49 00 24
        ff ff ff ff 80 00 00 14 00 00 00 00 00 00 00 00
        00 03 02 05 94 79 ab 00 c0 a8 aa 02 80 00 00 01
        34 a5 00 24 ff ff ff 00 80 00 00 14 c0 a8 aa 01
        00 00 00 00 00 03 02 05 c0 82 78 00 c0 a8 aa 02
        80 00 00 01 d3 19 00 24 ff ff ff 00 80 00 00 14
        00 00 00 00 00 00 00 00 00 03 02 05 c0 a8 00 00
        c0 a8 aa 02 80 00 00 01 37 08 00 24 ff ff ff 00
        80 00 00 14 00 00 00 00 00 00 00 00 00 03 02 05
        c0 a8 01 00 c0 a8 aa 02 80 00 00 01 2c 12 00 24
        ff ff ff 00 80 00 00 14 00 00 00 00 00 00 00 00
        00 03 02 05 c0 a8 ac 00 c0 a8 aa 02 80 00 00 01
        33 41 00 24 ff ff ff 00 80 00 00 14 c0 a8 aa 0a
        00 00 00 00
        "
    );
    let (rem, packet) = parse(PACKET).unwrap();
    assert_eq!(rem.len(), 0);
    println!("{}", packet);
    println!("rem len: {:?}", rem.len());
}

#[test]
pub fn parse_ls_upd_router() {
    const PACKET: &[u8] = &hex!(
        "
        00 1c 42 45 b2 35 00 1c 42 e8 0c 23 08 00 45 c0
        00 54 9f 0e 00 00 01 59 03 81 0b 00 00 01 0b 00
        00 02 02 04 00 40 01 01 01 01 00 00 00 00 85 f5
        00 00 00 00 00 00 00 00 00 00 00 00 00 01 01 38
        02 01 01 01 01 01 01 01 01 01 80 00 00 d0 e0 85
        00 24 00 00 00 01 0b 00 00 00 ff ff ff 00 03 00
        00 0a
        "
    );
    let (rem, packet) = parse(&PACKET[34..]).unwrap();
    assert_eq!(rem.len(), 0);
    println!("{}", packet);
    println!("rem len: {:?}", rem.len());
}

#[test]
pub fn parse_ls_ack() {
    const PACKET: &[u8] = &hex!(
        "
        02 05 00 2c c0 a8 aa 08 00 00 00 01 02 f2 00 00
        00 00 00 00 00 00 00 00 00 01 02 01 c0 a8 aa 03
        c0 a8 aa 03 80 00 00 02 38 9d 00 30

        "
    );
    let (rem, packet) = parse(PACKET).unwrap();
    assert!(rem.is_empty());
    println!("{}", packet);
    println!("rem len: {:?}", rem.len());
}

#[test]
#[ignore]
pub fn parse_ls_summary() {
    const PACKET: &[u8] = &hex!(
        "
        00 0b 22 03 c0 a8 0a 00 04 04 04 04 80 00 00 01
        1e 7d 00 1c ff ff ff 00 00 00 00 1e
        "
    );
    let (rem, packet) = parse(PACKET).unwrap();
    assert!(rem.is_empty());
    println!("{}", packet);
    println!("rem len: {:?}", rem.len());
}

#[test]
#[ignore]
pub fn parse_lsa_type7() {
    const PACKET: &[u8] = &hex!(
        "
        00 66 28 07 ac 10 00 00 02 02 02 02 80 00 00 01
        63 ac 00 24 ff ff ff fc 80 00 00 64 c0 a8 0a 01
        00 00 00 00
        "
    );
    let (rem, packet) = parse(PACKET).unwrap();
    assert!(rem.is_empty());
    println!("{}", packet);
    println!("rem len: {:?}", rem.len());
}

#[test]
pub fn parse_unknown2() {
    const PACKET: &[u8] = &hex!(
        "
        00 66 28 07 ac 10 00 00 02 02 02 02 80 00 00 01
        63 ac 00 24 ff ff ff fc 80 00 00 64 c0 a8 0a 01
        00 00 00 00
        "
    );
    let (rem, packet) = UnknownLsa::parse_be(PACKET).unwrap();
    assert!(rem.is_empty());
    println!("{:?}", packet);
    println!("rem len: {:?}", rem.len());
}
