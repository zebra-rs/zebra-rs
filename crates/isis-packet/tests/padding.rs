use bytes::BytesMut;
use isis_packet::*;

#[test]
pub fn padding_hello() {
    let source_id = IsisSysId::default();
    let mut hello = IsisHello {
        circuit_type: 0x03.into(),
        source_id,
        hold_time: 1200,
        pdu_len: 0,
        priority: 64,
        lan_id: IsisNeighborId::default(),
        tlvs: Vec::new(),
    };
    hello.padding(1500);

    let packet = IsisPacket::from(IsisType::L1Hello, IsisPdu::L1Hello(hello.clone()));
    let mut buf = BytesMut::new();
    packet.emit(&mut buf);
    assert_eq!(buf.len(), 1500 - 3);
}
