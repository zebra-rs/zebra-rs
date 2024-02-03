use bgp_parser::*;
use bytes::BytesMut;
use nom::AsBytes;
use std::error::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let header = BgpHeader::new(BgpPacketType::Open, 29);
    let open = OpenPacket {
        header,
        version: 4,
        asn: 1,
        hold_time: 180,
        bgp_id: [10, 255, 65, 2],
        opt_parm_len: 0,
        caps: Vec::new(),
    };

    // Stream.
    let mut stream = TcpStream::connect("10.211.55.65:179").await?;

    let bytes: BytesMut = open.into();
    stream.write_all(&bytes[..]).await?;

    // Send keepavlie.
    let keepalive = BgpHeader::new(BgpPacketType::Keepalive, 19);
    let bytes: BytesMut = keepalive.into();
    stream.write_all(&bytes[..]).await?;

    // Send open.
    loop {
        let mut rx = [0u8; 4096];
        let rx_len = stream.read(&mut rx).await?;
        if rx_len >= BGP_PACKET_HEADER_LEN as usize {
            let (_, p) = parse_bgp_packet(rx.as_bytes()).expect("error");
            println!("{:?}", p);
        }
    }
}
