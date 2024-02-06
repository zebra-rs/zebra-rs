use crate::*;
use bytes::BytesMut;
use nom::AsBytes;
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Debug, Eq, PartialEq)]
pub enum State {
    Idle,
    Connect,
    Active,
    OpenSent,
    OpenConfirm,
    Established,
}

#[derive(Debug, Eq, PartialEq)]
pub enum Event {
    Start,        // 1
    Stop,         // 2
    Connected,    // 17
    ConnFail,     // 18
    BGPOpen,      // 19
    NotifMsg,     // 25
    KeepAliveMsg, // 26
    UpdateMsg,    // 27
}

pub struct Peer {
    pub bgp: BgpInstance,
    pub peer_as: u32,
    pub address: Ipv4Addr,
    pub state: State,
}

async fn handler() {
    println!("hello");
}

impl Peer {
    pub fn new(bgp: BgpInstance, peer_as: u32, address: Ipv4Addr) -> Self {
        let peer = Self {
            bgp: bgp.clone(),
            peer_as,
            address,
            state: State::Idle,
        };

        tokio::spawn(async move {
            let bgp = bgp.read().await;

            let mut stream = TcpStream::connect(address.to_string() + ":179")
                .await
                .unwrap();

            let header = BgpHeader::new(BgpPacketType::Open, BGP_PACKET_HEADER_LEN + 10);
            let open = OpenPacket::new(header, bgp.asn as u16, &bgp.router_id);

            let bytes: BytesMut = open.into();
            stream.write_all(&bytes[..]).await.unwrap();

            let keepalive = BgpHeader::new(BgpPacketType::Keepalive, BGP_PACKET_HEADER_LEN);
            let bytes: BytesMut = keepalive.into();
            stream.write_all(&bytes[..]).await.unwrap();

            // Keepalive timer.
            let _timer = Timer::new(Duration::new(3, 0), TimerType::Infinite, handler);

            loop {
                let mut rx = [0u8; BGP_PACKET_MAX_LEN];
                let rx_len = stream.read(&mut rx).await.unwrap();
                if rx_len >= BGP_PACKET_HEADER_LEN as usize {
                    let (_, p) = parse_bgp_packet(rx.as_bytes()).expect("error");
                    println!("{:?}", p);
                }
            }
        });
        peer
    }
}
