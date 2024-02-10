use crate::*;
use bytes::BytesMut;
use nom::AsBytes;
use std::net::Ipv4Addr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc::UnboundedSender;

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

#[derive(Debug)]
pub struct Peer {
    pub local_as: u32,
    pub router_id: Ipv4Addr,
    pub peer_as: u32,
    pub address: Ipv4Addr,
    pub state: State,
    pub tx: UnboundedSender<Message>,
    pub start: Option<Timer>,
}

impl Peer {
    pub fn new(
        local_as: u32,
        router_id: Ipv4Addr,
        peer_as: u32,
        address: Ipv4Addr,
        tx: UnboundedSender<Message>,
    ) -> Self {
        let mut peer = Self {
            router_id,
            local_as,
            peer_as,
            address,
            state: State::Idle,
            tx,
            start: None,
        };
        peer.start = Some(peer_start_timer(&peer));
        peer
    }

    pub fn work(&self) {
        let address = self.address;
        let local_as = self.local_as;
        let router_id = self.router_id;

        tokio::spawn(async move {
            let mut stream = TcpStream::connect(address.to_string() + ":179")
                .await
                .unwrap();

            let header = BgpHeader::new(BgpPacketType::Open, BGP_PACKET_HEADER_LEN + 10);
            let open = OpenPacket::new(header, local_as as u16, &router_id);

            let bytes: BytesMut = open.into();
            stream.write_all(&bytes[..]).await.unwrap();

            let keepalive = BgpHeader::new(BgpPacketType::Keepalive, BGP_PACKET_HEADER_LEN);
            let bytes: BytesMut = keepalive.into();
            stream.write_all(&bytes[..]).await.unwrap();

            loop {
                let mut rx = [0u8; BGP_PACKET_MAX_LEN];
                let rx_len = stream.read(&mut rx).await.unwrap();
                if rx_len >= BGP_PACKET_HEADER_LEN as usize {
                    let (_, p) = parse_bgp_packet(rx.as_bytes()).expect("error");
                    println!("{:?}", p);
                }
            }
        });
    }
}

pub fn fsm(peer: &mut Peer, event: Event) {
    match event {
        Event::Start => {
            peer.start = None;
        }
        Event::Stop => {}
        _ => {}
    }
}

pub fn peer_start_timer(peer: &Peer) -> Timer {
    let tx = peer.tx.clone();
    Timer::new(Timer::second(1), TimerType::Once, move || {
        let tx = tx.clone();
        async move {
            let _ = tx.send(Message::Config(String::from("peer start message")));
        }
    })
}

//pub fn peer_connection_start(peer: &mut Peer) {}

pub async fn peer_keepalive_send(stream: &mut TcpStream) {
    let keepalive = BgpHeader::new(BgpPacketType::Keepalive, BGP_PACKET_HEADER_LEN);
    let bytes: BytesMut = keepalive.into();
    stream.write_all(&bytes[..]).await.unwrap();
}

pub fn peer_keepalive_start(peer: &Peer) {
    let _tx = peer.tx.clone();
    Timer::new(Timer::second(3), TimerType::Infinite, move || {
        //let tx = tx.clone();
        async move {
            // let _ = tx.send(String::from("message"));
        }
    });
}
