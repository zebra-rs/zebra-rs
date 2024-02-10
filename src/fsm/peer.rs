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

#[derive(Debug)]
pub enum Event {
    Start,                // 1
    Stop,                 // 2
    Connected(TcpStream), // 17
    ConnFail,             // 18
    BGPOpen,              // 19
    NotifMsg,             // 25
    KeepAliveMsg,         // 26
    UpdateMsg,            // 27
}

#[derive(Debug)]
pub struct Peer {
    pub ident: Ipv4Addr,
    pub local_as: u32,
    pub router_id: Ipv4Addr,
    pub peer_as: u32,
    pub address: Ipv4Addr,
    pub state: State,
    pub tx: UnboundedSender<Message>,
    pub start: Option<Timer>,
    pub connect: Option<Task<()>>,
    pub stream: Option<TcpStream>,
}

impl Peer {
    pub fn new(
        ident: Ipv4Addr,
        local_as: u32,
        router_id: Ipv4Addr,
        peer_as: u32,
        address: Ipv4Addr,
        tx: UnboundedSender<Message>,
    ) -> Self {
        let mut peer = Self {
            ident,
            router_id,
            local_as,
            peer_as,
            address,
            state: State::Idle,
            tx,
            start: None,
            stream: None,
            connect: None,
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
            peer.connect = Some(peer_start_connection(peer));
        }
        Event::Connected(stream) => {
            peer.connect = None;
            // Send open, keepalive
        }
        Event::Stop => {}
        _ => {}
    }
}

pub fn peer_start_timer(peer: &Peer) -> Timer {
    let tx = peer.tx.clone();
    let ident = peer.ident;
    Timer::new(Timer::second(1), TimerType::Once, move || {
        let tx = tx.clone();
        async move {
            let _ = tx.send(Message::Event(ident, Event::Start));
        }
    })
}

pub fn peer_start_connection(peer: &mut Peer) -> Task<()> {
    let tx = peer.tx.clone();
    let ident = peer.ident;
    let address = peer.address;
    Task::spawn(async move {
        let tx = tx.clone();
        let stream = TcpStream::connect(address.to_string() + ":179")
            .await
            .unwrap();
        let _ = tx.send(Message::Event(ident, Event::Connected(stream)));
    })
}

pub fn peer_keepalive_start(peer: &Peer) {
    let tx = peer.tx.clone();
    let ident = peer.ident;
    Timer::new(Timer::second(3), TimerType::Infinite, move || {
        let tx = tx.clone();
        async move {
            //
        }
    });
}

pub async fn peer_keepalive_send(stream: &mut TcpStream) {
    let keepalive = BgpHeader::new(BgpPacketType::Keepalive, BGP_PACKET_HEADER_LEN);
    let bytes: BytesMut = keepalive.into();
    stream.write_all(&bytes[..]).await.unwrap();
}
