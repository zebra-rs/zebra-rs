use crate::*;
use bytes::BytesMut;
use nom::AsBytes;
use std::net::Ipv4Addr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

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
pub struct PeerTask {
    pub start: Option<Timer>,
    pub connect: Option<Task<()>>,
    pub reader: Option<Task<()>>,
    pub writer: Option<Task<()>>,
}

impl PeerTask {
    pub fn new() -> Self {
        Self {
            start: None,
            connect: None,
            reader: None,
            writer: None,
        }
    }
}

impl Default for PeerTask {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct Peer {
    pub ident: Ipv4Addr,
    pub local_as: u32,
    pub router_id: Ipv4Addr,
    pub peer_as: u32,
    pub address: Ipv4Addr,
    pub state: State,
    pub task: PeerTask,
    pub tx: UnboundedSender<Message>,
    pub packet_tx: Option<UnboundedSender<BytesMut>>,
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
            task: PeerTask::new(),
            tx,
            packet_tx: None,
        };
        peer.task.start = Some(peer_start_timer(&peer));
        peer
    }
}

pub fn fsm(peer: &mut Peer, event: Event) {
    match event {
        Event::Start => {
            peer.task.start = None;
            peer.task.connect = Some(peer_start_connection(peer));
        }
        Event::Connected(stream) => {
            peer.task.connect = None;
            let (tx, rx) = mpsc::unbounded_channel::<BytesMut>();
            peer.packet_tx = Some(tx);
            let (read_half, write_half) = stream.into_split();
            peer.task.reader = Some(peer_start_reader(peer, read_half));
            peer.task.writer = Some(peer_start_writer(write_half, rx));
            peer_send_open(peer);
            peer_send_keepalive(peer);
        }
        Event::Stop => {}
        _ => {}
    }
}

pub fn peer_start_reader(_peer: &Peer, mut read_half: OwnedReadHalf) -> Task<()> {
    Task::spawn(async move {
        loop {
            let mut rx = [0u8; BGP_PACKET_MAX_LEN];
            let rx_len = read_half.read(&mut rx).await.unwrap();
            if rx_len >= BGP_PACKET_HEADER_LEN as usize {
                let (_, p) = parse_bgp_packet(rx.as_bytes()).expect("error");
                println!("{:?}", p);
            }
        }
    })
}

pub fn peer_start_writer(
    mut write_half: OwnedWriteHalf,
    mut rx: UnboundedReceiver<BytesMut>,
) -> Task<()> {
    Task::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let _ = write_half.write_all(&msg).await;
        }
    })
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

pub fn peer_send_open(peer: &Peer) {
    let header = BgpHeader::new(BgpPacketType::Open, BGP_PACKET_HEADER_LEN + 10);
    let open = OpenPacket::new(header, peer.local_as as u16, &peer.router_id);
    let bytes: BytesMut = open.into();
    let _ = peer.packet_tx.as_ref().unwrap().send(bytes);
}

pub fn peer_send_keepalive(peer: &Peer) {
    let header = BgpHeader::new(BgpPacketType::Open, BGP_PACKET_HEADER_LEN);
    let bytes: BytesMut = header.into();
    let _ = peer.packet_tx.as_ref().unwrap().send(bytes);
}

// pub fn peer_keepalive_start(peer: &Peer) {
//     let tx = peer.tx.clone();
//     let ident = peer.ident;
//     Timer::new(Timer::second(3), TimerType::Infinite, move || {
//         let tx = tx.clone();
//         async move {
//             //
//         }
//     });
// }
