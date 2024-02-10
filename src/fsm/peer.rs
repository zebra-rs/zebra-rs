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
    Start,                        // 1
    Stop,                         // 2
    ConnRetryTimerExpires,        // 9
    HoldTimerExpires,             // 10
    KeepaliveTimerExpires,        // 11
    Connected(TcpStream),         // 17
    ConnFail,                     // 18
    BGPOpen(OpenPacket),          // 19
    NotifMsg(NotificationPacket), // 25
    KeepAliveMsg,                 // 26
    UpdateMsg(UpdatePacket),      // 27
}

#[derive(Debug)]
pub struct PeerTask {
    pub start: Option<Timer>,
    pub connect: Option<Task<()>>,
    pub connect_retry: Option<Timer>,
    pub reader: Option<Task<()>>,
    pub writer: Option<Task<()>>,
    pub keepalive: Option<Timer>,
}

impl PeerTask {
    pub fn new() -> Self {
        Self {
            start: None,
            connect: None,
            connect_retry: None,
            reader: None,
            writer: None,
            keepalive: None,
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
    pub packet_tx: Option<UnboundedSender<BytesMut>>,
    pub tx: UnboundedSender<Message>,
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
            packet_tx: None,
            tx,
        };
        peer.task.start = Some(peer_start_timer(&peer));
        peer
    }
}

pub fn fsm(peer: &mut Peer, event: Event) {
    println!("State: {:?} -> ", peer.state);
    peer.state = match event {
        Event::Start => fsm_start(peer),
        Event::Stop => fsm_stop(peer),
        Event::ConnRetryTimerExpires => fsm_conn_retry_expires(peer),
        Event::HoldTimerExpires => fsm_holdtimer_expires(peer),
        Event::KeepaliveTimerExpires => fsm_keepalive_expires(peer),
        Event::Connected(stream) => fsm_connected(peer, stream),
        Event::ConnFail => fsm_conn_fail(peer),
        Event::BGPOpen(packet) => fsm_bgp_open(peer, packet),
        Event::NotifMsg(packet) => fsm_bgp_notification(peer, packet),
        Event::KeepAliveMsg => fsm_bgp_keepalive(peer),
        Event::UpdateMsg(packet) => fsm_bgp_update(peer, packet),
    };
    println!("State: -> {:?}", peer.state);
}

pub fn fsm_start(peer: &mut Peer) -> State {
    peer.task.start = None;
    peer.task.connect = Some(peer_start_connection(peer));
    State::Connect
}

pub fn fsm_stop(_peer: &mut Peer) -> State {
    State::Idle
}

pub fn fsm_bgp_open(_peer: &mut Peer, _packet: OpenPacket) -> State {
    State::Idle
}

pub fn fsm_bgp_notification(_peer: &mut Peer, _packet: NotificationPacket) -> State {
    State::Idle
}

pub fn fsm_bgp_keepalive(_peer: &mut Peer) -> State {
    State::Idle
}

pub fn fsm_bgp_update(_peer: &mut Peer, _packet: UpdatePacket) -> State {
    State::Idle
}

pub fn fsm_connected(peer: &mut Peer, stream: TcpStream) -> State {
    peer.task.connect = None;
    let (packet_tx, packet_rx) = mpsc::unbounded_channel::<BytesMut>();
    peer.packet_tx = Some(packet_tx);
    let (read_half, write_half) = stream.into_split();
    peer.task.reader = Some(peer_start_reader(peer, read_half));
    peer.task.writer = Some(peer_start_writer(write_half, packet_rx));
    peer_send_open(peer);
    peer_send_keepalive(peer);
    State::OpenSent
}

pub fn fsm_conn_retry_expires(_peer: &mut Peer) -> State {
    // peer_send_notification(peer);
    State::Idle
}

pub fn fsm_holdtimer_expires(_peer: &mut Peer) -> State {
    // peer_send_notification(peer);
    State::Idle
}

pub fn fsm_keepalive_expires(_peer: &mut Peer) -> State {
    // peer_send_notification(peer);
    State::Idle
}

pub fn fsm_conn_fail(peer: &mut Peer) -> State {
    peer.task.writer = None;
    peer.task.reader = None;
    State::Idle
}

pub fn peer_packet_parse(rx: &[u8], rx_len: usize, ident: Ipv4Addr, tx: UnboundedSender<Message>) {
    if rx_len >= BGP_PACKET_HEADER_LEN as usize {
        let (_, p) = parse_bgp_packet(rx).expect("error");
        match p {
            BgpPacket::Open(p) => {
                let _ = tx.send(Message::Event(ident, Event::BGPOpen(p)));
            }
            BgpPacket::Keepalive(_) => {
                let _ = tx.send(Message::Event(ident, Event::KeepAliveMsg));
            }
            BgpPacket::Notification(p) => {
                let _ = tx.send(Message::Event(ident, Event::NotifMsg(p)));
            }
            BgpPacket::Update(p) => {
                let _ = tx.send(Message::Event(ident, Event::UpdateMsg(p)));
            }
        }
    }
}

pub async fn peer_read(
    ident: Ipv4Addr,
    tx: UnboundedSender<Message>,
    mut read_half: OwnedReadHalf,
) {
    loop {
        let mut rx = [0u8; BGP_PACKET_MAX_LEN];
        match read_half.read(&mut rx).await {
            Ok(rx_len) => {
                peer_packet_parse(rx.as_bytes(), rx_len, ident, tx.clone());
            }
            Err(err) => {
                println!("{:?}", err);
                let _ = tx.send(Message::Event(ident, Event::ConnFail));
            }
        }
    }
}

pub fn peer_start_reader(peer: &Peer, read_half: OwnedReadHalf) -> Task<()> {
    let tx = peer.tx.clone();
    let ident = peer.ident;
    Task::spawn(async move {
        peer_read(ident, tx, read_half).await;
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

pub fn peer_start_keepalive(peer: &Peer) -> Timer {
    let tx = peer.tx.clone();
    let ident = peer.ident;
    Timer::new(Timer::second(3), TimerType::Infinite, move || {
        let tx = tx.clone();
        async move {
            let _ = tx.send(Message::Event(ident, Event::KeepaliveTimerExpires));
        }
    })
}
