#![allow(dead_code)]
use super::instance::Message;
use super::packet::*;
use super::tasks::*;
use bytes::BytesMut;
use nom::AsBytes;
use std::net::Ipv4Addr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

#[derive(Debug, Eq, PartialEq, Clone)]
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
    IdleHoldTimerExpires,         // 13
    Connected(TcpStream),         // 17
    ConnFail,                     // 18
    BGPOpen(OpenPacket),          // 19
    NotifMsg(NotificationPacket), // 25
    KeepAliveMsg,                 // 26
    UpdateMsg(UpdatePacket),      // 27
}

#[derive(Debug)]
pub struct PeerTask {
    pub connect: Option<Task<()>>,
    pub reader: Option<Task<()>>,
    pub writer: Option<Task<()>>,
}

impl PeerTask {
    pub fn new() -> Self {
        Self {
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
pub struct PeerTimer {
    pub idle_hold_timer: Option<Timer>,
    pub connect_retry: Option<Timer>,
    pub hold_timer: Option<Timer>,
    pub keepalive: Option<Timer>,
    pub min_as_origin: Option<Timer>,
    pub min_route_adv: Option<Timer>,
}

#[derive(Debug, Default)]
pub struct PeerCounter {
    pub tx: [u64; 5],
    pub rx: [u64; 5],
}

impl PeerTimer {
    pub fn new() -> Self {
        Self {
            idle_hold_timer: None,
            connect_retry: None,
            hold_timer: None,
            keepalive: None,
            min_as_origin: None,
            min_route_adv: None,
        }
    }
}

impl Default for PeerTimer {
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
    pub active: bool,
    pub state: State,
    pub task: PeerTask,
    pub timer: PeerTimer,
    pub counter: PeerCounter,
    pub packet_tx: Option<UnboundedSender<BytesMut>>,
    pub tx: UnboundedSender<Message>,
    pub local_identifier: Option<Ipv4Addr>,
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
        Self {
            ident,
            router_id,
            local_as,
            peer_as,
            address,
            active: false,
            state: State::Idle,
            task: PeerTask::new(),
            timer: PeerTimer::new(),
            counter: PeerCounter::default(),
            packet_tx: None,
            tx,
            local_identifier: None,
        }
    }

    pub fn event(&self, ident: Ipv4Addr, event: Event) {
        let _ = self.tx.clone().send(Message::Event(ident, event));
    }

    pub fn is_passive(&self) -> bool {
        false
    }

    pub fn update(&mut self) {
        if self.peer_as != 0 && !self.address.is_unspecified() && !self.active {
            fsm_init(self);
            self.active = true;
        }
    }
}

pub fn fsm(peer: &mut Peer, event: Event) {
    let prev_state = peer.state.clone();
    peer.state = match event {
        Event::Start => fsm_start(peer),
        Event::Stop => fsm_stop(peer),
        Event::ConnRetryTimerExpires => fsm_conn_retry_expires(peer),
        Event::HoldTimerExpires => fsm_holdtimer_expires(peer),
        Event::KeepaliveTimerExpires => fsm_keepalive_expires(peer),
        Event::IdleHoldTimerExpires => fsm_idle_hold_timer_expires(peer),
        Event::Connected(stream) => fsm_connected(peer, stream),
        Event::ConnFail => fsm_conn_fail(peer),
        Event::BGPOpen(packet) => fsm_bgp_open(peer, packet),
        Event::NotifMsg(packet) => fsm_bgp_notification(peer, packet),
        Event::KeepAliveMsg => fsm_bgp_keepalive(peer),
        Event::UpdateMsg(packet) => fsm_bgp_update(peer, packet),
    };
    println!("State: {:?} -> {:?}", prev_state, peer.state);
    if prev_state != State::Idle && peer.state == State::Idle {
        fsm_stop(peer);
    }
}

pub fn fsm_init(peer: &mut Peer) -> State {
    if !peer.is_passive() {
        peer.timer.idle_hold_timer = Some(peer_start_idle_hold_timer(peer));
    }
    State::Idle
}

pub fn fsm_start(peer: &mut Peer) -> State {
    peer.task.connect = Some(peer_start_connection(peer));
    State::Connect
}

pub fn fsm_stop(peer: &mut Peer) -> State {
    peer.task.writer = None;
    peer.task.reader = None;
    peer.timer.idle_hold_timer = None;
    peer.timer.connect_retry = None;
    peer.timer.keepalive = None;
    peer.timer.hold_timer = None;
    fsm_init(peer);
    State::Idle
}

pub fn fsm_bgp_open(peer: &mut Peer, packet: OpenPacket) -> State {
    peer.counter.rx[usize::from(BgpType::Open)] += 1;
    if peer.state != State::OpenSent {
        println!("peer state mismatch {:?}", peer.state);
        // Send notification.
        return State::Idle;
    }
    if packet.asn as u32 != peer.peer_as {
        // Send notification.
        println!("ASN mismatch");
        return State::Idle;
    }
    if packet.bgp_id != peer.address.octets() {
        // Send notification.
        println!("router-id mismatch {:?}", peer.address);
        return State::Idle;
    }
    peer.timer.keepalive = Some(peer_start_keepalive(peer));
    peer.timer.hold_timer = Some(peer_start_holdtimer(peer));
    State::Established
}

pub fn fsm_bgp_notification(peer: &mut Peer, _packet: NotificationPacket) -> State {
    peer.counter.rx[usize::from(BgpType::Notification)] += 1;
    State::Idle
}

pub fn fsm_bgp_keepalive(peer: &mut Peer) -> State {
    peer.counter.rx[usize::from(BgpType::Keepalive)] += 1;
    peer_refresh_holdtimer(peer);
    State::Established
}

pub fn fsm_bgp_update(peer: &mut Peer, _packet: UpdatePacket) -> State {
    peer.counter.rx[usize::from(BgpType::Update)] += 1;
    peer_refresh_holdtimer(peer);
    State::Established
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

pub fn fsm_conn_retry_expires(peer: &mut Peer) -> State {
    peer.task.connect = Some(peer_start_connection(peer));
    State::Connect
}

pub fn fsm_holdtimer_expires(_peer: &mut Peer) -> State {
    // peer_send_notification(peer);
    State::Idle
}

pub fn fsm_idle_hold_timer_expires(peer: &mut Peer) -> State {
    peer.timer.idle_hold_timer = None;
    peer.task.connect = Some(peer_start_connection(peer));
    State::Connect
}

pub fn fsm_keepalive_expires(peer: &mut Peer) -> State {
    peer_send_keepalive(peer);
    State::Established
}

pub fn fsm_conn_fail(peer: &mut Peer) -> State {
    peer.task.writer = None;
    peer.task.reader = None;
    // peer.timer.connect = Some()
    State::Active
}

pub fn peer_start_idle_hold_timer(peer: &Peer) -> Timer {
    let ident = peer.ident;
    let tx = peer.tx.clone();
    Timer::new(Timer::second(5), TimerType::Once, move || {
        let tx = tx.clone();
        async move {
            let _ = tx.send(Message::Event(ident, Event::Start));
        }
    })
}

pub fn peer_start_connect_timer(peer: &Peer) -> Timer {
    let ident = peer.ident;
    let tx = peer.tx.clone();
    Timer::new(Timer::second(5), TimerType::Once, move || {
        let tx = tx.clone();
        async move {
            let _ = tx.send(Message::Event(ident, Event::Start));
        }
    })
}

pub fn peer_packet_parse(
    rx: &[u8],
    ident: Ipv4Addr,
    tx: UnboundedSender<Message>,
) -> Result<(), &'static str> {
    if let Ok((_, p)) = parse_bgp_packet(rx, false) {
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
        Ok(())
    } else {
        Err("parse error")
    }
}

pub async fn peer_read(
    ident: Ipv4Addr,
    tx: UnboundedSender<Message>,
    mut read_half: OwnedReadHalf,
) {
    let mut buf = BytesMut::with_capacity(BGP_MAX_LEN * 2);
    loop {
        match read_half.read_buf(&mut buf).await {
            Ok(read_len) => {
                if read_len == 0 {
                    let _ = tx.send(Message::Event(ident, Event::ConnFail));
                    return;
                }
                while buf.len() >= BGP_HEADER_LEN as usize
                    && buf.len() >= peek_bgp_length(buf.as_bytes())
                {
                    let length = peek_bgp_length(buf.as_bytes());
                    match peer_packet_parse(buf.as_bytes(), ident, tx.clone()) {
                        Ok(_) => {
                            println!("U: split");
                            buf = buf.split_off(length);
                            buf.reserve(BGP_MAX_LEN);
                        }
                        Err(err) => {
                            println!("E: {}", err);
                            let _ = tx.send(Message::Event(ident, Event::ConnFail));
                            return;
                        }
                    }
                }
            }
            Err(err) => {
                println!("{:?}", err);
                let _ = tx.send(Message::Event(ident, Event::ConnFail));
            }
        }
    }
}

pub fn peer_start_reader(peer: &Peer, read_half: OwnedReadHalf) -> Task<()> {
    let ident = peer.ident;
    let tx = peer.tx.clone();
    Task::spawn(async move {
        peer_read(ident, tx.clone(), read_half).await;
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

pub fn peer_start_connection(peer: &mut Peer) -> Task<()> {
    let ident = peer.ident;
    let tx = peer.tx.clone();
    let address = peer.address;
    Task::spawn(async move {
        let tx = tx.clone();
        let result = TcpStream::connect(address.to_string() + ":179").await;
        match result {
            Ok(stream) => {
                let _ = tx.send(Message::Event(ident, Event::Connected(stream)));
            }
            Err(err) => {
                println!("{:?}", err);
                let _ = tx.send(Message::Event(ident, Event::ConnFail));
            }
        };
    })
}

pub fn peer_send_open(peer: &mut Peer) {
    let header = BgpHeader::new(BgpType::Open, BGP_HEADER_LEN + 10);
    let router_id = if let Some(identifier) = peer.local_identifier {
        identifier
    } else {
        peer.router_id
    };
    let open = OpenPacket::new(header, peer.local_as as u16, &router_id);
    let bytes: BytesMut = open.into();
    let _ = peer.packet_tx.as_ref().unwrap().send(bytes);
    peer.counter.tx[usize::from(BgpType::Open)] += 1;
}

pub fn peer_start_keepalive(peer: &Peer) -> Timer {
    let ident = peer.ident;
    let tx = peer.tx.clone();
    Timer::new(Timer::second(30), TimerType::Infinite, move || {
        let tx = tx.clone();
        async move {
            let _ = tx.send(Message::Event(ident, Event::KeepaliveTimerExpires));
        }
    })
}

pub fn peer_send_keepalive(peer: &mut Peer) {
    let header = BgpHeader::new(BgpType::Keepalive, BGP_HEADER_LEN);
    let bytes: BytesMut = header.into();
    let _ = peer.packet_tx.as_ref().unwrap().send(bytes);
    peer.counter.tx[usize::from(BgpType::Keepalive)] += 1;
}

pub fn peer_start_holdtimer(peer: &Peer) -> Timer {
    let ident = peer.ident;
    let tx = peer.tx.clone();
    Timer::new(Timer::second(180), TimerType::Infinite, move || {
        let tx = tx.clone();
        async move {
            let _ = tx.send(Message::Event(ident, Event::HoldTimerExpires));
        }
    })
}

pub fn peer_refresh_holdtimer(peer: &Peer) {
    if let Some(holdtimer) = peer.timer.hold_timer.as_ref() {
        holdtimer.refresh();
    }
}
