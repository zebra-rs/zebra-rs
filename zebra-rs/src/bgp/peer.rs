#![allow(dead_code)]
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Instant;

use bytes::BytesMut;
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use bgp_packet::*;

use caps::CapAs4;
use caps::CapRefresh;
use caps::CapabilityPacket;

use crate::bgp::cap::cap_register_recv;
use crate::bgp::route::{route_clean, route_sync};
use crate::bgp::timer;
use crate::bgp::{AdjRib, In, Out};
use crate::config::Args;
use crate::context::task::*;
use crate::{bgp_debug, bgp_info, rib};

use super::cap::{CapAfiMap, cap_addpath_recv, cap_register_send};
use super::inst::Message;
use super::route::LocalRib;
use super::route::route_from_peer;
use super::{BGP_PORT, PolicyListValue, PrefixSetValue};
use super::{Bgp, InOuts};

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum State {
    Idle,
    Connect,
    Active,
    OpenSent,
    OpenConfirm,
    Established,
}

impl State {
    pub fn to_str(&self) -> &str {
        match self {
            Self::Idle => "Idle",
            Self::Connect => "Connect",
            Self::Active => "Active",
            Self::OpenSent => "OpenSent",
            Self::OpenConfirm => "OpenConfirm",
            Self::Established => "Established",
        }
    }

    pub fn is_established(&self) -> bool {
        *self == State::Established
    }
}

#[derive(Debug)]
pub enum Event {
    ConfigUpdate,                 // 0
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

#[derive(Debug, Default)]
pub struct PeerTask {
    pub connect: Option<Task<()>>,
    pub reader: Option<Task<()>>,
    pub writer: Option<Task<()>>,
}

#[derive(Debug, Default)]
pub struct PeerTimer {
    pub idle_hold_timer: Option<Timer>,
    pub connect_retry: Option<Timer>,
    pub hold_timer: Option<Timer>,
    pub keepalive: Option<Timer>,
    pub min_as_origin: Option<Timer>,
    pub min_route_adv: Option<Timer>,
}

#[derive(Serialize, Debug, Default, Clone, Copy)]
pub struct PeerCounter {
    pub sent: u64,
    pub rcvd: u64,
}

#[derive(Debug, Default, Clone)]
pub struct PeerTransportConfig {
    pub passive: bool,
}

#[derive(Debug, Clone)]
pub struct PeerConfig {
    pub transport: PeerTransportConfig,
    pub four_octet: bool,
    pub mp: AfiSafis<bool>,
    pub restart: AfiSafis<RestartValue>,
    pub llgr: AfiSafis<LlgrValue>,
    pub addpath: AfiSafis<AddPathValue>,
    pub route_refresh: bool,
    pub timer: timer::Config,
    pub sub: BTreeMap<AfiSafi, PeerSubConfig>,
}

impl Default for PeerConfig {
    fn default() -> Self {
        Self {
            transport: Default::default(),
            four_octet: Default::default(),
            mp: Default::default(),
            restart: AfiSafis::new(),
            llgr: AfiSafis::new(),
            addpath: AfiSafis::new(),
            route_refresh: Default::default(),
            timer: Default::default(),
            sub: Default::default(),
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct PeerSubConfig {
    pub graceful_restart: Option<u32>,
    pub llgr: Option<u32>,
}

#[derive(Debug, Eq, PartialEq)]
pub enum PeerType {
    IBGP,
    EBGP,
}

impl PeerType {
    pub fn is_ibgp(&self) -> bool {
        *self == PeerType::IBGP
    }

    pub fn is_ebgp(&self) -> bool {
        *self == PeerType::EBGP
    }

    pub fn to_str(&self) -> &'static str {
        match self {
            Self::IBGP => "internal",
            Self::EBGP => "external",
        }
    }
}

#[derive(Debug, Default, Serialize, Clone)]
pub struct PeerParam {
    pub hold_time: u16,
    pub keepalive: u16,
    pub local_addr: Option<SocketAddr>,
}

#[derive(Debug, Default)]
pub struct PeerStatEntry {
    tx: u64,
    rx: u64,
}

#[derive(Debug, Default)]
pub struct PeerStat(BTreeMap<AfiSafi, PeerStatEntry>);

impl PeerStat {
    pub fn clear(&mut self) {
        for (_, entry) in self.0.iter_mut() {
            entry.tx = 0;
            entry.rx = 0;
        }
    }

    pub fn rx(&self, afi: Afi, safi: Safi) -> u64 {
        let afi_safi = AfiSafi::new(afi, safi);
        if let Some(entry) = self.0.get(&afi_safi) {
            entry.rx
        } else {
            0
        }
    }

    pub fn tx(&self, afi: Afi, safi: Safi) -> u64 {
        let afi_safi = AfiSafi::new(afi, safi);
        if let Some(entry) = self.0.get(&afi_safi) {
            entry.tx
        } else {
            0
        }
    }

    pub fn rx_inc(&mut self, afi: Afi, safi: Safi) {
        let afi_safi = AfiSafi::new(afi, safi);
        let entry = self.0.entry(afi_safi).or_default();
        entry.rx += 1;
    }

    pub fn rx_dec(&mut self, afi: Afi, safi: Safi) {
        let afi_safi = AfiSafi::new(afi, safi);
        if let Some(entry) = self.0.get_mut(&afi_safi) {
            entry.rx -= 1;
        }
    }

    pub fn tx_inc(&mut self, afi: Afi, safi: Safi) {
        let afi_safi = AfiSafi::new(afi, safi);
        let entry = self.0.entry(afi_safi).or_default();
        entry.tx += 1;
    }

    pub fn tx_dec(&mut self, afi: Afi, safi: Safi) {
        let afi_safi = AfiSafi::new(afi, safi);
        if let Some(entry) = self.0.get_mut(&afi_safi) {
            entry.tx -= 1;
        }
    }
}

#[derive(Debug)]
pub struct Peer {
    pub ident: IpAddr,
    pub address: IpAddr,
    pub router_id: Ipv4Addr,
    pub local_identifier: Option<Ipv4Addr>,
    pub remote_id: Ipv4Addr,
    pub local_as: u32,
    pub peer_as: u32,
    pub active: bool,
    pub peer_type: PeerType,
    pub state: State,
    pub task: PeerTask,
    pub timer: PeerTimer,
    pub counter: [PeerCounter; BgpType::Max as usize],
    pub as4: bool,
    pub param: PeerParam,
    pub param_tx: PeerParam,
    pub param_rx: PeerParam,
    pub packet_tx: Option<UnboundedSender<BytesMut>>,
    pub tx: UnboundedSender<Message>,
    pub config: PeerConfig,
    pub cap_send: BgpCap,
    pub cap_recv: BgpCap,
    pub cap_map: CapAfiMap,
    pub adj_in: AdjRib<In>,
    pub adj_out: AdjRib<Out>,
    pub opt: ParseOption,
    pub policy_list: InOuts<PolicyListValue>,
    pub prefix_set: InOuts<PrefixSetValue>,
    pub rtcv4: BTreeSet<ExtCommunityValue>,
    pub eor: BTreeMap<AfiSafi, bool>,
    pub reflector_client: bool,
    pub instant: Option<Instant>,
}

impl Peer {
    pub fn new(
        ident: IpAddr,
        local_as: u32,
        router_id: Ipv4Addr,
        peer_as: u32,
        address: IpAddr,
        tx: UnboundedSender<Message>,
    ) -> Self {
        let mut peer = Self {
            ident,
            router_id,
            local_as,
            peer_as,
            address,
            active: false,
            peer_type: PeerType::IBGP,
            state: State::Idle,
            task: PeerTask::default(),
            timer: PeerTimer::default(),
            counter: [PeerCounter::default(); BgpType::Max as usize],
            tx,
            remote_id: Ipv4Addr::UNSPECIFIED,
            local_identifier: None,
            config: PeerConfig::default(),
            as4: true,
            param: PeerParam::default(),
            param_tx: PeerParam::default(),
            param_rx: PeerParam::default(),
            // stat: PeerStat::default(),
            packet_tx: None,
            cap_send: BgpCap::default(),
            cap_recv: BgpCap::default(),
            cap_map: CapAfiMap::new(),
            adj_in: AdjRib::new(),
            adj_out: AdjRib::new(),
            opt: ParseOption::default(),
            policy_list: InOuts::<PolicyListValue>::default(),
            prefix_set: InOuts::<PrefixSetValue>::default(),
            rtcv4: BTreeSet::default(),
            eor: BTreeMap::default(),
            reflector_client: false,
            instant: None,
        };
        peer.config
            .mp
            .set(AfiSafi::new(Afi::Ip, Safi::Unicast), true);
        peer.config.four_octet = true;
        peer.config.route_refresh = true;
        // peer.config.graceful_restart = Some(65535);
        peer
    }

    pub fn event(&self, ident: IpAddr, event: Event) {
        let _ = self.tx.clone().send(Message::Event(ident, event));
    }

    pub fn is_passive(&self) -> bool {
        self.config.transport.passive
    }

    pub fn start(&mut self) {
        if self.peer_as != 0 && !self.address.is_unspecified() && !self.active {
            timer::update_timers(self);
            self.active = true;
        }
    }

    pub fn count_clear(&mut self) {
        for count in self.counter.iter_mut() {
            count.sent = 0;
            count.rcvd = 0;
        }
    }

    pub fn is_ebgp(&self) -> bool {
        self.peer_type.is_ebgp()
    }

    pub fn is_ibgp(&self) -> bool {
        self.peer_type.is_ibgp()
    }

    pub fn is_reflector_client(&self) -> bool {
        self.reflector_client
    }

    pub fn is_afi_safi(&self, afi: Afi, safi: Safi) -> bool {
        let afi = CapMultiProtocol::new(&afi, &safi);
        if let Some(cap) = self.cap_map.entries.get(&afi) {
            if cap.send && cap.recv {
                return true;
            }
        }
        false
    }
}

pub struct ConfigRef<'a> {
    pub router_id: &'a Ipv4Addr,
    pub local_rib: &'a mut LocalRib,
    pub rib_tx: &'a UnboundedSender<rib::Message>,
}

pub fn fsm(bgp: &mut Bgp, id: IpAddr, event: Event) {
    // Handle UpdateMsg separately to avoid borrow checker issues
    if let Event::UpdateMsg(packet) = event {
        let mut bgp_ref = ConfigRef {
            router_id: &bgp.router_id,
            local_rib: &mut bgp.local_rib,
            rib_tx: &bgp.rib_tx,
        };

        // Take ownership temporarily to avoid double borrow
        let mut peer_map = std::mem::take(&mut bgp.peers);
        let prev_state = peer_map.get(&id).unwrap().state.clone();
        let new_state = fsm_bgp_update(id, packet, &mut bgp_ref, &mut peer_map);
        if prev_state.is_established() && !new_state.is_established() {
            route_clean(id, &mut bgp_ref, &mut peer_map, false);
        }
        peer_map.get_mut(&id).unwrap().state = new_state.clone();

        // Put the peers back
        bgp.peers = peer_map;

        if prev_state == new_state {
            return;
        }
        // bgp_info!("FSM: {:?} -> {:?}", prev_state, new_state);

        let peer = bgp.peers.get_mut(&id).unwrap();
        if prev_state.is_established() && !peer.state.is_established() {
            peer.instant = Some(Instant::now());
        }

        if !prev_state.is_established() && peer.state.is_established() {
            peer.instant = Some(Instant::now());
            route_sync(peer, &mut bgp_ref);
        }

        timer::update_timers(peer);
        return;
    }

    // Handle other events normally
    let mut bgp_ref = ConfigRef {
        router_id: &bgp.router_id,
        local_rib: &mut bgp.local_rib,
        rib_tx: &bgp.rib_tx,
    };
    let mut need_clean = false;
    {
        let peer = bgp.peers.get_mut(&id).unwrap();
        let prev_state = peer.state.clone();
        peer.state = match event {
            Event::ConfigUpdate => fsm_config_update(&bgp_ref, peer),
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
            Event::UpdateMsg(_) => unreachable!(), // Handled above
        };
        if prev_state == peer.state {
            return;
        }
        // bgp_info!("FSM: {:?} -> {:?}", prev_state, peer.state);

        if prev_state.is_established() && !peer.state.is_established() {
            peer.instant = Some(Instant::now());
            need_clean = true;
        }

        // Update instant when entering or leaving the Established state.
        if !prev_state.is_established() && peer.state.is_established() {
            peer.instant = Some(Instant::now());
            route_sync(peer, &mut bgp_ref);
        }

        timer::update_timers(peer);
    }

    let mut peer_map = std::mem::take(&mut bgp.peers);
    if need_clean {
        route_clean(id, &mut bgp_ref, &mut peer_map, false);
    }
    bgp.peers = peer_map;
}

pub fn fsm_start(peer: &mut Peer) -> State {
    peer.task.connect = Some(peer_start_connection(peer));
    State::Connect
}

pub fn fsm_stop(_peer: &mut Peer) -> State {
    State::Idle
}

fn fsm_config_update(bgp: &ConfigRef, peer: &mut Peer) -> State {
    bgp_debug!("BGP router ID: {}", bgp.router_id);
    peer.state.clone()
}

pub fn capability_as4(caps: &[CapabilityPacket]) -> Option<u32> {
    for cap in caps.iter() {
        if let CapabilityPacket::As4(m) = cap {
            return Some(m.asn);
        }
    }
    None
}

pub fn open_asn(packet: &OpenPacket) -> u32 {
    if let Some(as4) = &packet.bgp_cap.as4 {
        as4.asn
    } else {
        packet.asn as u32
    }
}

pub fn fsm_bgp_open(peer: &mut Peer, packet: OpenPacket) -> State {
    peer.counter[BgpType::Open as usize].rcvd += 1;

    // Peer ASN.
    let asn = open_asn(&packet);

    // Compare with configured asn.
    if peer.peer_as != asn {
        peer_send_notification(
            peer,
            NotifyCode::OpenMsgError,
            OpenError::BadPeerAS.into(),
            Vec::new(),
        );
        return State::Idle;
    }

    if peer.state != State::OpenSent {
        // Send notification.
        return State::Idle;
    }
    if packet.asn as u32 != peer.peer_as {
        // Send notification.
        return State::Idle;
    }
    // TODO: correct router-id validation.
    // if packet.bgp_id != peer.address.octets() {
    //     // Send notification.
    //     println!("router-id mismatch {:?}", peer.address);
    //     return State::Idle;
    // }
    if packet.hold_time > 0 && packet.hold_time < 3 {
        return State::Idle;
    }
    peer.remote_id = Ipv4Addr::new(
        packet.bgp_id[0],
        packet.bgp_id[1],
        packet.bgp_id[2],
        packet.bgp_id[3],
    );

    timer::update_open_timers(peer, &packet);

    // Register recv caps.
    cap_register_recv(&packet.bgp_cap, &mut peer.cap_map);

    // Register add path caps.
    cap_addpath_recv(&packet.bgp_cap, &mut peer.opt, &peer.config.addpath);

    // Register graceful restart.
    peer.cap_recv = packet.bgp_cap;

    State::Established
}

pub fn fsm_bgp_notification(peer: &mut Peer, _packet: NotificationPacket) -> State {
    peer.counter[BgpType::Notification as usize].rcvd += 1;
    State::Idle
}

pub fn fsm_bgp_keepalive(peer: &mut Peer) -> State {
    peer.counter[BgpType::Keepalive as usize].rcvd += 1;
    timer::refresh_hold_timer(peer);
    State::Established
}

fn fsm_bgp_update(
    peer_id: IpAddr,
    packet: UpdatePacket,
    bgp: &mut ConfigRef,
    peers: &mut BTreeMap<IpAddr, Peer>,
) -> State {
    {
        let peer = peers.get_mut(&peer_id).unwrap();
        peer.counter[BgpType::Update as usize].rcvd += 1;
        timer::refresh_hold_timer(peer);
    }

    route_from_peer(peer_id, packet, bgp, peers);

    State::Established
}

pub fn fsm_connected(peer: &mut Peer, stream: TcpStream) -> State {
    if let Ok(local_addr) = stream.local_addr() {
        peer.param.local_addr = Some(local_addr);
    }
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

pub fn fsm_holdtimer_expires(peer: &mut Peer) -> State {
    peer_send_notification(peer, NotifyCode::HoldTimerExpired, 0, Vec::new());
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
    peer.timer.connect_retry = Some(timer::start_connect_retry_timer(peer));
    State::Active
}

pub fn peer_packet_parse(
    rx: &[u8],
    ident: IpAddr,
    tx: UnboundedSender<Message>,
    config: &mut PeerConfig,
    opt: &mut ParseOption,
) -> Result<(), String> {
    match BgpPacket::parse_packet(rx, true, Some(opt.clone())) {
        Ok((_, p)) => {
            match p {
                BgpPacket::Open(p) => {
                    // config.cap_recv = p.bgp_cap.clone();
                    cap_addpath_recv(&p.bgp_cap, opt, &config.addpath);
                    let _ = tx.send(Message::Event(ident, Event::BGPOpen(*p)));
                }
                BgpPacket::Keepalive(_) => {
                    let _ = tx.send(Message::Event(ident, Event::KeepAliveMsg));
                }
                BgpPacket::Notification(p) => {
                    let _ = tx.send(Message::Event(ident, Event::NotifMsg(p)));
                }
                BgpPacket::Update(p) => {
                    let _ = tx.send(Message::Event(ident, Event::UpdateMsg(*p)));
                }
            }
            Ok(())
        }
        Err(e) => Err(e.to_string()),
    }
}

pub async fn peer_read(
    ident: IpAddr,
    tx: UnboundedSender<Message>,
    mut read_half: OwnedReadHalf,
    mut config: PeerConfig,
    mut opt: ParseOption,
) {
    let mut buf = BytesMut::with_capacity(BGP_PACKET_LEN * 2);
    loop {
        match read_half.read_buf(&mut buf).await {
            Ok(read_len) => {
                if read_len == 0 {
                    let _ = tx.send(Message::Event(ident, Event::ConnFail));
                    return;
                }
                while buf.len() >= BGP_HEADER_LEN as usize && buf.len() >= peek_bgp_length(&buf) {
                    let length = peek_bgp_length(&buf);

                    let mut remain = buf.split_off(length);
                    remain.reserve(BGP_PACKET_LEN * 2);

                    match peer_packet_parse(&buf, ident, tx.clone(), &mut config, &mut opt) {
                        Ok(_) => {
                            buf = remain;
                        }
                        Err(err) => {
                            let _ = tx.send(Message::Event(ident, Event::ConnFail));
                            return;
                        }
                    }
                }
            }
            Err(err) => {
                let _ = tx.send(Message::Event(ident, Event::ConnFail));
            }
        }
    }
}

pub fn peer_start_reader(peer: &Peer, read_half: OwnedReadHalf) -> Task<()> {
    let ident = peer.ident;
    let tx = peer.tx.clone();
    let config = peer.config.clone();
    let opt = peer.opt.clone();
    Task::spawn(async move {
        peer_read(ident, tx.clone(), read_half, config, opt).await;
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
        let addr = match address {
            IpAddr::V4(addr) => format!("{}:{}", addr, BGP_PORT),
            IpAddr::V6(addr) => format!("[{}]:{}", addr, BGP_PORT),
        };
        let result = TcpStream::connect(addr).await;
        match result {
            Ok(stream) => {
                let _ = tx.send(Message::Event(ident, Event::Connected(stream)));
            }
            Err(err) => {
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
    let mut bgp_cap = BgpCap::default();

    for (afi_safi, _) in peer.config.mp.0.iter() {
        let cap = CapMultiProtocol::new(&afi_safi.afi, &afi_safi.safi);
        bgp_cap.mp.insert(afi_safi.clone(), cap);
    }
    if peer.config.four_octet {
        let cap = CapAs4::new(peer.local_as);
        bgp_cap.as4 = Some(cap);
    }
    if peer.config.route_refresh {
        let cap = CapRefresh::default();
        bgp_cap.refresh = Some(cap);
    }
    for (key, addpath) in peer.config.addpath.iter() {
        bgp_cap.addpath.insert(key.clone(), addpath.clone());
    }
    for (key, sub) in peer.config.sub.iter() {
        if let Some(_restart_time) = sub.graceful_restart {
            let restart = RestartValue::new(1, key.afi, key.safi);
            bgp_cap.restart.insert(key.clone(), restart);
        }
        if let Some(llgr_time) = sub.llgr {
            let llgr = LlgrValue::new(key.afi, key.safi, llgr_time);
            bgp_cap.llgr.insert(key.clone(), llgr);
        }
    }

    cap_register_send(&bgp_cap, &mut peer.cap_map);
    peer.cap_send = bgp_cap.clone();

    // Remmeber sent hold time.
    let hold_time = peer.config.timer.hold_time() as u16;
    peer.param_tx.hold_time = hold_time;
    peer.param_tx.keepalive = hold_time / 3;

    let open = OpenPacket::new(header, peer.local_as as u16, hold_time, &router_id, bgp_cap);
    let bytes: BytesMut = open.into();
    peer.counter[BgpType::Open as usize].sent += 1;
    let _ = peer.packet_tx.as_ref().unwrap().send(bytes);
}

pub fn peer_send_notification(peer: &mut Peer, code: NotifyCode, sub_code: u8, data: Vec<u8>) {
    let notification = NotificationPacket::new(code, sub_code, data);
    let bytes: BytesMut = notification.into();
    peer.counter[BgpType::Notification as usize].sent += 1;
    let _ = peer.packet_tx.as_ref().unwrap().send(bytes);
}

pub fn peer_send_keepalive(peer: &mut Peer) {
    let header = BgpHeader::new(BgpType::Keepalive, BGP_HEADER_LEN);
    let bytes: BytesMut = header.into();
    peer.counter[BgpType::Keepalive as usize].sent += 1;
    let _ = peer.packet_tx.as_ref().unwrap().send(bytes);
}

/// Handle incoming connection for a peer based on current BGP state
fn handle_peer_connection(
    bgp: &mut Bgp,
    peer_addr: IpAddr,
    stream: TcpStream,
) -> Option<TcpStream> {
    if let Some(peer) = bgp.peers.get_mut(&peer_addr) {
        match peer.state {
            State::Idle => {
                // bgp_info!("Idle state, rejecting remote connection from {}", peer_addr);
                None
            }
            State::Connect => {
                // Cancel connect task.
                //bgp_info!("Connect state, cancel connection then accept {}", peer_addr);
                peer.task.connect = None;
                peer.state = fsm_connected(peer, stream);
                None
            }
            State::Active => {
                peer.state = fsm_connected(peer, stream);
                None
            }
            State::OpenSent => {
                // In case of OpenSent. We need to keep the session until we
                // receives Open.
                Some(stream)
            }
            State::OpenConfirm => {
                // In case of OpenConfirm keep current session.
                None
            }
            State::Established => {
                // bgp_info!(
                //     "Established state, rejecting remote connection from {}",
                //     peer_addr
                // );
                None
            }
        }
    } else {
        Some(stream)
    }
}

pub fn accept(bgp: &mut Bgp, stream: TcpStream, sockaddr: SocketAddr) {
    let remaining_stream = match sockaddr {
        SocketAddr::V4(addr) => {
            let peer_addr = IpAddr::V4(*addr.ip());
            handle_peer_connection(bgp, peer_addr, stream)
        }
        SocketAddr::V6(addr) => {
            let peer_addr = IpAddr::V6(*addr.ip());
            handle_peer_connection(bgp, peer_addr, stream)
        }
    };

    // Next, lookup peer-group for dynamic peer.
    if let Some(_stream) = remaining_stream {
        // TODO: Handle dynamic peer lookup
    }
}

pub fn clear(bgp: &Bgp, args: &mut Args) -> std::result::Result<String, std::fmt::Error> {
    let Some(addr) = args.addr() else {
        return Ok("peer not found".to_string());
    };

    let Some(peer) = bgp.peers.get(&addr) else {
        return Ok("peer not found".to_string());
    };

    let _ = bgp.tx.send(Message::Event(peer.ident, Event::Stop));
    Ok(format!("%% peer {} is cleared", addr))
}
