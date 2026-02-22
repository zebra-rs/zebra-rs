#![allow(dead_code)]
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
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
use crate::bgp::{AdjRib, In, Out};
use crate::bgp::{stale_route_withdraw, timer};
use crate::config::Args;
use crate::context::task::*;
use crate::rib;

use super::cap::{CapAfiMap, cap_addpath_recv, cap_register_send};
use super::inst::Message;
use super::route::LocalRib;
use super::route::route_from_peer;
use super::{BGP_PORT, PolicyListValue, PrefixSetValue};
use super::{Bgp, BgpAttrStore, InOuts};

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
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
    StaleTimerExipires(AfiSafi),
    AdvTimerIpv4Expires,
    AdvTimerVpnv4Expires,
}

pub enum FsmEffect {
    None,
    RouteUpdate(UpdatePacket),
    StaleExpire(AfiSafi),
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
    pub stale_timer: BTreeMap<AfiSafi, Timer>,
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
    pub idx: usize,
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
    pub tx: mpsc::Sender<Message>,
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
    pub first_start: bool,
    pub cache_ipv4: HashMap<Arc<BgpAttr>, HashSet<Ipv4Nlri>>,
    pub cache_ipv4_rev: HashMap<Ipv4Nlri, Arc<BgpAttr>>,
    pub cache_vpnv4: HashMap<Arc<BgpAttr>, HashSet<Vpnv4Nlri>>,
    pub cache_vpnv4_rev: HashMap<Vpnv4Nlri, Arc<BgpAttr>>,
    pub cache_ipv4_timer: Option<Timer>,
    pub cache_vpnv4_timer: Option<Timer>,
}

impl Peer {
    pub fn new(
        ident: IpAddr,
        idx: usize,
        local_as: u32,
        router_id: Ipv4Addr,
        peer_as: u32,
        address: IpAddr,
        tx: mpsc::Sender<Message>,
    ) -> Self {
        let mut peer = Self {
            ident,
            idx,
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
            first_start: true,
            cache_ipv4: HashMap::default(),
            cache_ipv4_rev: HashMap::default(),
            cache_vpnv4: HashMap::default(),
            cache_vpnv4_rev: HashMap::default(),
            cache_ipv4_timer: None,
            cache_vpnv4_timer: None,
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

pub struct BgpTop<'a> {
    pub router_id: &'a Ipv4Addr,
    pub local_rib: &'a mut LocalRib,
    pub tx: &'a mpsc::Sender<Message>,
    pub rib_tx: &'a UnboundedSender<rib::Message>,
    pub attr_store: &'a mut BgpAttrStore,
}

pub fn fsm_next_state(peer: &mut Peer, event: Event) -> (State, FsmEffect) {
    match event {
        Event::ConfigUpdate => (peer.state, FsmEffect::None),
        Event::Start => (fsm_start(peer), FsmEffect::None),
        Event::Stop => (fsm_stop(peer), FsmEffect::None),
        Event::ConnRetryTimerExpires => (fsm_conn_retry_expires(peer), FsmEffect::None),
        Event::HoldTimerExpires => (fsm_holdtimer_expires(peer), FsmEffect::None),
        Event::KeepaliveTimerExpires => (fsm_keepalive_expires(peer), FsmEffect::None),
        Event::IdleHoldTimerExpires => (fsm_idle_hold_timer_expires(peer), FsmEffect::None),
        Event::Connected(stream) => (fsm_connected(peer, stream), FsmEffect::None),
        Event::ConnFail => (fsm_conn_fail(peer), FsmEffect::None),
        Event::BGPOpen(packet) => (fsm_bgp_open(peer, packet), FsmEffect::None),
        Event::NotifMsg(packet) => (fsm_bgp_notification(peer, packet), FsmEffect::None),
        Event::KeepAliveMsg => (fsm_bgp_keepalive(peer), FsmEffect::None),
        Event::UpdateMsg(packet) => {
            peer.counter[BgpType::Update as usize].rcvd += 1;
            timer::refresh_hold_timer(peer);
            (State::Established, FsmEffect::RouteUpdate(packet))
        }
        Event::StaleTimerExipires(afi_safi) => {
            peer.timer.stale_timer.remove(&afi_safi);
            (peer.state, FsmEffect::StaleExpire(afi_safi))
        }
        Event::AdvTimerIpv4Expires => (fsm_adv_timer_ipv4_expires(peer), FsmEffect::None),
        Event::AdvTimerVpnv4Expires => (fsm_adv_timer_vpnv4_expires(peer), FsmEffect::None),
    }
}

fn fsm_effect(id: IpAddr, effect: FsmEffect, bgp: &mut BgpTop, peers: &mut BTreeMap<IpAddr, Peer>) {
    match effect {
        FsmEffect::None => {}
        FsmEffect::RouteUpdate(packet) => {
            route_from_peer(id, packet, bgp, peers);
        }
        FsmEffect::StaleExpire(_afi_safi) => {
            stale_route_withdraw(id, bgp, peers);
        }
    }
}

pub fn fsm(bgp_ref: &mut BgpTop, peer_map: &mut BTreeMap<IpAddr, Peer>, id: IpAddr, event: Event) {
    // Phase 1: Compute new state (single match, only &mut Peer)
    let (prev_state, effect) = {
        let peer = peer_map.get_mut(&id).unwrap();
        let prev_state = peer.state;
        let (new_state, effect) = fsm_next_state(peer, event);
        peer.state = new_state;
        (prev_state, effect)
    };

    // Phase 2: Execute side effects that need peer_map
    fsm_effect(id, effect, bgp_ref, peer_map);

    // Phase 3: Handle state transition consequences
    {
        let peer = peer_map.get_mut(&id).unwrap();
        if prev_state == peer.state {
            return;
        }
        if prev_state.is_established() && !peer.state.is_established() {
            peer.instant = Some(Instant::now());
        }
        if !prev_state.is_established() && peer.state.is_established() {
            peer.instant = Some(Instant::now());
            route_sync(peer, bgp_ref);
        }
        timer::update_timers(peer);
    }

    // Phase 4: route_clean if leaving Established (needs peer_map)
    if prev_state.is_established() && !peer_map.get(&id).unwrap().state.is_established() {
        route_clean(id, bgp_ref, peer_map, false);
    }
}

pub fn fsm_adv_timer_ipv4_expires(peer: &mut Peer) -> State {
    peer.cache_ipv4_timer = None;
    peer.flush_ipv4();
    State::Established
}

pub fn fsm_adv_timer_vpnv4_expires(peer: &mut Peer) -> State {
    peer.cache_vpnv4_timer = None;
    peer.flush_vpnv4();
    State::Established
}

pub fn fsm_start(peer: &mut Peer) -> State {
    peer.first_start = false;
    peer.task.connect = Some(peer_start_connection(peer));
    State::Connect
}

pub fn fsm_stop(_peer: &mut Peer) -> State {
    State::Idle
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
    // tracing::info!("Send keepalive {}", peer.ident);
    peer_send_keepalive(peer);
    State::Established
}

pub fn fsm_conn_fail(peer: &mut Peer) -> State {
    peer.task.writer = None;
    peer.task.reader = None;
    peer.packet_tx = None;
    peer.timer.connect_retry = Some(timer::start_connect_retry_timer(peer));
    State::Active
}

pub async fn peer_packet_parse(
    rx: &[u8],
    ident: IpAddr,
    tx: mpsc::Sender<Message>,
    config: &mut PeerConfig,
    opt: &mut ParseOption,
) -> Result<(), String> {
    match BgpPacket::parse_packet(rx, true, Some(opt.clone())) {
        Ok((_, p)) => {
            match p {
                BgpPacket::Open(p) => {
                    // config.cap_recv = p.bgp_cap.clone();
                    cap_addpath_recv(&p.bgp_cap, opt, &config.addpath);
                    let _ = tx.send(Message::Event(ident, Event::BGPOpen(*p))).await;
                }
                BgpPacket::Keepalive(_) => {
                    // tracing::info!("Recv keepavlie {}", ident);
                    let _ = tx.send(Message::Event(ident, Event::KeepAliveMsg)).await;
                }
                BgpPacket::Notification(p) => {
                    // tracing::info!("{p}");
                    let _ = tx.send(Message::Event(ident, Event::NotifMsg(p))).await;
                }
                BgpPacket::Update(p) => {
                    let _ = tx.send(Message::Event(ident, Event::UpdateMsg(*p))).await;
                }
            }
            Ok(())
        }
        Err(e) => Err(e.to_string()),
    }
}

pub async fn peer_read(
    ident: IpAddr,
    tx: mpsc::Sender<Message>,
    mut read_half: OwnedReadHalf,
    mut config: PeerConfig,
    mut opt: ParseOption,
) {
    let mut buf = BytesMut::with_capacity(BGP_PACKET_LEN * 2);
    loop {
        match read_half.read_buf(&mut buf).await {
            Ok(read_len) => {
                if read_len == 0 {
                    let _ = tx.try_send(Message::Event(ident, Event::ConnFail));
                    return;
                }
                while buf.len() >= BGP_HEADER_LEN as usize && buf.len() >= peek_bgp_length(&buf) {
                    let length = peek_bgp_length(&buf);

                    let mut remain = buf.split_off(length);
                    remain.reserve(BGP_PACKET_LEN * 2);

                    match peer_packet_parse(&buf, ident, tx.clone(), &mut config, &mut opt).await {
                        Ok(_) => {
                            buf = remain;
                        }
                        Err(err) => {
                            let _ = tx.try_send(Message::Event(ident, Event::ConnFail));
                            return;
                        }
                    }
                }
            }
            Err(err) => {
                let _ = tx.send(Message::Event(ident, Event::ConnFail)).await;
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
                //
                let _ = tx.try_send(Message::Event(ident, Event::Connected(stream)));
            }
            Err(err) => {
                let _ = tx.try_send(Message::Event(ident, Event::ConnFail));
            }
        };
    })
}

pub fn peer_send_open(peer: &mut Peer) {
    let Some(packet_tx) = peer.packet_tx.as_ref() else {
        return;
    };
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

    // Remember sent hold time.
    let hold_time = peer.config.timer.hold_time() as u16;
    peer.param_tx.hold_time = hold_time;
    peer.param_tx.keepalive = hold_time / 3;

    let open = OpenPacket::new(header, peer.local_as as u16, hold_time, &router_id, bgp_cap);
    let bytes: BytesMut = open.into();
    peer.counter[BgpType::Open as usize].sent += 1;
    let _ = packet_tx.send(bytes);
}

pub fn peer_send_notification(peer: &mut Peer, code: NotifyCode, sub_code: u8, data: Vec<u8>) {
    let Some(packet_tx) = peer.packet_tx.as_ref() else {
        return;
    };
    let notification = NotificationPacket::new(code, sub_code, data);
    let bytes: BytesMut = notification.into();
    peer.counter[BgpType::Notification as usize].sent += 1;
    let _ = packet_tx.send(bytes);
}

pub fn peer_send_keepalive(peer: &mut Peer) {
    let Some(packet_tx) = peer.packet_tx.as_ref() else {
        return;
    };
    let header = BgpHeader::new(BgpType::Keepalive, BGP_HEADER_LEN);
    let bytes: BytesMut = header.into();
    peer.counter[BgpType::Keepalive as usize].sent += 1;
    let _ = packet_tx.send(bytes);
}

/// Reject a connection by sending a NOTIFICATION and closing the socket.
/// Spawns an async task with a timeout to prevent FD exhaustion.
fn reject_connection(stream: TcpStream, code: NotifyCode, sub_code: u8) {
    use std::time::Duration;
    use tokio::time::timeout;

    tokio::spawn(async move {
        let notification = NotificationPacket::new(code, sub_code, Vec::new());
        let bytes: BytesMut = notification.into();
        let mut stream = stream;
        // Use a short timeout to prevent FD exhaustion from slow/unresponsive peers
        let _ = timeout(Duration::from_secs(5), async {
            let _ = stream.write_all(&bytes).await;
            let _ = stream.shutdown().await;
        })
        .await;
        // Stream is dropped here, closing the socket regardless of timeout
    });
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
                // No session established yet - just drop (sends TCP RST/FIN)
                drop(stream);
                None
            }
            State::Connect => {
                // Cancel connect task.
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
                // receive Open for collision detection (RFC 4271).
                Some(stream)
            }
            State::OpenConfirm => {
                // Already in OpenConfirm with another connection - send NOTIFICATION.
                reject_connection(stream, NotifyCode::Cease, 7); // ConnectionCollisionResolution
                None
            }
            State::Established => {
                // Session already established - send NOTIFICATION.
                reject_connection(stream, NotifyCode::Cease, 5); // ConnectionRejected
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
    if let Some(stream) = remaining_stream {
        // No configured peer found - just drop (sends TCP RST/FIN)
        drop(stream);
    }
}

pub fn clear(bgp: &Bgp, args: &mut Args) -> std::result::Result<String, std::fmt::Error> {
    let Some(addr) = args.addr() else {
        return Ok("peer not found".to_string());
    };

    let Some(peer) = bgp.peers.get(&addr) else {
        return Ok("peer not found".to_string());
    };

    match bgp.tx.try_send(Message::Event(peer.ident, Event::Stop)) {
        Ok(()) => Ok(format!("%% peer {} is cleared", addr)),
        Err(e) => Ok(format!("%% failed to clear peer {}: {}", addr, e)),
    }
}

pub fn clear_keepalive(bgp: &Bgp, args: &mut Args) -> std::result::Result<String, std::fmt::Error> {
    let Some(addr) = args.addr() else {
        return Ok("peer not found".to_string());
    };

    let Some(peer) = bgp.peers.get(&addr) else {
        return Ok("peer not found".to_string());
    };

    match bgp
        .tx
        .try_send(Message::Event(peer.ident, Event::KeepaliveTimerExpires))
    {
        Ok(()) => Ok(format!("%% peer {} keepalive expire event is sent", addr)),
        Err(e) => Ok(format!(
            "%% failed to send keepalive event for {}: {}",
            addr, e
        )),
    }
}

pub fn clear_keepalive_recv(
    bgp: &Bgp,
    args: &mut Args,
) -> std::result::Result<String, std::fmt::Error> {
    let Some(addr) = args.addr() else {
        return Ok("peer not found".to_string());
    };

    let Some(peer) = bgp.peers.get(&addr) else {
        return Ok("peer not found".to_string());
    };

    match bgp
        .tx
        .try_send(Message::Event(peer.ident, Event::KeepAliveMsg))
    {
        Ok(()) => Ok(format!("%% peer {} keepalive recv event is sent", addr)),
        Err(e) => Ok(format!(
            "%% failed to send keepalive recv event for {}: {}",
            addr, e
        )),
    }
}
