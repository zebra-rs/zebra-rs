#![allow(dead_code)]
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use bytes::BytesMut;
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpSocket, TcpStream};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use bgp_packet::*;

use super::peer_map::PeerMap;

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
    pub fn to_str(self) -> &'static str {
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
    // RFC 2918 Route Refresh receive. Carries the AFI/SAFI from the
    // wire (raw u16/u8) so unknown-AF refreshes still dispatch
    // through the FSM rather than tearing the session down.
    RouteRefreshMsg(u16, u8),
    StaleTimerExipires(AfiSafi),
    AdvTimerIpv4Expires,
    AdvTimerVpnv4Expires,
    AdvTimerEvpnExpires,
}

pub enum FsmEffect {
    None,
    RouteUpdate(UpdatePacket),
    StaleExpire(AfiSafi),
    // Peer asked us to re-send the Adj-RIB-Out for an AFI/SAFI
    // (RFC 2918). The current implementation re-runs the full
    // soft-out replay across every negotiated AFI/SAFI rather than
    // narrowing to the requested one — over-eager but correct, and
    // simpler than threading AFI/SAFI through the route layer. The
    // (afi, safi) pair is kept in the variant so a future revision
    // can do the targeted version without an FSM change.
    RouteRefreshRecv { afi: u16, safi: u8 },
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

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum PasswordEncoding {
    #[default]
    Clear,
    Encrypted,
}

#[derive(Debug, Default, Clone)]
pub struct PeerTransportConfig {
    pub passive: bool,
    pub update_source: Option<IpAddr>,
    // TCP MD5 (RFC 2385) shared secret. When Some, installed on the
    // listening socket (for the peer's address) and on the active
    // TcpSocket before connect(). The encoding determines how the
    // bytes are interpreted when the kernel key is derived. See
    // zebra-bgp-auth.yang `tcp-md5`.
    pub md5_password: Option<String>,
    pub md5_encoding: PasswordEncoding,
    // TCP-AO (RFC 5925 / RFC 5926) configuration. When Some, the key
    // chain is resolved at connect/listen time and installed via
    // TCP_AO_ADD_KEY. MD5 and AO are mutually exclusive per session;
    // enforcement is at commit.
    pub ao_config: Option<super::auth::AoConfig>,
    // Resolved AO key selected from `ao_config`'s referenced chain.
    // Recomputed whenever ao_config or the chain changes; the active
    // side in peer_connect applies it directly.
    pub resolved_ao_key: Option<super::auth::ResolvedAoKey>,
}

#[derive(Debug, Clone)]
pub struct PeerConfig {
    pub transport: PeerTransportConfig,
    pub four_octet: bool,
    pub extended_message: bool,
    pub mp: AfiSafis<bool>,
    pub restart: AfiSafis<RestartValue>,
    pub llgr: AfiSafis<LlgrValue>,
    pub addpath: AfiSafis<AddPathValue>,
    pub route_refresh: bool,
    // When true, the peer's pre-policy Adj-RIB-In is replayed locally
    // on `clear ... soft in` instead of (or in addition to) sending a
    // Route Refresh. Lets policy changes take effect without a session
    // bounce when the peer doesn't support RFC 2918, at the cost of
    // keeping received UPDATEs in memory.
    pub soft_reconfig_in: bool,
    pub timer: timer::Config,
    pub sub: BTreeMap<AfiSafi, PeerSubConfig>,
    /// Reference to a `neighbor-group` (zebra-bgp-neighbor-group.yang)
    /// whose attributes this peer should inherit. Recorded on
    /// `set router bgp neighbor <addr> neighbor-group <name>`. The
    /// runtime stores the reference but does not yet resolve
    /// inheritance — that's a follow-up.
    pub neighbor_group: Option<String>,
}

impl Default for PeerConfig {
    fn default() -> Self {
        Self {
            transport: Default::default(),
            four_octet: Default::default(),
            extended_message: true,
            mp: Default::default(),
            restart: AfiSafis::new(),
            llgr: AfiSafis::new(),
            addpath: AfiSafis::new(),
            route_refresh: Default::default(),
            soft_reconfig_in: Default::default(),
            timer: Default::default(),
            sub: Default::default(),
            neighbor_group: None,
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct PeerSubConfig {
    pub graceful_restart: Option<u32>,
    pub llgr: Option<u32>,
}

#[derive(Debug, Eq, PartialEq, PartialOrd, Ord, Hash, Clone, Copy)]
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

    pub fn to_str(self) -> &'static str {
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
    pub ident: usize,
    pub address: IpAddr,
    pub router_id: Ipv4Addr,
    pub local_identifier: Option<Ipv4Addr>,
    pub remote_id: Ipv4Addr,
    pub local_as: u32,
    pub peer_as: u32,
    /// Local BGP speaker's hostname snapshot used to populate the FQDN
    /// capability in OPEN. Set at peer creation from `Bgp::hostname()`
    /// and refreshed by the global hostname callback so that re-opened
    /// sessions advertise the latest value.
    pub local_hostname: Option<String>,
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
    /// EVPN advertise cache. Mirrors `cache_vpnv4` shape — NLRIs
    /// grouped by attribute so a single MP_REACH UPDATE on flush can
    /// carry every route that shares one attr set. Withdraw path uses
    /// the reverse map; not yet implemented in this PR.
    pub cache_evpn: HashMap<Arc<BgpAttr>, HashSet<EvpnRoute>>,
    pub cache_evpn_rev: HashMap<EvpnRoute, Arc<BgpAttr>>,
    pub cache_ipv4_timer: Option<Timer>,
    pub cache_vpnv4_timer: Option<Timer>,
    pub cache_evpn_timer: Option<Timer>,
    // Runtime bookkeeping for TCP-AO listener state: the (send_id,
    // recv_id) pair most recently installed via TCP_AO_ADD_KEY for
    // this peer. Needed because TCP_AO_DEL_KEY requires the exact
    // IDs — we can't "wildcard-delete" by address. Cleared after a
    // successful removal or when no AO key is present for this
    // peer.
    pub last_ao_installed: Option<(u8, u8)>,
    /// Back-reference into `Bgp::update_groups`. One entry per AFI/SAFI
    /// the peer is in; written by `update_group::attach` on entering
    /// Established and cleared by `detach` on leaving. Empty otherwise.
    pub update_group_id: BTreeMap<AfiSafi, super::update_group::UpdateGroupId>,
}

impl Peer {
    pub fn new(
        ident: usize,
        local_as: u32,
        router_id: Ipv4Addr,
        peer_as: u32,
        address: IpAddr,
        local_hostname: Option<String>,
        tx: mpsc::Sender<Message>,
    ) -> Self {
        let mut peer = Self {
            ident,
            router_id,
            local_as,
            peer_as,
            local_hostname,
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
            cache_evpn: HashMap::default(),
            cache_evpn_rev: HashMap::default(),
            cache_ipv4_timer: None,
            cache_vpnv4_timer: None,
            cache_evpn_timer: None,
            last_ao_installed: None,
            update_group_id: BTreeMap::new(),
        };
        peer.config
            .mp
            .set(AfiSafi::new(Afi::Ip, Safi::Unicast), true);
        peer.config.four_octet = true;
        peer.config.route_refresh = true;
        // peer.config.graceful_restart = Some(65535);
        peer
    }

    pub fn event(&self, ident: usize, event: Event) {
        let _ = self.tx.clone().send(Message::Event(ident, event));
    }

    pub fn is_passive(&self) -> bool {
        self.config.transport.passive
    }

    pub fn max_packet_size(&self) -> usize {
        if self.opt.extended_message {
            BGP_EXTENDED_PACKET_LEN
        } else {
            BGP_PACKET_LEN
        }
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
        if let Some(cap) = self.cap_map.entries.get(&afi)
            && cap.send
            && cap.recv
        {
            return true;
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
        Event::RouteRefreshMsg(afi, safi) => {
            peer.counter[BgpType::RouteRefresh as usize].rcvd += 1;
            timer::refresh_hold_timer(peer);
            (peer.state, FsmEffect::RouteRefreshRecv { afi, safi })
        }
        Event::StaleTimerExipires(afi_safi) => {
            peer.timer.stale_timer.remove(&afi_safi);
            (peer.state, FsmEffect::StaleExpire(afi_safi))
        }
        Event::AdvTimerIpv4Expires => (fsm_adv_timer_ipv4_expires(peer), FsmEffect::None),
        Event::AdvTimerVpnv4Expires => (fsm_adv_timer_vpnv4_expires(peer), FsmEffect::None),
        Event::AdvTimerEvpnExpires => (fsm_adv_timer_evpn_expires(peer), FsmEffect::None),
    }
}

fn fsm_effect(id: usize, effect: FsmEffect, bgp: &mut BgpTop, peers: &mut PeerMap) {
    match effect {
        FsmEffect::None => {}
        FsmEffect::RouteUpdate(packet) => {
            route_from_peer(id, packet, bgp, peers);
        }
        FsmEffect::StaleExpire(_afi_safi) => {
            stale_route_withdraw(id, bgp, peers);
        }
        FsmEffect::RouteRefreshRecv { afi: _, safi: _ } => {
            super::route::route_soft_out_peer(id, bgp, peers);
        }
    }
}

pub fn fsm(
    bgp_ref: &mut BgpTop,
    peer_map: &mut PeerMap,
    update_groups: &mut super::update_group::UpdateGroupMap,
    id: usize,
    event: Event,
) {
    // Phase 1: Compute new state (single match, only &mut Peer)
    let (prev_state, effect) = {
        let peer = peer_map.get_mut_by_idx(id).unwrap();
        let prev_state = peer.state;
        let (new_state, effect) = fsm_next_state(peer, event);
        peer.state = new_state;
        (prev_state, effect)
    };

    // Phase 2: Execute side effects that need peer_map
    fsm_effect(id, effect, bgp_ref, peer_map);

    // Phase 3: Handle state transition consequences
    {
        let peer = peer_map.get_mut_by_idx(id).unwrap();
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
    if prev_state.is_established() && !peer_map.get_by_idx(id).unwrap().state.is_established() {
        route_clean(id, bgp_ref, peer_map);
    }

    // Phase 5: maintain update-group membership across the
    // Established boundary. Detach must run *after* route_clean so
    // observability sees the peer leave the group only once routes
    // have been torn down; attach runs after route_sync so the
    // group reflects the post-sync state.
    {
        let now_established = peer_map
            .get_by_idx(id)
            .map(|p| p.state.is_established())
            .unwrap_or(false);
        if prev_state.is_established() && !now_established {
            super::update_group::detach(update_groups, peer_map, id);
        } else if !prev_state.is_established() && now_established {
            super::update_group::attach(update_groups, peer_map, id);
        }
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

pub fn fsm_adv_timer_evpn_expires(peer: &mut Peer) -> State {
    peer.cache_evpn_timer = None;
    peer.flush_evpn();
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

//
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

    // Extended message negotiation (RFC 8654).
    if peer.cap_send.extended.is_some() && packet.bgp_cap.extended.is_some() {
        peer.opt.extended_message = true;
    }

    // Record received capability.
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
    ident: usize,
    tx: mpsc::Sender<Message>,
    config: &mut PeerConfig,
    opt: &mut ParseOption,
) -> Result<(), String> {
    match BgpPacket::parse_packet(rx, true, Some(opt.clone())) {
        Ok((_, p)) => {
            match p {
                BgpPacket::Open(p) => {
                    cap_addpath_recv(&p.bgp_cap, opt, &config.addpath);
                    if config.extended_message && p.bgp_cap.extended.is_some() {
                        opt.extended_message = true;
                    }
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
                BgpPacket::RouteRefresh(p) => {
                    let _ = tx
                        .send(Message::Event(ident, Event::RouteRefreshMsg(p.afi, p.safi)))
                        .await;
                }
            }
            Ok(())
        }
        Err(e) => Err(e.to_string()),
    }
}

pub async fn peer_read(
    ident: usize,
    tx: mpsc::Sender<Message>,
    mut read_half: OwnedReadHalf,
    mut config: PeerConfig,
    mut opt: ParseOption,
) {
    let mut buf = BytesMut::with_capacity(BGP_EXTENDED_PACKET_LEN);
    loop {
        match read_half.read_buf(&mut buf).await {
            Ok(read_len) => {
                if read_len == 0 {
                    let _ = tx.try_send(Message::Event(ident, Event::ConnFail));
                    return;
                }
                while buf.len() >= BGP_HEADER_LEN as usize && buf.len() >= peek_bgp_length(&buf) {
                    let length = peek_bgp_length(&buf);

                    // Validate message length (RFC 8654).
                    if length < BGP_HEADER_LEN as usize || length > opt.max_message_len() {
                        let _ = tx.try_send(Message::Event(ident, Event::ConnFail));
                        return;
                    }

                    let mut remain = buf.split_off(length);
                    remain.reserve(BGP_EXTENDED_PACKET_LEN);

                    match peer_packet_parse(&buf, ident, tx.clone(), &mut config, &mut opt).await {
                        Ok(_) => {
                            buf = remain;
                        }
                        Err(_err) => {
                            let _ = tx.try_send(Message::Event(ident, Event::ConnFail));
                            return;
                        }
                    }
                }
            }
            Err(_err) => {
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
    let update_source = peer.config.transport.update_source;
    let md5_password = peer.config.transport.md5_password.clone();
    let ao_key = peer.config.transport.resolved_ao_key.clone();
    Task::spawn(async move {
        let tx = tx.clone();
        let remote: SocketAddr = match address {
            IpAddr::V4(addr) => SocketAddr::new(IpAddr::V4(addr), BGP_PORT),
            IpAddr::V6(addr) => SocketAddr::new(IpAddr::V6(addr), BGP_PORT),
        };
        let result = peer_connect(remote, update_source, md5_password.as_deref(), ao_key).await;
        match result {
            Ok(stream) => {
                let _ = tx.try_send(Message::Event(ident, Event::Connected(stream)));
            }
            Err(_err) => {
                let _ = tx.try_send(Message::Event(ident, Event::ConnFail));
            }
        };
    })
}

async fn peer_connect(
    remote: SocketAddr,
    update_source: Option<IpAddr>,
    md5_password: Option<&str>,
    ao_key: Option<super::auth::ResolvedAoKey>,
) -> std::io::Result<TcpStream> {
    // Address family of the source must match the remote when specified.
    if let Some(src) = update_source
        && src.is_ipv4() != remote.is_ipv4()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "update-source address family does not match peer address",
        ));
    }

    let socket = if remote.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };

    // Install TCP MD5 / TCP-AO key BEFORE connect() so the outgoing
    // SYN carries a valid auth option. A mismatched or missing key
    // on the peer's listener causes the SYN to be silently dropped
    // by the kernel (no log, no SYN-ACK).
    use std::os::fd::AsRawFd;
    if let Some(password) = md5_password {
        super::auth::set_tcp_md5_key(socket.as_raw_fd(), remote.ip(), password.as_bytes())?;
    }
    if let Some(key) = ao_key {
        super::auth::set_tcp_ao_key(
            socket.as_raw_fd(),
            remote.ip(),
            key.alg_name,
            &key.key_material,
            key.send_id,
            key.recv_id,
            key.include_tcp_options,
        )?;
    }

    if let Some(src) = update_source {
        socket.bind(SocketAddr::new(src, 0))?;
    }

    socket.connect(remote).await
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
    // Sending 0.0.0.0 as the BGP Identifier is a protocol error per
    // RFC 4271 §4.2; the peer will respond with NOTIFICATION
    // (Bad BGP Identifier). Surface it loudly here so the operator
    // sees it before chasing FSM symptoms.
    if router_id.is_unspecified() {
        tracing::warn!(
            "peer {}: sending OPEN with router-id 0.0.0.0 — \
             configure `router bgp global identifier <ipv4>` or wait \
             for an interface address to seed the auto-derivation",
            peer.address
        );
    }
    let mut bgp_cap = BgpCap::default();

    for (afi_safi, _) in peer.config.mp.0.iter() {
        let cap = CapMultiProtocol::new(&afi_safi.afi, &afi_safi.safi);
        bgp_cap.mp.insert(*afi_safi, cap);
    }
    if peer.config.four_octet {
        let cap = CapAs4::new(peer.local_as);
        bgp_cap.as4 = Some(cap);
    }
    if peer.config.route_refresh {
        let cap = CapRefresh::default();
        bgp_cap.refresh = Some(cap);
    }
    if peer.config.extended_message {
        bgp_cap.extended = Some(CapExtended::default());
    }
    if let Some(name) = &peer.local_hostname {
        // FQDN capability (draft-walton, code 73). Domain name is left
        // empty for now — operators have only asked for hostname.
        bgp_cap.fqdn = Some(CapFqdn::new(name, ""));
    }
    for (key, addpath) in peer.config.addpath.iter() {
        bgp_cap.addpath.insert(*key, addpath.clone());
    }
    for (key, sub) in peer.config.sub.iter() {
        if let Some(_restart_time) = sub.graceful_restart {
            let restart = RestartValue::new(1, key.afi, key.safi);
            bgp_cap.restart.insert(*key, restart);
        }
        if let Some(llgr_time) = sub.llgr {
            let llgr = LlgrValue::new(key.afi, key.safi, llgr_time);
            bgp_cap.llgr.insert(*key, llgr);
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
    let mut bytes: BytesMut = notification.into();
    // RFC 8654: NOTIFICATION to non-extended peer MUST NOT exceed 4096.
    if !peer.opt.extended_message && bytes.len() > BGP_PACKET_LEN {
        bytes.truncate(BGP_PACKET_LEN);
        let length = bytes.len() as u16;
        bytes[16..18].copy_from_slice(&length.to_be_bytes());
    }
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

// Send a BGP Route Refresh (RFC 2918, type 5) for one AFI/SAFI. The
// caller is responsible for verifying the peer is established and
// advertised the Route Refresh capability — sending REFRESH to a peer
// that didn't advertise the cap is technically permitted but the peer
// is allowed to ignore it.
pub fn peer_send_route_refresh(peer: &mut Peer, afi: u16, safi: u8) {
    let Some(packet_tx) = peer.packet_tx.as_ref() else {
        return;
    };
    let pkt = RouteRefreshPacket::new(afi, safi);
    let bytes: BytesMut = pkt.into();
    peer.counter[BgpType::RouteRefresh as usize].sent += 1;
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

/// Replay Adj-RIB-In through the current inbound policy for `peer_idx`,
/// without bouncing the session. If the peer has `soft-reconfiguration
/// inbound` configured we replay locally from the stored Adj-RIB-In.
/// Otherwise we fall back to RFC 2918 Route Refresh provided the peer
/// advertised the capability. With neither, the call is a silent no-op
/// — the peer will only converge on its next update.
///
/// Used by both the `clear bgp <afi> <peer> soft in` CLI dispatcher
/// (`clear_bgp_action`) and the policy-update path in
/// `process_policy_msg`.
pub fn apply_soft_in_peer(bgp: &mut Bgp, peer_idx: usize) {
    let Some(peer) = bgp.peers.get_by_idx(peer_idx) else {
        return;
    };
    if !peer.state.is_established() {
        return;
    }
    let soft_in = peer.config.soft_reconfig_in;
    let supports_refresh = peer.cap_recv.refresh.is_some();
    let mp_pairs: Vec<(u16, u8)> = peer
        .cap_recv
        .mp
        .keys()
        .map(|af| (u16::from(af.afi), u8::from(af.safi)))
        .collect();

    if soft_in {
        let mut bgp_ref = BgpTop {
            router_id: &bgp.router_id,
            local_rib: &mut bgp.local_rib,
            tx: &bgp.tx,
            rib_tx: &bgp.rib_tx,
            attr_store: &mut bgp.attr_store,
        };
        super::route::route_soft_in_peer(peer_idx, &mut bgp_ref, &mut bgp.peers);
    } else if supports_refresh {
        let peer = bgp.peers.get_mut_by_idx(peer_idx).expect("peer exists");
        for (afi, safi) in &mp_pairs {
            peer_send_route_refresh(peer, *afi, *safi);
        }
    }
}

/// Replay Loc-RIB through the current outbound policy for `peer_idx`,
/// without bouncing the session. Always works when the peer is
/// Established — no peer cooperation needed because we drive the
/// re-advertisement from our local RIB.
pub fn apply_soft_out_peer(bgp: &mut Bgp, peer_idx: usize) {
    let Some(peer) = bgp.peers.get_by_idx(peer_idx) else {
        return;
    };
    if !peer.state.is_established() {
        return;
    }
    let mut bgp_ref = BgpTop {
        router_id: &bgp.router_id,
        local_rib: &mut bgp.local_rib,
        tx: &bgp.tx,
        rib_tx: &bgp.rib_tx,
        attr_store: &mut bgp.attr_store,
    };
    super::route::route_soft_out_peer(peer_idx, &mut bgp_ref, &mut bgp.peers);
}

/// Action selector for the `clear bgp <afi> <peer> ...` family of
/// operational commands. `Hard` bounces the session; the soft variants
/// re-evaluate without disturbing the BGP FSM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BgpClearOp {
    Hard,
    SoftBoth,
    SoftIn,
    SoftOut,
}

/// Drive `clear bgp <afi> <peer-or-all> [soft [in|out]]` requests from
/// the new YANG schema in zebra-bgp-clear.yang. The first arg is the
/// list key — either an IP literal or the keyword `all`.
///
/// Filtering by `(afi, safi)` only matters when the key is `all`; for
/// a concrete peer address we look it up directly and skip the filter
/// (the caller asked for *that* peer specifically). EVPN soft-in is
/// not yet wired into `route_soft_in_peer`, so a soft-in/soft-both on
/// EVPN logs a "not yet implemented" notice and leaves the session
/// alone — Phase 5 of the EVPN work in route.rs lifts that.
pub fn clear_bgp_action(
    bgp: &mut Bgp,
    args: &mut Args,
    afi: bgp_packet::Afi,
    safi: bgp_packet::Safi,
    op: BgpClearOp,
) -> std::result::Result<String, std::fmt::Error> {
    let Some(target) = args.string() else {
        return Ok("missing peer or 'all' argument".to_string());
    };

    if matches!(op, BgpClearOp::SoftIn | BgpClearOp::SoftBoth) && safi == bgp_packet::Safi::Evpn {
        return Ok("%% EVPN soft-in is not yet implemented".to_string());
    }

    let targets: Vec<IpAddr> = if target == "all" {
        bgp.peers
            .iter()
            .filter_map(|(_, p)| p.is_afi_safi(afi, safi).then_some(p.address))
            .collect()
    } else {
        match target.parse::<IpAddr>() {
            Ok(addr) => vec![addr],
            Err(_) => return Ok(format!("invalid peer or 'all': {}", target)),
        }
    };

    if targets.is_empty() {
        return Ok("%% no matching peers".to_string());
    }

    for addr in &targets {
        let Some(peer_idx) = bgp.peers.get(addr).map(|p| p.ident) else {
            continue;
        };
        match op {
            BgpClearOp::Hard => {
                let _ = bgp.tx.try_send(Message::Event(peer_idx, Event::Stop));
            }
            BgpClearOp::SoftBoth => {
                apply_soft_in_peer(bgp, peer_idx);
                apply_soft_out_peer(bgp, peer_idx);
            }
            BgpClearOp::SoftIn => apply_soft_in_peer(bgp, peer_idx),
            BgpClearOp::SoftOut => apply_soft_out_peer(bgp, peer_idx),
        }
    }
    Ok(format!(
        "%% cleared {} peer(s) (op={:?})",
        targets.len(),
        op
    ))
}
