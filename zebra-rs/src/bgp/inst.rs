use super::BgpAttrStore;
use super::peer::{BgpTop, Event, fsm};
use super::peer_map::PeerMap;
use super::route::LocalRib;
use crate::bgp::debug::BgpDebugFlags;
use crate::bgp::peer::accept;
use crate::bgp::{InOut, peer};
use crate::config::{
    Args, ConfigChannel, ConfigOp, ConfigRequest, DisplayRequest, ShowChannel, path_from_command,
};
use crate::context::Task;
use crate::policy::com_list::CommunityListMap;
use crate::policy::{self, PolicyRxChannel};
use crate::rib::api::{FdbEntry, RibRx, RibRxChannel};
use crate::rib::{self, MacAddr};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::{BTreeMap, HashMap};
use std::net::{Ipv4Addr, SocketAddr};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{self, Sender, UnboundedReceiver, UnboundedSender};

/// Map a `/clear/bgp/<afi>/neighbor[/soft[/in|out]]` path (from
/// zebra-bgp-clear.yang) to the (AFI, SAFI, op) triple the BGP runtime
/// understands. Returns None for unrecognised paths.
fn parse_clear_bgp_path(
    path: &str,
) -> Option<(bgp_packet::Afi, bgp_packet::Safi, peer::BgpClearOp)> {
    use bgp_packet::{Afi, Safi};
    use peer::BgpClearOp;

    let rest = path.strip_prefix("/clear/bgp/")?;
    let (afi_str, tail) = rest.split_once('/')?;
    let (afi, safi) = match afi_str {
        "ipv4" => (Afi::Ip, Safi::Unicast),
        "ipv6" => (Afi::Ip6, Safi::Unicast),
        "vpnv4" => (Afi::Ip, Safi::MplsVpn),
        "evpn" => (Afi::L2vpn, Safi::Evpn),
        _ => return None,
    };
    let op = match tail {
        "neighbor" => BgpClearOp::Hard,
        "neighbor/soft" => BgpClearOp::SoftBoth,
        "neighbor/soft/in" => BgpClearOp::SoftIn,
        "neighbor/soft/out" => BgpClearOp::SoftOut,
        _ => return None,
    };
    Some((afi, safi, op))
}

/// Create an IPv6-only TCP listener to avoid conflicts with IPv4 binding
fn create_ipv6_listener() -> Result<TcpListener, std::io::Error> {
    let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;

    // Set IPV6_V6ONLY to true to prevent binding to IPv4 as well
    socket.set_only_v6(true)?;
    socket.set_reuse_address(true)?;

    let addr = "[::]:179".parse::<SocketAddr>().unwrap();
    socket.bind(&addr.into())?;
    socket.listen(128)?;

    // Convert socket2::Socket to std::net::TcpListener, then to tokio::net::TcpListener
    let std_listener: std::net::TcpListener = socket.into();
    std_listener.set_nonblocking(true)?;
    TcpListener::from_std(std_listener)
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum Message {
    Event(usize, Event),
    Accept(TcpStream, SocketAddr),
    Show(Sender<String>),
    /// Adv-debounce timer expired for an IPv4-unicast update-group:
    /// drain the group's pending cache, encode one UPDATE per attr
    /// bucket, and ship to each member with split-horizon pruning.
    FlushUpdateGroupIpv4(super::update_group::UpdateGroupId),
}

pub type Callback = fn(&mut Bgp, Args, ConfigOp) -> Option<()>;
pub type PCallback = fn(&mut CommunityListMap, Args, ConfigOp) -> Option<()>;
pub type ShowCallback = fn(&Bgp, Args, bool) -> std::result::Result<String, std::fmt::Error>;

#[allow(dead_code)]
pub struct Bgp {
    pub asn: u32,
    pub router_id: Ipv4Addr,
    /// FRR-style `advertise-all-vni` knob under `router bgp afi-safi
    /// evpn`. When true, every locally-configured VXLAN VNI
    /// participates in EVPN advertisement: Type-2 (MAC/IP) routes
    /// from the kernel's bridge FDB and Type-3 (Inclusive Multicast)
    /// routes per local VTEP. Bridge -> VNI mapping is inferred from
    /// the kernel (each bridge's VXLAN slave supplies the VNI). RD =
    /// router-id:VNI; RT-import / RT-export = local-AS:VNI per
    /// RFC 8365 §5.1.2.
    ///
    /// Schema-only in the PR that introduced this — no consumer yet.
    /// The Rib::neighbors -> EvpnPrefix::MacIp pipeline that reads
    /// this lands separately.
    pub advertise_all_vni: bool,
    /// Local bridge FDB shadow keyed by `(vni, mac)`. Populated from
    /// every `RibRx::FdbAdd`, removed on `RibRx::FdbDel`. We need
    /// durable state (not just one-shot event handling) because the
    /// FDB events from `Rib::subscribe` / `fib_dump` race with the
    /// config commit that flips `advertise_all_vni` to true: at cold
    /// start, fib_dump's netlink walk almost always finishes before
    /// `config.load_config` does, so the FdbAdd messages arrive while
    /// the gate is still false and `evpn_originate_macip` drops them.
    /// With the shadow, the config callback can replay every cached
    /// entry on the false→true transition (and withdraw on true→false),
    /// so origination becomes deterministic regardless of which
    /// channel wins the boot race.
    pub local_fdb: BTreeMap<(u32, MacAddr), FdbEntry>,
    /// Local VXLAN VTEP shadow keyed by VNI, value = local VTEP IP
    /// (the VXLAN device's `IFLA_VXLAN_LOCAL` / `LOCAL6`). Populated
    /// from `RibRx::VxlanAdd`, removed on `RibRx::VxlanDel`. Drives
    /// Type-3 (Inclusive Multicast) origination — one IMET per VNI
    /// — and replays on `advertise_all_vni` / `router_id` transitions
    /// just like `local_fdb`.
    pub local_vxlans: BTreeMap<u32, std::net::IpAddr>,
    /// Configured hostname for the local BGP speaker. Advertised in
    /// the FQDN capability (capability code 73). When None, falls back
    /// to the OS hostname; if that also fails, no FQDN capability is
    /// emitted. See `Bgp::hostname()` for the resolution order.
    pub hostname: Option<String>,
    pub peers: PeerMap,
    /// Bounded channel for BGP events (capacity: 8192)
    pub tx: mpsc::Sender<Message>,
    pub rx: mpsc::Receiver<Message>,
    pub cm: ConfigChannel,
    pub show: ShowChannel,
    pub show_cb: HashMap<String, ShowCallback>,
    pub rib_tx: UnboundedSender<rib::Message>,
    pub rib_rx: UnboundedReceiver<RibRx>,
    pub callbacks: HashMap<String, Callback>,
    pub pcallbacks: HashMap<String, PCallback>,
    /// BGP Local RIB (Loc-RIB) for best path selection
    pub local_rib: LocalRib,
    pub listen_task: Option<Task<()>>,
    pub listen_task6: Option<Task<()>>,
    pub listen_err: Option<anyhow::Error>,
    // Raw fds of the IPv4 / IPv6 BGP listening sockets, captured in
    // listen() before the TcpListeners are moved into their accept
    // tasks. Used by config callbacks to install or remove TCP MD5 /
    // TCP-AO keys per-peer on the passive side — the kernel requires
    // the key to be on the listener before the peer's SYN arrives;
    // a post-accept() setsockopt is too late. See TCP-MD5-AO.md
    // "Passive vs active side placement".
    pub listen_fd_v4: Option<std::os::fd::RawFd>,
    pub listen_fd_v6: Option<std::os::fd::RawFd>,
    // RFC 8177 key-chain registry, indexed by chain name. Populated
    // by config callbacks for /key-chains/... and referenced from a
    // peer's AoConfig.key_chain leafref.
    pub key_chains: HashMap<String, super::auth::KeyChain>,

    /// IOS-XR-style `neighbor-group` definitions
    /// (zebra-bgp-neighbor-group.yang). Phase-1 storage: each entry
    /// holds the group's overridable defaults; field-level
    /// inheritance into peers that reference a group via
    /// `PeerConfig::neighbor_group` is not wired in the runtime
    /// yet — that lands in a follow-up.
    pub neighbor_groups: BTreeMap<String, super::neighbor_group::NeighborGroup>,
    /// `dynamic-neighbors` runtime (zebra-bgp-dynamic-neighbors.yang).
    /// Holds the configured listen-ranges and the soft cap on
    /// materialized passive peers. `dynamic_peer_count` is bumped on
    /// successful accept-time materialization in `peer::accept`; it
    /// is never decremented yet — session-close GC is deferred to a
    /// follow-up so this PR stays focused on the accept path.
    pub dynamic_neighbors: super::dynamic_neighbors::DynamicNeighbors,
    pub dynamic_peer_count: u32,
    /// IOS-XR-style update-groups, keyed by `(AfiSafi, signature)`.
    /// Phase-1: signature + membership tracking only — the advertise
    /// pipeline does not yet share work across members. See
    /// `docs/design/bgp-update-groups.md`.
    pub update_groups: super::update_group::UpdateGroupMap,
    /// Debug configuration flags
    pub debug_flags: BgpDebugFlags,
    pub policy_tx: UnboundedSender<policy::Message>,
    pub policy_rx: UnboundedReceiver<policy::PolicyRx>,
    /// Handle into the BFD instance's client-request channel — used
    /// by the per-neighbor `bfd { enable }` path to submit
    /// `ClientReq::Subscribe` / `Unsubscribe`. `None` means BFD has
    /// not (yet) been configured: BGP silently skips its BFD attach
    /// logic in that case. Captured at spawn time from
    /// `ConfigManager::bfd_client_tx`; not refreshed if BFD respawns
    /// later (late-binding work is a follow-up).
    pub bfd_client_tx: Option<UnboundedSender<crate::bfd::inst::ClientReq>>,
    /// Sender half of the per-instance `BfdEvent` channel. Cloned and
    /// handed to BFD as the `notifier` on every `Subscribe`, so all
    /// state-change events for BGP-attached BFD sessions land on the
    /// matching `bfd_event_rx` below.
    pub bfd_event_tx: UnboundedSender<crate::bfd::inst::BfdEvent>,
    /// Receive half drained by the BGP event loop in
    /// [`Self::event_loop`]. PR 5d logs the events; PR 5e replaces
    /// the log with neighbor teardown on `BfdEvent::Down`.
    pub bfd_event_rx: UnboundedReceiver<crate::bfd::inst::BfdEvent>,
    // BgpAttr shared storage.
    pub attr_store: BgpAttrStore,

    /// Per-AFI redistribution configuration. Populated by the
    /// `/router/bgp/afi-safi/redistribute/<source>...` callbacks
    /// (zebra-bgp-redistribute.yang); one entry per (AfiSafi, source)
    /// pair, holding policy / metric / multipath plus per-source
    /// extras (IS-IS level filter, OSPF match types).
    ///
    /// Each commit converts these into wire-level RedistAdd /
    /// RedistUpdate / RedistDel messages bound for RIB; the per-AFI
    /// snapshots below catch the route deliveries that come back.
    pub redistribute: BTreeMap<
        (bgp_packet::AfiSafi, super::config::BgpRedistSource),
        super::config::BgpRedistribute,
    >,

    /// Redistribute snapshot — routes the RIB delivered via
    /// `RouteAdd`/`RouteDel` for our `RedistAdd` subscriptions.
    /// Keyed by `(RibType, prefix)` so different source protocols
    /// advertising the same prefix stay distinct (each row carries
    /// its own policy / metric / multipath override at Loc-RIB
    /// injection time). Consumed by the BGP origination path in a
    /// follow-up (step 5b).
    pub redist_v4: BTreeMap<(crate::rib::RibType, ipnet::Ipv4Net), crate::rib::RouteEntryV4>,
    pub redist_v6: BTreeMap<(crate::rib::RibType, ipnet::Ipv6Net), crate::rib::RouteEntryV6>,
}

impl Bgp {
    pub fn new(
        rib_tx: UnboundedSender<rib::Message>,
        policy_tx: UnboundedSender<policy::Message>,
        bfd_client_tx: Option<UnboundedSender<crate::bfd::inst::ClientReq>>,
    ) -> Self {
        let chan = RibRxChannel::new();
        let msg = rib::Message::Subscribe {
            proto: "bgp".into(),
            tx: chan.tx.clone(),
        };
        let _ = rib_tx.send(msg);

        let policy_chan = PolicyRxChannel::new();
        let msg = policy::Message::Subscribe {
            proto: "bgp".into(),
            tx: policy_chan.tx.clone(),
        };
        let _ = policy_tx.send(msg);

        let (tx, rx) = mpsc::channel(8192);
        let (bfd_event_tx, bfd_event_rx) = mpsc::unbounded_channel();
        let mut bgp = Self {
            asn: 0,
            router_id: Ipv4Addr::UNSPECIFIED,
            advertise_all_vni: false,
            local_fdb: BTreeMap::new(),
            local_vxlans: BTreeMap::new(),
            hostname: None,
            peers: PeerMap::new(),
            tx,
            rx,
            local_rib: LocalRib::default(),
            rib_tx,
            rib_rx: chan.rx,
            cm: ConfigChannel::new(),
            show: ShowChannel::new(),
            show_cb: HashMap::new(),
            callbacks: HashMap::new(),
            pcallbacks: HashMap::new(),
            listen_task: None,
            listen_task6: None,
            listen_err: None,
            listen_fd_v4: None,
            listen_fd_v6: None,
            key_chains: HashMap::new(),
            neighbor_groups: super::neighbor_group::empty_map(),
            dynamic_neighbors: super::dynamic_neighbors::DynamicNeighbors::default(),
            dynamic_peer_count: 0,
            update_groups: super::update_group::empty_map(),
            debug_flags: BgpDebugFlags::default(),
            policy_tx,
            policy_rx: policy_chan.rx,
            bfd_client_tx,
            bfd_event_tx,
            bfd_event_rx,
            attr_store: BgpAttrStore::new(),
            redistribute: BTreeMap::new(),
            redist_v4: BTreeMap::new(),
            redist_v6: BTreeMap::new(),
        };
        bgp.callback_build();
        bgp.show_build();
        bgp
    }

    pub fn callback_add(&mut self, path: &str, cb: Callback) {
        self.callbacks.insert(path.to_string(), cb);
    }

    /// Resolve the hostname to advertise in the FQDN capability.
    /// Configured value wins; otherwise we fall back to the OS
    /// hostname. None means "skip the FQDN capability entirely".
    pub fn hostname(&self) -> Option<String> {
        if let Some(name) = &self.hostname {
            return Some(name.clone());
        }
        hostname::get()
            .ok()
            .and_then(|s| s.into_string().ok())
            .filter(|s| !s.is_empty())
    }

    /// Update the configured hostname and propagate the resolved
    /// value to every peer's `local_hostname` snapshot. Existing
    /// sessions keep using the value they captured at OPEN; the
    /// next OPEN this peer sends (after a reset / re-establishment)
    /// will pick up the new one.
    pub fn config_set_hostname(&mut self, value: Option<String>) {
        if self.hostname == value {
            return;
        }
        self.hostname = value;
        let resolved = self.hostname();
        for (_, peer) in self.peers.iter_mut() {
            peer.local_hostname = resolved.clone();
        }
    }

    /// Update the BGP router-id and propagate it to every peer's
    /// `router_id` snapshot. `Peer::new` captures `bgp.router_id` at
    /// peer-create time; without this propagation, peers configured
    /// before the router-id was known would emit OPEN messages with
    /// `0.0.0.0` in the BGP Identifier field forever.
    ///
    /// Inputs:
    ///   - operator config (`set router bgp global identifier <ip>`)
    ///     via `config_global_identifier`.
    ///   - RIB-derived auto-pick (`RibRx::RouterIdUpdate`) when no
    ///     explicit identifier is configured. Same precedence Cisco /
    ///     Junos use — last write wins for now; an explicit / auto
    ///     priority pin is a follow-up.
    ///
    /// Existing established sessions keep using the value they sent
    /// at OPEN; the next OPEN (after a reset) picks up the new one.
    pub fn set_router_id(&mut self, router_id: Ipv4Addr) {
        if self.router_id == router_id {
            return;
        }
        // EVPN RD = `<router-id>:<VNI>` (RFC 8365 §5.1.2). When
        // router-id changes, every locally-originated route is now
        // sitting under a stale RD that no peer (and no future
        // re-originate) will withdraw. Drain the local FDB cache and
        // withdraw under the OLD router-id BEFORE flipping the field,
        // then re-originate under the NEW value below. Skips the
        // withdraw when the old router-id is unspecified (initial
        // 0.0.0.0 → operator value transition — nothing was ever
        // originated under the all-zero RD because
        // `evpn_originate_macip` gates on a valid router-id) or when
        // `advertise_all_vni` is off (we never originated, so nothing
        // to withdraw).
        let old_router_id = self.router_id;
        let advertising = self.advertise_all_vni;
        if advertising && !old_router_id.is_unspecified() {
            if !self.local_fdb.is_empty() {
                let entries: Vec<FdbEntry> = self.local_fdb.values().cloned().collect();
                for entry in entries {
                    self.evpn_withdraw_macip(&entry);
                }
            }
            // Same RD-rebind story for Type-3 (IMET): each VXLAN's
            // outbound IMET is keyed by the local router-id-derived
            // RD; a router-id change requires withdrawing under the
            // old RD and re-originating under the new.
            if !self.local_vxlans.is_empty() {
                let vxlans: Vec<(u32, std::net::IpAddr)> =
                    self.local_vxlans.iter().map(|(k, v)| (*k, *v)).collect();
                for (vni, vtep_local) in vxlans {
                    self.evpn_withdraw_imet(vni, vtep_local);
                }
            }
        }

        self.router_id = router_id;
        for (_, peer) in self.peers.iter_mut() {
            peer.router_id = router_id;
        }

        // Re-originate under the new router-id so the cache contents
        // come back into the local-RIB / wire under the right RD.
        // Same gate as the false→true advertise-all-vni replay; the
        // `evpn_originate_macip` body re-checks both conditions, so
        // an unspecified `router_id` here is a safe no-op.
        if advertising && !router_id.is_unspecified() {
            if !self.local_fdb.is_empty() {
                let entries: Vec<FdbEntry> = self.local_fdb.values().cloned().collect();
                for entry in entries {
                    self.evpn_originate_macip(&entry);
                }
            }
            if !self.local_vxlans.is_empty() {
                let vxlans: Vec<(u32, std::net::IpAddr)> =
                    self.local_vxlans.iter().map(|(k, v)| (*k, *v)).collect();
                for (vni, vtep_local) in vxlans {
                    self.evpn_originate_imet(vni, vtep_local);
                }
            }
        }
    }

    pub fn pcallback_add(&mut self, path: &str, cb: PCallback) {
        self.pcallbacks.insert(path.to_string(), cb);
    }

    pub fn process_msg(&mut self, msg: Message) {
        match msg {
            Message::Event(ident, event) => {
                match event {
                    Event::BGPOpen(ref _msg) => {
                        // tracing::info!("Open from: {}", peer);
                    }
                    Event::UpdateMsg(ref _msg) => {
                        // tracing::info!("Update from: {}", peer);
                    }
                    Event::KeepAliveMsg => {
                        // tracing::info!("Keepalive from: {}", peer);
                    }
                    Event::KeepaliveTimerExpires => {
                        // tracing::info!("KeepaliveTimerExpires for {}", peer);
                    }
                    _ => {
                        // tracing::info!("Other Event: {:?} for {}", event, peer);
                    }
                }
                let mut bgp_ref = BgpTop {
                    router_id: &self.router_id,
                    local_rib: &mut self.local_rib,
                    tx: &self.tx,
                    rib_tx: &self.rib_tx,
                    attr_store: &mut self.attr_store,
                    update_groups: &mut self.update_groups,
                };

                fsm(&mut bgp_ref, &mut self.peers, ident, event);
            }
            Message::Accept(socket, sockaddr) => {
                // println!("Accept: {:?}", sockaddr);
                accept(self, socket, sockaddr);
            }
            Message::Show(tx) => {
                let _ = self.tx.try_send(Message::Show(tx));
            }
            Message::FlushUpdateGroupIpv4(group_id) => {
                super::update_group::flush_ipv4(
                    &mut self.update_groups,
                    &mut self.peers,
                    &mut self.attr_store,
                    &group_id,
                );
            }
        }
    }

    pub fn peer_comps(&self) -> Vec<String> {
        self.peers
            .keys()
            .map(|addr| addr.to_string().clone())
            .collect()
    }

    pub fn process_cm_msg(&mut self, msg: ConfigRequest) {
        match msg.op {
            ConfigOp::CommitStart => {
                //
            }
            ConfigOp::Set | ConfigOp::Delete => {
                let (path, args) = path_from_command(&msg.paths);
                if let Some(f) = self.callbacks.get(&path) {
                    f(self, args, msg.op);
                }
            }
            ConfigOp::CommitEnd => {
                //
            }
            ConfigOp::Completion => {
                msg.resp.unwrap().send(self.peer_comps()).unwrap();
            }
            ConfigOp::Clear => {
                // FRR-style `clear bgp <afi> <peer-or-all> [soft [in|out]]`
                // surface (zebra-bgp-clear.yang). The first segment after
                // `/clear/bgp/` is the AFI; the remainder selects the
                // operation.
                let (path, mut args) = path_from_command(&msg.paths);
                if let Some((afi, safi, op)) = parse_clear_bgp_path(&path) {
                    let _ = peer::clear_bgp_action(self, &mut args, afi, safi, op);
                }
            }
        }
    }

    async fn process_show_msg(&self, msg: DisplayRequest) {
        let (path, args) = path_from_command(&msg.paths);
        if let Some(f) = self.show_cb.get(&path) {
            let output = match f(self, args, msg.json) {
                Ok(result) => result,
                Err(e) => format!("Error formatting output: {}", e),
            };
            msg.resp.send(output).await.unwrap();
        }
    }

    pub async fn listen(&mut self) -> anyhow::Result<()> {
        let tx = self.tx.clone();
        let tx_clone = tx.clone();

        // Try to bind to both IPv4 and IPv6
        let mut ipv4_bound = false;
        let mut ipv6_bound = false;

        // Check if we can bind to IPv4
        match TcpListener::bind("0.0.0.0:179").await {
            Ok(listener) => {
                ipv4_bound = true;
                // println!("Successfully bound to IPv4 0.0.0.0:179");
                use std::os::fd::AsRawFd;
                self.listen_fd_v4 = Some(listener.as_raw_fd());
                let tx_ipv4 = tx.clone();
                self.listen_task = Some(Task::spawn(async move {
                    // println!("BGP listening on 0.0.0.0:179");
                    loop {
                        match listener.accept().await {
                            Ok((socket, sockaddr)) => {
                                // println!("IPv4 connection accepted from: {}", sockaddr);
                                if let Err(e) =
                                    tx_ipv4.send(Message::Accept(socket, sockaddr)).await
                                {
                                    eprintln!("Failed to send Accept message: {}", e);
                                    break;
                                }
                            }
                            Err(e) => {
                                eprintln!("IPv4 accept error: {}", e);
                                // Backoff on accept errors to prevent tight loop on FD exhaustion
                                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                            }
                        }
                    }
                }));
            }
            Err(e) => {
                eprintln!("Failed to bind to IPv4 0.0.0.0:179: {}", e);
            }
        }

        // Check if we can bind to IPv6 with IPv6-only socket
        match create_ipv6_listener() {
            Ok(listener) => {
                ipv6_bound = true;
                // println!("Successfully bound to IPv6 [::]:179");
                use std::os::fd::AsRawFd;
                self.listen_fd_v6 = Some(listener.as_raw_fd());
                let tx_ipv6 = tx_clone;
                self.listen_task6 = Some(Task::spawn(async move {
                    // println!("BGP listening on [::]:179");
                    loop {
                        match listener.accept().await {
                            Ok((socket, sockaddr)) => {
                                if let Err(e) =
                                    tx_ipv6.send(Message::Accept(socket, sockaddr)).await
                                {
                                    eprintln!("Failed to send Accept message: {}", e);
                                    break;
                                }
                            }
                            Err(e) => {
                                eprintln!("IPv6 accept error: {}", e);
                                // Backoff on accept errors to prevent tight loop on FD exhaustion
                                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                            }
                        }
                    }
                }));
            }
            Err(e) => {
                eprintln!("Failed to bind to IPv6 [::]:179: {}", e);
            }
        }

        if !ipv4_bound && !ipv6_bound {
            return Err(anyhow::anyhow!(
                "Failed to bind to any address (both IPv4 and IPv6)"
            ));
        }

        Ok(())
    }

    pub fn process_rib_msg(&mut self, msg: RibRx) {
        // println!("RIB Message {:?}", msg);
        match msg {
            RibRx::LinkAdd(_link) => {
                //self.link_add(link);
            }
            RibRx::AddrAdd(_addr) => {
                // isis_info!("Isis::AddrAdd {}", addr.addr);
                // self.addr_add(addr);
            }
            RibRx::AddrDel(_addr) => {
                // isis_info!("Isis::AddrDel {}", addr.addr);
                // self.addr_del(addr);
            }
            RibRx::RouterIdUpdate(router_id) => {
                // RIB auto-derived a router-id from interface IPv4
                // addresses (highest loopback, falling back to
                // non-loopback). Without this arm BGP missed the
                // notification and emitted OPEN with 0.0.0.0 in the
                // BGP Identifier whenever the operator hadn't typed
                // `set router bgp global identifier <ip>`.
                self.set_router_id(router_id);
            }
            RibRx::FdbAdd(entry) => {
                // Cache durably so we can replay on `advertise_all_vni`
                // false→true transitions — see `local_fdb` doc.
                self.local_fdb.insert((entry.vni, entry.mac), entry.clone());
                self.evpn_originate_macip(&entry);
            }
            RibRx::FdbDel(entry) => {
                self.local_fdb.remove(&(entry.vni, entry.mac));
                self.evpn_withdraw_macip(&entry);
            }
            RibRx::VxlanAdd { vni, vtep_local } => {
                self.local_vxlans.insert(vni, vtep_local);
                self.evpn_originate_imet(vni, vtep_local);
            }
            RibRx::VxlanDel { vni } => {
                if let Some(vtep_local) = self.local_vxlans.remove(&vni) {
                    self.evpn_withdraw_imet(vni, vtep_local);
                }
            }
            // Redistribute deliveries from RIB — initial walk
            // (chunks ending in `bulk: Eor`) plus steady-state deltas
            // (single-entry `bulk: More`). Stored in `redist_v{4,6}`
            // keyed by `(rtype, prefix)`; consumed at Loc-RIB
            // injection time in a follow-up.
            RibRx::RouteAdd { rtype, routes, .. } => {
                self.route_redist_add(rtype, routes);
            }
            RibRx::RouteDel { rtype, routes, .. } => {
                self.route_redist_del(rtype, routes);
            }
            _ => {
                //
            }
        }
    }

    fn route_redist_add(&mut self, rtype: crate::rib::RibType, batch: crate::rib::RouteBatch) {
        match batch {
            crate::rib::RouteBatch::V4(entries) => {
                for e in entries {
                    let prefix = e.prefix;
                    let rib_metric = e.metric;
                    self.redist_v4.insert((rtype, prefix), e);
                    // Lower into Loc-RIB. Per-AFI override metric beats
                    // the RIB cost; no override → use RIB cost as MED.
                    let metric = self
                        .redist_metric_v4_override(rtype, prefix)
                        .unwrap_or(rib_metric);
                    self.route_redist_inject(rtype, prefix, metric);
                }
            }
            crate::rib::RouteBatch::V6(entries) => {
                // v6 stays storage-only until LocalRib grows a v6 path.
                for e in entries {
                    self.redist_v6.insert((rtype, e.prefix), e);
                }
            }
        }
    }

    fn route_redist_del(&mut self, rtype: crate::rib::RibType, batch: crate::rib::RouteBatch) {
        match batch {
            crate::rib::RouteBatch::V4(entries) => {
                for e in entries {
                    self.redist_v4.remove(&(rtype, e.prefix));
                    self.route_redist_withdraw(rtype, e.prefix);
                }
            }
            crate::rib::RouteBatch::V6(entries) => {
                // v6 storage-only — see route_redist_add.
                for e in entries {
                    self.redist_v6.remove(&(rtype, e.prefix));
                }
            }
        }
    }

    /// Pull the `metric` static override from any `Bgp.redistribute`
    /// row matching `(rtype, ipv4-unicast)`. Iterates because the map
    /// is keyed by full `AfiSafi`, and we only care about the IPv4
    /// unicast row here. `None` means "no override, use RIB cost".
    fn redist_metric_v4_override(
        &self,
        rtype: crate::rib::RibType,
        _prefix: ipnet::Ipv4Net,
    ) -> Option<u32> {
        use crate::bgp::config::BgpRedistSource;
        use bgp_packet::{Afi, Safi};
        let source = match rtype {
            crate::rib::RibType::Connected => BgpRedistSource::Connected,
            crate::rib::RibType::Static => BgpRedistSource::Static,
            crate::rib::RibType::Isis => BgpRedistSource::Isis,
            crate::rib::RibType::Ospf => BgpRedistSource::Ospf,
            _ => return None,
        };
        let afi_safi = bgp_packet::AfiSafi {
            afi: Afi::Ip,
            safi: Safi::Unicast,
        };
        self.redistribute
            .get(&(afi_safi, source))
            .and_then(|c| c.metric)
    }

    pub async fn process_policy_msg(&mut self, msg: policy::PolicyRx) {
        // Two responsibilities per message: refresh the per-peer policy
        // snapshot, then trigger a soft-reconfiguration so already-
        // received Adj-RIB-In or already-advertised Loc-RIB entries
        // get re-evaluated against the new policy. Without the second
        // step a prefix-set / policy-list edit only affects routes
        // that arrive *after* the edit.
        match msg {
            policy::PolicyRx::PrefixSet {
                name: _,
                ident,
                policy_type,
                prefix_set,
            } => {
                let Some(peer) = self.peers.get_mut_by_idx(ident) else {
                    return;
                };
                let direction = match policy_type {
                    policy::PolicyType::PrefixSetIn => InOut::Input,
                    policy::PolicyType::PrefixSetOut => InOut::Output,
                    _ => return,
                };
                let config = peer.prefix_set.get_mut(&direction);
                config.prefix_set = prefix_set;

                match direction {
                    InOut::Input => super::peer::apply_soft_in_peer(self, ident),
                    InOut::Output => super::peer::apply_soft_out_peer(self, ident),
                }
            }
            policy::PolicyRx::PolicyList {
                name: _,
                ident,
                policy_type,
                policy_list,
            } => {
                let Some(peer) = self.peers.get_mut_by_idx(ident) else {
                    return;
                };
                let direction = match policy_type {
                    policy::PolicyType::PolicyListIn => InOut::Input,
                    policy::PolicyType::PolicyListOut => InOut::Output,
                    _ => return,
                };
                let config = peer.policy_list.get_mut(&direction);
                config.policy_list = policy_list;

                match direction {
                    InOut::Input => super::peer::apply_soft_in_peer(self, ident),
                    InOut::Output => super::peer::apply_soft_out_peer(self, ident),
                }
            }
        }
    }

    pub async fn event_loop(&mut self) {
        if let Err(err) = self.listen().await {
            self.listen_err = Some(err);
        }
        loop {
            match self.rib_rx.recv().await {
                Some(RibRx::EoR) => {
                    // tracing::info!("BGP: Received EoR, entering main event loop");
                    break;
                }
                Some(msg) => self.process_rib_msg(msg),
                None => break,
            }
        }
        // tracing::info!(
        //     "BGP: Main event loop started with {} peers",
        //     self.peers.len()
        // );
        loop {
            tokio::select! {
                Some(msg) = self.rib_rx.recv() => {
                    self.process_rib_msg(msg);
                }
                Some(msg) = self.rx.recv() => {
                    self.process_msg(msg);
                }
                Some(msg) = self.cm.rx.recv() => {
                    self.process_cm_msg(msg);
                }
                Some(msg) = self.show.rx.recv() => {
                    self.process_show_msg(msg).await;
                }
                Some(msg) = self.policy_rx.recv() => {
                    self.process_policy_msg(msg).await;
                }
                Some(event) = self.bfd_event_rx.recv() => {
                    self.process_bfd_event(event);
                }
            }
        }
    }

    /// Handle a [`crate::bfd::inst::BfdEvent`] forwarded by the BFD
    /// instance. RFC 5882 §5 prescribes that a BFD signal of session
    /// Down should be treated as a path-failure indication for the
    /// IGP/BGP session — we react by sending `Event::Stop` to the
    /// matching peer's FSM, which triggers the usual BGP teardown
    /// path (NOTIFICATION + TCP close + transition to Idle).
    ///
    /// Synthetic Down→Down notifications (emitted by BFD when a new
    /// subscriber attaches before any peer Rx has arrived) are
    /// ignored — they carry no state-transition information and
    /// would otherwise tear down a peer that hasn't yet had a chance
    /// to establish.
    pub fn process_bfd_event(&mut self, event: crate::bfd::inst::BfdEvent) {
        let crate::bfd::inst::BfdEvent::StateChange { key, change } = event;
        tracing::info!(
            ?key,
            from = %change.from,
            to = %change.to,
            diag = %change.diag,
            "bgp: bfd session state change",
        );

        // Synthetic "current state" mirror from `Bfd::subscribe`
        // — no transition has occurred.
        if change.from == change.to {
            return;
        }

        if change.to != bfd_packet::State::Down {
            return;
        }

        // SessionKey.remote is the BGP neighbor address — direct
        // lookup. A missing peer means the user removed the
        // neighbor since BGP last subscribed; safe to ignore.
        let Some(peer) = self.peers.get(&key.remote) else {
            tracing::debug!(?key, "bgp: bfd-down for unknown peer; ignoring",);
            return;
        };
        let peer_idx = peer.ident;
        tracing::warn!(
            peer = %key.remote,
            diag = %change.diag,
            "bgp: tearing down peer on bfd-down (RFC 5882 §5)",
        );
        let _ = self.tx.try_send(Message::Event(peer_idx, Event::Stop));
    }
}

pub fn serve(mut bgp: Bgp) -> Task<()> {
    Task::spawn(async move {
        bgp.event_loop().await;
    })
}
