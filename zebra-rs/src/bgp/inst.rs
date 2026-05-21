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
use crate::context::{ProtoContext, Task};
use crate::policy::com_list::CommunityListMap;
use crate::policy::{self, PolicyRxChannel};
use crate::rib::MacAddr;
use crate::rib::api::{FdbEntry, RibRx};
use std::collections::{BTreeMap, HashMap};
use std::net::{Ipv4Addr, SocketAddr};
use tokio::net::TcpStream;
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

/// Insert (or refresh) the `peer_index` row claiming `addr` for
/// `vrf`. Warns and overrides when a different VRF already owned
/// the address — matches FRR behaviour for the same conflict.
pub(crate) fn peer_index_register(
    index: &mut BTreeMap<std::net::IpAddr, String>,
    vrf: String,
    addr: std::net::IpAddr,
) {
    if let Some(prev) = index.insert(addr, vrf.clone())
        && prev != vrf
    {
        tracing::warn!(
            peer = %addr,
            old_vrf = %prev,
            new_vrf = %vrf,
            "bgp: peer address claimed by multiple VRFs; most recent wins",
        );
    }
}

/// Drop the `peer_index` entry for `addr` iff it currently
/// belongs to `vrf`. Guards against a stale `UnregisterPeer`
/// arriving after the operator moved the peer to a different
/// VRF.
pub(crate) fn peer_index_unregister(
    index: &mut BTreeMap<std::net::IpAddr, String>,
    vrf: &str,
    addr: std::net::IpAddr,
) {
    if let Some(owner) = index.get(&addr)
        && owner == vrf
    {
        index.remove(&addr);
    }
}

/// Kernel VRF master info as observed by `Bgp` via
/// `RibRx::VrfAdd`. Used by [`Bgp::maybe_respawn_vrf_with_kernel_ctx`]
/// to lift a step-14 placeholder `ProtoContext` to a real
/// `ProtoContext::for_vrf(rib, table_id, name)`.
#[derive(Debug, Clone, Copy)]
pub struct RibKnownVrf {
    pub table_id: u32,
    #[allow(dead_code)] // read by step 16's accept dispatcher.
    pub ifindex: u32,
}

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
    /// Spawn-time runtime context. Bundles the `RibClient` (sends
    /// to RIB through `self.ctx.rib`) with the VRF identity the
    /// socket factories on `ctx` consult — so BGP code calls
    /// `self.ctx.tcp_listen(...)` / `self.ctx.tcp_socket_v*()`
    /// without ever branching on whether it's the default routing
    /// table or a future VRF instance.
    pub ctx: ProtoContext,
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

    /// Color → Flex-Algorithm binding table
    /// (zebra-bgp-color-policy.yang). Storage-only on landing — the
    /// color-aware nexthop resolver (Phase 3 of the BGP ↔ Flex-Algo
    /// plan) reads this to pick a per-algo entry from
    /// `Isis::rib_flex_algo` when a route carries a Color extcomm.
    pub color_policy: super::color_policy::ColorPolicy,
    /// `dynamic-neighbors` runtime (zebra-bgp-dynamic-neighbors.yang).
    /// Holds the configured listen-ranges and the soft cap on
    /// materialized passive peers. `dynamic_peer_count` is bumped on
    /// successful accept-time materialization in `peer::accept`; it
    /// is never decremented yet — session-close GC is deferred to a
    /// follow-up so this PR stays focused on the accept path.
    pub dynamic_neighbors: super::dynamic_neighbors::DynamicNeighbors,
    pub dynamic_peer_count: u32,
    /// `interface-neighbor` config — operator types
    /// `set router bgp interface-neighbor <name>`. Lookup key is the
    /// interface name; the runtime resolves to ifindex via
    /// [`Self::link_index_by_name`] when an RA arrives and triggers
    /// peer materialization. Materialization itself happens in
    /// [`super::interface_neighbor::materialize_peer`].
    pub interface_neighbors: BTreeMap<String, super::interface_neighbor::InterfaceNeighborCfg>,
    /// Staged per-VRF BGP intent — populated by the callbacks for
    /// `/router/bgp/vrf/<name>/...` (zebra-bgp-vrf.yang, steps 11
    /// and 12). Diffed against [`Self::vrf_registry`] at each
    /// `CommitEnd` to drive [`super::vrf::spawn_bgp_vrf`] and
    /// [`super::vrf::despawn_bgp_vrf`] (step 14).
    pub vrfs: BTreeMap<String, super::vrf_config::BgpVrfConfig>,
    /// Per-VRF tasks currently running. The diff against
    /// [`Self::vrfs`] at `CommitEnd` spawns the names that show up
    /// in the desired set but not here, and despawns names that
    /// show up here but not in the desired set. Step 15 lifts the
    /// step-14 placeholder `ProtoContext::default_table_no_rib`
    /// to a real `ProtoContext::for_vrf(rib, table_id, name)` when
    /// [`Self::rib_known_vrfs`] gains the matching kernel info via
    /// `RibRx::VrfAdd`.
    pub vrf_registry: BTreeMap<String, super::vrf::BgpVrfHandle>,
    /// Kernel VRF master devices RIB has told us about, keyed by
    /// VRF name. Populated by `RibRx::VrfAdd` (and replayed from
    /// `Rib::subscribe`). Step 15 consults this at per-VRF spawn
    /// time to build a real `ProtoContext::for_vrf`; when the kernel
    /// info isn't yet known the spawn falls back to a placeholder
    /// context and the entry gets a respawn the moment `VrfAdd`
    /// arrives.
    pub rib_known_vrfs: BTreeMap<String, RibKnownVrf>,
    /// Send-capable RIB-subscription handle, cloned from
    /// `ConfigManager::rib_subscriber()` at spawn time. The
    /// per-VRF spawn site uses this to mint a fresh `RibClient`
    /// plus `Subscribe` with the VRF's kernel `table_id`, so the
    /// step-9 inbound dispatcher routes route installs into
    /// `vrf_tables[table_id]`.
    pub rib_subscriber: crate::config::RibSubscriber,
    /// Inbound `:179` dispatch index — peer source IP to VRF name.
    /// Populated by [`super::vrf::BgpGlobalMsg::RegisterPeer`]
    /// each per-VRF task emits at spawn / materialise time, and
    /// drained on `UnregisterPeer`. Step 16's accept handler
    /// consults this: a connection from an IP claimed by some VRF
    /// is forwarded via `BgpVrfMsg::Accept` to that VRF's task;
    /// every other connection falls through to the existing
    /// global-instance accept path.
    pub peer_index: BTreeMap<std::net::IpAddr, String>,
    /// Outbound sender every per-VRF task uses to push messages
    /// back to the global runtime — peer registration, exports,
    /// withdraws. Cloned into [`super::vrf::BgpVrf::global_tx`] at
    /// spawn time so all VRFs fan in to one channel here.
    pub vrf_global_tx: UnboundedSender<super::vrf::BgpGlobalMsg>,
    /// Receiver paired with [`Self::vrf_global_tx`], drained in
    /// the event loop. Step 14 logs each variant at debug; the
    /// real handlers wire in at step 16 (peer register / accept
    /// dispatch) and step 17 (export -> VPNv4/v6).
    pub vrf_global_rx: UnboundedReceiver<super::vrf::BgpGlobalMsg>,
    /// `if-name` → `ifindex` mirror fed by `RibRx::LinkAdd`. Needed
    /// because the YANG callback receives a name but
    /// `PeerKey::Interface` keys on ifindex. Lookups that miss
    /// (config staged before the link surfaces) defer materialization
    /// until the next link-add event.
    pub link_index_by_name: BTreeMap<String, u32>,
    /// Per-ifindex IPv6 link-local registry, populated from
    /// `RibRx::AddrAdd`/`AddrDel`. Source of the v6 next-hop emitted
    /// in MP_REACH for IPv4-unicast advertisements on interface peers
    /// (RFC 8950). See [`super::interface_addrs`].
    pub interface_addrs: super::interface_addrs::InterfaceAddrs,
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
    /// Receive half of the ND `NeighborDiscovered` subscription. ND's
    /// engine sends here whenever a Router Advertisement arrives on
    /// an interface; the BGP event loop drains it and materializes
    /// an interface-keyed Peer for any matching `interface-neighbor`
    /// config.
    pub nd_event_rx: UnboundedReceiver<crate::nd::engine::NdEvent>,
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
        ctx: ProtoContext,
        rib_rx: UnboundedReceiver<RibRx>,
        rib_subscriber: crate::config::RibSubscriber,
        policy_tx: UnboundedSender<policy::Message>,
        bfd_client_tx: Option<UnboundedSender<crate::bfd::inst::ClientReq>>,
        nd_client_tx: Option<UnboundedSender<crate::nd::inst::NdClientReq>>,
    ) -> Self {
        let policy_chan = PolicyRxChannel::new();
        let msg = policy::Message::Subscribe {
            proto: "bgp".into(),
            tx: policy_chan.tx.clone(),
        };
        let _ = policy_tx.send(msg);

        let (tx, rx) = mpsc::channel(8192);
        let (bfd_event_tx, bfd_event_rx) = mpsc::unbounded_channel();
        // Fan-in channel: every per-VRF task gets a clone of
        // `vrf_global_tx_init` at spawn time, so all VRF→global
        // messages land on one receiver in the global event loop.
        let (vrf_global_tx_init, vrf_global_rx_init) = mpsc::unbounded_channel();

        // Subscribe to ND `NeighborDiscovered` events so the BGP
        // unnumbered runtime can materialize an interface-keyed Peer
        // when an RA reveals the remote's link-local. If ND failed
        // to start (no `CAP_NET_RAW`), the channel pair is created
        // but no events ever arrive — the BGP event loop just sits
        // on a dead arm.
        let (nd_event_tx, nd_event_rx) = mpsc::unbounded_channel();
        if let Some(ref tx) = nd_client_tx {
            let _ = tx.send(crate::nd::inst::NdClientReq::SetNotifier { tx: nd_event_tx });
        }
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
            ctx,
            rib_rx,
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
            color_policy: super::color_policy::ColorPolicy::new(),
            dynamic_neighbors: super::dynamic_neighbors::DynamicNeighbors::default(),
            dynamic_peer_count: 0,
            interface_neighbors: super::interface_neighbor::empty_map(),
            vrfs: BTreeMap::new(),
            vrf_registry: BTreeMap::new(),
            rib_known_vrfs: BTreeMap::new(),
            rib_subscriber,
            peer_index: BTreeMap::new(),
            vrf_global_tx: vrf_global_tx_init,
            vrf_global_rx: vrf_global_rx_init,
            link_index_by_name: BTreeMap::new(),
            interface_addrs: super::interface_addrs::InterfaceAddrs::new(),
            update_groups: super::update_group::empty_map(),
            debug_flags: BgpDebugFlags::default(),
            policy_tx,
            policy_rx: policy_chan.rx,
            bfd_client_tx,
            bfd_event_tx,
            bfd_event_rx,
            nd_event_rx,
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
                // Capture peer state before the FSM mutates it so we
                // can detect the "session just ended" transition for
                // dynamic-peer GC below.
                let prev_state = self.peers.get_by_idx(ident).map(|p| p.state);

                let mut bgp_ref = BgpTop {
                    router_id: &self.router_id,
                    local_rib: &mut self.local_rib,
                    tx: &self.tx,
                    rib_client: &self.ctx.rib,
                    attr_store: &mut self.attr_store,
                    update_groups: &mut self.update_groups,
                    interface_addrs: &self.interface_addrs,
                };

                fsm(&mut bgp_ref, &mut self.peers, ident, event);

                self.gc_dynamic_peer_if_session_ended(ident, prev_state);
            }
            Message::Accept(socket, sockaddr) => {
                // Step 16: if the source IP is claimed by a per-VRF
                // task, hand the connection off there. The receiving
                // task picks up the stream from `BgpVrfMsg::Accept`
                // and continues the FSM. Unclaimed addresses fall
                // through to the existing global-instance accept
                // path — that's how default-VRF peers and the
                // dynamic-neighbor fallback still work.
                let src_ip = sockaddr.ip();
                if let Some(vrf_name) = self.peer_index.get(&src_ip).cloned()
                    && let Some(handle) = self.vrf_registry.get(&vrf_name)
                {
                    let msg = super::vrf::msg::BgpVrfMsg::Accept(socket, sockaddr);
                    if handle.inbox.send(msg).is_err() {
                        tracing::warn!(
                            peer = %src_ip,
                            vrf = %vrf_name,
                            "bgp: VRF task gone while routing inbound accept; dropping connection",
                        );
                    }
                } else {
                    accept(self, socket, sockaddr);
                }
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
                    &self.interface_addrs,
                );
            }
        }
    }

    /// GC a `PeerOrigin::Dynamic` peer whose session just ended.
    ///
    /// Triggered after every FSM call in [`Self::process_msg`]. The
    /// condition is `prev_state ∈ {OpenSent, OpenConfirm, Established}`
    /// AND `current_state ∈ {Idle, Active}` — i.e. the peer had a real
    /// TCP session in flight that is now gone. Removing the peer
    /// frees its `listen-limit` slot; the next inbound SYN from the
    /// same source re-materializes via the accept path.
    ///
    /// Static peers are untouched — they stay in `PeerMap` so a config
    /// change or reconnect attempt can revive them.
    fn gc_dynamic_peer_if_session_ended(
        &mut self,
        ident: usize,
        prev_state: Option<super::peer::State>,
    ) {
        use super::peer::State;
        use super::peer_key::PeerOrigin;

        let Some(prev) = prev_state else { return };
        let session_was_alive = matches!(
            prev,
            State::OpenSent | State::OpenConfirm | State::Established
        );
        if !session_was_alive {
            return;
        }
        let Some(peer) = self.peers.get_by_idx(ident) else {
            return;
        };
        if !matches!(peer.origin, PeerOrigin::Dynamic { .. }) {
            return;
        }
        if !matches!(peer.state, State::Idle | State::Active) {
            return;
        }
        let addr = peer.address;
        self.peers.remove(&addr);
        self.dynamic_peer_count = self.dynamic_peer_count.saturating_sub(1);
    }

    pub fn peer_comps(&self) -> Vec<String> {
        self.peers
            .keys()
            .map(|addr| addr.to_string().clone())
            .collect()
    }

    /// Reconcile [`Self::vrfs`] (desired set, populated by step 12
    /// callbacks) against [`Self::vrf_registry`] (running set):
    /// spawn the additions, despawn the removals. Called from
    /// `CommitEnd` once per commit.
    fn apply_vrf_commit_diff(&mut self) {
        let (to_spawn, to_despawn) = super::vrf::compute_vrf_diff(&self.vrfs, &self.vrf_registry);

        for name in to_despawn {
            if let Some(handle) = self.vrf_registry.remove(&name) {
                super::vrf::despawn_bgp_vrf(&name, &handle);
                // Drop every `peer_index` entry that pointed at
                // this VRF — defensive cleanup against the VRF
                // task exiting before its `UnregisterPeer`
                // messages have been processed.
                self.peer_index.retain(|_, owner| owner != &name);
            }
        }

        for name in to_spawn {
            // `to_spawn` came from a key iteration on `self.vrfs`;
            // the entry is guaranteed to still be present.
            let Some(cfg) = self.vrfs.get(&name).cloned() else {
                continue;
            };
            let kernel = self.rib_known_vrfs.get(&name).copied();
            let handle = super::vrf::spawn_bgp_vrf(
                name.clone(),
                &cfg,
                self.router_id,
                self.asn,
                kernel,
                &self.rib_subscriber,
                self.vrf_global_tx.clone(),
            );
            self.vrf_registry.insert(name, handle);
        }
    }

    /// Called when `RibRx::VrfAdd` for `name` arrives. If a step-14
    /// placeholder per-VRF task is already running for this name,
    /// tear it down and respawn it with the real
    /// `ProtoContext::for_vrf` so the `SO_BINDTODEVICE` binding
    /// kicks in. If the VRF intent hasn't been committed yet, this
    /// is a no-op — the next `apply_vrf_commit_diff` will pick up
    /// the kernel info via [`Self::rib_known_vrfs`].
    fn maybe_respawn_vrf_with_kernel_ctx(&mut self, name: &str) {
        // Nothing to do if there's no BGP intent for this VRF yet.
        let Some(cfg) = self.vrfs.get(name).cloned() else {
            return;
        };
        // Likewise if nothing is currently running for the name —
        // the next `apply_vrf_commit_diff` will spawn it.
        if !self.vrf_registry.contains_key(name) {
            return;
        }
        let Some(kernel) = self.rib_known_vrfs.get(name).copied() else {
            return;
        };
        // Tear the placeholder-ctx task down before spawning the
        // real one. `despawn_bgp_vrf` sends Shutdown; the handle
        // drop right after aborts the runtime if the loop hasn't
        // yet drained the signal.
        if let Some(handle) = self.vrf_registry.remove(name) {
            super::vrf::despawn_bgp_vrf(name, &handle);
            // Clear stale `peer_index` entries — the spawned task
            // is about to push fresh RegisterPeer messages.
            self.peer_index.retain(|_, owner| owner != name);
        }
        let new_handle = super::vrf::spawn_bgp_vrf(
            name.to_string(),
            &cfg,
            self.router_id,
            self.asn,
            Some(kernel),
            &self.rib_subscriber,
            self.vrf_global_tx.clone(),
        );
        self.vrf_registry.insert(name.to_string(), new_handle);
        tracing::info!(
            vrf = %name,
            table_id = kernel.table_id,
            "bgp: respawned per-VRF task with real ProtoContext::for_vrf",
        );
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
                // Step 12 observed the per-VRF intent at debug;
                // step 14 turns the observation into action: diff
                // `self.vrfs` (desired) against `self.vrf_registry`
                // (running), spawn the additions, despawn the
                // removals. Edits to an already-spawned VRF aren't
                // detected here — step 15 layers cfg-hash
                // comparison on top.
                super::vrf_config::log_commit_diff(self);
                self.apply_vrf_commit_diff();
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
        match self.ctx.tcp_listen("0.0.0.0:179".parse().unwrap()).await {
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
        match self
            .ctx
            .tcp_listen_v6_only("[::]:179".parse().unwrap())
            .await
        {
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
            RibRx::LinkAdd(link) => {
                // Maintain the name↔ifindex mirror used by
                // interface-neighbor materialization. Keeps the most
                // recent name for an ifindex; renames are rare but
                // covered by simple insert-replaces-on-collision.
                self.link_index_by_name
                    .insert(link.name.clone(), link.index);
            }
            RibRx::AddrAdd(addr) => {
                self.interface_addrs.record(&addr);
            }
            RibRx::AddrDel(addr) => {
                self.interface_addrs.forget(&addr);
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
            RibRx::VrfAdd {
                name,
                table_id,
                ifindex,
            } => {
                self.rib_known_vrfs
                    .insert(name.clone(), RibKnownVrf { table_id, ifindex });
                // If the operator already committed `router bgp vrf
                // <name> ...` and the step-14 placeholder context
                // is in place, swap it for a real `for_vrf` now. The
                // placeholder spawn happened before the kernel had
                // assigned `table_id`; without this respawn the
                // `SO_BINDTODEVICE` binding step 8 installed would
                // never fire for that VRF.
                self.maybe_respawn_vrf_with_kernel_ctx(&name);
            }
            RibRx::VrfDel { name } => {
                self.rib_known_vrfs.remove(&name);
                // No despawn here — the VRF could come back, and the
                // per-VRF task carries the YANG intent. If the
                // operator subsequently deletes the BGP VRF block,
                // step 14's `apply_vrf_commit_diff` handles teardown.
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
                Some(event) = self.nd_event_rx.recv() => {
                    self.process_nd_event(event);
                }
                Some(msg) = self.vrf_global_rx.recv() => {
                    // VRF→global fan-in. Step 14 just logs each
                    // variant — the real handlers wire in later
                    // (step 16: peer register / accept dispatch;
                    // step 17: Export → VPNv4/v6).
                    self.process_vrf_global_msg(msg);
                }
            }
        }
    }

    fn process_vrf_global_msg(&mut self, msg: super::vrf::BgpGlobalMsg) {
        match msg {
            super::vrf::BgpGlobalMsg::Export { vrf } => {
                tracing::debug!(vrf = %vrf, "bgp: ignored Export (step 17 wires the handler)");
            }
            super::vrf::BgpGlobalMsg::WithdrawExport { vrf } => {
                tracing::debug!(
                    vrf = %vrf,
                    "bgp: ignored WithdrawExport (step 17 wires the handler)",
                );
            }
            super::vrf::BgpGlobalMsg::RegisterPeer { vrf, addr } => {
                peer_index_register(&mut self.peer_index, vrf, addr);
            }
            super::vrf::BgpGlobalMsg::UnregisterPeer { vrf, addr } => {
                peer_index_unregister(&mut self.peer_index, &vrf, addr);
            }
        }
    }

    /// Handle an ND `NeighborDiscovered` notification by checking for
    /// a configured `interface-neighbor` on the matching ifindex and,
    /// if found, materializing the peer. The lookup is a linear scan
    /// of `link_index_by_name` since the operator-typed leaf is keyed
    /// by name; for typical (single-digit) interface-neighbor counts
    /// this is fine, and it lets the config use the friendly name in
    /// `show bgp summary`.
    fn process_nd_event(&mut self, event: crate::nd::engine::NdEvent) {
        let crate::nd::engine::NdEvent::NeighborDiscovered { ifindex, src } = event;
        let name = self
            .link_index_by_name
            .iter()
            .find(|(_, idx)| **idx == ifindex)
            .map(|(name, _)| name.clone());
        let Some(name) = name else {
            // RA arrived on an interface RIB hasn't told us about yet
            // — possible during early startup. Drop; the next RA will
            // re-trigger this path.
            return;
        };
        super::interface_neighbor::materialize_peer(self, &name, ifindex, src);
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

#[cfg(test)]
mod tests {
    //! Pure-function tests on the step-16 `peer_index` mutations.
    //! Building a full `Bgp` to drive `process_vrf_global_msg`
    //! end-to-end would require netlink — out of reach for unit
    //! tests; the BDD scenarios in step 21 cover that. Here we
    //! exercise the index helpers directly.
    use std::collections::BTreeMap;
    use std::net::IpAddr;

    use super::{peer_index_register, peer_index_unregister};

    fn addr(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn register_inserts_the_mapping() {
        let mut index: BTreeMap<IpAddr, String> = BTreeMap::new();
        peer_index_register(&mut index, "vrfA".to_string(), addr("192.0.2.1"));
        assert_eq!(index.get(&addr("192.0.2.1")), Some(&"vrfA".to_string()));
    }

    #[test]
    fn register_overrides_a_conflicting_owner() {
        // FRR-style "most recent wins" behaviour. A different
        // VRF claiming the same peer IP is a config error the
        // operator must fix, but we don't refuse the update.
        let mut index: BTreeMap<IpAddr, String> = BTreeMap::new();
        peer_index_register(&mut index, "vrfA".to_string(), addr("192.0.2.1"));
        peer_index_register(&mut index, "vrfB".to_string(), addr("192.0.2.1"));
        assert_eq!(index.get(&addr("192.0.2.1")), Some(&"vrfB".to_string()));
    }

    #[test]
    fn re_register_same_owner_is_idempotent() {
        let mut index: BTreeMap<IpAddr, String> = BTreeMap::new();
        peer_index_register(&mut index, "vrfA".to_string(), addr("192.0.2.1"));
        peer_index_register(&mut index, "vrfA".to_string(), addr("192.0.2.1"));
        assert_eq!(index.get(&addr("192.0.2.1")), Some(&"vrfA".to_string()));
        assert_eq!(index.len(), 1);
    }

    #[test]
    fn unregister_drops_only_when_owner_matches() {
        // Defends against a stale `UnregisterPeer` arriving from
        // a VRF that no longer owns the address (operator moved
        // the peer to a different VRF since).
        let mut index: BTreeMap<IpAddr, String> = BTreeMap::new();
        peer_index_register(&mut index, "vrfB".to_string(), addr("192.0.2.1"));
        peer_index_unregister(&mut index, "vrfA", addr("192.0.2.1"));
        assert_eq!(
            index.get(&addr("192.0.2.1")),
            Some(&"vrfB".to_string()),
            "stale Unregister from vrfA must not strip vrfB's claim",
        );
        peer_index_unregister(&mut index, "vrfB", addr("192.0.2.1"));
        assert!(index.is_empty());
    }

    #[test]
    fn unregister_unknown_addr_is_noop() {
        let mut index: BTreeMap<IpAddr, String> = BTreeMap::new();
        peer_index_unregister(&mut index, "vrfA", addr("203.0.113.1"));
        assert!(index.is_empty());
    }
}
