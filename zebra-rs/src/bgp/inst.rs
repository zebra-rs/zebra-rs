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
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

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

#[derive(Debug)]
pub enum Message {
    Event(usize, Event),
    Accept(TcpStream, SocketAddr),
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

/// Append `export_rts` to `attr.ecom` as Route-Target extended
/// communities (RFC 4360 §4.1 — subtype `0x02`). RTs share the
/// 6-octet on-wire encoding with RDs; the `From<RouteDistinguisher>`
/// impl picks the right high_type (Two-Octet-AS vs IPv4) but
/// leaves `low_type = 0`, so step 17b-ii sets it to `0x02` to
/// mark each entry as RT. Returns `attr` unchanged when the
/// export-RT set is empty.
pub(crate) fn tag_attr_with_export_rts(
    mut attr: bgp_packet::BgpAttr,
    export_rts: &std::collections::BTreeSet<bgp_packet::RouteDistinguisher>,
) -> bgp_packet::BgpAttr {
    use bgp_packet::{ExtCommunity, ExtCommunityValue};

    if export_rts.is_empty() {
        return attr;
    }
    let mut ecom = attr.ecom.take().unwrap_or_default();
    for rt in export_rts {
        let mut val: ExtCommunityValue = (*rt).into();
        // RFC 4360 §4 — Route Target sub-type. The `From<RD>` impl
        // sets `high_type` per ASN-vs-IPv4 RD but leaves the
        // sub-type at the default 0; flipping it here is what
        // distinguishes RT from Route-Origin (sub-type 0x03).
        val.low_type = 0x02;
        ecom.0.push(val);
    }
    attr.ecom = Some(ExtCommunity(ecom.0));
    attr
}

/// Walk `vrf_index` and return every VRF name whose
/// `import_rts_v4` intersects the route's Route-Target extended
/// communities in `ecom`. RTs on the wire are distinguished from
/// other extended communities by the (`high_type`, `low_type`)
/// pair — RFC 4360 §4.1 puts the sub-type at `low_type = 0x02`.
/// Routes with no RT extcomms match no VRF; routes with RTs that
/// no configured VRF imports match no VRF either (and the global
/// VPNv4 row sits in `local_rib.v4vpn` unimported).
pub(crate) fn matching_import_vrfs(
    vrf_index: &BTreeMap<String, RibKnownVrf>,
    ecom: &Option<bgp_packet::ExtCommunity>,
) -> Vec<String> {
    let Some(ecom) = ecom else {
        return Vec::new();
    };
    // Build the set of RTs the route carries: every extcomm with
    // RT sub-type, reinterpreted as a `RouteDistinguisher` (RT and
    // RD share the on-wire 6-octet shape — same trick as step 17a).
    let route_rts: std::collections::BTreeSet<bgp_packet::RouteDistinguisher> = ecom
        .0
        .iter()
        .filter(|v| v.low_type == 0x02)
        .map(|v| {
            use bgp_packet::RouteDistinguisherType;
            // high_type 0x00 = Two-Octet AS, 0x01 = IPv4. Anything
            // else (0x02 = 4-byte AS, future types) maps onto ASN
            // by default — `RouteDistinguisher::PartialEq` is per-
            // byte so a 4-byte ASN extcomm just won't intersect
            // any configured RT (the config builder rejects 4-byte
            // ASN strings today).
            let typ = if v.high_type == 0x01 {
                RouteDistinguisherType::IP
            } else {
                RouteDistinguisherType::ASN
            };
            let mut rd = bgp_packet::RouteDistinguisher::new(typ);
            rd.val = v.val;
            rd
        })
        .collect();
    if route_rts.is_empty() {
        return Vec::new();
    }
    vrf_index
        .iter()
        .filter(|(_, info)| !info.import_rts_v4.is_disjoint(&route_rts))
        .map(|(name, _)| name.clone())
        .collect()
}

/// Kernel VRF master info as observed by `Bgp` via
/// `RibRx::VrfAdd` and the matching RT sets observed via
/// `RibRx::VrfRouteTargets`. Used by
/// [`Bgp::maybe_respawn_vrf_with_kernel_ctx`] to lift a step-14
/// placeholder `ProtoContext` to a real
/// `ProtoContext::for_vrf(rib, table_id, name)`; step 17b's
/// Export pipeline reads `export_rts_v4`/`v6` and step 18's
/// Import pipeline reads `import_rts_v4`/`v6`.
#[derive(Debug, Clone, Default)]
pub struct RibKnownVrf {
    pub table_id: u32,
    pub ifindex: u32,
    pub import_rts_v4: std::collections::BTreeSet<bgp_packet::RouteDistinguisher>,
    pub export_rts_v4: std::collections::BTreeSet<bgp_packet::RouteDistinguisher>,
    pub import_rts_v6: std::collections::BTreeSet<bgp_packet::RouteDistinguisher>,
    pub export_rts_v6: std::collections::BTreeSet<bgp_packet::RouteDistinguisher>,
}

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
    /// Snapshot of `/key-chains/key-chain <name>` entries pushed
    /// here by the policy actor via `PolicyRx::KeyChain`. The
    /// canonical map lives in `policy::Policy`; this is the
    /// per-neighbor-subscribed view BGP consults when resolving a
    /// peer's `tcp-ao/key-chain <name>` leafref. Updated by
    /// `process_policy_msg`.
    pub key_chains: BTreeMap<String, crate::policy::KeyChain>,

    /// IOS-XR-style `neighbor-group` definitions
    /// (zebra-bgp-neighbor-group.yang). Phase-1 storage: each entry
    /// holds the group's overridable defaults; field-level
    /// inheritance into peers that reference a group via
    /// `PeerConfig::neighbor_group` is not wired in the runtime
    /// yet — that lands in a follow-up.
    pub neighbor_groups: BTreeMap<String, super::neighbor_group::NeighborGroup>,

    /// Color → Flex-Algorithm binding table
    /// (zebra-bgp-color-policy.yang). The colour-aware nexthop
    /// resolver consults this to pick a per-algo entry from
    /// `flex_algo_routes` when a route carries a Color extcomm.
    pub color_policy: super::color_policy::ColorPolicy,

    /// Local shadow of `Rib::flex_algo_routes`, populated by
    /// `RibRx::FlexAlgoRouteAdd/Del` events emitted from IS-IS via
    /// RIB (PR #697). Outer key is the IS-IS Flex-Algorithm id; inner
    /// map is the per-algo IPv4 RIB. The colour-aware resolver does
    /// a longest-prefix match on the BGP next-hop against the
    /// inner map for the algo bound to the route's Color extcomm,
    /// and pushes the resulting outer MPLS label onto the FIB
    /// install.
    pub flex_algo_routes:
        BTreeMap<u8, prefix_trie::PrefixMap<ipnet::Ipv4Net, crate::rib::api::FlexAlgoNexthop>>,
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
    /// Per-VRF MPLS label allocator (step 19a). Hands out one
    /// label per `spawn_bgp_vrf` call; reclaims at despawn. The
    /// label gets stamped onto every `BgpGlobalMsg::Export` the
    /// VRF emits and (step 19b) drives the matching ILM Decap
    /// install on the PE.
    pub vrf_label_alloc: super::vrf::VrfLabelAllocator,
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

    /// Global MinRouteAdvertisementInterval (MRAI) per RFC 4271
    /// §9.2.1.1, split by peer type. Source of truth for the per-Peer
    /// / per-UpdateGroup `adv_interval` snapshots. Configured under
    /// `router bgp timer adv-interval { ibgp; ebgp; }`.
    pub adv_interval: super::timer::AdvInterval,
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
            key_chains: BTreeMap::new(),
            neighbor_groups: super::neighbor_group::empty_map(),
            color_policy: super::color_policy::ColorPolicy::new(),
            flex_algo_routes: BTreeMap::new(),
            dynamic_neighbors: super::dynamic_neighbors::DynamicNeighbors::default(),
            dynamic_peer_count: 0,
            interface_neighbors: super::interface_neighbor::empty_map(),
            vrfs: BTreeMap::new(),
            vrf_registry: BTreeMap::new(),
            rib_known_vrfs: BTreeMap::new(),
            rib_subscriber,
            vrf_label_alloc: super::vrf::VrfLabelAllocator::new(),
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
            adv_interval: super::timer::AdvInterval::default(),
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

                // Step 18a: the global v4vpn ingest path uses this
                // dispatcher to fan accepted VPNv4 routes out to
                // every VRF whose `import_rts_v4` matches. Borrows
                // are disjoint from the BgpTop mutable refs below
                // (`rib_known_vrfs` and `vrf_registry` are different
                // fields).
                let import_dispatcher = super::vrf::VrfImportDispatcher {
                    rib_known_vrfs: &self.rib_known_vrfs,
                    vrf_registry: &self.vrf_registry,
                };

                let mut bgp_ref = BgpTop {
                    router_id: &self.router_id,
                    local_rib: &mut self.local_rib,
                    tx: &self.tx,
                    rib_client: &self.ctx.rib,
                    attr_store: &mut self.attr_store,
                    update_groups: &mut self.update_groups,
                    interface_addrs: &self.interface_addrs,
                    vrf_export: None,
                    color_policy: Some(&self.color_policy),
                    flex_algo_routes: Some(&self.flex_algo_routes),
                    vrf_import: Some(&import_dispatcher),
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
                // Step 19b: withdraw the AF_MPLS DecapVrf ILM
                // ahead of returning the label. The netlink
                // delete keys off the label alone so the
                // IlmEntry contents are mostly informational —
                // any non-zero match on `rtype = Bgp` works.
                if let Some(vrf_ifindex) = handle.ilm_decap_ifindex {
                    let entry = crate::rib::inst::IlmEntry {
                        rtype: crate::rib::RibType::Bgp,
                        ilm_type: crate::rib::inst::IlmType::DecapVrf {
                            table_id: 0,
                            vrf_ifindex,
                        },
                        nexthop: crate::rib::Nexthop::default(),
                    };
                    self.rib_subscriber.send_ilm_del(handle.label, entry);
                }
                // Return the label to the pool so a future VRF
                // can pick it back up. Reclaim before the handle
                // drops — handle drop aborts the task but doesn't
                // know about the allocator.
                self.vrf_label_alloc.free(handle.label);
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
            let kernel = self.rib_known_vrfs.get(&name).cloned();
            // Allocate a fresh MPLS label for this VRF — used in
            // every `BgpGlobalMsg::Export` it emits and (step 19b)
            // bound to an AF_MPLS ILM for PE-side decap. The
            // 20-bit label space is large enough that the
            // `.unwrap_or(0)` fallback effectively never fires;
            // 0 would mean "no label" downstream, which the
            // Export handler already treats as "skip label
            // install" — a safe degradation.
            let label = self.vrf_label_alloc.alloc().unwrap_or(0);
            let handle = super::vrf::spawn_bgp_vrf(
                name.clone(),
                &cfg,
                self.router_id,
                self.asn,
                label,
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
        let Some(kernel) = self.rib_known_vrfs.get(name).cloned() else {
            return;
        };
        // Tear the placeholder-ctx task down before spawning the
        // real one. `despawn_bgp_vrf` sends Shutdown; the handle
        // drop right after aborts the runtime if the loop hasn't
        // yet drained the signal. Preserve the existing label so
        // the respawn stays addressable from any PE that already
        // cached it; the original allocation stays held on the
        // new handle.
        let preserved_label = if let Some(handle) = self.vrf_registry.remove(name) {
            super::vrf::despawn_bgp_vrf(name, &handle);
            // Clear stale `peer_index` entries — the spawned task
            // is about to push fresh RegisterPeer messages.
            self.peer_index.retain(|_, owner| owner != name);
            handle.label
        } else {
            self.vrf_label_alloc.alloc().unwrap_or(0)
        };
        let table_id = kernel.table_id;
        let new_handle = super::vrf::spawn_bgp_vrf(
            name.to_string(),
            &cfg,
            self.router_id,
            self.asn,
            preserved_label,
            Some(kernel),
            &self.rib_subscriber,
            self.vrf_global_tx.clone(),
        );
        self.vrf_registry.insert(name.to_string(), new_handle);
        tracing::info!(
            vrf = %name,
            table_id,
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
                // Preserve any RT cache already populated from a
                // prior `VrfRouteTargets` (e.g. when the operator
                // sets RTs in the same commit as the VRF itself
                // and they happen to arrive before `VrfAdd`).
                let prev_rts = self.rib_known_vrfs.remove(&name);
                let entry = RibKnownVrf {
                    table_id,
                    ifindex,
                    import_rts_v4: prev_rts
                        .as_ref()
                        .map(|p| p.import_rts_v4.clone())
                        .unwrap_or_default(),
                    export_rts_v4: prev_rts
                        .as_ref()
                        .map(|p| p.export_rts_v4.clone())
                        .unwrap_or_default(),
                    import_rts_v6: prev_rts
                        .as_ref()
                        .map(|p| p.import_rts_v6.clone())
                        .unwrap_or_default(),
                    export_rts_v6: prev_rts
                        .as_ref()
                        .map(|p| p.export_rts_v6.clone())
                        .unwrap_or_default(),
                };
                self.rib_known_vrfs.insert(name.clone(), entry);
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
            RibRx::VrfRouteTargets {
                name,
                ipv4_import_rts,
                ipv4_export_rts,
                ipv6_import_rts,
                ipv6_export_rts,
            } => {
                // Mutate-in-place if a `VrfAdd` already populated
                // the row; otherwise stage the RT cache so a later
                // `VrfAdd` picks it up (defensive against
                // out-of-order delivery — step 15a's replay
                // contract puts VrfAdd first, but the active
                // commit path sends them as separate messages and
                // a slow `tokio::select!` could draw the RT
                // message ahead of the VrfAdd).
                let entry = self.rib_known_vrfs.entry(name).or_default();
                entry.import_rts_v4 = ipv4_import_rts;
                entry.export_rts_v4 = ipv4_export_rts;
                entry.import_rts_v6 = ipv6_import_rts;
                entry.export_rts_v6 = ipv6_export_rts;
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
            // IS-IS per-algo routes published via RIB (#697). We
            // shadow only the first nexthop per (algo, prefix); a
            // future ECMP-aware resolver can extend this to walk the
            // full set.
            RibRx::FlexAlgoRouteAdd { route } => {
                if let Some(nh) = route.nexthops.into_iter().next() {
                    self.flex_algo_routes
                        .entry(route.algo)
                        .or_default()
                        .insert(route.prefix, nh);
                } else {
                    // Defensive: a FlexAlgoRoute with zero nexthops
                    // is meaningless; treat it as a delete.
                    if let Some(table) = self.flex_algo_routes.get_mut(&route.algo) {
                        table.remove(&route.prefix);
                    }
                }
            }
            RibRx::FlexAlgoRouteDel { algo, prefix } => {
                let became_empty = if let Some(table) = self.flex_algo_routes.get_mut(&algo) {
                    table.remove(&prefix);
                    table.iter().next().is_none()
                } else {
                    false
                };
                if became_empty {
                    self.flex_algo_routes.remove(&algo);
                }
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
            policy::PolicyRx::KeyChain {
                name, key_chain, ..
            } => {
                // Apply the snapshot delta first so any downstream
                // resolve() sees the new state. Then reconcile the
                // TCP-AO MKTs installed on the listening sockets so
                // a key edit lands on the kernel before the peer's
                // next SYN arrives.
                if let Some(kc) = key_chain {
                    self.key_chains.insert(name, kc);
                } else {
                    self.key_chains.remove(&name);
                }
                super::config::apply_ao_refresh_all(self);
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
            super::vrf::BgpGlobalMsg::Export {
                vrf,
                prefix,
                attr,
                label,
            } => {
                let Some(rd) = self.vrfs.get(&vrf).and_then(|cfg| cfg.rd) else {
                    tracing::warn!(
                        vrf = %vrf,
                        %prefix,
                        "bgp: export dropped — VRF has no RD configured",
                    );
                    return;
                };
                let export_rts = self
                    .rib_known_vrfs
                    .get(&vrf)
                    .map(|k| k.export_rts_v4.clone())
                    .unwrap_or_default();

                // Tag with export-RT extcommunities, then intern
                // the result in the global attr_store. The VRF
                // task sent us `attr` by value so it could be
                // mutated independently; this is the only place
                // the global instance interns it.
                let tagged = tag_attr_with_export_rts(attr, &export_rts);
                let interned = self.attr_store.intern(tagged);

                // VPNv4 NLRI carries a single MPLS label per route.
                // Step 19 wires a real per-VRF label allocator;
                // until then VRF tasks pass `0` and we treat that
                // as "no label allocated yet", which `make_bgp_rib_entry_v4`
                // and the VPNv4 emit path interpret as "skip
                // install / advertise" rather than emit the
                // explicit-null label.
                let label_obj = if label != 0 {
                    Some(bgp_packet::Label {
                        label,
                        exp: 0,
                        bos: true,
                    })
                } else {
                    None
                };

                let nexthop = bgp_packet::Vpnv4Nexthop {
                    rd,
                    nhop: self.router_id,
                };

                let rib = super::route::BgpRib {
                    remote_id: 0,
                    local_id: 0,
                    attr: interned,
                    ident: 0,
                    router_id: self.router_id,
                    weight: 0,
                    typ: super::route::BgpRibType::Originated,
                    best_path: false,
                    best_reason: super::route::Reason::Default,
                    label: label_obj,
                    nexthop: Some(nexthop),
                    egress_ifindex_v6: None,
                    stale: false,
                    esi: None,
                };

                let (_, selected, _gen) = self.local_rib.update(Some(rd), prefix, rib);
                let selected_len = selected.len();

                // Step 17c: fan out the new VPNv4 winner to PE
                // peers via the existing `route_advertise_to_peers`
                // helper. The helper iterates Established peers
                // matching (Afi=Ip, Safi=MplsVpn), runs split-
                // horizon + outbound policy + RTC, and pushes to
                // each peer's `cache_vpnv4` (debounced flush). The
                // global instance has `vrf_export = None`, so no
                // infinite loop on the export hook in
                // `route_ipv4_update`.
                let mut top = super::peer::BgpTop {
                    router_id: &self.router_id,
                    local_rib: &mut self.local_rib,
                    tx: &self.tx,
                    rib_client: &self.ctx.rib,
                    attr_store: &mut self.attr_store,
                    update_groups: &mut self.update_groups,
                    interface_addrs: &self.interface_addrs,
                    color_policy: Some(&self.color_policy),
                    flex_algo_routes: Some(&self.flex_algo_routes),
                    vrf_export: None,
                    vrf_import: None,
                };
                super::route::route_advertise_to_peers(
                    Some(rd),
                    prefix,
                    &selected,
                    /* source peer */ 0,
                    &mut top,
                    &mut self.peers,
                );

                tracing::info!(
                    vrf = %vrf,
                    %prefix,
                    rd = %rd,
                    export_rts = export_rts.len(),
                    label,
                    winners = selected_len,
                    "bgp: export written to LocalRib.v4vpn and advertised to PE peers",
                );
            }
            super::vrf::BgpGlobalMsg::WithdrawExport { vrf, prefix } => {
                let Some(rd) = self.vrfs.get(&vrf).and_then(|cfg| cfg.rd) else {
                    tracing::debug!(
                        vrf = %vrf,
                        %prefix,
                        "bgp: withdraw-export dropped — VRF has no RD configured",
                    );
                    return;
                };
                // VRF-originated routes always carry `ident == 0`
                // and `local_id == 0` (the values used in the
                // matching Export); the remove path uses that
                // tuple to identify the row.
                let removed = self.local_rib.remove(Some(rd), prefix, 0, 0);

                // Re-run best-path so any remaining candidate at
                // (rd, prefix) becomes the new selected winner.
                // Pass that result to `route_advertise_to_peers` —
                // empty `selected` triggers the Withdraw branch
                // there (`peer.adj_out` cleanup, MP_UNREACH emit).
                let selected = self.local_rib.select_best_path_vpn(&rd, prefix);
                let mut top = super::peer::BgpTop {
                    router_id: &self.router_id,
                    local_rib: &mut self.local_rib,
                    tx: &self.tx,
                    rib_client: &self.ctx.rib,
                    attr_store: &mut self.attr_store,
                    update_groups: &mut self.update_groups,
                    interface_addrs: &self.interface_addrs,
                    color_policy: Some(&self.color_policy),
                    flex_algo_routes: Some(&self.flex_algo_routes),
                    vrf_export: None,
                    vrf_import: None,
                };
                super::route::route_advertise_to_peers(
                    Some(rd),
                    prefix,
                    &selected,
                    /* source peer */ 0,
                    &mut top,
                    &mut self.peers,
                );

                tracing::info!(
                    vrf = %vrf,
                    %prefix,
                    rd = %rd,
                    removed = removed.len(),
                    winners = selected.len(),
                    "bgp: export withdrawn from LocalRib.v4vpn and PE peers",
                );
            }
            super::vrf::BgpGlobalMsg::RegisterPeer { vrf, addr } => {
                peer_index_register(&mut self.peer_index, vrf, addr);
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

    use super::peer_index_register;

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

    /// Step 17b-ii: helper that takes a `BgpAttr` and tags it with
    /// one `ExtCommunity` per RT in the export set. Sub-type 0x02
    /// distinguishes RT from Route Origin (sub-type 0x03);
    /// `high_type` (0x00 for ASN, 0x01 for IPv4) is carried over
    /// from the matching `RouteDistinguisher`.
    mod tag_attr {
        use std::str::FromStr;

        use bgp_packet::{BgpAttr, RouteDistinguisher};

        use super::super::tag_attr_with_export_rts;

        fn rt(s: &str) -> RouteDistinguisher {
            RouteDistinguisher::from_str(s).unwrap()
        }

        #[test]
        fn empty_export_set_returns_attr_unchanged() {
            // No exports configured -> no ExtCommunity added.
            // Critical: tagging an empty set would otherwise
            // create an empty `Some(ExtCommunity(vec![]))` and
            // upset the dedup pool's PartialEq.
            let attr = BgpAttr::default();
            let out = tag_attr_with_export_rts(attr.clone(), &Default::default());
            assert_eq!(out, attr);
        }

        #[test]
        fn single_rt_adds_one_extcom_with_subtype_2() {
            let mut rts = std::collections::BTreeSet::new();
            rts.insert(rt("65000:100"));

            let out = tag_attr_with_export_rts(BgpAttr::default(), &rts);
            let ecom = out.ecom.expect("ecom populated");
            assert_eq!(ecom.0.len(), 1);
            let entry = &ecom.0[0];
            // Two-byte ASN RD -> high_type 0x00.
            assert_eq!(entry.high_type, 0x00);
            assert_eq!(entry.low_type, 0x02, "RT sub-type per RFC 4360");
        }

        #[test]
        fn ipv4_rt_uses_high_type_1() {
            // The `From<RouteDistinguisher>` impl picks
            // `high_type = 0x01` for IPv4-shaped RDs; the
            // tagging helper must preserve that.
            let mut rts = std::collections::BTreeSet::new();
            rts.insert(rt("192.0.2.1:100"));

            let out = tag_attr_with_export_rts(BgpAttr::default(), &rts);
            let ecom = out.ecom.expect("ecom populated");
            assert_eq!(ecom.0.len(), 1);
            assert_eq!(ecom.0[0].high_type, 0x01);
            assert_eq!(ecom.0[0].low_type, 0x02);
        }

        #[test]
        fn multiple_rts_yield_one_extcom_per_rt() {
            let mut rts = std::collections::BTreeSet::new();
            rts.insert(rt("65000:1"));
            rts.insert(rt("65000:2"));
            rts.insert(rt("65001:3"));

            let out = tag_attr_with_export_rts(BgpAttr::default(), &rts);
            let ecom = out.ecom.expect("ecom populated");
            assert_eq!(ecom.0.len(), 3);
            for entry in &ecom.0 {
                assert_eq!(entry.low_type, 0x02);
            }
        }

        #[test]
        fn pre_existing_ecom_is_preserved() {
            // Caller-attached extcomms (colour, etc.) MUST NOT be
            // dropped by the RT tag — append, don't replace.
            let mut attr = BgpAttr::default();
            let preexisting = bgp_packet::ExtCommunityValue::from_color(0, 100);
            attr.ecom = Some(bgp_packet::ExtCommunity(vec![preexisting.clone()]));

            let mut rts = std::collections::BTreeSet::new();
            rts.insert(rt("65000:1"));

            let out = tag_attr_with_export_rts(attr, &rts);
            let ecom = out.ecom.expect("ecom populated");
            assert_eq!(ecom.0.len(), 2, "colour + RT");
            assert_eq!(ecom.0[0], preexisting, "colour stays at index 0");
            assert_eq!(ecom.0[1].low_type, 0x02, "RT appended");
        }
    }

    /// Step 18a: `matching_import_vrfs` walks `rib_known_vrfs`
    /// and returns every VRF whose `import_rts_v4` intersects
    /// the route's RT ext-communities.
    mod matching_import_vrfs_tests {
        use std::collections::{BTreeMap, BTreeSet};
        use std::str::FromStr;

        use bgp_packet::{ExtCommunity, ExtCommunityValue, RouteDistinguisher};

        use super::super::{RibKnownVrf, matching_import_vrfs};

        fn rt(s: &str) -> RouteDistinguisher {
            RouteDistinguisher::from_str(s).unwrap()
        }

        fn rt_extcom(rt_str: &str) -> ExtCommunityValue {
            let mut v: ExtCommunityValue = rt(rt_str).into();
            v.low_type = 0x02;
            v
        }

        fn vrf_with_imports(rts: &[&str]) -> RibKnownVrf {
            let mut import_rts_v4 = BTreeSet::new();
            for s in rts {
                import_rts_v4.insert(rt(s));
            }
            RibKnownVrf {
                table_id: 100,
                ifindex: 1,
                import_rts_v4,
                export_rts_v4: BTreeSet::new(),
                import_rts_v6: BTreeSet::new(),
                export_rts_v6: BTreeSet::new(),
            }
        }

        #[test]
        fn no_ecom_attr_matches_no_vrf() {
            // A VPNv4 route with no RT ext-communities can't be
            // imported anywhere.
            let mut index = BTreeMap::new();
            index.insert("v1".to_string(), vrf_with_imports(&["65000:1"]));
            assert!(matching_import_vrfs(&index, &None).is_empty());
        }

        #[test]
        fn empty_ecom_attr_matches_no_vrf() {
            let mut index = BTreeMap::new();
            index.insert("v1".to_string(), vrf_with_imports(&["65000:1"]));
            let ecom = Some(ExtCommunity::default());
            assert!(matching_import_vrfs(&index, &ecom).is_empty());
        }

        #[test]
        fn rt_matches_single_importing_vrf() {
            let mut index = BTreeMap::new();
            index.insert("v1".to_string(), vrf_with_imports(&["65000:1"]));
            index.insert("v2".to_string(), vrf_with_imports(&["65000:2"]));
            let ecom = Some(ExtCommunity(vec![rt_extcom("65000:1")]));
            assert_eq!(matching_import_vrfs(&index, &ecom), vec!["v1".to_string()]);
        }

        #[test]
        fn rt_matches_multiple_importing_vrfs() {
            // Two VRFs both import RT 65000:99. A route with that
            // RT should be delivered to both. Order follows
            // BTreeMap key iteration (sorted by name) — caller
            // doesn't depend on order but the test pins it for
            // determinism.
            let mut index = BTreeMap::new();
            index.insert("v1".to_string(), vrf_with_imports(&["65000:99"]));
            index.insert("v2".to_string(), vrf_with_imports(&["65000:99"]));
            let ecom = Some(ExtCommunity(vec![rt_extcom("65000:99")]));
            let mut got = matching_import_vrfs(&index, &ecom);
            got.sort();
            assert_eq!(got, vec!["v1".to_string(), "v2".to_string()]);
        }

        #[test]
        fn non_rt_extcomm_does_not_count_as_rt() {
            // An ext-community with low_type != 0x02 (e.g.
            // Route-Origin sub-type 0x03) must not be treated as
            // an RT — even if its 6-octet value happens to match
            // a configured RT.
            let mut origin: ExtCommunityValue = rt("65000:1").into();
            origin.low_type = 0x03;
            let mut index = BTreeMap::new();
            index.insert("v1".to_string(), vrf_with_imports(&["65000:1"]));
            let ecom = Some(ExtCommunity(vec![origin]));
            assert!(matching_import_vrfs(&index, &ecom).is_empty());
        }
    }
}
