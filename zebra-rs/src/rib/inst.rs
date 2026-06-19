use super::api::{FdbEntry, RibRx};
use super::client::{ClientRegistry, ProtoId, RibInbound};
use super::entry::RibEntry;
use super::link::{LinkConfig, link_config_exec};
use super::{
    Block, BlockBuilder, BlockConfig, BridgeBuilder, BridgeConfig, DEFAULT_BLOCK_NAME, GroupTrait,
    Link, Locator, LocatorBuilder, LocatorConfig, MacAddr, MplsConfig, Nexthop, NexthopMap,
    NexthopUni, RibSrRx, RibType, Sid, SidBehavior, StaticConfig, V4, V6, Vrf, VrfBuilder,
    VrfIdAllocator, VrfRibTables, Vxlan, VxlanBuilder, VxlanConfig,
};

use crate::config::{Args, path_from_command};
use crate::config::{ConfigChannel, ConfigOp, ConfigRequest, DisplayRequest, ShowChannel};
use crate::context::Timer;
use crate::fib::fib_dump;
use crate::fib::sysctl::sysctl_enable;
use crate::fib::{FibChannel, FibHandle, FibMessage, FibNeighbor};
use crate::rib::route::{
    AddrRecoveryState, ipv4_nexthop_sync, ipv6_nexthop_sync, nexthop_orphan_gc,
};
use crate::rib::{Bridge, RibEntries};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use prefix_trie::PrefixMap;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::sync::oneshot;

pub type ShowCallback = fn(&Rib, Args, bool) -> String;

pub enum Message {
    LinkUp {
        ifindex: u32,
    },
    LinkDown {
        ifindex: u32,
    },
    Ipv4Add {
        prefix: Ipv4Net,
        rib: RibEntry,
    },
    Ipv4Del {
        prefix: Ipv4Net,
        rib: RibEntry,
    },
    Ipv6Add {
        prefix: Ipv6Net,
        rib: RibEntry,
    },
    Ipv6Del {
        prefix: Ipv6Net,
        rib: RibEntry,
    },
    IlmAdd {
        label: u32,
        ilm: IlmEntry,
    },
    IlmDel {
        label: u32,
        ilm: IlmEntry,
    },
    /// IS-IS publishes a per-algorithm IPv4 route snapshot. RIB
    /// shadows it in `flex_algo_routes` and re-broadcasts via
    /// `RibRx::FlexAlgoRouteAdd`. No FIB install — per-algo IPv4
    /// would collide with algo-0 in the kernel; forwarding goes
    /// through the algo-N MPLS LFIB which IS-IS already installs.
    FlexAlgoRouteAdd {
        route: crate::rib::api::FlexAlgoRoute,
    },
    /// Inverse of `FlexAlgoRouteAdd`. Either the prefix is no longer
    /// reachable in algo-N, or the algo itself has been removed from
    /// the configuration.
    FlexAlgoRouteDel {
        algo: u8,
        prefix: Ipv4Net,
    },
    /// SRv6 twin of `FlexAlgoRouteAdd`: IS-IS publishes a per-algo
    /// (prefix → node End SID) snapshot. RIB re-broadcasts it via
    /// `RibRx::FlexAlgoSrv6RouteAdd` for the colour-aware resolver. No
    /// FIB install here — the per-algo locator routes are installed by
    /// IS-IS; this is the steering metadata BGP needs to H.Encap a
    /// coloured service route toward the destination node's End SID.
    FlexAlgoSrv6RouteAdd {
        route: crate::rib::api::FlexAlgoSrv6Route,
    },
    FlexAlgoSrv6RouteDel {
        algo: u8,
        prefix: ipnet::IpNet,
    },
    BridgeAdd {
        name: String,
        config: BridgeConfig,
    },
    BridgeDel {
        name: String,
    },
    BlockAdd {
        name: String,
        config: BlockConfig,
    },
    BlockDel {
        name: String,
    },
    LocatorAdd {
        name: String,
        config: LocatorConfig,
    },
    LocatorDel {
        name: String,
    },
    /// One-time per-protocol registration of the SR return channel. The
    /// channel carries `RibSrRx` updates for any block / locator the
    /// protocol later watches.
    SrSubscribe {
        proto: String,
        tx: UnboundedSender<RibSrRx>,
    },
    /// Register interest in a named block. Triggers an immediate push of
    /// the current `Rib::blocks.get(name)` value (Some or None) and any
    /// subsequent updates.
    SrBlockWatch {
        proto: String,
        name: String,
    },
    SrBlockUnwatch {
        proto: String,
        name: String,
    },
    SrLocatorWatch {
        proto: String,
        name: String,
    },
    SrLocatorUnwatch {
        proto: String,
        name: String,
    },
    /// Next-Hop Tracking: register interest in resolving `nh` against
    /// the global table. Triggers an immediate `RibRx::NexthopUpdate`
    /// back to `proto` and subsequent updates whenever the covering
    /// route changes. Registrations are deduplicated + refcounted per
    /// nexthop in `Rib::nht`.
    NexthopRegister {
        proto: String,
        nh: std::net::IpAddr,
    },
    /// Fast-reroute switchover trigger (phase 2 of
    /// `docs/design/nexthop-protect-kernel-failover.md`): the sender
    /// detected a primary-adjacency failure the kernel can't see (BFD
    /// down while the link stays up) at gateway `addr`. RIB rewires
    /// every protection indirection group whose primary rides that
    /// adjacency onto its repair — one atomic kernel group-replace
    /// per group, independent of prefix count. The sender's normal
    /// SPF reconvergence then supersedes the bridge.
    // Constructed by RibClient::protect_switch, whose own
    // expect(dead_code) (callers land in phase 3/4) roots it — and
    // the construction inside keeps this variant live with it.
    ProtectSwitch {
        addr: IpAddr,
    },
    /// Drop `proto`'s interest in `nh`; the tracking entry is removed
    /// once its last watcher unregisters.
    NexthopUnregister {
        proto: String,
        nh: std::net::IpAddr,
    },
    /// Reserve a dynamic MPLS label block of `size` labels for `proto`
    /// from the central [`super::label_manager::LabelManager`]. The RIB
    /// replies synchronously with a `RibRx::LabelBlock`. Used by BGP for
    /// L3VPN per-VRF labels (LDP / others later).
    LabelBlockRequest {
        proto: String,
        size: u32,
    },
    /// Return a previously-reserved label block `[start, start+size)` to
    /// the pool — produced by a protocol whose label usage shrank enough
    /// to free a whole block. `proto_cleanup` is the backstop for a
    /// proto that exits without releasing.
    LabelBlockRelease {
        proto: String,
        start: u32,
        size: u32,
    },
    /// Register an allocated SRv6 SID. Owners (IS-IS, OSPF, BGP) push
    /// one of these whenever they carve a function out of a locator;
    /// the RIB stores it for `show segment-routing srv6 sid`.
    SidAdd {
        sid: Sid,
    },
    SidDel {
        addr: std::net::Ipv6Addr,
    },
    /// Install a mirror-context route for IS-IS egress protection: in
    /// `context_table`, route the protected egress's locator `prefix` to
    /// a seg6local End.DT46 that decaps into the local VRF named
    /// `vrf_name`. The RIB resolves `vrf_name` to its kernel table id and
    /// the seg6 device before pushing to the FIB; a not-yet-known VRF is
    /// skipped (a later reconcile re-sends it).
    MirrorRouteAdd {
        prefix: ipnet::Ipv6Net,
        context_table: u32,
        vrf_name: String,
    },
    MirrorRouteDel {
        prefix: ipnet::Ipv6Net,
        context_table: u32,
    },
    VxlanAdd {
        name: String,
        config: VxlanConfig,
    },
    VxlanDel {
        name: String,
    },
    VrfAdd {
        name: String,
    },
    VrfDel {
        name: String,
    },
    /// Replace the route-target sets for `name`. Emitted by
    /// `VrfBuilder::commit` on every commit cycle so the RIB
    /// state stays a snapshot of the staged config. Carries every
    /// (afi, kind) tuple in one message so the receiving end
    /// updates atomically — no risk of a half-updated state being
    /// observed by a subscriber that drains the channel between
    /// individual mutations.
    VrfRouteTargets {
        name: String,
        ipv4_import_rts: std::collections::BTreeSet<bgp_packet::RouteDistinguisher>,
        ipv4_export_rts: std::collections::BTreeSet<bgp_packet::RouteDistinguisher>,
        ipv6_import_rts: std::collections::BTreeSet<bgp_packet::RouteDistinguisher>,
        ipv6_export_rts: std::collections::BTreeSet<bgp_packet::RouteDistinguisher>,
    },
    /// Configured `vrf <name> router-id` snapshot from the VRF config
    /// builder, sent on commit after `VrfAdd` (same ordering contract
    /// as `VrfRouteTargets`). `None` means the leaf is absent —
    /// fall back to the derived per-VRF pick.
    VrfRouterId {
        name: String,
        router_id: Option<Ipv4Addr>,
    },
    /// Bind / unbind an interface to a VRF master device.
    /// `vrf == Some(name)` enslaves; `vrf == None` clears the binding
    /// (sets IFLA_MASTER = 0). The handler tolerates the interface or
    /// the VRF not yet existing in our tables and stages the intent in
    /// `pending_vrf_bind` so it fires when the missing piece arrives.
    LinkVrfBind {
        ifname: String,
        vrf: Option<String>,
    },
    MacAdd {
        vni: u32,
        mac: MacAddr,
        tunnel_endpoint: Option<IpAddr>,
        flags: u8,
        seq: u32,
        esi: Option<[u8; 10]>,
    },
    MacDel {
        vni: u32,
        mac: MacAddr,
    },
    MdbAdd {
        vni: u32,
        group: IpAddr,
        source: Option<IpAddr>,
        ifindex: u32,
        seq: u32,
    },
    MdbDel {
        vni: u32,
        group: IpAddr,
        source: Option<IpAddr>,
        ifindex: u32,
    },
    Shutdown {
        tx: oneshot::Sender<()>,
    },
    Resolve,
    /// Register a subscriber. Sent by
    /// [`crate::config::ConfigManager::subscribe_to_rib`] right after
    /// it has allocated a `ProtoId` and built the matching
    /// [`crate::rib::client::RibClient`]. RIB inserts the row in
    /// both the typed `client_registry` (keyed by `proto_id`) and
    /// the legacy `redists` map (keyed by proto name), then drives
    /// the link / addr / VXLAN / FDB / router-id initial-state
    /// replay before terminating with `RibRx::EoR`.
    Subscribe {
        proto_id: ProtoId,
        proto: String,
        tx: UnboundedSender<RibRx>,
        /// VRF the subscriber's installs should land in (kernel
        /// `rtm_table` id; `0` = default-VRF). Recorded on the
        /// `Subscriber` row so the inbound dispatcher can pick the
        /// right per-VRF table without a name-based lookup.
        vrf_id: u32,
    },

    // ---- redistribute subscription messages ----------------------
    //
    // Per-(proto, AFI, rtype) subscriptions. Subtype is a wildcard
    // set (empty = match every subtype under `rtype`). Self-route
    // filtering (route's rtype belonging to the subscriber's proto)
    // is enforced unconditionally by RIB before any other check.
    // No consumer wired yet — the walker / steady-state hook and the
    // per-protocol senders land in follow-ups.
    /// Walk the FIB for the current matching set, then keep delivering
    /// future deltas for `(proto, afi, rtype)` with subtype filtered
    /// by `subtypes`. Empty `subtypes` is wildcard. Triggers a bulk
    /// replay followed by a `BulkPhase::Eor` marker.
    RedistAdd {
        proto: String,
        afi: super::RedistAfi,
        rtype: RibType,
        subtypes: BTreeSet<super::RibSubType>,
    },
    /// Replace the previous `subtypes` set for the same
    /// `(proto, afi, rtype)` row. RIB diffs old vs new:
    ///   - removed subtypes → RouteDel of their matching prefixes;
    ///   - added subtypes → walk-and-replay of those prefixes.
    ///
    /// No-op on identical sets. Issuing RedistUpdate for a row that
    /// was never RedistAdd'd is treated as RedistAdd.
    RedistUpdate {
        proto: String,
        afi: super::RedistAfi,
        rtype: RibType,
        subtypes: BTreeSet<super::RibSubType>,
    },
    /// Tear down a redistribute subscription. RIB sends RouteDel for
    /// every currently-matched prefix (in chunks ending in
    /// `BulkPhase::Eor`) so the consumer can withdraw without having
    /// to remember its own per-filter state.
    RedistDel {
        proto: String,
        afi: super::RedistAfi,
        rtype: RibType,
    },
    /// Tear down all RIB state owned by a protocol whose task is
    /// being despawned (`no router bgp` / `no router isis` / `no
    /// router ospf`). Withdraws every route / ILM whose `rtype`
    /// matches, drops the redist sender, and clears SR watchers
    /// registered under the proto name. Idempotent.
    ProtoCleanup {
        proto: String,
    },
}

impl Message {
    /// Whether this message programs a forwarding entry into the kernel
    /// FIB/LFIB. Used by [`crate::rib::client::RibClient`] to drop only
    /// forwarding installs when a subscriber asks to stay out of the
    /// data path (BGP route reflector `no-fib-install`); withdrawals and
    /// every control-plane message return `false` so they still flow.
    pub fn is_fib_install(&self) -> bool {
        matches!(
            self,
            Message::Ipv4Add { .. } | Message::Ipv6Add { .. } | Message::IlmAdd { .. }
        )
    }
}

#[derive(Default, Debug, Clone, PartialEq)]
pub enum IlmType {
    #[default]
    None,
    Node(u32),
    Adjacency(u32),
    /// BGP/MPLS-VPN per-VRF decap (RFC 4364). The kernel pops
    /// the label and routes the inner packet through the VRF
    /// master device, which lands the lookup in
    /// `vrf_tables[table_id]`. `vrf_ifindex` is the kernel
    /// ifindex of the VRF master (e.g. `ip link show vrf-blue`);
    /// `table_id` is informational only (the netlink action
    /// keys off the Oif, not the table id), but the show path
    /// renders it for operators.
    DecapVrf {
        table_id: u32,
        vrf_ifindex: u32,
    },
    /// BGP Labeled-Unicast transit swap (RFC 3107 / RFC 8277): the
    /// kernel swaps the incoming local label for the next-hop's outgoing
    /// label stack (`nexthop.mpls_label`) and forwards toward the
    /// resolved egress. The netlink action is the generic `NewDestination`
    /// swap (same path as Node/Adjacency); this variant only labels the
    /// owner for show output and ILM selection.
    Swap,
}

/// All ILM candidates competing for a single incoming label. Mirrors
/// `RibEntries` for the IP table: every protocol that claims a label
/// contributes one entry, and `ilm_next` picks the best by admin
/// distance. At most one entry is `selected` and installed to the
/// kernel LFIB (the kernel holds a single AF_MPLS route per label).
pub type IlmEntries = Vec<IlmEntry>;

#[derive(Default, Debug, Clone)]
pub struct IlmEntry {
    pub rtype: RibType,
    pub ilm_type: IlmType,
    pub nexthop: Nexthop,
    /// Administrative distance, mirroring the IP RIB convention
    /// (static 1, OSPF 110, IS-IS 115, BGP 20). Set by
    /// `IlmEntry::new` from the owning `rtype`. Primary tie-break key
    /// for ILM RIB selection.
    pub distance: u8,
    /// Path metric, the second tie-break key (after distance, before
    /// rtype) in `ilm_next`. Defaults to 0; producers don't yet stamp
    /// a per-label cost onto the ILM, so today it only disambiguates
    /// same-distance candidates from the same protocol.
    pub metric: u32,
    /// True for the winning candidate at this label — the one
    /// installed to the kernel LFIB. Set by `Rib::ilm_select_sync`.
    pub selected: bool,
}

impl IlmEntry {
    pub fn new(rtype: RibType) -> Self {
        Self {
            rtype,
            ilm_type: IlmType::None,
            nexthop: Nexthop::default(),
            distance: ilm_distance(rtype),
            metric: 0,
            selected: false,
        }
    }
}

/// Default administrative distance for an ILM entry owned by `rtype`,
/// following the same FRR/Cisco convention as the IP RIB. BGP uses the
/// eBGP value (20); VPN decap labels are uniquely owned, so the
/// eBGP/iBGP split doesn't apply at the LFIB.
fn ilm_distance(rtype: RibType) -> u8 {
    match rtype {
        RibType::Kernel | RibType::Connected => 0,
        RibType::Static => 1,
        RibType::Ospf => 110,
        RibType::Isis => 115,
        RibType::Bgp => 20,
        RibType::Dhcp => 254,
        RibType::Other(_) => 255,
    }
}

#[derive(Debug, Clone)]
pub struct MacEntry {
    pub tunnel_endpoint: Option<IpAddr>,
    pub flags: u8,
    pub seq: u32,
    pub installed: bool,
}

/// Composite key for `Rib::neighbors`. The kernel's neighbor table mixes
/// three address families behind one RTM_NEWNEIGH; the key distinguishes
/// them while staying naturally Ord/Hash so all three can live in one
/// BTreeMap.
///
/// - `Inet` covers `AF_INET` (ARP) and `AF_INET6` (NDP) — uniqueness is
///   `(ifindex, ip)`. The `IpAddr` discriminant carries the family.
/// - `Bridge` covers `AF_BRIDGE` (FDB) — uniqueness is
///   `(ifindex, mac, vlan)`. VXLAN's per-VNI uniqueness comes via the
///   `dst` and `vni` attributes inside the stored `FibNeighbor`; on a
///   classic bridge the `vlan` portion of the key handles 802.1Q.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum NeighborKey {
    Inet {
        ifindex: u32,
        addr: IpAddr,
    },
    Bridge {
        ifindex: u32,
        mac: MacAddr,
        vlan: Option<u16>,
    },
}

pub struct Rib {
    pub cm: ConfigChannel,
    pub show: ShowChannel,
    pub show_cb: HashMap<String, ShowCallback>,
    pub fib: FibChannel,
    pub fib_handle: FibHandle,
    /// Subscriber registry — the sole source of truth for protocol
    /// modules attached to RIB. Populated by `Rib::subscribe`,
    /// drained by `proto_cleanup`, walked by the inbound dispatcher
    /// and the outbound `api_*` push paths.
    pub client_registry: ClientRegistry,
    /// Sender half of the `RibInbound` channel — cloned by
    /// `ConfigManager` into every `RibClient` it hands out at
    /// subscribe time.
    pub inbound_tx: UnboundedSender<RibInbound>,
    /// Receive half polled in `event_loop`. Each `RibInbound` is
    /// unwrapped and forwarded to `process_msg` exactly like the
    /// legacy `rx` channel. The `from: ProtoId` field routes
    /// per-VRF installs through the inbound dispatcher.
    pub inbound_rx: UnboundedReceiver<RibInbound>,
    /// Per-proto redistribute subscription registry. Outer key is the
    /// subscriber's protocol name (matches `Subscriber::proto`); inner
    /// map is keyed by `(afi, rtype)` and holds the subtype filter set
    /// (empty = wildcard). Updated by RedistAdd / RedistUpdate /
    /// RedistDel; consulted by `redist::notify_v*_delta`, which
    /// resolves each row's sender through `client_registry`.
    pub redist_filters: HashMap<String, super::redist::FilterMap>,
    pub links: BTreeMap<u32, Link>,
    pub bridges: BTreeMap<String, Bridge>,
    pub vxlan: BTreeMap<String, Vxlan>,
    /// Applied VRFs, keyed by name. Populated when `Message::VrfAdd`
    /// is handled (allocator hands out a fresh table id, netlink
    /// creates the kernel `vrf` master, entry is recorded here).
    /// `Message::VrfDel` removes the entry and releases the id.
    pub vrfs: BTreeMap<String, Vrf>,
    /// Per-VRF routing tables, keyed by the same `table_id` the
    /// kernel uses. Each entry holds the IPv4 + IPv6 prefix tries
    /// and the MPLS ILM map for that VRF. Created on `VrfAdd`
    /// (empty), removed on `VrfDel`. The per-`ProtoId` inbound
    /// dispatcher writes into these when a VRF-attached protocol
    /// installs a route.
    pub vrf_tables: BTreeMap<u32, VrfRibTables>,
    pub vrf_id_alloc: VrfIdAllocator,
    /// Operator intent for per-interface VRF binding, keyed by ifname.
    /// `Some(vrf)` = enslave; `None` = unbind. The handler retries this
    /// when a missing interface or VRF master appears later, and clears
    /// the entry once the netlink call succeeds.
    pub pending_vrf_bind: BTreeMap<String, Option<String>>,
    /// Operator-configured interface MTU, keyed by ifname. This is the
    /// durable desired-state for `set interface <name> mtu <n>`: it is
    /// applied to the kernel when set, replayed when a matching link
    /// (re)appears, and on delete reverts the kernel to the link's
    /// originally-observed MTU (`Link::original_mtu`).
    pub mtu_config: BTreeMap<String, u32>,
    pub table: PrefixMap<Ipv4Net, RibEntries>,
    pub table_v6: PrefixMap<Ipv6Net, RibEntries>,
    pub ilm: BTreeMap<u32, IlmEntries>,
    /// Per-IS-IS-Flex-Algorithm IPv4 route shadow used by the
    /// BGP ↔ IS-IS Flex-Algo integration. Outer key is the algo id
    /// (128..=255); inner map mirrors the per-algo subset of IS-IS's
    /// `Isis::rib_flex_algo`. Populated by `Message::FlexAlgoRouteAdd`
    /// / `Del`, cleared on shutdown. **Not** installed to the kernel
    /// IPv4 table — algo-N routes would collide with algo-0; the
    /// per-algo MPLS LFIB (already in `Isis::ilm` and pushed through
    /// `ilm_add`) provides forwarding. The colour-aware nexthop
    /// resolver (next PR) reads this shadow to attach the outer MPLS
    /// label for service routes carrying a Color extcomm.
    pub flex_algo_routes: BTreeMap<u8, PrefixMap<Ipv4Net, crate::rib::api::FlexAlgoRoute>>,
    pub mac_table: BTreeMap<(u32, MacAddr), MacEntry>,
    /// Remote VTEPs we've installed as VXLAN BUM ingress-replication
    /// targets (zero-MAC FDB rows on the VXLAN device, keyed by
    /// `(vni, peer-VTEP-IP)`). Populated by `mdb_add`, removed by
    /// `mdb_del`. Walked at `Message::Shutdown` so we can DELNEIGH
    /// every entry we installed before exiting — externally-created
    /// VXLAN devices outlive the daemon and would otherwise keep
    /// our zero-MAC rows around forever.
    pub vtep_table: std::collections::BTreeSet<(u32, IpAddr)>,
    /// Local snapshot of the kernel's neighbor table (ARP + NDP + bridge
    /// FDB). Populated from `FibMessage::NewNeighbor` / `DelNeighbor`,
    /// initially seeded by `fib_dump` at startup. Read by `show l2
    /// neighbor` today; the EVPN Type-2 advertise path will iterate
    /// the `NeighborKey::Bridge` entries in a follow-up.
    pub neighbors: BTreeMap<NeighborKey, FibNeighbor>,
    pub tx: UnboundedSender<Message>,
    pub rx: UnboundedReceiver<Message>,
    pub static_v4: StaticConfig<V4>,
    pub static_v6: StaticConfig<V6>,
    pub mpls_config: MplsConfig,
    pub link_config: LinkConfig,
    pub bridge_config: BridgeBuilder,
    pub vxlan_config: VxlanBuilder,
    pub vrf_config: VrfBuilder,
    pub block_config: BlockBuilder,
    pub locator_config: LocatorBuilder,
    /// Applied snapshots, populated by Block/Locator Add/Del messages.
    /// Other modules read these by name to resolve their `mpls/block` or
    /// `srv6/locator` reference.
    pub blocks: BTreeMap<String, Block>,
    pub locators: BTreeMap<String, Locator>,
    /// Allocated SRv6 SIDs across all owners. Keyed by SID address so
    /// inserts collide naturally on duplicate allocations; the show
    /// callback iterates this in address order.
    pub sids: BTreeMap<std::net::Ipv6Addr, Sid>,
    /// SR-update return channels keyed by protocol name. One sender per
    /// protocol; established once via Message::SrSubscribe.
    pub sr_clients: BTreeMap<String, UnboundedSender<RibSrRx>>,
    /// Per-name block watchers — set of protocol names interested in
    /// updates to that block.
    pub block_watch: BTreeMap<String, BTreeSet<String>>,
    pub locator_watch: BTreeMap<String, BTreeSet<String>>,
    /// Next-Hop Tracking registry — per-nexthop watcher sets + cached
    /// resolution. Driven by `Message::NexthopRegister`/`Unregister`
    /// and re-resolved on global-table route changes.
    pub nht: super::nht::NhtRegistry,

    /// Central dynamic MPLS label-block manager. Hands out non-
    /// overlapping label blocks to protocols (BGP L3VPN today).
    pub label_manager: super::label_manager::LabelManager,
    pub nmap: NexthopMap,
    /// Effective global Router ID — what subscribers receive via
    /// `RibRx::RouterIdUpdate` and what the subscribe-time replay
    /// sends. Either the configured override (`router_id_config`) or
    /// the automatic pick from interface addresses; sticky once set
    /// (never reverts to 0.0.0.0 while running).
    pub router_id: Ipv4Addr,
    /// Operator-configured global Router ID (top-level
    /// `router-id A.B.C.D`). Takes precedence over the automatic
    /// pick; `None` falls back to it.
    pub router_id_config: Option<Ipv4Addr>,

    /// Single-shot timer that fires Message::Resolve after a debounce when
    /// the FIB has changed. None when no resolve is pending. Set by
    /// schedule_rib_sync(), cleared by the Message::Resolve handler.
    pub rib_sync_timer: Option<Timer>,

    /// Debounce interval (seconds) before a queued FIB modification triggers
    /// nexthop resolution. Configurable so an operator can tune for their
    /// convergence vs. churn trade-off; default 1s matches the typical
    /// "kick once shortly after the wave settles" pattern.
    pub rib_sync_interval: u64,

    /// True when the sr0 dummy was created by this process and must
    /// therefore be cleaned up on Shutdown. False when sr0 already
    /// existed (operator-managed) — leave it alone on exit.
    pub sr0_owned: bool,

    /// Per-address state for kernel-driven address recovery. Keyed by
    /// (ifindex, prefix). Entries are created lazily on the first
    /// DelAddr we receive for a configured address; the burst counter
    /// inside trips a 10-minute cool-down per
    /// `crate::rib::route::RECOVERY_*` if an external actor keeps
    /// fighting us.
    pub addr_recovery: BTreeMap<(u32, IpNet), AddrRecoveryState>,
}

/// Name of the dummy interface that hosts End-style seg6local routes
/// (table=main + kind=Unicast). Created at startup if missing.
pub const SR0_DUMMY_NAME: &str = "sr0";

/// Kernel `rtm_table` id for the default routing table — what
/// non-VRF protocol installs target. Matches
/// `netlink_packet_route::route::RouteHeader::RT_TABLE_MAIN`
/// (254) and is the value every callsite that operates on the
/// global routing table passes to `FibHandle::route_ipv*_add/del`.
/// `table_id` is threaded through those calls so per-VRF dispatch
/// can supply a different value without changing the call shape.
pub const RT_TABLE_MAIN: u32 = 254;

const DEFAULT_RIB_SYNC_INTERVAL_SEC: u64 = 1;

impl Rib {
    pub fn new(no_nhid: bool) -> anyhow::Result<Self> {
        let fib = FibChannel::new();
        let fib_handle = FibHandle::new(fib.tx.clone(), no_nhid)?;
        let (tx, rx) = mpsc::unbounded_channel();
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        let mut rib = Rib {
            cm: ConfigChannel::new(),
            show: ShowChannel::new(),
            show_cb: HashMap::new(),
            fib,
            fib_handle,
            client_registry: ClientRegistry::new(),
            inbound_tx,
            inbound_rx,
            redist_filters: HashMap::new(),
            links: BTreeMap::new(),
            bridges: BTreeMap::new(),
            vxlan: BTreeMap::new(),
            vrfs: BTreeMap::new(),
            vrf_tables: BTreeMap::new(),
            vrf_id_alloc: VrfIdAllocator::new(),
            pending_vrf_bind: BTreeMap::new(),
            mtu_config: BTreeMap::new(),
            table: PrefixMap::new(),
            table_v6: PrefixMap::new(),
            ilm: BTreeMap::new(),
            flex_algo_routes: BTreeMap::new(),
            mac_table: BTreeMap::new(),
            vtep_table: std::collections::BTreeSet::new(),
            neighbors: BTreeMap::new(),
            tx,
            rx,
            static_v4: StaticConfig::<V4>::new(),
            static_v6: StaticConfig::<V6>::new(),
            mpls_config: MplsConfig::new(),
            link_config: LinkConfig::new(),
            bridge_config: BridgeBuilder::new(),
            vxlan_config: VxlanBuilder::new(),
            vrf_config: VrfBuilder::new(),
            block_config: BlockBuilder::new(),
            locator_config: LocatorBuilder::new(),
            blocks: {
                // Seed the canonical default block at startup so protocols can
                // subscribe to "default" without anyone having configured one.
                let mut m = BTreeMap::new();
                m.insert(DEFAULT_BLOCK_NAME.to_string(), Block::default_block());
                m
            },
            locators: BTreeMap::new(),
            sids: BTreeMap::new(),
            sr_clients: BTreeMap::new(),
            block_watch: BTreeMap::new(),
            locator_watch: BTreeMap::new(),
            nht: super::nht::NhtRegistry::default(),
            label_manager: super::label_manager::LabelManager::new(),
            nmap: NexthopMap::default(),
            router_id: Ipv4Addr::UNSPECIFIED,
            router_id_config: None,
            rib_sync_timer: None,
            rib_sync_interval: DEFAULT_RIB_SYNC_INTERVAL_SEC,
            sr0_owned: false,
            addr_recovery: BTreeMap::new(),
        };
        rib.show_build();
        Ok(rib)
    }

    /// Arm a one-shot timer that fires Message::Resolve after rib_sync_interval
    /// seconds, debouncing further FIB modifications until the timer fires.
    /// Repeated calls while a timer is already pending are no-ops, which lets
    /// a burst of FIB events (e.g. an IS-IS LSDB update producing many route
    /// installs in quick succession) collapse into a single resolve cycle.
    pub fn schedule_rib_sync(&mut self) {
        if self.rib_sync_timer.is_some() {
            return;
        }
        let tx = self.tx.clone();
        self.rib_sync_timer = Some(Timer::once(self.rib_sync_interval, move || {
            let tx = tx.clone();
            async move {
                let _ = tx.send(Message::Resolve);
            }
        }));
    }

    /// Push the current value of `blocks[name]` (Some / None) to every
    /// protocol that has registered a watch on this name.
    /// Resolve `nh` against the appropriate global (default-VRF) table.
    fn nht_resolve(&self, nh: IpAddr) -> super::nht::NexthopResolution {
        match nh {
            IpAddr::V4(a) => super::nht::resolve_v4(&self.table, a),
            IpAddr::V6(a) => super::nht::resolve_v6(&self.table_v6, a),
        }
    }

    /// Handle `Message::NexthopRegister`: add the watcher, resolve,
    /// cache, and push the current resolution to the registering
    /// client immediately (the "synchronous-first" reply — even on a
    /// non-fresh register, so a late joiner gets the state).
    fn nht_register(&mut self, proto: String, nh: IpAddr) {
        self.nht.register(proto.clone(), nh);
        let resolution = self.nht_resolve(nh);
        if let Some(entry) = self.nht.entries.get_mut(&nh) {
            entry.resolution = resolution.clone();
        }
        if let Some(sub) = self.client_registry.subscriber_for_proto(&proto) {
            let _ = sub.rib_rx_tx.send(RibRx::NexthopUpdate { nh, resolution });
        }
    }

    /// Handle `Message::LabelBlockRequest`: reserve a dynamic label
    /// block for `proto` and reply synchronously with it. An exhausted
    /// pool gets no reply (the requester degrades to label-less); a
    /// missing subscriber returns the block rather than stranding it.
    fn label_block_request(&mut self, proto: String, size: u32) {
        let Some(block) = self.label_manager.alloc(&proto, size) else {
            tracing::warn!(%proto, size, "label block request: dynamic pool exhausted");
            return;
        };
        let (start, size) = (block.start, block.end - block.start);
        if let Some(sub) = self.client_registry.subscriber_for_proto(&proto) {
            let _ = sub.rib_rx_tx.send(RibRx::LabelBlock { start, size });
        } else {
            self.label_manager.release(&proto, start, size);
        }
    }

    /// Re-resolve every tracked nexthop; where the resolution changed,
    /// update the cache and notify all its watchers. Called after a
    /// global-table route change. (Recompute-all for now; narrowing to
    /// only the affected nexthops is a follow-up, as is firing on
    /// link/addr changes.)
    fn nht_recompute_and_notify(&mut self) {
        if self.nht.entries.is_empty() {
            return;
        }
        let mut updates: Vec<(IpAddr, super::nht::NexthopResolution, Vec<String>)> = Vec::new();
        for nh in self.nht.tracked() {
            let resolution = self.nht_resolve(nh);
            if let Some(entry) = self.nht.entries.get_mut(&nh)
                && entry.resolution != resolution
            {
                entry.resolution = resolution.clone();
                let watchers = entry.watchers.iter().cloned().collect();
                updates.push((nh, resolution, watchers));
            }
        }
        for (nh, resolution, watchers) in updates {
            for proto in watchers {
                if let Some(sub) = self.client_registry.subscriber_for_proto(&proto) {
                    let _ = sub.rib_rx_tx.send(RibRx::NexthopUpdate {
                        nh,
                        resolution: resolution.clone(),
                    });
                }
            }
        }
    }

    fn notify_block_watchers(&self, name: &str) {
        let Some(watchers) = self.block_watch.get(name) else {
            return;
        };
        let block = self.blocks.get(name).cloned();
        for proto in watchers {
            if let Some(tx) = self.sr_clients.get(proto) {
                let _ = tx.send(RibSrRx::Block {
                    name: name.to_string(),
                    block: block.clone(),
                });
            }
        }
    }

    fn notify_locator_watchers(&self, name: &str) {
        let Some(watchers) = self.locator_watch.get(name) else {
            return;
        };
        let locator = self.locators.get(name).cloned();
        for proto in watchers {
            if let Some(tx) = self.sr_clients.get(proto) {
                let _ = tx.send(RibSrRx::Locator {
                    name: name.to_string(),
                    locator: locator.clone(),
                });
            }
        }
    }

    /// Build the seg6local NexthopUni a SID install resolves through
    /// NexthopMap. The (action, ifindex, nh6) triple is the dedup key —
    /// two End SIDs end up sharing one nh_id, two End.X SIDs to the
    /// same neighbor likewise share, distinct adjacencies don't.
    fn sid_nexthop_uni(sid: &Sid) -> NexthopUni {
        let addr = match sid.nh6 {
            Some(a) => IpAddr::V6(a),
            None => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        };
        NexthopUni {
            addr,
            // SID installs pre-resolve the egress link (sr0 / lo for
            // End/uN, the per-adjacency link for End.X/uA). Treat it
            // as an origin so the resolver doesn't second-guess.
            ifindex_origin: (sid.ifindex != 0).then_some(sid.ifindex),
            seg6local_action: Some(sid.behavior),
            valid: true,
            ..Default::default()
        }
    }

    /// Resolve a Sid's `ifindex == 0` to the system's loopback before
    /// install. End SIDs arrive without an ifindex from IS-IS so the
    /// daemon stays portable; the FIB needs a real one.
    fn resolve_lo_ifindex(&self) -> Option<u32> {
        self.links
            .values()
            .find(|link| link.is_loopback())
            .map(|link| link.index)
    }

    /// Resolve the L2VPN VNI for a bridge.
    ///
    /// Walks the link table looking for a link whose `master` is the
    /// requested bridge ifindex AND whose `vni` is set — i.e. a VXLAN
    /// device enslaved to this bridge. Returns the VNI of the first
    /// such slave (typical EVPN deployment is exactly one VXLAN per
    /// bridge per VNI).
    ///
    /// Used by the EVPN advertise path: a kernel FDB entry tells us
    /// `(master = bridge_ifindex, mac, ...)`; this helper turns the
    /// bridge into the VNI used to derive the Type-2 route's RD/RT.
    pub fn vni_for_bridge(&self, bridge_ifindex: u32) -> Option<u32> {
        self.links
            .values()
            .find(|link| link.master == Some(bridge_ifindex) && link.vni.is_some())
            .and_then(|link| link.vni)
    }

    /// Sibling of `vni_for_bridge` returning the same VXLAN slave's
    /// local source IP (`IFLA_VXLAN_LOCAL` / `IFLA_VXLAN_LOCAL6`),
    /// when set. The EVPN advertise path uses this for the BGP
    /// MP_REACH nexthop on Type-2 / Type-3 routes — receivers
    /// encapsulate VXLAN packets to this address.
    pub fn vxlan_local_for_bridge(&self, bridge_ifindex: u32) -> Option<IpAddr> {
        self.links
            .values()
            .find(|link| link.master == Some(bridge_ifindex) && link.vni.is_some())
            .and_then(|link| link.vxlan_local)
    }

    /// Re-emit `RibRx::FdbAdd` for every existing AF_BRIDGE entry on
    /// `bridge_ifindex`. Called from `link_add` when a VXLAN device
    /// gains a bridge master so MACs that were learned BEFORE the
    /// VXLAN was wired in get re-evaluated and pushed to BGP.
    ///
    /// Without this, the operator's typical sequence — bridge ->
    /// VXLAN -> enslave VXLAN -> enslave physical port -> traffic
    /// flows -> MAC learned -> *operator wonders why BGP shows
    /// nothing* — leaves data-plane-learned MACs invisible until
    /// the kernel happens to re-learn them. Each successful re-emit
    /// flows through `evpn_originate_macip` whose `update_evpn` is
    /// idempotent (matches on `(ident, remote_id)`), so a benign
    /// re-fire on already-known entries doesn't multiply the route.
    pub fn rescan_fdb_for_bridge(&self, bridge_ifindex: u32) {
        let Some(vni) = self.vni_for_bridge(bridge_ifindex) else {
            return;
        };
        let vxlan_local = self.vxlan_local_for_bridge(bridge_ifindex);
        for (key, nbr) in self.neighbors.iter() {
            let NeighborKey::Bridge {
                ifindex,
                mac,
                vlan: _,
            } = key
            else {
                continue;
            };
            // Match only entries whose slave port belongs to this
            // bridge (either via the cached IFLA_MASTER on the slave
            // link, or via NDA_MASTER on the FDB entry itself).
            let slave_master = self.links.get(ifindex).and_then(|l| l.master);
            let belongs_here =
                slave_master == Some(bridge_ifindex) || nbr.master == Some(bridge_ifindex);
            if !belongs_here {
                continue;
            }
            // Match `fdb_entry_from_neighbor`: drop multicast/broadcast.
            if mac.is_multicast() {
                continue;
            }
            // And drop MACs learned on VXLAN ports (remote hosts).
            if let Some(slave) = self.links.get(ifindex)
                && slave.vni.is_some()
            {
                continue;
            }
            let entry = FdbEntry {
                vni,
                mac: *mac,
                ifindex: *ifindex,
                bridge_ifindex,
                flags: nbr.flags.bits(),
                vxlan_local,
            };
            self.api_fdb_add(&entry);
        }
    }

    /// Resolve the device the kernel binds the seg6local action to,
    /// per behavior. End / uN / End.DT4 / End.DT6 are local-processing
    /// actions; all four ride on the sr0 dummy so the install can stay
    /// in table=main + kind=Unicast. End.X / uA already run on the
    /// actual outgoing interface and never hit this path.
    pub fn resolve_sid_ifindex(&self, behavior: SidBehavior) -> Option<u32> {
        match behavior {
            // These bind their seg6local action to the sr0 dummy, not the
            // loopback: the kernel silently STRIPS a seg6local encap whose
            // oif is `lo` (verified on 6.8 — `End.DT6 dev lo` installs as a
            // plain route), so a decap localsid must ride on a real device.
            // End.M reuses the End.DT6 kernel action; End.DT46 is the
            // dual-family decap BGP L3VPN-over-SRv6 programs per VRF — both
            // join this group or their decap silently vanishes.
            SidBehavior::End
            | SidBehavior::UN
            | SidBehavior::EndDT4
            | SidBehavior::EndDT6
            | SidBehavior::EndDT46
            | SidBehavior::EndM => self.resolve_sr0_ifindex(),
            _ => self.resolve_lo_ifindex(),
        }
    }

    /// Look up the sr0 dummy by name, falling back to lo when sr0 isn't
    /// in the link table yet (early startup). Pulled out of
    /// `resolve_sid_ifindex` so the message handlers can reach it
    /// directly when filling in `ifindex_origin` for static
    /// seg6local routes.
    fn resolve_sr0_ifindex(&self) -> Option<u32> {
        self.links
            .values()
            .find(|link| link.name == SR0_DUMMY_NAME)
            .map(|link| link.index)
            .or_else(|| self.resolve_lo_ifindex())
    }

    /// Make sure the sr0 dummy interface exists and is up. Called once
    /// at startup after the initial FIB dump has populated `self.links`,
    /// so we can detect a pre-existing sr0 and avoid clobbering it.
    /// Sets `sr0_owned = true` only when this process created the
    /// device — used by the shutdown path to decide whether to delete it.
    pub async fn ensure_sr0_dummy(&mut self) {
        if self.links.values().any(|link| link.name == SR0_DUMMY_NAME) {
            // Operator (or a prior run) left sr0 in place — assume they
            // own its lifecycle and just verify it's up.
            return;
        }
        let Some(ifindex) = self.fib_handle.dummy_add(SR0_DUMMY_NAME).await else {
            tracing::warn!("sr0 dummy create failed — End SID installs will fall back to lo");
            return;
        };
        self.fib_handle.link_set_up(ifindex).await;
        self.sr0_owned = true;
        // tracing::info!("sr0 dummy created (ifindex={})", ifindex);
    }

    /// Inverse of `ensure_sr0_dummy` — only deletes when this process
    /// created the device. Called from the Shutdown message handler.
    pub async fn cleanup_sr0_dummy(&self) {
        if !self.sr0_owned {
            return;
        }
        self.fib_handle.dummy_del(SR0_DUMMY_NAME).await;
    }

    /// Install an allocated SID into the FIB: allocate / share a kernel
    /// nhid via NexthopMap, install the route as RouteType::Local with
    /// seg6local action, and record the entry in `self.sids` so the
    /// show table reflects it.
    async fn sid_install(&mut self, mut sid: Sid) {
        let original_ifindex = sid.ifindex;
        if sid.ifindex == 0
            && let Some(ifindex) = self.resolve_sid_ifindex(sid.behavior)
        {
            sid.ifindex = ifindex;
        }
        if crate::rib::tracing::rib_srv6() {
            tracing::info!(
                "[sid_install] addr={} behavior={:?} locator={} owner={} \
                 ifindex={} (orig={}) nh6={:?}",
                sid.addr,
                sid.behavior,
                sid.locator,
                sid.owner,
                sid.ifindex,
                original_ifindex,
                sid.nh6,
            );
        }
        // No usable ifindex → skip FIB install but keep the registry
        // entry so the LSP advertisement and show table are unaffected.
        if sid.ifindex == 0 {
            tracing::warn!(
                "[sid_install] addr={} skipped — no SID device ifindex resolved yet",
                sid.addr
            );
            self.sids.insert(sid.addr, sid);
            return;
        }

        let uni = Self::sid_nexthop_uni(&sid);
        let Some(group) = self.nmap.fetch(&uni, RT_TABLE_MAIN) else {
            tracing::warn!(
                "[sid_install] addr={} NexthopMap::fetch returned None",
                sid.addr
            );
            self.sids.insert(sid.addr, sid);
            return;
        };
        let gid = group.gid();
        let need_install = !group.is_installed();
        group.refcnt_inc();
        if crate::rib::tracing::rib_srv6() {
            tracing::info!(
                "[sid_install] addr={} resolved gid={} need_install={} refcnt={}",
                sid.addr,
                gid,
                need_install,
                group.refcnt(),
            );
        }

        if need_install {
            self.fib_handle.nexthop_add(group).await;
            if let Some(g) = self.nmap.get_mut(gid) {
                g.set_installed(true);
            }
        }
        let ifindex = sid.ifindex;
        self.fib_handle.route_sid_install(&sid, gid, ifindex).await;

        // Surface the SID in the IPv6 RIB so `show ipv6 route` reflects
        // it. We index by `Sid::prefix()` so install / uninstall keep
        // RIB and FIB in lock-step (uN is a /(LB+LN) install; the rest
        // are /128).
        self.sid_rib_insert(&sid);

        self.sids.insert(sid.addr, sid);
    }

    /// Insert a `RibEntry` for this SID into `self.table_v6`. Replaces
    /// any prior entry for the same prefix that was owned by a SID
    /// (idempotent across re-installs); leaves SPF-installed entries
    /// alone.
    fn sid_rib_insert(&mut self, sid: &Sid) {
        let prefix = sid.prefix();
        let entry = sid_rib_entry(sid);
        let entries = self.table_v6.entry(prefix).or_default();
        entries.retain(|e| !is_seg6local_entry(e));
        entries.push(entry);
    }

    /// Remove a previously-inserted SID `RibEntry`. Must match the same
    /// prefix the install used.
    fn sid_rib_remove(&mut self, sid: &Sid) {
        let prefix = sid.prefix();
        if let Some(entries) = self.table_v6.get_mut(&prefix) {
            entries.retain(|e| !is_seg6local_entry(e));
        }
    }

    /// Tear down a previously-installed SID. Walks back through the
    /// same NexthopMap entry the install used; the kernel nhid is only
    /// removed when the last referencing SID drops it.
    async fn sid_uninstall(&mut self, addr: Ipv6Addr) {
        let Some(sid) = self.sids.remove(&addr) else {
            return;
        };

        // Drop the RIB entry first so a concurrent show doesn't see a
        // dangling row after the kernel install is gone.
        self.sid_rib_remove(&sid);

        if sid.ifindex == 0 {
            // Wasn't installed (no loopback at SidAdd time); nothing to
            // tear down on the kernel side.
            return;
        }

        self.fib_handle.route_sid_uninstall(&sid).await;

        let uni = Self::sid_nexthop_uni(&sid);
        let Some(group) = self.nmap.fetch(&uni, RT_TABLE_MAIN) else {
            return;
        };
        let gid = group.gid();
        group.refcnt_dec();
        if group.refcnt() == 0 {
            self.fib_handle.nexthop_del(group).await;
            if let Some(g) = self.nmap.get_mut(gid) {
                g.set_installed(false);
            }
        }
    }

    /// Resolve a mirror-context route's VRF name to its kernel table id
    /// and the seg6 device, then install it. A VRF the RIB doesn't know
    /// yet is skipped — IS-IS re-sends on its next reconcile (config /
    /// locator change), by which point the VRF master has usually
    /// appeared.
    async fn mirror_route_install(
        &mut self,
        prefix: ipnet::Ipv6Net,
        context_table: u32,
        vrf_name: String,
    ) {
        let Some(vrf_table) = self.vrfs.get(&vrf_name).map(|v| v.table_id) else {
            tracing::warn!(
                "[mirror_route] vrf {} not known — skipping mirror-context install of {}",
                vrf_name,
                prefix
            );
            return;
        };
        let Some(ifindex) = self.resolve_sr0_ifindex() else {
            tracing::warn!(
                "[mirror_route] no seg6 device — skipping mirror-context install of {}",
                prefix
            );
            return;
        };
        self.fib_handle
            .route_mirror_context_install(&prefix, context_table, vrf_table, ifindex)
            .await;
    }

    /// Register a subscriber. `proto_id` is allocated by
    /// [`crate::config::ConfigManager::subscribe_to_rib`] before this
    /// runs; we record the row in `client_registry`, which is the
    /// sole source of truth for both inbound dispatch and the
    /// outbound push paths. The initial-state dump and the trailing
    /// `EoR` are unchanged.
    pub fn subscribe(
        &mut self,
        proto_id: ProtoId,
        tx: UnboundedSender<RibRx>,
        proto: String,
        vrf_id: u32,
    ) {
        // A subscriber may have dropped its receiver before this
        // handler ran (e.g. its constructor failed after the
        // `Message::Subscribe` was already queued). Every dump send
        // below is therefore best-effort: on the first `SendError` we
        // bail out without registering the subscriber, so we don't
        // panic and don't leave a dead entry in `client_registry`.
        if tx.is_closed() {
            tracing::warn!(
                "rib: subscriber '{proto}' dropped before subscribe could deliver dump; skipping"
            );
            return;
        }
        // Link dump.
        for (_, link) in self.links.iter() {
            let msg = RibRx::LinkAdd(link.clone());
            if tx.send(msg).is_err() {
                return;
            }
            for addr in link.addr4.iter() {
                let msg = RibRx::AddrAdd(addr.clone());
                if tx.send(msg).is_err() {
                    return;
                }
            }
            for addr in link.addr6.iter() {
                let msg = RibRx::AddrAdd(addr.clone());
                if tx.send(msg).is_err() {
                    return;
                }
            }
        }
        // VXLAN dump. Replay every observed VXLAN device with a
        // local IP — same cold-start race motivation as the FDB
        // replay below: without this, BGP misses VXLANs that
        // `link_add` saw during `fib_dump` and Type-3 (IMET) routes
        // would never originate.
        for link in self.links.values() {
            if let (Some(vni), Some(local)) = (link.vni, link.vxlan_local) {
                let _ = tx.send(RibRx::VxlanAdd {
                    vni,
                    vtep_local: local,
                });
            }
        }
        // FDB dump. Replay every existing AF_BRIDGE neighbor that
        // resolves to a known VNI. Without this, FDB entries learned
        // during `fib_dump` — i.e. *before* BGP subscribed — would
        // never reach the EVPN advertise path: `api_fdb_add` walks
        // `client_registry`, which was empty at fib_dump time. The
        // typical cold-start order is fib_dump (populates
        // `self.neighbors`) → BGP subscribe (this fn), so every
        // entry needs an explicit replay here.
        for (key, nbr) in self.neighbors.iter() {
            if !matches!(key, NeighborKey::Bridge { .. }) {
                continue;
            }
            if let Some(entry) = fdb_entry_from_neighbor(self, nbr) {
                let _ = tx.send(RibRx::FdbAdd(entry));
            }
        }
        // Router-id replay: default-VRF subscribers get the global
        // effective value; per-VRF subscribers (registered under
        // their kernel `table_id`) get their VRF's effective value —
        // configured `vrf <name> router-id`, else derived from the
        // VRF's member interfaces, else the global value (see
        // `router_id_update`).
        let replay_router_id = if vrf_id == 0 {
            self.router_id
        } else {
            self.vrfs
                .values()
                .find(|v| v.table_id == vrf_id)
                .map(|v| v.router_id)
                .unwrap_or(self.router_id)
        };
        if !replay_router_id.is_unspecified() {
            let msg = RibRx::RouterIdUpdate(replay_router_id);
            if tx.send(msg).is_err() {
                return;
            }
        }
        // VRF dump — only for default-VRF subscribers (BGP). A
        // per-VRF subscriber wouldn't act on VrfAdd for sibling
        // VRFs and the global Bgp is the only one that needs to
        // lift placeholder `BgpVrf` contexts to real `for_vrf`
        // once the kernel has acknowledged the master.
        if vrf_id == 0 {
            for vrf in self.vrfs.values() {
                let msg = RibRx::VrfAdd {
                    name: vrf.name.clone(),
                    table_id: vrf.table_id,
                    ifindex: vrf.ifindex,
                };
                if tx.send(msg).is_err() {
                    return;
                }
                // RT snapshot follows the VrfAdd. The receiver
                // can already key off `name` because the replay
                // guarantees VrfAdd lands first.
                let rt_msg = RibRx::VrfRouteTargets {
                    name: vrf.name.clone(),
                    ipv4_import_rts: vrf.ipv4_import_rts.clone(),
                    ipv4_export_rts: vrf.ipv4_export_rts.clone(),
                    ipv6_import_rts: vrf.ipv6_import_rts.clone(),
                    ipv6_export_rts: vrf.ipv6_export_rts.clone(),
                };
                if tx.send(rt_msg).is_err() {
                    return;
                }
            }
        }
        if tx.send(RibRx::EoR).is_err() {
            return;
        }
        self.client_registry
            .register_with_id(proto_id, &proto, tx, vrf_id);
    }

    async fn proto_cleanup(&mut self, proto: String) {
        // Reclaim any dynamic label blocks the protocol held — done
        // before the rtype gate so it covers every requester.
        self.label_manager.release_all(&proto);

        let rtype = match proto.as_str() {
            "bgp" => RibType::Bgp,
            "isis" => RibType::Isis,
            "ospf" => RibType::Ospf,
            // Protocols with no main-table rtype (e.g. a per-VRF
            // instance like `"isis:vrf:<name>"`, whose routes live in
            // `vrf_tables` and are reclaimed by `VrfDel`) still need
            // their client-registry / SR / redistribute rows dropped.
            _ => {
                self.proto_unregister(&proto);
                return;
            }
        };

        let v4_prefixes: Vec<Ipv4Net> = self
            .table
            .iter()
            .filter_map(|(prefix, entries)| {
                entries.iter().any(|e| e.rtype == rtype).then_some(prefix)
            })
            .collect();
        for prefix in v4_prefixes {
            self.ipv4_route_del(&prefix, RibEntry::new(rtype), RT_TABLE_MAIN)
                .await;
        }

        let v6_prefixes: Vec<Ipv6Net> = self
            .table_v6
            .iter()
            .filter_map(|(prefix, entries)| {
                entries.iter().any(|e| e.rtype == rtype).then_some(prefix)
            })
            .collect();
        for prefix in v6_prefixes {
            self.ipv6_route_del(&prefix, RibEntry::new(rtype), RT_TABLE_MAIN)
                .await;
        }

        // Withdraw this protocol's contribution to every label it owns
        // a candidate at. `ilm_del` re-selects, so a label shared with
        // another protocol simply falls back to the surviving entry.
        let targets: Vec<(u32, IlmEntry)> = self
            .ilm
            .iter()
            .flat_map(|(label, entries)| {
                entries
                    .iter()
                    .filter(|e| e.rtype == rtype)
                    .map(move |e| (*label, e.clone()))
            })
            .collect();
        for (label, entry) in targets {
            self.ilm_del(label, entry).await;
        }

        self.proto_unregister(&proto);
    }

    /// Drop the per-protocol registry / redist filters / SR
    /// watchers without touching the FIB. Used by
    /// `proto_cleanup` after withdrawing routes.
    fn proto_unregister(&mut self, proto: &str) {
        if let Some(proto_id) = self.client_registry.find_by_proto(proto) {
            self.client_registry.unregister(proto_id);
        }
        self.redist_filters.remove(proto);
        self.sr_clients.remove(proto);
        for watchers in self.block_watch.values_mut() {
            watchers.remove(proto);
        }
        for watchers in self.locator_watch.values_mut() {
            watchers.remove(proto);
        }
    }

    // ---- redistribute subscription handlers ------------------------
    //
    // Registry + walk-and-replay plus the steady-state delta hook
    // that fires on FIB churn.

    /// Self-route check + registry insert. Returns the Tx the walker
    /// should push routes to, or `None` if the subscription is to be
    /// silently dropped (self-loop, or subscriber never called
    /// Subscribe so there's no Tx).
    fn redist_register(
        &mut self,
        proto: &str,
        afi: super::RedistAfi,
        rtype: RibType,
        subtypes: std::collections::BTreeSet<super::RibSubType>,
    ) -> Option<UnboundedSender<RibRx>> {
        // Self-route filter — unconditional. A subscriber whose proto
        // maps to the rtype it's asking for would never receive
        // anything; drop at registration so the registry stays clean.
        if !super::redist::deliverable(proto, rtype) {
            return None;
        }
        let tx = self
            .client_registry
            .subscriber_for_proto(proto)?
            .rib_rx_tx
            .clone();
        self.redist_filters
            .entry(proto.to_string())
            .or_default()
            .insert((afi, rtype), subtypes);
        Some(tx)
    }

    fn redist_add(
        &mut self,
        proto: String,
        afi: super::RedistAfi,
        rtype: RibType,
        subtypes: std::collections::BTreeSet<super::RibSubType>,
    ) {
        let Some(tx) = self.redist_register(&proto, afi, rtype, subtypes.clone()) else {
            return;
        };
        self.redist_walk(
            &proto,
            afi,
            rtype,
            &subtypes,
            super::redist::WalkOp::Add,
            &tx,
        );
    }

    /// Replace the prior subtype set for `(proto, afi, rtype)` and
    /// emit the appropriate Add/Del delta. Treats a missing prior row
    /// as empty (so first-ever Update behaves like Add).
    ///
    /// Wildcard handling (`subtypes: {}` means "match every subtype"):
    /// the symmetric-difference shortcut is only valid when both
    /// sides are non-wildcard. When either side is wildcard, fall
    /// back to a full `Del(prior) + Add(new)` sweep — slightly
    /// heavier but the only correct option since "every subtype
    /// except this list" isn't expressible as a finite set without
    /// enumerating `RibSubType::Other(u8)`.
    fn redist_update(
        &mut self,
        proto: String,
        afi: super::RedistAfi,
        rtype: RibType,
        subtypes: std::collections::BTreeSet<super::RibSubType>,
    ) {
        if !super::redist::deliverable(&proto, rtype) {
            return;
        }
        let Some(tx) = self
            .client_registry
            .subscriber_for_proto(&proto)
            .map(|s| s.rib_rx_tx.clone())
        else {
            return;
        };
        let prior = self
            .redist_filters
            .get(&proto)
            .and_then(|f| f.get(&(afi, rtype)))
            .cloned()
            .unwrap_or_default();
        if prior == subtypes {
            return; // no-op
        }

        if prior.is_empty() || subtypes.is_empty() {
            // Wildcard on either side — fall back to full re-walk.
            // Consumer briefly sees Del then Add for any routes
            // shared by both filters; acceptable for redistribute
            // (config-time, not data-plane).
            self.redist_walk(&proto, afi, rtype, &prior, super::redist::WalkOp::Del, &tx);
            self.redist_walk(
                &proto,
                afi,
                rtype,
                &subtypes,
                super::redist::WalkOp::Add,
                &tx,
            );
        } else {
            // Both non-wildcard — symmetric difference is correct and
            // avoids the brief Del→Add glitch on shared subtypes.
            let removed: std::collections::BTreeSet<super::RibSubType> =
                prior.difference(&subtypes).cloned().collect();
            if !removed.is_empty() {
                self.redist_walk(
                    &proto,
                    afi,
                    rtype,
                    &removed,
                    super::redist::WalkOp::Del,
                    &tx,
                );
            }
            let added: std::collections::BTreeSet<super::RibSubType> =
                subtypes.difference(&prior).cloned().collect();
            if !added.is_empty() {
                self.redist_walk(&proto, afi, rtype, &added, super::redist::WalkOp::Add, &tx);
            }
        }

        self.redist_filters
            .entry(proto)
            .or_default()
            .insert((afi, rtype), subtypes);
    }

    fn redist_del(&mut self, proto: String, afi: super::RedistAfi, rtype: RibType) {
        let Some(tx) = self
            .client_registry
            .subscriber_for_proto(&proto)
            .map(|s| s.rib_rx_tx.clone())
        else {
            // No Tx → nothing to withdraw. Still clear the filter row
            // so memory doesn't leak across re-subscribes.
            if let Some(f) = self.redist_filters.get_mut(&proto) {
                f.remove(&(afi, rtype));
            }
            return;
        };
        // Withdraw using whatever filter we had registered.
        let Some(filter) = self
            .redist_filters
            .get(&proto)
            .and_then(|f| f.get(&(afi, rtype)))
            .cloned()
        else {
            return;
        };
        self.redist_walk(&proto, afi, rtype, &filter, super::redist::WalkOp::Del, &tx);
        if let Some(f) = self.redist_filters.get_mut(&proto) {
            f.remove(&(afi, rtype));
        }
    }

    fn redist_walk(
        &self,
        proto: &str,
        afi: super::RedistAfi,
        rtype: RibType,
        subtypes: &std::collections::BTreeSet<super::RibSubType>,
        op: super::redist::WalkOp,
        tx: &UnboundedSender<RibRx>,
    ) {
        match afi {
            super::RedistAfi::Ipv4 => {
                super::redist::walk_v4(&self.table, proto, rtype, subtypes, op, tx);
            }
            super::RedistAfi::Ipv6 => {
                super::redist::walk_v6(&self.table_v6, proto, rtype, subtypes, op, tx);
            }
        }
    }

    /// `table_id` is the kernel `rtm_table` the route should be
    /// installed into. Inbound envelopes from a VRF-bound subscriber
    /// arrive with their VRF's table id; legacy / internal sends
    /// arrive with [`RT_TABLE_MAIN`].
    ///
    /// IPv4/IPv6 installs dispatch to the global default-table
    /// helper (legacy path, full best-path + FIB install) when
    /// `table_id == RT_TABLE_MAIN`, or to the per-VRF helper that
    /// records the install in `vrf_tables[table_id]` otherwise.
    /// The per-VRF helper deliberately skips best-path / FIB; the
    /// import / export pipeline supplies the resolution overlay
    /// that makes the kernel install correct.
    ///
    /// ILM is VRF-agnostic at the kernel (single global MPLS table),
    /// so the dispatcher ignores `table_id` for those variants and
    /// the global path runs unchanged — see `Rib::ilm_add`.
    /// A connected route belongs in the routing table of the VRF its
    /// interface is enslaved to. Internal `Ipv4Add`/`Ipv6Add` sends
    /// arrive with `RT_TABLE_MAIN` and carry the interface ifindex on
    /// the entry; redirect the connected ones onto their interface's
    /// VRF table so they land in `vrf_tables` instead of polluting the
    /// default table. Non-connected entries and inbound envelopes that
    /// already name a VRF table are returned unchanged.
    fn route_table_for(&self, entry: &RibEntry, table_id: u32) -> u32 {
        if table_id == RT_TABLE_MAIN && entry.is_connected() {
            let vrf_id = self.ifindex_vrf_id(entry.ifindex);
            if vrf_id != 0 {
                return vrf_id;
            }
        }
        table_id
    }

    async fn process_msg(&mut self, msg: Message, table_id: u32) {
        match msg {
            Message::Ipv4Add { prefix, rib } => {
                let table_id = self.route_table_for(&rib, table_id);
                if table_id == RT_TABLE_MAIN {
                    self.ipv4_route_add(&prefix, rib, table_id).await;
                    self.nht_recompute_and_notify();
                } else {
                    self.ipv4_route_add_vrf(table_id, &prefix, rib).await;
                }
            }
            Message::Ipv4Del { prefix, rib } => {
                let table_id = self.route_table_for(&rib, table_id);
                if table_id == RT_TABLE_MAIN {
                    self.ipv4_route_del(&prefix, rib, table_id).await;
                    self.nht_recompute_and_notify();
                } else {
                    self.ipv4_route_del_vrf(table_id, &prefix, rib).await;
                }
            }
            Message::Ipv6Add { prefix, rib } => {
                let table_id = self.route_table_for(&rib, table_id);
                if table_id == RT_TABLE_MAIN {
                    self.ipv6_route_add(&prefix, rib, table_id).await;
                    self.nht_recompute_and_notify();
                } else {
                    self.ipv6_route_add_vrf(table_id, &prefix, rib).await;
                }
            }
            Message::Ipv6Del { prefix, rib } => {
                let table_id = self.route_table_for(&rib, table_id);
                if table_id == RT_TABLE_MAIN {
                    self.ipv6_route_del(&prefix, rib, table_id).await;
                    self.nht_recompute_and_notify();
                } else {
                    self.ipv6_route_del_vrf(table_id, &prefix, rib).await;
                }
            }
            Message::NexthopRegister { proto, nh } => {
                self.nht_register(proto, nh);
            }
            Message::ProtectSwitch { addr } => {
                let (rewired, evicted) =
                    super::route::protect_switch(&mut self.nmap, &self.fib_handle, table_id, addr)
                        .await;
                // Distinct info lines ONLY when something actually moved —
                // the BDD log assertions key on these exact phrasings, so a
                // zero-candidate no-op must not be able to satisfy them.
                if rewired > 0 {
                    tracing::info!(
                        "ProtectSwitch {addr} table {table_id}: rewired {rewired} protection group(s) onto repairs"
                    );
                }
                if evicted > 0 {
                    tracing::info!(
                        "ProtectSwitch {addr} table {table_id}: evicted failed leg from {evicted} ECMP group(s)"
                    );
                }
                if rewired == 0 && evicted == 0 {
                    tracing::debug!("ProtectSwitch {addr} table {table_id}: no eligible groups");
                }
            }
            Message::NexthopUnregister { proto, nh } => {
                self.nht.unregister(&proto, nh);
            }
            Message::LabelBlockRequest { proto, size } => {
                self.label_block_request(proto, size);
            }
            Message::LabelBlockRelease { proto, start, size } => {
                self.label_manager.release(&proto, start, size);
            }
            Message::IlmAdd { label, ilm } => {
                self.ilm_add(label, ilm).await;
            }
            Message::IlmDel { label, ilm } => {
                self.ilm_del(label, ilm).await;
            }
            Message::FlexAlgoRouteAdd { route } => {
                // Last-writer-wins on (algo, prefix). The same key
                // re-published from a later SPF cycle overwrites the
                // previous snapshot in place; consumers see the new
                // metric / nexthops on the next subscribe-side recv.
                self.flex_algo_routes
                    .entry(route.algo)
                    .or_default()
                    .insert(route.prefix, route.clone());
                self.api_flex_algo_route_add(&route);
            }
            Message::FlexAlgoRouteDel { algo, prefix } => {
                let became_empty = if let Some(table) = self.flex_algo_routes.get_mut(&algo) {
                    table.remove(&prefix);
                    table.iter().next().is_none()
                } else {
                    false
                };
                if became_empty {
                    self.flex_algo_routes.remove(&algo);
                }
                self.api_flex_algo_route_del(algo, prefix);
            }
            Message::FlexAlgoSrv6RouteAdd { route } => {
                // No RIB-side shadow: the per-algo locator routes already
                // live in the FIB (installed by IS-IS) and this metadata
                // is only consumed live by the colour-aware resolver, so
                // we fan it out without persisting (same delivery model
                // as the SR-MPLS path's re-broadcast).
                self.api_flex_algo_srv6_route_add(&route);
            }
            Message::FlexAlgoSrv6RouteDel { algo, prefix } => {
                self.api_flex_algo_srv6_route_del(algo, prefix);
            }
            Message::BridgeAdd { name, config } => {
                let bridge = Bridge {
                    name: name.clone(),
                    addr_gen_mode: config.addr_gen_mode,
                };
                self.bridges.insert(name.clone(), bridge.clone());
                self.fib_handle.bridge_add(&bridge).await;
            }
            Message::BridgeDel { name } => {
                let bridge = Bridge {
                    name: name.clone(),
                    ..Default::default()
                };
                self.bridges.remove(&name);
                self.fib_handle.bridge_del(&bridge).await;
            }
            Message::VxlanAdd { name, config } => {
                let vxlan = Vxlan {
                    name: name.clone(),
                    vni: config.vni,
                    local_addr: config.local_addr,
                    dport: config.dport,
                    addr_gen_mode: config.addr_gen_mode,
                };
                self.vxlan.insert(name.clone(), vxlan.clone());
                self.fib_handle.vxlan_add(&vxlan).await;
            }
            Message::VxlanDel { name } => {
                let vxlan = Vxlan {
                    name: name.clone(),
                    ..Default::default()
                };
                self.vxlan.remove(&name);
                self.fib_handle.vxlan_del(&vxlan).await;
            }
            Message::VrfAdd { name } => {
                if self.vrfs.contains_key(&name) {
                    // Re-creating an already-applied VRF (e.g. operator
                    // sets the same name twice in one commit batch) is a
                    // no-op: the kernel interface already exists with
                    // the previously-allocated table id, and re-issuing
                    // `ip link add` would just error.
                    return;
                }
                // A VRF master of this name may already exist in the
                // kernel — left over from a previous run that didn't
                // clean up, or pre-created by the operator. Adopt it
                // (taking the kernel's table id as authoritative) rather
                // than trying to create a duplicate, which the kernel
                // rejects with EEXIST and which would leave the VRF
                // unusable and any pending interface binding stuck.
                let (ifindex, table_id, owned) = if let Some((ifindex, existing_table)) =
                    self.fib_handle.vrf_index_table_by_name(&name).await
                {
                    self.vrf_id_alloc.reserve(existing_table);
                    tracing::info!(
                        "vrf_add: adopting existing kernel VRF {} ifindex={} table_id={}",
                        name,
                        ifindex,
                        existing_table
                    );
                    // Adopted, not created — leave it in place on exit.
                    (ifindex, existing_table, false)
                } else {
                    let Some(table_id) = self.vrf_id_alloc.allocate() else {
                        tracing::warn!("vrf_add({}) failed — id space exhausted", name);
                        return;
                    };
                    let Some(ifindex) = self.fib_handle.vrf_add(&name, table_id).await else {
                        // Netlink rejected the create — release the id so
                        // the next attempt isn't penalised by a leak.
                        self.vrf_id_alloc.release(table_id);
                        return;
                    };
                    (ifindex, table_id, true)
                };
                self.vrfs.insert(
                    name.clone(),
                    Vrf {
                        name: name.clone(),
                        table_id,
                        ifindex,
                        // Router-id config arrives separately via
                        // `Message::VrfRouterId`; the effective value
                        // is computed by `router_id_update` below once
                        // the row exists.
                        router_id: Ipv4Addr::UNSPECIFIED,
                        router_id_config: None,
                        owned,
                        // RT sets arrive separately via
                        // `Message::VrfRouteTargets` once the VRF
                        // config builder has finished parsing
                        // /vrf/<name>/{ipv4,ipv6}/route-target.
                        ipv4_import_rts: std::collections::BTreeSet::new(),
                        ipv4_export_rts: std::collections::BTreeSet::new(),
                        ipv6_import_rts: std::collections::BTreeSet::new(),
                        ipv6_export_rts: std::collections::BTreeSet::new(),
                    },
                );
                // Park an empty per-VRF routing table set keyed by
                // the same `table_id` the kernel uses. The
                // per-`ProtoId` dispatcher writes routes here when a
                // VRF-attached protocol installs.
                self.vrf_tables.insert(table_id, VrfRibTables::new());
                tracing::info!(
                    "vrf_add: {} table_id={} ifindex={}",
                    name,
                    table_id,
                    ifindex
                );
                // Notify default-VRF subscribers (currently only the
                // global BGP instance). The per-VRF spawn site lifts
                // the placeholder `ProtoContext` to a real
                // `for_vrf(rib, table_id, name)` when the VrfAdd
                // arrives — see `bgp::vrf::spawn::spawn_bgp_vrf`.
                let vrf = self.vrfs.get(&name).expect("just inserted").clone();
                self.api_vrf_add(&vrf);
                // Replay any interface bindings that were waiting for
                // this VRF to come up.
                let to_replay: Vec<(String, Option<String>)> = self
                    .pending_vrf_bind
                    .iter()
                    .filter(|(_, vrf)| vrf.as_deref() == Some(name.as_str()))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                for (ifname, vrf) in to_replay {
                    let _ = self.tx.send(Message::LinkVrfBind { ifname, vrf });
                }
                // Compute the new VRF's effective router-id (members
                // may already be enslaved when adopting a pre-existing
                // kernel VRF) — and re-evaluate the global pick, which
                // excludes VRF-enslaved links and may change now that
                // this master is known.
                self.router_id_update();
            }
            Message::VrfDel { name } => {
                let Some(vrf) = self.vrfs.remove(&name) else {
                    // Either never created, or a previous VrfAdd failed
                    // partway through. Nothing to undo locally; defer to
                    // netlink to clean up if the kernel happens to have
                    // an interface by that name.
                    self.fib_handle.vrf_del(&name).await;
                    return;
                };
                // Drop the parked per-VRF routing tables alongside
                // the kernel VRF master. The per-VRF dispatcher
                // populates these on install; a follow-up will add
                // the matching withdraw walk.
                self.vrf_tables.remove(&vrf.table_id);
                self.fib_handle.vrf_del(&name).await;
                self.vrf_id_alloc.release(vrf.table_id);
                tracing::info!("vrf_del: {} (table_id={})", name, vrf.table_id);
                self.api_vrf_del(&name);
            }
            Message::VrfRouteTargets {
                name,
                ipv4_import_rts,
                ipv4_export_rts,
                ipv6_import_rts,
                ipv6_export_rts,
            } => {
                // Idempotent — the message carries a full snapshot
                // of the staged RT sets, replacing whatever was on
                // the `Vrf` row before. A `VrfRouteTargets` for an
                // unknown VRF name is dropped silently: the YANG
                // commit always emits `VrfAdd` first, so the only
                // way to hit the `None` arm is via an out-of-order
                // self-send.
                if let Some(vrf) = self.vrfs.get_mut(&name) {
                    vrf.ipv4_import_rts = ipv4_import_rts;
                    vrf.ipv4_export_rts = ipv4_export_rts;
                    vrf.ipv6_import_rts = ipv6_import_rts;
                    vrf.ipv6_export_rts = ipv6_export_rts;
                    let vrf_snapshot = vrf.clone();
                    self.api_vrf_route_targets(&vrf_snapshot);
                } else {
                    tracing::debug!(
                        vrf = %name,
                        "rib: VrfRouteTargets for unknown VRF; dropping",
                    );
                }
            }
            Message::VrfRouterId { name, router_id } => {
                // Same ordering contract as `VrfRouteTargets`: the
                // YANG commit emits `VrfAdd` first, so an unknown name
                // here is an out-of-order self-send — drop it.
                if let Some(vrf) = self.vrfs.get_mut(&name) {
                    vrf.router_id_config = router_id;
                    // Recompute + emit (configured wins; delete falls
                    // back to the derived pick / global value).
                    self.router_id_update();
                } else {
                    tracing::debug!(
                        vrf = %name,
                        "rib: VrfRouterId for unknown VRF; dropping",
                    );
                }
            }
            Message::LinkVrfBind { ifname, vrf } => {
                // Always record operator intent so a later kernel
                // NewLink (interface appears) or VrfAdd (master is
                // created) can fire the bind without the operator
                // re-issuing the command.
                if vrf.is_none() {
                    self.pending_vrf_bind.remove(&ifname);
                } else {
                    self.pending_vrf_bind.insert(ifname.clone(), vrf.clone());
                }

                let (ifindex, current_master) = match self.links.values().find(|l| l.name == ifname)
                {
                    Some(link) => (link.index, link.master.unwrap_or(0)),
                    None => {
                        tracing::info!(
                            "link_vrf_bind: interface {} not present yet — pending",
                            ifname
                        );
                        return;
                    }
                };

                let master = match &vrf {
                    Some(vrf_name) => match self.vrfs.get(vrf_name) {
                        Some(v) => v.ifindex,
                        None => {
                            tracing::info!(
                                "link_vrf_bind: vrf {} not present yet — pending",
                                vrf_name
                            );
                            return;
                        }
                    },
                    None => 0,
                };

                // Only touch the kernel when the master actually changes.
                // `pending_vrf_bind` is kept as durable desired-state (so
                // an interface flap re-binds), which means `link_add`
                // replays this message on every RTM_NEWLINK for the
                // interface. Enslaving emits a burst of those (master +
                // operstate/flag transitions), so without this guard each
                // one re-issues a redundant `link_set_master` — log spam
                // and a potential feedback loop.
                if current_master == master {
                    return;
                }

                self.fib_handle.link_set_master(ifindex, master).await;
                tracing::info!(
                    "link_vrf_bind: ifname={} ifindex={} master={} vrf={:?}",
                    ifname,
                    ifindex,
                    master,
                    vrf
                );
            }
            Message::BlockAdd { name, config } => {
                let block = config.to_block();
                self.blocks.insert(name.clone(), block);
                self.notify_block_watchers(&name);
            }
            Message::BlockDel { name } => {
                self.blocks.remove(&name);
                // The default block is always present — re-seed it so a
                // delete of `default` reverts to the canonical values
                // rather than leaving subscribers without a block.
                if name == DEFAULT_BLOCK_NAME {
                    self.blocks
                        .insert(DEFAULT_BLOCK_NAME.to_string(), Block::default_block());
                }
                self.notify_block_watchers(&name);
            }
            Message::LocatorAdd { name, config } => {
                let locator = config.to_locator();
                self.locators.insert(name.clone(), locator);
                self.notify_locator_watchers(&name);
            }
            Message::LocatorDel { name } => {
                self.locators.remove(&name);
                self.notify_locator_watchers(&name);
            }
            Message::SrSubscribe { proto, tx } => {
                self.sr_clients.insert(proto, tx);
            }
            Message::SrBlockWatch { proto, name } => {
                self.block_watch
                    .entry(name.clone())
                    .or_default()
                    .insert(proto.clone());
                // Push the current value so the subscriber doesn't have to
                // wait for the next change to learn what's there today.
                if let Some(tx) = self.sr_clients.get(&proto) {
                    let _ = tx.send(RibSrRx::Block {
                        name: name.clone(),
                        block: self.blocks.get(&name).cloned(),
                    });
                }
            }
            Message::SrBlockUnwatch { proto, name } => {
                if let Some(set) = self.block_watch.get_mut(&name) {
                    set.remove(&proto);
                    if set.is_empty() {
                        self.block_watch.remove(&name);
                    }
                }
            }
            Message::SrLocatorWatch { proto, name } => {
                self.locator_watch
                    .entry(name.clone())
                    .or_default()
                    .insert(proto.clone());
                if let Some(tx) = self.sr_clients.get(&proto) {
                    let _ = tx.send(RibSrRx::Locator {
                        name: name.clone(),
                        locator: self.locators.get(&name).cloned(),
                    });
                }
            }
            Message::SrLocatorUnwatch { proto, name } => {
                if let Some(set) = self.locator_watch.get_mut(&name) {
                    set.remove(&proto);
                    if set.is_empty() {
                        self.locator_watch.remove(&name);
                    }
                }
            }
            Message::SidAdd { sid } => {
                self.sid_install(sid).await;
            }
            Message::SidDel { addr } => {
                self.sid_uninstall(addr).await;
            }
            Message::MirrorRouteAdd {
                prefix,
                context_table,
                vrf_name,
            } => {
                self.mirror_route_install(prefix, context_table, vrf_name)
                    .await;
            }
            Message::MirrorRouteDel {
                prefix,
                context_table,
            } => {
                self.fib_handle
                    .route_mirror_context_uninstall(&prefix, context_table)
                    .await;
            }
            Message::Shutdown { tx } => {
                self.nmap.shutdown(&self.fib_handle).await;
                let ilms = self.ilm.clone();

                // One AF_MPLS route per label in the kernel — delete the
                // installed (selected) candidate for each.
                for (&label, entries) in ilms.iter() {
                    if let Some(installed) = entries.iter().find(|e| e.selected) {
                        self.fib_handle.ilm_del(label, installed).await;
                    }
                }
                self.ilm.clear();
                // Clean up EVPN-installed FDB rows on externally-managed
                // VXLAN devices BEFORE we tear down zebra-rs-managed
                // bridges/VXLANs. For zebra-rs-managed devices the
                // device deletion would auto-purge the FDB, but
                // operators commonly create the VXLAN themselves
                // (`ip link add vni550 type vxlan ...`) — those
                // outlive the daemon and would keep stale extern_learn
                // rows. Walk both the unicast MAC table and the
                // ingress-replication VTEP set; the FIB calls are
                // no-ops if the VXLAN itself was removed by the
                // bridge/vxlan loops below.
                let macs: Vec<(u32, MacAddr)> = self.mac_table.keys().copied().collect();
                for (vni, mac) in macs {
                    self.fib_handle.mac_del(vni, &mac).await;
                }
                self.mac_table.clear();
                let vteps: Vec<(u32, IpAddr)> = self.vtep_table.iter().copied().collect();
                for (vni, group) in vteps {
                    self.fib_handle.mdb_del(vni, group, None, 0).await;
                }
                self.vtep_table.clear();
                for (_, bridge) in self.bridges.iter() {
                    self.fib_handle.bridge_del(bridge).await;
                }
                for (_, vxlan) in self.vxlan.iter() {
                    self.fib_handle.vxlan_del(vxlan).await;
                }
                // Tear down the VRF master devices this process created
                // (adopted ones are left for their owner). Enslaved
                // interfaces are released back to the default VRF by the
                // kernel automatically when the master goes.
                let owned_vrfs: Vec<String> = self
                    .vrfs
                    .values()
                    .filter(|v| v.owned)
                    .map(|v| v.name.clone())
                    .collect();
                for name in owned_vrfs {
                    self.fib_handle.vrf_del(&name).await;
                }
                self.cleanup_sr0_dummy().await;
                let _ = tx.send(());
            }
            Message::LinkUp { ifindex } => {
                // println!("LinkUp {}", ifindex);
                self.link_up(ifindex).await;
            }
            Message::LinkDown { ifindex } => {
                // println!("LinkDown {}", ifindex);
                self.link_down(ifindex).await;
            }
            Message::Resolve => {
                // Drop the timer so the next FIB modification can arm a fresh
                // one. Run both family resolves so static / SRv6 nexthops that
                // were unresolved at config time get a second chance once the
                // underlying IGP / connected route lands.
                self.rib_sync_timer = None;
                self.ipv4_route_resolve().await;
                self.ipv6_route_resolve().await;
                // After both families' routes have been (re)selected and
                // any now-invalid ones withdrawn, drop the kernel
                // nexthop objects for recursive groups that went
                // unresolvable — safe to delete only now that nothing
                // references them.
                nexthop_orphan_gc(&mut self.nmap, &self.fib_handle).await;
            }
            Message::Subscribe {
                proto_id,
                tx,
                proto,
                vrf_id,
            } => {
                self.subscribe(proto_id, tx, proto, vrf_id);
            }
            Message::ProtoCleanup { proto } => {
                self.proto_cleanup(proto).await;
            }
            Message::MacAdd {
                vni,
                mac,
                tunnel_endpoint,
                flags,
                seq,
                esi,
            } => {
                self.mac_add(vni, mac, tunnel_endpoint, flags, seq, esi)
                    .await;
            }
            Message::MacDel { vni, mac } => {
                self.mac_del(vni, mac).await;
            }
            Message::MdbAdd {
                vni,
                group,
                source,
                ifindex,
                seq,
            } => {
                self.mdb_add(vni, group, source, ifindex, seq).await;
            }
            Message::MdbDel {
                vni,
                group,
                source,
                ifindex,
            } => {
                self.mdb_del(vni, group, source, ifindex).await;
            }
            Message::RedistAdd {
                proto,
                afi,
                rtype,
                subtypes,
            } => {
                self.redist_add(proto, afi, rtype, subtypes);
            }
            Message::RedistUpdate {
                proto,
                afi,
                rtype,
                subtypes,
            } => {
                self.redist_update(proto, afi, rtype, subtypes);
            }
            Message::RedistDel { proto, afi, rtype } => {
                self.redist_del(proto, afi, rtype);
            }
        }
    }

    /// Kernel reported a nexthop object exists (RTM_NEWNEXTHOP). This
    /// is almost always the echo of our own install. We only keep our
    /// view consistent for a gid we own: if we thought it uninstalled,
    /// record that the kernel now has it so the next sync doesn't issue
    /// a redundant add. External nexthop ids we don't track are
    /// ignored (the gid space here is RIB-managed).
    fn fib_nexthop_added(&mut self, id: u32) {
        if let Some(group) = self.nmap.get_mut(id as usize)
            && !group.is_installed()
        {
            group.set_installed(true);
        }
    }

    /// Kernel reported a nexthop object was removed (RTM_DELNEXTHOP).
    /// Linux auto-deletes a nexthop object — and every route that
    /// referenced it — when its egress link goes down or the gateway
    /// becomes unreachable. Without this hook our `NexthopMap` keeps
    /// the group flagged `installed`, so the next resolve cycle skips
    /// re-creating it and routes pointing at the now-missing nh_id fail
    /// to install with EINVAL. Clearing `installed` lets the debounced
    /// resolve rebuild the nexthop (and re-add its dependent routes).
    /// Our own deletes echo back here too, but by then the group is
    /// gone or the flag already clear, so it's a no-op.
    fn fib_nexthop_removed(&mut self, id: u32) {
        let cleared = self.nmap.get_mut(id as usize).is_some_and(|group| {
            let was_installed = group.is_installed();
            if was_installed {
                group.set_installed(false);
            }
            was_installed
        });
        if cleared {
            tracing::info!("fib: kernel removed nexthop id {id}; scheduling reinstall");
            self.schedule_rib_sync();
        }
    }

    pub async fn process_fib_msg(&mut self, msg: FibMessage) {
        // println!("{:?}", msg);
        match msg {
            FibMessage::NewLink(link) => {
                self.link_add(link).await;
            }
            FibMessage::DelLink(link) => {
                self.link_delete(link);
            }
            FibMessage::NewAddr(addr) => {
                // Kernel netlink path: from_config=false. If a configured
                // LinkAddr is already present for this address, the merge in
                // link_addr_update will flip its `fib` flag to true.
                self.addr_add(addr, false);
                ipv4_nexthop_sync(
                    &mut self.nmap,
                    &self.table,
                    &self.vrf_tables,
                    &self.links,
                    &self.fib_handle,
                )
                .await;
                self.ipv4_default_sync(true).await;
                ipv6_nexthop_sync(
                    &mut self.nmap,
                    &self.table_v6,
                    &self.vrf_tables,
                    &self.links,
                    &self.fib_handle,
                )
                .await;
                self.ipv6_default_sync().await;
                self.router_id_update();
            }
            FibMessage::DelAddr(addr) => {
                // If the deleted address is still in config, push it
                // back to the kernel rather than tearing down state.
                // Recovery may be suppressed by hold-down; in either
                // case skip the normal teardown so the connected
                // route doesn't churn. The next NewAddr we receive
                // (from our own re-install, or from a future operator
                // add) runs the sync chain.
                if self.addr_recover_if_configured(&addr).await {
                    return;
                }

                self.addr_del(addr);
                ipv4_nexthop_sync(
                    &mut self.nmap,
                    &self.table,
                    &self.vrf_tables,
                    &self.links,
                    &self.fib_handle,
                )
                .await;
                self.ipv4_default_sync(true).await;
                ipv6_nexthop_sync(
                    &mut self.nmap,
                    &self.table_v6,
                    &self.vrf_tables,
                    &self.links,
                    &self.fib_handle,
                )
                .await;
                self.ipv6_default_sync().await;
                self.router_id_update();
            }
            FibMessage::NewRoute(route) => {
                if let IpNet::V4(prefix) = route.prefix {
                    if route.table_id == RT_TABLE_MAIN {
                        self.ipv4_route_add(&prefix, route.entry, RT_TABLE_MAIN)
                            .await;
                    } else if self.vrf_tables.contains_key(&route.table_id) {
                        // A route the kernel placed in a VRF's table —
                        // mirror it into that VRF. Tables we don't manage
                        // are ignored rather than dumped into the default.
                        self.ipv4_route_add_vrf(route.table_id, &prefix, route.entry)
                            .await;
                    }
                }
            }
            FibMessage::DelRoute(route) => {
                if let IpNet::V4(prefix) = route.prefix {
                    if route.table_id == RT_TABLE_MAIN {
                        self.ipv4_route_del(&prefix, route.entry, RT_TABLE_MAIN)
                            .await;
                    } else if self.vrf_tables.contains_key(&route.table_id) {
                        self.ipv4_route_del_vrf(route.table_id, &prefix, route.entry)
                            .await;
                    }
                }
            }
            FibMessage::NewNexthop(id) => {
                self.fib_nexthop_added(id);
            }
            FibMessage::DelNexthop(id) => {
                self.fib_nexthop_removed(id);
            }
            FibMessage::NewNeighbor(nbr) => {
                let fdb_entry = fdb_entry_from_neighbor(self, &nbr);
                if let Some(key) = neighbor_key(&nbr) {
                    self.neighbors.insert(key, nbr);
                }
                if let Some(entry) = fdb_entry {
                    self.api_fdb_add(&entry);
                }
            }
            FibMessage::DelNeighbor(nbr) => {
                let fdb_entry = fdb_entry_from_neighbor(self, &nbr);
                if let Some(key) = neighbor_key(&nbr) {
                    self.neighbors.remove(&key);
                }
                if let Some(entry) = fdb_entry {
                    self.api_fdb_del(&entry);
                }
            }
            FibMessage::NewMdb(entry) => {
                if let Some((vni, vtep_local)) = self.mdb_vni_vtep(entry.bridge_ifindex) {
                    self.api_snoop_join(vni, vtep_local, entry.group, entry.source);
                }
            }
            FibMessage::DelMdb(entry) => {
                if let Some((vni, vtep_local)) = self.mdb_vni_vtep(entry.bridge_ifindex) {
                    self.api_snoop_leave(vni, vtep_local, entry.group, entry.source);
                }
            }
        }
    }

    /// Resolve a snooped MDB entry's bridge ifindex to `(VNI, local
    /// VTEP IP)` via the bridge's VXLAN slave. `None` when the bridge
    /// has no VXLAN slave with a VNI + local address (e.g. a plain L2
    /// bridge not participating in EVPN) — such memberships are not
    /// advertised.
    fn mdb_vni_vtep(&self, bridge_ifindex: u32) -> Option<(u32, IpAddr)> {
        let vni = self.vni_for_bridge(bridge_ifindex)?;
        let vtep_local = self.vxlan_local_for_bridge(bridge_ifindex)?;
        Some((vni, vtep_local))
    }

    async fn process_cm_msg(&mut self, msg: ConfigRequest) {
        match msg.op {
            ConfigOp::CommitStart => {
                //
            }
            ConfigOp::Set | ConfigOp::Delete => {
                let (path, args) = path_from_command(&msg.paths);
                if path.as_str() == "/system/router-id" {
                    let _ = self.router_id_config_exec(args, msg.op);
                } else if path.as_str().starts_with("/router/static/ipv4/route") {
                    let _ = self.static_v4.exec(path, args, msg.op);
                } else if path.as_str().starts_with("/router/static/ipv6/route") {
                    let _ = self.static_v6.exec(path, args, msg.op);
                } else if path.as_str().starts_with("/router/static/mpls/label") {
                    let _ = self.mpls_config.exec(path, args, msg.op);
                } else if path.as_str().starts_with("/interface") {
                    // let _ = self.link_config.exec(path, args, msg.op);
                    let _ = link_config_exec(self, path, args, msg.op).await;
                } else if path.as_str().starts_with("/bridge") {
                    let _ = self.bridge_config.exec(path, args, msg.op);
                } else if path.as_str().starts_with("/vxlan") {
                    let _ = self.vxlan_config.exec(path, args, msg.op);
                } else if path.as_str().starts_with("/vrf") {
                    let _ = self.vrf_config.exec(path, args, msg.op);
                } else if path.as_str().starts_with("/segment-routing/block") {
                    let _ = self.block_config.exec(path, args, msg.op);
                } else if path.as_str().starts_with("/segment-routing/locator") {
                    let _ = self.locator_config.exec(path, args, msg.op);
                } else if path.as_str().starts_with("/system/tracing") {
                    crate::rib::tracing::config_dispatch(&path, args, msg.op);
                }
            }
            ConfigOp::CommitEnd => {
                self.bridge_config.commit(self.tx.clone());
                self.vxlan_config.commit(self.tx.clone());
                self.vrf_config.commit(self.tx.clone());
                self.link_config.commit(self.tx.clone());
                self.static_v4.commit(self.tx.clone());
                self.static_v6.commit(self.tx.clone());
                self.mpls_config.commit(self.tx.clone());
                self.block_config.commit(self.tx.clone());
                self.locator_config.commit(self.tx.clone());
            }
            ConfigOp::Completion => {
                // `comps_dynamic` passes the dynamic handler name
                // (`rib:<handler>`) as the first path segment.
                let comps = match msg.paths.first().map(|p| p.name.as_str()) {
                    Some("vrf") => self.vrf_comps(),
                    _ => self.link_comps(),
                };
                msg.resp.unwrap().send(comps).unwrap();
            }
            ConfigOp::Clear => {
                //
            }
        }
    }

    async fn process_show_msg(&self, msg: DisplayRequest) {
        let (path, args) = path_from_command(&msg.paths);
        if let Some(f) = self.show_cb.get(&path) {
            let output = f(self, args, msg.json);
            msg.resp.send(output).await.unwrap();
        }
    }

    async fn mac_add(
        &mut self,
        vni: u32,
        mac: MacAddr,
        tunnel_endpoint: Option<IpAddr>,
        flags: u8,
        seq: u32,
        esi: Option<[u8; 10]>,
    ) {
        // MAC Mobility: ignore stale duplicates (lower sequence number)
        if let Some(existing) = self.mac_table.get(&(vni, mac))
            && seq < existing.seq
        {
            return; // Ignore stale duplicate
        }

        let entry = MacEntry {
            tunnel_endpoint,
            flags,
            seq,
            installed: false,
        };

        self.mac_table.insert((vni, mac), entry);

        // Forward to kernel FIB
        self.fib_handle
            .mac_add(vni, &mac, tunnel_endpoint, flags, seq, esi)
            .await;
    }

    async fn mac_del(&mut self, vni: u32, mac: MacAddr) {
        self.mac_table.remove(&(vni, mac));
        // Forward deletion to kernel FIB
        self.fib_handle.mac_del(vni, &mac).await;
    }

    async fn mdb_add(
        &mut self,
        vni: u32,
        group: IpAddr,
        source: Option<IpAddr>,
        ifindex: u32,
        seq: u32,
    ) {
        // Track the VTEP we're about to install so the shutdown path
        // can DELNEIGH it before exit.
        self.vtep_table.insert((vni, group));
        self.fib_handle
            .mdb_add(vni, group, source, ifindex, seq)
            .await;
    }

    async fn mdb_del(&mut self, vni: u32, group: IpAddr, source: Option<IpAddr>, ifindex: u32) {
        self.vtep_table.remove(&(vni, group));
        self.fib_handle.mdb_del(vni, group, source, ifindex).await;
    }

    pub async fn event_loop(&mut self) {
        // Before get into FIB interaction, we enable sysctl.
        let _ = sysctl_enable();

        if let Err(_err) = fib_dump(self).await {
            // warn!("FIB dump error {}", err);
        }

        // The fib_dump above populated `self.links`; we can now decide
        // whether sr0 already exists or needs to be created.
        self.ensure_sr0_dummy().await;

        loop {
            tokio::select! {
                Some(msg) = self.rx.recv() => {
                    // Legacy / internal channel. Every `rib_tx`
                    // sender drives the default routing table — the
                    // `Subscribe`, `VrfAdd`, `LinkVrfBind` and self-
                    // re-schedule paths have no VRF semantics —
                    // so `RT_TABLE_MAIN` is unconditional here.
                    self.process_msg(msg, RT_TABLE_MAIN).await;
                }
                Some(env) = self.inbound_rx.recv() => {
                    // Look up the sender's VRF binding from
                    // `client_registry` and translate to the kernel
                    // `rtm_table` id. `vrf_id == 0` is default-VRF
                    // (= `RT_TABLE_MAIN`); a non-zero value flows
                    // straight through as the kernel table id —
                    // that's what `VrfIdAllocator` hands out and what
                    // `vrf_tables` is keyed by.
                    let vrf_id = self.client_registry.vrf_id_for(env.from);
                    let table_id = if vrf_id == 0 { RT_TABLE_MAIN } else { vrf_id };
                    tracing::trace!(
                        from = %env.from,
                        vrf_id,
                        table_id,
                        "rib: inbound envelope",
                    );
                    self.process_msg(env.msg, table_id).await;
                }
                Some(msg) = self.fib.rx.recv() => {
                    self.process_fib_msg(msg).await;
                }
                Some(msg) = self.cm.rx.recv() => {
                    self.process_cm_msg(msg).await;
                }
                Some(msg) = self.show.rx.recv() => {
                    self.process_show_msg(msg).await;
                }
            }
        }
    }
}

/// Build a `RibEntry` for an allocated SID. The shape mirrors what
/// the FIB install path would dump back from the kernel: rtype Isis
/// (IS-IS is the only allocator today; broaden when OSPF / BGP
/// follow), distance 115 / metric 0, and a single `Uni` nexthop
/// carrying `seg6local_action` so the show callback can render
/// `seg6local <action> [nh6 <addr>]`.
fn sid_rib_entry(sid: &Sid) -> RibEntry {
    let mut entry = RibEntry::new(RibType::Isis);
    entry.distance = 115;
    entry.metric = 0;
    entry.set_valid(true);
    entry.set_selected(true);
    entry.set_fib(true);
    entry.ifindex = sid.ifindex;

    let addr = match sid.nh6 {
        Some(a) => IpAddr::V6(a),
        None => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    entry.nexthop = Nexthop::Uni(NexthopUni {
        addr,
        ifindex_origin: (sid.ifindex != 0).then_some(sid.ifindex),
        seg6local_action: Some(sid.behavior),
        valid: true,
        ..Default::default()
    });
    entry
}

/// True when this RibEntry was inserted by `sid_rib_insert` — single
/// `Uni` nexthop with `seg6local_action` set. Lets `sid_rib_remove`
/// scrub only its own entries when an install gets replaced or the
/// SID is withdrawn.
fn is_seg6local_entry(entry: &RibEntry) -> bool {
    matches!(&entry.nexthop, Nexthop::Uni(uni) if uni.seg6local_action.is_some())
}

/// Build a `NeighborKey` from a `FibNeighbor` so the entry can be inserted
/// into / removed from `Rib::neighbors`. Returns `None` when the entry
/// lacks the discriminator the family requires (no `dst` for ARP/NDP, no
/// `lladdr` for FDB) — those are dropped silently rather than stored
/// under an ambiguous key.
/// Build an `FdbEntry` for the api-side fan-out from a `FibNeighbor`.
///
/// Returns `None` when the neighbor isn't a publishable FDB row:
///   - non-`AF_BRIDGE` family (covered by `RibRx::FdbAdd` only)
///   - no MAC address attached
///   - the slave port has no resolvable bridge master
///   - the master bridge has no VXLAN slave with a known VNI — until
///     the bridge is wired to VXLAN, an EVPN advertise consumer
///     wouldn't have anywhere to put the route, so dropping early
///     keeps the message stream tidy.
///
/// **Bridge resolution is two-tier**: try `NDA_MASTER` from the FDB
/// message first (set by userland tools — e.g. `bridge fdb add ...
/// master <br>` — and by some sticky/permanent path), then fall back
/// to the slave port's `IFLA_MASTER` (which we cached when the link
/// came up). Without the fallback, data-plane-learned MACs that the
/// kernel broadcasts WITHOUT `NDA_MASTER` are silently dropped here
/// — matched user-visible bug: `bridge fdb show` lists the MAC but
/// `show bgp evpn` doesn't, because the operator-added MACs
/// (which carry NDA_MASTER) succeed and the data-plane-learned ones
/// don't.
fn fdb_entry_from_neighbor(rib: &Rib, nbr: &FibNeighbor) -> Option<FdbEntry> {
    use netlink_packet_route::AddressFamily;
    if nbr.family != AddressFamily::Bridge {
        return None;
    }
    let mac = nbr.lladdr?;
    // Skip multicast / broadcast MACs. The kernel's bridge FDB
    // contains rows for every multicast group the local device
    // joined (`33:33:..` for IPv6, `01:00:5e:..` for IPv4, plus
    // reserved-link addresses like `01:80:c2:..`); these are
    // local-reception filters, not remote hosts, and have no
    // meaning as EVPN Type-2 MAC advertisements.
    if mac.is_multicast() {
        return None;
    }
    // Skip MACs the bridge learned on a VXLAN port — those are
    // remote hosts whose frames came in over a tunnel; advertising
    // them as locally-originated would loop the route back to
    // peers. NTF_EXT_LEARNED catches operator-installed entries
    // but NOT data-plane learns (kernel sets neither flag on a
    // dynamically learned bridge FDB row), so the slave-port type
    // is the authoritative signal: any link with a `vni` is a
    // VXLAN device.
    if let Some(slave) = rib.links.get(&nbr.ifindex)
        && slave.vni.is_some()
    {
        return None;
    }
    let bridge_ifindex = nbr
        .master
        .or_else(|| rib.links.get(&nbr.ifindex).and_then(|link| link.master))?;
    let vni = rib.vni_for_bridge(bridge_ifindex)?;
    let vxlan_local = rib.vxlan_local_for_bridge(bridge_ifindex);
    Some(FdbEntry {
        vni,
        mac,
        ifindex: nbr.ifindex,
        bridge_ifindex,
        flags: nbr.flags.bits(),
        vxlan_local,
    })
}

fn neighbor_key(nbr: &FibNeighbor) -> Option<NeighborKey> {
    use netlink_packet_route::AddressFamily;
    match nbr.family {
        AddressFamily::Inet | AddressFamily::Inet6 => {
            let addr = nbr.dst?;
            Some(NeighborKey::Inet {
                ifindex: nbr.ifindex,
                addr,
            })
        }
        AddressFamily::Bridge => {
            let mac = nbr.lladdr?;
            Some(NeighborKey::Bridge {
                ifindex: nbr.ifindex,
                mac,
                vlan: nbr.vlan,
            })
        }
        _ => None,
    }
}

pub fn serve(mut rib: Rib) {
    let rib_tx = rib.tx.clone();
    tokio::spawn(async move {
        rib.event_loop().await;
    });
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_err() {
            return;
        }
        let (tx, rx) = oneshot::channel::<()>();
        let _ = rib_tx.send(Message::Shutdown { tx });
        // If the event loop is already gone (e.g. panicked earlier),
        // `rx` resolves to `Err(RecvError)`. Exit anyway — there's
        // nothing left to wait for.
        let _ = rx.await;
        std::process::exit(0);
    });
}
