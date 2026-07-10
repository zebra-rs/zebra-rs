use super::api::{FdbEntry, RibRx};
use super::client::{ClientRegistry, ProtoId, RibInbound};
use super::entry::RibEntry;
use super::link::{LinkConfig, link_config_exec};
use super::{
    Block, BlockBuilder, BlockConfig, BridgeBuilder, BridgeConfig, DEFAULT_BLOCK_NAME, GroupTrait,
    Link, Locator, LocatorBuilder, LocatorConfig, MacAddr, MplsConfig, Nexthop, NexthopMap,
    NexthopUni, RibSrRx, RibType, Sid, SidBehavior, StaticConfig, V4, V6, Vrf, VrfBuilder,
    VrfIdAllocator, VrfRibTables, VrfStaticConfig, Vxlan, VxlanBuilder, VxlanConfig,
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
    /// Static-route install/withdraw into a named VRF's table. The VRF
    /// name (not the kernel `table_id`) is carried so the message
    /// survives a VRF whose table isn't up yet — `process_msg` resolves
    /// it via `self.vrfs`, and the `VrfAdd` reconcile re-emits it.
    Ipv4AddVrf {
        vrf: String,
        prefix: Ipv4Net,
        rib: RibEntry,
    },
    Ipv4DelVrf {
        vrf: String,
        prefix: Ipv4Net,
        rib: RibEntry,
    },
    Ipv6AddVrf {
        vrf: String,
        prefix: Ipv6Net,
        rib: RibEntry,
    },
    Ipv6DelVrf {
        vrf: String,
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
    /// Fast-reroute switchover trigger (see
    /// `docs/design/nexthop-protect-kernel-failover.md`): the sender
    /// detected a primary-adjacency failure the kernel can't see (BFD
    /// down while the link stays up) at gateway `addr`. RIB rewires
    /// every protection indirection group whose primary rides that
    /// adjacency onto its repair — one atomic kernel group-replace
    /// per group, independent of prefix count. The sender's normal
    /// SPF reconvergence then supersedes the bridge.
    // Constructed by RibClient::protect_switch, whose own
    // expect(dead_code) (callers arrive later) roots it — and
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
    /// Reset the local node's Mirror SID egress-protection registrations:
    /// every `(protected_locator, mirror_sid)` a peer advertised. IS-IS
    /// recomputes the full set on each SPF and sends it here. The RIB
    /// matches a protected locator against its *own* End.DT46 service SIDs
    /// — so a SID inside a protected locator is redirected (via
    /// `End.B6.Encaps` to the Mirror SID) when its CE-facing VRF can no
    /// longer deliver (PE-CE link down), and restored when it recovers.
    /// This is egress *link* protection: the protected egress (PEA) acts
    /// as its own PLR.
    EgressProtectSet {
        protections: Vec<(ipnet::Ipv6Net, std::net::Ipv6Addr)>,
    },
    /// SR-MPLS Mirror Context egress link protection: the local node is
    /// protected — each `(context_label, protector_loopback)` says that on
    /// a PE-CE link failure its per-VRF VPN-label ILM should be swapped to
    /// push `context_label` toward `protector_loopback` (resolved to the
    /// transport LSP by the RIB). IS-IS recomputes the full set on each
    /// SPF. The RIB overrides the BGP-owned `DecapVrf` ILM for the failed
    /// VRF and restores it on recovery.
    EgressMplsProtectSet {
        protections: Vec<(u32, std::net::Ipv4Addr)>,
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
        mup_import_rts: std::collections::BTreeSet<bgp_packet::RouteDistinguisher>,
        mup_export_rts: std::collections::BTreeSet<bgp_packet::RouteDistinguisher>,
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
    /// Bind / unbind an interface to a bridge master device
    /// (`ip link set <ifname> master <bridge>` / `... nomaster`).
    /// `bridge == Some(name)` enslaves to that bridge; `None` detaches
    /// (sets IFLA_MASTER = 0). Like `LinkVrfBind`, the handler tolerates
    /// the interface or the bridge not yet existing in our tables and
    /// stages the intent in `pending_bridge_bind`, firing it when the
    /// missing kernel device appears via `link_add`.
    LinkBridgeBind {
        ifname: String,
        bridge: Option<String>,
    },
    MacAdd {
        vni: u32,
        mac: MacAddr,
        tunnel_endpoint: Option<IpAddr>,
        flags: u8,
        seq: u32,
        esi: Option<[u8; 10]>,
        /// EVPN-over-SRv6 (RFC 9252): the remote PE's L2 service SID this
        /// MAC sits behind — End.DT2U for a unicast MAC, End.DT2M for the
        /// all-ones BUM sentinel. `Some` selects the cradle L2 tee over the
        /// kernel VXLAN FDB.
        srv6_sid: Option<std::net::Ipv6Addr>,
    },
    MacDel {
        vni: u32,
        mac: MacAddr,
    },
    /// A remote PE joined/left a VNI's BUM flood set (EVPN Type-3 with an
    /// SRv6 `End.DT2M` SID, RFC 9252 §6.4) — teed to cradle as a BUM
    /// replication slot (per-copy MAC-in-SRv6 encap in the flood list).
    CradleReplAdd {
        vni: u32,
        sid: std::net::Ipv6Addr,
    },
    CradleReplDel {
        vni: u32,
        sid: std::net::Ipv6Addr,
    },
    /// MUP `dataplane gtp` uplink decap (`H.M.GTP4.D`): a GTP-U decap PDR teed
    /// to cradle — a G-PDU on (`dst`, `teid`) is stripped and its inner packet
    /// forwarded in VRF `table_id`. Cradle-only (the kernel has no GTP action).
    CradleGtpPdrAdd {
        dst: std::net::Ipv4Addr,
        teid: u32,
        table_id: u32,
    },
    CradleGtpPdrDel {
        dst: std::net::Ipv4Addr,
        teid: u32,
    },
    /// EVPN VPWS (RFC 8214): bind attachment circuit `ifname` to a remote
    /// PE's `End.DX2`/`End.DX2V` service SID — teed to cradle as an
    /// XCONNECT entry (every AC frame MAC-in-SRv6 encapsulates toward it,
    /// no FDB) plus, when `local_sid` is present, the local decap LocalSid
    /// that emits raw on the same AC. A non-zero `vid` scopes the binding
    /// to that 802.1Q VID (End.DX2V over VLAN table `table`). No kernel
    /// counterpart — cradle is the L2 data plane.
    XconnectAdd {
        ifname: String,
        remote_sid: std::net::Ipv6Addr,
        local_sid: Option<std::net::Ipv6Addr>,
        vid: u16,
        table: u32,
    },
    XconnectDel {
        ifname: String,
        local_sid: Option<std::net::Ipv6Addr>,
        vid: u16,
        table: u32,
    },
    /// MUP `dataplane gtp` downlink encap (`GTP4.E`): a GTP-U encap route teed
    /// to cradle — traffic to `prefix` in VRF `table_id` is wrapped in outer
    /// IPv4 + UDP(2152) + GTP-U(`teid`) toward `gtp_dst` (sourced from
    /// `gtp_src`) over the resolved v4 underlay `gw`/`oif`. Cradle-only.
    CradleGtpEncapAdd {
        prefix: ipnet::Ipv4Net,
        table_id: u32,
        gtp_src: std::net::Ipv4Addr,
        gtp_dst: std::net::Ipv4Addr,
        teid: u32,
        gw: Option<std::net::Ipv4Addr>,
        oif: u32,
    },
    CradleGtpEncapDel {
        prefix: ipnet::Ipv4Net,
        table_id: u32,
    },
    /// A MAC the cradle eBPF datapath learned on a local L2 port (via the
    /// `WatchFdb` stream). Re-emitted to EVPN subscribers as a synthesized
    /// `RibRx::FdbAdd` — the cradle analogue of a kernel bridge FDB learn —
    /// so BGP originates a Type-2 for it.
    CradleFdbLearn {
        vni: u32,
        mac: MacAddr,
    },
    /// A cradle-learned MAC aged out (idle past `fdb_age_secs`) — withdraw
    /// its Type-2 by re-emitting the same synthesized entry as a
    /// `RibRx::FdbDel`.
    CradleFdbAge {
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
    /// Install (`SmetInstall`) or remove (`SmetRemove`) a selective EVPN
    /// multicast forwarding entry from a received Type-6 SMET route:
    /// deliver `(source, group)` in `vni` toward the remote VTEP `dst`
    /// (the SMET originator). The RIB resolves `vni` to its local
    /// `(bridge, vxlan-port)` and programs the kernel bridge MDB.
    SmetInstall {
        vni: u32,
        group: IpAddr,
        source: Option<IpAddr>,
        dst: IpAddr,
    },
    SmetRemove {
        vni: u32,
        group: IpAddr,
        source: Option<IpAddr>,
        dst: IpAddr,
    },
    /// Install an RFC 9524 SR P2MP replication segment for a VNI's BUM
    /// delivery (EVPN, draft-ietf-bess-mvpn-evpn-sr-p2mp). `root` is the tree
    /// Root (local VTEP), `leaves` the egress PEs to replicate to, `srv6`
    /// selects SRv6 (vs SR-MPLS) encapsulation. Consumed by the SR
    /// replication dataplane (eBPF TC/clsact, offload crate
    /// `tc-evpn-replicate`); a stub today.
    ReplSegAdd {
        vni: u32,
        tree_id: u32,
        root: IpAddr,
        srv6: bool,
        leaves: Vec<IpAddr>,
    },
    /// Withdraw the SR P2MP replication segment for a VNI.
    ReplSegDel {
        vni: u32,
    },
    /// Program this node's local `End.DT2M` SID for a VNI into the
    /// `tc-evpn-replicate` leaf datapath, so a replicated copy addressed to it
    /// is decapsulated and flooded into the bridge. Driven by the SR P2MP leaf
    /// role (the SID this PE advertises in its Type-3 IMET's SRv6 L2 Prefix-SID).
    ReplLeafAdd {
        vni: u32,
        sid: Ipv6Addr,
    },
    /// Withdraw this node's `End.DT2M` leaf SID for a VNI.
    ReplLeafDel {
        vni: u32,
    },
    /// Topology for the SR P2MP BUM-replication dataplane, from BGP's
    /// `sr-p2mp-dataplane` config: the overlay bridge port the root encap
    /// attaches to, the SR underlay NIC, the bridge port a leaf floods into,
    /// and the outer next-hop MAC. Stored by the replication supervisor and
    /// used when it (re)spawns the eBPF children. Any field may be `None`.
    ReplDataplaneCfg {
        overlay: Option<String>,
        underlay: Option<String>,
        bridge: Option<String>,
        next_hop_mac: Option<String>,
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
    /// Watch the default route (0.0.0.0/0 or ::/0) for
    /// `default-information originate` tracking: RIB replays the
    /// current default (if any, self-routes excluded) and keeps
    /// delivering RouteAdd/RouteDel for the default prefix from any
    /// source protocol.
    RedistDefaultAdd {
        proto: String,
        afi: super::RedistAfi,
    },
    /// Subscribe to `redistribute table <id>`: routes the kernel
    /// holds in the non-main, non-VRF routing table `table_id`
    /// (installed externally, e.g. `ip route ... table N`). RIB
    /// replays the table's current contents as
    /// `RibRx::TableRouteAdd` batches ending in `BulkPhase::Eor`,
    /// then streams deltas. v4-only today (FRR parity: only ospfd
    /// has a `table` redistribute source).
    RedistTableAdd {
        proto: String,
        table_id: u32,
    },
    /// Tear down a table subscription. RIB replays the table's
    /// current contents as `TableRouteDel` (ending in Eor) so the
    /// consumer can withdraw without duplicating per-table state.
    RedistTableDel {
        proto: String,
        table_id: u32,
    },
    /// Tear down a default-route watch. No Del replay: the default
    /// prefix may also be covered by an overlapping per-rtype
    /// subscription, so cache cleanup is the consumer's job.
    RedistDefaultDel {
        proto: String,
        afi: super::RedistAfi,
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
            Message::Ipv4Add { .. }
                | Message::Ipv6Add { .. }
                | Message::Ipv4AddVrf { .. }
                | Message::Ipv6AddVrf { .. }
                | Message::IlmAdd { .. }
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
    /// IS-IS SR-MPLS Mirror Context label (RFC 8679 egress protection):
    /// the protector (PEB) pops the context label a failed egress's PLR
    /// pushed and delivers the inner packet into the dual-homed VRF.
    /// Netlink-identical to [`IlmType::DecapVrf`] (pop + `Oif(vrf_ifindex)`
    /// so the inner packet lands in `vrf_tables[table_id]`) — a distinct
    /// variant only so show output and ILM selection can tell a context
    /// label from a BGP VPN label. The egress-link-protection model (the
    /// protected egress redirects and strips its own VPN label, like the
    /// SRv6 End.B6.Encaps path) means the protector only ever pops this
    /// one label; the two-label node-protection variant (a context label
    /// over the egress's VPN label) needs the Linux global-ILM
    /// approximation and is deferred.
    ContextLabel {
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
    /// The pop delivers locally: the nexthop egress is a loopback
    /// (a node's own prefix-SID / UHP entry), so whatever sits under
    /// the label is also ours. Stamped by `Rib::ilm_add` from the
    /// link table — producers install the loopback nexthop the
    /// kernel LFIB needs and don't set this themselves. The cradle
    /// tee keys on it: a local pop must NOT be teed with the
    /// loopback nexthop (the eBPF pop-and-forward would try to
    /// resolve an L2 neighbor on `lo` and punt); it becomes a
    /// nexthop-less pop so the data plane's chained-pop path
    /// continues into the label(s)/IP underneath.
    pub local_pop: bool,
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
            local_pop: false,
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
    /// The cradle `WatchFdb` subscriber task (datapath MAC learning →
    /// EVPN Type-2 origination); aborted and respawned when the
    /// `system cradle grpc-endpoint` endpoint changes.
    pub cradle_fdb_watch: Option<tokio::task::JoinHandle<()>>,
    /// `system cradle enabled` — master switch for the cradle eBPF tee.
    pub cradle_enabled: bool,
    /// `system cradle grpc-endpoint <endpoint>` override. When the tee is enabled
    /// but this is unset, the endpoint defaults to `unix:cradle/grpc`.
    pub cradle_grpc: Option<String>,
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
    /// Default-prefix watch registry (`default-information originate`
    /// tracking): per-proto set of AFIs for which the subscriber wants
    /// RouteAdd/RouteDel deliveries for the default route only, any
    /// rtype (self-routes excluded). Updated by RedistDefaultAdd /
    /// RedistDefaultDel; consulted by `redist::notify_v*_delta`.
    pub redist_default_watch: HashMap<String, std::collections::BTreeSet<super::RedistAfi>>,
    /// `redistribute table <id>` watches: kernel table id -> the
    /// protocols subscribed to it (`Message::RedistTableAdd`).
    pub redist_table_watch: BTreeMap<u32, std::collections::BTreeSet<String>>,
    /// v4 routes the kernel holds in non-main, non-VRF tables,
    /// stored in the redistribute delivery shape. Populated from the
    /// netlink dump/monitor (previously these routes were dropped);
    /// consulted for `RedistTableAdd` replay and kept fresh so
    /// deltas notify `redist_table_watch` subscribers.
    pub table_routes_v4: BTreeMap<u32, BTreeMap<Ipv4Net, super::RouteEntryV4>>,
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
    /// Operator intent for per-interface bridge binding, keyed by
    /// ifname. `Some(bridge)` = enslave; `None` = detach. Mirrors
    /// `pending_vrf_bind`: retried when either the interface or the
    /// bridge master appears later, kept as durable desired-state across
    /// link flaps, and cleared on detach.
    pub pending_bridge_bind: BTreeMap<String, Option<String>>,
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
    pub static_vrf_v4: VrfStaticConfig<V4>,
    pub static_vrf_v6: VrfStaticConfig<V6>,
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
    /// Mirror SID egress-protection registrations from IS-IS: every
    /// `protected_locator -> mirror_sid` a peer advertised (see
    /// [`Message::EgressProtectSet`]). A local End.DT46 service SID whose
    /// address falls inside one of these locators is redirected to the
    /// Mirror SID (via `End.B6.Encaps`) while its CE-facing VRF can't
    /// deliver.
    pub egress_protect: BTreeMap<ipnet::Ipv6Net, std::net::Ipv6Addr>,
    /// Local SIDs currently installed in their redirect (`seg6 H.Encaps ->
    /// mirror_sid`) form rather than the normal End.DT46 decap, mapped to
    /// the protector's Mirror SID they redirect to. Tracks the live FIB
    /// form so a reconcile only emits a netlink change on an actual
    /// transition, and lets `show segment-routing srv6 sid` surface the
    /// redirect target independently of the (volatile) `egress_protect`
    /// registration.
    pub redirected_sids: BTreeMap<std::net::Ipv6Addr, std::net::Ipv6Addr>,
    /// SR-MPLS Mirror Context egress link protection registrations from
    /// IS-IS (see [`Message::EgressMplsProtectSet`]): each
    /// `(context_label, protector_loopback)` the local node is protected
    /// by. On a PE-CE link failure the protected VRF's BGP `DecapVrf`
    /// VPN-label ILM is overridden to a swap pushing the context label
    /// toward the protector.
    pub egress_mpls_protect: Vec<(u32, std::net::Ipv4Addr)>,
    /// VPN labels whose `DecapVrf` ILM is currently overridden with a
    /// Mirror Context redirect swap. Maps the label to the original
    /// `DecapVrf` IlmEntry so the decap can be restored on link recovery.
    pub redirected_vpn_labels: BTreeMap<u32, IlmEntry>,
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

    /// Operator-configured `system hostname`. Preferred by
    /// `show hostname` over the OS hostname; `None` falls back to it.
    /// The vty prompt tracks the same config through the Execute
    /// reply path in the config manager, so the two stay consistent.
    pub hostname_config: Option<String>,

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

    /// Supervisor for the EVPN SR P2MP replication dataplane (RFC 9524).
    /// Driven by `Message::ReplSegAdd` / `ReplSegDel`; spawns/feeds the
    /// `tc-evpn-replicate` offload child.
    pub evpn_repl: super::evpn_replicate::ReplicationHelper,
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
            cradle_fdb_watch: None,
            cradle_enabled: false,
            cradle_grpc: None,
            cm: ConfigChannel::new(),
            show: ShowChannel::new(),
            show_cb: HashMap::new(),
            fib,
            fib_handle,
            client_registry: ClientRegistry::new(),
            inbound_tx,
            inbound_rx,
            redist_filters: HashMap::new(),
            redist_default_watch: HashMap::new(),
            redist_table_watch: BTreeMap::new(),
            table_routes_v4: BTreeMap::new(),
            links: BTreeMap::new(),
            bridges: BTreeMap::new(),
            vxlan: BTreeMap::new(),
            vrfs: BTreeMap::new(),
            vrf_tables: BTreeMap::new(),
            vrf_id_alloc: VrfIdAllocator::new(),
            pending_vrf_bind: BTreeMap::new(),
            pending_bridge_bind: BTreeMap::new(),
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
            static_vrf_v4: VrfStaticConfig::<V4>::new(),
            static_vrf_v6: VrfStaticConfig::<V6>::new(),
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
            egress_protect: BTreeMap::new(),
            redirected_sids: BTreeMap::new(),
            egress_mpls_protect: Vec::new(),
            redirected_vpn_labels: BTreeMap::new(),
            sr_clients: BTreeMap::new(),
            block_watch: BTreeMap::new(),
            locator_watch: BTreeMap::new(),
            nht: super::nht::NhtRegistry::default(),
            label_manager: super::label_manager::LabelManager::new(),
            nmap: NexthopMap::default(),
            router_id: Ipv4Addr::UNSPECIFIED,
            router_id_config: None,
            hostname_config: None,
            rib_sync_timer: None,
            rib_sync_interval: DEFAULT_RIB_SYNC_INTERVAL_SEC,
            sr0_owned: false,
            addr_recovery: BTreeMap::new(),
            evpn_repl: super::evpn_replicate::ReplicationHelper::new(),
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
            | SidBehavior::EndM
            | SidBehavior::EndT
            | SidBehavior::UT
            | SidBehavior::EndDX4
            | SidBehavior::EndDX6
            // End.B6.Encaps is a seg6local action too — bound to `lo` the
            // kernel strips it exactly like the decap group.
            | SidBehavior::EndB6Encap => self.resolve_sr0_ifindex(),
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

        let addr = sid.addr;
        self.sids.insert(sid.addr, sid);
        // A protected End.DT46 SID installed while its PE-CE link is
        // already down must go straight to its redirect form.
        self.apply_egress_redirect(addr).await;
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

    /// True when the VRF behind `table_id` still has an operationally-up,
    /// addressed, non-loopback member link — i.e. it can still reach its
    /// CE. `table_id == 0` (the main table, not a VRF SID) always
    /// delivers. Gates Mirror SID egress link protection: when the PE-CE
    /// link goes down the VRF can no longer deliver, so the protected
    /// End.DT46 service SID is redirected to the protector's Mirror SID.
    fn vrf_can_deliver(&self, table_id: u32) -> bool {
        if table_id == 0 {
            return true;
        }
        self.links.values().any(|link| {
            self.ifindex_vrf_id(link.index) == table_id
                && !link.is_loopback()
                && link.is_up()
                && (!link.addr4.is_empty() || !link.addr6.is_empty())
        })
    }

    /// The Mirror SID a local End.DT46 service SID is protected by: the
    /// first registered protected-locator that covers the SID's address.
    /// `None` when the SID isn't covered by any registration. The match
    /// against the node's *own* SID address is why IS-IS can send every
    /// received Mirror SID untouched — only a locator that actually covers
    /// a local service SID redirects anything.
    fn protecting_mirror_sid(&self, sid: &Sid) -> Option<std::net::Ipv6Addr> {
        if sid.behavior != SidBehavior::EndDT46 {
            return None;
        }
        self.egress_protect
            .iter()
            .find(|(loc, _)| loc.contains(&sid.addr))
            .map(|(_, m)| *m)
    }

    /// Resolve the underlay nexthop (link-local + ifindex) toward an SRv6
    /// destination — the protector's Mirror SID — by longest-prefix match
    /// in the main IPv6 table (the IS-IS route to the protector's
    /// locator). Returns the `via`/`dev` the redirect's seg6 H.Encaps
    /// route needs. `None` if the protector isn't reachable.
    fn resolve_underlay_nexthop_v6(&self, dest: std::net::Ipv6Addr) -> Option<(Ipv6Addr, u32)> {
        let host = Ipv6Net::new(dest, 128).ok()?;
        let (_, entries) = self.table_v6.get_lpm(&host)?;
        for entry in entries.iter() {
            let unis: &[NexthopUni] = match &entry.nexthop {
                Nexthop::Uni(uni) => std::slice::from_ref(uni),
                Nexthop::Multi(multi) => &multi.nexthops,
                _ => continue,
            };
            for uni in unis {
                if let (IpAddr::V6(a), Some(ifindex)) = (uni.addr, uni.ifindex()) {
                    return Some((a, ifindex));
                }
            }
        }
        None
    }

    /// Reconcile one local SID's installed FIB form against the egress-
    /// protection decision, with a **link-state latch**:
    ///
    /// - Enter the redirect form (`End.B6.Encaps -> mirror_sid`) when the
    ///   SID is protected *and* its CE-facing VRF can't deliver (PE-CE link
    ///   down).
    /// - Leave it (restore the normal End.DT46 decap) **only** when the VRF
    ///   can deliver again — never just because the protection registration
    ///   vanished. The registration is recomputed from a live LSDB scan on
    ///   every SPF and can transiently read empty (e.g. during the SPF the
    ///   PE-CE link-down itself triggers); dropping an active redirect on
    ///   that transient would black-hole the very traffic it protects. A
    ///   fast-reroute redirect must hold until the data-plane condition
    ///   that caused it clears.
    ///
    /// A single `route_sid_install` (NLM_F_REPLACE) swaps the /128 in
    /// place; `redirected_sids` tracks the live form so the FIB is only
    /// touched on an actual transition.
    pub async fn apply_egress_redirect(&mut self, addr: std::net::Ipv6Addr) {
        let Some(sid) = self.sids.get(&addr).cloned() else {
            return;
        };
        if sid.behavior != SidBehavior::EndDT46 {
            return;
        }
        let is_redirected = self.redirected_sids.contains_key(&addr);
        let can_deliver = self.vrf_can_deliver(sid.table_id);
        if is_redirected {
            // Latched: hold the redirect until the PE-CE link recovers.
            if can_deliver {
                self.fib_handle
                    .route_sid_install(&sid, 0, sid.ifindex)
                    .await;
                self.redirected_sids.remove(&addr);
                tracing::info!(
                    "[egress-protect] restore {} -> End.DT46 (VRF table {} delivers again)",
                    addr,
                    sid.table_id
                );
            }
        } else if !can_deliver {
            // Enter redirect: the VRF can't deliver and a peer protects us.
            // Re-encapsulate (seg6 H.Encaps, route-level — not a seg6local
            // endpoint action, since the inbound SRH is already exhausted)
            // toward the protector's Mirror SID via the underlay nexthop.
            let Some(mirror_sid) = self.protecting_mirror_sid(&sid) else {
                return;
            };
            let Some((nh6, ifindex)) = self.resolve_underlay_nexthop_v6(mirror_sid) else {
                tracing::warn!(
                    "[egress-protect] {} protected by {} but protector unreachable — not redirecting",
                    addr,
                    mirror_sid
                );
                return;
            };
            self.fib_handle
                .route_sid_redirect_install(&sid.prefix(), mirror_sid, nh6, ifindex)
                .await;
            self.redirected_sids.insert(addr, mirror_sid);
            tracing::info!(
                "[egress-protect] redirect {} -> seg6 H.Encaps [{}] via {} dev {} (VRF table {} can't deliver)",
                addr,
                mirror_sid,
                nh6,
                ifindex,
                sid.table_id
            );
        }
    }

    /// Re-evaluate every local End.DT46 SID inside a protected locator (or
    /// currently redirected). Called when IS-IS resets the egress-
    /// protection registrations and on PE-CE link up/down.
    pub async fn reconcile_egress_redirects(&mut self) {
        if self.egress_protect.is_empty() && self.redirected_sids.is_empty() {
            return;
        }
        let addrs: Vec<std::net::Ipv6Addr> = self
            .sids
            .values()
            .filter(|s| s.behavior == SidBehavior::EndDT46)
            .filter(|s| {
                self.redirected_sids.contains_key(&s.addr)
                    || self.egress_protect.keys().any(|loc| loc.contains(&s.addr))
            })
            .map(|s| s.addr)
            .collect();
        for addr in addrs {
            self.apply_egress_redirect(addr).await;
        }
    }

    // ── SR-MPLS Mirror Context egress redirect ────────────────────────

    /// Resolve the SR-MPLS transport to `protector_loopback`: the outgoing
    /// label stack (the prefix-SID transport label — empty under PHP for a
    /// directly-adjacent protector) plus the underlay nexthop + ifindex,
    /// by longest-prefix match in the main IPv4 table.
    fn resolve_protector_transport_v4(
        &self,
        protector_loopback: Ipv4Addr,
    ) -> Option<(Vec<u32>, Ipv4Addr, u32)> {
        let host = Ipv4Net::new(protector_loopback, 32).ok()?;
        let (_, entries) = self.table.get_lpm(&host)?;
        for entry in entries.iter() {
            let unis: &[NexthopUni] = match &entry.nexthop {
                Nexthop::Uni(uni) => std::slice::from_ref(uni),
                Nexthop::Multi(multi) => &multi.nexthops,
                _ => continue,
            };
            for uni in unis {
                if let (IpAddr::V4(a), Some(ifindex)) = (uni.addr, uni.ifindex()) {
                    return Some((uni.mpls_label.clone(), a, ifindex));
                }
            }
        }
        None
    }

    /// Re-evaluate every BGP VPN-label `DecapVrf` ILM for the Mirror
    /// Context redirect. Called when IS-IS resets the registration and on
    /// PE-CE link up/down.
    pub async fn reconcile_egress_mpls_redirects(&mut self) {
        if self.egress_mpls_protect.is_empty() && self.redirected_vpn_labels.is_empty() {
            return;
        }
        // Snapshot the (label, table_id) of every VPN decap ILM.
        let targets: Vec<(u32, u32)> = self
            .ilm
            .iter()
            .filter_map(|(&label, entries)| {
                entries.iter().find_map(|e| match e.ilm_type {
                    IlmType::DecapVrf { table_id, .. } => Some((label, table_id)),
                    _ => None,
                })
            })
            .chain(
                // Already-redirected labels may have lost their candidate;
                // keep them so a restore can run.
                self.redirected_vpn_labels.keys().map(|&l| (l, 0)),
            )
            .collect();
        for (label, table_id) in targets {
            self.apply_egress_mpls_redirect(label, table_id).await;
        }
    }

    /// Reconcile one VPN-label ILM with the redirect decision, **latched**
    /// on link state (like the SRv6 path): override the BGP `DecapVrf` to a
    /// swap pushing `[transport…, context_label]` toward the protector when
    /// the VRF can't deliver, and restore the decap only when it can again.
    async fn apply_egress_mpls_redirect(&mut self, label: u32, table_id: u32) {
        let is_redirected = self.redirected_vpn_labels.contains_key(&label);
        // Resolve the live DecapVrf entry (the restore target) + its VRF.
        let decap = self.ilm.get(&label).and_then(|es| {
            es.iter()
                .find(|e| matches!(e.ilm_type, IlmType::DecapVrf { .. }))
                .cloned()
        });
        let vrf_table = match (&decap, is_redirected) {
            (Some(e), _) => match e.ilm_type {
                IlmType::DecapVrf { table_id, .. } => table_id,
                _ => table_id,
            },
            (None, true) => table_id, // restore-only; table_id from caller is 0/unused
            (None, false) => return,
        };
        let can_deliver = self.vrf_can_deliver(vrf_table);
        if is_redirected {
            if can_deliver && let Some(orig) = self.redirected_vpn_labels.remove(&label) {
                // Restore the BGP VPN decap, replacing the IS-IS swap
                // (the kernel holds one route per label).
                self.fib_handle.ilm_replace(label, &orig).await;
                tracing::info!(
                    "[egress-protect-mpls] restore VPN label {} -> DecapVrf (VRF table {} delivers)",
                    label,
                    vrf_table
                );
            }
        } else if !can_deliver {
            let Some(orig) = decap else { return };
            // Pick a protection (single-protector dual-homing).
            let Some(&(context_label, protector_lo)) = self.egress_mpls_protect.first() else {
                return;
            };
            let Some((mut stack, nexthop, ifindex)) =
                self.resolve_protector_transport_v4(protector_lo)
            else {
                tracing::warn!(
                    "[egress-protect-mpls] protector {} unreachable — not redirecting VPN label {}",
                    protector_lo,
                    label
                );
                return;
            };
            stack.push(context_label);
            let swap = IlmEntry {
                ilm_type: IlmType::Swap,
                nexthop: Nexthop::Uni(NexthopUni {
                    addr: IpAddr::V4(nexthop),
                    ifindex_origin: Some(ifindex),
                    mpls_label: stack.clone(),
                    valid: true,
                    ..Default::default()
                }),
                ..IlmEntry::new(RibType::Isis)
            };
            // Replace the BGP DecapVrf route at this label with the swap.
            self.fib_handle.ilm_replace(label, &swap).await;
            self.redirected_vpn_labels.insert(label, orig);
            tracing::info!(
                "[egress-protect-mpls] redirect VPN label {} -> swap {:?} via {} dev {} (VRF table {} can't deliver)",
                label,
                stack,
                nexthop,
                ifindex,
                vrf_table
            );
        }
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
            // Benign during startup churn: a per-VRF task that respawns
            // (table_id / SID fill in) drops its earlier subscribe before
            // this handler delivers the dump. Gated with the task
            // lifecycle traces rather than logged unconditionally.
            if crate::rib::tracing::task() {
                tracing::warn!(
                    "rib: subscriber '{proto}' dropped before subscribe could deliver dump; skipping"
                );
            }
            return;
        }
        // Link dump.
        for link in self.links.values() {
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
                    mup_import_rts: vrf.mup_import_rts.clone(),
                    mup_export_rts: vrf.mup_export_rts.clone(),
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
        // Redistribute registrations ride the inbound channel while this
        // Subscribe rides the message channel, and `event_loop`'s
        // `select!` gives the two no relative order. A RedistAdd /
        // RedistTableAdd / RedistDefaultAdd processed before this row
        // landed found no subscriber and its walk-and-replay was dropped
        // — permanently, because routes already in the store never
        // re-fire as deltas. Replay whatever the recorded filters and
        // watches imply now that the row exists.
        self.replay_pending_redist(&proto);
    }

    /// Replay every redistribute walk this protocol's recorded
    /// filters/watches imply. Called from `subscribe` to close the
    /// cross-channel registration race (bit `@ospfv2_redist_table`
    /// in a loaded concurrent BDD run: the pre-start table-100 route
    /// was never originated). In the unraced order the filter maps
    /// are still empty at Subscribe time, so this is a no-op.
    fn replay_pending_redist(&self, proto: &str) {
        let Some(tx) = self
            .client_registry
            .subscriber_for_proto(proto)
            .map(|s| s.rib_rx_tx.clone())
        else {
            return;
        };
        if let Some(rows) = self.redist_filters.get(proto) {
            for ((afi, rtype), subtypes) in rows.clone() {
                self.redist_walk(
                    proto,
                    afi,
                    rtype,
                    &subtypes,
                    super::redist::WalkOp::Add,
                    &tx,
                );
            }
        }
        if let Some(afis) = self.redist_default_watch.get(proto) {
            for afi in afis.clone() {
                self.redist_default_replay_add(proto, afi);
            }
        }
        for (table_id, protos) in self.redist_table_watch.iter() {
            if protos.contains(proto) {
                self.replay_table_routes_to(*table_id, &tx);
            }
        }
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
        self.redist_default_watch.remove(proto);
        self.redist_table_watch.retain(|_, protos| {
            protos.remove(proto);
            !protos.is_empty()
        });
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
        // Record the filter row even when the subscriber row hasn't
        // landed yet (Subscribe rides the other channel): steady-state
        // deltas resolve the subscriber at delta time, and `subscribe`
        // replays the initial walk via `replay_pending_redist`. Bailing
        // before the insert used to drop BOTH permanently.
        self.redist_filters
            .entry(proto.to_string())
            .or_default()
            .insert((afi, rtype), subtypes);
        self.client_registry
            .subscriber_for_proto(proto)
            .map(|s| s.rib_rx_tx.clone())
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
        let prior = self
            .redist_filters
            .get(&proto)
            .and_then(|f| f.get(&(afi, rtype)))
            .cloned()
            .unwrap_or_default();
        if prior == subtypes {
            return; // no-op
        }
        let Some(tx) = self
            .client_registry
            .subscriber_for_proto(&proto)
            .map(|s| s.rib_rx_tx.clone())
        else {
            // Subscriber row not landed yet (cross-channel race with
            // Subscribe) — still record the new set; `subscribe`
            // replays the whole filter as an Add walk.
            self.redist_filters
                .entry(proto)
                .or_default()
                .insert((afi, rtype), subtypes);
            return;
        };

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

    /// Walk the table the subscriber is bound to. A subscriber's
    /// `vrf_id` (recorded at `Subscribe` time) selects the table:
    /// `0` walks the default `self.table` / `self.table_v6`; any other
    /// value is the kernel table id keying `vrf_tables`. A VRF whose
    /// table has since been torn down walks nothing.
    /// `RedistDefaultAdd`: record the watch and replay the currently
    /// selected default route (if any and not the subscriber's own)
    /// as a RouteAdd, mirroring the walk-and-replay of `redist_add`.
    fn redist_default_add(&mut self, proto: String, afi: super::RedistAfi) {
        self.redist_default_watch
            .entry(proto.clone())
            .or_default()
            .insert(afi);
        self.redist_default_replay_add(&proto, afi);
    }

    /// `RedistDefaultDel`: drop the watch. Deliberately no Del
    /// replay — the default prefix may also match an overlapping
    /// per-rtype subscription whose cache entry must survive, so the
    /// consumer purges its own cache when it stops watching.
    fn redist_default_del(&mut self, proto: String, afi: super::RedistAfi) {
        let emptied = if let Some(afis) = self.redist_default_watch.get_mut(&proto) {
            afis.remove(&afi);
            afis.is_empty()
        } else {
            false
        };
        if emptied {
            self.redist_default_watch.remove(&proto);
        }
    }

    /// Emit the current default route (per the subscriber's VRF) as a
    /// single RouteAdd, self-routes excluded. No-op when no default
    /// exists or the subscriber is unknown.
    fn redist_default_replay_add(&self, proto: &str, afi: super::RedistAfi) {
        let Some(sub) = self.client_registry.subscriber_for_proto(proto) else {
            return;
        };
        let vrf_id = sub.vrf_id;
        let tx = sub.rib_rx_tx.clone();
        match afi {
            super::RedistAfi::Ipv4 => {
                let prefix: Ipv4Net = Ipv4Net::new(std::net::Ipv4Addr::UNSPECIFIED, 0).unwrap();
                let table = if vrf_id == 0 {
                    &self.table
                } else {
                    match self.vrf_tables.get(&vrf_id) {
                        Some(t) => &t.table,
                        None => return,
                    }
                };
                let entry = table
                    .get(&prefix)
                    .and_then(|entries| entries.iter().find(|e| e.is_selected()));
                if let Some((rt, e)) = super::redist::entry_for_default_v4(&prefix, entry, proto) {
                    super::redist::emit_default_v4(&tx, None, Some((rt, e)));
                }
            }
            super::RedistAfi::Ipv6 => {
                let prefix: Ipv6Net = Ipv6Net::new(std::net::Ipv6Addr::UNSPECIFIED, 0).unwrap();
                let table = if vrf_id == 0 {
                    &self.table_v6
                } else {
                    match self.vrf_tables.get(&vrf_id) {
                        Some(t) => &t.table_v6,
                        None => return,
                    }
                };
                let entry = table
                    .get(&prefix)
                    .and_then(|entries| entries.iter().find(|e| e.is_selected()));
                if let Some((rt, e)) = super::redist::entry_for_default_v6(&prefix, entry, proto) {
                    super::redist::emit_default_v6(&tx, None, Some((rt, e)));
                }
            }
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
        let vrf_id = self
            .client_registry
            .subscriber_for_proto(proto)
            .map(|s| s.vrf_id)
            .unwrap_or(0);
        match afi {
            super::RedistAfi::Ipv4 => {
                let table = if vrf_id == 0 {
                    &self.table
                } else {
                    match self.vrf_tables.get(&vrf_id) {
                        Some(t) => &t.table,
                        None => return,
                    }
                };
                super::redist::walk_v4(table, proto, rtype, subtypes, op, tx);
            }
            super::RedistAfi::Ipv6 => {
                let table = if vrf_id == 0 {
                    &self.table_v6
                } else {
                    match self.vrf_tables.get(&vrf_id) {
                        Some(t) => &t.table_v6,
                        None => return,
                    }
                };
                super::redist::walk_v6(table, proto, rtype, subtypes, op, tx);
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

    /// Pre-resolve a VRF-static route's gateway that sits directly on a
    /// VRF interface by stamping its egress `ifindex_origin`. The kernel
    /// flushes (and silently re-adds) an interface's addresses when it is
    /// enslaved to a VRF, which races our connected-route shadow out of
    /// the per-VRF table — so a table-walk resolution of an on-link
    /// gateway intermittently fails. `ifindex_origin` makes the resolver
    /// skip the table walk (`GroupUni::resolve_v6`) and install the route
    /// on-link, exactly as the kernel resolves it. Only stamps a Uni/Multi
    /// gateway the source didn't already pin to an interface.
    fn stamp_vrf_onlink(&self, entry: &mut RibEntry, table_id: u32) {
        let onlink_ifindex = |nh: IpAddr| -> Option<u32> {
            self.links.values().find_map(|link| {
                if self.ifindex_vrf_id(link.index) != table_id {
                    return None;
                }
                let hit = match nh {
                    IpAddr::V4(a) => link
                        .addr4
                        .iter()
                        .any(|x| matches!(x.addr, IpNet::V4(net) if net.contains(&a))),
                    IpAddr::V6(a) => link
                        .addr6
                        .iter()
                        .any(|x| matches!(x.addr, IpNet::V6(net) if net.contains(&a))),
                };
                hit.then_some(link.index)
            })
        };
        let stamp = |uni: &mut NexthopUni| {
            if uni.ifindex_origin.is_none()
                && let Some(ifindex) = onlink_ifindex(uni.addr)
            {
                uni.ifindex_origin = Some(ifindex);
            }
        };
        match &mut entry.nexthop {
            Nexthop::Uni(uni) => stamp(uni),
            Nexthop::Multi(multi) => multi.nexthops.iter_mut().for_each(stamp),
            _ => {}
        }
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
            // Static-route install/withdraw into a named VRF's table.
            // Resolve the VRF name → kernel `table_id`; a VRF that isn't
            // up yet drops the install (re-emitted by the `VrfAdd`
            // reconcile once its table exists).
            Message::Ipv4AddVrf {
                vrf,
                prefix,
                mut rib,
            } => match self.vrfs.get(&vrf).map(|v| v.table_id) {
                Some(table_id) => {
                    self.stamp_vrf_onlink(&mut rib, table_id);
                    self.ipv4_route_add_vrf(table_id, &prefix, rib).await
                }
                None => tracing::debug!(%vrf, %prefix, "static vrf route: vrf table not up yet"),
            },
            Message::Ipv4DelVrf { vrf, prefix, rib } => {
                if let Some(table_id) = self.vrfs.get(&vrf).map(|v| v.table_id) {
                    self.ipv4_route_del_vrf(table_id, &prefix, rib).await;
                }
            }
            Message::Ipv6AddVrf {
                vrf,
                prefix,
                mut rib,
            } => match self.vrfs.get(&vrf).map(|v| v.table_id) {
                Some(table_id) => {
                    self.stamp_vrf_onlink(&mut rib, table_id);
                    self.ipv6_route_add_vrf(table_id, &prefix, rib).await
                }
                None => tracing::debug!(%vrf, %prefix, "static vrf route: vrf table not up yet"),
            },
            Message::Ipv6DelVrf { vrf, prefix, rib } => {
                if let Some(table_id) = self.vrfs.get(&vrf).map(|v| v.table_id) {
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
                // Deleting the VXLAN device removes its kernel master
                // implicitly. Drop any staged bridge-bind for it so a
                // later same-named VXLAN isn't silently re-enslaved by a
                // stale intent (belt-and-braces: a `delete vxlan X bridge
                // BR` line, when present, already clears it via the
                // `/vxlan/bridge` dispatch above).
                self.pending_bridge_bind.remove(&name);
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
                        // /vrf/<name>/{ipv4,ipv6,mup}/route-target.
                        ipv4_import_rts: std::collections::BTreeSet::new(),
                        ipv4_export_rts: std::collections::BTreeSet::new(),
                        ipv6_import_rts: std::collections::BTreeSet::new(),
                        ipv6_export_rts: std::collections::BTreeSet::new(),
                        mup_import_rts: std::collections::BTreeSet::new(),
                        mup_export_rts: std::collections::BTreeSet::new(),
                    },
                );
                // Park an empty per-VRF routing table set keyed by
                // the same `table_id` the kernel uses. The
                // per-`ProtoId` dispatcher writes routes here when a
                // VRF-attached protocol installs.
                self.vrf_tables.insert(table_id, VrfRibTables::new());
                // A locator may bind this VRF by name (End.T/uT). If it
                // was configured before the VRF existed its snapshot holds
                // table 0 — resolve it now and re-notify the IGPs.
                let bound: Vec<String> = self
                    .locators
                    .iter()
                    .filter(|(_, l)| l.vrf.as_deref() == Some(name.as_str()))
                    .filter(|(_, l)| l.table_id != table_id)
                    .map(|(n, _)| n.clone())
                    .collect();
                for lname in bound {
                    if let Some(l) = self.locators.get_mut(&lname) {
                        l.table_id = table_id;
                    }
                    self.notify_locator_watchers(&lname);
                }
                // Adopting a pre-existing kernel VRF can surface members
                // that were already enslaved before we knew this VRF, so
                // their connected routes were filed in the default table
                // (`route_table_for` saw `master_vrf_id` == 0 because the
                // VRF wasn't in `self.vrfs` yet). Now that the VRF and its
                // table exist, re-home each member's connected routes out
                // of the default table and into this one — mirroring the
                // per-interface reconcile in `link_add`. The common
                // fresh-create path has no members yet, so this is a
                // no-op there.
                let members: Vec<u32> = self
                    .links
                    .values()
                    .filter(|l| l.master == Some(ifindex) && l.is_up())
                    .map(|l| l.index)
                    .collect();
                for member in members {
                    let addrs: Vec<IpNet> = self
                        .links
                        .get(&member)
                        .map(|l| {
                            l.addr4
                                .iter()
                                .chain(l.addr6.iter())
                                .map(|a| a.addr)
                                .collect()
                        })
                        .unwrap_or_default();
                    for addr in addrs {
                        // Old table is the default (0): the member was
                        // enslaved in the kernel but this VRF was unknown.
                        self.connected_route_del(member, addr, 0).await;
                        self.connected_route_add(member, addr).await;
                    }
                }
                // Re-emit any static routes configured for this VRF now
                // that its kernel table exists — the initial commit's
                // install was dropped if it raced ahead of the VRF.
                self.static_vrf_v4.reinstall(&name, &self.tx);
                self.static_vrf_v6.reinstall(&name, &self.tx);
                if crate::rib::tracing::fib_vrf() {
                    tracing::info!(
                        "vrf_add: {} table_id={} ifindex={}",
                        name,
                        table_id,
                        ifindex
                    );
                }
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
                // Unbind any End.T/uT locator that referenced this VRF —
                // its node SID degrades to plain End/uN until the VRF
                // returns.
                let bound: Vec<String> = self
                    .locators
                    .iter()
                    .filter(|(_, l)| l.vrf.as_deref() == Some(name.as_str()))
                    .filter(|(_, l)| l.table_id != 0)
                    .map(|(n, _)| n.clone())
                    .collect();
                for lname in bound {
                    if let Some(l) = self.locators.get_mut(&lname) {
                        l.table_id = 0;
                    }
                    self.notify_locator_watchers(&lname);
                }
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
                mup_import_rts,
                mup_export_rts,
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
                    vrf.mup_import_rts = mup_import_rts;
                    vrf.mup_export_rts = mup_export_rts;
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
                        if crate::rib::tracing::fib_vrf() {
                            tracing::info!(
                                "link_vrf_bind: interface {} not present yet — pending",
                                ifname
                            );
                        }
                        return;
                    }
                };

                let master = match &vrf {
                    Some(vrf_name) => match self.vrfs.get(vrf_name) {
                        Some(v) => v.ifindex,
                        None => {
                            if crate::rib::tracing::fib_vrf() {
                                tracing::info!(
                                    "link_vrf_bind: vrf {} not present yet — pending",
                                    vrf_name
                                );
                            }
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
                if crate::rib::tracing::fib_vrf() {
                    tracing::info!(
                        "link_vrf_bind: ifname={} ifindex={} master={} vrf={:?}",
                        ifname,
                        ifindex,
                        master,
                        vrf
                    );
                }
            }
            Message::LinkBridgeBind { ifname, bridge } => {
                // Always record operator intent so a later kernel
                // NewLink (the slave interface appears, or the bridge
                // master is created) can fire the bind without the
                // operator re-issuing the command.
                if bridge.is_none() {
                    self.pending_bridge_bind.remove(&ifname);
                } else {
                    self.pending_bridge_bind
                        .insert(ifname.clone(), bridge.clone());
                }

                let (ifindex, current_master) = match self.links.values().find(|l| l.name == ifname)
                {
                    Some(link) => (link.index, link.master.unwrap_or(0)),
                    None => {
                        if crate::rib::tracing::fib_link() {
                            tracing::info!(
                                "link_bridge_bind: interface {} not present yet — pending",
                                ifname
                            );
                        }
                        return;
                    }
                };

                // Resolve the bridge to its kernel ifindex. `master == 0`
                // detaches (`ip link set ... nomaster`). Gate on TWO
                // things, mirroring how the VRF bind resolves through
                // `self.vrfs`:
                //   1. config presence (`self.bridges`) — `BridgeDel`
                //      removes the entry synchronously, BEFORE the netlink
                //      delete that releases this port. The released port's
                //      RTM_NEWLINK (master cleared) re-fires this bind via
                //      `link_add`; gating here means it sees the bridge
                //      already gone and stays pending, instead of racing a
                //      `link_set_master` against the vanishing device —
                //      which the kernel rejects with EINVAL. The `bridge`
                //      leaf is a leafref to `/bridge/name`, so a bound
                //      bridge is always a configured one.
                //   2. kernel presence (`self.links`) for the ifindex — it
                //      lands there once `BridgeAdd`'s netlink create echoes
                //      back as RTM_NEWLINK.
                let master_ifindex = match &bridge {
                    Some(bridge) => {
                        if !self.bridges.contains_key(bridge) {
                            if crate::rib::tracing::fib_link() {
                                tracing::info!(
                                    "link_bridge_bind: bridge {} not configured — pending",
                                    bridge
                                );
                            }
                            return;
                        }
                        match self.links.values().find(|l| l.name == *bridge) {
                            Some(l) => l.index,
                            None => {
                                if crate::rib::tracing::fib_link() {
                                    tracing::info!(
                                        "link_bridge_bind: bridge {} not present yet — pending",
                                        bridge
                                    );
                                }
                                return;
                            }
                        }
                    }
                    None => 0,
                };

                // Only touch the kernel when the master actually changes.
                // `pending_bridge_bind` is durable desired-state, so
                // `link_add` replays this on every RTM_NEWLINK for the
                // interface; without this guard the enslave burst would
                // re-issue redundant `link_set_master` calls (see the
                // `LinkVrfBind` guard for the same rationale).
                if current_master == master_ifindex {
                    return;
                }

                self.fib_handle
                    .link_set_master(ifindex, master_ifindex)
                    .await;
                if crate::rib::tracing::fib_link() {
                    tracing::info!(
                        "link_bridge_bind: ifname={} ifindex={} master={} bridge={:?}",
                        ifname,
                        ifindex,
                        master_ifindex,
                        bridge
                    );
                }
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
                let mut locator = config.to_locator();
                // Resolve the End.T/uT VRF binding against the registry.
                // The VRF may not exist yet (netlink creation is async) —
                // vrf_add re-resolves and re-notifies when it appears.
                if let Some(vrf) = &locator.vrf {
                    locator.table_id = self.vrfs.get(vrf).map(|v| v.table_id).unwrap_or(0);
                }
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
            Message::EgressProtectSet { protections } => {
                // Authoritative replace. The PIC-sticky / withdrawal logic
                // now lives in IS-IS `register_egress_protections`, which
                // has the LSDB to tell a genuine withdrawal (protector
                // present, no longer advertising) from a convergence
                // transient (protector's LSP absent — carried forward).
                self.egress_protect = protections.into_iter().collect();
                self.reconcile_egress_redirects().await;
            }
            Message::EgressMplsProtectSet { protections } => {
                // Sticky, like EgressProtectSet: a transiently-empty SPF
                // LSDB scan must not disarm protection mid-failure.
                if !protections.is_empty() {
                    self.egress_mpls_protect = protections;
                }
                self.reconcile_egress_mpls_redirects().await;
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
                for bridge in self.bridges.values() {
                    self.fib_handle.bridge_del(bridge).await;
                }
                for vxlan in self.vxlan.values() {
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
                srv6_sid,
            } => {
                self.mac_add(vni, mac, tunnel_endpoint, flags, seq, esi, srv6_sid)
                    .await;
            }
            Message::MacDel { vni, mac } => {
                self.mac_del(vni, mac).await;
            }
            Message::CradleFdbLearn { vni, mac } => {
                self.cradle_fdb_learn(vni, mac);
            }
            Message::CradleFdbAge { vni, mac } => {
                self.cradle_fdb_age(vni, mac);
            }
            Message::CradleReplAdd { vni, sid } => {
                self.fib_handle.cradle_repl_add(vni, sid).await;
            }
            Message::CradleReplDel { vni, sid } => {
                self.fib_handle.cradle_repl_del(vni, sid).await;
            }
            Message::CradleGtpPdrAdd {
                dst,
                teid,
                table_id,
            } => {
                self.fib_handle
                    .cradle_gtp_pdr_add(dst, teid, table_id)
                    .await;
            }
            Message::CradleGtpPdrDel { dst, teid } => {
                self.fib_handle.cradle_gtp_pdr_del(dst, teid).await;
            }
            Message::XconnectAdd {
                ifname,
                remote_sid,
                local_sid,
                vid,
                table,
            } => {
                self.fib_handle
                    .cradle_xconnect_add(&ifname, remote_sid, local_sid, vid, table)
                    .await;
            }
            Message::XconnectDel {
                ifname,
                local_sid,
                vid,
                table,
            } => {
                self.fib_handle
                    .cradle_xconnect_del(&ifname, local_sid, vid, table)
                    .await;
            }
            Message::CradleGtpEncapAdd {
                prefix,
                table_id,
                gtp_src,
                gtp_dst,
                teid,
                gw,
                oif,
            } => {
                self.fib_handle
                    .cradle_gtp_encap_add(prefix, table_id, gtp_src, gtp_dst, teid, gw, oif)
                    .await;
            }
            Message::CradleGtpEncapDel { prefix, table_id } => {
                self.fib_handle.cradle_gtp_encap_del(prefix, table_id).await;
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
            Message::SmetInstall {
                vni,
                group,
                source,
                dst,
            } => {
                self.smet_install(vni, group, source, dst, true).await;
            }
            Message::SmetRemove {
                vni,
                group,
                source,
                dst,
            } => {
                self.smet_install(vni, group, source, dst, false).await;
            }
            Message::ReplSegAdd {
                vni,
                tree_id,
                root,
                srv6,
                leaves,
            } => {
                // Hand the replication segment to the SR P2MP dataplane
                // supervisor (the `tc-evpn-replicate` offload child). With no
                // offload interface configured this is a logged no-op — the
                // control plane still signals, nothing forwards.
                tracing::info!(
                    "EVPN ReplSeg add: VNI {vni} tree {tree_id} root {root} {} -> {} leaf PE(s)",
                    if srv6 { "SRv6" } else { "SR-MPLS" },
                    leaves.len()
                );
                self.evpn_repl.add(vni, tree_id, root, srv6, &leaves);
            }
            Message::ReplSegDel { vni } => {
                tracing::info!("EVPN ReplSeg del: VNI {vni}");
                self.evpn_repl.del(vni);
            }
            Message::ReplLeafAdd { vni, sid } => {
                tracing::info!("EVPN ReplLeaf add: VNI {vni} End.DT2M SID {sid}");
                self.evpn_repl.leaf_add(vni, sid);
            }
            Message::ReplLeafDel { vni } => {
                tracing::info!("EVPN ReplLeaf del: VNI {vni}");
                self.evpn_repl.leaf_del(vni);
            }
            Message::ReplDataplaneCfg {
                overlay,
                underlay,
                bridge,
                next_hop_mac,
            } => {
                self.evpn_repl
                    .set_topology(overlay, underlay, bridge, next_hop_mac);
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
            Message::RedistDefaultAdd { proto, afi } => {
                self.redist_default_add(proto, afi);
            }
            Message::RedistDefaultDel { proto, afi } => {
                self.redist_default_del(proto, afi);
            }
            Message::RedistTableAdd { proto, table_id } => {
                self.redist_table_add(proto, table_id);
            }
            Message::RedistTableDel { proto, table_id } => {
                self.redist_table_del(proto, table_id);
            }
        }
    }

    /// Store or refresh one non-main, non-VRF kernel-table route and
    /// stream the delta to `redistribute table <id>` subscribers.
    fn table_route_upsert(&mut self, table_id: u32, prefix: Ipv4Net, entry: &RibEntry) {
        if !super::redist::redistributable_v4(&prefix) {
            return;
        }
        let e = super::RouteEntryV4 {
            prefix,
            nexthop: super::redist::first_v4_nexthop(&entry.nexthop)
                .unwrap_or(std::net::Ipv4Addr::UNSPECIFIED),
            subtype: entry.rsubtype.clone(),
            metric: entry.metric,
            tag: 0,
            ifindex: entry.ifindex,
        };
        let slot = self
            .table_routes_v4
            .entry(table_id)
            .or_default()
            .insert(prefix, e.clone());
        if slot.as_ref() == Some(&e) {
            return;
        }
        if let Some(protos) = self.redist_table_watch.get(&table_id) {
            for proto in protos {
                if let Some(sub) = self.client_registry.subscriber_for_proto(proto) {
                    let _ = sub.rib_rx_tx.send(RibRx::TableRouteAdd {
                        table_id,
                        routes: super::RouteBatch::V4(vec![e.clone()]),
                        bulk: super::BulkPhase::Eor,
                    });
                }
            }
        }
    }

    /// Remove one kernel-table route and stream the withdrawal.
    fn table_route_remove(&mut self, table_id: u32, prefix: Ipv4Net) {
        let Some(routes) = self.table_routes_v4.get_mut(&table_id) else {
            return;
        };
        let Some(e) = routes.remove(&prefix) else {
            return;
        };
        if routes.is_empty() {
            self.table_routes_v4.remove(&table_id);
        }
        if let Some(protos) = self.redist_table_watch.get(&table_id) {
            for proto in protos {
                if let Some(sub) = self.client_registry.subscriber_for_proto(proto) {
                    let _ = sub.rib_rx_tx.send(RibRx::TableRouteDel {
                        table_id,
                        routes: super::RouteBatch::V4(vec![e.clone()]),
                        bulk: super::BulkPhase::Eor,
                    });
                }
            }
        }
    }

    /// `Message::RedistTableAdd`: register the watch and replay the
    /// table's current contents, ending in Eor. When the subscriber
    /// row hasn't landed yet (cross-channel race with Subscribe),
    /// the watch still registers and `subscribe` runs the replay.
    fn redist_table_add(&mut self, proto: String, table_id: u32) {
        self.redist_table_watch
            .entry(table_id)
            .or_default()
            .insert(proto.clone());
        if let Some(sub) = self.client_registry.subscriber_for_proto(&proto) {
            self.replay_table_routes_to(table_id, &sub.rib_rx_tx);
        }
    }

    /// Chunked replay of one kernel table's stored routes to a
    /// subscriber Tx, closed with an Eor marker. Shared by
    /// `redist_table_add` and the Subscribe-side race replay.
    fn replay_table_routes_to(&self, table_id: u32, tx: &UnboundedSender<RibRx>) {
        let entries: Vec<super::RouteEntryV4> = self
            .table_routes_v4
            .get(&table_id)
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default();
        for chunk in entries.chunks(super::types::REDIST_BATCH_MAX.max(1)) {
            let _ = tx.send(RibRx::TableRouteAdd {
                table_id,
                routes: super::RouteBatch::V4(chunk.to_vec()),
                bulk: super::BulkPhase::More,
            });
        }
        let _ = tx.send(RibRx::TableRouteAdd {
            table_id,
            routes: super::RouteBatch::V4(Vec::new()),
            bulk: super::BulkPhase::Eor,
        });
    }

    /// `Message::RedistTableDel`: drop the watch and replay the
    /// table's contents as withdrawals so the consumer can flush
    /// without duplicating per-table state.
    fn redist_table_del(&mut self, proto: String, table_id: u32) {
        if let Some(protos) = self.redist_table_watch.get_mut(&table_id) {
            protos.remove(&proto);
            if protos.is_empty() {
                self.redist_table_watch.remove(&table_id);
            }
        }
        let entries: Vec<super::RouteEntryV4> = self
            .table_routes_v4
            .get(&table_id)
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default();
        if let Some(sub) = self.client_registry.subscriber_for_proto(&proto) {
            for chunk in entries.chunks(super::types::REDIST_BATCH_MAX.max(1)) {
                let _ = sub.rib_rx_tx.send(RibRx::TableRouteDel {
                    table_id,
                    routes: super::RouteBatch::V4(chunk.to_vec()),
                    bulk: super::BulkPhase::More,
                });
            }
            let _ = sub.rib_rx_tx.send(RibRx::TableRouteDel {
                table_id,
                routes: super::RouteBatch::V4(Vec::new()),
                bulk: super::BulkPhase::Eor,
            });
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
                    } else {
                        // A non-main, non-VRF kernel table: keep it in
                        // the `redistribute table <id>` store and
                        // notify subscribers.
                        self.table_route_upsert(route.table_id, prefix, &route.entry);
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
                    } else {
                        self.table_route_remove(route.table_id, prefix);
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
                // Tee resolved ARP/ND to the cradle eBPF data plane — its
                // MPLS egress rewrite resolves next-hop MACs from this state.
                if let (Some(dst), Some(mac)) = (nbr.dst, &nbr.lladdr) {
                    self.fib_handle
                        .cradle_neighbor_add(dst, nbr.ifindex, mac.octets())
                        .await;
                }
                let fdb_entry = fdb_entry_from_neighbor(self, &nbr);
                if let Some(key) = neighbor_key(&nbr) {
                    self.neighbors.insert(key, nbr);
                }
                if let Some(entry) = fdb_entry {
                    // When the cradle eBPF tee owns the data plane, cradle's
                    // WatchFdb is the single source of truth for bridge-domain
                    // MAC learning. The kernel bridge FDB (e.g. br100/vxlan100)
                    // does not forward here, so its stale/racy NEWNEIGH events
                    // would conflict with the cradle learn/age stream and thrash
                    // EVPN Type-2 origination on MAC mobility (RFC 7432 §7.7).
                    // Suppress the kernel feed while the tee is active.
                    if self.cradle_fdb_watch.is_none() {
                        self.api_fdb_add(&entry);
                    }
                }
            }
            FibMessage::DelNeighbor(nbr) => {
                let fdb_entry = fdb_entry_from_neighbor(self, &nbr);
                if let Some(key) = neighbor_key(&nbr) {
                    self.neighbors.remove(&key);
                }
                if let Some(entry) = fdb_entry {
                    // See NewNeighbor: cradle's WatchFdb owns bridge MAC
                    // learning/aging when the tee is active; ignore the kernel
                    // bridge FDB feed so a stale DELNEIGH can't withdraw a
                    // cradle-originated Type-2 out from under a live station.
                    if self.cradle_fdb_watch.is_none() {
                        self.api_fdb_del(&entry);
                    }
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

    /// `set system hostname <name>` — store the configured hostname so
    /// `show hostname` prefers it over the OS hostname. Deleting falls
    /// back to the OS hostname. Purely daemon-internal (FRR-style): no
    /// `sethostname(2)`, no OS side effects; the vty prompt tracks the
    /// same leaf via the config manager's Execute-reply path.
    pub(crate) fn hostname_config_exec(
        &mut self,
        mut args: crate::config::Args,
        op: ConfigOp,
    ) -> Option<()> {
        if op.is_set() {
            self.hostname_config = Some(args.string()?);
        } else {
            self.hostname_config = None;
        }
        Some(())
    }

    /// `set system cradle enabled <bool>` — the sole switch for the cradle
    /// eBPF data-plane tee. Deleting it (or setting false) disables the tee
    /// regardless of any `system cradle grpc-endpoint` endpoint.
    #[cfg(target_os = "linux")]
    pub(crate) fn cradle_enabled_config_exec(
        &mut self,
        mut args: crate::config::Args,
        op: ConfigOp,
    ) -> Option<()> {
        self.cradle_enabled = op.is_set() && args.boolean()?;
        self.cradle_apply();
        Some(())
    }

    /// `set system cradle grpc-endpoint <endpoint>` overrides (or re-points) the cradle
    /// tee endpoint; deleting it falls back to the `unix:cradle/grpc` default.
    /// This only takes effect while the tee is enabled (`system cradle
    /// enabled`); on its own it does not enable the tee. The endpoint is
    /// `unix:NAME` / `unix:/path`, `http://host:port` or a bare `host:port`
    /// (treated as TCP).
    #[cfg(target_os = "linux")]
    pub(crate) fn cradle_grpc_config_exec(
        &mut self,
        mut args: crate::config::Args,
        op: ConfigOp,
    ) -> Option<()> {
        self.cradle_grpc = if op.is_set() {
            Some(args.string()?)
        } else {
            None
        };
        self.cradle_apply();
        Some(())
    }

    /// Effective cradle tee endpoint: `None` when disabled, else the
    /// `system cradle grpc-endpoint` override or the `unix:cradle/grpc` default.
    #[cfg(target_os = "linux")]
    fn cradle_endpoint(&self) -> Option<String> {
        cradle_effective_endpoint(self.cradle_enabled, self.cradle_grpc.as_deref())
    }

    /// Re-derive the cradle tee from the current `enabled` / `grpc-endpoint`
    /// state and (re)start or stop the forward tee plus the reverse
    /// `WatchFdb` subscriber accordingly. Called on any change to either
    /// config knob.
    #[cfg(target_os = "linux")]
    fn cradle_apply(&mut self) {
        // Tear down any previous watcher before re-pointing/disabling.
        if let Some(watch) = self.cradle_fdb_watch.take() {
            watch.abort();
        }
        let Some(endpoint) = self.cradle_endpoint() else {
            self.fib_handle.set_cradle(None);
            return;
        };
        self.fib_handle.set_cradle(Some(&endpoint));
        // The reverse channel: subscribe to cradle's datapath MAC learning
        // and feed each entry back into this RIB as a `CradleFdbLearn`, which
        // re-emits it to EVPN subscribers. Reconnects with backoff for the
        // daemon lifetime.
        let cradle = crate::fib::cradle::CradleFib::new(&endpoint);
        let tx = self.tx.clone();
        self.cradle_fdb_watch = Some(tokio::spawn(async move {
            loop {
                match cradle.watch_fdb().await {
                    Ok(mut stream) => {
                        while let Ok(Some(ev)) = stream.message().await {
                            let Ok(mac) = ev.mac.parse::<MacAddr>() else {
                                continue;
                            };
                            let msg = if ev.event == 1 {
                                Message::CradleFdbAge { vni: ev.bd, mac }
                            } else {
                                Message::CradleFdbLearn { vni: ev.bd, mac }
                            };
                            let _ = tx.send(msg);
                        }
                    }
                    Err(e) => {
                        tracing::debug!("rib: cradle WatchFdb connect failed: {e}");
                    }
                }
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        }));
    }

    /// A cradle-datapath MAC learn: synthesize the same `FdbEntry` a kernel
    /// bridge learn produces (VNI = the cradle bridge domain) and dispatch
    /// it to EVPN subscribers, so BGP originates a Type-2 exactly as it
    /// would for a kernel-learned MAC. The VXLAN local address (the BGP
    /// nexthop source) resolves from the VNI's vxlan device when one is
    /// configured; router-id is the callers' fallback.
    fn cradle_fdb_learn(&mut self, vni: u32, mac: MacAddr) {
        if mac.is_multicast() {
            return;
        }
        let vxlan_local = self
            .links
            .values()
            .find(|link| link.vni == Some(vni))
            .and_then(|link| link.vxlan_local);
        let entry = FdbEntry {
            vni,
            mac,
            ifindex: 0,
            bridge_ifindex: 0,
            flags: 0,
            vxlan_local,
        };
        self.api_fdb_add(&entry);
    }

    /// A cradle-datapath MAC aged out: dispatch the same synthesized entry
    /// as an `FdbDel` so BGP withdraws the Type-2 it originated for the
    /// learn (`evpn_withdraw_macip` matches on `(vni, mac)`).
    fn cradle_fdb_age(&mut self, vni: u32, mac: MacAddr) {
        if mac.is_multicast() {
            return;
        }
        let vxlan_local = self
            .links
            .values()
            .find(|link| link.vni == Some(vni))
            .and_then(|link| link.vxlan_local);
        let entry = FdbEntry {
            vni,
            mac,
            ifindex: 0,
            bridge_ifindex: 0,
            flags: 0,
            vxlan_local,
        };
        self.api_fdb_del(&entry);
    }

    async fn process_cm_msg(&mut self, msg: ConfigRequest) {
        match msg.op {
            ConfigOp::CommitStart => {
                //
            }
            ConfigOp::Set | ConfigOp::Delete => {
                let (path, mut args) = path_from_command(&msg.paths);
                if path.as_str() == "/system/router-id" {
                    let _ = self.router_id_config_exec(args, msg.op);
                } else if path.as_str() == "/system/hostname" {
                    let _ = self.hostname_config_exec(args, msg.op);
                } else if path.as_str() == "/system/cradle/enabled" {
                    #[cfg(target_os = "linux")]
                    let _ = self.cradle_enabled_config_exec(args, msg.op);
                } else if path.as_str() == "/system/cradle/grpc-endpoint" {
                    #[cfg(target_os = "linux")]
                    let _ = self.cradle_grpc_config_exec(args, msg.op);
                } else if path.as_str().starts_with("/router/static/vrf/ipv4/route") {
                    let _ = self.static_vrf_v4.exec(path, args, msg.op);
                } else if path.as_str().starts_with("/router/static/vrf/ipv6/route") {
                    let _ = self.static_vrf_v6.exec(path, args, msg.op);
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
                } else if path.as_str() == "/vxlan/bridge" {
                    // `set vxlan X bridge BR` enslaves the VXLAN device X
                    // to bridge BR, reusing the SAME deferred bridge-bind
                    // as `interface X bridge BR` (a VXLAN is an ordinary
                    // kernel link in `self.links`, keyed by name). The
                    // VXLAN-specific bridge-slave defaults are applied
                    // automatically: `neigh_suppress on` + `learning off`
                    // by `vxlan_bridge_port_defaults` (fired from
                    // `link_add` when a VXLAN gains a master), and
                    // addrgenmode none is the VXLAN creation default. We
                    // intercept here rather than routing through the
                    // VxlanBuilder so a bridge-only change doesn't re-emit
                    // VxlanAdd (which would re-create the device). The
                    // leaf still lands in the running-config tree like the
                    // interface case. `delete … bridge BR` carries the
                    // value, which we drain and treat as detach.
                    if let Some(name) = args.string() {
                        let bridge = if msg.op.is_set() {
                            args.string()
                        } else {
                            let _ = args.string();
                            None
                        };
                        let _ = self.tx.send(Message::LinkBridgeBind {
                            ifname: name,
                            bridge,
                        });
                    }
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
                self.static_vrf_v4.commit(&self.tx);
                self.static_vrf_v6.commit(&self.tx);
                self.mpls_config.commit(self.tx.clone());
                self.block_config.commit(self.tx.clone());
                self.locator_config.commit(self.tx.clone());
            }
            ConfigOp::Completion => {
                // `comps_dynamic` passes the dynamic handler name
                // (`rib:<handler>`) as the first path segment.
                let comps = match msg.paths.first().map(|p| p.name.as_str()) {
                    Some("vrf") => self.vrf_comps(),
                    Some("bridge") => self.bridge_comps(),
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

    #[allow(clippy::too_many_arguments)]
    async fn mac_add(
        &mut self,
        vni: u32,
        mac: MacAddr,
        tunnel_endpoint: Option<IpAddr>,
        flags: u8,
        seq: u32,
        esi: Option<[u8; 10]>,
        srv6_sid: Option<std::net::Ipv6Addr>,
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

        // Forward to kernel FIB (or, with an SRv6 L2 service SID, the
        // cradle eBPF tee).
        self.fib_handle
            .mac_add(vni, &mac, tunnel_endpoint, flags, seq, esi, srv6_sid)
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

    /// Resolve a VNI to its local `(bridge ifindex, VXLAN-port ifindex)`
    /// — the VXLAN link carrying `vni` is the bridge port, and its
    /// `master` is the bridge. `None` when the VNI has no local VXLAN
    /// enslaved to a bridge.
    fn vni_to_bridge_vxlan(&self, vni: u32) -> Option<(u32, u32)> {
        self.links.iter().find_map(|(ifindex, link)| {
            if link.vni == Some(vni) {
                link.master.map(|bridge| (bridge, *ifindex))
            } else {
                None
            }
        })
    }

    /// Program (or remove) a selective EVPN multicast forwarding entry
    /// in the kernel bridge MDB from a received Type-6 SMET route.
    /// vid 0 (non-VLAN-aware bridge) for now — per-VLAN mapping is a
    /// follow-up. No-op when the VNI has no local VXLAN bridge.
    async fn smet_install(
        &self,
        vni: u32,
        group: IpAddr,
        source: Option<IpAddr>,
        dst: IpAddr,
        add: bool,
    ) {
        let Some((bridge_ifindex, vxlan_ifindex)) = self.vni_to_bridge_vxlan(vni) else {
            return;
        };
        self.fib_handle
            .mdb_install(
                bridge_ifindex,
                vxlan_ifindex,
                0,
                group,
                source,
                dst,
                vni,
                add,
            )
            .await;
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

/// Resolve the effective cradle tee endpoint from the two `system cradle`
/// knobs. The tee is active only when `system cradle enabled` is true; the
/// endpoint is the `system cradle grpc-endpoint` override if set, else the
/// `unix:cradle/grpc` default. `system cradle grpc-endpoint` on its own does not enable
/// the tee — it only points an already-enabled tee somewhere else.
fn cradle_effective_endpoint(enabled: bool, grpc: Option<&str>) -> Option<String> {
    if enabled {
        Some(grpc.unwrap_or("unix:cradle/grpc").to_string())
    } else {
        None
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

#[cfg(test)]
mod cradle_endpoint_tests {
    use super::cradle_effective_endpoint;

    #[test]
    fn disabled_without_override_is_none() {
        assert_eq!(cradle_effective_endpoint(false, None), None);
    }

    #[test]
    fn enabled_without_override_uses_default() {
        assert_eq!(
            cradle_effective_endpoint(true, None).as_deref(),
            Some("unix:cradle/grpc"),
        );
    }

    #[test]
    fn override_wins_when_enabled() {
        assert_eq!(
            cradle_effective_endpoint(true, Some("unix:/tmp/c.sock")).as_deref(),
            Some("unix:/tmp/c.sock"),
        );
    }

    #[test]
    fn override_alone_does_not_enable_tee() {
        // `system cradle grpc-endpoint` without `system cradle enabled` is inert.
        assert_eq!(
            cradle_effective_endpoint(false, Some("127.0.0.1:50151")),
            None
        );
    }
}
