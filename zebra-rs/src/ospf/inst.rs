use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ipnet::{IpNet, Ipv4Net};
use isis_packet::SidLabelValue;
use netlink_packet_route::link::LinkFlags;
use ospf_packet::*;
use prefix_trie::PrefixMap;
use socket2::Socket;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use crate::config::{DisplayRequest, ShowChannel};
use crate::ospf::Ospfv2;
use crate::ospf::addr::OspfAddr;
use crate::ospf::packet::{
    apply_link_auth, build_auth_ctx, ospf_db_desc_recv, ospf_hello_recv, ospf_hello_send,
    record_md5_seq, verify_link_auth,
};
use crate::rib::api::RibRx;
use crate::rib::inst::{IlmEntry, IlmType};
use crate::rib::link::LinkAddr;
use crate::rib::{self, Link, LinkFlagsExt, Nexthop, NexthopMulti, NexthopUni, RibType};
use crate::spf::label_block::LabelConfig;
use crate::{
    config::{
        Args, CommandPath, ConfigChannel, ConfigOp, ConfigRequest, RibSubscriber,
        path_from_command, vrf_config_split,
    },
    context::Task,
    ospf_event_trace, ospf_fsm_trace,
};

use super::area::{OspfArea, OspfAreaMap};
use super::config::Callback;
use super::ifsm::{IfsmEvent, IfsmState, ospf_ifsm};
use super::link::{OspfLink, OspfLinkBfdConfig, OspfNetworkType};
use super::lsdb::{LsdbEvent, OspfLsaKey, seq_max, v2_lsa_key_unpack};
use super::network::{read_packet, write_packet};
use super::nfsm::{NfsmEvent, ospf_nfsm};
use super::socket::ospf_socket_ipv4;
use super::tilfa::{
    RepairPathMpls, build_repair_path_mpls, build_repair_path_mpls_v3, tilfa_repair_path,
};
use super::tracing::OspfTracing;
use super::version::{OspfVersion, Ospfv3};
use super::{
    AREA0, Identity, Lsdb, Neighbor, NfsmState, ospf_ls_ack_recv, ospf_ls_req_recv,
    ospf_ls_upd_recv,
};
use crate::context::{Timer, TimerType};

/// `show <path>` dispatch handler. Parameterized over `V` so an
/// `Ospf<Ospfv3>` instance carries its own `ShowCallback<Ospfv3>`
/// table distinct from `Ospf<Ospfv2>`'s. Defaults to `Ospfv2` to
/// keep existing v2 callsites resolving unchanged.
pub type ShowCallback<V = Ospfv2> = fn(&Ospf<V>, Args, bool) -> Result<String, std::fmt::Error>;

/// Constructor-default Router ID, used until a configured or
/// RIB-derived value arrives (and as the fallback when a configured
/// one is deleted on an instance that never received a RIB value).
pub const DEFAULT_ROUTER_ID: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

/// OSPF protocol instance.
///
/// Parameterized over `V: OspfVersion` (default `Ospfv2`) so the
/// embedded link/area/LSDB state can specialize per version while
/// keeping every existing v2 callsite resolving to `Ospf<Ospfv2>`
/// without textual churn. Methods on `Ospf` are still v2-bound and
/// live in `impl Ospf<Ospfv2>` below — they manipulate v2-specific
/// LSA bodies (`OspfLsp::OpaqueAreaRouterInfo`, etc.) and the v2
/// `Message` enum directly. They generalize when the
/// `OspfVersion` trait grows accessor methods, in a future round
/// of trait expansion.
pub struct Ospf<V: OspfVersion = Ospfv2> {
    pub tx: UnboundedSender<Message<V>>,
    pub rx: UnboundedReceiver<Message<V>>,
    pub ptx: UnboundedSender<Message<V>>,
    pub cm: ConfigChannel,
    pub callbacks: HashMap<String, Callback<V>>,
    pub ctx: crate::context::ProtoContext,
    pub rib_rx: UnboundedReceiver<RibRx>,
    pub links: BTreeMap<u32, OspfLink<V>>,
    /// Instance-level BFD defaults (`router ospf { bfd {} }`), inherited by
    /// every interface and overridden per interface (see
    /// [`OspfLinkBfdConfig::resolve`]).
    pub bfd: OspfLinkBfdConfig,
    pub areas: OspfAreaMap<V>,
    pub show: ShowChannel,
    pub show_cb: HashMap<String, ShowCallback<V>>,
    pub sock: Arc<AsyncFd<Socket>>,
    /// Effective Router ID — what packets, LSAs and every link
    /// `ident` carry. Derived: configured `router-id` wins, then the
    /// RIB-derived value, then [`DEFAULT_ROUTER_ID`]. Mutate via
    /// `refresh_router_id`, never directly.
    pub router_id: Ipv4Addr,
    /// Operator-configured `router ospf{,v3} router-id`. Wins over
    /// the RIB-derived value; deleting it falls back (the IS-IS
    /// configured-vs-derived split).
    pub router_id_config: Option<Ipv4Addr>,
    /// Last RIB-derived router-id (`RibRx::RouterIdUpdate`), kept
    /// while a configured router-id overrides it so a later delete
    /// can fall back immediately.
    pub rib_router_id: Option<Ipv4Addr>,
    pub lsdb_as: Lsdb<V>,
    pub lsp_map: LspMap,
    pub spf_result: Option<BTreeMap<usize, Path>>,
    pub graph: Option<spf::Graph>,
    /// `/router/ospf/fast-reroute/ti-lfa` — gates the per-destination
    /// TI-LFA repair-path computation (RFC 9490). When off, the SPF
    /// primary RIB still installs; only the repair backups are skipped.
    pub ti_lfa_enabled: bool,
    /// `/router/ospf/fast-reroute/backup-as-primary` — swap the
    /// metric-sort so the TI-LFA repair installs ahead of the SPF
    /// primary. A protection-testing knob; no effect when
    /// `ti_lfa_enabled` is off (there is no repair to promote).
    pub fast_reroute_backup_as_primary: bool,
    /// `/router/ospf{,v3}/fast-reroute/ti-lfa/compute-mode` — how the
    /// per-destination TI-LFA computation is scheduled (serial default;
    /// conservative/aggressive/sharding fan out on the rayon pool),
    /// selected by one keyword per mode under the `mode` choice. Joined
    /// with `ti_lfa_compute_shards` at SPF-input build time. Results are
    /// identical across modes.
    pub ti_lfa_compute_mode: spf::TilfaComputeModeConfig,
    /// `/router/ospf{,v3}/fast-reroute/ti-lfa/compute-mode/sharding/shards`
    /// — hard upper bound on TI-LFA parallelism, consulted only in
    /// sharding mode. Default 8, matching the YANG default.
    pub ti_lfa_compute_shards: u16,
    /// TI-LFA compute telemetry for the most recent SPF run, stamped
    /// by `apply_spf_result` like `spf_duration` (last-area-wins).
    /// None until TI-LFA runs (and cleared when it is disabled).
    pub tilfa_stats: Option<spf::TilfaStats>,
    /// Per-destination TI-LFA repair paths from the most recent SPF
    /// (keyed by destination vertex id), mirror of `spf_result`'s
    /// single-area snapshot. Produced graph-only on the SPF worker;
    /// resolved to MPLS labels + stamped onto the RIB on the main task.
    /// Read by `show ospf ti-lfa`. `None` until the first run with
    /// TI-LFA enabled.
    pub tilfa_result: Option<BTreeMap<usize, Vec<spf::RepairPath>>>,
    /// Per-Flexible-Algorithm SPF trees (RFC 9350), keyed by algo id
    /// (128..=255 from `flex_algo.config`). `None` for an algo whose
    /// per-algo graph had no source this cycle. Recomputed each SPF
    /// run alongside `spf_result`; read by `show ospf flex-algo`.
    pub spf_flex_algo: BTreeMap<u8, Option<BTreeMap<usize, Path>>>,
    /// Per-Flexible-Algorithm IPv4 RIB, keyed by algo id. Each prefix
    /// carries the per-algo SPF nexthops + the prefix's per-algo
    /// Prefix-SID (RFC 9350 §7). Held in-memory only — the per-algo
    /// Prefix-SID *labels* install into the kernel MPLS ILM (a
    /// follow-up), but per-algo IPv4 does not reach the FIB (the global
    /// table has no algorithm dimension), mirroring IS-IS.
    pub rib_flex_algo: BTreeMap<u8, PrefixMap<Ipv4Net, SpfRoute>>,
    /// Per-Flexible-Algorithm IPv6 RIB (OSPFv3), keyed by algo id. v6
    /// sibling of `rib_flex_algo`: each prefix carries the per-algo SPF
    /// nexthops + the prefix's per-algo Prefix-SID. In-memory only — the
    /// per-algo Prefix-SID labels install into `ilm6` (a follow-up), but
    /// per-algo IPv6 does not reach the FIB.
    pub rib6_flex_algo: BTreeMap<u8, PrefixMap<ipnet::Ipv6Net, SpfRouteV3>>,
    pub rib: PrefixMap<Ipv4Net, SpfRoute>,
    /// Per-area route contributions, keyed by area-id. Each area's SPF
    /// completion stores its own routing-table slice here (intra-area
    /// from that area's LSDB + inter-area from that area's Type-3
    /// summaries). `apply_spf_result` merges them — with RFC 2328
    /// §16.4 path-type preference — into `rib` for the FIB. An ABR's
    /// two areas no longer clobber each other, and Type-3 origination
    /// reads these per-area slices to decide what to re-advertise.
    pub rib_areas: BTreeMap<Ipv4Addr, PrefixMap<Ipv4Net, SpfRoute>>,
    /// Per-area SPF results, keyed by area-id. Mirrors `rib_areas`
    /// but stores the raw vertex-id → Path map so Type-4 Summary-ASBR
    /// origination can look up the exact SPF cost to any vertex in any
    /// area without being limited to the last-computed area snapshot
    /// stored in `spf_result`.
    pub spf_results: BTreeMap<Ipv4Addr, BTreeMap<usize, crate::spf::calc::Path>>,
    /// MPLS LFIB shadow. Keyed by absolute incoming label, value
    /// carries the swap/pop action + the nexthops where the kernel
    /// should forward labeled traffic. Diffed against the freshly
    /// rebuilt ILM after each SPF run to emit `rib::Message::IlmAdd`
    /// / `IlmDel` so the kernel MPLS table tracks the SR-MPLS state.
    pub ilm: BTreeMap<u32, SpfIlm>,
    /// v3 sibling of `ilm`. Same key (absolute label) and same role
    /// (MPLS LFIB shadow), but the value carries v6-keyed nexthops
    /// matching `SpfRouteV3`. Populated by `apply_routing_updates_v3`
    /// from the v3 SR-MPLS RIB; empty on v2 instances.
    pub ilm6: BTreeMap<u32, SpfIlmV3>,
    /// First-fit Adjacency-SID label allocator backed by the local SRLB
    /// (`srmpls::SRLB_START` .. `SRLB_START + SRLB_RANGE - 1`). Created
    /// when `segment-routing mpls` is enabled, dropped when it's
    /// disabled. Each Full adjacency claims one label from the pool on
    /// transition into Full and releases it on regression; the
    /// `(ifindex, neighbor_router_id) -> label` mapping is held in
    /// `lan_adj_sids` below so origination and ILM install can read it.
    pub local_pool: Option<crate::spf::label_pool::LabelPool>,
    /// Per-adjacency Adjacency-SID label map. Keyed by
    /// `(ifindex, neighbor_interface_addr)`; the value is the absolute
    /// label allocated from `local_pool` on the corresponding NFSM
    /// Full transition. Keyed on the interface address (not the
    /// router-id) because the address is always available even when
    /// the `Neighbor` struct has just been removed by an inactivity
    /// kill — the origination side resolves the address back to a
    /// router-id at LSA build time.
    /// Used to drive LAN Adj-SID origination on broadcast/NBMA links
    /// (RFC 8665 §6), the dynamic P2P Adj-SID fallback (advertised as
    /// a local V|L label when no `adjacency-sid` is configured —
    /// IS-IS-parity automatic allocation), and the matching local ILM
    /// install. Cleared when SR-MPLS is disabled.
    pub lan_adj_sids: BTreeMap<(u32, Ipv4Addr), u32>,
    /// v3 IPv6 RIB shadow. Populated by
    /// `apply_routing_updates_v3` after each SPF run; diffed
    /// against the next computation so we only emit
    /// `rib::Message::Ipv6Add` / `Ipv6Del` for changed entries.
    /// Empty on v2 instances (they don't compute v6 routes).
    pub rib6: PrefixMap<ipnet::Ipv6Net, SpfRouteV3>,
    /// Per-area v6 route slices, keyed by area — the v3 sibling of
    /// `rib_areas`. Refreshed by `apply_v3_spf_result` after each
    /// area's SPF; merged into `rib6` by `merge_area_ribs6` and read
    /// by the ABR Inter-Area-Prefix origination (`abr_summary_*_v3`).
    pub rib6_areas: BTreeMap<Ipv4Addr, PrefixMap<ipnet::Ipv6Net, SpfRouteV3>>,
    pub tracing: OspfTracing,
    pub segment_routing: super::srmpls::SegmentRoutingMode,

    /// SRv6 (RFC 9513) — name of the locator configured under
    /// `segment-routing srv6 locator`, the name currently watched at
    /// the RIB, the resolved snapshot, and the installed End/uN SID.
    /// v3-only: the config handler exists only in `config_v3.rs`, so
    /// these stay `None` on an `Ospf<Ospfv2>` instance.
    pub srv6_locator_name: Option<String>,
    pub watched_locator: Option<String>,
    pub sr_locator: Option<crate::rib::Locator>,
    pub sr_end_sid: Option<std::net::Ipv6Addr>,
    /// ELIB function pool for End.X allocation — shared allocator
    /// implementation with IS-IS (RFC 9352 reserves the same upper
    /// half of the 16-bit function space).
    pub elib: crate::isis::srv6::ElibPool,
    /// Per-adjacency End.X SIDs, keyed like `lan_adj_sids` by
    /// `(ifindex, neighbor router-id)`.
    pub endx_sids: BTreeMap<(u32, Ipv4Addr), super::srv6::EndxSidState>,
    /// SR snapshot channel from the RIB (`SrSubscribe`); only the v3
    /// event loop polls it.
    pub sr_rx: UnboundedReceiver<crate::rib::RibSrRx>,
    /// Per-instance graceful-restart helper policy (RFC 3623 §3.1).
    /// Defaults: helper enabled, max grace 1800s, strict LSA
    /// checking on — same as the YANG model's defaults.
    pub gr_config: super::neigh::GracefulRestartConfig,
    /// RFC 3623 §2 restarting-router state. `Some` once
    /// `gr_restart_begin` floods Grace LSAs and stages the
    /// restart; `None` in steady state. While `Some`, the
    /// originated Router-Info LSA carries `gr_capable=true`.
    pub restarting: Option<super::neigh::RestartingState>,
    /// Snapshot of `/key-chains/key-chain <name>` entries the policy
    /// actor has pushed to this OSPF instance via `PolicyRx::KeyChain`
    /// notifications. The canonical map lives in `policy::Policy`;
    /// this is a per-interface-subscribed view kept up to date by
    /// the OSPF event loop. Per-interface `key-chain <name>` leaves
    /// resolve into entries here.
    ///
    /// Empty when no interface is bound to a chain or when the
    /// referenced chain hasn't been configured yet — `auth_send_ctx`
    /// will then return `None` and peers reject the zero-trailer
    /// packet, which is the louder failure we want over silently
    /// picking a stale key.
    pub key_chains: BTreeMap<String, crate::policy::KeyChain>,
    /// Subscriber side of the policy channel. The `Subscribe`
    /// message is sent on `new()`; subsequent `Register` /
    /// `Unregister` messages happen from the per-interface
    /// `key-chain <name>` callback. `policy_tx` is also stashed so
    /// the config callback can fire Register / Unregister without
    /// having to thread it through every layer.
    pub policy_tx: UnboundedSender<crate::policy::Message>,
    pub policy_rx: UnboundedReceiver<crate::policy::PolicyRx>,
    pub spf_last: Option<Instant>,
    pub spf_duration: Option<Duration>,
    /// Cached snapshot of v4 routes the RIB is pushing via
    /// `RedistAdd` subscriptions. Keyed by `(rtype, prefix)`. Today
    /// only `RibType::Connected` is subscribed (per-area
    /// `redistribute connected` under NSSA); future static / bgp
    /// sources add their rtype to the same map. Updated by
    /// `process_rib_msg`'s `RouteAdd` / `RouteDel` handlers and
    /// consumed by `nssa_redist_connected_resync` when origination
    /// state needs to be rebuilt (config change, area-type flip).
    pub redist_v4: BTreeMap<(crate::rib::RibType, Ipv4Net), crate::rib::RouteEntryV4>,
    /// v6 sibling of `redist_v4`, populated by an OSPFv3 instance from
    /// `RedistAfi::Ipv6` `RouteAdd`/`RouteDel` and consumed by
    /// `nssa_redist_connected_resync_v3`. The generic `Ospf<V>` carries
    /// both maps; a v2 instance leaves this empty.
    pub redist_v6: BTreeMap<(crate::rib::RibType, ipnet::Ipv6Net), crate::rib::RouteEntryV6>,
    /// Instance-level `redistribute <source>` knobs, keyed by the RIB
    /// route type (connected / static / kernel / isis / bgp). An entry
    /// enables Type-5 AS-External origination (FA=0) for every route of
    /// that source in `redist_v4` / `redist_v6`; removing it stops and
    /// flushes. In a per-VRF instance the bgp source injects the
    /// VPNv4/VPNv6 routes BGP imported into the VRF into the CE-facing
    /// OSPF (the L3VPN PE-CE down direction).
    pub redist: BTreeMap<crate::rib::RibType, crate::ospf::area::RedistEntry>,
    /// Per-source prefixes of Type-5 LSAs we self-originated from the
    /// instance-level `redistribute` knobs (v2 / IPv4). Diffed by
    /// `as_external_redist_resync`; flushed when the knob is removed.
    pub redist_originated: BTreeMap<crate::rib::RibType, BTreeSet<Ipv4Net>>,
    /// IPv6 counterpart of [`Self::redist_originated`]: per-source
    /// prefixes of OSPFv3 AS-External (Type-5) LSAs self-originated from
    /// instance-level `redistribute`. A v2 instance leaves this empty.
    pub redist_originated_v6: BTreeMap<crate::rib::RibType, BTreeSet<ipnet::Ipv6Net>>,
    /// Staged Flexible Algorithm definitions for this instance
    /// (`/router/ospf{,v3}/flex-algo`, RFC 9350). Shared staging engine
    /// keyed by the version's `FLEX_ALGO_PREFIX`; origination from the
    /// committed entries lands in a later phase.
    pub flex_algo: crate::flex_algo::FlexAlgoConfig,
    /// This instance's copy of the global `/affinity-map` table,
    /// resolving affinity names to RFC 7308 admin-group bit positions.
    /// Fed by the config broadcast; shared by all IGPs.
    pub affinity_map: crate::flex_algo::AffinityMap,
    /// This instance's staging of the global `/srlg` table.
    pub srlg_config: crate::flex_algo::SrlgGroupBuilder,
    /// Applied snapshot of the global `/srlg` table (name → 32-bit
    /// value), folded from `srlg_config` at CommitEnd. Read by FAD
    /// origination to resolve `srlg-exclude` names.
    pub srlg_groups: std::collections::BTreeMap<String, crate::flex_algo::SrlgGroup>,
    /// v3-only outbound packet channel. `Ospf<Ospfv3>::new` spawns
    /// `network_v6::write_packet_v6` consuming the matching receiver;
    /// producers of v3 outgoing packets clone this sender to push
    /// packets. `None` on v2.
    pub v3_send_tx: Option<UnboundedSender<super::network_v6::Ospfv3Send>>,
    /// v3-only inbound packet channel. `Ospf<Ospfv3>::new` spawns
    /// `network_v6::read_packet_v6` producing into the matching
    /// sender; the v3 event loop `take()`s this receiver at startup.
    /// `None` on v2.
    pub v3_recv_rx: Option<UnboundedReceiver<super::network_v6::Ospfv3Recv>>,

    /// Protocol identity for name-keyed RIB / policy registrations.
    /// `V::PROTO` (`"ospf"` / `"ospfv3"`) for the default instance,
    /// `"<proto>:vrf:<name>"` for a per-VRF instance — so the two
    /// don't clobber each other's rows in the name-keyed policy /
    /// redistribute / SR registries. Route-install attribution is by
    /// the numeric `ProtoId` in `ctx.rib`, so it is unaffected.
    pub proto_label: String,
    /// Send-capable RIB-subscription factory. The default instance
    /// uses it to mint a per-VRF `RibClient` bound to the VRF's kernel
    /// `table_id` when spawning a child; cloned into each child too.
    pub rib_subscriber: RibSubscriber,
    /// Sender into the config manager, for (de)registering a child's
    /// `show ... vrf <name>` channel via `SubscribeShowVrf` /
    /// `UnsubscribeShowVrf`. Bounded — send with `try_send`.
    pub config_tx: tokio::sync::mpsc::Sender<crate::config::Message>,
    /// Per-VRF buffered config (default instance only). Each
    /// `router ospf{,v3} vrf <name> ...` line, rewritten to strip the
    /// `vrf <name>` prefix, is appended in commit order; replayed into
    /// a child at spawn and kept so a `VrfDel`→`VrfAdd` flap respawns
    /// from intent. Empty for child instances.
    pub vrf_log: BTreeMap<String, Vec<(Vec<CommandPath>, ConfigOp)>>,
    /// Running per-VRF child tasks (default instance only), by name.
    pub vrf_registry: BTreeMap<String, super::vrf::OspfVrfHandle>,
    /// Kernel VRF master info from `RibRx::VrfAdd` (default instance
    /// only): VRF name → (table_id, ifindex). A child spawns once both
    /// config intent (`vrf_log`) and kernel info exist.
    pub rib_known_vrfs: BTreeMap<String, (u32, u32)>,

    /// BFD client handle, captured at spawn (BFD is eager-spawned
    /// before OSPF). `None` only if BFD failed to start. Used to
    /// Subscribe / Unsubscribe per-neighbor single-hop sessions; see
    /// [`Ospf::bfd_reconcile_nbr`].
    pub bfd_client_tx: Option<UnboundedSender<crate::bfd::inst::ClientReq>>,
    /// Notifier the BFD instance fans state-change events back on.
    /// Cloned into every Subscribe; the matching receiver is drained by
    /// the event loop into [`Ospf::process_bfd_event`].
    pub bfd_event_tx: UnboundedSender<crate::bfd::inst::BfdEvent>,
    pub bfd_event_rx: UnboundedReceiver<crate::bfd::inst::BfdEvent>,

    /// STAMP client handle, captured at spawn (STAMP is eager-spawned
    /// before OSPF). Used by [`Ospf::stamp_reconcile_link`] to
    /// (un)subscribe per-link measurement sessions for `te-metric
    /// measurement` interfaces. `None` for per-VRF children (sessions
    /// are default-VRF only in Phase 1) or if STAMP failed to start.
    /// Only v2 ever subscribes — the v3 config tree has no
    /// measurement block.
    pub stamp_client_tx: Option<UnboundedSender<crate::stamp::client::ClientReq>>,
    /// Notifier STAMP fans `MetricUpdate`s back on; cloned into every
    /// Subscribe. The receiver is drained by the v2 event loop into
    /// [`Ospf::process_stamp_event`].
    pub stamp_event_tx: UnboundedSender<crate::stamp::client::StampEvent>,
    pub stamp_event_rx: UnboundedReceiver<crate::stamp::client::StampEvent>,
}

// OSPF inteface structure which points out upper layer struct members.
//
// Parameterized over V: OspfVersion via the borrowed references
// into v3-shaped state (Identity<V>, Lsdb<V>, Vec<OspfAddr<V>>).
// Default V = Ospfv2 keeps function signatures unchanged at callsites.
pub struct OspfInterface<'a, V: OspfVersion = Ospfv2> {
    pub tx: &'a UnboundedSender<Message<V>>,
    pub router_id: &'a Ipv4Addr,
    pub ident: &'a Identity<V>,
    pub addr: &'a Vec<OspfAddr<V>>,
    pub mtu: u32,
    pub db_desc_in: &'a mut usize,
    pub lsdb: &'a mut Lsdb<V>,
    pub lsdb_as: &'a mut Lsdb<V>,
    pub area_id: Ipv4Addr,
    pub area_type: super::area::AreaType,
    pub exchange_loading_count: usize,
    pub mtu_ignore: bool,
    pub retransmit_interval: u16,
    /// Snapshot of the parent link's resolved network type. The NFSM
    /// keys off this to decide 2-Way -> ExStart on P2P links without
    /// gating on DR/BDR.
    pub network_type: OspfNetworkType,
    /// Snapshot of the parent link's resolved RFC 2328 §D
    /// authentication mode. Cached here so packet builders that
    /// only borrow `OspfInterface` (not `OspfLink`) can stamp
    /// outbound packets without a second `links` lookup.
    pub auth_mode: super::link::OspfAuthMode,
    /// Snapshot of the configured simple-password key, if any.
    /// Only consulted when `auth_mode == Simple`.
    pub auth_key: Option<[u8; 8]>,
    /// Snapshot of the active cryptographic-auth send key (lowest
    /// configured key-id across MD5 + HMAC-SHA entries). `None`
    /// when `MessageDigest` is configured but no key has been
    /// added yet.
    pub crypto_key: Option<(u8, super::link::AuthKey)>,
    /// Borrow of the parent link's cryptographic-auth send
    /// counter. `AtomicU32` allows mutation through an `&` borrow
    /// so every send path can `fetch_add(1)` without taking `&mut`
    /// on the surrounding `OspfLink`.
    pub md5_seq: &'a std::sync::atomic::AtomicU32,
    /// Snapshot of the per-instance graceful-restart helper
    /// policy. Read by `gr_maybe_enter_helper` to gate Grace-LSA
    /// acceptance against `helper_enabled` and `max_grace_period`.
    pub gr_config: super::neigh::GracefulRestartConfig,
    pub tracing: &'a OspfTracing,
    /// v3-only outbound packet channel borrow. Carries the `Ospfv3Send`
    /// sender that the `network_v6::write_packet_v6` task consumes.
    /// `None` on v2 (where the v2 `Message::Send` path on `tx` is used
    /// instead). Populated by `Ospf<Ospfv3>::ospf_interface` from
    /// `self.v3_send_tx`.
    pub v3_send_tx: Option<&'a UnboundedSender<super::network_v6::Ospfv3Send>>,
    /// Per-link LSDB (RFC 5340 §A.4.9). Holds link-scope LSAs that
    /// flood only on the segment they originated on. Always
    /// borrowed from `OspfLink::lsdb`; on v2 it's empty (no
    /// link-scope LSA types in RFC 2328).
    pub link_lsdb: &'a mut Lsdb<V>,
}

impl<'a, V: OspfVersion> OspfInterface<'a, V> {
    /// Bundle the auth state needed to stamp one outbound packet.
    /// Bumps the borrowed cryptographic-auth seq as a side effect
    /// — mirrors `OspfLink::auth_send_ctx`.
    pub fn auth_send_ctx(&self) -> crate::ospf::packet::AuthSendCtx {
        let s = self
            .md5_seq
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        crate::ospf::packet::AuthSendCtx {
            mode: self.auth_mode,
            simple_key: self.auth_key,
            crypto_key: self.crypto_key.clone(),
            md5_seq: s,
        }
    }
}

// Version-agnostic helpers. These methods touch only generic-safe
// fields on `Ospf<V>` (links, areas, lsdb_as, router_id, tracing,
// the v2-shaped tx channel) and produce `OspfInterface<V>` /
// `&Neighbor<V>` values typed by `V`.
impl<V: OspfVersion> Ospf<V> {
    /// Reconcile one neighbor's BFD subscription against the interface
    /// config and the neighbor's current NFSM state. Idempotent and
    /// order-independent: the desired (key, params) pair is compared to
    /// the tracked `nbr.bfd_session_key` / `nbr.bfd_session_params`. A
    /// *key* change unsubscribes the stale key before subscribing the
    /// new one (so an address change or a `min-neighbor-state` flip
    /// never leaks or duplicates a session); a params-only change (e.g.
    /// `echo-mode`) re-sends `Subscribe`, which the BFD instance applies
    /// to the live session (`Bfd::update_echo_params`) — no unsubscribe,
    /// which could tear the session down if we were its last subscriber.
    /// OSPF sessions are single-hop (directly connected neighbors); the
    /// `profile` is stored but not yet applied (the session uses
    /// `SessionParams::default()`, matching BGP / IS-IS).
    fn bfd_reconcile_nbr(&mut self, ifindex: u32, nbr_addr: Ipv4Addr) {
        // Effective BFD config for this interface = the per-interface `bfd {}`
        // merged over the instance-level `router ospf { bfd {} }` default, per
        // leaf (so an instance `enable true` blanket-enables interfaces that
        // didn't set their own). No link ⇒ nothing to reconcile.
        let eff = match self.links.get(&ifindex) {
            Some(link) => link.config.bfd.resolve(&self.bfd),
            None => return,
        };
        // Echo role + intervals. `echo-mode` selects which half is active; the
        // BFD instance further gates Echo to single-hop with a live reflector.
        // Both families work — v2 sessions run IPv4 Echo, v3 sessions IPv6
        // Echo over the link-local pair. No `echo-mode` ⇒ Echo off.
        let (echo_mode, echo_rx_us, echo_tx_us) = match eff.echo_mode {
            Some(mode) => (
                mode,
                eff.echo_receive_ms.saturating_mul(1000),
                eff.echo_transmit_ms.saturating_mul(1000),
            ),
            None => (crate::bfd::session::EchoMode::Off, 0, 0),
        };

        let desired = {
            let Some(link) = self.links.get(&ifindex) else {
                return;
            };
            let Some(nbr) = link.nbrs.get(&nbr_addr) else {
                return;
            };
            let up = eff.enable && nbr.state >= eff.min_neighbor_state.as_nfsm();
            if up {
                V::bfd_addrs(&link.addr, nbr).map(|(local, remote)| {
                    crate::bfd::session::SessionKey {
                        local,
                        remote,
                        ifindex,
                        multihop: false,
                    }
                })
            } else {
                None
            }
        };

        let params = crate::bfd::session::SessionParams {
            echo_mode,
            required_min_echo_rx_us: echo_rx_us,
            echo_transmit_us: echo_tx_us,
            detect_offload: eff.detect_offload,
            ..crate::bfd::session::SessionParams::default()
        };
        let desired_params = desired.map(|_| params);

        let (current, current_params) = self
            .links
            .get(&ifindex)
            .and_then(|l| l.nbrs.get(&nbr_addr))
            .map(|n| (n.bfd_session_key, n.bfd_session_params))
            .unwrap_or((None, None));
        if desired == current && desired_params == current_params {
            return;
        }

        // Apply the delta against the BFD instance (eager-spawned, so
        // the handle is normally live). If it's absent, leave the
        // tracked key untouched so a later reconcile retries.
        let Some(client_tx) = self.bfd_client_tx.as_ref() else {
            return;
        };
        if let Some(old) = current
            && desired != current
        {
            let _ = client_tx.send(crate::bfd::inst::ClientReq::Unsubscribe {
                client: V::PROTO.to_string(),
                key: old,
            });
        }
        if let Some(key) = desired {
            let _ = client_tx.send(crate::bfd::inst::ClientReq::Subscribe {
                client: V::PROTO.to_string(),
                key,
                params,
                notifier: self.bfd_event_tx.clone(),
            });
        }
        if let Some(nbr) = self
            .links
            .get_mut(&ifindex)
            .and_then(|l| l.nbrs.get_mut(&nbr_addr))
        {
            nbr.bfd_session_key = desired;
            nbr.bfd_session_params = desired_params;
        }
    }

    /// Re-evaluate every neighbor on every interface — used by the
    /// instance-level `bfd {}` config callbacks, whose defaults (e.g. a
    /// blanket `enable`) affect interfaces that set nothing of their own.
    pub(crate) fn bfd_reconcile_all(&mut self) {
        let ifindexes: Vec<u32> = self.links.keys().copied().collect();
        for ifindex in ifindexes {
            self.bfd_reconcile_link(ifindex);
        }
    }

    /// Re-evaluate every neighbor on `ifindex` — used by the `bfd`
    /// interface config callbacks, which can flip the subscribe state
    /// of already-formed neighbors.
    pub(crate) fn bfd_reconcile_link(&mut self, ifindex: u32) {
        let nbrs: Vec<Ipv4Addr> = match self.links.get(&ifindex) {
            Some(link) => link.nbrs.keys().copied().collect(),
            None => return,
        };
        for nbr_addr in nbrs {
            self.bfd_reconcile_nbr(ifindex, nbr_addr);
        }
    }

    /// Diff the STAMP measurement session this link *should* hold
    /// (measurement enabled ∧ point-to-point ∧ a Full neighbor ∧ an
    /// IPv4 address pair — `V::bfd_addrs` yields link-locals on v3, so
    /// the v4 gate keeps v3 inert on top of it having no measurement
    /// YANG) against the tracked subscription, and (un)subscribe on
    /// the edges only. Tearing a session down also clears the link's
    /// measured values — they must not survive into the next adjacency
    /// or outlive a disable. Returns `true` when measured values were
    /// cleared, so the (version-specific) caller re-originates the
    /// Extended-Link LSA.
    pub(crate) fn stamp_reconcile_link(&mut self, ifindex: u32) -> bool {
        if self.stamp_client_tx.is_none() {
            return false;
        }
        let Some(link) = self.links.get(&ifindex) else {
            return false;
        };

        let desired = if link.config.te_metric_measurement.enabled()
            && link.network_type == super::link::OspfNetworkType::PointToPoint
        {
            link.nbrs
                .values()
                .find(|n| n.state == NfsmState::Full)
                .and_then(|nbr| V::bfd_addrs(&link.addr, nbr))
                .and_then(|(local, remote)| match (local, remote) {
                    (std::net::IpAddr::V4(_), std::net::IpAddr::V4(_)) => Some((
                        crate::stamp::session::SessionKey {
                            local,
                            remote,
                            ifindex,
                        },
                        link.config.te_metric_measurement.resolve(),
                    )),
                    _ => None,
                })
        } else {
            None
        };

        if desired == link.stamp_session {
            return false;
        }
        let stale = link.stamp_session;
        let Some(client_tx) = self.stamp_client_tx.as_ref() else {
            return false;
        };
        if let Some((key, _)) = stale {
            let _ = client_tx.send(crate::stamp::client::ClientReq::Unsubscribe {
                client: V::PROTO.to_string(),
                key,
            });
        }
        if let Some((key, params)) = desired {
            let _ = client_tx.send(crate::stamp::client::ClientReq::Subscribe {
                client: V::PROTO.to_string(),
                key,
                params,
                notifier: self.stamp_event_tx.clone(),
            });
        }
        let Some(link) = self.links.get_mut(&ifindex) else {
            return false;
        };
        link.stamp_session = desired;
        // A torn-down session's measured values are stale the moment
        // the subscription ends — clear them; static config (if any)
        // takes back over via `te_metric_effective`.
        if stale.is_some() && link.measured_te_metric != super::link::LinkTeMetric::default() {
            link.measured_te_metric = super::link::LinkTeMetric::default();
            return true;
        }
        false
    }

    /// Store a damped STAMP export on its link. Returns the ifindex
    /// when the link's measured values changed (the version-specific
    /// caller re-originates), `None` for stale/unknown sessions.
    pub(crate) fn stamp_apply_metric_update(
        &mut self,
        event: crate::stamp::client::StampEvent,
    ) -> Option<u32> {
        let crate::stamp::client::StampEvent::MetricUpdate { key, snapshot } = event;
        let link = self.links.get_mut(&key.ifindex)?;
        // Only the tracked session may write — a late event from a
        // just-unsubscribed key must not resurrect stale values.
        if link.stamp_session.map(|(k, _)| k) != Some(key) {
            return None;
        }
        link.measured_te_metric = match snapshot {
            Some(snap) => super::link::LinkTeMetric {
                unidirectional_delay: Some(snap.avg),
                min_delay: Some(snap.min),
                max_delay: Some(snap.max),
                delay_variation: Some(snap.variation),
                loss: None,
            },
            None => super::link::LinkTeMetric::default(),
        };
        tracing::info!(
            ifindex = key.ifindex,
            ?snapshot,
            "{}: stamp metric update applied",
            V::PROTO,
        );
        Some(key.ifindex)
    }

    /// React to a BFD session state change. On Down, tear the matching
    /// OSPF adjacency down via the same dead-timer (`InactivityTimer`)
    /// path the hold-timer uses (RFC 5882 §5), and drop the
    /// subscription. The synthetic `from == to` mirror (sent on
    /// subscribe) and non-Down transitions are ignored.
    pub(crate) fn process_bfd_event(&mut self, event: crate::bfd::inst::BfdEvent) {
        let crate::bfd::inst::BfdEvent::StateChange { key, change } = event;
        tracing::info!(
            ?key,
            from = %change.from,
            to = %change.to,
            diag = %change.diag,
            "{}: bfd session state change",
            V::PROTO,
        );
        if change.from == change.to || change.to != bfd_packet::State::Down {
            return;
        }

        let ifindex = key.ifindex;
        let Some((nbr_addr, protect_addr)) = self.links.get(&ifindex).and_then(|link| {
            link.nbrs
                .iter()
                .find(|(_, n)| n.bfd_session_key == Some(key))
                .map(|(addr, n)| (*addr, V::prefix_ip(&n.ident.prefix)))
        }) else {
            tracing::debug!(
                ?key,
                "{}: bfd-down for unknown neighbor; ignoring",
                V::PROTO
            );
            return;
        };
        tracing::warn!(
            ?key,
            ifindex,
            diag = %change.diag,
            "{}: tearing down adjacency on bfd-down (RFC 5882 §5)",
            V::PROTO,
        );

        // Drop the subscription (clear tracked key + unsubscribe), then
        // drive the neighbor down via the dead-timer event.
        if let Some(client_tx) = self.bfd_client_tx.as_ref() {
            let _ = client_tx.send(crate::bfd::inst::ClientReq::Unsubscribe {
                client: V::PROTO.to_string(),
                key,
            });
        }
        if let Some(nbr) = self
            .links
            .get_mut(&ifindex)
            .and_then(|l| l.nbrs.get_mut(&nbr_addr))
        {
            nbr.bfd_session_key = None;
            nbr.bfd_session_params = None;
        }
        // Fast-reroute switchover (kernel-failover phase 4): rewire the
        // pre-installed protection groups onto their TI-LFA repairs NOW,
        // before the teardown-driven SPF / per-prefix reinstall pipeline
        // starts. The address is the neighbour's hello source — exactly
        // what SPF keyed this adjacency's route nexthops on. The RIB
        // no-ops when nothing is protected; channel ordering lands this
        // before the post-convergence route updates.
        let _ = self.ctx.rib.protect_switch(protect_addr);
        let _ = self.tx.send(Message::Nfsm(
            ifindex,
            nbr_addr,
            super::nfsm::NfsmEvent::InactivityTimer,
        ));
    }

    /// Reset OSPF adjacencies on operator request (`clear ospf
    /// neighbor [<router-id>]`). `None` resets every neighbor on
    /// every link; `Some(id)` resets only the neighbor whose OSPF
    /// Router-ID (the "Neighbor ID" column in `show ospf
    /// neighbor`) is `id`. We match on `ident.router_id`, but key the
    /// `Message::Nfsm` teardown by the `nbrs` map key (the interface
    /// source IP for v2) the handler looks the neighbor up by.
    ///
    /// Each target is driven with `InactivityTimer` — the same event
    /// the dead-timer fires — so a clear is identical to a timeout:
    /// the neighbor instance is destroyed (see `nfsm_kill_neighbor`),
    /// and because a live peer keeps Helloing it is re-learned from
    /// scratch (Down → … → Full), bouncing the adjacency.
    fn clear_neighbor(&self, id: Option<Ipv4Addr>) {
        let mut targets: Vec<(u32, Ipv4Addr)> = Vec::new();
        for (ifindex, link) in self.links.iter() {
            for (nbr_key, nbr) in link.nbrs.iter() {
                if id.is_none_or(|want| want == nbr.ident.router_id) {
                    targets.push((*ifindex, *nbr_key));
                }
            }
        }
        for (ifindex, nbr_key) in targets {
            let _ = self.tx.send(Message::Nfsm(
                ifindex,
                nbr_key,
                super::nfsm::NfsmEvent::InactivityTimer,
            ));
        }
    }

    /// Candidate completions for `ext:dynamic "ospf:neighbor"` — the
    /// current neighbor Router-IDs (the "Neighbor ID" column in
    /// `show ospf neighbor`), since `clear ospf neighbor
    /// <router-id>` matches on the Router-ID, not the interface
    /// address. Deduped + sorted via `BTreeSet` (a Router-ID can
    /// appear on more than one link via parallel adjacencies).
    fn neighbor_comps(&self) -> Vec<String> {
        let mut ids: BTreeSet<Ipv4Addr> = BTreeSet::new();
        for link in self.links.values() {
            for nbr in link.nbrs.values() {
                ids.insert(nbr.ident.router_id);
            }
        }
        ids.iter().map(|id| id.to_string()).collect()
    }

    /// Record a rewritten per-VRF config line (default instance only).
    /// Appends to the VRF's replay log and, if its child is already
    /// running, forwards the line live to the child's config inbox.
    pub(crate) fn vrf_config_record(
        &mut self,
        name: String,
        rewritten: Vec<CommandPath>,
        op: ConfigOp,
    ) {
        if let Some(handle) = self.vrf_registry.get(&name) {
            let _ = handle.cm_tx.send(ConfigRequest::new(rewritten.clone(), op));
        }
        self.vrf_log
            .entry(name.clone())
            .or_default()
            .push((rewritten, op));
        // The kernel VrfAdd may already have been processed BEFORE this
        // intent line: in a same-commit `vrf X` + `router ... vrf X ...`
        // apply, the netlink-acked VrfAdd and the config lines race on
        // separate channels, and `vrf_add` alone only spawns when intent
        // landed first. Spawn here too (no-op while either half is still
        // missing) instead of waiting for a VrfDel/VrfAdd flap.
        self.vrf_spawn_if_ready(&name);
    }

    /// Spawn the per-VRF child once BOTH halves exist — kernel info
    /// (`rib_known_vrfs`, from `VrfAdd`) and active config intent
    /// (`vrf_log`). Called from `vrf_add` (kernel half arriving) and
    /// `vrf_config_record` (intent half arriving); whichever lands
    /// second performs the spawn.
    pub(crate) fn vrf_spawn_if_ready(&mut self, name: &str) {
        if self.vrf_registry.contains_key(name) {
            return;
        }
        let Some(&(table_id, _)) = self.rib_known_vrfs.get(name) else {
            return;
        };
        let has_intent = self
            .vrf_log
            .get(name)
            .is_some_and(|log| super::vrf::vrf_log_active(log));
        if !has_intent {
            return;
        }
        // Clone the replay log so the spawn borrow doesn't overlap the
        // `vrf_registry` insert below.
        let log = self.vrf_log.get(name).cloned().unwrap_or_default();
        let handle = V::spawn_vrf(
            name,
            table_id,
            &self.rib_subscriber,
            &self.config_tx,
            &self.policy_tx,
            &log,
        );
        self.vrf_registry.insert(name.to_string(), handle);
    }

    /// `CommitEnd` fan-out for the default instance: tear down per-VRF
    /// children whose `router ospf{,v3} vrf <name>` block was fully
    /// deleted this commit, then forward `CommitEnd` to every surviving
    /// live child so it runs its own commit-time reconcile.
    pub(crate) fn vrf_commit_end(&mut self) {
        let emptied: Vec<String> = self
            .vrf_log
            .iter()
            .filter(|(_, log)| !super::vrf::vrf_log_active(log))
            .map(|(name, _)| name.clone())
            .collect();
        for name in emptied {
            self.vrf_log.remove(&name);
            // Kernel info (`rib_known_vrfs`) is owned by VrfAdd/VrfDel,
            // not by config — leave it so a re-added block respawns if
            // the kernel VRF still exists.
            if self.vrf_registry.remove(&name).is_some() {
                super::vrf::despawn_ospf_vrf(
                    V::PROTO,
                    &name,
                    &self.config_tx,
                    &self.rib_subscriber,
                );
            }
        }
        for handle in self.vrf_registry.values() {
            let _ = handle
                .cm_tx
                .send(ConfigRequest::new(Vec::new(), ConfigOp::CommitEnd));
        }
    }

    /// Kernel VRF master appeared (or was replayed at subscribe time).
    /// Record its `table_id`/`ifindex`, and spawn the per-VRF OSPF
    /// child of this version if config intent exists and it isn't
    /// already running. Default instance only.
    pub(crate) fn vrf_add(&mut self, name: String, table_id: u32, ifindex: u32) {
        self.rib_known_vrfs
            .insert(name.clone(), (table_id, ifindex));
        self.vrf_spawn_if_ready(&name);
    }

    /// Kernel VRF master removed. Despawn the child but KEEP its config
    /// log so a later `VrfAdd` (master re-created) respawns from intent.
    /// RIB reclaims the VRF's FIB table on its side. Default instance
    /// only.
    pub(crate) fn vrf_del(&mut self, name: String) {
        self.rib_known_vrfs.remove(&name);
        if self.vrf_registry.remove(&name).is_some() {
            super::vrf::despawn_ospf_vrf(V::PROTO, &name, &self.config_tx, &self.rib_subscriber);
        }
    }

    /// Stage a flex-algo (`{V::FLEX_ALGO_PREFIX}/...`), `/affinity-map`
    /// or `/srlg/group` config leaf into its builder. The caller gates
    /// on the path prefix and returns early after this; the staged
    /// values apply at `CommitEnd` via `commit_flex_algo_tables`.
    fn flex_algo_table_exec(&mut self, path: String, args: Args, op: ConfigOp) {
        if path.starts_with(V::FLEX_ALGO_PREFIX) {
            let _ = self.flex_algo.exec(path, args, op);
        } else if path.starts_with("/affinity-map") {
            let _ = self.affinity_map.exec(path, args, op);
        } else if path.starts_with("/srlg/group") {
            let _ = self.srlg_config.exec(path, args, op);
        }
    }

    /// Apply the staged flex-algo / affinity-map / SRLG tables at the
    /// end of a commit cycle. Origination from the committed config
    /// (FAD / SR-Algorithm / per-link ASLA) lands in a later phase, so
    /// there are no LSA side effects here yet.
    fn commit_flex_algo_tables(&mut self) {
        self.flex_algo.commit();
        self.affinity_map.commit();
        if let Some(groups) = self.srlg_config.commit() {
            self.srlg_groups = groups;
        }
    }

    pub fn ospf_interface<'a>(
        &'a mut self,
        ifindex: u32,
        src: &Ipv4Addr,
    ) -> Option<(OspfInterface<'a, V>, &'a mut Neighbor<V>)> {
        // Compute area-wide exchange/loading count before borrowing mutably.
        let exchange_loading_count = self.count_exchange_loading_neighbors(ifindex);
        self.links.get_mut(&ifindex).and_then(|link| {
            let link_area = link.area;
            let retransmit_interval = link.retransmit_interval();
            let auth_mode = link.auth_mode();
            let auth_key = link.config.auth_key;
            let crypto_key = link.resolve_active_send_key(&self.key_chains, chrono::Utc::now());
            self.areas.get_mut(link_area).and_then(|area| {
                let area_type = area.area_type;
                link.nbrs.get_mut(src).map(|nbr| {
                    (
                        OspfInterface {
                            tx: &self.tx,
                            router_id: &self.router_id,
                            ident: &link.ident,
                            addr: &link.addr,
                            mtu: link.mtu,
                            db_desc_in: &mut link.db_desc_in,
                            lsdb: &mut area.lsdb,
                            lsdb_as: &mut self.lsdb_as,
                            area_id: link_area,
                            area_type,
                            exchange_loading_count,
                            mtu_ignore: link.config.mtu_ignore,
                            retransmit_interval,
                            network_type: link.network_type,
                            auth_mode,
                            auth_key,
                            crypto_key,
                            md5_seq: &link.md5_seq,
                            gr_config: self.gr_config,
                            tracing: &self.tracing,
                            v3_send_tx: self.v3_send_tx.as_ref(),
                            link_lsdb: &mut link.lsdb,
                        },
                        nbr,
                    )
                })
            })
        })
    }

    /// Register a kernel link in `self.links`. Idempotent: re-adding
    /// an existing ifindex is a no-op. Shared by v2 and v3 — body is
    /// version-agnostic (`OspfLink::from` is generic over `V`).
    fn link_add(&mut self, link: Link)
    where
        V::Prefix: Default,
    {
        if self.links.contains_key(&link.index) {
            return;
        }
        let link = OspfLink::from(
            self.tx.clone(),
            link,
            self.sock.clone(),
            self.router_id,
            self.ptx.clone(),
        );
        self.links.insert(link.index, link);
    }

    /// Mark a link operationally up and, if OSPF is enabled on it,
    /// fire `Ifsm::InterfaceUp`. Shared by v2 and v3.
    ///
    /// A kernel-driven `LinkDown` queues a `Message::Disable` that
    /// clears `link.enabled` / `link.area` — but the operator's
    /// YANG config (`link.config.enable`, `link.config.area`) stays
    /// intact. When the kernel link comes back up, the runtime
    /// state is stale and a bare `if link.enabled` check would skip
    /// `InterfaceUp`, leaving the IFSM in `Down` with no Hellos
    /// flowing. Peer Hellos still arrive on the still-joined
    /// multicast socket, so the neighbor lands in `Init` and never
    /// progresses — that's the symptom. Re-fire `Enable` from the
    /// config to repair the runtime state; the `Enable` arm
    /// re-originates LSAs and fires `InterfaceUp` itself.
    fn link_up(&mut self, ifindex: u32) {
        let Some(link) = self.links.get_mut(&ifindex) else {
            return;
        };
        link.link_flags |= LinkFlags::Up | LinkFlags::LowerUp;

        if !link.enabled
            && link.config.enable
            && let Some(area) = link.config.area
        {
            let _ = self.tx.send(Message::Enable(ifindex, area));
            return;
        }

        if link.enabled {
            let _ = self.tx.send(Message::Ifsm(ifindex, IfsmEvent::InterfaceUp));
        }
    }

    /// Mark a link operationally down and, if OSPF was enabled on
    /// it, fire `Disable` so the IFSM tears the adjacency down.
    /// Shared by v2 and v3.
    fn link_down(&mut self, ifindex: u32) {
        let Some(link) = self.links.get_mut(&ifindex) else {
            return;
        };
        link.link_flags &= !LinkFlags::LowerUp;

        if link.enabled {
            let area_id = link.area_id;
            let _ = self.tx.send(Message::Disable(ifindex, area_id));
        }
    }

    /// The kernel MTU of an interface changed. Refresh the cached
    /// value used to stamp the DD packet's `if_mtu` (RFC 2328 §10.6 MTU
    /// mismatch) and shown by `show ip[v6] ospf interface`. Shared by
    /// v2 and v3; updating in place keeps the IFSM/adjacency untouched.
    fn link_mtu(&mut self, ifindex: u32, mtu: u32) {
        if let Some(link) = self.links.get_mut(&ifindex) {
            link.mtu = mtu;
        }
    }

    /// The kernel link is gone. If OSPF was enabled on it, fire
    /// `Disable` so the IFSM tears the adjacency down, then drop
    /// the link from `self.links`. Shared by v2 and v3.
    fn link_del(&mut self, ifindex: u32) {
        let Some(link) = self.links.get(&ifindex) else {
            return;
        };
        if link.enabled {
            let area_id = link.area_id;
            let _ = self.tx.send(Message::Disable(ifindex, area_id));
        }
        self.links.remove(&ifindex);
    }

    /// Count Exchange/Loading neighbors across all links in the same area.
    fn count_exchange_loading_neighbors(&self, ifindex: u32) -> usize {
        let Some(link) = self.links.get(&ifindex) else {
            return 0;
        };
        let area_id = link.area;
        let Some(area) = self.areas.get(area_id) else {
            return 0;
        };
        let mut count = 0;
        for &link_ifindex in area.links.iter() {
            if let Some(area_link) = self.links.get(&link_ifindex) {
                for (_, nbr) in area_link.nbrs.iter() {
                    if nbr.state == NfsmState::Exchange || nbr.state == NfsmState::Loading {
                        count += 1;
                    }
                }
            }
        }
        count
    }

    pub fn ifname(&self, ifindex: u32) -> String {
        self.links
            .get(&ifindex)
            .map_or_else(|| "unknown".to_string(), |link| link.name.clone())
    }

    /// One-second deferred SPF trigger for `area_id`. Same shape
    /// for v2 and v3; the `Message::SpfCalc` variant doesn't carry
    /// V-specific data, so the timer body is generic.
    fn ospf_spf_timer_generic(tx: &UnboundedSender<Message<V>>, area_id: Ipv4Addr) -> Timer {
        let tx = tx.clone();
        Timer::new(1, TimerType::Once, move || {
            let tx = tx.clone();
            async move {
                let _ = tx.send(Message::SpfCalc(area_id));
            }
        })
    }

    /// Arm the SPF timer on `area` if not already armed. v3 calls
    /// this from `router_lsa_originate` / `network_lsa_originate`
    /// / `router_intra_area_prefix_lsa_originate` so any LSA
    /// install kicks off an SPF after a 1-second coalescing window.
    fn ospf_spf_schedule_generic(tx: &UnboundedSender<Message<V>>, area: &mut OspfArea<V>) {
        if area.spf_timer.is_none() {
            area.spf_timer = Some(Self::ospf_spf_timer_generic(tx, area.id));
        }
    }
}

impl Ospf<Ospfv2> {
    pub fn new(
        ctx: crate::context::ProtoContext,
        rib_rx: UnboundedReceiver<RibRx>,
        policy_tx: UnboundedSender<crate::policy::Message>,
        proto_label: String,
        rib_subscriber: RibSubscriber,
        config_tx: tokio::sync::mpsc::Sender<crate::config::Message>,
        bfd_client_tx: Option<UnboundedSender<crate::bfd::inst::ClientReq>>,
        stamp_client_tx: Option<UnboundedSender<crate::stamp::client::ClientReq>>,
    ) -> Self {
        let sock = Arc::new(AsyncFd::new(ospf_socket_ipv4(&ctx).unwrap()).unwrap());
        let (bfd_event_tx, bfd_event_rx) = mpsc::unbounded_channel();
        let (stamp_event_tx, stamp_event_rx) = mpsc::unbounded_channel();

        let policy_chan = crate::policy::PolicyRxChannel::new();
        let _ = policy_tx.send(crate::policy::Message::Subscribe {
            proto: proto_label.clone(),
            tx: policy_chan.tx.clone(),
        });

        let (tx, rx) = mpsc::unbounded_channel();
        let (ptx, prx) = mpsc::unbounded_channel();
        // v2 never watches SRv6 locators; the channel exists only
        // because the field is shared with v3. Dropping the tx makes
        // it permanently silent (and the v2 loop never polls it).
        let (_sr_tx, sr_rx) = mpsc::unbounded_channel();
        let mut ospf = Self {
            tx,
            rx,
            ptx,
            cm: ConfigChannel::new(),
            callbacks: HashMap::new(),
            rib_rx,
            ctx,
            links: BTreeMap::new(),
            bfd: OspfLinkBfdConfig::default(),
            areas: OspfAreaMap::new(),
            show: ShowChannel::new(),
            show_cb: HashMap::new(),
            router_id: DEFAULT_ROUTER_ID,
            router_id_config: None,
            rib_router_id: None,
            lsdb_as: Lsdb::new(),
            lsp_map: LspMap::default(),
            spf_result: None,
            graph: None,
            ti_lfa_enabled: false,
            ti_lfa_compute_mode: spf::TilfaComputeModeConfig::default(),
            // Matches the YANG `default 8` on the sharding `shards` leaf.
            ti_lfa_compute_shards: 8,
            tilfa_stats: None,
            fast_reroute_backup_as_primary: false,
            tilfa_result: None,
            spf_flex_algo: BTreeMap::new(),
            rib_flex_algo: BTreeMap::new(),
            rib6_flex_algo: BTreeMap::new(),
            rib: PrefixMap::new(),
            rib_areas: BTreeMap::new(),
            spf_results: BTreeMap::new(),
            ilm: BTreeMap::new(),
            ilm6: BTreeMap::new(),
            local_pool: None,
            lan_adj_sids: BTreeMap::new(),
            rib6: PrefixMap::new(),
            rib6_areas: BTreeMap::new(),
            tracing: OspfTracing::default(),
            segment_routing: super::srmpls::SegmentRoutingMode::default(),
            srv6_locator_name: None,
            watched_locator: None,
            sr_locator: None,
            sr_end_sid: None,
            elib: crate::isis::srv6::ElibPool::new(),
            endx_sids: BTreeMap::new(),
            sr_rx,
            gr_config: super::neigh::GracefulRestartConfig::default(),
            restarting: None,
            key_chains: BTreeMap::new(),
            policy_tx,
            policy_rx: policy_chan.rx,
            spf_last: None,
            spf_duration: None,
            redist_v4: BTreeMap::new(),
            redist_v6: BTreeMap::new(),
            redist: BTreeMap::new(),
            redist_originated: BTreeMap::new(),
            redist_originated_v6: BTreeMap::new(),
            flex_algo: crate::flex_algo::FlexAlgoConfig::new(Ospfv2::FLEX_ALGO_PREFIX),
            affinity_map: crate::flex_algo::AffinityMap::new(),
            srlg_config: crate::flex_algo::SrlgGroupBuilder::new(),
            srlg_groups: BTreeMap::new(),
            sock,
            v3_send_tx: None,
            v3_recv_rx: None,
            proto_label,
            rib_subscriber,
            config_tx,
            vrf_log: BTreeMap::new(),
            vrf_registry: BTreeMap::new(),
            rib_known_vrfs: BTreeMap::new(),
            bfd_client_tx,
            bfd_event_tx,
            bfd_event_rx,
            stamp_client_tx,
            stamp_event_tx,
            stamp_event_rx,
        };
        ospf.callback_build();
        ospf.show_build();

        // If a fresh graceful-restart checkpoint is on disk, replay
        // the saved state into this instance + enter restarting mode
        // so we don't cold-start over a planned restart. Only the
        // default instance loads it — the on-disk path is keyed by a
        // fixed proto name (`ospf.cbor`), so a per-VRF child must not
        // restore the default instance's state.
        if ospf.proto_label == "ospf" {
            ospf.gr_restart_load_checkpoint();
        }

        ospf.tracing.proto = Ospfv2::PROTO;

        let tx = ospf.tx.clone();
        let sock = ospf.sock.clone();
        tokio::spawn(async move {
            read_packet(sock, tx).await;
        });
        let sock = ospf.sock.clone();
        tokio::spawn(async move {
            write_packet(sock, prx).await;
        });
        ospf
    }

    pub fn process_cm_msg(&mut self, msg: ConfigRequest) {
        // CommitEnd: fan out to per-VRF children (run their reconcile)
        // and prune any whose `router ospf vrf <name>` block was fully
        // deleted, then apply this instance's own flex-algo / affinity
        // / SRLG staging (mirrors IS-IS).
        if msg.op == ConfigOp::CommitEnd {
            self.vrf_commit_end();
            self.commit_flex_algo_tables();
            return;
        }

        // Dynamic tab-completion (`ext:dynamic "ospf:<handler>"`): the
        // manager sends the handler name as the sole path segment and
        // waits on `msg.resp` for the candidate list. Answer directly —
        // these are instance-level, not VRF-scoped.
        if msg.op == ConfigOp::Completion {
            let (path, _) = path_from_command(&msg.paths);
            let comps = match path.as_str() {
                "/neighbor" => self.neighbor_comps(),
                _ => Vec::new(),
            };
            if let Some(resp) = msg.resp {
                let _ = resp.send(comps);
            }
            return;
        }

        // `/router/ospf/vrf/<name>/...` belongs to a per-VRF child, not
        // the default instance. Strip the `vrf <name>` selector and
        // buffer + forward the rewritten line; never dispatch it through
        // the default instance's own callback table. Anchored to `router
        // ospf` (see `vrf_config_split`): the manager broadcasts every
        // committed line to every protocol, so a generic match would
        // otherwise spawn a phantom child for the top-level `/vrf/<name>`
        // list or for another protocol's `router <other> vrf <name>`.
        if let Some((name, rewritten)) = vrf_config_split("ospf", &msg.paths) {
            self.vrf_config_record(name, rewritten, msg.op);
            return;
        }

        let (path, mut args) = path_from_command(&msg.paths);

        // Clear ops bypass the YANG callback table — they map
        // straight to runtime side-effects (kick SPF, drop a peer,
        // ...) the way `clear ip bgp` works in BGP. Other op-codes
        // continue through the Set/Delete dispatch below.
        if msg.op == ConfigOp::Clear {
            if path == "/clear/ospf/spf" {
                self.clear_spf();
            } else if path == "/clear/ospf/checkpoint/write" {
                self.checkpoint_write_debug();
            } else if path == "/clear/ospf/checkpoint/clear" {
                self.checkpoint_clear_debug();
            } else if path == "/clear/ospf/graceful-restart/begin" {
                // Default to 120s / SoftwareRestart; YANG-side
                // optional args (period, reason) land alongside
                // the restart-aware boot path.
                let _ = self.gr_restart_begin(120, GraceRestartReason::SoftwareRestart);
            } else if path == "/clear/ospf/graceful-restart/abort" {
                self.gr_restart_abort();
            } else if path == "/clear/ospf/graceful-restart/commit" {
                let _ = self.gr_restart_commit();
            } else if path == "/clear/ospf/neighbor" {
                // `clear ospf neighbor [<addr>]` — the bare form
                // resets every adjacency; a trailing address resets
                // only the neighbor at that interface IP (the v2
                // `nbrs` map key). Empty args -> v4addr() is None.
                self.clear_neighbor(args.v4addr());
            }
            return;
        }

        // Flex-algo definitions (`/router/ospf/flex-algo`) and the
        // global `/affinity-map` / `/srlg` tables stage into their
        // builders here and apply at CommitEnd; the registry callbacks
        // below don't cover them.
        if path.starts_with(Ospfv2::FLEX_ALGO_PREFIX)
            || path.starts_with("/affinity-map")
            || path.starts_with("/srlg/group")
        {
            self.flex_algo_table_exec(path, args, msg.op);
            return;
        }

        if let Some(f) = self.callbacks.get(&path) {
            f(self, args, msg.op);
        } else {
            // `/router/ospf/tracing/...` is not in the callback table —
            // its message-type names are YANG presence containers, so a
            // single subtree dispatcher parses the path tail. Returns
            // `None` (ignored) for any other unmatched path.
            super::tracing::config_tracing_dispatch(self, &path, args, msg.op);
        }
    }

    /// Force-recalculate the OSPFv2 SPF for every attached area.
    /// Mirrors FRR's `clear ip ospf process` SPF-side effect:
    /// useful when manual diagnosis suspects a stuck route after
    /// an LSDB-side fix and the operator does not want to wait
    /// for the 1-second coalescing timer.
    fn clear_spf(&mut self) {
        let area_ids: Vec<Ipv4Addr> = self.areas.iter().map(|(id, _)| *id).collect();
        for id in area_ids {
            let _ = self.tx.send(Message::SpfCalc(id));
        }
    }

    /// Debug entry — capture the current instance state and
    /// atomically write a checkpoint to disk. Grace period +
    /// reason are placeholders (60s / SoftwareRestart) since this
    /// path isn't an actual restart.
    fn checkpoint_write_debug(&mut self) {
        use super::checkpoint::{OspfCheckpoint, default_path};

        let cp = OspfCheckpoint::from_instance(self, 60, 1);
        let path = default_path("ospf");
        match cp.write_to_path(&path) {
            Ok(()) => tracing::info!(
                "[Checkpoint] wrote {} areas, {} links to {}",
                cp.areas.len(),
                cp.links.len(),
                path.display()
            ),
            Err(e) => tracing::warn!("[Checkpoint] write to {} failed: {}", path.display(), e),
        }
    }

    /// Debug entry — delete the on-disk checkpoint. Idempotent.
    fn checkpoint_clear_debug(&mut self) {
        use super::checkpoint::{OspfCheckpoint, default_path};

        let path = default_path("ospf");
        match OspfCheckpoint::delete(&path) {
            Ok(()) => tracing::info!("[Checkpoint] cleared {}", path.display()),
            Err(e) => tracing::warn!("[Checkpoint] clear {} failed: {}", path.display(), e),
        }
    }

    fn ospf_spf_timer(tx: &UnboundedSender<Message>, area_id: Ipv4Addr) -> Timer {
        Self::ospf_spf_timer_generic(tx, area_id)
    }

    fn ospf_spf_schedule(tx: &UnboundedSender<Message>, area: &mut OspfArea) {
        if area.spf_timer.is_none() {
            area.spf_timer = Some(Self::ospf_spf_timer(tx, area.id));
        }
    }

    fn router_lsa_stub_link(prefix: Ipv4Net, metric: u16) -> RouterLsaLink {
        RouterLsaLink {
            link_id: prefix.network(),
            link_data: prefix.netmask(),
            link_type: OspfLinkType::Stub,
            num_tos: 0,
            tos_0_metric: metric,
            toses: vec![],
        }
    }

    fn link_has_transit_adjacency(link: &OspfLink) -> bool {
        if link.state == IfsmState::Waiting || link.full_nbr_count == 0 {
            return false;
        }
        if Ospfv2::is_declared_dr(&link.ident) {
            return true;
        }
        if let Some(dr_nbr) = link.nbrs.get(&link.ident.d_router) {
            return dr_nbr.state == NfsmState::Full;
        }
        false
    }

    /// Build the v2 Router-LSA body from current interface + neighbor
    /// state.
    ///
    /// GR-helper invariant (RFC 3623 §3.1): adjacencies to neighbors
    /// in helper mode must keep appearing in this LSA exactly as
    /// they did when the link was Full. The inactivity-timer
    /// suppression in `ospf_nfsm_inactivity_timer` keeps `nbr.state`
    /// stuck at `Full` while we're helping, so the `state ==
    /// NfsmState::Full` filters below honour the invariant
    /// implicitly — do not switch them to a tighter "still receiving
    /// Hellos" check without re-establishing equivalence here.
    /// Build the Router-LSA this router originates into `area_id`.
    /// RFC 2328 §12.4.1: a router that belongs to several areas
    /// originates a separate Router-LSA into each, listing only the
    /// links that attach to that area. The caller
    /// (`router_lsa_originate_with_min_seq`) loops over every attached
    /// area; here we just filter `self.links` down to `area_id`.
    fn router_lsa_build(&self, area_id: Ipv4Addr) -> RouterLsa {
        let mut router_lsa = RouterLsa::default();

        // RFC 2328 §A.4.2 / RFC 3101 §3.1 Router-LSA flags:
        //   bit 0 (0x01) — B: this router is an ABR
        //   bit 1 (0x02) — E: this router is an ASBR
        //   bit 4 (0x10) — Nt: this router is an NSSA translator
        // B-bit goes in the LSA we originate into every area we're
        // attached to; Candidate election (in
        // `is_nssa_translator_for`) reads other routers' B-bits out
        // of NSSA Router-LSAs to pick the elected translator.
        //
        // Nt-bit is still intentionally NOT set here. Per-area
        // emission now lands (this LSA is scoped to `area_id`), so the
        // bit *could* be stamped on the NSSA-scoped copy, but election
        // is locally-computed across all OSPF implementations, so
        // omitting it stays interop-safe; wiring the Nt-bit is left to
        // the NSSA-translator work.
        if self.is_abr() {
            router_lsa.flags |= 0x0001;
        }
        if self.is_asbr() {
            router_lsa.flags |= 0x0002;
        }

        for link in self.links.values() {
            if !link.enabled {
                continue;
            }
            // Only this area's links belong in this area's Router-LSA.
            if link.area_id != area_id {
                continue;
            }

            // RFC 2328 §12.4.1.1 leaves the loopback stub metric as
            // "the configured cost of the interface", but FRR and
            // Juniper Junos hardcode 0 by convention (Cisco uses 1).
            // Stamping the regular `output_cost` (default 10) on a
            // loopback /32 inflates downstream route metrics by a
            // phantom hop. Match the FRR/Junos convention.
            let metric = if link.link_flags.is_loopback() {
                0
            } else {
                link.output_cost.min(u16::MAX as u32) as u16
            };

            // RFC 2328 §12.4.1.1, numbered point-to-point: one Type-1
            // P2p link per Full neighbor (pointing at the neighbor's
            // router-id, link_data = our interface address), plus a
            // Type-3 Stub for the local /N. With no Full neighbor we
            // fall through to Stub-only, which keeps the local prefix
            // advertised even while the adjacency is still forming.
            if link.is_pointopoint() {
                for addr in &link.addr {
                    if addr.prefix.addr().octets()[0] == 127 {
                        continue;
                    }
                    for nbr in link.nbrs.values() {
                        if nbr.state != NfsmState::Full {
                            continue;
                        }
                        router_lsa.links.push(RouterLsaLink {
                            link_id: nbr.ident.router_id,
                            link_data: addr.prefix.addr(),
                            link_type: OspfLinkType::P2p,
                            num_tos: 0,
                            tos_0_metric: metric,
                            toses: vec![],
                        });
                    }
                    router_lsa
                        .links
                        .push(Self::router_lsa_stub_link(addr.prefix, metric));
                }
                continue;
            }

            let use_transit = matches!(
                link.network_type,
                OspfNetworkType::Broadcast | OspfNetworkType::NBMA
            ) && Self::link_has_transit_adjacency(link);

            for addr in &link.addr {
                // Skip loopback addresses (127.0.0.0/8).
                if addr.prefix.addr().octets()[0] == 127 {
                    continue;
                }
                let lsa_link = if use_transit {
                    RouterLsaLink {
                        // Transit link points to DR interface address.
                        link_id: link.ident.d_router,
                        link_data: addr.prefix.addr(),
                        link_type: OspfLinkType::Transit,
                        num_tos: 0,
                        tos_0_metric: metric,
                        toses: vec![],
                    }
                } else {
                    Self::router_lsa_stub_link(addr.prefix, metric)
                };
                router_lsa.links.push(lsa_link);
            }
        }

        router_lsa.num_links = router_lsa.links.len() as u16;
        router_lsa
    }

    fn router_lsa_originate_with_min_seq(&mut self, min_seq: Option<u32>) {
        // While restarting, the checkpoint-loaded Router-LSA must
        // stay verbatim (helpers snapshotted its seq+checksum).
        // Fresh re-origination here would clobber it and trip
        // `gr_helper_check_exit`. Skip; the exit-restart path
        // re-originates at seq+1 once we declare the restart
        // complete.
        if self.in_restart() {
            return;
        }
        // RFC 2328 §12.4.1: originate one Router-LSA per attached area
        // (an area is "attached" once it has at least one enabled
        // link). Each carries only that area's links, lives in that
        // area's LSDB, and floods only on that area's interfaces.
        let area_ids: Vec<Ipv4Addr> = self
            .areas
            .iter()
            .filter(|(_, area)| !area.links.is_empty())
            .map(|(id, _)| *id)
            .collect();

        for area_id in area_ids {
            let router_lsa = self.router_lsa_build(area_id);
            let flood_lsa = if let Some(area) = self.areas.get_mut(area_id) {
                let current_seq = area
                    .lsdb
                    .lookup_by_id(OspfLsType::Router, self.router_id, self.router_id)
                    .map(|lsa| lsa.h.ls_seq_number);

                let lsah = OspfLsaHeader::new(OspfLsType::Router, self.router_id, self.router_id);
                let mut lsa = OspfLsa::from(lsah, router_lsa.into());

                if let Some(seq) = current_seq {
                    lsa.h.ls_seq_number = seq_max(lsa.h.ls_seq_number, seq.saturating_add(1));
                }
                if let Some(seq) = min_seq {
                    lsa.h.ls_seq_number = seq_max(lsa.h.ls_seq_number, seq.saturating_add(1));
                }

                lsa.update();
                let flood_lsa = lsa.clone();
                area.lsdb
                    .insert_self_originated(lsa, &self.tx, Some(area_id));
                Self::ospf_spf_schedule(&self.tx, area);
                Some(flood_lsa)
            } else {
                None
            };

            if let Some(lsa) = flood_lsa {
                self.flood_self_originated_lsa(area_id, &lsa);
            }
        }
    }

    pub fn router_lsa_originate(&mut self) {
        tracing::info!("Router LSA Originate");
        self.router_lsa_originate_with_min_seq(None);
    }

    /// RFC 2328 §12.4.3 — an Area Border Router condenses each area's
    /// routing table into Type-3 Summary-LSAs that it floods into the
    /// *other* areas it attaches to, so internal routers learn
    /// inter-area destinations. Driven from `apply_spf_result` after
    /// the per-area route slices (`rib_areas`) are refreshed.
    ///
    /// Loop-safety: we never schedule our own SPF here (a summary we
    /// originate is skipped by our own inter-area route computation,
    /// `add_inter_area_routes`), and origination is diff-gated against
    /// the LSDB, so once the topology converges this re-floods nothing
    /// and terminates — no SPF→summary→SPF cycle.
    pub fn abr_summary_originate(&mut self) {
        if self.in_restart() {
            return;
        }

        // Areas we currently attach to (≥1 enabled link).
        let attached: Vec<Ipv4Addr> = self
            .areas
            .iter()
            .filter(|(_, a)| !a.links.is_empty())
            .map(|(id, _)| *id)
            .collect();

        // Fewer than two areas ⇒ not an ABR. Withdraw any summaries we
        // may have originated earlier (e.g. we just lost an area) by
        // syncing every known area down to an empty desired set.
        if attached.len() < 2 {
            let all: Vec<Ipv4Addr> = self.areas.iter().map(|(id, _)| *id).collect();
            for area_id in all {
                self.abr_summary_sync_area(area_id, &BTreeMap::new());
            }
            return;
        }

        for &area_a in &attached {
            let desired = self.abr_summary_desired(area_a, &attached);
            self.abr_summary_sync_area(area_a, &desired);
        }
    }

    /// Compute the set of `prefix -> metric` Type-3 summaries to
    /// advertise into `area_a`, drawn from the route slices of the
    /// *other* attached areas per RFC 2328 §12.4.3:
    ///   - intra-area routes of any other area are summarized into A;
    ///   - inter-area routes are summarized only from the backbone and
    ///     only into non-backbone areas (loop prevention — inter-area
    ///     routes are never re-injected into area 0, and a non-backbone
    ///     area's inter-area routes are not trusted as a source);
    ///   - a prefix that is already intra-area within A is not
    ///     summarized into A;
    ///   - LSInfinity / external routes are skipped.
    ///
    /// The lowest metric wins when several source areas offer a prefix.
    fn abr_summary_desired(
        &self,
        area_a: Ipv4Addr,
        attached: &[Ipv4Addr],
    ) -> BTreeMap<Ipv4Net, u32> {
        // OSPF metrics are 24-bit; 0xFFFFFF = LSInfinity (unreachable).
        const LS_INFINITY: u32 = 0x00FF_FFFF;

        let mut desired: BTreeMap<Ipv4Net, u32> = BTreeMap::new();

        // Totally-stubby / totally-NSSA areas take no Type-3s except a
        // default route (default origination into stub areas is a
        // follow-up); suppress everything here.
        if self
            .areas
            .get(area_a)
            .map(|a| a.area_type.no_summary)
            .unwrap_or(false)
        {
            return desired;
        }

        for &area_b in attached {
            if area_b == area_a {
                continue;
            }
            let Some(rib_b) = self.rib_areas.get(&area_b) else {
                continue;
            };
            let ranges_b = self
                .areas
                .get(area_b)
                .map(|a| a.ranges.clone())
                .unwrap_or_default();
            // Active ranges of area B this walk: range prefix ->
            // largest component metric (RFC 2328 §12.4.3).
            let mut active_ranges: BTreeMap<Ipv4Net, u32> = BTreeMap::new();
            for (prefix, route) in rib_b.iter() {
                let advertise = match route.path_type {
                    RouteType::IntraArea => true,
                    RouteType::InterArea => area_b == AREA0 && area_a != AREA0,
                    RouteType::External => false,
                };
                if !advertise || route.metric >= LS_INFINITY {
                    continue;
                }
                // Address ranges condense area B's own intra-area
                // routes: a component inside a configured range is
                // never advertised individually — it activates the
                // aggregate instead (most-specific range wins).
                if route.path_type == RouteType::IntraArea {
                    if let Some(range_prefix) = ranges_b
                        .keys()
                        .filter(|r| r.contains(&prefix))
                        .max_by_key(|r| r.prefix_len())
                        .copied()
                    {
                        active_ranges
                            .entry(range_prefix)
                            .and_modify(|m| *m = (*m).max(route.metric))
                            .or_insert(route.metric);
                        continue;
                    }
                }
                // Don't summarize a prefix that A reaches intra-area.
                let intra_in_a = self
                    .rib_areas
                    .get(&area_a)
                    .and_then(|r| r.get(&prefix))
                    .map(|r| r.path_type == RouteType::IntraArea)
                    .unwrap_or(false);
                if intra_in_a {
                    continue;
                }
                let metric = route.metric.min(LS_INFINITY - 1);
                desired
                    .entry(prefix)
                    .and_modify(|m| *m = (*m).min(metric))
                    .or_insert(metric);
            }
            // Fold the aggregates in: an active range advertises one
            // summary at the largest component metric (or the
            // configured cost); `not-advertise` hides it entirely.
            for (range_prefix, max_metric) in active_ranges {
                let Some(entry) = ranges_b.get(&range_prefix) else {
                    continue;
                };
                if entry.not_advertise {
                    continue;
                }
                let intra_in_a = self
                    .rib_areas
                    .get(&area_a)
                    .and_then(|r| r.get(&range_prefix))
                    .map(|r| r.path_type == RouteType::IntraArea)
                    .unwrap_or(false);
                if intra_in_a {
                    continue;
                }
                let metric = entry.cost.unwrap_or(max_metric).min(LS_INFINITY - 1);
                desired
                    .entry(range_prefix)
                    .and_modify(|m| *m = (*m).min(metric))
                    .or_insert(metric);
            }
        }
        desired
    }

    /// Reconcile the self-originated Type-3 LSAs in `area_id`'s LSDB to
    /// match `desired`: flush summaries no longer wanted, (re)originate
    /// new or metric-changed ones, leave unchanged ones untouched
    /// (so a steady state floods nothing).
    fn abr_summary_sync_area(&mut self, area_id: Ipv4Addr, desired: &BTreeMap<Ipv4Net, u32>) {
        use crate::ospf::lsdb::OSPF_MAX_AGE;

        // Snapshot our current self-originated summaries (prefix, metric).
        let current: Vec<(Ipv4Net, u32)> = {
            let Some(area) = self.areas.get(area_id) else {
                return;
            };
            area.lsdb
                .iter_by_type(OspfLsType::Summary)
                .filter(|(_, lsa)| lsa.data.h.adv_router == self.router_id)
                .filter(|(_, lsa)| lsa.data.h.ls_age < OSPF_MAX_AGE)
                .filter_map(|((ls_id, _), lsa)| {
                    let OspfLsp::Summary(ref s) = lsa.data.lsp else {
                        return None;
                    };
                    let mask = u32::from(s.netmask).leading_ones() as u8;
                    Ipv4Net::new(ls_id, mask)
                        .ok()
                        .map(|p| (p.trunc(), s.metric))
                })
                .collect()
        };

        // Flush summaries that are no longer desired.
        for (prefix, _metric) in &current {
            if !desired.contains_key(prefix) {
                self.summary_lsa_flush(area_id, *prefix);
            }
        }

        // Originate the new ones and any whose metric changed.
        for (prefix, metric) in desired {
            let unchanged = current.iter().any(|(p, m)| p == prefix && m == metric);
            if !unchanged {
                self.summary_lsa_originate(area_id, *prefix, *metric);
            }
        }
    }

    /// Originate (or re-originate at seq+1) one Type-3 Summary-LSA for
    /// `prefix`/`metric` into `area_id`, then flood it. Does not touch
    /// SPF — our own routing ignores summaries we originate.
    fn summary_lsa_originate(&mut self, area_id: Ipv4Addr, prefix: Ipv4Net, metric: u32) {
        let ls_id = prefix.network();
        let netmask = prefix.netmask();

        let flood_lsa = if let Some(area) = self.areas.get_mut(area_id) {
            let current_seq = area
                .lsdb
                .lookup_by_id(OspfLsType::Summary, ls_id, self.router_id)
                .map(|lsa| lsa.h.ls_seq_number);

            let lsah = OspfLsaHeader::new(OspfLsType::Summary, ls_id, self.router_id);
            let mut lsa = OspfLsa::from(
                lsah,
                OspfLsp::Summary(SummaryLsa {
                    netmask,
                    tos: 0,
                    metric: metric & 0x00FF_FFFF,
                    tos_routes: vec![],
                }),
            );
            if let Some(seq) = current_seq {
                lsa.h.ls_seq_number = seq_max(lsa.h.ls_seq_number, seq.saturating_add(1));
            }
            lsa.update();
            let flood_lsa = lsa.clone();
            area.lsdb
                .insert_self_originated(lsa, &self.tx, Some(area_id));
            Some(flood_lsa)
        } else {
            None
        };

        if let Some(lsa) = flood_lsa {
            self.flood_self_originated_lsa(area_id, &lsa);
        }
    }

    /// Flush (MaxAge) one self-originated Type-3 Summary-LSA for
    /// `prefix` out of `area_id` and re-flood so neighbors drop it.
    fn summary_lsa_flush(&mut self, area_id: Ipv4Addr, prefix: Ipv4Net) {
        let ls_id = prefix.network();
        let flushed = if let Some(area) = self.areas.get_mut(area_id) {
            area.lsdb.flush_lsa(
                OspfLsType::Summary,
                ls_id,
                self.router_id,
                &self.tx,
                Some(area_id),
            )
        } else {
            None
        };
        if let Some(lsa) = flushed {
            self.flood_self_originated_lsa(area_id, &lsa);
        }
    }

    /// (Re)originate / flush Type-4 Summary-ASBR LSAs for all ASBRs
    /// known to this ABR (RFC 2328 §12.4.3). Called from
    /// `apply_spf_result` alongside `abr_summary_originate`.
    pub fn abr_summary_asbr_originate(&mut self) {
        if self.in_restart() {
            return;
        }

        let attached: Vec<Ipv4Addr> = self
            .areas
            .iter()
            .filter(|(_, a)| !a.links.is_empty())
            .map(|(id, _)| *id)
            .collect();

        if attached.len() < 2 {
            let all: Vec<Ipv4Addr> = self.areas.iter().map(|(id, _)| *id).collect();
            for area_id in all {
                self.abr_summary_asbr_sync_area(area_id, &BTreeMap::new());
            }
            return;
        }

        for &area_a in &attached {
            let desired = self.abr_summary_asbr_desired(area_a, &attached);
            self.abr_summary_asbr_sync_area(area_a, &desired);
        }
    }

    /// Compute the `asbr_router_id → metric` map of Type-4 LSAs to
    /// advertise into `area_a`. Walks all other attached areas and
    /// checks each router vertex for the E-bit (ASBR flag) in its
    /// Router-LSA. The ABR's SPF cost to that vertex (from the
    /// per-area SPF result) becomes the Type-4 metric.
    fn abr_summary_asbr_desired(
        &self,
        area_a: Ipv4Addr,
        attached: &[Ipv4Addr],
    ) -> BTreeMap<Ipv4Addr, u32> {
        const E_BIT: u16 = 0x0002;
        const LS_INFINITY: u32 = 0x00FF_FFFF;

        let mut desired: BTreeMap<Ipv4Addr, u32> = BTreeMap::new();

        for &area_b in attached {
            if area_b == area_a {
                continue;
            }
            let Some(spf_b) = self.spf_results.get(&area_b) else {
                continue;
            };
            let Some(area_b_ref) = self.areas.get(area_b) else {
                continue;
            };
            // Walk all Router-LSAs in area B; if E-bit set → ASBR.
            for ((_ls_id, _adv), lsa) in area_b_ref.lsdb.iter_by_type(OspfLsType::Router) {
                let OspfLsp::Router(ref body) = lsa.data.lsp else {
                    continue;
                };
                if (body.flags & E_BIT) == 0 {
                    continue;
                }
                let asbr_id = lsa.data.h.adv_router;
                if asbr_id == self.router_id {
                    continue;
                }
                let Some(vertex) = self.lsp_map.lookup(asbr_id) else {
                    continue;
                };
                let Some(path) = spf_b.get(&vertex) else {
                    continue;
                };
                let metric = path.cost.min(LS_INFINITY - 1);
                desired
                    .entry(asbr_id)
                    .and_modify(|m| *m = (*m).min(metric))
                    .or_insert(metric);
            }
        }
        desired
    }

    /// Reconcile self-originated Type-4 LSAs in `area_id` against `desired`.
    fn abr_summary_asbr_sync_area(&mut self, area_id: Ipv4Addr, desired: &BTreeMap<Ipv4Addr, u32>) {
        use crate::ospf::lsdb::OSPF_MAX_AGE;

        let current: Vec<(Ipv4Addr, u32)> = {
            let Some(area) = self.areas.get(area_id) else {
                return;
            };
            area.lsdb
                .iter_by_type(OspfLsType::SummaryAsbr)
                .filter(|(_, lsa)| lsa.data.h.adv_router == self.router_id)
                .filter(|(_, lsa)| lsa.data.h.ls_age < OSPF_MAX_AGE)
                .filter_map(|((ls_id, _), lsa)| {
                    let OspfLsp::Summary(ref s) = lsa.data.lsp else {
                        return None;
                    };
                    Some((ls_id, s.metric))
                })
                .collect()
        };

        for (asbr_id, _) in &current {
            if !desired.contains_key(asbr_id) {
                self.summary_asbr_lsa_flush(area_id, *asbr_id);
                if let Some(area) = self.areas.get_mut(area_id) {
                    area.asbr_summaries_originated.remove(asbr_id);
                }
            }
        }

        for (asbr_id, metric) in desired {
            let unchanged = current.iter().any(|(id, m)| id == asbr_id && m == metric);
            if !unchanged {
                self.summary_asbr_lsa_originate(area_id, *asbr_id, *metric);
                if let Some(area) = self.areas.get_mut(area_id) {
                    area.asbr_summaries_originated.insert(*asbr_id);
                }
            }
        }
    }

    /// Originate (or refresh) one Type-4 Summary-ASBR LSA for `asbr_id`
    /// into `area_id`. Uses the same SummaryLsa body as Type-3 but with
    /// `ls_type = SummaryAsbr`, `netmask = 0.0.0.0`, and
    /// `ls_id = asbr_id` (RFC 2328 §12.4.3).
    fn summary_asbr_lsa_originate(&mut self, area_id: Ipv4Addr, asbr_id: Ipv4Addr, metric: u32) {
        let flood_lsa = if let Some(area) = self.areas.get_mut(area_id) {
            let current_seq = area
                .lsdb
                .lookup_by_id(OspfLsType::SummaryAsbr, asbr_id, self.router_id)
                .map(|lsa| lsa.h.ls_seq_number);

            let lsah = OspfLsaHeader::new(OspfLsType::SummaryAsbr, asbr_id, self.router_id);
            let mut lsa = OspfLsa::from(
                lsah,
                OspfLsp::Summary(SummaryLsa {
                    netmask: Ipv4Addr::UNSPECIFIED,
                    tos: 0,
                    metric: metric & 0x00FF_FFFF,
                    tos_routes: vec![],
                }),
            );
            if let Some(seq) = current_seq {
                lsa.h.ls_seq_number = seq_max(lsa.h.ls_seq_number, seq.saturating_add(1));
            }
            lsa.update();
            let flood_lsa = lsa.clone();
            area.lsdb
                .insert_self_originated(lsa, &self.tx, Some(area_id));
            Some(flood_lsa)
        } else {
            None
        };
        if let Some(lsa) = flood_lsa {
            self.flood_self_originated_lsa(area_id, &lsa);
        }
    }

    /// Flush one self-originated Type-4 Summary-ASBR LSA for `asbr_id`
    /// from `area_id`.
    fn summary_asbr_lsa_flush(&mut self, area_id: Ipv4Addr, asbr_id: Ipv4Addr) {
        let flushed = if let Some(area) = self.areas.get_mut(area_id) {
            area.lsdb.flush_lsa(
                OspfLsType::SummaryAsbr,
                asbr_id,
                self.router_id,
                &self.tx,
                Some(area_id),
            )
        } else {
            None
        };
        if let Some(lsa) = flushed {
            self.flood_self_originated_lsa(area_id, &lsa);
        }
    }

    pub fn router_info_lsa_originate(&mut self) {
        use super::srmpls::SegmentRoutingMode;

        let ls_id = Ipv4Addr::from((OpaqueLsaType::ROUTER_INFO as u32) << 24);

        if self.segment_routing == SegmentRoutingMode::Mpls {
            let gr_capable = self.restarting.is_some();
            let algos = crate::flex_algo::sr_algorithms(&self.flex_algo);
            let fads =
                super::flex_algo::build_fad(&self.flex_algo, &self.affinity_map, &self.srlg_groups);
            let mut lsa =
                super::srmpls::router_info_lsa_build(self.router_id, gr_capable, algos, fads);

            // Preserve sequence number if re-originating.
            if let Some(area) = self.areas.get(AREA0)
                && let Some(existing) =
                    area.lsdb
                        .lookup_by_id(OspfLsType::OpaqueAreaLocal, ls_id, self.router_id)
            {
                lsa.h.ls_seq_number = seq_max(
                    lsa.h.ls_seq_number,
                    existing.h.ls_seq_number.saturating_add(1),
                );
            }
            lsa.update();

            let flood_lsa = lsa.clone();
            if let Some(area) = self.areas.get_mut(AREA0) {
                area.lsdb.insert_self_originated(lsa, &self.tx, Some(AREA0));
            }
            self.flood_self_originated_lsa(AREA0, &flood_lsa);
        } else {
            // Flush Router Info LSA when SR is disabled.
            let flushed = if let Some(area) = self.areas.get_mut(AREA0) {
                area.lsdb.flush_lsa(
                    OspfLsType::OpaqueAreaLocal,
                    ls_id,
                    self.router_id,
                    &self.tx,
                    Some(AREA0),
                )
            } else {
                None
            };
            if let Some(lsa) = flushed {
                self.flood_self_originated_lsa(AREA0, &lsa);
            }
        }
    }

    /// Originate (or flush) the Extended-Link Opaque LSA for `ifindex`.
    ///
    /// Originates when SR-MPLS is enabled, the link is enabled, has at
    /// least one Full neighbor, and either of:
    ///   * P2P link — one `AdjSidSubTlv` carrying the configured
    ///     `adjacency_sid` or, when none is configured, the SRLB
    ///     label dynamically allocated on the Full transition
    ///     (advertised as a local V|L Adj-SID, IS-IS parity).
    ///   * Broadcast / NBMA link with a known DR and at least one
    ///     entry in `lan_adj_sids` — one `LanAdjSidSubTlv` per Full
    ///     neighbor that has a label allocated, per RFC 8665 §6.
    ///
    /// Flushes (MaxAge) otherwise.
    ///
    /// The opaque-id is derived from the ifindex (same convention as
    /// `ext_prefix_lsa_originate`) so the per-link LSA gets a stable
    /// `ls_id` across re-originations.
    pub fn ext_link_lsa_originate(&mut self, ifindex: u32) {
        use super::link::OspfNetworkType;
        use super::srmpls::SegmentRoutingMode;

        let opaque_id = ifindex & 0x00FF_FFFF;
        let ls_id = Ipv4Addr::from(((OpaqueLsaType::EXT_LINK as u32) << 24) | opaque_id);

        // Build the (link_type, link_id, link_data, subs) tuple if
        // origination is warranted, otherwise fall through to the
        // flush path. Returning `Option` keeps the borrow on `self`
        // confined to this block so the install / flood code below can
        // mutate `self.areas`.
        let build_inputs = if self.segment_routing == SegmentRoutingMode::Mpls
            && let Some(link) = self.links.get(&ifindex)
            && link.enabled
            && link.nbrs.values().any(|n| n.state == NfsmState::Full)
            && let Some(addr) = link.addr.iter().find(|a| !a.prefix.addr().is_loopback())
        {
            let our_addr = addr.prefix.addr();
            // Per-link ASLA carrying this link's flex-algo affinity
            // (RFC 9492 / RFC 9350 §6.3) and the RFC 7471 TE metrics,
            // independent of Adj-SID: a link with affinity or TE
            // metrics but no Adj-SID still originates an Extended-Link
            // LSA so peers can run the FAD constraints / read the
            // metrics. The metrics are the static-over-measured merge:
            // STAMP measurement fills any field the operator left
            // unconfigured.
            let asla = super::flex_algo::build_link_asla(
                &link.config.affinity,
                &self.affinity_map,
                link.te_metric_effective().asla_sub_subs(),
            );
            match link.network_type {
                OspfNetworkType::PointToPoint => {
                    if let Some(nbr) = link.nbrs.values().find(|n| n.state == NfsmState::Full) {
                        let mut subs = Vec::new();
                        if let Some(adjacency_sid) = link.config.adjacency_sid {
                            subs.push(super::srmpls::build_p2p_adj_sub(&adjacency_sid));
                        } else if let Some(label) =
                            self.lan_adj_sids.get(&(ifindex, nbr.ident.prefix.addr()))
                        {
                            // Dynamic SRLB Adj-SID fallback — see the
                            // v3 sibling in `e_router_v3_lsa_originate`.
                            subs.push(super::srmpls::build_p2p_adj_sub(
                                &super::link::AdjacencySid::Absolute(*label),
                            ));
                        }
                        if let Some(asla) = asla {
                            subs.push(asla);
                        }
                        if subs.is_empty() {
                            None
                        } else {
                            Some((1u8, nbr.ident.router_id, our_addr, subs))
                        }
                    } else {
                        None
                    }
                }
                OspfNetworkType::Broadcast | OspfNetworkType::NBMA => {
                    let dr = link.ident.d_router;
                    if dr.is_unspecified() {
                        // DR election not yet settled. Fall through to
                        // the flush path so we don't keep a stale LSA
                        // pointing at a `link_id` we can no longer name.
                        None
                    } else {
                        let mut subs: Vec<_> = link
                            .nbrs
                            .values()
                            .filter(|n| n.state == NfsmState::Full)
                            .filter_map(|nbr| {
                                let label =
                                    *self.lan_adj_sids.get(&(ifindex, nbr.ident.prefix.addr()))?;
                                Some(super::srmpls::build_lan_adj_sub(nbr.ident.router_id, label))
                            })
                            .collect();
                        if let Some(asla) = asla {
                            subs.push(asla);
                        }
                        if subs.is_empty() {
                            // No Adj-SID labels and no affinity yet.
                            None
                        } else {
                            Some((2u8, dr, our_addr, subs))
                        }
                    }
                }
            }
        } else {
            None
        };

        if let Some((link_type, link_id, link_data, subs)) = build_inputs {
            let mut lsa = super::srmpls::ext_link_lsa_build(
                self.router_id,
                link_type,
                link_id,
                link_data,
                subs,
                opaque_id,
            );

            if let Some(area) = self.areas.get(AREA0)
                && let Some(existing) =
                    area.lsdb
                        .lookup_by_id(OspfLsType::OpaqueAreaLocal, ls_id, self.router_id)
            {
                lsa.h.ls_seq_number = seq_max(
                    lsa.h.ls_seq_number,
                    existing.h.ls_seq_number.saturating_add(1),
                );
            }
            lsa.update();

            let flood_lsa = lsa.clone();
            if let Some(area) = self.areas.get_mut(AREA0) {
                area.lsdb.insert_self_originated(lsa, &self.tx, Some(AREA0));
            }
            self.flood_self_originated_lsa(AREA0, &flood_lsa);
        } else {
            let flushed = if let Some(area) = self.areas.get_mut(AREA0) {
                area.lsdb.flush_lsa(
                    OspfLsType::OpaqueAreaLocal,
                    ls_id,
                    self.router_id,
                    &self.tx,
                    Some(AREA0),
                )
            } else {
                None
            };
            if let Some(lsa) = flushed {
                self.flood_self_originated_lsa(AREA0, &lsa);
            }
        }
    }

    pub fn ext_prefix_lsa_originate(&mut self, ifindex: u32) {
        use super::srmpls::SegmentRoutingMode;

        let opaque_id = ifindex & 0x00FF_FFFF;
        let ls_id = Ipv4Addr::from(((OpaqueLsaType::EXT_PREFIX as u32) << 24) | opaque_id);

        let link = self.links.get(&ifindex);
        let should_originate = self.segment_routing == SegmentRoutingMode::Mpls
            && link.is_some_and(|l| {
                l.enabled
                    && (l.config.prefix_sid.is_some() || !l.config.flex_algo_prefix_sids.is_empty())
            });

        if should_originate {
            let link = link.unwrap();
            // Use the first non-loopback address as a /32 host prefix.
            let Some(addr) = link.addr.iter().find(|a| !a.prefix.addr().is_loopback()) else {
                return;
            };
            let prefix = ipnet::Ipv4Net::new(addr.prefix.addr(), 32).unwrap_or(addr.prefix);

            let mut lsa = super::srmpls::ext_prefix_lsa_build(
                self.router_id,
                prefix,
                link.config.prefix_sid.as_ref(),
                &link.config.flex_algo_prefix_sids,
                opaque_id,
            );

            // Preserve sequence number if re-originating.
            if let Some(area) = self.areas.get(AREA0)
                && let Some(existing) =
                    area.lsdb
                        .lookup_by_id(OspfLsType::OpaqueAreaLocal, ls_id, self.router_id)
            {
                lsa.h.ls_seq_number = seq_max(
                    lsa.h.ls_seq_number,
                    existing.h.ls_seq_number.saturating_add(1),
                );
            }
            lsa.update();

            let flood_lsa = lsa.clone();
            if let Some(area) = self.areas.get_mut(AREA0) {
                area.lsdb.insert_self_originated(lsa, &self.tx, Some(AREA0));
            }
            self.flood_self_originated_lsa(AREA0, &flood_lsa);
        } else {
            // Flush Extended Prefix LSA when SR is disabled or prefix-sid removed.
            let flushed = if let Some(area) = self.areas.get_mut(AREA0) {
                area.lsdb.flush_lsa(
                    OspfLsType::OpaqueAreaLocal,
                    ls_id,
                    self.router_id,
                    &self.tx,
                    Some(AREA0),
                )
            } else {
                None
            };
            if let Some(lsa) = flushed {
                self.flood_self_originated_lsa(AREA0, &lsa);
            }
        }
    }

    /// Generic Type-7 NSSA-AS-External originator. Builds a Type-7
    /// LSA for `prefix` and installs it in `area_id`'s LSDB.
    ///
    /// `prefix` carries both the network address and mask; ls_id is
    /// the prefix's network address (RFC 2328 §12.4.4 inherited by
    /// RFC 3101). `metric_type_2 = true` sets the E-bit (E2 — metric
    /// dominant over SPF cost); false = E1 (added to SPF cost on the
    /// receiver). `fwd_addr = 0.0.0.0` defers FA-based path
    /// selection on the receiver; RFC 3101 §2.5 step 5 FA
    /// resolution lands in a follow-up.
    ///
    /// Caller is responsible for gating on area type / config; this
    /// helper does not check whether origination is appropriate. The
    /// per-prefix entry points
    /// (`nssa_default_lsa_originate`,
    ///  `nssa_redist_connected_originate_one`) own the policy
    /// decision before invoking this builder.
    fn nssa_lsa_originate_for_prefix(
        &mut self,
        area_id: Ipv4Addr,
        prefix: Ipv4Net,
        metric: u32,
        metric_type_2: bool,
        fwd_addr: Ipv4Addr,
    ) {
        let ls_id = prefix.network();
        let mut lsa_header = OspfLsaHeader::new(OspfLsType::NssaAsExternal, ls_id, self.router_id);
        // RFC 3101 §2.4 LSA-header Options on a Type-7: the E-bit MUST
        // be clear (NSSA areas can't carry Type-5) and the O-bit is
        // set. The N/P-bit (mask 0x08) is the *Propagate* bit in a
        // Type-7 header — the very same wire bit the Hello/DBD options
        // field calls "N". Set, it asks an NSSA ABR to translate this
        // LSA into a Type-5; a pure NSSA ASBR sets it. An ABR clears
        // it on its *own* Type-7s so that a peer ABR in the same NSSA
        // never re-translates them (RFC 3101 §3.2) — which also keeps
        // an ABR-originated default-LSA from leaking into the backbone.
        let propagate = !self.is_abr();
        let mut options = OspfOptions::default();
        options.set_nssa(propagate);
        options.set_o(true);
        lsa_header.options = u8::from(options);

        let body = NssaAsExternalLsa {
            netmask: prefix.netmask(),
            ext_and_tos: if metric_type_2 { 0x80 } else { 0x00 },
            metric,
            forwarding_address: fwd_addr,
            external_route_tag: 0,
            tos_list: Vec::new(),
        };
        let mut lsa = OspfLsa::from(lsa_header, OspfLsp::NssaAsExternal(body));

        // Preserve sequence number if re-originating.
        if let Some(area) = self.areas.get(area_id)
            && let Some(existing) =
                area.lsdb
                    .lookup_by_id(OspfLsType::NssaAsExternal, ls_id, self.router_id)
        {
            lsa.h.ls_seq_number = seq_max(
                lsa.h.ls_seq_number,
                existing.h.ls_seq_number.saturating_add(1),
            );
        }
        lsa.update();

        let flood_lsa = lsa.clone();
        if let Some(area) = self.areas.get_mut(area_id) {
            area.lsdb
                .insert_self_originated(lsa, &self.tx, Some(area_id));
        }
        self.flood_self_originated_lsa(area_id, &flood_lsa);
    }

    /// Flush a single self-originated Type-7 LSA from `area_id`
    /// keyed by `prefix.network()` as ls_id. No-op if the area or
    /// LSA doesn't exist.
    fn nssa_lsa_flush_for_prefix(&mut self, area_id: Ipv4Addr, prefix: Ipv4Net) {
        let ls_id = prefix.network();
        let flushed = if let Some(area) = self.areas.get_mut(area_id) {
            area.lsdb.flush_lsa(
                OspfLsType::NssaAsExternal,
                ls_id,
                self.router_id,
                &self.tx,
                Some(area_id),
            )
        } else {
            None
        };
        if let Some(lsa) = flushed {
            self.flood_self_originated_lsa(area_id, &lsa);
        }
    }

    /// Originate a single Type-5 AS-External LSA for `prefix` and
    /// install it in `lsdb_as`. `metric_type_2 = true` sets the E-bit
    /// (E2); clear = E1. Forwarding address is always 0.0.0.0 (FA=0 →
    /// consumers use the SPF path to this ASBR). Floods AS-wide.
    fn as_external_lsa_originate_for_prefix(
        &mut self,
        prefix: Ipv4Net,
        metric: u32,
        metric_type_2: bool,
    ) {
        use ospf_packet::OspfOptions;

        let ls_id = prefix.network();
        let mut header = OspfLsaHeader::new(OspfLsType::AsExternal, ls_id, self.router_id);
        let mut options = OspfOptions::default();
        options.set_external(true);
        options.set_o(true);
        header.options = u8::from(options);

        let body = AsExternalLsa {
            netmask: prefix.netmask(),
            ext_and_resvd: if metric_type_2 { 0x80 } else { 0x00 },
            metric,
            forwarding_address: Ipv4Addr::UNSPECIFIED,
            external_route_tag: 0,
            tos_list: vec![],
        };
        let mut lsa = OspfLsa::from(header, OspfLsp::AsExternal(body));

        if let Some(existing) =
            self.lsdb_as
                .lookup_by_id(OspfLsType::AsExternal, ls_id, self.router_id)
        {
            lsa.h.ls_seq_number = seq_max(
                lsa.h.ls_seq_number,
                existing.h.ls_seq_number.saturating_add(1),
            );
        }
        lsa.update();

        let flood_lsa = lsa.clone();
        self.lsdb_as.insert_self_originated(lsa, &self.tx, None);
        self.flood_lsa_through_as(&flood_lsa, None);
    }

    /// Flush our self-originated Type-5 AS-External LSA for `prefix`
    /// from `lsdb_as`. No-op if no such LSA exists.
    fn as_external_lsa_flush_for_prefix(&mut self, prefix: Ipv4Net) {
        let ls_id = prefix.network();
        if let Some(flushed) = self.lsdb_as.flush_lsa(
            OspfLsType::AsExternal,
            ls_id,
            self.router_id,
            &self.tx,
            None,
        ) {
            self.flood_lsa_through_as(&flushed, None);
        }
    }

    /// Rebuild self-originated Type-5 AS-External LSAs for one
    /// instance-level `redistribute <source>` knob from `redist_v4`.
    /// Idempotent: originates missing, refreshes changed, flushes stale.
    /// Generic over the source — connected, static, kernel, isis, and
    /// bgp all share this body; for a per-VRF instance the bgp source
    /// carries the VPNv4 routes BGP imported into the VRF (the L3VPN
    /// PE-CE down direction).
    pub fn as_external_redist_resync(&mut self, rtype: crate::rib::RibType) {
        let entry = self.redist.get(&rtype).copied();
        let prev_originated = self
            .redist_originated
            .get(&rtype)
            .cloned()
            .unwrap_or_default();

        let desired: BTreeSet<Ipv4Net> = if entry.is_some() {
            self.redist_v4
                .iter()
                .filter(|((rt, _), _)| *rt == rtype)
                .map(|((_, prefix), _)| *prefix)
                .collect()
        } else {
            BTreeSet::new()
        };

        for prefix in prev_originated
            .difference(&desired)
            .copied()
            .collect::<Vec<_>>()
        {
            self.as_external_lsa_flush_for_prefix(prefix);
            if let Some(set) = self.redist_originated.get_mut(&rtype) {
                set.remove(&prefix);
            }
        }

        if let Some(redist_entry) = entry {
            for prefix in &desired {
                self.as_external_lsa_originate_for_prefix(
                    *prefix,
                    redist_entry.metric,
                    redist_entry.metric_type.is_type_2(),
                );
                self.redist_originated
                    .entry(rtype)
                    .or_default()
                    .insert(*prefix);
            }
        }
        if self
            .redist_originated
            .get(&rtype)
            .is_some_and(|s| s.is_empty())
        {
            self.redist_originated.remove(&rtype);
        }

        self.router_lsa_originate();
    }

    /// Run [`Self::as_external_redist_resync`] for every source that is
    /// either configured or still has originated state to clean up.
    /// Called from the RIB route-churn handlers, where any subscribed
    /// source may have changed.
    pub fn as_external_redist_resync_all(&mut self) {
        let rtypes: BTreeSet<crate::rib::RibType> = self
            .redist
            .keys()
            .copied()
            .chain(self.redist_originated.keys().copied())
            .collect();
        for rtype in rtypes {
            self.as_external_redist_resync(rtype);
        }
    }

    /// RFC 3101 §2.3 NSSA default-LSA origination. Thin wrapper
    /// around `nssa_lsa_originate_for_prefix` that gates on area
    /// type + `nssa_default_originate` knob and calls the generic
    /// builder with prefix=0.0.0.0/0, metric=1, E2, fwd=0.
    pub fn nssa_default_lsa_originate(&mut self, area_id: Ipv4Addr) {
        let area_type = match self.areas.get(area_id) {
            Some(area) => area.area_type,
            None => return,
        };
        if !area_type.is_nssa() || !area_type.nssa_default_originate {
            self.nssa_default_lsa_flush(area_id);
            return;
        }
        let default = Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).expect("0.0.0.0/0 is valid");
        self.nssa_lsa_originate_for_prefix(
            area_id,
            default,
            /* metric */ 1,
            /* metric_type_2 */ true,
            /* fwd_addr */ Ipv4Addr::UNSPECIFIED,
        );
    }

    /// Flush our self-originated Type-7 default LSA from `area_id`.
    pub fn nssa_default_lsa_flush(&mut self, area_id: Ipv4Addr) {
        let default = Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).expect("0.0.0.0/0 is valid");
        self.nssa_lsa_flush_for_prefix(area_id, default);
    }

    /// Rebuild this area's self-originated Type-7 LSAs for
    /// redistribute-connected from the cached RIB-known v4 connected
    /// routes (`self.redist_v4`).
    ///
    /// Idempotent: walks the cache and the previously-originated set,
    /// originates any missing Type-7s (or refreshes them — metric /
    /// metric-type may have changed) and flushes any stale ones.
    /// Called by:
    ///   - `RouteAdd` / `RouteDel` event from RIB (cache changed)
    ///   - redistribute-connected presence / metric / metric-type
    ///     config change
    ///   - area-type set (entering or leaving NSSA)
    pub fn nssa_redist_connected_resync(&mut self, area_id: Ipv4Addr) {
        use crate::rib::RibType;

        // Snapshot inputs to avoid holding a borrow across the
        // originate / flush calls (both take `&mut self`).
        let (entry, area_type, prev_originated) = {
            let Some(area) = self.areas.get(area_id) else {
                return;
            };
            (
                area.redistribute.connected,
                area.area_type,
                area.redist_connected_originated.clone(),
            )
        };

        // Compute the desired set of prefixes we should be
        // originating right now.
        let desired: BTreeSet<Ipv4Net> = if area_type.is_nssa()
            && let Some(_e) = entry
        {
            self.redist_v4
                .iter()
                .filter(|((rtype, _prefix), _entry)| *rtype == RibType::Connected)
                .map(|((_, prefix), _)| *prefix)
                .collect()
        } else {
            BTreeSet::new()
        };

        // Flush previously-originated prefixes that are no longer
        // desired.
        for prefix in prev_originated
            .difference(&desired)
            .copied()
            .collect::<Vec<_>>()
        {
            self.nssa_lsa_flush_for_prefix(area_id, prefix);
            if let Some(area) = self.areas.get_mut(area_id) {
                area.redist_connected_originated.remove(&prefix);
            }
        }

        // Re-originate all currently desired prefixes — covers
        // both first-time origination and refresh after a metric /
        // metric-type change.
        if let Some(redist_entry) = entry
            && area_type.is_nssa()
        {
            for prefix in &desired {
                self.nssa_lsa_originate_for_prefix(
                    area_id,
                    *prefix,
                    redist_entry.metric,
                    redist_entry.metric_type.is_type_2(),
                    Ipv4Addr::UNSPECIFIED,
                );
                if let Some(area) = self.areas.get_mut(area_id) {
                    area.redist_connected_originated.insert(*prefix);
                }
            }
        }
    }

    /// True when this router has interfaces in two or more OSPF
    /// areas (RFC 2328 §3.3 ABR test). Areas with zero attached
    /// links don't count — the area exists only in the LSDB-map
    /// shape, not on this router.
    pub fn is_abr(&self) -> bool {
        self.areas
            .iter()
            .filter(|(_, area)| !area.links.is_empty())
            .count()
            >= 2
    }

    /// True when this router originates Type-5 AS-External LSAs
    /// (RFC 2328 §3.3 ASBR definition). Today this requires the
    /// instance-level `redistribute connected` knob to be set.
    pub fn is_asbr(&self) -> bool {
        !self.redist.is_empty()
    }

    /// True when this router should translate Type-7 → Type-5 for
    /// `area_id`. RFC 3101 §3.1 translator-role evaluation:
    ///
    /// - `Never`: never translate.
    /// - `Always`: translate unconditionally (may create duplicate
    ///   Type-5s across multiple Always-mode ABRs in the same NSSA;
    ///   operator hazard called out in RFC 3101 §3.1).
    /// - `Candidate` (default): translate iff our router-id is the
    ///   highest among all ABRs visible in this NSSA's LSDB.
    ///   "ABR" is identified by the B-bit in the peer's Router-LSA
    ///   (set per `router_lsa_build`); a peer that doesn't set
    ///   B-bit is treated as non-ABR.
    ///
    /// Election is locally computed (no protocol negotiation). The
    /// Nt-bit in our Router-LSA is the spec-mandated announcement of
    /// our translator role, but currently isn't emitted — see
    /// `router_lsa_build` for the deferral note. All known
    /// implementations (FRR / IOS / Junos) elect locally, so the
    /// missing Nt-bit doesn't affect interop.
    pub fn is_nssa_translator_for(&self, area_id: Ipv4Addr) -> bool {
        use super::area::NssaTranslatorRole;
        let Some(area) = self.areas.get(area_id) else {
            return false;
        };
        if !area.area_type.is_nssa() {
            return false;
        }
        if !self.is_abr() {
            return false;
        }
        match area.area_type.nssa_translator_role {
            NssaTranslatorRole::Never => false,
            NssaTranslatorRole::Always => true,
            NssaTranslatorRole::Candidate => {
                // Find the highest router-id among other ABRs in
                // this NSSA's LSDB. We win the election iff our
                // router-id is greater or equal; greater handles
                // the normal case, equal handles the (unlikely)
                // tie where our own Router-LSA is also visible in
                // the LSDB.
                let highest_other = area
                    .lsdb
                    .iter_by_type(OspfLsType::Router)
                    .filter_map(|(_, lsa)| {
                        let OspfLsp::Router(ref body) = lsa.data.lsp else {
                            return None;
                        };
                        // B-bit (bit 0, mask 0x01) in Router-LSA
                        // flags = peer is an ABR.
                        if (body.flags & 0x0001) == 0 {
                            return None;
                        }
                        // Skip our own Router-LSA when present —
                        // we're comparing against OTHERS.
                        if lsa.data.h.adv_router == self.router_id {
                            return None;
                        }
                        Some(lsa.data.h.adv_router)
                    })
                    .max();
                match highest_other {
                    None => true, // No other ABRs visible; we win.
                    Some(other) => self.router_id >= other,
                }
            }
        }
    }

    /// Translate a single Type-7 NSSA-AS-External LSA into a Type-5
    /// AS-External LSA, install it in `lsdb_as`, and flood to all
    /// non-stub / non-NSSA areas (RFC 3101 §3.2).
    ///
    /// Gates (all must hold for translation to happen):
    /// - source LSA body is `NssaAsExternal` (defensive)
    /// - not MaxAge — flushed Type-7s shouldn't seed translations
    /// - not self-originated — re-translating our own Type-7 would
    ///   double state for no gain
    /// - P-bit set in the source — RFC 3101 §3.2.1
    ///
    /// The forwarding address is copied verbatim into the Type-5
    /// (RFC 3101 §3.2). A zero FA is permitted: the translated
    /// Type-5 then also carries FA=0, so receivers reach the prefix
    /// via the path to *this* ABR (the Type-5's advertising router),
    /// which itself installs the Type-7 route into the NSSA — the
    /// same FA=0 semantics `add_as_external_routes` /
    /// `add_nssa_routes` already implement on the receive side.
    fn nssa_translate_one(&mut self, type7: &OspfLsa) -> bool {
        use crate::ospf::lsdb::OSPF_MAX_AGE;
        const P_BIT: u8 = 0x08;

        let OspfLsp::NssaAsExternal(ref body) = type7.lsp else {
            return false;
        };
        if type7.h.ls_age >= OSPF_MAX_AGE {
            return false;
        }
        if type7.h.adv_router == self.router_id {
            return false;
        }
        if (type7.h.options & P_BIT) == 0 {
            return false;
        }

        let ls_id = type7.h.ls_id;
        let mut header = OspfLsaHeader::new(OspfLsType::AsExternal, ls_id, self.router_id);
        // Options on a translated Type-5: E-bit set (Type-5 belongs
        // to normal areas which accept External), O-bit set, N/P
        // cleared.
        let mut options = OspfOptions::default();
        options.set_external(true);
        options.set_o(true);
        header.options = u8::from(options);

        let new_body = AsExternalLsa {
            netmask: body.netmask,
            // RFC 3101 §3.2: preserve E-bit + TOS byte verbatim.
            ext_and_resvd: body.ext_and_tos,
            metric: body.metric,
            forwarding_address: body.forwarding_address,
            external_route_tag: body.external_route_tag,
            tos_list: body.tos_list.clone(),
        };
        let mut new_lsa = OspfLsa::from(header, OspfLsp::AsExternal(new_body));

        // Preserve sequence number on refresh (re-translation of a
        // changed source Type-7).
        if let Some(existing) =
            self.lsdb_as
                .lookup_by_id(OspfLsType::AsExternal, ls_id, self.router_id)
        {
            new_lsa.h.ls_seq_number = seq_max(
                new_lsa.h.ls_seq_number,
                existing.h.ls_seq_number.saturating_add(1),
            );
        }
        new_lsa.update();

        let flood_lsa = new_lsa.clone();
        self.lsdb_as.insert_self_originated(new_lsa, &self.tx, None);
        self.flood_lsa_through_as(&flood_lsa, None);
        true
    }

    /// Compute the set of Type-7 ls_ids in `area_id` that we
    /// SHOULD currently be translating (applies the same gates as
    /// `nssa_translate_one`). Used by `nssa_translate_resync` to
    /// diff against the previously-translated set.
    fn nssa_translatable_ls_ids(&self, area_id: Ipv4Addr) -> BTreeSet<Ipv4Addr> {
        use crate::ospf::lsdb::OSPF_MAX_AGE;
        const P_BIT: u8 = 0x08;
        let mut out = BTreeSet::new();
        let Some(area) = self.areas.get(area_id) else {
            return out;
        };
        for (_, lsa) in area.lsdb.iter_by_type(OspfLsType::NssaAsExternal) {
            let d = &lsa.data;
            if d.h.ls_age >= OSPF_MAX_AGE {
                continue;
            }
            if d.h.adv_router == self.router_id {
                continue;
            }
            if (d.h.options & P_BIT) == 0 {
                continue;
            }
            // Body shape is the only remaining gate; FA may be zero
            // (see `nssa_translate_one` for the FA=0 rationale).
            let OspfLsp::NssaAsExternal(_) = d.lsp else {
                continue;
            };
            out.insert(d.h.ls_id);
        }
        out
    }

    /// Rebuild this area's translated Type-5 LSA set from the
    /// current NSSA LSDB contents. Walks the area's Type-7s,
    /// re-translates any that match the gates, and flushes any
    /// previously-translated Type-5s whose source Type-7 is gone or
    /// no longer eligible. Idempotent.
    ///
    /// Called from:
    /// - `Message::NssaTranslateResync` (flood path on Type-7 arrival)
    /// - `area-type` config change
    /// - `nssa-translator-role` config change
    /// - `Message::Enable` / `Message::Disable` (link bindings flip
    ///   ABR status)
    pub fn nssa_translate_resync(&mut self, area_id: Ipv4Addr) {
        let translating = self.is_nssa_translator_for(area_id);
        let desired = if translating {
            self.nssa_translatable_ls_ids(area_id)
        } else {
            BTreeSet::new()
        };
        let prev: BTreeSet<Ipv4Addr> = self
            .areas
            .get(area_id)
            .map(|a| a.nssa_translated.clone())
            .unwrap_or_default();

        // Flush translations that should no longer exist.
        for ls_id in prev.difference(&desired).copied().collect::<Vec<_>>() {
            let flushed = self.lsdb_as.flush_lsa(
                OspfLsType::AsExternal,
                ls_id,
                self.router_id,
                &self.tx,
                None,
            );
            if let Some(lsa) = flushed {
                self.flood_lsa_through_as(&lsa, None);
            }
            if let Some(area) = self.areas.get_mut(area_id) {
                area.nssa_translated.remove(&ls_id);
            }
        }

        if !translating {
            return;
        }

        // Translate / refresh all desired Type-7s. Snapshot the
        // source LSAs first to release the area borrow before
        // calling `nssa_translate_one` (which takes `&mut self`).
        let sources: Vec<OspfLsa> = self
            .areas
            .get(area_id)
            .map(|a| {
                a.lsdb
                    .iter_by_type(OspfLsType::NssaAsExternal)
                    .filter(|(_, lsa)| desired.contains(&lsa.data.h.ls_id))
                    .map(|(_, lsa)| lsa.data.clone())
                    .collect()
            })
            .unwrap_or_default();

        // RFC 3101 §3.2.3 says the ABR should prefer the lowest-
        // metric Type-7 when several share an ls_id; the BTreeMap
        // key in the LSDB already collapses by `(LS-Type, LS-ID,
        // Adv-Router)`, so iteration here yields at most one
        // source per ls_id — fine until cross-NSSA collision
        // becomes a real shape worth handling (deferred).
        for source in &sources {
            if self.nssa_translate_one(source)
                && let Some(area) = self.areas.get_mut(area_id)
            {
                area.nssa_translated.insert(source.h.ls_id);
            }
        }
    }

    /// Resync NSSA translator state for every NSSA area on this
    /// router. Use when a router-wide property changed (e.g., ABR
    /// status due to a link join / leave); a per-area call would
    /// miss areas whose translator status changed indirectly.
    pub fn nssa_translate_resync_all(&mut self) {
        let nssa_area_ids: Vec<Ipv4Addr> = self
            .areas
            .iter()
            .filter(|(_, area)| area.area_type.is_nssa())
            .map(|(&id, _)| id)
            .collect();
        for area_id in nssa_area_ids {
            self.nssa_translate_resync(area_id);
        }
    }

    /// `RibRx::RouteAdd` handler. Update the cache, then nudge
    /// every NSSA area to resync. Per-area filtering happens inside
    /// `nssa_redist_connected_resync`.
    fn route_redist_add(&mut self, rtype: crate::rib::RibType, batch: crate::rib::RouteBatch) {
        if let crate::rib::RouteBatch::V4(entries) = batch {
            for e in entries {
                self.redist_v4.insert((rtype, e.prefix), e);
            }
        }
        // v6 batches arrive only for v3 subscriptions, which this
        // v2 instance doesn't issue today.

        let area_ids: Vec<Ipv4Addr> = self.areas.iter().map(|(&id, _)| id).collect();
        for area_id in area_ids {
            self.nssa_redist_connected_resync(area_id);
        }
        self.as_external_redist_resync_all();
    }

    /// `RibRx::RouteDel` handler. Mirror of `route_redist_add`.
    fn route_redist_del(&mut self, rtype: crate::rib::RibType, batch: crate::rib::RouteBatch) {
        if let crate::rib::RouteBatch::V4(entries) = batch {
            for e in entries {
                self.redist_v4.remove(&(rtype, e.prefix));
            }
        }

        let area_ids: Vec<Ipv4Addr> = self.areas.iter().map(|(&id, _)| id).collect();
        for area_id in area_ids {
            self.nssa_redist_connected_resync(area_id);
        }
        self.as_external_redist_resync_all();
    }

    fn process_lsdb(&mut self, ev: LsdbEvent, area_id: Option<Ipv4Addr>, key: OspfLsaKey) {
        // Unpack the widened key back into v2-typed components for the
        // v2-bound match arms / method calls below.
        let (ls_type, ls_id, adv_router) = v2_lsa_key_unpack(key);

        ospf_event_trace!(
            self.tracing,
            Lsdb,
            event = ?ev,
            ls_type = ?ls_type,
            ls_id = %ls_id,
            adv_router = %adv_router,
            "LSDB event"
        );

        // Handle SelfOriginatedReceived before borrowing lsdb, since
        // re-origination needs full &mut self access.
        if ev == LsdbEvent::SelfOriginatedReceived {
            self.process_self_originated_lsa(area_id, ls_type, ls_id, adv_router);
            return;
        }

        // Handle RefreshTimerExpire: rebuild the LSA from current state when
        // a dedicated originator exists (Router / Network LSA). Otherwise
        // fall back to cloning the old body and bumping the sequence number.
        if ev == LsdbEvent::RefreshTimerExpire {
            tracing::info!(
                "LSDB refresh timer expired: type={} id={} adv={}",
                ls_type,
                ls_id,
                adv_router
            );

            // Self-originated only. Defensive — refresh timers should only
            // ever be armed for our own LSAs.
            if adv_router != self.router_id {
                return;
            }

            match ls_type {
                OspfLsType::Router => {
                    self.router_lsa_originate();
                    return;
                }
                OspfLsType::Network => {
                    // The Network LSA's LS-ID is the DR interface IP. Find
                    // the matching interface and rebuild from its current
                    // Full-adjacency set.
                    let ifindex = self.links.iter().find_map(|(idx, link)| {
                        link.addr
                            .iter()
                            .any(|a| a.prefix.addr() == ls_id)
                            .then_some(*idx)
                    });
                    if let Some(ifindex) = ifindex {
                        self.update_network_lsa_by_interface(ifindex);
                    }
                    return;
                }
                _ => {}
            }

            // Fallback: clone body, bump seq#, reinstall, then flood.
            let refreshed = {
                let lsdb = if let Some(area_id) = area_id {
                    let Some(area) = self.areas.get_mut(area_id) else {
                        return;
                    };
                    &mut area.lsdb
                } else {
                    &mut self.lsdb_as
                };
                lsdb.refresh_lsa(ls_type, ls_id, adv_router, &self.tx, area_id);
                lsdb.lookup_by_id(ls_type, ls_id, adv_router).cloned()
            };
            if let Some(lsa) = refreshed
                && let Some(area_id) = area_id
            {
                self.flood_self_originated_lsa(area_id, &lsa);
            }
            return;
        }

        {
            let lsdb = if let Some(area_id) = area_id {
                let Some(area) = self.areas.get_mut(area_id) else {
                    return;
                };
                &mut area.lsdb
            } else {
                &mut self.lsdb_as
            };
            match ev {
                LsdbEvent::HoldTimerExpire => {
                    tracing::info!(
                        "LSDB hold timer expired: type={} id={} adv={}",
                        ls_type,
                        ls_id,
                        adv_router
                    );
                    lsdb.remove_lsa(ls_type, ls_id, adv_router);
                }
                _ => unreachable!(),
            }
        }

        if ev == LsdbEvent::HoldTimerExpire {
            match ls_type {
                OspfLsType::Router | OspfLsType::Network | OspfLsType::Summary => {
                    if let Some(area_id) = area_id
                        && let Some(area) = self.areas.get_mut(area_id)
                    {
                        Self::ospf_spf_schedule(&self.tx, area);
                    }
                }
                OspfLsType::AsExternal => {
                    // AS-scoped; reschedule SPF on every area.
                    let _ = self.tx.send(Message::SpfSchedule(None));
                }
                _ => {}
            }
        }
    }

    /// Handle a self-originated LSA received from a neighbor (RFC 2328 Section 13.4).
    /// If we still own this LSA, re-originate with seq# = max(current, received) + 1.
    /// If we no longer own it, flush it from the LSDB.
    fn process_self_originated_lsa(
        &mut self,
        area_id: Option<Ipv4Addr>,
        ls_type: OspfLsType,
        ls_id: Ipv4Addr,
        adv_router: Ipv4Addr,
    ) {
        // Get the received seq# from the LSDB entry.
        let received_seq = {
            let lsdb = if let Some(area_id) = area_id {
                let Some(area) = self.areas.get(area_id) else {
                    return;
                };
                &area.lsdb
            } else {
                &self.lsdb_as
            };
            let Some(lsa) = lsdb.lookup_lsa(ls_type, ls_id, adv_router) else {
                return;
            };
            lsa.data.h.ls_seq_number
        };

        match ls_type {
            OspfLsType::Router => {
                tracing::info!(
                    "[Self-Originated] Re-originating Router LSA id={} seq={:#x}",
                    ls_id,
                    received_seq
                );
                self.router_lsa_reoriginate(received_seq);
            }
            OspfLsType::Network => {
                if self.is_dr_for_network_lsa(ls_id) {
                    tracing::info!(
                        "[Self-Originated] Re-originating Network LSA id={} seq={:#x}",
                        ls_id,
                        received_seq
                    );
                    // Re-originate by refreshing with min_seq from received LSA.
                    if let Some(area_id) = area_id {
                        let refreshed = {
                            let Some(area) = self.areas.get_mut(area_id) else {
                                return;
                            };
                            area.lsdb.refresh_lsa_with_seq(
                                ls_type,
                                ls_id,
                                adv_router,
                                received_seq,
                                &self.tx,
                                Some(area_id),
                            );
                            area.lsdb.lookup_by_id(ls_type, ls_id, adv_router).cloned()
                        };
                        if let Some(lsa) = refreshed {
                            self.flood_self_originated_lsa(area_id, &lsa);
                        }
                    }
                } else {
                    tracing::info!(
                        "[Self-Originated] Flushing Network LSA id={} (no longer DR)",
                        ls_id
                    );
                    if let Some(area_id) = area_id {
                        let flushed = {
                            let Some(area) = self.areas.get_mut(area_id) else {
                                return;
                            };
                            area.lsdb
                                .flush_lsa(ls_type, ls_id, adv_router, &self.tx, Some(area_id))
                        };
                        if let Some(lsa) = flushed {
                            self.flood_self_originated_lsa(area_id, &lsa);
                        }
                    }
                }
            }
            OspfLsType::NssaAsExternal => {
                // Three self-origination paths today:
                //   1. NSSA default-LSA (ls_id 0.0.0.0).
                //   2. Redistributed connected (ls_id ∈ area's
                //      `redist_connected_originated`).
                //   3. Other — no owner; flush.
                let Some(area_id) = area_id else {
                    return;
                };
                if ls_id.is_unspecified() {
                    tracing::info!(
                        "[Self-Originated] Re-originating NSSA default Type-7 id={} seq={:#x}",
                        ls_id,
                        received_seq
                    );
                    self.nssa_default_lsa_originate(area_id);
                    return;
                }
                let owned_redist = self
                    .areas
                    .get(area_id)
                    .map(|a| {
                        a.redist_connected_originated
                            .iter()
                            .any(|p| p.network() == ls_id)
                    })
                    .unwrap_or(false);
                if owned_redist {
                    tracing::info!(
                        "[Self-Originated] Re-originating NSSA redistribute Type-7 id={} seq={:#x}",
                        ls_id,
                        received_seq
                    );
                    self.nssa_redist_connected_resync(area_id);
                    return;
                }
                tracing::info!(
                    "[Self-Originated] Flushing Type-7 LSA id={} (no owner)",
                    ls_id
                );
                let flushed = self.areas.get_mut(area_id).and_then(|area| {
                    area.lsdb
                        .flush_lsa(ls_type, ls_id, adv_router, &self.tx, Some(area_id))
                });
                if let Some(lsa) = flushed {
                    self.flood_self_originated_lsa(area_id, &lsa);
                }
            }
            OspfLsType::AsExternal => {
                // Type-5s can be self-originated via two paths:
                //   1. instance-level `redistribute <source>` → `redist_originated`
                //   2. NSSA Type-7→Type-5 translation → `nssa_translated`
                // Check the redistribute set first, then NSSA, then flush.
                let network = {
                    let prefix_len = self
                        .lsdb_as
                        .lookup_by_id(OspfLsType::AsExternal, ls_id, adv_router)
                        .and_then(|lsa| {
                            if let OspfLsp::AsExternal(ref ext) = lsa.lsp {
                                Some(u32::from(ext.netmask).leading_ones() as u8)
                            } else {
                                None
                            }
                        });
                    prefix_len
                        .and_then(|plen| Ipv4Net::new(ls_id, plen).ok())
                        .map(|p| p.trunc())
                };
                if network
                    .is_some_and(|p| self.redist_originated.values().any(|set| set.contains(&p)))
                {
                    tracing::info!(
                        "[Self-Originated] Re-originating redistribute Type-5 id={} seq={:#x}",
                        ls_id,
                        received_seq
                    );
                    self.as_external_redist_resync_all();
                } else {
                    let owning_area = self
                        .areas
                        .iter()
                        .find(|(_, area)| area.nssa_translated.contains(&ls_id))
                        .map(|(&id, _)| id);
                    if let Some(area_id) = owning_area {
                        tracing::info!(
                            "[Self-Originated] Re-translating Type-5 from NSSA area {} id={} seq={:#x}",
                            area_id,
                            ls_id,
                            received_seq
                        );
                        self.nssa_translate_resync(area_id);
                    } else {
                        tracing::info!(
                            "[Self-Originated] Flushing AS-External LSA id={} (no owner)",
                            ls_id
                        );
                        let flushed = self
                            .lsdb_as
                            .flush_lsa(ls_type, ls_id, adv_router, &self.tx, None);
                        if let Some(lsa) = flushed {
                            self.flood_lsa_through_as(&lsa, None);
                        }
                    }
                }
            }
            OspfLsType::OpaqueAreaLocal => {
                // Opaque-Area LSAs (RFC 5250) we originate are
                // Router-Info / Extended-Prefix / Extended-Link.
                // The opaque-type sits in the top byte of `ls_id`;
                // the lower 24 bits are the opaque-id (for
                // ExtPrefix/ExtLink that's the originating ifindex
                // masked to 24 bits, mirroring the originate path).
                // Each originator already bumps seq# above the
                // existing LSDB copy via its `lookup_by_id...max(seq+1)`
                // pattern, so calling it here is enough to take us
                // past the received_seq the §13.4 trigger holds.
                let opaque_type = (u32::from(ls_id) >> 24) as u8;
                let opaque_id = u32::from(ls_id) & 0x00FF_FFFF;
                match opaque_type {
                    OpaqueLsaType::ROUTER_INFO => {
                        tracing::info!(
                            "[Self-Originated] Re-originating Router-Info Opaque LSA id={} seq={:#x}",
                            ls_id,
                            received_seq
                        );
                        self.router_info_lsa_originate();
                    }
                    OpaqueLsaType::EXT_PREFIX => {
                        tracing::info!(
                            "[Self-Originated] Re-originating Ext-Prefix Opaque LSA id={} ifindex={} seq={:#x}",
                            ls_id,
                            opaque_id,
                            received_seq
                        );
                        self.ext_prefix_lsa_originate(opaque_id);
                    }
                    OpaqueLsaType::EXT_LINK => {
                        tracing::info!(
                            "[Self-Originated] Re-originating Ext-Link Opaque LSA id={} ifindex={} seq={:#x}",
                            ls_id,
                            opaque_id,
                            received_seq
                        );
                        self.ext_link_lsa_originate(opaque_id);
                    }
                    _ => {
                        tracing::info!(
                            "[Self-Originated] Flushing Opaque LSA id={} opaque-type={} (unknown owner)",
                            ls_id,
                            opaque_type
                        );
                        let flushed =
                            self.areas
                                .get_mut(area_id.expect("area-local"))
                                .and_then(|area| {
                                    area.lsdb
                                        .flush_lsa(ls_type, ls_id, adv_router, &self.tx, area_id)
                                });
                        if let Some(lsa) = flushed
                            && let Some(area_id) = area_id
                        {
                            self.flood_self_originated_lsa(area_id, &lsa);
                        }
                    }
                }
            }
            OspfLsType::Summary | OspfLsType::SummaryAsbr => {
                // RFC 2328 §13.4: a neighbor reflected our own Type-3/4
                // back at a seq >= ours. Re-assert it above that seq
                // with the body intact (content changes are handled by
                // `abr_summary_originate`); a stale summary we no longer
                // want is dropped on the next SPF-driven sync instead.
                tracing::info!(
                    "[Self-Originated] Re-asserting Summary LSA type={:?} id={} seq={:#x}",
                    ls_type,
                    ls_id,
                    received_seq
                );
                if let Some(area_id) = area_id {
                    let refreshed = {
                        let Some(area) = self.areas.get_mut(area_id) else {
                            return;
                        };
                        area.lsdb.refresh_lsa_with_seq(
                            ls_type,
                            ls_id,
                            adv_router,
                            received_seq,
                            &self.tx,
                            Some(area_id),
                        );
                        area.lsdb.lookup_by_id(ls_type, ls_id, adv_router).cloned()
                    };
                    if let Some(lsa) = refreshed {
                        self.flood_self_originated_lsa(area_id, &lsa);
                    }
                }
            }
            _ => {
                // Other self-originated types we don't re-originate yet;
                // flush with MaxAge.
                tracing::info!(
                    "[Self-Originated] Flushing LSA type={:?} id={} (not re-originable)",
                    ls_type,
                    ls_id
                );
                let flushed = {
                    let lsdb = if let Some(area_id) = area_id {
                        let Some(area) = self.areas.get_mut(area_id) else {
                            return;
                        };
                        &mut area.lsdb
                    } else {
                        &mut self.lsdb_as
                    };
                    lsdb.flush_lsa(ls_type, ls_id, adv_router, &self.tx, area_id)
                };
                if let Some(lsa) = flushed
                    && let Some(area_id) = area_id
                {
                    self.flood_self_originated_lsa(area_id, &lsa);
                }
            }
        }
    }

    /// Re-originate Router LSA with seq# >= min_seq + 1.
    fn router_lsa_reoriginate(&mut self, min_seq: u32) {
        tracing::info!("Router LSA Re-originate (min_seq={:#x})", min_seq);
        self.router_lsa_originate_with_min_seq(Some(min_seq));
    }

    /// Re-originate or flush the v2 Network-LSA for the broadcast
    /// segment on `ifindex` (DR-only origination).
    ///
    /// GR-helper invariant (RFC 3623 §3.1): when we are DR and a
    /// neighbor on this segment is in helper mode, that neighbor
    /// must continue appearing in the `attached_routers` list, and
    /// the segment's `full_nbr_count` must continue counting it.
    /// The inactivity-timer suppression keeps `nbr.state` at `Full`
    /// throughout helper, so the `state == Full` filter below
    /// honours both invariants implicitly; in particular the
    /// `full_nbr_count == 0` branch (which would flush the
    /// Network-LSA per RFC 2328 §14.1) does not fire while a
    /// helper-mode neighbor remains.
    fn update_network_lsa_by_interface(&mut self, ifindex: u32) {
        // Network-LSA is topology-affecting, so the checkpoint-loaded
        // copy stays verbatim during restart. The exit-restart path
        // re-emits at seq+1 once adjacencies re-converge.
        if self.in_restart() {
            return;
        }
        let (area_id, ls_id, netmask, attached_routers, full_nbr_count) = {
            let Some(link) = self.links.get_mut(&ifindex) else {
                return;
            };
            if !link.enabled {
                return;
            }

            let Some(primary_addr) = link.addr.first() else {
                return;
            };

            let mut attached_routers = Vec::with_capacity(link.nbrs.len() + 1);
            attached_routers.push(self.router_id);
            for nbr in link.nbrs.values() {
                if nbr.state == NfsmState::Full {
                    attached_routers.push(nbr.ident.router_id);
                }
            }
            attached_routers.sort_unstable();
            attached_routers.dedup();

            link.full_nbr_count = link
                .nbrs
                .values()
                .filter(|nbr| nbr.state == NfsmState::Full)
                .count();

            (
                link.area,
                primary_addr.prefix.addr(),
                primary_addr.prefix.netmask(),
                attached_routers,
                link.full_nbr_count,
            )
        };

        let flood_lsa = if let Some(area) = self.areas.get_mut(area_id) {
            if full_nbr_count == 0 {
                area.lsdb.flush_lsa(
                    OspfLsType::Network,
                    ls_id,
                    self.router_id,
                    &self.tx,
                    Some(area_id),
                )
            } else {
                let current_seq = area
                    .lsdb
                    .lookup_by_id(OspfLsType::Network, ls_id, self.router_id)
                    .map(|lsa| lsa.h.ls_seq_number);

                let lsah = OspfLsaHeader::new(OspfLsType::Network, ls_id, self.router_id);
                let mut lsa = OspfLsa::from(
                    lsah,
                    OspfLsp::Network(NetworkLsa {
                        netmask,
                        attached_routers,
                    }),
                );
                if let Some(seq) = current_seq {
                    lsa.h.ls_seq_number = seq_max(lsa.h.ls_seq_number, seq.saturating_add(1));
                }

                lsa.update();
                let flood_lsa = lsa.clone();
                area.lsdb
                    .insert_self_originated(lsa, &self.tx, Some(area_id));
                Some(flood_lsa)
            }
        } else {
            None
        };

        if let Some(lsa) = flood_lsa {
            self.flood_self_originated_lsa(area_id, &lsa);
            if let Some(area) = self.areas.get_mut(area_id) {
                Self::ospf_spf_schedule(&self.tx, area);
            }
        }
    }

    /// Premature-age (RFC 2328 §14.1) the self-originated Network-LSA
    /// scoped to `ifindex` and re-flood it so peers drop it. Called
    /// from `Message::Disable` (interface going away) and from the
    /// `Message::Ifsm` DR-leave hook (we lost the DR role through
    /// election or network-type change) — the LSA must not outlive
    /// our DR state on the segment, otherwise peers carry a stale
    /// pseudo-node that contradicts our current Router-LSA.
    ///
    /// Mirrors v3's `network_lsa_flush` (inst.rs:2847). The LSA's
    /// `ls_id` is the primary interface address — same value used
    /// at origination in `update_network_lsa_by_interface`.
    pub fn network_lsa_flush(&mut self, ifindex: u32, area_id: Ipv4Addr) {
        // Premature-aging our Network-LSA mid-restart would tear
        // down helpers' view of this segment. Skip until
        // exit-restart.
        if self.in_restart() {
            return;
        }
        let Some(link) = self.links.get(&ifindex) else {
            return;
        };
        let Some(primary_addr) = link.addr.first() else {
            return;
        };
        let ls_id = primary_addr.prefix.addr();

        let flushed = if let Some(area) = self.areas.get_mut(area_id) {
            area.lsdb.flush_lsa(
                OspfLsType::Network,
                ls_id,
                self.router_id,
                &self.tx,
                Some(area_id),
            )
        } else {
            None
        };
        if let Some(lsa) = flushed {
            self.flood_self_originated_lsa(area_id, &lsa);
        }
    }

    fn process_neighbor_state_change(
        &mut self,
        ifindex: u32,
        nbr_addr: Ipv4Addr,
        old_state: NfsmState,
        new_state: NfsmState,
    ) {
        if old_state == new_state {
            return;
        }

        let full_state_changed = (old_state == NfsmState::Full && new_state != NfsmState::Full)
            || (old_state != NfsmState::Full && new_state == NfsmState::Full);
        if !full_state_changed {
            return;
        }

        let if_state = {
            let Some(link) = self.links.get_mut(&ifindex) else {
                return;
            };
            link.full_nbr_count = link
                .nbrs
                .values()
                .filter(|nbr| nbr.state == NfsmState::Full)
                .count();
            link.state
        };

        tracing::info!(
            "[NFSM:FullTransition] ifindex={} nbr={} {} -> {}",
            ifindex,
            nbr_addr,
            old_state,
            new_state
        );

        // Adjacency-SID label allocation. Each Full adjacency claims
        // one label out of the SRLB on transition into Full and
        // releases it on regression. The label is consumed by LAN
        // Adj-SID origination (broadcast / NBMA links), by the dynamic
        // P2P Adj-SID fallback (no `adjacency-sid` configured), and by
        // the matching local ILM install. Pool is only present when
        // SR-MPLS is enabled, so this is a no-op otherwise.
        if new_state == NfsmState::Full
            && let Some(pool) = self.local_pool.as_mut()
            && let Some(label) = pool.allocate()
        {
            self.lan_adj_sids.insert((ifindex, nbr_addr), label as u32);
        } else if old_state == NfsmState::Full
            && let Some(label) = self.lan_adj_sids.remove(&(ifindex, nbr_addr))
            && let Some(pool) = self.local_pool.as_mut()
        {
            pool.release(label as usize);
        }

        // Router-LSA must be re-originated whenever Full adjacency count changes.
        // (Gated against `in_restart()` inside the method — the
        // restart-exit success path is what re-originates instead.)
        self.router_lsa_originate();

        // DR updates/flushes its Network-LSA based on current full adjacency set.
        if if_state == IfsmState::DR {
            self.update_network_lsa_by_interface(ifindex);
        }

        // Extended-Link Opaque LSA tracks the per-link Adj-SID, which
        // is only meaningful while the link has a Full neighbor.
        // `ext_link_lsa_originate` flushes when no Full neighbor remains.
        self.ext_link_lsa_originate(ifindex);

        // Count Full transitions during restart. When we've
        // recovered as many adjacencies as the checkpoint expected,
        // exit-restart fires.
        if new_state == NfsmState::Full
            && old_state != NfsmState::Full
            && let Some(state) = self.restarting.as_mut()
        {
            state.current_full_count = state.current_full_count.saturating_add(1);
            if state.current_full_count >= state.expected_full_count
                && state.expected_full_count > 0
            {
                tracing::info!(
                    "[GR Restart] exit-restart triggered ({}/{} adjacencies recovered)",
                    state.current_full_count,
                    state.expected_full_count
                );
                let _ = self.tx.send(Message::GrRestartExitSuccess);
            }
        }
    }

    /// Destroy a neighbor whose inactivity timer fired — dead-timer
    /// expiry, BFD-down (RFC 5882 §5), or an operator `clear ospf
    /// neighbor`. `ospf_nfsm` has already run `ospf_nfsm_reset_nbr` on
    /// it; here we finish the teardown its early-return defers to "the
    /// caller":
    ///
    ///   * GR-helper neighbors are spared — `ospf_nfsm_inactivity_timer`
    ///     re-armed their timer and kept them Full, so we must not drop
    ///     them mid-restart.
    ///   * otherwise the instance is removed from `link.nbrs`, its BFD
    ///     subscription (if any) released, and the Full-transition
    ///     cleanup run (Router-LSA / Network-LSA / Adj-SID / SPF) with a
    ///     DR re-election when it had reached 2-Way.
    ///
    /// A later Hello re-creates the neighbor from `Down`, so clearing a
    /// live neighbor bounces the adjacency while a real timeout simply
    /// leaves it gone.
    fn nfsm_kill_neighbor(&mut self, ifindex: u32, src: Ipv4Addr, old_state: Option<NfsmState>) {
        let Some(old_state) = old_state else {
            return;
        };
        // Snapshot the BFD key before removal; bail if GR-helper
        // suppression kept the neighbor (its timer was re-armed).
        let bfd_key = match self.links.get(&ifindex).and_then(|l| l.nbrs.get(&src)) {
            Some(nbr) if nbr.gr_helper.is_some() => return,
            Some(nbr) => nbr.bfd_session_key,
            None => return,
        };

        if let Some(link) = self.links.get_mut(&ifindex) {
            link.nbrs.remove(&src);
        }

        // Release the BFD session for the gone neighbor. (BFD-down
        // already cleared the key before firing InactivityTimer, so
        // this only does work on the timeout / clear paths.)
        if let Some(key) = bfd_key
            && let Some(client_tx) = self.bfd_client_tx.as_ref()
        {
            let _ = client_tx.send(crate::bfd::inst::ClientReq::Unsubscribe {
                client: Ospfv2::PROTO.to_string(),
                key,
            });
        }

        // Drive the Full → Down side effects now that the neighbor is
        // gone (the helper re-counts Full adjacencies from the map, so
        // removing first is correct), then re-elect the DR if it had
        // formed at least a 2-Way adjacency.
        self.process_neighbor_state_change(ifindex, src, old_state, NfsmState::Down);
        if old_state >= NfsmState::TwoWay {
            let _ = self
                .tx
                .send(Message::Ifsm(ifindex, IfsmEvent::NeighborChange));
        }

        // The Full neighbor (if it was one) is gone — release the STAMP
        // measurement session (diff-gated no-op when none exists).
        self.stamp_reconcile_and_originate(ifindex);
    }

    /// v2 wrapper around the generic [`Self::stamp_reconcile_link`]:
    /// when the reconcile cleared measured values, refresh the
    /// Extended-Link Opaque LSA so the stale sub-TLVs are withdrawn.
    pub(crate) fn stamp_reconcile_and_originate(&mut self, ifindex: u32) {
        if self.stamp_reconcile_link(ifindex) {
            self.ext_link_lsa_originate(ifindex);
        }
    }

    /// A damped STAMP export arrived: store the measured values on the
    /// link and refresh the Extended-Link Opaque LSA so the RFC 7471
    /// sub-TLVs (and flex-algo metric-type-1 SPF inputs) reflect them.
    /// A `None` snapshot clears — the sub-TLVs are withdrawn unless
    /// static config backs them
    /// ([`super::link::OspfLink::te_metric_effective`]).
    pub(crate) fn process_stamp_event(&mut self, event: crate::stamp::client::StampEvent) {
        if let Some(ifindex) = self.stamp_apply_metric_update(event) {
            self.ext_link_lsa_originate(ifindex);
        }
    }

    /// Grace-period expiry handler (RFC 3623 §3.2 bullet 1).
    fn gr_helper_expire(&mut self, ifindex: u32, router_id: Ipv4Addr) {
        self.gr_helper_exit(ifindex, router_id, "grace period expired");
    }

    /// Shared helper-exit path. Clears `nbr.gr_helper` and re-fires
    /// the inactivity-timer event so the normal
    /// `ospf_nfsm_kill_nbr` path runs — by now the neighbor really
    /// should be gone (or about to re-adjacency-form fresh).
    /// `reason` is a free-form string for the tracing log.
    fn gr_helper_exit(&mut self, ifindex: u32, router_id: Ipv4Addr, reason: &str) {
        let Some(link) = self.links.get_mut(&ifindex) else {
            return;
        };
        let Some(nbr) = link.nbrs.get_mut(&router_id) else {
            return;
        };
        if nbr.gr_helper.take().is_none() {
            return;
        }
        tracing::info!(
            "[GR Helper] exit for nbr {} on ifindex={} (reason: {})",
            router_id,
            ifindex,
            reason
        );
        let _ = self.tx.send(Message::Nfsm(
            ifindex,
            router_id,
            super::nfsm::NfsmEvent::InactivityTimer,
        ));
    }

    /// RFC 3623 §3.2 bullets 2-3 — topology-change exit. Called
    /// from `flood_lsa_through_area` after `ospf_flood` has just
    /// installed `lsa` into the area LSDB. For every helper-mode
    /// neighbor in this area, decide whether the install warrants
    /// exit:
    ///
    ///   - If `lsa.adv_router != restarter`: any topology-affecting
    ///     LSA represents a change to the area outside the
    ///     restarter, so exit.
    ///   - If `lsa.adv_router == restarter`: compare against the
    ///     `(seq, checksum)` we snapshotted at helper entry. Exact
    ///     match → quiescent re-flood (no exit). Differs → the
    ///     restarter's content / sequence changed (restart finished
    ///     or content drifted), so exit.
    ///
    /// Non-topology-affecting LSAs (Opaque, AS-External, Link-LSA)
    /// are ignored — they don't change intra-area routing.
    fn gr_helper_check_exit(&mut self, area_id: Ipv4Addr, lsa: &OspfLsa) {
        let topology_affecting = matches!(
            lsa.h.ls_type,
            OspfLsType::Router
                | OspfLsType::Network
                | OspfLsType::Summary
                | OspfLsType::SummaryAsbr
        );
        if !topology_affecting {
            return;
        }
        let key = super::lsdb::v2_lsa_key(lsa.h.ls_type, lsa.h.ls_id, lsa.h.adv_router);

        let Some(area) = self.areas.get(area_id) else {
            return;
        };
        let link_indices: Vec<u32> = area.links.iter().copied().collect();

        let mut exits: Vec<(u32, Ipv4Addr, &'static str)> = Vec::new();
        for ifindex in link_indices {
            let Some(link) = self.links.get(&ifindex) else {
                continue;
            };
            for (_nbr_addr, nbr) in link.nbrs.iter() {
                let Some(helper) = nbr.gr_helper.as_ref() else {
                    continue;
                };
                let exit_reason = if lsa.h.adv_router == nbr.ident.router_id {
                    match helper.lsdb_snapshot.get(&key) {
                        Some(&(seq, csum))
                            if seq == lsa.h.ls_seq_number && csum == lsa.h.ls_checksum =>
                        {
                            // Identical re-flood — quiescent.
                            continue;
                        }
                        _ => "restarter LSA changed from snapshot",
                    }
                } else if self.gr_config.helper_strict_lsa_checking {
                    "non-restarter topology change in area"
                } else {
                    // Strict-LSA-checking disabled — ignore non-restarter
                    // topology changes per `helper-strict-lsa-checking false`.
                    continue;
                };
                exits.push((ifindex, nbr.ident.router_id, exit_reason));
            }
        }
        for (ifindex, router_id, reason) in exits {
            self.gr_helper_exit(ifindex, router_id, reason);
        }
    }

    /// Check if we are currently the DR for the network identified by ls_id.
    fn is_dr_for_network_lsa(&self, ls_id: Ipv4Addr) -> bool {
        for (_, link) in self.links.iter() {
            if !link.enabled {
                continue;
            }
            for addr in link.addr.iter() {
                if addr.prefix.addr() == ls_id {
                    return Ospfv2::is_declared_dr(&link.ident);
                }
            }
        }
        false
    }

    /// Stage a planned graceful restart (RFC 3623 §2). Builds and
    /// floods one Grace LSA per active interface so peers enter
    /// helper mode for us, marks the instance as restarting (so
    /// the next Router-Info LSA carries `gr_capable=true`), and
    /// arms an auto-abort timer that walks the staging back if
    /// the commit side doesn't fire in time.
    ///
    /// Returns `false` if a restart was already staged (idempotent
    /// re-entry would lose the original `entered_at`). The caller
    /// (vty handler) reports failure to the operator.
    pub fn gr_restart_begin(
        &mut self,
        grace_period: u32,
        reason: ospf_packet::GraceRestartReason,
    ) -> bool {
        use super::neigh::RestartingState;
        use crate::context::{Timer, TimerType};

        if self.restarting.is_some() {
            tracing::info!("[GR Restart] begin rejected — already staged");
            return false;
        }

        // Build + flood a Grace LSA on every enabled interface.
        // RFC 3623 §A.3 — Grace LSA scope is link-local; we send
        // it down each link's neighbor set directly rather than
        // using `flood_lsa_through_area`, which would (incorrectly)
        // fan the link-local LSA out across the area.
        let ifindices: Vec<u32> = self
            .links
            .iter()
            .filter(|(_, link)| link.enabled)
            .map(|(ifindex, _)| *ifindex)
            .collect();
        let mut originated = 0usize;
        for ifindex in &ifindices {
            if self.originate_grace_lsa(*ifindex, grace_period, reason) {
                originated += 1;
            }
        }

        let tx = self.tx.clone();
        let abort_timer = Timer::new(grace_period as u64, TimerType::Once, move || {
            let tx = tx.clone();
            async move {
                let _ = tx.send(Message::GrRestartAbort);
            }
        });

        // Snapshot Full-neighbor count at staging time. The
        // commit handler will store the same number into the
        // checkpoint so the post-reboot exit path knows when to
        // declare success.
        let expected_full_count = self
            .links
            .values()
            .flat_map(|link| link.nbrs.values())
            .filter(|nbr| nbr.state == NfsmState::Full)
            .count();
        self.restarting = Some(RestartingState {
            grace_period,
            reason,
            entered_at: tokio::time::Instant::now(),
            abort_timer: Some(abort_timer),
            expected_full_count,
            current_full_count: 0,
        });

        // Re-originate the Router-Info LSA so peers see
        // `gr_capable=true`. Only takes effect under SR-MPLS today
        // (the LSA itself is gated on SR-MPLS); GR-without-SR-MPLS
        // signaling falls back to the Grace LSA we just flooded,
        // which FRR also accepts as the sole entry trigger.
        self.router_info_lsa_originate();

        tracing::info!(
            "[GR Restart] staged: grace={}s, reason={:?}, {} Grace LSA(s) emitted",
            grace_period,
            reason,
            originated
        );
        true
    }

    /// Walk back a staged restart without committing. Flushes the
    /// Grace LSAs (MaxAge re-flood so helpers exit), clears
    /// `self.restarting`, and re-originates the Router-Info LSA
    /// without `gr_capable`. Idempotent — no-op when no restart
    /// is staged.
    /// `true` while we're in the middle of a graceful restart —
    /// either because the operator just typed `… begin` or because
    /// we booted with a fresh checkpoint on disk. Self-LSA
    /// origination paths check this and skip seq-number bumps so
    /// the helpers' snapshot keeps matching across the restart
    /// window.
    pub fn in_restart(&self) -> bool {
        self.restarting.is_some()
    }

    /// Replay an on-disk checkpoint into a freshly constructed
    /// `Ospf<Ospfv2>` instance.
    ///
    /// Called from `Ospf::new()` after the default-construction.
    /// If `/var/lib/zebra-rs/checkpoint/ospf.cbor` (or the
    /// `ZEBRA_OSPF_CHECKPOINT_DIR` override) is present AND fresh
    /// (within `1.5 × grace_period_secs` of `written_at` per the
    /// locked design), the daemon comes up in restarting mode:
    ///
    ///   - `self.router_id` restored from the checkpoint.
    ///   - Each area's LSDB pre-populated from the saved LSA
    ///     bodies (verbatim, so re-flood on adjacency recovery
    ///     produces byte-identical content to what helpers
    ///     snapshotted).
    ///   - `lan_adj_sids` restored so SR-MPLS labels stay stable.
    ///   - `self.restarting = Some(...)` so origination methods
    ///     short-circuit and the show output reflects the mode.
    ///   - Auto-abort timer armed for the remaining grace
    ///     window; the exit-restart path will replace it once
    ///     adjacencies recover.
    ///
    /// The checkpoint file is deleted immediately after a
    /// successful load — a second restart MUST NOT replay the
    /// same stale state. Re-checkpointing is the next restart's
    /// responsibility (5d's commit handler).
    fn gr_restart_load_checkpoint(&mut self) {
        use super::checkpoint::{OspfCheckpoint, default_path};
        use super::neigh::RestartingState;
        use crate::context::{Timer, TimerType};
        use std::time::{Duration, SystemTime};

        let path = default_path("ospf");
        let cp = match OspfCheckpoint::read_from_path(&path) {
            Ok(cp) => cp,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(e) => {
                tracing::warn!(
                    "[GR Restart] checkpoint at {} unreadable, cold-starting: {}",
                    path.display(),
                    e
                );
                return;
            }
        };

        // Freshness: written_at must be within 1.5x grace_period
        // ago, per the locked design (wall clock + slack).
        let max_age = Duration::from_secs((cp.grace_period_secs as u64).saturating_mul(3) / 2);
        let age = SystemTime::now()
            .duration_since(cp.written_at)
            .unwrap_or(Duration::ZERO);
        if age > max_age {
            tracing::warn!(
                "[GR Restart] checkpoint at {} stale (age {:?} > {:?}), cold-starting",
                path.display(),
                age,
                max_age
            );
            let _ = OspfCheckpoint::delete(&path);
            return;
        }

        // Replay: router-id, areas + their LSDBs, lan_adj_sids.
        self.router_id = cp.router_id;
        let mut total_lsas = 0usize;
        for area_cp in &cp.areas {
            let area = self.areas.fetch(area_cp.area_id);
            area.area_type.kind = area_cp.area_type_kind.into();
            for snap in &area_cp.lsas {
                let Some(lsa) = ospf_packet::OspfLsa::decode(&snap.body) else {
                    tracing::warn!(
                        "[GR Restart] failed to decode checkpointed LSA key={:?}, skipping",
                        snap.key
                    );
                    continue;
                };
                if snap.self_originated {
                    area.lsdb
                        .insert_self_originated(lsa, &self.tx, Some(area_cp.area_id));
                } else {
                    area.lsdb
                        .insert_received(lsa, &self.tx, Some(area_cp.area_id));
                }
                total_lsas += 1;
            }
        }
        for ((ifindex, addr), label) in &cp.lan_adj_sids {
            self.lan_adj_sids.insert((*ifindex, *addr), *label);
        }

        // Restarting state — entered_at is the original checkpoint
        // write time so the freshness slack on this side matches
        // the helpers' grace-period view of when we went down.
        let remaining = max_age.saturating_sub(age);
        let remaining_secs = remaining.as_secs().max(1);
        let tx = self.tx.clone();
        let abort_timer = Timer::new(remaining_secs, TimerType::Once, move || {
            let tx = tx.clone();
            async move {
                let _ = tx.send(Message::GrRestartAbort);
            }
        });
        let entered_at = tokio::time::Instant::now() - age;
        // Count was_full neighbors across every checkpointed link.
        // Exit-restart success fires when `current_full_count`
        // matches this — the post-reboot count of neighbors we've
        // driven back to Full.
        let expected_full_count = cp
            .links
            .iter()
            .flat_map(|l| l.neighbors.iter())
            .filter(|n| n.was_full)
            .count();
        self.restarting = Some(RestartingState {
            grace_period: cp.grace_period_secs,
            reason: ospf_packet::GraceRestartReason::from(cp.restart_reason),
            entered_at,
            abort_timer: Some(abort_timer),
            expected_full_count,
            current_full_count: 0,
        });

        // Delete the on-disk file immediately. The next restart's
        // commit handler writes a fresh one; replaying a stale
        // file on a second boot would propagate the wrong LSDB.
        let _ = OspfCheckpoint::delete(&path);

        tracing::info!(
            "[GR Restart] restored from checkpoint at {}: router-id={}, {} area(s), {} LSA(s), grace remaining ~{:?}",
            path.display(),
            cp.router_id,
            cp.areas.len(),
            total_lsas,
            remaining,
        );
    }

    pub fn gr_restart_abort(&mut self) {
        if self.restarting.take().is_none() {
            return;
        }

        let ifindices: Vec<u32> = self
            .links
            .iter()
            .filter(|(_, link)| link.enabled)
            .map(|(ifindex, _)| *ifindex)
            .collect();
        for ifindex in &ifindices {
            self.flush_grace_lsa(*ifindex);
        }

        self.router_info_lsa_originate();
        tracing::info!("[GR Restart] aborted; Grace LSAs flushed, gr_capable cleared");
    }

    /// Exit-restart success. Fired by
    /// `process_neighbor_state_change` once
    /// `current_full_count >= expected_full_count`.
    ///
    /// Clears `self.restarting` (which unblocks the
    /// `in_restart()` gates on `router_lsa_originate` /
    /// `update_network_lsa_by_interface` / `network_lsa_flush`),
    /// re-originates the topology-affecting self-LSAs at
    /// `seq+1` so helpers see the restart cleanly conclude,
    /// flushes our Grace LSAs (MaxAge re-flood) so helpers
    /// drop helper mode, and clears `gr_capable` from the
    /// Router-Info LSA via `router_info_lsa_originate`.
    ///
    /// Idempotent — no-op when called outside restart mode
    /// (e.g. if `GrRestartAbort` already ran first).
    pub fn gr_restart_exit_success(&mut self) {
        if self.restarting.take().is_none() {
            return;
        }

        let ifindices: Vec<u32> = self
            .links
            .iter()
            .filter(|(_, link)| link.enabled)
            .map(|(ifindex, _)| *ifindex)
            .collect();

        // Flush our Grace LSAs first so helpers see them
        // MaxAge'd before the fresh-seq topology LSAs arrive.
        for ifindex in &ifindices {
            self.flush_grace_lsa(*ifindex);
        }

        // Re-originate at seq+1 for every topology-affecting
        // self LSA. `router_lsa_originate` covers Router-LSA;
        // per-interface Network-LSA / Extended-Link comes from
        // `update_network_lsa_by_interface` /
        // `ext_link_lsa_originate` per DR-eligible link. The
        // `in_restart()` gates were lifted by the take() above.
        self.router_lsa_originate();
        for ifindex in &ifindices {
            self.update_network_lsa_by_interface(*ifindex);
            self.ext_link_lsa_originate(*ifindex);
        }
        // Router-Info refresh clears the gr_capable bit.
        self.router_info_lsa_originate();

        tracing::info!("[GR Restart] exit-restart success; LSAs re-originated at seq+1");
    }

    /// Commit a staged graceful restart (RFC 3623 §2):
    ///
    ///   1. Build a checkpoint and atomically write it to
    ///      `/var/lib/zebra-rs/checkpoint/ospf.cbor` (or the
    ///      `ZEBRA_OSPF_CHECKPOINT_DIR` override).
    ///   2. Arm a drain timer for `gr_config.drain_time_ms` so
    ///      the previously-flooded Grace LSAs reach the wire.
    ///   3. When the timer fires, `Message::GrRestartExit` runs
    ///      `std::process::exit(0)` — the supervisor (systemd /
    ///      operator script) is responsible for restarting us.
    ///
    /// Kernel routes installed by the OSPFv2 instance survive the
    /// exit because the protocol task dies without calling
    /// `despawn_ospf` (which fires `ProtoCleanup` / withdraws
    /// every route). The restart-aware boot path reclaims
    /// ownership of those routes via checkpoint replay.
    ///
    /// Returns `false` if no restart is staged or the checkpoint
    /// write fails; the caller (vty handler) reports failure.
    pub fn gr_restart_commit(&mut self) -> bool {
        use super::checkpoint::{OspfCheckpoint, default_path};
        use crate::context::Timer;

        let Some(state) = self.restarting.as_ref() else {
            tracing::warn!("[GR Restart] commit rejected — no restart staged");
            return false;
        };
        let grace_period = state.grace_period;
        let reason: u8 = state.reason.into();

        let cp = OspfCheckpoint::from_instance(self, grace_period, reason);
        let path = default_path("ospf");
        if let Err(e) = cp.write_to_path(&path) {
            tracing::warn!(
                "[GR Restart] commit aborted: checkpoint write to {} failed: {}",
                path.display(),
                e
            );
            return false;
        }
        tracing::info!(
            "[GR Restart] committed: checkpoint at {} ({} areas, {} links), drain={}ms",
            path.display(),
            cp.areas.len(),
            cp.links.len(),
            self.gr_config.drain_time_ms
        );

        // Arm the drain timer. When it fires the handler in
        // `process_msg` calls `process::exit(0)`. We don't try to
        // tear down the runtime gracefully — that's the
        // supervisor's job after we exit.
        let tx = self.tx.clone();
        let drain_ms = self.gr_config.drain_time_ms as u64;
        let drain_timer = Timer::once_ms(drain_ms, move || {
            let tx = tx.clone();
            async move {
                let _ = tx.send(Message::GrRestartExit);
            }
        });
        // Park the timer on the existing RestartingState so it
        // doesn't get dropped before firing. Replaces the
        // auto-abort timer — committed restarts don't auto-abort.
        if let Some(state) = self.restarting.as_mut() {
            state.abort_timer = Some(drain_timer);
        }
        true
    }

    /// Build a Grace LSA for `ifindex` and emit it on that
    /// interface only (link-local scope).
    ///
    /// Returns `true` on success, `false` if the interface has no
    /// primary IPv4 address or otherwise can't be staged.
    fn originate_grace_lsa(
        &mut self,
        ifindex: u32,
        grace_period: u32,
        reason: ospf_packet::GraceRestartReason,
    ) -> bool {
        use ospf_packet::{GraceLsa, GraceTlv, OpaqueLsaType, OspfLsType, OspfLsaHeader, OspfLsp};

        let Some(link) = self.links.get(&ifindex) else {
            return false;
        };
        let Some(addr) = link.addr.first() else {
            return false;
        };
        let if_addr = addr.prefix.addr();

        // Opaque-link-local LSA (LSA type 9), opaque type 3
        // (Grace), opaque-id 0 — RFC 3623 §A.1 doesn't constrain
        // the opaque-id; FRR uses 0 too.
        let ls_id = Ipv4Addr::from((OpaqueLsaType::GRACE as u32) << 24);
        let body = GraceLsa {
            tlvs: vec![
                GraceTlv::GracePeriod(grace_period),
                GraceTlv::Reason(reason),
                GraceTlv::IpInterfaceAddress(if_addr),
            ],
        };
        let mut h = OspfLsaHeader::new(OspfLsType::OpaqueLinkLocal, ls_id, self.router_id);
        h.options = 0x42; // O-bit + E-bit.

        // Preserve seq number across re-stages.
        let area_id = link.area;
        if let Some(area) = self.areas.get(area_id)
            && let Some(existing) =
                area.lsdb
                    .lookup_by_id(OspfLsType::OpaqueLinkLocal, ls_id, self.router_id)
        {
            h.ls_seq_number = seq_max(h.ls_seq_number, existing.h.ls_seq_number.saturating_add(1));
        }
        let mut lsa = OspfLsa::from(h, OspfLsp::OpaqueLinkLocalGrace(body));
        lsa.update();

        // Install into the area LSDB (v2's link-local LSAs live
        // there for lookup purposes) and emit on this interface
        // alone.
        let flood_copy = lsa.clone();
        if let Some(area) = self.areas.get_mut(area_id) {
            area.lsdb
                .insert_self_originated(lsa, &self.tx, Some(area_id));
        }
        self.flood_link_scope_lsa_v2(ifindex, &flood_copy);
        true
    }

    /// Pre-age a previously-originated Grace LSA to MaxAge and
    /// re-flood on `ifindex`. Called from `gr_restart_abort` to
    /// drop helpers cleanly. No-op if no prior Grace LSA exists.
    fn flush_grace_lsa(&mut self, ifindex: u32) {
        use ospf_packet::{OpaqueLsaType, OspfLsType};

        let ls_id = Ipv4Addr::from((OpaqueLsaType::GRACE as u32) << 24);
        let Some(link) = self.links.get(&ifindex) else {
            return;
        };
        let area_id = link.area;
        let flushed = if let Some(area) = self.areas.get_mut(area_id) {
            area.lsdb.flush_lsa(
                OspfLsType::OpaqueLinkLocal,
                ls_id,
                self.router_id,
                &self.tx,
                Some(area_id),
            )
        } else {
            None
        };
        if let Some(lsa) = flushed {
            self.flood_link_scope_lsa_v2(ifindex, &lsa);
        }
    }

    /// Emit `lsa` to every Exchange-or-later neighbor on
    /// `ifindex`, bypassing the area-wide fanout. Used for
    /// link-local-scope LSAs (Grace) that must not cross the
    /// segment they were originated on.
    fn flood_link_scope_lsa_v2(&mut self, ifindex: u32, lsa: &OspfLsa) {
        let now = chrono::Utc::now();
        let chains = self.key_chains.clone();
        let Some(link) = self.links.get_mut(&ifindex) else {
            return;
        };
        let area = link.area;
        let ctx = link.auth_send_ctx(&chains, now);
        for (_, nbr) in link.nbrs.iter_mut() {
            if nbr.state < NfsmState::Exchange {
                continue;
            }
            let ls_upd = OspfLsUpdate {
                num_adv: 1,
                lsas: vec![lsa.clone()],
            };
            let mut packet =
                Ospfv2Packet::new(&self.router_id, &area, Ospfv2Payload::LsUpdate(ls_upd));
            super::packet::apply_link_auth(&mut packet, &ctx);
            let _ = nbr.ptx.send(Message::Send(
                packet,
                nbr.ifindex,
                Some(nbr.ident.prefix.addr()),
            ));
        }
    }

    /// Flood an LSA to all eligible neighbors in an area (RFC 2328 Section 13.3).
    ///
    /// When `source` is `Some((ifindex, addr))`, the neighbor identified by that
    /// (interface, address) pair is skipped (it sent us this LSA). When `source`
    /// is `None` (self-originated), no neighbor is skipped.
    fn flood_lsa_through_area(
        &mut self,
        area_id: Ipv4Addr,
        lsa: &OspfLsa,
        source: Option<(u32, Ipv4Addr)>,
    ) {
        // RFC 3623 §3.2 bullets 2-3 — every LSA that reaches the
        // flood-out path was just installed in the area LSDB, so
        // this is the choke point for the topology-change exit
        // check. Runs before the fanout iteration so a helper exit
        // can deconstruct any state we'd otherwise loop over.
        self.gr_helper_check_exit(area_id, lsa);

        let Some(area) = self.areas.get(area_id) else {
            return;
        };
        let link_indices: Vec<u32> = area.links.iter().copied().collect();
        let now = chrono::Utc::now();
        for ifindex in link_indices {
            let chains = &self.key_chains;
            let Some(link) = self.links.get_mut(&ifindex) else {
                continue;
            };
            let retransmit_interval = link.retransmit_interval();
            let link_state = link.state;
            let auth_mode = link.auth_mode();
            let auth_key = link.config.auth_key;
            let crypto_key = link.resolve_active_send_key(chains, now);
            let md5_seq_cell = &link.md5_seq;

            // RFC 2328 Section 13.3 Step 2-4: DR/BDR flooding decision.
            let is_source_iface = source.is_some_and(|(src_if, _)| src_if == ifindex);

            // RFC 2328 Section 13.3 Step 3: If interface state is Backup and
            // LSA was received on this interface, do not flood back out.
            if is_source_iface && link_state == IfsmState::Backup {
                continue;
            }

            // RFC 2328 Section 13.3 Step 4: For broadcast/NBMA interfaces in
            // state DROther, only flood if we received from DR or BDR.
            if is_source_iface
                && link_state == IfsmState::DROther
                && let Some((_, src_addr)) = source
            {
                let dr = link.ident.d_router;
                let bdr = link.ident.bd_router;
                if src_addr != dr && src_addr != bdr {
                    continue;
                }
            }

            for (_, nbr) in link.nbrs.iter_mut() {
                // RFC 2328 Section 13.3 Step 1(a): Skip neighbors below Exchange.
                if nbr.state < NfsmState::Exchange {
                    continue;
                }

                // RFC 2328 Section 13.3 Step 1(c): Skip the source neighbor.
                if let Some((src_ifindex, src_addr)) = source
                    && nbr.ifindex == src_ifindex
                    && nbr.ident.prefix.addr() == src_addr
                {
                    continue;
                }

                // RFC 2328 Section 13.3 Step 1(b): For neighbors in
                // Exchange or Loading state, remove from ls_req if present.
                if nbr.state >= NfsmState::Exchange
                    && nbr.state < NfsmState::Full
                    && let Some(idx) = super::ospf_ls_request_lookup(nbr, &lsa.h)
                {
                    nbr.ls_req.remove(idx);
                }

                // RFC 2328 Section 13.3 Step 1(d): Add LSA to retransmit list.
                super::flood::ospf_ls_retransmit_add(nbr, lsa, retransmit_interval);

                let ls_upd = OspfLsUpdate {
                    num_adv: 1,
                    lsas: vec![lsa.clone()],
                };
                let mut packet =
                    Ospfv2Packet::new(&self.router_id, &area_id, Ospfv2Payload::LsUpdate(ls_upd));
                apply_link_auth(
                    &mut packet,
                    &build_auth_ctx(auth_mode, auth_key, crypto_key.clone(), md5_seq_cell),
                );
                tracing::info!(
                    "[Flood] Sending LSA type={:?} id={} adv={} to nbr={}",
                    lsa.h.ls_type,
                    lsa.h.ls_id,
                    lsa.h.adv_router,
                    nbr.ident.prefix.addr()
                );
                let _ = nbr.ptx.send(Message::Send(
                    packet,
                    nbr.ifindex,
                    Some(nbr.ident.prefix.addr()),
                ));
            }
        }
    }

    /// Flood a self-originated LSA to all eligible neighbors in an area.
    fn flood_self_originated_lsa(&mut self, area_id: Ipv4Addr, lsa: &OspfLsa) {
        self.flood_lsa_through_area(area_id, lsa, None);
    }

    /// Flood an AS-scoped LSA to all non-stub areas.
    fn flood_lsa_through_as(&mut self, lsa: &OspfLsa, source: Option<(u32, Ipv4Addr)>) {
        // Collect area IDs to avoid borrowing issues.
        let area_ids: Vec<(Ipv4Addr, super::area::AreaType)> = self
            .areas
            .iter()
            .map(|(&id, area)| (id, area.area_type))
            .collect();
        for (area_id, area_type) in area_ids {
            if area_type.is_stub_or_nssa() {
                continue;
            }
            self.flood_lsa_through_area(area_id, lsa, source);
        }
    }

    /// Handle retransmit timer firing for a neighbor.
    fn process_retransmit(&mut self, ifindex: u32, addr: Ipv4Addr) {
        let now = chrono::Utc::now();
        let chains = &self.key_chains;
        let Some(link) = self.links.get_mut(&ifindex) else {
            return;
        };
        let retransmit_interval = link.retransmit_interval();
        let area_id = link.area;
        let auth_mode = link.auth_mode();
        let auth_key = link.config.auth_key;
        let crypto_key = link.resolve_active_send_key(chains, now);
        let md5_seq_cell = &link.md5_seq;
        let Some(nbr) = link.nbrs.get_mut(&addr) else {
            return;
        };
        if nbr.ls_rxmt.is_empty() {
            nbr.timer.ls_rxmt = None;
            return;
        }
        let lsas: Vec<OspfLsa> = nbr.ls_rxmt.values().cloned().collect();
        tracing::info!("[Retransmit] Sending {} LSAs to {}", lsas.len(), addr);
        let ls_upd = OspfLsUpdate {
            num_adv: lsas.len() as u32,
            lsas,
        };
        let mut packet =
            Ospfv2Packet::new(&self.router_id, &area_id, Ospfv2Payload::LsUpdate(ls_upd));
        apply_link_auth(
            &mut packet,
            &build_auth_ctx(auth_mode, auth_key, crypto_key.clone(), md5_seq_cell),
        );
        let _ = nbr.ptx.send(Message::Send(
            packet,
            nbr.ifindex,
            Some(nbr.ident.prefix.addr()),
        ));
        // Restart retransmit timer.
        nbr.timer.ls_rxmt = Some(super::flood::ospf_retransmit_timer(
            nbr,
            retransmit_interval,
        ));
    }

    /// Handle Database Description master-retransmit timer firing
    /// (RFC 2328 §10.8). Resend the DD packet stored in `nbr.dd.sent` while
    /// the master is still in ExStart or Exchange. The timer is replaced
    /// (not cancelled) when the master sends the next DD; once the neighbor
    /// progresses past Exchange the regular timer-set logic clears it.
    fn process_dd_retransmit(&mut self, ifindex: u32, addr: Ipv4Addr) {
        let Some((link, nbr)) = self.ospf_interface(ifindex, &addr) else {
            return;
        };
        if (nbr.state != NfsmState::ExStart && nbr.state != NfsmState::Exchange)
            || !nbr.dd.flags.master()
        {
            nbr.timer.db_desc = None;
            return;
        }
        let Some(ref sent) = nbr.dd.sent else {
            return;
        };
        let mut packet = Ospfv2Packet::new(
            link.router_id,
            &link.area_id,
            Ospfv2Payload::DbDesc(sent.clone()),
        );
        apply_link_auth(&mut packet, &link.auth_send_ctx());
        tracing::info!("[DB Desc:Retransmit] to {} seq={:#x}", addr, sent.seqnum);
        let _ = nbr.ptx.send(Message::Send(
            packet,
            nbr.ifindex,
            Some(nbr.ident.prefix.addr()),
        ));
    }

    /// Handle Link State Request retransmit timer firing for a neighbor
    /// (RFC 2328 §10.9). Resend the pending LS Request packet built from
    /// `nbr.ls_req`. Stop the timer once the list is empty or the neighbor
    /// has left Exchange/Loading.
    fn process_ls_req_retransmit(&mut self, ifindex: u32, addr: Ipv4Addr) {
        let Some((mut link, nbr)) = self.ospf_interface(ifindex, &addr) else {
            return;
        };
        if nbr.state < NfsmState::Exchange || nbr.state >= NfsmState::Full || nbr.ls_req.is_empty()
        {
            nbr.timer.ls_req = None;
            return;
        }
        let ident = link.ident;
        super::ospf_ls_req_send(&mut link, nbr, ident);
    }

    /// Handle delayed ack timer firing for an interface.
    fn process_delayed_ack(&mut self, ifindex: u32) {
        let now = chrono::Utc::now();
        let chains = &self.key_chains;
        let Some(link) = self.links.get_mut(&ifindex) else {
            return;
        };
        // This is a one-shot timer; clear the handle so future queued acks can re-arm it.
        link.timer.ls_ack = None;
        if link.ls_ack_delayed.is_empty() {
            return;
        }
        let ack_headers: Vec<OspfLsaHeader> = link.ls_ack_delayed.drain(..).collect();
        tracing::info!(
            "[DelayedAck] Sending {} acks on ifindex={}",
            ack_headers.len(),
            ifindex
        );
        let ls_ack = OspfLsAck {
            lsa_headers: ack_headers,
        };
        let mut packet =
            Ospfv2Packet::new(&self.router_id, &link.area, Ospfv2Payload::LsAck(ls_ack));
        apply_link_auth(&mut packet, &link.auth_send_ctx(chains, now));
        // Send to AllSPFRouters multicast.
        let _ = link.ptx.send(Message::Send(packet, ifindex, None));
    }

    /// Queue delayed ack headers and start delayed ack timer if needed.
    fn queue_delayed_acks(&mut self, ifindex: u32, headers: Vec<OspfLsaHeader>) {
        let Some(link) = self.links.get_mut(&ifindex) else {
            return;
        };
        link.ls_ack_delayed.extend(headers);
        // Start delayed ack timer if not already running (1 second interval).
        if link.timer.ls_ack.is_none() {
            let tx = self.tx.clone();
            link.timer.ls_ack = Some(Timer::new(1, TimerType::Once, move || {
                let tx = tx.clone();
                async move {
                    let _ = tx.send(Message::DelayedAck(ifindex));
                }
            }));
        }
    }

    pub(super) fn router_id_update(&mut self, router_id: Ipv4Addr) {
        // Flush everything we originated under the PREVIOUS Router-ID
        // before adopting the new one. Self-originated LSAs are keyed by
        // advertising router, so once our Router-ID changes the old
        // instances are no longer "self" — nothing refreshes them and
        // they would linger as phantom nodes in every router's LSDB
        // until they age out at MaxAge (~1 h). Pre-aging + re-flooding
        // them now withdraws the stale identity immediately.
        let old_router_id = self.router_id;
        if old_router_id != router_id {
            self.flush_self_originated_under(old_router_id);
        }

        self.router_id = router_id;
        for (_, link) in self.links.iter_mut() {
            link.ident.router_id = router_id;
        }
        self.router_lsa_originate();
    }

    /// Flush (pre-age to MaxAge + re-flood) every LSA we originated
    /// under `old_router_id` — the per-area Router/Network/Summary/
    /// Opaque LSAs plus AS-External LSAs. Called from
    /// [`Self::router_id_update`] when the effective Router-ID moves so
    /// the database advertised under our former identity is withdrawn
    /// instead of lingering until MaxAge.
    fn flush_self_originated_under(&mut self, old_router_id: Ipv4Addr) {
        if self.in_restart() {
            return;
        }
        // Per-area LSDBs.
        let area_ids: Vec<Ipv4Addr> = self.areas.iter().map(|(id, _)| *id).collect();
        for area_id in area_ids {
            let keys: Vec<OspfLsaKey> = match self.areas.get(area_id) {
                Some(area) => area
                    .lsdb
                    .tables
                    .keys()
                    .filter(|(_, _, adv)| *adv == old_router_id)
                    .copied()
                    .collect(),
                None => continue,
            };
            for key in keys {
                let flushed = if let Some(area) = self.areas.get_mut(area_id) {
                    area.lsdb.flush_lsa_by_raw_key(key, &self.tx, Some(area_id))
                } else {
                    None
                };
                if let Some(lsa) = flushed {
                    self.flood_self_originated_lsa(area_id, &lsa);
                }
            }
        }
        // AS-External LSDB (Type-5), flooded AS-wide.
        let as_keys: Vec<OspfLsaKey> = self
            .lsdb_as
            .tables
            .keys()
            .filter(|(_, _, adv)| *adv == old_router_id)
            .copied()
            .collect();
        for key in as_keys {
            if let Some(lsa) = self.lsdb_as.flush_lsa_by_raw_key(key, &self.tx, None) {
                self.flood_lsa_through_as(&lsa, None);
            }
        }

        // Per-link LSDBs: link-scope Opaque LSAs (e.g. the Extended-Link
        // LSA that carries an Adj-SID) live in `link.lsdb`, not the area
        // LSDB. Flush + re-flood them on their link so a peer's
        // link-scope database doesn't keep the old identity around.
        let ifindices: Vec<u32> = self.links.keys().copied().collect();
        for ifindex in ifindices {
            let keys: Vec<OspfLsaKey> = match self.links.get(&ifindex) {
                Some(link) => link
                    .lsdb
                    .tables
                    .keys()
                    .filter(|(_, _, adv)| *adv == old_router_id)
                    .copied()
                    .collect(),
                None => continue,
            };
            for key in keys {
                let flushed = if let Some(link) = self.links.get_mut(&ifindex) {
                    link.lsdb.flush_lsa_by_raw_key(key, &self.tx, None)
                } else {
                    None
                };
                if let Some(lsa) = flushed {
                    self.flood_link_scope_lsa_v2(ifindex, &lsa);
                }
            }
        }
    }

    /// Recompute the effective Router ID from its sources —
    /// configured `router-id` wins, RIB-derived second, constructor
    /// default last — and apply it (links + Router-LSA re-origination)
    /// when it moved. Both the config callback and the
    /// `RibRx::RouterIdUpdate` arm funnel through here, so a
    /// configured value can't be stomped by a RIB push and a config
    /// delete falls back instead of keeping the stale value.
    pub(super) fn refresh_router_id(&mut self) {
        let effective = self
            .router_id_config
            .or(self.rib_router_id)
            .unwrap_or(DEFAULT_ROUTER_ID);
        if self.router_id != effective {
            self.router_id_update(effective);
        }
    }

    fn addr_add(&mut self, addr: LinkAddr) {
        // println!("OSPF: AddrAdd {} {}", addr.addr, addr.ifindex);
        let Some(link) = self.links.get_mut(&addr.ifindex) else {
            return;
        };
        let IpNet::V4(prefix) = &addr.addr else {
            return;
        };
        // Duplicate-delivery guard — see `link_addr_push_unique` for
        // why the same address arrives multiple times. Without it the
        // Router-LSA repeats the stub network once per delivery.
        let ospf_addr = OspfAddr::from(&addr, prefix);
        super::addr::link_addr_push_unique(&mut link.addr, ospf_addr);
        link.ident.prefix = *prefix;

        // If this address made an enabled-but-Down interface usable,
        // re-fire `InterfaceUp` so the FSM can progress past the
        // empty-`addr` short-circuit in `ospf_ifsm_interface_up`.
        // OSPF-enable can be processed before the interface address
        // has propagated from netlink (config commit applies both at
        // once); without this re-fire a transit interface stays Down
        // forever — no Hellos, no multicast join, no adjacency. v3's
        // `addr_add` already did this; v2 was missing it.
        if link.enabled && link.state == IfsmState::Down {
            let _ = self
                .tx
                .send(Message::Ifsm(addr.ifindex, IfsmEvent::InterfaceUp));
        }

        // The Prefix-SID's Extended-Prefix LSA advertises this link's
        // first non-loopback address as a /32 host prefix. The config
        // handler originates it at commit time, but the kernel's
        // AddrAdd for an address configured in the same commit can
        // land *after* that — origination then finds no usable
        // address and bails without retry. Re-originate here so the
        // LSA appears as soon as the address does (no-op on links
        // without SR + a configured prefix-sid). Mirrors the v3
        // `addr_add` fix.
        self.ext_prefix_lsa_originate(addr.ifindex);
    }

    fn addr_del(&mut self, addr: LinkAddr) {
        let Some(link) = self.links.get_mut(&addr.ifindex) else {
            return;
        };
        let IpNet::V4(prefix) = &addr.addr else {
            return;
        };
        link.addr.retain(|a| a.prefix != *prefix);

        // Re-evaluate enable state after address removal.
        let (next, next_id) = super::config::link_should_enable(link);
        super::config::apply_link_enable_transition(link, next, next_id);

        // Mirror of the `addr_add` re-origination: the advertised
        // host prefix may have just gone away or a different
        // remaining address now wins.
        self.ext_prefix_lsa_originate(addr.ifindex);
    }

    async fn process_recv(
        &mut self,
        packet: Ospfv2Packet,
        src: Ipv4Addr,
        _from: Ipv4Addr,
        index: u32,
        _dest: Ipv4Addr,
    ) {
        // Drop self-originated packets (e.g. received on loopback interface).
        if packet.router_id == self.router_id {
            return;
        }

        // RFC 2328 §D.4: AuType + auth field must match the
        // receiving interface's configured authentication. RFC §D.5
        // adds anti-replay for Type 2 — packets with a seq below
        // the per-neighbor high-watermark are dropped.
        {
            let chains = &self.key_chains;
            let now = chrono::Utc::now();
            let Some(link) = self.links.get(&index) else {
                return;
            };
            let last_seq = link
                .nbrs
                .get(&src)
                .map(|n| n.auth_md5_last_seq)
                .unwrap_or(0);
            // Build the key source: chain takes precedence when the
            // interface names one; otherwise the per-interface
            // `crypto_keys` map serves the cryptographic-auth
            // configuration.
            let key_source = match link.config.key_chain.as_deref() {
                Some(name) => match chains.get(name) {
                    Some(c) => crate::ospf::packet::KeySource::Chain { chain: c, now },
                    None => {
                        tracing::debug!(
                            "OSPFv2 auth drop on {} from {}: chain `{}` not configured",
                            link.name,
                            src,
                            name
                        );
                        return;
                    }
                },
                None => crate::ospf::packet::KeySource::PerIface(&link.config.crypto_keys),
            };
            if !verify_link_auth(
                &packet,
                link.auth_mode(),
                link.config.auth_key,
                &key_source,
                last_seq,
            ) {
                tracing::debug!(
                    "OSPFv2 auth drop on {} from {}: type={} expected={:?}",
                    link.name,
                    src,
                    packet.auth_type,
                    link.auth_mode(),
                );
                return;
            }
        }

        match packet.typ {
            OspfType::Hello => {
                let Some(link) = self.links.get_mut(&index) else {
                    return;
                };
                ospf_hello_recv(&self.router_id, link, &packet, &src, &self.tracing);
                // Hello creates the neighbor on first sight; stamp
                // the accepted seq after the create so subsequent
                // packets from this peer enforce monotonicity.
                if let Some(nbr) = link.nbrs.get_mut(&src) {
                    record_md5_seq(&packet, nbr);
                }
            }
            OspfType::DbDesc => {
                let Some((mut link, nbr)) = self.ospf_interface(index, &src) else {
                    return;
                };
                record_md5_seq(&packet, nbr);
                ospf_db_desc_recv(&mut link, nbr, &packet, &src);
            }
            OspfType::LsRequest => {
                let Some((mut link, nbr)) = self.ospf_interface(index, &src) else {
                    return;
                };
                record_md5_seq(&packet, nbr);
                ospf_ls_req_recv(&mut link, nbr, &packet, &src);
            }
            OspfType::LsUpdate => {
                let Some((mut link, nbr)) = self.ospf_interface(index, &src) else {
                    return;
                };
                record_md5_seq(&packet, nbr);
                ospf_ls_upd_recv(&mut link, nbr, &packet, &src);
            }
            OspfType::LsAck => {
                let Some((mut link, nbr)) = self.ospf_interface(index, &src) else {
                    return;
                };
                record_md5_seq(&packet, nbr);
                ospf_ls_ack_recv(&mut link, nbr, &packet, &src);
            }
            OspfType::Unknown(_typ) => {
                // println!("Unknown: packet type {}", typ);
            }
        }
    }

    async fn process_msg(&mut self, msg: Message) {
        match msg {
            Message::Enable(ifindex, area_id) => {
                let Some(link) = self.links.get_mut(&ifindex) else {
                    return;
                };
                link.enabled = true;
                link.area = area_id;
                link.area_id = area_id;
                // Sync the runtime network_type from config at enable
                // time so IFSM / NFSM / Router-LSA emission key off
                // the operator's choice (default Broadcast).
                link.network_type = link.config_network_type();
                let area = self.areas.fetch(area_id);
                area.links.insert(ifindex);
                let area_type = area.area_type;
                if let Some(link) = self.links.get_mut(&ifindex) {
                    link.area_type = area_type;
                }
                self.router_lsa_originate();
                let _ = self.tx.send(Message::Ifsm(ifindex, IfsmEvent::InterfaceUp));
                // Adding a link to an area may turn this router into
                // an ABR (gained interface in a 2nd area). Resync
                // every NSSA area's translator state — the helper
                // gates on `is_abr()` internally.
                self.nssa_translate_resync_all();
            }
            Message::Disable(ifindex, area_id) => {
                // Flush self-originated Network-LSA *before* clearing
                // the link's area binding so the flush helper can read
                // through `link.addr` / `link.area` to find the LSA
                // key. Mirrors v3's Disable handler at inst.rs:2356.
                self.network_lsa_flush(ifindex, area_id);

                let Some(link) = self.links.get_mut(&ifindex) else {
                    return;
                };
                link.enabled = false;
                link.area = Ipv4Addr::UNSPECIFIED;
                link.area_id = Ipv4Addr::UNSPECIFIED;
                link.area_type = super::area::AreaType::default();
                let area = self.areas.fetch(area_id);
                area.links.remove(&ifindex);
                self.router_lsa_originate();
                let _ = self
                    .tx
                    .send(Message::Ifsm(ifindex, IfsmEvent::InterfaceDown));
                // Dropping a link may turn this router back into a
                // non-ABR (lost interface in the area). Flush any
                // translated Type-5s if we no longer qualify.
                self.nssa_translate_resync_all();
            }
            Message::Recv(packet, src, from, index, dest) => {
                self.process_recv(packet, src, from, index, dest).await;
            }
            Message::Ifsm(index, ev) => {
                // Snapshot pre-state so we can detect a DR-leave
                // transition after `ospf_ifsm` runs and flush the
                // now-orphan Network-LSA. Without this, the
                // self-originated Network-LSA outlives our DR role
                // (election yield, network-type change, etc.) and
                // pollutes peers' LSDBs until MaxAge.
                let prev = self.links.get(&index).map(|l| (l.state, l.area_id));
                let Some(link) = self.links.get_mut(&index) else {
                    return;
                };
                ospf_ifsm(link, ev);
                if let Some((prev_state, area_id)) = prev {
                    let new_state = self.links.get(&index).map(|l| l.state);
                    if prev_state == IfsmState::DR && new_state != Some(IfsmState::DR) {
                        self.network_lsa_flush(index, area_id);
                    }
                    // Re-originate the per-link Extended-Link Opaque LSA
                    // on any IFSM state change. For broadcast / NBMA the
                    // `link_id` is the DR's interface address (RFC 7684
                    // §3) so a DR election outcome must trigger a
                    // refresh; the originator gates on its own
                    // preconditions and flushes when they no longer
                    // hold. P2P sees no semantic change here.
                    if let Some(new) = new_state
                        && new != prev_state
                    {
                        let ifname = self.links.get(&index).map(|l| l.name.clone());
                        ospf_fsm_trace!(
                            self.tracing,
                            Ifsm,
                            false,
                            ifindex = index,
                            interface = ifname.as_deref().unwrap_or("?"),
                            from = ?prev_state,
                            to = ?new,
                            "IFSM transition"
                        );
                        self.ext_link_lsa_originate(index);
                    }
                }
            }
            Message::Nfsm(index, src, ev) => {
                let old_state = self
                    .links
                    .get(&index)
                    .and_then(|link| link.nbrs.get(&src))
                    .map(|nbr| nbr.state);

                if let Some((mut link, nbr)) = self.ospf_interface(index, &src) {
                    let ident = link.ident;
                    ospf_nfsm(&mut link, nbr, ev, ident);
                }

                if matches!(ev, NfsmEvent::InactivityTimer) {
                    // InactivityTimer destroys the neighbor (dead-timer
                    // expiry, BFD-down, or `clear ospf neighbor`).
                    // `ospf_nfsm` reset its lists but, per its "the
                    // caller will delete it" contract, left the actual
                    // removal to us; do it so the instance is really
                    // gone and a later Hello re-forms it from scratch.
                    self.nfsm_kill_neighbor(index, src, old_state);
                } else {
                    let new_state = self
                        .links
                        .get(&index)
                        .and_then(|link| link.nbrs.get(&src))
                        .map(|nbr| nbr.state);

                    if let (Some(old_state), Some(new_state)) = (old_state, new_state) {
                        if old_state != new_state {
                            ospf_fsm_trace!(
                                self.tracing,
                                Nfsm,
                                false,
                                neighbor = %src,
                                event = ?ev,
                                from = ?old_state,
                                to = ?new_state,
                                "NFSM transition"
                            );
                        }
                        self.process_neighbor_state_change(index, src, old_state, new_state);
                        // Re-evaluate the BFD session against the configured
                        // threshold (the reconcile reads the now-current
                        // neighbor state, so it covers both 2-Way and Full).
                        self.bfd_reconcile_nbr(index, src);
                        // Likewise the STAMP measurement session, which is
                        // gated on a Full neighbor (and tears down the
                        // moment Full is lost).
                        self.stamp_reconcile_and_originate(index);
                    }
                }
            }
            Message::HelloTimer(index) => {
                let now = chrono::Utc::now();
                let chains = &self.key_chains;
                let tracing = &self.tracing;
                let Some(link) = self.links.get_mut(&index) else {
                    return;
                };
                ospf_hello_send(link, chains, now, tracing);
            }
            Message::Lsdb(ev, area_id, key) => {
                self.process_lsdb(ev, area_id, key);
            }
            Message::Flood(area_id, lsa, source_ifindex, source_nbr_addr) => {
                self.flood_lsa_through_area(area_id, &lsa, Some((source_ifindex, source_nbr_addr)));
            }
            Message::FloodAs(lsa, source_ifindex, source_nbr_addr) => {
                self.flood_lsa_through_as(&lsa, Some((source_ifindex, source_nbr_addr)));
            }
            Message::Retransmit(ifindex, addr) => {
                self.process_retransmit(ifindex, addr);
            }
            Message::LsReqRetransmit(ifindex, addr) => {
                self.process_ls_req_retransmit(ifindex, addr);
            }
            Message::DdRetransmit(ifindex, addr) => {
                self.process_dd_retransmit(ifindex, addr);
            }
            Message::DelayedAck(ifindex) => {
                self.process_delayed_ack(ifindex);
            }
            Message::DelayedAckQueue(ifindex, headers) => {
                self.queue_delayed_acks(ifindex, headers);
            }
            Message::SpfSchedule(area_id) => {
                if let Some(area_id) = area_id {
                    if let Some(area) = self.areas.get_mut(area_id) {
                        Self::ospf_spf_schedule(&self.tx, area);
                    }
                } else {
                    // None = AS-scope event (e.g. AS-external LSA install /
                    // expiry); recompute SPF on every attached area so each
                    // area's RIB picks up the new external routes.
                    let area_ids: Vec<Ipv4Addr> = self.areas.iter().map(|(id, _)| *id).collect();
                    for id in area_ids {
                        if let Some(area) = self.areas.get_mut(id) {
                            Self::ospf_spf_schedule(&self.tx, area);
                        }
                    }
                }
            }
            Message::SpfCalc(area_id) => {
                let Some(area) = self.areas.get_mut(area_id) else {
                    return;
                };
                if area.spf_inflight {
                    // A SPF is already running for this area. Remember
                    // that another trigger arrived; the completion
                    // path re-fires exactly one follow-up SpfCalc.
                    area.spf_pending = true;
                    return;
                }
                area.spf_timer = None;
                // Build the SPF input (graph + source vertex) on the
                // main task — reads the LSDB and is cheap. If there
                // is no source node yet, there is nothing to compute.
                let Some(input) = build_spf_input(self, area_id) else {
                    return;
                };
                if let Some(area) = self.areas.get_mut(area_id) {
                    area.spf_inflight = true;
                }
                let tx = self.tx.clone();
                tokio::task::spawn_blocking(move || {
                    let output = compute_spf(input);
                    let _ = tx.send(Message::SpfDone(Box::new(output)));
                });
                tracing::info!("[SPF] Calculation dispatched for area {}", area_id);
            }
            Message::SpfDone(output) => {
                let area_id = output.area_id;
                apply_spf_result(self, *output);
                if let Some(area) = self.areas.get_mut(area_id) {
                    area.spf_inflight = false;
                    if std::mem::take(&mut area.spf_pending) {
                        let _ = self.tx.send(Message::SpfCalc(area_id));
                    }
                }
            }
            Message::GrHelperExpire(ifindex, router_id) => {
                self.gr_helper_expire(ifindex, router_id);
            }
            Message::GrRestartAbort => {
                tracing::info!(
                    "[GR Restart] auto-abort timer fired (no commit within grace period)"
                );
                self.gr_restart_abort();
            }
            Message::GrRestartExit => {
                tracing::info!("[GR Restart] drain complete; exiting process");
                std::process::exit(0);
            }
            Message::GrRestartExitSuccess => {
                self.gr_restart_exit_success();
            }
            Message::NssaTranslateResync(area_id) => {
                self.nssa_translate_resync(area_id);
            }
            _ => {}
        }
    }

    fn process_rib_msg(&mut self, msg: RibRx) {
        match msg {
            RibRx::RouterIdUpdate(router_id) => {
                // Remember the RIB-derived value and refresh: a
                // configured `router-id` keeps winning (this push
                // used to stomp it), and a later config delete falls
                // back to the stored value.
                self.rib_router_id = (!router_id.is_unspecified()).then_some(router_id);
                self.refresh_router_id();
            }
            RibRx::LinkAdd(link) => {
                self.link_add(link);
            }
            RibRx::LinkUp(ifindex) => {
                self.link_up(ifindex);
            }
            RibRx::LinkDown(ifindex) => {
                self.link_down(ifindex);
            }
            RibRx::LinkDel(ifindex) => {
                self.link_del(ifindex);
            }
            RibRx::LinkMtu { ifindex, mtu } => {
                self.link_mtu(ifindex, mtu);
            }
            RibRx::AddrAdd(addr) => {
                self.addr_add(addr);
            }
            RibRx::AddrDel(addr) => {
                self.addr_del(addr);
            }
            // Redistribute delivery. Today only `Connected` is
            // subscribed (per-area NSSA redistribute connected); the
            // handler updates the cache and resyncs Type-7 LSAs in
            // every NSSA area whose `redistribute connected` knob
            // is set.
            RibRx::RouteAdd { rtype, routes, .. } => {
                self.route_redist_add(rtype, routes);
            }
            RibRx::RouteDel { rtype, routes, .. } => {
                self.route_redist_del(rtype, routes);
            }
            // VRF master lifecycle (default instance only): spawn /
            // despawn the per-VRF OSPFv2 child once config intent +
            // kernel table_id both exist.
            RibRx::VrfAdd {
                name,
                table_id,
                ifindex,
            } => self.vrf_add(name, table_id, ifindex),
            RibRx::VrfDel { name } => self.vrf_del(name),
            _ => {
                //
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

    pub async fn event_loop(&mut self) {
        loop {
            match self.rib_rx.recv().await {
                Some(RibRx::EoR) => break,
                Some(msg) => self.process_rib_msg(msg),
                None => break,
            }
        }
        loop {
            tokio::select! {
                Some(msg) = self.rx.recv() => {
                    self.process_msg(msg).await;
                }
                Some(msg) = self.rib_rx.recv() => {
                    self.process_rib_msg(msg);
                }
                Some(msg) = self.cm.rx.recv() => {
                    self.process_cm_msg(msg);
                }
                Some(msg) = self.show.rx.recv() => {
                    self.process_show_msg(msg).await;
                }
                Some(msg) = self.policy_rx.recv() => {
                    self.process_policy_msg(msg);
                }
                Some(event) = self.bfd_event_rx.recv() => {
                    self.process_bfd_event(event);
                }
                Some(event) = self.stamp_event_rx.recv() => {
                    self.process_stamp_event(event);
                }
            }
        }
    }

    /// Handle a `PolicyRx` push from the policy actor. Today we only
    /// subscribe to key-chain updates, but the match is exhaustive
    /// against the enum so future variants don't silently no-op.
    /// Resolution is lazy (per packet, in `auth_send_ctx`) so all
    /// this needs to do is keep the snapshot fresh.
    fn process_policy_msg(&mut self, msg: crate::policy::PolicyRx) {
        match msg {
            crate::policy::PolicyRx::KeyChain {
                name, key_chain, ..
            } => {
                if let Some(kc) = key_chain {
                    self.key_chains.insert(name, kc);
                } else {
                    self.key_chains.remove(&name);
                }
            }
            crate::policy::PolicyRx::PrefixSet { .. }
            | crate::policy::PolicyRx::PolicyList { .. } => {
                // OSPF doesn't subscribe to prefix-set or policy-list.
            }
        }
    }
}

/// v3-specific methods on the parameterized `Ospf` instance.
///
/// Walks `Ospf<Ospfv3>` state to build wire LSAs, run the
/// IFSM/NFSM-driven send/receive paths, and drive SPF + RIB
/// installation. Entered from `spawn_ospfv3` in `crate::config::ospf`.
impl Ospf<Ospfv3> {
    /// Construct an `Ospf<Ospfv3>` instance.
    ///
    /// Mirrors the shape of `Ospf<Ospfv2>::new` (see above) so the
    /// two version-specific constructors stay readable side by side.
    /// The differences from v2:
    ///
    /// - **Socket.** Uses `ospf_socket_ipv6` — same IP protocol
    ///   number 89, but `Domain::IPV6` with `IPV6_MULTICAST_HOPS=1`
    ///   and `IPV6_RECVPKTINFO` enabled. `IPV6_V6ONLY` is not set
    ///   because Linux rejects it with `EINVAL` on raw sockets with
    ///   non-TCP/UDP protocols (raw v6 sockets don't surface
    ///   v4-mapped sources anyway).
    /// - **Router-id default.** Still 32-bit (RFC 5340 §2.1).
    /// - **No `callback_build` / `show_build`.** The v2 versions
    ///   register paths under `/router/ospf/...`; the v3 schema is
    ///   currently an empty `container ospfv3` stub with no Rust
    ///   handlers wired. The `callbacks` and `show_cb` maps stay
    ///   empty for v3 until the v3 config plumbing lands.
    /// - **No network read/write task spawn.** The v2 path uses
    ///   `read_packet` / `write_packet`, which are typed against
    ///   `Message<Ospfv2>` and the v2 wire format. The v3 wire path
    ///   uses `network_v6::{read_packet_v6, write_packet_v6}` —
    ///   spawned here, but the channels they drive are not yet
    ///   bridged into `Message<Ospfv3>` events. Until the v3 IFSM /
    ///   NFSM lands the rx side just buffers; producers will clone
    ///   `v3_send_tx` to push outgoing packets through the v6
    ///   socket. The four `build_*_lsa` self-origination helpers
    ///   above can still be exercised from tests.
    pub fn new(
        ctx: crate::context::ProtoContext,
        rib_rx: UnboundedReceiver<RibRx>,
        policy_tx: UnboundedSender<crate::policy::Message>,
        proto_label: String,
        rib_subscriber: RibSubscriber,
        config_tx: tokio::sync::mpsc::Sender<crate::config::Message>,
        bfd_client_tx: Option<UnboundedSender<crate::bfd::inst::ClientReq>>,
        stamp_client_tx: Option<UnboundedSender<crate::stamp::client::ClientReq>>,
    ) -> Self {
        let sock = Arc::new(AsyncFd::new(super::socket::ospf_socket_ipv6(&ctx).unwrap()).unwrap());
        let (bfd_event_tx, bfd_event_rx) = mpsc::unbounded_channel();
        let (stamp_event_tx, stamp_event_rx) = mpsc::unbounded_channel();

        let policy_chan = crate::policy::PolicyRxChannel::new();
        let _ = policy_tx.send(crate::policy::Message::Subscribe {
            proto: proto_label.clone(),
            tx: policy_chan.tx.clone(),
        });

        let (tx, rx) = mpsc::unbounded_channel();
        let (ptx, _prx) = mpsc::unbounded_channel();

        // SR snapshot subscription (locator watches for RFC 9513).
        // One-time registration keyed by the instance's proto label so
        // VRF children don't stomp the parent's channel.
        let (sr_tx, sr_rx) = mpsc::unbounded_channel();
        let _ = ctx.rib.send(crate::rib::Message::SrSubscribe {
            proto: proto_label.clone(),
            tx: sr_tx,
        });

        // v3 raw-IPv6 packet path. `read_packet_v6` recvmsg's,
        // verifies the RFC 5340 §4.4 pseudo-header checksum, parses
        // `Ospfv3Packet`, and pushes `Ospfv3Recv` items. `write_packet_v6`
        // consumes `Ospfv3Send` items, stamps the checksum using the
        // supplied (src, dst) v6, and sendmsg's with an `in6_pktinfo`
        // ancillary so the kernel emits from the chosen ifindex /
        // link-local source.
        let (v3_send_tx, v3_send_rx) = mpsc::unbounded_channel();
        let (v3_recv_tx, v3_recv_rx) = mpsc::unbounded_channel();
        {
            let sock = sock.clone();
            tokio::spawn(async move {
                super::network_v6::read_packet_v6(sock, v3_recv_tx).await;
            });
        }
        {
            let sock = sock.clone();
            tokio::spawn(async move {
                super::network_v6::write_packet_v6(sock, v3_send_rx).await;
            });
        }

        let mut ospf = Self {
            tx,
            rx,
            ptx,
            cm: ConfigChannel::new(),
            callbacks: HashMap::new(),
            rib_rx,
            ctx,
            links: BTreeMap::new(),
            bfd: OspfLinkBfdConfig::default(),
            areas: OspfAreaMap::new(),
            show: ShowChannel::new(),
            show_cb: HashMap::new(),
            router_id: DEFAULT_ROUTER_ID,
            router_id_config: None,
            rib_router_id: None,
            lsdb_as: Lsdb::new(),
            lsp_map: LspMap::default(),
            spf_result: None,
            graph: None,
            ti_lfa_enabled: false,
            ti_lfa_compute_mode: spf::TilfaComputeModeConfig::default(),
            // Matches the YANG `default 8` on the sharding `shards` leaf.
            ti_lfa_compute_shards: 8,
            tilfa_stats: None,
            fast_reroute_backup_as_primary: false,
            tilfa_result: None,
            spf_flex_algo: BTreeMap::new(),
            rib_flex_algo: BTreeMap::new(),
            rib6_flex_algo: BTreeMap::new(),
            rib: PrefixMap::new(),
            rib_areas: BTreeMap::new(),
            spf_results: BTreeMap::new(),
            ilm: BTreeMap::new(),
            ilm6: BTreeMap::new(),
            local_pool: None,
            lan_adj_sids: BTreeMap::new(),
            rib6: PrefixMap::new(),
            rib6_areas: BTreeMap::new(),
            tracing: OspfTracing::default(),
            segment_routing: super::srmpls::SegmentRoutingMode::default(),
            srv6_locator_name: None,
            watched_locator: None,
            sr_locator: None,
            sr_end_sid: None,
            elib: crate::isis::srv6::ElibPool::new(),
            endx_sids: BTreeMap::new(),
            sr_rx,
            gr_config: super::neigh::GracefulRestartConfig::default(),
            restarting: None,
            key_chains: BTreeMap::new(),
            policy_tx,
            policy_rx: policy_chan.rx,
            spf_last: None,
            spf_duration: None,
            redist_v4: BTreeMap::new(),
            redist_v6: BTreeMap::new(),
            redist: BTreeMap::new(),
            redist_originated: BTreeMap::new(),
            redist_originated_v6: BTreeMap::new(),
            flex_algo: crate::flex_algo::FlexAlgoConfig::new(Ospfv3::FLEX_ALGO_PREFIX),
            affinity_map: crate::flex_algo::AffinityMap::new(),
            srlg_config: crate::flex_algo::SrlgGroupBuilder::new(),
            srlg_groups: BTreeMap::new(),
            sock,
            v3_send_tx: Some(v3_send_tx),
            v3_recv_rx: Some(v3_recv_rx),
            proto_label,
            rib_subscriber,
            config_tx,
            vrf_log: BTreeMap::new(),
            vrf_registry: BTreeMap::new(),
            rib_known_vrfs: BTreeMap::new(),
            bfd_client_tx,
            bfd_event_tx,
            bfd_event_rx,
            stamp_client_tx,
            stamp_event_tx,
            stamp_event_rx,
        };
        ospf.tracing.proto = Ospfv3::PROTO;
        ospf.callback_build();
        ospf.show_build();
        // v3 has no on-disk GR checkpoint load today, so nothing to
        // gate here (a per-VRF child would otherwise need the same
        // default-instance guard the v2 path uses).
        ospf
    }

    /// Look up the v3 YANG-path handler for `msg.paths` and invoke
    /// it. Mirrors v2's `process_cm_msg`. Currently only
    /// `/router/ospfv3/area/interface/enable` is registered (#791-stub
    /// path); more leaves land alongside the YANG schema expansion.
    pub fn process_cm_msg(&mut self, msg: ConfigRequest) {
        // CommitEnd: fan out to per-VRF children and prune deleted
        // ones, then apply this instance's own staging (mirrors the v2
        // sibling).
        if msg.op == ConfigOp::CommitEnd {
            self.vrf_commit_end();
            self.commit_flex_algo_tables();
            return;
        }

        // Dynamic tab-completion (`ext:dynamic "ospfv3:<handler>"`):
        // the manager sends the handler name as the sole path segment
        // and waits on `msg.resp`. Answer directly — instance-level,
        // not VRF-scoped. Mirrors the v2 sibling.
        if msg.op == ConfigOp::Completion {
            let (path, _) = path_from_command(&msg.paths);
            let comps = match path.as_str() {
                "/neighbor" => self.neighbor_comps(),
                _ => Vec::new(),
            };
            if let Some(resp) = msg.resp {
                let _ = resp.send(comps);
            }
            return;
        }

        // `/router/ospfv3/vrf/<name>/...` belongs to a per-VRF child.
        // Strip the `vrf <name>` selector and buffer + forward the
        // rewritten line; never dispatch it through the default
        // instance's own callback table. Anchored to `router ospfv3`
        // (see `vrf_config_split`): the manager broadcasts every
        // committed line to every protocol, so a generic match would
        // otherwise spawn a phantom child for the top-level `/vrf/<name>`
        // list or for another protocol's `router <other> vrf <name>`.
        if let Some((name, rewritten)) = vrf_config_split("ospfv3", &msg.paths) {
            self.vrf_config_record(name, rewritten, msg.op);
            return;
        }

        let (path, mut args) = path_from_command(&msg.paths);

        // Clear ops bypass the YANG callback table; see the v2
        // sibling. Path-filter so the v3 instance ignores the v2
        // `/clear/ospf/spf` broadcast (and vice versa).
        if msg.op == ConfigOp::Clear {
            if path == "/clear/ospfv3/spf" {
                self.clear_spf();
            } else if path == "/clear/ospfv3/neighbor" {
                // v3 sibling of `clear ospf neighbor`. For v3 the
                // `nbrs` map key already IS the Router-ID, but
                // clear_neighbor matches `ident.router_id` either way.
                self.clear_neighbor(args.v4addr());
            }
            return;
        }

        // Flex-algo definitions (`/router/ospfv3/flex-algo`) and the
        // global `/affinity-map` / `/srlg` tables stage into their
        // builders here and apply at CommitEnd; the registry callbacks
        // below don't cover them.
        if path.starts_with(Ospfv3::FLEX_ALGO_PREFIX)
            || path.starts_with("/affinity-map")
            || path.starts_with("/srlg/group")
        {
            self.flex_algo_table_exec(path, args, msg.op);
            return;
        }

        if let Some(f) = self.callbacks.get(&path) {
            f(self, args, msg.op);
        } else {
            // `/router/ospfv3/tracing/...` subtree — see the v2 sibling.
            super::tracing::config_tracing_dispatch(self, &path, args, msg.op);
        }
    }

    /// Force-recalculate the OSPFv3 SPF for every attached area.
    /// v3 sibling of `Ospf<Ospfv2>::clear_spf`.
    fn clear_spf(&mut self) {
        let area_ids: Vec<Ipv4Addr> = self.areas.iter().map(|(id, _)| *id).collect();
        for id in area_ids {
            let _ = self.tx.send(Message::SpfCalc(id));
        }
    }

    /// Handle a kernel `RibRx` event for the v3 instance: register
    /// new interfaces in `self.links`, propagate up/down events into
    /// the IFSM, and track IPv6 addresses learned from netlink so
    /// `link.addr` is populated by the time the IFSM
    /// `InterfaceUp` event fires. Without `AddrAdd`, the IFSM bails
    /// in `ospf_ifsm_interface_up` (it short-circuits when
    /// `link.addr.is_empty()`), leaving every v3 interface stuck in
    /// `Down`; no Hello timer is ever armed.
    ///
    /// Subset of v2's `process_rib_msg`: `RouterIdUpdate` (with v3
    /// router-LSA re-origination) is a follow-up PR.
    fn process_rib_msg(&mut self, msg: RibRx) {
        match msg {
            // RIB-derived router-id (`system router-id` config or
            // the automatic pick from interface IPv4 addresses).
            // Mirrors the v2 arm: store and refresh, so a configured
            // `router ospfv3 router-id` keeps winning and a config
            // delete falls back to this value. Before this arm every
            // unconfigured v3 instance kept the constructor default
            // 10.0.0.1 — two such routers shared one Router-ID and
            // could never form an adjacency.
            RibRx::RouterIdUpdate(router_id) => {
                self.rib_router_id = (!router_id.is_unspecified()).then_some(router_id);
                self.refresh_router_id();
            }
            RibRx::LinkAdd(link) => self.link_add(link),
            RibRx::LinkUp(ifindex) => self.link_up(ifindex),
            RibRx::LinkDown(ifindex) => self.link_down(ifindex),
            RibRx::LinkDel(ifindex) => self.link_del(ifindex),
            RibRx::LinkMtu { ifindex, mtu } => self.link_mtu(ifindex, mtu),
            RibRx::AddrAdd(addr) => self.addr_add(addr),
            RibRx::AddrDel(addr) => self.addr_del(addr),
            // VRF master lifecycle (default instance only): spawn /
            // despawn the per-VRF OSPFv3 child once config intent +
            // kernel table_id both exist.
            RibRx::VrfAdd {
                name,
                table_id,
                ifindex,
            } => self.vrf_add(name, table_id, ifindex),
            RibRx::VrfDel { name } => self.vrf_del(name),
            // Redistribute delivery. Only `Connected` is subscribed
            // (per-area NSSA redistribute connected); the handler
            // updates the `redist_v6` cache and resyncs Type-7 LSAs in
            // every NSSA area whose `redistribute connected` knob is set.
            RibRx::RouteAdd { rtype, routes, .. } => self.route_redist_add(rtype, routes),
            RibRx::RouteDel { rtype, routes, .. } => self.route_redist_del(rtype, routes),
            _ => {}
        }
    }

    /// `RibRx::RouteAdd` handler (v3): cache the delivered IPv6
    /// connected routes in `redist_v6`, then resync every NSSA area's
    /// Type-7 redistribution. v4 batches never arrive for a v3
    /// subscription.
    fn route_redist_add(&mut self, rtype: crate::rib::RibType, batch: crate::rib::RouteBatch) {
        if let crate::rib::RouteBatch::V6(entries) = batch {
            for e in entries {
                self.redist_v6.insert((rtype, e.prefix), e);
            }
        }
        let area_ids: Vec<Ipv4Addr> = self.areas.iter().map(|(&id, _)| id).collect();
        for area_id in area_ids {
            self.nssa_redist_connected_resync_v3(area_id);
        }
        self.as_external_redist_resync_all_v3();
    }

    /// `RibRx::RouteDel` handler (v3). Mirror of `route_redist_add`.
    fn route_redist_del(&mut self, rtype: crate::rib::RibType, batch: crate::rib::RouteBatch) {
        if let crate::rib::RouteBatch::V6(entries) = batch {
            for e in entries {
                self.redist_v6.remove(&(rtype, e.prefix));
            }
        }
        let area_ids: Vec<Ipv4Addr> = self.areas.iter().map(|(&id, _)| id).collect();
        for area_id in area_ids {
            self.nssa_redist_connected_resync_v3(area_id);
        }
        self.as_external_redist_resync_all_v3();
    }

    /// Stash an IPv6 address learned from netlink on the matching
    /// link's `addr` list. IPv4 addresses are dropped — v3 only
    /// operates over IPv6 (RFC 5340 §1). If the addition makes
    /// `link.addr` non-empty for the first time on an enabled link
    /// that's still in IFSM `Down`, re-fire `InterfaceUp` so the
    /// FSM can progress past the empty-`addr` short-circuit in
    /// `ospf_ifsm_interface_up`.
    fn addr_add(&mut self, addr: LinkAddr) {
        let Some(link) = self.links.get_mut(&addr.ifindex) else {
            return;
        };
        let IpNet::V6(prefix) = &addr.addr else {
            return;
        };
        // Duplicate-delivery guard — see `link_addr_push_unique` for
        // why the same address arrives multiple times. Without it the
        // Intra-Area-Prefix-LSA repeats the prefix once per delivery.
        let ospf_addr = OspfAddr::<Ospfv3>::from(&addr, prefix);
        super::addr::link_addr_push_unique(&mut link.addr, ospf_addr);

        if link.enabled && link.state == IfsmState::Down {
            let _ = self
                .tx
                .send(Message::Ifsm(addr.ifindex, IfsmEvent::InterfaceUp));
        }

        // The Prefix-SID's E-Intra-Area-Prefix-LSA advertises this
        // link's first routable global as a /128 host prefix. The
        // config handler originates it at commit time, but the
        // kernel's AddrAdd for an address configured in the same
        // commit can land *after* that — origination then finds no
        // usable address and stays flushed forever. Re-originate
        // here so the LSA appears as soon as the address does (the
        // builder gates on SR mode + a configured prefix-sid, so
        // this is a no-op on links without one).
        self.ext_intra_area_prefix_v3_lsa_originate(addr.ifindex);
    }

    /// Apply a Router-ID to this OSPFv3 instance. Mirror of the v2
    /// `router_id_update`; reached via `refresh_router_id` from
    /// `config_ospfv3_router_id` so `router ospfv3 { router-id ... }`
    /// is honoured (previously v3 had no per-instance Router-ID path
    /// at all and every instance kept the constructor default
    /// 10.0.0.1).
    pub(super) fn router_id_update(&mut self, router_id: Ipv4Addr) {
        // See the v2 sibling: withdraw everything originated under the
        // previous Router-ID so it does not linger as a phantom node in
        // peers' LSDBs until MaxAge.
        let old_router_id = self.router_id;
        if old_router_id != router_id {
            self.flush_self_originated_under(old_router_id);
        }

        self.router_id = router_id;
        for (_, link) in self.links.iter_mut() {
            link.ident.router_id = router_id;
        }
        self.router_lsa_originate();
    }

    /// v3 sibling of the v2 `flush_self_originated_under`: pre-age to
    /// MaxAge + re-flood every LSA we originated under `old_router_id`
    /// (per-area LSAs plus AS-External LSAs) when the effective
    /// Router-ID moves.
    fn flush_self_originated_under(&mut self, old_router_id: Ipv4Addr) {
        let area_ids: Vec<Ipv4Addr> = self.areas.iter().map(|(id, _)| *id).collect();
        for area_id in area_ids {
            let keys: Vec<OspfLsaKey> = match self.areas.get(area_id) {
                Some(area) => area
                    .lsdb
                    .tables
                    .keys()
                    .filter(|(_, _, adv)| *adv == old_router_id)
                    .copied()
                    .collect(),
                None => continue,
            };
            for key in keys {
                let flushed = if let Some(area) = self.areas.get_mut(area_id) {
                    area.lsdb.flush_lsa_by_raw_key(key, &self.tx, Some(area_id))
                } else {
                    None
                };
                if let Some(lsa) = flushed {
                    self.flood_self_originated_lsa(area_id, &lsa);
                }
            }
        }
        let as_keys: Vec<OspfLsaKey> = self
            .lsdb_as
            .tables
            .keys()
            .filter(|(_, _, adv)| *adv == old_router_id)
            .copied()
            .collect();
        for key in as_keys {
            if let Some(lsa) = self.lsdb_as.flush_lsa_by_raw_key(key, &self.tx, None) {
                self.flood_lsa_through_as_v3(&lsa, None);
            }
        }

        // Per-link LSDBs: v3 Link-LSAs (RFC 5340 §A.4.9) are
        // link-local scope and live in `link.lsdb`, not the area
        // LSDB, so the loop above misses them. A peer keeps the
        // Link-LSA we originated under the old Router-ID (it shows up
        // in its `show ospfv3 database`) until it MaxAges on its own;
        // flush + re-flood it on the link so it goes away with the
        // rest of the old identity.
        let ifindices: Vec<u32> = self.links.keys().copied().collect();
        for ifindex in ifindices {
            let keys: Vec<OspfLsaKey> = match self.links.get(&ifindex) {
                Some(link) => link
                    .lsdb
                    .tables
                    .keys()
                    .filter(|(_, _, adv)| *adv == old_router_id)
                    .copied()
                    .collect(),
                None => continue,
            };
            for key in keys {
                let flushed = if let Some(link) = self.links.get_mut(&ifindex) {
                    link.lsdb.flush_lsa_by_raw_key(key, &self.tx, None)
                } else {
                    None
                };
                if let Some(lsa) = flushed {
                    self.flood_link_scope_lsa(ifindex, &lsa);
                }
            }
        }
    }

    /// v3 sibling of the v2 `refresh_router_id`: configured value
    /// wins, then the RIB-derived value (v3's `process_rib_msg`
    /// `RouterIdUpdate` arm), then the constructor default.
    pub(super) fn refresh_router_id(&mut self) {
        let effective = self
            .router_id_config
            .or(self.rib_router_id)
            .unwrap_or(DEFAULT_ROUTER_ID);
        if self.router_id != effective {
            self.router_id_update(effective);
        }
    }

    /// Remove an IPv6 address from the matching link's `addr` list
    /// and, if the link's enable predicate now flips, drive the
    /// IFSM through the resulting transition (mirrors v2's
    /// `addr_del`).
    fn addr_del(&mut self, addr: LinkAddr) {
        let Some(link) = self.links.get_mut(&addr.ifindex) else {
            return;
        };
        let IpNet::V6(prefix) = &addr.addr else {
            return;
        };
        link.addr.retain(|a| a.prefix != *prefix);

        let (next, next_id) = super::config::link_should_enable(link);
        super::config::apply_link_enable_transition(link, next, next_id);

        // Mirror of the `addr_add` re-origination: the advertised
        // host prefix may have just gone away (the builder flushes)
        // or a different remaining address now wins.
        self.ext_intra_area_prefix_v3_lsa_originate(addr.ifindex);
    }

    /// Look up the v3 show-path handler for `msg.paths` and invoke
    /// it. Mirrors v2's `process_show_msg`.
    pub async fn process_show_msg(&self, msg: DisplayRequest) {
        let (path, args) = path_from_command(&msg.paths);
        if let Some(f) = self.show_cb.get(&path) {
            let output = match f(self, args, msg.json) {
                Ok(result) => result,
                Err(e) => format!("Error formatting output: {}", e),
            };
            msg.resp.send(output).await.unwrap();
        }
    }

    /// Build the v3 Intra-Area-Prefix-LSA that references this
    /// router's Router-LSA in `area_id` (RFC 5340 §A.4.10).
    ///
    /// v3 separates topology (Router-LSA / Network-LSA) from prefix
    /// advertisement. This LSA carries the IPv6 prefixes that this
    /// router contributes to the area, hanging them off the
    /// Router-LSA reference triple
    /// `(referenced_ls_type = Router-LSA,
    ///   referenced_link_state_id = 0,
    ///   referenced_advertising_router = self.router_id)`.
    ///
    /// Iterates every enabled link in `area_id`, walks each
    /// link's configured IPv6 addresses, and emits one
    /// `Ospfv3IntraAreaPrefix` per non-link-local prefix with the
    /// link's `output_cost` as the metric.
    ///
    /// Returns `None` if there are no advertisable prefixes in
    /// the area — there's nothing to originate.
    ///
    /// The DR's Network-LSA-referenced variant (which aggregates
    /// per-segment Link-LSA prefixes into a single area-scope
    /// LSA) lands in a follow-up; the two share the same body
    /// shape but differ on which LSA they reference.
    pub fn build_router_intra_area_prefix_lsa(
        &self,
        area_id: Ipv4Addr,
    ) -> Option<ospf_packet::Ospfv3Lsa> {
        use ospf_packet::{
            OSPFV3_INTRA_AREA_PREFIX_LSA_TYPE, OSPFV3_ROUTER_LSA_TYPE, Ospfv3IntraAreaPrefix,
            Ospfv3IntraAreaPrefixLsa, Ospfv3LsBody, Ospfv3Lsa, Ospfv3LsaHeader,
            Ospfv3PrefixOptions, ospfv3_prefix_wire_len,
        };

        let mut prefixes: Vec<Ospfv3IntraAreaPrefix> = Vec::new();
        for link in self.links.values() {
            if !link.enabled || link.area != area_id {
                continue;
            }
            // RFC 5340 §A.4.10: prefixes on a broadcast / NBMA transit
            // segment with at least one Full adjacency are advertised
            // by the DR's Network-LSA-referenced Intra-Area-Prefix-LSA,
            // not by each attached router's Router-LSA-referenced one.
            // Without this filter, both LSAs carry the segment prefix
            // and `build_rib6_from_spf` ECMP-merges them — the route
            // ends up with the directly-attached path *and* a
            // redundant via-peer path at the same cost.
            let transit_with_adjacencies =
                matches!(
                    link.network_type,
                    OspfNetworkType::Broadcast | OspfNetworkType::NBMA
                ) && link.nbrs.values().any(|n| n.state == NfsmState::Full);
            if transit_with_adjacencies {
                continue;
            }
            // Loopback parity with v2 / FRR / Junos: stamp 0 instead
            // of the link's output_cost so a /128 (or /N) on `lo`
            // doesn't add a phantom hop's worth of metric to every
            // route that traverses this router.
            let metric = if link.link_flags.is_loopback() {
                0
            } else {
                link.output_cost as u16
            };
            for a in link.addr.iter() {
                // Skip link-local addresses — those are
                // advertised by Link-LSAs (RFC 5340 §A.4.9), not
                // by Intra-Area-Prefix-LSAs (§A.4.10).
                if a.prefix.addr().segments()[0] == 0xfe80 {
                    continue;
                }
                let net = &a.prefix;
                let prefix_length = net.prefix_len();
                let wire_len = ospfv3_prefix_wire_len(prefix_length);
                let mut address_prefix = vec![0u8; wire_len];
                let bytes = net.addr().octets();
                let copy_len = prefix_length.div_ceil(8) as usize;
                address_prefix[..copy_len].copy_from_slice(&bytes[..copy_len]);
                prefixes.push(Ospfv3IntraAreaPrefix {
                    prefix_length,
                    prefix_options: Ospfv3PrefixOptions::default(),
                    metric,
                    address_prefix,
                });
            }
        }

        if prefixes.is_empty() {
            return None;
        }

        let body = Ospfv3IntraAreaPrefixLsa {
            referenced_ls_type: OSPFV3_ROUTER_LSA_TYPE,
            referenced_link_state_id: 0,
            referenced_advertising_router: self.router_id,
            prefixes,
        };
        let mut lsa = Ospfv3Lsa {
            h: Ospfv3LsaHeader {
                ls_age: 0,
                ls_type: OSPFV3_INTRA_AREA_PREFIX_LSA_TYPE,
                // First (and so far only) fragment uses LS-ID 0;
                // a future PR that splits large prefix sets across
                // multiple Intra-Area-Prefix-LSAs will use distinct
                // LS-IDs per fragment.
                link_state_id: 0,
                advertising_router: self.router_id,
                ls_seq_number: 0x8000_0001,
                ls_checksum: 0,
                length: 0,
            },
            body: Ospfv3LsBody::IntraAreaPrefix(body),
            raw: None,
        };
        lsa.update();
        Some(lsa)
    }

    /// Build the v3 Link-LSA for a given interface (RFC 5340 §A.4.9).
    ///
    /// Originated by every router on every active interface with
    /// **link-local scope** — never flooded beyond the segment.
    /// Carries:
    ///   - our Hello priority for the link,
    ///   - our options bits,
    ///   - our IPv6 link-local address on the link (so other
    ///     routers on the segment can install a usable next hop),
    ///   - the IPv6 prefixes configured on the interface (the DR
    ///     aggregates these into the Intra-Area-Prefix-LSA the
    ///     Network-LSA references).
    ///
    /// LS-ID = the local Interface ID (RFC 5340 §A.4.9).
    ///
    /// Returns `None` for unknown / disabled interfaces. If no
    /// link-local address is configured yet (interface coming up
    /// before netlink populates addresses), the Link-LSA carries
    /// `::` as a placeholder — the interface-enable path will
    /// re-originate once the address lands.
    pub fn build_link_lsa(&self, ifindex: u32) -> Option<ospf_packet::Ospfv3Lsa> {
        use ospf_packet::{
            OSPFV3_LINK_LSA_TYPE, Ospfv3LinkLsa, Ospfv3LinkLsaPrefix, Ospfv3LsBody, Ospfv3Lsa,
            Ospfv3LsaHeader, Ospfv3Options, Ospfv3PrefixOptions, ospfv3_prefix_wire_len,
        };
        use std::net::Ipv6Addr;

        let link = self.links.get(&ifindex)?;
        if !link.enabled {
            return None;
        }

        // Pick a link-local. v3 hellos source from the link-local
        // and v3 Link-LSAs advertise it (RFC 5340 §A.4.9). Until
        // netlink reports one we publish `::` as a placeholder.
        let link_local_address: Ipv6Addr = link
            .addr
            .iter()
            .map(|a| a.prefix.addr())
            .find(|a| a.segments()[0] == 0xfe80)
            .unwrap_or(Ipv6Addr::UNSPECIFIED);

        // Every non-link-local prefix configured on the interface
        // gets advertised. Each prefix's wire bytes are the
        // address octets truncated to `ceil(prefix_len / 8)`,
        // then padded to a 32-bit boundary by
        // `ospfv3_prefix_wire_len`.
        let mut prefixes: Vec<Ospfv3LinkLsaPrefix> = link
            .addr
            .iter()
            .filter(|a| a.prefix.addr().segments()[0] != 0xfe80)
            .map(|a| {
                let net = &a.prefix;
                let prefix_length = net.prefix_len();
                let wire_len = ospfv3_prefix_wire_len(prefix_length);
                let mut address_prefix = vec![0u8; wire_len];
                let addr_bytes = net.addr().octets();
                let copy_len = prefix_length.div_ceil(8) as usize;
                address_prefix[..copy_len].copy_from_slice(&addr_bytes[..copy_len]);
                Ospfv3LinkLsaPrefix {
                    prefix_length,
                    prefix_options: Ospfv3PrefixOptions::default(),
                    address_prefix,
                }
            })
            .collect();

        // RFC 5340 §4.4.3.8 LA-bit: additionally advertise each global
        // interface address as a /128 host prefix. Peers use it as the
        // SRv6 End.X nexthop — Linux's seg6local End.X cannot resolve
        // a link-local nexthop correctly (it re-looks nh6 up with the
        // packet's ingress iif, PR #1361), so the global is the only
        // reliable kernel programming and OSPFv3 has no other channel
        // that carries neighbor global addresses.
        prefixes.extend(
            link.addr
                .iter()
                .map(|a| a.prefix.addr())
                .filter(|a| a.segments()[0] != 0xfe80)
                .map(|addr| {
                    let mut options = Ospfv3PrefixOptions::default();
                    options.set_la(true);
                    Ospfv3LinkLsaPrefix {
                        prefix_length: 128,
                        prefix_options: options,
                        address_prefix: addr.octets().to_vec(),
                    }
                }),
        );

        let body = Ospfv3LinkLsa {
            priority: link.priority(),
            options: Ospfv3Options::default(),
            link_local_address,
            prefixes,
        };
        let mut lsa = Ospfv3Lsa {
            h: Ospfv3LsaHeader {
                ls_age: 0,
                ls_type: OSPFV3_LINK_LSA_TYPE,
                link_state_id: link.interface_id,
                advertising_router: self.router_id,
                ls_seq_number: 0x8000_0001,
                ls_checksum: 0,
                length: 0,
            },
            body: Ospfv3LsBody::Link(body),
            raw: None,
        };
        lsa.update();
        Some(lsa)
    }

    /// Build the v3 Network-LSA for a broadcast / NBMA segment
    /// on which this router is the elected DR (RFC 5340 §A.4.4).
    ///
    /// Returns `None` if any of these conditions hold:
    ///   - the ifindex doesn't name an enabled link
    ///   - the link isn't Broadcast / NBMA
    ///   - this router is not the DR on the link (i.e.
    ///     `link.ident.d_router != self.router_id`)
    ///
    /// LS-ID = the local Interface ID for the link (§A.4.4 — v3
    /// Network-LSA LS-ID is the DR's Interface ID, not the
    /// interface's IP as in v2). Attached routers = every
    /// neighbor in Full state plus ourselves.
    ///
    /// Unlike v2's Network-LSA, the v3 body carries no netmask /
    /// prefix info — those move to the Intra-Area-Prefix-LSA.
    pub fn build_network_lsa(&self, ifindex: u32) -> Option<ospf_packet::Ospfv3Lsa> {
        use ospf_packet::{
            OSPFV3_NETWORK_LSA_TYPE, Ospfv3LsBody, Ospfv3Lsa, Ospfv3LsaHeader, Ospfv3NetworkLsa,
            Ospfv3Options,
        };

        let link = self.links.get(&ifindex)?;
        if !link.enabled {
            return None;
        }
        if !matches!(link.network_type, OspfNetworkType::Broadcast) {
            return None;
        }
        if link.ident.d_router != self.router_id {
            return None;
        }

        // RFC 5340 §A.4.4: the DR's Network-LSA enumerates every
        // router fully adjacent to it on the segment, including
        // the DR itself.
        let mut attached_routers: Vec<Ipv4Addr> = vec![self.router_id];
        attached_routers.extend(
            link.nbrs
                .values()
                .filter(|n| n.state == NfsmState::Full)
                .map(|n| n.ident.router_id),
        );

        let body = Ospfv3NetworkLsa {
            options: Ospfv3Options::default(),
            attached_routers,
        };
        let mut lsa = Ospfv3Lsa {
            h: Ospfv3LsaHeader {
                ls_age: 0,
                ls_type: OSPFV3_NETWORK_LSA_TYPE,
                link_state_id: link.interface_id,
                advertising_router: self.router_id,
                ls_seq_number: 0x8000_0001,
                ls_checksum: 0,
                length: 0,
            },
            body: Ospfv3LsBody::Network(body),
            raw: None,
        };
        lsa.update();
        Some(lsa)
    }

    /// Build the Router-LSA for self-origination (RFC 5340 §A.4.3).
    ///
    /// Walks every enabled `OspfLink<Ospfv3>` and emits one
    /// `Ospfv3RouterLsaLink` per qualifying adjacency:
    ///
    ///   - Broadcast network with a full-state DR adjacency
    ///     -> TransitNetwork link naming the DR's interface_id +
    ///     router-id (per §A.4.3 the "neighbor" fields on Transit
    ///     links point at the DR, not at every adjacent peer).
    ///
    /// PointToPoint and VirtualLink emission lands when the
    /// matching `OspfNetworkType` variants surface in zebra-rs
    /// (currently the enum has only Broadcast and NBMA; v3 needs
    /// PointToPoint as a network type for Router-LSA link type 1
    /// to be emittable).
    ///
    /// Returns an `Ospfv3Lsa` with checksum + length stamped via
    /// `Ospfv3Lsa::update`. Ready to install through
    /// `Lsdb::install_originated`.
    pub fn build_router_lsa(&self, area_id: Ipv4Addr) -> ospf_packet::Ospfv3Lsa {
        use ospf_packet::{
            OSPFV3_ROUTER_LSA_FLAG_B, OSPFV3_ROUTER_LSA_FLAG_E, OSPFV3_ROUTER_LSA_TYPE,
            Ospfv3LsBody, Ospfv3Lsa, Ospfv3LsaHeader, Ospfv3Options, Ospfv3RouterLsa,
            Ospfv3RouterLsaLink,
        };

        let mut links = Vec::new();
        for link in self.links.values() {
            if !link.enabled {
                continue;
            }
            // Router-LSAs are area-scoped (RFC 5340 §3.4.3): include
            // only the links that belong to `area_id`.
            if link.area_id != area_id {
                continue;
            }
            let cost = link.output_cost as u16;
            let my_iid = link.interface_id;

            // RFC 5340 §A.4.3 link type 1: PointToPoint. One link
            // entry per Full neighbor, naming the peer's
            // interface-id and router-id. No DR involvement — the
            // P2P link is its own bidirectional edge. Skipped while
            // the adjacency is still forming so the Router-LSA
            // doesn't carry a half-built reference.
            if link.is_pointopoint() {
                for nbr in link.nbrs.values() {
                    if nbr.state != NfsmState::Full {
                        continue;
                    }
                    links.push(Ospfv3RouterLsaLink::point_to_point(
                        cost,
                        my_iid,
                        nbr.interface_id,
                        nbr.ident.router_id,
                    ));
                }
                continue;
            }

            if matches!(link.network_type, OspfNetworkType::Broadcast) {
                let dr_router_id = link.ident.d_router;
                if dr_router_id == Ipv4Addr::UNSPECIFIED {
                    continue;
                }
                if dr_router_id == self.router_id {
                    // RFC 5340 §A.4.3: when this router is the DR
                    // for the segment, the Transit-link's "neighbor"
                    // fields name us — our own interface_id and
                    // router-id. Without this branch the link is
                    // silently dropped on the DR side (`link.nbrs`
                    // never contains an entry keyed by our own
                    // router-id), the Router-LSA goes out with zero
                    // links, and SPF can never relax through the
                    // Network-LSA pseudo-node we just originated.
                    // Only emit when at least one neighbor reached
                    // Full so the matching Network-LSA actually
                    // exists in the LSDB to back-link against.
                    let has_full_nbr = link.nbrs.values().any(|n| n.state == NfsmState::Full);
                    if has_full_nbr {
                        links.push(Ospfv3RouterLsaLink::transit_network(
                            cost,
                            my_iid,
                            my_iid,
                            self.router_id,
                        ));
                    }
                } else if let Some(dr_nbr) = link.nbrs.get(&dr_router_id)
                    && dr_nbr.state == NfsmState::Full
                {
                    links.push(Ospfv3RouterLsaLink::transit_network(
                        cost,
                        my_iid,
                        dr_nbr.interface_id,
                        dr_router_id,
                    ));
                }
            }
        }

        // RFC 5340 §A.4.3 Router-LSA flags: B (Border / ABR), E
        // (ASBR), V (virtual-link endpoint), W (wild-card multicast).
        // B-bit is set when this router attaches to two or more
        // areas — both peers (and our own NSSA Candidate election in
        // `is_nssa_translator_for`) read it to identify ABRs. The
        // E-bit follows `is_asbr()` (any instance-level redistribute)
        // so remote ABRs originate Inter-Area-Router-LSAs only for
        // real ASBRs — v2 parity.
        let mut router_flags = 0u8;
        if self.is_asbr() {
            router_flags |= OSPFV3_ROUTER_LSA_FLAG_E;
        }
        if self.is_abr() {
            router_flags |= OSPFV3_ROUTER_LSA_FLAG_B;
        }
        let body = Ospfv3RouterLsa::new(router_flags, Ospfv3Options::default(), links);
        let mut lsa = Ospfv3Lsa {
            h: Ospfv3LsaHeader {
                ls_age: 0,
                ls_type: OSPFV3_ROUTER_LSA_TYPE,
                link_state_id: 0,
                advertising_router: self.router_id,
                ls_seq_number: 0x8000_0001,
                ls_checksum: 0,
                length: 0,
            },
            body: Ospfv3LsBody::Router(body),
            raw: None,
        };
        lsa.update();
        lsa
    }

    /// Originate this router's Router-LSA into AREA0's LSDB.
    /// Mirrors v2's `router_lsa_originate_with_min_seq` shape with
    /// the v3-specific differences:
    ///
    /// - v3 carries `ls_type` as a raw `u16` (RFC 5340 §A.4.2.1);
    ///   the AREA0 LSDB lookup uses `lookup_by_raw_key` with the
    ///   3-tuple `(OSPFV3_ROUTER_LSA_TYPE, link_state_id=0,
    ///   advertising_router=self.router_id)`.
    /// - Checksum / length are restamped via `Ospfv3Lsa::update`
    ///   after the sequence number bump.
    /// - Install via the already-generic
    ///   `Lsdb::install_originated` (no v2-specific seq logic to
    ///   thread through `insert_self_originated`).
    /// - After install, flood the LSA to every Exchange-or-later
    ///   neighbor in the area via `flood_self_originated_lsa`.
    pub fn router_lsa_originate(&mut self) {
        // Router-LSAs are area-scoped (RFC 5340 §3.4.3): originate one
        // per area this router has enabled links in, each carrying only
        // that area's links. Previously hardcoded to AREA0, which left
        // every non-backbone area without a topology LSA — so its SPF
        // never ran and the area's routers got no routes.
        let area_ids: BTreeSet<Ipv4Addr> = self
            .links
            .values()
            .filter(|l| l.enabled)
            .map(|l| l.area_id)
            .collect();
        for area_id in area_ids {
            self.router_lsa_originate_for_area(area_id);
        }
    }

    /// Originate this router's Router-LSA for a single `area_id` (only
    /// that area's links) into the area's LSDB, then flood + reschedule
    /// the area's SPF.
    fn router_lsa_originate_for_area(&mut self, area_id: Ipv4Addr) {
        use ospf_packet::OSPFV3_ROUTER_LSA_TYPE;
        let mut lsa = self.build_router_lsa(area_id);

        let key: super::lsdb::OspfLsaKey = (OSPFV3_ROUTER_LSA_TYPE, 0, self.router_id);
        if let Some(area) = self.areas.get(area_id) {
            let current_seq = area
                .lsdb
                .lookup_by_raw_key(key)
                .map(|prev| prev.h.ls_seq_number);
            if let Some(seq) = current_seq {
                lsa.h.ls_seq_number = seq_max(lsa.h.ls_seq_number, seq.saturating_add(1));
            }
        }
        lsa.update();

        let flood_lsa = lsa.clone();
        if let Some(area) = self.areas.get_mut(area_id) {
            area.lsdb.install_originated(lsa, &self.tx, Some(area_id));
            Self::ospf_spf_schedule_generic(&self.tx, area);
        }

        self.flood_self_originated_lsa(area_id, &flood_lsa);
    }

    /// v3 generic Type-7 NSSA-LSA originator. Builds an
    /// `Ospfv3LsBody::Nssa(Ospfv3AsExternalLsa)` body for the
    /// given v6 prefix and installs it into `area_id`'s LSDB.
    /// `metric_type_2 = true` sets the E-bit; `fwd_addr` is
    /// optional (encoded with the F-flag when `Some`).
    ///
    /// Mirror of v2's `nssa_lsa_originate_for_prefix`. Caller is
    /// responsible for gating on area type / config; the v3
    /// equivalents of v2's policy wrappers
    /// (`nssa_default_lsa_originate`) sit just below.
    ///
    /// RFC 5340 §A.4.9: NSSA-LSA body is identical to AS-External
    /// (§A.4.7). RFC 3101 §2.4 P-bit lives in the prefix-options
    /// field (not the LSA header as in v2); the default-LSA
    /// originator leaves it clear per §2.3.
    fn nssa_lsa_originate_for_prefix_v3(
        &mut self,
        area_id: Ipv4Addr,
        prefix: ipnet::Ipv6Net,
        metric: u32,
        metric_type_2: bool,
        fwd_addr: Option<std::net::Ipv6Addr>,
    ) {
        use ospf_packet::{
            OSPFV3_AS_EXTERNAL_FLAG_E, OSPFV3_AS_EXTERNAL_FLAG_F, OSPFV3_NSSA_LSA_TYPE,
            Ospfv3AsExternalLsa, Ospfv3LsBody, Ospfv3LsaHeader, Ospfv3PrefixOptions,
            ospfv3_prefix_wire_len,
        };

        // RFC 5340 §A.4.9 / RFC 3101 §2.4: the P-bit (Propagate) lives
        // in the NSSA-LSA's prefix-options. A pure NSSA ASBR sets it to
        // ask the ABR to translate; an ABR clears it on its own Type-7s
        // (default-LSA, ABR redistribute) so a peer ABR never
        // re-translates them. Same `!is_abr()` rule as the v2 N/P-bit.
        let propagate = !self.is_abr();

        // v3 LSA header: link_state_id is a 32-bit opaque value
        // selected by the originator (ls-id 0 for the NSSA default-LSA,
        // a full-prefix hash otherwise — see `nssa_v3_ls_id`).
        let link_state_id = nssa_v3_ls_id(&prefix);

        let mut flags = 0u8;
        if metric_type_2 {
            flags |= OSPFV3_AS_EXTERNAL_FLAG_E;
        }
        if fwd_addr.is_some() {
            flags |= OSPFV3_AS_EXTERNAL_FLAG_F;
        }

        // Address prefix bytes, padded to the next 4-octet boundary
        // per RFC 5340 §A.4.1.1. `ospfv3_prefix_wire_len` gives the
        // padded length; truncate the network bytes to that.
        let wire_len = ospfv3_prefix_wire_len(prefix.prefix_len());
        let mut address_prefix = vec![0u8; wire_len];
        let net_bytes = prefix.network().octets();
        let copy_len = wire_len.min(net_bytes.len());
        address_prefix[..copy_len].copy_from_slice(&net_bytes[..copy_len]);

        let mut prefix_options = Ospfv3PrefixOptions::new();
        prefix_options.set_p(propagate);
        let body = Ospfv3AsExternalLsa {
            flags,
            metric,
            prefix_length: prefix.prefix_len(),
            prefix_options,
            referenced_ls_type: 0,
            address_prefix,
            forwarding_address: fwd_addr,
            external_route_tag: None,
            referenced_link_state_id: None,
        };

        let header = Ospfv3LsaHeader {
            ls_age: 0,
            ls_type: OSPFV3_NSSA_LSA_TYPE,
            link_state_id,
            advertising_router: self.router_id,
            ls_seq_number: 0x8000_0001,
            ls_checksum: 0,
            length: 0,
        };
        let mut lsa = ospf_packet::Ospfv3Lsa {
            h: header,
            body: Ospfv3LsBody::Nssa(body),
            raw: None,
        };

        // Preserve sequence number on refresh.
        let key: super::lsdb::OspfLsaKey = (OSPFV3_NSSA_LSA_TYPE, link_state_id, self.router_id);
        if let Some(area) = self.areas.get(area_id)
            && let Some(existing) = area.lsdb.lookup_by_raw_key(key)
        {
            lsa.h.ls_seq_number = seq_max(
                lsa.h.ls_seq_number,
                existing.h.ls_seq_number.saturating_add(1),
            );
        }
        lsa.update();

        let flood_lsa = lsa.clone();
        if let Some(area) = self.areas.get_mut(area_id) {
            area.lsdb.install_originated(lsa, &self.tx, Some(area_id));
        }
        self.flood_self_originated_lsa(area_id, &flood_lsa);
    }

    /// Flush a single self-originated v3 Type-7 LSA from
    /// `area_id` keyed by the prefix-derived ls-id (0 for default).
    fn nssa_lsa_flush_for_prefix_v3(&mut self, area_id: Ipv4Addr, prefix: ipnet::Ipv6Net) {
        use ospf_packet::OSPFV3_NSSA_LSA_TYPE;
        let link_state_id = nssa_v3_ls_id(&prefix);
        let key: super::lsdb::OspfLsaKey = (OSPFV3_NSSA_LSA_TYPE, link_state_id, self.router_id);
        let flushed = if let Some(area) = self.areas.get_mut(area_id) {
            area.lsdb.flush_lsa_by_raw_key(key, &self.tx, Some(area_id))
        } else {
            None
        };
        if let Some(lsa) = flushed {
            self.flood_self_originated_lsa(area_id, &lsa);
        }
    }

    /// Originate (or refresh) an OSPFv3 AS-External (Type-5, 0x4005) LSA
    /// for `prefix` into the AS-scope LSDB and flood it AS-wide. The v3
    /// sibling of `as_external_lsa_originate_for_prefix`; the body build
    /// mirrors `nssa_lsa_originate_for_prefix_v3` but with the AS-External
    /// LSA type, no P-bit (Propagate is NSSA-only), FA absent, and
    /// AS-scope install/flood instead of per-area.
    fn as_external_lsa_originate_for_prefix_v3(
        &mut self,
        prefix: ipnet::Ipv6Net,
        metric: u32,
        metric_type_2: bool,
    ) {
        use ospf_packet::{
            OSPFV3_AS_EXTERNAL_FLAG_E, OSPFV3_AS_EXTERNAL_LSA_TYPE, Ospfv3AsExternalLsa,
            Ospfv3LsBody, Ospfv3LsaHeader, Ospfv3PrefixOptions, ospfv3_prefix_wire_len,
        };

        let link_state_id = nssa_v3_ls_id(&prefix);

        let mut flags = 0u8;
        if metric_type_2 {
            flags |= OSPFV3_AS_EXTERNAL_FLAG_E;
        }

        let wire_len = ospfv3_prefix_wire_len(prefix.prefix_len());
        let mut address_prefix = vec![0u8; wire_len];
        let net_bytes = prefix.network().octets();
        let copy_len = wire_len.min(net_bytes.len());
        address_prefix[..copy_len].copy_from_slice(&net_bytes[..copy_len]);

        // No P-bit: that is an NSSA-LSA construct (RFC 3101). A Type-5
        // ASBR leaves prefix-options clear and emits no forwarding address.
        let body = Ospfv3AsExternalLsa {
            flags,
            metric,
            prefix_length: prefix.prefix_len(),
            prefix_options: Ospfv3PrefixOptions::new(),
            referenced_ls_type: 0,
            address_prefix,
            forwarding_address: None,
            external_route_tag: None,
            referenced_link_state_id: None,
        };

        let header = Ospfv3LsaHeader {
            ls_age: 0,
            ls_type: OSPFV3_AS_EXTERNAL_LSA_TYPE,
            link_state_id,
            advertising_router: self.router_id,
            ls_seq_number: 0x8000_0001,
            ls_checksum: 0,
            length: 0,
        };
        let mut lsa = ospf_packet::Ospfv3Lsa {
            h: header,
            body: Ospfv3LsBody::AsExternal(body),
            raw: None,
        };

        let key: super::lsdb::OspfLsaKey =
            (OSPFV3_AS_EXTERNAL_LSA_TYPE, link_state_id, self.router_id);
        if let Some(existing) = self.lsdb_as.lookup_by_raw_key(key) {
            lsa.h.ls_seq_number = seq_max(
                lsa.h.ls_seq_number,
                existing.h.ls_seq_number.saturating_add(1),
            );
        }
        lsa.update();

        let flood_lsa = lsa.clone();
        self.lsdb_as.install_originated(lsa, &self.tx, None);
        self.flood_lsa_through_as_v3(&flood_lsa, None);
    }

    /// Flush a self-originated v3 AS-External LSA keyed by the
    /// prefix-derived ls-id and reflood the MaxAge copy AS-wide.
    fn as_external_lsa_flush_for_prefix_v3(&mut self, prefix: ipnet::Ipv6Net) {
        use ospf_packet::OSPFV3_AS_EXTERNAL_LSA_TYPE;
        let link_state_id = nssa_v3_ls_id(&prefix);
        let key: super::lsdb::OspfLsaKey =
            (OSPFV3_AS_EXTERNAL_LSA_TYPE, link_state_id, self.router_id);
        let flushed = self.lsdb_as.flush_lsa_by_raw_key(key, &self.tx, None);
        if let Some(lsa) = flushed {
            self.flood_lsa_through_as_v3(&lsa, None);
        }
    }

    /// v3 sibling of `as_external_redist_resync`: rebuild this
    /// instance's self-originated AS-External (Type-5) LSAs for one
    /// instance-level `redistribute <source>` knob from the cached
    /// routes (`redist_v6` entries with a matching rtype), diffing
    /// against `redist_originated_v6`. In a per-VRF OSPFv3 instance the
    /// bgp source carries the VPNv6 routes BGP imported into the VRF —
    /// injecting them into the CE-facing OSPFv3 is the L3VPN PE-CE down
    /// direction.
    pub fn as_external_redist_resync_v3(&mut self, rtype: crate::rib::RibType) {
        let entry = self.redist.get(&rtype).copied();
        let prev_originated = self
            .redist_originated_v6
            .get(&rtype)
            .cloned()
            .unwrap_or_default();

        let desired: BTreeSet<ipnet::Ipv6Net> = if entry.is_some() {
            self.redist_v6
                .iter()
                .filter(|((rt, _), _)| *rt == rtype)
                .map(|((_, prefix), _)| *prefix)
                .collect()
        } else {
            BTreeSet::new()
        };

        for prefix in prev_originated
            .difference(&desired)
            .copied()
            .collect::<Vec<_>>()
        {
            self.as_external_lsa_flush_for_prefix_v3(prefix);
            if let Some(set) = self.redist_originated_v6.get_mut(&rtype) {
                set.remove(&prefix);
            }
        }

        if let Some(redist_entry) = entry {
            for prefix in &desired {
                self.as_external_lsa_originate_for_prefix_v3(
                    *prefix,
                    redist_entry.metric,
                    redist_entry.metric_type.is_type_2(),
                );
                self.redist_originated_v6
                    .entry(rtype)
                    .or_default()
                    .insert(*prefix);
            }
        }
        if self
            .redist_originated_v6
            .get(&rtype)
            .is_some_and(|s| s.is_empty())
        {
            self.redist_originated_v6.remove(&rtype);
        }

        // A v3 router that redistributes is an ASBR; refresh the
        // Router-LSA so the E-bit reflects it.
        self.router_lsa_originate();
    }

    /// Run [`Self::as_external_redist_resync_v3`] for every source that
    /// is either configured or still has originated state to clean up.
    /// Called from the RIB route-churn handlers.
    pub fn as_external_redist_resync_all_v3(&mut self) {
        let rtypes: BTreeSet<crate::rib::RibType> = self
            .redist
            .keys()
            .copied()
            .chain(self.redist_originated_v6.keys().copied())
            .collect();
        for rtype in rtypes {
            self.as_external_redist_resync_v3(rtype);
        }
    }

    /// v3 sibling of `nssa_redist_connected_resync`: rebuild this
    /// area's self-originated Type-7 (NSSA-LSA) set for redistribute-
    /// connected from the cached RIB-known v6 connected routes
    /// (`redist_v6`). Idempotent; originates with FA=None (the
    /// translator and `add_nssa_routes_v3` resolve via the originator /
    /// the translating ABR) and metric / E-bit from config.
    pub fn nssa_redist_connected_resync_v3(&mut self, area_id: Ipv4Addr) {
        use crate::rib::RibType;

        let (entry, area_type, prev_originated) = {
            let Some(area) = self.areas.get(area_id) else {
                return;
            };
            (
                area.redistribute.connected,
                area.area_type,
                area.redist_connected_originated_v6.clone(),
            )
        };

        let desired: BTreeSet<ipnet::Ipv6Net> = if area_type.is_nssa() && entry.is_some() {
            self.redist_v6
                .iter()
                .filter(|((rtype, _prefix), _entry)| *rtype == RibType::Connected)
                .map(|((_, prefix), _)| *prefix)
                .collect()
        } else {
            BTreeSet::new()
        };

        for prefix in prev_originated
            .difference(&desired)
            .copied()
            .collect::<Vec<_>>()
        {
            self.nssa_lsa_flush_for_prefix_v3(area_id, prefix);
            if let Some(area) = self.areas.get_mut(area_id) {
                area.redist_connected_originated_v6.remove(&prefix);
            }
        }

        if let Some(redist_entry) = entry
            && area_type.is_nssa()
        {
            for prefix in &desired {
                self.nssa_lsa_originate_for_prefix_v3(
                    area_id,
                    *prefix,
                    redist_entry.metric,
                    redist_entry.metric_type.is_type_2(),
                    None,
                );
                if let Some(area) = self.areas.get_mut(area_id) {
                    area.redist_connected_originated_v6.insert(*prefix);
                }
            }
        }
    }

    /// RFC 3101 §2.3 v3 NSSA default-LSA origination. Thin
    /// wrapper around `nssa_lsa_originate_for_prefix_v3`: gates
    /// on area type + `nssa_default_originate` knob, then
    /// originates `::/0` with metric 1, E2, no FA.
    pub fn nssa_default_lsa_originate(&mut self, area_id: Ipv4Addr) {
        let area_type = match self.areas.get(area_id) {
            Some(area) => area.area_type,
            None => return,
        };
        if !area_type.is_nssa() || !area_type.nssa_default_originate {
            self.nssa_default_lsa_flush(area_id);
            return;
        }
        let default =
            ipnet::Ipv6Net::new(std::net::Ipv6Addr::UNSPECIFIED, 0).expect("::/0 is valid");
        self.nssa_lsa_originate_for_prefix_v3(
            area_id, default, /* metric */ 1, /* metric_type_2 */ true,
            /* fwd_addr */ None,
        );
    }

    /// Flush our self-originated v3 Type-7 default LSA from
    /// `area_id`.
    pub fn nssa_default_lsa_flush(&mut self, area_id: Ipv4Addr) {
        let default =
            ipnet::Ipv6Net::new(std::net::Ipv6Addr::UNSPECIFIED, 0).expect("::/0 is valid");
        self.nssa_lsa_flush_for_prefix_v3(area_id, default);
    }

    /// v3 mirror of v2's `is_abr`. True when this router has
    /// interfaces in two or more OSPF areas (RFC 2328 §3.3 ABR
    /// test). Areas with zero attached links don't count.
    pub fn is_abr(&self) -> bool {
        self.areas
            .iter()
            .filter(|(_, area)| !area.links.is_empty())
            .count()
            >= 2
    }

    /// True when this router originates AS-External LSAs (RFC 2328
    /// §3.3 ASBR definition) — any instance-level `redistribute`
    /// source is configured. v3 sibling of the v2 `is_asbr`.
    pub fn is_asbr(&self) -> bool {
        !self.redist.is_empty()
    }

    /// RFC 2328 §12.4.3 for OSPFv3 (RFC 5340 §4.4.3.4) — an Area
    /// Border Router condenses each area's route slice into
    /// Inter-Area-Prefix-LSAs (0x2003) flooded into the *other*
    /// attached areas. Driven from `apply_v3_spf_result` after the
    /// per-area slices (`rib6_areas`) are refreshed.
    ///
    /// Loop-safety mirrors v2: our own inter-area route computation
    /// (`add_inter_area_routes_v3`) skips self-originated LSAs, and
    /// origination is diff-gated against the LSDB, so a converged
    /// topology re-floods nothing.
    pub fn abr_summary_originate_v3(&mut self) {
        let attached: Vec<Ipv4Addr> = self
            .areas
            .iter()
            .filter(|(_, a)| !a.links.is_empty())
            .map(|(id, _)| *id)
            .collect();

        if attached.len() < 2 {
            let all: Vec<Ipv4Addr> = self.areas.iter().map(|(id, _)| *id).collect();
            for area_id in all {
                self.abr_summary_sync_area_v3(area_id, &BTreeMap::new());
            }
            return;
        }

        for &area_a in &attached {
            let desired = self.abr_summary_desired_v3(area_a, &attached);
            self.abr_summary_sync_area_v3(area_a, &desired);
        }
    }

    /// Compute the `prefix -> metric` set of Inter-Area-Prefix-LSAs
    /// to advertise into `area_a` from the other attached areas'
    /// route slices — same rules as v2's `abr_summary_desired`:
    /// intra-area routes of any other area; inter-area routes only
    /// from the backbone into non-backbone areas; skip prefixes
    /// `area_a` reaches intra-area; externals and LSInfinity never;
    /// lowest metric wins; `no-summary` areas take nothing.
    fn abr_summary_desired_v3(
        &self,
        area_a: Ipv4Addr,
        attached: &[Ipv4Addr],
    ) -> BTreeMap<ipnet::Ipv6Net, u32> {
        use ospf_packet::OSPFV3_LS_INFINITY;

        let mut desired: BTreeMap<ipnet::Ipv6Net, u32> = BTreeMap::new();

        if self
            .areas
            .get(area_a)
            .map(|a| a.area_type.no_summary)
            .unwrap_or(false)
        {
            return desired;
        }

        for &area_b in attached {
            if area_b == area_a {
                continue;
            }
            let Some(rib_b) = self.rib6_areas.get(&area_b) else {
                continue;
            };
            let ranges_b = self
                .areas
                .get(area_b)
                .map(|a| a.ranges_v6.clone())
                .unwrap_or_default();
            // Active ranges of area B this walk: range prefix ->
            // largest component metric (RFC 2328 §12.4.3).
            let mut active_ranges: BTreeMap<ipnet::Ipv6Net, u32> = BTreeMap::new();
            for (prefix, route) in rib_b.iter() {
                let advertise = match route.path_type {
                    RouteType::IntraArea => true,
                    RouteType::InterArea => area_b == AREA0 && area_a != AREA0,
                    RouteType::External => false,
                };
                if !advertise || route.metric >= OSPFV3_LS_INFINITY {
                    continue;
                }
                // Address ranges condense area B's own intra-area
                // routes — the component activates the aggregate
                // instead of advertising (most-specific range wins).
                if route.path_type == RouteType::IntraArea {
                    if let Some(range_prefix) = ranges_b
                        .keys()
                        .filter(|r| r.contains(&prefix))
                        .max_by_key(|r| r.prefix_len())
                        .copied()
                    {
                        active_ranges
                            .entry(range_prefix)
                            .and_modify(|m| *m = (*m).max(route.metric))
                            .or_insert(route.metric);
                        continue;
                    }
                }
                let intra_in_a = self
                    .rib6_areas
                    .get(&area_a)
                    .and_then(|r| r.get(&prefix))
                    .map(|r| r.path_type == RouteType::IntraArea)
                    .unwrap_or(false);
                if intra_in_a {
                    continue;
                }
                let metric = route.metric.min(OSPFV3_LS_INFINITY - 1);
                desired
                    .entry(prefix)
                    .and_modify(|m| *m = (*m).min(metric))
                    .or_insert(metric);
            }
            // Fold the aggregates in — largest component metric or
            // the configured cost; `not-advertise` hides the range.
            for (range_prefix, max_metric) in active_ranges {
                let Some(entry) = ranges_b.get(&range_prefix) else {
                    continue;
                };
                if entry.not_advertise {
                    continue;
                }
                let intra_in_a = self
                    .rib6_areas
                    .get(&area_a)
                    .and_then(|r| r.get(&range_prefix))
                    .map(|r| r.path_type == RouteType::IntraArea)
                    .unwrap_or(false);
                if intra_in_a {
                    continue;
                }
                let metric = entry.cost.unwrap_or(max_metric).min(OSPFV3_LS_INFINITY - 1);
                desired
                    .entry(range_prefix)
                    .and_modify(|m| *m = (*m).min(metric))
                    .or_insert(metric);
            }
        }
        desired
    }

    /// Reconcile the self-originated Inter-Area-Prefix-LSAs in
    /// `area_id`'s LSDB against `desired`: flush stale, (re)originate
    /// new / metric-changed, leave unchanged untouched.
    fn abr_summary_sync_area_v3(
        &mut self,
        area_id: Ipv4Addr,
        desired: &BTreeMap<ipnet::Ipv6Net, u32>,
    ) {
        use crate::ospf::lsdb::OSPF_MAX_AGE;
        use ospf_packet::{OSPFV3_INTER_AREA_PREFIX_LSA_TYPE, Ospfv3LsBody};

        // Snapshot current self-originated (ls_id, prefix, metric).
        let current: Vec<(u32, ipnet::Ipv6Net, u32)> = {
            let Some(area) = self.areas.get(area_id) else {
                return;
            };
            area.lsdb
                .iter_by_raw_type(OSPFV3_INTER_AREA_PREFIX_LSA_TYPE)
                .filter(|(_, lsa)| lsa.data.h.advertising_router == self.router_id)
                .filter(|(_, lsa)| lsa.data.h.ls_age < OSPF_MAX_AGE)
                .filter_map(|((ls_id, _), lsa)| {
                    let Ospfv3LsBody::InterAreaPrefix(ref body) = lsa.data.body else {
                        return None;
                    };
                    ospfv3_prefix_to_ipv6net(body.prefix_length, &body.address_prefix)
                        .map(|p| (ls_id, p, body.metric))
                })
                .collect()
        };

        for (ls_id, prefix, _metric) in &current {
            if !desired.contains_key(prefix) {
                self.inter_area_prefix_lsa_flush_v3(area_id, *ls_id);
            }
        }

        for (prefix, metric) in desired {
            let unchanged = current.iter().any(|(_, p, m)| p == prefix && m == metric);
            if !unchanged {
                self.inter_area_prefix_lsa_originate_v3(area_id, *prefix, *metric);
            }
        }
    }

    /// Originate (or re-originate at seq+1) one Inter-Area-Prefix-LSA
    /// for `prefix`/`metric` into `area_id` and flood it. LS-ID is the
    /// same FNV-1a prefix hash the v3 NSSA/AS-External originators use
    /// (v3 LS-IDs carry no addressing semantics, RFC 5340 §4.4.3.4).
    fn inter_area_prefix_lsa_originate_v3(
        &mut self,
        area_id: Ipv4Addr,
        prefix: ipnet::Ipv6Net,
        metric: u32,
    ) {
        use ospf_packet::{
            OSPFV3_INTER_AREA_PREFIX_LSA_TYPE, Ospfv3InterAreaPrefixLsa, Ospfv3LsBody,
            Ospfv3LsaHeader, Ospfv3PrefixOptions, ospfv3_prefix_wire_len,
        };

        let link_state_id = nssa_v3_ls_id(&prefix);

        let wire_len = ospfv3_prefix_wire_len(prefix.prefix_len());
        let mut address_prefix = vec![0u8; wire_len];
        let net_bytes = prefix.network().octets();
        let copy_len = wire_len.min(net_bytes.len());
        address_prefix[..copy_len].copy_from_slice(&net_bytes[..copy_len]);

        let body = Ospfv3InterAreaPrefixLsa {
            metric: metric & 0x00FF_FFFF,
            prefix_length: prefix.prefix_len(),
            prefix_options: Ospfv3PrefixOptions::new(),
            address_prefix,
        };
        let header = Ospfv3LsaHeader {
            ls_age: 0,
            ls_type: OSPFV3_INTER_AREA_PREFIX_LSA_TYPE,
            link_state_id,
            advertising_router: self.router_id,
            ls_seq_number: 0x8000_0001,
            ls_checksum: 0,
            length: 0,
        };
        let mut lsa = ospf_packet::Ospfv3Lsa {
            h: header,
            body: Ospfv3LsBody::InterAreaPrefix(body),
            raw: None,
        };

        let key: super::lsdb::OspfLsaKey = (
            OSPFV3_INTER_AREA_PREFIX_LSA_TYPE,
            link_state_id,
            self.router_id,
        );
        let flood_lsa = if let Some(area) = self.areas.get_mut(area_id) {
            if let Some(existing) = area.lsdb.lookup_by_raw_key(key) {
                lsa.h.ls_seq_number = seq_max(
                    lsa.h.ls_seq_number,
                    existing.h.ls_seq_number.saturating_add(1),
                );
            }
            lsa.update();
            let flood_lsa = lsa.clone();
            area.lsdb.install_originated(lsa, &self.tx, Some(area_id));
            Some(flood_lsa)
        } else {
            None
        };
        if let Some(lsa) = flood_lsa {
            self.flood_self_originated_lsa(area_id, &lsa);
        }
    }

    /// Flush (MaxAge) one self-originated Inter-Area-Prefix-LSA out of
    /// `area_id` and re-flood so neighbors drop it.
    fn inter_area_prefix_lsa_flush_v3(&mut self, area_id: Ipv4Addr, ls_id: u32) {
        use ospf_packet::OSPFV3_INTER_AREA_PREFIX_LSA_TYPE;

        let key: super::lsdb::OspfLsaKey =
            (OSPFV3_INTER_AREA_PREFIX_LSA_TYPE, ls_id, self.router_id);
        let flushed = if let Some(area) = self.areas.get_mut(area_id) {
            area.lsdb.flush_lsa_by_raw_key(key, &self.tx, Some(area_id))
        } else {
            None
        };
        if let Some(lsa) = flushed {
            self.flood_self_originated_lsa(area_id, &lsa);
        }
    }

    /// (Re)originate / flush Inter-Area-Router-LSAs (0x2004) for all
    /// ASBRs known to this ABR — v3 sibling of v2's Type-4 machinery
    /// (RFC 2328 §12.4.3 / RFC 5340 §4.4.3.5). A router in area A
    /// cannot see the E-bit of an ASBR in area B; these LSAs give it
    /// the ASBR reachability that AS-External route computation needs.
    pub fn abr_summary_asbr_originate_v3(&mut self) {
        let attached: Vec<Ipv4Addr> = self
            .areas
            .iter()
            .filter(|(_, a)| !a.links.is_empty())
            .map(|(id, _)| *id)
            .collect();

        if attached.len() < 2 {
            let all: Vec<Ipv4Addr> = self.areas.iter().map(|(id, _)| *id).collect();
            for area_id in all {
                self.abr_summary_asbr_sync_area_v3(area_id, &BTreeMap::new());
            }
            return;
        }

        for &area_a in &attached {
            let desired = self.abr_summary_asbr_desired_v3(area_a, &attached);
            self.abr_summary_asbr_sync_area_v3(area_a, &desired);
        }
    }

    /// Compute the `asbr_router_id -> metric` map of
    /// Inter-Area-Router-LSAs to advertise into `area_a`: walk the
    /// other attached areas' Router-LSAs for the E-bit, and use our
    /// SPF cost to that router (from `spf_results`) as the metric.
    fn abr_summary_asbr_desired_v3(
        &self,
        area_a: Ipv4Addr,
        attached: &[Ipv4Addr],
    ) -> BTreeMap<Ipv4Addr, u32> {
        use ospf_packet::{
            OSPFV3_LS_INFINITY, OSPFV3_ROUTER_LSA_FLAG_E, OSPFV3_ROUTER_LSA_TYPE, Ospfv3LsBody,
        };

        let mut desired: BTreeMap<Ipv4Addr, u32> = BTreeMap::new();

        for &area_b in attached {
            if area_b == area_a {
                continue;
            }
            let Some(spf_b) = self.spf_results.get(&area_b) else {
                continue;
            };
            let Some(area_b_ref) = self.areas.get(area_b) else {
                continue;
            };
            for (_, lsa) in area_b_ref.lsdb.iter_by_raw_type(OSPFV3_ROUTER_LSA_TYPE) {
                let Ospfv3LsBody::Router(ref body) = lsa.data.body else {
                    continue;
                };
                if (body.flags & OSPFV3_ROUTER_LSA_FLAG_E) == 0 {
                    continue;
                }
                let asbr_id = lsa.data.h.advertising_router;
                if asbr_id == self.router_id {
                    continue;
                }
                let Some(vertex) = self.lsp_map.lookup(asbr_id) else {
                    continue;
                };
                let Some(path) = spf_b.get(&vertex) else {
                    continue;
                };
                let metric = path.cost.min(OSPFV3_LS_INFINITY - 1);
                desired
                    .entry(asbr_id)
                    .and_modify(|m| *m = (*m).min(metric))
                    .or_insert(metric);
            }
        }
        desired
    }

    /// Reconcile self-originated Inter-Area-Router-LSAs in `area_id`
    /// against `desired`.
    fn abr_summary_asbr_sync_area_v3(
        &mut self,
        area_id: Ipv4Addr,
        desired: &BTreeMap<Ipv4Addr, u32>,
    ) {
        use crate::ospf::lsdb::OSPF_MAX_AGE;
        use ospf_packet::{OSPFV3_INTER_AREA_ROUTER_LSA_TYPE, Ospfv3LsBody};

        let current: Vec<(Ipv4Addr, u32)> = {
            let Some(area) = self.areas.get(area_id) else {
                return;
            };
            area.lsdb
                .iter_by_raw_type(OSPFV3_INTER_AREA_ROUTER_LSA_TYPE)
                .filter(|(_, lsa)| lsa.data.h.advertising_router == self.router_id)
                .filter(|(_, lsa)| lsa.data.h.ls_age < OSPF_MAX_AGE)
                .filter_map(|(_, lsa)| {
                    let Ospfv3LsBody::InterAreaRouter(ref body) = lsa.data.body else {
                        return None;
                    };
                    Some((Ipv4Addr::from(body.destination_router_id), body.metric))
                })
                .collect()
        };

        for (asbr_id, _) in &current {
            if !desired.contains_key(asbr_id) {
                self.inter_area_router_lsa_flush_v3(area_id, *asbr_id);
                if let Some(area) = self.areas.get_mut(area_id) {
                    area.asbr_summaries_originated.remove(asbr_id);
                }
            }
        }

        for (asbr_id, metric) in desired {
            let unchanged = current.iter().any(|(id, m)| id == asbr_id && m == metric);
            if !unchanged {
                self.inter_area_router_lsa_originate_v3(area_id, *asbr_id, *metric);
                if let Some(area) = self.areas.get_mut(area_id) {
                    area.asbr_summaries_originated.insert(*asbr_id);
                }
            }
        }
    }

    /// Originate (or refresh) one Inter-Area-Router-LSA for `asbr_id`
    /// into `area_id`. LS-ID is the destination router-id, mirroring
    /// v2's Type-4 convention.
    fn inter_area_router_lsa_originate_v3(
        &mut self,
        area_id: Ipv4Addr,
        asbr_id: Ipv4Addr,
        metric: u32,
    ) {
        use ospf_packet::{
            OSPFV3_INTER_AREA_ROUTER_LSA_TYPE, Ospfv3InterAreaRouterLsa, Ospfv3LsBody,
            Ospfv3LsaHeader, Ospfv3Options,
        };

        let link_state_id = u32::from(asbr_id);
        let body = Ospfv3InterAreaRouterLsa {
            options: Ospfv3Options::default(),
            metric: metric & 0x00FF_FFFF,
            destination_router_id: u32::from(asbr_id),
        };
        let header = Ospfv3LsaHeader {
            ls_age: 0,
            ls_type: OSPFV3_INTER_AREA_ROUTER_LSA_TYPE,
            link_state_id,
            advertising_router: self.router_id,
            ls_seq_number: 0x8000_0001,
            ls_checksum: 0,
            length: 0,
        };
        let mut lsa = ospf_packet::Ospfv3Lsa {
            h: header,
            body: Ospfv3LsBody::InterAreaRouter(body),
            raw: None,
        };

        let key: super::lsdb::OspfLsaKey = (
            OSPFV3_INTER_AREA_ROUTER_LSA_TYPE,
            link_state_id,
            self.router_id,
        );
        let flood_lsa = if let Some(area) = self.areas.get_mut(area_id) {
            if let Some(existing) = area.lsdb.lookup_by_raw_key(key) {
                lsa.h.ls_seq_number = seq_max(
                    lsa.h.ls_seq_number,
                    existing.h.ls_seq_number.saturating_add(1),
                );
            }
            lsa.update();
            let flood_lsa = lsa.clone();
            area.lsdb.install_originated(lsa, &self.tx, Some(area_id));
            Some(flood_lsa)
        } else {
            None
        };
        if let Some(lsa) = flood_lsa {
            self.flood_self_originated_lsa(area_id, &lsa);
        }
    }

    /// Flush one self-originated Inter-Area-Router-LSA for `asbr_id`
    /// from `area_id`.
    fn inter_area_router_lsa_flush_v3(&mut self, area_id: Ipv4Addr, asbr_id: Ipv4Addr) {
        use ospf_packet::OSPFV3_INTER_AREA_ROUTER_LSA_TYPE;

        let key: super::lsdb::OspfLsaKey = (
            OSPFV3_INTER_AREA_ROUTER_LSA_TYPE,
            u32::from(asbr_id),
            self.router_id,
        );
        let flushed = if let Some(area) = self.areas.get_mut(area_id) {
            area.lsdb.flush_lsa_by_raw_key(key, &self.tx, Some(area_id))
        } else {
            None
        };
        if let Some(lsa) = flushed {
            self.flood_self_originated_lsa(area_id, &lsa);
        }
    }

    /// v3 mirror of v2's `is_nssa_translator_for`. RFC 3101 §3.1
    /// translator-role evaluation:
    /// - `Never`: never translate.
    /// - `Always`: translate unconditionally.
    /// - `Candidate`: translate iff our router-id is the highest
    ///   among NSSA Router-LSAs with B-bit set
    ///   (`OSPFV3_ROUTER_LSA_FLAG_B = 0x01`).
    ///
    /// Election is locally computed. The Nt-bit equivalent in our
    /// Router-LSA is not emitted (same reason as v2: per-area
    /// Router-LSA emission is a wider refactor). All known
    /// implementations elect locally so interop is unaffected.
    pub fn is_nssa_translator_for(&self, area_id: Ipv4Addr) -> bool {
        use super::area::NssaTranslatorRole;
        use ospf_packet::{OSPFV3_ROUTER_LSA_FLAG_B, OSPFV3_ROUTER_LSA_TYPE, Ospfv3LsBody};
        let Some(area) = self.areas.get(area_id) else {
            return false;
        };
        if !area.area_type.is_nssa() {
            return false;
        }
        if !self.is_abr() {
            return false;
        }
        match area.area_type.nssa_translator_role {
            NssaTranslatorRole::Never => false,
            NssaTranslatorRole::Always => true,
            NssaTranslatorRole::Candidate => {
                let highest_other = area
                    .lsdb
                    .iter_by_raw_type(OSPFV3_ROUTER_LSA_TYPE)
                    .filter_map(|(_, lsa)| {
                        let Ospfv3LsBody::Router(ref body) = lsa.data.body else {
                            return None;
                        };
                        if (body.flags & OSPFV3_ROUTER_LSA_FLAG_B) == 0 {
                            return None;
                        }
                        if lsa.data.h.advertising_router == self.router_id {
                            return None;
                        }
                        Some(lsa.data.h.advertising_router)
                    })
                    .max();
                match highest_other {
                    None => true,
                    Some(other) => self.router_id >= other,
                }
            }
        }
    }

    /// Translate a single v3 Type-7 NSSA-LSA into a Type-5
    /// AS-External-LSA, install in `lsdb_as`, and flood AS-wide.
    /// RFC 3101 §3.2 (inherited by v3 via RFC 5340 §A.4.9). Same
    /// gate semantics as v2's `nssa_translate_one`:
    ///
    /// - source body is `Ospfv3LsBody::Nssa(_)` (defensive)
    /// - not MaxAge — flushed Type-7s shouldn't seed translations
    /// - not self-originated
    /// - P-bit set in the source's `prefix_options` per RFC 3101
    ///   §2.4 (in v3 the P-bit lives in prefix_options, not in
    ///   the LSA header as in v2)
    /// - forwarding-address present — FA=None mirrors v2's
    ///   FA=0.0.0.0 skip (defer FA-resolution symmetrically)
    fn nssa_translate_one_v3(&mut self, type7: &ospf_packet::Ospfv3Lsa) -> bool {
        use crate::ospf::lsdb::OSPF_MAX_AGE;
        use ospf_packet::{OSPFV3_AS_EXTERNAL_LSA_TYPE, Ospfv3LsBody, Ospfv3Lsa, Ospfv3LsaHeader};

        let Ospfv3LsBody::Nssa(ref body) = type7.body else {
            return false;
        };
        if type7.h.ls_age >= OSPF_MAX_AGE {
            return false;
        }
        if type7.h.advertising_router == self.router_id {
            return false;
        }
        if !body.prefix_options.p() {
            return false;
        }
        // FA=None (forwarding address absent) is permitted: the
        // translated Type-5 also carries no FA, so receivers reach the
        // prefix via the path to this ABR, which itself installs the
        // Type-7 route. Mirrors the v2 `nssa_translate_one` FA=0
        // handling.

        let link_state_id = type7.h.link_state_id;
        // Build a Type-5 wrapping the same body — RFC 5340 §A.4.9
        // says NSSA-LSA and AS-External-LSA share the wire body.
        let translated_body = body.clone();
        let header = Ospfv3LsaHeader {
            ls_age: 0,
            ls_type: OSPFV3_AS_EXTERNAL_LSA_TYPE,
            link_state_id,
            advertising_router: self.router_id,
            ls_seq_number: 0x8000_0001,
            ls_checksum: 0,
            length: 0,
        };
        let mut new_lsa = Ospfv3Lsa {
            h: header,
            body: Ospfv3LsBody::AsExternal(translated_body),
            raw: None,
        };

        // Preserve sequence number on refresh.
        let key: super::lsdb::OspfLsaKey =
            (OSPFV3_AS_EXTERNAL_LSA_TYPE, link_state_id, self.router_id);
        if let Some(existing) = self.lsdb_as.lookup_by_raw_key(key) {
            new_lsa.h.ls_seq_number = seq_max(
                new_lsa.h.ls_seq_number,
                existing.h.ls_seq_number.saturating_add(1),
            );
        }
        new_lsa.update();

        let flood_lsa = new_lsa.clone();
        self.lsdb_as.install_originated(new_lsa, &self.tx, None);
        self.flood_lsa_through_as_v3(&flood_lsa, None);
        true
    }

    /// Compute the set of v3 Type-7 link_state_ids in `area_id`
    /// that we SHOULD currently be translating. Mirror of v2's
    /// `nssa_translatable_ls_ids`. Stored as `Ipv4Addr` for shape
    /// parity with the existing `OspfArea::nssa_translated`
    /// bookkeeping (a v3 link_state_id is just a u32 and round-
    /// trips through `Ipv4Addr::from(u32)` losslessly).
    fn nssa_translatable_link_state_ids_v3(&self, area_id: Ipv4Addr) -> BTreeSet<Ipv4Addr> {
        use crate::ospf::lsdb::OSPF_MAX_AGE;
        use ospf_packet::{OSPFV3_NSSA_LSA_TYPE, Ospfv3LsBody};
        let mut out = BTreeSet::new();
        let Some(area) = self.areas.get(area_id) else {
            return out;
        };
        for (_, lsa) in area.lsdb.iter_by_raw_type(OSPFV3_NSSA_LSA_TYPE) {
            let d = &lsa.data;
            if d.h.ls_age >= OSPF_MAX_AGE {
                continue;
            }
            if d.h.advertising_router == self.router_id {
                continue;
            }
            let Ospfv3LsBody::Nssa(ref body) = d.body else {
                continue;
            };
            if !body.prefix_options.p() {
                continue;
            }
            // FA=None is translatable (see `nssa_translate_one_v3`).
            out.insert(Ipv4Addr::from(d.h.link_state_id));
        }
        out
    }

    /// Rebuild this NSSA area's translated Type-5 set from the
    /// current Type-7 LSDB contents. Mirror of v2's
    /// `nssa_translate_resync`.
    pub fn nssa_translate_resync(&mut self, area_id: Ipv4Addr) {
        use ospf_packet::{OSPFV3_AS_EXTERNAL_LSA_TYPE, OSPFV3_NSSA_LSA_TYPE};

        let translating = self.is_nssa_translator_for(area_id);
        let desired = if translating {
            self.nssa_translatable_link_state_ids_v3(area_id)
        } else {
            BTreeSet::new()
        };
        let prev: BTreeSet<Ipv4Addr> = self
            .areas
            .get(area_id)
            .map(|a| a.nssa_translated.clone())
            .unwrap_or_default();

        // Flush translations that should no longer exist.
        for ls_id in prev.difference(&desired).copied().collect::<Vec<_>>() {
            let key: super::lsdb::OspfLsaKey = (
                OSPFV3_AS_EXTERNAL_LSA_TYPE,
                u32::from(ls_id),
                self.router_id,
            );
            let flushed = self.lsdb_as.flush_lsa_by_raw_key(key, &self.tx, None);
            if let Some(lsa) = flushed {
                self.flood_lsa_through_as_v3(&lsa, None);
            }
            if let Some(area) = self.areas.get_mut(area_id) {
                area.nssa_translated.remove(&ls_id);
            }
        }

        if !translating {
            return;
        }

        // Snapshot source Type-7 LSAs before calling
        // `nssa_translate_one_v3` (which takes &mut self).
        let sources: Vec<ospf_packet::Ospfv3Lsa> = self
            .areas
            .get(area_id)
            .map(|a| {
                a.lsdb
                    .iter_by_raw_type(OSPFV3_NSSA_LSA_TYPE)
                    .filter(|(_, lsa)| desired.contains(&Ipv4Addr::from(lsa.data.h.link_state_id)))
                    .map(|(_, lsa)| lsa.data.clone())
                    .collect()
            })
            .unwrap_or_default();

        for source in &sources {
            if self.nssa_translate_one_v3(source)
                && let Some(area) = self.areas.get_mut(area_id)
            {
                area.nssa_translated
                    .insert(Ipv4Addr::from(source.h.link_state_id));
            }
        }
    }

    /// Resync NSSA translator state for every NSSA area on this
    /// v3 router. Use when a router-wide property changed (ABR
    /// status flip via link join/leave). Mirror of v2.
    pub fn nssa_translate_resync_all(&mut self) {
        let nssa_area_ids: Vec<Ipv4Addr> = self
            .areas
            .iter()
            .filter(|(_, area)| area.area_type.is_nssa())
            .map(|(&id, _)| id)
            .collect();
        for area_id in nssa_area_ids {
            self.nssa_translate_resync(area_id);
        }
    }

    /// AS-scope flood for v3. Walks every non-stub / non-NSSA
    /// area attached to this router and re-floods the LSA on each
    /// using the existing per-area flood path.
    fn flood_lsa_through_as_v3(
        &mut self,
        lsa: &ospf_packet::Ospfv3Lsa,
        source: Option<(u32, std::net::Ipv6Addr)>,
    ) {
        let area_ids: Vec<(Ipv4Addr, super::area::AreaType)> = self
            .areas
            .iter()
            .map(|(&id, area)| (id, area.area_type))
            .collect();
        for (area_id, area_type) in area_ids {
            if area_type.is_stub_or_nssa() {
                continue;
            }
            self.flood_lsa_through_area(area_id, lsa, source);
        }
    }

    /// Flood a v3 LSA through `area_id`, optionally exempting the
    /// source neighbor that fed it to us (RFC 2328 §13.3 Step 1c).
    /// RFC 5187 §3.2 bullets 2-3 — v3 mirror of
    /// `Ospf<Ospfv2>::gr_helper_check_exit`. Called from
    /// `flood_lsa_through_area` after each area-LSA install. For
    /// each helper-mode neighbor in the area, decide whether the
    /// install warrants exit:
    ///
    ///   - `advertising_router != restarter`: any topology-affecting
    ///     LSA is an exit trigger when `helper_strict_lsa_checking`.
    ///     When that knob is off (relaxed mode), non-restarter
    ///     LSAs are ignored.
    ///   - `advertising_router == restarter`: compare against the
    ///     `(seq, checksum)` we snapshotted at helper entry. Exact
    ///     match → quiescent re-flood (no exit). Differs → exit.
    ///
    /// Topology-affecting v3 LS Types: Router (0x2001), Network
    /// (0x2002), Inter-Area-Prefix (0x2003), Inter-Area-Router
    /// (0x2004), Intra-Area-Prefix (0x2009). All other LSAs (Link,
    /// AS-External, Grace, the RFC 8362 E-LSAs) are ignored
    /// because they don't change intra-area routing.
    fn gr_helper_check_exit(&mut self, area_id: Ipv4Addr, lsa: &ospf_packet::Ospfv3Lsa) {
        use ospf_packet::{
            OSPFV3_INTER_AREA_PREFIX_LSA_TYPE, OSPFV3_INTER_AREA_ROUTER_LSA_TYPE,
            OSPFV3_INTRA_AREA_PREFIX_LSA_TYPE, OSPFV3_NETWORK_LSA_TYPE, OSPFV3_ROUTER_LSA_TYPE,
        };

        let topology_affecting = matches!(
            lsa.h.ls_type,
            OSPFV3_ROUTER_LSA_TYPE
                | OSPFV3_NETWORK_LSA_TYPE
                | OSPFV3_INTER_AREA_PREFIX_LSA_TYPE
                | OSPFV3_INTER_AREA_ROUTER_LSA_TYPE
                | OSPFV3_INTRA_AREA_PREFIX_LSA_TYPE
        );
        if !topology_affecting {
            return;
        }
        // v3 LSDB key shape: `(ls_type: u16, link_state_id: u32,
        // advertising_router: Ipv4Addr)`. No conversion needed —
        // these fields are already in their key-native form.
        let key: super::lsdb::OspfLsaKey =
            (lsa.h.ls_type, lsa.h.link_state_id, lsa.h.advertising_router);

        let Some(area) = self.areas.get(area_id) else {
            return;
        };
        let link_indices: Vec<u32> = area.links.iter().copied().collect();

        let mut exits: Vec<(u32, Ipv4Addr, &'static str)> = Vec::new();
        for ifindex in link_indices {
            let Some(link) = self.links.get(&ifindex) else {
                continue;
            };
            for nbr in link.nbrs.values() {
                let Some(helper) = nbr.gr_helper.as_ref() else {
                    continue;
                };
                let exit_reason = if lsa.h.advertising_router == nbr.ident.router_id {
                    match helper.lsdb_snapshot.get(&key) {
                        Some(&(seq, csum))
                            if seq == lsa.h.ls_seq_number && csum == lsa.h.ls_checksum =>
                        {
                            continue;
                        }
                        _ => "restarter LSA changed from snapshot",
                    }
                } else if self.gr_config.helper_strict_lsa_checking {
                    "non-restarter topology change in area"
                } else {
                    continue;
                };
                exits.push((ifindex, nbr.ident.router_id, exit_reason));
            }
        }
        for (ifindex, router_id, reason) in exits {
            // v3 reuses v2's gr_helper_exit body verbatim — clear
            // helper state, fire `InactivityTimer` event so the
            // shared NFSM kill path runs.
            let Some(link) = self.links.get_mut(&ifindex) else {
                continue;
            };
            let Some(nbr) = link.nbrs.get_mut(&router_id) else {
                continue;
            };
            if nbr.gr_helper.take().is_none() {
                continue;
            }
            tracing::info!(
                "[GR Helper v3] exit for nbr {} on ifindex={} (reason: {})",
                router_id,
                ifindex,
                reason
            );
            let _ = self.tx.send(Message::Nfsm(
                ifindex,
                router_id,
                super::nfsm::NfsmEvent::InactivityTimer,
            ));
        }
    }

    /// Mirrors v2's `flood_lsa_through_area`.
    ///
    /// `source = None` is the self-origination path: every
    /// Exchange-or-later neighbor on every area link is a
    /// recipient. `source = Some((ifindex, nbr_v6))` is the
    /// "received LSA" path: skip the (ifindex, neighbor link-local
    /// v6) we got the LSA from. v3 identifies the source neighbor
    /// by link-local v6 because that's what `Message::Flood<Ospfv3>`
    /// carries (`V::Addr = Ipv6Addr`).
    ///
    /// Per RFC 2328 §13.3 step 1(d), every LSA sent to a neighbor
    /// is added to that neighbor's retransmit list and re-sent
    /// at RxmtInterval until acknowledged (either explicitly via
    /// LSAck or implicitly via §13.1 step 7 — see
    /// `ospfv3_ls_upd_proc`).
    fn flood_lsa_through_area(
        &mut self,
        area_id: Ipv4Addr,
        lsa: &ospf_packet::Ospfv3Lsa,
        source: Option<(u32, std::net::Ipv6Addr)>,
    ) {
        use ospf_packet::{Ospfv3LsUpdate, Ospfv3Packet, Ospfv3Payload};

        // RFC 5187 §3.2 — every LSA flooded here was just installed
        // in the area LSDB, so this is the v3 choke point for the
        // topology-change helper exit (mirror of v2's hook in
        // `Ospf<Ospfv2>::flood_lsa_through_area`). Runs before the
        // fanout iteration so an exit can deconstruct any state
        // we'd otherwise loop over.
        self.gr_helper_check_exit(area_id, lsa);

        let Some(tx) = self.v3_send_tx.as_ref().cloned() else {
            return;
        };
        let Some(area) = self.areas.get(area_id) else {
            return;
        };
        let link_indices: Vec<u32> = area.links.iter().copied().collect();

        for ifindex in link_indices {
            let Some(link) = self.links.get_mut(&ifindex) else {
                continue;
            };
            let Some(src) = link.addr.iter().find_map(|a| {
                let addr = a.prefix.addr();
                addr.is_unicast_link_local().then_some(addr)
            }) else {
                continue;
            };
            let retransmit_interval = link.retransmit_interval();

            for nbr in link.nbrs.values_mut() {
                if nbr.state < NfsmState::Exchange {
                    continue;
                }
                if let Some((src_if, src_v6)) = source
                    && ifindex == src_if
                    && nbr.ident.prefix.addr() == src_v6
                {
                    continue;
                }

                // RFC 2328 §13.3 step 1(d): track the LSA on this
                // neighbor's retransmit list so the per-neighbor
                // retransmit timer can resend it until we get an
                // ack.
                super::flood::ospf_ls_retransmit_add(nbr, lsa, retransmit_interval);

                let ls_upd = Ospfv3LsUpdate {
                    lsas: vec![lsa.clone()],
                };
                let packet = Ospfv3Packet::new(
                    &self.router_id,
                    &area_id,
                    0,
                    Ospfv3Payload::LsUpdate(ls_upd),
                );
                let item = super::network_v6::Ospfv3Send {
                    packet,
                    ifindex,
                    dest: Some(nbr.ident.prefix.addr()),
                    src,
                };
                if let Err(e) = tx.send(item) {
                    tracing::warn!("[v3 Flood] channel send failed: {}", e);
                }
            }
        }
    }

    /// Flood a self-originated v3 LSA to every Exchange-or-later
    /// neighbor in the area. Minimal RFC 2328 §13.3 — no DR / BDR
    /// ordering, no ls_req cleanup for Exchange / Loading neighbors.
    /// Those land alongside the §13.1 hardening of
    /// `ospfv3_ls_upd_recv`. Retransmit-list bookkeeping happens
    /// in `flood_lsa_through_area`.
    ///
    /// The LSU goes through the dedicated `Ospfv3Send` channel so
    /// `network_v6::write_packet_v6` stamps the IPv6 pseudo-header
    /// checksum. Source = the link's first link-local v6; dest =
    /// the neighbor's link-local (the `/128` captured in
    /// `ospfv3_hello_recv`).
    fn flood_self_originated_lsa(&mut self, area_id: Ipv4Addr, lsa: &ospf_packet::Ospfv3Lsa) {
        self.flood_lsa_through_area(area_id, lsa, None);
    }

    /// Handle the retransmit timer firing for a v3 neighbor.
    /// Mirrors v2's `process_retransmit`: walk the neighbor's
    /// `ls_rxmt` map, resend every LSA still on it in a single
    /// LSU, and restart the timer. Empty `ls_rxmt` simply clears
    /// the timer slot.
    ///
    /// `router_id` is the neighbor key in `OspfLink::nbrs` for v3
    /// (the `Ipv4Addr` passed through `Message::Retransmit` is the
    /// neighbor's router-id, set up by `ospf_retransmit_timer` via
    /// `V::nbr_addr`).
    fn process_retransmit(&mut self, ifindex: u32, router_id: Ipv4Addr) {
        use ospf_packet::{Ospfv3LsUpdate, Ospfv3Packet, Ospfv3Payload};

        let Some(tx) = self.v3_send_tx.as_ref().cloned() else {
            return;
        };
        let Some(link) = self.links.get_mut(&ifindex) else {
            return;
        };
        let area_id = link.area;
        let retransmit_interval = link.retransmit_interval();
        let Some(src) = link.addr.iter().find_map(|a| {
            let addr = a.prefix.addr();
            addr.is_unicast_link_local().then_some(addr)
        }) else {
            return;
        };
        let Some(nbr) = link.nbrs.get_mut(&router_id) else {
            return;
        };
        if nbr.ls_rxmt.is_empty() {
            nbr.timer.ls_rxmt = None;
            return;
        }

        let lsas: Vec<ospf_packet::Ospfv3Lsa> = nbr.ls_rxmt.values().cloned().collect();
        tracing::info!(
            "[v3 Retransmit] Sending {} LSAs to {}",
            lsas.len(),
            router_id
        );
        let dest = nbr.ident.prefix.addr();
        let ls_upd = Ospfv3LsUpdate { lsas };
        let packet = Ospfv3Packet::new(
            &self.router_id,
            &area_id,
            0,
            Ospfv3Payload::LsUpdate(ls_upd),
        );
        let item = super::network_v6::Ospfv3Send {
            packet,
            ifindex,
            dest: Some(dest),
            src,
        };
        if let Err(e) = tx.send(item) {
            tracing::warn!("[v3 Retransmit] channel send failed: {}", e);
        }

        nbr.timer.ls_rxmt = Some(super::flood::ospf_retransmit_timer(
            nbr,
            retransmit_interval,
        ));
    }

    /// v3 sibling of v2's `process_dd_retransmit` (RFC 2328 §10.8,
    /// inherited by RFC 5340 §4.2.2): the master resends the DBD in
    /// `nbr.dd.sent` while still in ExStart / Exchange. Without this
    /// a single lost or crossed negotiation DBD wedges both ends in
    /// ExStart forever — the NFSM only sends one DBD per state entry,
    /// and the slave only echoes on duplicate receipt, so nobody ever
    /// transmits again (the `Message::DdRetransmit` the timer fires
    /// used to fall through v3's unhandled-variant arm).
    fn process_dd_retransmit(&mut self, ifindex: u32, router_id: Ipv4Addr) {
        let Some((oi, nbr)) = self.ospf_interface(ifindex, &router_id) else {
            return;
        };
        if (nbr.state != NfsmState::ExStart && nbr.state != NfsmState::Exchange)
            || !nbr.dd.flags.master()
        {
            nbr.timer.db_desc = None;
            return;
        }
        tracing::info!(
            "[v3 DBD:Retransmit] to {} seq={:#x}",
            router_id,
            nbr.dd.seqnum
        );
        super::packet_v3::ospfv3_db_desc_resend(&oi, nbr);
    }

    /// v3 sibling of v2's `process_ls_req_retransmit` (RFC 2328
    /// §10.9): resend the pending LS Request while the neighbor sits
    /// in Exchange / Loading. Same missing-arm story as
    /// `process_dd_retransmit` — a lost LS Request (or its LS Update
    /// reply) used to park the neighbor in Loading forever.
    fn process_ls_req_retransmit(&mut self, ifindex: u32, router_id: Ipv4Addr) {
        let Some((mut oi, nbr)) = self.ospf_interface(ifindex, &router_id) else {
            return;
        };
        if nbr.state < NfsmState::Exchange || nbr.state >= NfsmState::Full || nbr.ls_req.is_empty()
        {
            nbr.timer.ls_req = None;
            return;
        }
        let ident = *oi.ident;
        tracing::info!(
            "[v3 LSReq:Retransmit] to {} entries={}",
            router_id,
            nbr.ls_req.len()
        );
        super::packet_v3::ospfv3_ls_req_send(&mut oi, nbr, &ident);
    }

    /// Dispatch one v3 instance-level message.
    ///
    /// Subset of v2's `process_msg` covering the IFSM-driver scope:
    /// `Enable` / `Disable` (toggle the link's enabled flag and emit
    /// the IFSM transition event), `Ifsm` (drive the FSM), and
    /// `HelloTimer` (emit a v3 Hello via the v3 send channel).
    ///
    /// Other `Message<Ospfv3>` variants (Recv / Nfsm / Send / Flood /
    /// Lsdb / SpfSchedule / SpfCalc) need additional v3-side wiring
    /// — packet recv bridging, v3 NFSM dispatch, v3 LSA flooding —
    /// and land in subsequent PRs. They fall through to a debug log
    /// for now so traffic that arrives early doesn't panic.
    pub async fn process_msg(&mut self, msg: Message<Ospfv3>) {
        match msg {
            Message::Enable(ifindex, area_id) => {
                let Some(link) = self.links.get_mut(&ifindex) else {
                    return;
                };
                link.enabled = true;
                link.area = area_id;
                link.area_id = area_id;
                // Mirror the v2 Enable arm — sync runtime
                // network_type from config so IFSM / NFSM /
                // Router-LSA key off the operator's choice.
                link.network_type = link.config_network_type();
                let area = self.areas.fetch(area_id);
                area.links.insert(ifindex);
                let area_type = area.area_type;
                if let Some(link) = self.links.get_mut(&ifindex) {
                    link.area_type = area_type;
                }
                self.router_lsa_originate();
                self.router_intra_area_prefix_lsa_originate(area_id);
                self.link_lsa_originate(ifindex);
                let _ = self.tx.send(Message::Ifsm(ifindex, IfsmEvent::InterfaceUp));
                // ABR status may have flipped (gained interface
                // in a 2nd area) — resync NSSA translator state
                // across all NSSA areas; the helper gates on
                // `is_abr()` internally.
                self.nssa_translate_resync_all();
            }
            Message::Disable(ifindex, area_id) => {
                // Flush self-originated LSAs scoped to this link
                // *before* tearing down the link's area binding —
                // the flushes read through the link (interface_id)
                // and the area LSDB, so the lookups must happen
                // while both still resolve.
                self.network_intra_area_prefix_lsa_flush(ifindex, area_id);
                self.network_lsa_flush(ifindex, area_id);
                self.link_lsa_flush(ifindex);

                let Some(link) = self.links.get_mut(&ifindex) else {
                    return;
                };
                link.enabled = false;
                link.area = Ipv4Addr::UNSPECIFIED;
                link.area_id = Ipv4Addr::UNSPECIFIED;
                link.area_type = super::area::AreaType::default();
                let area = self.areas.fetch(area_id);
                area.links.remove(&ifindex);
                self.router_lsa_originate();
                self.router_intra_area_prefix_lsa_originate(area_id);
                let _ = self
                    .tx
                    .send(Message::Ifsm(ifindex, IfsmEvent::InterfaceDown));
                // Dropping a link may turn this router back into a
                // non-ABR; flush any translated Type-5s if we no
                // longer qualify.
                self.nssa_translate_resync_all();
            }
            Message::Ifsm(index, ev) => {
                // Same DR-leave hook as v2: premature-age the
                // self-originated Network-LSA when the IFSM yields
                // DR so the LSA doesn't outlive our DR role. v3
                // additionally flushes the Network-ref
                // Intra-Area-Prefix-LSA (RFC 5340 §A.4.10 — only
                // the DR originates it; on yield it would otherwise
                // dangle referencing the now-MaxAged Network-LSA's
                // (ls_id, adv_router) until natural MaxAge).
                let prev = self.links.get(&index).map(|l| (l.state, l.area_id));
                let Some(link) = self.links.get_mut(&index) else {
                    return;
                };
                ospf_ifsm(link, ev);
                if let Some((prev_state, area_id)) = prev {
                    let new_state = self.links.get(&index).map(|l| l.state);
                    if prev_state == IfsmState::DR && new_state != Some(IfsmState::DR) {
                        self.network_intra_area_prefix_lsa_flush(index, area_id);
                        self.network_lsa_flush(index, area_id);
                    }
                    // Re-originate the per-link SR-MPLS E-Router-LSA
                    // on any IFSM state change. Broadcast / NBMA
                    // links carry the DR's interface_id in the
                    // Router-Link TLV, so a DR election outcome must
                    // refresh the LSA; the originator's own gating
                    // makes the call a no-op when the preconditions
                    // don't hold (P2P sees no semantic change).
                    if let Some(new) = new_state
                        && new != prev_state
                    {
                        let ifname = self.links.get(&index).map(|l| l.name.clone());
                        ospf_fsm_trace!(
                            self.tracing,
                            Ifsm,
                            false,
                            ifindex = index,
                            interface = ifname.as_deref().unwrap_or("?"),
                            from = ?prev_state,
                            to = ?new,
                            "IFSM transition"
                        );
                        self.e_router_v3_lsa_originate(index);
                    }
                }
            }
            Message::HelloTimer(index) => {
                let now = chrono::Utc::now();
                let chains = &self.key_chains;
                let tracing = &self.tracing;
                let Some(link) = self.links.get_mut(&index) else {
                    return;
                };
                let Some(tx) = self.v3_send_tx.as_ref() else {
                    return;
                };
                super::packet_v3::ospfv3_hello_send(link, tx, chains, now, tracing);
            }
            Message::Nfsm(index, src, ev) => {
                let old_state = self
                    .links
                    .get(&index)
                    .and_then(|link| link.nbrs.get(&src))
                    .map(|nbr| nbr.state);

                if let Some((mut link, nbr)) = self.ospf_interface(index, &src) {
                    let ident = link.ident;
                    super::nfsm::ospf_nfsm(&mut link, nbr, ev, ident);
                }

                if matches!(ev, NfsmEvent::InactivityTimer) {
                    // InactivityTimer destroys the neighbor (dead-timer
                    // expiry, BFD-down, or `clear ospfv3 neighbor`);
                    // `ospf_nfsm` reset its lists but leaves the actual
                    // removal to us. Mirrors the v2 sibling.
                    self.nfsm_kill_neighbor(index, src, old_state);
                } else {
                    let new_state = self
                        .links
                        .get(&index)
                        .and_then(|link| link.nbrs.get(&src))
                        .map(|nbr| nbr.state);

                    if let (Some(old_state), Some(new_state)) = (old_state, new_state) {
                        if old_state != new_state {
                            ospf_fsm_trace!(
                                self.tracing,
                                Nfsm,
                                false,
                                neighbor = %src,
                                event = ?ev,
                                from = ?old_state,
                                to = ?new_state,
                                "NFSM transition"
                            );
                        }
                        self.process_neighbor_state_change(index, src, old_state, new_state);
                        // Re-evaluate the BFD session against the configured
                        // threshold (the reconcile reads the now-current
                        // neighbor state, so it covers both 2-Way and Full).
                        self.bfd_reconcile_nbr(index, src);
                    }
                }
            }
            Message::SpfSchedule(area_id) => {
                if let Some(area_id) = area_id {
                    if let Some(area) = self.areas.get_mut(area_id) {
                        Self::ospf_spf_schedule_generic(&self.tx, area);
                    }
                } else {
                    // None = AS-scope event (Type-5 AS-External install /
                    // MaxAge): recompute every attached area so each
                    // area's RIB re-runs `add_as_external_routes_v3` and
                    // installs or drops the external. Mirrors v2.
                    let area_ids: Vec<Ipv4Addr> = self.areas.iter().map(|(id, _)| *id).collect();
                    for id in area_ids {
                        if let Some(area) = self.areas.get_mut(id) {
                            Self::ospf_spf_schedule_generic(&self.tx, area);
                        }
                    }
                }
            }
            Message::SpfCalc(area_id) => {
                let Some(area) = self.areas.get_mut(area_id) else {
                    return;
                };
                if area.spf_inflight {
                    // A SPF is already running for this area. Remember
                    // that another trigger arrived; the completion
                    // path re-fires exactly one follow-up SpfCalc.
                    area.spf_pending = true;
                    return;
                }
                area.spf_timer = None;
                // Build the SPF input on the main task; if there is
                // no source Router-LSA yet there is nothing to do.
                let Some(input) = build_v3_spf_input(self, area_id) else {
                    return;
                };
                if let Some(area) = self.areas.get_mut(area_id) {
                    area.spf_inflight = true;
                }
                let tx = self.tx.clone();
                tokio::task::spawn_blocking(move || {
                    let output = compute_spf(input);
                    let _ = tx.send(Message::SpfDone(Box::new(output)));
                });
                tracing::info!("[v3 SPF] Calculation dispatched for area {}", area_id);
            }
            Message::SpfDone(output) => {
                let area_id = output.area_id;
                apply_v3_spf_result(self, *output);
                if let Some(area) = self.areas.get_mut(area_id) {
                    area.spf_inflight = false;
                    if std::mem::take(&mut area.spf_pending) {
                        let _ = self.tx.send(Message::SpfCalc(area_id));
                    }
                }
            }
            Message::Flood(area_id, lsa, source_ifindex, source_nbr_addr) => {
                // RFC 2328 §13.3: flood the LSA to every other
                // Exchange-or-later neighbor in the area, exempting
                // the (ifindex, router-id) pair we received it from.
                self.flood_lsa_through_area(area_id, &lsa, Some((source_ifindex, source_nbr_addr)));
            }
            Message::Retransmit(ifindex, router_id) => {
                self.process_retransmit(ifindex, router_id);
            }
            Message::Srv6EndxReconcile(ifindex) => {
                // A Link-LSA landed on this interface — the neighbor's
                // global /128 may have just become available. Sweep
                // the link's Full neighbors so any installed End.X
                // drifts its nexthop to the global.
                let rids: Vec<Ipv4Addr> = self
                    .links
                    .get(&ifindex)
                    .map(|l| {
                        l.nbrs
                            .values()
                            .filter(|n| n.state == NfsmState::Full)
                            .map(|n| n.ident.router_id)
                            .collect()
                    })
                    .unwrap_or_default();
                for rid in rids {
                    self.reconcile_endx_sid(ifindex, rid);
                }
            }
            Message::DdRetransmit(ifindex, router_id) => {
                self.process_dd_retransmit(ifindex, router_id);
            }
            Message::LsReqRetransmit(ifindex, router_id) => {
                self.process_ls_req_retransmit(ifindex, router_id);
            }
            Message::Lsdb(ev, area_id, key) => {
                ospf_event_trace!(
                    self.tracing,
                    Lsdb,
                    event = ?ev,
                    area = ?area_id,
                    "LSDB event"
                );
                // RFC 2328 §13.4: a peer flooded our own LSA back to
                // us at a higher sequence number (typical post-restart
                // scenario). Re-originate at an even higher seq so
                // we own the LSA again. Currently handles the wired
                // self-origination paths (Router-LSA, Network-LSA,
                // Intra-Area-Prefix-LSA, NSSA-LSA default, translated
                // AS-External); other LSA types fall through.
                use ospf_packet::{
                    OSPFV3_AS_EXTERNAL_LSA_TYPE, OSPFV3_E_INTRA_AREA_PREFIX_LSA_TYPE,
                    OSPFV3_E_ROUTER_LSA_TYPE, OSPFV3_INTRA_AREA_PREFIX_LSA_TYPE,
                    OSPFV3_LINK_LSA_TYPE, OSPFV3_NETWORK_LSA_TYPE, OSPFV3_NSSA_LSA_TYPE,
                    OSPFV3_ROUTER_LSA_TYPE,
                };

                use super::srmpls::SR_INFO_LSID;
                if ev == super::lsdb::LsdbEvent::SelfOriginatedReceived {
                    let (ls_type, ls_id, _) = key;
                    let area = area_id.unwrap_or(AREA0);
                    match ls_type {
                        t if t == OSPFV3_ROUTER_LSA_TYPE => self.router_lsa_originate(),
                        t if t == OSPFV3_NETWORK_LSA_TYPE => self.network_lsa_originate(ls_id),
                        // Link-LSA (RFC 5340 §A.4.9): link-scoped,
                        // keyed by ifindex. Originator lives at
                        // `link_lsa_originate(ifindex)` — `interface_id
                        // = link.index` so passing `ls_id` directly
                        // is correct.
                        t if t == OSPFV3_LINK_LSA_TYPE => self.link_lsa_originate(ls_id),
                        // Intra-Area-Prefix-LSA (RFC 5340 §A.4.10)
                        // has two distinct origin paths:
                        //   * Router-referenced (ls_id == 0): one
                        //     per area, drives `router_intra_area_
                        //     prefix_lsa_originate`.
                        //   * Network-referenced (ls_id == DR
                        //     interface_id): one per broadcast
                        //     segment we're DR for, drives
                        //     `network_intra_area_prefix_lsa_
                        //     originate(ifindex)`.
                        // The originate paths key on those exact
                        // ls_id values, so the dispatch matches.
                        t if t == OSPFV3_INTRA_AREA_PREFIX_LSA_TYPE && ls_id == 0 => {
                            self.router_intra_area_prefix_lsa_originate(area)
                        }
                        t if t == OSPFV3_INTRA_AREA_PREFIX_LSA_TYPE => {
                            self.network_intra_area_prefix_lsa_originate(ls_id)
                        }
                        // E-Router-LSA (RFC 8362 §3.1) — two callers:
                        //   * SR-Info (ls_id == SR_INFO_LSID == 0):
                        //     per-area aggregate via
                        //     `e_router_v3_sr_info_lsa_originate`.
                        //   * Per-link Adj-SID (ls_id == ifindex):
                        //     `e_router_v3_lsa_originate(ifindex)`.
                        t if t == OSPFV3_E_ROUTER_LSA_TYPE && ls_id == SR_INFO_LSID => {
                            self.e_router_v3_sr_info_lsa_originate(area)
                        }
                        // SRv6 Locator LSA (RFC 9513) — single
                        // instance, ls_id == SRV6_LOCATOR_LSID.
                        t if t == ospf_packet::OSPFV3_SRV6_LOCATOR_LSA_TYPE => {
                            self.srv6_locator_lsa_originate(area)
                        }
                        t if t == OSPFV3_E_ROUTER_LSA_TYPE => self.e_router_v3_lsa_originate(ls_id),
                        // E-Intra-Area-Prefix-LSA (RFC 8362 §3.7 /
                        // RFC 8666 §5) carries the per-link
                        // Prefix-SID; ls_id == ifindex.
                        t if t == OSPFV3_E_INTRA_AREA_PREFIX_LSA_TYPE => {
                            self.ext_intra_area_prefix_v3_lsa_originate(ls_id)
                        }
                        // Only the default NSSA-LSA (link_state_id
                        // == 0) is self-originated today. Other
                        // ls-ids will land here once redistribute
                        // is wired on v3; for now they're treated
                        // as no-owner and the generic flush path
                        // handles them.
                        t if t == OSPFV3_NSSA_LSA_TYPE && ls_id == 0 => {
                            self.nssa_default_lsa_originate(area)
                        }
                        // Translated Type-5 (RFC 3101 §3.2). If
                        // `ls_id` matches an entry in any NSSA
                        // area's `nssa_translated`, re-translate
                        // (the resync bumps seq#); otherwise it's
                        // a stray Type-5 we don't own — fall
                        // through to flush.
                        t if t == OSPFV3_AS_EXTERNAL_LSA_TYPE => {
                            let owning_area = self
                                .areas
                                .iter()
                                .find(|(_, a)| a.nssa_translated.contains(&Ipv4Addr::from(ls_id)))
                                .map(|(&id, _)| id);
                            if let Some(a) = owning_area {
                                self.nssa_translate_resync(a);
                            }
                        }
                        _ => {}
                    }
                }
            }
            Message::GrHelperExpire(ifindex, router_id) => {
                self.gr_helper_expire(ifindex, router_id);
            }
            Message::NssaTranslateResync(area_id) => {
                self.nssa_translate_resync(area_id);
            }
            other => {
                tracing::debug!(
                    "v3 process_msg: unhandled variant {:?}",
                    std::mem::discriminant(&other)
                );
            }
        }
    }

    /// v3 mirror of `Ospf<Ospfv2>::gr_helper_expire`. Same body —
    /// clear `gr_helper` and re-fire `InactivityTimer` so the
    /// shared NFSM kill path runs.
    fn gr_helper_expire(&mut self, ifindex: u32, router_id: Ipv4Addr) {
        let Some(link) = self.links.get_mut(&ifindex) else {
            return;
        };
        let Some(nbr) = link.nbrs.get_mut(&router_id) else {
            return;
        };
        if nbr.gr_helper.take().is_none() {
            return;
        }
        tracing::info!(
            "[GR Helper v3] grace-period expired for nbr {} on ifindex={}, killing neighbor",
            router_id,
            ifindex
        );
        let _ = self.tx.send(Message::Nfsm(
            ifindex,
            router_id,
            super::nfsm::NfsmEvent::InactivityTimer,
        ));
    }

    /// Originate this router's Link-LSA for `ifindex` into the
    /// per-link LSDB (RFC 5340 §A.4.9). Mirrors
    /// `router_lsa_originate`'s shape, with two differences forced
    /// by the link scope:
    ///
    /// - Lookup / install go into `OspfLink::lsdb` (not the area
    ///   LSDB), since RFC 5340 §4.5.2 forbids Link-LSAs from
    ///   leaving the segment.
    /// - Flooding uses `flood_link_scope_lsa(ifindex, lsa)`, which
    ///   walks only the neighbors on this one link.
    ///
    /// Returns silently if `build_link_lsa(ifindex)` declines (the
    /// interface is unknown or disabled).
    pub fn link_lsa_originate(&mut self, ifindex: u32) {
        use ospf_packet::OSPFV3_LINK_LSA_TYPE;

        let Some(mut lsa) = self.build_link_lsa(ifindex) else {
            return;
        };

        let key: super::lsdb::OspfLsaKey = (OSPFV3_LINK_LSA_TYPE, ifindex, self.router_id);

        // Pull the prior sequence number out of the link's LSDB.
        if let Some(link) = self.links.get(&ifindex)
            && let Some(prev_seq) = link
                .lsdb
                .lookup_by_raw_key(key)
                .map(|prev| prev.h.ls_seq_number)
        {
            lsa.h.ls_seq_number = seq_max(lsa.h.ls_seq_number, prev_seq.saturating_add(1));
        }
        lsa.update();

        let flood_lsa = lsa.clone();
        if let Some(link) = self.links.get_mut(&ifindex) {
            // Link-LSA lives in the per-link LSDB; no area_id is
            // associated with link-scope LSAs in the hold-timer
            // protocol, so pass `None`.
            link.lsdb.install_originated(lsa, &self.tx, None);
        }
        self.flood_link_scope_lsa(ifindex, &flood_lsa);
    }

    /// Flush every Link-LSA we originated on `ifindex` (RFC 2328
    /// §14.1: re-flood the LSA at `ls_age = OSPF_MAX_AGE` so peers
    /// remove it instead of waiting LSRefreshTime). Called from
    /// `Message::Disable` so that disabling OSPFv3 on an interface
    /// promptly tears down the Link-LSA peers learned about.
    ///
    /// `ls_age` is not part of the LSA checksum (RFC 2328 §A.4.1
    /// — Fletcher is computed with the age field skipped), so
    /// `flush_lsa_by_raw_key` only flips the age field and is good
    /// to flood as-is. The hold timer it installs keeps the
    /// MaxAge LSA around long enough for the retransmit-list cycle
    /// to drain.
    pub fn link_lsa_flush(&mut self, ifindex: u32) {
        use ospf_packet::OSPFV3_LINK_LSA_TYPE;

        let router_id = self.router_id;
        let tx = self.tx.clone();
        let Some(link) = self.links.get_mut(&ifindex) else {
            return;
        };
        let keys: Vec<super::lsdb::OspfLsaKey> = link
            .lsdb
            .iter_by_raw_type(OSPFV3_LINK_LSA_TYPE)
            .filter(|(_, lsa)| lsa.data.h.advertising_router == router_id)
            .map(|((id, adv), _)| (OSPFV3_LINK_LSA_TYPE, id, adv))
            .collect();
        let mut flushed: Vec<ospf_packet::Ospfv3Lsa> = Vec::new();
        for key in keys {
            if let Some(lsa) = link.lsdb.flush_lsa_by_raw_key(key, &tx, None) {
                flushed.push(lsa);
            }
        }
        for lsa in flushed {
            self.flood_link_scope_lsa(ifindex, &lsa);
        }
    }

    /// Flood a link-scope LSA to every Exchange-or-later neighbor
    /// on the originating link only. Counterpart to
    /// `flood_self_originated_lsa` which walks the whole area;
    /// RFC 5340 §4.5.2 bounds link-scope flooding to the segment.
    ///
    /// Per RFC 2328 §13.3 step 1(d), every LSA sent to a neighbor
    /// is added to that neighbor's retransmit list so the
    /// retransmit timer can resend it until acknowledged. Same
    /// shape as `flood_lsa_through_area`'s bookkeeping (#808).
    fn flood_link_scope_lsa(&mut self, ifindex: u32, lsa: &ospf_packet::Ospfv3Lsa) {
        use ospf_packet::{Ospfv3LsUpdate, Ospfv3Packet, Ospfv3Payload};

        let Some(tx) = self.v3_send_tx.as_ref().cloned() else {
            return;
        };
        let Some(link) = self.links.get_mut(&ifindex) else {
            return;
        };
        let area_id = link.area;
        let Some(src) = link.addr.iter().find_map(|a| {
            let addr = a.prefix.addr();
            addr.is_unicast_link_local().then_some(addr)
        }) else {
            return;
        };
        let retransmit_interval = link.retransmit_interval();

        for nbr in link.nbrs.values_mut() {
            if nbr.state < NfsmState::Exchange {
                continue;
            }

            // RFC 2328 §13.3 step 1(d): track the LSA on this
            // neighbor's retransmit list so the per-neighbor
            // retransmit timer can resend it until we get an ack.
            super::flood::ospf_ls_retransmit_add(nbr, lsa, retransmit_interval);

            let ls_upd = Ospfv3LsUpdate {
                lsas: vec![lsa.clone()],
            };
            let packet = Ospfv3Packet::new(
                &self.router_id,
                &area_id,
                0,
                Ospfv3Payload::LsUpdate(ls_upd),
            );
            let item = super::network_v6::Ospfv3Send {
                packet,
                ifindex,
                dest: Some(nbr.ident.prefix.addr()),
                src,
            };
            if let Err(e) = tx.send(item) {
                tracing::warn!("[v3 Link-LSA Flood] channel send failed: {}", e);
            }
        }
    }

    /// Originate (or flush) this router's Router-referenced
    /// Intra-Area-Prefix-LSA for `area_id` (RFC 5340 §A.4.10).
    /// Mirrors `router_lsa_originate`'s shape:
    ///
    /// - Build via `build_router_intra_area_prefix_lsa`. Returns
    ///   `None` when no advertisable prefixes exist in the area —
    ///   in that case, flush the previous LSA so receivers age it
    ///   out.
    /// - Look up the existing area-LSDB entry via
    ///   `lookup_by_raw_key` (#779). Key is
    ///   `(OSPFV3_INTRA_AREA_PREFIX_LSA_TYPE, link_state_id=0,
    ///   advertising_router=self.router_id)`.
    /// - Bump `ls_seq_number` past the prior entry, restamp via
    ///   `Ospfv3Lsa::update`, install through `install_originated`,
    ///   flood via `flood_self_originated_lsa`.
    ///
    /// Called from `Message::Enable` / `Message::Disable` arms in
    /// `process_msg` — the link's address set changes when an
    /// interface joins or leaves the area.
    pub fn router_intra_area_prefix_lsa_originate(&mut self, area_id: Ipv4Addr) {
        use ospf_packet::OSPFV3_INTRA_AREA_PREFIX_LSA_TYPE;

        let key: super::lsdb::OspfLsaKey = (OSPFV3_INTRA_AREA_PREFIX_LSA_TYPE, 0, self.router_id);

        // No prefixes to advertise — flush any existing copy.
        let Some(mut lsa) = self.build_router_intra_area_prefix_lsa(area_id) else {
            let flushed = if let Some(area) = self.areas.get_mut(area_id) {
                area.lsdb.flush_lsa_by_raw_key(key, &self.tx, Some(area_id))
            } else {
                None
            };
            if let Some(lsa) = flushed {
                self.flood_self_originated_lsa(area_id, &lsa);
            }
            return;
        };

        if let Some(area) = self.areas.get(area_id)
            && let Some(prev_seq) = area
                .lsdb
                .lookup_by_raw_key(key)
                .map(|prev| prev.h.ls_seq_number)
        {
            lsa.h.ls_seq_number = seq_max(lsa.h.ls_seq_number, prev_seq.saturating_add(1));
        }
        lsa.update();

        let flood_lsa = lsa.clone();
        if let Some(area) = self.areas.get_mut(area_id) {
            area.lsdb.install_originated(lsa, &self.tx, Some(area_id));
            Self::ospf_spf_schedule_generic(&self.tx, area);
        }
        self.flood_self_originated_lsa(area_id, &flood_lsa);
    }

    /// Originate (or flush) the OSPFv3 E-Intra-Area-Prefix-LSA
    /// (RFC 8362 §3.7) carrying a Prefix-SID (RFC 8666 §5) for
    /// `ifindex`. v3 analogue of `Ospf<Ospfv2>::ext_prefix_lsa_originate`.
    ///
    /// Originates when:
    ///   * SR-MPLS is enabled (`segment_routing == Mpls`).
    ///   * The link is enabled and has a `prefix_sid` configured.
    ///   * The link has at least one non-link-local IPv6 address
    ///     (origination targets the first such address as a /128
    ///     host prefix; mirrors the v2 path's first-non-loopback
    ///     choice).
    ///
    /// Flushes (MaxAge) otherwise. The `link_state_id` is the
    /// interface ifindex so the per-link LSA gets a stable key
    /// across re-originations -- same convention as the v2 opaque-id.
    pub fn ext_intra_area_prefix_v3_lsa_originate(&mut self, ifindex: u32) {
        use ipnet::Ipv6Net;
        use ospf_packet::OSPFV3_E_INTRA_AREA_PREFIX_LSA_TYPE;

        use super::srmpls::SegmentRoutingMode;

        let link_state_id = ifindex;
        let key: super::lsdb::OspfLsaKey = (
            OSPFV3_E_INTRA_AREA_PREFIX_LSA_TYPE,
            link_state_id,
            self.router_id,
        );

        let build_inputs = if self.segment_routing == SegmentRoutingMode::Mpls
            && let Some(link) = self.links.get(&ifindex)
            && link.enabled
            && (link.config.prefix_sid.is_some() || !link.config.flex_algo_prefix_sids.is_empty())
            && let Some(addr) = link.addr.iter().find(|a| {
                // The SID's host prefix must be a routable global —
                // skip fe80 (advertised via Link-LSAs) and ::1: the
                // kernel auto-assigns ::1/128 to `lo` ahead of any
                // configured loopback address, and a `find` keyed
                // only on !fe80 made every router advertise its
                // Prefix-SID for ::1/128. Receivers then stamped all
                // remote SIDs onto their own ::1/128 route (last
                // writer wins) instead of the advertised loopbacks.
                let a = a.prefix.addr();
                a.segments()[0] != 0xfe80 && !a.is_loopback() && !a.is_unspecified()
            }) {
            let host = Ipv6Net::new(addr.prefix.addr(), 128).unwrap_or(addr.prefix);
            // Loopback parity with v2 / FRR / Junos: stamp 0 instead
            // of the link's output_cost so a /128 on `lo` doesn't add
            // a phantom hop's worth of metric to every SR path.
            let metric = if link.link_flags.is_loopback() {
                0
            } else {
                link.output_cost as u16
            };
            Some((
                link.area,
                link.config.prefix_sid,
                link.config.flex_algo_prefix_sids.clone(),
                host,
                metric,
            ))
        } else {
            None
        };

        if let Some((area_id, prefix_sid, flex_algo_sids, host, metric)) = build_inputs {
            let mut lsa = super::srmpls::ext_intra_area_prefix_v3_lsa_build(
                self.router_id,
                host,
                prefix_sid.as_ref(),
                &flex_algo_sids,
                link_state_id,
                metric,
            );

            if let Some(area) = self.areas.get(area_id)
                && let Some(prev_seq) = area
                    .lsdb
                    .lookup_by_raw_key(key)
                    .map(|prev| prev.h.ls_seq_number)
            {
                lsa.h.ls_seq_number = seq_max(lsa.h.ls_seq_number, prev_seq.saturating_add(1));
            }
            lsa.update();

            let flood_lsa = lsa.clone();
            if let Some(area) = self.areas.get_mut(area_id) {
                area.lsdb.install_originated(lsa, &self.tx, Some(area_id));
            }
            self.flood_self_originated_lsa(area_id, &flood_lsa);
        } else {
            // Walk every area in case the link's area moved between
            // calls -- a stale LSA must be flushed wherever it lives.
            let area_ids: Vec<Ipv4Addr> = self.areas.iter().map(|(id, _)| *id).collect();
            for area_id in area_ids {
                let flushed = if let Some(area) = self.areas.get_mut(area_id) {
                    area.lsdb.flush_lsa_by_raw_key(key, &self.tx, Some(area_id))
                } else {
                    None
                };
                if let Some(lsa) = flushed {
                    self.flood_self_originated_lsa(area_id, &lsa);
                }
            }
        }
    }

    /// Originate (or flush) the OSPFv3 E-Router-LSA (RFC 8362 §3.1)
    /// carrying an Adj-SID (RFC 8666 §6) for `ifindex`. v3 analogue
    /// of `Ospf<Ospfv2>::ext_link_lsa_originate`.
    ///
    /// Originates when SR-MPLS is on, the link is enabled, has at
    /// least one Full neighbor, and either of:
    ///   * P2P link -- one `AdjSid` sub-TLV with the configured
    ///     `adjacency_sid` or, when none is configured, the SRLB
    ///     label dynamically allocated on the Full transition
    ///     (advertised as a local V|L Adj-SID, IS-IS parity).
    ///   * Broadcast / NBMA link with a known DR and at least one
    ///     entry in `lan_adj_sids` -- one `LanAdjSid` sub-TLV per
    ///     Full neighbor that has a label allocated (RFC 8666 §6.2).
    ///
    /// Flushes (MaxAge) otherwise. `link_state_id` is the ifindex
    /// so the per-link LSA gets a stable key across re-originations.
    pub fn e_router_v3_lsa_originate(&mut self, ifindex: u32) {
        use ospf_packet::{OSPFV3_E_ROUTER_LSA_TYPE, Ospfv3RouterLinkType};

        use super::link::OspfNetworkType;
        use super::srmpls::SegmentRoutingMode;

        let link_state_id = ifindex;
        let key: super::lsdb::OspfLsaKey =
            (OSPFV3_E_ROUTER_LSA_TYPE, link_state_id, self.router_id);

        // Build the (area, link_type, metric, my_iid, peer_iid,
        // peer_rid, subs) tuple if origination is warranted, else
        // fall through to the flush path.
        let srv6 = self.srv6_active();
        let build_inputs = if (self.segment_routing == SegmentRoutingMode::Mpls || srv6)
            && let Some(link) = self.links.get(&ifindex)
            && link.enabled
            && link.nbrs.values().any(|n| n.state == NfsmState::Full)
        {
            let metric = link.output_cost as u16;
            let my_iid = link.interface_id;
            // Per-link Flex-Algo affinity (RFC 9492 ASLA). Rides the
            // Router-Link TLV alongside any Adj-SID; a link with
            // affinity but no Adj-SID still originates the TLV (so the
            // admin-group is visible to flex-algo SPF), as long as the
            // adjacency itself is Full — mirrors v2's broadened
            // Ext-Link origination gate.
            let asla =
                super::flex_algo::build_link_asla_v3(&link.config.affinity, &self.affinity_map);
            match link.network_type {
                OspfNetworkType::PointToPoint => {
                    if let Some(nbr) = link.nbrs.values().find(|n| n.state == NfsmState::Full) {
                        let mut subs = Vec::new();
                        if self.segment_routing == SegmentRoutingMode::Mpls {
                            if let Some(adjacency_sid) = link.config.adjacency_sid {
                                subs.push(super::srmpls::build_v3_p2p_adj_sub(&adjacency_sid));
                            } else if let Some(label) =
                                self.lan_adj_sids.get(&(ifindex, nbr.ident.router_id))
                            {
                                // No configured Adj-SID: advertise the SRLB
                                // label allocated on the Full transition as
                                // a local (V|L) Adj-SID — IS-IS-parity
                                // dynamic allocation, no config needed.
                                subs.push(super::srmpls::build_v3_p2p_adj_sub(
                                    &super::link::AdjacencySid::Absolute(*label),
                                ));
                            }
                        }
                        // RFC 9513 §9.1: the SRv6 End.X SID for this
                        // adjacency, carved from the locator on the
                        // Full transition.
                        if let (true, Some(locator), Some(endx)) = (
                            srv6,
                            self.sr_locator.as_ref(),
                            self.endx_sids.get(&(ifindex, nbr.ident.router_id)),
                        ) {
                            subs.push(super::srv6::build_v3_endx_sub(locator, endx.addr));
                        }
                        if let Some(a) = asla.clone() {
                            subs.push(a);
                        }
                        if subs.is_empty() {
                            None
                        } else {
                            Some((
                                link.area,
                                Ospfv3RouterLinkType::PointToPoint,
                                metric,
                                my_iid,
                                nbr.interface_id,
                                nbr.ident.router_id,
                                subs,
                            ))
                        }
                    } else {
                        None
                    }
                }
                OspfNetworkType::Broadcast | OspfNetworkType::NBMA => {
                    let dr_router_id = link.ident.d_router;
                    if dr_router_id == Ipv4Addr::UNSPECIFIED {
                        // DR election not yet settled. Fall through
                        // to the flush path so we don't keep a stale
                        // LSA naming a `link_id` we can no longer
                        // resolve.
                        None
                    } else {
                        // The DR's interface_id is taken from its
                        // entry in `link.nbrs` (which carries the
                        // peer's Hello-advertised interface ID). When
                        // we are the DR the peer-id lookup misses;
                        // fall back to our own interface ID, mirroring
                        // the convention in `build_router_lsa`.
                        let dr_peer_iid = if dr_router_id == self.router_id {
                            my_iid
                        } else {
                            link.nbrs
                                .get(&dr_router_id)
                                .map(|n| n.interface_id)
                                .unwrap_or(my_iid)
                        };
                        // `lan_adj_sids` is keyed by `(ifindex, nbr_key)`
                        // where `nbr_key` is whatever the NFSM hook
                        // received as its `nbr_addr` argument. For v3
                        // that's the neighbor's router-id (same key
                        // used to index `link.nbrs`), not the v6
                        // interface address — RFC 5340 keys v3
                        // neighbor state machines by router-id.
                        let mut subs: Vec<_> = if self.segment_routing == SegmentRoutingMode::Mpls {
                            link.nbrs
                                .values()
                                .filter(|n| n.state == NfsmState::Full)
                                .filter_map(|nbr| {
                                    let label =
                                        *self.lan_adj_sids.get(&(ifindex, nbr.ident.router_id))?;
                                    Some(super::srmpls::build_v3_lan_adj_sub(
                                        nbr.ident.router_id,
                                        label,
                                    ))
                                })
                                .collect()
                        } else {
                            Vec::new()
                        };
                        // RFC 9513 §9.2: one LAN End.X SID per Full
                        // neighbor on the segment.
                        if srv6 && let Some(locator) = self.sr_locator.as_ref() {
                            subs.extend(
                                link.nbrs
                                    .values()
                                    .filter(|n| n.state == NfsmState::Full)
                                    .filter_map(|nbr| {
                                        let endx =
                                            self.endx_sids.get(&(ifindex, nbr.ident.router_id))?;
                                        Some(super::srv6::build_v3_lan_endx_sub(
                                            locator,
                                            nbr.ident.router_id,
                                            endx.addr,
                                        ))
                                    }),
                            );
                        }
                        if let Some(a) = asla.clone() {
                            subs.push(a);
                        }
                        if subs.is_empty() {
                            None
                        } else {
                            Some((
                                link.area,
                                Ospfv3RouterLinkType::Transit,
                                metric,
                                my_iid,
                                dr_peer_iid,
                                dr_router_id,
                                subs,
                            ))
                        }
                    }
                }
            }
        } else {
            None
        };

        if let Some((area_id, link_type, metric, my_iid, peer_iid, peer_rid, subs)) = build_inputs {
            let mut lsa = super::srmpls::e_router_v3_lsa_build(
                self.router_id,
                link_type,
                metric,
                my_iid,
                peer_iid,
                peer_rid,
                subs,
                link_state_id,
            );

            if let Some(area) = self.areas.get(area_id)
                && let Some(prev_seq) = area
                    .lsdb
                    .lookup_by_raw_key(key)
                    .map(|prev| prev.h.ls_seq_number)
            {
                lsa.h.ls_seq_number = seq_max(lsa.h.ls_seq_number, prev_seq.saturating_add(1));
            }
            lsa.update();

            let flood_lsa = lsa.clone();
            if let Some(area) = self.areas.get_mut(area_id) {
                area.lsdb.install_originated(lsa, &self.tx, Some(area_id));
            }
            self.flood_self_originated_lsa(area_id, &flood_lsa);
        } else {
            // Walk every area in case the link's area moved between
            // calls -- a stale LSA must be flushed wherever it lives.
            let area_ids: Vec<Ipv4Addr> = self.areas.iter().map(|(id, _)| *id).collect();
            for area_id in area_ids {
                let flushed = if let Some(area) = self.areas.get_mut(area_id) {
                    area.lsdb.flush_lsa_by_raw_key(key, &self.tx, Some(area_id))
                } else {
                    None
                };
                if let Some(lsa) = flushed {
                    self.flood_self_originated_lsa(area_id, &lsa);
                }
            }
        }
    }

    /// Originate (or flush) the per-area E-Router-LSA carrying the
    /// RFC 8666 §3 SR capability TLVs (SR-Algorithm, SID/Label Range
    /// = SRGB, SR Local Block = SRLB) for the given area.
    ///
    /// Uses `SR_INFO_LSID` (= 0) as the per-LSA key so it never
    /// collides with per-link E-Router-LSAs (which key by ifindex
    /// ≥ 1 on Linux). Originates when `segment_routing == Mpls`;
    /// flushes (MaxAge) otherwise. Re-origination on subsequent
    /// calls bumps the sequence number based on the LSDB's prior
    /// copy, matching the convention `e_router_v3_lsa_originate`
    /// already uses for per-link LSAs.
    pub fn e_router_v3_sr_info_lsa_originate(&mut self, area_id: Ipv4Addr) {
        use ospf_packet::OSPFV3_E_ROUTER_LSA_TYPE;

        use super::srmpls::{SR_INFO_LSID, SegmentRoutingMode};

        let key: super::lsdb::OspfLsaKey = (OSPFV3_E_ROUTER_LSA_TYPE, SR_INFO_LSID, self.router_id);

        let srv6 = self.srv6_active();
        if (self.segment_routing == SegmentRoutingMode::Mpls || srv6)
            && self.areas.get(area_id).is_some()
        {
            let algos = crate::flex_algo::sr_algorithms(&self.flex_algo);
            let fads = super::flex_algo::build_fad_v3(
                &self.flex_algo,
                &self.affinity_map,
                &self.srlg_groups,
            );
            let mut lsa =
                super::srmpls::e_router_v3_sr_info_lsa_build(self.router_id, algos, fads, srv6);

            if let Some(area) = self.areas.get(area_id)
                && let Some(prev_seq) = area
                    .lsdb
                    .lookup_by_raw_key(key)
                    .map(|prev| prev.h.ls_seq_number)
            {
                lsa.h.ls_seq_number = seq_max(lsa.h.ls_seq_number, prev_seq.saturating_add(1));
            }
            lsa.update();

            let flood_lsa = lsa.clone();
            if let Some(area) = self.areas.get_mut(area_id) {
                area.lsdb.install_originated(lsa, &self.tx, Some(area_id));
            }
            self.flood_self_originated_lsa(area_id, &flood_lsa);
        } else {
            let flushed = if let Some(area) = self.areas.get_mut(area_id) {
                area.lsdb.flush_lsa_by_raw_key(key, &self.tx, Some(area_id))
            } else {
                None
            };
            if let Some(lsa) = flushed {
                self.flood_self_originated_lsa(area_id, &lsa);
            }
        }
    }

    /// SRv6 is active once the watched locator resolved with a prefix
    /// — the gate for Locator-LSA origination and the SRv6
    /// Capabilities TLV.
    fn srv6_active(&self) -> bool {
        self.sr_locator.as_ref().is_some_and(|l| l.prefix.is_some())
    }

    /// Align the RIB locator watch with `srv6_locator_name` —
    /// the OSPFv3 sibling of `Isis::reconcile_locator_watch`.
    /// Unwatching drops the resolved snapshot, withdraws the End/uN
    /// SID, and flushes the Locator LSA; watching triggers an
    /// immediate snapshot reply from the RIB which re-originates.
    pub fn reconcile_locator_watch(&mut self) {
        let desired = self.srv6_locator_name.clone();
        if desired == self.watched_locator {
            return;
        }
        if let Some(prev) = self.watched_locator.take() {
            let _ = self.ctx.rib.send(rib::Message::SrLocatorUnwatch {
                proto: self.proto_label.clone(),
                name: prev,
            });
            self.sr_locator = None;
            self.update_srv6_end_sid();
            self.clear_all_endx_sids();
        }
        if let Some(next) = desired {
            let _ = self.ctx.rib.send(rib::Message::SrLocatorWatch {
                proto: self.proto_label.clone(),
                name: next.clone(),
            });
            self.watched_locator = Some(next);
        }
        self.srv6_originate_all_areas();
    }

    /// SR snapshot from the RIB (`SrSubscribe` channel). A locator
    /// update re-installs the End/uN SID against the new snapshot and
    /// re-originates the SRv6 LSAs in every area.
    pub fn process_sr_rx(&mut self, msg: crate::rib::RibSrRx) {
        match msg {
            crate::rib::RibSrRx::Locator { name, locator } => {
                if self.watched_locator.as_deref() != Some(name.as_str()) {
                    return;
                }
                self.sr_locator = locator;
                self.update_srv6_end_sid();
                // Locator snapshot churned: every End.X address
                // computed against the previous prefix is stale. Drop
                // them all, then sweep current Full neighbors so they
                // re-allocate from the fresh pool (the sweep also
                // covers adjacencies that reached Full before the
                // locator resolved).
                self.clear_all_endx_sids();
                self.sweep_endx_sids();
                self.srv6_originate_all_areas();
            }
            // OSPF's SRGB / SRLB are fixed constants today; no block
            // watches are registered, so nothing arrives here.
            crate::rib::RibSrRx::Block { .. } => {}
        }
    }

    /// Re-originate (or flush) the SRv6 Locator LSA and the SR-info
    /// E-Router-LSA (which carries the SRv6 Capabilities TLV) in
    /// every configured area.
    fn srv6_originate_all_areas(&mut self) {
        let area_ids: Vec<Ipv4Addr> = self.areas.iter().map(|(id, _)| *id).collect();
        for id in area_ids {
            self.srv6_locator_lsa_originate(id);
            self.e_router_v3_sr_info_lsa_originate(id);
        }
    }

    /// Install / withdraw the End (classic) or uN (uSID) SID derived
    /// from the resolved locator — the OSPFv3 sibling of
    /// `Isis::update_end_sid`. Always del-then-add: the address can
    /// survive a classic↔uSID flip while behavior/structure change,
    /// and the FIB needs the updated install.
    fn update_srv6_end_sid(&mut self) {
        use crate::rib::{
            LocatorBehavior, Sid, SidAllocationType, SidBehavior, SidContext, SidOwner,
        };
        if let Some(prev) = self.sr_end_sid.take() {
            let _ = self.ctx.rib.send(rib::Message::SidDel { addr: prev });
        }
        if let Some(locator) = self.sr_locator.as_ref()
            && let Some(addr) = locator.node_sid_addr()
            && let Some(loc_name) = self.watched_locator.clone()
        {
            let (behavior, structure) = match locator.behavior {
                Some(LocatorBehavior::Usid) => (SidBehavior::UN, locator.sid_structure()),
                None => (SidBehavior::End, None),
            };
            let sid = Sid {
                addr,
                behavior,
                context: SidContext::None,
                owner: SidOwner::new("ospfv3", 0),
                locator: loc_name,
                allocation_type: SidAllocationType::Dynamic,
                // End / uN is local-processing; ifindex=0 lets the RIB
                // resolve to the sr0 dummy. nh6 has no meaning here.
                ifindex: 0,
                nh6: None,
                structure,
                table_id: 0,
                segs: Vec::new(),
            };
            let _ = self.ctx.rib.send(rib::Message::SidAdd { sid });
            self.sr_end_sid = Some(addr);
        }
    }

    /// Originate (locator resolved) or flush (not) the SRv6 Locator
    /// LSA in `area_id` — the same keyed install/flush shape as
    /// `e_router_v3_sr_info_lsa_originate`.
    pub fn srv6_locator_lsa_originate(&mut self, area_id: Ipv4Addr) {
        use ospf_packet::OSPFV3_SRV6_LOCATOR_LSA_TYPE;

        let key: super::lsdb::OspfLsaKey = (
            OSPFV3_SRV6_LOCATOR_LSA_TYPE,
            super::srv6::SRV6_LOCATOR_LSID,
            self.router_id,
        );

        let built = self
            .sr_locator
            .as_ref()
            .filter(|_| self.areas.get(area_id).is_some())
            .and_then(|loc| super::srv6::srv6_locator_lsa_build(self.router_id, loc));
        if let Some(mut lsa) = built {
            if let Some(area) = self.areas.get(area_id)
                && let Some(prev_seq) = area
                    .lsdb
                    .lookup_by_raw_key(key)
                    .map(|prev| prev.h.ls_seq_number)
            {
                lsa.h.ls_seq_number = seq_max(lsa.h.ls_seq_number, prev_seq.saturating_add(1));
            }
            lsa.update();

            let flood_lsa = lsa.clone();
            if let Some(area) = self.areas.get_mut(area_id) {
                area.lsdb.install_originated(lsa, &self.tx, Some(area_id));
            }
            self.flood_self_originated_lsa(area_id, &flood_lsa);
        } else {
            let flushed = if let Some(area) = self.areas.get_mut(area_id) {
                area.lsdb.flush_lsa_by_raw_key(key, &self.tx, Some(area_id))
            } else {
                None
            };
            if let Some(lsa) = flushed {
                self.flood_self_originated_lsa(area_id, &lsa);
            }
        }
    }

    /// The neighbor's global IPv6 address on `ifindex`, learned from
    /// the LA-bit /128 prefixes in its Link-LSA. Falls back to `None`
    /// when the Link-LSA hasn't arrived (or carries no global) — the
    /// caller then uses the hello-source link-local, and the
    /// Link-LSA-arrival reconcile upgrades the install later.
    ///
    /// The preference is the same Linux kernel constraint as IS-IS
    /// (PR #1361): seg6local End.X resolves nh6 with iif = the
    /// packet's ingress interface, so a link-local nexthop matches
    /// fe80::/64 on the wrong link and blackholes.
    fn neighbor_global_nh6(&self, ifindex: u32, nbr_router_id: Ipv4Addr) -> Option<Ipv6Addr> {
        use ospf_packet::{OSPFV3_LINK_LSA_TYPE, Ospfv3LsBody};
        let link = self.links.get(&ifindex)?;
        let nbr = link.nbrs.get(&nbr_router_id)?;
        let key: super::lsdb::OspfLsaKey = (OSPFV3_LINK_LSA_TYPE, nbr.interface_id, nbr_router_id);
        let lsa = link.lsdb.lookup_by_raw_key(key)?;
        let Ospfv3LsBody::Link(body) = &lsa.body else {
            return None;
        };
        body.prefixes.iter().find_map(|p| {
            if !p.prefix_options.la() || p.prefix_length != 128 || p.address_prefix.len() < 16 {
                return None;
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&p.address_prefix[..16]);
            let addr = Ipv6Addr::from(octets);
            (addr.segments()[0] != 0xfe80).then_some(addr)
        })
    }

    /// Reconcile the End.X SID for one neighbor — the OSPFv3 port of
    /// `isis::Neighbor::reconcile_endx_sid`. Eligible while SRv6 is
    /// active and the neighbor is Full:
    ///
    /// - no SID yet → allocate an ELIB function, install the
    ///   advertised SID (global nh6 preferred, hello link-local as
    ///   fallback) plus the LIB twin for uSID locators, and
    ///   re-originate the per-link E-Router-LSA;
    /// - SID held but the preferred nexthop drifted (the neighbor's
    ///   Link-LSA with its global /128 typically lands after Full) →
    ///   delete-then-add both kernel entries with the new nexthop;
    /// - not eligible → release.
    pub fn reconcile_endx_sid(&mut self, ifindex: u32, nbr_router_id: Ipv4Addr) {
        let eligible = self.srv6_active()
            && self
                .links
                .get(&ifindex)
                .and_then(|l| l.nbrs.get(&nbr_router_id))
                .is_some_and(|n| n.state == NfsmState::Full);
        if !eligible {
            if self.release_endx_sid(ifindex, nbr_router_id) {
                self.e_router_v3_lsa_originate(ifindex);
            }
            return;
        }

        let Some(locator) = self.sr_locator.clone() else {
            return;
        };
        let Some(prefix) = locator.prefix else {
            return;
        };

        // Preferred nexthop: the neighbor's global from its Link-LSA,
        // else its hello-source link-local.
        let nh6 = self
            .neighbor_global_nh6(ifindex, nbr_router_id)
            .or_else(|| {
                self.links
                    .get(&ifindex)
                    .and_then(|l| l.nbrs.get(&nbr_router_id))
                    .map(|n| n.ident.prefix.addr())
            });

        if let Some(state) = self.endx_sids.get(&(ifindex, nbr_router_id)).cloned() {
            if state.nh6 == nh6 {
                return;
            }
            // Nexthop drifted: reinstall both kernel entries. The
            // advertised SID is unchanged, so no LSA re-origination.
            let _ = self.ctx.rib.send(rib::Message::SidDel { addr: state.addr });
            if let Some(lib) = state.lib_addr {
                let _ = self.ctx.rib.send(rib::Message::SidDel { addr: lib });
            }
            let lib_addr = self.install_endx_kernel(ifindex, &locator, state.addr, nh6);
            self.endx_sids.insert(
                (ifindex, nbr_router_id),
                super::srv6::EndxSidState {
                    function: state.function,
                    addr: state.addr,
                    lib_addr,
                    nh6,
                },
            );
            return;
        }

        let Some(function) = self.elib.allocate() else {
            return;
        };
        let Some(addr) = crate::isis::srv6::function_addr(prefix, function) else {
            self.elib.release(function);
            return;
        };
        let lib_addr = self.install_endx_kernel(ifindex, &locator, addr, nh6);
        self.endx_sids.insert(
            (ifindex, nbr_router_id),
            super::srv6::EndxSidState {
                function,
                addr,
                lib_addr,
                nh6,
            },
        );
        self.e_router_v3_lsa_originate(ifindex);
    }

    /// Send the SidAdd pair for an End.X: the advertised /128 (classic
    /// End.X or uA) and, for uSID locators, the LIB twin at
    /// block:function with the NEXT-CSID flavor (PR #1364 semantics).
    /// Returns the LIB twin address when one was installed.
    fn install_endx_kernel(
        &self,
        ifindex: u32,
        locator: &crate::rib::Locator,
        addr: Ipv6Addr,
        nh6: Option<Ipv6Addr>,
    ) -> Option<Ipv6Addr> {
        use crate::rib::{
            LocatorBehavior, Sid, SidAllocationType, SidBehavior, SidContext, SidOwner,
        };
        let ifname = self
            .links
            .get(&ifindex)
            .map(|l| l.name.clone())
            .unwrap_or_default();
        let loc_name = self.watched_locator.clone().unwrap_or_default();
        let (behavior, structure) = match locator.behavior {
            Some(LocatorBehavior::Usid) => (SidBehavior::UA, locator.sid_structure()),
            None => (SidBehavior::EndX, None),
        };
        let sid = Sid {
            addr,
            behavior,
            context: SidContext::Interface(ifname.clone()),
            owner: SidOwner::new("ospfv3", 0),
            locator: loc_name.clone(),
            allocation_type: SidAllocationType::Dynamic,
            ifindex,
            nh6,
            structure,
            table_id: 0,
            segs: Vec::new(),
        };
        let _ = self.ctx.rib.send(rib::Message::SidAdd { sid });

        if !matches!(locator.behavior, Some(LocatorBehavior::Usid)) {
            return None;
        }
        let prefix = locator.prefix?;
        let structure = locator.sid_structure()?;
        // Extract the 16-bit function back out of the full SID — the
        // bits right after the locator prefix.
        let fun = ((u128::from(addr) >> (128 - prefix.prefix_len() as u32 - 16)) & 0xffff) as u16;
        let lib = crate::isis::srv6::lib_addr(prefix, structure.lb_bits, fun)?;
        let sid = Sid {
            addr: lib,
            behavior: SidBehavior::UALib,
            context: SidContext::Interface(ifname),
            owner: SidOwner::new("ospfv3", 0),
            locator: loc_name,
            allocation_type: SidAllocationType::Dynamic,
            ifindex,
            nh6,
            structure: Some(structure),
            table_id: 0,
            segs: Vec::new(),
        };
        let _ = self.ctx.rib.send(rib::Message::SidAdd { sid });
        Some(lib)
    }

    /// Release one neighbor's End.X SID (kernel entries + ELIB
    /// function). Returns true when something was held.
    fn release_endx_sid(&mut self, ifindex: u32, nbr_router_id: Ipv4Addr) -> bool {
        let Some(state) = self.endx_sids.remove(&(ifindex, nbr_router_id)) else {
            return false;
        };
        self.elib.release(state.function);
        let _ = self.ctx.rib.send(rib::Message::SidDel { addr: state.addr });
        if let Some(lib) = state.lib_addr {
            let _ = self.ctx.rib.send(rib::Message::SidDel { addr: lib });
        }
        true
    }

    /// Withdraw every End.X SID and reset the ELIB pool — locator
    /// changed or SRv6 unconfigured; every issued address is invalid.
    /// The follow-up sweep re-allocates for current Full neighbors.
    fn clear_all_endx_sids(&mut self) {
        let keys: Vec<(u32, Ipv4Addr)> = self.endx_sids.keys().cloned().collect();
        for (ifindex, rid) in keys {
            self.release_endx_sid(ifindex, rid);
        }
        self.elib.reset();
    }

    /// Allocate End.X SIDs for every Full neighbor on every link —
    /// the catch-up sweep after a locator resolves (adjacencies may
    /// have reached Full before SRv6 was active). Enumerates ALL
    /// links unconditionally: filtering on config/state here is the
    /// PR #1358 disable-after-teardown trap.
    fn sweep_endx_sids(&mut self) {
        let pairs: Vec<(u32, Ipv4Addr)> = self
            .links
            .iter()
            .flat_map(|(ifindex, link)| {
                link.nbrs
                    .values()
                    .filter(|n| n.state == NfsmState::Full)
                    .map(|n| (*ifindex, n.ident.router_id))
                    .collect::<Vec<_>>()
            })
            .collect();
        for (ifindex, rid) in pairs {
            self.reconcile_endx_sid(ifindex, rid);
        }
    }

    /// Destroy a neighbor whose inactivity timer fired — dead-timer
    /// expiry, BFD-down (RFC 5882 §5), or an operator `clear ospfv3
    /// neighbor`. v3 sibling of `Ospf<Ospfv2>::nfsm_kill_neighbor`:
    /// `ospf_nfsm` has already reset the neighbor's lists; here we
    /// finish the teardown — skip GR-helper neighbors (their timer was
    /// re-armed), else remove the instance from `link.nbrs`, release
    /// any BFD subscription, run the Full-transition cleanup
    /// (Router-LSA / Network-LSA / SPF) and re-elect the DR if it had
    /// reached 2-Way. A later Hello re-creates the neighbor from
    /// `Down`.
    fn nfsm_kill_neighbor(&mut self, ifindex: u32, src: Ipv4Addr, old_state: Option<NfsmState>) {
        let Some(old_state) = old_state else {
            return;
        };
        // Snapshot the BFD key before removal; bail if GR-helper
        // suppression kept the neighbor (its timer was re-armed).
        let bfd_key = match self.links.get(&ifindex).and_then(|l| l.nbrs.get(&src)) {
            Some(nbr) if nbr.gr_helper.is_some() => return,
            Some(nbr) => nbr.bfd_session_key,
            None => return,
        };

        if let Some(link) = self.links.get_mut(&ifindex) {
            link.nbrs.remove(&src);
        }

        if let Some(key) = bfd_key
            && let Some(client_tx) = self.bfd_client_tx.as_ref()
        {
            let _ = client_tx.send(crate::bfd::inst::ClientReq::Unsubscribe {
                client: Ospfv3::PROTO.to_string(),
                key,
            });
        }

        self.process_neighbor_state_change(ifindex, src, old_state, NfsmState::Down);
        if old_state >= NfsmState::TwoWay {
            let _ = self
                .tx
                .send(Message::Ifsm(ifindex, IfsmEvent::NeighborChange));
        }
    }

    /// Detect Full state transitions on `nbr` and re-originate the
    /// LSAs that depend on the full-adjacency set. Mirrors v2's
    /// `process_neighbor_state_change`:
    ///
    /// - Router-LSA always re-originates when Full changes (since
    ///   transit-network link records list only Full-DR adjacencies).
    /// - Network-LSA (DR only) re-originates / flushes based on the
    ///   updated Full-neighbor set.
    fn process_neighbor_state_change(
        &mut self,
        ifindex: u32,
        nbr_addr: Ipv4Addr,
        old_state: NfsmState,
        new_state: NfsmState,
    ) {
        if old_state == new_state {
            return;
        }
        let full_state_changed = (old_state == NfsmState::Full && new_state != NfsmState::Full)
            || (old_state != NfsmState::Full && new_state == NfsmState::Full);
        if !full_state_changed {
            return;
        }

        let (if_state, area_id) = {
            let Some(link) = self.links.get_mut(&ifindex) else {
                return;
            };
            link.full_nbr_count = link
                .nbrs
                .values()
                .filter(|nbr| nbr.state == NfsmState::Full)
                .count();
            (link.state, link.area)
        };

        tracing::info!(
            "[v3 NFSM:FullTransition] ifindex={} nbr={} {} -> {}",
            ifindex,
            nbr_addr,
            old_state,
            new_state
        );

        // Adjacency-SID label allocation. Mirrors v2 (#850): each Full
        // adjacency claims one label out of the SRLB on transition
        // into Full and releases it on regression. Consumed by the
        // LAN-Adj-SID origination path (broadcast / NBMA links) and
        // by the dynamic P2P Adj-SID fallback (no `adjacency-sid`
        // configured). No-op when SR-MPLS is disabled (no pool
        // present).
        if new_state == NfsmState::Full
            && let Some(pool) = self.local_pool.as_mut()
            && let Some(label) = pool.allocate()
        {
            self.lan_adj_sids.insert((ifindex, nbr_addr), label as u32);
        } else if old_state == NfsmState::Full
            && let Some(label) = self.lan_adj_sids.remove(&(ifindex, nbr_addr))
            && let Some(pool) = self.local_pool.as_mut()
        {
            pool.release(label as usize);
        }

        self.router_lsa_originate();
        // Re-originate the Router-LSA-referenced Intra-Area-Prefix-LSA
        // so its transit-segment filter (RFC 5340 §A.4.10) re-evaluates
        // against the new Full-adjacency count: a segment that just
        // gained its first Full nbr drops out of the LSA (the DR's
        // Network-LSA-referenced LSA owns it now); a segment that just
        // lost its last Full nbr re-appears.
        self.router_intra_area_prefix_lsa_originate(area_id);

        if if_state == IfsmState::DR {
            self.network_lsa_originate(ifindex);
            // The Network-LSA-referenced companion LSA carries the
            // segment's prefixes — originate it alongside the
            // Network-LSA so peers learn the segment prefix exactly
            // once, via the DR.
            self.network_intra_area_prefix_lsa_originate(ifindex);
        } else {
            // We lost (or never had) DR. Flush any prior copy of the
            // Network-referenced Intra-Area-Prefix-LSA we owned.
            // `network_intra_area_prefix_lsa_originate`'s self-flush
            // branch handles the gate, but it needs the call.
            self.network_intra_area_prefix_lsa_originate(ifindex);
        }

        // SRv6 End.X follows the same Full lifecycle as the Adj-SID:
        // allocate + advertise on the transition into Full, release on
        // regression. Re-originate our Link-LSA too — it now carries
        // our global /128 (LA-bit) so the peer can upgrade its End.X
        // nexthop from our link-local to the global, and link-scope
        // floods at interface-up reached nobody.
        self.reconcile_endx_sid(ifindex, nbr_addr);
        self.link_lsa_originate(ifindex);

        // SR-MPLS E-Router-LSA tracks the per-link P2P Adj-SID, which
        // is only meaningful while the link has a Full neighbor.
        // `e_router_v3_lsa_originate` flushes when no Full neighbor
        // remains; the call is a no-op on non-P2P links.
        self.e_router_v3_lsa_originate(ifindex);
    }

    /// Originate (or flush) the v3 Network-LSA for the broadcast
    /// segment on `ifindex`. Mirrors v2's
    /// `update_network_lsa_by_interface` with the v3-specific
    /// differences:
    ///
    /// - LS-ID is the DR's **Interface ID** (RFC 5340 §A.4.4),
    ///   not the DR's interface IP as in v2.
    /// - LSA-type is `OSPFV3_NETWORK_LSA_TYPE` (0x2002) — the v3
    ///   ls_type doesn't compress to a v2 `OspfLsType`, so the
    ///   LSDB flush uses `flush_lsa_by_raw_key`.
    /// - The v3 body carries no netmask (prefixes move to
    ///   Intra-Area-Prefix-LSA in v3).
    ///
    /// Flushes the existing Network-LSA when this router is no
    /// longer DR or has no Full-adjacent neighbors on the segment;
    /// otherwise installs the fresh LSA and floods it to every
    /// Exchange-or-later neighbor in the area.
    pub fn network_lsa_originate(&mut self, ifindex: u32) {
        use ospf_packet::OSPFV3_NETWORK_LSA_TYPE;

        let Some(link) = self.links.get(&ifindex) else {
            return;
        };
        let area_id = link.area;
        let interface_id = link.interface_id;
        let is_dr = link.ident.d_router == self.router_id;
        let full_nbr_count = link
            .nbrs
            .values()
            .filter(|n| n.state == NfsmState::Full)
            .count();

        let key: super::lsdb::OspfLsaKey = (OSPFV3_NETWORK_LSA_TYPE, interface_id, self.router_id);

        // No Full neighbors (or no longer DR): flush the LSA so
        // receivers age it out of their LSDBs.
        if !is_dr || full_nbr_count == 0 {
            let flushed = if let Some(area) = self.areas.get_mut(area_id) {
                area.lsdb.flush_lsa_by_raw_key(key, &self.tx, Some(area_id))
            } else {
                None
            };
            if let Some(lsa) = flushed {
                self.flood_self_originated_lsa(area_id, &lsa);
            }
            return;
        }

        let Some(mut lsa) = self.build_network_lsa(ifindex) else {
            return;
        };

        if let Some(area) = self.areas.get(area_id)
            && let Some(prev_seq) = area
                .lsdb
                .lookup_by_raw_key(key)
                .map(|prev| prev.h.ls_seq_number)
        {
            lsa.h.ls_seq_number = seq_max(lsa.h.ls_seq_number, prev_seq.saturating_add(1));
        }
        lsa.update();

        let flood_lsa = lsa.clone();
        if let Some(area) = self.areas.get_mut(area_id) {
            area.lsdb.install_originated(lsa, &self.tx, Some(area_id));
            Self::ospf_spf_schedule_generic(&self.tx, area);
        }
        self.flood_self_originated_lsa(area_id, &flood_lsa);
    }

    /// Unconditionally flush the Network-LSA we originated for
    /// `ifindex` in `area_id` (RFC 2328 §14.1): if one exists in
    /// the area LSDB at our router-id, set its age to MaxAge and
    /// re-flood so peers remove it instead of waiting
    /// LSRefreshTime.
    ///
    /// Differs from `network_lsa_originate`'s flush branch by not
    /// gating on the live `is_dr` / `full_nbr_count` checks — those
    /// can still be "we are DR with Full neighbors" when this is
    /// invoked from `Message::Disable`, but the link is going away
    /// regardless and the LSA must be torn down.
    pub fn network_lsa_flush(&mut self, ifindex: u32, area_id: Ipv4Addr) {
        use ospf_packet::OSPFV3_NETWORK_LSA_TYPE;

        let Some(link) = self.links.get(&ifindex) else {
            return;
        };
        let interface_id = link.interface_id;
        let key: super::lsdb::OspfLsaKey = (OSPFV3_NETWORK_LSA_TYPE, interface_id, self.router_id);

        let flushed = if let Some(area) = self.areas.get_mut(area_id) {
            area.lsdb.flush_lsa_by_raw_key(key, &self.tx, Some(area_id))
        } else {
            None
        };
        if let Some(lsa) = flushed {
            self.flood_self_originated_lsa(area_id, &lsa);
        }
    }

    /// Build the v3 Network-LSA-referenced Intra-Area-Prefix-LSA for
    /// the broadcast segment on `ifindex` (RFC 5340 §A.4.10). Only
    /// the DR originates this LSA; it carries the non-link-local
    /// prefixes attached to the segment with `prefix.metric = 0`
    /// (the network-pseudo-node-to-prefix cost is zero in v3 —
    /// the router-to-pseudo-node cost is the interface
    /// `output_cost`).
    ///
    /// Returns `None` unless this router is the DR on a Broadcast
    /// link with at least one non-link-local prefix configured. The
    /// LSA's `link_state_id` is the same Interface ID as the
    /// Network-LSA we own for the segment — the two LSAs share an
    /// identifier so receivers can correlate them.
    pub fn build_network_intra_area_prefix_lsa(
        &self,
        ifindex: u32,
    ) -> Option<ospf_packet::Ospfv3Lsa> {
        use ospf_packet::{
            OSPFV3_INTRA_AREA_PREFIX_LSA_TYPE, OSPFV3_NETWORK_LSA_TYPE, Ospfv3IntraAreaPrefix,
            Ospfv3IntraAreaPrefixLsa, Ospfv3LsBody, Ospfv3Lsa, Ospfv3LsaHeader,
            Ospfv3PrefixOptions, ospfv3_prefix_wire_len,
        };

        let link = self.links.get(&ifindex)?;
        if !link.enabled {
            return None;
        }
        if !matches!(link.network_type, OspfNetworkType::Broadcast) {
            return None;
        }
        if link.ident.d_router != self.router_id {
            return None;
        }

        let mut prefixes: Vec<Ospfv3IntraAreaPrefix> = Vec::new();
        for a in link.addr.iter() {
            if a.prefix.addr().segments()[0] == 0xfe80 {
                continue;
            }
            let net = &a.prefix;
            let prefix_length = net.prefix_len();
            let wire_len = ospfv3_prefix_wire_len(prefix_length);
            let mut address_prefix = vec![0u8; wire_len];
            let bytes = net.addr().octets();
            let copy_len = prefix_length.div_ceil(8) as usize;
            address_prefix[..copy_len].copy_from_slice(&bytes[..copy_len]);
            prefixes.push(Ospfv3IntraAreaPrefix {
                prefix_length,
                prefix_options: Ospfv3PrefixOptions::default(),
                metric: 0,
                address_prefix,
            });
        }
        if prefixes.is_empty() {
            return None;
        }

        let body = Ospfv3IntraAreaPrefixLsa {
            referenced_ls_type: OSPFV3_NETWORK_LSA_TYPE,
            referenced_link_state_id: link.interface_id,
            referenced_advertising_router: self.router_id,
            prefixes,
        };
        let mut lsa = Ospfv3Lsa {
            h: Ospfv3LsaHeader {
                ls_age: 0,
                ls_type: OSPFV3_INTRA_AREA_PREFIX_LSA_TYPE,
                link_state_id: link.interface_id,
                advertising_router: self.router_id,
                ls_seq_number: 0x8000_0001,
                ls_checksum: 0,
                length: 0,
            },
            body: Ospfv3LsBody::IntraAreaPrefix(body),
            raw: None,
        };
        lsa.update();
        Some(lsa)
    }

    /// Originate (or flush) the v3 Network-LSA-referenced
    /// Intra-Area-Prefix-LSA for `ifindex`. Mirrors
    /// `network_lsa_originate`'s shape: self-contained, gates on
    /// "we are DR on a Broadcast segment with ≥1 Full adjacency".
    /// When the gate fails (we lost DR, dropped to zero Fulls, etc.)
    /// flushes any prior copy from the area LSDB so peers age it
    /// out, mirroring `network_lsa_originate`'s flush branch.
    pub fn network_intra_area_prefix_lsa_originate(&mut self, ifindex: u32) {
        use ospf_packet::OSPFV3_INTRA_AREA_PREFIX_LSA_TYPE;

        let Some(link) = self.links.get(&ifindex) else {
            return;
        };
        let area_id = link.area;
        let interface_id = link.interface_id;
        let is_dr = link.ident.d_router == self.router_id;
        let full_nbr_count = link
            .nbrs
            .values()
            .filter(|n| n.state == NfsmState::Full)
            .count();

        let key: super::lsdb::OspfLsaKey = (
            OSPFV3_INTRA_AREA_PREFIX_LSA_TYPE,
            interface_id,
            self.router_id,
        );

        if !is_dr || full_nbr_count == 0 {
            let flushed = if let Some(area) = self.areas.get_mut(area_id) {
                area.lsdb.flush_lsa_by_raw_key(key, &self.tx, Some(area_id))
            } else {
                None
            };
            if let Some(lsa) = flushed {
                self.flood_self_originated_lsa(area_id, &lsa);
            }
            return;
        }

        let Some(mut lsa) = self.build_network_intra_area_prefix_lsa(ifindex) else {
            return;
        };

        if let Some(area) = self.areas.get(area_id)
            && let Some(prev_seq) = area
                .lsdb
                .lookup_by_raw_key(key)
                .map(|prev| prev.h.ls_seq_number)
        {
            lsa.h.ls_seq_number = seq_max(lsa.h.ls_seq_number, prev_seq.saturating_add(1));
        }
        lsa.update();

        let flood_lsa = lsa.clone();
        if let Some(area) = self.areas.get_mut(area_id) {
            area.lsdb.install_originated(lsa, &self.tx, Some(area_id));
            Self::ospf_spf_schedule_generic(&self.tx, area);
        }
        self.flood_self_originated_lsa(area_id, &flood_lsa);
    }

    /// Unconditional MaxAge-flush of the Network-LSA-referenced
    /// Intra-Area-Prefix-LSA we originated on `ifindex` in `area_id`.
    /// Counterpart to `network_lsa_flush`; called from
    /// `Message::Disable` before clearing the link's area binding
    /// so peers age out the LSA without waiting LSRefreshTime.
    pub fn network_intra_area_prefix_lsa_flush(&mut self, ifindex: u32, area_id: Ipv4Addr) {
        use ospf_packet::OSPFV3_INTRA_AREA_PREFIX_LSA_TYPE;

        let Some(link) = self.links.get(&ifindex) else {
            return;
        };
        let interface_id = link.interface_id;
        let key: super::lsdb::OspfLsaKey = (
            OSPFV3_INTRA_AREA_PREFIX_LSA_TYPE,
            interface_id,
            self.router_id,
        );

        let flushed = if let Some(area) = self.areas.get_mut(area_id) {
            area.lsdb.flush_lsa_by_raw_key(key, &self.tx, Some(area_id))
        } else {
            None
        };
        if let Some(lsa) = flushed {
            self.flood_self_originated_lsa(area_id, &lsa);
        }
    }

    /// Dispatch one v3 packet received off the wire (`network_v6`).
    /// Bridges the `Ospfv3Recv` channel into the v3 instance by
    /// looking up the ingress link and routing by payload type.
    /// Only Hello is handled at the moment; the four other v3 packet
    /// types (DBD / LSReq / LSUpd / LSAck) fall through with a debug
    /// log until their recv handlers land.
    pub fn process_recv(&mut self, recv: super::network_v6::Ospfv3Recv) {
        let super::network_v6::Ospfv3Recv {
            packet,
            src,
            ifindex,
        } = recv;
        let our_router_id = self.router_id;
        let nbr_router_id = packet.router_id;

        // RFC 7166 Authentication Trailer verification — chain-
        // aware via `KeySource`, mirrors the v2 path in
        // `Ospf<Ospfv2>::process_recv`. The 64-bit replay seq is
        // stored alongside v2's 32-bit `auth_md5_last_seq` —
        // both fit in the same neighbor field by taking the
        // low 32 bits of the 64-bit seq (acceptable until the v3
        // counter actually exceeds 2^32, which is decades at any
        // realistic packet rate).
        {
            let chains = &self.key_chains;
            let now = chrono::Utc::now();
            let Some(link) = self.links.get(&ifindex) else {
                return;
            };
            if link.auth_mode() == super::link::OspfAuthMode::MessageDigest {
                let last_seq = link
                    .nbrs
                    .get(&nbr_router_id)
                    .map(|n| u64::from(n.auth_md5_last_seq))
                    .unwrap_or(0);
                let key_source = match link.config.key_chain.as_deref() {
                    Some(name) => match chains.get(name) {
                        Some(c) => crate::ospf::packet::KeySource::Chain { chain: c, now },
                        None => {
                            tracing::debug!(
                                "OSPFv3 auth drop on {} from {}: chain `{}` not configured",
                                link.name,
                                src,
                                name
                            );
                            return;
                        }
                    },
                    None => crate::ospf::packet::KeySource::PerIface(&link.config.crypto_keys),
                };
                let accepted = super::packet_v3::verify_v3_auth_trailer(
                    &packet,
                    &src,
                    link.auth_mode(),
                    &key_source,
                    last_seq,
                );
                let Some(new_seq) = accepted else {
                    tracing::debug!(
                        "OSPFv3 auth drop on {} from {} ({})",
                        link.name,
                        src,
                        nbr_router_id
                    );
                    return;
                };
                // Stash the accepted seq for replay protection on
                // subsequent packets from this neighbor. v3 has a
                // 64-bit seq on the wire but our `auth_md5_last_seq`
                // is u32; truncate.
                if let Some(link_mut) = self.links.get_mut(&ifindex)
                    && let Some(nbr_mut) = link_mut.nbrs.get_mut(&nbr_router_id)
                {
                    nbr_mut.auth_md5_last_seq = new_seq as u32;
                }
            }
        }

        match &packet.payload {
            Ospfv3Payload::Hello(_) => {
                let tracing = &self.tracing;
                let Some(link) = self.links.get_mut(&ifindex) else {
                    return;
                };
                super::packet_v3::ospfv3_hello_recv(&our_router_id, link, &packet, &src, tracing);
            }
            Ospfv3Payload::DbDesc(_) => {
                // v3 keys neighbors by router-id, which lives on the
                // packet header; pass it as the nbr-key to
                // `ospf_interface` to fetch the (link, nbr) pair.
                if let Some((mut oi, nbr)) = self.ospf_interface(ifindex, &nbr_router_id) {
                    super::packet_v3::ospfv3_db_desc_recv(&mut oi, nbr, &packet, &src);
                }
            }
            Ospfv3Payload::LsRequest(_) => {
                if let Some((mut oi, nbr)) = self.ospf_interface(ifindex, &nbr_router_id) {
                    super::packet_v3::ospfv3_ls_req_recv(&mut oi, nbr, &packet, &src);
                }
            }
            Ospfv3Payload::LsUpdate(_) => {
                if let Some((mut oi, nbr)) = self.ospf_interface(ifindex, &nbr_router_id) {
                    super::packet_v3::ospfv3_ls_upd_recv(&mut oi, nbr, &packet, &src);
                }
            }
            Ospfv3Payload::LsAck(_) => {
                if let Some((mut oi, nbr)) = self.ospf_interface(ifindex, &nbr_router_id) {
                    super::packet_v3::ospfv3_ls_ack_recv(&mut oi, nbr, &packet, &src);
                }
            }
            other => {
                tracing::debug!(
                    "v3 process_recv: unhandled packet payload {:?}",
                    std::mem::discriminant(other)
                );
            }
        }
    }

    /// Main event loop for the v3 instance. Mirrors v2's `event_loop`:
    /// pulls instance events from `rx`, RIB updates from `rib_rx`,
    /// config-manager requests from `cm.rx`, show requests from
    /// `show.rx`, and v3 packets from `v3_recv_rx`.
    ///
    /// `self.v3_recv_rx` is taken out of the `Option` at start so
    /// the `select!` arm doesn't have to re-borrow it through the
    /// `&mut self` used by `process_*`. `Ospf<Ospfv3>::new` always
    /// populates it (#768).
    pub async fn event_loop(&mut self) {
        let mut v3_recv_rx = self
            .v3_recv_rx
            .take()
            .expect("Ospf<Ospfv3> has no v3 recv channel");
        // Pre-roll: drain the RIB subscribe-time replay (LinkAdd,
        // AddrAdd, RouterIdUpdate, ...) before touching `cm.rx`.
        // Without this, a `set router ospfv3 area ... interface
        // <name> enable true` config message can race ahead of the
        // `LinkAdd` for that ifname; `ospf_link_get_mut_by_name`
        // then returns `None` and the enable silently no-ops.
        // Mirrors v2's pre-roll in `Ospf<Ospfv2>::event_loop`.
        loop {
            match self.rib_rx.recv().await {
                Some(RibRx::EoR) => break,
                Some(msg) => self.process_rib_msg(msg),
                None => break,
            }
        }
        loop {
            tokio::select! {
                Some(msg) = self.rx.recv() => {
                    self.process_msg(msg).await;
                }
                Some(msg) = self.rib_rx.recv() => {
                    self.process_rib_msg(msg);
                }
                Some(msg) = self.cm.rx.recv() => {
                    self.process_cm_msg(msg);
                }
                Some(msg) = self.show.rx.recv() => {
                    self.process_show_msg(msg).await;
                }
                Some(recv) = v3_recv_rx.recv() => {
                    self.process_recv(recv);
                }
                Some(msg) = self.sr_rx.recv() => {
                    self.process_sr_rx(msg);
                }
                Some(msg) = self.policy_rx.recv() => {
                    self.process_policy_msg(msg);
                }
                Some(event) = self.bfd_event_rx.recv() => {
                    self.process_bfd_event(event);
                }
            }
        }
    }

    /// Mirror of `Ospf<Ospfv2>::process_policy_msg` for the v3
    /// instance. Same shape — only key-chain updates are consumed
    /// today.
    fn process_policy_msg(&mut self, msg: crate::policy::PolicyRx) {
        match msg {
            crate::policy::PolicyRx::KeyChain {
                name, key_chain, ..
            } => {
                if let Some(kc) = key_chain {
                    self.key_chains.insert(name, kc);
                } else {
                    self.key_chains.remove(&name);
                }
            }
            crate::policy::PolicyRx::PrefixSet { .. }
            | crate::policy::PolicyRx::PolicyList { .. } => {}
        }
    }
}

pub fn serve(mut ospf: Ospf) -> Task<()> {
    Task::spawn(async move {
        ospf.event_loop().await;
    })
}

/// Spawn the v3 instance's main event loop. Symmetric with v2's
/// `serve`. Entered from `spawn_ospfv3` in `crate::config::ospf`
/// once the v3 config-schema dispatch hands off an `Ospf<Ospfv3>`.
pub fn serve_v3(mut ospf: Ospf<Ospfv3>) -> Task<()> {
    Task::spawn(async move {
        ospf.event_loop().await;
    })
}

/// Internal control / data messages threaded through the OSPF
/// instance's main mpsc channel.
///
/// Parameterized over `V: OspfVersion` (default `Ospfv2`) so the
/// variants carrying wire-shaped data (`Recv` / `Send` /
/// `Flood` / `FloodAs` / `DelayedAckQueue`) specialize on the
/// per-version packet, LSA, and address types. The remaining 13
/// variants don't carry version-specific data — they're agnostic
/// in shape even though they live on a `Message<V>` enum.
///
/// Default `V = Ospfv2` keeps every existing v2 callsite — both
/// pattern matches and `Message::Foo(...)` constructions —
/// resolving transparently to `Message<Ospfv2>`.
pub enum Message<V: OspfVersion = Ospfv2> {
    Enable(u32, Ipv4Addr),
    Disable(u32, Ipv4Addr),
    Ifsm(u32, IfsmEvent),
    Nfsm(u32, Ipv4Addr, NfsmEvent),
    HelloTimer(u32),
    /// Packet received off the wire. v2 carries
    /// `(Ospfv2Packet, src_addr, dst_group, ifindex, ifaddr)` where
    /// every address is `Ipv4Addr`; v3 will use `Ipv6Addr` for
    /// src/dst/ifaddr per its raw IPv6 socket layer.
    Recv(V::Packet, V::Addr, V::Addr, u32, V::Addr),
    /// Packet to send. v2 carries
    /// `(Ospfv2Packet, ifindex, Option<Ipv4Addr>)` — the optional
    /// destination is the multicast group or unicast nbr address.
    /// v3 uses `V::Addr = Ipv6Addr` accordingly.
    Send(V::Packet, u32, Option<V::Addr>),
    Lsdb(LsdbEvent, Option<Ipv4Addr>, OspfLsaKey),
    /// Flood LSA through area, excluding source neighbor.
    /// (area_id, lsa, source_ifindex, source_nbr_addr)
    Flood(Ipv4Addr, V::Lsa, u32, V::Addr),
    /// Flood AS-scoped LSA through all normal areas, excluding source neighbor.
    /// (lsa, source_ifindex, source_nbr_addr)
    FloodAs(V::Lsa, u32, V::Addr),
    /// A link-scope LSA (Link-LSA) was installed on this interface —
    /// re-evaluate SRv6 End.X nexthops, because the neighbor's global
    /// address (LA-bit /128 in its Link-LSA) may have just arrived
    /// and the kernel End.X entry must drift from the link-local to
    /// it (Linux resolves End.X nh6 by ingress iif — PR #1361).
    /// v3-only; the v2 handler ignores it.
    Srv6EndxReconcile(u32),
    /// Retransmit LSAs to a specific neighbor.
    /// (ifindex, nbr_addr)
    Retransmit(u32, Ipv4Addr),
    /// Retransmit pending Link State Request packet to a neighbor in
    /// Exchange or Loading. (ifindex, nbr_addr)
    LsReqRetransmit(u32, Ipv4Addr),
    /// Master retransmit of pending Database Description packet.
    /// (ifindex, nbr_addr)
    DdRetransmit(u32, Ipv4Addr),
    /// Send delayed LS Acks on an interface.
    /// (ifindex)
    DelayedAck(u32),
    /// Queue delayed ack headers on an interface.
    /// (ifindex, headers)
    DelayedAckQueue(u32, Vec<V::LsaHeader>),
    /// Request SPF scheduling for an area.
    SpfSchedule(Option<Ipv4Addr>),
    /// Timer-fired: perform SPF calculation for an area.
    SpfCalc(Ipv4Addr),
    /// Completion of an off-task SPF run dispatched by `SpfCalc`.
    /// Carries the owned, `Send` result that `apply_spf_result`
    /// folds back into `Ospf` on the main task. Currently only
    /// emitted by v2; v3 still runs SPF inline.
    SpfDone(Box<SpfOutput>),
    /// Graceful-restart helper-mode grace-period expiry for
    /// `(ifindex, nbr_router_id)`. RFC 3623 §3.2 bullet 1 — the
    /// restarter exceeded its grace window. Exit helper and let the
    /// normal `InactivityTimer` path tear the neighbor down.
    GrHelperExpire(u32, Ipv4Addr),
    /// Graceful-restart restarter-mode auto-abort. Fired when the
    /// staging timer set by `gr_restart_begin` expires without an
    /// operator-driven commit. Drives the same path as
    /// `clear ip ospf graceful-restart abort`.
    GrRestartAbort,
    /// Graceful-restart commit drain complete — fired by the
    /// short timer `gr_restart_commit` arms after writing the
    /// checkpoint, so the Grace LSAs have time to reach the wire
    /// before the process exits. Handler calls
    /// `std::process::exit(0)`; the supervisor restarts us.
    GrRestartExit,
    /// Fired from `process_neighbor_state_change` when the count
    /// of post-reboot Full transitions matches the expected count.
    /// Handler clears `restarting`, re-originates topology-affecting
    /// self LSAs at `seq+1`, and flushes our Grace LSAs so helpers
    /// exit cleanly.
    GrRestartExitSuccess,
    /// RFC 3101 NSSA Type-7→Type-5 translator resync request for
    /// `area_id`. Fired when a Type-7 LSA arrived in this NSSA, or
    /// when config (area-type / translator-role / ABR status)
    /// changed. The handler is idempotent; multiple coalescing
    /// triggers in flight is fine.
    NssaTranslateResync(Ipv4Addr),
}

use crate::spf::{self, Path};

#[derive(Default)]
pub struct LspMap {
    map: HashMap<Ipv4Addr, usize>,
    val: Vec<Ipv4Addr>,
}

impl LspMap {
    fn get(&mut self, router_id: Ipv4Addr) -> usize {
        if let Some(index) = self.map.get(&router_id) {
            *index
        } else {
            let index = self.val.len();
            self.map.insert(router_id, index);
            self.val.push(router_id);
            index
        }
    }

    pub fn resolve(&self, id: usize) -> Option<&Ipv4Addr> {
        self.val.get(id)
    }

    /// Read-only lookup. Returns None if `router_id` is not in the map.
    /// Use this when iterating LSAs that reference a router_id whose
    /// vertex may not have been allocated (e.g. ABR for an unreachable
    /// network).
    pub fn lookup(&self, router_id: Ipv4Addr) -> Option<usize> {
        self.map.get(&router_id).copied()
    }
}

/// Build SPF graph from OSPF LSDB (Router-LSAs and Network-LSAs).
///
/// Filters per RFC 2328 §16.1:
///  - step 1: MaxAge LSAs are excluded from the SPF tree
///  - step 2(b): the destination LSA must carry a back-link to us. For
///    Router→Router (P2P/Virtual) edges the peer's Router-LSA must list
///    our router-id as a P2P/Virtual link; for Router→Network (Transit)
///    edges the Network-LSA must list our router-id in its
///    attached_routers, and each attached router must itself have a
///    valid Router-LSA before its edge is emitted.
fn graph(top: &mut Ospf, area_id: Ipv4Addr) -> (spf::Graph, Option<usize>) {
    use crate::ospf::lsdb::OSPF_MAX_AGE;

    let mut graph = spf::Graph::new();
    let mut source_node = None;

    let Some(area) = top.areas.get(area_id) else {
        return (graph, source_node);
    };

    // Collect non-MaxAge Router-LSA data.
    let mut router_lsas = Vec::new();
    for ((_ls_id, adv_router), lsa) in area.lsdb.iter_by_type(OspfLsType::Router) {
        if lsa.data.h.ls_age >= OSPF_MAX_AGE {
            continue;
        }
        router_lsas.push((adv_router, lsa.originated, lsa.data.clone()));
    }

    // Side-table for the bidirectional back-link check on P2P / Virtual
    // edges. Keyed by adv_router; refs into the local router_lsas Vec.
    let mut router_lsa_by_id: HashMap<Ipv4Addr, &RouterLsa> = HashMap::new();
    for (adv_router, _, lsa_data) in &router_lsas {
        if let OspfLsp::Router(ref router_lsa) = lsa_data.lsp {
            router_lsa_by_id.insert(*adv_router, router_lsa);
        }
    }

    // Collect non-MaxAge Network-LSA attached routers for transit
    // network expansion.
    let mut network_lsas: HashMap<Ipv4Addr, Vec<Ipv4Addr>> = HashMap::new();
    for ((ls_id, _adv_router), lsa) in area.lsdb.iter_by_type(OspfLsType::Network) {
        if lsa.data.h.ls_age >= OSPF_MAX_AGE {
            continue;
        }
        if let OspfLsp::Network(ref net_lsa) = lsa.data.lsp {
            network_lsas.insert(ls_id, net_lsa.attached_routers.clone());
        }
    }

    // Map each neighbor router-id we hold a local adjacency to -> the
    // ifindex of the interface it sits on. Used to stamp `link_id`
    // onto the edges emitted from our own Router-LSA so TI-LFA's repair
    // first-hop resolves back to a concrete local egress interface
    // (mirrors IS-IS's `local_adj_to_ifindex`). Edges from other
    // routers' LSAs carry `link_id = 0`: SPF propagates the field
    // untouched, but only the first-hop slot of our own edges is
    // consumed at install time. Parallel adjacencies to the same peer
    // collapse to the last-inserted ifindex (one repair nexthop), the
    // same trade-off IS-IS accepts.
    let mut nbr_to_ifindex: HashMap<Ipv4Addr, u32> = HashMap::new();
    for (ifindex, link) in top.links.iter() {
        for (_, nbr) in link.nbrs.iter() {
            nbr_to_ifindex.insert(nbr.ident.router_id, *ifindex);
        }
    }

    // Pass 1: create every vertex and resolve the source. Vertices must
    // all exist before edges are wired so pass 2 can push each edge onto
    // both the originating vertex's `olinks` and the target's `ilinks`.
    for (adv_router, originated, _lsa_data) in &router_lsas {
        let node_id = top.lsp_map.get(*adv_router);
        if *originated {
            source_node = Some(node_id);
        }
        let vertex = spf::Vertex {
            id: node_id,
            name: adv_router.to_string(),
            sys_id: adv_router.to_string(),
            ..Default::default()
        };
        graph.insert(node_id, vertex);
    }

    // Pass 2: wire edges. Each edge is pushed onto the originating
    // vertex's `olinks` (forward SPF, unchanged from the previous
    // olinks-only build) and onto the target vertex's `ilinks`. The
    // ilinks are new: TI-LFA's Q-space is a reverse SPF that walks
    // incoming edges, which the old builder never populated.
    for (adv_router, originated, lsa_data) in &router_lsas {
        let node_id = top.lsp_map.get(*adv_router);
        let OspfLsp::Router(ref router_lsa) = lsa_data.lsp else {
            continue;
        };
        for link in &router_lsa.links {
            match link.link_type {
                OspfLinkType::P2p | OspfLinkType::VirtualLink => {
                    // Bidirectional check: peer's Router-LSA must exist
                    // (non-MaxAge) AND carry a P2P/Virtual link back to
                    // us. Otherwise the edge is one-way and SPF would
                    // compute a route to a destination that can't route
                    // back.
                    let Some(peer_lsa) = router_lsa_by_id.get(&link.link_id) else {
                        continue;
                    };
                    let has_backlink = peer_lsa.links.iter().any(|l| {
                        matches!(l.link_type, OspfLinkType::P2p | OspfLinkType::VirtualLink)
                            && l.link_id == *adv_router
                    });
                    if !has_backlink {
                        continue;
                    }
                    let to_id = top.lsp_map.get(link.link_id);
                    let link_id = if *originated {
                        nbr_to_ifindex.get(&link.link_id).copied().unwrap_or(0)
                    } else {
                        0
                    };
                    push_edge(
                        &mut graph,
                        node_id,
                        to_id,
                        link.tos_0_metric as u32,
                        link_id,
                    );
                }
                OspfLinkType::Transit => {
                    // Bidirectional check: the Network-LSA must list us
                    // in its attached_routers; otherwise our claim of
                    // membership doesn't match the DR's view and the
                    // back-edge is missing.
                    //
                    // link.link_id = DR's interface IP, which is the
                    // Network-LSA's ls_id.
                    let Some(attached) = network_lsas.get(&link.link_id) else {
                        continue;
                    };
                    if !attached.contains(adv_router) {
                        continue;
                    }
                    for attached_router in attached {
                        if *attached_router == *adv_router {
                            continue;
                        }
                        // Each peer router on the network must itself
                        // have a valid Router-LSA. Without one, the
                        // back-link from the pseudo-node to that
                        // router is missing.
                        if !router_lsa_by_id.contains_key(attached_router) {
                            continue;
                        }
                        let to_id = top.lsp_map.get(*attached_router);
                        let link_id = if *originated {
                            nbr_to_ifindex.get(attached_router).copied().unwrap_or(0)
                        } else {
                            0
                        };
                        push_edge(
                            &mut graph,
                            node_id,
                            to_id,
                            link.tos_0_metric as u32,
                            link_id,
                        );
                    }
                }
                OspfLinkType::Stub => {
                    // Stub (3): destination prefix, not an SPF edge.
                    // Consumed by build_rib_from_spf.
                }
            }
        }
    }

    (graph, source_node)
}

/// Push one directed SPF edge into `graph`: onto the originating
/// vertex's `olinks` (forward SPF) and the target vertex's `ilinks`
/// (reverse SPF for TI-LFA's Q-space). Both endpoints are expected to
/// already exist in `graph` (created in pass 1); a missing endpoint is
/// silently skipped, matching the previous olinks-only behavior.
fn push_edge(graph: &mut spf::Graph, from: usize, to: usize, cost: u32, link_id: u32) {
    let link = spf::Link {
        from,
        to,
        cost,
        link_id,
    };
    if let Some(v) = graph.get_mut(&from) {
        v.olinks.push(link.clone());
    }
    if let Some(v) = graph.get_mut(&to) {
        v.ilinks.push(link);
    }
}

/// Routers in `area` that participate in Flex-Algorithm `algo` — i.e.
/// list it in the SR-Algorithm TLV of their Router Information Opaque
/// LSA (RFC 9350 §5.2 / §6). Walks the area LSDB on demand (same shape
/// as `add_prefix_sids`); no separate ingested map is maintained.
fn flex_algo_participants(area: &OspfArea, algo: u8) -> BTreeSet<Ipv4Addr> {
    use crate::ospf::lsdb::OSPF_MAX_AGE;
    let mut set = BTreeSet::new();
    for (_, lsa) in area.lsdb.iter_by_type(OspfLsType::OpaqueAreaLocal) {
        if lsa.data.h.ls_age >= OSPF_MAX_AGE {
            continue;
        }
        let OspfLsp::OpaqueAreaRouterInfo(ref ri) = lsa.data.lsp else {
            continue;
        };
        let participates = ri.tlvs.iter().any(
            |tlv| matches!(tlv, RouterInfoTlv::Algo(a) if a.algos.contains(&Algo::FlexAlgo(algo))),
        );
        if participates {
            set.insert(lsa.data.h.adv_router);
        }
    }
    set
}

/// Per-link affinity (Extended Admin Group) advertised in this area's
/// Extended-Link Opaque LSAs via the flex-algo ASLA sub-TLV, keyed by
/// `(adv_router, link_id, link_data)` so a Router-LSA link can be
/// joined to its affinity during graph build. (In IS-IS the affinity
/// rides on the reach TLV inline; OSPF carries it in a separate LSA,
/// hence this join table.)
fn flex_algo_link_affinity(
    area: &OspfArea,
) -> BTreeMap<(Ipv4Addr, Ipv4Addr, Ipv4Addr), ExtAdminGroup> {
    use crate::ospf::lsdb::OSPF_MAX_AGE;
    let mut map = BTreeMap::new();
    for (_, lsa) in area.lsdb.iter_by_type(OspfLsType::OpaqueAreaLocal) {
        if lsa.data.h.ls_age >= OSPF_MAX_AGE {
            continue;
        }
        let OspfLsp::OpaqueAreaExtLink(ref el) = lsa.data.lsp else {
            continue;
        };
        let adv_router = lsa.data.h.adv_router;
        for tlv in &el.tlvs {
            for sub in &tlv.subs {
                if let ExtLinkSubTlv::Asla(asla) = sub
                    && asla.is_flex_algo()
                    && let Some(group) = asla.ext_admin_group()
                {
                    map.insert((adv_router, tlv.link_id, tlv.link_data), group.clone());
                }
            }
        }
    }
    map
}

/// Per-link minimum unidirectional delay (microseconds) advertised in
/// this area's Extended-Link Opaque LSAs via the flex-algo ASLA Min/Max
/// Link Delay sub-TLV (RFC 7471 §4.2), keyed the same way as
/// `flex_algo_link_affinity`. Used as the SPF edge cost when a
/// Flex-Algorithm selects metric-type 1 (min-unidir-link-delay, RFC
/// 9350 §6).
fn flex_algo_link_delay(area: &OspfArea) -> BTreeMap<(Ipv4Addr, Ipv4Addr, Ipv4Addr), u32> {
    use crate::ospf::lsdb::OSPF_MAX_AGE;
    let mut map = BTreeMap::new();
    for (_, lsa) in area.lsdb.iter_by_type(OspfLsType::OpaqueAreaLocal) {
        if lsa.data.h.ls_age >= OSPF_MAX_AGE {
            continue;
        }
        let OspfLsp::OpaqueAreaExtLink(ref el) = lsa.data.lsp else {
            continue;
        };
        let adv_router = lsa.data.h.adv_router;
        for tlv in &el.tlvs {
            for sub in &tlv.subs {
                if let ExtLinkSubTlv::Asla(asla) = sub
                    && asla.is_flex_algo()
                    && let Some(delay) = asla.min_unidir_delay()
                {
                    map.insert((adv_router, tlv.link_id, tlv.link_data), delay);
                }
            }
        }
    }
    map
}

/// Build the per-algo SPF graph for `area_id`. Mirrors `graph()` but
/// (a) includes only routers participating in `algo` (plus self), and
/// (b) admits each Router-LSA link only if it passes the FAD
/// constraints in `entry` (RFC 9350 §6), the link's affinity coming
/// from the Extended-Link ASLA join table.
///
/// Edge cost follows the FAD metric-type (RFC 9350 §5.1): metric-type 1
/// (min-unidir-link-delay) uses the per-link Min delay from the
/// Extended-Link ASLA, and a link with no delay advertised is pruned
/// (RFC 9350 §15 — a link missing the selected metric MUST NOT be used).
/// All other metric-types (IGP, and the not-yet-supported TE-default)
/// fall back to the IGP `tos_0_metric`.
///
/// Local FAD config (`entry`) drives the constraints and metric-type —
/// no multi-router FAD election yet (matches IS-IS). SRLG-exclude is not
/// enforced; deferred exactly as on the IS-IS side.
fn graph_flex_algo(
    top: &mut Ospf,
    area_id: Ipv4Addr,
    algo: u8,
    entry: &crate::flex_algo::FlexAlgoEntry,
) -> (spf::Graph, Option<usize>) {
    use crate::ospf::lsdb::OSPF_MAX_AGE;

    let mut graph = spf::Graph::new();
    let mut source_node = None;

    let Some(area) = top.areas.get(area_id) else {
        return (graph, source_node);
    };

    let participants = flex_algo_participants(area, algo);
    let link_affinity = flex_algo_link_affinity(area);

    // RFC 9350 §5.1 metric-type 1 routes on per-link delay instead of
    // the IGP cost. Build the delay join table only for that metric-type
    // — the IGP path never consults it.
    let use_delay = entry.metric_type == Some(crate::flex_algo::FadMetricType::MinUnidirLinkDelay);
    let link_delay = if use_delay {
        flex_algo_link_delay(area)
    } else {
        BTreeMap::new()
    };

    // Router-LSAs of participating routers (self always kept — it is
    // the SPF source).
    let mut router_lsas = Vec::new();
    for ((_ls_id, adv_router), lsa) in area.lsdb.iter_by_type(OspfLsType::Router) {
        if lsa.data.h.ls_age >= OSPF_MAX_AGE {
            continue;
        }
        if !lsa.originated && !participants.contains(&adv_router) {
            continue;
        }
        router_lsas.push((adv_router, lsa.originated, lsa.data.clone()));
    }

    let mut router_lsa_by_id: HashMap<Ipv4Addr, &RouterLsa> = HashMap::new();
    for (adv_router, _, lsa_data) in &router_lsas {
        if let OspfLsp::Router(ref router_lsa) = lsa_data.lsp {
            router_lsa_by_id.insert(*adv_router, router_lsa);
        }
    }

    let mut network_lsas: HashMap<Ipv4Addr, Vec<Ipv4Addr>> = HashMap::new();
    for ((ls_id, _adv_router), lsa) in area.lsdb.iter_by_type(OspfLsType::Network) {
        if lsa.data.h.ls_age >= OSPF_MAX_AGE {
            continue;
        }
        if let OspfLsp::Network(ref net_lsa) = lsa.data.lsp {
            network_lsas.insert(ls_id, net_lsa.attached_routers.clone());
        }
    }

    for (adv_router, originated, lsa_data) in &router_lsas {
        let node_id = top.lsp_map.get(*adv_router);
        if *originated {
            source_node = Some(node_id);
        }
        let mut vertex = spf::Vertex {
            id: node_id,
            name: adv_router.to_string(),
            sys_id: adv_router.to_string(),
            ..Default::default()
        };

        if let OspfLsp::Router(ref router_lsa) = lsa_data.lsp {
            for link in &router_lsa.links {
                // FAD admissibility for the owning router's link. A
                // link with no advertised ASLA resolves to `None` =
                // empty bitmap (rejected by include-any, passed by
                // exclude-only), per RFC 9350 §6.
                let affinity = link_affinity.get(&(*adv_router, link.link_id, link.link_data));
                if !crate::flex_algo::link_passes_fad(affinity, entry, &top.affinity_map) {
                    continue;
                }
                // Edge cost per the FAD metric-type. With a delay metric,
                // a link advertising no Min delay is pruned (RFC 9350
                // §15); otherwise the IGP cost is used.
                let cost = if use_delay {
                    match link_delay.get(&(*adv_router, link.link_id, link.link_data)) {
                        Some(&d) => d,
                        None => continue,
                    }
                } else {
                    link.tos_0_metric as u32
                };
                match link.link_type {
                    OspfLinkType::P2p | OspfLinkType::VirtualLink => {
                        if !participants.contains(&link.link_id) {
                            continue;
                        }
                        let Some(peer_lsa) = router_lsa_by_id.get(&link.link_id) else {
                            continue;
                        };
                        let has_backlink = peer_lsa.links.iter().any(|l| {
                            matches!(l.link_type, OspfLinkType::P2p | OspfLinkType::VirtualLink)
                                && l.link_id == *adv_router
                        });
                        if !has_backlink {
                            continue;
                        }
                        let to_id = top.lsp_map.get(link.link_id);
                        vertex.olinks.push(spf::Link {
                            from: node_id,
                            to: to_id,
                            cost,
                            link_id: 0,
                        });
                    }
                    OspfLinkType::Transit => {
                        let Some(attached) = network_lsas.get(&link.link_id) else {
                            continue;
                        };
                        if !attached.contains(adv_router) {
                            continue;
                        }
                        for attached_router in attached {
                            if *attached_router == *adv_router {
                                continue;
                            }
                            if !participants.contains(attached_router) {
                                continue;
                            }
                            if !router_lsa_by_id.contains_key(attached_router) {
                                continue;
                            }
                            let to_id = top.lsp_map.get(*attached_router);
                            vertex.olinks.push(spf::Link {
                                from: node_id,
                                to: to_id,
                                cost,
                                link_id: 0,
                            });
                        }
                    }
                    OspfLinkType::Stub => {}
                }
            }
        }

        graph.insert(node_id, vertex);
    }

    (graph, source_node)
}

/// OSPF route path type, ordered by RFC 2328 §16.4.1 preference:
/// intra-area is always preferred over inter-area, which is always
/// preferred over (AS-)external, independent of metric. `Ord` derives
/// the preference directly (lower discriminant = more preferred), so
/// `rib_insert` can pick the winner with a single comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RouteType {
    IntraArea,
    InterArea,
    External,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SpfRoute {
    pub metric: u32,
    /// RFC 2328 §16.4 path type. Drives both same-prefix preference in
    /// `rib_insert` (intra beats inter beats external) and ABR Type-3
    /// summary origination (only intra-area — and backbone-learned
    /// inter-area — routes get re-advertised across areas).
    pub path_type: RouteType,
    pub nhops: BTreeMap<Ipv4Addr, SpfNexthop>,
    pub sid: Option<u32>,
    pub prefix_sid: Option<(SidLabelValue, LabelConfig)>,
    /// SPF vertex id this route was built from (the prefix's
    /// advertising router, or the ABR/ASBR for inter-area / external
    /// routes). Set at build time; used by the TI-LFA second pass to
    /// join a route with the per-destination repair computed against
    /// that vertex's first-hop. `None` for routes that carry no
    /// single SPF destination (e.g. per-Flex-Algo entries, which have
    /// no TI-LFA today).
    pub dest_vertex: Option<usize>,
    /// Value of `fast-reroute backup-as-primary` when this route was
    /// built. Carried on the route — rather than read globally at
    /// install time — so it participates in the `PartialEq` that
    /// `spf::table_diff` uses to gate RIB updates: the flag flips the
    /// primary/backup metric in `make_rib_entry`, so two routes with
    /// identical SPF output but a different flag install differently,
    /// and without this field a toggle-then-recompute would diff clean
    /// and never reach the RIB. Mirrors IS-IS's `SpfRoute`.
    pub backup_as_primary: bool,
}

/// One entry in the SR-MPLS LFIB shadow held on `Ospf::ilm`.
/// Mirrors the IS-IS `SpfIlm` shape so `mpls_route()` and
/// `make_ilm_entry()` can stay structurally parallel.
#[derive(Debug, PartialEq)]
pub struct SpfIlm {
    pub nhops: BTreeMap<Ipv4Addr, SpfNexthop>,
    pub ilm_type: IlmType,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SpfNexthop {
    pub ifindex: u32,
    pub adjacency: bool,
    pub router_id: Option<Ipv4Addr>,
    /// TI-LFA post-convergence repair for this primary nexthop, or
    /// `None` when TI-LFA is off, the route is ECMP, or no repair
    /// resolved. Set only on the single primary nexthop of a RIB
    /// route by the TI-LFA second pass in `build_rib_from_spf`;
    /// always `None` for ILM / adjacency nexthops. `make_rib_entry`
    /// renders it as a second NexthopUni at the backup metric offset.
    pub backup: Option<RepairPathMpls>,
}

/// v3 RIB entry. Simpler than the v2 `SpfRoute` shape because v3
/// doesn't have SR-MPLS / prefix-SID wiring yet — there's just the
/// metric and the next-hop set keyed by IPv6 link-local. Added /
/// removed entries are computed via `spf::table_diff` between two
/// `PrefixMap<Ipv6Net, SpfRouteV3>` snapshots, mirroring how v2
/// diffs `top.rib`.
#[derive(Debug, Clone, PartialEq)]
pub struct SpfRouteV3 {
    pub metric: u32,
    /// RFC 2328 §16.4.1 path preference class (intra-area beats
    /// inter-area beats external), shared with v2's `SpfRoute`.
    /// Consulted by `rib6_insert` when two sources offer the same
    /// prefix — the class wins outright regardless of metric.
    pub path_type: RouteType,
    pub nhops: BTreeMap<std::net::Ipv6Addr, SpfNexthopV3>,
    /// Resolved absolute MPLS label for this prefix's SR Prefix-SID,
    /// or `None` if no E-Intra-Area-Prefix-LSA covers this prefix or
    /// the advertising router's SRGB isn't yet known (Index-form SID
    /// needs `label_map[adv_router]` to resolve). Populated by
    /// `add_prefix_sids_v3` after `build_rib6_from_spf`; mirror of
    /// v2's `SpfRoute::sid`.
    pub sid: Option<u32>,
    /// Raw `(SidLabelValue, LabelConfig)` pair preserved so the show
    /// path can surface the on-the-wire SID encoding alongside the
    /// resolved label. Mirror of v2's `SpfRoute::prefix_sid`.
    pub prefix_sid: Option<(SidLabelValue, LabelConfig)>,
    /// SPF vertex id this route was built from (advertising router, or
    /// ABR/ASBR for inter-area / NSSA). Set at build time; joined with
    /// the per-destination repair in the TI-LFA second pass. `None`
    /// for per-Flex-Algo entries (no v3 per-algo TI-LFA). Mirror of
    /// v2's `SpfRoute::dest_vertex`.
    pub dest_vertex: Option<usize>,
    /// `fast-reroute backup-as-primary` at build time, carried so it
    /// joins the `table_diff` equality that gates RIB updates. Mirror
    /// of v2's `SpfRoute::backup_as_primary`.
    pub backup_as_primary: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SpfNexthopV3 {
    pub ifindex: u32,
    /// When true the destination is one hop away (or is us, in the
    /// self-Prefix-SID-pop case). `make_ilm_entry_v6` keys off this
    /// to omit the swap label so the kernel install becomes
    /// Via + Oif with no `NewDestination` (implicit-null / PHP /
    /// local pop). Default `false` for transit nexthops produced by
    /// the SPF builder, which then triggers the standard swap
    /// (push the incoming label as the outgoing label).
    pub adjacency: bool,
    /// TI-LFA post-convergence repair for this primary nexthop, set
    /// only on the single primary nexthop of a RIB route by the v3
    /// TI-LFA second pass; `None` otherwise (ILM/adjacency nexthops,
    /// ECMP, TI-LFA off, or unresolved). v3 sibling of
    /// `SpfNexthop::backup`.
    pub backup: Option<super::tilfa::RepairBackupV3>,
}

/// v3 sibling of `SpfIlm`. Same role -- one entry in the SR-MPLS
/// LFIB shadow -- but the nexthop set is keyed by IPv6 link-local
/// (matching `SpfRouteV3::nhops`) so kernel installs go out with v6
/// `Via` and the right outgoing interface.
#[derive(Debug, PartialEq)]
pub struct SpfIlmV3 {
    pub nhops: BTreeMap<std::net::Ipv6Addr, SpfNexthopV3>,
    pub ilm_type: IlmType,
}

fn rib_insert(rib: &mut PrefixMap<Ipv4Net, SpfRoute>, prefix: Ipv4Net, route: SpfRoute) {
    if let Some(curr) = rib.get_mut(&prefix) {
        // RFC 2328 §16.4.1: a more-preferred path type wins outright,
        // regardless of metric (intra-area beats inter-area beats
        // external). Within the same type, lower metric wins and an
        // exact tie merges nexthops (ECMP).
        match route.path_type.cmp(&curr.path_type) {
            std::cmp::Ordering::Less => *curr = route,
            std::cmp::Ordering::Greater => {}
            std::cmp::Ordering::Equal => {
                if curr.metric > route.metric {
                    *curr = route;
                } else if curr.metric == route.metric {
                    for (addr, nhop) in route.nhops {
                        curr.nhops.insert(addr, nhop);
                    }
                }
            }
        }
    } else {
        rib.insert(prefix, route);
    }
}

/// v6 sibling of `rib_insert`: RFC 2328 §16.4.1 preference — a
/// more-preferred path type wins outright; within a type, lower
/// metric wins and an exact tie merges nexthops (ECMP).
fn rib6_insert(
    rib: &mut PrefixMap<ipnet::Ipv6Net, SpfRouteV3>,
    prefix: ipnet::Ipv6Net,
    route: SpfRouteV3,
) {
    if let Some(curr) = rib.get_mut(&prefix) {
        match route.path_type.cmp(&curr.path_type) {
            std::cmp::Ordering::Less => *curr = route,
            std::cmp::Ordering::Greater => {}
            std::cmp::Ordering::Equal => {
                if curr.metric > route.metric {
                    *curr = route;
                } else if curr.metric == route.metric {
                    for (addr, nhop) in route.nhops {
                        curr.nhops.insert(addr, nhop);
                    }
                }
            }
        }
    } else {
        rib.insert(prefix, route);
    }
}

/// Build the nexthop map for an SPF destination vertex. The set is
/// computed from `path.nexthops` (which each begin with the first-hop
/// neighbor's vertex id) by walking our links and matching neighbors
/// by router-id. Shared by intra-area and inter-area route building.
fn build_spf_nexthops(
    top: &Ospf,
    target_id: usize,
    path: &spf::Path,
) -> BTreeMap<Ipv4Addr, SpfNexthop> {
    let mut nhops = BTreeMap::new();
    for p in &path.nexthops {
        // p.is_empty() means the destination is the SPF root (us).
        if p.is_empty() {
            continue;
        }
        let Some(nhop_id) = top.lsp_map.resolve(p[0]) else {
            continue;
        };
        for (ifindex, link) in top.links.iter() {
            for (_, nbr) in link.nbrs.iter() {
                if *nhop_id == nbr.ident.router_id {
                    let addr = nbr.ident.prefix.addr();
                    let nhop = SpfNexthop {
                        ifindex: *ifindex,
                        adjacency: p[0] == target_id,
                        router_id: Some(*nhop_id),
                        // Stamped by the TI-LFA second pass (single-
                        // primary routes only); None at build time.
                        backup: None,
                    };
                    nhops.insert(addr, nhop);
                }
            }
        }
    }
    nhops
}

/// Walk Type 3 (Network Summary) LSAs in `area`'s LSDB and install
/// inter-area routes per RFC 2328 §16.2. For each Summary LSA whose
/// advertising router is reachable via SPF, install a route at cost
/// SPF(ABR) + LSA.metric, with the ABR's nexthops.
///
/// Type 4 (ASBR Summary) LSAs are consumed by AS-external route
/// computation (§16.4), not direct prefix install — they're handled
/// separately when that path lands.
fn add_inter_area_routes(
    top: &Ospf,
    area_id: Ipv4Addr,
    spf_result: &BTreeMap<usize, spf::Path>,
    rib: &mut PrefixMap<Ipv4Net, SpfRoute>,
) {
    use crate::ospf::lsdb::OSPF_MAX_AGE;
    // OSPF metrics are 24-bit; 0xFFFFFF = LSInfinity (unreachable).
    const LS_INFINITY: u32 = 0x00FF_FFFF;

    let Some(area) = top.areas.get(area_id) else {
        return;
    };

    for ((ls_id, _key_adv), lsa) in area.lsdb.iter_by_type(OspfLsType::Summary) {
        // RFC 2328 §16.2: skip MaxAge LSAs.
        if lsa.data.h.ls_age >= OSPF_MAX_AGE {
            continue;
        }
        // Skip self-originated summaries — we are the ABR for these.
        if lsa.data.h.adv_router == top.router_id {
            continue;
        }
        let OspfLsp::Summary(ref summary) = lsa.data.lsp else {
            continue;
        };
        if summary.metric >= LS_INFINITY {
            continue;
        }

        // Resolve the advertising router (the ABR) to its SPF vertex.
        // If the ABR has no allocated vertex, or isn't reachable in
        // this SPF run, the inter-area destination is unreachable.
        let Some(abr_vertex) = top.lsp_map.lookup(lsa.data.h.adv_router) else {
            continue;
        };
        let Some(abr_path) = spf_result.get(&abr_vertex) else {
            continue;
        };

        let mask = u32::from(summary.netmask).leading_ones() as u8;
        let Ok(prefix) = Ipv4Net::new(ls_id, mask) else {
            continue;
        };
        let prefix = prefix.trunc();

        let nhops = build_spf_nexthops(top, abr_vertex, abr_path);
        if nhops.is_empty() {
            continue;
        }

        let total_metric = abr_path.cost.saturating_add(summary.metric);
        let spf_route = SpfRoute {
            metric: total_metric,
            path_type: RouteType::InterArea,
            nhops,
            sid: None,
            prefix_sid: None,
            // Protect the path to the ABR: TI-LFA's repair is computed
            // against the first-hop toward `abr_vertex`.
            dest_vertex: Some(abr_vertex),
            backup_as_primary: top.fast_reroute_backup_as_primary,
        };
        rib_insert(rib, prefix, spf_route);
    }
}

/// Find the local enabled v2 link in `area_id` whose interface
/// address equals `addr` — used for self transit-network links,
/// where `link.link_id` is our own interface IP (we are the DR).
fn self_link_by_addr(top: &Ospf, area_id: Ipv4Addr, addr: Ipv4Addr) -> Option<&OspfLink> {
    top.links
        .values()
        .find(|l| l.enabled && l.area == area_id && l.addr.iter().any(|a| a.prefix.addr() == addr))
}

/// Find the local enabled v2 link in `area_id` whose configured
/// prefix matches the stub `prefix` — used for self stub links
/// (loopback /32 or segment /N from our own Router-LSA).
fn self_link_by_prefix(top: &Ospf, area_id: Ipv4Addr, prefix: Ipv4Net) -> Option<&OspfLink> {
    top.links.values().find(|l| {
        l.enabled && l.area == area_id && l.addr.iter().any(|a| a.prefix.trunc() == prefix)
    })
}

/// Build the v2 nexthop set for a directly-attached self route:
/// single entry keyed by `Ipv4Addr::UNSPECIFIED` with the local
/// ifindex. The show layer treats UNSPECIFIED as "directly attached".
fn attached_nhops(ifindex: u32) -> BTreeMap<Ipv4Addr, SpfNexthop> {
    let mut nhops = BTreeMap::new();
    nhops.insert(
        Ipv4Addr::UNSPECIFIED,
        SpfNexthop {
            ifindex,
            adjacency: false,
            router_id: None,
            backup: None,
        },
    );
    nhops
}

fn build_rib_from_spf(
    top: &Ospf,
    area_id: Ipv4Addr,
    source: usize,
    spf_result: &BTreeMap<usize, spf::Path>,
    tilfa_result: &BTreeMap<usize, Vec<spf::RepairPath>>,
) -> PrefixMap<Ipv4Net, SpfRoute> {
    let mut rib = PrefixMap::<Ipv4Net, SpfRoute>::new();

    let Some(area) = top.areas.get(area_id) else {
        return rib;
    };

    // Intra-area: walk each SPF destination's Router-LSA links.
    // Self is included so locally-attached stub prefixes (loopback /32s,
    // p2p stubs) and transit prefixes where we are the DR install with
    // empty (directly-attached) nexthops, mirroring v3's
    // `build_rib6_from_spf`. The kernel's connected route (admin 0)
    // wins over the OSPF route (admin 110) in the FIB, so this only
    // changes `show ospf route` — bringing it into parity with FRR.
    for (node, nhops) in spf_result {
        let is_self = *node == source;

        // Resolve node to router-id.
        let Some(router_id) = top.lsp_map.resolve(*node) else {
            continue;
        };

        let spf_nhops = build_spf_nexthops(top, *node, nhops);

        if let Some(lsa) = area
            .lsdb
            .lookup_by_id(OspfLsType::Router, *router_id, *router_id)
            && let OspfLsp::Router(ref router_lsa) = lsa.lsp
        {
            for link in &router_lsa.links {
                match link.link_type {
                    OspfLinkType::Transit => {
                        // Transit Network: look up Network-LSA to get the
                        // network prefix (link_id = dr's interface ip).
                        for ((_ls_id, _adv), nlsa) in area.lsdb.iter_by_type(OspfLsType::Network) {
                            if let OspfLsp::Network(ref net) = nlsa.data.lsp
                                && nlsa.data.h.ls_id == link.link_id
                            {
                                let mask = u32::from(net.netmask).leading_ones() as u8;
                                if let Ok(prefix) = Ipv4Net::new(link.link_id, mask) {
                                    let prefix = prefix.trunc();

                                    let (metric, route_nhops) = if is_self {
                                        // Self transit: we are the DR.
                                        // link.link_id is our interface
                                        // address on the segment; find
                                        // the local link and stamp its
                                        // ifindex as a directly-attached
                                        // nexthop.
                                        let Some(local) =
                                            self_link_by_addr(top, area_id, link.link_id)
                                        else {
                                            break;
                                        };
                                        (link.tos_0_metric as u32, attached_nhops(local.index))
                                    } else {
                                        // RFC 2328 §16.1.1: transit metric
                                        // is D(V) + V's link.tos_0_metric
                                        // to the network — *not* just D(V).
                                        // Without the per-link term, a
                                        // peer's transit advertisement for
                                        // the same prefix we serve as DR
                                        // tied at our local cost and
                                        // ECMP-merged with the
                                        // directly-attached entry.
                                        (
                                            nhops.cost.saturating_add(link.tos_0_metric as u32),
                                            spf_nhops.clone(),
                                        )
                                    };

                                    let spf_route = SpfRoute {
                                        metric,
                                        path_type: RouteType::IntraArea,
                                        nhops: route_nhops,
                                        sid: None,
                                        prefix_sid: None,
                                        dest_vertex: Some(*node),
                                        backup_as_primary: top.fast_reroute_backup_as_primary,
                                    };
                                    rib_insert(&mut rib, prefix, spf_route);
                                }
                                break;
                            }
                        }
                    }
                    OspfLinkType::Stub => {
                        // Stub Network: link_id = network addr,
                        // link_data = netmask.
                        let mask = u32::from(link.link_data).leading_ones() as u8;
                        if let Ok(prefix) = Ipv4Net::new(link.link_id, mask) {
                            let prefix = prefix.trunc();

                            let (metric, route_nhops) = if is_self {
                                // Self stub: find the local link whose
                                // address sits inside this prefix
                                // (loopback /32 matches itself; segment
                                // stub matches the configured /N).
                                let Some(local) = self_link_by_prefix(top, area_id, prefix) else {
                                    continue;
                                };
                                (link.tos_0_metric as u32, attached_nhops(local.index))
                            } else {
                                // RFC 2328 §16.1.1: stub metric is
                                // D(V) + L.cost (per V's Router-LSA).
                                // Symmetric with the transit arm above.
                                (
                                    nhops.cost.saturating_add(link.tos_0_metric as u32),
                                    spf_nhops.clone(),
                                )
                            };

                            let spf_route = SpfRoute {
                                metric,
                                path_type: RouteType::IntraArea,
                                nhops: route_nhops,
                                sid: None,
                                prefix_sid: None,
                                dest_vertex: Some(*node),
                                backup_as_primary: top.fast_reroute_backup_as_primary,
                            };
                            rib_insert(&mut rib, prefix, spf_route);
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    // Inter-area: walk Type 3 Summary LSAs and install via SPF nexthop
    // to the originating ABR.
    add_inter_area_routes(top, area_id, spf_result, &mut rib);

    // AS-external: walk Type 5 LSAs and install via SPF nexthop to the
    // originating ASBR. Falls back to Type-4 Summary-ASBR LSAs for
    // ASBRs reachable only via other areas (RFC 2328 §16.4 step 5).
    add_as_external_routes(top, area_id, spf_result, &mut rib);

    // NSSA Type-7: walk this area's Type 7 LSAs when the area is
    // NSSA. Type-7s flood with area scope (RFC 3101 §2.5), so the
    // walk reads from `area.lsdb` and resolves the originator via
    // this area's SPF.
    if area.area_type.is_nssa() {
        add_nssa_routes(top, area_id, spf_result, &mut rib);
    }

    // SR-MPLS: walk Extended-Prefix Opaque LSAs and attach the
    // advertised Prefix-SID to matching installed prefixes. No FIB
    // change here -- this only populates `SpfRoute.prefix_sid` so the
    // show command and a follow-up ILM-install pass can consume it.
    add_prefix_sids(top, area_id, &mut rib);

    // TI-LFA second pass: stamp the post-convergence repair backup
    // onto single-primary routes. ECMP routes (>1 nexthop) are
    // skipped — the surviving ECMP legs already protect the prefix,
    // mirroring IS-IS. `tilfa_repair_path` only emits repairs for
    // single-primary SPF destinations, so the `dest_vertex` lookup
    // either yields a repair built against a single protected
    // first-hop or nothing. Resolving a repair list to an MPLS label
    // stack needs the LSDB, which is why this runs on the main task
    // (here) rather than on the SPF worker that produced the lists.
    if let Some(area) = top.areas.get(area_id) {
        for (_, route) in rib.iter_mut() {
            if route.nhops.len() != 1 {
                continue;
            }
            let Some(dest) = route.dest_vertex else {
                continue;
            };
            let Some(repair) = tilfa_result.get(&dest).and_then(|paths| paths.first()) else {
                continue;
            };
            let Some(backup) = build_repair_path_mpls(top, area, repair) else {
                continue;
            };
            if let Some(nhop) = route.nhops.values_mut().next() {
                nhop.backup = Some(backup);
            }
        }
    }

    rib
}

/// Walk Extended-Prefix Opaque LSAs (type 10 / opaque-type 7,
/// RFC 7684 + RFC 8665) and attach the advertised Prefix-SID to any
/// route already in `rib` whose prefix matches an Ext-Prefix TLV.
///
/// For Index-form SIDs we resolve to the absolute label via the
/// advertising router's SRGB held in `Lsdb::label_map` (populated
/// from received Router Information LSAs). Label-form SIDs are
/// stored as-is. MaxAge'd LSAs are skipped, same as the AS-external
/// pass above.
///
/// This is a data-population step only: no MPLS routes are installed
/// here, and `SpfRoute.metric` / `SpfRoute.nhops` are left untouched.
fn add_prefix_sids(top: &Ospf, area_id: Ipv4Addr, rib: &mut PrefixMap<Ipv4Net, SpfRoute>) {
    use crate::ospf::lsdb::OSPF_MAX_AGE;

    // SR-MPLS participation is a local choice: with `segment-routing
    // mpls` removed, no label may be imposed and no ILM derived, even
    // though peers' Ext-Prefix LSAs stay in the LSDB. Same gate as
    // `add_prefix_sids_v3` — without it a disable kept every remote
    // node-SID swap entry in the LFIB while only the self pop entries
    // went away with the flushed self LSAs.
    if top.segment_routing != super::srmpls::SegmentRoutingMode::Mpls {
        return;
    }

    let Some(area) = top.areas.get(area_id) else {
        return;
    };

    for (_, lsa) in area.lsdb.iter_by_type(OspfLsType::OpaqueAreaLocal) {
        if lsa.data.h.ls_age >= OSPF_MAX_AGE {
            continue;
        }
        let OspfLsp::OpaqueAreaExtPrefix(ref ep) = lsa.data.lsp else {
            continue;
        };
        let adv_router = lsa.data.h.adv_router;
        // Skip self-originated Ext-Prefix LSAs. Resolving and installing
        // our own Prefix-SID would push an egress label onto a directly-
        // attached loopback route and seed an ILM entry against our own
        // /32 -- both nonsensical. The local Node-SID's "label X -> pop"
        // semantics belong to a follow-up dedicated to self-SID install.
        if adv_router == top.router_id {
            continue;
        }
        let Some(label_config) = area.lsdb.label_map.get(&adv_router) else {
            // No SRGB known for this advertiser yet -- the matching
            // Router Information LSA has not arrived (or carried no
            // SidLabelRange). The Index-form Prefix-SID would be
            // unresolvable in that case, so skip and let a later SPF
            // pick it up once the SRGB lands.
            continue;
        };
        for tlv in &ep.tlvs {
            let Some(route) = rib.get_mut(&tlv.prefix) else {
                continue;
            };
            for sub in &tlv.subs {
                let ExtPrefixSubTlv::PrefixSid(ps) = sub else {
                    continue;
                };
                let (value, sid_label) = match ps.sid {
                    SidLabelTlv::Label(v) => (SidLabelValue::Label(v), Some(v)),
                    SidLabelTlv::Index(v) => (
                        SidLabelValue::Index(v),
                        label_config.global.start.checked_add(v),
                    ),
                };
                route.prefix_sid = Some((value, label_config.clone()));
                // Resolved absolute label feeds nhop_to_nexthop_uni
                // (egress label imposition on the IPv4 route) and
                // mpls_route() below (ILM entry on the local LFIB).
                route.sid = sid_label;
                break;
            }
        }
    }
}

/// Build the per-Flexible-Algorithm IPv4 RIB for `algo` from its SPF
/// result. Unlike `build_rib_from_spf`, this is driven by the per-algo
/// Prefix-SIDs: for SR-MPLS Flex-Algo only prefixes that carry a
/// per-algo Prefix-SID are forwardable (a label is needed at every
/// hop), so each entry is one peer Extended-Prefix LSA's algo-`algo`
/// Prefix-SID, reached over the per-algo SPF path to its originator.
///
/// Mirrors the IS-IS `build_rib_from_flex_algo`: per-algo IPv4 is held
/// in-memory only; the resolved `sid` label is what installs into the
/// kernel MPLS ILM (follow-up). Self-originated per-algo SIDs (local
/// Node-SID pop) are skipped here, matching `add_prefix_sids`.
fn build_rib_from_flex_algo(
    top: &Ospf,
    area_id: Ipv4Addr,
    algo: u8,
    spf_result: &BTreeMap<usize, spf::Path>,
) -> PrefixMap<Ipv4Net, SpfRoute> {
    use crate::ospf::lsdb::OSPF_MAX_AGE;

    let mut rib = PrefixMap::<Ipv4Net, SpfRoute>::new();
    let Some(area) = top.areas.get(area_id) else {
        return rib;
    };

    for (_, lsa) in area.lsdb.iter_by_type(OspfLsType::OpaqueAreaLocal) {
        if lsa.data.h.ls_age >= OSPF_MAX_AGE {
            continue;
        }
        let OspfLsp::OpaqueAreaExtPrefix(ref ep) = lsa.data.lsp else {
            continue;
        };
        let adv_router = lsa.data.h.adv_router;
        if adv_router == top.router_id {
            continue;
        }
        let Some(label_config) = area.lsdb.label_map.get(&adv_router) else {
            continue;
        };
        // The per-algo path to the prefix's originator. If the origin
        // is unreachable under this algo's FAD-filtered topology, the
        // prefix isn't forwardable under the algo — skip it.
        let Some(origin_node) = top.lsp_map.lookup(adv_router) else {
            continue;
        };
        let Some(path) = spf_result.get(&origin_node) else {
            continue;
        };
        let nhops = build_spf_nexthops(top, origin_node, path);
        if nhops.is_empty() {
            continue;
        }

        for tlv in &ep.tlvs {
            for sub in &tlv.subs {
                let ExtPrefixSubTlv::PrefixSid(ps) = sub else {
                    continue;
                };
                if ps.algo != Algo::FlexAlgo(algo) {
                    continue;
                }
                let (value, sid_label) = match ps.sid {
                    SidLabelTlv::Label(v) => (SidLabelValue::Label(v), Some(v)),
                    SidLabelTlv::Index(v) => (
                        SidLabelValue::Index(v),
                        label_config.global.start.checked_add(v),
                    ),
                };
                let route = SpfRoute {
                    metric: path.cost,
                    path_type: RouteType::IntraArea,
                    nhops: nhops.clone(),
                    sid: sid_label,
                    prefix_sid: Some((value, label_config.clone())),
                    // Per-Flex-Algo routes have no TI-LFA today (the FAD
                    // topology may not admit the algo-0 repair); leave
                    // the repair-join fields inert.
                    dest_vertex: None,
                    backup_as_primary: false,
                };
                rib_insert(&mut rib, tlv.prefix, route);
                break;
            }
        }
    }
    rib
}

/// OSPFv3 sibling of `build_rib_from_flex_algo`: build the per-algo
/// IPv6 RIB from peer E-Intra-Area-Prefix-LSAs carrying a per-algo
/// Prefix-SID (RFC 9350 §7). For each such prefix whose originator is
/// reachable under `algo`'s FAD-filtered SPF (`spf_result`), resolve
/// the Prefix-SID label against the advertiser's SRGB
/// (`Lsdb::label_map`) and record the per-algo nexthops. Self prefixes
/// are skipped (pushing a label onto our own /128 is nonsensical),
/// matching `build_rib_from_flex_algo`.
fn build_rib6_from_flex_algo(
    top: &Ospf<Ospfv3>,
    area_id: Ipv4Addr,
    algo: u8,
    spf_result: &BTreeMap<usize, spf::Path>,
) -> PrefixMap<ipnet::Ipv6Net, SpfRouteV3> {
    use ospf_packet::{
        OSPFV3_E_INTRA_AREA_PREFIX_LSA_TYPE, Ospfv3ExtTlv, Ospfv3LsBody, Ospfv3SubTlv,
    };

    use crate::ospf::lsdb::OSPF_MAX_AGE;

    let mut rib = PrefixMap::<ipnet::Ipv6Net, SpfRouteV3>::new();
    let Some(area) = top.areas.get(area_id) else {
        return rib;
    };

    for ((_ls_id, adv_router), lsa) in area
        .lsdb
        .iter_by_raw_type(OSPFV3_E_INTRA_AREA_PREFIX_LSA_TYPE)
    {
        if lsa.data.h.ls_age >= OSPF_MAX_AGE {
            continue;
        }
        if adv_router == top.router_id {
            continue;
        }
        let Ospfv3LsBody::EIntraAreaPrefix(ref body) = lsa.data.body else {
            continue;
        };
        let Some(label_config) = area.lsdb.label_map.get(&adv_router) else {
            continue;
        };
        // Per-algo path to the prefix's originator. Unreachable under
        // this algo's FAD-filtered topology ⇒ not forwardable ⇒ skip.
        let Some(origin_node) = top.lsp_map.lookup(adv_router) else {
            continue;
        };
        let Some(path) = spf_result.get(&origin_node) else {
            continue;
        };
        let nhops: BTreeMap<std::net::Ipv6Addr, SpfNexthopV3> = collect_v3_nexthops(top, path)
            .into_iter()
            .map(|(addr, ifindex)| {
                (
                    addr,
                    SpfNexthopV3 {
                        ifindex,
                        adjacency: false,
                        backup: None,
                    },
                )
            })
            .collect();
        if nhops.is_empty() {
            continue;
        }

        for tlv in &body.tlvs {
            let Ospfv3ExtTlv::IntraAreaPrefix(prefix_tlv) = tlv else {
                continue;
            };
            let Some(prefix) =
                ospfv3_prefix_to_ipv6net(prefix_tlv.prefix_length, &prefix_tlv.address_prefix)
            else {
                continue;
            };
            for sub in &prefix_tlv.subs {
                let Ospfv3SubTlv::PrefixSid(ps) = sub else {
                    continue;
                };
                if ps.algo != Algo::FlexAlgo(algo) {
                    continue;
                }
                let (value, sid_label) = match ps.sid {
                    SidLabelTlv::Label(v) => (SidLabelValue::Label(v), Some(v)),
                    SidLabelTlv::Index(v) => (
                        SidLabelValue::Index(v),
                        label_config.global.start.checked_add(v),
                    ),
                };
                let route = SpfRouteV3 {
                    metric: path.cost,
                    path_type: RouteType::IntraArea,
                    nhops: nhops.clone(),
                    sid: sid_label,
                    prefix_sid: Some((value, label_config.clone())),
                    // Per-Flex-Algo routes have no TI-LFA today.
                    dest_vertex: None,
                    backup_as_primary: false,
                };
                rib6_insert(&mut rib, prefix, route);
                break;
            }
        }
    }
    rib
}

/// Walk Type 5 (AS-External) LSAs in the AS-scoped LSDB and install
/// external routes per RFC 2328 §16.4.
///
/// For each LSA whose advertising router (ASBR) is reachable via SPF
/// in the current area, compute the route metric per the LSA's E bit:
///   - Type 1 external: SPF(ASBR) + LSA.metric
///   - Type 2 external: LSA.metric only (SPF cost is the tiebreak,
///     but the FIB-installed metric is the external cost)
///
/// Non-zero forwarding-address LSAs are skipped for now. §16.4 step 3
/// requires resolving the forwarding address against an intra-area
/// route, which is a separate code path.
fn add_as_external_routes(
    top: &Ospf,
    area_id: Ipv4Addr,
    spf_result: &BTreeMap<usize, spf::Path>,
    rib: &mut PrefixMap<Ipv4Net, SpfRoute>,
) {
    use crate::ospf::lsdb::OSPF_MAX_AGE;
    // OSPF metrics are 24-bit; 0xFFFFFF = LSInfinity (unreachable).
    const LS_INFINITY: u32 = 0x00FF_FFFF;
    // E flag in the AS-external LSA's `ext_and_resvd` byte.
    const E_FLAG: u8 = 0x80;

    for ((ls_id, _key_adv), lsa) in top.lsdb_as.iter_by_type(OspfLsType::AsExternal) {
        if lsa.data.h.ls_age >= OSPF_MAX_AGE {
            continue;
        }
        if lsa.data.h.adv_router == top.router_id {
            continue;
        }
        let OspfLsp::AsExternal(ref ext) = lsa.data.lsp else {
            continue;
        };
        if ext.metric >= LS_INFINITY {
            continue;
        }
        // Forwarding-address resolution (§16.4 step 3) deferred.
        if !ext.forwarding_address.is_unspecified() {
            continue;
        }

        let asbr_id = lsa.data.h.adv_router;
        // The ASBR may not appear in THIS area's lsp_map / SPF at all when
        // it lives in another area (its Router-LSA is area-scoped) — that
        // is exactly the inter-area case the Type-4 fallback below handles,
        // so keep `asbr_vertex` optional rather than bailing here.
        let asbr_vertex = top.lsp_map.lookup(asbr_id);

        // Try the local (intra-area) SPF result first. If the ASBR is
        // in another area, fall back to a Type-4 Summary-ASBR LSA
        // advertised by an ABR that is reachable from this area
        // (RFC 2328 §16.4 step 5).
        let (asbr_cost, nexthop_vertex, nexthop_path) = if let Some((vertex, path)) =
            asbr_vertex.and_then(|v| spf_result.get(&v).map(|p| (v, p)))
        {
            (path.cost, vertex, path.clone())
        } else {
            // Look for a Type-4 in this area whose ls_id == asbr_id.
            let type4 = top.areas.get(area_id).and_then(|area| {
                area.lsdb
                    .iter_by_type(OspfLsType::SummaryAsbr)
                    .filter(|((ls_id_t4, _), lsa_t4)| {
                        *ls_id_t4 == asbr_id
                            && lsa_t4.data.h.ls_age < OSPF_MAX_AGE
                            && lsa_t4.data.h.adv_router != top.router_id
                    })
                    .filter_map(|((_, _), lsa_t4)| {
                        // A self-originated Type-4 carries an
                        // `OspfLsp::Summary` body, but one received off
                        // the wire is parsed into the distinct
                        // `OspfLsp::SummaryAsbr` variant — accept both,
                        // else a remote ABR's Type-4 (the only kind a
                        // non-backbone router ever sees) never resolves.
                        let (OspfLsp::Summary(ref s) | OspfLsp::SummaryAsbr(ref s)) =
                            lsa_t4.data.lsp
                        else {
                            return None;
                        };
                        let abr_id = lsa_t4.data.h.adv_router;
                        let abr_vertex = top.lsp_map.lookup(abr_id)?;
                        let abr_path = spf_result.get(&abr_vertex)?;
                        Some((
                            abr_path.cost.saturating_add(s.metric),
                            abr_vertex,
                            abr_path.clone(),
                        ))
                    })
                    .min_by_key(|(cost, _, _)| *cost)
            });
            match type4 {
                Some(t) => t,
                None => continue,
            }
        };

        let is_type2 = (ext.ext_and_resvd & E_FLAG) != 0;
        let metric = if is_type2 {
            ext.metric
        } else {
            asbr_cost.saturating_add(ext.metric)
        };

        let mask = u32::from(ext.netmask).leading_ones() as u8;
        let Ok(prefix) = Ipv4Net::new(ls_id, mask) else {
            continue;
        };
        let prefix = prefix.trunc();

        let nhops = build_spf_nexthops(top, nexthop_vertex, &nexthop_path);
        if nhops.is_empty() {
            continue;
        }

        let spf_route = SpfRoute {
            metric,
            path_type: RouteType::External,
            nhops,
            sid: None,
            prefix_sid: None,
            dest_vertex: Some(nexthop_vertex),
            backup_as_primary: top.fast_reroute_backup_as_primary,
        };
        rib_insert(rib, prefix, spf_route);
    }
}

/// Walk Type 7 (NSSA-AS-External) LSAs in the area LSDB and install
/// NSSA external routes per RFC 3101 §2.5.
///
/// Mirrors `add_as_external_routes` but scoped to a single area:
/// Type-7 LSAs flood only within an NSSA, so the walk reads from
/// `area.lsdb` (not `top.lsdb_as`). The originating router
/// reachability is also resolved against this area's SPF.
///
/// Metric handling matches Type-5:
///   - E1 (E-bit clear): SPF(originator) + LSA.metric
///   - E2 (E-bit set):    LSA.metric only
///
/// P-bit is intentionally not consulted here — it controls
/// Type-7→Type-5 translation at the ABR, not SPF installation on
/// the receiver. Non-zero forwarding-address LSAs are skipped
/// (RFC 3101 §2.5 step 5 FA resolution deferred to a follow-up);
/// MaxAge'd LSAs and self-originated LSAs are skipped for the
/// same reasons as Type-5.
fn add_nssa_routes(
    top: &Ospf,
    area_id: Ipv4Addr,
    spf_result: &BTreeMap<usize, spf::Path>,
    rib: &mut PrefixMap<Ipv4Net, SpfRoute>,
) {
    use crate::ospf::lsdb::OSPF_MAX_AGE;
    const LS_INFINITY: u32 = 0x00FF_FFFF;
    const E_FLAG: u8 = 0x80;

    let Some(area) = top.areas.get(area_id) else {
        return;
    };

    for ((ls_id, _key_adv), lsa) in area.lsdb.iter_by_type(OspfLsType::NssaAsExternal) {
        if lsa.data.h.ls_age >= OSPF_MAX_AGE {
            continue;
        }
        if lsa.data.h.adv_router == top.router_id {
            continue;
        }
        let OspfLsp::NssaAsExternal(ref ext) = lsa.data.lsp else {
            continue;
        };
        if ext.metric >= LS_INFINITY {
            continue;
        }
        // RFC 3101 §2.5 step 5: non-zero FA resolves the route via
        // an intra-area path to the FA, not to the originator. The
        // resolver lands in a follow-up — same shape that Type-5
        // is missing today.
        if !ext.forwarding_address.is_unspecified() {
            continue;
        }

        let Some(originator_vertex) = top.lsp_map.lookup(lsa.data.h.adv_router) else {
            continue;
        };
        let Some(originator_path) = spf_result.get(&originator_vertex) else {
            continue;
        };

        let is_e2 = (ext.ext_and_tos & E_FLAG) != 0;
        let metric = if is_e2 {
            ext.metric
        } else {
            originator_path.cost.saturating_add(ext.metric)
        };

        let mask = u32::from(ext.netmask).leading_ones() as u8;
        let Ok(prefix) = Ipv4Net::new(ls_id, mask) else {
            continue;
        };
        let prefix = prefix.trunc();

        let nhops = build_spf_nexthops(top, originator_vertex, originator_path);
        if nhops.is_empty() {
            continue;
        }

        let spf_route = SpfRoute {
            metric,
            path_type: RouteType::External,
            nhops,
            sid: None,
            prefix_sid: None,
            // Protect the path to the NSSA originator (ASBR).
            dest_vertex: Some(originator_vertex),
            backup_as_primary: top.fast_reroute_backup_as_primary,
        };
        rib_insert(rib, prefix, spf_route);
    }
}

/// Build the intra-area SPF graph for an OSPFv3 area.
///
/// Mirrors v2's `graph` but uses the v3 LSA-body shapes (Router-LSA
/// links carry `neighbor_router_id` directly; Network-LSAs are
/// keyed by `(interface_id_of_DR, advertising_router=DR_router_id)`).
/// Returns `(graph, Some(source))` where `source` is the SPF
/// vertex index for this router's Router-LSA, or
/// `(graph, None)` if no own Router-LSA exists yet.
fn graph_v3(top: &mut Ospf<Ospfv3>, area_id: Ipv4Addr) -> (spf::Graph, Option<usize>) {
    use crate::ospf::lsdb::OSPF_MAX_AGE;
    use ospf_packet::{OSPFV3_NETWORK_LSA_TYPE, OSPFV3_ROUTER_LSA_TYPE, Ospfv3LsBody};

    let mut graph = spf::Graph::new();
    let mut source_node = None;

    let Some(area) = top.areas.get(area_id) else {
        return (graph, source_node);
    };

    // Collect non-MaxAge Router-LSAs.
    let mut router_lsas = Vec::new();
    for ((_ls_id, adv_router), lsa) in area.lsdb.iter_by_raw_type(OSPFV3_ROUTER_LSA_TYPE) {
        if lsa.data.h.ls_age >= OSPF_MAX_AGE {
            continue;
        }
        router_lsas.push((adv_router, lsa.originated, lsa.data.clone()));
    }

    // Side-table for the bidirectional back-link check on
    // PointToPoint / VirtualLink edges. Keyed by adv_router; refs
    // into the local router_lsas Vec.
    let mut router_lsa_by_id: std::collections::HashMap<Ipv4Addr, &ospf_packet::Ospfv3RouterLsa> =
        std::collections::HashMap::new();
    for (adv_router, _, lsa_data) in &router_lsas {
        if let Ospfv3LsBody::Router(ref router_body) = lsa_data.body {
            router_lsa_by_id.insert(*adv_router, router_body);
        }
    }

    // Collect Network-LSAs by (DR_interface_id, DR_router_id) →
    // attached_routers. RFC 5340 §A.4.4: Network-LSA's ls_id is the
    // DR's Interface ID; adv_router is the DR's router-id.
    let mut network_lsas: std::collections::HashMap<(u32, Ipv4Addr), Vec<Ipv4Addr>> =
        std::collections::HashMap::new();
    for ((ls_id, adv_router), lsa) in area.lsdb.iter_by_raw_type(OSPFV3_NETWORK_LSA_TYPE) {
        if lsa.data.h.ls_age >= OSPF_MAX_AGE {
            continue;
        }
        if let Ospfv3LsBody::Network(ref net_body) = lsa.data.body {
            network_lsas.insert((ls_id, adv_router), net_body.attached_routers.clone());
        }
    }

    // Map each neighbor router-id we hold a local adjacency to -> the
    // ifindex of its interface, so edges from our own Router-LSA carry
    // a usable `link_id` for TI-LFA's repair first-hop (mirrors the v2
    // graph builder). v3 keys `link.nbrs` by router-id and learns the
    // ifindex from the adjacency.
    let mut nbr_to_ifindex: std::collections::HashMap<Ipv4Addr, u32> =
        std::collections::HashMap::new();
    for link in top.links.values() {
        for nbr in link.nbrs.values() {
            nbr_to_ifindex.insert(nbr.ident.router_id, nbr.ifindex);
        }
    }

    // Pass 1: create every vertex and resolve the source. All vertices
    // must exist before pass 2 wires edges onto both endpoints.
    for (adv_router, originated, _lsa_data) in &router_lsas {
        let node_id = top.lsp_map.get(*adv_router);
        if *originated {
            source_node = Some(node_id);
        }
        let vertex = spf::Vertex {
            id: node_id,
            name: adv_router.to_string(),
            sys_id: adv_router.to_string(),
            ..Default::default()
        };
        graph.insert(node_id, vertex);
    }

    // Pass 2: wire edges onto the originator's `olinks` (forward SPF,
    // unchanged) and the target's `ilinks` (reverse SPF for TI-LFA's
    // Q-space — new, previously unpopulated).
    for (adv_router, originated, lsa_data) in &router_lsas {
        let node_id = top.lsp_map.get(*adv_router);
        let Ospfv3LsBody::Router(ref router_body) = lsa_data.body else {
            continue;
        };
        for link in &router_body.links {
            use ospf_packet::Ospfv3RouterLinkType;
            match link.link_type {
                Ospfv3RouterLinkType::PointToPoint | Ospfv3RouterLinkType::VirtualLink => {
                    // Bidirectional check: peer's Router-LSA must exist
                    // (non-MaxAge) AND carry a matching link back to us.
                    let Some(peer_lsa) = router_lsa_by_id.get(&link.neighbor_router_id) else {
                        continue;
                    };
                    let has_backlink = peer_lsa.links.iter().any(|l| {
                        matches!(
                            l.link_type,
                            Ospfv3RouterLinkType::PointToPoint | Ospfv3RouterLinkType::VirtualLink
                        ) && l.neighbor_router_id == *adv_router
                    });
                    if !has_backlink {
                        continue;
                    }
                    let to_id = top.lsp_map.get(link.neighbor_router_id);
                    let link_id = if *originated {
                        nbr_to_ifindex
                            .get(&link.neighbor_router_id)
                            .copied()
                            .unwrap_or(0)
                    } else {
                        0
                    };
                    push_edge(&mut graph, node_id, to_id, link.metric as u32, link_id);
                }
                Ospfv3RouterLinkType::Transit => {
                    // Bidirectional check: Network-LSA must list us in
                    // attached_routers. Key is the DR's
                    // (interface_id, router_id) from the Router-LSA
                    // link's (neighbor_interface_id, neighbor_router_id).
                    let net_key = (link.neighbor_interface_id, link.neighbor_router_id);
                    let Some(attached) = network_lsas.get(&net_key) else {
                        continue;
                    };
                    if !attached.iter().any(|r| r == adv_router) {
                        continue;
                    }
                    // Edges to every other attached router (excluding
                    // self) at the link's metric.
                    for peer in attached {
                        if peer == adv_router {
                            continue;
                        }
                        let to_id = top.lsp_map.get(*peer);
                        let link_id = if *originated {
                            nbr_to_ifindex.get(peer).copied().unwrap_or(0)
                        } else {
                            0
                        };
                        push_edge(&mut graph, node_id, to_id, link.metric as u32, link_id);
                    }
                }
            }
        }
    }

    (graph, source_node)
}

/// OSPFv3 analog of `flex_algo_participants`: the set of routers that
/// advertise participation in `algo` via the SR-Algorithm TLV in their
/// E-Router-LSA (the per-router SR-info LSA at `SR_INFO_LSID`).
fn flex_algo_participants_v3(area: &OspfArea<Ospfv3>, algo: u8) -> BTreeSet<Ipv4Addr> {
    use crate::ospf::lsdb::OSPF_MAX_AGE;
    use ospf_packet::{OSPFV3_E_ROUTER_LSA_TYPE, Ospfv3ExtTlv, Ospfv3LsBody};

    let mut set = BTreeSet::new();
    for (_, lsa) in area.lsdb.iter_by_raw_type(OSPFV3_E_ROUTER_LSA_TYPE) {
        if lsa.data.h.ls_age >= OSPF_MAX_AGE {
            continue;
        }
        let Ospfv3LsBody::ERouter(ref body) = lsa.data.body else {
            continue;
        };
        let participates = body.tlvs.iter().any(|tlv| {
            matches!(tlv, Ospfv3ExtTlv::SrAlgorithm(a) if a.algos.contains(&Algo::FlexAlgo(algo)))
        });
        if participates {
            set.insert(lsa.data.h.advertising_router);
        }
    }
    set
}

/// OSPFv3 analog of `flex_algo_link_affinity`: per-link affinity
/// (Extended Admin Group) advertised in this area's E-Router-LSA
/// Router-Link TLVs via the flex-algo ASLA sub-TLV, keyed by
/// `(adv_router, interface_id)` so a standard Router-LSA link can be
/// joined to its affinity during graph build.
///
/// Unlike v2 (where the affinity rides a separate Extended-Link Opaque
/// LSA keyed by link_id/link_data), OSPFv3 carries the ASLA on the
/// E-Router-LSA Router-Link TLV, whose `interface_id` matches the
/// owning router's standard Router-LSA link `interface_id`.
fn flex_algo_link_affinity_v3(area: &OspfArea<Ospfv3>) -> BTreeMap<(Ipv4Addr, u32), ExtAdminGroup> {
    use crate::ospf::lsdb::OSPF_MAX_AGE;
    use ospf_packet::{OSPFV3_E_ROUTER_LSA_TYPE, Ospfv3ExtTlv, Ospfv3LsBody, Ospfv3SubTlv};

    let mut map = BTreeMap::new();
    for (_, lsa) in area.lsdb.iter_by_raw_type(OSPFV3_E_ROUTER_LSA_TYPE) {
        if lsa.data.h.ls_age >= OSPF_MAX_AGE {
            continue;
        }
        let Ospfv3LsBody::ERouter(ref body) = lsa.data.body else {
            continue;
        };
        let adv_router = lsa.data.h.advertising_router;
        for tlv in &body.tlvs {
            let Ospfv3ExtTlv::RouterLink(rl) = tlv else {
                continue;
            };
            for sub in &rl.subs {
                if let Ospfv3SubTlv::Asla(asla) = sub
                    && asla.is_flex_algo()
                    && let Some(group) = asla.ext_admin_group()
                {
                    map.insert((adv_router, rl.link.interface_id), group.clone());
                }
            }
        }
    }
    map
}

/// Build the per-algo OSPFv3 SPF graph for `area_id`. Mirrors
/// `graph_v3` but (a) includes only routers participating in `algo`
/// (plus self), and (b) admits each Router-LSA link only if it passes
/// the FAD constraints in `entry` (RFC 9350 §7), the link's affinity
/// coming from the E-Router-LSA ASLA join table. Same deferrals as the
/// v2 `graph_flex_algo` (local FAD config, IGP metric, no SRLG/TI-LFA).
fn graph_v3_flex_algo(
    top: &mut Ospf<Ospfv3>,
    area_id: Ipv4Addr,
    algo: u8,
    entry: &crate::flex_algo::FlexAlgoEntry,
) -> (spf::Graph, Option<usize>) {
    use crate::ospf::lsdb::OSPF_MAX_AGE;
    use ospf_packet::{
        OSPFV3_NETWORK_LSA_TYPE, OSPFV3_ROUTER_LSA_TYPE, Ospfv3LsBody, Ospfv3RouterLinkType,
    };

    let mut graph = spf::Graph::new();
    let mut source_node = None;

    let Some(area) = top.areas.get(area_id) else {
        return (graph, source_node);
    };

    let participants = flex_algo_participants_v3(area, algo);
    let link_affinity = flex_algo_link_affinity_v3(area);

    // Router-LSAs of participating routers (self always kept — it is
    // the SPF source).
    let mut router_lsas = Vec::new();
    for ((_ls_id, adv_router), lsa) in area.lsdb.iter_by_raw_type(OSPFV3_ROUTER_LSA_TYPE) {
        if lsa.data.h.ls_age >= OSPF_MAX_AGE {
            continue;
        }
        if !lsa.originated && !participants.contains(&adv_router) {
            continue;
        }
        router_lsas.push((adv_router, lsa.originated, lsa.data.clone()));
    }

    let mut router_lsa_by_id: HashMap<Ipv4Addr, &ospf_packet::Ospfv3RouterLsa> = HashMap::new();
    for (adv_router, _, lsa_data) in &router_lsas {
        if let Ospfv3LsBody::Router(ref router_body) = lsa_data.body {
            router_lsa_by_id.insert(*adv_router, router_body);
        }
    }

    let mut network_lsas: HashMap<(u32, Ipv4Addr), Vec<Ipv4Addr>> = HashMap::new();
    for ((ls_id, adv_router), lsa) in area.lsdb.iter_by_raw_type(OSPFV3_NETWORK_LSA_TYPE) {
        if lsa.data.h.ls_age >= OSPF_MAX_AGE {
            continue;
        }
        if let Ospfv3LsBody::Network(ref net_body) = lsa.data.body {
            network_lsas.insert((ls_id, adv_router), net_body.attached_routers.clone());
        }
    }

    for (adv_router, originated, lsa_data) in &router_lsas {
        let node_id = top.lsp_map.get(*adv_router);
        if *originated {
            source_node = Some(node_id);
        }
        let mut vertex = spf::Vertex {
            id: node_id,
            name: adv_router.to_string(),
            sys_id: adv_router.to_string(),
            ..Default::default()
        };

        if let Ospfv3LsBody::Router(ref router_body) = lsa_data.body {
            for link in &router_body.links {
                // FAD admissibility for the owning router's link. A
                // link with no advertised ASLA resolves to `None` =
                // empty bitmap (rejected by include-any, passed by
                // exclude-only), per RFC 9350 §7.
                let affinity = link_affinity.get(&(*adv_router, link.interface_id));
                if !crate::flex_algo::link_passes_fad(affinity, entry, &top.affinity_map) {
                    continue;
                }
                match link.link_type {
                    Ospfv3RouterLinkType::PointToPoint | Ospfv3RouterLinkType::VirtualLink => {
                        if !participants.contains(&link.neighbor_router_id) {
                            continue;
                        }
                        let Some(peer_lsa) = router_lsa_by_id.get(&link.neighbor_router_id) else {
                            continue;
                        };
                        let has_backlink = peer_lsa.links.iter().any(|l| {
                            matches!(
                                l.link_type,
                                Ospfv3RouterLinkType::PointToPoint
                                    | Ospfv3RouterLinkType::VirtualLink
                            ) && l.neighbor_router_id == *adv_router
                        });
                        if !has_backlink {
                            continue;
                        }
                        let to_id = top.lsp_map.get(link.neighbor_router_id);
                        vertex.olinks.push(spf::Link {
                            from: node_id,
                            to: to_id,
                            cost: link.metric as u32,
                            link_id: 0,
                        });
                    }
                    Ospfv3RouterLinkType::Transit => {
                        let net_key = (link.neighbor_interface_id, link.neighbor_router_id);
                        let Some(attached) = network_lsas.get(&net_key) else {
                            continue;
                        };
                        if !attached.iter().any(|r| r == adv_router) {
                            continue;
                        }
                        for peer in attached {
                            if peer == adv_router {
                                continue;
                            }
                            if !participants.contains(peer) {
                                continue;
                            }
                            let to_id = top.lsp_map.get(*peer);
                            vertex.olinks.push(spf::Link {
                                from: node_id,
                                to: to_id,
                                cost: link.metric as u32,
                                link_id: 0,
                            });
                        }
                    }
                }
            }
        }

        graph.insert(node_id, vertex);
    }

    (graph, source_node)
}

/// Reconstruct an `Ipv6Net` from the v3 wire-format prefix bytes.
/// RFC 5340 §A.4.10 packs the address into `ceil(prefix_length / 8)`
/// octets at the front, padded out to a 32-bit boundary by the
/// codec. To get back to a regular `Ipv6Addr`, pad the bytes back
/// to 16 with trailing zeros.
fn ospfv3_prefix_to_ipv6net(prefix_length: u8, address_prefix: &[u8]) -> Option<ipnet::Ipv6Net> {
    if prefix_length > 128 {
        return None;
    }
    let mut bytes = [0u8; 16];
    let n = address_prefix.len().min(16);
    bytes[..n].copy_from_slice(&address_prefix[..n]);
    let addr = std::net::Ipv6Addr::from(bytes);
    ipnet::Ipv6Net::new(addr, prefix_length)
        .ok()
        .map(|n| n.trunc())
}

/// Main-task wrapper mirroring v2's `build_spf_input`. Assembles
/// the v3 SPF graph from the area's LSDB and resolves the local
/// vertex. Returns `None` when the source Router-LSA hasn't been
/// originated yet — nothing to compute.
fn build_v3_spf_input(top: &mut Ospf<Ospfv3>, area_id: Ipv4Addr) -> Option<SpfInput> {
    let (graph, source_node) = graph_v3(top, area_id);
    let source = source_node?;

    // Snapshot the configured algos so the per-algo graph build can
    // take `&mut top` without holding a borrow on `top.flex_algo`
    // (mirrors v2's `build_spf_input`).
    let algos: Vec<(u8, crate::flex_algo::FlexAlgoEntry)> = top
        .flex_algo
        .config
        .iter()
        .map(|(algo, entry)| (*algo, entry.clone()))
        .collect();
    let flex_algos = algos
        .iter()
        .map(|(algo, entry)| {
            let (graph, source) = graph_v3_flex_algo(top, area_id, *algo, entry);
            FlexAlgoSpfInput {
                algo: *algo,
                graph,
                source,
            }
        })
        .collect();

    Some(SpfInput {
        area_id,
        graph,
        source,
        ti_lfa_enabled: top.ti_lfa_enabled,
        tilfa_mode: top
            .ti_lfa_compute_mode
            .with_shards(top.ti_lfa_compute_shards),
        flex_algos,
    })
}

/// Main-task wrapper mirroring v2's `apply_spf_result`. Stamps
/// telemetry, runs the Intra-Area-Prefix-LSA walk to push v6
/// routes into the system RIB, then stashes the SPF result and
/// graph on the instance.
fn apply_v3_spf_result(top: &mut Ospf<Ospfv3>, output: SpfOutput) {
    let SpfOutput {
        area_id,
        graph,
        source,
        spf_result,
        tilfa_result,
        tilfa_stats,
        duration,
        last,
        flex_algos,
    } = output;
    top.spf_duration = Some(duration);
    top.spf_last = Some(last);
    top.tilfa_stats = tilfa_stats;
    ospf_event_trace!(
        top.tracing,
        Spf,
        area = %area_id,
        duration_us = duration.as_micros() as u64,
        "SPF calculation complete"
    );

    // Per-algo IPv6 RIBs from the per-algo SPF results (top borrowed
    // immutably, so collect locally then swap the field). Single
    // (last-computed-area) snapshot, like `spf_result` — fine for the
    // common single-area flex-algo deployment. Mirror of v2's
    // apply_spf_result. Built BEFORE apply_routing_updates_v3 so the
    // ILM merge there can read `top.rib6_flex_algo`.
    let mut rib6_flex_algo = BTreeMap::new();
    for o in &flex_algos {
        let algo_rib = match &o.spf_result {
            Some(spf_res) => build_rib6_from_flex_algo(top, area_id, o.algo, spf_res),
            None => PrefixMap::new(),
        };
        rib6_flex_algo.insert(o.algo, algo_rib);
    }
    top.rib6_flex_algo = rib6_flex_algo;

    // Build this area's route slice, attach Prefix-SIDs, store it,
    // and merge all attached areas' slices into the instance RIB —
    // mirroring v2's apply_spf_result. The per-area slices and SPF
    // results also feed the ABR Inter-Area-Prefix/-Router origination
    // below.
    let mut area_rib = build_rib6_from_spf(top, area_id, source, &spf_result, &tilfa_result);
    add_prefix_sids_v3(top, area_id, &mut area_rib);
    top.rib6_areas.insert(area_id, area_rib);
    top.spf_results.insert(area_id, spf_result.clone());
    let merged = merge_area_ribs6(top);
    apply_routing_updates_v3(top, merged);

    top.spf_result = Some(spf_result);
    top.graph = Some(graph);
    top.tilfa_result = Some(tilfa_result);

    // RFC 2328 §12.4.3 (RFC 5340 §4.4.3.4): reconcile the ABR
    // Inter-Area-Prefix and Inter-Area-Router LSAs after the route
    // slices moved. Diff-gated — a converged topology re-floods
    // nothing.
    top.abr_summary_originate_v3();
    top.abr_summary_asbr_originate_v3();

    // Per-algo SPF trees, for `show ospfv3 flex-algo`.
    top.spf_flex_algo = flex_algos
        .into_iter()
        .map(|o| (o.algo, o.spf_result))
        .collect();
}

/// Build a `PrefixMap<Ipv6Net, SpfRouteV3>` from the area's
/// Intra-Area-Prefix-LSAs + the SPF result, per RFC 5340 §3.8.1.
///
/// For each non-MaxAge Intra-Area-Prefix-LSA:
///   - referenced router is reachable via SPF (`ref_vertex != source`):
///     cost = `ref_path.cost + prefix.metric`, nexthops resolved from
///     the path's `first_hop_links`.
///   - referenced router is self (we originated the LSA): SPF cost to
///     self is 0 with no first-hops, so we synthesize. Two sub-cases:
///       * Network-LSA reference (we are the DR for the segment):
///         the prefix is on the segment whose Network-LSA we own.
///         cost = our link's `output_cost + prefix.metric`; nexthop
///         is directly attached via that link (mirrors how a peer-DR
///         peer's LSA installs the same prefix at the same cost).
///       * Router-LSA reference (stub on one of our links): cost =
///         `prefix.metric` (== the link's `output_cost` we stamp in
///         at origination); nexthop directly attached via the link
///         whose `link.addr` matches the prefix.
///
/// The self-case install matches the strict RFC §16.1.1 / §3.8.1
/// procedure — every Intra-Area-Prefix-LSA contributes, including
/// our own. The FIB picks between this OSPF route (admin distance
/// 110) and the kernel's connected route (0), so the connected
/// route always wins for the directly-attached prefix; the OSPF
/// route table still shows the prefix for `show ospfv3 route`
/// symmetry across DR-role flips.
fn build_rib6_from_spf(
    top: &Ospf<Ospfv3>,
    area_id: Ipv4Addr,
    source: usize,
    spf_result: &BTreeMap<usize, spf::Path>,
    tilfa_result: &BTreeMap<usize, Vec<spf::RepairPath>>,
) -> PrefixMap<ipnet::Ipv6Net, SpfRouteV3> {
    use crate::ospf::lsdb::OSPF_MAX_AGE;
    use ospf_packet::{OSPFV3_INTRA_AREA_PREFIX_LSA_TYPE, OSPFV3_NETWORK_LSA_TYPE, Ospfv3LsBody};

    let mut rib = PrefixMap::<ipnet::Ipv6Net, SpfRouteV3>::new();

    let Some(area) = top.areas.get(area_id) else {
        return rib;
    };

    for (_key, lsa) in area
        .lsdb
        .iter_by_raw_type(OSPFV3_INTRA_AREA_PREFIX_LSA_TYPE)
    {
        if lsa.data.h.ls_age >= OSPF_MAX_AGE {
            continue;
        }
        let Ospfv3LsBody::IntraAreaPrefix(ref body) = lsa.data.body else {
            continue;
        };

        let Some(ref_vertex) = top.lsp_map.lookup(body.referenced_advertising_router) else {
            continue;
        };

        // Common path: referenced router is some other vertex. Pull
        // the SPF path and nexthops once for all prefixes in this LSA.
        let nonself = if ref_vertex != source {
            let Some(ref_path) = spf_result.get(&ref_vertex) else {
                continue;
            };
            let nhops = collect_v3_nexthops(top, ref_path);
            if nhops.is_empty() {
                continue;
            }
            let nhops_map: BTreeMap<std::net::Ipv6Addr, SpfNexthopV3> = nhops
                .into_iter()
                .map(|(addr, ifindex)| {
                    (
                        addr,
                        SpfNexthopV3 {
                            ifindex,
                            adjacency: false,
                            backup: None,
                        },
                    )
                })
                .collect();
            Some((ref_path.cost, nhops_map))
        } else {
            None
        };

        // Self / Network-LSA reference: the entire LSA shares one
        // local link (the one whose interface_id matches the
        // referenced LS-ID — i.e., our own segment as DR). Resolve
        // up-front so the per-prefix loop is cheap.
        let self_network_link = if ref_vertex == source
            && body.referenced_ls_type == OSPFV3_NETWORK_LSA_TYPE
        {
            top.links.values().find(|l| {
                l.enabled && l.area == area_id && l.interface_id == body.referenced_link_state_id
            })
        } else {
            None
        };

        for prefix in &body.prefixes {
            let Some(net) = ospfv3_prefix_to_ipv6net(prefix.prefix_length, &prefix.address_prefix)
            else {
                continue;
            };

            let (total_metric, nhops_map) = if let Some((cost, ref nhops)) = nonself {
                (cost.saturating_add(prefix.metric as u32), nhops.clone())
            } else if let Some(link) = self_network_link {
                // Self-DR transit-network LSA. cost is the link's
                // output_cost (RFC 5340 §3.8.1 transit-network base)
                // plus the prefix's per-entry metric (typically 0 for
                // Network-LSA-referenced prefixes, RFC 5340 §A.4.10).
                let mut nhops_map = BTreeMap::new();
                nhops_map.insert(
                    std::net::Ipv6Addr::UNSPECIFIED,
                    SpfNexthopV3 {
                        ifindex: link.index,
                        adjacency: false,
                        backup: None,
                    },
                );
                (
                    link.output_cost.saturating_add(prefix.metric as u32),
                    nhops_map,
                )
            } else {
                // Self / Router-LSA reference: stub prefix on one of
                // our links. cost = 0 (SPF to self) + prefix.metric;
                // resolve the link by matching the prefix back to
                // `link.addr` so the route renders with the right
                // ifindex.
                //
                // `link.addr` carries the kernel-reported address
                // *with host bits* (e.g. `2001:db8::1/64`), but the
                // LSA-derived `net` is truncated to the network
                // (e.g. `2001:db8::/64`) by `ospfv3_prefix_to_ipv6net`.
                // Truncate both sides or the find never matches.
                let Some(link) = top.links.values().find(|l| {
                    l.enabled && l.area == area_id && l.addr.iter().any(|a| a.prefix.trunc() == net)
                }) else {
                    continue;
                };
                let mut nhops_map = BTreeMap::new();
                nhops_map.insert(
                    std::net::Ipv6Addr::UNSPECIFIED,
                    SpfNexthopV3 {
                        ifindex: link.index,
                        adjacency: false,
                        backup: None,
                    },
                );
                (prefix.metric as u32, nhops_map)
            };

            let entry = SpfRouteV3 {
                metric: total_metric,
                path_type: RouteType::IntraArea,
                nhops: nhops_map,
                sid: None,
                prefix_sid: None,
                dest_vertex: Some(ref_vertex),
                backup_as_primary: top.fast_reroute_backup_as_primary,
            };
            rib6_insert(&mut rib, net, entry);
        }
    }

    // AS-External: walk Type-5 LSAs (incl. those translated from a
    // Type-7 by an NSSA ABR) and install via the SPF nexthop to the
    // Inter-area: walk Inter-Area-Prefix-LSAs (0x2003) an ABR
    // originated into this area and install routes through that ABR
    // (RFC 2328 §16.2 for v3). Ordered between intra-area and
    // external so `rib6_insert`'s path-type preference resolves
    // collisions per §16.4.1.
    add_inter_area_routes_v3(top, area_id, spf_result, &mut rib);

    // originating ASBR. `lsdb_as` is empty for stub / NSSA-internal
    // routers (Type-5 isn't flooded into those areas), so this is a
    // no-op there.
    add_as_external_routes_v3(top, area_id, spf_result, &mut rib);

    // RFC 3101 §2.5 (inherited by v3): Type-7 NSSA-LSAs flood with
    // area scope, so the walk reads from `area.lsdb` and resolves
    // the originator via this area's SPF. Gated on area being NSSA;
    // a no-op for Normal / Stub areas.
    if let Some(area) = top.areas.get(area_id)
        && area.area_type.is_nssa()
    {
        add_nssa_routes_v3(top, area_id, spf_result, &mut rib);
    }

    // RFC 9513 §7: SRv6 locator reachability. Locator prefixes ride
    // their own LSA (not any Intra-Area-Prefix-LSA), so without this
    // pass remote locators — and every SID carved from them — are
    // unreachable. Runs before the TI-LFA pass so locator routes
    // carry dest_vertex and pick up repair backups like any other
    // single-nexthop prefix.
    add_srv6_locator_routes_v3(top, area_id, source, spf_result, &mut rib);

    // TI-LFA second pass: stamp the post-convergence repair backup onto
    // single-primary routes (ECMP skipped — surviving legs already
    // protect). v3 sibling of the v2 second pass in `build_rib_from_spf`;
    // resolving a repair list to SR-MPLS labels needs the LSDB, so it
    // runs here on the main task rather than on the SPF worker.
    if let Some(area) = top.areas.get(area_id) {
        for (_, route) in rib.iter_mut() {
            if route.nhops.len() != 1 {
                continue;
            }
            let Some(dest) = route.dest_vertex else {
                continue;
            };
            let Some(repair) = tilfa_result.get(&dest).and_then(|paths| paths.first()) else {
                continue;
            };
            // SRv6 repair when the locator is active (RFC 9513 SID
            // list, H.Insert); SR-MPLS label stack otherwise.
            let backup = if top.srv6_active() {
                super::tilfa::build_repair_path_srv6_v3(top, area, repair)
                    .map(super::tilfa::RepairBackupV3::Srv6)
            } else {
                build_repair_path_mpls_v3(top, area, repair).map(super::tilfa::RepairBackupV3::Mpls)
            };
            let Some(backup) = backup else {
                continue;
            };
            if let Some(nhop) = route.nhops.values_mut().next() {
                nhop.backup = Some(backup);
            }
        }
    }

    rib
}

/// RFC 9513 §7: install routes toward remote SRv6 locators. Walks the
/// area's SRv6 Locator LSAs; each algo-0 intra-area Locator TLV
/// installs at `cost(advertising router) + locator metric` with the
/// same nexthops as any other prefix of that router. Self-originated
/// Locator LSAs are skipped — the local End/uN SID install already
/// covers the prefix in the FIB. Non-zero algorithms (Flex-Algo
/// SRv6) and inter-area route types are deferred per the plan.
fn add_srv6_locator_routes_v3(
    top: &Ospf<Ospfv3>,
    area_id: Ipv4Addr,
    source: usize,
    spf_result: &BTreeMap<usize, spf::Path>,
    rib: &mut PrefixMap<ipnet::Ipv6Net, SpfRouteV3>,
) {
    use crate::ospf::lsdb::OSPF_MAX_AGE;
    use ospf_packet::{OSPFV3_SRV6_LOCATOR_LSA_TYPE, Ospfv3LsBody, Ospfv3Srv6LocatorLsaTlv};

    let Some(area) = top.areas.get(area_id) else {
        return;
    };
    for (_key, lsa) in area.lsdb.iter_by_raw_type(OSPFV3_SRV6_LOCATOR_LSA_TYPE) {
        if lsa.data.h.ls_age >= OSPF_MAX_AGE {
            continue;
        }
        let Ospfv3LsBody::Srv6Locator(ref body) = lsa.data.body else {
            continue;
        };
        let Some(vertex) = top.lsp_map.lookup(lsa.data.h.advertising_router) else {
            continue;
        };
        if vertex == source {
            continue;
        }
        let Some(path) = spf_result.get(&vertex) else {
            continue;
        };
        let nhops = collect_v3_nexthops(top, path);
        if nhops.is_empty() {
            continue;
        }
        let nhops_map: BTreeMap<std::net::Ipv6Addr, SpfNexthopV3> = nhops
            .into_iter()
            .map(|(addr, ifindex)| {
                (
                    addr,
                    SpfNexthopV3 {
                        ifindex,
                        adjacency: false,
                        backup: None,
                    },
                )
            })
            .collect();

        for tlv in &body.tlvs {
            let Ospfv3Srv6LocatorLsaTlv::Locator(loc) = tlv else {
                continue;
            };
            if loc.algorithm != 0 {
                continue;
            }
            let Ok(net) = ipnet::Ipv6Net::new(loc.locator, loc.locator_length) else {
                continue;
            };
            let net = net.trunc();
            let entry = SpfRouteV3 {
                metric: path.cost.saturating_add(loc.metric),
                path_type: RouteType::IntraArea,
                nhops: nhops_map.clone(),
                sid: None,
                prefix_sid: None,
                dest_vertex: Some(vertex),
                backup_as_primary: top.fast_reroute_backup_as_primary,
            };
            rib6_insert(rib, net, entry);
        }
    }
}

/// Walk v3 Type-5 (AS-External, 0x4005) entries in `lsdb_as` and
/// install routes — v3 sibling of v2's `add_as_external_routes`,
/// modelled on `add_nssa_routes_v3`. Resolves the originating ASBR
/// (the LSA's advertising-router — for a translated Type-5, the NSSA
/// ABR) via this area's SPF.
///
/// Deferred (same incremental build-out as the v2 walker): non-zero
/// forwarding-address resolution, and the cross-area Type-4
/// Inter-Area-Router-LSA fallback for an ASBR reachable only through
/// another area. A backbone observer reaches a backbone ABR directly,
/// which is the translation case this enables.
/// Pick a stable, collision-resistant 32-bit Link-State ID for a v3
/// NSSA / AS-External LSA covering `prefix`. RFC 5340 §A.4.7 leaves the
/// ls-id opaque to the originator; the only requirement is per-LSA
/// uniqueness. A high-32-bit slice of the address collides for every
/// prefix under a common /32 (e.g. all `2001:db8::/32` networks), so
/// hash all 16 network octets plus the prefix length (FNV-1a). ls-id 0
/// is reserved for the NSSA default-LSA, so a zero result (and the
/// `::/0` default) map there; any non-default prefix that hashes to 0
/// is nudged to 1. Residual hash collisions are vanishingly unlikely
/// for a handful of redistributed prefixes; a per-prefix counter
/// allocator is the robust follow-up if dense collisions ever bite.
fn nssa_v3_ls_id(prefix: &ipnet::Ipv6Net) -> u32 {
    if prefix.prefix_len() == 0 {
        return 0;
    }
    let mut h: u32 = 0x811c_9dc5;
    for b in prefix.network().octets() {
        h ^= b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    h ^= prefix.prefix_len() as u32;
    h = h.wrapping_mul(0x0100_0193);
    if h == 0 { 1 } else { h }
}

/// Walk Inter-Area-Prefix-LSAs (0x2003) in `area_id`'s LSDB and
/// install inter-area routes per RFC 2328 §16.2 (RFC 5340 §4.8.3):
/// for each LSA whose advertising ABR is reachable via SPF, install
/// the prefix at cost SPF(ABR) + LSA.metric with the ABR's nexthops.
/// Self-originated LSAs are skipped — we are the ABR for those,
/// which is the loop-safety half of `abr_summary_originate_v3`.
fn add_inter_area_routes_v3(
    top: &Ospf<Ospfv3>,
    area_id: Ipv4Addr,
    spf_result: &BTreeMap<usize, spf::Path>,
    rib: &mut PrefixMap<ipnet::Ipv6Net, SpfRouteV3>,
) {
    use crate::ospf::lsdb::OSPF_MAX_AGE;
    use ospf_packet::{OSPFV3_INTER_AREA_PREFIX_LSA_TYPE, OSPFV3_LS_INFINITY, Ospfv3LsBody};

    let Some(area) = top.areas.get(area_id) else {
        return;
    };

    for (_key, lsa) in area
        .lsdb
        .iter_by_raw_type(OSPFV3_INTER_AREA_PREFIX_LSA_TYPE)
    {
        if lsa.data.h.ls_age >= OSPF_MAX_AGE {
            continue;
        }
        if lsa.data.h.advertising_router == top.router_id {
            continue;
        }
        let Ospfv3LsBody::InterAreaPrefix(ref body) = lsa.data.body else {
            continue;
        };
        if body.metric >= OSPFV3_LS_INFINITY {
            continue;
        }
        let Some(abr_vertex) = top.lsp_map.lookup(lsa.data.h.advertising_router) else {
            continue;
        };
        let Some(abr_path) = spf_result.get(&abr_vertex) else {
            continue;
        };
        let Some(net) = ospfv3_prefix_to_ipv6net(body.prefix_length, &body.address_prefix) else {
            continue;
        };

        let nhops = collect_v3_nexthops(top, abr_path);
        if nhops.is_empty() {
            continue;
        }
        let nhops_map: BTreeMap<std::net::Ipv6Addr, SpfNexthopV3> = nhops
            .into_iter()
            .map(|(addr, ifindex)| {
                (
                    addr,
                    SpfNexthopV3 {
                        ifindex,
                        adjacency: false,
                        backup: None,
                    },
                )
            })
            .collect();

        let entry = SpfRouteV3 {
            metric: abr_path.cost.saturating_add(body.metric),
            path_type: RouteType::InterArea,
            nhops: nhops_map,
            sid: None,
            prefix_sid: None,
            // Protect the path to the ABR.
            dest_vertex: Some(abr_vertex),
            backup_as_primary: top.fast_reroute_backup_as_primary,
        };
        rib6_insert(rib, net, entry);
    }
}

/// RFC 2328 §16.4 step 5 for v3: when an AS-External LSA's ASBR is
/// not reachable in this area's SPF (its Router-LSA is area-scoped),
/// fall back to an Inter-Area-Router-LSA (0x2004) an ABR originated
/// into this area. Returns the cheapest `(abr_vertex, abr_path,
/// cost_to_asbr)` across all advertising ABRs, or None.
fn inter_area_asbr_fallback_v3<'a>(
    top: &Ospf<Ospfv3>,
    area_id: Ipv4Addr,
    asbr_id: Ipv4Addr,
    spf_result: &'a BTreeMap<usize, spf::Path>,
) -> Option<(usize, &'a spf::Path, u32)> {
    use crate::ospf::lsdb::OSPF_MAX_AGE;
    use ospf_packet::{OSPFV3_INTER_AREA_ROUTER_LSA_TYPE, OSPFV3_LS_INFINITY, Ospfv3LsBody};

    let area = top.areas.get(area_id)?;
    let mut best: Option<(usize, &spf::Path, u32)> = None;
    for (_key, lsa) in area
        .lsdb
        .iter_by_raw_type(OSPFV3_INTER_AREA_ROUTER_LSA_TYPE)
    {
        if lsa.data.h.ls_age >= OSPF_MAX_AGE {
            continue;
        }
        if lsa.data.h.advertising_router == top.router_id {
            continue;
        }
        let Ospfv3LsBody::InterAreaRouter(ref body) = lsa.data.body else {
            continue;
        };
        if Ipv4Addr::from(body.destination_router_id) != asbr_id {
            continue;
        }
        if body.metric >= OSPFV3_LS_INFINITY {
            continue;
        }
        let Some(abr_vertex) = top.lsp_map.lookup(lsa.data.h.advertising_router) else {
            continue;
        };
        let Some(abr_path) = spf_result.get(&abr_vertex) else {
            continue;
        };
        let cost = abr_path.cost.saturating_add(body.metric);
        if best.as_ref().map(|(_, _, c)| cost < *c).unwrap_or(true) {
            best = Some((abr_vertex, abr_path, cost));
        }
    }
    best
}

fn add_as_external_routes_v3(
    top: &Ospf<Ospfv3>,
    area_id: Ipv4Addr,
    spf_result: &BTreeMap<usize, spf::Path>,
    rib: &mut PrefixMap<ipnet::Ipv6Net, SpfRouteV3>,
) {
    use crate::ospf::lsdb::OSPF_MAX_AGE;
    use ospf_packet::{
        OSPFV3_AS_EXTERNAL_FLAG_E, OSPFV3_AS_EXTERNAL_LSA_TYPE, OSPFV3_LS_INFINITY, Ospfv3LsBody,
    };

    for (_key, lsa) in top.lsdb_as.iter_by_raw_type(OSPFV3_AS_EXTERNAL_LSA_TYPE) {
        if lsa.data.h.ls_age >= OSPF_MAX_AGE {
            continue;
        }
        if lsa.data.h.advertising_router == top.router_id {
            continue;
        }
        let Ospfv3LsBody::AsExternal(ref ext) = lsa.data.body else {
            continue;
        };
        if ext.metric >= OSPFV3_LS_INFINITY {
            continue;
        }
        if ext.forwarding_address.is_some() {
            continue;
        }

        // Resolve the path to the ASBR: intra-area SPF first, else the
        // Inter-Area-Router-LSA fallback (RFC 2328 §16.4 step 5) so a
        // cross-area ASBR's externals still compute.
        let advertiser = lsa.data.h.advertising_router;
        let direct = top
            .lsp_map
            .lookup(advertiser)
            .and_then(|v| spf_result.get(&v).map(|p| (v, p, p.cost)));
        let resolved =
            direct.or_else(|| inter_area_asbr_fallback_v3(top, area_id, advertiser, spf_result));
        let Some((asbr_vertex, asbr_path, asbr_cost)) = resolved else {
            continue;
        };

        let is_e2 = (ext.flags & OSPFV3_AS_EXTERNAL_FLAG_E) != 0;
        let metric = if is_e2 {
            ext.metric
        } else {
            asbr_cost.saturating_add(ext.metric)
        };

        let Some(net) = ospfv3_prefix_to_ipv6net(ext.prefix_length, &ext.address_prefix) else {
            continue;
        };

        let nhops = collect_v3_nexthops(top, asbr_path);
        if nhops.is_empty() {
            continue;
        }
        let nhops_map: BTreeMap<std::net::Ipv6Addr, SpfNexthopV3> = nhops
            .into_iter()
            .map(|(addr, ifindex)| {
                (
                    addr,
                    SpfNexthopV3 {
                        ifindex,
                        adjacency: false,
                        backup: None,
                    },
                )
            })
            .collect();

        let entry = SpfRouteV3 {
            metric,
            path_type: RouteType::External,
            nhops: nhops_map,
            sid: None,
            prefix_sid: None,
            dest_vertex: Some(asbr_vertex),
            backup_as_primary: top.fast_reroute_backup_as_primary,
        };
        rib6_insert(rib, net, entry);
    }
}

/// Walk v3 Type-7 (NSSA-LSA, 0x2007) entries in the area LSDB and
/// install routes — RFC 3101 §2.5 mirror for v3, modelled on v2's
/// `add_nssa_routes`.
///
/// v3 differences from the v2 walker:
///   - LSDB lookup uses `iter_by_raw_type(OSPFV3_NSSA_LSA_TYPE)`
///     (v3 LS-Types are u16, not the v2 `OspfLsType` enum).
///   - Body decode is via `Ospfv3LsBody::Nssa(Ospfv3AsExternalLsa)`.
///   - Prefix comes from `(prefix_length, address_prefix)` per
///     RFC 5340 §A.4.1.1, not v2's `(netmask, ls_id)`.
///   - E-bit lives in `flags & OSPFV3_AS_EXTERNAL_FLAG_E` per
///     RFC 5340 §A.4.7.
///   - Forwarding address is `Option<Ipv6Addr>` gated by F-flag.
///   - Nexthop construction uses `collect_v3_nexthops` /
///     `SpfNexthopV3` instead of v2's `SpfNexthop`.
///
/// Skip conditions match v2:
///   - MaxAge'd or self-originated source — same hygiene.
///   - Metric == OSPFV3_LS_INFINITY — unreachable per RFC 5340 §A.4.7.
///   - Non-zero forwarding address — FA-resolution lands in a
///     follow-up symmetric with the v3 AS-External walker (none
///     exists yet) and v2's same skip.
///
/// P-bit (RFC 3101 §2.4, carried in `prefix_options`) is
/// intentionally NOT consulted here — it controls Type-7→Type-5
/// translation at the ABR, not SPF installation on the receiver.
fn add_nssa_routes_v3(
    top: &Ospf<Ospfv3>,
    area_id: Ipv4Addr,
    spf_result: &BTreeMap<usize, spf::Path>,
    rib: &mut PrefixMap<ipnet::Ipv6Net, SpfRouteV3>,
) {
    use crate::ospf::lsdb::OSPF_MAX_AGE;
    use ospf_packet::{
        OSPFV3_AS_EXTERNAL_FLAG_E, OSPFV3_LS_INFINITY, OSPFV3_NSSA_LSA_TYPE, Ospfv3LsBody,
    };

    let Some(area) = top.areas.get(area_id) else {
        return;
    };

    for (_key, lsa) in area.lsdb.iter_by_raw_type(OSPFV3_NSSA_LSA_TYPE) {
        if lsa.data.h.ls_age >= OSPF_MAX_AGE {
            continue;
        }
        if lsa.data.h.advertising_router == top.router_id {
            continue;
        }
        let Ospfv3LsBody::Nssa(ref ext) = lsa.data.body else {
            continue;
        };
        if ext.metric >= OSPFV3_LS_INFINITY {
            continue;
        }
        // RFC 3101 §2.5 step 5: non-zero FA resolves the route via
        // an intra-area path to the FA, not to the originator. The
        // resolver lands in a follow-up (same shape as v2 and the
        // not-yet-written v3 AS-External walker).
        if ext.forwarding_address.is_some() {
            continue;
        }

        let Some(originator_vertex) = top.lsp_map.lookup(lsa.data.h.advertising_router) else {
            continue;
        };
        let Some(originator_path) = spf_result.get(&originator_vertex) else {
            continue;
        };

        let is_e2 = (ext.flags & OSPFV3_AS_EXTERNAL_FLAG_E) != 0;
        let metric = if is_e2 {
            ext.metric
        } else {
            originator_path.cost.saturating_add(ext.metric)
        };

        let Some(net) = ospfv3_prefix_to_ipv6net(ext.prefix_length, &ext.address_prefix) else {
            continue;
        };

        let nhops = collect_v3_nexthops(top, originator_path);
        if nhops.is_empty() {
            continue;
        }
        let nhops_map: BTreeMap<std::net::Ipv6Addr, SpfNexthopV3> = nhops
            .into_iter()
            .map(|(addr, ifindex)| {
                (
                    addr,
                    SpfNexthopV3 {
                        ifindex,
                        adjacency: false,
                        backup: None,
                    },
                )
            })
            .collect();

        let entry = SpfRouteV3 {
            metric,
            path_type: RouteType::External,
            nhops: nhops_map,
            sid: None,
            prefix_sid: None,
            // Protect the path to the NSSA originator (ASBR).
            dest_vertex: Some(originator_vertex),
            backup_as_primary: top.fast_reroute_backup_as_primary,
        };
        // Equal-cost merge — same shape as the intra-area insert
        // above in `build_rib6_from_spf`.
        rib6_insert(rib, net, entry);
    }
}

/// One v3 primary nexthop as a `NexthopUni` at `metric`, with the
/// prefix-SID label (if any) pushed as an Explicit swap. `SpfNexthopV3`
/// doesn't carry the adjacency/PHP flag in its label form yet, so we
/// always push Explicit — functionally correct (swap to same label),
/// just no PHP optimization. v3 sibling of `nhop_to_nexthop_uni`.
fn nhop_v3_to_nexthop_uni(
    addr: &std::net::Ipv6Addr,
    route: &SpfRouteV3,
    nhop: &SpfNexthopV3,
    metric: u32,
) -> rib::NexthopUni {
    let labels: Vec<rib::Label> = match route.sid {
        Some(sid) => vec![rib::Label::Explicit(sid)],
        None => vec![],
    };
    let mut uni = rib::NexthopUni::new(std::net::IpAddr::V6(*addr), metric, labels);
    uni.ifindex_origin = (nhop.ifindex != 0).then_some(nhop.ifindex);
    uni
}

/// A v3 TI-LFA repair as a backup `NexthopUni`: the repair's v6
/// link-local, the resolved SR-MPLS label stack, and the egress
/// ifindex, at `metric`. v3 sibling of `backup_to_nexthop_uni`.
fn backup_v3_to_nexthop_uni(backup: &super::tilfa::RepairBackupV3, metric: u32) -> rib::NexthopUni {
    use super::tilfa::RepairBackupV3;
    match backup {
        RepairBackupV3::Mpls(b) => {
            let mut uni =
                rib::NexthopUni::new(std::net::IpAddr::V6(b.addr), metric, b.labels.clone());
            uni.ifindex_origin = (b.ifindex != 0).then_some(b.ifindex);
            uni
        }
        RepairBackupV3::Srv6(b) => {
            let mut uni = rib::NexthopUni::new(std::net::IpAddr::V6(b.addr), metric, vec![]);
            uni.ifindex_origin = (b.ifindex != 0).then_some(b.ifindex);
            uni.segs = b.segs.clone();
            uni.encap_type = Some(b.encap);
            uni
        }
    }
}

/// Build a `rib::entry::RibEntry` from a `SpfRouteV3`. Flattens the
/// primaries and (when present) their TI-LFA repair backups into one
/// Vec at distinct metrics; `build_rib_nexthop` groups by metric and
/// dispatches Uni / Multi / Protect. Mirrors v2's `make_rib_entry`.
fn make_rib6_entry(route: &SpfRouteV3) -> rib::entry::RibEntry {
    let offset_metric = route.metric.saturating_add(BACKUP_METRIC_OFFSET);
    let (primary_metric, backup_metric) = if route.backup_as_primary {
        (offset_metric, route.metric)
    } else {
        (route.metric, offset_metric)
    };
    let nhops: Vec<rib::NexthopUni> = route
        .nhops
        .iter()
        .flat_map(|(addr, nhop)| {
            let primary = nhop_v3_to_nexthop_uni(addr, route, nhop, primary_metric);
            let backup = nhop
                .backup
                .as_ref()
                .map(|b| backup_v3_to_nexthop_uni(b, backup_metric));
            std::iter::once(primary).chain(backup)
        })
        .collect();

    let mut rib_entry = rib::entry::RibEntry::new(RibType::Ospf);
    rib_entry.distance = 110;
    rib_entry.metric = route.metric;
    rib_entry.nexthop = build_rib_nexthop(nhops);
    rib_entry
}

/// Walk every area's E-Intra-Area-Prefix-LSAs (RFC 8362 §3.7) and
/// attach each advertised Prefix-SID (RFC 8666 §5) to the matching
/// route already in `rib`. Mirrors v2's `add_prefix_sids`.
///
/// For Index-form SIDs we resolve to the absolute label via the
/// advertising router's SRGB (`Lsdb::label_map`, populated from
/// Router Information LSAs); Label-form SIDs are stored verbatim.
/// MaxAge'd LSAs are skipped. Self-originated LSAs are skipped --
/// pushing a label onto our own loopback /128 route is nonsensical
/// (mirrors the v2 add_prefix_sids self-skip).
///
/// Data-population only; no FIB change here. The MPLS install lands
/// in the D4b follow-up.
fn add_prefix_sids_v3(
    top: &Ospf<Ospfv3>,
    area_id: Ipv4Addr,
    rib: &mut PrefixMap<ipnet::Ipv6Net, SpfRouteV3>,
) {
    use ipnet::Ipv6Net;
    use ospf_packet::{
        OSPFV3_E_INTRA_AREA_PREFIX_LSA_TYPE, Ospfv3ExtTlv, Ospfv3LsBody, Ospfv3SubTlv,
        ospfv3_prefix_wire_len,
    };

    use crate::ospf::lsdb::OSPF_MAX_AGE;

    // SR-MPLS participation is a local choice: with `segment-routing
    // mpls` removed, no label may be imposed and no ILM derived, even
    // though peers' E-LSAs stay in the LSDB. Without this gate a
    // disable kept every remote node-SID swap entry in the LFIB
    // (`build_ilm_from_rib6` reads `route.sid` stamped here) — only
    // the self pop entries went away with the flushed self E-LSAs.
    if top.segment_routing != super::srmpls::SegmentRoutingMode::Mpls {
        return;
    }

    let Some(area) = top.areas.get(area_id) else {
        return;
    };

    for ((_ls_id, adv_router), lsa) in area
        .lsdb
        .iter_by_raw_type(OSPFV3_E_INTRA_AREA_PREFIX_LSA_TYPE)
    {
        if lsa.data.h.ls_age >= OSPF_MAX_AGE {
            continue;
        }
        if lsa.data.h.advertising_router == top.router_id {
            continue;
        }
        let Ospfv3LsBody::EIntraAreaPrefix(ref body) = lsa.data.body else {
            continue;
        };
        let Some(label_config) = area.lsdb.label_map.get(&adv_router) else {
            // No SRGB known for this advertiser yet -- the matching
            // Router Information LSA has not arrived (or carried no
            // SidLabelRange). Index-form Prefix-SIDs would be
            // unresolvable; Label-form would still work, but skipping
            // here matches the v2 behavior of waiting for the SRGB.
            continue;
        };
        for tlv in &body.tlvs {
            let Ospfv3ExtTlv::IntraAreaPrefix(prefix_tlv) = tlv else {
                continue;
            };
            // Reconstruct the IPv6 prefix from the wire bytes. The
            // address_prefix vec is padded to a 4-byte boundary per
            // RFC 5340 §A.4.1.1; rebuild a 16-byte buffer for
            // `Ipv6Addr::from`.
            let wire_len = ospfv3_prefix_wire_len(prefix_tlv.prefix_length);
            if prefix_tlv.address_prefix.len() < wire_len {
                continue;
            }
            let mut bytes = [0u8; 16];
            let copy = wire_len.min(16);
            bytes[..copy].copy_from_slice(&prefix_tlv.address_prefix[..copy]);
            let addr = std::net::Ipv6Addr::from(bytes);
            let Ok(prefix) = Ipv6Net::new(addr, prefix_tlv.prefix_length) else {
                continue;
            };
            let prefix = prefix.trunc();
            let Some(route) = rib.get_mut(&prefix) else {
                continue;
            };
            for sub in &prefix_tlv.subs {
                let Ospfv3SubTlv::PrefixSid(ps) = sub else {
                    continue;
                };
                // `Ospfv3PrefixSidSubTlv::sid` is a `SidLabelTlv`
                // (the wire-side enum from `packet_utils`); the
                // `SpfRouteV3::prefix_sid` field carries the
                // protocol-neutral `SidLabelValue`. Same trivial
                // conversion v2's add_prefix_sids does.
                let (value, sid_label) = match ps.sid {
                    SidLabelTlv::Label(v) => (SidLabelValue::Label(v), Some(v)),
                    SidLabelTlv::Index(v) => (
                        SidLabelValue::Index(v),
                        label_config.global.start.checked_add(v),
                    ),
                };
                route.prefix_sid = Some((value, label_config.clone()));
                route.sid = sid_label;
                break;
            }
        }
    }
}

/// Merge the per-area v6 route slices into one instance RIB —
/// v3 sibling of `merge_area_ribs`. Slices of areas with no
/// enabled links are skipped (stale after an area teardown);
/// cross-area collisions resolve via `rib6_insert` (§16.4.1
/// path-type preference, then metric, then ECMP merge).
fn merge_area_ribs6(top: &Ospf<Ospfv3>) -> PrefixMap<ipnet::Ipv6Net, SpfRouteV3> {
    let mut merged = PrefixMap::<ipnet::Ipv6Net, SpfRouteV3>::new();
    for (area_id, rib) in &top.rib6_areas {
        match top.areas.get(*area_id) {
            Some(area) if !area.links.is_empty() => {}
            _ => continue,
        }
        for (prefix, route) in rib.iter() {
            rib6_insert(&mut merged, prefix, route.clone());
        }
    }
    merged
}

/// Diff the freshly-built v3 RIB against the prior snapshot and
/// emit `Ipv6Del` for prefixes only in the old, `Ipv6Add` for
/// prefixes new or changed. Replaces `top.rib6` with `new_rib`
/// so the next SPF run diffs against this new baseline.
fn apply_routing_updates_v3(
    top: &mut Ospf<Ospfv3>,
    new_rib: PrefixMap<ipnet::Ipv6Net, SpfRouteV3>,
) {
    // SR-MPLS LFIB shadow: build a fresh ILM from labeled routes in
    // the new RIB, diff against `top.ilm6`, emit IlmAdd / IlmDel so
    // the kernel MPLS table tracks our SR-MPLS state. Self-Prefix-SID
    // pop and self-Adj-SID / LAN-Adj-SID pop entries are layered in
    // here, mirroring the v2 ordering.
    let mut new_ilm = build_ilm_from_rib6(&new_rib);
    // Per-Flexible-Algorithm Prefix-SID labels (RFC 9350 §7). The label
    // space is shared with algo-0 (Prefix-SIDs are globally unique), so
    // the per-algo entries coexist in the single ILM map and install
    // into the kernel MPLS LFIB alongside algo-0 via the same diff
    // below. Per-algo IPv6 stays in-memory; only the labels forward,
    // mirroring v2 / IS-IS. `top.rib6_flex_algo` was populated by
    // `apply_v3_spf_result` before this call.
    for algo_rib in top.rib6_flex_algo.values() {
        for (label, spf_ilm) in build_ilm_from_rib6(algo_rib) {
            new_ilm.insert(label, spf_ilm);
        }
    }
    add_self_prefix_sids_to_ilm_v3(top, &mut new_ilm);
    add_self_adj_sids_to_ilm_v3(top, &mut new_ilm);
    let ilm_diff = spf::table_diff(
        top.ilm6.iter().map(|(&k, v)| (k, v)),
        new_ilm.iter().map(|(&k, v)| (k, v)),
    );
    diff_ilm_apply_v6(&top.ctx.rib, &ilm_diff);
    top.ilm6 = new_ilm;

    let diff = spf::table_diff(top.rib6.iter(), new_rib.iter());

    // Withdrawals: always fire, even for an empty-nexthop cached route.
    for (prefix, route) in diff.only_curr.iter() {
        let entry = make_rib6_entry(route);
        let _ = top.ctx.rib.send(rib::Message::Ipv6Del {
            prefix: *prefix,
            rib: entry,
        });
    }
    // Changed: a route that lost all nexthops collapses to a withdrawal.
    for (prefix, _, route) in diff.different.iter() {
        let entry = make_rib6_entry(route);
        let msg = if route.nhops.is_empty() {
            rib::Message::Ipv6Del {
                prefix: *prefix,
                rib: entry,
            }
        } else {
            rib::Message::Ipv6Add {
                prefix: *prefix,
                rib: entry,
            }
        };
        let _ = top.ctx.rib.send(msg);
    }
    // New: nothing to install without nexthops.
    for (prefix, route) in diff.only_next.iter() {
        if !route.nhops.is_empty() {
            let entry = make_rib6_entry(route);
            let _ = top.ctx.rib.send(rib::Message::Ipv6Add {
                prefix: *prefix,
                rib: entry,
            });
        }
    }

    top.rib6 = new_rib;
}

/// Resolve a v3 SPF path's first-hop set to a `Vec<(Ipv6Addr,
/// ifindex)>` by reverse-mapping each first-hop vertex back to its
/// router-id and looking that router-id up as a neighbor on any of
/// our links. Skips first-hops that don't correspond to a known
/// neighbor (defensive — SPF only relaxes through Router-LSA links,
/// so the absence is rare).
fn collect_v3_nexthops(top: &Ospf<Ospfv3>, path: &spf::Path) -> Vec<(std::net::Ipv6Addr, u32)> {
    let mut out = Vec::new();
    for (hop_vertex, _link_id) in path.first_hop_links.iter() {
        let Some(hop_router_id) = top.lsp_map.resolve(*hop_vertex).copied() else {
            continue;
        };
        for link in top.links.values() {
            if let Some(nbr) = link.nbrs.get(&hop_router_id) {
                let ll = nbr.ident.prefix.addr();
                if !ll.is_unspecified() {
                    out.push((ll, nbr.ifindex));
                }
                break;
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Owned, `Send`-able inputs to a single v2 SPF run for one area.
///
/// Built on the main task by [`build_spf_input`] (which reads the
/// LSDB to assemble the graph); the resulting value carries no
/// borrow on `Ospf`, so [`compute_spf`] can in a follow-up patch be
/// dispatched onto `tokio::task::spawn_blocking`.
struct SpfInput {
    area_id: Ipv4Addr,
    graph: spf::Graph,
    source: usize,
    /// `/router/ospf/fast-reroute/ti-lfa` snapshot. Gates the
    /// graph-only TI-LFA repair computation on the worker.
    ti_lfa_enabled: bool,
    /// TI-LFA compute scheduling (`compute-mode` + the nested sharding
    /// `shards` count joined), snapshotted from config at build time so
    /// a mid-run change cleanly applies to the next run.
    tilfa_mode: spf::TilfaComputeMode,
    /// One per configured Flex-Algorithm: its FAD-filtered graph and
    /// source vertex (None if the algo's graph had no source).
    flex_algos: Vec<FlexAlgoSpfInput>,
}

struct FlexAlgoSpfInput {
    algo: u8,
    graph: spf::Graph,
    source: Option<usize>,
}

/// Result of a single v2 SPF run, ready to be applied back to
/// `Ospf` by [`apply_spf_result`] on the main task. Public because
/// it is carried by the `Message::SpfDone` variant.
pub struct SpfOutput {
    area_id: Ipv4Addr,
    graph: spf::Graph,
    source: usize,
    spf_result: BTreeMap<usize, spf::Path>,
    /// Per-destination TI-LFA repair lists (keyed by destination vertex
    /// id), computed graph-only on the worker. Empty when TI-LFA is
    /// disabled. Resolved to MPLS labels + stamped onto the RIB on the
    /// main task in `apply_spf_result`.
    tilfa_result: BTreeMap<usize, Vec<spf::RepairPath>>,
    /// TI-LFA compute telemetry, None when TI-LFA is disabled.
    /// Stamped onto `Ospf::tilfa_stats` for `show ospf` / `show
    /// ospfv3 summary`.
    tilfa_stats: Option<spf::TilfaStats>,
    duration: Duration,
    last: Instant,
    flex_algos: Vec<FlexAlgoSpfOutput>,
}

struct FlexAlgoSpfOutput {
    algo: u8,
    spf_result: Option<BTreeMap<usize, spf::Path>>,
}

/// Build the SPF graph for `area_id` and resolve the local vertex.
/// Returns `None` if the area has no source node (router-LSA for
/// self not yet originated), matching the previous early-return. Also
/// builds the per-Flex-Algorithm graphs for every configured algo.
fn build_spf_input(top: &mut Ospf, area_id: Ipv4Addr) -> Option<SpfInput> {
    let (graph, source_node) = graph(top, area_id);
    let source = source_node?;

    // Snapshot the configured algos so the per-algo graph build can
    // take `&mut top` without holding a borrow on `top.flex_algo`.
    let algos: Vec<(u8, crate::flex_algo::FlexAlgoEntry)> = top
        .flex_algo
        .config
        .iter()
        .map(|(algo, entry)| (*algo, entry.clone()))
        .collect();
    let flex_algos = algos
        .iter()
        .map(|(algo, entry)| {
            let (graph, source) = graph_flex_algo(top, area_id, *algo, entry);
            FlexAlgoSpfInput {
                algo: *algo,
                graph,
                source,
            }
        })
        .collect();

    Some(SpfInput {
        area_id,
        graph,
        source,
        ti_lfa_enabled: top.ti_lfa_enabled,
        tilfa_mode: top
            .ti_lfa_compute_mode
            .with_shards(top.ti_lfa_compute_shards),
        flex_algos,
    })
}

/// Pure compute: runs Dijkstra. Holds no reference to `Ospf` so it
/// can later move to a blocking worker without touching shared state.
fn compute_spf(input: SpfInput) -> SpfOutput {
    let SpfInput {
        area_id,
        graph,
        source,
        ti_lfa_enabled,
        tilfa_mode,
        flex_algos,
    } = input;
    let start = Instant::now();
    let spf_result = spf::spf(&graph, source, &spf::SpfOpt::default());

    // TI-LFA repair lists, graph-only. Gated on `fast-reroute ti-lfa`;
    // when off, the SPF primary RIB still installs — only the repair
    // backups are skipped. Resolution to MPLS labels happens on the
    // main task in `apply_spf_result` (it needs the LSDB).
    let (tilfa_result, tilfa_stats) = if ti_lfa_enabled {
        let (result, stats) = tilfa_repair_path(&graph, source, &spf_result, tilfa_mode);
        (result, Some(stats))
    } else {
        (BTreeMap::new(), None)
    };

    let flex_algos = flex_algos
        .into_iter()
        .map(
            |FlexAlgoSpfInput {
                 algo,
                 graph,
                 source,
             }| FlexAlgoSpfOutput {
                algo,
                spf_result: source.map(|src| spf::spf(&graph, src, &spf::SpfOpt::default())),
            },
        )
        .collect();
    let last = Instant::now();
    let duration = last.duration_since(start);
    SpfOutput {
        area_id,
        graph,
        source,
        spf_result,
        tilfa_result,
        tilfa_stats,
        duration,
        last,
        flex_algos,
    }
}

/// Apply a completed SPF run: stamp telemetry, build the area RIB
/// from the SPF tree, and push the diff into the system RIB. Must
/// run on the main task — `build_rib_from_spf` reads the LSDB and
/// `apply_routing_updates` mutates `Ospf` and emits on `ctx.rib`.
fn apply_spf_result(top: &mut Ospf, output: SpfOutput) {
    let SpfOutput {
        area_id,
        graph,
        source,
        spf_result,
        tilfa_result,
        tilfa_stats,
        duration,
        last,
        flex_algos,
    } = output;
    top.spf_duration = Some(duration);
    top.spf_last = Some(last);
    top.tilfa_stats = tilfa_stats;
    ospf_event_trace!(
        top.tracing,
        Spf,
        area = %area_id,
        duration_us = duration.as_micros() as u64,
        "SPF calculation complete"
    );

    let rib = build_rib_from_spf(top, area_id, source, &spf_result, &tilfa_result);

    // Multi-area: store this area's contribution and merge across all
    // attached areas (RFC 2328 §16.4) so an ABR's areas don't clobber
    // each other in the FIB. A single-area router merges its one slice.
    top.rib_areas.insert(area_id, rib);

    // Store the SPF result, graph, and TI-LFA repair lists on the
    // instance (single last-computed-area snapshot, like spf_result).
    // `show ospf ti-lfa` renders tilfa_result against graph.
    top.spf_results.insert(area_id, spf_result.clone());
    top.spf_result = Some(spf_result);
    top.graph = Some(graph);
    top.tilfa_result = Some(tilfa_result);

    // Build the per-algo RIBs from the per-algo SPF results (top is
    // borrowed immutably here, so collect into a local map first, then
    // swap the instance fields). Like `spf_result`, these are a single
    // (last-computed-area) snapshot — fine for the common single-area
    // flex-algo deployment.
    let mut rib_flex_algo = BTreeMap::new();
    for o in &flex_algos {
        let algo_rib = match &o.spf_result {
            Some(spf_res) => build_rib_from_flex_algo(top, area_id, o.algo, spf_res),
            None => PrefixMap::new(),
        };
        rib_flex_algo.insert(o.algo, algo_rib);
    }
    top.rib_flex_algo = rib_flex_algo;

    // Per-algo SPF trees, for `show ospf flex-algo`. Per-algo
    // Prefix-SID MPLS-ILM install is a follow-up.
    top.spf_flex_algo = flex_algos
        .into_iter()
        .map(|o| (o.algo, o.spf_result))
        .collect();

    let merged = merge_area_ribs(top);
    apply_routing_updates(top, merged);

    // ABR: (re)originate / refresh / flush Type-3 Summary LSAs from the
    // freshly merged per-area routing tables. Diff-gated and does not
    // schedule our own SPF, so a converged topology re-floods nothing
    // and this terminates rather than looping SPF→summary→SPF.
    top.abr_summary_originate();
    // ABR: (re)originate / flush Type-4 Summary-ASBR LSAs for ASBRs
    // reachable in the other area. Enables non-backbone routers to
    // compute E1 metrics to ASBRs they cannot reach intra-area.
    top.abr_summary_asbr_originate();
}

/// Merge every attached area's route slice (`rib_areas`) into one
/// routing table for the FIB. Uses `rib_insert`, so RFC 2328 §16.4
/// path-type preference (intra > inter > external) and same-type
/// ECMP apply across areas. Slices for areas we're no longer attached
/// to are skipped, so a stale snapshot can't keep a route alive.
fn merge_area_ribs(top: &Ospf) -> PrefixMap<Ipv4Net, SpfRoute> {
    let mut merged = PrefixMap::<Ipv4Net, SpfRoute>::new();
    for (area_id, rib) in &top.rib_areas {
        match top.areas.get(*area_id) {
            Some(area) if !area.links.is_empty() => {}
            _ => continue,
        }
        for (prefix, route) in rib.iter() {
            rib_insert(&mut merged, prefix, route.clone());
        }
    }
    merged
}

pub type DiffResult<'a> = spf::TableDiffResult<'a, Ipv4Net, SpfRoute>;

/// Sort offset between a primary nexthop's metric and its TI-LFA
/// backup's metric inside the rendered `Nexthop`. RIB-internal only —
/// it never reaches the wire; it just governs the metric-sort that
/// keeps the primary at `.nexthops[0]`. Mirrors IS-IS's
/// `BACKUP_METRIC_OFFSET`.
pub const BACKUP_METRIC_OFFSET: u32 = 1;

fn nhop_to_nexthop_uni(
    key: &Ipv4Addr,
    route: &SpfRoute,
    value: &SpfNexthop,
    metric: u32,
) -> rib::NexthopUni {
    let mut mpls = vec![];
    if let Some(sid) = route.sid {
        mpls.push(if value.adjacency {
            rib::Label::Implicit(sid)
        } else {
            rib::Label::Explicit(sid)
        });
    }
    let mut nhop = rib::NexthopUni::from(*key, metric, mpls);
    // OSPF, like IS-IS, learns the egress link from the adjacency
    // state machine, so record it as the origin and let the RIB
    // resolver leave it alone. 0 means "no usable adjacency ifindex"
    // — record as None so callers can detect that case.
    nhop.ifindex_origin = (value.ifindex != 0).then_some(value.ifindex);
    nhop
}

/// Render a TI-LFA repair into a backup `NexthopUni`: the repair's
/// neighbor address, the resolved SR-MPLS label stack, and the chosen
/// egress ifindex, installed at `metric` (primary.metric + offset, or
/// swapped under backup-as-primary). Mirrors IS-IS.
fn backup_to_nexthop_uni(backup: &RepairPathMpls, metric: u32) -> rib::NexthopUni {
    let mut nhop = rib::NexthopUni::new(
        std::net::IpAddr::V4(backup.addr),
        metric,
        backup.labels.clone(),
    );
    nhop.ifindex_origin = (backup.ifindex != 0).then_some(backup.ifindex);
    nhop
}

fn make_rib_entry(route: &SpfRoute) -> rib::entry::RibEntry {
    let mut rib = rib::entry::RibEntry::new(RibType::Ospf);
    rib.distance = 110;
    rib.metric = route.metric;

    // Flatten primaries and (when present) their TI-LFA repair backups
    // into one Vec at distinct metrics; `build_rib_nexthop` groups by
    // metric and dispatches Uni / Multi / Protect from there.
    //
    // `backup_as_primary` flips the offset: when set, the repair
    // installs at route.metric (sorted first) and the SPF primary at
    // route.metric + offset. The flag is read off the route (stamped at
    // build time) so the value rendered matches what `table_diff` saw.
    let offset_metric = route.metric.saturating_add(BACKUP_METRIC_OFFSET);
    let (primary_metric, backup_metric) = if route.backup_as_primary {
        (offset_metric, route.metric)
    } else {
        (route.metric, offset_metric)
    };
    let nhops: Vec<rib::NexthopUni> = route
        .nhops
        .iter()
        .flat_map(|(key, value)| {
            let primary = nhop_to_nexthop_uni(key, route, value, primary_metric);
            let backup = value
                .backup
                .as_ref()
                .map(|b| backup_to_nexthop_uni(b, backup_metric));
            std::iter::once(primary).chain(backup)
        })
        .collect();
    rib.nexthop = build_rib_nexthop(nhops);

    rib
}

// Dispatch a flat list of NexthopUni into the right rib::Nexthop
// variant. Group nhops by metric (BTreeMap iter is ascending), then:
//
//   - 0 groups          -> Nexthop::default()
//   - 1 group, 1 nhop   -> Nexthop::Uni
//   - 1 group, N nhops  -> Nexthop::Multi (ECMP)
//   - 2 groups          -> Nexthop::Protect: the lower-metric group is
//                          the primary, the offset group the TI-LFA
//                          backup.
//
// Mirrors IS-IS's `build_rib_nexthop`. With TI-LFA off every nhop sits
// at route.metric, so only the first three arms fire; a stamped backup
// adds the second metric group. The caller only ever feeds two
// distinct metrics, so >2 groups can't happen — the List fallback is
// defensive.
fn build_rib_nexthop(nhops: Vec<rib::NexthopUni>) -> rib::Nexthop {
    if nhops.is_empty() {
        return rib::Nexthop::default();
    }
    let mut groups: BTreeMap<u32, Vec<rib::NexthopUni>> = BTreeMap::new();
    for n in nhops {
        groups.entry(n.metric).or_default().push(n);
    }
    if groups.len() == 1 {
        let (metric, mut grp) = groups.into_iter().next().unwrap();
        if grp.len() == 1 {
            rib::Nexthop::Uni(grp.pop().unwrap())
        } else {
            rib::Nexthop::Multi(rib::NexthopMulti {
                metric,
                nexthops: grp,
                ..Default::default()
            })
        }
    } else {
        let mut members: Vec<_> = groups
            .into_iter()
            .map(|(metric, mut grp)| {
                if grp.len() == 1 {
                    rib::NexthopMember::Uni(grp.pop().unwrap())
                } else {
                    rib::NexthopMember::Multi(rib::NexthopMulti {
                        metric,
                        nexthops: grp,
                        ..Default::default()
                    })
                }
            })
            .collect();
        if members.len() == 2 {
            let backup = members.pop().unwrap();
            let primary = members.pop().unwrap();
            rib::Nexthop::Protect(rib::NexthopProtect {
                primary,
                backup,
                gid: 0,
            })
        } else {
            rib::Nexthop::List(rib::NexthopList { nexthops: members })
        }
    }
}

pub fn diff_apply(rib_client: &crate::rib::client::RibClient, diff: &DiffResult) {
    // Withdraw any prefix that left the table, unconditionally. `Ipv4Del`
    // is keyed on RibType, so it is a harmless no-op when nothing is
    // installed — but guarding it on `!nhops.is_empty()` would leak a
    // previously-installed FIB route whose nexthops were later cleared.
    // `build_rib_from_spf` already skips empty-nexthop destinations, so
    // this is defense-in-depth; it mirrors the IS-IS `diff_apply` fix.
    for (prefix, route) in diff.only_curr.iter() {
        let rib = make_rib_entry(route);
        let msg = rib::Message::Ipv4Del {
            prefix: *prefix,
            rib,
        };
        rib_client.send(msg).unwrap();
    }
    // Changed: a route that lost all nexthops collapses to a withdrawal
    // rather than being skipped (which would orphan the prior install).
    for (prefix, _, route) in diff.different.iter() {
        let rib = make_rib_entry(route);
        let msg = if route.nhops.is_empty() {
            rib::Message::Ipv4Del {
                prefix: *prefix,
                rib,
            }
        } else {
            rib::Message::Ipv4Add {
                prefix: *prefix,
                rib,
            }
        };
        rib_client.send(msg).unwrap();
    }
    // New: a brand-new nexthop-less prefix has nothing to install and no
    // prior FIB state to withdraw, so it is simply skipped.
    for (prefix, route) in diff.only_next.iter() {
        if !route.nhops.is_empty() {
            let rib = make_rib_entry(route);
            let msg = rib::Message::Ipv4Add {
                prefix: *prefix,
                rib,
            };
            rib_client.send(msg).unwrap();
        }
    }
}

pub type DiffIlmResult<'a> = spf::TableDiffResult<'a, u32, SpfIlm>;

/// Render an `(incoming_label, SpfIlm)` pair into the `rib::IlmEntry`
/// shape the RIB subsystem expects. Mirrors IS-IS's `make_ilm_entry`
/// in `isis/rib.rs`: an `adjacency` nexthop carries the implicit-null
/// (PHP) marker via an empty outgoing label stack; non-adjacency
/// nexthops push the incoming label as the swap label.
fn make_ilm_entry(label: u32, ilm: &SpfIlm) -> IlmEntry {
    let build_uni = |addr: &Ipv4Addr, nhop: &SpfNexthop| -> NexthopUni {
        let mut uni = NexthopUni {
            addr: std::net::IpAddr::V4(*addr),
            ifindex_origin: (nhop.ifindex != 0).then_some(nhop.ifindex),
            ..Default::default()
        };
        if !nhop.adjacency {
            uni.mpls_label.push(label);
        }
        uni
    };

    let nexthop = if ilm.nhops.len() == 1
        && let Some((addr, nhop)) = ilm.nhops.iter().next()
    {
        Nexthop::Uni(build_uni(addr, nhop))
    } else {
        let mut multi = NexthopMulti::default();
        for (addr, nhop) in ilm.nhops.iter() {
            multi.nexthops.push(build_uni(addr, nhop));
        }
        Nexthop::Multi(multi)
    };

    IlmEntry {
        ilm_type: ilm.ilm_type.clone(),
        nexthop,
        ..IlmEntry::new(RibType::Ospf)
    }
}

pub fn diff_ilm_apply(rib_client: &crate::rib::client::RibClient, diff: &DiffIlmResult) {
    // Always withdraw a label that left the table (keyed on the incoming
    // label, so the IlmDel is a no-op when nothing is installed). See
    // `diff_apply` for the empty-nexthop rationale.
    for (label, ilm) in diff.only_curr.iter() {
        let msg = rib::Message::IlmDel {
            label: *label,
            ilm: make_ilm_entry(*label, ilm),
        };
        rib_client.send(msg).unwrap();
    }
    for (label, _, ilm) in diff.different.iter() {
        let msg = if ilm.nhops.is_empty() {
            rib::Message::IlmDel {
                label: *label,
                ilm: make_ilm_entry(*label, ilm),
            }
        } else {
            rib::Message::IlmAdd {
                label: *label,
                ilm: make_ilm_entry(*label, ilm),
            }
        };
        rib_client.send(msg).unwrap();
    }
    for (label, ilm) in diff.only_next.iter() {
        if !ilm.nhops.is_empty() {
            let msg = rib::Message::IlmAdd {
                label: *label,
                ilm: make_ilm_entry(*label, ilm),
            };
            rib_client.send(msg).unwrap();
        }
    }
}

/// Walk a freshly-built IPv4 RIB and emit one ILM entry per
/// labeled prefix. The incoming-label key is the absolute label
/// (`SpfRoute::sid`), which `add_prefix_sids` already resolved
/// against the advertising router's SRGB. The `pfx_index` carried
/// on `IlmType::Node` is only used by show-side rendering; it is
/// derived from the route's `prefix_sid` so an Index-form SID
/// renders symmetrically with its on-the-wire value.
fn build_ilm_from_rib(rib: &PrefixMap<Ipv4Net, SpfRoute>) -> BTreeMap<u32, SpfIlm> {
    let mut ilm = BTreeMap::new();
    for (_prefix, route) in rib.iter() {
        let Some(label) = route.sid else {
            continue;
        };
        if route.nhops.is_empty() {
            continue;
        }
        let pfx_index = match route.prefix_sid {
            Some((SidLabelValue::Index(idx), _)) => idx,
            Some((SidLabelValue::Label(lbl), ref cfg)) => lbl.saturating_sub(cfg.global.start),
            None => 0,
        };
        ilm.insert(
            label,
            SpfIlm {
                nhops: route.nhops.clone(),
                ilm_type: IlmType::Node(pfx_index),
            },
        );
    }
    ilm
}

pub type DiffIlmResultV3<'a> = spf::TableDiffResult<'a, u32, SpfIlmV3>;

/// v3 sibling of `make_ilm_entry`. Same role -- render an
/// `(incoming_label, SpfIlmV3)` pair into the `rib::IlmEntry` shape
/// the RIB subsystem expects -- but the nexthop is v6 (matching
/// `SpfRouteV3`). No PHP optimization yet (SpfNexthopV3 doesn't
/// carry an adjacency flag); every nexthop pushes the incoming
/// label as a swap label.
fn make_ilm_entry_v6(label: u32, ilm: &SpfIlmV3) -> IlmEntry {
    let build_uni = |addr: &std::net::Ipv6Addr, nhop: &SpfNexthopV3| -> NexthopUni {
        let mut uni = NexthopUni {
            addr: std::net::IpAddr::V6(*addr),
            ifindex_origin: (nhop.ifindex != 0).then_some(nhop.ifindex),
            ..Default::default()
        };
        if !nhop.adjacency {
            uni.mpls_label.push(label);
        }
        uni
    };

    let nexthop = if ilm.nhops.len() == 1
        && let Some((addr, nhop)) = ilm.nhops.iter().next()
    {
        Nexthop::Uni(build_uni(addr, nhop))
    } else {
        let mut multi = NexthopMulti::default();
        for (addr, nhop) in ilm.nhops.iter() {
            multi.nexthops.push(build_uni(addr, nhop));
        }
        Nexthop::Multi(multi)
    };

    IlmEntry {
        ilm_type: ilm.ilm_type.clone(),
        nexthop,
        ..IlmEntry::new(RibType::Ospf)
    }
}

pub fn diff_ilm_apply_v6(rib_client: &crate::rib::client::RibClient, diff: &DiffIlmResultV3) {
    // Always withdraw a label that left the table (keyed on the incoming
    // label, so the IlmDel is a no-op when nothing is installed). See
    // `diff_apply` for the empty-nexthop rationale.
    for (label, ilm) in diff.only_curr.iter() {
        let msg = rib::Message::IlmDel {
            label: *label,
            ilm: make_ilm_entry_v6(*label, ilm),
        };
        rib_client.send(msg).unwrap();
    }
    for (label, _, ilm) in diff.different.iter() {
        let msg = if ilm.nhops.is_empty() {
            rib::Message::IlmDel {
                label: *label,
                ilm: make_ilm_entry_v6(*label, ilm),
            }
        } else {
            rib::Message::IlmAdd {
                label: *label,
                ilm: make_ilm_entry_v6(*label, ilm),
            }
        };
        rib_client.send(msg).unwrap();
    }
    for (label, ilm) in diff.only_next.iter() {
        if !ilm.nhops.is_empty() {
            let msg = rib::Message::IlmAdd {
                label: *label,
                ilm: make_ilm_entry_v6(*label, ilm),
            };
            rib_client.send(msg).unwrap();
        }
    }
}

/// v3 sibling of `build_ilm_from_rib`. Walks the freshly-built v6
/// RIB, emits one ILM entry per labeled prefix. Incoming-label key
/// is `SpfRouteV3::sid` (resolved against the advertising router's
/// SRGB by `add_prefix_sids_v3`). `IlmType::Node(pfx_index)` is
/// only used by show-side rendering; derived from `prefix_sid` so
/// an Index-form SID renders symmetrically with its on-the-wire
/// value.
fn build_ilm_from_rib6(rib: &PrefixMap<ipnet::Ipv6Net, SpfRouteV3>) -> BTreeMap<u32, SpfIlmV3> {
    let mut ilm = BTreeMap::new();
    for (_prefix, route) in rib.iter() {
        let Some(label) = route.sid else {
            continue;
        };
        if route.nhops.is_empty() {
            continue;
        }
        let pfx_index = match route.prefix_sid {
            Some((SidLabelValue::Index(idx), _)) => idx,
            Some((SidLabelValue::Label(lbl), ref cfg)) => lbl.saturating_sub(cfg.global.start),
            None => 0,
        };
        ilm.insert(
            label,
            SpfIlmV3 {
                nhops: route.nhops.clone(),
                ilm_type: IlmType::Node(pfx_index),
            },
        );
    }
    ilm
}

/// For every self-originated Extended-Prefix LSA in any area, emit
/// an ILM entry that pops the local Prefix-SID label and delivers
/// to the owning interface.
///
/// Needed because `srmpls.rs::ext_prefix_lsa_build` sets the NP
/// (No-PHP) flag on Index-form Prefix-SIDs we originate. With NP=1
/// the penultimate hop does not pop the label per RFC 8665 §5, so
/// labeled packets reach the local kernel MPLS layer and require
/// an explicit pop entry; without it the kernel drops them.
///
/// The emitted nexthop carries `adjacency: true` so `make_ilm_entry`
/// builds an `IlmEntry` with no swap label — Via + Oif only. The
/// kernel pops the label and forwards to the via address on the
/// owning interface; since the via address is one of our own
/// interface addresses, the inner packet is delivered locally.
fn add_self_prefix_sids_to_ilm(top: &Ospf, ilm: &mut BTreeMap<u32, SpfIlm>) {
    use super::srmpls::SRGB_START;
    use crate::ospf::lsdb::OSPF_MAX_AGE;

    for (area_id, area) in top.areas.iter() {
        let area_id = *area_id;
        for (_, lsa) in area.lsdb.iter_by_type(OspfLsType::OpaqueAreaLocal) {
            if lsa.data.h.ls_age >= OSPF_MAX_AGE {
                continue;
            }
            if lsa.data.h.adv_router != top.router_id {
                continue;
            }
            let OspfLsp::OpaqueAreaExtPrefix(ref ep) = lsa.data.lsp else {
                continue;
            };
            for tlv in &ep.tlvs {
                let Some(link) = self_link_by_prefix(top, area_id, tlv.prefix) else {
                    continue;
                };
                let Some(addr) = link.addr.first().map(|a| a.prefix.addr()) else {
                    continue;
                };
                for sub in &tlv.subs {
                    let ExtPrefixSubTlv::PrefixSid(ps) = sub else {
                        continue;
                    };
                    let (label, pfx_index) = match ps.sid {
                        SidLabelTlv::Label(v) => (v, v.saturating_sub(SRGB_START)),
                        SidLabelTlv::Index(idx) => match SRGB_START.checked_add(idx) {
                            Some(v) => (v, idx),
                            None => continue,
                        },
                    };
                    let mut nhops = BTreeMap::new();
                    nhops.insert(
                        addr,
                        SpfNexthop {
                            ifindex: link.index,
                            adjacency: true,
                            router_id: None,
                            backup: None,
                        },
                    );
                    ilm.insert(
                        label,
                        SpfIlm {
                            nhops,
                            ilm_type: IlmType::Node(pfx_index),
                        },
                    );
                    break;
                }
            }
        }
    }
}

/// v3 sibling of `add_self_prefix_sids_to_ilm`. Walks every area's
/// self-originated E-Intra-Area-Prefix-LSAs (LS Type 0xA029,
/// RFC 8362 §3.7) and emits an ILM entry that pops the local
/// Prefix-SID label and delivers to the owning link.
///
/// Needed because `srmpls::ext_intra_area_prefix_v3_lsa_build` sets
/// the NP (No-PHP) flag on Index-form Prefix-SIDs we originate; per
/// RFC 8666 §5 the upstream MUST NOT pop, so labeled packets reach
/// our kernel MPLS layer and require an explicit pop entry.
///
/// The emitted nexthop carries `adjacency: true` so
/// `make_ilm_entry_v6` omits the swap label -- Via + Oif only. With
/// Via set to one of our own IPv6 addresses on the owning interface
/// the kernel pops the label and routes the inner packet locally.
fn add_self_prefix_sids_to_ilm_v3(top: &Ospf<Ospfv3>, ilm: &mut BTreeMap<u32, SpfIlmV3>) {
    use ipnet::Ipv6Net;
    use ospf_packet::{
        OSPFV3_E_INTRA_AREA_PREFIX_LSA_TYPE, Ospfv3ExtTlv, Ospfv3LsBody, Ospfv3SubTlv,
        ospfv3_prefix_wire_len,
    };

    use super::srmpls::SRGB_START;
    use crate::ospf::lsdb::OSPF_MAX_AGE;

    for (area_id, area) in top.areas.iter() {
        let area_id = *area_id;
        for ((_ls_id, _adv_router), lsa) in area
            .lsdb
            .iter_by_raw_type(OSPFV3_E_INTRA_AREA_PREFIX_LSA_TYPE)
        {
            if lsa.data.h.ls_age >= OSPF_MAX_AGE {
                continue;
            }
            if lsa.data.h.advertising_router != top.router_id {
                continue;
            }
            let Ospfv3LsBody::EIntraAreaPrefix(ref body) = lsa.data.body else {
                continue;
            };
            for tlv in &body.tlvs {
                let Ospfv3ExtTlv::IntraAreaPrefix(prefix_tlv) = tlv else {
                    continue;
                };
                // Reconstruct the IPv6 prefix from the wire bytes
                // (same logic as `add_prefix_sids_v3`).
                let wire_len = ospfv3_prefix_wire_len(prefix_tlv.prefix_length);
                if prefix_tlv.address_prefix.len() < wire_len {
                    continue;
                }
                let mut bytes = [0u8; 16];
                let copy = wire_len.min(16);
                bytes[..copy].copy_from_slice(&prefix_tlv.address_prefix[..copy]);
                let addr = std::net::Ipv6Addr::from(bytes);
                let Ok(prefix) = Ipv6Net::new(addr, prefix_tlv.prefix_length) else {
                    continue;
                };
                let prefix = prefix.trunc();
                // Find the local link owning this prefix so the ILM
                // entry can name a real interface for the pop's Oif.
                let Some(link) = top.links.values().find(|l| {
                    l.enabled
                        && l.area == area_id
                        && l.addr.iter().any(|a| a.prefix.trunc() == prefix)
                }) else {
                    continue;
                };
                let Some(our_addr) = link
                    .addr
                    .iter()
                    .find(|a| a.prefix.addr().segments()[0] != 0xfe80)
                    .map(|a| a.prefix.addr())
                else {
                    continue;
                };
                for sub in &prefix_tlv.subs {
                    let Ospfv3SubTlv::PrefixSid(ps) = sub else {
                        continue;
                    };
                    let (label, pfx_index) = match ps.sid {
                        SidLabelTlv::Label(v) => (v, v.saturating_sub(SRGB_START)),
                        SidLabelTlv::Index(idx) => match SRGB_START.checked_add(idx) {
                            Some(v) => (v, idx),
                            None => continue,
                        },
                    };
                    let mut nhops = BTreeMap::new();
                    nhops.insert(
                        our_addr,
                        SpfNexthopV3 {
                            ifindex: link.index,
                            adjacency: true,
                            backup: None,
                        },
                    );
                    ilm.insert(
                        label,
                        SpfIlmV3 {
                            nhops,
                            ilm_type: IlmType::Node(pfx_index),
                        },
                    );
                    break;
                }
            }
        }
    }
}

/// v3 sibling of `add_self_adj_sids_to_ilm`. Walks every area's
/// self-originated E-Router-LSAs (LS Type 0xA021, RFC 8362 §3.2)
/// and, for each Router-Link TLV, emits an ILM entry that pops the
/// local Adjacency-SID label and forwards over the specific
/// adjacency the SID identifies (RFC 8666 §6).
///
/// `srmpls::e_router_v3_lsa_build` sets `link_state_id` to the
/// owning interface's ifindex, so the link-LSDB key maps straight
/// back to a local `OspfLink`. Each LSA carries exactly one
/// Router-Link TLV (the originator's per-link iteration); its
/// sub-TLVs are:
///   * `AdjSid` (P2P): one sub-TLV; resolve the neighbor by
///     `link.neighbor_router_id` from `link.nbrs` (v3 keys by
///     router-id, RFC 5340 §10).
///   * `LanAdjSid` (transit, broadcast/NBMA): one sub-TLV per Full
///     neighbor; each carries its own `neighbor_router_id`.
///
/// The emitted nexthop carries the neighbor's link-local IPv6 as
/// the via, the link's ifindex as the oif, and `adjacency: true`
/// so `make_ilm_entry_v6` omits the swap label -- Via + Oif only,
/// matching the implicit-null / PHP path the v3 Prefix-SID pop
/// uses.
fn add_self_adj_sids_to_ilm_v3(top: &Ospf<Ospfv3>, ilm: &mut BTreeMap<u32, SpfIlmV3>) {
    use ospf_packet::{
        OSPFV3_E_ROUTER_LSA_TYPE, Ospfv3ExtTlv, Ospfv3LsBody, Ospfv3RouterLinkType, Ospfv3SubTlv,
    };

    use super::srmpls::SRGB_START;
    use crate::ospf::lsdb::OSPF_MAX_AGE;

    // Resolve `(link, neighbor_router_id)` -> `(ifindex, link-local v6 addr)`.
    // Returns `None` when the named neighbor has aged out of `link.nbrs`
    // or carries no usable link-local address yet.
    fn resolve_nbr(
        link: &OspfLink<Ospfv3>,
        neighbor_router_id: Ipv4Addr,
    ) -> Option<(u32, std::net::Ipv6Addr)> {
        let nbr = link.nbrs.get(&neighbor_router_id)?;
        let addr = nbr.ident.prefix.addr();
        if addr.is_unspecified() {
            return None;
        }
        Some((link.index, addr))
    }

    // Install one neighbor-keyed SID. `label` is the absolute label
    // on the wire (Index→SRGB resolution for P2P, raw Label for LAN
    // since LAN-Adj-SID is always allocated out of the local SRLB).
    fn install(
        ilm: &mut BTreeMap<u32, SpfIlmV3>,
        label: u32,
        adj_index: u32,
        ifindex: u32,
        nbr_addr: std::net::Ipv6Addr,
    ) {
        let mut nhops = BTreeMap::new();
        nhops.insert(
            nbr_addr,
            SpfNexthopV3 {
                ifindex,
                adjacency: true,
                backup: None,
            },
        );
        ilm.insert(
            label,
            SpfIlmV3 {
                nhops,
                ilm_type: IlmType::Adjacency(adj_index),
            },
        );
    }

    for (_area_id, area) in top.areas.iter() {
        for ((link_state_id, _adv_router), lsa) in
            area.lsdb.iter_by_raw_type(OSPFV3_E_ROUTER_LSA_TYPE)
        {
            if lsa.data.h.ls_age >= OSPF_MAX_AGE {
                continue;
            }
            if lsa.data.h.advertising_router != top.router_id {
                continue;
            }
            let Ospfv3LsBody::ERouter(ref body) = lsa.data.body else {
                continue;
            };
            // `link_state_id` is the originating interface's ifindex
            // by construction (see `e_router_v3_lsa_build` callers).
            let Some(link) = top.links.get(&link_state_id) else {
                continue;
            };
            for tlv in &body.tlvs {
                let Ospfv3ExtTlv::RouterLink(rl) = tlv else {
                    continue;
                };
                match rl.link.link_type {
                    Ospfv3RouterLinkType::PointToPoint => {
                        let Some((ifindex, nbr_addr)) =
                            resolve_nbr(link, rl.link.neighbor_router_id)
                        else {
                            continue;
                        };
                        for sub in &rl.subs {
                            let Ospfv3SubTlv::AdjSid(adj) = sub else {
                                continue;
                            };
                            let (label, adj_index) = match adj.sid {
                                SidLabelTlv::Label(v) => (v, v.saturating_sub(SRGB_START)),
                                SidLabelTlv::Index(idx) => match SRGB_START.checked_add(idx) {
                                    Some(v) => (v, idx),
                                    None => continue,
                                },
                            };
                            install(ilm, label, adj_index, ifindex, nbr_addr);
                            break;
                        }
                    }
                    Ospfv3RouterLinkType::Transit => {
                        for sub in &rl.subs {
                            let Ospfv3SubTlv::LanAdjSid(lan) = sub else {
                                continue;
                            };
                            let Some((ifindex, nbr_addr)) =
                                resolve_nbr(link, lan.neighbor_router_id)
                            else {
                                continue;
                            };
                            let (label, adj_index) = match lan.sid {
                                SidLabelTlv::Label(v) => (v, v.saturating_sub(SRGB_START)),
                                SidLabelTlv::Index(idx) => match SRGB_START.checked_add(idx) {
                                    Some(v) => (v, idx),
                                    None => continue,
                                },
                            };
                            install(ilm, label, adj_index, ifindex, nbr_addr);
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

/// For every self-originated Extended-Link Opaque LSA, emit ILM
/// entries that pop the local Adjacency-SID label and forward over
/// the specific adjacency the SID identifies.
///
/// Per RFC 8402 §3.4.1 the Adj-SID is locally significant -- only
/// the advertiser installs forwarding state for it. The kernel-
/// level action is "pop and forward to neighbor on this link", so
/// the emitted nexthop carries the neighbor's address as the via,
/// the link's ifindex as the oif, and `adjacency: true` so
/// `make_ilm_entry` omits the swap label (Via + Oif only on the
/// wire, matching the implicit-null/PHP path the Prefix-SID pop
/// uses).
///
/// Handles both link types:
///   * link_type=1 (P2P, RFC 8665 §5): one `AdjSid` sub-TLV; the
///     TLV's `link_id` is the neighbor's router-id, used to resolve
///     the neighbor's interface address on `link.nbrs`.
///   * link_type=2 (broadcast / NBMA, RFC 8665 §6): one
///     `LanAdjSid` sub-TLV per Full neighbor; each sub-TLV carries
///     the neighbor's router-id in its `neighbor_id` field, which
///     is resolved the same way.
fn add_self_adj_sids_to_ilm(top: &Ospf, ilm: &mut BTreeMap<u32, SpfIlm>) {
    use super::srmpls::SRGB_START;
    use crate::ospf::lsdb::OSPF_MAX_AGE;

    // Resolve (link, neighbor_router_id) -> (link.index, nbr_addr).
    // Returns None when either side is missing -- the LSA may name a
    // neighbor that has already aged out of `link.nbrs`.
    fn resolve_nbr(link: &OspfLink, neighbor_router_id: Ipv4Addr) -> Option<(u32, Ipv4Addr)> {
        let addr = link
            .nbrs
            .values()
            .find(|n| n.ident.router_id == neighbor_router_id)
            .map(|n| n.ident.prefix.addr())?;
        Some((link.index, addr))
    }

    // Build the ILM entry for one neighbor-keyed SID and insert it.
    // `label_value` is the absolute label on the wire (Index→SRGB
    // resolution for P2P, raw Label for LAN since LAN-Adj-SID is
    // always allocated out of the local SRLB).
    fn install(
        ilm: &mut BTreeMap<u32, SpfIlm>,
        label: u32,
        adj_index: u32,
        ifindex: u32,
        nbr_addr: Ipv4Addr,
        neighbor_router_id: Ipv4Addr,
    ) {
        let mut nhops = BTreeMap::new();
        nhops.insert(
            nbr_addr,
            SpfNexthop {
                ifindex,
                adjacency: true,
                router_id: Some(neighbor_router_id),
                backup: None,
            },
        );
        ilm.insert(
            label,
            SpfIlm {
                nhops,
                ilm_type: IlmType::Adjacency(adj_index),
            },
        );
    }

    for (area_id, area) in top.areas.iter() {
        let area_id = *area_id;
        for (_, lsa) in area.lsdb.iter_by_type(OspfLsType::OpaqueAreaLocal) {
            if lsa.data.h.ls_age >= OSPF_MAX_AGE {
                continue;
            }
            if lsa.data.h.adv_router != top.router_id {
                continue;
            }
            let OspfLsp::OpaqueAreaExtLink(ref el) = lsa.data.lsp else {
                continue;
            };
            for tlv in &el.tlvs {
                let Some(link) = self_link_by_addr(top, area_id, tlv.link_data) else {
                    continue;
                };
                match tlv.link_type {
                    // P2P: tlv.link_id is the neighbor's router-id.
                    1 => {
                        let Some((ifindex, nbr_addr)) = resolve_nbr(link, tlv.link_id) else {
                            continue;
                        };
                        for sub in &tlv.subs {
                            let ExtLinkSubTlv::AdjSid(adj) = sub else {
                                continue;
                            };
                            let (label, adj_index) = match adj.sid {
                                SidLabelTlv::Label(v) => (v, v.saturating_sub(SRGB_START)),
                                SidLabelTlv::Index(idx) => match SRGB_START.checked_add(idx) {
                                    Some(v) => (v, idx),
                                    None => continue,
                                },
                            };
                            install(ilm, label, adj_index, ifindex, nbr_addr, tlv.link_id);
                            break;
                        }
                    }
                    // Broadcast / NBMA: one LanAdjSid sub-TLV per
                    // Full neighbor; each carries its own neighbor_id.
                    2 => {
                        for sub in &tlv.subs {
                            let ExtLinkSubTlv::LanAdjSid(lan) = sub else {
                                continue;
                            };
                            let Some((ifindex, nbr_addr)) = resolve_nbr(link, lan.neighbor_id)
                            else {
                                continue;
                            };
                            let (label, adj_index) = match lan.sid {
                                SidLabelTlv::Label(v) => (v, v.saturating_sub(SRGB_START)),
                                SidLabelTlv::Index(idx) => match SRGB_START.checked_add(idx) {
                                    Some(v) => (v, idx),
                                    None => continue,
                                },
                            };
                            install(ilm, label, adj_index, ifindex, nbr_addr, lan.neighbor_id);
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

/// Apply routing updates to RIB subsystem
fn apply_routing_updates(top: &mut Ospf, rib: PrefixMap<Ipv4Net, SpfRoute>) {
    // Build the SR-MPLS LFIB from labeled routes in the freshly
    // computed RIB, then diff against the previous snapshot so the
    // RIB subsystem sees only the IlmAdd / IlmDel deltas.
    let mut ilm = build_ilm_from_rib(&rib);
    // Per-Flexible-Algorithm Prefix-SID labels (RFC 9350 §7). The
    // label space is shared with algo-0 (Prefix-SIDs are globally
    // unique), so the per-algo entries coexist in the single ILM map
    // and install into the kernel MPLS LFIB alongside algo-0 via the
    // same diff below. Per-algo IPv4 stays in-memory; only the labels
    // forward, mirroring IS-IS.
    for algo_rib in top.rib_flex_algo.values() {
        for (label, spf_ilm) in build_ilm_from_rib(algo_rib) {
            ilm.insert(label, spf_ilm);
        }
    }
    add_self_prefix_sids_to_ilm(top, &mut ilm);
    add_self_adj_sids_to_ilm(top, &mut ilm);
    let ilm_diff = spf::table_diff(
        top.ilm.iter().map(|(&k, v)| (k, v)),
        ilm.iter().map(|(&k, v)| (k, v)),
    );
    diff_ilm_apply(&top.ctx.rib, &ilm_diff);
    top.ilm = ilm;

    // Update IPv4 RIB. Egress label imposition for labeled routes
    // is already wired through `nhop_to_nexthop_uni` reading
    // `SpfRoute::sid` -- no extra plumbing here.
    let diff = spf::table_diff(top.rib.iter(), rib.iter());
    diff_apply(&top.ctx.rib, &diff);

    top.rib = rib;
}

#[cfg(test)]
mod multi_area_tests {
    use super::{RouteType, SpfRoute, rib_insert};
    use ipnet::Ipv4Net;
    use prefix_trie::PrefixMap;
    use std::collections::BTreeMap;

    fn route(metric: u32, path_type: RouteType) -> SpfRoute {
        SpfRoute {
            metric,
            path_type,
            nhops: BTreeMap::new(),
            sid: None,
            prefix_sid: None,
            dest_vertex: None,
            backup_as_primary: false,
        }
    }

    #[test]
    fn route_type_orders_intra_before_inter_before_external() {
        assert!(RouteType::IntraArea < RouteType::InterArea);
        assert!(RouteType::InterArea < RouteType::External);
    }

    #[test]
    fn rib_insert_prefers_path_type_over_metric() {
        let p: Ipv4Net = "10.0.0.0/32".parse().unwrap();

        // A cheap inter-area route must NOT displace a costlier
        // intra-area route (RFC 2328 §16.4.1: type beats metric).
        let mut rib = PrefixMap::<Ipv4Net, SpfRoute>::new();
        rib_insert(&mut rib, p, route(100, RouteType::IntraArea));
        rib_insert(&mut rib, p, route(1, RouteType::InterArea));
        let r = rib.get(&p).unwrap();
        assert_eq!(r.path_type, RouteType::IntraArea);
        assert_eq!(r.metric, 100);

        // ...and a later intra-area route DOES displace an inter-area
        // one regardless of order.
        let mut rib = PrefixMap::<Ipv4Net, SpfRoute>::new();
        rib_insert(&mut rib, p, route(1, RouteType::InterArea));
        rib_insert(&mut rib, p, route(100, RouteType::IntraArea));
        let r = rib.get(&p).unwrap();
        assert_eq!(r.path_type, RouteType::IntraArea);
        assert_eq!(r.metric, 100);
    }

    #[test]
    fn rib_insert_same_type_lowest_metric_wins() {
        let p: Ipv4Net = "10.0.0.0/32".parse().unwrap();
        let mut rib = PrefixMap::<Ipv4Net, SpfRoute>::new();
        rib_insert(&mut rib, p, route(30, RouteType::InterArea));
        rib_insert(&mut rib, p, route(20, RouteType::InterArea));
        rib_insert(&mut rib, p, route(40, RouteType::InterArea));
        assert_eq!(rib.get(&p).unwrap().metric, 20);
    }
}

#[cfg(test)]
mod diff_apply_tests {
    use super::{RouteType, SpfNexthop, SpfRoute, diff_apply};
    use crate::rib::client::{ProtoId, RibClient};
    use crate::spf;
    use ipnet::Ipv4Net;
    use prefix_trie::PrefixMap;
    use std::collections::BTreeMap;
    use std::net::Ipv4Addr;

    fn spf_route(metric: u32, nhops: &[(&str, u32)]) -> SpfRoute {
        let mut nh = BTreeMap::new();
        for (addr, ifindex) in nhops {
            nh.insert(
                addr.parse::<Ipv4Addr>().unwrap(),
                SpfNexthop {
                    ifindex: *ifindex,
                    adjacency: false,
                    router_id: None,
                    backup: None,
                },
            );
        }
        SpfRoute {
            metric,
            path_type: RouteType::IntraArea,
            nhops: nh,
            sid: None,
            prefix_sid: None,
            dest_vertex: None,
            backup_as_primary: false,
        }
    }

    // Returns (withdrawn prefixes, installed prefixes) emitted by
    // `diff_apply` for `curr`→`next`, captured off an in-memory channel
    // so no live RIB task is needed.
    fn run_diff_apply(
        curr: &PrefixMap<Ipv4Net, SpfRoute>,
        next: &PrefixMap<Ipv4Net, SpfRoute>,
    ) -> (Vec<Ipv4Net>, Vec<Ipv4Net>) {
        let diff = spf::table_diff(curr.iter(), next.iter());
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let client = RibClient::new(tx, ProtoId::from_raw(1));
        diff_apply(&client, &diff);
        drop(client);

        let (mut dels, mut adds) = (vec![], vec![]);
        while let Ok(env) = rx.try_recv() {
            match env.msg {
                crate::rib::Message::Ipv4Del { prefix, .. } => dels.push(prefix),
                crate::rib::Message::Ipv4Add { prefix, .. } => adds.push(prefix),
                _ => panic!("unexpected message variant"),
            }
        }
        (dels, adds)
    }

    #[test]
    fn diff_apply_withdraws_empty_nexthop_route() {
        // A cached route with no nexthops must still be withdrawn when its
        // prefix leaves the table — guarding the delete on `!nhops.is_empty()`
        // would leak the kernel FIB route (the IS-IS keychain leak class).
        let prefix: Ipv4Net = "10.0.0.2/32".parse().unwrap();
        let mut curr = PrefixMap::new();
        curr.insert(prefix, spf_route(10, &[]));
        let next = PrefixMap::new();

        let (dels, adds) = run_diff_apply(&curr, &next);
        assert_eq!(dels, vec![prefix]);
        assert!(adds.is_empty());
    }

    #[test]
    fn diff_apply_collapses_emptied_route_to_del() {
        // A route that changes to a no-nexthop state (present in both
        // tables, so it lands in `different`) must collapse to a delete,
        // not be skipped and leave the stale install behind.
        let prefix: Ipv4Net = "10.0.0.2/32".parse().unwrap();
        let mut curr = PrefixMap::new();
        curr.insert(prefix, spf_route(10, &[("10.0.1.2", 2)]));
        let mut next = PrefixMap::new();
        next.insert(prefix, spf_route(20, &[]));

        let (dels, adds) = run_diff_apply(&curr, &next);
        assert_eq!(dels, vec![prefix]);
        assert!(adds.is_empty());
    }
}
