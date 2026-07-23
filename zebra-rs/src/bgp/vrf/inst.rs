//! Per-VRF BGP task — owns the runtime state for one
//! `router bgp vrf X` block.
//!
//! Mirrors the global [`crate::bgp::Bgp`] structure on a smaller
//! surface: a [`PeerMap`] for CE peers, a per-VRF [`LocalRib`]
//! for the IPv4/IPv6 unicast Loc-RIB (populated by best-path /
//! import), and the identity (`name`, `rd`, `router_id`) the
//! global task supplies at spawn time.

use std::net::Ipv4Addr;

use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use crate::config::{ConfigChannel, ShowChannel};
use crate::context::{ProtoContext, Task};
use crate::{bgp_vpn_trace, bgp_vrf_trace};

use super::super::Message;
use super::super::config::BgpRedistSource;
use super::super::interface_addrs::InterfaceAddrs;
use super::super::peer_map::PeerMap;
use super::super::route::{LocalRib, ORIGINATED_PEER};
use super::super::shard::BgpShard;
use super::super::store::BgpAttrStore;
use super::super::update_group::UpdateGroupMap;
use super::msg::{BgpGlobalMsg, BgpVrfMsg};

/// Per-VRF BGP runtime. One task per `router bgp vrf X` block.
pub struct BgpVrf {
    /// VRF name (matches the YANG list key under
    /// `/router/bgp/vrf/<name>`). Used in log lines, `show bgp vrf
    /// <name> ...` dispatch, and as the `BgpGlobalMsg::Export` /
    /// `RegisterPeer` payload so the global task can attribute
    /// cross-task messages back to a VRF.
    pub name: String,
    /// Spawn-time runtime context built via
    /// [`ProtoContext::for_vrf`]. Every socket the per-VRF runtime
    /// opens flows through `ctx.tcp_socket_v*` / `ctx.tcp_listen`
    /// and therefore inherits the `SO_BINDTODEVICE` binding.
    pub ctx: ProtoContext,
    /// Per-VRF peer table — CE peers configured under
    /// `/router/bgp/vrf/<name>/neighbor/...`.
    pub peers: PeerMap,
    /// IPv4/IPv6 unicast Loc-RIB scoped to this VRF. VPNv4/v6 /
    /// EVPN stay anchored on the global Loc-RIB; the per-VRF Loc-
    /// RIB holds only the CE-facing surface plus routes imported
    /// from the global Loc-RIB via [`BgpVrfMsg::ImportV4`].
    pub local_rib: LocalRib,
    /// Shard-scope Loc-RIB tables (unicast/LU/VPN) — the per-VRF
    /// twin of [`crate::bgp::shard::BgpShard`] on the global task.
    pub shard: BgpShard,
    /// Mirror of the instance-wide `router bgp tracing { … }` config,
    /// seeded at spawn by `spawn_bgp_vrf` and refreshed on every edit
    /// via [`BgpVrfMsg::Tracing`] (the per-VRF `ConfigChannel` never
    /// sees the instance-scoped path). Read by this task's gated trace
    /// sites — `bgp_vpn_trace!` for the import/withdraw pipeline,
    /// `bgp_vrf_trace!` for task lifecycle. There is no per-neighbor
    /// overlay here: the CE peers in a VRF are traced through the
    /// instance config only.
    pub tracing: super::super::tracing::BgpTracing,
    /// Per-VRF BGP router-id. Defaults to the global router-id at
    /// spawn time; the operator may override via
    /// `set router bgp vrf <name> router-id <addr>`, in which case
    /// the VRF is respawned with the new value.
    pub router_id: Ipv4Addr,
    /// This VRF's Route Distinguisher (`set router bgp vrf <name> rd`),
    /// or `None` if unset. The per-VRF MUP RIB is scoped to this single
    /// RD: an imported MUP route is re-keyed under the VRF's *own* RD,
    /// not the route's origin RD — the MUP analog of L3VPN dropping the
    /// VPNv4 RD on import (a VRF owns its routes under its own RD).
    /// Captured from the VRF config at spawn; an `rd` edit on a live VRF
    /// doesn't yet re-key the running task (same spawn-time-capture
    /// limitation as `router_id`).
    pub rd: Option<bgp_packet::RouteDistinguisher>,
    /// MUP `dataplane {end-dt46|gtp}` mode for this VRF, captured from the
    /// config at spawn (same spawn-time-capture as `rd`/`router_id`). `Gtp`
    /// programs GTP-U tunnels via cradle instead of the End.DT46 stand-in.
    pub dataplane: super::super::vrf_config::MupDataplane,
    /// Config-manager subscription. Path-dispatch routes
    /// `/router/bgp/vrf/<name>/...` callbacks here so the per-VRF
    /// runtime owns its own commit sequencing.
    pub cm: ConfigChannel,
    /// Show-command subscription. `show bgp vrf <name> ...`
    /// dispatches through this channel.
    pub show: ShowChannel,
    /// Outbound channel to the global `Bgp` task. Used for peer
    /// registration and per-VRF best-path exports.
    pub global_tx: UnboundedSender<BgpGlobalMsg>,
    /// Inbound channel from the global `Bgp` task. The accept
    /// dispatcher and the import pipeline push here. `Shutdown`
    /// from `despawn_bgp_vrf` also arrives on this channel.
    pub global_rx: UnboundedReceiver<BgpVrfMsg>,
    /// RIB redistribute stream. The receive half of the per-VRF RIB
    /// subscription (`subscribe_for_vrf("bgp:vrf:<name>", table_id)`):
    /// after the task sends `Message::RedistAdd`, the RIB walks
    /// `vrf_tables[table_id]` and streams the matching connected/static
    /// routes here as `RibRx::RouteAdd`/`RouteDel`, which the event
    /// loop turns into per-VRF Loc-RIB originations + VPNv4/v6 exports.
    /// A placeholder-context spawn (kernel VRF not yet known) holds a
    /// closed channel here, so the select arm stays inert until the
    /// kernel-ctx respawn installs a live subscription.
    pub rib_rx: UnboundedReceiver<super::super::super::rib::api::RibRx>,
    /// FSM event channel. Per-VRF peers send `Event(ident, ...)`
    /// here when their timers expire or their TCP state changes;
    /// the per-VRF event loop drives the FSM from these. Bounded
    /// (8192) to match the global `Bgp::tx/rx`.
    pub tx: tokio::sync::mpsc::Sender<Message>,
    pub rx: tokio::sync::mpsc::Receiver<Message>,
    /// Local AS number. Threaded in from the global `Bgp::asn` at
    /// spawn time so per-VRF peers `Peer::new` can fill
    /// `local_as`. The per-VRF runtime does not maintain a
    /// separate ASN today; if a future spec requires one this is
    /// where it lives.
    pub asn: u32,
    /// Per-VRF MPLS label, allocated by `Bgp::vrf_label_alloc`
    /// at spawn time. Stamped onto every `BgpGlobalMsg::Export`
    /// this VRF emits so receiving PEs can identify the egress
    /// VRF; the matching AF_MPLS ILM pops this label and routes
    /// the inner packet into `vrf_tables[table_id]`.
    pub label: u32,
    /// Inter-AS MPLS/VPN Option AB (`inter-as-hybrid`). When set, this
    /// VRF re-exports the VPNv4 routes it *imports* (not just `network`/
    /// CE-learned routes) back into the global VPNv4 table, so an ASBR
    /// can relay a remote AS's VPN routes to its own PEs (and the other
    /// ASBR) over a single MP-eBGP VPNv4 session while still forwarding
    /// per-VRF (the VPN label terminates at the ASBR → VRF lookup). The
    /// re-import loop is broken by `dispatch_import_v4`'s `skip_vrf` (the
    /// originating VRF is excluded) and by eBGP AS-path. Off by default,
    /// so non-hybrid VRF behaviour is unchanged.
    pub inter_as_hybrid: bool,
    /// Dedup pool for `BgpAttr` instances seen by this VRF's
    /// peers. Every per-VRF runtime gets its own pool (cheaper
    /// than threading a shared lock across the `!Send` boundary,
    /// and the attribute populations are largely disjoint between
    /// VRFs in practice).
    pub attr_store: BgpAttrStore,
    /// IOS-XR-style update-groups scoped to this VRF. Same
    /// rationale as `attr_store`: per-VRF copy avoids cross-task
    /// sharing.
    pub update_groups: UpdateGroupMap,
    /// Per-link IPv6 link-local cache for RFC 8950 next-hop
    /// resolution. The per-VRF runtime starts with an empty
    /// cache; BGP unnumbered (interface-neighbor) lives on the
    /// global instance and isn't yet exposed at the VRF surface.
    /// Threaded through `BgpTop` so the FSM driver compiles even
    /// though no path here populates it today.
    pub interface_addrs: InterfaceAddrs,
    /// Resolved transport for the current best-path *winner* of each
    /// imported VPN prefix. Refreshed from [`Self::import_transport_v4`]
    /// (the per-origin-RD store) whenever an import or withdraw-import
    /// re-runs best-path; read by `fib_install_v4`/`v6` (via `BgpTop`)
    /// so an imported VPN winner installs its `{transport,service}`
    /// labelled tunnel entry while CE routes install plain entries —
    /// one FIB install path arbitrating both.
    pub transport_v4:
        std::collections::BTreeMap<ipnet::Ipv4Net, Vec<crate::rib::nht::ResolvedNexthop>>,
    pub transport_v6:
        std::collections::BTreeMap<ipnet::Ipv6Net, Vec<crate::rib::nht::ResolvedNexthop>>,
    /// Synthetic Loc-RIB candidate ids for imported rows, one per
    /// origin RD. A dual-homed prefix arrives from two PEs under two
    /// RDs; storing every import under one `(remote_id 0,
    /// ORIGINATED_PEER)` identity aliased them to a single row, so the
    /// first PE's withdraw removed the row that by then held the
    /// *surviving* PE's route — a CE-side blackhole (review finding
    /// #4). Ids start at [`IMPORT_ID_BASE`] to stay clear of the
    /// redistribute identities (`redist_remote_id`, 1..=5) and the
    /// legacy 0. Never recycled; bounded by the number of distinct
    /// origin RDs this VRF ever imported from.
    pub import_ids: std::collections::BTreeMap<bgp_packet::RouteDistinguisher, u32>,
    /// Resolved transport per `(prefix, origin RD)` — the full store
    /// behind the winner-only `transport_v4`/`v6` maps, so a withdraw
    /// of one RD's import can restore the surviving RD's transport.
    pub import_transport_v4: std::collections::BTreeMap<
        (ipnet::Ipv4Net, bgp_packet::RouteDistinguisher),
        Vec<crate::rib::nht::ResolvedNexthop>,
    >,
    pub import_transport_v6: std::collections::BTreeMap<
        (ipnet::Ipv6Net, bgp_packet::RouteDistinguisher),
        Vec<crate::rib::nht::ResolvedNexthop>,
    >,
    /// Colour-steering state mirrored from the global task via
    /// `BgpVrfMsg::ColourSteering`: the Color→Flex-Algo bindings and the
    /// per-algo SRv6 End-SID shadow. Read by `fib_install_v4`/`v6` (via
    /// `BgpTop`) so an imported SRv6 L3VPN route whose Color binds to a
    /// Flex-Algo gets the algo-N End SID prepended before its service
    /// SID. Empty until the first snapshot arrives.
    pub color_policy: super::super::color_policy::ColorPolicy,
    pub flex_algo_srv6_routes: super::super::color_policy::FlexAlgoSrv6Shadow,
    /// Sender toward the policy actor, set by
    /// [`Self::subscribe_policy`] at spawn. `None` in unit tests that
    /// build a `BgpVrf` directly, which simply means their peers never
    /// register a policy watch.
    pub policy_tx: Option<UnboundedSender<crate::policy::Message>>,
    /// Replies from the policy actor for THIS VRF's registrations.
    ///
    /// The actor keys its client channels by `proto`, so the per-VRF
    /// subscription uses `bgp-vrf:<name>` rather than the global
    /// `"bgp"`. That is not cosmetic: `peer_policy_ident` encodes an
    /// index into the *owning task's* `PeerMap`, and a per-VRF peer's
    /// index means nothing in the global map. Sharing the `"bgp"` proto
    /// would deliver this VRF's resolutions to whichever global peer
    /// happened to sit at that index.
    pub policy_rx: UnboundedReceiver<crate::policy::PolicyRx>,
    /// Our half of the reply channel, kept so `subscribe_policy` can
    /// hand a clone to the actor (and a respawn can re-subscribe).
    policy_reply_tx: UnboundedSender<crate::policy::PolicyRx>,
    /// Sender toward the BFD subsystem, set by [`Self::set_bfd_client`]
    /// at spawn. `None` in unit tests / when BFD is unavailable, which
    /// simply means CE peers never bring up a BFD session.
    ///
    /// Per-VRF BFD is single-hop only: the BFD `SessionKey` has no
    /// VRF/table dimension and the daemon's socket is not VRF-bound, so
    /// a session is disambiguated (and made reachable) purely by the
    /// egress ifindex of a directly-connected CE. Multihop, which keys
    /// on ifindex 0, would conflate overlapping-address VRFs and can't
    /// egress a VRF-only route, so it is refused at config time.
    pub bfd_client_tx: Option<UnboundedSender<crate::bfd::inst::ClientReq>>,
    /// BFD state-change events for THIS VRF's sessions. Each Subscribe
    /// carries `bfd_notifier` as the notifier, and the client id is
    /// `bfd-vrf:<name>` so two VRFs with overlapping CE addresses get
    /// distinct subscriptions.
    pub bfd_event_rx: UnboundedReceiver<crate::bfd::inst::BfdEvent>,
    bfd_notifier: UnboundedSender<crate::bfd::inst::BfdEvent>,
    /// This VRF's snapshot of the key-chains its CE peers reference for
    /// TCP-AO, populated from the policy actor's `PolicyRx::KeyChain`
    /// replies (subscribed under `bgp-vrf:<name>`, so a chain edit is
    /// delivered here rather than to the global task). Read to resolve
    /// each peer's `resolved_ao_key`.
    pub key_chains: std::collections::BTreeMap<String, crate::policy::KeyChain>,
    /// Dedicated channel for streams this VRF's own listener accepts.
    /// Separate from the `BgpVrfMsg` inbox on purpose: the accept
    /// sub-tasks hold `accept_tx` clones, and routing them through the
    /// inbox would keep `global_rx` alive and defeat the "all senders
    /// dropped -> exit" detection. The task drops `accept_rx` when it
    /// ends, which lets the accept loops notice and exit.
    accept_tx: tokio::sync::mpsc::UnboundedSender<(tokio::net::TcpStream, std::net::SocketAddr)>,
    accept_rx: tokio::sync::mpsc::UnboundedReceiver<(tokio::net::TcpStream, std::net::SocketAddr)>,
    /// Raw fds of this VRF's own listener sockets (VRF-bound, opened in
    /// `open_listeners`). Held so the passive-side MD5/AO key installs
    /// (`set_tcp_md5_key` / `set_tcp_ao_key`) can target them — the whole
    /// point of the per-VRF listener. `None` until opened (a
    /// placeholder-ctx spawn never opens one).
    listen_fd_v4: Option<std::os::fd::RawFd>,
    listen_fd_v6: Option<std::os::fd::RawFd>,
    /// Accept-loop tasks for the listeners above; abort when the VRF task
    /// ends (dropping `self`), closing the listeners.
    #[allow(dead_code)]
    listen_tasks: Vec<crate::context::Task<()>>,
    /// VRF-first MUP origination tracking: per PFCP SEID, the RD-free ST
    /// prefixes this VRF exported to the global SAFI-85 RIB. Lets a Session
    /// Deletion / Modification (`MupWithdrawOriginate`) withdraw exactly the
    /// routes that session created. Up to one prefix per bound direction —
    /// a single-direction VRF holds one, a dual-direction VRF (single-N6
    /// UPF, issue #1947) holds the session's T1ST and T2ST together.
    pub mup_originated: std::collections::BTreeMap<u64, Vec<bgp_packet::MupPrefix>>,
    /// VRF-first MUP segment tracking: the RD-free DSD/ISD prefix this VRF
    /// currently has exported (`MupSegmentOriginate`), or `None`. A VRF has at
    /// most one segment route, so a re-originate under a different NLRI key
    /// (direct↔interwork switch / router-id change) withdraws this prior one
    /// first.
    pub mup_segment_prefix: Option<bgp_packet::MupPrefix>,
    /// Installed ST1→ISD encap FIB entries: ST1 UE prefix → the ISD's
    /// End.DT46 SID it is steered into. A selected ST1 whose GTP endpoint
    /// (gNB) address is covered by an imported ISD's prefix installs a
    /// resolved-underlay seg6 H.Encaps route for its UE prefix into this
    /// VRF's table (`dst = UE prefix, via <underlay egress> encap seg6 segs
    /// [SID]`). Tracked so `reconcile_mup_st1_isd` can diff and withdraw when
    /// the ST1 or the covering ISD goes away.
    pub mup_st1_isd_installed: std::collections::BTreeMap<ipnet::IpNet, std::net::Ipv6Addr>,
    /// Resolved underlay transport for each imported segment route (DSD/ISD)
    /// next-hop, keyed by its `(rd, prefix)`. Supplied by the global NHT via
    /// `MupUpdate.transport` and consumed by `reconcile_mup_st2_dsd` /
    /// `reconcile_mup_st1_isd` to build the resolved-underlay seg6 encap for
    /// an ST2 (by Direct-segment id) / ST1 (by prefix containment) that
    /// matches. Absent/empty ⇒ the segment next-hop hasn't resolved, so no
    /// encap is installable for it.
    pub mup_segment_transport: std::collections::BTreeMap<
        (bgp_packet::RouteDistinguisher, bgp_packet::MupPrefix),
        Vec<crate::rib::nht::ResolvedNexthop>,
    >,
    /// Installed ST2→DSD encap FIB entries: ST2 endpoint host prefix → the
    /// DSD's End.DT46 SID it is steered into. Diff base for
    /// `reconcile_mup_st2_dsd`, mirroring `mup_st1_isd_installed`.
    pub mup_st2_dsd_installed: std::collections::BTreeMap<ipnet::IpNet, std::net::Ipv6Addr>,
    /// Installed GTP-U decap PDRs for `dataplane gtp` (the ST2 uplink /
    /// `H.M.GTP4.D`): the set of (endpoint, TEID) tunnels teed to cradle. Diff
    /// base for `reconcile_mup_gtp`.
    pub mup_gtp_pdr_installed: std::collections::BTreeSet<(std::net::Ipv4Addr, u32)>,
    /// Resolved v4 underlay transport for each selected ST1's GTP endpoint
    /// (gNB), keyed by the ST1's `(rd, prefix)`. Supplied by the global NHT via
    /// `MupUpdate.endpoint_transport` (register-then-gate on `st1.endpoint`) and
    /// consumed by the `dataplane gtp` downlink reconcile to fill the cradle
    /// GTP encap nexthop's underlay gateway/oif. Absent/empty ⇒ the endpoint
    /// hasn't resolved, so no `GTP4.E` encap is installable for it.
    pub mup_endpoint_transport: std::collections::BTreeMap<
        (bgp_packet::RouteDistinguisher, bgp_packet::MupPrefix),
        Vec<crate::rib::nht::ResolvedNexthop>,
    >,
    /// Installed GTP-U encap routes for `dataplane gtp` (the ST1 downlink /
    /// `GTP4.E`): UE prefix → the encap key `(gtp_src, endpoint, TEID, gw,
    /// oif)` teed to cradle. Diff base for the downlink reconcile — a changed
    /// key re-installs, a vanished UE prefix withdraws.
    pub mup_gtp_encap_installed: std::collections::BTreeMap<ipnet::Ipv4Net, MupGtpEncapKey>,
}

/// The cradle GTP-U encap install key for one downlink (`GTP4.E`) UE prefix:
/// outer source, gNB endpoint, TEID, and the resolved v4 underlay
/// `(gateway, oif)`. Re-installed only when this tuple changes.
pub type MupGtpEncapKey = (
    std::net::Ipv4Addr,
    std::net::Ipv4Addr,
    u32,
    Option<std::net::Ipv4Addr>,
    u32,
);

/// Sender side of the per-VRF inbound channel — handed back to
/// the global task at spawn time so `despawn_bgp_vrf` can send
/// `BgpVrfMsg::Shutdown`, and so the accept / import dispatchers
/// can locate the matching VRF's queue.
pub type BgpVrfInbox = UnboundedSender<BgpVrfMsg>;

/// Hook handed to the shared `route_update_ipv4` path so a
/// per-VRF best-path winner gets pushed up to the global Bgp
/// task as a VPNv4 export candidate. Carries the VRF name (so
/// the global side can look up RD + RT) and the per-VRF
/// `global_tx` channel.
///
/// The global `Bgp` task constructs its own `BgpTop` with
/// `vrf_export = None`, so the shared route pipeline doesn't
/// fire any export for default-VRF traffic. Per-VRF tasks build
/// a `BgpTop` with `Some(VrfExporter { ... })` and the same
/// code path emits exports as a side-effect.
pub struct VrfExporter {
    pub name: String,
    pub tx: UnboundedSender<BgpGlobalMsg>,
    /// Per-VRF MPLS label, allocated by `Bgp::vrf_label_alloc`.
    /// Stamped onto every `BgpGlobalMsg::Export` emitted from
    /// this exporter; the receiving PE binds an AF_MPLS ILM at
    /// this label so data-plane forwarding pops the label and
    /// looks the inner packet up in the matching VRF table.
    pub label: u32,
}

/// Send a `BgpGlobalMsg::Export` for `prefix` carrying the
/// winner's `BgpAttr` (cloned out of the `Arc` so the global
/// task can re-intern). Called from `route_update_ipv4` after
/// best-path returns a non-empty `selected`. `label = 0` means
/// "no per-VRF label allocated" — the global handler treats it as
/// "skip the per-route install" rather than emit an
/// explicit-null label.
/// Drop every Route-Target extended community (RFC 4360 sub-type 0x02)
/// from a clone of `attr`. Used on the Inter-AS Option AB re-export path:
/// a route imported into a hybrid VRF carries the RTs it matched on, but
/// the re-originated route must carry only *this* VRF's export RTs (the
/// global Export handler re-tags). Without the strip the same RT would
/// accumulate one copy per inter-AS hop.
fn attr_without_route_targets(attr: &bgp_packet::BgpAttr) -> bgp_packet::BgpAttr {
    let mut a = attr.clone();
    if let Some(ref mut ecom) = a.ecom {
        ecom.0.retain(|v| v.low_type != 0x02);
    }
    a
}

pub fn vrf_emit_export(exporter: &VrfExporter, prefix: ipnet::Ipv4Net, attr: &bgp_packet::BgpAttr) {
    let _ = exporter.tx.send(BgpGlobalMsg::Export {
        vrf: exporter.name.clone(),
        prefix,
        attr: attr.clone(),
        label: exporter.label,
    });
}

/// Send a `BgpGlobalMsg::WithdrawExport` for `prefix`. Step
/// 17b-iii calls this when `route_update_ipv4` / withdraw path
/// observes the per-VRF best-path go from "has a winner" to
/// "empty" — the global instance drops the matching VPNv4 row.
pub fn vrf_emit_withdraw(exporter: &VrfExporter, prefix: ipnet::Ipv4Net) {
    let _ = exporter.tx.send(BgpGlobalMsg::WithdrawExport {
        vrf: exporter.name.clone(),
        prefix,
    });
}

/// VPNv6 counterpart of [`vrf_emit_export`] — push a per-VRF IPv6
/// unicast best-path winner up to the global task as a VPNv6 export
/// candidate.
pub fn vrf_emit_export_v6(
    exporter: &VrfExporter,
    prefix: ipnet::Ipv6Net,
    attr: &bgp_packet::BgpAttr,
) {
    let _ = exporter.tx.send(BgpGlobalMsg::ExportV6 {
        vrf: exporter.name.clone(),
        prefix,
        attr: attr.clone(),
        label: exporter.label,
    });
}

/// VPNv6 counterpart of [`vrf_emit_withdraw`].
pub fn vrf_emit_withdraw_v6(exporter: &VrfExporter, prefix: ipnet::Ipv6Net) {
    let _ = exporter.tx.send(BgpGlobalMsg::WithdrawExportV6 {
        vrf: exporter.name.clone(),
        prefix,
    });
}

/// Inverse of [`VrfExporter`] — references the global Bgp state
/// the shared `route_ipv4_update` path needs to fan a VPNv4
/// route out to every importing VRF task.
///
/// Carries `rib_known_vrfs` (for the RT intersection check) and
/// `vrf_registry` (for the per-VRF inbound senders). Both are
/// borrowed from the global `Bgp` for the span of one
/// `process_msg` call.
pub struct VrfImportDispatcher<'a> {
    pub rib_known_vrfs: &'a std::collections::BTreeMap<String, super::super::inst::RibKnownVrf>,
    pub vrf_registry: &'a std::collections::BTreeMap<String, super::spawn::BgpVrfHandle>,
}

/// Fan a freshly best-path-selected VPNv4 route out to every
/// VRF whose `import_rts_v4` intersects the route's RT extcomms.
/// Called from the shared `route_ipv4_update` after
/// `shard.update(Some(rd), ...)` returns. `label = 0` means
/// "no per-VRF label" — the receiving VRF treats it the same way
/// the Export side does (skip the install).
///
/// `skip_vrf` names the VRF the route originated from on the
/// local-leak path (`process_vrf_global_msg::Export`). It's
/// excluded from the fan-out so a VRF whose import-RT set overlaps
/// its own export-RTs (e.g. `rt both 1:1`) doesn't re-import the
/// route it just exported. `None` on the remote-VPNv4 ingress path
/// (no originating local VRF).
pub fn dispatch_import_v4(
    dispatcher: &VrfImportDispatcher<'_>,
    rd: bgp_packet::RouteDistinguisher,
    prefix: ipnet::Ipv4Net,
    attr: &bgp_packet::BgpAttr,
    label: u32,
    transport: &[crate::rib::nht::ResolvedNexthop],
    skip_vrf: Option<&str>,
) {
    let matches =
        super::super::inst::import_targets(dispatcher.rib_known_vrfs, &attr.ecom, skip_vrf);
    for vrf_name in matches {
        let Some(handle) = dispatcher.vrf_registry.get(&vrf_name) else {
            continue;
        };
        let _ = handle.inbox.send(BgpVrfMsg::ImportV4 {
            rd,
            prefix,
            attr: attr.clone(),
            label,
            transport: transport.to_vec(),
        });
    }
}

/// Inverse of [`dispatch_import_v4`]. Floods
/// `BgpVrfMsg::WithdrawImport` to every VRF whose
/// `import_rts_v4` matches; the receiver decides whether the
/// matching imported route is one it actually holds. `skip_vrf`
/// is excluded for the same self-import reason as
/// [`dispatch_import_v4`].
pub fn dispatch_withdraw_import_v4(
    dispatcher: &VrfImportDispatcher<'_>,
    rd: bgp_packet::RouteDistinguisher,
    prefix: ipnet::Ipv4Net,
    attr: &bgp_packet::BgpAttr,
    skip_vrf: Option<&str>,
) {
    let matches =
        super::super::inst::import_targets(dispatcher.rib_known_vrfs, &attr.ecom, skip_vrf);
    for vrf_name in matches {
        let Some(handle) = dispatcher.vrf_registry.get(&vrf_name) else {
            continue;
        };
        let _ = handle.inbox.send(BgpVrfMsg::WithdrawImport { rd, prefix });
    }
}

/// VPNv6 counterpart of [`dispatch_import_v4`] — fan a VPNv6 route out
/// to every VRF whose `import_rts_v6` intersects the route's RTs
/// (minus `skip_vrf`).
pub fn dispatch_import_v6(
    dispatcher: &VrfImportDispatcher<'_>,
    rd: bgp_packet::RouteDistinguisher,
    prefix: ipnet::Ipv6Net,
    attr: &bgp_packet::BgpAttr,
    label: u32,
    transport: &[crate::rib::nht::ResolvedNexthop],
    skip_vrf: Option<&str>,
) {
    let matches =
        super::super::inst::import_targets_v6(dispatcher.rib_known_vrfs, &attr.ecom, skip_vrf);
    for vrf_name in matches {
        let Some(handle) = dispatcher.vrf_registry.get(&vrf_name) else {
            continue;
        };
        let _ = handle.inbox.send(BgpVrfMsg::ImportV6 {
            rd,
            prefix,
            attr: attr.clone(),
            label,
            transport: transport.to_vec(),
        });
    }
}

/// VPNv6 counterpart of [`dispatch_withdraw_import_v4`].
pub fn dispatch_withdraw_import_v6(
    dispatcher: &VrfImportDispatcher<'_>,
    rd: bgp_packet::RouteDistinguisher,
    prefix: ipnet::Ipv6Net,
    attr: &bgp_packet::BgpAttr,
    skip_vrf: Option<&str>,
) {
    let matches =
        super::super::inst::import_targets_v6(dispatcher.rib_known_vrfs, &attr.ecom, skip_vrf);
    for vrf_name in matches {
        let Some(handle) = dispatcher.vrf_registry.get(&vrf_name) else {
            continue;
        };
        let _ = handle
            .inbox
            .send(BgpVrfMsg::WithdrawImportV6 { rd, prefix });
    }
}

/// Mirror a MUP (SAFI 85) best-path — or its withdrawal — into the
/// per-VRF tasks so `show bgp vrf <name> mup` reflects it. A route reaches
/// a VRF two ways, mirroring VPNv4/v6:
///   * **RT import** — every VRF whose `mup_import_rts` intersects the
///     route's RT extcomms (cross-VRF import + peer-learned routes).
///   * **RD origin** — when `origin_vrf` is `Some`, the VRF that locally
///     originated the route (its `rd` equals the route's RD) always
///     receives it, *regardless of route-targets*, because the route is
///     conceptually born in that VRF (an N6/N3 ST route, or a per-VRF
///     DSD/ISD segment route). The receive path passes `None` — a
///     peer-learned route has no local originating VRF — so it keys purely
///     on RTs; the originate path passes the RD-matched VRF name.
///
/// The per-VRF MUP RIB is authoritative for its own imported set (it owns
/// best-path selection); the global `Bgp` Loc-RIB stays the authoritative
/// advertiser. On withdrawal (`best` is `None`) the route's RTs are no
/// longer available, so `BgpVrfMsg::MupWithdraw` is flooded to every VRF —
/// the per-VRF removal is idempotent, so a VRF that never held the prefix
/// simply ignores it (this covers the RD-origin VRF too).
pub fn dispatch_mup(
    dispatcher: &VrfImportDispatcher<'_>,
    rd: bgp_packet::RouteDistinguisher,
    prefix: &bgp_packet::MupPrefix,
    best: Option<&super::super::route::BgpRib>,
    origin_vrf: Option<&str>,
    transport: &[crate::rib::nht::ResolvedNexthop],
    endpoint_transport: &[crate::rib::nht::ResolvedNexthop],
) {
    match best {
        Some(rib) => {
            let targets = super::super::inst::mup_dispatch_targets(
                dispatcher.rib_known_vrfs,
                &rib.attr.ecom,
                origin_vrf,
            );
            for vrf_name in targets {
                let Some(handle) = dispatcher.vrf_registry.get(&vrf_name) else {
                    continue;
                };
                let _ = handle.inbox.send(BgpVrfMsg::MupUpdate {
                    rd,
                    prefix: prefix.clone(),
                    rib: rib.clone(),
                    transport: transport.to_vec(),
                    endpoint_transport: endpoint_transport.to_vec(),
                });
            }
        }
        None => {
            for handle in dispatcher.vrf_registry.values() {
                let _ = handle.inbox.send(BgpVrfMsg::MupWithdraw {
                    rd,
                    prefix: prefix.clone(),
                });
            }
        }
    }
}

/// The (VRF, direction) pairs a PFCP session should originate ST routes in:
/// every `afi-safi mup route {st1|st2}` binding whose `network-instance`
/// matches the session's Network Instance, paired with its direction
/// (st1 = Encapsulation / st2 = Decapsulation) and st2 Direct-segment
/// ext-comm. This is the dual-ST fan-out, in either topology: one NI bound
/// by an st1 and an st2 VRF yields one target each, and one VRF binding
/// BOTH directions (single-N6 UPF, issue #1947) yields two targets under
/// the same VRF name. Pure (no I/O) so the correlation is unit testable;
/// [`dispatch_mup_session`] groups the targets per VRF into `MupOriginate`.
pub fn mup_session_targets(
    vrfs: &std::collections::BTreeMap<String, super::super::vrf_config::BgpVrfConfig>,
    session: &crate::mup_c::session::MupSession,
) -> Vec<(
    String,
    super::super::vrf_config::MupSrv6Direction,
    Option<bgp_packet::RouteDistinguisher>,
)> {
    let Some(ni) = session.network_instance.as_deref() else {
        return Vec::new();
    };
    vrfs.iter()
        .flat_map(|(name, cfg)| {
            cfg.mobile_uplane
                .routes
                .iter()
                .filter(|(_, binding)| binding.network_instance.as_deref() == Some(ni))
                .map(|(direction, binding)| (name.clone(), *direction, binding.mup_ext_comm))
        })
        .collect()
}

/// VRF-first MUP session dispatch: send each VRF that [`mup_session_targets`]
/// matches a `MupOriginate` with its resolved direction + st2 Direct-segment
/// ext-comm. The per-VRF task builds the RD-free ST NLRI and exports it back
/// via `MupExport`; the global export handler stamps the RD / export-RTs /
/// controller next-hop. One session can fan out to several VRFs (an st1 and an
/// st2 VRF sharing the NI). Replaces the old global `build_mup_origination` +
/// `originate_mup_route`.
/// The 6-octet Direct-segment id carried by a MUP Extended Community
/// (transitive type 0x0c, sub-type 0x00), if present — the id an ST2
/// route resolves to a DSD by. Mirrors the same-named helper in `show.rs`.
fn mup_direct_segment_id(attr: &bgp_packet::BgpAttr) -> Option<[u8; 6]> {
    attr.ecom
        .as_ref()?
        .0
        .iter()
        .find(|v| v.high_type == 0x0c && v.low_type == 0x00)
        .map(|v| v.val)
}

/// A single IP address as a host prefix (`/32` for IPv4, `/128` for IPv6).
fn host_net(addr: std::net::IpAddr) -> ipnet::IpNet {
    match addr {
        std::net::IpAddr::V4(a) => ipnet::IpNet::V4(ipnet::Ipv4Net::new(a, 32).unwrap()),
        std::net::IpAddr::V6(a) => ipnet::IpNet::V6(ipnet::Ipv6Net::new(a, 128).unwrap()),
    }
}

pub fn dispatch_mup_session(
    vrfs: &std::collections::BTreeMap<String, super::super::vrf_config::BgpVrfConfig>,
    vrf_registry: &std::collections::BTreeMap<String, super::spawn::BgpVrfHandle>,
    session: &crate::mup_c::session::MupSession,
) {
    // Group the per-direction targets by VRF so each matched VRF receives
    // ONE `MupOriginate` carrying its full desired direction set — the
    // per-VRF handler reconciles prior exports against exactly that set, so
    // a dual-direction VRF (issue #1947) must not see its directions as two
    // competing messages.
    let mut grouped: std::collections::BTreeMap<
        String,
        Vec<(
            super::super::vrf_config::MupSrv6Direction,
            Option<bgp_packet::RouteDistinguisher>,
        )>,
    > = std::collections::BTreeMap::new();
    for (name, direction, ext_comm) in mup_session_targets(vrfs, session) {
        grouped.entry(name).or_default().push((direction, ext_comm));
    }
    for (name, bindings) in grouped {
        let Some(handle) = vrf_registry.get(&name) else {
            continue;
        };
        let _ = handle.inbox.send(BgpVrfMsg::MupOriginate {
            session: session.clone(),
            bindings,
        });
    }
}

/// Withdraw the ST routes a PFCP session originated across all VRFs (Session
/// Deletion / association teardown). Broadcasts `MupWithdrawOriginate`; the
/// per-VRF removal is idempotent for a VRF that never originated for `seid`.
pub fn withdraw_mup_session(
    vrf_registry: &std::collections::BTreeMap<String, super::spawn::BgpVrfHandle>,
    seid: u64,
) {
    for handle in vrf_registry.values() {
        let _ = handle.inbox.send(BgpVrfMsg::MupWithdrawOriginate { seid });
    }
}

/// Tell one VRF task to originate (or refresh) its MUP Segment Discovery route
/// with the resolved config (VRF-first segment origination). The global gated
/// on the SID/locator/kernel-VRF/RD being ready; the VRF builds the RD-free
/// NLRI and exports it back via `MupExport`. No-op if the VRF task is gone.
pub fn dispatch_mup_segment(
    vrf_registry: &std::collections::BTreeMap<String, super::spawn::BgpVrfHandle>,
    vrf: &str,
    mode: super::super::vrf_config::MupSegmentMode,
    ext_comm: Option<bgp_packet::RouteDistinguisher>,
    interwork_prefix: Option<ipnet::IpNet>,
) {
    if let Some(handle) = vrf_registry.get(vrf) {
        let _ = handle.inbox.send(BgpVrfMsg::MupSegmentOriginate {
            mode,
            ext_comm,
            interwork_prefix,
        });
    }
}

/// Tell one VRF task to withdraw its MUP Segment Discovery route (a SID /
/// locator / kernel-VRF / config precondition dropped). No-op if the VRF task
/// is gone.
pub fn withdraw_mup_segment(
    vrf_registry: &std::collections::BTreeMap<String, super::spawn::BgpVrfHandle>,
    vrf: &str,
) {
    if let Some(handle) = vrf_registry.get(vrf) {
        let _ = handle.inbox.send(BgpVrfMsg::MupSegmentWithdraw);
    }
}

/// Per-rtype `remote_id` discriminator for redistribute-originated VRF
/// rows (matches the global `Bgp::redist_remote_id`), so connected /
/// static / IGP sources — and a `network` row at id 0 — coexist for
/// one prefix in the per-VRF shard without overwriting one another.
/// First synthetic `remote_id` for imported rows ([`BgpVrf::import_ids`]).
/// Everything below is reserved: 0 is the legacy shared-import id (and the
/// unknown-rtype redistribute fallback), 1..=5 are the per-rtype
/// redistribute identities of [`redist_remote_id`] — all under the same
/// `ORIGINATED_PEER` ident.
const IMPORT_ID_BASE: u32 = 16;

fn redist_remote_id(rtype: crate::rib::RibType) -> u32 {
    match rtype {
        crate::rib::RibType::Connected => 1,
        crate::rib::RibType::Static => 2,
        crate::rib::RibType::Ospf => 3,
        crate::rib::RibType::Isis => 4,
        crate::rib::RibType::Kernel => 5,
        _ => 0,
    }
}

/// Map a configured redistribute source to the RIB route type the
/// subscription filters on.
pub(super) fn redist_source_rtype(source: BgpRedistSource) -> crate::rib::RibType {
    match source {
        BgpRedistSource::Connected => crate::rib::RibType::Connected,
        BgpRedistSource::Static => crate::rib::RibType::Static,
        BgpRedistSource::Isis => crate::rib::RibType::Isis,
        BgpRedistSource::Ospf => crate::rib::RibType::Ospf,
    }
}

impl BgpVrf {
    /// Build a `BgpVrf` and the matching inbound sender. The
    /// caller (`spawn_bgp_vrf`) keeps the `BgpVrfInbox`, hands the
    /// `BgpVrf` to [`serve_vrf`], and stashes the inbox in a
    /// per-VRF registry so cross-task messages can locate this
    /// task.
    pub fn new(
        name: String,
        ctx: ProtoContext,
        router_id: Ipv4Addr,
        asn: u32,
        label: u32,
        global_tx: UnboundedSender<BgpGlobalMsg>,
        rib_rx: UnboundedReceiver<super::super::super::rib::api::RibRx>,
    ) -> (Self, BgpVrfInbox) {
        let (inbox_tx, global_rx) = mpsc::unbounded_channel();
        let (tx, rx) = mpsc::channel(8192);
        let policy_chan = crate::policy::PolicyRxChannel::new();
        let (bfd_notifier, bfd_event_rx) = mpsc::unbounded_channel();
        let (accept_tx, accept_rx) = mpsc::unbounded_channel();
        let vrf = Self {
            name,
            ctx,
            peers: PeerMap::new(),
            local_rib: LocalRib::default(),
            shard: BgpShard::default(),
            // Default all-off; `spawn_bgp_vrf` seeds it from the
            // instance config and `BgpVrfMsg::Tracing` refreshes it.
            tracing: Default::default(),
            router_id,
            // Default unset; `spawn_bgp_vrf` sets it from the VRF config.
            rd: None,
            // Default End.DT46; `spawn_bgp_vrf` sets it from the VRF config.
            dataplane: super::super::vrf_config::MupDataplane::default(),
            cm: ConfigChannel::new(),
            show: ShowChannel::new(),
            global_tx,
            global_rx,
            rib_rx,
            tx,
            rx,
            asn,
            label,
            // Default off; `spawn_bgp_vrf` sets it from the VRF config.
            inter_as_hybrid: false,
            attr_store: BgpAttrStore::new(),
            update_groups: super::super::update_group::empty_map(),
            interface_addrs: InterfaceAddrs::new(),
            transport_v4: std::collections::BTreeMap::new(),
            transport_v6: std::collections::BTreeMap::new(),
            import_ids: std::collections::BTreeMap::new(),
            import_transport_v4: std::collections::BTreeMap::new(),
            import_transport_v6: std::collections::BTreeMap::new(),
            color_policy: Default::default(),
            flex_algo_srv6_routes: Default::default(),
            policy_tx: None,
            policy_rx: policy_chan.rx,
            policy_reply_tx: policy_chan.tx,
            bfd_client_tx: None,
            bfd_event_rx,
            bfd_notifier,
            key_chains: std::collections::BTreeMap::new(),
            accept_tx,
            accept_rx,
            listen_fd_v4: None,
            listen_fd_v6: None,
            listen_tasks: Vec::new(),
            mup_originated: std::collections::BTreeMap::new(),
            mup_segment_prefix: None,
            mup_st1_isd_installed: std::collections::BTreeMap::new(),
            mup_segment_transport: std::collections::BTreeMap::new(),
            mup_st2_dsd_installed: std::collections::BTreeMap::new(),
            mup_gtp_pdr_installed: std::collections::BTreeSet::new(),
            mup_endpoint_transport: std::collections::BTreeMap::new(),
            mup_gtp_encap_installed: std::collections::BTreeMap::new(),
        };
        (vrf, inbox_tx)
    }

    /// Withdraw every controller ST route this VRF exported for `seid`: emit a
    /// `WithdrawMupExport` for each tracked RD-free prefix so the global
    /// SAFI-85 RIB removes it and re-runs best-path. No-op when nothing was
    /// originated for the session.
    fn withdraw_mup_originate(&mut self, seid: u64) {
        let Some(prefixes) = self.mup_originated.remove(&seid) else {
            return;
        };
        for prefix in prefixes {
            let _ = self.global_tx.send(BgpGlobalMsg::WithdrawMupExport {
                vrf: self.name.clone(),
                prefix,
            });
        }
    }

    /// Reconcile ST1→ISD encap FIB entries for this VRF. A selected ST1
    /// whose GTP endpoint (gNB) address is covered (longest-match) by an
    /// imported ISD's prefix (the gNB N3 network) has its **UE prefix**
    /// steered into that ISD's End.DT46 SID: install a resolved-underlay seg6
    /// H.Encaps route for the UE prefix (`dst = UE prefix, via <underlay
    /// egress> encap seg6 segs [SID]`) into this VRF's table, so downlink
    /// traffic to the UE is encapsulated toward the gNB's segment. The lookup
    /// *key* is the endpoint (draft §3.3.9); the FIB *destination* is the UE
    /// prefix (the Prefix field, §3.1.3). The ISD is remote (received from
    /// the access-side PE), so the encap resolves through the global-supplied
    /// `mup_segment_transport`; an unresolved ISD next-hop yields no install.
    /// Diff-gated against `mup_st1_isd_installed`. Mirrors the show-side
    /// resolution in `render_mup_table`; the ST2→DSD reconcile is the uplink
    /// twin (dst = the ST2 endpoint, matched by Direct-segment id).
    fn reconcile_mup_st1_isd(&mut self) {
        use std::net::Ipv6Addr;
        type Transport = Vec<crate::rib::nht::ResolvedNexthop>;
        // Index imported ISDs by their advertised prefix → (service SIDs,
        // transport). Only an ISD with at least one SID and a resolved
        // underlay transport qualifies. All SIDs are kept (an ISD may split
        // End.DT4 + End.DT6 instead of one End.DT46); the per-ST1 pick
        // below matches the UE prefix's family.
        let mut isd_index: Vec<(ipnet::IpNet, Vec<(Ipv6Addr, u16)>, Transport)> = Vec::new();
        for (rd, table) in self.local_rib.mup.iter() {
            for (prefix, rib) in table.selected.iter() {
                let bgp_packet::MupPrefix::Isd { prefix: isd_prefix } = prefix else {
                    continue;
                };
                let sids: Vec<_> = rib.attr.srv6_l3_sids().collect();
                if sids.is_empty() {
                    continue;
                }
                let Some(transport) = self.mup_segment_transport.get(&(*rd, prefix.clone())) else {
                    continue;
                };
                if transport.is_empty() {
                    continue;
                }
                isd_index.push((*isd_prefix, sids, transport.clone()));
            }
        }
        // Desired: each selected ST1 UE prefix → the most-specific covering
        // ISD's (SID, transport).
        let mut desired: std::collections::BTreeMap<ipnet::IpNet, (Ipv6Addr, Transport)> =
            std::collections::BTreeMap::new();
        if !isd_index.is_empty() {
            for (prefix, rib) in self.local_rib.mup.values().flat_map(|t| t.selected.iter()) {
                // Resolve on the ST1 GTP endpoint (gNB) — the ISD advertises
                // the gNB N3 network, so the endpoint is what falls inside it
                // (draft §3.3.9; also handles a mixed-AFI IPv6-UE /
                // IPv4-endpoint route) — but install the *UE prefix* as the
                // FIB destination (§3.1.3): downlink traffic to the UE is
                // steered toward the gNB's segment. The endpoint is off the
                // ST1 route key (§3.2.1), so read it from the path. The SID
                // must be able to decap the UE family (End.DT4 for a v4 UE /
                // End.DT6 for v6 / End.DT46 for either) — an ISD without a
                // compatible SID is skipped, letting a less-specific covering
                // ISD with one win rather than installing a blackhole.
                if let bgp_packet::MupPrefix::T1st { prefix: ue } = prefix
                    && let Some(st1) = &rib.mup_st1
                    && let Some((sid, transport)) = isd_index
                        .iter()
                        .filter(|(p, _, _)| p.contains(&st1.endpoint))
                        .filter_map(|(p, sids, transport)| {
                            bgp_packet::srv6_l3_sid_for_dest(
                                sids,
                                matches!(ue, ipnet::IpNet::V4(_)),
                            )
                            .map(|(sid, _behavior)| (p, sid, transport))
                        })
                        .max_by_key(|(p, _, _)| p.prefix_len())
                        .map(|(_p, sid, transport)| (sid, transport))
                {
                    desired.insert(*ue, (sid, transport.clone()));
                }
            }
        }
        // Withdraw entries no longer desired (or whose SID changed).
        let stale: Vec<ipnet::IpNet> = self
            .mup_st1_isd_installed
            .iter()
            .filter(|(ue, sid)| desired.get(*ue).map(|(s, _)| s) != Some(*sid))
            .map(|(ue, _)| *ue)
            .collect();
        for ue in stale {
            self.mup_encap_withdraw(ue);
            self.mup_st1_isd_installed.remove(&ue);
        }
        // Install new / changed entries.
        for (ue, (sid, transport)) in &desired {
            if self.mup_st1_isd_installed.get(ue) == Some(sid) {
                continue;
            }
            self.mup_encap_install(*ue, *sid, transport);
            self.mup_st1_isd_installed.insert(*ue, *sid);
        }
    }

    /// Withdraw a previously-installed ST1→ISD encap entry. The RIB dels
    /// the kernel route using its own stored nexthop, so a valueless stub
    /// (like `fib_install_v4`'s withdraw) is enough to trigger it.
    /// Withdraw a previously-installed MUP encap entry (ST1→ISD or
    /// ST2→DSD). The RIB dels the kernel route using its own stored
    /// nexthop, so a valueless stub (like `fib_install_v4`'s withdraw) is
    /// enough to trigger it.
    fn mup_encap_withdraw(&self, dst: ipnet::IpNet) {
        let mut stub = crate::rib::entry::RibEntry::new(crate::rib::RibType::Bgp);
        stub.valid = false;
        match dst {
            ipnet::IpNet::V4(prefix) => {
                let _ = self
                    .ctx
                    .rib
                    .send(crate::rib::Message::Ipv4Del { prefix, rib: stub });
            }
            ipnet::IpNet::V6(prefix) => {
                let _ = self
                    .ctx
                    .rib
                    .send(crate::rib::Message::Ipv6Del { prefix, rib: stub });
            }
        }
    }

    /// Reconcile ST2→DSD encap FIB entries for this VRF. A selected ST2
    /// whose Direct-segment id (MUP Extended Community) matches an imported
    /// DSD is steered into that DSD's End.DT46 SID: install a resolved-
    /// underlay seg6 H.Encaps route for the ST2 endpoint (`dst = endpoint
    /// /32|/128, via <underlay egress> encap seg6 segs [SID]`) into this
    /// VRF's table. The DSD is remote, so the encap resolves through the
    /// global-supplied `mup_segment_transport`; an unresolved DSD next-hop
    /// yields no install. Diff-gated against `mup_st2_dsd_installed`. The
    /// prefix-containment twin is `reconcile_mup_st1_isd`; both mirror the
    /// show-side resolution in `render_mup_table`.
    fn reconcile_mup_st2_dsd(&mut self) {
        use std::net::Ipv6Addr;
        type Transport = Vec<crate::rib::nht::ResolvedNexthop>;
        // Index imported DSDs by Direct-segment id → (service SIDs,
        // transport). Only a DSD with at least one SID and a resolved
        // underlay transport qualifies. All SIDs are kept (a DSD may split
        // End.DT4 + End.DT6 instead of one End.DT46); the per-ST2 pick
        // below matches the endpoint's family.
        let mut dsd_index: std::collections::BTreeMap<[u8; 6], (Vec<(Ipv6Addr, u16)>, Transport)> =
            std::collections::BTreeMap::new();
        for (rd, table) in self.local_rib.mup.iter() {
            for (prefix, rib) in table.selected.iter() {
                if !matches!(prefix, bgp_packet::MupPrefix::Dsd { .. }) {
                    continue;
                }
                let Some(seg) = mup_direct_segment_id(&rib.attr) else {
                    continue;
                };
                let sids: Vec<_> = rib.attr.srv6_l3_sids().collect();
                if sids.is_empty() {
                    continue;
                }
                let Some(transport) = self.mup_segment_transport.get(&(*rd, prefix.clone())) else {
                    continue;
                };
                if transport.is_empty() {
                    continue;
                }
                dsd_index.insert(seg, (sids, transport.clone()));
            }
        }
        // Desired: each selected ST2 whose Direct-segment id matches a DSD →
        // the ST2 endpoint host prefix → (SID, transport). The SID must be
        // able to decap the endpoint's family (the installed FIB
        // destination); a DSD without a compatible SID yields no install.
        let mut desired: std::collections::BTreeMap<ipnet::IpNet, (Ipv6Addr, Transport)> =
            std::collections::BTreeMap::new();
        if !dsd_index.is_empty() {
            for table in self.local_rib.mup.values() {
                for (prefix, rib) in table.selected.iter() {
                    if let bgp_packet::MupPrefix::T2st { endpoint, .. } = prefix
                        && let Some(seg) = mup_direct_segment_id(&rib.attr)
                        && let Some((sids, transport)) = dsd_index.get(&seg)
                        && let Some((sid, _behavior)) =
                            bgp_packet::srv6_l3_sid_for_dest(sids, endpoint.is_ipv4())
                    {
                        desired.insert(host_net(*endpoint), (sid, transport.clone()));
                    }
                }
            }
        }
        // Withdraw entries no longer desired (or whose SID changed).
        let stale: Vec<ipnet::IpNet> = self
            .mup_st2_dsd_installed
            .iter()
            .filter(|(ep, sid)| desired.get(*ep).map(|(s, _)| s) != Some(*sid))
            .map(|(ep, _)| *ep)
            .collect();
        for ep in stale {
            self.mup_encap_withdraw(ep);
            self.mup_st2_dsd_installed.remove(&ep);
        }
        // Install new / changed entries.
        for (ep, (sid, transport)) in &desired {
            if self.mup_st2_dsd_installed.get(ep) == Some(sid) {
                continue;
            }
            self.mup_encap_install(*ep, *sid, transport);
            self.mup_st2_dsd_installed.insert(*ep, *sid);
        }
    }

    /// Program the real GTP-U datapath for a `dataplane gtp` VRF via cradle:
    /// the ST2 uplink decap (`H.M.GTP4.D`) and the ST1 downlink encap
    /// (`GTP4.E`). Runs in place of the End.DT46 reconcilers when the VRF's
    /// `dataplane` is `gtp`.
    fn reconcile_mup_gtp(&mut self) {
        self.reconcile_mup_gtp_uplink();
        self.reconcile_mup_gtp_downlink();
    }

    /// Install GTP-U decap PDRs for a `dataplane gtp` VRF — the ST2 uplink
    /// (`H.M.GTP4.D`). Each selected Type-2 ST route's `(endpoint, TEID)`
    /// becomes a cradle PDR: a G-PDU arriving on that tunnel is stripped and
    /// its inner packet forwarded in this VRF's table. Cradle-only (the kernel
    /// has no GTP action), diff-gated against `mup_gtp_pdr_installed`.
    fn reconcile_mup_gtp_uplink(&mut self) {
        use std::net::{IpAddr, Ipv4Addr};
        let table_id = self.ctx.vrf_id();
        // Desired PDRs: each selected ST2 with a v4 endpoint + non-zero TEID.
        let mut desired: std::collections::BTreeSet<(Ipv4Addr, u32)> =
            std::collections::BTreeSet::new();
        for table in self.local_rib.mup.values() {
            for prefix in table.selected.keys() {
                if let bgp_packet::MupPrefix::T2st { endpoint, teid } = prefix
                    && let IpAddr::V4(v4) = endpoint
                    && *teid != 0
                {
                    desired.insert((*v4, *teid));
                }
            }
        }
        // Withdraw PDRs no longer desired.
        let stale: Vec<(Ipv4Addr, u32)> = self
            .mup_gtp_pdr_installed
            .iter()
            .filter(|k| !desired.contains(k))
            .copied()
            .collect();
        for (dst, teid) in stale {
            let _ = self
                .ctx
                .rib
                .send(crate::rib::Message::CradleGtpPdrDel { dst, teid });
            self.mup_gtp_pdr_installed.remove(&(dst, teid));
        }
        // Install new PDRs.
        for (dst, teid) in &desired {
            if !self.mup_gtp_pdr_installed.insert((*dst, *teid)) {
                continue;
            }
            let _ = self.ctx.rib.send(crate::rib::Message::CradleGtpPdrAdd {
                dst: *dst,
                teid: *teid,
                table_id,
            });
        }
    }

    /// Install GTP-U encap routes for a `dataplane gtp` VRF — the ST1 downlink
    /// (`GTP4.E`). Each selected Type-1 ST route with a v4 UE prefix, a v4 GTP
    /// endpoint (gNB), a non-zero TEID and a v4 source becomes a cradle GTP
    /// encap route: traffic to the UE prefix in this VRF's table is wrapped in
    /// outer IPv4 + UDP(2152) + GTP-U(TEID) toward the endpoint (sourced from
    /// the ST1 source), forwarded over the endpoint's resolved v4 underlay
    /// (`mup_endpoint_transport`, register-then-gate on the global NHT). An
    /// unresolved endpoint or a missing source yields no install. Cradle-only,
    /// diff-gated against `mup_gtp_encap_installed`. The ST1 endpoint is the
    /// lookup key; the UE prefix is the FIB destination (draft §3.1.3 / §3.3.9)
    /// — the same key/destination split as `reconcile_mup_st1_isd`, but a real
    /// GTP tunnel instead of the End.DT46 stand-in.
    fn reconcile_mup_gtp_downlink(&mut self) {
        use std::net::IpAddr;
        let table_id = self.ctx.vrf_id();
        // Desired encaps: each selected ST1 (v4 UE prefix) whose GTP endpoint
        // has resolved to a v4 underlay next-hop → the cradle encap key.
        let mut desired: std::collections::BTreeMap<ipnet::Ipv4Net, MupGtpEncapKey> =
            std::collections::BTreeMap::new();
        for (rd, table) in self.local_rib.mup.iter() {
            for (prefix, rib) in table.selected.iter() {
                let bgp_packet::MupPrefix::T1st { prefix: ue } = prefix else {
                    continue;
                };
                let ipnet::IpNet::V4(ue4) = ue else {
                    continue;
                };
                let Some(st1) = &rib.mup_st1 else {
                    continue;
                };
                let (IpAddr::V4(endpoint), Some(IpAddr::V4(src))) = (st1.endpoint, st1.source)
                else {
                    continue;
                };
                if st1.teid == 0 {
                    continue;
                }
                // The gNB endpoint must have resolved to a v4 underlay egress
                // (register-then-gate); take the first (primary) next-hop.
                let Some(nh) = self
                    .mup_endpoint_transport
                    .get(&(*rd, prefix.clone()))
                    .and_then(|t| t.first())
                else {
                    continue;
                };
                let gw = match nh.addr {
                    IpAddr::V4(a) if !a.is_unspecified() => Some(a),
                    _ => None,
                };
                desired.insert(*ue4, (src, endpoint, st1.teid, gw, nh.ifindex));
            }
        }
        // Withdraw encaps no longer desired (or whose key changed).
        let stale: Vec<ipnet::Ipv4Net> = self
            .mup_gtp_encap_installed
            .iter()
            .filter(|(ue, key)| desired.get(*ue) != Some(*key))
            .map(|(ue, _)| *ue)
            .collect();
        for ue in stale {
            let _ = self.ctx.rib.send(crate::rib::Message::CradleGtpEncapDel {
                prefix: ue,
                table_id,
            });
            self.mup_gtp_encap_installed.remove(&ue);
        }
        // Install new / changed encaps.
        for (ue, key) in &desired {
            if self.mup_gtp_encap_installed.get(ue) == Some(key) {
                continue;
            }
            let (gtp_src, gtp_dst, teid, gw, oif) = *key;
            let _ = self.ctx.rib.send(crate::rib::Message::CradleGtpEncapAdd {
                prefix: *ue,
                table_id,
                gtp_src,
                gtp_dst,
                teid,
                gw,
                oif,
            });
            self.mup_gtp_encap_installed.insert(*ue, *key);
        }
    }

    /// Build + send the resolved-underlay seg6 H.Encaps RibEntry for one MUP
    /// encap binding (ST2→DSD endpoint or ST1→ISD UE prefix) into this VRF's
    /// table. The remote segment's End.DT46 SID rides an `H.Encaps` toward
    /// the resolved underlay egress(es) — the SRv6-L3VPN dataplane shape
    /// ([`build_srv6_vpn_fib_entry`]). A no-op when the transport doesn't
    /// resolve to any egress.
    fn mup_encap_install(
        &self,
        dst: ipnet::IpNet,
        sid: std::net::Ipv6Addr,
        transport: &[crate::rib::nht::ResolvedNexthop],
    ) {
        let Some(entry) = super::super::route::build_srv6_vpn_fib_entry(sid, transport) else {
            return;
        };
        match dst {
            ipnet::IpNet::V4(prefix) => {
                let _ = self
                    .ctx
                    .rib
                    .send(crate::rib::Message::Ipv4Add { prefix, rib: entry });
            }
            ipnet::IpNet::V6(prefix) => {
                let _ = self
                    .ctx
                    .rib
                    .send(crate::rib::Message::Ipv6Add { prefix, rib: entry });
            }
        }
    }

    /// Drive the per-VRF task. The loop exits cleanly when the
    /// Apply a resolution the policy actor pushed back for one of this
    /// VRF's peers.
    ///
    /// The mirror of `Bgp::process_policy_msg`, minus two things the
    /// global task does:
    ///
    ///   * `shard_replace_in_policy` — per-VRF tasks don't drive the
    ///     shard pool; their ingest is synchronous.
    ///   * the soft-in / soft-out replay. `apply_soft_in_peer` /
    ///     `apply_soft_out_peer` take `&mut Bgp` and reach global state,
    ///     so replaying a per-VRF peer needs its own implementation.
    ///     Until that lands, a resolution updates the binding but does
    ///     NOT re-evaluate routes already in Adj-RIB-In / Adj-RIB-Out.
    ///
    /// That gap is invisible for the common case — bindings are
    /// registered by `materialize_peers` at spawn, so the resolution
    /// arrives long before the CE session establishes and any route
    /// exists to re-evaluate. It bites only when an operator edits a
    /// policy definition while a VRF session is up, which is the
    /// follow-up.
    ///
    /// An unresolved name is *not* special-cased here: the actor always
    /// answers, sending `None` when the name is undefined, and a
    /// bound-but-unresolved set is deny-all by construction in the
    /// filter path. Clearing the slot on `None` is what makes a rebind
    /// to an undefined name fail closed rather than silently keep the
    /// previous set.
    pub fn process_policy_msg(&mut self, msg: crate::policy::PolicyRx) {
        use super::super::policy::InOut;
        use crate::policy::{PolicyRx, PolicyType};
        match msg {
            PolicyRx::PrefixSet {
                name: _,
                ident,
                policy_type,
                prefix_set,
            } => {
                let (peer_idx, afi_opt) = super::super::config::peer_policy_ident_decode(ident);
                let Some(afi) = afi_opt else {
                    // The peer-wide slot is only populated by a
                    // neighbor-group, which per-VRF peers resolve
                    // eagerly rather than registering for.
                    return;
                };
                let Some(peer) = self.peers.get_mut_by_idx(peer_idx) else {
                    return;
                };
                let direction = match policy_type {
                    PolicyType::PrefixSetIn => InOut::Input,
                    PolicyType::PrefixSetOut => InOut::Output,
                    _ => return,
                };
                peer.prefix_set_slot(afi, direction).prefix_set = prefix_set;
                if direction == InOut::Output {
                    peer.rebuild_out_policy();
                }
            }
            PolicyRx::PolicyList {
                name: _,
                ident,
                policy_type,
                policy_list,
            } => {
                let (peer_idx, afi_opt) = super::super::config::peer_policy_ident_decode(ident);
                let Some(afi) = afi_opt else {
                    return;
                };
                let Some(peer) = self.peers.get_mut_by_idx(peer_idx) else {
                    return;
                };
                let direction = match policy_type {
                    PolicyType::PolicyListIn => InOut::Input,
                    PolicyType::PolicyListOut => InOut::Output,
                    _ => return,
                };
                peer.policy_list_slot(afi, direction).policy_list = policy_list;
                if direction == InOut::Output {
                    peer.rebuild_out_policy();
                }
            }
            PolicyRx::KeyChain {
                name, key_chain, ..
            } => {
                // A CE peer's TCP-AO key-chain resolved (or changed). Store
                // the snapshot by name, then re-resolve every peer that
                // references it. The ident in the reply is only for the
                // actor's unregister matching; resolution is by name, like
                // the global `apply_ao_refresh_all`.
                if let Some(kc) = key_chain {
                    self.key_chains.insert(name, kc);
                } else {
                    self.key_chains.remove(&name);
                }
                self.resolve_ao_keys();
            }
        }
    }

    /// Re-resolve `resolved_ao_key` for every CE peer from the current
    /// key-chain snapshot, and bounce a live session whose key materially
    /// changed so its next dial carries the new key. The per-VRF twin of
    /// the global `apply_ao_refresh_all`, minus the listener install
    /// (active/outbound only — the connect socket reads
    /// `resolved_ao_key`). An Idle peer just adopts the new key on its
    /// next connect, so it is not bounced.
    fn resolve_ao_keys(&mut self) {
        use super::super::peer::State;
        let key_chains = self.key_chains.clone();
        let mut bounce: Vec<usize> = Vec::new();
        for ident in self.peers.idents() {
            let Some(peer) = self.peers.get_mut_by_idx(ident) else {
                continue;
            };
            let resolved = peer
                .config
                .transport
                .ao_config
                .as_ref()
                .and_then(|ao| ao.resolve(&key_chains));
            if peer.config.transport.resolved_ao_key != resolved {
                if !matches!(peer.state, State::Idle) {
                    bounce.push(ident);
                }
                peer.config.transport.resolved_ao_key = resolved;
            }
        }
        for ident in bounce {
            let _ = self
                .tx
                .try_send(Message::Event(ident, super::super::peer::Event::Stop));
        }
        // Push the newly-resolved keys onto the VRF listener so a
        // CE-initiated SYN authenticates passively too.
        self.refresh_listener_ao();
    }

    /// The `proto` string this VRF uses with the policy actor.
    ///
    /// Per-VRF rather than the global `"bgp"` because the actor routes
    /// replies by proto and `peer_policy_ident` encodes an index into
    /// the owning task's `PeerMap` — see [`Self::policy_rx`].
    pub fn policy_proto(&self) -> String {
        format!("bgp-vrf:{}", self.name)
    }

    /// The BFD client id this VRF uses. Per-VRF so two VRFs with
    /// overlapping CE addresses subscribe as distinct clients (the BFD
    /// `subscribers` map keys on `(SessionKey, ClientId)`).
    pub fn bfd_client(&self) -> String {
        format!("bfd-vrf:{}", self.name)
    }

    /// Stash the BFD client sender at spawn so `materialize_peers` can
    /// bring up CE sessions.
    pub fn set_bfd_client(
        &mut self,
        bfd_client_tx: Option<UnboundedSender<crate::bfd::inst::ClientReq>>,
    ) {
        self.bfd_client_tx = bfd_client_tx;
    }

    /// Reconcile the BFD session for one CE peer, single-hop only.
    ///
    /// A trimmed per-VRF counterpart of the global `bfd_apply_ident`.
    /// The differences, all forced by the single-hop scope:
    ///   * `multihop` is always false — the config path refuses the
    ///     `bfd multihop` leaf, and an inferred-multihop (iBGP) CE runs
    ///     single-hop rather than a session that can't egress the VRF;
    ///   * `min_ttl` is 255 (GTSM), never the multihop value;
    ///   * the egress ifindex comes from this VRF's own
    ///     `interface_addrs`, which is what both disambiguates
    ///     overlapping VRFs and pins the BFD packet to the CE's link.
    ///
    /// There is no per-VRF `router bgp { bfd {} }` default, so the
    /// per-neighbor config resolves over `PeerBfdConfig::default()`.
    pub fn bfd_reconcile(&mut self, ident: usize) {
        use crate::bfd::inst::ClientReq;
        use crate::bfd::session::{EchoMode, SessionKey, SessionParams};
        let Some(bfd_client_tx) = self.bfd_client_tx.clone() else {
            return;
        };
        let Some(peer) = self.peers.get_by_idx(ident) else {
            return;
        };
        let addr = peer.address;
        let eff = peer
            .config
            .bfd
            .resolve(&crate::bgp::peer::PeerBfdConfig::default());
        let local = peer.config.transport.update_source.unwrap_or(match addr {
            std::net::IpAddr::V4(_) => std::net::Ipv4Addr::UNSPECIFIED.into(),
            std::net::IpAddr::V6(_) => std::net::Ipv6Addr::UNSPECIFIED.into(),
        });
        // Single-hop keying: the connected CE's veth ifindex. v6 CE
        // (link-local) has no v4 lookup; falls back to 0 (session still
        // forms, helper-backed Echo stays off) and re-reconciles when
        // the interface is learned.
        let ifindex = match addr {
            std::net::IpAddr::V4(v4) => self.interface_addrs.ifindex_for_v4(v4).unwrap_or(0),
            std::net::IpAddr::V6(_) => 0,
        };
        let key = SessionKey {
            local,
            remote: addr,
            ifindex,
            multihop: false,
        };
        let (echo_mode, echo_rx_us, echo_tx_us) = match eff.echo_mode {
            Some(mode) => (
                mode,
                eff.echo_receive_ms.saturating_mul(1000),
                eff.echo_transmit_ms.saturating_mul(1000),
            ),
            None => (EchoMode::Off, 0, 0),
        };
        let params = SessionParams {
            dst_port: crate::bfd::socket::BFD_SINGLE_HOP_PORT,
            min_ttl: 255,
            echo_mode,
            required_min_echo_rx_us: echo_rx_us,
            echo_transmit_us: echo_tx_us,
            detect_offload: eff.detect_offload,
            ..SessionParams::default()
        };

        let current = self.peers.get_by_idx(ident).and_then(|p| p.bfd_session_key);
        let want = eff.enable.then_some(key);
        let want_params = eff.enable.then_some(params);
        let client = self.bfd_client();
        // A key/params change re-subscribes (BFD treats a repeat
        // Subscribe on the same key as an in-place param update); a
        // disable or key change unsubscribes the stale key first.
        if let Some(old) = current
            && want != current
        {
            let _ = bfd_client_tx.send(ClientReq::Unsubscribe {
                client: client.clone(),
                key: old,
            });
        }
        if eff.enable {
            let _ = bfd_client_tx.send(ClientReq::Subscribe {
                client,
                key,
                params,
                notifier: self.bfd_notifier.clone(),
            });
        }
        if let Some(peer) = self.peers.get_mut_by_idx(ident) {
            peer.bfd_session_key = want;
            peer.bfd_session_params = want_params;
        }
    }

    /// Every BFD key this VRF's peers currently subscribe, for the
    /// synchronous unsubscribe on despawn — same ordering hazard as the
    /// policy watches (a respawn reuses the client id + keys, so a late
    /// unsubscribe from the outgoing incarnation would tear down the
    /// incoming one's session).
    pub fn bfd_session_list(&self) -> Vec<crate::bfd::session::SessionKey> {
        self.peers
            .idents()
            .into_iter()
            .filter_map(|idx| self.peers.get_by_idx(idx).and_then(|p| p.bfd_session_key))
            .collect()
    }

    /// Handle a BFD state change for one of this VRF's CE sessions.
    /// Mirrors the global `Bgp::process_bfd_event`: on a transition to
    /// Down, tear the BGP session down (RFC 5882 §5).
    pub fn process_bfd_event(&mut self, event: crate::bfd::inst::BfdEvent) {
        let crate::bfd::inst::BfdEvent::StateChange { key, change } = event;
        if change.from == change.to || change.to != bfd_packet::State::Down {
            return;
        }
        let Some(peer) = self.peers.get_mut(&key.remote) else {
            return;
        };
        let peer_idx = peer.ident;
        peer.down_reason = Some(super::super::peer::PeerDownReason::BfdDown);
        let _ = self
            .tx
            .try_send(Message::Event(peer_idx, super::super::peer::Event::Stop));
    }

    /// Subscribe this VRF's reply channel with the policy actor and
    /// remember the sender so peers can register their bindings.
    ///
    /// Called by `spawn_bgp_vrf`. A respawn re-subscribes under the same
    /// proto key, which the actor treats as a replace — the stale
    /// channel from the previous incarnation is simply overwritten.
    pub fn subscribe_policy(&mut self, policy_tx: UnboundedSender<crate::policy::Message>) {
        let _ = policy_tx.send(crate::policy::Message::Subscribe {
            proto: self.policy_proto(),
            tx: self.policy_reply_tx.clone(),
        });
        self.policy_tx = Some(policy_tx);
    }

    /// Every policy watch this VRF's peers registered, as
    /// `(name, ident, policy_type)`.
    ///
    /// Handed to `BgpVrfHandle` so `despawn_bgp_vrf` can withdraw them
    /// **synchronously**, on the global task, before a respawn registers
    /// the replacements. Doing it from this task's shutdown path instead
    /// would be a use-after-free in slow motion: the actor's `retain`
    /// matches on `(proto, ident, policy_type)`, and a respawned VRF
    /// reuses both the proto and its peers' idents, so a late Unregister
    /// from the outgoing incarnation deletes the incoming one's watch —
    /// and the `None` reply it triggers clears the freshly resolved
    /// policy, leaving the session fail-closed for good.
    ///
    /// Both messages ride the same `policy_tx`, so FIFO ordering is what
    /// guarantees the withdraw is processed before the re-register.
    pub fn policy_watch_list(&self) -> Vec<(String, usize, crate::policy::PolicyType)> {
        use crate::policy::PolicyType;
        let mut out = Vec::new();
        for idx in self.peers.idents() {
            let Some(peer) = self.peers.get_by_idx(idx) else {
                continue;
            };
            let mut push = |name: Option<&String>, policy_type: PolicyType, fam| {
                if let Some(name) = name {
                    out.push((
                        name.clone(),
                        super::super::config::peer_policy_ident(idx, Some(fam)),
                        policy_type,
                    ));
                }
            };
            for (fam, io) in &peer.policy_list {
                push(
                    io.get(&super::super::policy::InOut::Input).name.as_ref(),
                    PolicyType::PolicyListIn,
                    *fam,
                );
                push(
                    io.get(&super::super::policy::InOut::Output).name.as_ref(),
                    PolicyType::PolicyListOut,
                    *fam,
                );
            }
            for (fam, io) in &peer.prefix_set {
                push(
                    io.get(&super::super::policy::InOut::Input).name.as_ref(),
                    PolicyType::PrefixSetIn,
                    *fam,
                );
                push(
                    io.get(&super::super::policy::InOut::Output).name.as_ref(),
                    PolicyType::PrefixSetOut,
                    *fam,
                );
            }
            // TCP-AO key-chain watch. Keyed by the raw peer ident (not
            // `peer_policy_ident`) matching the global neighbor, and by a
            // distinct `KeyChain` policy_type, so it never collides with a
            // policy/prefix-set watch even if the idents coincide.
            if let Some(ao) = &peer.config.transport.ao_config
                && !ao.key_chain.is_empty()
            {
                out.push((
                    ao.key_chain.clone(),
                    idx,
                    PolicyType::KeyChain(crate::policy::KeyChainScope::BgpNeighbor),
                ));
            }
        }
        out
    }

    /// global task sends [`BgpVrfMsg::Shutdown`] or when the
    /// inbound channel is closed (i.e. every sender — the global
    /// task plus any per-peer holds — has dropped).
    /// Open this VRF's own passive listener sockets, spawn an accept loop
    /// per family, and install the passive-side auth keys any peer
    /// already carries. Called once at the top of `event_loop`.
    ///
    /// Only when the ctx is VRF-bound (`SO_BINDTODEVICE`): a
    /// device-unbound listener on the BGP port would join the global
    /// listener's REUSEPORT group and steal default-VRF connections. A
    /// placeholder-ctx spawn skips it; the kernel-ctx respawn opens it.
    ///
    /// The listener is created here (not in a sub-task) so the fd stays
    /// on `self` for the MD5/AO installs — the reason the per-VRF listener
    /// exists. Each `TcpListener` is then handed to a spawned accept loop
    /// that feeds `BgpVrfMsg::Accept` back to this task.
    async fn open_listeners(&mut self) {
        use std::net::SocketAddr;
        use std::os::fd::AsRawFd;
        if !self.ctx.is_vrf_bound() {
            return;
        }
        let v4: SocketAddr = "0.0.0.0:179".parse().unwrap();
        let v6: SocketAddr = "[::]:179".parse().unwrap();
        match self.ctx.tcp_listen(v4).await {
            Ok(listener) => {
                self.listen_fd_v4 = Some(listener.as_raw_fd());
                self.listen_tasks.push(spawn_accept_loop(
                    listener,
                    self.accept_tx.clone(),
                    self.name.clone(),
                ));
            }
            Err(e) => {
                tracing::warn!(vrf = %self.name, error = %e, "bgp vrf: v4 listener open failed")
            }
        }
        match self.ctx.tcp_listen_v6_only(v6).await {
            Ok(listener) => {
                self.listen_fd_v6 = Some(listener.as_raw_fd());
                self.listen_tasks.push(spawn_accept_loop(
                    listener,
                    self.accept_tx.clone(),
                    self.name.clone(),
                ));
            }
            Err(e) => {
                tracing::warn!(vrf = %self.name, error = %e, "bgp vrf: v6 listener open failed")
            }
        }
        // Install listener keys for peers materialised before the
        // listener existed (the common case: materialize_peers runs at
        // spawn, this runs at event-loop start).
        self.refresh_listener_md5();
        self.refresh_listener_ao();
    }

    /// Reconcile the passive-side TCP-MD5 key on this VRF's listener for
    /// every peer, from `config.transport.md5_password`. The active-side
    /// key is applied by the connect path; this is what lets a
    /// CE-initiated SYN authenticate against the VRF listener.
    pub fn refresh_listener_md5(&mut self) {
        for ident in self.peers.idents() {
            let Some(peer) = self.peers.get_by_idx(ident) else {
                continue;
            };
            let addr = peer.address;
            if addr.is_unspecified() {
                continue;
            }
            let fd = match addr {
                std::net::IpAddr::V4(_) => self.listen_fd_v4,
                std::net::IpAddr::V6(_) => self.listen_fd_v6,
            };
            let Some(fd) = fd else { continue };
            // Empty key removes the entry; a set key installs it.
            let key = peer
                .config
                .transport
                .md5_password
                .clone()
                .unwrap_or_default();
            if let Err(e) = super::super::auth::set_tcp_md5_key(fd, addr, key.as_bytes()) {
                tracing::warn!(vrf = %self.name, peer = %addr, error = %e, "bgp vrf: listener MD5 set failed");
            }
        }
    }

    /// Reconcile the passive-side TCP-AO MKT on this VRF's listener for
    /// every peer from `config.transport.resolved_ao_key`, deleting a
    /// stale entry before a re-add (the kernel keys MKTs by
    /// `(addr, send_id, recv_id)` and rejects a duplicate).
    pub fn refresh_listener_ao(&mut self) {
        let idents = self.peers.idents();
        for ident in idents {
            let Some(peer) = self.peers.get_by_idx(ident) else {
                continue;
            };
            let addr = peer.address;
            if addr.is_unspecified() {
                continue;
            }
            let fd = match addr {
                std::net::IpAddr::V4(_) => self.listen_fd_v4,
                std::net::IpAddr::V6(_) => self.listen_fd_v6,
            };
            let Some(fd) = fd else { continue };
            let resolved = peer.config.transport.resolved_ao_key.clone();
            let new_ids = resolved.as_ref().map(|r| (r.send_id, r.recv_id));
            let prev_ids = peer.last_ao_installed;
            // Delete a stale MKT when the key disappears or its ids change.
            if let Some((s, r)) = prev_ids
                && new_ids != Some((s, r))
                && let Err(e) = super::super::auth::del_tcp_ao_key(fd, addr, s, r)
            {
                tracing::warn!(vrf = %self.name, peer = %addr, error = %e, "bgp vrf: listener AO del failed");
            }
            if let Some(r) = &resolved
                && let Err(e) = super::super::auth::set_tcp_ao_key(
                    fd,
                    addr,
                    r.alg_name,
                    &r.key_material,
                    r.send_id,
                    r.recv_id,
                    r.include_tcp_options,
                )
            {
                tracing::warn!(vrf = %self.name, peer = %addr, error = %e, "bgp vrf: listener AO set failed");
            }
            if let Some(peer) = self.peers.get_mut_by_idx(ident) {
                peer.last_ao_installed = new_ids;
            }
        }
    }

    /// Drive the passive side of the FSM for one accepted inbound
    /// connection against this VRF's own `peers` — the same path
    /// `peer::accept` runs for the global instance. Fed by both this
    /// VRF's own listener (`accept_rx`) and the global dispatcher's
    /// `BgpVrfMsg::Accept` forward (the pre-respawn fallback: it only
    /// carries inbound during the placeholder-ctx window, before this
    /// task's own listener opens on the kernel-ctx respawn).
    fn handle_accept(&mut self, stream: tokio::net::TcpStream, sockaddr: std::net::SocketAddr) {
        tracing::debug!(vrf = %self.name, peer = %sockaddr.ip(), "bgp vrf: inbound Accept");
        let peer_addr = sockaddr.ip();
        let scope_id = match sockaddr {
            std::net::SocketAddr::V6(addr) if addr.scope_id() != 0 => Some(addr.scope_id()),
            _ => None,
        };
        if let Some(stream) =
            super::super::peer::handle_peer_connection(&mut self.peers, peer_addr, scope_id, stream)
        {
            // No matching peer in this VRF — drop, closing the TCP.
            drop(stream);
        }
    }

    pub async fn event_loop(&mut self) {
        self.open_listeners().await;
        loop {
            tokio::select! {
                msg = self.global_rx.recv() => {
                    match msg {
                        Some(BgpVrfMsg::Shutdown) => {
                            bgp_vrf_trace!(&self.tracing, vrf = %self.name, "bgp vrf: shutdown");
                            break;
                        }
                        Some(other) => self.process_global_msg(other),
                        None => {
                            // All senders dropped — the global task
                            // exited without sending Shutdown.
                            bgp_vrf_trace!(
                                &self.tracing,
                                vrf = %self.name,
                                "bgp vrf: inbound channel closed; exiting",
                            );
                            break;
                        }
                    }
                }
                _msg = self.cm.rx.recv() => {
                    // CM dispatch from /router/bgp/vrf/<name>/...
                    // arrives once `spawn_bgp_vrf` registers the
                    // path handler. Drained but ignored when no
                    // consumer is wired yet — keeps the select!
                    // arm from livelocking.
                }
                Some(msg) = self.rib_rx.recv() => {
                    // Redistributed routes streamed back from the RIB
                    // (RibRx::RouteAdd/RouteDel for the connected/static
                    // sources this VRF subscribed to). A placeholder-ctx
                    // spawn holds a closed channel here, so this arm is
                    // inert until the kernel-ctx respawn provides a live
                    // subscription.
                    self.process_rib_msg(msg);
                }
                Some(msg) = self.show.rx.recv() => {
                    // `show bgp vrf <name> …` — the manager stripped the
                    // `vrf <name>` selector and redirected the plain
                    // command here; render against this VRF's RIB/peers.
                    crate::bgp::show::process_vrf_show(self, msg).await;
                }
                Some(msg) = self.policy_rx.recv() => {
                    // Resolution (or clearing) of a policy / prefix-set
                    // this VRF's peers bound. Routed here rather than to
                    // the global task because we subscribed under our own
                    // proto — see `policy_rx`.
                    self.process_policy_msg(msg);
                }
                Some(event) = self.bfd_event_rx.recv() => {
                    // BFD state change for one of this VRF's CE sessions;
                    // a transition to Down tears the BGP session down.
                    self.process_bfd_event(event);
                }
                Some((stream, sockaddr)) = self.accept_rx.recv() => {
                    // A connection this VRF's own listener accepted.
                    self.handle_accept(stream, sockaddr);
                }
                Some(msg) = self.rx.recv() => {
                    self.process_msg(msg);
                }
            }
        }
    }

    /// Handle a per-VRF FSM event off `self.rx`. Wires the same
    /// set the global `Bgp::process_msg` handles — minus `Accept`
    /// (passive accept lives at the global task and is forwarded
    /// via `BgpVrfMsg::Accept`; the per-VRF path doesn't yet drive
    /// it because `peer::accept` is tied to the global `Bgp`).
    fn process_msg(&mut self, msg: Message) {
        use super::super::peer::{BgpTop, fsm};
        match msg {
            Message::Event(ident, event) => {
                // Build a fresh `VrfExporter` per call so the
                // shared `route_update_ipv4` path emits Export to
                // the global Bgp instance when this VRF's
                // best-path changes. The handle is the same
                // `global_tx` the per-VRF runtime already holds;
                // we wrap it with the VRF name so the receiver
                // can resolve RD/RT.
                let exporter = VrfExporter {
                    name: self.name.clone(),
                    tx: self.global_tx.clone(),
                    label: self.label,
                };
                let mut top = BgpTop {
                    router_id: &self.router_id,
                    srv6_ipv6_export: None,
                    local_rib: &mut self.local_rib,
                    shard: &mut self.shard,
                    tx: &self.tx,
                    rib_client: &self.ctx.rib,
                    attr_store: &mut self.attr_store,
                    update_groups: &mut self.update_groups,
                    interface_addrs: &self.interface_addrs,
                    vrf_export: Some(&exporter),
                    // Color → Flex-Algo binding is a default-VRF
                    // concept today; per-VRF support is a follow-up.
                    color_policy: Some(&self.color_policy),
                    flex_algo_routes: None,
                    flex_algo_srv6_routes: Some(&self.flex_algo_srv6_routes),
                    // Per-VRF tasks never receive VPNv4 NLRI directly,
                    // so no import dispatcher to thread through.
                    vrf_import: None,
                    nexthop_cache: None,
                    vrf_transport_v4: Some(&self.transport_v4),
                    vrf_transport_v6: Some(&self.transport_v6),
                    central_label_alloc: None,
                    as_sets_withdraw: true,
                };
                // Per-VRF tasks don't drive the global shard pool (their
                // RIB is the VRF's own); ingest stays synchronous.
                fsm(&mut top, &mut self.peers, ident, event, None);
            }
            Message::Accept(_, _) => {
                // Active-connect path is driven by `Event(...)` from
                // peer-side timers; the global Bgp's accept
                // dispatcher routes passive connections to a VRF
                // via `BgpVrfMsg::Accept`, but `peer::accept` is
                // tied to `&mut Bgp` — refactoring it for per-VRF
                // is a follow-up. Drop here so the channel doesn't
                // accumulate stale Accepts if `peer.rs::accept`
                // ever gains a path that sends into `vrf.tx`.
                tracing::debug!(
                    vrf = %self.name,
                    "bgp vrf: ignored Accept on vrf.tx (active-only path)",
                );
            }
            Message::FlushUpdateGroupIpv4(group_id) => {
                super::super::update_group::flush_ipv4(
                    &mut self.update_groups,
                    &mut self.peers,
                    &self.tx,
                    &group_id,
                    &self.interface_addrs,
                );
            }
            Message::FlushUpdateGroupIpv6(group_id) => {
                super::super::update_group::flush_ipv6(
                    &mut self.update_groups,
                    &mut self.peers,
                    &self.tx,
                    &group_id,
                );
            }
            Message::FlushDoneIpv4(group_id, deltas) => {
                super::super::update_group::flush_done_ipv4(
                    &mut self.update_groups,
                    &mut self.peers,
                    &self.tx,
                    &group_id,
                    deltas,
                    &self.interface_addrs,
                );
            }
            Message::FlushDoneIpv6(group_id, deltas) => {
                super::super::update_group::flush_done_ipv6(
                    &mut self.update_groups,
                    &mut self.peers,
                    &self.tx,
                    &group_id,
                    deltas,
                );
            }
            Message::BgpLs { .. } => {
                // BGP-LS (RFC 9552) is produced and stored only by the
                // global BGP instance — per-VRF tasks never see it.
            }
            Message::MupC(_) => {
                // The MUP controller reports only to the global BGP
                // instance (it is handed the global `tx`); per-VRF tasks
                // never see `MupC`.
            }
            Message::Relisten => {
                // `router bgp port` is a global-instance knob; only the
                // global event loop queues (and handles) Relisten.
                // Per-VRF tasks keep their default-port listeners.
            }
        }
    }

    /// Insert an imported VPNv4 route into the per-VRF
    /// IPv4 unicast LocRIB and fan out to CE peers. `attr` is
    /// re-interned in the per-VRF `attr_store`, the VPNv4
    /// next-hop is rewritten to the VRF's router-id
    /// (next-hop-self — CE peers cannot reach the PE address
    /// the original carried), and the BgpRib lands with
    /// `typ: Originated` because there's no peer-side ident
    /// behind the import.
    ///
    /// After best-path runs, the shared `route_advertise_to_peers`
    /// helper flows the winner out to every Established CE peer
    /// with (AFI=Ip, SAFI=Unicast). The BgpTop hands
    /// `vrf_export: None` so the export hook in
    /// `route_ipv4_update` doesn't re-emit the imported route
    /// back to the global instance — VPNv4 round-trip would be
    /// a loop.
    /// The synthetic candidate id for imports from `rd`, allocating on
    /// first sight (see [`Self::import_ids`]).
    fn import_id(&mut self, rd: bgp_packet::RouteDistinguisher) -> u32 {
        if let Some(&id) = self.import_ids.get(&rd) {
            return id;
        }
        let id = self
            .import_ids
            .values()
            .copied()
            .max()
            .map(|m| m + 1)
            .unwrap_or(IMPORT_ID_BASE);
        self.import_ids.insert(rd, id);
        id
    }

    /// Reverse of [`Self::import_id`]: which origin RD a winning
    /// imported row's `remote_id` belongs to. Linear scan — the map is
    /// bounded by the distinct origin RDs seen.
    fn import_rd_of(&self, id: u32) -> Option<bgp_packet::RouteDistinguisher> {
        self.import_ids
            .iter()
            .find(|&(_, &v)| v == id)
            .map(|(rd, _)| *rd)
    }

    /// Point `transport_v4[prefix]` at the current best-path winner's
    /// transport (from the per-RD store), or clear it when the winner
    /// is not an imported row / has no resolved transport. Keeps the
    /// single-key map `fib_install_v4` reads coherent when imports
    /// from several RDs coexist and the winner changes.
    fn refresh_import_transport_v4(
        &mut self,
        prefix: ipnet::Ipv4Net,
        selected: &[super::super::route::BgpRib],
    ) {
        let winner_transport = selected
            .first()
            .filter(|w| w.vrf_imported)
            .and_then(|w| self.import_rd_of(w.remote_id))
            .and_then(|rd| self.import_transport_v4.get(&(prefix, rd)))
            .cloned();
        match winner_transport {
            Some(t) if !t.is_empty() => {
                self.transport_v4.insert(prefix, t);
            }
            _ => {
                self.transport_v4.remove(&prefix);
            }
        }
    }

    /// IPv6 twin of [`Self::refresh_import_transport_v4`].
    fn refresh_import_transport_v6(
        &mut self,
        prefix: ipnet::Ipv6Net,
        selected: &[super::super::route::BgpRib],
    ) {
        let winner_transport = selected
            .first()
            .filter(|w| w.vrf_imported)
            .and_then(|w| self.import_rd_of(w.remote_id))
            .and_then(|rd| self.import_transport_v6.get(&(prefix, rd)))
            .cloned();
        match winner_transport {
            Some(t) if !t.is_empty() => {
                self.transport_v6.insert(prefix, t);
            }
            _ => {
                self.transport_v6.remove(&prefix);
            }
        }
    }

    fn handle_import_v4(
        &mut self,
        rd: bgp_packet::RouteDistinguisher,
        prefix: ipnet::Ipv4Net,
        mut attr: bgp_packet::BgpAttr,
        label: u32,
        transport: &[crate::rib::nht::ResolvedNexthop],
    ) {
        // Capture an EVPN symmetric-IRB (VXLAN) route's remote VTEP from its
        // EVPN next-hop BEFORE the rewrite below drops it — the FIB install
        // (`vxlan_vpn_entry`) reads it back to build the VXLAN L3 encap. The
        // next-hop itself is still rewritten to self so v4-unicast best-path
        // and CE re-advertise see a plain reachable address.
        let vxlan_vtep = super::super::route::attr_vxlan_vtep(&attr);
        // Rewrite the next-hop to "self" (the VRF's router-id)
        // so CE peers receive a reachable v4 address.
        attr.nexthop = Some(bgp_packet::BgpNexthop::Ipv4(self.router_id));
        let interned = self.shard.intern(attr);
        // Per-origin-RD candidate identity: a dual-homed prefix
        // imported from two PEs (two RDs) must keep two rows, so one
        // PE's withdraw leaves the survivor selected (finding #4).
        let import_id = self.import_id(rd);

        let label_obj = if label != 0 {
            Some(bgp_packet::Label {
                label,
                exp: 0,
                bos: true,
            })
        } else {
            None
        };

        let rib = super::super::route::BgpRib {
            remote_id: import_id,
            local_id: 0,
            attr: interned,
            // Originated/imported VRF rows carry the ORIGINATED_PEER
            // sentinel, NOT 0: a literal 0 collides with the PeerMap index
            // of whatever CE peer occupies slot 0 (a lone PE-CE peer is
            // index 0), and the advertise-path split-horizon
            // (`rib.ident == peer.ident`) would then silently drop this
            // imported route toward that CE — breaking Inter-AS Option A,
            // where the ASBR must re-advertise VPNv4-imported routes over
            // its per-VRF PE-CE eBGP session to the other ASBR.
            ident: super::super::route::ORIGINATED_PEER,
            router_id: self.router_id,
            weight: 0,
            typ: super::super::route::BgpRibType::Originated,
            best_path: false,
            best_reason: super::super::route::Reason::Default,
            label: label_obj,
            local_label: None,
            // v4-unicast rows in LocRIB don't read the
            // Vpnv4-shaped `nexthop` slot; FIB install pulls
            // from `attr.nexthop` set above.
            nexthop: None,
            nexthop_reachable: true,
            enhe_egress: None,
            stale: false,
            esi: None,
            vrf_transit_only: false,
            // Imported from the VPN table: keep `typ: Originated` for the
            // tunnel FIB-install path, but tell best-path this is NOT a
            // genuine local origination (a direct CE eBGP route must win
            // over a reflected copy of the same prefix).
            vrf_imported: true,
            smet_flags: 0,
            igmp_max_resp_time: 0,
            ingress_region: None,
            mup_st1: None,
            vxlan_vtep,
        };

        let (_, selected, _gen) = self.shard.update(None, prefix, rib);
        let winners = selected.len();

        // Persist this RD's resolved transport, then point the
        // winner-only map `fib_install` reads at the *current* best
        // path's transport — which may belong to another RD's import.
        // An empty transport (unresolved) clears this RD's entry.
        if transport.is_empty() {
            self.import_transport_v4.remove(&(prefix, rd));
        } else {
            self.import_transport_v4
                .insert((prefix, rd), transport.to_vec());
        }
        self.refresh_import_transport_v4(prefix, &selected);

        let mut top = super::super::peer::BgpTop {
            router_id: &self.router_id,
            srv6_ipv6_export: None,
            local_rib: &mut self.local_rib,
            shard: &mut self.shard,
            tx: &self.tx,
            rib_client: &self.ctx.rib,
            attr_store: &mut self.attr_store,
            update_groups: &mut self.update_groups,
            interface_addrs: &self.interface_addrs,
            // No re-export of imported routes: a VPNv4-from-RD
            // re-emitted as a VPNv4-with-same-RD would loop.
            vrf_export: None,
            color_policy: Some(&self.color_policy),
            flex_algo_routes: None,
            flex_algo_srv6_routes: Some(&self.flex_algo_srv6_routes),
            vrf_import: None,
            nexthop_cache: None,
            vrf_transport_v4: Some(&self.transport_v4),
            vrf_transport_v6: Some(&self.transport_v6),
            central_label_alloc: None,
            as_sets_withdraw: true,
        };
        super::super::route::route_advertise_to_peers(
            None,
            prefix,
            &selected,
            /* source */ 0,
            &mut top,
            &mut self.peers,
        );

        // Single VRF FIB install path: `fib_install_v4` programs the
        // current best-path winner — the imported route's labelled
        // tunnel entry (via `vrf_transport_v4`) when it wins, or a CE
        // route's plain entry when that wins, or a withdraw when
        // neither. The VRF-bound `ctx.rib` lands it in the VRF table;
        // a placeholder (no-kernel) context's parked client no-ops.
        super::super::route::fib_install_v4(&top, prefix, &selected);

        // Inter-AS Option AB: relay this imported route back into the
        // global VPNv4 table (toward our PEs and the peer ASBR over the
        // single MP-eBGP session). Ordinary VRFs leave `inter_as_hybrid`
        // off and never re-export an import — the explicit hook here is
        // needed because the import path bypasses `route_update_ipv4`,
        // where the normal VRF→global export fires. The re-import loop is
        // broken by `dispatch_import_v4`'s `skip_vrf` (this VRF is
        // excluded from its own export's fan-out) and by eBGP AS-path.
        if self.inter_as_hybrid {
            let exporter = VrfExporter {
                name: self.name.clone(),
                tx: self.global_tx.clone(),
                label: self.label,
            };
            match selected.first() {
                Some(winner) => {
                    vrf_emit_export(&exporter, prefix, &attr_without_route_targets(&winner.attr))
                }
                None => vrf_emit_withdraw(&exporter, prefix),
            }
        }

        bgp_vpn_trace!(
            &self.tracing,
            vrf = %self.name,
            %prefix,
            rd = %rd,
            label,
            winners,
            "bgp vrf: ImportV4 written to LocRIB and advertised to CE peers",
        );
    }

    /// Drop an imported route from the per-VRF LocRIB
    /// and advertise the withdraw (or a replacement winner) to
    /// CE peers. Symmetric with [`Self::handle_import_v4`].
    fn handle_withdraw_import(
        &mut self,
        rd: bgp_packet::RouteDistinguisher,
        prefix: ipnet::Ipv4Net,
    ) {
        // Remove exactly the withdrawing RD's row. An RD this VRF never
        // imported from has nothing to remove — and must not touch a
        // sibling RD's row (the aliasing this fixes).
        let Some(&import_id) = self.import_ids.get(&rd) else {
            bgp_vpn_trace!(
                &self.tracing,
                vrf = %self.name,
                %prefix,
                rd = %rd,
                "bgp vrf: WithdrawImport for an RD with no imports — no-op",
            );
            return;
        };
        let removed = self.shard.remove(
            None,
            prefix,
            import_id,
            super::super::route::ORIGINATED_PEER,
        );
        let selected = self.shard.select_best_path(prefix);
        let removed_n = removed.len();
        let winners = selected.len();

        // Drop the withdrawing RD's transport, then restore the
        // surviving winner's (a dual-homed prefix keeps forwarding on
        // the other PE's tunnel).
        self.import_transport_v4.remove(&(prefix, rd));
        self.refresh_import_transport_v4(prefix, &selected);

        let mut top = super::super::peer::BgpTop {
            router_id: &self.router_id,
            srv6_ipv6_export: None,
            local_rib: &mut self.local_rib,
            shard: &mut self.shard,
            tx: &self.tx,
            rib_client: &self.ctx.rib,
            attr_store: &mut self.attr_store,
            update_groups: &mut self.update_groups,
            interface_addrs: &self.interface_addrs,
            vrf_export: None,
            color_policy: Some(&self.color_policy),
            flex_algo_routes: None,
            flex_algo_srv6_routes: Some(&self.flex_algo_srv6_routes),
            vrf_import: None,
            nexthop_cache: None,
            vrf_transport_v4: Some(&self.transport_v4),
            vrf_transport_v6: Some(&self.transport_v6),
            central_label_alloc: None,
            as_sets_withdraw: true,
        };
        super::super::route::route_advertise_to_peers(
            None,
            prefix,
            &selected,
            /* source */ 0,
            &mut top,
            &mut self.peers,
        );

        // Reconcile the VRF FIB against the *new* best-path. If a CE
        // route was runner-up it now wins and gets installed; if there's
        // no winner left, `fib_install_v4` emits the withdraw. (The old
        // code unconditionally deleted, dropping a now-winning CE route.)
        super::super::route::fib_install_v4(&top, prefix, &selected);

        // Inter-AS Option AB: mirror `handle_import_v4` — re-export the
        // replacement winner, or withdraw the global VPNv4 row when the
        // last candidate is gone.
        if self.inter_as_hybrid {
            let exporter = VrfExporter {
                name: self.name.clone(),
                tx: self.global_tx.clone(),
                label: self.label,
            };
            match selected.first() {
                Some(winner) => {
                    vrf_emit_export(&exporter, prefix, &attr_without_route_targets(&winner.attr))
                }
                None => vrf_emit_withdraw(&exporter, prefix),
            }
        }

        bgp_vpn_trace!(
            &self.tracing,
            vrf = %self.name,
            %prefix,
            rd = %rd,
            removed = removed_n,
            winners,
            "bgp vrf: WithdrawImport removed from LocRIB and withdrawn from CE peers",
        );
    }

    /// VPNv6 counterpart of [`Self::handle_import_v4`]. Inserts the
    /// imported route into the VRF's IPv6 unicast Loc-RIB and fans it
    /// out to CE peers. Unlike v4 we don't pre-stamp a next-hop — the
    /// VRF router-id is IPv4 and can't serve as a v6 next-hop, so
    /// `route_update_ipv6` applies v6 next-hop-self (the CE-facing
    /// session-local address) at advertise time since the row is
    /// `Originated`. The direct Loc-RIB insert bypasses the inbound
    /// `route_ipv6_update` path, so the VRF→global export hook never
    /// fires for an imported route (no VPNv6 round-trip loop).
    fn handle_import_v6(
        &mut self,
        rd: bgp_packet::RouteDistinguisher,
        prefix: ipnet::Ipv6Net,
        mut attr: bgp_packet::BgpAttr,
        label: u32,
        transport: &[crate::rib::nht::ResolvedNexthop],
    ) {
        // Capture an EVPN symmetric-IRB (VXLAN) route's remote VTEP (always
        // IPv4, even for a v6 inner prefix) before clearing the next-hop; the
        // FIB install reads it back to build the VXLAN L3 encap.
        let vxlan_vtep = super::super::route::attr_vxlan_vtep(&attr);
        attr.nexthop = None;
        let interned = self.shard.intern(attr);
        // Per-origin-RD candidate identity — see `handle_import_v4`.
        let import_id = self.import_id(rd);

        let label_obj = if label != 0 {
            Some(bgp_packet::Label {
                label,
                exp: 0,
                bos: true,
            })
        } else {
            None
        };

        let rib = super::super::route::BgpRib {
            remote_id: import_id,
            local_id: 0,
            attr: interned,
            // Originated/imported VRF rows carry the ORIGINATED_PEER
            // sentinel, NOT 0: a literal 0 collides with the PeerMap index
            // of whatever CE peer occupies slot 0 (a lone PE-CE peer is
            // index 0), and the advertise-path split-horizon
            // (`rib.ident == peer.ident`) would then silently drop this
            // imported route toward that CE — breaking Inter-AS Option A,
            // where the ASBR must re-advertise VPNv4-imported routes over
            // its per-VRF PE-CE eBGP session to the other ASBR.
            ident: super::super::route::ORIGINATED_PEER,
            router_id: self.router_id,
            weight: 0,
            typ: super::super::route::BgpRibType::Originated,
            best_path: false,
            best_reason: super::super::route::Reason::Default,
            label: label_obj,
            local_label: None,
            nexthop: None,
            nexthop_reachable: true,
            enhe_egress: None,
            stale: false,
            esi: None,
            vrf_transit_only: false,
            // Imported from the VPN table: keep `typ: Originated` for the
            // tunnel FIB-install path, but tell best-path this is NOT a
            // genuine local origination (a direct CE eBGP route must win
            // over a reflected copy of the same prefix).
            vrf_imported: true,
            smet_flags: 0,
            igmp_max_resp_time: 0,
            ingress_region: None,
            mup_st1: None,
            vxlan_vtep,
        };

        let (_, selected, _gen) = self.shard.update_v6(prefix, rib);
        let winners = selected.len();

        // Per-RD transport + winner refresh (see `handle_import_v4`).
        if transport.is_empty() {
            self.import_transport_v6.remove(&(prefix, rd));
        } else {
            self.import_transport_v6
                .insert((prefix, rd), transport.to_vec());
        }
        self.refresh_import_transport_v6(prefix, &selected);

        let mut top = super::super::peer::BgpTop {
            router_id: &self.router_id,
            srv6_ipv6_export: None,
            local_rib: &mut self.local_rib,
            shard: &mut self.shard,
            tx: &self.tx,
            rib_client: &self.ctx.rib,
            attr_store: &mut self.attr_store,
            update_groups: &mut self.update_groups,
            interface_addrs: &self.interface_addrs,
            vrf_export: None,
            color_policy: Some(&self.color_policy),
            flex_algo_routes: None,
            flex_algo_srv6_routes: Some(&self.flex_algo_srv6_routes),
            vrf_import: None,
            nexthop_cache: None,
            vrf_transport_v4: Some(&self.transport_v4),
            vrf_transport_v6: Some(&self.transport_v6),
            central_label_alloc: None,
            as_sets_withdraw: true,
        };
        super::super::route::route_advertise_to_peers_v6(
            prefix,
            &selected,
            &mut top,
            &mut self.peers,
        );

        // Single VRF FIB install path (see `handle_import_v4`).
        super::super::route::fib_install_v6(&top, prefix, &selected);

        // Inter-AS Option AB (VPNv6): re-export the imported route — see
        // `handle_import_v4`.
        if self.inter_as_hybrid {
            let exporter = VrfExporter {
                name: self.name.clone(),
                tx: self.global_tx.clone(),
                label: self.label,
            };
            match selected.first() {
                Some(winner) => {
                    vrf_emit_export_v6(&exporter, prefix, &attr_without_route_targets(&winner.attr))
                }
                None => vrf_emit_withdraw_v6(&exporter, prefix),
            }
        }

        bgp_vpn_trace!(
            &self.tracing,
            vrf = %self.name,
            %prefix,
            rd = %rd,
            label,
            winners,
            "bgp vrf: ImportV6 written to LocRIB and advertised to CE peers",
        );
    }

    /// VPNv6 counterpart of [`Self::handle_withdraw_import`].
    fn handle_withdraw_import_v6(
        &mut self,
        rd: bgp_packet::RouteDistinguisher,
        prefix: ipnet::Ipv6Net,
    ) {
        // See `handle_withdraw_import`: only the withdrawing RD's row.
        let Some(&import_id) = self.import_ids.get(&rd) else {
            bgp_vpn_trace!(
                &self.tracing,
                vrf = %self.name,
                %prefix,
                rd = %rd,
                "bgp vrf: WithdrawImportV6 for an RD with no imports — no-op",
            );
            return;
        };
        let removed = self
            .shard
            .remove_v6(prefix, import_id, super::super::route::ORIGINATED_PEER);
        let selected = self.shard.select_best_path_v6(prefix);
        let removed_n = removed.len();
        let winners = selected.len();

        self.import_transport_v6.remove(&(prefix, rd));
        self.refresh_import_transport_v6(prefix, &selected);

        let mut top = super::super::peer::BgpTop {
            router_id: &self.router_id,
            srv6_ipv6_export: None,
            local_rib: &mut self.local_rib,
            shard: &mut self.shard,
            tx: &self.tx,
            rib_client: &self.ctx.rib,
            attr_store: &mut self.attr_store,
            update_groups: &mut self.update_groups,
            interface_addrs: &self.interface_addrs,
            vrf_export: None,
            color_policy: Some(&self.color_policy),
            flex_algo_routes: None,
            flex_algo_srv6_routes: Some(&self.flex_algo_srv6_routes),
            vrf_import: None,
            nexthop_cache: None,
            vrf_transport_v4: Some(&self.transport_v4),
            vrf_transport_v6: Some(&self.transport_v6),
            central_label_alloc: None,
            as_sets_withdraw: true,
        };
        super::super::route::route_advertise_to_peers_v6(
            prefix,
            &selected,
            &mut top,
            &mut self.peers,
        );

        // Reconcile against the new best-path (see `handle_withdraw_import`).
        super::super::route::fib_install_v6(&top, prefix, &selected);

        // Inter-AS Option AB (VPNv6): re-export the replacement winner or
        // withdraw the global row — see `handle_withdraw_import`.
        if self.inter_as_hybrid {
            let exporter = VrfExporter {
                name: self.name.clone(),
                tx: self.global_tx.clone(),
                label: self.label,
            };
            match selected.first() {
                Some(winner) => {
                    vrf_emit_export_v6(&exporter, prefix, &attr_without_route_targets(&winner.attr))
                }
                None => vrf_emit_withdraw_v6(&exporter, prefix),
            }
        }

        bgp_vpn_trace!(
            &self.tracing,
            vrf = %self.name,
            %prefix,
            rd = %rd,
            removed = removed_n,
            winners,
            "bgp vrf: WithdrawImportV6 removed from LocRIB and withdrawn from CE peers",
        );
    }

    /// Originate one `network <p>` self-route into this VRF's
    /// Loc-RIB as an `Originated` row and emit `Export` so the
    /// global instance promotes it to a VPNv4 advertisement. Shared
    /// by the spawn-time `materialize_self_originated_networks` and
    /// the dynamic [`BgpVrfMsg::OriginateNetwork`] path (a `network`
    /// added to an already-running VRF).
    pub fn originate_self_network_v4(&mut self, prefix: ipnet::Ipv4Net) {
        use bgp_packet::{BgpAttr, BgpNexthop, Origin};

        // Build a self-originated attr: IGP origin, next-hop-self.
        // Local-pref / weight default to the same values
        // `BgpAttr::new` uses for the global `network` path.
        let mut attr = BgpAttr::new();
        attr.origin = Some(Origin::Igp);
        attr.nexthop = Some(BgpNexthop::Ipv4(self.router_id));
        let interned = self.shard.intern(attr);

        let rib = self.self_originated_rib(interned);
        let (_, selected, _) = self.shard.update(None, prefix, rib);
        // A freshly-inserted self-originated row always wins when
        // it's the only candidate; emit Export for whoever won.
        if let Some(winner) = selected.first() {
            let exporter = self.exporter();
            vrf_emit_export(&exporter, prefix, &winner.attr);
        }
    }

    /// Inverse of [`Self::originate_self_network_v4`]: drop the
    /// self-originated row (ident 0 / remote 0) for `prefix`,
    /// re-run best-path, and either re-export the surviving winner
    /// or emit `WithdrawExport` when nothing else carries the
    /// prefix. Driven by [`BgpVrfMsg::WithdrawNetwork`] when a
    /// `network` is removed from a running VRF.
    pub fn withdraw_self_network_v4(&mut self, prefix: ipnet::Ipv4Net) {
        let removed = self.shard.remove(None, prefix, 0, 0);
        if removed.is_empty() {
            return;
        }
        let exporter = self.exporter();
        // `remove` does not re-run best-path; do it explicitly so a
        // surviving candidate (e.g. an imported route on the same
        // prefix) is re-advertised instead of withdrawn.
        match self.shard.select_best_path(prefix).first() {
            Some(winner) => vrf_emit_export(&exporter, prefix, &winner.attr),
            None => vrf_emit_withdraw(&exporter, prefix),
        }
    }

    /// IPv6 counterpart of [`Self::originate_self_network_v4`]. The
    /// next-hop is a placeholder — the global re-advertise rewrites
    /// it to next-hop-self in `route_update_ipv6`.
    pub fn originate_self_network_v6(&mut self, prefix: ipnet::Ipv6Net) {
        use bgp_packet::{BgpAttr, BgpNexthop, Origin};

        let mut attr = BgpAttr::new();
        attr.origin = Some(Origin::Igp);
        attr.nexthop = Some(BgpNexthop::Ipv6(std::net::Ipv6Addr::UNSPECIFIED));
        let interned = self.shard.intern(attr);

        let rib = self.self_originated_rib(interned);
        let (_, selected, _) = self.shard.update_v6(prefix, rib);
        if let Some(winner) = selected.first() {
            let exporter = self.exporter();
            vrf_emit_export_v6(&exporter, prefix, &winner.attr);
        }
    }

    /// IPv6 counterpart of [`Self::withdraw_self_network_v4`].
    pub fn withdraw_self_network_v6(&mut self, prefix: ipnet::Ipv6Net) {
        let removed = self.shard.remove_v6(prefix, 0, 0);
        if removed.is_empty() {
            return;
        }
        let exporter = self.exporter();
        match self.shard.select_best_path_v6(prefix).first() {
            Some(winner) => vrf_emit_export_v6(&exporter, prefix, &winner.attr),
            None => vrf_emit_withdraw_v6(&exporter, prefix),
        }
    }

    /// Tell the RIB to start redistributing `source` for `afi` into
    /// this VRF. The RIB resolves our subscriber by proto name
    /// (`bgp:vrf:<name>`, registered at spawn) → its `vrf_id` (this
    /// VRF's kernel table id) → walks `vrf_tables[table_id]` and
    /// streams the matching routes back on `rib_rx`. Empty subtype set
    /// = wildcard (every subtype under the rtype). `pub(super)` so
    /// `spawn_bgp_vrf` can replay the staged config at spawn time.
    pub(super) fn redist_subscribe(&self, afi: crate::rib::RedistAfi, source: BgpRedistSource) {
        let _ = self.ctx.rib.send(crate::rib::Message::RedistAdd {
            proto: format!("bgp:vrf:{}", self.name),
            afi,
            rtype: redist_source_rtype(source),
            subtypes: std::collections::BTreeSet::new(),
        });
    }

    /// Inverse of [`Self::redist_subscribe`]: drop the redistribute
    /// subscription. The RIB replays the matched prefixes as
    /// `RouteDel`, which `process_rib_msg` turns into withdraws — so no
    /// local sweep is needed here.
    fn redist_unsubscribe(&self, afi: crate::rib::RedistAfi, source: BgpRedistSource) {
        let _ = self.ctx.rib.send(crate::rib::Message::RedistDel {
            proto: format!("bgp:vrf:{}", self.name),
            afi,
            rtype: redist_source_rtype(source),
        });
    }

    /// Consume one RIB redistribute notification. Only the route
    /// add/del stream is relevant to a per-VRF redistribute subscriber;
    /// link / addr / router-id / EoR markers are ignored.
    fn process_rib_msg(&mut self, msg: crate::rib::api::RibRx) {
        use crate::rib::RouteBatch;
        use crate::rib::api::RibRx;
        match msg {
            RibRx::RouteAdd { rtype, routes, .. } => match routes {
                RouteBatch::V4(entries) => {
                    for e in entries {
                        self.redist_inject_v4(rtype, e.prefix, e.metric);
                    }
                }
                RouteBatch::V6(entries) => {
                    for e in entries {
                        self.redist_inject_v6(rtype, e.prefix, e.metric);
                    }
                }
            },
            RibRx::RouteDel { rtype, routes, .. } => match routes {
                RouteBatch::V4(entries) => {
                    for e in entries {
                        self.redist_withdraw_v4(rtype, e.prefix);
                    }
                }
                RouteBatch::V6(entries) => {
                    for e in entries {
                        self.redist_withdraw_v6(rtype, e.prefix);
                    }
                }
            },
            _ => {}
        }
    }

    /// Originate one redistributed IPv4 route into this VRF's Loc-RIB
    /// and export the winner to the global VPNv4 table. Mirrors
    /// [`Self::originate_self_network_v4`] but keyed by a redistribute
    /// identity (so it coexists with a `network` row for the same
    /// prefix) and carries the source RIB cost as MED.
    fn redist_inject_v4(
        &mut self,
        rtype: crate::rib::RibType,
        prefix: ipnet::Ipv4Net,
        metric: u32,
    ) {
        use bgp_packet::{BgpAttr, BgpNexthop, Med, Origin};

        let mut attr = BgpAttr::new();
        attr.origin = Some(Origin::Incomplete);
        attr.nexthop = Some(BgpNexthop::Ipv4(self.router_id));
        attr.med = Some(Med::new(metric));
        let interned = self.shard.intern(attr);

        let rib = self.redist_originated_rib(interned, rtype);
        let (_, selected, _) = self.shard.update(None, prefix, rib);
        if let Some(winner) = selected.first() {
            let exporter = self.exporter();
            vrf_emit_export(&exporter, prefix, &winner.attr);
        }
    }

    /// Inverse of [`Self::redist_inject_v4`].
    fn redist_withdraw_v4(&mut self, rtype: crate::rib::RibType, prefix: ipnet::Ipv4Net) {
        let removed = self
            .shard
            .remove(None, prefix, redist_remote_id(rtype), ORIGINATED_PEER);
        if removed.is_empty() {
            return;
        }
        let exporter = self.exporter();
        match self.shard.select_best_path(prefix).first() {
            Some(winner) => vrf_emit_export(&exporter, prefix, &winner.attr),
            None => vrf_emit_withdraw(&exporter, prefix),
        }
    }

    /// IPv6 counterpart of [`Self::redist_inject_v4`]. The next-hop is a
    /// placeholder — the global re-advertise rewrites it to
    /// next-hop-self in `route_update_ipv6`.
    fn redist_inject_v6(
        &mut self,
        rtype: crate::rib::RibType,
        prefix: ipnet::Ipv6Net,
        metric: u32,
    ) {
        use bgp_packet::{BgpAttr, BgpNexthop, Med, Origin};

        let mut attr = BgpAttr::new();
        attr.origin = Some(Origin::Incomplete);
        attr.nexthop = Some(BgpNexthop::Ipv6(std::net::Ipv6Addr::UNSPECIFIED));
        attr.med = Some(Med::new(metric));
        let interned = self.shard.intern(attr);

        let rib = self.redist_originated_rib(interned, rtype);
        let (_, selected, _) = self.shard.update_v6(prefix, rib);
        if let Some(winner) = selected.first() {
            let exporter = self.exporter();
            vrf_emit_export_v6(&exporter, prefix, &winner.attr);
        }
    }

    /// IPv6 counterpart of [`Self::redist_withdraw_v4`].
    fn redist_withdraw_v6(&mut self, rtype: crate::rib::RibType, prefix: ipnet::Ipv6Net) {
        let removed = self
            .shard
            .remove_v6(prefix, redist_remote_id(rtype), ORIGINATED_PEER);
        if removed.is_empty() {
            return;
        }
        let exporter = self.exporter();
        match self.shard.select_best_path_v6(prefix).first() {
            Some(winner) => vrf_emit_export_v6(&exporter, prefix, &winner.attr),
            None => vrf_emit_withdraw_v6(&exporter, prefix),
        }
    }

    /// A redistribute-originated [`BgpRib`]: the self-originated shape
    /// with a redistribute identity (ident `ORIGINATED_PEER`, per-rtype
    /// `remote_id`) so distinct sources — and a `network` row at
    /// id 0 — coexist for the same prefix without overwriting.
    fn redist_originated_rib(
        &self,
        attr: std::sync::Arc<bgp_packet::BgpAttr>,
        rtype: crate::rib::RibType,
    ) -> super::super::route::BgpRib {
        let mut rib = self.self_originated_rib(attr);
        rib.ident = ORIGINATED_PEER;
        rib.remote_id = redist_remote_id(rtype);
        rib
    }

    /// Build a fresh [`VrfExporter`] pointing at the global task.
    fn exporter(&self) -> VrfExporter {
        VrfExporter {
            name: self.name.clone(),
            tx: self.global_tx.clone(),
            label: self.label,
        }
    }

    /// A self-originated `BgpRib` (ident 0 / remote 0) carrying the
    /// interned `attr`. Identical shape for v4 and v6 — only the
    /// shard table the caller inserts into differs.
    fn self_originated_rib(
        &self,
        attr: std::sync::Arc<bgp_packet::BgpAttr>,
    ) -> super::super::route::BgpRib {
        super::super::route::BgpRib {
            remote_id: 0,
            local_id: 0,
            attr,
            ident: 0,
            router_id: self.router_id,
            weight: 32768,
            typ: super::super::route::BgpRibType::Originated,
            best_path: false,
            best_reason: super::super::route::Reason::Default,
            label: None,
            local_label: None,
            nexthop: None,
            nexthop_reachable: true,
            enhe_egress: None,
            stale: false,
            esi: None,
            vrf_transit_only: false,
            vrf_imported: false,
            smet_flags: 0,
            igmp_max_resp_time: 0,
            ingress_region: None,
            mup_st1: None,
            vxlan_vtep: None,
        }
    }

    /// Per-task handling of cross-task messages that aren't
    /// `Shutdown`.
    fn process_global_msg(&mut self, msg: BgpVrfMsg) {
        match msg {
            BgpVrfMsg::ColourSteering {
                color_policy,
                srv6_shadow,
            } => {
                // Mirror the global colour-steering state so this VRF's
                // FIB install can steer imported SRv6 L3VPN routes. No
                // re-install of existing routes here — the next best-path
                // / NHT churn re-runs `fib_install`; steady-state VPN
                // routes refresh on the SPF that changed the shadow.
                self.color_policy = color_policy;
                self.flex_algo_srv6_routes = srv6_shadow;
            }
            BgpVrfMsg::Tracing(tracing) => {
                // Instance-wide tracing config changed. Purely a
                // logging switch — nothing to re-run.
                self.tracing = tracing;
            }
            BgpVrfMsg::Accept(stream, sockaddr) => {
                // Passive accept forwarded by the global dispatcher (the
                // pre-respawn fallback, before this task's own listener
                // opens). Same handling as a connection our own listener
                // accepts.
                self.handle_accept(stream, sockaddr);
            }
            BgpVrfMsg::ImportV4 {
                rd,
                prefix,
                attr,
                label,
                transport,
            } => {
                self.handle_import_v4(rd, prefix, attr, label, &transport);
            }
            BgpVrfMsg::WithdrawImport { rd, prefix } => {
                self.handle_withdraw_import(rd, prefix);
            }
            BgpVrfMsg::ImportV6 {
                rd,
                prefix,
                attr,
                label,
                transport,
            } => {
                self.handle_import_v6(rd, prefix, attr, label, &transport);
            }
            BgpVrfMsg::WithdrawImportV6 { rd, prefix } => {
                self.handle_withdraw_import_v6(rd, prefix);
            }
            BgpVrfMsg::OriginateNetwork { prefix } => {
                self.originate_self_network_v4(prefix);
            }
            BgpVrfMsg::WithdrawNetwork { prefix } => {
                self.withdraw_self_network_v4(prefix);
            }
            BgpVrfMsg::OriginateNetworkV6 { prefix } => {
                self.originate_self_network_v6(prefix);
            }
            BgpVrfMsg::WithdrawNetworkV6 { prefix } => {
                self.withdraw_self_network_v6(prefix);
            }
            BgpVrfMsg::RedistEnable { afi, source } => {
                self.redist_subscribe(afi, source);
            }
            BgpVrfMsg::RedistDisable { afi, source } => {
                self.redist_unsubscribe(afi, source);
            }
            // Authoritative per-VRF MUP import (RT-matched at the global
            // dispatch): insert the route as a candidate in this VRF's own
            // MUP RIB and best-path it. The VRF receives the global winner
            // per prefix, so best-path is single-candidate here, but the
            // table is authoritative — `show bgp vrf <name> mup` (redirected
            // here) reads the resulting `selected`. MUP has no CE peers and
            // no kernel FIB yet, so this neither re-advertises nor installs;
            // it owns the control-plane RIB only.
            //
            // The route is keyed under the VRF's *own* RD, not the message's
            // origin RD: a VRF holds its MUP routes under its own RD (the one
            // it would re-originate them with), exactly as an L3VPN VRF drops
            // the VPNv4 RD on import. So a cross-RD import (e.g. an ISD
            // originated under RD 65501:20, imported by a VRF whose rd is
            // 65501:10) lands under 65501:10 here. A VRF with no `rd` falls
            // back to the message RD.
            BgpVrfMsg::MupUpdate {
                rd,
                prefix,
                rib,
                transport,
                endpoint_transport,
            } => {
                let rd = self.rd.unwrap_or(rd);
                // A received segment route (DSD/ISD) carries the
                // global-resolved underlay transport for its next-hop; stash
                // it (keyed by the re-keyed rd + prefix) so the ST2→DSD /
                // ST1→ISD reconcile can build the endpoint / UE encap. Empty
                // transport ⇒ unresolved.
                if matches!(
                    prefix,
                    bgp_packet::MupPrefix::Dsd { .. } | bgp_packet::MupPrefix::Isd { .. }
                ) {
                    if transport.is_empty() {
                        self.mup_segment_transport.remove(&(rd, prefix.clone()));
                    } else {
                        self.mup_segment_transport
                            .insert((rd, prefix.clone()), transport);
                    }
                }
                // A Type-1 ST carries the global-resolved v4 underlay transport
                // for its GTP endpoint (gNB); stash it for the `dataplane gtp`
                // downlink `GTP4.E` encap. Empty ⇒ the endpoint is unresolved.
                if matches!(prefix, bgp_packet::MupPrefix::T1st { .. }) {
                    if endpoint_transport.is_empty() {
                        self.mup_endpoint_transport.remove(&(rd, prefix.clone()));
                    } else {
                        self.mup_endpoint_transport
                            .insert((rd, prefix.clone()), endpoint_transport);
                    }
                }
                let _ = self
                    .local_rib
                    .mup
                    .entry(rd)
                    .or_default()
                    .update(prefix, rib);
                match self.dataplane {
                    super::super::vrf_config::MupDataplane::Gtp => self.reconcile_mup_gtp(),
                    super::super::vrf_config::MupDataplane::EndDt46 => {
                        self.reconcile_mup_st1_isd();
                        self.reconcile_mup_st2_dsd();
                    }
                }
            }
            BgpVrfMsg::MupWithdraw { rd, prefix } => {
                // Same own-RD scoping as MupUpdate. The VRF holds the single
                // dispatched winner per prefix, so a prefix-keyed removal
                // clears it; prune the per-RD table when it empties so an
                // empty RD never renders.
                let rd = self.rd.unwrap_or(rd);
                self.mup_segment_transport.remove(&(rd, prefix.clone()));
                self.mup_endpoint_transport.remove(&(rd, prefix.clone()));
                let empty = if let Some(table) = self.local_rib.mup.get_mut(&rd) {
                    table.cands.remove(&prefix);
                    table.selected.remove(&prefix);
                    table.cands.is_empty() && table.selected.is_empty()
                } else {
                    false
                };
                if empty {
                    self.local_rib.mup.remove(&rd);
                }
                match self.dataplane {
                    super::super::vrf_config::MupDataplane::Gtp => self.reconcile_mup_gtp(),
                    super::super::vrf_config::MupDataplane::EndDt46 => {
                        self.reconcile_mup_st1_isd();
                        self.reconcile_mup_st2_dsd();
                    }
                }
            }
            // VRF-first MUP origination: build the RD-free ST NLRI for every
            // dispatched direction binding — a dual-direction VRF (single-N6
            // UPF, issue #1947) builds the session's T1ST AND T2ST here — and
            // export each to the global SAFI-85 RIB. The global export
            // handler applies the RD, export route-targets and controller
            // next-hop; the resulting routes are mirrored back here
            // (RT/RD-origin) so this VRF's own `show bgp vrf <name> mup`
            // reflects them. A Modification reconciles against the prior
            // exports as a set — the ST keys exclude the session-transform
            // fields (an ST1 keys on RD+Prefix alone, §3.2.1), so a handover
            // that only moves the tunnel (new TEID/QFI/endpoint) rebuilds the
            // *same* NLRI key: re-export it and let the Loc-RIB replace in
            // place (an implicit withdraw on the wire). Only a prior export
            // no longer among the built keys — a changed UE prefix / ST2 core
            // tunnel, an ST the modified session no longer builds, or a
            // direction unbound since — gets an explicit withdraw, so peers
            // and the dataplane never see the surviving routes flap
            // mid-handover.
            BgpVrfMsg::MupOriginate { session, bindings } => {
                let built: Vec<_> = bindings
                    .into_iter()
                    .filter_map(|(direction, ext_comm)| {
                        super::super::route::build_mup_st_route(&session, direction, ext_comm)
                    })
                    .collect();
                let prior = self
                    .mup_originated
                    .remove(&session.seid)
                    .unwrap_or_default();
                for old in prior {
                    if !built.iter().any(|(p, _, _)| p == &old) {
                        let _ = self.global_tx.send(BgpGlobalMsg::WithdrawMupExport {
                            vrf: self.name.clone(),
                            prefix: old,
                        });
                    }
                }
                for (prefix, st1, attr) in built {
                    self.mup_originated
                        .entry(session.seid)
                        .or_default()
                        .push(prefix.clone());
                    let _ = self.global_tx.send(BgpGlobalMsg::MupExport {
                        vrf: self.name.clone(),
                        prefix,
                        st1,
                        attr,
                    });
                }
            }
            BgpVrfMsg::MupWithdrawOriginate { seid } => {
                self.withdraw_mup_originate(seid);
            }
            // VRF-first MUP segment origination: build the RD-free DSD/ISD NLRI
            // (DSD = this VRF's router-id, ISD = the interwork prefix) and
            // export it. The global gated on SID/locator/kernel-VRF/RD before
            // sending this; the global export handler stamps the RD,
            // export-RTs, locator next-hop and End.DT46 Prefix-SID. If the NLRI
            // key changed from a prior segment (direct↔interwork / router-id),
            // withdraw the old one first.
            BgpVrfMsg::MupSegmentOriginate {
                mode,
                ext_comm,
                interwork_prefix,
            } => {
                let prefix =
                    super::super::route::mup_segment_nlri(mode, self.router_id, interwork_prefix);
                if let Some(old) = self.mup_segment_prefix.take()
                    && Some(&old) != prefix.as_ref()
                {
                    let _ = self.global_tx.send(BgpGlobalMsg::WithdrawMupExport {
                        vrf: self.name.clone(),
                        prefix: old,
                    });
                }
                if let Some(prefix) = prefix {
                    let attr = super::super::route::build_mup_segment_attr(mode, ext_comm);
                    self.mup_segment_prefix = Some(prefix.clone());
                    let _ = self.global_tx.send(BgpGlobalMsg::MupExport {
                        vrf: self.name.clone(),
                        prefix,
                        // A DSD/ISD segment carries no off-key ST1 fields.
                        st1: None,
                        attr,
                    });
                }
            }
            BgpVrfMsg::MupSegmentWithdraw => {
                if let Some(prefix) = self.mup_segment_prefix.take() {
                    let _ = self.global_tx.send(BgpGlobalMsg::WithdrawMupExport {
                        vrf: self.name.clone(),
                        prefix,
                    });
                }
            }
            BgpVrfMsg::Shutdown => unreachable!("handled in event_loop"),
        }
    }
}

/// Spawn the per-VRF event loop on its own tokio task. Mirrors
/// [`crate::bgp::inst::serve`] / [`crate::nd::inst::serve`].
/// Accept loop for one per-VRF listener socket: hand each accepted
/// stream to the VRF task via `BgpVrfMsg::Accept` (the same message the
/// global dispatcher forwards). Exits when the inbox is gone (task ended)
/// or on a persistent accept error.
fn spawn_accept_loop(
    listener: tokio::net::TcpListener,
    accept_tx: tokio::sync::mpsc::UnboundedSender<(tokio::net::TcpStream, std::net::SocketAddr)>,
    name: String,
) -> Task<()> {
    Task::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, sockaddr)) => {
                    if accept_tx.send((stream, sockaddr)).is_err() {
                        return;
                    }
                }
                Err(e) => {
                    tracing::warn!(vrf = %name, error = %e, "bgp vrf: accept error");
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        }
    })
}

pub fn serve_vrf(mut vrf: BgpVrf) -> Task<()> {
    Task::spawn(async move {
        vrf.event_loop().await;
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::sync::mpsc::unbounded_channel;

    use crate::rib::client::{ProtoId, RibClient, RibInbound};

    use super::*;

    fn test_ctx_for_vrf(table_id: u32, ifname: &str) -> ProtoContext {
        // Parked RibClient — the test doesn't exercise rib.send().
        let (inbound_tx, inbound_rx) = unbounded_channel::<RibInbound>();
        Box::leak(Box::new(inbound_rx));
        let rib = RibClient::new(inbound_tx, ProtoId::from_raw(0));
        ProtoContext::for_vrf(rib, table_id, ifname.to_string())
    }

    #[tokio::test]
    async fn shutdown_message_exits_event_loop_within_timeout() {
        // Lifecycle invariant: `Shutdown` on the inbound channel
        // makes `event_loop` return — without that contract,
        // `despawn_bgp_vrf` wouldn't be able to tear a VRF task
        // down cleanly.
        let (global_tx, _global_rx) = unbounded_channel::<BgpGlobalMsg>();
        let ctx = test_ctx_for_vrf(10, "vrf-test");
        let (_rib_tx, rib_rx) = mpsc::unbounded_channel();
        let (mut vrf, inbox) = BgpVrf::new(
            "vrf-test".to_string(),
            ctx,
            Ipv4Addr::UNSPECIFIED,
            65000,
            /* label */ 16,
            global_tx,
            rib_rx,
        );

        inbox.send(BgpVrfMsg::Shutdown).expect("inbound rx alive");

        // Two-second timeout: the loop should exit on the very
        // next `recv` call; a slow exit would indicate a deadlock
        // on the inbound channel.
        tokio::time::timeout(Duration::from_secs(2), vrf.event_loop())
            .await
            .expect("event_loop returns after Shutdown");
    }

    #[tokio::test]
    async fn dataplane_gtp_reconciles_st2_endpoints_to_pdrs() {
        use crate::bgp::route::{BgpRib, BgpRibType};
        use bgp_packet::{BgpAttr, MupPrefix};
        use std::net::{IpAddr, Ipv4Addr};

        let (global_tx, _global_rx) = unbounded_channel::<BgpGlobalMsg>();
        let ctx = test_ctx_for_vrf(42, "vrf-gtp");
        let (_rib_tx, rib_rx) = mpsc::unbounded_channel();
        let (mut vrf, _inbox) = BgpVrf::new(
            "vrf-gtp".to_string(),
            ctx,
            Ipv4Addr::UNSPECIFIED,
            65000,
            /* label */ 16,
            global_tx,
            rib_rx,
        );
        vrf.dataplane = crate::bgp::vrf_config::MupDataplane::Gtp;

        let attr = BgpAttr::new();
        let mk = || {
            BgpRib::new(
                1,
                Ipv4Addr::UNSPECIFIED,
                BgpRibType::EBGP,
                0,
                0,
                &attr,
                None,
                None,
                false,
            )
        };
        let rd: bgp_packet::RouteDistinguisher = "65000:1".parse().unwrap();
        {
            let table = vrf.local_rib.mup.entry(rd).or_default();
            // v4 endpoint + non-zero TEID → a decap PDR.
            table.selected.insert(
                MupPrefix::T2st {
                    endpoint: IpAddr::V4(Ipv4Addr::new(10, 9, 0, 1)),
                    teid: 0x1234,
                },
                mk(),
            );
            // teid 0 (the null TEID) → skipped.
            table.selected.insert(
                MupPrefix::T2st {
                    endpoint: IpAddr::V4(Ipv4Addr::new(10, 9, 0, 2)),
                    teid: 0,
                },
                mk(),
            );
            // v6 endpoint → skipped (GTP4 only in this slice).
            table.selected.insert(
                MupPrefix::T2st {
                    endpoint: "2001:db8::1".parse().unwrap(),
                    teid: 0x5678,
                },
                mk(),
            );
        }

        vrf.reconcile_mup_gtp();
        assert!(
            vrf.mup_gtp_pdr_installed
                .contains(&(Ipv4Addr::new(10, 9, 0, 1), 0x1234))
        );
        assert_eq!(
            vrf.mup_gtp_pdr_installed.len(),
            1,
            "only the v4, non-zero-TEID ST2 installs a decap PDR"
        );

        // The ST2 goes away → its PDR is withdrawn from the tracker.
        vrf.local_rib.mup.get_mut(&rd).unwrap().selected.clear();
        vrf.reconcile_mup_gtp();
        assert!(
            vrf.mup_gtp_pdr_installed.is_empty(),
            "the decap PDR is withdrawn when its ST2 is gone"
        );
    }

    #[tokio::test]
    async fn dataplane_gtp_reconciles_st1_to_encaps() {
        use crate::bgp::route::{BgpRib, BgpRibType};
        use crate::rib::nht::ResolvedNexthop;
        use bgp_packet::{BgpAttr, MupPrefix, MupSt1Fields};
        use std::net::{IpAddr, Ipv4Addr};

        let (global_tx, _global_rx) = unbounded_channel::<BgpGlobalMsg>();
        let ctx = test_ctx_for_vrf(43, "vrf-gtp-dl");
        let (_rib_tx, rib_rx) = mpsc::unbounded_channel();
        let (mut vrf, _inbox) = BgpVrf::new(
            "vrf-gtp-dl".to_string(),
            ctx,
            Ipv4Addr::UNSPECIFIED,
            65000,
            /* label */ 16,
            global_tx,
            rib_rx,
        );
        vrf.dataplane = crate::bgp::vrf_config::MupDataplane::Gtp;

        let attr = BgpAttr::new();
        let mk_st1 = |teid: u32, endpoint: IpAddr, source: Option<IpAddr>| {
            let mut rib = BgpRib::new(
                1,
                Ipv4Addr::UNSPECIFIED,
                BgpRibType::EBGP,
                0,
                0,
                &attr,
                None,
                None,
                false,
            );
            rib.mup_st1 = Some(MupSt1Fields {
                teid,
                qfi: 5,
                endpoint,
                source,
            });
            rib
        };
        let rd: bgp_packet::RouteDistinguisher = "65000:1".parse().unwrap();
        let gnb = IpAddr::V4(Ipv4Addr::new(10, 0, 12, 1));
        let src = IpAddr::V4(Ipv4Addr::new(10, 0, 12, 2));
        // A fully-specified ST1 whose gNB endpoint has resolved to a v4
        // underlay egress (gateway 10.0.99.1, oif 7).
        let ue_ok: ipnet::Ipv4Net = "10.60.1.0/24".parse().unwrap();
        let p_ok = MupPrefix::T1st {
            prefix: ipnet::IpNet::V4(ue_ok),
        };
        // An ST1 with no source → cannot build a GTP outer header → skipped.
        let ue_nosrc: ipnet::Ipv4Net = "10.60.2.0/24".parse().unwrap();
        let p_nosrc = MupPrefix::T1st {
            prefix: ipnet::IpNet::V4(ue_nosrc),
        };
        // An ST1 whose endpoint hasn't resolved (no endpoint transport) →
        // skipped.
        let ue_unres: ipnet::Ipv4Net = "10.60.3.0/24".parse().unwrap();
        let p_unres = MupPrefix::T1st {
            prefix: ipnet::IpNet::V4(ue_unres),
        };
        {
            let table = vrf.local_rib.mup.entry(rd).or_default();
            table
                .selected
                .insert(p_ok.clone(), mk_st1(0x2222, gnb, Some(src)));
            table
                .selected
                .insert(p_nosrc.clone(), mk_st1(0x3333, gnb, None));
            table
                .selected
                .insert(p_unres.clone(), mk_st1(0x4444, gnb, Some(src)));
        }
        // Only the first ST1's endpoint is resolved.
        vrf.mup_endpoint_transport.insert(
            (rd, p_ok.clone()),
            vec![ResolvedNexthop {
                addr: IpAddr::V4(Ipv4Addr::new(10, 0, 99, 1)),
                ifindex: 7,
                labels: Vec::new(),
                segs: vec![],
                seg_encap: None,
            }],
        );

        vrf.reconcile_mup_gtp();
        assert_eq!(
            vrf.mup_gtp_encap_installed.get(&ue_ok),
            Some(&(
                Ipv4Addr::new(10, 0, 12, 2),       // gtp_src
                Ipv4Addr::new(10, 0, 12, 1),       // gtp_dst (gNB endpoint)
                0x2222,                            // teid
                Some(Ipv4Addr::new(10, 0, 99, 1)), // resolved gateway
                7,                                 // resolved oif
            )),
            "the resolved ST1 with a source installs a GTP4.E encap"
        );
        assert_eq!(
            vrf.mup_gtp_encap_installed.len(),
            1,
            "only the source-carrying, endpoint-resolved ST1 installs an encap"
        );

        // The endpoint resolution goes away → the encap is withdrawn.
        vrf.mup_endpoint_transport.remove(&(rd, p_ok.clone()));
        vrf.reconcile_mup_gtp();
        assert!(
            vrf.mup_gtp_encap_installed.is_empty(),
            "the GTP4.E encap is withdrawn when its endpoint stops resolving"
        );
    }

    /// An ISD carrying a split End.DT4 + End.DT6 SID pair (instead of one
    /// End.DT46) must steer each ST1 UE prefix into the SID that can decap
    /// its family — not blindly the first SID. When the ISD loses the
    /// v6-capable SID, the v6 UE's encap is withdrawn rather than left (or
    /// re-pointed) at the End.DT4 SID.
    #[tokio::test]
    async fn st1_isd_reconcile_picks_sid_by_ue_family() {
        use crate::bgp::route::{BgpRib, BgpRibType};
        use crate::rib::nht::ResolvedNexthop;
        use bgp_packet::{
            BgpAttr, MupPrefix, MupSt1Fields, PrefixSid, PrefixSidTlv, SRV6_BEHAVIOR_END_DT4,
            SRV6_BEHAVIOR_END_DT6, Srv6ServiceTlv, Srv6SidInfo,
        };
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

        let (global_tx, _global_rx) = unbounded_channel::<BgpGlobalMsg>();
        let ctx = test_ctx_for_vrf(44, "vrf-isd");
        let (_rib_tx, rib_rx) = mpsc::unbounded_channel();
        let (mut vrf, _inbox) = BgpVrf::new(
            "vrf-isd".to_string(),
            ctx,
            Ipv4Addr::UNSPECIFIED,
            65000,
            /* label */ 16,
            global_tx,
            rib_rx,
        );

        let dt4: Ipv6Addr = "fcbb:aaaa::4".parse().unwrap();
        let dt6: Ipv6Addr = "fcbb:aaaa::6".parse().unwrap();
        let isd_rib = |sids: Vec<Srv6SidInfo>| {
            let mut attr = BgpAttr::new();
            attr.prefix_sid = Some(PrefixSid {
                tlvs: vec![PrefixSidTlv::Srv6L3Service(Srv6ServiceTlv {
                    sids,
                    ..Default::default()
                })],
            });
            BgpRib::new(
                1,
                Ipv4Addr::UNSPECIFIED,
                BgpRibType::EBGP,
                0,
                0,
                &attr,
                None,
                None,
                false,
            )
        };
        let mk_st1 = |ue: ipnet::IpNet, endpoint: IpAddr| {
            let attr = BgpAttr::new();
            let mut rib = BgpRib::new(
                1,
                Ipv4Addr::UNSPECIFIED,
                BgpRibType::EBGP,
                0,
                0,
                &attr,
                None,
                None,
                false,
            );
            rib.mup_st1 = Some(MupSt1Fields {
                teid: 0x100,
                qfi: 5,
                endpoint,
                source: None,
            });
            (MupPrefix::T1st { prefix: ue }, rib)
        };

        let rd: bgp_packet::RouteDistinguisher = "65000:1".parse().unwrap();
        let isd_prefix = MupPrefix::Isd {
            prefix: "10.0.12.0/24".parse().unwrap(),
        };
        let gnb = IpAddr::V4(Ipv4Addr::new(10, 0, 12, 1));
        let ue_v4: ipnet::IpNet = "10.60.1.0/24".parse().unwrap();
        let ue_v6: ipnet::IpNet = "2001:db8:cafe::/64".parse().unwrap();
        {
            let table = vrf.local_rib.mup.entry(rd).or_default();
            table.selected.insert(
                isd_prefix.clone(),
                isd_rib(vec![
                    Srv6SidInfo::new(dt4, 0, SRV6_BEHAVIOR_END_DT4, None),
                    Srv6SidInfo::new(dt6, 0, SRV6_BEHAVIOR_END_DT6, None),
                ]),
            );
            let (p, rib) = mk_st1(ue_v4, gnb);
            table.selected.insert(p, rib);
            let (p, rib) = mk_st1(ue_v6, gnb);
            table.selected.insert(p, rib);
        }
        // The ISD's next-hop has a resolved underlay.
        vrf.mup_segment_transport.insert(
            (rd, isd_prefix.clone()),
            vec![ResolvedNexthop {
                addr: IpAddr::V4(Ipv4Addr::new(10, 0, 99, 1)),
                ifindex: 7,
                labels: Vec::new(),
                segs: vec![],
                seg_encap: None,
            }],
        );

        vrf.reconcile_mup_st1_isd();
        assert_eq!(
            vrf.mup_st1_isd_installed.get(&ue_v4),
            Some(&dt4),
            "the v4 UE prefix is steered into the End.DT4 SID"
        );
        assert_eq!(
            vrf.mup_st1_isd_installed.get(&ue_v6),
            Some(&dt6),
            "the v6 UE prefix is steered into the End.DT6 SID"
        );

        // The ISD drops to DT4-only → the v6 UE cannot be serviced: its
        // entry is withdrawn, the v4 one stays put.
        vrf.local_rib.mup.get_mut(&rd).unwrap().selected.insert(
            isd_prefix.clone(),
            isd_rib(vec![Srv6SidInfo::new(dt4, 0, SRV6_BEHAVIOR_END_DT4, None)]),
        );
        vrf.reconcile_mup_st1_isd();
        assert_eq!(vrf.mup_st1_isd_installed.get(&ue_v4), Some(&dt4));
        assert_eq!(
            vrf.mup_st1_isd_installed.get(&ue_v6),
            None,
            "a DT4-only ISD must not carry an IPv6 UE prefix"
        );
    }

    #[tokio::test]
    async fn inbox_drop_closes_event_loop() {
        // If every sender to the inbound channel is dropped, the
        // VRF task exits anyway — defensive cleanup so a buggy
        // caller that forgets to send `Shutdown` still doesn't
        // leak the task.
        let (global_tx, _global_rx) = unbounded_channel::<BgpGlobalMsg>();
        let ctx = test_ctx_for_vrf(11, "vrf-test2");
        let (_rib_tx, rib_rx) = mpsc::unbounded_channel();
        let (mut vrf, inbox) = BgpVrf::new(
            "vrf-test2".to_string(),
            ctx,
            Ipv4Addr::UNSPECIFIED,
            65000,
            /* label */ 16,
            global_tx,
            rib_rx,
        );

        drop(inbox);

        tokio::time::timeout(Duration::from_secs(2), vrf.event_loop())
            .await
            .expect("event_loop exits when inbox is dropped");
    }

    #[tokio::test]
    async fn vrf_emit_export_sends_export_msg_via_exporter() {
        // The free-function hook called from `route_update_ipv4`'s
        // post-best-path arm pushes an Export with the winner's
        // prefix + attr + label.
        let (tx, mut rx) = unbounded_channel::<BgpGlobalMsg>();
        let exporter = VrfExporter {
            name: "vrf-hook".to_string(),
            tx,
            label: 42,
        };
        let prefix: ipnet::Ipv4Net = "10.0.0.0/24".parse().unwrap();
        let attr = bgp_packet::BgpAttr::default();

        vrf_emit_export(&exporter, prefix, &attr);

        let msg = rx.try_recv().expect("Export pushed");
        match msg {
            BgpGlobalMsg::Export {
                vrf,
                prefix: p,
                attr: a,
                label,
            } => {
                assert_eq!(vrf, "vrf-hook");
                assert_eq!(p, prefix);
                assert_eq!(a, attr);
                assert_eq!(label, 42, "exporter's label is stamped onto Export");
            }
            other => panic!("expected Export, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn vrf_emit_withdraw_sends_withdraw_export_msg() {
        let (tx, mut rx) = unbounded_channel::<BgpGlobalMsg>();
        let exporter = VrfExporter {
            name: "vrf-hook2".to_string(),
            tx,
            label: 17,
        };
        let prefix: ipnet::Ipv4Net = "10.0.0.0/24".parse().unwrap();

        vrf_emit_withdraw(&exporter, prefix);

        let msg = rx.try_recv().expect("WithdrawExport pushed");
        match msg {
            BgpGlobalMsg::WithdrawExport { vrf, prefix: p } => {
                assert_eq!(vrf, "vrf-hook2");
                assert_eq!(p, prefix);
            }
            other => panic!("expected WithdrawExport, got {other:?}"),
        }
    }

    /// A PFCP Modification that only moves the GTP tunnel (handover: new
    /// gNB endpoint / TEID) rebuilds the *same* ST1 NLRI key — RD+Prefix
    /// alone keys an ST1 (§3.2.1) — so the repeat `MupOriginate` must
    /// re-export in place with NO `WithdrawMupExport`: peers replace via
    /// implicit withdraw and the UE prefix never flaps mid-handover. A
    /// modification after which the ST no longer builds still withdraws
    /// the prior export explicitly.
    #[tokio::test]
    async fn mup_handover_reexports_in_place_without_withdraw() {
        use crate::bgp::vrf_config::MupSrv6Direction;
        use crate::mup_c::session::MupSession;
        use std::net::IpAddr;

        fn session(endpoint: Option<&str>, teid: u32) -> MupSession {
            MupSession {
                seid: 7,
                cp_seid: 0x1111,
                peer: "10.0.0.2:8805".parse().unwrap(),
                ue_ipv4: Some("192.0.2.5".parse().unwrap()),
                ue_ipv6: None,
                teid,
                endpoint: endpoint.map(|e| e.parse().unwrap()),
                core_teid: 0,
                core_endpoint: None,
                network_instance: Some("internet".to_string()),
                qfi: Some(9),
            }
        }

        let (global_tx, mut global_rx) = unbounded_channel::<BgpGlobalMsg>();
        let ctx = test_ctx_for_vrf(12, "vrf-ho");
        let (_rib_tx, rib_rx) = mpsc::unbounded_channel();
        let (mut vrf, _inbox) = BgpVrf::new(
            "vrf-ho".to_string(),
            ctx,
            Ipv4Addr::UNSPECIFIED,
            65000,
            /* label */ 16,
            global_tx,
            rib_rx,
        );

        // Establishment: one export, nothing withdrawn.
        vrf.process_global_msg(BgpVrfMsg::MupOriginate {
            session: session(Some("10.0.1.1"), 0x100),
            bindings: vec![(MupSrv6Direction::Encapsulation, None)],
        });
        let first = global_rx.try_recv().expect("establishment exports");
        let BgpGlobalMsg::MupExport {
            prefix: key,
            st1: Some(st1),
            ..
        } = first
        else {
            panic!("expected MupExport, got {first:?}");
        };
        assert_eq!(st1.teid, 0x100);
        assert!(
            global_rx.try_recv().is_err(),
            "establishment sends exactly one message"
        );

        // Handover: same seid + UE prefix, new endpoint/TEID.
        vrf.process_global_msg(BgpVrfMsg::MupOriginate {
            session: session(Some("10.0.2.1"), 0x200),
            bindings: vec![(MupSrv6Direction::Encapsulation, None)],
        });
        let second = global_rx.try_recv().expect("handover re-exports");
        let BgpGlobalMsg::MupExport {
            prefix: rekey,
            st1: Some(moved),
            ..
        } = second
        else {
            panic!("handover must re-export in place, got {second:?}");
        };
        assert_eq!(rekey, key, "handover keeps the RD-free ST1 key");
        assert_eq!(moved.teid, 0x200);
        assert_eq!(moved.endpoint, "10.0.2.1".parse::<IpAddr>().unwrap());
        assert!(
            global_rx.try_recv().is_err(),
            "no WithdrawMupExport around the handover re-export"
        );

        // The access tunnel drops out of the session → the ST1 no longer
        // builds → the prior export is withdrawn explicitly.
        vrf.process_global_msg(BgpVrfMsg::MupOriginate {
            session: session(None, 0),
            bindings: vec![(MupSrv6Direction::Encapsulation, None)],
        });
        let third = global_rx.try_recv().expect("unbuildable ST withdraws");
        let BgpGlobalMsg::WithdrawMupExport { prefix: gone, .. } = third else {
            panic!("expected WithdrawMupExport, got {third:?}");
        };
        assert_eq!(gone, key);
        assert!(global_rx.try_recv().is_err());
        assert!(
            vrf.mup_originated.is_empty(),
            "nothing is tracked once the session exports no ST"
        );
    }

    /// A VRF binding BOTH directions (single-N6 UPF, issue #1947) receives
    /// one `MupOriginate` carrying both bindings and exports the session's
    /// T1ST and T2ST together under its own RD. A handover that only moves
    /// the access tunnel withdraws nothing (both keys unchanged), and
    /// unbinding one direction (the next dispatch carries only the other)
    /// withdraws exactly that direction's export while the survivor
    /// re-exports.
    #[tokio::test]
    async fn mup_dual_direction_vrf_originates_and_reconciles_both_sts() {
        use crate::bgp::vrf_config::MupSrv6Direction;
        use crate::mup_c::session::MupSession;

        fn session(endpoint: &str, teid: u32) -> MupSession {
            MupSession {
                seid: 9,
                cp_seid: 0x2222,
                peer: "10.0.0.2:8805".parse().unwrap(),
                ue_ipv4: Some("192.0.2.5".parse().unwrap()),
                ue_ipv6: None,
                teid,
                endpoint: Some(endpoint.parse().unwrap()),
                core_teid: 0x9000,
                core_endpoint: Some("10.0.12.2".parse().unwrap()),
                network_instance: Some("internet".to_string()),
                qfi: Some(9),
            }
        }
        let both = || {
            vec![
                (MupSrv6Direction::Encapsulation, None),
                (MupSrv6Direction::Decapsulation, None),
            ]
        };
        fn recv_exports(
            rx: &mut tokio::sync::mpsc::UnboundedReceiver<BgpGlobalMsg>,
            n: usize,
        ) -> Vec<bgp_packet::MupPrefix> {
            let mut prefixes = Vec::new();
            for _ in 0..n {
                match rx.try_recv().expect("expected another MupExport") {
                    BgpGlobalMsg::MupExport { prefix, .. } => prefixes.push(prefix),
                    other => panic!("expected MupExport, got {other:?}"),
                }
            }
            assert!(rx.try_recv().is_err(), "no extra messages");
            prefixes
        }

        let (global_tx, mut global_rx) = unbounded_channel::<BgpGlobalMsg>();
        let ctx = test_ctx_for_vrf(13, "vrf-dual");
        let (_rib_tx, rib_rx) = mpsc::unbounded_channel();
        let (mut vrf, _inbox) = BgpVrf::new(
            "vrf-dual".to_string(),
            ctx,
            Ipv4Addr::UNSPECIFIED,
            65000,
            /* label */ 16,
            global_tx,
            rib_rx,
        );

        // Establishment: BOTH the T1ST and the T2ST export, nothing withdrawn.
        vrf.process_global_msg(BgpVrfMsg::MupOriginate {
            session: session("10.0.1.1", 0x100),
            bindings: both(),
        });
        let first = recv_exports(&mut global_rx, 2);
        assert!(
            first
                .iter()
                .any(|p| matches!(p, bgp_packet::MupPrefix::T1st { .. })),
            "dual-direction VRF exports the downlink T1ST"
        );
        assert!(
            first
                .iter()
                .any(|p| matches!(p, bgp_packet::MupPrefix::T2st { .. })),
            "dual-direction VRF exports the uplink T2ST"
        );
        assert_eq!(
            vrf.mup_originated.get(&9).map(Vec::len),
            Some(2),
            "both STs tracked under the one seid"
        );

        // Handover: the access tunnel moves, the core tunnel stays. Both
        // NLRI keys are unchanged (an ST1 keys on RD+Prefix alone), so both
        // re-export in place with NO withdraw — the old single-direction
        // bookkeeping would have withdrawn the sibling ST here.
        vrf.process_global_msg(BgpVrfMsg::MupOriginate {
            session: session("10.0.2.1", 0x200),
            bindings: both(),
        });
        recv_exports(&mut global_rx, 2);

        // Unbind st1 (the next dispatch carries only the st2 binding): the
        // T1ST is withdrawn explicitly, the T2ST re-exports.
        vrf.process_global_msg(BgpVrfMsg::MupOriginate {
            session: session("10.0.2.1", 0x200),
            bindings: vec![(MupSrv6Direction::Decapsulation, None)],
        });
        let mut saw_withdraw_t1 = false;
        let mut saw_export_t2 = false;
        while let Ok(msg) = global_rx.try_recv() {
            match msg {
                BgpGlobalMsg::WithdrawMupExport { prefix, .. } => {
                    assert!(matches!(prefix, bgp_packet::MupPrefix::T1st { .. }));
                    saw_withdraw_t1 = true;
                }
                BgpGlobalMsg::MupExport { prefix, .. } => {
                    assert!(matches!(prefix, bgp_packet::MupPrefix::T2st { .. }));
                    saw_export_t2 = true;
                }
                other => panic!("unexpected message {other:?}"),
            }
        }
        assert!(saw_withdraw_t1, "unbound st1's T1ST withdrawn");
        assert!(saw_export_t2, "surviving st2's T2ST re-exported");
        assert_eq!(
            vrf.mup_originated.get(&9).map(Vec::len),
            Some(1),
            "only the surviving direction stays tracked"
        );
    }
}
