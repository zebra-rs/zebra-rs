//! Message types crossing the boundary between the global
//! `Bgp` task and a per-VRF [`BgpVrf`] task.
//!
//! - [`BgpVrfMsg`] travels global → VRF. It carries handoffs from
//!   the global passive-accept dispatcher, VPNv4/v6 import
//!   deliveries from the global Loc-RIB, and the `Shutdown` signal
//!   that ends the VRF task's event loop.
//! - [`BgpGlobalMsg`] travels VRF → global. It carries the
//!   inverse: best-path exports the global task should re-emit as
//!   VPNv4/v6, peer registration so the global accept dispatcher
//!   knows which VRF to forward a given source IP to, and the
//!   matching withdraw/unregister events.

use std::net::SocketAddr;

use ipnet::{Ipv4Net, Ipv6Net};
use tokio::net::TcpStream;

use bgp_packet::{BgpAttr, RouteDistinguisher};

use crate::rib::nht::ResolvedNexthop;

/// Message from the global `Bgp` task to a per-VRF [`BgpVrf`]
/// task. The receiver lives on `BgpVrf::global_rx`.
#[derive(Debug)]
pub enum BgpVrfMsg {
    /// Inbound TCP connection accepted on `:179` whose source IP
    /// matches a peer configured in this VRF. The global accept
    /// dispatcher hands the stream off here; `process_global_msg`
    /// drives it through the per-VRF passive-accept FSM path
    /// (`peer::handle_peer_connection` against the VRF's own peers).
    Accept(TcpStream, SocketAddr),

    /// VPNv4 best-path import. The global Loc-RIB resolved a route
    /// whose RT list intersects this VRF's `import_rts_v4`; the
    /// per-VRF task strips the RD and inserts the route into its
    /// own IPv4 unicast Loc-RIB. `attr` travels by value so the
    /// per-VRF task can re-intern into its own `BgpAttrStore`
    /// without locking; `label` is the per-VRF MPLS label the
    /// originator advertised.
    ImportV4 {
        rd: RouteDistinguisher,
        prefix: ipnet::Ipv4Net,
        attr: BgpAttr,
        label: u32,
        /// Resolved transport egress(es) for the remote PE next-hop,
        /// from the global NHT cache. The per-VRF task pushes the VPN
        /// service `label` (inner) plus each egress's transport labels
        /// (outer) and installs the result into the VRF FIB. Empty for
        /// a label-less / unresolved transport (no FIB install).
        transport: Vec<ResolvedNexthop>,
    },

    /// Withdraw a previously-imported route. RD identifies the
    /// origin row; the per-VRF task locates the matching imported
    /// path and runs best-path withdraw.
    WithdrawImport {
        rd: RouteDistinguisher,
        prefix: ipnet::Ipv4Net,
    },

    /// A MUP (SAFI 85) best-path the global Loc-RIB selected whose route
    /// targets match this VRF's `mup_import_rts` (RT-import, dispatched via
    /// [`super::inst::dispatch_mup`]). The per-VRF task imports it
    /// authoritatively into its own per-RD MUP Loc-RIB and best-paths it, so
    /// `show bgp vrf <name> mup` (which the manager redirects into this task)
    /// renders the VRF's imported MUP routes. The global `Bgp` instance
    /// remains the BGP-peer advertiser (MUP has no CE peers); the per-VRF
    /// task owns only the control-plane RIB — no re-advertise, no FIB yet.
    MupUpdate {
        rd: RouteDistinguisher,
        prefix: bgp_packet::MupPrefix,
        rib: crate::bgp::route::BgpRib,
        /// Resolved underlay transport for the route's next-hop, when the
        /// global instance has NHT-resolved it (currently only populated
        /// for a received DSD, whose next-hop the ST2→DSD encap install
        /// resolves through). Empty for locally-originated routes and for
        /// route types the install doesn't steer. Mirrors `ImportV4`'s
        /// `transport`.
        transport: Vec<ResolvedNexthop>,
        /// Resolved v4 underlay transport for a Type-1 ST route's GTP endpoint
        /// (gNB), when the global instance has NHT-resolved it
        /// (register-then-gate on `st1.endpoint`). Consumed by the `dataplane
        /// gtp` downlink reconcile to fill the cradle `GTP4.E` encap nexthop's
        /// underlay gateway/oif. Empty for non-ST1 routes and unresolved
        /// endpoints.
        endpoint_transport: Vec<ResolvedNexthop>,
    },
    /// Withdraw a previously-imported MUP route (the global RIB no longer has
    /// a selected path for it). Flooded to every VRF; the per-VRF removal is
    /// idempotent for a VRF that never imported the prefix.
    MupWithdraw {
        rd: RouteDistinguisher,
        prefix: bgp_packet::MupPrefix,
    },

    /// Originate the controller Session-Transformed (ST1/ST2) routes in this
    /// VRF (VRF-first MUP origination). The global task correlates a PFCP
    /// session's Network Instance to the matching VRF(s) and forwards the
    /// session here with every matched direction binding (st1=Encapsulation /
    /// st2=Decapsulation, each with its optional st2 Direct-segment
    /// ext-comm) — one message per (VRF, session) carrying the VRF's full
    /// desired direction set. A VRF binding both directions (single-N6 UPF,
    /// issue #1947) builds both the T1ST and the T2ST here; the classic
    /// two-VRF split gets one binding each. The per-VRF task builds the
    /// **RD-free** ST NLRIs and emits [`BgpGlobalMsg::MupExport`]; the global
    /// export handler applies the RD, export route-targets and controller
    /// next-hop. A repeat for a known seid (PFCP Modification) reconciles
    /// against the prior exports: an unchanged NLRI key re-exports in place —
    /// an ST1 keys on RD+Prefix alone, so a handover's new TEID/QFI/endpoint
    /// replaces without a withdraw — and only a prior export whose key is no
    /// longer built (changed key, or its direction unbound since) is
    /// withdrawn explicitly.
    MupOriginate {
        session: crate::mup_c::session::MupSession,
        bindings: Vec<(
            crate::bgp::vrf_config::MupSrv6Direction,
            Option<RouteDistinguisher>,
        )>,
    },

    /// Withdraw every ST route this VRF originated for `seid` (PFCP Session
    /// Deletion or association teardown; a Modification instead replaces via
    /// [`Self::MupOriginate`]). Broadcast to every VRF; the per-VRF removal
    /// is idempotent for a VRF that never originated for this session.
    MupWithdrawOriginate { seid: u64 },

    /// Originate (or refresh) this VRF's MUP Segment Discovery route — a DSD
    /// (`Direct`) or ISD (`Interwork`) (VRF-first segment origination). The
    /// global task gates on the SID / locator / kernel-VRF / RD being ready
    /// and sends the resolved segment config; the per-VRF task builds the
    /// RD-free segment NLRI (DSD = its router-id, ISD = `interwork_prefix`)
    /// and emits [`BgpGlobalMsg::MupExport`]. The global export handler stamps
    /// the RD, export route-targets, locator next-hop and End.DT46
    /// Prefix-SID. A VRF has at most one segment, so a new `MupSegmentOriginate`
    /// replaces a prior one (the per-VRF task withdraws the old NLRI if the
    /// key changed — a direct↔interwork switch or router-id change).
    MupSegmentOriginate {
        mode: crate::bgp::vrf_config::MupSegmentMode,
        ext_comm: Option<RouteDistinguisher>,
        interwork_prefix: Option<ipnet::IpNet>,
    },

    /// Withdraw this VRF's MUP Segment Discovery route (a SID / locator /
    /// kernel-VRF / config precondition dropped). Idempotent for a VRF that
    /// never originated a segment.
    MupSegmentWithdraw,

    /// VPNv6 counterpart of [`Self::ImportV4`] — a VPNv6 route whose
    /// RT list intersects this VRF's `import_rts_v6`; inserted into
    /// the VRF's IPv6 unicast Loc-RIB and advertised to CE peers.
    ImportV6 {
        rd: RouteDistinguisher,
        prefix: ipnet::Ipv6Net,
        attr: BgpAttr,
        label: u32,
        /// Resolved transport egress(es) for the remote PE next-hop —
        /// VPNv6 counterpart of [`Self::ImportV4`]'s `transport`.
        transport: Vec<ResolvedNexthop>,
    },

    /// VPNv6 counterpart of [`Self::WithdrawImport`].
    WithdrawImportV6 {
        rd: RouteDistinguisher,
        prefix: ipnet::Ipv6Net,
    },

    /// Originate one self-network into the running VRF's Loc-RIB
    /// (`router bgp vrf X afi-safi ipv4 network <p>` added *after*
    /// the VRF task spawned). [`super::compute_vrf_diff`] only
    /// spawns / despawns on the VRF *name* set, so a `network`
    /// change to an already-running VRF never reaches it through the
    /// spawn path — it arrives here instead. The not-yet-spawned
    /// case is still handled by the spawn-time materialize.
    OriginateNetwork { prefix: Ipv4Net },

    /// Inverse of [`Self::OriginateNetwork`]: a `network` was
    /// removed from a running VRF. Drop the self-originated row
    /// (ident 0 / remote 0) from the VRF Loc-RIB and emit
    /// `BgpGlobalMsg::WithdrawExport` so the global instance
    /// withdraws the VPNv4 advertisement.
    WithdrawNetwork { prefix: Ipv4Net },

    /// IPv6 counterpart of [`Self::OriginateNetwork`].
    OriginateNetworkV6 { prefix: Ipv6Net },

    /// IPv6 counterpart of [`Self::WithdrawNetwork`].
    WithdrawNetworkV6 { prefix: Ipv6Net },

    /// A `redistribute {connected,static}` source was enabled for this
    /// VRF/AFI on a running task. The task sends `Message::RedistAdd`
    /// to the RIB (proto `bgp:vrf:<name>`, vrf_id = this VRF's table
    /// id), so the RIB walks `vrf_tables[table_id]` and streams the
    /// matching routes back on `rib_rx` for origination + VPN export.
    RedistEnable {
        afi: crate::rib::RedistAfi,
        source: crate::bgp::config::BgpRedistSource,
    },

    /// Inverse of [`Self::RedistEnable`]: a redistribute source was
    /// removed. The task sends `Message::RedistDel`; the RIB replays
    /// the matching prefixes as `RouteDel` so the task withdraws them.
    RedistDisable {
        afi: crate::rib::RedistAfi,
        source: crate::bgp::config::BgpRedistSource,
    },

    /// Snapshot of the global colour-steering state (Color→Flex-Algo
    /// bindings + the per-algo SRv6 End-SID shadow) so the per-VRF FIB
    /// install can steer imported SRv6 L3VPN routes into a Flex-Algo.
    /// The shadow is rebuilt on every IS-IS SPF; the global task
    /// re-sends this on change (and once at VRF spawn). Both travel by
    /// value so the VRF task owns its copy without locking the global.
    ColourSteering {
        color_policy: crate::bgp::color_policy::ColorPolicy,
        srv6_shadow: crate::bgp::color_policy::FlexAlgoSrv6Shadow,
    },

    /// Snapshot of the instance-wide `router bgp tracing { … }` config,
    /// so the per-VRF task's gated trace sites (`bgp_vpn_trace!`,
    /// `bgp_vrf_trace!`) can read it. The per-VRF `ConfigChannel` only
    /// receives `/router/bgp/vrf/<name>/…` paths, so an instance-scoped
    /// `/router/bgp/tracing/…` edit can't reach the task by config
    /// dispatch — the global task mirrors it here on every change, the
    /// same way `ColourSteering` mirrors the colour shadow. Spawn-time
    /// initialisation goes through `spawn_bgp_vrf` instead, so a VRF
    /// task never runs a single event with a stale snapshot.
    Tracing(crate::bgp::tracing::BgpTracing),

    /// Tear the VRF task down cleanly. The event loop exits on the
    /// next select iteration after receiving this. Used by
    /// `despawn_bgp_vrf` and during daemon shutdown.
    Shutdown,
}

/// Message from a per-VRF [`BgpVrf`] task to the global `Bgp`
/// task. The receiver lives on the global task; each VRF holds an
/// `UnboundedSender<BgpGlobalMsg>` in `BgpVrf::global_tx`.
#[derive(Debug)]
pub enum BgpGlobalMsg {
    /// A best-path winner inside this VRF that the global task
    /// should re-emit as VPNv4. The VRF name lets the global side
    /// look up the matching RD (from `Bgp::vrfs`) and the export
    /// RT set (from `Bgp::rib_known_vrfs`). `attr` travels by
    /// value — the receiver re-interns into its own
    /// `BgpAttrStore`. `label` is a per-VRF MPLS label; callers
    /// without an allocator may pass `0`, which the global instance
    /// treats as "no label yet" (skip the install until a real
    /// label arrives).
    Export {
        vrf: String,
        prefix: Ipv4Net,
        attr: BgpAttr,
        label: u32,
    },

    /// Inverse of [`Self::Export`]. The global instance withdraws
    /// the VPNv4 advertisement matching this VRF's RD and the
    /// given prefix.
    WithdrawExport { vrf: String, prefix: Ipv4Net },

    /// VPNv6 counterpart of [`Self::Export`] — an IPv6 unicast
    /// best-path winner in this VRF that the global task re-emits as
    /// VPNv6 (and, once 3b lands, leaks into sibling VRFs).
    ExportV6 {
        vrf: String,
        prefix: Ipv6Net,
        attr: BgpAttr,
        label: u32,
    },

    /// Inverse of [`Self::ExportV6`].
    WithdrawExportV6 { vrf: String, prefix: Ipv6Net },

    /// A controller ST route this VRF originated (VRF-first MUP), for the
    /// global task to promote into the SAFI-85 Loc-RIB and advertise. The
    /// VRF name lets the global side resolve the RD (from `Bgp::vrfs`), the
    /// export route-targets (from `Bgp::rib_known_vrfs`) and the controller
    /// next-hop (from `Bgp::mup_c_config`) — applied at this export boundary,
    /// mirroring [`Self::Export`] for VPNv4. `prefix` is RD-free; `attr`
    /// carries only route-specific extended communities (e.g. the st2
    /// Direct-segment id), no RD / RT / next-hop.
    MupExport {
        vrf: String,
        prefix: bgp_packet::MupPrefix,
        /// The ST1 (Type-1 Session-Transformed) off-key NLRI fields
        /// (draft §3.2.1), when `prefix` is a `MupPrefix::T1st`. Stamped onto
        /// the originated path so the global re-advertise / FIB reconcile see
        /// the real TEID/QFI/endpoint. `None` for DSD/ISD/ST2.
        st1: Option<bgp_packet::MupSt1Fields>,
        attr: BgpAttr,
    },

    /// Inverse of [`Self::MupExport`]. The global instance removes the
    /// originated ST route under this VRF's RD and re-runs best-path.
    WithdrawMupExport {
        vrf: String,
        prefix: bgp_packet::MupPrefix,
    },

    /// Register a peer IP with the global accept dispatcher so an
    /// inbound `:179` connect from that IP is handed to this VRF
    /// via [`BgpVrfMsg::Accept`]. Emitted by the per-VRF spawn
    /// site for every materialised peer.
    RegisterPeer { vrf: String, addr: std::net::IpAddr },
}
