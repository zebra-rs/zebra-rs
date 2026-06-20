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

    /// Register a peer IP with the global accept dispatcher so an
    /// inbound `:179` connect from that IP is handed to this VRF
    /// via [`BgpVrfMsg::Accept`]. Emitted by the per-VRF spawn
    /// site for every materialised peer.
    RegisterPeer { vrf: String, addr: std::net::IpAddr },
}
