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

/// Message from the global `Bgp` task to a per-VRF [`BgpVrf`]
/// task. The receiver lives on `BgpVrf::global_rx`.
#[derive(Debug)]
pub enum BgpVrfMsg {
    /// Inbound TCP connection accepted on `:179` whose source IP
    /// matches a peer configured in this VRF. The stream is handed
    /// off to the per-VRF runtime; until the per-VRF FSM driver
    /// picks it up, `BgpVrf::event_loop` drops the stream silently
    /// — the dispatch is still wired so the global instance's
    /// accept path no longer claims connections that should belong
    /// to a VRF.
    Accept(#[allow(dead_code)] TcpStream, SocketAddr),

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
    },

    /// Withdraw a previously-imported route. RD identifies the
    /// origin row; the per-VRF task locates the matching imported
    /// path and runs best-path withdraw.
    WithdrawImport {
        rd: RouteDistinguisher,
        prefix: ipnet::Ipv4Net,
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
