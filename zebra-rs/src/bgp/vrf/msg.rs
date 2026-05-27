//! Message types crossing the boundary between the global
//! `Bgp` task and a per-VRF [`BgpVrf`] task.
//!
//! - [`BgpVrfMsg`] travels global → VRF. It carries handoffs from
//!   the global passive-accept dispatcher (step 16), VPNv4/v6
//!   import deliveries from the global Loc-RIB (step 18), and the
//!   `Shutdown` signal that ends the VRF task's event loop.
//! - [`BgpGlobalMsg`] travels VRF → global. It carries the
//!   inverse: best-path exports the global task should re-emit as
//!   VPNv4/v6 (step 17), peer registration so the global accept
//!   dispatcher knows which VRF to forward a given source IP to
//!   (step 16), and the matching withdraw/unregister events.
//!
//! Step 13 landed the enums with `Shutdown` and `Accept`
//! populated; step 14 drains `BgpGlobalMsg` in the global event
//! loop (`process_vrf_global_msg`) and uses `Shutdown` from
//! `despawn_bgp_vrf`. Step 16's accept dispatcher emits `Accept`
//! though the per-VRF FSM driver (step 15d) doesn't yet consume
//! the stream; the field carries an `#[allow(dead_code)]` until
//! that lands.

use std::net::SocketAddr;

use ipnet::Ipv4Net;
use tokio::net::TcpStream;

use bgp_packet::{BgpAttr, RouteDistinguisher};

/// Message from the global `Bgp` task to a per-VRF [`BgpVrf`]
/// task. The receiver lives on `BgpVrf::global_rx`.
#[derive(Debug)]
pub enum BgpVrfMsg {
    /// Inbound TCP connection accepted on `:179` whose source IP
    /// matches a peer configured in this VRF. The stream is handed
    /// off to the per-VRF runtime; the per-VRF FSM driver (step
    /// 15d) picks up here. Until that lands, `BgpVrf::event_loop`
    /// drops the stream silently — step 16 still wires the
    /// dispatch so the global instance's accept path no longer
    /// claims connections that should belong to a VRF.
    Accept(
        #[allow(dead_code)] // first reader lands in step 15d.
        TcpStream,
        SocketAddr,
    ),

    /// VPNv4 best-path import. The global Loc-RIB resolved a route
    /// whose RT list intersects this VRF's `import_rts_v4`; the
    /// per-VRF task strips the RD and inserts the route into its
    /// own IPv4 unicast Loc-RIB. `attr` travels by value so the
    /// per-VRF task can re-intern into its own `BgpAttrStore`
    /// without locking; `label` is the per-VRF MPLS label the
    /// originator advertised (step 19 wires the matching ILM
    /// install). Step 18a delivers the payload but the per-VRF
    /// handler is still a log-only stub — the LocRIB write lands
    /// in step 18b.
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
    /// next select iteration after receiving this. Used by step
    /// 14's `despawn_bgp_vrf` and during daemon shutdown.
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
    /// `BgpAttrStore`. `label` is a per-VRF MPLS label allocated
    /// by step 19; step 17b passes `0` as a stub and the global
    /// instance treats that as "no label yet" (skip the install
    /// until a real label arrives).
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

    /// Register a peer IP with the global accept dispatcher so an
    /// inbound `:179` connect from that IP is handed to this VRF
    /// via [`BgpVrfMsg::Accept`]. Emitted by step 16's spawn
    /// site for every materialised peer.
    RegisterPeer { vrf: String, addr: std::net::IpAddr },
}
