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
//! Step 13 lands the enums with `Shutdown` / `Accept` populated;
//! every other variant is a stub waiting on its consumer. Adding
//! the variants now keeps the channel typing stable across later
//! steps — adding a variant to a public enum that other modules
//! `match` exhaustively is the only kind of change that would
//! force a wide refactor at step 16/17/18.
//!
//! The module-level allow goes away when step 14 wires the
//! cross-task channel ends to real producers / consumers.
#![allow(dead_code)]

use std::net::SocketAddr;

use tokio::net::TcpStream;

use bgp_packet::RouteDistinguisher;

/// Message from the global `Bgp` task to a per-VRF [`BgpVrf`]
/// task. The receiver lives on `BgpVrf::global_rx`.
#[derive(Debug)]
pub enum BgpVrfMsg {
    /// Inbound TCP connection accepted on `:179` whose source IP
    /// matches a peer configured in this VRF. The stream is handed
    /// off to the per-VRF runtime, which continues the FSM on its
    /// own task. Populated by step 16's accept dispatcher; the
    /// step-13 event loop just drops the connection.
    #[allow(dead_code)]
    Accept(TcpStream, SocketAddr),

    /// VPNv4 best-path import. The global Loc-RIB resolved a route
    /// whose RT list intersects this VRF's import-RT set; the per-
    /// VRF task inserts it into its IPv4 unicast Loc-RIB and runs
    /// best-path. Payload shape lands with step 18.
    #[allow(dead_code)]
    ImportV4 {
        rd: RouteDistinguisher,
        // step 18 fills the remaining fields: prefix, BgpAttr id,
        // label, peer ident, etc.
    },

    /// VPNv6 best-path import. Symmetric to [`Self::ImportV4`].
    #[allow(dead_code)]
    ImportV6 {
        rd: RouteDistinguisher,
        // step 18 fills the remaining fields.
    },

    /// Withdraw a previously-imported route. RD identifies the
    /// origin row; the per-VRF task locates the matching imported
    /// path and runs best-path withdraw.
    #[allow(dead_code)]
    WithdrawImport { rd: RouteDistinguisher },

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
    /// should re-emit as VPNv4/v6 (step 17). Carries the VRF name
    /// so the global task can look up the RD/RT policy when
    /// re-encoding the NLRI.
    #[allow(dead_code)]
    Export {
        vrf: String,
        // step 17 fills prefix, BgpAttr id, label, etc.
    },

    /// Inverse of [`Self::Export`]. Tells the global task to
    /// withdraw the corresponding VPNv4/v6 advertisement.
    #[allow(dead_code)]
    WithdrawExport {
        vrf: String,
        // step 17 fills the prefix identifier.
    },

    /// Register a peer IP with the global accept dispatcher so an
    /// inbound `:179` connect from that IP is handed to this VRF
    /// via [`BgpVrfMsg::Accept`]. Emitted by step 15 / 16 when a
    /// passive peer is configured in this VRF.
    #[allow(dead_code)]
    RegisterPeer { vrf: String, addr: std::net::IpAddr },

    /// Inverse of [`Self::RegisterPeer`]. The global dispatcher
    /// stops routing inbound connects from this IP to the VRF.
    #[allow(dead_code)]
    UnregisterPeer { vrf: String, addr: std::net::IpAddr },
}
