//! Per-VRF BGP runtime.
//!
//! Sibling of the global [`crate::bgp::Bgp`] runtime: one
//! [`BgpVrf`] task per `router bgp vrf X` block. The task shape
//! and lifecycle (message enums, event loop, channels to the
//! global task) live here, alongside `spawn_bgp_vrf` /
//! `despawn_bgp_vrf` (driven from the commit-time diff against
//! [`crate::bgp::Bgp::vrfs`]), per-VRF peer configure + active
//! connect via `ProtoContext::for_vrf`, passive accept dispatch
//! from the global task via `BgpVrfMsg::Accept`, and export to /
//! import from the global VPNv4 Loc-RIB across the
//! `BgpGlobalMsg` / `BgpVrfMsg` channels.

pub mod inst;
pub mod label;
pub mod msg;
pub mod spawn;

pub use label::VrfLabelAllocator;

// External consumers (`Bgp` field types, `process_vrf_global_msg`)
// only reach for the names below. `inst::{BgpVrf, serve_vrf}` and
// `msg::BgpVrfMsg` stay internal — they're constructed / consumed
// inside `vrf::spawn` only.
pub use inst::{
    VrfExporter, VrfImportDispatcher, dispatch_import_v4, dispatch_withdraw_import_v4,
    vrf_emit_export, vrf_emit_export_v6, vrf_emit_withdraw, vrf_emit_withdraw_v6,
};
pub use msg::BgpGlobalMsg;
pub use spawn::{BgpVrfHandle, compute_vrf_diff, despawn_bgp_vrf, spawn_bgp_vrf};
