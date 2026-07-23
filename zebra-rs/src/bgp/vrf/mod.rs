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
pub mod sid;
pub mod spawn;

pub use label::VrfLabelAllocator;
pub use sid::{BgpSidPool, Srv6VrfSid};

// External consumers (`Bgp` field types, `process_vrf_global_msg`)
// only reach for the names below. `inst::{BgpVrf, serve_vrf}` and
// `msg::BgpVrfMsg` stay internal — they're constructed / consumed
// inside `vrf::spawn` only.
pub use inst::{
    VrfExporter, VrfImportDispatcher, dispatch_import_v4, dispatch_import_v6, dispatch_mup,
    dispatch_mup_segment, dispatch_mup_session, dispatch_withdraw_import_v4,
    dispatch_withdraw_import_v6, vrf_emit_export, vrf_emit_export_v6, vrf_emit_withdraw,
    vrf_emit_withdraw_v6, withdraw_mup_segment, withdraw_mup_session,
};
pub use msg::BgpGlobalMsg;
pub use spawn::{
    BgpVrfHandle, compute_vrf_diff, compute_vrf_respawn, despawn_bgp_vrf, spawn_bgp_vrf,
};
