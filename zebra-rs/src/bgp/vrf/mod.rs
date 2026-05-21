//! Per-VRF BGP runtime (step 13 of the BGP MPLS/VPN refactor).
//!
//! Sibling of the global [`crate::bgp::Bgp`] runtime: one
//! [`BgpVrf`] task per `router bgp vrf X` block. Step 13 lays down
//! the task shape and lifecycle — message enums, the event loop,
//! channels to the global task — without wiring peers or the
//! import/export pipeline. Subsequent steps fill those in:
//!
//! * step 14 — `spawn_bgp_vrf` / `despawn_bgp_vrf` from the
//!   commit-time diff against [`crate::bgp::Bgp::vrfs`].
//! * step 15 — per-VRF peer configure + active connect via
//!   `ProtoContext::for_vrf` (the per-VRF socket binding gets
//!   exercised end-to-end here).
//! * step 16 — passive accept dispatch from the global task to the
//!   matching VRF via `BgpVrfMsg::Accept`.
//! * step 17 / 18 — export to / import from the global VPNv4
//!   Loc-RIB across the `BgpGlobalMsg` / `BgpVrfMsg` channels.

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
    vrf_emit_export, vrf_emit_withdraw,
};
pub use msg::BgpGlobalMsg;
pub use spawn::{BgpVrfHandle, compute_vrf_diff, despawn_bgp_vrf, spawn_bgp_vrf};
