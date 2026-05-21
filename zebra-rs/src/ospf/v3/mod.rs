//! OSPFv3 protocol-side implementation.
//!
//! Hybrid layout per the Phase 6 plan: this module owns the
//! v3-specific instance, link, neighbor, LSDB, and FSM state. The
//! `OspfVersion` trait (in `super::version`), the v3 wire codec
//! (in the `ospf-packet` crate), the v6 socket primitives (in
//! `super::socket`), the v6 network read/write loops (in
//! `super::network_v6`), and the SPF Dijkstra (in `crate::spf`)
//! are all shared with v2 — only the protocol logic that has to
//! differ lives here.
//!
//! Most of this module's types are introduced incrementally across
//! Phase 6 PRs; this first PR adds only the instance spine.

// `dead_code` and `unused_imports` allow-attributes cover the
// fact that nothing constructs an `Ospfv3Instance` yet — the
// daemon's main spawn path comes in a later PR. The re-export
// below is the intended public surface for that future caller.
#![allow(dead_code, unused_imports)]

pub mod inst;
pub use inst::{Ospfv3Instance, serve};
