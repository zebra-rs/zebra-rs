//! Global Shared Risk Link Group (SRLG) table. The RIB is the
//! authoritative owner — operator config under `/srlg/group/...` lands
//! here, and protocol modules (IS-IS, OSPF) subscribe to receive the
//! full table each time it changes. The per-protocol per-interface
//! `srlg` leaf-list references entries here by name; the protocol
//! resolves names against its cached table when building its LSAs /
//! LSPs.

use std::collections::BTreeMap;

pub mod group;
pub use group::{SrlgGroup, SrlgGroupBuilder};
// `SrlgGroupConfig` is intentionally not re-exported — it's an
// implementation detail of the staging machinery inside `group.rs`
// and never crosses the rib module boundary.

/// Subscription-channel return type from RIB to a protocol module.
/// Carries the full SRLG group table — subscribers replace their
/// local cache wholesale. Enum-wrapped to leave room for delta-style
/// pushes later without changing the channel signature, mirroring the
/// shape of `RibSrRx`.
///
/// The `Table` payload is `#[allow(dead_code)]` until the IS-IS
/// subscriber lands (next task) destructures it.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum RibSrlgRx {
    /// Full snapshot of the current `Rib::srlg_groups`. Emitted on
    /// subscribe and after every commit that touched any group.
    Table(BTreeMap<String, SrlgGroup>),
}
