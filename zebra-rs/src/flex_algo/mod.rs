//! Protocol-neutral Flexible Algorithm (RFC 9350) core, shared by
//! IS-IS and OSPF.
//!
//! Holds the configured per-algorithm definition (`FlexAlgoEntry`),
//! the FAD link-admission constraint engine (`link_passes_fad`), and
//! the `AffinityBits` extension point each protocol's affinity-map
//! table implements. The wire codecs (isis-packet / ospf-packet
//! sub-TLVs) and the config-callback shims stay in each protocol
//! module; only the pure data model and constraint logic live here.

pub mod affinity_map;
pub mod config;
pub mod constraint;
pub mod entry;
pub mod participation;
pub mod selection;
pub mod srlg;

pub use affinity_map::AffinityMap;
pub use config::{FlexAlgoConfig, sr_algorithms, sr_algorithms_for};
pub use constraint::{
    AffinityBits, FadConstraints, LinkAttrs, LossPercent, Pruned, link_passes_fad,
    link_prune_reason, local_link_affinity,
};
pub use entry::{FadMetricType, FlexAlgoEntry, check_max_link_loss};
pub use participation::{Participation, Unsupported};
pub use srlg::{SrlgGroup, SrlgGroupBuilder};
