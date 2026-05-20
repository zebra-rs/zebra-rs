pub mod api;
pub use api::RibRxChannel;

pub mod inst;
pub use inst::{Message, Rib, serve};

pub mod link;
pub use link::{Link, LinkType};

pub mod link_ext;
pub use link_ext::LinkFlagsExt;

pub mod entry;
pub use entry::RibEntries;

pub mod route;

pub mod nexthop;
pub use nexthop::*;

pub mod show;

pub mod srv6;

pub mod types;
pub use types::{BulkPhase, RedistAfi, RibSubType, RibType, RouteBatch};
// `RouteEntryV4`, `RouteEntryV6`, and `REDIST_BATCH_MAX` are re-exported
// once the RIB walker (and the per-protocol consumers that construct
// `RouteBatch::V4(vec![RouteEntryV4 { … }])`) land in follow-up PRs.

pub mod util;

pub mod r#static;
pub use r#static::*;

pub mod mpls;
pub use mpls::*;

pub mod resolve;

// pub mod nanomsg;

pub mod router_id;

pub mod mac_addr;
pub use mac_addr::*;

pub mod logging;
pub use logging::*;

pub mod bridge;
pub use bridge::*;

pub mod vxlan;
pub use vxlan::*;

pub mod vrf;
pub use vrf::*;

pub mod addr_gen_mode;
pub use addr_gen_mode::*;

pub mod segment_routing;
pub use segment_routing::*;

pub mod srlg;
pub use srlg::*;
