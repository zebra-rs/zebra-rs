pub mod api;
// `RibRxChannel` is no longer re-exported at the rib crate root —
// every external caller now obtains the rx half via
// `ConfigManager::subscribe_to_rib`. Test code that needs the raw
// channel reaches it as `crate::rib::api::RibRxChannel`.

pub mod client;
// Re-exports intentionally omitted — the binary crate has no
// external consumer that would benefit from re-exporting these
// names; using `crate::rib::client::*` from callsites avoids
// `unused_imports`.

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
pub use types::{
    BulkPhase, RedistAfi, RibSubType, RibType, RouteBatch, RouteEntryV4, RouteEntryV6,
};
// `REDIST_BATCH_MAX` stays unexported — only the RIB walker constructs
// pre-sized batches; consumers receive them already chunked.

pub mod redist;

pub mod util;

pub mod r#static;
pub use r#static::*;

pub mod mpls;
pub use mpls::*;

pub mod resolve;

pub mod nht;

pub mod label_manager;

// pub mod nanomsg;

pub mod router_id;

pub mod mac_addr;
pub use mac_addr::*;

pub mod logging;
pub use logging::*;

pub mod tracing;

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

pub mod evpn_replicate;
