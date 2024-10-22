pub mod api;
pub use api::RibTxChannel;

pub mod inst;
pub use inst::{serve, Rib};

pub mod link;
pub use link::{Link, LinkFlags, LinkType};

pub mod entry;

pub mod route;

pub mod nexthop;
pub mod nexthop_map;

pub mod config;

pub mod show;

pub mod fib;

pub mod srv6;

pub mod static_config;
pub use static_config::{static_config_commit, static_config_exec};
pub mod static_route;
pub use static_route::StaticRoute;
