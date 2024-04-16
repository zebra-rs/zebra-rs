#[cfg(target_os = "linux")]
pub mod netlink;
#[cfg(target_os = "linux")]
pub use netlink::os_dump_spawn;
#[cfg(target_os = "linux")]
pub use netlink::os_traffic_dump;
#[cfg(target_os = "linux")]
pub use netlink::route_add;
#[cfg(target_os = "linux")]
pub use netlink::route_del;

#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "macos")]
pub use macos::os_dump_spawn;
#[cfg(target_os = "macos")]
pub use macos::os_traffic_dump;
#[cfg(target_os = "macos")]
pub use macos::route_add;
#[cfg(target_os = "macos")]
pub use macos::route_del;

pub mod message;

pub use super::{LinkFlags, LinkType};
