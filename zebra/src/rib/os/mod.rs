#[cfg(target_os = "linux")]
pub mod netlink;
#[cfg(target_os = "linux")]
pub use netlink::os_dump_spawn;
#[cfg(target_os = "linux")]
pub use netlink::os_traffic_dump;

#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "macos")]
pub use macos::os_dump_spawn;
#[cfg(target_os = "macos")]
pub use macos::os_traffic_dump;

pub mod message;

pub use super::{LinkFlags, LinkType};
