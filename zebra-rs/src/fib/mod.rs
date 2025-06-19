#[cfg(target_os = "linux")]
pub mod netlink;
#[cfg(target_os = "linux")]
pub use netlink::*;

#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "macos")]
pub use macos::FibHandle;
#[cfg(target_os = "macos")]
pub use macos::fib_dump;
#[cfg(target_os = "macos")]
pub use macos::os_traffic_dump;

pub mod message;
pub use message::*;

pub use crate::rib::{LinkFlags, LinkType};
