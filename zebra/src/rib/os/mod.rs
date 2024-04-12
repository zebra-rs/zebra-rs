#[cfg(target_os = "linux")]
pub mod netlink;
#[cfg(target_os = "linux")]
pub use netlink::spawn_os_dump;

#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "macos")]
pub use macos::spawn_os_dump;

pub mod message;

pub use super::{LinkFlags, LinkType};
