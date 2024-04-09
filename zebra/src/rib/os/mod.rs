#[cfg(target_os = "linux")]
pub mod netlink;

#[cfg(target_os = "macos")]
pub mod macos;

pub mod message;

pub use super::LinkFlags;
