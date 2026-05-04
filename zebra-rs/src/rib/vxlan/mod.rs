pub mod config;
pub use config::*;

pub mod builder;
pub use builder::*;

use std::net::IpAddr;

use super::AddrGenMode;

#[derive(Debug, Default, Clone)]
pub struct Vxlan {
    pub name: String,

    // VNI.
    pub vni: Option<u32>,

    // Local address.
    pub local_addr: Option<IpAddr>,

    // Destination port.
    pub dport: Option<u16>,

    // Address generation mode.
    pub addr_gen_mode: Option<AddrGenMode>,
}
