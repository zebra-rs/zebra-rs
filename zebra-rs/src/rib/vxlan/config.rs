use std::net::IpAddr;

use crate::rib::AddrGenMode;

#[derive(Default, Debug, Clone)]
pub struct VxlanConfig {
    // Vxlan configuration structure
    pub delete: bool,

    // VNI.
    pub vni: Option<u32>,

    // Local address.
    pub local_addr: Option<IpAddr>,

    // Destination port.
    pub dport: Option<u16>,

    // Address generation mode.
    pub addr_gen_mode: Option<AddrGenMode>,
}
