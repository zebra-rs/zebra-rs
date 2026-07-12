pub mod config;
pub use config::*;

pub mod builder;
pub use builder::*;

use std::net::IpAddr;

use super::{AddrGenMode, MacAddr};

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

    // Tenant VRF this device is an L3VNI for (EVPN symmetric IRB). When
    // set, the VNI binds to the VRF's FIB in the cradle data plane instead
    // of an L2 bridge domain.
    pub vrf: Option<String>,

    // Router-MAC advertised/rewritten for this L3VNI. Defaults to the VRF
    // master device MAC when unset.
    pub router_mac: Option<MacAddr>,
}
