use ipnet::Ipv4Net;

use crate::rib::link::LinkAddr;

pub struct OspfAddr {
    prefix: Ipv4Net,
    ifindex: u32,
}

impl OspfAddr {
    pub fn from(addr: &LinkAddr, prefix: &Ipv4Net) -> Self {
        Self {
            prefix: *prefix,
            ifindex: addr.ifindex,
        }
    }
}
