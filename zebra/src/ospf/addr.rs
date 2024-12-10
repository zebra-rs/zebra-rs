use ipnet::Ipv4Net;

use crate::rib::link::LinkAddr;

#[derive(Default, Clone)]
pub struct OspfAddr {
    pub prefix: Ipv4Net,
    pub ifindex: u32,
}

impl OspfAddr {
    pub fn from(addr: &LinkAddr, prefix: &Ipv4Net) -> Self {
        Self {
            prefix: *prefix,
            ifindex: addr.ifindex,
        }
    }
}
