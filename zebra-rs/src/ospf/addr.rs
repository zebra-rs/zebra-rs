use ipnet::Ipv4Net;

use crate::rib::link::LinkAddr;

#[derive(Debug, Default, Clone)]
pub struct OspfAddr {
    pub prefix: Ipv4Net,
}

impl OspfAddr {
    pub fn from(_addr: &LinkAddr, prefix: &Ipv4Net) -> Self {
        Self { prefix: *prefix }
    }
}
