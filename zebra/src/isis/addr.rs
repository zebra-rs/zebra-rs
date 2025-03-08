use ipnet::Ipv4Net;

use crate::rib::link::LinkAddr;

#[derive(Debug, Default, Clone)]
pub struct IsisAddr {
    prefix: Ipv4Net,
    ifindex: u32,
}

impl IsisAddr {
    pub fn from(addr: &LinkAddr, prefix: &Ipv4Net) -> Self {
        Self {
            prefix: *prefix,
            ifindex: addr.ifindex,
        }
    }
}
