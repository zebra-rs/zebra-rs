use ipnet::Ipv4Net;

use crate::rib::link::LinkAddr;

#[derive(Debug, Default, Clone)]
pub struct IsisAddr {
    pub prefix: Ipv4Net,
    pub ifindex: u32,
}

impl IsisAddr {
    pub fn from(addr: &LinkAddr, prefix: &Ipv4Net) -> Self {
        Self {
            prefix: *prefix,
            ifindex: addr.ifindex,
        }
    }
}
