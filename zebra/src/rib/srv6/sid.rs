use std::net::Ipv6Addr;

pub enum SidFormat {}

pub struct Sid {
    sid: Ipv6Addr,
}

impl Sid {
    pub fn locator_get(&self) -> u64 {
        0u64
    }
}
