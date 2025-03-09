use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

#[derive(Debug, PartialEq, Clone, Copy)]
pub struct Identity {
    pub prefix: Ipv4Net,
    pub router_id: Ipv4Addr,
    pub d_router: Ipv4Addr,
    pub bd_router: Ipv4Addr,
    pub priority: u8,
}

impl Identity {
    pub fn new(router_id: Ipv4Addr) -> Self {
        Self {
            prefix: Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).unwrap(),
            router_id,
            d_router: Ipv4Addr::UNSPECIFIED,
            bd_router: Ipv4Addr::UNSPECIFIED,
            priority: 1,
        }
    }

    pub fn is_declared_dr(&self) -> bool {
        self.prefix.addr() == self.d_router
    }

    pub fn is_declared_bdr(&self) -> bool {
        self.prefix.addr() == self.bd_router
    }
}
