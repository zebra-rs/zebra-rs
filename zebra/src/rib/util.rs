use std::net::{Ipv4Addr, Ipv6Addr};

use ipnet::{Ipv4Net, Ipv6Net};

pub trait IpAddrExt<T> {
    #[allow(dead_code)]
    fn to_host_prefix(&self) -> T;
}

impl IpAddrExt<Ipv4Net> for Ipv4Addr {
    fn to_host_prefix(&self) -> Ipv4Net {
        Ipv4Net::new(*self, Self::BITS as u8).unwrap()
    }
}

impl IpAddrExt<Ipv6Net> for Ipv6Addr {
    fn to_host_prefix(&self) -> Ipv6Net {
        Ipv6Net::new(*self, Self::BITS as u8).unwrap()
    }
}
