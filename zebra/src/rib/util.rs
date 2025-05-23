use std::net::{Ipv4Addr, Ipv6Addr};

use ipnet::{Ipv4Net, Ipv6Net};

pub trait IpAddrExt<T> {
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

pub trait IpNetExt<T> {
    fn apply_mask(&self) -> T;
}

impl IpNetExt<Ipv4Net> for Ipv4Net {
    fn apply_mask(&self) -> Ipv4Net {
        Ipv4Net::new(self.network(), self.prefix_len()).unwrap()
    }
}

impl IpNetExt<Ipv6Net> for Ipv6Net {
    fn apply_mask(&self) -> Ipv6Net {
        Ipv6Net::new(self.network(), self.prefix_len()).unwrap()
    }
}
