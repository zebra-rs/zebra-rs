use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::Vpnv4Nexthop;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BgpNexthop {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Vpnv4(Vpnv4Nexthop),
    Evpn(IpAddr),
}
