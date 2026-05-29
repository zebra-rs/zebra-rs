use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::{Vpnv4Nexthop, Vpnv6Nexthop};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BgpNexthop {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Vpnv4(Vpnv4Nexthop),
    Vpnv6(Vpnv6Nexthop),
    Evpn(IpAddr),
}
