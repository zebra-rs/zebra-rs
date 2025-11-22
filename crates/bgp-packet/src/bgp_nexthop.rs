use std::net::{IpAddr, Ipv4Addr};

use crate::Vpnv4Nexthop;

#[derive(Debug, Clone)]
pub enum BgpNexthop {
    Ipv4(Ipv4Addr),
    Vpnv4(Vpnv4Nexthop),
    Evpn(IpAddr),
}
