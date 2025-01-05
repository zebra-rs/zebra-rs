use std::net::Ipv4Addr;

use netlink_packet_route::route::MplsLabel;

#[derive(Debug, Clone, PartialEq)]
pub struct NexthopUni {
    pub addr: Ipv4Addr,
    pub metric: u32,
    pub weight: u8,
    pub ifindex: u32,
    pub valid: bool,
    pub mpls: Option<Vec<MplsLabel>>,
    pub gid: usize,
}

impl NexthopUni {
    pub fn new(addr: Ipv4Addr) -> Self {
        Self {
            addr,
            ..Default::default()
        }
    }
}

impl Default for NexthopUni {
    fn default() -> Self {
        Self {
            addr: Ipv4Addr::UNSPECIFIED,
            ifindex: 0,
            metric: 0,
            weight: 1,
            mpls: None,
            gid: 0,
            valid: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Nexthop {
    Link(u32),
    Uni(NexthopUni),
    List(NexthopList),
    Multi(NexthopMulti),
}

impl Default for Nexthop {
    fn default() -> Self {
        Self::Link(0)
    }
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct NexthopList {
    pub nexthops: Vec<NexthopUni>,
}

impl NexthopList {
    pub fn metric(&self) -> u32 {
        match self.nexthops.first() {
            Some(nhop) => nhop.metric,
            None => 0,
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct NexthopMulti {
    // ECMP or UCMP multipath.  metric will be the same.
    pub metric: u32,

    // For UCMP, we have weight.
    pub nexthops: Vec<NexthopUni>,

    // Nexthop Group id for multipath.
    pub gid: usize,
}
