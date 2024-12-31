use std::net::Ipv4Addr;

use netlink_packet_route::route::MplsLabel;

#[derive(Debug, Clone, PartialEq)]
pub struct NexthopUni {
    pub addr: Ipv4Addr,
    pub ifindex: u32,
    pub metric: u32,
    pub weight: u8,
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
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq)]
pub enum Nexthop {
    #[default]
    Onlink,
    Uni(NexthopUni),
    Multi(NexthopMulti),
    List(NexthopProtect),
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct NexthopProtect {
    pub nexthops: Vec<NexthopUni>,
}

impl NexthopProtect {
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
