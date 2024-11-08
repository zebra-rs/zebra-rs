use std::collections::BTreeMap;
use std::fmt;
use std::net::Ipv4Addr;

#[derive(Debug, Clone, PartialEq)]
pub struct NexthopUni {
    pub addr: Ipv4Addr,
    pub ifindex: u32,
    pub metric: u32,
    pub weight: u8,
    pub gid: usize,
}

impl NexthopUni {
    pub fn new(addr: Ipv4Addr) -> Self {
        let mut nhop = Self::default();
        nhop.addr = addr;
        nhop
    }
}

impl Default for NexthopUni {
    fn default() -> Self {
        Self {
            addr: Ipv4Addr::UNSPECIFIED,
            ifindex: 0,
            metric: 0,
            weight: 0,
            gid: 0,
        }
    }
}

impl fmt::Display for NexthopUni {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.addr)
    }
}

#[derive(Debug, Default, Clone, PartialEq)]
pub enum Nexthop {
    #[default]
    Onlink,
    Uni(NexthopUni),
    Multi(NexthopMulti),
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
