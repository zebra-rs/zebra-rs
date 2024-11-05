use std::collections::BTreeMap;
use std::fmt;
use std::net::Ipv4Addr;

#[derive(Debug, Clone, PartialEq)]
pub struct Nexthop {
    pub addr: Ipv4Addr,
    pub invalid: bool,
    pub onlink: bool,
    pub ifindex: u32,
    pub metric: u32,
    pub weight: u8,
    pub gid: usize,
}

impl Nexthop {
    pub fn new(addr: Ipv4Addr) -> Self {
        let mut nhop = Self::default();
        nhop.addr = addr;
        nhop
    }
}

impl Default for Nexthop {
    fn default() -> Self {
        Self {
            addr: Ipv4Addr::UNSPECIFIED,
            invalid: false,
            onlink: false,
            ifindex: 0,
            metric: 0,
            weight: 0,
            gid: 0,
        }
    }
}

impl fmt::Display for Nexthop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.addr)
    }
}

#[derive(Debug, Default, Clone, PartialEq)]
pub enum NexthopSet {
    #[default]
    None,
    Uni(Nexthop),
    Multi(NexthopMulti),
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct NexthopMulti {
    pub metric: u32,
    pub nexthops: BTreeMap<Ipv4Addr, Nexthop>,
}
