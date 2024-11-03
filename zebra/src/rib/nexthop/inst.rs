use std::fmt;
use std::net::Ipv4Addr;

#[derive(Debug, Clone, PartialEq)]
pub struct Nexthop {
    pub addr: Ipv4Addr,
    pub invalid: bool,
    pub onlink: bool,
    pub ifindex: u32,
    pub weight: u8,
    pub recursive: Vec<Nexthop>,
    pub resolved: Vec<usize>,
    pub refcnt: usize,
    pub ngid: usize,
}

impl Nexthop {
    pub fn new(addr: Ipv4Addr) -> Self {
        Self {
            addr,
            invalid: false,
            onlink: false,
            ifindex: 0,
            weight: 0,
            recursive: Vec::new(),
            resolved: Vec::new(),
            refcnt: 0,
            ngid: 0,
        }
    }

    pub fn builder() -> NexthopBuilder {
        NexthopBuilder::default()
    }
}

impl Default for Nexthop {
    fn default() -> Self {
        Self {
            addr: Ipv4Addr::UNSPECIFIED,
            invalid: false,
            onlink: false,
            ifindex: 0,
            weight: 0,
            recursive: Vec::new(),
            resolved: Vec::new(),
            refcnt: 0,
            ngid: 0,
        }
    }
}

impl fmt::Display for Nexthop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.addr)
    }
}

#[derive(Debug)]
pub struct NexthopBuilder {
    addr: Ipv4Addr,
}

impl Default for NexthopBuilder {
    fn default() -> Self {
        Self {
            addr: Ipv4Addr::UNSPECIFIED,
        }
    }
}

impl NexthopBuilder {
    pub fn addr(mut self, addr: Ipv4Addr) -> Self {
        self.addr = addr;
        self
    }

    pub fn build(&self) -> Nexthop {
        Nexthop {
            addr: self.addr,
            ..Default::default()
        }
    }
}
