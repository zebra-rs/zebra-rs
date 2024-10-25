use std::fmt;
use std::net::Ipv4Addr;

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub struct Nexthop {
    pub onlink: bool,
    pub valid: bool,
    pub addr: Ipv4Addr,
    ifindex: Option<u32>,
    pub weight: u8,
    pub recursive: Vec<Nexthop>,
}

impl Nexthop {
    pub fn builder() -> NexthopBuilder {
        NexthopBuilder::default()
    }
}

impl Default for Nexthop {
    fn default() -> Self {
        Self {
            onlink: false,
            valid: false,
            addr: Ipv4Addr::UNSPECIFIED,
            ifindex: None,
            weight: 0,
            recursive: Vec::new(),
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
