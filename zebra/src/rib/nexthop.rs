use std::fmt;
use std::net::Ipv4Addr;

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub struct Nexthop {
    pub onlink: bool,
    pub valid: bool,
    pub addr: Option<Ipv4Addr>,
    ifindex: Option<u32>,
    weight: Option<u32>,
}

impl Default for Nexthop {
    fn default() -> Self {
        Self {
            onlink: false,
            valid: false,
            addr: None,
            ifindex: None,
            weight: None,
        }
    }
}

impl Nexthop {
    pub fn builder() -> NexthopBuilder {
        NexthopBuilder::default()
    }
}

impl fmt::Display for Nexthop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(addr) = self.addr {
            write!(f, "{}", addr)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Default)]
pub struct NexthopBuilder {
    addr: Option<Ipv4Addr>,
}

impl NexthopBuilder {
    pub fn addr(mut self, addr: Ipv4Addr) -> Self {
        self.addr = Some(addr);
        self
    }

    pub fn build(&self) -> Nexthop {
        let mut nexthop = Nexthop::default();
        nexthop.addr = self.addr.clone();
        nexthop
    }
}
