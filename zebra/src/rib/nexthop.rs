use std::fmt;
use std::net::Ipv4Addr;

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct Nexthop {
    valid: bool,
    addr: Ipv4Addr,
    ifindex: u32,
    weight: Option<u32>,
    saddr: Option<Ipv4Addr>,
    sifname: Option<String>,
}

impl Default for Nexthop {
    fn default() -> Self {
        Self {
            valid: false,
            addr: Ipv4Addr::UNSPECIFIED,
            ifindex: 0,
            weight: None,
            saddr: None,
            sifname: None,
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
        if let Some(addr) = self.saddr {
            write!(f, "{}", addr)
        } else {
            if self.addr.is_unspecified() {
                write!(f, "unspec")
            } else {
                write!(f, "{}", self.addr)
            }
        }
    }
}

#[derive(Debug, Default)]
pub struct NexthopBuilder {
    addr: Option<Ipv4Addr>,
    saddr: Option<Ipv4Addr>,
    sifname: Option<String>,
    weight: Option<u32>,
}

impl NexthopBuilder {
    pub fn addr(mut self, addr: Ipv4Addr) -> Self {
        self.addr = Some(addr);
        self
    }

    pub fn saddr(mut self, saddr: Ipv4Addr) -> Self {
        self.saddr = Some(saddr);
        self
    }

    // pub fn sifname(mut self, sifname: String) -> Self {
    //     self.sifname = Some(sifname);
    //     self
    // }

    pub fn build(&self) -> Nexthop {
        let mut nexthop = Nexthop::default();
        nexthop.saddr = self.saddr.clone();
        nexthop.sifname = self.sifname.clone();
        nexthop
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parse() {}
}
