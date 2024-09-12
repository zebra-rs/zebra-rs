use std::net::Ipv4Addr;

#[derive(Debug, Default, Clone)]
pub struct NexthopSource {
    addr: Option<Ipv4Addr>,
    ifindex: Option<u32>,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct Nexthop {
    addr: Ipv4Addr,
    ifindex: u32,
    weight: Option<u32>,
    source: NexthopSource,
    valid: bool,
}

impl Default for Nexthop {
    fn default() -> Self {
        Self {
            valid: false,
            addr: Ipv4Addr::UNSPECIFIED,
            ifindex: 0,
            weight: None,
            source: NexthopSource::default(),
        }
    }
}

pub struct NexthopBuilder {
    source_addr: Option<Ipv4Addr>,
    source_ifname: Option<String>,
    weight: Option<u32>,
}

impl NexthopBuilder {
    pub fn builder(&self) -> Nexthop {
        Nexthop {
            valid: false,
            addr: Ipv4Addr::UNSPECIFIED,
            ifindex: 0,
            weight: self.weight,
            source: NexthopSource::default(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parse() {}
}
