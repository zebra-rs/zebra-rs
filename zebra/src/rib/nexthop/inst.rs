use std::net::Ipv4Addr;

#[derive(Debug, Clone, PartialEq)]
pub enum Label {
    Implicit(u32),
    Explicit(u32),
}

#[derive(Debug, Clone, PartialEq)]
pub struct NexthopUni {
    pub addr: Ipv4Addr,
    pub metric: u32,
    pub weight: u8,
    pub ifindex: u32,
    pub valid: bool,
    pub mpls: Vec<Label>,
    pub mpls_label: Vec<u32>,
    pub gid: usize,
}

impl NexthopUni {
    pub fn new_mpls(addr: Ipv4Addr, mpls: Vec<Label>) -> Self {
        let mut uni = Self {
            addr,
            mpls,
            ..Default::default()
        };
        for mpls in uni.mpls.iter() {
            match mpls {
                Label::Implicit(_) => {
                    // Implicit null is treated as no label.
                }
                Label::Explicit(label) => {
                    uni.mpls_label.push(label.clone());
                }
            }
        }
        uni
    }
}

impl Default for NexthopUni {
    fn default() -> Self {
        Self {
            addr: Ipv4Addr::UNSPECIFIED,
            ifindex: 0,
            metric: 0,
            weight: 1,
            mpls: vec![],
            mpls_label: vec![],
            gid: 0,
            valid: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Nexthop {
    Link(u32),
    Uni(NexthopUni),
    Multi(NexthopMulti),
    List(NexthopList),
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
