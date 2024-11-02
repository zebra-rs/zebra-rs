use ipnet::Ipv4Net;
use prefix_trie::PrefixMap;
use NexthopGroup::*;

use std::{collections::BTreeSet, net::Ipv4Addr};

use crate::rib::entry::RibEntries;

#[allow(dead_code)]
#[derive(Default)]
pub struct NexthopResilience {
    buckets: u16,
    idle_timer: u32,
    unbalanced_timer: u32,
    unbalanced_time: u64,
}

pub enum NexthopGroup {
    Uni(NexthopUni),
    Multi(NexthopMulti),
    Protect(NexthopProtect),
}

impl NexthopGroup {
    pub fn new_unipath(addr: &Ipv4Addr, ngid: usize) -> Self {
        let mut uni: NexthopUni = NexthopUni::new(addr);
        uni.common.ngid = ngid;
        NexthopGroup::Uni(uni)
    }
}

#[derive(Default)]
pub struct NexthopGroupCommon {
    ngid: usize,
    valid: bool,
    installed: bool,
    refcnt: usize,
}

pub struct NexthopUni {
    common: NexthopGroupCommon,
    addr: Ipv4Addr,
    ifindex: u32,
}

impl NexthopUni {
    pub fn new(addr: &Ipv4Addr) -> Self {
        Self {
            common: NexthopGroupCommon::default(),
            addr: *addr,
            ifindex: 0,
        }
    }
}

pub struct NexthopWeight {
    weight: u8,
    nhop: usize,
}

pub struct NexthopMulti {
    common: NexthopGroupCommon,
    nhops: Vec<NexthopWeight>,
}

pub struct NexthopProtect {
    common: NexthopGroupCommon,
    primary: usize,
    backup: Vec<usize>,
}

pub trait GroupTrait {
    fn common(&self) -> &NexthopGroupCommon;
    fn common_mut(&mut self) -> &mut NexthopGroupCommon;

    fn ngid(&self) -> usize;
    fn set_ngid(&mut self, ngid: usize);

    fn is_valid(&self) -> bool;
    fn set_valid(&mut self, valid: bool);

    fn refcnt(&self) -> usize;
}

impl NexthopGroup {
    pub fn resolve(&mut self, table: &PrefixMap<Ipv4Net, RibEntries>) {
        match self {
            Uni(uni) => {
                //
            }
            _ => {
                // TODO.
            }
        }
    }
}

impl GroupTrait for NexthopGroup {
    fn common(&self) -> &NexthopGroupCommon {
        match self {
            Uni(uni) => &uni.common,
            Multi(multi) => &multi.common,
            Protect(protect) => &protect.common,
        }
    }

    fn common_mut(&mut self) -> &mut NexthopGroupCommon {
        match self {
            Uni(uni) => &mut uni.common,
            Multi(multi) => &mut multi.common,
            Protect(protect) => &mut protect.common,
        }
    }

    fn ngid(&self) -> usize {
        self.common().ngid
    }

    fn set_ngid(&mut self, ngid: usize) {
        self.common_mut().ngid = ngid;
    }

    fn is_valid(&self) -> bool {
        self.common().valid
    }

    fn set_valid(&mut self, valid: bool) {
        self.common_mut().valid = valid;
    }

    fn refcnt(&self) -> usize {
        self.common().refcnt
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uni() {
        let addr: Ipv4Addr = "10.211.55.2".parse().unwrap();
        let mut unipath = NexthopGroup::new_unipath(&addr, 0);
        assert_eq!(false, unipath.is_valid());
        unipath.set_valid(true);
        assert_eq!(true, unipath.is_valid());
    }
}
