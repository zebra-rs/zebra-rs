use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use prefix_trie::PrefixMap;
use NexthopGroup::*;

use crate::fib::FibHandle;
use crate::rib::{
    entry::RibEntries,
    inst::{rib_resolve, Resolve, ResolveOpt},
};

pub enum NexthopGroup {
    Uni(NexthopUni),
    Multi(NexthopMulti),
    Protect(NexthopProtect),
}

impl NexthopGroup {
    pub fn new_uni(addr: &Ipv4Addr, ngid: usize) -> Self {
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
    pub addr: Ipv4Addr,
    pub ifindex: u32,
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

impl NexthopGroupTrait for NexthopUni {
    fn common(&self) -> &NexthopGroupCommon {
        &self.common
    }

    fn common_mut(&mut self) -> &mut NexthopGroupCommon {
        &mut self.common
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

pub trait NexthopGroupTrait {
    fn common(&self) -> &NexthopGroupCommon;

    fn common_mut(&mut self) -> &mut NexthopGroupCommon;

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

    fn is_installed(&self) -> bool {
        self.common().installed
    }

    fn set_installed(&mut self, installed: bool) {
        self.common_mut().installed = installed;
    }

    fn refcnt(&self) -> usize {
        self.common().refcnt
    }
}

impl NexthopGroup {
    pub fn resolve(&mut self, table: &PrefixMap<Ipv4Net, RibEntries>) {
        let Uni(uni) = self else {
            return;
        };
        let resolve = rib_resolve(table, uni.addr, &ResolveOpt::default());
        match resolve {
            Resolve::Onlink(ifindex) => {
                uni.ifindex = ifindex;
                self.set_valid(true);
            }
            _ => {}
        }
    }

    pub async fn sync(&mut self, fib: &FibHandle) {
        if self.is_valid() && !self.is_installed() {
            fib.nexthop_add(self).await;
            self.set_installed(true);
        }
    }
}

impl NexthopGroupTrait for NexthopGroup {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uni() {
        let addr: Ipv4Addr = "10.211.55.2".parse().unwrap();
        let mut unipath = NexthopGroup::new_uni(&addr, 0);
        assert_eq!(false, unipath.is_valid());
        unipath.set_valid(true);
        assert_eq!(true, unipath.is_valid());
    }
}
