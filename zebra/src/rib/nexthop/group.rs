use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use prefix_trie::PrefixMap;
use GroupSet::*;

use crate::fib::FibHandle;
use crate::rib::entry::RibEntries;
use crate::rib::route::{rib_resolve, Resolve, ResolveOpt};

pub enum GroupSet {
    Uni(GroupUni),
    Multi(GroupMulti),
    Protect(GroupProtect),
}

impl GroupSet {
    pub fn new_uni(addr: &Ipv4Addr, gid: usize) -> Self {
        let mut uni: GroupUni = GroupUni::new(addr);
        uni.common.gid = gid;
        GroupSet::Uni(uni)
    }
}

#[derive(Default)]
pub struct GroupCommon {
    gid: usize,
    valid: bool,
    installed: bool,
    refcnt: usize,
}

pub struct GroupUni {
    common: GroupCommon,
    pub addr: Ipv4Addr,
    pub ifindex: u32,
}

impl GroupUni {
    pub fn new(addr: &Ipv4Addr) -> Self {
        Self {
            common: GroupCommon::default(),
            addr: *addr,
            ifindex: 0,
        }
    }
}

impl GroupTrait for GroupUni {
    fn common(&self) -> &GroupCommon {
        &self.common
    }

    fn common_mut(&mut self) -> &mut GroupCommon {
        &mut self.common
    }
}

pub struct GroupWeight {
    weight: u8,
    nhop: usize,
}

pub struct GroupMulti {
    common: GroupCommon,
    nhops: Vec<GroupWeight>,
}

pub struct GroupProtect {
    common: GroupCommon,
    primary: usize,
    backup: Vec<usize>,
}

pub trait GroupTrait {
    fn common(&self) -> &GroupCommon;

    fn common_mut(&mut self) -> &mut GroupCommon;

    fn gid(&self) -> usize {
        self.common().gid
    }

    fn set_gid(&mut self, gid: usize) {
        self.common_mut().gid = gid;
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

impl GroupSet {
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

impl GroupTrait for GroupSet {
    fn common(&self) -> &GroupCommon {
        match self {
            Uni(uni) => &uni.common,
            Multi(multi) => &multi.common,
            Protect(protect) => &protect.common,
        }
    }

    fn common_mut(&mut self) -> &mut GroupCommon {
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
