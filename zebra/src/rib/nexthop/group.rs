use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use prefix_trie::PrefixMap;
use Group::*;

use crate::rib::entry::RibEntries;
use crate::rib::resolve::{rib_resolve, Resolve, ResolveOpt};

pub enum Group {
    Uni(GroupUni),
    Multi(GroupMulti),
    Protect(GroupProtect),
}

impl Group {
    pub fn new_uni(addr: &Ipv4Addr, ifindex: u32, gid: usize) -> Self {
        let mut uni: GroupUni = GroupUni::new(gid, addr);
        uni.ifindex = ifindex;
        Group::Uni(uni)
    }
}

#[derive(Default)]
pub struct GroupCommon {
    gid: usize,
    valid: bool,
    installed: bool,
    refcnt: usize,
}

impl GroupCommon {
    pub fn new(gid: usize) -> Self {
        Self {
            gid,
            ..Default::default()
        }
    }
}

pub struct GroupUni {
    common: GroupCommon,
    pub addr: Ipv4Addr,
    pub ifindex: u32,
}

impl GroupUni {
    pub fn new(gid: usize, addr: &Ipv4Addr) -> Self {
        Self {
            common: GroupCommon::new(gid),
            addr: *addr,
            ifindex: 0,
        }
    }

    pub fn resolve(&mut self, table: &PrefixMap<Ipv4Net, RibEntries>) {
        let resolve = rib_resolve(table, self.addr, &ResolveOpt::default());
        if let Resolve::Onlink(ifindex) = resolve {
            self.ifindex = ifindex;
            self.set_valid(true);
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

pub struct GroupMulti {
    common: GroupCommon,
    pub set: BTreeSet<(usize, u8)>,
}

impl GroupMulti {
    pub fn new(gid: usize) -> Self {
        Self {
            common: GroupCommon::new(gid),
            set: BTreeSet::new(),
        }
    }
}

impl GroupTrait for GroupMulti {
    fn common(&self) -> &GroupCommon {
        &self.common
    }

    fn common_mut(&mut self) -> &mut GroupCommon {
        &mut self.common
    }
}

#[derive(Default)]
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

    fn refcnt_mut(&mut self) -> &mut usize {
        &mut self.common_mut().refcnt
    }

    fn refcnt_inc(&mut self) {
        let refcnt = self.refcnt_mut();
        *refcnt += 1;
    }

    fn refcnt_dec(&mut self) {
        let refcnt = self.refcnt_mut();
        if *refcnt > 0 {
            *refcnt -= 1;
        }
    }
}

impl GroupTrait for Group {
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
