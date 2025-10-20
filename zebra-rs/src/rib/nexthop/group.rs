use std::collections::BTreeSet;
use std::net::IpAddr;

use Group::*;
use ipnet::Ipv4Net;
use prefix_trie::PrefixMap;

use crate::rib::entry::RibEntries;
use crate::rib::resolve::{Resolve, ResolveOpt, rib_resolve};

use super::NexthopUni;

#[derive(Debug)]
pub enum Group {
    Uni(GroupUni),
    Multi(GroupMulti),
}

#[derive(Default, Debug, Clone)]
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

#[derive(Debug, Clone)]
pub struct GroupUni {
    common: GroupCommon,
    pub addr: IpAddr,
    pub ifindex: u32,
    pub labels: Vec<u32>,
}

impl GroupUni {
    pub fn new(gid: usize, uni: &NexthopUni) -> Self {
        Self {
            common: GroupCommon::new(gid),
            addr: uni.addr,
            ifindex: 0,
            labels: uni.mpls_label.clone(),
        }
    }

    pub fn resolve(&mut self, table: &PrefixMap<Ipv4Net, RibEntries>) {
        match self.addr {
            IpAddr::V4(ipv4_addr) => {
                let resolve = rib_resolve(table, ipv4_addr, &ResolveOpt::default());
                if let Resolve::Onlink(ifindex) = resolve {
                    self.ifindex = ifindex;
                    self.set_valid(true);
                }
            }
            IpAddr::V6(_ipv6_addr) => {
                // TODO: Implement IPv6 resolution when IPv6 table is available
                // For now, we'll leave IPv6 nexthops unresolved
            }
        }
    }

    pub fn set_ifindex(&mut self, ifindex: u32) {
        self.ifindex = ifindex
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

#[derive(Debug, Clone)]
pub struct GroupMulti {
    common: GroupCommon,
    pub set: BTreeSet<(usize, u8)>,
    pub valid: BTreeSet<(usize, u8)>,
}

impl GroupMulti {
    pub fn new(gid: usize) -> Self {
        Self {
            common: GroupCommon::new(gid),
            set: BTreeSet::new(),
            valid: BTreeSet::new(),
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
        }
    }

    fn common_mut(&mut self) -> &mut GroupCommon {
        match self {
            Uni(uni) => &mut uni.common,
            Multi(multi) => &mut multi.common,
        }
    }

    fn refcnt(&self) -> usize {
        match self {
            Group::Uni(uni) => uni.refcnt(),
            Group::Multi(multi) => multi.refcnt(),
        }
    }
}
