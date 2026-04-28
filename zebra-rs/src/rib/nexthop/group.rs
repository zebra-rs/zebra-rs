// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2025-2026 Kunihiro Ishiguro

use std::collections::BTreeSet;
use std::net::IpAddr;

use Group::*;
use ipnet::{Ipv4Net, Ipv6Net};
use prefix_trie::PrefixMap;

use crate::rib::entry::RibEntries;
use crate::rib::resolve::{Resolve, ResolveOpt, rib_resolve, rib_resolve_v6};

use super::NexthopUni;

// Flip to true to re-enable IPv6 nexthop resolution diagnostic prints.
const DEBUG_V6: bool = false;

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
            IpAddr::V6(_) => {
                // IPv6 nexthops resolve against the v6 table via resolve_v6.
            }
        }
    }

    pub fn resolve_v6(&mut self, table: &PrefixMap<Ipv6Net, RibEntries>) {
        if let IpAddr::V6(ipv6_addr) = self.addr {
            let resolve = rib_resolve_v6(table, ipv6_addr, &ResolveOpt::default());
            match &resolve {
                Resolve::Onlink(ifindex) => {
                    if DEBUG_V6 {
                        println!(
                            "[GroupUni::resolve_v6] {} -> Onlink(ifindex={})",
                            ipv6_addr, ifindex
                        );
                    }
                    self.ifindex = *ifindex;
                    self.set_valid(true);
                }
                Resolve::Recursive(_) => {
                    if DEBUG_V6 {
                        println!("[GroupUni::resolve_v6] {} -> Recursive", ipv6_addr);
                    }
                }
                Resolve::NotFound => {
                    if DEBUG_V6 {
                        println!("[GroupUni::resolve_v6] {} -> NotFound", ipv6_addr);
                    }
                }
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
