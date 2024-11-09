use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use tracing::instrument::WithSubscriber;

use crate::fib::FibHandle;

use super::nexthop::{GroupTrait, NexthopUni};
use super::{Nexthop, NexthopMap, NexthopMulti, Rib, RibSubType, RibType};

// #[derive(Default)]
// pub struct RibEntries {
//     pub ribs: Vec<RibEntry>,
// }

pub type RibEntries = Vec<RibEntry>;

#[derive(Debug, Clone, PartialEq)]
pub struct RibEntry {
    pub rtype: RibType,
    pub rsubtype: RibSubType,
    selected: bool,
    fib: bool,
    valid: bool,
    pub distance: u8,
    pub metric: u32,
    pub nexthop: Nexthop,

    // Connected RIB's ifindex.
    pub ifindex: u32,
}

impl RibEntry {
    pub fn new(rtype: RibType) -> Self {
        Self {
            rtype,
            rsubtype: RibSubType::Default,
            selected: false,
            fib: false,
            valid: false,
            distance: 0,
            metric: 0,
            nexthop: Nexthop::default(),
            ifindex: 0,
        }
    }

    pub fn is_connected(&self) -> bool {
        self.rtype == RibType::Connected
    }

    pub fn is_static(&self) -> bool {
        self.rtype == RibType::Static
    }

    pub fn set_valid(&mut self, valid: bool) {
        self.valid = valid;
    }

    pub fn is_valid(&self) -> bool {
        self.valid
    }

    pub fn is_protocol(&self) -> bool {
        match self.rtype {
            RibType::Static | RibType::Rip | RibType::Ospf | RibType::Isis | RibType::Bgp => true,
            _ => false,
        }
    }

    pub fn is_fib(&self) -> bool {
        self.fib
    }

    pub fn set_fib(&mut self, fib: bool) {
        self.fib = fib;
    }

    pub fn is_selected(&self) -> bool {
        self.selected
    }

    pub fn set_selected(&mut self, selected: bool) {
        self.selected = selected;
    }

    // pub fn distance(&self) -> String {
    //     if self.rtype != RibType::Connected {
    //         format!(" [{}/{}]", &self.distance, &self.metric)
    //     } else {
    //         String::new()
    //     }
    // }

    // pub fn gateway(&self, rib: &Rib) -> String {
    //     if self.is_connected() {
    //         if let Some(name) = rib.link_name(self.ifindex) {
    //             format!("directly connected {}", name)
    //         } else {
    //             "directly connected unknown".to_string()
    //         }
    //     } else if let Nexthop::Uni(uni) = &self.nexthop {
    //         let mut out: String = String::from("via ");
    //         out += &format!("{} ", uni.addr);
    //         out
    //     } else {
    //         String::new()
    //     }
    // }

    pub fn selected(&self) -> String {
        let selected = if self.selected { '>' } else { ' ' };
        let fib = if self.fib { '*' } else { ' ' };
        format!("{}{}", fib, selected)
    }

    pub fn is_valid_nexthop(&self, nmap: &NexthopMap) -> bool {
        match &self.nexthop {
            Nexthop::Uni(uni) => nmap.get(uni.gid).map_or(false, |group| group.is_valid()),
            Nexthop::Multi(multi) => multi
                .nexthops
                .iter()
                .any(|nhop| nmap.get(nhop.gid).map_or(false, |group| group.is_valid())),
            _ => false,
        }
    }

    pub async fn nexthop_sync(&mut self, nmap: &mut NexthopMap, fib: &FibHandle) {
        if let Nexthop::Uni(uni) = &mut self.nexthop {
            uni_group_sync(uni, nmap, fib).await;
        }
        if let Nexthop::Multi(multi) = &mut self.nexthop {
            for uni in multi.nexthops.iter_mut() {
                uni_group_sync(uni, nmap, fib).await;
            }
            multi_group_sync(multi, nmap, fib).await;
        }
    }

    pub async fn nexthop_unsync(&mut self, nmap: &mut NexthopMap, fib: &FibHandle) {
        if let Nexthop::Uni(uni) = &self.nexthop {
            if let Some(group) = nmap.get_mut(uni.gid) {
                group.refcnt_dec();

                if group.refcnt() == 0 {
                    // If ref count is zero and the nexthop is installed, remove it from FIB
                    if group.is_installed() {
                        fib.nexthop_del(group).await;
                    }
                    // Remove nexthop group since it's no longer referenced
                    nmap.groups[uni.gid] = None;
                }
            }
        }
    }
}

async fn uni_group_sync(uni: &NexthopUni, nmap: &mut NexthopMap, fib: &FibHandle) {
    let Some(group) = nmap.get_mut(uni.gid) else {
        return;
    };
    if !group.is_valid() || group.is_installed() {
        return;
    }
    fib.nexthop_add(group).await;
    group.set_installed(true);
}

async fn multi_group_sync(multi: &NexthopMulti, nmap: &mut NexthopMap, fib: &FibHandle) {
    let Some(group) = nmap.get_mut(multi.gid) else {
        return;
    };
    if !group.is_valid() || group.is_installed() {
        return;
    }
    fib.nexthop_add(group).await;
    group.set_installed(true);
}
