use std::{collections::BTreeMap, net::Ipv4Addr};

use crate::fib::FibHandle;

use super::{GroupProtect, GroupSet, GroupTrait};

pub struct NexthopMap {
    map: BTreeMap<Ipv4Addr, usize>,
    pub groups: Vec<GroupSet>,
}

impl Default for NexthopMap {
    fn default() -> Self {
        let mut nmap = Self {
            map: BTreeMap::new(),
            groups: Vec::new(),
        };
        // Pushing dummy for making first index to be 1.
        // nmap.values.push(None);
        nmap.groups.push(GroupSet::Protect(GroupProtect::default()));
        nmap
    }
}

impl NexthopMap {
    pub async fn register_group(&mut self, addr: Ipv4Addr, ifindex: u32, fib: &FibHandle) -> usize {
        if let Some(&index) = self.map.get(&addr) {
            if let Some(group) = self.get_mut(index) {
                group.refcnt_inc();
            }
            index
        } else {
            let gid = self.groups.len();
            self.map.insert(addr, gid);
            let mut uni = GroupSet::new_uni(&addr, ifindex, gid);
            fib.nexthop_add(&uni).await;
            uni.set_valid(true);
            uni.set_installed(true);
            self.groups.push(uni);
            gid
        }
    }

    pub async fn unregister(&mut self, gid: usize, fib: &FibHandle) {
        if let Some(group) = self.groups.get_mut(gid) {
            group.refcnt_dec();
            if group.refcnt() == 0 {
                fib.nexthop_del(group).await;
            }
        }
    }

    pub fn get_mut(&mut self, index: usize) -> Option<&mut GroupSet> {
        self.groups.get_mut(index)
    }

    pub fn get(&self, index: usize) -> Option<&GroupSet> {
        self.groups.get(index)
    }

    pub async fn shutdown(&mut self, fib: &FibHandle) {
        for grp in self.groups.iter() {
            if grp.is_installed() {
                fib.nexthop_del(grp).await;
            }
        }
    }
}
