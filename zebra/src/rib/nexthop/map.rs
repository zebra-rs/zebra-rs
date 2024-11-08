use std::{collections::BTreeMap, net::Ipv4Addr};

use crate::fib::FibHandle;

use super::{GroupSet, GroupTrait, GroupUni};

pub struct NexthopMap {
    map: BTreeMap<Ipv4Addr, usize>,
    pub groups: Vec<Option<GroupSet>>,
}

impl Default for NexthopMap {
    fn default() -> Self {
        let mut nmap = Self {
            map: BTreeMap::new(),
            groups: Vec::new(),
        };
        nmap.groups.push(None);
        nmap
    }
}

impl NexthopMap {
    pub fn get(&self, index: usize) -> Option<&GroupSet> {
        if let Some(grp) = self.groups.get(index) {
            grp.as_ref()
        } else {
            None
        }
    }

    pub fn get_mut(&mut self, index: usize) -> Option<&mut GroupSet> {
        if let Some(grp) = self.groups.get_mut(index) {
            grp.as_mut()
        } else {
            None
        }
    }

    fn new_gid(&self) -> usize {
        self.groups.len()
    }

    pub fn fetch_uni(&mut self, addr: &Ipv4Addr) -> Option<&mut GroupSet> {
        let gid = if let Some(&gid) = self.map.get(addr) {
            gid
        } else {
            let gid = self.new_gid();
            let group = GroupSet::Uni(GroupUni::new(gid, addr));

            self.map.insert(*addr, gid);
            self.groups.push(Some(group));

            gid
        };
        self.get_mut(gid)
    }

    pub fn clear(&mut self, index: usize) {
        if index < self.groups.len() {
            self.groups.remove(index);
        }
    }

    pub async fn shutdown(&mut self, fib: &FibHandle) {
        for grp in self.groups.iter() {
            if let Some(grp) = grp {
                if grp.is_installed() {
                    fib.nexthop_del(grp).await;
                }
            }
        }
    }
}
