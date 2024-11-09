use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv4Addr,
};

use crate::fib::FibHandle;

use super::{Group, GroupMulti, GroupTrait, GroupUni};

pub struct NexthopMap {
    map: BTreeMap<Ipv4Addr, usize>,
    set: BTreeMap<BTreeSet<(usize, u8)>, usize>,
    pub groups: Vec<Option<Group>>,
}

impl Default for NexthopMap {
    fn default() -> Self {
        let mut nmap = Self {
            map: BTreeMap::new(),
            set: BTreeMap::new(),
            groups: Vec::new(),
        };
        nmap.groups.push(None);
        nmap
    }
}

impl NexthopMap {
    pub fn get(&self, index: usize) -> Option<&Group> {
        if let Some(grp) = self.groups.get(index) {
            grp.as_ref()
        } else {
            None
        }
    }

    pub fn get_mut(&mut self, index: usize) -> Option<&mut Group> {
        if let Some(grp) = self.groups.get_mut(index) {
            grp.as_mut()
        } else {
            None
        }
    }

    fn new_gid(&self) -> usize {
        self.groups.len()
    }

    pub fn fetch_uni(&mut self, addr: &Ipv4Addr) -> Option<&mut Group> {
        let gid = if let Some(&gid) = self.map.get(addr) {
            gid
        } else {
            let gid = self.new_gid();
            let group = Group::Uni(GroupUni::new(gid, addr));

            self.map.insert(*addr, gid);
            self.groups.push(Some(group));

            gid
        };
        self.get_mut(gid)
    }

    pub fn fetch_multi(&mut self, set: &BTreeSet<(usize, u8)>) -> Option<&mut Group> {
        let gid = if let Some(&gid) = self.set.get(&set) {
            gid
        } else {
            let gid = self.new_gid();
            let mut multi = GroupMulti::new(gid);
            multi.set = set.clone();

            self.set.insert(set.clone(), gid);
            self.groups.push(Some(Group::Multi(multi)));

            gid
        };
        self.get_mut(gid)
    }

    pub async fn shutdown(&mut self, fib: &FibHandle) {
        for (_, id) in self.set.iter() {
            let entry = self.get(*id as usize);
            if let Some(grp) = entry {
                if grp.is_installed() {
                    fib.nexthop_del(grp).await;
                }
            }
        }
        for (_, id) in self.map.iter() {
            let entry = self.get(*id as usize);
            if let Some(grp) = entry {
                if grp.is_installed() {
                    fib.nexthop_del(grp).await;
                }
            }
        }
    }
}
