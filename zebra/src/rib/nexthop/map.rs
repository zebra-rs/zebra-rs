use std::{collections::BTreeMap, net::Ipv4Addr};

use crate::fib::FibHandle;

use super::{GroupProtect, GroupSet, GroupTrait, GroupUni};

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
    pub fn get(&self, index: usize) -> Option<&GroupSet> {
        self.groups.get(index)
    }

    pub fn get_mut(&mut self, index: usize) -> Option<&mut GroupSet> {
        self.groups.get_mut(index)
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
            self.groups.push(group);

            gid
        };
        self.groups.get_mut(gid)
    }

    pub async fn shutdown(&mut self, fib: &FibHandle) {
        for grp in self.groups.iter() {
            if grp.is_installed() {
                fib.nexthop_del(grp).await;
            }
        }
    }
}
