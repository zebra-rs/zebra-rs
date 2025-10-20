use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

use crate::fib::FibHandle;

use super::{Group, GroupMulti, GroupTrait, GroupUni, NexthopUni};

pub struct NexthopMap {
    map: BTreeMap<IpAddr, usize>,
    set: BTreeMap<BTreeSet<(usize, u8)>, usize>,
    mpls: BTreeMap<(IpAddr, Vec<u32>), usize>,
    pub groups: Vec<Option<Group>>,
}

impl Group {
    pub fn from_nexthop_uni(uni: &NexthopUni, gid: usize) -> Self {
        Group::Uni(GroupUni::new(gid, &uni))
    }
}

impl Default for NexthopMap {
    fn default() -> Self {
        let mut nmap = Self {
            map: BTreeMap::new(),
            set: BTreeMap::new(),
            mpls: BTreeMap::new(),
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

    pub fn get_uni(&self, index: usize) -> Option<&GroupUni> {
        self.groups
            .get(index)
            .and_then(|grp| grp.as_ref())
            .and_then(|grp| {
                if let Group::Uni(uni) = grp {
                    Some(uni)
                } else {
                    None
                }
            })
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

    pub fn fetch_uni(&mut self, uni: &NexthopUni) -> Option<&mut Group> {
        if let Some(&gid) = self.map.get(&uni.addr) {
            let entry = self.groups.get_mut(gid)?;
            if entry.is_none() {
                *entry = Some(Group::from_nexthop_uni(uni, gid));
            }
            return self.get_mut(gid);
        }

        let gid = self.new_gid();
        let group = Group::from_nexthop_uni(uni, gid);

        self.map.insert(uni.addr, gid);
        self.groups.push(Some(group));

        self.get_mut(gid)
    }

    pub fn fetch_mpls(&mut self, uni: &NexthopUni) -> Option<&mut Group> {
        if let Some(&gid) = self.mpls.get(&(uni.addr, uni.mpls_label.clone())) {
            let entry = self.groups.get_mut(gid)?;
            if entry.is_none() {
                *entry = Some(Group::from_nexthop_uni(uni, gid));
            }
            return self.get_mut(gid);
        }

        let gid = self.new_gid();
        let group = Group::from_nexthop_uni(uni, gid);

        self.mpls.insert((uni.addr, uni.mpls_label.clone()), gid);
        self.groups.push(Some(group));

        self.get_mut(gid)
    }

    pub fn fetch(&mut self, uni: &NexthopUni) -> Option<&mut Group> {
        if uni.mpls_label.is_empty() {
            self.fetch_uni(uni)
        } else {
            self.fetch_mpls(uni)
        }
    }

    pub fn fetch_multi(&mut self, set: &BTreeSet<(usize, u8)>) -> Option<&mut Group> {
        let gid = if let Some(&gid) = self.set.get(set) {
            let update = self.groups.get_mut(gid)?;
            if update.is_none() {
                let mut multi = GroupMulti::new(gid);
                multi.set = set.clone();
                *update = Some(Group::Multi(multi));
            }
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
            let entry = self.get(*id);
            if let Some(grp) = entry {
                if grp.is_installed() {
                    fib.nexthop_del(grp).await;
                }
            }
        }
        for (_, id) in self.map.iter() {
            let entry = self.get(*id);
            if let Some(grp) = entry {
                if grp.is_installed() {
                    fib.nexthop_del(grp).await;
                }
            }
        }
        for (_, id) in self.mpls.iter() {
            let entry = self.get(*id);
            if let Some(grp) = entry {
                if grp.is_installed() {
                    fib.nexthop_del(grp).await;
                }
            }
        }
    }
}
