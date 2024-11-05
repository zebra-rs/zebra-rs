use std::{collections::BTreeMap, net::Ipv4Addr};

use ipnet::Ipv4Net;
use prefix_trie::PrefixMap;

use crate::{
    fib::FibHandle,
    rib::{nexthop::Nexthop, RibEntries},
};

use super::{GroupSet, GroupTrait};

pub struct NexthopMap {
    map: BTreeMap<Ipv4Addr, usize>,
    groups: Vec<GroupSet>,
}

impl Default for NexthopMap {
    fn default() -> Self {
        let mut nmap = Self {
            map: BTreeMap::new(),
            groups: Vec::new(),
        };
        // Pushing dummy for making first index to be 1.
        // nmap.values.push(None);
        nmap.groups
            .push(GroupSet::new_uni(&Ipv4Addr::UNSPECIFIED, 0));
        nmap
    }
}

impl NexthopMap {
    // pub fn register(&mut self, addr: Ipv4Addr) -> usize {
    //     // When indexed nexthop is None, set a new one.
    //     if let Some(&index) = self.map.get(&addr) {
    //         self.values[index]
    //             .get_or_insert_with(|| Nexthop::new(addr))
    //             .refcnt += 1;
    //         return index;
    //     }

    //     // Insert new nexthop if the address does not exist
    //     let index = self.values.len();
    //     self.map.insert(addr, index);
    //     self.values.push(Some(Nexthop::new(addr)));
    //     index
    // }

    pub fn register_group(&mut self, addr: Ipv4Addr) -> usize {
        if let Some(&index) = self.map.get(&addr) {
            index
        } else {
            let index = self.groups.len();
            self.map.insert(addr, index);
            self.groups.push(GroupSet::new_uni(&addr, index));
            index
        }
    }

    pub fn unregister(&mut self, addr: Ipv4Addr) {
        // Decrement refcnt; if it reaches zero, remove the nexthop at this index.
        if let Some(&index) = self.map.get(&addr) {
            // if let Some(ref mut nhop) = self.groups.[index] {
            //     nhop.refcnt -= 1;
            //     if nhop.refcnt == 0 {
            //         // self.values[index] = None;
            //     }
            // }
        }
    }

    // pub fn get(&self, index: usize) -> Option<&Nexthop> {
    //     self.values.get(index)?.as_ref()
    // }

    pub fn get_mut(&mut self, index: usize) -> Option<&mut GroupSet> {
        self.groups.get_mut(index)
    }

    pub fn lookup(&self, addr: Ipv4Addr) -> Option<usize> {
        self.map.get(&addr).copied()
    }

    // pub fn resolve(&mut self, table: &PrefixMap<Ipv4Net, RibEntries>) {
    //     for n in self.groups.iter_mut().flatten() {
    //         match rib_resolve(table, n.addr, &ResolveOpt::default()) {
    //             Resolve::NotFound => {
    //                 n.invalid = true;
    //             }
    //             Resolve::Onlink(_) => {
    //                 n.onlink = true;
    //             }
    //             Resolve::Recursive(resolved) => {
    //                 n.resolved = resolved;
    //             }
    //         }
    //     }
    // }

    pub async fn shutdown(&mut self, fib: &FibHandle) {
        for grp in self.groups.iter() {
            if grp.is_installed() {
                fib.nexthop_del(grp).await;
            }
        }
    }
}
