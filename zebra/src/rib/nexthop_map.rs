use std::{collections::BTreeMap, net::Ipv4Addr};

use super::nexthop::Nexthop;

#[derive(Default)]
struct NexthopMap {
    map: BTreeMap<Ipv4Addr, usize>,
    values: Vec<Option<Nexthop>>,
}

impl NexthopMap {
    pub fn register(&mut self, addr: Ipv4Addr) -> usize {
        // When indexed nexthop is None, set a new one.
        if let Some(&index) = self.map.get(&addr) {
            self.values[index]
                .get_or_insert_with(|| Nexthop::new(addr))
                .refcnt += 1;
            return index;
        }

        // Insert new nexthop if the address does not exist
        let index = self.values.len();
        self.map.insert(addr, index);
        self.values.push(Some(Nexthop::new(addr)));
        index
    }

    pub fn unregister(&mut self, addr: Ipv4Addr) {
        // Decrement refcnt; if it reaches zero, remove the nexthop at this index.
        if let Some(&index) = self.map.get(&addr) {
            if let Some(ref mut nhop) = self.values[index] {
                nhop.refcnt -= 1;
                if nhop.refcnt == 0 {
                    self.values[index] = None;
                }
            }
        }
    }

    pub fn get(&self, index: usize) -> Option<&Nexthop> {
        self.values.get(index)?.as_ref()
    }

    pub fn lookup(&self, addr: Ipv4Addr) -> Option<usize> {
        self.map.get(&addr).copied()
    }
}
