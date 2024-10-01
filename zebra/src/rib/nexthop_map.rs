use std::collections::BTreeMap;
use std::net::Ipv4Addr;

#[derive(Default)]
pub struct NexthopResolve {
    pub resolved: bool,
    pub valid: bool,
    refcnt: usize,
}

pub struct NexthopMap {
    pub map: BTreeMap<Ipv4Addr, NexthopResolve>,
}

impl NexthopMap {
    pub fn new() -> Self {
        Self {
            map: BTreeMap::new(),
        }
    }

    pub fn set() {}

    pub fn add(&mut self, nhop: &Ipv4Addr) {}

    pub fn del(&mut self, nhop: &Ipv4Addr) {}

    pub fn need_resolve_all(&mut self) {
        self.map.iter_mut().for_each(|(_, x)| x.resolved = false);
    }
}
