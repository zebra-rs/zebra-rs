use super::entry::{RibEntry, RibType};
use super::fib::message::FibRoute;
use super::instance::Rib;
use super::nexthop::Nexthop;
use ipnet::{IpNet, Ipv4Net};
use prefix_trie::PrefixMap;

fn rib_same_type(ribs: &Vec<RibEntry>, entry: &RibEntry) -> Option<usize> {
    for (i, rib) in ribs.iter().enumerate() {
        if rib.rtype == entry.rtype {
            return Some(i);
        }
    }
    None
}

pub fn nexthop_resolve(table: &PrefixMap<Ipv4Net, Vec<RibEntry>>, nexthop: &Nexthop) {
    //
}

impl Rib {
    pub fn ipv4_add(&mut self, dest: Ipv4Net, e: RibEntry) {
        //nexthop_resolve(&self.rib, &e.nexthops[0]);

        let ribs = self.rib.entry(dest).or_default();
        let find = rib_same_type(&ribs.ribs, &e);
        let mut prev: Option<RibEntry> = None;
        match find {
            Some(index) => {
                prev = Some(ribs.ribs.remove(index));
            }
            None => {}
        }

        ribs.ribs.push(e);

        // Path selection.
        let mut selected: Option<usize> = None;
        let mut srib: Option<&RibEntry> = None;
        for (i, rib) in ribs.ribs.iter().enumerate() {
            if let Some(x) = srib {
                if rib.distance < x.distance {
                    srib = Some(rib);
                    selected = Some(i);
                }
            } else {
                srib = Some(rib);
                selected = Some(i);
            }
        }

        if let Some(prev) = prev {
            println!("Previous route {:?}", prev);
        }
        if let Some(selected) = selected {
            println!("Found selected");
            ribs.ribs[selected].selected = true;
            ribs.ribs[selected].fib = true;
        }
    }

    pub fn route_add(&mut self, r: FibRoute) {
        if let IpNet::V4(v4) = r.route {
            let mut e = RibEntry::new(RibType::Kernel);
            e.distance = 0;
            e.selected = true;
            e.fib = true;
            if let IpAddr::V4(addr) = r.gateway {
                if !addr.is_unspecified() {
                    let nexthop = Nexthop::builder().addr(addr).build();
                    e.nexthops.push(nexthop);
                    self.ipv4_add(v4, e);
                }
            }
        }
    }

    pub fn route_del(&mut self, r: FibRoute) {
        if let IpNet::V4(v4) = r.route {
            if let Some(_ribs) = self.rib.get(&v4) {
                //
            }
        }
    }
}

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};

#[derive(Debug, Default, Clone)]
pub struct StaticNexthop {
    pub distance: Option<u8>,
    pub metric: Option<u32>,
    pub weight: Option<u32>,
}

#[derive(Debug, Default, Clone)]
pub struct StaticRoute {
    pub distance: Option<u8>,
    pub metric: Option<u32>,
    pub nexthops: BTreeMap<Ipv4Addr, StaticNexthop>,
}

impl StaticRoute {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn to_rib(&self) -> Vec<RibEntry> {
        Vec::new()
    }

    pub fn set_metric(&mut self, metric: u32) {
        self.metric = Some(metric);
    }

    pub fn del_metric(&mut self) {
        self.metric = None;
    }

    pub fn set_distance(&mut self, distance: u8) {
        self.distance = Some(distance);
    }

    pub fn del_distance(&mut self) {
        self.distance = None;
    }

    pub fn set_nexthop(&mut self, nexthop: Ipv4Addr) {
        self.nexthops.entry(nexthop).or_default();
    }

    pub fn del_nexthop(&mut self, nexthop: Ipv4Addr) {
        self.nexthops.remove(&nexthop);
    }

    pub fn set_nexthop_distance(&mut self, nexthop: Ipv4Addr, distance: u8) {
        let nexthop = self.nexthops.entry(nexthop).or_default();
        nexthop.distance = Some(distance);
    }

    pub fn del_nexthop_distance(&mut self, nexthop: Ipv4Addr) {
        if let Some(nexthop) = self.nexthops.get_mut(&nexthop) {
            nexthop.distance = None;
        }
    }

    pub fn set_nexthop_metric(&mut self, nexthop: Ipv4Addr, metric: u32) {
        let nexthop = self.nexthops.entry(nexthop).or_default();
        nexthop.metric = Some(metric);
    }

    pub fn del_nexthop_metric(&mut self, nexthop: Ipv4Addr) {
        if let Some(nexthop) = self.nexthops.get_mut(&nexthop) {
            nexthop.metric = None;
        }
    }

    pub fn set_nexthop_weight(&mut self, nexthop: Ipv4Addr, weight: u32) {
        let nexthop = self.nexthops.entry(nexthop).or_default();
        nexthop.weight = Some(weight);
    }

    pub fn del_nexthop_weight(&mut self, nexthop: Ipv4Addr) {
        if let Some(nexthop) = self.nexthops.get_mut(&nexthop) {
            nexthop.weight = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_static_set() {
        let mut st = StaticRoute::new();
        assert_eq!(st.nexthops.len(), 0);

        let nexthop: Ipv4Addr = "1.1.1.1".parse().unwrap();
        st.set_nexthop(nexthop);
        assert_eq!(st.nexthops.len(), 1);

        st.set_metric(10);
        st.set_distance(10);
    }
}
