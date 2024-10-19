use super::entry::{RibEntry, RibType};
use super::fib::message::FibRoute;
use super::instance::Rib;
use super::nexthop::Nexthop;
use ipnet::{IpNet, Ipv4Net};
use prefix_trie::PrefixMap;
use std::net::IpAddr;

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
