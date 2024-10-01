use std::net::IpAddr;

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
        let find = rib_same_type(&ribs, &e);
        match find {
            Some(index) => {
                let prev = ribs.remove(index);
                println!("XX Prev {:?}", prev);
            }
            None => {
                // println!("XX No same type rib");
            }
        }

        // Nexthop resolve.
        // if e.rtype == RibType::Static {
        //     for nhop in e.nexthops.iter() {
        //         if let Some(addr) = nhop.addr {
        //             let addr = Ipv4Net::new(addr, 32).unwrap();
        //             self.rib.get_lpm(&addr);
        //         }
        //         //nexthop_resolve(&self.rib, nhop);
        //     }
        // }

        ribs.push(e);
        // Path selection.
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
                    println!("XXX kernel route add");
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
