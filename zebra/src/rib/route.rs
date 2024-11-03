use ipnet::{IpNet, Ipv4Net};
use std::net::IpAddr;

use crate::fib::message::FibRoute;

use super::entry::RibEntry;
use super::inst::Rib;
use super::nexthop::Nexthop;
use super::{Message, RibType};

fn rib_same_type(ribs: &[RibEntry], entry: &RibEntry) -> Option<usize> {
    for (i, rib) in ribs.iter().enumerate() {
        if rib.rtype == entry.rtype {
            return Some(i);
        }
    }
    None
}

impl Rib {
    pub fn route_add(&mut self, r: FibRoute) {
        if let IpNet::V4(v4) = r.route {
            let mut e = RibEntry::new(RibType::Kernel);
            e.distance = 0;
            e.set_selected(true);
            e.set_fib(true);
            if let IpAddr::V4(addr) = r.gateway {
                if !addr.is_unspecified() {
                    let nexthop = Nexthop::builder().addr(addr).build();
                    e.nexthops.push(nexthop);
                    let _ = self.tx.send(Message::Ipv4Add {
                        rtype: RibType::Kernel,
                        prefix: v4,
                        ribs: vec![e],
                    });
                }
            }
        }
    }

    pub fn route_del(&mut self, r: FibRoute) {
        if let IpNet::V4(v4) = r.route {
            if let Some(_ribs) = self.table.get(&v4) {
                //
            }
        }
    }
}
