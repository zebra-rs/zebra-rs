use ipnet::IpNet;
use std::net::IpAddr;

use crate::fib::message::FibRoute;

use super::entry::RibEntry;
use super::inst::Rib;
use super::nexthop::Nexthop;
use super::{Message, RibType};

impl Rib {
    pub fn route_add(&mut self, r: FibRoute) {
        if let IpNet::V4(v4) = r.route {
            let mut e = RibEntry::new(RibType::Kernel);
            e.distance = 0;
            e.set_selected(true);
            e.set_fib(true);
            if let IpAddr::V4(addr) = r.gateway {
                if !addr.is_unspecified() {
                    let mut nexthop = Nexthop::default();
                    nexthop.addr = addr;
                    e.nexthops.push(nexthop);
                    let _ = self.tx.send(Message::Ipv4Add { prefix: v4, rib: e });
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
