use super::entry::{RibEntry, RibType};
use super::fib::message::FibRoute;
use super::instance::Rib;
use ipnet::{IpNet, Ipv4Net};

impl Rib {
    pub fn ipv4_add(&mut self, dest: Ipv4Net, e: RibEntry) {
        let ribs = self.rib.entry(dest).or_default();
        ribs.push(e);
    }

    pub fn route_add(&mut self, r: FibRoute) {
        if let IpNet::V4(v4) = r.route {
            let mut e = RibEntry::new(RibType::Kernel);
            e.distance = 0;
            e.selected = true;
            e.fib = true;
            e.gateway = r.gateway;
            if !e.gateway.is_unspecified() {
                self.ipv4_add(v4, e);
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
