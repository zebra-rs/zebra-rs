use std::collections::BTreeMap;
use std::fmt;
use std::net::Ipv4Addr;

use crate::rib::entry::{RibEntry, RibType};
use crate::rib::nexthop::Nexthop;

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
    pub delete: bool,
}

impl fmt::Display for StaticRoute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let distance = self.distance.unwrap_or(1);
        let metric = self.metric.unwrap_or(0);

        write!(f, "[{}/{}]", distance, metric).unwrap();
        for (p, n) in self.nexthops.iter() {
            let distance = n.distance.unwrap_or(distance);
            let metric = n.metric.unwrap_or(metric);
            writeln!(f, "  {} [{}/{}]", p, distance, metric).unwrap();
        }
        write!(f, "")
    }
}

impl StaticRoute {
    pub fn to_ribs(&self) -> Vec<RibEntry> {
        let mut entries: Vec<RibEntry> = Vec::new();
        if self.nexthops.is_empty() {
            return entries;
        }
        let mut map: BTreeMap<(u8, u32), Vec<Ipv4Addr>> = BTreeMap::new();
        let metric = self.metric.unwrap_or(0);
        let distance = self.distance.unwrap_or(1);
        for (p, n) in self.nexthops.iter() {
            let metric = n.metric.unwrap_or(metric);
            let distance = n.distance.unwrap_or(distance);
            let e = map.entry((distance, metric)).or_default();
            e.push(*p);
        }
        for ((d, m), v) in map.iter() {
            let mut entry = RibEntry::new(RibType::Static);
            entry.distance = *d;
            entry.metric = *m;
            for n in v.iter() {
                let mut nhop = Nexthop::default();
                nhop.addr = Some(*n);
                entry.nexthops.push(nhop);
            }
            entries.push(entry);
        }
        entries
    }
}
