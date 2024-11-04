use std::collections::BTreeMap;
use std::fmt;
use std::net::Ipv4Addr;

use crate::rib::entry::RibEntry;
use crate::rib::nexthop::Nexthop;
use crate::rib::RibType;

#[derive(Debug, Default, Clone)]
pub struct StaticNexthop {
    pub metric: Option<u32>,
    pub weight: Option<u8>,
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
            let metric = n.metric.unwrap_or(metric);
            let weight = n.weight.unwrap_or(1);
            writeln!(f, "  {} metric {} weight {}", p, metric, weight).unwrap();
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
        let mut map: BTreeMap<u32, Vec<Nexthop>> = BTreeMap::new();
        let metric = self.metric.unwrap_or(0);
        let distance = self.distance.unwrap_or(1);

        for (p, n) in self.nexthops.iter() {
            let metric = n.metric.unwrap_or(metric);
            let e = map.entry(metric).or_default();
            let mut nhop = Nexthop::default();
            nhop.addr = *p;
            if let Some(w) = n.weight {
                nhop.weight = w;
            }
            e.push(nhop);
        }
        for (m, v) in map.iter() {
            let mut entry = RibEntry::new(RibType::Static);
            entry.distance = distance;
            entry.metric = *m;
            entry.nexthops = v.clone();
            // entry.valid = true;
            entries.push(entry);
        }
        entries
    }

    // pub fn to_entry(&self) -> Option<RibEntry> {
    //     if self.nexthops.is_empty() {
    //         return None;
    //     }
    //     let mut entry = RibEntry::new(RibType::Static);

    //     let distance = self.distance.unwrap_or(1);
    //     entry.distance = distance;

    //     if self.nexthops.len() == 1 {
    //         // Uni nexthop.
    //         // NexthopUni::new()
    //     }

    //     let mut map: BTreeMap<u32, Vec<Nexthop>> = BTreeMap::new();
    //     let metric = self.metric.unwrap_or(0);

    //     for (p, n) in self.nexthops.iter() {
    //         let metric = n.metric.unwrap_or(metric);
    //         let e = map.entry(metric).or_default();

    //         let mut nhop = Nexthop::default();
    //         nhop.addr = *p;
    //         if let Some(w) = n.weight {
    //             nhop.weight = w;
    //         }
    //         e.push(nhop);
    //     }
    //     for ((d, m), v) in map.iter() {
    //         let mut entry = RibEntry::new(RibType::Static);
    //         entry.distance = *d;
    //         entry.metric = *m;
    //         entry.nexthops = v.clone();
    //         // entry.valid = true;
    //         entries.push(entry);
    //     }
    //     Some(entry)
    // }
}
