use std::collections::BTreeMap;
use std::fmt;
use std::net::Ipv4Addr;

use crate::rib::entry::RibEntry;
use crate::rib::nexthop::Nexthop;
use crate::rib::{NexthopMulti, RibType};

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

    pub fn to_entry(&self) -> Option<RibEntry> {
        if self.nexthops.is_empty() {
            return None;
        }

        let mut entry = RibEntry::new(RibType::Static);
        entry.distance = self.distance.unwrap_or(1);

        let metric = self.metric.unwrap_or(0);

        if self.nexthops.len() == 1 {
            let Some((p, n)) = self.nexthops.iter().next() else {
                return None;
            };
            let mut nhop = Nexthop::default();
            nhop.addr = *p;
            nhop.metric = n.metric.unwrap_or(metric);
            nhop.weight = n.weight.unwrap_or(0);
            entry.nexthops.push(nhop);
            return Some(entry);
        }

        let mut map: BTreeMap<u32, Vec<(Ipv4Addr, StaticNexthop)>> = BTreeMap::new();
        for (p, n) in self.nexthops.clone().iter() {
            let metric = n.metric.unwrap_or(metric);
            let e = map.entry(metric).or_default();
            e.push((*p, n.clone()));
        }

        if map.len() == 1 {
            // ECMP/UCMP case.
            let Some((metric, pair)) = map.iter().next() else {
                return None;
            };
            let mut multi = NexthopMulti::default();
            multi.metric = *metric;
            for (p, n) in pair.iter() {
                let mut nhop = Nexthop::default();
                nhop.addr = *p;
                nhop.metric = n.metric.unwrap_or(*metric);
                nhop.weight = n.weight.unwrap_or(0);
                multi.nexthops.insert(*p, nhop);
            }
        } else {
            // Protected.
        }
        Some(entry)
    }
}
