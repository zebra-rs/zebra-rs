use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use super::nexthop::Nexthop;
use super::{Rib, RibSubType, RibType};

#[derive(Debug, Clone, PartialEq)]
pub struct RibEntry {
    pub rtype: RibType,
    pub rsubtype: RibSubType,
    pub selected: bool,
    pub fib: bool,
    pub valid: bool,
    pub distance: u8,
    pub metric: u32,
    pub nexthops: Vec<Nexthop>,
    pub nhops: Vec<usize>,
    pub link_index: u32,
    pub resolved: BTreeSet<Ipv4Addr>,
}

impl RibEntry {
    pub fn new(rtype: RibType) -> Self {
        Self {
            rtype,
            rsubtype: RibSubType::Default,
            selected: false,
            fib: false,
            valid: false,
            distance: 0,
            metric: 0,
            nexthops: Vec::new(),
            nhops: Vec::new(),
            link_index: 0,
            resolved: BTreeSet::new(),
        }
    }

    pub fn is_static(&self) -> bool {
        self.rtype == RibType::Static
    }

    pub fn is_connected(&self) -> bool {
        self.rtype == RibType::Connected
    }

    pub fn distance(&self) -> String {
        if self.rtype != RibType::Connected {
            format!(" [{}/{}]", &self.distance, &self.metric)
        } else {
            String::new()
        }
    }

    pub fn gateway(&self, rib: &Rib) -> String {
        if self.rtype == RibType::Connected {
            if let Some(name) = rib.link_name(self.link_index) {
                format!("directly connected {}", name)
            } else {
                "directly connected unknown".to_string()
            }
        } else if !self.nexthops.is_empty() {
            let mut out: String = String::from("via ");
            for n in self.nexthops.iter() {
                out += &format!("{} ", n);
            }
            out
        } else {
            String::new()
        }
    }

    pub fn selected(&self) -> String {
        let selected = if self.selected { '>' } else { ' ' };
        let fib = if self.fib { '*' } else { ' ' };
        format!("{}{}", fib, selected)
    }
}

#[derive(Default)]
pub struct RibEntries {
    pub ribs: Vec<RibEntry>,
    pub fibs: Vec<RibEntry>,
}
