use crate::fib::FibHandle;

use super::nexthop::{GroupTrait, Nexthop};
use super::{GroupSet, NexthopMap, NexthopSet, Rib, RibSubType, RibType};

#[derive(Debug, Clone, PartialEq)]
pub struct RibEntry {
    pub rtype: RibType,
    pub rsubtype: RibSubType,
    selected: bool,
    fib: bool,
    valid: bool,
    pub distance: u8,
    pub metric: u32,
    pub nexthops: Vec<Nexthop>,

    // Nexthop set. Nexthop can be unipath, multipath and protected path.
    pub nhopset: NexthopSet,

    // Connected RIB's ifindex.
    pub ifindex: u32,
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
            nhopset: NexthopSet::default(),
            ifindex: 0,
        }
    }

    pub fn is_connected(&self) -> bool {
        self.rtype == RibType::Connected
    }

    pub fn set_valid(&mut self, valid: bool) {
        self.valid = valid;
    }

    pub fn is_valid(&self) -> bool {
        self.valid
    }

    pub fn is_protocol(&self) -> bool {
        match self.rtype {
            RibType::Static | RibType::Rip | RibType::Ospf | RibType::Isis | RibType::Bgp => true,
            _ => false,
        }
    }

    pub fn is_fib(&self) -> bool {
        self.fib
    }

    pub fn set_fib(&mut self, fib: bool) {
        self.fib = fib;
    }

    pub fn is_selected(&self) -> bool {
        self.selected
    }

    pub fn set_selected(&mut self, selected: bool) {
        self.selected = selected;
    }

    pub fn distance(&self) -> String {
        if self.rtype != RibType::Connected {
            format!(" [{}/{}]", &self.distance, &self.metric)
        } else {
            String::new()
        }
    }

    pub fn gateway(&self, rib: &Rib) -> String {
        if self.is_connected() {
            if let Some(name) = rib.link_name(self.ifindex) {
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

    pub fn is_valid_nexthop(&self, nmap: &NexthopMap) -> bool {
        self.nexthops
            .iter()
            .any(|nhop| nmap.get(nhop.gid).map_or(false, |group| group.is_valid()))
    }

    pub async fn nexthop_sync(&mut self, nmap: &mut NexthopMap, fib: &FibHandle) {
        for nhop in &mut self.nexthops {
            let Some(group) = nmap.get_mut(nhop.gid) else {
                continue;
            };
            if !group.is_valid() || group.is_installed() {
                continue;
            }
            fib.nexthop_add(group).await;
            group.set_installed(true);
        }
    }
}

#[derive(Default)]
pub struct RibEntries {
    pub ribs: Vec<RibEntry>,
}
