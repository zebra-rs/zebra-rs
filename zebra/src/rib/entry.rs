use super::nexthop::Nexthop;
use super::{Rib, RibSubType, RibType};

#[derive(Debug, Clone, PartialEq)]
pub struct RibEntry {
    pub rtype: RibType,
    pub rsubtype: RibSubType,
    pub selected: bool,
    pub fib: bool,
    valid: bool,
    pub distance: u8,
    pub metric: u32,
    pub nexthops: Vec<Nexthop>,
    pub nhops: Vec<usize>,
    pub resolved: Vec<Nexthop>,
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
            nhops: Vec::new(),
            ifindex: 0,
            resolved: Vec::new(),
        }
    }

    pub fn is_static(&self) -> bool {
        self.rtype == RibType::Static
    }

    pub fn is_connected(&self) -> bool {
        self.rtype == RibType::Connected
    }

    pub fn is_valid(&self) -> bool {
        true
    }

    pub fn is_fib(&self) -> bool {
        self.fib
    }

    pub fn set_fib(&mut self, fib: bool) {
        self.fib = fib;
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
}

#[derive(Default)]
pub struct RibEntries {
    pub ribs: Vec<RibEntry>,
    // pub fibs: Vec<RibEntry>,
}
