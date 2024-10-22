use ipnet::Ipv4Net;

use super::fib::FibHandle;
use super::nexthop::Nexthop;
use super::{Rib, RibSubType, RibType, StaticRoute};

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
    pub link_index: u32,
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
            link_index: 0,
        }
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
    pub st: Option<StaticRoute>,
}

impl RibEntries {
    pub async fn static_process(&mut self, prefix: &Ipv4Net, fib: &FibHandle) {
        self.ribs.retain(|x| x.rtype != RibType::Static);

        if let Some(st) = &self.st {
            let mut sts: Vec<RibEntry> = st.to_ribs();
            self.ribs.append(&mut sts);
        }

        self.process(prefix, fib).await;
    }

    pub async fn process(&mut self, prefix: &Ipv4Net, fib: &FibHandle) {
        let index = self
            .ribs
            .iter()
            .filter(|x| x.valid)
            .enumerate()
            .fold(
                None,
                |acc: Option<(usize, &RibEntry)>, (index, entry)| match acc {
                    Some((_, aentry))
                        if entry.distance > aentry.distance
                            || (entry.distance == aentry.distance
                                && entry.metric > aentry.metric) =>
                    {
                        acc
                    }
                    _ => Some((index, entry)),
                },
            )
            .map(|(index, _)| index);

        while let Some(entry) = self.fibs.pop() {
            println!("Del: {} [{}/{}]", prefix, entry.distance, entry.metric);
            fib.route_ipv4_del(prefix, &entry).await;
        }

        if let Some(sindex) = index {
            let entry = self.ribs.get(sindex).unwrap();
            println!("Add: {} [{}/{}]", prefix, entry.distance, entry.metric);
            fib.route_ipv4_add(prefix, entry).await;
            self.fibs.push(entry.clone());
        }
    }
}
