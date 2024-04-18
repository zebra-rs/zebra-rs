use std::net::{IpAddr, Ipv4Addr};

use super::nexthop::Nexthop;

#[derive(Debug, PartialEq)]
#[allow(dead_code, non_camel_case_types, clippy::upper_case_acronyms)]
pub enum RibType {
    UNKNOWN,
    KERNEL,
    CONNECTED,
    STATIC,
    RIP,
    OSPF,
    ISIS,
    BGP,
}

#[derive(Debug, PartialEq)]
#[allow(dead_code, non_camel_case_types)]
pub enum RibSubType {
    Unknown,
    OSPF_IA,
    OSPF_NSSA_1,
    OSPF_NSSA_2,
    OSPF_EXTERNAL_1,
    OSPF_EXTERNAL_2,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct RibEntry {
    pub rtype: RibType,
    pub rsubtype: RibSubType,
    pub selected: bool,
    pub fib: bool,
    pub distance: u32,
    pub metric: u32,
    pub tag: u32,
    pub color: Vec<String>,
    pub nexthops: Vec<Nexthop>,
    pub gateway: IpAddr,
    pub link_index: u32,
}

impl RibEntry {
    pub fn new() -> Self {
        Self {
            rtype: RibType::UNKNOWN,
            rsubtype: RibSubType::Unknown,
            selected: false,
            fib: false,
            distance: 0,
            metric: 0,
            tag: 0,
            color: Vec::new(),
            nexthops: Vec::new(),
            gateway: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            link_index: 0,
        }
    }

    pub fn distance(&self) -> String {
        if self.rtype != RibType::CONNECTED {
            format!(" [{}/{}]", &self.distance, &self.metric)
        } else {
            String::new()
        }
    }

    pub fn gateway(&self) -> String {
        if self.rtype == RibType::CONNECTED {
            format!("directly connected {}", &self.link_index)
        } else {
            format!("via {:?}", &self.gateway)
        }
    }

    pub fn selected(&self) -> String {
        let selected = if self.selected { '>' } else { ' ' };
        let fib = if self.fib { '*' } else { ' ' };
        format!("{}{}", fib, selected)
    }
}
