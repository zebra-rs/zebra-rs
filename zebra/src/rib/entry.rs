use super::{nexthop::Nexthop, Rib};

#[derive(Debug, PartialEq, Clone)]
#[allow(non_camel_case_types, dead_code, clippy::upper_case_acronyms)]
pub enum RibType {
    Kernel,
    Connected,
    Static,
    RIP,
    OSPF,
    ISIS,
    BGP,
}

#[derive(Debug, PartialEq, Clone)]
#[allow(non_camel_case_types, dead_code)]
pub enum RibSubType {
    NotApplicable,
    OSPF_IA,
    OSPF_NSSA_1,
    OSPF_NSSA_2,
    OSPF_External_1,
    OSPF_External_2,
    ISIS_Level_1,
    ISIS_Level_2,
    ISIS_Intra_Area,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
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
    // pub gateway: IpAddr,
    pub link_index: u32,
}

impl RibEntry {
    pub fn new(rtype: RibType) -> Self {
        Self {
            rtype,
            rsubtype: RibSubType::NotApplicable,
            selected: false,
            fib: false,
            distance: 0,
            metric: 0,
            tag: 0,
            color: Vec::new(),
            nexthops: Vec::new(),
            // gateway: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
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
        } else {
            if !self.nexthops.is_empty() {
                format!("via {}", &self.nexthops[0])
            } else {
                format!("")
            }
        }
    }

    pub fn selected(&self) -> String {
        let selected = if self.selected { '>' } else { ' ' };
        let fib = if self.fib { '*' } else { ' ' };
        format!("{}{}", fib, selected)
    }
}
