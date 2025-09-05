use std::{collections::BTreeMap, net::Ipv4Addr};

use ospf_packet::OspfLsa;

pub struct Lsdb {
    pub db: BTreeMap<(u32, Ipv4Addr), OspfLsa>,
}

impl Lsdb {
    pub fn new() -> Self {
        Self {
            db: BTreeMap::new(),
        }
    }
}
