use ipnet::Ipv4Net;
use std::{collections::BTreeMap, net::Ipv4Addr};

use super::Action;

#[derive(Default)]
pub struct PrefixListIpv4Map {
    pub plist: BTreeMap<String, PrefixListIpv4>,
    pub cache: BTreeMap<String, PrefixListIpv4>,
}

#[derive(Default, Clone, Debug)]
pub struct PrefixListIpv4 {
    pub seq: BTreeMap<u32, PrefixListIpv4Entry>,
    pub delete: bool,
}

#[derive(Clone, Debug)]
pub struct PrefixListIpv4Entry {
    pub action: Action,
    pub prefix: Ipv4Net,
    pub le: Option<u8>,
    pub eq: Option<u8>,
    pub ge: Option<u8>,
}

impl Default for PrefixListIpv4Entry {
    fn default() -> Self {
        Self {
            action: Action::Permit,
            prefix: Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).unwrap(),
            le: None,
            eq: None,
            ge: None,
        }
    }
}

pub fn plist_ipv4_show(plist: &BTreeMap<String, PrefixListIpv4>) {
    for (n, p) in plist.iter() {
        println!("name: {}", n);
        for (seq, e) in p.seq.iter() {
            println!(
                " seq: {} action: {} prefix: {} le: {} eq: {} ge: {}",
                seq,
                e.action,
                e.prefix,
                e.le.unwrap_or(0),
                e.eq.unwrap_or(0),
                e.ge.unwrap_or(0)
            );
        }
    }
}
