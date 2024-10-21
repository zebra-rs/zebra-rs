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

impl PrefixListIpv4 {
    pub fn apply(&self, prefix: &Ipv4Net) -> Action {
        for (_, seq) in self.seq.iter() {
            if seq.apply(prefix) {
                return seq.action.clone();
            }
        }
        Action::Deny
    }
}

#[derive(Clone, Debug)]
pub struct PrefixListIpv4Entry {
    pub action: Action,
    pub prefix: Ipv4Net,
    pub le: Option<u8>,
    pub eq: Option<u8>,
    pub ge: Option<u8>,
}

impl PrefixListIpv4Entry {
    pub fn apply(&self, prefix: &Ipv4Net) -> bool {
        if self.prefix.contains(prefix) {
            if let Some(le) = self.le {
                if prefix.prefix_len() <= le {
                    return true;
                } else {
                    return false;
                }
            }
            if let Some(eq) = self.eq {
                if prefix.prefix_len() == eq {
                    return true;
                } else {
                    return false;
                }
            }
            if let Some(ge) = self.ge {
                if prefix.prefix_len() >= ge {
                    return true;
                } else {
                    return false;
                }
            }
            self.prefix.prefix_len() == prefix.prefix_len()
        } else {
            false
        }
    }
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

#[allow(dead_code)]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply() {
        let net1: Ipv4Net = "10.1.1.0/24".parse().unwrap();
        let seq1 = PrefixListIpv4Entry {
            action: Action::Permit,
            prefix: net1,
            le: None,
            eq: None,
            ge: None,
        };
        let mut plist = PrefixListIpv4::default();
        plist.seq.insert(1, seq1);

        let net: Ipv4Net = "10.1.1.0/24".parse().unwrap();
        let action = plist.apply(&net);
        assert_eq!(action, Action::Permit);
    }
}
