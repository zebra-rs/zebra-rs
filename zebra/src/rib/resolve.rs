use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use prefix_trie::PrefixMap;

use super::RibEntries;

pub enum Resolve {
    Onlink(u32),
    Recursive(u32),
    NotFound,
}

impl Resolve {
    pub fn is_valid(&self) -> u32 {
        match self {
            Self::Onlink(v) | Self::Recursive(v) => *v,
            Self::NotFound => 0,
        }
    }
}

#[derive(Default)]
pub struct ResolveOpt {
    allow_default: bool,
    #[allow(dead_code)]
    limit: u8,
}

impl ResolveOpt {
    // Use default route for recursive lookup.
    pub fn allow_default(&self) -> bool {
        self.allow_default
    }
}

pub fn rib_resolve(
    table: &PrefixMap<Ipv4Net, RibEntries>,
    p: Ipv4Addr,
    opt: &ResolveOpt,
) -> Resolve {
    let Ok(key) = Ipv4Net::new(p, Ipv4Addr::BITS as u8) else {
        return Resolve::NotFound;
    };

    let Some((p, entries)) = table.get_lpm(&key) else {
        return Resolve::NotFound;
    };

    if !opt.allow_default() && p.prefix_len() == 0 {
        return Resolve::NotFound;
    }

    for entry in entries.iter() {
        if entry.is_connected() {
            return Resolve::Onlink(entry.ifindex);
        }
        if entry.is_static() {
            return Resolve::Recursive(1);
        }
    }
    Resolve::NotFound
}
