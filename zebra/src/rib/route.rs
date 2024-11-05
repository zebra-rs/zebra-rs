use ipnet::{IpNet, Ipv4Net};
use prefix_trie::PrefixMap;
use std::net::{IpAddr, Ipv4Addr};

use crate::fib::message::FibRoute;
use crate::fib::FibHandle;

use super::entry::RibEntry;
use super::inst::Rib;
use super::nexthop::Nexthop;
use super::{Message, RibEntries, RibType};

impl Rib {
    pub fn route_add(&mut self, r: FibRoute) {
        if let IpNet::V4(v4) = r.route {
            let mut e = RibEntry::new(RibType::Kernel);
            e.distance = 0;
            e.set_selected(true);
            e.set_fib(true);
            if let IpAddr::V4(addr) = r.gateway {
                if !addr.is_unspecified() {
                    let mut nexthop = Nexthop::default();
                    nexthop.addr = addr;
                    e.nexthops.push(nexthop);
                    let _ = self.tx.send(Message::Ipv4Add { prefix: v4, rib: e });
                }
            }
        }
    }

    pub fn route_del(&mut self, r: FibRoute) {
        if let IpNet::V4(v4) = r.route {
            if let Some(_ribs) = self.table.get(&v4) {
                //
            }
        }
    }

    pub async fn ipv4_route_add(&mut self, prefix: &Ipv4Net, mut rib: RibEntry) {
        let replace = rib_replace(&mut self.table, prefix, rib.rtype);

        if rib.is_protocol() {
            for nhop in rib.nexthops.iter_mut() {
                let gid = self.nmap.register_group(nhop.addr);
                nhop.gid = gid;

                let resolve = rib_resolve(&self.table, nhop.addr, &ResolveOpt::default());
            }
            for nhop in rib.nexthops.iter() {
                let gid = nhop.gid;
                if let Some(uni) = self.nmap.get_mut(gid) {
                    uni.resolve(&self.table);
                    uni.sync(&self.fib_handle).await;
                }
            }
        }
        rib_add(&mut self.table, prefix, rib);

        let selected = rib_select(&self.table, prefix);
        rib_sync(&mut self.table, prefix, selected, replace, &self.fib_handle).await;
    }

    pub async fn ipv4_route_del(&mut self, prefix: &Ipv4Net, rib: RibEntry) {
        let replace = rib_replace(&mut self.table, prefix, rib.rtype);
        let selected = rib_select(&self.table, prefix);
        rib_sync(&mut self.table, prefix, selected, replace, &self.fib_handle).await;
    }
}

pub fn rib_add(rib: &mut PrefixMap<Ipv4Net, RibEntries>, prefix: &Ipv4Net, entry: RibEntry) {
    let entries = rib.entry(*prefix).or_default();
    entries.ribs.push(entry);
}

pub fn rib_replace(
    rib: &mut PrefixMap<Ipv4Net, RibEntries>,
    prefix: &Ipv4Net,
    rtype: RibType,
) -> Vec<RibEntry> {
    let Some(entries) = rib.get_mut(prefix) else {
        return vec![];
    };
    let (remain, replace): (Vec<_>, Vec<_>) =
        entries.ribs.drain(..).partition(|x| x.rtype != rtype);
    entries.ribs = remain;
    replace
}

pub enum Resolve {
    Onlink(u32),
    #[allow(dead_code)]
    Recursive(u8),
    NotFound,
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

    // Zero means infinite lookup.
    #[allow(dead_code)]
    pub fn limit(&self) -> u8 {
        self.limit
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

    for entry in entries.ribs.iter() {
        if entry.rtype == RibType::Connected {
            return Resolve::Onlink(entry.ifindex);
        }
        if entry.rtype == RibType::Static {
            return Resolve::Recursive(1);
        }
    }
    Resolve::NotFound
}

pub fn rib_select(rib: &PrefixMap<Ipv4Net, RibEntries>, prefix: &Ipv4Net) -> Option<usize> {
    let entries = rib.get(prefix)?;
    let index = entries
        .ribs
        .iter()
        .filter(|x| x.is_valid())
        .enumerate()
        .fold(
            None,
            |acc: Option<(usize, &RibEntry)>, (index, entry)| match acc {
                Some((_, aentry))
                    if entry.distance > aentry.distance
                        || (entry.distance == aentry.distance && entry.metric > aentry.metric) =>
                {
                    acc
                }
                _ => Some((index, entry)),
            },
        )
        .map(|(index, _)| index);

    index
}

pub async fn rib_sync(
    rib: &mut PrefixMap<Ipv4Net, RibEntries>,
    prefix: &Ipv4Net,
    index: Option<usize>,
    mut replace: Vec<RibEntry>,
    fib: &FibHandle,
) {
    let Some(entries) = rib.get_mut(prefix) else {
        return;
    };

    while let Some(entry) = replace.pop() {
        if entry.is_fib() {
            fib.route_ipv4_del(prefix, &entry).await;
        }
    }

    if let Some(sindex) = index {
        let entry = entries.ribs.get_mut(sindex).unwrap();
        fib.route_ipv4_add(prefix, &entry).await;
        entry.set_fib(true);
    }
}

// fn resolve(nmap: &NexthopMap, nexthops: &[usize], opt: &ResolveOpt) -> (Vec<Nexthop>, u8) {
//     let mut acc: BTreeSet<Ipv4Addr> = BTreeSet::new();
//     let mut sea_depth: u8 = 0;
//     nexthops
//         .iter()
//         .filter_map(|r| nmap.get(*r))
//         .for_each(|nhop| {
//             resolve_func(nmap, nhop, &mut acc, &mut sea_depth, opt, 0);
//         });
//     let mut nvec: Vec<Nexthop> = Vec::new();
//     for a in acc.iter() {
//         nvec.push(Nexthop::new(*a));
//     }
//     (nvec, sea_depth)
// }

// fn resolve_func(
//     nmap: &NexthopMap,
//     nhop: &Nexthop,
//     acc: &mut BTreeSet<Ipv4Addr>,
//     sea_depth: &mut u8,
//     opt: &ResolveOpt,
//     depth: u8,
// ) {
//     if opt.limit() > 0 && depth >= opt.limit() {
//         return;
//     }

//     // if sea_depth depth is not current one.
//     if *sea_depth < depth {
//         *sea_depth = depth;
//     }

//     // Early exit if the current nexthop is invalid
//     if nhop.invalid {
//         return;
//     }

//     // Directly insert if on-link, otherwise recursively resolve nexthops
//     if nhop.onlink {
//         acc.insert(nhop.addr);
//         return;
//     }

//     nhop.resolved
//         .iter()
//         .filter_map(|r| nmap.get(*r))
//         .for_each(|nhop| {
//             resolve_func(nmap, nhop, acc, sea_depth, opt, depth + 1);
//         });
// }
