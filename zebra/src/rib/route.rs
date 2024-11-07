use ipnet::{IpNet, Ipv4Net};
use prefix_trie::PrefixMap;
use std::net::{IpAddr, Ipv4Addr};

use crate::fib::message::FibRoute;
use crate::fib::FibHandle;
use crate::rib::util::IpNetExt;

use super::entry::RibEntry;
use super::inst::Rib;
use super::nexthop::Nexthop;
use super::{GroupSet, GroupTrait, Message, NexthopMap, RibEntries, RibType};

pub async fn ipv4_entry_sync(
    prefix: &Ipv4Net,
    entries: &mut RibEntries,
    replace: Option<RibEntry>,
    nmap: &mut NexthopMap,
    fib: &FibHandle,
) {
    // Selected.
    let prev = rib_prev(&entries.ribs);

    // New select.
    let next = rib_next(&entries.ribs);

    if prev.is_some() && prev == next {
        println!("prev and next is same");
        return;
    }

    if let Some(replace) = replace {
        if replace.is_protocol() && replace.is_fib() {
            fib.route_ipv4_del(prefix, &replace).await;
            for nhop in replace.nexthops.iter() {
                nmap.unregister(nhop.gid, fib).await;
            }
        }
    }
    if let Some(prev) = prev {
        let prev = entries.ribs.get_mut(prev).unwrap();
        fib.route_ipv4_del(prefix, prev).await;
        for nhop in prev.nexthops.iter() {
            nmap.unregister(nhop.gid, fib).await;
        }
        prev.set_selected(false);
        prev.set_fib(false);
    }
    if let Some(next) = next {
        let next = entries.ribs.get_mut(next).unwrap();
        next.set_selected(true);
        next.set_fib(true);
        // Add Route.
        if next.is_protocol() {
            for nhop in next.nexthops.iter_mut() {
                nhop.gid = nmap.register_group(nhop.addr, nhop.ifindex, fib).await;
            }
            fib.route_ipv4_add(prefix, &next).await;
        }
    }
}

fn entry_valid_check(entry: &RibEntry) -> bool {
    nexthop_valid(&entry.nexthops)
}

fn ipv4_entry_resolve(p: &Ipv4Net, entries: &mut RibEntries) {
    for entry in entries.ribs.iter_mut() {
        let valid = entry_valid_check(entry);
        entry.set_valid(valid);
        println!("nexthop valid {} -> {}", p, valid);
    }
}

pub async fn ipv4_route_sync(
    table: &mut PrefixMap<Ipv4Net, RibEntries>,
    nmap: &mut NexthopMap,
    fib: &FibHandle,
) {
    for (p, entries) in table.iter_mut() {
        ipv4_entry_resolve(p, entries);
        ipv4_entry_sync(p, entries, None, nmap, fib).await;
    }
}

impl Rib {
    pub async fn link_down(&mut self, ifindex: u32) {
        let Some(link) = self.links.get(&ifindex) else {
            return;
        };
        println!("link down: {}", link.name);

        // Remove connected route.
        for addr4 in link.addr4.iter() {
            if let IpNet::V4(addr) = addr4.addr {
                let prefix = addr.apply_mask();
                println!("Connected: {:?} down - removing from RIB", prefix);
                let mut rib = RibEntry::new(RibType::Connected);
                rib.ifindex = ifindex;
                let msg = Message::Ipv4Del { prefix, rib };
                self.tx.send(msg);
            }
        }
    }

    pub fn link_up(&mut self, ifindex: u32) {
        let Some(link) = self.links.get(&ifindex) else {
            return;
        };
        println!("link up {}", link.name);

        // Add connected route.
        for addr4 in link.addr4.iter() {
            if let IpNet::V4(addr) = addr4.addr {
                let prefix = addr.apply_mask();
                println!("Connected: {:?} add - adding to RIB", prefix);
                let mut rib = RibEntry::new(RibType::Connected);
                rib.ifindex = ifindex;
                let msg = Message::Ipv4Add { prefix, rib };
                self.tx.send(msg);
            }
        }

        // RIB resolve all.
        for (p, entries) in self.table.iter() {
            for rib in entries.ribs.iter() {
                println!("P: {} ifindex", p);
            }
        }
    }

    pub fn route_add(&mut self, r: FibRoute) {
        if let IpNet::V4(prefix) = r.route {
            let mut rib = RibEntry::new(RibType::Kernel);
            rib.set_valid(true);
            rib.set_fib(true);
            if let IpAddr::V4(addr) = r.gateway {
                if !addr.is_unspecified() {
                    let nexthop = Nexthop::new(addr);
                    rib.nexthops.push(nexthop);
                    let _ = self.tx.send(Message::Ipv4Add { prefix, rib });
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

    pub async fn ipv4_sync(&mut self) {
        ipv4_nexthop_sync(&mut self.nmap, &self.table);
        ipv4_route_sync(&mut self.table, &mut self.nmap, &self.fib_handle).await;
    }

    pub async fn ipv4_route_add(&mut self, prefix: &Ipv4Net, mut rib: RibEntry) {
        println!("IPv4 route add: {} {}", rib.rtype.abbrev(), prefix);
        let mut replace = rib_replace(&mut self.table, prefix, rib.rtype);
        rib_resolve_nexthop(&mut rib, &self.table);
        rib_add(&mut self.table, prefix, rib);
        self.rib_selection(prefix, replace.pop()).await;
        self.ipv4_sync().await;
    }

    pub async fn ipv4_route_del(&mut self, prefix: &Ipv4Net, rib: RibEntry) {
        println!("IPv4 route del: {} {}", rib.rtype.abbrev(), prefix);
        let mut replace = rib_replace(&mut self.table, prefix, rib.rtype);
        self.rib_selection(prefix, replace.pop()).await;
        self.ipv4_sync().await;
    }

    pub async fn rib_selection(&mut self, prefix: &Ipv4Net, replace: Option<RibEntry>) {
        let Some(entries) = self.table.get_mut(prefix) else {
            return;
        };
        ipv4_entry_sync(prefix, entries, replace, &mut self.nmap, &self.fib_handle);
    }
}

fn rib_resolve_nexthop(rib: &mut RibEntry, table: &PrefixMap<Ipv4Net, RibEntries>) {
    if !rib.is_protocol() {
        return;
    }
    for nhop in rib.nexthops.iter_mut() {
        let resolve = rib_resolve(table, nhop.addr, &ResolveOpt::default());
        let ifindex = resolve.is_valid();
        if ifindex != 0 {
            nhop.ifindex = ifindex;
        }
    }
    rib.set_valid(nexthop_valid(&rib.nexthops));
}

fn nexthop_valid(nhops: &Vec<Nexthop>) -> bool {
    // nhops.iter().any(|nhop| nhop.is_valid())
    false
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

fn rib_prev(entries: &Vec<RibEntry>) -> Option<usize> {
    entries.iter().position(|e| e.is_selected())
}

pub fn rib_next(ribs: &Vec<RibEntry>) -> Option<usize> {
    let index = ribs
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

pub fn ipv4_nexthop_sync(nmap: &mut NexthopMap, table: &PrefixMap<Ipv4Net, RibEntries>) {
    //for grp in nmap.
    for nhop in nmap.groups.iter_mut() {
        if let GroupSet::Uni(uni) = nhop {
            if uni.refcnt() == 0 {
                continue;
            }
            println!(
                "IPv4 nexthop: {} refcnt {} is_valid {} is_installed {}",
                uni.addr,
                uni.refcnt(),
                uni.is_valid(),
                uni.is_installed()
            );
            let resolve = rib_resolve(table, uni.addr, &ResolveOpt::default());
            println!(
                "resolve: uni id {}-> {} [{}]",
                uni.gid(),
                resolve.is_valid() != 0,
                resolve.is_valid()
            );
            if resolve.is_valid() == 0 {
                uni.set_valid(false);
                uni.set_installed(false);
            } else {
                uni.set_valid(true);
            }
        }
    }
}
