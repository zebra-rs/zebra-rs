use ipnet::{IpNet, Ipv4Net};
use prefix_trie::PrefixMap;
use std::net::{IpAddr, Ipv4Addr};

use crate::fib::message::FibRoute;
use crate::fib::FibHandle;
use crate::rib::resolve::{rib_resolve, ResolveOpt};
use crate::rib::util::IpNetExt;

use super::entry::RibEntry;
use super::inst::Rib;
use super::nexthop::Nexthop;
use super::{GroupSet, GroupTrait, Message, NexthopMap, RibEntries, RibType};

pub async fn ipv4_entry_selection(
    prefix: &Ipv4Net,
    entries: &mut RibEntries,
    replace: Option<RibEntry>,
    nmap: &mut NexthopMap,
    fib: &FibHandle,
) {
    if let Some(mut replace) = replace {
        if replace.is_protocol() && replace.is_fib() {
            fib.route_ipv4_del(prefix, &replace).await;
            replace.nexthop_unsync(nmap, fib).await;
        }
    }
    // Selected.
    let prev = rib_prev(&entries);

    // New select.
    let next = rib_next(&entries);

    if prev == next {
        return;
    }
    if let Some(prev) = prev {
        let prev = entries.get_mut(prev).unwrap();
        prev.set_selected(false);

        fib.route_ipv4_del(prefix, prev).await;
        prev.set_fib(false);
    }
    if let Some(next) = next {
        let next = entries.get_mut(next).unwrap();
        next.set_selected(true);

        if next.is_protocol() {
            next.nexthop_sync(nmap, fib).await;
            fib.route_ipv4_add(prefix, &next).await;
        }
        next.set_fib(true);
    }
}

// Resolve RibEntries.  gid is already resolved.
fn ipv4_entry_resolve(_p: &Ipv4Net, entries: &mut RibEntries, nmap: &NexthopMap) {
    for entry in entries.iter_mut() {
        if entry.is_protocol() {
            let valid = entry.is_valid_nexthop(nmap);
            entry.set_valid(valid);
        }
    }
}

pub async fn ipv4_route_sync(
    table: &mut PrefixMap<Ipv4Net, RibEntries>,
    nmap: &mut NexthopMap,
    fib: &FibHandle,
) {
    for (p, entries) in table.iter_mut() {
        ipv4_entry_resolve(p, entries, nmap);
        ipv4_entry_selection(p, entries, None, nmap, fib).await;
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
                let _ = self.tx.send(msg);
            }
        }
        // Resolve all RIB.
        let msg = Message::Resolve;
        let _ = self.tx.send(msg);
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
                rib.set_fib(true);
                rib.set_valid(true);
                rib.ifindex = ifindex;
                let msg = Message::Ipv4Add { prefix, rib };
                let _ = self.tx.send(msg);
            }
        }
        // Resolve all RIB.
        let msg = Message::Resolve;
        let _ = self.tx.send(msg);
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

    pub async fn ipv4_route_add(&mut self, prefix: &Ipv4Net, mut rib: RibEntry) {
        println!("IPv4 route add: {} {}", rib.rtype.abbrev(), prefix);
        let mut replace = rib_replace(&mut self.table, prefix, rib.rtype);
        rib_resolve_nexthop(&mut rib, &self.table, &mut self.nmap);
        rib_add(&mut self.table, prefix, rib);
        self.rib_selection(prefix, replace.pop()).await;
    }

    pub async fn ipv4_route_del(&mut self, prefix: &Ipv4Net, rib: RibEntry) {
        println!("IPv4 route del: {} {}", rib.rtype.abbrev(), prefix);
        let mut replace = rib_replace(&mut self.table, prefix, rib.rtype);
        self.rib_selection(prefix, replace.pop()).await;
    }

    pub async fn ipv4_route_resolve(&mut self) {
        println!("ipv4_route_resolve");
        ipv4_nexthop_sync(&mut self.nmap, &self.table);
        ipv4_route_sync(&mut self.table, &mut self.nmap, &self.fib_handle).await;
    }

    pub async fn rib_selection(&mut self, prefix: &Ipv4Net, replace: Option<RibEntry>) {
        let Some(entries) = self.table.get_mut(prefix) else {
            return;
        };
        ipv4_entry_selection(prefix, entries, replace, &mut self.nmap, &self.fib_handle).await;
    }
}

// Function is called when rib is added.
fn rib_resolve_nexthop(
    rib: &mut RibEntry,
    table: &PrefixMap<Ipv4Net, RibEntries>,
    nmap: &mut NexthopMap,
) {
    // Only protocol entry.
    if !rib.is_protocol() {
        return;
    }
    for nhop in rib.nexthops.iter_mut() {
        // Only GroupUni is handled.
        let Some(group) = nmap.fetch_uni(&nhop.addr) else {
            continue;
        };
        // When this is first time allocation, resolve the nexthop group.
        if group.refcnt() == 0 {
            group.resolve(table);
        }
        // Reference counter increment.
        group.refcnt_inc();

        // Set the nexthop group id to the nexthop.
        nhop.gid = group.gid();
    }
    // If one of nexthop is valid, the entry is valid.
    rib.set_valid(rib.is_valid_nexthop(nmap));
}

pub fn rib_add(table: &mut PrefixMap<Ipv4Net, RibEntries>, prefix: &Ipv4Net, entry: RibEntry) {
    let entries = table.entry(*prefix).or_default();
    entries.push(entry);
}

pub fn rib_replace(
    table: &mut PrefixMap<Ipv4Net, RibEntries>,
    prefix: &Ipv4Net,
    rtype: RibType,
) -> Vec<RibEntry> {
    let Some(entries) = table.get_mut(prefix) else {
        return vec![];
    };
    let (remain, replace): (Vec<_>, Vec<_>) = entries.drain(..).partition(|x| x.rtype != rtype);
    *entries = remain;
    replace
}

fn rib_prev(entries: &Vec<RibEntry>) -> Option<usize> {
    entries.iter().position(|e| e.is_selected())
}

fn rib_next(entries: &RibEntries) -> Option<usize> {
    let index = entries
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
        if let Some(nhop) = nhop {
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
                if resolve.is_valid() == 0 {
                    uni.set_valid(false);
                    uni.set_installed(false);
                } else {
                    uni.set_valid(true);
                }
                println!(
                    "resolve: uni id {} is_valid {} is_installed {}",
                    uni.gid(),
                    uni.is_valid(),
                    uni.is_installed()
                );
            }
        }
    }
}
