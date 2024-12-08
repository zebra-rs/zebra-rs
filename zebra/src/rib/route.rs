use ipnet::{IpNet, Ipv4Net};
use prefix_trie::PrefixMap;
use std::collections::BTreeSet;

use crate::fib::FibHandle;
use crate::rib::resolve::{rib_resolve, ResolveOpt};
use crate::rib::util::IpNetExt;
use crate::rib::Nexthop;

use super::entry::RibEntry;
use super::inst::Rib;
use super::nexthop::NexthopUni;
use super::{
    Group, GroupTrait, Message, NexthopMap, NexthopMulti, NexthopProtect, RibEntries, RibType,
};

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
    }

    pub async fn ipv4_route_add(&mut self, prefix: &Ipv4Net, mut entry: RibEntry) {
        // println!("IPv4 route add: {} {}", entry.rtype.abbrev(), prefix);
        let is_connected = entry.is_connected();
        if entry.is_protocol() {
            let mut replace = rib_replace(&mut self.table, prefix, entry.rtype);
            rib_resolve_nexthop(&mut entry, &self.table, &mut self.nmap);
            rib_add(&mut self.table, prefix, entry);
            self.rib_selection(prefix, replace.pop()).await;
        } else {
            rib_add_system(&mut self.table, prefix, entry);
            self.rib_selection(prefix, None).await;
        }

        if is_connected {
            let msg = Message::Resolve;
            let _ = self.tx.send(msg);
        }
    }

    pub async fn ipv4_route_del(&mut self, prefix: &Ipv4Net, entry: RibEntry) {
        // println!("IPv4 route del: {} {}", entry.rtype.abbrev(), prefix);
        if entry.is_protocol() {
            let mut replace = rib_replace(&mut self.table, prefix, entry.rtype);
            self.rib_selection(prefix, replace.pop()).await;
        } else {
            let mut replace = rib_replace_system(&mut self.table, prefix, entry);
            self.rib_selection(prefix, replace.pop()).await;
        }
    }

    pub async fn ipv4_route_resolve(&mut self) {
        ipv4_nexthop_sync(&mut self.nmap, &self.table, &self.fib_handle).await;
        ipv4_route_sync(&mut self.table, &mut self.nmap, &self.fib_handle).await;
    }

    pub async fn rib_selection(&mut self, prefix: &Ipv4Net, replace: Option<RibEntry>) {
        let Some(entries) = self.table.get_mut(prefix) else {
            return;
        };
        ipv4_entry_selection(prefix, entries, replace, &mut self.nmap, &self.fib_handle).await;
    }
}

async fn ipv4_entry_selection(
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
    let prev = rib_prev(entries);

    // New select.
    let next = rib_next(entries);

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
            fib.route_ipv4_add(prefix, next).await;
        }
        next.set_fib(true);
    }
}

// Resolve RibEntries.  gid is already resolved.
fn ipv4_entry_resolve(entries: &mut RibEntries, nmap: &NexthopMap) {
    for entry in entries.iter_mut() {
        if entry.is_protocol() {
            let valid = entry.is_valid_nexthop(nmap);
            entry.set_valid(valid);
        }
    }
}

async fn ipv4_route_sync(
    table: &mut PrefixMap<Ipv4Net, RibEntries>,
    nmap: &mut NexthopMap,
    fib: &FibHandle,
) {
    for (p, entries) in table.iter_mut() {
        ipv4_entry_resolve(entries, nmap);
        ipv4_entry_selection(p, entries, None, nmap, fib).await;
    }
}

fn resolve_nexthop_uni(
    uni: &mut NexthopUni,
    nmap: &mut NexthopMap,
    table: &PrefixMap<Ipv4Net, RibEntries>,
) -> bool {
    // Only GroupUni is handled.
    let Some(Group::Uni(group)) = nmap.fetch_uni(&uni.addr) else {
        return false;
    };
    // When this is first time allocation, resolve the nexthop group.
    if group.refcnt() == 0 {
        group.resolve(table);
    }
    // Reference counter increment.
    group.refcnt_inc();

    // Set the nexthop group id to the nexthop.
    uni.gid = group.gid();
    uni.ifindex = group.ifindex;

    group.is_valid()
}

fn resolve_nexthop_multi(multi: &mut NexthopMulti, nmap: &mut NexthopMap, multi_valid: bool) {
    // Create set with gid:u32 and weight:u8.
    let mut set: BTreeSet<(usize, u8)> = BTreeSet::new();

    for nhop in multi.nexthops.iter() {
        set.insert((nhop.gid, nhop.weight));
    }

    let Some(Group::Multi(group)) = nmap.fetch_multi(&set) else {
        return;
    };

    group.set_valid(multi_valid);

    // Reference counter increment.
    group.refcnt_inc();

    // Set the nexthop group id to the nexthop.
    multi.gid = group.gid();
}

// Function is called when rib is added.
fn rib_resolve_nexthop(
    entry: &mut RibEntry,
    table: &PrefixMap<Ipv4Net, RibEntries>,
    nmap: &mut NexthopMap,
) {
    // Only protocol entry.
    if !entry.is_protocol() {
        return;
    }
    if let Nexthop::Uni(uni) = &mut entry.nexthop {
        let _ = resolve_nexthop_uni(uni, nmap, table);
    }
    if let Nexthop::Multi(multi) = &mut entry.nexthop {
        let mut multi_valid = false;
        for uni in multi.nexthops.iter_mut() {
            let valid = resolve_nexthop_uni(uni, nmap, table);
            if valid {
                multi_valid = true;
            }
        }
        resolve_nexthop_multi(multi, nmap, multi_valid);
    }
    if let Nexthop::Protect(pro) = &mut entry.nexthop {
        let mut pro_valid = false;
        for uni in pro.nexthops.iter_mut() {
            let valid = resolve_nexthop_uni(uni, nmap, table);
            if valid {
                pro_valid = true;
            }
        }
    }
    // If one of nexthop is valid, the entry is valid.
    entry.set_valid(entry.is_valid_nexthop(nmap));
}

fn rib_rtype(entries: &[RibEntry], rtype: RibType) -> Option<usize> {
    entries.iter().position(|e| e.rtype == rtype)
}

fn rib_add(table: &mut PrefixMap<Ipv4Net, RibEntries>, prefix: &Ipv4Net, entry: RibEntry) {
    let entries = table.entry(*prefix).or_default();
    entries.push(entry);
}

fn rib_add_system(table: &mut PrefixMap<Ipv4Net, RibEntries>, prefix: &Ipv4Net, entry: RibEntry) {
    let entries = table.entry(*prefix).or_default();
    let index = rib_rtype(entries, entry.rtype);
    match index {
        None => {
            entries.push(entry);
        }
        Some(index) => {
            let e = entries.get_mut(index).unwrap();
            let nhop = match &mut e.nexthop {
                Nexthop::Uni(uni) => {
                    let Nexthop::Uni(euni) = entry.nexthop else {
                        return;
                    };
                    if uni.metric == euni.metric {
                        Nexthop::Uni(euni)
                    } else {
                        let mut pro = NexthopProtect::default();
                        pro.nexthops.push(uni.clone());
                        pro.nexthops.push(euni);
                        pro.nexthops.sort_by(|a, b| a.metric.cmp(&b.metric));
                        e.metric = pro.metric();
                        Nexthop::Protect(pro)
                    }
                }
                Nexthop::Protect(pro) => {
                    let Nexthop::Uni(euni) = entry.nexthop else {
                        return;
                    };
                    pro.nexthops.push(euni);
                    pro.nexthops.sort_by(|a, b| a.metric.cmp(&b.metric));
                    e.metric = pro.metric();
                    Nexthop::Protect(pro.clone())
                }
                _ => {
                    return;
                }
            };
            e.nexthop = nhop;
        }
    }
}

fn rib_replace_system(
    table: &mut PrefixMap<Ipv4Net, RibEntries>,
    prefix: &Ipv4Net,
    entry: RibEntry,
) -> Vec<RibEntry> {
    let entries = table.entry(*prefix).or_default();
    let index = rib_rtype(entries, entry.rtype);
    let Some(index) = index else {
        return vec![];
    };
    let e = entries.get_mut(index).unwrap();
    let replace = match &mut e.nexthop {
        Nexthop::Uni(uni) => uni.metric == entry.metric,
        Nexthop::Multi(multi) => multi.metric == entry.metric,
        Nexthop::Protect(pro) => {
            pro.nexthops.retain(|x| x.metric != entry.metric);
            if pro.nexthops.len() == 1 {
                let uni = pro.nexthops.pop().unwrap();
                e.metric = uni.metric;
                e.nexthop = Nexthop::Uni(uni);
            }
            false
        }
        _ => false,
    };
    if replace {
        return rib_replace(table, prefix, entry.rtype);
    }
    vec![]
}

fn rib_replace(
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

fn rib_prev(entries: &[RibEntry]) -> Option<usize> {
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
                Some((_, aentry)) if aentry < entry => acc,
                _ => Some((index, entry)),
            },
        )
        .map(|(index, _)| index);

    index
}

async fn ipv4_nexthop_sync(
    nmap: &mut NexthopMap,
    table: &PrefixMap<Ipv4Net, RibEntries>,
    fib: &FibHandle,
) {
    for nhop in nmap.groups.iter_mut().flatten() {
        if let Group::Uni(uni) = nhop {
            // Resolve the next hop
            let resolve = rib_resolve(table, uni.addr, &ResolveOpt::default());

            // Update the status of the next hop
            let ifindex = resolve.is_valid();
            if ifindex == 0 {
                uni.set_valid(false);
                uni.set_installed(false);
            } else {
                uni.set_ifindex(ifindex);
                uni.set_valid(true);
                if !uni.is_installed() {
                    uni.set_installed(true);
                    fib.nexthop_add(&Group::Uni(uni.clone())).await;
                }
            }
        }
    }
}
