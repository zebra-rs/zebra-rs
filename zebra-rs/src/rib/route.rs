use ipnet::{IpNet, Ipv4Net};
use prefix_trie::PrefixMap;
use std::collections::{BTreeMap, BTreeSet};

use crate::fib::FibHandle;
use crate::rib::resolve::{rib_resolve, ResolveOpt};
use crate::rib::util::IpNetExt;
use crate::rib::Nexthop;

use super::entry::RibEntry;
use super::inst::{IlmEntry, Rib};
use super::nexthop::NexthopUni;
use super::{
    Group, GroupTrait, Message, NexthopList, NexthopMap, NexthopMulti, RibEntries, RibType,
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
        // Remove DHCP and Kernel routes.
        for (prefix, rib) in self.table.iter() {
            for entry in rib.iter() {
                if entry.rtype == RibType::Dhcp || entry.rtype == RibType::Kernel {
                    match &entry.nexthop {
                        Nexthop::Link(_) => {
                            //
                        }
                        Nexthop::Uni(uni) => {
                            if uni.ifindex == ifindex {
                                let msg = Message::Ipv4Del {
                                    prefix: *prefix,
                                    rib: entry.clone(),
                                };
                                self.tx.send(msg).unwrap();
                            }
                        }
                        Nexthop::List(_list) => {
                            //
                        }
                        Nexthop::Multi(_multi) => {
                            //
                        }
                    }
                }
            }
        }

        // Resolve RIB.
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
        if entry.is_protocol() {
            let mut replace = rib_replace(&mut self.table, prefix, entry.rtype);
            self.rib_selection(prefix, replace.pop()).await;
        } else {
            println!("System route remove");
            let mut replace = rib_replace_system(&mut self.table, prefix, entry);
            self.rib_selection(prefix, replace.pop()).await;
        }
    }

    pub async fn ilm_add(&mut self, label: u32, ilm: IlmEntry) {
        // Need to update ilm table.
        self.ilm.insert(label, ilm.clone());

        self.fib_handle.ilm_del(label, &ilm).await;
        self.fib_handle.ilm_add(label, &ilm).await;
    }

    pub async fn ilm_del(&mut self, label: u32, ilm: IlmEntry) {
        self.ilm.remove(&label);

        self.fib_handle.ilm_del(label, &ilm).await;
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
        if replace.is_protocol() {
            if replace.is_fib() {
                fib.route_ipv4_del(prefix, &replace).await;
            }
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

fn nexthop_uni_resolve(nhop: &mut NexthopUni, nmap: &NexthopMap) {
    if let Some(grp) = nmap.get_uni(nhop.gid) {
        nhop.valid = grp.is_valid();
        nhop.ifindex = grp.ifindex;
    }
}

fn entry_resolve(entry: &mut RibEntry, nmap: &NexthopMap) {
    match &mut entry.nexthop {
        Nexthop::Link(iflink) => {
            tracing::info!("Nexthop::Link({}): this won't happen", iflink);
        }
        Nexthop::Uni(uni) => {
            nexthop_uni_resolve(uni, nmap);
        }
        Nexthop::Multi(multi) => {
            for uni in multi.nexthops.iter_mut() {
                nexthop_uni_resolve(uni, nmap);
            }
        }
        Nexthop::List(list) => {
            for uni in list.nexthops.iter_mut() {
                nexthop_uni_resolve(uni, nmap);
            }
        }
    }
}

fn entry_update(entry: &mut RibEntry) {
    match &entry.nexthop {
        Nexthop::Link(iflink) => {
            tracing::info!("Nexthop::Link({}): this won't happen", iflink);
        }
        Nexthop::Uni(uni) => {
            entry.valid = uni.valid;
            entry.metric = uni.metric;
        }
        Nexthop::Multi(multi) => {
            for _uni in multi.nexthops.iter() {
                //
            }
        }
        Nexthop::List(list) => {
            for uni in list.nexthops.iter() {
                if uni.valid {
                    entry.metric = uni.metric;
                    entry.valid = uni.valid;
                    return;
                }
            }
            entry.metric = 0;
            entry.valid = false;
        }
    }
}

fn ipv4_entry_resolve(entries: &mut RibEntries, nmap: &NexthopMap) {
    for entry in entries.iter_mut() {
        if entry.is_protocol() {
            entry_resolve(entry, nmap);
            entry_update(entry);
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
    let Some(Group::Uni(group)) = nmap.fetch(&uni) else {
        return false;
    };
    if group.refcnt() == 0 {
        group.resolve(table);
    }
    group.refcnt_inc();

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
    if let Nexthop::List(pro) = &mut entry.nexthop {
        let mut _pro_valid = false;
        for uni in pro.nexthops.iter_mut() {
            let valid = resolve_nexthop_uni(uni, nmap, table);
            if valid {
                _pro_valid = true;
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
                        let mut pro = NexthopList::default();
                        pro.nexthops.push(uni.clone());
                        pro.nexthops.push(euni);
                        pro.nexthops.sort_by(|a, b| a.metric.cmp(&b.metric));
                        e.metric = pro.metric();
                        Nexthop::List(pro)
                    }
                }
                Nexthop::List(list) => {
                    // Current One.
                    let mut btree = BTreeMap::new();

                    for l in list.nexthops.iter() {
                        println!("");
                        btree.insert(l.metric, l.clone());
                    }

                    let Nexthop::Uni(uni) = entry.nexthop else {
                        return;
                    };

                    btree.insert(uni.metric, uni);

                    let vec: Vec<_> = btree.iter().map(|(_, &ref value)| value.clone()).collect();
                    let list = NexthopList { nexthops: vec };

                    Nexthop::List(list)
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
    // println!("rib_replace_system {}", prefix);
    let entries = table.entry(*prefix).or_default();
    let index = rib_rtype(entries, entry.rtype);
    let Some(index) = index else {
        return vec![];
    };
    // println!("index {}", index);
    let e = entries.get_mut(index).unwrap();
    let replace = match &mut e.nexthop {
        Nexthop::Uni(uni) => uni.metric == entry.metric,
        Nexthop::Multi(multi) => multi.metric == entry.metric,
        Nexthop::List(list) => {
            list.nexthops.retain(|x| x.metric != entry.metric);
            if list.nexthops.len() == 1 {
                let uni = list.nexthops.pop().unwrap();
                e.metric = uni.metric;
                e.nexthop = Nexthop::Uni(uni);
            }
            false
        }
        Nexthop::Link(_ifindex) => true,
    };
    // println!("replace {}", replace);
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
            // println!("before: {:?}", uni);
            // Resolve the next hop
            let resolve = rib_resolve(table, uni.addr, &ResolveOpt::default());

            // Update the status of the next hop
            let ifindex = resolve.is_valid();
            if ifindex == 0 {
                uni.set_valid(false);
                uni.set_installed(false);
                uni.set_ifindex(0);
            } else {
                uni.set_ifindex(ifindex);
                uni.set_valid(true);
                if !uni.is_installed() {
                    uni.set_installed(true);
                    fib.nexthop_add(&Group::Uni(uni.clone())).await;
                }
            }
            // println!("after: {:?}", uni);
        }
    }
}
