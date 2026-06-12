//! Next-Hop Tracking (NHT) — recursive nexthop resolution as a RIB
//! service for protocol clients (BGP, static).
//!
//! A client registers interest in a nexthop address (e.g. a BGP route's
//! next-hop `10.0.0.8`); the RIB resolves it against the global table
//! and returns a [`NexthopResolution`] — reachability, IGP metric, and
//! the resolved on-link egress(es) with any accumulated MPLS transport
//! label stack (SR-MPLS prefix-SID labels). The registration persists;
//! the RIB re-resolves and notifies the client whenever the covering
//! route changes (see the `Message::NexthopRegister` handler in
//! `inst.rs`).
//!
//! The resolver is **recursive** (reusing the depth cap that already
//! guards `rib_resolve`), so chained nexthops resolve transparently:
//!
//! ```text
//! 1.1.1.1/32  -> 10.0.0.8       (recurse)
//! 10.0.0.0/24 -> 172.16.0.2     (recurse)
//! 172.16.0.0/24 connected eth0  (on-link -> terminate)
//! => 1.1.1.1/32 via 172.16.0.2 dev eth0
//! ```
//!
//! and **ECMP-aware** at each level (a covering `NexthopMulti` yields
//! every resolvable egress). The result shape — a `Vec` of egresses,
//! each carrying its own label stack — is intentionally future-proof
//! for full recursive-ECMP/weighted composition; today the recursion
//! follows resolvable nexthops and accumulates labels per branch.
//!
//! The common case is **label-less**: a plain iBGP next-hop resolving
//! to an IGP route with no MPLS yields `labels: []` and installs as a
//! bare `via <addr> dev <ifindex>`.

use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::{Ipv4Net, Ipv6Net};
use prefix_trie::PrefixMap;

use super::Nexthop;
use super::RibEntries;
use super::nexthop::NexthopUni;
use super::resolve::entry_resolvable;

/// Cap on recursive resolution depth — also the loop backstop until a
/// per-branch visited-set lands. Matches `resolve.rs`'s default.
const RESOLVE_DEPTH: u8 = 4;

/// One resolved egress for a tracked nexthop. `labels` is the
/// transport label stack to push (empty for plain IP forwarding).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedNexthop {
    pub addr: IpAddr,
    pub ifindex: u32,
    pub labels: Vec<u32>,
}

/// The result of resolving a tracked nexthop against the RIB.
/// `reachable == false` (empty `nexthops`) means best-path / install
/// should treat the route as unusable.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NexthopResolution {
    pub reachable: bool,
    pub metric: u32,
    pub nexthops: Vec<ResolvedNexthop>,
}

/// Resolve an IPv4 nexthop against the global IPv4 table.
pub fn resolve_v4(table: &PrefixMap<Ipv4Net, RibEntries>, target: Ipv4Addr) -> NexthopResolution {
    let mut nexthops = Vec::new();
    let metric = resolve_v4_inner(table, target, RESOLVE_DEPTH, &[], &mut nexthops);
    NexthopResolution {
        reachable: !nexthops.is_empty(),
        metric: metric.unwrap_or(0),
        nexthops,
    }
}

/// Resolve an IPv6 nexthop against the global IPv6 table.
pub fn resolve_v6(table: &PrefixMap<Ipv6Net, RibEntries>, target: Ipv6Addr) -> NexthopResolution {
    let mut nexthops = Vec::new();
    let metric = resolve_v6_inner(table, target, RESOLVE_DEPTH, &[], &mut nexthops);
    NexthopResolution {
        reachable: !nexthops.is_empty(),
        metric: metric.unwrap_or(0),
        nexthops,
    }
}

/// Append the resolved egress(es) for `target` into `out`. Returns the
/// metric of the covering route at this level (the IGP cost to reach
/// the nexthop), or `None` if nothing resolved.
fn resolve_v4_inner(
    table: &PrefixMap<Ipv4Net, RibEntries>,
    target: Ipv4Addr,
    depth: u8,
    accum: &[u32],
    out: &mut Vec<ResolvedNexthop>,
) -> Option<u32> {
    if depth == 0 {
        return None;
    }
    let key = Ipv4Net::new(target, Ipv4Addr::BITS as u8).ok()?;
    let (prefix, entries) = table.get_lpm(&key)?;
    // A default route never resolves a recursive nexthop.
    if prefix.prefix_len() == 0 {
        return None;
    }

    for entry in entries.iter() {
        if !entry_resolvable(entry) {
            continue;
        }
        // Connected: `target` is directly on-link via this entry.
        if entry.is_connected() {
            if entry.ifindex != 0 {
                out.push(ResolvedNexthop {
                    addr: IpAddr::V4(target),
                    ifindex: entry.ifindex,
                    labels: accum.to_vec(),
                });
            }
            return Some(entry.metric);
        }
        // Protocol route: resolve each (ECMP) nexthop, accumulating
        // labels and recursing on not-yet-on-link addresses.
        for uni in entry_unis(&entry.nexthop) {
            let mut labels = accum.to_vec();
            labels.extend_from_slice(&uni.mpls_label);
            match uni.ifindex() {
                Some(ifindex) => out.push(ResolvedNexthop {
                    addr: uni.addr,
                    ifindex,
                    labels,
                }),
                None => {
                    if let IpAddr::V4(next) = uni.addr {
                        resolve_v4_inner(table, next, depth - 1, &labels, out);
                    }
                }
            }
        }
        return Some(entry.metric);
    }
    None
}

fn resolve_v6_inner(
    table: &PrefixMap<Ipv6Net, RibEntries>,
    target: Ipv6Addr,
    depth: u8,
    accum: &[u32],
    out: &mut Vec<ResolvedNexthop>,
) -> Option<u32> {
    if depth == 0 {
        return None;
    }
    let key = Ipv6Net::new(target, Ipv6Addr::BITS as u8).ok()?;
    let (prefix, entries) = table.get_lpm(&key)?;
    if prefix.prefix_len() == 0 {
        return None;
    }

    for entry in entries.iter() {
        if !entry_resolvable(entry) {
            continue;
        }
        if entry.is_connected() {
            if entry.ifindex != 0 {
                out.push(ResolvedNexthop {
                    addr: IpAddr::V6(target),
                    ifindex: entry.ifindex,
                    labels: accum.to_vec(),
                });
            }
            return Some(entry.metric);
        }
        for uni in entry_unis(&entry.nexthop) {
            let mut labels = accum.to_vec();
            labels.extend_from_slice(&uni.mpls_label);
            match uni.ifindex() {
                Some(ifindex) => out.push(ResolvedNexthop {
                    addr: uni.addr,
                    ifindex,
                    labels,
                }),
                None => {
                    if let IpAddr::V6(next) = uni.addr {
                        resolve_v6_inner(table, next, depth - 1, &labels, out);
                    }
                }
            }
        }
        return Some(entry.metric);
    }
    None
}

/// Flatten a `Nexthop` into its unicast members (ECMP-aware).
fn entry_unis(nexthop: &Nexthop) -> Vec<&NexthopUni> {
    match nexthop {
        Nexthop::Uni(u) => vec![u],
        Nexthop::Multi(m) => m.nexthops.iter().collect(),
        Nexthop::List(l) => l.iter_unis().collect(),
        Nexthop::Protect(p) => p.iter_unis().collect(),
        _ => Vec::new(),
    }
}

/// Per-nexthop registration state: the cached resolution plus the set
/// of client protocol names watching it. The registry lives on `Rib`;
/// the message handlers in `inst.rs` drive resolve + notify.
#[derive(Debug, Default)]
pub struct NhtEntry {
    pub resolution: NexthopResolution,
    pub watchers: BTreeSet<String>,
}

/// Registry of tracked nexthops, keyed by address. One entry per
/// distinct nexthop regardless of how many clients/routes depend on
/// it; an entry is dropped when its last watcher unregisters.
#[derive(Debug, Default)]
pub struct NhtRegistry {
    pub entries: HashMap<IpAddr, NhtEntry>,
}

impl NhtRegistry {
    /// Add `client` as a watcher of `nh`. Returns `true` when this is
    /// the first registration for `nh` (the caller should resolve it).
    pub fn register(&mut self, client: String, nh: IpAddr) -> bool {
        let entry = self.entries.entry(nh).or_default();
        let fresh = entry.watchers.is_empty();
        entry.watchers.insert(client);
        fresh
    }

    /// Remove `client` from `nh`'s watchers. Returns `true` when the
    /// entry has no watchers left and was dropped.
    pub fn unregister(&mut self, client: &str, nh: IpAddr) -> bool {
        if let Some(entry) = self.entries.get_mut(&nh) {
            entry.watchers.remove(client);
            if entry.watchers.is_empty() {
                self.entries.remove(&nh);
                return true;
            }
        }
        false
    }

    /// Tracked nexthop addresses (for re-resolution on a RIB change).
    pub fn tracked(&self) -> Vec<IpAddr> {
        self.entries.keys().copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rib::entry::RibEntry;
    use crate::rib::nexthop::{Label, NexthopUni};
    use crate::rib::{Nexthop, RibType};

    fn connected(ifindex: u32) -> RibEntry {
        let mut e = RibEntry::new(RibType::Connected);
        e.ifindex = ifindex;
        e.valid = true;
        e
    }

    fn static_via(addr: Ipv4Addr, labels: Vec<u32>) -> RibEntry {
        let mut e = RibEntry::new(RibType::Static);
        e.valid = true;
        e.metric = 5;
        let mpls: Vec<Label> = labels.into_iter().map(Label::Explicit).collect();
        e.nexthop = Nexthop::Uni(NexthopUni::new(IpAddr::V4(addr), 0, mpls));
        e
    }

    fn table(rows: Vec<(&str, RibEntry)>) -> PrefixMap<Ipv4Net, RibEntries> {
        let mut t: PrefixMap<Ipv4Net, RibEntries> = PrefixMap::new();
        for (p, e) in rows {
            t.insert(p.parse().unwrap(), vec![e]);
        }
        t
    }

    #[test]
    fn connected_nexthop_resolves_onlink_no_label() {
        // 172.16.0.2 is directly on-link in 172.16.0.0/24 dev 7.
        let t = table(vec![("172.16.0.0/24", connected(7))]);
        let r = resolve_v4(&t, "172.16.0.2".parse().unwrap());
        assert!(r.reachable);
        assert_eq!(r.nexthops.len(), 1);
        assert_eq!(r.nexthops[0].addr, "172.16.0.2".parse::<IpAddr>().unwrap());
        assert_eq!(r.nexthops[0].ifindex, 7);
        assert!(r.nexthops[0].labels.is_empty());
    }

    #[test]
    fn recursive_static_chain_resolves_to_bottom_onlink() {
        // 1.1.1.1/32 -> 10.0.0.8 -> 172.16.0.2 (connected eth7).
        let t = table(vec![
            (
                "1.1.1.1/32",
                static_via("10.0.0.8".parse().unwrap(), vec![]),
            ),
            (
                "10.0.0.0/24",
                static_via("172.16.0.2".parse().unwrap(), vec![]),
            ),
            ("172.16.0.0/24", connected(7)),
        ]);
        let r = resolve_v4(&t, "1.1.1.1".parse().unwrap());
        assert!(r.reachable);
        assert_eq!(r.nexthops.len(), 1);
        assert_eq!(r.nexthops[0].addr, "172.16.0.2".parse::<IpAddr>().unwrap());
        assert_eq!(r.nexthops[0].ifindex, 7);
    }

    #[test]
    fn label_accumulates_along_recursion() {
        // SR-MPLS-ish: the static toward 10.0.0.8 pushes label 16800.
        let t = table(vec![
            (
                "1.1.1.1/32",
                static_via("10.0.0.8".parse().unwrap(), vec![16800]),
            ),
            (
                "10.0.0.0/24",
                static_via("172.16.0.2".parse().unwrap(), vec![]),
            ),
            ("172.16.0.0/24", connected(7)),
        ]);
        let r = resolve_v4(&t, "1.1.1.1".parse().unwrap());
        assert_eq!(r.nexthops[0].labels, vec![16800]);
    }

    #[test]
    fn unresolvable_nexthop_is_unreachable() {
        let t = table(vec![("172.16.0.0/24", connected(7))]);
        let r = resolve_v4(&t, "9.9.9.9".parse().unwrap());
        assert!(!r.reachable);
        assert!(r.nexthops.is_empty());
    }

    #[test]
    fn registry_dedup_and_refcount() {
        let mut reg = NhtRegistry::default();
        let nh: IpAddr = "10.0.0.8".parse().unwrap();
        assert!(reg.register("bgp".into(), nh)); // first → fresh
        assert!(!reg.register("static".into(), nh)); // second watcher → not fresh
        assert!(!reg.unregister("bgp", nh)); // still has "static"
        assert!(reg.unregister("static", nh)); // last watcher → dropped
        assert!(reg.entries.is_empty());
    }
}
