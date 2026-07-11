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
use isis_packet::srv6::EncapType;
use prefix_trie::PrefixMap;

use super::Nexthop;
use super::RibEntries;
use super::nexthop::{Label, NexthopUni};
use super::resolve::entry_resolvable;
use super::types::RibType;

/// Cap on recursive resolution depth — also the loop backstop until a
/// per-branch visited-set lands. Matches `resolve.rs`'s default.
const RESOLVE_DEPTH: u8 = 4;

/// One resolved egress for a tracked nexthop. `labels` is the MPLS
/// transport label stack to push and `segs` the SRv6 H.Encap segment
/// list to encapsulate with (both empty for plain IP forwarding; never
/// both non-empty — a mixed-transport chain does not resolve).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedNexthop {
    pub addr: IpAddr,
    pub ifindex: u32,
    pub labels: Vec<u32>,
    /// SRv6 segment list inherited from the covering route(s), in SRH
    /// visit order (`segs[0]` is the outer destination).
    pub segs: Vec<Ipv6Addr>,
    /// Encap flavor for `segs` (H.Encap / H.Encap.Red). None when
    /// `segs` is empty.
    pub seg_encap: Option<EncapType>,
}

/// Transport state gathered from the covering routes above the current
/// recursion level: the MPLS label stack and/or SRv6 segment list a
/// packet must carry once the on-link egress is found.
#[derive(Clone, Default)]
struct Transport {
    labels: Vec<u32>,
    segs: Vec<Ipv6Addr>,
    seg_encap: Option<EncapType>,
}

impl Transport {
    /// Fold one covering route's nexthop into the accumulated
    /// transport before descending (or emitting).
    ///
    /// MPLS labels append (the historical order; in practice only one
    /// recursion level carries labels). SRv6 segments *prepend*: this
    /// level's segments are the transport used to reach everything
    /// accumulated so far, and SRH visit order is `segs[0]` outward —
    /// so the deeper level's segments must come first. The encap
    /// flavor keeps the shallowest (service-route) choice when levels
    /// disagree.
    fn fold(&self, uni: &NexthopUni) -> Transport {
        let mut next = self.clone();
        next.labels.extend_from_slice(&uni_transport_labels(uni));
        if !uni.segs.is_empty() {
            let mut segs = uni.segs.clone();
            segs.extend_from_slice(&next.segs);
            next.segs = segs;
            next.seg_encap = self.seg_encap.or(uni.encap_type);
        }
        next
    }

    /// A kernel nexthop carries at most one lwtunnel encap, so a chain
    /// that accumulates both MPLS labels and SRv6 segments cannot be
    /// installed — refuse the egress instead of programming garbage.
    fn mixed(&self) -> bool {
        !self.labels.is_empty() && !self.segs.is_empty()
    }

    fn egress(&self, addr: IpAddr, ifindex: u32) -> Option<ResolvedNexthop> {
        if self.mixed() {
            return None;
        }
        Some(ResolvedNexthop {
            addr,
            ifindex,
            labels: self.labels.clone(),
            segs: self.segs.clone(),
            seg_encap: if self.segs.is_empty() {
                None
            } else {
                self.seg_encap
            },
        })
    }
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
    let metric = resolve_v4_inner(
        table,
        target,
        RESOLVE_DEPTH,
        &Transport::default(),
        &mut nexthops,
    );
    NexthopResolution {
        reachable: !nexthops.is_empty(),
        metric: metric.unwrap_or(0),
        nexthops,
    }
}

/// Resolve an IPv6 nexthop against the global IPv6 table.
pub fn resolve_v6(table: &PrefixMap<Ipv6Net, RibEntries>, target: Ipv6Addr) -> NexthopResolution {
    let mut nexthops = Vec::new();
    let metric = resolve_v6_inner(
        table,
        target,
        RESOLVE_DEPTH,
        &Transport::default(),
        &mut nexthops,
    );
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
    accum: &Transport,
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

    let entry = nht_best_entry(entries)?;
    // Connected: `target` is directly on-link via this entry.
    if entry.is_connected() {
        if entry.ifindex != 0 {
            out.extend(accum.egress(IpAddr::V4(target), entry.ifindex));
        }
        return Some(entry.metric);
    }
    // Protocol route: resolve each (ECMP) nexthop, accumulating
    // transport (MPLS labels / SRv6 segments) and recursing on
    // not-yet-on-link addresses.
    for uni in entry_unis(&entry.nexthop) {
        let transport = accum.fold(uni);
        match uni.ifindex() {
            Some(ifindex) => out.extend(transport.egress(uni.addr, ifindex)),
            None => {
                if let IpAddr::V4(next) = uni.addr {
                    resolve_v4_inner(table, next, depth - 1, &transport, out);
                }
            }
        }
    }
    Some(entry.metric)
}

fn resolve_v6_inner(
    table: &PrefixMap<Ipv6Net, RibEntries>,
    target: Ipv6Addr,
    depth: u8,
    accum: &Transport,
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

    let entry = nht_best_entry(entries)?;
    if entry.is_connected() {
        if entry.ifindex != 0 {
            out.extend(accum.egress(IpAddr::V6(target), entry.ifindex));
        }
        return Some(entry.metric);
    }
    for uni in entry_unis(&entry.nexthop) {
        let transport = accum.fold(uni);
        match uni.ifindex() {
            Some(ifindex) => out.extend(transport.egress(uni.addr, ifindex)),
            None => {
                if let IpAddr::V6(next) = uni.addr {
                    resolve_v6_inner(table, next, depth - 1, &transport, out);
                }
            }
        }
    }
    Some(entry.metric)
}

/// Pick the covering route NHT should recurse through. Kernel/DHCP
/// shadows of zebra-installed routes are skipped — they carry no MPLS
/// metadata and would otherwise hide the protocol path's label stack.
fn nht_best_entry(entries: &RibEntries) -> Option<&crate::rib::entry::RibEntry> {
    entries
        .iter()
        .filter(|e| {
            e.is_valid()
                && e.rtype != RibType::Kernel
                && e.rtype != RibType::Dhcp
                && entry_resolvable(e)
        })
        .min_by(|a, b| {
            a.distance
                .cmp(&b.distance)
                .then(a.metric.cmp(&b.metric))
                .then(a.rtype.u8().cmp(&b.rtype.u8()))
        })
}

/// MPLS labels to push for recursive resolution. Prefer the explicit
/// install stack (`mpls_label`); fall back to `mpls` when only the
/// protocol label vector was populated (implicit-null entries are
/// omitted — PHP does not push).
fn uni_transport_labels(uni: &NexthopUni) -> Vec<u32> {
    if !uni.mpls_label.is_empty() {
        return uni.mpls_label.clone();
    }
    uni.mpls
        .iter()
        .filter_map(|label| match label {
            Label::Explicit(label) => Some(*label),
            Label::Implicit(_) => None,
        })
        .collect()
}

/// Flatten a `Nexthop` into its unicast members (ECMP-aware). A
/// `Protect` yields only its primary member — that slot always holds
/// the active path (a `backup-as-primary` promotion swaps the repair
/// into it), and resolving through the standby too would hand
/// dependents a bogus ECMP over primary + repair.
fn entry_unis(nexthop: &Nexthop) -> Vec<&NexthopUni> {
    match nexthop {
        Nexthop::Uni(u) => vec![u],
        Nexthop::Multi(m) => m.nexthops.iter().collect(),
        Nexthop::List(l) => l.iter_unis().collect(),
        Nexthop::Protect(p) => p.primary.iter_unis().collect(),
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

    fn isis_mpls_via(addr: Ipv4Addr, label: u32, ifindex: u32) -> RibEntry {
        let mut e = RibEntry::new(RibType::Isis);
        e.valid = true;
        e.distance = 115;
        e.metric = 13;
        let mut uni = NexthopUni::new(IpAddr::V4(addr), 13, vec![Label::Explicit(label)]);
        uni.ifindex_origin = Some(ifindex);
        e.nexthop = Nexthop::Uni(uni);
        e
    }

    fn kernel_shadow(addr: Ipv4Addr, ifindex: u32) -> RibEntry {
        let mut e = RibEntry::new(RibType::Kernel);
        e.valid = true;
        e.distance = 0;
        e.metric = 13;
        let mut uni = NexthopUni::new(IpAddr::V4(addr), 13, vec![]);
        uni.ifindex_origin = Some(ifindex);
        e.nexthop = Nexthop::Uni(uni);
        e
    }

    fn table_rows(rows: Vec<(&str, RibEntry)>) -> PrefixMap<Ipv4Net, RibEntries> {
        let mut t: PrefixMap<Ipv4Net, RibEntries> = PrefixMap::new();
        for (p, e) in rows {
            t.insert(p.parse().unwrap(), vec![e]);
        }
        t
    }

    fn table_multi(rows: Vec<(&str, Vec<RibEntry>)>) -> PrefixMap<Ipv4Net, RibEntries> {
        let mut t: PrefixMap<Ipv4Net, RibEntries> = PrefixMap::new();
        for (p, es) in rows {
            t.insert(p.parse().unwrap(), es);
        }
        t
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
    fn kernel_shadow_does_not_hide_isis_mpls_transport() {
        let t = table_multi(vec![(
            "10.0.0.3/32",
            vec![
                kernel_shadow("192.168.2.1".parse().unwrap(), 11),
                isis_mpls_via("192.168.2.1".parse().unwrap(), 16600, 11),
            ],
        )]);
        let r = resolve_v4(&t, "10.0.0.3".parse().unwrap());
        assert!(r.reachable);
        assert_eq!(r.nexthops.len(), 1);
        assert_eq!(r.nexthops[0].labels, vec![16600]);
    }

    #[test]
    fn transport_labels_fall_back_to_mpls_vector() {
        let mut e = RibEntry::new(RibType::Isis);
        e.valid = true;
        e.distance = 115;
        let uni = NexthopUni {
            addr: "192.168.2.1".parse::<IpAddr>().unwrap(),
            mpls: vec![Label::Explicit(16500)],
            ifindex_origin: Some(11),
            valid: true,
            ..Default::default()
        };
        e.nexthop = Nexthop::Uni(uni);
        let t = table_rows(vec![("10.0.0.2/32", e)]);
        let r = resolve_v4(&t, "10.0.0.2".parse().unwrap());
        assert_eq!(r.nexthops[0].labels, vec![16500]);
    }

    #[test]
    fn protect_resolution_follows_promoted_primary() {
        use crate::rib::nexthop::{NexthopMember, NexthopProtect};

        fn uni(addr: &str, metric: u32, labels: Vec<u32>, ifindex: u32) -> NexthopUni {
            let mut u = NexthopUni::new(
                addr.parse::<IpAddr>().unwrap(),
                metric,
                labels.into_iter().map(Label::Explicit).collect(),
            );
            u.ifindex_origin = Some(ifindex);
            u
        }
        fn protect(primary: NexthopUni, backup: NexthopUni) -> RibEntry {
            let mut e = RibEntry::new(RibType::Isis);
            e.valid = true;
            e.distance = 115;
            e.metric = 12;
            e.nexthop = Nexthop::Protect(NexthopProtect {
                primary: NexthopMember::Uni(primary),
                backup: NexthopMember::Uni(backup),
                gid: 0,
            });
            e
        }
        let spf = || uni("192.168.10.2", 12, vec![16800], 2);
        let repair = || uni("192.168.3.2", 13, vec![16500, 15003, 15002], 3);

        // Normal orientation: only the SPF primary resolves — the
        // standby repair must not surface as a second ECMP egress.
        let t = table_rows(vec![("10.0.0.8/32", protect(spf(), repair()))]);
        let before = resolve_v4(&t, "10.0.0.8".parse().unwrap());
        assert!(before.reachable);
        assert_eq!(before.nexthops.len(), 1);
        assert_eq!(
            before.nexthops[0].addr,
            "192.168.10.2".parse::<IpAddr>().unwrap()
        );
        assert_eq!(before.nexthops[0].labels, vec![16800]);

        // A backup-as-primary promotion swaps the members: the
        // resolution must follow the promoted repair — and differ
        // from the pre-promotion result so registered watchers are
        // notified of the transport change.
        let t = table_rows(vec![("10.0.0.8/32", protect(repair(), spf()))]);
        let after = resolve_v4(&t, "10.0.0.8".parse().unwrap());
        assert!(after.reachable);
        assert_eq!(after.nexthops.len(), 1);
        assert_eq!(
            after.nexthops[0].addr,
            "192.168.3.2".parse::<IpAddr>().unwrap()
        );
        assert_eq!(after.nexthops[0].labels, vec![16500, 15003, 15002]);
        assert_ne!(before, after);
    }

    fn table6(rows: Vec<(&str, RibEntry)>) -> PrefixMap<Ipv6Net, RibEntries> {
        let mut t: PrefixMap<Ipv6Net, RibEntries> = PrefixMap::new();
        for (p, e) in rows {
            t.insert(p.parse().unwrap(), vec![e]);
        }
        t
    }

    // A BGP-over-SRv6 service route: the nexthop is the remote SID with
    // an H.Encap segment list (the shape `encapsulation-type srv6`
    // installs). `ifindex` None models a not-yet-flattened nexthop that
    // needs another recursion level.
    fn bgp_srv6_via(sid: &str, ifindex: Option<u32>) -> RibEntry {
        let mut e = RibEntry::new(RibType::Bgp);
        e.valid = true;
        e.distance = 200;
        let uni = NexthopUni {
            addr: sid.parse::<IpAddr>().unwrap(),
            segs: vec![sid.parse().unwrap()],
            encap_type: Some(EncapType::HEncap),
            ifindex_origin: ifindex,
            valid: true,
            ..Default::default()
        };
        e.nexthop = Nexthop::Uni(uni);
        e
    }

    fn static6_via(addr: &str, ifindex: Option<u32>) -> RibEntry {
        let mut e = RibEntry::new(RibType::Static);
        e.valid = true;
        e.metric = 5;
        let mut uni = NexthopUni::new(addr.parse::<IpAddr>().unwrap(), 0, vec![]);
        uni.ifindex_origin = ifindex;
        e.nexthop = Nexthop::Uni(uni);
        e
    }

    #[test]
    fn srv6_segs_inherited_from_covering_route() {
        // Gateway 2001:db8:200::1 is covered by a BGP-over-SRv6 route
        // whose nexthop carries an H.Encap segment list — the resolved
        // egress must inherit it.
        let sid = "fcbb:bbbb:3:40::";
        let t = table6(vec![("2001:db8:200::/64", bgp_srv6_via(sid, Some(2)))]);
        let r = resolve_v6(&t, "2001:db8:200::1".parse().unwrap());
        assert!(r.reachable);
        assert_eq!(r.nexthops.len(), 1);
        assert_eq!(r.nexthops[0].addr, sid.parse::<IpAddr>().unwrap());
        assert_eq!(r.nexthops[0].ifindex, 2);
        assert_eq!(r.nexthops[0].segs, vec![sid.parse::<Ipv6Addr>().unwrap()]);
        assert_eq!(r.nexthops[0].seg_encap, Some(EncapType::HEncap));
        assert!(r.nexthops[0].labels.is_empty());
    }

    #[test]
    fn srv6_segs_survive_deeper_recursion() {
        // The SRv6 route's SID nexthop is itself not flattened: the SID
        // resolves through a plain route to the locator prefix. The
        // final egress is the locator route's gateway, still carrying
        // the inherited segment list.
        let sid = "fcbb:bbbb:3:40::";
        let t = table6(vec![
            ("2001:db8:200::/64", bgp_srv6_via(sid, None)),
            ("fcbb:bbbb:3::/48", static6_via("2001:db8:12::2", Some(5))),
        ]);
        let r = resolve_v6(&t, "2001:db8:200::1".parse().unwrap());
        assert!(r.reachable);
        assert_eq!(r.nexthops.len(), 1);
        assert_eq!(
            r.nexthops[0].addr,
            "2001:db8:12::2".parse::<IpAddr>().unwrap()
        );
        assert_eq!(r.nexthops[0].ifindex, 5);
        assert_eq!(r.nexthops[0].segs, vec![sid.parse::<Ipv6Addr>().unwrap()]);
        assert_eq!(r.nexthops[0].seg_encap, Some(EncapType::HEncap));
    }

    #[test]
    fn srv6_multi_level_segments_prepend_deeper_transport() {
        // Two SRv6 levels compose into one SRH: the deeper level's
        // segments are the transport used to reach the shallower
        // level's first segment, so they are visited first.
        let outer_sid = "fcbb:bbbb:2:40::";
        let inner_sid = "fcbb:bbbb:3:40::";
        let t = table6(vec![
            ("2001:db8:200::/64", bgp_srv6_via(inner_sid, None)),
            ("fcbb:bbbb:3::/48", bgp_srv6_via(outer_sid, Some(5))),
        ]);
        let r = resolve_v6(&t, "2001:db8:200::1".parse().unwrap());
        assert!(r.reachable);
        assert_eq!(
            r.nexthops[0].segs,
            vec![
                outer_sid.parse::<Ipv6Addr>().unwrap(),
                inner_sid.parse::<Ipv6Addr>().unwrap(),
            ]
        );
    }

    #[test]
    fn mixed_label_and_seg_transport_is_refused() {
        // An SRv6 service route whose SID resolves through an SR-MPLS
        // labeled path would need both a seg6 encap and a label push on
        // one kernel nexthop — impossible; the chain must not resolve.
        let sid = "fcbb:bbbb:3:40::";
        let mut labeled = RibEntry::new(RibType::Isis);
        labeled.valid = true;
        labeled.distance = 115;
        let mut uni = NexthopUni::new(
            "2001:db8:12::2".parse::<IpAddr>().unwrap(),
            13,
            vec![Label::Explicit(16600)],
        );
        uni.ifindex_origin = Some(11);
        labeled.nexthop = Nexthop::Uni(uni);

        let t = table6(vec![
            ("2001:db8:200::/64", bgp_srv6_via(sid, None)),
            ("fcbb:bbbb:3::/48", labeled),
        ]);
        let r = resolve_v6(&t, "2001:db8:200::1".parse().unwrap());
        assert!(!r.reachable);
        assert!(r.nexthops.is_empty());
    }

    #[test]
    fn srv6_segs_inherited_v4_service_route() {
        // IPv4-over-SRv6 (RFC 8950-style): a v4 service route whose
        // nexthop is a v6 SID with segments. The v4 resolver inherits
        // the segment list the same way.
        let sid = "fcbb:bbbb:3:40::";
        let mut e = RibEntry::new(RibType::Bgp);
        e.valid = true;
        e.distance = 200;
        let uni = NexthopUni {
            addr: sid.parse::<IpAddr>().unwrap(),
            segs: vec![sid.parse().unwrap()],
            encap_type: Some(EncapType::HEncap),
            ifindex_origin: Some(2),
            valid: true,
            ..Default::default()
        };
        e.nexthop = Nexthop::Uni(uni);
        let t = table(vec![("10.2.0.0/24", e)]);
        let r = resolve_v4(&t, "10.2.0.1".parse().unwrap());
        assert!(r.reachable);
        assert_eq!(r.nexthops[0].segs, vec![sid.parse::<Ipv6Addr>().unwrap()]);
        assert_eq!(r.nexthops[0].seg_encap, Some(EncapType::HEncap));
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
