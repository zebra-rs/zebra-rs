//! Connected-subnet registry for the eBGP directly-connected-network
//! check (`disable-connected-check`).
//!
//! Populated from `RibRx::AddrAdd` / `AddrDel`: every interface address
//! contributes its *network* (the address with host bits cleared) so the
//! BGP instance can answer "is this peer on one of our directly-connected
//! subnets?" — FRR's `if_lookup_by_ipv4` / `shared_network`. A single-hop
//! eBGP peer that is **not** on any connected subnet is held down unless
//! the operator sets `disable-connected-check` (see
//! [`super::peer::Peer::connected_check_ok`]).
//!
//! Subnets are reference-counted by network so two interface addresses in
//! the same subnet (or a flapping secondary) don't prematurely drop it.
//! The table is consulted only at connect-initiation time; an empty table
//! (no interface knowledge yet, or a per-VRF instance not fed interface
//! addresses) makes the check **fail open**, matching FRR's behaviour
//! when it has no RIB connectivity information.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use ipnet::IpNet;

use crate::rib::link::LinkAddr;

/// One connected network, its contributing addresses, and the interface
/// it lives on.
#[derive(Debug, Default)]
struct SubnetRef {
    /// The interface addresses (with host bits, plus owning ifindex)
    /// that contribute this network. A set, not a counter: the RIB
    /// re-broadcasts an address it already announced whenever its
    /// *state* changes (kernel secondary flip today, address-flag
    /// updates when those start re-broadcasting), so counting events
    /// would inflate on every re-delivery and one AddrDel could never
    /// drain the subnet again.
    addrs: BTreeSet<(IpNet, u32)>,
    /// The recording address's ifindex. With several addresses in one subnet
    /// the last writer wins — a subnet spanning *different* interfaces is a
    /// pathological config we don't try to disambiguate.
    ifindex: u32,
}

/// Set of directly-connected networks, keyed by network with the exact
/// contributing addresses tracked per entry.
#[derive(Debug, Default)]
pub struct ConnectedSubnets {
    nets: BTreeMap<IpNet, SubnetRef>,
}

impl ConnectedSubnets {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an interface address. The stored key is its network
    /// (`addr.trunc()`, host bits cleared); the exact address is tracked
    /// so several addresses sharing one subnet coexist and re-delivery
    /// of a known address is a no-op. A /32 or /128 host address
    /// contributes only itself, which is exactly what we want — it does
    /// not make a different peer "connected".
    pub fn record(&mut self, addr: &LinkAddr) {
        let entry = self.nets.entry(addr.addr.trunc()).or_default();
        entry.addrs.insert((addr.addr, addr.ifindex));
        entry.ifindex = addr.ifindex;
    }

    /// Forget an interface address previously passed to [`Self::record`].
    /// The subnet is dropped only when its last contributing address goes;
    /// forgetting an address never recorded (or already forgotten) changes
    /// nothing.
    pub fn forget(&mut self, addr: &LinkAddr) {
        let net = addr.addr.trunc();
        if let Some(entry) = self.nets.get_mut(&net) {
            entry.addrs.remove(&(addr.addr, addr.ifindex));
            if entry.addrs.is_empty() {
                self.nets.remove(&net);
            }
        }
    }

    /// Drop every contribution made by addresses on `ifindex`. A deleted
    /// link's addresses are not reliably withdrawn one by one — a veth
    /// moved into another netns emits only RTM_DELLINK — so the LinkDel
    /// handler sweeps them here wholesale.
    pub fn purge_ifindex(&mut self, ifindex: u32) {
        self.nets.retain(|_, entry| {
            entry.addrs.retain(|(_, ifi)| *ifi != ifindex);
            if let Some((_, survivor)) = entry.addrs.iter().next()
                && entry.ifindex == ifindex
            {
                entry.ifindex = *survivor;
            }
            !entry.addrs.is_empty()
        });
    }

    /// True while no interface address is known. The connected check
    /// fails open in this state (see the module docs).
    pub fn is_empty(&self) -> bool {
        self.nets.is_empty()
    }

    /// Whether `ip` falls inside one of the recorded connected subnets.
    /// Address-family mismatches never match (an IPv4 subnet does not
    /// cover an IPv6 address).
    pub fn covers(&self, ip: IpAddr) -> bool {
        self.nets.keys().any(|net| net.contains(&ip))
    }

    /// The interface a directly-connected `ip` lives on, if known — used to
    /// key single-hop BFD sessions so the XDP data plane (Echo
    /// reflector + expiration watchdog) can attach to the right link.
    /// IPv6 link-locals are excluded: `fe80::/64` is recorded by *every*
    /// v6 interface, so a covering match would be meaningless (link-local
    /// peering is the interface-peer machinery's job).
    pub fn ifindex_for(&self, ip: IpAddr) -> Option<u32> {
        if matches!(ip, IpAddr::V6(a) if a.is_unicast_link_local()) {
            return None;
        }
        self.nets
            .iter()
            .find(|(net, _)| net.contains(&ip))
            .map(|(_, r)| r.ifindex)
            .filter(|&ifindex| ifindex != 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipnet::{Ipv4Net, Ipv6Net};

    fn v4(addr: &str, prefix: u8) -> LinkAddr {
        let net: Ipv4Net = format!("{addr}/{prefix}").parse().unwrap();
        LinkAddr {
            addr: IpNet::V4(net),
            ifindex: 1,
            secondary: false,
            config: false,
            fib: true,
            ..Default::default()
        }
    }

    fn v6(addr: &str, prefix: u8) -> LinkAddr {
        let net: Ipv6Net = format!("{addr}/{prefix}").parse().unwrap();
        LinkAddr {
            addr: IpNet::V6(net),
            ifindex: 1,
            secondary: false,
            config: false,
            fib: true,
            ..Default::default()
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn record_is_idempotent_per_address() {
        let mut t = ConnectedSubnets::new();
        // The RIB re-broadcasts a known address on state changes
        // (secondary flip, flag updates) — the re-delivery must not
        // create a second reference one AddrDel can't drain.
        t.record(&v4("10.0.0.1", 24));
        t.record(&v4("10.0.0.1", 24));
        assert!(t.covers(ip("10.0.0.2")));
        t.forget(&v4("10.0.0.1", 24));
        assert!(!t.covers(ip("10.0.0.2")));

        // Two DISTINCT addresses in one subnet still keep it alive
        // until the last one goes.
        t.record(&v4("10.0.0.1", 24));
        t.record(&v4("10.0.0.9", 24));
        t.forget(&v4("10.0.0.1", 24));
        assert!(t.covers(ip("10.0.0.2")));
        t.forget(&v4("10.0.0.9", 24));
        assert!(!t.covers(ip("10.0.0.2")));
    }

    #[test]
    fn purge_ifindex_sweeps_only_that_link() {
        let mut t = ConnectedSubnets::new();
        t.record(&v4_on("10.0.0.1", 24, 3));
        t.record(&v4_on("10.1.0.1", 24, 5));
        // A subnet spanning both links survives the purge via the
        // other link's contribution, and its ifindex re-points.
        t.record(&v4_on("10.2.0.1", 24, 3));
        t.record(&v4_on("10.2.0.2", 24, 5));

        t.purge_ifindex(3);
        assert!(!t.covers(ip("10.0.0.2")), "purged link's subnet gone");
        assert!(t.covers(ip("10.1.0.2")), "other link untouched");
        assert!(t.covers(ip("10.2.0.9")), "shared subnet survives");
        assert_eq!(t.ifindex_for(ip("10.2.0.9")), Some(5));

        t.purge_ifindex(5);
        assert!(t.is_empty());
    }

    #[test]
    fn empty_table_covers_nothing_and_reports_empty() {
        let t = ConnectedSubnets::new();
        assert!(t.is_empty());
        assert!(!t.covers(ip("10.0.0.2")));
    }

    #[test]
    fn link_subnet_covers_peer_on_subnet() {
        let mut t = ConnectedSubnets::new();
        t.record(&v4("10.0.0.1", 24));
        assert!(!t.is_empty());
        // A peer sharing the /24 is connected; the loopback two hops away
        // is not.
        assert!(t.covers(ip("10.0.0.2")));
        assert!(!t.covers(ip("10.255.0.2")));
    }

    #[test]
    fn host_address_only_covers_itself() {
        // The classic loopback-peering case: the only interface addresses
        // are the /24 link and a /32 loopback, and the peer's loopback is
        // covered by neither.
        let mut t = ConnectedSubnets::new();
        t.record(&v4("10.0.0.1", 24));
        t.record(&v4("10.255.0.1", 32));
        assert!(t.covers(ip("10.0.0.9")));
        assert!(t.covers(ip("10.255.0.1")));
        assert!(!t.covers(ip("10.255.0.2")));
    }

    #[test]
    fn refcount_keeps_subnet_until_last_address_gone() {
        // Two addresses in the same /24 share one subnet key.
        let mut t = ConnectedSubnets::new();
        t.record(&v4("10.0.0.1", 24));
        t.record(&v4("10.0.0.2", 24));
        t.forget(&v4("10.0.0.1", 24));
        assert!(
            t.covers(ip("10.0.0.7")),
            "subnet survives while a peer addr remains"
        );
        t.forget(&v4("10.0.0.2", 24));
        assert!(!t.covers(ip("10.0.0.7")));
        assert!(t.is_empty());
    }

    #[test]
    fn forget_unknown_is_noop() {
        let mut t = ConnectedSubnets::new();
        t.forget(&v4("10.0.0.1", 24));
        assert!(t.is_empty());
    }

    #[test]
    fn ipv6_subnet_and_family_isolation() {
        let mut t = ConnectedSubnets::new();
        t.record(&v6("2001:db8::1", 64));
        assert!(t.covers(ip("2001:db8::2")));
        assert!(!t.covers(ip("2001:db8:1::2")));
        // An IPv6 subnet never covers an IPv4 address and vice versa.
        assert!(!t.covers(ip("10.0.0.2")));
    }

    fn v4_on(addr: &str, prefix: u8, ifindex: u32) -> LinkAddr {
        LinkAddr {
            ifindex,
            ..v4(addr, prefix)
        }
    }

    /// `ifindex_for` resolves a covered peer to the recording interface —
    /// the key the XDP data plane (Echo / expiration watchdog)
    /// needs — and returns `None` for uncovered peers, link-local v6, and
    /// after the subnet's last address is forgotten.
    #[test]
    fn ifindex_for_resolves_connected_interface() {
        let mut t = ConnectedSubnets::new();
        t.record(&v4_on("10.0.0.1", 24, 7));
        t.record(&v6("2001:db8::1", 64)); // helper ifindex 1

        assert_eq!(t.ifindex_for(ip("10.0.0.2")), Some(7));
        assert_eq!(t.ifindex_for(ip("2001:db8::2")), Some(1));
        assert_eq!(t.ifindex_for(ip("10.99.0.2")), None, "not connected");
        // fe80::/64 is on every v6 interface — a covering match would be
        // meaningless, so link-locals never resolve.
        t.record(&v6("fe80::1", 64));
        assert_eq!(t.ifindex_for(ip("fe80::2")), None);

        t.forget(&v4_on("10.0.0.1", 24, 7));
        assert_eq!(t.ifindex_for(ip("10.0.0.2")), None, "subnet gone");
    }
}
