//! Per-interface IPv6 address registry used to source the next-hop
//! for RFC 8950 IPv4-over-IPv6 advertisements on interface-keyed
//! peers.
//!
//! The table is populated from `RibRx::AddrAdd` / `AddrDel` events
//! and consulted at MP_REACH emit time by
//! [`super::peer::Peer::next_hop_v6`] (link-local half) and
//! [`super::peer::Peer::next_hop_v6_global`] (global half). Both
//! halves can coexist on the same interface — when both are present
//! the encoder emits the 32-octet `global || link-local` form per
//! RFC 8950 §3; otherwise the 16-octet link-local-only form, which
//! is the only thing pure-unnumbered links can produce.
//!
//! Multiple addresses of the same kind on one interface are uncommon
//! but legal; this module keeps every observed entry and exposes a
//! deterministic chosen address (numerically smallest) per kind so
//! peers see stable next-hops across daemon restarts and reorderings.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv6Addr;

use ipnet::IpNet;

use crate::rib::link::LinkAddr;

/// Per-ifindex IPv6 address registry, split by kind.
#[derive(Debug, Default)]
pub struct InterfaceAddrs {
    link_local: BTreeMap<u32, BTreeSet<Ipv6Addr>>,
    global: BTreeMap<u32, BTreeSet<Ipv6Addr>>,
}

impl InterfaceAddrs {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an address with the table. IPv4, loopback, and the
    /// unspecified address are ignored; link-locals and globals
    /// (including ULA) are routed to their respective bucket.
    pub fn record(&mut self, addr: &LinkAddr) {
        match classify(addr) {
            Some(V6Kind::LinkLocal(host)) => {
                self.link_local
                    .entry(addr.ifindex)
                    .or_default()
                    .insert(host);
            }
            Some(V6Kind::Global(host)) => {
                self.global.entry(addr.ifindex).or_default().insert(host);
            }
            None => {}
        }
    }

    /// Forget an address previously passed to [`Self::record`]. If the
    /// removal empties the bucket for this ifindex, the map entry is
    /// dropped so subsequent lookups return `None`.
    pub fn forget(&mut self, addr: &LinkAddr) {
        match classify(addr) {
            Some(V6Kind::LinkLocal(host)) => drop_from(&mut self.link_local, addr.ifindex, host),
            Some(V6Kind::Global(host)) => drop_from(&mut self.global, addr.ifindex, host),
            None => {}
        }
    }

    /// Return the chosen link-local for `ifindex`, or `None` if none
    /// is registered. The choice is numerically smallest — stable
    /// across runs so a peer's advertised next-hop doesn't shift
    /// whenever a transient LL appears or disappears.
    pub fn link_local_for(&self, ifindex: u32) -> Option<Ipv6Addr> {
        self.link_local.get(&ifindex)?.first().copied()
    }

    /// Return the chosen global IPv6 for `ifindex`, or `None` if none
    /// is registered. Used by the RFC 8950 32-octet dual-nexthop
    /// emit path — pure-unnumbered links typically have no global v6,
    /// in which case this returns `None` and the encoder falls back
    /// to the 16-octet link-local-only form.
    pub fn global_for(&self, ifindex: u32) -> Option<Ipv6Addr> {
        self.global.get(&ifindex)?.first().copied()
    }
}

fn drop_from(map: &mut BTreeMap<u32, BTreeSet<Ipv6Addr>>, ifindex: u32, addr: Ipv6Addr) {
    if let Some(set) = map.get_mut(&ifindex) {
        set.remove(&addr);
        if set.is_empty() {
            map.remove(&ifindex);
        }
    }
}

enum V6Kind {
    LinkLocal(Ipv6Addr),
    Global(Ipv6Addr),
}

/// Decide how to route an IPv6 interface address into the registry.
/// `None` means "ignore" — IPv4, loopback, unspecified. Everything
/// else routes to either the link-local or global bucket.
fn classify(addr: &LinkAddr) -> Option<V6Kind> {
    let IpNet::V6(net) = addr.addr else {
        return None;
    };
    let host = net.addr();
    if host.is_unspecified() || host.is_loopback() {
        return None;
    }
    if is_unicast_link_local(host) {
        Some(V6Kind::LinkLocal(host))
    } else {
        // ULA, GUA, and anything else routable in some scope — the
        // RFC 8950 32-octet form just calls it "global IPv6", so we
        // don't discriminate further. Multicast / loopback /
        // unspecified are filtered above; multicast in particular
        // shouldn't appear as an interface address anyway.
        Some(V6Kind::Global(host))
    }
}

/// `Ipv6Addr::is_unicast_link_local` is unstable as of Rust 1.84;
/// open-code the `fe80::/10` test that RFC 4291 §2.5.6 specifies.
fn is_unicast_link_local(addr: Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xffc0) == 0xfe80
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipnet::Ipv6Net;

    fn v6(addr: &str, prefix: u8, ifindex: u32) -> LinkAddr {
        let host: Ipv6Addr = addr.parse().unwrap();
        let net = Ipv6Net::new(host, prefix).unwrap();
        LinkAddr {
            addr: IpNet::V6(net),
            ifindex,
            secondary: false,
            config: false,
            fib: true,
        }
    }

    fn v4(addr: &str, prefix: u8, ifindex: u32) -> LinkAddr {
        let net: ipnet::Ipv4Net = format!("{addr}/{prefix}").parse().unwrap();
        LinkAddr {
            addr: IpNet::V4(net),
            ifindex,
            secondary: false,
            config: false,
            fib: true,
        }
    }

    #[test]
    fn record_then_forget_round_trips() {
        let mut t = InterfaceAddrs::new();
        let a = v6("fe80::1", 64, 7);
        t.record(&a);
        assert_eq!(t.link_local_for(7), Some("fe80::1".parse().unwrap()));
        t.forget(&a);
        assert_eq!(t.link_local_for(7), None);
    }

    #[test]
    fn ignores_v4_and_loopback() {
        let mut t = InterfaceAddrs::new();
        t.record(&v4("10.0.0.1", 24, 7));
        t.record(&v6("::1", 128, 7));
        assert_eq!(t.link_local_for(7), None);
        assert_eq!(t.global_for(7), None);
    }

    #[test]
    fn global_v6_lands_in_global_bucket() {
        let mut t = InterfaceAddrs::new();
        t.record(&v6("2001:db8::1", 64, 7));
        assert_eq!(t.global_for(7), Some("2001:db8::1".parse().unwrap()));
        // Should not leak into the LL bucket.
        assert_eq!(t.link_local_for(7), None);
    }

    #[test]
    fn ula_v6_is_treated_as_global() {
        // ULAs are not "Internet-global" but RFC 8950 §3's
        // "global || link-local" form just means "non-LL"; operators
        // running BGP on ULA addressing should get the 32-octet
        // emit.
        let mut t = InterfaceAddrs::new();
        t.record(&v6("fc00::1", 64, 7));
        assert_eq!(t.global_for(7), Some("fc00::1".parse().unwrap()));
        assert_eq!(t.link_local_for(7), None);
    }

    #[test]
    fn both_buckets_coexist_on_one_ifindex() {
        let mut t = InterfaceAddrs::new();
        t.record(&v6("fe80::1", 64, 7));
        t.record(&v6("2001:db8::1", 64, 7));
        assert_eq!(t.link_local_for(7), Some("fe80::1".parse().unwrap()));
        assert_eq!(t.global_for(7), Some("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn deterministic_smallest_wins_per_bucket() {
        let mut t = InterfaceAddrs::new();
        t.record(&v6("fe80::2", 64, 7));
        t.record(&v6("fe80::1", 64, 7));
        t.record(&v6("2001:db8::2", 64, 7));
        t.record(&v6("2001:db8::1", 64, 7));
        assert_eq!(t.link_local_for(7), Some("fe80::1".parse().unwrap()));
        assert_eq!(t.global_for(7), Some("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn forgetting_smallest_falls_back_to_next() {
        let mut t = InterfaceAddrs::new();
        t.record(&v6("fe80::1", 64, 7));
        t.record(&v6("fe80::2", 64, 7));
        t.forget(&v6("fe80::1", 64, 7));
        assert_eq!(t.link_local_for(7), Some("fe80::2".parse().unwrap()));
    }

    #[test]
    fn forgetting_one_bucket_does_not_disturb_the_other() {
        let mut t = InterfaceAddrs::new();
        t.record(&v6("fe80::1", 64, 7));
        t.record(&v6("2001:db8::1", 64, 7));
        t.forget(&v6("2001:db8::1", 64, 7));
        assert_eq!(t.link_local_for(7), Some("fe80::1".parse().unwrap()));
        assert_eq!(t.global_for(7), None);
    }

    #[test]
    fn ifindex_isolation() {
        let mut t = InterfaceAddrs::new();
        t.record(&v6("fe80::1", 64, 7));
        t.record(&v6("fe80::5", 64, 9));
        assert_eq!(t.link_local_for(7), Some("fe80::1".parse().unwrap()));
        assert_eq!(t.link_local_for(9), Some("fe80::5".parse().unwrap()));
        assert_eq!(t.link_local_for(42), None);
    }

    #[test]
    fn forget_unknown_is_noop() {
        let mut t = InterfaceAddrs::new();
        t.forget(&v6("fe80::1", 64, 7));
        t.forget(&v6("2001:db8::1", 64, 7));
        assert_eq!(t.link_local_for(7), None);
        assert_eq!(t.global_for(7), None);
    }
}
