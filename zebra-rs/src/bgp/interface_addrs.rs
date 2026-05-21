//! Per-interface IPv6 link-local registry used as the next-hop for
//! RFC 8950 IPv4-over-IPv6 advertisements on interface-keyed peers.
//!
//! The table is populated from `RibRx::AddrAdd` / `AddrDel` events
//! (filtered to addresses in `fe80::/10`) and consulted at MP_REACH
//! emit time by [`super::peer::Peer::next_hop_v6`]. Multiple link-local
//! addresses on one interface are uncommon but legal; this module
//! keeps every observed LL and exposes a deterministic chosen-LL via
//! [`InterfaceAddrs::link_local_for`] so peers see stable next-hops
//! across daemon restarts and reorderings.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv6Addr;

use ipnet::IpNet;

use crate::rib::link::LinkAddr;

/// Per-ifindex set of IPv6 link-local addresses observed on the box.
#[derive(Debug, Default)]
pub struct InterfaceAddrs {
    by_ifindex: BTreeMap<u32, BTreeSet<Ipv6Addr>>,
}

impl InterfaceAddrs {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an address with the table. Non-link-local entries
    /// (IPv4, IPv6 global, ULA, loopback, multicast …) are ignored.
    pub fn record(&mut self, addr: &LinkAddr) {
        let Some(ll) = link_local(addr) else {
            return;
        };
        self.by_ifindex.entry(addr.ifindex).or_default().insert(ll);
    }

    /// Forget an address. If this was the last LL on the ifindex, the
    /// map entry is dropped so [`Self::link_local_for`] returns `None`.
    pub fn forget(&mut self, addr: &LinkAddr) {
        let Some(ll) = link_local(addr) else {
            return;
        };
        if let Some(set) = self.by_ifindex.get_mut(&addr.ifindex) {
            set.remove(&ll);
            if set.is_empty() {
                self.by_ifindex.remove(&addr.ifindex);
            }
        }
    }

    /// Return the chosen link-local for `ifindex`, or `None` if none
    /// is registered. The choice is numerically smallest — stable
    /// across runs so a peer's advertised next-hop doesn't shift
    /// whenever a transient LL appears or disappears.
    pub fn link_local_for(&self, ifindex: u32) -> Option<Ipv6Addr> {
        self.by_ifindex.get(&ifindex)?.first().copied()
    }
}

/// Extract an IPv6 link-local host address from a `LinkAddr`. Returns
/// `None` for v4, for v6 prefixes whose host bits aren't in `fe80::/10`,
/// and for the unspecified address.
fn link_local(addr: &LinkAddr) -> Option<Ipv6Addr> {
    let IpNet::V6(net) = addr.addr else {
        return None;
    };
    let host = net.addr();
    if host.is_unspecified() || !is_unicast_link_local(host) {
        return None;
    }
    Some(host)
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
    fn ignores_v4_and_non_link_local_v6() {
        let mut t = InterfaceAddrs::new();
        t.record(&v4("10.0.0.1", 24, 7));
        t.record(&v6("2001:db8::1", 64, 7));
        t.record(&v6("fc00::1", 64, 7)); // ULA, not LL.
        assert_eq!(t.link_local_for(7), None);
    }

    #[test]
    fn deterministic_smallest_wins_with_multiple_lls() {
        let mut t = InterfaceAddrs::new();
        t.record(&v6("fe80::2", 64, 7));
        t.record(&v6("fe80::1", 64, 7));
        t.record(&v6("fe80::3", 64, 7));
        assert_eq!(t.link_local_for(7), Some("fe80::1".parse().unwrap()));
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
        assert_eq!(t.link_local_for(7), None);
    }
}
