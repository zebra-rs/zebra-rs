//! `update-source`: where a neighbor's TCP session is sourced from.
//!
//! The statement names either an address, bound as it is, or an
//! interface, which stands for that interface's address of the
//! neighbor's address family (FRR `neighbor X update-source
//! <A.B.C.D|X:X::X:X|IFNAME>`). The interface form exists so the source
//! follows the interface: SONiC writes `update-source Loopback4096` and
//! never the loopback's address.
//!
//! What was written is an [`UpdateSource`], kept in
//! [`super::neighbor_group::InheritableKnobs`]. What the session binds
//! is `PeerTransportConfig::update_source`, an address in both forms:
//! for the interface form it is the outcome of [`resolve`], stored by
//! [`adopt`], and made again whenever the statement, the interface or
//! one of its addresses changes. The dial path and BFD read only that
//! address, so neither knows the two forms apart.
//!
//! The interface is one of the neighbor's own VRF. The default
//! instance asks its interface table (`config::update_source_resolve`);
//! a per-VRF task keeps a [`SourceInterfaces`] of what the RIB tells it
//! of its VRF (`BgpVrf::update_source_resolve`).
//!
//! An interface that gives no address leaves the neighbor *pending*
//! ([`super::peer::Peer::update_source_pending`]): it is not dialed,
//! because a session sourced from whatever the kernel picks is not the
//! one that was asked for. FRR fails the connect the same way
//! (`bgp_update_source()` returns -1 when the interface or its address
//! is missing).

use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::interface_addrs::InterfaceAddrs;
use super::peer::{Peer, State};
use crate::rib::api::RibRx;

/// The value of an `update-source` (or `transport local-address`)
/// statement, as written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateSource {
    /// A local address, bound before the connect.
    Addr(IpAddr),
    /// An interface, by name: its address of the neighbor's family.
    Interface(String),
}

impl UpdateSource {
    /// Read a leaf value: an address when it parses as one, an
    /// interface name otherwise. The order is FRR's
    /// (`peer_update_source_vty` tries `str2sockunion` first), and it
    /// is why a link that happens to be named like an address cannot be
    /// named here.
    pub fn parse(value: &str) -> Self {
        match value.parse::<IpAddr>() {
            Ok(addr) => Self::Addr(addr),
            Err(_) => Self::Interface(value.to_string()),
        }
    }
}

impl fmt::Display for UpdateSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Addr(addr) => write!(f, "{addr}"),
            Self::Interface(name) => f.write_str(name),
        }
    }
}

/// The address the interface `ifindex` gives a session to `peer`, or
/// `None` when it has no usable address of the peer's family. The
/// caller finds the ifindex of the name that was written
/// (`Bgp::live_link_index`); a name no link has gives nothing either.
///
/// Of several addresses the one sharing the most leading bits with the
/// peer's address is taken — FRR's `bgp_update_address()`, which on a
/// multi-homed interface lands on the subnet the peer is in — and the
/// lowest of equals, where FRR takes whichever comes first in its list.
///
/// IPv6: only global addresses (a link-local cannot source a session to
/// a global peer), and only ones a socket can bind now, so not one that
/// failed duplicate address detection nor one still tentative. The RIB
/// announces an address again when its state moves, and the choice is
/// made again then. A deprecated or temporary (RFC 4941) address is
/// taken only when there is no other.
pub fn resolve(addrs: &InterfaceAddrs, ifindex: u32, peer: IpAddr) -> Option<IpAddr> {
    match peer {
        IpAddr::V4(peer) => addrs
            .v4_on(ifindex)
            .min_by_key(|addr| (std::cmp::Reverse(common_bits_v4(*addr, peer)), *addr))
            .map(IpAddr::V4),
        IpAddr::V6(peer) => addrs
            .v6_global_bindable(ifindex)
            .min_by_key(|(addr, flags)| {
                (
                    flags.deprecated,
                    flags.temporary,
                    std::cmp::Reverse(common_bits_v6(*addr, peer)),
                    *addr,
                )
            })
            .map(|(addr, _)| IpAddr::V6(addr)),
    }
}

/// What became of a neighbor's source when its interface was asked
/// again ([`adopt`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Adopted {
    /// The interface gives what the neighbor already had, or the
    /// neighbor's source is not an interface's.
    Unchanged,
    /// The source changed; a BFD session keyed by it is to be
    /// reconciled. `start`: the neighbor was held for want of a source
    /// (`fsm_start` parks it in Active) and is to be sent
    /// `Event::Start`, so it dials now and not at the connect-retry
    /// tick.
    Changed { start: bool },
}

/// Store `want`, what the interface of an `update-source <interface>`
/// gives `peer` now, as the neighbor's source.
///
/// A session that is up is left alone when the address moves: it keeps
/// the one it was opened with — as it does when an `update-source
/// <address>` is changed — and the next connect binds the new one. A
/// passive neighbor is never started, and an Idle one has its own timer.
pub fn adopt(peer: &mut Peer, want: Option<IpAddr>) -> Adopted {
    let Some(ifname) = peer.config.transport.update_source_if.as_deref() else {
        return Adopted::Unchanged;
    };
    let had = peer.config.transport.update_source;
    if had == want {
        return Adopted::Unchanged;
    }
    match want {
        Some(source) => tracing::info!(
            peer = %peer.display_name(),
            interface = %ifname,
            source = %source,
            "bgp: update-source interface gives this neighbor its source address",
        ),
        None => tracing::warn!(
            peer = %peer.display_name(),
            interface = %ifname,
            "bgp: update-source interface has no usable address for this neighbor; it is not dialed",
        ),
    }
    peer.config.transport.update_source = want;
    let start = had.is_none() && peer.active && !peer.is_passive() && peer.state == State::Active;
    Adopted::Changed { start }
}

/// The interfaces of one VRF and their addresses, as a per-VRF BGP task
/// is told of them by the RIB: what an `update-source <interface>` of a
/// neighbor in that VRF is resolved against.
///
/// A subscriber of a VRF is sent the links of that VRF only, with their
/// addresses, at subscribe time and as they change; an interface that
/// moves to another VRF leaves as an `AddrDel` of each address and a
/// `LinkDel`. So a name found here is an interface of this VRF, and one
/// of another VRF is not found.
///
/// Kept apart from the task's `BgpVrf::interface_addrs`, which is the
/// next-hop source of RFC 8950 advertisements and is deliberately left
/// empty in a per-VRF task: feeding that one would change the next hops
/// a CE is sent.
#[derive(Debug, Default)]
pub struct SourceInterfaces {
    index_by_name: BTreeMap<String, u32>,
    name_by_index: BTreeMap<u32, String>,
    addrs: InterfaceAddrs,
}

impl SourceInterfaces {
    /// Take a RIB event. `true` for a link or address event, after
    /// which every neighbor's source is to be resolved again; `false`
    /// for anything else, which is not looked at.
    pub fn rib_event(&mut self, msg: &RibRx) -> bool {
        match msg {
            RibRx::LinkAdd(link) => self.link_add(link.index, &link.name),
            RibRx::LinkDel(ifindex) => self.link_del(*ifindex),
            RibRx::AddrAdd(addr) => self.addrs.record(addr),
            RibRx::AddrDel(addr) => self.addrs.forget(addr),
            _ => return false,
        }
        true
    }

    fn link_add(&mut self, index: u32, name: &str) {
        // The ifindex under another name: the old name is no link's.
        if let Some(old) = self.name_by_index.insert(index, name.to_string())
            && old != name
            && self.index_by_name.get(&old) == Some(&index)
        {
            self.index_by_name.remove(&old);
        }
        // The name under another ifindex (the link was deleted and
        // created again, and its `LinkDel` did not come first): what the
        // old ifindex had is not this link's.
        if let Some(old) = self.index_by_name.insert(name.to_string(), index)
            && old != index
            && self.name_by_index.get(&old).map(String::as_str) == Some(name)
        {
            self.name_by_index.remove(&old);
            self.addrs.purge_ifindex(old);
        }
    }

    fn link_del(&mut self, index: u32) {
        if let Some(name) = self.name_by_index.remove(&index)
            && self.index_by_name.get(&name) == Some(&index)
        {
            self.index_by_name.remove(&name);
        }
        // A deleted link's addresses are not reliably withdrawn one by
        // one (see `InterfaceAddrs::purge_ifindex`).
        self.addrs.purge_ifindex(index);
    }

    /// The address interface `ifname` gives a session to `peer`
    /// ([`resolve`]), `None` also when this VRF has no such interface.
    pub fn resolve(&self, ifname: &str, peer: IpAddr) -> Option<IpAddr> {
        let ifindex = *self.index_by_name.get(ifname)?;
        resolve(&self.addrs, ifindex, peer)
    }
}

fn common_bits_v4(a: Ipv4Addr, b: Ipv4Addr) -> u32 {
    (u32::from(a) ^ u32::from(b)).leading_zeros()
}

fn common_bits_v6(a: Ipv6Addr, b: Ipv6Addr) -> u32 {
    (u128::from(a) ^ u128::from(b)).leading_zeros()
}

/// A link as the RIB announces one, for the tests of what follows the
/// link events: only its index and its name matter to them.
#[cfg(test)]
pub(crate) fn test_link(index: u32, name: &str) -> crate::rib::Link {
    crate::rib::Link {
        index,
        name: name.to_string(),
        mtu: 1500,
        original_mtu: 1500,
        metric: 1,
        flags: Default::default(),
        link_type: crate::rib::LinkType::Ethernet,
        label: false,
        mac: None,
        addr4: Vec::new(),
        addr6: Vec::new(),
        master: None,
        vni: None,
        vrf_table: None,
        bridge: false,
        vxlan_local: None,
        vxlan_metadata: None,
        parent: None,
        vlan_id: None,
        mtu_error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rib::link::{AddrFlags, LinkAddr};
    use ipnet::IpNet;

    fn addr(net: &str, ifindex: u32) -> LinkAddr {
        LinkAddr {
            addr: net.parse::<IpNet>().unwrap(),
            ifindex,
            fib: true,
            ..Default::default()
        }
    }

    fn flagged(net: &str, ifindex: u32, f: impl Fn(&mut AddrFlags)) -> LinkAddr {
        let mut a = addr(net, ifindex);
        f(&mut a.flags);
        a
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn parse_reads_an_address_before_a_name() {
        assert_eq!(
            UpdateSource::parse("10.0.0.1"),
            UpdateSource::Addr(ip("10.0.0.1"))
        );
        assert_eq!(
            UpdateSource::parse("2001:db8::1"),
            UpdateSource::Addr(ip("2001:db8::1"))
        );
        assert_eq!(
            UpdateSource::parse("Loopback4096"),
            UpdateSource::Interface("Loopback4096".to_string())
        );
        // A hex-only word is a name: it is not an IPv6 address, though
        // the CLI's IPv6 matcher lets it through as the start of one.
        assert_eq!(
            UpdateSource::parse("face"),
            UpdateSource::Interface("face".to_string())
        );
        assert_eq!(UpdateSource::parse("Loopback0").to_string(), "Loopback0");
        assert_eq!(UpdateSource::parse("10.0.0.1").to_string(), "10.0.0.1");
    }

    /// One statement serves both families: each peer gets the
    /// interface's address of its own.
    #[test]
    fn interface_gives_each_family_its_own_address() {
        let mut addrs = InterfaceAddrs::new();
        addrs.record(&addr("10.1.0.32/32", 7));
        addrs.record(&addr("fc00:1::32/128", 7));
        assert_eq!(resolve(&addrs, 7, ip("10.0.0.57")), Some(ip("10.1.0.32")));
        assert_eq!(resolve(&addrs, 7, ip("fc00::72")), Some(ip("fc00:1::32")));
    }

    #[test]
    fn no_address_of_the_family_gives_none() {
        let mut addrs = InterfaceAddrs::new();
        addrs.record(&addr("10.1.0.32/32", 7));
        // An IPv4 address only: nothing for an IPv6 peer.
        assert_eq!(resolve(&addrs, 7, ip("fc00::72")), None);
        // No address at all.
        assert_eq!(resolve(&addrs, 8, ip("10.0.0.57")), None);
        // Another interface's address is not this one's, however close
        // to the peer it is.
        addrs.record(&addr("192.0.2.1/24", 8));
        assert_eq!(resolve(&addrs, 7, ip("192.0.2.2")), Some(ip("10.1.0.32")));
        // Gone with its interface.
        addrs.purge_ifindex(7);
        assert_eq!(resolve(&addrs, 7, ip("192.0.2.2")), None);
    }

    /// FRR's rule: the address with the most leading bits in common
    /// with the peer, so on a multi-homed interface the one in the
    /// peer's subnet. The lowest address of equals.
    #[test]
    fn most_common_leading_bits_then_lowest() {
        let mut addrs = InterfaceAddrs::new();
        addrs.record(&addr("10.0.0.1/24", 3));
        addrs.record(&addr("192.168.0.1/24", 3));
        assert_eq!(
            resolve(&addrs, 3, ip("192.168.0.2")),
            Some(ip("192.168.0.1"))
        );
        assert_eq!(resolve(&addrs, 3, ip("10.0.0.2")), Some(ip("10.0.0.1")));
        // 172.16.0.1 shares one leading bit with 192.168.0.1 and none
        // with 10.0.0.1.
        assert_eq!(
            resolve(&addrs, 3, ip("172.16.0.1")),
            Some(ip("192.168.0.1"))
        );
        // Equal: 10.0.0.2 and 10.0.0.3 both share 30 bits with 10.0.0.1.
        let mut addrs = InterfaceAddrs::new();
        addrs.record(&addr("10.0.0.3/24", 3));
        addrs.record(&addr("10.0.0.2/24", 3));
        assert_eq!(resolve(&addrs, 3, ip("10.0.0.1")), Some(ip("10.0.0.2")));
    }

    /// A link-local never sources a session to a global peer, and an
    /// address a socket cannot bind is not taken: the neighbor waits.
    #[test]
    fn v6_takes_only_bindable_global_addresses() {
        let peer = ip("2001:db8::72");

        let mut addrs = InterfaceAddrs::new();
        addrs.record(&addr("fe80::1/64", 7));
        assert_eq!(resolve(&addrs, 7, peer), None);

        // Tentative: duplicate address detection still runs.
        addrs.record(&flagged("2001:db8::1/128", 7, |f| f.tentative = true));
        assert_eq!(resolve(&addrs, 7, peer), None);
        // ... and done: the RIB announces the address again.
        addrs.record(&addr("2001:db8::1/128", 7));
        assert_eq!(resolve(&addrs, 7, peer), Some(ip("2001:db8::1")));

        // Optimistic (RFC 4429) is usable while detection runs.
        let mut addrs = InterfaceAddrs::new();
        addrs.record(&flagged("2001:db8::2/128", 7, |f| {
            f.tentative = true;
            f.optimistic = true;
        }));
        assert_eq!(resolve(&addrs, 7, peer), Some(ip("2001:db8::2")));

        // A duplicate is dead.
        let mut addrs = InterfaceAddrs::new();
        addrs.record(&flagged("2001:db8::3/128", 7, |f| f.dadfailed = true));
        assert_eq!(resolve(&addrs, 7, peer), None);
    }

    /// A deprecated or temporary address only when there is no other,
    /// whatever it shares with the peer.
    #[test]
    fn v6_prefers_a_preferred_stable_address() {
        let peer = ip("2001:db8::72");
        let mut addrs = InterfaceAddrs::new();
        addrs.record(&flagged("2001:db8::71/64", 3, |f| f.deprecated = true));
        assert_eq!(resolve(&addrs, 3, peer), Some(ip("2001:db8::71")));
        addrs.record(&addr("2001:db9::1/64", 3));
        assert_eq!(resolve(&addrs, 3, peer), Some(ip("2001:db9::1")));
        addrs.record(&flagged("2001:db8::70/64", 3, |f| f.temporary = true));
        assert_eq!(resolve(&addrs, 3, peer), Some(ip("2001:db9::1")));
    }

    fn link_add(index: u32, name: &str) -> RibRx {
        RibRx::LinkAdd(test_link(index, name))
    }

    /// The interfaces of a VRF as the RIB reports them: a name resolves
    /// while a link of that name is there, by that link's addresses.
    #[test]
    fn source_interfaces_follow_the_rib_events() {
        let peer = ip("192.0.2.1");
        let mut vrf = SourceInterfaces::default();
        assert_eq!(vrf.resolve("ce-lo", peer), None);

        // The subscribe-time dump: the link, then its addresses.
        assert!(vrf.rib_event(&link_add(7, "ce-lo")));
        assert_eq!(vrf.resolve("ce-lo", peer), None);
        assert!(vrf.rib_event(&RibRx::AddrAdd(addr("10.255.0.1/32", 7))));
        assert_eq!(vrf.resolve("ce-lo", peer), Some(ip("10.255.0.1")));
        assert_eq!(vrf.resolve("ce-lo", ip("2001:db8::1")), None);
        // Not another name's.
        assert_eq!(vrf.resolve("ce1", peer), None);

        assert!(vrf.rib_event(&RibRx::AddrDel(addr("10.255.0.1/32", 7))));
        assert_eq!(vrf.resolve("ce-lo", peer), None);
        assert!(vrf.rib_event(&RibRx::AddrAdd(addr("10.255.0.3/32", 7))));
        assert_eq!(vrf.resolve("ce-lo", peer), Some(ip("10.255.0.3")));

        // The interface leaves the VRF, or is deleted: a `LinkDel`, with
        // or without an `AddrDel` of each address before it.
        assert!(vrf.rib_event(&RibRx::LinkDel(7)));
        assert_eq!(vrf.resolve("ce-lo", peer), None);
        // Its addresses went with it: back under the same ifindex, it
        // has none until they are reported.
        assert!(vrf.rib_event(&link_add(7, "ce-lo")));
        assert_eq!(vrf.resolve("ce-lo", peer), None);

        // Anything else is not a link or address event.
        assert!(!vrf.rib_event(&RibRx::LinkUp(7)));
        assert!(!vrf.rib_event(&RibRx::RouterIdUpdate(Ipv4Addr::LOCALHOST)));
    }

    /// An ifindex that changes its name, and a name that changes its
    /// ifindex, leave no stale answer behind.
    #[test]
    fn source_interfaces_do_not_answer_for_a_stale_name_or_ifindex() {
        let peer = ip("192.0.2.1");
        let mut vrf = SourceInterfaces::default();
        vrf.rib_event(&link_add(7, "ce-lo"));
        vrf.rib_event(&RibRx::AddrAdd(addr("10.255.0.1/32", 7)));

        // The ifindex is another name's now.
        vrf.rib_event(&link_add(7, "ce9"));
        assert_eq!(vrf.resolve("ce-lo", peer), None);
        assert_eq!(vrf.resolve("ce9", peer), Some(ip("10.255.0.1")));

        // The name under a new ifindex, with no `LinkDel` of the old
        // one: what the old ifindex had is not the new link's.
        vrf.rib_event(&link_add(11, "ce9"));
        assert_eq!(vrf.resolve("ce9", peer), None);
        vrf.rib_event(&RibRx::AddrAdd(addr("10.255.0.9/32", 11)));
        assert_eq!(vrf.resolve("ce9", peer), Some(ip("10.255.0.9")));
        // The old ifindex under yet another name is a new link: it has
        // none of the addresses the link before it had.
        vrf.rib_event(&link_add(7, "ce1"));
        assert_eq!(vrf.resolve("ce1", peer), None);
        // A `LinkDel` of that ifindex does not take the name that left it.
        vrf.rib_event(&RibRx::LinkDel(7));
        assert_eq!(vrf.resolve("ce1", peer), None);
        assert_eq!(vrf.resolve("ce9", peer), Some(ip("10.255.0.9")));
    }
}
