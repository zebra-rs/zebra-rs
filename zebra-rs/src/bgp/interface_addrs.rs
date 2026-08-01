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

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;

use crate::rib::link::{AddrFlags, LinkAddr};

/// Per-ifindex IPv6 address registry, split by kind, plus an
/// IPv4-address → owning-ifindex map so a v4-addressed BGP session
/// can be tied back to its interface (and from there to that
/// interface's global v6 — the RFC 2545 next-hop source for v6 NLRI
/// carried over v4 transport).
///
/// Each v6 entry carries the kernel's address state (`AddrFlags`) —
/// the RIB re-broadcasts an address whenever its state moves (DAD
/// completing, deprecation), and [`Self::record`] upserts the flags
/// in place, so the next-hop choice tracks address usability live.
#[derive(Debug, Default)]
pub struct InterfaceAddrs {
    link_local: BTreeMap<u32, BTreeMap<Ipv6Addr, AddrFlags>>,
    global: BTreeMap<u32, BTreeMap<Ipv6Addr, AddrFlags>>,
    v4_owner: BTreeMap<Ipv4Addr, u32>,
}

impl InterfaceAddrs {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an address with the table. Loopback and the
    /// unspecified address are ignored; v6 link-locals and globals
    /// (including ULA) are routed to their respective bucket, and v4
    /// addresses record which ifindex owns them. Re-recording a known
    /// address updates its flags in place.
    pub fn record(&mut self, addr: &LinkAddr) {
        match classify(addr) {
            Some(V6Kind::LinkLocal(host)) => {
                self.link_local
                    .entry(addr.ifindex)
                    .or_default()
                    .insert(host, addr.flags);
            }
            Some(V6Kind::Global(host)) => {
                self.global
                    .entry(addr.ifindex)
                    .or_default()
                    .insert(host, addr.flags);
            }
            None => {}
        }
        if let IpNet::V4(net) = addr.addr {
            let host = net.addr();
            if !host.is_loopback() && !host.is_unspecified() {
                self.v4_owner.insert(host, addr.ifindex);
            }
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
        if let IpNet::V4(net) = addr.addr {
            // Guard against an out-of-order AddrDel for an address that
            // has since been re-claimed by another interface.
            if self.v4_owner.get(&net.addr()) == Some(&addr.ifindex) {
                self.v4_owner.remove(&net.addr());
            }
        }
    }

    /// Drop everything recorded against `ifindex`. A deleted link's
    /// addresses are not reliably withdrawn one by one — a veth moved
    /// into another netns emits only RTM_DELLINK — so the LinkDel
    /// handler sweeps them here wholesale. Without it, a dead
    /// interface keeps serving next-hop sources forever.
    pub fn purge_ifindex(&mut self, ifindex: u32) {
        self.link_local.remove(&ifindex);
        self.global.remove(&ifindex);
        self.v4_owner.retain(|_, owner| *owner != ifindex);
    }

    /// Which interface owns this local IPv4 address, if any. Used to
    /// map a v4-addressed BGP session's local end back to its
    /// interface so [`Self::global_for`] can supply the v6 next-hop
    /// for v6 NLRI advertised over that session.
    pub fn ifindex_for_v4(&self, addr: Ipv4Addr) -> Option<u32> {
        self.v4_owner.get(&addr).copied()
    }

    /// Return the chosen link-local for `ifindex`, or `None` if none
    /// is registered. State-aware: see [`pick`].
    pub fn link_local_for(&self, ifindex: u32) -> Option<Ipv6Addr> {
        pick(self.link_local.get(&ifindex)?)
    }

    /// Return the chosen global IPv6 for `ifindex`, or `None` if none
    /// is registered. Used by the RFC 8950 32-octet dual-nexthop
    /// emit path — pure-unnumbered links typically have no global v6,
    /// in which case this returns `None` and the encoder falls back
    /// to the 16-octet link-local-only form. State-aware: see
    /// [`pick`].
    pub fn global_for(&self, ifindex: u32) -> Option<Ipv6Addr> {
        pick(self.global.get(&ifindex)?)
    }
}

/// The next-hop choice for one bucket, ranked by kernel address state:
///
/// - DAD-failed addresses are never used — the kernel won't source
///   from one, so advertising it as a next-hop black-holes the peer.
/// - Otherwise rank `(tentative, deprecated, temporary, address)`,
///   lowest first: a preferred stable address wins; a deprecated one
///   is used only when nothing preferred exists (RFC 6724 rule 3); a
///   temporary (RFC 4941) address loses to a stable one because an
///   advertised next-hop must outlive the privacy rotation; a
///   tentative address (DAD still running) is the last resort — the
///   fail-open keeps a freshly-configured single address usable, and
///   the DAD-completion re-broadcast re-runs this choice moments
///   later. Ties break on the numerically smallest address, so the
///   pick is stable across list reorderings and restarts.
fn pick(bucket: &BTreeMap<Ipv6Addr, AddrFlags>) -> Option<Ipv6Addr> {
    bucket
        .iter()
        .filter(|(_, f)| !f.dadfailed)
        .min_by_key(|(addr, f)| (f.tentative, f.deprecated, f.temporary, **addr))
        .map(|(addr, _)| *addr)
}

fn drop_from(map: &mut BTreeMap<u32, BTreeMap<Ipv6Addr, AddrFlags>>, ifindex: u32, addr: Ipv6Addr) {
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
            ..Default::default()
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
            ..Default::default()
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

    fn v6_flagged(
        addr: &str,
        prefix: u8,
        ifindex: u32,
        f: impl Fn(&mut crate::rib::link::AddrFlags),
    ) -> LinkAddr {
        let mut a = v6(addr, prefix, ifindex);
        f(&mut a.flags);
        a
    }

    #[test]
    fn dad_lifecycle_moves_the_pick() {
        let mut t = InterfaceAddrs::new();
        let stable = v6("2001:db8::9", 64, 7);
        t.record(&stable);

        // A lower address arrives tentative (DAD running): the
        // established stable address keeps winning.
        let fresh = v6_flagged("2001:db8::1", 64, 7, |f| f.tentative = true);
        t.record(&fresh);
        assert_eq!(t.global_for(7), Some("2001:db8::9".parse().unwrap()));

        // DAD completes — the RIB re-broadcasts with tentative
        // cleared, record() upserts, and the lower address takes over.
        let done = v6_flagged("2001:db8::1", 64, 7, |f| f.permanent = true);
        t.record(&done);
        assert_eq!(t.global_for(7), Some("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn dadfailed_is_never_used() {
        let mut t = InterfaceAddrs::new();
        t.record(&v6_flagged("2001:db8::1", 64, 7, |f| f.dadfailed = true));
        assert_eq!(t.global_for(7), None, "a dead address black-holes peers");

        t.record(&v6("2001:db8::9", 64, 7));
        assert_eq!(t.global_for(7), Some("2001:db8::9".parse().unwrap()));
    }

    #[test]
    fn deprecated_and_temporary_rank_below_stable() {
        let mut t = InterfaceAddrs::new();
        t.record(&v6_flagged("2001:db8::1", 64, 7, |f| f.deprecated = true));
        t.record(&v6_flagged("2001:db8::2", 64, 7, |f| f.temporary = true));
        t.record(&v6("2001:db8::9", 64, 7));
        // The preferred stable address wins over both the lower
        // deprecated and the lower temporary one.
        assert_eq!(t.global_for(7), Some("2001:db8::9".parse().unwrap()));

        // With the stable one gone, deprecated ranks below temporary
        // (RFC 6724 rule 3: avoid deprecated first).
        t.forget(&v6("2001:db8::9", 64, 7));
        assert_eq!(t.global_for(7), Some("2001:db8::2".parse().unwrap()));
    }

    #[test]
    fn tentative_is_the_fail_open_last_resort() {
        let mut t = InterfaceAddrs::new();
        // A freshly-configured lone address mid-DAD must still be
        // usable — refusing it would break the single-address common
        // case for the ~1s DAD window.
        t.record(&v6_flagged("2001:db8::1", 64, 7, |f| f.tentative = true));
        assert_eq!(t.global_for(7), Some("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn purge_ifindex_drops_all_kinds() {
        let mut t = InterfaceAddrs::new();
        t.record(&v6("fe80::1", 64, 7));
        t.record(&v6("2001:db8::1", 64, 7));
        t.record(&v4("10.0.0.1", 24, 7));
        t.record(&v6("fe80::2", 64, 9));

        t.purge_ifindex(7);
        assert_eq!(t.link_local_for(7), None);
        assert_eq!(t.global_for(7), None);
        assert_eq!(t.ifindex_for_v4("10.0.0.1".parse().unwrap()), None);
        // The other interface is untouched.
        assert_eq!(t.link_local_for(9), Some("fe80::2".parse().unwrap()));
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
    fn v4_owner_maps_session_address_to_interface_v6_global() {
        // The RFC 2545 fix: a v4-addressed session's local end resolves
        // to its owning ifindex, whose global v6 becomes the MP_REACH
        // next-hop for v6 NLRI carried over that session.
        let mut t = InterfaceAddrs::new();
        t.record(&v4("192.168.0.1", 30, 7));
        t.record(&v6("2001:db8:12::1", 64, 7));
        let ifindex = t.ifindex_for_v4("192.168.0.1".parse().unwrap());
        assert_eq!(ifindex, Some(7));
        assert_eq!(
            ifindex.and_then(|i| t.global_for(i)),
            Some("2001:db8:12::1".parse().unwrap())
        );
        // Forget drops the mapping; a stale AddrDel for an address
        // re-claimed by another interface must not clobber it.
        t.record(&v4("192.168.0.1", 30, 9));
        t.forget(&v4("192.168.0.1", 30, 7));
        assert_eq!(t.ifindex_for_v4("192.168.0.1".parse().unwrap()), Some(9));
        t.forget(&v4("192.168.0.1", 30, 9));
        assert_eq!(t.ifindex_for_v4("192.168.0.1".parse().unwrap()), None);
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
