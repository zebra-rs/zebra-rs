use crate::rib::link::LinkAddr;

use super::OspfVersion;

/// A configured address on an OSPF interface. Generic over the
/// address family so v3 (`Ipv6Net`) can reuse the wrapper unchanged.
#[derive(Debug, Clone)]
pub struct OspfAddr<V: OspfVersion> {
    pub prefix: V::Prefix,
    /// Kernel IFA_F_SECONDARY: a same-subnet duplicate of an existing
    /// primary. Never the interface identity, never advertised as its
    /// own Router-LSA link (its subnet is already covered by the
    /// primary). Always false for v3 — IPv6 has no secondary concept.
    pub secondary: bool,
}

impl<V: OspfVersion> OspfAddr<V> {
    pub fn from(addr: &LinkAddr, prefix: &V::Prefix) -> Self {
        Self {
            prefix: *prefix,
            secondary: addr.secondary,
        }
    }
}

impl<V: OspfVersion> Default for OspfAddr<V>
where
    V::Prefix: Default,
{
    fn default() -> Self {
        Self {
            prefix: V::Prefix::default(),
            secondary: false,
        }
    }
}

/// The interface's IPv6 link-local source address (RFC 5340 §A.1:
/// every v3 control packet sources from it, and the Link-LSA
/// advertises it).
///
/// Selection must be STABLE against address-list reordering — the
/// list order is netlink delivery order, which a re-notify or a
/// delete/re-add can permute — because every consumer must keep
/// agreeing on one address: the Hello source, the pseudo-header
/// checksum + `IPV6_PKTINFO` pin, the Link-LSA, and the BFD session
/// local endpoint. Pick the numerically lowest link-local instead of
/// the first in list order. Adding a lower link-local moves the
/// source; peers absorb that via the same-Router-ID source refresh
/// in `ospfv3_hello_recv`.
pub fn stable_link_local(
    addrs: &[OspfAddr<crate::ospf::version::Ospfv3>],
) -> Option<std::net::Ipv6Addr> {
    addrs
        .iter()
        .map(|a| a.prefix.addr())
        .filter(|a| a.is_unicast_link_local())
        .min()
}

/// First address passing `pred` that is not kernel-secondary, falling
/// back to the first passing one at all. Selection sites (identity,
/// Hello netmask, Network-LSA ls_id, BFD, SR host prefix) go through
/// this so a same-subnet secondary never becomes "the" interface
/// address, matching Cisco/FRR — while a transient all-secondary list
/// still yields a usable address.
pub fn primary_addr_where<V: OspfVersion>(
    addrs: &[OspfAddr<V>],
    pred: impl Fn(&OspfAddr<V>) -> bool + Copy,
) -> Option<&OspfAddr<V>> {
    addrs
        .iter()
        .find(|a| !a.secondary && pred(a))
        .or_else(|| addrs.iter().find(|a| pred(a)))
}

/// [`primary_addr_where`] with no extra predicate: the first
/// non-secondary address, else the first address.
pub fn primary_addr<V: OspfVersion>(addrs: &[OspfAddr<V>]) -> Option<&OspfAddr<V>> {
    primary_addr_where(addrs, |_| true)
}

/// Insert `addr` into a link's address list, or update the existing
/// same-prefix entry's `secondary` flag; returns whether anything
/// changed.
///
/// The RIB redistributes every AddrAdd *event*, not every address —
/// one configured address arrives several times (config-exec push,
/// kernel netlink echo, DAD re-notify, link-bounce re-install), so
/// consumers must be idempotent (IS-IS guards the same way in
/// `isis::link::addr_add`). Without this, every duplicate delivery
/// adds another copy of the prefix to the Router-LSA stub networks
/// (v2) / Intra-Area-Prefix-LSA (v3). A re-delivery whose `secondary`
/// verdict moved (kernel promotion/demotion) updates the entry in
/// place.
pub fn link_addr_push_unique<V: OspfVersion>(
    addrs: &mut Vec<OspfAddr<V>>,
    addr: OspfAddr<V>,
) -> bool {
    if let Some(existing) = addrs.iter_mut().find(|a| a.prefix == addr.prefix) {
        let changed = existing.secondary != addr.secondary;
        existing.secondary = addr.secondary;
        return changed;
    }
    addrs.push(addr);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ospf::version::{Ospfv2, Ospfv3};

    #[test]
    fn push_unique_dedups_v6_prefix() {
        let mut addrs: Vec<OspfAddr<Ospfv3>> = Vec::new();
        let lo: ipnet::Ipv6Net = "2001:db8::1/128".parse().unwrap();
        let transit: ipnet::Ipv6Net = "2001:db8:1::1/64".parse().unwrap();

        assert!(link_addr_push_unique(
            &mut addrs,
            OspfAddr {
                prefix: lo,
                secondary: false
            }
        ));
        // Same prefix delivered again (kernel echo / DAD re-notify) —
        // must not grow the list.
        assert!(!link_addr_push_unique(
            &mut addrs,
            OspfAddr {
                prefix: lo,
                secondary: false
            }
        ));
        assert_eq!(addrs.len(), 1);

        assert!(link_addr_push_unique(
            &mut addrs,
            OspfAddr {
                prefix: transit,
                secondary: false
            }
        ));
        assert_eq!(addrs.len(), 2);
    }

    #[test]
    fn primary_addr_skips_secondary() {
        let p1: ipnet::Ipv4Net = "10.0.0.1/24".parse().unwrap();
        let p2: ipnet::Ipv4Net = "10.0.0.2/24".parse().unwrap();
        let addrs: Vec<OspfAddr<Ospfv2>> = vec![
            OspfAddr {
                prefix: p2,
                secondary: true,
            },
            OspfAddr {
                prefix: p1,
                secondary: false,
            },
        ];
        // The secondary is first in delivery order but must not win.
        assert_eq!(primary_addr(&addrs).unwrap().prefix, p1);

        // All-secondary (transient, e.g. primary deleted externally):
        // fall back to the first address rather than none.
        let only_sec: Vec<OspfAddr<Ospfv2>> = vec![OspfAddr {
            prefix: p2,
            secondary: true,
        }];
        assert_eq!(primary_addr(&only_sec).unwrap().prefix, p2);
        assert!(primary_addr::<Ospfv2>(&[]).is_none());
    }

    #[test]
    fn push_unique_updates_secondary_verdict() {
        let p: ipnet::Ipv4Net = "10.0.0.2/24".parse().unwrap();
        let mut addrs: Vec<OspfAddr<Ospfv2>> = Vec::new();
        assert!(link_addr_push_unique(
            &mut addrs,
            OspfAddr {
                prefix: p,
                secondary: true
            }
        ));
        // Promotion re-broadcast: same prefix, verdict now primary —
        // updates in place and reports a change.
        assert!(link_addr_push_unique(
            &mut addrs,
            OspfAddr {
                prefix: p,
                secondary: false
            }
        ));
        assert_eq!(addrs.len(), 1);
        assert!(!addrs[0].secondary);
        // Identical re-delivery: no change.
        assert!(!link_addr_push_unique(
            &mut addrs,
            OspfAddr {
                prefix: p,
                secondary: false
            }
        ));
    }

    #[test]
    fn stable_link_local_is_order_independent() {
        let ll_low: ipnet::Ipv6Net = "fe80::1/64".parse().unwrap();
        let ll_high: ipnet::Ipv6Net = "fe80::5054:ff:fe00:1/64".parse().unwrap();
        let global: ipnet::Ipv6Net = "2001:db8::1/64".parse().unwrap();
        let mk = |p: ipnet::Ipv6Net| OspfAddr::<Ospfv3> {
            prefix: p,
            secondary: false,
        };

        // Same set, both delivery orders → same pick (the lowest).
        let fwd = vec![mk(global), mk(ll_low), mk(ll_high)];
        let rev = vec![mk(ll_high), mk(ll_low), mk(global)];
        assert_eq!(stable_link_local(&fwd), Some("fe80::1".parse().unwrap()));
        assert_eq!(stable_link_local(&fwd), stable_link_local(&rev));

        // No link-local → None; globals never qualify.
        assert_eq!(stable_link_local(&[mk(global)]), None);
        assert_eq!(stable_link_local(&[]), None);
    }

    #[test]
    fn push_unique_dedups_v4_prefix() {
        let mut addrs: Vec<OspfAddr<Ospfv2>> = Vec::new();
        let p: ipnet::Ipv4Net = "10.0.0.1/24".parse().unwrap();

        assert!(link_addr_push_unique(
            &mut addrs,
            OspfAddr {
                prefix: p,
                secondary: false
            }
        ));
        assert!(!link_addr_push_unique(
            &mut addrs,
            OspfAddr {
                prefix: p,
                secondary: false
            }
        ));
        assert_eq!(addrs.len(), 1);
    }
}
