use std::net::IpAddr;

use ipnet::IpNet;

/// How a peer is keyed inside [`super::peer_map::PeerMap`].
///
/// Today every peer is keyed by remote address. Two future workflows
/// need additional variants:
///   * IPv6 unnumbered peers, where the remote link-local is unknown
///     until a Router Advertisement is received and the long-lived
///     identity of the peer is its outbound interface.
///   * Dynamic peers accepted via `bgp listen range`, which are still
///     keyed by remote address but originate from a configured prefix
///     (see [`PeerOrigin`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PeerKey {
    Addr(IpAddr),
    // Wired in by the follow-up interface-neighbor PR; defining the
    // variant now keeps PeerMap signatures stable across that change.
    #[allow(dead_code)]
    Interface(u32),
}

impl PeerKey {
    #[allow(dead_code)]
    pub fn addr(&self) -> Option<IpAddr> {
        match self {
            Self::Addr(a) => Some(*a),
            Self::Interface(_) => None,
        }
    }
}

impl From<IpAddr> for PeerKey {
    fn from(addr: IpAddr) -> Self {
        PeerKey::Addr(addr)
    }
}

/// Provenance of a [`super::peer::Peer`].
///
/// Distinct from [`PeerKey`] because a dynamic peer is keyed by the
/// connecting address (we only learn it on accept) but its origin is
/// the configured listen-range prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PeerOrigin {
    /// Configured by name/address: `router bgp ... neighbor X.X.X.X`.
    #[default]
    Static,
    /// Configured by interface: `neighbor IFNAME interface ...`.
    #[allow(dead_code)]
    Interface { ifindex: u32 },
    /// Created on inbound accept by a `bgp listen range` match.
    #[allow(dead_code)]
    Dynamic { range_prefix: IpNet },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn peer_key_addr_round_trip() {
        let a: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();
        let k: PeerKey = a.into();
        assert_eq!(k, PeerKey::Addr(a));
        assert_eq!(k.addr(), Some(a));
    }

    #[test]
    fn peer_key_interface_has_no_addr() {
        let k = PeerKey::Interface(42);
        assert_eq!(k.addr(), None);
    }

    #[test]
    fn peer_key_orders_addr_before_interface() {
        // The variant ordering is part of the public contract because
        // PeerMap's iteration order depends on it (BTreeMap key order).
        // Keep Addr-keyed peers before Interface-keyed ones so existing
        // address-ordered iteration is preserved when no interface
        // peers exist.
        let addr: PeerKey = IpAddr::from(Ipv4Addr::new(255, 255, 255, 255)).into();
        let iface = PeerKey::Interface(0);
        assert!(addr < iface);
    }

    #[test]
    fn peer_origin_default_is_static() {
        assert_eq!(PeerOrigin::default(), PeerOrigin::Static);
    }
}
