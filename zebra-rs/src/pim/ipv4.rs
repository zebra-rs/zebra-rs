//! The IPv4 [`PimAf`] marker and its pure address-family semantics.

use std::net::{IpAddr, Ipv4Addr};

use ipnet::{IpNet, Ipv4Net};

use crate::rib::Link;

use super::af::PimAf;
use super::mroute::Mrt4;

/// IPv4 address-family marker. The ordering / hash / default derives
/// are what let `#[derive(Ord, Hash, Default)]` on the generic data
/// types (which add an `A: …` bound) resolve for `A = Ipv4`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Ipv4;

impl PimAf for Ipv4 {
    type Addr = Ipv4Addr;
    type Prefix = Ipv4Net;
    type Fp = Mrt4;

    const ALL_PIM_ROUTERS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 13);
    const GENERAL_QUERY_DST: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 1);

    fn is_unspecified(a: Ipv4Addr) -> bool {
        a.is_unspecified()
    }

    fn from_ip(ip: IpAddr) -> Option<Ipv4Addr> {
        match ip {
            IpAddr::V4(a) => Some(a),
            IpAddr::V6(_) => None,
        }
    }

    fn to_ip(a: Ipv4Addr) -> IpAddr {
        IpAddr::V4(a)
    }

    fn prefix_from_ipnet(net: IpNet) -> Option<Ipv4Net> {
        match net {
            IpNet::V4(p) => Some(p),
            IpNet::V6(_) => None,
        }
    }

    fn link_prefixes(link: &Link) -> Vec<Ipv4Net> {
        link.addr4
            .iter()
            .filter_map(|a| Self::prefix_from_ipnet(a.addr))
            .collect()
    }

    // `Ipv4Net::new_assert` is a const fn, so the canonical ranges are
    // true associated consts. `232.0.0.0/8` is the RFC 4607 SSM range;
    // `224.0.0.0/4` is the RFC 7761 RP-eligible group range.
    const DEFAULT_SSM_RANGE: Ipv4Net = Ipv4Net::new_assert(Ipv4Addr::new(232, 0, 0, 0), 8);
    const DEFAULT_RP_RANGE: Ipv4Net = Ipv4Net::new_assert(Ipv4Addr::new(224, 0, 0, 0), 4);

    fn is_multicast(a: Ipv4Addr) -> bool {
        a.is_multicast()
    }

    fn is_ssm(a: Ipv4Addr) -> bool {
        Self::DEFAULT_SSM_RANGE.contains(&a)
    }

    fn is_reserved_group(a: Ipv4Addr) -> bool {
        // 224.0.0.0/24 — the link-local control scope, never forwarded.
        a.octets()[..3] == [224, 0, 0]
    }

    fn prefix_new(addr: Ipv4Addr, len: u8) -> Option<Ipv4Net> {
        Ipv4Net::new(addr, len).ok()
    }

    fn prefix_contains(p: &Ipv4Net, a: &Ipv4Addr) -> bool {
        p.contains(a)
    }

    fn prefix_len(p: &Ipv4Net) -> u8 {
        p.prefix_len()
    }

    fn prefix_addr(p: &Ipv4Net) -> Ipv4Addr {
        p.addr()
    }

    fn null_register_payload(src: Ipv4Addr, grp: Ipv4Addr) -> Vec<u8> {
        // A minimal inner IPv4 header naming (S,G).
        let mut header = vec![0u8; 20];
        header[0] = 0x45;
        header[3] = 20; // total length
        header[8] = 64; // ttl
        header[12..16].copy_from_slice(&src.octets());
        header[16..20].copy_from_slice(&grp.octets());
        header
    }

    fn register_inner_sg(data: &[u8]) -> Option<(Ipv4Addr, Ipv4Addr)> {
        // The inner packet (or Null-Register dummy) is an IPv4 header:
        // version nibble 4, (S,G) at the source/destination fields.
        if data.len() < 20 || data[0] >> 4 != 4 {
            return None;
        }
        let src = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
        let grp = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
        Some((src, grp))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multicast_classification() {
        assert!(Ipv4::is_multicast(Ipv4Addr::new(239, 1, 1, 1)));
        assert!(Ipv4::is_multicast(Ipv4Addr::new(232, 0, 0, 5)));
        assert!(!Ipv4::is_multicast(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn ssm_range_is_232_slash_8() {
        assert!(Ipv4::is_ssm(Ipv4Addr::new(232, 0, 0, 1)));
        assert!(Ipv4::is_ssm(Ipv4Addr::new(232, 255, 255, 255)));
        // ASM groups and non-multicast are not SSM.
        assert!(!Ipv4::is_ssm(Ipv4Addr::new(239, 1, 1, 1)));
        assert!(!Ipv4::is_ssm(Ipv4Addr::new(233, 0, 0, 1)));
        assert!(!Ipv4::is_ssm(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn reserved_group_is_link_local_control_scope() {
        assert!(Ipv4::is_reserved_group(Ipv4Addr::new(224, 0, 0, 1)));
        assert!(Ipv4::is_reserved_group(Ipv4Addr::new(224, 0, 0, 13)));
        assert!(!Ipv4::is_reserved_group(Ipv4Addr::new(224, 0, 1, 1)));
        assert!(!Ipv4::is_reserved_group(Ipv4Addr::new(239, 1, 1, 1)));
    }

    #[test]
    fn prefix_ops() {
        let p = Ipv4::prefix_new(Ipv4Addr::new(10, 1, 0, 0), 16).unwrap();
        assert!(Ipv4::prefix_contains(&p, &Ipv4Addr::new(10, 1, 2, 3)));
        assert!(!Ipv4::prefix_contains(&p, &Ipv4Addr::new(10, 2, 0, 1)));
        assert_eq!(Ipv4::prefix_len(&p), 16);
        assert_eq!(Ipv4::prefix_addr(&p), Ipv4Addr::new(10, 1, 0, 0));
        assert!(Ipv4::prefix_new(Ipv4Addr::new(10, 0, 0, 0), 33).is_none());
    }

    #[test]
    fn default_ranges() {
        assert_eq!(Ipv4::prefix_len(&Ipv4::DEFAULT_SSM_RANGE), 8);
        assert_eq!(
            Ipv4::prefix_addr(&Ipv4::DEFAULT_SSM_RANGE),
            Ipv4Addr::new(232, 0, 0, 0)
        );
        assert_eq!(Ipv4::prefix_len(&Ipv4::DEFAULT_RP_RANGE), 4);
        assert_eq!(
            Ipv4::prefix_addr(&Ipv4::DEFAULT_RP_RANGE),
            Ipv4Addr::new(224, 0, 0, 0)
        );
    }
}
