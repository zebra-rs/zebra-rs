//! The IPv4 [`PimAf`] marker and its pure address-family semantics.

use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

use super::af::PimAf;

/// IPv4 address-family marker. The ordering / hash / default derives
/// are what let `#[derive(Ord, Hash, Default)]` on the generic data
/// types (which add an `A: …` bound) resolve for `A = Ipv4`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Ipv4;

impl PimAf for Ipv4 {
    type Addr = Ipv4Addr;
    type Prefix = Ipv4Net;

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
