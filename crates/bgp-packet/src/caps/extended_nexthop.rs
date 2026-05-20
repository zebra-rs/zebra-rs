use std::fmt;

use bytes::{BufMut, BytesMut};
use nom_derive::*;

use super::{CapCode, CapEmit};
use crate::{Afi, Safi};

/// One `(NLRI AFI, NLRI SAFI, Nexthop AFI)` tuple from the
/// Extended Next Hop Encoding capability (RFC 8950, formerly RFC 5549).
///
/// SAFI is encoded as 16 bits on the wire even though the IANA
/// registry assigns 8-bit values — the high octet is reserved and
/// MUST be zero per RFC 8950 §3. We model it as a separate
/// `res: u8` field so the auto-derived parser consumes the right
/// number of bytes and the typed [`Safi`] only holds the low octet.
#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord, Hash, NomBE)]
pub struct ExtendedNextHopValue {
    pub nlri_afi: Afi,
    res: u8,
    pub nlri_safi: Safi,
    pub nexthop_afi: Afi,
}

impl ExtendedNextHopValue {
    pub const WIRE_LEN: usize = 6;

    pub fn new(nlri_afi: Afi, nlri_safi: Safi, nexthop_afi: Afi) -> Self {
        Self {
            nlri_afi,
            res: 0,
            nlri_safi,
            nexthop_afi,
        }
    }
}

/// Extended Next Hop Encoding capability (RFC 8950, code 5).
///
/// Lets a speaker advertise that IPv4 (and other) NLRI may be sent
/// with an IPv6 next-hop — the foundation for BGP unnumbered.
/// Per RFC 8950 §3 the capability carries one or more tuples of
/// the form `(NLRI AFI, NLRI SAFI, Nexthop AFI)`.
#[derive(Debug, Default, PartialEq, Eq, Clone, NomBE)]
pub struct CapExtendedNextHop {
    pub values: Vec<ExtendedNextHopValue>,
}

impl CapExtendedNextHop {
    pub fn new(values: Vec<ExtendedNextHopValue>) -> Self {
        Self { values }
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// True if this capability advertises a v6 next-hop for IPv4
    /// unicast NLRI — the gating condition for emitting RFC 8950
    /// UPDATEs on a peer (e.g., an unnumbered BGP session).
    pub fn supports_v6_nexthop_for_ipv4_unicast(&self) -> bool {
        self.values.iter().any(|v| {
            v.nlri_afi == Afi::Ip && v.nlri_safi == Safi::Unicast && v.nexthop_afi == Afi::Ip6
        })
    }
}

impl CapEmit for CapExtendedNextHop {
    fn code(&self) -> CapCode {
        CapCode::ExtendedNextHop
    }

    fn len(&self) -> u8 {
        (self.values.len() * ExtendedNextHopValue::WIRE_LEN) as u8
    }

    fn emit_value(&self, buf: &mut BytesMut) {
        for v in &self.values {
            buf.put_u16(v.nlri_afi.into());
            buf.put_u8(0); // SAFI high octet, reserved per RFC 8950 §3
            buf.put_u8(v.nlri_safi.into());
            buf.put_u16(v.nexthop_afi.into());
        }
    }
}

impl fmt::Display for CapExtendedNextHop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Extended Next Hop: ")?;
        for (i, v) in self.values.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}/{} -> {}", v.nlri_afi, v.nlri_safi, v.nexthop_afi)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn parse_single_tuple_ipv4_over_ipv6() {
        // (AFI=1, SAFI=1, NextHopAFI=2) — IPv4 unicast over IPv6 nexthop.
        let wire = [0x00, 0x01, 0x00, 0x01, 0x00, 0x02];
        let (rest, cap) = CapExtendedNextHop::parse_be(&wire).unwrap();
        assert!(rest.is_empty());
        assert_eq!(cap.values.len(), 1);
        assert_eq!(cap.values[0].nlri_afi, Afi::Ip);
        assert_eq!(cap.values[0].nlri_safi, Safi::Unicast);
        assert_eq!(cap.values[0].nexthop_afi, Afi::Ip6);
        assert!(cap.supports_v6_nexthop_for_ipv4_unicast());
    }

    #[test]
    fn parse_multi_tuple_drains_buffer() {
        // Two tuples back-to-back.
        let wire = [
            0x00, 0x01, 0x00, 0x01, 0x00, 0x02, // IPv4/unicast -> v6
            0x00, 0x01, 0x00, 0x80, 0x00, 0x02, // IPv4/MPLS-VPN -> v6
        ];
        let (rest, cap) = CapExtendedNextHop::parse_be(&wire).unwrap();
        assert!(rest.is_empty());
        assert_eq!(cap.values.len(), 2);
        assert_eq!(cap.values[1].nlri_safi, Safi::MplsVpn);
    }

    #[test]
    fn parse_ignores_reserved_high_octet_of_safi() {
        // SAFI field high octet set to non-zero; per RFC 8950 it is
        // reserved and parsers MUST ignore it.
        let wire = [0x00, 0x01, 0xff, 0x01, 0x00, 0x02];
        let (_, cap) = CapExtendedNextHop::parse_be(&wire).unwrap();
        assert_eq!(cap.values[0].nlri_safi, Safi::Unicast);
    }

    #[test]
    fn emit_matches_len_and_round_trips() {
        let cap = CapExtendedNextHop::new(vec![
            ExtendedNextHopValue::new(Afi::Ip, Safi::Unicast, Afi::Ip6),
            ExtendedNextHopValue::new(Afi::Ip, Safi::MplsVpn, Afi::Ip6),
        ]);
        let mut buf = BytesMut::new();
        cap.emit_value(&mut buf);
        assert_eq!(buf.len() as u8, cap.len());

        let (rest, parsed) = CapExtendedNextHop::parse_be(&buf).unwrap();
        assert!(rest.is_empty());
        assert_eq!(parsed, cap);
    }

    #[test]
    fn cap_code_is_five() {
        let cap = CapExtendedNextHop::default();
        assert_eq!(u8::from(cap.code()), 5);
    }

    #[test]
    fn empty_cap_advertises_nothing() {
        let cap = CapExtendedNextHop::default();
        assert!(cap.is_empty());
        assert!(!cap.supports_v6_nexthop_for_ipv4_unicast());
        assert_eq!(cap.len(), 0);
    }
}
