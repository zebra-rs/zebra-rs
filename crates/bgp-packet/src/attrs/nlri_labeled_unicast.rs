use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::{BufMut, BytesMut};
use ipnet::{Ipv4Net, Ipv6Net};
use nom::IResult;
use nom::bytes::complete::take;
use nom::error::{ErrorKind, make_error};
use nom::number::complete::{be_u8, be_u32};
use nom_derive::*;

use crate::{Ipv4Nlri, Ipv6Nlri, Label, ParseNlri, nlri_psize};

// RFC 3107 / RFC 8277 Labeled-Unicast NLRI:
//
//   +---------------------------+
//   | Length (1 octet, in bits) |
//   +---------------------------+
//   | Label (3 octets)          |  <- one or more; BGP-LU uses a single
//   +---------------------------+     label with the bottom-of-stack bit
//   | Prefix (variable)         |
//   +---------------------------+
//
// `Length` counts the label (24 bits) plus the prefix bits, so the
// encoding is identical to a VPNv4/VPNv6 NLRI (`nlri_vpnv4.rs`) minus
// the 8-octet Route Distinguisher: subtract 24, not 88.

/// IPv4 Labeled-Unicast NLRI (AFI 1, SAFI 4).
#[derive(Debug, Clone)]
pub struct Labelv4Nlri {
    pub label: Label,
    pub nlri: Ipv4Nlri,
}

// Identity excludes the MPLS `label`, mirroring `Vpnv4Nlri`: a route is
// identified by its (prefix, path-id); the label is a forwarding
// property attached to it and may not be known at every comparison site
// (e.g. an advertise-cache removal keyed only by prefix). Hashing/eq
// over the label too would make a default-label removal key miss the
// cached entry advertised under its real label.
impl PartialEq for Labelv4Nlri {
    fn eq(&self, other: &Self) -> bool {
        self.nlri == other.nlri
    }
}

impl Eq for Labelv4Nlri {}

impl std::hash::Hash for Labelv4Nlri {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.nlri.hash(state);
    }
}

impl Labelv4Nlri {
    /// Encode into an MP_REACH / MP_UNREACH NLRI list: optional 4-octet
    /// AddPath ID, 1-octet length (`prefix_len + 24`), the 3-octet
    /// label, then the significant prefix octets. Inverse of
    /// [`Labelv4Nlri::parse_nlri`].
    pub fn nlri_emit(&self, buf: &mut BytesMut) {
        if self.nlri.id != 0 {
            buf.put_u32(self.nlri.id);
        }
        let plen = self.nlri.prefix.prefix_len() + 24;
        buf.put_u8(plen);
        buf.put(&self.label.to_bytes()[..]);
        let psize = nlri_psize(self.nlri.prefix.prefix_len());
        buf.put(&self.nlri.prefix.addr().octets()[0..psize]);
    }
}

impl ParseNlri<Labelv4Nlri> for Labelv4Nlri {
    fn parse_nlri(input: &[u8], add_path: bool) -> IResult<&[u8], Labelv4Nlri> {
        let (input, id) = if add_path { be_u32(input)? } else { (input, 0) };

        // Length (bits) covers the 24-bit label plus the prefix.
        let (input, mut plen) = be_u8(input)?;
        if plen < 24 {
            return Err(nom::Err::Error(make_error(input, ErrorKind::LengthValue)));
        }
        let psize = nlri_psize(plen);
        if input.len() < psize {
            return Err(nom::Err::Error(make_error(input, ErrorKind::Eof)));
        }

        // 3-octet MPLS label. BGP-LU advertises a single label; a deeper
        // stack (BoS=0) is not emitted in practice, so we read exactly
        // one and treat the rest of the length as prefix.
        let (input, label) = take(3usize).parse(input)?;
        let label = Label::from(label);

        plen -= 24;
        let psize = nlri_psize(plen);
        if psize > 4 {
            return Err(nom::Err::Error(make_error(input, ErrorKind::LengthValue)));
        }
        if psize > input.len() {
            return Err(nom::Err::Error(make_error(input, ErrorKind::LengthValue)));
        }

        let mut paddr = [0u8; 4];
        paddr[..psize].copy_from_slice(&input[..psize]);
        let (input, _) = take(psize).parse(input)?;
        let prefix = Ipv4Net::new(Ipv4Addr::from(paddr), plen).expect("Ipv4Net create error");

        let nlri = Ipv4Nlri { id, prefix };
        Ok((input, Labelv4Nlri { label, nlri }))
    }
}

impl fmt::Display for Labelv4Nlri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bos = if self.label.bos { " (BoS)" } else { "" };
        write!(
            f,
            "{}:{} label: {}{}",
            self.nlri.id, self.nlri.prefix, self.label.label, bos,
        )
    }
}

/// IPv6 Labeled-Unicast NLRI (AFI 2, SAFI 4). Also carries 6PE routes
/// (RFC 4798) — the NLRI is identical; only the MP_REACH next-hop
/// differs (an IPv4-mapped IPv6 address), which is handled at emit time.
#[derive(Debug, Clone)]
pub struct Labelv6Nlri {
    pub label: Label,
    pub nlri: Ipv6Nlri,
}

impl PartialEq for Labelv6Nlri {
    fn eq(&self, other: &Self) -> bool {
        self.nlri == other.nlri
    }
}

impl Eq for Labelv6Nlri {}

impl std::hash::Hash for Labelv6Nlri {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.nlri.hash(state);
    }
}

impl Labelv6Nlri {
    /// See [`Labelv4Nlri::nlri_emit`]; identical layout over an IPv6
    /// prefix.
    pub fn nlri_emit(&self, buf: &mut BytesMut) {
        if self.nlri.id != 0 {
            buf.put_u32(self.nlri.id);
        }
        let plen = self.nlri.prefix.prefix_len() + 24;
        buf.put_u8(plen);
        buf.put(&self.label.to_bytes()[..]);
        let psize = nlri_psize(self.nlri.prefix.prefix_len());
        buf.put(&self.nlri.prefix.addr().octets()[0..psize]);
    }
}

impl ParseNlri<Labelv6Nlri> for Labelv6Nlri {
    fn parse_nlri(input: &[u8], add_path: bool) -> IResult<&[u8], Labelv6Nlri> {
        let (input, id) = if add_path { be_u32(input)? } else { (input, 0) };

        let (input, mut plen) = be_u8(input)?;
        if plen < 24 {
            return Err(nom::Err::Error(make_error(input, ErrorKind::LengthValue)));
        }
        let psize = nlri_psize(plen);
        if input.len() < psize {
            return Err(nom::Err::Error(make_error(input, ErrorKind::Eof)));
        }

        let (input, label) = take(3usize).parse(input)?;
        let label = Label::from(label);

        plen -= 24;
        let psize = nlri_psize(plen);
        if psize > 16 {
            return Err(nom::Err::Error(make_error(input, ErrorKind::LengthValue)));
        }
        if psize > input.len() {
            return Err(nom::Err::Error(make_error(input, ErrorKind::LengthValue)));
        }

        let mut paddr = [0u8; 16];
        paddr[..psize].copy_from_slice(&input[..psize]);
        let (input, _) = take(psize).parse(input)?;
        let prefix = Ipv6Net::new(Ipv6Addr::from(paddr), plen).expect("Ipv6Net create error");

        let nlri = Ipv6Nlri { id, prefix };
        Ok((input, Labelv6Nlri { label, nlri }))
    }
}

impl fmt::Display for Labelv6Nlri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bos = if self.label.bos { " (BoS)" } else { "" };
        write!(
            f,
            "{}:{} label: {}{}",
            self.nlri.id, self.nlri.prefix, self.label.label, bos,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;
    use crate::{MpReachAttr, MpUnreachAttr};

    fn v4(prefix: &str, label: u32) -> Labelv4Nlri {
        Labelv4Nlri {
            label: Label::new(label, 0, true),
            nlri: Ipv4Nlri {
                id: 0,
                prefix: prefix.parse().unwrap(),
            },
        }
    }

    fn v6(prefix: &str, label: u32) -> Labelv6Nlri {
        Labelv6Nlri {
            label: Label::new(label, 0, true),
            nlri: Ipv6Nlri {
                id: 0,
                prefix: prefix.parse().unwrap(),
            },
        }
    }

    #[test]
    fn labelv4_reach_round_trips() {
        let reach = MpReachAttr::Labelv4 {
            snpa: 0,
            nhop: "10.0.0.1".parse::<IpAddr>().unwrap(),
            updates: vec![v4("10.1.0.0/24", 24000), v4("10.2.0.0/16", 24001)],
        };
        let mut buf = BytesMut::new();
        reach.attr_emit(&mut buf);
        // Strip the 3-byte path-attribute header (flags + type + len).
        let (_rest, parsed) =
            MpReachAttr::parse_nlri_opt(&buf[3..], None).expect("Labelv4 MP_REACH must parse");
        match parsed {
            MpReachAttr::Labelv4 { nhop, updates, .. } => {
                assert_eq!(nhop, "10.0.0.1".parse::<IpAddr>().unwrap());
                assert_eq!(updates.len(), 2);
                assert_eq!(updates[0].nlri.prefix, "10.1.0.0/24".parse().unwrap());
                assert_eq!(updates[0].label.label, 24000);
                assert!(updates[0].label.bos);
                assert_eq!(updates[1].nlri.prefix, "10.2.0.0/16".parse().unwrap());
                assert_eq!(updates[1].label.label, 24001);
            }
            other => panic!("expected Labelv4, got {other:?}"),
        }
    }

    #[test]
    fn labelv4_reach_round_trips_ipv6_nexthop() {
        // RFC 8950: IPv4 labeled-unicast advertised with an IPv6 next-hop.
        let addr: IpAddr = "2001:db8::1".parse().unwrap();
        let reach = MpReachAttr::Labelv4 {
            snpa: 0,
            nhop: addr,
            updates: vec![v4("192.0.2.0/24", 100)],
        };
        let mut buf = BytesMut::new();
        reach.attr_emit(&mut buf);
        let (_rest, parsed) = MpReachAttr::parse_nlri_opt(&buf[3..], None).expect("parse");
        match parsed {
            MpReachAttr::Labelv4 { nhop, updates, .. } => {
                assert_eq!(nhop, addr);
                assert_eq!(updates[0].nlri.prefix, "192.0.2.0/24".parse().unwrap());
            }
            other => panic!("expected Labelv4, got {other:?}"),
        }
    }

    #[test]
    fn labelv6_reach_round_trips() {
        let addr: IpAddr = "2001:db8::1".parse().unwrap();
        let reach = MpReachAttr::Labelv6 {
            snpa: 0,
            nhop: addr,
            updates: vec![v6("2001:db8:1::/64", 24010)],
        };
        let mut buf = BytesMut::new();
        reach.attr_emit(&mut buf);
        let (_rest, parsed) =
            MpReachAttr::parse_nlri_opt(&buf[3..], None).expect("Labelv6 MP_REACH must parse");
        match parsed {
            MpReachAttr::Labelv6 { nhop, updates, .. } => {
                assert_eq!(nhop, addr);
                assert_eq!(updates.len(), 1);
                assert_eq!(updates[0].nlri.prefix, "2001:db8:1::/64".parse().unwrap());
                assert_eq!(updates[0].label.label, 24010);
            }
            other => panic!("expected Labelv6, got {other:?}"),
        }
    }

    #[test]
    fn labelv6_reach_6pe_ipv4_mapped_nexthop() {
        // RFC 4798 (6PE): an IPv4 next-hop is encoded as its IPv4-mapped
        // IPv6 form on the wire, and parses back as that IPv6 address.
        let reach = MpReachAttr::Labelv6 {
            snpa: 0,
            nhop: "10.0.0.1".parse::<IpAddr>().unwrap(),
            updates: vec![v6("2001:db8:5::/48", 500)],
        };
        let mut buf = BytesMut::new();
        reach.attr_emit(&mut buf);
        let (_rest, parsed) = MpReachAttr::parse_nlri_opt(&buf[3..], None).expect("parse");
        match parsed {
            MpReachAttr::Labelv6 { nhop, updates, .. } => {
                let mapped: IpAddr = "::ffff:10.0.0.1".parse().unwrap();
                assert_eq!(nhop, mapped);
                assert_eq!(updates[0].nlri.prefix, "2001:db8:5::/48".parse().unwrap());
            }
            other => panic!("expected Labelv6, got {other:?}"),
        }
    }

    #[test]
    fn labelv4_unreach_round_trips() {
        let unreach = MpUnreachAttr::Labelv4(vec![v4("10.9.0.0/24", 24099)]);
        let mut buf = BytesMut::new();
        unreach.attr_emit(&mut buf);
        let (_rest, parsed) =
            MpUnreachAttr::parse_nlri_opt(&buf[3..], None).expect("Labelv4 MP_UNREACH must parse");
        match parsed {
            MpUnreachAttr::Labelv4(w) => {
                assert_eq!(w.len(), 1);
                assert_eq!(w[0].nlri.prefix, "10.9.0.0/24".parse().unwrap());
            }
            other => panic!("expected Labelv4, got {other:?}"),
        }
    }

    #[test]
    fn labelv4_unreach_empty_is_eor() {
        let mut buf = BytesMut::new();
        MpUnreachAttr::Labelv4Eor.attr_emit(&mut buf);
        let (_rest, parsed) =
            MpUnreachAttr::parse_nlri_opt(&buf[3..], None).expect("Labelv4 EoR must parse");
        assert!(matches!(parsed, MpUnreachAttr::Labelv4Eor));
    }

    #[test]
    fn labelv6_unreach_round_trips() {
        let unreach = MpUnreachAttr::Labelv6(vec![v6("2001:db8:9::/56", 24199)]);
        let mut buf = BytesMut::new();
        unreach.attr_emit(&mut buf);
        let (_rest, parsed) =
            MpUnreachAttr::parse_nlri_opt(&buf[3..], None).expect("Labelv6 MP_UNREACH must parse");
        match parsed {
            MpUnreachAttr::Labelv6(w) => {
                assert_eq!(w.len(), 1);
                assert_eq!(w[0].nlri.prefix, "2001:db8:9::/56".parse().unwrap());
            }
            other => panic!("expected Labelv6, got {other:?}"),
        }
    }

    #[test]
    fn identity_ignores_label() {
        use std::collections::HashSet;
        // Same prefix, different label → equal + same hash, so a route
        // advertised+cached under its real label is still found and
        // removed by a default-label key.
        let advertised = v4("10.0.0.0/24", 80);
        let remove_key = v4("10.0.0.0/24", 0);
        assert_eq!(advertised, remove_key);
        let mut set = HashSet::new();
        set.insert(advertised);
        assert!(set.remove(&remove_key), "default-label key matches");
    }
}
