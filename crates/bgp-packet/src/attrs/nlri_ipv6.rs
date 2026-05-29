use std::net::Ipv6Addr;

use bytes::{BufMut, BytesMut};
use ipnet::Ipv6Net;
use nom::IResult;
use nom::bytes::complete::take;
use nom::error::{ErrorKind, make_error};
use nom::number::complete::{be_u8, be_u32};
use nom_derive::*;

use crate::{ParseBe, ParseNlri, nlri_psize};

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct Ipv6Nlri {
    pub id: u32,
    pub prefix: Ipv6Net,
}

impl Ipv6Nlri {
    /// Encode this NLRI into an MP_REACH / MP_UNREACH NLRI list:
    /// an optional 4-octet AddPath ID (only when `id != 0`), the
    /// 1-octet prefix length, then the `ceil(plen / 8)` significant
    /// prefix octets. Inverse of [`Ipv6Nlri::parse_nlri`].
    pub fn nlri_emit(&self, buf: &mut BytesMut) {
        if self.id != 0 {
            buf.put_u32(self.id);
        }
        let plen = self.prefix.prefix_len();
        buf.put_u8(plen);
        let psize = nlri_psize(plen);
        buf.put(&self.prefix.addr().octets()[0..psize]);
    }
}

impl ParseNlri<Ipv6Nlri> for Ipv6Nlri {
    fn parse_nlri(input: &[u8], add_path: bool) -> IResult<&[u8], Ipv6Nlri> {
        let (input, id) = if add_path { be_u32(input)? } else { (input, 0) };
        let (input, plen) = be_u8(input)?;
        if plen > 128 {
            return Err(nom::Err::Error(make_error(input, ErrorKind::Verify)));
        }
        let psize = nlri_psize(plen);
        if input.len() < psize {
            return Err(nom::Err::Error(make_error(input, ErrorKind::Eof)));
        }
        let mut paddr = [0u8; 16];
        paddr[..psize].copy_from_slice(&input[..psize]);
        let (input, _) = take(psize).parse(input)?;
        let prefix = Ipv6Net::new(Ipv6Addr::from(paddr), plen).expect("Ipv6Net create error");
        let nlri = Ipv6Nlri { id, prefix };
        Ok((input, nlri))
    }
}

impl ParseBe<Ipv6Net> for Ipv6Net {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Ipv6Net> {
        let (input, plen) = be_u8(input)?;
        if plen > 128 {
            return Err(nom::Err::Error(make_error(input, ErrorKind::Verify)));
        }
        let psize = nlri_psize(plen);
        if input.len() < psize {
            return Err(nom::Err::Error(make_error(input, ErrorKind::Eof)));
        }
        let mut paddr = [0u8; 16];
        paddr[..psize].copy_from_slice(&input[..psize]);
        let (input, _) = take(psize).parse(input)?;
        let prefix = Ipv6Net::new(Ipv6Addr::from(paddr), plen).expect("Ipv6Net create error");

        Ok((input, prefix))
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use bytes::BytesMut;

    use super::Ipv6Nlri;
    use crate::{MpReachAttr, MpUnreachAttr, ParseBe, ParseNlri};
    use ipnet::Ipv6Net;

    fn nlri(prefix: &str) -> Ipv6Nlri {
        Ipv6Nlri {
            id: 0,
            prefix: prefix.parse().unwrap(),
        }
    }

    #[test]
    fn reach_emit_round_trips_through_parser() {
        // Build an MP_REACH IPv6 unicast attr, emit it (header +
        // value), strip the 3-byte path-attribute header, and parse
        // the value back. The parser returns the pointer at the start
        // of the NLRI section (post-`many0` remainder discarded, as on
        // every MP_REACH path), so the `updates` are the contract.
        let reach = MpReachAttr::Ipv6 {
            snpa: 0,
            nhop: "2001:db8::1".parse::<IpAddr>().unwrap(),
            updates: vec![nlri("2001:db8:1::/64"), nlri("2001:db8:2::/48")],
        };
        let mut buf = BytesMut::new();
        reach.attr_emit(&mut buf);
        // flags(1) + type(1) + len(1) header.
        let (_rest, parsed) =
            MpReachAttr::parse_nlri_opt(&buf[3..], None).expect("IPv6 MP_REACH must parse");
        match parsed {
            MpReachAttr::Ipv6 { nhop, updates, .. } => {
                assert_eq!(nhop, "2001:db8::1".parse::<IpAddr>().unwrap());
                assert_eq!(updates.len(), 2);
                assert_eq!(
                    updates[0].prefix,
                    "2001:db8:1::/64".parse::<Ipv6Net>().unwrap()
                );
                assert_eq!(
                    updates[1].prefix,
                    "2001:db8:2::/48".parse::<Ipv6Net>().unwrap()
                );
            }
            other => panic!("expected Ipv6, got {other:?}"),
        }
    }

    #[test]
    fn unreach_emit_round_trips_through_parser() {
        let unreach = MpUnreachAttr::Ipv6Nlri(vec![nlri("2001:db8:3::/56")]);
        let mut buf = BytesMut::new();
        unreach.attr_emit(&mut buf);
        let (_rest, parsed) =
            MpUnreachAttr::parse_nlri_opt(&buf[3..], None).expect("IPv6 MP_UNREACH must parse");
        match parsed {
            MpUnreachAttr::Ipv6Nlri(w) => {
                assert_eq!(w.len(), 1);
                assert_eq!(w[0].prefix, "2001:db8:3::/56".parse::<Ipv6Net>().unwrap());
            }
            other => panic!("expected Ipv6Nlri, got {other:?}"),
        }
    }

    #[test]
    fn unreach_emit_empty_is_eor() {
        let mut buf = BytesMut::new();
        MpUnreachAttr::Ipv6Eor.attr_emit(&mut buf);
        let (_rest, parsed) =
            MpUnreachAttr::parse_nlri_opt(&buf[3..], None).expect("IPv6 EoR must parse");
        assert!(matches!(parsed, MpUnreachAttr::Ipv6Eor));
    }

    #[test]
    fn parse_nlri_rejects_prefixlen_over_128() {
        let input = [
            129, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert!(Ipv6Nlri::parse_nlri(&input, false).is_err());
    }

    #[test]
    fn parse_ipv6net_rejects_prefixlen_over_128() {
        let input = [
            129, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert!(Ipv6Net::parse_be(&input).is_err());
    }
}
