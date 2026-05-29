use std::fmt;
use std::net::Ipv6Addr;

use bytes::{BufMut, BytesMut};
use ipnet::Ipv6Net;
use nom::IResult;
use nom::bytes::complete::take;
use nom::error::{ErrorKind, make_error};
use nom::number::complete::{be_u8, be_u32};
use nom_derive::*;

use crate::{Afi, AttrType, Label, ParseNlri, RouteDistinguisher, Safi, nlri_psize};

use super::{AttrEmitter, AttrFlags, Ipv6Nlri};

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct Vpnv6Nlri {
    pub label: Label,
    pub rd: RouteDistinguisher,
    pub nlri: Ipv6Nlri,
}

impl ParseNlri<Vpnv6Nlri> for Vpnv6Nlri {
    fn parse_nlri(input: &[u8], add_path: bool) -> IResult<&[u8], Vpnv6Nlri> {
        let (input, id) = if add_path { be_u32(input)? } else { (input, 0) };

        // MPLS Label (3 octets) + RD (8 octets) + IPv6 Prefix (0-16 octets).
        let (input, mut plen) = be_u8(input)?;

        // Validate plen >= 88 (label 24 + RD 64) before parsing label and RD.
        if plen < 88 {
            return Err(nom::Err::Error(make_error(input, ErrorKind::LengthValue)));
        }

        let psize = nlri_psize(plen);
        if input.len() < psize {
            return Err(nom::Err::Error(make_error(input, ErrorKind::Eof)));
        }
        // MPLS Label.
        let (input, label) = take(3usize).parse(input)?;
        let label = Label::from(label);

        // RD.
        let (input, rd) = RouteDistinguisher::parse_be(input)?;

        // Adjust plen to MPLS Label and Route Distinguisher.
        plen -= 88;
        let psize = nlri_psize(plen);

        if psize > 16 {
            // Prefix size must be 0..=16 (the `> 16` bound also rejects
            // any `plen > 128`, keeping `Ipv6Net::new` below infallible).
            return Err(nom::Err::Error(make_error(input, ErrorKind::LengthValue)));
        }
        if psize > input.len() {
            // Prefix size must be same or smaller than remaining input buffer.
            return Err(nom::Err::Error(make_error(input, ErrorKind::LengthValue)));
        }

        // IPv6 prefix.
        let mut paddr = [0u8; 16];
        paddr[..psize].copy_from_slice(&input[..psize]);
        let (input, _) = take(psize).parse(input)?;
        let prefix = Ipv6Net::new(Ipv6Addr::from(paddr), plen).expect("Ipv6Net create error");

        let nlri = Ipv6Nlri { id, prefix };

        let vpnv6 = Vpnv6Nlri { label, rd, nlri };

        Ok((input, vpnv6))
    }
}

impl fmt::Display for Vpnv6Nlri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bos = if self.label.bos { "(BoS)" } else { "" };
        write!(
            f,
            "VPNv6 [{}]:[{}]{} label: {} {}",
            self.rd, self.nlri.id, self.nlri.prefix, self.label.label, bos,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Vpnv6Nexthop {
    pub rd: RouteDistinguisher,
    pub nhop: Ipv6Addr,
}

impl fmt::Display for Vpnv6Nexthop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}]:{}", self.rd, self.nhop)
    }
}

#[derive(Debug, Clone)]
pub struct Vpnv6Reach {
    pub snpa: u8,
    pub nhop: Vpnv6Nexthop,
    pub updates: Vec<Vpnv6Nlri>,
}

impl AttrEmitter for Vpnv6Reach {
    fn attr_type(&self) -> AttrType {
        AttrType::MpReachNlri
    }

    fn attr_flags(&self) -> AttrFlags {
        AttrFlags::new().with_optional(true)
    }

    fn len(&self) -> Option<usize> {
        None
    }

    fn emit(&self, buf: &mut BytesMut) {
        // AFI/SAFI.
        buf.put_u16(u16::from(Afi::Ip6));
        buf.put_u8(u8::from(Safi::MplsVpn));
        // Nexthop
        buf.put_u8(24); // Nexthop length.  RD(8)+IPv6 Nexthop(16);
        // Nexthop RD.
        let rd = [0u8; 8];
        buf.put(&rd[..]);
        // Nexthop.
        buf.put(&self.nhop.nhop.octets()[..]);
        // SNPA
        buf.put_u8(0);
        // Prefix.
        for update in self.updates.iter() {
            // AddPath
            if update.nlri.id != 0 {
                buf.put_u32(update.nlri.id);
            }
            // Plen
            let plen = update.nlri.prefix.prefix_len() + 88;
            buf.put_u8(plen);
            // Label
            buf.put(&update.label.to_bytes()[..]);
            // RD
            buf.put_u16(update.rd.typ as u16);
            buf.put(&update.rd.val[..]);
            // Prefix
            let plen = nlri_psize(update.nlri.prefix.prefix_len());
            buf.put(&update.nlri.prefix.addr().octets()[0..plen]);
        }
    }
}

impl Vpnv6Reach {
    pub fn attr_emit_mut(&mut self, buf: &mut BytesMut, max_size: usize) {
        let flags = self.attr_flags();
        let attr_type = self.attr_type();
        let emit_header = |buf: &mut BytesMut, len: usize, extended: bool| {
            if extended {
                buf.put_u8(flags.with_extended(true).into());
                buf.put_u8(attr_type.into());
                buf.put_u16(len as u16);
            } else {
                buf.put_u8(flags.into());
                buf.put_u8(attr_type.into());
                buf.put_u8(len as u8);
            }
        };

        if let Some(len) = self.len() {
            // Length is known.
            let extended = len > 255;
            emit_header(buf, len, extended);
            self.emit_mut(buf, max_size);
        } else {
            // Buffer the attribute to determine its length.
            let mut attr_buf = BytesMut::new();
            self.emit_mut(&mut attr_buf, max_size);
            let len = attr_buf.len();
            let extended = len > 255;
            emit_header(buf, len, extended);
            buf.put(&attr_buf[..]);
        }
    }

    fn emit_mut(&mut self, buf: &mut BytesMut, max_size: usize) {
        // AFI/SAFI.
        buf.put_u16(u16::from(Afi::Ip6));
        buf.put_u8(u8::from(Safi::MplsVpn));
        // Nexthop
        buf.put_u8(24); // Nexthop length.  RD(8)+IPv6 Nexthop(16);
        // Nexthop RD.
        let rd = [0u8; 8];
        buf.put(&rd[..]);
        // Nexthop.
        buf.put(&self.nhop.nhop.octets()[..]);
        // SNPA
        buf.put_u8(0);

        // Prefix.
        while let Some(update) = self.updates.pop() {
            // Need to check remaining buffer size.
            let mut nlri_len: usize = 0;
            if update.nlri.id != 0 {
                nlri_len += 4;
            }
            // Plen.
            nlri_len += 1;
            // Label.
            nlri_len += 4;
            // RD.
            nlri_len += 8;
            // Prefix.
            nlri_len += nlri_psize(update.nlri.prefix.prefix_len());

            if nlri_len + buf.len() > max_size {
                self.updates.push(update);
                return;
            }

            // AddPath
            if update.nlri.id != 0 {
                buf.put_u32(update.nlri.id);
            }
            // Plen
            let plen = update.nlri.prefix.prefix_len() + 88;
            buf.put_u8(plen);
            // Label
            buf.put(&update.label.to_bytes()[..]);
            // RD
            buf.put_u16(update.rd.typ as u16);
            buf.put(&update.rd.val[..]);
            // Prefix
            let plen = nlri_psize(update.nlri.prefix.prefix_len());
            buf.put(&update.nlri.prefix.addr().octets()[0..plen]);
        }
    }
}

pub struct Vpnv6Unreach {
    pub withdraw: Vec<Vpnv6Nlri>,
}

impl AttrEmitter for Vpnv6Unreach {
    fn attr_type(&self) -> AttrType {
        AttrType::MpUnreachNlri
    }

    fn attr_flags(&self) -> AttrFlags {
        AttrFlags::new().with_optional(true)
    }

    fn len(&self) -> Option<usize> {
        None
    }

    fn emit(&self, buf: &mut BytesMut) {
        // AFI/SAFI.
        buf.put_u16(u16::from(Afi::Ip6));
        buf.put_u8(u8::from(Safi::MplsVpn));
        // Prefix.
        for withdraw in self.withdraw.iter() {
            // AddPath
            if withdraw.nlri.id != 0 {
                buf.put_u32(withdraw.nlri.id);
            }
            // Plen
            let plen = withdraw.nlri.prefix.prefix_len() + 88;
            buf.put_u8(plen);
            // Label
            buf.put(&withdraw.label.to_bytes()[..]);
            // RD
            buf.put_u16(withdraw.rd.typ as u16);
            buf.put(&withdraw.rd.val[..]);
            // Prefix
            let plen = nlri_psize(withdraw.nlri.prefix.prefix_len());
            buf.put(&withdraw.nlri.prefix.addr().octets()[0..plen]);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::Ipv6Nlri;

    fn nlri(rd: &str, prefix: &str, label: u32) -> Vpnv6Nlri {
        Vpnv6Nlri {
            label: Label {
                label,
                exp: 0,
                bos: true,
            },
            rd: RouteDistinguisher::from_str(rd).unwrap(),
            nlri: Ipv6Nlri {
                id: 0,
                prefix: prefix.parse().unwrap(),
            },
        }
    }

    #[test]
    fn reach_round_trips_through_parser() {
        // Emit a Vpnv6Reach, strip the attribute header, and parse the
        // value back through the MP_REACH VPNv6 path.
        let reach = Vpnv6Reach {
            snpa: 0,
            nhop: Vpnv6Nexthop {
                rd: RouteDistinguisher::from_str("65000:1").unwrap(),
                nhop: "2001:db8::1".parse().unwrap(),
            },
            updates: vec![
                nlri("65000:1", "2001:db8:1::/64", 100),
                nlri("65000:1", "2001:db8:2::/48", 200),
            ],
        };

        let mut buf = BytesMut::new();
        reach.emit(&mut buf);

        // emit() writes the MP_REACH value (AFI/SAFI/nexthop/SNPA/NLRI)
        // without the path-attribute header, which is exactly what
        // `parse_nlri_opt` expects after MpReachHeader. Note the
        // MP_REACH parser returns the input positioned at the start of
        // the NLRI section (the post-`many0` remainder is discarded, as
        // on the Vpnv4 path), so the returned pointer is intentionally
        // non-empty — the parsed `updates` are the contract here.
        let (_rest, parsed) =
            crate::MpReachAttr::parse_nlri_opt(&buf, None).expect("VPNv6 MP_REACH must parse");

        match parsed {
            crate::MpReachAttr::Vpnv6(r) => {
                assert_eq!(r.nhop.nhop, "2001:db8::1".parse::<Ipv6Addr>().unwrap());
                assert_eq!(r.updates.len(), 2);
                // Order is preserved by the iterator-based emit().
                assert_eq!(
                    r.updates[0].nlri.prefix,
                    "2001:db8:1::/64".parse::<Ipv6Net>().unwrap()
                );
                assert_eq!(r.updates[0].label.label, 100);
                assert_eq!(
                    r.updates[0].rd,
                    RouteDistinguisher::from_str("65000:1").unwrap()
                );
                assert_eq!(
                    r.updates[1].nlri.prefix,
                    "2001:db8:2::/48".parse::<Ipv6Net>().unwrap()
                );
                assert_eq!(r.updates[1].label.label, 200);
            }
            other => panic!("expected Vpnv6, got {other:?}"),
        }
    }

    #[test]
    fn unreach_round_trips_through_parser() {
        let unreach = Vpnv6Unreach {
            withdraw: vec![nlri("65001:7", "2001:db8:3::/56", 0)],
        };
        let mut buf = BytesMut::new();
        unreach.emit(&mut buf);

        let (rest, parsed) =
            crate::MpUnreachAttr::parse_nlri_opt(&buf, None).expect("VPNv6 MP_UNREACH must parse");
        assert!(rest.is_empty());
        match parsed {
            crate::MpUnreachAttr::Vpnv6(w) => {
                assert_eq!(w.len(), 1);
                assert_eq!(
                    w[0].nlri.prefix,
                    "2001:db8:3::/56".parse::<Ipv6Net>().unwrap()
                );
                assert_eq!(w[0].rd, RouteDistinguisher::from_str("65001:7").unwrap());
            }
            other => panic!("expected Vpnv6, got {other:?}"),
        }
    }

    #[test]
    fn unreach_empty_is_eor() {
        // AFI(Ip6) + SAFI(MplsVpn) with no NLRI bytes is an EoR marker.
        let mut buf = BytesMut::new();
        buf.put_u16(u16::from(Afi::Ip6));
        buf.put_u8(u8::from(Safi::MplsVpn));
        let (_rest, parsed) =
            crate::MpUnreachAttr::parse_nlri_opt(&buf, None).expect("EoR must parse");
        assert!(matches!(parsed, crate::MpUnreachAttr::Vpnv6Eor));
    }

    #[test]
    fn parse_rejects_plen_below_label_rd_floor() {
        // plen < 88 (less than label+RD) must be rejected before the
        // label/RD reads.
        let input = [0x00u8, 0x00, 0x00, 0x00];
        assert!(Vpnv6Nlri::parse_nlri(&input, false).is_err());
    }
}
