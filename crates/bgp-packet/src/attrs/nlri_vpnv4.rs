use std::fmt;
use std::net::{IpAddr, Ipv4Addr};

use bytes::{BufMut, BytesMut};
use ipnet::Ipv4Net;
use nom::IResult;
use nom::bytes::complete::take;
use nom::error::{ErrorKind, make_error};
use nom::number::complete::{be_u8, be_u32};
use nom_derive::*;

use crate::{Afi, AttrType, Label, ParseNlri, RouteDistinguisher, Safi, nlri_psize};

use super::{AttrEmitter, AttrFlags, Ipv4Nlri};

#[derive(Debug, Clone)]
pub struct Vpnv4Nlri {
    pub label: Label,
    pub rd: RouteDistinguisher,
    pub nlri: Ipv4Nlri,
}

// Identity excludes the MPLS `label`: a VPNv4 route is identified by its
// (RD, prefix, path-id), and the label is a forwarding property attached
// to it (and may not be known at every comparison site — e.g. an
// advertise cache removal keyed by RD+prefix). Equality/hash over the
// label too would make `cache_remove_vpnv4` (which doesn't carry the
// label) fail to match the cached `send_vpnv4` entry.
impl PartialEq for Vpnv4Nlri {
    fn eq(&self, other: &Self) -> bool {
        self.rd == other.rd && self.nlri == other.nlri
    }
}

impl Eq for Vpnv4Nlri {}

impl std::hash::Hash for Vpnv4Nlri {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.rd.hash(state);
        self.nlri.hash(state);
    }
}

impl ParseNlri<Vpnv4Nlri> for Vpnv4Nlri {
    fn parse_nlri(input: &[u8], add_path: bool) -> IResult<&[u8], Vpnv4Nlri> {
        let (input, id) = if add_path { be_u32(input)? } else { (input, 0) };

        // MPLS Label (3 octets) + RD (8 octets) + IPv4 Prefix (0-4 octets).
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

        if psize > 4 {
            // Prefix size must be 0..=4.
            return Err(nom::Err::Error(make_error(input, ErrorKind::LengthValue)));
        }
        if psize > input.len() {
            // Prefix size must be same or smaller than remaining input buffer.
            return Err(nom::Err::Error(make_error(input, ErrorKind::LengthValue)));
        }

        // IPv4 prefix.
        let mut paddr = [0u8; 4];
        paddr[..psize].copy_from_slice(&input[..psize]);
        let (input, _) = take(psize).parse(input)?;
        let prefix = Ipv4Net::new(Ipv4Addr::from(paddr), plen).expect("Ipv4Net create error");

        let nlri = Ipv4Nlri { id, prefix };

        let vpnv4 = Vpnv4Nlri { label, rd, nlri };

        Ok((input, vpnv4))
    }
}

impl fmt::Display for Vpnv4Nlri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bos = if self.label.bos { "(BoS)" } else { "" };
        write!(
            f,
            "VPNv4 [{}]:[{}]{} label: {} {}",
            self.rd, self.nlri.id, self.nlri.prefix, self.label.label, bos,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Vpnv4Nexthop {
    pub rd: RouteDistinguisher,
    /// VPNv4 next-hop address. Normally IPv4 (RFC 4364), but RFC 8950 /
    /// RFC 9252 allow a VPN-IPv4 NLRI to be advertised with an IPv6
    /// next-hop (e.g. L3VPN over an SRv6 underlay), so this holds either.
    pub nhop: IpAddr,
}

impl fmt::Display for Vpnv4Nexthop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}]:{}", self.rd, self.nhop)
    }
}

/// Emit a VPNv4 MP_REACH next-hop field: the 1-octet length, the
/// 8-octet (always-zero) RD, then the next-hop address. RFC 4364 uses
/// an IPv4 next-hop (length 12); RFC 8950 / RFC 9252 allow an IPv6
/// next-hop (length 24) when a VPN-IPv4 NLRI rides, e.g., an SRv6
/// underlay.
fn emit_vpnv4_nexthop(buf: &mut BytesMut, nhop: &IpAddr) {
    let rd = [0u8; 8];
    match nhop {
        IpAddr::V4(a) => {
            buf.put_u8(12); // RD(8) + IPv4(4)
            buf.put(&rd[..]);
            buf.put(&a.octets()[..]);
        }
        IpAddr::V6(a) => {
            buf.put_u8(24); // RD(8) + IPv6(16)
            buf.put(&rd[..]);
            buf.put(&a.octets()[..]);
        }
    }
}

#[derive(Debug, Clone)]
pub struct Vpnv4Reach {
    pub snpa: u8,
    pub nhop: Vpnv4Nexthop,
    pub updates: Vec<Vpnv4Nlri>,
}

impl AttrEmitter for Vpnv4Reach {
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
        buf.put_u16(u16::from(Afi::Ip));
        buf.put_u8(u8::from(Safi::MplsVpn));
        // Nexthop
        // Nexthop: length + zero RD + address. Adapts to v4 (len 12)
        // or v6 (len 24, RFC 8950 / RFC 9252).
        emit_vpnv4_nexthop(buf, &self.nhop.nhop);
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

impl Vpnv4Reach {
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
        buf.put_u16(u16::from(Afi::Ip));
        buf.put_u8(u8::from(Safi::MplsVpn));
        // Nexthop
        // Nexthop: length + zero RD + address. Adapts to v4 (len 12)
        // or v6 (len 24, RFC 8950 / RFC 9252).
        emit_vpnv4_nexthop(buf, &self.nhop.nhop);
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

pub struct Vpnv4Unreach {
    pub withdraw: Vec<Vpnv4Nlri>,
}

impl AttrEmitter for Vpnv4Unreach {
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
        buf.put_u16(u16::from(Afi::Ip));
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
    use super::*;

    #[test]
    fn identity_ignores_label() {
        use std::collections::HashSet;
        let rd = RouteDistinguisher::default();
        let nlri = Ipv4Nlri {
            id: 0,
            prefix: "10.0.0.0/24".parse().unwrap(),
        };
        // Same (RD, prefix), different label → equal + same hash, so a
        // route advertised+cached under its real label is still found
        // and removed by `cache_remove_vpnv4`'s default-label key.
        let advertised = Vpnv4Nlri {
            label: Label::new(80, 0, true),
            rd,
            nlri: nlri.clone(),
        };
        let remove_key = Vpnv4Nlri {
            label: Label::default(),
            rd,
            nlri,
        };
        assert_eq!(advertised, remove_key);
        let mut set = HashSet::new();
        set.insert(advertised);
        assert!(set.remove(&remove_key), "default-label key matches");
    }

    #[test]
    fn nexthop_emits_ipv4_with_length_12() {
        let mut buf = BytesMut::new();
        emit_vpnv4_nexthop(&mut buf, &IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        // length(1) + RD(8) + IPv4(4)
        assert_eq!(buf.len(), 13);
        assert_eq!(buf[0], 12);
    }

    #[test]
    fn nexthop_emits_ipv6_with_length_24() {
        let addr: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        let mut buf = BytesMut::new();
        emit_vpnv4_nexthop(&mut buf, &IpAddr::V6(addr));
        // length(1) + RD(8) + IPv6(16)
        assert_eq!(buf.len(), 25);
        assert_eq!(buf[0], 24);
        assert_eq!(&buf[9..25], &addr.octets()[..]);
    }

    #[test]
    fn vpnv4_reach_round_trips_ipv6_nexthop() {
        // RFC 8950 / RFC 9252: a VPN-IPv4 NLRI advertised with an IPv6
        // next-hop (length 24). Emit the MP_REACH body then parse it
        // back and confirm the IPv6 next-hop survives.
        let addr: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        let reach = Vpnv4Reach {
            snpa: 0,
            nhop: Vpnv4Nexthop {
                rd: RouteDistinguisher::default(),
                nhop: IpAddr::V6(addr),
            },
            updates: vec![Vpnv4Nlri {
                label: Label::new(80, 0, true),
                rd: RouteDistinguisher::default(),
                nlri: Ipv4Nlri {
                    id: 0,
                    prefix: "192.168.5.0/24".parse().unwrap(),
                },
            }],
        };
        let mut buf = BytesMut::new();
        reach.emit(&mut buf);
        // `parse_nlri_opt` returns the input positioned at the NLRI
        // section (the `many0` remainder is discarded), so the parsed
        // `updates` carry the routes; the returned `rest` is not empty.
        let (_, parsed) = crate::MpReachAttr::parse_nlri_opt(&buf, None).expect("parse");
        match parsed {
            crate::MpReachAttr::Vpnv4(r) => {
                assert_eq!(r.nhop.nhop, IpAddr::V6(addr));
                assert_eq!(r.updates.len(), 1);
                assert_eq!(r.updates[0].nlri.prefix, "192.168.5.0/24".parse().unwrap());
            }
            _ => panic!("expected Vpnv4 reach"),
        }
    }

    #[test]
    fn vpnv4_reach_round_trips_ipv4_nexthop() {
        // The classic RFC 4364 shape (length 12) still round-trips.
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        let reach = Vpnv4Reach {
            snpa: 0,
            nhop: Vpnv4Nexthop {
                rd: RouteDistinguisher::default(),
                nhop: IpAddr::V4(addr),
            },
            updates: vec![Vpnv4Nlri {
                label: Label::new(80, 0, true),
                rd: RouteDistinguisher::default(),
                nlri: Ipv4Nlri {
                    id: 0,
                    prefix: "192.168.5.0/24".parse().unwrap(),
                },
            }],
        };
        let mut buf = BytesMut::new();
        reach.emit(&mut buf);
        let (_, parsed) = crate::MpReachAttr::parse_nlri_opt(&buf, None).expect("parse");
        match parsed {
            crate::MpReachAttr::Vpnv4(r) => assert_eq!(r.nhop.nhop, IpAddr::V4(addr)),
            _ => panic!("expected Vpnv4 reach"),
        }
    }
}
