use std::fmt;
use std::net::Ipv4Addr;

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

impl ParseNlri<Vpnv4Nlri> for Vpnv4Nlri {
    fn parse_nlri(input: &[u8], add_path: bool) -> IResult<&[u8], Vpnv4Nlri> {
        let (input, id) = if add_path { be_u32(input)? } else { (input, 0) };

        // MPLS Label (3 octets) + RD (8 octets) + IPv4 Prefix (0-4 octets).
        let (input, mut plen) = be_u8(input)?;

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
        if plen < 88 {
            // Prefix length must be >= 88.
            return Err(nom::Err::Error(make_error(input, ErrorKind::LengthValue)));
        }
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
    pub nhop: Ipv4Addr,
}

impl fmt::Display for Vpnv4Nexthop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}]:{}", self.rd, self.nhop)
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
        buf.put_u8(12); // Nexthop length.  RD(8)+IPv4 Nexthop(4);
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

impl Vpnv4Reach {
    pub fn attr_emit_mut(&mut self, buf: &mut BytesMut) {
        // Helper to emit the header based on length.
        let emit_header = |buf: &mut BytesMut, len: usize, extended: bool| {
            if extended {
                buf.put_u8(self.attr_flags().with_extended(true).into());
                buf.put_u8(self.attr_type().into());
                buf.put_u16(len as u16);
            } else {
                buf.put_u8(self.attr_flags().into());
                buf.put_u8(self.attr_type().into());
                buf.put_u8(len as u8);
            }
        };

        if let Some(len) = self.len() {
            // Length is known.
            let extended = len > 255;
            emit_header(buf, len, extended);
            self.emit_mut(buf);
        } else {
            // Buffer the attribute to determine its length.
            let mut attr_buf = BytesMut::new();
            self.emit_mut(&mut attr_buf);
            let len = attr_buf.len();
            let extended = len > 255;
            emit_header(buf, len, extended);
            buf.put(&attr_buf[..]);
        }
    }

    fn emit_mut(&mut self, buf: &mut BytesMut) {
        // AFI/SAFI.
        buf.put_u16(u16::from(Afi::Ip));
        buf.put_u8(u8::from(Safi::MplsVpn));
        // Nexthop
        buf.put_u8(12); // Nexthop length.  RD(8)+IPv4 Nexthop(4);
        // Nexthop RD.
        let rd = [0u8; 8];
        buf.put(&rd[..]);
        // Nexthop.
        buf.put(&self.nhop.nhop.octets()[..]);
        // SNPA
        buf.put_u8(0);
        // Prefix.
        while let Some(update) = self.updates.pop() {
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
