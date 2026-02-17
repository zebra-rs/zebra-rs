use std::net::{IpAddr, Ipv4Addr};

use bytes::{BufMut, BytesMut};
use nom::IResult;
use nom::error::{ErrorKind, make_error};
use nom::number::complete::{be_u8, be_u32};
use nom_derive::*;

use crate::{Afi, ExtCommunityValue, ParseNlri, Safi};

use super::{AttrEmitter, AttrFlags, AttrType};

#[derive(Debug, Clone)]
pub struct Rtcv4 {
    pub id: u32,
    pub asn: u32,
    pub rt: ExtCommunityValue,
}

impl ParseNlri<Rtcv4> for Rtcv4 {
    fn parse_nlri(input: &[u8], addpath: bool) -> IResult<&[u8], Rtcv4> {
        let (input, id) = if addpath { be_u32(input)? } else { (input, 0) };
        let (input, plen) = be_u8(input)?;
        if plen != 96 {
            return Err(nom::Err::Error(make_error(input, ErrorKind::LengthValue)));
        }
        let (input, asn) = be_u32(input)?;
        let (input, rt) = ExtCommunityValue::parse_be(input)?;
        let nlri = Rtcv4 { id, asn, rt };
        Ok((input, nlri))
    }
}

#[derive(Debug, Clone)]
pub struct Rtcv4Reach {
    pub snpa: u8,
    pub nhop: IpAddr,
    pub updates: Vec<Rtcv4>,
}

impl AttrEmitter for Rtcv4Reach {
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
        buf.put_u8(u8::from(Safi::Rtc));
        // Nexthop
        buf.put_u8(4); // Nexthop length. IPv4.
        // Nexthop.
        let nhop = Ipv4Addr::UNSPECIFIED;
        buf.put(&nhop.octets()[..]);
        // SNPA
        buf.put_u8(0);
        // Prefix.
        if self.updates.is_empty() {
            // XXX AddPath?
            // buf.put_u32(1);
            // Zero prefix length for default.
            buf.put_u8(0);
        }
    }
}

pub struct Rtcv4Unreach {
    pub withdraw: Vec<Rtcv4>,
}

impl AttrEmitter for Rtcv4Unreach {
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
        buf.put_u8(u8::from(Safi::Rtc));
        // Prefix.
        for withdraw in self.withdraw.iter() {
            // AddPath
            if withdraw.id != 0 {
                buf.put_u32(withdraw.id);
            }
            // RD
            withdraw.rt.encode(buf);
        }
    }
}
