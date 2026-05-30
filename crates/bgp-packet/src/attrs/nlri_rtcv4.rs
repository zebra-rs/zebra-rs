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
        // NLRI.
        if self.updates.is_empty() {
            // Zero prefix length: the default RT membership of
            // RFC 4684 §3.2 — "interested in all Route Targets".
            buf.put_u8(0);
        } else {
            // Each membership NLRI is a 96-bit prefix: the 4-octet
            // origin-AS followed by the 8-octet Route Target extended
            // community (RFC 4684 §4). Mirrors `Rtcv4::parse_nlri`,
            // which reads the AddPath id (when negotiated), the
            // prefix length, the AS, then the RT.
            for update in self.updates.iter() {
                if update.id != 0 {
                    buf.put_u32(update.id);
                }
                buf.put_u8(96);
                buf.put_u32(update.asn);
                update.rt.encode(buf);
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    // The MP_REACH header `Rtcv4Reach::emit` writes before the NLRI:
    // AFI(2) + SAFI(1) + nexthop-length(1) + nexthop(4) + SNPA(1).
    const HEADER_LEN: usize = 9;

    #[test]
    fn membership_emit_roundtrips() {
        // Route Target 100:1 marked as an RT (sub-type 0x02).
        let rt = ExtCommunityValue {
            high_type: 0x00,
            low_type: 0x02,
            val: [0x00, 0x64, 0x00, 0x00, 0x00, 0x01],
        };
        let reach = Rtcv4Reach {
            snpa: 0,
            nhop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            updates: vec![Rtcv4 {
                id: 0,
                asn: 65001,
                rt: rt.clone(),
            }],
        };

        let mut buf = BytesMut::new();
        reach.emit(&mut buf);

        let (rest, parsed) = Rtcv4::parse_nlri(&buf[HEADER_LEN..], false).unwrap();
        assert!(rest.is_empty());
        assert_eq!(parsed.asn, 65001);
        assert_eq!(parsed.rt, rt);
    }

    #[test]
    fn empty_membership_emits_zero_length_default() {
        let reach = Rtcv4Reach {
            snpa: 0,
            nhop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            updates: vec![],
        };

        let mut buf = BytesMut::new();
        reach.emit(&mut buf);

        // Header followed by a single zero prefix-length octet (the
        // RFC 4684 §3.2 default "all Route Targets" membership).
        assert_eq!(buf.len(), HEADER_LEN + 1);
        assert_eq!(buf[HEADER_LEN], 0);
    }
}
