use std::net::{IpAddr, Ipv6Addr};

use bytes::{BufMut, BytesMut};
use nom::IResult;

use crate::{Afi, ExtCommunityValue, ParseNlri, Safi};

use super::nlri_rtcv4::{RTC_PLEN_MAX, emit_rtc_membership, parse_rtc_membership};
use super::{AttrEmitter, AttrFlags, AttrType};

/// One IPv6 Route Target Constraint membership NLRI. The on-wire NLRI
/// is identical to the IPv4 form ([`crate::Rtcv4`], RFC 4684 §4): a
/// prefix of at most 96 bits over a 4-octet origin-AS + 8-octet Route
/// Target, so both families share one reader and writer. zebra-rs
/// models the v6 family as its own `(Ip6, Rtc)` capability so VPNv6
/// import-RTs are advertised independently of VPNv4's.
#[derive(Debug, Clone)]
pub struct Rtcv6 {
    pub id: u32,
    /// Prefix length in bits, `0..=96`; see [`Rtcv4::plen`](crate::Rtcv4).
    pub plen: u8,
    pub asn: u32,
    pub rt: ExtCommunityValue,
}

impl Rtcv6 {
    /// A fully specified membership naming one exact Route Target.
    pub fn new(asn: u32, rt: ExtCommunityValue) -> Self {
        Self {
            id: 0,
            plen: RTC_PLEN_MAX,
            asn,
            rt,
        }
    }

    /// The RFC 4684 §3.2 default membership: a zero-length prefix asking for
    /// every Route Target.
    pub fn default_membership() -> Self {
        Self {
            id: 0,
            plen: 0,
            asn: 0,
            rt: ExtCommunityValue::default(),
        }
    }

    /// True only for a full 96-bit prefix, i.e. the one case where `rt` names an
    /// exact Route Target.
    pub fn is_exact(&self) -> bool {
        self.plen == RTC_PLEN_MAX
    }

    /// True for the RFC 4684 §3.2 default membership ("send me everything").
    pub fn is_default(&self) -> bool {
        self.plen == 0
    }
}

impl ParseNlri<Rtcv6> for Rtcv6 {
    fn parse_nlri(input: &[u8], addpath: bool) -> IResult<&[u8], Rtcv6> {
        let (input, (id, plen, asn, rt)) = parse_rtc_membership(input, addpath)?;
        Ok((input, Rtcv6 { id, plen, asn, rt }))
    }
}

#[derive(Debug, Clone)]
pub struct Rtcv6Reach {
    pub snpa: u8,
    pub nhop: IpAddr,
    pub updates: Vec<Rtcv6>,
}

impl AttrEmitter for Rtcv6Reach {
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
        buf.put_u8(u8::from(Safi::Rtc));
        // Nexthop. RTC membership is family metadata, not a forwarding
        // entry; emit an unspecified IPv6 next-hop for the Ip6 family.
        buf.put_u8(16); // Nexthop length. IPv6.
        let nhop = Ipv6Addr::UNSPECIFIED;
        buf.put(&nhop.octets()[..]);
        // SNPA
        buf.put_u8(0);
        // NLRI.
        if self.updates.is_empty() {
            // Zero prefix length: the default RT membership of
            // RFC 4684 §3.2 — "interested in all Route Targets".
            emit_rtc_membership(buf, 0, 0, 0, &ExtCommunityValue::default());
        } else {
            // Each membership NLRI is the AddPath id (when negotiated), the
            // prefix length, and that many bits of 4-octet origin-AS followed
            // by 8-octet Route Target (RFC 4684 §4). Shares its encoder with
            // `Rtcv6::parse_nlri`'s reader so the two cannot drift.
            for update in self.updates.iter() {
                emit_rtc_membership(buf, update.id, update.plen, update.asn, &update.rt);
            }
        }
    }
}

pub struct Rtcv6Unreach {
    pub withdraw: Vec<Rtcv6>,
}

impl AttrEmitter for Rtcv6Unreach {
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
        buf.put_u8(u8::from(Safi::Rtc));
        // A withdrawn membership uses the same NLRI encoding as MP_REACH
        // (RFC 4684 §4), so it shares the encoder. The hand-rolled loop this
        // replaces wrote only the 8-octet Route Target, omitting the prefix
        // length and origin AS that `Rtcv6::parse_nlri` reads back — a receiver
        // would have read the RT's first octet as the prefix length and
        // rejected it. Dormant so far: `mp_unreach.rs` only ever builds this
        // with an empty `withdraw` (the End-of-RIB marker).
        for withdraw in self.withdraw.iter() {
            emit_rtc_membership(buf, withdraw.id, withdraw.plen, withdraw.asn, &withdraw.rt);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The MP_REACH header `Rtcv6Reach::emit` writes before the NLRI:
    // AFI(2) + SAFI(1) + nexthop-length(1) + nexthop(16) + SNPA(1).
    const HEADER_LEN: usize = 21;

    #[test]
    fn membership_emit_roundtrips() {
        // Route Target 100:1 marked as an RT (sub-type 0x02).
        let rt = ExtCommunityValue {
            high_type: 0x00,
            low_type: 0x02,
            val: [0x00, 0x64, 0x00, 0x00, 0x00, 0x01],
        };
        let reach = Rtcv6Reach {
            snpa: 0,
            nhop: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            updates: vec![Rtcv6::new(65001, rt.clone())],
        };

        let mut buf = BytesMut::new();
        reach.emit(&mut buf);

        let (rest, parsed) = Rtcv6::parse_nlri(&buf[HEADER_LEN..], false).unwrap();
        assert!(rest.is_empty());
        assert_eq!(parsed.plen, RTC_PLEN_MAX);
        assert_eq!(parsed.asn, 65001);
        assert_eq!(parsed.rt, rt);
        assert!(parsed.is_exact());
    }

    /// The IPv6 default membership round-trips too — the v6 NLRI shares the
    /// v4 reader and writer, so this pins that the sharing holds.
    #[test]
    fn default_membership_round_trips() {
        let reach = Rtcv6Reach {
            snpa: 0,
            nhop: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            updates: vec![],
        };
        let mut buf = BytesMut::new();
        reach.emit(&mut buf);

        let (rest, parsed) = Rtcv6::parse_nlri(&buf[HEADER_LEN..], false).unwrap();
        assert!(rest.is_empty());
        assert!(parsed.is_default());
        assert!(!parsed.is_exact());
    }

    #[test]
    fn empty_membership_emits_zero_length_default() {
        let reach = Rtcv6Reach {
            snpa: 0,
            nhop: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
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
