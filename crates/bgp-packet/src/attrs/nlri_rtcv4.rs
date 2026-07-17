use std::net::{IpAddr, Ipv4Addr};

use bytes::{BufMut, BytesMut};
use nom::IResult;
use nom::error::{ErrorKind, make_error};
use nom::number::complete::{be_u8, be_u32};
use nom_derive::*;

use crate::{Afi, ExtCommunityValue, ParseNlri, Safi};

use super::{AttrEmitter, AttrFlags, AttrType};

/// Longest RTC membership prefix: a 4-octet origin AS followed by an 8-octet
/// Route Target (RFC 4684 §4).
pub const RTC_PLEN_MAX: u8 = 96;

/// Shortest non-default RTC membership prefix: enough to carry the 4-octet
/// origin AS. Anything between 1 and 31 cannot, and is malformed.
pub const RTC_PLEN_MIN: u8 = 32;

/// One Route Target Constraint membership NLRI (RFC 4684 §4).
#[derive(Debug, Clone)]
pub struct Rtcv4 {
    pub id: u32,
    /// Prefix length in bits, `0..=96`. Zero is the RFC 4684 §3.2 default
    /// membership — "interested in all Route Targets" — and carries neither an
    /// origin AS nor a Route Target. `96` fully specifies both. A length in
    /// `32..96` specifies the origin AS and only a prefix of the Route Target,
    /// constraining a range rather than naming one target.
    pub plen: u8,
    pub asn: u32,
    pub rt: ExtCommunityValue,
}

impl Rtcv4 {
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

    /// True only for a full 96-bit prefix, i.e. the one case where both `asn`
    /// and `rt` are fully specified and `rt` names an exact Route Target.
    pub fn is_exact(&self) -> bool {
        self.plen == RTC_PLEN_MAX
    }

    /// True for the RFC 4684 §3.2 default membership ("send me everything").
    pub fn is_default(&self) -> bool {
        self.plen == 0
    }
}

/// Parse one RTC membership NLRI. The wire encoding is identical for the IPv4
/// and IPv6 families (RFC 4684 §4), so [`Rtcv4`] and [`Rtcv6`](crate::Rtcv6)
/// share this.
pub(crate) fn parse_rtc_membership(
    input: &[u8],
    addpath: bool,
) -> IResult<&[u8], (u32, u8, u32, ExtCommunityValue)> {
    let (input, id) = if addpath { be_u32(input)? } else { (input, 0) };
    let (input, plen) = be_u8(input)?;
    // RFC 4684 §4: the prefix runs over a 4-octet origin AS followed by an
    // 8-octet Route Target, so 96 bits is the maximum, and §3.2 gives a
    // zero-length prefix the special meaning "interested in all Route Targets".
    // Rejecting anything but 96 dropped that default membership — which
    // `Rtcv4Reach::emit` itself originates — and, because the NLRI list is read
    // with `many0_complete`, took every membership after it down as well.
    if plen > RTC_PLEN_MAX || (plen > 0 && plen < RTC_PLEN_MIN) {
        return Err(nom::Err::Error(make_error(input, ErrorKind::LengthValue)));
    }
    // Consume exactly the octets the prefix length advertises, so a default or
    // partial membership stops short of the next NLRI instead of eating it.
    let (input, body) = packet_utils::safe_split_at(input, plen.div_ceil(8) as usize)?;
    if plen == 0 {
        return Ok((input, (id, plen, 0, ExtCommunityValue::default())));
    }
    let (body, asn) = be_u32(body)?;
    // Only a full 96-bit prefix names an exact Route Target. A shorter prefix
    // constrains a range, so leave `rt` unset rather than invent one out of
    // truncated octets — GoBGP likewise leaves its RouteTarget nil below 96.
    let rt = if plen == RTC_PLEN_MAX {
        ExtCommunityValue::parse_be(body)?.1
    } else {
        ExtCommunityValue::default()
    };
    Ok((input, (id, plen, asn, rt)))
}

/// Emit one RTC membership NLRI, the shared counterpart of
/// [`parse_rtc_membership`].
pub(crate) fn emit_rtc_membership(
    buf: &mut BytesMut,
    id: u32,
    plen: u8,
    asn: u32,
    rt: &ExtCommunityValue,
) {
    if id != 0 {
        buf.put_u32(id);
    }
    buf.put_u8(plen);
    if plen == 0 {
        // The default membership is the length octet and nothing else.
        return;
    }
    // The prefix is origin-AS(4) || RT(8) truncated to ceil(plen/8) octets, so
    // one path covers both an exact 96-bit membership and a partial one.
    let mut prefix = BytesMut::with_capacity(12);
    prefix.put_u32(asn);
    rt.encode(&mut prefix);
    let nbytes = (plen.div_ceil(8) as usize).min(prefix.len());
    buf.put(&prefix[..nbytes]);
}

impl ParseNlri<Rtcv4> for Rtcv4 {
    fn parse_nlri(input: &[u8], addpath: bool) -> IResult<&[u8], Rtcv4> {
        let (input, (id, plen, asn, rt)) = parse_rtc_membership(input, addpath)?;
        Ok((input, Rtcv4 { id, plen, asn, rt }))
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
            emit_rtc_membership(buf, 0, 0, 0, &ExtCommunityValue::default());
        } else {
            // Each membership NLRI is the AddPath id (when negotiated), the
            // prefix length, and that many bits of 4-octet origin-AS followed
            // by 8-octet Route Target (RFC 4684 §4). Shares its encoder with
            // `Rtcv4::parse_nlri`'s reader so the two cannot drift.
            for update in self.updates.iter() {
                emit_rtc_membership(buf, update.id, update.plen, update.asn, &update.rt);
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
        // A withdrawn membership uses the same NLRI encoding as MP_REACH
        // (RFC 4684 §4), so it shares the encoder. The hand-rolled loop this
        // replaces wrote only the 8-octet Route Target — mislabelled "RD" —
        // omitting the prefix length and origin AS that `Rtcv4::parse_nlri`
        // reads back, so a receiver would have read the RT's first octet as the
        // prefix length and rejected it. Dormant so far: `mp_unreach.rs` only
        // ever builds this with an empty `withdraw` (the End-of-RIB marker).
        for withdraw in self.withdraw.iter() {
            emit_rtc_membership(buf, withdraw.id, withdraw.plen, withdraw.asn, &withdraw.rt);
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
            updates: vec![Rtcv4::new(65001, rt.clone())],
        };

        let mut buf = BytesMut::new();
        reach.emit(&mut buf);

        let (rest, parsed) = Rtcv4::parse_nlri(&buf[HEADER_LEN..], false).unwrap();
        assert!(rest.is_empty());
        assert_eq!(parsed.plen, RTC_PLEN_MAX);
        assert_eq!(parsed.asn, 65001);
        assert_eq!(parsed.rt, rt);
        assert!(parsed.is_exact());
    }

    /// The zero-length default membership (RFC 4684 §3.2) that
    /// `Rtcv4Reach::emit` originates must parse back. Regression: `parse_nlri`
    /// rejected every `plen != 96`, so our own default membership was
    /// unreadable, and because the NLRI list is read with `many0_complete` the
    /// error also discarded every membership following it.
    #[test]
    fn default_membership_round_trips() {
        let reach = Rtcv4Reach {
            snpa: 0,
            nhop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            updates: vec![],
        };
        let mut buf = BytesMut::new();
        reach.emit(&mut buf);

        let (rest, parsed) = Rtcv4::parse_nlri(&buf[HEADER_LEN..], false).unwrap();
        assert!(rest.is_empty());
        assert!(
            parsed.is_default(),
            "zero-length prefix is the default membership"
        );
        assert!(!parsed.is_exact(), "it names no specific Route Target");
        assert_eq!(parsed.plen, 0);
    }

    /// A default membership no longer stops the parse, so memberships after it
    /// still arrive.
    #[test]
    fn default_membership_does_not_swallow_following_nlri() {
        let rt = ExtCommunityValue {
            high_type: 0x00,
            low_type: 0x02,
            val: [0x00, 0x64, 0x00, 0x00, 0x00, 0x01],
        };
        let mut buf = BytesMut::new();
        emit_rtc_membership(&mut buf, 0, 0, 0, &ExtCommunityValue::default());
        emit_rtc_membership(&mut buf, 0, RTC_PLEN_MAX, 65001, &rt);

        let (rest, first) = Rtcv4::parse_nlri(&buf, false).unwrap();
        assert!(first.is_default());
        let (rest, second) = Rtcv4::parse_nlri(rest, false).unwrap();
        assert!(rest.is_empty(), "both NLRI consumed");
        assert_eq!(second.asn, 65001);
        assert_eq!(second.rt, rt);
    }

    /// RFC 4684 §4 allows any prefix length in 0..=96. A partial prefix carries
    /// the origin AS but only part of the Route Target, so it must consume
    /// exactly ceil(plen/8) octets and leave `rt` unset rather than invent one.
    #[test]
    fn partial_prefix_parses_and_consumes_its_octets() {
        // plen=32: origin AS only.
        let wire = [32u8, 0x00, 0x00, 0xfd, 0xe9];
        let (rest, rd) = Rtcv4::parse_nlri(&wire, false).unwrap();
        assert!(rest.is_empty(), "consumed exactly ceil(32/8) = 4 octets");
        assert_eq!(rd.plen, 32);
        assert_eq!(rd.asn, 65001);
        assert!(!rd.is_exact(), "no Route Target is named");

        // plen=48: origin AS plus two RT octets.
        let wire = [48u8, 0x00, 0x00, 0xfd, 0xe9, 0x00, 0x02];
        let (rest, rd) = Rtcv4::parse_nlri(&wire, false).unwrap();
        assert!(rest.is_empty(), "consumed exactly ceil(48/8) = 6 octets");
        assert_eq!(rd.plen, 48);
        assert!(!rd.is_exact());
    }

    /// Lengths beyond the 96-bit prefix, or too short to hold the origin AS,
    /// are malformed.
    #[test]
    fn out_of_range_prefix_lengths_rejected() {
        for plen in [1u8, 31, 97, 255] {
            let mut wire = vec![plen];
            wire.extend_from_slice(&[0u8; 16]);
            assert!(
                Rtcv4::parse_nlri(&wire, false).is_err(),
                "plen {plen} must be rejected"
            );
        }
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
