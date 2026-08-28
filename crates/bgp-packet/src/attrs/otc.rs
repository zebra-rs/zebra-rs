//! RFC 9234 §5 Only-to-Customer (OTC) path attribute (type code 35).
//!
//! Optional transitive, four octets: the AS number of the speaker that
//! marked the route as "only to be advertised to customers". Set by a
//! Provider / Peer / Route Server on egress toward a Customer / Peer /
//! RS-Client (or by the receiver on ingress from one of those), and never
//! changed once present — a route carrying OTC must not be propagated to
//! a Provider, Peer or RS, and receiving one from a Customer or RS-Client
//! identifies a route leak. The procedures themselves live in the
//! `zebra-rs` ingress/egress paths; this module is only the codec.

use std::fmt;

use bytes::{BufMut, BytesMut};
use nom::error::{ErrorKind, make_error};
use nom::number::complete::be_u32;

use crate::{AttrEmitter, AttrFlags, AttrType, ParseBe};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Otc {
    /// The AS number that marked the route.
    pub asn: u32,
}

impl Otc {
    pub fn new(asn: u32) -> Self {
        Self { asn }
    }
}

impl ParseBe<Otc> for Otc {
    fn parse_be(input: &[u8]) -> nom::IResult<&[u8], Otc> {
        // RFC 9234 §5: "The OTC Attribute is considered malformed if the
        // length value is not 4." Reject short *and* long values — a
        // plain `be_u32` would silently accept trailing octets. The
        // caller maps this error to treat-as-withdraw
        // (`attr_malformation_is_withdraw`), as the RFC requires.
        if input.len() != 4 {
            return Err(nom::Err::Error(make_error(input, ErrorKind::LengthValue)));
        }
        let (input, asn) = be_u32(input)?;
        Ok((input, Otc { asn }))
    }
}

impl AttrEmitter for Otc {
    fn attr_flags(&self) -> AttrFlags {
        AttrFlags::new().with_optional(true).with_transitive(true)
    }

    fn attr_type(&self) -> AttrType {
        AttrType::Otc
    }

    fn len(&self) -> Option<usize> {
        Some(4)
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u32(self.asn);
    }
}

impl fmt::Display for Otc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.asn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emits_optional_transitive_type_35_four_octets() {
        let mut buf = BytesMut::new();
        Otc::new(65540).attr_emit(&mut buf);
        // flags: Optional|Transitive = 0xc0, type 35, length 4, 65540.
        assert_eq!(&buf[..], &[0xc0u8, 35, 4, 0x00, 0x01, 0x00, 0x04]);
    }

    #[test]
    fn parses_exactly_four_octets() {
        let (rest, otc) = Otc::parse_be(&[0x00, 0x00, 0xfd, 0xe9]).unwrap();
        assert!(rest.is_empty());
        assert_eq!(otc, Otc::new(65001));
    }

    #[test]
    fn rejects_short_and_long_values() {
        assert!(Otc::parse_be(&[0x00, 0x00, 0xfd]).is_err());
        assert!(Otc::parse_be(&[0x00, 0x00, 0x00, 0xfd, 0xe9]).is_err());
        assert!(Otc::parse_be(&[]).is_err());
    }

    #[test]
    fn round_trips_through_the_emitter() {
        let mut buf = BytesMut::new();
        Otc::new(4_200_000_000).attr_emit(&mut buf);
        let (_, parsed) = Otc::parse_be(&buf[3..]).unwrap();
        assert_eq!(parsed.asn, 4_200_000_000);
        assert_eq!(parsed.to_string(), "4200000000");
    }
}
