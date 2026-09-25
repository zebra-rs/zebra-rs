use std::fmt;

use bytes::{BufMut, BytesMut};
use nom::error::{ErrorKind, make_error};
use nom::number::complete::be_u32;
use std::net::Ipv4Addr;

use crate::{AttrEmitter, AttrFlags, AttrType, ParseBe};

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct OriginatorId {
    pub id: Ipv4Addr,
}

impl OriginatorId {
    pub fn new(id: Ipv4Addr) -> Self {
        Self { id }
    }

    pub fn id(&self) -> Ipv4Addr {
        self.id
    }
}

impl ParseBe<OriginatorId> for OriginatorId {
    fn parse_be(input: &[u8]) -> nom::IResult<&[u8], OriginatorId> {
        // RFC 7606 §7.9: an ORIGINATOR_ID "SHALL be considered malformed
        // if its length is not equal to 4". Reject long values too — a
        // plain `be_u32` would accept trailing octets. From an internal
        // neighbor the caller maps this to treat-as-withdraw
        // (`attr_malformation_is_withdraw`); from an external one the
        // attribute never reaches this parser (attribute discard).
        if input.len() != 4 {
            return Err(nom::Err::Error(make_error(input, ErrorKind::LengthValue)));
        }
        let (input, id) = be_u32(input)?;
        Ok((input, OriginatorId::new(Ipv4Addr::from(id))))
    }
}

impl AttrEmitter for OriginatorId {
    fn attr_flags(&self) -> AttrFlags {
        AttrFlags::new().with_optional(true)
    }

    fn attr_type(&self) -> AttrType {
        AttrType::OriginatorId
    }

    fn len(&self) -> Option<usize> {
        Some(4)
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put(&self.id.octets()[..]);
    }
}

impl fmt::Display for OriginatorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.id)
    }
}

impl fmt::Debug for OriginatorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Originator ID: {}", self)
    }
}
