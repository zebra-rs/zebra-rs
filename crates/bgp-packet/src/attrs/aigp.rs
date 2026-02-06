use std::fmt;

use bytes::{BufMut, BytesMut};
use nom::{
    error::{ErrorKind, make_error},
    number::complete::{be_u8, be_u16, be_u64},
};
use nom_derive::*;

use crate::ParseBe;

use super::{AttrEmitter, AttrFlags};
use crate::AttrType;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Aigp {
    pub aigp: u64,
}

impl ParseBe<Aigp> for Aigp {
    fn parse_be(input: &[u8]) -> nom::IResult<&[u8], Aigp> {
        let (input, typ) = be_u8(input)?;
        if typ != 1 {
            return Err(nom::Err::Error(make_error(input, ErrorKind::Tag)));
        }
        let (input, length) = be_u16(input)?;
        if length != 11 {
            return Err(nom::Err::Error(make_error(input, ErrorKind::Tag)));
        }
        let (_, aigp) = be_u64(input)?;
        Ok((input, Aigp { aigp }))
    }
}

impl Aigp {
    pub fn new(aigp: u64) -> Self {
        Self { aigp }
    }
}

impl AttrEmitter for Aigp {
    fn attr_flags(&self) -> AttrFlags {
        AttrFlags::new().with_optional(true)
    }

    fn attr_type(&self) -> AttrType {
        AttrType::Aigp
    }

    fn len(&self) -> Option<usize> {
        Some(11) // Fixed length: Type(1) + Length(2) + Value(8) = 11
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(1); // Type
        buf.put_u16(11); // Length
        buf.put_u64(self.aigp); // Value
    }
}

impl fmt::Display for Aigp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, " AIGP:")
    }
}
