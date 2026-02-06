use std::fmt;

use bytes::{BufMut, BytesMut};
use nom::IResult;
use nom::number::complete::be_u8;
use nom_derive::*;

use crate::{AttrEmitter, AttrFlags, AttrType, ParseBe};

/// BGP route origin types as defined in RFC 4271
#[repr(u8)]
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Copy, Default, Hash)]
pub enum Origin {
    #[default]
    Igp = 0, // IGP (lowest preference)
    Egp = 1,        // EGP
    Incomplete = 2, // Incomplete (highest preference)
}

impl From<Origin> for u8 {
    fn from(value: Origin) -> Self {
        match value {
            Origin::Igp => 0,
            Origin::Egp => 1,
            Origin::Incomplete => 2,
        }
    }
}

impl Origin {
    pub fn short_str(&self) -> &'static str {
        match self {
            Origin::Igp => "i",
            Origin::Egp => "e",
            Origin::Incomplete => "?",
        }
    }
}

impl AttrEmitter for Origin {
    fn attr_type(&self) -> AttrType {
        AttrType::Origin
    }

    fn attr_flags(&self) -> AttrFlags {
        AttrFlags::new().with_transitive(true)
    }

    fn len(&self) -> Option<usize> {
        Some(1)
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8((*self).into());
    }
}

impl ParseBe<Origin> for Origin {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Origin> {
        let (input, val) = be_u8(input)?;
        let origin = match val {
            0 => Origin::Igp,
            1 => Origin::Egp,
            _ => Origin::Incomplete,
        };
        Ok((input, origin))
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Origin::Igp => {
                write!(f, "i")
            }
            Origin::Egp => {
                write!(f, "e")
            }
            Origin::Incomplete => {
                write!(f, "?")
            }
        }
    }
}

impl fmt::Debug for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Origin::Igp => {
                write!(f, "Origin: IGP")
            }
            Origin::Egp => {
                write!(f, "Origin: EGP")
            }
            Origin::Incomplete => {
                write!(f, "Origin: Incomplete")
            }
        }
    }
}
