use bytes::{BufMut, BytesMut};
use nom_derive::*;
use std::fmt;

use super::{AttributeFlags, AttributeType};

pub const ORIGIN_IGP: u8 = 0;
pub const ORIGIN_EGP: u8 = 1;
pub const ORIGIN_INCOMPLETE: u8 = 2;

#[derive(Clone, NomBE)]
pub struct Origin {
    pub origin: u8,
}

impl Origin {
    const LEN: u8 = 1;

    pub fn new(origin: u8) -> Self {
        Self { origin }
    }

    fn flags() -> AttributeFlags {
        AttributeFlags::TRANSITIVE
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(Self::flags().bits());
        buf.put_u8(AttributeType::Origin.0);
        buf.put_u8(Self::LEN);
        buf.put_u8(self.origin);
    }

    pub fn validate_flags(flags: &AttributeFlags) -> bool {
        let mut f = flags.clone();
        f.remove(AttributeFlags::EXTENDED);
        f.bits() == Self::flags().bits()
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.origin {
            ORIGIN_IGP => {
                write!(f, "i")
            }
            ORIGIN_EGP => {
                write!(f, "e")
            }
            ORIGIN_INCOMPLETE => {
                write!(f, "?")
            }
            _ => {
                write!(f, "?")
            }
        }
    }
}

impl fmt::Debug for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.origin {
            ORIGIN_IGP => {
                write!(f, "IGP")
            }
            ORIGIN_EGP => {
                write!(f, "EGP")
            }
            ORIGIN_INCOMPLETE => {
                write!(f, "Incomplete")
            }
            _ => {
                write!(f, "Incomplete")
            }
        }
    }
}
