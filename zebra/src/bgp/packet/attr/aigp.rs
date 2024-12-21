use bytes::{BufMut, BytesMut};
use nom_derive::*;

use super::{AttributeFlags, AttributeType};

#[derive(Debug, Clone, NomBE)]
pub struct Aigp {
    aigp: u64,
}

impl Aigp {
    const LEN: u8 = 11; // Type: 1 + Length: 2 + Value: 8 = 11.

    pub fn new(aigp: u64) -> Self {
        Self { aigp }
    }

    fn flags() -> AttributeFlags {
        AttributeFlags::OPTIONAL
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(Self::flags().bits());
        buf.put_u8(AttributeType::Aigp.0);
        buf.put_u8(Self::LEN);
        buf.put_u8(1);
        buf.put_u16(11);
        buf.put_u64(self.aigp);
    }

    pub fn validate_flags(flags: &AttributeFlags) -> bool {
        let mut f = flags.clone();
        f.remove(AttributeFlags::EXTENDED);
        f.bits() == Self::flags().bits()
    }
}
