use bytes::{BufMut, BytesMut};
use nom_derive::*;

use super::{AttributeFlags, AttributeType};

#[derive(Clone, Debug, NomBE)]
pub struct Med {
    pub med: u32,
}

impl Med {
    const LEN: u8 = 4;

    pub fn new(med: u32) -> Self {
        Self { med }
    }

    fn flags() -> AttributeFlags {
        AttributeFlags::OPTIONAL
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(Self::flags().bits());
        buf.put_u8(AttributeType::Med.0);
        buf.put_u8(Self::LEN);
        buf.put_u32(self.med);
    }
}
