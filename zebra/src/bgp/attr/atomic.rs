use bytes::{BufMut, BytesMut};
use nom_derive::*;

use super::{AttributeFlags, AttributeType};

const LEN: u8 = 0;

#[derive(Clone, Debug, NomBE)]
pub struct AtomicAggregate {}

impl AtomicAggregate {
    pub fn new() -> Self {
        Self {}
    }

    fn flags() -> AttributeFlags {
        AttributeFlags::TRANSITIVE
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(Self::flags().bits());
        buf.put_u8(AttributeType::AtomicAggregate.0);
        buf.put_u8(LEN);
    }
}
