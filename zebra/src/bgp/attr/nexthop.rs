use bytes::{BufMut, BytesMut};
use nom_derive::*;

use super::{AttributeFlags, AttributeType};

#[derive(Clone, Debug, NomBE)]
pub struct NextHopAttr {
    pub next_hop: [u8; 4],
}

impl NextHopAttr {
    const LEN: u8 = 4;

    fn flags() -> AttributeFlags {
        AttributeFlags::TRANSITIVE
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(Self::flags().bits());
        buf.put_u8(AttributeType::NextHop.0);
        buf.put_u8(Self::LEN);
        buf.put(&self.next_hop[..]);
    }
}
