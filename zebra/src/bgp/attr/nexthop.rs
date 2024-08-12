use bytes::{BufMut, BytesMut};
use nom_derive::*;

use super::{AttributeFlags, AttributeType};

const LEN: u8 = 4;

#[derive(Clone, Debug, NomBE)]
pub struct NextHopAttr {
    pub next_hop: [u8; 4],
}

impl NextHopAttr {
    fn flags() -> AttributeFlags {
        AttributeFlags::TRANSITIVE
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(Self::flags().bits());
        buf.put_u8(AttributeType::NextHop.0);
        buf.put_u8(LEN);
        buf.put(&self.next_hop[..]);
    }
}
