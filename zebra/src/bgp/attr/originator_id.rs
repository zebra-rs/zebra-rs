use bytes::{BufMut, BytesMut};
use nom_derive::*;
use std::net::Ipv4Addr;

use super::{AttributeFlags, AttributeType};

#[derive(Clone, NomBE, Debug)]
pub struct OriginatorId {
    pub id: [u8; 4],
}

impl OriginatorId {
    const LEN: u8 = 4;
    const TYPE: AttributeType = AttributeType::OriginatorId;

    pub fn new(id: &Ipv4Addr) -> Self {
        Self { id: id.octets() }
    }

    fn flags() -> AttributeFlags {
        AttributeFlags::OPTIONAL
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(Self::flags().bits());
        buf.put_u8(Self::TYPE.0);
        buf.put_u8(Self::LEN);
        buf.put(&self.id[..]);
    }
}
