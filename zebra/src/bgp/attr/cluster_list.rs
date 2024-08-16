use bytes::{BufMut, BytesMut};
use nom_derive::*;

use super::{AttributeFlags, AttributeType};

#[derive(Clone, NomBE, Debug)]
pub struct ClusterList {
    pub list: Vec<ClusterId>,
}

impl ClusterList {
    const TYPE: AttributeType = AttributeType::ClusterList;

    pub fn new() -> Self {
        Self { list: Vec::new() }
    }

    fn flags() -> AttributeFlags {
        AttributeFlags::OPTIONAL
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        let mut attr_buf = BytesMut::new();
        for id in self.list.iter() {
            id.encode(&mut attr_buf);
        }
        if attr_buf.len() > 255 {
            buf.put_u8(Self::flags().bits() | AttributeFlags::EXTENDED.bits());
            buf.put_u8(Self::TYPE.0);
            buf.put_u16(attr_buf.len() as u16)
        } else {
            buf.put_u8(Self::flags().bits());
            buf.put_u8(Self::TYPE.0);
            buf.put_u8(attr_buf.len() as u8);
        }
        buf.put(&attr_buf[..]);
    }
}

#[derive(Clone, NomBE, Debug)]
pub struct ClusterId {
    pub id: [u8; 4],
}

impl ClusterId {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put(&self.id[..]);
    }
}
