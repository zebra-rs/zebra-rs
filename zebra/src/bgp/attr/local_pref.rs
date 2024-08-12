use bytes::{BufMut, BytesMut};
use nom_derive::*;

use super::{AttributeFlags, AttributeType};

const LEN: u8 = 4;

#[derive(Clone, Debug, NomBE)]
pub struct LocalPref {
    pub local_pref: u32,
}

impl LocalPref {
    pub fn new(local_pref: u32) -> Self {
        Self { local_pref }
    }

    fn flags() -> AttributeFlags {
        AttributeFlags::TRANSITIVE
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(Self::flags().bits());
        buf.put_u8(AttributeType::LocalPref.0);
        buf.put_u8(LEN);
        buf.put_u32(self.local_pref);
    }
}
