use bytes::{BufMut, BytesMut};
use nom_derive::*;

use super::{CapabilityCode, CapabilityHeader, Emit};

#[derive(Debug, PartialEq, NomBE, Clone)]
pub struct CapabilityUnknown {
    pub header: CapabilityHeader,
    pub data: Vec<u8>,
}

impl Default for CapabilityUnknown {
    fn default() -> Self {
        Self {
            header: CapabilityHeader::new(CapabilityCode::AddPath, 0),
            data: Vec::new(),
        }
    }
}

impl Emit for CapabilityUnknown {
    fn code(&self) -> CapabilityCode {
        CapabilityCode::Unknown(100)
    }

    fn len(&self) -> u8 {
        self.data.len() as u8
    }

    fn emit_value(&self, buf: &mut BytesMut) {
        buf.put(&self.data[..]);
    }
}
