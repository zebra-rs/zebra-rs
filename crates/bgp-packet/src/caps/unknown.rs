use std::fmt;

use bytes::{BufMut, BytesMut};
use nom_derive::*;

use super::{CapCode, CapEmit, CapabilityHeader};

#[derive(Debug, PartialEq, NomBE, Clone)]
pub struct CapUnknown {
    pub header: CapabilityHeader,
    pub data: Vec<u8>,
}

impl Default for CapUnknown {
    fn default() -> Self {
        Self {
            header: CapabilityHeader::new(CapCode::AddPath, 0),
            data: Vec::new(),
        }
    }
}

impl CapEmit for CapUnknown {
    fn code(&self) -> CapCode {
        CapCode::Unknown(100)
    }

    fn len(&self) -> u8 {
        self.data.len() as u8
    }

    fn emit_value(&self, buf: &mut BytesMut) {
        buf.put(&self.data[..]);
    }
}

impl fmt::Display for CapUnknown {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Unknown: Code {}", self.header.code)
    }
}
