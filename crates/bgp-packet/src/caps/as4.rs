use std::fmt;

use bytes::{BufMut, BytesMut};
use nom_derive::*;

use super::{CapCode, CapEmit};

#[derive(Debug, PartialEq, NomBE, Clone)]
pub struct CapAs4 {
    pub asn: u32,
}

impl CapAs4 {
    pub fn new(asn: u32) -> Self {
        Self { asn }
    }
}

impl CapEmit for CapAs4 {
    fn code(&self) -> CapCode {
        CapCode::As4
    }

    fn len(&self) -> u8 {
        4
    }

    fn emit_value(&self, buf: &mut BytesMut) {
        buf.put_u32(self.asn);
    }
}

impl fmt::Display for CapAs4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "4 Octet AS: {}", self.asn)
    }
}
