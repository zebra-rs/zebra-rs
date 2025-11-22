use std::fmt;

use bytes::{BufMut, BytesMut};
use nom_derive::*;
use serde::Serialize;

use super::{CapCode, CapEmit};
use crate::{Afi, Safi};

#[derive(Debug, PartialEq, NomBE, Clone, Eq, Hash, Serialize)]
pub struct CapMultiProtocol {
    pub afi: Afi,
    res: u8,
    pub safi: Safi,
}

impl CapMultiProtocol {
    pub fn new(afi: &Afi, safi: &Safi) -> Self {
        Self {
            afi: *afi,
            res: 0,
            safi: *safi,
        }
    }
}

impl CapEmit for CapMultiProtocol {
    fn code(&self) -> CapCode {
        CapCode::MultiProtocol
    }

    fn len(&self) -> u8 {
        4
    }

    fn emit_value(&self, buf: &mut BytesMut) {
        buf.put_u16(self.afi.into());
        buf.put_u8(0);
        buf.put_u8(self.safi.into());
    }
}

impl fmt::Display for CapMultiProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MultiProtocol: {}/{}", self.afi, self.safi)
    }
}
