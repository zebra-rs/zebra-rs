use bytes::{BufMut, BytesMut};
use nom_derive::*;

use super::{CapabilityCode, Emit};
use crate::bgp::packet::{Afi, Safi};

#[derive(Debug, PartialEq, NomBE, Clone)]
pub struct CapabilityMultiProtocol {
    afi: Afi,
    res: u8,
    safi: Safi,
}

impl CapabilityMultiProtocol {
    pub fn new(afi: &Afi, safi: &Safi) -> Self {
        Self {
            afi: *afi,
            res: 0,
            safi: *safi,
        }
    }
}

impl Emit for CapabilityMultiProtocol {
    fn code(&self) -> CapabilityCode {
        CapabilityCode::MultiProtocol
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
