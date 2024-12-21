use bytes::{BufMut, BytesMut};
use nom_derive::*;

use super::{CapabilityCode, Emit};
use crate::bgp::packet::{Afi, Safi};

#[derive(Debug, Default, PartialEq, NomBE, Clone)]
pub struct CapabilityLlgr {
    pub values: Vec<LLGRValue>,
}

#[derive(Debug, PartialEq, NomBE, Clone)]
pub struct LLGRValue {
    afi: Afi,
    safi: Safi,
    flags_stale_time: u32,
}

impl Emit for CapabilityLlgr {
    fn code(&self) -> CapabilityCode {
        CapabilityCode::Llgr
    }

    fn len(&self) -> u8 {
        (self.values.len() * 7) as u8
    }

    fn emit_value(&self, buf: &mut BytesMut) {
        for val in self.values.iter() {
            buf.put_u16(val.afi.into());
            buf.put_u8(val.safi.into());
            buf.put_u32(val.flags_stale_time);
        }
    }
}
