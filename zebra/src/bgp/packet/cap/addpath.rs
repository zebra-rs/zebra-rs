use bytes::{BufMut, BytesMut};
use nom_derive::*;

use super::{CapabilityCode, Emit};
use crate::bgp::packet::{Afi2, Safi2};

#[derive(Debug, PartialEq, NomBE, Clone)]
pub struct AddPathValue {
    afi: Afi2,
    safi: Safi2,
    send_receive: u8,
}

#[derive(Debug, PartialEq, NomBE, Clone)]
pub struct CapabilityAddPath {
    pub values: Vec<AddPathValue>,
}

impl CapabilityAddPath {
    pub fn new(afi: Afi2, safi: Safi2, send_receive: u8) -> Self {
        Self {
            values: vec![AddPathValue {
                afi,
                safi,
                send_receive,
            }],
        }
    }
}

impl Emit for CapabilityAddPath {
    fn code(&self) -> CapabilityCode {
        CapabilityCode::AddPath
    }

    fn len(&self) -> u8 {
        (self.values.len() * 4) as u8
    }

    fn emit_value(&self, buf: &mut BytesMut) {
        for val in self.values.iter() {
            buf.put_u16(val.afi.into());
            buf.put_u8(val.safi.into());
            buf.put_u8(val.send_receive);
        }
    }
}
