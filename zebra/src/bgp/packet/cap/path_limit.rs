use bytes::{BufMut, BytesMut};
use nom::number::complete::{be_u16, be_u8};
use nom::IResult;
use nom_derive::*;

use super::{CapabilityCode, Emit};
use crate::bgp::packet::{Afi2, Safi2};

#[derive(Debug, PartialEq, NomBE, Clone)]
pub struct CapabilityPathLimit {
    pub values: Vec<PathLimitValue>,
}

#[derive(Debug, PartialEq, NomBE, Clone)]
pub struct PathLimitValue {
    pub afi: Afi2,
    pub safi: Safi2,
    pub path_limit: u16,
}

impl CapabilityPathLimit {
    pub fn new(afi: Afi2, safi: Safi2, path_limit: u16) -> Self {
        Self {
            values: vec![PathLimitValue {
                afi,
                safi,
                path_limit,
            }],
        }
    }
}

impl Emit for CapabilityPathLimit {
    fn code(&self) -> CapabilityCode {
        CapabilityCode::PathLimit
    }

    fn len(&self) -> u8 {
        (self.values.len() * 5) as u8
    }

    fn emit_value(&self, buf: &mut BytesMut) {
        for val in self.values.iter() {
            buf.put_u16(val.afi.into());
            buf.put_u8(val.safi.into());
            buf.put_u16(val.path_limit);
        }
    }
}
