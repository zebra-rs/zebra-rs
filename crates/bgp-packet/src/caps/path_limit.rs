use std::fmt;

use bytes::{BufMut, BytesMut};
use nom_derive::*;

use super::{CapCode, CapEmit};
use crate::{Afi, Safi};

#[derive(Debug, Default, PartialEq, NomBE, Clone)]
pub struct CapPathLimit {
    pub values: Vec<PathLimitValue>,
}

#[derive(Debug, PartialEq, NomBE, Clone)]
pub struct PathLimitValue {
    pub afi: Afi,
    pub safi: Safi,
    pub path_limit: u16,
}

impl CapPathLimit {
    pub fn new(afi: Afi, safi: Safi, path_limit: u16) -> Self {
        Self {
            values: vec![PathLimitValue {
                afi,
                safi,
                path_limit,
            }],
        }
    }
}

impl CapEmit for CapPathLimit {
    fn code(&self) -> CapCode {
        CapCode::PathLimit
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

impl fmt::Display for CapPathLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = write!(f, "Path Limit: ");
        for (i, value) in self.values.iter().enumerate() {
            if i > 0 {
                let _ = write!(f, ", ");
            }
            let _ = write!(f, "{}/{} {}", value.afi, value.safi, value.path_limit);
        }
        Ok(())
    }
}
