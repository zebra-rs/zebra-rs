use std::fmt;

use bitfield_struct::bitfield;
use bytes::{BufMut, BytesMut};
use nom_derive::*;
use serde::{Deserialize, Serialize};

use crate::{Afi, CapCode, CapEmit, Safi};

#[bitfield(u16, debug = true)]
#[derive(Serialize, Deserialize, PartialEq, NomBE)]
pub struct RestartFlagTime {
    #[bits(12)]
    pub restart_time: u16,
    #[bits(2)]
    pub resvd: u8,
    pub n_flag: bool,
    pub r_flag: bool,
}

#[bitfield(u8, debug = true)]
#[derive(Serialize, Deserialize, PartialEq, NomBE)]
pub struct RestartFlags {
    #[bits(7)]
    pub resvd: u8,
    pub p_flag: bool,
}

#[derive(Debug, PartialEq, Clone, NomBE)]
pub struct RestartValue {
    pub flag_time: RestartFlagTime,
    pub afi: Afi,
    pub safi: Safi,
    pub flags: RestartFlags,
}

impl RestartValue {
    pub fn new(restart_time: u16, afi: Afi, safi: Safi) -> Self {
        Self {
            flag_time: RestartFlagTime::new().with_restart_time(restart_time),
            afi,
            safi,
            flags: RestartFlags::default(),
        }
    }
}

#[derive(Debug, Default, PartialEq, NomBE, Clone)]
pub struct CapRestart {
    pub values: Vec<RestartValue>,
}

impl CapEmit for CapRestart {
    fn code(&self) -> CapCode {
        CapCode::GracefulRestart
    }

    fn len(&self) -> u8 {
        (self.values.len() * 6) as u8
    }

    fn emit_value(&self, buf: &mut BytesMut) {
        for val in self.values.iter() {
            buf.put_u16(val.flag_time.into());
            buf.put_u16(val.afi.into());
            buf.put_u8(val.safi.into());
            buf.put_u8(val.flags.into());
        }
    }
}

impl fmt::Display for CapRestart {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = write!(f, "GracefulRestart: ");
        for (i, value) in self.values.iter().enumerate() {
            if i > 0 {
                let _ = write!(f, ", ");
            }
            let _ = write!(
                f,
                "{}/{} restart time:{} R:{} N:{} P:{}",
                value.afi,
                value.safi,
                value.flag_time.restart_time(),
                value.flag_time.r_flag(),
                value.flag_time.n_flag(),
                value.flags.p_flag(),
            );
        }
        Ok(())
    }
}
