use bytes::{BufMut, BytesMut};
use nom::number::complete::{be_u16, be_u32};
use nom::IResult;
use nom_derive::*;

use super::{CapabilityCode, Emit};

#[derive(Debug, PartialEq, NomBE, Clone)]
pub struct CapabilityGracefulRestart {
    #[nom(Parse = "parse_restart_time")]
    pub restart_time: u32,
}

impl CapabilityGracefulRestart {
    pub fn new(restart_time: u32) -> Self {
        Self { restart_time }
    }
}

impl Emit for CapabilityGracefulRestart {
    fn code(&self) -> CapabilityCode {
        CapabilityCode::GracefulRestart
    }

    fn len(&self) -> u8 {
        4
    }

    fn emit_value(&self, buf: &mut BytesMut) {
        buf.put_u32(self.restart_time);
    }
}

pub fn parse_restart_time(input: &[u8]) -> IResult<&[u8], u32> {
    if input.len() == 2 {
        let (input, val) = be_u16(input)?;
        Ok((input, val as u32))
    } else {
        let (input, val) = be_u32(input)?;
        Ok((input, val))
    }
}
