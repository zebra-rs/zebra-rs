use std::fmt;

use bytes::{BufMut, BytesMut};
use nom::{IResult, number::complete::be_u8};
use nom_derive::*;
use strum_macros::{Display, EnumString};

use super::{CapCode, CapEmit};
use crate::{Afi, Safi};

#[derive(Debug, PartialEq, NomBE, Clone, Ord, PartialOrd, Eq)]
pub struct AddPathValue {
    pub afi: Afi,
    pub safi: Safi,
    pub send_receive: AddPathSendReceive,
}

#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Copy, Ord, PartialOrd, Eq, Display, EnumString)]
pub enum AddPathSendReceive {
    Receive = 1,
    Send = 2,
    SendReceive = 3,
    #[strum(disabled)]
    Unknown(u8),
}

impl From<AddPathSendReceive> for u8 {
    fn from(typ: AddPathSendReceive) -> Self {
        use AddPathSendReceive::*;
        match typ {
            Receive => 1,
            Send => 2,
            SendReceive => 3,
            Unknown(v) => v,
        }
    }
}

impl From<u8> for AddPathSendReceive {
    fn from(typ: u8) -> Self {
        use AddPathSendReceive::*;
        match typ {
            1 => Receive,
            2 => Send,
            3 => SendReceive,
            v => Unknown(v),
        }
    }
}

impl AddPathSendReceive {
    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, val) = be_u8(input)?;
        let send_receive: Self = val.into();
        Ok((input, send_receive))
    }

    pub fn is_receive(&self) -> bool {
        *self == AddPathSendReceive::Receive || *self == AddPathSendReceive::SendReceive
    }

    pub fn is_send(&self) -> bool {
        *self == AddPathSendReceive::Send || *self == AddPathSendReceive::SendReceive
    }
}

// Display and FromStr implementation now provided by strum macros
// Note: The Unknown variant will display as "Unknown" and cannot be parsed from string

#[derive(Debug, Default, PartialEq, NomBE, Clone)]
pub struct CapAddPath {
    pub values: Vec<AddPathValue>,
}

impl CapAddPath {
    pub fn new(afi: Afi, safi: Safi, send_receive: u8) -> Self {
        Self {
            values: vec![AddPathValue {
                afi,
                safi,
                send_receive: send_receive.into(),
            }],
        }
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

impl CapEmit for CapAddPath {
    fn code(&self) -> CapCode {
        CapCode::AddPath
    }

    fn len(&self) -> u8 {
        (self.values.len() * 4) as u8
    }

    fn emit_value(&self, buf: &mut BytesMut) {
        for val in self.values.iter() {
            buf.put_u16(val.afi.into());
            buf.put_u8(val.safi.into());
            buf.put_u8(val.send_receive.into());
        }
    }
}

impl fmt::Display for CapAddPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = write!(f, "AddPath: ");
        for (i, value) in self.values.iter().enumerate() {
            if i > 0 {
                let _ = write!(f, ", ");
            }
            let _ = write!(f, "{}/{}: {}", value.afi, value.safi, value.send_receive);
        }
        Ok(())
    }
}
