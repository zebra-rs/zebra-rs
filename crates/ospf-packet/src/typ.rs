use std::fmt::Display;

use nom::IResult;
use nom::number::complete::be_u8;
use nom_derive::*;

#[repr(u8)]
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub enum OspfType {
    #[default]
    Hello = 1,
    DbDesc = 2,
    LsRequest = 3,
    LsUpdate = 4,
    LsAck = 5,
    Unknown(u8),
}

impl Display for OspfType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use OspfType::*;
        let str = match self {
            Hello => "Hello",
            DbDesc => "Database Description",
            LsRequest => "LS Request",
            LsUpdate => "LS Update",
            LsAck => "LS Acknowlegement",
            Unknown(_) => "Unknown",
        };
        write!(f, "{str}")
    }
}

impl From<OspfType> for u8 {
    fn from(typ: OspfType) -> Self {
        use OspfType::*;
        match typ {
            Hello => 1,
            DbDesc => 2,
            LsRequest => 3,
            LsUpdate => 4,
            LsAck => 5,
            Unknown(v) => v,
        }
    }
}

impl From<u8> for OspfType {
    fn from(val: u8) -> Self {
        use OspfType::*;
        match val {
            1 => Hello,
            2 => DbDesc,
            3 => LsRequest,
            4 => LsUpdate,
            5 => LsAck,
            v => Unknown(v),
        }
    }
}

impl OspfType {
    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, typ) = be_u8(input)?;
        let ospf_type: Self = typ.into();
        Ok((input, ospf_type))
    }
}
