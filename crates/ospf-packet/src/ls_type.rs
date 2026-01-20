use std::fmt::Display;

use nom::number::complete::be_u8;
use nom::IResult;
use nom_derive::*;

#[repr(u8)]
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub enum OspfLsType {
    #[default]
    Router = 1,
    Network = 2,
    Summary = 3,
    SummaryAsbr = 4,
    AsExternal = 5,
    NssaAsExternal = 7,
    OpaqueLinkLocal = 9,
    OpaqueAreaLocal = 10,
    OpaqueAsWide = 11,
    Unknown(u8),
}

impl Display for OspfLsType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use OspfLsType::*;
        let str = match self {
            Router => "Router",
            Network => "Network",
            Summary => "Summary",
            SummaryAsbr => "Summary ASBR",
            AsExternal => "AS External",
            NssaAsExternal => "NSSA AS External",
            OpaqueLinkLocal => "Opaque Link Local",
            OpaqueAreaLocal => "Opaque Area Local",
            OpaqueAsWide => "Opaque AS Wide",
            Unknown(_) => "Unknown",
        };
        write!(f, "{str}")
    }
}

impl From<OspfLsType> for u8 {
    fn from(typ: OspfLsType) -> Self {
        use OspfLsType::*;
        match typ {
            Router => 1,
            Network => 2,
            Summary => 3,
            SummaryAsbr => 4,
            AsExternal => 5,
            NssaAsExternal => 7,
            OpaqueLinkLocal => 9,
            OpaqueAreaLocal => 10,
            OpaqueAsWide => 11,
            Unknown(v) => v,
        }
    }
}

impl From<OspfLsType> for u32 {
    fn from(typ: OspfLsType) -> Self {
        let val: u8 = typ.into();
        val as u32
    }
}

impl From<u8> for OspfLsType {
    fn from(typ: u8) -> Self {
        use OspfLsType::*;
        match typ {
            1 => Router,
            2 => Network,
            3 => Summary,
            4 => SummaryAsbr,
            5 => AsExternal,
            7 => NssaAsExternal,
            9 => OpaqueLinkLocal,
            10 => OpaqueAreaLocal,
            11 => OpaqueAsWide,
            v => Unknown(v),
        }
    }
}

impl OspfLsType {
    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, typ) = be_u8(input)?;
        let ls_type: Self = typ.into();
        Ok((input, ls_type))
    }
}
