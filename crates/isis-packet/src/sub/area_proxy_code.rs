use nom::IResult;
use nom::number::complete::be_u8;
use nom_derive::*;

/// Sub-TLV type codes of the Area Proxy TLV (RFC 9666 §4.3).
#[repr(u8)]
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub enum IsisAreaProxyCode {
    #[default]
    ProxySystemId = 1,
    AreaSid = 2,
    Unknown(u8),
}

impl From<IsisAreaProxyCode> for u8 {
    fn from(typ: IsisAreaProxyCode) -> Self {
        use IsisAreaProxyCode::*;
        match typ {
            ProxySystemId => 1,
            AreaSid => 2,
            Unknown(v) => v,
        }
    }
}

impl From<u8> for IsisAreaProxyCode {
    fn from(typ: u8) -> Self {
        use IsisAreaProxyCode::*;
        match typ {
            1 => ProxySystemId,
            2 => AreaSid,
            v => Unknown(v),
        }
    }
}

impl IsisAreaProxyCode {
    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, typ) = be_u8(input)?;
        Ok((input, typ.into()))
    }
}
