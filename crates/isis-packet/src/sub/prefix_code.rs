use nom::IResult;
use nom::number::complete::be_u8;
use nom_derive::*;

#[repr(u8)]
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub enum IsisPrefixCode {
    #[default]
    PrefixSid = 3,
    Srv6EndSid = 5,
    Unknown(u8),
}

impl From<IsisPrefixCode> for u8 {
    fn from(typ: IsisPrefixCode) -> Self {
        use IsisPrefixCode::*;
        match typ {
            PrefixSid => 3,
            Srv6EndSid => 5,
            Unknown(v) => v,
        }
    }
}

impl From<u8> for IsisPrefixCode {
    fn from(typ: u8) -> Self {
        use IsisPrefixCode::*;
        match typ {
            3 => PrefixSid,
            5 => Srv6EndSid,
            v => Unknown(v),
        }
    }
}

impl IsisPrefixCode {
    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, typ) = be_u8(input)?;
        let isis_type: Self = typ.into();
        Ok((input, isis_type))
    }
}

#[repr(u8)]
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub enum IsisSrv6SidSub2Code {
    #[default]
    SidStructure = 1,
    Unknown(u8),
}

impl From<IsisSrv6SidSub2Code> for u8 {
    fn from(typ: IsisSrv6SidSub2Code) -> Self {
        use IsisSrv6SidSub2Code::*;
        match typ {
            SidStructure => 1,
            Unknown(v) => v,
        }
    }
}

impl From<u8> for IsisSrv6SidSub2Code {
    fn from(typ: u8) -> Self {
        use IsisSrv6SidSub2Code::*;
        match typ {
            1 => SidStructure,
            v => Unknown(v),
        }
    }
}
