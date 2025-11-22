use nom::IResult;
use nom::number::complete::be_u8;
use nom_derive::*;

#[repr(u8)]
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub enum IsisCapCode {
    #[default]
    SegmentRoutingCap = 2,
    SegmentRoutingAlgo = 19,
    SegmentRoutingLb = 22,
    NodeMaxSidDepth = 23,
    Srv6 = 25,
    Unknown(u8),
}

impl From<IsisCapCode> for u8 {
    fn from(typ: IsisCapCode) -> Self {
        use IsisCapCode::*;
        match typ {
            SegmentRoutingCap => 2,
            SegmentRoutingAlgo => 19,
            SegmentRoutingLb => 22,
            NodeMaxSidDepth => 23,
            Srv6 => 25,
            Unknown(v) => v,
        }
    }
}

impl From<u8> for IsisCapCode {
    fn from(typ: u8) -> Self {
        use IsisCapCode::*;
        match typ {
            2 => SegmentRoutingCap,
            19 => SegmentRoutingAlgo,
            22 => SegmentRoutingLb,
            23 => NodeMaxSidDepth,
            25 => Srv6,
            v => Unknown(v),
        }
    }
}

impl IsisCapCode {
    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, typ) = be_u8(input)?;
        let isis_type: Self = typ.into();
        Ok((input, isis_type))
    }
}
