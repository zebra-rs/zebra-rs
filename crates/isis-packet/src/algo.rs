use nom::IResult;
use nom::number::complete::be_u8;
use serde::{Deserialize, Serialize};

use crate::util::ParseBe;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum Algo {
    Spf,
    StrictSpf,
    FlexAlgo(u8),
    Unknown(u8),
}

impl Algo {
    pub fn to_byte(&self) -> u8 {
        match self {
            Algo::Spf => 0,
            Algo::StrictSpf => 1,
            Algo::FlexAlgo(val) => *val,
            Algo::Unknown(val) => *val,
        }
    }
}

impl From<Algo> for u8 {
    fn from(val: Algo) -> u8 {
        match val {
            Algo::Spf => 0u8,
            Algo::StrictSpf => 1u8,
            Algo::FlexAlgo(val) => val,
            Algo::Unknown(val) => val,
        }
    }
}

impl From<u8> for Algo {
    fn from(val: u8) -> Self {
        match val {
            0 => Algo::Spf,
            1 => Algo::StrictSpf,
            128..=255 => Algo::FlexAlgo(val),
            _ => Algo::Unknown(val),
        }
    }
}

impl ParseBe<Algo> for Algo {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, val) = be_u8(input)?;
        let algo: Algo = val.into();
        Ok((input, algo))
    }
}
