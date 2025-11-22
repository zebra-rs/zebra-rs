use std::net::Ipv4Addr;

use nom::{IResult, number::complete::be_u32};

pub trait ParseBe<T> {
    fn parse_be(input: &[u8]) -> IResult<&[u8], T>;
}

pub trait ParseNlri<T> {
    fn parse_nlri(input: &[u8], addpath: bool) -> IResult<&[u8], T>;
}

impl ParseBe<Ipv4Addr> for Ipv4Addr {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        if input.len() < 4 {
            return Err(nom::Err::Incomplete(nom::Needed::new(4)));
        }
        let (input, addr) = be_u32(input)?;
        Ok((input, Self::from(addr)))
    }
}
