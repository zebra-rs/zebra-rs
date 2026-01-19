use std::net::Ipv4Addr;

use bytes::BytesMut;
use nom::number::complete::be_u32;
use nom::{Err, IResult, Needed};

pub trait Emit {
    fn emit(&self, buf: &mut BytesMut);
}

pub trait ParseBe<T> {
    fn parse_be(input: &[u8]) -> IResult<&[u8], T>;
}

impl ParseBe<Ipv4Addr> for Ipv4Addr {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        if input.len() < 4 {
            return Err(Err::Incomplete(Needed::new(4)));
        }
        let (input, addr) = be_u32(input)?;
        Ok((input, Self::from(addr)))
    }
}
