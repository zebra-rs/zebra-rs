use std::net::Ipv4Addr;

use bytes::BytesMut;
use nom::error::ParseError;
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

// many0 which avoid passing empty input to the parser.
pub fn many0<'a, O, E: ParseError<&'a [u8]>>(
    parser: impl Fn(&'a [u8]) -> IResult<&'a [u8], O, E>,
) -> impl Fn(&'a [u8]) -> IResult<&'a [u8], Vec<O>, E> {
    move |input| {
        let mut res = Vec::new();
        let mut remaining = input;

        while !remaining.is_empty() {
            match parser(remaining) {
                Ok((new_input, value)) => {
                    remaining = new_input;
                    res.push(value);
                }
                Err(Err::Incomplete(_)) => {
                    // In many0, if we encounter incomplete data, we stop and return what we have
                    break;
                }
                Err(_) => {
                    // For other errors, we also stop and return what we have
                    // This is the expected behavior for many0
                    break;
                }
            }
        }

        Ok((remaining, res))
    }
}
