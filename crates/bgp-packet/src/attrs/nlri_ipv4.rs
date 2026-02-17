use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use nom::IResult;
use nom::bytes::complete::take;
use nom::error::{ErrorKind, make_error};
use nom::number::complete::{be_u8, be_u32};
use nom_derive::*;

use crate::{ParseNlri, many0_complete, nlri_psize};

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct Ipv4Nlri {
    pub id: u32,
    pub prefix: Ipv4Net,
}

impl ParseNlri<Ipv4Nlri> for Ipv4Nlri {
    fn parse_nlri(input: &[u8], add_path: bool) -> IResult<&[u8], Ipv4Nlri> {
        let (input, id) = if add_path { be_u32(input)? } else { (input, 0) };
        let (input, plen) = be_u8(input)?;
        let psize = nlri_psize(plen);
        if input.len() < psize {
            return Err(nom::Err::Error(make_error(input, ErrorKind::Eof)));
        }
        let mut paddr = [0u8; 4];
        paddr[..psize].copy_from_slice(&input[..psize]);
        let (input, _) = take(psize).parse(input)?;
        let prefix = Ipv4Net::new(Ipv4Addr::from(paddr), plen).expect("Ipv4Net crete error");
        let nlri = Ipv4Nlri { id, prefix };
        Ok((input, nlri))
    }
}

pub fn parse_bgp_nlri_ipv4(
    input: &[u8],
    length: u16,
    add_path: bool,
) -> IResult<&[u8], Vec<Ipv4Nlri>> {
    let (nlri, input) = input.split_at(length as usize);
    let (_, nlris) = many0_complete(|i| Ipv4Nlri::parse_nlri(i, add_path)).parse(nlri)?;
    Ok((input, nlris))
}
