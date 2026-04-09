// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2025-2026 Kunihiro Ishiguro

use std::net::Ipv6Addr;

use ipnet::Ipv6Net;
use nom::IResult;
use nom::bytes::complete::take;
use nom::error::{ErrorKind, make_error};
use nom::number::complete::{be_u8, be_u32};
use nom_derive::*;

use crate::{ParseBe, ParseNlri, nlri_psize};

#[derive(Debug, Clone)]
pub struct Ipv6Nlri {
    pub id: u32,
    pub prefix: Ipv6Net,
}

impl ParseNlri<Ipv6Nlri> for Ipv6Nlri {
    fn parse_nlri(input: &[u8], add_path: bool) -> IResult<&[u8], Ipv6Nlri> {
        let (input, id) = if add_path { be_u32(input)? } else { (input, 0) };
        let (input, plen) = be_u8(input)?;
        if plen > 128 {
            return Err(nom::Err::Error(make_error(input, ErrorKind::Verify)));
        }
        let psize = nlri_psize(plen);
        if input.len() < psize {
            return Err(nom::Err::Error(make_error(input, ErrorKind::Eof)));
        }
        let mut paddr = [0u8; 16];
        paddr[..psize].copy_from_slice(&input[..psize]);
        let (input, _) = take(psize).parse(input)?;
        let prefix = Ipv6Net::new(Ipv6Addr::from(paddr), plen).expect("Ipv6Net create error");
        let nlri = Ipv6Nlri { id, prefix };
        Ok((input, nlri))
    }
}

impl ParseBe<Ipv6Net> for Ipv6Net {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Ipv6Net> {
        let (input, plen) = be_u8(input)?;
        if plen > 128 {
            return Err(nom::Err::Error(make_error(input, ErrorKind::Verify)));
        }
        let psize = nlri_psize(plen);
        if input.len() < psize {
            return Err(nom::Err::Error(make_error(input, ErrorKind::Eof)));
        }
        let mut paddr = [0u8; 16];
        paddr[..psize].copy_from_slice(&input[..psize]);
        let (input, _) = take(psize).parse(input)?;
        let prefix = Ipv6Net::new(Ipv6Addr::from(paddr), plen).expect("Ipv6Net create error");

        Ok((input, prefix))
    }
}

#[cfg(test)]
mod tests {
    use super::Ipv6Nlri;
    use crate::{ParseBe, ParseNlri};
    use ipnet::Ipv6Net;

    #[test]
    fn parse_nlri_rejects_prefixlen_over_128() {
        let input = [
            129, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert!(Ipv6Nlri::parse_nlri(&input, false).is_err());
    }

    #[test]
    fn parse_ipv6net_rejects_prefixlen_over_128() {
        let input = [
            129, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert!(Ipv6Net::parse_be(&input).is_err());
    }
}
