use std::net::Ipv4Addr;

use bytes::{BufMut, BytesMut};
use ipnet::Ipv4Net;
use nom::IResult;
use nom::bytes::complete::take;
use nom::error::{ErrorKind, make_error};
use nom::number::complete::{be_u8, be_u32};
use nom_derive::*;

use crate::{ParseNlri, nlri_psize};

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct Ipv4Nlri {
    pub id: u32,
    pub prefix: Ipv4Net,
}

impl Ipv4Nlri {
    /// Encode this NLRI into an MP_REACH / MP_UNREACH NLRI list:
    /// an optional 4-octet AddPath ID (only when `id != 0`), the
    /// 1-octet prefix length, then the `ceil(plen / 8)` significant
    /// prefix octets. Inverse of [`Ipv4Nlri::parse_nlri`].
    pub fn nlri_emit(&self, buf: &mut BytesMut) {
        if self.id != 0 {
            buf.put_u32(self.id);
        }
        let plen = self.prefix.prefix_len();
        buf.put_u8(plen);
        let psize = nlri_psize(plen);
        buf.put(&self.prefix.addr().octets()[0..psize]);
    }
}

impl ParseNlri<Ipv4Nlri> for Ipv4Nlri {
    fn parse_nlri(input: &[u8], add_path: bool) -> IResult<&[u8], Ipv4Nlri> {
        let (input, id) = if add_path { be_u32(input)? } else { (input, 0) };
        let (input, plen) = be_u8(input)?;
        if plen > 32 {
            return Err(nom::Err::Error(make_error(input, ErrorKind::Verify)));
        }
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
    let len = length as usize;
    let (input, mut nlri) = packet_utils::safe_split_at(input, len)?;
    // Drain the whole bounded slice: every byte must belong to a complete
    // NLRI. A leftover (malformed/truncated trailing entry) surfaces the
    // real parse error instead of being silently discarded.
    let mut nlris = Vec::new();
    while !nlri.is_empty() {
        let (rest, entry) = Ipv4Nlri::parse_nlri(nlri, add_path)?;
        nlris.push(entry);
        nlri = rest;
    }
    Ok((input, nlris))
}

#[cfg(test)]
mod tests {
    use super::{Ipv4Nlri, parse_bgp_nlri_ipv4};
    use crate::ParseNlri;

    #[test]
    fn parse_nlri_rejects_prefixlen_over_32() {
        let input = [33, 192, 0, 2, 1, 0];
        assert!(Ipv4Nlri::parse_nlri(&input, false).is_err());
    }

    #[test]
    fn parse_bgp_nlri_ipv4_consumes_whole_block() {
        // Two NLRIs: 192.0.2.0/24 (4 bytes) then the default route /0 (1 byte).
        let input = [24, 192, 0, 2, 0];
        let (rest, nlris) = parse_bgp_nlri_ipv4(&input, 5, false).unwrap();
        assert!(rest.is_empty());
        assert_eq!(nlris.len(), 2);
        assert_eq!(nlris[0].prefix, "192.0.2.0/24".parse().unwrap());
        assert_eq!(nlris[1].prefix, "0.0.0.0/0".parse().unwrap());
    }

    #[test]
    fn parse_bgp_nlri_ipv4_rejects_trailing_garbage() {
        // One /24 NLRI (4 bytes) plus a stray length octet that cannot form a
        // complete NLRI; previously many0_complete dropped it silently.
        let input = [24, 192, 0, 2, 8];
        assert!(parse_bgp_nlri_ipv4(&input, 5, false).is_err());
    }
}
