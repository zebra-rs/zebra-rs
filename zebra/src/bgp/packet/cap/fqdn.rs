use bytes::{BufMut, BytesMut};
use nom::bytes::complete::take;
use nom::number::complete::{be_u16, be_u32, be_u8};
use nom::IResult;
use nom_derive::*;

use super::{CapabilityCode, Emit};

#[derive(Debug, Default, PartialEq, Clone)]
pub struct CapabilityFqdn {
    pub hostname: Vec<u8>,
    pub domain: Vec<u8>,
}

impl CapabilityFqdn {
    pub fn new(hostname: &str, domain: &str) -> Self {
        Self {
            hostname: hostname.into(),
            domain: domain.into(),
        }
    }
}

impl Emit for CapabilityFqdn {
    fn code(&self) -> CapabilityCode {
        CapabilityCode::Fqdn
    }

    fn len(&self) -> u8 {
        (2 + self.hostname.len() + self.domain.len()) as u8
    }

    fn emit_value(&self, buf: &mut BytesMut) {
        buf.put_u8(self.hostname.len() as u8);
        buf.put(&self.hostname[..]);
        buf.put_u8(self.domain.len() as u8);
        buf.put(&self.domain[..]);
    }
}

impl CapabilityFqdn {
    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, hostname_len) = be_u8(input)?;
        let (input, hostname) = take(hostname_len)(input)?;
        let hostname = hostname.to_vec();
        let (input, domain_len) = be_u8(input)?;
        let (input, domain) = take(domain_len)(input)?;
        let domain = domain.to_vec();

        let fqdn = Self { hostname, domain };
        Ok((input, fqdn))
    }
}
