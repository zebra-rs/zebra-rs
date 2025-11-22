use std::{borrow::Cow, fmt};

use bytes::{BufMut, BytesMut};
use nom::IResult;
use nom::bytes::complete::take;
use nom::number::complete::be_u8;
use nom_derive::*;

use super::{CapCode, CapEmit};

#[derive(Debug, Default, PartialEq, Clone)]
pub struct CapFqdn {
    pub hostname: Vec<u8>,
    pub domain: Vec<u8>,
}

impl CapFqdn {
    pub fn new(hostname: &str, domain: &str) -> Self {
        Self {
            hostname: hostname.into(),
            domain: domain.into(),
        }
    }

    pub fn hostname(&self) -> Cow<'_, str> {
        if self.hostname.is_empty() {
            Cow::Borrowed("n/a")
        } else {
            String::from_utf8_lossy(&self.hostname)
        }
    }

    pub fn domain(&self) -> Cow<'_, str> {
        if self.domain.is_empty() {
            Cow::Borrowed("n/a")
        } else {
            String::from_utf8_lossy(&self.domain)
        }
    }
}

impl CapEmit for CapFqdn {
    fn code(&self) -> CapCode {
        CapCode::Fqdn
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

impl CapFqdn {
    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, hostname_len) = be_u8(input)?;
        let (input, hostname) = take(hostname_len).parse(input)?;
        let hostname = hostname.to_vec();
        let (input, domain_len) = be_u8(input)?;
        let (input, domain) = take(domain_len).parse(input)?;
        let domain = domain.to_vec();

        let fqdn = Self { hostname, domain };
        Ok((input, fqdn))
    }
}

impl fmt::Display for CapFqdn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hostname = String::from_utf8_lossy(&self.hostname);
        let domain = String::from_utf8_lossy(&self.domain);
        write!(f, "FQDN: {} {}", hostname, domain)
    }
}
