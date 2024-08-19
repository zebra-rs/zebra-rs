use bytes::{BufMut, BytesMut};
use nom_derive::*;
use std::net::Ipv4Addr;

use super::{AttributeFlags, AttributeType};

#[derive(Clone, Debug, NomBE)]
pub struct Aggregator2 {
    pub asn: u16,
    pub ip: [u8; 4],
}

#[derive(Clone, Debug, NomBE)]
pub struct Aggregator4 {
    pub asn: u32,
    pub ip: [u8; 4],
}

impl Aggregator2 {
    pub fn new(asn: u16, id: &Ipv4Addr) -> Self {
        Self {
            asn,
            ip: id.octets(),
        }
    }

    fn flags() -> AttributeFlags {
        AttributeFlags::TRANSITIVE
    }

    fn len() -> u8 {
        6
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(Self::flags().bits());
        buf.put_u8(AttributeType::Aggregator.0);
        buf.put_u8(Self::len());
        buf.put_u16(self.asn);
        buf.put(&self.ip[..]);
    }
}

impl Aggregator4 {
    pub fn new(asn: u32, id: Ipv4Addr) -> Self {
        Self {
            asn,
            ip: id.octets(),
        }
    }

    fn flags() -> AttributeFlags {
        AttributeFlags::TRANSITIVE | AttributeFlags::OPTIONAL
    }

    fn len() -> u8 {
        8
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(Self::flags().bits());
        buf.put_u8(AttributeType::Aggregator.0);
        buf.put_u8(Self::len());
        buf.put_u32(self.asn);
        buf.put(&self.ip[..]);
    }
}
