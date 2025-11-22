use std::fmt;

use bytes::{BufMut, BytesMut};
use nom_derive::*;
use std::net::Ipv4Addr;

use crate::{AttrEmitter, AttrFlags, AttrType, ParseBe};

use super::AS_TRANS;

#[derive(Clone, NomBE)]
pub struct Aggregator {
    pub asn: u32,
    pub ip: Ipv4Addr,
}

impl Aggregator {
    pub fn new(asn: u32, ip: Ipv4Addr) -> Self {
        Self { asn, ip }
    }

    pub fn ip(&self) -> Ipv4Addr {
        self.ip
    }
}

impl AttrEmitter for Aggregator {
    fn attr_flags(&self) -> AttrFlags {
        AttrFlags::new().with_transitive(true).with_optional(true)
    }

    fn attr_type(&self) -> AttrType {
        AttrType::Aggregator
    }

    fn len(&self) -> Option<usize> {
        Some(8)
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u32(self.asn);
        buf.put(&self.ip.octets()[..]);
    }
}

impl fmt::Display for Aggregator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.asn)
    }
}

impl fmt::Debug for Aggregator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, " Aggregator: {}", self)
    }
}

// Aggregator with 2octet AS.
#[derive(Clone, NomBE)]
pub struct Aggregator2 {
    pub asn: u16,
    pub ip: Ipv4Addr,
}

impl Aggregator2 {
    pub fn new(asn: u16, ip: Ipv4Addr) -> Self {
        Self { asn, ip }
    }

    pub fn ip(&self) -> Ipv4Addr {
        self.ip
    }
}

impl AttrEmitter for Aggregator2 {
    fn attr_flags(&self) -> AttrFlags {
        AttrFlags::new().with_transitive(true)
    }

    fn attr_type(&self) -> AttrType {
        AttrType::Aggregator
    }

    fn len(&self) -> Option<usize> {
        Some(6)
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u16(self.asn);
        buf.put(&self.ip.octets()[..]);
    }
}

impl fmt::Display for Aggregator2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.asn)
    }
}

impl fmt::Debug for Aggregator2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, " Aggregator: {}", self)
    }
}

// Aggregator2 to Aggregator.
impl From<Aggregator2> for Aggregator {
    fn from(value: Aggregator2) -> Self {
        Self {
            asn: value.asn.into(),
            ip: value.ip,
        }
    }
}

// Aggregator to Aggregator2.
impl From<Aggregator> for Aggregator2 {
    fn from(value: Aggregator) -> Self {
        let asn: u16 = if value.asn <= 65536 {
            value.asn.try_into().unwrap()
        } else {
            AS_TRANS
        };
        Self { asn, ip: value.ip }
    }
}
