use std::fmt;

use bytes::{BufMut, BytesMut};
use nom_derive::*;
use std::net::Ipv4Addr;

use crate::{AttrEmitter, AttrFlags, AttrType, ParseBe};

#[derive(Clone, NomBE)]
pub struct OriginatorId {
    pub id: Ipv4Addr,
}

impl OriginatorId {
    pub fn new(id: Ipv4Addr) -> Self {
        Self { id }
    }

    pub fn id(&self) -> Ipv4Addr {
        self.id
    }
}

impl AttrEmitter for OriginatorId {
    fn attr_flags(&self) -> AttrFlags {
        AttrFlags::new().with_optional(true)
    }

    fn attr_type(&self) -> AttrType {
        AttrType::OriginatorId
    }

    fn len(&self) -> Option<usize> {
        Some(4)
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put(&self.id.octets()[..]);
    }
}

impl fmt::Display for OriginatorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.id)
    }
}

impl fmt::Debug for OriginatorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Originator ID: {}", self)
    }
}
