use std::fmt;
use std::net::Ipv4Addr;

use bytes::{BufMut, BytesMut};
use nom_derive::*;

use crate::{AttrEmitter, AttrFlags, AttrType, ParseBe};

#[derive(Clone, NomBE)]
pub struct NexthopAttr {
    pub nexthop: Ipv4Addr,
}

impl AttrEmitter for NexthopAttr {
    fn attr_flags(&self) -> AttrFlags {
        AttrFlags::new().with_transitive(true)
    }

    fn attr_type(&self) -> AttrType {
        AttrType::NextHop
    }

    fn len(&self) -> Option<usize> {
        Some(4)
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put(&self.nexthop.octets()[..]);
    }
}

impl fmt::Display for NexthopAttr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.nexthop)
    }
}

impl fmt::Debug for NexthopAttr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Nexthop: {}", self)
    }
}
