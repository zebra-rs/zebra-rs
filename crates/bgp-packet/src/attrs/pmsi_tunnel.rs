use std::fmt;
use std::net::Ipv4Addr;

use bytes::{BufMut, BytesMut};
use nom::number::complete::be_u24;
use nom_derive::*;

use crate::{AttrEmitter, AttrFlags, AttrType, ParseBe, u32_u24};

#[derive(Clone, NomBE, PartialEq, Eq, Hash)]
pub struct PmsiTunnel {
    pub flags: u8,
    pub tunnel_type: u8,
    #[nom(Parse = "be_u24")]
    pub vni: u32,
    pub endpoint: Ipv4Addr,
}

impl AttrEmitter for PmsiTunnel {
    fn attr_type(&self) -> AttrType {
        AttrType::PmsiTunnel
    }

    fn attr_flags(&self) -> AttrFlags {
        AttrFlags::new().with_optional(true).with_transitive(true)
    }

    fn len(&self) -> Option<usize> {
        None
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.flags);
        buf.put_u8(self.tunnel_type);
        buf.put(&u32_u24(self.vni)[..]);
        buf.put(&self.endpoint.octets()[..]);
    }
}

impl fmt::Display for PmsiTunnel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Flag: {}, Tunnel Type: {}, VNI: {}, Endpoint: {}",
            self.flags, self.tunnel_type, self.vni, self.endpoint,
        )
    }
}

impl fmt::Debug for PmsiTunnel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, " PMSI Tunnel; {}", self)
    }
}
