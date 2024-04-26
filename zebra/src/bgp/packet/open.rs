use super::BgpHeader;
use crate::bgp::{Afi, Safi};
use bytes::BufMut;
use bytes::BytesMut;
use nom_derive::*;
use rusticata_macros::newtype_enum;
use std::net::Ipv4Addr;

#[derive(Debug, PartialEq, NomBE)]
pub struct OpenPacket {
    pub header: BgpHeader,
    pub version: u8,
    pub asn: u16,
    pub hold_time: u16,
    pub bgp_id: [u8; 4],
    pub opt_param_len: u8,
    #[nom(Ignore)]
    pub caps: Vec<CapabilityPacket>,
}

#[derive(Debug, Eq, PartialEq, NomBE)]
pub struct CapabilityType(pub u8);

newtype_enum! {
    impl display CapabilityType {
        MultiProtocol = 1,
        RouteRefresh = 2,
        GracefulRestart = 64,
        As4 = 65,
        RouteRefreshCisco = 128,
    }
}

#[derive(Debug, PartialEq)]
pub enum CapabilityPacket {
    MultiProtocol(CapabilityMultiProtocol),
    RouteRefresh(CapabilityRouteRefresh),
    As4(CapabilityAs4),
    GracefulRestart(CapabilityGracefulRestart),
}

impl CapabilityPacket {
    pub fn encode(&self, buf: &mut BytesMut) {
        match self {
            Self::MultiProtocol(m) => {
                m.header.encode(buf);
                buf.put_u8(m.typ.0);
                buf.put_u8(m.length);
                buf.put_u16(m.afi.0);
                buf.put_u8(0);
                buf.put_u8(m.safi.0);
            }
            Self::RouteRefresh(m) => {
                m.header.encode(buf);
                buf.put_u8(m.typ);
                buf.put_u8(m.length);
            }
            Self::As4(m) => {
                m.header.encode(buf);
                buf.put_u8(m.typ);
                buf.put_u8(m.length);
                buf.put_u32(m.asn);
            }
            Self::GracefulRestart(m) => {
                m.header.encode(buf);
                buf.put_u32(m.restart_timers);
            }
        }
    }
}

#[derive(Debug, PartialEq, NomBE)]
pub struct CapabilityHeader {
    pub code: u8,
    pub length: u8,
}

impl CapabilityHeader {
    pub fn new(code: u8, length: u8) -> Self {
        Self { code, length }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.code);
        buf.put_u8(self.length);
    }
}

#[derive(Debug, PartialEq, NomBE)]
pub struct CapabilityPeekHeader {
    pub header: CapabilityHeader,
    pub typ: u8,
    pub length: u8,
}

#[derive(Debug, PartialEq, NomBE)]
pub struct CapabilityMultiProtocol {
    header: CapabilityHeader,
    typ: CapabilityType,
    length: u8,
    afi: Afi,
    res: u8,
    safi: Safi,
}

const OpenCapability: u8 = 2;

impl CapabilityMultiProtocol {
    pub fn new(afi: &Afi, safi: &Safi) -> Self {
        Self {
            header: CapabilityHeader::new(OpenCapability, 6),
            typ: CapabilityType::MultiProtocol,
            length: 4,
            afi: afi.clone(),
            res: 0,
            safi: safi.clone(),
        }
    }
}

//

#[derive(Debug, PartialEq, NomBE)]
pub struct CapabilityRouteRefresh {
    header: CapabilityHeader,
    typ: u8,
    length: u8,
}

#[derive(Debug, PartialEq, NomBE)]
pub struct CapabilityAs4 {
    header: CapabilityHeader,
    typ: u8,
    length: u8,
    asn: u32,
}

#[derive(Debug, PartialEq, NomBE)]
pub struct CapabilityGracefulRestart {
    header: CapabilityHeader,
    restart_timers: u32,
}

impl OpenPacket {
    pub fn new(
        header: BgpHeader,
        asn: u16,
        router_id: &Ipv4Addr,
        caps: Vec<CapabilityPacket>,
    ) -> OpenPacket {
        OpenPacket {
            header,
            version: 4,
            asn,
            hold_time: 180,
            bgp_id: router_id.octets(),
            opt_param_len: 0,
            caps,
        }
    }
}
