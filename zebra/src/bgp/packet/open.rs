use super::BgpHeader;
use crate::bgp::{Afi, Safi};
use bytes::BufMut;
use bytes::BytesMut;
use nom_derive::*;
use rusticata_macros::newtype_enum;
use std::net::Ipv4Addr;

const CAPABILITY_CODE: u8 = 2;

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

#[derive(Debug, Eq, PartialEq, NomBE, Clone)]
pub struct CapabilityType(pub u8);

newtype_enum! {
    impl display CapabilityType {
        MultiProtocol = 1,
        RouteRefresh = 2,
    ExtendedMessage = 6,
        GracefulRestart = 64,
        As4 = 65,
        DynamicCapability = 67,
    AddPath = 69,
    EnhancedRouteRefresh = 70,
    LLGR = 71,
    FQDN = 73,
    SoftwareVersion = 76,
        RouteRefreshCisco = 128,
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum CapabilityPacket {
    MultiProtocol(CapabilityMultiProtocol),
    RouteRefresh(CapabilityRouteRefresh),
    ExtendedMessage(CapabilityExtendedMessage),
    As4(CapabilityAs4),
    DynamicCapability(CapabilityDynamicCapability),
    AddPath(CapabilityAddPath),
    GracefulRestart(CapabilityGracefulRestart),
    EnhancedRouteRefresh(CapabilityEnhancedRouteRefresh),
    LLGR(CapabilityLLGR),
    FQDN(CapabilityFQDN),
    SoftwareVersion(CapabilitySoftwareVersion),
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
                buf.put_u8(m.typ.0);
                buf.put_u8(m.length);
            }
            Self::ExtendedMessage(m) => {
                m.header.encode(buf);
                buf.put_u8(m.typ.0);
                buf.put_u8(m.length);
            }
            Self::As4(m) => {
                m.header.encode(buf);
                buf.put_u8(m.typ.0);
                buf.put_u8(m.length);
                buf.put_u32(m.asn);
            }
            Self::DynamicCapability(m) => {
                m.header.encode(buf);
                buf.put_u8(m.typ.0);
                buf.put_u8(m.length);
            }
            Self::AddPath(m) => {
                m.header.encode(buf);
                buf.put_u8(m.typ.0);
                buf.put_u8(m.length);
            }
            Self::GracefulRestart(m) => {
                m.header.encode(buf);
                buf.put_u32(m.restart_time);
            }
            Self::EnhancedRouteRefresh(m) => {
                m.header.encode(buf);
                buf.put_u8(m.typ.0);
                buf.put_u8(m.length);
            }
            Self::LLGR(m) => {
                m.header.encode(buf);
                buf.put_u8(m.typ.0);
                buf.put_u8(m.length);
            }
            Self::FQDN(m) => {
                m.header.encode(buf);
                buf.put_u8(m.typ.0);
                buf.put_u8(m.length);
                buf.put_u8(m.hostname.len() as u8);
                buf.put(&m.hostname[..]);
                buf.put_u8(m.domain.len() as u8);
                buf.put(&m.domain[..]);
            }
            Self::SoftwareVersion(m) => {
                m.header.encode(buf);
                buf.put_u8(m.typ.0);
                buf.put_u8(m.length);
            }
        }
    }
}

#[derive(Debug, PartialEq, NomBE, Clone)]
pub struct CapabilityHeader {
    pub code: u8,
    pub length: u8,
}

impl CapabilityHeader {
    pub fn new(length: u8) -> Self {
        Self {
            code: CAPABILITY_CODE,
            length,
        }
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

#[derive(Debug, PartialEq, NomBE, Clone)]
pub struct CapabilityMultiProtocol {
    header: CapabilityHeader,
    typ: CapabilityType,
    length: u8,
    afi: Afi,
    res: u8,
    safi: Safi,
}

impl CapabilityMultiProtocol {
    pub fn new(afi: &Afi, safi: &Safi) -> Self {
        Self {
            header: CapabilityHeader::new(6),
            typ: CapabilityType::MultiProtocol,
            length: 4,
            afi: afi.clone(),
            res: 0,
            safi: safi.clone(),
        }
    }
}

#[derive(Debug, PartialEq, NomBE, Clone)]
pub struct CapabilityRouteRefresh {
    header: CapabilityHeader,
    typ: CapabilityType,
    length: u8,
}

impl CapabilityRouteRefresh {
    pub fn new(typ: CapabilityType) -> Self {
        Self {
            header: CapabilityHeader::new(2),
            typ,
            length: 0,
        }
    }
}

#[derive(Debug, PartialEq, NomBE, Clone)]
pub struct CapabilityAs4 {
    header: CapabilityHeader,
    typ: CapabilityType,
    length: u8,
    pub asn: u32,
}

impl CapabilityAs4 {
    pub fn new(asn: u32) -> Self {
        Self {
            header: CapabilityHeader::new(6),
            typ: CapabilityType::As4,
            length: 4,
            asn,
        }
    }
}

#[derive(Debug, PartialEq, NomBE, Clone)]
pub struct CapabilityDynamicCapability {
    header: CapabilityHeader,
    typ: CapabilityType,
    length: u8,
}

impl CapabilityDynamicCapability {
    pub fn new() -> Self {
        Self {
            header: CapabilityHeader::new(2),
            typ: CapabilityType::DynamicCapability,
            length: 0,
        }
    }
}

#[derive(Debug, PartialEq, NomBE, Clone)]
pub struct CapabilityAddPath {
    header: CapabilityHeader,
    typ: CapabilityType,
    length: u8,
    afi: Afi,
    safi: Safi,
    send_receive: u8,
}

impl CapabilityAddPath {
    pub fn new(afi: Afi, safi: Safi, send_receive: u8) -> Self {
        Self {
            header: CapabilityHeader::new(2),
            typ: CapabilityType::AddPath,
            length: 4,
            afi,
            safi,
            send_receive,
        }
    }
}

#[derive(Debug, PartialEq, NomBE, Clone)]
pub struct CapabilityGracefulRestart {
    header: CapabilityHeader,
    restart_time: u32,
}

impl CapabilityGracefulRestart {
    pub fn new(restart_time: u32) -> Self {
        Self {
            header: CapabilityHeader::new(4),
            restart_time,
        }
    }
}

#[derive(Debug, PartialEq, NomBE, Clone)]
pub struct CapabilityExtendedMessage {
    header: CapabilityHeader,
    typ: CapabilityType,
    length: u8,
}

impl CapabilityExtendedMessage {
    pub fn new() -> Self {
        Self {
            header: CapabilityHeader::new(2),
            typ: CapabilityType::ExtendedMessage,
            length: 0,
        }
    }
}

#[derive(Debug, PartialEq, NomBE, Clone)]
pub struct CapabilityEnhancedRouteRefresh {
    header: CapabilityHeader,
    typ: CapabilityType,
    length: u8,
}

impl CapabilityEnhancedRouteRefresh {
    pub fn new() -> Self {
        Self {
            header: CapabilityHeader::new(2),
            typ: CapabilityType::EnhancedRouteRefresh,
            length: 0,
        }
    }
}

#[derive(Debug, PartialEq, NomBE, Clone)]
pub struct LLGRValue {
    afi: Afi,
    safi: Safi,
    flags_stale_time: u32,
}

#[derive(Debug, PartialEq, NomBE, Clone)]
pub struct CapabilityLLGR {
    header: CapabilityHeader,
    typ: CapabilityType,
    length: u8,
    #[nom(Ignore)]
    values: Vec<LLGRValue>,
}

impl CapabilityLLGR {
    pub fn new(hostname: &String, domain: &String) -> Self {
        Self {
            header: CapabilityHeader::new(2),
            typ: CapabilityType::EnhancedRouteRefresh,
            length: 0,
            values: Vec::new(),
        }
    }
}

#[derive(Debug, PartialEq, NomBE, Clone)]
pub struct CapabilityFQDN {
    header: CapabilityHeader,
    typ: CapabilityType,
    length: u8,
    #[nom(Ignore)]
    pub hostname: Vec<u8>,
    #[nom(Ignore)]
    pub domain: Vec<u8>,
}

impl CapabilityFQDN {
    pub fn new(hostname: &String, domain: &String) -> Self {
        Self {
            header: CapabilityHeader::new(2),
            typ: CapabilityType::EnhancedRouteRefresh,
            length: 0,
            hostname: hostname.clone().into_bytes(),
            domain: domain.clone().into_bytes(),
        }
    }
}

#[derive(Debug, PartialEq, NomBE, Clone)]
pub struct CapabilitySoftwareVersion {
    header: CapabilityHeader,
    typ: CapabilityType,
    pub length: u8,
    #[nom(Ignore)]
    pub version: Vec<u8>,
}

impl CapabilitySoftwareVersion {
    pub fn new(version: Vec<u8>) -> Self {
        Self {
            header: CapabilityHeader::new(2),
            typ: CapabilityType::AddPath,
            length: version.len() as u8,
            version,
        }
    }
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
