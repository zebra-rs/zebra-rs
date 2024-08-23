use super::BgpHeader;
use crate::bgp::BGP_VERSION;
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

#[derive(Debug, PartialEq, NomBE)]
pub struct OpenExtended {
    pub non_ext_op_type: u8,
    pub ext_opt_parm_len: u16,
}

#[derive(Debug, Eq, PartialEq, NomBE, Clone)]
pub struct CapabilityCode(pub u8);

newtype_enum! {
    impl display CapabilityCode {
        MultiProtocol = 1,
        RouteRefresh = 2,
        ExtendedNextHop = 5,
        ExtendedMessage = 6,
        Role = 9,
        GracefulRestart = 64,
        As4 = 65,
        DynamicCapability = 67,
        AddPath = 69,
        EnhancedRouteRefresh = 70,
        LLGR = 71,
        FQDN = 73,
        SoftwareVersion = 75,
        PathLimit = 76,
        RouteRefreshCisco = 128,
    }
}

#[derive(Debug, PartialEq, Clone)]
#[allow(clippy::upper_case_acronyms)]
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
    PathLimit(CapabilityPathLimit),
    Unknown(CapabilityUnknown),
}

macro_rules! cap_header_encode {
    ($m:expr, $buf:expr) => {
        $buf.put_u8(CAPABILITY_CODE);
        $buf.put_u8($m.header.length + 2);
        $buf.put_u8($m.header.code);
        $buf.put_u8($m.header.length);
    };
}

impl CapabilityPacket {
    pub fn encode(&self, buf: &mut BytesMut) {
        match self {
            Self::MultiProtocol(m) => {
                cap_header_encode!(m, buf);
                buf.put_u16(m.afi.0);
                buf.put_u8(0);
                buf.put_u8(m.safi.0);
            }
            Self::RouteRefresh(m) => {
                cap_header_encode!(m, buf);
            }
            Self::ExtendedMessage(m) => {
                cap_header_encode!(m, buf);
            }
            Self::As4(m) => {
                cap_header_encode!(m, buf);
                buf.put_u32(m.asn);
            }
            Self::DynamicCapability(m) => {
                cap_header_encode!(m, buf);
            }
            Self::AddPath(m) => {
                cap_header_encode!(m, buf);
            }
            Self::GracefulRestart(m) => {
                cap_header_encode!(m, buf);
                buf.put_u32(m.restart_time);
            }
            Self::EnhancedRouteRefresh(m) => {
                cap_header_encode!(m, buf);
            }
            Self::LLGR(m) => {
                cap_header_encode!(m, buf);
            }
            Self::FQDN(m) => {
                cap_header_encode!(m, buf);
                buf.put_u8(m.hostname.len() as u8);
                buf.put(&m.hostname[..]);
                buf.put_u8(m.domain.len() as u8);
                buf.put(&m.domain[..]);
            }
            Self::SoftwareVersion(m) => {
                cap_header_encode!(m, buf);
            }
            Self::PathLimit(m) => {
                cap_header_encode!(m, buf);
                for v in m.values.iter() {
                    buf.put_u16(v.afi.0);
                    buf.put_u8(v.safi.0);
                    buf.put_u16(v.path_limit);
                }
            }
            Self::Unknown(m) => {
                cap_header_encode!(m, buf);
                buf.put(&m.data[..]);
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
    pub fn new(code: CapabilityCode, length: u8) -> Self {
        Self {
            code: code.0,
            length,
        }
    }

    // pub fn encode(&self, buf: &mut BytesMut) {
    //     buf.put_u8(self.code);
    //     buf.put_u8(self.length);
    // }
}

#[derive(Debug, PartialEq, NomBE, Clone)]
pub struct CapabilityMultiProtocol {
    header: CapabilityHeader,
    afi: Afi,
    res: u8,
    safi: Safi,
}

impl CapabilityMultiProtocol {
    pub fn new(afi: &Afi, safi: &Safi) -> Self {
        Self {
            header: CapabilityHeader::new(CapabilityCode::MultiProtocol, 4),
            afi: afi.clone(),
            res: 0,
            safi: safi.clone(),
        }
    }
}

#[derive(Debug, PartialEq, NomBE, Clone)]
pub struct CapabilityRouteRefresh {
    header: CapabilityHeader,
}

impl CapabilityRouteRefresh {
    pub fn new(typ: CapabilityCode) -> Self {
        Self {
            header: CapabilityHeader::new(typ, 0),
        }
    }
}

#[derive(Debug, PartialEq, NomBE, Clone)]
pub struct CapabilityAs4 {
    header: CapabilityHeader,
    pub asn: u32,
}

impl CapabilityAs4 {
    pub fn new(asn: u32) -> Self {
        Self {
            header: CapabilityHeader::new(CapabilityCode::As4, 4),
            asn,
        }
    }
}

#[derive(Debug, PartialEq, NomBE, Clone)]
pub struct CapabilityDynamicCapability {
    header: CapabilityHeader,
}

impl CapabilityDynamicCapability {
    pub fn new() -> Self {
        Self {
            header: CapabilityHeader::new(CapabilityCode::DynamicCapability, 0),
        }
    }
}

#[derive(Debug, PartialEq, NomBE, Clone)]
pub struct AddPathValue {
    afi: Afi,
    safi: Safi,
    send_receive: u8,
}

#[derive(Debug, PartialEq, NomBE, Clone)]
pub struct CapabilityAddPath {
    pub header: CapabilityHeader,
    #[nom(Ignore)]
    pub values: Vec<AddPathValue>,
}

impl CapabilityAddPath {
    pub fn new(afi: Afi, safi: Safi, send_receive: u8) -> Self {
        let value = AddPathValue {
            afi,
            safi,
            send_receive,
        };
        Self {
            header: CapabilityHeader::new(CapabilityCode::AddPath, 4),
            values: vec![value],
        }
    }
}

#[derive(Debug, PartialEq, NomBE, Clone)]
pub struct CapabilityGracefulRestart {
    pub header: CapabilityHeader,
    #[nom(Ignore)]
    pub restart_time: u32,
}

impl CapabilityGracefulRestart {
    pub fn new(restart_time: u32) -> Self {
        Self {
            header: CapabilityHeader::new(CapabilityCode::GracefulRestart, 4),
            restart_time,
        }
    }
}

#[derive(Debug, PartialEq, NomBE, Clone)]
pub struct CapabilityExtendedMessage {
    header: CapabilityHeader,
}

impl CapabilityExtendedMessage {
    pub fn new() -> Self {
        Self {
            header: CapabilityHeader::new(CapabilityCode::ExtendedMessage, 0),
        }
    }
}

#[derive(Debug, PartialEq, NomBE, Clone)]
pub struct CapabilityEnhancedRouteRefresh {
    header: CapabilityHeader,
}

impl CapabilityEnhancedRouteRefresh {
    pub fn new() -> Self {
        Self {
            header: CapabilityHeader::new(CapabilityCode::EnhancedRouteRefresh, 0),
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
    pub header: CapabilityHeader,
    #[nom(Ignore)]
    pub values: Vec<LLGRValue>,
}

impl CapabilityLLGR {
    pub fn new() -> Self {
        Self {
            header: CapabilityHeader::new(CapabilityCode::EnhancedRouteRefresh, 0),
            values: Vec::new(),
        }
    }
}

#[derive(Debug, PartialEq, NomBE, Clone)]
pub struct CapabilityFQDN {
    header: CapabilityHeader,
    #[nom(Ignore)]
    pub hostname: Vec<u8>,
    #[nom(Ignore)]
    pub domain: Vec<u8>,
}

impl CapabilityFQDN {
    pub fn new(hostname: &str, domain: &str) -> Self {
        Self {
            header: CapabilityHeader::new(
                CapabilityCode::EnhancedRouteRefresh,
                (2 + hostname.len() + domain.len()) as u8,
            ),
            hostname: hostname.into(),
            domain: domain.into(),
        }
    }
}

#[derive(Debug, PartialEq, NomBE, Clone)]
pub struct CapabilitySoftwareVersion {
    pub header: CapabilityHeader,
    #[nom(Ignore)]
    pub version: Vec<u8>,
}

impl CapabilitySoftwareVersion {
    pub fn new(version: Vec<u8>) -> Self {
        Self {
            header: CapabilityHeader::new(CapabilityCode::SoftwareVersion, 1 + version.len() as u8),
            version,
        }
    }
}

#[derive(Debug, PartialEq, NomBE, Clone)]
pub struct PathLimitValue {
    pub afi: Afi,
    pub safi: Safi,
    pub path_limit: u16,
}

#[derive(Debug, PartialEq, NomBE, Clone)]
pub struct CapabilityPathLimit {
    pub header: CapabilityHeader,
    #[nom(Ignore)]
    pub values: Vec<PathLimitValue>,
}

impl CapabilityPathLimit {
    pub fn new(afi: Afi, safi: Safi, path_limit: u16) -> Self {
        let value = PathLimitValue {
            afi,
            safi,
            path_limit,
        };
        Self {
            header: CapabilityHeader::new(CapabilityCode::PathLimit, 5),
            values: vec![value],
        }
    }
}

#[derive(Debug, PartialEq, NomBE, Clone)]
pub struct CapabilityUnknown {
    pub header: CapabilityHeader,
    #[nom(Ignore)]
    pub data: Vec<u8>,
}

impl OpenPacket {
    pub fn new(
        header: BgpHeader,
        asn: u16,
        hold_time: u16,
        router_id: &Ipv4Addr,
        caps: Vec<CapabilityPacket>,
    ) -> OpenPacket {
        OpenPacket {
            header,
            version: BGP_VERSION,
            asn,
            hold_time,
            bgp_id: router_id.octets(),
            opt_param_len: 0,
            caps,
        }
    }
}
