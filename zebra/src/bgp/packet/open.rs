use bytes::BufMut;
use bytes::BytesMut;
use nom::bytes::complete::take;
use nom::number::complete::{be_u16, be_u32, be_u8};
use nom::IResult;
use nom_derive::*;
use rusticata_macros::newtype_enum;
use std::net::Ipv4Addr;

use super::BgpHeader;
use super::CapabilityCode;
use super::{Afi2, Safi2};
use crate::bgp::BGP_VERSION;
use crate::bgp::{Afi, Safi};

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

#[derive(Debug, PartialEq, Clone, NomBE)]
#[nom(Selector = "CapabilityCode")]
pub enum CapabilityPacket {
    #[nom(Selector = "CapabilityCode::MultiProtocol")]
    MultiProtocol(CapabilityMultiProtocol),
    #[nom(Selector = "CapabilityCode::RouteRefresh")]
    RouteRefresh(CapabilityRouteRefresh),
    #[nom(Selector = "CapabilityCode::ExtendedMessage")]
    ExtendedMessage(CapabilityExtendedMessage),
    #[nom(Selector = "CapabilityCode::GracefulRestart")]
    GracefulRestart(CapabilityGracefulRestart),
    #[nom(Selector = "CapabilityCode::As4")]
    As4(CapabilityAs4),
    #[nom(Selector = "CapabilityCode::DynamicCapability")]
    DynamicCapability(CapabilityDynamicCapability),
    #[nom(Selector = "CapabilityCode::AddPath")]
    AddPath(CapabilityAddPath),
    #[nom(Selector = "CapabilityCode::EnhancedRouteRefresh")]
    EnhancedRouteRefresh(CapabilityEnhancedRouteRefresh),
    #[nom(Selector = "CapabilityCode::Llgr")]
    Llgr(CapabilityLlgr),
    #[nom(Selector = "CapabilityCode::Fqdn")]
    Fqdn(CapabilityFqdn),
    #[nom(Selector = "CapabilityCode::SoftwareVersion")]
    SoftwareVersion(CapabilitySoftwareVersion),
    #[nom(Selector = "CapabilityCode::PathLimit")]
    PathLimit(CapabilityPathLimit),
    #[nom(Selector = "_")]
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
                println!("XXX emit");
                m.emit(buf);
                // cap_header_encode!(m, buf);
                // buf.put_u16(m.afi.0);
                // buf.put_u8(0);
                // buf.put_u8(m.safi.0);
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
            Self::Llgr(m) => {
                cap_header_encode!(m, buf);
            }
            Self::Fqdn(m) => {
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

pub trait Emit {
    fn code(&self) -> CapabilityCode;
    fn len(&self) -> u8;
    fn emit_value(&self, buf: &mut BytesMut);
    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(CAPABILITY_CODE);
        buf.put_u8(self.len() + 2);
        buf.put_u8(self.code().into());
        buf.put_u8(self.len());
        self.emit_value(buf);
    }
}

impl CapabilityHeader {
    pub fn new(code: CapabilityCode, length: u8) -> Self {
        Self {
            code: code.into(),
            length,
        }
    }
}

#[derive(Debug, PartialEq, NomBE, Clone)]
pub struct CapabilityMultiProtocol {
    header: CapabilityHeader,
    afi: Afi2,
    res: u8,
    safi: Safi2,
}

impl CapabilityMultiProtocol {
    pub fn new(afi: &Afi2, safi: &Safi2) -> Self {
        Self {
            header: CapabilityHeader::new(CapabilityCode::MultiProtocol, 4),
            afi: *afi,
            res: 0,
            safi: *safi,
        }
    }
}

impl Emit for CapabilityMultiProtocol {
    fn code(&self) -> CapabilityCode {
        CapabilityCode::MultiProtocol
    }

    fn len(&self) -> u8 {
        4
    }

    fn emit_value(&self, buf: &mut BytesMut) {
        buf.put_u16(self.afi.into());
        buf.put_u8(0);
        buf.put_u8(self.safi.into());
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

impl Default for CapabilityDynamicCapability {
    fn default() -> Self {
        Self::new()
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
    #[nom(Parse = "parse_restart_time")]
    pub restart_time: u32,
}

pub fn parse_restart_time(input: &[u8]) -> IResult<&[u8], u32> {
    if input.len() == 2 {
        let (input, val) = be_u16(input)?;
        Ok((input, val as u32))
    } else {
        let (input, val) = be_u32(input)?;
        Ok((input, val))
    }
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

impl Default for CapabilityExtendedMessage {
    fn default() -> Self {
        Self::new()
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

impl Default for CapabilityEnhancedRouteRefresh {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, PartialEq, NomBE, Clone)]
pub struct LLGRValue {
    afi: Afi,
    safi: Safi,
    flags_stale_time: u32,
}

#[derive(Debug, PartialEq, NomBE, Clone)]
pub struct CapabilityLlgr {
    pub header: CapabilityHeader,
    pub values: Vec<LLGRValue>,
}

impl CapabilityLlgr {
    pub fn new() -> Self {
        Self {
            header: CapabilityHeader::new(CapabilityCode::EnhancedRouteRefresh, 0),
            values: Vec::new(),
        }
    }
}

impl Default for CapabilityLlgr {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct CapabilityFqdn {
    header: CapabilityHeader,
    pub hostname: Vec<u8>,
    pub domain: Vec<u8>,
}

impl CapabilityFqdn {
    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, header) = CapabilityHeader::parse_be(input)?;

        let (input, hostname_len) = be_u8(input)?;
        let (input, hostname) = take(hostname_len)(input)?;
        let hostname = hostname.to_vec();
        let (input, domain_len) = be_u8(input)?;
        let (input, domain) = take(domain_len)(input)?;
        let domain = domain.to_vec();

        let fqdn = Self {
            header,
            hostname,
            domain,
        };
        Ok((input, fqdn))
    }
}

impl CapabilityFqdn {
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
