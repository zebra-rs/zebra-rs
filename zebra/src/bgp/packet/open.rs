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

impl CapabilityPacket {
    pub fn encode(&self, buf: &mut BytesMut) {
        match self {
            Self::MultiProtocol(m) => {
                m.emit(buf, false);
            }
            Self::RouteRefresh(m) => {
                m.emit(buf, false);
            }
            Self::ExtendedMessage(m) => {
                m.emit(buf, false);
            }
            Self::As4(m) => {
                m.emit(buf, false);
            }
            Self::DynamicCapability(m) => {
                m.emit(buf, false);
            }
            Self::AddPath(m) => {
                m.emit(buf, false);
            }
            Self::GracefulRestart(m) => {
                m.emit(buf, false);
            }
            Self::EnhancedRouteRefresh(m) => {
                m.emit(buf, false);
            }
            Self::Llgr(m) => {
                m.emit(buf, false);
            }
            Self::Fqdn(m) => {
                m.emit(buf, false);
            }
            Self::SoftwareVersion(m) => {
                m.emit(buf, false);
            }
            Self::PathLimit(m) => {
                m.emit(buf, false);
            }
            Self::Unknown(m) => {
                m.emit(buf, false);
            }
        }
    }
}

#[derive(Debug, Default, PartialEq, NomBE, Clone)]
pub struct CapabilityHeader {
    pub code: u8,
    pub length: u8,
}

pub trait Emit {
    fn code(&self) -> CapabilityCode;

    fn len(&self) -> u8 {
        0
    }

    fn emit_value(&self, buf: &mut BytesMut) {}

    fn emit(&self, buf: &mut BytesMut, opt: bool) {
        if !opt {
            buf.put_u8(CAPABILITY_CODE);
            buf.put_u8(self.len() + 2);
        }
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
    afi: Afi2,
    res: u8,
    safi: Safi2,
}

impl CapabilityMultiProtocol {
    pub fn new(afi: &Afi2, safi: &Safi2) -> Self {
        Self {
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

#[derive(Debug, Default, PartialEq, NomBE, Clone)]
pub struct CapabilityRouteRefresh {}

impl Emit for CapabilityRouteRefresh {
    fn code(&self) -> CapabilityCode {
        CapabilityCode::RouteRefresh
    }
}

#[derive(Debug, PartialEq, NomBE, Clone)]
pub struct CapabilityAs4 {
    pub asn: u32,
}

impl CapabilityAs4 {
    pub fn new(asn: u32) -> Self {
        Self { asn }
    }
}

impl Emit for CapabilityAs4 {
    fn code(&self) -> CapabilityCode {
        CapabilityCode::As4
    }

    fn len(&self) -> u8 {
        4
    }

    fn emit_value(&self, buf: &mut BytesMut) {
        buf.put_u32(self.asn);
    }
}

#[derive(Debug, Default, PartialEq, NomBE, Clone)]
pub struct CapabilityDynamicCapability {}

impl Emit for CapabilityDynamicCapability {
    fn code(&self) -> CapabilityCode {
        CapabilityCode::DynamicCapability
    }
}

#[derive(Debug, PartialEq, NomBE, Clone)]
pub struct AddPathValue {
    afi: Afi2,
    safi: Safi2,
    send_receive: u8,
}

#[derive(Debug, PartialEq, NomBE, Clone)]
pub struct CapabilityAddPath {
    pub values: Vec<AddPathValue>,
}

impl CapabilityAddPath {
    pub fn new(afi: Afi2, safi: Safi2, send_receive: u8) -> Self {
        Self {
            values: vec![AddPathValue {
                afi,
                safi,
                send_receive,
            }],
        }
    }
}

impl Emit for CapabilityAddPath {
    fn code(&self) -> CapabilityCode {
        CapabilityCode::AddPath
    }

    fn len(&self) -> u8 {
        (self.values.len() * 4) as u8
    }

    fn emit_value(&self, buf: &mut BytesMut) {
        for val in self.values.iter() {
            buf.put_u16(val.afi.into());
            buf.put_u8(val.safi.into());
            buf.put_u8(val.send_receive);
        }
    }
}

#[derive(Debug, PartialEq, NomBE, Clone)]
pub struct CapabilityGracefulRestart {
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
        Self { restart_time }
    }
}

impl Emit for CapabilityGracefulRestart {
    fn code(&self) -> CapabilityCode {
        CapabilityCode::GracefulRestart
    }

    fn len(&self) -> u8 {
        4
    }

    fn emit_value(&self, buf: &mut BytesMut) {
        buf.put_u32(self.restart_time);
    }
}

#[derive(Debug, Default, PartialEq, NomBE, Clone)]
pub struct CapabilityExtendedMessage {}

impl Emit for CapabilityExtendedMessage {
    fn code(&self) -> CapabilityCode {
        CapabilityCode::ExtendedMessage
    }
}

#[derive(Debug, Default, PartialEq, NomBE, Clone)]
pub struct CapabilityEnhancedRouteRefresh {}

impl Emit for CapabilityEnhancedRouteRefresh {
    fn code(&self) -> CapabilityCode {
        CapabilityCode::EnhancedRouteRefresh
    }
}

#[derive(Debug, Default, PartialEq, NomBE, Clone)]
pub struct CapabilityLlgr {
    pub values: Vec<LLGRValue>,
}

#[derive(Debug, PartialEq, NomBE, Clone)]
pub struct LLGRValue {
    afi: Afi2,
    safi: Safi2,
    flags_stale_time: u32,
}

impl Emit for CapabilityLlgr {
    fn code(&self) -> CapabilityCode {
        CapabilityCode::Llgr
    }

    fn len(&self) -> u8 {
        (self.values.len() * 7) as u8
    }

    fn emit_value(&self, buf: &mut BytesMut) {
        for val in self.values.iter() {
            buf.put_u16(val.afi.into());
            buf.put_u8(val.safi.into());
            buf.put_u32(val.flags_stale_time);
        }
    }
}

#[derive(Debug, Default, PartialEq, Clone)]
pub struct CapabilityFqdn {
    pub hostname: Vec<u8>,
    pub domain: Vec<u8>,
}

impl CapabilityFqdn {
    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, hostname_len) = be_u8(input)?;
        let (input, hostname) = take(hostname_len)(input)?;
        let hostname = hostname.to_vec();
        let (input, domain_len) = be_u8(input)?;
        let (input, domain) = take(domain_len)(input)?;
        let domain = domain.to_vec();

        let fqdn = Self { hostname, domain };
        Ok((input, fqdn))
    }
}

impl CapabilityFqdn {
    pub fn new(hostname: &str, domain: &str) -> Self {
        Self {
            hostname: hostname.into(),
            domain: domain.into(),
        }
    }
}

impl Emit for CapabilityFqdn {
    fn code(&self) -> CapabilityCode {
        CapabilityCode::Fqdn
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

#[derive(Debug, Default, PartialEq, NomBE, Clone)]
pub struct CapabilitySoftwareVersion {
    pub version: Vec<u8>,
}

impl CapabilitySoftwareVersion {
    pub fn new(version: &str) -> Self {
        Self {
            version: version.into(),
        }
    }
}

impl Emit for CapabilitySoftwareVersion {
    fn code(&self) -> CapabilityCode {
        CapabilityCode::SoftwareVersion
    }

    fn len(&self) -> u8 {
        self.version.len() as u8
    }

    fn emit_value(&self, buf: &mut BytesMut) {
        buf.put(&self.version[..]);
    }
}

#[derive(Debug, PartialEq, NomBE, Clone)]
pub struct CapabilityPathLimit {
    pub values: Vec<PathLimitValue>,
}

#[derive(Debug, PartialEq, NomBE, Clone)]
pub struct PathLimitValue {
    pub afi: Afi2,
    pub safi: Safi2,
    pub path_limit: u16,
}

impl CapabilityPathLimit {
    pub fn new(afi: Afi2, safi: Safi2, path_limit: u16) -> Self {
        Self {
            values: vec![PathLimitValue {
                afi,
                safi,
                path_limit,
            }],
        }
    }
}

impl Emit for CapabilityPathLimit {
    fn code(&self) -> CapabilityCode {
        CapabilityCode::PathLimit
    }

    fn len(&self) -> u8 {
        (self.values.len() * 5) as u8
    }

    fn emit_value(&self, buf: &mut BytesMut) {
        for val in self.values.iter() {
            buf.put_u16(val.afi.into());
            buf.put_u8(val.safi.into());
            buf.put_u16(val.path_limit);
        }
    }
}

#[derive(Debug, PartialEq, NomBE, Clone)]
pub struct CapabilityUnknown {
    pub header: CapabilityHeader,
    pub data: Vec<u8>,
}

impl Default for CapabilityUnknown {
    fn default() -> Self {
        Self {
            header: CapabilityHeader::new(CapabilityCode::AddPath, 0),
            data: Vec::new(),
        }
    }
}

impl Emit for CapabilityUnknown {
    fn code(&self) -> CapabilityCode {
        CapabilityCode::Unknown(100)
    }

    fn len(&self) -> u8 {
        self.data.len() as u8
    }

    fn emit_value(&self, buf: &mut BytesMut) {
        buf.put(&self.data[..]);
    }
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
