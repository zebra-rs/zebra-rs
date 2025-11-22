use std::fmt;

use bytes::BytesMut;
use nom::IResult;
use nom_derive::*;

use super::*;

#[derive(Debug, Default, PartialEq, NomBE, Clone)]
pub struct CapabilityHeader {
    pub code: u8,
    pub length: u8,
}

impl CapabilityHeader {
    pub fn new(code: CapCode, length: u8) -> Self {
        Self {
            code: code.into(),
            length,
        }
    }
}

#[derive(Debug, PartialEq, Clone, NomBE)]
#[nom(Selector = "CapCode")]
pub enum CapabilityPacket {
    #[nom(Selector = "CapCode::MultiProtocol")]
    MultiProtocol(CapMultiProtocol),
    #[nom(Selector = "CapCode::RouteRefresh")]
    RouteRefresh(CapRefresh),
    #[nom(Selector = "CapCode::ExtendedMessage")]
    ExtendedMessage(CapExtended),
    #[nom(Selector = "CapCode::GracefulRestart")]
    GracefulRestart(CapRestart),
    #[nom(Selector = "CapCode::As4")]
    As4(CapAs4),
    #[nom(Selector = "CapCode::DynamicCapability")]
    DynamicCapability(CapDynamic),
    #[nom(Selector = "CapCode::AddPath")]
    AddPath(CapAddPath),
    #[nom(Selector = "CapCode::EnhancedRouteRefresh")]
    EnhancedRouteRefresh(CapEnhancedRefresh),
    #[nom(Selector = "CapCode::Llgr")]
    Llgr(CapLlgr),
    #[nom(Selector = "CapCode::Fqdn")]
    Fqdn(CapFqdn),
    #[nom(Selector = "CapCode::SoftwareVersion")]
    SoftwareVersion(CapVersion),
    #[nom(Selector = "CapCode::PathLimit")]
    PathLimit(CapPathLimit),
    #[nom(Selector = "CapCode::RouteRefreshCisco")]
    RouteRefreshCisco(CapRefreshCisco),
    #[nom(Selector = "CapCode::LlgrOld")]
    LlgrOld(CapLlgr),
    #[nom(Selector = "_")]
    Unknown(CapUnknown),
}

impl CapabilityPacket {
    pub fn parse_cap(input: &[u8]) -> IResult<&[u8], CapabilityPacket> {
        let (input, cap_header) = CapabilityHeader::parse_be(input)?;
        let (cap, input) = input.split_at(cap_header.length as usize);
        let (_, cap) = CapabilityPacket::parse_be(cap, cap_header.code.into())?;
        Ok((input, cap))
    }

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
            Self::RouteRefreshCisco(m) => {
                m.emit(buf, false);
            }
            Self::LlgrOld(m) => {
                m.emit(buf, false);
            }
            Self::Unknown(m) => {
                m.emit(buf, false);
            }
        }
    }
}

impl fmt::Display for CapabilityPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MultiProtocol(v) => write!(f, "{}", v),
            Self::RouteRefresh(v) => write!(f, "{}", v),
            Self::ExtendedMessage(v) => write!(f, "{}", v),
            Self::GracefulRestart(v) => write!(f, "{}", v),
            Self::As4(v) => write!(f, "{}", v),
            Self::DynamicCapability(v) => write!(f, "{}", v),
            Self::AddPath(v) => write!(f, "{}", v),
            Self::EnhancedRouteRefresh(v) => write!(f, "{}", v),
            Self::Llgr(v) => write!(f, "{}", v),
            Self::Fqdn(v) => write!(f, "{}", v),
            Self::SoftwareVersion(v) => write!(f, "{}", v),
            Self::PathLimit(v) => write!(f, "{}", v),
            Self::RouteRefreshCisco(v) => write!(f, "{}", v),
            Self::LlgrOld(v) => write!(f, "{}", v),
            Self::Unknown(v) => write!(f, "{}", v),
        }
    }
}
