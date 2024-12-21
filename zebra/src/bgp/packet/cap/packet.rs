use bytes::BytesMut;
use nom_derive::*;

use super::*;

#[derive(Debug, Default, PartialEq, NomBE, Clone)]
pub struct CapabilityHeader {
    pub code: u8,
    pub length: u8,
}

impl CapabilityHeader {
    pub fn new(code: CapabilityCode, length: u8) -> Self {
        Self {
            code: code.into(),
            length,
        }
    }
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
