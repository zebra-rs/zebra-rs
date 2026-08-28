use std::fmt;

use bytes::BytesMut;
use nom::IResult;
use nom::error::{ErrorKind, make_error};
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
    #[nom(Selector = "CapCode::ExtendedNextHop")]
    ExtendedNextHop(CapExtendedNextHop),
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
    #[nom(Selector = "CapCode::Role")]
    Role(CapRole),
    #[nom(Selector = "_")]
    Unknown(CapUnknown),
}

impl CapabilityPacket {
    pub fn parse_cap(input: &[u8]) -> IResult<&[u8], CapabilityPacket> {
        let (input, cap_header) = CapabilityHeader::parse_be(input)?;
        let len = cap_header.length as usize;
        let (input, cap) = packet_utils::safe_split_at(input, len)?;
        // RFC 9234 §4.1: the Role capability value is exactly one octet.
        // Any other length is malformed, but failing the whole OPEN over it
        // would reset a session RFC 5492 says to keep (unusable
        // capabilities are ignored). Route it through the opaque `Unknown`
        // passthrough instead, so the session logic sees "no role
        // received" — which strict mode then rejects on its own terms.
        let mut code: CapCode = cap_header.code.into();
        if code == CapCode::Role && len != 1 {
            code = CapCode::Unknown(cap_header.code);
        }
        let (remaining, mut cap) = CapabilityPacket::parse_be(cap, code)?;
        if !remaining.is_empty() {
            return Err(nom::Err::Error(make_error(input, ErrorKind::LengthValue)));
        }
        // The opaque `Unknown` passthrough parses only the value bytes, so carry
        // the real capability code (already consumed into `cap_header`) across so
        // display and re-emit preserve it.
        if let CapabilityPacket::Unknown(unknown) = &mut cap {
            unknown.code = cap_header.code;
        }
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
            Self::ExtendedNextHop(m) => {
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
            Self::Role(m) => {
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
            Self::ExtendedNextHop(v) => write!(f, "{}", v),
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
            Self::Role(v) => write!(f, "{}", v),
            Self::Unknown(v) => write!(f, "{}", v),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CapEmit;

    // A one-octet capability with an unassigned code (200) has no
    // `CapabilityPacket` arm, so it must fall through to the opaque `Unknown`
    // passthrough and parse without error (RFC 5492 requires ignoring unknown
    // capabilities). Regression: the old `CapUnknown` re-read a 2-byte header
    // from the 1-byte value and failed the whole OPEN. (This test used the
    // RFC 9234 Role capability, code 9, as its example until that grew a
    // typed arm — see `role_capability_parses_to_typed_variant`.)
    #[test]
    fn unknown_short_capability_parses_and_round_trips() {
        let wire = [200u8, 1, 0x03]; // code=200 (unassigned), len=1
        let (rest, cap) = CapabilityPacket::parse_cap(&wire).unwrap();
        assert!(rest.is_empty());
        let CapabilityPacket::Unknown(u) = &cap else {
            panic!("expected Unknown, got {cap:?}");
        };
        assert_eq!(u.code, 200);
        assert_eq!(u.data, vec![0x03]);

        // Grouped re-emit (code + length + value) preserves the code and value.
        let mut buf = BytesMut::new();
        u.emit(&mut buf, true);
        assert_eq!(&buf[..], &wire[..]);
    }

    // A zero-length unknown capability (code with no value) must also parse
    // rather than error on the missing header.
    #[test]
    fn unknown_zero_length_capability_parses() {
        let wire = [200u8, 0]; // code=200, len=0, no value
        let (rest, cap) = CapabilityPacket::parse_cap(&wire).unwrap();
        assert!(rest.is_empty());
        let CapabilityPacket::Unknown(u) = &cap else {
            panic!("expected Unknown");
        };
        assert_eq!(u.code, 200);
        assert!(u.data.is_empty());
    }

    // RFC 9234 §4.1 Role capability: code 9, length 1, one value octet.
    #[test]
    fn role_capability_parses_to_typed_variant() {
        let wire = [9u8, 1, 0x03]; // Customer
        let (rest, cap) = CapabilityPacket::parse_cap(&wire).unwrap();
        assert!(rest.is_empty());
        let CapabilityPacket::Role(role) = &cap else {
            panic!("expected Role, got {cap:?}");
        };
        assert_eq!(role.role(), Some(crate::BgpRole::Customer));

        let mut buf = BytesMut::new();
        cap.encode(&mut buf);
        assert_eq!(&buf[..], &[2u8, 3, 9, 1, 0x03]);
    }

    // A Role capability whose length is not 1 is malformed (RFC 9234 §4.1).
    // It must neither fail the OPEN nor surface as a role: it lands in the
    // opaque `Unknown` passthrough with its code preserved.
    #[test]
    fn role_capability_wrong_length_falls_to_unknown() {
        for wire in [&[9u8, 0][..], &[9u8, 2, 0x03, 0x00][..]] {
            let (rest, cap) = CapabilityPacket::parse_cap(wire).unwrap();
            assert!(rest.is_empty());
            let CapabilityPacket::Unknown(u) = &cap else {
                panic!("expected Unknown for {wire:?}, got {cap:?}");
            };
            assert_eq!(u.code, 9);
            assert_eq!(u.data.len(), wire.len() - 2);
        }
    }

    // A known capability still routes to its typed variant, and the Unknown
    // stamping does not disturb it.
    #[test]
    fn known_capability_still_parses() {
        // As4 capability: code 65, length 4, ASN 0x0000FDE8 (65000).
        let wire = [65u8, 4, 0x00, 0x00, 0xfd, 0xe8];
        let (rest, cap) = CapabilityPacket::parse_cap(&wire).unwrap();
        assert!(rest.is_empty());
        let CapabilityPacket::As4(a) = &cap else {
            panic!("expected As4, got {cap:?}");
        };
        assert_eq!(a.asn, 65000);
    }
}
