//! BGP MUP (Mobile User Plane) SAFI 85 NLRI — Phase 2 dispatch shell.
//!
//! Implements the outer NLRI envelope from RFC 9833 §3.1:
//!
//! ```text
//! +------------------------------------+
//! |  Architecture Type (1 octet)       |
//! +------------------------------------+
//! |  Route Type (2 octets)             |
//! +------------------------------------+
//! |  Length (1 octet, payload octets)  |
//! +------------------------------------+
//! |  Route Type specific (variable)    |
//! +------------------------------------+
//! ```
//!
//! Per-route-type bodies are intentionally kept opaque (`Vec<u8>`) at
//! this phase; typed decoders land in Phases 4–6. Add-Path follows
//! the EVPN convention used elsewhere in this crate: a non-zero `id`
//! signals a 4-octet Path Identifier (RFC 7911) is prepended on the
//! wire.

use bytes::{BufMut, BytesMut};
use nom::IResult;
use nom::Parser;
use nom::bytes::complete::take;
use nom::number::complete::{be_u8, be_u16, be_u32};

use crate::ParseNlri;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MupArchitectureType {
    /// 3GPP 5G (RFC 9833 §3.1.1).
    Gpp5g,
    Unknown(u8),
}

impl From<MupArchitectureType> for u8 {
    fn from(val: MupArchitectureType) -> u8 {
        use MupArchitectureType::*;
        match val {
            Gpp5g => 1,
            Unknown(v) => v,
        }
    }
}

impl From<u8> for MupArchitectureType {
    fn from(val: u8) -> Self {
        use MupArchitectureType::*;
        match val {
            1 => Gpp5g,
            v => Unknown(v),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MupRouteType {
    /// Interwork Segment Discovery (RFC 9833 §3.1.1).
    Isd,
    /// Direct Segment Discovery (§3.1.2).
    Dsd,
    /// Type 1 Session Transformed (§3.2.1).
    T1st,
    /// Type 2 Session Transformed (§3.2.2).
    T2st,
    Unknown(u16),
}

impl From<MupRouteType> for u16 {
    fn from(val: MupRouteType) -> u16 {
        use MupRouteType::*;
        match val {
            Isd => 1,
            Dsd => 2,
            T1st => 3,
            T2st => 4,
            Unknown(v) => v,
        }
    }
}

impl From<u16> for MupRouteType {
    fn from(val: u16) -> Self {
        use MupRouteType::*;
        match val {
            1 => Isd,
            2 => Dsd,
            3 => T1st,
            4 => T2st,
            v => Unknown(v),
        }
    }
}

/// MUP NLRI route. Each variant carries the Add-Path identifier
/// (`id`, zero when Add-Path is off), the architecture type, and the
/// route-type-specific payload as opaque bytes. Typed bodies arrive
/// in later phases.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MupRoute {
    Isd {
        id: u32,
        arch: MupArchitectureType,
        body: Vec<u8>,
    },
    Dsd {
        id: u32,
        arch: MupArchitectureType,
        body: Vec<u8>,
    },
    T1st {
        id: u32,
        arch: MupArchitectureType,
        body: Vec<u8>,
    },
    T2st {
        id: u32,
        arch: MupArchitectureType,
        body: Vec<u8>,
    },
    Unknown {
        id: u32,
        arch: MupArchitectureType,
        route_type: u16,
        body: Vec<u8>,
    },
}

impl MupRoute {
    pub fn route_type(&self) -> MupRouteType {
        match self {
            MupRoute::Isd { .. } => MupRouteType::Isd,
            MupRoute::Dsd { .. } => MupRouteType::Dsd,
            MupRoute::T1st { .. } => MupRouteType::T1st,
            MupRoute::T2st { .. } => MupRouteType::T2st,
            MupRoute::Unknown { route_type, .. } => MupRouteType::Unknown(*route_type),
        }
    }

    pub fn architecture(&self) -> MupArchitectureType {
        match self {
            MupRoute::Isd { arch, .. }
            | MupRoute::Dsd { arch, .. }
            | MupRoute::T1st { arch, .. }
            | MupRoute::T2st { arch, .. }
            | MupRoute::Unknown { arch, .. } => *arch,
        }
    }

    pub fn add_path_id(&self) -> u32 {
        match self {
            MupRoute::Isd { id, .. }
            | MupRoute::Dsd { id, .. }
            | MupRoute::T1st { id, .. }
            | MupRoute::T2st { id, .. }
            | MupRoute::Unknown { id, .. } => *id,
        }
    }
}

impl ParseNlri<MupRoute> for MupRoute {
    fn parse_nlri(input: &[u8], addpath: bool) -> IResult<&[u8], MupRoute> {
        let (input, id) = if addpath { be_u32(input)? } else { (input, 0) };
        let (input, arch_raw) = be_u8(input)?;
        let arch: MupArchitectureType = arch_raw.into();
        let (input, type_raw) = be_u16(input)?;
        let (input, length) = be_u8(input)?;
        let (input, body_raw) = take(length as usize).parse(input)?;
        let body = body_raw.to_vec();

        let route = match MupRouteType::from(type_raw) {
            MupRouteType::Isd => MupRoute::Isd { id, arch, body },
            MupRouteType::Dsd => MupRoute::Dsd { id, arch, body },
            MupRouteType::T1st => MupRoute::T1st { id, arch, body },
            MupRouteType::T2st => MupRoute::T2st { id, arch, body },
            MupRouteType::Unknown(rt) => MupRoute::Unknown {
                id,
                arch,
                route_type: rt,
                body,
            },
        };
        Ok((input, route))
    }
}

impl MupRoute {
    /// Emit one MUP NLRI (optional Path Identifier + architecture +
    /// route type + length + opaque body) onto `buf`. Mirror of
    /// `parse_nlri`. Non-zero `id` prepends the 4-octet RFC 7911 Path
    /// Identifier, matching the asymmetry the EVPN and VPNv4 encoders
    /// already use.
    pub fn nlri_emit(&self, buf: &mut BytesMut) {
        let id = self.add_path_id();
        if id != 0 {
            buf.put_u32(id);
        }
        buf.put_u8(self.architecture().into());
        let rt: u16 = self.route_type().into();
        buf.put_u16(rt);

        let body: &[u8] = match self {
            MupRoute::Isd { body, .. }
            | MupRoute::Dsd { body, .. }
            | MupRoute::T1st { body, .. }
            | MupRoute::T2st { body, .. }
            | MupRoute::Unknown { body, .. } => body,
        };
        buf.put_u8(body.len() as u8);
        buf.put(body);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_isd_bytes() -> Vec<u8> {
        // arch=1 (5G), route_type=1 (ISD), length=4, payload=[0xde,0xad,0xbe,0xef]
        vec![0x01, 0x00, 0x01, 0x04, 0xde, 0xad, 0xbe, 0xef]
    }

    #[test]
    fn arch_round_trip_known_and_unknown() {
        for raw in [0u8, 1, 2, 7, 255] {
            let arch = MupArchitectureType::from(raw);
            assert_eq!(u8::from(arch), raw);
        }
        assert_eq!(MupArchitectureType::from(1), MupArchitectureType::Gpp5g);
    }

    #[test]
    fn route_type_round_trip_known_and_unknown() {
        for raw in [0u16, 1, 2, 3, 4, 5, 99, 0xFFFF] {
            let rt = MupRouteType::from(raw);
            assert_eq!(u16::from(rt), raw);
        }
        assert_eq!(MupRouteType::from(3), MupRouteType::T1st);
    }

    fn round_trip(route: MupRoute, addpath: bool) {
        let mut buf = BytesMut::new();
        route.nlri_emit(&mut buf);
        let (rest, parsed) =
            MupRoute::parse_nlri(&buf[..], addpath).expect("nlri_emit must round-trip");
        assert!(rest.is_empty(), "trailing bytes after parse: {rest:?}");
        assert_eq!(parsed, route);
    }

    #[test]
    fn isd_round_trips_without_addpath() {
        round_trip(
            MupRoute::Isd {
                id: 0,
                arch: MupArchitectureType::Gpp5g,
                body: vec![0xde, 0xad, 0xbe, 0xef],
            },
            false,
        );
    }

    #[test]
    fn dsd_round_trips_without_addpath() {
        round_trip(
            MupRoute::Dsd {
                id: 0,
                arch: MupArchitectureType::Gpp5g,
                body: vec![1, 2, 3],
            },
            false,
        );
    }

    #[test]
    fn t1st_round_trips_without_addpath() {
        round_trip(
            MupRoute::T1st {
                id: 0,
                arch: MupArchitectureType::Gpp5g,
                body: vec![0; 16],
            },
            false,
        );
    }

    #[test]
    fn t2st_round_trips_without_addpath() {
        round_trip(
            MupRoute::T2st {
                id: 0,
                arch: MupArchitectureType::Gpp5g,
                body: vec![],
            },
            false,
        );
    }

    #[test]
    fn unknown_route_type_round_trips() {
        round_trip(
            MupRoute::Unknown {
                id: 0,
                arch: MupArchitectureType::Gpp5g,
                route_type: 99,
                body: vec![0xaa, 0xbb],
            },
            false,
        );
    }

    #[test]
    fn add_path_round_trips() {
        round_trip(
            MupRoute::Isd {
                id: 0x1234_5678,
                arch: MupArchitectureType::Gpp5g,
                body: vec![0xff; 10],
            },
            true,
        );
    }

    #[test]
    fn unknown_architecture_preserved() {
        round_trip(
            MupRoute::Isd {
                id: 0,
                arch: MupArchitectureType::Unknown(42),
                body: vec![0xde, 0xad],
            },
            false,
        );
    }

    #[test]
    fn parses_known_isd_bytes() {
        let bytes = sample_isd_bytes();
        let (rest, route) = MupRoute::parse_nlri(&bytes, false).unwrap();
        assert!(rest.is_empty());
        match route {
            MupRoute::Isd { id, arch, body } => {
                assert_eq!(id, 0);
                assert_eq!(arch, MupArchitectureType::Gpp5g);
                assert_eq!(body, vec![0xde, 0xad, 0xbe, 0xef]);
            }
            other => panic!("expected Isd, got {other:?}"),
        }
    }

    #[test]
    fn truncated_input_errors() {
        // Header says length=4 but only 2 body bytes follow.
        let bytes = [0x01, 0x00, 0x01, 0x04, 0x00, 0x00];
        assert!(MupRoute::parse_nlri(&bytes, false).is_err());
    }

    #[test]
    fn empty_body_round_trips() {
        round_trip(
            MupRoute::T2st {
                id: 0,
                arch: MupArchitectureType::Gpp5g,
                body: vec![],
            },
            false,
        );
    }
}
