//! BGP MUP (Mobile User Plane) SAFI 85 NLRI.
//!
//! Outer envelope (RFC 9833 §3.1):
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
//! As of Phase 5, Type 1 (Interwork Segment Discovery, §3.1.1) and
//! Type 2 (Direct Segment Discovery, §3.1.2) bodies are decoded into
//! typed fields. Types 3–4 remain opaque (`Vec<u8>`) and land in
//! Phase 6. Add-Path follows the EVPN convention used elsewhere in
//! this crate: a non-zero `id` signals a 4-octet RFC 7911 Path
//! Identifier on the wire.
//!
//! Parsing the typed ISD / DSD bodies requires the outer AFI
//! (IPv4 ⇒ 4-octet address; IPv6 ⇒ 16-octet address), so
//! `MupRoute::parse` is an associated function rather than a
//! `ParseNlri` impl — that trait's signature does not carry AFI
//! context.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::{BufMut, BytesMut};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use nom::IResult;
use nom::Parser;
use nom::bytes::complete::take;
use nom::error::{ErrorKind, make_error};
use nom::number::complete::{be_u8, be_u16, be_u32};
use nom_derive::Parse;

use crate::{Afi, RouteDistinguisher, nlri_psize};

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
/// (`id`, zero when Add-Path is off) and the architecture type.
/// Types 1 (Isd), 2 (Dsd), and 3 (T1st) hold typed fields; T2st
/// still holds opaque bytes until Phase 6b decodes it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MupRoute {
    /// Interwork Segment Discovery Route (RFC 9833 §3.1.1).
    ///
    /// Wire body: 8-octet RD + 1-octet prefix length + prefix bytes
    /// (variable, sized to cover the prefix length). The address
    /// family of `prefix` is selected by the outer AFI at parse time.
    Isd {
        id: u32,
        arch: MupArchitectureType,
        rd: RouteDistinguisher,
        prefix: IpNet,
    },
    /// Direct Segment Discovery Route (RFC 9833 §3.1.2).
    ///
    /// Wire body: 8-octet RD + 4-octet (IPv4) or 16-octet (IPv6)
    /// segment endpoint address. The address family is selected by
    /// the outer AFI at parse time.
    Dsd {
        id: u32,
        arch: MupArchitectureType,
        rd: RouteDistinguisher,
        address: IpAddr,
    },
    /// Type 1 Session Transformed Route (RFC 9833 §3.2.1).
    ///
    /// Wire body: 8-octet RD + 1-octet prefix length (bits) + prefix
    /// bytes + 4-octet TEID + 1-octet QFI + 1-octet endpoint address
    /// length (bits) + endpoint address bytes. Both prefix and
    /// endpoint follow the outer AFI's address family. The optional
    /// Source Address suffix from earlier draft revisions is not
    /// emitted here; trailing bytes inside the NLRI length window
    /// would surface as a parse failure.
    T1st {
        id: u32,
        arch: MupArchitectureType,
        rd: RouteDistinguisher,
        prefix: IpNet,
        teid: u32,
        qfi: u8,
        endpoint: IpAddr,
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

    /// Wire-encoded payload length (the value the Length byte carries
    /// on the wire — bytes *after* the length byte itself).
    pub fn body_len(&self) -> usize {
        match self {
            MupRoute::Isd { prefix, .. } => 8 + 1 + nlri_psize(prefix.prefix_len()),
            MupRoute::Dsd { address, .. } => {
                8 + match address {
                    IpAddr::V4(_) => 4,
                    IpAddr::V6(_) => 16,
                }
            }
            MupRoute::T1st {
                prefix, endpoint, ..
            } => {
                let ep_bits = match endpoint {
                    IpAddr::V4(_) => 32u8,
                    IpAddr::V6(_) => 128u8,
                };
                8 + 1 + nlri_psize(prefix.prefix_len()) + 4 + 1 + 1 + nlri_psize(ep_bits)
            }
            MupRoute::T2st { body, .. } | MupRoute::Unknown { body, .. } => body.len(),
        }
    }
}

impl MupRoute {
    /// Parse one MUP NLRI from `input`. `afi` is the outer AFI from
    /// the MP_REACH / MP_UNREACH header and selects IPv4 vs IPv6
    /// address-family decoding for route types whose body carries
    /// a prefix (currently only ISD).
    pub fn parse(input: &[u8], addpath: bool, afi: Afi) -> IResult<&[u8], Self> {
        let (input, id) = if addpath { be_u32(input)? } else { (input, 0) };
        let (input, arch_raw) = be_u8(input)?;
        let arch: MupArchitectureType = arch_raw.into();
        let (input, type_raw) = be_u16(input)?;
        let (input, length) = be_u8(input)?;
        let (input, body_slice) = take(length as usize).parse(input)?;

        let route = match MupRouteType::from(type_raw) {
            MupRouteType::Isd => {
                let (rest, rd) = RouteDistinguisher::parse_be(body_slice)?;
                let (rest, plen) = be_u8(rest)?;
                let max_plen = match afi {
                    Afi::Ip => 32u8,
                    Afi::Ip6 => 128u8,
                    _ => return Err(nom::Err::Error(make_error(input, ErrorKind::Verify))),
                };
                if plen > max_plen {
                    return Err(nom::Err::Error(make_error(input, ErrorKind::Verify)));
                }
                let psize = nlri_psize(plen);
                if rest.len() < psize {
                    return Err(nom::Err::Error(make_error(input, ErrorKind::Eof)));
                }
                let prefix = match afi {
                    Afi::Ip => {
                        let mut octets = [0u8; 4];
                        octets[..psize].copy_from_slice(&rest[..psize]);
                        IpNet::V4(
                            Ipv4Net::new(Ipv4Addr::from(octets), plen)
                                .expect("Ipv4Net create error"),
                        )
                    }
                    Afi::Ip6 => {
                        let mut octets = [0u8; 16];
                        octets[..psize].copy_from_slice(&rest[..psize]);
                        IpNet::V6(
                            Ipv6Net::new(Ipv6Addr::from(octets), plen)
                                .expect("Ipv6Net create error"),
                        )
                    }
                    _ => unreachable!(),
                };
                MupRoute::Isd {
                    id,
                    arch,
                    rd,
                    prefix,
                }
            }
            MupRouteType::Dsd => {
                let (rest, rd) = RouteDistinguisher::parse_be(body_slice)?;
                let address = match afi {
                    Afi::Ip => {
                        if rest.len() < 4 {
                            return Err(nom::Err::Error(make_error(input, ErrorKind::Eof)));
                        }
                        let mut octets = [0u8; 4];
                        octets.copy_from_slice(&rest[..4]);
                        IpAddr::V4(Ipv4Addr::from(octets))
                    }
                    Afi::Ip6 => {
                        if rest.len() < 16 {
                            return Err(nom::Err::Error(make_error(input, ErrorKind::Eof)));
                        }
                        let mut octets = [0u8; 16];
                        octets.copy_from_slice(&rest[..16]);
                        IpAddr::V6(Ipv6Addr::from(octets))
                    }
                    _ => return Err(nom::Err::Error(make_error(input, ErrorKind::Verify))),
                };
                MupRoute::Dsd {
                    id,
                    arch,
                    rd,
                    address,
                }
            }
            MupRouteType::T1st => {
                let (rest, rd) = RouteDistinguisher::parse_be(body_slice)?;
                let (rest, plen) = be_u8(rest)?;
                let max_addr_bits = match afi {
                    Afi::Ip => 32u8,
                    Afi::Ip6 => 128u8,
                    _ => return Err(nom::Err::Error(make_error(input, ErrorKind::Verify))),
                };
                if plen > max_addr_bits {
                    return Err(nom::Err::Error(make_error(input, ErrorKind::Verify)));
                }
                let psize = nlri_psize(plen);
                if rest.len() < psize {
                    return Err(nom::Err::Error(make_error(input, ErrorKind::Eof)));
                }
                let prefix = match afi {
                    Afi::Ip => {
                        let mut octets = [0u8; 4];
                        octets[..psize].copy_from_slice(&rest[..psize]);
                        IpNet::V4(Ipv4Net::new(Ipv4Addr::from(octets), plen).unwrap())
                    }
                    Afi::Ip6 => {
                        let mut octets = [0u8; 16];
                        octets[..psize].copy_from_slice(&rest[..psize]);
                        IpNet::V6(Ipv6Net::new(Ipv6Addr::from(octets), plen).unwrap())
                    }
                    _ => unreachable!(),
                };
                let rest = &rest[psize..];
                let (rest, teid) = be_u32(rest)?;
                let (rest, qfi) = be_u8(rest)?;
                let (rest, ep_len) = be_u8(rest)?;
                if ep_len > max_addr_bits {
                    return Err(nom::Err::Error(make_error(input, ErrorKind::Verify)));
                }
                let ep_size = nlri_psize(ep_len);
                if rest.len() < ep_size {
                    return Err(nom::Err::Error(make_error(input, ErrorKind::Eof)));
                }
                let endpoint = match afi {
                    Afi::Ip => {
                        let mut octets = [0u8; 4];
                        octets[..ep_size].copy_from_slice(&rest[..ep_size]);
                        IpAddr::V4(Ipv4Addr::from(octets))
                    }
                    Afi::Ip6 => {
                        let mut octets = [0u8; 16];
                        octets[..ep_size].copy_from_slice(&rest[..ep_size]);
                        IpAddr::V6(Ipv6Addr::from(octets))
                    }
                    _ => unreachable!(),
                };
                MupRoute::T1st {
                    id,
                    arch,
                    rd,
                    prefix,
                    teid,
                    qfi,
                    endpoint,
                }
            }
            MupRouteType::T2st => MupRoute::T2st {
                id,
                arch,
                body: body_slice.to_vec(),
            },
            MupRouteType::Unknown(rt) => MupRoute::Unknown {
                id,
                arch,
                route_type: rt,
                body: body_slice.to_vec(),
            },
        };
        Ok((input, route))
    }
}

impl MupRoute {
    /// Emit one MUP NLRI (optional Path Identifier + architecture +
    /// route type + length + body) onto `buf`. Mirror of `parse`.
    pub fn nlri_emit(&self, buf: &mut BytesMut) {
        let id = self.add_path_id();
        if id != 0 {
            buf.put_u32(id);
        }
        buf.put_u8(self.architecture().into());
        let rt: u16 = self.route_type().into();
        buf.put_u16(rt);

        let mut payload = BytesMut::new();
        match self {
            MupRoute::Isd { rd, prefix, .. } => {
                payload.put_u16(rd.typ as u16);
                payload.put(&rd.val[..]);
                let plen = prefix.prefix_len();
                payload.put_u8(plen);
                let psize = nlri_psize(plen);
                match prefix {
                    IpNet::V4(p) => payload.put(&p.addr().octets()[..psize]),
                    IpNet::V6(p) => payload.put(&p.addr().octets()[..psize]),
                }
            }
            MupRoute::Dsd { rd, address, .. } => {
                payload.put_u16(rd.typ as u16);
                payload.put(&rd.val[..]);
                match address {
                    IpAddr::V4(v4) => payload.put(&v4.octets()[..]),
                    IpAddr::V6(v6) => payload.put(&v6.octets()[..]),
                }
            }
            MupRoute::T1st {
                rd,
                prefix,
                teid,
                qfi,
                endpoint,
                ..
            } => {
                payload.put_u16(rd.typ as u16);
                payload.put(&rd.val[..]);
                let plen = prefix.prefix_len();
                payload.put_u8(plen);
                let psize = nlri_psize(plen);
                match prefix {
                    IpNet::V4(p) => payload.put(&p.addr().octets()[..psize]),
                    IpNet::V6(p) => payload.put(&p.addr().octets()[..psize]),
                }
                payload.put_u32(*teid);
                payload.put_u8(*qfi);
                let ep_bits = match endpoint {
                    IpAddr::V4(_) => 32u8,
                    IpAddr::V6(_) => 128u8,
                };
                payload.put_u8(ep_bits);
                match endpoint {
                    IpAddr::V4(v4) => payload.put(&v4.octets()[..]),
                    IpAddr::V6(v6) => payload.put(&v6.octets()[..]),
                }
            }
            MupRoute::T2st { body, .. } | MupRoute::Unknown { body, .. } => {
                payload.put(&body[..]);
            }
        }
        buf.put_u8(payload.len() as u8);
        buf.put(&payload[..]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RouteDistinguisherType;
    use std::str::FromStr;

    fn sample_rd() -> RouteDistinguisher {
        RouteDistinguisher::from_str("65000:3").unwrap()
    }

    fn opaque_isd_bytes() -> Vec<u8> {
        // arch=1, route_type=1, length=12 (RD=8 + plen=1 + prefix=3).
        let mut v = vec![0x01, 0x00, 0x01, 12];
        v.extend_from_slice(&[0x00, 0x00]); // RD type=ASN
        v.extend_from_slice(&[0xFD, 0xE8]); // ASN 65000
        v.extend_from_slice(&[0x00, 0x00, 0x00, 0x03]); // value 3
        v.push(24); // prefix len
        v.extend_from_slice(&[10, 0, 0]); // 10.0.0.0
        v
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

    fn round_trip(route: MupRoute, addpath: bool, afi: Afi) {
        let mut buf = BytesMut::new();
        route.nlri_emit(&mut buf);
        let (rest, parsed) =
            MupRoute::parse(&buf[..], addpath, afi).expect("nlri_emit must round-trip");
        assert!(rest.is_empty(), "trailing bytes after parse: {rest:?}");
        assert_eq!(parsed, route);
    }

    #[test]
    fn isd_v4_round_trip() {
        round_trip(
            MupRoute::Isd {
                id: 0,
                arch: MupArchitectureType::Gpp5g,
                rd: sample_rd(),
                prefix: "10.0.0.0/24".parse().unwrap(),
            },
            false,
            Afi::Ip,
        );
    }

    #[test]
    fn isd_v4_host_route_round_trip() {
        round_trip(
            MupRoute::Isd {
                id: 0,
                arch: MupArchitectureType::Gpp5g,
                rd: sample_rd(),
                prefix: "192.0.2.1/32".parse().unwrap(),
            },
            false,
            Afi::Ip,
        );
    }

    #[test]
    fn isd_v4_default_route_round_trip() {
        round_trip(
            MupRoute::Isd {
                id: 0,
                arch: MupArchitectureType::Gpp5g,
                rd: sample_rd(),
                prefix: "0.0.0.0/0".parse().unwrap(),
            },
            false,
            Afi::Ip,
        );
    }

    #[test]
    fn isd_v6_round_trip() {
        round_trip(
            MupRoute::Isd {
                id: 0,
                arch: MupArchitectureType::Gpp5g,
                rd: sample_rd(),
                prefix: "2001:db8::/64".parse().unwrap(),
            },
            false,
            Afi::Ip6,
        );
    }

    #[test]
    fn isd_v6_host_route_round_trip() {
        round_trip(
            MupRoute::Isd {
                id: 0,
                arch: MupArchitectureType::Gpp5g,
                rd: sample_rd(),
                prefix: "2001:db8::1/128".parse().unwrap(),
            },
            false,
            Afi::Ip6,
        );
    }

    #[test]
    fn isd_add_path_round_trip() {
        round_trip(
            MupRoute::Isd {
                id: 0xCAFEBABE,
                arch: MupArchitectureType::Gpp5g,
                rd: sample_rd(),
                prefix: "10.1.0.0/16".parse().unwrap(),
            },
            true,
            Afi::Ip,
        );
    }

    #[test]
    fn isd_parses_known_bytes_against_v4_afi() {
        let bytes = opaque_isd_bytes();
        let (rest, route) = MupRoute::parse(&bytes, false, Afi::Ip).unwrap();
        assert!(rest.is_empty());
        match route {
            MupRoute::Isd {
                arch,
                rd,
                prefix,
                id,
            } => {
                assert_eq!(id, 0);
                assert_eq!(arch, MupArchitectureType::Gpp5g);
                assert_eq!(rd.typ, RouteDistinguisherType::ASN);
                assert_eq!(prefix.to_string(), "10.0.0.0/24");
            }
            other => panic!("expected Isd, got {other:?}"),
        }
    }

    #[test]
    fn isd_rejects_prefix_len_over_v4_max() {
        // arch=1, route_type=1, length=10, RD(8) + plen=33 + 1 byte
        let mut v = vec![0x01, 0x00, 0x01, 10];
        v.extend_from_slice(&[0; 8]); // RD
        v.push(33); // > 32 for IPv4
        v.push(0);
        assert!(MupRoute::parse(&v, false, Afi::Ip).is_err());
    }

    #[test]
    fn isd_rejects_prefix_len_over_v6_max() {
        let mut v = vec![0x01, 0x00, 0x01, 10];
        v.extend_from_slice(&[0; 8]);
        v.push(129); // > 128
        v.push(0);
        assert!(MupRoute::parse(&v, false, Afi::Ip6).is_err());
    }

    #[test]
    fn dsd_v4_round_trip() {
        round_trip(
            MupRoute::Dsd {
                id: 0,
                arch: MupArchitectureType::Gpp5g,
                rd: sample_rd(),
                address: "203.0.113.7".parse().unwrap(),
            },
            false,
            Afi::Ip,
        );
    }

    #[test]
    fn dsd_v6_round_trip() {
        round_trip(
            MupRoute::Dsd {
                id: 0,
                arch: MupArchitectureType::Gpp5g,
                rd: sample_rd(),
                address: "2001:db8::1".parse().unwrap(),
            },
            false,
            Afi::Ip6,
        );
    }

    #[test]
    fn dsd_add_path_round_trip() {
        round_trip(
            MupRoute::Dsd {
                id: 0xDEADBEEF,
                arch: MupArchitectureType::Gpp5g,
                rd: sample_rd(),
                address: "192.0.2.99".parse().unwrap(),
            },
            true,
            Afi::Ip,
        );
    }

    #[test]
    fn dsd_v4_truncated_address_errors() {
        // length=11 = 8 RD + 3 bytes (one short of the IPv4 address).
        let mut v = vec![0x01, 0x00, 0x02, 11];
        v.extend_from_slice(&[0; 8]);
        v.extend_from_slice(&[10, 0, 0]);
        assert!(MupRoute::parse(&v, false, Afi::Ip).is_err());
    }

    #[test]
    fn dsd_body_len_matches_emitted_size() {
        let route = MupRoute::Dsd {
            id: 0,
            arch: MupArchitectureType::Gpp5g,
            rd: sample_rd(),
            address: "2001:db8::1".parse().unwrap(),
        };
        let mut buf = BytesMut::new();
        route.nlri_emit(&mut buf);
        assert_eq!(buf.len(), 4 + route.body_len());
    }

    #[test]
    fn t1st_v4_round_trip() {
        round_trip(
            MupRoute::T1st {
                id: 0,
                arch: MupArchitectureType::Gpp5g,
                rd: sample_rd(),
                prefix: "10.0.0.0/24".parse().unwrap(),
                teid: 0x1234_5678,
                qfi: 9,
                endpoint: "192.0.2.1".parse().unwrap(),
            },
            false,
            Afi::Ip,
        );
    }

    #[test]
    fn t1st_v6_round_trip() {
        round_trip(
            MupRoute::T1st {
                id: 0,
                arch: MupArchitectureType::Gpp5g,
                rd: sample_rd(),
                prefix: "2001:db8::/64".parse().unwrap(),
                teid: 0xAAAA_BBBB,
                qfi: 5,
                endpoint: "2001:db8::1".parse().unwrap(),
            },
            false,
            Afi::Ip6,
        );
    }

    #[test]
    fn t1st_add_path_round_trip() {
        round_trip(
            MupRoute::T1st {
                id: 0xFEEDFACE,
                arch: MupArchitectureType::Gpp5g,
                rd: sample_rd(),
                prefix: "10.1.0.0/16".parse().unwrap(),
                teid: 0,
                qfi: 0,
                endpoint: "203.0.113.99".parse().unwrap(),
            },
            true,
            Afi::Ip,
        );
    }

    #[test]
    fn t1st_zero_prefix_round_trip() {
        round_trip(
            MupRoute::T1st {
                id: 0,
                arch: MupArchitectureType::Gpp5g,
                rd: sample_rd(),
                prefix: "0.0.0.0/0".parse().unwrap(),
                teid: 42,
                qfi: 1,
                endpoint: "192.0.2.250".parse().unwrap(),
            },
            false,
            Afi::Ip,
        );
    }

    #[test]
    fn t1st_rejects_prefix_len_over_afi_max() {
        // arch=1, route_type=3, length=24, RD(8) + plen=33 (> 32 for v4) + rest
        let mut v = vec![0x01, 0x00, 0x03, 24];
        v.extend_from_slice(&[0; 8]); // RD
        v.push(33);
        v.extend_from_slice(&[0; 15]); // pad to length
        assert!(MupRoute::parse(&v, false, Afi::Ip).is_err());
    }

    #[test]
    fn t1st_rejects_endpoint_len_over_afi_max() {
        // arch=1, route_type=3, length=20, RD(8) + plen=0 + TEID(4) + QFI(1)
        // + ep_len=33 (> 32 for v4) + filler
        let mut v = vec![0x01, 0x00, 0x03, 20];
        v.extend_from_slice(&[0; 8]); // RD
        v.push(0); // plen=0 → no prefix bytes
        v.extend_from_slice(&[0; 4]); // TEID
        v.push(0); // QFI
        v.push(33); // ep_len > 32
        v.extend_from_slice(&[0; 6]); // pad to length=20
        assert!(MupRoute::parse(&v, false, Afi::Ip).is_err());
    }

    #[test]
    fn t1st_body_len_matches_emitted_size() {
        let route = MupRoute::T1st {
            id: 0,
            arch: MupArchitectureType::Gpp5g,
            rd: sample_rd(),
            prefix: "10.0.0.0/24".parse().unwrap(),
            teid: 1,
            qfi: 2,
            endpoint: "192.0.2.1".parse().unwrap(),
        };
        let mut buf = BytesMut::new();
        route.nlri_emit(&mut buf);
        assert_eq!(buf.len(), 4 + route.body_len());
    }

    #[test]
    fn t2st_opaque_round_trip() {
        round_trip(
            MupRoute::T2st {
                id: 0,
                arch: MupArchitectureType::Gpp5g,
                body: vec![],
            },
            false,
            Afi::Ip,
        );
    }

    #[test]
    fn unknown_route_type_round_trip() {
        round_trip(
            MupRoute::Unknown {
                id: 0,
                arch: MupArchitectureType::Gpp5g,
                route_type: 99,
                body: vec![0xaa, 0xbb],
            },
            false,
            Afi::Ip,
        );
    }

    #[test]
    fn unknown_architecture_preserved() {
        round_trip(
            MupRoute::Isd {
                id: 0,
                arch: MupArchitectureType::Unknown(42),
                rd: sample_rd(),
                prefix: "10.0.0.0/8".parse().unwrap(),
            },
            false,
            Afi::Ip,
        );
    }

    #[test]
    fn truncated_body_errors() {
        // Header length=4 but only 2 body bytes follow.
        let bytes = [0x01, 0x00, 0x01, 0x04, 0x00, 0x00];
        assert!(MupRoute::parse(&bytes, false, Afi::Ip).is_err());
    }

    #[test]
    fn isd_body_len_matches_emitted_size() {
        let route = MupRoute::Isd {
            id: 0,
            arch: MupArchitectureType::Gpp5g,
            rd: sample_rd(),
            prefix: "10.0.0.0/24".parse().unwrap(),
        };
        let mut buf = BytesMut::new();
        route.nlri_emit(&mut buf);
        // 1 arch + 2 rt + 1 len + body
        assert_eq!(buf.len(), 4 + route.body_len());
    }
}
