//! BGP MUP (Mobile User Plane) SAFI 85 NLRI.
//!
//! Outer envelope (draft-ietf-bess-mup-safi §3.1):
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
//! All four defined route types are now decoded into typed fields:
//! Type 1 (Interwork Segment Discovery, §3.1.1), Type 2 (Direct
//! Segment Discovery, §3.1.2), Type 3 (Type-1 Session Transformed,
//! §3.2.1), and Type 4 (Type-2 Session Transformed, §3.2.2).
//! Unknown route types fall through to `MupRoute::Unknown` with an
//! opaque body. Add-Path follows the EVPN convention used elsewhere
//! in this crate: a non-zero `id` signals a 4-octet RFC 7911 Path
//! Identifier on the wire.
//!
//! Parsing typed bodies requires the outer AFI (IPv4 ⇒ 4-octet
//! address space, IPv6 ⇒ 16-octet) so `MupRoute::parse` is an
//! associated function rather than a `ParseNlri` impl — that
//! trait's signature does not carry AFI context.

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
    /// 3GPP 5G (draft-ietf-bess-mup-safi §3.1.1).
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
    /// Interwork Segment Discovery (draft-ietf-bess-mup-safi §3.1.1).
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
/// All four defined route types (Isd, Dsd, T1st, T2st) hold typed
/// fields; unrecognized route types arrive as `Unknown` with an
/// opaque body so the dispatch shell never drops an UPDATE.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MupRoute {
    /// Interwork Segment Discovery Route (draft-ietf-bess-mup-safi §3.1.1).
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
    /// Direct Segment Discovery Route (draft-ietf-bess-mup-safi §3.1.2).
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
    /// Type 1 Session Transformed Route (draft-ietf-bess-mup-safi §3.2.1).
    ///
    /// Wire body: 8-octet RD + 1-octet prefix length (bits) + prefix
    /// bytes + 4-octet TEID + 1-octet QFI + 1-octet endpoint address
    /// length (bits, 32 or 128) + endpoint address bytes + 1-octet
    /// source address length (bits, 0/32/128) + optional source
    /// address bytes. The source-address-length octet is always
    /// present on the wire (zero when no source is carried), matching
    /// GoBGP and draft-ietf-bess-mup-safi §3.2.1. Only the UE `prefix`
    /// follows the outer AFI; the `endpoint` (gNB) and `source` (UPF)
    /// families are decided by their own length octets (32 = IPv4,
    /// 128 = IPv6), so an IPv6 UE route may carry an IPv4 endpoint/source
    /// (the mixed-AFI 5G case).
    T1st {
        id: u32,
        arch: MupArchitectureType,
        rd: RouteDistinguisher,
        prefix: IpNet,
        teid: u32,
        qfi: u8,
        endpoint: IpAddr,
        /// Optional GTP source address (§3.2.1). `None` encodes a
        /// source-address-length of 0 on the wire.
        source: Option<IpAddr>,
    },
    /// Type 2 Session Transformed Route (draft-ietf-bess-mup-safi §3.2.2).
    ///
    /// Wire body: 8-octet RD + 1-octet endpoint address length (bits,
    /// up to 64 for IPv4 / 160 for IPv6) + full-width endpoint address
    /// (4 or 16 octets, selected by the outer AFI) + TEID bytes. The
    /// endpoint-address-length covers both the address and the trailing
    /// TEID bits, so the TEID occupies ceil((len - addr_bits)/8) octets
    /// stored high-aligned in a 32-bit value (GoBGP-compatible).
    T2st {
        id: u32,
        arch: MupArchitectureType,
        rd: RouteDistinguisher,
        endpoint: IpAddr,
        /// Endpoint Address Length in bits (address bits + TEID bits).
        endpoint_len: u8,
        /// GTP TEID, high-aligned into 32 bits per §3.2.2.
        teid: u32,
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
                prefix,
                endpoint,
                source,
                ..
            } => {
                let ep_bits = match endpoint {
                    IpAddr::V4(_) => 32u8,
                    IpAddr::V6(_) => 128u8,
                };
                // RD(8) + plen(1) + prefix + TEID(4) + QFI(1)
                // + ep_len(1) + endpoint + src_len(1) + optional source.
                let mut len =
                    8 + 1 + nlri_psize(prefix.prefix_len()) + 4 + 1 + 1 + nlri_psize(ep_bits) + 1;
                if let Some(src) = source {
                    let src_bits = match src {
                        IpAddr::V4(_) => 32u8,
                        IpAddr::V6(_) => 128u8,
                    };
                    len += nlri_psize(src_bits);
                }
                len
            }
            MupRoute::T2st {
                endpoint,
                endpoint_len,
                ..
            } => {
                let (addr_bytes, addr_bits) = match endpoint {
                    IpAddr::V4(_) => (4usize, 32u8),
                    IpAddr::V6(_) => (16usize, 128u8),
                };
                8 + 1 + addr_bytes + t2st_teid_size(*endpoint_len, addr_bits)
            }
            MupRoute::Unknown { body, .. } => body.len(),
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
                // The endpoint-address-length octet selects the endpoint's
                // address family on its own (32 = IPv4 gNB, 128 = IPv6
                // gNB), independent of the outer AFI: draft-ietf-bess-mup-safi
                // §3.2.1 deliberately permits an IPv6 UE prefix to carry an
                // IPv4 endpoint/source — the real 5G case where the N3
                // transport is IPv4. (GoBGP infers the family from this octet
                // the same way; only the UE prefix is tied to the outer AFI.)
                let (rest, ep_len) = be_u8(rest)?;
                let (endpoint, rest) = match ep_len {
                    32 => {
                        if rest.len() < 4 {
                            return Err(nom::Err::Error(make_error(input, ErrorKind::Eof)));
                        }
                        let mut octets = [0u8; 4];
                        octets.copy_from_slice(&rest[..4]);
                        (IpAddr::V4(Ipv4Addr::from(octets)), &rest[4..])
                    }
                    128 => {
                        if rest.len() < 16 {
                            return Err(nom::Err::Error(make_error(input, ErrorKind::Eof)));
                        }
                        let mut octets = [0u8; 16];
                        octets.copy_from_slice(&rest[..16]);
                        (IpAddr::V6(Ipv6Addr::from(octets)), &rest[16..])
                    }
                    _ => return Err(nom::Err::Error(make_error(input, ErrorKind::Verify))),
                };
                // Mandatory source-address-length octet: 0 = no source,
                // else 32 (IPv4) or 128 (IPv6) — also family-by-length,
                // independent of the outer AFI.
                let (rest, src_len) = be_u8(rest)?;
                let source = match src_len {
                    0 => None,
                    32 => {
                        if rest.len() < 4 {
                            return Err(nom::Err::Error(make_error(input, ErrorKind::Eof)));
                        }
                        let mut octets = [0u8; 4];
                        octets.copy_from_slice(&rest[..4]);
                        Some(IpAddr::V4(Ipv4Addr::from(octets)))
                    }
                    128 => {
                        if rest.len() < 16 {
                            return Err(nom::Err::Error(make_error(input, ErrorKind::Eof)));
                        }
                        let mut octets = [0u8; 16];
                        octets.copy_from_slice(&rest[..16]);
                        Some(IpAddr::V6(Ipv6Addr::from(octets)))
                    }
                    _ => return Err(nom::Err::Error(make_error(input, ErrorKind::Verify))),
                };
                MupRoute::T1st {
                    id,
                    arch,
                    rd,
                    prefix,
                    teid,
                    qfi,
                    endpoint,
                    source,
                }
            }
            MupRouteType::T2st => {
                let (rest, rd) = RouteDistinguisher::parse_be(body_slice)?;
                let (rest, endpoint_len) = be_u8(rest)?;
                let (max_ep_len, addr_size, addr_bits) = match afi {
                    Afi::Ip => (64u8, 4usize, 32u8),
                    Afi::Ip6 => (160u8, 16usize, 128u8),
                    _ => return Err(nom::Err::Error(make_error(input, ErrorKind::Verify))),
                };
                if endpoint_len > max_ep_len {
                    return Err(nom::Err::Error(make_error(input, ErrorKind::Verify)));
                }
                if rest.len() < addr_size {
                    return Err(nom::Err::Error(make_error(input, ErrorKind::Eof)));
                }
                let endpoint = match afi {
                    Afi::Ip => {
                        let mut octets = [0u8; 4];
                        octets.copy_from_slice(&rest[..4]);
                        IpAddr::V4(Ipv4Addr::from(octets))
                    }
                    Afi::Ip6 => {
                        let mut octets = [0u8; 16];
                        octets.copy_from_slice(&rest[..16]);
                        IpAddr::V6(Ipv6Addr::from(octets))
                    }
                    _ => unreachable!(),
                };
                let rest = &rest[addr_size..];
                // The endpoint-address-length covers the address plus the
                // trailing TEID bits; the TEID is high-aligned in 32 bits
                // (GoBGP-compatible).
                let teid_bits = endpoint_len.saturating_sub(addr_bits);
                let teid = if teid_bits > 0 {
                    let tsize = nlri_psize(teid_bits);
                    if rest.len() < tsize {
                        return Err(nom::Err::Error(make_error(input, ErrorKind::Eof)));
                    }
                    let mut octets = [0u8; 4];
                    octets[..tsize].copy_from_slice(&rest[..tsize]);
                    u32::from_be_bytes(octets)
                } else {
                    0
                };
                MupRoute::T2st {
                    id,
                    arch,
                    rd,
                    endpoint,
                    endpoint_len,
                    teid,
                }
            }
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

/// Octet width of the high-aligned TEID carried by a Type-2 Session
/// Transformed (ST2) MUP route. The TEID is a 32-bit value, so it never
/// occupies more than 4 octets — clamp `nlri_psize(endpoint_len - addr_bits)`
/// at 4 so the emitter cannot index past `teid.to_be_bytes()` when a
/// locally-constructed route carries an out-of-range `endpoint_len` (the parser
/// already bounds `endpoint_len` to `addr_bits + 32`). `len()` / `emit` /
/// `body_len` all derive from this so the declared body length matches the
/// bytes written.
fn t2st_teid_size(endpoint_len: u8, addr_bits: u8) -> usize {
    nlri_psize(endpoint_len.saturating_sub(addr_bits)).min(4)
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
                source,
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
                // Source-address-length octet is mandatory (0 = absent).
                match source {
                    Some(IpAddr::V4(v4)) => {
                        payload.put_u8(32);
                        payload.put(&v4.octets()[..]);
                    }
                    Some(IpAddr::V6(v6)) => {
                        payload.put_u8(128);
                        payload.put(&v6.octets()[..]);
                    }
                    None => payload.put_u8(0),
                }
            }
            MupRoute::T2st {
                rd,
                endpoint,
                endpoint_len,
                teid,
                ..
            } => {
                payload.put_u16(rd.typ as u16);
                payload.put(&rd.val[..]);
                payload.put_u8(*endpoint_len);
                let addr_bits = match endpoint {
                    IpAddr::V4(_) => 32u8,
                    IpAddr::V6(_) => 128u8,
                };
                match endpoint {
                    IpAddr::V4(v4) => payload.put(&v4.octets()[..]),
                    IpAddr::V6(v6) => payload.put(&v6.octets()[..]),
                }
                // TEID occupies the bits beyond the address, high-aligned. It
                // is a 32-bit value, so the width is capped at 4 octets even if
                // `endpoint_len` claims more.
                let tsize = t2st_teid_size(*endpoint_len, addr_bits);
                if tsize > 0 {
                    let tb = teid.to_be_bytes();
                    payload.put(&tb[..tsize]);
                }
            }
            MupRoute::Unknown { body, .. } => {
                payload.put(&body[..]);
            }
        }
        buf.put_u8(payload.len() as u8);
        buf.put(&payload[..]);
    }
}

/// MUP NLRI key with the add-path Path Identifier, the constant
/// architecture type, *and* the Route Distinguisher stripped off, used as
/// the inner key of the per-RD MUP RIB tables.
///
/// Like EVPN's `EvpnPrefix` (and VPN's `Ipv4Net`), the RD is **not** part
/// of this key — it is the outer `BTreeMap<RouteDistinguisher, _>` key, so
/// [`MupPrefix::from_route`] returns `(rd, key)`. Every other wire field
/// except the add-path `id` (which lives on `BgpRib.remote_id`) is part of
/// the key, so two routes that differ only in TEID/QFI/endpoint/source
/// coexist, and replacement is by explicit withdraw. Variant declaration
/// order (`Dsd, Isd, T1st, T2st`) drives the derived `Ord`, so a RIB walk
/// lists routes grouped by type (DSD then ISD then ST1 then ST2).
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum MupPrefix {
    /// Direct Segment Discovery Route key (draft-ietf-bess-mup-safi §3.1.2).
    Dsd { address: IpAddr },
    /// Interwork Segment Discovery Route key (§3.1.1).
    Isd { prefix: IpNet },
    /// Type 1 Session Transformed Route (ST1) key (§3.2.1).
    T1st {
        prefix: IpNet,
        teid: u32,
        qfi: u8,
        endpoint: IpAddr,
        source: Option<IpAddr>,
    },
    /// Type 2 Session Transformed Route (ST2) key (§3.2.2).
    T2st {
        endpoint: IpAddr,
        endpoint_len: u8,
        teid: u32,
    },
    /// Unrecognized route type — keyed by its raw type and opaque body so
    /// the RIB never coalesces distinct unknown routes.
    Unknown { route_type: u16, body: Vec<u8> },
}

impl MupPrefix {
    /// MUP route type number (1=ISD, 2=DSD, 3=T1ST, 4=T2ST).
    pub fn route_type(&self) -> u16 {
        match self {
            MupPrefix::Isd { .. } => 1,
            MupPrefix::Dsd { .. } => 2,
            MupPrefix::T1st { .. } => 3,
            MupPrefix::T2st { .. } => 4,
            MupPrefix::Unknown { route_type, .. } => *route_type,
        }
    }

    /// Split a parsed `MupRoute` into its Route Distinguisher and the
    /// RD-and-id-stripped inner key used to index the per-RD MUP RIB.
    /// The add-path `id` and the (constant) arch type are dropped; the
    /// `id` lives on `BgpRib.remote_id`. The `Unknown` variant has no
    /// decoded RD, so it pairs with the default (`0:0`) RD.
    pub fn from_route(route: &MupRoute) -> (RouteDistinguisher, MupPrefix) {
        match route {
            MupRoute::Isd { rd, prefix, .. } => (*rd, MupPrefix::Isd { prefix: *prefix }),
            MupRoute::Dsd { rd, address, .. } => (*rd, MupPrefix::Dsd { address: *address }),
            MupRoute::T1st {
                rd,
                prefix,
                teid,
                qfi,
                endpoint,
                source,
                ..
            } => (
                *rd,
                MupPrefix::T1st {
                    prefix: *prefix,
                    teid: *teid,
                    qfi: *qfi,
                    endpoint: *endpoint,
                    source: *source,
                },
            ),
            MupRoute::T2st {
                rd,
                endpoint,
                endpoint_len,
                teid,
                ..
            } => (
                *rd,
                MupPrefix::T2st {
                    endpoint: *endpoint,
                    endpoint_len: *endpoint_len,
                    teid: *teid,
                },
            ),
            MupRoute::Unknown {
                route_type, body, ..
            } => (
                RouteDistinguisher::default(),
                MupPrefix::Unknown {
                    route_type: *route_type,
                    body: body.clone(),
                },
            ),
        }
    }

    /// Outer AFI implied by the route's keyed address. The MP_REACH AFI
    /// tracks the prefix/address that names the route — the UE prefix for
    /// ISD/T1ST, the segment address for DSD, the endpoint for T2ST — so
    /// that field is authoritative. (A T1ST endpoint/source may be a
    /// different family; see `MupRoute::T1st`.) `Unknown` has no decoded
    /// address, so it defaults to IPv4.
    pub fn afi(&self) -> Afi {
        let v6 = match self {
            MupPrefix::Isd { prefix, .. } | MupPrefix::T1st { prefix, .. } => {
                matches!(prefix, IpNet::V6(_))
            }
            MupPrefix::Dsd { address, .. } => address.is_ipv6(),
            MupPrefix::T2st { endpoint, .. } => endpoint.is_ipv6(),
            MupPrefix::Unknown { .. } => false,
        };
        if v6 { Afi::Ip6 } else { Afi::Ip }
    }

    /// Reconstruct a wire `MupRoute` from the inner key and its RD (the
    /// outer per-RD map key) for re-advertisement. The only other
    /// synthesized values are the 3GPP-5G architecture type and a zero
    /// add-path id. The RD is ignored for the `Unknown` variant (its
    /// opaque body already carries the original bytes).
    pub fn to_route(&self, rd: RouteDistinguisher) -> MupRoute {
        let arch = MupArchitectureType::Gpp5g;
        match self {
            MupPrefix::Isd { prefix } => MupRoute::Isd {
                id: 0,
                arch,
                rd,
                prefix: *prefix,
            },
            MupPrefix::Dsd { address } => MupRoute::Dsd {
                id: 0,
                arch,
                rd,
                address: *address,
            },
            MupPrefix::T1st {
                prefix,
                teid,
                qfi,
                endpoint,
                source,
            } => MupRoute::T1st {
                id: 0,
                arch,
                rd,
                prefix: *prefix,
                teid: *teid,
                qfi: *qfi,
                endpoint: *endpoint,
                source: *source,
            },
            MupPrefix::T2st {
                endpoint,
                endpoint_len,
                teid,
            } => MupRoute::T2st {
                id: 0,
                arch,
                rd,
                endpoint: *endpoint,
                endpoint_len: *endpoint_len,
                teid: *teid,
            },
            MupPrefix::Unknown { route_type, body } => MupRoute::Unknown {
                id: 0,
                arch,
                route_type: *route_type,
                body: body.clone(),
            },
        }
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
                source: Some("198.51.100.7".parse().unwrap()),
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
                source: Some("2001:db8::abcd".parse().unwrap()),
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
                source: None,
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
                source: None,
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
    fn t1st_rejects_invalid_endpoint_len() {
        // arch=1, route_type=3, length=20, RD(8) + plen=0 + TEID(4) + QFI(1)
        // + ep_len=33 (not 32 or 128 → invalid host width) + filler.
        let mut v = vec![0x01, 0x00, 0x03, 20];
        v.extend_from_slice(&[0; 8]); // RD
        v.push(0); // plen=0 → no prefix bytes
        v.extend_from_slice(&[0; 4]); // TEID
        v.push(0); // QFI
        v.push(33); // ep_len neither 32 nor 128
        v.extend_from_slice(&[0; 6]); // pad to length=20
        assert!(MupRoute::parse(&v, false, Afi::Ip).is_err());
    }

    #[test]
    fn t1st_mixed_afi_v6_ue_v4_endpoint_round_trip() {
        // The real 5G case: an IPv6 UE prefix (outer AFI = IPv6) carrying
        // an IPv4 gNB endpoint and IPv4 UPF source (IPv4 N3 transport).
        // The endpoint/source families come from their own length octets,
        // so this must round-trip under the IPv6 outer AFI.
        round_trip(
            MupRoute::T1st {
                id: 0,
                arch: MupArchitectureType::Gpp5g,
                rd: sample_rd(),
                prefix: "2001:db8::5/128".parse().unwrap(),
                teid: 0x1234_5678,
                qfi: 9,
                endpoint: "10.0.0.1".parse().unwrap(),
                source: Some("198.51.100.7".parse().unwrap()),
            },
            false,
            Afi::Ip6,
        );
    }

    #[test]
    fn t1st_mixed_afi_v4_ue_v6_endpoint_round_trip() {
        // The mirror case: an IPv4 UE prefix (outer AFI = IPv4) carrying an
        // IPv6 endpoint/source (IPv6 N3 transport).
        round_trip(
            MupRoute::T1st {
                id: 0,
                arch: MupArchitectureType::Gpp5g,
                rd: sample_rd(),
                prefix: "192.0.2.5/32".parse().unwrap(),
                teid: 7,
                qfi: 1,
                endpoint: "2001:db8::1".parse().unwrap(),
                source: Some("2001:db8::abcd".parse().unwrap()),
            },
            false,
            Afi::Ip,
        );
    }

    #[test]
    fn t1st_parses_v6_ue_with_v4_endpoint_bytes() {
        // Hand-rolled wire bytes: outer AFI = IPv6, UE prefix /128, then a
        // 32-bit endpoint and a 32-bit source. A parser that forced the
        // endpoint/source to match the outer AFI (128) would reject this.
        // arch=1, route_type=3 (T1ST).
        // body = RD(8) + plen(1)=128 + ue(16) + TEID(4) + QFI(1)
        //        + ep_len(1)=32 + ep(4) + src_len(1)=32 + src(4) = 40
        let ue = std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 5);
        let mut v = vec![0x01, 0x00, 0x03, 40];
        v.extend_from_slice(&[0; 8]); // RD = 0:0
        v.push(128); // prefix length
        v.extend_from_slice(&ue.octets()); // UE prefix (16)
        v.extend_from_slice(&0x1234_5678u32.to_be_bytes()); // TEID
        v.push(9); // QFI
        v.push(32); // endpoint length → IPv4
        v.extend_from_slice(&[10, 0, 0, 1]); // endpoint
        v.push(32); // source length → IPv4
        v.extend_from_slice(&[198, 51, 100, 7]); // source
        let (_, route) = MupRoute::parse(&v, false, Afi::Ip6).expect("mixed-AFI T1ST parses");
        match route {
            MupRoute::T1st {
                prefix,
                endpoint,
                source,
                ..
            } => {
                assert_eq!(prefix, "2001:db8::5/128".parse::<IpNet>().unwrap());
                assert_eq!(endpoint, "10.0.0.1".parse::<IpAddr>().unwrap());
                assert_eq!(source, Some("198.51.100.7".parse::<IpAddr>().unwrap()));
            }
            other => panic!("expected T1st, got {other:?}"),
        }
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
            source: Some("203.0.113.1".parse().unwrap()),
        };
        let mut buf = BytesMut::new();
        route.nlri_emit(&mut buf);
        assert_eq!(buf.len(), 4 + route.body_len());
    }

    #[test]
    fn t2st_v4_round_trip() {
        round_trip(
            MupRoute::T2st {
                id: 0,
                arch: MupArchitectureType::Gpp5g,
                rd: sample_rd(),
                endpoint: "10.0.0.1".parse().unwrap(),
                endpoint_len: 64,
                teid: 600,
            },
            false,
            Afi::Ip,
        );
    }

    #[test]
    fn t2st_v6_round_trip() {
        round_trip(
            MupRoute::T2st {
                id: 0,
                arch: MupArchitectureType::Gpp5g,
                rd: sample_rd(),
                endpoint: "2001:db8::1".parse().unwrap(),
                endpoint_len: 160,
                teid: 0xAABB_CCDD,
            },
            false,
            Afi::Ip6,
        );
    }

    #[test]
    fn t2st_v4_partial_teid_round_trip() {
        // endpoint_len = 48 → 32 address bits + 16 TEID bits. The TEID is
        // stored high-aligned, so only its upper 16 bits survive the
        // 2-octet on-wire field.
        round_trip(
            MupRoute::T2st {
                id: 0,
                arch: MupArchitectureType::Gpp5g,
                rd: sample_rd(),
                endpoint: "10.0.0.1".parse().unwrap(),
                endpoint_len: 48,
                teid: 0x0258_0000,
            },
            false,
            Afi::Ip,
        );
    }

    #[test]
    fn t2st_add_path_round_trip() {
        round_trip(
            MupRoute::T2st {
                id: 0xC0FFEE00,
                arch: MupArchitectureType::Gpp5g,
                rd: sample_rd(),
                endpoint: "192.0.2.99".parse().unwrap(),
                endpoint_len: 64,
                teid: 0x0000_3039,
            },
            true,
            Afi::Ip,
        );
    }

    #[test]
    fn t2st_rejects_endpoint_len_over_afi_max() {
        // arch=1, route_type=4, length=9: RD(8) + ep_len=65 (> 64 for v4).
        let mut v = vec![0x01, 0x00, 0x04, 9];
        v.extend_from_slice(&[0; 8]);
        v.push(65);
        assert!(MupRoute::parse(&v, false, Afi::Ip).is_err());
    }

    #[test]
    fn t2st_body_len_matches_emitted_size() {
        let route = MupRoute::T2st {
            id: 0,
            arch: MupArchitectureType::Gpp5g,
            rd: sample_rd(),
            endpoint: "2001:db8::1".parse().unwrap(),
            endpoint_len: 160,
            teid: 42,
        };
        let mut buf = BytesMut::new();
        route.nlri_emit(&mut buf);
        assert_eq!(buf.len(), 4 + route.body_len());
    }

    #[test]
    fn t2st_emit_clamps_oversized_endpoint_len() {
        // A locally-constructed route with an out-of-range endpoint_len must
        // not panic on emit: the TEID is a u32, so at most 4 octets are
        // written, and body_len() agrees with the emitted size.
        let route = MupRoute::T2st {
            id: 0,
            arch: MupArchitectureType::Gpp5g,
            rd: sample_rd(),
            endpoint: "10.0.0.1".parse().unwrap(),
            endpoint_len: 255, // 255 - 32 = 223 bits -> 28 octets before clamp
            teid: 0x1122_3344,
        };
        let mut buf = BytesMut::new();
        route.nlri_emit(&mut buf); // must not panic
        // TEID clamped to 4 octets: RD(8) + ep_len(1) + addr(4) + TEID(4) = 17.
        assert_eq!(route.body_len(), 8 + 1 + 4 + 4);
        assert_eq!(buf.len(), 4 + route.body_len());
    }

    // --- GoBGP byte-exact interop vectors ---------------------------------
    // These pin the on-wire layout against GoBGP's mup.go encoders. A
    // zero Route Distinguisher (8 zero octets) keeps the vectors free of
    // any dependence on RD string parsing.

    #[test]
    fn t1st_parses_gobgp_v4_bytes_with_source() {
        // RD(8) + plen=24 + prefix(3) + TEID(4)=601 + QFI=9
        // + ep_len=32 + endpoint(4) + src_len=32 + source(4).
        let mut body = vec![0u8; 8];
        body.push(24);
        body.extend_from_slice(&[10, 0, 3]); // 10.0.3.0/24
        body.extend_from_slice(&[0x00, 0x00, 0x02, 0x59]); // TEID 601
        body.push(9); // QFI
        body.push(32); // endpoint address length
        body.extend_from_slice(&[20, 0, 3, 99]); // 20.0.3.99
        body.push(32); // source address length
        body.extend_from_slice(&[20, 0, 1, 1]); // 20.0.1.1
        let mut v = vec![0x01, 0x00, 0x03, body.len() as u8];
        v.extend_from_slice(&body);

        let (rest, route) = MupRoute::parse(&v, false, Afi::Ip).unwrap();
        assert!(rest.is_empty());
        match route {
            MupRoute::T1st {
                prefix,
                teid,
                qfi,
                endpoint,
                source,
                ..
            } => {
                assert_eq!(prefix.to_string(), "10.0.3.0/24");
                assert_eq!(teid, 601);
                assert_eq!(qfi, 9);
                assert_eq!(endpoint, "20.0.3.99".parse::<IpAddr>().unwrap());
                assert_eq!(source, Some("20.0.1.1".parse::<IpAddr>().unwrap()));
            }
            other => panic!("expected T1st, got {other:?}"),
        }

        // Re-emit must reproduce the exact same wire bytes.
        let mut buf = BytesMut::new();
        route.nlri_emit(&mut buf);
        assert_eq!(&buf[..], &v[..]);
    }

    #[test]
    fn t1st_parses_gobgp_v4_bytes_without_source() {
        // Same as above but the mandatory source-address-length octet is
        // zero and no source bytes follow.
        let mut body = vec![0u8; 8];
        body.push(24);
        body.extend_from_slice(&[10, 0, 3]);
        body.extend_from_slice(&[0x00, 0x00, 0x02, 0x59]);
        body.push(9);
        body.push(32);
        body.extend_from_slice(&[20, 0, 3, 99]);
        body.push(0); // source address length = 0
        let mut v = vec![0x01, 0x00, 0x03, body.len() as u8];
        v.extend_from_slice(&body);

        let (rest, route) = MupRoute::parse(&v, false, Afi::Ip).unwrap();
        assert!(rest.is_empty());
        assert!(matches!(route, MupRoute::T1st { source: None, .. }));
        let mut buf = BytesMut::new();
        route.nlri_emit(&mut buf);
        assert_eq!(&buf[..], &v[..]);
    }

    #[test]
    fn t1st_rejects_non_host_endpoint_len() {
        // ep_len = 24 is neither 32 nor 128 → malformed (draft-ietf-bess-mup-safi §3.2.1).
        let mut body = vec![0u8; 8];
        body.push(0); // plen=0
        body.extend_from_slice(&[0; 4]); // TEID
        body.push(0); // QFI
        body.push(24); // ep_len not a host width
        body.extend_from_slice(&[0; 3]);
        let mut v = vec![0x01, 0x00, 0x03, body.len() as u8];
        v.extend_from_slice(&body);
        assert!(MupRoute::parse(&v, false, Afi::Ip).is_err());
    }

    #[test]
    fn t2st_parses_gobgp_v4_bytes_with_teid() {
        // RD(8) + ep_len=64 + endpoint(4) + TEID(4)=600. The endpoint
        // address length covers the 32 address bits plus 32 TEID bits.
        let mut body = vec![0u8; 8];
        body.push(64);
        body.extend_from_slice(&[20, 0, 1, 1]); // 20.0.1.1
        body.extend_from_slice(&[0x00, 0x00, 0x02, 0x58]); // TEID 600
        let mut v = vec![0x01, 0x00, 0x04, body.len() as u8];
        v.extend_from_slice(&body);

        let (rest, route) = MupRoute::parse(&v, false, Afi::Ip).unwrap();
        assert!(rest.is_empty());
        match route {
            MupRoute::T2st {
                endpoint,
                endpoint_len,
                teid,
                ..
            } => {
                assert_eq!(endpoint, "20.0.1.1".parse::<IpAddr>().unwrap());
                assert_eq!(endpoint_len, 64);
                assert_eq!(teid, 600);
            }
            other => panic!("expected T2st, got {other:?}"),
        }

        let mut buf = BytesMut::new();
        route.nlri_emit(&mut buf);
        assert_eq!(&buf[..], &v[..]);
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

    #[test]
    fn mup_prefix_strips_add_path_id() {
        // Two routes identical but for the add-path id map to one key.
        let a = MupRoute::Isd {
            id: 1,
            arch: MupArchitectureType::Gpp5g,
            rd: sample_rd(),
            prefix: "10.0.0.0/24".parse().unwrap(),
        };
        let b = MupRoute::Isd {
            id: 999,
            arch: MupArchitectureType::Gpp5g,
            rd: sample_rd(),
            prefix: "10.0.0.0/24".parse().unwrap(),
        };
        assert_eq!(MupPrefix::from_route(&a), MupPrefix::from_route(&b));
    }

    #[test]
    fn mup_prefix_afi_and_to_route_round_trip() {
        // afi() reflects the route-key address family; to_route() inverts
        // from_route for the full-NLRI key (arch=Gpp5g, id=0).
        let cases = [
            MupRoute::Isd {
                id: 7,
                arch: MupArchitectureType::Gpp5g,
                rd: sample_rd(),
                prefix: "10.0.3.0/24".parse().unwrap(),
            },
            MupRoute::Dsd {
                id: 7,
                arch: MupArchitectureType::Gpp5g,
                rd: sample_rd(),
                address: "1.1.1.99".parse().unwrap(),
            },
            MupRoute::T1st {
                id: 7,
                arch: MupArchitectureType::Gpp5g,
                rd: sample_rd(),
                prefix: "2001:db8:cafe::5/128".parse().unwrap(),
                teid: 601,
                qfi: 9,
                endpoint: "2001:db8::99".parse().unwrap(),
                source: Some("2001:db8::1".parse().unwrap()),
            },
            MupRoute::T2st {
                id: 7,
                arch: MupArchitectureType::Gpp5g,
                rd: sample_rd(),
                endpoint: "20.0.1.1".parse().unwrap(),
                endpoint_len: 64,
                teid: 600,
            },
        ];
        let expect_afi = [Afi::Ip, Afi::Ip, Afi::Ip6, Afi::Ip];
        for (route, afi) in cases.iter().zip(expect_afi) {
            let (rd, prefix) = MupPrefix::from_route(route);
            assert_eq!(prefix.afi(), afi);
            // to_route() round-trips back to the same (rd, key).
            assert_eq!(MupPrefix::from_route(&prefix.to_route(rd)), (rd, prefix));
        }
    }

    #[test]
    fn mup_prefix_orders_dsd_before_isd_before_st() {
        let (_, dsd) = MupPrefix::from_route(&MupRoute::Dsd {
            id: 0,
            arch: MupArchitectureType::Gpp5g,
            rd: sample_rd(),
            address: "1.1.1.1".parse().unwrap(),
        });
        let (isd_rd, isd) = MupPrefix::from_route(&MupRoute::Isd {
            id: 0,
            arch: MupArchitectureType::Gpp5g,
            rd: sample_rd(),
            prefix: "10.0.0.0/24".parse().unwrap(),
        });
        let (_, st2) = MupPrefix::from_route(&MupRoute::T2st {
            id: 0,
            arch: MupArchitectureType::Gpp5g,
            rd: sample_rd(),
            endpoint: "20.0.1.1".parse().unwrap(),
            endpoint_len: 64,
            teid: 600,
        });
        assert!(dsd < isd, "Dsd sorts before Isd");
        assert!(isd < st2, "Isd sorts before T2st");
        assert_eq!(dsd.route_type(), 2);
        assert_eq!(isd.route_type(), 1);
        assert_eq!(st2.route_type(), 4);
        // The RD is now the outer per-RD map key, returned alongside the key.
        assert_eq!(isd_rd, sample_rd());
    }
}
