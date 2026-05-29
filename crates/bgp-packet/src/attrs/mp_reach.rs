use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::BytesMut;
use nom::error::{ErrorKind, make_error};
use nom::number::complete::{be_u8, be_u32, be_u128};
use nom_derive::*;

use bytes::BufMut;

use crate::{
    Afi, AttrFlags, AttrType, EvpnRoute, Ipv4Nlri, Ipv6Nlri, MupRoute, ParseBe, ParseNlri,
    ParseOption, Rtcv4, Safi, Vpnv4Nexthop, Vpnv4Nlri, Vpnv6Nexthop, Vpnv6Nlri, many0_complete,
};

use super::{AttrEmitter, RouteDistinguisher, Rtcv4Reach, Vpnv4Reach, Vpnv6Reach};

#[derive(Clone, Debug, NomBE)]
pub struct MpReachHeader {
    pub afi: Afi,
    pub safi: Safi,
    pub nhop_len: u8,
}

#[derive(Clone)]
pub enum MpReachAttr {
    Ipv4 {
        snpa: u8,
        nhop: IpAddr,
        updates: Vec<Ipv4Nlri>,
    },
    Ipv6 {
        snpa: u8,
        nhop: IpAddr,
        updates: Vec<Ipv6Nlri>,
    },
    Vpnv4(Vpnv4Reach),
    Vpnv6(Vpnv6Reach),
    Evpn {
        snpa: u8,
        nhop: IpAddr,
        updates: Vec<EvpnRoute>,
    },
    Rtcv4(Rtcv4Reach),
    /// BGP MUP (RFC 9833), SAFI 85. The outer AFI distinguishes the
    /// IPv4 from the IPv6 MUP address family; per-route-type bodies
    /// stay opaque at this phase.
    Mup {
        afi: Afi,
        snpa: u8,
        nhop: IpAddr,
        updates: Vec<MupRoute>,
    },
}

impl MpReachAttr {
    pub fn attr_emit(&self, buf: &mut BytesMut) {
        match self {
            MpReachAttr::Vpnv4(nlri) => {
                nlri.attr_emit(buf);
            }
            MpReachAttr::Vpnv6(nlri) => {
                nlri.attr_emit(buf);
            }
            MpReachAttr::Rtcv4(nlri) => {
                nlri.attr_emit(buf);
            }
            MpReachAttr::Evpn {
                snpa,
                nhop,
                updates,
            } => {
                evpn_attr_emit(*snpa, nhop, updates, buf);
            }
            MpReachAttr::Mup {
                afi,
                snpa,
                nhop,
                updates,
            } => {
                mup_attr_emit(*afi, *snpa, nhop, updates, buf);
            }
            _ => {
                //
            }
        }
    }

    pub fn attr_emit_mut(&mut self, buf: &mut BytesMut, max_size: usize) {
        match self {
            MpReachAttr::Vpnv4(attr) => {
                attr.attr_emit_mut(buf, max_size);
            }
            MpReachAttr::Vpnv6(attr) => {
                attr.attr_emit_mut(buf, max_size);
            }
            _ => {
                //
            }
        }
    }
}

impl MpReachAttr {
    pub fn parse_nlri_opt(input: &[u8], opt: Option<ParseOption>) -> nom::IResult<&[u8], Self> {
        if input.len() < size_of::<MpReachHeader>() {
            return Err(nom::Err::Error(make_error(input, ErrorKind::Eof)));
        }
        let (input, header) = MpReachHeader::parse_be(input)?;
        let add_path = if let Some(opt) = opt {
            opt.is_add_path_recv(header.afi, header.safi)
        } else {
            false
        };
        if header.afi == Afi::Ip && header.safi == Safi::MplsVpn {
            let (input, rd) = RouteDistinguisher::parse_be(input)?;
            let (input, nhop) = be_u32(input)?;
            let nhop: Ipv4Addr = Ipv4Addr::from(nhop);
            let nhop = Vpnv4Nexthop { rd, nhop };
            let (input, snpa) = be_u8(input)?;
            let (_, updates) =
                many0_complete(|i| Vpnv4Nlri::parse_nlri(i, add_path)).parse(input)?;
            let nlri = Vpnv4Reach {
                snpa,
                nhop,
                updates,
            };
            let mp_nlri = MpReachAttr::Vpnv4(nlri);
            return Ok((input, mp_nlri));
        }
        if header.afi == Afi::Ip6 && header.safi == Safi::MplsVpn {
            // VPNv6 next-hop (RFC 4659 §3.2): an 8-octet RD (always
            // zero on the wire) followed by the IPv6 address. The
            // 48-octet form carries global || link-local, each with its
            // own zero RD (RFC 8950 style); surface the global half.
            let (input, nhop) = match header.nhop_len {
                24 => {
                    let (input, rd) = RouteDistinguisher::parse_be(input)?;
                    let (input, addr) = be_u128(input)?;
                    (
                        input,
                        Vpnv6Nexthop {
                            rd,
                            nhop: Ipv6Addr::from(addr),
                        },
                    )
                }
                48 => {
                    let (input, rd) = RouteDistinguisher::parse_be(input)?;
                    let (input, global) = be_u128(input)?;
                    let (input, _ll_rd) = RouteDistinguisher::parse_be(input)?;
                    let (input, _link_local) = be_u128(input)?;
                    (
                        input,
                        Vpnv6Nexthop {
                            rd,
                            nhop: Ipv6Addr::from(global),
                        },
                    )
                }
                _ => return Err(nom::Err::Error(make_error(input, ErrorKind::LengthValue))),
            };
            let (input, snpa) = be_u8(input)?;
            let (_, updates) =
                many0_complete(|i| Vpnv6Nlri::parse_nlri(i, add_path)).parse(input)?;
            let nlri = Vpnv6Reach {
                snpa,
                nhop,
                updates,
            };
            let mp_nlri = MpReachAttr::Vpnv6(nlri);
            return Ok((input, mp_nlri));
        }
        if header.afi == Afi::Ip && header.safi == Safi::Unicast {
            // RFC 8950 §3: once Extended Next Hop is negotiated, an
            // MP_REACH carrying IPv4 unicast NLRI may use either an
            // IPv4 next-hop (4 octets) or an IPv6 next-hop (16 octets,
            // or 32 octets carrying global || link-local). Receivers
            // SHOULD accept either length; for the 32-octet form, we
            // take the first 16 octets as the canonical next-hop —
            // the global half by convention, falling back to the
            // link-local when the sender only has one.
            let (input, nhop): (&[u8], IpAddr) = match header.nhop_len {
                4 => {
                    let (input, addr) = be_u32(input)?;
                    (input, IpAddr::V4(Ipv4Addr::from(addr)))
                }
                16 => {
                    let (input, addr) = be_u128(input)?;
                    (input, IpAddr::V6(Ipv6Addr::from(addr)))
                }
                32 => {
                    // Global || link-local; consume both, surface the
                    // global for now. PR D will revisit if best-path
                    // resolution wants the link-local explicitly.
                    let (input, global) = be_u128(input)?;
                    let (input, _link_local) = be_u128(input)?;
                    (input, IpAddr::V6(Ipv6Addr::from(global)))
                }
                _ => return Err(nom::Err::Error(make_error(input, ErrorKind::LengthValue))),
            };
            let (input, snpa) = be_u8(input)?;
            let (_, updates) =
                many0_complete(|i| Ipv4Nlri::parse_nlri(i, add_path)).parse(input)?;
            let mp_nlri = MpReachAttr::Ipv4 {
                snpa,
                nhop,
                updates,
            };
            return Ok((input, mp_nlri));
        }
        if header.afi == Afi::Ip6 && header.safi == Safi::Unicast {
            if header.nhop_len != 16 {
                return Err(nom::Err::Error(make_error(input, ErrorKind::LengthValue)));
            }
            let (input, nhop) = be_u128(input)?;
            let nhop = IpAddr::V6(Ipv6Addr::from(nhop));
            let (input, snpa) = be_u8(input)?;
            let (_, updates) =
                many0_complete(|i| Ipv6Nlri::parse_nlri(i, add_path)).parse(input)?;
            let mp_nlri = MpReachAttr::Ipv6 {
                snpa,
                nhop,
                updates,
            };
            return Ok((input, mp_nlri));
        }
        if header.afi == Afi::L2vpn && header.safi == Safi::Evpn {
            // Nexthop can be IPv4 or IPv6 address.
            if header.nhop_len != 4 && header.nhop_len != 16 {
                return Err(nom::Err::Error(make_error(input, ErrorKind::LengthValue)));
            }
            let (input, nhop) = if header.nhop_len == 4 {
                let (input, addr) = be_u32(input)?;
                let nhop: IpAddr = IpAddr::V4(Ipv4Addr::from(addr));
                (input, nhop)
            } else {
                let (input, addr) = be_u128(input)?;
                let nhop: IpAddr = IpAddr::V6(Ipv6Addr::from(addr));
                (input, nhop)
            };
            let (input, snpa) = be_u8(input)?;

            // EVPN
            let (input, updates) =
                many0_complete(|i| EvpnRoute::parse_nlri(i, add_path)).parse(input)?;

            let mp_nlri = MpReachAttr::Evpn {
                snpa,
                nhop,
                updates,
            };
            return Ok((input, mp_nlri));
        }
        if (header.afi == Afi::Ip || header.afi == Afi::Ip6) && header.safi == Safi::Mup {
            // RFC 9833 §11: MUP nexthop matches the underlying IP
            // SAFI's. Accept 4 (IPv4), 16 (IPv6 single), or 32 (IPv6
            // global || link-local — RFC 8950 style), and surface the
            // global half. Anything else is malformed.
            let (input, nhop): (&[u8], IpAddr) = match header.nhop_len {
                4 => {
                    let (input, addr) = be_u32(input)?;
                    (input, IpAddr::V4(Ipv4Addr::from(addr)))
                }
                16 => {
                    let (input, addr) = be_u128(input)?;
                    (input, IpAddr::V6(Ipv6Addr::from(addr)))
                }
                32 => {
                    let (input, global) = be_u128(input)?;
                    let (input, _link_local) = be_u128(input)?;
                    (input, IpAddr::V6(Ipv6Addr::from(global)))
                }
                _ => return Err(nom::Err::Error(make_error(input, ErrorKind::LengthValue))),
            };
            let (input, snpa) = be_u8(input)?;
            let (input, updates) =
                many0_complete(|i| MupRoute::parse(i, add_path, header.afi)).parse(input)?;
            let mp_nlri = MpReachAttr::Mup {
                afi: header.afi,
                snpa,
                nhop,
                updates,
            };
            return Ok((input, mp_nlri));
        }
        if header.afi == Afi::Ip && header.safi == Safi::Rtc {
            // Nexthop can be IPv4 or IPv6 address.
            if header.nhop_len != 4 && header.nhop_len != 16 {
                return Err(nom::Err::Error(make_error(input, ErrorKind::LengthValue)));
            }
            let (input, nhop) = if header.nhop_len == 4 {
                let (input, addr) = be_u32(input)?;
                let nhop: IpAddr = IpAddr::V4(Ipv4Addr::from(addr));
                (input, nhop)
            } else {
                let (input, addr) = be_u128(input)?;
                let nhop: IpAddr = IpAddr::V6(Ipv6Addr::from(addr));
                (input, nhop)
            };
            let (input, snpa) = be_u8(input)?;
            let (input, updates) =
                many0_complete(|i| Rtcv4::parse_nlri(i, add_path)).parse(input)?;
            let nlri = Rtcv4Reach {
                snpa,
                nhop,
                updates,
            };
            let rtc_nlri = MpReachAttr::Rtcv4(nlri);
            return Ok((input, rtc_nlri));
        }
        Err(nom::Err::Error(make_error(input, ErrorKind::NoneOf)))
    }
}

// Not used.
impl ParseBe<MpReachAttr> for MpReachAttr {
    fn parse_be(input: &[u8]) -> nom::IResult<&[u8], Self> {
        Self::parse_nlri_opt(input, None)
    }
}

impl fmt::Display for MpReachAttr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use MpReachAttr::*;
        match self {
            Ipv4 {
                snpa: _,
                nhop,
                updates,
            } => {
                for update in updates.iter() {
                    writeln!(f, "{}:{} => {}", update.id, update.prefix, nhop)?;
                }
            }
            Ipv6 {
                snpa: _,
                nhop,
                updates,
            } => {
                for update in updates.iter() {
                    writeln!(f, "{}:{} => {}", update.id, update.prefix, nhop)?;
                }
            }
            Vpnv4(nlri) => {
                for update in nlri.updates.iter() {
                    writeln!(
                        f,
                        " {}:[{}]:{}",
                        update.nlri.id, update.rd, update.nlri.prefix,
                    )?;
                }
            }
            Vpnv6(nlri) => {
                for update in nlri.updates.iter() {
                    writeln!(
                        f,
                        " {}:[{}]:{}",
                        update.nlri.id, update.rd, update.nlri.prefix,
                    )?;
                }
            }
            Evpn {
                snpa: _,
                nhop: _,
                updates,
            } => {
                for update in updates.iter() {
                    match update {
                        EvpnRoute::Mac(v) => {
                            writeln!(
                                f,
                                " [{}] VNI:{}, MAC:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                                v.rd,
                                v.vni,
                                v.mac[0],
                                v.mac[1],
                                v.mac[2],
                                v.mac[3],
                                v.mac[4],
                                v.mac[5],
                            )?;
                        }
                        EvpnRoute::Multicast(v) => {
                            writeln!(f, " [{}] {}:{}", v.rd, v.ether_tag, v.addr)?;
                        }
                    }
                }
            }
            Mup {
                afi,
                snpa: _,
                nhop,
                updates,
            } => {
                for update in updates.iter() {
                    writeln!(
                        f,
                        " {afi}/MUP rt={:?} arch={:?} body={}B => {nhop}",
                        update.route_type(),
                        update.architecture(),
                        update.body_len()
                    )?;
                }
            }
            _ => {
                //
            }
        }
        Ok(())
    }
}

impl fmt::Debug for MpReachAttr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

/// Serialize an `MpReachAttr::Evpn { snpa, nhop, updates }` as a
/// complete `MP_REACH_NLRI` path attribute (header + value).
///
/// Wire format (RFC 4760 §3 + RFC 7432 §7):
/// ```text
///   AFI  (2 octets) = 25 (L2VPN)
///   SAFI (1 octet)  = 70 (EVPN)
///   Nexthop Length (1 octet) = 4 or 16
///   Nexthop Address
///   Reserved / SNPA (1 octet) = 0
///   NLRIs (one or more EvpnRoute encodings)
/// ```
///
/// The value is buffered first so the attribute length can be set
/// before writing the header — extended (2-byte) length is used when
/// the value exceeds 255 octets, matching the convention used by
/// `Vpnv4Reach::attr_emit_mut`.
pub(crate) fn evpn_attr_emit(_snpa: u8, nhop: &IpAddr, updates: &[EvpnRoute], buf: &mut BytesMut) {
    let mut value = BytesMut::new();
    value.put_u16(u16::from(Afi::L2vpn));
    value.put_u8(u8::from(Safi::Evpn));
    match nhop {
        IpAddr::V4(v4) => {
            value.put_u8(4);
            value.put(&v4.octets()[..]);
        }
        IpAddr::V6(v6) => {
            value.put_u8(16);
            value.put(&v6.octets()[..]);
        }
    }
    // Reserved / SNPA byte, always zero per RFC 4760 §3.
    value.put_u8(0);
    for r in updates {
        r.nlri_emit(&mut value);
    }

    let len = value.len();
    let extended = len > 255;
    let flags = if extended {
        AttrFlags::new().with_optional(true).with_extended(true)
    } else {
        AttrFlags::new().with_optional(true)
    };
    buf.put_u8(flags.into());
    buf.put_u8(AttrType::MpReachNlri.into());
    if extended {
        buf.put_u16(len as u16);
    } else {
        buf.put_u8(len as u8);
    }
    buf.put(&value[..]);
}

/// Serialize an `MpReachAttr::Mup { afi, snpa, nhop, updates }` as a
/// complete `MP_REACH_NLRI` path attribute (header + value).
///
/// Wire format (RFC 4760 §3 + RFC 9833 §11):
/// ```text
///   AFI  (2 octets) = 1 (IPv4) or 2 (IPv6)
///   SAFI (1 octet)  = 85 (MUP)
///   Nexthop Length (1 octet) = 4 or 16
///   Nexthop Address
///   Reserved / SNPA (1 octet) = 0
///   NLRIs (zero or more MupRoute encodings)
/// ```
///
/// Nexthop is encoded per the address family of `nhop` (`IpAddr::V4`
/// → 4 octets, `IpAddr::V6` → 16 octets); senders that need the
/// 32-octet "global || link-local" form will be added when a caller
/// asks for it (Phase 3 keeps the emit side single-address).
pub(crate) fn mup_attr_emit(
    afi: Afi,
    _snpa: u8,
    nhop: &IpAddr,
    updates: &[MupRoute],
    buf: &mut BytesMut,
) {
    let mut value = BytesMut::new();
    value.put_u16(u16::from(afi));
    value.put_u8(u8::from(Safi::Mup));
    match nhop {
        IpAddr::V4(v4) => {
            value.put_u8(4);
            value.put(&v4.octets()[..]);
        }
        IpAddr::V6(v6) => {
            value.put_u8(16);
            value.put(&v6.octets()[..]);
        }
    }
    value.put_u8(0);
    for r in updates {
        r.nlri_emit(&mut value);
    }

    let len = value.len();
    let extended = len > 255;
    let flags = if extended {
        AttrFlags::new().with_optional(true).with_extended(true)
    } else {
        AttrFlags::new().with_optional(true)
    };
    buf.put_u8(flags.into());
    buf.put_u8(AttrType::MpReachNlri.into());
    if extended {
        buf.put_u16(len as u16);
    } else {
        buf.put_u8(len as u8);
    }
    buf.put(&value[..]);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-rolled MP_REACH value (no attr header — `parse_nlri_opt`
    /// reads just the inner value): AFI + SAFI + nhop_len + nhop +
    /// SNPA + NLRI.
    fn build(afi: u16, safi: u8, nhop: &[u8], nlri: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&afi.to_be_bytes());
        v.push(safi);
        v.push(nhop.len() as u8);
        v.extend_from_slice(nhop);
        v.push(0); // SNPA
        v.extend_from_slice(nlri);
        v
    }

    /// One IPv4 prefix `10.0.0.0/24` in compact NLRI form: 1-octet
    /// prefix length followed by the high-order 3 octets.
    fn nlri_10_24() -> Vec<u8> {
        vec![24, 10, 0, 0]
    }

    #[test]
    fn rfc8950_ipv4_with_v6_link_local_nexthop() {
        // Single 16-octet IPv6 next-hop (link-local), AFI=1, SAFI=1.
        let nhop: Ipv6Addr = "fe80::1".parse().unwrap();
        let value = build(1, 1, &nhop.octets(), &nlri_10_24());
        let (_rest, mp) = MpReachAttr::parse_nlri_opt(&value, None).expect("must parse");
        match mp {
            MpReachAttr::Ipv4 { nhop, updates, .. } => {
                assert_eq!(nhop, IpAddr::V6("fe80::1".parse().unwrap()));
                assert_eq!(updates.len(), 1);
                assert_eq!(updates[0].prefix.to_string(), "10.0.0.0/24");
            }
            other => panic!("expected Ipv4, got {:?}", other),
        }
    }

    #[test]
    fn rfc8950_ipv4_with_dual_v6_nexthop_takes_global() {
        // 32-octet form: global || link-local. We expose the global.
        let global: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let ll: Ipv6Addr = "fe80::1".parse().unwrap();
        let mut nhop = global.octets().to_vec();
        nhop.extend_from_slice(&ll.octets());
        let value = build(1, 1, &nhop, &nlri_10_24());
        let (_rest, mp) = MpReachAttr::parse_nlri_opt(&value, None).expect("must parse");
        match mp {
            MpReachAttr::Ipv4 { nhop, .. } => {
                assert_eq!(nhop, IpAddr::V6("2001:db8::1".parse().unwrap()));
            }
            other => panic!("expected Ipv4, got {:?}", other),
        }
    }

    #[test]
    fn rfc8950_ipv4_with_v4_nexthop_still_decodes() {
        // 4-octet IPv4 next-hop is the pre-8950 native case — keep
        // accepting it.
        let nhop: Ipv4Addr = "192.0.2.1".parse().unwrap();
        let value = build(1, 1, &nhop.octets(), &nlri_10_24());
        let (_rest, mp) = MpReachAttr::parse_nlri_opt(&value, None).expect("must parse");
        match mp {
            MpReachAttr::Ipv4 { nhop, .. } => {
                assert_eq!(nhop, IpAddr::V4("192.0.2.1".parse().unwrap()));
            }
            other => panic!("expected Ipv4, got {:?}", other),
        }
    }

    /// MUP NLRI body: Architecture=1, Route Type, Length, payload bytes.
    fn mup_nlri(route_type: u16, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.push(0x01); // architecture = 5G
        v.extend_from_slice(&route_type.to_be_bytes());
        v.push(payload.len() as u8);
        v.extend_from_slice(payload);
        v
    }

    /// Minimal ISD body: 8 zero RD bytes + plen=0 (default route).
    /// AFI-agnostic at plen=0, so safe to reuse for both v4 and v6.
    fn min_isd_body() -> Vec<u8> {
        let mut v = vec![0u8; 8];
        v.push(0); // plen=0 → no prefix bytes follow
        v
    }

    /// Minimal DSD body for the IPv4 outer AFI: 8 RD + 4 zero address bytes.
    fn min_dsd_body_v4() -> Vec<u8> {
        vec![0u8; 8 + 4]
    }

    /// Minimal T1ST body (AFI-agnostic at plen=0 and ep_len=0):
    /// 8 RD + 1 plen=0 + 0 prefix + 4 TEID + 1 QFI + 1 ep_len=0 + 0 endpoint.
    fn min_t1st_body() -> Vec<u8> {
        let mut v = vec![0u8; 8]; // RD
        v.push(0); // plen
        v.extend_from_slice(&[0; 4]); // TEID
        v.push(0); // QFI
        v.push(0); // ep_len
        v
    }

    #[test]
    fn mup_ipv4_round_trip_via_parse_nlri_opt() {
        let nhop: Ipv4Addr = "192.0.2.1".parse().unwrap();
        let mut nlri = mup_nlri(1, &min_isd_body());
        nlri.extend_from_slice(&mup_nlri(2, &min_dsd_body_v4()));
        let value = build(1, 85, &nhop.octets(), &nlri);
        let (_rest, mp) = MpReachAttr::parse_nlri_opt(&value, None).expect("must parse");
        match mp {
            MpReachAttr::Mup {
                afi, nhop, updates, ..
            } => {
                assert_eq!(afi, Afi::Ip);
                assert_eq!(nhop, IpAddr::V4("192.0.2.1".parse().unwrap()));
                assert_eq!(updates.len(), 2);
                assert!(matches!(updates[0], MupRoute::Isd { .. }));
                assert!(matches!(updates[1], MupRoute::Dsd { .. }));
            }
            other => panic!("expected Mup, got {other:?}"),
        }
    }

    #[test]
    fn mup_ipv6_round_trip_via_parse_nlri_opt() {
        let nhop: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let nlri = mup_nlri(3, &min_t1st_body());
        let value = build(2, 85, &nhop.octets(), &nlri);
        let (_rest, mp) = MpReachAttr::parse_nlri_opt(&value, None).expect("must parse");
        match mp {
            MpReachAttr::Mup {
                afi, nhop, updates, ..
            } => {
                assert_eq!(afi, Afi::Ip6);
                assert_eq!(nhop, IpAddr::V6("2001:db8::1".parse().unwrap()));
                assert_eq!(updates.len(), 1);
                assert!(matches!(updates[0], MupRoute::T1st { .. }));
            }
            other => panic!("expected Mup, got {other:?}"),
        }
    }

    #[test]
    fn mup_ipv6_dual_nexthop_takes_global() {
        let global: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let ll: Ipv6Addr = "fe80::1".parse().unwrap();
        let mut nhop = global.octets().to_vec();
        nhop.extend_from_slice(&ll.octets());
        let nlri = mup_nlri(1, &min_isd_body());
        let value = build(2, 85, &nhop, &nlri);
        let (_rest, mp) = MpReachAttr::parse_nlri_opt(&value, None).expect("must parse");
        match mp {
            MpReachAttr::Mup { nhop, .. } => {
                assert_eq!(nhop, IpAddr::V6("2001:db8::1".parse().unwrap()));
            }
            other => panic!("expected Mup, got {other:?}"),
        }
    }

    #[test]
    fn mup_rejects_other_nexthop_lengths() {
        for bad in [0u8, 1, 8, 15, 17, 31, 33, 64] {
            let mut value = Vec::new();
            value.extend_from_slice(&1u16.to_be_bytes()); // AFI=IPv4
            value.push(85); // SAFI=MUP
            value.push(bad);
            value.extend(std::iter::repeat_n(0u8, bad as usize));
            value.push(0); // SNPA
            value.extend_from_slice(&mup_nlri(1, &min_isd_body()));
            assert!(
                MpReachAttr::parse_nlri_opt(&value, None).is_err(),
                "expected parse error for nhop_len={bad}",
            );
        }
    }

    #[test]
    fn mup_emit_round_trips_through_parser() {
        // Emit the full attribute, strip the 1-byte flags + 1-byte
        // type + 1-byte length header, then feed the inner value back
        // through `parse_nlri_opt`.
        use std::str::FromStr;
        let nhop = IpAddr::V4("203.0.113.7".parse().unwrap());
        let updates = vec![
            MupRoute::Isd {
                id: 0,
                arch: crate::MupArchitectureType::Gpp5g,
                rd: crate::RouteDistinguisher::from_str("65000:1").unwrap(),
                prefix: "10.0.0.0/24".parse().unwrap(),
            },
            MupRoute::T2st {
                id: 0,
                arch: crate::MupArchitectureType::Gpp5g,
                rd: crate::RouteDistinguisher::from_str("65000:2").unwrap(),
                endpoint: "192.0.2.50/32".parse().unwrap(),
            },
        ];
        let mut buf = BytesMut::new();
        mup_attr_emit(Afi::Ip, 0, &nhop, &updates, &mut buf);

        // Strip header: flags(1) + type(1) + length(1).
        let value = &buf[3..];
        let (_rest, mp) =
            MpReachAttr::parse_nlri_opt(value, None).expect("emitter must round-trip");
        match mp {
            MpReachAttr::Mup {
                afi,
                nhop: parsed_nhop,
                updates: parsed,
                ..
            } => {
                assert_eq!(afi, Afi::Ip);
                assert_eq!(parsed_nhop, nhop);
                assert_eq!(parsed, updates);
            }
            other => panic!("expected Mup, got {other:?}"),
        }
    }

    #[test]
    fn rfc8950_ipv4_rejects_other_nexthop_lengths() {
        // Anything outside {4, 16, 32} must error so a malformed
        // sender resets cleanly instead of being silently truncated.
        for bad in [0u8, 1, 8, 15, 17, 31, 33, 64] {
            let mut value = Vec::new();
            value.extend_from_slice(&1u16.to_be_bytes()); // AFI=1
            value.push(1); // SAFI=1
            value.push(bad); // nhop_len
            value.extend(std::iter::repeat_n(0u8, bad as usize));
            value.push(0); // SNPA
            value.extend_from_slice(&nlri_10_24());
            assert!(
                MpReachAttr::parse_nlri_opt(&value, None).is_err(),
                "expected parse error for nhop_len={bad}",
            );
        }
    }
}
