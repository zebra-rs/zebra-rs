use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::BytesMut;
use nom::error::{ErrorKind, make_error};
use nom::number::complete::{be_u8, be_u32, be_u128};
use nom_derive::*;

use bytes::BufMut;

use crate::{
    Afi, AttrFlags, AttrType, EvpnRoute, Ipv4Nlri, Ipv6Nlri, ParseBe, ParseNlri, ParseOption,
    Rtcv4, Safi, Vpnv4Nexthop, Vpnv4Nlri, many0_complete,
};

use super::{AttrEmitter, RouteDistinguisher, Rtcv4Reach, Vpnv4Reach};

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
    Evpn {
        snpa: u8,
        nhop: IpAddr,
        updates: Vec<EvpnRoute>,
    },
    Rtcv4(Rtcv4Reach),
}

impl MpReachAttr {
    pub fn attr_emit(&self, buf: &mut BytesMut) {
        match self {
            MpReachAttr::Vpnv4(nlri) => {
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
fn evpn_attr_emit(_snpa: u8, nhop: &IpAddr, updates: &[EvpnRoute], buf: &mut BytesMut) {
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
