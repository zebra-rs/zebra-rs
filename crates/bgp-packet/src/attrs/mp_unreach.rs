use std::fmt;

use bytes::{BufMut, BytesMut};
use nom::error::{ErrorKind, make_error};
use nom_derive::*;

use crate::{
    Afi, AttrFlags, AttrType, EvpnRoute, Ipv6Nlri, ParseBe, ParseNlri, ParseOption, Rtcv4,
    Rtcv4Unreach, Safi, Vpnv4Nlri, many0_complete,
};

use super::{AttrEmitter, Vpnv4Unreach};

#[derive(Clone, Debug, NomBE)]
pub struct MpUnreachHeader {
    pub afi: Afi,
    pub safi: Safi,
}

#[derive(Clone)]
pub enum MpUnreachAttr {
    // Ipv4Nlri(Vec<>),
    Ipv4Eor,
    Ipv6Nlri(Vec<Ipv6Nlri>),
    Ipv6Eor,
    Vpnv4(Vec<Vpnv4Nlri>),
    Vpnv4Eor,
    // Vpnv6,
    // Vpnv6Eor,
    Evpn(Vec<EvpnRoute>),
    EvpnEor,
    Rtcv4(Vec<Rtcv4>),
    Rtcv4Eor,
}

impl MpUnreachAttr {
    pub fn attr_emit(&self, buf: &mut BytesMut) {
        match self {
            MpUnreachAttr::Vpnv4(withdraw) => {
                let attr = Vpnv4Unreach {
                    withdraw: withdraw.clone(),
                };
                attr.attr_emit(buf);
            }
            MpUnreachAttr::Vpnv4Eor => {
                let attr = Vpnv4Unreach { withdraw: vec![] };
                attr.attr_emit(buf);
            }
            MpUnreachAttr::Rtcv4Eor => {
                let attr = Rtcv4Unreach { withdraw: vec![] };
                attr.attr_emit(buf);
            }
            MpUnreachAttr::Evpn(withdraw) => {
                evpn_unreach_attr_emit(withdraw, buf);
            }
            MpUnreachAttr::EvpnEor => {
                evpn_unreach_attr_emit(&[], buf);
            }
            _ => {
                //
            }
        }
    }
}

/// Serialize an `MpUnreachAttr::Evpn(updates)` (or `EvpnEor` when
/// `updates` is empty) as a complete `MP_UNREACH_NLRI` path attribute
/// (header + value).
///
/// Wire format (RFC 4760 §4):
/// ```text
///   AFI  (2 octets) = 25 (L2VPN)
///   SAFI (1 octet)  = 70 (EVPN)
///   Withdrawn Routes (one or more EvpnRoute encodings; empty for EoR)
/// ```
///
/// MP_UNREACH carries neither nexthop nor SNPA — only the AFI/SAFI
/// header and the NLRI list. The NLRI body bytes are produced by
/// `EvpnRoute::nlri_emit` (PR #399), the same encoder used by the
/// MP_REACH advertise path.
fn evpn_unreach_attr_emit(withdraw: &[EvpnRoute], buf: &mut BytesMut) {
    let mut value = BytesMut::new();
    value.put_u16(u16::from(Afi::L2vpn));
    value.put_u8(u8::from(Safi::Evpn));
    for r in withdraw {
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
    buf.put_u8(AttrType::MpUnreachNlri.into());
    if extended {
        buf.put_u16(len as u16);
    } else {
        buf.put_u8(len as u8);
    }
    buf.put(&value[..]);
}

impl MpUnreachAttr {
    pub fn parse_nlri_opt(input: &[u8], opt: Option<ParseOption>) -> nom::IResult<&[u8], Self> {
        // AFI + SAFI = 3.
        if input.len() < 3 {
            return Err(nom::Err::Error(nom::error::Error::new(
                input,
                ErrorKind::Verify,
            )));
        }
        let (input, header) = MpUnreachHeader::parse_be(input)?;
        let add_path = if let Some(opt) = opt {
            opt.is_add_path_recv(header.afi, header.safi)
        } else {
            false
        };
        if header.afi == Afi::Ip && header.safi == Safi::MplsVpn {
            if input.is_empty() {
                let mp_nlri = MpUnreachAttr::Vpnv4Eor;
                return Ok((input, mp_nlri));
            }
            let (input, withdrawal) =
                many0_complete(|i| Vpnv4Nlri::parse_nlri(i, add_path)).parse(input)?;
            let mp_nlri = MpUnreachAttr::Vpnv4(withdrawal);
            return Ok((input, mp_nlri));
        }
        if header.afi == Afi::Ip6 && header.safi == Safi::Unicast {
            if input.is_empty() {
                let mp_nlri = MpUnreachAttr::Ipv6Eor;
                return Ok((input, mp_nlri));
            }
            let (input, withdrawal) =
                many0_complete(|i| Ipv6Nlri::parse_nlri(i, add_path)).parse(input)?;
            let mp_nlri = MpUnreachAttr::Ipv6Nlri(withdrawal);
            return Ok((input, mp_nlri));
        }
        if header.afi == Afi::L2vpn && header.safi == Safi::Evpn {
            if input.is_empty() {
                let mp_nlri = MpUnreachAttr::EvpnEor;
                return Ok((input, mp_nlri));
            }
            let (input, evpns) =
                many0_complete(|i| EvpnRoute::parse_nlri(i, add_path)).parse(input)?;
            let mp_nlri = MpUnreachAttr::Evpn(evpns);
            return Ok((input, mp_nlri));
        }
        if header.afi == Afi::Ip && header.safi == Safi::Rtc {
            if input.is_empty() {
                let mp_nlri = MpUnreachAttr::Rtcv4Eor;
                return Ok((input, mp_nlri));
            }
            let (input, rtcv4) = many0_complete(|i| Rtcv4::parse_nlri(i, add_path)).parse(input)?;
            let mp_nlri = MpUnreachAttr::Rtcv4(rtcv4);
            return Ok((input, mp_nlri));
        }
        Err(nom::Err::Error(make_error(input, ErrorKind::NoneOf)))
    }
}

impl ParseBe<MpUnreachAttr> for MpUnreachAttr {
    fn parse_be(input: &[u8]) -> nom::IResult<&[u8], Self> {
        Self::parse_nlri_opt(input, None)
    }
}

impl fmt::Display for MpUnreachAttr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use MpUnreachAttr::*;
        match self {
            Ipv4Eor => {
                writeln!(f, " EoR: {}/{}", Afi::Ip, Safi::Unicast)
            }
            Ipv6Nlri(ipv6_nlris) => {
                for ipv6 in ipv6_nlris.iter() {
                    writeln!(f, " {}:{}", ipv6.id, ipv6.prefix)?;
                }
                Ok(())
            }
            Ipv6Eor => {
                writeln!(f, " EoR: {}/{}", Afi::Ip6, Safi::Unicast)
            }
            Vpnv4(vpnv4_nlris) => {
                for vpnv4 in vpnv4_nlris.iter() {
                    writeln!(f, " {}:{}:{}", vpnv4.nlri.id, vpnv4.rd, vpnv4.nlri.prefix)?;
                }
                Ok(())
            }
            Vpnv4Eor => {
                writeln!(f, " EoR: {}/{}", Afi::Ip, Safi::MplsVpn)
            }
            Evpn(evpn_routes) => {
                for evpn in evpn_routes.iter() {
                    match evpn {
                        EvpnRoute::Mac(v) => {
                            writeln!(
                                f,
                                " RD: {}, VNI: {}, MAC: {:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
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
                            writeln!(f, " [{}]{}", v.rd, v.addr)?;
                        }
                    }
                }
                Ok(())
            }
            EvpnEor => {
                writeln!(f, " EoR: {}/{}", Afi::L2vpn, Safi::Evpn)
            }
            Rtcv4(rtcv4s) => {
                for rtcv4 in rtcv4s {
                    writeln!(f, " ASN:{} {}", rtcv4.asn, rtcv4.rt)?;
                }
                Ok(())
            }
            Rtcv4Eor => {
                writeln!(f, " EoR: {}/{}", Afi::Ip, Safi::Rtc)
            }
        }
    }
}

impl fmt::Debug for MpUnreachAttr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}
