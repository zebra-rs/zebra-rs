use std::fmt;

use bytes::BytesMut;
use nom::error::{ErrorKind, make_error};
use nom_derive::*;

use crate::{
    Afi, EvpnRoute, Ipv6Nlri, ParseBe, ParseNlri, ParseOption, Rtcv4, Rtcv4Unreach, Safi,
    Vpnv4Nlri, many0,
};

use super::{AttrEmitter, Vpnv4Unreach};

#[derive(Clone, Debug, NomBE)]
pub struct MpNlriUnreachHeader {
    pub afi: Afi,
    pub safi: Safi,
}

#[derive(Clone)]
pub enum MpNlriUnreachAttr {
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

impl MpNlriUnreachAttr {
    pub fn attr_emit(&self, buf: &mut BytesMut) {
        match self {
            MpNlriUnreachAttr::Vpnv4(withdraw) => {
                let attr = Vpnv4Unreach {
                    withdraw: withdraw.clone(),
                };
                attr.attr_emit(buf);
            }
            MpNlriUnreachAttr::Vpnv4Eor => {
                let attr = Vpnv4Unreach { withdraw: vec![] };
                attr.attr_emit(buf);
            }
            MpNlriUnreachAttr::Rtcv4Eor => {
                let attr = Rtcv4Unreach { withdraw: vec![] };
                attr.attr_emit(buf);
            }
            _ => {
                //
            }
        }
    }
}

impl MpNlriUnreachAttr {
    pub fn parse_nlri_opt(input: &[u8], opt: Option<ParseOption>) -> nom::IResult<&[u8], Self> {
        // AFI + SAFI = 3.
        if input.len() < 3 {
            return Err(nom::Err::Error(nom::error::Error::new(
                input,
                ErrorKind::Verify,
            )));
        }
        let (input, header) = MpNlriUnreachHeader::parse_be(input)?;
        let add_path = if let Some(opt) = opt {
            opt.is_add_path_recv(header.afi, header.safi)
        } else {
            false
        };
        if header.afi == Afi::Ip && header.safi == Safi::MplsVpn {
            if input.is_empty() {
                let mp_nlri = MpNlriUnreachAttr::Vpnv4Eor;
                return Ok((input, mp_nlri));
            }
            let (input, withdrawal) = many0(|i| Vpnv4Nlri::parse_nlri(i, add_path)).parse(input)?;
            let mp_nlri = MpNlriUnreachAttr::Vpnv4(withdrawal);
            return Ok((input, mp_nlri));
        }
        if header.afi == Afi::Ip6 && header.safi == Safi::Unicast {
            if input.is_empty() {
                let mp_nlri = MpNlriUnreachAttr::Ipv6Eor;
                return Ok((input, mp_nlri));
            }
            let (input, withdrawal) = many0(|i| Ipv6Nlri::parse_nlri(i, add_path)).parse(input)?;
            let mp_nlri = MpNlriUnreachAttr::Ipv6Nlri(withdrawal);
            return Ok((input, mp_nlri));
        }
        if header.afi == Afi::L2vpn && header.safi == Safi::Evpn {
            if input.is_empty() {
                let mp_nlri = MpNlriUnreachAttr::EvpnEor;
                return Ok((input, mp_nlri));
            }
            let (input, evpns) = many0(|i| EvpnRoute::parse_nlri(i, add_path)).parse(input)?;
            let mp_nlri = MpNlriUnreachAttr::Evpn(evpns);
            return Ok((input, mp_nlri));
        }
        if header.afi == Afi::Ip && header.safi == Safi::Rtc {
            if input.is_empty() {
                let mp_nlri = MpNlriUnreachAttr::Rtcv4Eor;
                return Ok((input, mp_nlri));
            }
            let (input, rtcv4) = many0(|i| Rtcv4::parse_nlri(i, add_path)).parse(input)?;
            let mp_nlri = MpNlriUnreachAttr::Rtcv4(rtcv4);
            return Ok((input, mp_nlri));
        }
        Err(nom::Err::Error(make_error(input, ErrorKind::NoneOf)))
    }
}

impl ParseBe<MpNlriUnreachAttr> for MpNlriUnreachAttr {
    fn parse_be(input: &[u8]) -> nom::IResult<&[u8], Self> {
        Self::parse_nlri_opt(input, None)
    }
}

impl fmt::Display for MpNlriUnreachAttr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use MpNlriUnreachAttr::*;
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

impl fmt::Debug for MpNlriUnreachAttr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}
