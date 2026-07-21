use std::fmt;

use bytes::{BufMut, BytesMut};
use nom::error::{ErrorKind, make_error};
use nom_derive::*;

use crate::{
    Afi, AttrFlags, AttrType, BgpLsNlri, EvpnRoute, FlowspecNlri, Ipv4Nlri, Ipv6Nlri, Labelv4Nlri,
    Labelv6Nlri, MupRoute, ParseBe, ParseNlri, ParseOption, Rtcv4, Rtcv4Unreach, Rtcv6,
    Rtcv6Unreach, Safi, SrPolicyNlri, Vpnv4Nlri, Vpnv6Nlri, parse_nlri_block,
};

use super::{AttrEmitter, Vpnv4Unreach, Vpnv6Unreach};

#[derive(Clone, Debug, NomBE)]
pub struct MpUnreachHeader {
    pub afi: Afi,
    pub safi: Safi,
}

#[derive(Clone)]
pub enum MpUnreachAttr {
    /// IPv4 unicast withdrawals carried in MP_UNREACH (RFC 4760 §4,
    /// AFI=1/SAFI=1). IPv4 unicast normally uses the UPDATE's legacy
    /// Withdrawn Routes field, but a sender that announces through
    /// MP_REACH typically withdraws through MP_UNREACH too, and
    /// RFC 4760 permits it whenever capability 1/1 is negotiated.
    Ipv4Nlri(Vec<Ipv4Nlri>),
    Ipv4Eor,
    Ipv6Nlri(Vec<Ipv6Nlri>),
    Ipv6Eor,
    Vpnv4(Vec<Vpnv4Nlri>),
    Vpnv4Eor,
    Vpnv6(Vec<Vpnv6Nlri>),
    Vpnv6Eor,
    Evpn(Vec<EvpnRoute>),
    EvpnEor,
    Rtcv4(Vec<Rtcv4>),
    Rtcv4Eor,
    Rtcv6(Vec<Rtcv6>),
    Rtcv6Eor,
    /// BGP MUP withdraws (draft-ietf-bess-mup-safi §11). The outer AFI is preserved
    /// so the emitter can re-encode it without a separate Eor
    /// variant; an empty `withdraws` list represents end-of-RIB.
    Mup {
        afi: Afi,
        withdraws: Vec<MupRoute>,
    },
    /// BGP Flow Specification withdraws (RFC 8955 / RFC 8956), SAFI 133.
    /// As with MUP, the outer AFI is preserved and an empty `withdraws`
    /// list represents end-of-RIB.
    Flowspec {
        afi: Afi,
        withdraws: Vec<FlowspecNlri>,
    },
    /// IPv4 Labeled-Unicast withdrawals (RFC 3107 / RFC 8277), SAFI 4.
    Labelv4(Vec<Labelv4Nlri>),
    Labelv4Eor,
    /// IPv6 Labeled-Unicast withdrawals (RFC 3107 / RFC 8277), SAFI 4.
    Labelv6(Vec<Labelv6Nlri>),
    Labelv6Eor,
    /// BGP SR Policy withdraws (RFC 9830), SAFI 73. The outer AFI is
    /// preserved so the emitter can re-encode it; an empty `withdraws`
    /// list represents end-of-RIB.
    SrPolicy {
        afi: Afi,
        withdraws: Vec<SrPolicyNlri>,
    },
    /// BGP Link-State withdrawals (RFC 9552), AFI 16388 / SAFI 71. An empty
    /// `withdraws` list represents end-of-RIB.
    LinkState {
        withdraws: Vec<BgpLsNlri>,
    },
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
            MpUnreachAttr::Vpnv6(withdraw) => {
                let attr = Vpnv6Unreach {
                    withdraw: withdraw.clone(),
                };
                attr.attr_emit(buf);
            }
            MpUnreachAttr::Vpnv6Eor => {
                let attr = Vpnv6Unreach { withdraw: vec![] };
                attr.attr_emit(buf);
            }
            MpUnreachAttr::Ipv4Nlri(withdraws) => {
                ipv4_unreach_attr_emit(withdraws, buf);
            }
            MpUnreachAttr::Ipv4Eor => {
                ipv4_unreach_attr_emit(&[], buf);
            }
            MpUnreachAttr::Ipv6Nlri(withdraws) => {
                ipv6_unreach_attr_emit(withdraws, buf);
            }
            MpUnreachAttr::Ipv6Eor => {
                ipv6_unreach_attr_emit(&[], buf);
            }
            MpUnreachAttr::Rtcv4Eor => {
                let attr = Rtcv4Unreach { withdraw: vec![] };
                attr.attr_emit(buf);
            }
            MpUnreachAttr::Rtcv6Eor => {
                let attr = Rtcv6Unreach { withdraw: vec![] };
                attr.attr_emit(buf);
            }
            MpUnreachAttr::Evpn(withdraw) => {
                evpn_unreach_attr_emit(withdraw, buf);
            }
            MpUnreachAttr::EvpnEor => {
                evpn_unreach_attr_emit(&[], buf);
            }
            MpUnreachAttr::Mup { afi, withdraws } => {
                mup_unreach_attr_emit(*afi, withdraws, buf);
            }
            MpUnreachAttr::Flowspec { afi, withdraws } => {
                flowspec_unreach_attr_emit(*afi, withdraws, buf);
            }
            MpUnreachAttr::Labelv4(withdraws) => {
                labelv4_unreach_attr_emit(withdraws, buf);
            }
            MpUnreachAttr::Labelv4Eor => {
                labelv4_unreach_attr_emit(&[], buf);
            }
            MpUnreachAttr::Labelv6(withdraws) => {
                labelv6_unreach_attr_emit(withdraws, buf);
            }
            MpUnreachAttr::Labelv6Eor => {
                labelv6_unreach_attr_emit(&[], buf);
            }
            MpUnreachAttr::SrPolicy { afi, withdraws } => {
                srpolicy_unreach_attr_emit(*afi, withdraws, buf);
            }
            MpUnreachAttr::LinkState { withdraws } => {
                linkstate_unreach_attr_emit(withdraws, buf);
            }
            _ => {
                //
            }
        }
    }
}

/// Serialize an `MpUnreachAttr::Ipv4Nlri(withdraws)` (or `Ipv4Eor` when
/// `withdraws` is empty) as a complete MP_UNREACH_NLRI path attribute.
///
/// Wire format (RFC 4760 §4): AFI=1, SAFI=1, then the NLRI list (empty
/// for end-of-RIB). zebra-rs itself withdraws IPv4 unicast through the
/// UPDATE's legacy Withdrawn Routes field, so this is the decode-side
/// inverse rather than something the advertise path emits.
fn ipv4_unreach_attr_emit(withdraws: &[Ipv4Nlri], buf: &mut BytesMut) {
    let mut value = BytesMut::new();
    value.put_u16(u16::from(Afi::Ip));
    value.put_u8(u8::from(Safi::Unicast));
    for nlri in withdraws {
        nlri.nlri_emit(&mut value);
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

/// Serialize an `MpUnreachAttr::Ipv6Nlri(withdraws)` (or `Ipv6Eor`
/// when `withdraws` is empty) as a complete MP_UNREACH_NLRI path
/// attribute. IPv6 unicast withdrawals have no legacy field, so this
/// is the only encode path.
///
/// Wire format (RFC 4760 §4): AFI=2, SAFI=1, then the NLRI list (empty
/// for end-of-RIB).
fn ipv6_unreach_attr_emit(withdraws: &[Ipv6Nlri], buf: &mut BytesMut) {
    let mut value = BytesMut::new();
    value.put_u16(u16::from(Afi::Ip6));
    value.put_u8(u8::from(Safi::Unicast));
    for nlri in withdraws {
        nlri.nlri_emit(&mut value);
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
/// `EvpnRoute::nlri_emit`, the same encoder used by the
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

/// Serialize an `MpUnreachAttr::Mup { afi, withdraws }` (empty
/// `withdraws` encodes an end-of-RIB marker) as a complete
/// `MP_UNREACH_NLRI` path attribute.
///
/// Wire format (RFC 4760 §4 + draft-ietf-bess-mup-safi §11):
/// ```text
///   AFI  (2 octets) = 1 (IPv4) or 2 (IPv6)
///   SAFI (1 octet)  = 85 (MUP)
///   Withdrawn Routes (zero or more MupRoute encodings)
/// ```
fn mup_unreach_attr_emit(afi: Afi, withdraws: &[MupRoute], buf: &mut BytesMut) {
    let mut value = BytesMut::new();
    value.put_u16(u16::from(afi));
    value.put_u8(u8::from(Safi::Mup));
    for r in withdraws {
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

/// Serialize an `MpUnreachAttr::Flowspec { afi, withdraws }` (empty
/// `withdraws` encodes an end-of-RIB marker) as a complete
/// `MP_UNREACH_NLRI` path attribute.
///
/// Wire format (RFC 4760 §4 + RFC 8955 §4.2.2): AFI, SAFI=133, then the
/// NLRI list. MP_UNREACH carries neither next-hop nor SNPA.
fn flowspec_unreach_attr_emit(afi: Afi, withdraws: &[FlowspecNlri], buf: &mut BytesMut) {
    let mut value = BytesMut::new();
    value.put_u16(u16::from(afi));
    value.put_u8(u8::from(Safi::Flowspec));
    for w in withdraws {
        w.nlri_emit(&mut value);
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

/// Serialize an `MpUnreachAttr::Labelv4(withdraws)` (or `Labelv4Eor`
/// when `withdraws` is empty) as a complete `MP_UNREACH_NLRI` path
/// attribute. The label is carried on the wire (RFC 3107) but ignored
/// for identity; `Labelv4Nlri::nlri_emit` writes whatever label the
/// withdraw entry holds.
///
/// Wire format (RFC 4760 §4): AFI=1, SAFI=4, then the NLRI list (empty
/// for end-of-RIB).
fn labelv4_unreach_attr_emit(withdraws: &[Labelv4Nlri], buf: &mut BytesMut) {
    let mut value = BytesMut::new();
    value.put_u16(u16::from(Afi::Ip));
    value.put_u8(u8::from(Safi::MplsLabel));
    for nlri in withdraws {
        nlri.nlri_emit(&mut value);
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

/// Serialize an `MpUnreachAttr::Labelv6(withdraws)` (or `Labelv6Eor`
/// when empty) as a complete `MP_UNREACH_NLRI` path attribute, AFI=2,
/// SAFI=4.
fn labelv6_unreach_attr_emit(withdraws: &[Labelv6Nlri], buf: &mut BytesMut) {
    let mut value = BytesMut::new();
    value.put_u16(u16::from(Afi::Ip6));
    value.put_u8(u8::from(Safi::MplsLabel));
    for nlri in withdraws {
        nlri.nlri_emit(&mut value);
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

/// Serialize an `MpUnreachAttr::SrPolicy { afi, withdraws }` (empty
/// `withdraws` encodes an end-of-RIB marker) as a complete
/// `MP_UNREACH_NLRI` path attribute.
///
/// Wire format (RFC 4760 §4 + RFC 9830 §2.1):
/// ```text
///   AFI  (2 octets) = 1 (IPv4 endpoint) or 2 (IPv6 endpoint)
///   SAFI (1 octet)  = 73 (SR Policy)
///   Withdrawn Routes (zero or more SrPolicyNlri encodings)
/// ```
fn srpolicy_unreach_attr_emit(afi: Afi, withdraws: &[SrPolicyNlri], buf: &mut BytesMut) {
    let mut value = BytesMut::new();
    value.put_u16(u16::from(afi));
    value.put_u8(u8::from(Safi::SrTePolicy));
    for r in withdraws {
        r.nlri_emit(&mut value, false);
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

/// Serialize an `MpUnreachAttr::LinkState { withdraws }` (empty `withdraws`
/// encodes an end-of-RIB marker) as a complete `MP_UNREACH_NLRI` path
/// attribute: AFI 16388, SAFI 71, then the Link-State NLRI list (RFC 9552).
fn linkstate_unreach_attr_emit(withdraws: &[BgpLsNlri], buf: &mut BytesMut) {
    let mut value = BytesMut::new();
    value.put_u16(u16::from(Afi::LinkState));
    value.put_u8(u8::from(Safi::LinkState));
    for w in withdraws {
        crate::bgpls_nlri_emit(&mut value, w);
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
                parse_nlri_block(input, |i| Vpnv4Nlri::parse_nlri(i, add_path))?;
            let mp_nlri = MpUnreachAttr::Vpnv4(withdrawal);
            return Ok((input, mp_nlri));
        }
        if header.afi == Afi::Ip6 && header.safi == Safi::MplsVpn {
            if input.is_empty() {
                let mp_nlri = MpUnreachAttr::Vpnv6Eor;
                return Ok((input, mp_nlri));
            }
            let (input, withdrawal) =
                parse_nlri_block(input, |i| Vpnv6Nlri::parse_nlri(i, add_path))?;
            let mp_nlri = MpUnreachAttr::Vpnv6(withdrawal);
            return Ok((input, mp_nlri));
        }
        if header.afi == Afi::Ip && header.safi == Safi::Unicast {
            // RFC 4724 §2 makes the bare empty UPDATE the IPv4-unicast
            // end-of-RIB, so an empty MP_UNREACH(1/1) is unusual — but
            // some stacks send it, and every other family here treats an
            // empty withdraw list as EoR. Mirror that rather than
            // failing the parse (a parse error here resets the session).
            if input.is_empty() {
                return Ok((input, MpUnreachAttr::Ipv4Eor));
            }
            let (input, withdrawal) =
                parse_nlri_block(input, |i| Ipv4Nlri::parse_nlri(i, add_path))?;
            return Ok((input, MpUnreachAttr::Ipv4Nlri(withdrawal)));
        }
        if header.afi == Afi::Ip6 && header.safi == Safi::Unicast {
            if input.is_empty() {
                let mp_nlri = MpUnreachAttr::Ipv6Eor;
                return Ok((input, mp_nlri));
            }
            let (input, withdrawal) =
                parse_nlri_block(input, |i| Ipv6Nlri::parse_nlri(i, add_path))?;
            let mp_nlri = MpUnreachAttr::Ipv6Nlri(withdrawal);
            return Ok((input, mp_nlri));
        }
        if header.afi == Afi::Ip && header.safi == Safi::MplsLabel {
            if input.is_empty() {
                return Ok((input, MpUnreachAttr::Labelv4Eor));
            }
            let (input, withdrawal) =
                parse_nlri_block(input, |i| Labelv4Nlri::parse_nlri(i, add_path))?;
            return Ok((input, MpUnreachAttr::Labelv4(withdrawal)));
        }
        if header.afi == Afi::Ip6 && header.safi == Safi::MplsLabel {
            if input.is_empty() {
                return Ok((input, MpUnreachAttr::Labelv6Eor));
            }
            let (input, withdrawal) =
                parse_nlri_block(input, |i| Labelv6Nlri::parse_nlri(i, add_path))?;
            return Ok((input, MpUnreachAttr::Labelv6(withdrawal)));
        }
        if header.afi == Afi::L2vpn && header.safi == Safi::Evpn {
            if input.is_empty() {
                let mp_nlri = MpUnreachAttr::EvpnEor;
                return Ok((input, mp_nlri));
            }
            let (input, evpns) = parse_nlri_block(input, |i| EvpnRoute::parse_nlri(i, add_path))?;
            let mp_nlri = MpUnreachAttr::Evpn(evpns);
            return Ok((input, mp_nlri));
        }
        if (header.afi == Afi::Ip || header.afi == Afi::Ip6) && header.safi == Safi::Mup {
            if input.is_empty() {
                return Ok((
                    input,
                    MpUnreachAttr::Mup {
                        afi: header.afi,
                        withdraws: vec![],
                    },
                ));
            }
            let (input, withdraws) =
                parse_nlri_block(input, |i| MupRoute::parse(i, add_path, header.afi))?;
            return Ok((
                input,
                MpUnreachAttr::Mup {
                    afi: header.afi,
                    withdraws,
                },
            ));
        }
        if header.afi == Afi::Ip && header.safi == Safi::Rtc {
            if input.is_empty() {
                let mp_nlri = MpUnreachAttr::Rtcv4Eor;
                return Ok((input, mp_nlri));
            }
            let (input, rtcv4) = parse_nlri_block(input, |i| Rtcv4::parse_nlri(i, add_path))?;
            let mp_nlri = MpUnreachAttr::Rtcv4(rtcv4);
            return Ok((input, mp_nlri));
        }
        if (header.afi == Afi::Ip || header.afi == Afi::Ip6) && header.safi == Safi::Flowspec {
            if input.is_empty() {
                return Ok((
                    input,
                    MpUnreachAttr::Flowspec {
                        afi: header.afi,
                        withdraws: vec![],
                    },
                ));
            }
            let (input, withdraws) =
                parse_nlri_block(input, |i| FlowspecNlri::parse(i, add_path, header.afi))?;
            return Ok((
                input,
                MpUnreachAttr::Flowspec {
                    afi: header.afi,
                    withdraws,
                },
            ));
        }
        if header.afi == Afi::Ip6 && header.safi == Safi::Rtc {
            if input.is_empty() {
                let mp_nlri = MpUnreachAttr::Rtcv6Eor;
                return Ok((input, mp_nlri));
            }
            let (input, rtcv6) = parse_nlri_block(input, |i| Rtcv6::parse_nlri(i, add_path))?;
            let mp_nlri = MpUnreachAttr::Rtcv6(rtcv6);
            return Ok((input, mp_nlri));
        }
        if (header.afi == Afi::Ip || header.afi == Afi::Ip6) && header.safi == Safi::SrTePolicy {
            if input.is_empty() {
                return Ok((
                    input,
                    MpUnreachAttr::SrPolicy {
                        afi: header.afi,
                        withdraws: vec![],
                    },
                ));
            }
            let (input, withdraws) =
                parse_nlri_block(input, |i| SrPolicyNlri::parse(i, add_path, header.afi))?;
            return Ok((
                input,
                MpUnreachAttr::SrPolicy {
                    afi: header.afi,
                    withdraws,
                },
            ));
        }
        if header.afi == Afi::LinkState && header.safi == Safi::LinkState {
            if input.is_empty() {
                return Ok((input, MpUnreachAttr::LinkState { withdraws: vec![] }));
            }
            let (input, withdraws) = parse_nlri_block(input, |i| BgpLsNlri::parse(i, add_path))?;
            return Ok((input, MpUnreachAttr::LinkState { withdraws }));
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
            Ipv4Nlri(ipv4_nlris) => {
                for ipv4 in ipv4_nlris.iter() {
                    writeln!(f, " {}:{}", ipv4.id, ipv4.prefix)?;
                }
                Ok(())
            }
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
            Vpnv6(vpnv6_nlris) => {
                for vpnv6 in vpnv6_nlris.iter() {
                    writeln!(f, " {}:{}:{}", vpnv6.nlri.id, vpnv6.rd, vpnv6.nlri.prefix)?;
                }
                Ok(())
            }
            Vpnv6Eor => {
                writeln!(f, " EoR: {}/{}", Afi::Ip6, Safi::MplsVpn)
            }
            Evpn(evpn_routes) => {
                for evpn in evpn_routes.iter() {
                    match evpn {
                        EvpnRoute::EthernetAd(v) => {
                            writeln!(f, " [{}] ethernet-ad tag:{}", v.rd, v.ether_tag)?;
                        }
                        EvpnRoute::EthernetSeg(v) => {
                            writeln!(f, " [{}] ethernet-segment orig:{}", v.rd, v.orig)?;
                        }
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
                        EvpnRoute::Prefix(v) => {
                            writeln!(f, " [{}]{}", v.rd, v.prefix)?;
                        }
                        EvpnRoute::Smet(v) => {
                            let src = v.src.map_or_else(|| "*".to_string(), |s| s.to_string());
                            writeln!(f, " [{}] SMET ({},{})", v.rd, src, v.grp)?;
                        }
                        EvpnRoute::IgmpJoinSync(v) => {
                            let src = v.src.map_or_else(|| "*".to_string(), |s| s.to_string());
                            writeln!(f, " [{}] igmp-join-sync ({},{})", v.rd, src, v.grp)?;
                        }
                        EvpnRoute::IgmpLeaveSync(v) => {
                            let src = v.src.map_or_else(|| "*".to_string(), |s| s.to_string());
                            writeln!(f, " [{}] igmp-leave-sync ({},{})", v.rd, src, v.grp)?;
                        }
                        EvpnRoute::PerRegionImet(v) => {
                            writeln!(f, " [{}] per-region-imet:{}", v.rd, v.ether_tag)?;
                        }
                        EvpnRoute::SPmsi(v) => {
                            writeln!(f, " [{}] s-pmsi:{}", v.rd, v.originator)?;
                        }
                        EvpnRoute::LeafAd(v) => {
                            writeln!(f, " leaf-ad:{}", v.originator)?;
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
            Rtcv6(rtcv6s) => {
                for rtcv6 in rtcv6s {
                    writeln!(f, " ASN:{} {}", rtcv6.asn, rtcv6.rt)?;
                }
                Ok(())
            }
            Rtcv6Eor => {
                writeln!(f, " EoR: {}/{}", Afi::Ip6, Safi::Rtc)
            }
            Mup { afi, withdraws } => {
                if withdraws.is_empty() {
                    return writeln!(f, " EoR: {}/{}", afi, Safi::Mup);
                }
                for r in withdraws {
                    writeln!(
                        f,
                        " {afi}/MUP rt={:?} arch={:?}",
                        r.route_type(),
                        r.architecture()
                    )?;
                }
                Ok(())
            }
            Flowspec { afi, withdraws } => {
                if withdraws.is_empty() {
                    return writeln!(f, " EoR: {}/{}", afi, Safi::Flowspec);
                }
                for w in withdraws {
                    writeln!(f, " {afi}/flowspec {w}")?;
                }
                Ok(())
            }
            Labelv4(nlris) => {
                for nlri in nlris.iter() {
                    writeln!(f, " {nlri}")?;
                }
                Ok(())
            }
            Labelv4Eor => {
                writeln!(f, " EoR: {}/{}", Afi::Ip, Safi::MplsLabel)
            }
            Labelv6(nlris) => {
                for nlri in nlris.iter() {
                    writeln!(f, " {nlri}")?;
                }
                Ok(())
            }
            Labelv6Eor => {
                writeln!(f, " EoR: {}/{}", Afi::Ip6, Safi::MplsLabel)
            }
            SrPolicy { afi, withdraws } => {
                if withdraws.is_empty() {
                    return writeln!(f, " EoR: {}/{}", afi, Safi::SrTePolicy);
                }
                for r in withdraws {
                    writeln!(
                        f,
                        " {afi}/SR-Policy color={} endpoint={} disc={}",
                        r.color, r.endpoint, r.distinguisher,
                    )?;
                }
                Ok(())
            }
            LinkState { withdraws } => {
                if withdraws.is_empty() {
                    return writeln!(f, " EoR: {}/{}", Afi::LinkState, Safi::LinkState);
                }
                for nlri in withdraws {
                    writeln!(
                        f,
                        " LS type={} proto={:?}",
                        nlri.nlri_type(),
                        nlri.protocol_id()
                    )?;
                }
                Ok(())
            }
        }
    }
}

impl fmt::Debug for MpUnreachAttr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MupArchitectureType, RouteDistinguisher};
    use std::str::FromStr;

    /// Minimal ISD body: 8 zero RD bytes + plen=0 (default route).
    fn min_isd_body() -> Vec<u8> {
        let mut v = vec![0u8; 8];
        v.push(0);
        v
    }

    /// Minimal T2ST body for the IPv4 outer AFI (its only caller): RD(8),
    /// ep_len=32, endpoint(4) (no TEID bits). The endpoint length covers
    /// the full-width address per draft-ietf-bess-mup-safi §3.2.2.
    fn min_t2st_body() -> Vec<u8> {
        let mut v = vec![0u8; 8];
        v.push(32); // endpoint_len = IPv4 address width
        v.extend_from_slice(&[0; 4]); // endpoint
        v
    }

    /// MUP MP_UNREACH inner value: AFI + SAFI + withdraws.
    fn build(afi: u16, withdraws: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&afi.to_be_bytes());
        v.push(u8::from(Safi::Mup));
        v.extend_from_slice(withdraws);
        v
    }

    fn mup_nlri(route_type: u16, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.push(0x01);
        v.extend_from_slice(&route_type.to_be_bytes());
        v.push(payload.len() as u8);
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn mup_ipv4_unreach_round_trips() {
        let mut nlri = mup_nlri(1, &min_isd_body());
        nlri.extend_from_slice(&mup_nlri(4, &min_t2st_body()));
        let value = build(1, &nlri);
        let (_rest, mp) = MpUnreachAttr::parse_nlri_opt(&value, None).expect("must parse");
        match mp {
            MpUnreachAttr::Mup { afi, withdraws } => {
                assert_eq!(afi, Afi::Ip);
                assert_eq!(withdraws.len(), 2);
                assert!(matches!(withdraws[0], MupRoute::Isd { .. }));
                assert!(matches!(withdraws[1], MupRoute::T2st { .. }));
            }
            other => panic!("expected Mup, got {other:?}"),
        }
    }

    #[test]
    fn mup_ipv6_unreach_round_trips() {
        // Minimal DSD body for IPv6 outer AFI: 8 RD + 16 zero address bytes.
        let dsd_body = vec![0u8; 8 + 16];
        let nlri = mup_nlri(2, &dsd_body);
        let value = build(2, &nlri);
        let (_rest, mp) = MpUnreachAttr::parse_nlri_opt(&value, None).expect("must parse");
        match mp {
            MpUnreachAttr::Mup { afi, withdraws } => {
                assert_eq!(afi, Afi::Ip6);
                assert_eq!(withdraws.len(), 1);
                assert!(matches!(withdraws[0], MupRoute::Dsd { .. }));
            }
            other => panic!("expected Mup, got {other:?}"),
        }
    }

    #[test]
    fn mup_unreach_empty_is_eor() {
        // Header-only, no NLRI bytes.
        let value = build(1, &[]);
        let (_rest, mp) = MpUnreachAttr::parse_nlri_opt(&value, None).expect("must parse");
        match mp {
            MpUnreachAttr::Mup { afi, withdraws } => {
                assert_eq!(afi, Afi::Ip);
                assert!(withdraws.is_empty());
            }
            other => panic!("expected Mup, got {other:?}"),
        }
    }

    #[test]
    fn mup_unreach_emit_round_trips_through_parser() {
        let withdraws = vec![
            MupRoute::Isd {
                id: 0,
                arch: MupArchitectureType::Gpp5g,
                rd: RouteDistinguisher::from_str("65000:7").unwrap(),
                prefix: "2001:db8::/64".parse().unwrap(),
            },
            MupRoute::T1st {
                id: 0,
                arch: MupArchitectureType::Gpp5g,
                rd: RouteDistinguisher::from_str("65000:8").unwrap(),
                prefix: "2001:db8:1::/48".parse().unwrap(),
                teid: 7,
                qfi: 4,
                endpoint: "2001:db8::5".parse().unwrap(),
                source: None,
            },
        ];
        let mut buf = BytesMut::new();
        mup_unreach_attr_emit(Afi::Ip6, &withdraws, &mut buf);
        // Strip header: flags(1) + type(1) + length(1).
        let value = &buf[3..];
        let (_rest, mp) =
            MpUnreachAttr::parse_nlri_opt(value, None).expect("emitter must round-trip");
        match mp {
            MpUnreachAttr::Mup {
                afi,
                withdraws: parsed,
            } => {
                assert_eq!(afi, Afi::Ip6);
                assert_eq!(parsed, withdraws);
            }
            other => panic!("expected Mup, got {other:?}"),
        }
    }

    #[test]
    fn flowspec_unreach_emit_round_trips_through_parser() {
        use crate::{FlowspecComponent, FlowspecNlri, FlowspecOp, FlowspecPrefix};
        let withdraws = vec![FlowspecNlri::new(
            Afi::Ip,
            vec![
                FlowspecComponent::DestinationPrefix(FlowspecPrefix::V4(
                    "192.0.2.0/24".parse().unwrap(),
                )),
                FlowspecComponent::IpProtocol(vec![FlowspecOp::numeric(
                    false, false, false, true, 6,
                )]),
            ],
        )];
        let mut buf = BytesMut::new();
        flowspec_unreach_attr_emit(Afi::Ip, &withdraws, &mut buf);
        let value = &buf[3..];
        let (_rest, mp) =
            MpUnreachAttr::parse_nlri_opt(value, None).expect("emitter must round-trip");
        match mp {
            MpUnreachAttr::Flowspec {
                afi,
                withdraws: parsed,
            } => {
                assert_eq!(afi, Afi::Ip);
                assert_eq!(parsed, withdraws);
            }
            other => panic!("expected Flowspec, got {other:?}"),
        }
    }

    #[test]
    fn flowspec_unreach_emit_eor_round_trips() {
        let mut buf = BytesMut::new();
        flowspec_unreach_attr_emit(Afi::Ip6, &[], &mut buf);
        let value = &buf[3..];
        let (_rest, mp) = MpUnreachAttr::parse_nlri_opt(value, None).expect("EoR must round-trip");
        match mp {
            MpUnreachAttr::Flowspec { afi, withdraws } => {
                assert_eq!(afi, Afi::Ip6);
                assert!(withdraws.is_empty());
            }
            other => panic!("expected Flowspec, got {other:?}"),
        }
    }

    #[test]
    fn mup_unreach_emit_eor_round_trips() {
        let mut buf = BytesMut::new();
        mup_unreach_attr_emit(Afi::Ip, &[], &mut buf);
        let value = &buf[3..];
        let (_rest, mp) = MpUnreachAttr::parse_nlri_opt(value, None).expect("EoR must round-trip");
        match mp {
            MpUnreachAttr::Mup { afi, withdraws } => {
                assert_eq!(afi, Afi::Ip);
                assert!(withdraws.is_empty());
            }
            other => panic!("expected Mup, got {other:?}"),
        }
    }

    #[test]
    fn linkstate_unreach_emit_round_trips_through_parser() {
        use crate::{LsNodeDescSub, LsNodeDescriptor, LsNodeNlri, LsProtocolId};
        let withdraws = vec![BgpLsNlri::Node(LsNodeNlri {
            protocol_id: LsProtocolId::IsisL2,
            identifier: 0,
            local_node: LsNodeDescriptor {
                subs: vec![LsNodeDescSub::IgpRouterId(vec![0, 0, 0, 0, 0, 1])],
            },
        })];
        let mut buf = BytesMut::new();
        linkstate_unreach_attr_emit(&withdraws, &mut buf);
        // Strip the attr header: flags(1) + type(1) + length(1).
        let value = &buf[3..];
        let (_rest, mp) =
            MpUnreachAttr::parse_nlri_opt(value, None).expect("emitter must round-trip");
        match mp {
            MpUnreachAttr::LinkState { withdraws: parsed } => {
                assert_eq!(parsed, withdraws);
            }
            other => panic!("expected LinkState, got {other:?}"),
        }
    }

    #[test]
    fn linkstate_unreach_emit_eor_round_trips() {
        // Empty withdraws encodes an end-of-RIB marker (header only).
        let mut buf = BytesMut::new();
        linkstate_unreach_attr_emit(&[], &mut buf);
        let value = &buf[3..];
        let (_rest, mp) = MpUnreachAttr::parse_nlri_opt(value, None).expect("EoR must round-trip");
        match mp {
            MpUnreachAttr::LinkState { withdraws } => assert!(withdraws.is_empty()),
            other => panic!("expected LinkState, got {other:?}"),
        }
    }

    #[test]
    fn srpolicy_unreach_emit_round_trips_through_parser() {
        use std::net::IpAddr;
        let withdraws = vec![
            SrPolicyNlri {
                id: 0,
                distinguisher: 1,
                color: 100,
                endpoint: IpAddr::V4("10.0.0.9".parse().unwrap()),
            },
            SrPolicyNlri {
                id: 0,
                distinguisher: 2,
                color: 100,
                endpoint: IpAddr::V4("10.0.0.10".parse().unwrap()),
            },
        ];
        let mut buf = BytesMut::new();
        srpolicy_unreach_attr_emit(Afi::Ip, &withdraws, &mut buf);
        // Strip header: flags(1) + type(1) + length(1).
        let value = &buf[3..];
        let (_rest, mp) =
            MpUnreachAttr::parse_nlri_opt(value, None).expect("emitter must round-trip");
        match mp {
            MpUnreachAttr::SrPolicy {
                afi,
                withdraws: parsed,
            } => {
                assert_eq!(afi, Afi::Ip);
                assert_eq!(parsed, withdraws);
            }
            other => panic!("expected SrPolicy, got {other:?}"),
        }
    }

    #[test]
    fn srpolicy_unreach_emit_eor_round_trips() {
        let mut buf = BytesMut::new();
        srpolicy_unreach_attr_emit(Afi::Ip6, &[], &mut buf);
        let value = &buf[3..];
        let (_rest, mp) = MpUnreachAttr::parse_nlri_opt(value, None).expect("EoR must round-trip");
        match mp {
            MpUnreachAttr::SrPolicy { afi, withdraws } => {
                assert_eq!(afi, Afi::Ip6);
                assert!(withdraws.is_empty());
            }
            other => panic!("expected SrPolicy, got {other:?}"),
        }
    }

    /// Regression: AFI=1/SAFI=1 had no arm here at all, so an IPv4-unicast
    /// MP_UNREACH fell through to the trailing `Err`. That error is not on
    /// the RFC 7606 treat-as-withdraw or attribute-discard lists, so the
    /// whole UPDATE failed to parse and the session was reset — the
    /// withdraw-side counterpart of the MP_REACH gap fixed in #2045.
    #[test]
    fn ipv4_unicast_unreach_parses_instead_of_erroring() {
        // AFI=1, SAFI=1, then 10.0.0.0/24 (3 prefix octets) and
        // 192.0.2.0/25 (4 — a /25 still spans the fourth octet).
        let value = [0x00u8, 0x01, 0x01, 24, 10, 0, 0, 25, 192, 0, 2, 0];
        let (rest, mp) = MpUnreachAttr::parse_nlri_opt(&value, None)
            .expect("IPv4-unicast MP_UNREACH must parse");
        assert!(rest.is_empty());
        match mp {
            MpUnreachAttr::Ipv4Nlri(withdraws) => {
                assert_eq!(withdraws.len(), 2);
                assert_eq!(withdraws[0].prefix.to_string(), "10.0.0.0/24");
                assert_eq!(withdraws[1].prefix.to_string(), "192.0.2.0/25");
            }
            other => panic!("expected Ipv4Nlri, got {other:?}"),
        }
    }

    /// An empty IPv4-unicast MP_UNREACH is end-of-RIB. RFC 4724 §2 makes
    /// the bare empty UPDATE the canonical v4 EoR, but some stacks send
    /// this form and every other family here treats an empty withdraw
    /// list the same way.
    #[test]
    fn ipv4_unicast_unreach_empty_is_eor() {
        let value = [0x00u8, 0x01, 0x01];
        let (_rest, mp) = MpUnreachAttr::parse_nlri_opt(&value, None).expect("EoR must parse");
        assert!(matches!(mp, MpUnreachAttr::Ipv4Eor));
    }

    #[test]
    fn ipv4_unreach_emit_round_trips() {
        let withdraws = vec![
            Ipv4Nlri {
                id: 0,
                prefix: "10.0.0.0/24".parse().unwrap(),
            },
            Ipv4Nlri {
                id: 0,
                prefix: "0.0.0.0/0".parse().unwrap(),
            },
        ];
        let mut buf = BytesMut::new();
        ipv4_unreach_attr_emit(&withdraws, &mut buf);
        // Skip the attribute header (flags, type, 1-octet length).
        let (_rest, mp) =
            MpUnreachAttr::parse_nlri_opt(&buf[3..], None).expect("emitter must round-trip");
        match mp {
            MpUnreachAttr::Ipv4Nlri(parsed) => assert_eq!(parsed, withdraws),
            other => panic!("expected Ipv4Nlri, got {other:?}"),
        }
    }

    #[test]
    fn ipv4_unreach_emit_eor_round_trips() {
        let mut buf = BytesMut::new();
        ipv4_unreach_attr_emit(&[], &mut buf);
        let (_rest, mp) =
            MpUnreachAttr::parse_nlri_opt(&buf[3..], None).expect("EoR must round-trip");
        assert!(matches!(mp, MpUnreachAttr::Ipv4Eor));
    }

    /// A malformed NLRI must fail the whole block rather than silently
    /// truncating it, matching every other family (`parse_nlri_block`).
    #[test]
    fn ipv4_unicast_unreach_rejects_malformed_nlri() {
        // 10.0.0.0/24 followed by prefix length 33, which exceeds 32.
        let value = [0x00u8, 0x01, 0x01, 24, 10, 0, 0, 33, 1, 2, 3, 4, 5];
        assert!(MpUnreachAttr::parse_nlri_opt(&value, None).is_err());
    }
}
