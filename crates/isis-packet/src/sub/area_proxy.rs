use bitfield_struct::bitfield;
use bytes::{BufMut, BytesMut};
use ipnet::{Ipv4Net, Ipv6Net};
use nom::IResult;
use nom::number::complete::be_u8;
use nom_derive::*;
use serde::{Deserialize, Serialize};

use crate::util::{ParseBe, TlvEmitter};
use crate::{IsisSysId, IsisTlv, IsisTlvType, SidLabelValue, many0_complete};

use super::prefix::{psize, ptake, ptakev6};
use super::{IsisAreaProxyCode, IsisSubTlvUnknown};

impl_parse_subs!(IsisAreaProxySub);

// ─────────────────────────────────────────────────────────────────────
// RFC 9666 — Area Proxy TLV (type 20) and its sub-TLVs. The TLV is a
// bare sub-TLV container carried in fragment 0 of an L2 LSP: every
// Inside Router (pseudonodes included) advertises an empty one to
// signal Area Proxy readiness, and the elected Area Leader adds the
// Proxy System Identifier sub-TLV (and optionally an Area SID) once
// the whole area is ready. It MUST NOT appear in L1 LSPs, IIHs, or
// SNPs (IANA: IIH:n, LSP:y, SNP:n).
// ─────────────────────────────────────────────────────────────────────

/// One sub-TLV of the Area Proxy TLV, dispatched by `IsisAreaProxyCode`
/// (RFC 9666 §4.3).
#[derive(Debug, NomBE, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[nom(Selector = "IsisAreaProxyCode")]
pub enum IsisAreaProxySub {
    #[nom(Selector = "IsisAreaProxyCode::ProxySystemId")]
    ProxySystemId(IsisSubProxySystemId),
    #[nom(Selector = "IsisAreaProxyCode::AreaSid")]
    AreaSid(IsisSubAreaSid),
    #[nom(Selector = "_")]
    Unknown(IsisSubTlvUnknown),
}

impl IsisAreaProxySub {
    pub fn len(&self) -> u8 {
        use IsisAreaProxySub::*;
        match self {
            ProxySystemId(v) => v.len(),
            AreaSid(v) => v.len(),
            Unknown(v) => v.len,
        }
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        use IsisAreaProxySub::*;
        match self {
            ProxySystemId(v) => v.tlv_emit(buf),
            AreaSid(v) => v.tlv_emit(buf),
            Unknown(v) => v.tlv_emit(buf),
        }
    }
}

/// Area Proxy System Identifier sub-TLV (RFC 9666 §4.3.1, type 1).
/// Advertised by the Area Leader to distribute the Proxy System ID —
/// the system ID under which the Proxy LSP is originated and which
/// Inside Edge Routers use as the source of IIHs and SNPs on Outside
/// Circuits.
#[derive(Debug, Default, NomBE, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisSubProxySystemId {
    pub sys_id: IsisSysId,
}

impl TlvEmitter for IsisSubProxySystemId {
    fn typ(&self) -> u8 {
        IsisAreaProxyCode::ProxySystemId.into()
    }

    fn len(&self) -> u8 {
        6
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put(&self.sys_id.id[..]);
    }
}

impl From<IsisSubProxySystemId> for IsisAreaProxySub {
    fn from(sub: IsisSubProxySystemId) -> Self {
        IsisAreaProxySub::ProxySystemId(sub)
    }
}

// RFC 9666 §4.3.2 flags octet (IETF bit 0 is the MSB):
//   0 1 2 3 4 5 6 7
//  +-+-+-+-+-+-+-+-+
//  |F|V|L|         |
//  +-+-+-+-+-+-+-+-+
// F = 0x80 (address family: 0 IPv4, 1 IPv6), V = 0x40, L = 0x20 per
// RFC 8667 §2.1.1.1. `bitfield(u8)` is LSB-first — declare the five
// reserved bits first so L, V, F land at 0x20/0x40/0x80.
#[bitfield(u8, debug = true)]
#[derive(PartialEq)]
pub struct AreaSidFlags {
    #[bits(5)]
    pub resvd: u8,
    pub l_flag: bool,
    pub v_flag: bool,
    pub f_flag: bool,
}

impl ParseBe<AreaSidFlags> for AreaSidFlags {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, flags) = be_u8(input)?;
        Ok((input, flags.into()))
    }
}

/// Prefix carried by the Area SID sub-TLV; family is selected by the
/// F-flag (kept as a typed enum so consumers don't re-derive it).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AreaSidPrefix {
    V4(Ipv4Net),
    V6(Ipv6Net),
}

impl AreaSidPrefix {
    pub fn prefix_len(&self) -> u8 {
        match self {
            AreaSidPrefix::V4(p) => p.prefix_len(),
            AreaSidPrefix::V6(p) => p.prefix_len(),
        }
    }

    fn emit(&self, buf: &mut BytesMut) {
        let plen = psize(self.prefix_len());
        buf.put_u8(self.prefix_len());
        match self {
            AreaSidPrefix::V4(p) => buf.put(&p.addr().octets()[..plen]),
            AreaSidPrefix::V6(p) => buf.put(&p.addr().octets()[..plen]),
        }
    }
}

/// Area SID sub-TLV (RFC 9666 §4.3.2, type 2). Advertised by the Area
/// Leader: an anycast prefix + SID representing the entire Inside Area,
/// installed by every Inside Edge Router and re-advertised as a Node
/// SID in the Proxy LSP.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisSubAreaSid {
    pub flags: AreaSidFlags,
    pub sid: SidLabelValue,
    pub prefix: AreaSidPrefix,
}

impl ParseBe<IsisSubAreaSid> for IsisSubAreaSid {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, flags) = AreaSidFlags::parse_be(input)?;
        // RFC 9666 defers to RFC 8667 §2.1.1.1: the V/L flags decide
        // the SID form — V=L=1 a 3-octet label, V=L=0 a 4-octet index,
        // anything else invalid (the registry walk degrades the
        // sub-TLV to Unknown). `SidLabelValue::parse_be_flags` can't
        // be used here: it requires the SID to be the sub-TLV's final
        // field, but the prefix follows it — so slice the width by
        // flags and let the length-keyed parser handle the value.
        let width = match (flags.v_flag(), flags.l_flag()) {
            (true, true) => 3,
            (false, false) => 4,
            _ => {
                return Err(nom::Err::Error(nom::error::make_error(
                    input,
                    nom::error::ErrorKind::Verify,
                )));
            }
        };
        let (input, sid_bytes) = packet_utils::safe_split_at(input, width)?;
        let (_, sid) = SidLabelValue::parse_be(sid_bytes)?;
        let (input, plen) = be_u8(input)?;
        let (input, prefix) = if flags.f_flag() {
            let (input, p) = ptakev6(input, plen)?;
            (input, AreaSidPrefix::V6(p))
        } else {
            let (input, p) = ptake(input, plen)?;
            (input, AreaSidPrefix::V4(p))
        };
        Ok((input, Self { flags, sid, prefix }))
    }
}

impl TlvEmitter for IsisSubAreaSid {
    fn typ(&self) -> u8 {
        IsisAreaProxyCode::AreaSid.into()
    }

    fn len(&self) -> u8 {
        // Flags: 1 + SID + Prefix Length: 1 + packed prefix.
        1 + self.sid.len() + 1 + psize(self.prefix.prefix_len()) as u8
    }

    fn emit(&self, buf: &mut BytesMut) {
        // Derive V/L from the SID form and F from the prefix family so
        // the emitted flags can never disagree with the bytes that
        // follow.
        let flags = match self.sid {
            SidLabelValue::Label(_) => self.flags.with_v_flag(true).with_l_flag(true),
            SidLabelValue::Index(_) => self.flags.with_v_flag(false).with_l_flag(false),
        };
        let flags = flags.with_f_flag(matches!(self.prefix, AreaSidPrefix::V6(_)));
        buf.put_u8(flags.into());
        self.sid.emit(buf);
        self.prefix.emit(buf);
    }
}

impl From<IsisSubAreaSid> for IsisAreaProxySub {
    fn from(sub: IsisSubAreaSid) -> Self {
        IsisAreaProxySub::AreaSid(sub)
    }
}

/// Area Proxy TLV (RFC 9666 §4.3, type 20). A bare sub-TLV container;
/// an empty one is the readiness signal every Inside Router advertises
/// in fragment 0 of its L2 LSP.
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisTlvAreaProxy {
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub subs: Vec<IsisAreaProxySub>,
}

impl ParseBe<IsisTlvAreaProxy> for IsisTlvAreaProxy {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, subs) = many0_complete(IsisAreaProxySub::parse_subs).parse(input)?;
        Ok((input, Self { subs }))
    }
}

impl IsisTlvAreaProxy {
    fn sub_len(&self) -> usize {
        // 2 bytes (type + length) per sub-TLV header.
        self.subs.iter().map(|sub| sub.len() as usize + 2).sum()
    }

    /// True value length in bytes, unsaturated (the u8 `len()`
    /// saturates at 255) — used by `IsisTlv::wire_len`.
    pub fn value_wire_len(&self) -> usize {
        self.sub_len()
    }
}

impl TlvEmitter for IsisTlvAreaProxy {
    fn typ(&self) -> u8 {
        IsisTlvType::AreaProxy.into()
    }

    fn len(&self) -> u8 {
        self.sub_len().min(255) as u8
    }

    fn emit(&self, buf: &mut BytesMut) {
        self.subs.iter().for_each(|sub| sub.emit(buf));
    }
}

impl From<IsisTlvAreaProxy> for IsisTlv {
    fn from(tlv: IsisTlvAreaProxy) -> Self {
        IsisTlv::AreaProxy(tlv)
    }
}
