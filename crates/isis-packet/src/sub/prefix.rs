use std::net::{Ipv4Addr, Ipv6Addr};

use bitfield_struct::bitfield;
use bytes::{BufMut, BytesMut};
use ipnet::{Ipv4Net, Ipv6Net};
use nom::bytes::complete::take;
use nom::number::complete::{be_u8, be_u16, be_u32};
use nom::{IResult, Needed};
use nom_derive::*;
use packet_utils::{Algo, safe_split_at};
use serde::{Deserialize, Serialize};

use crate::util::{ParseBe, TlvEmitter, emit_sub_tlvs};
use crate::{IsisTlv, IsisTlvType, SidLabelValue, many0_complete};

use super::{
    Behavior, IsisCodeLen, IsisPrefixCode, IsisSrv6MirrorSub2Code, IsisSrv6SidSub2Code,
    IsisSubTlvUnknown,
};

#[derive(Debug, NomBE, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[nom(Selector = "IsisPrefixCode")]
pub enum IsisSubTlv {
    #[nom(Selector = "IsisPrefixCode::PrefixSid")]
    PrefixSid(IsisSubPrefixSid),
    #[nom(Selector = "IsisPrefixCode::Srv6EndSid")]
    Srv6EndSid(IsisSubSrv6EndSid),
    #[nom(Selector = "IsisPrefixCode::Srv6MirrorSid")]
    Srv6MirrorSid(IsisSubSrv6MirrorSid),
    #[nom(Selector = "IsisPrefixCode::Ipv4SourceRouterId")]
    Ipv4SourceRouterId(IsisSubIpv4SourceRouterId),
    #[nom(Selector = "IsisPrefixCode::Ipv6SourceRouterId")]
    Ipv6SourceRouterId(IsisSubIpv6SourceRouterId),
    #[nom(Selector = "_")]
    Unknown(IsisSubTlvUnknown),
}

#[bitfield(u8, debug = true)]
#[derive(PartialEq)]
pub struct PrefixSidFlags {
    #[bits(2)]
    pub resvd: u8,
    pub l_flag: bool,
    pub v_flag: bool,
    pub e_flag: bool,
    pub p_flag: bool,
    pub n_flag: bool,
    pub r_flag: bool,
}

impl ParseBe<PrefixSidFlags> for PrefixSidFlags {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, flags) = be_u8(input)?;
        Ok((input, flags.into()))
    }
}

#[derive(Debug, NomBE, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisSubPrefixSid {
    pub flags: PrefixSidFlags,
    pub algo: Algo,
    pub sid: SidLabelValue,
}

impl TlvEmitter for IsisSubPrefixSid {
    fn typ(&self) -> u8 {
        IsisPrefixCode::PrefixSid.into()
    }

    fn len(&self) -> u8 {
        2 + self.sid.len()
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.flags.into());
        buf.put_u8(self.algo.into());
        self.sid.emit(buf);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisSubSrv6EndSid {
    pub flags: u8,
    pub behavior: Behavior,
    pub sid: Ipv6Addr,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sub2s: Vec<IsisSub2Tlv>,
}

impl ParseBe<IsisSubSrv6EndSid> for IsisSubSrv6EndSid {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, flags) = be_u8(input)?;
        let (input, behavior) = be_u16(input)?;
        let (input, sid) = Ipv6Addr::parse_be(input)?;
        let (input, sub2_len) = be_u8(input)?;
        let mut sub = Self {
            flags,
            behavior: behavior.into(),
            sid,
            sub2s: vec![],
        };
        if sub2_len == 0 {
            return Ok((input, sub));
        }
        let (input, sub2_data) = safe_split_at(input, sub2_len as usize)?;
        let (_, sub2s) = many0_complete(IsisSub2Tlv::parse_subs).parse(sub2_data)?;
        sub.sub2s = sub2s;
        Ok((input, sub))
    }
}

impl TlvEmitter for IsisSubSrv6EndSid {
    fn typ(&self) -> u8 {
        IsisPrefixCode::Srv6EndSid.into()
    }

    fn len(&self) -> u8 {
        // Flags(1)+Behavior(2)+Sid(16)+Sub2Len(1)+Sub2
        let len: usize = self.sub2s.iter().map(|sub| sub.len() as usize + 2).sum();
        (1 + 2 + 16 + 1 + len).min(255) as u8
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.flags);
        buf.put_u16(self.behavior.into());
        buf.put(&self.sid.octets()[..]);
        emit_sub_tlvs(buf, |buf| {
            for sub2 in &self.sub2s {
                sub2.emit(buf);
            }
        });
    }
}

/// draft-ietf-rtgwg-srv6-egress-protection — SRv6 Mirror SID sub-TLV
/// (type 8 inside the SRv6 Locator TLV). Wire layout mirrors the SRv6
/// End SID sub-TLV (RFC 9352 §7.2): Flags(1) + SRv6 Endpoint
/// Behavior(2, = End.M / 74) + SID(16) + sub-sub-TLV-length(1) +
/// sub-sub-TLVs. The draft requires exactly one Protected Locators
/// sub-sub-TLV identifying the protected egress locator(s).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisSubSrv6MirrorSid {
    pub flags: u8,
    pub behavior: Behavior,
    pub sid: Ipv6Addr,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sub2s: Vec<IsisMirrorSub2Tlv>,
}

impl ParseBe<IsisSubSrv6MirrorSid> for IsisSubSrv6MirrorSid {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, flags) = be_u8(input)?;
        let (input, behavior) = be_u16(input)?;
        let (input, sid) = Ipv6Addr::parse_be(input)?;
        let (input, sub2_len) = be_u8(input)?;
        let mut sub = Self {
            flags,
            behavior: behavior.into(),
            sid,
            sub2s: vec![],
        };
        if sub2_len == 0 {
            return Ok((input, sub));
        }
        let (input, sub2_data) = safe_split_at(input, sub2_len as usize)?;
        let (_, sub2s) = many0_complete(IsisMirrorSub2Tlv::parse_subs).parse(sub2_data)?;
        sub.sub2s = sub2s;
        Ok((input, sub))
    }
}

impl TlvEmitter for IsisSubSrv6MirrorSid {
    fn typ(&self) -> u8 {
        IsisPrefixCode::Srv6MirrorSid.into()
    }

    fn len(&self) -> u8 {
        // Flags(1)+Behavior(2)+Sid(16)+Sub2Len(1)+Sub2
        let len: usize = self.sub2s.iter().map(|sub| sub.len() as usize + 2).sum();
        (1 + 2 + 16 + 1 + len).min(255) as u8
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.flags);
        buf.put_u16(self.behavior.into());
        buf.put(&self.sid.octets()[..]);
        emit_sub_tlvs(buf, |buf| {
            for sub2 in &self.sub2s {
                sub2.emit(buf);
            }
        });
    }
}

/// Protected Locators sub-sub-TLV (type 1) carried inside the SRv6
/// Mirror SID sub-TLV. Encodes one protected egress locator as a
/// Locator-Size (number of significant bits, 1..=128) followed by the
/// ceil(bits/8) most-significant locator octets.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisSub2ProtectedLocators {
    pub locator: Ipv6Net,
}

impl ParseBe<IsisSub2ProtectedLocators> for IsisSub2ProtectedLocators {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, locator_size) = be_u8(input)?;
        let (input, locator) = ptakev6(input, locator_size)?;
        Ok((input, Self { locator }))
    }
}

impl TlvEmitter for IsisSub2ProtectedLocators {
    fn typ(&self) -> u8 {
        IsisSrv6MirrorSub2Code::ProtectedLocators.into()
    }

    fn len(&self) -> u8 {
        1 + psize(self.locator.prefix_len()) as u8
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.locator.prefix_len());
        let plen = psize(self.locator.prefix_len());
        if plen != 0 {
            buf.put(&self.locator.addr().octets()[..plen]);
        }
    }
}

#[derive(Debug, NomBE, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[nom(Selector = "IsisSrv6MirrorSub2Code")]
pub enum IsisMirrorSub2Tlv {
    #[nom(Selector = "IsisSrv6MirrorSub2Code::ProtectedLocators")]
    ProtectedLocators(IsisSub2ProtectedLocators),
    #[nom(Selector = "_")]
    Unknown(IsisSubTlvUnknown),
}

impl IsisMirrorSub2Tlv {
    pub fn parse_subs(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, cl) = IsisCodeLen::parse_be(input)?;
        let (input, sub) = safe_split_at(input, cl.len as usize)?;
        // Malformed known sub-TLV → Unknown, so followers still parse.
        let mut val = match Self::parse_be(sub, cl.code.into()) {
            Ok((_, val)) => val,
            Err(_) => IsisMirrorSub2Tlv::Unknown(IsisSubTlvUnknown {
                code: cl.code,
                len: cl.len,
                data: sub.to_vec(),
            }),
        };
        if let IsisMirrorSub2Tlv::Unknown(ref mut v) = val {
            v.code = cl.code;
            v.len = cl.len;
        }
        Ok((input, val))
    }

    pub fn len(&self) -> u8 {
        use IsisMirrorSub2Tlv::*;
        match self {
            ProtectedLocators(v) => v.len(),
            Unknown(v) => v.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        use IsisMirrorSub2Tlv::*;
        match self {
            ProtectedLocators(v) => v.tlv_emit(buf),
            Unknown(v) => v.tlv_emit(buf),
        }
    }
}

#[derive(Debug, NomBE, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisSub2SidStructure {
    pub lb_len: u8,
    pub ln_len: u8,
    pub fun_len: u8,
    pub arg_len: u8,
}

impl TlvEmitter for IsisSub2SidStructure {
    fn typ(&self) -> u8 {
        IsisSrv6SidSub2Code::SidStructure.into()
    }

    fn len(&self) -> u8 {
        4
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.lb_len);
        buf.put_u8(self.ln_len);
        buf.put_u8(self.fun_len);
        buf.put_u8(self.arg_len);
    }
}

#[derive(Debug, NomBE, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[nom(Selector = "IsisSrv6SidSub2Code")]
pub enum IsisSub2Tlv {
    #[nom(Selector = "IsisSrv6SidSub2Code::SidStructure")]
    SidStructure(IsisSub2SidStructure),
    #[nom(Selector = "_")]
    Unknown(IsisSubTlvUnknown),
}

impl IsisSub2Tlv {
    pub fn parse_subs(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, cl) = IsisCodeLen::parse_be(input)?;
        let (input, sub) = safe_split_at(input, cl.len as usize)?;
        // Malformed known sub-TLV → Unknown, so followers still parse.
        let mut val = match Self::parse_be(sub, cl.code.into()) {
            Ok((_, val)) => val,
            Err(_) => IsisSub2Tlv::Unknown(IsisSubTlvUnknown {
                code: cl.code,
                len: cl.len,
                data: sub.to_vec(),
            }),
        };
        if let IsisSub2Tlv::Unknown(ref mut v) = val {
            v.code = cl.code;
            v.len = cl.len;
        }
        Ok((input, val))
    }

    pub fn len(&self) -> u8 {
        use IsisSub2Tlv::*;
        match self {
            SidStructure(v) => v.len(),
            Unknown(v) => v.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        use IsisSub2Tlv::*;
        match self {
            SidStructure(v) => v.tlv_emit(buf),
            Unknown(v) => v.tlv_emit(buf),
        }
    }
}

impl IsisSubTlv {
    pub fn parse_subs(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, cl) = IsisCodeLen::parse_be(input)?;
        let (input, sub) = safe_split_at(input, cl.len as usize)?;
        // A malformed *known* sub-TLV must not truncate the list —
        // degrade it to Unknown with its bytes preserved (mirroring the
        // top-level TLV loop) so the sub-TLVs after it still parse.
        let mut val = match Self::parse_be(sub, cl.code.into()) {
            Ok((_, val)) => val,
            Err(_) => IsisSubTlv::Unknown(IsisSubTlvUnknown {
                code: cl.code,
                len: cl.len,
                data: sub.to_vec(),
            }),
        };
        if let IsisSubTlv::Unknown(ref mut v) = val {
            v.code = cl.code;
            v.len = cl.len;
        }
        Ok((input, val))
    }

    pub fn len(&self) -> u8 {
        use IsisSubTlv::*;
        match self {
            PrefixSid(v) => v.len(),
            Srv6EndSid(v) => v.len(),
            Srv6MirrorSid(v) => v.len(),
            Ipv4SourceRouterId(v) => v.len(),
            Ipv6SourceRouterId(v) => v.len(),
            Unknown(v) => v.len,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        use IsisSubTlv::*;
        match self {
            PrefixSid(v) => v.tlv_emit(buf),
            Srv6EndSid(v) => v.tlv_emit(buf),
            Srv6MirrorSid(v) => v.tlv_emit(buf),
            Ipv4SourceRouterId(v) => v.tlv_emit(buf),
            Ipv6SourceRouterId(v) => v.tlv_emit(buf),
            Unknown(v) => v.tlv_emit(buf),
        }
    }
}

/// RFC 7794 §3.1 — IPv4 Source Router ID sub-TLV (type 11).
///
/// Carries the 32-bit IPv4 TE Router ID (TLV 134) of the router that
/// originally advertised the enclosing prefix. The originator MAY
/// include it on first origination; once present, an L1/L2 router
/// leaking the prefix to another level MUST carry it across unchanged
/// so downstream routers can attribute the prefix to its true origin
/// rather than to the leaker.
#[derive(Debug, NomBE, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisSubIpv4SourceRouterId {
    pub router_id: Ipv4Addr,
}

impl TlvEmitter for IsisSubIpv4SourceRouterId {
    fn typ(&self) -> u8 {
        IsisPrefixCode::Ipv4SourceRouterId.into()
    }

    fn len(&self) -> u8 {
        4
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put(&self.router_id.octets()[..]);
    }
}

impl From<IsisSubIpv4SourceRouterId> for IsisSubTlv {
    fn from(v: IsisSubIpv4SourceRouterId) -> Self {
        IsisSubTlv::Ipv4SourceRouterId(v)
    }
}

/// RFC 7794 §3.2 — IPv6 Source Router ID sub-TLV (type 12).
///
/// Carries the 128-bit IPv6 TE Router ID (TLV 140) of the prefix
/// originator. Same leaking semantics as the IPv4 variant: optional
/// at origination, mandatory to copy through on L1↔L2 leaks once
/// present.
#[derive(Debug, NomBE, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisSubIpv6SourceRouterId {
    pub router_id: Ipv6Addr,
}

impl TlvEmitter for IsisSubIpv6SourceRouterId {
    fn typ(&self) -> u8 {
        IsisPrefixCode::Ipv6SourceRouterId.into()
    }

    fn len(&self) -> u8 {
        16
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put(&self.router_id.octets()[..]);
    }
}

impl From<IsisSubIpv6SourceRouterId> for IsisSubTlv {
    fn from(v: IsisSubIpv6SourceRouterId) -> Self {
        IsisSubTlv::Ipv6SourceRouterId(v)
    }
}

#[bitfield(u8, debug = true)]
#[derive(PartialEq)]
pub struct Ipv4ControlInfo {
    #[bits(6)]
    pub prefixlen: usize,
    pub sub_tlv: bool,
    pub distribution: bool,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisTlvExtIpReach {
    pub entries: Vec<IsisTlvExtIpReachEntry>,
}

impl ParseBe<IsisTlvExtIpReach> for IsisTlvExtIpReach {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, entries) = parse_reach_entries(
            input,
            IsisTlvExtIpReachEntry::parse_be,
            ext_ip_reach_entry_span,
        )?;
        Ok((input, Self { entries }))
    }
}

impl TlvEmitter for IsisTlvExtIpReach {
    fn typ(&self) -> u8 {
        IsisTlvType::ExtIpReach.into()
    }

    fn len(&self) -> u8 {
        // See note on `IsisTlvExtIsReach::len`: saturate so the
        // packer can measure oversized instances via wire_len in
        // debug builds before sharding them.
        self.entries
            .iter()
            .map(|entry| entry.len())
            .fold(0u8, u8::saturating_add)
    }

    fn emit(&self, buf: &mut BytesMut) {
        self.entries.iter().for_each(|entry| entry.emit(buf));
    }
}

impl From<IsisTlvExtIpReach> for IsisTlv {
    fn from(tlv: IsisTlvExtIpReach) -> Self {
        IsisTlv::ExtIpReach(tlv)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisTlvMtIpReach {
    pub mt: MultiTopologyId,
    pub entries: Vec<IsisTlvExtIpReachEntry>,
}

impl ParseBe<IsisTlvMtIpReach> for IsisTlvMtIpReach {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, mt) = be_u16(input)?;
        let (input, entries) = parse_reach_entries(
            input,
            IsisTlvExtIpReachEntry::parse_be,
            ext_ip_reach_entry_span,
        )?;
        Ok((
            input,
            Self {
                mt: mt.into(),
                entries,
            },
        ))
    }
}

impl TlvEmitter for IsisTlvMtIpReach {
    fn typ(&self) -> u8 {
        IsisTlvType::MtIpReach.into()
    }

    fn len(&self) -> u8 {
        // See note on `IsisTlvExtIsReach::len`.
        let entries_len = self
            .entries
            .iter()
            .map(|entry| entry.len())
            .fold(0u8, u8::saturating_add);
        entries_len.saturating_add(2)
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u16(self.mt.into());
        self.entries.iter().for_each(|entry| entry.emit(buf));
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisTlvExtIpReachEntry {
    pub metric: u32,
    pub flags: Ipv4ControlInfo,
    pub prefix: Ipv4Net,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub subs: Vec<IsisSubTlv>,
}

impl IsisTlvExtIpReachEntry {
    fn len(&self) -> u8 {
        if self.subs.is_empty() {
            // Metric:4 + Flags:1 + Prefix.
            (4 + 1 + psize(self.prefix.prefix_len())) as u8
        } else {
            // Metric:4 + Flags:1 + Prefix + Sub TLV length + Sub TLV.
            // usize + min keeps the packer's wire_len() probe of an
            // over-full entry debug-safe (see `IsisTlvExtIsReach::len`).
            (4 + 1 + psize(self.prefix.prefix_len()) + 1 + self.sub_len()).min(255) as u8
        }
    }

    fn sub_len(&self) -> usize {
        self.subs.iter().map(|sub| sub.len() as usize + 2).sum()
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u32(self.metric);
        buf.put_u8(self.flags.into());
        let plen = psize(self.prefix.prefix_len());
        if plen != 0 {
            buf.put(&self.prefix.addr().octets()[..plen]);
        }
        if self.subs.is_empty() {
            return;
        }
        emit_sub_tlvs(buf, |buf| {
            for sub in self.subs.iter() {
                sub.emit(buf);
            }
        });
    }

    pub fn prefix_sid(&self) -> Option<IsisSubPrefixSid> {
        for sub in self.subs.iter() {
            if let IsisSubTlv::PrefixSid(prefix_sid) = sub {
                return Some(prefix_sid.clone());
            }
        }
        None
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisTlvIpv6Reach {
    pub entries: Vec<IsisTlvIpv6ReachEntry>,
}

impl ParseBe<IsisTlvIpv6Reach> for IsisTlvIpv6Reach {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, entries) = parse_reach_entries(
            input,
            IsisTlvIpv6ReachEntry::parse_be,
            ipv6_reach_entry_span,
        )?;
        Ok((input, Self { entries }))
    }
}

impl TlvEmitter for IsisTlvIpv6Reach {
    fn typ(&self) -> u8 {
        IsisTlvType::Ipv6Reach.into()
    }

    fn len(&self) -> u8 {
        // See note on `IsisTlvExtIsReach::len`.
        self.entries
            .iter()
            .map(|entry| entry.len())
            .fold(0u8, u8::saturating_add)
    }

    fn emit(&self, buf: &mut BytesMut) {
        self.entries.iter().for_each(|entry| entry.emit(buf));
    }
}

impl From<IsisTlvIpv6Reach> for IsisTlv {
    fn from(tlv: IsisTlvIpv6Reach) -> Self {
        IsisTlv::Ipv6Reach(tlv)
    }
}

// RFC 5120 §7.2 wire layout for an MT identifier:
//   bit:  0 1 2 3  4 5 6 7 8 9 10 11 12 13 14 15
//        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//        |R R R R| MT ID                  |
//        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// As a big-endian u16, the 4 reserved bits sit in the MSB and the
// 12-bit MT ID in the LSB. `bitfield(u16)` is LSB-first by default,
// so the *first* declared field lands at the lowest bit positions —
// declare `id` first to land at bits 0-11 and `resvd` second at bits
// 12-15. The previous order produced .id()=0 for an MT 2 LSP because
// MT ID was being read out of the reserved bits.
#[bitfield(u16, debug = true)]
#[derive(PartialEq)]
pub struct MultiTopologyId {
    #[bits(12)]
    pub id: u16,
    #[bits(4)]
    pub resvd: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisTlvMultiTopology {
    pub entries: Vec<MultiTopologyId>,
}

impl ParseBe<IsisTlvMultiTopology> for IsisTlvMultiTopology {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, entries) = many0_complete(|i| {
            let (i, mt) = be_u16(i)?;
            Ok((i, mt.into()))
        })
        .parse(input)?;
        Ok((input, Self { entries }))
    }
}

impl TlvEmitter for IsisTlvMultiTopology {
    fn typ(&self) -> u8 {
        IsisTlvType::MultiTopology.into()
    }

    fn len(&self) -> u8 {
        (self.entries.len() * 2) as u8
    }

    fn emit(&self, buf: &mut BytesMut) {
        for entry in &self.entries {
            buf.put_u16((*entry).into());
        }
    }
}

impl From<IsisTlvMultiTopology> for IsisTlv {
    fn from(tlv: IsisTlvMultiTopology) -> Self {
        IsisTlv::MultiTopology(tlv)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisTlvMtIpv6Reach {
    pub mt: MultiTopologyId,
    pub entries: Vec<IsisTlvIpv6ReachEntry>,
}

impl ParseBe<IsisTlvMtIpv6Reach> for IsisTlvMtIpv6Reach {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, mt) = be_u16(input)?;
        let (input, entries) = parse_reach_entries(
            input,
            IsisTlvIpv6ReachEntry::parse_be,
            ipv6_reach_entry_span,
        )?;
        Ok((
            input,
            Self {
                mt: mt.into(),
                entries,
            },
        ))
    }
}

impl TlvEmitter for IsisTlvMtIpv6Reach {
    fn typ(&self) -> u8 {
        IsisTlvType::MtIpv6Reach.into()
    }

    fn len(&self) -> u8 {
        // See note on `IsisTlvExtIsReach::len`.
        let entries_len = self
            .entries
            .iter()
            .map(|entry| entry.len())
            .fold(0u8, u8::saturating_add);
        entries_len.saturating_add(2)
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u16(self.mt.into());
        self.entries.iter().for_each(|entry| entry.emit(buf));
    }
}

impl From<IsisTlvMtIpv6Reach> for IsisTlv {
    fn from(tlv: IsisTlvMtIpv6Reach) -> Self {
        IsisTlv::MtIpv6Reach(tlv)
    }
}

#[bitfield(u8, debug = true)]
#[derive(PartialEq)]
pub struct Ipv6ControlInfo {
    #[bits(5)]
    pub resvd: usize,
    pub sub_tlv: bool,
    pub dist_internal: bool,
    pub dist_up: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisTlvIpv6ReachEntry {
    pub metric: u32,
    pub flags: Ipv6ControlInfo,
    pub prefix: Ipv6Net,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub subs: Vec<IsisSubTlv>,
}

impl IsisTlvIpv6ReachEntry {
    fn len(&self) -> u8 {
        if self.subs.is_empty() {
            // Metric:4 + Flags:1 + Prefixlen:1.
            (4 + 1 + 1 + psize(self.prefix.prefix_len())) as u8
        } else {
            // Metric:4 + Flags:1 + Prefix len:1 + Sub TLV length + Sub TLV.
            // usize + min keeps the packer's wire_len() probe of an
            // over-full entry debug-safe (see `IsisTlvExtIsReach::len`).
            (4 + 1 + 1 + psize(self.prefix.prefix_len()) + 1 + self.sub_len()).min(255) as u8
        }
    }

    fn sub_len(&self) -> usize {
        self.subs.iter().map(|sub| sub.len() as usize + 2).sum()
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u32(self.metric);
        buf.put_u8(self.flags.into());
        buf.put_u8(self.prefix.prefix_len());
        let plen = psize(self.prefix.prefix_len());
        if plen != 0 {
            buf.put(&self.prefix.addr().octets()[..plen]);
        }
        if self.subs.is_empty() {
            return;
        }
        emit_sub_tlvs(buf, |buf| {
            for sub in &self.subs {
                sub.emit(buf);
            }
        });
    }
}

/// SID/Label Binding TLV (type 149) flags — RFC 8667 §2.4. Wire order
/// is MSB-first (F at bit 7); the `bitfield` macro lays fields LSB-first,
/// so the *last*-declared field lands at the MSB. The **M-flag (Mirror
/// Context)** is what egress protection's SR-MPLS path (RFC 8679 context
/// label) keys on: M-set means the binding advertises a *context label*
/// (in a SID/Label sub-TLV) for the prefix's mirroring context rather
/// than a normal Prefix-SID mapping.
#[bitfield(u8, debug = true)]
#[derive(PartialEq)]
pub struct BindingFlags {
    #[bits(3)]
    pub resvd: u8,
    /// A-flag — Attached.
    pub a_flag: bool,
    /// D-flag — leaked Down from L2 to L1.
    pub d_flag: bool,
    /// S-flag — leak into another level.
    pub s_flag: bool,
    /// M-flag — Mirror Context (RFC 8679 egress protection).
    pub m_flag: bool,
    /// F-flag — Address Family of the prefix: 0 = IPv4, 1 = IPv6.
    pub f_flag: bool,
}

impl ParseBe<BindingFlags> for BindingFlags {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, flags) = be_u8(input)?;
        Ok((input, flags.into()))
    }
}

/// FEC prefix carried by the Binding TLV; family is selected by the
/// TLV's F-flag (kept here as a typed enum so consumers don't re-derive
/// it).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BindingPrefix {
    V4(Ipv4Net),
    V6(Ipv6Net),
}

impl BindingPrefix {
    fn prefix_len(&self) -> u8 {
        match self {
            BindingPrefix::V4(p) => p.prefix_len(),
            BindingPrefix::V6(p) => p.prefix_len(),
        }
    }

    fn emit(&self, buf: &mut BytesMut) {
        let plen = psize(self.prefix_len());
        buf.put_u8(self.prefix_len());
        match self {
            BindingPrefix::V4(p) => buf.put(&p.addr().octets()[..plen]),
            BindingPrefix::V6(p) => buf.put(&p.addr().octets()[..plen]),
        }
    }
}

/// One sub-TLV of a Binding TLV. The codec is permissive: it understands
/// the SID/Label sub-TLV (type 1, RFC 8667 §2.3 — the context label for a
/// Mirror Context binding) and round-trips everything else as raw bytes.
/// Validation (M-set ⇒ exactly one SID/Label sub-TLV, no Prefix-SID) lives
/// in the IS-IS layer, not here.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IsisBindingSubTlv {
    /// SID/Label sub-TLV (type 1) — a 20-bit label (len 3) or 32-bit
    /// index (len 4).
    SidLabel(SidLabelValue),
    Unknown {
        typ: u8,
        value: Vec<u8>,
    },
}

impl IsisBindingSubTlv {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, typ) = be_u8(input)?;
        let (input, len) = be_u8(input)?;
        let (input, value) = safe_split_at(input, len as usize)?;
        match typ {
            1 => {
                let (_, sid) = SidLabelValue::parse_be(value)?;
                Ok((input, Self::SidLabel(sid)))
            }
            other => Ok((
                input,
                Self::Unknown {
                    typ: other,
                    value: value.to_vec(),
                },
            )),
        }
    }

    /// Value length (excludes the 2-byte type+length header).
    fn value_len(&self) -> u8 {
        match self {
            Self::SidLabel(sid) => sid.len(),
            Self::Unknown { value, .. } => value.len() as u8,
        }
    }

    fn emit(&self, buf: &mut BytesMut) {
        match self {
            Self::SidLabel(sid) => {
                buf.put_u8(1);
                buf.put_u8(sid.len());
                sid.emit(buf);
            }
            Self::Unknown { typ, value } => {
                buf.put_u8(*typ);
                buf.put_u8(value.len() as u8);
                buf.put(&value[..]);
            }
        }
    }
}

/// SID/Label Binding TLV (type 149) — RFC 8667 §2.4. Advertises a
/// mapping from a FEC prefix (range of prefixes) to a SID/Label, plus
/// sub-TLVs. With the **M-flag** set it is a Mirror Context binding
/// (RFC 8679): the SID/Label sub-TLV carries the context label a PLR
/// pushes to steer protected traffic to the protector. The codec is
/// permissive — the M-set ⇒ SID/Label-present / Prefix-SID-absent
/// invariant is enforced at origination in the IS-IS layer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisTlvSidLabelBinding {
    pub flags: BindingFlags,
    pub weight: u8,
    pub range: u16,
    pub prefix: BindingPrefix,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub subs: Vec<IsisBindingSubTlv>,
}

impl ParseBe<IsisTlvSidLabelBinding> for IsisTlvSidLabelBinding {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, flags) = BindingFlags::parse_be(input)?;
        let (input, weight) = be_u8(input)?;
        let (input, range) = be_u16(input)?;
        let (input, prefixlen) = be_u8(input)?;
        let (input, prefix) = if flags.f_flag() {
            let (input, p) = ptakev6(input, prefixlen)?;
            (input, BindingPrefix::V6(p))
        } else {
            let (input, p) = ptake(input, prefixlen)?;
            (input, BindingPrefix::V4(p))
        };
        // The remainder of the TLV value is sub-TLVs (no separate
        // sub-TLV-length field — the TLV length bounds them).
        let (input, subs) = many0_complete(IsisBindingSubTlv::parse_be).parse(input)?;
        Ok((
            input,
            Self {
                flags,
                weight,
                range,
                prefix,
                subs,
            },
        ))
    }
}

impl TlvEmitter for IsisTlvSidLabelBinding {
    fn typ(&self) -> u8 {
        IsisTlvType::SidLabelBinding.into()
    }

    fn len(&self) -> u8 {
        // Flags(1)+Weight(1)+Range(2)+PrefixLen(1)+Prefix+Sub-TLVs.
        let prefix = psize(self.prefix.prefix_len()) as u8;
        let subs: u8 = self
            .subs
            .iter()
            .map(|sub| sub.value_len() + 2)
            .fold(0u8, u8::saturating_add);
        1u8.saturating_add(1)
            .saturating_add(2)
            .saturating_add(1)
            .saturating_add(prefix)
            .saturating_add(subs)
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.flags.into());
        buf.put_u8(self.weight);
        buf.put_u16(self.range);
        self.prefix.emit(buf);
        for sub in &self.subs {
            sub.emit(buf);
        }
    }
}

impl From<IsisTlvSidLabelBinding> for IsisTlv {
    fn from(tlv: IsisTlvSidLabelBinding) -> Self {
        IsisTlv::SidLabelBinding(tlv)
    }
}

pub fn psize(plen: u8) -> usize {
    // From Rust 1.73 we can use .dev_ceil()
    // ((plen + 7) / 8) as usize
    (plen as usize).div_ceil(8)
}

pub fn ptake(input: &[u8], prefixlen: u8) -> IResult<&[u8], Ipv4Net> {
    if prefixlen == 0 {
        return Ok((
            input,
            Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).expect("prefix length 0 is always valid"),
        ));
    }
    if prefixlen > 32 {
        return Err(nom::Err::Error(nom::error::make_error(
            input,
            nom::error::ErrorKind::Verify,
        )));
    }
    let psize = psize(prefixlen);
    if input.len() < psize {
        return Err(nom::Err::Incomplete(Needed::new(psize)));
    }
    let mut addr = [0u8; 4];
    addr[..psize].copy_from_slice(&input[..psize]);
    let (input, _) = take(psize)(input)?;
    let Ok(prefix) = Ipv4Net::new(Ipv4Addr::from(addr), prefixlen) else {
        return Err(nom::Err::Error(nom::error::make_error(
            input,
            nom::error::ErrorKind::Verify,
        )));
    };
    Ok((input, prefix))
}

pub fn ptakev6(input: &[u8], prefixlen: u8) -> IResult<&[u8], Ipv6Net> {
    if prefixlen == 0 {
        return Ok((
            input,
            Ipv6Net::new(Ipv6Addr::UNSPECIFIED, 0).expect("prefix length 0 is always valid"),
        ));
    }
    if prefixlen > 128 {
        return Err(nom::Err::Error(nom::error::make_error(
            input,
            nom::error::ErrorKind::Verify,
        )));
    }
    let psize = psize(prefixlen);
    if input.len() < psize {
        return Err(nom::Err::Incomplete(Needed::new(psize)));
    }
    let mut addr = [0u8; 16];
    addr[..psize].copy_from_slice(&input[..psize]);
    let (input, _) = take(psize)(input)?;
    let Ok(prefix) = Ipv6Net::new(Ipv6Addr::from(addr), prefixlen) else {
        return Err(nom::Err::Error(nom::error::make_error(
            input,
            nom::error::ErrorKind::Verify,
        )));
    };
    Ok((input, prefix))
}

/// Byte span of one TLV 135 entry computed from its header fields
/// alone, so a semantically invalid entry (e.g. control-byte prefixlen
/// 33..63) can be skipped without desyncing the entries that follow.
/// Returns `None` when the claimed span overruns `input` — that tail is
/// unframeable garbage.
fn ext_ip_reach_entry_span(input: &[u8]) -> Option<usize> {
    // Metric(4) + Control(1).
    if input.len() < 5 {
        return None;
    }
    let flags: Ipv4ControlInfo = input[4].into();
    let mut span = 5 + psize(flags.prefixlen() as u8);
    if flags.sub_tlv() {
        span += 1 + *input.get(span)? as usize;
    }
    (input.len() >= span).then_some(span)
}

/// TLV 236 sibling of [`ext_ip_reach_entry_span`] (prefixlen is an
/// explicit octet, invalid when > 128).
fn ipv6_reach_entry_span(input: &[u8]) -> Option<usize> {
    // Metric(4) + Flags(1) + PrefixLen(1).
    if input.len() < 6 {
        return None;
    }
    let flags: Ipv6ControlInfo = input[4].into();
    let mut span = 6 + psize(input[5]);
    if flags.sub_tlv() {
        span += 1 + *input.get(span)? as usize;
    }
    (input.len() >= span).then_some(span)
}

/// Parse a reach-entry list, *skipping* a malformed entry instead of
/// truncating the list at it (`many0` treats an entry error as
/// end-of-list, which silently dropped every valid entry after a bad
/// one). `parse` reads one entry; `span` frames one entry from raw
/// bytes. An unframeable tail returns an error so the enclosing TLV
/// degrades to Unknown at the top-level loop rather than silently
/// discarding bytes.
fn parse_reach_entries<T>(
    mut input: &[u8],
    parse: impl Fn(&[u8]) -> IResult<&[u8], T>,
    span: impl Fn(&[u8]) -> Option<usize>,
) -> IResult<&[u8], Vec<T>> {
    let mut entries = Vec::new();
    while !input.is_empty() {
        match parse(input) {
            Ok((rest, entry)) => {
                entries.push(entry);
                input = rest;
            }
            Err(_) => match span(input) {
                Some(n) => input = &input[n..],
                None => {
                    return Err(nom::Err::Error(nom::error::make_error(
                        input,
                        nom::error::ErrorKind::Verify,
                    )));
                }
            },
        }
    }
    Ok((input, entries))
}

impl ParseBe<IsisTlvExtIpReachEntry> for IsisTlvExtIpReachEntry {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, metric) = be_u32(input)?;
        let (input, flags) = be_u8(input)?;
        let flags: Ipv4ControlInfo = flags.into();
        let (input, prefix) = ptake(input, flags.prefixlen() as u8)?;
        let mut tlv = Self {
            metric,
            flags,
            prefix,
            subs: Vec::new(),
        };
        if !flags.sub_tlv() {
            return Ok((input, tlv));
        }
        let (input, sublen) = be_u8(input)?;
        let (input, sub) = safe_split_at(input, sublen as usize)?;
        let (_, subs) = many0_complete(IsisSubTlv::parse_subs).parse(sub)?;
        tlv.subs = subs;
        Ok((input, tlv))
    }
}

impl ParseBe<IsisTlvIpv6ReachEntry> for IsisTlvIpv6ReachEntry {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, metric) = be_u32(input)?;
        let (input, flags) = be_u8(input)?;
        let flags: Ipv6ControlInfo = flags.into();
        let (input, prefixlen) = be_u8(input)?;
        let (input, prefix) = ptakev6(input, prefixlen)?;
        let mut tlv = Self {
            metric,
            flags,
            prefix,
            subs: Vec::new(),
        };
        if !flags.sub_tlv() {
            return Ok((input, tlv));
        }
        let (input, sublen) = be_u8(input)?;
        let (input, sub) = safe_split_at(input, sublen as usize)?;
        let (_, subs) = many0_complete(IsisSubTlv::parse_subs).parse(sub)?;
        tlv.subs = subs;
        Ok((input, tlv))
    }
}

// RFC 9352 §7.1: the SRv6 Locator TLV (type 27) opens with the same
// 2-octet MT header as RFC 5120 — 4 reserved bits in the MSBs, then a
// 12-bit MT ID. `bitfield(u16)` is LSB-first (see `MultiTopologyId`
// above): declare `mtid` first to land at bits 0-11 and `resvd` second
// at bits 12-15. The previous order (`resvd` first, MT ID misnamed
// `v_flag`) read the MT ID out of the reserved bits, so an MT-2 locator
// parsed as MT-0 and a locally-built MTID=2 emitted 0x0020.
#[bitfield(u16, debug = true)]
#[derive(PartialEq)]
pub struct Srv6TlvFlags {
    #[bits(12)]
    pub mtid: u16,
    #[bits(4)]
    pub resvd: u8,
}

impl ParseBe<Srv6TlvFlags> for Srv6TlvFlags {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, flags) = be_u16(input)?;
        Ok((input, flags.into()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Srv6Locator {
    pub metric: u32,
    pub flags: u8,
    pub algo: Algo,
    pub locator: Ipv6Net,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub subs: Vec<IsisSubTlv>,
}

impl Srv6Locator {
    fn len(&self) -> u8 {
        // Metric(4)+Flags(1)+Algo(1)+PrefixLen(1)+Locator+SubLen(1)+Subs
        let sub_len: usize = self.subs.iter().map(|sub| sub.len() as usize + 2).sum();
        (4 + 1 + 1 + 1 + psize(self.locator.prefix_len()) + 1 + sub_len).min(255) as u8
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u32(self.metric);
        buf.put_u8(self.flags);
        buf.put_u8(self.algo.into());
        buf.put_u8(self.locator.prefix_len());
        let plen = psize(self.locator.prefix_len());
        if plen != 0 {
            buf.put(&self.locator.addr().octets()[..plen]);
        }
        emit_sub_tlvs(buf, |buf| {
            for sub in &self.subs {
                sub.emit(buf);
            }
        });
    }
}

impl ParseBe<Srv6Locator> for Srv6Locator {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, metric) = be_u32(input)?;
        let (input, flags) = be_u8(input)?;
        let (input, algo) = be_u8(input)?;
        let (input, prefixlen) = be_u8(input)?;
        let (input, locator) = ptakev6(input, prefixlen)?;
        let mut tlv = Self {
            metric,
            flags,
            algo: algo.into(),
            locator,
            subs: Vec::new(),
        };
        let (input, sublen) = be_u8(input)?;
        if sublen == 0 {
            return Ok((input, tlv));
        }
        let (input, sub) = safe_split_at(input, sublen as usize)?;
        let (_, subs) = many0_complete(IsisSubTlv::parse_subs).parse(sub)?;
        tlv.subs = subs;
        Ok((input, tlv))
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct IsisTlvSrv6 {
    pub flags: Srv6TlvFlags,
    pub locators: Vec<Srv6Locator>,
}

impl ParseBe<IsisTlvSrv6> for IsisTlvSrv6 {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, flags) = be_u16(input)?;
        let (input, locators) = many0_complete(Srv6Locator::parse_be).parse(input)?;
        Ok((
            input,
            Self {
                flags: flags.into(),
                locators,
            },
        ))
    }
}

impl TlvEmitter for IsisTlvSrv6 {
    fn typ(&self) -> u8 {
        IsisTlvType::Srv6.into()
    }

    fn len(&self) -> u8 {
        // See note on `IsisTlvExtIsReach::len` — saturate so the packer's
        // wire_len() probe of a not-yet-split TLV stays debug-safe.
        let len: usize = self
            .locators
            .iter()
            .map(|locator| locator.len() as usize)
            .sum();
        (len + 2).min(255) as u8
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u16(self.flags.into());
        for locator in &self.locators {
            locator.emit(buf);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Finding #10 (v4): a semantically invalid entry (control-byte
    /// prefixlen 33, illegal for IPv4) used to stop `many0` and
    /// silently drop every valid entry after it. It is now framed from
    /// its header and skipped alone.
    #[test]
    fn malformed_v4_reach_entry_is_skipped_not_truncating() {
        #[rustfmt::skip]
        let raw = [
            // Entry 1 (malformed): metric 10, control 0x21 = prefixlen
            // 33 (no subs), ceil(33/8) = 5 prefix octets.
            0, 0, 0, 10, 0x21, 1, 2, 3, 4, 5,
            // Entry 2 (valid): metric 20, control 0x18 = /24, 10.1.1/24.
            0, 0, 0, 20, 0x18, 10, 1, 1,
        ];
        let (rest, tlv) = IsisTlvExtIpReach::parse_be(&raw).expect("parse");
        assert!(rest.is_empty());
        assert_eq!(tlv.entries.len(), 1);
        assert_eq!(tlv.entries[0].prefix, "10.1.1.0/24".parse().unwrap());
    }

    /// Finding #10 (v6): prefixlen 200 (> 128) in the first entry must
    /// not swallow the valid /64 entry after it.
    #[test]
    fn malformed_v6_reach_entry_is_skipped_not_truncating() {
        let mut raw = vec![0u8, 0, 0, 10, 0x00, 200];
        raw.extend(vec![0xEE; psize(200)]); // ceil(200/8) = 25
        // Valid entry: metric 20, flags 0, 2001:db8::/64.
        raw.extend([0, 0, 0, 20, 0x00, 64, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0]);
        let (rest, tlv) = IsisTlvIpv6Reach::parse_be(&raw).expect("parse");
        assert!(rest.is_empty());
        assert_eq!(tlv.entries.len(), 1);
        assert_eq!(tlv.entries[0].prefix, "2001:db8::/64".parse().unwrap());
    }

    /// Finding #10 (sub-TLVs): a malformed *known* sub-TLV degrades to
    /// Unknown with its bytes preserved instead of truncating the list.
    #[test]
    fn malformed_known_sub_tlv_degrades_to_unknown() {
        #[rustfmt::skip]
        let raw = [
            3u8, 1, 0xFF,        // PrefixSid (code 3) with a 1-byte body: malformed.
            11, 4, 10, 0, 0, 1,  // Ipv4SourceRouterId (code 11): valid.
        ];
        let (rest, first) = IsisSubTlv::parse_subs(&raw).expect("first");
        let IsisSubTlv::Unknown(u) = &first else {
            panic!("expected Unknown, got {first:?}");
        };
        assert_eq!((u.code, u.len, u.data.as_slice()), (3, 1, &[0xFF][..]));
        let (rest, second) = IsisSubTlv::parse_subs(rest).expect("second");
        assert!(matches!(second, IsisSubTlv::Ipv4SourceRouterId(_)));
        assert!(rest.is_empty());
    }

    #[test]
    fn srv6_tlv_mtid_bit_positions() {
        // RFC 9352 §7.1 / RFC 5120 §7.2: 4 reserved MSBs, 12-bit MT ID
        // in the LSBs — wire 0x0002 is MT 2, and MT 2 emits 0x0002.
        let flags = Srv6TlvFlags::from(0x0002u16);
        assert_eq!(flags.mtid(), 2);
        assert_eq!(flags.resvd(), 0);

        let emitted: u16 = Srv6TlvFlags::new().with_mtid(2).into();
        assert_eq!(emitted, 0x0002);

        // Reserved bits stay in the top nibble.
        let flags = Srv6TlvFlags::from(0xF002u16);
        assert_eq!(flags.mtid(), 2);
        assert_eq!(flags.resvd(), 0xF);

        // Full TLV round-trip keeps the MT ID.
        let tlv = IsisTlvSrv6 {
            flags: Srv6TlvFlags::new().with_mtid(2),
            locators: vec![],
        };
        let mut buf = BytesMut::new();
        tlv.emit(&mut buf);
        assert_eq!(&buf[..], &[0x00, 0x02]);
        let (rest, parsed) = IsisTlvSrv6::parse_be(&buf).expect("parse");
        assert!(rest.is_empty());
        assert_eq!(parsed.flags.mtid(), 2);
    }
}
