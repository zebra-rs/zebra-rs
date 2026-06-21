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
        let len: u8 = self.sub2s.iter().map(|sub| sub.len() + 2).sum();
        1 + 2 + 16 + 1 + len
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
        let len: u8 = self.sub2s.iter().map(|sub| sub.len() + 2).sum();
        1 + 2 + 16 + 1 + len
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
        let (_, mut val) = Self::parse_be(sub, cl.code.into())?;
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
        let (_, mut val) = Self::parse_be(sub, cl.code.into())?;
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
        let (_, mut val) = Self::parse_be(sub, cl.code.into())?;
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
        let (input, entries) = many0_complete(IsisTlvExtIpReachEntry::parse_be).parse(input)?;
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
        let (input, entries) = many0_complete(IsisTlvExtIpReachEntry::parse_be).parse(input)?;
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
            4 + 1 + (psize(self.prefix.prefix_len()) as u8)
        } else {
            // Metric:4 + Flags:1 + Prefix + Sub TLV length + Sub TLV.
            4 + 1 + (psize(self.prefix.prefix_len()) as u8) + 1 + self.sub_len()
        }
    }

    fn sub_len(&self) -> u8 {
        self.subs.iter().map(|sub| sub.len() + 2).sum()
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
        buf.put_u8(self.sub_len());
        for sub in self.subs.iter() {
            sub.emit(buf);
        }
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
        let (input, entries) = many0_complete(IsisTlvIpv6ReachEntry::parse_be).parse(input)?;
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
        let (input, entries) = many0_complete(IsisTlvIpv6ReachEntry::parse_be).parse(input)?;
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
            4 + 1 + 1 + (psize(self.prefix.prefix_len()) as u8)
        } else {
            // Metric:4 + Flags:1 + Prefix len:1 + Sub TLV length + Sub TLV.
            4 + 1 + 1 + (psize(self.prefix.prefix_len()) as u8) + 1 + self.sub_len()
        }
    }

    fn sub_len(&self) -> u8 {
        self.subs.iter().map(|sub| sub.len() + 2).sum()
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
        buf.put_u8(self.sub_len());
        for sub in &self.subs {
            sub.emit(buf);
        }
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

#[bitfield(u16, debug = true)]
#[derive(PartialEq)]
pub struct Srv6TlvFlags {
    #[bits(4)]
    pub resvd: u8,
    #[bits(12)]
    pub v_flag: u16,
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
        // Metric(4)+Flags(1)+Algo(1)+Locator(16)+SubLen(1)+Subs
        let sub_len: u8 = self.subs.iter().map(|sub| sub.len() + 2).sum();
        4 + 1 + 1 + 1 + (psize(self.locator.prefix_len()) as u8) + 1 + sub_len
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
        let len: u8 = self.locators.iter().map(|locator| locator.len()).sum();
        len + 2
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u16(self.flags.into());
        for locator in &self.locators {
            locator.emit(buf);
        }
    }
}
