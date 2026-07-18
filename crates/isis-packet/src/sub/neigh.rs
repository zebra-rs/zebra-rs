use std::net::{Ipv4Addr, Ipv6Addr};

use super::prefix::MultiTopologyId;
use bitfield_struct::bitfield;
use bytes::{BufMut, BytesMut};
use nom::IResult;
use nom::bytes::complete::take;
use nom::number::complete::{be_u8, be_u16, be_u24, be_u32};
use nom_derive::*;
use packet_utils::{Algo, safe_split_at};
use serde::{Deserialize, Serialize};

use crate::util::{ParseBe, TlvEmitter, emit_sub_tlvs, u32_u8_3};
use crate::{
    IPV4_ADDR_LEN, IPV6_ADDR_LEN, IsisNeighborId, IsisSysId, IsisTlv, IsisTlvType, SidLabelValue,
    many0_complete,
};

use super::{Behavior, IsisCodeLen, IsisNeighCode, IsisSub2Tlv, IsisSubTlvUnknown};

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisTlvExtIsReach {
    pub entries: Vec<IsisTlvExtIsReachEntry>,
}

impl From<IsisTlvExtIsReach> for IsisTlv {
    fn from(tlv: IsisTlvExtIsReach) -> Self {
        IsisTlv::ExtIsReach(tlv)
    }
}

impl ParseBe<IsisTlvExtIsReach> for IsisTlvExtIsReach {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, entries) = many0_complete(IsisTlvExtIsReachEntry::parse_be).parse(input)?;
        Ok((input, Self { entries }))
    }
}

impl IsisTlvExtIsReach {
    /// True value length in bytes, unsaturated. The u8 `len()`
    /// saturates at 255 by design; this is the packer's source of
    /// truth for probing a not-yet-split TLV without serializing it.
    pub fn value_wire_len(&self) -> usize {
        self.entries.iter().map(|e| e.len() as usize).sum()
    }
}

impl TlvEmitter for IsisTlvExtIsReach {
    fn typ(&self) -> u8 {
        IsisTlvType::ExtIsReach.into()
    }

    fn len(&self) -> u8 {
        // The packer pre-shards entry-bearing TLVs at the 255-byte
        // value boundary, so a well-formed TLV here stays under
        // u8::MAX. `saturating_add` is for the diagnostic path —
        // measurement via `wire_len()` clones a not-yet-split TLV
        // to probe its true size; raw `u8::add` would panic in debug
        // mode before the splitter could correct it.
        self.entries
            .iter()
            .map(|entry| entry.len())
            .fold(0u8, u8::saturating_add)
    }

    fn emit(&self, buf: &mut BytesMut) {
        self.entries.iter().for_each(|entry| entry.emit(buf));
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisTlvMtIsReach {
    pub mt: MultiTopologyId,
    pub entries: Vec<IsisTlvExtIsReachEntry>,
}

impl ParseBe<IsisTlvMtIsReach> for IsisTlvMtIsReach {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, mt) = be_u16(input)?;
        let (input, entries) = many0_complete(IsisTlvExtIsReachEntry::parse_be).parse(input)?;
        Ok((
            input,
            Self {
                mt: mt.into(),
                entries,
            },
        ))
    }
}

impl IsisTlvMtIsReach {
    /// See `IsisTlvExtIsReach::value_wire_len` — plus the 2-byte MT ID.
    pub fn value_wire_len(&self) -> usize {
        2 + self.entries.iter().map(|e| e.len() as usize).sum::<usize>()
    }
}

impl TlvEmitter for IsisTlvMtIsReach {
    fn typ(&self) -> u8 {
        IsisTlvType::MtIsReach.into()
    }

    fn len(&self) -> u8 {
        // See note on `IsisTlvExtIsReach::len`: saturate to keep
        // the packer's probe-via-wire_len path debug-safe.
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

impl From<IsisTlvMtIsReach> for IsisTlv {
    fn from(tlv: IsisTlvMtIsReach) -> Self {
        IsisTlv::MtIsReach(tlv)
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisTlvExtIsReachEntry {
    pub neighbor_id: IsisNeighborId,
    pub metric: u32,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub subs: Vec<IsisSubTlv>,
}

impl IsisTlvExtIsReachEntry {
    /// Local IPv4 interface address (sub-TLV 6), if present. Exposed so
    /// consumers outside this crate (e.g. the BGP-LS producer) can read link
    /// addresses without naming the module-private `IsisSubTlv` enum, which is
    /// ambiguous at the crate root (both `neigh` and `prefix` define one).
    pub fn ipv4_if_addr(&self) -> Option<std::net::Ipv4Addr> {
        self.subs.iter().find_map(|s| match s {
            IsisSubTlv::Ipv4IfAddr(a) => Some(a.addr),
            _ => None,
        })
    }

    /// Remote IPv4 neighbor address (sub-TLV 8), if present.
    pub fn ipv4_neigh_addr(&self) -> Option<std::net::Ipv4Addr> {
        self.subs.iter().find_map(|s| match s {
            IsisSubTlv::Ipv4NeighAddr(a) => Some(a.addr),
            _ => None,
        })
    }

    /// Local IPv6 interface address (sub-TLV 12), if present.
    pub fn ipv6_if_addr(&self) -> Option<std::net::Ipv6Addr> {
        self.subs.iter().find_map(|s| match s {
            IsisSubTlv::Ipv6IfAddr(a) => Some(a.addr),
            _ => None,
        })
    }

    /// Remote IPv6 neighbor address (sub-TLV 13), if present.
    pub fn ipv6_neigh_addr(&self) -> Option<std::net::Ipv6Addr> {
        self.subs.iter().find_map(|s| match s {
            IsisSubTlv::Ipv6NeighAddr(a) => Some(a.addr),
            _ => None,
        })
    }

    /// Administrative group / link-color bitmask (sub-TLV 3,
    /// RFC 5305 §3.1) — the classic fixed 32-bit mask. Maps to BGP-LS
    /// Administrative Group (TLV 1088).
    pub fn admin_group(&self) -> Option<u32> {
        self.subs.iter().find_map(|s| match s {
            IsisSubTlv::AdminGroup(a) => Some(a.group),
            _ => None,
        })
    }

    /// Extended Administrative Groups (sub-TLV 14, RFC 7308), if
    /// present — a variable-length list of 32-bit words. Maps to
    /// BGP-LS Extended Administrative Group (TLV 1173), not TLV 1088.
    pub fn ext_admin_group(&self) -> Option<&[u32]> {
        self.subs.iter().find_map(|s| match s {
            IsisSubTlv::AdminGrp(a) => Some(a.groups.as_slice()),
            _ => None,
        })
    }

    /// TE default metric (sub-TLV 18, RFC 5305), if present. A 24-bit value.
    pub fn te_metric(&self) -> Option<u32> {
        self.subs.iter().find_map(|s| match s {
            IsisSubTlv::TeMetric(t) => Some(t.metric),
            _ => None,
        })
    }

    fn len(&self) -> u8 {
        // 11 is the entry length without sub-TLVs. usize + min keeps the
        // packer's wire_len() probe of an over-full entry debug-safe
        // (see `IsisTlvExtIsReach::len`).
        (11 + self.sub_len()).min(255) as u8
    }

    fn sub_len(&self) -> usize {
        self.subs.iter().map(|sub| sub.len() as usize + 2).sum()
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put(&self.neighbor_id.id[..]);
        buf.put(&u32_u8_3(self.metric)[..]);
        emit_sub_tlvs(buf, |buf| {
            for sub in self.subs.iter() {
                sub.emit(buf);
            }
        });
    }
}

impl ParseBe<IsisTlvExtIsReachEntry> for IsisTlvExtIsReachEntry {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, neighbor_id) = take(7usize)(input)?;
        let (input, metric) = be_u24(input)?;
        let (input, sublen) = be_u8(input)?;
        let (input, sub) = safe_split_at(input, sublen as usize)?;
        let (_, subs) = many0_complete(IsisSubTlv::parse_subs).parse(sub)?;

        let mut tlv = Self::default();
        tlv.neighbor_id.id.copy_from_slice(neighbor_id);
        tlv.metric = metric;
        tlv.subs = subs;

        Ok((input, tlv))
    }
}

#[derive(Debug, NomBE, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[nom(Selector = "IsisNeighCode")]
pub enum IsisSubTlv {
    #[nom(Selector = "IsisNeighCode::Ipv4IfAddr")]
    Ipv4IfAddr(IsisSubIpv4IfAddr),
    #[nom(Selector = "IsisNeighCode::Ipv4NeighAddr")]
    Ipv4NeighAddr(IsisSubIpv4NeighAddr),
    #[nom(Selector = "IsisNeighCode::Ipv6IfAddr")]
    Ipv6IfAddr(IsisSubIpv6IfAddr),
    #[nom(Selector = "IsisNeighCode::Ipv6NeighAddr")]
    Ipv6NeighAddr(IsisSubIpv6NeighAddr),
    #[nom(Selector = "IsisNeighCode::AdminGroup")]
    AdminGroup(IsisSubAdminGroup),
    #[nom(Selector = "IsisNeighCode::AdminGrp")]
    AdminGrp(IsisSubAdminGrp),
    #[nom(Selector = "IsisNeighCode::Asla")]
    Asla(IsisSubAsla),
    #[nom(Selector = "IsisNeighCode::TeMetric")]
    TeMetric(IsisSubTeMetric),
    #[nom(Selector = "IsisNeighCode::AdjSid")]
    AdjSid(IsisSubAdjSid),
    #[nom(Selector = "IsisNeighCode::LanAdjSid")]
    LanAdjSid(IsisSubLanAdjSid),
    #[nom(Selector = "IsisNeighCode::UniLinkDelay")]
    UniLinkDelay(IsisSubUniLinkDelay),
    #[nom(Selector = "IsisNeighCode::MinMaxLinkDelay")]
    MinMaxLinkDelay(IsisSubMinMaxLinkDelay),
    #[nom(Selector = "IsisNeighCode::DelayVariation")]
    DelayVariation(IsisSubDelayVariation),
    #[nom(Selector = "IsisNeighCode::LinkLoss")]
    LinkLoss(IsisSubLinkLoss),
    #[nom(Selector = "IsisNeighCode::ResidualBw")]
    ResidualBw(IsisSubResidualBw),
    #[nom(Selector = "IsisNeighCode::AvailableBw")]
    AvailableBw(IsisSubAvailableBw),
    #[nom(Selector = "IsisNeighCode::UtilizedBw")]
    UtilizedBw(IsisSubUtilizedBw),
    #[nom(Selector = "IsisNeighCode::Srv6EndXSid")]
    Srv6EndXSid(IsisSubSrv6EndXSid),
    #[nom(Selector = "IsisNeighCode::Srv6LanEndXSid")]
    Srv6LanEndXSid(IsisSubSrv6LanEndXSid),
    #[nom(Selector = "_")]
    Unknown(IsisSubTlvUnknown),
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
            Ipv4IfAddr(v) => v.len(),
            Ipv4NeighAddr(v) => v.len(),
            Ipv6IfAddr(v) => v.len(),
            Ipv6NeighAddr(v) => v.len(),
            AdminGroup(v) => v.len(),
            AdminGrp(v) => v.len(),
            Asla(v) => v.len(),
            TeMetric(v) => v.len(),
            AdjSid(v) => v.len(),
            LanAdjSid(v) => v.len(),
            UniLinkDelay(v) => v.len(),
            MinMaxLinkDelay(v) => v.len(),
            DelayVariation(v) => v.len(),
            LinkLoss(v) => v.len(),
            ResidualBw(v) => v.len(),
            AvailableBw(v) => v.len(),
            UtilizedBw(v) => v.len(),
            Srv6EndXSid(v) => v.len(),
            Srv6LanEndXSid(v) => v.len(),
            Unknown(v) => v.len,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        use IsisSubTlv::*;
        match self {
            Ipv4IfAddr(v) => v.tlv_emit(buf),
            Ipv4NeighAddr(v) => v.tlv_emit(buf),
            Ipv6IfAddr(v) => v.tlv_emit(buf),
            Ipv6NeighAddr(v) => v.tlv_emit(buf),
            AdminGroup(v) => v.tlv_emit(buf),
            AdminGrp(v) => v.tlv_emit(buf),
            Asla(v) => v.tlv_emit(buf),
            TeMetric(v) => v.tlv_emit(buf),
            AdjSid(v) => v.tlv_emit(buf),
            LanAdjSid(v) => v.tlv_emit(buf),
            UniLinkDelay(v) => v.tlv_emit(buf),
            MinMaxLinkDelay(v) => v.tlv_emit(buf),
            DelayVariation(v) => v.tlv_emit(buf),
            LinkLoss(v) => v.tlv_emit(buf),
            ResidualBw(v) => v.tlv_emit(buf),
            AvailableBw(v) => v.tlv_emit(buf),
            UtilizedBw(v) => v.tlv_emit(buf),
            Srv6EndXSid(v) => v.tlv_emit(buf),
            Srv6LanEndXSid(v) => v.tlv_emit(buf),
            Unknown(v) => v.tlv_emit(buf),
        }
    }
}

#[derive(Debug, NomBE, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisSubIpv4IfAddr {
    pub addr: Ipv4Addr,
}

impl TlvEmitter for IsisSubIpv4IfAddr {
    fn typ(&self) -> u8 {
        IsisNeighCode::Ipv4IfAddr.into()
    }

    fn len(&self) -> u8 {
        IPV4_ADDR_LEN
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put(&self.addr.octets()[..]);
    }
}

#[derive(Debug, NomBE, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisSubIpv4NeighAddr {
    pub addr: Ipv4Addr,
}

impl TlvEmitter for IsisSubIpv4NeighAddr {
    fn typ(&self) -> u8 {
        IsisNeighCode::Ipv4NeighAddr.into()
    }

    fn len(&self) -> u8 {
        IPV4_ADDR_LEN
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put(&self.addr.octets()[..]);
    }
}

#[derive(Debug, NomBE, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisSubIpv6IfAddr {
    pub addr: Ipv6Addr,
}

impl TlvEmitter for IsisSubIpv6IfAddr {
    fn typ(&self) -> u8 {
        IsisNeighCode::Ipv6IfAddr.into()
    }

    fn len(&self) -> u8 {
        IPV6_ADDR_LEN
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put(&self.addr.octets()[..]);
    }
}

#[derive(Debug, NomBE, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisSubIpv6NeighAddr {
    pub addr: Ipv6Addr,
}

impl TlvEmitter for IsisSubIpv6NeighAddr {
    fn typ(&self) -> u8 {
        IsisNeighCode::Ipv6NeighAddr.into()
    }

    fn len(&self) -> u8 {
        IPV6_ADDR_LEN
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put(&self.addr.octets()[..]);
    }
}

/// RFC 5305 §3.1 Administrative Group / link color (sub-TLV 3) — the
/// classic fixed 4-octet mask, distinct from the RFC 7308 Extended
/// Administrative Groups (sub-TLV 14, [`IsisSubAdminGrp`]). BGP-LS
/// keeps them distinct too (TLV 1088 vs TLV 1173).
#[derive(Debug, NomBE, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisSubAdminGroup {
    pub group: u32,
}

impl TlvEmitter for IsisSubAdminGroup {
    fn typ(&self) -> u8 {
        IsisNeighCode::AdminGroup.into()
    }

    fn len(&self) -> u8 {
        4
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u32(self.group);
    }
}

impl From<IsisSubAdminGroup> for IsisSubTlv {
    fn from(value: IsisSubAdminGroup) -> Self {
        IsisSubTlv::AdminGroup(value)
    }
}

// RFC 7308 Extended Administrative Groups (sub-TLV 14)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisSubAdminGrp {
    pub groups: Vec<u32>,
}

impl ParseBe<IsisSubAdminGrp> for IsisSubAdminGrp {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, groups) = many0_complete(be_u32).parse(input)?;
        Ok((input, Self { groups }))
    }
}

impl TlvEmitter for IsisSubAdminGrp {
    fn typ(&self) -> u8 {
        IsisNeighCode::AdminGrp.into()
    }

    fn len(&self) -> u8 {
        // Up to 63 groups (63 * 4 = 252), capped to 255.
        (self.groups.len().min(63) * 4) as u8
    }

    fn emit(&self, buf: &mut BytesMut) {
        for group in self.groups.iter().take(63) {
            buf.put_u32(*group);
        }
    }
}

impl From<IsisSubAdminGrp> for IsisSubTlv {
    fn from(value: IsisSubAdminGrp) -> Self {
        IsisSubTlv::AdminGrp(value)
    }
}

/// RFC 8570 §4.1 — Unidirectional Link Delay (sub-TLV 33).
///
/// Wire payload is 4 octets: the high bit of byte 0 is the `A`
/// (anomalous) flag, the next 7 bits are reserved, and the
/// remaining 24 bits are the average one-way delay in microseconds
/// (so the maximum representable delay is ~16.78 seconds). The
/// `A` flag is set by the originator when the measured value
/// crosses a configured high-water threshold and cleared again
/// once it falls below the reuse threshold.
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisSubUniLinkDelay {
    pub anomalous: bool,
    pub delay: u32,
}

impl ParseBe<IsisSubUniLinkDelay> for IsisSubUniLinkDelay {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, raw) = be_u32(input)?;
        Ok((input, Self::from_raw(raw)))
    }
}

impl IsisSubUniLinkDelay {
    fn from_raw(raw: u32) -> Self {
        Self {
            anomalous: (raw & 0x8000_0000) != 0,
            delay: raw & 0x00FF_FFFF,
        }
    }

    fn to_raw(&self) -> u32 {
        let a = if self.anomalous { 0x8000_0000 } else { 0 };
        a | (self.delay & 0x00FF_FFFF)
    }
}

impl TlvEmitter for IsisSubUniLinkDelay {
    fn typ(&self) -> u8 {
        IsisNeighCode::UniLinkDelay.into()
    }
    fn len(&self) -> u8 {
        4
    }
    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u32(self.to_raw());
    }
}

impl From<IsisSubUniLinkDelay> for IsisSubTlv {
    fn from(v: IsisSubUniLinkDelay) -> Self {
        IsisSubTlv::UniLinkDelay(v)
    }
}

/// RFC 8570 §4.2 — Min/Max Unidirectional Link Delay (sub-TLV 34).
///
/// Wire payload is 8 octets:
///   - byte 0 bit 7: `A` flag, bits 6..0: reserved
///   - bytes 1..3:   24-bit Min delay (microseconds)
///   - byte 4:       reserved
///   - bytes 5..7:   24-bit Max delay (microseconds)
///
/// The single `A` flag covers both Min and Max — the originator
/// raises it if *either* measured bound crosses the configured
/// high-water threshold.
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisSubMinMaxLinkDelay {
    pub anomalous: bool,
    pub min_delay: u32,
    pub max_delay: u32,
}

impl ParseBe<IsisSubMinMaxLinkDelay> for IsisSubMinMaxLinkDelay {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, w0) = be_u32(input)?;
        let (input, w1) = be_u32(input)?;
        Ok((
            input,
            Self {
                anomalous: (w0 & 0x8000_0000) != 0,
                min_delay: w0 & 0x00FF_FFFF,
                max_delay: w1 & 0x00FF_FFFF,
            },
        ))
    }
}

impl TlvEmitter for IsisSubMinMaxLinkDelay {
    fn typ(&self) -> u8 {
        IsisNeighCode::MinMaxLinkDelay.into()
    }
    fn len(&self) -> u8 {
        8
    }
    fn emit(&self, buf: &mut BytesMut) {
        let a = if self.anomalous { 0x8000_0000 } else { 0 };
        buf.put_u32(a | (self.min_delay & 0x00FF_FFFF));
        buf.put_u32(self.max_delay & 0x00FF_FFFF);
    }
}

impl From<IsisSubMinMaxLinkDelay> for IsisSubTlv {
    fn from(v: IsisSubMinMaxLinkDelay) -> Self {
        IsisSubTlv::MinMaxLinkDelay(v)
    }
}

/// RFC 8570 §4.3 — Unidirectional Delay Variation (sub-TLV 35).
///
/// 4-octet payload: byte 0 reserved, bytes 1..3 carry a 24-bit
/// delay-variation value in microseconds. No `A` flag — RFC 8570
/// §3 explicitly drops it from this sub-TLV to avoid feedback
/// loops between routing and the metric's own oscillation.
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisSubDelayVariation {
    pub variation: u32,
}

impl ParseBe<IsisSubDelayVariation> for IsisSubDelayVariation {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, raw) = be_u32(input)?;
        Ok((
            input,
            Self {
                variation: raw & 0x00FF_FFFF,
            },
        ))
    }
}

impl TlvEmitter for IsisSubDelayVariation {
    fn typ(&self) -> u8 {
        IsisNeighCode::DelayVariation.into()
    }
    fn len(&self) -> u8 {
        4
    }
    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u32(self.variation & 0x00FF_FFFF);
    }
}

impl From<IsisSubDelayVariation> for IsisSubTlv {
    fn from(v: IsisSubDelayVariation) -> Self {
        IsisSubTlv::DelayVariation(v)
    }
}

/// RFC 8570 §4.4 — Unidirectional Link Loss (sub-TLV 36).
///
/// 4-octet payload: byte 0 bit 7 = `A` flag, bits 6..0 reserved;
/// bytes 1..3 = 24-bit loss expressed in units of 0.000003 %, so
/// the encoded ceiling 0xFFFFFE represents ~50.331642 %. The
/// reserved value 0xFFFFFF marks the metric as unavailable.
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisSubLinkLoss {
    pub anomalous: bool,
    pub loss: u32,
}

impl ParseBe<IsisSubLinkLoss> for IsisSubLinkLoss {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, raw) = be_u32(input)?;
        Ok((
            input,
            Self {
                anomalous: (raw & 0x8000_0000) != 0,
                loss: raw & 0x00FF_FFFF,
            },
        ))
    }
}

impl TlvEmitter for IsisSubLinkLoss {
    fn typ(&self) -> u8 {
        IsisNeighCode::LinkLoss.into()
    }
    fn len(&self) -> u8 {
        4
    }
    fn emit(&self, buf: &mut BytesMut) {
        let a = if self.anomalous { 0x8000_0000 } else { 0 };
        buf.put_u32(a | (self.loss & 0x00FF_FFFF));
    }
}

impl From<IsisSubLinkLoss> for IsisSubTlv {
    fn from(v: IsisSubLinkLoss) -> Self {
        IsisSubTlv::LinkLoss(v)
    }
}

/// RFC 8570 §4.5–4.7 — Unidirectional bandwidth metrics
/// (Residual, Available, Utilized) share an identical wire shape:
/// a single 32-bit IEEE 754 single-precision value in bytes/sec.
/// No `A` flag, no reserved bits. The three are distinguished by
/// sub-TLV code (37/38/39) and by semantic — see the per-type
/// wrappers below.
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisSubBandwidthMetric {
    /// Bandwidth in bytes-per-second (IEEE 754 single-precision).
    pub bw_bps: f32,
}

impl IsisSubBandwidthMetric {
    fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, raw) = be_u32(input)?;
        Ok((
            input,
            Self {
                bw_bps: f32::from_bits(raw),
            },
        ))
    }
    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u32(self.bw_bps.to_bits());
    }
}

/// RFC 8570 §4.5 — Unidirectional Residual Bandwidth (sub-TLV 37).
/// Maximum bandwidth minus bandwidth currently reserved by RSVP-TE.
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisSubResidualBw {
    pub bw: IsisSubBandwidthMetric,
}

impl ParseBe<IsisSubResidualBw> for IsisSubResidualBw {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, bw) = IsisSubBandwidthMetric::parse(input)?;
        Ok((input, Self { bw }))
    }
}

impl TlvEmitter for IsisSubResidualBw {
    fn typ(&self) -> u8 {
        IsisNeighCode::ResidualBw.into()
    }
    fn len(&self) -> u8 {
        4
    }
    fn emit(&self, buf: &mut BytesMut) {
        self.bw.emit(buf);
    }
}

impl From<IsisSubResidualBw> for IsisSubTlv {
    fn from(v: IsisSubResidualBw) -> Self {
        IsisSubTlv::ResidualBw(v)
    }
}

/// RFC 8570 §4.6 — Unidirectional Available Bandwidth (sub-TLV 38).
/// Residual minus the measured non-RSVP-TE forwarding load.
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisSubAvailableBw {
    pub bw: IsisSubBandwidthMetric,
}

impl ParseBe<IsisSubAvailableBw> for IsisSubAvailableBw {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, bw) = IsisSubBandwidthMetric::parse(input)?;
        Ok((input, Self { bw }))
    }
}

impl TlvEmitter for IsisSubAvailableBw {
    fn typ(&self) -> u8 {
        IsisNeighCode::AvailableBw.into()
    }
    fn len(&self) -> u8 {
        4
    }
    fn emit(&self, buf: &mut BytesMut) {
        self.bw.emit(buf);
    }
}

impl From<IsisSubAvailableBw> for IsisSubTlv {
    fn from(v: IsisSubAvailableBw) -> Self {
        IsisSubTlv::AvailableBw(v)
    }
}

/// RFC 8570 §4.7 — Unidirectional Utilized Bandwidth (sub-TLV 39).
/// Actual link utilization as measured by the advertising node.
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisSubUtilizedBw {
    pub bw: IsisSubBandwidthMetric,
}

impl ParseBe<IsisSubUtilizedBw> for IsisSubUtilizedBw {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, bw) = IsisSubBandwidthMetric::parse(input)?;
        Ok((input, Self { bw }))
    }
}

impl TlvEmitter for IsisSubUtilizedBw {
    fn typ(&self) -> u8 {
        IsisNeighCode::UtilizedBw.into()
    }
    fn len(&self) -> u8 {
        4
    }
    fn emit(&self, buf: &mut BytesMut) {
        self.bw.emit(buf);
    }
}

impl From<IsisSubUtilizedBw> for IsisSubTlv {
    fn from(v: IsisSubUtilizedBw) -> Self {
        IsisSubTlv::UtilizedBw(v)
    }
}

// RFC 9479 IS-IS Application-Specific Link Attributes
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisSubAsla {
    pub l_flag: bool,
    pub sabm: Vec<u8>,
    pub udabm: Vec<u8>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub subs: Vec<IsisSubTlv>,
}

impl ParseBe<IsisSubAsla> for IsisSubAsla {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, first_byte) = be_u8(input)?;
        let l_flag = (first_byte & 0x80) != 0;
        let sabm_len = (first_byte & 0x7F) as usize;
        let (input, udabm_len) = be_u8(input)?;
        let udabm_len = udabm_len as usize;

        // RFC 9479 §4.2: each mask length is the actual octet count of
        // the mask that follows (0-8); zero means the mask is absent,
        // L-flag or not. The parser used to force L=1 masks to >= 1
        // byte "regardless of the length fields", which consumed the
        // first bytes of the nested sub-TLVs as fabricated masks when a
        // peer sent L=1 with zero-length masks — and made our own emit
        // (which writes the actual lengths) unreadable to ourselves.
        // Honor the advertised lengths; reject out-of-range ones so the
        // sub-TLV degrades to Unknown instead of desyncing.
        if sabm_len > 8 || udabm_len > 8 {
            return Err(nom::Err::Error(nom::error::make_error(
                input,
                nom::error::ErrorKind::Verify,
            )));
        }

        let (input, sabm) = take(sabm_len)(input)?;
        let (input, udabm) = take(udabm_len)(input)?;
        let (input, subs) = many0_complete(IsisSubTlv::parse_subs).parse(input)?;

        Ok((
            input,
            Self {
                l_flag,
                sabm: sabm.to_vec(),
                udabm: udabm.to_vec(),
                subs,
            },
        ))
    }
}

impl TlvEmitter for IsisSubAsla {
    fn typ(&self) -> u8 {
        IsisNeighCode::Asla.into()
    }

    fn len(&self) -> u8 {
        let sub_len: usize = self.subs.iter().map(|sub| sub.len() as usize + 2).sum();
        (2 + self.sabm.len() + self.udabm.len() + sub_len).min(255) as u8
    }

    fn emit(&self, buf: &mut BytesMut) {
        let first_byte = if self.l_flag { 0x80 } else { 0 } | (self.sabm.len() as u8 & 0x7F);
        buf.put_u8(first_byte);
        buf.put_u8(self.udabm.len() as u8);
        buf.put(&self.sabm[..]);
        buf.put(&self.udabm[..]);
        for sub in &self.subs {
            sub.emit(buf);
        }
    }
}

impl From<IsisSubAsla> for IsisSubTlv {
    fn from(value: IsisSubAsla) -> Self {
        IsisSubTlv::Asla(value)
    }
}

#[derive(Debug, NomBE, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisSubTeMetric {
    #[nom(Parse = "be_u24")]
    pub metric: u32,
}

impl TlvEmitter for IsisSubTeMetric {
    fn typ(&self) -> u8 {
        IsisNeighCode::TeMetric.into()
    }

    fn len(&self) -> u8 {
        3
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put(&u32_u8_3(self.metric)[..]);
    }
}

impl From<IsisSubTeMetric> for IsisSubTlv {
    fn from(value: IsisSubTeMetric) -> Self {
        IsisSubTlv::TeMetric(value)
    }
}

#[bitfield(u8, debug = true)]
#[derive(PartialEq)]
pub struct AdjSidFlags {
    #[bits(2)]
    pub resvd: u8,
    pub p_flag: bool,
    pub s_flag: bool,
    pub l_flag: bool,
    pub v_flag: bool,
    pub b_flag: bool,
    pub f_flag: bool,
}

impl ParseBe<AdjSidFlags> for AdjSidFlags {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, flags) = be_u8(input)?;
        Ok((input, flags.into()))
    }
}

impl AdjSidFlags {
    pub fn lan_adj_flag_ipv4() -> Self {
        AdjSidFlags::new()
            .with_f_flag(false)
            .with_l_flag(true)
            .with_v_flag(true)
    }

    pub fn lan_adj_flag_ipv6() -> Self {
        AdjSidFlags::new()
            .with_f_flag(true)
            .with_l_flag(true)
            .with_v_flag(true)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisSubAdjSid {
    pub flags: AdjSidFlags,
    pub weight: u8,
    pub sid: SidLabelValue,
}

impl ParseBe<IsisSubAdjSid> for IsisSubAdjSid {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, flags) = AdjSidFlags::parse_be(input)?;
        let (input, weight) = be_u8(input)?;
        // RFC 8667 §2.2.1: the V/L flags decide the SID form — see
        // `SidLabelValue::parse_be_flags`.
        let (input, sid) = SidLabelValue::parse_be_flags(input, flags.v_flag(), flags.l_flag())?;
        Ok((input, Self { flags, weight, sid }))
    }
}

impl TlvEmitter for IsisSubAdjSid {
    fn typ(&self) -> u8 {
        IsisNeighCode::AdjSid.into()
    }

    fn len(&self) -> u8 {
        2 + self.sid.len()
    }

    fn emit(&self, buf: &mut BytesMut) {
        // Derive V/L from the SID form so the emitted flags can never
        // disagree with the width that follows (see IsisSubPrefixSid).
        let flags = match self.sid {
            SidLabelValue::Label(_) => self.flags.with_v_flag(true).with_l_flag(true),
            SidLabelValue::Index(_) => self.flags.with_v_flag(false).with_l_flag(false),
        };
        buf.put_u8(flags.into());
        buf.put_u8(self.weight);
        self.sid.emit(buf);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisSubLanAdjSid {
    pub flags: AdjSidFlags,
    pub weight: u8,
    pub system_id: IsisSysId,
    pub sid: SidLabelValue,
}

impl ParseBe<IsisSubLanAdjSid> for IsisSubLanAdjSid {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, flags) = AdjSidFlags::parse_be(input)?;
        let (input, weight) = be_u8(input)?;
        let (input, system_id) = IsisSysId::parse_be(input)?;
        let (input, sid) = SidLabelValue::parse_be_flags(input, flags.v_flag(), flags.l_flag())?;
        Ok((
            input,
            Self {
                flags,
                weight,
                system_id,
                sid,
            },
        ))
    }
}

impl TlvEmitter for IsisSubLanAdjSid {
    fn typ(&self) -> u8 {
        IsisNeighCode::LanAdjSid.into()
    }

    fn len(&self) -> u8 {
        8 + self.sid.len()
    }

    fn emit(&self, buf: &mut BytesMut) {
        // Derive V/L from the SID form (see IsisSubAdjSid).
        let flags = match self.sid {
            SidLabelValue::Label(_) => self.flags.with_v_flag(true).with_l_flag(true),
            SidLabelValue::Index(_) => self.flags.with_v_flag(false).with_l_flag(false),
        };
        buf.put_u8(flags.into());
        buf.put_u8(self.weight);
        buf.put(&self.system_id.id[..]);
        self.sid.emit(buf);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisSubSrv6EndXSid {
    pub flags: u8,
    pub algo: Algo,
    pub weight: u8,
    pub behavior: Behavior,
    pub sid: Ipv6Addr,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sub2s: Vec<IsisSub2Tlv>,
}

impl ParseBe<IsisSubSrv6EndXSid> for IsisSubSrv6EndXSid {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, flags) = be_u8(input)?;
        let (input, algo) = be_u8(input)?;
        let (input, weight) = be_u8(input)?;
        let (input, behavior) = be_u16(input)?;
        let (input, sid) = Ipv6Addr::parse_be(input)?;
        let (input, sub2_len) = be_u8(input)?;
        let mut sub = Self {
            flags,
            algo: algo.into(),
            weight,
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

impl TlvEmitter for IsisSubSrv6EndXSid {
    fn typ(&self) -> u8 {
        IsisNeighCode::Srv6EndXSid.into()
    }

    fn len(&self) -> u8 {
        // Flags(1)+Algo(1)+Weight(1)+Behavior(2)+Sid(16)+Sub2Len(1)+Sub2
        let len: usize = self.sub2s.iter().map(|sub| sub.len() as usize + 2).sum();
        (1 + 1 + 1 + 2 + 16 + 1 + len).min(255) as u8
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.flags);
        buf.put_u8(self.algo.into());
        buf.put_u8(self.weight);
        buf.put_u16(self.behavior.into());
        buf.put(&self.sid.octets()[..]);
        emit_sub_tlvs(buf, |buf| {
            for sub2 in &self.sub2s {
                sub2.emit(buf);
            }
        });
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisSubSrv6LanEndXSid {
    pub system_id: IsisSysId,
    pub flags: u8,
    pub algo: Algo,
    pub weight: u8,
    pub behavior: Behavior,
    pub sid: Ipv6Addr,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sub2s: Vec<IsisSub2Tlv>,
}

impl ParseBe<IsisSubSrv6LanEndXSid> for IsisSubSrv6LanEndXSid {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, system_id) = IsisSysId::parse_be(input)?;
        let (input, flags) = be_u8(input)?;
        let (input, algo) = be_u8(input)?;
        let (input, weight) = be_u8(input)?;
        let (input, behavior) = be_u16(input)?;
        let (input, sid) = Ipv6Addr::parse_be(input)?;
        let (input, sub2_len) = be_u8(input)?;
        let mut sub = Self {
            system_id,
            flags,
            algo: algo.into(),
            weight,
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

impl TlvEmitter for IsisSubSrv6LanEndXSid {
    fn typ(&self) -> u8 {
        IsisNeighCode::Srv6LanEndXSid.into()
    }

    fn len(&self) -> u8 {
        // SystemID(6)+Flags(1)+Algo(1)+Weight(1)+Behavior(2)+Sid(16)+Sub2Len(1)+Sub2
        let len: usize = self.sub2s.iter().map(|sub| sub.len() as usize + 2).sum();
        (6 + 1 + 1 + 1 + 2 + 16 + 1 + len).min(255) as u8
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put(&self.system_id.id[..]);
        buf.put_u8(self.flags);
        buf.put_u8(self.algo.into());
        buf.put_u8(self.weight);
        buf.put_u16(self.behavior.into());
        buf.put(&self.sid.octets()[..]);
        emit_sub_tlvs(buf, |buf| {
            for sub2 in &self.sub2s {
                sub2.emit(buf);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Follow-up #1 (Adj-SID flavor): the V/L flags are authoritative
    /// for the SID form — a flag/width mismatch degrades to Unknown
    /// instead of misreading an index as a label.
    #[test]
    fn adj_sid_width_follows_v_l_flags() {
        // V|L (0x30) claiming a label but carrying 4 SID octets.
        let raw = [31u8, 6, 0x30, 0, 0, 0, 0, 100];
        let (_, sub) = IsisSubTlv::parse_subs(&raw).expect("parse");
        assert!(matches!(sub, IsisSubTlv::Unknown(_)));

        // The conformant label form round-trips.
        let label = IsisSubAdjSid {
            flags: AdjSidFlags::from(0x30),
            weight: 1,
            sid: SidLabelValue::Label(16001),
        };
        let mut buf = BytesMut::new();
        IsisSubTlv::AdjSid(label.clone()).emit(&mut buf);
        let (rest, parsed) = IsisSubTlv::parse_subs(&buf).expect("re-parse");
        assert!(rest.is_empty());
        assert_eq!(parsed, IsisSubTlv::AdjSid(label));
    }

    /// Finding #14: RFC 9479 §4.2 mask lengths are actual octet counts
    /// (0-8), L-flag or not. The parser used to force L=1 masks to
    /// ≥ 1 byte, consuming the first two bytes of the nested sub-TLVs
    /// as fabricated masks — and making our own emitted L=1/empty-mask
    /// ASLA unreadable to ourselves.
    #[test]
    fn asla_l_flag_with_zero_length_masks_round_trips() {
        let asla = IsisSubAsla {
            l_flag: true,
            sabm: vec![],
            udabm: vec![],
            subs: vec![IsisSubTlv::TeMetric(IsisSubTeMetric { metric: 100 })],
        };
        let mut buf = BytesMut::new();
        asla.tlv_emit(&mut buf);
        // code 16, len 7: first byte 0x80 (L set, SABM len 0), UDABM
        // len 0, then the nested TE metric <18, 3, 0, 0, 100>.
        assert_eq!(&buf[..], &[16, 7, 0x80, 0, 18, 3, 0, 0, 100]);
        let (rest, parsed) = IsisSubTlv::parse_subs(&buf).expect("parse");
        assert!(rest.is_empty());
        let IsisSubTlv::Asla(a) = parsed else {
            panic!("expected Asla");
        };
        assert_eq!(a, asla);
    }

    /// RFC 9479 §4.2 bounds each mask at 8 octets; a longer claim is
    /// rejected so the registry degrades the sub-TLV to Unknown and the
    /// sub-TLVs after it survive.
    #[test]
    fn asla_oversized_mask_length_degrades_to_unknown() {
        // ASLA (code 16) claiming SABM Length 9, then a valid TE metric.
        let raw = [16u8, 2, 0x09, 0, 18, 3, 0, 0, 100];
        let (rest, first) = IsisSubTlv::parse_subs(&raw).expect("first");
        assert!(matches!(first, IsisSubTlv::Unknown(_)));
        let (rest, second) = IsisSubTlv::parse_subs(rest).expect("second");
        assert!(matches!(second, IsisSubTlv::TeMetric(_)));
        assert!(rest.is_empty());
    }

    /// Finding #13: the classic RFC 5305 §3.1 Administrative Group
    /// (sub-TLV 3) had no dispatch arm, so a standards-compliant link
    /// color landed in Unknown and `admin_group()` returned None —
    /// while the accessor actually read the RFC 7308 *Extended* Admin
    /// Group (sub-TLV 14), which BGP-LS maps to a different TLV.
    #[test]
    fn classic_admin_group_subtlv3_dispatches() {
        let raw = [3u8, 4, 0x00, 0x00, 0x00, 0x14];
        let (rest, sub) = IsisSubTlv::parse_subs(&raw).expect("parse");
        assert!(rest.is_empty());
        let IsisSubTlv::AdminGroup(g) = &sub else {
            panic!("expected AdminGroup, got {sub:?}");
        };
        assert_eq!(g.group, 0x14);

        let mut buf = BytesMut::new();
        sub.emit(&mut buf);
        assert_eq!(&buf[..], &raw[..]);

        // The accessors keep the two group flavors distinct.
        let entry = IsisTlvExtIsReachEntry {
            subs: vec![
                IsisSubTlv::AdminGroup(IsisSubAdminGroup { group: 0x14 }),
                IsisSubTlv::AdminGrp(IsisSubAdminGrp {
                    groups: vec![0xAA, 0xBB],
                }),
            ],
            ..Default::default()
        };
        assert_eq!(entry.admin_group(), Some(0x14));
        assert_eq!(entry.ext_admin_group(), Some(&[0xAA, 0xBB][..]));
    }

    fn oversized_entry() -> IsisTlvExtIsReachEntry {
        // 50 IPv4 interface-address sub-TLVs = 50 * (4+2) = 300 bytes,
        // more than the one-octet sub-TLV-length field can express.
        IsisTlvExtIsReachEntry {
            subs: (0..50)
                .map(|_| {
                    IsisSubTlv::Ipv4IfAddr(IsisSubIpv4IfAddr {
                        addr: Ipv4Addr::UNSPECIFIED,
                    })
                })
                .collect(),
            ..Default::default()
        }
    }

    /// The old `sum::<u8>()` in `sub_len` panicked in debug builds
    /// ("attempt to add with overflow") when the packer's wire_len()
    /// probe measured an over-full entry, and wrapped the length in
    /// release; `len()` now saturates at 255.
    #[test]
    fn ext_is_reach_entry_oversized_subs_saturate() {
        assert_eq!(oversized_entry().len(), 255);
    }

    /// Emitting an over-full sub-TLV block is a builder bug — the
    /// emit_sub_tlvs debug assert trips instead of a length byte being
    /// written that disagrees with the bytes emitted.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "sub-TLV block overflows")]
    fn ext_is_reach_entry_oversized_subs_emit_asserts() {
        let mut buf = BytesMut::new();
        oversized_entry().emit(&mut buf);
    }

    /// The back-patched sub-TLV length byte must equal the bytes
    /// actually emitted, and the entry must round-trip.
    #[test]
    fn ext_is_reach_entry_sub_block_backpatch_round_trip() {
        let entry = IsisTlvExtIsReachEntry {
            metric: 10,
            subs: vec![
                IsisSubTlv::Ipv4IfAddr(IsisSubIpv4IfAddr {
                    addr: "10.0.0.1".parse().unwrap(),
                }),
                IsisSubTlv::TeMetric(IsisSubTeMetric { metric: 100 }),
            ],
            ..Default::default()
        };
        let mut buf = BytesMut::new();
        entry.emit(&mut buf);
        // neighbor_id(7) + metric(3) + sublen(1) + subs.
        assert_eq!(buf[10] as usize, buf.len() - 11);
        let (rest, parsed) = IsisTlvExtIsReachEntry::parse_be(&buf).expect("parse");
        assert!(rest.is_empty());
        assert_eq!(parsed, entry);
    }

    #[test]
    fn admin_grp_len_truncates_at_63_groups() {
        let short = IsisSubAdminGrp {
            groups: vec![1, 2, 3],
        };
        assert_eq!(short.len(), 12);

        let exact = IsisSubAdminGrp {
            groups: vec![0u32; 63],
        };
        assert_eq!(exact.len(), 252);

        let long = IsisSubAdminGrp {
            groups: vec![0u32; 100],
        };
        assert_eq!(long.len(), 252);
    }

    #[test]
    fn admin_grp_emit_truncates_at_63_groups() {
        let long = IsisSubAdminGrp {
            groups: vec![0u32; 100],
        };
        let mut buf = BytesMut::new();
        long.emit(&mut buf);
        assert_eq!(buf.len(), 252);
    }

    #[test]
    fn adj_sid_flag_ipv4_baseline_is_l_and_v_only() {
        // RFC 8667 §2.2.1: F=0 (IPv4), L=1 (local), V=1 (label value),
        // B=S=P=0. Bit positions: L=0x10, V=0x20.
        let byte: u8 = AdjSidFlags::lan_adj_flag_ipv4().into();
        assert_eq!(byte, 0x30);
    }

    #[test]
    fn adj_sid_emits_b_flag_when_protected() {
        // TI-LFA on: the B-flag (bit 6, 0x40) layered on top of the
        // V|L baseline yields 0x70 as the first sub-TLV body byte.
        let sub = IsisSubAdjSid {
            flags: AdjSidFlags::lan_adj_flag_ipv4().with_b_flag(true),
            weight: 0,
            sid: SidLabelValue::Label(16001),
        };
        let mut buf = BytesMut::new();
        sub.emit(&mut buf);
        assert_eq!(buf[0], 0x70);
    }

    #[test]
    fn lan_adj_sid_emits_b_flag_when_protected() {
        let sub = IsisSubLanAdjSid {
            flags: AdjSidFlags::lan_adj_flag_ipv4().with_b_flag(true),
            weight: 0,
            system_id: IsisSysId::default(),
            sid: SidLabelValue::Label(16001),
        };
        let mut buf = BytesMut::new();
        sub.emit(&mut buf);
        assert_eq!(buf[0], 0x70);
    }
}
