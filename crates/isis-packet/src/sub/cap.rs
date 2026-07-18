use std::net::Ipv4Addr;

use bitfield_struct::bitfield;
use bytes::{BufMut, BytesMut};
use nom::IResult;
use nom::number::complete::{be_u8, be_u16, be_u24, be_u32};
use nom_derive::*;
use packet_utils::{Algo, SidLabelTlv, parse_sid_label};
use serde::{Deserialize, Serialize};

use crate::util::{ParseBe, TlvEmitter, u32_u8_3};
use crate::{IsisTlv, IsisTlvType, many0_complete};

use super::{IsisCapCode, IsisSubTlvUnknown};

impl_parse_subs!(IsisSubTlv, FadSubTlv);

#[derive(Debug, NomBE, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[nom(Selector = "IsisCapCode")]
pub enum IsisSubTlv {
    #[nom(Selector = "IsisCapCode::SegmentRoutingCap")]
    SegmentRoutingCap(IsisSubSegmentRoutingCap),
    #[nom(Selector = "IsisCapCode::SegmentRoutingAlgo")]
    SegmentRoutingAlgo(IsisSubSegmentRoutingAlgo),
    #[nom(Selector = "IsisCapCode::SegmentRoutingLb")]
    SegmentRoutingLB(IsisSubSegmentRoutingLB),
    #[nom(Selector = "IsisCapCode::NodeMaxSidDepth")]
    NodeMaxSidDepth(IsisSubNodeMaxSidDepth),
    #[nom(Selector = "IsisCapCode::Srv6")]
    Srv6(IsisSubSrv6),
    #[nom(Selector = "IsisCapCode::FlexAlgoDef")]
    FlexAlgoDef(IsisSubFlexAlgoDef),
    #[nom(Selector = "_")]
    Unknown(IsisSubTlvUnknown),
}

impl IsisSubTlv {
    pub fn len(&self) -> u8 {
        use IsisSubTlv::*;
        match self {
            SegmentRoutingCap(v) => v.len(),
            SegmentRoutingAlgo(v) => v.len(),
            SegmentRoutingLB(v) => v.len(),
            NodeMaxSidDepth(v) => v.len(),
            Srv6(v) => v.len(),
            FlexAlgoDef(v) => v.len(),
            Unknown(v) => v.len,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        use IsisSubTlv::*;
        match self {
            SegmentRoutingCap(v) => v.tlv_emit(buf),
            SegmentRoutingAlgo(v) => v.tlv_emit(buf),
            SegmentRoutingLB(v) => v.tlv_emit(buf),
            NodeMaxSidDepth(v) => v.tlv_emit(buf),
            Srv6(v) => v.tlv_emit(buf),
            FlexAlgoDef(v) => v.tlv_emit(buf),
            Unknown(v) => v.tlv_emit(buf),
        }
    }
}

#[bitfield(u8, debug = true)]
#[derive(PartialEq)]
pub struct SegmentRoutingCapFlags {
    #[bits(6)]
    pub resvd: u8,
    pub v_flag: bool,
    pub i_flag: bool,
}

impl ParseBe<SegmentRoutingCapFlags> for SegmentRoutingCapFlags {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, flags) = be_u8(input)?;
        Ok((input, flags.into()))
    }
}

#[derive(Debug, NomBE, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisSubSegmentRoutingCap {
    pub flags: SegmentRoutingCapFlags,
    #[nom(Parse = "be_u24")]
    pub range: u32,
    #[nom(Parse = "parse_sid_label")]
    pub sid_label: SidLabelTlv,
}

impl TlvEmitter for IsisSubSegmentRoutingCap {
    fn typ(&self) -> u8 {
        IsisCapCode::SegmentRoutingCap.into()
    }

    fn len(&self) -> u8 {
        // Flags: 1 + Range: 3 + SID Type:1 + SID Length: 1 + SID.
        1 + 3 + 1 + 1 + self.sid_label.len()
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.flags.into());
        // Range is a 24-bit wire field: saturate instead of letting
        // u32_u8_3 silently drop the high bits of an over-large range.
        buf.put(&u32_u8_3(self.range.min(0x00FF_FFFF))[..]);
        self.sid_label.emit(buf);
    }
}

impl From<IsisSubSegmentRoutingCap> for IsisSubTlv {
    fn from(sub: IsisSubSegmentRoutingCap) -> Self {
        IsisSubTlv::SegmentRoutingCap(sub)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisSubSegmentRoutingAlgo {
    pub algo: Vec<Algo>,
}

impl ParseBe<IsisSubSegmentRoutingAlgo> for IsisSubSegmentRoutingAlgo {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, algo) = many0_complete(Algo::parse_be).parse(input)?;
        Ok((input, Self { algo }))
    }
}

impl TlvEmitter for IsisSubSegmentRoutingAlgo {
    fn typ(&self) -> u8 {
        IsisCapCode::SegmentRoutingAlgo.into()
    }

    fn len(&self) -> u8 {
        self.algo.len().min(255) as u8
    }

    fn emit(&self, buf: &mut BytesMut) {
        for algo in self.algo.iter().take(255) {
            buf.put_u8((*algo).into());
        }
    }
}

impl From<IsisSubSegmentRoutingAlgo> for IsisSubTlv {
    fn from(sub: IsisSubSegmentRoutingAlgo) -> Self {
        IsisSubTlv::SegmentRoutingAlgo(sub)
    }
}

#[derive(Debug, NomBE, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisSubSegmentRoutingLB {
    pub flags: u8,
    #[nom(Parse = "be_u24")]
    pub range: u32,
    #[nom(Parse = "parse_sid_label")]
    pub sid_label: SidLabelTlv,
}

impl TlvEmitter for IsisSubSegmentRoutingLB {
    fn typ(&self) -> u8 {
        IsisCapCode::SegmentRoutingLb.into()
    }

    fn len(&self) -> u8 {
        // Flags: 1 + Range: 3 + SID Type:1 + SID Length: 1 + SID.
        1 + 3 + 1 + 1 + self.sid_label.len()
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.flags);
        // See IsisSubSegmentRoutingCap — saturate the 24-bit range.
        buf.put(&u32_u8_3(self.range.min(0x00FF_FFFF))[..]);
        self.sid_label.emit(buf);
    }
}

impl From<IsisSubSegmentRoutingLB> for IsisSubTlv {
    fn from(sub: IsisSubSegmentRoutingLB) -> Self {
        IsisSubTlv::SegmentRoutingLB(sub)
    }
}

#[derive(Debug, NomBE, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisSubNodeMaxSidDepth {
    pub flags: u8,
    pub depth: u8,
}

impl TlvEmitter for IsisSubNodeMaxSidDepth {
    fn typ(&self) -> u8 {
        IsisCapCode::NodeMaxSidDepth.into()
    }

    fn len(&self) -> u8 {
        2
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.flags);
        buf.put_u8(self.depth);
    }
}

// RFC 7981 §2 flags octet:
//   0 1 2 3 4 5 6 7
//  +-+-+-+-+-+-+-+-+
//  | Reserved  |D|S|
//  +-+-+-+-+-+-+-+-+
// IETF bit 7 is the least-significant bit, so S = 0x01 and D = 0x02
// (FRR: ISIS_ROUTER_CAP_FLAG_S/_D). `bitfield(u8)` is LSB-first —
// declare S first to land at bit 0, then D, then the 6 reserved MSBs.
#[bitfield(u8, debug = true)]
#[derive(PartialEq)]
pub struct RouterCapFlags {
    pub s_flag: bool,
    pub d_flag: bool,
    #[bits(6)]
    pub resvd: u8,
}

impl ParseBe<RouterCapFlags> for RouterCapFlags {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, flags) = be_u8(input)?;
        Ok((input, flags.into()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisTlvRouterCap {
    pub router_id: Ipv4Addr,
    pub flags: RouterCapFlags,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub subs: Vec<IsisSubTlv>,
}

impl ParseBe<IsisTlvRouterCap> for IsisTlvRouterCap {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, router_id) = Ipv4Addr::parse_be(input)?;
        let (input, flags) = be_u8(input)?;
        let (input, subs) = many0_complete(IsisSubTlv::parse_subs).parse(input)?;
        let tlv = Self {
            router_id,
            flags: flags.into(),
            subs,
        };
        Ok((input, tlv))
    }
}

impl IsisTlvRouterCap {
    fn sub_len(&self) -> usize {
        self.subs.iter().map(|sub| sub.len() as usize + 2).sum()
    }

    /// True value length in bytes, unsaturated (the u8 `len()`
    /// saturates at 255) — used by `IsisTlv::wire_len`.
    pub fn value_wire_len(&self) -> usize {
        5 + self.sub_len()
    }
}

impl TlvEmitter for IsisTlvRouterCap {
    fn typ(&self) -> u8 {
        IsisTlvType::RouterCap.into()
    }

    fn len(&self) -> u8 {
        (5 + self.sub_len()).min(255) as u8
    }

    fn emit(&self, buf: &mut bytes::BytesMut) {
        buf.put(&self.router_id.octets()[..]);
        buf.put_u8(self.flags.into());
        self.subs.iter().for_each(|sub| sub.emit(buf));
    }
}

impl From<IsisTlvRouterCap> for IsisTlv {
    fn from(tlv: IsisTlvRouterCap) -> Self {
        IsisTlv::RouterCap(tlv)
    }
}

#[bitfield(u16, debug = true)]
#[derive(PartialEq)]
pub struct Srv6Flags {
    #[bits(14)]
    pub resvd2: u16,
    pub o_flag: bool,
    pub resvd1: bool,
}

impl ParseBe<Srv6Flags> for Srv6Flags {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, flags) = be_u16(input)?;
        Ok((input, flags.into()))
    }
}

#[derive(Debug, Default, NomBE, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisSubSrv6 {
    pub flags: Srv6Flags,
}

impl TlvEmitter for IsisSubSrv6 {
    fn typ(&self) -> u8 {
        IsisCapCode::Srv6.into()
    }

    fn len(&self) -> u8 {
        2
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u16(self.flags.into());
    }
}

impl From<IsisSubSrv6> for IsisSubTlv {
    fn from(sub: IsisSubSrv6) -> Self {
        IsisSubTlv::Srv6(sub)
    }
}

// ─────────────────────────────────────────────────────────────────────
// RFC 9350 — Flex-Algorithm Definition (FAD) sub-TLV (type 26) and
// its nested sub-TLVs. The FAD lives inside Router Capability TLV 242
// and carries one algorithm's definition: ID + metric type + calc type
// + priority + a set of constraint sub-TLVs (admin-group include /
// exclude, exclude-SRLG, flags). The FAD itself is originated by one
// (or two, for redundancy) routers per area; every participant uses
// it as the recipe for SPF on the matching algorithm.
// ─────────────────────────────────────────────────────────────────────

/// Sub-TLV type codes that may appear inside a FAD body (RFC 9350
/// §5.1). These live in a FAD-local namespace, distinct from the
/// `IsisCapCode` space the FAD itself lives in.
#[repr(u8)]
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub enum FadSubCode {
    #[default]
    ExcludeAg = 1, // RFC 9350 §6.1
    IncludeAnyAg = 2, // RFC 9350 §6.1
    IncludeAllAg = 3, // RFC 9350 §6.1
    Flags = 4,        // RFC 9350 §6.4 (M-flag for prefix metric)
    ExcludeSrlg = 5,  // RFC 9350 §6.2
    Unknown(u8),
}

impl From<FadSubCode> for u8 {
    fn from(typ: FadSubCode) -> Self {
        use FadSubCode::*;
        match typ {
            ExcludeAg => 1,
            IncludeAnyAg => 2,
            IncludeAllAg => 3,
            Flags => 4,
            ExcludeSrlg => 5,
            Unknown(v) => v,
        }
    }
}

impl From<u8> for FadSubCode {
    fn from(typ: u8) -> Self {
        use FadSubCode::*;
        match typ {
            1 => ExcludeAg,
            2 => IncludeAnyAg,
            3 => IncludeAllAg,
            4 => Flags,
            5 => ExcludeSrlg,
            v => Unknown(v),
        }
    }
}

impl FadSubCode {
    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, typ) = be_u8(input)?;
        Ok((input, typ.into()))
    }
}

/// Extended Admin Group bitmap payload (RFC 7308). Defined in
/// `packet-utils` and re-exported here so IS-IS callers keep using
/// `isis_packet::ExtAdminGroup`; OSPF shares the same type.
pub use packet_utils::ExtAdminGroup;

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisSubFadExcludeAg {
    pub group: ExtAdminGroup,
}

impl ParseBe<IsisSubFadExcludeAg> for IsisSubFadExcludeAg {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, group) = ExtAdminGroup::parse_be(input)?;
        Ok((input, Self { group }))
    }
}

impl TlvEmitter for IsisSubFadExcludeAg {
    fn typ(&self) -> u8 {
        FadSubCode::ExcludeAg.into()
    }
    fn len(&self) -> u8 {
        self.group.byte_len().min(255) as u8
    }
    fn emit(&self, buf: &mut BytesMut) {
        self.group.emit(buf);
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisSubFadIncludeAnyAg {
    pub group: ExtAdminGroup,
}

impl ParseBe<IsisSubFadIncludeAnyAg> for IsisSubFadIncludeAnyAg {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, group) = ExtAdminGroup::parse_be(input)?;
        Ok((input, Self { group }))
    }
}

impl TlvEmitter for IsisSubFadIncludeAnyAg {
    fn typ(&self) -> u8 {
        FadSubCode::IncludeAnyAg.into()
    }
    fn len(&self) -> u8 {
        self.group.byte_len().min(255) as u8
    }
    fn emit(&self, buf: &mut BytesMut) {
        self.group.emit(buf);
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisSubFadIncludeAllAg {
    pub group: ExtAdminGroup,
}

impl ParseBe<IsisSubFadIncludeAllAg> for IsisSubFadIncludeAllAg {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, group) = ExtAdminGroup::parse_be(input)?;
        Ok((input, Self { group }))
    }
}

impl TlvEmitter for IsisSubFadIncludeAllAg {
    fn typ(&self) -> u8 {
        FadSubCode::IncludeAllAg.into()
    }
    fn len(&self) -> u8 {
        self.group.byte_len().min(255) as u8
    }
    fn emit(&self, buf: &mut BytesMut) {
        self.group.emit(buf);
    }
}

/// FAD Flags sub-TLV (RFC 9350 §6.4). One byte minimum; only the
/// M-flag (bit 0 of byte 0, "Prefix Metric") is currently defined.
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisSubFadFlags {
    pub m_flag: bool,
    /// Trailing bytes preserved on parse to round-trip flags defined
    /// after this codec was written.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub trailing: Vec<u8>,
}

impl ParseBe<IsisSubFadFlags> for IsisSubFadFlags {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, first) = be_u8(input)?;
        // RFC 9350 §6.4: M-flag is the MSB of byte 0 (bit position 7
        // when bit 0 is LSB).
        let m_flag = (first & 0x80) != 0;
        let trailing = input.to_vec();
        Ok((&[], Self { m_flag, trailing }))
    }
}

impl TlvEmitter for IsisSubFadFlags {
    fn typ(&self) -> u8 {
        FadSubCode::Flags.into()
    }
    fn len(&self) -> u8 {
        (1 + self.trailing.len()).min(255) as u8
    }
    fn emit(&self, buf: &mut BytesMut) {
        let first: u8 = if self.m_flag { 0x80 } else { 0x00 };
        buf.put_u8(first);
        buf.put_slice(&self.trailing);
    }
}

/// FAD Exclude SRLG sub-TLV (RFC 9350 §6.2). Carries an ordered list
/// of 32-bit SRLG identifiers; any link whose advertised SRLG set
/// intersects this list is excluded from the algorithm's SPF.
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisSubFadExcludeSrlg {
    pub srlgs: Vec<u32>,
}

impl ParseBe<IsisSubFadExcludeSrlg> for IsisSubFadExcludeSrlg {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, srlgs) = many0_complete(be_u32).parse(input)?;
        Ok((input, Self { srlgs }))
    }
}

impl TlvEmitter for IsisSubFadExcludeSrlg {
    fn typ(&self) -> u8 {
        FadSubCode::ExcludeSrlg.into()
    }
    fn len(&self) -> u8 {
        (self.srlgs.len().min(63) * 4) as u8
    }
    fn emit(&self, buf: &mut BytesMut) {
        for s in self.srlgs.iter().take(63) {
            buf.put_u32(*s);
        }
    }
}

/// Nested sub-TLV under a FAD. Dispatched by `FadSubCode` per
/// RFC 9350 §5.1.
#[derive(Debug, NomBE, Clone, Serialize, Deserialize, PartialEq)]
#[nom(Selector = "FadSubCode")]
pub enum FadSubTlv {
    #[nom(Selector = "FadSubCode::ExcludeAg")]
    ExcludeAg(IsisSubFadExcludeAg),
    #[nom(Selector = "FadSubCode::IncludeAnyAg")]
    IncludeAnyAg(IsisSubFadIncludeAnyAg),
    #[nom(Selector = "FadSubCode::IncludeAllAg")]
    IncludeAllAg(IsisSubFadIncludeAllAg),
    #[nom(Selector = "FadSubCode::Flags")]
    Flags(IsisSubFadFlags),
    #[nom(Selector = "FadSubCode::ExcludeSrlg")]
    ExcludeSrlg(IsisSubFadExcludeSrlg),
    #[nom(Selector = "_")]
    Unknown(IsisSubTlvUnknown),
}

impl FadSubTlv {
    pub fn len(&self) -> u8 {
        use FadSubTlv::*;
        match self {
            ExcludeAg(v) => v.len(),
            IncludeAnyAg(v) => v.len(),
            IncludeAllAg(v) => v.len(),
            Flags(v) => v.len(),
            ExcludeSrlg(v) => v.len(),
            Unknown(v) => v.len,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        use FadSubTlv::*;
        match self {
            ExcludeAg(v) => v.tlv_emit(buf),
            IncludeAnyAg(v) => v.tlv_emit(buf),
            IncludeAllAg(v) => v.tlv_emit(buf),
            Flags(v) => v.tlv_emit(buf),
            ExcludeSrlg(v) => v.tlv_emit(buf),
            Unknown(v) => v.tlv_emit(buf),
        }
    }
}

/// Flex-Algorithm Definition sub-TLV (RFC 9350 §5.1, IsisCapCode = 26).
///
/// Fixed header layout:
/// ```text
///   0                   1                   2                   3
///   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |  Flex-Algo    |  Metric-Type  |  Calc-Type    |   Priority    |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  //                       Sub-TLVs                              //
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IsisSubFlexAlgoDef {
    /// Algorithm identifier, 128..=255 per RFC 9350 §4.
    pub flex_algorithm: u8,
    /// Metric-Type per RFC 9350 §5.1 IANA registry
    /// (0=IGP, 1=Min Unidir Link Delay, 2=TE Default).
    pub metric_type: u8,
    /// Calc-Type. Only 0 (SPF) is currently defined (RFC 9350 §5.1).
    pub calc_type: u8,
    /// Tie-breaker priority when multiple routers originate a FAD for
    /// the same Flex-Algorithm. Higher wins; ties resolved by router
    /// system ID (RFC 9350 §5.2).
    pub priority: u8,
    /// Nested FAD constraint sub-TLVs (admin-group include/exclude,
    /// flags, exclude-SRLG).
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub subs: Vec<FadSubTlv>,
}

impl ParseBe<IsisSubFlexAlgoDef> for IsisSubFlexAlgoDef {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, flex_algorithm) = be_u8(input)?;
        let (input, metric_type) = be_u8(input)?;
        let (input, calc_type) = be_u8(input)?;
        let (input, priority) = be_u8(input)?;
        let (input, subs) = many0_complete(FadSubTlv::parse_subs).parse(input)?;
        Ok((
            input,
            Self {
                flex_algorithm,
                metric_type,
                calc_type,
                priority,
                subs,
            },
        ))
    }
}

impl IsisSubFlexAlgoDef {
    fn sub_len(&self) -> usize {
        // 2 bytes (type + length) per nested sub-TLV header.
        self.subs.iter().map(|s| 2 + s.len() as usize).sum()
    }
}

impl TlvEmitter for IsisSubFlexAlgoDef {
    fn typ(&self) -> u8 {
        IsisCapCode::FlexAlgoDef.into()
    }

    fn len(&self) -> u8 {
        (4 + self.sub_len()).min(255) as u8
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.flex_algorithm);
        buf.put_u8(self.metric_type);
        buf.put_u8(self.calc_type);
        buf.put_u8(self.priority);
        for s in &self.subs {
            s.emit(buf);
        }
    }
}

impl From<IsisSubFlexAlgoDef> for IsisSubTlv {
    fn from(sub: IsisSubFlexAlgoDef) -> Self {
        IsisSubTlv::FlexAlgoDef(sub)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn router_cap_flags_s_and_d_bit_positions() {
        // RFC 7981 §2: S (flood entire domain) = 0x01, D (down) = 0x02,
        // reserved bits in the six MSBs.
        let s_only = RouterCapFlags::from(0x01);
        assert!(s_only.s_flag());
        assert!(!s_only.d_flag());
        assert_eq!(s_only.resvd(), 0);

        let d_only = RouterCapFlags::from(0x02);
        assert!(d_only.d_flag());
        assert!(!d_only.s_flag());
        assert_eq!(d_only.resvd(), 0);

        let emitted: u8 = RouterCapFlags::new().with_s_flag(true).into();
        assert_eq!(emitted, 0x01);
        let emitted: u8 = RouterCapFlags::new().with_d_flag(true).into();
        assert_eq!(emitted, 0x02);
    }

    /// Follow-up #3: the SRGB/SRLB range is a 24-bit wire field — an
    /// over-large u32 saturates instead of wrapping to garbage.
    #[test]
    fn srgb_range_saturates_at_24_bits() {
        let cap = IsisSubSegmentRoutingCap {
            flags: SegmentRoutingCapFlags::from(0),
            range: 0x0100_0001, // 2^24 + 1 would wrap to 1
            sid_label: SidLabelTlv::Label(16000),
        };
        let mut buf = BytesMut::new();
        cap.emit(&mut buf);
        // Flags(1), then the saturated 24-bit range.
        assert_eq!(&buf[1..4], &[0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn sr_algo_len_truncates_at_255() {
        let short = IsisSubSegmentRoutingAlgo {
            algo: vec![Algo::Spf, Algo::StrictSpf],
        };
        assert_eq!(short.len(), 2);

        let exact = IsisSubSegmentRoutingAlgo {
            algo: vec![Algo::Spf; 255],
        };
        assert_eq!(exact.len(), 255);

        let long = IsisSubSegmentRoutingAlgo {
            algo: vec![Algo::Spf; 300],
        };
        assert_eq!(long.len(), 255);
    }

    #[test]
    fn sr_algo_emit_truncates_at_255() {
        let long = IsisSubSegmentRoutingAlgo {
            algo: vec![Algo::Spf; 300],
        };
        let mut buf = BytesMut::new();
        long.emit(&mut buf);
        assert_eq!(buf.len(), 255);
    }

    #[test]
    fn ext_admin_group_set_grows_and_round_trips() {
        let mut g = ExtAdminGroup::default();
        g.set(0);
        g.set(31);
        g.set(32);
        g.set(255);
        assert!(g.get(0) && g.get(31) && g.get(32) && g.get(255));
        assert!(!g.get(1) && !g.get(254));
        // bit 255 lives in word 7 (zero-indexed), so we expect 8 words.
        assert_eq!(g.words.len(), 8);
        assert_eq!(g.byte_len(), 32);
    }

    fn round_trip_fad(fad: IsisSubFlexAlgoDef) -> IsisSubFlexAlgoDef {
        let mut buf = BytesMut::new();
        fad.emit(&mut buf);
        let (rest, parsed) = IsisSubFlexAlgoDef::parse_be(&buf).expect("parse");
        assert!(rest.is_empty(), "leftover bytes: {rest:?}");
        parsed
    }

    #[test]
    fn fad_header_only_round_trip() {
        let fad = IsisSubFlexAlgoDef {
            flex_algorithm: 128,
            metric_type: 1, // min-unidir-link-delay
            calc_type: 0,   // SPF
            priority: 200,
            subs: vec![],
        };
        let parsed = round_trip_fad(fad.clone());
        assert_eq!(parsed, fad);
        // 4 header bytes only.
        let mut buf = BytesMut::new();
        fad.emit(&mut buf);
        assert_eq!(buf.len(), 4);
    }

    #[test]
    fn fad_with_exclude_and_flags_round_trips() {
        let mut excl = ExtAdminGroup::default();
        excl.set(0); // "blue"
        let fad = IsisSubFlexAlgoDef {
            flex_algorithm: 129,
            metric_type: 0,
            calc_type: 0,
            priority: 128,
            subs: vec![
                FadSubTlv::ExcludeAg(IsisSubFadExcludeAg { group: excl }),
                FadSubTlv::Flags(IsisSubFadFlags {
                    m_flag: true,
                    trailing: vec![],
                }),
                FadSubTlv::ExcludeSrlg(IsisSubFadExcludeSrlg {
                    srlgs: vec![100, 200],
                }),
            ],
        };
        let parsed = round_trip_fad(fad.clone());
        assert_eq!(parsed, fad);
    }

    #[test]
    fn fad_unknown_sub_preserved_on_round_trip() {
        // Inject an unknown FAD sub-TLV (type 99) by hand-crafting the bytes
        // and parsing them; the result must include an Unknown variant whose
        // re-emission reproduces the original bytes.
        let bytes: &[u8] = &[
            128, // flex-algorithm
            0,   // metric-type
            0,   // calc-type
            128, // priority
            99,  // unknown sub-tlv type
            3,   // length
            0xDE, 0xAD, 0xBE,
        ];
        let (rest, fad) = IsisSubFlexAlgoDef::parse_be(bytes).expect("parse");
        assert!(rest.is_empty());
        assert_eq!(fad.subs.len(), 1);
        match &fad.subs[0] {
            FadSubTlv::Unknown(u) => {
                assert_eq!(u.code, 99);
                assert_eq!(u.len, 3);
            }
            _ => panic!("expected Unknown FAD sub-TLV"),
        }
        let mut buf = BytesMut::new();
        fad.emit(&mut buf);
        assert_eq!(&buf[..], bytes);
    }

    #[test]
    fn router_cap_dispatches_fad_variant() {
        // Build a Router Capability TLV containing a FAD and round-trip
        // through the IsisSubTlv codec used by lsp_generate.
        let fad = IsisSubFlexAlgoDef {
            flex_algorithm: 128,
            metric_type: 1,
            calc_type: 0,
            priority: 128,
            subs: vec![],
        };
        let cap = IsisTlvRouterCap {
            router_id: Ipv4Addr::new(1, 1, 1, 1),
            flags: 0u8.into(),
            subs: vec![fad.into()],
        };
        // Serialize Router Capability body + parse it back.
        let mut buf = BytesMut::new();
        cap.emit(&mut buf);
        let (rest, parsed) = IsisTlvRouterCap::parse_be(&buf).expect("parse");
        assert!(rest.is_empty());
        assert_eq!(parsed.subs.len(), 1);
        match &parsed.subs[0] {
            IsisSubTlv::FlexAlgoDef(p) => assert_eq!(p.flex_algorithm, 128),
            other => panic!("expected FlexAlgoDef variant, got {other:?}"),
        }
    }
}
