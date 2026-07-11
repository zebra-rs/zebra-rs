use std::fmt;
use std::net::Ipv6Addr;

use bytes::{BufMut, BytesMut};
use nom::IResult;
use nom::number::complete::{be_u8, be_u16, be_u32};

use crate::{AttrType, ParseBe};

use super::{AttrEmitter, AttrFlags};

/// SRv6 Endpoint Behavior codepoints (IANA "SRv6 Endpoint Behaviors",
/// RFC 8986). The L3VPN decap behaviors plus the L2 behaviors used by
/// EVPN-over-SRv6: VPWS cross-connect (`End.DX2`/`End.DX2V`, RFC 9252
/// §6.3 on Type-1), unicast bridging (`End.DT2U`, §6.1/§6.2 on Type-2)
/// and multicast/BUM (`End.DT2M`, §6.4 on Type-3).
pub const SRV6_BEHAVIOR_END_DT6: u16 = 0x0012;
pub const SRV6_BEHAVIOR_END_DT4: u16 = 0x0013;
pub const SRV6_BEHAVIOR_END_DT46: u16 = 0x0014;
pub const SRV6_BEHAVIOR_END_DX2: u16 = 0x0015;
pub const SRV6_BEHAVIOR_END_DX2V: u16 = 0x0016;
pub const SRV6_BEHAVIOR_END_DT2U: u16 = 0x0017;
pub const SRV6_BEHAVIOR_END_DT2M: u16 = 0x0018;

/// Pick the SRv6 L3 Service SID a destination of the given address
/// family should be steered into, from a route's `(SID, behavior)`
/// pairs in wire order (`BgpAttr::srv6_l3_sids`). An originator may
/// advertise a split `End.DT4` + `End.DT6` pair instead of one
/// `End.DT46`, so taking the first SID can encapsulate traffic toward
/// a decap behavior of the wrong family (an `End.DT4` drops IPv6).
/// Preference: the exact per-family decap behavior (`End.DT4` for v4,
/// `End.DT6` for v6), then `End.DT46`. `None` when the SIDs carry
/// known L3-decap behaviors but none is family-compatible — the route
/// cannot service this destination. When no SID carries a known
/// L3-decap behavior at all (unmodeled codepoints), fall back to the
/// first SID rather than second-guessing semantics we don't know.
pub fn srv6_l3_sid_for_dest(sids: &[(Ipv6Addr, u16)], dest_v4: bool) -> Option<(Ipv6Addr, u16)> {
    let exact = if dest_v4 {
        SRV6_BEHAVIOR_END_DT4
    } else {
        SRV6_BEHAVIOR_END_DT6
    };
    if let Some(hit) = sids.iter().find(|(_, b)| *b == exact) {
        return Some(*hit);
    }
    if let Some(hit) = sids.iter().find(|(_, b)| *b == SRV6_BEHAVIOR_END_DT46) {
        return Some(*hit);
    }
    const L3_DECAP: [u16; 3] = [
        SRV6_BEHAVIOR_END_DT4,
        SRV6_BEHAVIOR_END_DT6,
        SRV6_BEHAVIOR_END_DT46,
    ];
    if sids.iter().any(|(_, b)| L3_DECAP.contains(b)) {
        return None;
    }
    sids.first().copied()
}

/// BGP Prefix-SID TLV Types (IANA "BGP Prefix-SID TLV Types", RFC 8669 /
/// RFC 9252 §8.1).
const PREFIX_SID_TLV_LABEL_INDEX: u8 = 1;
const PREFIX_SID_TLV_ORIGINATOR_SRGB: u8 = 3;
const PREFIX_SID_TLV_SRV6_L3_SERVICE: u8 = 5;
const PREFIX_SID_TLV_SRV6_L2_SERVICE: u8 = 6;

/// SRv6 Service Sub-TLV Type for the SID Information sub-TLV (RFC 9252
/// §3.1 / §8.2).
const SRV6_SUBTLV_SID_INFO: u8 = 1;
/// SRv6 Service Data Sub-Sub-TLV Type for the SID Structure sub-sub-TLV
/// (RFC 9252 §3.2.1 / §8.3).
const SRV6_SUBSUBTLV_SID_STRUCTURE: u8 = 1;
/// Minimum SID Information sub-TLV Value length: RESERVED1(1) + SID(16) +
/// Flags(1) + Behavior(2) + RESERVED2(1). RFC 9252 §7 deems the sub-TLV
/// malformed below this.
const SRV6_SID_INFO_MIN_LEN: usize = 21;
/// Fixed Value length of the SID Structure sub-sub-TLV (RFC 9252 §3.2.1).
const SRV6_SID_STRUCTURE_LEN: usize = 6;

/// BGP Prefix-SID path attribute (type 40, RFC 8669) plus SRv6 service
/// extensions (RFC 9252).
///
/// The attribute carries an ordered list of TLVs. We decode the
/// well-known ones (Label-Index, Originator-SRGB) into structured
/// variants; SRv6 L3/L2 service TLVs and any future codepoints are
/// preserved as opaque bytes so the round-trip stays bit-exact while
/// the SRv6 services layer is built out in a later PR.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct PrefixSid {
    pub tlvs: Vec<PrefixSidTlv>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PrefixSidTlv {
    /// RFC 8669 §3.1 Label-Index TLV. Wire layout:
    /// `reserved(1) | flags(2) | label_index(4)`. Carries the index
    /// the originator assigns to the prefix within its SRGB; receivers
    /// derive the local label as `local_srgb.base + label_index`.
    LabelIndex { flags: u16, label_index: u32 },

    /// RFC 8669 §3.2 Originator SRGB TLV. Wire layout: `flags(2) |
    /// SRGB[0..N]`. Each SRGB entry is `base(3) | range(3)` (24-bit
    /// values stored in the low bits of `u32`). Used by receivers to
    /// resolve a Label-Index against the originator's label block.
    OriginatorSrgb { flags: u16, srgbs: Vec<SrgbRange> },

    /// RFC 9252 §2 SRv6 L3 Service TLV — carries the per-prefix /
    /// per-VRF SRv6 SID(s) for L3 services (L3VPN, 6PE). Decoded into
    /// the SID Information sub-TLVs; unknown sub-/sub-sub-TLVs are not
    /// preserved (we re-emit in canonical form).
    Srv6L3Service(Srv6ServiceTlv),

    /// RFC 9252 §2 SRv6 L2 Service TLV — same shape, used for EVPN.
    Srv6L2Service(Srv6ServiceTlv),

    /// Unknown TLV type — preserved verbatim so a router that doesn't
    /// understand a new IANA codepoint can still propagate the
    /// attribute byte-for-byte.
    Unknown { typ: u8, value: Vec<u8> },
}

/// An SRv6 Service TLV body (RFC 9252 §2): a leading RESERVED octet then
/// an unordered list of SRv6 Service sub-TLVs. The L3VPN case carries
/// exactly one SID Information sub-TLV.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct Srv6ServiceTlv {
    /// Leading RESERVED octet (RFC 9252 §2). A sender MUST set it to 0; a
    /// receiver MUST ignore it but MUST propagate it unchanged, so we
    /// keep the received value rather than forcing 0 on re-emit.
    pub reserved: u8,
    /// SRv6 SID Information sub-TLVs (type 1), in receive order.
    pub sids: Vec<Srv6SidInfo>,
    /// Sub-TLVs whose Type we don't model, preserved verbatim. RFC 9252
    /// §2 requires unrecognized sub-TLVs to be propagated further when
    /// the BGP next hop is unchanged. They are re-emitted after the
    /// modelled SID sub-TLVs — the list is unordered per §2, so this is
    /// conformant.
    pub unknown_sub_tlvs: Vec<RawSubTlv>,
}

/// A TLV-encoded element (an SRv6 Service sub-TLV or sub-sub-TLV) whose
/// Type this implementation does not model. `value` excludes the
/// 3-octet `type(1) | length(2)` header. Preserved so the attribute can
/// be re-emitted unchanged when propagated with the next hop unchanged
/// (RFC 9252 §2).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RawSubTlv {
    pub typ: u8,
    pub value: Vec<u8>,
}

/// SRv6 SID Information Sub-TLV (RFC 9252 §3.1).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Srv6SidInfo {
    /// RESERVED1 (RFC 9252 §3.1). MUST be 0 on origination; preserved
    /// verbatim on receive for propagation.
    pub reserved1: u8,
    /// The 16-byte SRv6 SID value (e.g. an End.DT46 SID).
    pub sid: Ipv6Addr,
    /// SRv6 Service SID Flags.
    pub flags: u8,
    /// SRv6 Endpoint Behavior (one of the `SRV6_BEHAVIOR_*` codepoints).
    pub behavior: u16,
    /// RESERVED2 (RFC 9252 §3.1). MUST be 0 on origination; preserved
    /// verbatim on receive for propagation.
    pub reserved2: u8,
    /// SRv6 SID Structure Sub-Sub-TLV, when present.
    pub structure: Option<Srv6SidStructure>,
    /// Sub-sub-TLVs whose Type we don't model, preserved verbatim
    /// (RFC 9252 §2). Re-emitted after the SID Structure sub-sub-TLV.
    pub unknown_sub_sub_tlvs: Vec<RawSubTlv>,
}

impl Srv6SidInfo {
    /// Build a SID Information sub-TLV the way a producer originates it:
    /// zeroed RESERVED octets and no unknown sub-sub-TLVs.
    pub fn new(
        sid: Ipv6Addr,
        flags: u8,
        behavior: u16,
        structure: Option<Srv6SidStructure>,
    ) -> Self {
        Self {
            reserved1: 0,
            sid,
            flags,
            behavior,
            reserved2: 0,
            structure,
            unknown_sub_sub_tlvs: Vec::new(),
        }
    }
}

/// SRv6 SID Structure Sub-Sub-TLV (RFC 9252 §3.2.1) — the bit-length
/// breakdown of the SID. Lets a receiver locate the function/argument
/// for label transposition (transposition len 0 here = full SID).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Srv6SidStructure {
    pub locator_block_len: u8,
    pub locator_node_len: u8,
    pub function_len: u8,
    pub argument_len: u8,
    pub transposition_len: u8,
    pub transposition_offset: u8,
}

/// One SRGB range advertised inside the Originator SRGB TLV. Both
/// fields are 24-bit on the wire (3 octets each) but stored as `u32`
/// for ergonomics. The high byte of each is always zero on read and
/// is masked off on emit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SrgbRange {
    pub base: u32,
    pub range: u32,
}

impl ParseBe<PrefixSid> for PrefixSid {
    fn parse_be(input: &[u8]) -> IResult<&[u8], PrefixSid> {
        let mut remaining = input;
        let mut tlvs = Vec::new();
        while !remaining.is_empty() {
            let (rest, typ) = be_u8(remaining)?;
            let (rest, len) = be_u16(rest)?;
            let (rest, value) = nom::bytes::complete::take(len as usize)(rest)?;
            let (_, decoded) = decode_tlv(typ, value)?;
            tlvs.push(decoded);
            remaining = rest;
        }
        Ok((remaining, PrefixSid { tlvs }))
    }
}

fn decode_tlv(typ: u8, value: &[u8]) -> IResult<&[u8], PrefixSidTlv> {
    match typ {
        PREFIX_SID_TLV_LABEL_INDEX => {
            // Label-Index TLV: reserved(1) | flags(2) | label_index(4) = 7 octets.
            let (rest, _reserved) = be_u8(value)?;
            let (rest, flags) = be_u16(rest)?;
            let (rest, label_index) = be_u32(rest)?;
            // Any trailing bytes are a malformed TLV per §3.1; surface
            // by failing parse so callers can mark the attribute as
            // unreachable rather than silently dropping data.
            if !rest.is_empty() {
                return Err(nom::Err::Error(nom::error::make_error(
                    rest,
                    nom::error::ErrorKind::Verify,
                )));
            }
            Ok((rest, PrefixSidTlv::LabelIndex { flags, label_index }))
        }
        PREFIX_SID_TLV_ORIGINATOR_SRGB => {
            // Originator-SRGB TLV: flags(2) | SRGB(6) repeating.
            let (mut rest, flags) = be_u16(value)?;
            if rest.len() % 6 != 0 {
                return Err(nom::Err::Error(nom::error::make_error(
                    rest,
                    nom::error::ErrorKind::Verify,
                )));
            }
            let mut srgbs = Vec::with_capacity(rest.len() / 6);
            while !rest.is_empty() {
                let (r, base) = parse_be_u24(rest)?;
                let (r, range) = parse_be_u24(r)?;
                srgbs.push(SrgbRange { base, range });
                rest = r;
            }
            Ok((rest, PrefixSidTlv::OriginatorSrgb { flags, srgbs }))
        }
        PREFIX_SID_TLV_SRV6_L3_SERVICE => {
            let (rest, svc) = decode_srv6_service(value)?;
            Ok((rest, PrefixSidTlv::Srv6L3Service(svc)))
        }
        PREFIX_SID_TLV_SRV6_L2_SERVICE => {
            let (rest, svc) = decode_srv6_service(value)?;
            Ok((rest, PrefixSidTlv::Srv6L2Service(svc)))
        }
        other => Ok((
            &[],
            PrefixSidTlv::Unknown {
                typ: other,
                value: value.to_vec(),
            },
        )),
    }
}

/// Decode an SRv6 Service TLV body (RFC 9252 §2): a leading RESERVED
/// byte then an unordered list of SRv6 Service sub-TLVs. SID Information
/// sub-TLVs (type 1) are modelled; every other sub-TLV — and any
/// sub-sub-TLV we don't model — is preserved verbatim so the attribute
/// can be propagated unchanged (§2). A SID Information sub-TLV shorter
/// than its fixed 21-octet head is malformed (§7) and fails the parse so
/// the caller can treat-as-withdraw (RFC 7606).
fn decode_srv6_service(value: &[u8]) -> IResult<&[u8], Srv6ServiceTlv> {
    let (mut rest, reserved) = be_u8(value)?;
    let mut sids = Vec::new();
    let mut unknown_sub_tlvs = Vec::new();
    while !rest.is_empty() {
        let (r, sub_type) = be_u8(rest)?;
        let (r, sub_len) = be_u16(r)?;
        let (r, sub_val) = nom::bytes::complete::take(sub_len as usize)(r)?;
        rest = r;
        if sub_type != SRV6_SUBTLV_SID_INFO {
            unknown_sub_tlvs.push(RawSubTlv {
                typ: sub_type,
                value: sub_val.to_vec(),
            });
            continue;
        }
        // SID Information: RESERVED1(1) SID(16) Flags(1) Behavior(2) RESERVED2(1).
        if sub_val.len() < SRV6_SID_INFO_MIN_LEN {
            return Err(nom::Err::Error(nom::error::make_error(
                sub_val,
                nom::error::ErrorKind::Verify,
            )));
        }
        let (sv, reserved1) = be_u8(sub_val)?;
        let (sv, sid_bytes) = nom::bytes::complete::take(16usize)(sv)?;
        let mut octets = [0u8; 16];
        octets.copy_from_slice(sid_bytes);
        let sid = Ipv6Addr::from(octets);
        let (sv, flags) = be_u8(sv)?;
        let (sv, behavior) = be_u16(sv)?;
        let (mut sv, reserved2) = be_u8(sv)?;
        let mut structure = None;
        let mut unknown_sub_sub_tlvs = Vec::new();
        while !sv.is_empty() {
            let (s, ss_type) = be_u8(sv)?;
            let (s, ss_len) = be_u16(s)?;
            let (s, ss_val) = nom::bytes::complete::take(ss_len as usize)(s)?;
            sv = s;
            // Decode the SID Structure sub-sub-TLV only at its exact
            // 6-octet length, and only the first instance; anything else
            // (incl. a type-1 of a different length) is preserved
            // verbatim rather than reinterpreted.
            if ss_type == SRV6_SUBSUBTLV_SID_STRUCTURE
                && ss_val.len() == SRV6_SID_STRUCTURE_LEN
                && structure.is_none()
            {
                structure = Some(Srv6SidStructure {
                    locator_block_len: ss_val[0],
                    locator_node_len: ss_val[1],
                    function_len: ss_val[2],
                    argument_len: ss_val[3],
                    transposition_len: ss_val[4],
                    transposition_offset: ss_val[5],
                });
            } else {
                unknown_sub_sub_tlvs.push(RawSubTlv {
                    typ: ss_type,
                    value: ss_val.to_vec(),
                });
            }
        }
        sids.push(Srv6SidInfo {
            reserved1,
            sid,
            flags,
            behavior,
            reserved2,
            structure,
            unknown_sub_sub_tlvs,
        });
    }
    Ok((
        rest,
        Srv6ServiceTlv {
            reserved,
            sids,
            unknown_sub_tlvs,
        },
    ))
}

/// Encoded length of an SRv6 Service TLV body: RESERVED(1) + each SID
/// Information sub-TLV (header 3 + 21 body + optional 9-byte structure
/// sub-sub-TLV).
fn srv6_service_len(svc: &Srv6ServiceTlv) -> usize {
    let mut len = 1; // RESERVED
    for sid in &svc.sids {
        len += 3 + sid_info_len(sid); // sub-TLV header + Value
    }
    for raw in &svc.unknown_sub_tlvs {
        len += 3 + raw.value.len();
    }
    len
}

/// Encoded Value length of one SID Information sub-TLV: the 21-octet
/// fixed head plus an optional SID Structure sub-sub-TLV (3 + 6) plus
/// any preserved unknown sub-sub-TLVs.
fn sid_info_len(sid: &Srv6SidInfo) -> usize {
    let mut len = SRV6_SID_INFO_MIN_LEN;
    if sid.structure.is_some() {
        len += 3 + SRV6_SID_STRUCTURE_LEN;
    }
    for raw in &sid.unknown_sub_sub_tlvs {
        len += 3 + raw.value.len();
    }
    len
}

fn emit_raw_sub_tlv(buf: &mut BytesMut, raw: &RawSubTlv) {
    buf.put_u8(raw.typ);
    buf.put_u16(raw.value.len() as u16);
    buf.put(&raw.value[..]);
}

fn emit_srv6_service(buf: &mut BytesMut, svc: &Srv6ServiceTlv) {
    buf.put_u8(svc.reserved); // RESERVED (preserved)
    for sid in &svc.sids {
        buf.put_u8(SRV6_SUBTLV_SID_INFO);
        buf.put_u16(sid_info_len(sid) as u16);
        buf.put_u8(sid.reserved1); // RESERVED1 (preserved)
        buf.put(&sid.sid.octets()[..]);
        buf.put_u8(sid.flags);
        buf.put_u16(sid.behavior);
        buf.put_u8(sid.reserved2); // RESERVED2 (preserved)
        if let Some(st) = sid.structure {
            buf.put_u8(SRV6_SUBSUBTLV_SID_STRUCTURE);
            buf.put_u16(SRV6_SID_STRUCTURE_LEN as u16);
            buf.put_u8(st.locator_block_len);
            buf.put_u8(st.locator_node_len);
            buf.put_u8(st.function_len);
            buf.put_u8(st.argument_len);
            buf.put_u8(st.transposition_len);
            buf.put_u8(st.transposition_offset);
        }
        for raw in &sid.unknown_sub_sub_tlvs {
            emit_raw_sub_tlv(buf, raw);
        }
    }
    for raw in &svc.unknown_sub_tlvs {
        emit_raw_sub_tlv(buf, raw);
    }
}

fn parse_be_u24(input: &[u8]) -> IResult<&[u8], u32> {
    let (rest, bytes) = nom::bytes::complete::take(3usize)(input)?;
    Ok((
        rest,
        ((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | (bytes[2] as u32),
    ))
}

fn put_be_u24(buf: &mut BytesMut, value: u32) {
    buf.put_u8(((value >> 16) & 0xff) as u8);
    buf.put_u8(((value >> 8) & 0xff) as u8);
    buf.put_u8((value & 0xff) as u8);
}

impl PrefixSid {
    /// Sum the encoded length of every TLV plus its 3-octet header so
    /// the AttrEmitter wrapper can pick standard vs extended length
    /// without buffering.
    fn encoded_len(&self) -> usize {
        self.tlvs.iter().map(tlv_encoded_len).sum()
    }
}

fn tlv_encoded_len(tlv: &PrefixSidTlv) -> usize {
    let body = match tlv {
        PrefixSidTlv::LabelIndex { .. } => 7,
        PrefixSidTlv::OriginatorSrgb { srgbs, .. } => 2 + srgbs.len() * 6,
        PrefixSidTlv::Srv6L3Service(svc) | PrefixSidTlv::Srv6L2Service(svc) => {
            srv6_service_len(svc)
        }
        PrefixSidTlv::Unknown { value, .. } => value.len(),
    };
    3 + body
}

fn emit_tlv(buf: &mut BytesMut, tlv: &PrefixSidTlv) {
    let (typ, body_len) = match tlv {
        PrefixSidTlv::LabelIndex { .. } => (1u8, 7u16),
        PrefixSidTlv::OriginatorSrgb { srgbs, .. } => (3u8, (2 + srgbs.len() * 6) as u16),
        PrefixSidTlv::Srv6L3Service(svc) => (5u8, srv6_service_len(svc) as u16),
        PrefixSidTlv::Srv6L2Service(svc) => (6u8, srv6_service_len(svc) as u16),
        PrefixSidTlv::Unknown { typ, value } => (*typ, value.len() as u16),
    };
    buf.put_u8(typ);
    buf.put_u16(body_len);
    match tlv {
        PrefixSidTlv::LabelIndex { flags, label_index } => {
            buf.put_u8(0); // reserved
            buf.put_u16(*flags);
            buf.put_u32(*label_index);
        }
        PrefixSidTlv::OriginatorSrgb { flags, srgbs } => {
            buf.put_u16(*flags);
            for srgb in srgbs {
                put_be_u24(buf, srgb.base & 0x00ff_ffff);
                put_be_u24(buf, srgb.range & 0x00ff_ffff);
            }
        }
        PrefixSidTlv::Srv6L3Service(svc) | PrefixSidTlv::Srv6L2Service(svc) => {
            emit_srv6_service(buf, svc);
        }
        PrefixSidTlv::Unknown { value, .. } => {
            buf.put(&value[..]);
        }
    }
}

impl AttrEmitter for PrefixSid {
    fn attr_flags(&self) -> AttrFlags {
        // RFC 8669 §3: Optional, Transitive.
        AttrFlags::new().with_optional(true).with_transitive(true)
    }

    fn attr_type(&self) -> AttrType {
        AttrType::PrefixSid
    }

    fn len(&self) -> Option<usize> {
        Some(self.encoded_len())
    }

    fn emit(&self, buf: &mut BytesMut) {
        for tlv in &self.tlvs {
            emit_tlv(buf, tlv);
        }
    }
}

impl fmt::Display for PrefixSid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PrefixSid[")?;
        for (i, tlv) in self.tlvs.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            match tlv {
                PrefixSidTlv::LabelIndex { label_index, .. } => {
                    write!(f, "LabelIndex={label_index}")?;
                }
                PrefixSidTlv::OriginatorSrgb { srgbs, .. } => {
                    write!(f, "OriginatorSRGB(")?;
                    for (j, s) in srgbs.iter().enumerate() {
                        if j > 0 {
                            write!(f, ",")?;
                        }
                        write!(f, "{}/{}", s.base, s.range)?;
                    }
                    write!(f, ")")?;
                }
                PrefixSidTlv::Srv6L3Service(svc) => {
                    write!(f, "SRv6L3Service(")?;
                    for (j, s) in svc.sids.iter().enumerate() {
                        if j > 0 {
                            write!(f, ",")?;
                        }
                        write!(f, "{} behavior={:#06x}", s.sid, s.behavior)?;
                    }
                    write!(f, ")")?;
                }
                PrefixSidTlv::Srv6L2Service(svc) => {
                    write!(f, "SRv6L2Service({} SIDs)", svc.sids.len())?;
                }
                PrefixSidTlv::Unknown { typ, value } => {
                    write!(f, "Unknown(type={typ}, {} bytes)", value.len())?;
                }
            }
        }
        write!(f, "]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn srv6_l3_sid_for_dest_prefers_exact_family_then_dt46() {
        let dt4: Ipv6Addr = "fcbb:1::4".parse().unwrap();
        let dt6: Ipv6Addr = "fcbb:1::6".parse().unwrap();
        let dt46: Ipv6Addr = "fcbb:1::46".parse().unwrap();
        // Split DT4+DT6 pair: each family gets its own SID regardless of
        // wire order (DT6 listed first here).
        let split = [(dt6, SRV6_BEHAVIOR_END_DT6), (dt4, SRV6_BEHAVIOR_END_DT4)];
        assert_eq!(
            srv6_l3_sid_for_dest(&split, true),
            Some((dt4, SRV6_BEHAVIOR_END_DT4))
        );
        assert_eq!(
            srv6_l3_sid_for_dest(&split, false),
            Some((dt6, SRV6_BEHAVIOR_END_DT6))
        );
        // The exact-family SID wins over an also-present DT46; without an
        // exact match, DT46 serves either family.
        let mixed = [(dt46, SRV6_BEHAVIOR_END_DT46), (dt4, SRV6_BEHAVIOR_END_DT4)];
        assert_eq!(
            srv6_l3_sid_for_dest(&mixed, true),
            Some((dt4, SRV6_BEHAVIOR_END_DT4))
        );
        assert_eq!(
            srv6_l3_sid_for_dest(&mixed, false),
            Some((dt46, SRV6_BEHAVIOR_END_DT46))
        );
    }

    #[test]
    fn srv6_l3_sid_for_dest_rejects_family_incompatible_decap() {
        // A DT4-only segment cannot service an IPv6 destination (End.DT4
        // decaps into the IPv4 table only) — and vice versa.
        let dt4: Ipv6Addr = "fcbb:1::4".parse().unwrap();
        let only_v4 = [(dt4, SRV6_BEHAVIOR_END_DT4)];
        assert_eq!(srv6_l3_sid_for_dest(&only_v4, false), None);
        let dt6: Ipv6Addr = "fcbb:1::6".parse().unwrap();
        let only_v6 = [(dt6, SRV6_BEHAVIOR_END_DT6)];
        assert_eq!(srv6_l3_sid_for_dest(&only_v6, true), None);
    }

    #[test]
    fn srv6_l3_sid_for_dest_falls_back_to_first_for_unmodeled_behaviors() {
        // No known L3-decap behavior at all → first SID (semantics we
        // don't model, so keep the historical pick). Empty → None.
        let odd: Ipv6Addr = "fcbb:1::99".parse().unwrap();
        let vendor = [(odd, 0x7fff_u16)];
        assert_eq!(srv6_l3_sid_for_dest(&vendor, true), Some((odd, 0x7fff)));
        assert_eq!(srv6_l3_sid_for_dest(&vendor, false), Some((odd, 0x7fff)));
        assert_eq!(srv6_l3_sid_for_dest(&[], true), None);
    }

    fn round_trip(sid: PrefixSid) -> PrefixSid {
        let mut buf = BytesMut::new();
        sid.emit(&mut buf);
        let bytes: Vec<u8> = buf.to_vec();
        let (rest, parsed) = PrefixSid::parse_be(&bytes).expect("parse");
        assert!(rest.is_empty(), "trailing bytes after parse");
        parsed
    }

    /// Pin the IANA "SRv6 Endpoint Behaviors" codepoints — End.DX2/DX2V
    /// sit at 21/22 and End.DT2U/DT2M at 23/24; an off-by-two here once
    /// shipped DT2U/DT2M as 21/22.
    #[test]
    fn behavior_codepoints_match_iana() {
        assert_eq!(SRV6_BEHAVIOR_END_DT6, 18);
        assert_eq!(SRV6_BEHAVIOR_END_DT4, 19);
        assert_eq!(SRV6_BEHAVIOR_END_DT46, 20);
        assert_eq!(SRV6_BEHAVIOR_END_DX2, 21);
        assert_eq!(SRV6_BEHAVIOR_END_DX2V, 22);
        assert_eq!(SRV6_BEHAVIOR_END_DT2U, 23);
        assert_eq!(SRV6_BEHAVIOR_END_DT2M, 24);
    }

    #[test]
    fn label_index_round_trip() {
        let sid = PrefixSid {
            tlvs: vec![PrefixSidTlv::LabelIndex {
                flags: 0x4000,
                label_index: 128,
            }],
        };
        assert_eq!(round_trip(sid.clone()), sid);
    }

    #[test]
    fn originator_srgb_round_trip_zero_srgbs() {
        let sid = PrefixSid {
            tlvs: vec![PrefixSidTlv::OriginatorSrgb {
                flags: 0,
                srgbs: vec![],
            }],
        };
        assert_eq!(round_trip(sid.clone()), sid);
    }

    #[test]
    fn originator_srgb_round_trip_multiple_ranges() {
        let sid = PrefixSid {
            tlvs: vec![PrefixSidTlv::OriginatorSrgb {
                flags: 0,
                srgbs: vec![
                    SrgbRange {
                        base: 16000,
                        range: 8000,
                    },
                    SrgbRange {
                        base: 100000,
                        range: 4096,
                    },
                ],
            }],
        };
        assert_eq!(round_trip(sid.clone()), sid);
    }

    #[test]
    fn mixed_tlvs_preserve_order() {
        let sid = PrefixSid {
            tlvs: vec![
                PrefixSidTlv::LabelIndex {
                    flags: 0,
                    label_index: 42,
                },
                PrefixSidTlv::OriginatorSrgb {
                    flags: 0,
                    srgbs: vec![SrgbRange {
                        base: 24000,
                        range: 1000,
                    }],
                },
            ],
        };
        let rt = round_trip(sid.clone());
        assert_eq!(rt, sid);
        assert!(matches!(rt.tlvs[0], PrefixSidTlv::LabelIndex { .. }));
        assert!(matches!(rt.tlvs[1], PrefixSidTlv::OriginatorSrgb { .. }));
    }

    #[test]
    fn srv6_l3_service_round_trips_structured() {
        // One End.DT46 SID with a full SID-structure sub-sub-TLV — the
        // L3VPN-over-SRv6 advertise shape.
        let sid = PrefixSid {
            tlvs: vec![PrefixSidTlv::Srv6L3Service(Srv6ServiceTlv {
                sids: vec![Srv6SidInfo::new(
                    "2001:db8:1:1::".parse().unwrap(),
                    0,
                    SRV6_BEHAVIOR_END_DT46,
                    Some(Srv6SidStructure {
                        locator_block_len: 32,
                        locator_node_len: 16,
                        function_len: 16,
                        argument_len: 0,
                        transposition_len: 0,
                        transposition_offset: 0,
                    }),
                )],
                ..Default::default()
            })],
        };
        let rt = round_trip(sid.clone());
        assert_eq!(rt, sid);
        // The SID + behavior decode back out.
        match &rt.tlvs[0] {
            PrefixSidTlv::Srv6L3Service(svc) => {
                assert_eq!(svc.sids[0].behavior, SRV6_BEHAVIOR_END_DT46);
                assert_eq!(
                    svc.sids[0].sid,
                    "2001:db8:1:1::".parse::<Ipv6Addr>().unwrap()
                );
            }
            _ => panic!("expected SRv6 L3 Service TLV"),
        }
    }

    #[test]
    fn srv6_l2_service_end_dt2m_round_trips() {
        // One End.DT2M SID in an SRv6 L2 Service TLV (sub-TLV type 6) — the
        // EVPN-over-SRv6 BUM-replication advertise shape on a Type-3 IMET.
        let sid = PrefixSid {
            tlvs: vec![PrefixSidTlv::Srv6L2Service(Srv6ServiceTlv {
                sids: vec![Srv6SidInfo::new(
                    "2001:db8:1:2::".parse().unwrap(),
                    0,
                    SRV6_BEHAVIOR_END_DT2M,
                    Some(Srv6SidStructure {
                        locator_block_len: 32,
                        locator_node_len: 16,
                        function_len: 16,
                        argument_len: 0,
                        transposition_len: 0,
                        transposition_offset: 0,
                    }),
                )],
                ..Default::default()
            })],
        };
        let rt = round_trip(sid.clone());
        assert_eq!(rt, sid);
        match &rt.tlvs[0] {
            PrefixSidTlv::Srv6L2Service(svc) => {
                assert_eq!(svc.sids[0].behavior, SRV6_BEHAVIOR_END_DT2M);
                assert_eq!(
                    svc.sids[0].sid,
                    "2001:db8:1:2::".parse::<Ipv6Addr>().unwrap()
                );
            }
            _ => panic!("expected SRv6 L2 Service TLV"),
        }
    }

    #[test]
    fn srv6_sid_without_structure_round_trips() {
        let sid = PrefixSid {
            tlvs: vec![PrefixSidTlv::Srv6L3Service(Srv6ServiceTlv {
                sids: vec![Srv6SidInfo::new(
                    "2001:db8::1".parse().unwrap(),
                    0,
                    SRV6_BEHAVIOR_END_DT4,
                    None,
                )],
                ..Default::default()
            })],
        };
        assert_eq!(round_trip(sid.clone()), sid);
    }

    #[test]
    fn srv6_service_with_unknowns_struct_round_trips() {
        // A hand-built service TLV carrying an unrecognized sub-TLV and
        // an unrecognized sub-sub-TLV round-trips through emit→parse.
        let sid = PrefixSid {
            tlvs: vec![PrefixSidTlv::Srv6L3Service(Srv6ServiceTlv {
                reserved: 0,
                sids: vec![Srv6SidInfo {
                    reserved1: 0,
                    sid: "2001:db8::1".parse().unwrap(),
                    flags: 0,
                    behavior: SRV6_BEHAVIOR_END_DT46,
                    reserved2: 0,
                    structure: None,
                    unknown_sub_sub_tlvs: vec![RawSubTlv {
                        typ: 7,
                        value: vec![9, 9],
                    }],
                }],
                unknown_sub_tlvs: vec![RawSubTlv {
                    typ: 250,
                    value: vec![1, 2, 3, 4],
                }],
            })],
        };
        assert_eq!(round_trip(sid.clone()), sid);
    }

    #[test]
    fn srv6_service_preserves_reserved_and_unknown_tlvs_bit_exact() {
        // An SRv6 L3 Service TLV whose RESERVED octets are non-zero and
        // which carries an unrecognized sub-TLV (type 9) plus an
        // unrecognized sub-sub-TLV (type 7) inside the SID Information
        // sub-TLV. RFC 9252 §2 requires all of this — Reserved fields
        // included — to survive a receive→propagate (parse→emit) cycle
        // unchanged when the next hop is unchanged.
        let mut sid_info_value = vec![0xAA]; // RESERVED1 (non-zero)
        sid_info_value.extend_from_slice(&[0u8; 16]); // SID
        sid_info_value.push(0x00); // flags
        sid_info_value.extend_from_slice(&SRV6_BEHAVIOR_END_DT46.to_be_bytes());
        sid_info_value.push(0xBB); // RESERVED2 (non-zero)
        sid_info_value.extend_from_slice(&[7, 0x00, 0x02, 0xDE, 0xAD]); // unknown sub-sub-TLV

        let mut service_value = vec![0xCC]; // service RESERVED (non-zero)
        service_value.push(SRV6_SUBTLV_SID_INFO);
        service_value.extend_from_slice(&(sid_info_value.len() as u16).to_be_bytes());
        service_value.extend_from_slice(&sid_info_value);
        service_value.extend_from_slice(&[9, 0x00, 0x03, 1, 2, 3]); // unknown sub-TLV

        let mut attr_bytes = vec![PREFIX_SID_TLV_SRV6_L3_SERVICE];
        attr_bytes.extend_from_slice(&(service_value.len() as u16).to_be_bytes());
        attr_bytes.extend_from_slice(&service_value);

        let (rest, parsed) = PrefixSid::parse_be(&attr_bytes).expect("parse");
        assert!(rest.is_empty());
        match &parsed.tlvs[0] {
            PrefixSidTlv::Srv6L3Service(svc) => {
                assert_eq!(svc.reserved, 0xCC);
                assert_eq!(
                    svc.unknown_sub_tlvs,
                    vec![RawSubTlv {
                        typ: 9,
                        value: vec![1, 2, 3]
                    }]
                );
                let s = &svc.sids[0];
                assert_eq!(s.reserved1, 0xAA);
                assert_eq!(s.reserved2, 0xBB);
                assert_eq!(
                    s.unknown_sub_sub_tlvs,
                    vec![RawSubTlv {
                        typ: 7,
                        value: vec![0xDE, 0xAD]
                    }]
                );
            }
            _ => panic!("expected SRv6 L3 Service TLV"),
        }

        let mut buf = BytesMut::new();
        parsed.emit(&mut buf);
        assert_eq!(buf.to_vec(), attr_bytes, "re-emit must be byte-for-byte");
    }

    #[test]
    fn srv6_sid_info_shorter_than_21_is_rejected() {
        // SID Information sub-TLV (type 1) with a Value length of 20, one
        // short of the fixed 21-octet head. RFC 9252 §7 deems it
        // malformed; the parse must fail so the caller treats-as-withdraw.
        let mut service_value = vec![0x00]; // service RESERVED
        service_value.push(SRV6_SUBTLV_SID_INFO);
        service_value.extend_from_slice(&20u16.to_be_bytes());
        service_value.extend_from_slice(&[0u8; 20]);

        let mut attr_bytes = vec![PREFIX_SID_TLV_SRV6_L3_SERVICE];
        attr_bytes.extend_from_slice(&(service_value.len() as u16).to_be_bytes());
        attr_bytes.extend_from_slice(&service_value);

        assert!(PrefixSid::parse_be(&attr_bytes).is_err());
    }

    #[test]
    fn unknown_tlv_round_trips_verbatim() {
        let sid = PrefixSid {
            tlvs: vec![PrefixSidTlv::Unknown {
                typ: 99,
                value: vec![0xde, 0xad, 0xbe, 0xef],
            }],
        };
        assert_eq!(round_trip(sid.clone()), sid);
    }

    #[test]
    fn label_index_with_trailing_bytes_is_rejected() {
        // Type=1, len=8 (one extra byte beyond the 7-octet spec).
        let bytes: Vec<u8> = vec![
            1, // type
            0, 8, // length 8
            0, // reserved
            0, 0, // flags
            0, 0, 0, 1,    // label_index
            0xff, // surplus byte → must reject
        ];
        assert!(PrefixSid::parse_be(&bytes).is_err());
    }

    #[test]
    fn originator_srgb_with_partial_range_is_rejected() {
        // Flags(2) + 5 bytes (not a multiple of 6).
        let bytes: Vec<u8> = vec![
            3, // type
            0, 7, // length 7
            0, 0, // flags
            0, 0, 0, // base low
            0, 0, // truncated range
        ];
        assert!(PrefixSid::parse_be(&bytes).is_err());
    }

    #[test]
    fn empty_attribute_parses_to_empty_tlv_list() {
        let (rest, parsed) = PrefixSid::parse_be(&[]).expect("empty parse");
        assert!(rest.is_empty());
        assert!(parsed.tlvs.is_empty());
    }
}
