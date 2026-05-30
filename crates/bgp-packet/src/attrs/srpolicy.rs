use std::net::Ipv6Addr;

use thiserror::Error;

use super::{TunnelEncap, TunnelSubTlv, TunnelTlv};

/// Typed view over the sub-TLVs of an SR Policy Tunnel TLV (Tunnel-Type
/// 15), as defined by RFC 9830 (*Advertising Segment Routing Policies in
/// BGP*) and RFC 9831 (the C–K segment-type extensions).
///
/// The generic [`TunnelEncap`] keeps storing opaque [`TunnelSubTlv`]s so
/// that unknown sub-TLVs round-trip unchanged for route reflectors; this
/// type is a lossless-ish projection on top of it: recognised sub-TLVs
/// are decoded into typed fields, and anything we don't model is kept
/// verbatim in [`SrPolicyTlvs::unknown`] (policy-level) or as
/// [`Segment::Unknown`] (inside a segment list). Convert with
/// [`SrPolicyTlvs::from_tunnel`] / [`SrPolicyTlvs::to_tunnel`].
///
/// Wire notes (RFC 9830 §2.4, verified against the RFC figures):
/// - Every policy-level value sub-TLV begins with `Flags(1) RESERVED(1)`
///   except Priority (`Priority(1) RESERVED(1)`) and the name sub-TLVs
///   (`RESERVED(1)` then UTF-8 — there *is* a leading RESERVED octet,
///   contrary to an earlier draft of our design notes).
/// - The Segment List value is `RESERVED(1)` followed by inner sub-TLVs
///   (an optional Weight then the segments).
/// - SR-MPLS labels (Binding SID, Segment Type A) are carried in a
///   4-octet MPLS label-stack entry whose top 20 bits are the label; the
///   TC/S/TTL bits MUST be zero and are ignored.
///
/// v1 decodes Segment Type A (SR-MPLS, code 1) and Type B (SRv6, code
/// 13); the RFC 9831 types C–K and the deprecated codepoints (2, 10, 11,
/// 12) decode into [`Segment::Unknown`] with their bytes preserved.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct SrPolicyTlvs {
    /// Preference (sub-TLV 12); RFC 9256 default is 100 when absent.
    pub preference: Option<u32>,
    /// Binding SID (sub-TLV 13) — none / SR-MPLS label / SRv6 SID.
    pub binding_sid: Option<BindingSid>,
    /// SRv6 Binding SID (sub-TLV 20).
    pub srv6_binding_sid: Option<Srv6BindingSid>,
    /// Explicit NULL Label Policy (sub-TLV 14): 1=v4, 2=v6, 3=both,
    /// 4=none. Stored raw; semantics are the consumer's.
    pub enlp: Option<u8>,
    /// Priority (sub-TLV 15); RFC 9256 default is 128 when absent.
    pub priority: Option<u8>,
    /// Segment List sub-TLVs (128); a policy may carry several.
    pub segment_lists: Vec<SegmentList>,
    /// SR Policy Name (sub-TLV 130).
    pub policy_name: Option<String>,
    /// SR Policy Candidate Path Name (sub-TLV 129).
    pub cp_name: Option<String>,
    /// Policy-level sub-TLVs we don't model, preserved verbatim so they
    /// survive a decode/encode round-trip (reflector-friendly).
    pub unknown: Vec<TunnelSubTlv>,
}

/// Binding SID (sub-TLV 13). The S/I flags are not modelled in v1; they
/// are emitted as zero. An SRv6 SID may also arrive in the dedicated
/// SRv6 Binding SID sub-TLV (20) — see [`Srv6BindingSid`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BindingSid {
    /// Length 2: Flags+RESERVED only, no BSID value.
    None,
    /// Length 6: a 20-bit SR-MPLS label.
    MplsLabel(u32),
    /// Length 18: a 16-octet SRv6 SID.
    Srv6(Ipv6Addr),
}

/// SRv6 Binding SID (sub-TLV 20): `Flags(1) RESERVED(1) SID(16)` with an
/// optional 8-octet Endpoint Behavior & SID Structure present when the
/// B-flag (bit 2) is set (Length 26 vs 18).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Srv6BindingSid {
    /// Flag octet: S=bit0, I=bit1, B=bit2 (preserved verbatim).
    pub flags: u8,
    pub sid: Ipv6Addr,
    pub structure: Option<Srv6BehaviorStructure>,
}

/// Segment List (sub-TLV 128): an optional Weight and an ordered list of
/// segments.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct SegmentList {
    /// Weight sub-TLV (inner code 9); RFC 9256 default is 1, 0 is invalid.
    pub weight: Option<u32>,
    pub segments: Vec<Segment>,
}

/// One segment within a [`SegmentList`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Segment {
    /// Type A (inner code 1): SR-MPLS, a 20-bit label. The flag octet
    /// (V=bit0, …) is preserved.
    TypeA { flags: u8, label: u32 },
    /// Type B (inner code 13): SRv6 SID with an optional Endpoint
    /// Behavior & SID Structure (present when the B-flag, bit 3, is set).
    TypeB {
        flags: u8,
        sid: Ipv6Addr,
        structure: Option<Srv6BehaviorStructure>,
    },
    /// Any segment code we don't decode (RFC 9831 Types C–K, the
    /// deprecated codepoints 2/10/11/12, or future ones). Bytes are the
    /// sub-TLV *value* (after the type/length header) and are preserved.
    Unknown { code: u8, value: Vec<u8> },
}

/// SRv6 Endpoint Behavior & SID Structure (RFC 9830 §2.4.4.2.2), an
/// 8-octet block: `Behavior(2) RESERVED(2) LB-len(1) LN-len(1)
/// Fun-len(1) Arg-len(1)`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct Srv6BehaviorStructure {
    /// SRv6 Endpoint Behavior (RFC 8986); 0xFFFF = opaque/headend-chosen.
    pub endpoint_behavior: u16,
    pub locator_block_len: u8,
    pub locator_node_len: u8,
    pub function_len: u8,
    pub argument_len: u8,
}

/// IANA Tunnel Type for SR Policy.
pub const SR_POLICY_TUNNEL_TYPE: u16 = 15;

// Policy-level sub-TLV type codes (direct children of the Tunnel-Type-15
// TLV).
const PREFERENCE: u8 = 12;
const BINDING_SID: u8 = 13;
const ENLP: u8 = 14;
const PRIORITY: u8 = 15;
const SRV6_BINDING_SID: u8 = 20;
const SEGMENT_LIST: u8 = 128;
const CP_NAME: u8 = 129;
const POLICY_NAME: u8 = 130;

// Segment-List inner sub-TLV codes (a distinct registry; note Binding
// SID and Segment Type B share code 13 but live in different contexts).
const SEG_TYPE_A: u8 = 1;
const SEG_WEIGHT: u8 = 9;
const SEG_TYPE_B: u8 = 13;

/// Errors from decoding a Tunnel-Type-15 TLV into [`SrPolicyTlvs`].
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum SrPolicyError {
    #[error("tunnel TLV is not an SR Policy TLV (tunnel_type={0}, expected 15)")]
    NotSrPolicy(u16),
    #[error("sub-TLV {typ} has invalid length {len} (expected {expected})")]
    BadLength {
        typ: u8,
        len: usize,
        expected: &'static str,
    },
    #[error("truncated sub-TLV {typ}: need {needed} bytes, have {got}")]
    Truncated { typ: u8, needed: usize, got: usize },
    #[error("segment list mixes SR-MPLS (Type A) and SRv6 (Type B) segments")]
    MixedSegmentTypes,
    #[error("invalid UTF-8 in name sub-TLV {0}")]
    BadName(u8),
}

/// Mask selecting the top 20 bits (the label) of a 4-octet MPLS
/// label-stack entry.
const MPLS_LABEL_MASK: u32 = 0x000F_FFFF;
/// Shift placing a 20-bit label into the high bits of the 4-octet word.
const MPLS_LABEL_SHIFT: u32 = 12;

impl SrPolicyTlvs {
    /// Decode the sub-TLVs of an SR Policy Tunnel TLV into a typed view.
    /// Returns [`SrPolicyError::NotSrPolicy`] if `tunnel` is not a
    /// Tunnel-Type-15 TLV. Validation is intentionally codec-level
    /// (lengths, no mixed SR-MPLS/SRv6 in one list); policy-level
    /// validation (e.g. "at least one segment list") is the consumer's.
    pub fn from_tunnel(tunnel: &TunnelTlv) -> Result<Self, SrPolicyError> {
        if tunnel.tunnel_type != SR_POLICY_TUNNEL_TYPE {
            return Err(SrPolicyError::NotSrPolicy(tunnel.tunnel_type));
        }
        let mut out = SrPolicyTlvs::default();
        for sub in &tunnel.sub_tlvs {
            match sub.typ {
                PREFERENCE => out.preference = Some(parse_preference(&sub.value)?),
                BINDING_SID => out.binding_sid = Some(parse_binding_sid(&sub.value)?),
                SRV6_BINDING_SID => {
                    out.srv6_binding_sid = Some(parse_srv6_binding_sid(&sub.value)?)
                }
                ENLP => out.enlp = Some(parse_enlp(&sub.value)?),
                PRIORITY => out.priority = Some(parse_priority(&sub.value)?),
                SEGMENT_LIST => out.segment_lists.push(parse_segment_list(&sub.value)?),
                CP_NAME => out.cp_name = Some(parse_name(CP_NAME, &sub.value)?),
                POLICY_NAME => out.policy_name = Some(parse_name(POLICY_NAME, &sub.value)?),
                _ => out.unknown.push(sub.clone()),
            }
        }
        Ok(out)
    }

    /// Encode this typed view back into a Tunnel-Type-15 TLV. RESERVED
    /// octets are zeroed; unknown sub-TLVs (policy-level and per-segment)
    /// are emitted verbatim, after the recognised ones.
    pub fn to_tunnel(&self) -> TunnelTlv {
        let mut sub_tlvs = Vec::new();
        if let Some(pref) = self.preference {
            sub_tlvs.push(sub(PREFERENCE, emit_preference(pref)));
        }
        if let Some(bsid) = &self.binding_sid {
            sub_tlvs.push(sub(BINDING_SID, emit_binding_sid(bsid)));
        }
        if let Some(sbsid) = &self.srv6_binding_sid {
            sub_tlvs.push(sub(SRV6_BINDING_SID, emit_srv6_binding_sid(sbsid)));
        }
        if let Some(enlp) = self.enlp {
            sub_tlvs.push(sub(ENLP, vec![0, 0, enlp]));
        }
        if let Some(prio) = self.priority {
            sub_tlvs.push(sub(PRIORITY, vec![prio, 0]));
        }
        for sl in &self.segment_lists {
            sub_tlvs.push(sub(SEGMENT_LIST, emit_segment_list(sl)));
        }
        if let Some(name) = &self.cp_name {
            sub_tlvs.push(sub(CP_NAME, emit_name(name)));
        }
        if let Some(name) = &self.policy_name {
            sub_tlvs.push(sub(POLICY_NAME, emit_name(name)));
        }
        sub_tlvs.extend(self.unknown.iter().cloned());
        TunnelTlv {
            tunnel_type: SR_POLICY_TUNNEL_TYPE,
            sub_tlvs,
        }
    }
}

/// Decode the first SR Policy (Tunnel-Type-15) TLV in a Tunnel
/// Encapsulation attribute, if any. `None` when no SR Policy tunnel is
/// present; `Some(Err(..))` when one is present but malformed.
pub fn sr_policy_tlvs(enc: &TunnelEncap) -> Option<Result<SrPolicyTlvs, SrPolicyError>> {
    enc.tunnels
        .iter()
        .find(|t| t.tunnel_type == SR_POLICY_TUNNEL_TYPE)
        .map(SrPolicyTlvs::from_tunnel)
}

fn sub(typ: u8, value: Vec<u8>) -> TunnelSubTlv {
    TunnelSubTlv { typ, value }
}

// --- policy-level sub-TLV decoders -----------------------------------

fn parse_preference(v: &[u8]) -> Result<u32, SrPolicyError> {
    // Flags(1) RESERVED(1) Preference(4).
    if v.len() != 6 {
        return Err(SrPolicyError::BadLength {
            typ: PREFERENCE,
            len: v.len(),
            expected: "6",
        });
    }
    Ok(u32::from_be_bytes([v[2], v[3], v[4], v[5]]))
}

fn parse_binding_sid(v: &[u8]) -> Result<BindingSid, SrPolicyError> {
    // Flags(1) RESERVED(1) BSID(0 | 4 SR-MPLS | 16 SRv6).
    match v.len() {
        2 => Ok(BindingSid::None),
        6 => {
            let word = u32::from_be_bytes([v[2], v[3], v[4], v[5]]);
            Ok(BindingSid::MplsLabel(word >> MPLS_LABEL_SHIFT))
        }
        18 => Ok(BindingSid::Srv6(read_v6(&v[2..18]))),
        _ => Err(SrPolicyError::BadLength {
            typ: BINDING_SID,
            len: v.len(),
            expected: "2, 6, or 18",
        }),
    }
}

fn parse_srv6_binding_sid(v: &[u8]) -> Result<Srv6BindingSid, SrPolicyError> {
    // Flags(1) RESERVED(1) SID(16) [Structure(8)].
    match v.len() {
        18 | 26 => Ok(Srv6BindingSid {
            flags: v[0],
            sid: read_v6(&v[2..18]),
            structure: (v.len() == 26).then(|| read_srv6_structure(&v[18..26])),
        }),
        _ => Err(SrPolicyError::BadLength {
            typ: SRV6_BINDING_SID,
            len: v.len(),
            expected: "18 or 26",
        }),
    }
}

fn parse_enlp(v: &[u8]) -> Result<u8, SrPolicyError> {
    // Flags(1) RESERVED(1) ENLP(1).
    if v.len() != 3 {
        return Err(SrPolicyError::BadLength {
            typ: ENLP,
            len: v.len(),
            expected: "3",
        });
    }
    Ok(v[2])
}

fn parse_priority(v: &[u8]) -> Result<u8, SrPolicyError> {
    // Priority(1) RESERVED(1).
    if v.len() != 2 {
        return Err(SrPolicyError::BadLength {
            typ: PRIORITY,
            len: v.len(),
            expected: "2",
        });
    }
    Ok(v[0])
}

fn parse_name(typ: u8, v: &[u8]) -> Result<String, SrPolicyError> {
    // RESERVED(1) then UTF-8 name (no NUL). An empty name (value == just
    // the RESERVED octet) is valid.
    if v.is_empty() {
        return Err(SrPolicyError::Truncated {
            typ,
            needed: 1,
            got: 0,
        });
    }
    String::from_utf8(v[1..].to_vec()).map_err(|_| SrPolicyError::BadName(typ))
}

fn parse_segment_list(v: &[u8]) -> Result<SegmentList, SrPolicyError> {
    // RESERVED(1) then inner sub-TLVs (Weight + segments).
    if v.is_empty() {
        return Err(SrPolicyError::Truncated {
            typ: SEGMENT_LIST,
            needed: 1,
            got: 0,
        });
    }
    let mut rest = &v[1..];
    let mut list = SegmentList::default();
    while !rest.is_empty() {
        let (code, value, tail) = take_inner_tlv(rest)?;
        match code {
            SEG_WEIGHT => list.weight = Some(parse_weight(value)?),
            SEG_TYPE_A => list.segments.push(parse_seg_type_a(value)?),
            SEG_TYPE_B => list.segments.push(parse_seg_type_b(value)?),
            _ => list.segments.push(Segment::Unknown {
                code,
                value: value.to_vec(),
            }),
        }
        rest = tail;
    }
    let has_mpls = list
        .segments
        .iter()
        .any(|s| matches!(s, Segment::TypeA { .. }));
    let has_srv6 = list
        .segments
        .iter()
        .any(|s| matches!(s, Segment::TypeB { .. }));
    if has_mpls && has_srv6 {
        return Err(SrPolicyError::MixedSegmentTypes);
    }
    Ok(list)
}

// --- segment-list inner decoders -------------------------------------

/// Peel one inner sub-TLV (`Type(1) Length(1|2) Value`) off `input`,
/// honouring the RFC 9012 §3.1 length-width rule. Returns the code, the
/// value slice, and the remaining bytes.
fn take_inner_tlv(input: &[u8]) -> Result<(u8, &[u8], &[u8]), SrPolicyError> {
    let code = input[0];
    let (len, hdr) = if code < 128 {
        if input.len() < 2 {
            return Err(SrPolicyError::Truncated {
                typ: code,
                needed: 2,
                got: input.len(),
            });
        }
        (input[1] as usize, 2)
    } else {
        if input.len() < 3 {
            return Err(SrPolicyError::Truncated {
                typ: code,
                needed: 3,
                got: input.len(),
            });
        }
        (u16::from_be_bytes([input[1], input[2]]) as usize, 3)
    };
    if input.len() < hdr + len {
        return Err(SrPolicyError::Truncated {
            typ: code,
            needed: hdr + len,
            got: input.len(),
        });
    }
    Ok((code, &input[hdr..hdr + len], &input[hdr + len..]))
}

fn parse_weight(v: &[u8]) -> Result<u32, SrPolicyError> {
    // Flags(1) RESERVED(1) Weight(4).
    if v.len() != 6 {
        return Err(SrPolicyError::BadLength {
            typ: SEG_WEIGHT,
            len: v.len(),
            expected: "6",
        });
    }
    Ok(u32::from_be_bytes([v[2], v[3], v[4], v[5]]))
}

fn parse_seg_type_a(v: &[u8]) -> Result<Segment, SrPolicyError> {
    // Flags(1) RESERVED(1) MPLS-label-entry(4).
    if v.len() != 6 {
        return Err(SrPolicyError::BadLength {
            typ: SEG_TYPE_A,
            len: v.len(),
            expected: "6",
        });
    }
    let word = u32::from_be_bytes([v[2], v[3], v[4], v[5]]);
    Ok(Segment::TypeA {
        flags: v[0],
        label: word >> MPLS_LABEL_SHIFT,
    })
}

fn parse_seg_type_b(v: &[u8]) -> Result<Segment, SrPolicyError> {
    // Flags(1) RESERVED(1) SRv6-SID(16) [Structure(8)].
    match v.len() {
        18 | 26 => Ok(Segment::TypeB {
            flags: v[0],
            sid: read_v6(&v[2..18]),
            structure: (v.len() == 26).then(|| read_srv6_structure(&v[18..26])),
        }),
        _ => Err(SrPolicyError::BadLength {
            typ: SEG_TYPE_B,
            len: v.len(),
            expected: "18 or 26",
        }),
    }
}

/// Read a 16-octet SRv6 SID from a slice known to be exactly 16 bytes.
fn read_v6(b: &[u8]) -> Ipv6Addr {
    let mut o = [0u8; 16];
    o.copy_from_slice(b);
    Ipv6Addr::from(o)
}

/// Read the 8-octet SRv6 Endpoint Behavior & SID Structure from a slice
/// known to be exactly 8 bytes.
fn read_srv6_structure(b: &[u8]) -> Srv6BehaviorStructure {
    Srv6BehaviorStructure {
        endpoint_behavior: u16::from_be_bytes([b[0], b[1]]),
        // b[2..4] RESERVED
        locator_block_len: b[4],
        locator_node_len: b[5],
        function_len: b[6],
        argument_len: b[7],
    }
}

// --- emitters --------------------------------------------------------

fn emit_preference(pref: u32) -> Vec<u8> {
    let mut v = vec![0u8, 0u8]; // Flags, RESERVED
    v.extend_from_slice(&pref.to_be_bytes());
    v
}

fn emit_binding_sid(bsid: &BindingSid) -> Vec<u8> {
    let mut v = vec![0u8, 0u8]; // Flags, RESERVED
    match bsid {
        BindingSid::None => {}
        BindingSid::MplsLabel(label) => {
            v.extend_from_slice(&((label & MPLS_LABEL_MASK) << MPLS_LABEL_SHIFT).to_be_bytes());
        }
        BindingSid::Srv6(sid) => v.extend_from_slice(&sid.octets()),
    }
    v
}

fn emit_srv6_binding_sid(s: &Srv6BindingSid) -> Vec<u8> {
    let mut v = vec![s.flags, 0u8]; // Flags, RESERVED
    v.extend_from_slice(&s.sid.octets());
    if let Some(st) = &s.structure {
        emit_srv6_structure(&mut v, st);
    }
    v
}

fn emit_name(name: &str) -> Vec<u8> {
    let mut v = vec![0u8]; // RESERVED
    v.extend_from_slice(name.as_bytes());
    v
}

fn emit_segment_list(sl: &SegmentList) -> Vec<u8> {
    let mut v = vec![0u8]; // RESERVED
    if let Some(w) = sl.weight {
        v.extend_from_slice(&[SEG_WEIGHT, 6, 0, 0]); // type, len, Flags, RESERVED
        v.extend_from_slice(&w.to_be_bytes());
    }
    for seg in &sl.segments {
        emit_segment(&mut v, seg);
    }
    v
}

fn emit_segment(v: &mut Vec<u8>, seg: &Segment) {
    match seg {
        Segment::TypeA { flags, label } => {
            v.extend_from_slice(&[SEG_TYPE_A, 6, *flags, 0]); // type, len, Flags, RESERVED
            v.extend_from_slice(&((label & MPLS_LABEL_MASK) << MPLS_LABEL_SHIFT).to_be_bytes());
        }
        Segment::TypeB {
            flags,
            sid,
            structure,
        } => {
            let len = if structure.is_some() { 26 } else { 18 };
            v.extend_from_slice(&[SEG_TYPE_B, len, *flags, 0]); // type, len, Flags, RESERVED
            v.extend_from_slice(&sid.octets());
            if let Some(st) = structure {
                emit_srv6_structure(v, st);
            }
        }
        Segment::Unknown { code, value } => {
            v.push(*code);
            if *code < 128 {
                v.push(value.len() as u8);
            } else {
                v.extend_from_slice(&(value.len() as u16).to_be_bytes());
            }
            v.extend_from_slice(value);
        }
    }
}

fn emit_srv6_structure(v: &mut Vec<u8>, s: &Srv6BehaviorStructure) {
    v.extend_from_slice(&s.endpoint_behavior.to_be_bytes());
    v.extend_from_slice(&[0u8, 0u8]); // RESERVED(2)
    v.push(s.locator_block_len);
    v.push(s.locator_node_len);
    v.push(s.function_len);
    v.push(s.argument_len);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tlv(sub_tlvs: Vec<TunnelSubTlv>) -> TunnelTlv {
        TunnelTlv {
            tunnel_type: SR_POLICY_TUNNEL_TYPE,
            sub_tlvs,
        }
    }

    /// Decode a TLV, re-encode it, and assert the re-encoded TLV is
    /// byte-identical to `expected` (which should have RESERVED octets
    /// and unmodelled flags zeroed). Returns the decoded view.
    fn round_trip(input: TunnelTlv, expected: &TunnelTlv) -> SrPolicyTlvs {
        let decoded = SrPolicyTlvs::from_tunnel(&input).expect("decode");
        assert_eq!(&decoded.to_tunnel(), expected, "re-encode mismatch");
        decoded
    }

    #[test]
    fn preference_round_trips() {
        let t = tlv(vec![sub(PREFERENCE, vec![0, 0, 0, 0, 0x07, 0xd0])]); // 2000
        let v = round_trip(t.clone(), &t);
        assert_eq!(v.preference, Some(2000));
    }

    #[test]
    fn binding_sid_mpls_round_trips_and_extracts_20bit_label() {
        // label 16001 = 0x3E81 → word = 0x3E81 << 12 = 0x03E81000.
        let word: u32 = 16001 << 12;
        let mut value = vec![0u8, 0u8];
        value.extend_from_slice(&word.to_be_bytes());
        let t = tlv(vec![sub(BINDING_SID, value.clone())]);
        let v = round_trip(t.clone(), &t);
        assert_eq!(v.binding_sid, Some(BindingSid::MplsLabel(16001)));
        // Wire bytes: Flags=0, RESERVED=0, then the 4-octet label entry.
        assert_eq!(v.to_tunnel().sub_tlvs[0].value, value);
    }

    #[test]
    fn binding_sid_none_and_srv6_round_trip() {
        let none = tlv(vec![sub(BINDING_SID, vec![0, 0])]);
        assert_eq!(
            round_trip(none.clone(), &none).binding_sid,
            Some(BindingSid::None)
        );

        let sid: Ipv6Addr = "fc00:0:9::100".parse().unwrap();
        let mut value = vec![0u8, 0u8];
        value.extend_from_slice(&sid.octets());
        let t = tlv(vec![sub(BINDING_SID, value)]);
        assert_eq!(
            round_trip(t.clone(), &t).binding_sid,
            Some(BindingSid::Srv6(sid))
        );
    }

    #[test]
    fn srv6_binding_sid_with_and_without_structure() {
        let sid: Ipv6Addr = "fc00:0:9::100".parse().unwrap();

        // Without structure (len 18), flags = S|I = 0xC0.
        let mut bare = vec![0xC0u8, 0u8];
        bare.extend_from_slice(&sid.octets());
        let t = tlv(vec![sub(SRV6_BINDING_SID, bare)]);
        let v = round_trip(t.clone(), &t);
        let sbsid = v.srv6_binding_sid.clone().unwrap();
        assert_eq!(sbsid.flags, 0xC0);
        assert!(sbsid.structure.is_none());

        // With structure (len 26), B-flag (bit 2 = 0x20) set.
        let mut withst = vec![0x20u8, 0u8];
        withst.extend_from_slice(&sid.octets());
        withst.extend_from_slice(&[0x00, 0x21, 0, 0, 32, 16, 16, 0]); // End.B6.Encaps-ish
        let t = tlv(vec![sub(SRV6_BINDING_SID, withst)]);
        let v = round_trip(t.clone(), &t);
        let st = v.srv6_binding_sid.unwrap().structure.unwrap();
        assert_eq!(st.endpoint_behavior, 0x0021);
        assert_eq!(st.locator_block_len, 32);
        assert_eq!(st.locator_node_len, 16);
        assert_eq!(st.function_len, 16);
        assert_eq!(st.argument_len, 0);
    }

    #[test]
    fn enlp_and_priority_round_trip() {
        let enlp = tlv(vec![sub(ENLP, vec![0, 0, 3])]); // push both
        assert_eq!(round_trip(enlp.clone(), &enlp).enlp, Some(3));

        let prio = tlv(vec![sub(PRIORITY, vec![10, 0])]);
        assert_eq!(round_trip(prio.clone(), &prio).priority, Some(10));
    }

    #[test]
    fn policy_and_cp_names_have_leading_reserved_octet() {
        // RFC 9830 Fig 17/18: value is RESERVED(1) then the UTF-8 name.
        let cp = tlv(vec![sub(CP_NAME, {
            let mut v = vec![0u8];
            v.extend_from_slice(b"cp-1");
            v
        })]);
        let v = round_trip(cp.clone(), &cp);
        assert_eq!(v.cp_name.as_deref(), Some("cp-1"));
        // The name must start at offset 1, after the RESERVED octet.
        assert_eq!(v.to_tunnel().sub_tlvs[0].value[0], 0);
        assert_eq!(&v.to_tunnel().sub_tlvs[0].value[1..], b"cp-1");

        let pol = tlv(vec![sub(POLICY_NAME, {
            let mut v = vec![0u8];
            v.extend_from_slice(b"green");
            v
        })]);
        assert_eq!(
            round_trip(pol.clone(), &pol).policy_name.as_deref(),
            Some("green")
        );

        // Empty name (value is just the RESERVED octet) decodes to "".
        let empty = tlv(vec![sub(POLICY_NAME, vec![0u8])]);
        assert_eq!(
            SrPolicyTlvs::from_tunnel(&empty)
                .unwrap()
                .policy_name
                .as_deref(),
            Some("")
        );
    }

    #[test]
    fn segment_list_weight_and_type_a_label() {
        // RESERVED(1) | Weight(type 9,len 6) | TypeA(type 1,len 6, label 16002).
        let mut value = vec![0u8]; // RESERVED
        value.extend_from_slice(&[SEG_WEIGHT, 6, 0, 0]);
        value.extend_from_slice(&5u32.to_be_bytes()); // weight 5
        value.extend_from_slice(&[SEG_TYPE_A, 6, 0, 0]);
        value.extend_from_slice(&(16002u32 << 12).to_be_bytes());
        let t = tlv(vec![sub(SEGMENT_LIST, value.clone())]);
        let v = round_trip(t.clone(), &t);
        assert_eq!(v.segment_lists.len(), 1);
        assert_eq!(v.segment_lists[0].weight, Some(5));
        assert_eq!(
            v.segment_lists[0].segments,
            vec![Segment::TypeA {
                flags: 0,
                label: 16002
            }]
        );
        assert_eq!(v.to_tunnel().sub_tlvs[0].value, value);
    }

    #[test]
    fn segment_list_type_b_with_structure() {
        let sid: Ipv6Addr = "fc00:0:2::".parse().unwrap();
        let mut value = vec![0u8]; // RESERVED
        // TypeB with B-flag (bit 3 = 0x10) set and an 8-octet structure.
        value.extend_from_slice(&[SEG_TYPE_B, 26, 0x10, 0]);
        value.extend_from_slice(&sid.octets());
        value.extend_from_slice(&[0x00, 0x1b, 0, 0, 40, 24, 16, 0]);
        let t = tlv(vec![sub(SEGMENT_LIST, value.clone())]);
        let v = round_trip(t.clone(), &t);
        match &v.segment_lists[0].segments[0] {
            Segment::TypeB {
                flags,
                sid: got,
                structure,
            } => {
                assert_eq!(*flags, 0x10);
                assert_eq!(*got, sid);
                assert_eq!(structure.as_ref().unwrap().endpoint_behavior, 0x001b);
            }
            other => panic!("expected TypeB, got {other:?}"),
        }
        assert_eq!(v.to_tunnel().sub_tlvs[0].value, value);
    }

    #[test]
    fn full_policy_round_trips_byte_equal() {
        let sid: Ipv6Addr = "fc00:0:9::".parse().unwrap();
        let mut sl1 = vec![0u8];
        sl1.extend_from_slice(&[SEG_WEIGHT, 6, 0, 0]);
        sl1.extend_from_slice(&1u32.to_be_bytes());
        sl1.extend_from_slice(&[SEG_TYPE_B, 18, 0, 0]);
        sl1.extend_from_slice(&sid.octets());

        let mut sl2 = vec![0u8];
        sl2.extend_from_slice(&[SEG_TYPE_A, 6, 0, 0]);
        sl2.extend_from_slice(&(24000u32 << 12).to_be_bytes());

        let mut name = vec![0u8];
        name.extend_from_slice(b"red");

        let input = tlv(vec![
            sub(PREFERENCE, vec![0, 0, 0, 0, 0, 200]),
            sub(BINDING_SID, vec![0, 0]),
            sub(SEGMENT_LIST, sl1),
            sub(SEGMENT_LIST, sl2),
            sub(POLICY_NAME, name),
        ]);
        // Emit order matches input order, so it round-trips byte-equal.
        let v = round_trip(input.clone(), &input);
        assert_eq!(v.preference, Some(200));
        assert_eq!(v.binding_sid, Some(BindingSid::None));
        assert_eq!(v.segment_lists.len(), 2);
        assert_eq!(v.policy_name.as_deref(), Some("red"));
    }

    #[test]
    fn mixed_segment_types_rejected() {
        let sid: Ipv6Addr = "fc00::1".parse().unwrap();
        let mut value = vec![0u8];
        value.extend_from_slice(&[SEG_TYPE_A, 6, 0, 0]);
        value.extend_from_slice(&(100u32 << 12).to_be_bytes());
        value.extend_from_slice(&[SEG_TYPE_B, 18, 0, 0]);
        value.extend_from_slice(&sid.octets());
        let t = tlv(vec![sub(SEGMENT_LIST, value)]);
        assert_eq!(
            SrPolicyTlvs::from_tunnel(&t),
            Err(SrPolicyError::MixedSegmentTypes)
        );
    }

    #[test]
    fn bad_lengths_rejected() {
        assert!(matches!(
            SrPolicyTlvs::from_tunnel(&tlv(vec![sub(PREFERENCE, vec![0, 0, 0, 5])])),
            Err(SrPolicyError::BadLength {
                typ: PREFERENCE,
                ..
            })
        ));
        assert!(matches!(
            SrPolicyTlvs::from_tunnel(&tlv(vec![sub(PRIORITY, vec![1])])),
            Err(SrPolicyError::BadLength { typ: PRIORITY, .. })
        ));
        // Type B with an illegal length (not 18/26).
        let mut value = vec![0u8];
        value.extend_from_slice(&[SEG_TYPE_B, 4, 0, 0, 0xaa, 0xbb]);
        assert!(matches!(
            SrPolicyTlvs::from_tunnel(&tlv(vec![sub(SEGMENT_LIST, value)])),
            Err(SrPolicyError::BadLength {
                typ: SEG_TYPE_B,
                ..
            })
        ));
    }

    #[test]
    fn unknown_segment_code_preserved_as_unknown() {
        // Code 5 = Type E (RFC 9831), not decoded in v1.
        let mut value = vec![0u8];
        value.extend_from_slice(&[5, 4, 0xde, 0xad, 0xbe, 0xef]);
        let t = tlv(vec![sub(SEGMENT_LIST, value.clone())]);
        let v = round_trip(t.clone(), &t);
        assert_eq!(
            v.segment_lists[0].segments,
            vec![Segment::Unknown {
                code: 5,
                value: vec![0xde, 0xad, 0xbe, 0xef]
            }]
        );
    }

    #[test]
    fn unknown_policy_sub_tlv_preserved() {
        // Type 6 (Remote Endpoint, RFC 9012) is not SR-Policy-specific.
        let t = tlv(vec![sub(6, vec![0, 0, 0xfd, 0xe8, 0, 1, 192, 0, 2, 1])]);
        let v = round_trip(t.clone(), &t);
        assert_eq!(v.unknown.len(), 1);
        assert_eq!(v.unknown[0].typ, 6);
    }

    #[test]
    fn not_sr_policy_tunnel_rejected() {
        let t = TunnelTlv {
            tunnel_type: 13, // MPLS-in-GRE
            sub_tlvs: vec![],
        };
        assert_eq!(
            SrPolicyTlvs::from_tunnel(&t),
            Err(SrPolicyError::NotSrPolicy(13))
        );
    }

    #[test]
    fn sr_policy_tlvs_finds_type_15_in_attribute() {
        let enc = TunnelEncap {
            tunnels: vec![
                TunnelTlv {
                    tunnel_type: 13,
                    sub_tlvs: vec![],
                },
                tlv(vec![sub(PREFERENCE, vec![0, 0, 0, 0, 0, 100])]),
            ],
        };
        let v = sr_policy_tlvs(&enc).expect("present").expect("decode");
        assert_eq!(v.preference, Some(100));

        let no_sr = TunnelEncap {
            tunnels: vec![TunnelTlv {
                tunnel_type: 13,
                sub_tlvs: vec![],
            }],
        };
        assert!(sr_policy_tlvs(&no_sr).is_none());
    }
}
