use std::fmt;
use std::net::Ipv6Addr;

use bytes::{BufMut, BytesMut};
use nom::IResult;
use nom::number::complete::{be_u8, be_u16, be_u32};

use crate::{AttrType, ParseBe};

use super::{AttrEmitter, AttrFlags};

/// SRv6 Endpoint Behavior codepoints (IANA "SRv6 Endpoint Behaviors",
/// RFC 8986). Only the L3VPN-relevant decap behaviors are named here.
pub const SRV6_BEHAVIOR_END_DT6: u16 = 0x0012;
pub const SRV6_BEHAVIOR_END_DT4: u16 = 0x0013;
pub const SRV6_BEHAVIOR_END_DT46: u16 = 0x0014;

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

/// An SRv6 Service TLV body (RFC 9252 §2): an ordered list of SRv6 SID
/// Information sub-TLVs. The L3VPN case carries exactly one.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct Srv6ServiceTlv {
    pub sids: Vec<Srv6SidInfo>,
}

/// SRv6 SID Information Sub-TLV (RFC 9252 §3.1).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Srv6SidInfo {
    /// The 16-byte SRv6 SID value (e.g. an End.DT46 SID).
    pub sid: Ipv6Addr,
    /// SRv6 Service SID Flags.
    pub flags: u8,
    /// SRv6 Endpoint Behavior (one of the `SRV6_BEHAVIOR_*` codepoints).
    pub behavior: u16,
    /// SRv6 SID Structure Sub-Sub-TLV, when present.
    pub structure: Option<Srv6SidStructure>,
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
        1 => {
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
        3 => {
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
        5 => {
            let (_, svc) = decode_srv6_service(value)?;
            Ok((&[], PrefixSidTlv::Srv6L3Service(svc)))
        }
        6 => {
            let (_, svc) = decode_srv6_service(value)?;
            Ok((&[], PrefixSidTlv::Srv6L2Service(svc)))
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
/// byte then SRv6 SID Information sub-TLVs. Unknown sub-/sub-sub-TLVs
/// are skipped (we re-emit canonically), but their length is honoured
/// so the walk stays aligned.
fn decode_srv6_service(value: &[u8]) -> IResult<&[u8], Srv6ServiceTlv> {
    let (mut rest, _reserved) = be_u8(value)?;
    let mut sids = Vec::new();
    while !rest.is_empty() {
        let (r, sub_type) = be_u8(rest)?;
        let (r, sub_len) = be_u16(r)?;
        let (r, sub_val) = nom::bytes::complete::take(sub_len as usize)(r)?;
        rest = r;
        if sub_type != 1 {
            continue; // only SID Information sub-TLVs are modelled
        }
        // SID Information: RESERVED1(1) SID(16) Flags(1) Behavior(2) RESERVED2(1).
        let (sv, _reserved1) = be_u8(sub_val)?;
        let (sv, sid_bytes) = nom::bytes::complete::take(16usize)(sv)?;
        let mut octets = [0u8; 16];
        octets.copy_from_slice(sid_bytes);
        let sid = Ipv6Addr::from(octets);
        let (sv, flags) = be_u8(sv)?;
        let (sv, behavior) = be_u16(sv)?;
        let (mut sv, _reserved2) = be_u8(sv)?;
        let mut structure = None;
        while !sv.is_empty() {
            let (s, ss_type) = be_u8(sv)?;
            let (s, ss_len) = be_u16(s)?;
            let (s, ss_val) = nom::bytes::complete::take(ss_len as usize)(s)?;
            sv = s;
            if ss_type == 1 && ss_val.len() >= 6 {
                structure = Some(Srv6SidStructure {
                    locator_block_len: ss_val[0],
                    locator_node_len: ss_val[1],
                    function_len: ss_val[2],
                    argument_len: ss_val[3],
                    transposition_len: ss_val[4],
                    transposition_offset: ss_val[5],
                });
            }
        }
        sids.push(Srv6SidInfo {
            sid,
            flags,
            behavior,
            structure,
        });
    }
    Ok((&[], Srv6ServiceTlv { sids }))
}

/// Encoded length of an SRv6 Service TLV body: RESERVED(1) + each SID
/// Information sub-TLV (header 3 + 21 body + optional 9-byte structure
/// sub-sub-TLV).
fn srv6_service_len(svc: &Srv6ServiceTlv) -> usize {
    let mut len = 1;
    for sid in &svc.sids {
        len += 3 + 21 + if sid.structure.is_some() { 9 } else { 0 };
    }
    len
}

fn emit_srv6_service(buf: &mut BytesMut, svc: &Srv6ServiceTlv) {
    buf.put_u8(0); // RESERVED
    for sid in &svc.sids {
        let sub_len = 21 + if sid.structure.is_some() { 9 } else { 0 };
        buf.put_u8(1); // SID Information sub-TLV
        buf.put_u16(sub_len as u16);
        buf.put_u8(0); // RESERVED1
        buf.put(&sid.sid.octets()[..]);
        buf.put_u8(sid.flags);
        buf.put_u16(sid.behavior);
        buf.put_u8(0); // RESERVED2
        if let Some(st) = sid.structure {
            buf.put_u8(1); // SID Structure sub-sub-TLV
            buf.put_u16(6);
            buf.put_u8(st.locator_block_len);
            buf.put_u8(st.locator_node_len);
            buf.put_u8(st.function_len);
            buf.put_u8(st.argument_len);
            buf.put_u8(st.transposition_len);
            buf.put_u8(st.transposition_offset);
        }
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

    fn round_trip(sid: PrefixSid) -> PrefixSid {
        let mut buf = BytesMut::new();
        sid.emit(&mut buf);
        let bytes: Vec<u8> = buf.to_vec();
        let (rest, parsed) = PrefixSid::parse_be(&bytes).expect("parse");
        assert!(rest.is_empty(), "trailing bytes after parse");
        parsed
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
                sids: vec![Srv6SidInfo {
                    sid: "2001:db8:1:1::".parse().unwrap(),
                    flags: 0,
                    behavior: SRV6_BEHAVIOR_END_DT46,
                    structure: Some(Srv6SidStructure {
                        locator_block_len: 32,
                        locator_node_len: 16,
                        function_len: 16,
                        argument_len: 0,
                        transposition_len: 0,
                        transposition_offset: 0,
                    }),
                }],
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
    fn srv6_sid_without_structure_round_trips() {
        let sid = PrefixSid {
            tlvs: vec![PrefixSidTlv::Srv6L3Service(Srv6ServiceTlv {
                sids: vec![Srv6SidInfo {
                    sid: "2001:db8::1".parse().unwrap(),
                    flags: 0,
                    behavior: SRV6_BEHAVIOR_END_DT4,
                    structure: None,
                }],
            })],
        };
        assert_eq!(round_trip(sid.clone()), sid);
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
