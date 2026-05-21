use std::fmt;

use bytes::{BufMut, BytesMut};
use nom::IResult;
use nom::number::complete::{be_u8, be_u16, be_u32};

use crate::{AttrType, ParseBe};

use super::{AttrEmitter, AttrFlags};

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

    /// RFC 9252 §2 SRv6 L3 Service TLV. Opaque bytes for v1 — the
    /// nested sub-TLV / sub-sub-TLV structure (SRv6 Services SID
    /// Information, SID Structure) is decoded by the SRv6-services
    /// PR. Storing the raw payload here keeps round-trip exact and
    /// lets policy / show layers surface the attribute today.
    Srv6L3Service(Vec<u8>),

    /// RFC 9252 §2 SRv6 L2 Service TLV. Same parse-and-store
    /// treatment as the L3 variant.
    Srv6L2Service(Vec<u8>),

    /// Unknown TLV type — preserved verbatim so a router that doesn't
    /// understand a new IANA codepoint can still propagate the
    /// attribute byte-for-byte.
    Unknown { typ: u8, value: Vec<u8> },
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
        5 => Ok((&[], PrefixSidTlv::Srv6L3Service(value.to_vec()))),
        6 => Ok((&[], PrefixSidTlv::Srv6L2Service(value.to_vec()))),
        other => Ok((
            &[],
            PrefixSidTlv::Unknown {
                typ: other,
                value: value.to_vec(),
            },
        )),
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
        PrefixSidTlv::Srv6L3Service(v) | PrefixSidTlv::Srv6L2Service(v) => v.len(),
        PrefixSidTlv::Unknown { value, .. } => value.len(),
    };
    3 + body
}

fn emit_tlv(buf: &mut BytesMut, tlv: &PrefixSidTlv) {
    let (typ, body_len) = match tlv {
        PrefixSidTlv::LabelIndex { .. } => (1u8, 7u16),
        PrefixSidTlv::OriginatorSrgb { srgbs, .. } => (3u8, (2 + srgbs.len() * 6) as u16),
        PrefixSidTlv::Srv6L3Service(v) => (5u8, v.len() as u16),
        PrefixSidTlv::Srv6L2Service(v) => (6u8, v.len() as u16),
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
        PrefixSidTlv::Srv6L3Service(v) | PrefixSidTlv::Srv6L2Service(v) => {
            buf.put(&v[..]);
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
                PrefixSidTlv::Srv6L3Service(v) => {
                    write!(f, "SRv6L3Service({} bytes)", v.len())?;
                }
                PrefixSidTlv::Srv6L2Service(v) => {
                    write!(f, "SRv6L2Service({} bytes)", v.len())?;
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
    fn srv6_service_tlvs_parse_as_opaque() {
        let sid = PrefixSid {
            tlvs: vec![
                PrefixSidTlv::Srv6L3Service(vec![0u8, 0x01, 0x02, 0x03]),
                PrefixSidTlv::Srv6L2Service(vec![0xaa, 0xbb]),
            ],
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
