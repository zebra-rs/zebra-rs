use std::fmt;

use bytes::{BufMut, BytesMut};
use nom::IResult;
use nom::number::complete::{be_u8, be_u16};

use crate::{AttrType, ParseBe};

use super::{AttrEmitter, AttrFlags};

/// BGP Tunnel Encapsulation path attribute (type 23, RFC 9012).
///
/// Carries an ordered list of Tunnel TLVs; each TLV nests an ordered
/// list of Sub-TLVs whose length-field width depends on the Sub-TLV
/// Type (1 octet when type < 128, 2 octets when type >= 128, per
/// RFC 9012 §3.1). v1 decodes the framing structurally and leaves
/// Sub-TLV values as opaque bytes — type-specific decoders
/// (Preference, Remote-Endpoint, Binding-SID, Segment List, …) land
/// in follow-up PRs alongside the consumers that need them.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct TunnelEncap {
    pub tunnels: Vec<TunnelTlv>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TunnelTlv {
    /// IANA Tunnel Type registry — 13 = MPLS-in-GRE, 15 = SR Policy,
    /// etc. Unknown values are preserved verbatim and propagated.
    pub tunnel_type: u16,
    pub sub_tlvs: Vec<TunnelSubTlv>,
}

/// Opaque sub-TLV. Type-specific decoding (Color, Preference,
/// Remote-Endpoint, Binding-SID, Segment List, Policy-Name,
/// Policy-Candidate-Path-Name, ...) is the next layer of work.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TunnelSubTlv {
    pub typ: u8,
    pub value: Vec<u8>,
}

impl ParseBe<TunnelEncap> for TunnelEncap {
    fn parse_be(input: &[u8]) -> IResult<&[u8], TunnelEncap> {
        let mut remaining = input;
        let mut tunnels = Vec::new();
        while !remaining.is_empty() {
            let (rest, tunnel_type) = be_u16(remaining)?;
            let (rest, len) = be_u16(rest)?;
            let (rest, value) = nom::bytes::complete::take(len as usize)(rest)?;
            let (_, sub_tlvs) = parse_sub_tlvs(value)?;
            tunnels.push(TunnelTlv {
                tunnel_type,
                sub_tlvs,
            });
            remaining = rest;
        }
        Ok((remaining, TunnelEncap { tunnels }))
    }
}

/// Walk a Tunnel TLV's value bytes, peeling off sub-TLVs whose length
/// width depends on the type code (RFC 9012 §3.1).
fn parse_sub_tlvs(input: &[u8]) -> IResult<&[u8], Vec<TunnelSubTlv>> {
    let mut remaining = input;
    let mut out = Vec::new();
    while !remaining.is_empty() {
        let (rest, typ) = be_u8(remaining)?;
        let (rest, len) = if typ < 128 {
            let (r, l) = be_u8(rest)?;
            (r, l as u16)
        } else {
            be_u16(rest)?
        };
        let (rest, value) = nom::bytes::complete::take(len as usize)(rest)?;
        out.push(TunnelSubTlv {
            typ,
            value: value.to_vec(),
        });
        remaining = rest;
    }
    Ok((remaining, out))
}

impl TunnelEncap {
    fn encoded_len(&self) -> usize {
        self.tunnels.iter().map(tunnel_encoded_len).sum()
    }
}

fn tunnel_encoded_len(tunnel: &TunnelTlv) -> usize {
    // Tunnel header: 2 (type) + 2 (length) = 4.
    4 + tunnel.sub_tlvs.iter().map(sub_encoded_len).sum::<usize>()
}

fn sub_encoded_len(sub: &TunnelSubTlv) -> usize {
    let header = if sub.typ < 128 { 2 } else { 3 };
    header + sub.value.len()
}

fn emit_sub_tlv(buf: &mut BytesMut, sub: &TunnelSubTlv) {
    buf.put_u8(sub.typ);
    if sub.typ < 128 {
        buf.put_u8(sub.value.len() as u8);
    } else {
        buf.put_u16(sub.value.len() as u16);
    }
    buf.put(&sub.value[..]);
}

fn emit_tunnel(buf: &mut BytesMut, tunnel: &TunnelTlv) {
    buf.put_u16(tunnel.tunnel_type);
    let body_len: usize = tunnel.sub_tlvs.iter().map(sub_encoded_len).sum();
    buf.put_u16(body_len as u16);
    for sub in &tunnel.sub_tlvs {
        emit_sub_tlv(buf, sub);
    }
}

impl AttrEmitter for TunnelEncap {
    fn attr_flags(&self) -> AttrFlags {
        // RFC 9012 §2: Optional Transitive.
        AttrFlags::new().with_optional(true).with_transitive(true)
    }

    fn attr_type(&self) -> AttrType {
        AttrType::TunnelEncap
    }

    fn len(&self) -> Option<usize> {
        Some(self.encoded_len())
    }

    fn emit(&self, buf: &mut BytesMut) {
        for tunnel in &self.tunnels {
            emit_tunnel(buf, tunnel);
        }
    }
}

impl fmt::Display for TunnelEncap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TunnelEncap[")?;
        for (i, t) in self.tunnels.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "type={} subs={}", t.tunnel_type, t.sub_tlvs.len())?;
        }
        write!(f, "]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(orig: TunnelEncap) -> TunnelEncap {
        let mut buf = BytesMut::new();
        orig.emit(&mut buf);
        let bytes: Vec<u8> = buf.to_vec();
        let (rest, parsed) = TunnelEncap::parse_be(&bytes).expect("parse");
        assert!(rest.is_empty(), "trailing bytes after parse");
        parsed
    }

    #[test]
    fn empty_attribute_parses_to_empty_list() {
        let (rest, parsed) = TunnelEncap::parse_be(&[]).expect("empty");
        assert!(rest.is_empty());
        assert!(parsed.tunnels.is_empty());
    }

    #[test]
    fn one_tunnel_with_no_sub_tlvs_round_trips() {
        // Tunnel-Type 15 (SR Policy) with no sub-TLVs.
        let enc = TunnelEncap {
            tunnels: vec![TunnelTlv {
                tunnel_type: 15,
                sub_tlvs: vec![],
            }],
        };
        assert_eq!(round_trip(enc.clone()), enc);
    }

    #[test]
    fn short_sub_tlv_uses_one_byte_length() {
        // Sub-TLV type 4 (Color, < 128) → 1-octet length field.
        let enc = TunnelEncap {
            tunnels: vec![TunnelTlv {
                tunnel_type: 15,
                sub_tlvs: vec![TunnelSubTlv {
                    typ: 4,
                    value: vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64],
                }],
            }],
        };
        let mut buf = BytesMut::new();
        enc.emit(&mut buf);
        let bytes: Vec<u8> = buf.to_vec();
        // Layout: tunnel_type(2) + tlen(2) + sub_type(1) + sub_len(1) + value(8) = 14
        assert_eq!(bytes.len(), 14);
        // Sub-TLV header at offset 4: type=4, then 1-octet length=8.
        assert_eq!(bytes[4], 4);
        assert_eq!(bytes[5], 8);
        assert_eq!(round_trip(enc.clone()), enc);
    }

    #[test]
    fn long_sub_tlv_uses_two_byte_length() {
        // Sub-TLV type 128 (Segment List, >= 128) → 2-octet length.
        let payload = vec![0xab; 300];
        let enc = TunnelEncap {
            tunnels: vec![TunnelTlv {
                tunnel_type: 15,
                sub_tlvs: vec![TunnelSubTlv {
                    typ: 128,
                    value: payload.clone(),
                }],
            }],
        };
        let mut buf = BytesMut::new();
        enc.emit(&mut buf);
        let bytes: Vec<u8> = buf.to_vec();
        // Sub-TLV header at offset 4: type=128, then 2-octet length=300.
        assert_eq!(bytes[4], 128);
        let len_field = u16::from_be_bytes([bytes[5], bytes[6]]);
        assert_eq!(len_field, 300);
        assert_eq!(round_trip(enc.clone()), enc);
    }

    #[test]
    fn multiple_tunnels_with_mixed_sub_tlvs_preserve_order() {
        let enc = TunnelEncap {
            tunnels: vec![
                TunnelTlv {
                    tunnel_type: 13, // MPLS-in-GRE
                    sub_tlvs: vec![TunnelSubTlv {
                        typ: 6, // Preference
                        value: vec![0, 0, 0, 0, 0x07, 0xd0],
                    }],
                },
                TunnelTlv {
                    tunnel_type: 15, // SR Policy
                    sub_tlvs: vec![
                        TunnelSubTlv {
                            typ: 12, // Remote-Endpoint
                            value: vec![0, 0, 0xfd, 0xe8, 0, 1, 192, 0, 2, 1],
                        },
                        TunnelSubTlv {
                            typ: 128, // Segment List
                            value: vec![0xde, 0xad, 0xbe, 0xef],
                        },
                    ],
                },
            ],
        };
        let rt = round_trip(enc.clone());
        assert_eq!(rt, enc);
        assert_eq!(rt.tunnels.len(), 2);
        assert_eq!(rt.tunnels[0].tunnel_type, 13);
        assert_eq!(rt.tunnels[1].sub_tlvs.len(), 2);
        assert_eq!(rt.tunnels[1].sub_tlvs[0].typ, 12);
        assert_eq!(rt.tunnels[1].sub_tlvs[1].typ, 128);
    }

    #[test]
    fn unknown_tunnel_type_round_trips_verbatim() {
        let enc = TunnelEncap {
            tunnels: vec![TunnelTlv {
                tunnel_type: 9999,
                sub_tlvs: vec![TunnelSubTlv {
                    typ: 200,
                    value: vec![0x01, 0x02, 0x03],
                }],
            }],
        };
        assert_eq!(round_trip(enc.clone()), enc);
    }

    #[test]
    fn truncated_tunnel_length_is_rejected() {
        // Tunnel claims length 10 but only 5 bytes of value follow.
        let bytes: Vec<u8> = vec![
            0, 15, // tunnel_type
            0, 10, // length 10
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, // only 5 bytes
        ];
        assert!(TunnelEncap::parse_be(&bytes).is_err());
    }

    #[test]
    fn truncated_short_sub_tlv_length_is_rejected() {
        let bytes: Vec<u8> = vec![
            0, 15, // tunnel_type
            0, 4, // tlen = 4
            4, // sub type (short)
            6, // sub len 6
            0xaa, 0xbb, // only 2 bytes
        ];
        assert!(TunnelEncap::parse_be(&bytes).is_err());
    }

    #[test]
    fn long_sub_tlv_with_short_header_field_underrun_rejected() {
        // Sub-TLV type 200 requires a 2-octet length field but only
        // 1 byte after the type is present.
        let bytes: Vec<u8> = vec![
            0, 15, // tunnel_type
            0, 2,   // tlen = 2
            200, // type
            0,   // truncated length byte
        ];
        assert!(TunnelEncap::parse_be(&bytes).is_err());
    }
}
