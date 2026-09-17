use std::fmt;

use bytes::{BufMut, BytesMut};
use nom::IResult;
use nom::bytes::complete::take;
use nom::number::complete::be_u16;
use serde::Serialize;

use crate::{AttrEmitter, AttrFlags, AttrType, ParseBe};

// BGP-LS Attribute (BGP path attribute type 29, RFC 9552 Section 4).
//
// Optional, non-transitive. Its value is a flat sequence of TLVs (Type: 2
// octets, Length: 2 octets, Value) that carry the Node, Link, and Prefix
// attributes for the Link-State NLRI(s) advertised in the companion
// MP_REACH_NLRI. TLVs are modeled as a preserved list: unknown and
// not-yet-typed codepoints round-trip and are reflected unchanged, which
// RFC 9552 Section 5.1 requires ("a BGP-LS Propagator ... MUST preserve and
// propagate unrecognized TLVs").
//
// Typed construction/decoding of individual TLVs (Node Name, IGP Metric,
// Adjacency SID, SR Capabilities, ...) is layered on top of this list by the
// IS-IS producer and the show path in later phases.

// ===== Node Attribute TLVs (RFC 9552 Section 4.1, RFC 9085) =====
/// Multi-Topology Identifier (also a descriptor codepoint; here it lists every
/// reachable topology for the node).
pub const BGPLS_ATTR_MULTI_TOPOLOGY_ID: u16 = 263;
pub const BGPLS_ATTR_NODE_FLAG_BITS: u16 = 1024;
pub const BGPLS_ATTR_OPAQUE_NODE: u16 = 1025;
pub const BGPLS_ATTR_NODE_NAME: u16 = 1026;
pub const BGPLS_ATTR_ISIS_AREA_ID: u16 = 1027;
pub const BGPLS_ATTR_IPV4_ROUTER_ID_LOCAL: u16 = 1028;
pub const BGPLS_ATTR_IPV6_ROUTER_ID_LOCAL: u16 = 1029;
pub const BGPLS_ATTR_SR_CAPABILITIES: u16 = 1034;
pub const BGPLS_ATTR_SR_ALGORITHM: u16 = 1035;
pub const BGPLS_ATTR_SR_LOCAL_BLOCK: u16 = 1036;
pub const BGPLS_ATTR_SRV6_CAPABILITIES: u16 = 1038;

// ===== Link Attribute TLVs (RFC 9552 Section 4.2, RFC 9085) =====
pub const BGPLS_ATTR_IPV4_ROUTER_ID_REMOTE: u16 = 1030;
pub const BGPLS_ATTR_IPV6_ROUTER_ID_REMOTE: u16 = 1031;
pub const BGPLS_ATTR_ADMIN_GROUP: u16 = 1088;
pub const BGPLS_ATTR_MAX_LINK_BANDWIDTH: u16 = 1089;
pub const BGPLS_ATTR_MAX_RESERVABLE_BANDWIDTH: u16 = 1090;
pub const BGPLS_ATTR_UNRESERVED_BANDWIDTH: u16 = 1091;
pub const BGPLS_ATTR_TE_DEFAULT_METRIC: u16 = 1092;
pub const BGPLS_ATTR_LINK_PROTECTION_TYPE: u16 = 1093;
pub const BGPLS_ATTR_MPLS_PROTOCOL_MASK: u16 = 1094;
pub const BGPLS_ATTR_IGP_METRIC: u16 = 1095;
pub const BGPLS_ATTR_SRLG: u16 = 1096;
pub const BGPLS_ATTR_OPAQUE_LINK: u16 = 1097;
pub const BGPLS_ATTR_LINK_NAME: u16 = 1098;
pub const BGPLS_ATTR_ADJACENCY_SID: u16 = 1099;
pub const BGPLS_ATTR_LAN_ADJACENCY_SID: u16 = 1100;
/// RFC 9104 — Extended Administrative Group (link attribute), distinct
/// from the classic Administrative Group (1088).
pub const BGPLS_ATTR_EXT_ADMIN_GROUP: u16 = 1173;

// ===== TE performance link attributes (RFC 8571) =====
//
// The value encodings are byte-identical to their IGP originals — the
// same A (Anomalous) bit in the top bit of the first octet and the same
// 24-bit microsecond fields — so a producer re-emits what it parsed
// from IS-IS RFC 8570 sub-TLVs 33-39 / OSPF RFC 7471 sub-TLVs 27-33
// without rescaling.
/// Unidirectional Link Delay (RFC 8571 §2.1): `A|RESERVED(7)` then a
/// 24-bit average delay in microseconds. 4 octets.
pub const BGPLS_ATTR_UNI_LINK_DELAY: u16 = 1114;
/// Min/Max Unidirectional Link Delay (RFC 8571 §2.2): `A|RESERVED(7)`
/// then 24-bit Min, then `RESERVED(8)` then 24-bit Max. 8 octets. One A
/// bit covers both bounds.
pub const BGPLS_ATTR_MIN_MAX_LINK_DELAY: u16 = 1115;
/// Unidirectional Delay Variation (RFC 8571 §2.3): `RESERVED(8)` then a
/// 24-bit value. 4 octets, and no A bit — the RFC defines none.
pub const BGPLS_ATTR_DELAY_VARIATION: u16 = 1116;
/// Unidirectional Link Loss (RFC 8571 §2.4): `A|RESERVED(7)` then a
/// 24-bit loss ratio in units of 0.000003 %. 4 octets.
pub const BGPLS_ATTR_LINK_LOSS: u16 = 1117;
/// Unidirectional Residual Bandwidth (RFC 8571 §2.5): IEEE 754
/// single-precision bytes/sec. 4 octets, no flags.
pub const BGPLS_ATTR_RESIDUAL_BANDWIDTH: u16 = 1118;
/// Unidirectional Available Bandwidth (RFC 8571 §2.6).
pub const BGPLS_ATTR_AVAILABLE_BANDWIDTH: u16 = 1119;
/// Unidirectional Utilized Bandwidth (RFC 8571 §2.7).
pub const BGPLS_ATTR_UTILIZED_BANDWIDTH: u16 = 1120;

/// Application-Specific Link Attributes (RFC 9294 §2), type 1122.
///
/// Carries link attributes that the IGP scoped to particular
/// applications, with that scope intact. RFC 9294 §2 is explicit that
/// attributes received in an IGP ASLA MUST be re-encoded here rather
/// than flattened into the top-level TLVs — a Flex-Algorithm-only delay
/// promoted to top level would read as an RSVP-TE attribute too.
pub const BGPLS_ATTR_ASLA: u16 = 1122;

/// Widen an IGP Application Identifier Bit Mask to a length BGP-LS
/// accepts.
///
/// RFC 9294 §2 inherits the OSPF encoding (RFC 8920 §3.1): a mask is
/// "of size 0, 4, or 8 octets as indicated by the SABM Length". IS-IS
/// instead advertises the shortest mask that carries its set bits
/// (RFC 9479 §4.1), so the ordinary one-octet `[0x10]` Flex-Algorithm
/// mask is not a legal BGP-LS length and a conformant consumer cannot
/// read the TLV.
///
/// Bits are numbered from the most significant bit of the first octet,
/// so zero-padding on the right widens the mask without moving any bit.
/// A mask longer than 8 octets cannot reach here from a parsed IS-IS
/// ASLA — RFC 9479 §4.2 caps it at 8 and our parser rejects more — but
/// it is truncated rather than trusted.
fn normalize_mask(mask: &[u8]) -> Vec<u8> {
    let width = match mask.len() {
        0 => return Vec::new(),
        n if n <= 4 => 4,
        _ => 8,
    };
    let mut out = mask.to_vec();
    out.truncate(width);
    out.resize(width, 0);
    out
}

/// Encode the value of a BGP-LS ASLA TLV (RFC 9294 §2):
/// `SABM Length | UDABM Length | Reserved(2) | SABM | UDABM | sub-TLVs`,
/// where the nested sub-TLVs use the ordinary BGP-LS 2-octet type and
/// 2-octet length. The two reserved octets MUST be zero on transmit.
///
/// Both masks are widened to a BGP-LS-legal length by
/// [`normalize_mask`]; their bit assignments are shared with the IGP
/// (RSVP-TE, SR Policy, LFA, Flex-Algorithm), so the scope survives.
pub fn bgpls_asla_value(sabm: &[u8], udabm: &[u8], subs: &[BgpLsAttrTlv]) -> Vec<u8> {
    let sabm = normalize_mask(sabm);
    let udabm = normalize_mask(udabm);
    let mut out = Vec::with_capacity(4 + sabm.len() + udabm.len());
    out.push(sabm.len() as u8);
    out.push(udabm.len() as u8);
    out.extend_from_slice(&[0, 0]); // Reserved
    out.extend_from_slice(&sabm);
    out.extend_from_slice(&udabm);
    for sub in subs {
        out.extend_from_slice(&sub.typ.to_be_bytes());
        out.extend_from_slice(&(sub.value.len() as u16).to_be_bytes());
        out.extend_from_slice(&sub.value);
    }
    out
}

// ===== Prefix Attribute TLVs (RFC 9552 Section 4.3, RFC 9085) =====
pub const BGPLS_ATTR_IGP_FLAGS: u16 = 1152;
pub const BGPLS_ATTR_IGP_ROUTE_TAG: u16 = 1153;
pub const BGPLS_ATTR_IGP_EXTENDED_ROUTE_TAG: u16 = 1154;
pub const BGPLS_ATTR_PREFIX_METRIC: u16 = 1155;
pub const BGPLS_ATTR_OSPF_FORWARDING_ADDRESS: u16 = 1156;
pub const BGPLS_ATTR_OPAQUE_PREFIX: u16 = 1157;
pub const BGPLS_ATTR_PREFIX_SID: u16 = 1158;

/// A single TLV inside the BGP-LS Attribute, kept verbatim so the attribute
/// round-trips and reflects unrecognized codepoints unchanged.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct BgpLsAttrTlv {
    pub typ: u16,
    pub value: Vec<u8>,
}

impl BgpLsAttrTlv {
    pub fn new(typ: u16, value: Vec<u8>) -> Self {
        Self { typ, value }
    }
}

/// The BGP-LS Attribute (path attribute type 29): an ordered list of TLVs.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize)]
pub struct BgpLsAttr {
    pub tlvs: Vec<BgpLsAttrTlv>,
}

impl BgpLsAttr {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.tlvs.is_empty()
    }

    /// Append a TLV.
    pub fn push(&mut self, typ: u16, value: Vec<u8>) {
        self.tlvs.push(BgpLsAttrTlv::new(typ, value));
    }

    /// First TLV value for `typ`, if present.
    pub fn get(&self, typ: u16) -> Option<&[u8]> {
        self.tlvs
            .iter()
            .find(|t| t.typ == typ)
            .map(|t| t.value.as_slice())
    }

    /// Parse the BGP-LS Attribute value (the bytes after the attribute header)
    /// into its TLV list.
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let mut tlvs = Vec::new();
        let mut rest = input;
        while !rest.is_empty() {
            let (next, typ) = be_u16(rest)?;
            let (next, len) = be_u16(next)?;
            let (next, value) = take(len as usize)(next)?;
            tlvs.push(BgpLsAttrTlv {
                typ,
                value: value.to_vec(),
            });
            rest = next;
        }
        Ok((rest, BgpLsAttr { tlvs }))
    }
}

impl ParseBe<BgpLsAttr> for BgpLsAttr {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        Self::parse(input)
    }
}

impl AttrEmitter for BgpLsAttr {
    fn attr_flags(&self) -> AttrFlags {
        // Optional, non-transitive (RFC 9552 Section 4). The extended-length
        // bit is managed by `attr_emit` from the computed length.
        AttrFlags::new().with_optional(true)
    }

    fn attr_type(&self) -> AttrType {
        AttrType::BgpLsAttr
    }

    fn len(&self) -> Option<usize> {
        // Variable; let `attr_emit` buffer the value and pick (extended)
        // length encoding. BGP-LS attributes commonly exceed 255 octets.
        None
    }

    fn emit(&self, buf: &mut BytesMut) {
        for tlv in &self.tlvs {
            buf.put_u16(tlv.typ);
            buf.put_u16(tlv.value.len() as u16);
            buf.put_slice(&tlv.value);
        }
    }
}

impl fmt::Display for BgpLsAttr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BGP-LS[")?;
        for (i, tlv) in self.tlvs.iter().enumerate() {
            if i != 0 {
                f.write_str(",")?;
            }
            write!(f, "{}({})", tlv.typ, tlv.value.len())?;
        }
        f.write_str("]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Emit the full attribute (header + value), assert the header is a valid
    /// BGP-LS Attribute, and parse the value back.
    fn emit_and_parse(attr: &BgpLsAttr) -> (BgpLsAttr, bool) {
        let mut buf = BytesMut::new();
        attr.attr_emit(&mut buf);

        // Attribute flag byte: optional (0x80) set, transitive (0x40) clear,
        // extended-length (0x10) set only for values > 255 octets.
        let flags = buf[0];
        assert!(flags & 0x80 != 0, "must be optional");
        assert!(flags & 0x40 == 0, "must be non-transitive");
        assert_eq!(AttrType::from(buf[1]), AttrType::BgpLsAttr);

        let extended = flags & 0x10 != 0;
        let (off, len) = if extended {
            (4usize, u16::from_be_bytes([buf[2], buf[3]]) as usize)
        } else {
            (3usize, buf[2] as usize)
        };
        let payload = &buf[off..off + len];
        let (rest, parsed) = BgpLsAttr::parse(payload).expect("parse");
        assert!(rest.is_empty(), "trailing bytes after parse");
        (parsed, extended)
    }

    #[test]
    fn attr_type_round_trip() {
        assert_eq!(u8::from(AttrType::BgpLsAttr), 29);
        assert_eq!(AttrType::from(29u8), AttrType::BgpLsAttr);
    }

    #[test]
    fn empty_attribute_round_trips() {
        let attr = BgpLsAttr::new();
        let (back, extended) = emit_and_parse(&attr);
        assert_eq!(back, attr);
        assert!(!extended);
    }

    #[test]
    fn node_attrs_round_trip() {
        let mut attr = BgpLsAttr::new();
        attr.push(BGPLS_ATTR_NODE_NAME, b"router1".to_vec());
        attr.push(BGPLS_ATTR_NODE_FLAG_BITS, vec![0x80]);
        attr.push(BGPLS_ATTR_ISIS_AREA_ID, vec![0x49, 0x00, 0x01]);
        let (back, extended) = emit_and_parse(&attr);
        assert_eq!(back, attr);
        assert!(!extended);
        assert_eq!(back.get(BGPLS_ATTR_NODE_NAME), Some(&b"router1"[..]));
    }

    #[test]
    fn link_attrs_round_trip() {
        let mut attr = BgpLsAttr::new();
        attr.push(BGPLS_ATTR_ADMIN_GROUP, vec![0, 0, 0, 0x0f]);
        attr.push(
            BGPLS_ATTR_EXT_ADMIN_GROUP,
            vec![0x01, 0x02, 0x03, 0x04, 0xaa, 0xbb, 0xcc, 0xdd],
        );
        // Maximum link bandwidth: IEEE 754 f32 (1 Gbit/s).
        attr.push(
            BGPLS_ATTR_MAX_LINK_BANDWIDTH,
            1.0e9f32.to_be_bytes().to_vec(),
        );
        attr.push(BGPLS_ATTR_TE_DEFAULT_METRIC, vec![0, 0, 0, 10]);
        attr.push(BGPLS_ATTR_IGP_METRIC, vec![0, 10]);
        let (back, _) = emit_and_parse(&attr);
        assert_eq!(back, attr);
    }

    #[test]
    fn prefix_attrs_round_trip() {
        let mut attr = BgpLsAttr::new();
        attr.push(BGPLS_ATTR_IGP_FLAGS, vec![0x00]);
        attr.push(BGPLS_ATTR_PREFIX_METRIC, vec![0, 0, 0, 20]);
        attr.push(BGPLS_ATTR_IGP_ROUTE_TAG, vec![0, 0, 0, 100]);
        let (back, _) = emit_and_parse(&attr);
        assert_eq!(back, attr);
    }

    #[test]
    fn unknown_tlv_preserved() {
        let mut attr = BgpLsAttr::new();
        attr.push(54321, vec![0xde, 0xad, 0xbe, 0xef]);
        let (back, _) = emit_and_parse(&attr);
        assert_eq!(back, attr);
        assert_eq!(back.get(54321), Some(&[0xde, 0xad, 0xbe, 0xef][..]));
    }

    #[test]
    fn extended_length_used_for_large_attribute() {
        let mut attr = BgpLsAttr::new();
        // One opaque TLV with a 300-octet value forces the attribute past 255
        // octets, so the extended-length header must be used.
        attr.push(BGPLS_ATTR_OPAQUE_NODE, vec![0xab; 300]);
        let (back, extended) = emit_and_parse(&attr);
        assert_eq!(back, attr);
        assert!(extended, "attribute >255 octets must use extended length");
    }

    #[test]
    fn tlv_wire_format() {
        let mut attr = BgpLsAttr::new();
        attr.push(BGPLS_ATTR_NODE_NAME, b"r1".to_vec());
        let mut buf = BytesMut::new();
        attr.attr_emit(&mut buf);
        let expected: &[u8] = &[
            0x80, // flags: optional, non-transitive
            0x1d, // type: 29 (BGP-LS Attribute)
            0x06, // length: 6
            0x04, 0x02, // TLV type 1026 (Node Name)
            0x00, 0x02, // TLV length 2
            b'r', b'1', // value
        ];
        assert_eq!(&buf[..], expected);
    }

    /// RFC 9294 §2 takes the OSPF mask encoding: 0, 4 or 8 octets. IS-IS
    /// sends the shortest mask that fits, so anything in 1..=4 widens to
    /// 4 and 5..=8 to 8, zero-padded on the right so no bit moves.
    #[test]
    fn asla_masks_widen_to_a_bgp_ls_legal_length() {
        for (input, want_len, want_mask) in [
            (vec![], 0usize, vec![]),
            (vec![0x10], 4, vec![0x10, 0, 0, 0]),
            (
                vec![0x10, 0x20, 0x30, 0x40],
                4,
                vec![0x10, 0x20, 0x30, 0x40],
            ),
            (vec![1, 2, 3, 4, 5], 8, vec![1, 2, 3, 4, 5, 0, 0, 0]),
            (
                vec![1, 2, 3, 4, 5, 6, 7, 8],
                8,
                vec![1, 2, 3, 4, 5, 6, 7, 8],
            ),
        ] {
            let v = bgpls_asla_value(&input, &[], &[]);
            assert_eq!(v[0] as usize, want_len, "SABM length for {input:?}");
            assert_eq!(v[1], 0, "UDABM length");
            assert_eq!(&v[2..4], &[0, 0], "reserved octets");
            assert_eq!(&v[4..4 + want_len], &want_mask[..], "mask for {input:?}");
        }
    }

    /// The user-defined mask is widened on its own, not copied from the
    /// standard one.
    #[test]
    fn asla_widens_the_user_defined_mask_independently() {
        let v = bgpls_asla_value(&[0x10], &[0xaa], &[]);
        assert_eq!((v[0], v[1]), (4, 4));
        assert_eq!(&v[4..8], &[0x10, 0, 0, 0]);
        assert_eq!(&v[8..12], &[0xaa, 0, 0, 0]);
    }
}
