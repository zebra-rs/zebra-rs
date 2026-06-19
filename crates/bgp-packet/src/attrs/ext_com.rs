use std::collections::BTreeSet;
use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

use bytes::{BufMut, BytesMut};
use nom::IResult;
use nom_derive::{NomBE, Parse};

use crate::{
    AttrEmitter, AttrFlags, AttrType, ExtCommunitySubType, ExtCommunityType, MupExtComSubType,
    RouteDistinguisher, RouteDistinguisherType, TunnelType,
};

use super::ext_com_token::{Token, tokenizer};

// Extended Communities are an unordered set on the wire (RFC 4360);
// BTreeSet keeps the values deduplicated and canonically sorted (the
// derived ExtCommunityValue Ord is wire-byte order: type bytes first,
// then value) so equal sets compare/hash equal regardless of received
// order.
#[derive(Clone, Default, PartialEq, Eq, Hash)]
pub struct ExtCommunity(pub BTreeSet<ExtCommunityValue>);

impl FromIterator<ExtCommunityValue> for ExtCommunity {
    fn from_iter<I: IntoIterator<Item = ExtCommunityValue>>(iter: I) -> Self {
        ExtCommunity(iter.into_iter().collect())
    }
}

impl<const N: usize> From<[ExtCommunityValue; N]> for ExtCommunity {
    fn from(values: [ExtCommunityValue; N]) -> Self {
        ExtCommunity(BTreeSet::from(values))
    }
}

// nom_derive has no Parse impl for BTreeSet, so the wire decode is
// hand-written: parse the attribute payload as consecutive 8-octet
// values (`Vec`'s blanket impl) and collect into the set.
impl<'a> Parse<&'a [u8]> for ExtCommunity {
    fn parse(input: &'a [u8]) -> IResult<&'a [u8], Self> {
        Self::parse_be(input)
    }
    fn parse_be(input: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (input, values) = <Vec<ExtCommunityValue>>::parse_be(input)?;
        Ok((input, values.into_iter().collect()))
    }
}

#[derive(Clone, Debug, Default, NomBE, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExtCommunityValue {
    pub high_type: u8,
    pub low_type: u8,
    pub val: [u8; 6],
}

impl ExtCommunityValue {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.high_type);
        buf.put_u8(self.low_type);
        buf.put(&self.val[..]);
    }

    /// True iff this entry encodes a Color extended community
    /// (RFC 9012 §4.3): Transitive Opaque (0x03) + Color sub-type
    /// (0x0b).
    pub fn is_color(&self) -> bool {
        self.high_type == ExtCommunityType::TransOpaque as u8
            && self.low_type == ExtCommunitySubType::Color as u8
    }

    /// Decode the Color value if this entry is a Color extcomm.
    /// Returns the 2-octet Flags field (CO bits live in the top two
    /// bits, see draft-ietf-idr-bgp-ct §3.2.1) and the 4-octet color
    /// identifier. Returns None for any other extcomm type.
    pub fn as_color(&self) -> Option<Color> {
        if !self.is_color() {
            return None;
        }
        let flags = u16::from_be_bytes([self.val[0], self.val[1]]);
        let color = u32::from_be_bytes([self.val[2], self.val[3], self.val[4], self.val[5]]);
        Some(Color { flags, color })
    }

    /// Build a Color extended community. `co_bits` is the 2-bit
    /// CO-bits field that occupies the top of the 16-bit Flags word;
    /// any value > 3 is masked to the low two bits.
    pub fn from_color(co_bits: u8, color: u32) -> Self {
        let flags: u16 = ((co_bits as u16) & 0b11) << 14;
        Color { flags, color }.into()
    }

    /// True iff this entry is a MUP Extended Community (RFC 9833 §5):
    /// high-type byte 0x0c.
    pub fn is_mup(&self) -> bool {
        self.high_type == ExtCommunityType::Mup as u8
    }

    /// Decode the MUP Extended Community sub-type and surface the
    /// 6-octet payload as opaque bytes. Typed payload decoding per
    /// RFC 9833 §5 is deferred to a follow-up.
    pub fn as_mup(&self) -> Option<MupExtCom> {
        if !self.is_mup() {
            return None;
        }
        Some(MupExtCom {
            sub_type: MupExtComSubType::from(self.low_type),
            value: self.val,
        })
    }

    /// True iff this entry is the EVPN Multicast Flags Extended
    /// Community (RFC 9251 §6): EVPN high-type (0x06) + Multicast
    /// Flags sub-type (0x09).
    pub fn is_evpn_mcast_flags(&self) -> bool {
        self.high_type == ExtCommunityType::Evpn as u8 && self.low_type == EVPN_MCAST_FLAGS_SUB_TYPE
    }

    /// Decode the EVPN Multicast Flags EC (RFC 9251 §6). Returns the
    /// IGMP / MLD proxy-support bits. Per §6 an EC with **both** bits
    /// clear is malformed and MUST be ignored by the receiver, so this
    /// returns `None` in that case (and for any non-matching EC).
    pub fn as_evpn_mcast_flags(&self) -> Option<EvpnMcastFlags> {
        if !self.is_evpn_mcast_flags() {
            return None;
        }
        let flags = u16::from_be_bytes([self.val[0], self.val[1]]);
        let mcast = EvpnMcastFlags {
            igmp_proxy: flags & EvpnMcastFlags::IGMP_PROXY != 0,
            mld_proxy: flags & EvpnMcastFlags::MLD_PROXY != 0,
            segmentation_support: flags & EvpnMcastFlags::SEGMENTATION_SUPPORT != 0,
        };
        // RFC 9251 §6: an EC with no capability bits set is malformed and
        // MUST be ignored. With the RFC 9572 §8 segmentation bit added, that
        // means all three known bits clear.
        if !mcast.igmp_proxy && !mcast.mld_proxy && !mcast.segmentation_support {
            return None;
        }
        Some(mcast)
    }
}

/// EVPN Multicast Flags Extended Community sub-type (RFC 9251 §6),
/// carried under the EVPN high-type (0x06).
const EVPN_MCAST_FLAGS_SUB_TYPE: u8 = 0x09;

/// Decoded EVPN Multicast Flags Extended Community (RFC 9251 §6, extended
/// by RFC 9572 §8). A PE attaches this to its Inclusive Multicast (Type-3)
/// route to advertise IGMP / MLD proxy capability and/or BUM tunnel
/// **segmentation** support. The 2-octet Flags field carries the capability
/// bits; the remaining 4 octets are reserved (zero).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EvpnMcastFlags {
    pub igmp_proxy: bool,
    pub mld_proxy: bool,
    /// Bit 8 (RFC 9572 §8): the PE supports BUM tunnel segmentation.
    pub segmentation_support: bool,
}

impl EvpnMcastFlags {
    /// Bit 15 of the Flags field (RFC 9251 §6): IGMP Proxy Support.
    const IGMP_PROXY: u16 = 0x0001;
    /// Bit 14 of the Flags field: MLD Proxy Support.
    const MLD_PROXY: u16 = 0x0002;
    /// Bit 8 of the Flags field (RFC 9572 §8): Segmentation Support. RFC
    /// bit numbering is MSB-0 across the 16-bit field, so bit 8 = `1 << 7`.
    const SEGMENTATION_SUPPORT: u16 = 0x0080;
}

impl From<EvpnMcastFlags> for ExtCommunityValue {
    fn from(m: EvpnMcastFlags) -> Self {
        let mut flags: u16 = 0;
        if m.igmp_proxy {
            flags |= EvpnMcastFlags::IGMP_PROXY;
        }
        if m.mld_proxy {
            flags |= EvpnMcastFlags::MLD_PROXY;
        }
        if m.segmentation_support {
            flags |= EvpnMcastFlags::SEGMENTATION_SUPPORT;
        }
        let mut val = [0u8; 6];
        val[0..2].copy_from_slice(&flags.to_be_bytes());
        ExtCommunityValue {
            high_type: ExtCommunityType::Evpn as u8,
            low_type: EVPN_MCAST_FLAGS_SUB_TYPE,
            val,
        }
    }
}

/// Decoded MUP Extended Community (RFC 9833 §5). The `value` field
/// is the raw 6-octet payload; typed accessors per sub-type will
/// follow once the spec layout is in-tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MupExtCom {
    pub sub_type: MupExtComSubType,
    pub value: [u8; 6],
}

impl MupExtCom {
    pub fn new(sub_type: MupExtComSubType, value: [u8; 6]) -> Self {
        Self { sub_type, value }
    }
}

impl From<MupExtCom> for ExtCommunityValue {
    fn from(m: MupExtCom) -> Self {
        ExtCommunityValue {
            high_type: ExtCommunityType::Mup as u8,
            low_type: m.sub_type.into(),
            val: m.value,
        }
    }
}

/// Decoded Color extended community (RFC 9012 §4.3). `flags` is the
/// raw 16-bit field; `co_bits` is the top two bits per
/// draft-ietf-idr-bgp-ct §3.2.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Color {
    pub flags: u16,
    pub color: u32,
}

impl Color {
    /// CO bits per draft-ietf-idr-bgp-ct §3.2.1: 00 default, 01 any
    /// transport supporting color, 10 SR-aware transport, 11 reserved.
    pub fn co_bits(self) -> u8 {
        ((self.flags >> 14) & 0b11) as u8
    }
}

impl From<Color> for ExtCommunityValue {
    fn from(c: Color) -> Self {
        let mut val = [0u8; 6];
        val[0..2].copy_from_slice(&c.flags.to_be_bytes());
        val[2..6].copy_from_slice(&c.color.to_be_bytes());
        ExtCommunityValue {
            high_type: ExtCommunityType::TransOpaque as u8,
            low_type: ExtCommunitySubType::Color as u8,
            val,
        }
    }
}

impl fmt::Display for ExtCommunityValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ExtCommunityType::*;
        if self.high_type == TransTwoOctetAS as u8 {
            let asn = u16::from_be_bytes([self.val[0], self.val[1]]);
            let val = u32::from_be_bytes([self.val[2], self.val[3], self.val[4], self.val[5]]);
            write!(
                f,
                "{}:{asn}:{val}",
                ExtCommunitySubType::display(self.low_type)
            )
        } else if let Some(m) = self.as_mup() {
            // MUP Extended Community (RFC 9833 §5). Until typed
            // payloads land, render the sub-type identifier plus the
            // raw 6-byte value as a colon-joined hex string.
            write!(
                f,
                "{}:{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                m.sub_type, m.value[0], m.value[1], m.value[2], m.value[3], m.value[4], m.value[5]
            )
        } else if self.high_type == TransOpaque as u8 {
            // Color extcomm (RFC 9012 §4.3) has its own 2-octet flags
            // + 4-octet color layout; surface that when it's set,
            // otherwise fall back to the generic tunnel-type / opaque
            // rendering.
            if let Some(c) = self.as_color() {
                return write!(f, "color:{}:{}", c.co_bits(), c.color);
            }
            let ip = Ipv4Addr::new(self.val[0], self.val[1], self.val[2], self.val[3]);
            let val = u16::from_be_bytes([self.val[4], self.val[5]]);
            if let Ok(tunnel_type) = TunnelType::try_from(val) {
                write!(
                    f,
                    "{}:{}",
                    ExtCommunitySubType::display(self.low_type),
                    tunnel_type
                )
            } else {
                write!(
                    f,
                    "{}:{ip}:{val}",
                    ExtCommunitySubType::display(self.low_type)
                )
            }
        } else if self.is_evpn_mcast_flags() {
            // EVPN Multicast Flags EC (RFC 9251 §6 / RFC 9572 §8). Render the
            // raw capability bits as `mcast-flags:` plus `I` (IGMP) / `M`
            // (MLD) / `S` (segmentation support); an all-clear value renders
            // as a bare `mcast-flags:`.
            let flags = u16::from_be_bytes([self.val[0], self.val[1]]);
            let mut s = String::new();
            if flags & EvpnMcastFlags::IGMP_PROXY != 0 {
                s.push('I');
            }
            if flags & EvpnMcastFlags::MLD_PROXY != 0 {
                s.push('M');
            }
            if flags & EvpnMcastFlags::SEGMENTATION_SUPPORT != 0 {
                s.push('S');
            }
            write!(f, "mcast-flags:{s}")
        } else {
            let ip = Ipv4Addr::new(self.val[0], self.val[1], self.val[2], self.val[3]);
            let val = u16::from_be_bytes([self.val[4], self.val[5]]);
            write!(
                f,
                "{}:{ip}:{val}",
                ExtCommunitySubType::display(self.low_type)
            )
        }
    }
}

impl AttrEmitter for ExtCommunity {
    fn attr_flags(&self) -> AttrFlags {
        AttrFlags::new().with_optional(true).with_transitive(true)
    }

    fn attr_type(&self) -> AttrType {
        AttrType::ExtendedCom
    }

    fn len(&self) -> Option<usize> {
        None // Length is variable, let attr_emit buffer and calculate
    }

    fn emit(&self, buf: &mut BytesMut) {
        for ext_community in &self.0 {
            buf.put_u8(ext_community.high_type);
            buf.put_u8(ext_community.low_type);
            buf.put(&ext_community.val[..]);
        }
    }
}

impl fmt::Display for ExtCommunity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let v = self
            .0
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>()
            .join(" ");
        write!(f, "{v}")
    }
}

impl fmt::Debug for ExtCommunity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ExtCommunity: {}", self)
    }
}

#[derive(PartialEq)]
enum State {
    Unspec,
    Rt,
    Soo,
}

impl FromStr for ExtCommunity {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut ecom = ExtCommunity::default();
        let tokens = tokenizer(String::from(s)).map_err(|_| ())?;
        let mut state = State::Unspec;

        for token in tokens.into_iter() {
            match token {
                Token::Rd(rd) => {
                    let mut val: ExtCommunityValue = rd.into();
                    match state {
                        State::Unspec => {
                            return Err(());
                        }
                        State::Rt => {
                            val.low_type = 0x02;
                        }
                        State::Soo => {
                            val.low_type = 0x03;
                        }
                    }
                    ecom.0.insert(val);
                }
                Token::Rt => {
                    state = State::Rt;
                }
                Token::Soo => {
                    state = State::Soo;
                }
            }
        }
        Ok(ecom)
    }
}

impl From<RouteDistinguisher> for ExtCommunityValue {
    fn from(from: RouteDistinguisher) -> Self {
        let mut to = ExtCommunityValue {
            val: from.val,
            ..Default::default()
        };
        match from.typ {
            RouteDistinguisherType::ASN => {
                to.high_type = 0x00;
            }
            RouteDistinguisherType::IP => {
                to.high_type = 0x01;
            }
        }
        to
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse() {
        // Test new colon-prefixed format
        let ecom: ExtCommunity = ExtCommunity::from_str("rt:100:200").unwrap();
        assert_eq!(ecom.to_string(), "rt:100:200");

        let ecom: ExtCommunity = ExtCommunity::from_str("soo:1.2.3.4:200").unwrap();
        assert_eq!(ecom.to_string(), "soo:1.2.3.4:200");

        // Values render in canonical sorted order (type bytes first):
        // the ASN-form soo (high_type 0x00) sorts before the IPv4-form
        // rt (high_type 0x01), regardless of input order.
        let ecom: ExtCommunity = ExtCommunity::from_str("rt:1.2.3.4:100 soo:10:100").unwrap();
        assert_eq!(ecom.to_string(), "soo:10:100 rt:1.2.3.4:100");

        // Test backward compatibility with old space-separated format
        let ecom: ExtCommunity = ExtCommunity::from_str("rt 100:200").unwrap();
        assert_eq!(ecom.to_string(), "rt:100:200");

        let ecom: ExtCommunity = ExtCommunity::from_str("soo 1.2.3.4:200").unwrap();
        assert_eq!(ecom.to_string(), "soo:1.2.3.4:200");
    }

    #[test]
    fn color_from_constructor_round_trips_decode() {
        let c = ExtCommunityValue::from_color(0b10, 100);
        assert!(c.is_color());
        let decoded = c.as_color().expect("color decode");
        assert_eq!(decoded.color, 100);
        assert_eq!(decoded.co_bits(), 0b10);
        // Top two bits of Flags carry the CO-bits.
        assert_eq!(decoded.flags & 0xc000, 0b10 << 14);
    }

    #[test]
    fn color_wire_layout_is_type_subtype_flags_color() {
        let c = ExtCommunityValue::from_color(0, 0x0000_002a);
        // [0x03, 0x0b, flags_hi=0, flags_lo=0, color bytes...]
        assert_eq!(c.high_type, 0x03);
        assert_eq!(c.low_type, 0x0b);
        assert_eq!(c.val, [0, 0, 0, 0, 0, 0x2a]);
    }

    #[test]
    fn color_co_bits_mask_to_two_bits() {
        // CO=0b11 — explicit max value.
        let c = ExtCommunityValue::from_color(0b11, 7);
        assert_eq!(c.as_color().unwrap().co_bits(), 0b11);
        // Values above 3 mask down — guards constructor callers that
        // forget the field is only 2 bits wide.
        let c = ExtCommunityValue::from_color(0b1111_0010, 7);
        assert_eq!(c.as_color().unwrap().co_bits(), 0b10);
    }

    #[test]
    fn is_color_false_for_rt_and_soo() {
        let rt: ExtCommunity = ExtCommunity::from_str("rt:100:200").unwrap();
        let soo: ExtCommunity = ExtCommunity::from_str("soo:1.2.3.4:200").unwrap();
        let rt = rt.0.first().unwrap();
        let soo = soo.0.first().unwrap();
        assert!(!rt.is_color());
        assert!(!soo.is_color());
        assert!(rt.as_color().is_none());
        assert!(soo.as_color().is_none());
    }

    #[test]
    fn color_renders_in_display() {
        let c = ExtCommunityValue::from_color(0b01, 4242);
        assert_eq!(c.to_string(), "color:1:4242");
    }

    #[test]
    fn evpn_mcast_flags_wire_layout() {
        // Both IGMP + MLD proxy: high 0x06, sub 0x09, Flags=0x0003,
        // reserved 4 octets zero.
        let ec: ExtCommunityValue = EvpnMcastFlags {
            igmp_proxy: true,
            mld_proxy: true,
            segmentation_support: false,
        }
        .into();
        assert_eq!(ec.high_type, 0x06);
        assert_eq!(ec.low_type, 0x09);
        assert_eq!(ec.val, [0x00, 0x03, 0, 0, 0, 0]);
        let mut buf = BytesMut::new();
        ec.encode(&mut buf);
        assert_eq!(&buf[..], &[0x06, 0x09, 0x00, 0x03, 0, 0, 0, 0]);
    }

    #[test]
    fn evpn_mcast_flags_igmp_only_round_trips() {
        let ec: ExtCommunityValue = EvpnMcastFlags {
            igmp_proxy: true,
            mld_proxy: false,
            segmentation_support: false,
        }
        .into();
        assert_eq!(ec.val[0..2], [0x00, 0x01], "Flags bit 15 (IGMP) set only");
        assert!(ec.is_evpn_mcast_flags());
        let decoded = ec.as_evpn_mcast_flags().expect("decode");
        assert!(decoded.igmp_proxy);
        assert!(!decoded.mld_proxy);
    }

    #[test]
    fn evpn_mcast_flags_both_zero_is_ignored() {
        // RFC 9251 §6: an EVPN Multicast Flags EC with both bits clear
        // is malformed; `as_evpn_mcast_flags` returns None so callers
        // ignore it (but `is_` still recognises the type for Display).
        let ec = ExtCommunityValue {
            high_type: 0x06,
            low_type: 0x09,
            val: [0; 6],
        };
        assert!(ec.is_evpn_mcast_flags());
        assert!(ec.as_evpn_mcast_flags().is_none());
        assert_eq!(ec.to_string(), "mcast-flags:");
    }

    #[test]
    fn evpn_mcast_flags_renders_in_display() {
        let both: ExtCommunityValue = EvpnMcastFlags {
            igmp_proxy: true,
            mld_proxy: true,
            segmentation_support: false,
        }
        .into();
        assert_eq!(both.to_string(), "mcast-flags:IM");
        let mld: ExtCommunityValue = EvpnMcastFlags {
            igmp_proxy: false,
            mld_proxy: true,
            segmentation_support: false,
        }
        .into();
        assert_eq!(mld.to_string(), "mcast-flags:M");
    }

    #[test]
    fn evpn_mcast_flags_false_for_rt() {
        let rt: ExtCommunity = ExtCommunity::from_str("rt:100:200").unwrap();
        let rt = rt.0.first().unwrap();
        assert!(!rt.is_evpn_mcast_flags());
        assert!(rt.as_evpn_mcast_flags().is_none());
    }

    #[test]
    fn evpn_mcast_flags_round_trips_through_parse() {
        let original: ExtCommunityValue = EvpnMcastFlags {
            igmp_proxy: true,
            mld_proxy: true,
            segmentation_support: false,
        }
        .into();
        let mut buf = BytesMut::new();
        original.encode(&mut buf);
        let (_, parsed) = ExtCommunityValue::parse_be(&buf).expect("parse 8-octet EC");
        assert_eq!(parsed, original);
        assert_eq!(parsed.as_evpn_mcast_flags(), original.as_evpn_mcast_flags());
    }

    #[test]
    fn evpn_mcast_flags_segmentation_support() {
        // RFC 9572 §8: segmentation support is bit 8 of the Flags field
        // (0x0080). A segmentation-only EC must survive decode (it is not
        // "all bits clear") and renders with `S`.
        let ec: ExtCommunityValue = EvpnMcastFlags {
            igmp_proxy: false,
            mld_proxy: false,
            segmentation_support: true,
        }
        .into();
        assert_eq!(ec.val[0..2], [0x00, 0x80], "Flags bit 8 (segmentation)");
        assert_eq!(ec.to_string(), "mcast-flags:S");
        let decoded = ec
            .as_evpn_mcast_flags()
            .expect("segmentation-only EC is valid");
        assert!(decoded.segmentation_support);
        assert!(!decoded.igmp_proxy && !decoded.mld_proxy);

        // Combined with IGMP: bit 15 (0x0001) + bit 8 (0x0080) = 0x0081.
        let combo: ExtCommunityValue = EvpnMcastFlags {
            igmp_proxy: true,
            mld_proxy: false,
            segmentation_support: true,
        }
        .into();
        assert_eq!(combo.val[0..2], [0x00, 0x81]);
        assert_eq!(combo.to_string(), "mcast-flags:IS");
        let mut buf = BytesMut::new();
        combo.encode(&mut buf);
        let (_, parsed) = ExtCommunityValue::parse_be(&buf).expect("parse 8-octet EC");
        assert_eq!(parsed.as_evpn_mcast_flags(), combo.as_evpn_mcast_flags());
    }

    #[test]
    fn color_round_trips_through_attribute_emit_parse() {
        // Build an ExtCommunity attribute with one Color value,
        // round-trip the wire bytes through emit, parse the raw 8
        // octets back, and assert decode matches.
        let original = ExtCommunityValue::from_color(0b10, 128);
        let ecom = ExtCommunity::from([original.clone()]);
        let mut buf = BytesMut::new();
        ecom.emit(&mut buf);
        let bytes: Vec<u8> = buf.to_vec();
        assert_eq!(bytes.len(), 8);
        // Re-build the ExtCommunityValue from raw bytes to confirm
        // wire layout matches our constructor.
        let mut val = [0u8; 6];
        val.copy_from_slice(&bytes[2..8]);
        let parsed = ExtCommunityValue {
            high_type: bytes[0],
            low_type: bytes[1],
            val,
        };
        assert_eq!(parsed, original);
        let c = parsed.as_color().unwrap();
        assert_eq!(c.color, 128);
        assert_eq!(c.co_bits(), 0b10);
    }

    #[test]
    fn mup_subtype_round_trip_known_and_unknown() {
        for raw in [0u8, 1, 2, 3, 4, 99, 255] {
            let st = MupExtComSubType::from(raw);
            assert_eq!(u8::from(st), raw);
        }
        assert_eq!(MupExtComSubType::from(0), MupExtComSubType::Sub00);
        assert_eq!(MupExtComSubType::from(3), MupExtComSubType::Sub03);
    }

    #[test]
    fn mup_extcom_recognized_via_high_type_0x0c() {
        let ev = ExtCommunityValue {
            high_type: 0x0c,
            low_type: 0x02,
            val: [0xde, 0xad, 0xbe, 0xef, 0x01, 0x02],
        };
        assert!(ev.is_mup());
        let m = ev.as_mup().expect("must decode");
        assert_eq!(m.sub_type, MupExtComSubType::Sub02);
        assert_eq!(m.value, [0xde, 0xad, 0xbe, 0xef, 0x01, 0x02]);
    }

    #[test]
    fn non_mup_extcom_returns_none_from_as_mup() {
        let color = ExtCommunityValue::from_color(0, 5);
        assert!(!color.is_mup());
        assert!(color.as_mup().is_none());
    }

    #[test]
    fn mup_extcom_round_trip_via_from() {
        let original = MupExtCom::new(MupExtComSubType::Sub01, [1, 2, 3, 4, 5, 6]);
        let ev: ExtCommunityValue = original.into();
        assert_eq!(ev.high_type, 0x0c);
        assert_eq!(ev.low_type, 0x01);
        let decoded = ev.as_mup().unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn mup_extcom_unknown_subtype_preserved() {
        let original = MupExtCom::new(MupExtComSubType::Unknown(0x7F), [0; 6]);
        let ev: ExtCommunityValue = original.into();
        assert_eq!(ev.low_type, 0x7F);
        assert_eq!(
            ev.as_mup().unwrap().sub_type,
            MupExtComSubType::Unknown(0x7F)
        );
    }

    #[test]
    fn mup_extcom_display_renders_subtype_and_hex_value() {
        let ev: ExtCommunityValue = MupExtCom::new(
            MupExtComSubType::Sub00,
            [0xab, 0xcd, 0x00, 0x11, 0x22, 0x33],
        )
        .into();
        assert_eq!(format!("{ev}"), "mup-sub-0x00:abcd00112233");
    }

    #[test]
    fn mup_extcom_wire_round_trip_through_attribute_emit() {
        // Build an ExtCommunity attribute with one MUP value, round-
        // trip the wire bytes through emit, then reconstruct the value.
        let original = ExtCommunityValue {
            high_type: 0x0c,
            low_type: 0x03,
            val: [0x10, 0x20, 0x30, 0x40, 0x50, 0x60],
        };
        let ecom = ExtCommunity::from([original.clone()]);
        let mut buf = BytesMut::new();
        ecom.emit(&mut buf);
        let bytes: Vec<u8> = buf.to_vec();
        assert_eq!(bytes.len(), 8);
        let mut val = [0u8; 6];
        val.copy_from_slice(&bytes[2..8]);
        let parsed = ExtCommunityValue {
            high_type: bytes[0],
            low_type: bytes[1],
            val,
        };
        assert_eq!(parsed, original);
        let m = parsed.as_mup().unwrap();
        assert_eq!(m.sub_type, MupExtComSubType::Sub03);
    }
}
