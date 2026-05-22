use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

use bytes::{BufMut, BytesMut};
use nom_derive::NomBE;

use crate::{
    AttrEmitter, AttrFlags, AttrType, ExtCommunitySubType, ExtCommunityType, MupExtComSubType,
    RouteDistinguisher, RouteDistinguisherType, TunnelType,
};

use super::ext_com_token::{Token, tokenizer};

#[derive(Clone, Default, NomBE, PartialEq, Eq, Hash)]
pub struct ExtCommunity(pub Vec<ExtCommunityValue>);

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
                    ecom.0.push(val);
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

        let ecom: ExtCommunity = ExtCommunity::from_str("rt:1.2.3.4:100 soo:10:100").unwrap();
        assert_eq!(ecom.to_string(), "rt:1.2.3.4:100 soo:10:100");

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
        assert!(!rt.0[0].is_color());
        assert!(!soo.0[0].is_color());
        assert!(rt.0[0].as_color().is_none());
        assert!(soo.0[0].as_color().is_none());
    }

    #[test]
    fn color_renders_in_display() {
        let c = ExtCommunityValue::from_color(0b01, 4242);
        assert_eq!(c.to_string(), "color:1:4242");
    }

    #[test]
    fn color_round_trips_through_attribute_emit_parse() {
        // Build an ExtCommunity attribute with one Color value,
        // round-trip the wire bytes through emit, parse the raw 8
        // octets back, and assert decode matches.
        let original = ExtCommunityValue::from_color(0b10, 128);
        let ecom = ExtCommunity(vec![original.clone()]);
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
        let ecom = ExtCommunity(vec![original.clone()]);
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
