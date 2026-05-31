//! STAMP optional-extension TLV framework (RFC 8972 §4) and the
//! RFC 9503 TLVs carried in a test packet.

use std::net::IpAddr;

use bytes::{BufMut, BytesMut};

use crate::packet::{ParseError, emit_ip, parse_ip};
use crate::return_path::ReturnPath;

/// Size of a STAMP TLV header: Flags (1) + Type (1) + Length (2).
/// RFC 8972 §4. Return-path sub-TLVs (RFC 9503) reuse the same shape.
pub const TLV_HEADER_LEN: usize = 4;

/// Extra Padding TLV (RFC 8972 §4.1).
pub const TYPE_EXTRA_PADDING: u8 = 1;
/// Destination Node Address TLV (RFC 9503 §3.2).
pub const TYPE_DEST_NODE_ADDRESS: u8 = 9;
/// Return Path TLV (RFC 9503 §3.3).
pub const TYPE_RETURN_PATH: u8 = 10;

/// The 1-octet STAMP TLV Flags field (RFC 8972 §4): the top three bits
/// are U (Unrecognized), M (Malformed), and I (Integrity failed); the
/// remaining bits are reserved. A Session-Sender sets all flags to 0;
/// a reflector raises them to report how it processed each TLV.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StampTlvFlags {
    pub unrecognized: bool,
    pub malformed: bool,
    pub integrity: bool,
}

impl StampTlvFlags {
    const U: u8 = 0x80;
    const M: u8 = 0x40;
    const I: u8 = 0x20;

    pub(crate) fn from_bits(b: u8) -> Self {
        Self {
            unrecognized: b & Self::U != 0,
            malformed: b & Self::M != 0,
            integrity: b & Self::I != 0,
        }
    }

    pub(crate) fn to_bits(self) -> u8 {
        let mut v = 0u8;
        if self.unrecognized {
            v |= Self::U;
        }
        if self.malformed {
            v |= Self::M;
        }
        if self.integrity {
            v |= Self::I;
        }
        v
    }
}

/// One STAMP optional-extension TLV: its flags plus the decoded value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StampTlv {
    pub flags: StampTlvFlags,
    pub value: StampTlvValue,
}

impl StampTlv {
    /// Build a TLV with cleared flags (the Session-Sender default).
    pub fn new(value: StampTlvValue) -> Self {
        Self {
            flags: StampTlvFlags::default(),
            value,
        }
    }
}

/// Decoded STAMP TLV value. TLV types this codec does not model are kept
/// verbatim as [`StampTlvValue::Unknown`] so they round-trip unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StampTlvValue {
    /// Extra Padding (Type 1, RFC 8972 §4.1) — opaque padding octets.
    ExtraPadding(Vec<u8>),
    /// Destination Node Address (Type 9, RFC 9503 §3.2).
    DestinationNodeAddress(IpAddr),
    /// Return Path (Type 10, RFC 9503 §3.3).
    ReturnPath(ReturnPath),
    /// Any TLV type not modelled above, preserved verbatim.
    Unknown { typ: u8, data: Vec<u8> },
}

impl StampTlv {
    /// The on-the-wire Type code for this TLV's value.
    pub fn typ(&self) -> u8 {
        match &self.value {
            StampTlvValue::ExtraPadding(_) => TYPE_EXTRA_PADDING,
            StampTlvValue::DestinationNodeAddress(_) => TYPE_DEST_NODE_ADDRESS,
            StampTlvValue::ReturnPath(_) => TYPE_RETURN_PATH,
            StampTlvValue::Unknown { typ, .. } => *typ,
        }
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.flags.to_bits());
        buf.put_u8(self.typ());
        let len_at = buf.len();
        buf.put_u16(0); // Length placeholder, fixed up below.
        let start = buf.len();
        match &self.value {
            StampTlvValue::ExtraPadding(p) => buf.put_slice(p),
            StampTlvValue::DestinationNodeAddress(ip) => emit_ip(buf, ip),
            StampTlvValue::ReturnPath(rp) => rp.emit(buf),
            StampTlvValue::Unknown { data, .. } => buf.put_slice(data),
        }
        let value_len = (buf.len() - start) as u16;
        buf[len_at..len_at + 2].copy_from_slice(&value_len.to_be_bytes());
    }

    /// Parse the trailing TLV section of a STAMP packet (the bytes after
    /// the 44-octet base). An empty input yields an empty list.
    pub fn parse_list(mut input: &[u8]) -> Result<Vec<Self>, ParseError> {
        let mut out = Vec::new();
        while !input.is_empty() {
            if input.len() < TLV_HEADER_LEN {
                return Err(ParseError::TlvHeaderTruncated { got: input.len() });
            }
            let flags = StampTlvFlags::from_bits(input[0]);
            let typ = input[1];
            let len = u16::from_be_bytes(input[2..4].try_into().unwrap()) as usize;
            let body = input.len() - TLV_HEADER_LEN;
            if body < len {
                return Err(ParseError::TlvTruncated {
                    typ,
                    declared: len,
                    got: body,
                });
            }
            let val = &input[TLV_HEADER_LEN..TLV_HEADER_LEN + len];
            let value = match typ {
                TYPE_EXTRA_PADDING => StampTlvValue::ExtraPadding(val.to_vec()),
                TYPE_DEST_NODE_ADDRESS => {
                    StampTlvValue::DestinationNodeAddress(parse_ip(typ, val)?)
                }
                TYPE_RETURN_PATH => StampTlvValue::ReturnPath(ReturnPath::parse(val)?),
                _ => StampTlvValue::Unknown {
                    typ,
                    data: val.to_vec(),
                },
            };
            out.push(Self { flags, value });
            input = &input[TLV_HEADER_LEN + len..];
        }
        Ok(out)
    }
}
