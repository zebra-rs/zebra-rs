//! RFC 9503 §3.3 Return Path TLV and its sub-TLVs.
//!
//! A Session-Sender uses the Return Path TLV to ask the reflector to
//! send its reply over a specific Segment Routing path, so no dynamic
//! per-session state has to be maintained on the reflector.

use std::net::{IpAddr, Ipv6Addr};

use bytes::{BufMut, BytesMut};

use crate::packet::{ParseError, emit_ip, parse_ip};
use crate::tlv::{StampTlvFlags, TLV_HEADER_LEN};

/// Return Path Control Code sub-TLV (RFC 9503 §3.3.1).
pub const SUBTYPE_CONTROL_CODE: u8 = 1;
/// Return Address sub-TLV (RFC 9503 §3.3.2).
pub const SUBTYPE_RETURN_ADDRESS: u8 = 2;
/// SR-MPLS Label Stack of Return Path sub-TLV (RFC 9503 §3.3.3).
pub const SUBTYPE_SR_MPLS: u8 = 3;
/// SRv6 Segment List of Return Path sub-TLV (RFC 9503 §3.3.4).
pub const SUBTYPE_SRV6: u8 = 4;

/// Control Code value (RFC 9503 §3.3.1): reply requested on the same
/// link the test packet arrived on. Bit 31 (the least-significant bit
/// of the 4-octet field); all other bits are reserved.
pub const REPLY_REQUESTED_SAME_LINK: u32 = 0x0000_0001;

/// One MPLS label-stack entry (RFC 3032), as carried in the SR-MPLS
/// return-path sub-TLV: 20-bit label, 3-bit Traffic Class, Bottom-of-
/// Stack flag, and 8-bit TTL packed into 4 octets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MplsLabelEntry {
    pub label: u32,
    pub tc: u8,
    pub bos: bool,
    pub ttl: u8,
}

impl MplsLabelEntry {
    fn from_raw(raw: u32) -> Self {
        Self {
            label: raw >> 12,
            tc: ((raw >> 9) & 0x07) as u8,
            bos: (raw >> 8) & 0x01 != 0,
            ttl: (raw & 0xFF) as u8,
        }
    }

    fn to_raw(self) -> u32 {
        ((self.label & 0x000F_FFFF) << 12)
            | ((self.tc as u32 & 0x07) << 9)
            | (u32::from(self.bos) << 8)
            | self.ttl as u32
    }
}

/// The Return Path TLV value: an ordered list of sub-TLVs (RFC 9503
/// §3.3). RFC 9503 restricts a sender to at most one of each sub-TLV
/// type and forbids mixing the Control Code with an address/segment
/// list; the codec preserves whatever is on the wire and leaves that
/// validation to the caller.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReturnPath {
    pub sub_tlvs: Vec<ReturnPathSubTlv>,
}

/// One Return Path sub-TLV: its flags plus the decoded value. Uses the
/// same 4-octet Flags/Type/Length header as RFC 8972 TLVs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReturnPathSubTlv {
    pub flags: StampTlvFlags,
    pub value: ReturnPathSubTlvValue,
}

impl ReturnPathSubTlv {
    /// Build a sub-TLV with cleared flags.
    pub fn new(value: ReturnPathSubTlvValue) -> Self {
        Self {
            flags: StampTlvFlags::default(),
            value,
        }
    }
}

/// Decoded Return Path sub-TLV value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReturnPathSubTlvValue {
    /// Control Code (Type 1) — 4-octet flags field; see
    /// [`REPLY_REQUESTED_SAME_LINK`].
    ControlCode(u32),
    /// Return Address (Type 2) — IPv4 or IPv6.
    ReturnAddress(IpAddr),
    /// SR-MPLS Label Stack (Type 3), top-of-stack first.
    SrMplsLabelStack(Vec<MplsLabelEntry>),
    /// SRv6 Segment List (Type 4), first segment first.
    Srv6SegmentList(Vec<Ipv6Addr>),
    /// Any sub-TLV type not modelled above, preserved verbatim.
    Unknown { typ: u8, data: Vec<u8> },
}

impl ReturnPath {
    pub fn emit(&self, buf: &mut BytesMut) {
        for sub in &self.sub_tlvs {
            sub.emit(buf);
        }
    }

    pub fn parse(input: &[u8]) -> Result<Self, ParseError> {
        let mut sub_tlvs = Vec::new();
        let mut rest = input;
        while !rest.is_empty() {
            if rest.len() < TLV_HEADER_LEN {
                return Err(ParseError::TlvHeaderTruncated { got: rest.len() });
            }
            let flags = StampTlvFlags::from_bits(rest[0]);
            let typ = rest[1];
            let len = u16::from_be_bytes(rest[2..4].try_into().unwrap()) as usize;
            let body = rest.len() - TLV_HEADER_LEN;
            if body < len {
                return Err(ParseError::TlvTruncated {
                    typ,
                    declared: len,
                    got: body,
                });
            }
            let val = &rest[TLV_HEADER_LEN..TLV_HEADER_LEN + len];
            let value = ReturnPathSubTlvValue::parse(typ, val)?;
            sub_tlvs.push(ReturnPathSubTlv { flags, value });
            rest = &rest[TLV_HEADER_LEN + len..];
        }
        Ok(Self { sub_tlvs })
    }
}

impl ReturnPathSubTlv {
    fn typ(&self) -> u8 {
        match &self.value {
            ReturnPathSubTlvValue::ControlCode(_) => SUBTYPE_CONTROL_CODE,
            ReturnPathSubTlvValue::ReturnAddress(_) => SUBTYPE_RETURN_ADDRESS,
            ReturnPathSubTlvValue::SrMplsLabelStack(_) => SUBTYPE_SR_MPLS,
            ReturnPathSubTlvValue::Srv6SegmentList(_) => SUBTYPE_SRV6,
            ReturnPathSubTlvValue::Unknown { typ, .. } => *typ,
        }
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.flags.to_bits());
        buf.put_u8(self.typ());
        let len_at = buf.len();
        buf.put_u16(0); // Length placeholder, fixed up below.
        let start = buf.len();
        match &self.value {
            ReturnPathSubTlvValue::ControlCode(code) => buf.put_u32(*code),
            ReturnPathSubTlvValue::ReturnAddress(ip) => emit_ip(buf, ip),
            ReturnPathSubTlvValue::SrMplsLabelStack(stack) => {
                for lse in stack {
                    buf.put_u32(lse.to_raw());
                }
            }
            ReturnPathSubTlvValue::Srv6SegmentList(sids) => {
                for sid in sids {
                    buf.put_slice(&sid.octets());
                }
            }
            ReturnPathSubTlvValue::Unknown { data, .. } => buf.put_slice(data),
        }
        let value_len = (buf.len() - start) as u16;
        buf[len_at..len_at + 2].copy_from_slice(&value_len.to_be_bytes());
    }
}

impl ReturnPathSubTlvValue {
    fn parse(typ: u8, val: &[u8]) -> Result<Self, ParseError> {
        Ok(match typ {
            SUBTYPE_CONTROL_CODE => {
                if val.len() != 4 {
                    return Err(ParseError::BadControlCodeLength { len: val.len() });
                }
                Self::ControlCode(u32::from_be_bytes(val[0..4].try_into().unwrap()))
            }
            SUBTYPE_RETURN_ADDRESS => Self::ReturnAddress(parse_ip(typ, val)?),
            SUBTYPE_SR_MPLS => {
                if !val.len().is_multiple_of(4) {
                    return Err(ParseError::BadLabelStackLength { len: val.len() });
                }
                let stack = val
                    .chunks_exact(4)
                    .map(|c| MplsLabelEntry::from_raw(u32::from_be_bytes(c.try_into().unwrap())))
                    .collect();
                Self::SrMplsLabelStack(stack)
            }
            SUBTYPE_SRV6 => {
                if !val.len().is_multiple_of(16) {
                    return Err(ParseError::BadSegmentListLength { len: val.len() });
                }
                let sids = val
                    .chunks_exact(16)
                    .map(|c| Ipv6Addr::from(<[u8; 16]>::try_from(c).unwrap()))
                    .collect();
                Self::Srv6SegmentList(sids)
            }
            _ => Self::Unknown {
                typ,
                data: val.to_vec(),
            },
        })
    }
}
