//! STAMP base test packets (RFC 8762 §4, RFC 8972 §3 SSID).

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::{BufMut, BytesMut};

use crate::tlv::StampTlv;

/// Default destination UDP port for STAMP test packets — the IANA
/// "TWAMP-Test Receiver Port" (RFC 8762 §4).
pub const STAMP_UDP_PORT: u16 = 862;

/// Size of the STAMP base packet, identical for Session-Sender and
/// Session-Reflector in unauthenticated mode (RFC 8762 §4.2, §4.3).
/// Optional TLVs, when present, follow this base.
pub const BASE_LEN: usize = 44;

/// 8-octet STAMP timestamp (RFC 8762 §4.1.1): two 32-bit words. Their
/// meaning — an NTP 64-bit timestamp (seconds since 1900-01-01 plus a
/// binary fraction) or a PTPv2 truncated timestamp (seconds plus
/// nanoseconds) — is signalled by the companion [`ErrorEstimate`]'s
/// Z bit (RFC 8186). This codec stores the raw words and leaves epoch
/// conversion to the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StampTimestamp {
    pub seconds: u32,
    pub fraction: u32,
}

impl StampTimestamp {
    fn parse(b: &[u8]) -> Self {
        Self {
            seconds: u32::from_be_bytes(b[0..4].try_into().unwrap()),
            fraction: u32::from_be_bytes(b[4..8].try_into().unwrap()),
        }
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u32(self.seconds);
        buf.put_u32(self.fraction);
    }
}

/// Timestamp format carried by the Error Estimate Z bit (RFC 8186 §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TimestampFormat {
    /// NTP 64-bit timestamp (Z = 0). The STAMP default.
    #[default]
    Ntp,
    /// PTPv2 truncated timestamp (Z = 1).
    Ptpv2,
}

/// 2-octet Error Estimate (RFC 4656 §4.1.2; Z bit redefined by
/// RFC 8186 §3 to indicate the timestamp format).
///
/// ```text
///  0                   1
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |S|Z|  Scale  |   Multiplier    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ErrorEstimate {
    /// S bit — the clock is synchronised to an external reference.
    pub synced: bool,
    /// Z bit — timestamp format (NTP vs PTPv2).
    pub format: TimestampFormat,
    /// 6-bit Scale.
    pub scale: u8,
    /// 8-bit Multiplier. The estimated error is `Multiplier * 2^Scale`.
    pub multiplier: u8,
}

impl ErrorEstimate {
    fn from_bits(raw: u16) -> Self {
        Self {
            synced: raw & 0x8000 != 0,
            format: if raw & 0x4000 != 0 {
                TimestampFormat::Ptpv2
            } else {
                TimestampFormat::Ntp
            },
            scale: ((raw >> 8) & 0x3F) as u8,
            multiplier: (raw & 0x00FF) as u8,
        }
    }

    fn to_bits(self) -> u16 {
        let mut v = 0u16;
        if self.synced {
            v |= 0x8000;
        }
        if matches!(self.format, TimestampFormat::Ptpv2) {
            v |= 0x4000;
        }
        v |= ((self.scale as u16) & 0x3F) << 8;
        v |= self.multiplier as u16;
        v
    }
}

/// STAMP Session-Sender test packet, unauthenticated mode
/// (RFC 8762 §4.2.1; SSID per RFC 8972 §3).
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                        Sequence Number                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                          Timestamp (8)                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |        Error Estimate         |             SSID              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                          MBZ (28)             .. then TLVs ..  |
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SenderPacket {
    pub seq: u32,
    pub timestamp: StampTimestamp,
    pub error_estimate: ErrorEstimate,
    /// STAMP Session Sender Identifier (RFC 8972 §3); 0 when unused.
    pub ssid: u16,
    /// Optional RFC 8972 / RFC 9503 TLVs appended after the base packet.
    pub tlvs: Vec<StampTlv>,
}

impl SenderPacket {
    pub fn parse(input: &[u8]) -> Result<Self, ParseError> {
        if input.len() < BASE_LEN {
            return Err(ParseError::TooShort {
                need: BASE_LEN,
                got: input.len(),
            });
        }
        let seq = u32::from_be_bytes(input[0..4].try_into().unwrap());
        let timestamp = StampTimestamp::parse(&input[4..12]);
        let error_estimate =
            ErrorEstimate::from_bits(u16::from_be_bytes(input[12..14].try_into().unwrap()));
        let ssid = u16::from_be_bytes(input[14..16].try_into().unwrap());
        // input[16..44] is MBZ on the wire and ignored here.
        let tlvs = StampTlv::parse_list(&input[BASE_LEN..])?;
        Ok(Self {
            seq,
            timestamp,
            error_estimate,
            ssid,
            tlvs,
        })
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        buf.put_u32(self.seq);
        self.timestamp.emit(buf);
        buf.put_u16(self.error_estimate.to_bits());
        buf.put_u16(self.ssid);
        buf.put_bytes(0, 28); // MBZ
        for tlv in &self.tlvs {
            tlv.emit(buf);
        }
    }
}

/// STAMP Session-Reflector test packet, unauthenticated mode
/// (RFC 8762 §4.3.1; SSID per RFC 8972 §3).
///
/// Carries the reflector's own sequence/timestamp/error-estimate plus a
/// copy of the originating Session-Sender's sequence number, timestamp,
/// error estimate, and received TTL, followed by the receive timestamp.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReflectorPacket {
    pub seq: u32,
    pub timestamp: StampTimestamp,
    pub error_estimate: ErrorEstimate,
    /// STAMP Session Sender Identifier (RFC 8972 §3); 0 when unused.
    pub ssid: u16,
    /// Timestamp at which the reflector received the sender's packet.
    pub receive_timestamp: StampTimestamp,
    pub sender_seq: u32,
    pub sender_timestamp: StampTimestamp,
    pub sender_error_estimate: ErrorEstimate,
    /// TTL/Hop-Limit of the received Session-Sender packet.
    pub sender_ttl: u8,
    /// Optional RFC 8972 / RFC 9503 TLVs appended after the base packet.
    pub tlvs: Vec<StampTlv>,
}

impl ReflectorPacket {
    pub fn parse(input: &[u8]) -> Result<Self, ParseError> {
        if input.len() < BASE_LEN {
            return Err(ParseError::TooShort {
                need: BASE_LEN,
                got: input.len(),
            });
        }
        let seq = u32::from_be_bytes(input[0..4].try_into().unwrap());
        let timestamp = StampTimestamp::parse(&input[4..12]);
        let error_estimate =
            ErrorEstimate::from_bits(u16::from_be_bytes(input[12..14].try_into().unwrap()));
        let ssid = u16::from_be_bytes(input[14..16].try_into().unwrap());
        let receive_timestamp = StampTimestamp::parse(&input[16..24]);
        let sender_seq = u32::from_be_bytes(input[24..28].try_into().unwrap());
        let sender_timestamp = StampTimestamp::parse(&input[28..36]);
        let sender_error_estimate =
            ErrorEstimate::from_bits(u16::from_be_bytes(input[36..38].try_into().unwrap()));
        // input[38..40] is MBZ.
        let sender_ttl = input[40];
        // input[41..44] is MBZ.
        let tlvs = StampTlv::parse_list(&input[BASE_LEN..])?;
        Ok(Self {
            seq,
            timestamp,
            error_estimate,
            ssid,
            receive_timestamp,
            sender_seq,
            sender_timestamp,
            sender_error_estimate,
            sender_ttl,
            tlvs,
        })
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        buf.put_u32(self.seq);
        self.timestamp.emit(buf);
        buf.put_u16(self.error_estimate.to_bits());
        buf.put_u16(self.ssid);
        self.receive_timestamp.emit(buf);
        buf.put_u32(self.sender_seq);
        self.sender_timestamp.emit(buf);
        buf.put_u16(self.sender_error_estimate.to_bits());
        buf.put_u16(0); // MBZ
        buf.put_u8(self.sender_ttl);
        buf.put_bytes(0, 3); // MBZ
        for tlv in &self.tlvs {
            tlv.emit(buf);
        }
    }
}

/// Errors surfaced while parsing a STAMP packet or its TLVs. Every
/// variant maps to "silently discard the packet" in a runtime; the
/// codec itself never logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Input is shorter than the 44-octet STAMP base packet.
    TooShort { need: usize, got: usize },
    /// Trailing bytes are present but too few for a 4-octet TLV header.
    TlvHeaderTruncated { got: usize },
    /// A TLV's Length field runs past the end of the buffer.
    TlvTruncated {
        typ: u8,
        declared: usize,
        got: usize,
    },
    /// An address-bearing TLV/sub-TLV has a Length that is neither 4
    /// (IPv4) nor 16 (IPv6).
    BadAddressLength { typ: u8, len: usize },
    /// A Return Path Control Code sub-TLV is not exactly 4 octets.
    BadControlCodeLength { len: usize },
    /// An SR-MPLS label-stack sub-TLV Length is not a multiple of 4.
    BadLabelStackLength { len: usize },
    /// An SRv6 segment-list sub-TLV Length is not a multiple of 16.
    BadSegmentListLength { len: usize },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::TooShort { need, got } => {
                write!(f, "packet of {got} octets shorter than {need}-octet base")
            }
            ParseError::TlvHeaderTruncated { got } => {
                write!(f, "{got} trailing octets too few for a 4-octet TLV header")
            }
            ParseError::TlvTruncated { typ, declared, got } => write!(
                f,
                "TLV type {typ} declares {declared} value octets but only {got} remain"
            ),
            ParseError::BadAddressLength { typ, len } => {
                write!(f, "TLV type {typ} address length {len} is neither 4 nor 16")
            }
            ParseError::BadControlCodeLength { len } => {
                write!(f, "Return Path Control Code length {len} is not 4")
            }
            ParseError::BadLabelStackLength { len } => {
                write!(f, "SR-MPLS label stack length {len} is not a multiple of 4")
            }
            ParseError::BadSegmentListLength { len } => {
                write!(f, "SRv6 segment list length {len} is not a multiple of 16")
            }
        }
    }
}

impl std::error::Error for ParseError {}

/// Decode an address whose family is given by its byte length (4 → IPv4,
/// 16 → IPv6), as used by RFC 9503 Type 9 and Return Address sub-TLVs.
pub(crate) fn parse_ip(typ: u8, val: &[u8]) -> Result<IpAddr, ParseError> {
    match val.len() {
        4 => Ok(IpAddr::V4(Ipv4Addr::from(
            <[u8; 4]>::try_from(val).unwrap(),
        ))),
        16 => Ok(IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(val).unwrap(),
        ))),
        len => Err(ParseError::BadAddressLength { typ, len }),
    }
}

pub(crate) fn emit_ip(buf: &mut BytesMut, ip: &IpAddr) {
    match ip {
        IpAddr::V4(a) => buf.put_slice(&a.octets()),
        IpAddr::V6(a) => buf.put_slice(&a.octets()),
    }
}
