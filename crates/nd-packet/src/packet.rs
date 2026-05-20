//! ICMPv6 packet structs: Router Advertisement (134) and Router
//! Solicitation (133). RFC 4861 §4.1 / §4.2.

use std::net::Ipv6Addr;

use bytes::{BufMut, BytesMut};

use crate::checksum::compute_icmp6_checksum;
use crate::option::NdOption;
use crate::typ::Icmp6Type;

/// Minimum size of a Router Advertisement (RFC 4861 §4.2). The
/// ICMPv6 header is 4 bytes; the RA-specific fields are 12.
pub const MIN_RA_LEN: usize = 16;

/// Minimum size of a Router Solicitation (RFC 4861 §4.1). ICMPv6
/// header (4) + RS reserved field (4).
pub const MIN_RS_LEN: usize = 8;

/// RFC 4861 §6.2.4 — initial RA bring-up rate limit. Exposed so
/// the runtime's send-side state machine doesn't need to redeclare it.
pub const MAX_INITIAL_RTR_ADVERTISEMENTS: u32 = 3;

bitflags::bitflags! {
    /// Flags from the Router Advertisement header (RFC 4861 §4.2,
    /// extended by RFC 5175 for the "Home Agent" bit).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct RaFlags: u8 {
        /// Managed address configuration (DHCPv6).
        const M = 0b1000_0000;
        /// Other configuration (DHCPv6 stateless).
        const O = 0b0100_0000;
        /// Home Agent (RFC 6275 mobile IPv6).
        const H = 0b0010_0000;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Input slice is shorter than the minimum ICMPv6 header.
    TooShort,
    /// ICMPv6 Type field is not one this codec handles.
    UnsupportedType(u8),
    /// ICMPv6 Code field MUST be zero per RFC 4861 §4.1 / §4.2.
    NonZeroCode(u8),
    /// Checksum verification failed against the supplied src/dst.
    ChecksumMismatch,
    /// An ND option's length field was zero — MUST silently discard.
    ZeroLengthOption,
    /// An ND option ran past the end of the input.
    TruncatedOption,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort => write!(f, "input shorter than ICMPv6 minimum"),
            Self::UnsupportedType(t) => write!(f, "unsupported ICMPv6 type {}", t),
            Self::NonZeroCode(c) => write!(f, "ICMPv6 code must be 0, got {}", c),
            Self::ChecksumMismatch => write!(f, "ICMPv6 checksum mismatch"),
            Self::ZeroLengthOption => write!(f, "ND option with zero length"),
            Self::TruncatedOption => write!(f, "ND option truncated"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Router Advertisement (RFC 4861 §4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterAdvert {
    pub cur_hop_limit: u8,
    pub flags: RaFlags,
    pub router_lifetime: u16,
    pub reachable_time: u32,
    pub retrans_timer: u32,
    pub options: Vec<NdOption>,
}

impl RouterAdvert {
    /// Parse a Router Advertisement from `payload`. If `verify_against`
    /// is `Some((src, dst))`, the ICMPv6 checksum is verified using
    /// those addresses; pass `None` if the socket already validated
    /// (e.g. via `IPV6_CHECKSUM`).
    pub fn parse(
        payload: &[u8],
        verify_against: Option<(Ipv6Addr, Ipv6Addr)>,
    ) -> Result<Self, ParseError> {
        if payload.len() < MIN_RA_LEN {
            return Err(ParseError::TooShort);
        }
        let typ = payload[0];
        if typ != Icmp6Type::RouterAdvert.into() {
            return Err(ParseError::UnsupportedType(typ));
        }
        let code = payload[1];
        if code != 0 {
            return Err(ParseError::NonZeroCode(code));
        }
        if let Some((src, dst)) = verify_against {
            let mut zeroed = payload.to_vec();
            zeroed[2] = 0;
            zeroed[3] = 0;
            let computed = compute_icmp6_checksum(src, dst, &zeroed);
            let on_wire = u16::from_be_bytes([payload[2], payload[3]]);
            if computed != on_wire {
                return Err(ParseError::ChecksumMismatch);
            }
        }
        let cur_hop_limit = payload[4];
        let flags = RaFlags::from_bits_truncate(payload[5]);
        let router_lifetime = u16::from_be_bytes([payload[6], payload[7]]);
        let reachable_time = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
        let retrans_timer =
            u32::from_be_bytes([payload[12], payload[13], payload[14], payload[15]]);

        let mut options = Vec::new();
        let mut rest = &payload[MIN_RA_LEN..];
        while !rest.is_empty() {
            let (opt, next) = NdOption::parse(rest)?;
            options.push(opt);
            rest = next;
        }

        Ok(Self {
            cur_hop_limit,
            flags,
            router_lifetime,
            reachable_time,
            retrans_timer,
            options,
        })
    }

    /// Emit the RA into `buf` with the ICMPv6 checksum filled in for
    /// the given source / destination addresses.
    pub fn emit(&self, buf: &mut BytesMut, src: Ipv6Addr, dst: Ipv6Addr) {
        let start = buf.len();
        self.emit_without_checksum(buf);
        let end = buf.len();
        let cksum = compute_icmp6_checksum(src, dst, &buf[start..end]);
        buf[start + 2] = (cksum >> 8) as u8;
        buf[start + 3] = (cksum & 0xff) as u8;
    }

    /// Emit the RA into `buf` with the checksum field left as zero.
    /// Useful when the kernel computes the checksum (`IPV6_CHECKSUM`
    /// on `IPPROTO_ICMPV6` sockets).
    pub fn emit_without_checksum(&self, buf: &mut BytesMut) {
        buf.put_u8(Icmp6Type::RouterAdvert.into());
        buf.put_u8(0); // code
        buf.put_u16(0); // checksum placeholder
        buf.put_u8(self.cur_hop_limit);
        buf.put_u8(self.flags.bits());
        buf.put_u16(self.router_lifetime);
        buf.put_u32(self.reachable_time);
        buf.put_u32(self.retrans_timer);
        for opt in &self.options {
            opt.emit(buf);
        }
    }
}

/// Router Solicitation (RFC 4861 §4.1).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RouterSolicit {
    pub options: Vec<NdOption>,
}

impl RouterSolicit {
    pub fn parse(
        payload: &[u8],
        verify_against: Option<(Ipv6Addr, Ipv6Addr)>,
    ) -> Result<Self, ParseError> {
        if payload.len() < MIN_RS_LEN {
            return Err(ParseError::TooShort);
        }
        let typ = payload[0];
        if typ != Icmp6Type::RouterSolicit.into() {
            return Err(ParseError::UnsupportedType(typ));
        }
        let code = payload[1];
        if code != 0 {
            return Err(ParseError::NonZeroCode(code));
        }
        if let Some((src, dst)) = verify_against {
            let mut zeroed = payload.to_vec();
            zeroed[2] = 0;
            zeroed[3] = 0;
            let computed = compute_icmp6_checksum(src, dst, &zeroed);
            let on_wire = u16::from_be_bytes([payload[2], payload[3]]);
            if computed != on_wire {
                return Err(ParseError::ChecksumMismatch);
            }
        }
        // payload[4..8] is reserved per RFC 4861 §4.1.
        let mut options = Vec::new();
        let mut rest = &payload[MIN_RS_LEN..];
        while !rest.is_empty() {
            let (opt, next) = NdOption::parse(rest)?;
            options.push(opt);
            rest = next;
        }
        Ok(Self { options })
    }

    pub fn emit(&self, buf: &mut BytesMut, src: Ipv6Addr, dst: Ipv6Addr) {
        let start = buf.len();
        self.emit_without_checksum(buf);
        let end = buf.len();
        let cksum = compute_icmp6_checksum(src, dst, &buf[start..end]);
        buf[start + 2] = (cksum >> 8) as u8;
        buf[start + 3] = (cksum & 0xff) as u8;
    }

    pub fn emit_without_checksum(&self, buf: &mut BytesMut) {
        buf.put_u8(Icmp6Type::RouterSolicit.into());
        buf.put_u8(0); // code
        buf.put_u16(0); // checksum placeholder
        buf.put_u32(0); // reserved
        for opt in &self.options {
            opt.emit(buf);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::option::LinkLayerAddress;
    use hex_literal::hex;

    fn ll(a: &str) -> Ipv6Addr {
        a.parse().unwrap()
    }

    #[test]
    fn ra_parse_minimal() {
        // Cur Hop Limit=64, flags=0, lifetime=1800 (0x0708),
        // reachable=0, retrans=0, no options. Checksum filled in for
        // src=fe80::1 dst=ff02::1.
        let mut buf = BytesMut::new();
        let ra = RouterAdvert {
            cur_hop_limit: 64,
            flags: RaFlags::empty(),
            router_lifetime: 1800,
            reachable_time: 0,
            retrans_timer: 0,
            options: vec![],
        };
        ra.emit(&mut buf, ll("fe80::1"), ll("ff02::1"));
        assert_eq!(buf.len(), MIN_RA_LEN);

        let parsed = RouterAdvert::parse(&buf, Some((ll("fe80::1"), ll("ff02::1")))).unwrap();
        assert_eq!(parsed, ra);
    }

    #[test]
    fn ra_round_trip_with_source_lla() {
        let ra = RouterAdvert {
            cur_hop_limit: 64,
            flags: RaFlags::M | RaFlags::O,
            router_lifetime: 1800,
            reachable_time: 30_000,
            retrans_timer: 1000,
            options: vec![NdOption::SourceLinkLayerAddress(
                LinkLayerAddress::ethernet([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]),
            )],
        };
        let mut buf = BytesMut::new();
        ra.emit(&mut buf, ll("fe80::1"), ll("ff02::1"));

        let parsed = RouterAdvert::parse(&buf, Some((ll("fe80::1"), ll("ff02::1")))).unwrap();
        assert_eq!(parsed, ra);
    }

    #[test]
    fn ra_checksum_mismatch_is_caught() {
        let mut buf = BytesMut::new();
        let ra = RouterAdvert {
            cur_hop_limit: 64,
            flags: RaFlags::empty(),
            router_lifetime: 1800,
            reachable_time: 0,
            retrans_timer: 0,
            options: vec![],
        };
        ra.emit(&mut buf, ll("fe80::1"), ll("ff02::1"));
        // Verify against the wrong destination — checksum should fail.
        let res = RouterAdvert::parse(&buf, Some((ll("fe80::1"), ll("ff02::2"))));
        assert_eq!(res, Err(ParseError::ChecksumMismatch));
    }

    #[test]
    fn ra_rejects_non_zero_code() {
        let mut buf = BytesMut::new();
        let ra = RouterAdvert {
            cur_hop_limit: 64,
            flags: RaFlags::empty(),
            router_lifetime: 0,
            reachable_time: 0,
            retrans_timer: 0,
            options: vec![],
        };
        ra.emit_without_checksum(&mut buf);
        buf[1] = 1; // bad code
        let res = RouterAdvert::parse(&buf, None);
        assert_eq!(res, Err(ParseError::NonZeroCode(1)));
    }

    #[test]
    fn ra_rejects_wrong_type() {
        // 16 bytes long enough to clear the length check but with the
        // ICMPv6 Type set to RS (133) instead of RA (134).
        let wire = hex!(
            "85 00 00 00 40 00 00 00 "
            "00 00 00 00 00 00 00 00"
        );
        let res = RouterAdvert::parse(&wire, None);
        assert_eq!(res, Err(ParseError::UnsupportedType(133)));
    }

    #[test]
    fn rs_minimal_round_trip() {
        let mut buf = BytesMut::new();
        let rs = RouterSolicit::default();
        rs.emit(&mut buf, ll("fe80::1"), ll("ff02::2"));
        assert_eq!(buf.len(), MIN_RS_LEN);

        let parsed = RouterSolicit::parse(&buf, Some((ll("fe80::1"), ll("ff02::2")))).unwrap();
        assert_eq!(parsed, rs);
    }

    #[test]
    fn rs_with_source_lla() {
        let rs = RouterSolicit {
            options: vec![NdOption::SourceLinkLayerAddress(
                LinkLayerAddress::ethernet([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            )],
        };
        let mut buf = BytesMut::new();
        rs.emit(&mut buf, ll("fe80::1"), ll("ff02::2"));
        let parsed = RouterSolicit::parse(&buf, Some((ll("fe80::1"), ll("ff02::2")))).unwrap();
        assert_eq!(parsed, rs);
    }

    #[test]
    fn ra_too_short_is_rejected() {
        let wire = hex!("86 00 00 00");
        assert_eq!(RouterAdvert::parse(&wire, None), Err(ParseError::TooShort));
    }
}
