//! ICMPv6 packet structs for all four RFC 4861 message types:
//! Router Solicitation (133), Router Advertisement (134),
//! Neighbor Solicitation (135), and Neighbor Advertisement (136).

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

/// Minimum size of a Neighbor Solicitation (RFC 4861 §4.3). ICMPv6
/// header (4) + reserved (4) + target address (16).
pub const MIN_NS_LEN: usize = 24;

/// Minimum size of a Neighbor Advertisement (RFC 4861 §4.4). ICMPv6
/// header (4) + flags/reserved (4) + target address (16).
pub const MIN_NA_LEN: usize = 24;

bitflags::bitflags! {
    /// Flags from the Neighbor Advertisement header (RFC 4861 §4.4).
    /// These occupy the first byte of the 4-byte flags/reserved word.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct NaFlags: u8 {
        /// Router flag — sender is a router.
        const R = 0b1000_0000;
        /// Solicited flag — sent in response to a Neighbor Solicitation.
        const S = 0b0100_0000;
        /// Override flag — should override an existing cache entry.
        const O = 0b0010_0000;
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

/// Neighbor Solicitation (RFC 4861 §4.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeighborSolicit {
    pub target: Ipv6Addr,
    pub options: Vec<NdOption>,
}

impl NeighborSolicit {
    /// Parse a Neighbor Solicitation from `payload`. If `verify_against`
    /// is `Some((src, dst))`, the ICMPv6 checksum is verified using
    /// those addresses; pass `None` if the socket already validated
    /// (e.g. via `IPV6_CHECKSUM`).
    pub fn parse(
        payload: &[u8],
        verify_against: Option<(Ipv6Addr, Ipv6Addr)>,
    ) -> Result<Self, ParseError> {
        if payload.len() < MIN_NS_LEN {
            return Err(ParseError::TooShort);
        }
        let typ = payload[0];
        if typ != Icmp6Type::NeighborSolicit.into() {
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
        // payload[4..8] is reserved per RFC 4861 §4.3.
        let mut target_bytes = [0u8; 16];
        target_bytes.copy_from_slice(&payload[8..24]);
        let target = Ipv6Addr::from(target_bytes);

        let mut options = Vec::new();
        let mut rest = &payload[MIN_NS_LEN..];
        while !rest.is_empty() {
            let (opt, next) = NdOption::parse(rest)?;
            options.push(opt);
            rest = next;
        }
        Ok(Self { target, options })
    }

    /// Emit the NS into `buf` with the ICMPv6 checksum filled in for
    /// the given source / destination addresses.
    pub fn emit(&self, buf: &mut BytesMut, src: Ipv6Addr, dst: Ipv6Addr) {
        let start = buf.len();
        self.emit_without_checksum(buf);
        let end = buf.len();
        let cksum = compute_icmp6_checksum(src, dst, &buf[start..end]);
        buf[start + 2] = (cksum >> 8) as u8;
        buf[start + 3] = (cksum & 0xff) as u8;
    }

    /// Emit the NS into `buf` with the checksum field left as zero.
    /// Useful when the kernel computes the checksum (`IPV6_CHECKSUM`
    /// on `IPPROTO_ICMPV6` sockets).
    pub fn emit_without_checksum(&self, buf: &mut BytesMut) {
        buf.put_u8(Icmp6Type::NeighborSolicit.into());
        buf.put_u8(0); // code
        buf.put_u16(0); // checksum placeholder
        buf.put_u32(0); // reserved
        buf.put_slice(&self.target.octets());
        for opt in &self.options {
            opt.emit(buf);
        }
    }
}

/// Neighbor Advertisement (RFC 4861 §4.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeighborAdvert {
    pub flags: NaFlags,
    pub target: Ipv6Addr,
    pub options: Vec<NdOption>,
}

impl NeighborAdvert {
    /// Parse a Neighbor Advertisement from `payload`. If `verify_against`
    /// is `Some((src, dst))`, the ICMPv6 checksum is verified using
    /// those addresses; pass `None` if the socket already validated
    /// (e.g. via `IPV6_CHECKSUM`).
    pub fn parse(
        payload: &[u8],
        verify_against: Option<(Ipv6Addr, Ipv6Addr)>,
    ) -> Result<Self, ParseError> {
        if payload.len() < MIN_NA_LEN {
            return Err(ParseError::TooShort);
        }
        let typ = payload[0];
        if typ != Icmp6Type::NeighborAdvert.into() {
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
        // payload[4] = flags byte; payload[5..8] = reserved per RFC 4861 §4.4.
        let flags = NaFlags::from_bits_truncate(payload[4]);
        let mut target_bytes = [0u8; 16];
        target_bytes.copy_from_slice(&payload[8..24]);
        let target = Ipv6Addr::from(target_bytes);

        let mut options = Vec::new();
        let mut rest = &payload[MIN_NA_LEN..];
        while !rest.is_empty() {
            let (opt, next) = NdOption::parse(rest)?;
            options.push(opt);
            rest = next;
        }
        Ok(Self {
            flags,
            target,
            options,
        })
    }

    /// Emit the NA into `buf` with the ICMPv6 checksum filled in for
    /// the given source / destination addresses.
    pub fn emit(&self, buf: &mut BytesMut, src: Ipv6Addr, dst: Ipv6Addr) {
        let start = buf.len();
        self.emit_without_checksum(buf);
        let end = buf.len();
        let cksum = compute_icmp6_checksum(src, dst, &buf[start..end]);
        buf[start + 2] = (cksum >> 8) as u8;
        buf[start + 3] = (cksum & 0xff) as u8;
    }

    /// Emit the NA into `buf` with the checksum field left as zero.
    /// Useful when the kernel computes the checksum (`IPV6_CHECKSUM`
    /// on `IPPROTO_ICMPV6` sockets).
    pub fn emit_without_checksum(&self, buf: &mut BytesMut) {
        buf.put_u8(Icmp6Type::NeighborAdvert.into());
        buf.put_u8(0); // code
        buf.put_u16(0); // checksum placeholder
        buf.put_u8(self.flags.bits());
        buf.put_u8(0); // reserved[0]
        buf.put_u8(0); // reserved[1]
        buf.put_u8(0); // reserved[2]
        buf.put_slice(&self.target.octets());
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

    // ── Neighbor Solicitation tests ──────────────────────────────────────

    #[test]
    fn ns_minimal_round_trip() {
        // NS to solicited-node multicast for fe80::2 (ff02::1:ff00:2).
        let target: Ipv6Addr = "fe80::2".parse().unwrap();
        let src = ll("fe80::1");
        let dst: Ipv6Addr = "ff02::1:ff00:2".parse().unwrap();
        let ns = NeighborSolicit {
            target,
            options: vec![],
        };
        let mut buf = BytesMut::new();
        ns.emit(&mut buf, src, dst);
        assert_eq!(buf.len(), MIN_NS_LEN);

        let parsed = NeighborSolicit::parse(&buf, Some((src, dst))).unwrap();
        assert_eq!(parsed, ns);
    }

    #[test]
    fn ns_with_source_lla() {
        let target: Ipv6Addr = "fe80::2".parse().unwrap();
        let src = ll("fe80::1");
        let dst: Ipv6Addr = "ff02::1:ff00:2".parse().unwrap();
        let ns = NeighborSolicit {
            target,
            options: vec![NdOption::SourceLinkLayerAddress(
                LinkLayerAddress::ethernet([0x52, 0x54, 0x00, 0xab, 0xcd, 0xef]),
            )],
        };
        let mut buf = BytesMut::new();
        ns.emit(&mut buf, src, dst);
        let parsed = NeighborSolicit::parse(&buf, Some((src, dst))).unwrap();
        assert_eq!(parsed, ns);
    }

    #[test]
    fn ns_dad_unspecified_source() {
        // DAD: source is ::, destination is the solicited-node multicast
        // address of the tentative address. The codec is address-agnostic
        // and should round-trip cleanly.
        let target: Ipv6Addr = "fe80::2".parse().unwrap();
        let src: Ipv6Addr = "::".parse().unwrap();
        let dst: Ipv6Addr = "ff02::1:ff00:2".parse().unwrap();
        let ns = NeighborSolicit {
            target,
            options: vec![],
        };
        let mut buf = BytesMut::new();
        ns.emit(&mut buf, src, dst);
        let parsed = NeighborSolicit::parse(&buf, Some((src, dst))).unwrap();
        assert_eq!(parsed, ns);
    }

    #[test]
    fn ns_rejects_non_zero_code() {
        let target: Ipv6Addr = "fe80::2".parse().unwrap();
        let ns = NeighborSolicit {
            target,
            options: vec![],
        };
        let mut buf = BytesMut::new();
        ns.emit_without_checksum(&mut buf);
        buf[1] = 1; // bad code
        let res = NeighborSolicit::parse(&buf, None);
        assert_eq!(res, Err(ParseError::NonZeroCode(1)));
    }

    #[test]
    fn ns_too_short_is_rejected() {
        // 0x87 = 135 (NS type), but only 8 bytes — shorter than MIN_NS_LEN (24).
        let wire = hex!("87 00 00 00 00 00 00 00");
        assert_eq!(
            NeighborSolicit::parse(&wire, None),
            Err(ParseError::TooShort)
        );
    }

    // ── Neighbor Advertisement tests ─────────────────────────────────────

    #[test]
    fn na_round_trip_with_flags_and_tlla() {
        // Solicited reply: S + O flags, target fe80::2, TLLA option.
        let target: Ipv6Addr = "fe80::2".parse().unwrap();
        let src = ll("fe80::2");
        let dst = ll("fe80::1");
        let na = NeighborAdvert {
            flags: NaFlags::S | NaFlags::O,
            target,
            options: vec![NdOption::TargetLinkLayerAddress(
                LinkLayerAddress::ethernet([0x52, 0x54, 0x00, 0xab, 0xcd, 0xef]),
            )],
        };
        let mut buf = BytesMut::new();
        na.emit(&mut buf, src, dst);
        let parsed = NeighborAdvert::parse(&buf, Some((src, dst))).unwrap();
        assert_eq!(parsed, na);
    }

    #[test]
    fn na_flags_wire_position() {
        // Emit NA with only R flag and no checksum; assert that byte[4]
        // is 0x80 (R bit) and bytes[5..8] are all zero — pins the flag
        // byte position per RFC 4861 §4.4.
        let target: Ipv6Addr = "fe80::2".parse().unwrap();
        let na = NeighborAdvert {
            flags: NaFlags::R,
            target,
            options: vec![],
        };
        let mut buf = BytesMut::new();
        na.emit_without_checksum(&mut buf);
        assert_eq!(buf[4], 0x80);
        assert_eq!(buf[5], 0x00);
        assert_eq!(buf[6], 0x00);
        assert_eq!(buf[7], 0x00);
    }

    #[test]
    fn na_checksum_mismatch_is_caught() {
        let target: Ipv6Addr = "fe80::2".parse().unwrap();
        let src = ll("fe80::2");
        let dst = ll("fe80::1");
        let na = NeighborAdvert {
            flags: NaFlags::S | NaFlags::O,
            target,
            options: vec![],
        };
        let mut buf = BytesMut::new();
        na.emit(&mut buf, src, dst);
        // Verify against wrong destination — checksum should fail.
        let res = NeighborAdvert::parse(&buf, Some((src, ll("fe80::2"))));
        assert_eq!(res, Err(ParseError::ChecksumMismatch));
    }

    #[test]
    fn na_rejects_wrong_type() {
        // Feed an NS wire image (type 0x87 = 135) to NeighborAdvert::parse.
        // The message is MIN_NA_LEN bytes long so it passes the length check.
        let target: Ipv6Addr = "fe80::2".parse().unwrap();
        let ns = NeighborSolicit {
            target,
            options: vec![],
        };
        let mut buf = BytesMut::new();
        ns.emit_without_checksum(&mut buf);
        let res = NeighborAdvert::parse(&buf, None);
        assert_eq!(res, Err(ParseError::UnsupportedType(135)));
    }

    #[test]
    fn na_parse_known_wire() {
        // Hand-crafted NA wire image:
        //   type=0x88 (136), code=0x00, checksum=0x0000 (skipped),
        //   flags=0x60 (S|O), reserved=0x00 0x00 0x00,
        //   target=fe80::2 (fe80:0000:...:0002),
        //   TLLA option: type=02 len=01 mac=52:54:00:ab:cd:ef
        let wire = hex!(
            "88 00 00 00 "          // type, code, checksum
            "60 00 00 00 "          // flags=S|O, reserved
            "fe 80 00 00 00 00 00 00 00 00 00 00 00 00 00 02 " // target fe80::2
            "02 01 52 54 00 ab cd ef" // TLLA option
        );
        let na = NeighborAdvert::parse(&wire, None).unwrap();
        assert_eq!(na.flags, NaFlags::S | NaFlags::O);
        assert_eq!(na.target, "fe80::2".parse::<Ipv6Addr>().unwrap());
        assert_eq!(na.options.len(), 1);
        assert_eq!(
            na.options[0],
            NdOption::TargetLinkLayerAddress(LinkLayerAddress::ethernet([
                0x52, 0x54, 0x00, 0xab, 0xcd, 0xef
            ]))
        );
    }
}
