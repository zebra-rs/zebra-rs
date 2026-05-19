//! Shared Risk Link Group (SRLG) top-level TLVs.
//!
//! * `IsisTlvSrlg`     — TLV 138, IPv4 (RFC 5307 §1).
//! * `IsisTlvIpv6Srlg` — TLV 139, IPv6 (RFC 6119 §3.4).
//!
//! Both bind a neighbor adjacency (sys-id + pseudonode #) to the set
//! of 32-bit SRLG values the link belongs to, with per-family
//! local/remote interface addresses. The on-wire `Length` is one
//! octet (255 byte cap), so a single TLV holds up to:
//!     - v4: (255 - 7 - 1 - 4 - 4) / 4 = 59 SRLG values.
//!     - v6: (255 - 7 - 1 - 16 - 16) / 4 = 53 SRLG values.
//!
//! Emit multiple TLVs of the same code if a link has more SRLGs than
//! that — the receiver concatenates by neighbor + addresses.

use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::{BufMut, BytesMut};
use nom::IResult;
use nom::number::complete::{be_u8, be_u32};
use nom_derive::Parse;
use serde::{Deserialize, Serialize};

use crate::IsisNeighborId;
use crate::tlv_type::IsisTlvType;
use crate::util::{ParseBe, TlvEmitter};

/// "Numbered" flag for `IsisTlvSrlg::flags` — when set the local /
/// remote address fields carry actual IPv4 addresses; when clear they
/// carry 32-bit Link Local / Remote Identifiers (RFC 5307 §1).
pub const SRLG_FLAG_T: u8 = 0x01;

/// IPv4 SRLG TLV (type 138, RFC 5307 §1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IsisTlvSrlg {
    pub neighbor: IsisNeighborId,
    /// Bit 0 (T): 1 = numbered link (local/remote are IPv4 addresses);
    /// 0 = unnumbered (local/remote are Link IDs, interpreted as the
    /// IPv4Addr bit pattern).
    pub flags: u8,
    pub local_addr: Ipv4Addr,
    pub remote_addr: Ipv4Addr,
    pub values: Vec<u32>,
}

impl IsisTlvSrlg {
    /// Fixed-portion size (neighbor + flags + local + remote).
    const FIXED_LEN: usize = 7 + 1 + 4 + 4;
    /// Maximum number of SRLG values that fit in a single TLV given
    /// the 255-byte length cap.
    pub const MAX_VALUES_PER_TLV: usize = (255 - Self::FIXED_LEN) / 4;
}

impl TlvEmitter for IsisTlvSrlg {
    fn typ(&self) -> u8 {
        IsisTlvType::Srlg.into()
    }

    fn len(&self) -> u8 {
        // Caller is responsible for splitting across multiple TLVs
        // when more than MAX_VALUES_PER_TLV are bound. min() here is
        // a safety belt — the wire length is u8.
        let val_bytes = self.values.len().min(Self::MAX_VALUES_PER_TLV) * 4;
        (Self::FIXED_LEN + val_bytes) as u8
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put(&self.neighbor.id[..]);
        buf.put_u8(self.flags);
        buf.put(&self.local_addr.octets()[..]);
        buf.put(&self.remote_addr.octets()[..]);
        for v in self.values.iter().take(Self::MAX_VALUES_PER_TLV) {
            buf.put_u32(*v);
        }
    }
}

impl ParseBe<IsisTlvSrlg> for IsisTlvSrlg {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, neighbor) = IsisNeighborId::parse(input)?;
        let (input, flags) = be_u8(input)?;
        let (mut input, local_addr) = Ipv4Addr::parse_be(input)?;
        let (rest, remote_addr) = Ipv4Addr::parse_be(input)?;
        input = rest;
        let mut values = Vec::new();
        while input.len() >= 4 {
            let (rest, v) = be_u32(input)?;
            values.push(v);
            input = rest;
        }
        Ok((
            input,
            Self {
                neighbor,
                flags,
                local_addr,
                remote_addr,
                values,
            },
        ))
    }
}

/// IPv6 SRLG TLV (type 139, RFC 6119 §3.4). The `flags` octet is
/// currently fully reserved per the RFC — emit 0, ignore on parse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IsisTlvIpv6Srlg {
    pub neighbor: IsisNeighborId,
    pub flags: u8,
    pub local_addr: Ipv6Addr,
    pub remote_addr: Ipv6Addr,
    pub values: Vec<u32>,
}

impl IsisTlvIpv6Srlg {
    const FIXED_LEN: usize = 7 + 1 + 16 + 16;
    pub const MAX_VALUES_PER_TLV: usize = (255 - Self::FIXED_LEN) / 4;
}

impl TlvEmitter for IsisTlvIpv6Srlg {
    fn typ(&self) -> u8 {
        IsisTlvType::Ipv6Srlg.into()
    }

    fn len(&self) -> u8 {
        let val_bytes = self.values.len().min(Self::MAX_VALUES_PER_TLV) * 4;
        (Self::FIXED_LEN + val_bytes) as u8
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put(&self.neighbor.id[..]);
        buf.put_u8(self.flags);
        buf.put(&self.local_addr.octets()[..]);
        buf.put(&self.remote_addr.octets()[..]);
        for v in self.values.iter().take(Self::MAX_VALUES_PER_TLV) {
            buf.put_u32(*v);
        }
    }
}

impl ParseBe<IsisTlvIpv6Srlg> for IsisTlvIpv6Srlg {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, neighbor) = IsisNeighborId::parse(input)?;
        let (input, flags) = be_u8(input)?;
        let (mut input, local_addr) = Ipv6Addr::parse_be(input)?;
        let (rest, remote_addr) = Ipv6Addr::parse_be(input)?;
        input = rest;
        let mut values = Vec::new();
        while input.len() >= 4 {
            let (rest, v) = be_u32(input)?;
            values.push(v);
            input = rest;
        }
        Ok((
            input,
            Self {
                neighbor,
                flags,
                local_addr,
                remote_addr,
                values,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IsisSysId;

    fn sample_neighbor() -> IsisNeighborId {
        IsisNeighborId::from_sys_id(
            &IsisSysId {
                id: [0x10, 0x20, 0x30, 0x40, 0x50, 0x60],
            },
            0,
        )
    }

    #[test]
    fn ipv4_srlg_round_trip() {
        let tlv = IsisTlvSrlg {
            neighbor: sample_neighbor(),
            flags: SRLG_FLAG_T,
            local_addr: "10.0.0.1".parse().unwrap(),
            remote_addr: "10.0.0.2".parse().unwrap(),
            values: vec![100, 200, 0xdead_beef],
        };
        let mut buf = BytesMut::new();
        tlv.tlv_emit(&mut buf);

        // type + len + fixed (16) + 3 * 4 values = 2 + 16 + 12 = 30 bytes
        assert_eq!(buf.len(), 30);
        assert_eq!(buf[0], 138);
        assert_eq!(buf[1], 28);

        let (rest, parsed) = IsisTlvSrlg::parse_be(&buf[2..]).expect("parse");
        assert!(rest.is_empty());
        assert_eq!(parsed, tlv);
    }

    #[test]
    fn ipv6_srlg_round_trip() {
        let tlv = IsisTlvIpv6Srlg {
            neighbor: sample_neighbor(),
            flags: 0,
            local_addr: "2001:db8::1".parse().unwrap(),
            remote_addr: "2001:db8::2".parse().unwrap(),
            values: vec![100, 200],
        };
        let mut buf = BytesMut::new();
        tlv.tlv_emit(&mut buf);

        // type + len + fixed (40) + 2 * 4 values = 2 + 40 + 8 = 50
        assert_eq!(buf.len(), 50);
        assert_eq!(buf[0], 139);
        assert_eq!(buf[1], 48);

        let (rest, parsed) = IsisTlvIpv6Srlg::parse_be(&buf[2..]).expect("parse");
        assert!(rest.is_empty());
        assert_eq!(parsed, tlv);
    }

    #[test]
    fn ipv4_per_tlv_capacity_matches_wire_cap() {
        // 255 - 16 (fixed) = 239; 239 / 4 = 59 values per TLV.
        assert_eq!(IsisTlvSrlg::MAX_VALUES_PER_TLV, 59);
    }

    #[test]
    fn ipv6_per_tlv_capacity_matches_wire_cap() {
        // 255 - 40 (fixed) = 215; 215 / 4 = 53 values per TLV.
        assert_eq!(IsisTlvIpv6Srlg::MAX_VALUES_PER_TLV, 53);
    }

    #[test]
    fn ipv4_emit_caps_excess_values() {
        // Values past MAX_VALUES_PER_TLV are silently dropped by emit
        // (the caller is supposed to chunk). Verify len() and emit()
        // both honor the cap so the on-wire length stays valid.
        let mut values = Vec::new();
        for i in 0..(IsisTlvSrlg::MAX_VALUES_PER_TLV as u32 + 5) {
            values.push(i);
        }
        let tlv = IsisTlvSrlg {
            neighbor: sample_neighbor(),
            flags: SRLG_FLAG_T,
            local_addr: "10.0.0.1".parse().unwrap(),
            remote_addr: "10.0.0.2".parse().unwrap(),
            values,
        };
        let mut buf = BytesMut::new();
        tlv.tlv_emit(&mut buf);
        // 2 (type+len) + 16 (fixed) + 59 * 4 = 254
        assert_eq!(buf.len(), 2 + 16 + IsisTlvSrlg::MAX_VALUES_PER_TLV * 4);
        // len byte equals 16 + 59*4 = 252
        assert_eq!(buf[1], (16 + IsisTlvSrlg::MAX_VALUES_PER_TLV * 4) as u8);
    }
}
