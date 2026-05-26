use bytes::{BufMut, BytesMut};
use nom::IResult;
use nom::number::complete::{be_u8, be_u16};
use nom_derive::Parse;
use serde::{Deserialize, Serialize};

use crate::parser::IsisSysId;
use crate::tlv_type::IsisTlvType;
use crate::util::{ParseBe, TlvEmitter};

/// Restart TLV (type 211) — RFC 5306 §3.
///
/// Wire layout:
///
/// ```text
///   Type     211
///   Length   1 .. (3 + ID Length)
///   Value
///       Flags          (1 octet)
///       Remaining Time (2 octets, present iff RA bit set)
///       Restarting Neighbor System ID (ID Length octets,
///                                      present iff RA bit set)
///
///   Flags:
///       0  1  2  3  4  5  6  7
///     +--+--+--+--+--+--+--+--+
///     |  Reserved    |SA|RA|RR|
///     +--+--+--+--+--+--+--+--+
/// ```
///
/// `remaining_time` and `restarting_neighbor` are required by the RFC
/// when `RA=1` and otherwise MUST be absent. The codec carries them as
/// `Option` so the absent case is representable; the IIH-level state
/// machine (Phase 3) is responsible for enforcing the RA-bit pairing.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IsisTlvRestart {
    pub flags: u8,
    pub remaining_time: Option<u16>,
    pub restarting_neighbor: Option<IsisSysId>,
}

/// RR — Restart Request (bit 7, LSB).
pub const ISIS_RESTART_FLAG_RR: u8 = 0x01;
/// RA — Restart Acknowledgement (bit 6).
pub const ISIS_RESTART_FLAG_RA: u8 = 0x02;
/// SA — Suppress Adjacency (bit 5).
pub const ISIS_RESTART_FLAG_SA: u8 = 0x04;

impl IsisTlvRestart {
    pub fn rr(&self) -> bool {
        self.flags & ISIS_RESTART_FLAG_RR != 0
    }

    pub fn ra(&self) -> bool {
        self.flags & ISIS_RESTART_FLAG_RA != 0
    }

    pub fn sa(&self) -> bool {
        self.flags & ISIS_RESTART_FLAG_SA != 0
    }

    pub fn set_rr(&mut self, v: bool) {
        self.set_flag(ISIS_RESTART_FLAG_RR, v);
    }

    pub fn set_ra(&mut self, v: bool) {
        self.set_flag(ISIS_RESTART_FLAG_RA, v);
    }

    pub fn set_sa(&mut self, v: bool) {
        self.set_flag(ISIS_RESTART_FLAG_SA, v);
    }

    fn set_flag(&mut self, mask: u8, v: bool) {
        if v {
            self.flags |= mask;
        } else {
            self.flags &= !mask;
        }
    }
}

impl ParseBe<IsisTlvRestart> for IsisTlvRestart {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, flags) = be_u8(input)?;
        // Per RFC 5306 §3, Remaining Time and Restarting Neighbor System
        // ID are only present when RA=1. Decode defensively against
        // truncation rather than the flag — older implementations have
        // been known to disagree on the pairing rule.
        let (input, remaining_time) = if input.len() >= 2 {
            let (input, t) = be_u16(input)?;
            (input, Some(t))
        } else {
            (input, None)
        };
        let (input, restarting_neighbor) = if input.len() >= 6 {
            let (input, id) = IsisSysId::parse_be(input)?;
            (input, Some(id))
        } else {
            (input, None)
        };
        Ok((
            input,
            Self {
                flags,
                remaining_time,
                restarting_neighbor,
            },
        ))
    }
}

impl TlvEmitter for IsisTlvRestart {
    fn typ(&self) -> u8 {
        IsisTlvType::Restart.into()
    }

    fn len(&self) -> u8 {
        let mut len: u8 = 1;
        if self.remaining_time.is_some() {
            len += 2;
        }
        if self.restarting_neighbor.is_some() {
            len += 6;
        }
        len
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.flags);
        if let Some(t) = self.remaining_time {
            buf.put_u16(t);
        }
        if let Some(id) = &self.restarting_neighbor {
            buf.put(&id.id[..]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bit positions per RFC 5306 §3: RR is the LSB, RA is bit 6, SA is
    /// bit 5. Encoding a TLV with only one flag set must produce the
    /// expected byte pattern.
    #[test]
    fn bit_positions_match_rfc5306() {
        let mut rr = IsisTlvRestart::default();
        rr.set_rr(true);
        assert_eq!(rr.flags, 0x01);

        let mut ra = IsisTlvRestart::default();
        ra.set_ra(true);
        assert_eq!(ra.flags, 0x02);

        let mut sa = IsisTlvRestart::default();
        sa.set_sa(true);
        assert_eq!(sa.flags, 0x04);
    }

    #[test]
    fn flag_accessors_round_trip() {
        let mut tlv = IsisTlvRestart::default();
        tlv.set_rr(true);
        tlv.set_ra(true);
        assert!(tlv.rr());
        assert!(tlv.ra());
        assert!(!tlv.sa());

        tlv.set_rr(false);
        assert!(!tlv.rr());
        assert!(tlv.ra());
    }

    /// Restarting router on a P2P circuit: RR=1, no RA-paired fields.
    /// On-wire value is the single flags byte 0x01.
    #[test]
    fn encode_decode_rr_only() {
        let mut tlv = IsisTlvRestart::default();
        tlv.set_rr(true);
        let mut buf = BytesMut::new();
        tlv.tlv_emit(&mut buf);
        // T(1) + L(1) + V(1) = 3 bytes.
        assert_eq!(&buf[..], &[211, 1, 0x01]);

        let (rest, decoded) = IsisTlvRestart::parse_be(&buf[2..]).unwrap();
        assert!(rest.is_empty());
        assert_eq!(decoded.flags, 0x01);
        assert_eq!(decoded.remaining_time, None);
        assert_eq!(decoded.restarting_neighbor, None);
    }

    /// Helper acknowledgement on a LAN: RA=1, Remaining Time = 27s,
    /// neighbor System ID populated. Full 10-byte value.
    #[test]
    fn encode_decode_ra_with_neighbor() {
        let tlv = IsisTlvRestart {
            flags: ISIS_RESTART_FLAG_RA,
            remaining_time: Some(27),
            restarting_neighbor: Some(IsisSysId {
                id: [0x10, 0x20, 0x30, 0x40, 0x50, 0x60],
            }),
        };
        let mut buf = BytesMut::new();
        tlv.tlv_emit(&mut buf);
        assert_eq!(
            &buf[..],
            &[
                211, 9,    // T, L
                0x02, // RA
                0x00, 0x1b, // remaining time = 27
                0x10, 0x20, 0x30, 0x40, 0x50, 0x60, // sys id
            ]
        );

        let (rest, decoded) = IsisTlvRestart::parse_be(&buf[2..]).unwrap();
        assert!(rest.is_empty());
        assert_eq!(decoded, tlv);
    }

    /// Starting router (fresh boot, RFC 5306 §3.4): SA=1, RR=0. The
    /// neighbor must distinguish this from a true restart.
    #[test]
    fn starting_router_flag_combo() {
        let mut tlv = IsisTlvRestart::default();
        tlv.set_sa(true);
        assert!(tlv.sa());
        assert!(!tlv.rr());
        assert!(!tlv.ra());
        assert_eq!(tlv.flags, ISIS_RESTART_FLAG_SA);
    }
}
