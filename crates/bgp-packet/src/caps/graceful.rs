use std::fmt;

use bitfield_struct::bitfield;
use bytes::{BufMut, BytesMut};
use nom_derive::*;
use serde::{Deserialize, Serialize};

use crate::{Afi, CapCode, CapEmit, Safi};

#[bitfield(u16, debug = true)]
#[derive(Serialize, Deserialize, PartialEq, NomBE)]
pub struct RestartFlagTime {
    #[bits(12)]
    pub restart_time: u16,
    #[bits(2)]
    pub resvd: u8,
    pub n_flag: bool,
    pub r_flag: bool,
}

#[bitfield(u8, debug = true)]
#[derive(Serialize, Deserialize, PartialEq, NomBE)]
pub struct RestartFlags {
    #[bits(7)]
    pub resvd: u8,
    pub f_flag: bool,
}

/// One per-AFI/SAFI tuple of the Graceful Restart capability: AFI (2) +
/// SAFI (1) + per-AF Flags (1) — 4 octets on the wire (RFC 4724 §3).
#[derive(Debug, PartialEq, Clone, NomBE)]
pub struct RestartEntry {
    pub afi: Afi,
    pub safi: Safi,
    pub flags: RestartFlags,
}

impl RestartEntry {
    pub fn new(afi: Afi, safi: Safi) -> Self {
        Self {
            afi,
            safi,
            flags: RestartFlags::default(),
        }
    }
}

/// RFC 4724 §3 Graceful Restart capability: one 2-octet Restart Flags +
/// Restart Time field followed by zero or more 4-octet [`RestartEntry`]
/// tuples, so a valid value length is `2 + 4n`. The flags/time field is
/// not repeated per tuple, and `n = 0` (length 2) is the common
/// helper-only form.
#[derive(Debug, Default, PartialEq, NomBE, Clone)]
pub struct CapRestart {
    pub flag_time: RestartFlagTime,
    pub entries: Vec<RestartEntry>,
}

impl CapRestart {
    /// Restart Flags + Restart Time header, always present on the wire.
    const HEADER_LEN: usize = 2;
    /// Each AFI/SAFI tuple is 4 octets. A capability value is at most 253
    /// octets — the BGP optional parameter that carries it has a single
    /// length octet covering `code(1) + length(1) + value` (`emit.rs`
    /// writes `put_u8(len() + 2)`), so `value <= 255 - 2` — which fits at
    /// most 62 tuples (2 + 248 = 250 octets).
    const ENTRY_LEN: usize = 4;
    const MAX_ENTRIES: usize = (253 - Self::HEADER_LEN) / Self::ENTRY_LEN; // 62

    /// Restart Time is a 12-bit field; clamp instead of letting the
    /// bitfield setter truncate or panic on out-of-range input.
    const MAX_RESTART_TIME: u16 = 0xfff;

    pub fn new(restart_time: u16) -> Self {
        Self {
            flag_time: RestartFlagTime::new()
                .with_restart_time(restart_time.min(Self::MAX_RESTART_TIME)),
            entries: Vec::new(),
        }
    }

    pub fn set_restart_time(&mut self, restart_time: u16) {
        self.flag_time
            .set_restart_time(restart_time.min(Self::MAX_RESTART_TIME));
    }

    /// Number of entries actually written on the wire. `len()` and
    /// `emit_value()` both derive from this so the declared length always
    /// matches the bytes emitted and the `as u8` cast cannot truncate;
    /// entries beyond the budget are dropped rather than wrapping the
    /// length octet.
    fn wire_count(&self) -> usize {
        self.entries.len().min(Self::MAX_ENTRIES)
    }
}

impl CapEmit for CapRestart {
    fn code(&self) -> CapCode {
        CapCode::GracefulRestart
    }

    fn len(&self) -> u8 {
        // wire_count() <= 62, so 2 + wire_count() * 4 <= 250 fits a u8 and
        // `len() + 2` stays within a u8 for the optional-parameter framing.
        (Self::HEADER_LEN + self.wire_count() * Self::ENTRY_LEN) as u8
    }

    fn emit_value(&self, buf: &mut BytesMut) {
        buf.put_u16(self.flag_time.into());
        for val in self.entries.iter().take(self.wire_count()) {
            buf.put_u16(val.afi.into());
            buf.put_u8(val.safi.into());
            buf.put_u8(val.flags.into());
        }
    }
}

impl fmt::Display for CapRestart {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GracefulRestart: restart time:{} R:{} N:{}",
            self.flag_time.restart_time(),
            self.flag_time.r_flag(),
            self.flag_time.n_flag(),
        )?;
        for entry in self.entries.iter() {
            write!(
                f,
                ", {}/{} F:{}",
                entry.afi,
                entry.safi,
                entry.flags.f_flag()
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CapabilityPacket;

    fn cap_with_entries(n: usize) -> CapRestart {
        CapRestart {
            flag_time: RestartFlagTime::new().with_restart_time(120),
            entries: (0..n)
                .map(|_| RestartEntry::new(Afi::Ip, Safi::Unicast))
                .collect(),
        }
    }

    /// Emit the value, assert `len()` matches the bytes written and `len() + 2`
    /// fits a u8 (the optional-parameter framing), then parse it back.
    fn emit_and_parse(cap: &CapRestart) -> (u8, CapRestart) {
        let mut buf = BytesMut::new();
        cap.emit_value(&mut buf);
        assert_eq!(
            cap.len() as usize,
            buf.len(),
            "len() must equal the emitted byte count"
        );
        assert!(
            cap.len().checked_add(2).is_some(),
            "len() + 2 must fit a u8"
        );
        let (rest, parsed) = CapRestart::parse_be(&buf).expect("parse emitted value");
        assert!(
            rest.is_empty(),
            "emit_value must be fully consumed by parse"
        );
        (cap.len(), parsed)
    }

    #[test]
    fn normal_round_trip() {
        let cap = cap_with_entries(2);
        let (len, parsed) = emit_and_parse(&cap);
        assert_eq!(len, 10, "2 octets flags/time + 2 entries * 4");
        assert_eq!(parsed.entries.len(), 2);
        assert_eq!(parsed, cap);
    }

    #[test]
    fn helper_only_round_trips() {
        // No AFI/SAFI tuples — the helper-only form is just the 2-octet
        // flags/time header, the most common shape on the wire.
        let cap = CapRestart::new(120);
        let (len, parsed) = emit_and_parse(&cap);
        assert_eq!(len, 2);
        assert_eq!(parsed, cap);
    }

    #[test]
    fn parses_helper_only_wire_form() {
        // 0x4078: N-bit set, restart time 120, zero tuples (e.g. FRR in
        // helper mode).
        let buf = [0x40, 0x78];
        let (rest, parsed) = CapRestart::parse_be(&buf).expect("length-2 value must parse");
        assert!(rest.is_empty());
        assert_eq!(parsed.flag_time.restart_time(), 120);
        assert!(parsed.flag_time.n_flag());
        assert!(!parsed.flag_time.r_flag());
        assert!(parsed.entries.is_empty());
    }

    #[test]
    fn parses_multi_afi_wire_form() {
        // R-bit set, time 120, IPv4/Unicast with F-bit + IPv6/Unicast
        // without — length 10 = 2 + 2 * 4.
        let buf = [
            0x80, 0x78, // flags/time
            0x00, 0x01, 0x01, 0x80, // IPv4 / Unicast, F=1
            0x00, 0x02, 0x01, 0x00, // IPv6 / Unicast, F=0
        ];
        let (rest, parsed) = CapRestart::parse_be(&buf).expect("length-10 value must parse");
        assert!(rest.is_empty());
        assert!(parsed.flag_time.r_flag());
        assert_eq!(parsed.flag_time.restart_time(), 120);
        assert_eq!(parsed.entries.len(), 2);
        assert_eq!(parsed.entries[0].afi, Afi::Ip);
        assert!(parsed.entries[0].flags.f_flag());
        assert_eq!(parsed.entries[1].afi, Afi::Ip6);
        assert!(!parsed.entries[1].flags.f_flag());
    }

    #[test]
    fn rejects_length_not_2_plus_4n() {
        // Capability code 64, declared length 4: flags/time plus a 2-octet
        // stub that is not a whole 4-octet tuple. `parse_cap` must reject
        // the trailing bytes instead of silently dropping them.
        let buf = [0x40, 0x04, 0x40, 0x78, 0x00, 0x01];
        assert!(CapabilityPacket::parse_cap(&buf).is_err());
    }

    #[test]
    fn restart_time_clamped_to_12_bits() {
        let mut cap = CapRestart::new(u16::MAX);
        assert_eq!(cap.flag_time.restart_time(), 0xfff);
        cap.set_restart_time(u16::MAX);
        assert_eq!(cap.flag_time.restart_time(), 0xfff);
    }

    #[test]
    fn too_many_entries_clamped_to_budget() {
        // 70 tuples * 4 + 2 = 282 octets would wrap the length octet; clamp
        // to 62 tuples (250 octets).
        let cap = cap_with_entries(70);
        let (len, parsed) = emit_and_parse(&cap);
        assert_eq!(len, 250, "2 + 62 entries * 4");
        assert_eq!(parsed.entries.len(), 62);
        assert_eq!(len + 2, 252, "optional-parameter length stays within a u8");
    }
}
