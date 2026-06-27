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
    pub p_flag: bool,
}

#[derive(Debug, PartialEq, Clone, NomBE)]
pub struct RestartValue {
    pub flag_time: RestartFlagTime,
    pub afi: Afi,
    pub safi: Safi,
    pub flags: RestartFlags,
}

impl RestartValue {
    pub fn new(restart_time: u16, afi: Afi, safi: Safi) -> Self {
        Self {
            flag_time: RestartFlagTime::new().with_restart_time(restart_time),
            afi,
            safi,
            flags: RestartFlags::default(),
        }
    }
}

#[derive(Debug, Default, PartialEq, NomBE, Clone)]
pub struct CapRestart {
    pub values: Vec<RestartValue>,
}

impl CapRestart {
    /// Each Graceful-Restart entry is 6 octets on the wire (Restart Flags +
    /// Time u16 + AFI u16 + SAFI u8 + per-AF Flags u8). A capability value is at
    /// most 253 octets — the BGP optional-parameter that carries it has a single
    /// length octet covering `code(1) + length(1) + value` (`emit.rs` writes
    /// `put_u8(len() + 2)`), so `value <= 255 - 2` — which fits at most 42
    /// entries (252 octets).
    const ENTRY_LEN: usize = 6;
    const MAX_ENTRIES: usize = 253 / Self::ENTRY_LEN; // 42

    /// Number of entries actually written on the wire. `len()` and
    /// `emit_value()` both derive from this so the declared length always
    /// matches the bytes emitted and the `as u8` cast cannot truncate; entries
    /// beyond the budget are dropped rather than wrapping the length octet.
    fn wire_count(&self) -> usize {
        self.values.len().min(Self::MAX_ENTRIES)
    }
}

impl CapEmit for CapRestart {
    fn code(&self) -> CapCode {
        CapCode::GracefulRestart
    }

    fn len(&self) -> u8 {
        // wire_count() <= 42, so wire_count() * 6 <= 252 fits a u8 and
        // `len() + 2` stays within a u8 for the optional-parameter framing.
        (self.wire_count() * Self::ENTRY_LEN) as u8
    }

    fn emit_value(&self, buf: &mut BytesMut) {
        for val in self.values.iter().take(self.wire_count()) {
            buf.put_u16(val.flag_time.into());
            buf.put_u16(val.afi.into());
            buf.put_u8(val.safi.into());
            buf.put_u8(val.flags.into());
        }
    }
}

impl fmt::Display for CapRestart {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = write!(f, "GracefulRestart: ");
        for (i, value) in self.values.iter().enumerate() {
            if i > 0 {
                let _ = write!(f, ", ");
            }
            let _ = write!(
                f,
                "{}/{} restart time:{} R:{} N:{} P:{}",
                value.afi,
                value.safi,
                value.flag_time.restart_time(),
                value.flag_time.r_flag(),
                value.flag_time.n_flag(),
                value.flags.p_flag(),
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cap_with_entries(n: usize) -> CapRestart {
        CapRestart {
            values: (0..n)
                .map(|_| RestartValue::new(120, Afi::Ip, Safi::Unicast))
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
        assert_eq!(len, 12, "2 entries * 6");
        assert_eq!(parsed.values.len(), 2);
        assert_eq!(parsed, cap);
    }

    #[test]
    fn empty_round_trips() {
        let cap = CapRestart::default();
        let (len, parsed) = emit_and_parse(&cap);
        assert_eq!(len, 0);
        assert_eq!(parsed, cap);
    }

    #[test]
    fn too_many_entries_clamped_to_budget() {
        // 50 entries * 6 = 300 octets would wrap the length octet; clamp to 42
        // entries (252 octets).
        let cap = cap_with_entries(50);
        let (len, parsed) = emit_and_parse(&cap);
        assert_eq!(len, 252, "42 entries * 6");
        assert_eq!(parsed.values.len(), 42);
        assert_eq!(len + 2, 254, "optional-parameter length stays within a u8");
    }
}
