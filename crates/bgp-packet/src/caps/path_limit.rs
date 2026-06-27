use std::fmt;

use bytes::{BufMut, BytesMut};
use nom_derive::*;

use super::{CapCode, CapEmit};
use crate::{Afi, Safi};

#[derive(Debug, Default, PartialEq, NomBE, Clone)]
pub struct CapPathLimit {
    pub values: Vec<PathLimitValue>,
}

#[derive(Debug, PartialEq, NomBE, Clone)]
pub struct PathLimitValue {
    pub afi: Afi,
    pub safi: Safi,
    pub path_limit: u16,
}

impl CapPathLimit {
    pub fn new(afi: Afi, safi: Safi, path_limit: u16) -> Self {
        Self {
            values: vec![PathLimitValue {
                afi,
                safi,
                path_limit,
            }],
        }
    }

    /// Each Path-Limit entry is 5 octets on the wire (AFI u16 + SAFI u8 +
    /// Path Limit u16). A capability value is at most 253 octets — the BGP
    /// optional-parameter that carries it has a single length octet covering
    /// `code(1) + length(1) + value` (`emit.rs` writes `put_u8(len() + 2)`),
    /// so `value <= 255 - 2` — which fits at most 50 entries (250 octets).
    const ENTRY_LEN: usize = 5;
    const MAX_ENTRIES: usize = 253 / Self::ENTRY_LEN; // 50

    /// Number of entries actually written on the wire. `len()` and
    /// `emit_value()` both derive from this so the declared length always
    /// matches the bytes emitted and the `as u8` cast cannot truncate; entries
    /// beyond the budget are dropped rather than wrapping the length octet.
    fn wire_count(&self) -> usize {
        self.values.len().min(Self::MAX_ENTRIES)
    }
}

impl CapEmit for CapPathLimit {
    fn code(&self) -> CapCode {
        CapCode::PathLimit
    }

    fn len(&self) -> u8 {
        // wire_count() <= 50, so wire_count() * 5 <= 250 fits a u8 and
        // `len() + 2` stays within a u8 for the optional-parameter framing.
        (self.wire_count() * Self::ENTRY_LEN) as u8
    }

    fn emit_value(&self, buf: &mut BytesMut) {
        for val in self.values.iter().take(self.wire_count()) {
            buf.put_u16(val.afi.into());
            buf.put_u8(val.safi.into());
            buf.put_u16(val.path_limit);
        }
    }
}

impl fmt::Display for CapPathLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = write!(f, "Path Limit: ");
        for (i, value) in self.values.iter().enumerate() {
            if i > 0 {
                let _ = write!(f, ", ");
            }
            let _ = write!(f, "{}/{} {}", value.afi, value.safi, value.path_limit);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cap_with_entries(n: usize) -> CapPathLimit {
        CapPathLimit {
            values: (0..n)
                .map(|_| PathLimitValue {
                    afi: Afi::Ip,
                    safi: Safi::Unicast,
                    path_limit: 100,
                })
                .collect(),
        }
    }

    /// Emit the value, assert `len()` matches the bytes written and `len() + 2`
    /// fits a u8 (the optional-parameter framing), then parse it back.
    fn emit_and_parse(cap: &CapPathLimit) -> (u8, CapPathLimit) {
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
        let (rest, parsed) = CapPathLimit::parse_be(&buf).expect("parse emitted value");
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
        assert_eq!(len, 10, "2 entries * 5");
        assert_eq!(parsed.values.len(), 2);
        assert_eq!(parsed, cap);
    }

    #[test]
    fn empty_round_trips() {
        let cap = CapPathLimit::default();
        let (len, parsed) = emit_and_parse(&cap);
        assert_eq!(len, 0);
        assert_eq!(parsed, cap);
    }

    #[test]
    fn too_many_entries_clamped_to_budget() {
        // 60 entries * 5 = 300 octets would wrap the length octet; clamp to 50
        // entries (250 octets).
        let cap = cap_with_entries(60);
        let (len, parsed) = emit_and_parse(&cap);
        assert_eq!(len, 250, "50 entries * 5");
        assert_eq!(parsed.values.len(), 50);
        assert_eq!(len + 2, 252, "optional-parameter length stays within a u8");
    }
}
