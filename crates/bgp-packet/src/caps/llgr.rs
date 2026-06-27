use std::fmt;

use bitfield_struct::bitfield;
use bytes::{BufMut, BytesMut};
use nom::IResult;
use nom::number::complete::{be_u8, be_u24};
use nom_derive::*;

use crate::{Afi, CapCode, CapEmit, ParseBe, Safi, u32_u24};

#[derive(Debug, Default, PartialEq, NomBE, Clone)]
pub struct CapLlgr {
    pub values: Vec<LlgrValue>,
}

impl CapLlgr {
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Each LLGR entry is 7 octets on the wire (AFI u16 + SAFI u8 + Flags u8 +
    /// Long-lived Stale Time u24). A capability value is at most 253 octets —
    /// the BGP optional-parameter that carries it has a single length octet
    /// covering `code(1) + length(1) + value` (`emit.rs` writes
    /// `put_u8(len() + 2)`), so `value <= 255 - 2` — which fits at most 36
    /// entries (252 octets).
    const ENTRY_LEN: usize = 7;
    const MAX_ENTRIES: usize = 253 / Self::ENTRY_LEN; // 36

    /// Number of entries actually written on the wire. `len()` and
    /// `emit_value()` both derive from this so the declared length always
    /// matches the bytes emitted and the `as u8` cast cannot truncate; entries
    /// beyond the budget are dropped rather than wrapping the length octet.
    fn wire_count(&self) -> usize {
        self.values.len().min(Self::MAX_ENTRIES)
    }
}

#[bitfield(u8, debug = true)]
#[derive(PartialEq)]
pub struct LlgrFlags {
    #[bits(7)]
    pub resvd: u8,
    #[bits(1)]
    pub f_bit: bool,
}

impl ParseBe<LlgrFlags> for LlgrFlags {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, flags) = be_u8(input)?;
        Ok((input, flags.into()))
    }
}

#[derive(Debug, PartialEq, NomBE, Clone)]
pub struct LlgrValue {
    pub afi: Afi,
    pub safi: Safi,
    flags: LlgrFlags,
    #[nom(Parse = "be_u24")]
    stale_time: u32,
}

impl LlgrValue {
    pub fn new(afi: Afi, safi: Safi, stale_time: u32) -> Self {
        Self {
            afi,
            safi,
            flags: LlgrFlags::default(),
            stale_time,
        }
    }

    pub fn stale_time(&self) -> u32 {
        self.stale_time
    }
}

impl CapEmit for CapLlgr {
    fn code(&self) -> CapCode {
        CapCode::LlgrOld
    }

    fn len(&self) -> u8 {
        // wire_count() <= 36, so wire_count() * 7 <= 252 fits a u8 and
        // `len() + 2` stays within a u8 for the optional-parameter framing.
        (self.wire_count() * Self::ENTRY_LEN) as u8
    }

    fn emit_value(&self, buf: &mut BytesMut) {
        for val in self.values.iter().take(self.wire_count()) {
            buf.put_u16(val.afi.into());
            buf.put_u8(val.safi.into());
            buf.put_u8(val.flags.into());
            buf.put(&u32_u24(val.stale_time)[..]);
        }
    }
}

impl fmt::Display for CapLlgr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = write!(f, "LLGR: ");
        for (i, value) in self.values.iter().enumerate() {
            if i > 0 {
                let _ = write!(f, ", ");
            }
            let _ = write!(
                f,
                "{}/{} F:{} StaleTime:{}",
                value.afi,
                value.safi,
                if value.flags.f_bit() { 1 } else { 0 },
                value.stale_time
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cap_with_entries(n: usize) -> CapLlgr {
        CapLlgr {
            values: (0..n)
                .map(|_| LlgrValue::new(Afi::Ip, Safi::Unicast, 120))
                .collect(),
        }
    }

    /// Emit the value, assert `len()` matches the bytes written and `len() + 2`
    /// fits a u8 (the optional-parameter framing), then parse it back.
    fn emit_and_parse(cap: &CapLlgr) -> (u8, CapLlgr) {
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
        let (rest, parsed) = CapLlgr::parse_be(&buf).expect("parse emitted value");
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
        assert_eq!(len, 14, "2 entries * 7");
        assert_eq!(parsed.values.len(), 2);
        assert_eq!(parsed, cap);
    }

    #[test]
    fn empty_round_trips() {
        let cap = CapLlgr::default();
        let (len, parsed) = emit_and_parse(&cap);
        assert_eq!(len, 0);
        assert_eq!(parsed, cap);
    }

    #[test]
    fn too_many_entries_clamped_to_budget() {
        // 50 entries * 7 = 350 octets would wrap the length octet; clamp to 36
        // entries (252 octets).
        let cap = cap_with_entries(50);
        let (len, parsed) = emit_and_parse(&cap);
        assert_eq!(len, 252, "36 entries * 7");
        assert_eq!(parsed.values.len(), 36);
        assert_eq!(len + 2, 254, "optional-parameter length stays within a u8");
    }
}
