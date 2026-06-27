use std::fmt;

use bytes::{BufMut, BytesMut};
use nom::{IResult, number::complete::be_u8};
use nom_derive::*;
use strum_macros::{Display, EnumString};

use super::{CapCode, CapEmit};
use crate::{Afi, Safi};

#[derive(Debug, PartialEq, NomBE, Clone, Ord, PartialOrd, Eq)]
pub struct AddPathValue {
    pub afi: Afi,
    pub safi: Safi,
    pub send_receive: AddPathSendReceive,
}

#[repr(u8)]
#[derive(Debug, Clone, PartialEq, Copy, Ord, PartialOrd, Eq, Display, EnumString)]
pub enum AddPathSendReceive {
    #[strum(serialize = "receive")]
    Receive = 1,
    #[strum(serialize = "send")]
    Send = 2,
    #[strum(serialize = "send-receive")]
    SendReceive = 3,
    #[strum(disabled)]
    Unknown(u8),
}

impl From<AddPathSendReceive> for u8 {
    fn from(typ: AddPathSendReceive) -> Self {
        use AddPathSendReceive::*;
        match typ {
            Receive => 1,
            Send => 2,
            SendReceive => 3,
            Unknown(v) => v,
        }
    }
}

impl From<u8> for AddPathSendReceive {
    fn from(typ: u8) -> Self {
        use AddPathSendReceive::*;
        match typ {
            1 => Receive,
            2 => Send,
            3 => SendReceive,
            v => Unknown(v),
        }
    }
}

impl AddPathSendReceive {
    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, val) = be_u8(input)?;
        let send_receive: Self = val.into();
        Ok((input, send_receive))
    }

    pub fn is_receive(&self) -> bool {
        *self == AddPathSendReceive::Receive || *self == AddPathSendReceive::SendReceive
    }

    pub fn is_send(&self) -> bool {
        *self == AddPathSendReceive::Send || *self == AddPathSendReceive::SendReceive
    }
}

// Display and FromStr implementation now provided by strum macros
// Note: The Unknown variant will display as "Unknown" and cannot be parsed from string

#[derive(Debug, Default, PartialEq, NomBE, Clone)]
pub struct CapAddPath {
    pub values: Vec<AddPathValue>,
}

impl CapAddPath {
    pub fn new(afi: Afi, safi: Safi, send_receive: u8) -> Self {
        Self {
            values: vec![AddPathValue {
                afi,
                safi,
                send_receive: send_receive.into(),
            }],
        }
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Each AddPath entry is 4 octets on the wire (AFI u16 + SAFI u8 +
    /// Send/Receive u8). A capability value is at most 253 octets — the BGP
    /// optional-parameter that carries it has a single length octet covering
    /// `code(1) + length(1) + value` (`emit.rs` writes `put_u8(len() + 2)`),
    /// so `value <= 255 - 2` — which fits at most 63 entries (252 octets).
    const ENTRY_LEN: usize = 4;
    const MAX_ENTRIES: usize = 253 / Self::ENTRY_LEN; // 63

    /// Number of entries actually written on the wire. `len()` and
    /// `emit_value()` both derive from this so the declared length always
    /// matches the bytes emitted and the `as u8` cast cannot truncate; entries
    /// beyond the budget are dropped rather than wrapping the length octet.
    fn wire_count(&self) -> usize {
        self.values.len().min(Self::MAX_ENTRIES)
    }
}

impl CapEmit for CapAddPath {
    fn code(&self) -> CapCode {
        CapCode::AddPath
    }

    fn len(&self) -> u8 {
        // wire_count() <= 63, so wire_count() * 4 <= 252 fits a u8 and
        // `len() + 2` stays within a u8 for the optional-parameter framing.
        (self.wire_count() * Self::ENTRY_LEN) as u8
    }

    fn emit_value(&self, buf: &mut BytesMut) {
        for val in self.values.iter().take(self.wire_count()) {
            buf.put_u16(val.afi.into());
            buf.put_u8(val.safi.into());
            buf.put_u8(val.send_receive.into());
        }
    }
}

impl fmt::Display for CapAddPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = write!(f, "AddPath: ");
        for (i, value) in self.values.iter().enumerate() {
            if i > 0 {
                let _ = write!(f, ", ");
            }
            let _ = write!(f, "{}/{}: {}", value.afi, value.safi, value.send_receive);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cap_with_entries(n: usize) -> CapAddPath {
        CapAddPath {
            values: (0..n)
                .map(|_| AddPathValue {
                    afi: Afi::Ip,
                    safi: Safi::Unicast,
                    send_receive: AddPathSendReceive::SendReceive,
                })
                .collect(),
        }
    }

    /// Emit the value, assert `len()` matches the bytes written and `len() + 2`
    /// fits a u8 (the optional-parameter framing), then parse it back.
    fn emit_and_parse(cap: &CapAddPath) -> (u8, CapAddPath) {
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
        let (rest, parsed) = CapAddPath::parse_be(&buf).expect("parse emitted value");
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
        assert_eq!(len, 8, "2 entries * 4");
        assert_eq!(parsed.values.len(), 2);
        assert_eq!(parsed, cap);
    }

    #[test]
    fn empty_round_trips() {
        let cap = CapAddPath::default();
        let (len, parsed) = emit_and_parse(&cap);
        assert_eq!(len, 0);
        assert_eq!(parsed, cap);
    }

    #[test]
    fn too_many_entries_clamped_to_budget() {
        // 100 entries * 4 = 400 octets would wrap the length octet; clamp to 63
        // entries (252 octets).
        let cap = cap_with_entries(100);
        let (len, parsed) = emit_and_parse(&cap);
        assert_eq!(len, 252, "63 entries * 4");
        assert_eq!(parsed.values.len(), 63);
        assert_eq!(len + 2, 254, "optional-parameter length stays within a u8");
    }
}
