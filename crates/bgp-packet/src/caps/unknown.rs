use std::fmt;

use bytes::{BufMut, BytesMut};
use nom_derive::*;

use super::{CapCode, CapEmit};

#[derive(Debug, PartialEq, NomBE, Clone, Default)]
pub struct CapUnknown {
    /// Capability code, stamped in by `CapabilityPacket::parse_cap` after it has
    /// stripped the code/length header. It is deliberately NOT parsed from the
    /// value: the slice handed to this parser already has the 2-byte header
    /// removed, so parsing a `CapabilityHeader` here would re-read two value
    /// octets and fail on any capability (e.g. RFC 9234 Role, code 9 len 1)
    /// whose value is shorter than two bytes — rejecting the whole OPEN instead
    /// of ignoring the unknown capability as RFC 5492 requires.
    #[nom(Ignore)]
    pub code: u8,
    pub data: Vec<u8>,
}

impl CapUnknown {
    /// The capability value is the opaque `data` blob, at most 253 octets on
    /// the wire: the BGP optional-parameter that carries it has a single length
    /// octet covering `code(1) + length(1) + value` (`emit.rs` writes
    /// `put_u8(len() + 2)`), so `value <= 255 - 2`.
    const VALUE_MAX: usize = 253;

    /// Number of data octets actually written on the wire. Clamped to the
    /// capability-value budget so the `as u8` length cast cannot truncate and
    /// the length octet always matches the bytes emitted. `len()` and
    /// `emit_value()` both derive from this.
    fn wire_len(&self) -> usize {
        self.data.len().min(Self::VALUE_MAX)
    }
}

impl CapEmit for CapUnknown {
    fn code(&self) -> CapCode {
        CapCode::Unknown(self.code)
    }

    fn len(&self) -> u8 {
        // wire_len() <= 253, so the cast cannot truncate and `len() + 2` stays
        // within a u8 for the optional-parameter framing.
        self.wire_len() as u8
    }

    fn emit_value(&self, buf: &mut BytesMut) {
        let n = self.wire_len();
        buf.put(&self.data[..n]);
    }
}

impl fmt::Display for CapUnknown {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Unknown: Code {}", self.code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cap_with_data(n: usize) -> CapUnknown {
        CapUnknown {
            code: 100,
            data: vec![0xab; n],
        }
    }

    #[test]
    fn len_matches_emitted_bytes() {
        let cap = cap_with_data(10);
        let mut buf = BytesMut::new();
        cap.emit_value(&mut buf);
        assert_eq!(
            cap.len() as usize,
            buf.len(),
            "len() must equal emitted bytes"
        );
        assert_eq!(cap.len(), 10);
    }

    #[test]
    fn empty_data() {
        let cap = cap_with_data(0);
        let mut buf = BytesMut::new();
        cap.emit_value(&mut buf);
        assert!(buf.is_empty());
        assert_eq!(cap.len(), 0);
    }

    #[test]
    fn oversized_data_clamped_to_budget() {
        // 300-octet blob clamps to 253; len() + 2 stays within a u8.
        let cap = cap_with_data(300);
        let mut buf = BytesMut::new();
        cap.emit_value(&mut buf);
        assert_eq!(cap.len(), 253);
        assert_eq!(buf.len(), 253, "emitted bytes match len()");
        assert_eq!(
            cap.len() + 2,
            255,
            "optional-parameter length stays within a u8"
        );
    }
}
