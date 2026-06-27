use std::{borrow::Cow, fmt};

use bytes::{BufMut, BytesMut};
use nom_derive::*;

use super::{CapCode, CapEmit};

#[derive(Debug, Default, PartialEq, NomBE, Clone)]
pub struct CapVersion {
    pub version: Vec<u8>,
}

impl CapVersion {
    pub fn new(version: &str) -> Self {
        Self {
            version: version.into(),
        }
    }

    pub fn version(&self) -> Cow<'_, str> {
        if self.version.is_empty() {
            Cow::Borrowed("n/a")
        } else {
            String::from_utf8_lossy(&self.version)
        }
    }

    /// The capability value is the version string itself, at most 253 octets
    /// on the wire: the BGP optional-parameter that carries it has a single
    /// length octet covering `code(1) + length(1) + value` (`emit.rs` writes
    /// `put_u8(len() + 2)`), so `value <= 255 - 2`.
    const VALUE_MAX: usize = 253;

    /// Number of version octets actually written on the wire. Clamped to the
    /// capability-value budget so the `as u8` length cast cannot truncate and
    /// the length octet always matches the bytes emitted. `len()` and
    /// `emit_value()` both derive from this.
    fn wire_len(&self) -> usize {
        self.version.len().min(Self::VALUE_MAX)
    }
}

impl CapEmit for CapVersion {
    fn code(&self) -> CapCode {
        CapCode::SoftwareVersion
    }

    fn len(&self) -> u8 {
        // wire_len() <= 253, so the cast cannot truncate and `len() + 2` stays
        // within a u8 for the optional-parameter framing.
        self.wire_len() as u8
    }

    fn emit_value(&self, buf: &mut BytesMut) {
        let n = self.wire_len();
        buf.put(&self.version[..n]);
    }
}

impl fmt::Display for CapVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Software Version: {}",
            String::from_utf8_lossy(&self.version)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Emit the value, assert `len()` matches the bytes written and `len() + 2`
    /// fits a u8 (the optional-parameter framing), then parse it back.
    fn emit_and_parse(cap: &CapVersion) -> (u8, CapVersion) {
        let mut buf = BytesMut::new();
        cap.emit_value(&mut buf);
        assert_eq!(
            cap.len() as usize,
            buf.len(),
            "len() must equal the emitted byte count"
        );
        // emit.rs writes the optional-parameter length as `put_u8(len() + 2)`.
        assert!(
            cap.len().checked_add(2).is_some(),
            "len() + 2 must fit a u8"
        );
        let (rest, parsed) = CapVersion::parse_be(&buf).expect("parse emitted value");
        assert!(
            rest.is_empty(),
            "emit_value must be fully consumed by parse"
        );
        (cap.len(), parsed)
    }

    #[test]
    fn normal_round_trip() {
        let cap = CapVersion::new("zebra-rs 1.0");
        let (len, parsed) = emit_and_parse(&cap);
        assert_eq!(len as usize, "zebra-rs 1.0".len());
        assert_eq!(parsed, cap);
    }

    #[test]
    fn empty_version_round_trips() {
        let cap = CapVersion::default();
        let (len, parsed) = emit_and_parse(&cap);
        assert_eq!(len, 0);
        assert_eq!(parsed, cap);
    }

    #[test]
    fn oversized_version_clamped_to_budget() {
        // 300-octet version clamps to 253; len() + 2 stays within a u8.
        let cap = CapVersion::new(&"v".repeat(300));
        let (len, parsed) = emit_and_parse(&cap);
        assert_eq!(parsed.version.len(), 253);
        assert_eq!(len, 253);
        assert_eq!(len + 2, 255, "optional-parameter length stays within a u8");
    }
}
