use std::fmt;

use bytes::{BufMut, BytesMut};

use crate::AttributeFlags;

/// An optional path attribute whose Type Code this implementation does
/// not recognize (RFC 4271 §5, §9). The flags, type code, and raw value
/// bytes are retained verbatim so an unrecognized **transitive** optional
/// attribute can be re-advertised to other peers (with the Partial bit
/// set). Unrecognized **non-transitive** optional attributes are never
/// stored here — they are dropped at parse time per RFC 4271 §9.
///
/// `flags` is the original Attribute Flags octet as received, except that
/// the Partial bit (0x20) is set when the attribute is stored, matching
/// RFC 4271 §9: "the Partial bit ... is set to 1, and the attribute is
/// retained for propagation to other BGP speakers." The Extended-Length
/// bit is recomputed from `value.len()` at emit time and is therefore not
/// authoritative in `flags`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnknownAttr {
    /// Attribute Flags octet (Optional / Transitive / Partial / Extended).
    pub flags: u8,
    /// Attribute Type Code.
    pub type_code: u8,
    /// Raw attribute Value bytes (Length octet(s) excluded).
    pub value: Vec<u8>,
}

impl UnknownAttr {
    pub fn new(flags: u8, type_code: u8, value: Vec<u8>) -> Self {
        Self {
            flags,
            type_code,
            value,
        }
    }

    fn flag_set(&self) -> AttributeFlags {
        AttributeFlags::from_bits_truncate(self.flags)
    }

    pub fn is_optional(&self) -> bool {
        self.flag_set().contains(AttributeFlags::OPTIONAL)
    }

    pub fn is_transitive(&self) -> bool {
        self.flag_set().contains(AttributeFlags::TRANSITIVE)
    }

    pub fn is_partial(&self) -> bool {
        self.flag_set().contains(AttributeFlags::PARTIAL)
    }

    /// Mark the attribute Partial (RFC 4271 §9). Called when an
    /// unrecognized transitive optional attribute is retained on receive.
    pub fn set_partial(&mut self) {
        self.flags |= AttributeFlags::PARTIAL.bits();
    }

    /// Emit the attribute verbatim — flags, type, length, value — for
    /// propagation. The Extended-Length bit is (re)derived from the value
    /// length so the on-wire length field width always matches; the other
    /// flag bits (Optional / Transitive / Partial) are written as stored.
    pub fn attr_emit(&self, buf: &mut BytesMut) {
        let len = self.value.len();
        let extended = len > 255;
        let mut flags = self.flags;
        if extended {
            flags |= AttributeFlags::EXTENDED.bits();
        } else {
            flags &= !AttributeFlags::EXTENDED.bits();
        }
        buf.put_u8(flags);
        buf.put_u8(self.type_code);
        if extended {
            buf.put_u16(len as u16);
        } else {
            buf.put_u8(len as u8);
        }
        buf.put_slice(&self.value);
    }
}

impl fmt::Display for UnknownAttr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value: String = self.value.iter().map(|b| format!("{b:02x}")).collect();
        write!(
            f,
            "type {} flags {} [{}] value 0x{}",
            self.type_code,
            self.flags,
            self.flag_set(),
            if value.is_empty() { "" } else { &value }
        )
    }
}

impl fmt::Debug for UnknownAttr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UnknownAttr {{ {} }}", self)
    }
}
