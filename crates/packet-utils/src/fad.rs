use bytes::{BufMut, BytesMut};

/// Flex-Algorithm Definition Flags sub-TLV payload (RFC 9350) — the M-flag in
/// the top bit of the first octet, with any trailing octets preserved so
/// later-defined flags round-trip. Shared by the OSPFv2 and OSPFv3 FAD codecs.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct FadFlags {
    pub m_flag: bool,
    pub trailing: Vec<u8>,
}

impl FadFlags {
    pub fn parse_value(value: &[u8]) -> Self {
        Self {
            m_flag: value.first().is_some_and(|b| b & 0x80 != 0),
            trailing: value.get(1..).unwrap_or(&[]).to_vec(),
        }
    }

    pub fn value_len(&self) -> usize {
        1 + self.trailing.len()
    }

    pub fn emit_value(&self, buf: &mut BytesMut) {
        buf.put_u8(if self.m_flag { 0x80 } else { 0 });
        buf.put_slice(&self.trailing);
    }
}

/// Flex-Algorithm Definition Exclude-SRLG sub-TLV payload (RFC 9350) — an
/// ordered list of 32-bit SRLG identifiers. Shared by the OSPFv2 and OSPFv3
/// FAD codecs.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct FadSrlg {
    pub srlgs: Vec<u32>,
}

impl FadSrlg {
    /// Parse 4-byte SRLG values; a trailing remainder shorter than 4 bytes is
    /// dropped (matches the OSPFv2 `many0` and OSPFv3 `while >= 4` originals).
    pub fn parse_value(value: &[u8]) -> Self {
        Self {
            srlgs: value
                .chunks_exact(4)
                .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
                .collect(),
        }
    }

    pub fn value_len(&self) -> usize {
        self.srlgs.len() * 4
    }

    pub fn emit_value(&self, buf: &mut BytesMut) {
        for v in &self.srlgs {
            buf.put_u32(*v);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fad_flags_roundtrip() {
        let f = FadFlags {
            m_flag: true,
            trailing: vec![0x11, 0x22],
        };
        let mut buf = BytesMut::new();
        f.emit_value(&mut buf);
        assert_eq!(&buf[..], &[0x80, 0x11, 0x22]);
        assert_eq!(f.value_len(), 3);
        assert_eq!(FadFlags::parse_value(&buf), f);
        assert_eq!(FadFlags::parse_value(&[0x00]), FadFlags::default());
    }

    #[test]
    fn fad_srlg_roundtrip_and_drops_short_tail() {
        let s = FadSrlg {
            srlgs: vec![1, 0x0a0b_0c0d],
        };
        let mut buf = BytesMut::new();
        s.emit_value(&mut buf);
        assert_eq!(s.value_len(), 8);
        assert_eq!(FadSrlg::parse_value(&buf), s);
        // A trailing remainder shorter than 4 bytes is ignored.
        assert_eq!(
            FadSrlg::parse_value(&[0, 0, 0, 1, 0xFF]),
            FadSrlg { srlgs: vec![1] }
        );
    }
}
