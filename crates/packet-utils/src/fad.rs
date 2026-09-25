use bytes::{BufMut, BytesMut};

/// Flex-Algorithm Definition Flags sub-TLV payload (RFC 9350) — the M-flag in
/// the top bit of the first octet. Every other bit is kept too, the rest of
/// the first octet and any octets after it: "Implementations MUST check all
/// advertised flag bits ... not just the subset currently defined" (RFC 9350
/// §6.4), since a router that does not support a flag set in the winning
/// definition must stop participating. Shared by the OSPFv2 and OSPFv3 FAD
/// codecs.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct FadFlags {
    pub m_flag: bool,
    /// The rest of the first octet — every bit but M — as received.
    pub other: u8,
    pub trailing: Vec<u8>,
}

impl FadFlags {
    pub fn parse_value(value: &[u8]) -> Self {
        let first = value.first().copied().unwrap_or(0);
        Self {
            m_flag: first & 0x80 != 0,
            other: first & 0x7f,
            trailing: value.get(1..).unwrap_or(&[]).to_vec(),
        }
    }

    /// Whether any flag but M is set: none other is defined today.
    pub fn has_unknown(&self) -> bool {
        self.other != 0 || self.trailing.iter().any(|b| *b != 0)
    }

    pub fn value_len(&self) -> usize {
        1 + self.trailing.len()
    }

    pub fn emit_value(&self, buf: &mut BytesMut) {
        let m = if self.m_flag { 0x80 } else { 0 };
        buf.put_u8(m | (self.other & 0x7f));
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
        let (srlgs, _) = value.as_chunks::<4>();
        Self {
            srlgs: srlgs.iter().copied().map(u32::from_be_bytes).collect(),
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
            ..Default::default()
        };
        let mut buf = BytesMut::new();
        f.emit_value(&mut buf);
        assert_eq!(&buf[..], &[0x80, 0x11, 0x22]);
        assert_eq!(f.value_len(), 3);
        assert_eq!(FadFlags::parse_value(&buf), f);
        assert_eq!(FadFlags::parse_value(&[0x00]), FadFlags::default());
    }

    /// RFC 9350 §6.4: every advertised flag bit is checked, so every bit
    /// survives the parse — M, an unknown bit in the first octet, and an
    /// octet past it — and re-emits as received.
    #[test]
    fn fad_flags_keep_every_bit() {
        for (bytes, m, unknown) in [
            (&[0x80u8][..], true, false),
            (&[0x40][..], false, true),
            (&[0xC1][..], true, true),
            (&[0x00, 0x01][..], false, true),
            (&[0x00, 0x00][..], false, false),
        ] {
            let f = FadFlags::parse_value(bytes);
            assert_eq!((f.m_flag, f.has_unknown()), (m, unknown), "{bytes:?}");
            let mut buf = BytesMut::new();
            f.emit_value(&mut buf);
            assert_eq!(&buf[..], bytes);
        }
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
