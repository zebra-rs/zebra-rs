//! Exponent-coded time fields shared by IGMPv3 (RFC 3376 §4.1.1,
//! §4.1.7) and MLDv2 (RFC 3810 §5.1.3, §5.1.9): the Max Response
//! Code / Max Response Delay and the Querier's Query Interval Code.
//!
//! A value below 128 is carried verbatim. From 128 up, the octet is
//! `0b1EEE_MMMM` and the represented value is
//! `(0x10 | mant) << (exp + 3)`, extending the range far past the
//! 8-bit maximum. IGMP times are in units of 1/10 s; MLD Max Resp is
//! in ms and QQIC in s — the unit is the caller's concern, this is
//! the raw code↔value transform. MLDv2 Max Resp is 16-bit but uses
//! the same rule; expose both widths.

/// Decode an 8-bit exponent-coded field (Max Resp / QQIC).
pub fn code_to_value(code: u8) -> u16 {
    if code < 128 {
        code as u16
    } else {
        let mant = (code & 0x0f) as u16;
        let exp = ((code >> 4) & 0x07) as u32;
        (0x10 | mant) << (exp + 3)
    }
}

/// Encode a value into an 8-bit exponent-coded field. Values < 128
/// pass through; larger values pick the smallest exponent whose
/// mantissa fits, saturating at the maximum representable code
/// (`0xff` ≈ 31744).
pub fn value_to_code(value: u16) -> u8 {
    if value < 128 {
        return value as u8;
    }
    for exp in 0u32..8 {
        // value = (0x10 | mant) << (exp + 3), mant in 0..=15.
        let base = 0x10u32 << (exp + 3);
        let step = 1u32 << (exp + 3);
        let v = value as u32;
        if v < base + 16 * step {
            let mant = ((v - base) / step).min(15) as u8;
            return 0x80 | ((exp as u8) << 4) | mant;
        }
    }
    0xff
}

/// Decode a 16-bit MLDv2 Max Response Code (RFC 3810 §5.1.3): the
/// same rule with a 12-bit mantissa/exponent split above `0x8000`.
pub fn code16_to_value(code: u16) -> u32 {
    if code < 0x8000 {
        code as u32
    } else {
        let mant = (code & 0x0fff) as u32;
        let exp = ((code >> 12) & 0x07) as u32;
        (0x1000 | mant) << (exp + 3)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_values_pass_through() {
        for v in [0u16, 1, 10, 100, 127] {
            assert_eq!(code_to_value(v as u8), v);
            assert_eq!(value_to_code(v), v as u8);
        }
    }

    #[test]
    fn exponent_form_round_trips_representable_values() {
        // Every code >= 128 decodes; re-encoding the decoded value
        // reproduces the same code (canonical representables).
        for code in 128u16..=255 {
            let v = code_to_value(code as u8);
            assert_eq!(value_to_code(v), code as u8, "code {code:#x} -> {v}");
        }
    }

    #[test]
    fn known_igmp_values() {
        // RFC 3376: Max Resp Code 0x80 → 128 base? decode check.
        assert_eq!(code_to_value(0x80), (0x10) << 3); // mant 0, exp 0
        assert_eq!(code_to_value(0xff), (0x1f) << 10); // mant 15, exp 7
    }

    #[test]
    fn large_value_encodes_above_255() {
        // A 400-decisecond max-resp (40 s) exceeds 8 bits and must
        // round-trip through the exponent form, not clamp to 255.
        let code = value_to_code(400);
        assert!(code >= 128);
        // Decodes back to a value near 400 (canonical granularity).
        let v = code_to_value(code);
        assert!((384..=416).contains(&v), "decoded {v}");
    }

    #[test]
    fn code16_matches_8bit_below_threshold() {
        assert_eq!(code16_to_value(100), 100);
        assert_eq!(code16_to_value(0x8000), 0x1000 << 3);
    }
}
