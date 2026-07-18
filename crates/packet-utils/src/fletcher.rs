use fletcher::calc_fletcher16;

/// Compute an RFC 1008 Fletcher checksum for an LSA/LSP-style packet whose
/// 2-byte checksum field sits at `cksum_offset` within `data` (where `data`
/// starts at the first checksummed byte). Returns the 16-bit checksum with the
/// high byte first.
///
/// Shared by the OSPF LSA checksum (`cksum_offset = 14`, data starting after
/// the 2-byte LS-Age field) and the IS-IS checksum (`cksum_offset = 12`). The
/// IS-IS form is exactly the offset-12 specialization of this function, so both
/// codecs delegate here instead of carrying their own copy of the mod-255
/// adjustment math.
pub fn fletcher_lsa_checksum(data: &[u8], cksum_offset: usize) -> u16 {
    if data.len() <= cksum_offset {
        return 0;
    }
    let checksum = calc_fletcher16(data);
    let mut c0 = (checksum & 0x00FF) as i32;
    let mut c1 = ((checksum >> 8) & 0x00FF) as i32;

    // sop = position of the checksum field counted from the end.
    let sop = (data.len() - cksum_offset - 1) as i32;
    let mut x = (sop * c0 - c1) % 255;
    if x <= 0 {
        x += 255;
    }
    c1 = 510 - c0 - x;
    if c1 > 255 {
        c1 -= 255;
    }
    c0 = x;

    ((c0 as u16) << 8) | (c1 as u16)
}

#[cfg(test)]
mod tests {
    use super::fletcher_lsa_checksum;
    use fletcher::calc_fletcher16;

    /// The original IS-IS `checksum_calc`, kept verbatim as a reference to lock
    /// the claim that IS-IS is the `cksum_offset = 12` specialization of the
    /// shared function.
    fn isis_reference(data: &[u8]) -> [u8; 2] {
        if data.len() < 13 {
            return [0, 0];
        }
        let checksum = calc_fletcher16(data);
        let mut c0 = (checksum & 0x00FF) as i32;
        let mut c1 = ((checksum >> 8) & 0x00FF) as i32;
        let sop = data.len() as u16 - 13;
        let mut x = (sop as i32 * c0 - c1) % 255;
        if x <= 0 {
            x += 255;
        }
        c1 = 510 - c0 - x;
        if c1 > 255 {
            c1 -= 255;
        }
        c0 = x;
        [c0 as u8, c1 as u8]
    }

    #[test]
    fn matches_isis_reference_at_offset_12() {
        for len in [13usize, 20, 30, 47, 64, 255] {
            let data: Vec<u8> = (0..len)
                .map(|i| (i as u8).wrapping_mul(37).wrapping_add(1))
                .collect();
            assert_eq!(
                fletcher_lsa_checksum(&data, 12).to_be_bytes(),
                isis_reference(&data),
                "len {len}"
            );
        }
    }

    #[test]
    fn short_data_returns_zero() {
        // Guard matches both callers' originals (IS-IS `< 13`, OSPF `<= 14`).
        assert_eq!(fletcher_lsa_checksum(&[1, 2, 3], 14), 0);
        assert_eq!(fletcher_lsa_checksum(&[0u8; 12], 12), 0);
        assert_eq!(fletcher_lsa_checksum(&[], 12), 0);
    }
}
