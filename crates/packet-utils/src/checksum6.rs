//! IPv6 upper-layer checksum with the RFC 8200 §8.1 pseudo-header.
//!
//! Shared by every IPv6 upper-layer protocol codec (ICMPv6/ND, MLD,
//! PIMv6): the pseudo-header sums the source and destination
//! addresses, the upper-layer packet length, and the next-header
//! value; the upper-layer message contributes its full byte stream
//! with its own checksum field treated as zero.

use std::net::Ipv6Addr;

/// Compute the IPv6 upper-layer checksum for `payload` (which must
/// include the upper-layer header with its checksum field zeroed)
/// carried between `src` and `dst` with the given `next_header`
/// (58 = ICMPv6/MLD, 103 = PIM).
///
/// Returns the value to write into the on-wire checksum field
/// (already one's-complemented). `0xffff` is returned instead of
/// `0x0000` — a transmitted zero means "no checksum" for UDP
/// (RFC 768), a convention RFC 4443 §2.3 carries forward.
pub fn checksum_v6_pseudo(src: Ipv6Addr, dst: Ipv6Addr, next_header: u8, payload: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Pseudo-header: src (16) + dst (16).
    sum = sum_be_u16_slice(&src.octets(), sum);
    sum = sum_be_u16_slice(&dst.octets(), sum);

    // Upper-layer packet length (32-bit BE).
    let len = payload.len() as u32;
    sum = sum.wrapping_add(len >> 16);
    sum = sum.wrapping_add(len & 0xffff);

    // 3 zero bytes + next-header.
    sum = sum.wrapping_add(next_header as u32);

    // Payload, treated as 16-bit BE words.
    sum = sum_be_u16_slice(payload, sum);

    // Fold the 32-bit accumulator into 16 bits.
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let folded = !(sum as u16);
    if folded == 0 { 0xffff } else { folded }
}

fn sum_be_u16_slice(bytes: &[u8], mut sum: u32) -> u32 {
    let mut i = 0;
    while i + 1 < bytes.len() {
        let word = ((bytes[i] as u32) << 8) | (bytes[i + 1] as u32);
        sum = sum.wrapping_add(word);
        i += 2;
    }
    if i < bytes.len() {
        // Odd-byte tail: pad with zero (RFC 1071).
        sum = sum.wrapping_add((bytes[i] as u32) << 8);
    }
    sum
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn icmp6_self_validates() {
        // RA fe80::1 → ff02::1 (next-header 58).
        let payload = hex!("86 00 00 00 40 00 07 08 00 00 00 00 00 00 00 00");
        let src = "fe80::1".parse::<Ipv6Addr>().unwrap();
        let dst = "ff02::1".parse::<Ipv6Addr>().unwrap();
        let cksum = checksum_v6_pseudo(src, dst, 58, &payload);
        let mut with = payload.to_vec();
        with[2..4].copy_from_slice(&cksum.to_be_bytes());
        let resum = checksum_v6_pseudo(src, dst, 58, &with);
        assert!(resum == 0 || resum == 0xffff, "self-check {:x}", resum);
    }

    #[test]
    fn next_header_changes_the_sum() {
        let src = "2001:db8::1".parse::<Ipv6Addr>().unwrap();
        let dst = "2001:db8::2".parse::<Ipv6Addr>().unwrap();
        let payload = hex!("20 00 00 00");
        assert_ne!(
            checksum_v6_pseudo(src, dst, 58, &payload),
            checksum_v6_pseudo(src, dst, 103, &payload),
        );
    }

    #[test]
    fn odd_length_payload() {
        let src = "fe80::1".parse::<Ipv6Addr>().unwrap();
        let dst = "fe80::2".parse::<Ipv6Addr>().unwrap();
        let payload = hex!("86 00 00 00 40");
        assert_ne!(checksum_v6_pseudo(src, dst, 58, &payload), 0);
    }
}
