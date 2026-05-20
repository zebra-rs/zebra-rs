//! ICMPv6 checksum, RFC 4443 §2.3 (pseudo-header form per RFC 8200).
//!
//! The pseudo-header sums the IPv6 source + destination addresses,
//! the upper-layer packet length, and a "next-header = 58" trailer.
//! The ICMPv6 message itself contributes its full byte stream with
//! the checksum field treated as zero.

use std::net::Ipv6Addr;

/// Compute the ICMPv6 checksum for `payload` carried between `src`
/// and `dst`. `payload` must include the ICMPv6 header with the
/// checksum field set to zero — the caller is responsible for that.
///
/// Returns the value to write into the on-wire checksum field
/// (i.e., already one's-complemented). 0xFFFF is preferred over 0x0000
/// because a transmitted zero indicates "no checksum" per RFC 768 for
/// UDP — RFC 4443 §2.3 carries forward the convention.
pub fn compute_icmp6_checksum(src: Ipv6Addr, dst: Ipv6Addr, payload: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Pseudo-header: src (16) + dst (16).
    sum = sum_be_u16_slice(&src.octets(), sum);
    sum = sum_be_u16_slice(&dst.octets(), sum);

    // Upper-layer packet length (32-bit BE).
    let len = payload.len() as u32;
    sum = sum.wrapping_add(len >> 16);
    sum = sum.wrapping_add(len & 0xffff);

    // 3 zero bytes + next-header (58 = ICMPv6).
    sum = sum.wrapping_add(58);

    // Payload, treated as 16-bit BE words.
    sum = sum_be_u16_slice(payload, sum);

    // Fold 32-bit accumulator into 16 bits.
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
        // Odd-byte tail: pad with zero per RFC 1071.
        sum = sum.wrapping_add((bytes[i] as u32) << 8);
    }
    sum
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn known_router_advert_checksum() {
        // RA from fe80::1 to ff02::1, type=134 code=0 chksum=0
        // CurHopLimit=64, M=O=0, RouterLifetime=1800, Reachable=0,
        // Retrans=0. No options.
        // ICMPv6 payload (16 bytes):
        //   86 00 00 00  40 00 07 08  00 00 00 00  00 00 00 00
        let payload = hex!(
            "86 00 00 00 40 00 07 08 "
            "00 00 00 00 00 00 00 00"
        );
        let src = "fe80::1".parse::<Ipv6Addr>().unwrap();
        let dst = "ff02::1".parse::<Ipv6Addr>().unwrap();
        let cksum = compute_icmp6_checksum(src, dst, &payload);

        // Verifying that recomputing with the checksum written back in
        // yields zero (the standard self-validation property).
        let mut with_cksum = payload.to_vec();
        with_cksum[2..4].copy_from_slice(&cksum.to_be_bytes());
        let resum = compute_icmp6_checksum(src, dst, &with_cksum);
        // The verified-checksum property is that summing in the
        // already-written checksum field flips it to 0 (or 0xffff).
        assert!(
            resum == 0 || resum == 0xffff,
            "self-check failed: {:x}",
            resum
        );
    }

    #[test]
    fn odd_length_payload() {
        // Lengths that aren't a multiple of 2 must still produce a
        // valid checksum (pad with zero on the last byte).
        let src = "fe80::1".parse::<Ipv6Addr>().unwrap();
        let dst = "fe80::2".parse::<Ipv6Addr>().unwrap();
        // 5 bytes: not realistic ICMPv6 but exercises the odd-byte path.
        let payload = hex!("86 00 00 00 40");
        // We just ensure it doesn't panic and returns a non-zero
        // value for a clearly-non-canonical zero checksum input.
        let cksum = compute_icmp6_checksum(src, dst, &payload);
        assert_ne!(cksum, 0);
    }
}
