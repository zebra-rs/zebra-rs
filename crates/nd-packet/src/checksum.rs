//! ICMPv6 checksum, RFC 4443 §2.3 (pseudo-header form per RFC 8200).
//!
//! Thin ND-facing wrapper over the shared
//! [`packet_utils::checksum_v6_pseudo`] with next-header 58 (ICMPv6).

use std::net::Ipv6Addr;

/// Compute the ICMPv6 checksum for `payload` carried between `src`
/// and `dst`. `payload` must include the ICMPv6 header with the
/// checksum field set to zero — the caller is responsible for that.
///
/// Returns the value to write into the on-wire checksum field
/// (already one's-complemented). `0xffff` is preferred over `0x0000`
/// per RFC 4443 §2.3.
pub fn compute_icmp6_checksum(src: Ipv6Addr, dst: Ipv6Addr, payload: &[u8]) -> u16 {
    packet_utils::checksum_v6_pseudo(src, dst, 58, payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn known_router_advert_checksum() {
        // RA from fe80::1 to ff02::1: the self-validation property
        // (writing the checksum back in yields 0/0xffff) still holds
        // through the delegated implementation.
        let payload = hex!("86 00 00 00 40 00 07 08 00 00 00 00 00 00 00 00");
        let src = "fe80::1".parse::<Ipv6Addr>().unwrap();
        let dst = "ff02::1".parse::<Ipv6Addr>().unwrap();
        let cksum = compute_icmp6_checksum(src, dst, &payload);
        let mut with_cksum = payload.to_vec();
        with_cksum[2..4].copy_from_slice(&cksum.to_be_bytes());
        let resum = compute_icmp6_checksum(src, dst, &with_cksum);
        assert!(
            resum == 0 || resum == 0xffff,
            "self-check failed: {:x}",
            resum
        );
    }
}
