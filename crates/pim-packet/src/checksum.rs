//! Internet checksum for PIM and IGMP/MLD.
//!
//! IPv4 PIM checksums the whole PIM message over a plain RFC 1071
//! sum; IPv6 PIM adds the RFC 8200 pseudo-header (next-header 103).
//! Register messages, in both families, checksum only the first eight
//! octets (header + flags word) so the encapsulated data packet is
//! excluded (RFC 7761 §4.9). IGMP checksums the whole message
//! plainly; MLD (ICMPv6) uses the pseudo-header (next-header 58).

use std::net::Ipv6Addr;

use internet_checksum::Checksum;
use packet_utils::checksum_v6_pseudo;

use crate::PimType;

/// PIM is IP protocol 103.
pub const PIM_NEXT_HEADER: u8 = 103;

/// Register checksum coverage: PIM header (4) + flags word (4).
const REGISTER_CHECKSUM_LEN: usize = 8;

/// The address-family context a PIM checksum is computed in. IPv4 is
/// a plain RFC 1071 sum; IPv6 folds in the pseudo-header, so it needs
/// the outer source and destination addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PimChecksumContext {
    Ipv4,
    Ipv6 { src: Ipv6Addr, dst: Ipv6Addr },
}

/// Compute the RFC 1071 internet checksum over `data` (checksum field
/// must be zero in the input). Returns the big-endian bytes to write
/// into the checksum field.
pub fn in_checksum(data: &[u8]) -> [u8; 2] {
    let mut cksum = Checksum::new();
    cksum.add_bytes(data);
    cksum.checksum()
}

/// Checksum coverage of a PIM message: whole message, except Register
/// which covers only the first eight octets.
fn pim_region(packet: &[u8]) -> &[u8] {
    let typ = PimType::from(packet[0] & 0x0f);
    if typ == PimType::Register && packet.len() >= REGISTER_CHECKSUM_LEN {
        &packet[..REGISTER_CHECKSUM_LEN]
    } else {
        packet
    }
}

/// Verify a received PIM message's checksum in its address-family
/// context. `packet` is the whole PIM message (transport payload)
/// including the on-wire checksum field.
///
/// For IPv6, RFC 7761 §4.9 allows a peer to checksum the entire
/// Register message (not just the first eight octets); the receive
/// path accepts either coverage for compatibility.
pub fn pim_verify_checksum(packet: &[u8], ctx: PimChecksumContext) -> bool {
    if packet.len() < 4 {
        return false;
    }
    match ctx {
        PimChecksumContext::Ipv4 => in_checksum(pim_region(packet)) == [0, 0],
        PimChecksumContext::Ipv6 { src, dst } => {
            let region = pim_region(packet);
            // A zero result over the covered region means valid.
            if checksum_v6_pseudo(src, dst, PIM_NEXT_HEADER, region) == 0xffff {
                return true;
            }
            // Compatibility: a peer that checksummed the whole
            // Register message.
            region.len() != packet.len()
                && checksum_v6_pseudo(src, dst, PIM_NEXT_HEADER, packet) == 0xffff
        }
    }
}

/// Verify a received IGMP message's checksum (plain, whole message).
pub fn igmp_verify_checksum(packet: &[u8]) -> bool {
    if packet.len() < 4 {
        return false;
    }
    in_checksum(packet) == [0, 0]
}

/// Verify a received MLD message's checksum (ICMPv6 pseudo-header,
/// next-header 58, whole message).
pub fn mld_verify_checksum(packet: &[u8], src: Ipv6Addr, dst: Ipv6Addr) -> bool {
    if packet.len() < 4 {
        return false;
    }
    checksum_v6_pseudo(src, dst, 58, packet) == 0xffff
}

/// Fill the PIM checksum field (bytes 2..4) of an emitted message
/// sitting at offset 0 of `buf`, in its address-family context.
pub(crate) fn pim_fill_checksum(buf: &mut [u8], ctx: PimChecksumContext) {
    let region_len = pim_region(buf).len();
    match ctx {
        PimChecksumContext::Ipv4 => {
            let cksum = in_checksum(&buf[..region_len]);
            buf[2..4].copy_from_slice(&cksum);
        }
        PimChecksumContext::Ipv6 { src, dst } => {
            let cksum = checksum_v6_pseudo(src, dst, PIM_NEXT_HEADER, &buf[..region_len]);
            buf[2..4].copy_from_slice(&cksum.to_be_bytes());
        }
    }
}

/// Fill the IGMP checksum field (bytes 2..4) of an emitted message
/// sitting at offset 0 of `buf`.
pub(crate) fn igmp_fill_checksum(buf: &mut [u8]) {
    let cksum = in_checksum(buf);
    buf[2..4].copy_from_slice(&cksum);
}

/// Fill the MLD (ICMPv6) checksum field (bytes 2..4).
pub(crate) fn mld_fill_checksum(buf: &mut [u8], src: Ipv6Addr, dst: Ipv6Addr) {
    let cksum = checksum_v6_pseudo(src, dst, 58, buf);
    buf[2..4].copy_from_slice(&cksum.to_be_bytes());
}
