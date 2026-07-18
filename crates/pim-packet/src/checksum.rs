//! Internet checksum (RFC 1071) helpers for PIM and IGMP.
//!
//! IPv4 PIM checksums the whole PIM message, except Register, whose
//! checksum covers only the first 8 octets (header + flags word) so
//! the encapsulated data packet is excluded (RFC 7761 §4.9). IGMP
//! checksums the whole IGMP message. IPv6 PIM adds a pseudo-header —
//! out of scope until the pim6 arc.

use internet_checksum::Checksum;

use crate::PimType;

/// Register checksum coverage: PIM header (4) + flags word (4).
const REGISTER_CHECKSUM_LEN: usize = 8;

/// Compute the internet checksum over `data` (checksum field must be
/// zero in the input). Returns the big-endian bytes to write into the
/// checksum field.
pub fn in_checksum(data: &[u8]) -> [u8; 2] {
    let mut cksum = Checksum::new();
    cksum.add_bytes(data);
    cksum.checksum()
}

/// Verify a received PIM message's checksum. `packet` is the whole
/// PIM message (IP payload) including the on-wire checksum field.
/// Register messages are verified over the first 8 octets only.
pub fn pim_verify_checksum(packet: &[u8]) -> bool {
    if packet.len() < 4 {
        return false;
    }
    let typ = PimType::from(packet[0] & 0x0f);
    let region = if typ == PimType::Register && packet.len() >= REGISTER_CHECKSUM_LEN {
        &packet[..REGISTER_CHECKSUM_LEN]
    } else {
        packet
    };
    in_checksum(region) == [0, 0]
}

/// Verify a received IGMP message's checksum over the whole message.
pub fn igmp_verify_checksum(packet: &[u8]) -> bool {
    if packet.len() < 4 {
        return false;
    }
    in_checksum(packet) == [0, 0]
}

/// Fill the PIM checksum field (bytes 2..4) of an emitted message
/// sitting at offset 0 of `buf`.
pub(crate) fn pim_fill_checksum(typ: PimType, buf: &mut [u8]) {
    let region_end = if typ == PimType::Register && buf.len() >= REGISTER_CHECKSUM_LEN {
        REGISTER_CHECKSUM_LEN
    } else {
        buf.len()
    };
    let cksum = in_checksum(&buf[..region_end]);
    buf[2..4].copy_from_slice(&cksum);
}

/// Fill the IGMP checksum field (bytes 2..4) of an emitted message
/// sitting at offset 0 of `buf`.
pub(crate) fn igmp_fill_checksum(buf: &mut [u8]) {
    let cksum = in_checksum(buf);
    buf[2..4].copy_from_slice(&cksum);
}
