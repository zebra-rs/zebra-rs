//! What goes on the wire below DHCP while the interface has no address:
//! IPv4 + UDP datagrams built and parsed by hand for the packet socket,
//! and the ARP probes of address conflict detection (RFC 5227).

use std::net::Ipv4Addr;

const IPV4_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;
const IPPROTO_UDP: u8 = 17;

/// The Internet checksum (RFC 1071) of `data`, continuing from `sum`.
fn ones_complement_sum(mut sum: u32, data: &[u8]) -> u32 {
    let (pairs, rest) = data.as_chunks::<2>();
    for pair in pairs {
        sum += u32::from(u16::from_be_bytes(*pair));
    }
    if let [last] = rest {
        sum += u32::from(*last) << 8;
    }
    sum
}

fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// The UDP checksum over the pseudo-header and `udp` (header + payload).
fn udp_checksum(source: Ipv4Addr, destination: Ipv4Addr, udp: &[u8]) -> u16 {
    let mut sum = ones_complement_sum(0, &source.octets());
    sum = ones_complement_sum(sum, &destination.octets());
    sum += u32::from(IPPROTO_UDP) + udp.len() as u32;
    fold(ones_complement_sum(sum, udp))
}

/// An IPv4 datagram carrying `payload` over UDP, checksums filled in.
pub fn udp_datagram(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = UDP_HEADER_LEN + payload.len();
    let total_len = IPV4_HEADER_LEN + udp_len;
    let mut out = Vec::with_capacity(total_len);
    // Version 4, header length 5 words; DSCP 0x10 (low delay), as other
    // clients send.
    out.extend_from_slice(&[0x45, 0x10]);
    out.extend_from_slice(&(total_len as u16).to_be_bytes());
    // Identification 0, don't fragment.
    out.extend_from_slice(&[0, 0, 0x40, 0]);
    out.extend_from_slice(&[64, IPPROTO_UDP, 0, 0]);
    out.extend_from_slice(&source.octets());
    out.extend_from_slice(&destination.octets());
    let header_checksum = fold(ones_complement_sum(0, &out));
    out[10..12].copy_from_slice(&header_checksum.to_be_bytes());

    out.extend_from_slice(&source_port.to_be_bytes());
    out.extend_from_slice(&destination_port.to_be_bytes());
    out.extend_from_slice(&(udp_len as u16).to_be_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(payload);
    let checksum = match udp_checksum(source, destination, &out[IPV4_HEADER_LEN..]) {
        // Zero means "no checksum" on the wire (RFC 768).
        0 => 0xffff,
        sum => sum,
    };
    out[IPV4_HEADER_LEN + 6..IPV4_HEADER_LEN + 8].copy_from_slice(&checksum.to_be_bytes());
    out
}

/// A UDP datagram taken out of an IPv4 packet.
#[derive(Debug, PartialEq, Eq)]
pub struct Udp<'a> {
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub source_port: u16,
    pub destination_port: u16,
    pub payload: &'a [u8],
}

/// Parses an IPv4 packet as the packet socket delivers it (from the IP
/// header on). `None` for anything that is not a whole, unfragmented UDP
/// datagram with a good IP header checksum.
///
/// `verify_udp_checksum` is false when the kernel says the checksum has
/// not been computed yet (`TP_STATUS_CSUMNOTREADY`): a datagram from a
/// sender on this host, or across a veth pair, is handed over with the
/// checksum still to be filled in by a NIC that will never see it.
pub fn parse_udp(packet: &[u8], verify_udp_checksum: bool) -> Option<Udp<'_>> {
    let first = *packet.first()?;
    let header_len = usize::from(first & 0x0f) * 4;
    if first >> 4 != 4 || header_len < IPV4_HEADER_LEN || packet.len() < header_len {
        return None;
    }
    let header = &packet[..header_len];
    if fold(ones_complement_sum(0, header)) != 0 {
        return None;
    }
    let total_len = usize::from(u16::from_be_bytes([header[2], header[3]]));
    // More-fragments set, or a fragment offset: not a whole datagram.
    if u16::from_be_bytes([header[6], header[7]]) & 0x3fff != 0 || header[9] != IPPROTO_UDP {
        return None;
    }
    let udp = packet.get(header_len..total_len)?;
    if udp.len() < UDP_HEADER_LEN {
        return None;
    }
    let udp_len = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
    let udp = udp.get(..udp_len).filter(|u| u.len() >= UDP_HEADER_LEN)?;
    let source = Ipv4Addr::new(header[12], header[13], header[14], header[15]);
    let destination = Ipv4Addr::new(header[16], header[17], header[18], header[19]);
    let has_checksum = udp[6] != 0 || udp[7] != 0;
    if verify_udp_checksum && has_checksum && udp_checksum(source, destination, udp) != 0 {
        return None;
    }
    Some(Udp {
        source,
        destination,
        source_port: u16::from_be_bytes([udp[0], udp[1]]),
        destination_port: u16::from_be_bytes([udp[2], udp[3]]),
        payload: &udp[UDP_HEADER_LEN..],
    })
}

/// An Ethernet/IPv4 ARP packet (RFC 826), without the Ethernet header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Arp {
    pub operation: u16,
    pub sender_mac: [u8; 6],
    pub sender_ip: Ipv4Addr,
    pub target_mac: [u8; 6],
    pub target_ip: Ipv4Addr,
}

pub const ARP_REQUEST: u16 = 1;
pub const ARP_LEN: usize = 28;

impl Arp {
    /// An ARP probe (RFC 5227 §1.1): a request for `target` from the
    /// all-zero sender address, so nobody's cache learns anything.
    pub fn probe(mac: [u8; 6], target: Ipv4Addr) -> Arp {
        Arp {
            operation: ARP_REQUEST,
            sender_mac: mac,
            sender_ip: Ipv4Addr::UNSPECIFIED,
            target_mac: [0; 6],
            target_ip: target,
        }
    }

    pub fn emit(&self) -> [u8; ARP_LEN] {
        let mut out = [0; ARP_LEN];
        // Hardware type Ethernet, protocol IPv4, lengths 6 and 4.
        out[..6].copy_from_slice(&[0, 1, 8, 0, 6, 4]);
        out[6..8].copy_from_slice(&self.operation.to_be_bytes());
        out[8..14].copy_from_slice(&self.sender_mac);
        out[14..18].copy_from_slice(&self.sender_ip.octets());
        out[18..24].copy_from_slice(&self.target_mac);
        out[24..28].copy_from_slice(&self.target_ip.octets());
        out
    }

    pub fn parse(packet: &[u8]) -> Option<Arp> {
        let packet = packet.get(..ARP_LEN)?;
        if packet[..6] != [0, 1, 8, 0, 6, 4] {
            return None;
        }
        let mac = |at: usize| {
            let mut mac = [0; 6];
            mac.copy_from_slice(&packet[at..at + 6]);
            mac
        };
        let ip =
            |at: usize| Ipv4Addr::new(packet[at], packet[at + 1], packet[at + 2], packet[at + 3]);
        Some(Arp {
            operation: u16::from_be_bytes([packet[6], packet[7]]),
            sender_mac: mac(8),
            sender_ip: ip(14),
            target_mac: mac(18),
            target_ip: ip(24),
        })
    }

    /// Whether this packet shows `address` in use by a host other than
    /// `mac` (RFC 5227 §2.1.1): someone answering for it, or someone else
    /// probing for it at the same time.
    pub fn conflicts_with(&self, address: Ipv4Addr, mac: [u8; 6]) -> bool {
        if self.sender_mac == mac {
            return false;
        }
        self.sender_ip == address || (self.sender_ip.is_unspecified() && self.target_ip == address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_round_trip() {
        let source = Ipv4Addr::UNSPECIFIED;
        let destination = Ipv4Addr::BROADCAST;
        for payload in [&b"x"[..], b"odd length payload!", &[0u8; 300]] {
            let wire = udp_datagram(source, destination, 68, 67, payload);
            assert_eq!(wire.len(), 28 + payload.len());
            assert_eq!(
                parse_udp(&wire, true),
                Some(Udp {
                    source,
                    destination,
                    source_port: 68,
                    destination_port: 67,
                    payload,
                })
            );
            // Trailing bytes (Ethernet padding) are not part of it.
            let mut padded = wire.clone();
            padded.extend_from_slice(&[0; 18]);
            assert_eq!(parse_udp(&padded, true).unwrap().payload, payload);
        }
    }

    /// The header of a DHCPDISCOVER as tcpdump shows it, to pin the
    /// checksum arithmetic against known values.
    #[test]
    fn known_ip_header_checksum() {
        let wire = udp_datagram(
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
            68,
            67,
            &[0; 300],
        );
        // 4510 0148 0000 4000 4011 ____ 0000 0000 ffff ffff
        assert_eq!(
            &wire[..10],
            [0x45, 0x10, 0x01, 0x48, 0, 0, 0x40, 0, 0x40, 0x11]
        );
        assert_eq!(&wire[10..12], [0x39, 0x96]);
    }

    #[test]
    fn refuses_what_is_not_a_whole_udp_datagram() {
        let wire = udp_datagram(
            Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::BROADCAST,
            67,
            68,
            b"dhcp",
        );
        assert!(parse_udp(&wire, true).is_some());

        let corrupt = |at: usize| {
            let mut bad = wire.clone();
            bad[at] ^= 0x40;
            bad
        };
        // IP header checksum, then the payload under the UDP checksum.
        assert_eq!(parse_udp(&corrupt(8), true), None);
        assert_eq!(parse_udp(&corrupt(30), true), None);
        // The same payload passes when the kernel has not filled the UDP
        // checksum in yet.
        assert!(parse_udp(&corrupt(30), false).is_some());

        // Truncated, not IPv4, a fragment, not UDP.
        assert_eq!(parse_udp(&wire[..wire.len() - 1], true), None);
        assert_eq!(parse_udp(&[], true), None);
        let mut v6 = wire.clone();
        v6[0] = 0x65;
        assert_eq!(parse_udp(&v6, true), None);
        let refit = |mut bad: Vec<u8>| {
            bad[10..12].copy_from_slice(&[0, 0]);
            let sum = fold(ones_complement_sum(0, &bad[..20]));
            bad[10..12].copy_from_slice(&sum.to_be_bytes());
            bad
        };
        let mut fragment = wire.clone();
        fragment[6] = 0x20;
        assert_eq!(parse_udp(&refit(fragment), true), None);
        let mut tcp = wire.clone();
        tcp[9] = 6;
        assert_eq!(parse_udp(&refit(tcp), true), None);
    }

    #[test]
    fn arp_probe_and_conflicts() {
        let mac = [2, 0, 0, 0, 0, 1];
        let other = [2, 0, 0, 0, 0, 2];
        let address = Ipv4Addr::new(192, 0, 2, 100);
        let probe = Arp::probe(mac, address);
        let wire = probe.emit();
        assert_eq!(
            wire,
            [
                0, 1, 8, 0, 6, 4, 0, 1, 2, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 0, 2,
                100
            ]
        );
        assert_eq!(Arp::parse(&wire), Some(probe));
        assert_eq!(Arp::parse(&wire[..27]), None);

        // Our own probe coming back is not a conflict.
        assert!(!probe.conflicts_with(address, mac));
        // Another host answering for the address, or probing for it too.
        let reply = Arp {
            operation: 2,
            sender_mac: other,
            sender_ip: address,
            target_mac: mac,
            target_ip: Ipv4Addr::UNSPECIFIED,
        };
        assert!(reply.conflicts_with(address, mac));
        assert!(Arp::probe(other, address).conflicts_with(address, mac));
        // Traffic about other addresses.
        assert!(!Arp::probe(other, Ipv4Addr::new(192, 0, 2, 101)).conflicts_with(address, mac));
    }
}
