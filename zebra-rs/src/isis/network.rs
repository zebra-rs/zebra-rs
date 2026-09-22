use std::io::{ErrorKind, IoSlice, IoSliceMut};
use std::os::fd::AsRawFd;
use std::sync::Arc;

use bytes::BytesMut;
use nix::sys::socket::{self, LinkAddr};
use socket2::Socket;
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use crate::isis_info;
use crate::rib::MacAddr;

use super::lsp::{Packet, PacketMessage};
use super::socket::link_addr;
use super::{Level, Message};

fn hexdump(data: &[u8]) {
    for (i, chunk) in data.chunks(16).enumerate() {
        // offset
        print!("{:08X}: ", i * 16);

        // hex bytes
        for byte in chunk {
            print!("{:02X} ", byte);
        }
        // pad last line if short
        for _ in 0..(16 - chunk.len()) {
            print!("   ");
        }

        // ASCII representation
        let ascii: String = chunk
            .iter()
            .map(|b| {
                if b.is_ascii_graphic() {
                    *b as char
                } else {
                    '.'
                }
            })
            .collect();
        println!("|{ascii}|");
    }
}

pub async fn read_packet(sock: Arc<AsyncFd<Socket>>, tx: UnboundedSender<Message>) {
    let mut buf = [0u8; 1024 * 16];
    let mut iov = [IoSliceMut::new(&mut buf)];

    loop {
        let _ = sock
            .async_io(Interest::READABLE, |sock| {
                let msg = socket::recvmsg::<LinkAddr>(
                    sock.as_raw_fd(),
                    &mut iov,
                    None,
                    socket::MsgFlags::empty(),
                )?;

                let Some(addr) = msg.address else {
                    return Err(ErrorKind::UnexpectedEof.into());
                };

                let Some(input) = msg.iovs().next() else {
                    return Err(ErrorKind::UnexpectedEof.into());
                };
                let Ok(mut packet) = isis_packet::parse(&input[3..]) else {
                    isis_info!(
                        "Error Packet parse on {} len {}",
                        addr.ifindex(),
                        input.len(),
                    );
                    hexdump(&input[3..]);
                    return Err(ErrorKind::UnexpectedEof.into());
                };

                if packet.1.pdu_type.is_lsp() && !isis_packet::is_valid_checksum(&input[3..]) {
                    return Err(ErrorKind::UnexpectedEof.into());
                }
                // Always preserve the raw PDU bytes — the auth-verify
                // path reads them to recompute HMAC against the exact
                // byte sequence the peer signed, and the existing LSP
                // install path needs them too.
                packet.1.bytes = input[3..].to_vec();

                let mac = addr.addr().map(MacAddr::from);

                let _ = tx.send(Message::Recv(packet.1, addr.ifindex() as u32, mac));
                Ok(())
            })
            .await;
    }
}

pub const LLC_HDR: [u8; 3] = [0xFE, 0xFE, 0x03];
pub const L1_ISS: [u8; 6] = [0x01, 0x80, 0xC2, 0x00, 0x00, 0x14];
pub const L2_ISS: [u8; 6] = [0x01, 0x80, 0xC2, 0x00, 0x00, 0x15];
pub const P2P_ISS: [u8; 6] = [0x09, 0x00, 0x2B, 0x00, 0x00, 0x05];

/// Largest value the IEEE 802.3 length/type field can carry as a
/// *length*. A receiver reads anything above this as an EtherType, so a
/// longer LLC frame cannot state its length there at all.
const ETHER_MAX_LEN: usize = 1500;

/// The "jumbo LLC" EtherType: an 802.2 LLC frame whose payload is too
/// long for the 802.3 length field. Introduced for exactly this case —
/// IS-IS Hellos padded to an MTU above 1500 and extended-size LSPs — and
/// retroactively standardised by IEEE 802.1AC-2016/Cor 1-2018.
pub const ETH_P_JUMBO_LLC: u16 = 0x8870;

/// The Ethernet length/type field for an LLC frame whose payload (LLC
/// header + IS-IS PDU) is `payload_len` bytes.
///
/// Up to 1500 bytes this is the payload length, the plain 802.3 form
/// every IS-IS implementation emits for unpadded PDUs. Above 1500 the
/// length no longer fits the field — a receiver classifies any value
/// from 1536 up as an EtherType — so the frame must be marked with the
/// jumbo LLC EtherType instead and its real length taken from the PDU
/// length field.
///
/// Sending the raw length regardless (what zebra-rs did before, and what
/// FRR still does) produces frames stamped with a nonsense EtherType
/// such as 0x0FEE. Linux delivers them anyway — `AF_PACKET` plus a BPF
/// filter that matches the LLC bytes never looks at the field — so
/// zebra-rs↔zebra-rs and zebra-rs↔FRR adjacencies came up on jumbo
/// links and hid the bug. Peers that classify ingress frames by
/// EtherType (Cisco, Juniper, and other ASIC-style pipelines) drop them,
/// which shows up as an adjacency stuck in Init/Down on a jumbo-MTU
/// link while ordinary traffic and small PDUs pass.
fn llc_length_type(payload_len: usize) -> u16 {
    if payload_len > ETHER_MAX_LEN {
        ETH_P_JUMBO_LLC
    } else {
        payload_len as u16
    }
}

pub async fn write_packet(sock: Arc<AsyncFd<Socket>>, mut rx: UnboundedReceiver<PacketMessage>) {
    // Exits the loop when the event loop drops the sender on
    // instance teardown — same pattern as `ospf::network` and
    // `ospf::network_v6`.
    while let Some(PacketMessage::Send(packet, ifindex, level, dest)) = rx.recv().await {
        let buf = match packet {
            Packet::Packet(packet) => {
                let mut buf = BytesMut::new();
                packet.emit(&mut buf);
                buf
            }
            Packet::Bytes(buf) => buf,
        };

        let iov = [IoSlice::new(&LLC_HDR), IoSlice::new(&buf)];

        let iss = if let Some(dest) = dest {
            dest.octets()
        } else if level == Level::L1 {
            L1_ISS
        } else {
            L2_ISS
        };

        let payload_len = LLC_HDR.len() + buf.len();
        let sockaddr = link_addr(llc_length_type(payload_len), ifindex, Some(iss));

        let _res = sock
            .async_io(Interest::WRITABLE, |sock| {
                socket::sendmsg(
                    sock.as_raw_fd(),
                    &iov,
                    &[],
                    socket::MsgFlags::empty(),
                    Some(&sockaddr),
                )
                .map_err(|e| std::io::Error::from_raw_os_error(e as i32))
            })
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Frames up to the 802.3 maximum state their own payload length —
    /// the unpadded PDUs and every Hello on a standard 1500-byte link.
    #[test]
    fn plain_frames_carry_the_802_3_length() {
        // A bare P2P Hello, and the 1500-byte boundary itself.
        assert_eq!(llc_length_type(53), 53);
        assert_eq!(llc_length_type(1497), 1497);
        assert_eq!(llc_length_type(ETHER_MAX_LEN), 1500);
    }

    /// One byte past the boundary the length stops fitting, so the frame
    /// is stamped with the jumbo LLC EtherType instead. These are the
    /// payloads that occur in practice: 1600 is the BDD feature's MTU,
    /// 4096 a jumbo MTU, 4078 the payload of `padding-size 4092` against
    /// a media-MTU-4096 peer. All three used to leave as bogus
    /// EtherTypes (0x0640, 0x1000, 0x0FEE) that EtherType-classifying
    /// peers drop.
    #[test]
    fn jumbo_frames_carry_the_jumbo_llc_ethertype() {
        for payload_len in [ETHER_MAX_LEN + 1, 1600, 4078, 4096, 9000] {
            assert_eq!(
                llc_length_type(payload_len),
                ETH_P_JUMBO_LLC,
                "payload {} must use the jumbo LLC EtherType",
                payload_len
            );
        }
    }

    /// Pin the wire value: 0x8870 is what IEEE 802.1AC standardised and
    /// what peers match on. A typo here is invisible in tests that only
    /// compare against the constant.
    #[test]
    fn jumbo_llc_ethertype_value_is_pinned() {
        assert_eq!(ETH_P_JUMBO_LLC, 0x8870);
        // And it is itself above the 802.3 length range, so no plain
        // frame can ever collide with it.
        assert!(ETH_P_JUMBO_LLC as usize > ETHER_MAX_LEN);
    }
}
