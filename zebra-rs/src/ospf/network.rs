use std::io::{ErrorKind, IoSlice, IoSliceMut};
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::BytesMut;
use nix::sys::socket::{self, ControlMessageOwned, SockaddrIn};
use socket2::Socket;
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use crate::ospf::Message;

/// Size of the receive buffer of both readers, OSPFv2 and OSPFv3.
///
/// An IPv4 datagram is at most 65,535 bytes with its header, and so is an
/// OSPFv3 packet short of an IPv6 jumbogram, so nothing a neighbor can send
/// is cut short. The size matters because a neighbor may put a whole
/// database summary, a whole request list or every LSA requested into one
/// packet, which then arrives as one reassembled datagram. The buffer was
/// 16 KB, and a longer packet was dropped without a word: two routers
/// stopped synchronizing at 454 AS-external LSAs.
pub(super) const RECV_BUF_LEN: usize = 65536;

/// Shortest time between two log lines of one kind from one reader or
/// writer task.
pub(super) const LOG_INTERVAL: Duration = Duration::from_secs(10);

/// Rate limit for a log line that a neighbor, or a failure that persists,
/// can raise once per packet: one line per interval, carrying the number of
/// events that were not logged in between.
pub(super) struct LogLimit {
    interval: Duration,
    last: Option<Instant>,
    held: u64,
}

impl LogLimit {
    pub(super) fn new(interval: Duration) -> Self {
        Self {
            interval,
            last: None,
            held: 0,
        }
    }

    /// `Some(n)` when the event should be logged now, `n` being the number
    /// of events held back since the last line; `None` to hold this one
    /// back too.
    pub(super) fn pass(&mut self) -> Option<u64> {
        self.pass_at(Instant::now())
    }

    fn pass_at(&mut self, now: Instant) -> Option<u64> {
        if self
            .last
            .is_some_and(|last| now.duration_since(last) < self.interval)
        {
            self.held += 1;
            return None;
        }
        self.last = Some(now);
        Some(std::mem::take(&mut self.held))
    }
}

/// An interface's name for a log line, or its index when it has none
/// (the interface is gone).
pub(super) fn ifname(ifindex: u32) -> String {
    nix::net::if_::if_indextoname(ifindex)
        .ok()
        .and_then(|name| name.into_string().ok())
        .unwrap_or_else(|| format!("ifindex {ifindex}"))
}

pub async fn read_packet(sock: Arc<AsyncFd<Socket>>, tx: UnboundedSender<Message>) {
    read_packet_into(sock, tx, RECV_BUF_LEN).await
}

/// [`read_packet`] with the buffer size given, so that a test can receive a
/// datagram longer than the buffer.
async fn read_packet_into(
    sock: Arc<AsyncFd<Socket>>,
    tx: UnboundedSender<Message>,
    buf_len: usize,
) {
    const IPV4_HEADER_LEN: usize = 20;

    // On the heap: the task's future would otherwise carry the 64 KB.
    let mut buf = vec![0u8; buf_len];
    let mut iov = [IoSliceMut::new(&mut buf)];
    let mut cmsgspace = nix::cmsg_space!(libc::in_pktinfo);
    let mut truncated = LogLimit::new(LOG_INTERVAL);

    loop {
        let _ = sock
            .async_io(Interest::READABLE, |sock| {
                let msg = socket::recvmsg::<SockaddrIn>(
                    sock.as_raw_fd(),
                    &mut iov,
                    Some(&mut cmsgspace),
                    socket::MsgFlags::empty(),
                )?;

                let mut cmsgs = msg.cmsgs()?;

                let Some(src) = msg.address else {
                    return Err(ErrorKind::AddrNotAvailable.into());
                };

                let Some(ControlMessageOwned::Ipv4PacketInfo(pktinfo)) = cmsgs.next() else {
                    return Err(ErrorKind::AddrNotAvailable.into());
                };

                let ifaddr: Ipv4Addr = Ipv4Addr::from(pktinfo.ipi_spec_dst.s_addr.to_be());
                let group: Ipv4Addr = Ipv4Addr::from(pktinfo.ipi_addr.s_addr.to_be());
                let ifindex = pktinfo.ipi_ifindex as u32;

                let Some(input) = msg.iovs().next() else {
                    return Err(ErrorKind::UnexpectedEof.into());
                };

                // The datagram is longer than the buffer and the kernel
                // has discarded the rest. What is left would fail the
                // length check below, silently, and every retransmission
                // after it: say so.
                if msg.flags.contains(socket::MsgFlags::MSG_TRUNC) {
                    if let Some(held) = truncated.pass() {
                        tracing::warn!(
                            src = %src.ip(),
                            interface = %ifname(ifindex),
                            buffer = buf_len,
                            suppressed = held,
                            "ospf: dropped a received packet longer than the receive buffer"
                        );
                    }
                    return Err(ErrorKind::InvalidData.into());
                }

                // RFC 2328: Header verification.

                // RFC 2328: Authentication and checksum verification.
                // For Type 2 (cryptographic) packets the on-wire
                // form is (header + body) followed by a digest
                // trailer; the OSPF header `len` field excludes the
                // trailer. Slice to that length before checksumming
                // — otherwise trailer bytes would corrupt the
                // 1's-complement sum on any Type 2 ingress.
                let ospf_input = &input[IPV4_HEADER_LEN..];
                if ospf_input.len() < 4 {
                    return Err(ErrorKind::UnexpectedEof.into());
                }
                let pkt_len = u16::from_be_bytes([ospf_input[2], ospf_input[3]]) as usize;
                if pkt_len < 24 || ospf_input.len() < pkt_len {
                    return Err(ErrorKind::InvalidData.into());
                }
                // RFC 2328 §D.4.3: cryptographic authentication
                // (AuType 2) does not use the standard checksum —
                // the field is zero on the wire and integrity is
                // verified via the digest trailer in the auth gate.
                let auth_type = u16::from_be_bytes([ospf_input[14], ospf_input[15]]);
                if auth_type != 2 && ospf_packet::validate_checksum(&ospf_input[..pkt_len]).is_err()
                {
                    return Err(ErrorKind::InvalidData.into());
                }

                let Ok(packet) = ospf_packet::parse(ospf_input) else {
                    return Err(ErrorKind::UnexpectedEof.into());
                };

                // println!(
                //     "Read: type {} src {} ifaddr {} ifindex {} dest {}",
                //     packet.1.typ,
                //     src.ip(),
                //     group,
                //     ifindex,
                //     ifaddr
                // );

                // We will verify Area later.

                let _ = tx.send(Message::Recv(packet.1, src.ip(), group, ifindex, ifaddr));

                Ok(())
            })
            .await;
        // The OSPF event loop owns the receiver; once the instance
        // is torn down (e.g. `delete router ospf`) the channel
        // closes and there is no one left to deliver to.
        if tx.is_closed() {
            return;
        }
    }
}

pub async fn write_packet(sock: Arc<AsyncFd<Socket>>, mut rx: UnboundedReceiver<Message>) {
    let mut failed = LogLimit::new(LOG_INTERVAL);

    // Exits the loop when the event loop drops the sender on
    // instance teardown — mirrors `network_v6::write_packet_v6`.
    while let Some(msg) = rx.recv().await {
        let Message::Send(packet, ifindex, dest, src) = msg else {
            continue;
        };

        let mut buf = BytesMut::new();
        packet.emit(&mut buf);

        let iov = [IoSlice::new(&buf)];
        let dest = if let Some(dest) = dest {
            dest
        } else {
            Ipv4Addr::from_str("224.0.0.5").unwrap()
        };
        let sockaddr: SockaddrIn = std::net::SocketAddrV4::new(dest, 0).into();
        // Virtual-link packets carry a synthetic ifindex (no kernel
        // interface behind it). They are always unicast to the far
        // ABR through the transit area, so hand egress selection to
        // the kernel FIB (`ipi_ifindex = 0`) instead of forcing an
        // interface — this also keeps multi-hop transit paths
        // working. Physical interfaces keep the forced egress.
        let egress_ifindex = if ifindex >= super::link::VL_IFINDEX_BASE {
            0
        } else {
            ifindex as i32
        };
        // `ipi_spec_dst` pins the source address when the sender
        // provided one (multicast Hellos/Acks — see `Message::Send`);
        // 0 leaves selection to the kernel (unicast).
        let spec_dst = src.map(|s| u32::from(s).to_be()).unwrap_or(0);
        let pktinfo = libc::in_pktinfo {
            ipi_ifindex: egress_ifindex,
            ipi_spec_dst: libc::in_addr { s_addr: spec_dst },
            ipi_addr: libc::in_addr { s_addr: 0 },
        };
        let cmsg = [socket::ControlMessage::Ipv4PacketInfo(&pktinfo)];

        let sent = sock
            .async_io(Interest::WRITABLE, |sock| {
                socket::sendmsg(
                    sock.as_raw_fd(),
                    &iov,
                    &cmsg,
                    socket::MsgFlags::empty(),
                    Some(&sockaddr),
                )
                .map_err(std::io::Error::from)?;
                Ok(())
            })
            .await;
        // The packet is lost and nothing above this task learns of it. A
        // packet of more than 65,535 bytes fails here with EMSGSIZE on
        // every retransmission.
        if let Err(err) = sent
            && let Some(held) = failed.pass()
        {
            // A virtual link's index names no interface (see above).
            let interface = if egress_ifindex == 0 {
                "virtual link".to_string()
            } else {
                ifname(ifindex)
            };
            tracing::warn!(
                dest = %dest,
                interface = %interface,
                packet = %packet.typ,
                bytes = buf.len(),
                error = %err,
                suppressed = held,
                "ospf: failed to send a packet"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddrV4;

    use ospf_packet::{OspfLsRequest, OspfLsRequestEntry, OspfLsType, Ospfv2Packet, Ospfv2Payload};
    use socket2::{Domain, Type};
    use tokio::sync::mpsc;

    use super::*;

    /// A UDP socket on loopback in place of the raw socket. It needs no
    /// privilege and carries `IP_PKTINFO` like the raw one. The reader
    /// skips the IPv4 header a raw socket delivers without looking into
    /// it, so [`send`] puts 20 bytes in front of each packet.
    fn udp() -> Arc<AsyncFd<Socket>> {
        let sock = Socket::new(Domain::IPV4, Type::DGRAM, None).unwrap();
        sock.set_nonblocking(true).unwrap();
        sock.bind(&SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0).into())
            .unwrap();
        crate::ospf::socket::set_ipv4_pktinfo(&sock);
        Arc::new(crate::async_fd::register(sock).unwrap())
    }

    /// An LS Request with `entries` entries: 24 + 12 × `entries` bytes.
    fn ls_request(entries: u32) -> Ospfv2Packet {
        let reqs = (0..entries)
            .map(|n| {
                OspfLsRequestEntry::new(
                    OspfLsType::AsExternal,
                    Ipv4Addr::from(0xac14_0000 + n),
                    Ipv4Addr::new(10, 0, 0, 2),
                )
            })
            .collect();
        Ospfv2Packet::new(
            &Ipv4Addr::new(10, 0, 0, 2),
            &Ipv4Addr::UNSPECIFIED,
            Ospfv2Payload::LsRequest(OspfLsRequest { reqs }),
        )
    }

    fn send(from: &AsyncFd<Socket>, to: &AsyncFd<Socket>, packet: &Ospfv2Packet) {
        let mut ospf = BytesMut::new();
        packet.emit(&mut ospf);
        let mut buf = vec![0u8; 20];
        buf.extend_from_slice(&ospf);
        let to = to.get_ref().local_addr().unwrap();
        assert_eq!(from.get_ref().send_to(&buf, &to).unwrap(), buf.len());
    }

    /// The number of entries of the next LS Request the reader delivers.
    async fn received(rx: &mut mpsc::UnboundedReceiver<Message>) -> usize {
        let msg = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("the reader delivers the packet")
            .unwrap();
        let Message::Recv(packet, ..) = msg else {
            panic!("not a received packet");
        };
        let Ospfv2Payload::LsRequest(req) = packet.payload else {
            panic!("not an LS Request");
        };
        req.reqs.len()
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn log_limit_passes_one_line_per_interval_and_counts_the_rest() {
        let start = Instant::now();
        let at = |secs| start + Duration::from_secs(secs);
        let mut limit = LogLimit::new(Duration::from_secs(10));

        assert_eq!(limit.pass_at(at(0)), Some(0));
        assert_eq!(limit.pass_at(at(1)), None);
        assert_eq!(limit.pass_at(at(9)), None);
        assert_eq!(limit.pass_at(at(10)), Some(2));
        assert_eq!(limit.pass_at(at(19)), None);
        assert_eq!(limit.pass_at(at(30)), Some(1));
        assert_eq!(limit.pass_at(at(40)), Some(0));
    }

    /// 60,024 bytes of OSPF, as a neighbor that does not size its packets
    /// to the MTU sends for a request list of 5,000 LSAs. The 16 KB buffer
    /// dropped it.
    #[tokio::test]
    async fn reader_accepts_a_60_kb_packet() {
        let (ours, theirs) = (udp(), udp());
        let (tx, mut rx) = mpsc::unbounded_channel();
        let reader = tokio::spawn(read_packet(ours.clone(), tx));

        send(&theirs, &ours, &ls_request(5000));

        assert_eq!(received(&mut rx).await, 5000);
        reader.abort();
    }

    /// With a buffer shorter than the datagram: one warning for the two
    /// packets dropped, and the packet after them is read.
    #[test]
    fn reader_reports_a_packet_longer_than_its_buffer() {
        let logged = crate::test_log::warnings(|| {
            runtime().block_on(async {
                let (ours, theirs) = (udp(), udp());
                let (tx, mut rx) = mpsc::unbounded_channel();
                let reader = tokio::spawn(read_packet_into(ours.clone(), tx, 1024));

                send(&theirs, &ours, &ls_request(200));
                send(&theirs, &ours, &ls_request(201));
                send(&theirs, &ours, &ls_request(3));

                assert_eq!(received(&mut rx).await, 3);
                reader.abort();
            })
        });

        assert_eq!(logged.lines().count(), 1, "{logged}");
        assert!(
            logged.contains("dropped a received packet longer than the receive buffer")
                && logged.contains("src=127.0.0.1")
                && logged.contains("interface=lo")
                && logged.contains("buffer=1024"),
            "{logged}"
        );
    }

    /// A send that fails is reported, once per interval, and the writer
    /// goes on to the next packet. The failure here is the UDP socket's:
    /// it refuses the port 0 the writer addresses a raw socket with.
    #[test]
    fn writer_reports_a_send_that_fails() {
        let logged = crate::test_log::warnings(|| {
            runtime().block_on(async {
                let (ptx, prx) = mpsc::unbounded_channel();
                let writer = tokio::spawn(write_packet(udp(), prx));

                let lo = nix::net::if_::if_nametoindex("lo").unwrap();
                for _ in 0..2 {
                    let dest = Some(Ipv4Addr::LOCALHOST);
                    ptx.send(Message::Send(ls_request(3), lo, dest, None))
                        .unwrap();
                }
                drop(ptx);

                tokio::time::timeout(Duration::from_secs(5), writer)
                    .await
                    .expect("the writer drains its queue and ends")
                    .unwrap();
            })
        });

        assert_eq!(logged.lines().count(), 1, "{logged}");
        assert!(
            logged.contains("failed to send a packet")
                && logged.contains("dest=127.0.0.1")
                && logged.contains("interface=lo")
                && logged.contains("bytes=60")
                && logged.contains("error="),
            "{logged}"
        );
    }
}
