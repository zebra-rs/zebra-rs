//! OSPFv3 raw-IPv6 read/write loop.
//!
//! Mirrors `network.rs` for v4. Two long-lived tasks drive the v6
//! socket: `read_packet_v6` receives raw IPv6 packets, verifies the
//! pseudo-header checksum, parses an `Ospfv3Packet`, and forwards
//! the result over an mpsc channel; `write_packet_v6` takes
//! `Ospfv3Send` items from a peer channel, stamps the checksum with
//! the supplied source/destination, and emits via `sendmsg` with an
//! `in6_pktinfo` ancillary message so the kernel uses the egress
//! interface we picked instead of doing a fresh route lookup.
//!
//! Spawned by `Ospf<Ospfv3>::new` (see `ospf::inst`). The channels
//! they drive are stored on the v3 instance as `v3_send_tx` /
//! `v3_recv_rx`; consumers / producers wire up as the v3 FSM lands.

use std::io::{ErrorKind, IoSlice, IoSliceMut};
use std::net::Ipv6Addr;
use std::os::fd::AsRawFd;
use std::sync::Arc;

use bytes::BytesMut;
use nix::sys::socket::{self, ControlMessageOwned, SockaddrIn6};
use socket2::Socket;
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use super::network::{LOG_INTERVAL, LogLimit, RECV_BUF_LEN, ifname};
use super::{OspfVersion, Ospfv3};
use ospf_packet::{Ospfv3Packet, ospfv3_verify_checksum, parse_v3};

/// One v3 packet pending transmission.
///
/// `dest` defaults to `ff02::5` (AllSPFRouters) when `None` —
/// matches the v2 loop's convention for "send to the multicast
/// group of the link". `src` is the egress interface's link-local
/// address; the IPv6 pseudo-header checksum (RFC 5340 §4.4) folds
/// it in, so the receiver's verify will fail if this doesn't
/// match what the kernel ends up putting in the IPv6 header.
#[derive(Debug)]
pub struct Ospfv3Send {
    pub packet: Ospfv3Packet,
    pub ifindex: u32,
    pub dest: Option<Ipv6Addr>,
    pub src: Ipv6Addr,
}

/// One v3 packet just received off the wire.
///
/// Carries the parsed packet plus the transport-layer metadata the
/// upper-layer protocol code needs to dispatch it: source v6 from
/// the recvmsg sockaddr and the ingress ifindex from the
/// `in6_pktinfo` ancillary message. The destination address is
/// consumed only by the pseudo-header checksum verification here
/// in [`read_packet_v6`] and is not forwarded up.
#[derive(Debug)]
pub struct Ospfv3Recv {
    pub packet: Ospfv3Packet,
    pub src: Ipv6Addr,
    pub ifindex: u32,
}

/// Long-lived recv loop for the v3 socket. Drops packets whose
/// pseudo-header checksum fails verification or whose body fails
/// to parse; the upper layer never sees malformed traffic.
///
/// IPv6 raw sockets (unlike v4) deliver the OSPF payload directly
/// — the kernel strips the IPv6 header on receive — so there's no
/// `IPV4_HEADER_LEN` skip to mirror.
pub async fn read_packet_v6(sock: Arc<AsyncFd<Socket>>, tx: UnboundedSender<Ospfv3Recv>) {
    read_packet_v6_into(sock, tx, RECV_BUF_LEN).await
}

/// [`read_packet_v6`] with the buffer size given, so that a test can
/// receive a datagram longer than the buffer.
async fn read_packet_v6_into(
    sock: Arc<AsyncFd<Socket>>,
    tx: UnboundedSender<Ospfv3Recv>,
    buf_len: usize,
) {
    // On the heap: the task's future would otherwise carry the 64 KB.
    let mut buf = vec![0u8; buf_len];
    let mut iov = [IoSliceMut::new(&mut buf)];
    let mut cmsgspace = nix::cmsg_space!(libc::in6_pktinfo);
    let mut truncated = LogLimit::new(LOG_INTERVAL);

    loop {
        let _ = sock
            .async_io(Interest::READABLE, |sock| {
                let msg = socket::recvmsg::<SockaddrIn6>(
                    sock.as_raw_fd(),
                    &mut iov,
                    Some(&mut cmsgspace),
                    socket::MsgFlags::empty(),
                )?;

                let mut cmsgs = msg.cmsgs()?;

                let Some(src_sa) = msg.address else {
                    return Err(ErrorKind::AddrNotAvailable.into());
                };
                let src: Ipv6Addr = src_sa.ip();

                let Some(ControlMessageOwned::Ipv6PacketInfo(pktinfo)) = cmsgs.next() else {
                    return Err(ErrorKind::AddrNotAvailable.into());
                };
                // On receive, `ipi6_addr` carries the destination
                // address (the multicast group or the unicast
                // address) of the packet. The kernel populates it
                // from the IPV6_RECVPKTINFO socket option we set in
                // `socket::ospf_socket_ipv6`.
                let dst: Ipv6Addr = Ipv6Addr::from(pktinfo.ipi6_addr.s6_addr);
                let ifindex = pktinfo.ipi6_ifindex;

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
                            src = %src,
                            interface = %ifname(ifindex),
                            buffer = buf_len,
                            suppressed = held,
                            "ospfv3: dropped a received packet longer than the receive buffer"
                        );
                    }
                    return Err(ErrorKind::InvalidData.into());
                }

                if input.len() < 16 {
                    return Err(ErrorKind::UnexpectedEof.into());
                }
                let pkt_len = u16::from_be_bytes([input[2], input[3]]) as usize;
                if pkt_len < 16 || input.len() < pkt_len {
                    return Err(ErrorKind::InvalidData.into());
                }
                // RFC 5340 §4.4: drop packets whose pseudo-header checksum is
                // wrong before any further processing. RFC 7166 §2.3: both the
                // OSPFv3 header length field and the checksum cover only the OSPF
                // packet, NOT a trailing Authentication Trailer — so verify over
                // `input[..pkt_len]`. (The earlier code verified the full
                // datagram, which corrupted the sum on every AT ingress.)
                //
                // This runs unconditionally. Skipping it whenever trailing bytes
                // are present let an attacker disable the only integrity check on
                // an unauthenticated interface by appending a byte; on an
                // authenticated interface the packet checksum is still valid over
                // input[..pkt_len] and the AT digest is verified downstream in the
                // auth gate.
                if !ospfv3_verify_checksum(&src, &dst, &input[..pkt_len]) {
                    return Err(ErrorKind::InvalidData.into());
                }

                let Ok((_, packet)) = parse_v3(input) else {
                    return Err(ErrorKind::UnexpectedEof.into());
                };

                let _ = tx.send(Ospfv3Recv {
                    packet,
                    src,
                    ifindex,
                });

                Ok(())
            })
            .await;
    }
}

/// Long-lived send loop for the v3 socket. Consumes `Ospfv3Send`
/// items from `rx` and pushes them onto the wire with the IPv6
/// pseudo-header checksum stamped in.
pub async fn write_packet_v6(sock: Arc<AsyncFd<Socket>>, mut rx: UnboundedReceiver<Ospfv3Send>) {
    let mut failed = LogLimit::new(LOG_INTERVAL);

    while let Some(item) = rx.recv().await {
        let Ospfv3Send {
            packet,
            ifindex,
            dest,
            src,
        } = item;
        let dest = dest.unwrap_or(Ospfv3::ALL_SPF_ROUTERS);

        let mut buf = BytesMut::new();
        // emit_with_checksum lays the packet down with checksum=0
        // and then stamps the pseudo-header checksum at octets
        // 12..14, folding in (src, dst).
        packet.emit_with_checksum(&mut buf, &src, &dest);

        // RFC 7166: when the upper-layer builder pre-computed an
        // Authentication Trailer (see `apply_v3_auth_trailer`),
        // append it after the body. The trailer is excluded from
        // both the OSPF `len` field and the pseudo-header
        // checksum, so it's a pure tail append here.
        if !packet.auth_trailer.is_empty() {
            buf.extend_from_slice(&packet.auth_trailer);
        }

        let iov = [IoSlice::new(&buf)];
        let sockaddr: SockaddrIn6 = std::net::SocketAddrV6::new(dest, 0, 0, 0).into();
        // On send, `ipi6_addr` carries the *source* address (the
        // opposite of recv). Setting it pins the IPv6 source the
        // kernel emits; otherwise the kernel would pick its own
        // based on the destination route, and our pseudo-header
        // checksum wouldn't match.
        let mut src_addr = libc::in6_addr { s6_addr: [0u8; 16] };
        src_addr.s6_addr = src.octets();
        let pktinfo = libc::in6_pktinfo {
            ipi6_addr: src_addr,
            ipi6_ifindex: ifindex,
        };
        let cmsg = [socket::ControlMessage::Ipv6PacketInfo(&pktinfo)];

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
            tracing::warn!(
                dest = %dest,
                interface = %ifname(ifindex),
                packet = %packet.typ,
                bytes = buf.len(),
                error = %err,
                suppressed = held,
                "ospfv3: failed to send a packet"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddrV6};
    use std::time::Duration;

    use ospf_packet::{Ospfv3LsRequest, Ospfv3LsRequestEntry, Ospfv3Payload};
    use socket2::{Domain, Type};
    use tokio::sync::mpsc;

    use super::*;

    /// A UDP socket on loopback in place of the raw socket. It needs no
    /// privilege, carries `IPV6_PKTINFO` like the raw one and, like it,
    /// delivers the packet with no IPv6 header in front.
    fn udp() -> Arc<AsyncFd<Socket>> {
        let sock = Socket::new(Domain::IPV6, Type::DGRAM, None).unwrap();
        sock.set_nonblocking(true).unwrap();
        sock.bind(&SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0).into())
            .unwrap();
        crate::ospf::socket::set_ipv6_pktinfo(&sock);
        Arc::new(crate::async_fd::register(sock).unwrap())
    }

    /// An LS Request with `entries` entries: 16 + 12 × `entries` bytes.
    fn ls_request(entries: u32) -> Ospfv3Packet {
        let reqs = (0..entries)
            .map(|n| Ospfv3LsRequestEntry::new(0x4005, n, Ipv4Addr::new(10, 0, 0, 2)))
            .collect();
        Ospfv3Packet::new(
            &Ipv4Addr::new(10, 0, 0, 2),
            &Ipv4Addr::UNSPECIFIED,
            0,
            Ospfv3Payload::LsRequest(Ospfv3LsRequest { reqs }),
        )
    }

    fn send(from: &AsyncFd<Socket>, to: &AsyncFd<Socket>, packet: &Ospfv3Packet) {
        let mut buf = BytesMut::new();
        packet.emit_with_checksum(&mut buf, &Ipv6Addr::LOCALHOST, &Ipv6Addr::LOCALHOST);
        let to = to.get_ref().local_addr().unwrap();
        assert_eq!(from.get_ref().send_to(&buf, &to).unwrap(), buf.len());
    }

    /// The number of entries of the next LS Request the reader delivers.
    async fn received(rx: &mut mpsc::UnboundedReceiver<Ospfv3Recv>) -> usize {
        let recv = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("the reader delivers the packet")
            .unwrap();
        let Ospfv3Payload::LsRequest(req) = recv.packet.payload else {
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

    /// 60,016 bytes of OSPFv3, as a neighbor that does not size its packets
    /// to the MTU sends for a request list of 5,000 LSAs. The 16 KB buffer
    /// dropped it.
    #[tokio::test]
    async fn reader_accepts_a_60_kb_packet() {
        let (ours, theirs) = (udp(), udp());
        let (tx, mut rx) = mpsc::unbounded_channel();
        let reader = tokio::spawn(read_packet_v6(ours.clone(), tx));

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
                let reader = tokio::spawn(read_packet_v6_into(ours.clone(), tx, 1024));

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
                && logged.contains("src=::1")
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
                let writer = tokio::spawn(write_packet_v6(udp(), prx));

                let lo = nix::net::if_::if_nametoindex("lo").unwrap();
                for _ in 0..2 {
                    ptx.send(Ospfv3Send {
                        packet: ls_request(3),
                        ifindex: lo,
                        dest: Some(Ipv6Addr::LOCALHOST),
                        src: Ipv6Addr::LOCALHOST,
                    })
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
                && logged.contains("dest=::1")
                && logged.contains("interface=lo")
                && logged.contains("bytes=52")
                && logged.contains("error="),
            "{logged}"
        );
    }
}
