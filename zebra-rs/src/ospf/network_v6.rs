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
    let mut buf = [0u8; 1024 * 16];
    let mut iov = [IoSliceMut::new(&mut buf)];
    let mut cmsgspace = nix::cmsg_space!(libc::in6_pktinfo);

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

                // RFC 5340 §4.4: drop packets whose pseudo-header
                // checksum is wrong before any further processing.
                if !ospfv3_verify_checksum(&src, &dst, input) {
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

        let _ = sock
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
    }
}
