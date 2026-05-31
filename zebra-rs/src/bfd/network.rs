use std::io::{ErrorKind, IoSlice, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::AsRawFd;
use std::sync::Arc;

use bytes::BytesMut;
use nix::sys::socket::{self, ControlMessageOwned, SockaddrIn, SockaddrIn6};
use socket2::Socket;
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use super::inst::Message;

/// Egress request consumed by [`write_packet`] (v4) / [`write_packet_v6`]
/// (v6). The event loop pushes these whenever a
/// [`super::timer::TimerEvent::TxTick`] fires; `on_tx_tick` routes to the
/// channel matching `dst`'s address family.
#[derive(Debug)]
pub struct WriteRequest {
    pub packet: bfd_packet::ControlPacket,
    pub dst: SocketAddr,
    /// Optional egress ifindex (sent via `IP_PKTINFO` / `IPV6_PKTINFO`).
    /// `None` lets the kernel route normally.
    pub ifindex: Option<u32>,
}

/// Async receive loop. Pulls one BFD control packet at a time off
/// `sock`, runs structural validation via
/// [`bfd_packet::ControlPacket::parse`], and forwards survivors to the
/// event loop via `tx`. The received IP TTL is carried up in
/// [`Message::Recv`]; the TTL floor (GTSM=255 single-hop, configured
/// minimum multihop) is enforced after session demux in
/// [`super::inst::Bfd::on_recv`], because the hop mode isn't known here.
pub async fn read_packet(sock: Arc<AsyncFd<Socket>>, tx: UnboundedSender<Message>) {
    let mut buf = [0u8; 1500];
    let mut iov = [IoSliceMut::new(&mut buf)];
    let mut cmsgspace = nix::cmsg_space!(libc::in_pktinfo, libc::c_int);

    loop {
        let _ = sock
            .async_io(Interest::READABLE, |sock| {
                let msg = socket::recvmsg::<SockaddrIn>(
                    sock.as_raw_fd(),
                    &mut iov,
                    Some(&mut cmsgspace),
                    socket::MsgFlags::empty(),
                )?;

                let Some(src) = msg.address else {
                    return Err(ErrorKind::AddrNotAvailable.into());
                };
                let src = SocketAddr::V4(SocketAddrV4::new(src.ip(), src.port()));

                let mut dst: Option<Ipv4Addr> = None;
                let mut ifindex: u32 = 0;
                let mut ttl: u8 = 0;
                for cmsg in msg.cmsgs()? {
                    match cmsg {
                        ControlMessageOwned::Ipv4PacketInfo(pi) => {
                            dst = Some(Ipv4Addr::from(pi.ipi_addr.s_addr.to_be()));
                            ifindex = pi.ipi_ifindex as u32;
                        }
                        ControlMessageOwned::Ipv4Ttl(v) => ttl = v.clamp(0, 255) as u8,
                        _ => {}
                    }
                }

                let Some(payload) = msg.iovs().next() else {
                    return Err(ErrorKind::UnexpectedEof.into());
                };

                let packet = match bfd_packet::ControlPacket::parse(payload) {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::debug!(?src, error = %e, "bfd: invalid control packet");
                        return Ok(());
                    }
                };

                // The per-session TTL floor (GTSM for single-hop, the
                // configured minimum for multihop) is checked after demux
                // in `on_recv`; we can't know the hop mode at this point.
                let _ = tx.send(Message::Recv {
                    packet,
                    src,
                    dst: dst.map(IpAddr::V4),
                    ifindex,
                    ttl,
                });
                Ok(())
            })
            .await;
    }
}

/// Async send loop. Drains [`WriteRequest`] from `rx`, encodes the
/// control packet, and dispatches it via `sendmsg`. The outgoing TTL
/// is fixed to 255 by the socket option configured in
/// [`super::socket::bfd_socket_ipv4`]. When `WriteRequest::ifindex`
/// is `Some`, an `IP_PKTINFO` ancillary message pins egress to that
/// interface; otherwise the kernel routes normally.
pub async fn write_packet(sock: Arc<AsyncFd<Socket>>, mut rx: UnboundedReceiver<WriteRequest>) {
    while let Some(req) = rx.recv().await {
        let SocketAddr::V4(dst) = req.dst else {
            // Routed to the wrong (v4) loop — `on_tx_tick` shouldn't do
            // this, but never send a v6 destination on the v4 socket.
            continue;
        };
        let mut buf = BytesMut::new();
        req.packet.emit(&mut buf);
        let iov = [IoSlice::new(&buf)];
        let sockaddr: SockaddrIn = dst.into();

        let pktinfo = req.ifindex.map(|ifindex| libc::in_pktinfo {
            ipi_ifindex: ifindex as i32,
            ipi_spec_dst: libc::in_addr { s_addr: 0 },
            ipi_addr: libc::in_addr { s_addr: 0 },
        });
        let cmsg_storage;
        let cmsgs: &[socket::ControlMessage<'_>] = if let Some(ref pi) = pktinfo {
            cmsg_storage = [socket::ControlMessage::Ipv4PacketInfo(pi)];
            &cmsg_storage
        } else {
            &[]
        };

        let _ = sock
            .async_io(Interest::WRITABLE, |sock| {
                socket::sendmsg(
                    sock.as_raw_fd(),
                    &iov,
                    cmsgs,
                    socket::MsgFlags::empty(),
                    Some(&sockaddr),
                )
                .map_err(std::io::Error::from)?;
                Ok(())
            })
            .await;
    }
}

/// IPv6 sibling of [`read_packet`]. Recovers the received Hop Limit
/// (via `IPV6_RECVHOPLIMIT`) and ingress ifindex (via
/// `IPV6_RECVPKTINFO`) and forwards survivors as [`Message::Recv`] with
/// a v6 `src`. The Hop-Limit floor is enforced after demux in
/// [`super::inst::Bfd::on_recv`], same as v4.
pub async fn read_packet_v6(sock: Arc<AsyncFd<Socket>>, tx: UnboundedSender<Message>) {
    let mut buf = [0u8; 1500];
    let mut iov = [IoSliceMut::new(&mut buf)];
    let mut cmsgspace = nix::cmsg_space!(libc::in6_pktinfo, libc::c_int);

    loop {
        let _ = sock
            .async_io(Interest::READABLE, |sock| {
                let msg = socket::recvmsg::<SockaddrIn6>(
                    sock.as_raw_fd(),
                    &mut iov,
                    Some(&mut cmsgspace),
                    socket::MsgFlags::empty(),
                )?;

                let Some(src6) = msg.address else {
                    return Err(ErrorKind::AddrNotAvailable.into());
                };
                let src = SocketAddr::V6(SocketAddrV6::new(
                    src6.ip(),
                    src6.port(),
                    src6.flowinfo(),
                    src6.scope_id(),
                ));

                let mut dst: Option<Ipv6Addr> = None;
                let mut ifindex: u32 = 0;
                let mut hop_limit: u8 = 0;
                for cmsg in msg.cmsgs()? {
                    match cmsg {
                        ControlMessageOwned::Ipv6PacketInfo(pi) => {
                            dst = Some(Ipv6Addr::from(pi.ipi6_addr.s6_addr));
                            ifindex = pi.ipi6_ifindex;
                        }
                        ControlMessageOwned::Ipv6HopLimit(v) => hop_limit = v.clamp(0, 255) as u8,
                        _ => {}
                    }
                }

                let Some(payload) = msg.iovs().next() else {
                    return Err(ErrorKind::UnexpectedEof.into());
                };

                let packet = match bfd_packet::ControlPacket::parse(payload) {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::debug!(?src, error = %e, "bfd: invalid control packet");
                        return Ok(());
                    }
                };

                let _ = tx.send(Message::Recv {
                    packet,
                    src,
                    dst: dst.map(IpAddr::V6),
                    ifindex,
                    ttl: hop_limit,
                });
                Ok(())
            })
            .await;
    }
}

/// IPv6 sibling of [`write_packet`]. The outgoing Hop Limit is fixed to
/// 255 by the socket option in [`super::socket::bfd_socket_ipv6`]. When
/// `WriteRequest::ifindex` is `Some`, an `IPV6_PKTINFO` ancillary
/// message pins egress to that interface — mandatory for link-local
/// destinations.
pub async fn write_packet_v6(sock: Arc<AsyncFd<Socket>>, mut rx: UnboundedReceiver<WriteRequest>) {
    while let Some(req) = rx.recv().await {
        let SocketAddr::V6(dst) = req.dst else {
            continue;
        };
        let mut buf = BytesMut::new();
        req.packet.emit(&mut buf);
        let iov = [IoSlice::new(&buf)];
        let sockaddr: SockaddrIn6 = dst.into();

        let pktinfo = req.ifindex.map(|ifindex| libc::in6_pktinfo {
            ipi6_addr: libc::in6_addr { s6_addr: [0u8; 16] },
            ipi6_ifindex: ifindex,
        });
        let cmsg_storage;
        let cmsgs: &[socket::ControlMessage<'_>] = if let Some(ref pi) = pktinfo {
            cmsg_storage = [socket::ControlMessage::Ipv6PacketInfo(pi)];
            &cmsg_storage
        } else {
            &[]
        };

        let _ = sock
            .async_io(Interest::WRITABLE, |sock| {
                socket::sendmsg(
                    sock.as_raw_fd(),
                    &iov,
                    cmsgs,
                    socket::MsgFlags::empty(),
                    Some(&sockaddr),
                )
                .map_err(std::io::Error::from)?;
                Ok(())
            })
            .await;
    }
}

#[cfg(test)]
mod tests {
    use bfd_packet::{ControlPacket, State};
    use bytes::BytesMut;
    use socket2::SockAddr;
    use tokio::sync::mpsc;

    use super::*;
    use crate::bfd::socket::{bfd_socket_ipv4, bfd_socket_ipv6};
    use crate::context::ProtoContext;

    fn loopback_recv_socket() -> (Arc<AsyncFd<Socket>>, u16) {
        let ctx = ProtoContext::default_table_no_rib();
        let sock = bfd_socket_ipv4(&ctx, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = sock.local_addr().unwrap().as_socket_ipv4().unwrap().port();
        (Arc::new(AsyncFd::new(sock).unwrap()), port)
    }

    fn loopback_recv_socket_v6() -> (Arc<AsyncFd<Socket>>, u16) {
        let ctx = ProtoContext::default_table_no_rib();
        let sock = bfd_socket_ipv6(&ctx, SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0)).unwrap();
        let port = sock.local_addr().unwrap().as_socket_ipv6().unwrap().port();
        (Arc::new(AsyncFd::new(sock).unwrap()), port)
    }

    fn send_raw_v6(buf: &[u8], dst_port: u16, hops: u32) {
        let sock = Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .unwrap();
        sock.set_unicast_hops_v6(hops).unwrap();
        sock.bind(&SockAddr::from(SocketAddrV6::new(
            Ipv6Addr::LOCALHOST,
            0,
            0,
            0,
        )))
        .unwrap();
        let dst = SocketAddrV6::new(Ipv6Addr::LOCALHOST, dst_port, 0, 0);
        sock.send_to(buf, &SockAddr::from(dst)).unwrap();
    }

    fn send_raw(buf: &[u8], dst_port: u16, ttl: u32) {
        let sock = Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .unwrap();
        sock.set_ttl_v4(ttl).unwrap();
        sock.bind(&SockAddr::from(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
            .unwrap();
        let dst = SocketAddrV4::new(Ipv4Addr::LOCALHOST, dst_port);
        sock.send_to(buf, &SockAddr::from(dst)).unwrap();
    }

    /// End-to-end loopback: bind an ephemeral receive socket, send a
    /// hand-crafted Down-state packet with TTL=255, and verify the
    /// recv path delivers a parsed [`Message::Recv`].
    #[tokio::test]
    async fn loopback_recv_one_packet() {
        let (sock, port) = loopback_recv_socket();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let read_handle = tokio::spawn(async move { read_packet(sock, tx).await });

        let packet = ControlPacket {
            state: State::Down,
            my_disc: 0x1234_5678,
            ..ControlPacket::default()
        };
        let mut wire = BytesMut::new();
        packet.emit(&mut wire);
        send_raw(&wire, port, 255);

        let got = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("recv timed out")
            .expect("channel closed");

        let Message::Recv {
            packet: rx_packet, ..
        } = got
        else {
            panic!("expected Recv, got {got:?}");
        };
        assert_eq!(rx_packet, packet);

        read_handle.abort();
    }

    /// The TTL floor is no longer enforced in `read_packet` — it's
    /// deferred to `on_recv`, which knows the matched session's hop
    /// mode. So a TTL=1 packet is *forwarded*, carrying its received
    /// TTL up for the demux layer to accept or drop.
    #[tokio::test]
    async fn low_ttl_forwarded_for_demux_check() {
        let (sock, port) = loopback_recv_socket();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let read_handle = tokio::spawn(async move { read_packet(sock, tx).await });

        let packet = ControlPacket {
            state: State::Down,
            my_disc: 0xdead_beef,
            ..ControlPacket::default()
        };
        let mut wire = BytesMut::new();
        packet.emit(&mut wire);
        send_raw(&wire, port, 1);

        let got = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("recv timed out")
            .expect("channel closed");
        let Message::Recv { ttl, .. } = got else {
            panic!("expected Recv, got {got:?}");
        };
        assert_eq!(ttl, 1, "received TTL is carried up, not dropped here");

        read_handle.abort();
    }

    /// End-to-end IPv6 loopback: bind an ephemeral v6 receive socket via
    /// `bfd_socket_ipv6`, send a packet over ::1 with Hop Limit=255, and
    /// verify `read_packet_v6` delivers a `Message::Recv` with a v6 `src`
    /// and the received hop limit carried in `ttl`.
    #[tokio::test]
    async fn loopback_recv_one_packet_v6() {
        let (sock, port) = loopback_recv_socket_v6();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let read_handle = tokio::spawn(async move { read_packet_v6(sock, tx).await });

        let packet = ControlPacket {
            state: State::Down,
            my_disc: 0x6666_7777,
            ..ControlPacket::default()
        };
        let mut wire = BytesMut::new();
        packet.emit(&mut wire);
        send_raw_v6(&wire, port, 255);

        let got = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("recv timed out")
            .expect("channel closed");
        let Message::Recv {
            packet: rx_packet,
            src,
            ttl,
            ..
        } = got
        else {
            panic!("expected Recv, got {got:?}");
        };
        assert_eq!(rx_packet, packet);
        assert!(src.is_ipv6(), "src carries the v6 family, got {src:?}");
        assert_eq!(ttl, 255, "received hop limit is carried up");

        read_handle.abort();
    }

    /// A malformed packet (zero discriminator) is dropped by parse
    /// validation; no event reaches the channel.
    #[tokio::test]
    async fn parse_error_dropped() {
        let (sock, port) = loopback_recv_socket();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let read_handle = tokio::spawn(async move { read_packet(sock, tx).await });

        // A 24-byte buffer with version=1 but zero My Discriminator —
        // ControlPacket::parse rejects it (ZeroMyDisc).
        let mut wire = [0u8; 24];
        wire[0] = 0x20; // version=1
        wire[2] = 3; // detect mult
        wire[3] = 24; // length
        // my_disc bytes 4..8 left zero on purpose.
        send_raw(&wire, port, 255);

        let timed = tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv()).await;
        assert!(timed.is_err(), "malformed packet must be dropped");

        read_handle.abort();
    }
}
