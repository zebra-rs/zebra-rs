use std::io::{ErrorKind, IoSlice, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::os::fd::AsRawFd;
use std::sync::Arc;

use bytes::BytesMut;
use nix::sys::socket::{self, ControlMessageOwned, SockaddrIn};
use socket2::Socket;
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use super::inst::Message;

/// GTSM expected TTL for single-hop BFD (RFC 5881 §5).
const GTSM_TTL: u8 = 255;

/// Egress request consumed by [`write_packet`]. The event loop pushes
/// these whenever a [`super::timer::TimerEvent::TxTick`] fires (or in
/// future PRs, when a poll-sequence packet must be sent off-schedule).
#[derive(Debug)]
pub struct WriteRequest {
    pub packet: bfd_packet::ControlPacket,
    pub dst: SocketAddrV4,
    /// Optional egress ifindex (sent via `IP_PKTINFO`). `None` lets
    /// the kernel route normally.
    pub ifindex: Option<u32>,
}

/// Async receive loop. Pulls one BFD control packet at a time off
/// `sock`, runs structural validation via
/// [`bfd_packet::ControlPacket::parse`], drops packets that fail GTSM
/// (TTL < 255) with a debug log, and forwards survivors to the event
/// loop via `tx`.
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
                let src = SocketAddrV4::new(src.ip(), src.port());

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

                if ttl != GTSM_TTL {
                    // RFC 5881 §5: single-hop control packets MUST arrive
                    // with TTL=255. Misconfigured peer; debug-log only
                    // so a chatty bad neighbour can't flood the logs.
                    tracing::debug!(
                        ?src,
                        ?dst,
                        ttl,
                        ifindex,
                        "bfd: GTSM violation, dropping packet",
                    );
                    return Ok(());
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
                    dst: dst.map(IpAddr::V4),
                    ifindex,
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
        let mut buf = BytesMut::new();
        req.packet.emit(&mut buf);
        let iov = [IoSlice::new(&buf)];
        let sockaddr: SockaddrIn = req.dst.into();

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

#[cfg(test)]
mod tests {
    use bfd_packet::{ControlPacket, State};
    use bytes::BytesMut;
    use socket2::SockAddr;
    use tokio::sync::mpsc;

    use super::*;
    use crate::bfd::socket::bfd_socket_ipv4;
    use crate::context::ProtoContext;

    fn loopback_recv_socket() -> (Arc<AsyncFd<Socket>>, u16) {
        let ctx = ProtoContext::default_table_no_rib();
        let sock = bfd_socket_ipv4(&ctx, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = sock.local_addr().unwrap().as_socket_ipv4().unwrap().port();
        (Arc::new(AsyncFd::new(sock).unwrap()), port)
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

    /// Packets with TTL < 255 are dropped per the GTSM rule in
    /// RFC 5881 §5. No event reaches the channel.
    #[tokio::test]
    async fn gtsm_drops_low_ttl() {
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

        let timed = tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv()).await;
        assert!(
            timed.is_err(),
            "GTSM should have dropped the TTL=1 packet, got: {:?}",
            timed.ok()
        );

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
