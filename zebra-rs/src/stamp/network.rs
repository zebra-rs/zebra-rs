//! STAMP socket read/write tasks.
//!
//! Three loops, mirroring `bfd/network.rs`:
//!
//!   * [`reflector_read`] — `recvmsg` on the wildcard reflector socket
//!     with `IP_PKTINFO` + `IP_RECVTTL` ancillary data; stamps the
//!     receive timestamp (T2) at the earliest userspace point and
//!     forwards parsed probes to the event loop;
//!   * [`reflector_write`] — drains [`ReflectRequest`]s, sending each
//!     reply via `sendmsg` with the source address forced to the
//!     probed address (the sender's connected socket only accepts
//!     replies from exactly the address it probed) and egress pinned
//!     to the ingress interface;
//!   * [`sender_read`] — plain `recv` on one session's connected
//!     socket; stamps T4 at receipt and forwards parsed reflector
//!     packets keyed by the session.

use std::io::{ErrorKind, IoSlice, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::AsRawFd;
use std::sync::Arc;

use bytes::BytesMut;
use nix::sys::socket::{self, ControlMessageOwned, MsgFlags, SockaddrIn};
use socket2::Socket;
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use super::inst::Message;
use super::session::SessionKey;
use super::timestamp::now_ntp;

/// One reflected reply queued for [`reflector_write`].
#[derive(Debug)]
pub struct ReflectRequest {
    pub reply: stamp_packet::ReflectorPacket,
    /// The probe's source — where the reply goes.
    pub dst: SocketAddr,
    /// Source address to stamp (the probe's destination — the probed
    /// link address). `None` lets the kernel pick, which is only safe
    /// when the socket is bound to a concrete address (tests).
    pub src: Option<IpAddr>,
    /// Egress pinned to the probe's ingress interface.
    pub ifindex: Option<u32>,
}

/// Reflector receive loop. Parses [`stamp_packet::SenderPacket`]s and
/// forwards them as [`Message::ProbeRecv`] with the receive timestamp
/// (T2) taken here — the single T2 capture point; a cmsg-timestamp or
/// kernel-map source swaps in at this seam (offload notes §9b R3).
pub async fn reflector_read(sock: Arc<AsyncFd<Socket>>, tx: UnboundedSender<Message>) {
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
                    MsgFlags::empty(),
                )?;
                let rx_ts = now_ntp();

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
                let len = payload.len();

                let probe = match stamp_packet::SenderPacket::parse(payload) {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::debug!(?src, error = %e, "stamp: invalid sender packet");
                        return Ok(());
                    }
                };

                let _ = tx.send(Message::ProbeRecv {
                    probe,
                    src,
                    dst: dst.map(IpAddr::V4),
                    ifindex,
                    ttl,
                    rx_ts,
                    len,
                });
                Ok(())
            })
            .await;
    }
}

/// Reflector send loop. The source-address stamp works exactly like
/// BFD's: `ipi_spec_dst` names the *source* of an outgoing datagram.
pub async fn reflector_write(
    sock: Arc<AsyncFd<Socket>>,
    mut rx: UnboundedReceiver<ReflectRequest>,
) {
    while let Some(req) = rx.recv().await {
        let SocketAddr::V4(dst) = req.dst else {
            continue; // IPv4 only in Phase 1
        };
        let mut buf = BytesMut::new();
        req.reply.emit(&mut buf);
        let iov = [IoSlice::new(&buf)];
        let sockaddr: SockaddrIn = dst.into();

        let spec_dst = match req.src {
            Some(IpAddr::V4(a)) => u32::from_ne_bytes(a.octets()),
            _ => 0,
        };
        let pktinfo = (req.ifindex.is_some() || spec_dst != 0).then(|| libc::in_pktinfo {
            ipi_ifindex: req.ifindex.unwrap_or(0) as i32,
            ipi_spec_dst: libc::in_addr { s_addr: spec_dst },
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
                    MsgFlags::empty(),
                    Some(&sockaddr),
                )
                .map_err(std::io::Error::from)?;
                Ok(())
            })
            .await;
    }
}

/// Per-session reply read loop on the connected sender socket. The
/// kernel already demuxed by 4-tuple, so a plain `recv` suffices. T4
/// is taken here — the single T4 capture point (offload notes §9b R3).
pub async fn sender_read(
    key: SessionKey,
    sock: Arc<AsyncFd<Socket>>,
    tx: UnboundedSender<Message>,
) {
    let mut buf = [0u8; 1500];

    loop {
        let _ = sock
            .async_io(Interest::READABLE, |sock| {
                let n = socket::recv(sock.as_raw_fd(), &mut buf, MsgFlags::empty())
                    .map_err(std::io::Error::from)?;
                let t4 = now_ntp();

                let reply = match stamp_packet::ReflectorPacket::parse(&buf[..n]) {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::debug!(?key, error = %e, "stamp: invalid reflector packet");
                        return Ok(());
                    }
                };

                let _ = tx.send(Message::ReplyRecv { key, reply, t4 });
                Ok(())
            })
            .await;
    }
}
