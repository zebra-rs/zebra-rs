//! STAMP socket read/write tasks.
//!
//! Three loops, mirroring `bfd/network.rs`:
//!
//!   * [`reflector_read`] — `recvmsg` on the wildcard reflector socket
//!     with `IP_PKTINFO` + `IP_RECVTTL` + `SCM_TIMESTAMPING` ancillary
//!     data; takes T2 from the kernel software receive stamp when
//!     present, else a userspace read, and forwards
//!     parsed probes to the event loop;
//!   * [`reflector_write`] — drains [`ReflectRequest`]s, sending each
//!     reply via `sendmsg` with the source address forced to the
//!     probed address (the sender's connected socket only accepts
//!     replies from exactly the address it probed) and egress pinned
//!     to the ingress interface;
//!   * [`sender_read`] — `recvmsg` on one session's connected socket;
//!     takes T4 from the kernel software receive stamp when present
//!     (else a userspace read) and forwards parsed reflector packets
//!     keyed by the session.

use std::io::{ErrorKind, IoSlice, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::AsRawFd;
use std::sync::Arc;

use bytes::BytesMut;
use nix::sys::socket::{
    self, ControlMessageOwned, MsgFlags, SockaddrIn, SockaddrIn6, SockaddrStorage,
};
use socket2::Socket;
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use stamp_packet::StampTimestamp;

use super::inst::Message;
use super::session::SessionKey;
use super::timestamp::{now_ntp, unix_to_ntp};

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
    let mut cmsgspace =
        nix::cmsg_space!(libc::in_pktinfo, libc::c_int, nix::sys::socket::Timestamps);

    loop {
        let _ = sock
            .async_io(Interest::READABLE, |sock| {
                let msg = socket::recvmsg::<SockaddrIn>(
                    sock.as_raw_fd(),
                    &mut iov,
                    Some(&mut cmsgspace),
                    MsgFlags::empty(),
                )?;

                let Some(src) = msg.address else {
                    return Err(ErrorKind::AddrNotAvailable.into());
                };
                let src = SocketAddr::V4(SocketAddrV4::new(src.ip(), src.port()));

                let mut dst: Option<Ipv4Addr> = None;
                let mut ifindex: u32 = 0;
                let mut ttl: u8 = 0;
                let mut kernel_t2: Option<StampTimestamp> = None;
                for cmsg in msg.cmsgs()? {
                    match cmsg {
                        ControlMessageOwned::Ipv4PacketInfo(pi) => {
                            dst = Some(Ipv4Addr::from(pi.ipi_addr.s_addr.to_be()));
                            ifindex = pi.ipi_ifindex as u32;
                        }
                        ControlMessageOwned::Ipv4Ttl(v) => ttl = v.clamp(0, 255) as u8,
                        ControlMessageOwned::ScmTimestampsns(ts) => {
                            let (secs, nanos) = (ts.system.tv_sec(), ts.system.tv_nsec());
                            if secs != 0 || nanos != 0 {
                                kernel_t2 = Some(unix_to_ntp(secs as u64, nanos as u32));
                            }
                        }
                        _ => {}
                    }
                }
                // T2: the kernel software receive stamp when available,
                // else a userspace read (offload notes §9b R3).
                let t2_kernel = kernel_t2.is_some();
                let rx_ts = kernel_t2.unwrap_or_else(now_ntp);

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
                    t2_kernel,
                    len,
                });
                Ok(())
            })
            .await;
    }
}

/// IPv6 sibling of [`reflector_read`]: `recvmsg` on the `[::]:862`
/// reflector socket with `IPV6_PKTINFO` + `IPV6_RECVHOPLIMIT` +
/// `SCM_TIMESTAMPING` ancillary data. The probe `src` carries its
/// scope id (the ingress ifindex), and the probed link-local
/// destination (`dst`) plus the ingress `ifindex` flow through so the
/// reply can be stamped and pinned (see [`reflector_write_v6`]).
/// T2 comes from the kernel software stamp when present, else a
/// userspace read — identical to the v4 path.
pub async fn reflector_read_v6(sock: Arc<AsyncFd<Socket>>, tx: UnboundedSender<Message>) {
    let mut buf = [0u8; 1500];
    let mut iov = [IoSliceMut::new(&mut buf)];
    let mut cmsgspace =
        nix::cmsg_space!(libc::in6_pktinfo, libc::c_int, nix::sys::socket::Timestamps);

    loop {
        let _ = sock
            .async_io(Interest::READABLE, |sock| {
                let msg = socket::recvmsg::<SockaddrIn6>(
                    sock.as_raw_fd(),
                    &mut iov,
                    Some(&mut cmsgspace),
                    MsgFlags::empty(),
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
                let mut ttl: u8 = 0;
                let mut kernel_t2: Option<StampTimestamp> = None;
                for cmsg in msg.cmsgs()? {
                    match cmsg {
                        ControlMessageOwned::Ipv6PacketInfo(pi) => {
                            dst = Some(Ipv6Addr::from(pi.ipi6_addr.s6_addr));
                            ifindex = pi.ipi6_ifindex;
                        }
                        ControlMessageOwned::Ipv6HopLimit(v) => ttl = v.clamp(0, 255) as u8,
                        ControlMessageOwned::ScmTimestampsns(ts) => {
                            let (secs, nanos) = (ts.system.tv_sec(), ts.system.tv_nsec());
                            if secs != 0 || nanos != 0 {
                                kernel_t2 = Some(unix_to_ntp(secs as u64, nanos as u32));
                            }
                        }
                        _ => {}
                    }
                }
                // T2: the kernel software receive stamp when available,
                // else a userspace read (offload notes §9b R3).
                let t2_kernel = kernel_t2.is_some();
                let rx_ts = kernel_t2.unwrap_or_else(now_ntp);

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
                    dst: dst.map(IpAddr::V6),
                    ifindex,
                    ttl,
                    rx_ts,
                    t2_kernel,
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
            continue; // IPv4 only
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

/// IPv6 sibling of [`reflector_write`], modelled on BFD's
/// `write_packet_v6`. `ipi6_addr` forces the outgoing source to the
/// probed link-local (the sender's connected socket only accepts a
/// reply from exactly the address it probed), and `ipi6_ifindex` pins
/// egress to the ingress interface — mandatory for link-local
/// destinations.
pub async fn reflector_write_v6(
    sock: Arc<AsyncFd<Socket>>,
    mut rx: UnboundedReceiver<ReflectRequest>,
) {
    while let Some(req) = rx.recv().await {
        let SocketAddr::V6(dst) = req.dst else {
            continue; // v6 channel: drop any v4 reply queued by mistake
        };
        let mut buf = BytesMut::new();
        req.reply.emit(&mut buf);
        let iov = [IoSlice::new(&buf)];
        let sockaddr: SockaddrIn6 = dst.into();

        // `ipi6_addr` sets the source on the outgoing datagram; a cmsg
        // is emitted when either an egress ifindex or a source address
        // is requested (ifindex is mandatory for link-local).
        let src6 = match req.src {
            Some(IpAddr::V6(a)) => Some(a.octets()),
            _ => None,
        };
        let pktinfo = (req.ifindex.is_some() || src6.is_some()).then(|| libc::in6_pktinfo {
            ipi6_addr: libc::in6_addr {
                s6_addr: src6.unwrap_or([0u8; 16]),
            },
            ipi6_ifindex: req.ifindex.unwrap_or(0),
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
                    MsgFlags::empty(),
                    Some(&sockaddr),
                )
                .map_err(std::io::Error::from)?;
                Ok(())
            })
            .await;
    }
}

/// Extract the software receive timestamp from an `SCM_TIMESTAMPING`
/// ancillary message, if the kernel attached one (enabled by
/// [`super::socket::set_so_timestamping_rx`]). The `system`
/// field carries the software (CLOCK_REALTIME) stamp; an all-zero value
/// means the kernel didn't stamp this datagram, so we report `None` and
/// the caller falls back to a userspace `now_ntp()`.
fn kernel_rx_stamp<'a>(
    cmsgs: impl Iterator<Item = ControlMessageOwned> + 'a,
) -> Option<StampTimestamp> {
    for cmsg in cmsgs {
        if let ControlMessageOwned::ScmTimestampsns(ts) = cmsg {
            let (secs, nanos) = (ts.system.tv_sec(), ts.system.tv_nsec());
            if secs != 0 || nanos != 0 {
                return Some(unix_to_ntp(secs as u64, nanos as u32));
            }
        }
    }
    None
}

/// Per-session reply read loop on the connected sender socket. The
/// kernel already demuxed by 4-tuple. T4 is taken here — the single T4
/// capture point (offload notes §9b R3): the kernel software receive
/// stamp when available (`SO_TIMESTAMPING`), else a userspace
/// `now_ntp()`. `t4_kernel` records which, for `show stamp statistics`.
///
/// Family-agnostic: the connected socket never uses `msg.address`, so
/// the recvmsg decode type is [`SockaddrStorage`] and the same loop
/// serves both v4 and v6 sessions.
pub async fn sender_read(
    key: SessionKey,
    sock: Arc<AsyncFd<Socket>>,
    tx: UnboundedSender<Message>,
) {
    let mut buf = [0u8; 1500];
    let mut iov = [IoSliceMut::new(&mut buf)];
    let mut cmsgspace = nix::cmsg_space!(nix::sys::socket::Timestamps);

    loop {
        let _ = sock
            .async_io(Interest::READABLE, |sock| {
                let msg = socket::recvmsg::<SockaddrStorage>(
                    sock.as_raw_fd(),
                    &mut iov,
                    Some(&mut cmsgspace),
                    MsgFlags::empty(),
                )?;
                // Kernel stamp first (taken at skb receive, before the
                // softirq→queue→wake→poll chain), userspace fallback.
                let kernel_t4 = kernel_rx_stamp(msg.cmsgs()?);
                let t4_kernel = kernel_t4.is_some();
                let t4 = kernel_t4.unwrap_or_else(now_ntp);

                let Some(payload) = msg.iovs().next() else {
                    return Err(ErrorKind::UnexpectedEof.into());
                };
                let reply = match stamp_packet::ReflectorPacket::parse(payload) {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::debug!(?key, error = %e, "stamp: invalid reflector packet");
                        return Ok(());
                    }
                };

                let _ = tx.send(Message::ReplyRecv {
                    key,
                    reply,
                    t4,
                    t4_kernel,
                });
                Ok(())
            })
            .await;
    }
}

#[cfg(test)]
mod tests {
    use std::net::UdpSocket;

    use super::*;
    use crate::context::ProtoContext;
    use crate::stamp::socket::{stamp_reflector_socket, stamp_reflector_socket_v6};

    /// A socket built with `set_so_timestamping_rx`
    /// receives a software RX timestamp in the `SCM_TIMESTAMPING`
    /// ancillary message on loopback (software stamps are stack-level,
    /// so they work without NIC support), and `kernel_rx_stamp`
    /// extracts a non-zero NTP value from it.
    #[tokio::test]
    async fn reflector_socket_delivers_kernel_rx_stamp() {
        let ctx = ProtoContext::default_table_no_rib();
        let sock = stamp_reflector_socket(&ctx, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = sock.local_addr().unwrap().as_socket_ipv4().unwrap().port();
        let sock = Arc::new(AsyncFd::new(sock).unwrap());

        // Send one datagram to the bound port.
        let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        sender
            .send_to(&[0u8; 44], (Ipv4Addr::LOCALHOST, port))
            .unwrap();

        let mut buf = [0u8; 1500];
        let mut iov = [IoSliceMut::new(&mut buf)];
        let mut cmsgspace =
            nix::cmsg_space!(libc::in_pktinfo, libc::c_int, nix::sys::socket::Timestamps);

        let stamp = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                let got = sock
                    .async_io(Interest::READABLE, |sock| {
                        let msg = socket::recvmsg::<SockaddrIn>(
                            sock.as_raw_fd(),
                            &mut iov,
                            Some(&mut cmsgspace),
                            MsgFlags::empty(),
                        )?;
                        Ok(kernel_rx_stamp(msg.cmsgs()?))
                    })
                    .await;
                if let Ok(stamp) = got {
                    return stamp;
                }
            }
        })
        .await
        .expect("recv timed out");

        assert!(
            stamp.is_some(),
            "loopback must deliver a software RX timestamp with SO_TIMESTAMPING enabled"
        );
    }

    /// v6 parity for the rung-1 RX stamp: a `[::]`-bound v6
    /// reflector socket also gets a software `SCM_TIMESTAMPING` stamp on
    /// the `::1` loopback, decoded the same way as the v4 path. This
    /// exercises the v6 receive cmsg set (`in6_pktinfo` + hop-limit +
    /// timestamp) that [`reflector_read_v6`] reads.
    #[tokio::test]
    async fn reflector_socket_v6_delivers_kernel_rx_stamp() {
        let ctx = ProtoContext::default_table_no_rib();
        let sock = stamp_reflector_socket_v6(&ctx, SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0))
            .unwrap();
        let port = sock.local_addr().unwrap().as_socket_ipv6().unwrap().port();
        let sock = Arc::new(AsyncFd::new(sock).unwrap());

        let sender = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).unwrap();
        sender
            .send_to(&[0u8; 44], (Ipv6Addr::LOCALHOST, port))
            .unwrap();

        let mut buf = [0u8; 1500];
        let mut iov = [IoSliceMut::new(&mut buf)];
        let mut cmsgspace =
            nix::cmsg_space!(libc::in6_pktinfo, libc::c_int, nix::sys::socket::Timestamps);

        let stamp = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                let got = sock
                    .async_io(Interest::READABLE, |sock| {
                        let msg = socket::recvmsg::<SockaddrIn6>(
                            sock.as_raw_fd(),
                            &mut iov,
                            Some(&mut cmsgspace),
                            MsgFlags::empty(),
                        )?;
                        Ok(kernel_rx_stamp(msg.cmsgs()?))
                    })
                    .await;
                if let Ok(stamp) = got {
                    return stamp;
                }
            }
        })
        .await
        .expect("recv timed out");

        assert!(
            stamp.is_some(),
            "v6 loopback must deliver a software RX timestamp with SO_TIMESTAMPING enabled"
        );
    }
}
