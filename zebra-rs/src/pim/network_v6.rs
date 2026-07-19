//! PIMv6 socket read / write tasks. Mirrors `crate::ospf::network_v6`:
//! IPv6 raw sockets deliver the PIM payload directly (the kernel
//! strips the IPv6 header — no IHL skip), the read task recovers the
//! ingress ifindex and the destination from the `in6_pktinfo`
//! ancillary message for the pseudo-header checksum, and the write
//! task pins the link-local source + egress interface via
//! `in6_pktinfo` so the checksum matches what the kernel emits.

use std::io::{ErrorKind, IoSlice, IoSliceMut};
use std::net::Ipv6Addr;
use std::os::fd::AsRawFd;
use std::sync::Arc;

use bytes::BytesMut;
use nix::sys::socket::{self, ControlMessageOwned, SockaddrIn6};
use pim_packet::{PimChecksumContext, PimPacket, pim_verify_checksum};
use socket2::Socket;
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use super::inst::{Message, PimSend};
use super::ipv6::Ipv6;
use super::mroute::parse_upcall_v6;

/// Whether `a` is a unicast link-local (`fe80::/10`). PIMv6 control
/// messages MUST be sourced from a link-local (RFC 7761 §4.3.1); a
/// packet from any other scope is dropped.
fn is_link_local(a: &Ipv6Addr) -> bool {
    let o = a.octets();
    o[0] == 0xfe && (o[1] & 0xc0) == 0x80
}

pub async fn read_packet_v6(sock: Arc<AsyncFd<Socket>>, tx: UnboundedSender<Message<Ipv6>>) {
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
                // On receive `ipi6_addr` is the destination (our
                // unicast address or the multicast group); the
                // pseudo-header checksum folds it in.
                let dst: Ipv6Addr = Ipv6Addr::from(pktinfo.ipi6_addr.s6_addr);
                let ifindex = pktinfo.ipi6_ifindex;

                // RFC 7761 §4.3.1: PIMv6 control is link-local sourced.
                if !is_link_local(&src) {
                    tracing::debug!("pim6: non-link-local source {src} dropped");
                    return Err(ErrorKind::InvalidData.into());
                }

                let Some(input) = msg.iovs().next() else {
                    return Err(ErrorKind::UnexpectedEof.into());
                };

                if !pim_verify_checksum(input, PimChecksumContext::Ipv6 { src, dst }) {
                    tracing::debug!("pim6: bad checksum from {src} on ifindex {ifindex}");
                    return Err(ErrorKind::InvalidData.into());
                }
                let Ok((_, packet)) = PimPacket::parse_be(input) else {
                    tracing::debug!("pim6: malformed packet from {src} on ifindex {ifindex}");
                    return Err(ErrorKind::InvalidData.into());
                };

                let _ = tx.send(Message::Recv {
                    packet,
                    src,
                    ifindex,
                });

                Ok(())
            })
            .await;
        if tx.is_closed() {
            return;
        }
    }
}

/// Drain the MRT6 socket: kernel `mrt6msg` upcalls (first byte zero)
/// become [`Message::Upcall`]; genuine ICMPv6 the kernel also delivers
/// here is dropped by [`parse_upcall_v6`].
pub async fn mroute_read_v6(sock: Arc<AsyncFd<Socket>>, tx: UnboundedSender<Message<Ipv6>>) {
    let mut buf = [0u8; 1024 * 16];

    loop {
        let _ = sock
            .async_io(Interest::READABLE, |sock| {
                let n = unsafe {
                    libc::recv(
                        sock.as_raw_fd(),
                        buf.as_mut_ptr() as *mut libc::c_void,
                        buf.len(),
                        0,
                    )
                };
                if n < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if let Some(upcall) = parse_upcall_v6(&buf[..n as usize]) {
                    let _ = tx.send(Message::Upcall(upcall));
                }
                Ok(())
            })
            .await;
        if tx.is_closed() {
            return;
        }
    }
}

pub async fn write_packet_v6(sock: Arc<AsyncFd<Socket>>, mut rx: UnboundedReceiver<PimSend<Ipv6>>) {
    while let Some(send) = rx.recv().await {
        // The IPv6 pseudo-header checksum needs the source; without a
        // pinned link-local we cannot form a valid PIMv6 packet.
        let Some(src) = send.src else {
            tracing::debug!("pim6: send with no pinned source dropped");
            continue;
        };
        let dst = send.dst;

        let mut buf = BytesMut::new();
        send.packet
            .emit(&mut buf, PimChecksumContext::Ipv6 { src, dst });

        let iov = [IoSlice::new(&buf)];
        let sockaddr: SockaddrIn6 = std::net::SocketAddrV6::new(dst, 0, 0, 0).into();
        // On send `ipi6_addr` pins the source the kernel emits, so the
        // pseudo-header checksum matches.
        let pktinfo = libc::in6_pktinfo {
            ipi6_addr: libc::in6_addr {
                s6_addr: src.octets(),
            },
            ipi6_ifindex: send.ifindex,
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
