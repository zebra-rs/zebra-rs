//! Async read / write tasks for the ND raw socket.
//!
//! Mirrors the OSPF `read_packet` / `write_packet` shape in
//! `crate::ospf::network` so the runtime wiring (channels, cmsg
//! plumbing, `AsyncFd::async_io`) is familiar.
//!
//! Inbound packets are filtered to ICMPv6 RA + RS by the kernel
//! (`ICMP6_FILTER` was set in [`super::socket::nd_socket`]); we add
//! one more application-layer check here: drop anything whose
//! IPv6 hop limit isn't 255, per RFC 4861 §6.1.2. The kernel can't
//! enforce that on raw sockets, so it's our job.
#![allow(dead_code)]

use std::io::{ErrorKind, IoSlice, IoSliceMut};
use std::net::Ipv6Addr;
use std::os::fd::AsRawFd;
use std::sync::Arc;

use bytes::BytesMut;
use nd_packet::{Icmp6Type, RouterAdvert, RouterSolicit};
use nix::sys::socket::{self, ControlMessageOwned, SockaddrIn6};
use socket2::Socket;
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use super::{NdRecv, NdSend};

/// Hop limit required by RFC 4861 §6.1.2 — anything else is dropped.
const REQUIRED_HOP_LIMIT: i32 = 255;

/// All-routers multicast address (RFC 4291 §2.7.1).
const ALL_ROUTERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x2);

/// Read loop: parse ICMPv6 packets off the raw socket, deliver
/// [`NdRecv`] messages on `tx`. Drops malformed packets and packets
/// failing the hop-limit-255 check silently — both situations are
/// "MUST silently discard" in RFC 4861.
pub async fn read_packet(sock: Arc<AsyncFd<Socket>>, tx: UnboundedSender<NdRecv>) {
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

                let Some(src_sa) = msg.address else {
                    return Err(ErrorKind::AddrNotAvailable.into());
                };
                let src: Ipv6Addr = src_sa.ip();

                let mut ifindex: Option<u32> = None;
                let mut hop_limit: Option<i32> = None;
                for cm in msg.cmsgs()? {
                    match cm {
                        ControlMessageOwned::Ipv6PacketInfo(info) => {
                            ifindex = Some(info.ipi6_ifindex);
                        }
                        ControlMessageOwned::Ipv6HopLimit(hl) => {
                            hop_limit = Some(hl);
                        }
                        _ => {}
                    }
                }
                let (Some(ifindex), Some(hop_limit)) = (ifindex, hop_limit) else {
                    return Err(ErrorKind::InvalidData.into());
                };
                if hop_limit != REQUIRED_HOP_LIMIT {
                    // RFC 4861 §6.1.2: silently drop.
                    return Ok(());
                }

                let Some(payload) = msg.iovs().next() else {
                    return Err(ErrorKind::UnexpectedEof.into());
                };
                if payload.is_empty() {
                    return Ok(());
                }

                let parsed = match Icmp6Type::from_u8(payload[0]) {
                    Some(Icmp6Type::RouterAdvert) => match RouterAdvert::parse(payload, None) {
                        Ok(ra) => NdRecv::RouterAdvert { ifindex, src, ra },
                        Err(_) => return Ok(()),
                    },
                    Some(Icmp6Type::RouterSolicit) => match RouterSolicit::parse(payload, None) {
                        Ok(rs) => NdRecv::RouterSolicit { ifindex, src, rs },
                        Err(_) => return Ok(()),
                    },
                    None => return Ok(()),
                };

                // If the parent task drops the receiver, the read task
                // should exit rather than spin — but a SendError doesn't
                // surface here. Caller is expected to keep tx alive for
                // the socket's lifetime.
                let _ = tx.send(parsed);
                Ok(())
            })
            .await;
    }
}

/// Write loop: serialize [`NdSend`] messages and emit them via
/// sendmsg with an `IPV6_PKTINFO` cmsg pinning the egress ifindex.
/// The ICMPv6 checksum is computed by the kernel (we set
/// `IPV6_CHECKSUM = 2` on socket bring-up).
pub async fn write_packet(sock: Arc<AsyncFd<Socket>>, mut rx: UnboundedReceiver<NdSend>) {
    while let Some(msg) = rx.recv().await {
        let (ifindex, dst, payload) = match msg {
            NdSend::RouterAdvert { ifindex, dst, ra } => {
                let mut buf = BytesMut::new();
                ra.emit_without_checksum(&mut buf);
                (ifindex, dst, buf)
            }
            NdSend::RouterSolicit { ifindex, rs } => {
                let mut buf = BytesMut::new();
                rs.emit_without_checksum(&mut buf);
                (ifindex, ALL_ROUTERS, buf)
            }
        };

        let iov = [IoSlice::new(&payload)];
        let sockaddr: SockaddrIn6 = std::net::SocketAddrV6::new(dst, 0, 0, ifindex).into();
        let pktinfo = libc::in6_pktinfo {
            ipi6_addr: libc::in6_addr { s6_addr: [0u8; 16] },
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
