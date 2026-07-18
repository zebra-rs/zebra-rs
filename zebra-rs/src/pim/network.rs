//! Socket read / write tasks. `read_packet` turns received PIM
//! messages into [`Message::Recv`] events for the actor;
//! `write_packet` drains [`PimSend`] and transmits with the egress
//! interface pinned via `IP_PKTINFO`. Mirrors `crate::ospf::network`.

use std::io::{ErrorKind, IoSlice, IoSliceMut};
use std::net::SocketAddrV4;
use std::os::fd::AsRawFd;
use std::sync::Arc;

use bytes::BytesMut;
use nix::sys::socket::{self, ControlMessageOwned, SockaddrIn};
use pim_packet::{PimPacket, pim_verify_checksum};
use socket2::Socket;
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use super::inst::{Message, PimSend};

pub async fn read_packet(sock: Arc<AsyncFd<Socket>>, tx: UnboundedSender<Message>) {
    let mut buf = [0u8; 1024 * 16];
    let mut iov = [IoSliceMut::new(&mut buf)];
    let mut cmsgspace = nix::cmsg_space!(libc::in_pktinfo);

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

                let ifindex = pktinfo.ipi_ifindex as u32;

                let Some(input) = msg.iovs().next() else {
                    return Err(ErrorKind::UnexpectedEof.into());
                };

                // A raw IPv4 socket delivers the full IP header; PIM
                // packets commonly carry IP options (Router Alert),
                // so honor the IHL instead of assuming 20 bytes.
                if input.is_empty() {
                    return Err(ErrorKind::UnexpectedEof.into());
                }
                let ihl = ((input[0] & 0x0f) as usize) * 4;
                if ihl < 20 || input.len() <= ihl {
                    return Err(ErrorKind::InvalidData.into());
                }
                let pim_input = &input[ihl..];

                if !pim_verify_checksum(pim_input) {
                    tracing::debug!("pim: bad checksum from {} on ifindex {ifindex}", src.ip());
                    return Err(ErrorKind::InvalidData.into());
                }
                let Ok((_, packet)) = PimPacket::parse_be(pim_input) else {
                    tracing::debug!(
                        "pim: malformed packet from {} on ifindex {ifindex}",
                        src.ip()
                    );
                    return Err(ErrorKind::InvalidData.into());
                };

                let _ = tx.send(Message::Recv {
                    packet,
                    src: src.ip(),
                    ifindex,
                });

                Ok(())
            })
            .await;
        // The actor owns the receiver; once the instance is torn down
        // the channel closes and this task exits.
        if tx.is_closed() {
            return;
        }
    }
}

pub async fn write_packet(sock: Arc<AsyncFd<Socket>>, mut rx: UnboundedReceiver<PimSend>) {
    while let Some(send) = rx.recv().await {
        let mut buf = BytesMut::new();
        send.packet.emit(&mut buf);

        let iov = [IoSlice::new(&buf)];
        let sockaddr: SockaddrIn = SocketAddrV4::new(send.dst, 0).into();
        let pktinfo = libc::in_pktinfo {
            ipi_ifindex: send.ifindex as i32,
            ipi_spec_dst: libc::in_addr { s_addr: 0 },
            ipi_addr: libc::in_addr { s_addr: 0 },
        };
        let cmsg = [socket::ControlMessage::Ipv4PacketInfo(&pktinfo)];

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
