use std::io::{ErrorKind, IoSlice, IoSliceMut};
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use std::str::FromStr;
use std::sync::Arc;

use bytes::BytesMut;
use nix::sys::socket::{self, ControlMessageOwned, SockaddrIn};
use socket2::Socket;
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use crate::ospf::Message;

pub async fn read_packet(sock: Arc<AsyncFd<Socket>>, tx: UnboundedSender<Message>) {
    const IPV4_HEADER_LEN: usize = 20;

    let mut buf = [0u8; 1024 * 16];
    let mut iov = [IoSliceMut::new(&mut buf)];
    let mut cmsgspace = nix::cmsg_space!(libc::in_pktinfo);

    loop {
        sock.async_io(Interest::READABLE, |sock| {
            let msg = socket::recvmsg::<SockaddrIn>(
                sock.as_raw_fd(),
                &mut iov,
                Some(&mut cmsgspace),
                socket::MsgFlags::empty(),
            )?;

            println!("XXX mesage recv");

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

            let Ok(packet) = ospf_packet::parse(&input[IPV4_HEADER_LEN..]) else {
                return Err(ErrorKind::UnexpectedEof.into());
            };

            println!(
                "Read: type {} src {} ifaddr {} ifindex {} dest {}",
                packet.1.typ,
                src.ip(),
                group,
                ifindex,
                ifaddr
            );

            tx.send(Message::Recv(packet.1, src.ip(), group, ifindex, ifaddr))
                .unwrap();

            Ok(())
        })
        .await;
    }
}

pub async fn write_packet(sock: Arc<AsyncFd<Socket>>, mut rx: UnboundedReceiver<Message>) {
    loop {
        let msg = rx.recv().await;
        let Message::Send(packet, ifindex, dest) = msg.unwrap() else {
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
        let pktinfo = libc::in_pktinfo {
            ipi_ifindex: ifindex as i32,
            ipi_spec_dst: libc::in_addr { s_addr: 0 },
            ipi_addr: libc::in_addr { s_addr: 0 },
        };
        let cmsg = [socket::ControlMessage::Ipv4PacketInfo(&pktinfo)];

        sock.async_io(Interest::WRITABLE, |sock| {
            socket::sendmsg(
                sock.as_raw_fd(),
                &iov,
                &cmsg,
                socket::MsgFlags::empty(),
                Some(&sockaddr),
            )
            .unwrap();
            Ok(())
        })
        .await;
    }
}
