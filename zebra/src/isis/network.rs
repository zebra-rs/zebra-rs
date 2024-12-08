use std::io::{ErrorKind, IoSliceMut};
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;

use nix::sys::socket::{self, ControlMessageOwned, SockaddrIn};
use socket2::Socket;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use tokio::sync::mpsc::UnboundedSender;

use crate::isis::Message;

pub async fn read_packet(sock: Socket, tx: UnboundedSender<Message>) {
    const IPV4_HEADER_LEN: usize = 20;

    let sock = AsyncFd::new(sock).unwrap();

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

            let mut cmsgs = msg.cmsgs()?;

            let Some(ControlMessageOwned::Ipv4PacketInfo(pktinfo)) = cmsgs.next() else {
                return Err(ErrorKind::AddrNotAvailable.into());
            };

            let dest: Ipv4Addr = Ipv4Addr::from(pktinfo.ipi_spec_dst.s_addr.to_be());
            let ifaddr: Ipv4Addr = Ipv4Addr::from(pktinfo.ipi_addr.s_addr.to_be());
            let ifindex = pktinfo.ipi_ifindex as u32;

            let Some(input) = msg.iovs().next() else {
                return Err(ErrorKind::UnexpectedEof.into());
            };

            let Ok(packet) = ospf_packet::parse(&input[IPV4_HEADER_LEN..]) else {
                return Err(ErrorKind::UnexpectedEof.into());
            };

            // tx.send(Message::Packet(packet.1, ifaddr, ifindex, dest))
            //     .unwrap();

            Ok(())
        })
        .await;
    }
}
