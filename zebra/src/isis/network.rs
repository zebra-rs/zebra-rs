use std::io::{ErrorKind, IoSlice, IoSliceMut};
use std::os::fd::AsRawFd;
use std::sync::Arc;

use bytes::BytesMut;
use nix::sys::socket::{self, LinkAddr};
use socket2::Socket;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use super::socket::link_addr;
use super::Message;

pub async fn read_packet(sock: Arc<AsyncFd<Socket>>, tx: UnboundedSender<Message>) {
    let sock = AsyncFd::new(sock).unwrap();

    let mut buf = [0u8; 1024 * 16];
    let mut iov = [IoSliceMut::new(&mut buf)];

    loop {
        sock.async_io(Interest::READABLE, |sock| {
            let msg = socket::recvmsg::<LinkAddr>(
                sock.as_raw_fd(),
                &mut iov,
                None,
                socket::MsgFlags::empty(),
            )?;

            let Some(addr) = msg.address else {
                return Err(ErrorKind::UnexpectedEof.into());
            };

            let Some(input) = msg.iovs().next() else {
                return Err(ErrorKind::UnexpectedEof.into());
            };

            let Ok(packet) = isis_packet::parse(&input[3..]) else {
                return Err(ErrorKind::UnexpectedEof.into());
            };

            let mac = addr.addr();

            tx.send(Message::Recv(packet.1, addr.ifindex() as u32, mac))
                .unwrap();

            Ok(())
        })
        .await;
    }
}

pub const LLC_HDR: [u8; 3] = [0xFE, 0xFE, 0x03];

pub async fn write_packet(sock: Arc<AsyncFd<Socket>>, mut rx: UnboundedReceiver<Message>) {
    loop {
        let msg = rx.recv().await;
        let Message::Send(packet, ifindex) = msg.unwrap() else {
            continue;
        };

        let mut buf = BytesMut::new();
        packet.emit(&mut buf);

        let iov = [IoSlice::new(&LLC_HDR), IoSlice::new(&buf)];
        let l2iss = [0x01, 0x80, 0xC2, 0x00, 0x00, 0x15];

        let mut sockaddr = link_addr((LLC_HDR.len() + buf.len()) as u16, ifindex, Some(l2iss));

        sock.async_io(Interest::WRITABLE, |sock| {
            let msg = socket::sendmsg(
                sock.as_raw_fd(),
                &iov,
                &[],
                socket::MsgFlags::empty(),
                Some(&sockaddr),
            );
            Ok(())
        })
        .await;
    }
}
