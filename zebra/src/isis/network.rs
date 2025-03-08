use std::io::{ErrorKind, IoSliceMut};
use std::os::fd::AsRawFd;

use nix::sys::socket::{self, LinkAddr};
use socket2::Socket;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use crate::isis::Message;

pub async fn read_packet(sock: Socket, tx: UnboundedSender<Message>) {
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

            tx.send(Message::Recv(packet.1, addr.ifindex() as u32))
                .unwrap();

            Ok(())
        })
        .await;
    }
}

pub async fn write_packet(sock: Socket, mut rx: UnboundedReceiver<Message>) {
    loop {
        let msg = rx.recv().await;
    }
}
