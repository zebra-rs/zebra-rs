use std::io::{ErrorKind, IoSlice, IoSliceMut};
use std::os::fd::AsRawFd;
use std::sync::Arc;

use anyhow::Context;
use bytes::BytesMut;
use nix::sys::socket::{self, LinkAddr};
use socket2::Socket;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use crate::rib::MacAddr;

use super::inst::{Packet, PacketMessage};
use super::socket::link_addr;
use super::{Level, Message};

pub async fn read_packet(sock: Arc<AsyncFd<Socket>>, tx: UnboundedSender<Message>) {
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

            if packet.1.pdu_type.is_lsp() {
                if !isis_packet::is_valid_checksum(&input[3..]) {
                    return Err(ErrorKind::UnexpectedEof.into());
                }
            }

            let mac = addr.addr().map(MacAddr::from);

            let _ = tx.send(Message::Recv(packet.1, addr.ifindex() as u32, mac));
            Ok(())
        })
        .await;
    }
}

pub const LLC_HDR: [u8; 3] = [0xFE, 0xFE, 0x03];
pub const L1_ISS: [u8; 6] = [0x01, 0x80, 0xC2, 0x00, 0x00, 0x14];
pub const L2_ISS: [u8; 6] = [0x01, 0x80, 0xC2, 0x00, 0x00, 0x15];

pub async fn write_packet(sock: Arc<AsyncFd<Socket>>, mut rx: UnboundedReceiver<PacketMessage>) {
    loop {
        let msg = rx.recv().await;
        let PacketMessage::Send(packet, ifindex, level) = msg.unwrap();

        let buf = match packet {
            Packet::Packet(packet) => {
                let mut buf = BytesMut::new();
                packet.emit(&mut buf);
                buf
            }
            Packet::Bytes(buf) => buf,
        };

        let iov = [IoSlice::new(&LLC_HDR), IoSlice::new(&buf)];

        let iss = if level == Level::L1 { L1_ISS } else { L2_ISS };

        let sockaddr = link_addr((LLC_HDR.len() + buf.len()) as u16, ifindex, Some(iss));

        let res = sock
            .async_io(Interest::WRITABLE, |sock| {
                socket::sendmsg(
                    sock.as_raw_fd(),
                    &iov,
                    &[],
                    socket::MsgFlags::empty(),
                    Some(&sockaddr),
                )
                .map_err(|e| std::io::Error::from_raw_os_error(e as i32))
            })
            .await;
    }
}
