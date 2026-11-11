//! The DHCPv6 client's socket: one UDP socket per interface, on port 546
//! and bound to the device (docs/design/dhcp-client.md D11).
//!
//! The device binding tells the sockets of several interfaces apart,
//! though they share the port, and puts the socket in the interface's
//! VRF. Every message goes to `ff02::1:2` on that interface; the kernel
//! sends it from the interface's link-local address, which is why the
//! task waits for one that is past DAD before it lets the client talk.
//! Replies come back to that address, unicast.
//!
//! A reader task hands what arrives to the event loop as an [`Input6`];
//! dropping the [`Socket6`] stops it and closes the socket. Sends happen
//! on the event loop and never block: a datagram that cannot go out now
//! is covered by the protocol's retransmission.

use std::io;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::Arc;
use std::time::Duration;

use dhcp_packet::v6::{ALL_DHCP_RELAY_AGENTS_AND_SERVERS, CLIENT_PORT, SERVER_PORT};
use socket2::{Domain, Protocol, SockRef, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::UnboundedSender;

use crate::context::Task;

/// Larger than any DHCPv6 message a server sends a client.
const RECV_BUF: usize = 9216;

/// A UDP datagram to the DHCPv6 client port of an interface, and its
/// source.
#[derive(Debug)]
pub struct Input6 {
    pub ifindex: u32,
    pub source: Ipv6Addr,
    pub payload: Vec<u8>,
}

pub struct Socket6 {
    socket: Arc<UdpSocket>,
    ifindex: u32,
    _task: Task<()>,
}

/// Open the DHCPv6 socket of `ifname` and start reading from it.
pub fn open(ifindex: u32, ifname: &str, tx: UnboundedSender<Input6>) -> io::Result<Socket6> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_only_v6(true)?;
    // One socket per interface, all on port 546.
    socket.set_reuse_address(true)?;
    socket.bind_device(Some(ifname.as_bytes()))?;
    socket.bind(&SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, CLIENT_PORT, 0, 0).into())?;
    socket.set_nonblocking(true)?;
    let socket = Arc::new(UdpSocket::from_std(socket.into())?);
    let reader = socket.clone();
    let task = Task::spawn(async move {
        let mut buf = vec![0u8; RECV_BUF];
        loop {
            match reader.recv_from(&mut buf).await {
                Ok((n, SocketAddr::V6(from))) => {
                    let input = Input6 {
                        ifindex,
                        source: *from.ip(),
                        payload: buf[..n].to_vec(),
                    };
                    if tx.send(input).is_err() {
                        return;
                    }
                }
                Ok(_) => {}
                Err(_) => tokio::time::sleep(Duration::from_millis(200)).await,
            }
        }
    });
    Ok(Socket6 {
        socket,
        ifindex,
        _task: task,
    })
}

impl Socket6 {
    /// Send a DHCPv6 message to All_DHCP_Relay_Agents_and_Servers on the
    /// socket's interface. The scope id names the interface for the
    /// link-scoped destination; the kernel picks the source, a link-local
    /// address of that interface.
    pub fn send(&self, payload: &[u8]) -> io::Result<()> {
        let to = SocketAddrV6::new(
            ALL_DHCP_RELAY_AGENTS_AND_SERVERS,
            SERVER_PORT,
            0,
            self.ifindex,
        );
        // Straight to the socket: it is non-blocking, and tokio's own
        // send would wait for a readiness nobody polls.
        SockRef::from(&*self.socket)
            .send_to(payload, &to.into())
            .map(drop)
    }
}
