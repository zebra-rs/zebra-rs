//! The DHCPv4 client's sockets.
//!
//! - A **packet socket** (`AF_PACKET`, `SOCK_DGRAM`, IPv4) carries DHCP
//!   while the interface has no address to send from or be reached at:
//!   the kernel would not deliver a reply addressed to an address it does
//!   not hold yet, so the client reads IPv4 off the wire itself, behind a
//!   BPF filter that passes only UDP to port 68.
//! - A second packet socket (ARP) probes a new address before it is used.
//! - A **UDP socket**, bound to the interface, carries renewals once the
//!   address is installed: unicast to the server, broadcast when
//!   rebinding, each message sent from the leased address.
//!
//! Each open socket has a reader task that hands what it receives to the
//! event loop as an [`Input`]; dropping the [`Reader`] stops it and closes
//! the socket. Sends happen on the event loop and never block: a datagram
//! that cannot go out now is covered by the protocol's retransmission.

use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::Arc;
use std::time::Duration;

use dhcp_packet::v4::{CLIENT_PORT, SERVER_PORT};
use socket2::{Domain, Protocol, SockFilter, Socket, Type};
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::UnboundedSender;

use super::frame::{self, Arp};
use crate::async_fd;
use crate::context::Task;

const BROADCAST_MAC: [u8; 6] = [0xff; 6];

/// Larger than any DHCP message we ask for (option 57 is the MTU).
const RECV_BUF: usize = 9216;

/// What a reader task received on an interface.
#[derive(Debug)]
pub enum Input {
    /// A UDP datagram to the DHCP client port, and its IP source.
    Dhcp {
        ifindex: u32,
        source: Ipv4Addr,
        payload: Vec<u8>,
    },
    Arp {
        ifindex: u32,
        arp: Arp,
    },
}

/// IPv4, UDP, not a fragment, destination port 68. The offsets count
/// from the IP header: that is where an incoming frame starts for a
/// `SOCK_DGRAM` packet socket.
const DHCP_FILTER: [SockFilter; 9] = [
    // ldb [9]                 ; protocol
    SockFilter::new(0x30, 0, 0, 9),
    // jeq #17, next, drop
    SockFilter::new(0x15, 0, 6, 17),
    // ldh [6]                 ; flags and fragment offset
    SockFilter::new(0x28, 0, 0, 6),
    // jset #0x3fff, drop, next
    SockFilter::new(0x45, 4, 0, 0x3fff),
    // ldxb 4*([0]&0xf)        ; IP header length
    SockFilter::new(0xb1, 0, 0, 0),
    // ldh [x + 2]             ; UDP destination port
    SockFilter::new(0x48, 0, 0, 2),
    // jeq #68, accept, drop
    SockFilter::new(0x15, 0, 1, CLIENT_PORT as u32),
    // ret #0x40000
    SockFilter::new(0x06, 0, 0, 0x0004_0000),
    // ret #0
    SockFilter::new(0x06, 0, 0, 0),
];

fn sockaddr_ll(protocol: u16, ifindex: u32, mac: Option<[u8; 6]>) -> libc::sockaddr_ll {
    let mut sll = libc::sockaddr_ll {
        sll_family: libc::AF_PACKET as u16,
        sll_protocol: protocol.to_be(),
        sll_ifindex: ifindex as i32,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 0,
        sll_addr: [0; 8],
    };
    if let Some(mac) = mac {
        sll.sll_halen = 6;
        sll.sll_addr[..6].copy_from_slice(&mac);
    }
    sll
}

/// A packet socket for `protocol` (an EtherType) on `ifindex`.
fn packet_socket(protocol: u16, ifindex: u32, filter: Option<&[SockFilter]>) -> io::Result<Socket> {
    // Protocol 0, then the filter, then bind: an unbound protocol-0
    // socket is delivered nothing, so no frame queues ahead of the filter
    // (the same order as `isis_socket`).
    let socket = Socket::new(Domain::PACKET, Type::DGRAM, None)?;
    socket.set_nonblocking(true)?;
    if let Some(filter) = filter {
        socket.attach_filter(filter)?;
    }
    // Ask for each frame's status, to learn whether its checksum is
    // still to be computed (see `frame::parse_udp`).
    let one: libc::c_int = 1;
    // SAFETY: `one` outlives the call and its size is passed.
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_PACKET,
            libc::PACKET_AUXDATA,
            (&raw const one).cast(),
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    let sll = sockaddr_ll(protocol, ifindex, None);
    // SAFETY: `sll` is a valid sockaddr_ll and its size is passed.
    let rc = unsafe {
        libc::bind(
            socket.as_raw_fd(),
            (&raw const sll).cast(),
            size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(socket)
}

/// Receive one frame, and whether its transport checksum is already
/// computed (false while `TP_STATUS_CSUMNOTREADY` is set).
fn recv_frame(fd: RawFd, buf: &mut [u8]) -> io::Result<(usize, bool)> {
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    // Room for one tpacket_auxdata control message, aligned as cmsghdr.
    let mut control = [0u64; 8];
    // SAFETY: an all-zero msghdr is a valid one.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = size_of_val(&control) as _;
    // SAFETY: `msg` points at `iov` and `control`, both alive and sized
    // as stated, for the duration of the call.
    let n = unsafe { libc::recvmsg(fd, &raw mut msg, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut checksum_ready = true;
    // SAFETY: the kernel filled `msg`'s control area; the CMSG macros
    // walk it within `msg_controllen`, and a PACKET_AUXDATA message
    // carries a tpacket_auxdata.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&raw const msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_PACKET && (*cmsg).cmsg_type == libc::PACKET_AUXDATA {
                let aux: libc::tpacket_auxdata =
                    std::ptr::read_unaligned(libc::CMSG_DATA(cmsg).cast());
                checksum_ready = aux.tp_status & libc::TP_STATUS_CSUMNOTREADY == 0;
            }
            cmsg = libc::CMSG_NXTHDR(&raw const msg, cmsg);
        }
    }
    Ok((n as usize, checksum_ready))
}

/// Send `frame` to the broadcast address of `ifindex`.
fn send_broadcast(fd: RawFd, protocol: u16, ifindex: u32, frame: &[u8]) -> io::Result<()> {
    let sll = sockaddr_ll(protocol, ifindex, Some(BROADCAST_MAC));
    // SAFETY: `frame` and `sll` are valid for the stated lengths.
    let n = unsafe {
        libc::sendto(
            fd,
            frame.as_ptr().cast(),
            frame.len(),
            0,
            (&raw const sll).cast(),
            size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// An open socket with its reader task; dropping it stops the reader and
/// closes the socket.
pub struct Reader<S> {
    socket: Arc<S>,
    _task: Task<()>,
}

/// The packet socket DHCP uses before the interface has the address.
pub type PacketReader = Reader<AsyncFd<Socket>>;

pub fn open_packet(ifindex: u32, tx: UnboundedSender<Input>) -> io::Result<PacketReader> {
    let socket = packet_socket(libc::ETH_P_IP as u16, ifindex, Some(&DHCP_FILTER))?;
    let socket = Arc::new(async_fd::register(socket)?);
    let reader = socket.clone();
    let task = Task::spawn(async move {
        let mut buf = vec![0u8; RECV_BUF];
        loop {
            let received = reader
                .async_io(Interest::READABLE, |s| recv_frame(s.as_raw_fd(), &mut buf))
                .await;
            match received {
                Ok((n, checksum_ready)) => {
                    let Some(udp) = frame::parse_udp(&buf[..n], checksum_ready) else {
                        continue;
                    };
                    if udp.destination_port != CLIENT_PORT {
                        continue;
                    }
                    let input = Input::Dhcp {
                        ifindex,
                        source: udp.source,
                        payload: udp.payload.to_vec(),
                    };
                    if tx.send(input).is_err() {
                        return;
                    }
                }
                // The interface going down (ENETDOWN) must not spin.
                Err(_) => tokio::time::sleep(Duration::from_millis(200)).await,
            }
        }
    });
    Ok(Reader {
        socket,
        _task: task,
    })
}

impl PacketReader {
    /// Broadcast a DHCP message from `0.0.0.0`.
    pub fn broadcast_dhcp(&self, ifindex: u32, payload: &[u8]) -> io::Result<()> {
        let datagram = frame::udp_datagram(
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
            CLIENT_PORT,
            SERVER_PORT,
            payload,
        );
        send_broadcast(
            self.socket.as_raw_fd(),
            libc::ETH_P_IP as u16,
            ifindex,
            &datagram,
        )
    }
}

/// The ARP socket of address conflict detection.
pub struct ArpReader(Reader<AsyncFd<Socket>>);

pub fn open_arp(ifindex: u32, tx: UnboundedSender<Input>) -> io::Result<ArpReader> {
    let socket = packet_socket(libc::ETH_P_ARP as u16, ifindex, None)?;
    let socket = Arc::new(async_fd::register(socket)?);
    let reader = socket.clone();
    let task = Task::spawn(async move {
        let mut buf = [0u8; 64];
        loop {
            let received = reader
                .async_io(Interest::READABLE, |s| recv_frame(s.as_raw_fd(), &mut buf))
                .await;
            match received {
                Ok((n, _)) => {
                    if let Some(arp) = Arp::parse(&buf[..n])
                        && tx.send(Input::Arp { ifindex, arp }).is_err()
                    {
                        return;
                    }
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(200)).await,
            }
        }
    });
    Ok(ArpReader(Reader {
        socket,
        _task: task,
    }))
}

impl ArpReader {
    pub fn probe(&self, ifindex: u32, mac: [u8; 6], target: Ipv4Addr) -> io::Result<()> {
        send_broadcast(
            self.0.socket.as_raw_fd(),
            libc::ETH_P_ARP as u16,
            ifindex,
            &Arp::probe(mac, target).emit(),
        )
    }
}

/// The UDP socket of a held lease.
pub type UdpReader = Reader<UdpSocket>;

/// A UDP socket on `ifname` for a held lease.
///
/// It is bound to `0.0.0.0`, not to the leased address, because a server
/// broadcasts a DHCPNAK (RFC 2131 §4.1, when `giaddr` is zero) and a
/// socket bound to a unicast address is not given broadcasts: the refusal
/// of a renewal would go unheard, and the client would keep using a lease
/// the server has taken back. Which address a message leaves from is
/// said per message instead ([`UdpReader::send_dhcp`]).
pub fn open_udp(ifindex: u32, ifname: &str, tx: UnboundedSender<Input>) -> io::Result<UdpReader> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    // One socket per interface, all on port 68: the device binding tells
    // them apart, and puts route lookups in the interface's VRF.
    socket.set_reuse_address(true)?;
    socket.set_broadcast(true)?;
    socket.bind_device(Some(ifname.as_bytes()))?;
    socket.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, CLIENT_PORT).into())?;
    socket.set_nonblocking(true)?;
    let socket = Arc::new(UdpSocket::from_std(socket.into())?);
    let reader = socket.clone();
    let task = Task::spawn(async move {
        let mut buf = vec![0u8; RECV_BUF];
        loop {
            match reader.recv_from(&mut buf).await {
                Ok((n, std::net::SocketAddr::V4(from))) => {
                    let input = Input::Dhcp {
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
    Ok(Reader {
        socket,
        _task: task,
    })
}

/// Send `payload` to `destination`:67 from `source`, named with an
/// `IP_PKTINFO` control message (`ipi_spec_dst`). The interface comes
/// from the socket's device binding, so `ipi_ifindex` stays zero.
fn send_from(fd: RawFd, source: Ipv4Addr, destination: Ipv4Addr, payload: &[u8]) -> io::Result<()> {
    let in_addr = |address: Ipv4Addr| libc::in_addr {
        // `s_addr` is in network byte order: the octets as they are.
        s_addr: u32::from_ne_bytes(address.octets()),
    };
    // SAFETY: an all-zero sockaddr_in is a valid one.
    let mut to: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    to.sin_family = libc::AF_INET as libc::sa_family_t;
    to.sin_port = SERVER_PORT.to_be();
    to.sin_addr = in_addr(destination);
    let mut iov = libc::iovec {
        iov_base: payload.as_ptr().cast_mut().cast(),
        iov_len: payload.len(),
    };
    // Room for one in_pktinfo control message, aligned as cmsghdr.
    let mut control = [0u64; 8];
    let info = libc::in_pktinfo {
        ipi_ifindex: 0,
        ipi_spec_dst: in_addr(source),
        ipi_addr: in_addr(Ipv4Addr::UNSPECIFIED),
    };
    // SAFETY: an all-zero msghdr is a valid one.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = (&raw mut to).cast();
    msg.msg_namelen = size_of::<libc::sockaddr_in>() as libc::socklen_t;
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    // SAFETY: CMSG_SPACE only computes a size, and `control` (64 bytes)
    // holds the 32 a cmsghdr with an in_pktinfo takes.
    msg.msg_controllen = unsafe { libc::CMSG_SPACE(size_of::<libc::in_pktinfo>() as u32) } as _;
    // SAFETY: `msg` points at `to`, `iov` and `control`, all alive and
    // sized as stated; the one control message is written within
    // `msg_controllen`; sendmsg reads `payload` and does not write it.
    let n = unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&raw const msg);
        (*cmsg).cmsg_level = libc::IPPROTO_IP;
        (*cmsg).cmsg_type = libc::IP_PKTINFO;
        (*cmsg).cmsg_len = libc::CMSG_LEN(size_of::<libc::in_pktinfo>() as u32) as _;
        std::ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast(), info);
        libc::sendmsg(fd, &raw const msg, 0)
    };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Whether a datagram could leave `ifname` from `source` for
/// `destination` right now: `source` is an address of this host, and
/// there is a route. Nothing is sent.
///
/// A RELEASE is sent once and not answered, so it has to be sent when it
/// can go out. Right after a lease's address has been asked of the RIB it
/// cannot yet: the address is not on the interface (binding to it fails),
/// and neither is the connected route (connecting fails).
pub fn can_send_from(ifname: &str, source: Ipv4Addr, destination: Ipv4Addr) -> bool {
    let probe = || -> io::Result<()> {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        socket.bind_device(Some(ifname.as_bytes()))?;
        socket.bind(&SocketAddrV4::new(source, 0).into())?;
        socket.connect(&SocketAddrV4::new(destination, SERVER_PORT).into())
    };
    probe().is_ok()
}

impl UdpReader {
    /// Send a DHCP message to `destination` (the server, or
    /// `255.255.255.255`) from `source`, the leased address.
    ///
    /// The source is named because the kernel would otherwise pick the
    /// interface's primary address, and that is another one when the
    /// operator configured addresses beside the lease: a RENEW or RELEASE
    /// would carry a source that contradicts its `ciaddr`, which a server
    /// or a source-address filter may refuse.
    pub fn send_dhcp(
        &self,
        source: Ipv4Addr,
        destination: Ipv4Addr,
        payload: &[u8],
    ) -> io::Result<()> {
        send_from(self.socket.as_raw_fd(), source, destination, payload)
    }
}
