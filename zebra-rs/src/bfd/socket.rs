use std::net::SocketAddrV4;
use std::os::fd::AsRawFd;
use std::os::raw::c_int;

use socket2::{Domain, Protocol, Socket, Type};

/// IANA-assigned UDP port for BFD single-hop control packets (RFC 5881 §4).
pub const BFD_SINGLE_HOP_PORT: u16 = 3784;

/// Build an IPv4 UDP socket suitable for sending and receiving BFD
/// single-hop control packets.
///
/// The socket is configured to:
///   * send with IP TTL = 255 (RFC 5881 §5, GTSM on egress);
///   * report the received TTL via `IP_RECVTTL` ancillary data so the
///     receive path can enforce GTSM on ingress;
///   * report the destination address and ingress ifindex via
///     `IP_PKTINFO` so multi-address hosts can demultiplex sessions.
///
/// `bind` controls the local socket address. Production callers pass
/// `(0.0.0.0, BFD_SINGLE_HOP_PORT)`; tests can pass an ephemeral port.
pub fn bfd_socket_ipv4(bind: SocketAddrV4) -> std::io::Result<Socket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;

    socket.set_nonblocking(true)?;
    socket.set_reuse_address(true)?;
    socket.set_ttl_v4(255)?; // GTSM: every outgoing packet leaves with TTL=255
    set_ipv4_recvttl(&socket)?;
    set_ipv4_pktinfo(&socket)?;

    socket.bind(&bind.into())?;
    Ok(socket)
}

fn set_ipv4_recvttl(socket: &Socket) -> std::io::Result<()> {
    let on: c_int = 1;
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_RECVTTL,
            &on as *const _ as *const libc::c_void,
            std::mem::size_of::<c_int>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn set_ipv4_pktinfo(socket: &Socket) -> std::io::Result<()> {
    let on: c_int = 1;
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_PKTINFO,
            &on as *const _ as *const libc::c_void,
            std::mem::size_of::<c_int>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
