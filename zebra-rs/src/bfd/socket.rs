use std::net::{SocketAddrV4, SocketAddrV6};
use std::os::fd::AsRawFd;
use std::os::raw::c_int;

use socket2::{Domain, Socket};

use crate::context::ProtoContext;

/// IANA-assigned UDP port for BFD single-hop control packets (RFC 5881 §4).
pub const BFD_SINGLE_HOP_PORT: u16 = 3784;

/// IANA-assigned UDP port for BFD multihop control packets (RFC 5883 §5).
pub const BFD_MULTI_HOP_PORT: u16 = 4784;

/// Default minimum accepted received TTL for a multihop session
/// (RFC 5883). Single-hop sessions ignore this and require TTL=255
/// unconditionally (GTSM, RFC 5881 §5). Matches FRR's `minimum-ttl`
/// default and the equivalent IOS-XR `bfd multihop ttl-drop-threshold`.
pub const BFD_MULTIHOP_DEFAULT_MIN_TTL: u8 = 254;

/// Build an IPv4 UDP socket suitable for sending and receiving BFD
/// control packets. Used for both the single-hop listener (3784) and
/// the multihop listener (4784); the per-session TTL policy is enforced
/// after demux, not on this socket.
///
/// The socket is configured to:
///   * send with IP TTL = 255 (RFC 5881 §5, GTSM on egress);
///   * report the received TTL via `IP_RECVTTL` ancillary data so the
///     receive path can enforce GTSM on ingress;
///   * report the destination address and ingress ifindex via
///     `IP_PKTINFO` so multi-address hosts can demultiplex sessions.
///
/// The initial socket comes from the `ProtoContext` factory —
/// that's where `SO_BINDTODEVICE` is applied via the VRF-aware
/// branch in `maybe_bind_device`. `bind` controls the local socket
/// address. Production callers pass `(0.0.0.0, BFD_SINGLE_HOP_PORT)`;
/// tests can pass an ephemeral port.
pub fn bfd_socket_ipv4(ctx: &ProtoContext, bind: SocketAddrV4) -> std::io::Result<Socket> {
    let socket = ctx.udp_socket_unbound(Domain::IPV4)?;

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

/// Build an IPv6 UDP socket for BFD control packets. RFC 5881 §4 /
/// RFC 5883 §5 use the same well-known ports on the v6 transport, so
/// this is bound with `IPV6_V6ONLY` to avoid shadowing the v4 socket
/// on the same port. Mirrors [`bfd_socket_ipv4`]:
///   * send with Hop Limit = 255 (GTSM on egress);
///   * report the received Hop Limit via `IPV6_RECVHOPLIMIT` so the
///     receive path can enforce GTSM after demux;
///   * report destination + ingress ifindex via `IPV6_RECVPKTINFO`
///     so link-local sessions (which overlap across interfaces) can be
///     demultiplexed by `(remote, ifindex)`.
pub fn bfd_socket_ipv6(ctx: &ProtoContext, bind: SocketAddrV6) -> std::io::Result<Socket> {
    let socket = ctx.udp_socket_unbound(Domain::IPV6)?;

    socket.set_nonblocking(true)?;
    socket.set_reuse_address(true)?;
    socket.set_only_v6(true)?;
    socket.set_unicast_hops_v6(255)?; // GTSM: every outgoing packet leaves with Hop Limit=255
    set_ipv6_recvhoplimit(&socket)?;
    set_ipv6_recvpktinfo(&socket)?;

    socket.bind(&bind.into())?;
    Ok(socket)
}

fn set_ipv6_recvhoplimit(socket: &Socket) -> std::io::Result<()> {
    let on: c_int = 1;
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IPV6,
            libc::IPV6_RECVHOPLIMIT,
            &on as *const _ as *const libc::c_void,
            std::mem::size_of::<c_int>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn set_ipv6_recvpktinfo(socket: &Socket) -> std::io::Result<()> {
    let on: c_int = 1;
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IPV6,
            libc::IPV6_RECVPKTINFO,
            &on as *const _ as *const libc::c_void,
            std::mem::size_of::<c_int>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
