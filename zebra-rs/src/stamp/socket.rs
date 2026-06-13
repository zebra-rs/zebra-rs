//! STAMP UDP socket construction.
//!
//! Two socket shapes, both IPv4 (Phase 1):
//!
//!   * one wildcard **reflector** socket per instance, normally bound
//!     to `0.0.0.0:862`, with `IP_RECVTTL` + `IP_PKTINFO` so replies
//!     can be stamped with the probed address as source and pinned to
//!     the ingress interface — a copy of `bfd_socket_ipv4`;
//!   * one **connected sender** socket per session, bound to the link
//!     address with an ephemeral port and `connect()`ed to the
//!     reflector — the kernel then does reply demux per 4-tuple, so no
//!     SSID-based global demux is needed.
//!
//! Egress TTL is 255 on both: probes between direct IGP neighbors
//! should arrive with TTL 255, and the received TTL is surfaced for
//! `show stamp` (a GTSM-style floor is *not* enforced in Phase 1 — the
//! reflector allow-list is the admission gate).

use std::net::SocketAddrV4;
use std::os::fd::AsRawFd;
use std::os::raw::c_int;

use socket2::{Domain, Socket};

use crate::context::ProtoContext;

/// Build the wildcard reflector socket. Mirrors
/// [`crate::bfd::socket::bfd_socket_ipv4`]; see the module docs for the
/// option rationale. Production callers pass `(0.0.0.0, 862)`; tests an
/// ephemeral loopback port.
pub fn stamp_reflector_socket(ctx: &ProtoContext, bind: SocketAddrV4) -> std::io::Result<Socket> {
    let socket = ctx.udp_socket_unbound(Domain::IPV4)?;

    socket.set_nonblocking(true)?;
    socket.set_reuse_address(true)?;
    socket.set_ttl_v4(255)?;
    set_ipv4_recvttl(&socket)?;
    set_ipv4_pktinfo(&socket)?;

    socket.bind(&bind.into())?;
    Ok(socket)
}

/// Build one session's connected sender socket: bound to the link
/// address (ephemeral port), connected to the reflector. After
/// `connect()` the kernel delivers only datagrams from exactly
/// `remote` to this socket and `send()` needs no address.
pub fn stamp_sender_socket(
    ctx: &ProtoContext,
    local: SocketAddrV4,
    remote: SocketAddrV4,
) -> std::io::Result<Socket> {
    let socket = ctx.udp_socket_unbound(Domain::IPV4)?;

    socket.set_nonblocking(true)?;
    socket.set_ttl_v4(255)?;

    socket.bind(&local.into())?;
    socket.connect(&remote.into())?;
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
