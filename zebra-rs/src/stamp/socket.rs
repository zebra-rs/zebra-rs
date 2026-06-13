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
//! Both also enable software RX `SO_TIMESTAMPING` (Phase 1.5 rung 1) so
//! the receive timestamps (T2 / T4) come from the kernel network stack
//! rather than a post-wakeup userspace read — see
//! [`set_so_timestamping_rx`].
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
    // Phase 1.5 rung 1: kernel-stamp the probe receive (T2) so the
    // reflector residence we report to peers excludes our RX scheduling
    // latency. Non-fatal — falls back to the userspace stamp.
    set_so_timestamping_rx(&socket);

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
    // Phase 1.5 rung 1: kernel-stamp the reply receive (T4) so our own
    // delay math excludes the daemon RX scheduling tail (the `d` term
    // in the offload-notes §9b.1 error budget). Non-fatal.
    set_so_timestamping_rx(&socket);

    socket.bind(&local.into())?;
    socket.connect(&remote.into())?;
    Ok(socket)
}

/// Enable software RX timestamping (`SO_TIMESTAMPING` with
/// `RX_SOFTWARE | SOFTWARE`) so the kernel attaches a CLOCK_REALTIME
/// receive stamp as an `SCM_TIMESTAMPING` ancillary message — read back
/// in [`crate::stamp::network`] as T2 (reflector) / T4 (sender).
///
/// Software stamps are taken in the kernel network stack at skb
/// receive, so they work on every interface including veth/loopback
/// (unlike hardware stamps). Best-effort: a kernel that rejects the
/// option just leaves the receive path on the userspace `now_ntp()`
/// fallback (offload-notes §9b.3 rung 0), so a failure is logged at
/// debug and swallowed rather than propagated.
fn set_so_timestamping_rx(socket: &Socket) {
    let flags: libc::c_uint = libc::SOF_TIMESTAMPING_RX_SOFTWARE | libc::SOF_TIMESTAMPING_SOFTWARE;
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_TIMESTAMPING,
            &flags as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        tracing::debug!(
            error = %std::io::Error::last_os_error(),
            "stamp: SO_TIMESTAMPING unavailable; receive path uses userspace timestamps",
        );
    }
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
