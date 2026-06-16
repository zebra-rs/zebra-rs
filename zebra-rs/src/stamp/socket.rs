//! STAMP UDP socket construction.
//!
//! Two socket shapes, each with an IPv4 and an IPv6 variant:
//!
//!   * one wildcard **reflector** socket per instance per family,
//!     normally bound to `0.0.0.0:862` / `[::]:862`, with the receive
//!     TTL/Hop-Limit and `PKTINFO` options so replies can be stamped
//!     with the probed address as source and pinned to the ingress
//!     interface — copies of `bfd_socket_ipv4` / `bfd_socket_ipv6`;
//!   * one **connected sender** socket per session, bound to the link
//!     address with an ephemeral port and `connect()`ed to the
//!     reflector — the kernel then does reply demux per 4-tuple, so no
//!     SSID-based global demux is needed. For IPv6 link-local the
//!     `SocketAddrV6` scope id (ifindex) makes the 4-tuple unambiguous
//!     across interfaces that share an `fe80::` address.
//!
//! All of them enable software RX `SO_TIMESTAMPING` (Phase 1.5 rung 1)
//! so the receive timestamps (T2 / T4) come from the kernel network
//! stack rather than a post-wakeup userspace read — see
//! [`set_so_timestamping_rx`].
//!
//! Egress TTL / Hop Limit is 255 on every socket: probes between direct
//! IGP neighbors should arrive with TTL 255, and the received value is
//! surfaced for `show stamp` (a GTSM-style floor is *not* enforced in
//! Phase 1 — the reflector allow-list is the admission gate).

use std::net::{SocketAddrV4, SocketAddrV6};
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

/// IPv6 reflector socket. The v6 twin of [`stamp_reflector_socket`],
/// modelled on [`crate::bfd::socket::bfd_socket_ipv6`]: bound
/// `IPV6_V6ONLY` so it does not shadow the v4 reflector on the same
/// port, with `IPV6_RECVHOPLIMIT` + `IPV6_RECVPKTINFO` so a reply can
/// be stamped with the probed link-local as source and pinned to the
/// ingress interface (`IPV6_PKTINFO`). Production callers pass
/// `([::], 862)`; tests an ephemeral loopback port.
pub fn stamp_reflector_socket_v6(
    ctx: &ProtoContext,
    bind: SocketAddrV6,
) -> std::io::Result<Socket> {
    let socket = ctx.udp_socket_unbound(Domain::IPV6)?;

    socket.set_nonblocking(true)?;
    socket.set_reuse_address(true)?;
    socket.set_only_v6(true)?;
    socket.set_unicast_hops_v6(255)?;
    set_ipv6_recvhoplimit(&socket)?;
    set_ipv6_recvpktinfo(&socket)?;
    // Phase 1.5 rung 1: kernel-stamp the probe receive (T2). Non-fatal.
    set_so_timestamping_rx(&socket);

    socket.bind(&bind.into())?;
    Ok(socket)
}

/// IPv6 connected sender socket. The v6 twin of
/// [`stamp_sender_socket`]. For link-local sessions both `local` and
/// `remote` must carry the interface scope id (ifindex) in their
/// `SocketAddrV6` — the scope rides through `bind`/`connect` into the
/// kernel's 4-tuple demux, so replies on overlapping `fe80::`
/// addresses land on the right session.
pub fn stamp_sender_socket_v6(
    ctx: &ProtoContext,
    local: SocketAddrV6,
    remote: SocketAddrV6,
) -> std::io::Result<Socket> {
    let socket = ctx.udp_socket_unbound(Domain::IPV6)?;

    socket.set_nonblocking(true)?;
    socket.set_unicast_hops_v6(255)?;
    // Phase 1.5 rung 1: kernel-stamp the reply receive (T4). Non-fatal.
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

#[cfg(test)]
mod tests {
    use std::net::{Ipv6Addr, SocketAddrV6};

    use super::*;
    use crate::context::ProtoContext;

    /// Step 1 of the STAMP IPv6 slice: both v6 socket builders succeed
    /// on the `::1` loopback. This pins the option set the kernel must
    /// accept — `IPV6_V6ONLY`, hop-limit 255, `IPV6_RECVHOPLIMIT` /
    /// `IPV6_RECVPKTINFO`, and software RX `SO_TIMESTAMPING` — and that
    /// a connected sender can be `bind`/`connect`ed to the reflector's
    /// ephemeral port. The v6 read/write/stamp paths are exercised in
    /// the `network` module (Step 2).
    #[tokio::test]
    async fn ipv6_sockets_build() {
        let ctx = ProtoContext::default_table_no_rib();

        let reflector =
            stamp_reflector_socket_v6(&ctx, SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0))
                .expect("v6 reflector socket builds");
        let port = reflector
            .local_addr()
            .unwrap()
            .as_socket_ipv6()
            .unwrap()
            .port();

        // Loopback has no link scope, so scope id 0 is correct here; the
        // ifindex-scoped link-local path is covered by the BDD (Step 6).
        let local = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0);
        let remote = SocketAddrV6::new(Ipv6Addr::LOCALHOST, port, 0, 0);
        let _sender = stamp_sender_socket_v6(&ctx, local, remote).expect("v6 sender socket builds");
    }
}
