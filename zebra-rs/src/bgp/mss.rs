// BGP per-session TCP Maximum Segment Size (MSS).
//
// `tcp-mss <1-65535>` caps the MSS advertised on a neighbor's TCP
// connection (`setsockopt(TCP_MAXSEG)`), which bounds the size of every
// BGP segment the peer sends us. Operators use it to keep BGP traffic
// under a path MTU that is smaller than the interface MTU — a tunnel,
// an MPLS core, or a link that cannot carry full-size frames — so the
// session does not stall on a black-holed large UPDATE.
//
// Linux subtlety that dictates *where* the option is applied: the value
// must be set on the socket **before** the TCP handshake, because
// `getsockopt(TCP_MAXSEG)` on an established socket returns the cached,
// already-negotiated MSS (`tp->mss_cache`) and a late `setsockopt` no
// longer changes it. So zebra-rs sets it on:
//   - the active connect socket, before `connect(2)` (so our SYN
//     advertises the reduced MSS) — see `peer::peer_connect`;
//   - the *listening* socket, so a passively-accepted child inherits the
//     clamp on its SYN-ACK — see `config::apply_tcp_mss_refresh_all`.
// The listener carries a single value (one socket, many peers), so the
// reconciler installs the **minimum** `tcp-mss` across the configured
// peers of that address family, mirroring FRR's `bgp_tcp_mss_set`.
//
// The "synced" MSS shown by `show bgp neighbor` is this negotiated
// `tp->mss_cache` read back with [`get_tcp_mss`] once the session is up;
// it is typically a little below the configured value (the kernel
// subtracts the per-segment TCP options, e.g. 12 bytes for timestamps),
// and it can legitimately differ from the configured value when the
// change has not yet been applied to the live socket (a session reset is
// needed) — exactly the FRR semantics.
//
// Linux-primary, matching `ttl.rs` / `bfd/socket.rs`: the libc constants
// used here are Linux's and the daemon is built for Linux.

use std::io;
use std::os::fd::RawFd;
use std::os::raw::c_int;

/// Set the TCP Maximum Segment Size (`TCP_MAXSEG`) on a BGP socket `fd`.
/// Apply it **before** the TCP handshake (active connect socket or
/// listener) — see the module comment. `mss` is the configured
/// `tcp-mss <1-65535>`.
pub fn set_tcp_mss(fd: RawFd, mss: u16) -> io::Result<()> {
    setsockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_MAXSEG, mss as c_int)
}

/// Read back the kernel's current TCP MSS (`getsockopt(TCP_MAXSEG)`) on
/// `fd`. On an established socket this is the negotiated `mss_cache` (the
/// "synced" value). Returns 0 only if the kernel reports a non-positive
/// value (e.g. a socket with no connection); the cast saturates a value
/// above `u16::MAX` down to it (TCP MSS never approaches that).
pub fn get_tcp_mss(fd: RawFd) -> io::Result<u16> {
    let val = getsockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_MAXSEG)?;
    Ok(val.clamp(0, u16::MAX as c_int) as u16)
}

/// Thin `setsockopt(2)` wrapper for a single `c_int`-valued option.
fn setsockopt_int(fd: RawFd, level: c_int, optname: c_int, value: c_int) -> io::Result<()> {
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            optname,
            &value as *const c_int as *const libc::c_void,
            std::mem::size_of::<c_int>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Thin `getsockopt(2)` wrapper for a single `c_int`-valued option.
fn getsockopt_int(fd: RawFd, level: c_int, optname: c_int) -> io::Result<c_int> {
    let mut val: c_int = 0;
    let mut len = std::mem::size_of::<c_int>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            level,
            optname,
            &mut val as *mut c_int as *mut libc::c_void,
            &mut len,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(val)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};
    use std::os::fd::AsRawFd;

    /// Setting `TCP_MAXSEG` before the handshake reduces the MSS the
    /// kernel reads back on the established socket. Both ends advertise
    /// the clamp, so both report a value at or below it (the kernel
    /// subtracts per-segment TCP options, so it can be a little lower).
    #[test]
    fn set_tcp_mss_reduces_negotiated_mss() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        // The listener carries the clamp so the accepted child's SYN-ACK
        // advertises it (mirrors the zebra-rs listener reconciler).
        set_tcp_mss(listener.as_raw_fd(), 500).unwrap();
        let addr = listener.local_addr().unwrap();

        let client = TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();

        // Without any clamp loopback negotiates a very large MSS; with
        // the 500-byte clamp on both paths each end must be well under
        // the default ethernet MSS of 1460.
        let client_mss = get_tcp_mss(client.as_raw_fd()).unwrap();
        let server_mss = get_tcp_mss(server.as_raw_fd()).unwrap();
        assert!(
            client_mss > 0 && client_mss <= 500,
            "client synced MSS {client_mss} must be in (0, 500]",
        );
        assert!(
            server_mss > 0 && server_mss <= 500,
            "server synced MSS {server_mss} must be in (0, 500]",
        );
    }

    /// `set_tcp_mss` on the active socket before connect clamps that
    /// socket's own negotiated MSS regardless of what the peer
    /// advertises — this is what makes the active-connect path alone
    /// enough to bound the segments we send.
    #[test]
    fn set_tcp_mss_on_active_socket_clamps_local() {
        use socket2::{Domain, Socket, Type};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let sock = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
        set_tcp_mss(sock.as_raw_fd(), 500).unwrap();
        sock.connect(&addr.into()).unwrap();
        let (server, _) = listener.accept().unwrap();

        let local_mss = get_tcp_mss(sock.as_raw_fd()).unwrap();
        assert!(
            local_mss > 0 && local_mss <= 500,
            "active socket synced MSS {local_mss} must be in (0, 500]",
        );
        drop(server);
    }
}
