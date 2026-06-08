// Generalized TTL Security Mechanism (GTSM, RFC 5082 / RFC 3682) for
// directly-connected BGP sessions.
//
// zebra-rs supports only the directly-connected case (expected hop
// count 0), so the TTL is always 255: every outgoing segment leaves
// with IP TTL / IPv6 Hop Limit 255, and the kernel is told to drop any
// incoming segment whose TTL / Hop Limit is below 255 (IP_MINTTL /
// IPV6_MINHOPCOUNT). A spoofed packet injected from more than one hop
// away necessarily arrives with TTL < 255 and is discarded before BGP
// ever sees it. There is intentionally no configurable hop count — the
// YANG leaf is `type empty`.
//
// The options are installed on an already-connected socket (after the
// TCP handshake, from `fsm_connected`); the three-way handshake itself
// is not TTL-filtered, which is the standard GTSM trade-off — TCP
// sequence randomization protects the handshake, GTSM protects the
// established session that carries OPEN and every subsequent message.
//
// Linux-primary, matching `bfd/socket.rs`: the libc constants used here
// are Linux's and the daemon is built for Linux.

use std::io;
use std::os::fd::RawFd;
use std::os::raw::c_int;

/// The only TTL GTSM uses here: directly connected ⇒ expected hop count
/// 0 ⇒ TTL / Hop Limit 255 (RFC 5082 §3). There is intentionally no
/// configurable hop count.
pub const GTSM_TTL: c_int = 255;

/// Apply GTSM to a connected BGP socket `fd`: pin the egress TTL / Hop
/// Limit to 255 and floor the accepted ingress TTL / Hop Limit at 255.
/// `is_ipv4` selects the IPv4 (`IP_TTL` / `IP_MINTTL`) or IPv6
/// (`IPV6_UNICAST_HOPS` / `IPV6_MINHOPCOUNT`) option pair.
pub fn apply_gtsm(fd: RawFd, is_ipv4: bool) -> io::Result<()> {
    if is_ipv4 {
        setsockopt_int(fd, libc::IPPROTO_IP, libc::IP_TTL, GTSM_TTL)?;
        setsockopt_int(fd, libc::IPPROTO_IP, libc::IP_MINTTL, GTSM_TTL)?;
    } else {
        setsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_UNICAST_HOPS, GTSM_TTL)?;
        setsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_MINHOPCOUNT, GTSM_TTL)?;
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};
    use std::os::fd::AsRawFd;

    fn getsockopt_int(fd: RawFd, level: c_int, optname: c_int) -> c_int {
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
        assert!(rc >= 0, "getsockopt failed: {}", io::Error::last_os_error());
        val
    }

    /// `apply_gtsm` must succeed on a real connected IPv4 socket and the
    /// kernel must read the egress TTL and the ingress minimum TTL back
    /// as 255.
    #[test]
    fn apply_gtsm_v4_pins_ttl_and_minttl_to_255() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();

        apply_gtsm(client.as_raw_fd(), true).unwrap();

        assert_eq!(
            getsockopt_int(client.as_raw_fd(), libc::IPPROTO_IP, libc::IP_TTL),
            GTSM_TTL,
            "egress TTL must be pinned to 255",
        );
        assert_eq!(
            getsockopt_int(client.as_raw_fd(), libc::IPPROTO_IP, libc::IP_MINTTL),
            GTSM_TTL,
            "ingress minimum TTL must be floored at 255",
        );
        drop(server);
    }

    /// `apply_gtsm` must succeed on an IPv6 socket and the kernel must
    /// read the egress hop limit and the ingress minimum hop count back
    /// as 255. An unbound AF_INET6 socket is enough — both options are
    /// settable before connect — so the test needs no IPv6 reachability.
    #[test]
    fn apply_gtsm_v6_pins_hops_and_minhopcount_to_255() {
        use socket2::{Domain, Socket, Type};
        let sock = Socket::new(Domain::IPV6, Type::STREAM, None).unwrap();

        apply_gtsm(sock.as_raw_fd(), false).unwrap();

        assert_eq!(
            getsockopt_int(
                sock.as_raw_fd(),
                libc::IPPROTO_IPV6,
                libc::IPV6_UNICAST_HOPS
            ),
            GTSM_TTL,
            "egress hop limit must be pinned to 255",
        );
        assert_eq!(
            getsockopt_int(sock.as_raw_fd(), libc::IPPROTO_IPV6, libc::IPV6_MINHOPCOUNT),
            GTSM_TTL,
            "ingress minimum hop count must be floored at 255",
        );
    }
}
