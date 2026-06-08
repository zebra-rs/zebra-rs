// BGP per-session TTL policy: the egress IP TTL / IPv6 Hop Limit, plus
// GTSM (RFC 5082), which additionally floors the accepted ingress TTL.
//
// Egress TTL by session type (resolved in `Peer::session_ttl`):
//   - eBGP, directly connected (default)  → 1
//   - eBGP with `ebgp-multihop N`         → N
//   - iBGP                                → 255
//   - `ttl-security` (GTSM), either sort  → 255, plus an ingress floor of 255
//
// A directly-connected eBGP peer at TTL 1 cannot be reached through a
// router (the first hop decrements it to 0 and drops it), so a multihop
// peer needs an explicit `ebgp-multihop`. GTSM goes the other way: it
// pins egress to 255 and tells the kernel to drop any segment that
// arrives below 255, so an off-path / multi-hop spoofer is filtered
// before BGP ever sees the packet.
//
// These are applied to a connected socket — on the active side before
// connect (so the SYN already carries the right TTL) and, for both
// roles, from `fsm_connected` after the handshake. The GTSM ingress
// floor is applied only post-handshake: setting it earlier would drop
// the peer's default-TTL SYN-ACK. The three-way handshake is therefore
// never TTL-filtered — TCP sequence randomization protects it, GTSM
// protects the established session that carries OPEN onward.
//
// Linux-primary, matching `bfd/socket.rs`: the libc constants used here
// are Linux's and the daemon is built for Linux.

use std::io;
use std::os::fd::RawFd;
use std::os::raw::c_int;

/// Maximum IP TTL / IPv6 Hop Limit. The iBGP default and the value GTSM
/// pins both egress and the ingress floor to (RFC 5082 §3: directly
/// connected ⇒ expected hop count 0 ⇒ TTL 255).
pub const MAX_TTL: u8 = 255;

/// Default egress TTL for a directly-connected eBGP session (RFC 4271
/// operational practice; matches FRR's `BGP_DEFAULT_TTL`). `ebgp-multihop`
/// raises it.
pub const DEFAULT_EBGP_TTL: u8 = 1;

/// Set the egress IP TTL (IPv4 `IP_TTL`) / Unicast Hop Limit (IPv6
/// `IPV6_UNICAST_HOPS`) on a BGP socket `fd`.
pub fn set_egress_ttl(fd: RawFd, is_ipv4: bool, ttl: u8) -> io::Result<()> {
    if is_ipv4 {
        setsockopt_int(fd, libc::IPPROTO_IP, libc::IP_TTL, ttl as c_int)
    } else {
        setsockopt_int(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_UNICAST_HOPS,
            ttl as c_int,
        )
    }
}

/// Floor the accepted ingress TTL (IPv4 `IP_MINTTL`) / Hop Limit (IPv6
/// `IPV6_MINHOPCOUNT`) on `fd`: the kernel drops any segment arriving
/// below `min` before it reaches BGP. This is the GTSM ingress half;
/// apply it only after the TCP handshake.
pub fn set_min_ttl(fd: RawFd, is_ipv4: bool, min: u8) -> io::Result<()> {
    if is_ipv4 {
        setsockopt_int(fd, libc::IPPROTO_IP, libc::IP_MINTTL, min as c_int)
    } else {
        setsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_MINHOPCOUNT, min as c_int)
    }
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

    /// `set_egress_ttl` must pin an arbitrary egress TTL (here the eBGP
    /// default of 1) that the kernel reads back, without touching the
    /// ingress floor.
    #[test]
    fn set_egress_ttl_v4_sets_arbitrary_value() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();

        set_egress_ttl(client.as_raw_fd(), true, DEFAULT_EBGP_TTL).unwrap();

        assert_eq!(
            getsockopt_int(client.as_raw_fd(), libc::IPPROTO_IP, libc::IP_TTL),
            DEFAULT_EBGP_TTL as c_int,
            "egress TTL must be the value we set",
        );
        drop(server);
    }

    /// The GTSM pair on a connected IPv4 socket: egress TTL and the
    /// ingress minimum TTL must both read back as 255.
    #[test]
    fn gtsm_pair_v4_pins_ttl_and_minttl_to_255() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();
        let fd = client.as_raw_fd();

        set_egress_ttl(fd, true, MAX_TTL).unwrap();
        set_min_ttl(fd, true, MAX_TTL).unwrap();

        assert_eq!(
            getsockopt_int(fd, libc::IPPROTO_IP, libc::IP_TTL),
            MAX_TTL as c_int,
            "egress TTL must be pinned to 255",
        );
        assert_eq!(
            getsockopt_int(fd, libc::IPPROTO_IP, libc::IP_MINTTL),
            MAX_TTL as c_int,
            "ingress minimum TTL must be floored at 255",
        );
        drop(server);
    }

    /// The GTSM pair on an IPv6 socket: egress hop limit and ingress
    /// minimum hop count must both read back as 255. An unbound AF_INET6
    /// socket is enough — both options are settable before connect — so
    /// the test needs no IPv6 reachability.
    #[test]
    fn gtsm_pair_v6_pins_hops_and_minhopcount_to_255() {
        use socket2::{Domain, Socket, Type};
        let sock = Socket::new(Domain::IPV6, Type::STREAM, None).unwrap();
        let fd = sock.as_raw_fd();

        set_egress_ttl(fd, false, MAX_TTL).unwrap();
        set_min_ttl(fd, false, MAX_TTL).unwrap();

        assert_eq!(
            getsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_UNICAST_HOPS),
            MAX_TTL as c_int,
            "egress hop limit must be pinned to 255",
        );
        assert_eq!(
            getsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_MINHOPCOUNT),
            MAX_TTL as c_int,
            "ingress minimum hop count must be floored at 255",
        );
    }
}
