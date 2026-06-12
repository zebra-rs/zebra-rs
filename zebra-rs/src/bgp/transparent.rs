// BGP `neighbor X ip-transparent` (FRR 10.4, FRRouting/frr PR #18789):
// the IP_TRANSPARENT / IPV6_TRANSPARENT socket option, which lets a BGP
// session use a local address the host does not own.
//
// Normally the kernel rejects a bind() to a non-local address and
// refuses to emit packets with a non-local source. IP_TRANSPARENT
// (CAP_NET_ADMIN required) bypasses both checks, so a peer configured
// with `update-source <addr-we-do-not-own>` + `ip-transparent` can dial
// from that address — the container-peering / VRRP-VIP-takeover /
// transparent-firewall use cases. The option only liberates the local
// socket: delivery of return traffic destined to the non-local address
// is the operator's problem (AnyIP local route, TPROXY/fwmark policy
// routing, or VRRP ownership).
//
// Two application sites:
// - the active connect socket, before bind() (`peer::peer_connect`) —
//   gated on `update-source` being configured, matching FRR's
//   both-flags check in `bgp_connect()`;
// - the listening sockets, while any neighbor of that address family
//   has the knob (`config::apply_ip_transparent_refresh_all`), so a
//   passively accepted session destined to a non-local address (e.g.
//   TPROXY-steered) can be answered. FRR leaves its listener alone;
//   this side is what makes the documented passive scenarios work
//   without an AnyIP route.
//
// Linux-primary, like `ttl.rs` / `mss.rs`: IP_TRANSPARENT is a Linux
// option and the daemon is built for Linux.

use std::io;
use std::os::fd::RawFd;
use std::os::raw::c_int;

/// Set (or clear) IP_TRANSPARENT (IPv4) / IPV6_TRANSPARENT (IPv6) on
/// `fd`. The option must be applied before bind()/connect() to affect a
/// session — hence the bounce-on-change semantics of the config knob —
/// and requires CAP_NET_ADMIN (EPERM otherwise).
pub fn set_ip_transparent(fd: RawFd, is_ipv4: bool, on: bool) -> io::Result<()> {
    let value = on as c_int;
    if is_ipv4 {
        super::ttl::setsockopt_int(fd, libc::IPPROTO_IP, libc::IP_TRANSPARENT, value)
    } else {
        super::ttl::setsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_TRANSPARENT, value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

    /// IP_TRANSPARENT needs CAP_NET_ADMIN, so the observable behaviour
    /// differs by privilege — assert the right one either way so the
    /// test is meaningful both in an unprivileged dev run and a root
    /// (BDD-style) run: privileged, the flag must read back set and
    /// clear again; unprivileged, the set must fail cleanly (EPERM)
    /// rather than silently no-op.
    #[test]
    fn set_ip_transparent_v4_respects_privilege() {
        use socket2::{Domain, Socket, Type};
        let sock = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
        let fd = sock.as_raw_fd();

        match set_ip_transparent(fd, true, true) {
            Ok(()) => {
                assert_eq!(
                    getsockopt_int(fd, libc::IPPROTO_IP, libc::IP_TRANSPARENT),
                    1,
                    "flag must read back set after a privileged set",
                );
                set_ip_transparent(fd, true, false).unwrap();
                assert_eq!(
                    getsockopt_int(fd, libc::IPPROTO_IP, libc::IP_TRANSPARENT),
                    0,
                    "flag must read back clear after clearing",
                );
            }
            Err(e) => {
                assert_eq!(
                    e.raw_os_error(),
                    Some(libc::EPERM),
                    "without CAP_NET_ADMIN the only acceptable failure is EPERM, got: {e}",
                );
            }
        }
    }

    /// Same privilege split for the IPv6 variant (IPV6_TRANSPARENT).
    #[test]
    fn set_ip_transparent_v6_respects_privilege() {
        use socket2::{Domain, Socket, Type};
        let sock = Socket::new(Domain::IPV6, Type::STREAM, None).unwrap();
        let fd = sock.as_raw_fd();

        match set_ip_transparent(fd, false, true) {
            Ok(()) => {
                assert_eq!(
                    getsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_TRANSPARENT),
                    1,
                    "flag must read back set after a privileged set",
                );
            }
            Err(e) => {
                assert_eq!(
                    e.raw_os_error(),
                    Some(libc::EPERM),
                    "without CAP_NET_ADMIN the only acceptable failure is EPERM, got: {e}",
                );
            }
        }
    }
}
