// TCP MD5 (RFC 2385) and TCP-AO (RFC 5925 / RFC 5926) setsockopt
// helpers for BGP session authentication.
//
// Adapted from zebra-rs/examples/tcp_md5_*.rs and tcp_ao_*.rs.
// Linux-only; non-Linux builds log a warning and no-op so that
// configuration with MD5 / AO still parses but does not enforce
// authentication. This matches zebra-rs's Linux-primary posture.

use std::io;
use std::net::IpAddr;

#[cfg(target_os = "linux")]
use std::{mem, os::fd::RawFd};

#[cfg(target_os = "linux")]
#[repr(C)]
struct TcpMd5Sig {
    tcpm_addr: libc::sockaddr_storage,
    tcpm_flags: u8,
    tcpm_prefixlen: u8,
    tcpm_keylen: u16,
    tcpm_ifindex: i32,
    tcpm_key: [u8; libc::TCP_MD5SIG_MAXKEYLEN],
}

/// Install a TCP MD5 shared secret on `fd` keyed by `peer_ip`.
///
/// Must be called:
/// - Before `connect()` on an active-side `TcpSocket` (so the outgoing
///   SYN carries a valid MD5 option).
/// - Before the peer's SYN arrives on a listening socket (so the
///   handshake can validate the incoming MD5 option).
///
/// An empty `key` removes the entry for that peer on the socket.
#[cfg(target_os = "linux")]
pub fn set_tcp_md5_key(fd: RawFd, peer_ip: IpAddr, key: &[u8]) -> io::Result<()> {
    if key.len() > libc::TCP_MD5SIG_MAXKEYLEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "TCP MD5 key too long ({} > {})",
                key.len(),
                libc::TCP_MD5SIG_MAXKEYLEN
            ),
        ));
    }

    let mut sig: TcpMd5Sig = unsafe { mem::zeroed() };
    match peer_ip {
        IpAddr::V4(a) => {
            let sa = unsafe {
                &mut *(&mut sig.tcpm_addr as *mut libc::sockaddr_storage as *mut libc::sockaddr_in)
            };
            sa.sin_family = libc::AF_INET as libc::sa_family_t;
            sa.sin_addr = libc::in_addr {
                s_addr: u32::from(a).to_be(),
            };
        }
        IpAddr::V6(a) => {
            let sa = unsafe {
                &mut *(&mut sig.tcpm_addr as *mut libc::sockaddr_storage as *mut libc::sockaddr_in6)
            };
            sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sa.sin6_addr.s6_addr = a.octets();
        }
    }
    sig.tcpm_keylen = key.len() as u16;
    sig.tcpm_key[..key.len()].copy_from_slice(key);

    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_MD5SIG,
            &sig as *const TcpMd5Sig as *const libc::c_void,
            mem::size_of::<TcpMd5Sig>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn set_tcp_md5_key(_fd: i32, _peer_ip: IpAddr, _key: &[u8]) -> io::Result<()> {
    tracing::warn!("TCP MD5 authentication not supported on this platform; no-op");
    Ok(())
}
