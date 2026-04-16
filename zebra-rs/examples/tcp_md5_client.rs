// TCP MD5 (RFC 2385) client example for zebra-rs.
//
// Installs a TCP_MD5SIG key on the active socket *before* connect(),
// so the outgoing SYN already carries the MD5 option that the peer's
// listening socket will validate.
//
// Usage:
//   cargo run --example tcp_md5_client -- [server-addr] [password]
//   defaults: 127.0.0.1:17900 s3cret
//
// Pair with tcp_md5_server. Requires CAP_NET_ADMIN for TCP_MD5SIG on
// most distros.

#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::mem;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsRawFd;

use socket2::{Domain, Socket, Type};

#[repr(C)]
struct TcpMd5Sig {
    tcpm_addr: libc::sockaddr_storage,
    tcpm_flags: u8,
    tcpm_prefixlen: u8,
    tcpm_keylen: u16,
    tcpm_ifindex: i32,
    tcpm_key: [u8; libc::TCP_MD5SIG_MAXKEYLEN],
}

fn set_md5_key(sock: &Socket, peer_ip: IpAddr, key: &[u8]) -> std::io::Result<()> {
    assert!(
        key.len() <= libc::TCP_MD5SIG_MAXKEYLEN,
        "key too long (max {})",
        libc::TCP_MD5SIG_MAXKEYLEN
    );

    let mut sig: TcpMd5Sig = unsafe { mem::zeroed() };
    match peer_ip {
        IpAddr::V4(addr) => {
            let sa = unsafe {
                &mut *(&mut sig.tcpm_addr as *mut libc::sockaddr_storage as *mut libc::sockaddr_in)
            };
            sa.sin_family = libc::AF_INET as libc::sa_family_t;
            sa.sin_addr = libc::in_addr {
                s_addr: u32::from(addr).to_be(),
            };
        }
        IpAddr::V6(addr) => {
            let sa = unsafe {
                &mut *(&mut sig.tcpm_addr as *mut libc::sockaddr_storage as *mut libc::sockaddr_in6)
            };
            sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sa.sin6_addr.s6_addr = addr.octets();
        }
    }
    sig.tcpm_keylen = key.len() as u16;
    sig.tcpm_key[..key.len()].copy_from_slice(key);

    let ret = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_MD5SIG,
            &sig as *const TcpMd5Sig as *const libc::c_void,
            mem::size_of::<TcpMd5Sig>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let server: SocketAddr = args
        .get(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| "127.0.0.1:17900".parse().unwrap());
    let key: Vec<u8> = args
        .get(2)
        .map(|s| s.as_bytes().to_vec())
        .unwrap_or_else(|| b"s3cret".to_vec());

    let domain = if server.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let sock = Socket::new(domain, Type::STREAM, None)?;

    // Install the MD5 key BEFORE connect(). The outgoing SYN must carry a
    // valid MD5 option or the peer's listener will drop it silently.
    set_md5_key(&sock, server.ip(), &key)?;

    println!(
        "[md5-client] connecting to {server} with {}-byte key",
        key.len()
    );
    sock.connect(&server.into())?;

    let mut stream: std::net::TcpStream = sock.into();
    stream.write_all(b"hello from md5-client\n")?;
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf)?;
    let received = std::str::from_utf8(&buf[..n]).unwrap_or("<binary>");
    println!("[md5-client] read {n} bytes: {received:?}");

    Ok(())
}
