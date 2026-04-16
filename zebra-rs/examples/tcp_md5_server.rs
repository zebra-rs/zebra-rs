// TCP MD5 (RFC 2385) server example for zebra-rs.
//
// Installs a TCP_MD5SIG key on the listening socket *before* bind/listen,
// so that the kernel can validate MD5 digests on the incoming SYN during
// the three-way handshake. After accept() the handshake is already
// complete — setting the key after that point is too late.
//
// Usage:
//   cargo run --example tcp_md5_server -- [port] [peer-ip] [password]
//   defaults: 17900 127.0.0.1 s3cret
//
// Pair with tcp_md5_client on the same host (loopback) or across two
// hosts. Requires CAP_NET_ADMIN for TCP_MD5SIG on most distros.

#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
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
    let port: u16 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(17900);
    let peer_ip: IpAddr = args
        .get(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let key: Vec<u8> = args
        .get(3)
        .map(|s| s.as_bytes().to_vec())
        .unwrap_or_else(|| b"s3cret".to_vec());

    let (domain, bind_ip) = if peer_ip.is_ipv4() {
        (Domain::IPV4, IpAddr::V4(Ipv4Addr::UNSPECIFIED))
    } else {
        (Domain::IPV6, IpAddr::V6(Ipv6Addr::UNSPECIFIED))
    };
    let listen_addr = SocketAddr::new(bind_ip, port);

    let sock = Socket::new(domain, Type::STREAM, None)?;
    sock.set_reuse_address(true)?;

    // Install the MD5 key BEFORE bind/listen. The kernel checks digests on
    // incoming SYNs against the key database on the listening socket; after
    // accept() the handshake has already happened.
    set_md5_key(&sock, peer_ip, &key)?;

    sock.bind(&listen_addr.into())?;
    sock.listen(1)?;

    println!(
        "[md5-server] listening on {listen_addr}, expecting peer {peer_ip} with {}-byte key",
        key.len()
    );

    let (client_sock, peer) = sock.accept()?;
    println!(
        "[md5-server] accepted {}",
        peer.as_socket()
            .map(|s| s.to_string())
            .unwrap_or_else(|| "<unknown>".into())
    );

    let mut stream: std::net::TcpStream = client_sock.into();
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf)?;
    let received = std::str::from_utf8(&buf[..n]).unwrap_or("<binary>");
    println!("[md5-server] read {n} bytes: {received:?}");
    stream.write_all(b"pong from md5-server\n")?;

    Ok(())
}
