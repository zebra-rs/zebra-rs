// TCP Authentication Option (RFC 5925 / RFC 5926) server example.
//
// Installs a single Master Key Tuple (MKT) on the listening socket via
// TCP_AO_ADD_KEY before bind/listen. Like TCP_MD5SIG, AO is verified
// during the three-way handshake, so the key must be in place before
// the peer's SYN arrives.
//
// Algorithm: HMAC-SHA-1-96 (the RFC 5926 MUST-implement choice).
// SendID and RecvID are set equal on both peers for this minimal
// example — a single shared MKT used in both directions.
//
// Usage:
//   cargo run --example tcp_ao_server -- [port] [peer-ip] [key-id] [password]
//   defaults: 17901 127.0.0.1 100 s3cret-ao-key
//
// Requires Linux kernel >= 6.7 and CAP_NET_ADMIN.

#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::AsRawFd;

use socket2::{Domain, Socket, Type};

const TCP_AO_ADD_KEY: libc::c_int = 38;
const TCP_AO_MAXKEYLEN: usize = 80;
const TCP_AO_ALG_NAME_MAX: usize = 64;

// Layout matches `struct tcp_ao_add` in <linux/tcp.h> (kernel >= 6.7).
// The kernel header declares __attribute__((aligned(8))).
#[repr(C, align(8))]
struct TcpAoAdd {
    addr: libc::sockaddr_storage,
    alg_name: [u8; TCP_AO_ALG_NAME_MAX],
    ifindex: i32,
    // Bitfield in C: set_current:1, set_rnext:1, reserved:30.
    // Little-endian x86-64 packs bit 0 = set_current, bit 1 = set_rnext.
    flags: u32,
    reserved2: u16,
    prefix: u8,
    sndid: u8,
    rcvid: u8,
    maclen: u8,
    keyflags: u8,
    keylen: u8,
    key: [u8; TCP_AO_MAXKEYLEN],
}

fn set_ao_key(
    sock: &Socket,
    peer_ip: IpAddr,
    prefix: u8,
    sndid: u8,
    rcvid: u8,
    key: &[u8],
) -> std::io::Result<()> {
    assert!(
        key.len() <= TCP_AO_MAXKEYLEN,
        "key too long (max {TCP_AO_MAXKEYLEN})"
    );

    let mut add: TcpAoAdd = unsafe { mem::zeroed() };
    match peer_ip {
        IpAddr::V4(addr) => {
            let sa = unsafe {
                &mut *(&mut add.addr as *mut libc::sockaddr_storage as *mut libc::sockaddr_in)
            };
            sa.sin_family = libc::AF_INET as libc::sa_family_t;
            sa.sin_addr = libc::in_addr {
                s_addr: u32::from(addr).to_be(),
            };
        }
        IpAddr::V6(addr) => {
            let sa = unsafe {
                &mut *(&mut add.addr as *mut libc::sockaddr_storage as *mut libc::sockaddr_in6)
            };
            sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sa.sin6_addr.s6_addr = addr.octets();
        }
    }

    let alg = b"hmac(sha1)";
    add.alg_name[..alg.len()].copy_from_slice(alg);

    add.prefix = prefix;
    add.sndid = sndid;
    add.rcvid = rcvid;
    add.maclen = 12; // 96-bit MAC per RFC 5926
    add.keylen = key.len() as u8;
    add.key[..key.len()].copy_from_slice(key);

    let ret = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::IPPROTO_TCP,
            TCP_AO_ADD_KEY,
            &add as *const TcpAoAdd as *const libc::c_void,
            mem::size_of::<TcpAoAdd>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let port: u16 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(17901);
    let peer_ip: IpAddr = args
        .get(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let key_id: u8 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(100);
    let key: Vec<u8> = args
        .get(4)
        .map(|s| s.as_bytes().to_vec())
        .unwrap_or_else(|| b"s3cret-ao-key".to_vec());

    let (domain, bind_ip, prefix) = if peer_ip.is_ipv4() {
        (Domain::IPV4, IpAddr::V4(Ipv4Addr::UNSPECIFIED), 32u8)
    } else {
        (Domain::IPV6, IpAddr::V6(Ipv6Addr::UNSPECIFIED), 128u8)
    };
    let listen_addr = SocketAddr::new(bind_ip, port);

    let sock = Socket::new(domain, Type::STREAM, None)?;
    sock.set_reuse_address(true)?;

    // Single shared MKT: sndid == rcvid, used in both directions.
    set_ao_key(&sock, peer_ip, prefix, key_id, key_id, &key)?;

    sock.bind(&listen_addr.into())?;
    sock.listen(1)?;

    println!(
        "[ao-server] listening on {listen_addr}, peer {peer_ip}, key-id {key_id}, alg hmac(sha1)"
    );

    let (client_sock, peer) = sock.accept()?;
    println!(
        "[ao-server] accepted {}",
        peer.as_socket()
            .map(|s| s.to_string())
            .unwrap_or_else(|| "<unknown>".into())
    );

    let mut stream: std::net::TcpStream = client_sock.into();
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf)?;
    let received = std::str::from_utf8(&buf[..n]).unwrap_or("<binary>");
    println!("[ao-server] read {n} bytes: {received:?}");
    stream.write_all(b"pong from ao-server\n")?;

    Ok(())
}
