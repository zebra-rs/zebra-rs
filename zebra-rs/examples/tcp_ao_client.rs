// TCP Authentication Option (RFC 5925 / RFC 5926) client example.
//
// Installs a single Master Key Tuple (MKT) on the active socket via
// TCP_AO_ADD_KEY before connect(), so the outgoing SYN already carries
// a valid TCP-AO option that the peer's listening socket will verify.
//
// Algorithm: HMAC-SHA-1-96. SendID == RecvID, matching the companion
// server example for a single shared MKT.
//
// Usage:
//   cargo run --example tcp_ao_client -- [server-addr] [key-id] [password]
//   defaults: 127.0.0.1:17901 100 s3cret-ao-key
//
// Requires Linux kernel >= 6.7 and CAP_NET_ADMIN.

#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::mem;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsRawFd;

use socket2::{Domain, Socket, Type};

const TCP_AO_ADD_KEY: libc::c_int = 38;
const TCP_AO_MAXKEYLEN: usize = 80;
const TCP_AO_ALG_NAME_MAX: usize = 64;

#[repr(C, align(8))]
struct TcpAoAdd {
    addr: libc::sockaddr_storage,
    alg_name: [u8; TCP_AO_ALG_NAME_MAX],
    ifindex: i32,
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
    add.maclen = 12;
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
    let server: SocketAddr = args
        .get(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| "127.0.0.1:17901".parse().unwrap());
    let key_id: u8 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(100);
    let key: Vec<u8> = args
        .get(3)
        .map(|s| s.as_bytes().to_vec())
        .unwrap_or_else(|| b"s3cret-ao-key".to_vec());

    let (domain, prefix) = if server.is_ipv4() {
        (Domain::IPV4, 32u8)
    } else {
        (Domain::IPV6, 128u8)
    };
    let sock = Socket::new(domain, Type::STREAM, None)?;

    set_ao_key(&sock, server.ip(), prefix, key_id, key_id, &key)?;

    println!("[ao-client] connecting to {server}, key-id {key_id}, alg hmac(sha1)");
    sock.connect(&server.into())?;

    let mut stream: std::net::TcpStream = sock.into();
    stream.write_all(b"hello from ao-client\n")?;
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf)?;
    let received = std::str::from_utf8(&buf[..n]).unwrap_or("<binary>");
    println!("[ao-client] read {n} bytes: {received:?}");

    Ok(())
}
