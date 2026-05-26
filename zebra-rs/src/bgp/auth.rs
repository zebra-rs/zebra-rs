// TCP MD5 (RFC 2385) and TCP-AO (RFC 5925 / RFC 5926) setsockopt
// helpers for BGP session authentication, plus the zebra-rs-side
// RFC 8177 key-chain data model used by TCP-AO.
//
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

// =========================================================
// TCP-AO (RFC 5925) setsockopt wrapper.
// =========================================================

#[cfg(target_os = "linux")]
const TCP_AO_ADD_KEY: libc::c_int = 38;
#[cfg(target_os = "linux")]
const TCP_AO_DEL_KEY: libc::c_int = 39;
#[cfg(target_os = "linux")]
const TCP_AO_MAXKEYLEN: usize = 80;
#[cfg(target_os = "linux")]
const TCP_AO_ALG_NAME_MAX: usize = 64;
#[cfg(target_os = "linux")]
const TCP_AO_KEYF_EXCLUDE_OPT: u8 = 1 << 1;

// struct tcp_ao_add from <linux/tcp.h> (kernel >= 6.7).
#[cfg(target_os = "linux")]
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

// struct tcp_ao_del from <linux/tcp.h>.
#[cfg(target_os = "linux")]
#[repr(C, align(8))]
struct TcpAoDel {
    addr: libc::sockaddr_storage,
    ifindex: i32,
    flags: u32,
    reserved2: u16,
    prefix: u8,
    sndid: u8,
    rcvid: u8,
    current_key: u8,
    rnext: u8,
    keyflags: u8,
    del_async: u8,
}

#[cfg(target_os = "linux")]
fn fill_sockaddr(addr: &mut libc::sockaddr_storage, peer_ip: IpAddr) {
    match peer_ip {
        IpAddr::V4(a) => {
            let sa =
                unsafe { &mut *(addr as *mut libc::sockaddr_storage as *mut libc::sockaddr_in) };
            sa.sin_family = libc::AF_INET as libc::sa_family_t;
            sa.sin_addr = libc::in_addr {
                s_addr: u32::from(a).to_be(),
            };
        }
        IpAddr::V6(a) => {
            let sa =
                unsafe { &mut *(addr as *mut libc::sockaddr_storage as *mut libc::sockaddr_in6) };
            sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sa.sin6_addr.s6_addr = a.octets();
        }
    }
}

/// Install a TCP-AO Master Key Tuple for `peer_ip` on `fd` via
/// `setsockopt(TCP_AO_ADD_KEY)`.
///
/// - `alg_name`: Linux crypto API name, e.g. `"hmac(sha1)"`.
/// - `key`: raw master key bytes (≤ 80 B).
/// - `send_id` / `recv_id`: RFC 5925 §3.1 on-wire KeyIDs.
/// - `include_tcp_options`: when false, sets
///   `TCP_AO_KEYF_EXCLUDE_OPT` so the MAC does not cover TCP
///   options other than TCP-AO itself.
///
/// Must be called before `connect()` on the active side and before
/// the peer's SYN arrives on the listener side.
#[cfg(target_os = "linux")]
pub fn set_tcp_ao_key(
    fd: RawFd,
    peer_ip: IpAddr,
    alg_name: &str,
    key: &[u8],
    send_id: u8,
    recv_id: u8,
    include_tcp_options: bool,
) -> io::Result<()> {
    if key.len() > TCP_AO_MAXKEYLEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("TCP-AO key too long ({} > {})", key.len(), TCP_AO_MAXKEYLEN),
        ));
    }
    if alg_name.len() >= TCP_AO_ALG_NAME_MAX {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "TCP-AO algorithm name too long ({} >= {})",
                alg_name.len(),
                TCP_AO_ALG_NAME_MAX
            ),
        ));
    }

    let mut add: TcpAoAdd = unsafe { mem::zeroed() };
    fill_sockaddr(&mut add.addr, peer_ip);
    add.alg_name[..alg_name.len()].copy_from_slice(alg_name.as_bytes());
    add.prefix = if peer_ip.is_ipv4() { 32 } else { 128 };
    add.sndid = send_id;
    add.rcvid = recv_id;
    add.maclen = 12; // RFC 5926 default 96-bit MAC
    add.keylen = key.len() as u8;
    add.key[..key.len()].copy_from_slice(key);
    if !include_tcp_options {
        add.keyflags |= TCP_AO_KEYF_EXCLUDE_OPT;
    }

    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            TCP_AO_ADD_KEY,
            &add as *const TcpAoAdd as *const libc::c_void,
            mem::size_of::<TcpAoAdd>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Remove the TCP-AO MKT for `peer_ip` from `fd`.
#[cfg(target_os = "linux")]
pub fn del_tcp_ao_key(fd: RawFd, peer_ip: IpAddr, send_id: u8, recv_id: u8) -> io::Result<()> {
    let mut del: TcpAoDel = unsafe { mem::zeroed() };
    fill_sockaddr(&mut del.addr, peer_ip);
    del.prefix = if peer_ip.is_ipv4() { 32 } else { 128 };
    del.sndid = send_id;
    del.rcvid = recv_id;

    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            TCP_AO_DEL_KEY,
            &del as *const TcpAoDel as *const libc::c_void,
            mem::size_of::<TcpAoDel>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn set_tcp_ao_key(
    _fd: i32,
    _peer_ip: IpAddr,
    _alg_name: &str,
    _key: &[u8],
    _send_id: u8,
    _recv_id: u8,
    _include_tcp_options: bool,
) -> io::Result<()> {
    tracing::warn!("TCP-AO authentication not supported on this platform; no-op");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn del_tcp_ao_key(_fd: i32, _peer_ip: IpAddr, _send_id: u8, _recv_id: u8) -> io::Result<()> {
    Ok(())
}

// =========================================================
// TCP-AO key-chain resolution.
//
// The on-disk `/key-chains/...` data model lives in
// `policy::keychain` and is pushed to BGP as `PolicyRx::KeyChain`
// snapshots. The types below are just the BGP-side bindings that
// translate one of those policy keys into the kernel
// setsockopt struct.
// =========================================================

/// Project the shared policy algorithm enum onto the Linux crypto
/// API name passed in `tcp_ao_add.alg_name`. Returns `None` for
/// algorithms the kernel path doesn't implement here — `Md5` in
/// particular belongs to TCP-MD5's flat-password flow (RFC 2385),
/// not TCP-AO's key-chain flow, so the resolve falls through.
pub fn tcp_ao_alg_from_policy(a: crate::policy::CryptoAlgorithm) -> Option<&'static str> {
    use crate::policy::CryptoAlgorithm as P;
    match a {
        P::HmacSha1 => Some("hmac(sha1)"),
        P::AesCmacPrf128 => Some("cmac(aes128)"),
        P::HmacSha256 => Some("hmac(sha256)"),
        P::HmacSha384 => Some("hmac(sha384)"),
        P::HmacSha512 => Some("hmac(sha512)"),
        P::Md5 => None,
    }
}

/// Per-neighbor TCP-AO configuration (zebra-bgp-auth.yang `tcp-ao`
/// presence container).
#[derive(Debug, Clone)]
pub struct AoConfig {
    /// Name of a configured key chain under `/key-chains`.
    pub key_chain: String,
    /// Whether the TCP-AO MAC covers TCP options other than TCP-AO
    /// itself. Maps to Linux TCP_AO_KEYF_EXCLUDE_OPT (inverted).
    pub include_tcp_options: bool,
}

impl Default for AoConfig {
    fn default() -> Self {
        Self {
            key_chain: String::new(),
            include_tcp_options: true,
        }
    }
}

/// Fully resolved TCP-AO parameters for a specific session, ready to
/// pass into `set_tcp_ao_key`. Cached on `PeerTransportConfig` so the
/// active-side `peer_connect` can apply it without needing to walk
/// the `Bgp` registry at spawn time.
#[derive(Debug, Clone)]
pub struct ResolvedAoKey {
    pub alg_name: &'static str,
    pub key_material: Vec<u8>,
    pub send_id: u8,
    pub recv_id: u8,
    pub include_tcp_options: bool,
}

impl AoConfig {
    /// Resolve `(key-chain name, include-tcp-options)` against the
    /// policy-driven snapshot. Picks the lowest key-id (lifetime-
    /// based selection + in-band rollover via RNextKeyID are
    /// follow-ups). Returns `None` if the chain is missing, has no
    /// key, or the chosen key lacks an algorithm BGP can speak,
    /// SendID, RecvID, or has a zero-length material.
    pub fn resolve(
        &self,
        key_chains: &std::collections::BTreeMap<String, crate::policy::KeyChain>,
    ) -> Option<ResolvedAoKey> {
        let chain = key_chains.get(&self.key_chain)?;
        let (_, key) = chain.keys.iter().next()?;
        let alg_name = tcp_ao_alg_from_policy(key.algo?)?;
        let send_id = key.send_id?;
        let recv_id = key.recv_id?;
        if key.key_material.is_empty() {
            return None;
        }
        Some(ResolvedAoKey {
            alg_name,
            key_material: key.key_material.clone(),
            send_id,
            recv_id,
            include_tcp_options: self.include_tcp_options,
        })
    }
}
