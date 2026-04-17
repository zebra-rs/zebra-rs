// TCP MD5 (RFC 2385) and TCP-AO (RFC 5925 / RFC 5926) setsockopt
// helpers for BGP session authentication, plus the zebra-rs-side
// RFC 8177 key-chain data model used by TCP-AO.
//
// Adapted from zebra-rs/examples/tcp_md5_*.rs and tcp_ao_*.rs.
// Linux-only; non-Linux builds log a warning and no-op so that
// configuration with MD5 / AO still parses but does not enforce
// authentication. This matches zebra-rs's Linux-primary posture.

use std::collections::BTreeMap;
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
// RFC 8177 key-chain data model used by TCP-AO (zebra-bgp-auth
// YANG `key-chains` container).
// =========================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoAlgorithm {
    /// RFC 5926 MUST-implement: HMAC-SHA-1-96. Linux alg name
    /// "hmac(sha1)".
    HmacSha1,
    /// RFC 5926 MUST-implement: AES-128-CMAC-96. Linux alg name
    /// "cmac(aes128)".
    AesCmacPrf128,
    /// Other RFC 8177 identities we recognize but may not implement
    /// in the kernel path (e.g. md5 belongs to MD5's key-chain flow
    /// which zebra-rs does not use — tcp-md5 takes a flat password).
    Md5,
    HmacSha256,
    HmacSha384,
    HmacSha512,
}

impl CryptoAlgorithm {
    pub fn from_identity(name: &str) -> Option<Self> {
        // Accept both bare and prefixed forms
        // (e.g. "hmac-sha-1" and "ietf-key-chain:hmac-sha-1").
        let bare = name.rsplit(':').next().unwrap_or(name);
        match bare {
            "hmac-sha-1" => Some(Self::HmacSha1),
            "aes-cmac-prf-128" => Some(Self::AesCmacPrf128),
            "md5" => Some(Self::Md5),
            "hmac-sha-256" => Some(Self::HmacSha256),
            "hmac-sha-384" => Some(Self::HmacSha384),
            "hmac-sha-512" => Some(Self::HmacSha512),
            _ => None,
        }
    }

    /// Linux kernel crypto API name passed in `tcp_ao_add.alg_name`.
    /// Returns `None` for algorithms the kernel path does not
    /// implement in this module.
    pub fn linux_alg_name(&self) -> Option<&'static str> {
        match self {
            Self::HmacSha1 => Some("hmac(sha1)"),
            Self::AesCmacPrf128 => Some("cmac(aes128)"),
            Self::HmacSha256 => Some("hmac(sha256)"),
            Self::HmacSha384 => Some("hmac(sha384)"),
            Self::HmacSha512 => Some("hmac(sha512)"),
            Self::Md5 => None,
        }
    }
}

/// One RFC 8177 key within a chain. Fields mirror zebra-bgp-auth.yang:
/// `crypto-algorithm`, `key-string/{keystring | hexadecimal-string}`,
/// `send-id`, `recv-id`.
#[derive(Debug, Default, Clone)]
pub struct Key {
    pub key_id: u64,
    pub crypto_algorithm: Option<CryptoAlgorithm>,
    /// Raw key bytes. When the CLI leaf is `keystring`, this holds
    /// the ASCII bytes; when `hexadecimal-string`, the decoded hex
    /// bytes. Empty until set.
    pub key_material: Vec<u8>,
    pub send_id: Option<u8>,
    pub recv_id: Option<u8>,
}

impl Key {
    pub fn new(key_id: u64) -> Self {
        Self {
            key_id,
            ..Default::default()
        }
    }
}

/// Named RFC 8177 key chain. Keys are ordered by key-id.
#[derive(Debug, Default, Clone)]
pub struct KeyChain {
    pub name: String,
    pub description: Option<String>,
    pub keys: BTreeMap<u64, Key>,
}

impl KeyChain {
    pub fn new(name: String) -> Self {
        Self {
            name,
            ..Default::default()
        }
    }

    /// Pick the key to use for new connections. For this initial
    /// implementation we take the lowest key-id. Lifetime-based
    /// selection and in-band rollover via RNextKeyID are follow-ups.
    pub fn active_key(&self) -> Option<&Key> {
        self.keys.values().next()
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
