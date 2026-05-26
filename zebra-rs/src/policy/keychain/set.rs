use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};

/// RFC 8177 `crypto-algorithm` identityref values that have an actual
/// consumer in zebra-rs today. Union of OSPFv2 (RFC 5709 + keyed-MD5)
/// and BGP TCP-AO (RFC 5926). Protocols filter to their supported
/// subset at resolve time — selecting an unsupported algorithm yields
/// a runtime "no usable key" rather than a config-time error so that
/// a shared chain can carry algorithms used by only one daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoAlgorithm {
    /// Keyed-MD5 (RFC 2328 §D.4 for OSPF; not used by BGP's TCP-AO
    /// kernel path — BGP MD5 takes a flat password).
    Md5,
    /// HMAC-SHA-1-96. RFC 5926 MUST-implement for TCP-AO; RFC 5709
    /// for OSPFv2.
    HmacSha1,
    /// HMAC-SHA-256.
    HmacSha256,
    /// HMAC-SHA-384.
    HmacSha384,
    /// HMAC-SHA-512.
    HmacSha512,
    /// AES-128-CMAC-96. RFC 5926 MUST-implement for TCP-AO.
    AesCmacPrf128,
}

impl CryptoAlgorithm {
    /// Parse the IETF `crypto-algorithm` identityref. Accepts both
    /// bare (`"hmac-sha-1"`) and prefixed (`"ietf-key-chain:hmac-sha-1"`)
    /// forms — the libyang dispatch may deliver either depending on
    /// how the user typed it.
    pub fn from_identity(name: &str) -> Option<Self> {
        let bare = name.rsplit(':').next().unwrap_or(name);
        match bare {
            "md5" => Some(Self::Md5),
            "hmac-sha-1" => Some(Self::HmacSha1),
            "hmac-sha-256" => Some(Self::HmacSha256),
            "hmac-sha-384" => Some(Self::HmacSha384),
            "hmac-sha-512" => Some(Self::HmacSha512),
            "aes-cmac-prf-128" => Some(Self::AesCmacPrf128),
            _ => None,
        }
    }
}

/// End of a lifetime window — IETF `choice end-time` collapsed to the
/// cases we actually parse from YANG (`infinite` / `duration` /
/// `end-date-time`). `NoEnd` is the default while a key is being
/// incrementally configured; the YANG layer makes `end-time`
/// mandatory once `start-date-time` is set.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub enum LifetimeEnd {
    /// `no-end-time` — key stays active forever after start.
    #[default]
    NoEnd,
    /// `duration` (seconds from start).
    Duration(u32),
    /// `end-date-time` — explicit absolute end.
    EndAt(DateTime<Utc>),
}

/// Send-lifetime / accept-lifetime window. IETF YANG models this as
/// an outer `choice lifetime { case always | case start-end-time }`.
/// `Always` is the natural default when neither `always` nor
/// `start-date-time` has been configured.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub enum Lifetime {
    /// `case always { leaf always { type empty; } }` — matches any
    /// time, the RFC 8177 "no time bounds" shorthand.
    #[default]
    Always,
    /// `case start-end-time { leaf start-date-time; choice end-time; }`.
    Window {
        start: DateTime<Utc>,
        end: LifetimeEnd,
    },
}

impl Lifetime {
    /// Is `now` inside this lifetime window?
    pub fn is_active(&self, now: DateTime<Utc>) -> bool {
        match self {
            Self::Always => true,
            Self::Window { start, end } => {
                if now < *start {
                    return false;
                }
                match end {
                    LifetimeEnd::NoEnd => true,
                    LifetimeEnd::EndAt(t) => now < *t,
                    LifetimeEnd::Duration(secs) => {
                        let limit = *start + Duration::seconds(i64::from(*secs));
                        now < limit
                    }
                }
            }
        }
    }
}

/// One key inside a chain. `algo` is `Option` because the YANG
/// `crypto-algorithm` leaf is set incrementally — a key may exist
/// transiently with `key-string` written but no algorithm yet, and
/// protocol-side resolution should treat algorithm-less keys as
/// unusable rather than crashing on `unwrap`.
///
/// `send_id`/`recv_id` are RFC 5925 §3.1 (TCP-AO) / RFC 5310 §3.1
/// (IS-IS generic-crypto) Key IDs. OSPFv2 carries an 8-bit key-id
/// in the cryptographic-auth header that doubles as both send and
/// receive identifier, so it ignores these fields and uses the
/// chain-level key-id key directly.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Key {
    pub algo: Option<CryptoAlgorithm>,
    /// Raw key bytes. ASCII when the YANG leaf is `keystring`,
    /// hex-decoded when it's `hexadecimal-string`. Empty until set.
    pub key_material: Vec<u8>,
    pub send_id: Option<u8>,
    pub recv_id: Option<u8>,
    pub send_lifetime: Lifetime,
    pub accept_lifetime: Lifetime,
}

/// Named RFC 8177 key chain. Keys are ordered by key-id (YANG-typed
/// as `uint64`; individual protocols narrow to u8/u16 at resolve
/// time).
///
/// `delete` is the cache-pattern flag inherited from the prefix-set /
/// community-set modules: the commit step inspects it to decide
/// whether to remove or insert the entry into the canonical map.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct KeyChain {
    pub description: Option<String>,
    pub keys: BTreeMap<u64, Key>,
    pub delete: bool,
}
