//! RFC 8177 key-chain data model for OSPFv2 cryptographic
//! authentication (Phase 4 of OSPF authentication).
//!
//! OSPF keeps its own in-memory registry separate from BGP's: both
//! daemons listen to `/key-chains/...` config commits and update
//! their own `key_chains: HashMap<String, _>` storage. The
//! per-interface `key-chain <name>` leaf references an entry here;
//! when set it supersedes the per-interface
//! `message-digest-key` / `crypto-key` lists for both send-side
//! selection and receive-side validation.
//!
//! Lifetimes follow IETF `ietf-key-chain@2017-06-15.yang`. Each key
//! carries a `send-lifetime` and `accept-lifetime`. The IETF
//! `send-and-accept-lifetime` shorthand (one window shared by both)
//! lowers to two identical `Lifetime` values at commit time.
//!
//! Send-id / recv-id are intentionally ignored — OSPFv2's
//! cryptographic-auth header carries a single 8-bit key-id field
//! that both endpoints share (RFC 2328 §D.3), so the IETF
//! per-direction id distinction doesn't apply.

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};

use super::link::OspfCryptoAlgo;

/// End of a lifetime window — IETF `choice end-time` collapsed to
/// the cases we actually parse (the YANG `infinite` / `duration` /
/// `end-date-time` choices).
///
/// The `NoEnd` default applies only while a key is being
/// incrementally configured; the YANG `end-time` choice is
/// mandatory once `start-date-time` is set.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub enum LifetimeEnd {
    /// `no-end-time` was set — key stays active forever after start.
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
/// `start-date-time` has been configured for a key.
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

/// One key inside an RFC 8177 chain. `algo` is `Option` because the
/// YANG `crypto-algorithm` leaf is set incrementally — a key may
/// exist transiently with `key-string` written but no algorithm yet.
/// Send / accept resolution treats algorithm-less keys as inactive.
#[derive(Debug, Clone, Default)]
pub struct OspfChainKey {
    pub algo: Option<OspfCryptoAlgo>,
    /// Raw key bytes. ASCII when the YANG leaf is `keystring`.
    pub key_material: Vec<u8>,
    pub send_lifetime: Lifetime,
    pub accept_lifetime: Lifetime,
}

impl OspfChainKey {
    pub fn is_send_active(&self, now: DateTime<Utc>) -> bool {
        self.algo.is_some() && !self.key_material.is_empty() && self.send_lifetime.is_active(now)
    }

    pub fn is_accept_active(&self, now: DateTime<Utc>) -> bool {
        self.algo.is_some() && !self.key_material.is_empty() && self.accept_lifetime.is_active(now)
    }
}

/// One named RFC 8177 key chain. Keys are ordered by key-id; send
/// selection scans low-to-high until an active key is found.
#[derive(Debug, Clone, Default)]
pub struct OspfKeyChain {
    pub description: Option<String>,
    pub keys: BTreeMap<u8, OspfChainKey>,
}

impl OspfKeyChain {
    /// Active send key (lowest key-id whose send-lifetime contains
    /// `now` and which has a usable algorithm + material). `None`
    /// when the chain is empty, mid-configuration, or fully expired.
    pub fn active_send_key(&self, now: DateTime<Utc>) -> Option<(u8, &OspfChainKey)> {
        self.keys
            .iter()
            .find(|(_, k)| k.is_send_active(now))
            .map(|(&id, k)| (id, k))
    }

    /// Look up the key the sender stamped (`key_id`) for receive-side
    /// validation. Returns the key only if its accept-lifetime
    /// contains `now`.
    pub fn lookup_recv_key(&self, key_id: u8, now: DateTime<Utc>) -> Option<&OspfChainKey> {
        self.keys.get(&key_id).filter(|k| k.is_accept_active(now))
    }
}

/// Parse the IETF `crypto-algorithm` identityref (e.g. `"md5"`,
/// `"hmac-sha-256"`, optionally prefixed `"ietf-key-chain:..."`)
/// into the OSPF-side enum. Algorithms outside the RFC 5709 +
/// keyed-MD5 set yield `None` — operators get a config error
/// rather than silently picking a different algorithm.
pub fn parse_crypto_algorithm(name: &str) -> Option<OspfCryptoAlgo> {
    let bare = name.rsplit(':').next().unwrap_or(name);
    match bare {
        "md5" => Some(OspfCryptoAlgo::Md5),
        "hmac-sha-1" => Some(OspfCryptoAlgo::HmacSha1),
        "hmac-sha-256" => Some(OspfCryptoAlgo::HmacSha256),
        "hmac-sha-384" => Some(OspfCryptoAlgo::HmacSha384),
        "hmac-sha-512" => Some(OspfCryptoAlgo::HmacSha512),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn ts(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    #[test]
    fn always_lifetime_always_active() {
        assert!(Lifetime::Always.is_active(Utc.timestamp_opt(0, 0).unwrap()));
        assert!(Lifetime::Always.is_active(Utc::now()));
    }

    #[test]
    fn window_no_end_open_ended() {
        let lt = Lifetime::Window {
            start: ts("2026-01-01T00:00:00Z"),
            end: LifetimeEnd::NoEnd,
        };
        assert!(!lt.is_active(ts("2025-12-31T23:59:59Z")));
        assert!(lt.is_active(ts("2026-01-01T00:00:00Z")));
        assert!(lt.is_active(ts("3000-01-01T00:00:00Z")));
    }

    #[test]
    fn window_explicit_end() {
        let lt = Lifetime::Window {
            start: ts("2026-01-01T00:00:00Z"),
            end: LifetimeEnd::EndAt(ts("2026-02-01T00:00:00Z")),
        };
        assert!(!lt.is_active(ts("2025-12-31T00:00:00Z")));
        assert!(lt.is_active(ts("2026-01-15T00:00:00Z")));
        assert!(!lt.is_active(ts("2026-02-01T00:00:00Z")));
        assert!(!lt.is_active(ts("2026-02-02T00:00:00Z")));
    }

    #[test]
    fn window_duration_derived_end() {
        let lt = Lifetime::Window {
            start: ts("2026-01-01T00:00:00Z"),
            end: LifetimeEnd::Duration(60),
        };
        assert!(lt.is_active(ts("2026-01-01T00:00:30Z")));
        assert!(!lt.is_active(ts("2026-01-01T00:01:00Z")));
    }

    #[test]
    fn active_send_picks_lowest_active_key() {
        let mut chain = OspfKeyChain::default();
        // Key 1 expired, key 2 active, key 3 not-yet-active.
        chain.keys.insert(
            1,
            OspfChainKey {
                algo: Some(OspfCryptoAlgo::HmacSha256),
                key_material: b"k1".to_vec(),
                send_lifetime: Lifetime::Window {
                    start: ts("2026-01-01T00:00:00Z"),
                    end: LifetimeEnd::EndAt(ts("2026-01-02T00:00:00Z")),
                },
                accept_lifetime: Lifetime::Always,
            },
        );
        chain.keys.insert(
            2,
            OspfChainKey {
                algo: Some(OspfCryptoAlgo::HmacSha256),
                key_material: b"k2".to_vec(),
                send_lifetime: Lifetime::Window {
                    start: ts("2026-01-02T00:00:00Z"),
                    end: LifetimeEnd::NoEnd,
                },
                accept_lifetime: Lifetime::Always,
            },
        );
        chain.keys.insert(
            3,
            OspfChainKey {
                algo: Some(OspfCryptoAlgo::HmacSha256),
                key_material: b"k3".to_vec(),
                send_lifetime: Lifetime::Window {
                    start: ts("2027-01-01T00:00:00Z"),
                    end: LifetimeEnd::NoEnd,
                },
                accept_lifetime: Lifetime::Always,
            },
        );

        let (id, _) = chain
            .active_send_key(ts("2026-06-01T00:00:00Z"))
            .expect("key 2 should be active");
        assert_eq!(id, 2);
    }

    #[test]
    fn lookup_recv_gates_on_accept_lifetime() {
        let mut chain = OspfKeyChain::default();
        chain.keys.insert(
            7,
            OspfChainKey {
                algo: Some(OspfCryptoAlgo::HmacSha256),
                key_material: b"shared".to_vec(),
                send_lifetime: Lifetime::Always,
                accept_lifetime: Lifetime::Window {
                    start: ts("2026-01-01T00:00:00Z"),
                    end: LifetimeEnd::EndAt(ts("2026-02-01T00:00:00Z")),
                },
            },
        );
        assert!(
            chain
                .lookup_recv_key(7, ts("2026-01-15T00:00:00Z"))
                .is_some()
        );
        assert!(
            chain
                .lookup_recv_key(7, ts("2026-02-15T00:00:00Z"))
                .is_none()
        );
        // Unknown key-id never matches.
        assert!(
            chain
                .lookup_recv_key(8, ts("2026-01-15T00:00:00Z"))
                .is_none()
        );
    }

    #[test]
    fn algo_without_material_is_inactive() {
        let key = OspfChainKey {
            algo: Some(OspfCryptoAlgo::HmacSha256),
            key_material: Vec::new(),
            send_lifetime: Lifetime::Always,
            accept_lifetime: Lifetime::Always,
        };
        assert!(!key.is_send_active(Utc::now()));
        assert!(!key.is_accept_active(Utc::now()));
    }

    #[test]
    fn parse_algorithm_accepts_bare_and_prefixed() {
        assert_eq!(parse_crypto_algorithm("md5"), Some(OspfCryptoAlgo::Md5));
        assert_eq!(
            parse_crypto_algorithm("hmac-sha-256"),
            Some(OspfCryptoAlgo::HmacSha256)
        );
        assert_eq!(
            parse_crypto_algorithm("ietf-key-chain:hmac-sha-512"),
            Some(OspfCryptoAlgo::HmacSha512)
        );
        assert_eq!(parse_crypto_algorithm("unknown-algo"), None);
    }
}
