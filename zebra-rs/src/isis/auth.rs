//! HMAC-MD5 sign/verify and Auth TLV plumbing for IS-IS Hello + SNP PDUs.
//!
//! Covers Hellos (per-link `hello-authentication`), CSNP/PSNP
//! (per-level `area-password` / `domain-password`), and LSP signing.
//! LSP signing needs additional treatment for the LSP Checksum and
//! Remaining Lifetime fields per RFC 5304 §3.
//!
//! Cleartext (auth-type 1) is just bytes-in-TLV-value: the send path
//! appends the password bytes verbatim, and the verify path compares
//! them. HMAC-MD5 (auth-type 54) is the two-pass case: emit a
//! zero-filled placeholder, hash the whole serialized PDU, then patch
//! the digest into the placeholder's byte range.

use std::ops::Range;

use bytes::BytesMut;
use hmac::{Hmac, KeyInit, Mac};
use isis_packet::{
    ISIS_AUTH_GENERIC_KEY_ID_LEN, ISIS_AUTH_HMAC_MD5_LEN, ISIS_AUTH_TYPE_CLEARTEXT,
    ISIS_AUTH_TYPE_GENERIC, ISIS_AUTH_TYPE_HMAC_MD5, IsisTlv, IsisTlvAuth, IsisTlvType,
};
use md5::Md5;
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};

use super::config::{IsisAuthConfig, IsisAuthType};

/// Fully resolved IS-IS auth send/verify parameters for one PDU.
/// Either side composes one of these from the IsisAuthConfig and,
/// when no inline password is set, the policy key-chain snapshot.
#[derive(Debug, Clone)]
pub struct ResolvedAuth {
    pub auth_type: IsisAuthType,
    pub key: Vec<u8>,
    /// On-wire key-id stamped in the RFC 5310 2-byte prefix.
    /// Ignored for `Text` / `Md5`.
    pub key_id: u16,
}

/// Project the policy algorithm enum onto the IS-IS subset.
/// AesCmacPrf128 belongs to TCP-AO's MUST-implement set per RFC
/// 5926 and isn't an IS-IS algorithm, so it returns `None` and the
/// resolve falls through (no auth on the wire).
fn isis_algo_from_policy(a: crate::policy::CryptoAlgorithm) -> Option<IsisAuthType> {
    use crate::policy::CryptoAlgorithm as P;
    match a {
        P::Md5 => Some(IsisAuthType::Md5),
        P::HmacSha1 => Some(IsisAuthType::HmacSha1),
        P::HmacSha256 => Some(IsisAuthType::HmacSha256),
        P::HmacSha384 => Some(IsisAuthType::HmacSha384),
        P::HmacSha512 => Some(IsisAuthType::HmacSha512),
        P::AesCmacPrf128 => None,
    }
}

/// Is this policy key usable for sending right now? RFC 8177 says a
/// key with no algorithm or no material is mid-configuration and
/// inactive; we also require its send-lifetime to bracket `now`.
fn chain_key_is_send_active(k: &crate::policy::Key, now: chrono::DateTime<chrono::Utc>) -> bool {
    k.algo.is_some() && !k.key_material.is_empty() && k.send_lifetime.is_active(now)
}

/// Same as `chain_key_is_send_active` but against accept-lifetime —
/// gates whether a received PDU stamped with this key-id is allowed
/// to verify.
fn chain_key_is_accept_active(k: &crate::policy::Key, now: chrono::DateTime<chrono::Utc>) -> bool {
    k.algo.is_some() && !k.key_material.is_empty() && k.accept_lifetime.is_active(now)
}

/// Resolve the send-side `(auth_type, key, key_id)` to use for this
/// scope. Inline `password` always wins when set — operators of the
/// historical simple-password setup keep their behavior, and the
/// `key-chain` leaf is only consulted when no inline password is
/// present. Returns `None` when neither path is configured, the
/// chain is missing, has no active key, or the active key uses an
/// algorithm IS-IS can't sign with.
pub fn resolve_send(
    cfg: &IsisAuthConfig,
    chains: &std::collections::BTreeMap<String, crate::policy::KeyChain>,
    now: chrono::DateTime<chrono::Utc>,
) -> Option<ResolvedAuth> {
    if let Some(pw) = cfg.password.as_deref() {
        return Some(ResolvedAuth {
            auth_type: cfg.auth_type,
            key: pw.as_bytes().to_vec(),
            key_id: cfg.effective_key_id(),
        });
    }
    let chain_name = cfg.key_chain.as_deref()?;
    let chain = chains.get(chain_name)?;
    let (id, key) = chain
        .keys
        .iter()
        .find(|(_, k)| chain_key_is_send_active(k, now))?;
    let auth_type = isis_algo_from_policy(key.algo?)?;
    // YANG key-id is uint64; the wire stamps a u16. Reject IDs that
    // wouldn't fit so the send path doesn't silently truncate.
    let key_id_u16: u16 = (*id).try_into().ok()?;
    Some(ResolvedAuth {
        auth_type,
        key: key.key_material.clone(),
        key_id: key_id_u16,
    })
}

/// Resolve the receive-side key bytes for an incoming PDU.
///
/// Inline `password` always wins — operators of the historical
/// simple-password setup keep their behavior, and the `key-chain`
/// leaf is only consulted when no inline password is set. For the
/// chain path:
///   - generic-crypto wire types carry the sender's RFC 5310 key-id
///     in the TLV prefix; the caller passes that as `wire_key_id`
///     and the lookup is an exact match.
///   - RFC 5304 MD5 doesn't carry a key-id; the caller passes
///     `None` and the helper picks the lowest accept-active key
///     whose algo matches `expected_mode`.
///
/// The chosen key's algo must match `expected_mode` so the verify
/// path doesn't compare digests of differing lengths.
pub fn resolve_recv(
    cfg: &IsisAuthConfig,
    chains: &std::collections::BTreeMap<String, crate::policy::KeyChain>,
    expected_mode: IsisAuthType,
    wire_key_id: Option<u16>,
    now: chrono::DateTime<chrono::Utc>,
) -> Option<Vec<u8>> {
    if let Some(pw) = cfg.password.as_deref() {
        return Some(pw.as_bytes().to_vec());
    }
    let chain_name = cfg.key_chain.as_deref()?;
    let chain = chains.get(chain_name)?;
    let key = match wire_key_id {
        Some(id) => chain.keys.get(&u64::from(id))?,
        None => {
            // No wire key-id — find the lowest accept-active key
            // whose algo matches what the wire claims.
            chain.keys.values().find(|k| {
                chain_key_is_accept_active(k, now)
                    && k.algo
                        .and_then(isis_algo_from_policy)
                        .is_some_and(|a| a == expected_mode)
            })?
        }
    };
    if !chain_key_is_accept_active(key, now) {
        return None;
    }
    let algo = isis_algo_from_policy(key.algo?)?;
    if algo != expected_mode {
        return None;
    }
    Some(key.key_material.clone())
}

/// HMAC-MD5 over `data` keyed by `key` (RFC 2104 / RFC 5304 §3).
/// Returns the 16-byte digest. `Hmac::new_from_slice` accepts any
/// key length — internally hashed/padded to the MD5 block size.
pub fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut mac = <Hmac<Md5>>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut digest = [0u8; 16];
    digest.copy_from_slice(&out[..16]);
    digest
}

/// HMAC over arbitrary data with the algorithm selected by
/// `algo` — md5 (RFC 5304) or the RFC 5310 SHA family. Returns
/// the variable-length digest as a Vec so the caller can compare
/// it with whatever the wire format carries.
pub fn hmac_for_algo(algo: IsisAuthType, key: &[u8], data: &[u8]) -> Vec<u8> {
    match algo {
        IsisAuthType::Text | IsisAuthType::Md5 => hmac_md5(key, data).to_vec(),
        IsisAuthType::HmacSha1 => {
            let mut m = <Hmac<Sha1>>::new_from_slice(key).expect("HMAC accepts any key length");
            m.update(data);
            m.finalize().into_bytes().to_vec()
        }
        IsisAuthType::HmacSha256 => {
            let mut m = <Hmac<Sha256>>::new_from_slice(key).expect("HMAC accepts any key length");
            m.update(data);
            m.finalize().into_bytes().to_vec()
        }
        IsisAuthType::HmacSha384 => {
            let mut m = <Hmac<Sha384>>::new_from_slice(key).expect("HMAC accepts any key length");
            m.update(data);
            m.finalize().into_bytes().to_vec()
        }
        IsisAuthType::HmacSha512 => {
            let mut m = <Hmac<Sha512>>::new_from_slice(key).expect("HMAC accepts any key length");
            m.update(data);
            m.finalize().into_bytes().to_vec()
        }
    }
}

/// RFC 5310 §3.3 "Apad" — the value 0x878FE1F3 repeated `L/4` times
/// where L is the digest length. The IS-IS PDU's Authentication
/// Data field is set to Apad during the HMAC computation, then
/// replaced with the resulting digest on the wire.
pub fn apad(digest_len: usize) -> Vec<u8> {
    const APAD_WORD: [u8; 4] = [0x87, 0x8F, 0xE1, 0xF3];
    let mut out = Vec::with_capacity(digest_len);
    while out.len() < digest_len {
        let remaining = digest_len - out.len();
        let take = remaining.min(APAD_WORD.len());
        out.extend_from_slice(&APAD_WORD[..take]);
    }
    out
}

/// Constant-time byte comparison so a partial-match digest doesn't
/// leak timing information to an attacker probing different keys.
pub fn digest_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// On-wire byte cost of the Auth TLV this scope would emit (2-byte
/// header + 1-byte auth-type + payload), used by the SNP packer to
/// shrink its fragmentation budget so a CSNP/PSNP stays within MTU
/// once the TLV is appended. Returns 0 when no auth is configured.
///
/// Generic-crypto (RFC 5310) values are 1 (auth-type) + 2 (Key ID)
/// + digest-length, which is bigger than RFC 5304's md5 layout.
pub fn auth_tlv_wire_size(resolved: Option<&ResolvedAuth>) -> usize {
    let Some(r) = resolved else {
        return 0;
    };
    match r.auth_type {
        IsisAuthType::Text => 2 + 1 + r.key.len(),
        IsisAuthType::Md5 => 2 + 1 + ISIS_AUTH_HMAC_MD5_LEN,
        algo if algo.is_generic_crypto() => {
            2 + 1 + ISIS_AUTH_GENERIC_KEY_ID_LEN + algo.digest_len()
        }
        _ => 0,
    }
}

/// Append the Authentication TLV (type 10) to `tlvs` when this scope
/// has authentication configured. For cleartext the value is the
/// password bytes verbatim; for HMAC-MD5 it's a zero-filled
/// placeholder. For RFC 5310 generic crypto, the placeholder is the
/// Key-ID prefix followed by an Apad-filled digest area — `sign`
/// will patch the real HMAC over the Apad bytes once computed.
pub fn append_auth_tlv(tlvs: &mut Vec<IsisTlv>, resolved: Option<&ResolvedAuth>) {
    let Some(r) = resolved else {
        return;
    };
    let tlv = match r.auth_type {
        IsisAuthType::Text => IsisTlvAuth {
            auth_type: ISIS_AUTH_TYPE_CLEARTEXT,
            value: r.key.clone(),
        },
        IsisAuthType::Md5 => {
            IsisTlvAuth::placeholder(ISIS_AUTH_TYPE_HMAC_MD5, ISIS_AUTH_HMAC_MD5_LEN)
        }
        algo if algo.is_generic_crypto() => {
            let digest_len = algo.digest_len();
            let mut value = Vec::with_capacity(ISIS_AUTH_GENERIC_KEY_ID_LEN + digest_len);
            value.extend_from_slice(&r.key_id.to_be_bytes());
            value.extend_from_slice(&apad(digest_len));
            IsisTlvAuth {
                auth_type: ISIS_AUTH_TYPE_GENERIC,
                value,
            }
        }
        _ => return,
    };
    tlvs.push(tlv.into());
}

/// Two-pass HMAC sign step for Hello / SNP PDUs. Locate the Auth TLV
/// inside the just-emitted PDU bytes, compute the HMAC over the
/// buffer (the placeholder's digest area is already filled with
/// zero or Apad depending on `algo`, matching RFC 5304 §3 /
/// RFC 5310 §3.3), and patch the resulting digest into place.
/// No-op when the TLV isn't found, the digest area length doesn't
/// match `algo`, or `algo` isn't an HMAC algorithm.
pub fn sign_inplace(buf: &mut BytesMut, tlvs_start: usize, algo: IsisAuthType, key: &[u8]) {
    let Some(value_range) = locate_auth_tlv(buf, tlvs_start) else {
        return;
    };
    let digest_start = digest_start_for(value_range.start, algo);
    let digest_end = value_range.end;
    if digest_end <= digest_start {
        return;
    }
    if digest_end - digest_start != algo.digest_len() {
        return;
    }
    if !matches!(algo, IsisAuthType::Md5) && !algo.is_generic_crypto() {
        return;
    }
    let digest = hmac_for_algo(algo, key, buf);
    buf[digest_start..digest_end].copy_from_slice(&digest);
}

/// Byte offset where the digest area starts inside an Auth TLV's
/// value, relative to the TLV value's first byte. For RFC 5304 the
/// digest follows the 1-byte auth-type; for RFC 5310 it follows
/// auth-type + 2-byte Key ID.
fn digest_start_for(value_start: usize, algo: IsisAuthType) -> usize {
    let header = 1usize
        + if algo.is_generic_crypto() {
            ISIS_AUTH_GENERIC_KEY_ID_LEN
        } else {
            0
        };
    value_start + header
}

/// LSP fixed-header offsets relative to the IS-IS discriminator
/// (byte 0). Per ISO 10589 §9.10 / RFC 5304 §3, HMAC for LSPs is
/// computed with Remaining Lifetime and Fletcher Checksum zeroed.
pub const LSP_REMAINING_LIFETIME_RANGE: std::ops::Range<usize> = 10..12;
pub const LSP_CHECKSUM_RANGE: std::ops::Range<usize> = 24..26;
/// First TLV byte for an LSP (length_indicator = 27).
pub const LSP_TLVS_START: usize = 27;

/// Two-pass HMAC-MD5 sign step for LSPs (RFC 5304 §3). LSPs need
/// extra care versus Hello/SNP:
///   1. Remaining Lifetime is zeroed during the hash so the digest
///      stays valid as the LSP ages across the network.
///   2. Fletcher Checksum is zeroed too — the sender stamps it
///      *after* the HMAC is patched in, otherwise the checksum
///      would not cover the digest bytes the receiver checks.
///
/// `buf` must contain a serialized LSP PDU with an Auth TLV whose
/// digest area is zero-filled (i.e., `IsisTlvAuth::placeholder` was
/// added before `IsisPacket::emit`). On exit, the Auth Value carries
/// the HMAC and the Fletcher Checksum has been re-stamped to cover
/// the patched bytes.
pub fn sign_lsp_inplace(buf: &mut BytesMut, algo: IsisAuthType, key: &[u8]) {
    let Some(value_range) = locate_auth_tlv(buf, LSP_TLVS_START) else {
        return;
    };
    let digest_start = digest_start_for(value_range.start, algo);
    let digest_end = value_range.end;
    if digest_end <= digest_start {
        return;
    }
    if digest_end - digest_start != algo.digest_len() {
        return;
    }
    if !matches!(algo, IsisAuthType::Md5) && !algo.is_generic_crypto() {
        return;
    }

    // Compute HMAC over a copy with Remaining Lifetime + Checksum
    // zeroed. The Auth Value bytes carry the placeholder fill
    // (zero for md5, Apad for RFC 5310) which is what the digest
    // is meant to be computed over per the respective RFCs.
    let mut scratch = buf.to_vec();
    for b in &mut scratch[LSP_REMAINING_LIFETIME_RANGE] {
        *b = 0;
    }
    for b in &mut scratch[LSP_CHECKSUM_RANGE] {
        *b = 0;
    }
    let digest = hmac_for_algo(algo, key, &scratch);

    // Patch the HMAC into the live buffer at the auth-value range,
    // then re-stamp Fletcher over the bytes that now carry the
    // digest. `checksum_calc` assumes the checksum field reads as
    // zero (the existing IsisPacket::emit path satisfies that
    // implicitly by emitting with `IsisLsp.checksum = 0`), so zero
    // it explicitly before the recompute since the buffer already
    // carries an emit-time stamp.
    buf[digest_start..digest_end].copy_from_slice(&digest);
    if buf.len() >= LSP_CHECKSUM_RANGE.end {
        for b in &mut buf[LSP_CHECKSUM_RANGE] {
            *b = 0;
        }
        let checksum = isis_packet::checksum_calc(&buf[12..]);
        buf[LSP_CHECKSUM_RANGE].copy_from_slice(&checksum);
    }
}

/// Walk the TLV section starting at `tlvs_start` and return the byte
/// range covering the Auth TLV's *value* — i.e., the auth-type byte
/// plus the digest/password that follows. Returns `None` if no Auth
/// TLV is present, or if a TLV header would run off the end of
/// `pdu` (malformed input is treated as "no auth").
///
/// `tlvs_start` is the offset at which the first TLV header begins;
/// for a freshly-received IS-IS PDU that's the value of the
/// `length_indicator` field in the common header (e.g. 27 for
/// IIH/L1Hello/L2Hello, 20 for P2P Hello, 33 for CSNP, 17 for PSNP).
pub fn locate_auth_tlv(pdu: &[u8], tlvs_start: usize) -> Option<Range<usize>> {
    let auth_typ = u8::from(IsisTlvType::Auth);
    let mut i = tlvs_start;
    while i + 2 <= pdu.len() {
        let typ = pdu[i];
        let len = pdu[i + 1] as usize;
        let value_start = i + 2;
        let value_end = value_start.checked_add(len)?;
        if value_end > pdu.len() {
            return None;
        }
        if typ == auth_typ {
            return Some(value_start..value_end);
        }
        i = value_end;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// HMAC-MD5 reference vector from RFC 2202 §2 test case 1:
    /// key = 0x0b * 16, data = "Hi There" → 9294727a3638bb1c13f48ef8158bfc9d.
    #[test]
    fn hmac_md5_matches_rfc2202_vector_1() {
        let key = [0x0bu8; 16];
        let data = b"Hi There";
        let got = hmac_md5(&key, data);
        let want = [
            0x92, 0x94, 0x72, 0x7a, 0x36, 0x38, 0xbb, 0x1c, 0x13, 0xf4, 0x8e, 0xf8, 0x15, 0x8b,
            0xfc, 0x9d,
        ];
        assert_eq!(got, want);
    }

    #[test]
    fn digest_eq_rejects_length_mismatch() {
        assert!(!digest_eq(&[1, 2, 3], &[1, 2]));
        assert!(!digest_eq(&[1, 2, 3], &[1, 2, 3, 4]));
        assert!(digest_eq(&[1, 2, 3], &[1, 2, 3]));
    }

    #[test]
    fn digest_eq_is_byte_exact() {
        assert!(!digest_eq(&[1, 2, 3], &[1, 2, 4]));
        assert!(digest_eq(&[], &[]));
    }

    /// Locator returns the byte range of the Auth TLV's value field
    /// (auth-type + payload). Verify against a tiny hand-built PDU
    /// with two TLVs preceding the Auth TLV so the walker has to
    /// skip past them.
    #[test]
    fn locate_auth_tlv_finds_value_range() {
        // Fake PDU header (3 bytes, not actually parsed by this
        // helper — we just use tlvs_start=3 to skip them).
        // Then: TLV 1 (AreaAddr) len 2, TLV 9 (LspEntries) len 0,
        // TLV 10 (Auth) len 17 (1 byte auth-type + 16 bytes digest).
        let mut pdu = vec![0xAA, 0xBB, 0xCC];
        pdu.extend_from_slice(&[1, 2, 0xDE, 0xAD]); // AreaAddr
        pdu.extend_from_slice(&[9, 0]); // empty LspEntries
        pdu.extend_from_slice(&[10, 17, 54]); // Auth, len 17, auth-type 54
        pdu.extend_from_slice(&[0xFFu8; 16]); // digest

        let range = locate_auth_tlv(&pdu, 3).expect("auth TLV present");
        assert_eq!(range.start, 3 + 4 + 2 + 2); // past 3-byte hdr + TLV1 + TLV9 + 2-byte Auth header
        assert_eq!(range.len(), 17);
        assert_eq!(pdu[range.start], 54); // auth-type byte
    }

    #[test]
    fn locate_auth_tlv_returns_none_when_absent() {
        let mut pdu = vec![0xAA, 0xBB, 0xCC];
        pdu.extend_from_slice(&[1, 2, 0xDE, 0xAD]);
        assert!(locate_auth_tlv(&pdu, 3).is_none());
    }

    #[test]
    fn locate_auth_tlv_rejects_truncated_value() {
        // Auth TLV header claims length 17 but value bytes are missing.
        let mut pdu = vec![0xAA, 0xBB, 0xCC];
        pdu.extend_from_slice(&[10, 17]); // header only
        assert!(locate_auth_tlv(&pdu, 3).is_none());
    }

    /// End-to-end HMAC-MD5 round-trip across a real Hello PDU: emit a
    /// Hello with a zero-filled Auth TLV placeholder, sign the
    /// resulting bytes, then verify them by zeroing the digest area
    /// in a copy and recomputing. Mirrors the sign side of
    /// `ifsm::sign_hello_md5_inplace` and the verify side of
    /// `packet::verify_hello_auth` without needing LinkTop scaffolding.
    #[test]
    fn hello_pdu_md5_round_trip_via_helpers() {
        use bytes::BytesMut;
        use isis_packet::{
            ISIS_AUTH_HMAC_MD5_LEN, ISIS_AUTH_TYPE_HMAC_MD5, IsLevel, IsisHello, IsisNeighborId,
            IsisPacket, IsisPdu, IsisSysId, IsisTlv, IsisTlvAreaAddr, IsisTlvAuth, IsisType,
        };

        let mut hello = IsisHello {
            circuit_type: IsLevel::L1L2,
            source_id: IsisSysId {
                id: [1, 2, 3, 4, 5, 6],
            },
            hold_time: 30,
            pdu_len: 0,
            priority: 64,
            lan_id: IsisNeighborId::default(),
            tlvs: vec![
                IsisTlv::AreaAddr(IsisTlvAreaAddr {
                    area_addr: vec![0x49, 0x00, 0x01],
                }),
                IsisTlv::Auth(IsisTlvAuth::placeholder(
                    ISIS_AUTH_TYPE_HMAC_MD5,
                    ISIS_AUTH_HMAC_MD5_LEN,
                )),
            ],
        };
        let packet = IsisPacket::from(IsisType::L1Hello, IsisPdu::L1Hello(hello.clone()));
        let mut buf = BytesMut::new();
        packet.emit(&mut buf);

        // Sign: locate the auth TLV, compute HMAC over the buffer
        // (digest area still zero), patch the digest in.
        let key = b"hunter2";
        let value_range = locate_auth_tlv(&buf, packet.length_indicator as usize)
            .expect("auth TLV must be present");
        let digest_start = value_range.start + 1;
        let digest_end = value_range.end;
        let digest = hmac_md5(key, &buf);
        buf[digest_start..digest_end].copy_from_slice(&digest);

        // Verify: zero the digest area in a copy, recompute, compare
        // against the bytes the "sender" wrote into the patched buffer.
        let mut scratch = buf.to_vec();
        let stored_digest = buf[digest_start..digest_end].to_vec();
        for b in &mut scratch[digest_start..digest_end] {
            *b = 0;
        }
        let recomputed = hmac_md5(key, &scratch);
        assert!(digest_eq(&recomputed, &stored_digest));
        // Also: the stored digest should not be all-zero anymore.
        assert!(stored_digest.iter().any(|b| *b != 0));

        // Negative: flip a digest byte, recompute → mismatch.
        buf[digest_start] ^= 0x01;
        let tampered_stored = buf[digest_start..digest_end].to_vec();
        let mut scratch = buf.to_vec();
        for b in &mut scratch[digest_start..digest_end] {
            *b = 0;
        }
        let recomputed = hmac_md5(key, &scratch);
        assert!(!digest_eq(&recomputed, &tampered_stored));

        // Negative: wrong key.
        let recomputed_wrong_key = hmac_md5(b"wrong-key", &scratch);
        assert!(!digest_eq(&recomputed_wrong_key, &tampered_stored));

        // Touch `hello` so the binding compiles cleanly under the
        // `-D warnings` clippy gate; cloned into the packet above.
        hello.pdu_len = 0;
    }

    /// Cleartext (auth-type 1) is a plain byte-compare; verify
    /// matches the configured password and rejects mismatches.
    #[test]
    fn cleartext_password_compare() {
        let password = b"hunter2";
        let value = password.to_vec();
        assert!(digest_eq(&value, password));
        assert!(!digest_eq(&value, b"hunter3"));
        assert!(!digest_eq(&value, b""));
    }

    /// auth_tlv_wire_size exposes the on-wire byte count the SNP
    /// packer subtracts from its per-fragment entry budget. Verify
    /// it matches what `IsisTlv::wire_len()` reports for the same
    /// configured TLV (the function the packer would build).
    #[test]
    fn auth_tlv_wire_size_matches_emit_length() {
        let chains = std::collections::BTreeMap::new();
        let now = chrono::Utc::now();

        // Cleartext: TL header (2) + auth-type (1) + password bytes.
        let cfg = IsisAuthConfig {
            password: Some("hunter2".into()),
            auth_type: IsisAuthType::Text,
            key_id: 0,
            send_only: false,
            key_chain: None,
        };
        let tlv: IsisTlv = IsisTlvAuth {
            auth_type: ISIS_AUTH_TYPE_CLEARTEXT,
            value: b"hunter2".to_vec(),
        }
        .into();
        let resolved = resolve_send(&cfg, &chains, now);
        assert_eq!(auth_tlv_wire_size(resolved.as_ref()), tlv.wire_len());

        // HMAC-MD5: TL header (2) + auth-type (1) + 16-byte digest.
        let cfg = IsisAuthConfig {
            password: Some("hunter2".into()),
            auth_type: IsisAuthType::Md5,
            key_id: 0,
            send_only: false,
            key_chain: None,
        };
        let tlv: IsisTlv =
            IsisTlvAuth::placeholder(ISIS_AUTH_TYPE_HMAC_MD5, ISIS_AUTH_HMAC_MD5_LEN).into();
        let resolved = resolve_send(&cfg, &chains, now);
        assert_eq!(auth_tlv_wire_size(resolved.as_ref()), tlv.wire_len());

        // No auth → 0 bytes.
        let cfg = IsisAuthConfig::default();
        let resolved = resolve_send(&cfg, &chains, now);
        assert_eq!(auth_tlv_wire_size(resolved.as_ref()), 0);
    }

    /// End-to-end HMAC-MD5 round-trip across a real CSNP — same
    /// shape as the Hello test but with `length_indicator = 33`
    /// (CSNP header is bigger).
    #[test]
    fn csnp_pdu_md5_round_trip_via_helpers() {
        use isis_packet::{
            IsisCsnp, IsisLspId, IsisPacket, IsisPdu, IsisSysId, IsisTlv, IsisTlvAuth,
            IsisTlvLspEntries, IsisType,
        };

        let csnp = IsisCsnp {
            pdu_len: 0,
            source_id: IsisSysId {
                id: [1, 2, 3, 4, 5, 6],
            },
            source_id_circuit: 0,
            start: IsisLspId::start(),
            end: IsisLspId::end(),
            tlvs: vec![
                IsisTlv::LspEntries(IsisTlvLspEntries::default()),
                IsisTlv::Auth(IsisTlvAuth::placeholder(
                    ISIS_AUTH_TYPE_HMAC_MD5,
                    ISIS_AUTH_HMAC_MD5_LEN,
                )),
            ],
        };
        let packet = IsisPacket::from(IsisType::L1Csnp, IsisPdu::L1Csnp(csnp));
        let mut buf = BytesMut::new();
        packet.emit(&mut buf);

        let key = b"area-key";
        sign_inplace(
            &mut buf,
            packet.length_indicator as usize,
            IsisAuthType::Md5,
            key,
        );

        // Verify: peel out the patched digest, zero its range, recompute.
        let range = locate_auth_tlv(&buf, packet.length_indicator as usize).unwrap();
        let digest_start = range.start + 1;
        let digest_end = range.end;
        let stored = buf[digest_start..digest_end].to_vec();
        let mut scratch = buf.to_vec();
        for b in &mut scratch[digest_start..digest_end] {
            *b = 0;
        }
        assert!(digest_eq(&hmac_md5(key, &scratch), &stored));
        assert!(stored.iter().any(|b| *b != 0));

        // Wrong key → mismatch.
        assert!(!digest_eq(&hmac_md5(b"wrong", &scratch), &stored));
    }

    /// LSP HMAC-MD5 round-trip. Exercises the full sign_lsp_md5_inplace
    /// flow (zero lifetime + zero checksum + zero auth-value, HMAC,
    /// patch, re-stamp Fletcher) and the verify-side mirror.
    #[test]
    fn lsp_pdu_md5_round_trip_via_helpers() {
        use isis_packet::{
            IsisLsp, IsisLspId, IsisPacket, IsisPdu, IsisSysId, IsisTlv, IsisTlvAreaAddr,
            IsisTlvAuth, IsisType,
        };

        let lsp = IsisLsp {
            pdu_len: 0,
            hold_time: 1200,
            lsp_id: IsisLspId::new(
                IsisSysId {
                    id: [1, 2, 3, 4, 5, 6],
                },
                0,
                0,
            ),
            seq_number: 0x12,
            checksum: 0, // emit overwrites with real Fletcher
            types: Default::default(),
            tlvs: vec![
                IsisTlv::AreaAddr(IsisTlvAreaAddr {
                    area_addr: vec![0x49, 0x00, 0x01],
                }),
                IsisTlv::Auth(IsisTlvAuth::placeholder(
                    ISIS_AUTH_TYPE_HMAC_MD5,
                    ISIS_AUTH_HMAC_MD5_LEN,
                )),
            ],
        };
        let packet = IsisPacket::from(IsisType::L1Lsp, IsisPdu::L1Lsp(lsp));
        let mut buf = BytesMut::new();
        packet.emit(&mut buf);

        let key = b"area-key";
        sign_lsp_inplace(&mut buf, IsisAuthType::Md5, key);

        // Verify mirrors the recv side: zero lifetime + checksum +
        // auth-value, recompute, compare.
        let range = locate_auth_tlv(&buf, LSP_TLVS_START).unwrap();
        let digest_start = range.start + 1;
        let digest_end = range.end;
        let stored = buf[digest_start..digest_end].to_vec();

        let mut scratch = buf.to_vec();
        for b in &mut scratch[digest_start..digest_end] {
            *b = 0;
        }
        for b in &mut scratch[LSP_REMAINING_LIFETIME_RANGE] {
            *b = 0;
        }
        for b in &mut scratch[LSP_CHECKSUM_RANGE] {
            *b = 0;
        }
        assert!(digest_eq(&hmac_md5(key, &scratch), &stored));

        // Aging: simulate a peer decrementing the Remaining Lifetime
        // mid-flood. Receivers zero it before HMAC, so the digest
        // stays valid.
        let mut aged = buf.clone();
        aged[10..12].copy_from_slice(&100u16.to_be_bytes());
        let mut scratch_aged = aged.to_vec();
        for b in &mut scratch_aged[digest_start..digest_end] {
            *b = 0;
        }
        for b in &mut scratch_aged[LSP_REMAINING_LIFETIME_RANGE] {
            *b = 0;
        }
        for b in &mut scratch_aged[LSP_CHECKSUM_RANGE] {
            *b = 0;
        }
        let recomputed_aged = hmac_md5(key, &scratch_aged);
        assert!(
            digest_eq(&recomputed_aged, &stored),
            "HMAC must survive Remaining Lifetime decrement"
        );

        // Fletcher checksum must validate over the patched-digest
        // buffer (sign_lsp_md5_inplace re-stamps it).
        assert!(isis_packet::is_valid_checksum(&buf));

        // Tampering the body invalidates the digest.
        let mut tampered = buf.clone();
        tampered[28] ^= 0x01; // somewhere in the AreaAddr TLV value
        let mut scratch_t = tampered.to_vec();
        for b in &mut scratch_t[digest_start..digest_end] {
            *b = 0;
        }
        for b in &mut scratch_t[LSP_REMAINING_LIFETIME_RANGE] {
            *b = 0;
        }
        for b in &mut scratch_t[LSP_CHECKSUM_RANGE] {
            *b = 0;
        }
        assert!(!digest_eq(&hmac_md5(key, &scratch_t), &stored));
    }

    /// RFC 6232 purge: an LSP with Remaining Lifetime = 0 and no body
    /// TLVs (only the Auth TLV) must still produce a verifiable HMAC.
    #[test]
    fn lsp_purge_md5_round_trip() {
        use isis_packet::{
            IsisLsp, IsisLspId, IsisPacket, IsisPdu, IsisSysId, IsisTlv, IsisTlvAuth, IsisType,
        };

        let lsp = IsisLsp {
            pdu_len: 0,
            hold_time: 0, // purge
            lsp_id: IsisLspId::new(
                IsisSysId {
                    id: [7, 7, 7, 7, 7, 7],
                },
                0,
                3,
            ),
            seq_number: 42,
            checksum: 0,
            types: Default::default(),
            tlvs: vec![IsisTlv::Auth(IsisTlvAuth::placeholder(
                ISIS_AUTH_TYPE_HMAC_MD5,
                ISIS_AUTH_HMAC_MD5_LEN,
            ))],
        };
        let packet = IsisPacket::from(IsisType::L2Lsp, IsisPdu::L2Lsp(lsp));
        let mut buf = BytesMut::new();
        packet.emit(&mut buf);

        let key = b"domain-key";
        sign_lsp_inplace(&mut buf, IsisAuthType::Md5, key);

        let range = locate_auth_tlv(&buf, LSP_TLVS_START).unwrap();
        let digest_start = range.start + 1;
        let digest_end = range.end;
        let stored = buf[digest_start..digest_end].to_vec();

        let mut scratch = buf.to_vec();
        for b in &mut scratch[digest_start..digest_end] {
            *b = 0;
        }
        for b in &mut scratch[LSP_REMAINING_LIFETIME_RANGE] {
            *b = 0;
        }
        for b in &mut scratch[LSP_CHECKSUM_RANGE] {
            *b = 0;
        }
        assert!(digest_eq(&hmac_md5(key, &scratch), &stored));
        assert!(isis_packet::is_valid_checksum(&buf));
    }

    /// End-to-end HMAC-MD5 round-trip across a real PSNP. Verifies
    /// `length_indicator = 17` works the same.
    #[test]
    fn psnp_pdu_md5_round_trip_via_helpers() {
        use isis_packet::{
            IsisPacket, IsisPdu, IsisPsnp, IsisSysId, IsisTlv, IsisTlvAuth, IsisTlvLspEntries,
            IsisType,
        };

        let psnp = IsisPsnp {
            pdu_len: 0,
            source_id: IsisSysId {
                id: [9, 8, 7, 6, 5, 4],
            },
            source_id_circuit: 0,
            tlvs: vec![
                IsisTlv::LspEntries(IsisTlvLspEntries::default()),
                IsisTlv::Auth(IsisTlvAuth::placeholder(
                    ISIS_AUTH_TYPE_HMAC_MD5,
                    ISIS_AUTH_HMAC_MD5_LEN,
                )),
            ],
        };
        let packet = IsisPacket::from(IsisType::L2Psnp, IsisPdu::L2Psnp(psnp));
        let mut buf = BytesMut::new();
        packet.emit(&mut buf);

        let key = b"domain-key";
        sign_inplace(
            &mut buf,
            packet.length_indicator as usize,
            IsisAuthType::Md5,
            key,
        );

        let range = locate_auth_tlv(&buf, packet.length_indicator as usize).unwrap();
        let digest_start = range.start + 1;
        let digest_end = range.end;
        let stored = buf[digest_start..digest_end].to_vec();
        let mut scratch = buf.to_vec();
        for b in &mut scratch[digest_start..digest_end] {
            *b = 0;
        }
        assert!(digest_eq(&hmac_md5(key, &scratch), &stored));
    }

    /// RFC 5310 §3.3: Apad is 0x878FE1F3 repeated L/4 times.
    /// Verify the helper produces the right pattern at the digest
    /// lengths the IS-IS auth-type table allows.
    #[test]
    fn apad_pattern_repeats() {
        let p = apad(20);
        assert_eq!(p.len(), 20);
        assert_eq!(&p[0..4], &[0x87, 0x8F, 0xE1, 0xF3]);
        assert_eq!(&p[16..20], &[0x87, 0x8F, 0xE1, 0xF3]);

        let p = apad(64);
        assert_eq!(p.len(), 64);
        for chunk in p.chunks(4) {
            assert_eq!(chunk, &[0x87, 0x8F, 0xE1, 0xF3]);
        }
    }

    /// End-to-end HMAC-SHA256 round-trip across a real Hello PDU.
    /// Mirrors the md5 path but with the RFC 5310 wire shape:
    /// auth-type 3, 2-byte Key ID, 32-byte digest area filled with
    /// Apad before the HMAC.
    #[test]
    fn hello_pdu_sha256_round_trip_via_helpers() {
        use isis_packet::{
            IsLevel, IsisHello, IsisNeighborId, IsisPacket, IsisPdu, IsisSysId, IsisTlv,
            IsisTlvAreaAddr, IsisType,
        };

        let cfg = IsisAuthConfig {
            password: Some("sha-key".into()),
            auth_type: IsisAuthType::HmacSha256,
            key_id: 42,
            send_only: false,
            key_chain: None,
        };
        let mut tlvs = vec![IsisTlv::AreaAddr(IsisTlvAreaAddr {
            area_addr: vec![0x49, 0x00, 0x01],
        })];
        let chains = std::collections::BTreeMap::new();
        let resolved = resolve_send(&cfg, &chains, chrono::Utc::now());
        append_auth_tlv(&mut tlvs, resolved.as_ref());

        let hello = IsisHello {
            circuit_type: IsLevel::L1L2,
            source_id: IsisSysId {
                id: [1, 2, 3, 4, 5, 6],
            },
            hold_time: 30,
            pdu_len: 0,
            priority: 64,
            lan_id: IsisNeighborId::default(),
            tlvs,
        };
        let packet = IsisPacket::from(IsisType::L1Hello, IsisPdu::L1Hello(hello));
        let mut buf = BytesMut::new();
        packet.emit(&mut buf);

        sign_inplace(
            &mut buf,
            packet.length_indicator as usize,
            IsisAuthType::HmacSha256,
            cfg.password.as_deref().unwrap().as_bytes(),
        );

        // Locate auth TLV value: [auth-type=3, key_id(2), digest(32)].
        let range = locate_auth_tlv(&buf, packet.length_indicator as usize).unwrap();
        assert_eq!(buf[range.start], ISIS_AUTH_TYPE_GENERIC);
        let key_id = u16::from_be_bytes(buf[range.start + 1..range.start + 3].try_into().unwrap());
        assert_eq!(key_id, 42);

        let digest_start = range.start + 1 + ISIS_AUTH_GENERIC_KEY_ID_LEN;
        let digest_end = range.end;
        assert_eq!(digest_end - digest_start, 32);
        let stored = buf[digest_start..digest_end].to_vec();
        // Patched digest is no longer Apad.
        assert_ne!(stored, apad(32));

        // Verify: replace digest area with Apad, recompute HMAC,
        // compare. Mirrors `verify_hmac` in packet.rs.
        let mut scratch = buf.to_vec();
        let apad32 = apad(32);
        scratch[digest_start..digest_end].copy_from_slice(&apad32);
        let computed = hmac_for_algo(
            IsisAuthType::HmacSha256,
            cfg.password.as_deref().unwrap().as_bytes(),
            &scratch,
        );
        assert!(digest_eq(&computed, &stored));

        // Wrong key → mismatch.
        let bad = hmac_for_algo(IsisAuthType::HmacSha256, b"wrong", &scratch);
        assert!(!digest_eq(&bad, &stored));
    }

    /// LSP HMAC-SHA512 round-trip — exercises the LSP-specific
    /// lifetime+checksum zeroing and Fletcher re-stamping with the
    /// 64-byte digest.
    #[test]
    fn lsp_pdu_sha512_round_trip_via_helpers() {
        use isis_packet::{
            IsisLsp, IsisLspId, IsisPacket, IsisPdu, IsisSysId, IsisTlv, IsisTlvAreaAddr, IsisType,
        };

        let cfg = IsisAuthConfig {
            password: Some("lsp-sha-key".into()),
            auth_type: IsisAuthType::HmacSha512,
            key_id: 9,
            send_only: false,
            key_chain: None,
        };
        let mut tlvs = vec![IsisTlv::AreaAddr(IsisTlvAreaAddr {
            area_addr: vec![0x49, 0x00, 0x01],
        })];
        let chains = std::collections::BTreeMap::new();
        let resolved = resolve_send(&cfg, &chains, chrono::Utc::now());
        append_auth_tlv(&mut tlvs, resolved.as_ref());
        let lsp = IsisLsp {
            pdu_len: 0,
            hold_time: 1200,
            lsp_id: IsisLspId::new(
                IsisSysId {
                    id: [1, 2, 3, 4, 5, 6],
                },
                0,
                0,
            ),
            seq_number: 1,
            checksum: 0,
            types: Default::default(),
            tlvs,
        };
        let packet = IsisPacket::from(IsisType::L1Lsp, IsisPdu::L1Lsp(lsp));
        let mut buf = BytesMut::new();
        packet.emit(&mut buf);

        sign_lsp_inplace(
            &mut buf,
            IsisAuthType::HmacSha512,
            cfg.password.as_deref().unwrap().as_bytes(),
        );

        let range = locate_auth_tlv(&buf, LSP_TLVS_START).unwrap();
        let digest_start = range.start + 1 + ISIS_AUTH_GENERIC_KEY_ID_LEN;
        let digest_end = range.end;
        assert_eq!(digest_end - digest_start, 64);
        let stored = buf[digest_start..digest_end].to_vec();

        // Verify: Apad + zero lifetime + zero checksum, recompute.
        let mut scratch = buf.to_vec();
        scratch[digest_start..digest_end].copy_from_slice(&apad(64));
        for b in &mut scratch[LSP_REMAINING_LIFETIME_RANGE] {
            *b = 0;
        }
        for b in &mut scratch[LSP_CHECKSUM_RANGE] {
            *b = 0;
        }
        let computed = hmac_for_algo(
            IsisAuthType::HmacSha512,
            cfg.password.as_deref().unwrap().as_bytes(),
            &scratch,
        );
        assert!(digest_eq(&computed, &stored));

        // Fletcher must validate over the patched-digest buffer.
        assert!(isis_packet::is_valid_checksum(&buf));
    }
}
