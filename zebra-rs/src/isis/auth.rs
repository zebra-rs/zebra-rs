//! HMAC-MD5 sign/verify and Auth TLV plumbing for IS-IS Hello + SNP PDUs.
//!
//! Phase 3a: Hellos (per-link `hello-authentication`).
//! Phase 3b: CSNP/PSNP (per-level `area-password` / `domain-password`).
//! Phase 4 will add LSP signing, which needs additional treatment for
//! the LSP Checksum and Remaining Lifetime fields per RFC 5304 §3.
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
    ISIS_AUTH_HMAC_MD5_LEN, ISIS_AUTH_TYPE_CLEARTEXT, ISIS_AUTH_TYPE_HMAC_MD5, IsisTlv,
    IsisTlvAuth, IsisTlvType,
};
use md5::Md5;

use super::config::{IsisAuthConfig, IsisAuthType};

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
pub fn auth_tlv_wire_size(cfg: &IsisAuthConfig) -> usize {
    match (cfg.password.as_ref(), cfg.auth_type) {
        (None, _) => 0,
        (Some(pw), IsisAuthType::Text) => 2 + 1 + pw.len(),
        (Some(_), IsisAuthType::Md5) => 2 + 1 + ISIS_AUTH_HMAC_MD5_LEN,
    }
}

/// Append the Authentication TLV (type 10) to `tlvs` when this scope
/// has authentication configured. For cleartext the value is the
/// password bytes verbatim; for HMAC-MD5 it's a zero-filled
/// placeholder that `sign_md5_inplace` will patch in place once the
/// digest is known. No-op when `cfg.password.is_none()`.
pub fn append_auth_tlv(tlvs: &mut Vec<IsisTlv>, cfg: &IsisAuthConfig) {
    let Some(pw) = cfg.password.as_deref() else {
        return;
    };
    let tlv = match cfg.auth_type {
        IsisAuthType::Text => IsisTlvAuth {
            auth_type: ISIS_AUTH_TYPE_CLEARTEXT,
            value: pw.as_bytes().to_vec(),
        },
        IsisAuthType::Md5 => {
            IsisTlvAuth::placeholder(ISIS_AUTH_TYPE_HMAC_MD5, ISIS_AUTH_HMAC_MD5_LEN)
        }
    };
    tlvs.push(tlv.into());
}

/// Two-pass HMAC-MD5 sign step. Locate the Auth TLV inside the
/// just-emitted PDU bytes, compute HMAC over the buffer (the
/// placeholder's digest area is still zero, per RFC 5304 §3), and
/// patch the resulting digest into place. No-op when the TLV
/// isn't found or its digest area isn't the expected length —
/// the caller is responsible for having added a placeholder first.
pub fn sign_md5_inplace(buf: &mut BytesMut, tlvs_start: usize, key: &[u8]) {
    let Some(value_range) = locate_auth_tlv(buf, tlvs_start) else {
        return;
    };
    let digest_start = value_range.start + 1;
    let digest_end = value_range.end;
    if digest_end - digest_start != ISIS_AUTH_HMAC_MD5_LEN {
        return;
    }
    let digest = hmac_md5(key, buf);
    buf[digest_start..digest_end].copy_from_slice(&digest);
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
        // Cleartext: TL header (2) + auth-type (1) + password bytes.
        let cfg = IsisAuthConfig {
            password: Some("hunter2".into()),
            auth_type: IsisAuthType::Text,
            send_only: false,
        };
        let tlv: IsisTlv = IsisTlvAuth {
            auth_type: ISIS_AUTH_TYPE_CLEARTEXT,
            value: b"hunter2".to_vec(),
        }
        .into();
        assert_eq!(auth_tlv_wire_size(&cfg), tlv.wire_len());

        // HMAC-MD5: TL header (2) + auth-type (1) + 16-byte digest.
        let cfg = IsisAuthConfig {
            password: Some("hunter2".into()),
            auth_type: IsisAuthType::Md5,
            send_only: false,
        };
        let tlv: IsisTlv =
            IsisTlvAuth::placeholder(ISIS_AUTH_TYPE_HMAC_MD5, ISIS_AUTH_HMAC_MD5_LEN).into();
        assert_eq!(auth_tlv_wire_size(&cfg), tlv.wire_len());

        // No auth → 0 bytes.
        let cfg = IsisAuthConfig::default();
        assert_eq!(auth_tlv_wire_size(&cfg), 0);
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
        sign_md5_inplace(&mut buf, packet.length_indicator as usize, key);

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
        sign_md5_inplace(&mut buf, packet.length_indicator as usize, key);

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
}
