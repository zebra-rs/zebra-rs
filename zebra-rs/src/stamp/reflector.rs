//! Stateless Session-Reflector reply construction (RFC 8762 §4.3).
//!
//! [`build_reply`] is deliberately a pure function of the received
//! probe: it is the executable specification a future XDP reflector
//! mirrors as an in-place packet rewrite (offload notes §9b R1 — both
//! base packets are 44 octets, so the reflector fields overwrite the
//! sender's MBZ region byte-for-byte). Keep it free of session state
//! and side effects.

use stamp_packet::{
    BASE_LEN, ReflectorPacket, SenderPacket, StampTimestamp, StampTlv, StampTlvValue,
    TLV_HEADER_LEN,
};

/// Build the stateless reflection of `probe`.
///
/// Stateless mode (RFC 8762 §4.3): the reflector's own sequence number
/// is a copy of the sender's, the SSID is echoed, and no per-session
/// reflector state exists. `rx_ts` is the receive timestamp (T2, taken
/// at the socket read); the caller stamps T3 immediately before
/// transmission — here, since build-to-send is one synchronous path.
/// `ttl` is the probe's received TTL, copied into the Sender TTL field.
///
/// Symmetric size (RFC 8762 §4.3 / RFC 6038): when the probe was
/// longer than the 44-octet base, the reply is padded to the same
/// length with an Extra Padding TLV (RFC 8972 §4.1). A 1–3 octet
/// shortfall cannot be expressed (the TLV header alone is 4 octets) —
/// those replies stay at base length, which only mis-sizes probes that
/// were themselves padded by less than one TLV header.
pub fn build_reply(
    probe: &SenderPacket,
    rx_ts: StampTimestamp,
    ttl: u8,
    req_len: usize,
) -> ReflectorPacket {
    let mut tlvs = Vec::new();
    if req_len >= BASE_LEN + TLV_HEADER_LEN {
        // A 4-octet shortfall is a zero-length Extra Padding TLV.
        let pad = req_len - BASE_LEN - TLV_HEADER_LEN;
        tlvs.push(StampTlv::new(StampTlvValue::ExtraPadding(vec![0u8; pad])));
    }
    ReflectorPacket {
        seq: probe.seq,                         // stateless: copy of the sender's
        timestamp: super::timestamp::now_ntp(), // T3
        error_estimate: super::inst::local_error_estimate(),
        ssid: probe.ssid,
        receive_timestamp: rx_ts, // T2
        sender_seq: probe.seq,
        sender_timestamp: probe.timestamp,
        sender_error_estimate: probe.error_estimate,
        sender_ttl: ttl,
        tlvs,
    }
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;
    use stamp_packet::ErrorEstimate;

    use super::*;

    fn probe(seq: u32, ssid: u16) -> SenderPacket {
        SenderPacket {
            seq,
            timestamp: StampTimestamp {
                seconds: 0xAABB_CCDD,
                fraction: 0x1122_3344,
            },
            error_estimate: ErrorEstimate {
                synced: true,
                multiplier: 7,
                ..ErrorEstimate::default()
            },
            ssid,
            tlvs: vec![],
        }
    }

    fn rx_ts() -> StampTimestamp {
        StampTimestamp {
            seconds: 0xDEAD_BEEF,
            fraction: 0x0BAD_F00D,
        }
    }

    /// Every sender field lands in its reflector slot (RFC 8762 §4.3):
    /// seq copied twice (stateless), timestamp/error-estimate/ssid/TTL
    /// echoed, T2 = the receive timestamp.
    #[test]
    fn sender_fields_copied() {
        let p = probe(42, 0x0102);
        let r = build_reply(&p, rx_ts(), 255, BASE_LEN);
        assert_eq!(r.seq, 42, "stateless mode copies the sender seq");
        assert_eq!(r.sender_seq, 42);
        assert_eq!(r.ssid, 0x0102);
        assert_eq!(r.receive_timestamp, rx_ts());
        assert_eq!(r.sender_timestamp, p.timestamp);
        assert_eq!(r.sender_error_estimate, p.error_estimate);
        assert_eq!(r.sender_ttl, 255);
        assert!(r.tlvs.is_empty(), "base-length probe needs no padding");
    }

    /// A padded probe gets a same-length reply (RFC 6038 symmetric
    /// size): emit and compare byte counts.
    #[test]
    fn symmetric_size_padding() {
        let p = probe(1, 1);
        for req_len in [BASE_LEN + 4, BASE_LEN + 20, BASE_LEN + 200] {
            let r = build_reply(&p, rx_ts(), 255, req_len);
            let mut buf = BytesMut::new();
            r.emit(&mut buf);
            assert_eq!(buf.len(), req_len, "reply length for request {req_len}");
        }
    }

    /// A 1–3 octet shortfall can't be expressed with a 4-octet TLV
    /// header — the reply stays at base length instead of panicking or
    /// over-padding. (Exactly 4 octets *is* expressible: a zero-length
    /// Extra Padding TLV — covered by `symmetric_size_padding`.)
    #[test]
    fn sub_header_pad_skipped() {
        let p = probe(1, 1);
        for req_len in [BASE_LEN + 1, BASE_LEN + 2, BASE_LEN + 3] {
            let r = build_reply(&p, rx_ts(), 255, req_len);
            let mut buf = BytesMut::new();
            r.emit(&mut buf);
            assert_eq!(buf.len(), BASE_LEN, "no expressible pad for {req_len}");
        }
    }
}
