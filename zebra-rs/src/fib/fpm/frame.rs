//! FPM message framing, per SONiC's `fpmsyncd/fpm/fpm.h`.
//!
//! Every message is a 4-byte header followed by a complete netlink
//! message. `msg_len` covers the whole message including the header, is
//! in network byte order, and is rounded up to a 4-byte boundary — so a
//! payload may carry trailing pad. The header length is itself aligned,
//! which is why the netlink message inside never needs its own padding.

/// `FPM_MSG_HDR_LEN` — `fpm_msg_align(sizeof(fpm_msg_hdr_t))`.
pub const FPM_MSG_HDR_LEN: usize = 4;

/// `FPM_PROTO_VERSION`.
pub const FPM_PROTO_VERSION: u8 = 1;

/// `FPM_MSG_TYPE_NETLINK` — the only payload type either side sends.
pub const FPM_MSG_TYPE_NETLINK: u8 = 1;

/// `FPM_MAX_MSG_LEN`. `fpmsyncd` rejects anything longer as malformed.
pub const FPM_MAX_MSG_LEN: usize = 16384;

/// The port `fpmsyncd` listens on. Note the direction: fpmsyncd is the
/// **server**; the routing daemon dials out.
pub const FPM_DEFAULT_PORT: u16 = 2620;

/// `fpm_msg_align()` — round up to `FPM_MSG_ALIGNTO` (4).
pub const fn align(len: usize) -> usize {
    (len + 3) & !3
}

/// Wrap a complete netlink message in an FPM netlink frame.
///
/// Returns `None` if the framed result would exceed `FPM_MAX_MSG_LEN`,
/// which `fpmsyncd` would drop as a malformed header rather than
/// truncate — so the caller must not send it.
pub fn frame(payload: &[u8]) -> Option<Vec<u8>> {
    let msg_len = FPM_MSG_HDR_LEN + align(payload.len());
    if msg_len > FPM_MAX_MSG_LEN {
        return None;
    }
    let mut out = Vec::with_capacity(msg_len);
    out.push(FPM_PROTO_VERSION);
    out.push(FPM_MSG_TYPE_NETLINK);
    out.extend_from_slice(&(msg_len as u16).to_be_bytes());
    out.extend_from_slice(payload);
    // Pad to the alignment the length field claims.
    out.resize(msg_len, 0);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn align_rounds_up_to_four() {
        assert_eq!(align(0), 0);
        assert_eq!(align(1), 4);
        assert_eq!(align(4), 4);
        assert_eq!(align(5), 8);
    }

    #[test]
    fn frames_and_pads() {
        let f = frame(&[0xaa; 5]).unwrap();
        assert_eq!(f.len(), 12);
        assert_eq!(f[0], FPM_PROTO_VERSION);
        assert_eq!(f[1], FPM_MSG_TYPE_NETLINK);
        // Length is big-endian and covers the header.
        assert_eq!(&f[2..4], &[0x00, 0x0c]);
        assert_eq!(&f[4..9], &[0xaa; 5]);
        assert_eq!(&f[9..], &[0, 0, 0]);
    }

    #[test]
    fn refuses_oversized_payloads() {
        assert!(frame(&vec![0u8; FPM_MAX_MSG_LEN]).is_none());
    }
}
