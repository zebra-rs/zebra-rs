//! FPM message framing, per SONiC's `src/sonic-swss/fpmsyncd/fpm/fpm.h`.
//!
//! Every message on the wire is a 4-byte header followed by a payload —
//! for `FPM_MSG_TYPE_NETLINK`, a complete netlink message. The header's
//! `msg_len` covers the *whole* message including the header and is in
//! network byte order; it is rounded up to a 4-byte boundary, so a
//! payload may carry trailing pad. Because the header length is itself
//! aligned, the netlink message inside never needs its own padding.
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |    version    |    msg_type   |          msg_len (BE)         |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                    payload (netlink message)                  |
//! ```

use anyhow::{Result, bail};

/// `FPM_MSG_HDR_LEN` — `fpm_msg_align(sizeof(fpm_msg_hdr_t))`. The
/// struct is already 4 bytes, so the alignment is a no-op; spelled out
/// here so the constant tracks the header definition rather than a
/// coincidence.
pub const FPM_MSG_HDR_LEN: usize = 4;

/// `FPM_PROTO_VERSION`.
pub const FPM_PROTO_VERSION: u8 = 1;

/// `FPM_MSG_TYPE_NETLINK` — the only payload type either side sends.
pub const FPM_MSG_TYPE_NETLINK: u8 = 1;

/// `FPM_MAX_MSG_LEN`. A header claiming more than this is malformed;
/// `fpm_msg_hdr_ok()` rejects it and so do we, rather than trusting a
/// corrupt length and stalling forever waiting for bytes.
pub const FPM_MAX_MSG_LEN: usize = 16384;

/// The well-known port `fpmsyncd` listens on (`FPM_DEFAULT_PORT`).
/// Note the direction: **fpmsyncd is the server**, zebra dials out.
pub const FPM_DEFAULT_PORT: u16 = 2620;

/// `fpm_msg_align()` — round up to `FPM_MSG_ALIGNTO` (4).
pub const fn align(len: usize) -> usize {
    (len + 3) & !3
}

/// A decoded FPM header. `msg_len` is the total message length
/// including the header, already converted from network byte order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub version: u8,
    pub msg_type: u8,
    pub msg_len: usize,
}

impl Header {
    /// Parse a header from the front of `buf`, or `None` if fewer than
    /// `FPM_MSG_HDR_LEN` bytes are available yet.
    pub fn parse(buf: &[u8]) -> Option<Header> {
        if buf.len() < FPM_MSG_HDR_LEN {
            return None;
        }
        Some(Header {
            version: buf[0],
            msg_type: buf[1],
            msg_len: u16::from_be_bytes([buf[2], buf[3]]) as usize,
        })
    }

    /// `fpm_msg_hdr_ok()`: non-zero type, length within bounds, length
    /// aligned.
    pub fn is_ok(&self) -> bool {
        self.msg_type != 0
            && self.msg_len >= FPM_MSG_HDR_LEN
            && self.msg_len <= FPM_MAX_MSG_LEN
            && align(self.msg_len) == self.msg_len
    }

    /// Payload length — total minus header.
    pub fn data_len(&self) -> usize {
        self.msg_len - FPM_MSG_HDR_LEN
    }

    /// Serialize back to the wire.
    ///
    /// The tap itself never writes a header — it forwards and records
    /// bytes verbatim, which is the whole point. This exists so the
    /// codec is testable in both directions: a decoder validated only
    /// against its own encoder proves nothing, but an encoder that
    /// cannot reproduce a header the decoder accepts is definitely
    /// wrong.
    #[cfg(test)]
    pub fn to_bytes(self) -> [u8; FPM_MSG_HDR_LEN] {
        let len = (self.msg_len as u16).to_be_bytes();
        [self.version, self.msg_type, len[0], len[1]]
    }
}

/// Wrap `payload` (a complete netlink message) in an FPM netlink frame,
/// padding it out to the 4-byte alignment the header's length field must
/// satisfy.
///
/// Test-only, for the same reason as [`Header::to_bytes`]: captured and
/// replayed messages are byte-for-byte originals and never round-trip
/// through here, so a framing bug in this function can never contaminate
/// a golden trace.
#[cfg(test)]
pub fn frame(payload: &[u8]) -> Result<Vec<u8>> {
    let msg_len = FPM_MSG_HDR_LEN + align(payload.len());
    if msg_len > FPM_MAX_MSG_LEN {
        bail!(
            "payload of {} bytes exceeds FPM_MAX_MSG_LEN once framed ({} > {})",
            payload.len(),
            msg_len,
            FPM_MAX_MSG_LEN
        );
    }
    let hdr = Header {
        version: FPM_PROTO_VERSION,
        msg_type: FPM_MSG_TYPE_NETLINK,
        msg_len,
    };
    let mut out = Vec::with_capacity(msg_len);
    out.extend_from_slice(&hdr.to_bytes());
    out.extend_from_slice(payload);
    out.resize(msg_len, 0);
    Ok(out)
}

/// Incremental re-framer for a byte stream.
///
/// TCP gives no message boundaries: one `read()` may deliver half a
/// message or six of them. Feed everything that arrives into
/// [`Framer::extend`] and drain whole messages with [`Framer::next`].
/// Messages come back **including** their header and any trailing pad —
/// the exact bytes seen on the wire — because the whole point of the
/// recorder is byte fidelity.
#[derive(Default)]
pub struct Framer {
    buf: Vec<u8>,
    /// Latched so an unexpected header is reported once, not once per
    /// message. A version or type we don't recognize is not fatal — the
    /// bytes are still recorded faithfully — but it means SONiC changed
    /// the protocol under us, which is exactly the kind of drift this
    /// tool exists to catch.
    warned_version: bool,
    warned_type: bool,
}

impl Framer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn extend(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Bytes buffered but not yet forming a complete message. A non-zero
    /// value at end of stream means the peer was cut off mid-message.
    pub fn pending(&self) -> usize {
        self.buf.len()
    }

    /// Pop the next complete message, or `None` if more bytes are needed.
    ///
    /// Errors on a malformed header. That is deliberately fatal rather
    /// than a resync attempt: the stream has no sync marker, so once the
    /// framing is lost there is no principled way to recover, and
    /// silently skipping bytes would produce a corrupt capture that
    /// looks valid.
    pub fn next(&mut self) -> Result<Option<Vec<u8>>> {
        let Some(hdr) = Header::parse(&self.buf) else {
            return Ok(None);
        };
        if !hdr.is_ok() {
            bail!(
                "malformed FPM header (version {}, type {}, len {}) — stream desynchronized",
                hdr.version,
                hdr.msg_type,
                hdr.msg_len
            );
        }
        if self.buf.len() < hdr.msg_len {
            return Ok(None);
        }
        if hdr.version != FPM_PROTO_VERSION && !self.warned_version {
            self.warned_version = true;
            eprintln!(
                "fpm-tap: warning — peer speaks FPM version {}, expected {} \
                 (recording anyway; the dialect may have changed)",
                hdr.version, FPM_PROTO_VERSION
            );
        }
        if hdr.msg_type != FPM_MSG_TYPE_NETLINK && !self.warned_type {
            self.warned_type = true;
            eprintln!(
                "fpm-tap: warning — message type {} is not FPM_MSG_TYPE_NETLINK ({})",
                hdr.msg_type, FPM_MSG_TYPE_NETLINK
            );
        }
        let msg = self.buf.drain(..hdr.msg_len).collect();
        Ok(Some(msg))
    }
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
    fn header_round_trips() {
        let h = Header {
            version: FPM_PROTO_VERSION,
            msg_type: FPM_MSG_TYPE_NETLINK,
            msg_len: 68,
        };
        assert_eq!(Header::parse(&h.to_bytes()), Some(h));
        assert!(h.is_ok());
        assert_eq!(h.data_len(), 64);
    }

    #[test]
    fn header_length_is_big_endian() {
        // 0x0044 == 68 on the wire, MSB first, regardless of host order.
        let bytes = Header {
            version: 1,
            msg_type: 1,
            msg_len: 68,
        }
        .to_bytes();
        assert_eq!(bytes, [1, 1, 0x00, 0x44]);
    }

    #[test]
    fn rejects_malformed_headers() {
        // msg_type 0 is FPM_MSG_TYPE_NONE.
        assert!(
            !Header {
                version: 1,
                msg_type: 0,
                msg_len: 8
            }
            .is_ok()
        );
        // Unaligned length.
        assert!(
            !Header {
                version: 1,
                msg_type: 1,
                msg_len: 6
            }
            .is_ok()
        );
        // Shorter than the header itself.
        assert!(
            !Header {
                version: 1,
                msg_type: 1,
                msg_len: 0
            }
            .is_ok()
        );
        // Beyond FPM_MAX_MSG_LEN.
        assert!(
            !Header {
                version: 1,
                msg_type: 1,
                msg_len: FPM_MAX_MSG_LEN + 4
            }
            .is_ok()
        );
    }

    #[test]
    fn frame_pads_payload_to_alignment() {
        let framed = frame(&[0xaa; 5]).unwrap();
        assert_eq!(framed.len(), 12); // 4 header + 5 payload -> 8 aligned
        let hdr = Header::parse(&framed).unwrap();
        assert_eq!(hdr.msg_len, 12);
        assert_eq!(&framed[4..9], &[0xaa; 5]);
        assert_eq!(&framed[9..], &[0, 0, 0]); // pad
    }

    #[test]
    fn framer_splits_a_coalesced_stream() {
        let a = frame(&[1, 2, 3, 4]).unwrap();
        let b = frame(&[5, 6, 7, 8, 9, 10, 11, 12]).unwrap();
        let mut f = Framer::new();
        f.extend(&a);
        f.extend(&b);
        assert_eq!(f.next().unwrap().as_deref(), Some(a.as_slice()));
        assert_eq!(f.next().unwrap().as_deref(), Some(b.as_slice()));
        assert_eq!(f.next().unwrap(), None);
        assert_eq!(f.pending(), 0);
    }

    #[test]
    fn framer_waits_for_a_split_message() {
        let a = frame(&[1, 2, 3, 4]).unwrap();
        let mut f = Framer::new();
        // Header arrives, body does not.
        f.extend(&a[..4]);
        assert_eq!(f.next().unwrap(), None);
        f.extend(&a[4..]);
        assert_eq!(f.next().unwrap().as_deref(), Some(a.as_slice()));
    }

    #[test]
    fn framer_errors_on_desync() {
        let mut f = Framer::new();
        f.extend(&[1, 0, 0, 8]); // FPM_MSG_TYPE_NONE
        assert!(f.next().is_err());
    }
}
