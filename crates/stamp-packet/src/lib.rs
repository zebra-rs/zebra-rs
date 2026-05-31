//! STAMP test-packet codec.
//!
//! Encodes and decodes Simple Two-Way Active Measurement Protocol
//! (STAMP, RFC 8762) test packets, including the optional Type-Length-
//! Value (TLV) framework of RFC 8972 and the Segment Routing return-path
//! extensions of RFC 9503.
//!
//! The two packet types are [`SenderPacket`] (Session-Sender) and
//! [`ReflectorPacket`] (Session-Reflector); both expose `parse(&[u8])`
//! and `emit(&mut BytesMut)`. The unauthenticated base packet is
//! wire-compatible with a TWAMP-Light test packet (RFC 5357 Appendix I),
//! so a peer that only speaks TWAMP-Light treats any trailing STAMP TLVs
//! as opaque Packet Padding (RFC 8762 §4.6).
//!
//! Scope of this codec:
//!   * unauthenticated mode only — authenticated mode and the HMAC TLV
//!     (RFC 8972 §4.8) are not yet implemented;
//!   * the SSID field (RFC 8972 §3) is modelled explicitly and defaults
//!     to 0, which is equivalent to the RFC 8762 MBZ it overlays;
//!   * RFC 8972 TLVs implemented here: Extra Padding (Type 1). The other
//!     RFC 8972 TLVs are decoded as [`StampTlvValue::Unknown`];
//!   * RFC 9503 TLVs implemented here: Destination Node Address (Type 9)
//!     and Return Path (Type 10) with all four return-path sub-TLVs.
//!
//! Parsing performs structural validation only (sizes, length fields).
//! Stateful checks — session demux by SSID/4-tuple, sequence tracking
//! for synthetic loss, timestamp epoch conversion — are the caller's
//! responsibility, mirroring the split used by `bfd-packet`.

mod packet;
mod return_path;
mod tlv;

pub use packet::{
    BASE_LEN, ErrorEstimate, ParseError, ReflectorPacket, STAMP_UDP_PORT, SenderPacket,
    StampTimestamp, TimestampFormat,
};
pub use return_path::{
    MplsLabelEntry, REPLY_REQUESTED_SAME_LINK, ReturnPath, ReturnPathSubTlv, ReturnPathSubTlvValue,
    SUBTYPE_CONTROL_CODE, SUBTYPE_RETURN_ADDRESS, SUBTYPE_SR_MPLS, SUBTYPE_SRV6,
};
pub use tlv::{
    StampTlv, StampTlvFlags, StampTlvValue, TLV_HEADER_LEN, TYPE_DEST_NODE_ADDRESS,
    TYPE_EXTRA_PADDING, TYPE_RETURN_PATH,
};
