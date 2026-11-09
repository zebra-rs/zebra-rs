//! DHCPv4 and DHCPv6 packet codec for the zebra-rs DHCP client and the
//! insomnia DHCP relay.
//!
//! Pure data: no sockets, no clocks, no global state. A daemon reads a
//! datagram, hands the bytes to [`v4::Packet::parse`] or
//! [`v6::Message::parse`], looks at or edits the decoded value, and emits
//! it again.
//!
//! Two layers:
//! - **Framing** ([`v4::Packet`], [`v6::Message`]): the header, and the
//!   options as opaque code/value pairs in wire order. A relay needs
//!   nothing more.
//! - **Option values** ([`v4::params`], [`v6::params`], [`name`]): typed
//!   decoders for what a client reads from a server, and constructors for
//!   what it sends.
//!
//! Every `parse` and every decoder is total: any byte string yields `Ok`
//! or `Err`, never a panic, and its work is bounded by the input length.
//! Nothing recurses: a DHCPv6 Relay-Message option stays opaque bytes
//! until the caller parses it explicitly, so a deeply nested Relay-forw
//! costs one level per call, and a compressed domain name follows its
//! pointers in a loop that only ever moves backwards. The `parse_is_total`
//! property tests check those properties with a deterministic generator,
//! so the crate needs no dependencies, dev ones included.
//!
//! Emitting is canonical rather than byte-preserving: framing that
//! carries no information (DHCPv4 pad options, bytes after the end
//! option) is not kept, and DHCPv4 output is padded to the 300-byte
//! BOOTP minimum. Everything else — option order, unknown options,
//! repeated instances of one option code, `sname` and `file` — survives
//! a parse/emit round trip unchanged. The typed layer round-trips values,
//! not bytes: decoding what it encoded gives the same value back.
//!
//! zebra-rs (`crates/dhcp-packet`) owns this crate. insomnia vendors an
//! identical copy (`dhcp-packet/`) for its relay: change it here, then
//! copy it across.

use std::fmt;

pub mod name;
pub mod v4;
pub mod v6;

#[cfg(test)]
mod testutil;

/// Why a byte string is not a well-formed packet or option value, or why
/// a value cannot be encoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Shorter than the fixed header.
    Short,
    /// An option, sub-option or label runs past the end of its buffer.
    Truncated,
    /// A value too long for its length field.
    TooLong,
    /// An option value whose length does not fit its type: a 3-byte
    /// address, a list of addresses that ends mid-address.
    Length,
    /// An option value of a fitting length that its type does not allow:
    /// a non-contiguous subnet mask, a prefix longer than its address, a
    /// malformed domain name.
    Invalid,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::Short => "shorter than the fixed header",
            Error::Truncated => "option runs past the end of the packet",
            Error::TooLong => "value too long for its length field",
            Error::Length => "option value has the wrong length for its type",
            Error::Invalid => "option value is malformed",
        })
    }
}

impl std::error::Error for Error {}
