//! IPv6 Neighbor Discovery packet codec (RFC 4861).
//!
//! Covers all four RFC 4861 ICMPv6 message types:
//! Router Solicitation (133), Router Advertisement (134),
//! Neighbor Solicitation (135), and Neighbor Advertisement (136),
//! plus the ND options the codec recognises (Source/Target
//! Link-Layer Address, Prefix Information, MTU).
//!
//! NS/NA support exists for passive observation (counters/diagnostics)
//! — the host kernel still owns the NDP cache and this crate never
//! originates NS/NA in production; [`NeighborSolicit::emit`] and
//! [`NeighborAdvert::emit`] exist for symmetry and tests.
//!
//! ICMPv6 checksums are computed by [`emit_with_checksum`] given the
//! IPv6 source / destination addresses; on parse, [`parse`] verifies
//! the checksum against the addresses provided. Callers that bind a
//! raw `IPPROTO_ICMPV6` socket and set `IPV6_CHECKSUM` may skip the
//! checksum step — see [`checksum`] for the standalone helper.

mod checksum;
mod option;
mod packet;
mod typ;

pub use checksum::compute_icmp6_checksum;
pub use option::{LinkLayerAddress, NdOption, OptionType, PrefixInfo, PrefixInfoFlags};
pub use packet::{
    MAX_INITIAL_RTR_ADVERTISEMENTS, MIN_NA_LEN, MIN_NS_LEN, MIN_RA_LEN, MIN_RS_LEN, NaFlags,
    NeighborAdvert, NeighborSolicit, ParseError, RaFlags, RouterAdvert, RouterSolicit,
};
pub use typ::Icmp6Type;
