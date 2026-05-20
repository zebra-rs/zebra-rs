//! IPv6 Neighbor Discovery packet codec (RFC 4861).
//!
//! Scoped to the two message types BGP unnumbered needs: Router
//! Advertisement (134) and Router Solicitation (133), plus the
//! options the codec recognises (Source/Target Link-Layer Address,
//! Prefix Information, MTU). Neighbor Solicitation / Advertisement
//! are intentionally omitted — the host kernel handles the NDP
//! cache, this crate only deals with the RA exchange.
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
    MAX_INITIAL_RTR_ADVERTISEMENTS, MIN_RA_LEN, MIN_RS_LEN, ParseError, RaFlags, RouterAdvert,
    RouterSolicit,
};
pub use typ::Icmp6Type;
