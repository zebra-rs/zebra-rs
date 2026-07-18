//! The PIM address-family abstraction. The protocol data model is
//! generic over `A: PimAf`; one `Pim<A>` instance will be
//! monomorphized per `(VRF, AF)`.
//!
//! This slice carries the associated address / prefix types plus the
//! *pure* address-classification and prefix operations — the semantics
//! that differ between IPv4 and IPv6 but touch neither the actor nor
//! the sockets. The impure edges (wire conversion, checksum context,
//! transports, forwarding plane, membership codec) arrive with the
//! later monomorphization slices, alongside the generic logic that
//! calls them, so no trait method is ever dead.
//!
//! `ipnet` has no trait unifying `Ipv4Net`/`Ipv6Net`, which is why
//! prefix behaviour lives on this trait rather than on bounds of the
//! prefix type. `A` defaults to [`super::ipv4::Ipv4`] everywhere so
//! the concrete IPv4 engine reads unchanged.

use std::fmt::{Debug, Display};
use std::hash::Hash;

use serde::Serialize;

/// Marker, associated types and pure address-family semantics for one
/// PIM address family.
pub trait PimAf: Copy + Eq + Ord + Hash + Debug + Send + Sync + Sized + 'static {
    /// A router-wide protocol address (source, group, RP, neighbor).
    type Addr: Copy + Ord + Eq + Hash + Display + Debug + Send + Sync + Serialize + 'static;
    /// A multicast / RP group range.
    type Prefix: Copy + Eq + Ord + Display + Debug + Send + Sync + 'static;

    /// Default SSM range: `232.0.0.0/8` (RFC 4607) / `ff3x::/32`.
    const DEFAULT_SSM_RANGE: Self::Prefix;
    /// Default RP-eligible group range: `224.0.0.0/4` / `ff00::/8`.
    const DEFAULT_RP_RANGE: Self::Prefix;

    /// Whether `a` is a multicast address.
    fn is_multicast(a: Self::Addr) -> bool;

    /// Whether `a` falls in the Source-Specific Multicast range. For
    /// IPv6 this honours any scope nibble rather than a single literal
    /// prefix, so it is a required method rather than a
    /// `DEFAULT_SSM_RANGE` containment test.
    fn is_ssm(a: Self::Addr) -> bool;

    /// Whether `a` is a link-scope / control group that must never be
    /// forwarded (`224.0.0.0/24` for IPv4; interface- and link-local
    /// scopes for IPv6).
    fn is_reserved_group(a: Self::Addr) -> bool;

    /// Build a prefix from a network address and length; `None` if the
    /// length is invalid for the family.
    fn prefix_new(addr: Self::Addr, len: u8) -> Option<Self::Prefix>;

    /// Whether the prefix covers the address.
    fn prefix_contains(p: &Self::Prefix, a: &Self::Addr) -> bool;

    /// The prefix length in bits.
    fn prefix_len(p: &Self::Prefix) -> u8;

    /// The prefix's network address.
    fn prefix_addr(p: &Self::Prefix) -> Self::Addr;
}
