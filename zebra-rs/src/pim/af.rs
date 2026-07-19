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
use std::net::IpAddr;

use ipnet::IpNet;
use serde::Serialize;
use socket2::Socket;
use tokio::io::unix::AsyncFd;

use crate::rib::Link;

use super::mroute::PimForwardingPlane;

/// Marker, associated types and pure address-family semantics for one
/// PIM address family.
pub trait PimAf: Copy + Eq + Ord + Hash + Debug + Send + Sync + Sized + 'static {
    /// A router-wide protocol address (source, group, RP, neighbor).
    type Addr: Copy + Ord + Eq + Hash + Display + Debug + Send + Sync + Serialize + 'static;
    /// A multicast / RP group range.
    type Prefix: Copy + Eq + Ord + Display + Debug + Send + Sync + 'static;
    /// The kernel forwarding plane for this family (`Mrt4` / `Mrt6`).
    /// `Send + Sync + 'static` because it lives inside the `Pim<A>`
    /// actor that is spawned onto the tokio runtime and borrowed across
    /// awaits.
    type Fp: PimForwardingPlane<Self> + Send + Sync + 'static;

    /// The ALL-PIM-ROUTERS multicast address (RFC 7761 §4.3.1):
    /// `224.0.0.13` / `ff02::d`.
    const ALL_PIM_ROUTERS: Self::Addr;

    /// General-query destination for the membership protocol:
    /// `224.0.0.1` (IGMP all-hosts) / `ff02::1` (MLD).
    const GENERAL_QUERY_DST: Self::Addr;

    /// Whether `a` is the unspecified address (`0.0.0.0` / `::`) — a
    /// membership report sourced from it carries no reporter identity.
    fn is_unspecified(a: Self::Addr) -> bool;

    /// Convert a wire `IpAddr` (from a `pim-packet` encoded address)
    /// into this family's address, rejecting the other family. This is
    /// the single ingress conversion point — cross-family addresses are
    /// dropped here.
    fn from_ip(ip: IpAddr) -> Option<Self::Addr>;
    /// Convert back to a wire `IpAddr` for emission.
    fn to_ip(a: Self::Addr) -> IpAddr;

    /// Narrow a RIB `IpNet` to this family's prefix (`None` for the
    /// other family) — the per-address ingress from `AddrAdd`/`AddrDel`.
    fn prefix_from_ipnet(net: IpNet) -> Option<Self::Prefix>;

    /// This family's on-link prefixes for a RIB link, in order; the
    /// first is the Hello-source / DR-candidate identity. IPv4 reads
    /// `addr4`; IPv6 will read the link-local(s) then `addr6`.
    fn link_prefixes(link: &Link) -> Vec<Self::Prefix>;

    /// Join / leave the ALL-PIM-ROUTERS control group on an interface
    /// (`224.0.0.13` / `ff02::d`) on the instance's PIM socket.
    fn join_pim_if(sock: &AsyncFd<Socket>, ifindex: u32);
    fn leave_pim_if(sock: &AsyncFd<Socket>, ifindex: u32);

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

    /// A minimal inner header naming `(src, grp)` for a Null-Register
    /// (RFC 7761 §4.4.1): a 20-byte IPv4 header / a 40-byte IPv6 header.
    fn null_register_payload(src: Self::Addr, grp: Self::Addr) -> Vec<u8>;

    /// Extract `(src, grp)` from a Register's inner packet (or
    /// Null-Register dummy header). `None` if the inner family does not
    /// match this AF or the header is malformed.
    fn register_inner_sg(data: &[u8]) -> Option<(Self::Addr, Self::Addr)>;
}
