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

    /// Whether `a` is a link-local unicast address (`169.254.0.0/16` /
    /// `fe80::/10`). A unicast PIM message (Register / Register-Stop) must
    /// not be sourced from one — it has to be domain-routable so the RP
    /// can reply. See [`Pim::unicast_source`](super::inst::Pim).
    fn is_link_local(a: Self::Addr) -> bool;

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

    /// The RFC 2362 §3.7 group-to-RP hash `Value(G, M, C)`, used to break
    /// ties between candidate RPs of equal longest-match range and equal
    /// (lowest) priority so every router in the domain converges on the
    /// same RP for a group. `mask_len` masks the group with the BSR's
    /// advertised hash-mask length; the highest value wins. IPv4 uses the
    /// standard 32-bit arithmetic; IPv6 applies the same recurrence over
    /// the 128-bit masked group / RP XOR-folded to 32 bits (deterministic
    /// and domain-agreed within zebra-rs).
    fn bsr_hash(group: Self::Addr, rp: Self::Addr, mask_len: u8) -> u32;
}

/// The RFC 2362 §3.7 hash recurrence on 32-bit words:
/// `Value = (1103515245 · ((1103515245·gm + 12345) XOR c) + 12345) mod 2^31`.
/// `gm` is the masked group (or an XOR-fold of it for IPv6); `c` is the
/// candidate RP (likewise). Shared by both `PimAf::bsr_hash` impls.
pub(crate) fn bsr_hash_value(gm: u32, c: u32) -> u32 {
    1103515245u32
        .wrapping_mul(1103515245u32.wrapping_mul(gm).wrapping_add(12345) ^ c)
        .wrapping_add(12345)
        & 0x7fff_ffff
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pim::ipv4::Ipv4;
    use crate::pim::ipv6::Ipv6;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // Reference values from the RFC 2362 §3.7 recurrence (verified against
    // an independent Python computation of the formula); pin the exact
    // arithmetic so a refactor of `bsr_hash_value` is caught.
    #[test]
    fn hash_recurrence_known_vectors() {
        assert_eq!(bsr_hash_value(1, 1), 1_480_916_820);
        assert_eq!(
            Ipv4::bsr_hash(
                "239.1.2.3".parse().unwrap(),
                "10.0.0.5".parse().unwrap(),
                30
            ),
            1_036_833_733
        );
        assert_eq!(
            Ipv6::bsr_hash(
                "ff0e::10".parse().unwrap(),
                "2001:db8::5".parse().unwrap(),
                32
            ),
            572_234_093
        );
    }

    #[test]
    fn hash_masks_group_to_a_block() {
        // Groups sharing the top `mask_len` bits hash identically (the
        // RFC 2362 load-splitting granularity); a different block differs.
        let rp4: Ipv4Addr = "10.0.0.5".parse().unwrap();
        let g_a: Ipv4Addr = "239.1.2.10".parse().unwrap();
        let g_b: Ipv4Addr = "239.1.2.200".parse().unwrap(); // same /24
        let g_c: Ipv4Addr = "239.1.3.10".parse().unwrap(); // different /24
        assert_eq!(Ipv4::bsr_hash(g_a, rp4, 24), Ipv4::bsr_hash(g_b, rp4, 24));
        assert_ne!(Ipv4::bsr_hash(g_a, rp4, 24), Ipv4::bsr_hash(g_c, rp4, 24));

        let rp6: Ipv6Addr = "2001:db8::5".parse().unwrap();
        let h_a: Ipv6Addr = "ff0e::1:10".parse().unwrap();
        let h_b: Ipv6Addr = "ff0e::1:99".parse().unwrap(); // same /96
        assert_eq!(Ipv6::bsr_hash(h_a, rp6, 96), Ipv6::bsr_hash(h_b, rp6, 96));
    }

    #[test]
    fn hash_is_rp_sensitive() {
        // Different candidate RPs (generally) hash to different values, so
        // the hash actually breaks a same-priority, same-range tie.
        let g4: Ipv4Addr = "239.1.2.3".parse().unwrap();
        assert_ne!(
            Ipv4::bsr_hash(g4, "10.0.0.1".parse().unwrap(), 30),
            Ipv4::bsr_hash(g4, "10.0.0.2".parse().unwrap(), 30)
        );
        let g6: Ipv6Addr = "ff0e::3".parse().unwrap();
        assert_ne!(
            Ipv6::bsr_hash(g6, "2001:db8::1".parse().unwrap(), 32),
            Ipv6::bsr_hash(g6, "2001:db8::2".parse().unwrap(), 32)
        );
    }
}
