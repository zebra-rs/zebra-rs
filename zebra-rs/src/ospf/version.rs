//! OSPF address-family abstraction.
//!
//! The plan is to grow this trait into the boundary between
//! version-agnostic protocol logic (IFSM / NFSM / LSDB plumbing /
//! flooding) and the v2-vs-v3-specific bits (packet formats, address
//! sizes, multicast groups). For now it captures only the small set
//! of constants that already differ between v2 and v3 — `Addr`,
//! protocol number, and the two well-known multicast groups — so the
//! socket layer can reference them through the trait instead of
//! hardcoding v2 literals.
//!
//! Subsequent PRs in the Phase 3 series will parameterize
//! `Ospf<V>`, `OspfLink<V>`, `Neighbor<V>`, and `Lsdb<V>` and migrate
//! the remaining `Ipv4Addr` references that are genuinely
//! address-family-agnostic to `V::Addr`.

use std::fmt::{Debug, Display};
use std::hash::Hash;
use std::net::Ipv4Addr;

/// Marker / dispatch trait for an OSPF protocol version (v2 or v3).
///
/// Both versions use the same IP protocol number (89), so it's a
/// default on the trait. The well-known multicast groups
/// (AllSPFRouters / AllDRouters) and the address family itself are
/// what actually differs.
pub trait OspfVersion: 'static + Send + Sync + Copy + Clone {
    /// Address type used on the wire and for router/area identifiers.
    /// v2 uses `Ipv4Addr`; v3 will use `Ipv6Addr`. Router-id and
    /// area-id remain 32-bit in both versions, but the link-local
    /// source address differs — those v3-specific fields will land
    /// when `Ospfv3` is added.
    type Addr: Copy + Eq + Ord + Hash + Display + Debug + 'static;

    /// IP protocol number for OSPF packets — 89 in both versions
    /// (RFC 2328 §A and RFC 5340 §2.3).
    const IP_PROTO: u8 = 89;

    /// AllSPFRouters multicast group: 224.0.0.5 (v2) or ff02::5 (v3).
    const ALL_SPF_ROUTERS: Self::Addr;

    /// AllDRouters multicast group: 224.0.0.6 (v2) or ff02::6 (v3).
    const ALL_DROUTERS: Self::Addr;
}

/// OSPFv2 dispatch marker (RFC 2328).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ospfv2;

impl OspfVersion for Ospfv2 {
    type Addr = Ipv4Addr;
    const ALL_SPF_ROUTERS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 5);
    const ALL_DROUTERS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 6);
}
