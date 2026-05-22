use std::net::Ipv4Addr;

use super::link::OSPF_DEFAULT_PRIORITY;
use super::version::{OspfVersion, Ospfv2};

/// Per-interface identity carried in Hello-driven DR / BDR election
/// and propagated through IFSM / NFSM events.
///
/// Parameterized over `V: OspfVersion` so the `prefix` field can be
/// `Ipv4Net` for v2 and `Ipv6Net` for v3 in subsequent PRs. The
/// default `V = Ospfv2` keeps every existing v2 callsite working
/// without textual churn — `Identity` continues to mean
/// `Identity<Ospfv2>` everywhere until a callsite is migrated.
///
/// `router_id`, `d_router`, and `bd_router` stay `Ipv4Addr` in both
/// versions: router-ids remain 32-bit in v3 (RFC 5340 §A.3.1), and
/// `d_router` / `bd_router` are 32-bit in both versions but carry
/// different semantics — interface IPs in v2 vs. router-ids in v3
/// per RFC 5340 §A.3.2. The v3-shaped interpretation lives on
/// version-specific helper impls below.
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct Identity<V: OspfVersion = Ospfv2> {
    pub prefix: V::Prefix,
    pub router_id: Ipv4Addr,
    pub d_router: Ipv4Addr,
    pub bd_router: Ipv4Addr,
    pub priority: u8,
}

impl<V: OspfVersion> Identity<V>
where
    V::Prefix: Default,
{
    pub fn new(router_id: Ipv4Addr) -> Self {
        Self {
            prefix: V::Prefix::default(),
            router_id,
            d_router: Ipv4Addr::UNSPECIFIED,
            bd_router: Ipv4Addr::UNSPECIFIED,
            priority: OSPF_DEFAULT_PRIORITY,
        }
    }
}

// Note: the v2-bound `is_declared_dr` / `is_declared_bdr` inherent
// methods were replaced by `OspfVersion::is_declared_dr` /
// `OspfVersion::is_declared_bdr` static methods in `version.rs`.
// The trait accessors carry v3 semantics too (router-id comparison
// per RFC 5340 §A.3.2) and are how the generic IFSM reaches the
// DR / BDR predicates.
