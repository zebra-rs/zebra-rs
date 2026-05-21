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

impl Identity<Ospfv2> {
    /// True iff this identity considers itself the DR on its link
    /// (v2 semantics: `d_router` is the DR's interface IP, which
    /// matches our own when we won the election).
    ///
    /// v2-only because v3 stores router-ids in `d_router` per
    /// RFC 5340 §A.3.2; the equivalent check there compares
    /// `d_router` against `self.router_id`, not `prefix.addr()`.
    /// The v3 variant lands when an `Identity<Ospfv3>` consumer
    /// needs it.
    pub fn is_declared_dr(&self) -> bool {
        self.prefix.addr() == self.d_router
    }

    /// True iff this identity considers itself the BDR. v2-only
    /// for the same reason as [`Self::is_declared_dr`].
    pub fn is_declared_bdr(&self) -> bool {
        self.prefix.addr() == self.bd_router
    }
}
