use ipnet::{Ipv4Net, Ipv6Net};
use prefix_trie::PrefixMap;

use crate::rib::RibEntries;

/// Applied state for one VRF instance.
///
/// Created when `Message::VrfAdd { name }` is handled by the RIB —
/// the allocator hands out a fresh table ID, the netlink layer creates
/// the kernel `vrf` master interface, and the result is recorded here.
/// `ifindex` is the kernel-assigned ifindex of the VRF master device;
/// callers enslave member interfaces to it via `IFLA_MASTER`.
///
/// Route-target sets attached via
/// `set vrf X {ipv4,ipv6} route-target {import,export} …` flow in
/// through [`Message::VrfRouteTargets`] and live on this struct so
/// they replay alongside the kernel info when a subscriber attaches.
#[derive(Debug, Clone)]
pub struct Vrf {
    pub name: String,
    pub table_id: u32,
    pub ifindex: u32,
    /// Effective per-VRF Router ID — what this VRF's subscribers
    /// receive via `RibRx::RouterIdUpdate` and what the
    /// subscribe-time replay sends them. Derived by
    /// `Rib::router_id_update`: configured `vrf <name> router-id`
    /// first, then the automatic pick from this VRF's member
    /// interfaces, then the global effective Router ID. Sticky once
    /// set, like the global one.
    pub router_id: std::net::Ipv4Addr,
    /// Operator-configured `vrf <name> router-id`, delivered via
    /// `Message::VrfRouterId`. Wins over the derived values; `None`
    /// falls back.
    pub router_id_config: Option<std::net::Ipv4Addr>,
    /// `true` when this process created the kernel VRF master device,
    /// `false` when it adopted a pre-existing one (operator-created, or
    /// a leftover from a prior run). The shutdown path only deletes the
    /// devices it created — same ownership rule as the sr0 dummy.
    pub owned: bool,
    pub ipv4_import_rts: std::collections::BTreeSet<bgp_packet::RouteDistinguisher>,
    pub ipv4_export_rts: std::collections::BTreeSet<bgp_packet::RouteDistinguisher>,
    pub ipv6_import_rts: std::collections::BTreeSet<bgp_packet::RouteDistinguisher>,
    pub ipv6_export_rts: std::collections::BTreeSet<bgp_packet::RouteDistinguisher>,
}

/// Per-VRF routing-table set. Mirrors the `table` / `table_v6` /
/// `ilm` fields on `Rib`, so the per-`ProtoId` dispatcher can
/// pick between the global table and a VRF table without branching
/// on the field name. The inbound `RibInbound` envelope's
/// `ProtoId` resolves to a `vrf_id`, looks up the outer map, and
/// routes the install into the matching inner table.
#[derive(Debug, Default)]
pub struct VrfRibTables {
    pub table: PrefixMap<Ipv4Net, RibEntries>,
    pub table_v6: PrefixMap<Ipv6Net, RibEntries>,
}

impl VrfRibTables {
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_table_is_empty() {
        let t = VrfRibTables::new();
        assert!(t.table.iter().next().is_none());
        assert!(t.table_v6.iter().next().is_none());
    }

    #[test]
    fn default_matches_new() {
        let a = VrfRibTables::new();
        let b = VrfRibTables::default();
        assert_eq!(a.table.iter().count(), b.table.iter().count());
        assert_eq!(a.table_v6.iter().count(), b.table_v6.iter().count());
    }
}
