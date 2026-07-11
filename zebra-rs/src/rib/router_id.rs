use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

use crate::config::{Args, ConfigOp};

use super::{Link, Rib};

/// Highest non-localhost IPv4 among the links accepted by `in_scope`
/// — loopback-flagged links first, then the rest. "Highest" (not
/// first-seen) is the rule the book documents (ch. 0.2), matching
/// Cisco IOS selection so operators can predict the value.
fn pick_router_id(
    links: &BTreeMap<u32, Link>,
    in_scope: impl Fn(&Link) -> bool,
) -> Option<Ipv4Addr> {
    fn find(
        links: &BTreeMap<u32, Link>,
        in_scope: &impl Fn(&Link) -> bool,
        loopback: bool,
    ) -> Option<Ipv4Addr> {
        links
            .values()
            .filter(|link| in_scope(link) && link.is_loopback() == loopback)
            .flat_map(|link| &link.addr4)
            .filter_map(|laddr| match laddr.addr {
                ipnet::IpNet::V4(v4net) => Some(v4net.addr()),
                _ => None,
            })
            .filter(|&addr| addr != Ipv4Addr::LOCALHOST)
            .max()
    }

    find(links, &in_scope, true).or_else(|| find(links, &in_scope, false))
}

/// Automatic pick for the default VRF: links not enslaved to any VRF
/// master. (A bridge master is not a VRF master — its slaves stay in
/// the default routing table and remain candidates.)
fn auto_router_id(links: &BTreeMap<u32, Link>, vrf_masters: &BTreeSet<u32>) -> Option<Ipv4Addr> {
    pick_router_id(links, |link| {
        !link.master.is_some_and(|m| vrf_masters.contains(&m))
    })
}

/// Automatic pick for one VRF: links enslaved to its master device.
fn auto_router_id_vrf(links: &BTreeMap<u32, Link>, vrf_ifindex: u32) -> Option<Ipv4Addr> {
    pick_router_id(links, |link| link.master == Some(vrf_ifindex))
}

/// Configured value wins; otherwise the automatic pick; otherwise
/// `fallback` (`None` for the global instance — its stickiness is
/// handled by the caller — and the global effective value for a VRF).
fn effective_router_id(
    config: Option<Ipv4Addr>,
    auto: Option<Ipv4Addr>,
    fallback: Option<Ipv4Addr>,
) -> Option<Ipv4Addr> {
    config.or(auto).or(fallback)
}

impl Rib {
    /// Recompute the global and every VRF's effective Router ID and
    /// push `RouterIdUpdate` to the affected subscriber sets when a
    /// value moved. Call sites: address add/delete, VRF add, a link
    /// crossing a VRF boundary, and the `system router-id` /
    /// `vrf <name> router-id` config handlers.
    pub fn router_id_update(&mut self) {
        let vrf_masters: BTreeSet<u32> = self.vrfs.values().map(|v| v.ifindex).collect();

        // Global first, so VRFs falling back to it see the fresh value.
        // Sticky: when no source yields a value, keep the old one.
        if let Some(router_id) = effective_router_id(
            self.router_id_config,
            auto_router_id(&self.links, &vrf_masters),
            None,
        ) && self.router_id != router_id
        {
            self.router_id = router_id;
            self.api_router_id_update(0, router_id);
        }

        // Per-VRF: configured > derived-from-members > global
        // effective. The global fallback keeps the historical behavior
        // where per-VRF subscribers inherited the global value, while
        // letting a VRF-local address or an explicit
        // `vrf <name> router-id` take precedence. Collect emits first —
        // `api_router_id_update` borrows `&self`.
        let global = (!self.router_id.is_unspecified()).then_some(self.router_id);
        let mut emits: Vec<(u32, Ipv4Addr)> = Vec::new();
        for vrf in self.vrfs.values_mut() {
            if let Some(router_id) = effective_router_id(
                vrf.router_id_config,
                auto_router_id_vrf(&self.links, vrf.ifindex),
                global,
            ) && vrf.router_id != router_id
            {
                vrf.router_id = router_id;
                emits.push((vrf.table_id, router_id));
            }
        }
        for (vrf_id, router_id) in emits {
            self.api_router_id_update(vrf_id, router_id);
        }
    }

    /// `system router-id A.B.C.D` config handler. Set stores the
    /// override, delete clears it back to the automatic pick; either
    /// way the effective value is recomputed and, when it moved,
    /// broadcast to subscribers.
    pub(crate) fn router_id_config_exec(&mut self, mut args: Args, op: ConfigOp) -> Option<()> {
        if op.is_set() {
            self.router_id_config = Some(args.v4addr()?);
        } else {
            self.router_id_config = None;
        }
        self.router_id_update();
        Some(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::link::LinkAddr;
    use super::super::{LinkType, link_ext::LinkFlagsExt as _};
    use super::*;
    use ipnet::{IpNet, Ipv4Net};
    use netlink_packet_route::link::LinkFlags;

    fn test_link(index: u32, loopback: bool, master: Option<u32>, addrs: &[Ipv4Addr]) -> Link {
        Link {
            index,
            name: format!("test{index}"),
            mtu: 1500,
            original_mtu: 1500,
            metric: 1,
            flags: if loopback {
                LinkFlags::Loopback
            } else {
                LinkFlags::empty()
            },
            link_type: LinkType::Ethernet,
            label: false,
            mac: None,
            addr4: addrs
                .iter()
                .map(|&addr| LinkAddr {
                    addr: IpNet::V4(Ipv4Net::new(addr, 24).unwrap()),
                    ifindex: index,
                    secondary: false,
                    config: false,
                    fib: true,
                })
                .collect(),
            addr6: Vec::new(),
            master,
            vni: None,
            vrf_table: None,
            vxlan_local: None,
            mtu_error: None,
        }
    }

    fn addr(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn auto_pick_prefers_loopback_and_skips_localhost() {
        let mut links = BTreeMap::new();
        links.insert(1, test_link(1, true, None, &[addr("127.0.0.1")]));
        links.insert(2, test_link(2, false, None, &[addr("192.0.2.1")]));
        links.insert(3, test_link(3, true, None, &[addr("10.255.0.1")]));
        assert!(links.get(&1).unwrap().flags.is_loopback());
        let no_vrfs = BTreeSet::new();

        // Loopback wins over the non-loopback even though the
        // non-loopback address is numerically higher; the 127.0.0.1
        // loopback address is never a candidate.
        assert_eq!(auto_router_id(&links, &no_vrfs), Some(addr("10.255.0.1")));

        // Without any loopback candidate, fall back to non-loopback.
        links.remove(&3);
        assert_eq!(auto_router_id(&links, &no_vrfs), Some(addr("192.0.2.1")));

        // Only 127.0.0.1 left -> no candidate at all.
        links.remove(&2);
        assert_eq!(auto_router_id(&links, &no_vrfs), None);
    }

    #[test]
    fn auto_pick_selects_highest_address_within_a_class() {
        // The book's rule (ch. 0.2, Cisco-style): the HIGHEST address
        // among loopbacks wins — not the first one encountered in
        // ifindex order.
        let mut links = BTreeMap::new();
        links.insert(
            1,
            test_link(1, true, None, &[addr("10.2.2.2"), addr("10.1.1.1")]),
        );
        links.insert(2, test_link(2, true, None, &[addr("10.3.3.3")]));
        let no_vrfs = BTreeSet::new();
        assert_eq!(auto_router_id(&links, &no_vrfs), Some(addr("10.3.3.3")));

        // Same rule on the non-loopback fallback.
        let mut links = BTreeMap::new();
        links.insert(5, test_link(5, false, None, &[addr("192.0.2.9")]));
        links.insert(6, test_link(6, false, None, &[addr("192.0.2.200")]));
        assert_eq!(auto_router_id(&links, &no_vrfs), Some(addr("192.0.2.200")));
    }

    #[test]
    fn global_pick_excludes_vrf_enslaved_links_but_not_bridge_slaves() {
        const VRF_IF: u32 = 100;
        const BRIDGE_IF: u32 = 200;
        let mut links = BTreeMap::new();
        // VRF member with the lowest ifindex — must NOT win the
        // global pick.
        links.insert(1, test_link(1, false, Some(VRF_IF), &[addr("10.99.0.1")]));
        // Bridge slave — its master is not a VRF, so it stays a
        // global candidate.
        links.insert(
            2,
            test_link(2, false, Some(BRIDGE_IF), &[addr("192.0.2.1")]),
        );
        let vrf_masters = BTreeSet::from([VRF_IF]);

        assert_eq!(
            auto_router_id(&links, &vrf_masters),
            Some(addr("192.0.2.1"))
        );
        // The VRF-scoped pick selects exactly the member the global
        // pick skipped.
        assert_eq!(auto_router_id_vrf(&links, VRF_IF), Some(addr("10.99.0.1")));
        assert_eq!(auto_router_id_vrf(&links, 999), None);
    }

    #[test]
    fn effective_chain_config_then_auto_then_fallback() {
        let cfg = Some(addr("192.0.2.255"));
        let auto = Some(addr("10.255.0.1"));
        let global = Some(addr("9.9.9.9"));

        assert_eq!(effective_router_id(cfg, auto, global), cfg);
        assert_eq!(effective_router_id(None, auto, global), auto);
        assert_eq!(effective_router_id(None, None, global), global);
        assert_eq!(effective_router_id(None, None, None), None);
    }
}
