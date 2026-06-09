use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use crate::config::{Args, ConfigOp};

use super::{Link, Rib};

fn auto_router_id(links: &BTreeMap<u32, Link>) -> Option<Ipv4Addr> {
    fn find_router_id(links: &BTreeMap<u32, Link>, loopback: bool) -> Option<Ipv4Addr> {
        links
            .values()
            .filter(|link| link.is_loopback() == loopback)
            .flat_map(|link| &link.addr4)
            .filter_map(|laddr| match laddr.addr {
                ipnet::IpNet::V4(v4net) => Some(v4net.addr()),
                _ => None,
            })
            .find(|&addr| addr != Ipv4Addr::LOCALHOST)
    }

    // Try to find a router ID from up loopback interfaces first, then fallback
    // to non-loopback interfaces.
    find_router_id(links, true).or_else(|| find_router_id(links, false))
}

/// Configured global `router-id` wins; otherwise fall back to the
/// automatic pick from interface addresses. `None` when neither
/// exists yet (no config, no usable address).
fn effective_router_id(config: Option<Ipv4Addr>, links: &BTreeMap<u32, Link>) -> Option<Ipv4Addr> {
    config.or_else(|| auto_router_id(links))
}

impl Rib {
    pub fn router_id_update(&mut self) {
        if let Some(router_id) = effective_router_id(self.router_id_config, &self.links)
            && self.router_id != router_id
        {
            self.router_id = router_id;
            self.api_router_id_update(router_id);
        }
    }

    /// Top-level `router-id A.B.C.D` config handler. Set stores the
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

    fn test_link(index: u32, loopback: bool, addrs: &[Ipv4Addr]) -> Link {
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
            master: None,
            vni: None,
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
        links.insert(1, test_link(1, true, &[addr("127.0.0.1")]));
        links.insert(2, test_link(2, false, &[addr("192.0.2.1")]));
        links.insert(3, test_link(3, true, &[addr("10.255.0.1")]));
        assert!(links.get(&1).unwrap().flags.is_loopback());

        // Loopback wins over the (lower-ifindex) non-loopback; the
        // 127.0.0.1 loopback address is never a candidate.
        assert_eq!(auto_router_id(&links), Some(addr("10.255.0.1")));

        // Without any loopback candidate, fall back to non-loopback.
        links.remove(&3);
        assert_eq!(auto_router_id(&links), Some(addr("192.0.2.1")));

        // Only 127.0.0.1 left -> no candidate at all.
        links.remove(&2);
        assert_eq!(auto_router_id(&links), None);
    }

    #[test]
    fn configured_router_id_wins_over_auto_pick() {
        let mut links = BTreeMap::new();
        links.insert(1, test_link(1, true, &[addr("10.255.0.1")]));

        assert_eq!(
            effective_router_id(Some(addr("192.0.2.255")), &links),
            Some(addr("192.0.2.255"))
        );
        // Delete of the override falls back to the automatic pick.
        assert_eq!(effective_router_id(None, &links), Some(addr("10.255.0.1")));
        // No config and no usable address -> undecided.
        assert_eq!(effective_router_id(None, &BTreeMap::new()), None);
    }
}
