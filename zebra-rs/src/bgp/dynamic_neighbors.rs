//! BGP dynamic-neighbors runtime (zebra-bgp-dynamic-neighbors.yang).
//!
//! Stores the configured `listen-range` prefixes and `listen-limit`,
//! and exposes `lpm_match` for the accept-path. Materialization of
//! the synthesized [`super::peer::Peer`] lives in
//! [`super::peer::try_dynamic_accept`] — this module is just state
//! + config callbacks.

use std::collections::BTreeMap;
use std::net::IpAddr;

use ipnet::IpNet;

use super::Bgp;
use crate::config::{Args, ConfigOp};

#[derive(Debug, Default, Clone)]
pub struct ListenRange {
    /// Name of the `neighbor-group` whose attributes a peer
    /// materialized via this range inherits. `None` until the YANG
    /// callback sets it (the leaf is `mandatory true` so the schema
    /// catches an unset value at commit time).
    pub neighbor_group: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DynamicNeighbors {
    pub listen_limit: u32,
    pub ranges: BTreeMap<IpNet, ListenRange>,
}

/// RFC-style operator default — IOS-XR ships 100, FRR ships 100,
/// Arista ships 256. Picking 100 keeps us aligned with the more
/// conservative end.
const DEFAULT_LISTEN_LIMIT: u32 = 100;

impl Default for DynamicNeighbors {
    fn default() -> Self {
        Self {
            listen_limit: DEFAULT_LISTEN_LIMIT,
            ranges: BTreeMap::new(),
        }
    }
}

impl DynamicNeighbors {
    /// Longest-prefix match against the configured ranges. Returns
    /// the matched `(prefix, range)` so the caller can record the
    /// prefix on the synthesized peer's `PeerOrigin::Dynamic`.
    pub fn lpm_match(&self, addr: &IpAddr) -> Option<(IpNet, &ListenRange)> {
        let mut best: Option<(IpNet, &ListenRange)> = None;
        for (prefix, range) in self.ranges.iter() {
            if !prefix_contains(prefix, addr) {
                continue;
            }
            let plen = prefix.prefix_len();
            match best {
                None => best = Some((*prefix, range)),
                Some((p, _)) if plen > p.prefix_len() => best = Some((*prefix, range)),
                _ => {}
            }
        }
        best
    }
}

/// `ipnet::IpNet::contains(&IpAddr)` exists but takes `IpAddr` by
/// value; this wrapper hides the address-family bridging when the
/// caller already has a typed `&IpAddr`.
fn prefix_contains(net: &IpNet, addr: &IpAddr) -> bool {
    match (net, addr) {
        (IpNet::V4(n), IpAddr::V4(a)) => n.contains(a),
        (IpNet::V6(n), IpAddr::V6(a)) => n.contains(a),
        _ => false,
    }
}

/// `set router bgp dynamic-neighbors listen-limit <N>`.
pub fn config_listen_limit(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    match op {
        ConfigOp::Set => {
            bgp.dynamic_neighbors.listen_limit = args.u32()?;
        }
        ConfigOp::Delete => {
            bgp.dynamic_neighbors.listen_limit = DEFAULT_LISTEN_LIMIT;
        }
        _ => {}
    }
    Some(())
}

/// `set router bgp dynamic-neighbors listen-range <prefix>` —
/// list-key callback. Creates the entry on `Set` and removes it on
/// `Delete`.
pub fn config_listen_range(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let prefix: IpNet = args.string()?.parse().ok()?;
    match op {
        ConfigOp::Set => {
            bgp.dynamic_neighbors.ranges.entry(prefix).or_default();
        }
        ConfigOp::Delete => {
            bgp.dynamic_neighbors.ranges.remove(&prefix);
        }
        _ => {}
    }
    Some(())
}

/// `set router bgp dynamic-neighbors listen-range <prefix> neighbor-group <name>`.
pub fn config_listen_range_neighbor_group(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let prefix: IpNet = args.string()?.parse().ok()?;
    let entry = bgp.dynamic_neighbors.ranges.entry(prefix).or_default();
    match op {
        ConfigOp::Set => entry.neighbor_group = Some(args.string()?),
        ConfigOp::Delete => entry.neighbor_group = None,
        _ => {}
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    fn addr(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn lpm_picks_longest_prefix() {
        let mut dn = DynamicNeighbors::default();
        dn.ranges.insert(
            net("10.0.0.0/8"),
            ListenRange {
                neighbor_group: Some("default".into()),
            },
        );
        dn.ranges.insert(
            net("10.99.0.0/16"),
            ListenRange {
                neighbor_group: Some("special".into()),
            },
        );

        let hit = dn.lpm_match(&addr("10.99.5.7")).unwrap();
        assert_eq!(hit.0, net("10.99.0.0/16"));
        assert_eq!(hit.1.neighbor_group.as_deref(), Some("special"));

        let hit = dn.lpm_match(&addr("10.50.0.1")).unwrap();
        assert_eq!(hit.0, net("10.0.0.0/8"));
        assert_eq!(hit.1.neighbor_group.as_deref(), Some("default"));
    }

    #[test]
    fn lpm_returns_none_on_miss() {
        let mut dn = DynamicNeighbors::default();
        dn.ranges.insert(net("10.0.0.0/8"), ListenRange::default());
        assert!(dn.lpm_match(&addr("192.0.2.1")).is_none());
    }

    #[test]
    fn ipv4_and_ipv6_dont_cross_match() {
        let mut dn = DynamicNeighbors::default();
        dn.ranges.insert(net("10.0.0.0/8"), ListenRange::default());
        // IPv6 address must not match an IPv4 prefix.
        assert!(dn.lpm_match(&addr("::ffff:10.0.0.1")).is_none());
    }

    #[test]
    fn empty_table_returns_none() {
        let dn = DynamicNeighbors::default();
        assert!(
            dn.lpm_match(&IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))
                .is_none()
        );
    }

    #[test]
    fn default_listen_limit_is_one_hundred() {
        let dn = DynamicNeighbors::default();
        assert_eq!(dn.listen_limit, 100);
    }
}
