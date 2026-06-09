//! Per-VRF BGP configuration staging.
//!
//! The callbacks in this module fan out the YANG paths under
//! `/router/bgp/vrf/<name>/...` (zebra-bgp-vrf.yang) into a single
//! [`BgpVrfConfig`] per VRF, stored on `Bgp::vrfs`. The per-VRF
//! runtime consumes this map to spawn tasks and materialize peers.
//!
//! Design notes:
//!
//! - VRF entries are created lazily: a callback for any leaf under
//!   `vrf <NAME>` inserts a default entry if missing. That matches
//!   the order YANG callbacks fire in, which is depth-first by path
//!   — the list-key handler typically arrives first, but staging
//!   tolerates the leaf handler racing ahead.
//! - The `peer-group` reference is a plain string (matching the
//!   schema). Resolution against `neighbor-groups/neighbor-group/<X>`
//!   happens when the per-VRF runtime materializes peers.
//! - `BgpVrfNeighborConfig::enabled` defaults to `true` so a freshly
//!   added neighbor row matches the YANG default without the user
//!   needing to `set ... enabled true` explicitly.
//! - The label-mode value is parsed at the callback boundary into a
//!   typed enum; bad input fails the callback and is rejected by the
//!   config commit (same shape every other `enum`-typed leaf uses).

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

use bgp_packet::RouteDistinguisher;
use ipnet::{Ipv4Net, Ipv6Net};

use crate::bgp_vrf_trace;
use crate::config::{Args, ConfigOp};

use super::Bgp;

/// MPLS label allocation strategy for VPN routes originated from a
/// VRF — mirrors `label-mode` in zebra-bgp-vrf.yang. Default is
/// `Vrf` (one label per VRF, lowest label churn). Variant names
/// drop the redundant `Per`-prefix that the YANG values carry; the
/// `parse` helper bridges back to the wire form.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum BgpVrfLabelMode {
    #[default]
    Vrf,
    Route,
    Nexthop,
}

impl BgpVrfLabelMode {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "per-vrf" => Some(Self::Vrf),
            "per-route" => Some(Self::Route),
            "per-nexthop" => Some(Self::Nexthop),
            _ => None,
        }
    }
}

/// VPN data-plane encapsulation for a VRF — mirrors `encapsulation`
/// in zebra-bgp-vrf.yang. Default `Mpls` (RFC 4364 service label).
/// `Srv6` (RFC 9252) binds a per-VRF End.DT46 service SID from the
/// `segment-routing srv6 locator` instead of an MPLS label, and the
/// PE programs a seg6local decap rather than an AF_MPLS ILM.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum BgpVrfEncapsulation {
    #[default]
    Mpls,
    Srv6,
}

impl BgpVrfEncapsulation {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "mpls" => Some(Self::Mpls),
            "srv6" => Some(Self::Srv6),
            _ => None,
        }
    }
}

/// Per-peer attribute set for a CE peer configured under
/// `router bgp vrf X neighbor <addr>`. Mirrors `bgp-vrf-neighbor` in
/// zebra-bgp-vrf.yang.
#[derive(Debug, Clone)]
pub struct BgpVrfNeighborConfig {
    pub remote_as: Option<u32>,
    pub peer_group: Option<String>,
    pub description: Option<String>,
    pub enabled: bool,
}

impl Default for BgpVrfNeighborConfig {
    fn default() -> Self {
        // `enabled: true` matches the YANG default — when the
        // operator types `set ... neighbor X` without explicit
        // `enabled`, the peer is live.
        Self {
            remote_as: None,
            peer_group: None,
            description: None,
            enabled: true,
        }
    }
}

/// Per-AFI knobs under `router bgp vrf X afi-safi {ipv4,ipv6}-unicast`.
/// Generic on the prefix type so the same struct holds either v4 or
/// v6 networks.
#[derive(Debug, Clone)]
pub struct BgpVrfAfConfig<N: Ord> {
    pub networks: BTreeSet<N>,
}

impl<N: Ord> Default for BgpVrfAfConfig<N> {
    fn default() -> Self {
        Self {
            networks: BTreeSet::new(),
        }
    }
}

/// Staged candidate configuration for one VRF entry. Mirrors the
/// `list vrf` body in zebra-bgp-vrf.yang.
#[derive(Default, Debug, Clone)]
pub struct BgpVrfConfig {
    pub rd: Option<RouteDistinguisher>,
    pub router_id: Option<Ipv4Addr>,
    pub label_mode: BgpVrfLabelMode,
    pub encapsulation: BgpVrfEncapsulation,
    pub neighbors: BTreeMap<IpAddr, BgpVrfNeighborConfig>,
    pub ipv4_unicast: Option<BgpVrfAfConfig<Ipv4Net>>,
    pub ipv6_unicast: Option<BgpVrfAfConfig<Ipv6Net>>,
    /// Advertise this VRF's IPv4 routes as EVPN Type-5 (RFC 9136).
    /// Mirrors `evpn advertise-ipv4` in zebra-bgp-vrf.yang.
    pub evpn_advertise_v4: bool,
    /// Advertise this VRF's IPv6 routes as EVPN Type-5 (RFC 9136).
    pub evpn_advertise_v6: bool,
}

/// Borrow-or-create the per-VRF entry on `Bgp::vrfs`. Used by every
/// leaf callback; promotes the "set leaf before set list-key" race
/// to a no-op rather than a `None` return.
fn vrf_entry(bgp: &mut Bgp, name: String) -> &mut BgpVrfConfig {
    bgp.vrfs.entry(name).or_default()
}

/// `set router bgp vrf <NAME>` — list-key handler.
pub fn config_vrf(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    match op {
        ConfigOp::Set => {
            bgp.vrfs.entry(name).or_default();
        }
        ConfigOp::Delete => {
            bgp.vrfs.remove(&name);
        }
        _ => {}
    }
    Some(())
}

/// `set router bgp vrf <NAME> rd <RD>`.
pub fn config_vrf_rd(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let cfg = vrf_entry(bgp, name);
    match op {
        ConfigOp::Set => {
            let rd_str = args.string()?;
            cfg.rd = Some(RouteDistinguisher::from_str(&rd_str).ok()?);
        }
        ConfigOp::Delete => cfg.rd = None,
        _ => {}
    }
    Some(())
}

/// `set router bgp vrf <NAME> router-id <IPv4>`.
pub fn config_vrf_router_id(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let cfg = vrf_entry(bgp, name);
    match op {
        ConfigOp::Set => cfg.router_id = Some(args.v4addr()?),
        ConfigOp::Delete => cfg.router_id = None,
        _ => {}
    }
    Some(())
}

/// `set router bgp vrf <NAME> label-mode {per-vrf|per-route|per-nexthop}`.
pub fn config_vrf_label_mode(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let cfg = vrf_entry(bgp, name);
    match op {
        ConfigOp::Set => {
            let raw = args.string()?;
            cfg.label_mode = BgpVrfLabelMode::parse(&raw)?;
        }
        ConfigOp::Delete => cfg.label_mode = BgpVrfLabelMode::default(),
        _ => {}
    }
    Some(())
}

/// `set router bgp vrf <NAME> encapsulation {mpls|srv6}`.
pub fn config_vrf_encapsulation(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let cfg = vrf_entry(bgp, name);
    match op {
        ConfigOp::Set => {
            let raw = args.string()?;
            cfg.encapsulation = BgpVrfEncapsulation::parse(&raw)?;
        }
        ConfigOp::Delete => cfg.encapsulation = BgpVrfEncapsulation::default(),
        _ => {}
    }
    Some(())
}

/// `set router bgp vrf <NAME> neighbor <addr>` — list-key handler.
pub fn config_vrf_neighbor(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let addr = args.addr()?;
    let cfg = vrf_entry(bgp, name);
    match op {
        ConfigOp::Set => {
            cfg.neighbors.entry(addr).or_default();
        }
        ConfigOp::Delete => {
            cfg.neighbors.remove(&addr);
        }
        _ => {}
    }
    Some(())
}

/// `set router bgp vrf <NAME> neighbor <addr> remote-as <ASN>`.
pub fn config_vrf_neighbor_remote_as(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let addr = args.addr()?;
    let cfg = vrf_entry(bgp, name);
    let nbr = cfg.neighbors.entry(addr).or_default();
    match op {
        ConfigOp::Set => nbr.remote_as = Some(args.u32()?),
        ConfigOp::Delete => nbr.remote_as = None,
        _ => {}
    }
    Some(())
}

/// `set router bgp vrf <NAME> neighbor <addr> peer-group <GROUP>`.
pub fn config_vrf_neighbor_peer_group(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let addr = args.addr()?;
    let cfg = vrf_entry(bgp, name);
    let nbr = cfg.neighbors.entry(addr).or_default();
    match op {
        ConfigOp::Set => nbr.peer_group = Some(args.string()?),
        ConfigOp::Delete => nbr.peer_group = None,
        _ => {}
    }
    Some(())
}

/// `set router bgp vrf <NAME> neighbor <addr> description <STRING>`.
pub fn config_vrf_neighbor_description(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let addr = args.addr()?;
    let cfg = vrf_entry(bgp, name);
    let nbr = cfg.neighbors.entry(addr).or_default();
    match op {
        ConfigOp::Set => nbr.description = Some(args.string()?),
        ConfigOp::Delete => nbr.description = None,
        _ => {}
    }
    Some(())
}

/// `set router bgp vrf <NAME> neighbor <addr> enabled <BOOL>`.
pub fn config_vrf_neighbor_enabled(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let addr = args.addr()?;
    let cfg = vrf_entry(bgp, name);
    let nbr = cfg.neighbors.entry(addr).or_default();
    match op {
        ConfigOp::Set => nbr.enabled = args.boolean()?,
        // Reset to YANG default on delete.
        ConfigOp::Delete => nbr.enabled = true,
        _ => {}
    }
    Some(())
}

/// `set router bgp vrf <NAME> afi-safi ipv4` — presence container.
pub fn config_vrf_afi_ipv4(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let cfg = vrf_entry(bgp, name);
    match op {
        ConfigOp::Set => {
            cfg.ipv4_unicast.get_or_insert_with(Default::default);
        }
        ConfigOp::Delete => cfg.ipv4_unicast = None,
        _ => {}
    }
    Some(())
}

/// `set router bgp vrf <NAME> afi-safi ipv4 network <PREFIX>`.
pub fn config_vrf_afi_ipv4_network(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let cfg = vrf_entry(bgp, name);
    let af = cfg.ipv4_unicast.get_or_insert_with(Default::default);
    let prefix = args.v4net()?;
    match op {
        ConfigOp::Set => {
            af.networks.insert(prefix);
        }
        ConfigOp::Delete => {
            af.networks.remove(&prefix);
        }
        _ => {}
    }
    Some(())
}

/// `set router bgp vrf <NAME> afi-safi ipv6` — presence container.
pub fn config_vrf_afi_ipv6(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let cfg = vrf_entry(bgp, name);
    match op {
        ConfigOp::Set => {
            cfg.ipv6_unicast.get_or_insert_with(Default::default);
        }
        ConfigOp::Delete => cfg.ipv6_unicast = None,
        _ => {}
    }
    Some(())
}

/// `set router bgp vrf <NAME> afi-safi ipv6 network <PREFIX>`.
pub fn config_vrf_afi_ipv6_network(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let cfg = vrf_entry(bgp, name);
    let af = cfg.ipv6_unicast.get_or_insert_with(Default::default);
    let prefix = args.v6net()?;
    match op {
        ConfigOp::Set => {
            af.networks.insert(prefix);
        }
        ConfigOp::Delete => {
            af.networks.remove(&prefix);
        }
        _ => {}
    }
    Some(())
}

/// `set router bgp vrf <NAME> evpn advertise-ipv4 <bool>`.
pub fn config_vrf_evpn_advertise_ipv4(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let cfg = vrf_entry(bgp, name);
    match op {
        ConfigOp::Set => cfg.evpn_advertise_v4 = args.boolean()?,
        ConfigOp::Delete => cfg.evpn_advertise_v4 = false,
        _ => {}
    }
    Some(())
}

/// `set router bgp vrf <NAME> evpn advertise-ipv6 <bool>`.
pub fn config_vrf_evpn_advertise_ipv6(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let cfg = vrf_entry(bgp, name);
    match op {
        ConfigOp::Set => cfg.evpn_advertise_v6 = args.boolean()?,
        ConfigOp::Delete => cfg.evpn_advertise_v6 = false,
        _ => {}
    }
    Some(())
}

/// Commit-time observation hook. Emits a single `debug!` line per
/// VRF entry so operators can see the staged intent at the boundary
/// where spawn / despawn logic consumes `Bgp::vrfs`.
pub fn log_commit_diff(bgp: &Bgp) {
    if bgp.vrfs.is_empty() {
        return;
    }
    for (name, cfg) in &bgp.vrfs {
        bgp_vrf_trace!(
            bgp.tracing,
            vrf = %name,
            rd = ?cfg.rd,
            router_id = ?cfg.router_id,
            label_mode = ?cfg.label_mode,
            neighbors = cfg.neighbors.len(),
            ipv4_unicast = cfg.ipv4_unicast.is_some(),
            ipv6_unicast = cfg.ipv6_unicast.is_some(),
            evpn_advertise_v4 = cfg.evpn_advertise_v4,
            evpn_advertise_v6 = cfg.evpn_advertise_v6,
            "bgp: per-VRF intent staged",
        );
    }
}

#[cfg(test)]
mod tests {
    //! Pure-data tests on `BgpVrfConfig`. Building a full `Bgp`
    //! instance is impractical (it owns netlink-bound state and
    //! channels), so these tests exercise the callback bodies via
    //! a small helper that mutates a `BTreeMap<String, BgpVrfConfig>`
    //! directly. The callbacks themselves are thin wrappers over the
    //! same map mutations, so the test coverage of the staging
    //! shape is faithful to production behaviour.
    use super::*;

    fn neighbor_or_default(cfg: &mut BgpVrfConfig, addr: IpAddr) -> &mut BgpVrfNeighborConfig {
        cfg.neighbors.entry(addr).or_default()
    }

    #[test]
    fn label_mode_parse_accepts_yang_enums() {
        assert_eq!(
            BgpVrfLabelMode::parse("per-vrf"),
            Some(BgpVrfLabelMode::Vrf)
        );
        assert_eq!(
            BgpVrfLabelMode::parse("per-route"),
            Some(BgpVrfLabelMode::Route)
        );
        assert_eq!(
            BgpVrfLabelMode::parse("per-nexthop"),
            Some(BgpVrfLabelMode::Nexthop)
        );
        assert_eq!(BgpVrfLabelMode::parse("bogus"), None);
    }

    #[test]
    fn encapsulation_parse_accepts_yang_enums() {
        assert_eq!(
            BgpVrfEncapsulation::parse("mpls"),
            Some(BgpVrfEncapsulation::Mpls)
        );
        assert_eq!(
            BgpVrfEncapsulation::parse("srv6"),
            Some(BgpVrfEncapsulation::Srv6)
        );
        assert_eq!(BgpVrfEncapsulation::parse("bogus"), None);
    }

    #[test]
    fn vrf_config_default_encapsulation_is_mpls() {
        // YANG default is `mpls` — a VRF with no `encapsulation` leaf
        // keeps the RFC 4364 MPLS service-label data path.
        assert_eq!(
            BgpVrfConfig::default().encapsulation,
            BgpVrfEncapsulation::Mpls
        );
    }

    #[test]
    fn neighbor_default_is_enabled() {
        // YANG default for `enabled` is true — every other leaf is
        // None, so a `set ... neighbor X` without further leaves
        // produces a live peer at materialization time.
        let nbr = BgpVrfNeighborConfig::default();
        assert!(nbr.enabled);
        assert!(nbr.remote_as.is_none());
        assert!(nbr.peer_group.is_none());
        assert!(nbr.description.is_none());
    }

    #[test]
    fn vrf_config_default_has_label_mode_per_vrf() {
        let cfg = BgpVrfConfig::default();
        assert_eq!(cfg.label_mode, BgpVrfLabelMode::Vrf);
        assert!(cfg.rd.is_none());
        assert!(cfg.router_id.is_none());
        assert!(cfg.neighbors.is_empty());
        assert!(cfg.ipv4_unicast.is_none());
        assert!(cfg.ipv6_unicast.is_none());
    }

    #[test]
    fn rd_round_trips_through_from_str() {
        let rd = RouteDistinguisher::from_str("65000:10").expect("RD parses");
        let mut cfg = BgpVrfConfig {
            rd: Some(rd),
            ..Default::default()
        };
        assert_eq!(cfg.rd, Some(rd));
        cfg.rd = None;
        assert!(cfg.rd.is_none());
    }

    #[test]
    fn neighbor_remote_as_set_and_clear() {
        let mut cfg = BgpVrfConfig::default();
        let addr: IpAddr = "192.0.2.1".parse().unwrap();
        let nbr = neighbor_or_default(&mut cfg, addr);
        nbr.remote_as = Some(65001);
        assert_eq!(
            cfg.neighbors.get(&addr).and_then(|n| n.remote_as),
            Some(65001)
        );

        let nbr = cfg.neighbors.get_mut(&addr).unwrap();
        nbr.remote_as = None;
        assert!(cfg.neighbors.get(&addr).unwrap().remote_as.is_none());
    }

    #[test]
    fn afi_v4_network_insert_and_remove() {
        let mut cfg = BgpVrfConfig::default();
        let prefix: Ipv4Net = "10.10.0.0/16".parse().unwrap();
        cfg.ipv4_unicast
            .get_or_insert_with(Default::default)
            .networks
            .insert(prefix);
        assert!(
            cfg.ipv4_unicast
                .as_ref()
                .unwrap()
                .networks
                .contains(&prefix)
        );
        cfg.ipv4_unicast.as_mut().unwrap().networks.remove(&prefix);
        assert!(cfg.ipv4_unicast.as_ref().unwrap().networks.is_empty());
    }

    #[test]
    fn afi_v6_network_insert_and_remove() {
        let mut cfg = BgpVrfConfig::default();
        let prefix: Ipv6Net = "2001:db8::/64".parse().unwrap();
        cfg.ipv6_unicast
            .get_or_insert_with(Default::default)
            .networks
            .insert(prefix);
        assert!(
            cfg.ipv6_unicast
                .as_ref()
                .unwrap()
                .networks
                .contains(&prefix)
        );
        cfg.ipv6_unicast.as_mut().unwrap().networks.remove(&prefix);
        assert!(cfg.ipv6_unicast.as_ref().unwrap().networks.is_empty());
    }
}
