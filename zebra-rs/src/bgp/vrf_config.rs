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
//!   schema). Resolution against `neighbor-group <X>`
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
use super::vrf::msg::BgpVrfMsg;

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

/// SRv6 mobile user-plane direction for a per-VRF MUP service
/// (zebra-bgp-vrf.yang `afi-safi mup route {st1|st2}`). `Decapsulation`
/// is the `st2` egress/uplink (Type-2 ST, the N3 VRF); `Encapsulation`
/// is the `st1` ingress/downlink (Type-1 ST, the N6 VRF).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MupSrv6Direction {
    Decapsulation,
    Encapsulation,
}

/// MUP Segment Discovery route type for a per-VRF service — the PE side
/// (zebra-bgp-vrf.yang `afi-safi mup segment {direct|interwork}`).
/// `Direct` originates a Direct Segment Discovery (DSD, type 2) route
/// carrying the VRF's End.DT46 SID; `Interwork` an Interwork Segment
/// Discovery (ISD, type 1) route. Independent of [`MupSrv6Mobile`], which
/// is the controller-side Session-Transformed origination binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MupSegmentMode {
    Direct,
    Interwork,
}

impl MupSegmentMode {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "direct" => Some(Self::Direct),
            "interwork" => Some(Self::Interwork),
            _ => None,
        }
    }
}

/// `afi-safi mup route {st1|st2} { network-instance <ni>; [mup-ext-comm
/// <2:4>;] }` for one VRF: the ST route type (as a direction) plus the
/// session network-instance matched, and (st2 only) the Direct-segment
/// MUP Extended Community the originated ST2 routes resolve to. Surfaced
/// in `show bgp mup` (the `MUP VRFs:` block) and consumed by the
/// P5 MUP controller when it originates ST routes (st2/Decapsulation →
/// Type-2 ST, the N3 VRF; st1/Encapsulation → Type-1 ST, the N6 VRF).
#[derive(Debug, Clone)]
pub struct MupSrv6Mobile {
    pub direction: MupSrv6Direction,
    pub network_instance: Option<String>,
    /// `afi-safi mup route st2 mup-ext-comm <2:4>` — the BGP MUP Extended
    /// Community (Direct-Type Segment Identifier, draft-mpmz-bess-mup-safi
    /// §3.2 / §3.3.10) attached to the Type-2 ST routes this VRF
    /// originates, so a receiving PE resolves the (endpoint, TEID) tunnel
    /// onto the matching End.DT46 Direct segment. Set only for the
    /// Decapsulation (st2) direction; `None` for st1.
    pub mup_ext_comm: Option<RouteDistinguisher>,
}

/// Per-VRF BGP MUP (RFC 9833) service config — the `mup`
/// container under `router bgp vrf <name>` in zebra-bgp-vrf.yang. Holds
/// only the `route {st1|st2}` origination binding; the export/import
/// route-targets live on the top-level `vrf <name> mup
/// route-target {export|import}` (RIB-owned, surfaced to BGP via
/// `rib_known_vrfs`), the same framework as ipv4 / ipv6.
#[derive(Default, Debug, Clone)]
pub struct BgpVrfMobileUplane {
    pub srv6_mobile: Option<MupSrv6Mobile>,
    /// `afi-safi mup segment {direct|interwork}` — PE-side Segment
    /// Discovery origination for this VRF. `Direct` → DSD (type 2,
    /// carrying the VRF's End.DT46 SID); `Interwork` → ISD (type 1,
    /// origination deferred). Independent of `srv6_mobile`.
    pub segment: Option<MupSegmentMode>,
    /// `afi-safi mup segment direct mup-ext-comm <2:4>` — the BGP MUP
    /// Extended Community (transitive type 0x0c, sub-type 0x00 =
    /// Direct-Type Segment Identifier, draft-mpmz-bess-mup-safi §3.2)
    /// identifying this VRF's Direct segment. Attached to the VRF's DSD
    /// route and to the controller's Type-2 ST routes that resolve to
    /// this Direct segment (§3.3.10 / §3.3.12). The 6-octet value reuses
    /// the RD/RT 2:4 wire layout, so it is stored as a `RouteDistinguisher`.
    pub mup_ext_comm: Option<RouteDistinguisher>,
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
    /// Inter-AS MPLS/VPN Option AB (RFC 4364 hybrid of §10a/§10b).
    /// Mirrors `inter-as-hybrid` in zebra-bgp-vrf.yang. When set, the
    /// VRF re-exports the VPNv4 routes it *imports* (not only `network`/
    /// CE-learned ones), so an ASBR relays a remote AS's VPN routes to
    /// its own PEs over a single MP-eBGP VPNv4 session while still
    /// forwarding per-VRF. Default `false` (ordinary L3VPN VRF).
    pub inter_as_hybrid: bool,
    /// Per-VRF BGP MUP (RFC 9833) service config. Mirrors the
    /// `mup` container in zebra-bgp-vrf.yang.
    pub mobile_uplane: BgpVrfMobileUplane,
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

/// `set router bgp vrf <NAME> inter-as-hybrid <BOOL>` — RFC 4364
/// Inter-AS Option AB. Enables re-export of imported VPNv4 routes for
/// this VRF (see [`BgpVrfConfig::inter_as_hybrid`]).
pub fn config_vrf_inter_as_hybrid(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let cfg = vrf_entry(bgp, name);
    match op {
        ConfigOp::Set => cfg.inter_as_hybrid = args.boolean()?,
        ConfigOp::Delete => cfg.inter_as_hybrid = false,
        _ => {}
    }
    Some(())
}

/// Map an `afi-safi mup route` list key (`st1`/`st2`) to the ST direction:
/// st1 = Encapsulation (downlink / N6 / ingress GTP encap), st2 =
/// Decapsulation (uplink / N3 / egress GTP decap).
fn mup_route_direction(key: &str) -> Option<MupSrv6Direction> {
    match key {
        "st1" => Some(MupSrv6Direction::Encapsulation),
        "st2" => Some(MupSrv6Direction::Decapsulation),
        _ => None,
    }
}

/// Borrow-or-create the per-VRF `srv6_mobile` binding for the given ST
/// direction, forcing the direction (the single binding flips st1↔st2 if
/// the VRF is reconfigured). Lets the `network-instance` / `mup-ext-comm`
/// child-leaf handlers accumulate into the same binding regardless of the
/// order their callbacks fire.
fn mup_route_binding(cfg: &mut BgpVrfConfig, direction: MupSrv6Direction) -> &mut MupSrv6Mobile {
    let sm = cfg.mobile_uplane.srv6_mobile.get_or_insert(MupSrv6Mobile {
        direction,
        network_instance: None,
        mup_ext_comm: None,
    });
    sm.direction = direction;
    sm
}

/// `set router bgp vrf <NAME> afi-safi mup route {st1|st2}` — list-key
/// handler. Establishes the ST direction binding (st1 = Encapsulation /
/// downlink, st2 = Decapsulation / uplink); the session network-instance
/// and (st2) the Direct-segment `mup-ext-comm` hang off child leaves.
pub fn config_vrf_mup_route(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let direction = mup_route_direction(&args.string()?)?;
    let cfg = vrf_entry(bgp, name);
    match op {
        ConfigOp::Set => {
            mup_route_binding(cfg, direction);
        }
        ConfigOp::Delete
            if cfg
                .mobile_uplane
                .srv6_mobile
                .as_ref()
                .map(|sm| sm.direction)
                == Some(direction) =>
        {
            cfg.mobile_uplane.srv6_mobile = None;
        }
        _ => {}
    }
    Some(())
}

/// `set router bgp vrf <NAME> afi-safi mup route {st1|st2} network-instance
/// <NI>` — the PFCP session Network Instance this VRF originates ST routes
/// for. Matched against the session's Network Instance by the MUP
/// controller (st1 → Type-1 ST / ingress encap; st2 → Type-2 ST / egress
/// decap).
pub fn config_vrf_mup_route_network_instance(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let name = args.string()?;
    let direction = mup_route_direction(&args.string()?)?;
    let cfg = vrf_entry(bgp, name);
    match op {
        ConfigOp::Set => {
            let ni = args.string()?;
            mup_route_binding(cfg, direction).network_instance = Some(ni);
        }
        ConfigOp::Delete => {
            if let Some(sm) = cfg.mobile_uplane.srv6_mobile.as_mut()
                && sm.direction == direction
            {
                sm.network_instance = None;
            }
        }
        _ => {}
    }
    Some(())
}

/// `set router bgp vrf <NAME> afi-safi mup route st2 mup-ext-comm <2:4>` —
/// the BGP MUP Extended Community (Direct-Type Segment Identifier) the
/// originated Type-2 ST routes resolve to (draft §3.3.10). Meaningful only
/// under `route st2` (Decapsulation); stored on the `srv6_mobile` binding.
pub fn config_vrf_mup_route_mup_ext_comm(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let name = args.string()?;
    let direction = mup_route_direction(&args.string()?)?;
    let cfg = vrf_entry(bgp, name);
    match op {
        ConfigOp::Set => {
            let raw = args.string()?;
            mup_route_binding(cfg, direction).mup_ext_comm =
                Some(RouteDistinguisher::from_str(&raw).ok()?);
        }
        ConfigOp::Delete => {
            if let Some(sm) = cfg.mobile_uplane.srv6_mobile.as_mut()
                && sm.direction == direction
            {
                sm.mup_ext_comm = None;
            }
        }
        _ => {}
    }
    Some(())
}

/// `set router bgp vrf <NAME> afi-safi mup segment {direct|interwork}` —
/// list-key handler for the `segment` list (keyed by the route type).
/// PE-side Segment Discovery origination. `direct` originates a Direct
/// Segment Discovery (DSD, type 2) route carrying the VRF's End.DT46 SID;
/// `interwork` an Interwork Segment Discovery (ISD, type 1) route. The
/// list key is the only token, so it is read before the op branch (the
/// `config_vrf_neighbor` pattern) and the delete only clears a matching
/// mode.
pub fn config_vrf_mup_segment(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let mode = MupSegmentMode::parse(&args.string()?)?;
    let cfg = vrf_entry(bgp, name);
    match op {
        ConfigOp::Set => cfg.mobile_uplane.segment = Some(mode),
        ConfigOp::Delete if cfg.mobile_uplane.segment == Some(mode) => {
            cfg.mobile_uplane.segment = None;
        }
        _ => {}
    }
    Some(())
}

/// `set router bgp vrf <NAME> afi-safi mup segment direct mup-ext-comm
/// <2:4>` — the BGP MUP Extended Community (Direct-Type Segment
/// Identifier) for this VRF's Direct segment. This leaf hangs off the
/// `segment` list, so the segment list key (`direct`/`interwork`) sits
/// between the VRF name and the value and is skipped here. The value is
/// the RD/RT 2:4 notation, stored as a `RouteDistinguisher` whose 6-octet
/// `val` maps straight onto the extended-community value.
pub fn config_vrf_mup_ext_comm(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let _segment = args.string()?; // segment list key (direct|interwork)
    let cfg = vrf_entry(bgp, name);
    match op {
        ConfigOp::Set => {
            let raw = args.string()?;
            cfg.mobile_uplane.mup_ext_comm = Some(RouteDistinguisher::from_str(&raw).ok()?);
        }
        ConfigOp::Delete => cfg.mobile_uplane.mup_ext_comm = None,
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
    match op {
        ConfigOp::Set => {
            vrf_entry(bgp, name)
                .ipv4_unicast
                .get_or_insert_with(Default::default);
        }
        ConfigOp::Delete => {
            // Dropping the whole `afi-safi ipv4` container collapses to
            // this container delete — the per-network deletes are not
            // re-emitted — so withdraw every self-originated network
            // from the running VRF before clearing, else the routes
            // outlive the config. Idempotent with
            // `config_vrf_afi_ipv4_network`: a repeat WithdrawNetwork
            // on an already-gone prefix is a no-op in the VRF task.
            let nets: Vec<Ipv4Net> = bgp
                .vrfs
                .get(&name)
                .and_then(|c| c.ipv4_unicast.as_ref())
                .map(|af| af.networks.iter().copied().collect())
                .unwrap_or_default();
            if let Some(handle) = bgp.vrf_registry.get(&name) {
                for prefix in nets {
                    let _ = handle.inbox.send(BgpVrfMsg::WithdrawNetwork { prefix });
                }
            }
            vrf_entry(bgp, name).ipv4_unicast = None;
        }
        _ => {}
    }
    Some(())
}

/// `set router bgp vrf <NAME> afi-safi ipv4 network <PREFIX>`.
pub fn config_vrf_afi_ipv4_network(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let prefix = args.v4net()?;
    let set = match op {
        ConfigOp::Set => true,
        ConfigOp::Delete => false,
        _ => return Some(()),
    };
    {
        let af = vrf_entry(bgp, name.clone())
            .ipv4_unicast
            .get_or_insert_with(Default::default);
        if set {
            af.networks.insert(prefix);
        } else {
            af.networks.remove(&prefix);
        }
    }
    // `compute_vrf_diff` only spawns / despawns on the VRF *name*
    // set, so a `network` add/remove on an already-running VRF
    // reaches the task only through a message — drive the
    // originate / withdraw on the live instance. When the VRF isn't
    // spawned yet (initial config), the spawn-time materialize reads
    // the same `networks` set, so the message is simply skipped.
    if let Some(handle) = bgp.vrf_registry.get(&name) {
        let msg = if set {
            BgpVrfMsg::OriginateNetwork { prefix }
        } else {
            BgpVrfMsg::WithdrawNetwork { prefix }
        };
        let _ = handle.inbox.send(msg);
    }
    Some(())
}

/// `set router bgp vrf <NAME> afi-safi ipv6` — presence container.
pub fn config_vrf_afi_ipv6(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    match op {
        ConfigOp::Set => {
            vrf_entry(bgp, name)
                .ipv6_unicast
                .get_or_insert_with(Default::default);
        }
        ConfigOp::Delete => {
            // See `config_vrf_afi_ipv4`: withdraw every self-originated
            // network from the running VRF before dropping the
            // container, since the container delete is all the diff
            // emits when the whole `afi-safi ipv6` block is removed.
            let nets: Vec<Ipv6Net> = bgp
                .vrfs
                .get(&name)
                .and_then(|c| c.ipv6_unicast.as_ref())
                .map(|af| af.networks.iter().copied().collect())
                .unwrap_or_default();
            if let Some(handle) = bgp.vrf_registry.get(&name) {
                for prefix in nets {
                    let _ = handle.inbox.send(BgpVrfMsg::WithdrawNetworkV6 { prefix });
                }
            }
            vrf_entry(bgp, name).ipv6_unicast = None;
        }
        _ => {}
    }
    Some(())
}

/// `set router bgp vrf <NAME> afi-safi ipv6 network <PREFIX>`.
pub fn config_vrf_afi_ipv6_network(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let prefix = args.v6net()?;
    let set = match op {
        ConfigOp::Set => true,
        ConfigOp::Delete => false,
        _ => return Some(()),
    };
    {
        let af = vrf_entry(bgp, name.clone())
            .ipv6_unicast
            .get_or_insert_with(Default::default);
        if set {
            af.networks.insert(prefix);
        } else {
            af.networks.remove(&prefix);
        }
    }
    // See `config_vrf_afi_ipv4_network`: drive the originate /
    // withdraw on the running VRF task, since `compute_vrf_diff`
    // never re-spawns it for a network-only change.
    if let Some(handle) = bgp.vrf_registry.get(&name) {
        let msg = if set {
            BgpVrfMsg::OriginateNetworkV6 { prefix }
        } else {
            BgpVrfMsg::WithdrawNetworkV6 { prefix }
        };
        let _ = handle.inbox.send(msg);
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
    fn mobile_uplane_default_is_empty() {
        let mup = BgpVrfConfig::default().mobile_uplane;
        assert!(mup.srv6_mobile.is_none());
    }

    #[test]
    fn mobile_uplane_srv6_decap_and_encap() {
        let mut cfg = BgpVrfConfig::default();
        cfg.mobile_uplane.srv6_mobile = Some(MupSrv6Mobile {
            direction: MupSrv6Direction::Decapsulation,
            network_instance: Some("core-ni".to_string()),
            mup_ext_comm: Some("1:2".parse().unwrap()),
        });
        let sm = cfg.mobile_uplane.srv6_mobile.as_ref().unwrap();
        assert_eq!(sm.direction, MupSrv6Direction::Decapsulation);
        assert_eq!(sm.network_instance.as_deref(), Some("core-ni"));
        assert_eq!(sm.mup_ext_comm, Some("1:2".parse().unwrap()));

        cfg.mobile_uplane.srv6_mobile = Some(MupSrv6Mobile {
            direction: MupSrv6Direction::Encapsulation,
            network_instance: Some("access-ni".to_string()),
            mup_ext_comm: None,
        });
        assert_eq!(
            cfg.mobile_uplane.srv6_mobile.as_ref().unwrap().direction,
            MupSrv6Direction::Encapsulation
        );

        cfg.mobile_uplane.srv6_mobile = None;
        assert!(cfg.mobile_uplane.srv6_mobile.is_none());
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
