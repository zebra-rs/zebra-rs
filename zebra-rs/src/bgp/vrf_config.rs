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
//!   schema). Resolution against `neighbor-group <X>` (remote-as
//!   fallback + afi-safi opinions) happens when the per-VRF runtime
//!   materializes peers.
//! - The label-mode value is parsed at the callback boundary into a
//!   typed enum; bad input fails the callback and is rejected by the
//!   config commit (same shape every other `enum`-typed leaf uses).

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

use bgp_packet::{AfiSafi, RouteDistinguisher};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};

use crate::bgp_vrf_trace;
use crate::config::{Args, ConfigOp};

use super::Bgp;
use super::config::BgpRedistSource;
use super::peer::PeerConfig;
use super::vrf::msg::BgpVrfMsg;
use crate::rib::RedistAfi;

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
    /// EVPN symmetric IRB (RFC 9135): a Type-5 carries an L3VNI (the NLRI
    /// label) + this PE's router MAC (a Router's-MAC EC), routed over VXLAN.
    Vxlan,
}

impl BgpVrfEncapsulation {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "mpls" => Some(Self::Mpls),
            "srv6" => Some(Self::Srv6),
            "vxlan" => Some(Self::Vxlan),
            _ => None,
        }
    }
}

/// Per-peer attribute set for a CE peer configured under
/// `router bgp vrf X neighbor <addr>`. Mirrors `bgp-vrf-neighbor` in
/// zebra-bgp-vrf.yang.
/// Staging is the peer's *own* [`PeerConfig`] type rather than a
/// parallel struct that mirrors fragments of it. Every knob imported
/// from the global neighbor then costs a YANG leaf and one shared
/// setter — no new field here, no new line in `materialize_peers`, and
/// no opportunity for the two representations to drift.
///
/// `remote_as` stays outside because it lands on [`super::peer::Peer`]
/// itself, not on its config. Everything else the schema exposes
/// (`description`, `peer-group`, `timers`, per-family `afi-safi`
/// knobs) is a `PeerConfig` field already.
///
/// Fields the per-VRF schema does not expose simply keep their
/// `PeerConfig::default()` values, which is exactly what a peer built
/// by `Peer::new` would have had — so staging the whole struct is
/// behaviour-preserving for anything unconfigured, and wiring a new
/// knob later is a schema + setter change with no plumbing.
#[derive(Debug, Clone, Default)]
pub struct BgpVrfNeighborConfig {
    pub remote_as: Option<u32>,
    pub config: PeerConfig,
    /// Staged `afi-safi <af> {policy,prefix-set} {in,out} <name>`
    /// references.
    ///
    /// These are the one per-AFI knob that cannot ride `config` like
    /// every other: the resolved slots live on [`super::peer::Peer`]
    /// (`policy_list` / `prefix_set`), not on `PeerConfig`, because each
    /// holds the *resolved* set the policy actor hands back alongside
    /// the operator's name. `materialize_peers` therefore copies these
    /// onto the built peer separately, and — unlike every other knob —
    /// must also register a watch so the name resolves at all.
    pub policy_refs: BTreeMap<(AfiSafi, VrfPolicyRef), String>,
}

/// Which of a CE peer's four per-family policy bindings a staged name
/// refers to. Maps 1:1 onto [`crate::policy::PolicyType`]; kept separate
/// so the staging map has a total order and carries no variants (key
/// chains, table maps) a per-VRF neighbor cannot bind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum VrfPolicyRef {
    PolicyIn,
    PolicyOut,
    PrefixSetIn,
    PrefixSetOut,
}

impl VrfPolicyRef {
    pub fn policy_type(self) -> crate::policy::PolicyType {
        use crate::policy::PolicyType;
        match self {
            Self::PolicyIn => PolicyType::PolicyListIn,
            Self::PolicyOut => PolicyType::PolicyListOut,
            Self::PrefixSetIn => PolicyType::PrefixSetIn,
            Self::PrefixSetOut => PolicyType::PrefixSetOut,
        }
    }
}

impl BgpVrfNeighborConfig {
    /// The referenced `neighbor-group` name, if any. `materialize_peers`
    /// resolves the group's opinions eagerly at build time (the global
    /// group sweep doesn't reach per-VRF tasks).
    pub fn peer_group(&self) -> Option<&String> {
        self.config.neighbor_group.as_ref()
    }
}

/// Per-AFI knobs under `router bgp vrf X afi-safi {ipv4,ipv6}-unicast`.
/// Generic on the prefix type so the same struct holds either v4 or
/// v6 networks.
#[derive(Debug, Clone)]
pub struct BgpVrfAfConfig<N: Ord> {
    pub networks: BTreeSet<N>,
    /// Redistribution sources enabled for this VRF/AFI
    /// (`afi-safi {ipv4,ipv6} redistribute {connected,static}`). Each
    /// pulls the VRF table's routes of that protocol into the per-VRF
    /// Loc-RIB for VPNv4/v6 export. Bare presence today (no per-source
    /// modifiers).
    pub redistribute: BTreeSet<BgpRedistSource>,
}

impl<N: Ord> Default for BgpVrfAfConfig<N> {
    fn default() -> Self {
        Self {
            networks: BTreeSet::new(),
            redistribute: BTreeSet::new(),
        }
    }
}

/// SRv6 mobile user-plane direction for a per-VRF MUP service
/// (zebra-bgp-vrf.yang `afi-safi mup route {st1|st2}`). `Decapsulation`
/// is the `st2` egress/uplink (Type-2 ST, the N3 side); `Encapsulation`
/// is the `st1` ingress/downlink (Type-1 ST, the N6 side). Ordered so it
/// can key the per-direction `routes` map on [`BgpVrfMobileUplane`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MupSrv6Direction {
    Decapsulation,
    Encapsulation,
}

/// MUP Segment Discovery route type for a per-VRF service — the PE side
/// (zebra-bgp-vrf.yang `afi-safi mup segment {direct|interwork}`).
/// `Direct` originates a Direct Segment Discovery (DSD, type 2) route
/// carrying the VRF's End.DT46 SID; `Interwork` an Interwork Segment
/// Discovery (ISD, type 1) route. Independent of [`MupRouteBinding`], which
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

/// MUP forwarding-plane behaviour for a per-VRF service (`afi-safi mup
/// dataplane {end-dt46|gtp}`). `EndDt46` (default) installs the SRv6 End.DT46
/// stand-in into the mainline kernel; `Gtp` programs a real GTP-U tunnel from
/// the ST route's endpoint + TEID via the cradle eBPF forwarder. The control
/// plane is identical either way — this selects only the endpoint behaviour
/// advertised and the FIB-install target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MupDataplane {
    #[default]
    EndDt46,
    Gtp,
}

impl MupDataplane {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "end-dt46" => Some(Self::EndDt46),
            "gtp" => Some(Self::Gtp),
            _ => None,
        }
    }
}

/// One `afi-safi mup route {st1|st2} { network-instance <ni>;
/// [mup-ext-comm <2:4>;] }` list entry for one VRF: the session
/// network-instance matched, and (st2 only) the Direct-segment MUP
/// Extended Community the originated ST2 routes resolve to. Keyed by
/// its [`MupSrv6Direction`] in [`BgpVrfMobileUplane::routes`], so one
/// VRF may bind BOTH directions and serve a bidirectional UPF behind a
/// single N6 interface (issue #1947). Surfaced in `show bgp mup` (the
/// `MUP VRFs:` block) and consumed by the P5 MUP controller when it
/// originates ST routes (st2/Decapsulation → Type-2 ST;
/// st1/Encapsulation → Type-1 ST).
#[derive(Default, Debug, Clone)]
pub struct MupRouteBinding {
    pub network_instance: Option<String>,
    /// `afi-safi mup route st2 mup-ext-comm <2:4>` — the BGP MUP Extended
    /// Community (Direct-Type Segment Identifier, draft-mpmz-bess-mup-safi
    /// §3.2 / §3.3.10) attached to the Type-2 ST routes this VRF
    /// originates, so a receiving PE resolves the (endpoint, TEID) tunnel
    /// onto the matching End.DT46 Direct segment. Meaningful only on the
    /// Decapsulation (st2) binding; `None` for st1.
    pub mup_ext_comm: Option<RouteDistinguisher>,
}

/// Per-VRF BGP MUP (draft-ietf-bess-mup-safi) service config — the `mup`
/// container under `router bgp vrf <name>` in zebra-bgp-vrf.yang. Holds
/// only the `route {st1|st2}` origination binding; the export/import
/// route-targets live on the top-level `vrf <name> mup
/// route-target {export|import}` (RIB-owned, surfaced to BGP via
/// `rib_known_vrfs`), the same framework as ipv4 / ipv6.
#[derive(Default, Debug, Clone)]
pub struct BgpVrfMobileUplane {
    /// `afi-safi mup route {st1|st2}` — the controller-side ST origination
    /// bindings, keyed by direction. One VRF may carry both an `st1` and an
    /// `st2` entry (a bidirectional UPF behind a single N6 interface/VRF,
    /// issue #1947); the two-VRF split (one direction each) remains valid.
    pub routes: BTreeMap<MupSrv6Direction, MupRouteBinding>,
    /// `afi-safi mup segment {direct|interwork}` — PE-side Segment
    /// Discovery origination for this VRF. `Direct` → DSD (type 2, NLRI =
    /// RD + router-id); `Interwork` → ISD (type 1, NLRI = RD +
    /// [`Self::interwork_prefix`]). Both carry the VRF's End.DT46 SID.
    /// Independent of `routes`.
    pub segment: Option<MupSegmentMode>,
    /// `afi-safi mup segment direct mup-ext-comm <2:4>` — the BGP MUP
    /// Extended Community (transitive type 0x0c, sub-type 0x00 =
    /// Direct-Type Segment Identifier, draft-mpmz-bess-mup-safi §3.2)
    /// identifying this VRF's Direct segment. Attached to the VRF's DSD
    /// route and to the controller's Type-2 ST routes that resolve to
    /// this Direct segment (§3.3.10 / §3.3.12). The 6-octet value reuses
    /// the RD/RT 2:4 wire layout, so it is stored as a `RouteDistinguisher`.
    pub mup_ext_comm: Option<RouteDistinguisher>,
    /// `afi-safi mup segment interwork prefix <p>` — the interwork segment
    /// prefix advertised in this VRF's Interwork Segment Discovery (ISD,
    /// type 1) route NLRI (draft-mpmz-bess-mup-safi §3.1.1), typically the
    /// locally connected gNodeB N3 prefix. Meaningful only under the
    /// `interwork` segment; the ISD does not originate until it is set, and
    /// its AFI follows this prefix's family.
    pub interwork_prefix: Option<IpNet>,
    /// `afi-safi mup dataplane {end-dt46|gtp}` — the forwarding-plane
    /// behaviour for this VRF's MUP service. `EndDt46` (default) installs the
    /// SRv6 End.DT46 stand-in into the mainline kernel; `Gtp` programs a real
    /// GTP-U tunnel from the resolved ST route's endpoint + TEID via the
    /// cradle eBPF forwarder.
    pub dataplane: MupDataplane,
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
    /// EVPN symmetric-IRB L3VNI for this VRF (RFC 9135): stamped as the
    /// Type-5 NLRI label. Mirrors `evpn l3vni` in zebra-bgp-vrf.yang.
    pub l3vni: Option<u32>,
    /// This PE's router MAC for the L3VNI — attached to originated Type-5
    /// routes as a Router's-MAC EC. Mirrors `evpn router-mac`.
    pub router_mac: Option<[u8; 6]>,
    /// Inter-AS MPLS/VPN Option AB (RFC 4364 hybrid of §10a/§10b).
    /// Mirrors `inter-as-hybrid` in zebra-bgp-vrf.yang. When set, the
    /// VRF re-exports the VPNv4 routes it *imports* (not only `network`/
    /// CE-learned ones), so an ASBR relays a remote AS's VPN routes to
    /// its own PEs over a single MP-eBGP VPNv4 session while still
    /// forwarding per-VRF. Default `false` (ordinary L3VPN VRF).
    pub inter_as_hybrid: bool,
    /// Per-VRF BGP MUP (draft-ietf-bess-mup-safi) service config. Mirrors the
    /// `mup` container in zebra-bgp-vrf.yang.
    pub mobile_uplane: BgpVrfMobileUplane,
}

/// Borrow the per-VRF entry on `Bgp::vrfs`, creating it for Set (the
/// "set leaf before set list-key" firing order makes lazy creation
/// necessary) but NEVER for Delete. A whole-subtree delete fires the
/// list-entry callback — which removes the map entry — before the
/// child-leaf delete callbacks, so a lazily re-created entry here
/// resurrected the VRF as a default config: `compute_vrf_diff` then
/// saw the name as still desired and the despawn (task teardown,
/// export purge, ILM withdraw, label reclaim) never ran. `None` on a
/// Delete for a gone VRF means "nothing left to mutate" — callbacks
/// early-return.
fn vrf_entry(bgp: &mut Bgp, name: String, op: ConfigOp) -> Option<&mut BgpVrfConfig> {
    match op {
        ConfigOp::Delete => bgp.vrfs.get_mut(&name),
        _ => Some(bgp.vrfs.entry(name).or_default()),
    }
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
    let cfg = vrf_entry(bgp, name, op)?;
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
    let cfg = vrf_entry(bgp, name, op)?;
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
    let cfg = vrf_entry(bgp, name, op)?;
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
    let cfg = vrf_entry(bgp, name, op)?;
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
    let cfg = vrf_entry(bgp, name, op)?;
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

/// Borrow-or-create the per-VRF `route {st1|st2}` binding for the given
/// ST direction. Each direction is its own map entry, so one VRF may
/// bind both st1 and st2 (issue #1947); the `network-instance` /
/// `mup-ext-comm` child-leaf handlers accumulate into their direction's
/// binding regardless of the order their callbacks fire.
fn mup_route_binding(cfg: &mut BgpVrfConfig, direction: MupSrv6Direction) -> &mut MupRouteBinding {
    cfg.mobile_uplane.routes.entry(direction).or_default()
}

/// `set router bgp vrf <NAME> afi-safi mup route {st1|st2}` — list-key
/// handler. Establishes the ST direction binding (st1 = Encapsulation /
/// downlink, st2 = Decapsulation / uplink); the session network-instance
/// and (st2) the Direct-segment `mup-ext-comm` hang off child leaves.
/// The delete removes only that direction's entry, leaving a sibling
/// direction's binding intact.
pub fn config_vrf_mup_route(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let direction = mup_route_direction(&args.string()?)?;
    let cfg = vrf_entry(bgp, name, op)?;
    match op {
        ConfigOp::Set => {
            mup_route_binding(cfg, direction);
        }
        ConfigOp::Delete => {
            cfg.mobile_uplane.routes.remove(&direction);
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
    let cfg = vrf_entry(bgp, name, op)?;
    match op {
        ConfigOp::Set => {
            let ni = args.string()?;
            mup_route_binding(cfg, direction).network_instance = Some(ni);
        }
        ConfigOp::Delete => {
            if let Some(binding) = cfg.mobile_uplane.routes.get_mut(&direction) {
                binding.network_instance = None;
            }
        }
        _ => {}
    }
    Some(())
}

/// `set router bgp vrf <NAME> afi-safi mup route st2 mup-ext-comm <2:4>` —
/// the BGP MUP Extended Community (Direct-Type Segment Identifier) the
/// originated Type-2 ST routes resolve to (draft §3.3.10). Meaningful only
/// under `route st2` (Decapsulation); stored on that direction's binding.
pub fn config_vrf_mup_route_mup_ext_comm(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let name = args.string()?;
    let direction = mup_route_direction(&args.string()?)?;
    let cfg = vrf_entry(bgp, name, op)?;
    match op {
        ConfigOp::Set => {
            let raw = args.string()?;
            mup_route_binding(cfg, direction).mup_ext_comm =
                Some(RouteDistinguisher::from_str(&raw).ok()?);
        }
        ConfigOp::Delete => {
            if let Some(binding) = cfg.mobile_uplane.routes.get_mut(&direction) {
                binding.mup_ext_comm = None;
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
    let cfg = vrf_entry(bgp, name, op)?;
    match op {
        ConfigOp::Set => cfg.mobile_uplane.segment = Some(mode),
        ConfigOp::Delete if cfg.mobile_uplane.segment == Some(mode) => {
            cfg.mobile_uplane.segment = None;
        }
        _ => {}
    }
    Some(())
}

/// `set router bgp vrf <NAME> afi-safi mup dataplane {end-dt46|gtp}` — the
/// MUP forwarding-plane behaviour for this VRF (the SRv6 End.DT46 stand-in vs
/// real GTP-U via cradle). Delete restores the default (End.DT46).
pub fn config_vrf_mup_dataplane(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let mode = MupDataplane::parse(&args.string()?)?;
    let cfg = vrf_entry(bgp, name, op)?;
    match op {
        ConfigOp::Set => cfg.mobile_uplane.dataplane = mode,
        ConfigOp::Delete => cfg.mobile_uplane.dataplane = MupDataplane::default(),
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
    let cfg = vrf_entry(bgp, name, op)?;
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

/// `set router bgp vrf <NAME> afi-safi mup segment interwork prefix <p>` —
/// the interwork segment prefix carried in this VRF's Interwork Segment
/// Discovery (ISD, type 1) route NLRI (draft §3.1.1). Like `mup-ext-comm`,
/// this leaf hangs off the `segment` list, so the segment list key
/// (`direct`/`interwork`) sits between the VRF name and the value and is
/// skipped here. The value is an IPv4 or IPv6 prefix; the ISD's AFI follows
/// its family.
pub fn config_vrf_mup_segment_prefix(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let _segment = args.string()?; // segment list key (direct|interwork)
    let cfg = vrf_entry(bgp, name, op)?;
    match op {
        ConfigOp::Set => {
            let raw = args.string()?;
            cfg.mobile_uplane.interwork_prefix = Some(IpNet::from_str(&raw).ok()?);
        }
        ConfigOp::Delete => cfg.mobile_uplane.interwork_prefix = None,
        _ => {}
    }
    Some(())
}

/// `set router bgp vrf <NAME> neighbor <addr>` — list-key handler.
pub fn config_vrf_neighbor(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let addr = args.addr()?;
    let cfg = vrf_entry(bgp, name, op)?;
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

/// Borrow a staged neighbor without allowing trailing Delete callbacks to
/// resurrect a list entry already removed by [`config_vrf_neighbor`]. Set
/// callbacks may still arrive before the list-key callback, so they retain
/// lazy creation.
fn neighbor_entry(
    cfg: &mut BgpVrfConfig,
    address: IpAddr,
    op: ConfigOp,
) -> Option<&mut BgpVrfNeighborConfig> {
    match op {
        ConfigOp::Set => Some(cfg.neighbors.entry(address).or_default()),
        ConfigOp::Delete => cfg.neighbors.get_mut(&address),
        _ => None,
    }
}

/// `set router bgp vrf <NAME> neighbor <addr> remote-as <ASN>`.
pub fn config_vrf_neighbor_remote_as(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let addr = args.addr()?;
    let cfg = vrf_entry(bgp, name, op)?;
    let nbr = neighbor_entry(cfg, addr, op)?;
    match op {
        ConfigOp::Set => nbr.remote_as = Some(args.u32()?),
        ConfigOp::Delete => nbr.remote_as = None,
        _ => {}
    }
    Some(())
}

/// `set router bgp vrf <NAME> neighbor <addr> neighbor-group <GROUP>`.
pub fn config_vrf_neighbor_neighbor_group(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let name = args.string()?;
    let addr = args.addr()?;
    let cfg = vrf_entry(bgp, name, op)?;
    let nbr = neighbor_entry(cfg, addr, op)?;
    match op {
        ConfigOp::Set => nbr.config.neighbor_group = Some(args.string()?),
        ConfigOp::Delete => nbr.config.neighbor_group = None,
        _ => {}
    }
    Some(())
}

/// `set router bgp vrf <NAME> neighbor <addr> description <STRING>`.
pub fn config_vrf_neighbor_description(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let addr = args.addr()?;
    let cfg = vrf_entry(bgp, name, op)?;
    let nbr = neighbor_entry(cfg, addr, op)?;
    match op {
        ConfigOp::Set => nbr.config.description = Some(args.string()?),
        ConfigOp::Delete => nbr.config.description = None,
        _ => {}
    }
    Some(())
}

/// `set router bgp vrf <NAME> neighbor <addr> timers connect-retry-time
/// <SECS>`.
///
/// The three `timers` callbacks stage onto
/// [`BgpVrfNeighborConfig::timer`], which `materialize_peers` copies
/// onto the peer at build time. Unlike the global neighbor's
/// equivalents (`timer::config::*`) they do **not** re-arm anything:
/// there is no live peer to reach from here — the CE peers live in the
/// per-VRF task — so a change lands when the VRF next respawns or the
/// session is cleared. That matches how every other per-VRF neighbor
/// knob (remote-as, afi-safi) already behaves.
pub fn config_vrf_neighbor_connect_retry_time(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let name = args.string()?;
    let addr = args.addr()?;
    let cfg = vrf_entry(bgp, name, op)?;
    let nbr = neighbor_entry(cfg, addr, op)?;
    match op {
        ConfigOp::Set => nbr.config.timer.connect_retry_time = Some(args.u16()?),
        ConfigOp::Delete => nbr.config.timer.connect_retry_time = None,
        _ => {}
    }
    Some(())
}

/// `set router bgp vrf <NAME> neighbor <addr> timers hold-time <SECS>`.
pub fn config_vrf_neighbor_hold_time(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let addr = args.addr()?;
    let cfg = vrf_entry(bgp, name, op)?;
    let nbr = neighbor_entry(cfg, addr, op)?;
    match op {
        ConfigOp::Set => nbr.config.timer.hold_time = Some(args.u16()?),
        ConfigOp::Delete => nbr.config.timer.hold_time = None,
        _ => {}
    }
    Some(())
}

/// `set router bgp vrf <NAME> neighbor <addr> timers idle-hold-time
/// <SECS>`.
pub fn config_vrf_neighbor_idle_hold_time(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let name = args.string()?;
    let addr = args.addr()?;
    let cfg = vrf_entry(bgp, name, op)?;
    let nbr = neighbor_entry(cfg, addr, op)?;
    match op {
        ConfigOp::Set => nbr.config.timer.idle_hold_time = Some(args.u16()?),
        ConfigOp::Delete => nbr.config.timer.idle_hold_time = None,
        _ => {}
    }
    Some(())
}

/// Generate a `… afi-safi <af> {policy,prefix-set} {in,out} <name>`
/// callback. Unlike the `vrf_afi_knob!` family these do not go through a
/// shared `afi_knob` setter: the value is not a `PeerConfig` field but a
/// name that has to be resolved by the policy actor, so it is staged in
/// [`BgpVrfNeighborConfig::policy_refs`] and bound (with a `Register`)
/// by `materialize_peers` once the peer has its ident.
macro_rules! vrf_policy_ref {
    ($(#[$m:meta])* $name:ident => $kind:expr) => {
        $(#[$m])*
        pub fn $name(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
            let vrf = args.string()?;
            let addr = args.addr()?;
            let afi_safi: AfiSafi = args.afi_safi()?;
            let cfg = vrf_entry(bgp, vrf, op)?;
            let nbr = neighbor_entry(cfg, addr, op)?;
            match op {
                ConfigOp::Set => {
                    let name = args.string()?;
                    nbr.policy_refs.insert((afi_safi, $kind), name);
                }
                ConfigOp::Delete => {
                    nbr.policy_refs.remove(&(afi_safi, $kind));
                }
                _ => {}
            }
            Some(())
        }
    };
}

vrf_policy_ref! {
    /// `… afi-safi <af> policy in <name>`.
    config_vrf_neighbor_afi_safi_policy_in => VrfPolicyRef::PolicyIn
}
vrf_policy_ref! {
    /// `… afi-safi <af> policy out <name>`.
    config_vrf_neighbor_afi_safi_policy_out => VrfPolicyRef::PolicyOut
}
vrf_policy_ref! {
    /// `… afi-safi <af> prefix-set in <name>`.
    config_vrf_neighbor_afi_safi_prefix_set_in => VrfPolicyRef::PrefixSetIn
}
vrf_policy_ref! {
    /// `… afi-safi <af> prefix-set out <name>`.
    config_vrf_neighbor_afi_safi_prefix_set_out => VrfPolicyRef::PrefixSetOut
}

/// Transport / session knobs, staged onto the neighbor's
/// `config.knobs_explicit`. `materialize_peers` resolves each through
/// neighbor-group precedence and applies it via the shared `apply_*`
/// function — the same one the global neighbor's callback calls — so the
/// two paths cannot disagree on a knob's meaning. Unlike the global
/// callback these do not touch a live peer; a change lands on the next
/// VRF respawn.
pub fn config_vrf_neighbor_passive(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let vrf = args.string()?;
    let addr = args.addr()?;
    let cfg = vrf_entry(bgp, vrf, op)?;
    let nbr = neighbor_entry(cfg, addr, op)?;
    nbr.config.knobs_explicit.passive = match op {
        ConfigOp::Set => Some(args.boolean()?),
        ConfigOp::Delete => None,
        _ => return Some(()),
    };
    Some(())
}

pub fn config_vrf_neighbor_update_source(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let vrf = args.string()?;
    let addr = args.addr()?;
    let cfg = vrf_entry(bgp, vrf, op)?;
    let nbr = neighbor_entry(cfg, addr, op)?;
    nbr.config.knobs_explicit.update_source = match op {
        ConfigOp::Set => Some(args.addr()?),
        ConfigOp::Delete => None,
        _ => return Some(()),
    };
    Some(())
}

pub fn config_vrf_neighbor_ebgp_multihop(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let vrf = args.string()?;
    let addr = args.addr()?;
    let cfg = vrf_entry(bgp, vrf, op)?;
    let nbr = neighbor_entry(cfg, addr, op)?;
    nbr.config.knobs_explicit.ebgp_multihop = match op {
        ConfigOp::Set => Some(args.u8()?),
        ConfigOp::Delete => None,
        _ => return Some(()),
    };
    Some(())
}

pub fn config_vrf_neighbor_ttl_security(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let vrf = args.string()?;
    let addr = args.addr()?;
    let cfg = vrf_entry(bgp, vrf, op)?;
    let nbr = neighbor_entry(cfg, addr, op)?;
    // Presence container: Set means enabled, Delete means forget the
    // statement (fall back to the group / off).
    nbr.config.knobs_explicit.ttl_security = op.is_set().then_some(true);
    Some(())
}

pub fn config_vrf_neighbor_port(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let vrf = args.string()?;
    let addr = args.addr()?;
    let cfg = vrf_entry(bgp, vrf, op)?;
    let nbr = neighbor_entry(cfg, addr, op)?;
    nbr.config.knobs_explicit.port = match op {
        ConfigOp::Set => Some(args.u16()?),
        ConfigOp::Delete => None,
        _ => return Some(()),
    };
    Some(())
}

pub fn config_vrf_neighbor_ip_transparent(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let vrf = args.string()?;
    let addr = args.addr()?;
    let cfg = vrf_entry(bgp, vrf, op)?;
    let nbr = neighbor_entry(cfg, addr, op)?;
    nbr.config.knobs_explicit.ip_transparent = op.is_set().then_some(true);
    Some(())
}

pub fn config_vrf_neighbor_disable_connected_check(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let vrf = args.string()?;
    let addr = args.addr()?;
    let cfg = vrf_entry(bgp, vrf, op)?;
    let nbr = neighbor_entry(cfg, addr, op)?;
    nbr.config.knobs_explicit.disable_connected_check = op.is_set().then_some(true);
    Some(())
}

/// `set router bgp vrf <NAME> neighbor <addr> afi-safi {ipv4|ipv6} enabled
/// <BOOL>` — per-family activation for a CE peer, mirroring the global
/// neighbor's `config_afi_safi`. Records the verbatim statement into the
/// staged [`BgpVrfNeighborConfig::mp_explicit`]; `materialize_peers`
/// resolves the effective family set (address-derived default layered
/// with these overrides) when it builds the peer. The capability set is
/// fixed at OPEN time, so a change only takes effect when the CE session
/// next renegotiates (`clear bgp`).
pub fn config_vrf_neighbor_afi_safi_enabled(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let name = args.string()?;
    let addr = args.addr()?;
    let afi_safi: AfiSafi = args.afi_safi()?;
    let cfg = vrf_entry(bgp, name, op)?;
    let nbr = neighbor_entry(cfg, addr, op)?;
    match op {
        ConfigOp::Set => {
            let enabled = args.boolean()?;
            nbr.config.mp_explicit.insert(afi_safi, enabled);
        }
        ConfigOp::Delete => {
            nbr.config.mp_explicit.remove(&afi_safi);
        }
        _ => {}
    }
    Some(())
}

/// Generate a `router bgp vrf <NAME> neighbor <addr> afi-safi <af>
/// <knob>` callback that stages through one of the shared
/// [`super::afi_knob`] setters.
///
/// Every one of these is the same four lines — resolve the VRF, resolve
/// the neighbor, hand the staged `PeerConfig` to the setter — which is
/// the whole point of staging a real `PeerConfig`: importing a knob from
/// the global neighbor is a YANG leaf plus one line here, with the
/// knob's *meaning* defined once in `afi_knob` and shared with the
/// global callback.
macro_rules! vrf_afi_knob {
    ($(#[$m:meta])* $name:ident => $setter:ident) => {
        $(#[$m])*
        pub fn $name(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
            let vrf = args.string()?;
            let addr = args.addr()?;
            let afi_safi: AfiSafi = args.afi_safi()?;
            let cfg = vrf_entry(bgp, vrf, op)?;
            let nbr = neighbor_entry(cfg, addr, op)?;
            super::afi_knob::$setter(&mut nbr.config, afi_safi, op, &mut args)
        }
    };
}

vrf_afi_knob! {
    /// `… afi-safi <af> add-path <send|receive|send-receive>` (RFC 7911).
    config_vrf_neighbor_afi_safi_add_path => set_add_path
}
vrf_afi_knob! {
    /// `… afi-safi <af> graceful-restart enabled <bool>` (RFC 4724).
    config_vrf_neighbor_afi_safi_graceful_restart => set_graceful_restart
}
vrf_afi_knob! {
    /// `… afi-safi <af> long-lived-graceful-restart restart-time <secs>`.
    config_vrf_neighbor_afi_safi_llgr_restart_time => set_llgr_restart_time
}
vrf_afi_knob! {
    /// `… afi-safi <af> next-hop-unchanged <bool>`.
    config_vrf_neighbor_afi_safi_next_hop_unchanged => set_next_hop_unchanged
}
vrf_afi_knob! {
    /// `… afi-safi <af> encapsulation-type <srv6|srv6-relax>`.
    config_vrf_neighbor_afi_safi_encapsulation_type => set_encapsulation_type
}
vrf_afi_knob! {
    /// `… afi-safi <af> next-hop-self <bool>`.
    ///
    /// Records the verbatim statement only. The effective value is
    /// resolved through neighbor-group precedence by `materialize_peers`,
    /// which already holds the group map — the global neighbor does the
    /// same resolution in its own callback against `Bgp::neighbor_groups`.
    config_vrf_neighbor_afi_safi_next_hop_self => set_next_hop_self_explicit
}

/// `… afi-safi <af> long-lived-graceful-restart enabled` — the odd one
/// out: [`super::afi_knob::set_llgr`] keys off presence alone and takes
/// no value, so it doesn't fit the macro's `args`-consuming shape.
pub fn config_vrf_neighbor_afi_safi_llgr(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let vrf = args.string()?;
    let addr = args.addr()?;
    let afi_safi: AfiSafi = args.afi_safi()?;
    let cfg = vrf_entry(bgp, vrf, op)?;
    let nbr = neighbor_entry(cfg, addr, op)?;
    super::afi_knob::set_llgr(&mut nbr.config, afi_safi, op)
}

/// `set router bgp vrf <NAME> afi-safi ipv4` — presence container.
pub fn config_vrf_afi_ipv4(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    match op {
        ConfigOp::Set => {
            vrf_entry(bgp, name, op)?
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
            if let Some(cfg) = vrf_entry(bgp, name, op) {
                cfg.ipv4_unicast = None;
            }
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
        let af = vrf_entry(bgp, name.clone(), op)?
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
            vrf_entry(bgp, name, op)?
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
            if let Some(cfg) = vrf_entry(bgp, name, op) {
                cfg.ipv6_unicast = None;
            }
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
        let af = vrf_entry(bgp, name.clone(), op)?
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

/// Enable/disable one redistribute source for a VRF/AFI in the staged
/// config, and drive the change onto the running VRF task. Shared by
/// the four `redistribute {connected,static}` callbacks. Mirrors the
/// `network` callbacks: `compute_vrf_diff` only re-spawns on the VRF
/// *name* set, so a redistribute-only change reaches a live task through
/// a [`BgpVrfMsg`]; an initial-config VRF picks it up at spawn-time
/// materialization, which reads the same `redistribute` set.
fn vrf_redist_set(
    bgp: &mut Bgp,
    name: String,
    afi: RedistAfi,
    source: BgpRedistSource,
    op: ConfigOp,
) -> Option<()> {
    let set = match op {
        ConfigOp::Set => true,
        ConfigOp::Delete => false,
        _ => return Some(()),
    };
    {
        let Some(cfg) = vrf_entry(bgp, name.clone(), op) else {
            return Some(());
        };
        let redist = match afi {
            RedistAfi::Ipv4 => {
                &mut cfg
                    .ipv4_unicast
                    .get_or_insert_with(Default::default)
                    .redistribute
            }
            RedistAfi::Ipv6 => {
                &mut cfg
                    .ipv6_unicast
                    .get_or_insert_with(Default::default)
                    .redistribute
            }
        };
        if set {
            redist.insert(source);
        } else {
            redist.remove(&source);
        }
    }
    if let Some(handle) = bgp.vrf_registry.get(&name) {
        let msg = if set {
            BgpVrfMsg::RedistEnable { afi, source }
        } else {
            BgpVrfMsg::RedistDisable { afi, source }
        };
        let _ = handle.inbox.send(msg);
    }
    Some(())
}

/// Clear every redistribute source for a VRF/AFI and withdraw them
/// from the running task. Driven by the `redistribute` container
/// delete, whose child source-deletes the diff does not re-emit (same
/// rationale as `config_vrf_afi_ipv4`'s network sweep).
fn vrf_redist_clear(bgp: &mut Bgp, name: String, afi: RedistAfi) {
    let sources: Vec<BgpRedistSource> = {
        // Delete-only path: never create the entry (see `vrf_entry`).
        let Some(cfg) = bgp.vrfs.get_mut(&name) else {
            return;
        };
        let redist = match afi {
            RedistAfi::Ipv4 => cfg.ipv4_unicast.as_mut().map(|af| &mut af.redistribute),
            RedistAfi::Ipv6 => cfg.ipv6_unicast.as_mut().map(|af| &mut af.redistribute),
        };
        match redist {
            Some(set) => {
                let drained: Vec<_> = set.iter().copied().collect();
                set.clear();
                drained
            }
            None => Vec::new(),
        }
    };
    if let Some(handle) = bgp.vrf_registry.get(&name) {
        for source in sources {
            let _ = handle.inbox.send(BgpVrfMsg::RedistDisable { afi, source });
        }
    }
}

/// `delete router bgp vrf <NAME> afi-safi ipv4 redistribute` — clear
/// all IPv4 redistribute sources. The set callback for the bare
/// container is a no-op (sources are enabled by their own leaves).
pub fn config_vrf_afi_ipv4_redistribute(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    if matches!(op, ConfigOp::Delete) {
        vrf_redist_clear(bgp, name, RedistAfi::Ipv4);
    }
    Some(())
}

/// `set router bgp vrf <NAME> afi-safi ipv4 redistribute connected`.
pub fn config_vrf_afi_ipv4_redistribute_connected(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let name = args.string()?;
    vrf_redist_set(bgp, name, RedistAfi::Ipv4, BgpRedistSource::Connected, op)
}

/// `set router bgp vrf <NAME> afi-safi ipv4 redistribute static`.
pub fn config_vrf_afi_ipv4_redistribute_static(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let name = args.string()?;
    vrf_redist_set(bgp, name, RedistAfi::Ipv4, BgpRedistSource::Static, op)
}

/// `set router bgp vrf <NAME> afi-safi ipv4 redistribute ospf`.
pub fn config_vrf_afi_ipv4_redistribute_ospf(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let name = args.string()?;
    vrf_redist_set(bgp, name, RedistAfi::Ipv4, BgpRedistSource::Ospf, op)
}

/// `set router bgp vrf <NAME> afi-safi ipv4 redistribute isis`.
pub fn config_vrf_afi_ipv4_redistribute_isis(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let name = args.string()?;
    vrf_redist_set(bgp, name, RedistAfi::Ipv4, BgpRedistSource::Isis, op)
}

/// `delete router bgp vrf <NAME> afi-safi ipv6 redistribute`.
pub fn config_vrf_afi_ipv6_redistribute(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    if matches!(op, ConfigOp::Delete) {
        vrf_redist_clear(bgp, name, RedistAfi::Ipv6);
    }
    Some(())
}

/// `set router bgp vrf <NAME> afi-safi ipv6 redistribute connected`.
pub fn config_vrf_afi_ipv6_redistribute_connected(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let name = args.string()?;
    vrf_redist_set(bgp, name, RedistAfi::Ipv6, BgpRedistSource::Connected, op)
}

/// `set router bgp vrf <NAME> afi-safi ipv6 redistribute static`.
pub fn config_vrf_afi_ipv6_redistribute_static(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let name = args.string()?;
    vrf_redist_set(bgp, name, RedistAfi::Ipv6, BgpRedistSource::Static, op)
}

/// `set router bgp vrf <NAME> afi-safi ipv6 redistribute ospf`.
pub fn config_vrf_afi_ipv6_redistribute_ospf(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let name = args.string()?;
    vrf_redist_set(bgp, name, RedistAfi::Ipv6, BgpRedistSource::Ospf, op)
}

/// `set router bgp vrf <NAME> afi-safi ipv6 redistribute isis`.
pub fn config_vrf_afi_ipv6_redistribute_isis(
    bgp: &mut Bgp,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let name = args.string()?;
    vrf_redist_set(bgp, name, RedistAfi::Ipv6, BgpRedistSource::Isis, op)
}

/// `set router bgp vrf <NAME> evpn advertise-ipv4 <bool>`.
pub fn config_vrf_evpn_advertise_ipv4(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let cfg = vrf_entry(bgp, name, op)?;
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
    let cfg = vrf_entry(bgp, name, op)?;
    match op {
        ConfigOp::Set => cfg.evpn_advertise_v6 = args.boolean()?,
        ConfigOp::Delete => cfg.evpn_advertise_v6 = false,
        _ => {}
    }
    Some(())
}

/// `set router bgp vrf <NAME> evpn l3vni <VNI>`.
pub fn config_vrf_evpn_l3vni(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let cfg = vrf_entry(bgp, name, op)?;
    match op {
        ConfigOp::Set => cfg.l3vni = Some(args.u32()?),
        ConfigOp::Delete => cfg.l3vni = None,
        _ => {}
    }
    Some(())
}

/// `set router bgp vrf <NAME> evpn router-mac <MAC>` (symmetric IRB).
pub fn config_vrf_evpn_router_mac(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let cfg = vrf_entry(bgp, name, op)?;
    match op {
        ConfigOp::Set => {
            let mac: crate::rib::MacAddr = args.string()?.parse().ok()?;
            cfg.router_mac = Some(mac.octets());
        }
        ConfigOp::Delete => cfg.router_mac = None,
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
        assert!(mup.routes.is_empty());
    }

    #[test]
    fn mobile_uplane_binds_both_directions() {
        // One VRF may bind both st1 and st2 (single-N6 UPF, issue #1947):
        // each direction is an independent map entry, and removing one
        // leaves the other intact.
        let mut cfg = BgpVrfConfig::default();
        cfg.mobile_uplane.routes.insert(
            MupSrv6Direction::Decapsulation,
            MupRouteBinding {
                network_instance: Some("internet".to_string()),
                mup_ext_comm: Some("1:2".parse().unwrap()),
            },
        );
        cfg.mobile_uplane.routes.insert(
            MupSrv6Direction::Encapsulation,
            MupRouteBinding {
                network_instance: Some("internet".to_string()),
                mup_ext_comm: None,
            },
        );
        assert_eq!(cfg.mobile_uplane.routes.len(), 2);
        let st2 = &cfg.mobile_uplane.routes[&MupSrv6Direction::Decapsulation];
        assert_eq!(st2.network_instance.as_deref(), Some("internet"));
        assert_eq!(st2.mup_ext_comm, Some("1:2".parse().unwrap()));

        cfg.mobile_uplane
            .routes
            .remove(&MupSrv6Direction::Decapsulation);
        assert!(
            cfg.mobile_uplane
                .routes
                .contains_key(&MupSrv6Direction::Encapsulation),
            "removing st2 leaves the st1 binding intact"
        );
    }

    #[test]
    fn neighbor_default_is_empty() {
        // A `set ... neighbor X` with no further leaves stages an empty
        // neighbor: no remote-as / peer-group / description and no
        // explicit afi-safi activation. The peer only materializes once
        // a remote-as (own or group-inherited) is known.
        let nbr = BgpVrfNeighborConfig::default();
        assert!(nbr.remote_as.is_none());
        assert!(nbr.peer_group().is_none());
        assert!(nbr.config.description.is_none());
        assert!(nbr.config.mp_explicit.is_empty());
        // Every timer leaf unset — `materialize_peers` copies this
        // wholesale onto the peer, so an all-`None` default is what keeps
        // a `timers`-less VRF neighbor on the stock cadence.
        assert!(nbr.config.timer.connect_retry_time.is_none());
        assert!(nbr.config.timer.hold_time.is_none());
        assert!(nbr.config.timer.idle_hold_time.is_none());
    }

    #[test]
    fn neighbor_timers_stage_and_clear_independently() {
        let address: IpAddr = "192.0.2.1".parse().unwrap();
        let mut cfg = BgpVrfConfig::default();

        let nbr = neighbor_entry(&mut cfg, address, ConfigOp::Set).unwrap();
        nbr.config.timer.connect_retry_time = Some(3);
        nbr.config.timer.hold_time = Some(9);
        nbr.config.timer.idle_hold_time = Some(1);

        let nbr = &cfg.neighbors[&address];
        assert_eq!(nbr.config.timer.connect_retry_time, Some(3));
        assert_eq!(nbr.config.timer.hold_time, Some(9));
        assert_eq!(nbr.config.timer.idle_hold_time, Some(1));

        // Clearing one leaf must leave the siblings alone: the three
        // callbacks share one staged `timer::Config`, so a careless
        // implementation could reset the struct instead of the field.
        cfg.neighbors
            .get_mut(&address)
            .unwrap()
            .config
            .timer
            .hold_time = None;
        let nbr = &cfg.neighbors[&address];
        assert!(nbr.config.timer.hold_time.is_none());
        assert_eq!(nbr.config.timer.connect_retry_time, Some(3));
        assert_eq!(nbr.config.timer.idle_hold_time, Some(1));
    }

    #[test]
    fn neighbor_timers_leave_the_inert_leaves_unset() {
        // The schema deliberately omits advertisement-interval /
        // originate-interval / delay-open-time: they are staged onto
        // `PeerConfig::timer` and never read by any arming path, even for
        // a global neighbor. Sharing `timer::Config` with the peer means
        // they exist as fields, so pin that they stay `None` — if one is
        // ever wired up, this test should fail and prompt exposing it
        // here too.
        let address: IpAddr = "192.0.2.1".parse().unwrap();
        let mut cfg = BgpVrfConfig::default();
        let nbr = neighbor_entry(&mut cfg, address, ConfigOp::Set).unwrap();
        nbr.config.timer.connect_retry_time = Some(3);

        assert!(nbr.config.timer.min_adv_interval.is_none());
        assert!(nbr.config.timer.orig_interval.is_none());
        assert!(nbr.config.timer.delay_open_time.is_none());
    }

    #[test]
    fn neighbor_child_deletes_do_not_recreate_a_removed_neighbor() {
        let address: IpAddr = "192.0.2.1".parse().unwrap();
        let mut cfg = BgpVrfConfig::default();
        cfg.neighbors.entry(address).or_default().remote_as = Some(65001);

        // The list callback runs first when the whole neighbor is deleted.
        // Trailing child callbacks must traverse existing state only.
        cfg.neighbors.remove(&address);
        for _ in 0..4 {
            assert!(neighbor_entry(&mut cfg, address, ConfigOp::Delete).is_none());
        }
        assert!(cfg.neighbors.is_empty());
    }

    #[test]
    fn neighbor_child_set_can_create_before_the_list_key_callback() {
        let address: IpAddr = "192.0.2.1".parse().unwrap();
        let mut cfg = BgpVrfConfig::default();

        neighbor_entry(&mut cfg, address, ConfigOp::Set)
            .unwrap()
            .remote_as = Some(65001);

        assert_eq!(cfg.neighbors[&address].remote_as, Some(65001));
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
