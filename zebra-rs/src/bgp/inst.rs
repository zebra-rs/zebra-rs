use super::peer::{BgpTop, Event, PeerBfdConfig, fsm};
use super::peer_map::PeerMap;
use super::route::LocalRib;
use super::shard::BgpShard;
use super::{BGP_PORT, BgpAttrStore};
use crate::bgp::peer::accept;
use crate::bgp::tracing::{Direction, PacketKind};
use crate::bgp::{InOut, peer};
use crate::config::{
    Args, ConfigChannel, ConfigOp, ConfigRequest, DisplayRequest, ShowChannel, path_from_command,
};
use crate::context::{ProtoContext, Task};
use crate::policy::com_list::CommunityListMap;
use crate::policy::{self, PolicyRxChannel};
use crate::rib::MacAddr;
use crate::rib::api::{FdbEntry, RibRx};
use crate::{
    bgp_bfd_trace, bgp_fsm_trace, bgp_label_trace, bgp_packet_trace, bgp_srv6_trace, bgp_vpn_trace,
    bgp_vrf_trace,
};
use std::collections::{BTreeMap, HashMap};
use std::net::{Ipv4Addr, SocketAddr};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

/// Size of the dynamic MPLS label block BGP requests from the RIB
/// label manager at startup, for per-VRF L3VPN labels. One label per
/// VRF, so 1024 covers any realistic deployment; on-demand extension
/// for larger fleets is a follow-up.
const VRF_LABEL_BLOCK_SIZE: u32 = 1024;

/// Map a `/clear/bgp[/<afi>]/neighbor[/soft[/in|out]]` path (from
/// zebra-bgp-clear.yang) to the (AFI/SAFI filter, op) pair the BGP
/// runtime understands. The AFI segment is optional — the AFI-less
/// `clear bgp <peer-or-all>` form returns `None` for the filter,
/// meaning every AFI/SAFI. Returns None for unrecognised paths.
fn parse_clear_bgp_path(
    path: &str,
) -> Option<(
    Option<(bgp_packet::Afi, bgp_packet::Safi)>,
    peer::BgpClearOp,
)> {
    use bgp_packet::{Afi, Safi};
    use peer::BgpClearOp;

    let rest = path.strip_prefix("/clear/bgp/")?;
    let (afi_safi, tail) = if rest == "neighbor" || rest.starts_with("neighbor/") {
        (None, rest)
    } else {
        let (afi_str, tail) = rest.split_once('/')?;
        let pair = match afi_str {
            "ipv4" => (Afi::Ip, Safi::Unicast),
            "ipv6" => (Afi::Ip6, Safi::Unicast),
            "vpnv4" => (Afi::Ip, Safi::MplsVpn),
            "evpn" => (Afi::L2vpn, Safi::Evpn),
            _ => return None,
        };
        (Some(pair), tail)
    };
    let op = match tail {
        "neighbor" => BgpClearOp::Hard,
        "neighbor/soft" => BgpClearOp::SoftBoth,
        "neighbor/soft/in" => BgpClearOp::SoftIn,
        "neighbor/soft/out" => BgpClearOp::SoftOut,
        _ => return None,
    };
    Some((afi_safi, op))
}

/// Tier 1b sync backpressure: park the IPv4 sync cursor once this many
/// UPDATE messages are queued (not yet written) toward a peer, so a slow
/// socket can't let a large session-up dump outrun it and grow memory
/// unboundedly. At ~max-packet UPDATEs this caps in-flight bytes at a
/// few hundred KB. Re-polled every `SYNC_PARK_MS` while parked.
/// Overridable via `ZEBRA_BGP_SYNC_EGRESS_HIGH` (default 64).
fn sync_egress_high_water() -> usize {
    use std::sync::OnceLock;
    static W: OnceLock<usize> = OnceLock::new();
    *W.get_or_init(|| {
        std::env::var("ZEBRA_BGP_SYNC_EGRESS_HIGH")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(64)
    })
}
const SYNC_PARK_MS: u64 = 20;

#[derive(Debug)]
pub enum Message {
    Event(usize, Event),
    Accept(TcpStream, SocketAddr),
    /// Adv-debounce timer expired for an IPv4-unicast update-group:
    /// drain the group's pending cache, encode one UPDATE per attr
    /// bucket, and ship to each member with split-horizon pruning.
    FlushUpdateGroupIpv4(super::update_group::UpdateGroupId),
    FlushUpdateGroupIpv6(super::update_group::UpdateGroupId),
    /// A blocking-pool worker finished an update-group flush
    /// (sharding plan Phase A.2): merge the counter deltas, release
    /// the group's in-flight latch, replay withdraws parked during
    /// the flight, and re-run the flush if the debounce timer fired
    /// while the job was out.
    FlushDoneIpv4(
        super::update_group::UpdateGroupId,
        super::update_group::UpdateGroupCounters,
    ),
    FlushDoneIpv6(
        super::update_group::UpdateGroupId,
        super::update_group::UpdateGroupCounters,
    ),
    /// BGP Link-State (RFC 9552) objects produced by the local IS-IS task
    /// and pushed over the IS-IS→BGP channel. `add` are originated into the
    /// `bgp_ls` Loc-RIB; `withdraw` are removed. The IS-IS producer diffs
    /// against its own last-advertised set and sends only deltas, so this
    /// carries exactly the change for one trigger.
    BgpLs {
        add: Vec<(bgp_packet::BgpLsNlri, bgp_packet::BgpLsAttr)>,
        withdraw: Vec<bgp_packet::BgpLsNlri>,
    },
    /// `router bgp port <0-65535>` changed: close the BGP listen
    /// sockets and reopen them on the (new) configured port — or leave
    /// them closed when the port is 0. Sent by the config callback
    /// because the rebind is async (`Bgp::listen`) while callbacks are
    /// sync; handled directly in [`Bgp::event_loop`], which awaits
    /// [`Bgp::relisten`].
    Relisten,
}

pub type Callback = fn(&mut Bgp, Args, ConfigOp) -> Option<()>;
pub type PCallback = fn(&mut CommunityListMap, Args, ConfigOp) -> Option<()>;
pub type ShowCallback = fn(&Bgp, Args, bool) -> std::result::Result<String, std::fmt::Error>;

/// Insert (or refresh) the `peer_index` row claiming `addr` for
/// `vrf`. Warns and overrides when a different VRF already owned
/// the address — matches FRR behaviour for the same conflict.
pub(crate) fn peer_index_register(
    index: &mut BTreeMap<std::net::IpAddr, String>,
    vrf: String,
    addr: std::net::IpAddr,
) {
    if let Some(prev) = index.insert(addr, vrf.clone())
        && prev != vrf
    {
        tracing::warn!(
            peer = %addr,
            old_vrf = %prev,
            new_vrf = %vrf,
            "bgp: peer address claimed by multiple VRFs; most recent wins",
        );
    }
}

/// Append `export_rts` to `attr.ecom` as Route-Target extended
/// communities (RFC 4360 §4.1 — subtype `0x02`). RTs share the
/// 6-octet on-wire encoding with RDs; the `From<RouteDistinguisher>`
/// impl picks the right high_type (Two-Octet-AS vs IPv4) but
/// leaves `low_type = 0`, so this helper sets it to `0x02` to mark
/// each entry as RT. Returns `attr` unchanged when the export-RT
/// set is empty.
pub(crate) fn tag_attr_with_export_rts(
    mut attr: bgp_packet::BgpAttr,
    export_rts: &std::collections::BTreeSet<bgp_packet::RouteDistinguisher>,
) -> bgp_packet::BgpAttr {
    use bgp_packet::ExtCommunityValue;

    if export_rts.is_empty() {
        return attr;
    }
    let mut ecom = attr.ecom.take().unwrap_or_default();
    for rt in export_rts {
        let mut val: ExtCommunityValue = (*rt).into();
        // RFC 4360 §4 — Route Target sub-type. The `From<RD>` impl
        // sets `high_type` per ASN-vs-IPv4 RD but leaves the
        // sub-type at the default 0; flipping it here is what
        // distinguishes RT from Route-Origin (sub-type 0x03).
        val.low_type = 0x02;
        ecom.0.insert(val);
    }
    attr.ecom = Some(ecom);
    attr
}

/// Build a BGP Prefix-SID attribute carrying one SRv6 L3 Service TLV
/// (RFC 9252 §2) for a per-VRF End.DT46 service `sid`. The full SID is
/// in the TLV (transposition length 0 — no label transposition), with
/// an optional SID Structure sub-sub-TLV derived from the locator when
/// known. This is the attribute an `encapsulation srv6` VRF attaches to
/// every VPNv4 / VPNv6 route it originates.
/// Precomputed advertise-time SRv6 data for the global IPv6 unicast
/// table, derived from the resolved locator + the allocated End.DT6 SID.
/// Held on [`Bgp`] and borrowed into [`super::peer::BgpTop`] so the
/// egress path (`route_update_ipv6`) can stamp locally-originated routes
/// with the Prefix-SID + locator next-hop without re-deriving it per
/// route. `None` whenever `segment-routing srv6 ipv6-unicast` is off or
/// the locator is unresolved.
#[derive(Debug, Clone)]
pub struct Srv6Ipv6Export {
    /// BGP Prefix-SID attribute (SRv6 L3 Service TLV, End.DT6 SID).
    pub prefix_sid: bgp_packet::PrefixSid,
    /// PE locator next-hop advertised alongside the SID (the remote PE
    /// H.Encaps to this address, then the local End.DT6 decaps into the
    /// main table).
    pub nexthop: std::net::Ipv6Addr,
}

fn srv6_l3_service_prefix_sid(
    sid: std::net::Ipv6Addr,
    structure: Option<crate::rib::SidStructure>,
    behavior: u16,
) -> bgp_packet::PrefixSid {
    let structure = structure.map(|s| bgp_packet::Srv6SidStructure {
        locator_block_len: s.lb_bits,
        locator_node_len: s.ln_bits,
        function_len: s.fun_bits,
        argument_len: s.arg_bits,
        transposition_len: 0,
        transposition_offset: 0,
    });
    bgp_packet::PrefixSid {
        tlvs: vec![bgp_packet::PrefixSidTlv::Srv6L3Service(
            bgp_packet::Srv6ServiceTlv {
                sids: vec![bgp_packet::Srv6SidInfo::new(sid, 0, behavior, structure)],
                ..Default::default()
            },
        )],
    }
}

/// Walk `vrf_index` and return every VRF name whose
/// `import_rts_v4` intersects the route's Route-Target extended
/// communities in `ecom`. RTs on the wire are distinguished from
/// other extended communities by the (`high_type`, `low_type`)
/// pair — RFC 4360 §4.1 puts the sub-type at `low_type = 0x02`.
/// Routes with no RT extcomms match no VRF; routes with RTs that
/// no configured VRF imports match no VRF either (and the global
/// VPNv4 row sits in `shard.v4vpn` unimported).
pub(crate) fn matching_import_vrfs(
    vrf_index: &BTreeMap<String, RibKnownVrf>,
    ecom: &Option<bgp_packet::ExtCommunity>,
) -> Vec<String> {
    let route_rts = route_rts_from_ecom(ecom);
    if route_rts.is_empty() {
        return Vec::new();
    }
    vrf_index
        .iter()
        .filter(|(_, info)| !info.import_rts_v4.is_disjoint(&route_rts))
        .map(|(name, _)| name.clone())
        .collect()
}

/// VPNv6 counterpart of [`matching_import_vrfs`] — intersects against
/// each VRF's `import_rts_v6` instead of `import_rts_v4`.
pub(crate) fn matching_import_vrfs_v6(
    vrf_index: &BTreeMap<String, RibKnownVrf>,
    ecom: &Option<bgp_packet::ExtCommunity>,
) -> Vec<String> {
    let route_rts = route_rts_from_ecom(ecom);
    if route_rts.is_empty() {
        return Vec::new();
    }
    vrf_index
        .iter()
        .filter(|(_, info)| !info.import_rts_v6.is_disjoint(&route_rts))
        .map(|(name, _)| name.clone())
        .collect()
}

/// Extract the route-target set a route carries: every extended
/// community with RT sub-type (`low_type == 0x02`), reinterpreted as a
/// `RouteDistinguisher` (RT and RD share the on-wire 6-octet shape).
fn route_rts_from_ecom(
    ecom: &Option<bgp_packet::ExtCommunity>,
) -> std::collections::BTreeSet<bgp_packet::RouteDistinguisher> {
    let Some(ecom) = ecom else {
        return std::collections::BTreeSet::new();
    };
    ecom.0
        .iter()
        .filter(|v| v.low_type == 0x02)
        .map(|v| {
            use bgp_packet::RouteDistinguisherType;
            // high_type 0x00 = Two-Octet AS, 0x01 = IPv4. Anything
            // else (0x02 = 4-byte AS, future types) maps onto ASN
            // by default — `RouteDistinguisher::PartialEq` is per-
            // byte so a 4-byte ASN extcomm just won't intersect
            // any configured RT (the config builder rejects 4-byte
            // ASN strings today).
            let typ = if v.high_type == 0x01 {
                RouteDistinguisherType::IP
            } else {
                RouteDistinguisherType::ASN
            };
            let mut rd = bgp_packet::RouteDistinguisher::new(typ);
            rd.val = v.val;
            rd
        })
        .collect()
}

/// Compute the fan-out target VRFs for a VPNv4 route: every VRF
/// [`matching_import_vrfs`] returns, minus `skip_vrf`. The skip
/// excludes the VRF a locally-exported route originated from, so a
/// VRF whose import-RT set overlaps its own export-RTs (e.g.
/// `rt both 1:1`) doesn't re-import the route it just exported.
/// `None` on the remote-VPNv4 ingress path (no originating local
/// VRF).
pub(crate) fn import_targets(
    vrf_index: &BTreeMap<String, RibKnownVrf>,
    ecom: &Option<bgp_packet::ExtCommunity>,
    skip_vrf: Option<&str>,
) -> Vec<String> {
    matching_import_vrfs(vrf_index, ecom)
        .into_iter()
        .filter(|name| Some(name.as_str()) != skip_vrf)
        .collect()
}

/// VPNv6 counterpart of [`import_targets`].
pub(crate) fn import_targets_v6(
    vrf_index: &BTreeMap<String, RibKnownVrf>,
    ecom: &Option<bgp_packet::ExtCommunity>,
    skip_vrf: Option<&str>,
) -> Vec<String> {
    matching_import_vrfs_v6(vrf_index, ecom)
        .into_iter()
        .filter(|name| Some(name.as_str()) != skip_vrf)
        .collect()
}

/// Inter-AS Option AB: does the route's RT fall in the import set of any
/// `inter-as-hybrid` VRF? Such a received route is propagated only by
/// that VRF's re-export (an `Originated` row with next-hop-self), so the
/// receive path marks it [`super::route::BgpRib::vrf_transit_only`] and
/// the advertise path suppresses the transparent relay — otherwise the
/// same prefix would reach a peer under several RDs and thrash the
/// prefix-keyed VRF import.
pub(crate) fn rt_imported_by_hybrid_vrf_v4(
    vrf_index: &BTreeMap<String, RibKnownVrf>,
    ecom: &Option<bgp_packet::ExtCommunity>,
) -> bool {
    let route_rts = route_rts_from_ecom(ecom);
    !route_rts.is_empty()
        && vrf_index
            .values()
            .any(|info| info.inter_as_hybrid && !info.import_rts_v4.is_disjoint(&route_rts))
}

/// VPNv6 counterpart of [`rt_imported_by_hybrid_vrf_v4`].
pub(crate) fn rt_imported_by_hybrid_vrf_v6(
    vrf_index: &BTreeMap<String, RibKnownVrf>,
    ecom: &Option<bgp_packet::ExtCommunity>,
) -> bool {
    let route_rts = route_rts_from_ecom(ecom);
    !route_rts.is_empty()
        && vrf_index
            .values()
            .any(|info| info.inter_as_hybrid && !info.import_rts_v6.is_disjoint(&route_rts))
}

/// Kernel VRF master info as observed by `Bgp` via
/// `RibRx::VrfAdd` and the matching RT sets observed via
/// `RibRx::VrfRouteTargets`. Used by
/// [`Bgp::maybe_respawn_vrf_with_kernel_ctx`] to lift a placeholder
/// `ProtoContext` to a real
/// `ProtoContext::for_vrf(rib, table_id, name)`; the Export
/// pipeline reads `export_rts_v4`/`v6` and the Import pipeline
/// reads `import_rts_v4`/`v6`.
#[derive(Debug, Clone, Default)]
pub struct RibKnownVrf {
    pub table_id: u32,
    pub ifindex: u32,
    pub import_rts_v4: std::collections::BTreeSet<bgp_packet::RouteDistinguisher>,
    pub export_rts_v4: std::collections::BTreeSet<bgp_packet::RouteDistinguisher>,
    pub import_rts_v6: std::collections::BTreeSet<bgp_packet::RouteDistinguisher>,
    pub export_rts_v6: std::collections::BTreeSet<bgp_packet::RouteDistinguisher>,
    /// Inter-AS Option AB: copied from the VRF's BGP config
    /// (`inter_as_hybrid`). Lets the shared VPNv4/VPNv6 receive path
    /// (which only borrows `rib_known_vrfs`, not the config map) tell
    /// whether a route's RT is imported by a hybrid VRF — and therefore
    /// must be propagated only via that VRF's re-export, not transparently
    /// relayed. See [`super::route::BgpRib::vrf_transit_only`].
    pub inter_as_hybrid: bool,
}

/// Process-global shard count, frozen once at BGP instance spawn by
/// [`init_shard_count`]. A `OnceLock` (not a per-call env read) so the value
/// the shard pool spawns with is the exact same one `egress_pool()`
/// (route.rs) reads when sizing itself — they must agree or shards + egress
/// workers oversubscribe the cores (the Phase E.2 invariant).
static SHARD_COUNT: std::sync::OnceLock<usize> = std::sync::OnceLock::new();

/// The `ZEBRA_BGP_SHARDS` environment variable (the pre-C.4 form, now the
/// fallback when the YANG `shards` leaf is unset). `None` if unset/invalid.
fn shard_count_env() -> Option<usize> {
    std::env::var("ZEBRA_BGP_SHARDS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
}

/// Pure resolution policy (unit-tested): the YANG `router bgp shards <n>`
/// leaf (C.4) wins over the env var, which wins over the default `1`. The
/// chosen value is clamped to `1..=64` (so `0` and out-of-range fold to the
/// nearest valid degree).
fn resolve_shard_count(config_shards: Option<usize>, env_shards: Option<usize>) -> usize {
    config_shards
        .or(env_shards)
        .map(|n| n.clamp(1, 64))
        .unwrap_or(1)
}

/// Freeze the shard count at instance spawn from the YANG `shards` leaf
/// (else `ZEBRA_BGP_SHARDS`, else `1`). Called once from `spawn_bgp` before
/// [`Bgp::new`] constructs the pool; the result is stored process-globally
/// so [`shard_count`] returns it everywhere (the shard pool and the egress
/// pool alike). Idempotent — `spawn_bgp` short-circuits a re-spawn, and the
/// first frozen value wins regardless.
pub fn init_shard_count(config_shards: Option<usize>) -> usize {
    let n = resolve_shard_count(config_shards, shard_count_env());
    let _ = SHARD_COUNT.set(n);
    let n = shard_count();
    let source = if config_shards.is_some() {
        "config"
    } else if shard_count_env().is_some() {
        "ZEBRA_BGP_SHARDS"
    } else {
        "default"
    };
    if n > 1 {
        tracing::info!("BGP RIB sharding: {n} shards (from {source})");
    } else {
        tracing::info!("BGP RIB sharding: 1 shard, synchronous (from {source})");
    }
    n
}

/// Number of parallel RIB shards (RIB sharding Phase C). Returns the value
/// frozen at spawn by [`init_shard_count`]; before any instance spawns
/// (unit tests / env-only paths) it falls back to `ZEBRA_BGP_SHARDS`, then
/// `1`. `1` keeps the synchronous single-shard path (BDD-safe); `> 1` fans
/// ingest out by prefix hash across that many worker threads. Startup-only —
/// live resharding is out of scope (the pool spawns in [`Bgp::new`] before
/// any route state). Always in `1..=64`.
pub fn shard_count() -> usize {
    SHARD_COUNT
        .get()
        .copied()
        .unwrap_or_else(|| resolve_shard_count(None, shard_count_env()))
}

/// A2 step ① — per-`req_id` barrier for in-flight `DumpV4` dumps. Each
/// session-up dump is fanned to the N pool shards (`broadcast_dump_v4`);
/// every `ShardOut::DumpDoneV4` decrements that request's outstanding-ack
/// count, and the last ack returns a [`DumpDoneSummaryV4`] so main can
/// record the dump's `adj_out` deltas + emit EoR (step ③/④). `req_id`s are
/// a monotonic counter (no wall-clock), so the sequence is deterministic.
#[derive(Default)]
struct DumpBarrierV4 {
    next_req_id: u64,
    inflight: std::collections::HashMap<u64, DumpStateV4>,
}

struct DumpStateV4 {
    /// The peer this dump targets (`Peer::ident`).
    ident: usize,
    /// Shard acks still outstanding — starts at N, hits 0 on completion.
    remaining: usize,
    /// UPDATEs enqueued so far, summed across shards (for the EoR log).
    sent: usize,
}

/// Returned by [`DumpBarrierV4::ack`] on the final ack of a `req_id`.
struct DumpDoneSummaryV4 {
    ident: usize,
    sent: usize,
}

impl DumpBarrierV4 {
    /// Register a dump fanned to `n` shards for `ident`; returns its
    /// `req_id`. Called from `Bgp::broadcast_dump_v4` at session-up (N>1).
    fn start(&mut self, ident: usize, n: usize) -> u64 {
        let req_id = self.next_req_id;
        self.next_req_id += 1;
        self.inflight.insert(
            req_id,
            DumpStateV4 {
                ident,
                remaining: n,
                sent: 0,
            },
        );
        req_id
    }

    /// Record one shard's ack (`sent` UPDATEs). Returns `Some` summary on
    /// the last outstanding ack of `req_id`, else `None`. An ack for an
    /// unknown `req_id` (already completed, or never started) is ignored.
    fn ack(&mut self, req_id: u64, sent: usize) -> Option<DumpDoneSummaryV4> {
        let state = self.inflight.get_mut(&req_id)?;
        state.sent += sent;
        state.remaining = state.remaining.saturating_sub(1);
        if state.remaining > 0 {
            return None;
        }
        let state = self.inflight.remove(&req_id)?;
        Some(DumpDoneSummaryV4 {
            ident: state.ident,
            sent: state.sent,
        })
    }
}

pub struct Bgp {
    pub asn: u32,
    /// Effective BGP Identifier — what OPENs, EVPN RDs and the show
    /// paths use. Derived: configured `global router-id` wins, else
    /// the RIB-derived value, else 0.0.0.0. Mutate via
    /// `refresh_router_id` (or `set_router_id` for the propagation
    /// side effects), never directly.
    pub router_id: Ipv4Addr,
    /// Operator-configured `router bgp global router-id`. Wins over
    /// the RIB-derived value; deleting it falls back (same
    /// configured-vs-derived split IS-IS uses for te-router-id).
    pub router_id_config: Option<Ipv4Addr>,
    /// Last RIB-derived router-id (`RibRx::RouterIdUpdate`), kept
    /// even while a configured identifier overrides it so a later
    /// `delete ... router-id` can fall back without waiting for the
    /// next RIB push.
    pub rib_router_id: Option<Ipv4Addr>,
    /// FRR-style `advertise-all-vni` knob under `router bgp afi-safi
    /// evpn`. When true, every locally-configured VXLAN VNI
    /// participates in EVPN advertisement: Type-2 (MAC/IP) routes
    /// from the kernel's bridge FDB and Type-3 (Inclusive Multicast)
    /// routes per local VTEP. Bridge -> VNI mapping is inferred from
    /// the kernel (each bridge's VXLAN slave supplies the VNI). RD =
    /// router-id:VNI; RT-import / RT-export = local-AS:VNI per
    /// RFC 8365 §5.1.2.
    ///
    /// Schema-only in the PR that introduced this — no consumer yet.
    /// The Rib::neighbors -> EvpnPrefix::MacIp pipeline that reads
    /// this lands separately.
    pub advertise_all_vni: bool,
    /// Local bridge FDB shadow keyed by `(vni, mac)`. Populated from
    /// every `RibRx::FdbAdd`, removed on `RibRx::FdbDel`. We need
    /// durable state (not just one-shot event handling) because the
    /// FDB events from `Rib::subscribe` / `fib_dump` race with the
    /// config commit that flips `advertise_all_vni` to true: at cold
    /// start, fib_dump's netlink walk almost always finishes before
    /// `config.load_config` does, so the FdbAdd messages arrive while
    /// the gate is still false and `evpn_originate_macip` drops them.
    /// With the shadow, the config callback can replay every cached
    /// entry on the false→true transition (and withdraw on true→false),
    /// so origination becomes deterministic regardless of which
    /// channel wins the boot race.
    pub local_fdb: BTreeMap<(u32, MacAddr), FdbEntry>,
    /// Local VXLAN VTEP shadow keyed by VNI, value = local VTEP IP
    /// (the VXLAN device's `IFLA_VXLAN_LOCAL` / `LOCAL6`). Populated
    /// from `RibRx::VxlanAdd`, removed on `RibRx::VxlanDel`. Drives
    /// Type-3 (Inclusive Multicast) origination — one IMET per VNI
    /// — and replays on `advertise_all_vni` / `router_id` transitions
    /// just like `local_fdb`.
    pub local_vxlans: BTreeMap<u32, std::net::IpAddr>,
    /// Configured hostname for the local BGP speaker. Advertised in
    /// the FQDN capability (capability code 73). When None, falls back
    /// to the OS hostname; if that also fails, no FQDN capability is
    /// emitted. See `Bgp::hostname()` for the resolution order.
    pub hostname: Option<String>,
    /// `router bgp global no-fib-install`. When true, this instance's
    /// `ctx.rib` drops every forwarding install (IPv4/IPv6 unicast plus
    /// VPN/EVPN/labeled-unicast MPLS ILMs) so selected routes never
    /// reach the kernel FIB. The Loc-RIB is still built and routes are
    /// still reflected/advertised — this is the pure route-reflector
    /// mode for a speaker out of the forwarding path. The actual gate
    /// lives on the shared `RibClient` flag
    /// ([`crate::rib::client::RibClient::set_suppress_install`]); this
    /// field mirrors it for `show` / re-application. Scope is the
    /// default-VRF instance; per-VRF suppression is a follow-up.
    pub no_fib_install: bool,
    pub peers: PeerMap,
    /// Instance-level BFD defaults (`router bgp { bfd {} }`), inherited by
    /// every neighbor and overridden per neighbor (see
    /// [`super::peer::PeerBfdConfig::resolve`]).
    pub bfd: PeerBfdConfig,
    /// Bounded channel for BGP events (capacity: 8192)
    pub tx: mpsc::Sender<Message>,
    pub rx: mpsc::Receiver<Message>,
    /// Unbounded self-signal for the resumable IPv4 sync cursor (Tier
    /// 1a). Dedicated + unbounded so a continuation tick can never be
    /// dropped on a full `tx`; carries the peer `ident`. Idle (never
    /// fed) when `ZEBRA_BGP_SYNC_CHUNK` is unset.
    pub sync_tick_tx: mpsc::UnboundedSender<usize>,
    pub sync_tick_rx: mpsc::UnboundedReceiver<usize>,
    pub cm: ConfigChannel,
    pub show: ShowChannel,
    pub show_cb: HashMap<String, ShowCallback>,
    /// Sender to the config manager, used to (de)register this
    /// instance's per-VRF show channels so `show bgp vrf <name> …`
    /// can be redirected into the matching VRF task.
    pub manager_tx: mpsc::Sender<crate::config::Message>,
    /// Spawn-time runtime context. Bundles the `RibClient` (sends
    /// to RIB through `self.ctx.rib`) with the VRF identity the
    /// socket factories on `ctx` consult — so BGP code calls
    /// `self.ctx.tcp_listen(...)` / `self.ctx.tcp_socket_v*()`
    /// without ever branching on whether it's the default routing
    /// table or a future VRF instance.
    pub ctx: ProtoContext,
    pub rib_rx: UnboundedReceiver<RibRx>,
    /// Next-Hop Tracking cache (global instance only). Populated by the
    /// received-route path and updated by `RibRx::NexthopUpdate`.
    pub nexthop_cache: super::nht::NexthopCache,
    pub callbacks: HashMap<String, Callback>,
    pub pcallbacks: HashMap<String, PCallback>,
    /// BGP Local RIB (Loc-RIB) for best path selection
    pub local_rib: LocalRib,
    /// Shard-scope Loc-RIB tables (unicast/LU/VPN). The route pipeline
    /// applies ingest to these through [`BgpShard::handle`] — building a
    /// `ShardMsg`, dispatching it synchronously, and acting on the
    /// returned `ShardOut` delta (RIB sharding B.3, sync-dispatch). The
    /// same `handle` becomes the body of the shard *task* when C.1
    /// introduces real parallelism. See [`super::shard::BgpShard`] for
    /// the partition.
    ///
    /// [`BgpShard::handle`]: super::shard::BgpShard::handle
    pub shard: BgpShard,
    /// Parallel shard worker pool (RIB sharding Phase C). `None` when
    /// [`shard_count`]` == 1` — the synchronous `shard` field above is used
    /// and nothing is spawned. `Some` when `> 1`: N worker threads, each
    /// owning a `BgpShard`, with the ingest fanned out by prefix hash and
    /// their best-path deltas drained on `shard_results_rx`.
    pub shards: Option<super::shard::pool::ShardPool>,
    /// Merged best-path deltas from every shard worker, drained by the
    /// event loop's `select!`. Closed and idle when `shard_count() == 1`.
    pub shard_results_rx: UnboundedReceiver<super::shard::pool::ShardResult>,
    /// A2 step ① — per-`req_id` barrier for in-flight `DumpV4` dumps: counts
    /// the `ShardOut::DumpDoneV4` acks still outstanding for each session-up
    /// dump, so main records the dump's `adj_out` deltas + emits EoR once
    /// every shard has finished its slice (step ③/④).
    pending_dumps_v4: DumpBarrierV4,
    /// `router bgp port <0-65535>`: TCP port the BGP listener binds
    /// (IPv4 and IPv6 both), default [`BGP_PORT`] (179). 0 disables
    /// listening entirely — no server socket is open, so every session
    /// must be dialed by this router. A config change closes and
    /// reopens the listeners via [`Message::Relisten`] →
    /// [`Bgp::relisten`]; established sessions are not touched. Scope
    /// is this instance's listener (per-VRF tasks keep the default).
    pub port: u16,
    pub listen_task: Option<Task<()>>,
    pub listen_task6: Option<Task<()>>,
    pub listen_err: Option<anyhow::Error>,
    // Raw fds of the IPv4 / IPv6 BGP listening sockets, captured in
    // listen() before the TcpListeners are moved into their accept
    // tasks. Used by config callbacks to install or remove TCP MD5 /
    // TCP-AO keys per-peer on the passive side — the kernel requires
    // the key to be on the listener before the peer's SYN arrives;
    // a post-accept() setsockopt is too late. See TCP-MD5-AO.md
    // "Passive vs active side placement".
    pub listen_fd_v4: Option<std::os::fd::RawFd>,
    pub listen_fd_v6: Option<std::os::fd::RawFd>,
    /// Snapshot of `/key-chains/key-chain <name>` entries pushed
    /// here by the policy actor via `PolicyRx::KeyChain`. The
    /// canonical map lives in `policy::Policy`; this is the
    /// per-neighbor-subscribed view BGP consults when resolving a
    /// peer's `tcp-ao/key-chain <name>` leafref. Updated by
    /// `process_policy_msg`.
    pub key_chains: BTreeMap<String, crate::policy::KeyChain>,

    /// IOS-XR-style `neighbor-group` definitions
    /// (zebra-bgp-neighbor-group.yang). Each entry holds the
    /// group's overridable defaults; field-level inheritance into
    /// peers that reference a group via `PeerConfig::neighbor_group`
    /// is not wired in the runtime yet — that lands in a follow-up.
    pub neighbor_groups: BTreeMap<String, super::neighbor_group::NeighborGroup>,

    /// Color → Flex-Algorithm binding table
    /// (zebra-bgp-color-policy.yang). The colour-aware nexthop
    /// resolver consults this to pick a per-algo entry from
    /// `flex_algo_routes` when a route carries a Color extcomm.
    pub color_policy: super::color_policy::ColorPolicy,

    /// Local shadow of `Rib::flex_algo_routes`, populated by
    /// `RibRx::FlexAlgoRouteAdd/Del` events emitted from IS-IS via
    /// RIB (PR #697). Outer key is the IS-IS Flex-Algorithm id; inner
    /// map is the per-algo IPv4 RIB. The colour-aware resolver does
    /// a longest-prefix match on the BGP next-hop against the
    /// inner map for the algo bound to the route's Color extcomm,
    /// and pushes the resulting outer MPLS label onto the FIB
    /// install.
    pub flex_algo_routes:
        BTreeMap<u8, prefix_trie::PrefixMap<ipnet::Ipv4Net, crate::rib::api::FlexAlgoNexthop>>,
    /// SRv6 twin of `flex_algo_routes`, populated by
    /// `RibRx::FlexAlgoSrv6RouteAdd/Del`. Maps a destination prefix
    /// reachable in algo-N to the advertising node's algo-N End SID; the
    /// colour-aware resolver LPMs the BGP next-hop here and imposes an
    /// H.Encap toward the End SID instead of pushing an MPLS label.
    pub flex_algo_srv6_routes: super::color_policy::FlexAlgoSrv6Shadow,
    /// `dynamic-neighbors` runtime (zebra-bgp-dynamic-neighbors.yang).
    /// Holds the configured listen-ranges and the soft cap on
    /// materialized passive peers. `dynamic_peer_count` is bumped on
    /// successful accept-time materialization in `peer::accept`; it
    /// is never decremented yet — session-close GC is deferred to a
    /// follow-up so this PR stays focused on the accept path.
    pub dynamic_neighbors: super::dynamic_neighbors::DynamicNeighbors,
    pub dynamic_peer_count: u32,
    /// `interface-neighbor` config — operator types
    /// `set router bgp interface-neighbor <name>`. Lookup key is the
    /// interface name; the runtime resolves to ifindex via
    /// [`Self::link_index_by_name`] when an RA arrives and triggers
    /// peer materialization. Materialization itself happens in
    /// [`super::interface_neighbor::materialize_peer`].
    pub interface_neighbors: BTreeMap<String, super::interface_neighbor::InterfaceNeighborCfg>,
    /// Staged per-VRF BGP intent — populated by the callbacks for
    /// `/router/bgp/vrf/<name>/...` (zebra-bgp-vrf.yang). Diffed
    /// against [`Self::vrf_registry`] at each `CommitEnd` to drive
    /// [`super::vrf::spawn_bgp_vrf`] and
    /// [`super::vrf::despawn_bgp_vrf`].
    pub vrfs: BTreeMap<String, super::vrf_config::BgpVrfConfig>,
    /// Per-VRF tasks currently running. The diff against
    /// [`Self::vrfs`] at `CommitEnd` spawns the names that show up
    /// in the desired set but not here, and despawns names that
    /// show up here but not in the desired set. The spawn site
    /// lifts the placeholder `ProtoContext::default_table_no_rib`
    /// to a real `ProtoContext::for_vrf(rib, table_id, name)` when
    /// [`Self::rib_known_vrfs`] gains the matching kernel info via
    /// `RibRx::VrfAdd`.
    pub vrf_registry: BTreeMap<String, super::vrf::BgpVrfHandle>,
    /// Kernel VRF master devices RIB has told us about, keyed by
    /// VRF name. Populated by `RibRx::VrfAdd` (and replayed from
    /// `Rib::subscribe`). The per-VRF spawn site consults this to
    /// build a real `ProtoContext::for_vrf`; when the kernel info
    /// isn't yet known the spawn falls back to a placeholder
    /// context and the entry gets a respawn the moment `VrfAdd`
    /// arrives.
    pub rib_known_vrfs: BTreeMap<String, RibKnownVrf>,
    /// Send-capable RIB-subscription handle, cloned from
    /// `ConfigManager::rib_subscriber()` at spawn time. The
    /// per-VRF spawn site uses this to mint a fresh `RibClient`
    /// plus `Subscribe` with the VRF's kernel `table_id`, so the
    /// inbound dispatcher routes route installs into
    /// `vrf_tables[table_id]`.
    pub rib_subscriber: crate::config::RibSubscriber,
    /// Per-VRF MPLS label allocator. Hands out one label per
    /// `spawn_bgp_vrf` call; reclaims at despawn. The label gets
    /// stamped onto every `BgpGlobalMsg::Export` the VRF emits and
    /// drives the matching ILM Decap install on the PE.
    /// Per-VRF label allocator, bounded to the dynamic block the RIB
    /// label manager hands BGP at startup. `None` until that
    /// `RibRx::LabelBlock` arrives — VRFs spawned before then take
    /// label 0 (degraded) and are reconciled on arrival.
    pub vrf_label_alloc: Option<super::vrf::VrfLabelAllocator>,
    /// True while a `LabelBlockRequest` is outstanding — dedups the
    /// initial request and any on-demand extension so a burst of
    /// label-less VRFs asks the RIB label manager for only one block.
    vrf_label_request_pending: bool,
    // The per-prefix LU/VPNv4 local-label caches moved to
    // `BgpShard::labels` (RIB sharding B.2): they pair with the shard's
    // sub-block allocator, which refills by carving from
    // `vrf_label_alloc` above. `vrf_label_alloc` itself stays here — it
    // is the central pool and still serves the per-VRF-spawn labels.
    /// Configured SRv6 locator name (`router bgp segment-routing
    /// srv6 locator <name>`). When set, BGP watches this locator on the
    /// RIB and (in a follow-up) carves per-VRF End.DT46 service SIDs
    /// from it for `encapsulation srv6` VRFs. `None` until configured.
    pub srv6_locator_name: Option<String>,
    /// SRv6 locator updates from the RIB segment-routing manager,
    /// established once via `Message::SrSubscribe` in [`Self::new`].
    /// Drained in the event loop; resolution drives per-VRF End.DT46
    /// SID (re)allocation.
    pub srv6_locator_rx: UnboundedReceiver<crate::rib::RibSrRx>,
    /// Resolved [`crate::rib::Locator`] for [`Self::srv6_locator_name`],
    /// `None` until it resolves (or after withdrawal). `encapsulation
    /// srv6` VRFs carve their per-VRF End.DT46 SID from this locator's
    /// prefix; a prefix change re-seeds the pool and re-allocates.
    pub srv6_locator: Option<crate::rib::Locator>,
    /// First-fit function allocator for the per-VRF End.DT46 service
    /// SIDs carved from [`Self::srv6_locator`]. Reset when the locator
    /// prefix changes (every prior SID address is then invalid).
    pub srv6_sid_pool: super::vrf::BgpSidPool,
    /// `segment-routing srv6 ipv6-unicast` — when `true`, the global
    /// IPv6 unicast table originates routes with an SRv6 End.DT6 service
    /// SID (the default-table analogue of a per-VRF `encapsulation srv6`).
    pub srv6_ipv6_unicast: bool,
    /// The instance End.DT6 SID for the global IPv6 unicast table:
    /// `(addr, function)`, carved from [`Self::srv6_locator`] when
    /// [`Self::srv6_ipv6_unicast`] is on and the locator has resolved.
    /// `None` otherwise. The `function` is borrowed from
    /// [`Self::srv6_sid_pool`], same as a per-VRF SID.
    pub srv6_ipv6_sid: Option<(std::net::Ipv6Addr, u16)>,
    /// Precomputed advertise-time data derived from
    /// [`Self::srv6_ipv6_sid`] and the locator, borrowed into
    /// [`super::peer::BgpTop`] so the egress path stamps
    /// locally-originated IPv6 routes without re-deriving it per route.
    /// Kept in lock-step with `srv6_ipv6_sid`.
    pub srv6_ipv6_export: Option<Srv6Ipv6Export>,
    /// Locally-originated IPv6 unicast `network` prefixes, so they can be
    /// re-originated (SRv6 End.DT6 SID re-stamped) when the locator
    /// resolves after the `network` was configured. Redistributed
    /// prefixes are tracked separately in `redist_v6`.
    pub networks_v6: std::collections::BTreeSet<ipnet::Ipv6Net>,
    /// Inbound `:179` dispatch index — peer source IP to VRF name.
    /// Populated by [`super::vrf::BgpGlobalMsg::RegisterPeer`]
    /// each per-VRF task emits at spawn / materialise time, and
    /// drained on `UnregisterPeer`. The accept handler consults
    /// this: a connection from an IP claimed by some VRF is
    /// forwarded via `BgpVrfMsg::Accept` to that VRF's task; every
    /// other connection falls through to the existing
    /// global-instance accept path.
    pub peer_index: BTreeMap<std::net::IpAddr, String>,
    /// Outbound sender every per-VRF task uses to push messages
    /// back to the global runtime — peer registration, exports,
    /// withdraws. Cloned into [`super::vrf::BgpVrf::global_tx`] at
    /// spawn time so all VRFs fan in to one channel here.
    pub vrf_global_tx: UnboundedSender<super::vrf::BgpGlobalMsg>,
    /// Receiver paired with [`Self::vrf_global_tx`], drained in
    /// the event loop. Handlers cover peer register / accept
    /// dispatch and export -> VPNv4/v6.
    pub vrf_global_rx: UnboundedReceiver<super::vrf::BgpGlobalMsg>,
    /// `if-name` → `ifindex` mirror fed by `RibRx::LinkAdd`. Needed
    /// because the YANG callback receives a name but
    /// `PeerKey::Interface` keys on ifindex. Lookups that miss
    /// (config staged before the link surfaces) defer materialization
    /// until the next link-add event.
    pub link_index_by_name: BTreeMap<String, u32>,
    /// Per-ifindex IPv6 link-local registry, populated from
    /// `RibRx::AddrAdd`/`AddrDel`. Source of the v6 next-hop emitted
    /// in MP_REACH for IPv4-unicast advertisements on interface peers
    /// (RFC 8950). See [`super::interface_addrs`].
    pub interface_addrs: super::interface_addrs::InterfaceAddrs,
    /// Directly-connected subnets, populated from `RibRx::AddrAdd`/`AddrDel`.
    /// Backs the eBGP connected check: a single-hop eBGP peer whose address
    /// is not covered here is held down unless it has `disable-connected-check`
    /// (see [`super::connected`] and [`Self::refresh_connected`]).
    pub connected_subnets: super::connected::ConnectedSubnets,
    /// IOS-XR-style update-groups, keyed by `(AfiSafi, signature)`.
    /// Signature + membership tracking only — the advertise pipeline
    /// does not yet share work across members. See
    /// `docs/design/bgp-update-groups.md`.
    pub update_groups: super::update_group::UpdateGroupMap,
    /// Instance-wide conditional tracing config (zebra-bgp-tracing.yang
    /// `router bgp tracing`). Written by the tracing config dispatch;
    /// read by the gated `bgp_*_trace!` macros (follow-up).
    #[allow(dead_code)]
    pub tracing: super::tracing::BgpTracing,
    pub policy_tx: UnboundedSender<policy::Message>,
    pub policy_rx: UnboundedReceiver<policy::PolicyRx>,
    /// Handle into the BFD instance's client-request channel — used
    /// by the per-neighbor `bfd { enable }` path to submit
    /// `ClientReq::Subscribe` / `Unsubscribe`. `None` means BFD has
    /// not (yet) been configured: BGP silently skips its BFD attach
    /// logic in that case. Captured at spawn time from
    /// `ConfigManager::bfd_client_tx`; not refreshed if BFD respawns
    /// later (late-binding work is a follow-up).
    pub bfd_client_tx: Option<UnboundedSender<crate::bfd::inst::ClientReq>>,
    /// Sender half of the per-instance `BfdEvent` channel. Cloned and
    /// handed to BFD as the `notifier` on every `Subscribe`, so all
    /// state-change events for BGP-attached BFD sessions land on the
    /// matching `bfd_event_rx` below.
    pub bfd_event_tx: UnboundedSender<crate::bfd::inst::BfdEvent>,
    /// Receive half drained by the BGP event loop in
    /// [`Self::event_loop`]. Events are logged today; a future
    /// pass will replace the log with neighbor teardown on
    /// `BfdEvent::Down`.
    pub bfd_event_rx: UnboundedReceiver<crate::bfd::inst::BfdEvent>,
    /// Receive half of the ND `NeighborDiscovered` subscription. ND's
    /// engine sends here whenever a Router Advertisement arrives on
    /// an interface; the BGP event loop drains it and materializes
    /// an interface-keyed Peer for any matching `interface-neighbor`
    /// config.
    pub nd_event_rx: UnboundedReceiver<crate::nd::engine::NdEvent>,
    // BgpAttr shared storage.
    pub attr_store: BgpAttrStore,

    /// Per-AFI redistribution configuration. Populated by the
    /// `/router/bgp/afi-safi/redistribute/<source>...` callbacks
    /// (zebra-bgp-redistribute.yang); one entry per (AfiSafi, source)
    /// pair, holding policy / metric / multipath plus per-source
    /// extras (IS-IS level filter, OSPF match types).
    ///
    /// Each commit converts these into wire-level RedistAdd /
    /// RedistUpdate / RedistDel messages bound for RIB; the per-AFI
    /// snapshots below catch the route deliveries that come back.
    pub redistribute: BTreeMap<
        (bgp_packet::AfiSafi, super::config::BgpRedistSource),
        super::config::BgpRedistribute,
    >,

    /// Redistribute snapshot — routes the RIB delivered via
    /// `RouteAdd`/`RouteDel` for our `RedistAdd` subscriptions.
    /// Keyed by `(RibType, prefix)` so different source protocols
    /// advertising the same prefix stay distinct (each row carries
    /// its own policy / metric / multipath override at Loc-RIB
    /// injection time). Consumed by the BGP origination path in a
    /// follow-up.
    pub redist_v4: BTreeMap<(crate::rib::RibType, ipnet::Ipv4Net), crate::rib::RouteEntryV4>,
    pub redist_v6: BTreeMap<(crate::rib::RibType, ipnet::Ipv6Net), crate::rib::RouteEntryV6>,

    /// Global MinRouteAdvertisementInterval (MRAI) per RFC 4271
    /// §9.2.1.1, split by peer type. Source of truth for the per-Peer
    /// / per-UpdateGroup `adv_interval` snapshots. Configured under
    /// `router bgp timer adv-interval { ibgp; ebgp; }`.
    pub adv_interval: super::timer::AdvInterval,
}

impl Bgp {
    pub fn new(
        ctx: ProtoContext,
        rib_rx: UnboundedReceiver<RibRx>,
        rib_subscriber: crate::config::RibSubscriber,
        policy_tx: UnboundedSender<policy::Message>,
        bfd_client_tx: Option<UnboundedSender<crate::bfd::inst::ClientReq>>,
        nd_client_tx: Option<UnboundedSender<crate::nd::inst::NdClientReq>>,
        manager_tx: mpsc::Sender<crate::config::Message>,
    ) -> Self {
        let policy_chan = PolicyRxChannel::new();
        let msg = policy::Message::Subscribe {
            proto: "bgp".into(),
            tx: policy_chan.tx.clone(),
        };
        let _ = policy_tx.send(msg);

        let (tx, rx) = mpsc::channel(8192);
        let (sync_tick_tx, sync_tick_rx) = mpsc::unbounded_channel();
        let (bfd_event_tx, bfd_event_rx) = mpsc::unbounded_channel();
        // Fan-in channel: every per-VRF task gets a clone of
        // `vrf_global_tx_init` at spawn time, so all VRF→global
        // messages land on one receiver in the global event loop.
        let (vrf_global_tx_init, vrf_global_rx_init) = mpsc::unbounded_channel();

        // Subscribe to ND `NeighborDiscovered` events so the BGP
        // unnumbered runtime can materialize an interface-keyed Peer
        // when an RA reveals the remote's link-local. If ND failed
        // to start (no `CAP_NET_RAW`), the channel pair is created
        // but no events ever arrive — the BGP event loop just sits
        // on a dead arm.
        let (nd_event_tx, nd_event_rx) = mpsc::unbounded_channel();
        if let Some(ref tx) = nd_client_tx {
            let _ = tx.send(crate::nd::inst::NdClientReq::SetNotifier { tx: nd_event_tx });
        }
        // SRv6 locator subscription. Register the SR return channel
        // once up front (mirrors IS-IS); the per-locator interest is
        // expressed later via `SrLocatorWatch` when the operator sets
        // `router bgp segment-routing srv6 locator <name>`.
        let (srv6_sr_tx, srv6_locator_rx) = mpsc::unbounded_channel();
        // Parallel shard pool (RIB sharding Phase C). With `shard_count()`
        // == 1 (default) the synchronous `shard` field is used and no pool
        // is spawned — dropping `shard_results_tx` here closes the channel
        // so the event loop's drain arm stays idle. With `> 1` the pool
        // spawns N worker threads and owns the sender clones.
        let (shard_results_tx, shard_results_rx) = mpsc::unbounded_channel();
        let n_shards = shard_count();
        let shards = (n_shards > 1).then(move || {
            let workers = (0..n_shards).map(|_| BgpShard::default()).collect();
            super::shard::pool::ShardPool::spawn(workers, shard_results_tx)
        });
        let mut bgp = Self {
            asn: 0,
            router_id: Ipv4Addr::UNSPECIFIED,
            router_id_config: None,
            rib_router_id: None,
            advertise_all_vni: false,
            local_fdb: BTreeMap::new(),
            local_vxlans: BTreeMap::new(),
            hostname: None,
            no_fib_install: false,
            peers: PeerMap::new(),
            bfd: PeerBfdConfig::default(),
            tx,
            rx,
            sync_tick_tx,
            sync_tick_rx,
            local_rib: LocalRib::default(),
            shard: BgpShard::default(),
            shards,
            shard_results_rx,
            pending_dumps_v4: DumpBarrierV4::default(),
            ctx,
            rib_rx,
            nexthop_cache: super::nht::NexthopCache::default(),
            cm: ConfigChannel::new(),
            show: ShowChannel::new(),
            show_cb: HashMap::new(),
            manager_tx,
            callbacks: HashMap::new(),
            pcallbacks: HashMap::new(),
            port: BGP_PORT,
            listen_task: None,
            listen_task6: None,
            listen_err: None,
            listen_fd_v4: None,
            listen_fd_v6: None,
            key_chains: BTreeMap::new(),
            neighbor_groups: super::neighbor_group::empty_map(),
            color_policy: super::color_policy::ColorPolicy::new(),
            flex_algo_routes: BTreeMap::new(),
            flex_algo_srv6_routes: Default::default(),
            dynamic_neighbors: super::dynamic_neighbors::DynamicNeighbors::default(),
            dynamic_peer_count: 0,
            interface_neighbors: super::interface_neighbor::empty_map(),
            vrfs: BTreeMap::new(),
            vrf_registry: BTreeMap::new(),
            rib_known_vrfs: BTreeMap::new(),
            rib_subscriber,
            vrf_label_alloc: None,
            vrf_label_request_pending: false,
            srv6_locator_name: None,
            srv6_locator_rx,
            srv6_locator: None,
            srv6_sid_pool: super::vrf::BgpSidPool::new(),
            srv6_ipv6_unicast: false,
            srv6_ipv6_sid: None,
            srv6_ipv6_export: None,
            networks_v6: std::collections::BTreeSet::new(),
            peer_index: BTreeMap::new(),
            vrf_global_tx: vrf_global_tx_init,
            vrf_global_rx: vrf_global_rx_init,
            link_index_by_name: BTreeMap::new(),
            interface_addrs: super::interface_addrs::InterfaceAddrs::new(),
            connected_subnets: super::connected::ConnectedSubnets::new(),
            update_groups: super::update_group::empty_map(),
            tracing: super::tracing::BgpTracing::default(),
            policy_tx,
            policy_rx: policy_chan.rx,
            bfd_client_tx,
            bfd_event_tx,
            bfd_event_rx,
            nd_event_rx,
            attr_store: BgpAttrStore::new(),
            redistribute: BTreeMap::new(),
            redist_v4: BTreeMap::new(),
            redist_v6: BTreeMap::new(),
            adv_interval: super::timer::AdvInterval::default(),
        };
        bgp.callback_build();
        bgp.show_build();
        // One-time SR subscription so subsequent `SrLocatorWatch`
        // requests get a return channel; the RIB replies on
        // `srv6_locator_rx`.
        let _ = bgp.ctx.rib.send(crate::rib::Message::SrSubscribe {
            proto: "bgp".into(),
            tx: srv6_sr_tx,
        });
        bgp
    }

    pub fn callback_add(&mut self, path: &str, cb: Callback) {
        self.callbacks.insert(path.to_string(), cb);
    }

    /// Resolve the hostname to advertise in the FQDN capability.
    /// Configured value wins; otherwise we fall back to the OS
    /// hostname. None means "skip the FQDN capability entirely".
    pub fn hostname(&self) -> Option<String> {
        if let Some(name) = &self.hostname {
            return Some(name.clone());
        }
        hostname::get()
            .ok()
            .and_then(|s| s.into_string().ok())
            .filter(|s| !s.is_empty())
    }

    /// Update the configured hostname and propagate the resolved
    /// value to every peer's `local_hostname` snapshot. Existing
    /// sessions keep using the value they captured at OPEN; the
    /// next OPEN this peer sends (after a reset / re-establishment)
    /// will pick up the new one.
    pub fn config_set_hostname(&mut self, value: Option<String>) {
        if self.hostname == value {
            return;
        }
        self.hostname = value;
        let resolved = self.hostname();
        for (_, peer) in self.peers.iter_mut_all() {
            peer.local_hostname = resolved.clone();
        }
    }

    /// Update the configured global SRv6 locator name and (un)watch it
    /// on the RIB. Mirrors IS-IS `reconcile_locator_watch`: unwatch the
    /// previous name, watch the new one. The resolved [`Locator`]
    /// arrives asynchronously on [`Self::srv6_locator_rx`].
    pub fn set_srv6_locator(&mut self, name: Option<String>) {
        if self.srv6_locator_name == name {
            return;
        }
        if let Some(prev) = self.srv6_locator_name.take() {
            let _ = self.ctx.rib.send(crate::rib::Message::SrLocatorUnwatch {
                proto: "bgp".into(),
                name: prev,
            });
        }
        if let Some(next) = name {
            let _ = self.ctx.rib.send(crate::rib::Message::SrLocatorWatch {
                proto: "bgp".into(),
                name: next.clone(),
            });
            self.srv6_locator_name = Some(next);
        }
    }

    /// Handle an SRv6 locator update from the RIB segment-routing
    /// manager. Stores the resolved [`crate::rib::Locator`] and, when
    /// the usable *prefix* changes (resolved / withdrawn / moved),
    /// re-seeds the SID pool and re-allocates every `encapsulation
    /// srv6` VRF's End.DT46 service SID so it tracks the new locator.
    fn process_sr_rx(&mut self, msg: crate::rib::RibSrRx) {
        match msg {
            crate::rib::RibSrRx::Locator { name, locator } => {
                // Ignore stale updates for a locator we no longer watch.
                if self.srv6_locator_name.as_deref() != Some(name.as_str()) {
                    return;
                }
                let new_prefix = locator.as_ref().and_then(|l| l.prefix);
                let old_prefix = self.srv6_locator.as_ref().and_then(|l| l.prefix);
                // Always store the latest (behavior may change without
                // the prefix moving), but only reconcile SIDs on a
                // material prefix change — the RIB re-sends the same
                // locator on every watcher add, and a needless respawn
                // would bounce CE sessions.
                self.srv6_locator = locator;
                if new_prefix == old_prefix {
                    return;
                }
                match new_prefix {
                    Some(prefix) => {
                        bgp_srv6_trace!(self.tracing, locator = %name, %prefix, "bgp: SRv6 locator resolved");
                    }
                    None => {
                        bgp_srv6_trace!(self.tracing, locator = %name, "bgp: SRv6 locator withdrawn");
                    }
                }
                self.reconcile_srv6_vrfs();
                // Re-allocate the global IPv6 unicast End.DT6 SID against
                // the new locator prefix. `reconcile_srv6_vrfs` just
                // reset the pool, so the old function is gone — withdraw
                // without releasing (mirrors resid_vrf), then re-install.
                self.withdraw_srv6_ipv6_sid(false);
                self.install_srv6_ipv6_sid();
                // Re-stamp originated IPv6 routes now the SID exists (the
                // route delivery may have raced ahead of locator resolution).
                self.reoriginate_srv6_ipv6();
            }
            crate::rib::RibSrRx::Block { .. } => {}
        }
    }

    /// Is `name` configured as an `encapsulation srv6` VRF?
    fn is_srv6_vrf(&self, name: &str) -> bool {
        self.vrfs.get(name).map(|c| c.encapsulation)
            == Some(super::vrf_config::BgpVrfEncapsulation::Srv6)
    }

    /// Allocate a per-VRF End.DT46 service SID from the resolved
    /// locator. `None` when the VRF isn't srv6-mode, the locator hasn't
    /// resolved, or the function space is exhausted — the VRF then
    /// spawns SID-less and is reconciled on the next locator update.
    fn alloc_vrf_sid(
        &mut self,
        cfg: &super::vrf_config::BgpVrfConfig,
    ) -> Option<super::vrf::Srv6VrfSid> {
        if cfg.encapsulation != super::vrf_config::BgpVrfEncapsulation::Srv6 {
            return None;
        }
        let loc_name = self.srv6_locator_name.clone()?;
        let prefix = self.srv6_locator.as_ref().and_then(|l| l.prefix)?;
        let function = self.srv6_sid_pool.allocate()?;
        match crate::isis::srv6::function_addr(prefix, function) {
            Some(addr) => Some(super::vrf::Srv6VrfSid {
                addr,
                function,
                locator: loc_name,
            }),
            None => {
                // Prefix too long to carry a 16-bit function — give the
                // function back so it isn't leaked.
                self.srv6_sid_pool.release(function);
                None
            }
        }
    }

    /// Rebuild a [`super::vrf::Srv6VrfSid`] from a handle's preserved
    /// `(addr, function)` so a relabel / kernel-ctx respawn re-installs
    /// the *same* SID rather than churning the address.
    fn preserved_srv6(
        &self,
        sid: Option<(std::net::Ipv6Addr, u16)>,
    ) -> Option<super::vrf::Srv6VrfSid> {
        let loc = self.srv6_locator_name.clone().unwrap_or_default();
        sid.map(|(addr, function)| super::vrf::Srv6VrfSid {
            addr,
            function,
            locator: loc.clone(),
        })
    }

    /// Re-seed the SID pool and re-allocate every running srv6 VRF's
    /// End.DT46 SID against the current locator. Driven by
    /// [`Self::process_sr_rx`] on a locator prefix change.
    fn reconcile_srv6_vrfs(&mut self) {
        // The locator prefix moved, so every previously-issued function
        // maps to a now-invalid address. Throw the pool away and
        // re-allocate from the base under the new prefix.
        self.srv6_sid_pool.reset();
        let srv6_vrfs: Vec<String> = self
            .vrf_registry
            .keys()
            .filter(|name| self.is_srv6_vrf(name))
            .cloned()
            .collect();
        for name in srv6_vrfs {
            self.resid_vrf(&name);
        }
    }

    /// `segment-routing srv6 ipv6-unicast` toggle. Enables or disables
    /// End.DT6 SID origination for the global IPv6 unicast table and
    /// reconciles the instance SID against the current locator. The pool
    /// is *not* reset here (unlike a locator change), so a withdrawn
    /// function is returned to the pool for reuse.
    pub fn set_srv6_ipv6_unicast(&mut self, enabled: bool) {
        if self.srv6_ipv6_unicast == enabled {
            return;
        }
        self.srv6_ipv6_unicast = enabled;
        self.withdraw_srv6_ipv6_sid(true);
        self.install_srv6_ipv6_sid();
        self.reoriginate_srv6_ipv6();
    }

    /// Withdraw the instance global-IPv6 End.DT6 SID, if installed, and
    /// clear the precomputed export. `release` returns the function to
    /// the SID pool — pass `false` on the locator-change path where the
    /// caller already `reset()` the pool (the old function no longer
    /// exists in it; releasing would corrupt the free list, same caveat
    /// as [`Self::resid_vrf`]).
    fn withdraw_srv6_ipv6_sid(&mut self, release: bool) {
        if let Some((addr, function)) = self.srv6_ipv6_sid.take() {
            self.rib_subscriber.send_sid_del(addr);
            if release {
                self.srv6_sid_pool.release(function);
            }
        }
        self.srv6_ipv6_export = None;
    }

    /// Allocate + install the instance global-IPv6 End.DT6 SID when
    /// `srv6_ipv6_unicast` is on and the locator has resolved, and build
    /// the [`Srv6Ipv6Export`] the egress path stamps onto locally-
    /// originated routes. No-op when disabled, unresolved, already
    /// installed, or the function space is exhausted (origination then
    /// stays SID-less until the next locator update). Unlike a per-VRF
    /// End.DT46, the End.DT6 decaps into the main table (`table_id` 0),
    /// which always exists — so there is no kernel-presence gate.
    fn install_srv6_ipv6_sid(&mut self) {
        if !self.srv6_ipv6_unicast || self.srv6_ipv6_sid.is_some() {
            return;
        }
        // Snapshot locator-derived values before the mutable pool /
        // subscriber calls so the immutable borrow doesn't conflict.
        let (prefix, nexthop, structure, loc_name) = {
            let Some(locator) = self.srv6_locator.as_ref() else {
                return;
            };
            let (Some(prefix), Some(nexthop)) = (locator.prefix, locator.node_sid_addr()) else {
                return;
            };
            (
                prefix,
                nexthop,
                locator.sid_structure(),
                self.srv6_locator_name.clone().unwrap_or_default(),
            )
        };
        let Some(function) = self.srv6_sid_pool.allocate() else {
            return;
        };
        let Some(addr) = crate::isis::srv6::function_addr(prefix, function) else {
            self.srv6_sid_pool.release(function);
            return;
        };
        self.rib_subscriber.send_sid_add(crate::rib::Sid {
            addr,
            behavior: crate::rib::SidBehavior::EndDT6,
            context: crate::rib::SidContext::None,
            owner: crate::rib::SidOwner::new("bgp", 0),
            locator: loc_name,
            allocation_type: crate::rib::SidAllocationType::Dynamic,
            ifindex: 0,
            nh6: None,
            structure: None,
            table_id: 0,
            segs: Vec::new(),
        });
        self.srv6_ipv6_sid = Some((addr, function));
        self.srv6_ipv6_export = Some(Srv6Ipv6Export {
            prefix_sid: srv6_l3_service_prefix_sid(
                addr,
                structure,
                bgp_packet::SRV6_BEHAVIOR_END_DT6,
            ),
            nexthop,
        });
        bgp_srv6_trace!(
            self.tracing,
            sid = %addr,
            "bgp: global IPv6 unicast End.DT6 SID installed"
        );
    }

    /// Re-originate every locally-originated IPv6 unicast route (both
    /// `network` and redistribute) so its Loc-RIB attr picks up — or
    /// drops — the global End.DT6 Prefix-SID after a locator or
    /// `ipv6-unicast` change.
    /// The connected/static route delivery and the locator resolution
    /// race, so re-stamping after the fact keeps the SID consistent
    /// regardless of arrival order.
    fn reoriginate_srv6_ipv6(&mut self) {
        let networks: Vec<ipnet::Ipv6Net> = self.networks_v6.iter().copied().collect();
        for prefix in networks {
            self.route_add_v6(prefix);
        }
        let redist: Vec<(crate::rib::RibType, ipnet::Ipv6Net, u32)> = self
            .redist_v6
            .iter()
            .filter_map(|((rtype, prefix), e)| {
                let source = Self::redist_source(*rtype)?;
                let uni = bgp_packet::AfiSafi::new(bgp_packet::Afi::Ip6, bgp_packet::Safi::Unicast);
                if self.redistribute.contains_key(&(uni, source)) {
                    let metric = self.redist_metric_override(uni, source).unwrap_or(e.metric);
                    Some((*rtype, *prefix, metric))
                } else {
                    None
                }
            })
            .collect();
        for (rtype, prefix, metric) in redist {
            self.route_redist_inject_v6(rtype, prefix, metric);
        }
    }

    /// Respawn `name`'s per-VRF task with a freshly-allocated End.DT46
    /// SID (or none, if the locator is now unresolved). Withdraws the
    /// old SID first. Mirrors [`Self::relabel_vrf`] but swaps the
    /// service SID rather than the MPLS label. Assumes the SID pool was
    /// already reset by the caller, so it does not free the old
    /// function (it no longer exists in the pool).
    fn resid_vrf(&mut self, name: &str) {
        let Some(cfg) = self.vrfs.get(name).cloned() else {
            return;
        };
        let preserved_label = if let Some(handle) = self.vrf_registry.remove(name) {
            super::vrf::despawn_bgp_vrf(name, &handle);
            self.unregister_vrf_show(name);
            self.peer_index.retain(|_, owner| owner != name);
            // Withdraw the stale SID by its (old-prefix) address.
            if let Some((addr, _function)) = handle.srv6_sid {
                self.rib_subscriber.send_sid_del(addr);
            }
            handle.label
        } else {
            return;
        };
        let kernel = self.rib_known_vrfs.get(name).cloned();
        let srv6 = self.alloc_vrf_sid(&cfg);
        let new_handle = super::vrf::spawn_bgp_vrf(
            name.to_string(),
            &cfg,
            self.router_id,
            self.asn,
            preserved_label,
            kernel,
            &self.rib_subscriber,
            srv6,
            self.vrf_global_tx.clone(),
        );
        self.register_vrf_show(name, &new_handle);
        self.vrf_registry.insert(name.to_string(), new_handle);
        // Re-seed the respawned VRF with the colour-steering snapshot.
        self.broadcast_colour_steering();
        bgp_srv6_trace!(self.tracing, vrf = %name, "bgp: reconciled SRv6 service SID for VRF");
    }

    /// Update the BGP router-id and propagate it to every peer's
    /// `router_id` snapshot. `Peer::new` captures `bgp.router_id` at
    /// peer-create time; without this propagation, peers configured
    /// before the router-id was known would emit OPEN messages with
    /// `0.0.0.0` in the BGP Identifier field forever.
    ///
    /// Both inputs — operator config (`router bgp global router-id`)
    /// and the RIB-derived auto-pick (`RibRx::RouterIdUpdate`) — land
    /// here through `refresh_router_id`, which resolves their
    /// precedence (configured wins). Don't call this with a raw input
    /// value from either source; update the source field and refresh.
    ///
    /// Existing established sessions keep using the value they sent
    /// at OPEN; the next OPEN (after a reset) picks up the new one.
    pub fn set_router_id(&mut self, router_id: Ipv4Addr) {
        if self.router_id == router_id {
            return;
        }
        // EVPN RD = `<router-id>:<VNI>` (RFC 8365 §5.1.2). When
        // router-id changes, every locally-originated route is now
        // sitting under a stale RD that no peer (and no future
        // re-originate) will withdraw. Drain the local FDB cache and
        // withdraw under the OLD router-id BEFORE flipping the field,
        // then re-originate under the NEW value below. Skips the
        // withdraw when the old router-id is unspecified (initial
        // 0.0.0.0 → operator value transition — nothing was ever
        // originated under the all-zero RD because
        // `evpn_originate_macip` gates on a valid router-id) or when
        // `advertise_all_vni` is off (we never originated, so nothing
        // to withdraw).
        let old_router_id = self.router_id;
        let advertising = self.advertise_all_vni;
        if advertising && !old_router_id.is_unspecified() {
            if !self.local_fdb.is_empty() {
                let entries: Vec<FdbEntry> = self.local_fdb.values().cloned().collect();
                for entry in entries {
                    self.evpn_withdraw_macip(&entry);
                }
            }
            // Same RD-rebind story for Type-3 (IMET): each VXLAN's
            // outbound IMET is keyed by the local router-id-derived
            // RD; a router-id change requires withdrawing under the
            // old RD and re-originating under the new.
            if !self.local_vxlans.is_empty() {
                let vxlans: Vec<(u32, std::net::IpAddr)> =
                    self.local_vxlans.iter().map(|(k, v)| (*k, *v)).collect();
                for (vni, vtep_local) in vxlans {
                    self.evpn_withdraw_imet(vni, vtep_local);
                }
            }
        }

        self.router_id = router_id;
        for (_, peer) in self.peers.iter_mut_all() {
            peer.router_id = router_id;
        }

        // Re-originate under the new router-id so the cache contents
        // come back into the local-RIB / wire under the right RD.
        // Same gate as the false→true advertise-all-vni replay; the
        // `evpn_originate_macip` body re-checks both conditions, so
        // an unspecified `router_id` here is a safe no-op.
        if advertising && !router_id.is_unspecified() {
            if !self.local_fdb.is_empty() {
                let entries: Vec<FdbEntry> = self.local_fdb.values().cloned().collect();
                for entry in entries {
                    self.evpn_originate_macip(&entry);
                }
            }
            if !self.local_vxlans.is_empty() {
                let vxlans: Vec<(u32, std::net::IpAddr)> =
                    self.local_vxlans.iter().map(|(k, v)| (*k, *v)).collect();
                for (vni, vtep_local) in vxlans {
                    self.evpn_originate_imet(vni, vtep_local);
                }
            }
        }
    }

    /// Recompute the effective BGP Identifier from its two sources —
    /// configured `global router-id` wins, RIB-derived second — and
    /// propagate it. Falls back to 0.0.0.0 only when neither exists
    /// (pre-config cold start, or identifier deleted before any
    /// interface address was learned).
    pub fn refresh_router_id(&mut self) {
        let effective = self
            .router_id_config
            .or(self.rib_router_id)
            .unwrap_or(Ipv4Addr::UNSPECIFIED);
        self.set_router_id(effective);
    }

    /// `RibRx::RouterIdUpdate` handler: remember the RIB-derived
    /// value and refresh. A configured `global router-id` keeps
    /// winning (the update is stored, not applied), so a later
    /// identifier delete can still fall back to it — the IS-IS
    /// `rib_router_id` pattern, replacing the old last-writer-wins
    /// behavior where this push stomped the configured value.
    pub fn rib_router_id_update(&mut self, router_id: Ipv4Addr) {
        self.rib_router_id = (!router_id.is_unspecified()).then_some(router_id);
        self.refresh_router_id();
    }

    pub fn pcallback_add(&mut self, path: &str, cb: PCallback) {
        self.pcallbacks.insert(path.to_string(), cb);
    }

    /// Drive one chunk of a peer's resumable IPv4 sync cursor (Tier
    /// 1a), re-arming the next tick until the dump completes. Fired by
    /// the `sync_tick_rx` arm of the event loop. A tick for a peer that
    /// has dropped Established or already finished its cursor is a
    /// no-op (the cursor is cleared on leaving Established).
    fn drive_sync_v4(&mut self, ident: usize) {
        // Active + Tier 1b backpressure in one mutable borrow: a tick
        // for a dropped/finished peer is a no-op; a peer whose egress is
        // backed up (a slow socket letting UPDATEs pile up) parks the
        // cursor and re-polls shortly — the writer drains during the
        // delay, bounding in-flight memory instead of letting a large
        // dump outrun the peer. The gauge is published by
        // `peer_start_writer`; park/resume is logged once per transition.
        let backed_up = {
            let Some(peer) = self.peers.get_mut_by_idx(ident) else {
                return;
            };
            if !(peer.state.is_established() && peer.sync_v4.is_some()) {
                return;
            }
            let depth = peer.egress_depth.load(std::sync::atomic::Ordering::Relaxed);
            let over = depth >= sync_egress_high_water();
            if let Some(cursor) = peer.sync_v4.as_mut() {
                if over && !cursor.parked {
                    cursor.parked = true;
                    tracing::info!(ident, depth, "bgp: v4 sync parked (egress backpressure)");
                } else if !over && cursor.parked {
                    cursor.parked = false;
                    tracing::info!(ident, depth, "bgp: v4 sync resumed");
                }
            }
            over
        };
        if backed_up {
            let tx = self.sync_tick_tx.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(SYNC_PARK_MS)).await;
                let _ = tx.send(ident);
            });
            return;
        }
        let chunk = super::route::sync_chunk_size().unwrap_or(1000);

        let import_dispatcher = super::vrf::VrfImportDispatcher {
            rib_known_vrfs: &self.rib_known_vrfs,
            vrf_registry: &self.vrf_registry,
        };
        let mut bgp_ref = BgpTop {
            router_id: &self.router_id,
            srv6_ipv6_export: self.srv6_ipv6_export.as_ref(),
            local_rib: &mut self.local_rib,
            shard: &mut self.shard,
            tx: &self.tx,
            rib_client: &self.ctx.rib,
            attr_store: &mut self.attr_store,
            update_groups: &mut self.update_groups,
            interface_addrs: &self.interface_addrs,
            vrf_export: None,
            color_policy: Some(&self.color_policy),
            flex_algo_routes: Some(&self.flex_algo_routes),
            flex_algo_srv6_routes: Some(&self.flex_algo_srv6_routes),
            vrf_import: Some(&import_dispatcher),
            nexthop_cache: Some(&mut self.nexthop_cache),
            vrf_transport_v4: None,
            vrf_transport_v6: None,
            central_label_alloc: self.vrf_label_alloc.as_mut(),
        };
        let Some(peer) = self.peers.get_mut_by_idx(ident) else {
            return;
        };
        let done = super::route::route_sync_v4_chunk(peer, &mut bgp_ref, chunk);
        if !done {
            // Re-arm; unbounded channel, so this never drops.
            let _ = self.sync_tick_tx.send(ident);
        }
    }

    pub fn process_msg(&mut self, msg: Message) {
        match msg {
            Message::Event(ident, event) => {
                // Inbound BGP message tracing (recv direction), gated by
                // the peer's effective (instance ∪ per-neighbor) config.
                if let Some(peer) = self.peers.get_by_idx(ident) {
                    match &event {
                        Event::BGPOpen(..) => {
                            bgp_packet_trace!(peer, PacketKind::Open, Direction::Recv, "recv OPEN")
                        }
                        Event::UpdateMsg(..) => {
                            bgp_packet_trace!(
                                peer,
                                PacketKind::Update,
                                Direction::Recv,
                                "recv UPDATE"
                            )
                        }
                        Event::KeepAliveMsg(..) => {
                            bgp_packet_trace!(
                                peer,
                                PacketKind::Keepalive,
                                Direction::Recv,
                                "recv KEEPALIVE"
                            )
                        }
                        Event::NotifMsg(..) => {
                            bgp_packet_trace!(
                                peer,
                                PacketKind::Notification,
                                Direction::Recv,
                                "recv NOTIFICATION"
                            )
                        }
                        Event::RouteRefreshMsg(..) => {
                            bgp_packet_trace!(
                                peer,
                                PacketKind::RouteRefresh,
                                Direction::Recv,
                                "recv ROUTE-REFRESH"
                            )
                        }
                        _ => {}
                    }
                }
                // Capture peer state before the FSM mutates it so we
                // can detect the "session just ended" transition for
                // dynamic-peer GC below.
                let prev_state = self.peers.get_by_idx(ident).map(|p| p.state);

                // The global v4vpn ingest path uses this dispatcher
                // to fan accepted VPNv4 routes out to every VRF
                // whose `import_rts_v4` matches. Borrows are
                // disjoint from the BgpTop mutable refs below
                // (`rib_known_vrfs` and `vrf_registry` are different
                // fields).
                let import_dispatcher = super::vrf::VrfImportDispatcher {
                    rib_known_vrfs: &self.rib_known_vrfs,
                    vrf_registry: &self.vrf_registry,
                };

                let mut bgp_ref = BgpTop {
                    router_id: &self.router_id,
                    srv6_ipv6_export: self.srv6_ipv6_export.as_ref(),
                    local_rib: &mut self.local_rib,
                    shard: &mut self.shard,
                    tx: &self.tx,
                    rib_client: &self.ctx.rib,
                    attr_store: &mut self.attr_store,
                    update_groups: &mut self.update_groups,
                    interface_addrs: &self.interface_addrs,
                    vrf_export: None,
                    color_policy: Some(&self.color_policy),
                    flex_algo_routes: Some(&self.flex_algo_routes),
                    flex_algo_srv6_routes: Some(&self.flex_algo_srv6_routes),
                    vrf_import: Some(&import_dispatcher),
                    nexthop_cache: Some(&mut self.nexthop_cache),
                    vrf_transport_v4: None,
                    vrf_transport_v6: None,
                    central_label_alloc: self.vrf_label_alloc.as_mut(),
                };

                fsm(
                    &mut bgp_ref,
                    &mut self.peers,
                    ident,
                    event,
                    self.shards.as_ref(),
                );

                // FSM-transition tracing: compare the captured pre-FSM
                // state with the state the FSM left the peer in.
                if let (Some(prev), Some(peer)) = (prev_state, self.peers.get_by_idx(ident))
                    && peer.state != prev
                {
                    bgp_fsm_trace!(
                        peer,
                        from = prev.to_str(),
                        to = peer.state.to_str(),
                        "FSM transition"
                    );
                }

                // Tier 1a: a peer that just got a fresh resumable v4
                // sync cursor (set by `route_sync` inside the FSM) is
                // enqueued here exactly once — the kick needs full
                // `self` for `sync_tick_tx`; the continuation re-arms
                // from `drive_sync_v4`.
                let kick = self
                    .peers
                    .get_mut_by_idx(ident)
                    .and_then(|p| p.sync_v4.as_mut())
                    .filter(|c| c.fresh)
                    .map(|c| c.fresh = false)
                    .is_some();
                if kick {
                    let _ = self.sync_tick_tx.send(ident);
                }

                // A2 step ④: at N>1 the v4-unicast session-up dump runs
                // shard-parallel (`DumpV4`) instead of the main-loop cursor.
                // `route_sync` skipped its v4 block above, so broadcast the
                // dump to the pool here — it needs full `self` for the
                // per-req_id barrier. No-op at N=1 (no pool), where the
                // cursor / legacy `route_sync_ipv4` already ran the dump.
                let became_established = prev_state.is_some_and(|s| !s.is_established())
                    && self
                        .peers
                        .get_by_idx(ident)
                        .is_some_and(|p| p.state.is_established());
                if became_established {
                    self.broadcast_dump_v4(ident);
                }

                self.gc_dynamic_peer_if_session_ended(ident, prev_state);
            }
            Message::Accept(socket, sockaddr) => {
                // If the source IP is claimed by a per-VRF task,
                // hand the connection off there. The receiving task
                // picks up the stream from `BgpVrfMsg::Accept` and
                // continues the FSM. Unclaimed addresses fall
                // through to the existing global-instance accept
                // path — that's how default-VRF peers and the
                // dynamic-neighbor fallback still work.
                let src_ip = sockaddr.ip();
                if let Some(vrf_name) = self.peer_index.get(&src_ip).cloned()
                    && let Some(handle) = self.vrf_registry.get(&vrf_name)
                {
                    let msg = super::vrf::msg::BgpVrfMsg::Accept(socket, sockaddr);
                    if handle.inbox.send(msg).is_err() {
                        tracing::warn!(
                            peer = %src_ip,
                            vrf = %vrf_name,
                            "bgp: VRF task gone while routing inbound accept; dropping connection",
                        );
                    }
                } else {
                    accept(self, socket, sockaddr);
                }
            }
            Message::FlushUpdateGroupIpv4(group_id) => {
                super::update_group::flush_ipv4(
                    &mut self.update_groups,
                    &mut self.peers,
                    &self.tx,
                    &group_id,
                    &self.interface_addrs,
                );
            }
            Message::FlushUpdateGroupIpv6(group_id) => {
                super::update_group::flush_ipv6(
                    &mut self.update_groups,
                    &mut self.peers,
                    &self.tx,
                    &group_id,
                );
            }
            Message::FlushDoneIpv4(group_id, deltas) => {
                super::update_group::flush_done_ipv4(
                    &mut self.update_groups,
                    &mut self.peers,
                    &self.tx,
                    &group_id,
                    deltas,
                    &self.interface_addrs,
                );
            }
            Message::FlushDoneIpv6(group_id, deltas) => {
                super::update_group::flush_done_ipv6(
                    &mut self.update_groups,
                    &mut self.peers,
                    &self.tx,
                    &group_id,
                    deltas,
                );
            }
            Message::BgpLs { add, withdraw } => {
                // Locally-produced BGP-LS (IS-IS producer, RFC 9552). Store
                // into / remove from the `bgp_ls` Loc-RIB as Originated.
                // Re-advertisement to peers is a later phase; this records
                // the topology so `show bgp link-state` reflects it.
                for nlri in &withdraw {
                    super::route::route_bgpls_withdraw_originated(nlri, &mut self.local_rib);
                }
                for (nlri, ls_attr) in add {
                    super::route::route_bgpls_originate(
                        nlri,
                        ls_attr,
                        &mut self.local_rib,
                        &mut self.attr_store,
                    );
                }
            }
            Message::Relisten => {
                // Intercepted in `event_loop` before this dispatcher
                // (the rebind is async, this method is not). Nothing to
                // do if one slips through another path.
            }
        }
    }

    /// GC a `PeerOrigin::Dynamic` peer whose session just ended.
    ///
    /// Triggered after every FSM call in [`Self::process_msg`]. The
    /// condition is `prev_state ∈ {OpenSent, OpenConfirm, Established}`
    /// AND `current_state ∈ {Idle, Active}` — i.e. the peer had a real
    /// TCP session in flight that is now gone. Removing the peer
    /// frees its `listen-limit` slot; the next inbound SYN from the
    /// same source re-materializes via the accept path.
    ///
    /// Static peers are untouched — they stay in `PeerMap` so a config
    /// change or reconnect attempt can revive them.
    fn gc_dynamic_peer_if_session_ended(
        &mut self,
        ident: usize,
        prev_state: Option<super::peer::State>,
    ) {
        use super::peer::State;
        use super::peer_key::PeerOrigin;

        let Some(prev) = prev_state else { return };
        let session_was_alive = matches!(
            prev,
            State::OpenSent | State::OpenConfirm | State::Established
        );
        if !session_was_alive {
            return;
        }
        let Some(peer) = self.peers.get_by_idx(ident) else {
            return;
        };
        if !matches!(peer.origin, PeerOrigin::Dynamic { .. }) {
            return;
        }
        if !matches!(peer.state, State::Idle | State::Active) {
            return;
        }
        let addr = peer.address;
        // Idempotent safety net: the FSM detach already ran when the
        // session left Established (OpenSent/OpenConfirm sessions were
        // never attached), but a GC'd ident must never linger in a
        // group's member set — the slot is reused when the same source
        // re-materializes.
        super::update_group::detach(&mut self.update_groups, &mut self.peers, ident);
        self.peers.remove(&addr);
        self.dynamic_peer_count = self.dynamic_peer_count.saturating_sub(1);
    }

    /// Candidates for the `bgp:neighbor` dynamic completion (`show ip
    /// bgp neighbors <X>`, `clear bgp <afi> neighbor <X>`): every
    /// address-keyed peer plus the configured `interface-neighbor`
    /// names — interface-keyed (unnumbered) peers have no typeable
    /// address, the interface name IS their CLI identity.
    pub fn peer_comps(&self) -> Vec<String> {
        self.peers
            .keys()
            .map(|addr| addr.to_string())
            .chain(self.interface_neighbors.keys().cloned())
            .collect()
    }

    /// Candidates for the `bgp:update-group` dynamic completion (`show
    /// bgp update-group <id>`): the stable IOS-XR-style identifier
    /// ("ipv4-unicast.0", "ipv6-unicast.0", …) of every live
    /// update-group across all AFI/SAFIs — the same IDs the summary
    /// table lists in `show bgp update-group`.
    pub fn update_group_comps(&self) -> Vec<String> {
        super::update_group::id_comps(&self.update_groups)
    }

    /// Reconcile [`Self::vrfs`] (desired set, populated by per-VRF
    /// config callbacks) against [`Self::vrf_registry`] (running
    /// set): spawn the additions, despawn the removals. Called from
    /// `CommitEnd` once per commit.
    /// Register a VRF task's show channel with the config manager so
    /// `show bgp vrf <name> …` is redirected into it. Best-effort —
    /// if the manager mailbox is momentarily full the redirect simply
    /// isn't installed and the command falls back to the global view.
    fn register_vrf_show(&self, name: &str, handle: &super::vrf::BgpVrfHandle) {
        let _ = self
            .manager_tx
            .try_send(crate::config::Message::SubscribeShowVrf {
                key: format!("bgp:vrf:{name}"),
                tx: handle.show_tx.clone(),
            });
    }

    /// Drop the manager's redirect entry for this VRF (despawn / respawn).
    fn unregister_vrf_show(&self, name: &str) {
        let _ = self
            .manager_tx
            .try_send(crate::config::Message::UnsubscribeShowVrf {
                key: format!("bgp:vrf:{name}"),
            });
    }

    fn apply_vrf_commit_diff(&mut self) {
        let (to_spawn, to_despawn) = super::vrf::compute_vrf_diff(&self.vrfs, &self.vrf_registry);

        for name in to_despawn {
            if let Some(handle) = self.vrf_registry.remove(&name) {
                super::vrf::despawn_bgp_vrf(&name, &handle);
                self.unregister_vrf_show(&name);
                // Withdraw the AF_MPLS DecapVrf ILM ahead of
                // returning the label. The netlink delete keys off
                // the label alone so the IlmEntry contents are
                // mostly informational — any non-zero match on
                // `rtype = Bgp` works.
                if let Some(vrf_ifindex) = handle.ilm_decap_ifindex {
                    let entry = crate::rib::inst::IlmEntry {
                        ilm_type: crate::rib::inst::IlmType::DecapVrf {
                            table_id: 0,
                            vrf_ifindex,
                        },
                        nexthop: crate::rib::Nexthop::default(),
                        ..crate::rib::inst::IlmEntry::new(crate::rib::RibType::Bgp)
                    };
                    self.rib_subscriber.send_ilm_del(handle.label, entry);
                }
                // Return the label to the pool so a future VRF
                // can pick it back up. Reclaim before the handle
                // drops — handle drop aborts the task but doesn't
                // know about the allocator.
                let released: Vec<(u32, u32)> = if let Some(alloc) = self.vrf_label_alloc.as_mut() {
                    alloc.free(handle.label);
                    // A shrinking VRF count can free a whole block;
                    // return it to the RIB label manager.
                    alloc.reclaim_free_blocks()
                } else {
                    Vec::new()
                };
                for (start, end) in released {
                    self.rib_subscriber
                        .send_label_block_release("bgp", start, end - start);
                }
                // Withdraw the SRv6 End.DT46 service SID and return its
                // function to the pool (srv6-mode VRFs only).
                if let Some((addr, function)) = handle.srv6_sid {
                    self.rib_subscriber.send_sid_del(addr);
                    self.srv6_sid_pool.release(function);
                }
                // Drop every `peer_index` entry that pointed at
                // this VRF — defensive cleanup against the VRF
                // task exiting before its `UnregisterPeer`
                // messages have been processed.
                self.peer_index.retain(|_, owner| owner != &name);
            }
        }

        for name in to_spawn {
            // `to_spawn` came from a key iteration on `self.vrfs`;
            // the entry is guaranteed to still be present.
            let Some(cfg) = self.vrfs.get(&name).cloned() else {
                continue;
            };
            let kernel = self.rib_known_vrfs.get(&name).cloned();
            // Allocate a fresh MPLS label for this VRF — used in
            // every `BgpGlobalMsg::Export` it emits and bound to an
            // AF_MPLS ILM for PE-side decap. The 20-bit label space
            // is large enough that the `.unwrap_or(0)` fallback
            // effectively never fires; 0 would mean "no label"
            // downstream, which the Export handler already treats
            // as "skip label install" — a safe degradation.
            let label = self.alloc_vrf_label();
            // Allocate the per-VRF End.DT46 service SID for srv6-mode
            // VRFs (None for MPLS-mode, or srv6 before the locator
            // resolves — reconciled on the next locator update).
            let srv6 = self.alloc_vrf_sid(&cfg);
            let handle = super::vrf::spawn_bgp_vrf(
                name.clone(),
                &cfg,
                self.router_id,
                self.asn,
                label,
                kernel,
                &self.rib_subscriber,
                srv6,
                self.vrf_global_tx.clone(),
            );
            self.register_vrf_show(&name, &handle);
            self.vrf_registry.insert(name, handle);
        }
        // Seed every (including newly-spawned) VRF with the current
        // colour-steering snapshot so SRv6 L3VPN routes steer from the
        // first install, not only after the next shadow change.
        self.broadcast_colour_steering();
    }

    /// Called when `RibRx::VrfAdd` for `name` arrives. If a
    /// placeholder per-VRF task is already running for this name,
    /// tear it down and respawn it with the real
    /// `ProtoContext::for_vrf` so the `SO_BINDTODEVICE` binding
    /// kicks in. If the VRF intent hasn't been committed yet, this
    /// is a no-op — the next `apply_vrf_commit_diff` will pick up
    /// the kernel info via [`Self::rib_known_vrfs`].
    fn maybe_respawn_vrf_with_kernel_ctx(&mut self, name: &str) {
        // Nothing to do if there's no BGP intent for this VRF yet.
        let Some(cfg) = self.vrfs.get(name).cloned() else {
            return;
        };
        // Likewise if nothing is currently running for the name —
        // the next `apply_vrf_commit_diff` will spawn it.
        if !self.vrf_registry.contains_key(name) {
            return;
        }
        let Some(kernel) = self.rib_known_vrfs.get(name).cloned() else {
            return;
        };
        // Tear the placeholder-ctx task down before spawning the
        // real one. `despawn_bgp_vrf` sends Shutdown; the handle
        // drop right after aborts the runtime if the loop hasn't
        // yet drained the signal. Preserve the existing label so
        // the respawn stays addressable from any PE that already
        // cached it; the original allocation stays held on the
        // new handle.
        let (preserved_label, preserved_sid) = if let Some(handle) = self.vrf_registry.remove(name)
        {
            super::vrf::despawn_bgp_vrf(name, &handle);
            self.unregister_vrf_show(name);
            // Clear stale `peer_index` entries — the spawned task
            // is about to push fresh RegisterPeer messages.
            self.peer_index.retain(|_, owner| owner != name);
            (handle.label, handle.srv6_sid)
        } else {
            (self.alloc_vrf_label(), None)
        };
        // Preserve the same End.DT46 SID across the respawn so a PE that
        // already learned it stays valid; this respawn is what actually
        // installs the decap, now that the kernel table id is known.
        let srv6 = self.preserved_srv6(preserved_sid);
        let table_id = kernel.table_id;
        let new_handle = super::vrf::spawn_bgp_vrf(
            name.to_string(),
            &cfg,
            self.router_id,
            self.asn,
            preserved_label,
            Some(kernel),
            &self.rib_subscriber,
            srv6,
            self.vrf_global_tx.clone(),
        );
        self.register_vrf_show(name, &new_handle);
        self.vrf_registry.insert(name.to_string(), new_handle);
        bgp_vrf_trace!(
            self.tracing,
            vrf = %name,
            table_id,
            "bgp: respawned per-VRF task with real ProtoContext::for_vrf",
        );
    }

    pub fn process_cm_msg(&mut self, msg: ConfigRequest) {
        match msg.op {
            ConfigOp::CommitStart => {
                //
            }
            ConfigOp::Set | ConfigOp::Delete => {
                let (path, args) = path_from_command(&msg.paths);
                if let Some(f) = self.callbacks.get(&path) {
                    f(self, args, msg.op);
                } else {
                    // Tracing lives under `…/tracing/…` with per-message
                    // -type *containers* (not list keys), so the type is
                    // in the path rather than `args`. A single parser
                    // handles the whole subtree instead of registering a
                    // callback per node; non-tracing paths return None.
                    super::tracing::config_tracing_dispatch(self, &path, args, msg.op);
                }
            }
            ConfigOp::CommitEnd => {
                // Log the per-VRF intent at debug, then diff
                // `self.vrfs` (desired) against `self.vrf_registry`
                // (running), spawn the additions, despawn the
                // removals. Edits to an already-spawned VRF are
                // not detected here — a follow-up will layer
                // cfg-hash comparison on top.
                super::vrf_config::log_commit_diff(self);
                self.apply_vrf_commit_diff();
            }
            ConfigOp::Completion => {
                // `comps_dynamic` carries the dynamic handler name
                // (`bgp:<handler>`) as the first path segment, so dispatch
                // on it: `update-group` wants the group IDs, everything
                // else (`neighbor`, `neighbor-group`) wants peer names.
                let comps = match msg.paths.first().map(|p| p.name.as_str()) {
                    Some("update-group") => self.update_group_comps(),
                    _ => self.peer_comps(),
                };
                msg.resp.unwrap().send(comps).unwrap();
            }
            ConfigOp::Clear => {
                // FRR-style `clear bgp [<afi>] <peer-or-all> [soft [in|out]]`
                // surface (zebra-bgp-clear.yang). The optional segment after
                // `/clear/bgp/` is the AFI (absent = every AFI/SAFI); the
                // remainder selects the operation.
                let (path, mut args) = path_from_command(&msg.paths);
                if let Some((afi_safi, op)) = parse_clear_bgp_path(&path) {
                    let _ = peer::clear_bgp_action(self, &mut args, afi_safi, op);
                }
            }
        }
    }

    async fn process_show_msg(&self, msg: DisplayRequest) {
        let (path, mut args) = path_from_command(&msg.paths);
        // A2 ⑤: at N>1 a peer's v4-unicast Adj-RIB-In lives in the pool
        // shards, not main's Loc-RIB mirror — gather it for received-routes
        // (the sync render callback would read the empty main-side copy).
        if self.shards.is_some() && path == "/show/bgp/neighbors/received-routes" {
            let output = self.show_received_v4_gathered(&mut args, msg.json).await;
            let _ = msg.resp.send(output).await;
            return;
        }
        // Group-task: at gate-on a peer's v4 Adj-RIB-Out lives in its update
        // group's egress task — request it for advertised-routes.
        if super::group_egress::egress_group_task_enabled()
            && path == "/show/bgp/neighbors/advertised-routes"
        {
            let output = self
                .show_advertised_v4_from_group(&mut args, msg.json)
                .await;
            let _ = msg.resp.send(output).await;
            return;
        }
        // A2 ⑥: at gate-on a peer's v4 Adj-RIB-Out lives in its PET, not on
        // the peer — request it from the PET for advertised-routes.
        if super::peer_egress::peer_egress_task_enabled()
            && path == "/show/bgp/neighbors/advertised-routes"
        {
            let output = self.show_advertised_v4_from_pet(&mut args, msg.json).await;
            let _ = msg.resp.send(output).await;
            return;
        }
        // `show [ipv4] summary` at gate-on / N>1: the v4 PfxRcd/PfxSnt live
        // off-main — Adj-RIB-In in the pool shards (N>1), Adj-RIB-Out in the
        // PET (peer-task) or the per-update-group egress task (group-task) — so
        // the synchronous renderer reads the empty main copies and prints 0/0.
        // Gather the v4 counts first, then render. The other AFI sections stay
        // main-owned and read correctly. (`show bgp ipv4 summary` arrives as
        // `/show/bgp/ipv4` + a "summary" token, peeked non-destructively so a
        // non-summary command falls through untouched.)
        let v4_summary: Option<Option<bgp_packet::AfiSafi>> = match path.as_str() {
            "/show/bgp/summary" => Some(None),
            "/show/bgp/ipv4" if args.0.front().is_some_and(|t| t == "summary") => Some(Some(
                bgp_packet::AfiSafi::new(bgp_packet::Afi::Ip, bgp_packet::Safi::Unicast),
            )),
            _ => None,
        };
        if let Some(afi_safi_opt) = v4_summary
            && (self.shards.is_some()
                || super::peer_egress::peer_egress_task_enabled()
                || super::group_egress::egress_group_task_enabled())
        {
            let counts = self.gather_v4_summary_counts().await;
            let output =
                super::show::render_summary_with_counts(self, afi_safi_opt, msg.json, &counts);
            let _ = msg.resp.send(output).await;
            return;
        }
        if let Some(f) = self.show_cb.get(&path) {
            let output = match f(self, args, msg.json) {
                Ok(result) => result,
                Err(e) => format!("Error formatting output: {}", e),
            };
            msg.resp.send(output).await.unwrap();
        }
    }

    /// A2 ⑥ — `show … advertised-routes` at gate-on: request the peer's v4
    /// Adj-RIB-Out from its egress task (it owns `adj_out`) over a oneshot,
    /// then render. Empty when the peer has no task (not established).
    async fn show_advertised_v4_from_pet(
        &self,
        args: &mut crate::config::Args,
        json: bool,
    ) -> String {
        let Some(addr) = args.addr() else {
            return "% No neighbor address specified".to_string();
        };
        let delta_tx = match self.peers.get(&addr) {
            None => return format!("% No such neighbor: {}", addr),
            Some(peer) => peer.pet.as_ref().map(|pet| pet.delta_tx.clone()),
        };
        let table: std::collections::BTreeMap<ipnet::Ipv4Net, Vec<super::route::BgpRib>> =
            match delta_tx {
                Some(tx) => {
                    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
                    let _ =
                        tx.send(super::peer_egress::EgressDeltaV4::DumpAdjOut { reply: reply_tx });
                    reply_rx.await.unwrap_or_default().into_iter().collect()
                }
                None => std::collections::BTreeMap::new(),
            };
        super::show::show_adj_rib_routes(&table, self.router_id, json)
            .unwrap_or_else(|e| format!("Error formatting output: {}", e))
    }

    /// Group-task — `show … advertised-routes` at gate-on: the peer's v4
    /// Adj-RIB-Out is the adj-out of its update group's egress task. Request
    /// the group adj-out over a oneshot, then filter split-horizon — a route
    /// sourced from THIS peer (`rib.ident`) was never advertised to it — and
    /// render. Empty when the peer is in no group (not established).
    async fn show_advertised_v4_from_group(
        &self,
        args: &mut crate::config::Args,
        json: bool,
    ) -> String {
        let Some(addr) = args.addr() else {
            return "% No neighbor address specified".to_string();
        };
        let v4 = bgp_packet::AfiSafi::new(bgp_packet::Afi::Ip, bgp_packet::Safi::Unicast);
        let (peer_ident, gid) = match self.peers.get(&addr) {
            None => return format!("% No such neighbor: {}", addr),
            Some(peer) => (peer.ident, peer.update_group_id.get(&v4).cloned()),
        };
        // Request the group adj-out; drop the task borrow before awaiting.
        let rx = gid
            .and_then(|gid| {
                self.update_groups
                    .get(&v4)
                    .and_then(|af| af.group_by_id(&gid))
            })
            .and_then(|group| group.task.as_ref())
            .map(|task| task.request_adj_out());
        let table: std::collections::BTreeMap<ipnet::Ipv4Net, Vec<super::route::BgpRib>> = match rx
        {
            Some(rx) => rx
                .await
                .unwrap_or_default()
                .into_iter()
                .filter_map(|(prefix, ribs)| {
                    // Split-horizon: exclude paths sourced from this peer.
                    let kept: Vec<_> = ribs.into_iter().filter(|r| r.ident != peer_ident).collect();
                    (!kept.is_empty()).then_some((prefix, kept))
                })
                .collect(),
            None => std::collections::BTreeMap::new(),
        };
        super::show::show_adj_rib_routes(&table, self.router_id, json)
            .unwrap_or_else(|e| format!("Error formatting output: {}", e))
    }

    /// A2 ⑤ — `show … received-routes` at N>1: gather the peer's
    /// IPv4-unicast Adj-RIB-In from every pool shard and render it. The
    /// N=1 sync callback reads `bgp.shard.adj_in` directly, so this is only
    /// the N>1 path.
    async fn show_received_v4_gathered(
        &self,
        args: &mut crate::config::Args,
        json: bool,
    ) -> String {
        let Some(addr) = args.addr() else {
            return "% No neighbor address specified".to_string();
        };
        let Some(ident) = self.peers.get(&addr).map(|p| p.ident) else {
            return format!("% No such neighbor: {}", addr);
        };
        let table = self.gather_adj_in_v4(ident).await;
        super::show::show_adj_rib_routes(&table, self.router_id, json)
            .unwrap_or_else(|e| format!("Error formatting output: {}", e))
    }

    /// Scatter a `DumpAdjInV4` to every pool shard and merge the per-shard
    /// slices of peer `ident`'s v4-unicast Adj-RIB-In. Each prefix lives on
    /// exactly one shard (prefix hash), so the merge is a disjoint union.
    /// Empty at N=1 (no pool).
    async fn gather_adj_in_v4(
        &self,
        ident: usize,
    ) -> std::collections::BTreeMap<ipnet::Ipv4Net, Vec<super::route::BgpRib>> {
        let mut merged = std::collections::BTreeMap::new();
        let Some(pool) = self.shards.as_ref() else {
            return merged;
        };
        let mut rxs = Vec::with_capacity(pool.n());
        for idx in 0..pool.n() {
            let (tx, rx) = tokio::sync::oneshot::channel();
            pool.dispatch(
                idx,
                super::shard::ShardMsg::DumpAdjInV4 { ident, reply: tx },
            );
            rxs.push(rx);
        }
        for rx in rxs {
            if let Ok(slice) = rx.await {
                for (prefix, ribs) in slice {
                    merged.entry(prefix).or_insert_with(Vec::new).extend(ribs);
                }
            }
        }
        merged
    }

    /// Gather per-peer v4-unicast summary prefix counts — `(PfxRcd, PfxSnt)` —
    /// from their off-main owners for `show … summary` at gate-on: PfxRcd from
    /// the pool shards' Adj-RIB-In (N>1), PfxSnt from the PET's Adj-RIB-Out
    /// (peer-task) or the per-update-group egress task's shared Adj-RIB-Out
    /// (group-task, minus the member's split-horizoned own paths). **Counts
    /// only** — no prefixes or attributes cross the channel (lighter than the
    /// received/advertised dumps, which the summary row doesn't need). Keyed by
    /// peer ident, Established v4 peers only; each value is the COMPLETE count,
    /// falling back to the main-side read for the half that is not off-main
    /// (N=1 PfxRcd, gate-off PfxSnt), so the render uses it verbatim.
    async fn gather_v4_summary_counts(&self) -> std::collections::BTreeMap<usize, (u64, u64)> {
        use bgp_packet::{Afi, Safi};
        let v4 = bgp_packet::AfiSafi::new(Afi::Ip, Safi::Unicast);

        // PfxRcd: one count scatter per shard, summed per peer (N>1 only).
        let mut rcvd: std::collections::BTreeMap<usize, u64> = std::collections::BTreeMap::new();
        if let Some(pool) = self.shards.as_ref() {
            let mut rxs = Vec::with_capacity(pool.n());
            for idx in 0..pool.n() {
                let (tx, rx) = tokio::sync::oneshot::channel();
                pool.dispatch(idx, super::shard::ShardMsg::CountAdjInV4All { reply: tx });
                rxs.push(rx);
            }
            for rx in rxs {
                if let Ok(map) = rx.await {
                    for (ident, n) in map {
                        *rcvd.entry(ident).or_default() += n as u64;
                    }
                }
            }
        }

        // PfxSnt at group-gate-on: the v4 Adj-RIB-Out lives in each update
        // group's egress task (shared across members), so query each group's
        // counts ONCE — `(total, {ident → solely-sourced prefixes})` — and
        // derive every member's split-horizoned sent count below. Collect the
        // group reply receivers first so no borrow is held across await.
        let group_on = super::group_egress::egress_group_task_enabled();
        let mut group_counts: std::collections::BTreeMap<
            super::update_group::UpdateGroupId,
            (u64, std::collections::BTreeMap<usize, u64>),
        > = std::collections::BTreeMap::new();
        if group_on {
            let mut seen = std::collections::BTreeSet::new();
            let mut rxs = Vec::new();
            for (_, peer) in self.peers.iter_all() {
                if peer.state != super::peer::State::Established || !peer.config.mp.has(&v4) {
                    continue;
                }
                let Some(gid) = peer.update_group_id.get(&v4).cloned() else {
                    continue;
                };
                if !seen.insert(gid.clone()) {
                    continue;
                }
                if let Some(rx) = self
                    .update_groups
                    .get(&v4)
                    .and_then(|af| af.group_by_id(&gid))
                    .and_then(|g| g.task.as_ref())
                    .map(|t| t.request_count())
                {
                    rxs.push((gid, rx));
                }
            }
            for (gid, rx) in rxs {
                if let Ok((total, sole)) = rx.await {
                    let sole = sole.into_iter().map(|(k, v)| (k, v as u64)).collect();
                    group_counts.insert(gid, (total as u64, sole));
                }
            }
        }

        // Per-peer (rcvd, sent); query the PET for sent when present. Collect
        // the PET reply receivers first so no peer borrow is held across await.
        let mut out: std::collections::BTreeMap<usize, (u64, u64)> =
            std::collections::BTreeMap::new();
        let mut sent_rxs: Vec<(usize, tokio::sync::oneshot::Receiver<usize>)> = Vec::new();
        for (_, peer) in self.peers.iter_all() {
            if peer.state != super::peer::State::Established || !peer.config.mp.has(&v4) {
                continue;
            }
            let rcvd_count = if self.shards.is_some() {
                rcvd.get(&peer.ident).copied().unwrap_or(0)
            } else {
                (self.shard.adj_in_count(peer.ident, Afi::Ip, Safi::Unicast)
                    + peer.adj_in.count(Afi::Ip, Safi::Unicast)) as u64
            };
            // Sent precedence mirrors the egress gate (group → PET → flush).
            if group_on {
                // PfxSnt(member) = group total − the member's solely-sourced
                // prefixes (the ones split-horizon drops from its fan).
                let sent = peer
                    .update_group_id
                    .get(&v4)
                    .and_then(|gid| group_counts.get(gid))
                    .map(|(total, sole)| {
                        total.saturating_sub(sole.get(&peer.ident).copied().unwrap_or(0))
                    })
                    .unwrap_or(0);
                out.insert(peer.ident, (rcvd_count, sent));
            } else if let Some(pet) = peer.pet.as_ref() {
                let (tx, rx) = tokio::sync::oneshot::channel();
                let _ = pet
                    .delta_tx
                    .send(super::peer_egress::EgressDeltaV4::CountAdjOut { reply: tx });
                sent_rxs.push((peer.ident, rx));
                out.insert(peer.ident, (rcvd_count, 0));
            } else {
                let sent = peer.adj_out.count(Afi::Ip, Safi::Unicast) as u64;
                out.insert(peer.ident, (rcvd_count, sent));
            }
        }
        for (ident, rx) in sent_rxs {
            let sent = rx.await.unwrap_or(0) as u64;
            if let Some(slot) = out.get_mut(&ident) {
                slot.1 = sent;
            }
        }
        out
    }

    pub async fn listen(&mut self) -> anyhow::Result<()> {
        // `router bgp port 0` — do not open a server socket at all;
        // sessions can only be dialed actively from this side.
        if self.port == 0 {
            return Ok(());
        }

        let tx = self.tx.clone();
        let tx_clone = tx.clone();

        // Try to bind to both IPv4 and IPv6
        let mut ipv4_bound = false;
        let mut ipv6_bound = false;

        // Check if we can bind to IPv4
        let addr_v4: SocketAddr = format!("0.0.0.0:{}", self.port).parse().unwrap();
        match self.ctx.tcp_listen(addr_v4).await {
            Ok(listener) => {
                ipv4_bound = true;
                use std::os::fd::AsRawFd;
                self.listen_fd_v4 = Some(listener.as_raw_fd());
                let tx_ipv4 = tx.clone();
                self.listen_task = Some(Task::spawn(async move {
                    loop {
                        match listener.accept().await {
                            Ok((socket, sockaddr)) => {
                                // println!("IPv4 connection accepted from: {}", sockaddr);
                                if let Err(e) =
                                    tx_ipv4.send(Message::Accept(socket, sockaddr)).await
                                {
                                    eprintln!("Failed to send Accept message: {}", e);
                                    break;
                                }
                            }
                            Err(e) => {
                                eprintln!("IPv4 accept error: {}", e);
                                // Backoff on accept errors to prevent tight loop on FD exhaustion
                                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                            }
                        }
                    }
                }));
            }
            Err(e) => {
                eprintln!("Failed to bind to IPv4 {}: {}", addr_v4, e);
            }
        }

        // Check if we can bind to IPv6 with IPv6-only socket
        let addr_v6: SocketAddr = format!("[::]:{}", self.port).parse().unwrap();
        match self.ctx.tcp_listen_v6_only(addr_v6).await {
            Ok(listener) => {
                ipv6_bound = true;
                use std::os::fd::AsRawFd;
                self.listen_fd_v6 = Some(listener.as_raw_fd());
                let tx_ipv6 = tx_clone;
                self.listen_task6 = Some(Task::spawn(async move {
                    loop {
                        match listener.accept().await {
                            Ok((socket, sockaddr)) => {
                                if let Err(e) =
                                    tx_ipv6.send(Message::Accept(socket, sockaddr)).await
                                {
                                    eprintln!("Failed to send Accept message: {}", e);
                                    break;
                                }
                            }
                            Err(e) => {
                                eprintln!("IPv6 accept error: {}", e);
                                // Backoff on accept errors to prevent tight loop on FD exhaustion
                                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                            }
                        }
                    }
                }));
            }
            Err(e) => {
                eprintln!("Failed to bind to IPv6 {}: {}", addr_v6, e);
            }
        }

        if !ipv4_bound && !ipv6_bound {
            return Err(anyhow::anyhow!(
                "Failed to bind to any address (both IPv4 and IPv6)"
            ));
        }

        // Reconcile listener-side authentication for every peer that
        // already has a key configured. Necessary because per-leaf
        // callbacks that fired before `listen()` completed observed
        // `listen_fd_v4/v6 = None` and skipped the install — without
        // this sweep a passive peer with MD5/AO never sees a SYN-ACK
        // because the kernel drops the incoming SYN.
        super::config::apply_md5_refresh_all(self);
        super::config::apply_ao_refresh_all(self);
        // Reconcile the listener TCP MSS too: a `tcp-mss` callback that
        // ran before the bind observed `listen_fd_v4/v6 = None` and could
        // not clamp the listener, so a passively-accepted peer would
        // otherwise negotiate the default MSS.
        super::config::apply_tcp_mss_refresh_all(self);
        // And the listener IP_TRANSPARENT union (`ip-transparent`
        // knobs that were configured before the bind), so a
        // TPROXY-steered passive session to a non-local address can be
        // accepted and answered.
        super::config::apply_ip_transparent_refresh_all(self);

        Ok(())
    }

    /// Close the BGP listen sockets and, unless the configured
    /// [`Self::port`] is 0, reopen them on it. Dropping the accept
    /// tasks aborts them, which drops the `TcpListener`s and closes
    /// the fds; the cached raw fds (MD5 / TCP-AO / MSS install
    /// targets) are cleared with them and re-captured — and the
    /// per-peer options re-applied — by `listen()` on the new
    /// sockets. Established sessions are left alone: only the
    /// listener cycles. A `Message::Accept` already queued from an
    /// old listener is still processed — that connection was
    /// accepted while its port was live.
    pub async fn relisten(&mut self) {
        self.listen_task = None;
        self.listen_task6 = None;
        self.listen_fd_v4 = None;
        self.listen_fd_v6 = None;
        self.listen_err = None;
        if self.port == 0 {
            tracing::info!("bgp: listen port set to 0 — BGP listener disabled");
            return;
        }
        tracing::info!(port = self.port, "bgp: reopening BGP listener");
        if let Err(err) = self.listen().await {
            self.listen_err = Some(err);
        }
    }

    /// Recompute every peer's cached `shared_network` against the current
    /// [`Self::connected_subnets`] and re-kick any single-hop eBGP peer
    /// that was held by the connected check and is now on a connected
    /// subnet. Called whenever an interface address appears or disappears
    /// (and once per neighbor at config time). A peer that gains
    /// connectivity while parked in Idle/Active is sent Event::Start so it
    /// dials immediately instead of waiting out the connect-retry backstop;
    /// established sessions are never bounced on a connectivity change.
    pub fn refresh_connected(&mut self) {
        use super::peer::State;
        // Disjoint field borrows: the subnet table is read while the peer
        // map is mutated.
        let subnets = &self.connected_subnets;
        let mut kicks: Vec<usize> = Vec::new();
        for (_key, peer) in self.peers.iter_mut_all() {
            let was = peer.shared_network;
            peer.shared_network = subnets.is_empty() || subnets.covers(peer.address);
            if !was
                && peer.shared_network
                && peer.active
                && peer.connected_check_applies()
                && matches!(peer.state, State::Idle | State::Active)
            {
                kicks.push(peer.ident);
            }
        }
        for ident in kicks {
            let _ = self.tx.try_send(Message::Event(ident, Event::Start));
        }
    }

    /// Re-tag and re-advertise a VRF's locally-originated VPNv4 routes
    /// with the current export route-targets. Called when a VRF's RT
    /// policy is (re-)learned: the per-VRF route export can race ahead of
    /// the `VrfRouteTargets` message (the export reads `rib_known_vrfs` at
    /// emit time), so the `v4vpn` row can be left tagged with no export RT
    /// and the remote PE cannot import it. Re-tagging here closes the
    /// race — both an immediate re-advertise to established peers and any
    /// later `route_sync_vpnv4` dump then carry the RTs. Stale RT
    /// ecommunities are stripped first so a genuine RT reconfig replaces
    /// rather than accumulates. IPv4 only today (VPNv6 re-tag is a
    /// follow-up, consistent with the existing VPNv6-event-driven gaps).
    fn retag_vrf_exports_v4(&mut self, vrf: &str) {
        let Some(rd) = self.vrfs.get(vrf).and_then(|c| c.rd) else {
            return;
        };
        let export_rts = self
            .rib_known_vrfs
            .get(vrf)
            .map(|k| k.export_rts_v4.clone())
            .unwrap_or_default();
        // Snapshot the originated rows (clone to release the `local_rib`
        // borrow before mutating it / `peers` below).
        let rows: Vec<(ipnet::Ipv4Net, super::route::BgpRib)> = self
            .shard
            .v4vpn
            .get(&rd)
            .map(|t| {
                t.0.iter()
                    .filter_map(|(p, ribs)| {
                        ribs.iter()
                            .find(|r| r.ident == super::route::ORIGINATED_PEER)
                            .map(|r| (p, r.clone()))
                    })
                    .collect()
            })
            .unwrap_or_default();
        for (prefix, mut rib) in rows {
            let mut attr = (*rib.attr).clone();
            // Strip existing Route-Target ecoms (RFC 4360 sub-type 0x02)
            // so a genuine RT change replaces; the race case has none.
            if let Some(ref mut ecom) = attr.ecom {
                ecom.0.retain(|v| v.low_type != 0x02);
                if ecom.0.is_empty() {
                    attr.ecom = None;
                }
            }
            let tagged = tag_attr_with_export_rts(attr, &export_rts);
            rib.attr = self.shard.intern(tagged);
            let (_, selected, _) = self.shard.update(Some(rd), prefix, rib);
            let mut top = super::peer::BgpTop {
                router_id: &self.router_id,
                srv6_ipv6_export: self.srv6_ipv6_export.as_ref(),
                local_rib: &mut self.local_rib,
                shard: &mut self.shard,
                tx: &self.tx,
                rib_client: &self.ctx.rib,
                attr_store: &mut self.attr_store,
                update_groups: &mut self.update_groups,
                interface_addrs: &self.interface_addrs,
                color_policy: Some(&self.color_policy),
                flex_algo_routes: Some(&self.flex_algo_routes),
                flex_algo_srv6_routes: Some(&self.flex_algo_srv6_routes),
                vrf_export: None,
                vrf_import: None,
                nexthop_cache: None,
                vrf_transport_v4: None,
                vrf_transport_v6: None,
                central_label_alloc: None,
            };
            super::route::route_advertise_to_peers(
                Some(rd),
                prefix,
                &selected,
                super::route::ORIGINATED_PEER,
                &mut top,
                &mut self.peers,
            );
        }
    }

    /// Push the current colour-steering snapshot (Color→Flex-Algo
    /// bindings + the per-algo SRv6 End-SID shadow) to every per-VRF
    /// task, so a per-VRF SRv6 L3VPN route whose Color binds to a
    /// Flex-Algo gets the algo-N End SID prepended at FIB install. The
    /// per-VRF tasks leak their `RibRx` half, so the shadow can't reach
    /// them by subscription — the global task mirrors it via
    /// `BgpVrfMsg::ColourSteering` instead.
    ///
    /// Called on shadow change (each IS-IS SPF that moves a per-algo
    /// End SID), colour-policy commit, and VRF spawn. No-op when no VRF
    /// is spawned. Sent per-change today; coalescing across a
    /// convergence burst is a follow-up (VRFs are few and shadow churn
    /// is transient).
    pub fn broadcast_colour_steering(&self) {
        if self.vrf_registry.is_empty() {
            return;
        }
        for handle in self.vrf_registry.values() {
            let _ = handle
                .inbox
                .send(super::vrf::msg::BgpVrfMsg::ColourSteering {
                    color_policy: self.color_policy.clone(),
                    srv6_shadow: self.flex_algo_srv6_routes.clone(),
                });
        }
    }

    pub fn process_rib_msg(&mut self, msg: RibRx) {
        // println!("RIB Message {:?}", msg);
        match msg {
            RibRx::LinkAdd(link) => {
                // Maintain the name↔ifindex mirror used by
                // interface-neighbor materialization. Keeps the most
                // recent name for an ifindex; renames are rare but
                // covered by simple insert-replaces-on-collision.
                self.link_index_by_name
                    .insert(link.name.clone(), link.index);
                // An `interface-neighbor` typed before RIB announced
                // this link (config replay at startup races the link
                // dump) materializes its dormant peer now, so the
                // neighbor is listed by `show bgp summary` without
                // waiting for the remote's first RA.
                if self.interface_neighbors.contains_key(&link.name) {
                    super::interface_neighbor::materialize_dormant(self, &link.name);
                }
            }
            RibRx::AddrAdd(addr) => {
                self.interface_addrs.record(&addr);
                self.connected_subnets.record(&addr);
                self.refresh_connected();
                // The connected ifindex keys single-hop BFD sessions (the
                // per-interface XDP helper attaches by it): re-reconcile so a
                // session subscribed before this address was learned picks up
                // its concrete ifindex. Per-neighbor no-op when unchanged.
                super::config::bfd_reconcile_all(self);
            }
            RibRx::AddrDel(addr) => {
                self.interface_addrs.forget(&addr);
                self.connected_subnets.forget(&addr);
                self.refresh_connected();
                super::config::bfd_reconcile_all(self);
            }
            RibRx::RouterIdUpdate(router_id) => {
                // RIB-derived router-id (`system router-id` config
                // or the automatic pick from interface addresses).
                // Without this arm BGP emitted OPEN with 0.0.0.0 in
                // the BGP Identifier whenever the operator hadn't
                // typed `set router bgp global router-id <ip>`.
                self.rib_router_id_update(router_id);
            }
            RibRx::FdbAdd(entry) => {
                // Cache durably so we can replay on `advertise_all_vni`
                // false→true transitions — see `local_fdb` doc.
                self.local_fdb.insert((entry.vni, entry.mac), entry.clone());
                self.evpn_originate_macip(&entry);
            }
            RibRx::FdbDel(entry) => {
                self.local_fdb.remove(&(entry.vni, entry.mac));
                self.evpn_withdraw_macip(&entry);
            }
            RibRx::VxlanAdd { vni, vtep_local } => {
                self.local_vxlans.insert(vni, vtep_local);
                self.evpn_originate_imet(vni, vtep_local);
            }
            RibRx::VxlanDel { vni } => {
                if let Some(vtep_local) = self.local_vxlans.remove(&vni) {
                    self.evpn_withdraw_imet(vni, vtep_local);
                }
            }
            RibRx::VrfAdd {
                name,
                table_id,
                ifindex,
            } => {
                // Preserve any RT cache already populated from a
                // prior `VrfRouteTargets` (e.g. when the operator
                // sets RTs in the same commit as the VRF itself
                // and they happen to arrive before `VrfAdd`).
                let prev_rts = self.rib_known_vrfs.remove(&name);
                let entry = RibKnownVrf {
                    table_id,
                    ifindex,
                    import_rts_v4: prev_rts
                        .as_ref()
                        .map(|p| p.import_rts_v4.clone())
                        .unwrap_or_default(),
                    export_rts_v4: prev_rts
                        .as_ref()
                        .map(|p| p.export_rts_v4.clone())
                        .unwrap_or_default(),
                    import_rts_v6: prev_rts
                        .as_ref()
                        .map(|p| p.import_rts_v6.clone())
                        .unwrap_or_default(),
                    export_rts_v6: prev_rts
                        .as_ref()
                        .map(|p| p.export_rts_v6.clone())
                        .unwrap_or_default(),
                    inter_as_hybrid: self
                        .vrfs
                        .get(&name)
                        .map(|c| c.inter_as_hybrid)
                        .unwrap_or(false),
                };
                self.rib_known_vrfs.insert(name.clone(), entry);
                // If the operator already committed `router bgp vrf
                // <name> ...` and the placeholder context is in
                // place, swap it for a real `for_vrf` now. The
                // placeholder spawn happened before the kernel had
                // assigned `table_id`; without this respawn the
                // `SO_BINDTODEVICE` binding would never fire for
                // that VRF.
                self.maybe_respawn_vrf_with_kernel_ctx(&name);
            }
            RibRx::VrfDel { name } => {
                self.rib_known_vrfs.remove(&name);
                // No despawn here — the VRF could come back, and the
                // per-VRF task carries the YANG intent. If the
                // operator subsequently deletes the BGP VRF block,
                // `apply_vrf_commit_diff` handles teardown.
            }
            RibRx::VrfRouteTargets {
                name,
                ipv4_import_rts,
                ipv4_export_rts,
                ipv6_import_rts,
                ipv6_export_rts,
            } => {
                // Mutate-in-place if a `VrfAdd` already populated
                // the row; otherwise stage the RT cache so a later
                // `VrfAdd` picks it up (defensive against
                // out-of-order delivery — the replay contract puts
                // VrfAdd first, but the active commit path sends
                // them as separate messages and a slow
                // `tokio::select!` could draw the RT message ahead
                // of the VrfAdd).
                let hybrid = self
                    .vrfs
                    .get(&name)
                    .map(|c| c.inter_as_hybrid)
                    .unwrap_or(false);
                let entry = self.rib_known_vrfs.entry(name.clone()).or_default();
                let export_v4_changed = entry.export_rts_v4 != ipv4_export_rts;
                entry.import_rts_v4 = ipv4_import_rts;
                entry.export_rts_v4 = ipv4_export_rts;
                entry.import_rts_v6 = ipv6_import_rts;
                entry.export_rts_v6 = ipv6_export_rts;
                entry.inter_as_hybrid = hybrid;
                // Close the export / RT-learning race: a per-VRF route can
                // be exported into `v4vpn` before this RT policy lands (the
                // export reads `rib_known_vrfs` at emit time), leaving the
                // row with no export RT — unimportable by the remote PE.
                // Re-tag + re-advertise the VRF's originated rows now.
                if export_v4_changed {
                    self.retag_vrf_exports_v4(&name);
                }
            }
            // Redistribute deliveries from RIB — initial walk
            // (chunks ending in `bulk: Eor`) plus steady-state deltas
            // (single-entry `bulk: More`). Stored in `redist_v{4,6}`
            // keyed by `(rtype, prefix)`; consumed at Loc-RIB
            // injection time in a follow-up.
            RibRx::RouteAdd { rtype, routes, .. } => {
                self.route_redist_add(rtype, routes);
            }
            RibRx::RouteDel { rtype, routes, .. } => {
                self.route_redist_del(rtype, routes);
            }
            // IS-IS per-algo routes published via RIB (#697). We
            // shadow only the first nexthop per (algo, prefix); a
            // future ECMP-aware resolver can extend this to walk the
            // full set.
            RibRx::FlexAlgoRouteAdd { route } => {
                if let Some(nh) = route.nexthops.into_iter().next() {
                    self.flex_algo_routes
                        .entry(route.algo)
                        .or_default()
                        .insert(route.prefix, nh);
                } else {
                    // Defensive: a FlexAlgoRoute with zero nexthops
                    // is meaningless; treat it as a delete.
                    if let Some(table) = self.flex_algo_routes.get_mut(&route.algo) {
                        table.remove(&route.prefix);
                    }
                }
            }
            RibRx::FlexAlgoRouteDel { algo, prefix } => {
                let became_empty = if let Some(table) = self.flex_algo_routes.get_mut(&algo) {
                    table.remove(&prefix);
                    table.iter().next().is_none()
                } else {
                    false
                };
                if became_empty {
                    self.flex_algo_routes.remove(&algo);
                }
            }
            RibRx::FlexAlgoSrv6RouteAdd { route } => {
                self.flex_algo_srv6_routes
                    .insert(route.algo, route.prefix, route.end_sid);
                // Mirror the updated shadow to per-VRF tasks for L3VPN
                // colour steering.
                self.broadcast_colour_steering();
            }
            RibRx::FlexAlgoSrv6RouteDel { algo, prefix } => {
                self.flex_algo_srv6_routes.remove(algo, prefix);
                self.broadcast_colour_steering();
            }
            RibRx::NexthopUpdate { nh, resolution } => {
                self.nht_handle_update(nh, &resolution);
            }
            RibRx::LabelBlock { start, size } => {
                self.label_block_arrived(start, size);
            }
            _ => {
                //
            }
        }
    }

    /// The RIB label manager granted BGP a dynamic block `[start,
    /// start+size)`. Bind the per-VRF allocator to it, then reconcile
    /// any VRF that spawned label-less before the block arrived:
    /// give it a real label and respawn so it stamps exports and
    /// installs its decap ILM.
    fn label_block_arrived(&mut self, start: u32, size: u32) {
        self.vrf_label_request_pending = false;
        match self.vrf_label_alloc.as_mut() {
            // First grant binds the allocator; later grants extend it
            // (on-demand growth past the initial block).
            Some(alloc) => alloc.extend(start, start + size),
            None => {
                self.vrf_label_alloc =
                    Some(super::vrf::VrfLabelAllocator::bounded(start, start + size))
            }
        }
        bgp_label_trace!(
            self.tracing,
            start,
            size,
            "bgp: dynamic MPLS label block granted"
        );

        let unlabelled: Vec<String> = self
            .vrf_registry
            .iter()
            .filter(|(_, h)| h.label == 0)
            .map(|(name, _)| name.clone())
            .collect();
        for name in unlabelled {
            self.relabel_vrf(&name);
        }
        // The reconcile may have outgrown this block too (a large VRF
        // fleet). If any VRF is still label-less, ask for another.
        if self.vrf_registry.values().any(|h| h.label == 0) {
            self.request_label_block();
        }
    }

    /// Send a `LabelBlockRequest` to the RIB label manager unless one is
    /// already outstanding. Dedup keeps a burst of label-less VRFs from
    /// each requesting a block.
    pub(super) fn request_label_block(&mut self) {
        if self.vrf_label_request_pending {
            return;
        }
        self.vrf_label_request_pending = true;
        self.rib_subscriber
            .send_label_block_request("bgp", VRF_LABEL_BLOCK_SIZE);
    }

    /// Allocate a per-VRF label from the dynamic block(s). When no block
    /// is bound yet, or every block is spent, request (more) space and
    /// return 0 — the VRF spawns label-less and is reconciled by
    /// `label_block_arrived` once the grant lands.
    fn alloc_vrf_label(&mut self) -> u32 {
        if let Some(label) = self.vrf_label_alloc.as_mut().and_then(|a| a.alloc()) {
            return label;
        }
        self.request_label_block();
        0
    }

    /// Respawn `name`'s per-VRF task with a freshly-allocated label.
    /// Used to fix up a VRF that spawned with label 0 (the block hadn't
    /// arrived yet). Mirrors [`Self::maybe_respawn_vrf_with_kernel_ctx`]
    /// but swaps the label rather than the `ProtoContext`.
    fn relabel_vrf(&mut self, name: &str) {
        let Some(cfg) = self.vrfs.get(name).cloned() else {
            return;
        };
        let Some(label) = self.vrf_label_alloc.as_mut().and_then(|a| a.alloc()) else {
            return;
        };
        let kernel = self.rib_known_vrfs.get(name).cloned();
        let preserved_sid = if let Some(handle) = self.vrf_registry.remove(name) {
            super::vrf::despawn_bgp_vrf(name, &handle);
            self.unregister_vrf_show(name);
            self.peer_index.retain(|_, owner| owner != name);
            handle.srv6_sid
        } else {
            None
        };
        // A relabel swaps only the MPLS label; the End.DT46 SID (for an
        // srv6-mode VRF) is preserved and re-installed unchanged.
        let srv6 = self.preserved_srv6(preserved_sid);
        let new_handle = super::vrf::spawn_bgp_vrf(
            name.to_string(),
            &cfg,
            self.router_id,
            self.asn,
            label,
            kernel,
            &self.rib_subscriber,
            srv6,
            self.vrf_global_tx.clone(),
        );
        self.register_vrf_show(name, &new_handle);
        self.vrf_registry.insert(name.to_string(), new_handle);
        bgp_label_trace!(self.tracing, vrf = %name, label, "bgp: assigned dynamic label to VRF");
    }

    /// Apply a NHT resolution change: refresh the cached resolution
    /// (reachability + resolved transport) and re-evaluate every
    /// dependent prefix.
    fn nht_handle_update(
        &mut self,
        nh: std::net::IpAddr,
        resolution: &crate::rib::nht::NexthopResolution,
    ) {
        use super::nht::CacheChange;
        let reachable = resolution.reachable;
        match self.nexthop_cache.update(nh, resolution) {
            CacheChange::Unchanged => {}
            // Gate flipped → full re-eval: best-path, advertise, install.
            CacheChange::Reachability(deps) => {
                // At N>1, batch the v4-unicast re-evals per shard — every
                // one of this next-hop's dependent prefixes hashing to a
                // shard rides a single message instead of one dispatch
                // each (RouteBatch for the release path; a first-seen
                // next-hop can release a whole table's worth of held
                // routes at once). Non-v4 deps (v6 / LU / VPN / EVPN /
                // SR-Policy) stay on the inline sync-shard path.
                let mut inline: Vec<super::nht::NhtDep> = Vec::new();
                if let Some(pool) = self.shards.as_ref() {
                    let mut per_shard: Vec<Vec<bgp_packet::Ipv4Nlri>> = vec![Vec::new(); pool.n()];
                    for dep in deps {
                        match dep {
                            super::nht::NhtDep::V4(p) => {
                                let idx = pool.shard_of(std::net::IpAddr::V4(p.addr()));
                                per_shard[idx].push(bgp_packet::Ipv4Nlri { id: 0, prefix: p });
                            }
                            other => inline.push(other),
                        }
                    }
                    for (idx, nlris) in per_shard.into_iter().enumerate() {
                        if !nlris.is_empty() {
                            pool.dispatch(
                                idx,
                                super::shard::ShardMsg::NexthopReachableBatchV4 {
                                    nlris,
                                    nh,
                                    reachable,
                                },
                            );
                        }
                    }
                } else {
                    inline.extend(deps);
                }
                for dep in inline {
                    self.nht_reeval_dep(nh, reachable, dep);
                }
            }
            // PE still reachable but its transport rerouted → only the
            // fully-resolved VPN FIB entry is stale; re-install it
            // without re-advertising (best-path is unchanged).
            CacheChange::Transport(deps) => {
                for dep in deps {
                    self.nht_reinstall_transport(nh, dep);
                }
            }
        }
    }

    /// Re-install the dataplane for a VPN dep after its PE next-hop's
    /// transport rerouted (reachability unchanged). Re-dispatches the
    /// per-VRF import with the freshly-resolved transport, so each
    /// importing VRF re-programs its `{transport,service}`-labelled FIB
    /// entry. Unicast deps are a no-op: BGP installs the BGP next-hop
    /// and the RIB recursively re-resolves it, so there's nothing here
    /// to refresh.
    fn nht_reinstall_transport(&mut self, nh: std::net::IpAddr, dep: super::nht::NhtDep) {
        use super::nht::NhtDep;
        let dispatcher = super::vrf::VrfImportDispatcher {
            rib_known_vrfs: &self.rib_known_vrfs,
            vrf_registry: &self.vrf_registry,
        };
        let transport = self.nexthop_cache.transport_for(nh);
        match dep {
            NhtDep::V4vpn(rd, p) => {
                let selected = self.shard.select_best_path_vpn(&rd, p);
                if let Some(winner) = selected.first() {
                    let label = winner.label.map(|l| l.label).unwrap_or(0);
                    super::vrf::dispatch_import_v4(
                        &dispatcher,
                        rd,
                        p,
                        &winner.attr,
                        label,
                        transport,
                        None,
                    );
                }
                // Inter-AS Option B transit: re-program the swap ILM for our
                // advertised local label toward the rerouted transport.
                super::route::reconcile_swap_ilm(
                    &self.ctx.rib,
                    Some(&self.nexthop_cache),
                    selected.first(),
                );
            }
            NhtDep::V6vpn(rd, p) => {
                let selected = self.shard.select_best_path_vpn_v6(&rd, p);
                if let Some(winner) = selected.first() {
                    let label = winner.label.map(|l| l.label).unwrap_or(0);
                    super::vrf::dispatch_import_v6(
                        &dispatcher,
                        rd,
                        p,
                        &winner.attr,
                        label,
                        transport,
                        None,
                    );
                }
            }
            NhtDep::Evpn(rd, prefix) => {
                // EVPN Type-5: the imported IP prefix's underlay
                // rerouted; re-dispatch the VRF import with the fresh
                // transport. Reuses the VPNv4/v6 dispatch.
                let selected = self.local_rib.select_best_path_evpn(&rd, &prefix);
                if let Some(winner) = selected.last()
                    && let bgp_packet::EvpnPrefix::IpPrefix { prefix: net, .. } = &prefix
                {
                    let label = winner.label.map(|l| l.label).unwrap_or(0);
                    match net {
                        ipnet::IpNet::V4(p) => super::vrf::dispatch_import_v4(
                            &dispatcher,
                            rd,
                            *p,
                            &winner.attr,
                            label,
                            transport,
                            None,
                        ),
                        ipnet::IpNet::V6(p) => super::vrf::dispatch_import_v6(
                            &dispatcher,
                            rd,
                            *p,
                            &winner.attr,
                            label,
                            transport,
                            None,
                        ),
                    }
                }
            }
            // Labeled-Unicast: the next-hop's transport rerouted but it's
            // still reachable; re-install the FIB label-push entry with
            // the fresh transport. No re-advertise (best-path unchanged).
            NhtDep::V4lu(p) => {
                let selected = self.shard.select_best_path_v4lu(p);
                super::route::fib_install_labelv4(
                    &self.ctx.rib,
                    Some(&self.nexthop_cache),
                    p,
                    &selected,
                );
            }
            NhtDep::V6lu(p) => {
                let selected = self.shard.select_best_path_v6lu(p);
                super::route::fib_install_labelv6(
                    &self.ctx.rib,
                    Some(&self.nexthop_cache),
                    p,
                    &selected,
                );
            }
            // SR Policy: the endpoint's transport rerouted; re-install
            // the Binding-SID ILM toward the fresh next-hop.
            NhtDep::SrPolicy { color, endpoint } => {
                super::route::sr_policy_reconcile_mpls(
                    &self.ctx.rib,
                    &self.nexthop_cache,
                    &mut self.local_rib.sr_policy,
                    color,
                    endpoint,
                );
            }
            NhtDep::V4(_) | NhtDep::V6(_) => {}
        }
    }

    /// Re-evaluate one dependent prefix after its next-hop's
    /// reachability flipped: refresh the candidates' gate flag, re-run
    /// best-path, then re-advertise (and, for unicast, reconcile the
    /// FIB). For VPNv4/v6 deps this also (re-)dispatches the per-VRF
    /// import with the resolved transport — register-then-gate means an
    /// imported route only becomes best-path here, so this is where the
    /// VRF dataplane install is triggered.
    fn nht_reeval_dep(&mut self, nh: std::net::IpAddr, reachable: bool, dep: super::nht::NhtDep) {
        use super::nht::NhtDep;
        // Refresh gate flags + re-select (mutates `local_rib`). At N>1 the
        // v4-unicast deps are batched per shard by the caller
        // (`nht_handle_update`), so here `dep` is always sync-shard-owned
        // (v6 / LU / VPN / EVPN / SR-Policy) at N>1, or any dep at N=1.
        let selected = match &dep {
            NhtDep::V4(p) => {
                self.shard.v4.set_nexthop_reachable(*p, nh, reachable);
                self.shard.v4.select_best_path(*p)
            }
            NhtDep::V6(p) => {
                self.shard.v6.set_nexthop_reachable(*p, nh, reachable);
                self.shard.v6.select_best_path(*p)
            }
            NhtDep::V4lu(p) => {
                self.shard.v4lu.set_nexthop_reachable(*p, nh, reachable);
                self.shard.v4lu.select_best_path(*p)
            }
            NhtDep::V6lu(p) => {
                self.shard.v6lu.set_nexthop_reachable(*p, nh, reachable);
                self.shard.v6lu.select_best_path(*p)
            }
            NhtDep::V4vpn(rd, p) => {
                self.shard
                    .v4vpn
                    .entry(*rd)
                    .or_default()
                    .set_nexthop_reachable(*p, nh, reachable);
                self.shard.select_best_path_vpn(rd, *p)
            }
            NhtDep::V6vpn(rd, p) => {
                self.shard
                    .v6vpn
                    .entry(*rd)
                    .or_default()
                    .set_nexthop_reachable(*p, nh, reachable);
                self.shard.select_best_path_vpn_v6(rd, *p)
            }
            // EVPN Type-5 best-path isn't gated on next-hop reachability
            // (the VRF FIB install is gated by transport availability in
            // the dispatch below), so just re-select.
            NhtDep::Evpn(rd, prefix) => self.local_rib.select_best_path_evpn(rd, prefix),
            // SR Policy has no BGP best-path / advertise step; its ILM is
            // reconciled in the dispatch below, not via `selected`.
            NhtDep::SrPolicy { .. } => Vec::new(),
        };

        let mut top = super::peer::BgpTop {
            router_id: &self.router_id,
            srv6_ipv6_export: self.srv6_ipv6_export.as_ref(),
            local_rib: &mut self.local_rib,
            shard: &mut self.shard,
            tx: &self.tx,
            rib_client: &self.ctx.rib,
            attr_store: &mut self.attr_store,
            update_groups: &mut self.update_groups,
            interface_addrs: &self.interface_addrs,
            color_policy: Some(&self.color_policy),
            flex_algo_routes: Some(&self.flex_algo_routes),
            flex_algo_srv6_routes: Some(&self.flex_algo_srv6_routes),
            vrf_export: None,
            vrf_import: None,
            nexthop_cache: None,
            vrf_transport_v4: None,
            vrf_transport_v6: None,
            central_label_alloc: None,
        };
        match &dep {
            NhtDep::V4(p) => {
                super::route::fib_install_v4(&top, *p, &selected);
                super::route::route_advertise_to_peers(
                    None,
                    *p,
                    &selected,
                    0,
                    &mut top,
                    &mut self.peers,
                );
            }
            NhtDep::V6(p) => {
                super::route::fib_install_v6(&top, *p, &selected);
                super::route::route_advertise_to_peers_v6(*p, &selected, &mut top, &mut self.peers);
            }
            // Labeled-Unicast reachability flip: re-install the FIB
            // label-push entry (or withdraw) and re-advertise. The cache
            // is passed directly (not via `top`, whose `nexthop_cache` is
            // `None`) — `top`'s borrows don't include it.
            NhtDep::V4lu(p) => {
                super::route::fib_install_labelv4(
                    top.rib_client,
                    Some(&self.nexthop_cache),
                    *p,
                    &selected,
                );
                super::route::route_advertise_to_peers_labelv4(
                    *p,
                    &selected,
                    &mut top,
                    &mut self.peers,
                );
            }
            NhtDep::V6lu(p) => {
                super::route::fib_install_labelv6(
                    top.rib_client,
                    Some(&self.nexthop_cache),
                    *p,
                    &selected,
                );
                super::route::route_advertise_to_peers_labelv6(
                    *p,
                    &selected,
                    &mut top,
                    &mut self.peers,
                );
            }
            NhtDep::V4vpn(rd, p) => {
                super::route::route_advertise_to_peers(
                    Some(*rd),
                    *p,
                    &selected,
                    0,
                    &mut top,
                    &mut self.peers,
                );
                // Register-then-gate: an imported VPNv4 route only
                // becomes (or stops being) best-path here, after the PE
                // next-hop resolves asynchronously. (Re-)dispatch the
                // VRF import with the now-resolved transport, or flood a
                // withdraw if the PE went unreachable. `top`'s borrows
                // are released after the advertise above.
                let dispatcher = super::vrf::VrfImportDispatcher {
                    rib_known_vrfs: &self.rib_known_vrfs,
                    vrf_registry: &self.vrf_registry,
                };
                if reachable && let Some(winner) = selected.first() {
                    let label = winner.label.map(|l| l.label).unwrap_or(0);
                    let transport = self.nexthop_cache.transport_for(nh);
                    super::vrf::dispatch_import_v4(
                        &dispatcher,
                        *rd,
                        *p,
                        &winner.attr,
                        label,
                        transport,
                        None,
                    );
                } else if let Some(attr) =
                    self.shard.v4vpn.get(rd).and_then(|t| t.candidate_attr(*p))
                {
                    super::vrf::dispatch_withdraw_import_v4(&dispatcher, *rd, *p, &attr, None);
                }
                // Inter-AS Option B transit: (re-)install the swap ILM for
                // our advertised local label now that the next-hop's
                // transport resolved, or tear it down if it went away.
                super::route::reconcile_swap_ilm(
                    &self.ctx.rib,
                    Some(&self.nexthop_cache),
                    selected.first(),
                );
            }
            NhtDep::V6vpn(rd, p) => {
                super::route::route_advertise_to_peers_vpnv6(
                    *rd,
                    *p,
                    &selected,
                    &mut top,
                    &mut self.peers,
                );
                // VPNv6 counterpart of the V4vpn arm: (re-)dispatch the
                // VRF import with the resolved transport once the PE
                // next-hop resolves, or withdraw on PE failure.
                let dispatcher = super::vrf::VrfImportDispatcher {
                    rib_known_vrfs: &self.rib_known_vrfs,
                    vrf_registry: &self.vrf_registry,
                };
                if reachable && let Some(winner) = selected.first() {
                    let label = winner.label.map(|l| l.label).unwrap_or(0);
                    let transport = self.nexthop_cache.transport_for(nh);
                    super::vrf::dispatch_import_v6(
                        &dispatcher,
                        *rd,
                        *p,
                        &winner.attr,
                        label,
                        transport,
                        None,
                    );
                } else if let Some(attr) =
                    self.shard.v6vpn.get(rd).and_then(|t| t.candidate_attr(*p))
                {
                    super::vrf::dispatch_withdraw_import_v6(&dispatcher, *rd, *p, &attr, None);
                }
            }
            NhtDep::Evpn(rd, prefix) => {
                // EVPN Type-5 analog: advertise the re-selected best-path
                // to peers, then (re-)dispatch the VRF import with the
                // resolved transport, or withdraw if the PE went away.
                if !selected.is_empty() {
                    super::route::route_advertise_evpn_to_peers(
                        *rd,
                        prefix.clone(),
                        &selected,
                        &mut top,
                        &mut self.peers,
                    );
                }
                let dispatcher = super::vrf::VrfImportDispatcher {
                    rib_known_vrfs: &self.rib_known_vrfs,
                    vrf_registry: &self.vrf_registry,
                };
                if let bgp_packet::EvpnPrefix::IpPrefix { prefix: net, .. } = prefix
                    && let Some(winner) = selected.last()
                {
                    let label = winner.label.map(|l| l.label).unwrap_or(0);
                    let transport = self.nexthop_cache.transport_for(nh);
                    match net {
                        ipnet::IpNet::V4(p) => {
                            if reachable {
                                super::vrf::dispatch_import_v4(
                                    &dispatcher,
                                    *rd,
                                    *p,
                                    &winner.attr,
                                    label,
                                    transport,
                                    None,
                                );
                            } else {
                                super::vrf::dispatch_withdraw_import_v4(
                                    &dispatcher,
                                    *rd,
                                    *p,
                                    &winner.attr,
                                    None,
                                );
                            }
                        }
                        ipnet::IpNet::V6(p) => {
                            if reachable {
                                super::vrf::dispatch_import_v6(
                                    &dispatcher,
                                    *rd,
                                    *p,
                                    &winner.attr,
                                    label,
                                    transport,
                                    None,
                                );
                            } else {
                                super::vrf::dispatch_withdraw_import_v6(
                                    &dispatcher,
                                    *rd,
                                    *p,
                                    &winner.attr,
                                    None,
                                );
                            }
                        }
                    }
                }
            }
            // SR Policy reachability flip: (re)install or tear down the
            // Binding-SID ILM via the endpoint's NHT resolution.
            NhtDep::SrPolicy { color, endpoint } => {
                super::route::sr_policy_reconcile_mpls(
                    top.rib_client,
                    &self.nexthop_cache,
                    &mut top.local_rib.sr_policy,
                    *color,
                    *endpoint,
                );
            }
        }
    }

    fn route_redist_add(&mut self, rtype: crate::rib::RibType, batch: crate::rib::RouteBatch) {
        use bgp_packet::{Afi, AfiSafi, Safi};
        let source = Self::redist_source(rtype);
        match batch {
            crate::rib::RouteBatch::V4(entries) => {
                for e in entries {
                    let prefix = e.prefix;
                    let rib_metric = e.metric;
                    self.redist_v4.insert((rtype, prefix), e);
                    let Some(source) = source else { continue };
                    // One RIB subscription (per AFI) can feed several
                    // configured families: inject into each that has this
                    // (afi-safi, source) redistribute row. Per-row metric
                    // override beats the RIB cost; else RIB cost → MED.
                    let uni = AfiSafi::new(Afi::Ip, Safi::Unicast);
                    if self.redistribute.contains_key(&(uni, source)) {
                        let metric = self
                            .redist_metric_override(uni, source)
                            .unwrap_or(rib_metric);
                        self.route_redist_inject(rtype, prefix, metric);
                    }
                    let lu = AfiSafi::new(Afi::Ip, Safi::MplsLabel);
                    if self.redistribute.contains_key(&(lu, source)) {
                        let metric = self
                            .redist_metric_override(lu, source)
                            .unwrap_or(rib_metric);
                        self.route_redist_inject_labelv4(rtype, prefix, metric);
                    }
                }
            }
            crate::rib::RouteBatch::V6(entries) => {
                for e in entries {
                    let prefix = e.prefix;
                    let rib_metric = e.metric;
                    self.redist_v6.insert((rtype, prefix), e);
                    let Some(source) = source else { continue };
                    // Plain IPv6 unicast. With `segment-routing srv6
                    // ipv6-unicast` on, `route_redist_inject_v6` stamps the
                    // End.DT6 Prefix-SID at origination.
                    let uni = AfiSafi::new(Afi::Ip6, Safi::Unicast);
                    if self.redistribute.contains_key(&(uni, source)) {
                        let metric = self
                            .redist_metric_override(uni, source)
                            .unwrap_or(rib_metric);
                        self.route_redist_inject_v6(rtype, prefix, metric);
                    }
                    // IPv6 labeled-unicast.
                    let lu = AfiSafi::new(Afi::Ip6, Safi::MplsLabel);
                    if self.redistribute.contains_key(&(lu, source)) {
                        let metric = self
                            .redist_metric_override(lu, source)
                            .unwrap_or(rib_metric);
                        self.route_redist_inject_labelv6(rtype, prefix, metric);
                    }
                }
            }
        }
    }

    fn route_redist_del(&mut self, rtype: crate::rib::RibType, batch: crate::rib::RouteBatch) {
        match batch {
            crate::rib::RouteBatch::V4(entries) => {
                for e in entries {
                    let prefix = e.prefix;
                    self.redist_v4.remove(&(rtype, prefix));
                    // Withdraw from both v4 targets unconditionally: the
                    // config row may already be gone (this RouteDel can be
                    // the RIB's response to a RedistDel), and a withdraw of
                    // a prefix never injected is a harmless no-op + an
                    // ignored peer withdraw. Mirrors the v4-unicast path.
                    self.route_redist_withdraw(rtype, prefix);
                    self.route_redist_withdraw_labelv4(rtype, prefix);
                }
            }
            crate::rib::RouteBatch::V6(entries) => {
                for e in entries {
                    let prefix = e.prefix;
                    self.redist_v6.remove(&(rtype, prefix));
                    // Withdraw from both v6 targets unconditionally (the
                    // config row may already be gone), mirroring the v4 path.
                    self.route_redist_withdraw_v6(rtype, prefix);
                    self.route_redist_withdraw_labelv6(rtype, prefix);
                }
            }
        }
    }

    /// Map a RIB route type to the `BgpRedistSource` it redistributes as,
    /// or `None` for RIB types BGP doesn't redistribute (e.g. Kernel,
    /// Bgp itself).
    fn redist_source(rtype: crate::rib::RibType) -> Option<crate::bgp::config::BgpRedistSource> {
        use crate::bgp::config::BgpRedistSource;
        match rtype {
            crate::rib::RibType::Connected => Some(BgpRedistSource::Connected),
            crate::rib::RibType::Static => Some(BgpRedistSource::Static),
            crate::rib::RibType::Isis => Some(BgpRedistSource::Isis),
            crate::rib::RibType::Ospf => Some(BgpRedistSource::Ospf),
            _ => None,
        }
    }

    /// The static `metric` override for an `(afi-safi, source)`
    /// redistribute row, or `None` (use the RIB cost as MED).
    fn redist_metric_override(
        &self,
        afi_safi: bgp_packet::AfiSafi,
        source: crate::bgp::config::BgpRedistSource,
    ) -> Option<u32> {
        self.redistribute
            .get(&(afi_safi, source))
            .and_then(|c| c.metric)
    }

    /// Replicate a peer's resolved **inbound** policy into the shard(s)
    /// so the shard applies the operator's real route-map / prefix-list in
    /// `compute_policy` (RIB sharding — closes the Phase C default-permit
    /// placeholder). Broadcast to every pool shard (a peer's prefixes hash
    /// across all of them) at N>1, or applied to the synchronous shard at
    /// N=1. Called on every inbound `PolicyRx` resolve, before the soft-in
    /// replay so replayed Adj-RIB-In routes see the new policy.
    pub(super) fn shard_replace_in_policy(&mut self, ident: usize) {
        let Some(peer) = self.peers.get_by_idx(ident) else {
            return;
        };
        let snap = std::sync::Arc::new(super::shard::InPolicy {
            prefix_set: peer.prefix_set.input.clone(),
            policy_list: peer.policy_list.input.clone(),
        });
        if let Some(pool) = self.shards.as_ref() {
            pool.broadcast(|| super::shard::ShardMsg::PolicyReplace {
                ident,
                policy: Some(snap.clone()),
            });
            return;
        }
        self.shard.set_in_policy(ident, Some(snap));
    }

    pub async fn process_policy_msg(&mut self, msg: policy::PolicyRx) {
        // Two responsibilities per message: refresh the per-peer policy
        // snapshot, then trigger a soft-reconfiguration so already-
        // received Adj-RIB-In or already-advertised Loc-RIB entries
        // get re-evaluated against the new policy. Without the second
        // step a prefix-set / policy-list edit only affects routes
        // that arrive *after* the edit.
        match msg {
            policy::PolicyRx::PrefixSet {
                name: _,
                ident,
                policy_type,
                prefix_set,
            } => {
                let Some(peer) = self.peers.get_mut_by_idx(ident) else {
                    return;
                };
                let direction = match policy_type {
                    policy::PolicyType::PrefixSetIn => InOut::Input,
                    policy::PolicyType::PrefixSetOut => InOut::Output,
                    _ => return,
                };
                let config = peer.prefix_set.get_mut(&direction);
                config.prefix_set = prefix_set;
                // Keep the cached outbound-policy snapshot (carried by
                // every `SyncCtx`) current before the soft-out re-advertise
                // reads it. Inbound resolves replicate via PolicyReplace.
                if direction == InOut::Output {
                    peer.rebuild_out_policy();
                }

                match direction {
                    InOut::Input => {
                        // Push the new inbound policy into the shard(s)
                        // before replaying Adj-RIB-In, so the replay
                        // re-evaluates against it (single-relay FIFO keeps
                        // PolicyReplace ahead of the replayed routes).
                        self.shard_replace_in_policy(ident);
                        super::peer::apply_soft_in_peer(self, ident);
                    }
                    InOut::Output => super::peer::apply_soft_out_peer(self, ident),
                }
            }
            policy::PolicyRx::PolicyList {
                name,
                ident,
                policy_type,
                policy_list,
            } => {
                // Table-map bindings aren't peer-scoped — `ident`
                // encodes the AFI/SAFI — so route them before the
                // peer lookup. The refresh step is a FIB resync, not
                // a soft-reconfiguration: table-map never changes
                // best-path or what peers are advertised.
                if policy_type == policy::PolicyType::TableMap {
                    let Some(afi_safi) = super::config::table_map_ident_decode(ident) else {
                        return;
                    };
                    let Some(tm) = self.local_rib.table_map.get_mut(&afi_safi) else {
                        return;
                    };
                    // Drop a stale in-flight push from a name the
                    // operator has since rebound away from.
                    if tm.name.as_deref() != Some(name.as_str()) {
                        return;
                    }
                    tm.policy = policy_list;
                    self.table_map_resync(afi_safi);
                    return;
                }
                let Some(peer) = self.peers.get_mut_by_idx(ident) else {
                    return;
                };
                let direction = match policy_type {
                    policy::PolicyType::PolicyListIn => InOut::Input,
                    policy::PolicyType::PolicyListOut => InOut::Output,
                    _ => return,
                };
                let config = peer.policy_list.get_mut(&direction);
                config.policy_list = policy_list;
                // Keep the cached outbound-policy snapshot current before
                // the soft-out re-advertise reads it (see the prefix-set
                // arm above).
                if direction == InOut::Output {
                    peer.rebuild_out_policy();
                }

                match direction {
                    InOut::Input => {
                        // Push the new inbound policy into the shard(s)
                        // before replaying Adj-RIB-In, so the replay
                        // re-evaluates against it (single-relay FIFO keeps
                        // PolicyReplace ahead of the replayed routes).
                        self.shard_replace_in_policy(ident);
                        super::peer::apply_soft_in_peer(self, ident);
                    }
                    InOut::Output => super::peer::apply_soft_out_peer(self, ident),
                }
            }
            policy::PolicyRx::KeyChain {
                name, key_chain, ..
            } => {
                // Apply the snapshot delta first so any downstream
                // resolve() sees the new state. Then reconcile the
                // TCP-AO MKTs installed on the listening sockets so a key
                // edit lands on the kernel before the peer's next SYN
                // arrives. `apply_ao_refresh_all` also bounces any live
                // session whose resolved key materially changed — that is
                // how an in-chain key-string rotation (same chain name,
                // same SendID/RecvID, new material) resets the session
                // instead of surviving on the old key until the hold
                // timer expires.
                if let Some(kc) = key_chain {
                    self.key_chains.insert(name, kc);
                } else {
                    self.key_chains.remove(&name);
                }
                super::config::apply_ao_refresh_all(self);
            }
        }
    }

    /// Re-run the FIB install for every Loc-RIB winner of `afi_safi`
    /// after a `table-map` binding or its policy content changed.
    /// Install-only sweep: best-path selection and egress attributes
    /// are unaffected by table-map, so nothing is re-advertised. The
    /// `Selected` side of the Loc-RIB table is authoritative for
    /// "currently has a winner" — prefixes absent from it have no FIB
    /// state to reconcile (their withdraw fired when the winner
    /// disappeared).
    pub(super) fn table_map_resync(&mut self, afi_safi: bgp_packet::AfiSafi) {
        use bgp_packet::{Afi, Safi};
        // Unicast families only, matching `table_map_afi_valid`.
        let afi = match (afi_safi.afi, afi_safi.safi) {
            (afi @ (Afi::Ip | Afi::Ip6), Safi::Unicast) => afi,
            _ => return,
        };
        // Snapshot the winners first — building the `BgpTop` below
        // takes `&mut local_rib`.
        let winners_v4: Vec<(ipnet::Ipv4Net, super::route::BgpRib)> = if afi == Afi::Ip {
            self.shard
                .v4
                .1
                .iter()
                .map(|(p, best)| (p, best.clone()))
                .collect()
        } else {
            Vec::new()
        };
        let winners_v6: Vec<(ipnet::Ipv6Net, super::route::BgpRib)> = if afi == Afi::Ip6 {
            self.shard
                .v6
                .1
                .iter()
                .map(|(p, best)| (p, best.clone()))
                .collect()
        } else {
            Vec::new()
        };
        let top = super::peer::BgpTop {
            router_id: &self.router_id,
            srv6_ipv6_export: self.srv6_ipv6_export.as_ref(),
            local_rib: &mut self.local_rib,
            shard: &mut self.shard,
            tx: &self.tx,
            rib_client: &self.ctx.rib,
            attr_store: &mut self.attr_store,
            update_groups: &mut self.update_groups,
            interface_addrs: &self.interface_addrs,
            color_policy: Some(&self.color_policy),
            flex_algo_routes: Some(&self.flex_algo_routes),
            flex_algo_srv6_routes: Some(&self.flex_algo_srv6_routes),
            vrf_export: None,
            vrf_import: None,
            nexthop_cache: None,
            vrf_transport_v4: None,
            vrf_transport_v6: None,
            central_label_alloc: None,
        };
        for (prefix, best) in &winners_v4 {
            super::route::fib_install_v4(&top, *prefix, std::slice::from_ref(best));
        }
        for (prefix, best) in &winners_v6 {
            super::route::fib_install_v6(&top, *prefix, std::slice::from_ref(best));
        }
    }

    pub async fn event_loop(&mut self) {
        // Request our dynamic MPLS label block from the RIB label
        // manager up front. The reply (`RibRx::LabelBlock`) binds
        // `vrf_label_alloc` before per-VRF tasks start asking for
        // labels; a VRF spawned before it lands takes label 0 and is
        // reconciled on arrival.
        self.request_label_block();
        if let Err(err) = self.listen().await {
            self.listen_err = Some(err);
        }
        loop {
            match self.rib_rx.recv().await {
                Some(RibRx::EoR) => {
                    // tracing::info!("BGP: Received EoR, entering main event loop");
                    break;
                }
                Some(msg) => self.process_rib_msg(msg),
                None => break,
            }
        }
        // tracing::info!(
        //     "BGP: Main event loop started with {} peers",
        //     self.peers.len()
        // );
        loop {
            tokio::select! {
                Some(msg) = self.rib_rx.recv() => {
                    self.process_rib_msg(msg);
                }
                Some(msg) = self.rx.recv() => {
                    // Relisten needs `.await` (async bind), which the
                    // sync `process_msg` dispatcher cannot do — handle
                    // it here at the loop level.
                    if matches!(msg, Message::Relisten) {
                        self.relisten().await;
                    } else {
                        self.process_msg(msg);
                    }
                }
                Some(ident) = self.sync_tick_rx.recv() => {
                    // Tier 1a: one chunk of a peer's resumable IPv4
                    // sync dump, then it re-arms itself. Interleaves
                    // fairly with real events so a large dump never
                    // head-of-line-blocks ingest. Idle when the flag
                    // is off (nothing ever feeds `sync_tick_tx`).
                    self.drive_sync_v4(ident);
                }
                Some(msg) = self.cm.rx.recv() => {
                    self.process_cm_msg(msg);
                }
                Some(msg) = self.show.rx.recv() => {
                    self.process_show_msg(msg).await;
                }
                Some(msg) = self.policy_rx.recv() => {
                    self.process_policy_msg(msg).await;
                }
                Some(event) = self.bfd_event_rx.recv() => {
                    self.process_bfd_event(event);
                }
                Some(event) = self.nd_event_rx.recv() => {
                    self.process_nd_event(event);
                }
                Some(msg) = self.vrf_global_rx.recv() => {
                    // VRF→global fan-in: peer register / accept
                    // dispatch and Export → VPNv4/v6.
                    self.process_vrf_global_msg(msg);
                }
                Some(msg) = self.srv6_locator_rx.recv() => {
                    // SRv6 locator resolution from the RIB SR manager.
                    self.process_sr_rx(msg);
                }
                Some(result) = self.shard_results_rx.recv() => {
                    // Best-path deltas from the parallel shard pool (the
                    // map-reduce "reduce" side). Idle at N=1 (the
                    // channel is closed). The ingest "map" side that feeds
                    // it lands in the next slice.
                    self.process_shard_result(result);
                }
            }
        }
    }

    /// Reduce side of the shard pool: act on one worker's best-path
    /// deltas — NHT untrack + FIB install per delta, then the advertise
    /// out-policy + attribute transform precomputed in parallel across the
    /// batch (Phase E.1), then serial bucketing — via the same post-work
    /// the synchronous path runs. Reachable only at N>1, where
    /// v4-unicast ingest fanned out to the pool.
    fn process_shard_result(&mut self, result: super::shard::pool::ShardResult) {
        // A2 step ③ — peel the DumpV4 barrier acks off the delta stream.
        // For each shard's `DumpDoneV4`: record what it advertised into the
        // peer's Adj-RIB-Out (so a later withdraw reaches the peer),
        // spreading the inserts across the N acks to keep the main-loop
        // stall low; then decrement the `req_id`'s outstanding-ack count
        // and, on the last ack, emit EoR — every dump UPDATE is queued by
        // then (each shard enqueues its slice before acking). Everything
        // else is a best-path delta for the reduce below.
        let mut deltas = Vec::with_capacity(result.out.len());
        for out in result.out {
            match out {
                super::shard::ShardOut::DumpDoneV4 {
                    req_id,
                    ident,
                    sent,
                    advertised,
                } => {
                    // At gate-on `adj_out` lives in the egress task (group or
                    // PET), so forward the dump rows there as record-only — the
                    // shard already put the bytes on the wire. Group-task first
                    // (the N>1 twin of route_sync_ipv4's RecordAdjOut, Phase 3),
                    // then the per-peer PET, then main's adj_out at gate-off.
                    let v4 =
                        bgp_packet::AfiSafi::new(bgp_packet::Afi::Ip, bgp_packet::Safi::Unicast);
                    let group_tx = super::group_egress::egress_group_task_enabled()
                        .then(|| {
                            let gid = self
                                .peers
                                .get_by_idx(ident)?
                                .update_group_id
                                .get(&v4)?
                                .clone();
                            self.update_groups
                                .get(&v4)?
                                .group_by_id(&gid)?
                                .task
                                .as_ref()
                                .map(|t| t.delta_tx())
                        })
                        .flatten();
                    if let Some(tx) = group_tx {
                        for (nlri, rib) in advertised {
                            let _ =
                                tx.send(super::group_egress::GroupEgressDeltaV4::RecordAdjOut {
                                    prefix: nlri.prefix,
                                    rib,
                                });
                        }
                    } else if super::peer_egress::peer_egress_task_enabled()
                        && let Some(pet) = self.peers.get_by_idx(ident).and_then(|p| p.pet.as_ref())
                    {
                        for (nlri, rib) in advertised {
                            let _ = pet.delta_tx.send(
                                super::peer_egress::EgressDeltaV4::RecordAdjOut {
                                    prefix: nlri.prefix,
                                    rib,
                                },
                            );
                        }
                    } else if let Some(peer) = self.peers.get_mut_by_idx(ident) {
                        for (nlri, rib) in advertised {
                            peer.adj_out.add(None, nlri.prefix, rib);
                        }
                    }
                    if let Some(done) = self.pending_dumps_v4.ack(req_id, sent) {
                        if let Some(peer) = self.peers.get_mut_by_idx(done.ident) {
                            super::route::send_eor_ipv4_unicast(peer);
                        }
                        tracing::debug!(
                            req_id,
                            ident = done.ident,
                            sent = done.sent,
                            "DumpV4 complete"
                        );
                    }
                }
                other => deltas.push(other),
            }
        }
        if deltas.is_empty() {
            return;
        }
        let import_dispatcher = super::vrf::VrfImportDispatcher {
            rib_known_vrfs: &self.rib_known_vrfs,
            vrf_registry: &self.vrf_registry,
        };
        let mut bgp_ref = BgpTop {
            router_id: &self.router_id,
            srv6_ipv6_export: self.srv6_ipv6_export.as_ref(),
            local_rib: &mut self.local_rib,
            shard: &mut self.shard,
            tx: &self.tx,
            rib_client: &self.ctx.rib,
            attr_store: &mut self.attr_store,
            update_groups: &mut self.update_groups,
            interface_addrs: &self.interface_addrs,
            vrf_export: None,
            color_policy: Some(&self.color_policy),
            flex_algo_routes: Some(&self.flex_algo_routes),
            flex_algo_srv6_routes: Some(&self.flex_algo_srv6_routes),
            vrf_import: Some(&import_dispatcher),
            nexthop_cache: Some(&mut self.nexthop_cache),
            vrf_transport_v4: None,
            vrf_transport_v6: None,
            central_label_alloc: self.vrf_label_alloc.as_mut(),
        };
        super::route::route_apply_bestpath_v4_batch(&mut bgp_ref, &mut self.peers, deltas);
    }

    /// A2 — fan a `DumpV4` to every pool shard for `ident`'s session-up
    /// IPv4-unicast dump, returning the `req_id` its per-shard `DumpDoneV4`
    /// acks carry. `None` when there is no pool (N=1, where the resumable
    /// cursor handles the dump). Each shard builds + sends its own slice
    /// from the shared `Arc<SyncCtx>` (the `&Peer`-free egress snapshot);
    /// main records the adj_out deltas + counts the N acks via
    /// [`DumpBarrierV4`], emitting EoR on the last. Called at session-up
    /// from the FSM-event handler once the peer reaches Established.
    fn broadcast_dump_v4(&mut self, ident: usize) -> Option<u64> {
        use bgp_packet::{Afi, AfiSafi, Safi};

        let n = self.shards.as_ref()?.n();
        let high_water = sync_egress_high_water();
        let peer = self.peers.get_by_idx(ident)?;
        // The peer-derived egress params the shards can't reconstruct.
        let params = super::shard::msg::DumpParamsV4 {
            add_path: peer.opt.is_add_path_send(Afi::Ip, Safi::Unicast),
            llgr_v4: peer
                .cap_recv
                .llgr
                .contains_key(&AfiSafi::new(Afi::Ip, Safi::Unicast)),
            enhe_v6: peer
                .is_enhe_v4_negotiated()
                .then(|| super::update_group::compose_enhe_next_hop(peer, &self.interface_addrs))
                .flatten(),
            egress_high_water: high_water,
        };
        let ctx = std::sync::Arc::new(peer.sync_ctx(self.router_id));
        let req_id = self.pending_dumps_v4.start(ident, n);
        self.shards
            .as_ref()
            .expect("pool present (checked above)")
            .broadcast(|| super::shard::ShardMsg::DumpV4 {
                req_id,
                ctx: ctx.clone(),
                params,
            });
        Some(req_id)
    }

    /// If `vrf` is an `encapsulation srv6` VRF with an allocated
    /// End.DT46 SID and a resolved locator, attach the SRv6 L3 Service
    /// TLV (RFC 9252) to `attr` and return the IPv6 next-hop the VPN
    /// route should advertise — the PE's locator node address. Returns
    /// `None` for MPLS-mode VRFs (the caller keeps the MPLS service
    /// label and next-hop-self), and leaves `attr` untouched.
    fn srv6_export_nexthop(
        &self,
        vrf: &str,
        attr: &mut bgp_packet::BgpAttr,
    ) -> Option<std::net::Ipv6Addr> {
        let (sid, _function) = self.vrf_registry.get(vrf)?.srv6_sid?;
        let locator = self.srv6_locator.as_ref()?;
        let nexthop = locator.node_sid_addr()?;
        attr.prefix_sid = Some(srv6_l3_service_prefix_sid(
            sid,
            locator.sid_structure(),
            bgp_packet::SRV6_BEHAVIOR_END_DT46,
        ));
        Some(nexthop)
    }

    fn process_vrf_global_msg(&mut self, msg: super::vrf::BgpGlobalMsg) {
        match msg {
            super::vrf::BgpGlobalMsg::Export {
                vrf,
                prefix,
                attr,
                label,
            } => {
                let Some(rd) = self.vrfs.get(&vrf).and_then(|cfg| cfg.rd) else {
                    tracing::warn!(
                        vrf = %vrf,
                        %prefix,
                        "bgp: export dropped — VRF has no RD configured",
                    );
                    return;
                };
                let export_rts = self
                    .rib_known_vrfs
                    .get(&vrf)
                    .map(|k| k.export_rts_v4.clone())
                    .unwrap_or_default();
                let advertise_type5 = self
                    .vrfs
                    .get(&vrf)
                    .map(|c| c.evpn_advertise_v4)
                    .unwrap_or(false);

                // SRv6 L3VPN: for an `encapsulation srv6` VRF, attach
                // the SRv6 L3 Service TLV (End.DT46 SID) and advertise
                // the PE's locator as the IPv6 next-hop; the MPLS
                // service label is suppressed (the SID carries
                // forwarding). MPLS-mode VRFs are unaffected.
                let mut attr = attr;
                let srv6_nexthop = self.srv6_export_nexthop(&vrf, &mut attr);

                // Tag with export-RT extcommunities, then intern
                // the result in the global attr_store. The VRF
                // task sent us `attr` by value so it could be
                // mutated independently; this is the only place
                // the global instance interns it.
                let tagged = tag_attr_with_export_rts(attr, &export_rts);
                let interned = self.shard.intern(tagged);
                // Capture the export-RT-tagged attribute (incl. any SRv6
                // Prefix-SID) for a parallel EVPN Type-5 origination,
                // before `interned` is moved into the VPNv4 BgpRib below.
                let evpn_attr = advertise_type5.then(|| (*interned).clone());

                // VPNv4 NLRI carries a single MPLS label per route.
                // VRF tasks without an allocator pass `0`, which we
                // treat as "no label allocated yet":
                // `make_bgp_rib_entry_v4` and the VPNv4 emit path
                // interpret it as "skip install / advertise" rather
                // than emit the explicit-null label. SRv6-mode routes
                // carry no MPLS label (label 0 in the NLRI).
                let label_obj = if label != 0 && srv6_nexthop.is_none() {
                    Some(bgp_packet::Label {
                        label,
                        exp: 0,
                        bos: true,
                    })
                } else {
                    None
                };

                let nexthop = bgp_packet::Vpnv4Nexthop {
                    rd,
                    nhop: match srv6_nexthop {
                        Some(v6) => std::net::IpAddr::V6(v6),
                        None => std::net::IpAddr::V4(self.router_id),
                    },
                };

                let rib = super::route::BgpRib {
                    remote_id: 0,
                    local_id: 0,
                    attr: interned,
                    // Originated (VRF-exported) routes carry the
                    // `ORIGINATED_PEER` sentinel, NOT 0: a literal 0
                    // collides with the PeerMap index of whichever peer
                    // happens to occupy slot 0, and the advertise-path
                    // split-horizon (`rib.ident == peer.ident`) would then
                    // silently suppress this VPN route toward that peer
                    // (e.g. an Inter-AS Option C multihop VPNv4 PE whose
                    // session landed on slot 0). `usize::MAX` never matches
                    // a real peer.
                    ident: super::route::ORIGINATED_PEER,
                    router_id: self.router_id,
                    weight: 0,
                    typ: super::route::BgpRibType::Originated,
                    best_path: false,
                    best_reason: super::route::Reason::Default,
                    label: label_obj,
                    local_label: None,
                    nexthop: Some(super::route::VpnNexthop::V4(nexthop)),
                    nexthop_reachable: true,
                    enhe_egress: None,
                    stale: false,
                    esi: None,
                    vrf_transit_only: false,
                };

                let (_, selected, _gen) = self.shard.update(Some(rd), prefix, rib);
                let selected_len = selected.len();

                // Local intra-router leak. The remote-VPNv4 ingress
                // path (`route_ipv4_update`) fans an accepted VPNv4
                // winner out to every importing VRF; the direct
                // `shard.update` above bypasses that hook, so a
                // route exported by one local VRF would never reach a
                // sibling VRF on the same box. Replicate the fan-out
                // here, skipping the originating VRF so a `rt both`
                // config doesn't re-import what it just exported.
                if let Some(winner) = selected.first() {
                    let dispatcher = super::vrf::VrfImportDispatcher {
                        rib_known_vrfs: &self.rib_known_vrfs,
                        vrf_registry: &self.vrf_registry,
                    };
                    super::vrf::dispatch_import_v4(
                        &dispatcher,
                        rd,
                        prefix,
                        &winner.attr,
                        0,
                        // Local VRF-to-VRF leak carries no SR-MPLS
                        // transport; FIB install for local-leak is out
                        // of scope (remote-PE import is the gated path).
                        &[],
                        Some(vrf.as_str()),
                    );
                }

                // Fan out the new VPNv4 winner to PE peers via the
                // existing `route_advertise_to_peers` helper. The
                // helper iterates Established peers matching
                // (Afi=Ip, Safi=MplsVpn), runs split-horizon +
                // outbound policy + RTC, and pushes to each peer's
                // `cache_vpnv4` (debounced flush). The global
                // instance has `vrf_export = None`, so no infinite
                // loop on the export hook in `route_ipv4_update`.
                let mut top = super::peer::BgpTop {
                    router_id: &self.router_id,
                    srv6_ipv6_export: self.srv6_ipv6_export.as_ref(),
                    local_rib: &mut self.local_rib,
                    shard: &mut self.shard,
                    tx: &self.tx,
                    rib_client: &self.ctx.rib,
                    attr_store: &mut self.attr_store,
                    update_groups: &mut self.update_groups,
                    interface_addrs: &self.interface_addrs,
                    color_policy: Some(&self.color_policy),
                    flex_algo_routes: Some(&self.flex_algo_routes),
                    flex_algo_srv6_routes: Some(&self.flex_algo_srv6_routes),
                    vrf_export: None,
                    vrf_import: None,
                    nexthop_cache: None,
                    vrf_transport_v4: None,
                    vrf_transport_v6: None,
                    central_label_alloc: None,
                };
                super::route::route_advertise_to_peers(
                    Some(rd),
                    prefix,
                    &selected,
                    /* source peer */ 0,
                    &mut top,
                    &mut self.peers,
                );

                bgp_vpn_trace!(
                    self.tracing,
                    vrf = %vrf,
                    %prefix,
                    rd = %rd,
                    export_rts = export_rts.len(),
                    label,
                    winners = selected_len,
                    "bgp: export written to LocalRib.v4vpn and advertised to PE peers",
                );

                // EVPN Type-5: additionally advertise this VRF prefix as
                // an IP Prefix route reusing the same RD, export RTs,
                // service label and (SRv6) Prefix-SID. Peer-gated by the
                // L2VPN/EVPN AFI/SAFI, so it composes with the VPNv4 above.
                if let Some(attr) = evpn_attr {
                    self.evpn_originate_type5(
                        rd,
                        ipnet::IpNet::V4(prefix),
                        attr,
                        label,
                        srv6_nexthop,
                    );
                }
            }
            super::vrf::BgpGlobalMsg::WithdrawExport { vrf, prefix } => {
                let Some(rd) = self.vrfs.get(&vrf).and_then(|cfg| cfg.rd) else {
                    bgp_vpn_trace!(
                        self.tracing,
                        vrf = %vrf,
                        %prefix,
                        "bgp: withdraw-export dropped — VRF has no RD configured",
                    );
                    return;
                };
                // VRF-originated routes always carry `ident ==
                // ORIGINATED_PEER` and `local_id == 0` (the values used in
                // the matching Export); the remove path uses that tuple to
                // identify the row.
                let removed = self
                    .shard
                    .remove(Some(rd), prefix, 0, super::route::ORIGINATED_PEER);

                // Re-run best-path so any remaining candidate at
                // (rd, prefix) becomes the new selected winner.
                // Pass that result to `route_advertise_to_peers` —
                // empty `selected` triggers the Withdraw branch
                // there (`peer.adj_out` cleanup, MP_UNREACH emit).
                let selected = self.shard.select_best_path_vpn(&rd, prefix);

                // Local intra-router leak, symmetric with the Export
                // handler. If a replacement candidate survives at
                // (rd, prefix), re-import it into sibling VRFs with
                // the new attr; otherwise flood a withdraw using the
                // removed row's attr to resolve the matching-VRF set.
                // Skip the originating VRF (self-import guard).
                {
                    let dispatcher = super::vrf::VrfImportDispatcher {
                        rib_known_vrfs: &self.rib_known_vrfs,
                        vrf_registry: &self.vrf_registry,
                    };
                    if let Some(winner) = selected.first() {
                        super::vrf::dispatch_import_v4(
                            &dispatcher,
                            rd,
                            prefix,
                            &winner.attr,
                            0,
                            &[],
                            Some(vrf.as_str()),
                        );
                    } else if let Some(gone) = removed.first() {
                        super::vrf::dispatch_withdraw_import_v4(
                            &dispatcher,
                            rd,
                            prefix,
                            &gone.attr,
                            Some(vrf.as_str()),
                        );
                    }
                }

                let mut top = super::peer::BgpTop {
                    router_id: &self.router_id,
                    srv6_ipv6_export: self.srv6_ipv6_export.as_ref(),
                    local_rib: &mut self.local_rib,
                    shard: &mut self.shard,
                    tx: &self.tx,
                    rib_client: &self.ctx.rib,
                    attr_store: &mut self.attr_store,
                    update_groups: &mut self.update_groups,
                    interface_addrs: &self.interface_addrs,
                    color_policy: Some(&self.color_policy),
                    flex_algo_routes: Some(&self.flex_algo_routes),
                    flex_algo_srv6_routes: Some(&self.flex_algo_srv6_routes),
                    vrf_export: None,
                    vrf_import: None,
                    nexthop_cache: None,
                    vrf_transport_v4: None,
                    vrf_transport_v6: None,
                    central_label_alloc: None,
                };
                super::route::route_advertise_to_peers(
                    Some(rd),
                    prefix,
                    &selected,
                    /* source peer */ 0,
                    &mut top,
                    &mut self.peers,
                );

                bgp_vpn_trace!(
                    self.tracing,
                    vrf = %vrf,
                    %prefix,
                    rd = %rd,
                    removed = removed.len(),
                    winners = selected.len(),
                    "bgp: export withdrawn from LocalRib.v4vpn and PE peers",
                );

                // Mirror the EVPN Type-5 withdrawal.
                let advertise_type5 = self
                    .vrfs
                    .get(&vrf)
                    .map(|c| c.evpn_advertise_v4)
                    .unwrap_or(false);
                if advertise_type5 {
                    self.evpn_withdraw_type5(rd, ipnet::IpNet::V4(prefix));
                }
            }
            super::vrf::BgpGlobalMsg::ExportV6 {
                vrf,
                prefix,
                attr,
                label,
            } => {
                let Some(rd) = self.vrfs.get(&vrf).and_then(|cfg| cfg.rd) else {
                    tracing::warn!(
                        vrf = %vrf,
                        %prefix,
                        "bgp: v6 export dropped — VRF has no RD configured",
                    );
                    return;
                };
                let export_rts = self
                    .rib_known_vrfs
                    .get(&vrf)
                    .map(|k| k.export_rts_v6.clone())
                    .unwrap_or_default();
                let advertise_type5 = self
                    .vrfs
                    .get(&vrf)
                    .map(|c| c.evpn_advertise_v6)
                    .unwrap_or(false);

                // SRv6 L3VPN (VPNv6 over an SRv6 underlay): attach the
                // End.DT46 SID + advertise the locator next-hop; the
                // service label is suppressed. See the VPNv4 arm.
                let mut attr = attr;
                let srv6_nexthop = self.srv6_export_nexthop(&vrf, &mut attr);

                let tagged = tag_attr_with_export_rts(attr, &export_rts);
                let interned = self.shard.intern(tagged);
                let evpn_attr = advertise_type5.then(|| (*interned).clone());

                let label_obj = if label != 0 && srv6_nexthop.is_none() {
                    Some(bgp_packet::Label {
                        label,
                        exp: 0,
                        bos: true,
                    })
                } else {
                    None
                };

                // The on-wire next-hop is rewritten per-peer in
                // `route_update_ipv6` (next-hop-self), except SRv6
                // service routes, which carry the PE's locator address;
                // only the RD matters for the MPLS-mode placeholder.
                let nexthop = bgp_packet::Vpnv6Nexthop {
                    rd,
                    nhop: srv6_nexthop.unwrap_or(std::net::Ipv6Addr::UNSPECIFIED),
                };

                let rib = super::route::BgpRib {
                    remote_id: 0,
                    local_id: 0,
                    attr: interned,
                    // Originated (VRF-exported) routes carry the
                    // `ORIGINATED_PEER` sentinel, NOT 0: a literal 0
                    // collides with the PeerMap index of whichever peer
                    // happens to occupy slot 0, and the advertise-path
                    // split-horizon (`rib.ident == peer.ident`) would then
                    // silently suppress this VPN route toward that peer
                    // (e.g. an Inter-AS Option C multihop VPNv4 PE whose
                    // session landed on slot 0). `usize::MAX` never matches
                    // a real peer.
                    ident: super::route::ORIGINATED_PEER,
                    router_id: self.router_id,
                    weight: 0,
                    typ: super::route::BgpRibType::Originated,
                    best_path: false,
                    best_reason: super::route::Reason::Default,
                    label: label_obj,
                    local_label: None,
                    nexthop: Some(super::route::VpnNexthop::V6(nexthop)),
                    nexthop_reachable: true,
                    enhe_egress: None,
                    stale: false,
                    esi: None,
                    vrf_transit_only: false,
                };

                let (_, selected, _gen) = self.shard.update_v6vpn(rd, prefix, rib);
                let winners = selected.len();

                // Local intra-router leak — the v6 analog of the VPNv4
                // Export handler. The direct `update_v6vpn` above
                // bypasses the `route_ipv6_update` import hook, so fan
                // the winner into every sibling VRF whose import_rts_v6
                // match, skipping the originating VRF (so `rt both`
                // doesn't re-import what it just exported).
                if let Some(winner) = selected.first() {
                    let dispatcher = super::vrf::VrfImportDispatcher {
                        rib_known_vrfs: &self.rib_known_vrfs,
                        vrf_registry: &self.vrf_registry,
                    };
                    super::vrf::dispatch_import_v6(
                        &dispatcher,
                        rd,
                        prefix,
                        &winner.attr,
                        0,
                        // Local VRF-to-VRF leak: no SR-MPLS transport.
                        &[],
                        Some(vrf.as_str()),
                    );
                }

                let mut top = super::peer::BgpTop {
                    router_id: &self.router_id,
                    srv6_ipv6_export: self.srv6_ipv6_export.as_ref(),
                    local_rib: &mut self.local_rib,
                    shard: &mut self.shard,
                    tx: &self.tx,
                    rib_client: &self.ctx.rib,
                    attr_store: &mut self.attr_store,
                    update_groups: &mut self.update_groups,
                    interface_addrs: &self.interface_addrs,
                    color_policy: Some(&self.color_policy),
                    flex_algo_routes: Some(&self.flex_algo_routes),
                    flex_algo_srv6_routes: Some(&self.flex_algo_srv6_routes),
                    vrf_export: None,
                    vrf_import: None,
                    nexthop_cache: None,
                    vrf_transport_v4: None,
                    vrf_transport_v6: None,
                    central_label_alloc: None,
                };
                super::route::route_advertise_to_peers_vpnv6(
                    rd,
                    prefix,
                    &selected,
                    &mut top,
                    &mut self.peers,
                );

                bgp_vpn_trace!(
                    self.tracing,
                    vrf = %vrf,
                    %prefix,
                    rd = %rd,
                    export_rts = export_rts.len(),
                    label,
                    winners,
                    "bgp: v6 export written to LocalRib.v6vpn and advertised to PE peers",
                );

                // EVPN Type-5 (IPv6 prefix) — composes with VPNv6 above.
                if let Some(attr) = evpn_attr {
                    self.evpn_originate_type5(
                        rd,
                        ipnet::IpNet::V6(prefix),
                        attr,
                        label,
                        srv6_nexthop,
                    );
                }
            }
            super::vrf::BgpGlobalMsg::WithdrawExportV6 { vrf, prefix } => {
                let Some(rd) = self.vrfs.get(&vrf).and_then(|cfg| cfg.rd) else {
                    return;
                };
                let removed = self
                    .shard
                    .remove_v6vpn(rd, prefix, 0, super::route::ORIGINATED_PEER);
                let selected = self.shard.select_best_path_vpn_v6(&rd, prefix);

                // Local intra-router leak, symmetric with the ExportV6
                // handler: a surviving winner re-imports into sibling
                // VRFs; otherwise flood a withdraw from the removed
                // row's RTs. Skip the originating VRF.
                {
                    let dispatcher = super::vrf::VrfImportDispatcher {
                        rib_known_vrfs: &self.rib_known_vrfs,
                        vrf_registry: &self.vrf_registry,
                    };
                    if let Some(winner) = selected.first() {
                        super::vrf::dispatch_import_v6(
                            &dispatcher,
                            rd,
                            prefix,
                            &winner.attr,
                            0,
                            &[],
                            Some(vrf.as_str()),
                        );
                    } else if let Some(gone) = removed.first() {
                        super::vrf::dispatch_withdraw_import_v6(
                            &dispatcher,
                            rd,
                            prefix,
                            &gone.attr,
                            Some(vrf.as_str()),
                        );
                    }
                }

                let mut top = super::peer::BgpTop {
                    router_id: &self.router_id,
                    srv6_ipv6_export: self.srv6_ipv6_export.as_ref(),
                    local_rib: &mut self.local_rib,
                    shard: &mut self.shard,
                    tx: &self.tx,
                    rib_client: &self.ctx.rib,
                    attr_store: &mut self.attr_store,
                    update_groups: &mut self.update_groups,
                    interface_addrs: &self.interface_addrs,
                    color_policy: Some(&self.color_policy),
                    flex_algo_routes: Some(&self.flex_algo_routes),
                    flex_algo_srv6_routes: Some(&self.flex_algo_srv6_routes),
                    vrf_export: None,
                    vrf_import: None,
                    nexthop_cache: None,
                    vrf_transport_v4: None,
                    vrf_transport_v6: None,
                    central_label_alloc: None,
                };
                super::route::route_advertise_to_peers_vpnv6(
                    rd,
                    prefix,
                    &selected,
                    &mut top,
                    &mut self.peers,
                );

                bgp_vpn_trace!(
                    self.tracing,
                    vrf = %vrf,
                    %prefix,
                    rd = %rd,
                    winners = selected.len(),
                    "bgp: v6 export withdrawn from LocalRib.v6vpn and PE peers",
                );

                // Mirror the EVPN Type-5 (IPv6) withdrawal.
                let advertise_type5 = self
                    .vrfs
                    .get(&vrf)
                    .map(|c| c.evpn_advertise_v6)
                    .unwrap_or(false);
                if advertise_type5 {
                    self.evpn_withdraw_type5(rd, ipnet::IpNet::V6(prefix));
                }
            }
            super::vrf::BgpGlobalMsg::RegisterPeer { vrf, addr } => {
                peer_index_register(&mut self.peer_index, vrf, addr);
            }
        }
    }

    /// Handle an ND `NeighborDiscovered` notification by checking for
    /// a configured `interface-neighbor` on the matching ifindex and,
    /// if found, materializing the peer. The lookup is a linear scan
    /// of `link_index_by_name` since the operator-typed leaf is keyed
    /// by name; for typical (single-digit) interface-neighbor counts
    /// this is fine, and it lets the config use the friendly name in
    /// `show bgp summary`.
    fn process_nd_event(&mut self, event: crate::nd::engine::NdEvent) {
        let crate::nd::engine::NdEvent::NeighborDiscovered { ifindex, src } = event;
        let name = self
            .link_index_by_name
            .iter()
            .find(|(_, idx)| **idx == ifindex)
            .map(|(name, _)| name.clone());
        let Some(name) = name else {
            // RA arrived on an interface RIB hasn't told us about yet
            // — possible during early startup. Drop; the next RA will
            // re-trigger this path.
            return;
        };
        super::interface_neighbor::materialize_peer(self, &name, ifindex, src);
    }

    /// Handle a [`crate::bfd::inst::BfdEvent`] forwarded by the BFD
    /// instance. RFC 5882 §5 prescribes that a BFD signal of session
    /// Down should be treated as a path-failure indication for the
    /// IGP/BGP session — we react by sending `Event::Stop` to the
    /// matching peer's FSM, which triggers the usual BGP teardown
    /// path (NOTIFICATION + TCP close + transition to Idle).
    ///
    /// Synthetic Down→Down notifications (emitted by BFD when a new
    /// subscriber attaches before any peer Rx has arrived) are
    /// ignored — they carry no state-transition information and
    /// would otherwise tear down a peer that hasn't yet had a chance
    /// to establish.
    pub fn process_bfd_event(&mut self, event: crate::bfd::inst::BfdEvent) {
        let crate::bfd::inst::BfdEvent::StateChange { key, change } = event;
        bgp_bfd_trace!(
            self.tracing,
            ?key,
            from = %change.from,
            to = %change.to,
            diag = %change.diag,
            "bgp: bfd session state change",
        );

        // Synthetic "current state" mirror from `Bfd::subscribe`
        // — no transition has occurred.
        if change.from == change.to {
            return;
        }

        if change.to != bfd_packet::State::Down {
            return;
        }

        // SessionKey.remote is the BGP neighbor address — direct
        // lookup. A missing peer means the user removed the
        // neighbor since BGP last subscribed; safe to ignore.
        let Some(peer) = self.peers.get(&key.remote) else {
            bgp_bfd_trace!(
                self.tracing,
                ?key,
                "bgp: bfd-down for unknown peer; ignoring",
            );
            return;
        };
        let peer_idx = peer.ident;
        tracing::warn!(
            peer = %key.remote,
            diag = %change.diag,
            "bgp: tearing down peer on bfd-down (RFC 5882 §5)",
        );
        let _ = self.tx.try_send(Message::Event(peer_idx, Event::Stop));
    }
}

pub fn serve(mut bgp: Bgp) -> Task<()> {
    Task::spawn(async move {
        bgp.event_loop().await;
    })
}

#[cfg(test)]
mod tests {
    //! Pure-function tests on the `peer_index` mutations.
    //! Building a full `Bgp` to drive `process_vrf_global_msg`
    //! end-to-end would require netlink — out of reach for unit
    //! tests; BDD scenarios cover that path. Here we exercise the
    //! index helpers directly.
    use std::collections::BTreeMap;
    use std::net::IpAddr;

    use super::DumpBarrierV4;
    use super::peer_index_register;

    fn addr(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn shard_count_resolution_policy() {
        use super::resolve_shard_count;
        // C.4: the YANG `shards` leaf wins over the env var...
        assert_eq!(resolve_shard_count(Some(4), Some(8)), 4);
        // ...the env var is the fallback when the leaf is unset...
        assert_eq!(resolve_shard_count(None, Some(8)), 8);
        // ...and `1` (synchronous) is the default when neither is set.
        assert_eq!(resolve_shard_count(None, None), 1);
        // The chosen value is clamped to 1..=64 from either source.
        assert_eq!(resolve_shard_count(Some(100), None), 64);
        assert_eq!(resolve_shard_count(Some(0), None), 1);
        assert_eq!(resolve_shard_count(None, Some(0)), 1);
        assert_eq!(resolve_shard_count(None, Some(999)), 64);
    }

    #[test]
    fn dump_barrier_completes_on_last_ack() {
        // A2 step ① — the per-req_id barrier: N acks complete one dump,
        // summing the per-shard `sent` counts.
        let mut b = DumpBarrierV4::default();
        let req = b.start(7, 3); // peer ident 7, fanned to 3 shards
        assert!(b.ack(req, 10).is_none(), "1/3");
        assert!(b.ack(req, 5).is_none(), "2/3");
        let done = b.ack(req, 2).expect("3/3 completes");
        assert_eq!(done.ident, 7);
        assert_eq!(done.sent, 17); // 10 + 5 + 2 summed across shards
        assert!(b.ack(req, 1).is_none(), "ack after completion is ignored");
    }

    #[test]
    fn dump_barrier_tracks_concurrent_dumps_independently() {
        let mut b = DumpBarrierV4::default();
        let a = b.start(1, 2);
        let c = b.start(2, 2);
        assert_ne!(a, c, "req_ids are distinct");
        assert!(b.ack(a, 1).is_none());
        assert!(b.ack(c, 4).is_none());
        let done_c = b.ack(c, 6).expect("c completes");
        assert_eq!((done_c.ident, done_c.sent), (2, 10));
        let done_a = b.ack(a, 3).expect("a completes");
        assert_eq!((done_a.ident, done_a.sent), (1, 4));
    }

    #[test]
    fn dump_barrier_ignores_unknown_req_id() {
        let mut b = DumpBarrierV4::default();
        assert!(b.ack(999, 5).is_none());
    }

    /// `/clear/bgp/...` path → (AFI/SAFI filter, op) mapping, both the
    /// per-AFI containers and the AFI-less form (filter = None, meaning
    /// every AFI/SAFI). Pinned here because the vtyctl clear surface is
    /// garbage-tolerant: an unmapped path silently no-ops.
    #[test]
    fn clear_bgp_path_mapping() {
        use crate::bgp::peer::BgpClearOp;
        use bgp_packet::{Afi, Safi};

        let cases = [
            (
                "/clear/bgp/ipv4/neighbor",
                Some((Some((Afi::Ip, Safi::Unicast)), BgpClearOp::Hard)),
            ),
            (
                "/clear/bgp/ipv6/neighbor/soft",
                Some((Some((Afi::Ip6, Safi::Unicast)), BgpClearOp::SoftBoth)),
            ),
            (
                "/clear/bgp/vpnv4/neighbor/soft/in",
                Some((Some((Afi::Ip, Safi::MplsVpn)), BgpClearOp::SoftIn)),
            ),
            (
                "/clear/bgp/evpn/neighbor/soft/out",
                Some((Some((Afi::L2vpn, Safi::Evpn)), BgpClearOp::SoftOut)),
            ),
            ("/clear/bgp/neighbor", Some((None, BgpClearOp::Hard))),
            (
                "/clear/bgp/neighbor/soft",
                Some((None, BgpClearOp::SoftBoth)),
            ),
            (
                "/clear/bgp/neighbor/soft/in",
                Some((None, BgpClearOp::SoftIn)),
            ),
            (
                "/clear/bgp/neighbor/soft/out",
                Some((None, BgpClearOp::SoftOut)),
            ),
            ("/clear/bgp/bogus/neighbor", None),
            ("/clear/bgp/neighbor/bogus", None),
        ];
        for (path, want) in cases {
            assert_eq!(super::parse_clear_bgp_path(path), want, "path `{path}`");
        }
    }

    #[test]
    fn srv6_l3_service_prefix_sid_round_trips_to_end_dt46() {
        use bgp_packet::{AttrEmitter, ParseBe};
        use bytes::BytesMut;

        let sid: std::net::Ipv6Addr = "2001:db8:1:40::".parse().unwrap();
        let structure = crate::rib::SidStructure {
            lb_bits: 32,
            ln_bits: 16,
            fun_bits: 16,
            arg_bits: 0,
        };
        let ps = super::srv6_l3_service_prefix_sid(
            sid,
            Some(structure),
            bgp_packet::SRV6_BEHAVIOR_END_DT46,
        );

        // Emit the attribute body and parse it back; the SID + behavior
        // must survive so a remote PE reads End.DT46.
        let mut buf = BytesMut::new();
        ps.emit(&mut buf);
        let (_, parsed) = bgp_packet::PrefixSid::parse_be(&buf).expect("parse");
        let attr = bgp_packet::BgpAttr {
            prefix_sid: Some(parsed),
            ..Default::default()
        };
        assert_eq!(
            attr.srv6_l3_sid(),
            Some((sid, bgp_packet::SRV6_BEHAVIOR_END_DT46))
        );
    }

    /// The global IPv6 unicast origination path builds the Prefix-SID
    /// with End.DT6 (decap into the main table). Emit + parse it and
    /// assert `srv6_l3_sid()` — the exact accessor the encapsulation-type
    /// filter consults — reads back the SID with behavior End.DT6.
    #[test]
    fn srv6_l3_service_prefix_sid_round_trips_to_end_dt6() {
        use bgp_packet::{AttrEmitter, ParseBe};
        use bytes::BytesMut;

        let sid: std::net::Ipv6Addr = "2001:db8:1:41::".parse().unwrap();
        let structure = crate::rib::SidStructure {
            lb_bits: 32,
            ln_bits: 16,
            fun_bits: 16,
            arg_bits: 0,
        };
        let ps = super::srv6_l3_service_prefix_sid(
            sid,
            Some(structure),
            bgp_packet::SRV6_BEHAVIOR_END_DT6,
        );

        let mut buf = BytesMut::new();
        ps.emit(&mut buf);
        let (_, parsed) = bgp_packet::PrefixSid::parse_be(&buf).expect("parse");
        let attr = bgp_packet::BgpAttr {
            prefix_sid: Some(parsed),
            ..Default::default()
        };
        assert_eq!(
            attr.srv6_l3_sid(),
            Some((sid, bgp_packet::SRV6_BEHAVIOR_END_DT6))
        );
    }

    #[test]
    fn register_inserts_the_mapping() {
        let mut index: BTreeMap<IpAddr, String> = BTreeMap::new();
        peer_index_register(&mut index, "vrfA".to_string(), addr("192.0.2.1"));
        assert_eq!(index.get(&addr("192.0.2.1")), Some(&"vrfA".to_string()));
    }

    #[test]
    fn register_overrides_a_conflicting_owner() {
        // FRR-style "most recent wins" behaviour. A different
        // VRF claiming the same peer IP is a config error the
        // operator must fix, but we don't refuse the update.
        let mut index: BTreeMap<IpAddr, String> = BTreeMap::new();
        peer_index_register(&mut index, "vrfA".to_string(), addr("192.0.2.1"));
        peer_index_register(&mut index, "vrfB".to_string(), addr("192.0.2.1"));
        assert_eq!(index.get(&addr("192.0.2.1")), Some(&"vrfB".to_string()));
    }

    #[test]
    fn re_register_same_owner_is_idempotent() {
        let mut index: BTreeMap<IpAddr, String> = BTreeMap::new();
        peer_index_register(&mut index, "vrfA".to_string(), addr("192.0.2.1"));
        peer_index_register(&mut index, "vrfA".to_string(), addr("192.0.2.1"));
        assert_eq!(index.get(&addr("192.0.2.1")), Some(&"vrfA".to_string()));
        assert_eq!(index.len(), 1);
    }

    /// Helper that takes a `BgpAttr` and tags it with one
    /// `ExtCommunity` per RT in the export set. Sub-type 0x02
    /// distinguishes RT from Route Origin (sub-type 0x03);
    /// `high_type` (0x00 for ASN, 0x01 for IPv4) is carried over
    /// from the matching `RouteDistinguisher`.
    mod tag_attr {
        use std::str::FromStr;

        use bgp_packet::{BgpAttr, RouteDistinguisher};

        use super::super::tag_attr_with_export_rts;

        fn rt(s: &str) -> RouteDistinguisher {
            RouteDistinguisher::from_str(s).unwrap()
        }

        #[test]
        fn empty_export_set_returns_attr_unchanged() {
            // No exports configured -> no ExtCommunity added.
            // Critical: tagging an empty set would otherwise
            // create an empty `Some(ExtCommunity::from([]))` and
            // upset the dedup pool's PartialEq.
            let attr = BgpAttr::default();
            let out = tag_attr_with_export_rts(attr.clone(), &Default::default());
            assert_eq!(out, attr);
        }

        #[test]
        fn single_rt_adds_one_extcom_with_subtype_2() {
            let mut rts = std::collections::BTreeSet::new();
            rts.insert(rt("65000:100"));

            let out = tag_attr_with_export_rts(BgpAttr::default(), &rts);
            let ecom = out.ecom.expect("ecom populated");
            assert_eq!(ecom.0.len(), 1);
            let entry = ecom.0.first().unwrap();
            // Two-byte ASN RD -> high_type 0x00.
            assert_eq!(entry.high_type, 0x00);
            assert_eq!(entry.low_type, 0x02, "RT sub-type per RFC 4360");
        }

        #[test]
        fn ipv4_rt_uses_high_type_1() {
            // The `From<RouteDistinguisher>` impl picks
            // `high_type = 0x01` for IPv4-shaped RDs; the
            // tagging helper must preserve that.
            let mut rts = std::collections::BTreeSet::new();
            rts.insert(rt("192.0.2.1:100"));

            let out = tag_attr_with_export_rts(BgpAttr::default(), &rts);
            let ecom = out.ecom.expect("ecom populated");
            assert_eq!(ecom.0.len(), 1);
            let entry = ecom.0.first().unwrap();
            assert_eq!(entry.high_type, 0x01);
            assert_eq!(entry.low_type, 0x02);
        }

        #[test]
        fn multiple_rts_yield_one_extcom_per_rt() {
            let mut rts = std::collections::BTreeSet::new();
            rts.insert(rt("65000:1"));
            rts.insert(rt("65000:2"));
            rts.insert(rt("65001:3"));

            let out = tag_attr_with_export_rts(BgpAttr::default(), &rts);
            let ecom = out.ecom.expect("ecom populated");
            assert_eq!(ecom.0.len(), 3);
            for entry in &ecom.0 {
                assert_eq!(entry.low_type, 0x02);
            }
        }

        #[test]
        fn pre_existing_ecom_is_preserved() {
            // Caller-attached extcomms (colour, etc.) MUST NOT be
            // dropped by the RT tag — append, don't replace.
            let mut attr = BgpAttr::default();
            let preexisting = bgp_packet::ExtCommunityValue::from_color(0, 100);
            attr.ecom = Some(bgp_packet::ExtCommunity::from([preexisting.clone()]));

            let mut rts = std::collections::BTreeSet::new();
            rts.insert(rt("65000:1"));

            let out = tag_attr_with_export_rts(attr, &rts);
            let ecom = out.ecom.expect("ecom populated");
            assert_eq!(ecom.0.len(), 2, "colour + RT");
            assert!(ecom.0.contains(&preexisting), "colour preserved");
            assert!(
                ecom.0.iter().any(|v| v.low_type == 0x02),
                "RT added alongside"
            );
        }
    }

    /// `matching_import_vrfs` walks `rib_known_vrfs` and returns
    /// every VRF whose `import_rts_v4` intersects the route's RT
    /// ext-communities.
    mod matching_import_vrfs_tests {
        use std::collections::{BTreeMap, BTreeSet};
        use std::str::FromStr;

        use bgp_packet::{ExtCommunity, ExtCommunityValue, RouteDistinguisher};

        use super::super::{
            RibKnownVrf, import_targets, import_targets_v6, matching_import_vrfs,
            matching_import_vrfs_v6,
        };

        fn rt(s: &str) -> RouteDistinguisher {
            RouteDistinguisher::from_str(s).unwrap()
        }

        fn rt_extcom(rt_str: &str) -> ExtCommunityValue {
            let mut v: ExtCommunityValue = rt(rt_str).into();
            v.low_type = 0x02;
            v
        }

        fn vrf_with_imports(rts: &[&str]) -> RibKnownVrf {
            let mut import_rts_v4 = BTreeSet::new();
            for s in rts {
                import_rts_v4.insert(rt(s));
            }
            RibKnownVrf {
                table_id: 100,
                ifindex: 1,
                import_rts_v4,
                export_rts_v4: BTreeSet::new(),
                import_rts_v6: BTreeSet::new(),
                export_rts_v6: BTreeSet::new(),
                inter_as_hybrid: false,
            }
        }

        fn vrf_with_imports_v6(rts: &[&str]) -> RibKnownVrf {
            let mut import_rts_v6 = BTreeSet::new();
            for s in rts {
                import_rts_v6.insert(rt(s));
            }
            RibKnownVrf {
                table_id: 100,
                ifindex: 1,
                import_rts_v4: BTreeSet::new(),
                export_rts_v4: BTreeSet::new(),
                import_rts_v6,
                export_rts_v6: BTreeSet::new(),
                inter_as_hybrid: false,
            }
        }

        #[test]
        fn no_ecom_attr_matches_no_vrf() {
            // A VPNv4 route with no RT ext-communities can't be
            // imported anywhere.
            let mut index = BTreeMap::new();
            index.insert("v1".to_string(), vrf_with_imports(&["65000:1"]));
            assert!(matching_import_vrfs(&index, &None).is_empty());
        }

        #[test]
        fn empty_ecom_attr_matches_no_vrf() {
            let mut index = BTreeMap::new();
            index.insert("v1".to_string(), vrf_with_imports(&["65000:1"]));
            let ecom = Some(ExtCommunity::default());
            assert!(matching_import_vrfs(&index, &ecom).is_empty());
        }

        #[test]
        fn rt_matches_single_importing_vrf() {
            let mut index = BTreeMap::new();
            index.insert("v1".to_string(), vrf_with_imports(&["65000:1"]));
            index.insert("v2".to_string(), vrf_with_imports(&["65000:2"]));
            let ecom = Some(ExtCommunity::from([rt_extcom("65000:1")]));
            assert_eq!(matching_import_vrfs(&index, &ecom), vec!["v1".to_string()]);
        }

        #[test]
        fn rt_matches_multiple_importing_vrfs() {
            // Two VRFs both import RT 65000:99. A route with that
            // RT should be delivered to both. Order follows
            // BTreeMap key iteration (sorted by name) — caller
            // doesn't depend on order but the test pins it for
            // determinism.
            let mut index = BTreeMap::new();
            index.insert("v1".to_string(), vrf_with_imports(&["65000:99"]));
            index.insert("v2".to_string(), vrf_with_imports(&["65000:99"]));
            let ecom = Some(ExtCommunity::from([rt_extcom("65000:99")]));
            let mut got = matching_import_vrfs(&index, &ecom);
            got.sort();
            assert_eq!(got, vec!["v1".to_string(), "v2".to_string()]);
        }

        #[test]
        fn import_targets_skips_originating_vrf() {
            // `rt both 1:1`: a route exported by v1 carries RT
            // 65000:1, and v1 also imports 65000:1. On the
            // local-leak path the originating VRF (v1) must be
            // excluded so it doesn't re-import what it exported,
            // while a sibling (v2) that imports the same RT still
            // gets it.
            let mut index = BTreeMap::new();
            index.insert("v1".to_string(), vrf_with_imports(&["65000:1"]));
            index.insert("v2".to_string(), vrf_with_imports(&["65000:1"]));
            let ecom = Some(ExtCommunity::from([rt_extcom("65000:1")]));

            let mut got = import_targets(&index, &ecom, Some("v1"));
            got.sort();
            assert_eq!(got, vec!["v2".to_string()]);
        }

        #[test]
        fn import_targets_none_skip_keeps_all_matches() {
            // The remote-VPNv4 ingress path passes `skip_vrf: None`
            // — no originating local VRF — so every matching VRF is
            // a target, identical to `matching_import_vrfs`.
            let mut index = BTreeMap::new();
            index.insert("v1".to_string(), vrf_with_imports(&["65000:1"]));
            index.insert("v2".to_string(), vrf_with_imports(&["65000:1"]));
            let ecom = Some(ExtCommunity::from([rt_extcom("65000:1")]));

            let mut got = import_targets(&index, &ecom, None);
            got.sort();
            assert_eq!(got, vec!["v1".to_string(), "v2".to_string()]);
        }

        #[test]
        fn non_rt_extcomm_does_not_count_as_rt() {
            // An ext-community with low_type != 0x02 (e.g.
            // Route-Origin sub-type 0x03) must not be treated as
            // an RT — even if its 6-octet value happens to match
            // a configured RT.
            let mut origin: ExtCommunityValue = rt("65000:1").into();
            origin.low_type = 0x03;
            let mut index = BTreeMap::new();
            index.insert("v1".to_string(), vrf_with_imports(&["65000:1"]));
            let ecom = Some(ExtCommunity::from([origin]));
            assert!(matching_import_vrfs(&index, &ecom).is_empty());
        }

        #[test]
        fn v6_matching_uses_import_rts_v6() {
            // The v6 matcher consults `import_rts_v6`, independent of
            // the v4 set: a route with RT 65000:9 matches the VRF that
            // imports it under v6, not one that imports it under v4.
            let mut index = BTreeMap::new();
            index.insert("v4only".to_string(), vrf_with_imports(&["65000:9"]));
            index.insert("v6only".to_string(), vrf_with_imports_v6(&["65000:9"]));
            let ecom = Some(ExtCommunity::from([rt_extcom("65000:9")]));

            assert_eq!(
                matching_import_vrfs_v6(&index, &ecom),
                vec!["v6only".to_string()]
            );
            // And the v4 matcher sees only the v4-importing VRF.
            assert_eq!(
                matching_import_vrfs(&index, &ecom),
                vec!["v4only".to_string()]
            );
        }

        #[test]
        fn import_targets_v6_skips_originating_vrf() {
            // `rt both 1:1` on the v6 AF: the originating VRF is
            // excluded on the local-leak path; a sibling that imports
            // the same v6 RT still gets it.
            let mut index = BTreeMap::new();
            index.insert("v1".to_string(), vrf_with_imports_v6(&["65000:1"]));
            index.insert("v2".to_string(), vrf_with_imports_v6(&["65000:1"]));
            let ecom = Some(ExtCommunity::from([rt_extcom("65000:1")]));

            let mut got = import_targets_v6(&index, &ecom, Some("v1"));
            got.sort();
            assert_eq!(got, vec!["v2".to_string()]);
        }
    }
}
