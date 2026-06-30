//! Per-VRF BGP task — owns the runtime state for one
//! `router bgp vrf X` block.
//!
//! Mirrors the global [`crate::bgp::Bgp`] structure on a smaller
//! surface: a [`PeerMap`] for CE peers, a per-VRF [`LocalRib`]
//! for the IPv4/IPv6 unicast Loc-RIB (populated by best-path /
//! import), and the identity (`name`, `rd`, `router_id`) the
//! global task supplies at spawn time.

use std::net::Ipv4Addr;

use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use crate::config::{ConfigChannel, ShowChannel};
use crate::context::{ProtoContext, Task};

use super::super::Message;
use super::super::config::BgpRedistSource;
use super::super::interface_addrs::InterfaceAddrs;
use super::super::peer_map::PeerMap;
use super::super::route::{LocalRib, ORIGINATED_PEER};
use super::super::shard::BgpShard;
use super::super::store::BgpAttrStore;
use super::super::update_group::UpdateGroupMap;
use super::msg::{BgpGlobalMsg, BgpVrfMsg};

/// Per-VRF BGP runtime. One task per `router bgp vrf X` block.
pub struct BgpVrf {
    /// VRF name (matches the YANG list key under
    /// `/router/bgp/vrf/<name>`). Used in log lines, `show bgp vrf
    /// <name> ...` dispatch, and as the `BgpGlobalMsg::Export` /
    /// `RegisterPeer` payload so the global task can attribute
    /// cross-task messages back to a VRF.
    pub name: String,
    /// Spawn-time runtime context built via
    /// [`ProtoContext::for_vrf`]. Every socket the per-VRF runtime
    /// opens flows through `ctx.tcp_socket_v*` / `ctx.tcp_listen`
    /// and therefore inherits the `SO_BINDTODEVICE` binding.
    pub ctx: ProtoContext,
    /// Per-VRF peer table — CE peers configured under
    /// `/router/bgp/vrf/<name>/neighbor/...`.
    pub peers: PeerMap,
    /// IPv4/IPv6 unicast Loc-RIB scoped to this VRF. VPNv4/v6 /
    /// EVPN stay anchored on the global Loc-RIB; the per-VRF Loc-
    /// RIB holds only the CE-facing surface plus routes imported
    /// from the global Loc-RIB via [`BgpVrfMsg::ImportV4`].
    pub local_rib: LocalRib,
    /// Shard-scope Loc-RIB tables (unicast/LU/VPN) — the per-VRF
    /// twin of [`crate::bgp::shard::BgpShard`] on the global task.
    pub shard: BgpShard,
    /// Per-VRF BGP router-id. Defaults to the global router-id at
    /// spawn time; the operator may override via
    /// `set router bgp vrf <name> router-id <addr>`, in which case
    /// the VRF is respawned with the new value.
    pub router_id: Ipv4Addr,
    /// This VRF's Route Distinguisher (`set router bgp vrf <name> rd`),
    /// or `None` if unset. The per-VRF MUP RIB is scoped to this single
    /// RD: an imported MUP route is re-keyed under the VRF's *own* RD,
    /// not the route's origin RD — the MUP analog of L3VPN dropping the
    /// VPNv4 RD on import (a VRF owns its routes under its own RD).
    /// Captured from the VRF config at spawn; an `rd` edit on a live VRF
    /// doesn't yet re-key the running task (same spawn-time-capture
    /// limitation as `router_id`).
    pub rd: Option<bgp_packet::RouteDistinguisher>,
    /// Config-manager subscription. Path-dispatch routes
    /// `/router/bgp/vrf/<name>/...` callbacks here so the per-VRF
    /// runtime owns its own commit sequencing.
    pub cm: ConfigChannel,
    /// Show-command subscription. `show bgp vrf <name> ...`
    /// dispatches through this channel.
    pub show: ShowChannel,
    /// Outbound channel to the global `Bgp` task. Used for peer
    /// registration and per-VRF best-path exports.
    pub global_tx: UnboundedSender<BgpGlobalMsg>,
    /// Inbound channel from the global `Bgp` task. The accept
    /// dispatcher and the import pipeline push here. `Shutdown`
    /// from `despawn_bgp_vrf` also arrives on this channel.
    pub global_rx: UnboundedReceiver<BgpVrfMsg>,
    /// RIB redistribute stream. The receive half of the per-VRF RIB
    /// subscription (`subscribe_for_vrf("bgp:vrf:<name>", table_id)`):
    /// after the task sends `Message::RedistAdd`, the RIB walks
    /// `vrf_tables[table_id]` and streams the matching connected/static
    /// routes here as `RibRx::RouteAdd`/`RouteDel`, which the event
    /// loop turns into per-VRF Loc-RIB originations + VPNv4/v6 exports.
    /// A placeholder-context spawn (kernel VRF not yet known) holds a
    /// closed channel here, so the select arm stays inert until the
    /// kernel-ctx respawn installs a live subscription.
    pub rib_rx: UnboundedReceiver<super::super::super::rib::api::RibRx>,
    /// FSM event channel. Per-VRF peers send `Event(ident, ...)`
    /// here when their timers expire or their TCP state changes;
    /// the per-VRF event loop drives the FSM from these. Bounded
    /// (8192) to match the global `Bgp::tx/rx`.
    pub tx: tokio::sync::mpsc::Sender<Message>,
    pub rx: tokio::sync::mpsc::Receiver<Message>,
    /// Local AS number. Threaded in from the global `Bgp::asn` at
    /// spawn time so per-VRF peers `Peer::new` can fill
    /// `local_as`. The per-VRF runtime does not maintain a
    /// separate ASN today; if a future spec requires one this is
    /// where it lives.
    pub asn: u32,
    /// Per-VRF MPLS label, allocated by `Bgp::vrf_label_alloc`
    /// at spawn time. Stamped onto every `BgpGlobalMsg::Export`
    /// this VRF emits so receiving PEs can identify the egress
    /// VRF; the matching AF_MPLS ILM pops this label and routes
    /// the inner packet into `vrf_tables[table_id]`.
    pub label: u32,
    /// Inter-AS MPLS/VPN Option AB (`inter-as-hybrid`). When set, this
    /// VRF re-exports the VPNv4 routes it *imports* (not just `network`/
    /// CE-learned routes) back into the global VPNv4 table, so an ASBR
    /// can relay a remote AS's VPN routes to its own PEs (and the other
    /// ASBR) over a single MP-eBGP VPNv4 session while still forwarding
    /// per-VRF (the VPN label terminates at the ASBR → VRF lookup). The
    /// re-import loop is broken by `dispatch_import_v4`'s `skip_vrf` (the
    /// originating VRF is excluded) and by eBGP AS-path. Off by default,
    /// so non-hybrid VRF behaviour is unchanged.
    pub inter_as_hybrid: bool,
    /// Dedup pool for `BgpAttr` instances seen by this VRF's
    /// peers. Every per-VRF runtime gets its own pool (cheaper
    /// than threading a shared lock across the `!Send` boundary,
    /// and the attribute populations are largely disjoint between
    /// VRFs in practice).
    pub attr_store: BgpAttrStore,
    /// IOS-XR-style update-groups scoped to this VRF. Same
    /// rationale as `attr_store`: per-VRF copy avoids cross-task
    /// sharing.
    pub update_groups: UpdateGroupMap,
    /// Per-link IPv6 link-local cache for RFC 8950 next-hop
    /// resolution. The per-VRF runtime starts with an empty
    /// cache; BGP unnumbered (interface-neighbor) lives on the
    /// global instance and isn't yet exposed at the VRF surface.
    /// Threaded through `BgpTop` so the FSM driver compiles even
    /// though no path here populates it today.
    pub interface_addrs: InterfaceAddrs,
    /// Resolved transport for currently-imported VPN prefixes, keyed by
    /// prefix. Populated by `handle_import_v4`/`v6` (and cleared on
    /// withdraw); read by `fib_install_v4`/`v6` (via `BgpTop`) so an
    /// imported VPN winner installs its `{transport,service}` labelled
    /// tunnel entry while CE routes install plain entries — one FIB
    /// install path arbitrating both.
    pub transport_v4:
        std::collections::BTreeMap<ipnet::Ipv4Net, Vec<crate::rib::nht::ResolvedNexthop>>,
    pub transport_v6:
        std::collections::BTreeMap<ipnet::Ipv6Net, Vec<crate::rib::nht::ResolvedNexthop>>,
    /// Colour-steering state mirrored from the global task via
    /// `BgpVrfMsg::ColourSteering`: the Color→Flex-Algo bindings and the
    /// per-algo SRv6 End-SID shadow. Read by `fib_install_v4`/`v6` (via
    /// `BgpTop`) so an imported SRv6 L3VPN route whose Color binds to a
    /// Flex-Algo gets the algo-N End SID prepended before its service
    /// SID. Empty until the first snapshot arrives.
    pub color_policy: super::super::color_policy::ColorPolicy,
    pub flex_algo_srv6_routes: super::super::color_policy::FlexAlgoSrv6Shadow,
    /// VRF-first MUP origination tracking: per PFCP SEID, the RD-free ST
    /// prefixes this VRF exported to the global SAFI-85 RIB. Lets a Session
    /// Deletion / Modification (`MupWithdrawOriginate`) withdraw exactly the
    /// routes that session created. A VRF binds one direction, so this is
    /// normally one prefix per SEID.
    pub mup_originated: std::collections::BTreeMap<u64, Vec<bgp_packet::MupPrefix>>,
}

/// Sender side of the per-VRF inbound channel — handed back to
/// the global task at spawn time so `despawn_bgp_vrf` can send
/// `BgpVrfMsg::Shutdown`, and so the accept / import dispatchers
/// can locate the matching VRF's queue.
pub type BgpVrfInbox = UnboundedSender<BgpVrfMsg>;

/// Hook handed to the shared `route_update_ipv4` path so a
/// per-VRF best-path winner gets pushed up to the global Bgp
/// task as a VPNv4 export candidate. Carries the VRF name (so
/// the global side can look up RD + RT) and the per-VRF
/// `global_tx` channel.
///
/// The global `Bgp` task constructs its own `BgpTop` with
/// `vrf_export = None`, so the shared route pipeline doesn't
/// fire any export for default-VRF traffic. Per-VRF tasks build
/// a `BgpTop` with `Some(VrfExporter { ... })` and the same
/// code path emits exports as a side-effect.
pub struct VrfExporter {
    pub name: String,
    pub tx: UnboundedSender<BgpGlobalMsg>,
    /// Per-VRF MPLS label, allocated by `Bgp::vrf_label_alloc`.
    /// Stamped onto every `BgpGlobalMsg::Export` emitted from
    /// this exporter; the receiving PE binds an AF_MPLS ILM at
    /// this label so data-plane forwarding pops the label and
    /// looks the inner packet up in the matching VRF table.
    pub label: u32,
}

/// Send a `BgpGlobalMsg::Export` for `prefix` carrying the
/// winner's `BgpAttr` (cloned out of the `Arc` so the global
/// task can re-intern). Called from `route_update_ipv4` after
/// best-path returns a non-empty `selected`. `label = 0` means
/// "no per-VRF label allocated" — the global handler treats it as
/// "skip the per-route install" rather than emit an
/// explicit-null label.
/// Drop every Route-Target extended community (RFC 4360 sub-type 0x02)
/// from a clone of `attr`. Used on the Inter-AS Option AB re-export path:
/// a route imported into a hybrid VRF carries the RTs it matched on, but
/// the re-originated route must carry only *this* VRF's export RTs (the
/// global Export handler re-tags). Without the strip the same RT would
/// accumulate one copy per inter-AS hop.
fn attr_without_route_targets(attr: &bgp_packet::BgpAttr) -> bgp_packet::BgpAttr {
    let mut a = attr.clone();
    if let Some(ref mut ecom) = a.ecom {
        ecom.0.retain(|v| v.low_type != 0x02);
    }
    a
}

pub fn vrf_emit_export(exporter: &VrfExporter, prefix: ipnet::Ipv4Net, attr: &bgp_packet::BgpAttr) {
    let _ = exporter.tx.send(BgpGlobalMsg::Export {
        vrf: exporter.name.clone(),
        prefix,
        attr: attr.clone(),
        label: exporter.label,
    });
}

/// Send a `BgpGlobalMsg::WithdrawExport` for `prefix`. Step
/// 17b-iii calls this when `route_update_ipv4` / withdraw path
/// observes the per-VRF best-path go from "has a winner" to
/// "empty" — the global instance drops the matching VPNv4 row.
pub fn vrf_emit_withdraw(exporter: &VrfExporter, prefix: ipnet::Ipv4Net) {
    let _ = exporter.tx.send(BgpGlobalMsg::WithdrawExport {
        vrf: exporter.name.clone(),
        prefix,
    });
}

/// VPNv6 counterpart of [`vrf_emit_export`] — push a per-VRF IPv6
/// unicast best-path winner up to the global task as a VPNv6 export
/// candidate.
pub fn vrf_emit_export_v6(
    exporter: &VrfExporter,
    prefix: ipnet::Ipv6Net,
    attr: &bgp_packet::BgpAttr,
) {
    let _ = exporter.tx.send(BgpGlobalMsg::ExportV6 {
        vrf: exporter.name.clone(),
        prefix,
        attr: attr.clone(),
        label: exporter.label,
    });
}

/// VPNv6 counterpart of [`vrf_emit_withdraw`].
pub fn vrf_emit_withdraw_v6(exporter: &VrfExporter, prefix: ipnet::Ipv6Net) {
    let _ = exporter.tx.send(BgpGlobalMsg::WithdrawExportV6 {
        vrf: exporter.name.clone(),
        prefix,
    });
}

/// Inverse of [`VrfExporter`] — references the global Bgp state
/// the shared `route_ipv4_update` path needs to fan a VPNv4
/// route out to every importing VRF task.
///
/// Carries `rib_known_vrfs` (for the RT intersection check) and
/// `vrf_registry` (for the per-VRF inbound senders). Both are
/// borrowed from the global `Bgp` for the span of one
/// `process_msg` call.
pub struct VrfImportDispatcher<'a> {
    pub rib_known_vrfs: &'a std::collections::BTreeMap<String, super::super::inst::RibKnownVrf>,
    pub vrf_registry: &'a std::collections::BTreeMap<String, super::spawn::BgpVrfHandle>,
}

/// Fan a freshly best-path-selected VPNv4 route out to every
/// VRF whose `import_rts_v4` intersects the route's RT extcomms.
/// Called from the shared `route_ipv4_update` after
/// `shard.update(Some(rd), ...)` returns. `label = 0` means
/// "no per-VRF label" — the receiving VRF treats it the same way
/// the Export side does (skip the install).
///
/// `skip_vrf` names the VRF the route originated from on the
/// local-leak path (`process_vrf_global_msg::Export`). It's
/// excluded from the fan-out so a VRF whose import-RT set overlaps
/// its own export-RTs (e.g. `rt both 1:1`) doesn't re-import the
/// route it just exported. `None` on the remote-VPNv4 ingress path
/// (no originating local VRF).
pub fn dispatch_import_v4(
    dispatcher: &VrfImportDispatcher<'_>,
    rd: bgp_packet::RouteDistinguisher,
    prefix: ipnet::Ipv4Net,
    attr: &bgp_packet::BgpAttr,
    label: u32,
    transport: &[crate::rib::nht::ResolvedNexthop],
    skip_vrf: Option<&str>,
) {
    let matches =
        super::super::inst::import_targets(dispatcher.rib_known_vrfs, &attr.ecom, skip_vrf);
    for vrf_name in matches {
        let Some(handle) = dispatcher.vrf_registry.get(&vrf_name) else {
            continue;
        };
        let _ = handle.inbox.send(BgpVrfMsg::ImportV4 {
            rd,
            prefix,
            attr: attr.clone(),
            label,
            transport: transport.to_vec(),
        });
    }
}

/// Inverse of [`dispatch_import_v4`]. Floods
/// `BgpVrfMsg::WithdrawImport` to every VRF whose
/// `import_rts_v4` matches; the receiver decides whether the
/// matching imported route is one it actually holds. `skip_vrf`
/// is excluded for the same self-import reason as
/// [`dispatch_import_v4`].
pub fn dispatch_withdraw_import_v4(
    dispatcher: &VrfImportDispatcher<'_>,
    rd: bgp_packet::RouteDistinguisher,
    prefix: ipnet::Ipv4Net,
    attr: &bgp_packet::BgpAttr,
    skip_vrf: Option<&str>,
) {
    let matches =
        super::super::inst::import_targets(dispatcher.rib_known_vrfs, &attr.ecom, skip_vrf);
    for vrf_name in matches {
        let Some(handle) = dispatcher.vrf_registry.get(&vrf_name) else {
            continue;
        };
        let _ = handle.inbox.send(BgpVrfMsg::WithdrawImport { rd, prefix });
    }
}

/// VPNv6 counterpart of [`dispatch_import_v4`] — fan a VPNv6 route out
/// to every VRF whose `import_rts_v6` intersects the route's RTs
/// (minus `skip_vrf`).
pub fn dispatch_import_v6(
    dispatcher: &VrfImportDispatcher<'_>,
    rd: bgp_packet::RouteDistinguisher,
    prefix: ipnet::Ipv6Net,
    attr: &bgp_packet::BgpAttr,
    label: u32,
    transport: &[crate::rib::nht::ResolvedNexthop],
    skip_vrf: Option<&str>,
) {
    let matches =
        super::super::inst::import_targets_v6(dispatcher.rib_known_vrfs, &attr.ecom, skip_vrf);
    for vrf_name in matches {
        let Some(handle) = dispatcher.vrf_registry.get(&vrf_name) else {
            continue;
        };
        let _ = handle.inbox.send(BgpVrfMsg::ImportV6 {
            rd,
            prefix,
            attr: attr.clone(),
            label,
            transport: transport.to_vec(),
        });
    }
}

/// VPNv6 counterpart of [`dispatch_withdraw_import_v4`].
pub fn dispatch_withdraw_import_v6(
    dispatcher: &VrfImportDispatcher<'_>,
    rd: bgp_packet::RouteDistinguisher,
    prefix: ipnet::Ipv6Net,
    attr: &bgp_packet::BgpAttr,
    skip_vrf: Option<&str>,
) {
    let matches =
        super::super::inst::import_targets_v6(dispatcher.rib_known_vrfs, &attr.ecom, skip_vrf);
    for vrf_name in matches {
        let Some(handle) = dispatcher.vrf_registry.get(&vrf_name) else {
            continue;
        };
        let _ = handle
            .inbox
            .send(BgpVrfMsg::WithdrawImportV6 { rd, prefix });
    }
}

/// Mirror a MUP (SAFI 85) best-path — or its withdrawal — into the
/// per-VRF tasks so `show bgp vrf <name> mup` reflects it. A route reaches
/// a VRF two ways, mirroring VPNv4/v6:
///   * **RT import** — every VRF whose `mup_import_rts` intersects the
///     route's RT extcomms (cross-VRF import + peer-learned routes).
///   * **RD origin** — when `origin_vrf` is `Some`, the VRF that locally
///     originated the route (its `rd` equals the route's RD) always
///     receives it, *regardless of route-targets*, because the route is
///     conceptually born in that VRF (an N6/N3 ST route, or a per-VRF
///     DSD/ISD segment route). The receive path passes `None` — a
///     peer-learned route has no local originating VRF — so it keys purely
///     on RTs; the originate path passes the RD-matched VRF name.
///
/// The per-VRF MUP RIB is authoritative for its own imported set (it owns
/// best-path selection); the global `Bgp` Loc-RIB stays the authoritative
/// advertiser. On withdrawal (`best` is `None`) the route's RTs are no
/// longer available, so `BgpVrfMsg::MupWithdraw` is flooded to every VRF —
/// the per-VRF removal is idempotent, so a VRF that never held the prefix
/// simply ignores it (this covers the RD-origin VRF too).
pub fn dispatch_mup(
    dispatcher: &VrfImportDispatcher<'_>,
    rd: bgp_packet::RouteDistinguisher,
    prefix: &bgp_packet::MupPrefix,
    best: Option<&super::super::route::BgpRib>,
    origin_vrf: Option<&str>,
) {
    match best {
        Some(rib) => {
            let targets = super::super::inst::mup_dispatch_targets(
                dispatcher.rib_known_vrfs,
                &rib.attr.ecom,
                origin_vrf,
            );
            for vrf_name in targets {
                let Some(handle) = dispatcher.vrf_registry.get(&vrf_name) else {
                    continue;
                };
                let _ = handle.inbox.send(BgpVrfMsg::MupUpdate {
                    rd,
                    prefix: prefix.clone(),
                    rib: rib.clone(),
                });
            }
        }
        None => {
            for handle in dispatcher.vrf_registry.values() {
                let _ = handle.inbox.send(BgpVrfMsg::MupWithdraw {
                    rd,
                    prefix: prefix.clone(),
                });
            }
        }
    }
}

/// The VRFs a PFCP session should originate ST routes in: every VRF whose
/// `afi-safi mup route {st1|st2}` binding (`srv6_mobile.network_instance`)
/// matches the session's Network Instance, paired with its resolved direction
/// (st1 = Encapsulation / st2 = Decapsulation) and st2 Direct-segment
/// ext-comm. This is the dual-ST fan-out: one NI bound by both an st1 and an
/// st2 VRF yields two targets. Pure (no I/O) so the correlation is unit
/// testable; [`dispatch_mup_session`] turns each target into a `MupOriginate`.
pub fn mup_session_targets(
    vrfs: &std::collections::BTreeMap<String, super::super::vrf_config::BgpVrfConfig>,
    session: &crate::mup_c::session::MupSession,
) -> Vec<(
    String,
    super::super::vrf_config::MupSrv6Direction,
    Option<bgp_packet::RouteDistinguisher>,
)> {
    let Some(ni) = session.network_instance.as_deref() else {
        return Vec::new();
    };
    vrfs.iter()
        .filter_map(|(name, cfg)| {
            let sm = cfg.mobile_uplane.srv6_mobile.as_ref()?;
            if sm.network_instance.as_deref() != Some(ni) {
                return None;
            }
            Some((name.clone(), sm.direction, sm.mup_ext_comm))
        })
        .collect()
}

/// VRF-first MUP session dispatch: send each VRF that [`mup_session_targets`]
/// matches a `MupOriginate` with its resolved direction + st2 Direct-segment
/// ext-comm. The per-VRF task builds the RD-free ST NLRI and exports it back
/// via `MupExport`; the global export handler stamps the RD / export-RTs /
/// controller next-hop. One session can fan out to several VRFs (an st1 and an
/// st2 VRF sharing the NI). Replaces the old global `build_mup_origination` +
/// `originate_mup_route`.
pub fn dispatch_mup_session(
    vrfs: &std::collections::BTreeMap<String, super::super::vrf_config::BgpVrfConfig>,
    vrf_registry: &std::collections::BTreeMap<String, super::spawn::BgpVrfHandle>,
    session: &crate::mup_c::session::MupSession,
) {
    for (name, direction, ext_comm) in mup_session_targets(vrfs, session) {
        let Some(handle) = vrf_registry.get(&name) else {
            continue;
        };
        let _ = handle.inbox.send(BgpVrfMsg::MupOriginate {
            session: session.clone(),
            direction,
            ext_comm,
        });
    }
}

/// Withdraw the ST routes a PFCP session originated across all VRFs (Session
/// Deletion / association teardown). Broadcasts `MupWithdrawOriginate`; the
/// per-VRF removal is idempotent for a VRF that never originated for `seid`.
pub fn withdraw_mup_session(
    vrf_registry: &std::collections::BTreeMap<String, super::spawn::BgpVrfHandle>,
    seid: u64,
) {
    for handle in vrf_registry.values() {
        let _ = handle.inbox.send(BgpVrfMsg::MupWithdrawOriginate { seid });
    }
}

/// Per-rtype `remote_id` discriminator for redistribute-originated VRF
/// rows (matches the global `Bgp::redist_remote_id`), so connected /
/// static / IGP sources — and a `network` row at id 0 — coexist for
/// one prefix in the per-VRF shard without overwriting one another.
fn redist_remote_id(rtype: crate::rib::RibType) -> u32 {
    match rtype {
        crate::rib::RibType::Connected => 1,
        crate::rib::RibType::Static => 2,
        crate::rib::RibType::Ospf => 3,
        crate::rib::RibType::Isis => 4,
        crate::rib::RibType::Kernel => 5,
        _ => 0,
    }
}

/// Map a configured redistribute source to the RIB route type the
/// subscription filters on.
pub(super) fn redist_source_rtype(source: BgpRedistSource) -> crate::rib::RibType {
    match source {
        BgpRedistSource::Connected => crate::rib::RibType::Connected,
        BgpRedistSource::Static => crate::rib::RibType::Static,
        BgpRedistSource::Isis => crate::rib::RibType::Isis,
        BgpRedistSource::Ospf => crate::rib::RibType::Ospf,
    }
}

impl BgpVrf {
    /// Build a `BgpVrf` and the matching inbound sender. The
    /// caller (`spawn_bgp_vrf`) keeps the `BgpVrfInbox`, hands the
    /// `BgpVrf` to [`serve_vrf`], and stashes the inbox in a
    /// per-VRF registry so cross-task messages can locate this
    /// task.
    pub fn new(
        name: String,
        ctx: ProtoContext,
        router_id: Ipv4Addr,
        asn: u32,
        label: u32,
        global_tx: UnboundedSender<BgpGlobalMsg>,
        rib_rx: UnboundedReceiver<super::super::super::rib::api::RibRx>,
    ) -> (Self, BgpVrfInbox) {
        let (inbox_tx, global_rx) = mpsc::unbounded_channel();
        let (tx, rx) = mpsc::channel(8192);
        let vrf = Self {
            name,
            ctx,
            peers: PeerMap::new(),
            local_rib: LocalRib::default(),
            shard: BgpShard::default(),
            router_id,
            // Default unset; `spawn_bgp_vrf` sets it from the VRF config.
            rd: None,
            cm: ConfigChannel::new(),
            show: ShowChannel::new(),
            global_tx,
            global_rx,
            rib_rx,
            tx,
            rx,
            asn,
            label,
            // Default off; `spawn_bgp_vrf` sets it from the VRF config.
            inter_as_hybrid: false,
            attr_store: BgpAttrStore::new(),
            update_groups: super::super::update_group::empty_map(),
            interface_addrs: InterfaceAddrs::new(),
            transport_v4: std::collections::BTreeMap::new(),
            transport_v6: std::collections::BTreeMap::new(),
            color_policy: Default::default(),
            flex_algo_srv6_routes: Default::default(),
            mup_originated: std::collections::BTreeMap::new(),
        };
        (vrf, inbox_tx)
    }

    /// Withdraw every controller ST route this VRF exported for `seid`: emit a
    /// `WithdrawMupExport` for each tracked RD-free prefix so the global
    /// SAFI-85 RIB removes it and re-runs best-path. No-op when nothing was
    /// originated for the session.
    fn withdraw_mup_originate(&mut self, seid: u64) {
        let Some(prefixes) = self.mup_originated.remove(&seid) else {
            return;
        };
        for prefix in prefixes {
            let _ = self.global_tx.send(BgpGlobalMsg::WithdrawMupExport {
                vrf: self.name.clone(),
                prefix,
            });
        }
    }

    /// Drive the per-VRF task. The loop exits cleanly when the
    /// global task sends [`BgpVrfMsg::Shutdown`] or when the
    /// inbound channel is closed (i.e. every sender — the global
    /// task plus any per-peer holds — has dropped).
    pub async fn event_loop(&mut self) {
        loop {
            tokio::select! {
                msg = self.global_rx.recv() => {
                    match msg {
                        Some(BgpVrfMsg::Shutdown) => {
                            tracing::info!(vrf = %self.name, "bgp vrf: shutdown");
                            break;
                        }
                        Some(other) => self.process_global_msg(other),
                        None => {
                            // All senders dropped — the global task
                            // exited without sending Shutdown.
                            tracing::info!(
                                vrf = %self.name,
                                "bgp vrf: inbound channel closed; exiting",
                            );
                            break;
                        }
                    }
                }
                _msg = self.cm.rx.recv() => {
                    // CM dispatch from /router/bgp/vrf/<name>/...
                    // arrives once `spawn_bgp_vrf` registers the
                    // path handler. Drained but ignored when no
                    // consumer is wired yet — keeps the select!
                    // arm from livelocking.
                }
                Some(msg) = self.rib_rx.recv() => {
                    // Redistributed routes streamed back from the RIB
                    // (RibRx::RouteAdd/RouteDel for the connected/static
                    // sources this VRF subscribed to). A placeholder-ctx
                    // spawn holds a closed channel here, so this arm is
                    // inert until the kernel-ctx respawn provides a live
                    // subscription.
                    self.process_rib_msg(msg);
                }
                Some(msg) = self.show.rx.recv() => {
                    // `show bgp vrf <name> …` — the manager stripped the
                    // `vrf <name>` selector and redirected the plain
                    // command here; render against this VRF's RIB/peers.
                    crate::bgp::show::process_vrf_show(self, msg).await;
                }
                Some(msg) = self.rx.recv() => {
                    self.process_msg(msg);
                }
            }
        }
    }

    /// Handle a per-VRF FSM event off `self.rx`. Wires the same
    /// set the global `Bgp::process_msg` handles — minus `Accept`
    /// (passive accept lives at the global task and is forwarded
    /// via `BgpVrfMsg::Accept`; the per-VRF path doesn't yet drive
    /// it because `peer::accept` is tied to the global `Bgp`).
    fn process_msg(&mut self, msg: Message) {
        use super::super::peer::{BgpTop, fsm};
        match msg {
            Message::Event(ident, event) => {
                // Build a fresh `VrfExporter` per call so the
                // shared `route_update_ipv4` path emits Export to
                // the global Bgp instance when this VRF's
                // best-path changes. The handle is the same
                // `global_tx` the per-VRF runtime already holds;
                // we wrap it with the VRF name so the receiver
                // can resolve RD/RT.
                let exporter = VrfExporter {
                    name: self.name.clone(),
                    tx: self.global_tx.clone(),
                    label: self.label,
                };
                let mut top = BgpTop {
                    router_id: &self.router_id,
                    srv6_ipv6_export: None,
                    local_rib: &mut self.local_rib,
                    shard: &mut self.shard,
                    tx: &self.tx,
                    rib_client: &self.ctx.rib,
                    attr_store: &mut self.attr_store,
                    update_groups: &mut self.update_groups,
                    interface_addrs: &self.interface_addrs,
                    vrf_export: Some(&exporter),
                    // Color → Flex-Algo binding is a default-VRF
                    // concept today; per-VRF support is a follow-up.
                    color_policy: Some(&self.color_policy),
                    flex_algo_routes: None,
                    flex_algo_srv6_routes: Some(&self.flex_algo_srv6_routes),
                    // Per-VRF tasks never receive VPNv4 NLRI directly,
                    // so no import dispatcher to thread through.
                    vrf_import: None,
                    nexthop_cache: None,
                    vrf_transport_v4: Some(&self.transport_v4),
                    vrf_transport_v6: Some(&self.transport_v6),
                    central_label_alloc: None,
                };
                // Per-VRF tasks don't drive the global shard pool (their
                // RIB is the VRF's own); ingest stays synchronous.
                fsm(&mut top, &mut self.peers, ident, event, None);
            }
            Message::Accept(_, _) => {
                // Active-connect path is driven by `Event(...)` from
                // peer-side timers; the global Bgp's accept
                // dispatcher routes passive connections to a VRF
                // via `BgpVrfMsg::Accept`, but `peer::accept` is
                // tied to `&mut Bgp` — refactoring it for per-VRF
                // is a follow-up. Drop here so the channel doesn't
                // accumulate stale Accepts if `peer.rs::accept`
                // ever gains a path that sends into `vrf.tx`.
                tracing::debug!(
                    vrf = %self.name,
                    "bgp vrf: ignored Accept on vrf.tx (active-only path)",
                );
            }
            Message::FlushUpdateGroupIpv4(group_id) => {
                super::super::update_group::flush_ipv4(
                    &mut self.update_groups,
                    &mut self.peers,
                    &self.tx,
                    &group_id,
                    &self.interface_addrs,
                );
            }
            Message::FlushUpdateGroupIpv6(group_id) => {
                super::super::update_group::flush_ipv6(
                    &mut self.update_groups,
                    &mut self.peers,
                    &self.tx,
                    &group_id,
                );
            }
            Message::FlushDoneIpv4(group_id, deltas) => {
                super::super::update_group::flush_done_ipv4(
                    &mut self.update_groups,
                    &mut self.peers,
                    &self.tx,
                    &group_id,
                    deltas,
                    &self.interface_addrs,
                );
            }
            Message::FlushDoneIpv6(group_id, deltas) => {
                super::super::update_group::flush_done_ipv6(
                    &mut self.update_groups,
                    &mut self.peers,
                    &self.tx,
                    &group_id,
                    deltas,
                );
            }
            Message::BgpLs { .. } => {
                // BGP-LS (RFC 9552) is produced and stored only by the
                // global BGP instance — per-VRF tasks never see it.
            }
            Message::MupC(_) => {
                // The MUP controller reports only to the global BGP
                // instance (it is handed the global `tx`); per-VRF tasks
                // never see `MupC`.
            }
            Message::Relisten => {
                // `router bgp port` is a global-instance knob; only the
                // global event loop queues (and handles) Relisten.
                // Per-VRF tasks keep their default-port listeners.
            }
        }
    }

    /// Insert an imported VPNv4 route into the per-VRF
    /// IPv4 unicast LocRIB and fan out to CE peers. `attr` is
    /// re-interned in the per-VRF `attr_store`, the VPNv4
    /// next-hop is rewritten to the VRF's router-id
    /// (next-hop-self — CE peers cannot reach the PE address
    /// the original carried), and the BgpRib lands with
    /// `typ: Originated` because there's no peer-side ident
    /// behind the import.
    ///
    /// After best-path runs, the shared `route_advertise_to_peers`
    /// helper flows the winner out to every Established CE peer
    /// with (AFI=Ip, SAFI=Unicast). The BgpTop hands
    /// `vrf_export: None` so the export hook in
    /// `route_ipv4_update` doesn't re-emit the imported route
    /// back to the global instance — VPNv4 round-trip would be
    /// a loop.
    fn handle_import_v4(
        &mut self,
        rd: bgp_packet::RouteDistinguisher,
        prefix: ipnet::Ipv4Net,
        mut attr: bgp_packet::BgpAttr,
        label: u32,
        transport: &[crate::rib::nht::ResolvedNexthop],
    ) {
        // Rewrite the next-hop to "self" (the VRF's router-id)
        // so CE peers receive a reachable v4 address.
        attr.nexthop = Some(bgp_packet::BgpNexthop::Ipv4(self.router_id));
        let interned = self.shard.intern(attr);

        let label_obj = if label != 0 {
            Some(bgp_packet::Label {
                label,
                exp: 0,
                bos: true,
            })
        } else {
            None
        };

        let rib = super::super::route::BgpRib {
            remote_id: 0,
            local_id: 0,
            attr: interned,
            // Originated/imported VRF rows carry the ORIGINATED_PEER
            // sentinel, NOT 0: a literal 0 collides with the PeerMap index
            // of whatever CE peer occupies slot 0 (a lone PE-CE peer is
            // index 0), and the advertise-path split-horizon
            // (`rib.ident == peer.ident`) would then silently drop this
            // imported route toward that CE — breaking Inter-AS Option A,
            // where the ASBR must re-advertise VPNv4-imported routes over
            // its per-VRF PE-CE eBGP session to the other ASBR.
            ident: super::super::route::ORIGINATED_PEER,
            router_id: self.router_id,
            weight: 0,
            typ: super::super::route::BgpRibType::Originated,
            best_path: false,
            best_reason: super::super::route::Reason::Default,
            label: label_obj,
            local_label: None,
            // v4-unicast rows in LocRIB don't read the
            // Vpnv4-shaped `nexthop` slot; FIB install pulls
            // from `attr.nexthop` set above.
            nexthop: None,
            nexthop_reachable: true,
            enhe_egress: None,
            stale: false,
            esi: None,
            vrf_transit_only: false,
            smet_flags: 0,
            igmp_max_resp_time: 0,
            ingress_region: None,
        };

        let (_, selected, _gen) = self.shard.update(None, prefix, rib);
        let winners = selected.len();

        // Persist the resolved transport for this prefix so `fib_install`
        // builds the labelled tunnel entry whenever the imported route
        // wins best-path — now, or after a competing CE route later
        // withdraws. An empty transport (unresolved) clears it.
        if transport.is_empty() {
            self.transport_v4.remove(&prefix);
        } else {
            self.transport_v4.insert(prefix, transport.to_vec());
        }

        let mut top = super::super::peer::BgpTop {
            router_id: &self.router_id,
            srv6_ipv6_export: None,
            local_rib: &mut self.local_rib,
            shard: &mut self.shard,
            tx: &self.tx,
            rib_client: &self.ctx.rib,
            attr_store: &mut self.attr_store,
            update_groups: &mut self.update_groups,
            interface_addrs: &self.interface_addrs,
            // No re-export of imported routes: a VPNv4-from-RD
            // re-emitted as a VPNv4-with-same-RD would loop.
            vrf_export: None,
            color_policy: Some(&self.color_policy),
            flex_algo_routes: None,
            flex_algo_srv6_routes: Some(&self.flex_algo_srv6_routes),
            vrf_import: None,
            nexthop_cache: None,
            vrf_transport_v4: Some(&self.transport_v4),
            vrf_transport_v6: Some(&self.transport_v6),
            central_label_alloc: None,
        };
        super::super::route::route_advertise_to_peers(
            None,
            prefix,
            &selected,
            /* source */ 0,
            &mut top,
            &mut self.peers,
        );

        // Single VRF FIB install path: `fib_install_v4` programs the
        // current best-path winner — the imported route's labelled
        // tunnel entry (via `vrf_transport_v4`) when it wins, or a CE
        // route's plain entry when that wins, or a withdraw when
        // neither. The VRF-bound `ctx.rib` lands it in the VRF table;
        // a placeholder (no-kernel) context's parked client no-ops.
        super::super::route::fib_install_v4(&top, prefix, &selected);

        // Inter-AS Option AB: relay this imported route back into the
        // global VPNv4 table (toward our PEs and the peer ASBR over the
        // single MP-eBGP session). Ordinary VRFs leave `inter_as_hybrid`
        // off and never re-export an import — the explicit hook here is
        // needed because the import path bypasses `route_update_ipv4`,
        // where the normal VRF→global export fires. The re-import loop is
        // broken by `dispatch_import_v4`'s `skip_vrf` (this VRF is
        // excluded from its own export's fan-out) and by eBGP AS-path.
        if self.inter_as_hybrid {
            let exporter = VrfExporter {
                name: self.name.clone(),
                tx: self.global_tx.clone(),
                label: self.label,
            };
            match selected.first() {
                Some(winner) => {
                    vrf_emit_export(&exporter, prefix, &attr_without_route_targets(&winner.attr))
                }
                None => vrf_emit_withdraw(&exporter, prefix),
            }
        }

        tracing::info!(
            vrf = %self.name,
            %prefix,
            rd = %rd,
            label,
            winners,
            "bgp vrf: ImportV4 written to LocRIB and advertised to CE peers",
        );
    }

    /// Drop an imported route from the per-VRF LocRIB
    /// and advertise the withdraw (or a replacement winner) to
    /// CE peers. Symmetric with [`Self::handle_import_v4`].
    fn handle_withdraw_import(
        &mut self,
        rd: bgp_packet::RouteDistinguisher,
        prefix: ipnet::Ipv4Net,
    ) {
        let removed = self
            .shard
            .remove(None, prefix, 0, super::super::route::ORIGINATED_PEER);
        let selected = self.shard.select_best_path(prefix);
        let removed_n = removed.len();
        let winners = selected.len();

        // The imported route is gone, so drop its stored transport.
        self.transport_v4.remove(&prefix);

        let mut top = super::super::peer::BgpTop {
            router_id: &self.router_id,
            srv6_ipv6_export: None,
            local_rib: &mut self.local_rib,
            shard: &mut self.shard,
            tx: &self.tx,
            rib_client: &self.ctx.rib,
            attr_store: &mut self.attr_store,
            update_groups: &mut self.update_groups,
            interface_addrs: &self.interface_addrs,
            vrf_export: None,
            color_policy: Some(&self.color_policy),
            flex_algo_routes: None,
            flex_algo_srv6_routes: Some(&self.flex_algo_srv6_routes),
            vrf_import: None,
            nexthop_cache: None,
            vrf_transport_v4: Some(&self.transport_v4),
            vrf_transport_v6: Some(&self.transport_v6),
            central_label_alloc: None,
        };
        super::super::route::route_advertise_to_peers(
            None,
            prefix,
            &selected,
            /* source */ 0,
            &mut top,
            &mut self.peers,
        );

        // Reconcile the VRF FIB against the *new* best-path. If a CE
        // route was runner-up it now wins and gets installed; if there's
        // no winner left, `fib_install_v4` emits the withdraw. (The old
        // code unconditionally deleted, dropping a now-winning CE route.)
        super::super::route::fib_install_v4(&top, prefix, &selected);

        // Inter-AS Option AB: mirror `handle_import_v4` — re-export the
        // replacement winner, or withdraw the global VPNv4 row when the
        // last candidate is gone.
        if self.inter_as_hybrid {
            let exporter = VrfExporter {
                name: self.name.clone(),
                tx: self.global_tx.clone(),
                label: self.label,
            };
            match selected.first() {
                Some(winner) => {
                    vrf_emit_export(&exporter, prefix, &attr_without_route_targets(&winner.attr))
                }
                None => vrf_emit_withdraw(&exporter, prefix),
            }
        }

        tracing::info!(
            vrf = %self.name,
            %prefix,
            rd = %rd,
            removed = removed_n,
            winners,
            "bgp vrf: WithdrawImport removed from LocRIB and withdrawn from CE peers",
        );
    }

    /// VPNv6 counterpart of [`Self::handle_import_v4`]. Inserts the
    /// imported route into the VRF's IPv6 unicast Loc-RIB and fans it
    /// out to CE peers. Unlike v4 we don't pre-stamp a next-hop — the
    /// VRF router-id is IPv4 and can't serve as a v6 next-hop, so
    /// `route_update_ipv6` applies v6 next-hop-self (the CE-facing
    /// session-local address) at advertise time since the row is
    /// `Originated`. The direct Loc-RIB insert bypasses the inbound
    /// `route_ipv6_update` path, so the VRF→global export hook never
    /// fires for an imported route (no VPNv6 round-trip loop).
    fn handle_import_v6(
        &mut self,
        rd: bgp_packet::RouteDistinguisher,
        prefix: ipnet::Ipv6Net,
        mut attr: bgp_packet::BgpAttr,
        label: u32,
        transport: &[crate::rib::nht::ResolvedNexthop],
    ) {
        attr.nexthop = None;
        let interned = self.shard.intern(attr);

        let label_obj = if label != 0 {
            Some(bgp_packet::Label {
                label,
                exp: 0,
                bos: true,
            })
        } else {
            None
        };

        let rib = super::super::route::BgpRib {
            remote_id: 0,
            local_id: 0,
            attr: interned,
            // Originated/imported VRF rows carry the ORIGINATED_PEER
            // sentinel, NOT 0: a literal 0 collides with the PeerMap index
            // of whatever CE peer occupies slot 0 (a lone PE-CE peer is
            // index 0), and the advertise-path split-horizon
            // (`rib.ident == peer.ident`) would then silently drop this
            // imported route toward that CE — breaking Inter-AS Option A,
            // where the ASBR must re-advertise VPNv4-imported routes over
            // its per-VRF PE-CE eBGP session to the other ASBR.
            ident: super::super::route::ORIGINATED_PEER,
            router_id: self.router_id,
            weight: 0,
            typ: super::super::route::BgpRibType::Originated,
            best_path: false,
            best_reason: super::super::route::Reason::Default,
            label: label_obj,
            local_label: None,
            nexthop: None,
            nexthop_reachable: true,
            enhe_egress: None,
            stale: false,
            esi: None,
            vrf_transit_only: false,
            smet_flags: 0,
            igmp_max_resp_time: 0,
            ingress_region: None,
        };

        let (_, selected, _gen) = self.shard.update_v6(prefix, rib);
        let winners = selected.len();

        // Persist the resolved transport (see `handle_import_v4`).
        if transport.is_empty() {
            self.transport_v6.remove(&prefix);
        } else {
            self.transport_v6.insert(prefix, transport.to_vec());
        }

        let mut top = super::super::peer::BgpTop {
            router_id: &self.router_id,
            srv6_ipv6_export: None,
            local_rib: &mut self.local_rib,
            shard: &mut self.shard,
            tx: &self.tx,
            rib_client: &self.ctx.rib,
            attr_store: &mut self.attr_store,
            update_groups: &mut self.update_groups,
            interface_addrs: &self.interface_addrs,
            vrf_export: None,
            color_policy: Some(&self.color_policy),
            flex_algo_routes: None,
            flex_algo_srv6_routes: Some(&self.flex_algo_srv6_routes),
            vrf_import: None,
            nexthop_cache: None,
            vrf_transport_v4: Some(&self.transport_v4),
            vrf_transport_v6: Some(&self.transport_v6),
            central_label_alloc: None,
        };
        super::super::route::route_advertise_to_peers_v6(
            prefix,
            &selected,
            &mut top,
            &mut self.peers,
        );

        // Single VRF FIB install path (see `handle_import_v4`).
        super::super::route::fib_install_v6(&top, prefix, &selected);

        // Inter-AS Option AB (VPNv6): re-export the imported route — see
        // `handle_import_v4`.
        if self.inter_as_hybrid {
            let exporter = VrfExporter {
                name: self.name.clone(),
                tx: self.global_tx.clone(),
                label: self.label,
            };
            match selected.first() {
                Some(winner) => {
                    vrf_emit_export_v6(&exporter, prefix, &attr_without_route_targets(&winner.attr))
                }
                None => vrf_emit_withdraw_v6(&exporter, prefix),
            }
        }

        tracing::info!(
            vrf = %self.name,
            %prefix,
            rd = %rd,
            label,
            winners,
            "bgp vrf: ImportV6 written to LocRIB and advertised to CE peers",
        );
    }

    /// VPNv6 counterpart of [`Self::handle_withdraw_import`].
    fn handle_withdraw_import_v6(
        &mut self,
        rd: bgp_packet::RouteDistinguisher,
        prefix: ipnet::Ipv6Net,
    ) {
        let removed = self
            .shard
            .remove_v6(prefix, 0, super::super::route::ORIGINATED_PEER);
        let selected = self.shard.select_best_path_v6(prefix);
        let removed_n = removed.len();
        let winners = selected.len();

        self.transport_v6.remove(&prefix);

        let mut top = super::super::peer::BgpTop {
            router_id: &self.router_id,
            srv6_ipv6_export: None,
            local_rib: &mut self.local_rib,
            shard: &mut self.shard,
            tx: &self.tx,
            rib_client: &self.ctx.rib,
            attr_store: &mut self.attr_store,
            update_groups: &mut self.update_groups,
            interface_addrs: &self.interface_addrs,
            vrf_export: None,
            color_policy: Some(&self.color_policy),
            flex_algo_routes: None,
            flex_algo_srv6_routes: Some(&self.flex_algo_srv6_routes),
            vrf_import: None,
            nexthop_cache: None,
            vrf_transport_v4: Some(&self.transport_v4),
            vrf_transport_v6: Some(&self.transport_v6),
            central_label_alloc: None,
        };
        super::super::route::route_advertise_to_peers_v6(
            prefix,
            &selected,
            &mut top,
            &mut self.peers,
        );

        // Reconcile against the new best-path (see `handle_withdraw_import`).
        super::super::route::fib_install_v6(&top, prefix, &selected);

        // Inter-AS Option AB (VPNv6): re-export the replacement winner or
        // withdraw the global row — see `handle_withdraw_import`.
        if self.inter_as_hybrid {
            let exporter = VrfExporter {
                name: self.name.clone(),
                tx: self.global_tx.clone(),
                label: self.label,
            };
            match selected.first() {
                Some(winner) => {
                    vrf_emit_export_v6(&exporter, prefix, &attr_without_route_targets(&winner.attr))
                }
                None => vrf_emit_withdraw_v6(&exporter, prefix),
            }
        }

        tracing::info!(
            vrf = %self.name,
            %prefix,
            rd = %rd,
            removed = removed_n,
            winners,
            "bgp vrf: WithdrawImportV6 removed from LocRIB and withdrawn from CE peers",
        );
    }

    /// Originate one `network <p>` self-route into this VRF's
    /// Loc-RIB as an `Originated` row and emit `Export` so the
    /// global instance promotes it to a VPNv4 advertisement. Shared
    /// by the spawn-time `materialize_self_originated_networks` and
    /// the dynamic [`BgpVrfMsg::OriginateNetwork`] path (a `network`
    /// added to an already-running VRF).
    pub fn originate_self_network_v4(&mut self, prefix: ipnet::Ipv4Net) {
        use bgp_packet::{BgpAttr, BgpNexthop, Origin};

        // Build a self-originated attr: IGP origin, next-hop-self.
        // Local-pref / weight default to the same values
        // `BgpAttr::new` uses for the global `network` path.
        let mut attr = BgpAttr::new();
        attr.origin = Some(Origin::Igp);
        attr.nexthop = Some(BgpNexthop::Ipv4(self.router_id));
        let interned = self.shard.intern(attr);

        let rib = self.self_originated_rib(interned);
        let (_, selected, _) = self.shard.update(None, prefix, rib);
        // A freshly-inserted self-originated row always wins when
        // it's the only candidate; emit Export for whoever won.
        if let Some(winner) = selected.first() {
            let exporter = self.exporter();
            vrf_emit_export(&exporter, prefix, &winner.attr);
        }
    }

    /// Inverse of [`Self::originate_self_network_v4`]: drop the
    /// self-originated row (ident 0 / remote 0) for `prefix`,
    /// re-run best-path, and either re-export the surviving winner
    /// or emit `WithdrawExport` when nothing else carries the
    /// prefix. Driven by [`BgpVrfMsg::WithdrawNetwork`] when a
    /// `network` is removed from a running VRF.
    pub fn withdraw_self_network_v4(&mut self, prefix: ipnet::Ipv4Net) {
        let removed = self.shard.remove(None, prefix, 0, 0);
        if removed.is_empty() {
            return;
        }
        let exporter = self.exporter();
        // `remove` does not re-run best-path; do it explicitly so a
        // surviving candidate (e.g. an imported route on the same
        // prefix) is re-advertised instead of withdrawn.
        match self.shard.select_best_path(prefix).first() {
            Some(winner) => vrf_emit_export(&exporter, prefix, &winner.attr),
            None => vrf_emit_withdraw(&exporter, prefix),
        }
    }

    /// IPv6 counterpart of [`Self::originate_self_network_v4`]. The
    /// next-hop is a placeholder — the global re-advertise rewrites
    /// it to next-hop-self in `route_update_ipv6`.
    pub fn originate_self_network_v6(&mut self, prefix: ipnet::Ipv6Net) {
        use bgp_packet::{BgpAttr, BgpNexthop, Origin};

        let mut attr = BgpAttr::new();
        attr.origin = Some(Origin::Igp);
        attr.nexthop = Some(BgpNexthop::Ipv6(std::net::Ipv6Addr::UNSPECIFIED));
        let interned = self.shard.intern(attr);

        let rib = self.self_originated_rib(interned);
        let (_, selected, _) = self.shard.update_v6(prefix, rib);
        if let Some(winner) = selected.first() {
            let exporter = self.exporter();
            vrf_emit_export_v6(&exporter, prefix, &winner.attr);
        }
    }

    /// IPv6 counterpart of [`Self::withdraw_self_network_v4`].
    pub fn withdraw_self_network_v6(&mut self, prefix: ipnet::Ipv6Net) {
        let removed = self.shard.remove_v6(prefix, 0, 0);
        if removed.is_empty() {
            return;
        }
        let exporter = self.exporter();
        match self.shard.select_best_path_v6(prefix).first() {
            Some(winner) => vrf_emit_export_v6(&exporter, prefix, &winner.attr),
            None => vrf_emit_withdraw_v6(&exporter, prefix),
        }
    }

    /// Tell the RIB to start redistributing `source` for `afi` into
    /// this VRF. The RIB resolves our subscriber by proto name
    /// (`bgp:vrf:<name>`, registered at spawn) → its `vrf_id` (this
    /// VRF's kernel table id) → walks `vrf_tables[table_id]` and
    /// streams the matching routes back on `rib_rx`. Empty subtype set
    /// = wildcard (every subtype under the rtype). `pub(super)` so
    /// `spawn_bgp_vrf` can replay the staged config at spawn time.
    pub(super) fn redist_subscribe(&self, afi: crate::rib::RedistAfi, source: BgpRedistSource) {
        let _ = self.ctx.rib.send(crate::rib::Message::RedistAdd {
            proto: format!("bgp:vrf:{}", self.name),
            afi,
            rtype: redist_source_rtype(source),
            subtypes: std::collections::BTreeSet::new(),
        });
    }

    /// Inverse of [`Self::redist_subscribe`]: drop the redistribute
    /// subscription. The RIB replays the matched prefixes as
    /// `RouteDel`, which `process_rib_msg` turns into withdraws — so no
    /// local sweep is needed here.
    fn redist_unsubscribe(&self, afi: crate::rib::RedistAfi, source: BgpRedistSource) {
        let _ = self.ctx.rib.send(crate::rib::Message::RedistDel {
            proto: format!("bgp:vrf:{}", self.name),
            afi,
            rtype: redist_source_rtype(source),
        });
    }

    /// Consume one RIB redistribute notification. Only the route
    /// add/del stream is relevant to a per-VRF redistribute subscriber;
    /// link / addr / router-id / EoR markers are ignored.
    fn process_rib_msg(&mut self, msg: crate::rib::api::RibRx) {
        use crate::rib::RouteBatch;
        use crate::rib::api::RibRx;
        match msg {
            RibRx::RouteAdd { rtype, routes, .. } => match routes {
                RouteBatch::V4(entries) => {
                    for e in entries {
                        self.redist_inject_v4(rtype, e.prefix, e.metric);
                    }
                }
                RouteBatch::V6(entries) => {
                    for e in entries {
                        self.redist_inject_v6(rtype, e.prefix, e.metric);
                    }
                }
            },
            RibRx::RouteDel { rtype, routes, .. } => match routes {
                RouteBatch::V4(entries) => {
                    for e in entries {
                        self.redist_withdraw_v4(rtype, e.prefix);
                    }
                }
                RouteBatch::V6(entries) => {
                    for e in entries {
                        self.redist_withdraw_v6(rtype, e.prefix);
                    }
                }
            },
            _ => {}
        }
    }

    /// Originate one redistributed IPv4 route into this VRF's Loc-RIB
    /// and export the winner to the global VPNv4 table. Mirrors
    /// [`Self::originate_self_network_v4`] but keyed by a redistribute
    /// identity (so it coexists with a `network` row for the same
    /// prefix) and carries the source RIB cost as MED.
    fn redist_inject_v4(
        &mut self,
        rtype: crate::rib::RibType,
        prefix: ipnet::Ipv4Net,
        metric: u32,
    ) {
        use bgp_packet::{BgpAttr, BgpNexthop, Med, Origin};

        let mut attr = BgpAttr::new();
        attr.origin = Some(Origin::Incomplete);
        attr.nexthop = Some(BgpNexthop::Ipv4(self.router_id));
        attr.med = Some(Med::new(metric));
        let interned = self.shard.intern(attr);

        let rib = self.redist_originated_rib(interned, rtype);
        let (_, selected, _) = self.shard.update(None, prefix, rib);
        if let Some(winner) = selected.first() {
            let exporter = self.exporter();
            vrf_emit_export(&exporter, prefix, &winner.attr);
        }
    }

    /// Inverse of [`Self::redist_inject_v4`].
    fn redist_withdraw_v4(&mut self, rtype: crate::rib::RibType, prefix: ipnet::Ipv4Net) {
        let removed = self
            .shard
            .remove(None, prefix, redist_remote_id(rtype), ORIGINATED_PEER);
        if removed.is_empty() {
            return;
        }
        let exporter = self.exporter();
        match self.shard.select_best_path(prefix).first() {
            Some(winner) => vrf_emit_export(&exporter, prefix, &winner.attr),
            None => vrf_emit_withdraw(&exporter, prefix),
        }
    }

    /// IPv6 counterpart of [`Self::redist_inject_v4`]. The next-hop is a
    /// placeholder — the global re-advertise rewrites it to
    /// next-hop-self in `route_update_ipv6`.
    fn redist_inject_v6(
        &mut self,
        rtype: crate::rib::RibType,
        prefix: ipnet::Ipv6Net,
        metric: u32,
    ) {
        use bgp_packet::{BgpAttr, BgpNexthop, Med, Origin};

        let mut attr = BgpAttr::new();
        attr.origin = Some(Origin::Incomplete);
        attr.nexthop = Some(BgpNexthop::Ipv6(std::net::Ipv6Addr::UNSPECIFIED));
        attr.med = Some(Med::new(metric));
        let interned = self.shard.intern(attr);

        let rib = self.redist_originated_rib(interned, rtype);
        let (_, selected, _) = self.shard.update_v6(prefix, rib);
        if let Some(winner) = selected.first() {
            let exporter = self.exporter();
            vrf_emit_export_v6(&exporter, prefix, &winner.attr);
        }
    }

    /// IPv6 counterpart of [`Self::redist_withdraw_v4`].
    fn redist_withdraw_v6(&mut self, rtype: crate::rib::RibType, prefix: ipnet::Ipv6Net) {
        let removed = self
            .shard
            .remove_v6(prefix, redist_remote_id(rtype), ORIGINATED_PEER);
        if removed.is_empty() {
            return;
        }
        let exporter = self.exporter();
        match self.shard.select_best_path_v6(prefix).first() {
            Some(winner) => vrf_emit_export_v6(&exporter, prefix, &winner.attr),
            None => vrf_emit_withdraw_v6(&exporter, prefix),
        }
    }

    /// A redistribute-originated [`BgpRib`]: the self-originated shape
    /// with a redistribute identity (ident `ORIGINATED_PEER`, per-rtype
    /// `remote_id`) so distinct sources — and a `network` row at
    /// id 0 — coexist for the same prefix without overwriting.
    fn redist_originated_rib(
        &self,
        attr: std::sync::Arc<bgp_packet::BgpAttr>,
        rtype: crate::rib::RibType,
    ) -> super::super::route::BgpRib {
        let mut rib = self.self_originated_rib(attr);
        rib.ident = ORIGINATED_PEER;
        rib.remote_id = redist_remote_id(rtype);
        rib
    }

    /// Build a fresh [`VrfExporter`] pointing at the global task.
    fn exporter(&self) -> VrfExporter {
        VrfExporter {
            name: self.name.clone(),
            tx: self.global_tx.clone(),
            label: self.label,
        }
    }

    /// A self-originated `BgpRib` (ident 0 / remote 0) carrying the
    /// interned `attr`. Identical shape for v4 and v6 — only the
    /// shard table the caller inserts into differs.
    fn self_originated_rib(
        &self,
        attr: std::sync::Arc<bgp_packet::BgpAttr>,
    ) -> super::super::route::BgpRib {
        super::super::route::BgpRib {
            remote_id: 0,
            local_id: 0,
            attr,
            ident: 0,
            router_id: self.router_id,
            weight: 32768,
            typ: super::super::route::BgpRibType::Originated,
            best_path: false,
            best_reason: super::super::route::Reason::Default,
            label: None,
            local_label: None,
            nexthop: None,
            nexthop_reachable: true,
            enhe_egress: None,
            stale: false,
            esi: None,
            vrf_transit_only: false,
            smet_flags: 0,
            igmp_max_resp_time: 0,
            ingress_region: None,
        }
    }

    /// Per-task handling of cross-task messages that aren't
    /// `Shutdown`.
    fn process_global_msg(&mut self, msg: BgpVrfMsg) {
        match msg {
            BgpVrfMsg::ColourSteering {
                color_policy,
                srv6_shadow,
            } => {
                // Mirror the global colour-steering state so this VRF's
                // FIB install can steer imported SRv6 L3VPN routes. No
                // re-install of existing routes here — the next best-path
                // / NHT churn re-runs `fib_install`; steady-state VPN
                // routes refresh on the SPF that changed the shadow.
                self.color_policy = color_policy;
                self.flex_algo_srv6_routes = srv6_shadow;
            }
            BgpVrfMsg::Accept(stream, sockaddr) => {
                // Passive accept for the per-VRF PE-CE session. The global
                // accept dispatcher routed this inbound connection here by
                // source IP; drive the same FSM path the global `accept`
                // does, but against this VRF's own `peers`. The active
                // connect path already runs the per-VRF FSM, so adding the
                // passive side lets two per-VRF speakers (e.g. two Inter-AS
                // MPLS/VPN Option A ASBRs peering inside a VRF) resolve a
                // §6.8 collision into Established — without it neither side's
                // outbound connect is ever accepted and the session is stuck.
                tracing::debug!(
                    vrf = %self.name,
                    peer = %sockaddr.ip(),
                    "bgp vrf: inbound Accept",
                );
                let peer_addr = sockaddr.ip();
                let scope_id = match sockaddr {
                    std::net::SocketAddr::V6(addr) if addr.scope_id() != 0 => Some(addr.scope_id()),
                    _ => None,
                };
                if let Some(stream) = super::super::peer::handle_peer_connection(
                    &mut self.peers,
                    peer_addr,
                    scope_id,
                    stream,
                ) {
                    // No matching peer in this VRF (listen-ranges aren't
                    // supported inside a VRF yet) — drop, closing the TCP.
                    drop(stream);
                }
            }
            BgpVrfMsg::ImportV4 {
                rd,
                prefix,
                attr,
                label,
                transport,
            } => {
                self.handle_import_v4(rd, prefix, attr, label, &transport);
            }
            BgpVrfMsg::WithdrawImport { rd, prefix } => {
                self.handle_withdraw_import(rd, prefix);
            }
            BgpVrfMsg::ImportV6 {
                rd,
                prefix,
                attr,
                label,
                transport,
            } => {
                self.handle_import_v6(rd, prefix, attr, label, &transport);
            }
            BgpVrfMsg::WithdrawImportV6 { rd, prefix } => {
                self.handle_withdraw_import_v6(rd, prefix);
            }
            BgpVrfMsg::OriginateNetwork { prefix } => {
                self.originate_self_network_v4(prefix);
            }
            BgpVrfMsg::WithdrawNetwork { prefix } => {
                self.withdraw_self_network_v4(prefix);
            }
            BgpVrfMsg::OriginateNetworkV6 { prefix } => {
                self.originate_self_network_v6(prefix);
            }
            BgpVrfMsg::WithdrawNetworkV6 { prefix } => {
                self.withdraw_self_network_v6(prefix);
            }
            BgpVrfMsg::RedistEnable { afi, source } => {
                self.redist_subscribe(afi, source);
            }
            BgpVrfMsg::RedistDisable { afi, source } => {
                self.redist_unsubscribe(afi, source);
            }
            // Authoritative per-VRF MUP import (RT-matched at the global
            // dispatch): insert the route as a candidate in this VRF's own
            // MUP RIB and best-path it. The VRF receives the global winner
            // per prefix, so best-path is single-candidate here, but the
            // table is authoritative — `show bgp vrf <name> mup` (redirected
            // here) reads the resulting `selected`. MUP has no CE peers and
            // no kernel FIB yet, so this neither re-advertises nor installs;
            // it owns the control-plane RIB only.
            //
            // The route is keyed under the VRF's *own* RD, not the message's
            // origin RD: a VRF holds its MUP routes under its own RD (the one
            // it would re-originate them with), exactly as an L3VPN VRF drops
            // the VPNv4 RD on import. So a cross-RD import (e.g. an ISD
            // originated under RD 65501:20, imported by a VRF whose rd is
            // 65501:10) lands under 65501:10 here. A VRF with no `rd` falls
            // back to the message RD.
            BgpVrfMsg::MupUpdate { rd, prefix, rib } => {
                let rd = self.rd.unwrap_or(rd);
                let _ = self
                    .local_rib
                    .mup
                    .entry(rd)
                    .or_default()
                    .update(prefix, rib);
            }
            BgpVrfMsg::MupWithdraw { rd, prefix } => {
                // Same own-RD scoping as MupUpdate. The VRF holds the single
                // dispatched winner per prefix, so a prefix-keyed removal
                // clears it; prune the per-RD table when it empties so an
                // empty RD never renders.
                let rd = self.rd.unwrap_or(rd);
                let empty = if let Some(table) = self.local_rib.mup.get_mut(&rd) {
                    table.cands.remove(&prefix);
                    table.selected.remove(&prefix);
                    table.cands.is_empty() && table.selected.is_empty()
                } else {
                    false
                };
                if empty {
                    self.local_rib.mup.remove(&rd);
                }
            }
            // VRF-first MUP origination: build the RD-free ST NLRI from the
            // dispatched session + resolved direction, and export it to the
            // global SAFI-85 RIB. The global export handler applies the RD,
            // export route-targets and controller next-hop; the resulting
            // route is mirrored back here (RT/RD-origin) so this VRF's own
            // `show bgp vrf <name> mup` reflects it. A Modification replaces:
            // withdraw the session's prior exports first.
            BgpVrfMsg::MupOriginate {
                session,
                direction,
                ext_comm,
            } => {
                self.withdraw_mup_originate(session.seid);
                if let Some((prefix, attr)) =
                    super::super::route::build_mup_st_route(&session, direction, ext_comm)
                {
                    self.mup_originated
                        .entry(session.seid)
                        .or_default()
                        .push(prefix.clone());
                    let _ = self.global_tx.send(BgpGlobalMsg::MupExport {
                        vrf: self.name.clone(),
                        prefix,
                        attr,
                    });
                }
            }
            BgpVrfMsg::MupWithdrawOriginate { seid } => {
                self.withdraw_mup_originate(seid);
            }
            BgpVrfMsg::Shutdown => unreachable!("handled in event_loop"),
        }
    }
}

/// Spawn the per-VRF event loop on its own tokio task. Mirrors
/// [`crate::bgp::inst::serve`] / [`crate::nd::inst::serve`].
pub fn serve_vrf(mut vrf: BgpVrf) -> Task<()> {
    Task::spawn(async move {
        vrf.event_loop().await;
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::sync::mpsc::unbounded_channel;

    use crate::rib::client::{ProtoId, RibClient, RibInbound};

    use super::*;

    fn test_ctx_for_vrf(table_id: u32, ifname: &str) -> ProtoContext {
        // Parked RibClient — the test doesn't exercise rib.send().
        let (inbound_tx, inbound_rx) = unbounded_channel::<RibInbound>();
        Box::leak(Box::new(inbound_rx));
        let rib = RibClient::new(inbound_tx, ProtoId::from_raw(0));
        ProtoContext::for_vrf(rib, table_id, ifname.to_string())
    }

    #[tokio::test]
    async fn shutdown_message_exits_event_loop_within_timeout() {
        // Lifecycle invariant: `Shutdown` on the inbound channel
        // makes `event_loop` return — without that contract,
        // `despawn_bgp_vrf` wouldn't be able to tear a VRF task
        // down cleanly.
        let (global_tx, _global_rx) = unbounded_channel::<BgpGlobalMsg>();
        let ctx = test_ctx_for_vrf(10, "vrf-test");
        let (_rib_tx, rib_rx) = mpsc::unbounded_channel();
        let (mut vrf, inbox) = BgpVrf::new(
            "vrf-test".to_string(),
            ctx,
            Ipv4Addr::UNSPECIFIED,
            65000,
            /* label */ 16,
            global_tx,
            rib_rx,
        );

        inbox.send(BgpVrfMsg::Shutdown).expect("inbound rx alive");

        // Two-second timeout: the loop should exit on the very
        // next `recv` call; a slow exit would indicate a deadlock
        // on the inbound channel.
        tokio::time::timeout(Duration::from_secs(2), vrf.event_loop())
            .await
            .expect("event_loop returns after Shutdown");
    }

    #[tokio::test]
    async fn inbox_drop_closes_event_loop() {
        // If every sender to the inbound channel is dropped, the
        // VRF task exits anyway — defensive cleanup so a buggy
        // caller that forgets to send `Shutdown` still doesn't
        // leak the task.
        let (global_tx, _global_rx) = unbounded_channel::<BgpGlobalMsg>();
        let ctx = test_ctx_for_vrf(11, "vrf-test2");
        let (_rib_tx, rib_rx) = mpsc::unbounded_channel();
        let (mut vrf, inbox) = BgpVrf::new(
            "vrf-test2".to_string(),
            ctx,
            Ipv4Addr::UNSPECIFIED,
            65000,
            /* label */ 16,
            global_tx,
            rib_rx,
        );

        drop(inbox);

        tokio::time::timeout(Duration::from_secs(2), vrf.event_loop())
            .await
            .expect("event_loop exits when inbox is dropped");
    }

    #[tokio::test]
    async fn vrf_emit_export_sends_export_msg_via_exporter() {
        // The free-function hook called from `route_update_ipv4`'s
        // post-best-path arm pushes an Export with the winner's
        // prefix + attr + label.
        let (tx, mut rx) = unbounded_channel::<BgpGlobalMsg>();
        let exporter = VrfExporter {
            name: "vrf-hook".to_string(),
            tx,
            label: 42,
        };
        let prefix: ipnet::Ipv4Net = "10.0.0.0/24".parse().unwrap();
        let attr = bgp_packet::BgpAttr::default();

        vrf_emit_export(&exporter, prefix, &attr);

        let msg = rx.try_recv().expect("Export pushed");
        match msg {
            BgpGlobalMsg::Export {
                vrf,
                prefix: p,
                attr: a,
                label,
            } => {
                assert_eq!(vrf, "vrf-hook");
                assert_eq!(p, prefix);
                assert_eq!(a, attr);
                assert_eq!(label, 42, "exporter's label is stamped onto Export");
            }
            other => panic!("expected Export, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn vrf_emit_withdraw_sends_withdraw_export_msg() {
        let (tx, mut rx) = unbounded_channel::<BgpGlobalMsg>();
        let exporter = VrfExporter {
            name: "vrf-hook2".to_string(),
            tx,
            label: 17,
        };
        let prefix: ipnet::Ipv4Net = "10.0.0.0/24".parse().unwrap();

        vrf_emit_withdraw(&exporter, prefix);

        let msg = rx.try_recv().expect("WithdrawExport pushed");
        match msg {
            BgpGlobalMsg::WithdrawExport { vrf, prefix: p } => {
                assert_eq!(vrf, "vrf-hook2");
                assert_eq!(p, prefix);
            }
            other => panic!("expected WithdrawExport, got {other:?}"),
        }
    }
}
