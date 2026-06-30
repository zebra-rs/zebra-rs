//! OSPFv3 YANG-path callback handlers.
//!
//! Sibling of v2's `config.rs`. Registers the
//! `/router/ospfv3/area/interface/*` handlers — `enable`,
//! `priority`, `hello-interval`, `dead-interval`,
//! `retransmit-interval`, `mtu-ignore`. The handler bodies mirror
//! v2 almost line-for-line; the generic helpers in `config.rs`
//! (`link_should_enable`, `apply_link_enable_transition`,
//! `ospf_link_get_mut_by_name`, `parse_area_id`, `ospf_hello_timer`)
//! make this possible without duplication.

use super::area::{AreaTypeKind, ExternalMetricType, NssaTranslatorRole, RedistEntry};
use super::config::{
    Callback, apply_link_enable_transition, area_no_summary_set, area_nssa_default_originate_set,
    area_nssa_suppress_fa_set, area_nssa_translator_role_set, area_type_set,
    config_ospf_bfd_detect_offload, config_ospf_bfd_echo_mode,
    config_ospf_bfd_echo_receive_interval, config_ospf_bfd_echo_transmit_interval,
    config_ospf_bfd_enable, config_ospf_bfd_min_neighbor_state,
    config_ospf_interface_bfd_detect_offload, config_ospf_interface_bfd_echo_mode,
    config_ospf_interface_bfd_echo_receive_interval,
    config_ospf_interface_bfd_echo_transmit_interval, config_ospf_interface_bfd_enable,
    config_ospf_interface_bfd_min_neighbor_state, link_should_enable, ospf_link_get_mut_by_name,
    parse_area_id,
};
use super::ifsm::{IfsmEvent, ospf_hello_timer};
use super::link::{OSPF_DEFAULT_OUTPUT_COST, OspfNetworkType};
use super::version::Ospfv3;
use super::{Message, Ospf, OspfLink};

use crate::config::{Args, ConfigOp};

const OSPFV3: &str = "/router/ospfv3";

impl Ospf<Ospfv3> {
    /// Register the v3 YANG-path → handler dispatch table. Mirrors
    /// v2's `callback_build` shape; the table is keyed by full path
    /// (e.g. `/router/ospfv3/area/interface/enable`) so `process_msg`
    /// can look up handlers directly.
    pub fn callback_build(&mut self) {
        let prefix = OSPFV3;
        let entries: &[(&str, Callback<Ospfv3>)] = &[
            ("/router-id", config_ospfv3_router_id),
            ("/area/area-type", config_ospfv3_area_type),
            ("/area/no-summary", config_ospfv3_area_no_summary),
            (
                "/area/nssa-default-originate",
                config_ospfv3_area_nssa_default_originate,
            ),
            (
                "/area/nssa-suppress-fa",
                config_ospfv3_area_nssa_suppress_fa,
            ),
            (
                "/area/nssa-translator-role",
                config_ospfv3_area_nssa_translator_role,
            ),
            (
                "/area/redistribute/connected",
                config_ospfv3_area_redist_connected,
            ),
            (
                "/area/redistribute/connected/metric",
                config_ospfv3_area_redist_connected_metric,
            ),
            (
                "/area/redistribute/connected/metric-type",
                config_ospfv3_area_redist_connected_metric_type,
            ),
            ("/redistribute/bgp", config_ospfv3_redist_bgp),
            ("/redistribute/bgp/metric", config_ospfv3_redist_bgp_metric),
            (
                "/redistribute/bgp/metric-type",
                config_ospfv3_redist_bgp_metric_type,
            ),
            ("/area/interface/enable", config_ospfv3_interface_enable),
            (
                "/area/interface/bfd/enable",
                config_ospf_interface_bfd_enable,
            ),
            (
                "/area/interface/bfd/min-neighbor-state",
                config_ospf_interface_bfd_min_neighbor_state,
            ),
            (
                "/area/interface/bfd/echo-mode",
                config_ospf_interface_bfd_echo_mode,
            ),
            (
                "/area/interface/bfd/echo-transmit-interval",
                config_ospf_interface_bfd_echo_transmit_interval,
            ),
            (
                "/area/interface/bfd/echo-receive-interval",
                config_ospf_interface_bfd_echo_receive_interval,
            ),
            (
                "/area/interface/bfd/detect-offload",
                config_ospf_interface_bfd_detect_offload,
            ),
            // Instance-level `router ospfv3 { bfd { ... } }` defaults.
            ("/bfd/enable", config_ospf_bfd_enable),
            (
                "/bfd/min-neighbor-state",
                config_ospf_bfd_min_neighbor_state,
            ),
            ("/bfd/echo-mode", config_ospf_bfd_echo_mode),
            (
                "/bfd/echo-transmit-interval",
                config_ospf_bfd_echo_transmit_interval,
            ),
            (
                "/bfd/echo-receive-interval",
                config_ospf_bfd_echo_receive_interval,
            ),
            ("/bfd/detect-offload", config_ospf_bfd_detect_offload),
            (
                "/area/interface/network-type",
                config_ospfv3_interface_network_type,
            ),
            ("/area/interface/priority", config_ospfv3_interface_priority),
            ("/area/interface/cost", config_ospfv3_interface_cost),
            (
                "/area/interface/hello-interval",
                config_ospfv3_interface_hello_interval,
            ),
            (
                "/area/interface/dead-interval",
                config_ospfv3_interface_dead_interval,
            ),
            (
                "/area/interface/retransmit-interval",
                config_ospfv3_interface_retransmit_interval,
            ),
            (
                "/area/interface/mtu-ignore",
                config_ospfv3_interface_mtu_ignore,
            ),
            (
                "/area/interface/prefix-sid/index",
                config_ospfv3_interface_prefix_sid_index,
            ),
            (
                "/area/interface/prefix-sid/absolute",
                config_ospfv3_interface_prefix_sid_absolute,
            ),
            (
                "/area/interface/adjacency-sid/index",
                config_ospfv3_interface_adjacency_sid_index,
            ),
            (
                "/area/interface/adjacency-sid/absolute",
                config_ospfv3_interface_adjacency_sid_absolute,
            ),
            ("/area/interface/affinity", config_ospfv3_interface_affinity),
            (
                "/area/interface/flex-algo-prefix-sid/index",
                config_ospfv3_interface_flex_algo_prefix_sid_index,
            ),
            (
                "/area/interface/flex-algo-prefix-sid/absolute",
                config_ospfv3_interface_flex_algo_prefix_sid_absolute,
            ),
            ("/segment-routing/mpls", config_ospfv3_sr_mpls),
            ("/segment-routing/srv6/locator", config_ospfv3_srv6_locator),
            ("/fast-reroute/ti-lfa", config_ospfv3_ti_lfa),
            (
                "/fast-reroute/ti-lfa/compute-mode/serial",
                config_ospfv3_ti_lfa_compute_mode_serial,
            ),
            (
                "/fast-reroute/ti-lfa/compute-mode/conservative",
                config_ospfv3_ti_lfa_compute_mode_conservative,
            ),
            (
                "/fast-reroute/ti-lfa/compute-mode/aggressive",
                config_ospfv3_ti_lfa_compute_mode_aggressive,
            ),
            (
                "/fast-reroute/ti-lfa/compute-mode/sharding",
                config_ospfv3_ti_lfa_compute_mode_sharding,
            ),
            (
                "/fast-reroute/ti-lfa/compute-mode/sharding/shards",
                config_ospfv3_ti_lfa_compute_shards,
            ),
            (
                "/fast-reroute/backup-as-primary",
                config_ospfv3_fast_reroute_backup_as_primary,
            ),
        ];
        for (path, cb) in entries {
            self.callbacks.insert(format!("{}{}", prefix, path), *cb);
        }
    }
}

/// `/router/ospfv3/fast-reroute/ti-lfa` — v3 sibling of the v2
/// `config_ospf_ti_lfa`. Gates the per-destination TI-LFA repair
/// computation (RFC 9490); on a state change, kick an SPF recompute
/// for every area so the v6 RIB picks up or drops repair backups. No
/// LSA re-origination — the repair is a local install-side decision.
fn config_ospfv3_ti_lfa(ospf: &mut Ospf<Ospfv3>, _args: Args, op: ConfigOp) -> Option<()> {
    let prev = ospf.ti_lfa_enabled;
    ospf.ti_lfa_enabled = op.is_set();
    if ospf.ti_lfa_enabled == prev {
        return Some(());
    }
    let area_ids: Vec<std::net::Ipv4Addr> = ospf.areas.iter().map(|(id, _)| *id).collect();
    for id in area_ids {
        let _ = ospf.tx.send(Message::SpfCalc(id));
    }
    Some(())
}

/// Re-run SPF on every area iff the *effective* v3 TI-LFA scheduling
/// mode (mode + shard count) changed from `prev`. v3 sibling of the v2
/// `ospf_ti_lfa_recompute_if_changed`.
fn ospfv3_ti_lfa_recompute_if_changed(ospf: &mut Ospf<Ospfv3>, prev: crate::spf::TilfaComputeMode) {
    if ospf
        .ti_lfa_compute_mode
        .with_shards(ospf.ti_lfa_compute_shards)
        == prev
    {
        return;
    }
    let area_ids: Vec<std::net::Ipv4Addr> = ospf.areas.iter().map(|(id, _)| *id).collect();
    for id in area_ids {
        let _ = ospf.tx.send(Message::SpfCalc(id));
    }
}

/// Set the payload-free v3 `compute-mode` selector and re-run SPF on an
/// effective-mode change. Shared by the per-case callbacks below.
fn apply_ospfv3_ti_lfa_compute_mode(
    ospf: &mut Ospf<Ospfv3>,
    mode: crate::spf::TilfaComputeModeConfig,
) {
    let prev = ospf
        .ti_lfa_compute_mode
        .with_shards(ospf.ti_lfa_compute_shards);
    ospf.ti_lfa_compute_mode = mode;
    ospfv3_ti_lfa_recompute_if_changed(ospf, prev);
}

/// Body shared by the v3 `serial` / `conservative` / `aggressive`
/// `compute-mode` cases. Setting selects `mode`; deleting reverts to
/// the default mode only when *this* case is the active one (the
/// candidate store does not auto-clear sibling choice cases, so a stale
/// delete of an inactive case is a no-op).
fn config_ospfv3_ti_lfa_compute_mode_case(
    ospf: &mut Ospf<Ospfv3>,
    op: ConfigOp,
    mode: crate::spf::TilfaComputeModeConfig,
) -> Option<()> {
    if op.is_set() {
        apply_ospfv3_ti_lfa_compute_mode(ospf, mode);
    } else if ospf.ti_lfa_compute_mode == mode {
        apply_ospfv3_ti_lfa_compute_mode(ospf, crate::spf::TilfaComputeModeConfig::default());
    }
    Some(())
}

/// `/router/ospfv3/fast-reroute/ti-lfa/compute-mode/serial`.
fn config_ospfv3_ti_lfa_compute_mode_serial(
    ospf: &mut Ospf<Ospfv3>,
    _args: Args,
    op: ConfigOp,
) -> Option<()> {
    config_ospfv3_ti_lfa_compute_mode_case(ospf, op, crate::spf::TilfaComputeModeConfig::Serial)
}

/// `/router/ospfv3/fast-reroute/ti-lfa/compute-mode/conservative`.
fn config_ospfv3_ti_lfa_compute_mode_conservative(
    ospf: &mut Ospf<Ospfv3>,
    _args: Args,
    op: ConfigOp,
) -> Option<()> {
    config_ospfv3_ti_lfa_compute_mode_case(
        ospf,
        op,
        crate::spf::TilfaComputeModeConfig::Conservative,
    )
}

/// `/router/ospfv3/fast-reroute/ti-lfa/compute-mode/aggressive`.
fn config_ospfv3_ti_lfa_compute_mode_aggressive(
    ospf: &mut Ospf<Ospfv3>,
    _args: Args,
    op: ConfigOp,
) -> Option<()> {
    config_ospfv3_ti_lfa_compute_mode_case(ospf, op, crate::spf::TilfaComputeModeConfig::Aggressive)
}

/// `/router/ospfv3/fast-reroute/ti-lfa/compute-mode/sharding` — the
/// presence container for the sharding case. Bare `sharding` selects
/// the mode with the default shard count; the `shards` child overrides
/// it. Deleting the container drops the whole sharding subtree, so
/// reset the count here too and revert the mode when sharding is the
/// active case.
fn config_ospfv3_ti_lfa_compute_mode_sharding(
    ospf: &mut Ospf<Ospfv3>,
    _args: Args,
    op: ConfigOp,
) -> Option<()> {
    if op.is_set() {
        apply_ospfv3_ti_lfa_compute_mode(ospf, crate::spf::TilfaComputeModeConfig::Sharding);
    } else {
        let prev = ospf
            .ti_lfa_compute_mode
            .with_shards(ospf.ti_lfa_compute_shards);
        // Matches the YANG `default 8` on the `shards` leaf.
        ospf.ti_lfa_compute_shards = 8;
        if ospf.ti_lfa_compute_mode == crate::spf::TilfaComputeModeConfig::Sharding {
            ospf.ti_lfa_compute_mode = crate::spf::TilfaComputeModeConfig::default();
        }
        ospfv3_ti_lfa_recompute_if_changed(ospf, prev);
    }
    Some(())
}

/// `/router/ospfv3/fast-reroute/ti-lfa/compute-mode/sharding/shards` —
/// v3 sibling of the v2 callback. Consulted only in sharding mode.
fn config_ospfv3_ti_lfa_compute_shards(
    ospf: &mut Ospf<Ospfv3>,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let prev = ospf
        .ti_lfa_compute_mode
        .with_shards(ospf.ti_lfa_compute_shards);
    ospf.ti_lfa_compute_shards = if op.is_set() { args.u16()? } else { 8 };
    ospfv3_ti_lfa_recompute_if_changed(ospf, prev);
    Some(())
}

/// `/router/ospfv3/fast-reroute/backup-as-primary` — v3 sibling of the
/// v2 callback. Inverts the primary/backup metric ordering at install
/// time; re-run SPF so the v6 RIB rebuilds with the swapped offset.
fn config_ospfv3_fast_reroute_backup_as_primary(
    ospf: &mut Ospf<Ospfv3>,
    _args: Args,
    op: ConfigOp,
) -> Option<()> {
    let prev = ospf.fast_reroute_backup_as_primary;
    ospf.fast_reroute_backup_as_primary = op.is_set();
    if ospf.fast_reroute_backup_as_primary == prev {
        return Some(());
    }
    let area_ids: Vec<std::net::Ipv4Addr> = ospf.areas.iter().map(|(id, _)| *id).collect();
    for id in area_ids {
        let _ = ospf.tx.send(Message::SpfCalc(id));
    }
    Some(())
}

/// `/router/ospfv3/area/<id>/area-type` — same shape as the v2
/// sibling in `config.rs`; delegates to the shared
/// `area_type_set` helper, then triggers v3 NSSA default Type-7
/// origination so the LSA appears on entry to NSSA and is flushed
/// on exit (the helper short-circuits to flush when area is no
/// longer NSSA).
fn config_ospfv3_area_type(ospf: &mut Ospf<Ospfv3>, mut args: Args, op: ConfigOp) -> Option<()> {
    let area_id = parse_area_id(&args.string()?)?;
    let kind = if op.is_set() {
        AreaTypeKind::from_yang(&args.string()?)?
    } else {
        AreaTypeKind::default()
    };
    area_type_set(ospf, area_id, kind);
    ospf.nssa_default_lsa_originate(area_id);
    // Entering / leaving NSSA flips whether redistributed connected
    // routes are legal as Type-7s in this area — resync originates
    // fresh on entry, flushes on exit.
    ospf.nssa_redist_connected_resync_v3(area_id);
    // Area-type also flips whether we should be translating
    // Type-7→Type-5 for this area (phase 6d). Resync clears
    // stale Type-5s on exit and seeds fresh ones on entry (if
    // we are an ABR with translator-role = Always or are the
    // Candidate-elected winner).
    ospf.nssa_translate_resync(area_id);
    Some(())
}

/// `router ospfv3 { router-id ... }`. Mirrors v2's
/// `config_ospf_router_id`: store the configured Router-ID and
/// refresh — the instance (and every interface's `ident`) picks it
/// up and re-originates. Delete falls back instead of keeping the
/// old value. Previously OSPFv3 had no per-instance Router-ID
/// callback at all, so every v3 instance kept the constructor
/// default 10.0.0.1.
fn config_ospfv3_router_id(ospf: &mut Ospf<Ospfv3>, mut args: Args, op: ConfigOp) -> Option<()> {
    if op.is_set() {
        ospf.router_id_config = Some(args.v4addr()?);
    } else {
        ospf.router_id_config = None;
    }
    ospf.refresh_router_id();
    Some(())
}

fn config_ospfv3_area_no_summary(
    ospf: &mut Ospf<Ospfv3>,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let area_id = parse_area_id(&args.string()?)?;
    let value = op.is_set() && args.boolean()?;
    area_no_summary_set(ospf, area_id, value);
    Some(())
}

fn config_ospfv3_area_nssa_default_originate(
    ospf: &mut Ospf<Ospfv3>,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let area_id = parse_area_id(&args.string()?)?;
    let value = op.is_set() && args.boolean()?;
    area_nssa_default_originate_set(ospf, area_id, value);
    // Trigger the v3 originator (or flush) — the helper inspects
    // the current area type + knob value and picks the right
    // action.
    ospf.nssa_default_lsa_originate(area_id);
    Some(())
}

fn config_ospfv3_area_nssa_suppress_fa(
    ospf: &mut Ospf<Ospfv3>,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let area_id = parse_area_id(&args.string()?)?;
    let value = op.is_set() && args.boolean()?;
    area_nssa_suppress_fa_set(ospf, area_id, value);
    Some(())
}

fn config_ospfv3_area_nssa_translator_role(
    ospf: &mut Ospf<Ospfv3>,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let area_id = parse_area_id(&args.string()?)?;
    let role = if op.is_set() {
        NssaTranslatorRole::from_yang(&args.string()?)?
    } else {
        NssaTranslatorRole::default()
    };
    area_nssa_translator_role_set(ospf, area_id, role);
    // Role flip directly changes whether translation should be
    // happening on this router.
    ospf.nssa_translate_resync(area_id);
    Some(())
}

/// v3 sibling of `ospf_send_redist_connected` (`config.rs`): subscribe
/// (or unsubscribe) to RIB IPv6 connected routes for redistribution
/// into NSSA Type-7 LSAs. Keyed by `(proto, afi, rtype)` — not per
/// area — so multiple NSSA areas share one subscription.
fn ospfv3_send_redist_connected(ospf: &Ospf<Ospfv3>, first_time: bool) {
    use crate::rib::{Message as RibMsg, RedistAfi, RibType};
    // Subscribe under this instance's proto label, not the literal
    // "ospfv3": a per-VRF v3 instance registers as "ospfv3:vrf:<name>",
    // and the RIB routes redist delivery by the proto string. With the
    // literal, a VRF child's subscription resolved to the default v3
    // instance — so per-VRF redistribute never delivered. Same bug fixed
    // for v2 (config.rs) and IS-IS.
    let proto = ospf.proto_label.clone();
    let afi = RedistAfi::Ipv6;
    let rtype = RibType::Connected;

    let any_enabled = ospf
        .areas
        .iter()
        .any(|(_, area)| area.redistribute.connected.is_some());

    let msg = if !any_enabled {
        RibMsg::RedistDel { proto, afi, rtype }
    } else if first_time {
        RibMsg::RedistAdd {
            proto,
            afi,
            rtype,
            subtypes: std::collections::BTreeSet::new(),
        }
    } else {
        RibMsg::RedistUpdate {
            proto,
            afi,
            rtype,
            subtypes: std::collections::BTreeSet::new(),
        }
    };
    let _ = ospf.ctx.rib.send(msg);
}

/// Subscribe / unsubscribe this v3 instance's RIB redistribution for the
/// IPv6 BGP source, gated on the instance-level `redistribute bgp` knob.
/// Uses `proto_label` so a per-VRF instance receives only its VRF's BGP
/// routes. v3 sibling of v2's `ospf_send_redist_bgp`.
fn ospfv3_send_redist_bgp(ospf: &Ospf<Ospfv3>, first_time: bool) {
    use crate::rib::{Message as RibMsg, RedistAfi, RibType};
    let proto = ospf.proto_label.clone();
    let afi = RedistAfi::Ipv6;
    let rtype = RibType::Bgp;

    let msg = if ospf.redist_bgp.is_none() {
        RibMsg::RedistDel { proto, afi, rtype }
    } else if first_time {
        RibMsg::RedistAdd {
            proto,
            afi,
            rtype,
            subtypes: std::collections::BTreeSet::new(),
        }
    } else {
        RibMsg::RedistUpdate {
            proto,
            afi,
            rtype,
            subtypes: std::collections::BTreeSet::new(),
        }
    };
    let _ = ospf.ctx.rib.send(msg);
}

/// `/router/ospfv3/redistribute/bgp` — instance-level presence container.
/// On Set: subscribe to the VRF's BGP routes and originate an AS-External
/// (Type-5) LSA for each. On Delete: unsubscribe and flush them.
fn config_ospfv3_redist_bgp(ospf: &mut Ospf<Ospfv3>, _args: Args, op: ConfigOp) -> Option<()> {
    let first_time = ospf.redist_bgp.is_none();
    if op.is_set() {
        ospf.redist_bgp = Some(RedistEntry {
            metric: RedistEntry::DEFAULT_METRIC,
            ..Default::default()
        });
    } else {
        ospf.redist_bgp = None;
    }
    ospfv3_send_redist_bgp(ospf, first_time && op.is_set());
    ospf.as_external_redist_bgp_resync_v3();
    Some(())
}

/// `/router/ospfv3/redistribute/bgp/metric`.
fn config_ospfv3_redist_bgp_metric(
    ospf: &mut Ospf<Ospfv3>,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let metric = if op.is_set() {
        args.u32()?
    } else {
        RedistEntry::DEFAULT_METRIC
    };
    ospf.redist_bgp.get_or_insert_with(Default::default).metric = metric;
    ospf.as_external_redist_bgp_resync_v3();
    Some(())
}

/// `/router/ospfv3/redistribute/bgp/metric-type`.
fn config_ospfv3_redist_bgp_metric_type(
    ospf: &mut Ospf<Ospfv3>,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let mtype = if op.is_set() {
        ExternalMetricType::from_yang(&args.string()?)?
    } else {
        ExternalMetricType::default()
    };
    ospf.redist_bgp
        .get_or_insert_with(Default::default)
        .metric_type = mtype;
    ospf.as_external_redist_bgp_resync_v3();
    Some(())
}

/// `/router/ospfv3/area/<id>/redistribute/connected` — presence
/// container. Mirrors v2's `config_ospf_area_redist_connected` but
/// drives the IPv6 subscription + the v3 Type-7 resync.
fn config_ospfv3_area_redist_connected(
    ospf: &mut Ospf<Ospfv3>,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let area_id = parse_area_id(&args.string()?)?;

    let first_time = !ospf
        .areas
        .iter()
        .any(|(_, area)| area.redistribute.connected.is_some());

    if op.is_set() {
        ospf.areas.fetch(area_id).redistribute.connected = Some(RedistEntry {
            metric: RedistEntry::DEFAULT_METRIC,
            ..Default::default()
        });
    } else if let Some(area) = ospf.areas.get_mut(area_id) {
        area.redistribute.connected = None;
    }

    ospfv3_send_redist_connected(ospf, first_time && op.is_set());
    ospf.nssa_redist_connected_resync_v3(area_id);
    Some(())
}

/// `/router/ospfv3/area/<id>/redistribute/connected/metric`.
fn config_ospfv3_area_redist_connected_metric(
    ospf: &mut Ospf<Ospfv3>,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let area_id = parse_area_id(&args.string()?)?;
    let metric = if op.is_set() {
        args.u32()?
    } else {
        RedistEntry::DEFAULT_METRIC
    };
    let entry = ospf
        .areas
        .fetch(area_id)
        .redistribute
        .connected
        .get_or_insert_with(RedistEntry::default);
    entry.metric = metric;
    ospf.nssa_redist_connected_resync_v3(area_id);
    Some(())
}

/// `/router/ospfv3/area/<id>/redistribute/connected/metric-type` —
/// `type-1` / `type-2`. Re-originates the area's Type-7s (the E-bit
/// changes per LSA).
fn config_ospfv3_area_redist_connected_metric_type(
    ospf: &mut Ospf<Ospfv3>,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let area_id = parse_area_id(&args.string()?)?;
    let metric_type = if op.is_set() {
        ExternalMetricType::from_yang(&args.string()?)?
    } else {
        ExternalMetricType::default()
    };
    let entry = ospf
        .areas
        .fetch(area_id)
        .redistribute
        .connected
        .get_or_insert_with(RedistEntry::default);
    entry.metric_type = metric_type;
    ospf.nssa_redist_connected_resync_v3(area_id);
    Some(())
}

/// Toggle the link's `enabled` state and re-evaluate the IFSM
/// transition. Mirrors v2's `config_ospf_interface_enable`: the
/// path-args queue carries `(area-id, if-name, enable-bool)`.
///
/// On `Set` with `enable = true`, the area is captured from the
/// parent list key; on `Delete` (or `enable = false`), both `enable`
/// and the cached area are cleared. The transition helper
/// (`apply_link_enable_transition`) fires `Message::Enable` /
/// `Message::Disable` into the instance channel, which drives the
/// v3 cascade (LSA origination, IFSM `InterfaceUp` / `Down`).
fn config_ospfv3_interface_enable(
    ospf: &mut Ospf<Ospfv3>,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let area_id = parse_area_id(&args.string()?)?;
    let name = args.string()?;
    let enable = args.boolean()?;

    let link: &mut OspfLink<Ospfv3> = ospf_link_get_mut_by_name(&mut ospf.links, &name)?;

    if op.is_set() {
        link.config.enable = enable;
        link.config.area = Some(area_id);
    } else {
        link.config.enable = false;
        link.config.area = None;
    }

    let (next, next_id) = link_should_enable(link);
    apply_link_enable_transition(link, next, next_id);

    Some(())
}

/// `/router/ospfv3/area/<id>/interface/<name>/network-type` — same
/// shape as the v2 handler in `config.rs`. Stores the configured
/// type in `LinkConfig::network_type` (shared between v2 and v3)
/// and bounces the interface on any change so the IFSM re-enters
/// from the correct initial state (PointToPoint vs Waiting).
fn config_ospfv3_interface_network_type(
    ospf: &mut Ospf<Ospfv3>,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let _area_id = parse_area_id(&args.string()?)?;
    let name = args.string()?;
    let network_type = args.string()?.parse::<OspfNetworkType>().ok()?;

    let link: &mut OspfLink<Ospfv3> = ospf_link_get_mut_by_name(&mut ospf.links, &name)?;
    let old = link.config_network_type();
    if op.is_set() {
        link.config.network_type = Some(network_type);
    } else {
        link.config.network_type = None;
    }
    let new = link.config_network_type();

    if old != new && link.enabled {
        let area_id = link.area_id;
        let _ = link.tx.send(Message::Disable(link.index, area_id));
        let _ = link.tx.send(Message::Enable(link.index, area_id));
    }

    Some(())
}

fn config_ospfv3_interface_priority(
    ospf: &mut Ospf<Ospfv3>,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let _area_id = parse_area_id(&args.string()?)?;
    let name = args.string()?;
    let priority = args.u8()?;

    let link = ospf_link_get_mut_by_name(&mut ospf.links, &name)?;
    if op.is_set() {
        link.config.priority = Some(priority);
    } else {
        link.config.priority = None;
    }
    link.ident.priority = link.priority();

    let ifindex = link.index;
    let _ = link
        .tx
        .send(Message::Ifsm(ifindex, IfsmEvent::NeighborChange));

    Some(())
}

/// `/router/ospfv3/area/<id>/interface/<name>/cost` — v3 sibling of
/// v2's `config_ospf_interface_cost` (RFC 2328 §C.3 interface output
/// cost; RFC 5340 keeps the semantics). Stored straight into
/// `link.output_cost`; clearing restores the protocol default (10).
/// Unlike v2 — where the Router-LSA carries both topology and stub
/// prefixes — v3 splits the metric across three LSAs, so all of them
/// re-originate: the Router-LSA (P2P link metric / SPF edge weight),
/// the Intra-Area-Prefix-LSA (per-prefix metric), and the
/// E-Intra-Area-Prefix-LSA (Prefix-SID host metric on non-loopbacks).
/// Each origination path schedules the area's SPF itself.
fn config_ospfv3_interface_cost(
    ospf: &mut Ospf<Ospfv3>,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let _area_id = parse_area_id(&args.string()?)?;
    let name = args.string()?;
    let cost = args.u16()?;

    let link = ospf_link_get_mut_by_name(&mut ospf.links, &name)?;
    link.output_cost = if op.is_set() {
        cost as u32
    } else {
        OSPF_DEFAULT_OUTPUT_COST
    };
    let area_id = link.area_id;
    let ifindex = link.index;

    ospf.router_lsa_originate();
    ospf.router_intra_area_prefix_lsa_originate(area_id);
    ospf.ext_intra_area_prefix_v3_lsa_originate(ifindex);

    Some(())
}

fn config_ospfv3_interface_hello_interval(
    ospf: &mut Ospf<Ospfv3>,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let _area_id = parse_area_id(&args.string()?)?;
    let name = args.string()?;
    let hello_interval = args.u16()?;

    let link = ospf_link_get_mut_by_name(&mut ospf.links, &name)?;
    if op.is_set() {
        link.config.hello_interval = Some(hello_interval);
    } else {
        link.config.hello_interval = None;
    }

    if link.timer.hello.is_some() {
        link.timer.hello = Some(ospf_hello_timer(link));
    }

    Some(())
}

fn config_ospfv3_interface_dead_interval(
    ospf: &mut Ospf<Ospfv3>,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let _area_id = parse_area_id(&args.string()?)?;
    let name = args.string()?;
    let dead_interval = args.u32()?;

    let link = ospf_link_get_mut_by_name(&mut ospf.links, &name)?;
    if op.is_set() {
        link.config.dead_interval = Some(dead_interval);
    } else {
        link.config.dead_interval = None;
    }

    Some(())
}

fn config_ospfv3_interface_retransmit_interval(
    ospf: &mut Ospf<Ospfv3>,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let _area_id = parse_area_id(&args.string()?)?;
    let name = args.string()?;
    let retransmit_interval = args.u16()?;

    let link = ospf_link_get_mut_by_name(&mut ospf.links, &name)?;
    if op.is_set() {
        link.config.retransmit_interval = Some(retransmit_interval);
    } else {
        link.config.retransmit_interval = None;
    }

    Some(())
}

fn config_ospfv3_interface_mtu_ignore(
    ospf: &mut Ospf<Ospfv3>,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let _area_id = parse_area_id(&args.string()?)?;
    let name = args.string()?;
    let mtu_ignore = args.boolean()?;

    let link = ospf_link_get_mut_by_name(&mut ospf.links, &name)?;
    link.config.mtu_ignore = op.is_set() && mtu_ignore;

    Some(())
}

/// Record the per-interface Prefix-SID index and re-originate the
/// matching E-Intra-Area-Prefix-LSA. Mirrors v2's
/// `config_ospf_interface_prefix_sid_index`. The originator gates
/// on SR-MPLS enabled + the link being up with the Prefix-SID set,
/// so the LSA is flushed automatically if any precondition fails.
fn config_ospfv3_interface_prefix_sid_index(
    ospf: &mut Ospf<Ospfv3>,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let _area_id = parse_area_id(&args.string()?)?;
    let name = args.string()?;
    let index = args.u32()?;

    let link = ospf_link_get_mut_by_name(&mut ospf.links, &name)?;
    if op.is_set() {
        link.config.prefix_sid = Some(super::link::PrefixSid::Index(index));
    } else {
        link.config.prefix_sid = None;
    }
    let ifindex = link.index;

    ospf.ext_intra_area_prefix_v3_lsa_originate(ifindex);

    Some(())
}

fn config_ospfv3_interface_prefix_sid_absolute(
    ospf: &mut Ospf<Ospfv3>,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let _area_id = parse_area_id(&args.string()?)?;
    let name = args.string()?;
    let absolute = args.u32()?;

    let link = ospf_link_get_mut_by_name(&mut ospf.links, &name)?;
    if op.is_set() {
        link.config.prefix_sid = Some(super::link::PrefixSid::Absolute(absolute));
    } else {
        link.config.prefix_sid = None;
    }
    let ifindex = link.index;

    ospf.ext_intra_area_prefix_v3_lsa_originate(ifindex);

    Some(())
}

/// Store the per-interface Adjacency-SID and re-originate the
/// matching E-Router-LSA. Mirrors v2's
/// `config_ospf_interface_adjacency_sid_index`. The originator
/// gates on its own preconditions (SR-MPLS + P2P + Full neighbor),
/// so the LSA is flushed automatically when any are unmet.
fn config_ospfv3_interface_adjacency_sid_index(
    ospf: &mut Ospf<Ospfv3>,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let _area_id = parse_area_id(&args.string()?)?;
    let name = args.string()?;
    let index = args.u32()?;

    let link = ospf_link_get_mut_by_name(&mut ospf.links, &name)?;
    if op.is_set() {
        link.config.adjacency_sid = Some(super::link::AdjacencySid::Index(index));
    } else {
        link.config.adjacency_sid = None;
    }
    let ifindex = link.index;

    ospf.e_router_v3_lsa_originate(ifindex);

    Some(())
}

fn config_ospfv3_interface_adjacency_sid_absolute(
    ospf: &mut Ospf<Ospfv3>,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let _area_id = parse_area_id(&args.string()?)?;
    let name = args.string()?;
    let absolute = args.u32()?;

    let link = ospf_link_get_mut_by_name(&mut ospf.links, &name)?;
    if op.is_set() {
        link.config.adjacency_sid = Some(super::link::AdjacencySid::Absolute(absolute));
    } else {
        link.config.adjacency_sid = None;
    }
    let ifindex = link.index;

    ospf.e_router_v3_lsa_originate(ifindex);

    Some(())
}

// `/router/ospfv3/area/interface/affinity` — one call per affinity
// name on the leaf-list. Each name references a global `/affinity-map`
// entry; bit positions are resolved at LSA-build time, so we only
// stage the names here. Mirrors v2's `config_ospf_interface_affinity`
// (the RFC 9492 ASLA origination that reads them lands with v3
// flex-algo origination).
fn config_ospfv3_interface_affinity(
    ospf: &mut Ospf<Ospfv3>,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let _area_id = parse_area_id(&args.string()?)?;
    let name = args.string()?;

    let link = ospf_link_get_mut_by_name(&mut ospf.links, &name)?;
    // `affinity` is a leaf-list: every color arrives in one args deque,
    // so drain it rather than reading only the first.
    while let Some(affinity) = args.string() {
        if op.is_set() {
            link.config.affinity.insert(affinity);
        } else {
            link.config.affinity.remove(&affinity);
        }
    }
    Some(())
}

// `/router/ospfv3/area/interface/flex-algo-prefix-sid/<algo>/index` —
// per-algo Index-form Prefix-SID for this interface's prefix
// (RFC 9350 §7). Stored keyed by algo and re-originates the
// E-Intra-Area-Prefix-LSA. Mirrors v2's
// `config_ospf_interface_flex_algo_prefix_sid_index`.
fn config_ospfv3_interface_flex_algo_prefix_sid_index(
    ospf: &mut Ospf<Ospfv3>,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let _area_id = parse_area_id(&args.string()?)?;
    let name = args.string()?;
    let algo = args.u8()?;
    let index = args.u32()?;

    let link = ospf_link_get_mut_by_name(&mut ospf.links, &name)?;
    if op.is_set() {
        link.config
            .flex_algo_prefix_sids
            .insert(algo, super::link::PrefixSid::Index(index));
    } else {
        link.config.flex_algo_prefix_sids.remove(&algo);
    }
    let ifindex = link.index;

    ospf.ext_intra_area_prefix_v3_lsa_originate(ifindex);

    Some(())
}

// `/router/ospfv3/area/interface/flex-algo-prefix-sid/<algo>/absolute`
// — per-algo Absolute (label) Prefix-SID sibling of the index form.
fn config_ospfv3_interface_flex_algo_prefix_sid_absolute(
    ospf: &mut Ospf<Ospfv3>,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let _area_id = parse_area_id(&args.string()?)?;
    let name = args.string()?;
    let algo = args.u8()?;
    let absolute = args.u32()?;

    let link = ospf_link_get_mut_by_name(&mut ospf.links, &name)?;
    if op.is_set() {
        link.config
            .flex_algo_prefix_sids
            .insert(algo, super::link::PrefixSid::Absolute(absolute));
    } else {
        link.config.flex_algo_prefix_sids.remove(&algo);
    }
    let ifindex = link.index;

    ospf.ext_intra_area_prefix_v3_lsa_originate(ifindex);

    Some(())
}

/// Toggle the v3 SR-MPLS enable bit, manage the per-instance
/// Adjacency-SID label pool, and fan out to every link with a
/// configured SR-MPLS attribute so the matching E-LSAs are
/// originated (on enable) or flushed (on disable). Mirrors v2's
/// `config_ospf_sr_mpls`.
/// `/router/ospfv3/segment-routing/srv6/locator` — name of a locator
/// from the global /segment-routing/locator list (RFC 9513 Phase 2,
/// `docs/design/ospfv3-srv6-plan.md`). Mirrors the IS-IS staging
/// convention: the name is held as a string and only resolves once
/// the global locator commits — `reconcile_locator_watch` registers
/// at the RIB and the snapshot reply drives End/uN SID install plus
/// SRv6 Locator LSA origination.
fn config_ospfv3_srv6_locator(ospf: &mut Ospf<Ospfv3>, mut args: Args, op: ConfigOp) -> Option<()> {
    if op.is_set() {
        let name = args.string()?;
        ospf.srv6_locator_name = Some(name);
    } else {
        ospf.srv6_locator_name = None;
    }
    ospf.reconcile_locator_watch();
    Some(())
}

fn config_ospfv3_sr_mpls(ospf: &mut Ospf<Ospfv3>, _args: Args, op: ConfigOp) -> Option<()> {
    use super::srmpls::{SRLB_RANGE, SRLB_START, SegmentRoutingMode};
    use crate::spf::label_pool::LabelPool;
    ospf.segment_routing = if op.is_set() {
        SegmentRoutingMode::Mpls
    } else {
        SegmentRoutingMode::None
    };

    // Manage the per-instance Adjacency-SID label pool alongside the
    // mode toggle. The pool is bounded by the SRLB
    // (`srmpls::SRLB_START`..`+ SRLB_RANGE - 1`); on enable, sweep
    // current Full neighbors and allocate labels for any not yet in
    // `lan_adj_sids` so an SR-MPLS enable after adjacencies have
    // already settled still produces the LAN Adj-SID LSAs.
    if op.is_set() {
        if ospf.local_pool.is_none() {
            ospf.local_pool = Some(LabelPool::new(
                SRLB_START as usize,
                Some((SRLB_START + SRLB_RANGE - 1) as usize),
            ));
        }
        let pending: Vec<(u32, std::net::Ipv4Addr)> = ospf
            .links
            .iter()
            .flat_map(|(ifindex, link)| {
                link.nbrs.iter().filter_map(move |(nbr_key, nbr)| {
                    if nbr.state == super::nfsm::NfsmState::Full {
                        Some((*ifindex, *nbr_key))
                    } else {
                        None
                    }
                })
            })
            .filter(|key| !ospf.lan_adj_sids.contains_key(key))
            .collect();
        for key in pending {
            if let Some(pool) = ospf.local_pool.as_mut()
                && let Some(label) = pool.allocate()
            {
                ospf.lan_adj_sids.insert(key, label as u32);
            }
        }
    } else {
        ospf.local_pool = None;
        ospf.lan_adj_sids.clear();
    }

    // Re-originate / flush E-Intra-Area-Prefix-LSAs for every link
    // with a Prefix-SID. The originator gates on the mode, so on
    // disable each call lands in the flush path.
    let ifindexes: Vec<u32> = ospf
        .links
        .iter()
        .filter(|(_, link)| link.config.prefix_sid.is_some())
        .map(|(ifindex, _)| *ifindex)
        .collect();
    for ifindex in ifindexes {
        ospf.ext_intra_area_prefix_v3_lsa_originate(ifindex);
    }

    // Re-originate / flush the per-link E-Router-LSA on every link.
    // The originator gates on mode + warrant itself (and flushes
    // otherwise), so sweeping unconditionally covers all four cases:
    // enable/disable x configured/dynamic Adj-SID. Filtering by
    // `adjacency_sid.is_some() || lan_adj_sids non-empty` here broke
    // the disable path once Adj-SIDs went dynamic — the map is
    // cleared just above, so no link matched and the stale LSAs
    // (and their self-ILM pops) survived the SR-MPLS delete.
    let ifindexes: Vec<u32> = ospf.links.keys().copied().collect();
    for ifindex in ifindexes {
        ospf.e_router_v3_lsa_originate(ifindex);
    }

    // Originate (or flush, on disable) the per-area SR capability
    // LSA carrying SR-Algorithm + SRGB + SRLB top-level TLVs so
    // peers can decode the Index-form SIDs we advertise into
    // absolute labels.
    let area_ids: Vec<std::net::Ipv4Addr> = ospf.areas.iter().map(|(id, _)| *id).collect();
    for area_id in area_ids.iter() {
        ospf.e_router_v3_sr_info_lsa_originate(*area_id);
    }

    // Rebuild every area's v6 RIB + ILM under the new mode — same
    // pattern as the ti-lfa toggle below. `add_prefix_sids_v3` gates
    // on the mode, so a disable drops every label imposition and
    // empties the LFIB instead of waiting for an unrelated SPF.
    for area_id in area_ids {
        let _ = ospf.tx.send(Message::SpfCalc(area_id));
    }

    Some(())
}
