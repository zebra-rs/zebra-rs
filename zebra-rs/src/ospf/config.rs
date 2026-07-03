use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use super::Ospf;
use super::OspfLink;
use super::area::{AreaTypeKind, ExternalMetricType, NssaTranslatorRole, RedistEntry};
use super::ifsm::{IfsmEvent, ospf_hello_timer};
use super::link::{NbrStateThreshold, OSPF_DEFAULT_OUTPUT_COST, OspfAuthMode, OspfNetworkType};
use super::version::{OspfVersion, Ospfv2};

use crate::bfd::session::EchoMode;
use crate::config::{Args, ConfigOp};
use crate::ospf::Message;

/// YANG-path → handler dispatch type. Parameterized over `V` so an
/// `Ospf<Ospfv3>` instance carries its own `Callback<Ospfv3>` table,
/// distinct from `Ospf<Ospfv2>`'s. Defaults to `Ospfv2` to keep
/// existing v2 callsites resolving unchanged.
pub type Callback<V = Ospfv2> = fn(&mut Ospf<V>, Args, ConfigOp) -> Option<()>;

impl Ospf {
    const OSPF: &str = "/router/ospf";

    pub fn ospf_add(&mut self, path: &str, cb: Callback) {
        self.callbacks.insert(format!("{}{}", Self::OSPF, path), cb);
    }

    pub fn callback_build(&mut self) {
        self.ospf_add("/router-id", config_ospf_router_id);
        self.ospf_add("/area/area-type", config_ospf_area_type);
        self.ospf_add("/area/no-summary", config_ospf_area_no_summary);
        self.ospf_add(
            "/area/nssa-default-originate",
            config_ospf_area_nssa_default_originate,
        );
        self.ospf_add("/area/nssa-suppress-fa", config_ospf_area_nssa_suppress_fa);
        self.ospf_add(
            "/area/nssa-translator-role",
            config_ospf_area_nssa_translator_role,
        );
        self.ospf_add(
            "/area/redistribute/connected",
            config_ospf_area_redist_connected,
        );
        self.ospf_add(
            "/area/redistribute/connected/metric",
            config_ospf_area_redist_connected_metric,
        );
        self.ospf_add(
            "/area/redistribute/connected/metric-type",
            config_ospf_area_redist_connected_metric_type,
        );
        self.ospf_add(
            "/default-information/originate",
            config_ospf_default_originate,
        );
        self.ospf_add(
            "/default-information/originate/always",
            config_ospf_default_originate_always,
        );
        self.ospf_add(
            "/default-information/originate/metric",
            config_ospf_default_originate_metric,
        );
        self.ospf_add(
            "/default-information/originate/metric-type",
            config_ospf_default_originate_metric_type,
        );
        self.ospf_add("/area/range", config_ospf_area_range);
        self.ospf_add(
            "/area/range/not-advertise",
            config_ospf_area_range_not_advertise,
        );
        self.ospf_add("/area/range/cost", config_ospf_area_range_cost);
        self.ospf_add("/area/virtual-link", config_ospf_area_virtual_link);
        self.ospf_add(
            "/area/virtual-link/hello-interval",
            config_ospf_area_virtual_link_hello_interval,
        );
        self.ospf_add(
            "/area/virtual-link/dead-interval",
            config_ospf_area_virtual_link_dead_interval,
        );
        self.ospf_add(
            "/area/virtual-link/retransmit-interval",
            config_ospf_area_virtual_link_retransmit_interval,
        );
        self.ospf_add(
            "/area/virtual-link/authentication",
            config_ospf_area_virtual_link_authentication,
        );
        self.ospf_add(
            "/area/virtual-link/authentication-key",
            config_ospf_area_virtual_link_authentication_key,
        );
        self.ospf_add(
            "/area/virtual-link/message-digest-key/md5",
            config_ospf_area_virtual_link_md5_key,
        );
        self.ospf_add(
            "/area/virtual-link/key-chain",
            config_ospf_area_virtual_link_key_chain,
        );
        self.ospf_add("/area/interface/enable", config_ospf_interface_enable);
        self.ospf_add(
            "/area/interface/bfd/enable",
            config_ospf_interface_bfd_enable,
        );
        self.ospf_add(
            "/area/interface/bfd/min-neighbor-state",
            config_ospf_interface_bfd_min_neighbor_state,
        );
        self.ospf_add(
            "/area/interface/bfd/echo-mode",
            config_ospf_interface_bfd_echo_mode,
        );
        self.ospf_add(
            "/area/interface/bfd/echo-transmit-interval",
            config_ospf_interface_bfd_echo_transmit_interval,
        );
        self.ospf_add(
            "/area/interface/bfd/echo-receive-interval",
            config_ospf_interface_bfd_echo_receive_interval,
        );
        self.ospf_add(
            "/area/interface/bfd/detect-offload",
            config_ospf_interface_bfd_detect_offload,
        );
        // Instance-level `router ospf { redistribute connected ... }`.
        self.ospf_add("/redistribute/connected", config_ospf_redist_connected);
        self.ospf_add("/redistribute/static", config_ospf_redist_static);
        self.ospf_add(
            "/redistribute/static/metric",
            config_ospf_redist_static_metric,
        );
        self.ospf_add(
            "/redistribute/static/metric-type",
            config_ospf_redist_static_metric_type,
        );
        self.ospf_add("/redistribute/kernel", config_ospf_redist_kernel);
        self.ospf_add(
            "/redistribute/kernel/metric",
            config_ospf_redist_kernel_metric,
        );
        self.ospf_add(
            "/redistribute/kernel/metric-type",
            config_ospf_redist_kernel_metric_type,
        );
        self.ospf_add("/redistribute/isis", config_ospf_redist_isis);
        self.ospf_add("/redistribute/isis/metric", config_ospf_redist_isis_metric);
        self.ospf_add(
            "/redistribute/isis/metric-type",
            config_ospf_redist_isis_metric_type,
        );
        self.ospf_add("/redistribute/bgp", config_ospf_redist_bgp);
        self.ospf_add("/redistribute/bgp/metric", config_ospf_redist_bgp_metric);
        self.ospf_add(
            "/redistribute/bgp/metric-type",
            config_ospf_redist_bgp_metric_type,
        );
        self.ospf_add(
            "/redistribute/connected/metric",
            config_ospf_redist_connected_metric,
        );
        self.ospf_add(
            "/redistribute/connected/metric-type",
            config_ospf_redist_connected_metric_type,
        );
        // Instance-level `router ospf { bfd { ... } }` defaults.
        self.ospf_add("/bfd/enable", config_ospf_bfd_enable);
        self.ospf_add(
            "/bfd/min-neighbor-state",
            config_ospf_bfd_min_neighbor_state,
        );
        self.ospf_add("/bfd/echo-mode", config_ospf_bfd_echo_mode);
        self.ospf_add(
            "/bfd/echo-transmit-interval",
            config_ospf_bfd_echo_transmit_interval,
        );
        self.ospf_add(
            "/bfd/echo-receive-interval",
            config_ospf_bfd_echo_receive_interval,
        );
        self.ospf_add("/bfd/detect-offload", config_ospf_bfd_detect_offload);
        self.ospf_add(
            "/area/interface/network-type",
            config_ospf_interface_network_type,
        );
        self.ospf_add("/area/interface/passive", config_ospf_interface_passive);
        self.ospf_add("/area/interface/priority", config_ospf_interface_priority);
        self.ospf_add("/area/interface/cost", config_ospf_interface_cost);
        self.ospf_add("/area/interface/affinity", config_ospf_interface_affinity);
        self.ospf_add(
            "/area/interface/te-metric/unidirectional-delay",
            config_ospf_interface_te_unidirectional_delay,
        );
        self.ospf_add(
            "/area/interface/te-metric/min-delay",
            config_ospf_interface_te_min_delay,
        );
        self.ospf_add(
            "/area/interface/te-metric/max-delay",
            config_ospf_interface_te_max_delay,
        );
        self.ospf_add(
            "/area/interface/te-metric/delay-variation",
            config_ospf_interface_te_delay_variation,
        );
        self.ospf_add(
            "/area/interface/te-metric/loss",
            config_ospf_interface_te_loss,
        );
        // STAMP measurement block — v2 only (this `callback_build` is
        // `impl Ospf<Ospfv2>`; `config_v3.rs` registers nothing here,
        // so the v3 instance never enables measurement).
        self.ospf_add(
            "/area/interface/te-metric/measurement/enable",
            config_ospf_interface_te_measurement_enable,
        );
        self.ospf_add(
            "/area/interface/te-metric/measurement/interval",
            config_ospf_interface_te_measurement_interval,
        );
        self.ospf_add(
            "/area/interface/te-metric/measurement/damping-period",
            config_ospf_interface_te_measurement_damping_period,
        );
        self.ospf_add(
            "/area/interface/hello-interval",
            config_ospf_interface_hello_interval,
        );
        self.ospf_add(
            "/area/interface/dead-interval",
            config_ospf_interface_dead_interval,
        );
        self.ospf_add(
            "/area/interface/retransmit-interval",
            config_ospf_interface_retransmit_interval,
        );
        self.ospf_add(
            "/area/interface/mtu-ignore",
            config_ospf_interface_mtu_ignore,
        );
        self.ospf_add(
            "/area/interface/authentication",
            config_ospf_interface_authentication,
        );
        self.ospf_add(
            "/area/interface/authentication-key",
            config_ospf_interface_authentication_key,
        );
        self.ospf_add("/area/interface/key-chain", config_ospf_interface_key_chain);
        self.ospf_add(
            "/area/interface/message-digest-key/md5",
            config_ospf_interface_md5_key,
        );
        self.ospf_add(
            "/area/interface/crypto-key/hmac-sha-1",
            config_ospf_interface_crypto_key_hmac_sha_1,
        );
        self.ospf_add(
            "/area/interface/crypto-key/hmac-sha-256",
            config_ospf_interface_crypto_key_hmac_sha_256,
        );
        self.ospf_add(
            "/area/interface/crypto-key/hmac-sha-384",
            config_ospf_interface_crypto_key_hmac_sha_384,
        );
        self.ospf_add(
            "/area/interface/crypto-key/hmac-sha-512",
            config_ospf_interface_crypto_key_hmac_sha_512,
        );
        self.ospf_add(
            "/area/interface/prefix-sid/index",
            config_ospf_interface_prefix_sid_index,
        );
        self.ospf_add(
            "/area/interface/prefix-sid/absolute",
            config_ospf_interface_prefix_sid_absolute,
        );
        self.ospf_add(
            "/area/interface/flex-algo-prefix-sid/index",
            config_ospf_interface_flex_algo_prefix_sid_index,
        );
        self.ospf_add(
            "/area/interface/flex-algo-prefix-sid/absolute",
            config_ospf_interface_flex_algo_prefix_sid_absolute,
        );
        self.ospf_add(
            "/area/interface/adjacency-sid/index",
            config_ospf_interface_adjacency_sid_index,
        );
        self.ospf_add(
            "/area/interface/adjacency-sid/absolute",
            config_ospf_interface_adjacency_sid_absolute,
        );
        self.ospf_add("/segment-routing/mpls", config_ospf_sr_mpls);
        self.ospf_add("/fast-reroute/ti-lfa", config_ospf_ti_lfa);
        self.ospf_add(
            "/fast-reroute/ti-lfa/compute-mode/serial",
            config_ospf_ti_lfa_compute_mode_serial,
        );
        self.ospf_add(
            "/fast-reroute/ti-lfa/compute-mode/conservative",
            config_ospf_ti_lfa_compute_mode_conservative,
        );
        self.ospf_add(
            "/fast-reroute/ti-lfa/compute-mode/aggressive",
            config_ospf_ti_lfa_compute_mode_aggressive,
        );
        self.ospf_add(
            "/fast-reroute/ti-lfa/compute-mode/sharding",
            config_ospf_ti_lfa_compute_mode_sharding,
        );
        self.ospf_add(
            "/fast-reroute/ti-lfa/compute-mode/sharding/shards",
            config_ospf_ti_lfa_compute_shards,
        );
        self.ospf_add(
            "/fast-reroute/backup-as-primary",
            config_ospf_fast_reroute_backup_as_primary,
        );
        self.ospf_add(
            "/graceful-restart/helper-enabled",
            config_ospf_gr_helper_enabled,
        );
        self.ospf_add(
            "/graceful-restart/max-grace-period",
            config_ospf_gr_max_grace_period,
        );
        self.ospf_add(
            "/graceful-restart/helper-strict-lsa-checking",
            config_ospf_gr_helper_strict_lsa_checking,
        );
        self.ospf_add(
            "/graceful-restart/drain-time-ms",
            config_ospf_gr_drain_time_ms,
        );
        self.ospf_add("/spf-interval/initial-wait", config_ospf_spf_initial_wait);
        self.ospf_add(
            "/spf-interval/secondary-wait",
            config_ospf_spf_secondary_wait,
        );
        self.ospf_add("/spf-interval/maximum-wait", config_ospf_spf_maximum_wait);
        self.ospf_add("/min-ls-interval", config_ospf_min_ls_interval);
        self.ospf_add("/min-ls-arrival", config_ospf_min_ls_arrival);
        // `/router/ospf/tracing/...` is handled by the subtree dispatcher
        // `super::tracing::config_tracing_dispatch` (called from
        // `process_cm_msg` for paths this callback table does not claim),
        // not by per-node callbacks — the message-type names are YANG
        // presence containers, so they live in the path, not in args.
    }
}

/// Parse a YANG `union { uint32; inet:ipv4-address }` area-id arg into
/// the 32-bit area ID. `area 0` and `area 0.0.0.0` both normalize to
/// `0.0.0.0`. Tries dotted-quad first (more specific) so a bare digit
/// only falls through to the decimal interpretation.
pub(super) fn parse_area_id(s: &str) -> Option<Ipv4Addr> {
    if let Ok(addr) = s.parse::<Ipv4Addr>() {
        return Some(addr);
    }
    s.parse::<u32>().ok().map(Ipv4Addr::from)
}

/// Resolve the desired (enabled, area) state for `link`. The area now
/// comes from the parent `area` list in the YANG schema; each
/// per-interface callback writes it into `link.config.area` so this
/// IFSM transition helper keeps working unchanged.
pub(super) fn link_should_enable<V: OspfVersion>(link: &OspfLink<V>) -> (bool, Ipv4Addr) {
    if !link.config.enable {
        return (false, Ipv4Addr::UNSPECIFIED);
    }
    let area = link.config.area.unwrap_or(Ipv4Addr::UNSPECIFIED);
    (true, area)
}

pub(super) fn apply_link_enable_transition<V: OspfVersion>(
    link: &OspfLink<V>,
    next: bool,
    next_id: Ipv4Addr,
) {
    let curr = link.enabled;
    let curr_id = link.area_id;

    if curr {
        if next {
            if curr_id != next_id {
                // Enabled -> Enabled (area change).
                let _ = link.tx.send(Message::Disable(link.index, curr_id));
                let _ = link.tx.send(Message::Enable(link.index, next_id));
            }
        } else {
            // Enabled -> Disabled.
            let _ = link.tx.send(Message::Disable(link.index, curr_id));
        }
    } else if next {
        // Disabled -> Enabled.
        let _ = link.tx.send(Message::Enable(link.index, next_id));
    }
}

fn config_ospf_router_id(ospf: &mut Ospf, mut args: Args, op: ConfigOp) -> Option<()> {
    if op.is_set() {
        // Store the configured Router-ID; `refresh_router_id` pushes
        // it into the instance and every interface's `ident` and
        // re-originates. Previously this callback parsed the value
        // and dropped it, so every OSPFv2 instance kept the
        // constructor default (10.0.0.1) — making all routers share
        // one Router-ID, so each treated every neighbour's Hello as
        // self-originated and no adjacency ever formed.
        ospf.router_id_config = Some(args.v4addr()?);
    } else {
        // Delete falls back to the RIB-derived value (or the
        // constructor default) instead of keeping the old Router-ID.
        ospf.router_id_config = None;
    }
    ospf.refresh_router_id();
    Some(())
}

/// After mutating `ospf.areas[area_id].area_type`, push the new
/// value into every link's cached `area_type` so packet emit /
/// recv can read it directly without re-borrowing `ospf.areas`.
fn sync_area_type_to_links<V: OspfVersion>(ospf: &mut Ospf<V>, area_id: Ipv4Addr) {
    let Some(area) = ospf.areas.get(area_id) else {
        return;
    };
    let new_area_type = area.area_type;
    let ifindexes: Vec<u32> = area.links.iter().copied().collect();
    for ifindex in ifindexes {
        if let Some(link) = ospf.links.get_mut(&ifindex) {
            link.area_type = new_area_type;
        }
    }
}

/// Generic per-area `area-type` writer shared by v2 and v3 callbacks.
/// Looks up (or creates) the area, updates its `area_type.kind`
/// in-place, and leaves the sub-knobs alone — those have their own
/// callbacks. Hello/DBD pick up the new option bits on next emit;
/// existing neighbors with mismatched N/E bits drop out when the
/// next Hello arrives.
pub(super) fn area_type_set<V: OspfVersion>(
    ospf: &mut Ospf<V>,
    area_id: Ipv4Addr,
    kind: AreaTypeKind,
) {
    ospf.areas.fetch(area_id).area_type.kind = kind;
    sync_area_type_to_links(ospf, area_id);
}

pub(super) fn area_no_summary_set<V: OspfVersion>(
    ospf: &mut Ospf<V>,
    area_id: Ipv4Addr,
    value: bool,
) {
    ospf.areas.fetch(area_id).area_type.no_summary = value;
    sync_area_type_to_links(ospf, area_id);
}

pub(super) fn area_nssa_default_originate_set<V: OspfVersion>(
    ospf: &mut Ospf<V>,
    area_id: Ipv4Addr,
    value: bool,
) {
    ospf.areas.fetch(area_id).area_type.nssa_default_originate = value;
    sync_area_type_to_links(ospf, area_id);
}

pub(super) fn area_nssa_suppress_fa_set<V: OspfVersion>(
    ospf: &mut Ospf<V>,
    area_id: Ipv4Addr,
    value: bool,
) {
    ospf.areas.fetch(area_id).area_type.nssa_suppress_fa = value;
    sync_area_type_to_links(ospf, area_id);
}

pub(super) fn area_nssa_translator_role_set<V: OspfVersion>(
    ospf: &mut Ospf<V>,
    area_id: Ipv4Addr,
    role: NssaTranslatorRole,
) {
    ospf.areas.fetch(area_id).area_type.nssa_translator_role = role;
    sync_area_type_to_links(ospf, area_id);
}

/// `/router/ospf/area/<id>/area-type` — `normal | stub | nssa`.
/// Delete reverts to the default (`normal`).
///
/// Triggers `nssa_default_lsa_originate` after the area type change
/// so the Type-7 default-LSA appears when transitioning into NSSA
/// with `nssa-default-originate=true`, and is flushed when leaving
/// NSSA (the helper short-circuits to flush when the area is no
/// longer NSSA).
fn config_ospf_area_type(ospf: &mut Ospf, mut args: Args, op: ConfigOp) -> Option<()> {
    let area_id = parse_area_id(&args.string()?)?;
    let kind = if op.is_set() {
        AreaTypeKind::from_yang(&args.string()?)?
    } else {
        AreaTypeKind::default()
    };
    area_type_set(ospf, area_id, kind);
    ospf.nssa_default_lsa_originate(area_id);
    // Area-type transition flips whether redistributed Type-7s
    // are legal in this area — resync (originate fresh on
    // entry-to-NSSA, flush on exit).
    ospf.nssa_redist_connected_resync(area_id);
    // Area-type also flips whether we should be translating
    // Type-7→Type-5 for this area. Resync clears stale Type-5s on
    // exit and seeds fresh ones on entry (if we are an ABR with
    // translator-role = Always).
    ospf.nssa_translate_resync(area_id);
    Some(())
}

fn config_ospf_area_no_summary(ospf: &mut Ospf, mut args: Args, op: ConfigOp) -> Option<()> {
    let area_id = parse_area_id(&args.string()?)?;
    let value = op.is_set() && args.boolean()?;
    area_no_summary_set(ospf, area_id, value);
    Some(())
}

/// `/router/ospf/area/<id>/nssa-default-originate`. Trigger the
/// originator (or flush) — the helper inspects the current area
/// type + knob value and picks the right action.
fn config_ospf_area_nssa_default_originate(
    ospf: &mut Ospf,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let area_id = parse_area_id(&args.string()?)?;
    let value = op.is_set() && args.boolean()?;
    area_nssa_default_originate_set(ospf, area_id, value);
    ospf.nssa_default_lsa_originate(area_id);
    Some(())
}

fn config_ospf_area_nssa_suppress_fa(ospf: &mut Ospf, mut args: Args, op: ConfigOp) -> Option<()> {
    let area_id = parse_area_id(&args.string()?)?;
    let value = op.is_set() && args.boolean()?;
    area_nssa_suppress_fa_set(ospf, area_id, value);
    Some(())
}

fn config_ospf_area_nssa_translator_role(
    ospf: &mut Ospf,
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
    // Role flip (e.g. Candidate → Always) directly changes
    // whether translation should be happening on this router.
    ospf.nssa_translate_resync(area_id);
    Some(())
}

/// Send the appropriate RIB Redist message for the current state
/// of this area's `connected` redistribute knob. Mirrors IS-IS's
/// `send_redist` (`isis/config.rs:887`):
///   - knob removed from any NSSA area on this router → RedistDel
///   - knob present, first time across all NSSA areas → RedistAdd
///   - knob present, subsequent edit → RedistUpdate (no-op for
///     connected since subtypes are wildcard, but kept for
///     symmetry with future static / bgp sources)
///
/// RIB subscription is keyed by `(proto, afi, rtype)` — not per
/// area — so multiple NSSA areas with `redistribute connected`
/// share a single subscription. `any_connected_enabled` decides
/// whether the subscription should exist at all.
/// Subscribe / unsubscribe this instance's RIB redistribution for one
/// IPv4 source, gated on the instance-level knob (and, for connected,
/// the per-NSSA-area knobs too). Each `(afi, rtype)` row is its own
/// subscription. Uses this instance's proto label, not the literal
/// "ospf": a per-VRF instance registers as "ospf:vrf:<name>", and the
/// RIB routes the redistribute subscription by the proto string in the
/// message. With the literal, a VRF child's subscription resolved to
/// the default instance — so per-VRF redistribute never delivered.
fn ospf_send_redist(ospf: &Ospf, rtype: crate::rib::RibType, first_time: bool) {
    use crate::rib::{Message as RibMsg, RedistAfi, RibType};
    let proto = ospf.proto_label.clone();
    let afi = RedistAfi::Ipv4;

    let any_enabled = ospf.redist.contains_key(&rtype)
        || (rtype == RibType::Connected
            && ospf
                .areas
                .iter()
                .any(|(_, area)| area.redistribute.connected.is_some()));

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

/// Shared body of the instance-level `redistribute <source>` presence
/// handlers. On Set: subscribe to the source's routes and originate a
/// Type-5 AS-External LSA for each. On Delete: unsubscribe and flush.
fn ospf_redist_set(ospf: &mut Ospf, rtype: crate::rib::RibType, op: ConfigOp) -> Option<()> {
    use crate::rib::RibType;
    let nssa_connected = rtype == RibType::Connected
        && ospf
            .areas
            .iter()
            .any(|(_, area)| area.redistribute.connected.is_some());
    let first_time = !(ospf.redist.contains_key(&rtype) || nssa_connected);
    if op.is_set() {
        ospf.redist.insert(
            rtype,
            RedistEntry {
                metric: RedistEntry::DEFAULT_METRIC,
                ..Default::default()
            },
        );
    } else {
        ospf.redist.remove(&rtype);
    }
    ospf_send_redist(ospf, rtype, first_time && op.is_set());
    ospf.as_external_redist_resync(rtype);
    Some(())
}

/// Shared body of `redistribute <source> metric`.
fn ospf_redist_metric_set(
    ospf: &mut Ospf,
    rtype: crate::rib::RibType,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let metric = if op.is_set() {
        args.u32()?
    } else {
        RedistEntry::DEFAULT_METRIC
    };
    ospf.redist.entry(rtype).or_default().metric = metric;
    ospf.as_external_redist_resync(rtype);
    Some(())
}

/// Shared body of `redistribute <source> metric-type`.
fn ospf_redist_metric_type_set(
    ospf: &mut Ospf,
    rtype: crate::rib::RibType,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let mtype = if op.is_set() {
        ExternalMetricType::from_yang(&args.string()?)?
    } else {
        ExternalMetricType::default()
    };
    ospf.redist.entry(rtype).or_default().metric_type = mtype;
    ospf.as_external_redist_resync(rtype);
    Some(())
}

macro_rules! ospf_redist_handlers {
    ($set:ident, $metric:ident, $mtype:ident, $rtype:expr) => {
        fn $set(ospf: &mut Ospf, _args: Args, op: ConfigOp) -> Option<()> {
            ospf_redist_set(ospf, $rtype, op)
        }
        fn $metric(ospf: &mut Ospf, args: Args, op: ConfigOp) -> Option<()> {
            ospf_redist_metric_set(ospf, $rtype, args, op)
        }
        fn $mtype(ospf: &mut Ospf, args: Args, op: ConfigOp) -> Option<()> {
            ospf_redist_metric_type_set(ospf, $rtype, args, op)
        }
    };
}

ospf_redist_handlers!(
    config_ospf_redist_bgp,
    config_ospf_redist_bgp_metric,
    config_ospf_redist_bgp_metric_type,
    crate::rib::RibType::Bgp
);
ospf_redist_handlers!(
    config_ospf_redist_static,
    config_ospf_redist_static_metric,
    config_ospf_redist_static_metric_type,
    crate::rib::RibType::Static
);
ospf_redist_handlers!(
    config_ospf_redist_kernel,
    config_ospf_redist_kernel_metric,
    config_ospf_redist_kernel_metric_type,
    crate::rib::RibType::Kernel
);
ospf_redist_handlers!(
    config_ospf_redist_isis,
    config_ospf_redist_isis_metric,
    config_ospf_redist_isis_metric_type,
    crate::rib::RibType::Isis
);

/// Keep the RIB default watch aligned with the knob: subscribed
/// while `default-information originate` is set without `always`.
/// When the watch turns off, purge cached default entries that no
/// active per-rtype redistribute row covers — the RIB deliberately
/// does no Del replay (an overlapping row's cache entry must
/// survive), so the consumer owns this cleanup.
fn ospf_sync_default_watch(ospf: &mut Ospf) {
    use crate::rib::{Message as RibMsg, RedistAfi};
    let want = matches!(ospf.default_originate, Some(cfg) if !cfg.always);
    if want == ospf.default_watch_active {
        return;
    }
    let proto = ospf.proto_label.clone();
    let msg = if want {
        RibMsg::RedistDefaultAdd {
            proto,
            afi: RedistAfi::Ipv4,
        }
    } else {
        RibMsg::RedistDefaultDel {
            proto,
            afi: RedistAfi::Ipv4,
        }
    };
    let _ = ospf.ctx.rib.send(msg);
    ospf.default_watch_active = want;
    if !want {
        let covered = ospf.redist.clone();
        ospf.redist_v4
            .retain(|(rt, p), _| p.prefix_len() != 0 || covered.contains_key(rt));
    }
}

/// `/router/ospf/default-information/originate` — presence. Makes
/// this router an ASBR and (conditionally or with `always`)
/// originates the Type-5 default.
fn config_ospf_default_originate(ospf: &mut Ospf, _args: Args, op: ConfigOp) -> Option<()> {
    if op.is_set() {
        ospf.default_originate.get_or_insert_with(Default::default);
    } else {
        ospf.default_originate = None;
    }
    ospf_sync_default_watch(ospf);
    ospf.default_originate_resync();
    Some(())
}

/// `/router/ospf/default-information/originate/always`.
fn config_ospf_default_originate_always(
    ospf: &mut Ospf,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let value = if op.is_set() { args.boolean()? } else { false };
    ospf.default_originate
        .get_or_insert_with(Default::default)
        .always = value;
    ospf_sync_default_watch(ospf);
    ospf.default_originate_resync();
    Some(())
}

/// `/router/ospf/default-information/originate/metric`.
fn config_ospf_default_originate_metric(
    ospf: &mut Ospf,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let value = if op.is_set() { args.u32()? } else { 10 };
    ospf.default_originate
        .get_or_insert_with(Default::default)
        .metric = value;
    ospf.default_originate_resync();
    Some(())
}

/// `/router/ospf/default-information/originate/metric-type`.
fn config_ospf_default_originate_metric_type(
    ospf: &mut Ospf,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let value = if op.is_set() {
        ExternalMetricType::from_yang(&args.string()?)?
    } else {
        ExternalMetricType::default()
    };
    ospf.default_originate
        .get_or_insert_with(Default::default)
        .metric_type = value;
    ospf.default_originate_resync();
    Some(())
}

/// `/router/ospf/area/<id>/range` — one RFC 2328 §12.4.3 address
/// range entry (list keyed by prefix). Set creates it with defaults
/// (advertise, largest-component metric); delete removes it. Either
/// way the ABR summary reconciliation re-runs so aggregation applies
/// immediately.
fn config_ospf_area_range(ospf: &mut Ospf, mut args: Args, op: ConfigOp) -> Option<()> {
    let area_id = parse_area_id(&args.string()?)?;
    let prefix = args.v4net()?.trunc();
    if op.is_set() {
        ospf.areas.fetch(area_id).ranges.entry(prefix).or_default();
    } else if let Some(area) = ospf.areas.get_mut(area_id) {
        area.ranges.remove(&prefix);
    }
    ospf.abr_summary_originate();
    Some(())
}

/// `/router/ospf/area/<id>/range/<prefix>/not-advertise`.
fn config_ospf_area_range_not_advertise(
    ospf: &mut Ospf,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let area_id = parse_area_id(&args.string()?)?;
    let prefix = args.v4net()?.trunc();
    let value = if op.is_set() { args.boolean()? } else { false };
    ospf.areas
        .fetch(area_id)
        .ranges
        .entry(prefix)
        .or_default()
        .not_advertise = value;
    ospf.abr_summary_originate();
    Some(())
}

/// `/router/ospf/area/<id>/range/<prefix>/cost` — fixed aggregate
/// metric; delete reverts to largest-component.
fn config_ospf_area_range_cost(ospf: &mut Ospf, mut args: Args, op: ConfigOp) -> Option<()> {
    let area_id = parse_area_id(&args.string()?)?;
    let prefix = args.v4net()?.trunc();
    let cost = if op.is_set() { Some(args.u32()?) } else { None };
    ospf.areas
        .fetch(area_id)
        .ranges
        .entry(prefix)
        .or_default()
        .cost = cost;
    ospf.abr_summary_originate();
    Some(())
}

/// `/router/ospf/area/<transit-id>/virtual-link/<router-id>` —
/// RFC 2328 §15 virtual link through the list-key (transit) area to
/// the ABR `router-id`. The synthetic backbone interface itself is
/// materialized/torn down by `vl_reconcile` (driven off the transit
/// area's SPF), so config just records intent and reconciles.
fn config_ospf_area_virtual_link(ospf: &mut Ospf, mut args: Args, op: ConfigOp) -> Option<()> {
    let area_id = parse_area_id(&args.string()?)?;
    let peer = args.v4addr()?;
    if op.is_set() {
        ospf.areas
            .fetch(area_id)
            .virtual_links
            .entry(peer)
            .or_default();
    } else if let Some(area) = ospf.areas.get_mut(area_id) {
        area.virtual_links.remove(&peer);
    }
    ospf.vl_reconcile();
    Some(())
}

/// `/router/ospf/area/<id>/virtual-link/<rid>/hello-interval`.
fn config_ospf_area_virtual_link_hello_interval(
    ospf: &mut Ospf,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let area_id = parse_area_id(&args.string()?)?;
    let peer = args.v4addr()?;
    let value = if op.is_set() { Some(args.u16()?) } else { None };
    ospf.areas
        .fetch(area_id)
        .virtual_links
        .entry(peer)
        .or_default()
        .hello_interval = value;
    ospf.vl_reconcile();
    Some(())
}

/// `/router/ospf/area/<id>/virtual-link/<rid>/dead-interval`.
fn config_ospf_area_virtual_link_dead_interval(
    ospf: &mut Ospf,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let area_id = parse_area_id(&args.string()?)?;
    let peer = args.v4addr()?;
    let value = if op.is_set() { Some(args.u32()?) } else { None };
    ospf.areas
        .fetch(area_id)
        .virtual_links
        .entry(peer)
        .or_default()
        .dead_interval = value;
    ospf.vl_reconcile();
    Some(())
}

/// `/router/ospf/area/<id>/virtual-link/<rid>/retransmit-interval`.
fn config_ospf_area_virtual_link_retransmit_interval(
    ospf: &mut Ospf,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let area_id = parse_area_id(&args.string()?)?;
    let peer = args.v4addr()?;
    let value = if op.is_set() { Some(args.u16()?) } else { None };
    ospf.areas
        .fetch(area_id)
        .virtual_links
        .entry(peer)
        .or_default()
        .retransmit_interval = value;
    ospf.vl_reconcile();
    Some(())
}

/// `/router/ospf/area/<id>/virtual-link/<rid>/authentication` —
/// RFC 2328 §15: a virtual link carries its own authentication,
/// independent of the transit area's interfaces. Same modes as the
/// per-interface leaf.
fn config_ospf_area_virtual_link_authentication(
    ospf: &mut Ospf,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let area_id = parse_area_id(&args.string()?)?;
    let peer = args.v4addr()?;
    let mode = if op.is_set() {
        Some(match args.string()?.as_str() {
            "null" => OspfAuthMode::Null,
            "simple" => OspfAuthMode::Simple,
            "message-digest" => OspfAuthMode::MessageDigest,
            _ => return None,
        })
    } else {
        None
    };
    ospf.areas
        .fetch(area_id)
        .virtual_links
        .entry(peer)
        .or_default()
        .auth_mode = mode;
    ospf.vl_reconcile();
    Some(())
}

/// `/router/ospf/area/<id>/virtual-link/<rid>/authentication-key`.
fn config_ospf_area_virtual_link_authentication_key(
    ospf: &mut Ospf,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let area_id = parse_area_id(&args.string()?)?;
    let peer = args.v4addr()?;
    let key = if op.is_set() {
        let key = args.string()?;
        let bytes = key.as_bytes();
        // RFC 2328 §D.3 caps the simple-password at 8 octets.
        if bytes.is_empty() || bytes.len() > 8 {
            return None;
        }
        let mut padded = [0u8; 8];
        padded[..bytes.len()].copy_from_slice(bytes);
        Some(padded)
    } else {
        None
    };
    ospf.areas
        .fetch(area_id)
        .virtual_links
        .entry(peer)
        .or_default()
        .auth_key = key;
    ospf.vl_reconcile();
    Some(())
}

/// `/router/ospf/area/<id>/virtual-link/<rid>/message-digest-key/<key-id>/md5`.
fn config_ospf_area_virtual_link_md5_key(
    ospf: &mut Ospf,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    use super::link::{AuthKey, OspfCryptoAlgo};

    let area_id = parse_area_id(&args.string()?)?;
    let peer = args.v4addr()?;
    let key_id: u8 = args.string()?.parse().ok()?;
    if key_id == 0 {
        return None;
    }
    let vl = ospf
        .areas
        .fetch(area_id)
        .virtual_links
        .entry(peer)
        .or_default();
    if op.is_set() {
        let key = args.string()?;
        let bytes = key.as_bytes();
        // RFC 2328 §D.4 caps the simple MD5 key at 16 octets.
        if bytes.is_empty() || bytes.len() > 16 {
            return None;
        }
        let mut padded = vec![0u8; 16];
        padded[..bytes.len()].copy_from_slice(bytes);
        vl.crypto_keys.insert(
            key_id,
            AuthKey {
                algo: OspfCryptoAlgo::Md5,
                raw: padded,
            },
        );
    } else {
        vl.crypto_keys.remove(&key_id);
    }
    ospf.vl_reconcile();
    Some(())
}

/// `/router/ospf/area/<id>/virtual-link/<rid>/key-chain`.
fn config_ospf_area_virtual_link_key_chain(
    ospf: &mut Ospf,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let area_id = parse_area_id(&args.string()?)?;
    let peer = args.v4addr()?;
    let value = if op.is_set() {
        Some(args.string()?)
    } else {
        None
    };
    ospf.areas
        .fetch(area_id)
        .virtual_links
        .entry(peer)
        .or_default()
        .key_chain = value;
    ospf.vl_reconcile();
    Some(())
}

/// `/router/ospf/area/<id>/redistribute/connected` — presence
/// container. On Set: create the area's `RedistEntry` with
/// defaults (metric 20, E2) and (re)originate Type-7 LSAs for
/// every connected route the RIB has already pushed. On Delete:
/// drop the entry and flush our self-originated Type-7s that
/// belong to this area.
fn config_ospf_area_redist_connected(ospf: &mut Ospf, mut args: Args, op: ConfigOp) -> Option<()> {
    let area_id = parse_area_id(&args.string()?)?;

    // Was this the only NSSA area subscribed (or none yet)?
    let first_time = !ospf
        .areas
        .iter()
        .any(|(_, area)| area.redistribute.connected.is_some())
        && !ospf.redist.contains_key(&crate::rib::RibType::Connected);

    if op.is_set() {
        ospf.areas.fetch(area_id).redistribute.connected = Some(RedistEntry {
            metric: RedistEntry::DEFAULT_METRIC,
            ..Default::default()
        });
    } else if let Some(area) = ospf.areas.get_mut(area_id) {
        area.redistribute.connected = None;
    }

    ospf_send_redist(
        ospf,
        crate::rib::RibType::Connected,
        first_time && op.is_set(),
    );
    ospf.nssa_redist_connected_resync(area_id);
    Some(())
}

/// `/router/ospf/area/<id>/redistribute/connected/metric`.
/// Consumer-side override; no RIB resubscribe needed.
fn config_ospf_area_redist_connected_metric(
    ospf: &mut Ospf,
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
    ospf.nssa_redist_connected_resync(area_id);
    Some(())
}

/// `/router/ospf/area/<id>/redistribute/connected/metric-type` —
/// `type-1` / `type-2`. Re-originates all Type-7s for the area
/// since the E-bit changes per-LSA.
fn config_ospf_area_redist_connected_metric_type(
    ospf: &mut Ospf,
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
    ospf.nssa_redist_connected_resync(area_id);
    Some(())
}

pub(super) fn ospf_link_get_mut_by_name<'a, V: OspfVersion>(
    links: &'a mut BTreeMap<u32, OspfLink<V>>,
    name: &str,
) -> Option<&'a mut OspfLink<V>> {
    links.values_mut().find(|link| link.name == name)
}

fn config_ospf_interface_enable(ospf: &mut Ospf, mut args: Args, op: ConfigOp) -> Option<()> {
    let area_id = parse_area_id(&args.string()?)?;
    let name = args.string()?;
    let enable = args.boolean()?;

    let link = ospf_link_get_mut_by_name(&mut ospf.links, &name)?;

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

/// `/router/ospf/area/<id>/interface/<name>/network-type` — accepts
/// `broadcast` or `point-to-point` (YANG enum, kebab-case). Mirrors
/// the IS-IS `network-type` knob: bounce the interface on any change
/// so the IFSM re-initializes from the new type's entry state (P2P
/// skips Waiting / DR election; Broadcast goes through Waiting).
fn config_ospf_interface_network_type(ospf: &mut Ospf, mut args: Args, op: ConfigOp) -> Option<()> {
    let _area_id = parse_area_id(&args.string()?)?;
    let name = args.string()?;
    let network_type = args.string()?.parse::<OspfNetworkType>().ok()?;

    let link = ospf_link_get_mut_by_name(&mut ospf.links, &name)?;
    let old = link.config_network_type();
    if op.is_set() {
        link.config.network_type = Some(network_type);
    } else {
        link.config.network_type = None;
    }
    let new = link.config_network_type();

    // Network-type change on an already-enabled interface invalidates
    // the IFSM state (P2P shouldn't be in Waiting/DROther; broadcast
    // shouldn't be in PointToPoint) and the cached neighbor list.
    // Disable+Enable through the existing channel rebuilds both.
    if old != new && link.enabled {
        let area_id = link.area_id;
        let _ = link.tx.send(Message::Disable(link.index, area_id));
        let _ = link.tx.send(Message::Enable(link.index, area_id));
    }

    Some(())
}

/// `/router/ospf/area/<id>/interface/<name>/passive` — passive
/// interface: prefixes keep advertising, but the Hello send/receive
/// paths gate on `OspfLink::is_passive()`, so no Hello flows and no
/// adjacency forms. Toggling bounces the interface (Disable→Enable)
/// so an adjacency formed while active is dropped and the IFSM
/// re-enters from the correct state.
fn config_ospf_interface_passive(ospf: &mut Ospf, mut args: Args, op: ConfigOp) -> Option<()> {
    let _area_id = parse_area_id(&args.string()?)?;
    let name = args.string()?;
    let passive = args.boolean()?;

    let link = ospf_link_get_mut_by_name(&mut ospf.links, &name)?;
    let old = link.config.passive;
    link.config.passive = op.is_set() && passive;

    if old != link.config.passive && link.enabled {
        let area_id = link.area_id;
        let _ = link.tx.send(Message::Disable(link.index, area_id));
        let _ = link.tx.send(Message::Enable(link.index, area_id));
    }

    Some(())
}

fn config_ospf_interface_priority(ospf: &mut Ospf, mut args: Args, op: ConfigOp) -> Option<()> {
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

/// `/router/ospf/area/<id>/interface/<name>/cost` — RFC 2328 §C.3
/// interface output cost, i.e. the metric stamped on this link in the
/// Router-LSA (and the SPF edge weight). Stored straight into
/// `link.output_cost`; clearing restores the protocol default (10).
/// Because the metric rides in every attached area's Router-LSA,
/// re-originate — which re-emits one Router-LSA per area and schedules
/// that area's SPF — so the new cost takes effect immediately.
fn config_ospf_interface_cost(ospf: &mut Ospf, mut args: Args, op: ConfigOp) -> Option<()> {
    let _area_id = parse_area_id(&args.string()?)?;
    let name = args.string()?;
    let cost = args.u16()?;

    let link = ospf_link_get_mut_by_name(&mut ospf.links, &name)?;
    link.output_cost = if op.is_set() {
        cost as u32
    } else {
        OSPF_DEFAULT_OUTPUT_COST
    };

    ospf.router_lsa_originate();

    Some(())
}

// `/router/ospf/area/interface/affinity` — one call per affinity name
// on the leaf-list. Each name references a global `/affinity-map`
// entry; the bit positions are resolved at LSA-build time, so we only
// stage the names here (matching the per-interface IS-IS handler).
// Extended-Link ASLA origination from these names lands with flex-algo
// origination (RFC 9350 §6.3); for now this is pure config staging.
fn config_ospf_interface_affinity(ospf: &mut Ospf, mut args: Args, op: ConfigOp) -> Option<()> {
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

// `/router/ospf/area/interface/te-metric/*` — static RFC 7471 TE link
// metrics. Each leaf shares this helper: parse the area-id / interface
// name / u32 value, set or clear one `LinkTeMetric` field, then
// re-originate the Extended-Link Opaque LSA so the metric rides in the
// link's ASLA sub-TLV. Origination only happens when SR-MPLS is enabled
// (see `ext_link_lsa_originate`).
fn config_ospf_interface_te_metric(
    ospf: &mut Ospf,
    mut args: Args,
    op: ConfigOp,
    set: impl Fn(&mut super::link::LinkTeMetric, Option<u32>),
) -> Option<()> {
    let _area_id = parse_area_id(&args.string()?)?;
    let name = args.string()?;
    let value = args.u32()?;

    let link = ospf_link_get_mut_by_name(&mut ospf.links, &name)?;
    set(&mut link.config.te_metric, op.is_set().then_some(value));
    let ifindex = link.index;

    ospf.ext_link_lsa_originate(ifindex);

    Some(())
}

fn config_ospf_interface_te_unidirectional_delay(
    ospf: &mut Ospf,
    args: Args,
    op: ConfigOp,
) -> Option<()> {
    config_ospf_interface_te_metric(ospf, args, op, |m, v| m.unidirectional_delay = v)
}

fn config_ospf_interface_te_min_delay(ospf: &mut Ospf, args: Args, op: ConfigOp) -> Option<()> {
    config_ospf_interface_te_metric(ospf, args, op, |m, v| m.min_delay = v)
}

fn config_ospf_interface_te_max_delay(ospf: &mut Ospf, args: Args, op: ConfigOp) -> Option<()> {
    config_ospf_interface_te_metric(ospf, args, op, |m, v| m.max_delay = v)
}

fn config_ospf_interface_te_delay_variation(
    ospf: &mut Ospf,
    args: Args,
    op: ConfigOp,
) -> Option<()> {
    config_ospf_interface_te_metric(ospf, args, op, |m, v| m.delay_variation = v)
}

fn config_ospf_interface_te_loss(ospf: &mut Ospf, args: Args, op: ConfigOp) -> Option<()> {
    config_ospf_interface_te_metric(ospf, args, op, |m, v| m.loss = v)
}

// `/router/ospf/area/interface/te-metric/measurement/*` — the STAMP
// measurement block. Each leaf updates the config mirror and re-runs
// the session reconcile, which (un)subscribes on real changes and —
// on a teardown — clears the measured values and refreshes the
// Extended-Link LSA.
fn config_ospf_interface_te_measurement(
    ospf: &mut Ospf,
    mut args: Args,
    set: impl FnOnce(&mut crate::stamp::session::MeasurementConfig, &mut Args) -> Option<()>,
) -> Option<()> {
    let _area_id = parse_area_id(&args.string()?)?;
    let name = args.string()?;
    let link = ospf_link_get_mut_by_name(&mut ospf.links, &name)?;
    let ifindex = link.index;
    set(&mut link.config.te_metric_measurement, &mut args)?;
    ospf.stamp_reconcile_and_originate(ifindex);
    Some(())
}

fn config_ospf_interface_te_measurement_enable(
    ospf: &mut Ospf,
    args: Args,
    op: ConfigOp,
) -> Option<()> {
    config_ospf_interface_te_measurement(ospf, args, |m, args| {
        let value = args.boolean()?;
        m.enable = op.is_set().then_some(value);
        Some(())
    })
}

fn config_ospf_interface_te_measurement_interval(
    ospf: &mut Ospf,
    args: Args,
    op: ConfigOp,
) -> Option<()> {
    config_ospf_interface_te_measurement(ospf, args, |m, args| {
        let value = args.u32()?;
        m.interval_ms = op.is_set().then_some(value);
        Some(())
    })
}

fn config_ospf_interface_te_measurement_damping_period(
    ospf: &mut Ospf,
    args: Args,
    op: ConfigOp,
) -> Option<()> {
    config_ospf_interface_te_measurement(ospf, args, |m, args| {
        let value = args.u32()?;
        m.damping_period_secs = op.is_set().then_some(value);
        Some(())
    })
}

fn config_ospf_interface_hello_interval(
    ospf: &mut Ospf,
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

/// `interface <if> bfd enable <bool>` — attach/detach BFD on this
/// OSPF interface. Generic over `V` (shared by v2 and v3); reconciles
/// every neighbor on the link so already-formed adjacencies pick up
/// the change.
pub(super) fn config_ospf_interface_bfd_enable<V: OspfVersion>(
    ospf: &mut Ospf<V>,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let _area_id = parse_area_id(&args.string()?)?;
    let name = args.string()?;
    let enable = args.boolean()?;

    let ifindex = {
        let link = ospf_link_get_mut_by_name(&mut ospf.links, &name)?;
        // `None` ⇒ inherit the instance-level `bfd { enable }`; `Some(false)`
        // explicitly opts this interface out of a blanket instance enable.
        link.config.bfd.enable = op.is_set().then_some(enable);
        link.index
    };
    ospf.bfd_reconcile_link(ifindex);
    Some(())
}

/// `interface <if> bfd echo-mode <transmit|receive|both>` — which BFD Echo
/// role is active on this interface (RFC 5880 §6.4): `transmit` originates,
/// `receive` advertises + reflects, `both` does both. Single-hop IPv4 only.
/// Reconciles the link; the BFD instance applies the change to live sessions.
pub(super) fn config_ospf_interface_bfd_echo_mode<V: OspfVersion>(
    ospf: &mut Ospf<V>,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let _area_id = parse_area_id(&args.string()?)?;
    let name = args.string()?;
    let value = args.string()?;

    let mode = if op.is_set() {
        match value.as_str() {
            "transmit" => Some(EchoMode::Transmit),
            "receive" => Some(EchoMode::Receive),
            "both" => Some(EchoMode::Both),
            _ => return None,
        }
    } else {
        None
    };
    let ifindex = {
        let link = ospf_link_get_mut_by_name(&mut ospf.links, &name)?;
        link.config.bfd.echo_mode = mode;
        link.index
    };
    ospf.bfd_reconcile_link(ifindex);
    Some(())
}

/// `interface <if> bfd echo-transmit-interval <ms>` — the rate we originate
/// Echo at. Reconciles the link so live sessions pick the new rate up.
pub(super) fn config_ospf_interface_bfd_echo_transmit_interval<V: OspfVersion>(
    ospf: &mut Ospf<V>,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let _area_id = parse_area_id(&args.string()?)?;
    let name = args.string()?;
    let interval = args.u32()?;

    let ifindex = {
        let link = ospf_link_get_mut_by_name(&mut ospf.links, &name)?;
        link.config.bfd.echo_transmit_ms = op.is_set().then_some(interval);
        link.index
    };
    ospf.bfd_reconcile_link(ifindex);
    Some(())
}

/// `interface <if> bfd echo-receive-interval <ms>` — the advertised Required
/// Min Echo RX Interval. Reconciles the link so live sessions pick it up.
pub(super) fn config_ospf_interface_bfd_echo_receive_interval<V: OspfVersion>(
    ospf: &mut Ospf<V>,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let _area_id = parse_area_id(&args.string()?)?;
    let name = args.string()?;
    let interval = args.u32()?;

    let ifindex = {
        let link = ospf_link_get_mut_by_name(&mut ospf.links, &name)?;
        link.config.bfd.echo_receive_ms = op.is_set().then_some(interval);
        link.index
    };
    ospf.bfd_reconcile_link(ifindex);
    Some(())
}

/// `interface <if> bfd detect-offload <bool>` — offload control-packet
/// expiration detection to the per-interface XDP helper once the session is
/// Up (RFC 5880 §6.8.4 evaluated in-kernel). Reconciles the link; the BFD
/// instance arms/disarms the watchdog on live sessions.
pub(super) fn config_ospf_interface_bfd_detect_offload<V: OspfVersion>(
    ospf: &mut Ospf<V>,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let _area_id = parse_area_id(&args.string()?)?;
    let name = args.string()?;
    let offload = args.boolean()?;

    let ifindex = {
        let link = ospf_link_get_mut_by_name(&mut ospf.links, &name)?;
        // `None` ⇒ inherit the instance-level `bfd { detect-offload }`;
        // `Some(false)` explicitly opts this interface out.
        link.config.bfd.detect_offload = op.is_set().then_some(offload);
        link.index
    };
    ospf.bfd_reconcile_link(ifindex);
    Some(())
}

/// `interface <if> bfd min-neighbor-state <two-way|full>` — the NFSM
/// state at which the session is started/torn down. Default `two-way`
/// (FRR-style). Reconciles existing neighbors so a live flip takes
/// effect immediately.
pub(super) fn config_ospf_interface_bfd_min_neighbor_state<V: OspfVersion>(
    ospf: &mut Ospf<V>,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let _area_id = parse_area_id(&args.string()?)?;
    let name = args.string()?;
    let value = args.string()?;

    let threshold = op.is_set().then_some(match value.as_str() {
        "full" => NbrStateThreshold::Full,
        _ => NbrStateThreshold::TwoWay,
    });

    let ifindex = {
        let link = ospf_link_get_mut_by_name(&mut ospf.links, &name)?;
        // `None` ⇒ inherit the instance-level `bfd { min-neighbor-state }`
        // (hard default `two-way`).
        link.config.bfd.min_neighbor_state = threshold;
        link.index
    };
    ospf.bfd_reconcile_link(ifindex);
    Some(())
}

// ---- instance-level `router ospf{,v3} { bfd { ... } }` defaults --------------
// Each leaf becomes the default inherited by every interface's `bfd {}` block
// (overridable per interface via `OspfLinkBfdConfig::resolve`). Generic over
// `V`; registered by both v2 (`config.rs`) and v3 (`config_v3.rs`).

/// `router ospf bfd enable <bool>` — blanket-enable BFD on every interface in
/// the instance (a per-interface `bfd { enable false }` opts one out).
pub(super) fn config_ospf_bfd_enable<V: OspfVersion>(
    ospf: &mut Ospf<V>,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let enable = args.boolean()?;
    ospf.bfd.enable = op.is_set().then_some(enable);
    ospf.bfd_reconcile_all();
    Some(())
}

/// `router ospf bfd min-neighbor-state <two-way|full>` — instance default.
pub(super) fn config_ospf_bfd_min_neighbor_state<V: OspfVersion>(
    ospf: &mut Ospf<V>,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let value = args.string()?;
    ospf.bfd.min_neighbor_state = op.is_set().then_some(match value.as_str() {
        "full" => NbrStateThreshold::Full,
        _ => NbrStateThreshold::TwoWay,
    });
    ospf.bfd_reconcile_all();
    Some(())
}

/// `router ospf bfd echo-mode <transmit|receive|both>` — instance default Echo
/// role for every interface.
pub(super) fn config_ospf_bfd_echo_mode<V: OspfVersion>(
    ospf: &mut Ospf<V>,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let value = args.string()?;
    ospf.bfd.echo_mode = if op.is_set() {
        match value.as_str() {
            "transmit" => Some(EchoMode::Transmit),
            "receive" => Some(EchoMode::Receive),
            "both" => Some(EchoMode::Both),
            _ => return None,
        }
    } else {
        None
    };
    ospf.bfd_reconcile_all();
    Some(())
}

/// `router ospf bfd echo-transmit-interval <ms>` — instance default.
/// Reconciles so live sessions pick the new rate up.
pub(super) fn config_ospf_bfd_echo_transmit_interval<V: OspfVersion>(
    ospf: &mut Ospf<V>,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let interval = args.u32()?;
    ospf.bfd.echo_transmit_ms = op.is_set().then_some(interval);
    ospf.bfd_reconcile_all();
    Some(())
}

/// `router ospf bfd echo-receive-interval <ms>` — instance default.
/// Reconciles so live sessions pick the new advertisement up.
pub(super) fn config_ospf_bfd_echo_receive_interval<V: OspfVersion>(
    ospf: &mut Ospf<V>,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let interval = args.u32()?;
    ospf.bfd.echo_receive_ms = op.is_set().then_some(interval);
    ospf.bfd_reconcile_all();
    Some(())
}

/// `router ospf bfd detect-offload <bool>` — instance default for offloading
/// expiration detection to the XDP helper (overridable per interface).
pub(super) fn config_ospf_bfd_detect_offload<V: OspfVersion>(
    ospf: &mut Ospf<V>,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let offload = args.boolean()?;
    ospf.bfd.detect_offload = op.is_set().then_some(offload);
    ospf.bfd_reconcile_all();
    Some(())
}

fn config_ospf_interface_dead_interval(
    ospf: &mut Ospf,
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

fn config_ospf_interface_retransmit_interval(
    ospf: &mut Ospf,
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

fn config_ospf_interface_mtu_ignore(ospf: &mut Ospf, mut args: Args, op: ConfigOp) -> Option<()> {
    let _area_id = parse_area_id(&args.string()?)?;
    let name = args.string()?;
    let mtu_ignore = args.boolean()?;

    let link = ospf_link_get_mut_by_name(&mut ospf.links, &name)?;
    link.config.mtu_ignore = op.is_set() && mtu_ignore;

    Some(())
}

fn config_ospf_interface_authentication(
    ospf: &mut Ospf,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let _area_id = parse_area_id(&args.string()?)?;
    let name = args.string()?;
    let mode = args.string()?;

    let link = ospf_link_get_mut_by_name(&mut ospf.links, &name)?;
    if op.is_set() {
        link.config.auth_mode = Some(match mode.as_str() {
            "null" => OspfAuthMode::Null,
            "simple" => OspfAuthMode::Simple,
            "message-digest" => OspfAuthMode::MessageDigest,
            _ => return None,
        });
    } else {
        link.config.auth_mode = None;
    }

    Some(())
}

fn config_ospf_interface_authentication_key(
    ospf: &mut Ospf,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let _area_id = parse_area_id(&args.string()?)?;
    let name = args.string()?;
    let key = args.string()?;

    let link = ospf_link_get_mut_by_name(&mut ospf.links, &name)?;
    if op.is_set() {
        // RFC 2328 §D.3 caps the simple-password at 8 octets. YANG
        // also enforces `length 1..8`; this is a belt-and-suspenders
        // truncation in case the schema isn't loaded.
        let bytes = key.as_bytes();
        if bytes.is_empty() || bytes.len() > 8 {
            return None;
        }
        let mut padded = [0u8; 8];
        padded[..bytes.len()].copy_from_slice(bytes);
        link.config.auth_key = Some(padded);
    } else {
        link.config.auth_key = None;
    }

    Some(())
}

fn config_ospf_interface_md5_key(ospf: &mut Ospf, mut args: Args, op: ConfigOp) -> Option<()> {
    use super::link::{AuthKey, OspfCryptoAlgo};

    let _area_id = parse_area_id(&args.string()?)?;
    let name = args.string()?;
    let key_id: u8 = args.string()?.parse().ok()?;
    if key_id == 0 {
        return None;
    }

    let link = ospf_link_get_mut_by_name(&mut ospf.links, &name)?;
    if op.is_set() {
        let key = args.string()?;
        let bytes = key.as_bytes();
        // RFC 2328 §D.4 caps the simple MD5 key at 16 octets (the
        // block size for the `MD5(packet || key)` construction).
        // YANG also enforces `length 1..16`.
        if bytes.is_empty() || bytes.len() > 16 {
            return None;
        }
        let mut padded = vec![0u8; 16];
        padded[..bytes.len()].copy_from_slice(bytes);
        link.config.crypto_keys.insert(
            key_id,
            AuthKey {
                algo: OspfCryptoAlgo::Md5,
                raw: padded,
            },
        );
    } else {
        link.config.crypto_keys.remove(&key_id);
    }

    Some(())
}

/// Shared body for the four `/area/interface/crypto-key/hmac-sha-*`
/// callbacks. The leaf name selects the algorithm (each leaf
/// registers a distinct closure that fixes `algo` and calls in).
fn install_crypto_hmac_key(
    ospf: &mut Ospf,
    mut args: Args,
    op: ConfigOp,
    algo: super::link::OspfCryptoAlgo,
) -> Option<()> {
    use super::link::AuthKey;

    let _area_id = parse_area_id(&args.string()?)?;
    let name = args.string()?;
    let key_id: u8 = args.string()?.parse().ok()?;
    if key_id == 0 {
        return None;
    }

    let link = ospf_link_get_mut_by_name(&mut ospf.links, &name)?;
    if op.is_set() {
        let key = args.string()?;
        let bytes = key.as_bytes();
        // RFC 5709 §3.4 caps each algorithm at its block size.
        if bytes.is_empty() || bytes.len() > algo.digest_len() {
            return None;
        }
        link.config.crypto_keys.insert(
            key_id,
            AuthKey {
                algo,
                raw: bytes.to_vec(),
            },
        );
    } else {
        link.config.crypto_keys.remove(&key_id);
    }

    Some(())
}

fn config_ospf_interface_crypto_key_hmac_sha_1(
    ospf: &mut Ospf,
    args: Args,
    op: ConfigOp,
) -> Option<()> {
    install_crypto_hmac_key(ospf, args, op, super::link::OspfCryptoAlgo::HmacSha1)
}

fn config_ospf_interface_crypto_key_hmac_sha_256(
    ospf: &mut Ospf,
    args: Args,
    op: ConfigOp,
) -> Option<()> {
    install_crypto_hmac_key(ospf, args, op, super::link::OspfCryptoAlgo::HmacSha256)
}

fn config_ospf_interface_crypto_key_hmac_sha_384(
    ospf: &mut Ospf,
    args: Args,
    op: ConfigOp,
) -> Option<()> {
    install_crypto_hmac_key(ospf, args, op, super::link::OspfCryptoAlgo::HmacSha384)
}

fn config_ospf_interface_crypto_key_hmac_sha_512(
    ospf: &mut Ospf,
    args: Args,
    op: ConfigOp,
) -> Option<()> {
    install_crypto_hmac_key(ospf, args, op, super::link::OspfCryptoAlgo::HmacSha512)
}

fn config_ospf_interface_key_chain(ospf: &mut Ospf, mut args: Args, op: ConfigOp) -> Option<()> {
    let _area_id = parse_area_id(&args.string()?)?;
    let name = args.string()?;
    let link = ospf_link_get_mut_by_name(&mut ospf.links, &name)?;
    let link_index = link.index;
    // Capture the prior chain name before mutating so the
    // Unregister we send on a rename/delete drops the *old*
    // subscription, not the new one.
    let prev = link.config.key_chain.clone();
    let next = if op.is_set() { args.string() } else { None };
    link.config.key_chain = next.clone();

    use crate::policy::{KeyChainScope, Message as PolicyMsg, PolicyType};
    let scope = PolicyType::KeyChain(KeyChainScope::OspfInterface);
    if prev != next {
        if let Some(prev_name) = prev {
            let _ = ospf.policy_tx.send(PolicyMsg::Unregister {
                proto: "ospf".into(),
                name: prev_name,
                ident: link_index as usize,
                policy_type: scope,
            });
        }
        if let Some(new_name) = next {
            let _ = ospf.policy_tx.send(PolicyMsg::Register {
                proto: "ospf".into(),
                name: new_name,
                ident: link_index as usize,
                policy_type: scope,
            });
        }
    }
    Some(())
}

fn config_ospf_interface_prefix_sid_index(
    ospf: &mut Ospf,
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

    ospf.ext_prefix_lsa_originate(ifindex);

    Some(())
}

fn config_ospf_interface_prefix_sid_absolute(
    ospf: &mut Ospf,
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

    ospf.ext_prefix_lsa_originate(ifindex);

    Some(())
}

// `/router/ospf/area/interface/flex-algo-prefix-sid/<algo>/index` —
// per-algo Index-form Prefix-SID for this interface's prefix
// (RFC 9350 §7). Stored keyed by algo and re-originates the
// Extended-Prefix Opaque LSA so the extra Prefix-SID sub-TLV appears.
fn config_ospf_interface_flex_algo_prefix_sid_index(
    ospf: &mut Ospf,
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

    ospf.ext_prefix_lsa_originate(ifindex);

    Some(())
}

// `/router/ospf/area/interface/flex-algo-prefix-sid/<algo>/absolute` —
// per-algo Absolute (label) Prefix-SID sibling of the index form.
fn config_ospf_interface_flex_algo_prefix_sid_absolute(
    ospf: &mut Ospf,
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

    ospf.ext_prefix_lsa_originate(ifindex);

    Some(())
}

/// Store the Index-form Adjacency-SID for this interface and re-
/// originate the per-link Extended-Link Opaque LSA. The originator
/// gates on SR-MPLS enabled + a Full neighbor on a P2P link, so the
/// LSA is flushed automatically if any precondition is unmet.
fn config_ospf_interface_adjacency_sid_index(
    ospf: &mut Ospf,
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

    ospf.ext_link_lsa_originate(ifindex);

    Some(())
}

fn config_ospf_interface_adjacency_sid_absolute(
    ospf: &mut Ospf,
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

    ospf.ext_link_lsa_originate(ifindex);

    Some(())
}

/// `/router/ospf/fast-reroute/ti-lfa`. Gates the per-destination
/// TI-LFA repair computation (RFC 9490). On a state change, kick an
/// SPF recompute for every attached area so the RIB picks up repair
/// paths (on enable) or drops them (on disable). No LSA re-origination
/// is needed: the repair is a local install-side decision and changes
/// nothing this router advertises.
fn config_ospf_ti_lfa(ospf: &mut Ospf, _args: Args, op: ConfigOp) -> Option<()> {
    let prev = ospf.ti_lfa_enabled;
    ospf.ti_lfa_enabled = op.is_set();
    if ospf.ti_lfa_enabled == prev {
        return Some(());
    }
    let area_ids: Vec<Ipv4Addr> = ospf.areas.iter().map(|(id, _)| *id).collect();
    for id in area_ids {
        let _ = ospf.tx.send(Message::SpfCalc(id));
    }
    Some(())
}

/// Re-run SPF on every area iff the *effective* TI-LFA scheduling mode
/// (mode + shard count) changed from `prev`. Results are identical
/// across modes — nothing advertised changes, no LSA re-origination;
/// the SPF re-run only makes the new schedule observable in telemetry.
fn ospf_ti_lfa_recompute_if_changed(ospf: &mut Ospf, prev: crate::spf::TilfaComputeMode) {
    if ospf
        .ti_lfa_compute_mode
        .with_shards(ospf.ti_lfa_compute_shards)
        == prev
    {
        return;
    }
    let area_ids: Vec<Ipv4Addr> = ospf.areas.iter().map(|(id, _)| *id).collect();
    for id in area_ids {
        let _ = ospf.tx.send(Message::SpfCalc(id));
    }
}

/// Set the payload-free `compute-mode` selector and re-run SPF on an
/// effective-mode change. Shared by the per-case callbacks below.
fn apply_ospf_ti_lfa_compute_mode(ospf: &mut Ospf, mode: crate::spf::TilfaComputeModeConfig) {
    let prev = ospf
        .ti_lfa_compute_mode
        .with_shards(ospf.ti_lfa_compute_shards);
    ospf.ti_lfa_compute_mode = mode;
    ospf_ti_lfa_recompute_if_changed(ospf, prev);
}

/// Body shared by the `serial` / `conservative` / `aggressive`
/// `compute-mode` cases (each an empty leaf under the `mode` choice).
/// Setting the case selects `mode`; deleting it reverts to the default
/// mode — but only when *this* case is the active one, so a stale
/// delete of a non-active case node (the candidate store does not
/// auto-clear sibling choice cases) is a no-op rather than clobbering a
/// newer selection.
fn config_ospf_ti_lfa_compute_mode_case(
    ospf: &mut Ospf,
    op: ConfigOp,
    mode: crate::spf::TilfaComputeModeConfig,
) -> Option<()> {
    if op.is_set() {
        apply_ospf_ti_lfa_compute_mode(ospf, mode);
    } else if ospf.ti_lfa_compute_mode == mode {
        apply_ospf_ti_lfa_compute_mode(ospf, crate::spf::TilfaComputeModeConfig::default());
    }
    Some(())
}

/// `/router/ospf/fast-reroute/ti-lfa/compute-mode/serial`.
fn config_ospf_ti_lfa_compute_mode_serial(
    ospf: &mut Ospf,
    _args: Args,
    op: ConfigOp,
) -> Option<()> {
    config_ospf_ti_lfa_compute_mode_case(ospf, op, crate::spf::TilfaComputeModeConfig::Serial)
}

/// `/router/ospf/fast-reroute/ti-lfa/compute-mode/conservative`.
fn config_ospf_ti_lfa_compute_mode_conservative(
    ospf: &mut Ospf,
    _args: Args,
    op: ConfigOp,
) -> Option<()> {
    config_ospf_ti_lfa_compute_mode_case(ospf, op, crate::spf::TilfaComputeModeConfig::Conservative)
}

/// `/router/ospf/fast-reroute/ti-lfa/compute-mode/aggressive`.
fn config_ospf_ti_lfa_compute_mode_aggressive(
    ospf: &mut Ospf,
    _args: Args,
    op: ConfigOp,
) -> Option<()> {
    config_ospf_ti_lfa_compute_mode_case(ospf, op, crate::spf::TilfaComputeModeConfig::Aggressive)
}

/// `/router/ospf/fast-reroute/ti-lfa/compute-mode/sharding` — the
/// presence container for the sharding case. Bare `sharding` selects
/// the mode with the default shard count; the `shards` child overrides
/// the count. Deleting the container drops the whole sharding subtree,
/// so reset the count here too (regardless of whether the child
/// `shards` delete also fires) and revert the mode when sharding is the
/// active case.
fn config_ospf_ti_lfa_compute_mode_sharding(
    ospf: &mut Ospf,
    _args: Args,
    op: ConfigOp,
) -> Option<()> {
    if op.is_set() {
        apply_ospf_ti_lfa_compute_mode(ospf, crate::spf::TilfaComputeModeConfig::Sharding);
    } else {
        let prev = ospf
            .ti_lfa_compute_mode
            .with_shards(ospf.ti_lfa_compute_shards);
        // Matches the YANG `default 8` on the `shards` leaf.
        ospf.ti_lfa_compute_shards = 8;
        if ospf.ti_lfa_compute_mode == crate::spf::TilfaComputeModeConfig::Sharding {
            ospf.ti_lfa_compute_mode = crate::spf::TilfaComputeModeConfig::default();
        }
        ospf_ti_lfa_recompute_if_changed(ospf, prev);
    }
    Some(())
}

/// `/router/ospf/fast-reroute/ti-lfa/compute-mode/sharding/shards`.
/// Upper bound on TI-LFA parallelism; consulted only when sharding is
/// the active mode (the effective-mode comparison keeps the SPF re-run
/// suppressed otherwise). A bare-`sharding` reset of the count lands on
/// the YANG default 8.
fn config_ospf_ti_lfa_compute_shards(ospf: &mut Ospf, mut args: Args, op: ConfigOp) -> Option<()> {
    let prev = ospf
        .ti_lfa_compute_mode
        .with_shards(ospf.ti_lfa_compute_shards);
    ospf.ti_lfa_compute_shards = if op.is_set() { args.u16()? } else { 8 };
    ospf_ti_lfa_recompute_if_changed(ospf, prev);
    Some(())
}

/// `/router/ospf/fast-reroute/backup-as-primary`. Inverts the
/// primary/backup metric ordering at install time. Re-run SPF so the
/// RIB rebuilds with the swapped offset; like the ti-lfa toggle this
/// is install-side only and needs no LSA re-origination.
fn config_ospf_fast_reroute_backup_as_primary(
    ospf: &mut Ospf,
    _args: Args,
    op: ConfigOp,
) -> Option<()> {
    let prev = ospf.fast_reroute_backup_as_primary;
    ospf.fast_reroute_backup_as_primary = op.is_set();
    if ospf.fast_reroute_backup_as_primary == prev {
        return Some(());
    }
    let area_ids: Vec<Ipv4Addr> = ospf.areas.iter().map(|(id, _)| *id).collect();
    for id in area_ids {
        let _ = ospf.tx.send(Message::SpfCalc(id));
    }
    Some(())
}

fn config_ospf_sr_mpls(ospf: &mut Ospf, _args: Args, op: ConfigOp) -> Option<()> {
    use super::srmpls::{SRLB_RANGE, SRLB_START, SegmentRoutingMode};
    use crate::spf::label_pool::LabelPool;
    ospf.segment_routing = if op.is_set() {
        SegmentRoutingMode::Mpls
    } else {
        SegmentRoutingMode::None
    };

    // Manage the per-instance Adjacency-SID label pool alongside the
    // mode toggle, mirroring IS-IS (`isis/config.rs::config_sr_mpls_enable`).
    // The pool is bounded by the SRLB (15000..16000 by default) so any
    // re-enable that happens before existing adjacencies regress will
    // simply hand out fresh labels without colliding with stale ones.
    if op.is_set() {
        if ospf.local_pool.is_none() {
            ospf.local_pool = Some(LabelPool::new(
                SRLB_START as usize,
                Some((SRLB_START + SRLB_RANGE - 1) as usize),
            ));
        }
        // Sweep existing Full neighbors and allocate labels for any
        // that don't have one. Necessary when SR-MPLS is enabled after
        // adjacencies have already reached Full -- the NFSM-driven
        // allocation only fires on the Full transition itself, so those
        // pre-existing adjacencies would otherwise be missing from
        // `lan_adj_sids` and excluded from LAN Adj-SID origination.
        let pending: Vec<(u32, std::net::Ipv4Addr)> = ospf
            .links
            .iter()
            .flat_map(|(ifindex, link)| {
                link.nbrs.values().filter_map(move |nbr| {
                    if nbr.state == super::nfsm::NfsmState::Full {
                        Some((*ifindex, nbr.ident.prefix.addr()))
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

    ospf.router_info_lsa_originate();

    // Originate/flush Extended Prefix LSAs for all links with prefix-sid.
    let ifindexes: Vec<u32> = ospf
        .links
        .iter()
        .filter(|(_, link)| link.config.prefix_sid.is_some())
        .map(|(ifindex, _)| *ifindex)
        .collect();
    for ifindex in ifindexes {
        ospf.ext_prefix_lsa_originate(ifindex);
    }

    // Same for Extended Link LSAs (Adj-SID) — sweep every link
    // unconditionally; the originator gates on mode + warrant itself
    // (and flushes otherwise). Filtering on a configured
    // `adjacency_sid` here broke both toggle directions once
    // Adj-SIDs went dynamic: enable-after-Full never originated the
    // P2P LSAs, and disable never flushed them (leaving stale
    // self-ILM pops behind).
    let ifindexes: Vec<u32> = ospf.links.keys().copied().collect();
    for ifindex in ifindexes {
        ospf.ext_link_lsa_originate(ifindex);
    }

    // Rebuild every area's RIB + ILM under the new mode — same
    // pattern as the v3 toggle. `add_prefix_sids` gates on the mode,
    // so a disable drops every label imposition and empties the LFIB
    // instead of waiting for an unrelated SPF.
    let area_ids: Vec<std::net::Ipv4Addr> = ospf.areas.iter().map(|(id, _)| *id).collect();
    for area_id in area_ids {
        let _ = ospf.tx.send(Message::SpfCalc(area_id));
    }

    Some(())
}

/// `router ospf / graceful-restart / helper-enabled`. Toggles
/// whether `gr_maybe_enter_helper` accepts inbound Grace LSAs.
/// On disable, existing helpers are left intact — they'll exit on
/// grace-period expiry or topology change as normal.
fn config_ospf_gr_helper_enabled(ospf: &mut Ospf, mut args: Args, op: ConfigOp) -> Option<()> {
    let value = if op.is_set() { args.boolean()? } else { true };
    ospf.gr_config.helper_enabled = value;
    Some(())
}

/// `router ospf / graceful-restart / max-grace-period`. RFC 3623
/// §3.1 leaves the bound to the helper's policy; we enforce it at
/// helper-entry validation.
fn config_ospf_gr_max_grace_period(ospf: &mut Ospf, mut args: Args, op: ConfigOp) -> Option<()> {
    let value = if op.is_set() { args.u32()? } else { 1800 };
    ospf.gr_config.max_grace_period = value;
    Some(())
}

/// `router ospf / graceful-restart / helper-strict-lsa-checking`.
/// When false, only the restarter's own LSAs trigger
/// topology-change exit (RFC 3623 §3.2 relaxation).
fn config_ospf_gr_helper_strict_lsa_checking(
    ospf: &mut Ospf,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let value = if op.is_set() { args.boolean()? } else { true };
    ospf.gr_config.helper_strict_lsa_checking = value;
    Some(())
}

/// `router ospf / graceful-restart / drain-time-ms`. Drain
/// window between writing the restart checkpoint and exiting
/// the process during `clear ip ospf graceful-restart commit`.
/// YANG range 50-2000ms, default 200ms.
fn config_ospf_gr_drain_time_ms(ospf: &mut Ospf, mut args: Args, op: ConfigOp) -> Option<()> {
    let value = if op.is_set() { args.u32()? } else { 200 };
    ospf.gr_config.drain_time_ms = value.clamp(50, 2000);
    Some(())
}

// `/router/ospf/spf-interval/{initial,secondary,maximum}-wait`.
// Adaptive SPF-throttle bounds (milliseconds). Delete restores the
// per-field default from `SpfIntervalConfig::default()` (50/200/5000).
// Live per-area timers pick the new bounds up on the next schedule; a
// mid-flight timer keeps its already-computed wait.
fn config_ospf_spf_initial_wait(ospf: &mut Ospf, mut args: Args, op: ConfigOp) -> Option<()> {
    let default = super::inst::SpfIntervalConfig::default().initial_wait_ms;
    ospf.spf_interval.initial_wait_ms = if op.is_set() { args.u32()? } else { default };
    Some(())
}

fn config_ospf_spf_secondary_wait(ospf: &mut Ospf, mut args: Args, op: ConfigOp) -> Option<()> {
    let default = super::inst::SpfIntervalConfig::default().secondary_wait_ms;
    ospf.spf_interval.secondary_wait_ms = if op.is_set() { args.u32()? } else { default };
    Some(())
}

fn config_ospf_spf_maximum_wait(ospf: &mut Ospf, mut args: Args, op: ConfigOp) -> Option<()> {
    let default = super::inst::SpfIntervalConfig::default().maximum_wait_ms;
    ospf.spf_interval.maximum_wait_ms = if op.is_set() { args.u32()? } else { default };
    Some(())
}

// `/router/ospf/min-ls-interval` — RFC 2328 §12.4 MinLSInterval (ms).
// Delete restores the RFC/FRR default. Applies from the next
// re-origination; a deferral already in flight keeps its timer.
fn config_ospf_min_ls_interval(ospf: &mut Ospf, mut args: Args, op: ConfigOp) -> Option<()> {
    let value = if op.is_set() {
        args.u32()?
    } else {
        super::inst::OSPF_MIN_LS_INTERVAL_MS
    };
    ospf.min_ls_interval_ms = value;
    Some(())
}

// `/router/ospf/min-ls-arrival` — RFC 2328 §13 MinLSArrival (ms).
// Receive-side rate limit; applies to LSAs received after the change.
// Delete restores the RFC/FRR default.
fn config_ospf_min_ls_arrival(ospf: &mut Ospf, mut args: Args, op: ConfigOp) -> Option<()> {
    let value = if op.is_set() {
        args.u32()?
    } else {
        super::inst::OSPF_MIN_LS_ARRIVAL_MS
    };
    ospf.min_ls_arrival_ms = value;
    Some(())
}

// `/router/ospf/redistribute/connected` and its metric knobs share
// the generic instance-level redistribute bodies above.
ospf_redist_handlers!(
    config_ospf_redist_connected,
    config_ospf_redist_connected_metric,
    config_ospf_redist_connected_metric_type,
    crate::rib::RibType::Connected
);
