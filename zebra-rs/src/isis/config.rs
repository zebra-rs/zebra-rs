// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2025-2026 Kunihiro Ishiguro

use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::str::FromStr;

use isis_packet::{IsLevel, Nsap};
use strum_macros::{Display, EnumString};

use crate::config::{Args, ConfigOp};

use super::Isis;
use super::inst::{Callback, Message};
use super::link::Afis;
use super::tracing::{PacketConfig, PacketDirection};
use super::{Level, link};

use isis_packet::IsisLspId;

/// IS-IS Multi-Topology identifier (RFC 5120). The wire encoding is a
/// 12-bit MT ID; we model only the topologies we actually compute SPF
/// for. Multicast variants (MT 3, MT 4) parse on the wire but don't
/// surface here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, EnumString, Display)]
pub enum MtId {
    /// MT 0 — IPv4 unicast (the legacy "standard" topology). When no
    /// MT TLV is present in an LSP, RFC 5120 §3.4 says everything
    /// implicitly belongs here.
    #[strum(serialize = "standard")]
    Standard,
    /// MT 2 — IPv6 unicast.
    #[strum(serialize = "ipv6-unicast")]
    Ipv6Unicast,
}

impl MtId {
    /// 12-bit wire identifier per RFC 5120 §7.2 / §7.3.
    pub fn wire_id(self) -> u16 {
        match self {
            Self::Standard => 0,
            Self::Ipv6Unicast => 2,
        }
    }
}

impl Isis {
    const TRACING: &str = "/routing/isis/tracing";

    pub fn tracing_add(&mut self, path: &str, cb: Callback) {
        self.callbacks
            .insert(format!("{}{}", Self::TRACING, path), cb);
    }

    pub fn callback_build(&mut self) {
        self.callback_add("/routing/isis/net", config_net);
        self.callback_add("/routing/isis/is-type", config_is_type);
        self.callback_add("/routing/isis/hostname", config_hostname);
        self.callback_add("/routing/isis/timers/hold-time", config_hold_time);
        self.callback_add("/routing/isis/te-router-id", config_te_router_id);
        self.callback_add("/routing/isis/segment-routing/mpls", config_sr_mpls_enable);
        self.callback_add(
            "/routing/isis/segment-routing/mpls/block",
            config_sr_mpls_block,
        );
        self.callback_add("/routing/isis/segment-routing/srv6", config_sr_srv6_enable);
        self.callback_add(
            "/routing/isis/segment-routing/srv6/locator",
            config_sr_srv6_locator,
        );
        self.callback_add("/routing/isis/multi-topology", config_mt_enable);
        self.callback_add("/routing/isis/multi-topology/topology", config_mt_topology);
        self.callback_add(
            "/routing/isis/interface/multi-topology/metric",
            link::config_mt_metric,
        );
        self.callback_add("/routing/isis/interface/priority", link::config_priority);
        self.tracing_add("/event", config_tracing_event);
        self.tracing_add("/fsm", config_tracing_fsm);
        self.tracing_add("/packet", config_tracing_packet);
        self.tracing_add("/packet/direction", config_tracing_packet);
        self.tracing_add("/database", config_tracing_database);
        self.callback_add(
            "/routing/isis/interface/circuit-type",
            link::config_circuit_type,
        );
        self.callback_add("/routing/isis/interface/link-type", link::config_link_type);
        self.callback_add(
            "/routing/isis/interface/hello/padding",
            link::config_hello_padding,
        );
        self.callback_add(
            "/routing/isis/interface/ipv4/enable",
            link::config_ipv4_enable,
        );
        self.callback_add(
            "/routing/isis/interface/ipv4/prefix-sid/index",
            link::config_ipv4_prefix_sid_index,
        );
        self.callback_add("/routing/isis/interface/metric", link::config_metric);
        self.callback_add(
            "/routing/isis/interface/ipv6/enable",
            link::config_ipv6_enable,
        );
        self.callback_add("/routing/isis/distribute/rib", config_distribute_rib);
    }
}

pub struct IsisDistribute {
    pub rib: bool,
}

impl Default for IsisDistribute {
    fn default() -> Self {
        Self { rib: true }
    }
}

#[derive(Default)]
pub struct IsisConfig {
    pub net: Nsap,
    pub hostname: Option<String>,
    pub is_type: Option<IsLevel>,
    pub refresh_time: Option<u16>,
    pub hold_time: Option<u16>,
    pub te_router_id: Option<Ipv4Addr>,
    pub rib_router_id: Option<Ipv4Addr>,
    pub enable: Afis<usize>,
    pub distribute: IsisDistribute,

    /// Set when /routing/isis/segment-routing/mpls is committed (the
    /// presence-marked YANG container), even if no `block` is selected.
    /// Drives whether IS-IS originates SR-MPLS Capability sub-TLVs.
    pub sr_mpls_enabled: bool,

    /// Optional name of a block defined under the global
    /// /segment-routing/block list. The actual SRGB / SRLB values are
    /// looked up by name from RIB::blocks; left as a string here so the
    /// IS-IS config can be staged before the global block is committed.
    pub sr_mpls_block: Option<String>,

    /// Set when /routing/isis/segment-routing/srv6 is committed.
    pub sr_srv6_enabled: bool,

    /// Optional name of a locator defined under the global
    /// /segment-routing/locator list. Same staging-friendly rationale
    /// as sr_mpls_block.
    pub sr_srv6_locator: Option<String>,

    /// Set when /routing/isis/multi-topology is committed (the
    /// presence-marked YANG container). Drives whether IS-IS
    /// originates the MT TLV (229) and per-MT reach TLVs in
    /// follow-up PRs.
    pub mt_enabled: bool,

    /// MT IDs the operator selected under
    /// /routing/isis/multi-topology/topology. Empty when MT is on but
    /// the operator hasn't named any topologies yet — that's a
    /// no-op-friendly intermediate state during config staging.
    pub mt_topologies: BTreeSet<MtId>,
}

impl IsisConfig {
    const DEFAULT_REFRESH_TIME: u16 = 15 * 60;
    const DEFAULT_HOLD_TIME: u16 = 1200;

    pub fn is_type(&self) -> IsLevel {
        self.is_type.unwrap_or(IsLevel::L1L2)
    }

    /// Resolve the hostname to advertise in TLV 137. Configured hostname
    /// wins; otherwise we fall back to the OS hostname. If neither is
    /// available we return None and the caller should skip emitting the
    /// hostname TLV (RFC 5301 leaves the TLV optional).
    pub fn hostname(&self) -> Option<String> {
        if let Some(name) = &self.hostname {
            return Some(name.clone());
        }
        hostname::get()
            .ok()
            .and_then(|s| s.into_string().ok())
            .filter(|s| !s.is_empty())
    }

    pub fn refresh_time(&self) -> u16 {
        self.refresh_time.unwrap_or(Self::DEFAULT_REFRESH_TIME)
    }

    pub fn hold_time(&self) -> u16 {
        self.hold_time.unwrap_or(Self::DEFAULT_HOLD_TIME)
    }

    /// True when either SR dataplane is enabled. Used to gate emission
    /// of the TE Router ID TLV (it's only meaningful in an SR domain).
    pub fn sr_enabled(&self) -> bool {
        self.sr_mpls_enabled || self.sr_srv6_enabled
    }
}

fn config_net(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let nsap = args.string()?.parse::<Nsap>().unwrap();

    if op.is_set() {
        isis.lsp_map.get_mut(&Level::L1).get(&nsap.sys_id());
        isis.lsp_map.get_mut(&Level::L2).get(&nsap.sys_id());
        isis.config.net = nsap;
    } else {
        isis.config.net = Nsap::default();
    }

    Some(())
}

fn config_is_type(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let prev = isis.config.is_type();
    if op.is_set() {
        let is_type = args.string()?.parse::<IsLevel>().ok()?;
        isis.config.is_type = Some(is_type);
    } else {
        isis.config.is_type = None;
    }
    let curr = isis.config.is_type();
    if prev != curr {
        for (_, link) in isis.links.iter_mut() {
            let is_level = link::config_level_common(curr, link.config.circuit_type());
            link.state.set_level(is_level);
        }
    }
    Some(())
}

fn config_hostname(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let hostname = args.string()?;

    let prev = isis.config.hostname();
    if op == ConfigOp::Set {
        isis.config.hostname = Some(hostname);
    } else {
        isis.config.hostname = None;
    }
    let curr = isis.config.hostname();

    if prev == curr {
        return Some(());
    }

    // Re-originate self LSP at any level that has one so the new
    // hostname (or its absence) propagates without waiting for the
    // refresh timer. Levels with no self LSP yet are still pre-NET —
    // origination will pick the new value naturally on first emission.
    let key = IsisLspId::new(isis.config.net.sys_id(), 0, 0);
    for level in [Level::L1, Level::L2] {
        if isis.lsdb.get(&level).get(&key).is_some() {
            let _ = isis.tx.send(Message::LspOriginate(level));
        }
    }

    Some(())
}

fn config_hold_time(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let hold_time = args.u16()?;

    if op == ConfigOp::Set {
        isis.config.hold_time = Some(hold_time);
    } else {
        isis.config.hold_time = None;
    }
    Some(())
}

// Set/cleared by the presence of the YANG container itself, not by any
// child leaf. libyang invokes the callback at the container path with no
// extra args when the container is committed (set) or removed (delete).
fn config_sr_mpls_enable(isis: &mut Isis, _args: Args, op: ConfigOp) -> Option<()> {
    if op.is_set() {
        isis.config.sr_mpls_enabled = true;
    } else {
        isis.config.sr_mpls_enabled = false;
        isis.config.sr_mpls_block = None;
    }
    isis.reconcile_block_watch();
    Some(())
}

fn config_sr_mpls_block(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    if op.is_set() {
        let name = args.string()?;
        isis.config.sr_mpls_block = Some(name);
    } else {
        isis.config.sr_mpls_block = None;
    }
    isis.reconcile_block_watch();
    Some(())
}

fn config_sr_srv6_enable(isis: &mut Isis, _args: Args, op: ConfigOp) -> Option<()> {
    if op.is_set() {
        isis.config.sr_srv6_enabled = true;
    } else {
        isis.config.sr_srv6_enabled = false;
        isis.config.sr_srv6_locator = None;
    }
    isis.reconcile_locator_watch();
    Some(())
}

fn config_sr_srv6_locator(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    if op.is_set() {
        let name = args.string()?;
        isis.config.sr_srv6_locator = Some(name);
    } else {
        isis.config.sr_srv6_locator = None;
    }
    isis.reconcile_locator_watch();
    Some(())
}

// Set/cleared by the presence of the YANG container itself, like
// segment-routing/srv6 above. Removing the container also drops every
// configured topology; PR 2 will trigger LSP re-origination from here.
fn config_mt_enable(isis: &mut Isis, _args: Args, op: ConfigOp) -> Option<()> {
    if op.is_set() {
        isis.config.mt_enabled = true;
    } else {
        isis.config.mt_enabled = false;
        isis.config.mt_topologies.clear();
    }
    Some(())
}

// Per-list-entry callback: the value is the MT id keyword. Add on set,
// remove on delete. Unknown ids fall through to None — libyang's enum
// validation should keep them out, but we don't trust the wire.
fn config_mt_topology(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let id_str = args.string()?;
    let id = MtId::from_str(&id_str).ok()?;
    if op.is_set() {
        isis.config.mt_topologies.insert(id);
    } else {
        isis.config.mt_topologies.remove(&id);
    }
    Some(())
}

fn config_te_router_id(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let te_router_id = args.v4addr()?;

    if op == ConfigOp::Set {
        isis.config.te_router_id = Some(te_router_id);
    } else {
        isis.config.te_router_id = None;
    }
    Some(())
}

fn config_tracing_event(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let ev = args.string()?;

    match ev.as_str() {
        "dis" => {
            isis.tracing.event.dis.enabled = op.is_set();
        }
        "lsp-originate" => {
            isis.tracing.event.lsp_originate.enabled = op.is_set();
        }
        _ => {
            if op.is_set() {
                // println!("Trace on {} (not implemented)", ev);
            } else {
                //println!("Trace off {} (not implemented)", ev);
            }
        }
    }

    Some(())
}

fn config_tracing_fsm(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let typ = args.string()?;

    match typ.as_str() {
        "nfsm" => {
            isis.tracing.fsm.nfsm.enabled = op.is_set();
        }
        "ifsm" => {
            isis.tracing.fsm.ifsm.enabled = op.is_set();
        }
        _ => {
            //
        }
    }

    Some(())
}

fn parse_direction(args: &mut Args) -> PacketDirection {
    match args.string().as_deref() {
        Some("send") => PacketDirection::Send,
        Some("recv") | Some("receive") => PacketDirection::Recv,
        Some("both") | None => PacketDirection::Both,
        Some(_) => PacketDirection::Both,
    }
}

fn set_packet_config(config: &mut PacketConfig, op: ConfigOp, direction: PacketDirection) {
    if op.is_set() {
        config.enabled = true;
        config.direction = direction;
    } else {
        config.enabled = false;
        config.direction = PacketDirection::Both;
    }
}

fn config_tracing_packet(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let typ = args.string()?;
    let direction = parse_direction(&mut args);

    match typ.as_str() {
        "all" => {
            set_packet_config(&mut isis.tracing.packet.hello, op, direction);
            set_packet_config(&mut isis.tracing.packet.lsp, op, direction);
            set_packet_config(&mut isis.tracing.packet.csnp, op, direction);
            set_packet_config(&mut isis.tracing.packet.psnp, op, direction);
        }
        "hello" => {
            set_packet_config(&mut isis.tracing.packet.hello, op, direction);
        }
        "lsp" => {
            set_packet_config(&mut isis.tracing.packet.lsp, op, direction);
        }
        "csnp" => {
            set_packet_config(&mut isis.tracing.packet.csnp, op, direction);
        }
        "psnp" => {
            set_packet_config(&mut isis.tracing.packet.psnp, op, direction);
        }
        _ => {
            println!("Unknown packet type: {}", typ);
        }
    }

    Some(())
}

fn config_tracing_database(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let ev = args.string()?;

    match ev.as_str() {
        "lsdb" => {
            isis.tracing.database.lsdb.enabled = op.is_set();
        }
        _ => {
            if op.is_set() {
                println!("Trace on {} (not implemented)", ev);
            } else {
                println!("Trace off {} (not implemented)", ev);
            }
        }
    }

    Some(())
}

fn config_distribute_rib(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let enable = args.boolean()?;

    if op.is_set() {
        isis.config.distribute.rib = enable;
    } else {
        isis.config.distribute.rib = true;
    }

    Some(())
}
