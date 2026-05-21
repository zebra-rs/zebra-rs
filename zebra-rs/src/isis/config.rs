use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::str::FromStr;

use ipnet::{Ipv4Net, Ipv6Net};
use isis_packet::{IsLevel, Nsap};
use strum_macros::{Display, EnumString};

use crate::config::{Args, ConfigOp};

use super::Isis;
use super::ifsm::has_level;
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
    const TRACING: &str = "/router/isis/tracing";

    pub fn tracing_add(&mut self, path: &str, cb: Callback) {
        self.callbacks
            .insert(format!("{}{}", Self::TRACING, path), cb);
    }

    pub fn callback_build(&mut self) {
        self.callback_add("/router/isis/net", config_net);
        self.callback_add("/router/isis/is-type", config_is_type);
        self.callback_add("/router/isis/hostname", config_hostname);
        self.callback_add("/router/isis/timers/hold-time", config_hold_time);
        self.callback_add(
            "/router/isis/timers/lsp-refresh-interval",
            config_lsp_refresh_interval,
        );
        self.callback_add(
            "/router/isis/timers/min-lsp-arrival-time",
            config_min_lsp_arrival_time,
        );
        self.callback_add(
            "/router/isis/spf-interval/initial-wait",
            config_spf_initial_wait,
        );
        self.callback_add(
            "/router/isis/spf-interval/secondary-wait",
            config_spf_secondary_wait,
        );
        self.callback_add(
            "/router/isis/spf-interval/maximum-wait",
            config_spf_maximum_wait,
        );
        self.callback_add(
            "/router/isis/lsp-gen-interval/initial-wait",
            config_lsp_gen_initial_wait,
        );
        self.callback_add(
            "/router/isis/lsp-gen-interval/secondary-wait",
            config_lsp_gen_secondary_wait,
        );
        self.callback_add(
            "/router/isis/lsp-gen-interval/maximum-wait",
            config_lsp_gen_maximum_wait,
        );
        self.callback_add("/router/isis/lsp-mtu-size", config_lsp_mtu_size);
        self.callback_add("/router/isis/te-router-id", config_te_router_id);
        self.callback_add("/router/isis/segment-routing/mpls", config_sr_mpls_enable);
        self.callback_add(
            "/router/isis/segment-routing/mpls/block",
            config_sr_mpls_block,
        );
        self.callback_add("/router/isis/segment-routing/srv6", config_sr_srv6_enable);
        self.callback_add(
            "/router/isis/segment-routing/srv6/locator",
            config_sr_srv6_locator,
        );
        self.callback_add("/router/isis/fast-reroute/ti-lfa", config_ti_lfa);
        self.callback_add("/router/isis/multi-topology", config_mt);
        self.callback_add("/router/isis/afi-safi/network", config_network);

        // Per-AFI redistribution. One presence-container callback per
        // source plus one callback per modifier leaf — each is a thin
        // wrapper around `redist_set_presence` / `redist_with` carrying
        // the source enum as a const argument.
        self.callback_add(
            "/router/isis/afi-safi/redistribute/connected",
            config_redistribute_connected,
        );
        self.callback_add(
            "/router/isis/afi-safi/redistribute/connected/policy",
            config_redistribute_connected_policy,
        );
        self.callback_add(
            "/router/isis/afi-safi/redistribute/connected/metric",
            config_redistribute_connected_metric,
        );
        self.callback_add(
            "/router/isis/afi-safi/redistribute/connected/level",
            config_redistribute_connected_level,
        );
        self.callback_add(
            "/router/isis/afi-safi/redistribute/connected/metric-type",
            config_redistribute_connected_metric_type,
        );
        self.callback_add(
            "/router/isis/afi-safi/redistribute/static",
            config_redistribute_static,
        );
        self.callback_add(
            "/router/isis/afi-safi/redistribute/static/policy",
            config_redistribute_static_policy,
        );
        self.callback_add(
            "/router/isis/afi-safi/redistribute/static/metric",
            config_redistribute_static_metric,
        );
        self.callback_add(
            "/router/isis/afi-safi/redistribute/static/level",
            config_redistribute_static_level,
        );
        self.callback_add(
            "/router/isis/afi-safi/redistribute/static/metric-type",
            config_redistribute_static_metric_type,
        );
        self.callback_add(
            "/router/isis/afi-safi/redistribute/bgp",
            config_redistribute_bgp,
        );
        self.callback_add(
            "/router/isis/afi-safi/redistribute/bgp/policy",
            config_redistribute_bgp_policy,
        );
        self.callback_add(
            "/router/isis/afi-safi/redistribute/bgp/metric",
            config_redistribute_bgp_metric,
        );
        self.callback_add(
            "/router/isis/afi-safi/redistribute/bgp/level",
            config_redistribute_bgp_level,
        );
        self.callback_add(
            "/router/isis/afi-safi/redistribute/bgp/metric-type",
            config_redistribute_bgp_metric_type,
        );
        self.callback_add(
            "/router/isis/afi-safi/redistribute/ospf",
            config_redistribute_ospf,
        );
        self.callback_add(
            "/router/isis/afi-safi/redistribute/ospf/policy",
            config_redistribute_ospf_policy,
        );
        self.callback_add(
            "/router/isis/afi-safi/redistribute/ospf/metric",
            config_redistribute_ospf_metric,
        );
        self.callback_add(
            "/router/isis/afi-safi/redistribute/ospf/level",
            config_redistribute_ospf_level,
        );
        self.callback_add(
            "/router/isis/afi-safi/redistribute/ospf/metric-type",
            config_redistribute_ospf_metric_type,
        );
        self.callback_add(
            "/router/isis/afi-safi/redistribute/ospf/match/type",
            config_redistribute_ospf_match_type,
        );
        self.callback_add(
            "/router/isis/interface/multi-topology/metric",
            link::config_mt_metric,
        );
        self.callback_add("/router/isis/interface/priority", link::config_priority);
        self.tracing_add("/event", config_tracing_event);
        self.tracing_add("/fsm", config_tracing_fsm);
        self.tracing_add("/packet", config_tracing_packet);
        self.tracing_add("/packet/direction", config_tracing_packet);
        self.tracing_add("/database", config_tracing_database);
        self.callback_add(
            "/router/isis/interface/circuit-type",
            link::config_circuit_type,
        );
        self.callback_add(
            "/router/isis/interface/network-type",
            link::config_network_type,
        );
        self.callback_add(
            "/router/isis/interface/hello/interval",
            link::config_hello_interval,
        );
        self.callback_add(
            "/router/isis/interface/hello/multiplier",
            link::config_hello_multiplier,
        );
        self.callback_add(
            "/router/isis/interface/csnp-interval",
            link::config_csnp_interval,
        );
        self.callback_add(
            "/router/isis/interface/psnp-interval",
            link::config_psnp_interval,
        );
        self.callback_add(
            "/router/isis/interface/hello/padding",
            link::config_hello_padding,
        );
        self.callback_add(
            "/router/isis/interface/ipv4/enable",
            link::config_ipv4_enable,
        );
        // Per-interface BFD attachment (PR 6 — storage only; the
        // adjacency-FSM subscribe and BfdEvent::Down teardown paths
        // land in PR 7).
        self.callback_add("/router/isis/interface/bfd/enable", link::config_bfd_enable);
        self.callback_add(
            "/router/isis/interface/bfd/profile",
            link::config_bfd_profile,
        );
        self.callback_add(
            "/router/isis/interface/ipv4/prefix-sid/index",
            link::config_ipv4_prefix_sid_index,
        );
        self.callback_add("/router/isis/interface/metric", link::config_metric);
        self.callback_add("/router/isis/interface/srlg", link::config_srlg);
        self.callback_add("/router/isis/interface/affinity", link::config_affinity);
        self.callback_add(
            "/router/isis/interface/ipv4/flex-algo-prefix-sid",
            link::config_ipv4_flex_algo_prefix_sid,
        );
        self.callback_add(
            "/router/isis/interface/ipv4/flex-algo-prefix-sid/index",
            link::config_ipv4_flex_algo_prefix_sid_index,
        );
        self.callback_add(
            "/router/isis/segment-routing/srv6/flex-algo-locator/locator",
            config_sr_srv6_flex_algo_locator,
        );
        self.callback_add(
            "/router/isis/interface/ipv6/enable",
            link::config_ipv6_enable,
        );
        self.callback_add("/router/isis/distribute/rib", config_distribute_rib);

        super::flex_algo::callback_register(self);
        super::affinity_map::callback_register(self);
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
    pub min_lsp_arrival_time: Option<u32>,
    pub spf_initial_wait: Option<u32>,
    pub spf_secondary_wait: Option<u32>,
    pub spf_maximum_wait: Option<u32>,
    pub lsp_gen_initial_wait: Option<u32>,
    pub lsp_gen_secondary_wait: Option<u32>,
    pub lsp_gen_maximum_wait: Option<u32>,

    /// Originating LSP Buffer Size (ISO 10589 §7.2.5.1
    /// `originatingLSPBufferSize`, advertised in TLV 14 per RFC 1195).
    /// Caps the byte length of every self-originated LSP PDU and
    /// drives the send-side packer's fragment boundary. Default
    /// 1492 — the universally-accepted IS-IS PDU size.
    pub lsp_mtu_size: Option<u16>,
    pub te_router_id: Option<Ipv4Addr>,
    pub rib_router_id: Option<Ipv4Addr>,
    pub enable: Afis<usize>,
    pub distribute: IsisDistribute,

    /// Set when /router/isis/segment-routing/mpls is committed (the
    /// presence-marked YANG container), even if no `block` is selected.
    /// Drives whether IS-IS originates SR-MPLS Capability sub-TLVs.
    pub sr_mpls_enabled: bool,

    /// Optional name of a block defined under the global
    /// /segment-routing/block list. The actual SRGB / SRLB values are
    /// looked up by name from RIB::blocks; left as a string here so the
    /// IS-IS config can be staged before the global block is committed.
    pub sr_mpls_block: Option<String>,

    /// Set when /router/isis/segment-routing/srv6 is committed.
    pub sr_srv6_enabled: bool,

    /// Optional name of a locator defined under the global
    /// /segment-routing/locator list. Same staging-friendly rationale
    /// as sr_mpls_block.
    pub sr_srv6_locator: Option<String>,

    /// Per-Flex-Algorithm SRv6 locator bindings, from the YANG list at
    /// /router/isis/segment-routing/srv6/flex-algo-locator[algo=N].
    /// Each entry binds an algorithm (128..=255) to a /segment-routing/
    /// locator name; the LSP-emit follow-up will originate a SRv6
    /// Locator TLV 27 with Algorithm=N (RFC 9352 §7.1) for each entry.
    /// Names, not leafrefs — staged the same way as `sr_srv6_locator`.
    pub sr_srv6_flex_algo_locators: BTreeMap<u8, String>,

    /// Set when /router/isis/fast-reroute/ti-lfa is committed (the
    /// presence-marked YANG container). Gates the per-destination
    /// `tilfa_repair_path` calls in `perform_spf_calculation` and the
    /// Adj-SID B-flag (RFC 8667 §2.2.1) emitted in TLV 22 sub-TLVs.
    pub ti_lfa_enabled: bool,

    /// True when `/router/isis/multi-topology` carries an MT id.
    /// Drives whether IS-IS originates TLV 229 and the per-MT reach
    /// TLVs.
    pub mt_enabled: bool,

    /// The MT ids the operator turned on. Today the YANG only allows
    /// `ipv6-unicast`, so this set is either `{}` (off) or
    /// `{Ipv6Unicast}` (on); the BTreeSet shape is kept so adding
    /// future MTs (multicast variants, geo-redundancy, ...) doesn't
    /// reshape the runtime checks that read it.
    pub mt_topologies: BTreeSet<MtId>,

    /// Operator-configured IPv4 prefixes to advertise unconditionally
    /// in every self-originated LSP, BGP-style. Populated from
    /// `/router/isis/afi-safi[name=ipv4]/network`. Emitted as TLV 135
    /// entries with metric 0 (receivers add their own IS-reach metric).
    pub networks_v4: BTreeSet<Ipv4Net>,

    /// IPv6 sibling of `networks_v4`. Emitted as TLV 236 in legacy
    /// mode, TLV 237 when MT 2 is enabled — see `lsp_generate`.
    pub networks_v6: BTreeSet<Ipv6Net>,

    /// Per-AFI redistribution configuration. Populated by the
    /// `/router/isis/afi-safi/redistribute/<source>...` callbacks; one
    /// entry per (AFI, source) pair, holding the modifiers (policy,
    /// metric, level, metric-type, optional OSPF source-match).
    /// Storage-only today — the LSP emitter and RIB-source plumbing
    /// will read from it in a follow-up.
    pub redistribute: BTreeMap<(IsisRedistAfi, IsisRedistSource), IsisRedistribute>,
}

/// AFI key for the redistribute map. Mirrors the
/// `enum { ipv4; ipv6; }` in YANG. Kept local to `config.rs` so the
/// existing `link::Afi` (which lacks the trait derives we need for
/// `BTreeMap` keys) stays untouched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IsisRedistAfi {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IsisRedistSource {
    Connected,
    Static,
    Bgp,
    Ospf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsisRedistLevel {
    L1,
    L2,
    L1L2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsisRedistMetricType {
    Internal,
    External,
    RibAsInternal,
    RibAsExternal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IsisRedistOspfMatch {
    Internal,
    External,
    NssaExternal,
}

#[derive(Debug, Default, Clone)]
pub struct IsisRedistribute {
    pub policy: Option<String>,
    pub metric: Option<u32>,
    pub level: Option<IsisRedistLevel>,
    pub metric_type: Option<IsisRedistMetricType>,
    /// Populated only when source == Ospf. Empty set means "no filter".
    pub ospf_match: BTreeSet<IsisRedistOspfMatch>,
}

impl IsisConfig {
    const DEFAULT_REFRESH_TIME: u16 = 15 * 60;
    const DEFAULT_HOLD_TIME: u16 = 1200;
    // RFC 4444 §3.1 storm-protection floor for accepting new LSP versions.
    // 100 ms matches IOS-XR's default.
    const DEFAULT_MIN_LSP_ARRIVAL_TIME_MS: u32 = 100;
    // IOS-XR-style SPF exponential-backoff defaults (in milliseconds).
    const DEFAULT_SPF_INITIAL_WAIT_MS: u32 = 50;
    const DEFAULT_SPF_SECONDARY_WAIT_MS: u32 = 200;
    const DEFAULT_SPF_MAXIMUM_WAIT_MS: u32 = 5000;
    // IOS-XR-style LSP-generation exponential-backoff defaults
    // (milliseconds). IOS-XR's defaults are 50 ms / 5000 ms / 5000 ms —
    // a long maximum keeps self-LSP origination spaced out under churn.
    const DEFAULT_LSP_GEN_INITIAL_WAIT_MS: u32 = 50;
    const DEFAULT_LSP_GEN_SECONDARY_WAIT_MS: u32 = 5000;
    const DEFAULT_LSP_GEN_MAXIMUM_WAIT_MS: u32 = 5000;
    /// ISO 10589 §7.2.5.1: the originatingLSPBufferSize every IS-IS
    /// implementation is required to accept. Larger values are valid
    /// on links where every peer agrees, but 1492 is the safe default.
    pub const DEFAULT_LSP_MTU_SIZE: u16 = 1492;

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

    pub fn min_lsp_arrival_time(&self) -> u32 {
        self.min_lsp_arrival_time
            .unwrap_or(Self::DEFAULT_MIN_LSP_ARRIVAL_TIME_MS)
    }

    pub fn spf_initial_wait(&self) -> u32 {
        self.spf_initial_wait
            .unwrap_or(Self::DEFAULT_SPF_INITIAL_WAIT_MS)
    }

    pub fn spf_secondary_wait(&self) -> u32 {
        self.spf_secondary_wait
            .unwrap_or(Self::DEFAULT_SPF_SECONDARY_WAIT_MS)
    }

    pub fn spf_maximum_wait(&self) -> u32 {
        self.spf_maximum_wait
            .unwrap_or(Self::DEFAULT_SPF_MAXIMUM_WAIT_MS)
    }

    pub fn lsp_gen_initial_wait(&self) -> u32 {
        self.lsp_gen_initial_wait
            .unwrap_or(Self::DEFAULT_LSP_GEN_INITIAL_WAIT_MS)
    }

    pub fn lsp_gen_secondary_wait(&self) -> u32 {
        self.lsp_gen_secondary_wait
            .unwrap_or(Self::DEFAULT_LSP_GEN_SECONDARY_WAIT_MS)
    }

    pub fn lsp_gen_maximum_wait(&self) -> u32 {
        self.lsp_gen_maximum_wait
            .unwrap_or(Self::DEFAULT_LSP_GEN_MAXIMUM_WAIT_MS)
    }

    pub fn lsp_mtu_size(&self) -> u16 {
        self.lsp_mtu_size.unwrap_or(Self::DEFAULT_LSP_MTU_SIZE)
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
        isis.lsp_map.get_mut(&Level::L1).get_sys(&nsap.sys_id());
        isis.lsp_map.get_mut(&Level::L2).get_sys(&nsap.sys_id());
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
            let _ = isis.tx.send(Message::LspOriginate(level, None));
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

fn config_lsp_refresh_interval(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let refresh_time = args.u16()?;

    if op == ConfigOp::Set {
        isis.config.refresh_time = Some(refresh_time);
    } else {
        isis.config.refresh_time = None;
    }
    Some(())
}

fn config_min_lsp_arrival_time(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let ms = args.u32()?;

    if op == ConfigOp::Set {
        isis.config.min_lsp_arrival_time = Some(ms);
    } else {
        isis.config.min_lsp_arrival_time = None;
    }
    Some(())
}

fn config_spf_initial_wait(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let ms = args.u32()?;
    isis.config.spf_initial_wait = if op == ConfigOp::Set { Some(ms) } else { None };
    Some(())
}

fn config_spf_secondary_wait(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let ms = args.u32()?;
    isis.config.spf_secondary_wait = if op == ConfigOp::Set { Some(ms) } else { None };
    Some(())
}

fn config_spf_maximum_wait(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let ms = args.u32()?;
    isis.config.spf_maximum_wait = if op == ConfigOp::Set { Some(ms) } else { None };
    Some(())
}

fn config_lsp_gen_initial_wait(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let ms = args.u32()?;
    isis.config.lsp_gen_initial_wait = if op == ConfigOp::Set { Some(ms) } else { None };
    Some(())
}

fn config_lsp_gen_secondary_wait(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let ms = args.u32()?;
    isis.config.lsp_gen_secondary_wait = if op == ConfigOp::Set { Some(ms) } else { None };
    Some(())
}

fn config_lsp_gen_maximum_wait(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let ms = args.u32()?;
    isis.config.lsp_gen_maximum_wait = if op == ConfigOp::Set { Some(ms) } else { None };
    Some(())
}

fn config_lsp_mtu_size(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let size = args.u16()?;

    if op == ConfigOp::Set {
        isis.config.lsp_mtu_size = Some(size);
    } else {
        isis.config.lsp_mtu_size = None;
    }

    // Re-originate so the new buffer size lands in TLV 14 and (once
    // the packer is wired up) so the new fragment boundary takes
    // effect immediately rather than waiting for the next natural
    // origination trigger.
    for level in [Level::L1, Level::L2] {
        if has_level(isis.config.is_type(), level) {
            let _ = isis.tx.send(Message::LspOriginate(level, None));
        }
    }
    Some(())
}

// Set/cleared by the presence of the YANG container itself, not by any
// child leaf. libyang invokes the callback at the container path with no
// extra args when the container is committed (set) or removed (delete).
fn config_sr_mpls_enable(isis: &mut Isis, _args: Args, op: ConfigOp) -> Option<()> {
    if op.is_set() {
        isis.config.sr_mpls_enabled = true;
        // Allocate the adjacency-SID label pool so subsequent hellos
        // can carve labels for `IsisSubLanAdjSid` sub-TLVs. Idempotent:
        // re-enabling without a prior disable keeps any previously
        // handed-out labels intact.
        if isis.local_pool.is_none() {
            isis.local_pool = Some(super::LabelPool::new(15000, Some(16000)));
        }
    } else {
        isis.config.sr_mpls_enabled = false;
        isis.config.sr_mpls_block = None;
        // Drop the pool. Any labels still cached on neighbor addr4
        // entries become orphaned but stop short of producing fresh
        // MPLS installs — `nbr_hello_interpret` and `lsp_generate`
        // both gate on `local_pool`/`value.label` being present.
        isis.local_pool = None;
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

// `/router/isis/segment-routing/srv6/flex-algo-locator[algo=N]/locator`
// — bind a /segment-routing/locator name to algorithm N for SRv6
// origination. Storage-only here; the LSP emit follow-up will turn
// each entry into an SRv6 Locator TLV 27 with Algorithm=N (RFC 9352
// §7.1). The locator-watch reconciliation that fires for the algo-0
// `sr_srv6_locator` is not invoked here — per-algo locators live in
// the same /segment-routing/locator namespace and will be folded into
// the watch set in the same PR that consumes the map.
fn config_sr_srv6_flex_algo_locator(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let algo = args.u8()?;
    if !(128..=255).contains(&algo) {
        return None;
    }
    if op.is_set() {
        let name = args.string()?;
        isis.config.sr_srv6_flex_algo_locators.insert(algo, name);
    } else {
        isis.config.sr_srv6_flex_algo_locators.remove(&algo);
    }
    Some(())
}

fn config_ti_lfa(isis: &mut Isis, _args: Args, op: ConfigOp) -> Option<()> {
    let prev = isis.config.ti_lfa_enabled;
    isis.config.ti_lfa_enabled = op.is_set();
    if isis.config.ti_lfa_enabled == prev {
        return Some(());
    }
    // Re-originate the self LSP so the Adj-SID B-flag (RFC 8667 §2.2.1)
    // reflects the new state at LSP-generation time. has_level() inside
    // process_lsp_originate filters out the wrong level for
    // level-1-only / level-2-only instances, so sending both
    // unconditionally is safe.
    let _ = isis.tx.send(Message::LspOriginate(Level::L1, None));
    let _ = isis.tx.send(Message::LspOriginate(Level::L2, None));
    // Recompute SPF so the RIB picks up repair paths (on enable) or
    // drops them (on disable) for every prefix in this instance.
    let _ = isis.tx.send(Message::SpfCalc(Level::L1));
    let _ = isis.tx.send(Message::SpfCalc(Level::L2));
    Some(())
}

// Single-leaf callback. The YANG narrowed `multi-topology` from a
// container-with-list to a single enum leaf because the only MT every
// real-world IS-IS deployment turns on is MT 2 (IPv6 unicast); the
// classic dual-flavour matrix never landed in any operator's running
// config. Set with `ipv6-unicast` flips MT on for that topology;
// delete clears both the flag and the set.
fn config_mt(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    if op.is_set() {
        let id_str = args.string()?;
        let id = MtId::from_str(&id_str).ok()?;
        isis.config.mt_enabled = true;
        isis.config.mt_topologies.clear();
        isis.config.mt_topologies.insert(id);
    } else {
        isis.config.mt_enabled = false;
        isis.config.mt_topologies.clear();
    }
    Some(())
}

/// `/router/isis/afi-safi[name=ipv4|ipv6]/network[prefix=...]`.
///
/// Mirrors BGP's `network` statement: configured prefixes are
/// advertised in every self-originated LSP independently of any
/// interface address. Family validation happens here (v4 prefix under
/// afi-safi=ipv4, v6 under ipv6); a mismatch returns None so libyang
/// surfaces it as a commit failure.
fn config_network(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let afi = args.string()?;
    match afi.as_str() {
        "ipv4" => {
            let network = args.v4net()?;
            if op.is_set() {
                isis.config.networks_v4.insert(network);
            } else {
                isis.config.networks_v4.remove(&network);
            }
        }
        "ipv6" => {
            let network = args.v6net()?;
            if op.is_set() {
                isis.config.networks_v6.insert(network);
            } else {
                isis.config.networks_v6.remove(&network);
            }
        }
        _ => return None,
    }
    // Re-originate both levels so the change reaches peers without
    // waiting for the refresh timer. `process_lsp_originate` filters
    // out the level that doesn't apply on single-level instances.
    let _ = isis.tx.send(Message::LspOriginate(Level::L1, None));
    let _ = isis.tx.send(Message::LspOriginate(Level::L2, None));
    Some(())
}

// ---- redistribute -----------------------------------------------------
//
// One presence-container callback per source (creates/removes the
// (AFI, source) entry) plus one callback per modifier leaf (mutates
// the entry's field). The two helpers below carry the dispatch.

fn parse_redist_afi(s: &str) -> Option<IsisRedistAfi> {
    match s {
        "ipv4" => Some(IsisRedistAfi::Ipv4),
        "ipv6" => Some(IsisRedistAfi::Ipv6),
        _ => None,
    }
}

fn notify_lsp_reorigination(isis: &Isis) {
    let _ = isis.tx.send(Message::LspOriginate(Level::L1, None));
    let _ = isis.tx.send(Message::LspOriginate(Level::L2, None));
}

/// Translate the YANG-side `IsisRedistAfi` into the wire-side
/// `rib::RedistAfi`. Two enums with identical variants — separate
/// types because the YANG one is config-tree-local while the wire
/// one lives in the rib crate.
fn wire_afi(afi: IsisRedistAfi) -> crate::rib::RedistAfi {
    match afi {
        IsisRedistAfi::Ipv4 => crate::rib::RedistAfi::Ipv4,
        IsisRedistAfi::Ipv6 => crate::rib::RedistAfi::Ipv6,
    }
}

/// Map the YANG redistribute source to the RIB-side rtype identifier
/// for the filter on RedistAdd / RedistUpdate.
fn wire_rtype(src: IsisRedistSource) -> crate::rib::RibType {
    match src {
        IsisRedistSource::Connected => crate::rib::RibType::Connected,
        IsisRedistSource::Static => crate::rib::RibType::Static,
        IsisRedistSource::Bgp => crate::rib::RibType::Bgp,
        IsisRedistSource::Ospf => crate::rib::RibType::Ospf,
    }
}

/// Compute the wire-level subtype filter from the IS-IS `IsisRedistribute`
/// entry. OSPF source carries an `ospf_match` set with the coarse-grained
/// `{internal, external, nssa-external}` flags from the YANG; expand each
/// to the matching `RibSubType` variants. Non-OSPF sources have no
/// subtype dimension, so always wildcard (empty).
fn wire_subtypes(
    src: IsisRedistSource,
    entry: &IsisRedistribute,
) -> std::collections::BTreeSet<crate::rib::RibSubType> {
    use crate::rib::RibSubType;
    let mut out = std::collections::BTreeSet::new();
    if src != IsisRedistSource::Ospf || entry.ospf_match.is_empty() {
        return out; // wildcard
    }
    for m in &entry.ospf_match {
        match m {
            // OSPF "internal" = intra-area + inter-area routes
            // (the non-external bucket the RIB sees).
            IsisRedistOspfMatch::Internal => {
                out.insert(RibSubType::Default);
                out.insert(RibSubType::OspfIa);
            }
            IsisRedistOspfMatch::External => {
                out.insert(RibSubType::OspfExternal1);
                out.insert(RibSubType::OspfExternal2);
            }
            IsisRedistOspfMatch::NssaExternal => {
                out.insert(RibSubType::OspfNssa1);
                out.insert(RibSubType::OspfNssa2);
            }
        }
    }
    out
}

/// Send the RIB the appropriate Redist message for the current state
/// of `(afi, src)`:
///   - presence container removed (no entry) → RedistDel
///   - entry present, first time the filter shows up → caller passes
///     `first_time = true` and we send RedistAdd
///   - entry present, subsequent subtype change → RedistUpdate
fn send_redist(isis: &Isis, afi: IsisRedistAfi, src: IsisRedistSource, first_time: bool) {
    let wire_afi = wire_afi(afi);
    let rtype = wire_rtype(src);
    let proto = "isis".to_string();
    let msg = match isis.config.redistribute.get(&(afi, src)) {
        None => crate::rib::Message::RedistDel {
            proto,
            afi: wire_afi,
            rtype,
        },
        Some(entry) if first_time => crate::rib::Message::RedistAdd {
            proto,
            afi: wire_afi,
            rtype,
            subtypes: wire_subtypes(src, entry),
        },
        Some(entry) => crate::rib::Message::RedistUpdate {
            proto,
            afi: wire_afi,
            rtype,
            subtypes: wire_subtypes(src, entry),
        },
    };
    let _ = isis.ctx.rib.send(msg);
}

fn redist_set_presence(
    isis: &mut Isis,
    mut args: Args,
    op: ConfigOp,
    src: IsisRedistSource,
) -> Option<()> {
    let afi = parse_redist_afi(&args.string()?)?;
    let first_time = !isis.config.redistribute.contains_key(&(afi, src));
    if op.is_set() {
        isis.config.redistribute.entry((afi, src)).or_default();
    } else {
        isis.config.redistribute.remove(&(afi, src));
    }
    send_redist(isis, afi, src, first_time && op.is_set());
    notify_lsp_reorigination(isis);
    Some(())
}

/// Mutate a single field on the (AFI, source) entry. The leaf's value
/// is read inside the closure so the per-leaf callbacks stay one-liners.
/// `subtype_relevant = true` means the mutation may have changed the
/// wire-level subtype set (only the `ospf_match` callback today),
/// triggering a RedistUpdate to RIB; other modifier leaves stay
/// consumer-side and don't need to flip the RIB filter.
fn redist_with<F>(
    isis: &mut Isis,
    mut args: Args,
    op: ConfigOp,
    src: IsisRedistSource,
    subtype_relevant: bool,
    f: F,
) -> Option<()>
where
    F: FnOnce(&mut IsisRedistribute, &mut Args, ConfigOp) -> Option<()>,
{
    let afi = parse_redist_afi(&args.string()?)?;
    let entry = isis.config.redistribute.entry((afi, src)).or_default();
    f(entry, &mut args, op)?;
    if subtype_relevant {
        send_redist(isis, afi, src, /* first_time = */ false);
    }
    notify_lsp_reorigination(isis);
    Some(())
}

fn set_policy(e: &mut IsisRedistribute, a: &mut Args, op: ConfigOp) -> Option<()> {
    e.policy = if op.is_set() { Some(a.string()?) } else { None };
    Some(())
}
fn set_metric(e: &mut IsisRedistribute, a: &mut Args, op: ConfigOp) -> Option<()> {
    e.metric = if op.is_set() { Some(a.u32()?) } else { None };
    Some(())
}
fn set_level(e: &mut IsisRedistribute, a: &mut Args, op: ConfigOp) -> Option<()> {
    if op.is_set() {
        e.level = Some(match a.string()?.as_str() {
            "level-1" => IsisRedistLevel::L1,
            "level-2" => IsisRedistLevel::L2,
            "level-1-2" => IsisRedistLevel::L1L2,
            _ => return None,
        });
    } else {
        e.level = None;
    }
    Some(())
}
fn set_metric_type(e: &mut IsisRedistribute, a: &mut Args, op: ConfigOp) -> Option<()> {
    if op.is_set() {
        e.metric_type = Some(match a.string()?.as_str() {
            "internal" => IsisRedistMetricType::Internal,
            "external" => IsisRedistMetricType::External,
            "rib-metric-as-internal" => IsisRedistMetricType::RibAsInternal,
            "rib-metric-as-external" => IsisRedistMetricType::RibAsExternal,
            _ => return None,
        });
    } else {
        e.metric_type = None;
    }
    Some(())
}
fn set_ospf_match(e: &mut IsisRedistribute, a: &mut Args, op: ConfigOp) -> Option<()> {
    let v = match a.string()?.as_str() {
        "internal" => IsisRedistOspfMatch::Internal,
        "external" => IsisRedistOspfMatch::External,
        "nssa-external" => IsisRedistOspfMatch::NssaExternal,
        _ => return None,
    };
    if op.is_set() {
        e.ospf_match.insert(v);
    } else {
        e.ospf_match.remove(&v);
    }
    Some(())
}

// Per-source presence + modifier wrappers. Each is a one-liner that
// pins the IsisRedistSource for the path libyang dispatches on.
fn config_redistribute_connected(isis: &mut Isis, args: Args, op: ConfigOp) -> Option<()> {
    redist_set_presence(isis, args, op, IsisRedistSource::Connected)
}
fn config_redistribute_connected_policy(isis: &mut Isis, args: Args, op: ConfigOp) -> Option<()> {
    redist_with(
        isis,
        args,
        op,
        IsisRedistSource::Connected,
        false,
        set_policy,
    )
}
fn config_redistribute_connected_metric(isis: &mut Isis, args: Args, op: ConfigOp) -> Option<()> {
    redist_with(
        isis,
        args,
        op,
        IsisRedistSource::Connected,
        false,
        set_metric,
    )
}
fn config_redistribute_connected_level(isis: &mut Isis, args: Args, op: ConfigOp) -> Option<()> {
    redist_with(
        isis,
        args,
        op,
        IsisRedistSource::Connected,
        false,
        set_level,
    )
}
fn config_redistribute_connected_metric_type(
    isis: &mut Isis,
    args: Args,
    op: ConfigOp,
) -> Option<()> {
    redist_with(
        isis,
        args,
        op,
        IsisRedistSource::Connected,
        false,
        set_metric_type,
    )
}

fn config_redistribute_static(isis: &mut Isis, args: Args, op: ConfigOp) -> Option<()> {
    redist_set_presence(isis, args, op, IsisRedistSource::Static)
}
fn config_redistribute_static_policy(isis: &mut Isis, args: Args, op: ConfigOp) -> Option<()> {
    redist_with(isis, args, op, IsisRedistSource::Static, false, set_policy)
}
fn config_redistribute_static_metric(isis: &mut Isis, args: Args, op: ConfigOp) -> Option<()> {
    redist_with(isis, args, op, IsisRedistSource::Static, false, set_metric)
}
fn config_redistribute_static_level(isis: &mut Isis, args: Args, op: ConfigOp) -> Option<()> {
    redist_with(isis, args, op, IsisRedistSource::Static, false, set_level)
}
fn config_redistribute_static_metric_type(isis: &mut Isis, args: Args, op: ConfigOp) -> Option<()> {
    redist_with(
        isis,
        args,
        op,
        IsisRedistSource::Static,
        false,
        set_metric_type,
    )
}

fn config_redistribute_bgp(isis: &mut Isis, args: Args, op: ConfigOp) -> Option<()> {
    redist_set_presence(isis, args, op, IsisRedistSource::Bgp)
}
fn config_redistribute_bgp_policy(isis: &mut Isis, args: Args, op: ConfigOp) -> Option<()> {
    redist_with(isis, args, op, IsisRedistSource::Bgp, false, set_policy)
}
fn config_redistribute_bgp_metric(isis: &mut Isis, args: Args, op: ConfigOp) -> Option<()> {
    redist_with(isis, args, op, IsisRedistSource::Bgp, false, set_metric)
}
fn config_redistribute_bgp_level(isis: &mut Isis, args: Args, op: ConfigOp) -> Option<()> {
    redist_with(isis, args, op, IsisRedistSource::Bgp, false, set_level)
}
fn config_redistribute_bgp_metric_type(isis: &mut Isis, args: Args, op: ConfigOp) -> Option<()> {
    redist_with(
        isis,
        args,
        op,
        IsisRedistSource::Bgp,
        false,
        set_metric_type,
    )
}

fn config_redistribute_ospf(isis: &mut Isis, args: Args, op: ConfigOp) -> Option<()> {
    redist_set_presence(isis, args, op, IsisRedistSource::Ospf)
}
fn config_redistribute_ospf_policy(isis: &mut Isis, args: Args, op: ConfigOp) -> Option<()> {
    redist_with(isis, args, op, IsisRedistSource::Ospf, false, set_policy)
}
fn config_redistribute_ospf_metric(isis: &mut Isis, args: Args, op: ConfigOp) -> Option<()> {
    redist_with(isis, args, op, IsisRedistSource::Ospf, false, set_metric)
}
fn config_redistribute_ospf_level(isis: &mut Isis, args: Args, op: ConfigOp) -> Option<()> {
    redist_with(isis, args, op, IsisRedistSource::Ospf, false, set_level)
}
fn config_redistribute_ospf_metric_type(isis: &mut Isis, args: Args, op: ConfigOp) -> Option<()> {
    redist_with(
        isis,
        args,
        op,
        IsisRedistSource::Ospf,
        false,
        set_metric_type,
    )
}
// `match { type … }` is the one leaf whose change actually flips the
// wire-level subtype filter — pass `subtype_relevant: true` so the
// callback emits a `RedistUpdate` to RIB.
fn config_redistribute_ospf_match_type(isis: &mut Isis, args: Args, op: ConfigOp) -> Option<()> {
    redist_with(isis, args, op, IsisRedistSource::Ospf, true, set_ospf_match)
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
