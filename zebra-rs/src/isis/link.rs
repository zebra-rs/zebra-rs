use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::collections::btree_map::Iter;
use std::fmt::Write;
use std::sync::Arc;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use isis_packet::neigh::IsisSubTlv as NeighSubTlv;
use isis_packet::*;
use netlink_packet_route::link::LinkFlags;
use serde::Serialize;
use socket2::Socket;
use strum_macros::{Display, EnumString};
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::{self, UnboundedSender};

use crate::bfd::session::{EchoMode, SessionKey};
use crate::config::{Args, ConfigOp};
use crate::context::Timer;
use crate::isis_event_trace;
use crate::rib::link::LinkAddr;
use crate::rib::{Link, LinkFlagsExt, MacAddr};

use super::config::{
    self, IsisAuthConfig, IsisConfig, MtId, auth_set_key_id, auth_set_password, auth_set_send_only,
    auth_set_type,
};
use super::graph::{ReachMapV4, ReachMapV6};
use super::ifsm::{self, has_level};
use super::lsp::PacketMessage;
use super::neigh::Neighbor;
use super::network::{read_packet, write_packet};
use super::socket::isis_socket;
use super::srmpls::IsisLabelMap;
use super::tracing::IsisTracing;
use super::{Hostname, IfsmEvent, Isis, Level, Levels, Lsdb, Message};
use crate::spf::label_pool::LabelPool;

#[derive(Debug, Default)]
pub struct LinkTimer {
    pub hello: Levels<Option<Timer>>,
    pub csnp: Levels<Option<Timer>>,
    /// Debounce timer for LAN DIS (re)election. Coalesces the election
    /// triggers (adjacency up/down, a neighbour's priority/SNPA/LAN-ID
    /// change) that arrive close together into a single run against the
    /// settled neighbour state — see `ifsm::dis_schedule`.
    pub dis: Levels<Option<Timer>>,
}

#[derive(Default, Debug)]
pub struct Afis<T> {
    pub v4: T,
    pub v6: T,
}

#[derive(Debug)]
pub enum Afi {
    Ip,
    Ip6,
}

impl<T> Afis<T> {
    pub fn get(&self, afi: &Afi) -> &T {
        match afi {
            Afi::Ip => &self.v4,
            Afi::Ip6 => &self.v6,
        }
    }

    pub fn get_mut(&mut self, afi: &Afi) -> &mut T {
        match afi {
            Afi::Ip => &mut self.v4,
            Afi::Ip6 => &mut self.v6,
        }
    }
}

#[derive(Debug, Default)]
pub struct IsisLinks {
    pub map: BTreeMap<u32, IsisLink>,
}

impl IsisLinks {
    pub fn get(&self, key: &u32) -> Option<&IsisLink> {
        self.map.get(key)
    }

    pub fn get_mut(&mut self, key: &u32) -> Option<&mut IsisLink> {
        self.map.get_mut(key)
    }

    pub fn get_mut_by_name(&mut self, name: &str) -> Option<&mut IsisLink> {
        self.map.values_mut().find(|link| link.state.name == name)
    }

    pub fn insert(&mut self, key: u32, value: IsisLink) -> Option<IsisLink> {
        self.map.insert(key, value)
    }

    pub fn iter(&self) -> Iter<'_, u32, IsisLink> {
        self.map.iter()
    }

    pub fn values(&self) -> std::collections::btree_map::Values<'_, u32, IsisLink> {
        self.map.values()
    }

    pub fn values_mut(&mut self) -> std::collections::btree_map::ValuesMut<'_, u32, IsisLink> {
        self.map.values_mut()
    }
}

#[derive(Debug)]
pub struct IsisLink {
    pub ifindex: u32,
    pub ptx: UnboundedSender<PacketMessage>,
    pub sock: Arc<AsyncFd<Socket>>,
    pub flags: LinkFlags,
    pub config: LinkConfig,
    pub state: LinkState,
    pub timer: LinkTimer,
}

pub struct LinkTop<'a> {
    pub ifindex: u32,
    pub tx: &'a UnboundedSender<Message>,
    pub ptx: &'a UnboundedSender<PacketMessage>,
    pub lsdb: &'a mut Levels<Lsdb>,
    pub flags: &'a LinkFlags,
    pub up_config: &'a IsisConfig,
    /// Snapshot of the per-instance `Isis.restarting` state. `Some`
    /// only between `clear isis graceful-restart begin` and either
    /// `abort`, `restarter-enabled=false`, or successful exit.
    /// Read by the IIH send path to attach RR=1.
    pub restarting: Option<&'a super::inst::RestartingState>,
    pub tracing: &'a IsisTracing,
    pub config: &'a LinkConfig,
    pub state: &'a mut LinkState,
    pub timer: &'a mut LinkTimer,
    pub local_pool: &'a mut Option<LabelPool>,
    pub hostname: &'a mut Levels<Hostname>,
    pub reach_map: &'a mut Levels<Afis<ReachMapV4>>,
    pub reach_map_v6: &'a mut Levels<ReachMapV6>,
    pub mt2_reach_map_v6: &'a mut Levels<ReachMapV6>,
    pub mt_membership:
        &'a mut Levels<std::collections::BTreeMap<IsisSysId, std::collections::BTreeSet<MtId>>>,
    pub label_map: &'a mut Levels<IsisLabelMap>,
    pub srv6_end_map:
        &'a mut Levels<std::collections::BTreeMap<IsisSysId, super::srv6::Srv6EndSidInfo>>,
    pub peer_fad: &'a mut Levels<
        std::collections::BTreeMap<
            IsisSysId,
            std::collections::BTreeMap<u8, isis_packet::IsisSubFlexAlgoDef>,
        >,
    >,
    pub peer_link_affinity: &'a mut Levels<
        std::collections::BTreeMap<
            IsisSysId,
            std::collections::BTreeMap<isis_packet::IsisNeighborId, isis_packet::ExtAdminGroup>,
        >,
    >,
    pub peer_algo_sid: &'a mut Levels<
        std::collections::BTreeMap<
            IsisSysId,
            std::collections::BTreeMap<(u8, Ipv4Net), isis_packet::SidLabelValue>,
        >,
    >,
    pub peer_algos:
        &'a mut Levels<std::collections::BTreeMap<IsisSysId, std::collections::BTreeSet<u8>>>,
    pub peer_algo_srv6: &'a mut Levels<
        std::collections::BTreeMap<
            IsisSysId,
            std::collections::BTreeMap<u8, super::srv6::Srv6AlgoLoc>,
        >,
    >,
    pub spf_timer: &'a mut Levels<Option<Timer>>,
    pub spf_throttle: &'a mut Levels<crate::throttle::Throttle>,

    /// SR state needed for End.X (adjacency) SID allocation. Threaded
    /// through so packet handlers can carve a function from the ELIB
    /// pool the moment they learn about a new neighbor, without round-
    /// tripping back through the IS-IS instance.
    pub rib_client: &'a crate::rib::client::RibClient,
    pub sr_locator: &'a Option<crate::rib::Locator>,
    pub watched_locator: &'a Option<String>,
    /// Per-Flex-Algorithm locator snapshots + watched names (mirrors
    /// `IsisTop`). The End.X reconcile derives a per-algo End.X SID from
    /// the algo-0 ELIB function under each of these locators' prefixes.
    pub sr_flex_algo_locators: &'a std::collections::BTreeMap<u8, crate::rib::Locator>,
    pub watched_flex_algo_locators: &'a std::collections::BTreeMap<u8, String>,
    pub elib: &'a mut crate::isis::srv6::ElibPool,
    /// Read-only snapshot of the policy-driven key-chain registry
    /// (mirrors `IsisTop::key_chains`). Hello / CSNP / PSNP sign +
    /// verify paths consult this when the per-link
    /// `hello-authentication` scope has a `key-chain` leaf set.
    pub key_chains: &'a std::collections::BTreeMap<String, crate::policy::KeyChain>,
}

impl<'a> LinkTop<'a> {
    pub fn is_p2p(&self) -> bool {
        // When we have user configuration.
        if let Some(network_type) = self.config.network_type {
            return network_type == NetworkType::P2p;
        }
        // Otherwise check interface flags.
        (*self.flags & LinkFlags::Pointopoint) == LinkFlags::Pointopoint
    }

    pub fn is_lan(&self) -> bool {
        !self.is_p2p()
    }

    /// A passive circuit runs no Hello protocol: it advertises its
    /// prefixes into the LSP but never sends or processes Hellos, so it
    /// forms no adjacency. True when the operator set `passive`, and
    /// always true for loopback interfaces (a loopback reflects its own
    /// Hellos straight back, so running the protocol on it would form a
    /// spurious adjacency with this router itself). The Hello send path
    /// (`ifsm::hello_send` / `hello_originate` / `start`) and the Hello
    /// receive path (`packet::hello_recv` / `hello_p2p_recv`) both gate
    /// on this.
    pub fn is_passive(&self) -> bool {
        self.config.passive || self.flags.is_loopback()
    }

    pub fn dest(&self, level: Level) -> Option<MacAddr> {
        if self.is_p2p() {
            if let Some((_, mac)) = self.state.adj.get(&level) {
                *mac
            } else {
                None
            }
        } else {
            None
        }
    }

    pub fn event(&self, message: Message) {
        self.tx.send(message).unwrap();
    }
}

#[derive(Default, Debug)]
pub struct LinkConfig {
    pub enable: Afis<bool>,

    /// Configured circuit type. When it conflict with IS-IS instance's is-type
    /// configuration, we respect IS-IS instance's is-type value. For example,
    /// is-type is level-2-only and circuit-type is level-1, link is configured
    /// as level-2-only.
    pub circuit_type: Option<IsLevel>,

    /// Link type one of LAN or Point-to-point.
    pub network_type: Option<NetworkType>,

    /// Passive circuit (`/router/isis/interface/<name>/passive`). When
    /// set, the interface's prefixes are still advertised into the LSP
    /// but no Hello PDUs are sent or processed, so no adjacency forms.
    /// `LinkTop::is_passive()` also folds in loopback interfaces, which
    /// are implicitly passive regardless of this flag.
    pub passive: bool,

    // Metric of this Link.
    pub metric: Option<u32>,

    pub priority: Option<u8>,
    pub hello_interval: Option<u16>,
    pub hello_multiplier: Option<u16>,
    pub hello_padding: Option<HelloPaddingPolicy>,
    pub holddown_count: Option<u32>,

    pub psnp_interval: Option<u32>,
    pub csnp_interval: Option<u32>,

    pub prefix_sid: Option<SidLabelValue>,

    /// RFC 8667 §2.1.1 P (no-PHP) flag for the loopback Prefix-SID
    /// (`.../ipv4/prefix-sid/no-php`, type empty). When set, the
    /// penultimate hop must not pop this node-SID label — it forwards
    /// the packet to us with the label intact. Only meaningful when
    /// `prefix_sid` is configured.
    pub prefix_sid_no_php: bool,

    /// Per-MT metric overrides — populated from
    /// /router/isis/interface/<name>/multi-topology/<id>/metric.
    /// Empty when no per-MT metric is configured; lookup falls back
    /// to the link's `metric` leaf above. Consumed when emitting MT
    /// IS Reach (TLV 222) entries.
    pub mt_metrics: BTreeMap<MtId, u32>,

    /// Per-interface BFD attachment recorded from
    /// `/router/isis/interface/<name>/bfd/enable`. The adjacency FSM
    /// subscribe path (on Up) and the `BfdEvent::Down` → adjacency
    /// teardown path consume this.
    pub bfd: LinkBfdConfig,

    /// SRLG group names this link belongs to (from the leaf-list at
    /// /router/isis/interface/<name>/srlg). Each name references a
    /// /srlg/group entry in the RIB-side global SRLG table; resolution
    /// from name to the 32-bit on-wire value happens at LSP-build time
    /// via `Isis::srlg_groups`. Held as a `BTreeSet` so the set is
    /// deduplicated and iterated in deterministic order — important
    /// because the order influences the byte layout of TLVs 138/139
    /// (RFC 5307 / RFC 6119) and so the LSP-content signature.
    pub srlg_groups: BTreeSet<String>,

    /// Affinity (admin-group) names this link belongs to, from
    /// /router/isis/interface/<name>/affinity. Each name references a
    /// /affinity-map/affinity entry; the bit positions are
    /// resolved to a 256-bit Extended Admin Group bitmap (RFC 7308) at
    /// LSP-build time, advertised inside the ASLA sub-TLV (RFC 9479)
    /// whenever at least one flex-algo references the attribute.
    /// `BTreeSet` for the same deterministic-iteration reason as
    /// `srlg_groups`.
    pub affinity: BTreeSet<String>,

    /// Statically configured RFC 8570 TE link metrics (unidirectional
    /// delay, min/max delay, delay variation, link loss) for this link,
    /// from /router/isis/interface/<name>/te-metric. Emitted as
    /// sub-TLVs on the link's Extended IS Reachability entry. Merged
    /// with the measured values (static wins per field) by
    /// [`IsisLink::te_metric_effective`].
    pub te_metric: LinkTeMetric,

    /// STAMP measurement config for this link, from
    /// /router/isis/interface/<name>/te-metric/measurement. When
    /// enabled (and the circuit is P2P with an Up adjacency carrying a
    /// v4 pair), `Isis::stamp_reconcile_link` keeps a measurement
    /// session subscribed; its damped exports land in
    /// `LinkState::measured_te_metric`.
    pub te_metric_measurement: crate::stamp::session::MeasurementConfig,

    /// Per-Flex-Algorithm Prefix-SID for this link's IPv4 address(es).
    /// Populated from
    /// /router/isis/interface/<name>/ipv4/flex-algo-prefix-sid[algo=N].
    /// Each entry produces an additional Prefix-SID sub-TLV (RFC 8667)
    /// on the link's IP-reach TLV with the Algorithm field set to the
    /// map key (RFC 9350 §7), alongside the algo-0 SID in
    /// `prefix_sid`. Storage-only — the LSP emitter consumes it once
    /// per-algo origination lands.
    pub ipv4_flex_algo_prefix_sids: BTreeMap<u8, SidLabelValue>,

    /// Per-interface authentication for IIH / CSNP / PSNP PDUs,
    /// from /router/isis/interface/<name>/hello-authentication.
    /// Active iff `hello_auth.is_active()`.
    pub hello_auth: IsisAuthConfig,
}

/// IS-IS-side mirror of the YANG `bfd { ... }` container. Backs **both** the
/// instance-level default (`router isis { bfd {} }`, `IsisConfig::bfd`) and the
/// per-interface override (`interface X bfd {}`, `LinkConfig::bfd`); every leaf
/// is `Option`/`None`-default so the per-interface value overrides the instance
/// default per leaf (see [`LinkBfdConfig::resolve`]), and "unset" is
/// distinguishable from a value. The adjacency FSM reads the *resolved* value
/// when an adjacency reaches Up to decide whether to subscribe + with what Echo.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct LinkBfdConfig {
    /// Activate BFD. Instance-level `Some(true)` blanket-enables every
    /// interface; per-interface overrides it (`Some(false)` opts out). `None` ⇒
    /// inherit; off if unset everywhere.
    pub enable: Option<bool>,
    /// BFD Echo role for adjacencies on this interface
    /// (`transmit` / `receive` / `both`); `None` ⇒ inherit (off if unset
    /// everywhere). Single-hop only; both families (an IPv6-only adjacency
    /// runs Echo over the two ends' link-locals).
    pub echo_mode: Option<EchoMode>,
    /// Echo transmit interval (ms); `None` ⇒ [`DEFAULT_ECHO_INTERVAL_MS`].
    pub echo_transmit_ms: Option<u32>,
    /// Advertised Required Min Echo RX (ms); `None` ⇒
    /// [`DEFAULT_ECHO_INTERVAL_MS`].
    pub echo_receive_ms: Option<u32>,
    /// Offload control-packet expiration detection (RFC 5880 §6.8.4) to the
    /// per-interface XDP helper once the session is Up. `None` ⇒ inherit
    /// (hard default `false`: detection in userspace).
    pub detect_offload: Option<bool>,
}

/// FRR default Echo interval (ms) — the hard default for the transmit/receive
/// intervals when unset at every level.
pub const DEFAULT_ECHO_INTERVAL_MS: u32 = 50;

/// Effective BFD settings for one interface after merging its per-interface
/// `bfd {}` over the instance-level default. (IS-IS has no `min-neighbor-state`
/// — it subscribes at adjacency Up.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedBfd {
    pub enable: bool,
    pub echo_mode: Option<EchoMode>,
    pub echo_transmit_ms: u32,
    pub echo_receive_ms: u32,
    pub detect_offload: bool,
}

impl LinkBfdConfig {
    /// Resolve `self` (per-interface) over `default` (instance-level), per leaf.
    pub fn resolve(&self, default: &LinkBfdConfig) -> ResolvedBfd {
        ResolvedBfd {
            enable: self.enable.or(default.enable).unwrap_or(false),
            echo_mode: self.echo_mode.or(default.echo_mode),
            echo_transmit_ms: self
                .echo_transmit_ms
                .or(default.echo_transmit_ms)
                .unwrap_or(DEFAULT_ECHO_INTERVAL_MS),
            echo_receive_ms: self
                .echo_receive_ms
                .or(default.echo_receive_ms)
                .unwrap_or(DEFAULT_ECHO_INTERVAL_MS),
            detect_offload: self
                .detect_offload
                .or(default.detect_offload)
                .unwrap_or(false),
        }
    }
}

/// IS-IS-side mirror of the YANG `te-metric { ... }` container — the
/// per-interface RFC 8570 traffic-engineering link metrics. Each field
/// is `None` until configured (or, in a later phase, measured). Delay
/// values are in microseconds; `loss` is the 24-bit value encoded per
/// RFC 8570 §4.4 (units of 0.000003 %).
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct LinkTeMetric {
    pub unidirectional_delay: Option<u32>,
    pub min_delay: Option<u32>,
    pub max_delay: Option<u32>,
    pub delay_variation: Option<u32>,
    pub loss: Option<u32>,
}

impl LinkTeMetric {
    /// RFC 8570 sub-TLVs for this link's Extended IS Reachability entry
    /// (TLV 22, and MT IS Reach TLV 222 when multi-topology is on), in
    /// ascending sub-TLV-code order (33, 34, 35, 36). Statically
    /// configured values carry a clear Anomalous flag — the dynamic
    /// measurement task will raise it on threshold crossing in a later
    /// phase. Min/Max delay (sub-TLV 34) is emitted only when both
    /// bounds are configured.
    pub fn sub_tlvs(&self) -> Vec<NeighSubTlv> {
        let mut subs = Vec::new();
        if let Some(delay) = self.unidirectional_delay {
            subs.push(NeighSubTlv::UniLinkDelay(IsisSubUniLinkDelay {
                anomalous: false,
                delay,
            }));
        }
        if let (Some(min_delay), Some(max_delay)) = (self.min_delay, self.max_delay) {
            subs.push(NeighSubTlv::MinMaxLinkDelay(IsisSubMinMaxLinkDelay {
                anomalous: false,
                min_delay,
                max_delay,
            }));
        }
        if let Some(variation) = self.delay_variation {
            subs.push(NeighSubTlv::DelayVariation(IsisSubDelayVariation {
                variation,
            }));
        }
        if let Some(loss) = self.loss {
            subs.push(NeighSubTlv::LinkLoss(IsisSubLinkLoss {
                anomalous: false,
                loss,
            }));
        }
        subs
    }

    /// Per-field merge of `self` (static config) over `fallback`
    /// (measured values): a configured field always wins, an
    /// unconfigured one takes the measurement.
    pub fn merged_over(&self, fallback: &LinkTeMetric) -> LinkTeMetric {
        LinkTeMetric {
            unidirectional_delay: self.unidirectional_delay.or(fallback.unidirectional_delay),
            min_delay: self.min_delay.or(fallback.min_delay),
            max_delay: self.max_delay.or(fallback.max_delay),
            delay_variation: self.delay_variation.or(fallback.delay_variation),
            loss: self.loss.or(fallback.loss),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, EnumString, Display)]
pub enum NetworkType {
    #[strum(serialize = "loopback")]
    Loopback,
    #[strum(serialize = "lan")]
    Lan,
    #[strum(serialize = "point-to-point", to_string = "p2p")]
    P2p,
}

impl NetworkType {
    pub fn is_p2p(&self) -> bool {
        *self == Self::P2p
    }
}

impl LinkConfig {
    const DEFAULT_PRIORITY: u8 = 64;
    const DEFAULT_HELLO_INTERVAL: u16 = 3;
    // Higher than IOS-XR's default of 3 because zebra-rs's default
    // hello interval (3s) is shorter than IOS-XR's (10s); 3 × 10 = 30s
    // preserves the prior absolute hold-time default.
    const DEFAULT_HELLO_MULTIPLIER: u16 = 10;
    const DEFAULT_METRIC: u32 = 10;
    const DEFAULT_HOLDDOWN_COUNT: u32 = 10;
    const DEFAULT_PSNP_INTERVAL: u32 = 2;
    const DEFAULT_CSNP_INTERVAL: u32 = 10;

    pub fn circuit_type(&self) -> IsLevel {
        self.circuit_type.unwrap_or(IsLevel::L1L2)
    }

    pub fn network_type(&self) -> NetworkType {
        self.network_type.unwrap_or(NetworkType::Lan)
    }

    pub fn metric(&self) -> u32 {
        self.metric.unwrap_or(Self::DEFAULT_METRIC)
    }

    /// Metric for this link within a given Multi-Topology (RFC 5120).
    /// Three-level fallback: the per-MT override
    /// (`multi-topology/<id>/metric`), else the plain `metric` leaf,
    /// else the default (10). Callers use this for every MT-keyed
    /// advertisement (TLV 222 MT IS-reach, TLV 237 MT IPv6-reach) so a
    /// per-topology metric is honored consistently across adjacency and
    /// prefix cost.
    pub fn mt_metric(&self, mt: MtId) -> u32 {
        self.mt_metrics
            .get(&mt)
            .copied()
            .unwrap_or_else(|| self.metric())
    }

    pub fn priority(&self) -> u8 {
        self.priority.unwrap_or(Self::DEFAULT_PRIORITY)
    }

    pub fn hello_interval(&self) -> u64 {
        self.hello_interval.unwrap_or(Self::DEFAULT_HELLO_INTERVAL) as u64
    }

    pub fn hello_multiplier(&self) -> u16 {
        self.hello_multiplier
            .unwrap_or(Self::DEFAULT_HELLO_MULTIPLIER)
    }

    pub fn hold_time(&self) -> u16 {
        let interval = self.hello_interval() as u32;
        let mult = self.hello_multiplier() as u32;
        interval.saturating_mul(mult).min(u16::MAX as u32) as u16
    }

    pub fn hello_padding(&self) -> HelloPaddingPolicy {
        self.hello_padding.unwrap_or(HelloPaddingPolicy::Always)
    }
    pub fn holddown_count(&self) -> u32 {
        self.holddown_count.unwrap_or(Self::DEFAULT_HOLDDOWN_COUNT)
    }

    pub fn psnp_interval(&self) -> u64 {
        self.psnp_interval.unwrap_or(Self::DEFAULT_PSNP_INTERVAL) as u64
    }

    pub fn csnp_interval(&self) -> u64 {
        self.csnp_interval.unwrap_or(Self::DEFAULT_CSNP_INTERVAL) as u64
    }

    pub fn enabled(&self) -> bool {
        self.enable.v4 || self.enable.v6
    }
}

#[derive(Default, Debug, PartialEq, Clone, Copy)]
pub enum DisStatus {
    #[default]
    NotSelected,
    Myself,
    Other,
}

#[derive(Debug, Clone)]
pub struct DisChange {
    pub timestamp: std::time::SystemTime,
    pub from_status: DisStatus,
    pub to_status: DisStatus,
    pub from_sys_id: Option<IsisSysId>,
    pub to_sys_id: Option<IsisSysId>,
    pub reason: String,
}

#[derive(Debug, Default)]
pub struct DisStatistics {
    pub flap_count: u32,
    pub last_change: Option<std::time::SystemTime>,
    pub uptime: Option<std::time::SystemTime>,
    pub history: Vec<DisChange>,
}

impl DisStatistics {
    const MAX_HISTORY: usize = 50;

    pub fn record_change(
        &mut self,
        from_status: DisStatus,
        to_status: DisStatus,
        from_sys_id: Option<IsisSysId>,
        to_sys_id: Option<IsisSysId>,
        reason: String,
    ) {
        let now = std::time::SystemTime::now();

        // Update flap count
        self.flap_count += 1;
        self.last_change = Some(now);

        // If becoming DIS, update uptime
        if matches!(to_status, DisStatus::Myself) {
            self.uptime = Some(now);
        }

        // Add to history
        let change = DisChange {
            timestamp: now,
            from_status,
            to_status,
            from_sys_id,
            to_sys_id,
            reason,
        };

        self.history.push(change);
        if self.history.len() > Self::MAX_HISTORY {
            self.history.remove(0);
        }
    }
}

// Mutable data during operation.
#[derive(Default, Debug)]
pub struct LinkState {
    // pub ifindex: u32,
    pub name: String,
    pub mtu: u32,
    pub mac: Option<MacAddr>,

    // IP addresses.
    pub v4addr: Vec<Ipv4Net>,
    pub v6addr: Vec<Ipv6Net>,
    pub v6laddr: Vec<Ipv6Net>,

    // Link level. This value is the final level value from IS-IS instance's
    // is-type and link's circuit-type. Please use LinkState::level() method for
    // get link level value.
    level: IsLevel,

    // Neighbors.
    pub nbrs: Levels<BTreeMap<IsisSysId, Neighbor>>,

    // Up neighbors.
    pub nbrs_up: Levels<u32>,

    // Neighbours whose attached BFD session is currently Down (RFC 5882
    // §3.2 hold-down). While a neighbour's system-id sits in this set the
    // NFSM refuses to (re-)promote its adjacency to Up even though IIHs keep
    // arriving, and the BFD session is kept subscribed so it can detect the
    // peer coming back. The entry is cleared when BFD reports the session Up
    // again, or when the neighbour is torn down for real (hold-timer expiry).
    pub bfd_holddown: Levels<BTreeSet<IsisSysId>>,

    // Reverse map from BFD SessionKey → (Level, IsisSysId). Populated by
    // process_bfd_down alongside bfd_holddown so that process_bfd_up can
    // clear the hold-down pin even when the neighbour entry was already
    // removed from `nbrs` by nbr_hold_timer_expire (race: BFD recovers
    // before the next IIH re-creates the entry). Cleaned up by
    // nbr_hold_timer_expire and process_bfd_up on use.
    pub bfd_holddown_nbr: HashMap<SessionKey, (Level, IsisSysId)>,

    // DIS status.
    pub dis_status: Levels<DisStatus>,

    // DIS on LAN interface. This value is set when DIS selection has been
    // completed. After DIS selection, we may have 2 events. One is lan_id value
    // in DIS's hello packet.  Another one is DIS generated pseudo node LSP.
    // pub dis_sys_id: Levels<Option<IsisSysId>>,

    // DIS in pseudo node LSP. When LSP has been received and my own system ID
    // exists in.
    pub adj: Levels<Option<(IsisNeighborId, Option<MacAddr>)>>,

    // DIS statistics and flap tracking
    pub dis_stats: Levels<DisStatistics>,

    // Stats.
    pub stats: Direction<LinkStats>,
    pub stats_unknown: u64,

    /// Authentication counters (Hellos only). `tx_signed` increments
    /// whenever we attach an Auth TLV outbound. `rx_good` /
    /// `rx_bad` count auth-TLV validate outcomes; `rx_no_auth`
    /// counts inbound Hellos with no Auth TLV when this link has
    /// auth configured (and is not in `send-only` mode).
    pub auth_tx_signed: u64,
    pub auth_rx_good: u64,
    pub auth_rx_bad: u64,
    pub auth_rx_no_auth: u64,

    // TODO: need to fix.
    pub hello: Levels<Option<IsisPdu>>,

    /// Last STAMP measurement exported for this link (all fields
    /// `None` when no measurement is active or the last export was a
    /// clear). Merged under the static config per field by
    /// [`IsisLink::te_metric_effective`].
    pub measured_te_metric: LinkTeMetric,

    /// The STAMP subscription this link currently holds, tracked so
    /// `Isis::stamp_reconcile_link` can diff desired-vs-actual and
    /// only (un)subscribe on a real change.
    pub stamp_session: Option<(
        crate::stamp::session::SessionKey,
        crate::stamp::session::SessionParams,
    )>,
}

impl LinkState {
    pub fn is_up(&self) -> bool {
        true
    }

    pub fn level(&self) -> IsLevel {
        self.level
    }

    pub fn set_level(&mut self, level: IsLevel) {
        if self.level != level {
            self.level = level;
        }
    }
}

#[derive(Default, Debug)]
pub struct Direction<T> {
    pub rx: T,
}

#[derive(Default, Debug)]
pub struct LinkStats {
    pub p2p_hello: u64,
    pub hello: Levels<u64>,
    pub lsp: Levels<u64>,
    pub psnp: Levels<u64>,
    pub csnp: Levels<u64>,
}

impl IsisLink {
    /// Build a per-interface IS-IS link record. The raw `AF_PACKET`
    /// socket is bound to `link.index` and the BPF filter applied here;
    /// both require `CAP_NET_RAW`. On failure we return `Err` so the
    /// caller can warn and skip the link — historically this was a
    /// double `.unwrap()` that took down the IS-IS task whenever the
    /// daemon ran without the right caps.
    pub fn from(link: Link, tx: UnboundedSender<Message>) -> std::io::Result<Self> {
        let raw = isis_socket(link.index)?;
        let sock = Arc::new(AsyncFd::new(raw)?);
        let (ptx, prx) = mpsc::unbounded_channel();
        let mut is_link = Self {
            ifindex: link.index,
            ptx,
            sock,
            flags: link.flags,
            config: LinkConfig::default(),
            state: LinkState::default(),
            timer: LinkTimer::default(),
        };
        is_link.state.name = link.name.to_owned();
        is_link.state.mtu = link.mtu;
        is_link.state.mac = link.mac;
        // Socket for read/write per interface.
        let sock = is_link.sock.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            read_packet(sock, tx).await;
        });
        let sock = is_link.sock.clone();
        tokio::spawn(async move {
            write_packet(sock, prx).await;
        });

        Ok(is_link)
    }

    /// Same circuit-type resolution as [`LinkTop::is_p2p`]: explicit
    /// `network-type` config wins, otherwise the kernel POINTOPOINT
    /// interface flag decides.
    pub fn is_p2p(&self) -> bool {
        if let Some(network_type) = self.config.network_type {
            return network_type == NetworkType::P2p;
        }
        (self.flags & LinkFlags::Pointopoint) == LinkFlags::Pointopoint
    }

    /// The TE metrics this link advertises: statically configured
    /// values win over measured ones, per field — an operator override
    /// never gets clobbered by measurement, while unconfigured fields
    /// track the live measurement (or fall silent when it clears).
    pub fn te_metric_effective(&self) -> LinkTeMetric {
        self.config
            .te_metric
            .merged_over(&self.state.measured_te_metric)
    }
}

impl Isis {
    pub fn link_add(&mut self, link: Link) {
        // println!("ISIS: LinkAdd {} {}", link.name, link.index);
        if self.links.get(&link.index).is_some() {
            return;
        }
        let ifindex = link.index;
        let name = link.name.clone();
        match IsisLink::from(link, self.tx.clone()) {
            Ok(is_link) => {
                self.links.insert(is_link.ifindex, is_link);
            }
            Err(e) => {
                tracing::warn!(
                    "isis: skip link {name} (ifindex={ifindex}); raw socket open failed: {e}"
                );
            }
        }
    }

    /// React to a kernel-side link-up event. Mirror the IFF_UP flag
    /// on our own link record and, if IS-IS is configured on this
    /// interface, kick the IFSM to re-arm hellos. Adjacencies form
    /// from scratch via the normal hello / NFSM path; LSP
    /// re-origination + SPF land naturally on each adjacency Up
    /// transition.
    pub fn link_state_up(&mut self, ifindex: u32) {
        let Some(link) = self.links.get_mut(&ifindex) else {
            return;
        };
        link.flags |= LinkFlags::Up;
        link.flags |= LinkFlags::LowerUp;
        if link.config.enabled() {
            let _ = self.tx.send(Message::Ifsm(IfsmEvent::Start, ifindex, None));
        }
    }

    /// Refresh the cached interface MTU after a kernel/operator MTU
    /// change. IS-IS uses it for hello padding (RFC 1195 §8) and LSP
    /// fragmentation sizing, and renders it in `show isis interface`.
    /// Those all read the live `state.mtu`, so updating it in place is
    /// enough — adjacencies stay up.
    pub fn link_mtu(&mut self, ifindex: u32, mtu: u32) {
        if let Some(link) = self.links.get_mut(&ifindex) {
            link.state.mtu = mtu;
        }
    }

    /// React to a kernel-side link-down event. Adjacencies on this
    /// link can't continue — packets stop flowing the moment IFF_UP
    /// drops — so tear them down immediately rather than ride out
    /// the 30s hold timer. Drop every neighbor entry so when the
    /// link comes back up, IFSM starts on a blank slate and NFSM
    /// transitions through Init / Up via fresh hellos. Then
    /// re-originate the self LSP without the dropped peers and
    /// schedule SPF for both levels so the route table reflects the
    /// new topology.
    pub fn link_state_down(&mut self, ifindex: u32) {
        let Some(link) = self.links.get_mut(&ifindex) else {
            return;
        };
        link.flags &= !LinkFlags::Up;
        link.flags &= !LinkFlags::LowerUp;
        let was_enabled = link.config.enabled();

        // Tear down per-level adjacency state. Each neighbor returns
        // its SR-MPLS label / End.X SID to the pool the same way
        // `nbr_hold_timer_expire` does — keep that path the one
        // place that frees per-adjacency resources — and the
        // neighbor entry itself is dropped so the next hello
        // creates a fresh one. Otherwise stale `addr4` /
        // `hold_timer` / `endx_sid` values would survive the link
        // bounce and the NFSM would re-enter from a half-populated
        // record.
        for level in [Level::L1, Level::L2] {
            let nbr_ids: Vec<IsisSysId> = link.state.nbrs.get(&level).keys().copied().collect();

            for sys_id in nbr_ids {
                if let Some(nbr) = link.state.nbrs.get_mut(&level).get_mut(&sys_id) {
                    // Release SR-MPLS adjacency labels.
                    if let Some(local_pool) = self.local_pool.as_mut() {
                        for value in nbr.addr4.values_mut() {
                            if let Some(label) = value.label.take() {
                                local_pool.release(label as usize);
                            }
                        }
                    }
                    nbr.release_endx_sid(&mut self.elib, &self.ctx.rib);
                }
                // Drop the entry. The hold-timer JoinHandle goes
                // with it; tokio cancels the underlying task on
                // drop.
                link.state.nbrs.get_mut(&level).remove(&sys_id);
            }

            // If we were the elected DIS on this circuit, purge the
            // pseudonode LSP we originated rather than leaving it to
            // age out over MaxAge (~20 min). ISO 10589 §7.3.4.6: a
            // router that ceases to be DIS purges its pseudonode LSP.
            // `dis_selection` does this via `ifsm::dis_dropping`, but a
            // link bounce never reaches that path — it resets the DIS
            // state directly below — so without this the LSP lingers
            // in every LSDB in the area. `dis_selection`'s
            // Other -> Other handling already *assumes* an ex-DIS has
            // purged, so leaving it is an invariant violation, not
            // just cosmetic.
            //
            // Guard on `DisStatus::Myself`, NOT on `adj.is_some()`:
            // `adj` also carries the *other* node's LAN-ID while we are
            // a plain LAN member (`DisStatus::Other`), and purging then
            // would destroy a different router's pseudonode LSP.
            //
            // Must run before `adj` is cleared just below — the LAN-ID
            // it holds is what identifies the pseudonode.
            if *link.state.dis_status.get(&level) == DisStatus::Myself
                && let Some((adj, _)) = link.state.adj.get(&level)
            {
                let lsp_id = IsisLspId::from_neighbor_id(*adj, 0);
                let _ = self.tx.send(Message::LspPurge(level, lsp_id));
            }

            // Reset per-level Up-neighbor counter and adjacency
            // bookkeeping.
            *link.state.nbrs_up.get_mut(&level) = 0;
            *link.state.adj.get_mut(&level) = None;
            *link.timer.csnp.get_mut(&level) = None;
            self.lsdb.get_mut(&level).adj_clear(ifindex);

            // Reset DIS selection status.
            *link.state.dis_status.get_mut(&level) = DisStatus::NotSelected;
        }

        // Stop hello generation on this interface.
        if was_enabled {
            let _ = self.tx.send(Message::Ifsm(IfsmEvent::Stop, ifindex, None));
        }

        // Re-originate the self LSP at both levels (pseudonode peers
        // dropped, fewer Ext IS Reach entries) and recompute SPF so
        // the route table no longer shows paths via the down link.
        let _ = self.tx.send(Message::LspOriginate(Level::L1, None));
        let _ = self.tx.send(Message::LspOriginate(Level::L2, None));
        let _ = self.tx.send(Message::SpfCalc(Level::L1));
        let _ = self.tx.send(Message::SpfCalc(Level::L2));
    }

    pub fn addr_add(&mut self, addr: LinkAddr) {
        self.addr_update(addr, true);
    }

    pub fn addr_del(&mut self, addr: LinkAddr) {
        self.addr_update(addr, false);
    }

    /// Shared body of `addr_add` / `addr_del`: route the prefix to
    /// the link's per-family address list (v4 skipping loopbacks, v6
    /// split into link-local vs global), apply the add/remove, and
    /// re-originate the Hello so the interface-address TLVs track the
    /// kernel.
    fn addr_update(&mut self, addr: LinkAddr, add: bool) {
        let Some(link) = self.links.get_mut(&addr.ifindex) else {
            return;
        };

        match addr.addr {
            IpNet::V4(prefix) => {
                if !prefix.addr().is_loopback() {
                    addr_list_update(&mut link.state.v4addr, prefix, add);
                }
            }
            IpNet::V6(prefix) => {
                let list = if prefix.addr().is_unicast_link_local() {
                    &mut link.state.v6laddr
                } else {
                    &mut link.state.v6addr
                };
                addr_list_update(list, prefix, add);
            }
        }

        if link.config.enabled() {
            let msg = Message::Ifsm(IfsmEvent::HelloOriginate, addr.ifindex, None);
            let _ = self.tx.send(msg);
        }
    }
}

/// Ensure `item` is present in (add) or absent from (remove) `list`
/// — an order-preserving Vec used as a small set.
fn addr_list_update<T: PartialEq>(list: &mut Vec<T>, item: T, add: bool) {
    if add {
        if !list.contains(&item) {
            list.push(item);
        }
    } else {
        list.retain(|p| p != &item);
    }
}

pub fn config_priority(isis: &mut Isis, mut args: Args, _op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let priority = args.u8()?;

    let link = isis.links.get_mut_by_name(&name)?;
    link.config.priority = Some(priority);

    let msg = Message::Ifsm(IfsmEvent::DisSelection, link.ifindex, None);
    let _ = isis.tx.send(msg);

    Some(())
}

/// `set router isis interface X bfd enabled true|false` — flips the
/// per-interface BFD attachment recorded on the IS-IS link. The
/// runtime subscribe path runs on adjacency FSM Up; the teardown
/// path runs on `BfdEvent::Down`.
pub fn config_bfd_enable(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let enable = args.boolean()?;
    let link = isis.links.get_mut_by_name(&name)?;
    // `None` ⇒ inherit `router isis { bfd { enabled } }`; `Some(false)` opts this
    // interface out of a blanket instance enable.
    link.config.bfd.enable = op.is_set().then_some(enable);
    isis.bfd_reconcile_all();
    Some(())
}

/// Parse the `{transmit|receive|both}` echo-mode enum (set) → `Some(mode)`, or
/// `None` on delete. Shared by the per-interface and instance-level handlers.
fn parse_echo_mode(value: &str, op: ConfigOp) -> Option<Option<EchoMode>> {
    if !op.is_set() {
        return Some(None);
    }
    match value {
        "transmit" => Some(Some(EchoMode::Transmit)),
        "receive" => Some(Some(EchoMode::Receive)),
        "both" => Some(Some(EchoMode::Both)),
        _ => None,
    }
}

/// `interface X bfd echo-mode <transmit|receive|both>` — per-interface Echo role
/// (RFC 5880 §6.4; single-hop IPv4). Overrides the instance default.
pub fn config_bfd_echo_mode(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let value = args.string()?;
    let mode = parse_echo_mode(&value, op)?;
    let link = isis.links.get_mut_by_name(&name)?;
    link.config.bfd.echo_mode = mode;
    isis.bfd_reconcile_all();
    Some(())
}

/// `interface X bfd echo-transmit-interval <ms>` — per-interface Echo TX rate.
pub fn config_bfd_echo_transmit_interval(
    isis: &mut Isis,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let name = args.string()?;
    let interval = args.u32()?;
    let link = isis.links.get_mut_by_name(&name)?;
    link.config.bfd.echo_transmit_ms = op.is_set().then_some(interval);
    isis.bfd_reconcile_all();
    Some(())
}

/// `interface X bfd echo-receive-interval <ms>` — per-interface advertised RX.
pub fn config_bfd_echo_receive_interval(
    isis: &mut Isis,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let name = args.string()?;
    let interval = args.u32()?;
    let link = isis.links.get_mut_by_name(&name)?;
    link.config.bfd.echo_receive_ms = op.is_set().then_some(interval);
    isis.bfd_reconcile_all();
    Some(())
}

/// `interface X bfd detect-offload <bool>` — offload control-packet expiration
/// detection (RFC 5880 §6.8.4) to the per-interface XDP helper once the
/// session is Up. Overrides the instance default; the BFD instance arms /
/// disarms the in-kernel watchdog on live sessions.
pub fn config_bfd_detect_offload(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let offload = args.boolean()?;
    let link = isis.links.get_mut_by_name(&name)?;
    // `None` ⇒ inherit `router isis { bfd { detect-offload } }`; `Some(false)`
    // explicitly opts this interface out.
    link.config.bfd.detect_offload = op.is_set().then_some(offload);
    isis.bfd_reconcile_all();
    Some(())
}

// ---- instance-level `router isis { bfd { ... } }` defaults ------------------

/// `router isis bfd enable <bool>` — blanket-enable BFD on every IS-IS
/// interface (a per-interface `bfd { enabled false }` opts one out).
pub fn config_isis_bfd_enable(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let enable = args.boolean()?;
    isis.config.bfd.enable = op.is_set().then_some(enable);
    isis.bfd_reconcile_all();
    Some(())
}

/// `router isis bfd echo-mode <transmit|receive|both>` — instance default.
pub fn config_isis_bfd_echo_mode(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let value = args.string()?;
    isis.config.bfd.echo_mode = parse_echo_mode(&value, op)?;
    isis.bfd_reconcile_all();
    Some(())
}

/// `router isis bfd echo-transmit-interval <ms>` — instance default.
pub fn config_isis_bfd_echo_transmit_interval(
    isis: &mut Isis,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let interval = args.u32()?;
    isis.config.bfd.echo_transmit_ms = op.is_set().then_some(interval);
    isis.bfd_reconcile_all();
    Some(())
}

/// `router isis bfd echo-receive-interval <ms>` — instance default.
pub fn config_isis_bfd_echo_receive_interval(
    isis: &mut Isis,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let interval = args.u32()?;
    isis.config.bfd.echo_receive_ms = op.is_set().then_some(interval);
    isis.bfd_reconcile_all();
    Some(())
}

/// `router isis bfd detect-offload <bool>` — instance default for offloading
/// expiration detection to the XDP helper (overridable per interface).
pub fn config_isis_bfd_detect_offload(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let offload = args.boolean()?;
    isis.config.bfd.detect_offload = op.is_set().then_some(offload);
    isis.bfd_reconcile_all();
    Some(())
}

/// `set router isis interface X hello-authentication` (presence
/// container). The leaf callbacks below mutate fields; this one
/// only resets the auth state when the entire container is removed
/// so we don't leave a stale auth-type / send-only behind a
/// vanished password.
pub fn config_hello_auth(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let link = isis.links.get_mut_by_name(&name)?;
    if !op.is_set() {
        config::auth_reset(&mut link.config.hello_auth);
    }
    Some(())
}

pub fn config_hello_auth_password(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let link = isis.links.get_mut_by_name(&name)?;
    auth_set_password(&mut link.config.hello_auth, &mut args, op)
}

pub fn config_hello_auth_type(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let link = isis.links.get_mut_by_name(&name)?;
    auth_set_type(&mut link.config.hello_auth, &mut args, op)
}

pub fn config_hello_auth_key_id(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let link = isis.links.get_mut_by_name(&name)?;
    auth_set_key_id(&mut link.config.hello_auth, &mut args, op)
}

pub fn config_hello_auth_send_only(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let link = isis.links.get_mut_by_name(&name)?;
    auth_set_send_only(&mut link.config.hello_auth, &mut args, op)
}

pub fn config_hello_auth_key_chain(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let link = isis.links.get_mut_by_name(&name)?;
    let ifindex = link.ifindex as usize;
    crate::isis::config::auth_set_key_chain(
        &mut link.config.hello_auth,
        &mut args,
        op,
        &isis.policy_tx,
        ifindex,
        crate::policy::KeyChainScope::IsisIih,
    )
}

fn config_afi_enable(isis: &mut Isis, mut args: Args, op: ConfigOp, afi: Afi) -> Option<()> {
    let name = args.string()?;
    let enable = args.boolean()?;

    let link = isis.links.get_mut_by_name(&name)?;

    // Currently IS-IS is enabled on this interface.
    let enabled = link.config.enabled();

    // The global per-AFI interface count drives the AFI's NLPID in the
    // Protocols Supported TLV (RFC 1195) of our self-originated LSP, so
    // keep it in step with each interface's enable. `link_afi_changed`
    // records whether THIS interface's participation actually flipped — it
    // gates the LSP re-origination below.
    let mut link_afi_changed = false;
    if op.is_set() && enable {
        // Set Enable.
        if !*link.config.enable.get(&afi) {
            *link.config.enable.get_mut(&afi) = true;
            *isis.config.enable.get_mut(&afi) += 1;
            link_afi_changed = true;
        }
    } else {
        // Set Disable.
        if *link.config.enable.get(&afi) {
            *link.config.enable.get_mut(&afi) = false;
            *isis.config.enable.get_mut(&afi) -= 1;
            link_afi_changed = true;
        }
    }

    if !enabled {
        if link.config.enabled() {
            // Disable -> Enable.
            let msg = Message::Ifsm(IfsmEvent::Start, link.ifindex, None);
            let _ = isis.tx.send(msg);
        }
    } else {
        if !link.config.enabled() {
            // Enable -> Disable.
            let msg = Message::Ifsm(IfsmEvent::Stop, link.ifindex, None);
            let _ = isis.tx.send(msg);
        }
    }

    // Re-originate the self-LSP whenever this interface's participation in
    // the AFI flips. The prefixes carried in the IP / IPv6 Reachability
    // TLVs depend on which interfaces have the AFI enabled (and, on a
    // 0<->non-zero *global* transition, so does the Protocols Supported /
    // NLPID TLV). Gating only on the global transition missed the common
    // case — e.g. `set router isis interface lo ipv6 enabled true` while
    // another interface already carries IPv6 — leaving the loopback's IPv6
    // prefix out of the LSP until the next periodic refresh. The per-level
    // guard skips a level whose self-LSP hasn't been originated yet (e.g.
    // L1 on a level-2-only instance, or before the first origination);
    // at runtime the relevant level always exists.
    if link_afi_changed {
        let key = IsisLspId::new(isis.config.net.sys_id(), 0, 0);
        if isis.lsdb.get(&Level::L1).get(&key).is_some() {
            isis_event_trace!(
                isis.tracing,
                LspOriginate,
                &Level::L1,
                "LSP Originate L1 due to interface address-family change"
            );
            isis.tx
                .send(Message::LspOriginate(Level::L1, None))
                .unwrap();
        }
        if isis.lsdb.get(&Level::L2).get(&key).is_some() {
            isis_event_trace!(
                isis.tracing,
                LspOriginate,
                &Level::L2,
                "LSP Originate L2 due to interface address-family change"
            );
            isis.tx
                .send(Message::LspOriginate(Level::L2, None))
                .unwrap();
        }
    }

    Some(())
}

pub fn config_ipv4_enable(isis: &mut Isis, args: Args, op: ConfigOp) -> Option<()> {
    config_afi_enable(isis, args, op, Afi::Ip)
}

// Per-MT, per-link metric override. The path arrives with three
// values from libyang dispatch: outer interface key (`if-name`), inner
// list key (MT id keyword), then the leaf value (`metric`). The MT
// IS Reach emitter (TLV 222) consumes this.
pub fn config_mt_metric(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    use std::str::FromStr;

    let ifname = args.string()?;
    let id_str = args.string()?;
    let id = MtId::from_str(&id_str).ok()?;

    let link = isis.links.get_mut_by_name(&ifname)?;
    if op.is_set() {
        let metric = args.u32()?;
        link.config.mt_metrics.insert(id, metric);
    } else {
        link.config.mt_metrics.remove(&id);
    }
    Some(())
}

// Per-link SRLG membership. The path arrives with two values from
// libyang dispatch: outer interface key (`if-name`) and the leaf-list
// value (SRLG group name). One call per value — when an operator sets
// multiple names in a single commit, libyang fires this callback once
// per name. Empty cache after delete (handled by the config layer's
// leaf-list cascade) leaves the BTreeSet empty.
pub fn config_srlg(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let ifname = args.string()?;
    let name = args.string()?;

    let link = isis.links.get_mut_by_name(&ifname)?;
    if op.is_set() {
        link.config.srlg_groups.insert(name);
    } else {
        link.config.srlg_groups.remove(&name);
    }
    // Re-originate both levels so the SRLG sub-TLV changes propagate
    // to peers without waiting for the refresh timer. The level guard
    // inside `process_lsp_originate` skips the wrong level on
    // single-level instances.
    let _ = isis.tx.send(Message::LspOriginate(Level::L1, None));
    let _ = isis.tx.send(Message::LspOriginate(Level::L2, None));
    Some(())
}

// `/router/isis/interface/<ifname>/affinity` — one call per affinity
// name in the leaf-list. Storage-only; the LSP emit follow-up will
// resolve names against `Isis::affinity_map` to build the 256-bit
// Extended Admin Group bitmap (RFC 7308) inside ASLA (RFC 9479).
pub fn config_affinity(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let ifname = args.string()?;
    let link = isis.links.get_mut_by_name(&ifname)?;
    // `affinity` is a leaf-list: every color arrives in one args deque,
    // so drain it rather than reading only the first.
    while let Some(name) = args.string() {
        if op.is_set() {
            link.config.affinity.insert(name);
        } else {
            link.config.affinity.remove(&name);
        }
    }
    Some(())
}

// Per-link RFC 8570 TE metrics, from
// /router/isis/interface/<ifname>/te-metric/<leaf>. libyang passes the
// interface key then the leaf value; the value is present on delete too,
// so the field is cleared based on `op`. Each setter re-originates both
// levels (the level guard inside `process_lsp_originate` drops the wrong
// level on single-level instances) so the sub-TLV change reaches peers
// without waiting for the refresh timer.
fn config_te_metric(
    isis: &mut Isis,
    mut args: Args,
    op: ConfigOp,
    set: impl FnOnce(&mut LinkTeMetric, Option<u32>),
) -> Option<()> {
    let ifname = args.string()?;
    let value = args.u32()?;
    let link = isis.links.get_mut_by_name(&ifname)?;
    set(&mut link.config.te_metric, op.is_set().then_some(value));
    let _ = isis.tx.send(Message::LspOriginate(Level::L1, None));
    let _ = isis.tx.send(Message::LspOriginate(Level::L2, None));
    Some(())
}

pub fn config_te_unidirectional_delay(isis: &mut Isis, args: Args, op: ConfigOp) -> Option<()> {
    config_te_metric(isis, args, op, |t, v| t.unidirectional_delay = v)
}

pub fn config_te_min_delay(isis: &mut Isis, args: Args, op: ConfigOp) -> Option<()> {
    config_te_metric(isis, args, op, |t, v| t.min_delay = v)
}

pub fn config_te_max_delay(isis: &mut Isis, args: Args, op: ConfigOp) -> Option<()> {
    config_te_metric(isis, args, op, |t, v| t.max_delay = v)
}

pub fn config_te_delay_variation(isis: &mut Isis, args: Args, op: ConfigOp) -> Option<()> {
    config_te_metric(isis, args, op, |t, v| t.delay_variation = v)
}

pub fn config_te_loss(isis: &mut Isis, args: Args, op: ConfigOp) -> Option<()> {
    config_te_metric(isis, args, op, |t, v| t.loss = v)
}

// `/router/isis/interface/<ifname>/te-metric/measurement/*` — the
// STAMP measurement block. Callbacks only mutate the config mirror;
// the session itself is reconciled by `Isis::stamp_reconcile_all` on
// `ConfigOp::CommitEnd` (one robust hook covers enable flips, interval
// changes, and every other config path that can affect a session —
// network-type, afi enable, ...). The disable path's measured-value
// clear + re-origination also lives in the reconcile.
fn config_te_measurement(
    isis: &mut Isis,
    mut args: Args,
    set: impl FnOnce(&mut crate::stamp::session::MeasurementConfig, &mut Args) -> Option<()>,
) -> Option<()> {
    let ifname = args.string()?;
    let link = isis.links.get_mut_by_name(&ifname)?;
    set(&mut link.config.te_metric_measurement, &mut args)
}

pub fn config_te_measurement_enable(isis: &mut Isis, args: Args, op: ConfigOp) -> Option<()> {
    config_te_measurement(isis, args, |m, args| {
        let value = args.boolean()?;
        m.enable = op.is_set().then_some(value);
        Some(())
    })
}

pub fn config_te_measurement_interval(isis: &mut Isis, args: Args, op: ConfigOp) -> Option<()> {
    config_te_measurement(isis, args, |m, args| {
        let value = args.u32()?;
        m.interval_ms = op.is_set().then_some(value);
        Some(())
    })
}

pub fn config_te_measurement_damping_period(
    isis: &mut Isis,
    args: Args,
    op: ConfigOp,
) -> Option<()> {
    config_te_measurement(isis, args, |m, args| {
        let value = args.u32()?;
        m.damping_period_secs = op.is_set().then_some(value);
        Some(())
    })
}

pub fn config_metric(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let ifname = args.string()?;
    let metric = args.u32()?;

    let link = isis.links.get_mut_by_name(&ifname)?;
    if op.is_set() {
        link.config.metric = Some(metric);
    } else {
        link.config.metric = None;
    }
    // Originate L1 LSP when it is .
    let key = IsisLspId::new(isis.config.net.sys_id(), 0, 0);
    if isis.lsdb.get(&Level::L1).get(&key).is_some() {
        isis_event_trace!(
            isis.tracing,
            LspOriginate,
            &Level::L1,
            "LSP Originate L1 due to metric change"
        );
        isis.tx
            .send(Message::LspOriginate(Level::L1, None))
            .unwrap();
    }

    // Originate L2 LSP.
    if isis.lsdb.get(&Level::L2).get(&key).is_some() {
        isis_event_trace!(
            isis.tracing,
            LspOriginate,
            &Level::L2,
            "LSP Originate L2 due to metric change"
        );
        isis.tx
            .send(Message::LspOriginate(Level::L2, None))
            .unwrap();
    }

    Some(())
}

pub fn config_ipv6_enable(isis: &mut Isis, args: Args, op: ConfigOp) -> Option<()> {
    config_afi_enable(isis, args, op, Afi::Ip6)
}

pub fn config_ipv4_prefix_sid_index(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let index = args.u32()?;

    let link = isis.links.get_mut_by_name(&name)?;

    if op.is_set() {
        link.config.prefix_sid = Some(SidLabelValue::Index(index));
    } else {
        link.config.prefix_sid = None;
    }

    Some(())
}

/// `/router/isis/interface/<ifname>/ipv4/prefix-sid/no-php` (type empty).
/// Toggles the RFC 8667 P (no-PHP) flag on the loopback Prefix-SID. The
/// flag lives in the Prefix-SID sub-TLV of the self-LSP, so re-originate
/// both levels on change to push it to the wire without waiting for the
/// refresh timer.
pub fn config_ipv4_prefix_sid_no_php(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let link = isis.links.get_mut_by_name(&name)?;
    link.config.prefix_sid_no_php = op.is_set();
    let _ = isis.tx.send(Message::LspOriginate(Level::L1, None));
    let _ = isis.tx.send(Message::LspOriginate(Level::L2, None));
    Some(())
}

// `/router/isis/interface/<ifname>/ipv4/flex-algo-prefix-sid[algo=N]`
// list root. libyang fires Set on entry creation (no value yet) and
// Delete when the entire algo entry is removed.
pub fn config_ipv4_flex_algo_prefix_sid(
    isis: &mut Isis,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let ifname = args.string()?;
    let algo = args.u8()?;
    if !(128..=255).contains(&algo) {
        return None;
    }
    let link = isis.links.get_mut_by_name(&ifname)?;
    if !op.is_set() {
        link.config.ipv4_flex_algo_prefix_sids.remove(&algo);
    }
    Some(())
}

// `.../flex-algo-prefix-sid[algo=N]/index` — per-algo index-form SID
// for this link's IPv4 address(es), advertised as an additional
// Prefix-SID sub-TLV with Algorithm=N (RFC 9350 §7).
pub fn config_ipv4_flex_algo_prefix_sid_index(
    isis: &mut Isis,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let ifname = args.string()?;
    let algo = args.u8()?;
    if !(128..=255).contains(&algo) {
        return None;
    }
    let index = args.u32()?;
    let link = isis.links.get_mut_by_name(&ifname)?;
    if op.is_set() {
        link.config
            .ipv4_flex_algo_prefix_sids
            .insert(algo, SidLabelValue::Index(index));
    } else {
        link.config.ipv4_flex_algo_prefix_sids.remove(&algo);
    }
    Some(())
}

pub fn config_level_common(inst: IsLevel, link: IsLevel) -> IsLevel {
    use IsLevel::*;
    match inst {
        L1L2 => link,
        L1 => L1,
        L2 => L2,
    }
}

pub fn config_circuit_type(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let circuit_type = args.string()?.parse::<IsLevel>().ok()?;

    let link = isis.links.get_mut_by_name(&name)?;

    if op.is_set() {
        link.config.circuit_type = Some(circuit_type);
    } else {
        link.config.circuit_type = None;
    }

    let is_level = config_level_common(isis.config.is_type(), link.config.circuit_type());
    link.state.level = is_level;

    Some(())
}

pub fn config_network_type(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let network_type = args.string()?.parse::<NetworkType>().ok()?;

    let (ifindex, type_changed) = {
        let link = isis.links.get_mut_by_name(&name)?;
        let old_type = link.config.network_type();

        if op.is_set() {
            link.config.network_type = Some(network_type);
        } else {
            link.config.network_type = None;
        }
        let new_type = link.config.network_type();
        (link.ifindex, old_type != new_type)
    };

    // A network-type change makes any existing adjacency stale.
    // ExtIsReach uses a different shape per type — P2P emits
    // (peer_sys_id, 0); LAN emits the pseudonode's (DIS_sys_id,
    // pseudo_id) — so the cached `link.state.adj` from the old type
    // would be wrong under the new one. dis_selection's branch at
    // ifsm.rs:507 only installs the LAN PN id when `adj.is_none()`,
    // so a stale P2P adj indefinitely blocks the LAN transition and
    // our LSP keeps advertising the P2P-style ExtIsReach. Bounce
    // the link via link_state_down + link_state_up — drops nbrs,
    // clears adj / dis_status / nbrs_up, re-originates LSP, and
    // schedules SPF for both levels. Adjacencies rebuild through
    // the normal hello / NFSM path under the new type.
    if type_changed {
        isis.link_state_down(ifindex);
        isis.link_state_up(ifindex);
        return Some(());
    }

    if let Some(mut top) = isis.link_top(ifindex) {
        ifsm::hello_originate(&mut top, Level::L1);
        ifsm::hello_originate(&mut top, Level::L2);
    }

    Some(())
}

/// `set router isis interface <name> passive <bool>` — toggle a passive
/// circuit. A passive interface keeps advertising its prefixes (the LSP
/// build gates on `enable.v4`/`enable.v6` + level, not on any adjacency)
/// but the Hello send/receive paths gate on `LinkTop::is_passive()`, so
/// no Hello flows and no adjacency forms.
///
/// Toggling bounces the link (`link_state_down` + `link_state_up`): that
/// drops any adjacency formed while the circuit was active — including
/// the spurious self-adjacency a non-passive loopback creates when its
/// own Hellos loop back — re-originates the self-LSP, and reschedules
/// SPF. Unsetting it lets the normal Start path re-arm Hellos and rebuild
/// adjacencies.
pub fn config_passive(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let passive = args.boolean()?;

    let (ifindex, changed) = {
        let link = isis.links.get_mut_by_name(&name)?;
        let old = link.config.passive;
        link.config.passive = op.is_set() && passive;
        (link.ifindex, old != link.config.passive)
    };

    if changed {
        isis.link_state_down(ifindex);
        isis.link_state_up(ifindex);
    }

    Some(())
}

pub fn config_hello_padding(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let hello_padding = args.string()?.parse::<HelloPaddingPolicy>().ok()?;
    let link = isis.links.get_mut_by_name(&name)?;

    if op.is_set() {
        link.config.hello_padding = Some(hello_padding);
    } else {
        link.config.hello_padding = None;
    }

    hello_reoriginate(link, &isis.tx);
    Some(())
}

pub fn config_hello_interval(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let interval = args.u16()?;
    let link = isis.links.get_mut_by_name(&name)?;

    if op.is_set() {
        link.config.hello_interval = Some(interval);
    } else {
        link.config.hello_interval = None;
    }

    hello_reoriginate(link, &isis.tx);
    Some(())
}

pub fn config_hello_multiplier(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let multiplier = args.u16()?;
    let link = isis.links.get_mut_by_name(&name)?;

    if op.is_set() {
        link.config.hello_multiplier = Some(multiplier);
    } else {
        link.config.hello_multiplier = None;
    }

    hello_reoriginate(link, &isis.tx);
    Some(())
}

// CSNP / PSNP interval changes take effect on the next timer cycle.
// CSNP runs only on the DIS; PSNP runs only while ack-pending LSPs exist;
// recreating those timers on the fly would mean cancelling whatever's
// currently armed, with little benefit over waiting one cycle.
pub fn config_csnp_interval(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let interval = args.u16()?;
    let link = isis.links.get_mut_by_name(&name)?;

    if op.is_set() {
        link.config.csnp_interval = Some(interval as u32);
    } else {
        link.config.csnp_interval = None;
    }
    Some(())
}

pub fn config_psnp_interval(isis: &mut Isis, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let interval = args.u16()?;
    let link = isis.links.get_mut_by_name(&name)?;

    if op.is_set() {
        link.config.psnp_interval = Some(interval as u32);
    } else {
        link.config.psnp_interval = None;
    }
    Some(())
}

// Push hello config changes live by re-originating on each active level.
// hello_originate both emits a hello PDU (so the new hold_time field hits
// the wire) and re-arms the periodic timer (so the new hello_interval
// takes effect without waiting for adjacency reset).
fn hello_reoriginate(link: &IsisLink, tx: &UnboundedSender<Message>) {
    if link.state.hello.l1.is_some() {
        let _ = tx.send(Message::Ifsm(
            IfsmEvent::HelloOriginate,
            link.ifindex,
            Some(Level::L1),
        ));
    }
    if link.state.hello.l2.is_some() {
        let _ = tx.send(Message::Ifsm(
            IfsmEvent::HelloOriginate,
            link.ifindex,
            Some(Level::L2),
        ));
    }
}

#[derive(Serialize)]
struct LinkInfo {
    name: String,
    ifindex: u32,
    is_up: bool,
    network_type: String,
    level: String,
    dis: String,
    adjacency: String,
}

// Pick the level whose DIS / adjacency state is displayed in the
// summary view. Mirrors the prior behaviour (L2 only when the circuit
// is L2-only; otherwise L1) so single-level operators see the level
// they actually run, and L1L2 collapses to the more-common L1 view —
// `show isis interface detail` is the place to see both levels.
fn summary_level(link: &IsisLink) -> Level {
    if link.state.level() == IsLevel::L2 {
        Level::L2
    } else {
        Level::L1
    }
}

// DIS column. Loopback gets N/A regardless of the configured
// network-type because the kernel device can't carry an adjacency.
// Non-LAN circuits also show N/A — DIS election only runs on LAN.
fn dis_column(link: &IsisLink, level: Level) -> &'static str {
    if link.flags.is_loopback() {
        return "N/A";
    }
    if link.config.network_type() != NetworkType::Lan {
        return "N/A";
    }
    match link.state.dis_status.get(&level) {
        DisStatus::Myself => "DIS",
        DisStatus::Other => "Other",
        DisStatus::NotSelected => "Selecting",
    }
}

// Adjacency column: the LAN ID (sys-id + circuit-id) once the
// pseudonode LSP has confirmed our adjacency. `link.state.adj` is
// cleared on link-down and on DIS reset, so "Down" here means we
// have no usable adjacency for this level.
fn adjacency_column(link: &IsisLink, level: Level) -> String {
    match link.state.adj.get(&level) {
        Some((adj, _)) => format!("Up {}", adj),
        None => "Down".to_string(),
    }
}

pub fn show(isis: &Isis, _args: Args, json: bool) -> std::result::Result<String, std::fmt::Error> {
    if json {
        let mut links = Vec::new();
        for (_ifindex, link) in isis.links.iter() {
            if link.config.enabled() {
                let level = summary_level(link);
                links.push(LinkInfo {
                    name: link.state.name.clone(),
                    ifindex: link.ifindex,
                    is_up: link.state.is_up(),
                    network_type: link.config.network_type().to_string(),
                    level: link.state.level.to_string(),
                    dis: dis_column(link, level).to_string(),
                    adjacency: adjacency_column(link, level),
                });
            }
        }
        return Ok(serde_json::to_string_pretty(&links).unwrap());
    }
    let mut buf = String::new();
    writeln!(
        buf,
        "  {:<11} {:<8} {:<8} {:<8} {:<5} {:<9} Adjacency",
        "Interface", "CircId", "State", "Type", "Level", "DIS",
    )?;
    for (_ifindex, link) in isis.links.iter() {
        if !link.config.enabled() {
            continue;
        }
        let level = summary_level(link);
        let link_state = if link.state.is_up() { "Up" } else { "Down" };
        let circ_id = format!("0x{:02X}", link.ifindex);
        writeln!(
            buf,
            "  {:<11} {:<8} {:<8} {:<8} {:<5} {:<9} {}",
            link.state.name,
            circ_id,
            link_state,
            link.config.network_type().to_string(),
            link.state.level.to_string(),
            dis_column(link, level),
            adjacency_column(link, level),
        )?;
    }
    Ok(buf)
}

// JSON structures for interface detail
#[derive(Serialize)]
struct InterfaceDetailJson {
    interface: String,
    state: String,
    active: bool,
    circuit_id: String,
    #[serde(rename = "type")]
    network_type: String,
    level: String,
    snpa: Option<String>,
    mtu: u32,
    lsp_mtu: u16,
    /// True when `lsp_mtu` exceeds the interface MTU — LSPs are then
    /// dropped on send for this interface (see flood::srm_advertise).
    lsp_mtu_exceeds_interface: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    level_1_info: Option<LevelInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    level_2_info: Option<LevelInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    authentication: Option<AuthInfo>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    ip_prefixes: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    ipv6_link_locals: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    ipv6_prefixes: Vec<String>,
}

#[derive(Serialize)]
struct LevelInfo {
    metric: u32,
    active_neighbors: u32,
    hello_interval: u64,
    holddown_count: u32,
    padding: String,
    csnp_interval: u64,
    psnp_interval: u64,
    lan_priority: u8,
    dis: String,
    adjacency: String,
}

/// Per-interface authentication snapshot for `show isis interface
/// detail`. Populated when hello-authentication is configured; left
/// off when the operator hasn't turned it on.
#[derive(Serialize)]
struct AuthInfo {
    mode: String,
    key_id: u16,
    send_only: bool,
    tx_signed: u64,
    rx_good: u64,
    rx_bad: u64,
    rx_no_auth: u64,
}

fn build_auth_info(link: &IsisLink) -> Option<AuthInfo> {
    let cfg = &link.config.hello_auth;
    let _ = cfg.password.as_deref()?;
    Some(AuthInfo {
        mode: cfg.auth_type.to_string(),
        key_id: cfg.effective_key_id(),
        send_only: cfg.send_only,
        tx_signed: link.state.auth_tx_signed,
        rx_good: link.state.auth_rx_good,
        rx_bad: link.state.auth_rx_bad,
        rx_no_auth: link.state.auth_rx_no_auth,
    })
}

/// Text renderer for the auth block. Returns "" when no auth is
/// configured so the caller can `write!` it unconditionally — the
/// auth section disappears for un-authed interfaces.
fn render_auth_block(link: &IsisLink) -> String {
    let Some(info) = build_auth_info(link) else {
        return String::new();
    };
    render_auth_block_from(&info)
}

/// Pure renderer split out so unit tests can pin the format without
/// having to construct a full `IsisLink` (which owns a raw socket).
fn render_auth_block_from(info: &AuthInfo) -> String {
    let mut buf = String::new();
    use std::fmt::Write;
    let _ = writeln!(buf, "  Hello Authentication:");
    let _ = writeln!(
        buf,
        "    Mode: {}, Key ID: {}, Send-only: {}",
        info.mode, info.key_id, info.send_only
    );
    let _ = writeln!(
        buf,
        "    Counters: tx-signed {}, rx-good {}, rx-bad {}, rx-no-auth {}",
        info.tx_signed, info.rx_good, info.rx_bad, info.rx_no_auth
    );
    buf
}

pub fn show_detail_entry(buf: &mut String, link: &IsisLink, level: Level) -> std::fmt::Result {
    writeln!(
        buf,
        "    Metric: {}, Active neighbors: {}",
        link.config.metric(),
        link.state.nbrs_up.get(&level)
    )?;
    let padding = if link.config.hello_padding() == HelloPaddingPolicy::Always {
        "yes"
    } else {
        "no"
    };
    writeln!(
        buf,
        "    Hello interval: {}, Holddown count: {}, Padding: {}",
        link.config.hello_interval(),
        link.config.holddown_count(),
        padding,
    )?;
    writeln!(
        buf,
        "    CNSP interval: {}, PSNP interval: {}",
        link.config.csnp_interval(),
        link.config.psnp_interval()
    )?;

    // DIS + Adjacency — same tokens as `show isis interface`.
    writeln!(
        buf,
        "    LAN priority: {}, DIS status: {}",
        link.config.priority(),
        dis_column(link, level),
    )?;
    writeln!(buf, "    Adjacency: {}", adjacency_column(link, level))?;

    // Hello.
    if let Some(hello) = link.state.hello.get(&level) {
        writeln!(buf, "    {}", hello)?;
    }
    Ok(())
}

fn build_level_info(link: &IsisLink, level: Level) -> LevelInfo {
    let padding = if link.config.hello_padding() == HelloPaddingPolicy::Always {
        "yes".to_string()
    } else {
        "no".to_string()
    };

    LevelInfo {
        metric: link.config.metric(),
        active_neighbors: *link.state.nbrs_up.get(&level),
        hello_interval: link.config.hello_interval(),
        holddown_count: link.config.holddown_count(),
        padding,
        csnp_interval: link.config.csnp_interval(),
        psnp_interval: link.config.psnp_interval(),
        lan_priority: link.config.priority(),
        dis: dis_column(link, level).to_string(),
        adjacency: adjacency_column(link, level),
    }
}

pub fn show_detail(
    isis: &Isis,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    if json {
        // JSON output
        let mut interfaces = Vec::new();

        for (_ifindex, link) in isis.links.iter() {
            if link.config.enabled() {
                let mut interface_detail = InterfaceDetailJson {
                    interface: link.state.name.clone(),
                    state: if link.state.is_up() {
                        "Up".to_string()
                    } else {
                        "Down".to_string()
                    },
                    active: true,
                    circuit_id: format!("0x{:02X}", link.ifindex),
                    network_type: format!("{}", link.config.network_type()),
                    level: format!("{}", link.state.level()),
                    snpa: link.state.mac.map(|mac| mac.to_string()),
                    mtu: link.state.mtu,
                    lsp_mtu: isis.config.lsp_mtu(),
                    lsp_mtu_exceeds_interface: isis.config.lsp_mtu() as u32 > link.state.mtu,
                    level_1_info: None,
                    level_2_info: None,
                    authentication: build_auth_info(link),
                    ip_prefixes: link.state.v4addr.iter().map(|p| p.to_string()).collect(),
                    ipv6_link_locals: link.state.v6laddr.iter().map(|p| p.to_string()).collect(),
                    ipv6_prefixes: link.state.v6addr.iter().map(|p| p.to_string()).collect(),
                };

                if has_level(link.state.level(), Level::L1) {
                    interface_detail.level_1_info = Some(build_level_info(link, Level::L1));
                }
                if has_level(link.state.level(), Level::L2) {
                    interface_detail.level_2_info = Some(build_level_info(link, Level::L2));
                }

                interfaces.push(interface_detail);
            }
        }

        Ok(
            serde_json::to_string_pretty(&interfaces).unwrap_or_else(|e| {
                format!("{{\"error\": \"Failed to serialize interfaces: {}\"}}", e)
            }),
        )
    } else {
        // Text output (existing implementation)
        let mut buf = String::new();
        for (_ifindex, link) in isis.links.iter() {
            if link.config.enabled() {
                let link_state = if link.state.is_up() { "Up" } else { "Down" };
                writeln!(
                    buf,
                    "Interface: {}, State: {}, Active, Circuit Id: 0x{:02X}",
                    link.state.name, link_state, link.ifindex
                )?;
                writeln!(
                    buf,
                    "  Type: {}, Level: {}, SNPA: {}, MTU: {}",
                    link.config.network_type(),
                    link.state.level(),
                    link.state.mac.unwrap_or(MacAddr::from([0, 0, 0, 0, 0, 0])),
                    link.state.mtu,
                )?;
                // LSP MTU vs interface MTU. When lsp-mtu exceeds the
                // interface MTU, LSPs are dropped on send (see
                // flood::srm_advertise), so flag it here.
                let lsp_mtu = isis.config.lsp_mtu();
                if lsp_mtu as u32 > link.state.mtu {
                    writeln!(
                        buf,
                        "  LSP MTU: {} (exceeds interface MTU {} - LSPs dropped on send)",
                        lsp_mtu, link.state.mtu,
                    )?;
                } else {
                    writeln!(buf, "  LSP MTU: {}", lsp_mtu)?;
                }
                if has_level(link.state.level(), Level::L1) {
                    writeln!(buf, "  Level-1 Information:")?;
                    show_detail_entry(&mut buf, link, Level::L1)?;
                }
                if has_level(link.state.level(), Level::L2) {
                    writeln!(buf, "  Level-2 Information:")?;
                    show_detail_entry(&mut buf, link, Level::L2)?;
                }
                // Hello authentication block. Empty string when no
                // auth is configured so the block disappears
                // cleanly.
                buf.push_str(&render_auth_block(link));
                // IPv4 Address.
                if !link.state.v4addr.is_empty() {
                    writeln!(buf, "  IP Prefix(es):")?;
                    for prefix in link.state.v4addr.iter() {
                        writeln!(buf, "    {}", prefix)?;
                    }
                }
                if !link.state.v6laddr.is_empty() {
                    writeln!(buf, "  IPv6 Link-Locals:")?;
                    for prefix in link.state.v6laddr.iter() {
                        writeln!(buf, "    {}", prefix)?;
                    }
                }
                if !link.state.v6addr.is_empty() {
                    writeln!(buf, "  IPv6 Prefix(es):")?;
                    for prefix in link.state.v6addr.iter() {
                        writeln!(buf, "    {}", prefix)?;
                    }
                }
                writeln!(buf)?;
            }
        }
        Ok(buf)
    }
}

use std::fmt::{Display, Formatter, Result};
use std::str::FromStr;

#[derive(Default, Debug, PartialEq, Clone, Copy)]
pub enum HelloPaddingPolicy {
    #[default]
    Always,
    Disable,
}

#[derive(Debug)]
pub struct ParseHelloPaddingPolicyError;

impl Display for ParseHelloPaddingPolicyError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "invalid input for Hello Padding Policy")
    }
}

impl FromStr for HelloPaddingPolicy {
    type Err = ParseHelloPaddingPolicyError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "always" => Ok(HelloPaddingPolicy::Always),
            "disable" => Ok(HelloPaddingPolicy::Disable),
            _ => Err(ParseHelloPaddingPolicyError),
        }
    }
}

fn format_duration(duration: std::time::Duration) -> String {
    let secs = duration.as_secs();
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m{}s", secs / 60, secs % 60)
    } else {
        format!("{}h{}m{}s", secs / 3600, (secs % 3600) / 60, secs % 60)
    }
}

fn format_time_ago(timestamp: std::time::SystemTime) -> String {
    match timestamp.elapsed() {
        Ok(duration) => format!("{} ago", format_duration(duration)),
        Err(_) => "in the future".to_string(),
    }
}

pub fn show_dis_statistics(
    isis: &Isis,
    _args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    use serde::Serialize;

    #[derive(Serialize)]
    struct DisStatisticsInfo {
        interface: String,
        level: u8,
        current_status: String,
        current_dis: String,
        flap_count: u32,
        uptime: Option<String>,
        last_change: Option<String>,
        history_count: usize,
    }

    if json {
        let mut stats = Vec::new();
        for (_, link) in isis.links.iter() {
            if link.config.enabled() {
                for level in [Level::L1, Level::L2] {
                    if super::ifsm::has_level(link.state.level(), level) {
                        let dis_stats = link.state.dis_stats.get(&level);
                        let current_dis = match link.state.dis_status.get(&level) {
                            DisStatus::Myself => "Self".to_string(),
                            DisStatus::Other => {
                                if let Some((sys_id, _)) = link.state.adj.get(&level) {
                                    sys_id.to_string()
                                } else {
                                    "Unknown".to_string()
                                }
                            }
                            DisStatus::NotSelected => "None".to_string(),
                        };

                        stats.push(DisStatisticsInfo {
                            interface: link.state.name.clone(),
                            level: level.digit(),
                            current_status: format!("{:?}", link.state.dis_status.get(&level)),
                            current_dis,
                            flap_count: dis_stats.flap_count,
                            uptime: dis_stats.uptime.map(format_time_ago),
                            last_change: dis_stats.last_change.map(format_time_ago),
                            history_count: dis_stats.history.len(),
                        });
                    }
                }
            }
        }
        return Ok(serde_json::to_string_pretty(&stats).unwrap());
    }

    let mut buf = String::new();
    writeln!(buf, "DIS Statistics:").unwrap();
    writeln!(
        buf,
        "Interface        Level  Status      DIS              Flaps  Uptime     Last Change"
    )
    .unwrap();
    writeln!(
        buf,
        "---------------- ------ ----------- ---------------- ------ ---------- -----------"
    )
    .unwrap();

    for (_, link) in isis.links.iter() {
        if link.config.enabled() {
            for level in [Level::L1, Level::L2] {
                if super::ifsm::has_level(link.state.level(), level) {
                    let dis_stats = link.state.dis_stats.get(&level);
                    let status = match link.state.dis_status.get(&level) {
                        DisStatus::Myself => "Myself",
                        DisStatus::Other => "Other",
                        DisStatus::NotSelected => "None",
                    };
                    let current_dis = match link.state.dis_status.get(&level) {
                        DisStatus::Myself => "Self".to_string(),
                        DisStatus::Other => {
                            if let Some((sys_id, _)) = link.state.adj.get(&level) {
                                sys_id.to_string()
                            } else {
                                "Unknown".to_string()
                            }
                        }
                        DisStatus::NotSelected => "-".to_string(),
                    };

                    let uptime = if let Some(uptime) = dis_stats.uptime {
                        format_time_ago(uptime)
                    } else {
                        "-".to_string()
                    };

                    let last_change = if let Some(last) = dis_stats.last_change {
                        format_time_ago(last)
                    } else {
                        "-".to_string()
                    };

                    writeln!(
                        buf,
                        "{:<16} {:<6} {:<11} {:<16} {:<6} {:<10} {}",
                        link.state.name,
                        level.digit(),
                        status,
                        current_dis,
                        dis_stats.flap_count,
                        uptime,
                        last_change
                    )
                    .unwrap();
                }
            }
        }
    }

    Ok(buf)
}

pub fn show_dis_history(
    isis: &Isis,
    mut args: Args,
    json: bool,
) -> std::result::Result<String, std::fmt::Error> {
    use serde::Serialize;

    #[derive(Serialize)]
    struct DisHistoryEntry {
        interface: String,
        level: u8,
        timestamp: String,
        from_status: String,
        to_status: String,
        from_sys_id: Option<String>,
        to_sys_id: Option<String>,
        reason: String,
    }

    let interface_filter = args.string();

    if json {
        let mut history = Vec::new();
        for (_, link) in isis.links.iter() {
            if link.config.enabled() {
                if let Some(ref filter) = interface_filter
                    && link.state.name != *filter
                {
                    continue;
                }

                for level in [Level::L1, Level::L2] {
                    if super::ifsm::has_level(link.state.level(), level) {
                        let dis_stats = link.state.dis_stats.get(&level);
                        for change in &dis_stats.history {
                            history.push(DisHistoryEntry {
                                interface: link.state.name.clone(),
                                level: level.digit(),
                                timestamp: format_time_ago(change.timestamp),
                                from_status: format!("{:?}", change.from_status),
                                to_status: format!("{:?}", change.to_status),
                                from_sys_id: change.from_sys_id.as_ref().map(|s| s.to_string()),
                                to_sys_id: change.to_sys_id.as_ref().map(|s| s.to_string()),
                                reason: change.reason.clone(),
                            });
                        }
                    }
                }
            }
        }
        return Ok(serde_json::to_string_pretty(&history).unwrap());
    }

    let mut buf = String::new();
    writeln!(buf, "DIS Change History:").unwrap();
    writeln!(
        buf,
        "Interface        Level  Time                From        To          Reason"
    )?;
    writeln!(
        buf,
        "---------------- ------ ------------------- ----------- ----------- ------"
    )?;

    for (_, link) in isis.links.iter() {
        if link.config.enabled() {
            if let Some(ref filter) = interface_filter
                && link.state.name != *filter
            {
                continue;
            }

            for level in [Level::L1, Level::L2] {
                if super::ifsm::has_level(link.state.level(), level) {
                    let dis_stats = link.state.dis_stats.get(&level);
                    for change in &dis_stats.history {
                        let from_status = match change.from_status {
                            DisStatus::Myself => "Myself",
                            DisStatus::Other => "Other",
                            DisStatus::NotSelected => "None",
                        };
                        let to_status = match change.to_status {
                            DisStatus::Myself => "Myself",
                            DisStatus::Other => "Other",
                            DisStatus::NotSelected => "None",
                        };

                        writeln!(
                            buf,
                            "{:<16} {:<6} {:<19} {:<11} {:<11} {}",
                            link.state.name,
                            level.digit(),
                            format_time_ago(change.timestamp),
                            from_status,
                            to_status,
                            change.reason
                        )
                        .unwrap();
                    }
                }
            }
        }
    }

    Ok(buf)
}

#[cfg(test)]
mod auth_show_tests {
    use super::*;

    /// `show isis interface detail` auth block format. Locks the
    /// text shape so a future refactor that breaks the layout
    /// trips this test before the BDD/scripting suite notices.
    #[test]
    fn render_auth_block_format() {
        let info = AuthInfo {
            mode: "hmac-sha-256".to_string(),
            key_id: 42,
            send_only: false,
            tx_signed: 17,
            rx_good: 16,
            rx_bad: 1,
            rx_no_auth: 0,
        };
        let out = render_auth_block_from(&info);
        let expected = "  Hello Authentication:\n    Mode: hmac-sha-256, Key ID: 42, Send-only: false\n    Counters: tx-signed 17, rx-good 16, rx-bad 1, rx-no-auth 0\n";
        assert_eq!(out, expected);
    }

    /// Send-only is the rollover hatch — make sure it surfaces
    /// truthfully so operators can confirm one-sided auth is on.
    #[test]
    fn render_auth_block_send_only_visible() {
        let info = AuthInfo {
            mode: "md5".to_string(),
            key_id: 1,
            send_only: true,
            tx_signed: 0,
            rx_good: 0,
            rx_bad: 0,
            rx_no_auth: 0,
        };
        let out = render_auth_block_from(&info);
        assert!(out.contains("Send-only: true"));
    }
}

#[cfg(test)]
mod bfd_config_tests {
    use super::*;

    /// LinkBfdConfig default mirrors the YANG defaults (all unset ⇒
    /// inherit; off if unset everywhere).
    #[test]
    fn default_bfd_is_disabled() {
        let bfd = LinkBfdConfig::default();
        assert!(bfd.enable.is_none());
        assert!(!bfd.resolve(&LinkBfdConfig::default()).enable);

        // Lives on LinkConfig with the same default.
        let lc = LinkConfig::default();
        assert_eq!(lc.bfd, bfd);
    }

    /// Round-trip: setting enable + echo-mode mirrors the CLI flow
    /// (`bfd enabled true; bfd echo-mode both`) producing the state
    /// the adjacency-FSM subscribe path reads.
    #[test]
    fn enable_round_trip() {
        let mut lc = LinkConfig::default();
        lc.bfd.enable = Some(true);
        lc.bfd.echo_mode = Some(EchoMode::Both);

        assert_eq!(
            lc.bfd,
            LinkBfdConfig {
                enable: Some(true),
                echo_mode: Some(EchoMode::Both),
                ..LinkBfdConfig::default()
            },
        );
    }

    /// Per-interface BFD leaves override the instance default; unset inherit.
    #[test]
    fn bfd_resolve_merges_per_leaf() {
        let default = LinkBfdConfig {
            enable: Some(true), // blanket
            echo_mode: Some(EchoMode::Receive),
            echo_transmit_ms: Some(100),
            detect_offload: Some(true),
            ..LinkBfdConfig::default()
        };
        // Interface sets nothing → inherits.
        let inherit = LinkBfdConfig::default().resolve(&default);
        assert!(inherit.enable);
        assert_eq!(inherit.echo_mode, Some(EchoMode::Receive));
        assert_eq!(inherit.echo_transmit_ms, 100);
        assert_eq!(inherit.echo_receive_ms, DEFAULT_ECHO_INTERVAL_MS);
        assert!(inherit.detect_offload, "inherits the instance default");
        // Interface overrides: opt out + change role + keep detection local.
        let over = LinkBfdConfig {
            enable: Some(false),
            echo_mode: Some(EchoMode::Both),
            detect_offload: Some(false),
            ..LinkBfdConfig::default()
        };
        let eff = over.resolve(&default);
        assert!(!eff.enable);
        assert_eq!(eff.echo_mode, Some(EchoMode::Both));
        assert_eq!(eff.echo_transmit_ms, 100); // still inherits
        assert!(!eff.detect_offload, "per-interface override wins");
        // Unset everywhere → hard default off (userspace detection).
        let bare = LinkBfdConfig::default().resolve(&LinkBfdConfig::default());
        assert!(!bare.detect_offload);
    }
}

#[cfg(test)]
mod te_metric_tests {
    use super::*;

    /// All five metrics configured → four RFC 8570 sub-TLVs emitted in
    /// ascending code order (33, 34, 35, 36), Anomalous clear on
    /// statically configured values.
    #[test]
    fn sub_tlvs_emits_all_in_code_order() {
        let te = LinkTeMetric {
            unidirectional_delay: Some(1000),
            min_delay: Some(900),
            max_delay: Some(1200),
            delay_variation: Some(50),
            loss: Some(333),
        };
        let subs = te.sub_tlvs();
        assert_eq!(subs.len(), 4);
        assert!(matches!(
            subs[0],
            NeighSubTlv::UniLinkDelay(IsisSubUniLinkDelay {
                anomalous: false,
                delay: 1000,
            })
        ));
        assert!(matches!(
            subs[1],
            NeighSubTlv::MinMaxLinkDelay(IsisSubMinMaxLinkDelay {
                anomalous: false,
                min_delay: 900,
                max_delay: 1200,
            })
        ));
        assert!(matches!(
            subs[2],
            NeighSubTlv::DelayVariation(IsisSubDelayVariation { variation: 50 })
        ));
        assert!(matches!(
            subs[3],
            NeighSubTlv::LinkLoss(IsisSubLinkLoss {
                anomalous: false,
                loss: 333,
            })
        ));
    }

    /// Min/Max delay (sub-TLV 34) needs both bounds — a lone min-delay
    /// emits nothing, both together emit one sub-TLV.
    #[test]
    fn min_max_requires_both_bounds() {
        let only_min = LinkTeMetric {
            min_delay: Some(900),
            ..Default::default()
        };
        assert!(only_min.sub_tlvs().is_empty());

        let both = LinkTeMetric {
            min_delay: Some(900),
            max_delay: Some(1200),
            ..Default::default()
        };
        assert_eq!(both.sub_tlvs().len(), 1);
    }

    /// No TE metric configured → no sub-TLVs, and the default lives on
    /// LinkConfig.
    #[test]
    fn default_is_empty() {
        assert!(LinkTeMetric::default().sub_tlvs().is_empty());
        assert_eq!(LinkConfig::default().te_metric, LinkTeMetric::default());
    }

    /// `merged_over` (the [`IsisLink::te_metric_effective`] core):
    /// static config wins per field, measured fills the gaps, and a
    /// cleared measurement leaves only the static fields.
    #[test]
    fn merged_over_static_wins_measured_fills() {
        let config = LinkTeMetric {
            min_delay: Some(500), // operator override
            loss: Some(3),
            ..Default::default()
        };
        let measured = LinkTeMetric {
            unidirectional_delay: Some(120),
            min_delay: Some(100),
            max_delay: Some(150),
            delay_variation: Some(10),
            loss: None,
        };
        let effective = config.merged_over(&measured);
        assert_eq!(effective.min_delay, Some(500), "config wins");
        assert_eq!(effective.unidirectional_delay, Some(120), "measured fills");
        assert_eq!(effective.max_delay, Some(150));
        assert_eq!(effective.delay_variation, Some(10));
        assert_eq!(effective.loss, Some(3));

        // Measurement cleared (D8): only static fields remain.
        let effective = config.merged_over(&LinkTeMetric::default());
        assert_eq!(
            effective,
            LinkTeMetric {
                min_delay: Some(500),
                loss: Some(3),
                ..Default::default()
            }
        );
    }
}
