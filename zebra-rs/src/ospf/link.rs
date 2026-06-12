use std::fmt::Display;
use std::str::FromStr;
use std::sync::Arc;
use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv4Addr,
};

use bitfield_struct::bitfield;
use netlink_packet_route::link::LinkFlags;
use ospf_packet::{
    OspfAslaSubSubTlv, OspfSubDelayVariation, OspfSubLinkLoss, OspfSubMinMaxLinkDelay,
    OspfSubUniLinkDelay,
};
use socket2::Socket;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::UnboundedSender;

use crate::bfd::session::EchoMode;
use crate::rib::Link;

use super::addr::OspfAddr;
use super::version::{OspfVersion, Ospfv2};
use super::{Identity, IfsmState, Message, Neighbor, NfsmState};
use crate::context::Timer;

pub const OSPF_DEFAULT_PRIORITY: u8 = 64;
pub const OSPF_DEFAULT_HELLO_INTERVAL: u16 = 10;
pub const OSPF_DEFAULT_DEAD_INTERVAL: u32 = 40;
pub const OSPF_DEFAULT_RETRANSMIT_INTERVAL: u16 = 5;
pub const OSPF_DEFAULT_TRANSMIT_DELAY: u16 = 1;
pub const OSPF_DEFAULT_OUTPUT_COST: u32 = 10;

#[derive(Debug, Default, PartialEq, Clone, Copy)]
pub enum OspfNetworkType {
    #[default]
    Broadcast,
    NBMA,
    PointToPoint,
}

impl Display for OspfNetworkType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OspfNetworkType::Broadcast => write!(f, "BROADCAST"),
            OspfNetworkType::NBMA => write!(f, "NBMA"),
            OspfNetworkType::PointToPoint => write!(f, "POINT-TO-POINT"),
        }
    }
}

impl FromStr for OspfNetworkType {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // YANG enum names (kebab-case) only; uppercase Display forms
        // are output-only and not accepted back.
        match s {
            "broadcast" => Ok(Self::Broadcast),
            "nbma" => Ok(Self::NBMA),
            "point-to-point" => Ok(Self::PointToPoint),
            _ => Err(()),
        }
    }
}

#[bitfield(u8, debug = true)]
pub struct OspfMulticastMembership {
    pub all_routers: bool,
    pub all_drouters: bool,
    #[bits(6)]
    pub resvd: usize,
}

#[derive(Default)]
pub struct LinkConfig {
    pub enable: bool,
    pub area: Option<Ipv4Addr>,
    pub priority: Option<u8>,
    pub hello_interval: Option<u16>,
    pub dead_interval: Option<u32>,
    pub retransmit_interval: Option<u16>,
    pub transmit_delay: Option<u16>,
    pub mtu_ignore: bool,
    pub prefix_sid: Option<PrefixSid>,
    /// Per-Flexible-Algorithm Prefix-SIDs for this interface's prefix
    /// (RFC 9350 §7), keyed by algo id (128..=255). Emitted as extra
    /// Prefix-SID sub-TLVs (Algorithm = FlexAlgo(N)) in the
    /// Extended-Prefix Opaque LSA alongside the algo-0 `prefix_sid`.
    pub flex_algo_prefix_sids: BTreeMap<u8, PrefixSid>,
    pub adjacency_sid: Option<AdjacencySid>,
    pub network_type: Option<OspfNetworkType>,
    /// RFC 2328 §D authentication mode. `None` = inherit (Null
    /// today, until area/instance defaults land); `Some(Null)` is
    /// an explicit override.
    pub auth_mode: Option<OspfAuthMode>,
    /// Simple-password key, already zero-padded to the 8-octet
    /// on-wire field. Only consulted when `auth_mode == Simple`.
    pub auth_key: Option<[u8; 8]>,
    /// Cryptographic-auth keys keyed by key-id (RFC 2328 §D.4
    /// for keyed-MD5, RFC 5709 for HMAC-SHA). Each entry carries
    /// the algorithm and the raw secret. Only consulted when
    /// `auth_mode == MessageDigest` AND `key_chain` is unset.
    /// Populated by either the `message-digest-key` callback
    /// (MD5 entries) or the `crypto-key` callback (HMAC-SHA
    /// entries) — the two paths share this single keyring and
    /// using the same key-id from both is a config error.
    pub crypto_keys: BTreeMap<u8, AuthKey>,
    /// RFC 8177 key-chain name (see `/key-chains` callbacks).
    /// When set and `auth_mode == MessageDigest`, the chain
    /// supersedes `crypto_keys` for both send-side selection
    /// (`KeyChain::active_send_key(now)`) and receive-side
    /// validation (`KeyChain::lookup_recv_key(key_id, now)`).
    pub key_chain: Option<String>,
    /// Names of `/affinity-map` entries this link carries. Resolved to
    /// an Extended Admin Group bitmap (RFC 7308) and advertised in the
    /// link's ASLA sub-TLV (RFC 9492) by flex-algo origination, and
    /// tested against each FAD's include/exclude constraints at
    /// per-algo SPF time. Mirrors `isis::LinkConfig::affinity`.
    pub affinity: BTreeSet<String>,
    /// Static RFC 7471 TE link metrics (delay/jitter/loss) advertised in
    /// this link's ASLA sub-TLV on the Extended-Link Opaque LSA. Mirrors
    /// `isis::LinkConfig::te_metric`; a future TWAMP/STAMP task will
    /// populate these dynamically.
    pub te_metric: LinkTeMetric,
    /// Per-interface BFD attachment (zebra-ospf-bfd.yang).
    pub bfd: OspfLinkBfdConfig,
}

/// Per-interface RFC 7471 TE link metrics. All delay values are in
/// microseconds; `loss` is the raw 24-bit RFC 7471 encoding (units of
/// 0.000003 %). `None` means "not configured / not measured" — the
/// corresponding sub-TLV is simply not advertised.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct LinkTeMetric {
    pub unidirectional_delay: Option<u32>,
    pub min_delay: Option<u32>,
    pub max_delay: Option<u32>,
    pub delay_variation: Option<u32>,
    pub loss: Option<u32>,
}

impl LinkTeMetric {
    /// Build the RFC 7471 link-attribute sub-sub-TLVs for the configured
    /// metrics, in ascending code-point order (27/28/29/30). These ride
    /// inside the link's ASLA sub-TLV (RFC 9492) — see
    /// `flex_algo::build_link_asla`. The anomalous flag is always clear
    /// for statically-configured values; the dynamic measurement task
    /// will set it on threshold crossings.
    ///
    /// The Min/Max sub-TLV (28) is emitted only when *both* bounds are
    /// configured — a half-populated bound would be a meaningless wire
    /// artifact.
    pub fn asla_sub_subs(&self) -> Vec<OspfAslaSubSubTlv> {
        let mut subs = Vec::new();
        if let Some(delay) = self.unidirectional_delay {
            subs.push(OspfAslaSubSubTlv::UniLinkDelay(OspfSubUniLinkDelay {
                anomalous: false,
                delay,
            }));
        }
        if let (Some(min_delay), Some(max_delay)) = (self.min_delay, self.max_delay) {
            subs.push(OspfAslaSubSubTlv::MinMaxLinkDelay(OspfSubMinMaxLinkDelay {
                anomalous: false,
                min_delay,
                max_delay,
            }));
        }
        if let Some(variation) = self.delay_variation {
            subs.push(OspfAslaSubSubTlv::DelayVariation(OspfSubDelayVariation {
                variation,
            }));
        }
        if let Some(loss) = self.loss {
            subs.push(OspfAslaSubSubTlv::LinkLoss(OspfSubLinkLoss {
                anomalous: false,
                loss,
            }));
        }
        subs
    }
}

/// Neighbor-state threshold at which a BFD session is started and torn
/// down for this interface. `TwoWay` (default, FRR-style) also protects
/// DR-Other pairs on a broadcast LAN; `Full` (Cisco/IOS-XR-style)
/// tracks only DR/BDR adjacencies. Identical on point-to-point links,
/// where the neighbor goes straight to Full.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NbrStateThreshold {
    #[default]
    TwoWay,
    Full,
}

impl NbrStateThreshold {
    /// The NFSM state the neighbor must reach (or fall below) for the
    /// BFD session to be installed (or removed).
    pub fn as_nfsm(self) -> NfsmState {
        match self {
            Self::TwoWay => NfsmState::TwoWay,
            Self::Full => NfsmState::Full,
        }
    }
}

/// FRR default Echo interval (milliseconds) — the hard default for both
/// `echo-transmit-interval` and `echo-receive-interval` when unset at every
/// level.
pub const DEFAULT_ECHO_INTERVAL_MS: u32 = 50;

/// One `bfd { ... }` block (zebra-ospf-bfd.yang). The same struct backs both
/// the OSPF **instance-level** default (`router ospf { bfd {} }`,
/// `Ospf::bfd`) and the **per-interface** override
/// (`area <a> interface <if> bfd {}`, `LinkConfig::bfd`). Every leaf is
/// `Option` / `None`-default so the per-interface value can override the
/// instance default *per leaf* via [`OspfLinkBfdConfig::resolve`]; an unset
/// leaf at both levels falls back to a hard default. Shared by v2 and v3.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OspfLinkBfdConfig {
    /// Activate BFD. At instance level `Some(true)` blanket-enables every
    /// interface; per-interface it overrides (so `Some(false)` opts out).
    /// `None` ⇒ inherit; off if unset everywhere.
    pub enable: Option<bool>,
    /// Neighbor state at which the session starts/stops. `None` ⇒ inherit
    /// (hard default `TwoWay`).
    pub min_neighbor_state: Option<NbrStateThreshold>,
    /// BFD Echo role for this interface's single-hop sessions
    /// (`transmit` / `receive` / `both`); `None` ⇒ inherit (Echo off if unset
    /// everywhere). Backed by the per-interface `xdp-bfd-echo` helper;
    /// honoured for OSPFv2, inert for v3 (IPv6).
    pub echo_mode: Option<EchoMode>,
    /// Echo transmit interval (milliseconds) — the rate we originate Echo at
    /// (`transmit` / `both`). `None` ⇒ inherit / [`DEFAULT_ECHO_INTERVAL_MS`].
    pub echo_transmit_ms: Option<u32>,
    /// Advertised Required Min Echo RX Interval (milliseconds)
    /// (`receive` / `both`). `None` ⇒ inherit / [`DEFAULT_ECHO_INTERVAL_MS`].
    pub echo_receive_ms: Option<u32>,
    /// Offload control-packet expiration detection (RFC 5880 §6.8.4) to the
    /// per-interface XDP helper once the session is Up — detection immune to
    /// daemon scheduling latency. `None` ⇒ inherit (hard default `false`:
    /// detection in userspace).
    pub detect_offload: Option<bool>,
}

/// The effective BFD settings for one interface after merging its
/// per-interface `bfd {}` over the instance-level default — concrete values
/// ready for the reconcile path. Produced by [`OspfLinkBfdConfig::resolve`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedBfd {
    pub enable: bool,
    pub min_neighbor_state: NbrStateThreshold,
    pub echo_mode: Option<EchoMode>,
    pub echo_transmit_ms: u32,
    pub echo_receive_ms: u32,
    pub detect_offload: bool,
}

impl OspfLinkBfdConfig {
    /// Resolve `self` (the per-interface block) over `default` (the
    /// instance-level `router ospf { bfd {} }` block), per leaf: per-interface
    /// value if set, else the instance default, else a hard default.
    pub fn resolve(&self, default: &OspfLinkBfdConfig) -> ResolvedBfd {
        ResolvedBfd {
            enable: self.enable.or(default.enable).unwrap_or(false),
            min_neighbor_state: self
                .min_neighbor_state
                .or(default.min_neighbor_state)
                .unwrap_or_default(),
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

/// OSPFv2 per-interface authentication mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OspfAuthMode {
    /// RFC 2328 §D.2 — AuType 0, header auth field ignored.
    Null,
    /// RFC 2328 §D.3 — AuType 1, header auth field carries the
    /// plain key zero-padded to 8 bytes.
    Simple,
    /// RFC 2328 §D.4 / RFC 5709 — AuType 2, header overlay carries
    /// (key-id, digest-length, seq) and the body is followed by
    /// an algorithm-sized digest trailer. The trailer's algorithm
    /// is determined by the configured key for the key-id (MD5,
    /// HMAC-SHA-{1,256,384,512}).
    MessageDigest,
}

/// One cryptographic-auth key entry. The raw bytes are stored
/// at the length the operator configured; padding/truncation
/// for the on-wire digest happens at the apply/verify boundary.
#[derive(Debug, Clone)]
pub struct AuthKey {
    pub algo: OspfCryptoAlgo,
    pub raw: Vec<u8>,
}

/// Cryptographic-auth algorithms: MD5 and the HMAC-SHA family
/// per RFC 5709.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OspfCryptoAlgo {
    /// RFC 2328 §D.4 — keyed-MD5 `MD5(packet || key padded to 16)`.
    /// Trailer length = 16.
    Md5,
    /// RFC 5709 §2 — `HMAC-SHA-1(key, packet)`. Trailer length = 20.
    HmacSha1,
    /// RFC 5709 §2 — `HMAC-SHA-256(key, packet)`. Trailer length = 32.
    HmacSha256,
    /// RFC 5709 §2 — `HMAC-SHA-384(key, packet)`. Trailer length = 48.
    HmacSha384,
    /// RFC 5709 §2 — `HMAC-SHA-512(key, packet)`. Trailer length = 64.
    HmacSha512,
}

impl OspfCryptoAlgo {
    /// On-wire digest length for this algorithm — what the
    /// sender stamps into the header `auth_data_len` field and
    /// what the receiver expects in the trailer.
    pub fn digest_len(self) -> usize {
        match self {
            Self::Md5 => 16,
            Self::HmacSha1 => 20,
            Self::HmacSha256 => 32,
            Self::HmacSha384 => 48,
            Self::HmacSha512 => 64,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum PrefixSid {
    Index(u32),
    Absolute(u32),
}

/// Per-link Adjacency-SID (RFC 8665 §6). Stored verbatim from
/// the YANG `adjacency-sid` container; origination picks the wire
/// encoding (Index vs. Label sub-TLV) from whichever variant is set.
/// Kept distinct from `PrefixSid` because Adj-SIDs grow flags/weight
/// once Phase B consumption lands, while Prefix-SIDs do not.
#[derive(Debug, Clone, Copy)]
pub enum AdjacencySid {
    Index(u32),
    Absolute(u32),
}

/// Per-interface OSPF state.
///
/// Parameterized over `V: OspfVersion` so address-family-specific
/// fields (configured interface addresses, neighbor map, queued LSA
/// acks) specialize via the trait's associated types. Default
/// `V = Ospfv2` keeps every existing callsite resolving to
/// `OspfLink<Ospfv2>` without textual churn — same pattern as
/// `Identity<V>` and `Neighbor<V>`.
///
/// Parameterized:
///   - `addr: Vec<OspfAddr<V>>`              (V::Prefix)
///   - `ident: Identity<V>`                  (V::Prefix)
///   - `nbrs: BTreeMap<Ipv4Addr, Neighbor<V>>`  (V::DbDesc, LsaHeader, Lsa)
///   - `ls_ack_delayed: Vec<V::LsaHeader>`
///
/// Still v2-bound (concrete types):
///   - `tx` / `ptx: UnboundedSender<Message>` — the v2 Message enum
///     carries v2-specific packet variants; pending its own
///     parameterization PR.
///   - `config: LinkConfig` — area / intervals only; no
///     version-specific types.
///   - `sock: Arc<AsyncFd<Socket>>` — same socket type for both
///     versions (raw socket, just different domain).
///
/// `nbrs` key stays `Ipv4Addr`. The semantics differ between
/// versions — v2 keys by source IP, v3 by router-id per RFC 5340
/// §10 — but both are 32-bit and the storage works.
pub struct OspfLink<V: OspfVersion = Ospfv2> {
    pub index: u32,
    pub name: String,
    pub mtu: u32,
    pub enabled: bool,
    pub addr: Vec<OspfAddr<V>>,
    pub area: Ipv4Addr,
    pub area_id: Ipv4Addr,
    /// Cached copy of the parent area's `area_type`. Synced when the
    /// link joins an area and whenever the area's type or sub-knobs
    /// change (via `config::area_type_set` and siblings). Hello/DBD
    /// emit and recv read this directly without re-borrowing
    /// `Ospf::areas`. Default `AreaType::default()` = Normal.
    pub area_type: super::area::AreaType,
    pub state: IfsmState,
    pub ostate: IfsmState,
    pub sock: Arc<AsyncFd<Socket>>,
    pub ident: Identity<V>,
    pub tx: UnboundedSender<Message<V>>,
    pub nbrs: BTreeMap<Ipv4Addr, Neighbor<V>>,
    pub flags: OspfLinkFlags,
    pub link_flags: LinkFlags,
    pub network_type: OspfNetworkType,
    pub output_cost: u32,
    pub multicast_memberships: OspfMulticastMembership,
    pub timer: LinkTimer,
    pub state_change: usize,
    pub db_desc_in: usize,
    pub full_nbr_count: usize,
    pub ptx: UnboundedSender<Message<V>>,
    pub config: LinkConfig,
    /// Outbound RFC 2328 §D.4 cryptographic-auth sequence number.
    /// Monotonically increasing per interface across the link's
    /// lifetime; initialized to wall-clock seconds at link create
    /// so a daemon restart still produces a strictly larger value
    /// than the previous instance was using (RFC §D.4.3). Atomic
    /// so `&OspfLink` send paths can `fetch_add(1)` without an
    /// `&mut` borrow that would conflict with the surrounding
    /// `link.nbrs.iter_mut()` flood loops, while staying `Sync`
    /// (the show-info path borrows the parent `Ospf<V>` across
    /// `.await`).
    pub md5_seq: std::sync::atomic::AtomicU32,
    pub ls_ack_delayed: Vec<V::LsaHeader>,
    /// 32-bit Interface ID advertised in v3 Hellos and Router-LSA
    /// links (RFC 5340 §A.3.2 / §A.4.3). Unused by v2 (where the
    /// equivalent role is filled by the interface IP). Initialized
    /// from the kernel ifindex so it's unique per interface on
    /// this router (RFC 5340 §3.2 only requires per-router
    /// uniqueness).
    pub interface_id: u32,
    /// Per-link LSDB (RFC 5340 §A.4.9). Holds link-scope LSAs —
    /// `Link-LSAs` — that the v3 standard restricts to flooding
    /// only on the segment they were originated on. Empty on v2
    /// (no link-scope LSA types exist in RFC 2328) but the field
    /// stays generic for shape simplicity.
    pub lsdb: super::lsdb::Lsdb<V>,
}

#[derive(Default)]
pub struct LinkTimer {
    pub hello: Option<Timer>,
    pub wait: Option<Timer>,
    pub ls_ack: Option<Timer>,
    pub ls_upd_event: Option<Timer>,
}

impl<V: OspfVersion> OspfLink<V>
where
    V::Prefix: Default,
{
    pub fn from(
        tx: UnboundedSender<Message<V>>,
        link: Link,
        sock: Arc<AsyncFd<Socket>>,
        router_id: Ipv4Addr,
        ptx: UnboundedSender<Message<V>>,
    ) -> Self {
        Self {
            index: link.index,
            name: link.name.to_owned(),
            mtu: link.mtu,
            enabled: false,
            addr: Vec::new(),
            area: Ipv4Addr::UNSPECIFIED,
            area_id: Ipv4Addr::UNSPECIFIED,
            area_type: super::area::AreaType::default(),
            state: IfsmState::Down,
            ostate: IfsmState::Down,
            sock,
            ident: Identity::<V>::new(router_id),
            tx,
            nbrs: BTreeMap::new(),
            flags: 0.into(),
            link_flags: link.flags,
            network_type: OspfNetworkType::default(),
            output_cost: OSPF_DEFAULT_OUTPUT_COST,
            multicast_memberships: 0.into(),
            timer: LinkTimer::default(),
            state_change: 0,
            db_desc_in: 0,
            full_nbr_count: 0,
            ptx,
            config: LinkConfig::default(),
            // RFC 2328 §D.4.3: seed the cryptographic-auth seq with
            // wall-clock seconds so a daemon restart still produces
            // a strictly larger value than the previous instance.
            md5_seq: std::sync::atomic::AtomicU32::new(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as u32)
                    .unwrap_or(0),
            ),
            ls_ack_delayed: Vec::new(),
            interface_id: link.index,
            lsdb: super::lsdb::Lsdb::new(),
        }
    }
}

impl<V: OspfVersion> OspfLink<V> {
    pub fn priority(&self) -> u8 {
        self.config.priority.unwrap_or(OSPF_DEFAULT_PRIORITY)
    }

    pub fn hello_interval(&self) -> u16 {
        self.config
            .hello_interval
            .unwrap_or(OSPF_DEFAULT_HELLO_INTERVAL)
    }

    pub fn dead_interval(&self) -> u32 {
        self.config
            .dead_interval
            .unwrap_or(OSPF_DEFAULT_DEAD_INTERVAL)
    }

    pub fn retransmit_interval(&self) -> u16 {
        self.config
            .retransmit_interval
            .unwrap_or(OSPF_DEFAULT_RETRANSMIT_INTERVAL)
    }

    pub fn transmit_delay(&self) -> u16 {
        self.config
            .transmit_delay
            .unwrap_or(OSPF_DEFAULT_TRANSMIT_DELAY)
    }

    pub fn is_passive(&self) -> bool {
        false
    }

    pub fn is_multicast_if(&self) -> bool {
        matches!(
            self.network_type,
            OspfNetworkType::Broadcast | OspfNetworkType::NBMA
        )
    }

    pub fn is_nbma_if(&self) -> bool {
        self.network_type == OspfNetworkType::NBMA
    }

    pub fn is_pointopoint(&self) -> bool {
        self.network_type == OspfNetworkType::PointToPoint
    }

    /// Resolve the configured network type, defaulting to Broadcast
    /// (matches the historical zebra-rs behavior — every interface
    /// was Broadcast unless code explicitly overrode it).
    pub fn config_network_type(&self) -> OspfNetworkType {
        self.config
            .network_type
            .unwrap_or(OspfNetworkType::Broadcast)
    }

    /// Effective authentication mode for this interface. Defaults
    /// to Null when no mode is configured — RFC 2328 §D.2.
    pub fn auth_mode(&self) -> OspfAuthMode {
        self.config.auth_mode.unwrap_or(OspfAuthMode::Null)
    }

    /// Per-interface crypto-key fallback used when no key-chain is
    /// configured (or when the configured chain is missing /
    /// expired). Lowest configured key-id across MD5 + HMAC-SHA
    /// entries.
    pub fn active_crypto_key(&self) -> Option<(u8, AuthKey)> {
        self.config
            .crypto_keys
            .iter()
            .next()
            .map(|(&id, k)| (id, k.clone()))
    }

    /// Resolve the active send key — chain-aware. If `key_chain` is
    /// set, look it up in the policy-driven snapshot and pick the
    /// lowest key-id whose send-lifetime is active; otherwise fall
    /// back to the per-interface `crypto_keys` map. Returns `None`
    /// if a chain is named but missing, has no active key, or the
    /// active key uses an algorithm OSPFv2 doesn't speak — peers
    /// will reject our zero-trailer packets, which is a louder
    /// failure than silently picking a stale key.
    pub fn resolve_active_send_key(
        &self,
        chains: &std::collections::BTreeMap<String, crate::policy::KeyChain>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Option<(u8, AuthKey)> {
        if let Some(name) = &self.config.key_chain {
            let chain = chains.get(name)?;
            let (id, key) = chain
                .keys
                .iter()
                .find(|(_, k)| chain_key_is_send_active(k, now))?;
            let algo = policy_algo_to_ospf(key.algo?)?;
            // YANG key-id is uint64; OSPFv2 carries 8 bits on the
            // wire. Reject anything that wouldn't fit so we don't
            // silently truncate.
            let id_u8: u8 = (*id).try_into().ok()?;
            return Some((
                id_u8,
                AuthKey {
                    algo,
                    raw: key.key_material.clone(),
                },
            ));
        }
        self.active_crypto_key()
    }

    /// Read and increment the per-interface cryptographic-auth
    /// sequence number. Each outbound cryptographic-auth packet
    /// consumes one value; wrap is u32 (the on-wire field width)
    /// so the counter is allowed to roll over after ~136 years.
    pub fn next_md5_seq(&self) -> u32 {
        self.md5_seq
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    /// Bundle the auth state needed to stamp one outbound packet.
    /// Bumps the cryptographic-auth seq as a side effect — call
    /// once per packet, not once per buffer reuse.
    pub fn auth_send_ctx(
        &self,
        chains: &std::collections::BTreeMap<String, crate::policy::KeyChain>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> super::packet::AuthSendCtx {
        super::packet::AuthSendCtx {
            mode: self.auth_mode(),
            simple_key: self.config.auth_key,
            crypto_key: self.resolve_active_send_key(chains, now),
            md5_seq: self.next_md5_seq(),
        }
    }
}

/// Is this policy-side key usable for *sending* right now? RFC 8177
/// says a key with no algorithm or no material is mid-configuration
/// and inactive; we also require its send-lifetime to bracket `now`.
pub(super) fn chain_key_is_send_active(
    k: &crate::policy::Key,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    k.algo.is_some() && !k.key_material.is_empty() && k.send_lifetime.is_active(now)
}

/// Is this policy-side key usable for *accepting* a received PDU
/// right now? Same filter as send, against accept-lifetime.
pub(super) fn chain_key_is_accept_active(
    k: &crate::policy::Key,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    k.algo.is_some() && !k.key_material.is_empty() && k.accept_lifetime.is_active(now)
}

/// Project the shared policy algorithm enum onto the OSPFv2-supported
/// subset. Returns `None` for algorithms OSPF doesn't speak
/// (e.g. AES-CMAC-PRF-128 belongs to TCP-AO's MUST-implement set per
/// RFC 5926 but isn't an RFC 5709 OSPF algorithm) so resolve falls
/// through to `None`.
pub(super) fn policy_algo_to_ospf(a: crate::policy::CryptoAlgorithm) -> Option<OspfCryptoAlgo> {
    use crate::policy::CryptoAlgorithm as P;
    match a {
        P::Md5 => Some(OspfCryptoAlgo::Md5),
        P::HmacSha1 => Some(OspfCryptoAlgo::HmacSha1),
        P::HmacSha256 => Some(OspfCryptoAlgo::HmacSha256),
        P::HmacSha384 => Some(OspfCryptoAlgo::HmacSha384),
        P::HmacSha512 => Some(OspfCryptoAlgo::HmacSha512),
        P::AesCmacPrf128 => None,
    }
}

#[bitfield(u8, debug = true)]
pub struct OspfLinkFlags {
    pub hello_sent: bool,
    pub resvd1: bool,
    #[bits(6)]
    pub resvd2: usize,
}

#[cfg(test)]
mod bfd_resolve_tests {
    use super::*;

    /// Per-interface leaves override the instance default; unset leaves
    /// inherit it; leaves unset at both levels fall back to the hard default.
    #[test]
    fn resolve_merges_per_leaf() {
        let default = OspfLinkBfdConfig {
            enable: Some(true), // blanket-enable
            min_neighbor_state: Some(NbrStateThreshold::Full),
            echo_mode: Some(EchoMode::Receive),
            echo_transmit_ms: Some(100),
            echo_receive_ms: None, // → hard default 50
            detect_offload: Some(true),
        };

        // Interface that sets nothing → inherits everything from the default.
        let inherit = OspfLinkBfdConfig::default().resolve(&default);
        assert!(inherit.enable);
        assert_eq!(inherit.min_neighbor_state, NbrStateThreshold::Full);
        assert_eq!(inherit.echo_mode, Some(EchoMode::Receive));
        assert_eq!(inherit.echo_transmit_ms, 100);
        assert_eq!(inherit.echo_receive_ms, DEFAULT_ECHO_INTERVAL_MS);
        assert!(inherit.detect_offload, "inherits the instance default");

        // Interface overrides: opt out of the blanket enable, change echo
        // role, opt out of the instance-wide detect offload.
        let override_link = OspfLinkBfdConfig {
            enable: Some(false),
            echo_mode: Some(EchoMode::Both),
            detect_offload: Some(false),
            ..OspfLinkBfdConfig::default()
        };
        let eff = override_link.resolve(&default);
        assert!(!eff.enable, "per-interface enable=false opts out");
        assert_eq!(eff.echo_mode, Some(EchoMode::Both));
        assert!(!eff.detect_offload, "per-interface override wins");
        // Unset leaves still inherit the instance default.
        assert_eq!(eff.min_neighbor_state, NbrStateThreshold::Full);
        assert_eq!(eff.echo_transmit_ms, 100);
    }

    /// With no instance default and no per-interface override, everything is
    /// the hard default: BFD off, two-way, no echo, 50 ms intervals.
    #[test]
    fn resolve_hard_defaults_when_unset() {
        let eff = OspfLinkBfdConfig::default().resolve(&OspfLinkBfdConfig::default());
        assert!(!eff.enable);
        assert_eq!(eff.min_neighbor_state, NbrStateThreshold::TwoWay);
        assert_eq!(eff.echo_mode, None);
        assert_eq!(eff.echo_transmit_ms, DEFAULT_ECHO_INTERVAL_MS);
        assert_eq!(eff.echo_receive_ms, DEFAULT_ECHO_INTERVAL_MS);
        assert!(!eff.detect_offload, "hard default: userspace detection");
    }
}

#[cfg(test)]
mod te_metric_tests {
    use super::*;

    #[test]
    fn asla_sub_subs_emits_all_in_code_order() {
        let m = LinkTeMetric {
            unidirectional_delay: Some(1_000),
            min_delay: Some(900),
            max_delay: Some(1_200),
            delay_variation: Some(50),
            loss: Some(10),
        };
        let subs = m.asla_sub_subs();
        assert_eq!(subs.len(), 4);
        assert!(matches!(subs[0], OspfAslaSubSubTlv::UniLinkDelay(_)));
        assert!(matches!(subs[1], OspfAslaSubSubTlv::MinMaxLinkDelay(_)));
        assert!(matches!(subs[2], OspfAslaSubSubTlv::DelayVariation(_)));
        assert!(matches!(subs[3], OspfAslaSubSubTlv::LinkLoss(_)));
    }

    #[test]
    fn min_max_requires_both_bounds() {
        // Only min set → no Min/Max sub-TLV.
        let m = LinkTeMetric {
            min_delay: Some(900),
            ..Default::default()
        };
        assert!(m.asla_sub_subs().is_empty());

        // Only max set → no Min/Max sub-TLV.
        let m = LinkTeMetric {
            max_delay: Some(1_200),
            ..Default::default()
        };
        assert!(m.asla_sub_subs().is_empty());

        // Both set → exactly one Min/Max sub-TLV.
        let m = LinkTeMetric {
            min_delay: Some(900),
            max_delay: Some(1_200),
            ..Default::default()
        };
        let subs = m.asla_sub_subs();
        assert!(matches!(
            subs.as_slice(),
            [OspfAslaSubSubTlv::MinMaxLinkDelay(_)]
        ));
    }

    #[test]
    fn default_is_empty() {
        assert!(LinkTeMetric::default().asla_sub_subs().is_empty());
    }
}
