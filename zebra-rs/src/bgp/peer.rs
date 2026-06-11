#![allow(dead_code)]
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use bytes::BytesMut;
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use bgp_packet::*;

use super::peer_key::{PeerKey, PeerOrigin};
use super::peer_map::PeerMap;

use caps::CapAs4;
use caps::CapRefresh;
use caps::CapabilityPacket;

use crate::bfd::session::{EchoMode, SessionKey, SessionParams};
use crate::bgp::cap::cap_register_recv;
use crate::bgp::route::{route_clean, route_sync};
use crate::bgp::tracing::{Direction, PacketKind};
use crate::bgp::{AdjRib, In, Out};
use crate::bgp::{stale_route_withdraw, timer};
use crate::bgp_packet_trace;
use crate::config::Args;
use crate::context::task::*;

use super::cap::{CapAfiMap, cap_addpath_recv, cap_register_send};
use super::inst::Message;
use super::route::LocalRib;
use super::route::route_from_peer;
use super::{BGP_PORT, PolicyListValue, PrefixSetValue};
use super::{Bgp, BgpAttrStore, InOuts};

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub enum State {
    Idle,
    Connect,
    Active,
    OpenSent,
    OpenConfirm,
    Established,
}

/// Which side opened the TCP connection. Required for RFC 4271 §6.8
/// collision resolution: the BGP-Identifier comparison picks the
/// surviving connection by role (the higher-ID endpoint's initiated
/// connection wins).
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub enum Role {
    /// We initiated the connect.
    Active,
    /// Peer initiated; we accepted.
    Passive,
}

/// Identity of one TCP connection of a peer (one reader/writer
/// spawn), minted by [`Peer::alloc_conn_id`]. Events from a
/// connection carry its `ConnId`; the FSM resolves the id against the
/// peer's *current* slots at dispatch time ([`resolve_conn`]).
/// Identity must travel with the connection rather than as a role tag
/// baked into the reader at spawn: §6.8 promotion moves a connection
/// between slots while its reader keeps running, and a torn-down
/// connection's last events can still sit in the queue — both
/// misroute under a baked tag (a promoted conn's KEEPALIVEs were
/// ignored and its death never tore the session down).
pub type ConnId = u64;

/// Which slot a connection's event resolves to — the dispatch-time
/// product of [`resolve_conn`], never baked into a task. `Primary` is
/// the connection currently owning `Peer::packet_tx` and
/// `Peer::task.{reader,writer}`. `Collision` is the parallel
/// connection held in `Peer::collision` during §6.8 resolution.
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub enum ConnTag {
    Primary,
    Collision,
}

/// Parallel TCP connection held while RFC 4271 §6.8 collision
/// resolution is pending. Mirrors the primary connection's
/// reader/writer/packet_tx triple plus the originating role so the
/// BGP-Identifier comparison can pick the winner.
#[derive(Debug)]
pub struct CollisionConn {
    /// This connection's identity; becomes `Peer::primary_conn_id` if
    /// it wins §6.8 resolution and is promoted.
    pub conn_id: ConnId,
    pub packet_tx: UnboundedSender<BytesMut>,
    pub reader: Task<()>,
    pub writer: Task<()>,
    pub role: Role,
    /// Endpoint addresses of this collision conn, written into
    /// `peer.param` if it wins §6.8 resolution and is promoted —
    /// `show ip bgp neighbors`' Local/Foreign host lines must
    /// describe the surviving connection, not the primary it
    /// replaced.
    pub local_addr: Option<SocketAddr>,
    pub remote_addr: Option<SocketAddr>,
}

impl State {
    pub fn to_str(self) -> &'static str {
        match self {
            Self::Idle => "Idle",
            Self::Connect => "Connect",
            Self::Active => "Active",
            Self::OpenSent => "OpenSent",
            Self::OpenConfirm => "OpenConfirm",
            Self::Established => "Established",
        }
    }

    pub fn is_established(&self) -> bool {
        *self == State::Established
    }
}

#[derive(Debug)]
pub enum Event {
    ConfigUpdate,          // 0
    Start,                 // 1
    Stop,                  // 2
    ConnRetryTimerExpires, // 9
    HoldTimerExpires,      // 10
    KeepaliveTimerExpires, // 11
    IdleHoldTimerExpires,  // 13
    Connected(TcpStream),  // 17
    ConnFail(ConnId),      // 18
    /// An active dial failed before any connection existed, so no
    /// `ConnId` was ever minted. Handled only in Connect — a stale
    /// dial failure must not tear down a session that superseded it.
    DialFail,
    BGPOpen(ConnId, OpenPacket),          // 19
    NotifMsg(ConnId, NotificationPacket), // 25
    KeepAliveMsg(ConnId),                 // 26
    UpdateMsg(UpdatePacket),              // 27
    // RFC 2918 Route Refresh receive. Carries the AFI/SAFI from the
    // wire (raw u16/u8) so unknown-AF refreshes still dispatch
    // through the FSM rather than tearing the session down.
    RouteRefreshMsg(u16, u8),
    StaleTimerExipires(AfiSafi),
    AdvTimerVpnv4Expires,
    AdvTimerVpnv6Expires,
    AdvTimerEvpnExpires,
}

pub enum FsmEffect {
    None,
    RouteUpdate(UpdatePacket),
    StaleExpire(AfiSafi),
    // Peer asked us to re-send the Adj-RIB-Out for an AFI/SAFI
    // (RFC 2918). The current implementation re-runs the full
    // soft-out replay across every negotiated AFI/SAFI rather than
    // narrowing to the requested one — over-eager but correct, and
    // simpler than threading AFI/SAFI through the route layer. The
    // (afi, safi) pair is kept in the variant so a future revision
    // can do the targeted version without an FSM change.
    RouteRefreshRecv { afi: u16, safi: u8 },
}

#[derive(Debug, Default)]
pub struct PeerTask {
    pub connect: Option<Task<()>>,
    pub reader: Option<Task<()>>,
    pub writer: Option<Task<()>>,
}

#[derive(Debug, Default)]
pub struct PeerTimer {
    pub idle_hold_timer: Option<Timer>,
    pub connect_retry: Option<Timer>,
    pub hold_timer: Option<Timer>,
    pub keepalive: Option<Timer>,
    pub min_as_origin: Option<Timer>,
    pub min_route_adv: Option<Timer>,
    pub stale_timer: BTreeMap<AfiSafi, Timer>,
}

#[derive(Serialize, Debug, Default, Clone, Copy)]
pub struct PeerCounter {
    pub sent: u64,
    pub rcvd: u64,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum PasswordEncoding {
    #[default]
    Clear,
    Encrypted,
}

#[derive(Debug, Default, Clone)]
pub struct PeerTransportConfig {
    pub passive: bool,
    pub update_source: Option<IpAddr>,
    /// `port <1-65535>` (FRR `neighbor X port`): TCP destination port
    /// used when this router actively dials the neighbor. `None` is
    /// the IANA default [`BGP_PORT`] (179); deleting the leaf returns
    /// to it. Consulted only by [`peer_start_connection`] — inbound
    /// connections are matched to their neighbor by source address,
    /// never by port, so the listener side ignores this (move the
    /// listener with the instance-level `router bgp port` instead).
    /// A change bounces a live session (FRR `peer_change_reset`) so
    /// the new port takes effect immediately. See
    /// `zebra-bgp-transport.yang`.
    pub port: Option<u16>,
    /// GTSM / `ttl-security` (RFC 5082, originally RFC 3682): when set,
    /// this neighbor is treated as directly connected. Every BGP packet
    /// leaves with IP TTL / IPv6 Hop Limit 255 and inbound packets are
    /// accepted only at 255 (kernel `IP_MINTTL` / `IPV6_MINHOPCOUNT`).
    /// The options are installed on the session socket in
    /// [`fsm_connected`], the common active/passive convergence point,
    /// so one site covers both roles. Always 255 — there is no
    /// configurable hop count (the YANG node is a presence container). Mutually
    /// exclusive with ebgp-multihop. See `zebra-bgp-transport.yang`.
    pub ttl_security: bool,
    /// eBGP multihop TTL (`ebgp-multihop N`, RFC 4271 operational
    /// practice). `Some(n)` raises this eBGP session's egress IP TTL /
    /// IPv6 Hop Limit to `n` so a peer up to `n` hops away is reachable;
    /// `None` (the default) leaves a directly-connected eBGP peer at the
    /// `DEFAULT_EBGP_TTL` of 1. Ignored for iBGP (always 255) and
    /// overridden by `ttl_security` (255). Resolved by
    /// [`Peer::session_ttl`] and applied in [`fsm_connected`] /
    /// `peer_connect`. See `zebra-bgp-transport.yang`.
    pub ebgp_multihop: Option<u8>,
    /// `tcp-mss <1-65535>`: cap the TCP Maximum Segment Size on this
    /// neighbor's connection. `Some(n)` is installed on the active
    /// connect socket before `connect(2)` (`peer_connect`) and folded
    /// into the listener's minimum (`config::apply_tcp_mss_refresh_all`)
    /// so a passively-accepted child inherits it; both must precede the
    /// TCP handshake because `getsockopt(TCP_MAXSEG)` on an established
    /// socket returns the already-negotiated MSS. `None` leaves the
    /// kernel default (path-MTU derived). A change does not bounce a live
    /// session — like FRR, the new value takes effect on the next
    /// connect, so a `clear` is needed to apply it now. See `super::mss`
    /// and `zebra-bgp-transport.yang`.
    pub tcp_mss: Option<u16>,
    /// `disable-connected-check` (RFC 4271 operational practice). When
    /// `false` (the default), a single-hop eBGP session — egress TTL 1,
    /// i.e. neither `ebgp_multihop` nor `ttl_security` set — is only
    /// dialed when the neighbor's address is on a directly-connected
    /// subnet (FRR `shared_network`). When `true`, that requirement is
    /// dropped so the session can reach a non-connected address (e.g. a
    /// loopback one L2 hop away) while keeping TTL 1. Ignored for iBGP and
    /// for multihop / GTSM sessions (they are never gated). Consulted by
    /// [`Peer::connected_check_ok`]. See `zebra-bgp-transport.yang`.
    pub disable_connected_check: bool,
    // TCP MD5 (RFC 2385) shared secret. When Some, installed on the
    // listening socket (for the peer's address) and on the active
    // TcpSocket before connect(). The encoding determines how the
    // bytes are interpreted when the kernel key is derived. See
    // zebra-bgp-auth.yang `tcp-md5`.
    pub md5_password: Option<String>,
    pub md5_encoding: PasswordEncoding,
    // TCP-AO (RFC 5925 / RFC 5926) configuration. When Some, the key
    // chain is resolved at connect/listen time and installed via
    // TCP_AO_ADD_KEY. MD5 and AO are mutually exclusive per session;
    // enforcement is at commit.
    pub ao_config: Option<super::auth::AoConfig>,
    // Resolved AO key selected from `ao_config`'s referenced chain.
    // Recomputed whenever ao_config or the chain changes; the active
    // side in peer_connect applies it directly.
    pub resolved_ao_key: Option<super::auth::ResolvedAoKey>,
}

/// Per-neighbor BFD attachment recorded from
/// `set router bgp neighbor <addr> bfd { enable | multihop |
/// minimum-ttl }` (zebra-bgp-bfd.yang). The configuration is
/// stored here; `enable` flips translate into subscribe / unsubscribe
/// calls on the BFD instance via `bfd::inst::Bfd::client_req_tx`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PeerBfdConfig {
    /// Activate BFD. `None` ⇒ inherit the instance-level
    /// `router bgp { bfd { enable } }`; `Some(false)` opts this neighbor out
    /// of a blanket instance enable. Off if unset everywhere.
    pub enable: Option<bool>,
    /// Hop-mode override. `None` (the default) means "infer": the
    /// session is multihop iff the BGP session is iBGP, mirroring FRR's
    /// `PEER_IS_MULTIHOP`. `Some(true)`/`Some(false)` force it — used
    /// for eBGP-over-loopback until a dedicated `ebgp-multihop` knob
    /// exists. See [`Peer::bfd_multihop`]. Per-neighbor only (not inherited).
    pub multihop: Option<bool>,
    /// Multihop minimum received TTL (RFC 5883). `None` falls back to
    /// [`crate::bfd::socket::BFD_MULTIHOP_DEFAULT_MIN_TTL`]. Ignored for
    /// single-hop sessions (GTSM requires 255 unconditionally).
    pub minimum_ttl: Option<u8>,
    /// BFD Echo role (`transmit` / `receive` / `both`); `None` ⇒ inherit
    /// (off if unset everywhere). **Single-hop only** — RFC 5883 multihop has
    /// no Echo, so this is inert on multihop sessions (iBGP / multihop eBGP).
    pub echo_mode: Option<EchoMode>,
    /// Echo transmit interval (ms); `None` ⇒ [`DEFAULT_ECHO_INTERVAL_MS`].
    pub echo_transmit_ms: Option<u32>,
    /// Advertised Required Min Echo RX (ms); `None` ⇒
    /// [`DEFAULT_ECHO_INTERVAL_MS`].
    pub echo_receive_ms: Option<u32>,
}

/// FRR default Echo interval (ms) — the hard default for the Echo intervals
/// when unset at every level.
pub const DEFAULT_ECHO_INTERVAL_MS: u32 = 50;

/// Effective BFD Echo settings for a neighbor after merging its per-neighbor
/// `bfd {}` over the instance-level default. (Hop-mode / min-ttl are
/// per-neighbor and not part of this merge.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedPeerBfd {
    pub enable: bool,
    pub echo_mode: Option<EchoMode>,
    pub echo_transmit_ms: u32,
    pub echo_receive_ms: u32,
}

impl PeerBfdConfig {
    /// Resolve `self` (per-neighbor) over `default` (instance-level
    /// `router bgp { bfd {} }`), per leaf, for the inheritable bits
    /// (enable + Echo). Hop-mode / min-ttl stay per-neighbor (read directly).
    pub fn resolve(&self, default: &PeerBfdConfig) -> ResolvedPeerBfd {
        ResolvedPeerBfd {
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
        }
    }
}

/// Default occurrence budget for a bare `allowas-in` (FRR parity).
pub const ALLOWAS_IN_DEFAULT_COUNT: u8 = 3;

/// Per-neighbor `allowas-in` mode (zebra-bgp-allowas-in.yang). Relaxes
/// the RFC 4271 inbound AS_PATH loop check so routes carrying the local
/// AS are accepted. `None` on [`PeerConfig`] means the strict check
/// applies (the default).
/// Serializes as `{"mode":"count","count":N}` or `{"mode":"origin"}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "mode", content = "count", rename_all = "lowercase")]
pub enum AllowAsIn {
    /// Accept while the local AS appears at most this many times in the
    /// AS_PATH (CLI `allowas-in` / `allowas-in count <1-10>`, default
    /// [`ALLOWAS_IN_DEFAULT_COUNT`]).
    Count(u8),
    /// Accept only when the local AS appears solely as the originating
    /// (right-most) AS (CLI `allowas-in origin`).
    Origin,
}

/// Per-neighbor `remove-private-as` mode (zebra-bgp-remove-private-as.yang).
/// FRR exposes four CLI forms; they collapse to two orthogonal
/// modifiers on the egress AS_PATH transform (eBGP only):
///
/// - `all` (`false` by default): when `false` the strip only runs if the
///   *entire* AS_PATH is private (FRR's bare `remove-private-AS`); when
///   `true` it runs even on a mixed public/private path
///   (`remove-private-AS all`).
/// - `replace_as` (`false` by default): when `false` each private AS is
///   dropped from the path; when `true` it is rewritten to the local AS
///   instead (`remove-private-AS [all] replace-AS`).
///
/// In every form the neighbor's own AS is preserved so its RFC 4271 loop
/// check still works. `None` on [`PeerConfig`] disables the feature.
/// Serializes flat as `{"all":bool,"replace_as":bool}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
pub struct RemovePrivateAs {
    pub all: bool,
    pub replace_as: bool,
}

#[derive(Debug, Clone)]
pub struct PeerConfig {
    pub transport: PeerTransportConfig,
    pub four_octet: bool,
    pub extended_message: bool,
    /// Effective multiprotocol family set — what the next OPEN
    /// advertises. Presence means enabled. Recomputed by
    /// [`super::neighbor_group::recompute_peer_mp`] as
    /// default (IPv4 unicast) < group opinions < [`Self::mp_explicit`];
    /// for a peer with no group reference it equals default + explicit.
    pub mp: AfiSafis<bool>,
    /// Verbatim per-peer `afi-safi <name> enabled <bool>` statements.
    /// Kept separately from the effective [`Self::mp`] so a referenced
    /// neighbor-group's opinions can be merged underneath them ("any
    /// field set explicitly on the neighbor wins") and re-merged when
    /// the group changes.
    pub mp_explicit: BTreeMap<AfiSafi, bool>,
    /// Verbatim per-peer `afi-safi <name> next-hop-self <bool>`
    /// statements — same explicit-vs-effective split as
    /// [`Self::mp_explicit`]; the effective value lives in
    /// [`Self::sub`].
    pub nhs_explicit: BTreeMap<AfiSafi, bool>,
    /// Verbatim per-peer statements for the whole-session knobs a
    /// `neighbor-group` can supply (passive, update-source,
    /// ttl-security, …). Same explicit-vs-effective split: the
    /// effective values live in their usual homes
    /// ([`Self::transport`], [`Self::allowas_in`], `Peer` fields, …),
    /// re-resolved through
    /// [`super::neighbor_group::resolve_knob`] whenever either side
    /// changes.
    pub knobs_explicit: super::neighbor_group::InheritableKnobs,
    pub restart: AfiSafis<RestartValue>,
    pub llgr: AfiSafis<LlgrValue>,
    pub addpath: AfiSafis<AddPathValue>,
    pub route_refresh: bool,
    // When true, the peer's pre-policy Adj-RIB-In is replayed locally
    // on `clear ... soft in` instead of (or in addition to) sending a
    // Route Refresh. Lets policy changes take effect without a session
    // bounce when the peer doesn't support RFC 2918, at the cost of
    // keeping received UPDATEs in memory.
    pub soft_reconfig_in: bool,
    /// Per-neighbor BGP Flow Specification validation toggle (RFC 9117).
    /// `true` (default) validates received flow specs against the
    /// unicast RIB before re-advertising them; `false` accepts every
    /// flow spec from this neighbor as feasible (trusted controller).
    pub flowspec_validation: bool,
    pub timer: timer::Config,
    pub sub: BTreeMap<AfiSafi, PeerSubConfig>,
    /// Reference to a `neighbor-group` (zebra-bgp-neighbor-group.yang)
    /// whose attributes this peer should inherit. Recorded on
    /// `set router bgp neighbor <addr> neighbor-group <name>`. The
    /// peer's `remote_as` is resolved from the group when the operator
    /// has not set it explicitly on the neighbor; the `remote_as_inherited`
    /// flag below tracks which side won.
    pub neighbor_group: Option<String>,
    /// `true` when [`Peer::remote_as`] was populated from the
    /// referenced [`Self::neighbor_group`] rather than from an
    /// explicit per-peer `remote-as`. Used by the group-side and
    /// per-peer config callbacks to decide whether a change to the
    /// group should propagate (or unset) the peer's remote-as.
    pub remote_as_inherited: bool,
    /// BFD attachment for this neighbor.
    pub bfd: PeerBfdConfig,
    /// Per-neighbor `allowas-in` (zebra-bgp-allowas-in.yang). `None`
    /// keeps the strict RFC 4271 inbound AS_PATH loop check.
    pub allowas_in: Option<AllowAsIn>,
    /// Per-neighbor `as-override` (zebra-bgp-as-override.yang). When
    /// `true`, the peer's own AS is replaced with the local AS in the
    /// AS_PATH of every outbound eBGP UPDATE (before the local-AS
    /// prepend), so the receiver's RFC 4271 loop check accepts routes
    /// that have transited its own AS. Ignored for iBGP peers (which do
    /// not prepend). Default `false`.
    pub as_override: bool,
    /// Per-neighbor `remove-private-as` (zebra-bgp-remove-private-as.yang).
    /// `None` leaves the AS_PATH untouched; `Some` strips (or, with
    /// `replace_as`, rewrites) private ASNs from every outbound eBGP
    /// UPDATE before the local-AS prepend. Ignored for iBGP peers.
    pub remove_private_as: Option<RemovePrivateAs>,
    /// Per-neighbor `enforce-first-as` (zebra-bgp-enforce-first-as.yang).
    /// When `true`, an inbound UPDATE from this eBGP neighbor is dropped
    /// unless the left-most AS_PATH segment is an AS_SEQUENCE beginning
    /// with the neighbor's own AS (its `remote_as`). Guards against a peer
    /// that forwards routes without prepending its AS. Ignored for iBGP
    /// peers (which never prepend). Default `false`.
    pub enforce_first_as: bool,
}

impl Default for PeerConfig {
    fn default() -> Self {
        Self {
            transport: Default::default(),
            four_octet: Default::default(),
            extended_message: true,
            mp: Default::default(),
            mp_explicit: BTreeMap::new(),
            nhs_explicit: BTreeMap::new(),
            knobs_explicit: Default::default(),
            restart: AfiSafis::new(),
            llgr: AfiSafis::new(),
            addpath: AfiSafis::new(),
            route_refresh: Default::default(),
            soft_reconfig_in: Default::default(),
            flowspec_validation: true,
            timer: Default::default(),
            sub: Default::default(),
            neighbor_group: None,
            remote_as_inherited: false,
            bfd: PeerBfdConfig::default(),
            allowas_in: None,
            as_override: false,
            remove_private_as: None,
            enforce_first_as: false,
        }
    }
}

/// Per-neighbor, per-AFI/SAFI SRv6 encapsulation mode for the IPv6
/// unicast family (`afi-safi ipv6 encapsulation-type` in
/// ietf-bgp-neighbor). Selects how SRv6-SID-bearing routes are
/// exchanged on the session:
///
/// * [`Srv6`](Self::Srv6) — SRv6-only peer: only routes carrying an
///   SRv6 service SID (BGP Prefix-SID, RFC 9252) are advertised/accepted;
///   SID-less routes are filtered out on the session.
/// * [`Srv6Relax`](Self::Srv6Relax) — mixed session: routes with or
///   without an SRv6 SID may be exchanged with this peer.
///
/// Enforced symmetrically in `route_ipv6_update` (accept: drop a SID-less
/// route from a `Srv6` peer) and `route_update_ipv6` (advertise: withhold
/// a SID-less route from a `Srv6` peer). See [`Peer::ipv6_srv6_strict`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AfiSafiEncapType {
    Srv6,
    Srv6Relax,
}

impl AfiSafiEncapType {
    /// Parse the `encapsulation-type` enum value as it appears in the
    /// YANG / CLI (`srv6`, `srv6-relax`).
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "srv6" => Some(Self::Srv6),
            "srv6-relax" => Some(Self::Srv6Relax),
            _ => None,
        }
    }

    /// The CLI / YANG string form, for show output and round-tripping.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Srv6 => "srv6",
            Self::Srv6Relax => "srv6-relax",
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct PeerSubConfig {
    pub graceful_restart: Option<u32>,
    pub llgr: Option<u32>,
    /// `afi-safi <name> encapsulation-type` (ietf-bgp-neighbor). Only
    /// settable under `afi-safi ipv6` (YANG `when name = 'ipv6'`).
    /// `None` = no SRv6 encapsulation mode configured for this AF.
    pub encapsulation_type: Option<AfiSafiEncapType>,
    /// `afi-safi <name> next-hop-self` (ietf-bgp-neighbor). When `true`,
    /// routes re-advertised to this neighbor for this AF carry our own
    /// address as the next-hop even when they were learned from another
    /// peer (i.e. not just for eBGP / self-originated). Required on the
    /// iBGP labeled-unicast session an Inter-AS Option C ASBR runs toward
    /// its PE: the PE must resolve the ASBR (not the foreign-AS next-hop)
    /// and forward via the ASBR's swap label. Honored on the labeled-
    /// unicast advertise paths (`route_update_labelv4` / `…v6`).
    pub next_hop_self: bool,
}

#[derive(Debug, Eq, PartialEq, PartialOrd, Ord, Hash, Clone, Copy)]
pub enum PeerType {
    IBGP,
    EBGP,
}

impl PeerType {
    pub fn is_ibgp(&self) -> bool {
        *self == PeerType::IBGP
    }

    pub fn is_ebgp(&self) -> bool {
        *self == PeerType::EBGP
    }

    pub fn to_str(self) -> &'static str {
        match self {
            Self::IBGP => "internal",
            Self::EBGP => "external",
        }
    }
}

#[derive(Debug, Default, Serialize, Clone)]
pub struct PeerParam {
    pub hold_time: u16,
    pub keepalive: u16,
    pub local_addr: Option<SocketAddr>,
    /// Remote endpoint of the session's TCP connection, captured with
    /// [`Self::local_addr`] when the primary conn comes up (and
    /// refreshed if a §6.8 collision conn is promoted). For a dialed
    /// session the port is the neighbor's configured `port` (default
    /// 179); for an accepted one it is the peer's ephemeral source
    /// port. Rendered as `Foreign host/port` by `show ip bgp neighbors`,
    /// mirroring FRR's `su_remote`.
    pub remote_addr: Option<SocketAddr>,
}

#[derive(Debug, Default)]
pub struct PeerStatEntry {
    tx: u64,
    rx: u64,
}

#[derive(Debug, Default)]
pub struct PeerStat(BTreeMap<AfiSafi, PeerStatEntry>);

impl PeerStat {
    pub fn clear(&mut self) {
        for (_, entry) in self.0.iter_mut() {
            entry.tx = 0;
            entry.rx = 0;
        }
    }

    pub fn rx(&self, afi: Afi, safi: Safi) -> u64 {
        let afi_safi = AfiSafi::new(afi, safi);
        if let Some(entry) = self.0.get(&afi_safi) {
            entry.rx
        } else {
            0
        }
    }

    pub fn tx(&self, afi: Afi, safi: Safi) -> u64 {
        let afi_safi = AfiSafi::new(afi, safi);
        if let Some(entry) = self.0.get(&afi_safi) {
            entry.tx
        } else {
            0
        }
    }

    pub fn rx_inc(&mut self, afi: Afi, safi: Safi) {
        let afi_safi = AfiSafi::new(afi, safi);
        let entry = self.0.entry(afi_safi).or_default();
        entry.rx += 1;
    }

    pub fn rx_dec(&mut self, afi: Afi, safi: Safi) {
        let afi_safi = AfiSafi::new(afi, safi);
        if let Some(entry) = self.0.get_mut(&afi_safi) {
            entry.rx -= 1;
        }
    }

    pub fn tx_inc(&mut self, afi: Afi, safi: Safi) {
        let afi_safi = AfiSafi::new(afi, safi);
        let entry = self.0.entry(afi_safi).or_default();
        entry.tx += 1;
    }

    pub fn tx_dec(&mut self, afi: Afi, safi: Safi) {
        let afi_safi = AfiSafi::new(afi, safi);
        if let Some(entry) = self.0.get_mut(&afi_safi) {
            entry.tx -= 1;
        }
    }
}

#[derive(Debug)]
pub struct Peer {
    pub ident: usize,
    pub address: IpAddr,
    /// Provenance of this peer — set to [`PeerOrigin::Static`] for
    /// peers configured by remote address; future commits will set
    /// `Interface { ifindex }` for unnumbered neighbors and
    /// `Dynamic { range_prefix }` for peers materialized on inbound
    /// accept by a configured listen-range.
    pub origin: PeerOrigin,
    /// IPv6 scope identifier for the outbound connect, populated for
    /// interface-keyed peers whose `address` is a link-local. The
    /// kernel rejects a `connect(2)` to `fe80::/10` without a scope,
    /// so this is the ifindex captured at materialization time
    /// (see [`super::interface_neighbor::materialize_peer`]). `None`
    /// for address-keyed peers — `connect(2)` treats the v4/v6 global
    /// case fine without it.
    pub scope_id: Option<u32>,
    /// Interface name for an interface-keyed (IPv6 unnumbered) peer —
    /// the operator-typed `interface-neighbor` list key, captured at
    /// materialization. It is the peer's operator-facing identity in
    /// `show`/`clear` output and lookups: the remote link-local in
    /// `address` is kernel-assigned and can change between RAs, so it
    /// is not something the operator can name. `None` for
    /// address-keyed peers.
    pub ifname: Option<String>,
    pub router_id: Ipv4Addr,
    pub local_identifier: Option<Ipv4Addr>,
    pub remote_id: Ipv4Addr,
    pub local_as: u32,
    pub remote_as: u32,
    /// Local BGP speaker's hostname snapshot used to populate the FQDN
    /// capability in OPEN. Set at peer creation from `Bgp::hostname()`
    /// and refreshed by the global hostname callback so that re-opened
    /// sessions advertise the latest value.
    pub local_hostname: Option<String>,
    /// Per-protocol runtime context cloned from the owning `Bgp`.
    /// Carries the VRF identity the active-connect path uses to
    /// build TCP sockets through `ctx.tcp_socket_v4` / `v6` —
    /// SO_BINDTODEVICE happens inside the context, never at the
    /// peer call site. `RibClient` is reachable via `ctx.rib` if
    /// any per-peer code ever needs to send to RIB directly (none
    /// do today).
    pub ctx: crate::context::ProtoContext,
    pub active: bool,
    /// Cached "the neighbor's address is on one of our directly-connected
    /// subnets" (FRR `shared_network`). Maintained by the owning instance
    /// from interface-address events (`Bgp::refresh_connected`) rather
    /// than recomputed in the FSM, because the active-connect decision in
    /// [`fsm_start`] only has `&mut Peer`. Reads `true` while the instance
    /// has no interface-address knowledge yet, so the connected check
    /// fails open (see [`super::connected::ConnectedSubnets`]). Consulted
    /// only by [`Peer::connected_check_ok`].
    pub shared_network: bool,
    pub peer_type: PeerType,
    pub state: State,
    pub task: PeerTask,
    pub timer: PeerTimer,
    pub counter: [PeerCounter; BgpType::Max as usize],
    pub as4: bool,
    pub param: PeerParam,
    pub param_tx: PeerParam,
    pub param_rx: PeerParam,
    pub packet_tx: Option<UnboundedSender<BytesMut>>,
    /// Origin of the current primary connection. `Some(Active)` if we
    /// initiated, `Some(Passive)` if peer initiated. `None` while we
    /// have no primary (Idle/Connect/Active states).
    pub primary_role: Option<Role>,
    /// Identity of the connection in the primary slot, kept in
    /// lockstep with `packet_tx` / `task.{reader,writer}` /
    /// `primary_role`. Events whose [`ConnId`] matches neither this
    /// nor the collision slot come from a dead connection and are
    /// ignored at dispatch ([`resolve_conn`]).
    pub primary_conn_id: Option<ConnId>,
    /// Allocator backing [`Self::alloc_conn_id`].
    pub conn_id_next: ConnId,
    /// Parallel TCP connection awaiting RFC 4271 §6.8 resolution. Set
    /// when an inbound connect arrives while we already have a primary
    /// in OpenSent/OpenConfirm; cleared (one way or the other) when the
    /// first OPEN on either connection lets us pick the winner.
    pub collision: Option<CollisionConn>,
    pub tx: mpsc::Sender<Message>,
    pub config: PeerConfig,
    pub cap_send: BgpCap,
    pub cap_recv: BgpCap,
    pub cap_map: CapAfiMap,
    pub adj_in: AdjRib<In>,
    pub adj_out: AdjRib<Out>,
    pub opt: ParseOption,
    pub policy_list: InOuts<PolicyListValue>,
    pub prefix_set: InOuts<PrefixSetValue>,
    pub rtcv4: BTreeSet<ExtCommunityValue>,
    pub rtcv6: BTreeSet<ExtCommunityValue>,
    pub eor: BTreeMap<AfiSafi, bool>,
    pub reflector_client: bool,
    pub instant: Option<Instant>,
    pub first_start: bool,
    pub cache_vpnv4: HashMap<Arc<BgpAttr>, HashSet<Vpnv4Nlri>>,
    pub cache_vpnv4_rev: HashMap<Vpnv4Nlri, Arc<BgpAttr>>,
    /// VPNv6 advertise cache — same per-attribute batching shape as
    /// `cache_vpnv4`.
    pub cache_vpnv6: HashMap<Arc<BgpAttr>, HashSet<Vpnv6Nlri>>,
    pub cache_vpnv6_rev: HashMap<Vpnv6Nlri, Arc<BgpAttr>>,
    pub cache_vpnv6_timer: Option<Timer>,
    /// EVPN advertise cache. Mirrors `cache_vpnv4` shape — NLRIs
    /// grouped by attribute so a single MP_REACH UPDATE on flush can
    /// carry every route that shares one attr set. Withdraw path uses
    /// the reverse map; not yet implemented in this PR.
    pub cache_evpn: HashMap<Arc<BgpAttr>, HashSet<EvpnRoute>>,
    pub cache_evpn_rev: HashMap<EvpnRoute, Arc<BgpAttr>>,
    pub cache_vpnv4_timer: Option<Timer>,
    pub cache_evpn_timer: Option<Timer>,
    // Runtime bookkeeping for TCP-AO listener state: the (send_id,
    // recv_id) pair most recently installed via TCP_AO_ADD_KEY for
    // this peer. Needed because TCP_AO_DEL_KEY requires the exact
    // IDs — we can't "wildcard-delete" by address. Cleared after a
    // successful removal or when no AO key is present for this
    // peer.
    pub last_ao_installed: Option<(u8, u8)>,
    /// Back-reference into `Bgp::update_groups`. One entry per AFI/SAFI
    /// the peer is in; written by `update_group::attach` on entering
    /// Established and cleared by `detach` on leaving. Empty otherwise.
    pub update_group_id: BTreeMap<AfiSafi, super::update_group::UpdateGroupId>,

    /// Snapshot of `Bgp::adv_interval` captured at peer construction
    /// and refreshed by the global config callback. Read by the VPNv4
    /// / EVPN adv-debounce timers (`start_adv_timer_vpnv4` /
    /// `start_adv_timer_evpn`) so the timer-arming path doesn't need
    /// to reach back into the global `Bgp`.
    pub adv_interval: timer::AdvInterval,

    /// The BFD [`SessionKey`] this peer currently has a live
    /// subscription for, or `None` if BFD is off. Runtime bookkeeping
    /// (not config): lets the reconcile path in `config::config_peer_bfd_*`
    /// unsubscribe the *old* key before subscribing a new one when the
    /// key changes (hop-mode flip, update-source change), so config
    /// callbacks that arrive in any order within a commit never leak or
    /// duplicate a session.
    pub bfd_session_key: Option<SessionKey>,

    /// The [`SessionParams`] sent with that subscription. Compared by
    /// `config::bfd_apply` so an Echo-param-only change (same key)
    /// re-sends `Subscribe`, which the BFD instance applies to the live
    /// session — without an Unsubscribe, which could tear the session
    /// down if we were its last subscriber.
    pub bfd_session_params: Option<SessionParams>,

    /// Per-neighbor conditional tracing config (zebra-bgp-tracing.yang
    /// `router bgp neighbor <addr> tracing`). Written by the tracing
    /// config dispatch; read (additively with `tracing_instance`) by
    /// the `trace_*` accessors the gated `bgp_*_trace!` macros call.
    pub tracing: super::tracing::BgpTracing,

    /// Snapshot of the instance-wide tracing config (`router bgp
    /// tracing`), refreshed at peer creation and whenever the instance
    /// config changes (`propagate_instance_tracing`). Per-neighbor
    /// tracing is *additive* to this, so the `trace_*` accessors OR the
    /// two — a peer with no per-neighbor config still gets instance
    /// tracing. Mirrors the `adv_interval` snapshot pattern.
    pub tracing_instance: super::tracing::BgpTracing,

    /// Negotiated TCP MSS read back from the session socket
    /// (`getsockopt(TCP_MAXSEG)`) at [`fsm_connected`] — the "synced"
    /// value `show bgp neighbor` reports next to the configured
    /// `tcp-mss`. Runtime bookkeeping, not config: captured once per
    /// connection (it is the kernel's cached `mss_cache`, fixed for the
    /// life of the socket) and only meaningful while Established, so the
    /// show path gates on state rather than clearing this on teardown.
    /// `None` until the first session comes up. See [`super::mss`].
    pub tcp_mss_synced: Option<u16>,
}

impl Peer {
    pub fn new(
        ident: usize,
        local_as: u32,
        router_id: Ipv4Addr,
        remote_as: u32,
        address: IpAddr,
        local_hostname: Option<String>,
        tx: mpsc::Sender<Message>,
        ctx: crate::context::ProtoContext,
    ) -> Self {
        let mut peer = Self {
            ident,
            router_id,
            local_as,
            remote_as,
            local_hostname,
            address,
            ctx,
            origin: PeerOrigin::Static,
            scope_id: None,
            ifname: None,
            active: false,
            // Fail open until the instance computes connectedness from
            // interface-address events (see `shared_network`).
            shared_network: true,
            peer_type: PeerType::IBGP,
            state: State::Idle,
            task: PeerTask::default(),
            timer: PeerTimer::default(),
            counter: [PeerCounter::default(); BgpType::Max as usize],
            tx,
            remote_id: Ipv4Addr::UNSPECIFIED,
            local_identifier: None,
            config: PeerConfig::default(),
            as4: true,
            param: PeerParam::default(),
            param_tx: PeerParam::default(),
            param_rx: PeerParam::default(),
            // stat: PeerStat::default(),
            packet_tx: None,
            primary_role: None,
            primary_conn_id: None,
            conn_id_next: 0,
            collision: None,
            cap_send: BgpCap::default(),
            cap_recv: BgpCap::default(),
            cap_map: CapAfiMap::new(),
            adj_in: AdjRib::new(),
            adj_out: AdjRib::new(),
            opt: ParseOption::default(),
            policy_list: InOuts::<PolicyListValue>::default(),
            prefix_set: InOuts::<PrefixSetValue>::default(),
            rtcv4: BTreeSet::default(),
            rtcv6: BTreeSet::default(),
            eor: BTreeMap::default(),
            reflector_client: false,
            instant: None,
            first_start: true,
            cache_vpnv4: HashMap::default(),
            cache_vpnv4_rev: HashMap::default(),
            cache_vpnv6: HashMap::default(),
            cache_vpnv6_rev: HashMap::default(),
            cache_vpnv6_timer: None,
            cache_evpn: HashMap::default(),
            cache_evpn_rev: HashMap::default(),
            cache_vpnv4_timer: None,
            cache_evpn_timer: None,
            last_ao_installed: None,
            update_group_id: BTreeMap::new(),
            adv_interval: timer::AdvInterval::default(),
            bfd_session_key: None,
            bfd_session_params: None,
            tracing: super::tracing::BgpTracing::default(),
            tracing_instance: super::tracing::BgpTracing::default(),
            tcp_mss_synced: None,
        };
        peer.config
            .mp
            .set(AfiSafi::new(Afi::Ip, Safi::Unicast), true);
        peer.config.four_octet = true;
        peer.config.route_refresh = true;
        // peer.config.graceful_restart = Some(65535);
        peer
    }

    pub fn event(&self, ident: usize, event: Event) {
        let _ = self.tx.clone().send(Message::Event(ident, event));
    }

    /// Mint the identity for a freshly spawned connection.
    pub fn alloc_conn_id(&mut self) -> ConnId {
        self.conn_id_next += 1;
        self.conn_id_next
    }

    pub fn is_passive(&self) -> bool {
        self.config.transport.passive
    }

    /// Operator-facing identity for `show`/`clear`: the interface name
    /// for an unnumbered (interface-keyed) peer, the remote address
    /// otherwise. FRR renders unnumbered peers the same way in
    /// `show bgp summary`.
    pub fn display_name(&self) -> String {
        match &self.ifname {
            Some(name) => name.clone(),
            None => self.address.to_string(),
        }
    }

    // ---- effective (instance ∪ per-neighbor) tracing checks --------
    // Per-neighbor tracing is additive to the instance config, so each
    // check ORs the peer's snapshot of the instance config
    // (`tracing_instance`) with its own per-neighbor config (`tracing`).
    // A peer with no per-neighbor config falls back to instance-only.

    pub fn trace_fsm(&self) -> bool {
        self.tracing_instance.should_trace_fsm() || self.tracing.should_trace_fsm()
    }

    pub fn trace_packet(&self, kind: PacketKind, dir: Direction) -> bool {
        self.tracing_instance.should_trace_packet(kind, dir)
            || self.tracing.should_trace_packet(kind, dir)
    }

    pub fn trace_packet_detail(&self, kind: PacketKind, dir: Direction) -> bool {
        self.tracing_instance.packet_detail(kind, dir) || self.tracing.packet_detail(kind, dir)
    }

    pub fn trace_adj_in(&self) -> bool {
        self.tracing_instance.should_trace_adj_in() || self.tracing.should_trace_adj_in()
    }

    pub fn trace_adj_out(&self) -> bool {
        self.tracing_instance.should_trace_adj_out() || self.tracing.should_trace_adj_out()
    }

    pub fn max_packet_size(&self) -> usize {
        if self.opt.extended_message {
            BGP_EXTENDED_PACKET_LEN
        } else {
            BGP_PACKET_LEN
        }
    }

    pub fn start(&mut self) {
        if self.remote_as != 0 && !self.address.is_unspecified() && !self.active {
            timer::update_timers(self);
            self.active = true;
        }
    }

    pub fn count_clear(&mut self) {
        for count in self.counter.iter_mut() {
            count.sent = 0;
            count.rcvd = 0;
        }
    }

    pub fn is_ebgp(&self) -> bool {
        self.peer_type.is_ebgp()
    }

    pub fn is_ibgp(&self) -> bool {
        self.peer_type.is_ibgp()
    }

    /// Egress IP TTL / IPv6 Hop Limit for this session, per the BGP TTL
    /// convention (matches FRR):
    ///   - `ttl-security` (GTSM) ⇒ 255 (also floors the ingress TTL —
    ///     see [`super::ttl`]);
    ///   - iBGP ⇒ 255 (peers are typically several IGP hops away);
    ///   - eBGP with `ebgp-multihop N` ⇒ N (peer up to N hops away);
    ///   - eBGP, directly connected (the default) ⇒ 1 (the peer must be
    ///     a single hop away — a router in the path drops the packet).
    ///
    /// `ebgp-multihop` is silently ignored on an iBGP peer (which already
    /// uses 255), mirroring FRR. ttl-security and ebgp-multihop cannot
    /// both be configured on one neighbor — the config callbacks reject
    /// the second (see `config_ttl_security` / `config_ebgp_multihop`) —
    /// so the ttl-security-before-ebgp-multihop ordering here is only a
    /// defensive fallback.
    pub fn session_ttl(&self) -> u8 {
        if self.config.transport.ttl_security || self.is_ibgp() {
            return super::ttl::MAX_TTL;
        }
        self.config
            .transport
            .ebgp_multihop
            .unwrap_or(super::ttl::DEFAULT_EBGP_TTL)
    }

    /// Whether the eBGP directly-connected-network check governs this
    /// peer. It governs exactly a single-hop eBGP session — eBGP with an
    /// egress TTL of 1, i.e. neither `ebgp-multihop` nor `ttl-security`
    /// (both raise the TTL and signal an intentionally non-adjacent peer)
    /// — that the operator has not exempted with `disable-connected-check`.
    /// iBGP, multihop/GTSM, unresolved (`0.0.0.0`/`::`) and link-local /
    /// unnumbered peers are never governed: the last two are on-link by
    /// construction. Mirrors FRR's `peer->sort == BGP_PEER_EBGP &&
    /// peer->ttl == BGP_DEFAULT_TTL && !PEER_FLAG_DISABLE_CONNECTED_CHECK`.
    pub fn connected_check_applies(&self) -> bool {
        self.is_ebgp()
            && self.session_ttl() == super::ttl::DEFAULT_EBGP_TTL
            && !self.config.transport.disable_connected_check
            && !self.address.is_unspecified()
            && !addr_is_v6_link_local(&self.address)
    }

    /// True when the directly-connected-network check is satisfied: either
    /// it does not apply to this peer (see [`Self::connected_check_applies`])
    /// or the neighbor sits on one of our connected subnets
    /// ([`Self::shared_network`], which also reads `true` when the instance
    /// has no interface-address knowledge yet — the check fails open).
    /// Consulted by [`fsm_start`] before dialing the peer.
    pub fn connected_check_ok(&self) -> bool {
        !self.connected_check_applies() || self.shared_network
    }

    /// Effective BFD hop mode for this neighbour: the explicit
    /// `bfd multihop` override if set, else inferred from the BGP
    /// session type (iBGP ⇒ multihop), mirroring FRR's
    /// `PEER_IS_MULTIHOP`. eBGP-over-loopback uses the explicit
    /// override until a dedicated `ebgp-multihop` knob exists.
    pub fn bfd_multihop(&self) -> bool {
        self.config.bfd.multihop.unwrap_or_else(|| self.is_ibgp())
    }

    pub fn is_reflector_client(&self) -> bool {
        self.reflector_client
    }

    /// Whether `afi-safi <name> next-hop-self` is set for this neighbor in
    /// the given address family. Forces next-hop-self on forwarded routes
    /// (not just eBGP / self-originated) — see [`PeerSubConfig::next_hop_self`].
    pub fn next_hop_self(&self, afi: Afi, safi: Safi) -> bool {
        self.config
            .sub
            .get(&AfiSafi::new(afi, safi))
            .map(|c| c.next_hop_self)
            .unwrap_or(false)
    }

    pub fn is_afi_safi(&self, afi: Afi, safi: Safi) -> bool {
        let afi = CapMultiProtocol::new(&afi, &safi);
        if let Some(cap) = self.cap_map.entries.get(&afi)
            && cap.send
            && cap.recv
        {
            return true;
        }
        false
    }

    /// The configured SRv6 `encapsulation-type` for this peer's IPv6
    /// unicast family (`afi-safi ipv6 encapsulation-type`), or `None`
    /// when unset. See [`AfiSafiEncapType`].
    pub fn ipv6_srv6_encap(&self) -> Option<AfiSafiEncapType> {
        self.config
            .sub
            .get(&AfiSafi::new(Afi::Ip6, Safi::Unicast))
            .and_then(|s| s.encapsulation_type)
    }

    /// `true` when this peer is SRv6-strict for IPv6 unicast
    /// (`encapsulation-type srv6`): a plain IPv6 unicast route without
    /// an SRv6 service SID must not be advertised to / accepted from it.
    /// `srv6-relax` and the unset default both return `false` (no
    /// SID-presence filtering).
    pub fn ipv6_srv6_strict(&self) -> bool {
        matches!(self.ipv6_srv6_encap(), Some(AfiSafiEncapType::Srv6))
    }

    /// IPv6 link-local next-hop to advertise in MP_REACH for
    /// IPv4-unicast NLRI once RFC 8950 Extended Next Hop is
    /// negotiated on this peer. Returns `None` for any peer that
    /// isn't interface-keyed, or when the egress interface's
    /// link-local hasn't been observed yet via `RibRx::AddrAdd`.
    /// Callers should pair this with [`Self::is_enhe_v4_negotiated`]
    /// before emitting.
    pub fn next_hop_v6(
        &self,
        addrs: &super::interface_addrs::InterfaceAddrs,
    ) -> Option<std::net::Ipv6Addr> {
        if !matches!(self.origin, PeerOrigin::Interface { .. }) {
            return None;
        }
        addrs.link_local_for(self.scope_id?)
    }

    /// Global IPv6 next-hop for the egress interface, or `None` if
    /// none is registered (pure-unnumbered links typically have no
    /// global v6). When this returns `Some` and
    /// [`Self::next_hop_v6`] also returns `Some`, the encoder emits
    /// the RFC 8950 32-octet `global || link-local` form; otherwise
    /// it emits the 16-octet link-local-only form.
    pub fn next_hop_v6_global(
        &self,
        addrs: &super::interface_addrs::InterfaceAddrs,
    ) -> Option<std::net::Ipv6Addr> {
        if !matches!(self.origin, PeerOrigin::Interface { .. }) {
            return None;
        }
        addrs.global_for(self.scope_id?)
    }

    /// True iff both directions of the BGP capability exchange
    /// advertised RFC 8950 Extended Next Hop for (IPv4-unicast,
    /// IPv6 next-hop). Mirrors the per-AFI/SAFI gate used by
    /// `update_group::signature_of` so the encoder and the
    /// update-group accounting agree on what's negotiated.
    pub fn is_enhe_v4_negotiated(&self) -> bool {
        let sent = self
            .cap_send
            .extended_nexthop
            .as_ref()
            .is_some_and(|c| c.supports_v6_nexthop_for_ipv4_unicast());
        let received = self
            .cap_recv
            .extended_nexthop
            .as_ref()
            .is_some_and(|c| c.supports_v6_nexthop_for_ipv4_unicast());
        sent && received
    }
}

pub struct BgpTop<'a> {
    pub router_id: &'a Ipv4Addr,
    pub local_rib: &'a mut LocalRib,
    pub tx: &'a mpsc::Sender<Message>,
    pub rib_client: &'a crate::rib::client::RibClient,
    pub attr_store: &'a mut BgpAttrStore,
    pub update_groups: &'a mut super::update_group::UpdateGroupMap,
    /// Per-ifindex IPv6 link-local registry, used to resolve the v6
    /// next-hop for RFC 8950 IPv4-over-IPv6 emit on interface peers.
    pub interface_addrs: &'a super::interface_addrs::InterfaceAddrs,
    /// Per-VRF export hook. `None` when the runtime is the global
    /// `Bgp` (no VPNv4 export happens from default-VRF traffic);
    /// `Some(...)` when running inside a `BgpVrf` task — the
    /// shared route pipeline calls `vrf_emit_export` /
    /// `vrf_emit_withdraw` on best-path transitions so the global
    /// instance's VPNv4 LocRIB picks them up.
    pub vrf_export: Option<&'a super::vrf::VrfExporter>,
    /// VRF import dispatcher. Inverse of `vrf_export`: `Some(...)`
    /// in the global `Bgp` task; the v4vpn ingest path fans
    /// incoming routes out to every VRF whose `import_rts_v4`
    /// intersects the route's RT extcomms via
    /// `BgpVrfMsg::ImportV4`. `None` inside per-VRF tasks (they
    /// never receive VPNv4 NLRI directly).
    pub vrf_import: Option<&'a super::vrf::VrfImportDispatcher<'a>>,
    /// Next-Hop Tracking cache. `Some(...)` only in the global `Bgp`
    /// task (it owns the `rib_rx` stream that delivers
    /// `RibRx::NexthopUpdate`); the received-route path registers
    /// next-hops here and gates best-path on their resolution. `None`
    /// in per-VRF tasks and the local-origination/advertise BgpTops
    /// (no gating there).
    pub nexthop_cache: Option<&'a mut super::nht::NexthopCache>,
    /// Per-VRF imported-route transport maps, keyed by prefix. `Some`
    /// only inside a `BgpVrf` task; they let `fib_install_v4`/`v6`
    /// program an imported VPN winner's `{transport,service}` labelled
    /// tunnel entry instead of the plain next-hop entry, so CE-learned
    /// and imported routes arbitrate through one install path. `None`
    /// on the global instance (plain unicast / VPN take other paths).
    pub vrf_transport_v4: Option<
        &'a std::collections::BTreeMap<ipnet::Ipv4Net, Vec<crate::rib::nht::ResolvedNexthop>>,
    >,
    pub vrf_transport_v6: Option<
        &'a std::collections::BTreeMap<ipnet::Ipv6Net, Vec<crate::rib::nht::ResolvedNexthop>>,
    >,
    /// Colour-aware nexthop resolver inputs. Optional because
    /// per-VRF BGP runtimes don't carry them today — Color →
    /// Flex-Algo binding is a default-VRF concept; per-VRF support
    /// is a follow-up. `None` short-circuits the resolver to
    /// "no Color-based label push".
    pub color_policy: Option<&'a super::color_policy::ColorPolicy>,
    pub flex_algo_routes: Option<
        &'a std::collections::BTreeMap<
            u8,
            prefix_trie::PrefixMap<ipnet::Ipv4Net, crate::rib::api::FlexAlgoNexthop>,
        >,
    >,
    /// BGP Labeled-Unicast (SAFI 4) local-label allocation context.
    /// `Some` only in the receive `BgpTop` (the site that ingests
    /// received routes); `None` in every advertise / originate / NHT
    /// BgpTop — self-originated FECs advertise implicit-null and need no
    /// local label. A received route advertised with next-hop-self gets
    /// a local label here, swap-programmed via an ILM.
    pub lu_labels: Option<LuLabels<'a>>,
    /// Precomputed global-IPv6 SRv6 export data (`segment-routing srv6
    /// ipv6-unicast`), borrowed from the owning [`super::inst::Bgp`].
    /// `Some` only when origination is enabled and the locator has
    /// resolved; the egress path (`route_update_ipv6`) then stamps
    /// locally-originated routes with its End.DT6 Prefix-SID + locator
    /// next-hop. `None` on per-VRF tasks and whenever origination is off.
    pub srv6_ipv6_export: Option<&'a super::inst::Srv6Ipv6Export>,
}

/// Per-prefix local-label state for BGP Labeled Unicast, borrowed into
/// the receive [`BgpTop`]. Labels are drawn from the shared dynamic-label
/// allocator (the same pool that serves per-VRF labels).
pub struct LuLabels<'a> {
    pub alloc: &'a mut Option<super::vrf::VrfLabelAllocator>,
    pub v4: &'a mut std::collections::BTreeMap<ipnet::Ipv4Net, u32>,
    pub v6: &'a mut std::collections::BTreeMap<ipnet::Ipv6Net, u32>,
    /// Per-`(RD, prefix)` local labels for received VPNv4 (SAFI 128)
    /// routes — the Inter-AS Option B transit case. A transit ASBR that
    /// re-advertises a VPNv4 route with next-hop-self advertises this
    /// label and swap-programs it (our label → received label) via an
    /// ILM, so the VPN crosses the AS boundary on MPLS. The RD is part
    /// of the key because the same IP prefix can live in many VPNs.
    pub vpn_v4: &'a mut std::collections::BTreeMap<(RouteDistinguisher, ipnet::Ipv4Net), u32>,
}

impl LuLabels<'_> {
    /// Local label for an IPv4 LU prefix, allocating one on first use.
    /// `None` if the dynamic pool is empty (the caller advertises the
    /// received label as a fallback until a block is granted).
    pub fn label_v4(&mut self, prefix: ipnet::Ipv4Net) -> Option<u32> {
        if let Some(l) = self.v4.get(&prefix) {
            return Some(*l);
        }
        let label = self.alloc.as_mut().and_then(|a| a.alloc())?;
        self.v4.insert(prefix, label);
        Some(label)
    }

    /// Local label for a received VPNv4 `(RD, prefix)`, allocating one on
    /// first use. Mirrors [`label_v4`](Self::label_v4); `None` until a
    /// dynamic block is granted (the caller advertises the received
    /// label until then).
    pub fn label_vpn_v4(&mut self, rd: RouteDistinguisher, prefix: ipnet::Ipv4Net) -> Option<u32> {
        if let Some(l) = self.vpn_v4.get(&(rd, prefix)) {
            return Some(*l);
        }
        let label = self.alloc.as_mut().and_then(|a| a.alloc())?;
        self.vpn_v4.insert((rd, prefix), label);
        Some(label)
    }

    /// Release the label for a withdrawn VPNv4 `(RD, prefix)`; returns it
    /// so the caller can tear down the swap ILM.
    pub fn free_vpn_v4(&mut self, rd: RouteDistinguisher, prefix: ipnet::Ipv4Net) -> Option<u32> {
        let label = self.vpn_v4.remove(&(rd, prefix))?;
        if let Some(a) = self.alloc.as_mut() {
            a.free(label);
        }
        Some(label)
    }

    pub fn label_v6(&mut self, prefix: ipnet::Ipv6Net) -> Option<u32> {
        if let Some(l) = self.v6.get(&prefix) {
            return Some(*l);
        }
        let label = self.alloc.as_mut().and_then(|a| a.alloc())?;
        self.v6.insert(prefix, label);
        Some(label)
    }

    /// Release the label for a withdrawn IPv4 LU prefix; returns it so
    /// the caller can tear down the swap ILM.
    pub fn free_v4(&mut self, prefix: ipnet::Ipv4Net) -> Option<u32> {
        let label = self.v4.remove(&prefix)?;
        if let Some(a) = self.alloc.as_mut() {
            a.free(label);
        }
        Some(label)
    }

    pub fn free_v6(&mut self, prefix: ipnet::Ipv6Net) -> Option<u32> {
        let label = self.v6.remove(&prefix)?;
        if let Some(a) = self.alloc.as_mut() {
            a.free(label);
        }
        Some(label)
    }
}

/// Resolve a connection identity against the peer's current slots.
/// `None` means the event came from a connection that owns no slot —
/// it was torn down or superseded (e.g. the §6.8 loser whose last
/// events were still queued) — and the FSM must ignore it.
fn resolve_conn(peer: &Peer, id: ConnId) -> Option<ConnTag> {
    if peer.primary_conn_id == Some(id) {
        Some(ConnTag::Primary)
    } else if peer.collision.as_ref().map(|c| c.conn_id) == Some(id) {
        Some(ConnTag::Collision)
    } else {
        if peer.trace_fsm() {
            tracing::info!(
                peer = %peer.address,
                conn_id = id,
                "bgp: ignoring event from a superseded connection",
            );
        }
        None
    }
}

pub fn fsm_next_state(peer: &mut Peer, event: Event) -> (State, FsmEffect) {
    match event {
        Event::ConfigUpdate => (peer.state, FsmEffect::None),
        Event::Start => (fsm_start(peer), FsmEffect::None),
        Event::Stop => (fsm_stop(peer), FsmEffect::None),
        Event::ConnRetryTimerExpires => (fsm_conn_retry_expires(peer), FsmEffect::None),
        Event::HoldTimerExpires => (fsm_holdtimer_expires(peer), FsmEffect::None),
        Event::KeepaliveTimerExpires => (fsm_keepalive_expires(peer), FsmEffect::None),
        Event::IdleHoldTimerExpires => (fsm_idle_hold_timer_expires(peer), FsmEffect::None),
        Event::Connected(stream) => (fsm_connected(peer, Role::Active, stream), FsmEffect::None),
        Event::ConnFail(id) => match resolve_conn(peer, id) {
            Some(conn) => (fsm_conn_fail(peer, conn), FsmEffect::None),
            None => (peer.state, FsmEffect::None),
        },
        Event::DialFail => (fsm_dial_fail(peer), FsmEffect::None),
        Event::BGPOpen(id, packet) => match resolve_conn(peer, id) {
            Some(conn) => (fsm_bgp_open(peer, conn, packet), FsmEffect::None),
            None => (peer.state, FsmEffect::None),
        },
        Event::NotifMsg(id, packet) => match resolve_conn(peer, id) {
            Some(conn) => (fsm_bgp_notification(peer, conn, packet), FsmEffect::None),
            None => (peer.state, FsmEffect::None),
        },
        Event::KeepAliveMsg(id) => match resolve_conn(peer, id) {
            Some(conn) => (fsm_bgp_keepalive(peer, conn), FsmEffect::None),
            None => (peer.state, FsmEffect::None),
        },
        Event::UpdateMsg(packet) => {
            peer.counter[BgpType::Update as usize].rcvd += 1;
            timer::refresh_hold_timer(peer);
            (State::Established, FsmEffect::RouteUpdate(packet))
        }
        Event::RouteRefreshMsg(afi, safi) => {
            peer.counter[BgpType::RouteRefresh as usize].rcvd += 1;
            timer::refresh_hold_timer(peer);
            (peer.state, FsmEffect::RouteRefreshRecv { afi, safi })
        }
        Event::StaleTimerExipires(afi_safi) => {
            peer.timer.stale_timer.remove(&afi_safi);
            (peer.state, FsmEffect::StaleExpire(afi_safi))
        }
        Event::AdvTimerVpnv4Expires => (fsm_adv_timer_vpnv4_expires(peer), FsmEffect::None),
        Event::AdvTimerVpnv6Expires => (fsm_adv_timer_vpnv6_expires(peer), FsmEffect::None),
        Event::AdvTimerEvpnExpires => (fsm_adv_timer_evpn_expires(peer), FsmEffect::None),
    }
}

fn fsm_effect(id: usize, effect: FsmEffect, bgp: &mut BgpTop, peers: &mut PeerMap) {
    match effect {
        FsmEffect::None => {}
        FsmEffect::RouteUpdate(packet) => {
            route_from_peer(id, packet, bgp, peers);
        }
        FsmEffect::StaleExpire(_afi_safi) => {
            stale_route_withdraw(id, bgp, peers);
        }
        FsmEffect::RouteRefreshRecv { afi: _, safi: _ } => {
            super::route::route_soft_out_peer(id, bgp, peers);
        }
    }
}

pub fn fsm(bgp_ref: &mut BgpTop, peer_map: &mut PeerMap, id: usize, event: Event) {
    // Compute new state (single match, only &mut Peer).
    let (prev_state, effect) = {
        let peer = peer_map.get_mut_by_idx(id).unwrap();
        let prev_state = peer.state;
        let (new_state, effect) = fsm_next_state(peer, event);
        peer.state = new_state;
        (prev_state, effect)
    };

    // Execute side effects that need peer_map.
    fsm_effect(id, effect, bgp_ref, peer_map);

    // Handle state-transition consequences.
    {
        let peer = peer_map.get_mut_by_idx(id).unwrap();
        if prev_state == peer.state {
            return;
        }
        if prev_state.is_established() && !peer.state.is_established() {
            peer.instant = Some(Instant::now());
        }
        if !prev_state.is_established() && peer.state.is_established() {
            peer.instant = Some(Instant::now());
            route_sync(peer, bgp_ref);
        }
        timer::update_timers(peer);
    }

    // route_clean if leaving Established (needs peer_map).
    if prev_state.is_established() && !peer_map.get_by_idx(id).unwrap().state.is_established() {
        route_clean(id, bgp_ref, peer_map);
    }

    // Maintain update-group membership across the Established
    // boundary. Detach must run *after* route_clean so observability
    // sees the peer leave the group only once routes have been torn
    // down; attach runs after route_sync so the group reflects the
    // post-sync state.
    {
        let now_established = peer_map
            .get_by_idx(id)
            .map(|p| p.state.is_established())
            .unwrap_or(false);
        if prev_state.is_established() && !now_established {
            super::update_group::detach(bgp_ref.update_groups, peer_map, id);
        } else if !prev_state.is_established() && now_established {
            super::update_group::attach(bgp_ref.update_groups, peer_map, id);
        }
    }
}

pub fn fsm_adv_timer_vpnv4_expires(peer: &mut Peer) -> State {
    peer.cache_vpnv4_timer = None;
    peer.flush_vpnv4();
    State::Established
}

pub fn fsm_adv_timer_vpnv6_expires(peer: &mut Peer) -> State {
    peer.cache_vpnv6_timer = None;
    peer.flush_vpnv6();
    State::Established
}

pub fn fsm_adv_timer_evpn_expires(peer: &mut Peer) -> State {
    peer.cache_evpn_timer = None;
    peer.flush_evpn();
    State::Established
}

/// `fe80::/10` test (RFC 4291 §2.5.6). `Ipv6Addr::is_unicast_link_local`
/// is still unstable, so open-code it. A link-local / unnumbered peer is
/// directly attached by construction and is never subject to the eBGP
/// connected check.
fn addr_is_v6_link_local(addr: &IpAddr) -> bool {
    matches!(addr, IpAddr::V6(a) if (a.segments()[0] & 0xffc0) == 0xfe80)
}

pub fn fsm_start(peer: &mut Peer) -> State {
    peer.first_start = false;
    // eBGP directly-connected-network check: a single-hop eBGP peer that
    // is not on a connected subnet must not be dialed unless the operator
    // set `disable-connected-check`. FRR gates the same case through NHT;
    // we hold the active connection in Active and re-evaluate on the
    // connect-retry timer. The instance also re-kicks us with Event::Start
    // the moment a connected route to the peer appears
    // (`Bgp::refresh_connected`), and a relevant config change bounces the
    // peer through its callback — so the connect-retry tick is only a
    // backstop.
    if !peer.connected_check_ok() {
        if peer.trace_fsm() {
            tracing::info!(
                peer = %peer.address,
                "bgp: holding eBGP session — neighbor is not on a connected network and disable-connected-check is off",
            );
        }
        peer.timer.connect_retry = Some(timer::start_connect_retry_timer(peer));
        return State::Active;
    }
    peer.task.connect = Some(peer_start_connection(peer));
    // RFC 4271: the ConnectRetryTimer runs while we dial — started on
    // leaving Idle, restarted on every redial. If it expires before
    // the dial resolves (a blackholed SYN), its Event::Start lands
    // back here and replaces the stuck dial.
    peer.timer.connect_retry = Some(timer::start_connect_retry_timer(peer));
    State::Connect
}

pub fn fsm_stop(_peer: &mut Peer) -> State {
    State::Idle
}

pub fn capability_as4(caps: &[CapabilityPacket]) -> Option<u32> {
    for cap in caps.iter() {
        if let CapabilityPacket::As4(m) = cap {
            return Some(m.asn);
        }
    }
    None
}

pub fn open_asn(packet: &OpenPacket) -> u32 {
    if let Some(as4) = &packet.bgp_cap.as4 {
        as4.asn
    } else {
        packet.asn as u32
    }
}

/// RFC 4271 §6.8 — which side's connection survives. The connection
/// initiated by the higher-BGP-Identifier endpoint wins. On a tie
/// (misconfig — duplicate BGP IDs) we deterministically keep the
/// passive side so both ends converge on the same choice.
pub fn collision_winner(local_id: Ipv4Addr, remote_id: Ipv4Addr) -> Role {
    let local = u32::from(local_id);
    let remote = u32::from(remote_id);
    if local > remote {
        Role::Active
    } else {
        Role::Passive
    }
}

/// Send a NOTIFICATION on the collision conn's packet_tx and drop the
/// conn (its reader/writer tasks exit when the stream closes). Used to
/// tear down the loser of §6.8 resolution.
fn close_collision(collision: CollisionConn, code: NotifyCode, sub_code: u8) {
    let notif = NotificationPacket::new(code, sub_code, Vec::new());
    let bytes: BytesMut = notif.into();
    let _ = collision.packet_tx.send(bytes);
    // Dropping the CollisionConn drops packet_tx (writer task drains
    // its channel and exits) and the reader/writer task handles
    // (cancelling them).
    drop(collision);
}

/// Tear down the primary connection in place (send NOTIFICATION first,
/// then drop the reader/writer/packet_tx triple).
fn close_primary(peer: &mut Peer, code: NotifyCode, sub_code: u8) {
    peer_send_notification(peer, code, sub_code, Vec::new());
    peer.packet_tx = None;
    peer.task.reader = None;
    peer.task.writer = None;
    peer.primary_role = None;
    peer.primary_conn_id = None;
}

/// Move the collision conn into the primary slot. Caller is
/// responsible for having already torn down the previous primary.
/// Transferring `conn_id` is what re-routes the promoted conn's
/// events: from here on they resolve to `ConnTag::Primary` at
/// dispatch, so its KEEPALIVEs refresh the hold timer and its death
/// tears the session down — the two things the §6.8 winner's conn
/// silently lost when its role tag was baked in at spawn.
fn promote_collision_to_primary(peer: &mut Peer, collision: CollisionConn) {
    peer.packet_tx = Some(collision.packet_tx);
    peer.task.reader = Some(collision.reader);
    peer.task.writer = Some(collision.writer);
    peer.primary_role = Some(collision.role);
    peer.primary_conn_id = Some(collision.conn_id);
    // Show the surviving connection's endpoints, not the dead
    // primary's (the collision conn is always accepted, so its
    // local port is the listen port and its remote port ephemeral).
    if collision.local_addr.is_some() {
        peer.param.local_addr = collision.local_addr;
    }
    if collision.remote_addr.is_some() {
        peer.param.remote_addr = collision.remote_addr;
    }
}

pub fn fsm_bgp_open(peer: &mut Peer, conn: ConnTag, packet: OpenPacket) -> State {
    peer.counter[BgpType::Open as usize].rcvd += 1;

    // Peer ASN.
    let asn = open_asn(&packet);

    // Compare with configured asn.
    if peer.remote_as != asn {
        // The OPEN that fails this check came on `conn`. For Primary
        // this matches today's behaviour. For Collision we just tear
        // the collision conn down and stay in our current state — the
        // primary conn is unaffected.
        if conn == ConnTag::Collision
            && let Some(collision) = peer.collision.take()
        {
            close_collision(
                collision,
                NotifyCode::OpenMsgError,
                OpenError::BadPeerAS.into(),
            );
            return peer.state;
        }
        peer_send_notification(
            peer,
            NotifyCode::OpenMsgError,
            OpenError::BadPeerAS.into(),
            Vec::new(),
        );
        return State::Idle;
    }

    if peer.state != State::OpenSent && peer.state != State::OpenConfirm {
        // OPEN in an unexpected state — discard.
        return peer.state;
    }
    if packet.asn as u32 != peer.remote_as {
        // Send notification.
        return State::Idle;
    }
    if packet.hold_time > 0 && packet.hold_time < 3 {
        return State::Idle;
    }
    let remote_id = Ipv4Addr::new(
        packet.bgp_id[0],
        packet.bgp_id[1],
        packet.bgp_id[2],
        packet.bgp_id[3],
    );

    // RFC 4271 §6.8 collision resolution. If we have both a primary
    // and a collision connection at the moment this OPEN arrives, the
    // peer's BGP Identifier (just learned) tells us which side's
    // connection should survive.
    if let Some(collision) = peer.collision.take() {
        let local_id = peer.local_identifier.unwrap_or(peer.router_id);
        let winner_role = collision_winner(local_id, remote_id);
        let arriving_role = match conn {
            ConnTag::Primary => peer.primary_role.unwrap_or(Role::Active),
            ConnTag::Collision => collision.role,
        };
        if winner_role != arriving_role {
            // OPEN came on the loser. Close it, keep the other conn
            // alive, and stay in OpenSent waiting for the winner's
            // OPEN to arrive.
            match conn {
                ConnTag::Primary => {
                    // The arriving conn (primary) loses; promote the
                    // collision (winner) to primary.
                    close_primary(peer, NotifyCode::Cease, 7); // ConnectionCollisionResolution
                    promote_collision_to_primary(peer, collision);
                }
                ConnTag::Collision => {
                    // The arriving conn (collision) loses; just drop it.
                    close_collision(collision, NotifyCode::Cease, 7);
                }
            }
            return State::OpenSent;
        }
        // Arriving conn is the winner. Close the other conn and
        // continue processing this OPEN.
        match conn {
            ConnTag::Primary => {
                // Primary wins, collision loses.
                close_collision(collision, NotifyCode::Cease, 7);
            }
            ConnTag::Collision => {
                // Collision wins, primary loses. Tear down primary,
                // then move collision into the primary slot so the
                // rest of fsm_bgp_open writes to the right tx.
                close_primary(peer, NotifyCode::Cease, 7);
                promote_collision_to_primary(peer, collision);
            }
        }
    } else if conn == ConnTag::Collision {
        // OPEN arrived on a collision conn that the peer has already
        // forgotten about (e.g. a race where conn_fail cleared the
        // slot first). Discard.
        return peer.state;
    }

    peer.remote_id = remote_id;

    timer::update_open_timers(peer, &packet);

    // Register recv caps.
    cap_register_recv(&packet.bgp_cap, &mut peer.cap_map);

    // Register add path caps.
    cap_addpath_recv(&packet.bgp_cap, &mut peer.opt, &peer.config.addpath);

    // Extended message negotiation (RFC 8654).
    if peer.cap_send.extended.is_some() && packet.bgp_cap.extended.is_some() {
        peer.opt.extended_message = true;
    }

    // Record received capability.
    peer.cap_recv = packet.bgp_cap;

    // Per RFC 4271 §8.2.2, after validating the peer's OPEN we send
    // KEEPALIVE and transition to OpenConfirm. The
    // OpenConfirm→Established move happens when the peer's KEEPALIVE
    // is received (handled in `fsm_bgp_keepalive`).
    peer_send_keepalive(peer);
    State::OpenConfirm
}

pub fn fsm_bgp_notification(peer: &mut Peer, conn: ConnTag, _packet: NotificationPacket) -> State {
    peer.counter[BgpType::Notification as usize].rcvd += 1;
    // NOTIFICATION on the collision conn just kills that conn; the
    // primary session is unaffected.
    if conn == ConnTag::Collision
        && let Some(collision) = peer.collision.take()
    {
        drop(collision);
        return peer.state;
    }
    // NOTIFICATION on the primary tears the session down. Also drop
    // any pending collision conn — the peer is asking us to stop.
    if let Some(collision) = peer.collision.take() {
        drop(collision);
    }
    State::Idle
}

pub fn fsm_bgp_keepalive(peer: &mut Peer, conn: ConnTag) -> State {
    peer.counter[BgpType::Keepalive as usize].rcvd += 1;
    // KEEPALIVE on a collision conn before §6.8 has resolved is
    // meaningless to us (we haven't decided whether to keep the conn).
    // Ignore it; the resolution will happen when an OPEN arrives.
    if conn == ConnTag::Collision {
        return peer.state;
    }
    timer::refresh_hold_timer(peer);
    match peer.state {
        // RFC 4271 §8.2.2: KEEPALIVE in OpenConfirm completes the
        // handshake and moves us to Established.
        State::OpenConfirm | State::Established => State::Established,
        // KEEPALIVE arriving in any other state is unexpected. The
        // FSM should ignore it here rather than spuriously promote;
        // stricter handling (tear down to Idle) is deferred.
        other => other,
    }
}

/// Apply this session's TTL policy to a freshly-connected socket, once
/// the TCP handshake is complete and before OPEN is sent. eBGP is pinned
/// to TTL 1 (directly connected) unless `ebgp-multihop` raises it; iBGP
/// and `ttl-security` use 255. For a `ttl-security` neighbor the accepted
/// ingress TTL is additionally floored at 255 (GTSM, RFC 5082) — done
/// here, post-handshake, so it never drops the peer's default-TTL
/// SYN-ACK. setsockopt failures are logged, not fatal.
///
/// Called from **every** path that turns a `TcpStream` into a live BGP
/// connection: the active Connected event and passive accept (both via
/// [`fsm_connected`]) **and** the RFC 4271 §6.8 collision connection
/// ([`start_collision_conn`]). The collision path is easy to miss — a
/// promoted collision conn that skipped this would carry the OS-default
/// TTL and no ingress floor, silently defeating GTSM / ebgp-multihop.
fn apply_session_ttl(peer: &Peer, stream: &TcpStream) {
    use std::os::fd::AsRawFd;
    let fd = stream.as_raw_fd();
    let is_v4 = peer.address.is_ipv4();
    if let Err(e) = super::ttl::set_egress_ttl(fd, is_v4, peer.session_ttl()) {
        tracing::warn!(
            peer = %peer.address,
            error = %e,
            "bgp: failed to set egress TTL on session socket",
        );
    }
    if peer.config.transport.ttl_security
        && let Err(e) = super::ttl::set_min_ttl(fd, is_v4, super::ttl::MAX_TTL)
    {
        tracing::warn!(
            peer = %peer.address,
            error = %e,
            "bgp: failed to set GTSM ingress TTL floor on session socket; continuing without it",
        );
    }
}

/// Read back the kernel's negotiated TCP MSS (`getsockopt(TCP_MAXSEG)`)
/// on the freshly established `stream` and record it on the peer as the
/// "synced" MSS shown by `show bgp neighbor`. The connection's MSS was
/// fixed during the TCP handshake (the configured `tcp-mss` is applied
/// pre-connect / on the listener), so one read per connection captures
/// it for the socket's life. Best-effort: a failure leaves the previous
/// value untouched (logged at debug).
fn record_session_mss(peer: &mut Peer, stream: &TcpStream) {
    use std::os::fd::AsRawFd;
    match super::mss::get_tcp_mss(stream.as_raw_fd()) {
        Ok(mss) => peer.tcp_mss_synced = Some(mss),
        Err(e) => {
            tracing::debug!(
                peer = %peer.address,
                error = %e,
                "bgp: failed to read synced TCP MSS on session socket",
            );
        }
    }
}

pub fn fsm_connected(peer: &mut Peer, role: Role, stream: TcpStream) -> State {
    // RFC 4271: Idle refuses all connections (the accept path already
    // drops inbound streams in Idle — see `handle_peer_connection`).
    // A Connected event can still arrive here from a dial whose
    // completion was queued just before the peer fell back to Idle;
    // promoting it would resurrect a session the FSM has torn down,
    // bypassing the idle hold damping.
    if peer.state == State::Idle {
        drop(stream);
        return State::Idle;
    }
    if let Ok(local_addr) = stream.local_addr() {
        peer.param.local_addr = Some(local_addr);
    }
    if let Ok(remote_addr) = stream.peer_addr() {
        peer.param.remote_addr = Some(remote_addr);
    }
    apply_session_ttl(peer, &stream);
    record_session_mss(peer, &stream);
    peer.task.connect = None;
    let conn_id = peer.alloc_conn_id();
    let (packet_tx, packet_rx) = mpsc::unbounded_channel::<BytesMut>();
    peer.packet_tx = Some(packet_tx);
    peer.primary_role = Some(role);
    peer.primary_conn_id = Some(conn_id);
    let (read_half, write_half) = stream.into_split();
    peer.task.reader = Some(peer_start_reader(peer, conn_id, read_half));
    peer.task.writer = Some(peer_start_writer(write_half, packet_rx));
    peer_send_open(peer);
    State::OpenSent
}

pub fn fsm_conn_retry_expires(peer: &mut Peer) -> State {
    peer.task.connect = Some(peer_start_connection(peer));
    State::Connect
}

pub fn fsm_holdtimer_expires(peer: &mut Peer) -> State {
    peer_send_notification(peer, NotifyCode::HoldTimerExpired, 0, Vec::new());
    State::Idle
}

pub fn fsm_idle_hold_timer_expires(peer: &mut Peer) -> State {
    peer.timer.idle_hold_timer = None;
    peer.task.connect = Some(peer_start_connection(peer));
    State::Connect
}

pub fn fsm_keepalive_expires(peer: &mut Peer) -> State {
    // tracing::info!("Send keepalive {}", peer.ident);
    peer_send_keepalive(peer);
    // The keepalive *send* timer fires in both OpenConfirm and
    // Established (it is armed by `update_open_timers` after we
    // receive the peer's OPEN). It must not drive a transition —
    // sending a KEEPALIVE does not promote us to Established, the
    // peer's KEEPALIVE does.
    peer.state
}

/// An active dial failed before any connection existed (so no
/// [`ConnId`] was minted). Only an outstanding dial — Connect state —
/// can fail this way; a stale failure from a dial that an accept or a
/// teardown already superseded must not disturb the current session.
///
/// RFC 4271 Connect state, TcpConnectionFails (Event 18): restart the
/// ConnectRetryTimer, keep listening for the remote's connect, and go
/// to Active. The timer's Event::Start redials from there. Passive
/// peers don't redial — they park in Active listening.
pub fn fsm_dial_fail(peer: &mut Peer) -> State {
    if peer.state != State::Connect {
        return peer.state;
    }
    peer.task.connect = None;
    peer.timer.connect_retry = if peer.is_passive() {
        None
    } else {
        Some(timer::start_connect_retry_timer(peer))
    };
    State::Active
}

pub fn fsm_conn_fail(peer: &mut Peer, conn: ConnTag) -> State {
    // A failure on the collision conn just drops the collision slot;
    // the primary session is unaffected.
    if conn == ConnTag::Collision {
        if let Some(collision) = peer.collision.take() {
            drop(collision);
        }
        return peer.state;
    }
    // Primary conn failed. A parked collision conn is closed, not
    // promoted. Historically promotion here caused a permanent wedge
    // because the promoted conn's events were misrouted (the role tag
    // was baked into its reader at spawn — see the `ConnId` doc);
    // dispatch-time resolution has since fixed that for the
    // legitimate §6.8 promotion. Close-and-restart is kept here
    // regardless: the parked conn is pre-OPEN by definition, so
    // restarting costs one reconnect round-trip and keeps this arm a
    // plain teardown.
    peer.task.writer = None;
    peer.task.reader = None;
    peer.packet_tx = None;
    peer.primary_role = None;
    peer.primary_conn_id = None;
    if let Some(collision) = peer.collision.take() {
        close_collision(
            collision,
            NotifyCode::Cease,
            CeaseError::ConnectionRejected.into(),
        );
    }
    // RFC 4271 TcpConnectionFails cells, by the state the failure
    // arrived in. Either way the peer keeps retrying until the
    // connection succeeds — what differs is the pacer and whether we
    // keep accepting inbound connects in the meantime.
    match peer.state {
        // OpenSent: restart the ConnectRetryTimer, keep listening,
        // go to Active; the timer's Event::Start redials. Passive
        // peers don't redial — they park in Active listening.
        State::OpenSent => {
            if !peer.is_passive() {
                peer.timer.connect_retry = Some(timer::start_connect_retry_timer(peer));
            }
            State::Active
        }
        // Active / OpenConfirm / Established: release everything and
        // go to Idle. Entering Idle re-arms the idle hold timer (the
        // restart pacer firing Event::Start) and refuses inbound
        // connections while it runs — the peer-oscillation damping
        // RFC 4271 §8.1.1 ties to the IdleHoldTimer. Passive peers
        // skip the hold (`update_timers` flips them straight back to
        // Active listening). Historically every failure landed in
        // Active with a 120s connect-retry, so the idle hold timer
        // never ran again after the first failed redial.
        _ => State::Idle,
    }
}

pub async fn peer_packet_parse(
    rx: &[u8],
    ident: usize,
    conn: ConnId,
    tx: mpsc::Sender<Message>,
    config: &mut PeerConfig,
    opt: &mut ParseOption,
) -> Result<(), String> {
    match BgpPacket::parse_packet(rx, true, Some(opt.clone())) {
        Ok((_, p)) => {
            match p {
                BgpPacket::Open(p) => {
                    cap_addpath_recv(&p.bgp_cap, opt, &config.addpath);
                    if config.extended_message && p.bgp_cap.extended.is_some() {
                        opt.extended_message = true;
                    }
                    let _ = tx
                        .send(Message::Event(ident, Event::BGPOpen(conn, *p)))
                        .await;
                }
                BgpPacket::Keepalive(_) => {
                    // tracing::info!("Recv keepavlie {}", ident);
                    let _ = tx
                        .send(Message::Event(ident, Event::KeepAliveMsg(conn)))
                        .await;
                }
                BgpPacket::Notification(p) => {
                    // tracing::info!("{p}");
                    let _ = tx
                        .send(Message::Event(ident, Event::NotifMsg(conn, p)))
                        .await;
                }
                BgpPacket::Update(p) => {
                    let _ = tx.send(Message::Event(ident, Event::UpdateMsg(*p))).await;
                }
                BgpPacket::RouteRefresh(p) => {
                    let _ = tx
                        .send(Message::Event(ident, Event::RouteRefreshMsg(p.afi, p.safi)))
                        .await;
                }
            }
            Ok(())
        }
        Err(e) => Err(e.to_string()),
    }
}

pub async fn peer_read(
    ident: usize,
    conn: ConnId,
    tx: mpsc::Sender<Message>,
    mut read_half: OwnedReadHalf,
    mut config: PeerConfig,
    mut opt: ParseOption,
) {
    let mut buf = BytesMut::with_capacity(BGP_EXTENDED_PACKET_LEN);
    loop {
        match read_half.read_buf(&mut buf).await {
            Ok(read_len) => {
                if read_len == 0 {
                    let _ = tx.try_send(Message::Event(ident, Event::ConnFail(conn)));
                    return;
                }
                while buf.len() >= BGP_HEADER_LEN as usize && buf.len() >= peek_bgp_length(&buf) {
                    let length = peek_bgp_length(&buf);

                    // Validate message length (RFC 8654).
                    if length < BGP_HEADER_LEN as usize || length > opt.max_message_len() {
                        let _ = tx.try_send(Message::Event(ident, Event::ConnFail(conn)));
                        return;
                    }

                    let mut remain = buf.split_off(length);
                    remain.reserve(BGP_EXTENDED_PACKET_LEN);

                    match peer_packet_parse(&buf, ident, conn, tx.clone(), &mut config, &mut opt)
                        .await
                    {
                        Ok(_) => {
                            buf = remain;
                        }
                        Err(_err) => {
                            let _ = tx.try_send(Message::Event(ident, Event::ConnFail(conn)));
                            return;
                        }
                    }
                }
            }
            Err(_err) => {
                let _ = tx.send(Message::Event(ident, Event::ConnFail(conn))).await;
            }
        }
    }
}

pub fn peer_start_reader(peer: &Peer, conn: ConnId, read_half: OwnedReadHalf) -> Task<()> {
    let ident = peer.ident;
    let tx = peer.tx.clone();
    let config = peer.config.clone();
    let opt = peer.opt.clone();
    Task::spawn(async move {
        peer_read(ident, conn, tx.clone(), read_half, config, opt).await;
    })
}

pub fn peer_start_writer(
    mut write_half: OwnedWriteHalf,
    mut rx: UnboundedReceiver<BytesMut>,
) -> Task<()> {
    Task::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let _ = write_half.write_all(&msg).await;
        }
    })
}

pub fn peer_start_connection(peer: &mut Peer) -> Task<()> {
    let ident = peer.ident;
    let tx = peer.tx.clone();
    let address = peer.address;
    let scope_id = peer.scope_id;
    let update_source = peer.config.transport.update_source;
    let md5_password = peer.config.transport.md5_password.clone();
    let ao_key = peer.config.transport.resolved_ao_key.clone();
    // eBGP egress TTL (1 directly connected / N for ebgp-multihop), or
    // 255 for iBGP / ttl-security. Set on the socket before connect so
    // the SYN carries it (see `peer_connect`).
    let ttl = peer.session_ttl();
    // `tcp-mss <1-65535>`, likewise set before connect so our SYN
    // advertises the clamp and the kernel caches the reduced MSS.
    let tcp_mss = peer.config.transport.tcp_mss;
    // `neighbor X port <1-65535>` — TCP destination port for the dial;
    // the IANA 179 unless overridden.
    let port = peer.config.transport.port.unwrap_or(BGP_PORT);
    let ctx = peer.ctx.clone();
    Task::spawn(async move {
        let tx = tx.clone();
        let remote: SocketAddr = match address {
            IpAddr::V4(addr) => SocketAddr::new(IpAddr::V4(addr), port),
            // Pass `scope_id` through `SocketAddrV6` so a link-local
            // target (fe80::/10) resolves to the right interface — the
            // kernel `connect(2)` returns EINVAL otherwise. For global
            // v6 addresses `scope_id = 0` is fine, which is what
            // `unwrap_or(0)` produces when the peer wasn't materialized
            // by interface-neighbor.
            IpAddr::V6(addr) => SocketAddr::V6(std::net::SocketAddrV6::new(
                addr,
                port,
                0,
                scope_id.unwrap_or(0),
            )),
        };
        let result = peer_connect(
            &ctx,
            remote,
            update_source,
            md5_password.as_deref(),
            ao_key,
            ttl,
            tcp_mss,
        )
        .await;
        match result {
            Ok(stream) => {
                let _ = tx.try_send(Message::Event(ident, Event::Connected(stream)));
            }
            Err(_err) => {
                // The dial never produced a connection, so there is
                // no ConnId to attribute the failure to.
                let _ = tx.try_send(Message::Event(ident, Event::DialFail));
            }
        };
    })
}

async fn peer_connect(
    ctx: &crate::context::ProtoContext,
    remote: SocketAddr,
    update_source: Option<IpAddr>,
    md5_password: Option<&str>,
    ao_key: Option<super::auth::ResolvedAoKey>,
    ttl: u8,
    tcp_mss: Option<u16>,
) -> std::io::Result<TcpStream> {
    // Address family of the source must match the remote when specified.
    if let Some(src) = update_source
        && src.is_ipv4() != remote.is_ipv4()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "update-source address family does not match peer address",
        ));
    }

    let socket = if remote.is_ipv4() {
        ctx.tcp_socket_v4()?
    } else {
        ctx.tcp_socket_v6()?
    };

    // Install TCP MD5 / TCP-AO key BEFORE connect() so the outgoing
    // SYN carries a valid auth option. A mismatched or missing key
    // on the peer's listener causes the SYN to be silently dropped
    // by the kernel (no log, no SYN-ACK).
    use std::os::fd::AsRawFd;
    if let Some(password) = md5_password {
        super::auth::set_tcp_md5_key(socket.as_raw_fd(), remote.ip(), password.as_bytes())?;
    }
    if let Some(key) = ao_key {
        super::auth::set_tcp_ao_key(
            socket.as_raw_fd(),
            remote.ip(),
            key.alg_name,
            &key.key_material,
            key.send_id,
            key.recv_id,
            key.include_tcp_options,
        )?;
    }

    if let Some(src) = update_source {
        socket.bind(SocketAddr::new(src, 0))?;
    }

    // Set the egress TTL before connect so the SYN already carries it:
    // a directly-connected eBGP peer uses TTL 1 (a router in the path
    // drops the SYN — multihop needs explicit `ebgp-multihop`), while
    // iBGP / ttl-security use 255. The GTSM ingress floor is NOT set
    // here — it would drop the peer's default-TTL SYN-ACK — it is
    // applied post-handshake in `fsm_connected`. Best-effort: a failure
    // is logged, the connect proceeds at the OS default TTL.
    if let Err(e) = super::ttl::set_egress_ttl(socket.as_raw_fd(), remote.is_ipv4(), ttl) {
        tracing::warn!(
            peer = %remote.ip(),
            error = %e,
            "bgp: failed to set egress TTL before connect; using OS default",
        );
    }

    // Set the TCP MSS before connect so our SYN advertises the clamp and
    // the kernel caches the reduced MSS on this socket — a later set on
    // the established socket no longer changes `getsockopt(TCP_MAXSEG)`.
    // Best-effort: a failure is logged and the connect proceeds at the
    // path-MTU-derived default.
    if let Some(mss) = tcp_mss
        && let Err(e) = super::mss::set_tcp_mss(socket.as_raw_fd(), mss)
    {
        tracing::warn!(
            peer = %remote.ip(),
            error = %e,
            mss,
            "bgp: failed to set TCP MSS before connect; using path-MTU default",
        );
    }

    socket.connect(remote).await
}

pub fn peer_send_open(peer: &mut Peer) {
    let Some(packet_tx) = peer.packet_tx.clone() else {
        return;
    };
    let bytes = build_open_packet(peer);
    peer.counter[BgpType::Open as usize].sent += 1;
    bgp_packet_trace!(peer, PacketKind::Open, Direction::Send, "send OPEN");
    let _ = packet_tx.send(bytes);
}

/// Build the serialized OPEN packet for this peer using its current
/// caps/config. Side-effects on the peer: records the sent caps and
/// hold/keepalive in `cap_send` / `param_tx`. Callers ship the
/// resulting bytes via whichever `packet_tx` (primary or collision)
/// they own.
fn build_open_packet(peer: &mut Peer) -> BytesMut {
    let header = BgpHeader::new(BgpType::Open, BGP_HEADER_LEN + 10);
    let router_id = if let Some(identifier) = peer.local_identifier {
        identifier
    } else {
        peer.router_id
    };
    // Sending 0.0.0.0 as the BGP Identifier is a protocol error per
    // RFC 4271 §4.2; the peer will respond with NOTIFICATION
    // (Bad BGP Identifier). Surface it loudly here so the operator
    // sees it before chasing FSM symptoms.
    if router_id.is_unspecified() {
        tracing::warn!(
            "peer {}: sending OPEN with router-id 0.0.0.0 — \
             configure `router bgp global router-id <ipv4>` or wait \
             for an interface address to seed the auto-derivation",
            peer.address
        );
    }
    let mut bgp_cap = BgpCap::default();

    for (afi_safi, _) in peer.config.mp.0.iter() {
        let cap = CapMultiProtocol::new(&afi_safi.afi, &afi_safi.safi);
        bgp_cap.mp.insert(*afi_safi, cap);
    }
    if peer.config.four_octet {
        let cap = CapAs4::new(peer.local_as);
        bgp_cap.as4 = Some(cap);
    }
    if peer.config.route_refresh {
        let cap = CapRefresh::default();
        bgp_cap.refresh = Some(cap);
    }
    if peer.config.extended_message {
        bgp_cap.extended = Some(CapExtended::default());
    }
    // Auto-advertise RFC 8950 Extended Next Hop Encoding for IPv4
    // unicast over IPv6 next-hop on interface-keyed (unnumbered)
    // peers. Without this the peer can't carry IPv4 routes over a
    // session that has no IPv4 source address. Other AFIs / SAFIs
    // can be added once the operator has a knob, but the
    // single-tuple case covers every interface-neighbor deployment.
    // Skipped when IPv4 unicast itself is disabled on the peer (e.g.
    // via the neighbor-group's `afi-safi ipv4 enabled false`) — ENHE
    // qualifies an MP family we would not be advertising.
    if matches!(peer.origin, PeerOrigin::Interface { .. })
        && peer.config.mp.has(&AfiSafi::new(Afi::Ip, Safi::Unicast))
    {
        bgp_cap.extended_nexthop = Some(CapExtendedNextHop::new(vec![ExtendedNextHopValue::new(
            Afi::Ip,
            Safi::Unicast,
            Afi::Ip6,
        )]));
    }
    if let Some(name) = &peer.local_hostname {
        // FQDN capability (draft-walton, code 73). Domain name is left
        // empty for now — operators have only asked for hostname.
        bgp_cap.fqdn = Some(CapFqdn::new(name, ""));
    }
    for (key, addpath) in peer.config.addpath.iter() {
        bgp_cap.addpath.insert(*key, addpath.clone());
    }
    for (key, sub) in peer.config.sub.iter() {
        if let Some(_restart_time) = sub.graceful_restart {
            let restart = RestartValue::new(1, key.afi, key.safi);
            bgp_cap.restart.insert(*key, restart);
        }
        if let Some(llgr_time) = sub.llgr {
            let llgr = LlgrValue::new(key.afi, key.safi, llgr_time);
            bgp_cap.llgr.insert(*key, llgr);
        }
    }

    cap_register_send(&bgp_cap, &mut peer.cap_map);
    peer.cap_send = bgp_cap.clone();

    // Remember sent hold time.
    let hold_time = peer.config.timer.hold_time() as u16;
    peer.param_tx.hold_time = hold_time;
    peer.param_tx.keepalive = hold_time / 3;

    let open = OpenPacket::new(header, peer.local_as as u16, hold_time, &router_id, bgp_cap);
    let bytes: BytesMut = open.into();
    bytes
}

pub fn peer_send_notification(peer: &mut Peer, code: NotifyCode, sub_code: u8, data: Vec<u8>) {
    let Some(packet_tx) = peer.packet_tx.as_ref() else {
        return;
    };
    let notification = NotificationPacket::new(code, sub_code, data);
    let mut bytes: BytesMut = notification.into();
    // RFC 8654: NOTIFICATION to non-extended peer MUST NOT exceed 4096.
    if !peer.opt.extended_message && bytes.len() > BGP_PACKET_LEN {
        bytes.truncate(BGP_PACKET_LEN);
        let length = bytes.len() as u16;
        bytes[16..18].copy_from_slice(&length.to_be_bytes());
    }
    peer.counter[BgpType::Notification as usize].sent += 1;
    bgp_packet_trace!(
        peer,
        PacketKind::Notification,
        Direction::Send,
        code = ?code,
        sub_code,
        "send NOTIFICATION"
    );
    let _ = packet_tx.send(bytes);
}

pub fn peer_send_keepalive(peer: &mut Peer) {
    let Some(packet_tx) = peer.packet_tx.as_ref() else {
        return;
    };
    let header = BgpHeader::new(BgpType::Keepalive, BGP_HEADER_LEN);
    let bytes: BytesMut = header.into();
    peer.counter[BgpType::Keepalive as usize].sent += 1;
    bgp_packet_trace!(
        peer,
        PacketKind::Keepalive,
        Direction::Send,
        "send KEEPALIVE"
    );
    let _ = packet_tx.send(bytes);
}

// Send a BGP Route Refresh (RFC 2918, type 5) for one AFI/SAFI. The
// caller is responsible for verifying the peer is established and
// advertised the Route Refresh capability — sending REFRESH to a peer
// that didn't advertise the cap is technically permitted but the peer
// is allowed to ignore it.
pub fn peer_send_route_refresh(peer: &mut Peer, afi: u16, safi: u8) {
    let Some(packet_tx) = peer.packet_tx.as_ref() else {
        return;
    };
    let pkt = RouteRefreshPacket::new(afi, safi);
    let bytes: BytesMut = pkt.into();
    peer.counter[BgpType::RouteRefresh as usize].sent += 1;
    bgp_packet_trace!(
        peer,
        PacketKind::RouteRefresh,
        Direction::Send,
        afi,
        safi,
        "send ROUTE-REFRESH"
    );
    let _ = packet_tx.send(bytes);
}

/// Reject a connection by sending a NOTIFICATION and closing the socket.
/// Spawns an async task with a timeout to prevent FD exhaustion.
fn reject_connection(stream: TcpStream, code: NotifyCode, sub_code: u8) {
    use std::time::Duration;
    use tokio::time::timeout;

    tokio::spawn(async move {
        let notification = NotificationPacket::new(code, sub_code, Vec::new());
        let bytes: BytesMut = notification.into();
        let mut stream = stream;
        // Use a short timeout to prevent FD exhaustion from slow/unresponsive peers
        let _ = timeout(Duration::from_secs(5), async {
            let _ = stream.write_all(&bytes).await;
            let _ = stream.shutdown().await;
        })
        .await;
        // Stream is dropped here, closing the socket regardless of timeout
    });
}

/// Stash an inbound TCP stream as the peer's collision connection,
/// starting a reader/writer pair under a fresh [`ConnId`] and sending
/// our OPEN over it. The §6.8 resolution is deferred until an OPEN
/// arrives on either connection; if this conn wins, promotion moves
/// its `ConnId` into the primary slot and its events resolve to
/// Primary from then on.
fn start_collision_conn(peer: &mut Peer, stream: TcpStream) {
    // Same TTL policy as the primary connection: if this collision conn
    // wins §6.8 resolution it is promoted to primary, so it must carry
    // the egress TTL and (for ttl-security) the ingress floor too. Record
    // its negotiated MSS for the same reason — it negotiated the same
    // clamp as the primary (same config, same path), so capturing here
    // keeps the synced value correct whichever connection survives.
    apply_session_ttl(peer, &stream);
    record_session_mss(peer, &stream);
    let local_addr = stream.local_addr().ok();
    let remote_addr = stream.peer_addr().ok();
    let conn_id = peer.alloc_conn_id();
    let (packet_tx, packet_rx) = mpsc::unbounded_channel::<BytesMut>();
    let (read_half, write_half) = stream.into_split();
    let reader = peer_start_reader(peer, conn_id, read_half);
    let writer = peer_start_writer(write_half, packet_rx);
    // Stash before sending OPEN so peer_send_open_on_tx has the tx to
    // write into.
    peer.collision = Some(CollisionConn {
        conn_id,
        packet_tx: packet_tx.clone(),
        reader,
        writer,
        role: Role::Passive,
        local_addr,
        remote_addr,
    });
    // Mirror peer_send_open but target the collision packet_tx.
    let bytes = build_open_packet(peer);
    peer.counter[BgpType::Open as usize].sent += 1;
    bgp_packet_trace!(
        peer,
        PacketKind::Open,
        Direction::Send,
        "send OPEN (collision conn)"
    );
    let _ = packet_tx.send(bytes);
}

/// Handle incoming connection for a peer based on current BGP state.
///
/// `scope_id` is the IPv6 scope of the accepted socket — for a
/// link-local source it is the arrival ifindex, which is how an
/// IPv6-unnumbered (`interface-neighbor`) peer is keyed. The lookup
/// prefers an address-keyed peer (numbered + dynamic peers, which is
/// every non-unnumbered case) and only falls back to the
/// interface-keyed peer when the source has no address-keyed match —
/// an unnumbered peer's remote link-local is never written into the
/// address map, so an inbound connection from it would otherwise be
/// dropped, and the session (both ends connect actively *and* accept
/// passively) could never resolve a collision into Established.
pub(super) fn handle_peer_connection(
    peers: &mut PeerMap,
    peer_addr: IpAddr,
    scope_id: Option<u32>,
    stream: TcpStream,
) -> Option<TcpStream> {
    let key = if peers.get(&peer_addr).is_some() {
        PeerKey::Addr(peer_addr)
    } else if let Some(ifindex) = scope_id
        && peers.get_by_key(&PeerKey::Interface(ifindex)).is_some()
    {
        PeerKey::Interface(ifindex)
    } else {
        return Some(stream);
    };
    if let Some(peer) = peers.get_mut_by_key(&key) {
        // Pin the egress TTL on the freshly accepted socket *before* we
        // decide its fate. For a `ttl-security` (GTSM) peer this is what
        // lets a rejected or dropped inbound connection be torn down
        // cleanly: the NOTIFICATION and the kernel FIN/RST that close the
        // socket must leave at TTL 255, or the peer's `IP_MINTTL` = 255
        // floor silently drops them and the peer never learns the
        // connection is gone — it keeps retransmitting its OPEN into a
        // black hole and stays wedged in OpenSent until its hold timer
        // (minutes) expires. This bites whenever two GTSM speakers connect
        // at once (a collision after a simultaneous restart / clear): the
        // loser's teardown is invisible to the winner. The keep paths
        // (`fsm_connected` / `start_collision_conn`) re-apply this together
        // with the ingress floor, so the early set is harmless redundancy
        // for them.
        {
            use std::os::fd::AsRawFd;
            let _ = super::ttl::set_egress_ttl(
                stream.as_raw_fd(),
                peer.address.is_ipv4(),
                peer.session_ttl(),
            );
        }
        match peer.state {
            State::Idle => {
                // No session established yet - just drop (sends TCP RST/FIN)
                drop(stream);
                None
            }
            State::Connect => {
                // Cancel connect task.
                peer.task.connect = None;
                peer.state = fsm_connected(peer, Role::Passive, stream);
                None
            }
            State::Active => {
                peer.state = fsm_connected(peer, Role::Passive, stream);
                None
            }
            State::OpenSent | State::OpenConfirm => {
                // RFC 4271 §6.8 collision: we already have a primary
                // connection in flight. Stash this one as the
                // collision conn and wait for an OPEN on either side
                // to decide which survives. If a collision is already
                // pending, drop the new one — having three TCPs to
                // the same peer isn't worth modeling.
                if peer.primary_role == Some(Role::Active) && peer.collision.is_none() {
                    start_collision_conn(peer, stream);
                    None
                } else {
                    reject_connection(stream, NotifyCode::Cease, 7); // ConnectionCollisionResolution
                    None
                }
            }
            State::Established => {
                // Session already established. Per RFC 4271 §6.8,
                // close the new connection with Cease
                // (ConnectionCollisionResolution).
                reject_connection(stream, NotifyCode::Cease, 7);
                None
            }
        }
    } else {
        Some(stream)
    }
}

pub fn accept(bgp: &mut Bgp, stream: TcpStream, sockaddr: SocketAddr) {
    let peer_addr = match sockaddr {
        SocketAddr::V4(addr) => IpAddr::V4(*addr.ip()),
        SocketAddr::V6(addr) => IpAddr::V6(*addr.ip()),
    };
    // For an IPv6-unnumbered (`interface-neighbor`) peer the inbound
    // connection is matched by the arrival interface, not the source
    // address (a link-local we never recorded). The accepted socket's
    // IPv6 sockaddr carries that ifindex as its scope_id; a non
    // link-local source has scope_id 0 and is matched by address only.
    let scope_id = match sockaddr {
        SocketAddr::V6(addr) if addr.scope_id() != 0 => Some(addr.scope_id()),
        _ => None,
    };
    let mut remaining_stream = handle_peer_connection(&mut bgp.peers, peer_addr, scope_id, stream);

    // Static lookup missed — try a configured listen-range. If LPM
    // hits and the per-range neighbor-group resolves to a usable
    // `remote-as`, synthesize a passive Peer and re-run the connection
    // handler so the new entry picks up the same FSM path as a
    // statically-configured one.
    if let Some(stream) = remaining_stream.take() {
        remaining_stream = try_dynamic_accept(bgp, peer_addr, stream);
    }

    if let Some(stream) = remaining_stream {
        // No configured peer found - just drop (sends TCP RST/FIN)
        drop(stream);
    }
}

/// Materialize a dynamic peer when `peer_addr` matches a configured
/// `listen-range`. Returns `Some(stream)` (i.e. caller should drop)
/// on any failure path so the listen-range never holds the socket
/// open while we sort out a config gap.
fn try_dynamic_accept(bgp: &mut Bgp, peer_addr: IpAddr, stream: TcpStream) -> Option<TcpStream> {
    // Soft cap. The listen-limit guards against an attacker spamming
    // SYNs from many sources in a wide listen-range — once we hit
    // the limit, additional matches drop silently until existing
    // dynamic peers are GC'd (session-close GC lands in a follow-up).
    if bgp.dynamic_peer_count >= bgp.dynamic_neighbors.listen_limit {
        return Some(stream);
    }
    let (range_prefix, range) = bgp.dynamic_neighbors.lpm_match(&peer_addr)?;
    let group_name = range.neighbor_group.as_ref()?.clone();
    let remote_as = super::neighbor_group::group_remote_as(bgp, &group_name)?;

    let mut peer = Peer::new(
        0,
        bgp.asn,
        bgp.router_id,
        remote_as,
        peer_addr,
        bgp.hostname(),
        bgp.tx.clone(),
        bgp.ctx.clone(),
    );
    peer.tracing_instance = bgp.tracing.clone();
    peer.origin = super::peer_key::PeerOrigin::Dynamic { range_prefix };
    // Dynamic peers are passive-only — they never initiate a connect.
    peer.config.transport.passive = true;
    // The remote-as came from the listen-range's neighbor-group, so a
    // later change to the group must flow through to this peer. Stamp
    // the inherited flag and the back-reference for the reactive
    // sweep in `config_neighbor_group_remote_as` to consult.
    peer.config.neighbor_group = Some(group_name);
    peer.config.remote_as_inherited = true;

    bgp.peers.insert(peer_addr, peer);
    bgp.dynamic_peer_count += 1;

    // Resolve everything the group supplies (the MP family set for
    // the OPEN this very connection is about to exchange, plus the
    // whole-session knobs) — after insert so any timer the apply
    // ritual arms captures the real ident. Dynamic peers stay
    // passive regardless of the group's `passive` opinion (forced
    // above); the bounce flag is irrelevant for a fresh Idle peer.
    if let Some(peer) = bgp.peers.get_mut(&peer_addr) {
        let _ = super::neighbor_group::apply_inherited(&bgp.neighbor_groups, &bgp.policy_tx, peer);
    }

    // Dynamic (listen-range) peers are always address-keyed, so no
    // interface scope is needed here.
    handle_peer_connection(&mut bgp.peers, peer_addr, None, stream)
}

/// Replay Adj-RIB-In through the current inbound policy for `peer_idx`,
/// without bouncing the session. If the peer has `soft-reconfiguration
/// inbound` configured we replay locally from the stored Adj-RIB-In.
/// Otherwise we fall back to RFC 2918 Route Refresh provided the peer
/// advertised the capability. With neither, the call is a silent no-op
/// — the peer will only converge on its next update.
///
/// Used by both the `clear bgp <afi> <peer> soft in` CLI dispatcher
/// (`clear_bgp_action`) and the policy-update path in
/// `process_policy_msg`.
pub fn apply_soft_in_peer(bgp: &mut Bgp, peer_idx: usize) {
    let Some(peer) = bgp.peers.get_by_idx(peer_idx) else {
        return;
    };
    if !peer.state.is_established() {
        return;
    }
    let soft_in = peer.config.soft_reconfig_in;
    let supports_refresh = peer.cap_recv.refresh.is_some();
    let mp_pairs: Vec<(u16, u8)> = peer
        .cap_recv
        .mp
        .keys()
        .map(|af| (u16::from(af.afi), u8::from(af.safi)))
        .collect();

    if soft_in {
        let mut bgp_ref = BgpTop {
            router_id: &bgp.router_id,
            srv6_ipv6_export: bgp.srv6_ipv6_export.as_ref(),
            local_rib: &mut bgp.local_rib,
            tx: &bgp.tx,
            rib_client: &bgp.ctx.rib,
            attr_store: &mut bgp.attr_store,
            update_groups: &mut bgp.update_groups,
            interface_addrs: &bgp.interface_addrs,
            vrf_export: None,
            color_policy: Some(&bgp.color_policy),
            flex_algo_routes: Some(&bgp.flex_algo_routes),
            vrf_import: None,
            nexthop_cache: None,
            vrf_transport_v4: None,
            vrf_transport_v6: None,
            lu_labels: None,
        };
        super::route::route_soft_in_peer(peer_idx, &mut bgp_ref, &mut bgp.peers);
    } else if supports_refresh {
        let peer = bgp.peers.get_mut_by_idx(peer_idx).expect("peer exists");
        for (afi, safi) in &mp_pairs {
            peer_send_route_refresh(peer, *afi, *safi);
        }
    }
}

/// Replay Loc-RIB through the current outbound policy for `peer_idx`,
/// without bouncing the session. Always works when the peer is
/// Established — no peer cooperation needed because we drive the
/// re-advertisement from our local RIB.
pub fn apply_soft_out_peer(bgp: &mut Bgp, peer_idx: usize) {
    let Some(peer) = bgp.peers.get_by_idx(peer_idx) else {
        return;
    };
    if !peer.state.is_established() {
        return;
    }
    let mut bgp_ref = BgpTop {
        router_id: &bgp.router_id,
        srv6_ipv6_export: bgp.srv6_ipv6_export.as_ref(),
        local_rib: &mut bgp.local_rib,
        tx: &bgp.tx,
        rib_client: &bgp.ctx.rib,
        attr_store: &mut bgp.attr_store,
        update_groups: &mut bgp.update_groups,
        interface_addrs: &bgp.interface_addrs,
        vrf_export: None,
        color_policy: Some(&bgp.color_policy),
        flex_algo_routes: Some(&bgp.flex_algo_routes),
        vrf_import: None,
        nexthop_cache: None,
        vrf_transport_v4: None,
        vrf_transport_v6: None,
        lu_labels: None,
    };
    super::route::route_soft_out_peer(peer_idx, &mut bgp_ref, &mut bgp.peers);
}

/// Action selector for the `clear bgp <afi> <peer> ...` family of
/// operational commands. `Hard` bounces the session; the soft variants
/// re-evaluate without disturbing the BGP FSM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BgpClearOp {
    Hard,
    SoftBoth,
    SoftIn,
    SoftOut,
}

/// Drive `clear bgp [<afi>] <peer-or-all> [soft [in|out]]` requests
/// from the YANG schema in zebra-bgp-clear.yang. The first arg is the
/// list key — either an IP literal or the keyword `all`.
///
/// `afi_safi` is `Some` for the per-AFI containers and `None` for the
/// AFI-less `clear bgp <peer-or-all>` form. Filtering by it only
/// matters when the key is `all`; for a concrete peer address we look
/// it up directly and skip the filter (the caller asked for *that*
/// peer specifically). EVPN soft-in is not yet wired into
/// `route_soft_in_peer`, so a soft-in/soft-both on EVPN logs a "not
/// yet implemented" notice and leaves the session alone.
pub fn clear_bgp_action(
    bgp: &mut Bgp,
    args: &mut Args,
    afi_safi: Option<(bgp_packet::Afi, bgp_packet::Safi)>,
    op: BgpClearOp,
) -> std::result::Result<String, std::fmt::Error> {
    let Some(target) = args.string() else {
        return Ok("missing peer or 'all' argument".to_string());
    };

    if matches!(op, BgpClearOp::SoftIn | BgpClearOp::SoftBoth)
        && afi_safi.map(|(_, safi)| safi) == Some(bgp_packet::Safi::Evpn)
    {
        return Ok("%% EVPN soft-in is not yet implemented".to_string());
    }

    // Resolve to peer idents, not addresses: interface-keyed (IPv6
    // unnumbered) peers are not reachable via the address map — their
    // CLI identity is the `interface-neighbor` name, and `all` must
    // cover them too (hence `iter_all`).
    let targets: Vec<usize> = if target == "all" {
        bgp.peers
            .iter_all()
            .filter_map(|(_, p)| {
                afi_safi
                    .is_none_or(|(afi, safi)| p.is_afi_safi(afi, safi))
                    .then_some(p.ident)
            })
            .collect()
    } else {
        match target.parse::<IpAddr>() {
            Ok(addr) => bgp.peers.get(&addr).map(|p| p.ident).into_iter().collect(),
            Err(_) => bgp
                .peers
                .iter_all()
                .filter_map(|(_, p)| {
                    (p.ifname.as_deref() == Some(target.as_str())).then_some(p.ident)
                })
                .collect(),
        }
    };

    if targets.is_empty() {
        return Ok("%% no matching peers".to_string());
    }

    for &peer_idx in &targets {
        match op {
            BgpClearOp::Hard => {
                let _ = bgp.tx.try_send(Message::Event(peer_idx, Event::Stop));
            }
            BgpClearOp::SoftBoth => {
                apply_soft_in_peer(bgp, peer_idx);
                apply_soft_out_peer(bgp, peer_idx);
            }
            BgpClearOp::SoftIn => apply_soft_in_peer(bgp, peer_idx),
            BgpClearOp::SoftOut => apply_soft_out_peer(bgp, peer_idx),
        }
    }
    Ok(format!(
        "%% cleared {} peer(s) (op={:?})",
        targets.len(),
        op
    ))
}

#[cfg(test)]
mod collision_tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn higher_local_id_keeps_active_connection() {
        // local 10.0.0.2 > remote 10.0.0.1 → our active connect wins.
        let winner = collision_winner(Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(winner, Role::Active);
    }

    #[test]
    fn lower_local_id_keeps_passive_connection() {
        // local 10.0.0.1 < remote 10.0.0.2 → peer-initiated wins.
        let winner = collision_winner(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(winner, Role::Passive);
    }

    #[test]
    fn tie_breaks_to_passive_deterministically() {
        // Equal IDs is misconfig; both ends pick `Passive` so they
        // agree on which connection to drop.
        let winner = collision_winner(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(winner, Role::Passive);
    }

    #[test]
    fn comparison_is_unsigned_big_endian() {
        // 192.0.2.1 (u32=0xC0_00_02_01) > 1.2.3.4 (u32=0x01_02_03_04)
        // — guard against accidental signed compare flipping the sign.
        let winner = collision_winner(Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(winner, Role::Active);
    }
}

#[cfg(test)]
mod bfd_config_tests {
    use super::*;

    /// PeerBfdConfig default mirrors the YANG defaults (all unset ⇒
    /// inherit; off if unset everywhere).
    #[test]
    fn default_bfd_is_disabled() {
        let bfd = PeerBfdConfig::default();
        assert!(bfd.enable.is_none());
        assert!(!bfd.resolve(&PeerBfdConfig::default()).enable);

        // Lives on PeerConfig with the same default.
        let pc = PeerConfig::default();
        assert_eq!(pc.bfd, bfd);
    }

    /// Round-trip: setting enable + multihop + minimum-ttl mirrors the CLI
    /// flow (`bfd enable true; bfd multihop true; bfd minimum-ttl 250`)
    /// producing the recorded state the BFD subscribe path reads.
    #[test]
    fn enable_and_multihop_round_trip() {
        let mut pc = PeerConfig::default();
        pc.bfd.enable = Some(true);
        pc.bfd.multihop = Some(true);
        pc.bfd.minimum_ttl = Some(250);

        assert_eq!(
            pc.bfd,
            PeerBfdConfig {
                enable: Some(true),
                multihop: Some(true),
                minimum_ttl: Some(250),
                ..PeerBfdConfig::default()
            },
        );
    }

    /// Per-neighbor Echo leaves override the instance default; unset inherit.
    #[test]
    fn bfd_resolve_merges_echo() {
        let default = PeerBfdConfig {
            enable: Some(true), // blanket
            echo_mode: Some(EchoMode::Receive),
            echo_transmit_ms: Some(100),
            ..PeerBfdConfig::default()
        };
        let inherit = PeerBfdConfig::default().resolve(&default);
        assert!(inherit.enable);
        assert_eq!(inherit.echo_mode, Some(EchoMode::Receive));
        assert_eq!(inherit.echo_transmit_ms, 100);
        assert_eq!(inherit.echo_receive_ms, DEFAULT_ECHO_INTERVAL_MS);

        let over = PeerBfdConfig {
            enable: Some(false),
            echo_mode: Some(EchoMode::Both),
            ..PeerBfdConfig::default()
        };
        let eff = over.resolve(&default);
        assert!(!eff.enable);
        assert_eq!(eff.echo_mode, Some(EchoMode::Both));
        assert_eq!(eff.echo_transmit_ms, 100); // inherits
    }
}

#[cfg(test)]
mod fsm_idle_hold_tests {
    use super::*;

    /// Peer wired to a parked event channel — timer callbacks and
    /// dial tasks can send without erroring, and nothing reads.
    fn test_peer(passive: bool) -> Peer {
        let (tx, rx) = mpsc::channel::<Message>(64);
        Box::leak(Box::new(rx));
        let mut peer = Peer::new(
            1,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            65002,
            "10.0.0.2".parse().unwrap(),
            None,
            tx,
            crate::context::ProtoContext::default_table_no_rib(),
        );
        peer.config.transport.passive = passive;
        peer.first_start = false;
        peer
    }

    /// RFC 4271 OpenConfirm/Established TcpConnectionFails: the
    /// session lands back in Idle, where `update_timers` re-arms the
    /// idle hold timer — the restart pacer. Before the fix every
    /// failure parked in Active with a connect-retry, so the idle
    /// hold timer never ran again after the first failed redial.
    #[tokio::test]
    async fn conn_fail_lands_in_idle_and_rearms_idle_hold_timer() {
        let mut peer = test_peer(false);
        peer.state = State::OpenConfirm;

        let next = fsm_conn_fail(&mut peer, ConnTag::Primary);
        assert_eq!(next, State::Idle);

        // What `fsm()` does after a state change.
        peer.state = next;
        timer::update_timers(&mut peer);

        assert!(
            peer.timer.idle_hold_timer.is_some(),
            "idle hold timer must be re-armed after a connection failure"
        );
        assert!(peer.timer.connect_retry.is_none());
    }

    /// An Established session dying at TCP level (RST, peer killed)
    /// takes the same path: through Idle with the idle hold timer
    /// armed — not the old direct hop to Active that skipped idle
    /// damping entirely.
    #[tokio::test]
    async fn established_tcp_death_takes_idle_hold_damping() {
        let mut peer = test_peer(false);
        peer.state = State::Established;

        let next = fsm_conn_fail(&mut peer, ConnTag::Primary);
        assert_eq!(next, State::Idle);

        peer.state = next;
        timer::update_timers(&mut peer);
        assert!(peer.timer.idle_hold_timer.is_some());
    }

    /// RFC 4271 OpenSent TcpConnectionFails: restart the
    /// ConnectRetryTimer, keep listening, go to Active — the timer's
    /// Event::Start paces the redial.
    #[tokio::test]
    async fn opensent_tcp_failure_goes_active_with_connect_retry() {
        let mut peer = test_peer(false);
        peer.state = State::OpenSent;

        let next = fsm_conn_fail(&mut peer, ConnTag::Primary);
        assert_eq!(next, State::Active);
        assert!(
            peer.timer.connect_retry.is_some(),
            "ConnectRetryTimer must be restarted to pace the redial"
        );

        peer.state = next;
        timer::update_timers(&mut peer);
        assert!(peer.timer.connect_retry.is_some());
        assert!(peer.timer.idle_hold_timer.is_none());
    }

    /// Passive peers never dial: an OpenSent failure parks them in
    /// Active listening with no redial pacer armed.
    #[tokio::test]
    async fn conn_fail_passive_peer_returns_to_listening() {
        let mut peer = test_peer(true);
        peer.state = State::OpenSent;

        let next = fsm_conn_fail(&mut peer, ConnTag::Primary);
        assert_eq!(next, State::Active);
        assert!(
            peer.timer.connect_retry.is_none(),
            "a passive peer must not arm the redial pacer"
        );

        peer.state = next;
        timer::update_timers(&mut peer);
        assert!(peer.timer.idle_hold_timer.is_none());
    }

    /// `clear bgp <peer>` hard reset (Event::Stop): the session drops
    /// to Idle and the idle hold timer is armed — the pacer whose
    /// Event::Start brings the session back up.
    #[tokio::test]
    async fn stop_lands_in_idle_and_arms_idle_hold_timer() {
        let mut peer = test_peer(false);
        peer.state = State::Established;

        let next = fsm_stop(&mut peer);
        assert_eq!(next, State::Idle);

        peer.state = next;
        timer::update_timers(&mut peer);
        assert!(
            peer.timer.idle_hold_timer.is_some(),
            "a cleared peer must pace its restart with the idle hold timer"
        );
        assert!(peer.timer.connect_retry.is_none());
    }

    /// `clear bgp <peer>` on a passive neighbor: no idle hold, no
    /// redial — `update_timers` flips the peer straight to Active
    /// listening, waiting for the remote router to reconnect.
    #[tokio::test]
    async fn stop_passive_peer_returns_to_listening() {
        let mut peer = test_peer(true);
        peer.state = State::Established;

        let next = fsm_stop(&mut peer);
        assert_eq!(next, State::Idle);

        peer.state = next;
        timer::update_timers(&mut peer);
        assert_eq!(peer.state, State::Active);
        assert!(peer.timer.idle_hold_timer.is_none());
        assert!(
            peer.timer.connect_retry.is_none(),
            "a passive peer must not arm the redial pacer"
        );
    }

    /// The dial path arms the ConnectRetryTimer (RFC 4271: started on
    /// leaving Idle, restarted on every redial) so a blackholed SYN
    /// is bounded and a refused dial has its retry pacer ready.
    #[tokio::test]
    async fn dial_path_arms_connect_retry() {
        let mut peer = test_peer(false);
        let next = fsm_start(&mut peer);
        assert_eq!(next, State::Connect);
        assert!(peer.task.connect.is_some());
        assert!(peer.timer.connect_retry.is_some());
    }

    /// A collision-conn failure must not disturb the primary session.
    #[tokio::test]
    async fn collision_conn_fail_keeps_state() {
        let mut peer = test_peer(false);
        peer.state = State::OpenSent;
        let next = fsm_conn_fail(&mut peer, ConnTag::Collision);
        assert_eq!(next, State::OpenSent);
    }

    /// The eBGP connected-check holdoff parks in Active with the
    /// connect-retry backstop armed (and `show ip bgp neighbors`
    /// reports "Next connect retry timer fires in N seconds").
    #[tokio::test]
    async fn connected_check_holdoff_parks_active_with_connect_retry() {
        let mut peer = test_peer(false);
        peer.peer_type = PeerType::EBGP;
        peer.shared_network = false; // neighbor not on a connected subnet

        let next = fsm_start(&mut peer);
        assert_eq!(next, State::Active);
        assert!(peer.task.connect.is_none(), "holdoff must not dial");
        assert!(peer.timer.connect_retry.is_some());

        peer.state = next;
        timer::update_timers(&mut peer);
        assert!(
            peer.timer.connect_retry.is_some(),
            "Active keeps the backstop running"
        );
    }

    /// ConnectRetryTimer lifecycle across states: it runs in Connect
    /// (bounding the dial) and Active (pacing the redial), and is
    /// retired entering OpenSent (RFC 4271 stops it on TCP success;
    /// a late fire must not clobber the handshake) and Idle (the
    /// idle hold timer takes over as pacer).
    #[tokio::test]
    async fn connect_retry_lifecycle_across_states() {
        for (state, kept) in [
            (State::Idle, false),
            (State::Connect, true),
            (State::Active, true),
            (State::OpenSent, false),
        ] {
            let mut peer = test_peer(false);
            peer.timer.connect_retry = Some(timer::start_connect_retry_timer(&peer));
            peer.state = state;
            timer::update_timers(&mut peer);
            assert_eq!(
                peer.timer.connect_retry.is_some(),
                kept,
                "{state:?}: connect-retry timer kept = {kept}"
            );
        }
    }

    /// A parked collision conn for tests: live channel, no-op tasks.
    fn test_collision_conn(conn_id: ConnId) -> CollisionConn {
        let (packet_tx, packet_rx) = mpsc::unbounded_channel::<BytesMut>();
        Box::leak(Box::new(packet_rx));
        CollisionConn {
            conn_id,
            packet_tx,
            reader: Task::spawn(async {}),
            writer: Task::spawn(async {}),
            role: Role::Passive,
            local_addr: None,
            remote_addr: None,
        }
    }

    /// Peer in OpenSent with an active-role primary conn and a parked
    /// collision conn — the §6.8 staging position. Returns the two
    /// conn ids (primary, collision).
    fn peer_with_collision() -> (Peer, ConnId, ConnId) {
        let mut peer = test_peer(false);
        let primary_id = peer.alloc_conn_id();
        let (packet_tx, packet_rx) = mpsc::unbounded_channel::<BytesMut>();
        Box::leak(Box::new(packet_rx));
        peer.packet_tx = Some(packet_tx);
        peer.primary_role = Some(Role::Active);
        peer.primary_conn_id = Some(primary_id);
        peer.state = State::OpenSent;
        let collision_id = peer.alloc_conn_id();
        peer.collision = Some(test_collision_conn(collision_id));
        (peer, primary_id, collision_id)
    }

    /// After §6.8 promotion the surviving conn's KEEPALIVEs must
    /// resolve to Primary and drive the session — with the old baked
    /// tag they were ignored, so the hold timer was never refreshed
    /// and a healthy quiet session died of hold-timer expiry.
    #[tokio::test]
    async fn promoted_conn_keepalive_reaches_the_fsm() {
        let (mut peer, _primary_id, collision_id) = peer_with_collision();
        let collision = peer.collision.take().unwrap();
        promote_collision_to_primary(&mut peer, collision);
        assert_eq!(peer.primary_conn_id, Some(collision_id));

        peer.state = State::OpenConfirm;
        let (next, _) = fsm_next_state(&mut peer, Event::KeepAliveMsg(collision_id));
        assert_eq!(
            next,
            State::Established,
            "promoted conn's KEEPALIVE must complete the handshake"
        );
    }

    /// After §6.8 promotion the surviving conn's TCP death must tear
    /// the session down — with the old baked tag it hit the collision
    /// arm (empty slot, no-op) and the peer wedged in Established
    /// until hold-timer expiry.
    #[tokio::test]
    async fn promoted_conn_failure_tears_the_session_down() {
        let (mut peer, _primary_id, collision_id) = peer_with_collision();
        let collision = peer.collision.take().unwrap();
        promote_collision_to_primary(&mut peer, collision);

        peer.state = State::Established;
        let (next, _) = fsm_next_state(&mut peer, Event::ConnFail(collision_id));
        assert_eq!(next, State::Idle);
        assert!(peer.packet_tx.is_none());
        assert!(peer.primary_conn_id.is_none());
    }

    /// Events queued by the §6.8 loser (or any torn-down conn) before
    /// it died resolve to no slot and must be ignored — they must not
    /// be misattributed to whichever conn now owns the slot.
    #[tokio::test]
    async fn superseded_conn_events_are_ignored() {
        let (mut peer, old_primary_id, collision_id) = peer_with_collision();
        let collision = peer.collision.take().unwrap();
        promote_collision_to_primary(&mut peer, collision);
        assert_ne!(old_primary_id, collision_id);

        peer.state = State::Established;
        let (next, _) = fsm_next_state(&mut peer, Event::ConnFail(old_primary_id));
        assert_eq!(next, State::Established, "stale ConnFail must be ignored");
        assert!(peer.packet_tx.is_some(), "promoted conn must stay intact");

        let notif = NotificationPacket::new(NotifyCode::Cease, 0, Vec::new());
        let (next, _) = fsm_next_state(&mut peer, Event::NotifMsg(old_primary_id, notif));
        assert_eq!(
            next,
            State::Established,
            "stale NOTIFICATION must be ignored"
        );
    }

    /// A KEEPALIVE from a still-parked (unpromoted) collision conn is
    /// ignored, as before — §6.8 hasn't picked a winner yet.
    #[tokio::test]
    async fn parked_collision_keepalive_is_still_ignored() {
        let (mut peer, _primary_id, collision_id) = peer_with_collision();
        let (next, _) = fsm_next_state(&mut peer, Event::KeepAliveMsg(collision_id));
        assert_eq!(next, State::OpenSent);
        assert!(peer.collision.is_some());
    }

    /// A dial failure is only meaningful while the dial is
    /// outstanding (Connect); arriving later it must not disturb the
    /// session that superseded it. A current one follows the RFC 4271
    /// Connect cell: restart the ConnectRetryTimer and go to Active.
    #[tokio::test]
    async fn stale_dial_failure_does_not_touch_a_live_session() {
        let mut peer = test_peer(false);
        peer.state = State::Established;
        let (next, _) = fsm_next_state(&mut peer, Event::DialFail);
        assert_eq!(next, State::Established);

        peer.state = State::Connect;
        let (next, _) = fsm_next_state(&mut peer, Event::DialFail);
        assert_eq!(next, State::Active, "a current dial failure retries");
        assert!(peer.timer.connect_retry.is_some());
    }

    /// Idle refuses connections: a stale dial completing after the
    /// peer fell back to Idle must not resurrect the session.
    #[tokio::test]
    async fn connected_event_in_idle_is_refused() {
        let mut peer = test_peer(false);
        assert_eq!(peer.state, State::Idle);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let stream = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();

        let next = fsm_connected(&mut peer, Role::Active, stream);
        assert_eq!(next, State::Idle);
        assert!(peer.packet_tx.is_none());
        assert!(peer.task.reader.is_none());
        assert!(peer.task.writer.is_none());
    }
}
