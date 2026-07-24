#![allow(dead_code)]
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
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

use crate::bfd::session::{EchoMode, SessionKey, SessionParams};
use crate::bgp::cap::cap_register_recv;
use crate::bgp::route::{route_clean, route_sync};
use crate::bgp::tracing::{Direction, PacketKind};
use crate::bgp::{AdjRib, MainAdjIn, Out};
use crate::bgp::{stale_route_withdraw, timer};
use crate::config::Args;
use crate::context::task::*;
use crate::{bgp_fsm_trace, bgp_packet_trace};

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
    /// `show bgp neighbor`' Local/Foreign host lines must
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
    /// A received UPDATE failed validation with an error that RFC 4271
    /// §6.3 maps to a NOTIFICATION + session reset (today: an
    /// unrecognized well-known attribute). Carries the NOTIFICATION code,
    /// subcode, and Data field. The reader emits it before the
    /// connection drops; the FSM sends the NOTIFICATION and goes Idle.
    UpdateError(NotifyCode, u8, Vec<u8>),
    // RFC 2918 Route Refresh receive. Carries the AFI/SAFI from the
    // wire (raw u16/u8) so unknown-AF refreshes still dispatch
    // through the FSM rather than tearing the session down.
    RouteRefreshMsg(u16, u8),
    StaleTimerExipires(AfiSafi),
    AdvTimerVpnv4Expires,
    AdvTimerVpnv6Expires,
    AdvTimerEvpnExpires,
}

/// Why the last established session ended — FRR's `PEER_DOWN_*`
/// analog, shown as `Last reset …, due to <reason>` in
/// `show bgp neighbor`. Initiators that know the cause park it in
/// [`Peer::down_reason`] just before sending `Event::Stop`
/// (fast-external-failover, BFD-down, `clear … hard`); causes the FSM
/// can see for itself are derived from the triggering event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerDownReason {
    /// fast-external-failover: the session's interface went down.
    InterfaceDown,
    /// BFD declared the forwarding path dead (RFC 5882 §5).
    BfdDown,
    /// RFC 4271 hold timer expired.
    HoldTimerExpired,
    /// The peer sent a NOTIFICATION.
    NotificationReceived,
    /// The TCP connection failed (reset / EOF / unreachable).
    ConnectionFailed,
    /// A received UPDATE failed validation (NOTIFICATION sent).
    UpdateError,
    /// Operator `clear bgp … hard`.
    AdminReset,
    /// A neighbor knob change bounced the session.
    ConfigChange,
    /// The FSM left Established on an event with no self-evident cause.
    Unknown,
}

impl PeerDownReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InterfaceDown => "Interface down",
            Self::BfdDown => "BFD down",
            Self::HoldTimerExpired => "Hold timer expired",
            Self::NotificationReceived => "NOTIFICATION received",
            Self::ConnectionFailed => "TCP connection failed",
            Self::UpdateError => "Update error",
            Self::AdminReset => "Admin. reset",
            Self::ConfigChange => "Config change",
            Self::Unknown => "Unknown",
        }
    }

    /// The cause implied by the FSM event that ended the session, for
    /// events whose meaning is self-evident. `Event::Stop` maps to
    /// `ConfigChange`: every Stop initiator with a more specific cause
    /// (clear / BFD / failover) parks it in [`Peer::down_reason`]
    /// first, so an unattributed Stop is a config-driven bounce.
    fn from_event(event: &Event) -> Option<Self> {
        match event {
            Event::Stop => Some(Self::ConfigChange),
            Event::HoldTimerExpires => Some(Self::HoldTimerExpired),
            Event::ConnFail(_) | Event::DialFail => Some(Self::ConnectionFailed),
            Event::NotifMsg(..) => Some(Self::NotificationReceived),
            Event::UpdateError(..) => Some(Self::UpdateError),
            _ => None,
        }
    }
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
    /// `ip-transparent` (FRR 10.4): set IP_TRANSPARENT /
    /// IPV6_TRANSPARENT on this neighbor's TCP socket so the session
    /// can use a local address the host does not own. Applied on the
    /// active connect socket before bind() (`peer_connect`, gated on
    /// `update_source` being set — without a foreign source there is
    /// nothing to liberate) and folded onto the shared listener while
    /// any peer of the address family has it
    /// (`config::apply_ip_transparent_refresh_all`). A change bounces a
    /// live session (FRR `peer_change_reset`) — the option must precede
    /// bind()/connect(). See `super::transparent` and
    /// `zebra-bgp-transport.yang`.
    pub ip_transparent: bool,
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
/// `set router bgp neighbor <addr> bfd { enabled | multihop |
/// minimum-ttl }` (zebra-bgp-bfd.yang). The configuration is
/// stored here; `enabled` flips translate into subscribe / unsubscribe
/// calls on the BFD instance via `bfd::inst::Bfd::client_req_tx`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PeerBfdConfig {
    /// Activate BFD. `None` ⇒ inherit the instance-level
    /// `router bgp { bfd { enabled } }`; `Some(false)` opts this neighbor out
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
    /// Offload control-packet expiration detection (RFC 5880 §6.8.4) to the
    /// XDP data plane once the session is Up. Single-hop only —
    /// inert on multihop sessions (the helper attaches per interface).
    /// `None` ⇒ inherit (hard default `false`: detection in userspace).
    pub detect_offload: Option<bool>,
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
    pub detect_offload: bool,
}

impl PeerBfdConfig {
    /// Resolve `self` (per-neighbor) over `default` (instance-level
    /// `router bgp { bfd {} }`), per leaf, for the inheritable bits
    /// (enable + Echo + detect-offload). Hop-mode / min-ttl stay
    /// per-neighbor (read directly).
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
            detect_offload: self
                .detect_offload
                .or(default.detect_offload)
                .unwrap_or(false),
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

/// Per-neighbor `local-as` (zebra-bgp-local-as.yang): present a
/// substitute AS number to this neighbor instead of the router's
/// global AS — the RFC 7705 AS-migration tool. The bare form changes
/// three planes of the session:
///
/// - OPEN: the My-AS field (and the AS4 capability) carry
///   [`Self::as_number`];
/// - outbound eBGP updates: the real AS is prepended first, then the
///   substitute (the receiver sees `substitute, real, …`);
/// - inbound updates from this peer: the substitute is prepended at
///   ingress so the rest of the network still sees the path through
///   the old AS.
///
/// The three boolean modifiers are independent, one per plane
/// (`no_prepend` = inbound, `replace_as` = outbound, `dual_as` =
/// session); FRR's CLI nests them but its northbound model does not.
/// `None` on [`PeerConfig`] disables the feature. The substitute must
/// differ from the router's global AS (config-callback-enforced).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct LocalAs {
    /// The substitute AS presented to this neighbor.
    pub as_number: u32,
    /// Inbound: skip the ingress prepend of the substitute AS on
    /// routes received from this neighbor.
    pub no_prepend: bool,
    /// Outbound: prepend only the substitute AS, hiding the real AS.
    pub replace_as: bool,
    /// Session: allow the neighbor to peer with either the real AS or
    /// the substitute — a Bad Peer AS NOTIFICATION makes the next OPEN
    /// retry with the other AS number (see
    /// [`Peer::local_as_dual_fallback`]).
    pub dual_as: bool,
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
    pub llgr: AfiSafis<LlgrValue>,
    pub addpath: AfiSafis<AddPathValue>,
    pub route_refresh: bool,
    // When true, the peer's pre-policy Adj-RIB-In is replayed locally
    // on `clear ... soft in` instead of (or in addition to) sending a
    // Route Refresh. Lets policy changes take effect without a session
    // bounce when the peer doesn't support RFC 2918, at the cost of
    // keeping received UPDATEs in memory.
    pub soft_reconfig_in: bool,
    /// BGP-PIC next-hop-gated route retention (`neighbor X pic-retention`).
    /// When `true`, a session-down marks this peer's VPN routes stale and
    /// keeps them while their next hop stays NHT-reachable, instead of
    /// withdrawing immediately. Used by IS-IS Mirror SID egress *node*
    /// protection so the ingress keeps forwarding toward the failed
    /// egress's SID (held alive + redirected by the PLR's IGP retention).
    pub pic_retention: bool,
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
    /// Per-neighbor `local-as` (zebra-bgp-local-as.yang). `None` runs
    /// the session under the router's global AS; `Some` presents the
    /// substitute AS to this neighbor (see [`LocalAs`]).
    pub local_as: Option<LocalAs>,
    /// Debug/test knob (zebra-bgp-unknown-attr.yang): attach a synthetic
    /// unrecognized path attribute to every IPv4-unicast route advertised
    /// to this neighbor. Lets a test originate an unknown attribute with a
    /// chosen Type Code and Attribute Flags so the receiver's RFC 4271 §9
    /// handling (transitive-retain + Partial / non-transitive-drop /
    /// well-known NOTIFICATION) can be exercised end to end. `None` = off.
    pub attach_unknown_attr: Option<UnknownAttr>,
    /// Free-form operator note (`neighbor <addr> description <text>`),
    /// echoed under the header line of `show bgp neighbors`.
    pub description: Option<String>,
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
            llgr: AfiSafis::new(),
            addpath: AfiSafis::new(),
            route_refresh: Default::default(),
            soft_reconfig_in: Default::default(),
            pic_retention: false,
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
            local_as: None,
            attach_unknown_attr: None,
            description: None,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
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

/// Default RFC 4724 Restart Time (seconds) advertised for a
/// graceful-restart-enabled family when no explicit value is
/// configured — matches FRR's `bgp graceful-restart restart-time`
/// default. The neighbor YANG has no per-family restart-time leaf, so
/// this is the effective value. Clamped to the 12-bit field (≤ 4095) at
/// emit time.
pub const GR_RESTART_TIME_DEFAULT: u32 = 120;

#[derive(Debug, Default, Clone)]
pub struct PeerSubConfig {
    /// `afi-safi <name> graceful-restart enabled`: the RFC 4724 Restart
    /// Time in **seconds** to advertise for this family, or `None` when
    /// GR is off. Set to [`GR_RESTART_TIME_DEFAULT`] on enable (there is
    /// no per-family restart-time leaf in the YANG). Previously stored a
    /// bare `1`, which the OPEN emitted verbatim — a helper then flushed
    /// retained routes after ~1 s, defeating the whole feature.
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
    /// `afi-safi <name> next-hop-unchanged` (ietf-bgp-neighbor). When
    /// `true`, VPN routes re-advertised to this eBGP neighbor keep their
    /// received next-hop (and their received VPN label) instead of the
    /// default eBGP rewrite to self. Required on the multihop eBGP VPNv4
    /// session between the route reflectors of an RR-based Inter-AS
    /// Option C — the RRs are outside the forwarding path, so the
    /// reflected route must keep the originating PE as the LSP endpoint.
    /// Locally-originated routes still rewrite. Honored on the VPNv4
    /// advertise path (`route_update_ipv4` / `vpnv4_service_label`).
    pub next_hop_unchanged: bool,
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
    /// port. Rendered as `Foreign host/port` by `show bgp neighbor`,
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
        for entry in self.0.values_mut() {
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
    /// `local-as … dual-as` runtime state: `true` after a Bad Peer AS
    /// NOTIFICATION flipped the session back to the router's global AS
    /// (the neighbor's `remote-as` no longer expects the substitute).
    /// The next Bad Peer AS flips it again, so the session oscillates
    /// between the two until one is accepted — FRR's retry scheme.
    /// Only consulted while `config.local_as` has `dual_as` set; reset
    /// whenever the `local-as` configuration changes.
    pub local_as_dual_fallback: bool,
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
    /// The interface the established session rides, snapshotted by the
    /// owning instance on the transition into Established (from
    /// [`Self::resolve_session_ifindex`]) and cleared when the session
    /// ends. Consulted first by fast-external-failover's link-down
    /// sweep, so a session outlives `AddrDel` reordering and parallel
    /// links: the mapping was pinned while the connection was up
    /// (FRR's cached `peer->nexthop.ifp`). `None` while not
    /// established — the sweep falls back to live resolution.
    pub session_ifindex: Option<u32>,
    /// Pending session-down cause, parked by the initiator right
    /// before it sends `Event::Stop` (fast-external-failover,
    /// BFD-down, `clear … hard`). Consumed (`take`) by [`fsm`] when
    /// the session actually leaves Established; cleared on entering
    /// Established so a stale label cannot mis-attribute a later
    /// reset.
    pub down_reason: Option<PeerDownReason>,
    /// Why and when the last established session ended — the
    /// `Last reset …, due to <reason>` line in `show bgp neighbor`.
    /// Survives re-establishment (FRR semantics: it describes the
    /// *last* reset, not the current session).
    pub last_reset: Option<(PeerDownReason, Instant)>,
    pub peer_type: PeerType,
    /// RFC 9572 §6.1 region identifier, resolved from this peer's
    /// neighbor-group (`region-id`) by `apply_inherited`. `Some` marks the
    /// peer as belonging to a segmentation region; the EVPN receive /
    /// advertise paths use it for cross-region IMET suppression and Type-9
    /// Per-Region I-PMSI re-origination. `None` = not a region peer.
    pub region_id: Option<[u8; 8]>,
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
    /// Adj-RIB-In for the main-owned families (EVPN, flowspec,
    /// BGP-LS). The sharded families' received routes live in
    /// `BgpShard::adj_in` keyed by this peer's `ident` (RIB sharding
    /// plan B.1 / D3).
    pub adj_in: MainAdjIn,
    pub adj_out: AdjRib<Out>,
    /// Resumable IPv4-unicast session-up sync cursor (Tier 1a).
    /// `Some` only while a chunked dump is in flight; gated on
    /// `ZEBRA_BGP_SYNC_CHUNK` (legacy one-shot `route_sync_ipv4` when
    /// the flag is off, so this stays `None`).
    pub sync_v4: Option<super::route::Ipv4SyncCursor>,
    /// Per-peer egress task (A2 ⑥ / (a′)). `Some` only at gate-on
    /// (`ZEBRA_BGP_PEER_TASK`) while Established: it owns the v4-unicast
    /// egress off the main loop. `None` at gate-off (egress on main via
    /// update-groups, today's default) and between sessions. For now the
    /// task is spawned/torn down here but idle; routing the egress
    /// through it comes later.
    pub pet: Option<super::peer_egress::PeerEgressTask>,
    /// Egress backlog gauge (Tier 1b backpressure): the per-peer writer
    /// task publishes `packet_rx.len()` (pending UPDATE messages) here
    /// after each write; the sync cursor reads it and parks itself when
    /// a slow socket lets the queue exceed the watermark, so a large
    /// dump can't outrun the peer and grow memory unboundedly. Shared
    /// (the writer holds a clone).
    pub egress_depth: Arc<AtomicUsize>,
    pub opt: ParseOption,
    /// Per-AFI/SAFI inbound/outbound route-policy + prefix-set, bound via
    /// `neighbor X afi-safi <name> {policy,prefix-set} {in,out} <ref>`.
    /// An explicit entry for a family (name set) wins for that family;
    /// otherwise the family falls back to [`policy_list_legacy`] /
    /// [`prefix_set_legacy`]. Read through [`Peer::policy_list_at`] /
    /// [`Peer::prefix_set_at`], never indexed directly, so the fallback
    /// stays consistent across every apply site.
    pub policy_list: BTreeMap<AfiSafi, InOuts<PolicyListValue>>,
    pub prefix_set: BTreeMap<AfiSafi, InOuts<PrefixSetValue>>,
    /// Peer-wide fallback policy / prefix-set. Fed by the legacy
    /// top-level `neighbor X policy {in,out}` (kept for backward
    /// compatibility) and by `neighbor-group` inheritance, and used by
    /// any family without its own per-AFI binding.
    pub policy_list_legacy: InOuts<PolicyListValue>,
    pub prefix_set_legacy: InOuts<PrefixSetValue>,
    /// Cached owned snapshot of the effective IPv4-unicast *outbound*
    /// policy, rebuilt by `rebuild_out_policy` only when that policy
    /// resolves (`process_policy_msg`). `sync_ctx` clones the `Arc` into
    /// every (v4-unicast) `SyncCtx`, so the per-route egress evaluation
    /// (and later a shard worker) reads the policy without a deep clone.
    pub out_policy: Arc<super::policy::OutPolicy>,
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

    /// When the first `NdEvent::NeighborDiscovered` materialized this
    /// interface-keyed peer. `None` for address-keyed peers and for
    /// dormant peers created at config time before any RA has arrived.
    pub nd_discovered_at: Option<Instant>,
    /// Timestamp of the most recent `NdEvent::NeighborDiscovered` for
    /// this peer. Updated on every RA that refreshes the remote
    /// link-local; equal to `nd_discovered_at` right after the first
    /// event.  `None` in the same cases as `nd_discovered_at`.
    pub nd_refreshed_at: Option<Instant>,
    /// Running total of `NdEvent::NeighborDiscovered` events applied to
    /// this peer. 0 for address-keyed and dormant peers; 1 after the
    /// first RA; incremented on every subsequent refresh. The render
    /// path reports `nd_event_count.saturating_sub(1)` as the refresh
    /// count (events after the initial discovery).
    pub nd_event_count: u64,
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
            local_as_dual_fallback: false,
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
            session_ifindex: None,
            down_reason: None,
            last_reset: None,
            peer_type: PeerType::IBGP,
            region_id: None,
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
            adj_in: MainAdjIn::new(),
            adj_out: AdjRib::new(),
            sync_v4: None,
            pet: None,
            egress_depth: Arc::new(AtomicUsize::new(0)),
            opt: ParseOption::default(),
            policy_list: BTreeMap::new(),
            prefix_set: BTreeMap::new(),
            policy_list_legacy: InOuts::<PolicyListValue>::default(),
            prefix_set_legacy: InOuts::<PrefixSetValue>::default(),
            out_policy: Arc::new(super::policy::OutPolicy::default()),
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
            nd_discovered_at: None,
            nd_refreshed_at: None,
            nd_event_count: 0,
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

    /// An egress [`UpdatePacket`] sized and encoded for this session:
    /// the negotiated max message length and the RFC 6793 ASN width.
    /// Every per-peer UPDATE build must come through here (or copy the
    /// `as4` stamp) — a site that forgets sends 4-octet AS_PATHs to an
    /// OLD (non-AS4) peer, which misparses them.
    pub fn update_packet(&self) -> UpdatePacket {
        let mut update = UpdatePacket::with_max_packet_size(self.max_packet_size());
        update.as4 = self.as4;
        update
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

    /// The active `local-as` substitute for this session, if any.
    /// `None` when the knob is off — and also while the `dual-as`
    /// fallback has flipped the session to the router's global AS, so
    /// every consumer (OPEN, ingress/egress prepends, update-group
    /// signature) degrades to normal behavior in lockstep, mirroring
    /// FRR's `peer->change_local_as` toggling.
    pub fn change_local_as(&self) -> Option<u32> {
        match self.config.local_as {
            Some(la) if !(la.dual_as && self.local_as_dual_fallback) => Some(la.as_number),
            _ => None,
        }
    }

    /// The AS number this session presents in its OPEN (My-AS field
    /// and AS4 capability): the `local-as` substitute when active, the
    /// router's global AS otherwise.
    pub fn open_local_as(&self) -> u32 {
        self.change_local_as().unwrap_or(self.local_as)
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

    /// Whether fast-external-failover governs this peer: single-hop
    /// eBGP. FRR parity (`bgp_ifp_down`): default TTL-1 eBGP and GTSM
    /// (`ttl-security` — connected-only in zebra-rs) participate;
    /// `ebgp-multihop` opts out; iBGP (TTL 255) never participates.
    /// Deliberately NOT [`Self::connected_check_applies`]: that also
    /// exempts `disable-connected-check` and link-local peers, which
    /// FRR does fail over.
    pub fn fast_failover_applies(&self) -> bool {
        self.is_ebgp() && self.config.transport.ebgp_multihop.is_none()
    }

    /// Resolve the interface this peer's session rides right now, most
    /// precise source first: the interface key itself for unnumbered
    /// peers; the link-local connect scope; then the *local* socket
    /// address of the live/last connection (a v6 scope-id directly,
    /// else the connected subnet the local address sits on — unlike
    /// the peer address, the local address stays unambiguous across
    /// parallel links to the same neighbor); and only then the subnet
    /// covering the peer address. The owning instance snapshots this
    /// into [`Self::session_ifindex`] when the session establishes
    /// (FRR caches `peer->nexthop.ifp` the same way); the live form
    /// remains the fallback for peers that never established.
    pub fn resolve_session_ifindex(
        &self,
        subnets: &super::connected::ConnectedSubnets,
    ) -> Option<u32> {
        if let PeerOrigin::Interface { ifindex } = self.origin {
            return Some(ifindex);
        }
        if let Some(scope) = self.scope_id {
            // v6 link-local numbered peer
            return Some(scope);
        }
        if let Some(local) = self.param.local_addr {
            if let std::net::SocketAddr::V6(v6) = local
                && v6.scope_id() != 0
            {
                return Some(v6.scope_id());
            }
            if let Some(ifindex) = subnets.ifindex_for(local.ip()) {
                return Some(ifindex);
            }
        }
        subnets.ifindex_for(self.address)
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

    /// Borrowed view of this peer's outbound policy. The
    /// egress build takes this instead of `&Peer` so the same evaluation
    /// can run in a shard worker (which holds a `SyncCtx`, not a `Peer`).
    /// Rebuild the cached outbound-policy snapshot from the current
    /// Output-direction `prefix_set` / `policy_list`. Called whenever that
    /// policy resolves (`process_policy_msg`) so the `Arc` every `SyncCtx`
    /// clones stays current; the deep clone of the route-map / prefix-list
    /// happens here — once per resolve, never per advertised route.
    pub fn rebuild_out_policy(&mut self) {
        // The cached snapshot drives only the IPv4-unicast egress (the
        // `SyncCtx` family); other families read the peer directly.
        let v4u = AfiSafi::new(Afi::Ip, Safi::Unicast);
        self.out_policy = Arc::new(super::policy::OutPolicy {
            prefix_set: self
                .prefix_set_at(v4u, super::policy::InOut::Output)
                .clone(),
            policy_list: self
                .policy_list_at(v4u, super::policy::InOut::Output)
                .clone(),
        });
    }

    /// The effective inbound/outbound prefix-set for `afi_safi`: the
    /// family's explicit per-AFI binding if it names one, else the
    /// peer-wide [`prefix_set_legacy`] fallback (top-level / inherited).
    pub fn prefix_set_at(
        &self,
        afi_safi: AfiSafi,
        dir: super::policy::InOut,
    ) -> &super::policy::PrefixSetValue {
        match self.prefix_set.get(&afi_safi).map(|io| io.get(&dir)) {
            Some(v) if v.name.is_some() => v,
            _ => self.prefix_set_legacy.get(&dir),
        }
    }

    /// The effective inbound/outbound policy-list for `afi_safi`. Same
    /// per-AFI-wins-else-legacy rule as [`prefix_set_at`].
    pub fn policy_list_at(
        &self,
        afi_safi: AfiSafi,
        dir: super::policy::InOut,
    ) -> &super::policy::PolicyListValue {
        match self.policy_list.get(&afi_safi).map(|io| io.get(&dir)) {
            Some(v) if v.name.is_some() => v,
            _ => self.policy_list_legacy.get(&dir),
        }
    }

    /// Mutable per-AFI prefix-set slot, creating the family entry on
    /// demand. Used by the config + resolve paths to bind a name and to
    /// fill the resolved object.
    pub fn prefix_set_slot(
        &mut self,
        afi_safi: AfiSafi,
        dir: super::policy::InOut,
    ) -> &mut super::policy::PrefixSetValue {
        self.prefix_set.entry(afi_safi).or_default().get_mut(&dir)
    }

    /// Mutable per-AFI policy-list slot (see [`prefix_set_slot`]).
    pub fn policy_list_slot(
        &mut self,
        afi_safi: AfiSafi,
        dir: super::policy::InOut,
    ) -> &mut super::policy::PolicyListValue {
        self.policy_list.entry(afi_safi).or_default().get_mut(&dir)
    }

    /// Snapshot this peer's IPv4-unicast egress context (A2). `router_id`
    /// is the local/global router-id (`*bgp.router_id`), used for the
    /// next-hop fallback and the cluster-id. Cheap (all-`Copy`); the
    /// egress build (`route_update_ipv4`) takes this instead of `&Peer`
    /// so the same build can run in a shard worker that has no `Peer`.
    pub fn sync_ctx(&self, router_id: Ipv4Addr, as_sets_withdraw: bool) -> super::route::SyncCtx {
        super::route::SyncCtx {
            ident: self.ident,
            peer_type: self.peer_type,
            reflector_client: self.reflector_client,
            local_addr_v4: self.param.local_addr.and_then(|sa| match sa.ip() {
                IpAddr::V4(v4) => Some(v4),
                _ => None,
            }),
            router_id,
            remote_id: self.remote_id,
            remote_address: self.address,
            vpnv4_next_hop_self: self.next_hop_self(Afi::Ip, Safi::MplsVpn),
            vpnv4_next_hop_unchanged: self.next_hop_unchanged(Afi::Ip, Safi::MplsVpn),
            unicast_next_hop_self: self.next_hop_self(Afi::Ip, Safi::Unicast),
            unicast_next_hop_unchanged: self.next_hop_unchanged(Afi::Ip, Safi::Unicast),
            egress_as: self.egress_as(),
            out_policy: self.out_policy.clone(),
            packet_tx: self.packet_tx.clone(),
            egress_depth: self.egress_depth.clone(),
            extended_message: self.opt.extended_message,
            as4: self.as4,
            attach_unknown_attr: self.config.attach_unknown_attr.clone(),
            as_sets_withdraw,
        }
    }

    /// The eBGP AS_PATH egress transform inputs for this peer (A2). Shared
    /// across address families — the v6 / LU / VPN advertise builders call
    /// `ebgp_egress_aspath` with this too.
    pub fn egress_as(&self) -> super::route::EgressAs {
        super::route::EgressAs {
            is_ebgp: self.is_ebgp(),
            local_as: self.local_as,
            remote_as: self.remote_as,
            as_override: self.config.as_override,
            remove_private_as: self.config.remove_private_as,
            local_as_substitute: self.change_local_as(),
            local_as_replace: self.config.local_as.is_some_and(|la| la.replace_as),
        }
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

    /// Whether `afi-safi <name> next-hop-unchanged` is set for this
    /// neighbor in the given address family. Keeps the received next-hop
    /// (and VPN label) on eBGP advertisement of forwarded VPN routes —
    /// see [`PeerSubConfig::next_hop_unchanged`].
    pub fn next_hop_unchanged(&self, afi: Afi, safi: Safi) -> bool {
        self.config
            .sub
            .get(&AfiSafi::new(afi, safi))
            .map(|c| c.next_hop_unchanged)
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
    /// Shard-scope Loc-RIB tables (unicast/LU/VPN). Split from
    /// `local_rib` per the RIB sharding plan's B.1/D3 partition —
    /// these are the tables a future shard task will own.
    pub shard: &'a mut super::shard::BgpShard,
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
    /// SRv6 twin of `flex_algo_routes` (borrowed `Bgp::flex_algo_srv6_routes`):
    /// per-algo (prefix → node End SID) for colour-aware SRv6 H.Encap
    /// steering. `None` in contexts without colour steering (per-VRF).
    pub flex_algo_srv6_routes: Option<&'a super::color_policy::FlexAlgoSrv6Shadow>,
    /// Central MPLS label allocator (`Bgp::vrf_label_alloc`), borrowed
    /// for the receive `BgpTop` so the shard can refill its per-route
    /// label sub-block by [carving][super::vrf::VrfLabelAllocator::carve]
    /// from it (RIB sharding B.2). `Some` only on the receive path —
    /// the per-prefix label caches and the sub-block itself live on
    /// `BgpShard::labels`; this is just the refill source. `None` in
    /// every advertise / originate / NHT `BgpTop` (self-originated FECs
    /// advertise implicit-null and need no local label) and on per-VRF
    /// tasks.
    pub central_label_alloc: Option<&'a mut super::vrf::VrfLabelAllocator>,
    /// Precomputed global-IPv6 SRv6 export data (`segment-routing srv6
    /// ipv6-unicast`), borrowed from the owning [`super::inst::Bgp`].
    /// `Some` only when origination is enabled and the locator has
    /// resolved; the egress path (`route_update_ipv6`) then stamps
    /// locally-originated routes with its End.DT6 Prefix-SID + locator
    /// next-hop. `None` on per-VRF tasks and whenever origination is off.
    pub srv6_ipv6_export: Option<&'a super::inst::Srv6Ipv6Export>,
    /// RFC 9774 global toggle (`router bgp as-sets-withdraw`). Borrowed
    /// from the owning [`super::inst::Bgp`].
    pub as_sets_withdraw: bool,
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
        bgp_fsm_trace!(
            peer,
            conn_id = id,
            "bgp: ignoring event from a superseded connection",
        );
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
        Event::UpdateError(code, sub_code, data) => (
            fsm_update_error(peer, code, sub_code, data),
            FsmEffect::None,
        ),
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

fn fsm_effect(
    id: usize,
    effect: FsmEffect,
    bgp: &mut BgpTop,
    peers: &mut PeerMap,
    shards: Option<&super::shard::pool::ShardPool>,
) {
    match effect {
        FsmEffect::None => {}
        FsmEffect::RouteUpdate(packet) => {
            route_from_peer(id, packet, bgp, peers, shards);
        }
        FsmEffect::StaleExpire(_afi_safi) => {
            stale_route_withdraw(id, bgp, peers);
        }
        FsmEffect::RouteRefreshRecv { afi: _, safi: _ } => {
            super::route::route_soft_out_peer(id, bgp, peers);
        }
    }
}

pub fn fsm(
    bgp_ref: &mut BgpTop,
    peer_map: &mut PeerMap,
    id: usize,
    event: Event,
    shards: Option<&super::shard::pool::ShardPool>,
) {
    // Captured before `event` is consumed: the down-cause this event
    // implies, in case it ends the established session below.
    let event_reason = PeerDownReason::from_event(&event);

    // Compute new state (single match, only &mut Peer).
    let (prev_state, effect) = {
        // Events carry a bare slot index and sit queued in the event
        // channel: a config delete (`peers.remove`), interface-neighbor
        // delete, or the dynamic-peer reaper can empty `peers[id]`
        // before a queued event for it is dispatched. A tombstoned slot
        // is therefore a normal race, not a bug — drop the event. (No
        // path inside the FSM call graph removes slots, so this single
        // entry guard covers the later lookups in this function.)
        let Some(peer) = peer_map.get_mut_by_idx(id) else {
            tracing::debug!(ident = id, "bgp: dropping FSM event for a removed peer");
            return;
        };
        let prev_state = peer.state;
        let (new_state, effect) = fsm_next_state(peer, event);
        peer.state = new_state;
        (prev_state, effect)
    };

    // Keep the membership index in lockstep with the live
    // `state.is_established()` predicate the fan-outs used to scan:
    // the index must flip together with the state set above, before
    // the FSM effect and route_clean below can fan anything out —
    // withdraw-before-clean excludes the dying peer exactly as the
    // live-state filters did.
    {
        let now_established = peer_map
            .get_by_idx(id)
            .map(|p| p.state.is_established())
            .unwrap_or(false);
        if prev_state.is_established() && !now_established {
            peer_map.membership_withdraw(id);
        } else if !prev_state.is_established() && now_established {
            peer_map.membership_enroll(id);
        }
    }

    // Execute side effects that need peer_map.
    fsm_effect(id, effect, bgp_ref, peer_map, shards);

    // Handle state-transition consequences.
    {
        let peer = peer_map.get_mut_by_idx(id).unwrap();
        if prev_state == peer.state {
            return;
        }
        if prev_state.is_established() && !peer.state.is_established() {
            peer.instant = Some(Instant::now());
            // Record why the session ended: the initiator's parked
            // cause wins; else derive from the event itself.
            peer.last_reset = Some((
                peer.down_reason
                    .take()
                    .or(event_reason)
                    .unwrap_or(PeerDownReason::Unknown),
                Instant::now(),
            ));
        }
        if !prev_state.is_established() && peer.state.is_established() {
            peer.instant = Some(Instant::now());
            // A parked cause that never fired (its Stop lost a race
            // with the session coming up) must not mislabel the next
            // reset.
            peer.down_reason = None;
            // A2 ⑥ (gate-on): spawn the per-peer egress task. For now it
            // is idle (lifecycle only); routing the v4 egress to it comes later.
            if super::peer_egress::peer_egress_task_enabled() {
                let ctx = peer.sync_ctx(*bgp_ref.router_id, bgp_ref.as_sets_withdraw);
                let add_path = peer.opt.is_add_path_send(Afi::Ip, Safi::Unicast);
                peer.pet = Some(super::peer_egress::PeerEgressTask::spawn(ctx, add_path));
            }
            route_sync(peer, bgp_ref, shards.is_some());
        }
        timer::update_timers(peer);
    }

    // route_clean if leaving Established (needs peer_map).
    if prev_state.is_established() && !peer_map.get_by_idx(id).unwrap().state.is_established() {
        route_clean(id, bgp_ref, peer_map, shards);
        // Drop any in-flight resumable sync cursor (Tier 1a) — a
        // pending tick for this peer no-ops in `drive_sync_v4`, but
        // clear it so the keys snapshot isn't held past the session.
        if let Some(peer) = peer_map.get_mut_by_idx(id) {
            peer.sync_v4 = None;
            // A2 ⑥: drop the per-peer egress task (abort-on-drop) so it
            // doesn't outlive the session.
            peer.pet = None;
        }
    }

    // Maintain update-group membership across the Established
    // boundary. Detach must run *after* route_clean so observability
    // sees the peer leave the group only once routes have been torn
    // down; attach runs after route_sync so the group reflects the
    // post-sync state. (The membership index flipped earlier, with
    // the state itself.)
    {
        let now_established = peer_map
            .get_by_idx(id)
            .map(|p| p.state.is_established())
            .unwrap_or(false);
        if prev_state.is_established() && !now_established {
            super::update_group::detach(bgp_ref.update_groups, peer_map, id);
        } else if !prev_state.is_established() && now_established {
            super::update_group::attach(
                bgp_ref.update_groups,
                peer_map,
                id,
                *bgp_ref.router_id,
                bgp_ref.as_sets_withdraw,
            );
        }
        peer_map.debug_verify_membership();
    }
}

// The three advertise-debounce expiries below return `peer.state`, not
// a hardcoded `State::Established`: a timer that outlives its session
// (`route_clean` now cancels them, but any future re-arm path must not
// resurrect the bug) would otherwise forge an Idle peer into
// Established with no session behind it. The flush is likewise gated —
// a stale timer firing after a fast reconnect must not push the dead
// session's cached routes onto the new session's writer.

pub fn fsm_adv_timer_vpnv4_expires(peer: &mut Peer) -> State {
    peer.cache_vpnv4_timer = None;
    if peer.state.is_established() {
        peer.flush_vpnv4();
    }
    peer.state
}

pub fn fsm_adv_timer_vpnv6_expires(peer: &mut Peer) -> State {
    peer.cache_vpnv6_timer = None;
    if peer.state.is_established() {
        peer.flush_vpnv6();
    }
    peer.state
}

pub fn fsm_adv_timer_evpn_expires(peer: &mut Peer) -> State {
    peer.cache_evpn_timer = None;
    if peer.state.is_established() {
        peer.flush_evpn();
    }
    peer.state
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
        bgp_fsm_trace!(
            peer,
            "bgp: holding eBGP session — neighbor is not on a connected network and disable-connected-check is off",
        );
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
    // Drop packet_tx to close the writer's channel, cancel the
    // reader, and *detach* the writer so it drains the NOTIFICATION
    // onto the wire and exits — dropping it would abort the task
    // with the frame still queued, sending a bare FIN instead.
    let CollisionConn { reader, writer, .. } = collision;
    drop(reader);
    writer.detach();
}

/// Tear down the primary connection in place (send NOTIFICATION
/// first, then release the reader/writer/packet_tx triple — the
/// writer is detached, not aborted, so the NOTIFICATION drains onto
/// the wire before the socket closes).
fn close_primary(peer: &mut Peer, code: NotifyCode, sub_code: u8) {
    peer_send_notification(peer, code, sub_code, Vec::new());
    peer.packet_tx = None;
    peer.task.reader = None;
    if let Some(writer) = peer.task.writer.take() {
        writer.detach();
    }
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

    // Peer ASN — from the 4-octet AS capability when present, else the
    // 2-octet My-AS field (RFC 6793 §4.1).
    let asn = open_asn(&packet);

    // RFC 6793 §4.2 internal consistency of the peer's OPEN: the
    // capability must not name the AS_TRANS placeholder as a real AS,
    // and the My-AS field must be either AS_TRANS or the capability
    // value itself. (A 4-octet ASN has no 2-octet form, so AS_TRANS in
    // My-AS with the real ASN in the capability is the one legal way to
    // announce it — the check the old code failed: it re-compared the
    // raw 2-octet field against `remote_as` and sent every 4-byte-ASN
    // peer back to Idle.)
    let open_consistent = match &packet.bgp_cap.as4 {
        Some(cap) => {
            cap.asn != u32::from(AS_TRANS)
                && (packet.asn == AS_TRANS || u32::from(packet.asn) == cap.asn)
        }
        None => true,
    };

    // Compare with configured asn.
    if peer.remote_as != asn || !open_consistent {
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

    // RFC 6793: the session runs 4-octet AS encoding iff both sides
    // advertised the capability. `peer.as4` feeds the update-group
    // signature and the egress encode; `peer.opt.as4` mirrors it for
    // the parse option. (Our half was recorded when the OPEN we sent
    // was built.)
    peer.opt.as4.recv = packet.bgp_cap.as4.is_some();
    peer.as4 = peer.opt.is_as4();

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

pub fn fsm_bgp_notification(peer: &mut Peer, conn: ConnTag, packet: NotificationPacket) -> State {
    peer.counter[BgpType::Notification as usize].rcvd += 1;
    // A NOTIFICATION is the peer telling us why it is tearing the session down.
    // The dispatch-level `recv NOTIFICATION` in `Bgp::process_msg` only records
    // that one arrived; this is the decoded reason, including any RFC 9003
    // shutdown communication — an operator's "maintenance window, back at 03:00"
    // is worth exactly as much as the numeric subcode next to it. Same
    // `tracing packet notification` gate as its sibling.
    bgp_packet_trace!(
        peer,
        PacketKind::Notification,
        Direction::Recv,
        "bgp: NOTIFICATION received: {} / {}{}",
        packet.code,
        bgp_packet::notify_sub_code_str(packet.code, packet.sub_code),
        packet
            .shutdown_communication()
            .map(|m| format!(" — \"{m}\""))
            .unwrap_or_default(),
    );
    // `local-as … dual-as` (RFC 7705 migration aid): a Bad Peer AS
    // means the neighbor's `remote-as` expects the other one of our
    // two AS numbers — flip which one the next OPEN presents. FRR
    // retries the same way on this NOTIFICATION (bgp_packet.c).
    if packet.code == NotifyCode::OpenMsgError
        && packet.sub_code == u8::from(OpenError::BadPeerAS)
        && peer.config.local_as.is_some_and(|la| la.dual_as)
    {
        peer.local_as_dual_fallback = !peer.local_as_dual_fallback;
        bgp_fsm_trace!(
            peer,
            "bgp: Bad Peer AS with local-as dual-as — next OPEN presents AS {}",
            peer.open_local_as(),
        );
    }
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
    peer.task.writer = Some(peer_start_writer(
        write_half,
        packet_rx,
        peer.egress_depth.clone(),
    ));
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

/// RFC 4271 §6.3: a fatal UPDATE error (today, an unrecognized
/// well-known attribute) resets the session with a NOTIFICATION. Mirrors
/// [`fsm_holdtimer_expires`]: queue the NOTIFICATION on the writer, then
/// go Idle so the Established→Idle teardown drains it onto the wire (the
/// writer is detached, not aborted) and cleans the Adj-RIBs.
pub fn fsm_update_error(peer: &mut Peer, code: NotifyCode, sub_code: u8, data: Vec<u8>) -> State {
    peer_send_notification(peer, code, sub_code, data);
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
/// Park in Active per RFC 4271's Connect-state TcpConnectionFails
/// (Event 18) cell: the peer keeps accepting inbound connections while
/// it waits to redial. Routing through Idle here (as this function once
/// did for a fast idle-hold-paced redial) made a connect-only peer —
/// one that never listens, so our dial is refused instantly — spend
/// essentially the whole retry cycle in Idle, where
/// `handle_peer_connection` drops every inbound connect before its OPEN
/// is read; the session could never establish without passive-mode.
///
/// The RFC's ConnectRetryTimer default of 120s (RFC §10) is far too
/// slow a pacer for the common bring-up race where two peers boot
/// together, cross first SYNs before either listener is ready, and
/// *both* land here — so arm the connect-retry slot with an
/// idle-hold-paced (default 5s) timer instead; `update_timers` leaves
/// that slot running in Active, and its Event::Start redials via
/// [`fsm_start`]. Passive peers never dial, so they reach here only
/// defensively; keep them parked in Active listening for the remote to
/// reconnect.
pub fn fsm_dial_fail(peer: &mut Peer) -> State {
    if peer.state != State::Connect {
        return peer.state;
    }
    peer.task.connect = None;
    if peer.is_passive() {
        peer.timer.connect_retry = None;
        return State::Active;
    }
    peer.timer.connect_retry = Some(timer::start_dial_retry_timer(peer));
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
    match BgpPacket::parse_packet(rx, opt.is_as4(), Some(opt.clone())) {
        Ok((_, p)) => {
            match p {
                BgpPacket::Open(p) => {
                    cap_addpath_recv(&p.bgp_cap, opt, &config.addpath);
                    if config.extended_message && p.bgp_cap.extended.is_some() {
                        opt.extended_message = true;
                    }
                    // RFC 6793: every UPDATE after this OPEN decodes
                    // AS_PATH / AGGREGATOR at the negotiated width —
                    // 4-octet iff both sides advertised the capability.
                    // (Our own half was stamped on `opt` when this
                    // reader was spawned, in `peer_start_reader`.)
                    opt.as4.recv = p.bgp_cap.as4.is_some();
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
        Err(e) => {
            // RFC 4271 §6.3: an unrecognized well-known attribute must be
            // answered with a NOTIFICATION (Update Message Error, subcode
            // 2) before the session drops. The reader has no `&mut Peer`,
            // so hand the FSM the code/subcode/Data via an event; the
            // subsequent ConnFail is a no-op once the FSM has gone Idle.
            if let BgpParseError::UnrecognizedWellknownAttribute { attr, .. } = &e {
                let _ = tx
                    .send(Message::Event(
                        ident,
                        Event::UpdateError(
                            NotifyCode::UpdateMsgError,
                            UpdateError::UnrecognizedWellknownAttribute.into(),
                            attr.clone(),
                        ),
                    ))
                    .await;
            }
            Err(e.to_string())
        }
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
    let event_conn_fail = async |ident, conn| {
        let _ = tx.send(Message::Event(ident, Event::ConnFail(conn))).await;
    };

    let mut buf = BytesMut::with_capacity(BGP_EXTENDED_PACKET_LEN * 3);
    loop {
        match read_half.read_buf(&mut buf).await {
            Ok(read_len) => {
                if read_len == 0 {
                    event_conn_fail(ident, conn).await;
                    return;
                }

                while let Some(length) = peek_bgp_length(&buf) {
                    if length < BGP_HEADER_LEN.into() || length > opt.max_message_len() {
                        event_conn_fail(ident, conn).await;
                        return;
                    }

                    let mut remain = buf.split_off(length);
                    remain.reserve(BGP_EXTENDED_PACKET_LEN * 3);

                    match peer_packet_parse(&buf, ident, conn, tx.clone(), &mut config, &mut opt)
                        .await
                    {
                        Ok(_) => {
                            buf = remain;
                        }
                        Err(_err) => {
                            event_conn_fail(ident, conn).await;
                            return;
                        }
                    }
                }
            }
            Err(_err) => {
                event_conn_fail(ident, conn).await;
                return;
            }
        }
    }
}

pub fn peer_start_reader(peer: &Peer, conn: ConnId, read_half: OwnedReadHalf) -> Task<()> {
    let ident = peer.ident;
    let tx = peer.tx.clone();
    let config = peer.config.clone();
    let mut opt = peer.opt.clone();
    // Our half of the RFC 6793 negotiation is fixed before the OPEN
    // exchange: it is what `build_open_packet` advertises (the knob, or
    // forced by a local AS with no 2-octet form). Stamp it here rather
    // than inherit whatever the previous session negotiated.
    opt.as4.send = peer.config.four_octet || peer.open_local_as() > u16::MAX as u32;
    opt.as4.recv = false;
    Task::spawn(async move {
        peer_read(ident, conn, tx.clone(), read_half, config, opt).await;
    })
}

/// Test/debug knob: artificially slow the egress writer by N ms per
/// UPDATE (`ZEBRA_BGP_WRITER_DELAY_MS`, default 0 = off). Simulates a
/// slow peer at the application layer so the pending-UPDATE queue backs
/// up deterministically — used to exercise the Tier-1b sync-cursor park
/// without depending on kernel send-buffer / `tc` behaviour. Read once.
fn writer_delay_ms() -> u64 {
    use std::sync::OnceLock;
    static D: OnceLock<u64> = OnceLock::new();
    *D.get_or_init(|| {
        std::env::var("ZEBRA_BGP_WRITER_DELAY_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0)
    })
}

pub fn peer_start_writer(
    mut write_half: OwnedWriteHalf,
    mut rx: UnboundedReceiver<BytesMut>,
    egress_depth: Arc<AtomicUsize>,
) -> Task<()> {
    // Fresh connection ⇒ fresh queue: reset the in-flight gauge
    // synchronously (before any `send_packet` on the new channel) so it
    // doesn't carry a stale count across reconnects.
    egress_depth.store(0, Ordering::Relaxed);
    let delay = writer_delay_ms();
    Task::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let _ = write_half.write_all(&msg).await;
            // Tier 1b: decrement the in-flight gauge that `send_packet`
            // incremented on queue. Saturating because control frames
            // (keepalive/OPEN) bypass `send_packet` so weren't counted,
            // yet the writer drains them too — clamp at 0 rather than
            // wrap. The pair (send +1 / write −1) keeps the gauge a
            // real-time count of queued route UPDATEs.
            egress_depth
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                    Some(v.saturating_sub(1))
                })
                .ok();
            if delay > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
            }
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
    // `ip-transparent` — IP_TRANSPARENT before bind so a non-local
    // `update-source` is accepted (see `peer_connect`).
    let ip_transparent = peer.config.transport.ip_transparent;
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
            ip_transparent,
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
    ip_transparent: bool,
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

    // IP_TRANSPARENT must precede the bind: it is what makes the kernel
    // accept a bind to the non-local `update-source` address and emit
    // the SYN with that source. Gated on update-source being present —
    // without a foreign source there is nothing to liberate (FRR's
    // bgp_connect() applies the same both-flags gate). NOT best-effort:
    // a failure (no CAP_NET_ADMIN) is surfaced as a dial failure,
    // because the bind below would fail with EADDRNOTAVAIL anyway and
    // this error names the actual cause.
    if ip_transparent && update_source.is_some() {
        super::transparent::set_ip_transparent(socket.as_raw_fd(), remote.is_ipv4(), true)
            .inspect_err(|e| {
                tracing::warn!(
                    peer = %remote.ip(),
                    error = %e,
                    "bgp: failed to set IP_TRANSPARENT before connect \
                     (CAP_NET_ADMIN required); cannot dial from a non-local update-source",
                );
            })?;
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

    for afi_safi in peer.config.mp.0.keys() {
        let cap = CapMultiProtocol::new(&afi_safi.afi, &afi_safi.safi);
        bgp_cap.mp.insert(*afi_safi, cap);
    }
    // A local AS above 65535 is only expressible through the 4-octet AS
    // capability (the My-AS field carries AS_TRANS), so it overrides a
    // disabled `capability four-octet` knob — without the capability the
    // peer could never learn our real AS (RFC 6793 §4.1).
    if peer.config.four_octet || peer.open_local_as() > u16::MAX as u32 {
        let cap = CapAs4::new(peer.open_local_as());
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
        // RFC 7911 §3: a negotiated Send obliges us to stamp a path-id
        // on every NLRI of that family. Only IPv4 unicast and VPNv4
        // have the per-path advertise pipeline, so withhold the Send
        // half for every other family — advertising it would negotiate
        // a session we then feed malformed (id-less withdraw) or no
        // (excluded-from-fan-out) UPDATEs. The Receive half is
        // family-generic and passes through.
        let value = if super::cap::addpath_send_implemented(key.afi, key.safi) {
            addpath.clone()
        } else {
            match addpath.send_receive {
                AddPathSendReceive::Send => {
                    tracing::warn!(
                        afi = %key.afi,
                        safi = %key.safi,
                        "add-path send is not implemented for this family; \
                         capability not advertised"
                    );
                    continue;
                }
                AddPathSendReceive::SendReceive => {
                    tracing::warn!(
                        afi = %key.afi,
                        safi = %key.safi,
                        "add-path send is not implemented for this family; \
                         advertising receive only"
                    );
                    AddPathValue {
                        afi: key.afi,
                        safi: key.safi,
                        send_receive: AddPathSendReceive::Receive,
                    }
                }
                _ => addpath.clone(),
            }
        };
        bgp_cap.addpath.insert(*key, value);
    }
    for (key, sub) in peer.config.sub.iter() {
        if let Some(restart_time) = sub.graceful_restart {
            // RFC 4724 carries a single Restart Time for the whole
            // capability; advertise the largest configured per-family
            // value (each enabled family stores GR_RESTART_TIME_DEFAULT),
            // clamped to the 12-bit field.
            let time = restart_time.min(0xfff) as u16;
            let cap = bgp_cap.restart.get_or_insert_with(CapRestart::default);
            if time > cap.flag_time.restart_time() {
                cap.set_restart_time(time);
            }
            cap.entries.push(RestartEntry::new(key.afi, key.safi));
        }
        if let Some(llgr_time) = sub.llgr {
            let llgr = LlgrValue::new(key.afi, key.safi, llgr_time);
            bgp_cap.llgr.insert(*key, llgr);
        }
    }

    cap_register_send(&bgp_cap, &mut peer.cap_map);
    peer.opt.as4.send = bgp_cap.as4.is_some();
    peer.cap_send = bgp_cap.clone();

    // Remember sent hold time.
    let hold_time = peer.config.timer.hold_time() as u16;
    peer.param_tx.hold_time = hold_time;
    peer.param_tx.keepalive = hold_time / 3;

    // RFC 6793 §4.1: a local AS above 65535 has no 2-octet encoding —
    // the My Autonomous System field carries AS_TRANS and the real ASN
    // travels in the 4-octet AS capability set above. Truncating with
    // `as u16` sent a garbage AS the peer rejected with Bad Peer AS.
    let local_as = peer.open_local_as();
    let my_as = u16::try_from(local_as).unwrap_or(AS_TRANS);
    let open = OpenPacket::new(header, my_as, hold_time, &router_id, bgp_cap);
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
    let writer = peer_start_writer(write_half, packet_rx, peer.egress_depth.clone());
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
    // the limit, additional matches drop silently until a slot frees
    // up: `gc_dynamic_peer_if_session_ended` reclaims a peer whose
    // session ended, and `dynamic_neighbors::sweep_range_peers`
    // reclaims every peer of a deleted (or group-unbound) range.
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
        // Start the FSM the way a config commit does for a static
        // passive peer: `update_timers` flips a passive Idle peer to
        // Active, so the re-run of `handle_peer_connection` below
        // promotes this very stream instead of dropping it in Idle
        // (where the peer would otherwise be stuck forever — nothing
        // else ever starts a dynamic peer).
        peer.start();
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
            shard: &mut bgp.shard,
            tx: &bgp.tx,
            rib_client: &bgp.ctx.rib,
            attr_store: &mut bgp.attr_store,
            update_groups: &mut bgp.update_groups,
            interface_addrs: &bgp.interface_addrs,
            vrf_export: None,
            color_policy: Some(&bgp.color_policy),
            flex_algo_routes: Some(&bgp.flex_algo_routes),
            flex_algo_srv6_routes: Some(&bgp.flex_algo_srv6_routes),
            vrf_import: None,
            nexthop_cache: None,
            vrf_transport_v4: None,
            vrf_transport_v6: None,
            central_label_alloc: None,
            as_sets_withdraw: bgp.as_sets_withdraw,
        };
        super::route::route_soft_in_peer(
            peer_idx,
            &mut bgp_ref,
            &mut bgp.peers,
            bgp.shards.as_ref(),
        );
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
        shard: &mut bgp.shard,
        tx: &bgp.tx,
        rib_client: &bgp.ctx.rib,
        attr_store: &mut bgp.attr_store,
        update_groups: &mut bgp.update_groups,
        interface_addrs: &bgp.interface_addrs,
        vrf_export: None,
        color_policy: Some(&bgp.color_policy),
        flex_algo_routes: Some(&bgp.flex_algo_routes),
        flex_algo_srv6_routes: Some(&bgp.flex_algo_srv6_routes),
        vrf_import: None,
        nexthop_cache: None,
        vrf_transport_v4: None,
        vrf_transport_v6: None,
        central_label_alloc: None,
        as_sets_withdraw: bgp.as_sets_withdraw,
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
                if let Some(peer) = bgp.peers.get_mut_by_idx(peer_idx) {
                    peer.down_reason = Some(PeerDownReason::AdminReset);
                }
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
    /// flow (`bfd enabled true; bfd multihop true; bfd minimum-ttl 250`)
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
    /// connect-retry backstop armed (and `show bgp neighbor`
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

    /// `local-as … dual-as`: a Bad Peer AS NOTIFICATION toggles which
    /// of the two AS numbers the next OPEN presents (substitute ⇄
    /// global), and a second one toggles back. Without `dual-as` the
    /// substitute is pinned.
    #[tokio::test]
    async fn bad_peer_as_notification_toggles_dual_as_fallback() {
        let bad_peer_as = || {
            NotificationPacket::new(
                NotifyCode::OpenMsgError,
                OpenError::BadPeerAS.into(),
                Vec::new(),
            )
        };
        let mut peer = test_peer(false);
        peer.config.local_as = Some(LocalAs {
            as_number: 64999,
            no_prepend: false,
            replace_as: false,
            dual_as: true,
        });
        assert_eq!(peer.open_local_as(), 64999);

        fsm_bgp_notification(&mut peer, ConnTag::Primary, bad_peer_as());
        assert_eq!(peer.open_local_as(), 65001, "fallback to the global AS");
        assert!(
            peer.change_local_as().is_none(),
            "substitute fully inactive"
        );

        fsm_bgp_notification(&mut peer, ConnTag::Primary, bad_peer_as());
        assert_eq!(peer.open_local_as(), 64999, "second toggle flips back");

        // A non-Bad-Peer-AS NOTIFICATION must not touch the state.
        let cease = NotificationPacket::new(NotifyCode::Cease, 0, Vec::new());
        fsm_bgp_notification(&mut peer, ConnTag::Primary, cease);
        assert_eq!(peer.open_local_as(), 64999);

        // Without dual-as the substitute is pinned.
        peer.config.local_as = Some(LocalAs {
            as_number: 64999,
            no_prepend: false,
            replace_as: false,
            dual_as: false,
        });
        peer.local_as_dual_fallback = false;
        fsm_bgp_notification(&mut peer, ConnTag::Primary, bad_peer_as());
        assert_eq!(peer.open_local_as(), 64999);
    }

    /// A connection writer that is *detached* (the teardown path for
    /// connections with a queued NOTIFICATION) must drain its channel
    /// onto the wire before the socket closes — the receiver sees the
    /// frame, then FIN. The abort path used to send a bare FIN with
    /// the NOTIFICATION still queued, so the peer never learned why
    /// the session died (and `local-as dual-as` never saw the Bad
    /// Peer AS that drives its retry).
    #[tokio::test]
    async fn detached_writer_drains_queued_frames_before_fin() {
        use tokio::io::AsyncReadExt;
        use tokio::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (mut server, _) = listener.accept().await.unwrap();

        let (_read_half, write_half) = client.into_split();
        let (tx, rx) = mpsc::unbounded_channel::<BytesMut>();
        let writer = peer_start_writer(write_half, rx, Arc::new(AtomicUsize::new(0)));

        // Queue a frame, close the channel, detach — mirroring
        // `close_primary` / the Idle-entry teardown ordering.
        tx.send(BytesMut::from(&b"NOTIFICATION"[..])).unwrap();
        drop(tx);
        writer.detach();

        // read_to_end returns only at FIN, so a successful read of the
        // full frame proves frame-before-FIN ordering.
        let mut buf = Vec::new();
        server.read_to_end(&mut buf).await.unwrap();
        assert_eq!(&buf[..], b"NOTIFICATION");
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
    /// session that superseded it. A current one parks in Active — not
    /// Idle, which drops inbound connections — with an idle-hold-paced
    /// redial timer on the connect-retry slot (see `fsm_dial_fail`)
    /// rather than the 120s connect-retry backstop.
    #[tokio::test]
    async fn stale_dial_failure_does_not_touch_a_live_session() {
        let mut peer = test_peer(false);
        peer.state = State::Established;
        let (next, _) = fsm_next_state(&mut peer, Event::DialFail);
        assert_eq!(next, State::Established);

        peer.state = State::Connect;
        let (next, _) = fsm_next_state(&mut peer, Event::DialFail);
        assert_eq!(
            next,
            State::Active,
            "a current dial failure parks in Active so inbound connects are accepted"
        );
        assert!(
            peer.task.connect.is_none(),
            "the failed dial must be released"
        );

        // What `fsm()` does after a state change: re-arm timers.
        peer.state = next;
        timer::update_timers(&mut peer);
        assert!(
            peer.timer.connect_retry.is_some(),
            "the fast redial pacer must survive update_timers in Active"
        );
        assert!(
            peer.timer.idle_hold_timer.is_none(),
            "Active must not run the idle-hold timer"
        );
    }

    /// A passive peer never initiates a dial, so it only reaches
    /// `fsm_dial_fail` defensively — park it in Active listening with no
    /// redial pacer, waiting for the remote router to reconnect.
    #[tokio::test]
    async fn dial_failure_passive_peer_parks_in_active() {
        let mut peer = test_peer(true);
        peer.state = State::Connect;
        let (next, _) = fsm_next_state(&mut peer, Event::DialFail);
        assert_eq!(next, State::Active);

        peer.state = next;
        timer::update_timers(&mut peer);
        assert!(peer.timer.idle_hold_timer.is_none());
        assert!(
            peer.timer.connect_retry.is_none(),
            "a passive peer must not arm the redial pacer"
        );
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

    /// The connect-only-peer scenario: our dial toward a peer that
    /// never listens just failed with RST, and the peer then connects
    /// in. The inbound must be promoted to a session. Before the fix
    /// the failed dial parked the peer in Idle between redials, so
    /// every inbound connect was dropped before its OPEN was read and
    /// the session could never establish without passive-mode.
    #[tokio::test]
    async fn inbound_connection_after_dial_failure_is_promoted() {
        let mut peer = test_peer(false);
        peer.state = State::Connect;
        let (next, _) = fsm_next_state(&mut peer, Event::DialFail);
        peer.state = next;
        timer::update_timers(&mut peer);

        let addr: IpAddr = "10.0.0.2".parse().unwrap();
        let mut peers = PeerMap::new();
        peers.insert(addr, peer);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let stream = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();

        let leftover = handle_peer_connection(&mut peers, addr, None, stream);
        assert!(leftover.is_none(), "the inbound stream must be consumed");
        let peer = peers.get(&addr).unwrap();
        assert_eq!(
            peer.state,
            State::OpenSent,
            "the inbound connect must be promoted, not dropped"
        );
        assert_eq!(peer.primary_role, Some(Role::Passive));
        assert!(
            peer.packet_tx.is_some(),
            "our OPEN must be queued on the inbound conn"
        );
    }

    /// While the dial is still in flight (Connect), an inbound connect
    /// wins immediately: the pending dial is cancelled and the inbound
    /// carries the session.
    #[tokio::test]
    async fn inbound_connection_while_dialing_is_promoted() {
        let mut peer = test_peer(false);
        peer.state = State::Connect;
        peer.task.connect = Some(Task::spawn(async {}));

        let addr: IpAddr = "10.0.0.2".parse().unwrap();
        let mut peers = PeerMap::new();
        peers.insert(addr, peer);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let stream = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();

        let leftover = handle_peer_connection(&mut peers, addr, None, stream);
        assert!(leftover.is_none());
        let peer = peers.get(&addr).unwrap();
        assert_eq!(peer.state, State::OpenSent);
        assert!(
            peer.task.connect.is_none(),
            "the pending dial must be cancelled"
        );
        assert_eq!(peer.primary_role, Some(Role::Passive));
    }
}

#[cfg(test)]
mod fsm_removed_slot_tests {
    use super::*;
    use std::net::IpAddr;

    /// A queued event whose peer slot was emptied in the meantime
    /// (config delete of the neighbor, interface-neighbor delete, or
    /// the dynamic-peer reaper) must be dropped by `fsm()`, not
    /// dispatched into the tombstone — the old `unwrap` panicked and
    /// took the whole daemon down with it.
    #[tokio::test]
    async fn event_on_removed_peer_slot_is_dropped() {
        let (tx, rx) = mpsc::channel::<Message>(64);
        Box::leak(Box::new(rx));
        let addr: IpAddr = "10.0.0.2".parse().unwrap();
        let peer = Peer::new(
            1,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            65002,
            addr,
            None,
            tx.clone(),
            crate::context::ProtoContext::default_table_no_rib(),
        );
        let mut peers = PeerMap::new();
        peers.insert(addr, peer);
        let ident = peers.get(&addr).unwrap().ident;
        peers.remove(&addr);

        let router_id = Ipv4Addr::new(10, 0, 0, 1);
        let ctx = crate::context::ProtoContext::default_table_no_rib();
        let mut local_rib = LocalRib::default();
        let mut shard = crate::bgp::shard::BgpShard::default();
        let mut attr_store = BgpAttrStore::default();
        let mut update_groups = crate::bgp::update_group::empty_map();
        let interface_addrs = crate::bgp::interface_addrs::InterfaceAddrs::default();
        let mut top = BgpTop {
            router_id: &router_id,
            srv6_ipv6_export: None,
            local_rib: &mut local_rib,
            shard: &mut shard,
            tx: &tx,
            rib_client: &ctx.rib,
            attr_store: &mut attr_store,
            update_groups: &mut update_groups,
            interface_addrs: &interface_addrs,
            vrf_export: None,
            color_policy: None,
            flex_algo_routes: None,
            flex_algo_srv6_routes: None,
            vrf_import: None,
            nexthop_cache: None,
            vrf_transport_v4: None,
            vrf_transport_v6: None,
            central_label_alloc: None,
            as_sets_withdraw: false,
        };

        // Timer and teardown events are exactly what stays queued
        // across a neighbor delete. Each must be a silent no-op.
        fsm(
            &mut top,
            &mut peers,
            ident,
            Event::ConnRetryTimerExpires,
            None,
        );
        fsm(&mut top, &mut peers, ident, Event::Stop, None);
        assert!(peers.get_by_idx(ident).is_none());
    }
}

#[cfg(test)]
mod as4_negotiation_tests {
    use super::*;

    /// Peer in OpenSent with a parked event channel, ready to receive
    /// an OPEN. `remote_as` is what the operator configured.
    fn opensent_peer(remote_as: u32) -> Peer {
        let (tx, rx) = mpsc::channel::<Message>(64);
        Box::leak(Box::new(rx));
        let mut peer = Peer::new(
            1,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            remote_as,
            "10.0.0.2".parse().unwrap(),
            None,
            tx,
            crate::context::ProtoContext::default_table_no_rib(),
        );
        peer.state = State::OpenSent;
        peer
    }

    fn open_packet(my_as: u16, as4_cap: Option<u32>) -> OpenPacket {
        let header = BgpHeader::new(BgpType::Open, BGP_HEADER_LEN + 10);
        let mut bgp_cap = BgpCap::default();
        if let Some(asn) = as4_cap {
            bgp_cap.as4 = Some(CapAs4::new(asn));
        }
        OpenPacket::new(header, my_as, 180, &Ipv4Addr::new(2, 2, 2, 2), bgp_cap)
    }

    /// Review finding #2 regression: a 4-byte-ASN neighbor announces
    /// itself with AS_TRANS in My-AS and the real ASN in the 4-octet AS
    /// capability (RFC 6793 §4.1). The old code re-compared the raw
    /// 2-octet field against `remote_as` and sent the session to Idle
    /// on every attempt — such a peer could never establish.
    #[tokio::test]
    async fn four_byte_asn_peer_establishes_via_as_trans() {
        let mut peer = opensent_peer(4_200_000_000);
        // Build (and discard) our own OPEN so cap_send / opt.as4.send
        // record what we advertised, as they would on a live session.
        let _ = build_open_packet(&mut peer);

        let next = fsm_bgp_open(
            &mut peer,
            ConnTag::Primary,
            open_packet(AS_TRANS, Some(4_200_000_000)),
        );
        assert_eq!(next, State::OpenConfirm);
        assert!(peer.as4, "both sides advertised the capability");
        assert!(peer.opt.is_as4());
    }

    /// RFC 6793 §4.2 consistency: a My-AS field that is neither
    /// AS_TRANS nor the capability value is a Bad Peer AS.
    #[tokio::test]
    async fn my_as_disagreeing_with_as4_cap_is_rejected() {
        let mut peer = opensent_peer(4_200_000_000);
        let _ = build_open_packet(&mut peer);

        let next = fsm_bgp_open(
            &mut peer,
            ConnTag::Primary,
            open_packet(65009, Some(4_200_000_000)),
        );
        assert_eq!(next, State::Idle);
    }

    /// AS_TRANS itself is not a real AS: a capability naming it leaves
    /// the peer's AS unknowable and must be rejected.
    #[tokio::test]
    async fn as_trans_in_capability_is_rejected() {
        let mut peer = opensent_peer(u32::from(AS_TRANS));
        let _ = build_open_packet(&mut peer);

        let next = fsm_bgp_open(
            &mut peer,
            ConnTag::Primary,
            open_packet(AS_TRANS, Some(u32::from(AS_TRANS))),
        );
        assert_eq!(next, State::Idle);
    }

    /// A 2-byte peer that advertised no 4-octet AS capability leaves
    /// the session OLD: it still establishes, with `as4` off, so every
    /// UPDATE both ways uses the 2-octet encoding.
    #[tokio::test]
    async fn peer_without_as4_cap_negotiates_old_session() {
        let mut peer = opensent_peer(65002);
        let _ = build_open_packet(&mut peer);

        let next = fsm_bgp_open(&mut peer, ConnTag::Primary, open_packet(65002, None));
        assert_eq!(next, State::OpenConfirm);
        assert!(!peer.as4, "one-sided capability is not a negotiation");
        assert!(peer.opt.as4.send && !peer.opt.as4.recv);
    }

    /// The OPEN we send for a >65535 local AS: AS_TRANS in My-AS (the
    /// old code truncated with `as u16`) and the real ASN in the
    /// capability — forced even when `capability four-octet` is off.
    #[tokio::test]
    async fn open_for_four_byte_local_as_carries_as_trans() {
        let (tx, rx) = mpsc::channel::<Message>(64);
        Box::leak(Box::new(rx));
        let mut peer = Peer::new(
            1,
            4_200_000_001,
            Ipv4Addr::new(10, 0, 0, 1),
            65002,
            "10.0.0.2".parse().unwrap(),
            None,
            tx,
            crate::context::ProtoContext::default_table_no_rib(),
        );
        peer.config.four_octet = false;

        let bytes = build_open_packet(&mut peer);
        let (_, open) = OpenPacket::parse_packet(&bytes).expect("our OPEN must parse");
        assert_eq!(open.asn, AS_TRANS, "My-AS carries the placeholder");
        let cap = open.bgp_cap.as4.expect("capability forced by 4-byte AS");
        assert_eq!(cap.asn, 4_200_000_001);
        assert!(peer.opt.as4.send);
    }
}

#[cfg(test)]
mod adv_timer_phantom_tests {
    use super::*;

    fn idle_peer() -> Peer {
        let (tx, rx) = mpsc::channel::<Message>(64);
        Box::leak(Box::new(rx));
        let mut peer = Peer::new(
            1,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            65001,
            "10.0.0.2".parse().unwrap(),
            None,
            tx,
            crate::context::ProtoContext::default_table_no_rib(),
        );
        peer.state = State::Idle;
        peer
    }

    /// Review finding #10 regression (defense layer): a VPN / EVPN
    /// advertise-debounce timer that fires while the session is down
    /// must not forge the peer into `Established`. The old handlers
    /// returned `State::Established` unconditionally, so a timer armed
    /// before a bounce promoted the Idle peer — membership enroll,
    /// route-sync into a null `packet_tx`, update-group attach — with
    /// no session behind it.
    #[tokio::test]
    async fn adv_timer_on_idle_peer_does_not_forge_established() {
        let mut peer = idle_peer();
        assert_eq!(fsm_adv_timer_vpnv4_expires(&mut peer), State::Idle);
        assert_eq!(fsm_adv_timer_vpnv6_expires(&mut peer), State::Idle);
        assert_eq!(fsm_adv_timer_evpn_expires(&mut peer), State::Idle);

        // And an Established peer keeps behaving exactly as before.
        peer.state = State::Established;
        assert_eq!(fsm_adv_timer_vpnv4_expires(&mut peer), State::Established);
        assert_eq!(fsm_adv_timer_vpnv6_expires(&mut peer), State::Established);
        assert_eq!(fsm_adv_timer_evpn_expires(&mut peer), State::Established);
    }

    /// The same forgery through the full FSM dispatch: the events carry
    /// no state gate and `fsm()` applies the returned state blindly, so
    /// this is the exact path the stale timer took.
    #[tokio::test]
    async fn adv_timer_event_through_fsm_keeps_idle_peer_idle() {
        let (tx, rx) = mpsc::channel::<Message>(64);
        Box::leak(Box::new(rx));
        let mut peers = PeerMap::new();
        peers.insert("10.0.0.2".parse().unwrap(), idle_peer());
        let ident = peers.get(&"10.0.0.2".parse().unwrap()).unwrap().ident;

        let router_id = Ipv4Addr::new(10, 0, 0, 1);
        let ctx = crate::context::ProtoContext::default_table_no_rib();
        let mut local_rib = LocalRib::default();
        let mut shard = crate::bgp::shard::BgpShard::default();
        let mut attr_store = BgpAttrStore::default();
        let mut update_groups = crate::bgp::update_group::empty_map();
        let interface_addrs = crate::bgp::interface_addrs::InterfaceAddrs::default();
        let mut top = BgpTop {
            router_id: &router_id,
            srv6_ipv6_export: None,
            local_rib: &mut local_rib,
            shard: &mut shard,
            tx: &tx,
            rib_client: &ctx.rib,
            attr_store: &mut attr_store,
            update_groups: &mut update_groups,
            interface_addrs: &interface_addrs,
            vrf_export: None,
            color_policy: None,
            flex_algo_routes: None,
            flex_algo_srv6_routes: None,
            vrf_import: None,
            nexthop_cache: None,
            vrf_transport_v4: None,
            vrf_transport_v6: None,
            central_label_alloc: None,
            as_sets_withdraw: false,
        };

        fsm(
            &mut top,
            &mut peers,
            ident,
            Event::AdvTimerVpnv4Expires,
            None,
        );
        let peer = peers.get_by_idx(ident).unwrap();
        assert_eq!(
            peer.state,
            State::Idle,
            "a stale advertise timer must not promote an Idle peer"
        );
    }

    /// Root-cause layer: peer teardown must cancel the VPN advertise
    /// debounce timers (and drop the reverse maps) exactly like the
    /// EVPN teardown always did — an armed timer outliving the session
    /// is what delivered the forged event.
    #[tokio::test]
    async fn route_clean_cancels_vpn_advertise_timers() {
        let (tx, rx) = mpsc::channel::<Message>(64);
        Box::leak(Box::new(rx));
        let mut peers = PeerMap::new();
        let mut peer = idle_peer();
        peer.cache_vpnv4_timer = Some(timer::start_adv_timer_vpnv4(&peer));
        peer.cache_vpnv6_timer = Some(timer::start_adv_timer_vpnv6(&peer));
        peers.insert("10.0.0.2".parse().unwrap(), peer);
        let ident = peers.get(&"10.0.0.2".parse().unwrap()).unwrap().ident;

        let router_id = Ipv4Addr::new(10, 0, 0, 1);
        let ctx = crate::context::ProtoContext::default_table_no_rib();
        let mut local_rib = LocalRib::default();
        let mut shard = crate::bgp::shard::BgpShard::default();
        let mut attr_store = BgpAttrStore::default();
        let mut update_groups = crate::bgp::update_group::empty_map();
        let interface_addrs = crate::bgp::interface_addrs::InterfaceAddrs::default();
        let mut top = BgpTop {
            router_id: &router_id,
            srv6_ipv6_export: None,
            local_rib: &mut local_rib,
            shard: &mut shard,
            tx: &tx,
            rib_client: &ctx.rib,
            attr_store: &mut attr_store,
            update_groups: &mut update_groups,
            interface_addrs: &interface_addrs,
            vrf_export: None,
            color_policy: None,
            flex_algo_routes: None,
            flex_algo_srv6_routes: None,
            vrf_import: None,
            nexthop_cache: None,
            vrf_transport_v4: None,
            vrf_transport_v6: None,
            central_label_alloc: None,
            as_sets_withdraw: false,
        };

        route_clean(ident, &mut top, &mut peers, None);

        let peer = peers.get_by_idx(ident).unwrap();
        assert!(
            peer.cache_vpnv4_timer.is_none(),
            "route_clean must cancel the VPNv4 advertise timer"
        );
        assert!(
            peer.cache_vpnv6_timer.is_none(),
            "route_clean must cancel the VPNv6 advertise timer"
        );
    }

    // ── adv-interval 0: immediate flush, no timer ──

    /// `idle_peer()` leaks its receiver since the tests above only
    /// care about `peer.state`; the tests below need to inspect what
    /// actually lands on the channel, so build the peer inline keeping
    /// `rx`.
    fn peer_with_channel() -> (Peer, mpsc::Receiver<Message>) {
        let (tx, rx) = mpsc::channel::<Message>(64);
        let mut peer = Peer::new(
            1,
            65001,
            Ipv4Addr::new(10, 0, 0, 1),
            65001,
            "10.0.0.2".parse().unwrap(),
            None,
            tx,
            crate::context::ProtoContext::default_table_no_rib(),
        );
        peer.state = State::Idle;
        (peer, rx)
    }

    /// adv-interval 0 mirrors FRR's `bgp_adjust_routeadv`
    /// `v_routeadv == 0` case: arm a *next-tick* (~1 ms) debounce timer
    /// rather than the 1 s-clamped `Timer::once(0, …)`.
    /// `duration_sec() == 0` is the regression guard (the old clamp
    /// gave a 1 s timer); the flush event must also land on the channel
    /// well before the old 1 s floor.
    #[tokio::test]
    async fn send_vpnv4_zero_adv_interval_flushes_under_one_second_floor() {
        let (mut peer, mut rx) = peer_with_channel();
        peer.adv_interval = timer::AdvInterval { ibgp: 0, ebgp: 0 };
        let nlri = Vpnv4Nlri {
            label: Label::default(),
            rd: RouteDistinguisher::default(),
            nlri: Ipv4Nlri {
                id: 0,
                prefix: "10.0.0.0/24".parse().unwrap(),
            },
        };

        peer.send_vpnv4(nlri, Arc::new(BgpAttr::new()), true);

        let timer = peer
            .cache_vpnv4_timer
            .as_ref()
            .expect("adv-interval 0 must still arm a debounce timer");
        assert_eq!(
            timer.duration_sec(),
            0,
            "adv-interval 0 must arm a sub-second timer, not the 1 s-clamped one"
        );
        let msg = tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv())
            .await
            .expect("flush event must fire well under the old 1 s floor")
            .expect("channel open");
        match msg {
            Message::Event(ident, Event::AdvTimerVpnv4Expires) => assert_eq!(ident, peer.ident),
            other => panic!("expected AdvTimerVpnv4Expires, got {other:?}"),
        }
    }

    /// Non-zero adv-interval (the default) must keep debouncing via a
    /// multi-second timer exactly as before — no flush event before it
    /// fires.
    #[tokio::test]
    async fn send_vpnv4_nonzero_adv_interval_still_arms_timer() {
        let (mut peer, mut rx) = peer_with_channel();
        assert_eq!(peer.adv_interval, timer::AdvInterval::default());
        let nlri = Vpnv4Nlri {
            label: Label::default(),
            rd: RouteDistinguisher::default(),
            nlri: Ipv4Nlri {
                id: 0,
                prefix: "10.0.0.0/24".parse().unwrap(),
            },
        };

        peer.send_vpnv4(nlri, Arc::new(BgpAttr::new()), true);

        let timer = peer
            .cache_vpnv4_timer
            .as_ref()
            .expect("non-zero interval must debounce via a timer");
        assert!(
            timer.duration_sec() >= 1,
            "non-zero interval must arm a multi-second timer, not the next-tick one"
        );
        assert!(
            rx.try_recv().is_err(),
            "flush must not fire before the debounce timer elapses"
        );
    }

    /// EVPN twin of the VPNv4 zero-interval test above, using a
    /// distinct `EvpnRoute` shape to catch a copy-paste mistake in the
    /// mirrored wiring (VPNv6 is identical in shape to VPNv4, so it
    /// isn't repeated here).
    #[tokio::test]
    async fn send_evpn_zero_adv_interval_flushes_under_one_second_floor() {
        let (mut peer, mut rx) = peer_with_channel();
        peer.adv_interval = timer::AdvInterval { ibgp: 0, ebgp: 0 };
        let route = EvpnRoute::EthernetAd(EvpnEthernetAd {
            id: 0,
            rd: RouteDistinguisher::default(),
            esi: [0; 10],
            ether_tag: 0,
            label: 0,
        });

        peer.send_evpn(route, Arc::new(BgpAttr::new()), true);

        let timer = peer
            .cache_evpn_timer
            .as_ref()
            .expect("adv-interval 0 must still arm a debounce timer");
        assert_eq!(timer.duration_sec(), 0);
        let msg = tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv())
            .await
            .expect("flush event must fire well under the old 1 s floor")
            .expect("channel open");
        match msg {
            Message::Event(ident, Event::AdvTimerEvpnExpires) => assert_eq!(ident, peer.ident),
            other => panic!("expected AdvTimerEvpnExpires, got {other:?}"),
        }
    }
}

#[cfg(test)]
mod gr_restart_time_tests {
    use super::*;
    use bgp_packet::{Afi, AfiSafi, Safi};

    fn gr_peer() -> Peer {
        let (tx, rx) = mpsc::channel::<Message>(8);
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
        // A router-id so the OPEN builds without the unspecified warning.
        peer.router_id = Ipv4Addr::new(10, 0, 0, 1);
        peer
    }

    /// Review finding #15: a GR-enabled family must advertise a usable
    /// Restart Time, not the bare `1` the enable marker used to store —
    /// which made a helper flush retained routes after ~1 s.
    #[tokio::test]
    async fn gr_open_advertises_default_restart_time() {
        let mut peer = gr_peer();
        peer.config.sub.insert(
            AfiSafi::new(Afi::Ip, Safi::Unicast),
            PeerSubConfig {
                graceful_restart: Some(GR_RESTART_TIME_DEFAULT),
                ..Default::default()
            },
        );

        let bytes = build_open_packet(&mut peer);
        let (_, open) = OpenPacket::parse_packet(&bytes).expect("OPEN parses");
        let restart = open.bgp_cap.restart.expect("GR capability advertised");
        assert_eq!(
            restart.flag_time.restart_time(),
            GR_RESTART_TIME_DEFAULT as u16,
            "Restart Time must be the sane default, not 1 second"
        );
        assert!(
            restart.flag_time.restart_time() >= 3,
            "a sub-hold-time Restart Time defeats graceful restart"
        );
    }

    /// `graceful-restart enabled false` must NOT enable GR (the old
    /// callback keyed on op.is_set() and ignored the boolean).
    #[test]
    fn gr_enabled_false_does_not_advertise() {
        let mut peer = gr_peer();
        // No GR family configured → no restart capability in the OPEN.
        let bytes = build_open_packet(&mut peer);
        let (_, open) = OpenPacket::parse_packet(&bytes).expect("OPEN parses");
        assert!(
            open.bgp_cap.restart.is_none(),
            "GR must be off when no family enabled it"
        );
    }
}

#[cfg(test)]
mod dynamic_accept_tests {
    use super::*;

    /// Peer shaped exactly like `try_dynamic_accept` materializes it:
    /// Dynamic origin, forced passive, wired to a parked event channel.
    fn dynamic_peer(addr: IpAddr) -> Peer {
        let (tx, rx) = mpsc::channel::<Message>(64);
        Box::leak(Box::new(rx));
        let mut peer = Peer::new(
            0,
            65000,
            Ipv4Addr::new(10, 99, 0, 10),
            65001,
            addr,
            None,
            tx,
            crate::context::ProtoContext::default_table_no_rib(),
        );
        peer.origin = PeerOrigin::Dynamic {
            range_prefix: "127.0.0.0/8".parse().unwrap(),
        };
        peer.config.transport.passive = true;
        peer
    }

    /// A loopback TCP pair standing in for the accepted inbound socket.
    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (server, client)
    }

    /// The materialization ritual must start the FSM: `start()` on a
    /// passive peer flips Idle→Active via `update_timers`. Without it
    /// (the original bug) a dynamic peer stayed Idle forever and every
    /// inbound connection — including the one that materialized it —
    /// was dropped.
    #[tokio::test]
    async fn materialized_dynamic_peer_start_leaves_idle() {
        let mut peer = dynamic_peer("198.18.1.7".parse().unwrap());
        assert_eq!(peer.state, State::Idle);

        peer.start();

        assert!(peer.active);
        assert_eq!(
            peer.state,
            State::Active,
            "a started passive peer must listen in Active, not sit in Idle"
        );
        assert!(peer.timer.idle_hold_timer.is_none());
        assert!(peer.timer.connect_retry.is_none());
    }

    /// With the peer started (Active), the re-run of
    /// `handle_peer_connection` must promote the very stream that
    /// materialized the peer into a session (OpenSent), not return it
    /// to the caller for dropping.
    #[tokio::test]
    async fn active_dynamic_peer_promotes_inbound_stream() {
        let addr: IpAddr = "127.0.0.1".parse().unwrap();
        let mut peer = dynamic_peer(addr);
        peer.start();
        let mut peers = PeerMap::new();
        peers.insert(addr, peer);

        let (server, _client) = tcp_pair().await;
        let remaining = handle_peer_connection(&mut peers, addr, None, server);

        assert!(remaining.is_none(), "the stream must be consumed");
        assert_eq!(peers.get(&addr).unwrap().state, State::OpenSent);
    }

    /// The Idle branch of `handle_peer_connection` consumes and drops
    /// the stream — which is why an unstarted dynamic peer could never
    /// establish: the fix is to not be in Idle, not to change this
    /// RFC 4271 behavior.
    #[tokio::test]
    async fn idle_dynamic_peer_drops_inbound_stream() {
        let addr: IpAddr = "127.0.0.1".parse().unwrap();
        let mut peers = PeerMap::new();
        peers.insert(addr, dynamic_peer(addr));

        let (server, _client) = tcp_pair().await;
        let remaining = handle_peer_connection(&mut peers, addr, None, server);

        assert!(remaining.is_none());
        assert_eq!(peers.get(&addr).unwrap().state, State::Idle);
    }
}
