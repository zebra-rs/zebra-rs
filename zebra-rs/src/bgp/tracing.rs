/// BGP-specific tracing macros that automatically include proto="bgp" field
///
/// This module provides convenience macros for BGP protocol logging that automatically
/// include the proto="bgp" field for better log categorization and filtering.
///
/// Log an info-level message with proto="bgp" field
#[macro_export]
macro_rules! bgp_info {
    ($($arg:tt)*) => {
        tracing::info!(proto = "bgp", $($arg)*)
    };
}

/// Log a warning-level message with proto="bgp" field
#[macro_export]
macro_rules! bgp_warn {
    ($($arg:tt)*) => {
        tracing::warn!(proto = "bgp", $($arg)*)
    };
}

/// Log an error-level message with proto="bgp" field
#[macro_export]
macro_rules! bgp_error {
    ($($arg:tt)*) => {
        tracing::error!(proto = "bgp", $($arg)*)
    };
}

/// Log a debug-level message with proto="bgp" field
#[macro_export]
macro_rules! bgp_debug {
    ($($arg:tt)*) => {
        tracing::debug!(proto = "bgp", $($arg)*)
    };
}

/// Log a trace-level message with proto="bgp" field
#[macro_export]
macro_rules! bgp_trace {
    ($($arg:tt)*) => {
        tracing::trace!(proto = "bgp", $($arg)*)
    };
}

/// Conditional FSM-transition trace. Fires when this peer's effective
/// (instance ∪ per-neighbor) config enables `tracing fsm`.
#[macro_export]
macro_rules! bgp_fsm_trace {
    ($peer:expr, $($arg:tt)*) => {
        if $peer.trace_fsm() {
            tracing::info!(
                proto = "bgp",
                category = "fsm",
                peer = %$peer.address,
                $($arg)*
            );
        }
    };
}

/// Conditional BGP-message trace. `$kind` is a
/// [`PacketKind`](crate::bgp::tracing::PacketKind), `$dir` the actual
/// [`Direction`](crate::bgp::tracing::Direction) of the message. Fires
/// when this peer's effective config traces that type in that
/// direction; the `detail` field records whether full decoding was
/// requested.
#[macro_export]
macro_rules! bgp_packet_trace {
    ($peer:expr, $kind:expr, $dir:expr, $($arg:tt)*) => {{
        let __kind = $kind;
        let __dir = $dir;
        if $peer.trace_packet(__kind, __dir) {
            tracing::info!(
                proto = "bgp",
                category = "packet",
                peer = %$peer.address,
                packet = __kind.as_str(),
                direction = __dir.as_str(),
                detail = $peer.trace_packet_detail(__kind, __dir),
                $($arg)*
            );
        }
    }};
}

/// Conditional Adj-RIB-In trace. Fires when this peer's effective
/// config enables `tracing adj-in`.
#[macro_export]
macro_rules! bgp_adj_in_trace {
    ($peer:expr, $($arg:tt)*) => {
        if $peer.trace_adj_in() {
            tracing::info!(
                proto = "bgp",
                category = "adj-in",
                peer = %$peer.address,
                $($arg)*
            );
        }
    };
}

/// Conditional Adj-RIB-Out trace. Fires when this peer's effective
/// config enables `tracing adj-out`.
#[macro_export]
macro_rules! bgp_adj_out_trace {
    ($peer:expr, $($arg:tt)*) => {
        if $peer.trace_adj_out() {
            tracing::info!(
                proto = "bgp",
                category = "adj-out",
                peer = %$peer.address,
                $($arg)*
            );
        }
    };
}

/// Conditional MPLS-label trace. Instance-scoped (label allocation is
/// not tied to a peer), so it takes a `&BgpTracing` directly.
#[macro_export]
macro_rules! bgp_label_trace {
    ($tracing:expr, $($arg:tt)*) => {
        if $tracing.should_trace_label() {
            tracing::info!(proto = "bgp", category = "label", $($arg)*);
        }
    };
}

/// Conditional L3VPN import/export trace. Instance-scoped — VPN export
/// runs off the instance Loc-RIB and fans out to every PE/CE peer, so
/// it takes a `&BgpTracing` directly rather than a single peer.
#[macro_export]
macro_rules! bgp_vpn_trace {
    ($tracing:expr, $($arg:tt)*) => {
        if $tracing.should_trace_vpn() {
            tracing::info!(proto = "bgp", category = "vpn", $($arg)*);
        }
    };
}

/// Conditional SRv6 locator / SID trace. Instance-scoped (SID
/// resolution is keyed by locator, not a peer).
#[macro_export]
macro_rules! bgp_srv6_trace {
    ($tracing:expr, $($arg:tt)*) => {
        if $tracing.should_trace_srv6() {
            tracing::info!(proto = "bgp", category = "srv6", $($arg)*);
        }
    };
}

/// Conditional per-VRF task lifecycle trace (spawn / respawn / despawn /
/// shutdown / inbound-connection routing). Instance-scoped.
#[macro_export]
macro_rules! bgp_vrf_trace {
    ($tracing:expr, $($arg:tt)*) => {
        if $tracing.should_trace_vrf() {
            tracing::info!(proto = "bgp", category = "vrf", $($arg)*);
        }
    };
}

/// Conditional BFD-interaction trace (session state changes,
/// client-readiness). Instance-scoped — the BFD client is a single
/// per-instance channel, not a per-peer resource.
#[macro_export]
macro_rules! bgp_bfd_trace {
    ($tracing:expr, $($arg:tt)*) => {
        if $tracing.should_trace_bfd() {
            tracing::info!(proto = "bgp", category = "bfd", $($arg)*);
        }
    };
}

// ============================================================
// BgpTracing — runtime tracing configuration
// ============================================================
//
// Backs the `router bgp tracing { ... }` (instance-wide) and
// `router bgp neighbor <addr> tracing { ... }` (per-neighbor) config
// trees defined in zebra-bgp-tracing.yang. The config dispatch below
// writes it; the gated `bgp_*_trace!` macros above read it through the
// `should_trace_*` accessors. Per-neighbor config is additive to the
// instance config — see `Peer::trace_*`, which OR the peer's snapshot
// of the instance config with its own per-neighbor config.

use super::Bgp;
use crate::config::{Args, ConfigOp};

/// Direction filter for per-message-type tracing. The YANG `direction`
/// leaf omitted means both, so `Both` is the default.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Direction {
    #[default]
    Both,
    Send,
    Recv,
}

impl Direction {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Direction::Both => "both",
            Direction::Send => "send",
            Direction::Recv => "receive",
        }
    }

    /// Whether a message flowing in `actual` direction passes this
    /// filter. `Both` matches either direction.
    fn matches(self, actual: Direction) -> bool {
        self == Direction::Both || self == actual
    }
}

/// BGP message type, used to select a per-type toggle at a trace site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketKind {
    Open,
    Update,
    Keepalive,
    Notification,
    RouteRefresh,
}

impl PacketKind {
    pub const fn as_str(&self) -> &'static str {
        match self {
            PacketKind::Open => "open",
            PacketKind::Update => "update",
            PacketKind::Keepalive => "keepalive",
            PacketKind::Notification => "notification",
            PacketKind::RouteRefresh => "route-refresh",
        }
    }
}

/// Per-message-type tracing toggle. `enabled` is the presence of the
/// `packet <type>` container; `detail` and `direction` are its optional
/// refinements.
#[derive(Debug, Clone, Copy, Default)]
pub struct PacketConfig {
    pub enabled: bool,
    pub detail: bool,
    pub direction: Direction,
}

/// Per-message-type tracing block. `all` is a catch-all applied on top
/// of the individual per-type toggles.
#[derive(Debug, Clone, Default)]
pub struct PacketTracing {
    pub all: PacketConfig,
    pub open: PacketConfig,
    pub update: PacketConfig,
    pub keepalive: PacketConfig,
    pub notification: PacketConfig,
    pub route_refresh: PacketConfig,
}

impl PacketTracing {
    /// Resolve a `&mut PacketConfig` by its YANG node name. Returns
    /// `None` for an unknown name; the YANG enumeration constrains the
    /// set, so a miss only happens on a malformed path.
    fn get_mut(&mut self, name: &str) -> Option<&mut PacketConfig> {
        Some(match name {
            "all" => &mut self.all,
            "open" => &mut self.open,
            "update" => &mut self.update,
            "keepalive" => &mut self.keepalive,
            "notification" => &mut self.notification,
            "route-refresh" => &mut self.route_refresh,
            _ => return None,
        })
    }
}

/// Conditional BGP tracing configuration. One instance lives on `Bgp`
/// (instance-wide) and one on each `Peer` (per-neighbor override),
/// sharing this shape because both scopes `uses` the same YANG
/// grouping.
#[derive(Debug, Clone, Default)]
pub struct BgpTracing {
    pub all: bool,
    pub fsm: bool,
    pub packet: PacketTracing,
    pub label: bool,
    pub adj_in: bool,
    pub adj_out: bool,
    pub vpn: bool,
    pub srv6: bool,
    pub vrf: bool,
    pub bfd: bool,
    /// Instance-lifetime knobs frozen at spawn: the RIB shard count, the
    /// per-peer egress-task model, and update-group egress task
    /// spawn/exit. Mirrored into [`TRACE_SHARDING`] because those sites
    /// run where no `BgpTracing` is in reach — see [`trace_sharding`].
    pub sharding: bool,
}

impl BgpTracing {
    fn packet_cfg(&self, kind: PacketKind) -> &PacketConfig {
        match kind {
            PacketKind::Open => &self.packet.open,
            PacketKind::Update => &self.packet.update,
            PacketKind::Keepalive => &self.packet.keepalive,
            PacketKind::Notification => &self.packet.notification,
            PacketKind::RouteRefresh => &self.packet.route_refresh,
        }
    }

    /// Whether a `kind` message in `dir` should be traced. The `all`
    /// master switch and the `packet all` catch-all both apply on top
    /// of the per-type toggle.
    pub fn should_trace_packet(&self, kind: PacketKind, dir: Direction) -> bool {
        if self.all {
            return true;
        }
        let cfg = self.packet_cfg(kind);
        (self.packet.all.enabled && self.packet.all.direction.matches(dir))
            || (cfg.enabled && cfg.direction.matches(dir))
    }

    /// Whether full-decode detail was requested for a `kind` message in
    /// `dir`. Independent of the `all` master switch — that turns
    /// everything on at summary level only.
    pub fn packet_detail(&self, kind: PacketKind, dir: Direction) -> bool {
        let cfg = self.packet_cfg(kind);
        (self.packet.all.enabled
            && self.packet.all.direction.matches(dir)
            && self.packet.all.detail)
            || (cfg.enabled && cfg.direction.matches(dir) && cfg.detail)
    }

    pub fn should_trace_fsm(&self) -> bool {
        self.all || self.fsm
    }

    pub fn should_trace_label(&self) -> bool {
        self.all || self.label
    }

    pub fn should_trace_adj_in(&self) -> bool {
        self.all || self.adj_in
    }

    pub fn should_trace_adj_out(&self) -> bool {
        self.all || self.adj_out
    }

    pub fn should_trace_vpn(&self) -> bool {
        self.all || self.vpn
    }

    pub fn should_trace_srv6(&self) -> bool {
        self.all || self.srv6
    }

    pub fn should_trace_vrf(&self) -> bool {
        self.all || self.vrf
    }

    pub fn should_trace_bfd(&self) -> bool {
        self.all || self.bfd
    }

    pub fn should_trace_sharding(&self) -> bool {
        self.all || self.sharding
    }
}

/// Process-global mirror of [`BgpTracing::should_trace_sharding`].
///
/// The sharding trace sites cannot reach a `BgpTracing`: `init_shard_count`
/// and `init_peer_task` run inside `spawn_bgp` *before* `Bgp::new` builds
/// the instance, and `GroupEgressTask::spawn` is a plain constructor with
/// neither a `Bgp` nor a `Peer` in scope. A process-global atomic gives
/// every one of them the same gate — the pattern `bfd::trace` already uses
/// for its socket tasks.
///
/// Seeded by `spawn_bgp` from a candidate-config scan *before*
/// `init_shard_count` runs (so the freeze-time lines see it), then kept in
/// step with the live config by [`config_tracing_dispatch`] so a runtime
/// `set router bgp tracing sharding` reaches update-group tasks spawned
/// later.
static TRACE_SHARDING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Set the process-global sharding gate. See [`TRACE_SHARDING`].
pub fn set_trace_sharding(on: bool) {
    TRACE_SHARDING.store(on, std::sync::atomic::Ordering::Relaxed);
}

/// Whether the spawn-time sharding / egress-model traces are enabled.
pub fn trace_sharding() -> bool {
    TRACE_SHARDING.load(std::sync::atomic::Ordering::Relaxed)
}

fn parse_direction(args: &mut Args) -> Direction {
    match args.string().as_deref() {
        Some("send") => Direction::Send,
        Some("receive") | Some("recv") => Direction::Recv,
        // Absent or any other token (incl. an explicit "both") means
        // trace both directions.
        _ => Direction::Both,
    }
}

/// `tracing packet <type>` — bare presence enables the type; delete
/// clears the whole toggle (including any detail / direction).
fn packet_set_enable(pc: &mut PacketConfig, op: ConfigOp) {
    if op.is_set() {
        pc.enabled = true;
    } else {
        *pc = PacketConfig::default();
    }
}

/// `tracing packet <type> detail` — enabling detail implies the type is
/// traced; delete leaves the type enabled at summary level.
fn packet_set_detail(pc: &mut PacketConfig, op: ConfigOp) {
    if op.is_set() {
        pc.enabled = true;
        pc.detail = true;
    } else {
        pc.detail = false;
    }
}

/// `tracing packet <type> direction {send|receive}` — restrict the
/// direction (and enable the type); delete reverts to both directions.
fn packet_set_direction(pc: &mut PacketConfig, args: &mut Args, op: ConfigOp) {
    if op.is_set() {
        pc.enabled = true;
        pc.direction = parse_direction(args);
    } else {
        pc.direction = Direction::Both;
    }
}

/// Apply one committed `…/tracing/<rest>` config line to a single
/// `BgpTracing` target. `rest` is the path tail after the `tracing`
/// node (e.g. `/all`, `/fsm`, `/packet/open`, `/packet/open/detail`,
/// `/packet/open/direction`); for the direction case `args` still
/// holds the trailing send/receive value.
fn apply_tracing(t: &mut BgpTracing, rest: &str, args: &mut Args, op: ConfigOp) -> Option<()> {
    match rest {
        "/all" => t.all = op.is_set(),
        "/fsm" => t.fsm = op.is_set(),
        "/label" => t.label = op.is_set(),
        "/adj-in" => t.adj_in = op.is_set(),
        "/adj-out" => t.adj_out = op.is_set(),
        "/vpn" => t.vpn = op.is_set(),
        "/srv6" => t.srv6 = op.is_set(),
        "/vrf" => t.vrf = op.is_set(),
        "/bfd" => t.bfd = op.is_set(),
        "/sharding" => t.sharding = op.is_set(),
        other => {
            let pkt = other.strip_prefix("/packet/")?;
            let (typ, sub) = match pkt.split_once('/') {
                Some((typ, sub)) => (typ, Some(sub)),
                None => (pkt, None),
            };
            let pc = t.packet.get_mut(typ)?;
            match sub {
                None => packet_set_enable(pc, op),
                Some("detail") => packet_set_detail(pc, op),
                Some("direction") => packet_set_direction(pc, args, op),
                Some(_) => return None,
            }
        }
    }
    Some(())
}

/// Dispatch a committed `…/tracing/…` Set/Delete path to the right
/// `BgpTracing` (the instance, or a peer) and apply it.
///
/// Called from [`Bgp::process_cm_msg`] for paths the regular callback
/// table does not claim. Because the per-message-type names are YANG
/// containers (not list keys) they live in the *path*, not in `args`,
/// so a single parser handles the whole subtree instead of registering
/// one callback per node. Returns `None` (ignored) for non-tracing
/// paths and for unresolved peers / malformed tails.
pub fn config_tracing_dispatch(
    bgp: &mut Bgp,
    path: &str,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    if let Some(rest) = path.strip_prefix("/router/bgp/neighbor/tracing") {
        // Neighbor scope: the address is the leading arg (the stripped
        // list key), then the same tracing tail as the instance.
        let addr = args.addr()?;
        let peer = bgp.peers.get_mut(&addr)?;
        apply_tracing(&mut peer.tracing, rest, &mut args, op)
    } else if let Some(rest) = path.strip_prefix("/router/bgp/tracing") {
        let result = apply_tracing(&mut bgp.tracing, rest, &mut args, op);
        // Re-snapshot the instance config onto every peer so the
        // peer-context trace sites (which only see a `Peer`) can OR it
        // with the per-neighbor config. Same propagation pattern as
        // `adv_interval`.
        propagate_instance_tracing(bgp);
        result
    } else {
        None
    }
}

/// Copy the instance tracing config onto every peer's snapshot, so each
/// peer's effective (additive) config picks up an instance-level change,
/// and mirror it to every per-VRF task. Both are copies rather than
/// shared reads: the trace sites see only a `Peer` (global) or a
/// `BgpVrf` (per-VRF task, a different `!Send` runtime), never the
/// instance.
pub fn propagate_instance_tracing(bgp: &mut Bgp) {
    let snapshot = bgp.tracing.clone();
    for (_, peer) in bgp.peers.iter_mut_all() {
        peer.tracing_instance = snapshot.clone();
    }
    // Sharding is instance-scoped and read from contexts that hold no
    // `BgpTracing` at all, so it rides a process-global rather than a
    // per-peer snapshot. Only the instance config feeds it — a
    // per-neighbor `tracing sharding` would be meaningless.
    set_trace_sharding(snapshot.should_trace_sharding());
    bgp.broadcast_tracing();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Args, ConfigOp};

    fn args(items: &[&str]) -> Args {
        Args(items.iter().map(|s| s.to_string()).collect())
    }

    #[test]
    fn top_level_flags_toggle_on_set_delete() {
        let mut t = BgpTracing::default();

        apply_tracing(&mut t, "/all", &mut args(&[]), ConfigOp::Set);
        assert!(t.all);
        apply_tracing(&mut t, "/all", &mut args(&[]), ConfigOp::Delete);
        assert!(!t.all);

        apply_tracing(&mut t, "/fsm", &mut args(&[]), ConfigOp::Set);
        apply_tracing(&mut t, "/label", &mut args(&[]), ConfigOp::Set);
        apply_tracing(&mut t, "/adj-in", &mut args(&[]), ConfigOp::Set);
        apply_tracing(&mut t, "/adj-out", &mut args(&[]), ConfigOp::Set);
        assert!(t.fsm && t.label && t.adj_in && t.adj_out);

        apply_tracing(&mut t, "/vpn", &mut args(&[]), ConfigOp::Set);
        apply_tracing(&mut t, "/srv6", &mut args(&[]), ConfigOp::Set);
        apply_tracing(&mut t, "/vrf", &mut args(&[]), ConfigOp::Set);
        apply_tracing(&mut t, "/bfd", &mut args(&[]), ConfigOp::Set);
        assert!(t.vpn && t.srv6 && t.vrf && t.bfd);
        apply_tracing(&mut t, "/vpn", &mut args(&[]), ConfigOp::Delete);
        assert!(!t.vpn);

        apply_tracing(&mut t, "/sharding", &mut args(&[]), ConfigOp::Set);
        assert!(t.sharding);
        apply_tracing(&mut t, "/sharding", &mut args(&[]), ConfigOp::Delete);
        assert!(!t.sharding);
    }

    #[test]
    fn sharding_follows_all_master_switch() {
        let mut t = BgpTracing::default();
        assert!(!t.should_trace_sharding());

        // The `all` master switch implies the category, matching
        // `trace_sharding_from_config_text`'s spawn-time scan.
        apply_tracing(&mut t, "/all", &mut args(&[]), ConfigOp::Set);
        assert!(t.should_trace_sharding());

        apply_tracing(&mut t, "/all", &mut args(&[]), ConfigOp::Delete);
        assert!(!t.should_trace_sharding());
        apply_tracing(&mut t, "/sharding", &mut args(&[]), ConfigOp::Set);
        assert!(t.should_trace_sharding());
    }

    #[test]
    fn trace_sharding_global_tracks_setter() {
        // The spawn-time sites read this global, not a `BgpTracing`.
        set_trace_sharding(true);
        assert!(trace_sharding());
        set_trace_sharding(false);
        assert!(!trace_sharding());
    }

    #[test]
    fn packet_bare_enable_has_defaults() {
        let mut t = BgpTracing::default();
        apply_tracing(&mut t, "/packet/open", &mut args(&[]), ConfigOp::Set);
        assert!(t.packet.open.enabled);
        assert!(!t.packet.open.detail);
        assert_eq!(t.packet.open.direction, Direction::Both);
    }

    #[test]
    fn packet_detail_and_direction_imply_enabled() {
        let mut t = BgpTracing::default();
        apply_tracing(
            &mut t,
            "/packet/update/detail",
            &mut args(&[]),
            ConfigOp::Set,
        );
        assert!(t.packet.update.enabled);
        assert!(t.packet.update.detail);

        let mut t = BgpTracing::default();
        apply_tracing(
            &mut t,
            "/packet/notification/direction",
            &mut args(&["receive"]),
            ConfigOp::Set,
        );
        assert!(t.packet.notification.enabled);
        assert_eq!(t.packet.notification.direction, Direction::Recv);

        let mut t = BgpTracing::default();
        apply_tracing(
            &mut t,
            "/packet/keepalive/direction",
            &mut args(&["send"]),
            ConfigOp::Set,
        );
        assert_eq!(t.packet.keepalive.direction, Direction::Send);
    }

    #[test]
    fn hyphenated_type_name_resolves() {
        let mut t = BgpTracing::default();
        apply_tracing(
            &mut t,
            "/packet/route-refresh",
            &mut args(&[]),
            ConfigOp::Set,
        );
        assert!(t.packet.route_refresh.enabled);
    }

    #[test]
    fn delete_detail_keeps_type_delete_container_clears() {
        let mut t = BgpTracing::default();
        apply_tracing(&mut t, "/packet/open/detail", &mut args(&[]), ConfigOp::Set);
        apply_tracing(
            &mut t,
            "/packet/open/direction",
            &mut args(&["send"]),
            ConfigOp::Set,
        );
        assert!(t.packet.open.enabled && t.packet.open.detail);
        assert_eq!(t.packet.open.direction, Direction::Send);

        // Deleting `detail` leaves the type enabled at summary level.
        apply_tracing(
            &mut t,
            "/packet/open/detail",
            &mut args(&[]),
            ConfigOp::Delete,
        );
        assert!(t.packet.open.enabled);
        assert!(!t.packet.open.detail);

        // Deleting the container clears the whole toggle.
        apply_tracing(&mut t, "/packet/open", &mut args(&[]), ConfigOp::Delete);
        assert!(!t.packet.open.enabled);
        assert_eq!(t.packet.open.direction, Direction::Both);
    }

    #[test]
    fn unknown_tail_or_type_is_ignored() {
        let mut t = BgpTracing::default();
        assert_eq!(
            apply_tracing(&mut t, "/bogus", &mut args(&[]), ConfigOp::Set),
            None
        );
        assert_eq!(
            apply_tracing(&mut t, "/packet/bogus", &mut args(&[]), ConfigOp::Set),
            None
        );
        assert_eq!(
            apply_tracing(&mut t, "/packet/open/bogus", &mut args(&[]), ConfigOp::Set),
            None
        );
    }

    // ---- read side: should_trace_* -------------------------------

    #[test]
    fn should_trace_packet_respects_direction() {
        let mut t = BgpTracing::default();
        apply_tracing(
            &mut t,
            "/packet/open/direction",
            &mut args(&["send"]),
            ConfigOp::Set,
        );
        assert!(t.should_trace_packet(PacketKind::Open, Direction::Send));
        // A recv OPEN is filtered out by the send-only direction.
        assert!(!t.should_trace_packet(PacketKind::Open, Direction::Recv));
        // Other types are unaffected.
        assert!(!t.should_trace_packet(PacketKind::Update, Direction::Send));
    }

    #[test]
    fn should_trace_packet_both_matches_either_direction() {
        let mut t = BgpTracing::default();
        apply_tracing(&mut t, "/packet/update", &mut args(&[]), ConfigOp::Set);
        assert!(t.should_trace_packet(PacketKind::Update, Direction::Send));
        assert!(t.should_trace_packet(PacketKind::Update, Direction::Recv));
    }

    #[test]
    fn all_master_switch_traces_every_packet() {
        let mut t = BgpTracing::default();
        apply_tracing(&mut t, "/all", &mut args(&[]), ConfigOp::Set);
        assert!(t.should_trace_packet(PacketKind::Notification, Direction::Recv));
        assert!(t.should_trace_fsm());
        assert!(t.should_trace_label());
        assert!(t.should_trace_adj_in());
        assert!(t.should_trace_adj_out());
        assert!(t.should_trace_vpn());
        assert!(t.should_trace_srv6());
        assert!(t.should_trace_vrf());
        assert!(t.should_trace_bfd());
        // `all` is summary-level only — it does not imply detail.
        assert!(!t.packet_detail(PacketKind::Notification, Direction::Recv));
    }

    #[test]
    fn packet_all_catchall_applies_per_type() {
        let mut t = BgpTracing::default();
        apply_tracing(&mut t, "/packet/all", &mut args(&[]), ConfigOp::Set);
        assert!(t.should_trace_packet(PacketKind::Keepalive, Direction::Send));
        assert!(t.should_trace_packet(PacketKind::RouteRefresh, Direction::Recv));
    }

    #[test]
    fn detail_requires_matching_direction() {
        let mut t = BgpTracing::default();
        apply_tracing(
            &mut t,
            "/packet/update/direction",
            &mut args(&["receive"]),
            ConfigOp::Set,
        );
        apply_tracing(
            &mut t,
            "/packet/update/detail",
            &mut args(&[]),
            ConfigOp::Set,
        );
        assert!(t.packet_detail(PacketKind::Update, Direction::Recv));
        // Detail only applies in the configured (recv) direction.
        assert!(!t.packet_detail(PacketKind::Update, Direction::Send));
    }

    // ---- additive (instance ∪ per-neighbor) semantics ------------
    // Mirrors `Peer::trace_*`, which OR the instance snapshot with the
    // per-neighbor config.

    fn additive(a: &BgpTracing, b: &BgpTracing, kind: PacketKind, dir: Direction) -> bool {
        a.should_trace_packet(kind, dir) || b.should_trace_packet(kind, dir)
    }

    #[test]
    fn neighbor_adds_to_instance() {
        let mut inst = BgpTracing::default();
        apply_tracing(&mut inst, "/fsm", &mut args(&[]), ConfigOp::Set);
        let mut peer = BgpTracing::default();
        apply_tracing(&mut peer, "/packet/update", &mut args(&[]), ConfigOp::Set);

        // Instance-only FSM still applies via the instance side.
        assert!(inst.should_trace_fsm() || peer.should_trace_fsm());
        // Per-neighbor UPDATE applies via the peer side.
        assert!(additive(&inst, &peer, PacketKind::Update, Direction::Recv));
        // Neither side traces OPEN.
        assert!(!additive(&inst, &peer, PacketKind::Open, Direction::Recv));
    }

    #[test]
    fn empty_neighbor_falls_back_to_instance() {
        let mut inst = BgpTracing::default();
        apply_tracing(&mut inst, "/packet/open", &mut args(&[]), ConfigOp::Set);
        let peer = BgpTracing::default(); // no per-neighbor config

        // With no neighbor config, the effective decision is instance-only.
        assert!(additive(&inst, &peer, PacketKind::Open, Direction::Send));
        assert!(!additive(&inst, &peer, PacketKind::Update, Direction::Send));
    }
}
