// OSPF conditional tracing — consistent with BGP (zebra-bgp-tracing) and
// IS-IS.
//
// One `OspfTracing` lives on each `Ospf<V>` instance, shared by both
// versions by type (the `proto` field records `"ospf"` / `"ospfv3"` so
// v2 and v3 logs stay filterable apart). The `router ospf tracing { ...
// }` / `router ospfv3 tracing { ... }` config trees (defined in
// `zebra-ospf-tracing.yang`) write it through `config_tracing_dispatch`;
// the gated `ospf_*_trace!` macros below read it through the
// `should_trace_*` accessors before emitting a `proto`-tagged
// `tracing::info!` event.
//
// Categories: packet (hello/dd/ls-req/ls-update/ls-ack), fsm
// (ifsm/nfsm), and the OSPF events spf and lsdb. Each toggle is a YANG
// presence flag (`type empty`); per-message-type packet toggles carry
// optional `detail` (full decode vs one-line summary) and `direction`
// (send|receive; omit for both). This mirrors the BGP `PacketConfig`
// shape so the two protocols' tracing reads the same.

use super::Ospf;
use super::version::OspfVersion;
use crate::config::{Args, ConfigOp};

// ============================================================
// Plain proto-tagged convenience macros
// ============================================================

/// Log an info-level message with `proto="ospf"`.
#[macro_export]
macro_rules! ospf_info {
    ($($arg:tt)*) => {
        tracing::info!(proto = "ospf", $($arg)*)
    };
}

/// Log a warning-level message with `proto="ospf"`.
#[macro_export]
macro_rules! ospf_warn {
    ($($arg:tt)*) => {
        tracing::warn!(proto = "ospf", $($arg)*)
    };
}

/// Log an error-level message with `proto="ospf"`.
#[macro_export]
macro_rules! ospf_error {
    ($($arg:tt)*) => {
        tracing::error!(proto = "ospf", $($arg)*)
    };
}

/// Log a debug-level message with `proto="ospf"`.
#[macro_export]
macro_rules! ospf_debug {
    ($($arg:tt)*) => {
        tracing::debug!(proto = "ospf", $($arg)*)
    };
}

/// Log a trace-level message with `proto="ospf"`.
#[macro_export]
macro_rules! ospf_trace {
    ($($arg:tt)*) => {
        tracing::trace!(proto = "ospf", $($arg)*)
    };
}

// ============================================================
// Gated category macros
// ============================================================
//
// Each takes an `expr` that resolves to an `OspfTracing` (or
// `&OspfTracing`) — `self.tracing`, `oi.tracing`, or a threaded
// `tracing` borrow — gates on the matching `should_trace_*`, and emits
// `proto = <tracing>.proto` so v2 and v3 events are labelled apart.

/// Conditional packet trace with explicit type + direction.
#[macro_export]
macro_rules! ospf_packet_trace {
    ($tracing:expr, $packet_type:ident, $direction:ident, $($arg:tt)*) => {{
        let __t = &$tracing;
        let __ty = $crate::ospf::tracing::PacketType::$packet_type;
        let __dir = $crate::ospf::tracing::PacketDirection::$direction;
        if __t.should_trace_packet(__ty, __dir) {
            tracing::info!(
                proto = __t.proto,
                category = "packet",
                packet = __ty.as_str(),
                direction = __dir.as_str(),
                detail = __t.packet_detail(__ty, __dir),
                $($arg)*
            );
        }
    }};
}

/// Conditional FSM-transition trace. `$fsm_type` is `Ifsm` or `Nfsm`;
/// `$detail` flags a detail-level line (gated on the toggle's `detail`).
#[macro_export]
macro_rules! ospf_fsm_trace {
    ($tracing:expr, $fsm_type:ident, $detail:expr, $($arg:tt)*) => {{
        let __t = &$tracing;
        let __detail: bool = $detail;
        let __ty = $crate::ospf::tracing::FsmType::$fsm_type;
        if __t.should_trace_fsm(__ty, __detail) {
            tracing::info!(
                proto = __t.proto,
                category = "fsm",
                fsm = __ty.as_str(),
                detail = __detail,
                $($arg)*
            );
        }
    }};
}

/// Conditional OSPF-event trace. `$event_type` is `Spf` or `Lsdb`.
#[macro_export]
macro_rules! ospf_event_trace {
    ($tracing:expr, $event_type:ident, $($arg:tt)*) => {{
        let __t = &$tracing;
        let __ty = $crate::ospf::tracing::EventType::$event_type;
        if __t.should_trace_event(__ty) {
            tracing::info!(
                proto = __t.proto,
                category = "event",
                event = __ty.as_str(),
                $($arg)*
            );
        }
    }};
}

/// Inject `_OSPF_PKT_TYPE` / `_OSPF_PKT_DIR` constants for the enclosing
/// packet handler so [`ospf_pdu_trace!`] needs no repeated type/direction
/// arguments. The `#[ospf_packet_handler(Type, Dir)]` attribute macro
/// (in `crates/ospf-macros`) injects the same constants; this
/// declarative form is kept for hand-written scopes.
#[macro_export]
macro_rules! ospf_pdu_handler {
    ($packet_type:ident, $direction:ident) => {
        const _OSPF_PKT_TYPE: $crate::ospf::tracing::PacketType =
            $crate::ospf::tracing::PacketType::$packet_type;
        const _OSPF_PKT_DIR: $crate::ospf::tracing::PacketDirection =
            $crate::ospf::tracing::PacketDirection::$direction;
    };
}

/// Conditional packet trace using the handler-injected
/// `_OSPF_PKT_TYPE` / `_OSPF_PKT_DIR` constants. Use inside a function
/// annotated with `#[ospf_packet_handler(Type, Dir)]` (or after
/// `ospf_pdu_handler!`).
#[macro_export]
macro_rules! ospf_pdu_trace {
    ($tracing:expr, $($arg:tt)*) => {{
        let __t = &$tracing;
        if __t.should_trace_packet(_OSPF_PKT_TYPE, _OSPF_PKT_DIR) {
            tracing::info!(
                proto = __t.proto,
                category = "packet",
                packet = _OSPF_PKT_TYPE.as_str(),
                direction = _OSPF_PKT_DIR.as_str(),
                detail = __t.packet_detail(_OSPF_PKT_TYPE, _OSPF_PKT_DIR),
                $($arg)*
            );
        }
    }};
}

// ============================================================
// Tracing categories
// ============================================================

/// Direction filter for per-message-type tracing. The YANG `direction`
/// leaf omitted means both, so `Both` is the default.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PacketDirection {
    #[default]
    Both,
    Send,
    Recv,
}

impl PacketDirection {
    pub const fn as_str(&self) -> &'static str {
        match self {
            PacketDirection::Both => "both",
            PacketDirection::Send => "send",
            PacketDirection::Recv => "receive",
        }
    }

    /// Whether a message flowing in `actual` direction passes this
    /// filter. `Both` matches either direction.
    fn matches(self, actual: PacketDirection) -> bool {
        self == PacketDirection::Both || self == actual
    }
}

/// OSPF packet type. Variant names match the `#[ospf_packet_handler]`
/// proc-macro's accepted set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    Hello,
    DbDesc,
    LsRequest,
    LsUpdate,
    LsAck,
}

impl PacketType {
    pub const fn as_str(&self) -> &'static str {
        match self {
            PacketType::Hello => "hello",
            PacketType::DbDesc => "dd",
            PacketType::LsRequest => "ls-req",
            PacketType::LsUpdate => "ls-update",
            PacketType::LsAck => "ls-ack",
        }
    }
}

/// OSPF state machine, selected at an FSM trace site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsmType {
    Ifsm,
    Nfsm,
}

impl FsmType {
    pub const fn as_str(&self) -> &'static str {
        match self {
            FsmType::Ifsm => "ifsm",
            FsmType::Nfsm => "nfsm",
        }
    }
}

/// OSPF event category, selected at an event trace site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    Spf,
    Lsdb,
}

impl EventType {
    pub const fn as_str(&self) -> &'static str {
        match self {
            EventType::Spf => "spf",
            EventType::Lsdb => "lsdb",
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
    pub direction: PacketDirection,
}

/// Per-message-type tracing block. `all` is a catch-all applied on top
/// of the individual per-type toggles.
#[derive(Debug, Clone, Default)]
pub struct PacketTracing {
    pub all: PacketConfig,
    pub hello: PacketConfig,
    pub dd: PacketConfig,
    pub ls_req: PacketConfig,
    pub ls_update: PacketConfig,
    pub ls_ack: PacketConfig,
}

impl PacketTracing {
    /// Resolve a `&mut PacketConfig` by its YANG node name. `None` for an
    /// unknown name (only reachable on a malformed path — the YANG
    /// enumeration constrains the set).
    fn get_mut(&mut self, name: &str) -> Option<&mut PacketConfig> {
        Some(match name {
            "all" => &mut self.all,
            "hello" => &mut self.hello,
            "dd" => &mut self.dd,
            "ls-req" => &mut self.ls_req,
            "ls-update" => &mut self.ls_update,
            "ls-ack" => &mut self.ls_ack,
            _ => return None,
        })
    }
}

/// Per-FSM tracing toggle.
#[derive(Debug, Clone, Copy, Default)]
pub struct FsmConfig {
    pub enabled: bool,
    pub detail: bool,
}

/// FSM tracing block. `all` is a catch-all over both state machines.
#[derive(Debug, Clone, Default)]
pub struct FsmTracing {
    pub all: FsmConfig,
    pub ifsm: FsmConfig,
    pub nfsm: FsmConfig,
}

impl FsmTracing {
    fn get_mut(&mut self, name: &str) -> Option<&mut FsmConfig> {
        Some(match name {
            "all" => &mut self.all,
            "ifsm" => &mut self.ifsm,
            "nfsm" => &mut self.nfsm,
            _ => return None,
        })
    }
}

/// Simple presence-only event toggle (spf, lsdb).
#[derive(Debug, Clone, Copy, Default)]
pub struct EventConfig {
    pub enabled: bool,
}

/// Conditional OSPF tracing configuration. One instance lives on each
/// `Ospf<V>`; `proto` carries `V::PROTO` so the gated macros emit the
/// version-correct `proto` field.
#[derive(Debug, Clone)]
pub struct OspfTracing {
    pub proto: &'static str,
    pub all: bool,
    pub packet: PacketTracing,
    pub fsm: FsmTracing,
    pub spf: EventConfig,
    pub lsdb: EventConfig,
}

impl Default for OspfTracing {
    fn default() -> Self {
        Self {
            proto: "ospf",
            all: false,
            packet: PacketTracing::default(),
            fsm: FsmTracing::default(),
            spf: EventConfig::default(),
            lsdb: EventConfig::default(),
        }
    }
}

impl OspfTracing {
    fn packet_cfg(&self, ty: PacketType) -> &PacketConfig {
        match ty {
            PacketType::Hello => &self.packet.hello,
            PacketType::DbDesc => &self.packet.dd,
            PacketType::LsRequest => &self.packet.ls_req,
            PacketType::LsUpdate => &self.packet.ls_update,
            PacketType::LsAck => &self.packet.ls_ack,
        }
    }

    /// Whether a `ty` message in `dir` should be traced. The `all` master
    /// switch and the `packet all` catch-all both apply on top of the
    /// per-type toggle.
    pub fn should_trace_packet(&self, ty: PacketType, dir: PacketDirection) -> bool {
        if self.all {
            return true;
        }
        let cfg = self.packet_cfg(ty);
        (self.packet.all.enabled && self.packet.all.direction.matches(dir))
            || (cfg.enabled && cfg.direction.matches(dir))
    }

    /// Whether full-decode detail was requested for a `ty` message in
    /// `dir`. Independent of the `all` master switch (which is
    /// summary-level only).
    pub fn packet_detail(&self, ty: PacketType, dir: PacketDirection) -> bool {
        let cfg = self.packet_cfg(ty);
        (self.packet.all.enabled
            && self.packet.all.direction.matches(dir)
            && self.packet.all.detail)
            || (cfg.enabled && cfg.direction.matches(dir) && cfg.detail)
    }

    fn fsm_cfg(&self, ty: FsmType) -> &FsmConfig {
        match ty {
            FsmType::Ifsm => &self.fsm.ifsm,
            FsmType::Nfsm => &self.fsm.nfsm,
        }
    }

    /// Whether an FSM transition for `ty` should be traced. `detail`
    /// gates detail-level lines on the toggle's `detail` flag; the `all`
    /// master switch and `fsm all` catch-all both apply.
    pub fn should_trace_fsm(&self, ty: FsmType, detail: bool) -> bool {
        if self.all {
            return true;
        }
        let cfg = self.fsm_cfg(ty);
        let all = &self.fsm.all;
        (all.enabled && (!detail || all.detail)) || (cfg.enabled && (!detail || cfg.detail))
    }

    /// Whether an event of `ty` (spf, lsdb) should be traced.
    pub fn should_trace_event(&self, ty: EventType) -> bool {
        if self.all {
            return true;
        }
        match ty {
            EventType::Spf => self.spf.enabled,
            EventType::Lsdb => self.lsdb.enabled,
        }
    }
}

// ============================================================
// Config dispatch
// ============================================================

fn parse_direction(args: &mut Args) -> PacketDirection {
    match args.string().as_deref() {
        Some("send") => PacketDirection::Send,
        Some("receive") | Some("recv") => PacketDirection::Recv,
        // Absent or any other token (incl. an explicit "both") means
        // trace both directions.
        _ => PacketDirection::Both,
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
        pc.direction = PacketDirection::Both;
    }
}

/// `tracing fsm <type>` — bare presence enables; delete clears.
fn fsm_set_enable(fc: &mut FsmConfig, op: ConfigOp) {
    if op.is_set() {
        fc.enabled = true;
    } else {
        *fc = FsmConfig::default();
    }
}

/// `tracing fsm <type> detail` — detail implies enabled; delete drops
/// detail only.
fn fsm_set_detail(fc: &mut FsmConfig, op: ConfigOp) {
    if op.is_set() {
        fc.enabled = true;
        fc.detail = true;
    } else {
        fc.detail = false;
    }
}

/// Apply one committed `…/tracing/<rest>` config line to an
/// `OspfTracing`. `rest` is the path tail after the `tracing` node
/// (e.g. `/all`, `/spf`, `/packet/hello`, `/packet/hello/detail`,
/// `/fsm/nfsm`, `/fsm/nfsm/detail`); for the direction case `args` still
/// holds the trailing send/receive value.
fn apply_tracing(t: &mut OspfTracing, rest: &str, args: &mut Args, op: ConfigOp) -> Option<()> {
    match rest {
        "/all" => t.all = op.is_set(),
        "/spf" => t.spf.enabled = op.is_set(),
        "/lsdb" => t.lsdb.enabled = op.is_set(),
        other => {
            if let Some(pkt) = other.strip_prefix("/packet/") {
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
            } else if let Some(fsm) = other.strip_prefix("/fsm/") {
                let (typ, sub) = match fsm.split_once('/') {
                    Some((typ, sub)) => (typ, Some(sub)),
                    None => (fsm, None),
                };
                let fc = t.fsm.get_mut(typ)?;
                match sub {
                    None => fsm_set_enable(fc, op),
                    Some("detail") => fsm_set_detail(fc, op),
                    Some(_) => return None,
                }
            } else {
                return None;
            }
        }
    }
    Some(())
}

/// Dispatch a committed `/router/{ospf,ospfv3}/tracing/…` Set/Delete
/// path to this instance's `OspfTracing` and apply it.
///
/// Called from `Ospf::process_cm_msg` for paths the regular callback
/// table does not claim. The per-message-type names are YANG presence
/// containers (not list keys), so the type lives in the *path*, not in
/// `args`; a single parser handles the whole subtree. Returns `None`
/// (ignored) for non-tracing paths and malformed tails.
pub fn config_tracing_dispatch<V: OspfVersion>(
    ospf: &mut Ospf<V>,
    path: &str,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    // Prefix is `/router/ospf/tracing` or `/router/ospfv3/tracing`,
    // selected by the version's PROTO label.
    let rest = path
        .strip_prefix("/router/")?
        .strip_prefix(V::PROTO)?
        .strip_prefix("/tracing")?;
    apply_tracing(&mut ospf.tracing, rest, &mut args, op)
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
        let mut t = OspfTracing::default();

        apply_tracing(&mut t, "/all", &mut args(&[]), ConfigOp::Set);
        assert!(t.all);
        apply_tracing(&mut t, "/all", &mut args(&[]), ConfigOp::Delete);
        assert!(!t.all);

        apply_tracing(&mut t, "/spf", &mut args(&[]), ConfigOp::Set);
        apply_tracing(&mut t, "/lsdb", &mut args(&[]), ConfigOp::Set);
        assert!(t.spf.enabled && t.lsdb.enabled);
        apply_tracing(&mut t, "/spf", &mut args(&[]), ConfigOp::Delete);
        assert!(!t.spf.enabled);
    }

    #[test]
    fn packet_bare_enable_has_defaults() {
        let mut t = OspfTracing::default();
        apply_tracing(&mut t, "/packet/hello", &mut args(&[]), ConfigOp::Set);
        assert!(t.packet.hello.enabled);
        assert!(!t.packet.hello.detail);
        assert_eq!(t.packet.hello.direction, PacketDirection::Both);
    }

    #[test]
    fn packet_detail_and_direction_imply_enabled() {
        let mut t = OspfTracing::default();
        apply_tracing(
            &mut t,
            "/packet/ls-update/detail",
            &mut args(&[]),
            ConfigOp::Set,
        );
        assert!(t.packet.ls_update.enabled);
        assert!(t.packet.ls_update.detail);

        let mut t = OspfTracing::default();
        apply_tracing(
            &mut t,
            "/packet/dd/direction",
            &mut args(&["receive"]),
            ConfigOp::Set,
        );
        assert!(t.packet.dd.enabled);
        assert_eq!(t.packet.dd.direction, PacketDirection::Recv);

        let mut t = OspfTracing::default();
        apply_tracing(
            &mut t,
            "/packet/hello/direction",
            &mut args(&["send"]),
            ConfigOp::Set,
        );
        assert_eq!(t.packet.hello.direction, PacketDirection::Send);
    }

    #[test]
    fn hyphenated_type_names_resolve() {
        let mut t = OspfTracing::default();
        apply_tracing(&mut t, "/packet/ls-req", &mut args(&[]), ConfigOp::Set);
        apply_tracing(&mut t, "/packet/ls-ack", &mut args(&[]), ConfigOp::Set);
        assert!(t.packet.ls_req.enabled && t.packet.ls_ack.enabled);
    }

    #[test]
    fn fsm_toggles_and_detail() {
        let mut t = OspfTracing::default();
        apply_tracing(&mut t, "/fsm/nfsm", &mut args(&[]), ConfigOp::Set);
        assert!(t.fsm.nfsm.enabled && !t.fsm.nfsm.detail);

        apply_tracing(&mut t, "/fsm/ifsm/detail", &mut args(&[]), ConfigOp::Set);
        assert!(t.fsm.ifsm.enabled && t.fsm.ifsm.detail);

        // Deleting detail leaves the FSM enabled at summary level.
        apply_tracing(&mut t, "/fsm/ifsm/detail", &mut args(&[]), ConfigOp::Delete);
        assert!(t.fsm.ifsm.enabled && !t.fsm.ifsm.detail);
    }

    #[test]
    fn delete_detail_keeps_type_delete_container_clears() {
        let mut t = OspfTracing::default();
        apply_tracing(
            &mut t,
            "/packet/hello/detail",
            &mut args(&[]),
            ConfigOp::Set,
        );
        apply_tracing(
            &mut t,
            "/packet/hello/direction",
            &mut args(&["send"]),
            ConfigOp::Set,
        );
        assert!(t.packet.hello.enabled && t.packet.hello.detail);
        assert_eq!(t.packet.hello.direction, PacketDirection::Send);

        apply_tracing(
            &mut t,
            "/packet/hello/detail",
            &mut args(&[]),
            ConfigOp::Delete,
        );
        assert!(t.packet.hello.enabled);
        assert!(!t.packet.hello.detail);

        apply_tracing(&mut t, "/packet/hello", &mut args(&[]), ConfigOp::Delete);
        assert!(!t.packet.hello.enabled);
        assert_eq!(t.packet.hello.direction, PacketDirection::Both);
    }

    #[test]
    fn unknown_tail_or_type_is_ignored() {
        let mut t = OspfTracing::default();
        assert_eq!(
            apply_tracing(&mut t, "/bogus", &mut args(&[]), ConfigOp::Set),
            None
        );
        assert_eq!(
            apply_tracing(&mut t, "/packet/bogus", &mut args(&[]), ConfigOp::Set),
            None
        );
        assert_eq!(
            apply_tracing(&mut t, "/packet/hello/bogus", &mut args(&[]), ConfigOp::Set),
            None
        );
        assert_eq!(
            apply_tracing(&mut t, "/fsm/bogus", &mut args(&[]), ConfigOp::Set),
            None
        );
    }

    // ---- read side: should_trace_* -------------------------------

    #[test]
    fn should_trace_packet_respects_direction() {
        let mut t = OspfTracing::default();
        apply_tracing(
            &mut t,
            "/packet/hello/direction",
            &mut args(&["send"]),
            ConfigOp::Set,
        );
        assert!(t.should_trace_packet(PacketType::Hello, PacketDirection::Send));
        assert!(!t.should_trace_packet(PacketType::Hello, PacketDirection::Recv));
        // Other types are unaffected.
        assert!(!t.should_trace_packet(PacketType::DbDesc, PacketDirection::Send));
    }

    #[test]
    fn should_trace_packet_both_matches_either_direction() {
        let mut t = OspfTracing::default();
        apply_tracing(&mut t, "/packet/ls-update", &mut args(&[]), ConfigOp::Set);
        assert!(t.should_trace_packet(PacketType::LsUpdate, PacketDirection::Send));
        assert!(t.should_trace_packet(PacketType::LsUpdate, PacketDirection::Recv));
    }

    #[test]
    fn all_master_switch_traces_everything() {
        let mut t = OspfTracing::default();
        apply_tracing(&mut t, "/all", &mut args(&[]), ConfigOp::Set);
        assert!(t.should_trace_packet(PacketType::LsAck, PacketDirection::Recv));
        assert!(t.should_trace_fsm(FsmType::Nfsm, true));
        assert!(t.should_trace_fsm(FsmType::Ifsm, false));
        assert!(t.should_trace_event(EventType::Spf));
        assert!(t.should_trace_event(EventType::Lsdb));
        // `all` is summary-level only — it does not imply detail.
        assert!(!t.packet_detail(PacketType::LsAck, PacketDirection::Recv));
    }

    #[test]
    fn packet_all_catchall_applies_per_type() {
        let mut t = OspfTracing::default();
        apply_tracing(&mut t, "/packet/all", &mut args(&[]), ConfigOp::Set);
        assert!(t.should_trace_packet(PacketType::Hello, PacketDirection::Send));
        assert!(t.should_trace_packet(PacketType::LsAck, PacketDirection::Recv));
    }

    #[test]
    fn fsm_detail_gating() {
        let mut t = OspfTracing::default();
        apply_tracing(&mut t, "/fsm/nfsm", &mut args(&[]), ConfigOp::Set);
        // Summary line traces; detail line does not (no detail flag).
        assert!(t.should_trace_fsm(FsmType::Nfsm, false));
        assert!(!t.should_trace_fsm(FsmType::Nfsm, true));

        apply_tracing(&mut t, "/fsm/nfsm/detail", &mut args(&[]), ConfigOp::Set);
        assert!(t.should_trace_fsm(FsmType::Nfsm, true));
    }

    #[test]
    fn detail_requires_matching_direction() {
        let mut t = OspfTracing::default();
        apply_tracing(
            &mut t,
            "/packet/ls-update/direction",
            &mut args(&["receive"]),
            ConfigOp::Set,
        );
        apply_tracing(
            &mut t,
            "/packet/ls-update/detail",
            &mut args(&[]),
            ConfigOp::Set,
        );
        assert!(t.packet_detail(PacketType::LsUpdate, PacketDirection::Recv));
        assert!(!t.packet_detail(PacketType::LsUpdate, PacketDirection::Send));
    }
}
