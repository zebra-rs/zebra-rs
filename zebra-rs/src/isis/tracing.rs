//! IS-IS conditional tracing — consistent with OSPF (`zebra-ospf-tracing`)
//! and BGP (`zebra-bgp-tracing`).
//!
//! The `router isis tracing { ... }` config tree (defined in
//! `zebra-isis-tracing.yang`) is written through `config_tracing_dispatch`
//! into the typed [`IsisTracing`] block held on the instance; gated log
//! macros consult it via the `should_trace_*` methods, so categories can
//! be turned on at runtime without a rebuild.
//!
//! The schema mirrors the OSPF model (presence containers, an `all`
//! master switch, per-PDU `direction` refinement) with one IS-IS-specific
//! addition: a functional `level` filter (level-1 / level-2) on the packet
//! and event categories.
use super::Isis;
use super::level::Level;
use crate::config::{Args, ConfigOp};

// ============================================================
// Tracing categories
// ============================================================

/// IS-IS level filter for per-category tracing. The YANG `level` leaf
/// omitted means both levels, so `Both` is the default.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TracingLevel {
    #[default]
    Both,
    L1,
    L2,
}

impl TracingLevel {
    /// Whether an event at `actual` level passes this filter. `Both`
    /// matches either level.
    fn matches(self, actual: &Level) -> bool {
        match self {
            TracingLevel::Both => true,
            TracingLevel::L1 => matches!(actual, Level::L1),
            TracingLevel::L2 => matches!(actual, Level::L2),
        }
    }
}

/// Direction filter for per-PDU-type tracing. The YANG `direction` leaf
/// omitted means both, so `Both` is the default. Variant names match the
/// `#[isis_pdu_handler]` proc-macro's accepted set (Send / Recv / Both).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PacketDirection {
    Send,
    Recv,
    #[default]
    Both,
}

impl PacketDirection {
    pub const fn as_str(&self) -> &'static str {
        match self {
            PacketDirection::Send => "Send",
            PacketDirection::Recv => "Receive",
            PacketDirection::Both => "Both",
        }
    }

    /// Whether a PDU flowing in `actual` direction passes this filter.
    /// `Both` matches either direction.
    fn matches(self, actual: PacketDirection) -> bool {
        self == PacketDirection::Both || self == actual
    }
}

/// IS-IS PDU type. Variant names match the `#[isis_pdu_handler]`
/// proc-macro's accepted set (Hello / Lsp / Csnp / Psnp).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    Hello,
    Lsp,
    Csnp,
    Psnp,
}

impl PacketType {
    pub const fn as_str(&self) -> &'static str {
        match self {
            PacketType::Hello => "Hello",
            PacketType::Lsp => "Lsp",
            PacketType::Csnp => "Csnp",
            PacketType::Psnp => "Psnp",
        }
    }
}

/// IS-IS event category, selected at an event trace site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    LspOriginate,
    LspPurge,
}

/// IS-IS database category, selected at a database trace site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatabaseType {
    Lsdb,
}

/// Per-PDU-type tracing toggle. `enabled` is the presence of the
/// `packet <type>` container; `direction` and `level` are its optional
/// refinements.
#[derive(Debug, Clone, Copy, Default)]
pub struct PacketConfig {
    pub enabled: bool,
    pub direction: PacketDirection,
    pub level: TracingLevel,
}

/// Per-PDU-type tracing block. `all` is a catch-all applied on top of the
/// individual per-type toggles.
#[derive(Debug, Clone, Default)]
pub struct PacketTracing {
    pub all: PacketConfig,
    pub hello: PacketConfig,
    pub lsp: PacketConfig,
    pub csnp: PacketConfig,
    pub psnp: PacketConfig,
}

impl PacketTracing {
    /// Resolve a `&mut PacketConfig` by its YANG node name. `None` for an
    /// unknown name (only reachable on a malformed path — the YANG
    /// presence containers constrain the set).
    fn get_mut(&mut self, name: &str) -> Option<&mut PacketConfig> {
        Some(match name {
            "all" => &mut self.all,
            "hello" => &mut self.hello,
            "lsp" => &mut self.lsp,
            "csnp" => &mut self.csnp,
            "psnp" => &mut self.psnp,
            _ => return None,
        })
    }
}

/// Per-FSM tracing toggle.
#[derive(Debug, Clone, Copy, Default)]
pub struct FsmConfig {
    pub enabled: bool,
}

/// FSM tracing block. Only the neighbor (adjacency) FSM has trace sites
/// today; the interface FSM toggle lands here when it grows one.
#[derive(Debug, Clone, Default)]
pub struct FsmTracing {
    pub nfsm: FsmConfig,
}

/// Per-event / per-database tracing toggle. `enabled` is the presence of
/// the category container; `level` is its optional refinement.
#[derive(Debug, Clone, Copy, Default)]
pub struct EventConfig {
    pub enabled: bool,
    pub level: TracingLevel,
}

/// Conditional IS-IS tracing configuration. One instance lives on each
/// `Isis`; links borrow it as `&IsisTracing`.
#[derive(Debug, Clone, Default)]
pub struct IsisTracing {
    /// Master switch — when set, every category is traced regardless of
    /// its individual toggle.
    pub all: bool,
    pub packet: PacketTracing,
    pub fsm: FsmTracing,
    pub lsp_originate: EventConfig,
    pub lsp_purge: EventConfig,
    pub lsdb: EventConfig,
    /// IS-IS↔BFD interaction (RFC 5882): session state changes, subscribe,
    /// adjacency teardown and hold-down recovery. A bare toggle — a BFD
    /// session is keyed per interface and neighbor address, not per IS-IS
    /// level, so there is no `level` refinement.
    pub bfd: bool,
}

impl IsisTracing {
    fn packet_cfg(&self, ty: PacketType) -> &PacketConfig {
        match ty {
            PacketType::Hello => &self.packet.hello,
            PacketType::Lsp => &self.packet.lsp,
            PacketType::Csnp => &self.packet.csnp,
            PacketType::Psnp => &self.packet.psnp,
        }
    }

    /// Whether a `ty` PDU in `dir` at `level` should be traced. The `all`
    /// master switch and the `packet all` catch-all both apply on top of
    /// the per-type toggle.
    pub fn should_trace_packet(&self, ty: PacketType, dir: PacketDirection, level: &Level) -> bool {
        if self.all {
            return true;
        }
        let cfg = self.packet_cfg(ty);
        let all = &self.packet.all;
        (all.enabled && all.direction.matches(dir) && all.level.matches(level))
            || (cfg.enabled && cfg.direction.matches(dir) && cfg.level.matches(level))
    }

    /// Whether neighbor (adjacency) FSM transitions should be traced. The
    /// `all` master switch applies on top of the `fsm nfsm` toggle.
    pub fn should_trace_fsm(&self) -> bool {
        self.all || self.fsm.nfsm.enabled
    }

    fn event_cfg(&self, ty: EventType) -> &EventConfig {
        match ty {
            EventType::LspOriginate => &self.lsp_originate,
            EventType::LspPurge => &self.lsp_purge,
        }
    }

    /// Whether an event of `ty` at `level` should be traced.
    pub fn should_trace_event(&self, ty: EventType, level: &Level) -> bool {
        if self.all {
            return true;
        }
        let cfg = self.event_cfg(ty);
        cfg.enabled && cfg.level.matches(level)
    }

    /// Whether a database event of `ty` at `level` should be traced.
    pub fn should_trace_database(&self, ty: DatabaseType, level: &Level) -> bool {
        if self.all {
            return true;
        }
        let cfg = match ty {
            DatabaseType::Lsdb => &self.lsdb,
        };
        cfg.enabled && cfg.level.matches(level)
    }

    /// Whether IS-IS↔BFD interaction (RFC 5882 session events, subscribe /
    /// adjacency teardown / hold-down recovery) should be traced. The `all`
    /// master switch applies on top of the `bfd` toggle.
    pub fn should_trace_bfd(&self) -> bool {
        self.all || self.bfd
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

fn parse_level(args: &mut Args) -> TracingLevel {
    match args.string().as_deref() {
        Some("level-1") => TracingLevel::L1,
        Some("level-2") => TracingLevel::L2,
        // Absent or any other token means trace both levels.
        _ => TracingLevel::Both,
    }
}

/// `tracing packet <type>` — bare presence enables the type; delete
/// clears the whole toggle (including any direction / level).
fn packet_set_enable(pc: &mut PacketConfig, op: ConfigOp) {
    if op.is_set() {
        pc.enabled = true;
    } else {
        *pc = PacketConfig::default();
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

/// `tracing packet <type> level {level-1|level-2}` — restrict the level
/// (and enable the type); delete reverts to both levels.
fn packet_set_level(pc: &mut PacketConfig, args: &mut Args, op: ConfigOp) {
    if op.is_set() {
        pc.enabled = true;
        pc.level = parse_level(args);
    } else {
        pc.level = TracingLevel::Both;
    }
}

/// `tracing fsm nfsm` — bare presence enables; delete clears.
fn fsm_set_enable(fc: &mut FsmConfig, op: ConfigOp) {
    fc.enabled = op.is_set();
}

/// `tracing <event>` — bare presence enables; delete clears the whole
/// toggle (including any level).
fn event_set_enable(ec: &mut EventConfig, op: ConfigOp) {
    if op.is_set() {
        ec.enabled = true;
    } else {
        *ec = EventConfig::default();
    }
}

/// `tracing <event> level {level-1|level-2}` — restrict the level (and
/// enable the event); delete reverts to both levels.
fn event_set_level(ec: &mut EventConfig, args: &mut Args, op: ConfigOp) {
    if op.is_set() {
        ec.enabled = true;
        ec.level = parse_level(args);
    } else {
        ec.level = TracingLevel::Both;
    }
}

/// Apply one committed `…/tracing/<rest>` config line to an
/// `IsisTracing`. `rest` is the path tail after the `tracing` node
/// (e.g. `/all`, `/packet/hello`, `/packet/hello/direction`,
/// `/packet/lsp/level`, `/fsm/nfsm`, `/lsp-originate`,
/// `/lsdb/level`, `/bfd`); for the direction / level cases `args` still
/// holds the trailing value.
fn apply_tracing(t: &mut IsisTracing, rest: &str, args: &mut Args, op: ConfigOp) -> Option<()> {
    match rest {
        "/all" => t.all = op.is_set(),
        // `bfd` is a bare presence toggle (no level — a BFD session is not
        // IS-IS-level-scoped), so handle it here rather than via the
        // level-bearing event branch below.
        "/bfd" => t.bfd = op.is_set(),
        other => {
            if let Some(pkt) = other.strip_prefix("/packet/") {
                let (typ, sub) = match pkt.split_once('/') {
                    Some((typ, sub)) => (typ, Some(sub)),
                    None => (pkt, None),
                };
                let pc = t.packet.get_mut(typ)?;
                match sub {
                    None => packet_set_enable(pc, op),
                    Some("direction") => packet_set_direction(pc, args, op),
                    Some("level") => packet_set_level(pc, args, op),
                    Some(_) => return None,
                }
            } else if let Some(fsm) = other.strip_prefix("/fsm/") {
                // FSM types are bare presence containers (no sub-leaves).
                match fsm {
                    "nfsm" => fsm_set_enable(&mut t.fsm.nfsm, op),
                    _ => return None,
                }
            } else {
                let ev = other.strip_prefix('/')?;
                let (name, sub) = match ev.split_once('/') {
                    Some((name, sub)) => (name, Some(sub)),
                    None => (ev, None),
                };
                let ec = match name {
                    "lsp-originate" => &mut t.lsp_originate,
                    "lsp-purge" => &mut t.lsp_purge,
                    "lsdb" => &mut t.lsdb,
                    _ => return None,
                };
                match sub {
                    None => event_set_enable(ec, op),
                    Some("level") => event_set_level(ec, args, op),
                    Some(_) => return None,
                }
            }
        }
    }
    Some(())
}

/// Dispatch a committed `/router/isis/tracing/…` Set/Delete path to this
/// instance's `IsisTracing` and apply it.
///
/// Called from `Isis::process_cm_msg` for paths the regular callback
/// table does not claim. The per-category names are YANG presence
/// containers (not list keys), so the category lives in the *path*, not in
/// `args`; a single parser handles the whole subtree. Returns `None`
/// (ignored) for non-tracing paths and malformed tails.
pub fn config_tracing_dispatch(
    isis: &mut Isis,
    path: &str,
    mut args: Args,
    op: ConfigOp,
) -> Option<()> {
    let rest = path.strip_prefix("/router/isis/tracing")?;
    apply_tracing(&mut isis.tracing, rest, &mut args, op)
}

/// Log an info-level message with proto="isis" field
#[macro_export]
macro_rules! isis_info {
    ($($arg:tt)*) => {
        tracing::info!(proto = "isis", $($arg)*)
    };
}

/// Log a warning-level message with proto="isis" field
#[macro_export]
macro_rules! isis_warn {
    ($($arg:tt)*) => {
        tracing::warn!(proto = "isis", $($arg)*)
    };
}

/// Log an error-level message with proto="isis" field
#[macro_export]
macro_rules! isis_error {
    ($($arg:tt)*) => {
        tracing::error!(proto = "isis", $($arg)*)
    };
}

/// Log a debug-level message with proto="isis" field
#[macro_export]
macro_rules! isis_debug {
    ($($arg:tt)*) => {
        tracing::debug!(proto = "isis", $($arg)*)
    };
}

/// Log a trace-level message with proto="isis" field
#[macro_export]
macro_rules! isis_trace {
    ($($arg:tt)*) => {
        tracing::trace!(proto = "isis", $($arg)*)
    };
}

/// Conditional packet tracing macro
#[macro_export]
macro_rules! isis_packet_trace {
    ($tracing:expr, $packet_type:ident, $direction:ident, $level:expr, $($arg:tt)*) => {
        if $tracing.should_trace_packet(
            $crate::isis::tracing::PacketType::$packet_type,
            $crate::isis::tracing::PacketDirection::$direction,
            $level
        ) {
            tracing::info!(
                proto = "isis",
                category = "packet",
                packet_type = stringify!($packet_type),
                direction = stringify!($direction),
                level = %$level,
                $($arg)*
            )
        }
    };
}

/// Conditional event tracing macro
#[macro_export]
macro_rules! isis_event_trace {
    ($tracing:expr, $event_type:ident, $level:expr, $($arg:tt)*) => {
        if $tracing.should_trace_event(
            $crate::isis::tracing::EventType::$event_type,
            $level
        ) {
            tracing::info!(
                proto = "isis",
                category = "event",
                event_type = stringify!($event_type),
                level = %$level,
                $($arg)*
            )
        }
    };
}

/// Conditional database tracing macro
#[macro_export]
macro_rules! isis_database_trace {
    ($tracing:expr, $db_type:ident, $level:expr, $($arg:tt)*) => {
        if $tracing.should_trace_database(
            $crate::isis::tracing::DatabaseType::$db_type,
            $level
        ) {
            tracing::info!(
                proto = "isis",
                category = "database",
                db_type = stringify!($db_type),
                level = %$level,
                $($arg)*
            )
        }
    };
}

/// Simplified packet tracing macro that uses the context defined by the
/// `#[isis_pdu_handler]` proc-macro (`_ISIS_PKT_TYPE` / `_ISIS_PKT_DIR`).
/// Must be used in a function carrying that attribute.
#[macro_export]
macro_rules! isis_pkt_trace {
    ($tracing:expr, $level:expr, $($arg:tt)*) => {
        if $tracing.should_trace_packet(_ISIS_PKT_TYPE, _ISIS_PKT_DIR, $level) {
            tracing::info!(
                proto = "isis",
                category = "packet",
                packet_type = _ISIS_PKT_TYPE.as_str(),
                direction = _ISIS_PKT_DIR.as_str(),
                level = %$level,
                $($arg)*
            )
        }
    };
}

/// Like `isis_pkt_trace!` but reaches the tracing block through the
/// `.tracing` field of `$tracing` (e.g. a link state).
#[macro_export]
macro_rules! isis_pdu_trace {
    ($tracing:expr, $level:expr, $($arg:tt)*) => {
        if $tracing.tracing.should_trace_packet(_ISIS_PKT_TYPE, _ISIS_PKT_DIR, $level) {
            tracing::info!(
                proto = "isis",
                category = "packet",
                packet_type = _ISIS_PKT_TYPE.as_str(),
                direction = _ISIS_PKT_DIR.as_str(),
                level = %$level,
                $($arg)*
            )
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(items: &[&str]) -> Args {
        Args(items.iter().map(|s| s.to_string()).collect())
    }

    #[test]
    fn master_all_traces_everything() {
        let mut t = IsisTracing::default();
        apply_tracing(&mut t, "/all", &mut args(&[]), ConfigOp::Set);
        assert!(t.all);
        assert!(t.should_trace_packet(PacketType::Hello, PacketDirection::Send, &Level::L1));
        assert!(t.should_trace_fsm());
        assert!(t.should_trace_event(EventType::LspOriginate, &Level::L2));
        assert!(t.should_trace_database(DatabaseType::Lsdb, &Level::L1));
        assert!(t.should_trace_bfd());

        apply_tracing(&mut t, "/all", &mut args(&[]), ConfigOp::Delete);
        assert!(!t.all);
        assert!(!t.should_trace_packet(PacketType::Hello, PacketDirection::Send, &Level::L1));
        assert!(!t.should_trace_bfd());
    }

    #[test]
    fn bfd_toggle() {
        let mut t = IsisTracing::default();
        assert!(!t.should_trace_bfd());
        apply_tracing(&mut t, "/bfd", &mut args(&[]), ConfigOp::Set);
        assert!(t.bfd);
        assert!(t.should_trace_bfd());
        // bfd is independent of the other categories.
        assert!(!t.should_trace_fsm());
        apply_tracing(&mut t, "/bfd", &mut args(&[]), ConfigOp::Delete);
        assert!(!t.bfd);
        assert!(!t.should_trace_bfd());
    }

    #[test]
    fn packet_direction_and_level_filter() {
        let mut t = IsisTracing::default();
        // tracing packet hello direction receive
        apply_tracing(
            &mut t,
            "/packet/hello/direction",
            &mut args(&["receive"]),
            ConfigOp::Set,
        );
        assert!(t.packet.hello.enabled);
        assert!(t.should_trace_packet(PacketType::Hello, PacketDirection::Recv, &Level::L1));
        assert!(!t.should_trace_packet(PacketType::Hello, PacketDirection::Send, &Level::L1));
        // other PDU types unaffected
        assert!(!t.should_trace_packet(PacketType::Lsp, PacketDirection::Recv, &Level::L1));

        // tracing packet lsp level level-2
        apply_tracing(
            &mut t,
            "/packet/lsp/level",
            &mut args(&["level-2"]),
            ConfigOp::Set,
        );
        assert!(t.should_trace_packet(PacketType::Lsp, PacketDirection::Both, &Level::L2));
        assert!(!t.should_trace_packet(PacketType::Lsp, PacketDirection::Both, &Level::L1));
    }

    #[test]
    fn packet_all_catch_all() {
        let mut t = IsisTracing::default();
        apply_tracing(&mut t, "/packet/all", &mut args(&[]), ConfigOp::Set);
        for ty in [
            PacketType::Hello,
            PacketType::Lsp,
            PacketType::Csnp,
            PacketType::Psnp,
        ] {
            assert!(t.should_trace_packet(ty, PacketDirection::Send, &Level::L1));
        }
    }

    #[test]
    fn fsm_and_event_toggles() {
        let mut t = IsisTracing::default();
        assert!(!t.should_trace_fsm());
        apply_tracing(&mut t, "/fsm/nfsm", &mut args(&[]), ConfigOp::Set);
        assert!(t.should_trace_fsm());
        apply_tracing(&mut t, "/fsm/nfsm", &mut args(&[]), ConfigOp::Delete);
        assert!(!t.should_trace_fsm());

        // event with level filter
        apply_tracing(
            &mut t,
            "/lsp-originate/level",
            &mut args(&["level-1"]),
            ConfigOp::Set,
        );
        assert!(t.should_trace_event(EventType::LspOriginate, &Level::L1));
        assert!(!t.should_trace_event(EventType::LspOriginate, &Level::L2));
        assert!(!t.should_trace_event(EventType::LspPurge, &Level::L1));

        apply_tracing(&mut t, "/lsdb", &mut args(&[]), ConfigOp::Set);
        assert!(t.should_trace_database(DatabaseType::Lsdb, &Level::L2));
    }

    #[test]
    fn unknown_paths_ignored() {
        let mut t = IsisTracing::default();
        assert_eq!(
            apply_tracing(&mut t, "/bogus", &mut args(&[]), ConfigOp::Set),
            None
        );
        assert_eq!(
            apply_tracing(&mut t, "/packet/bogus", &mut args(&[]), ConfigOp::Set),
            None
        );
        assert_eq!(
            apply_tracing(&mut t, "/fsm/ifsm", &mut args(&[]), ConfigOp::Set),
            None
        );
    }
}
