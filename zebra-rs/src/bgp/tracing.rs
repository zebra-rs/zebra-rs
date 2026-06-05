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

// ============================================================
// BgpTracing — runtime tracing configuration
// ============================================================
//
// Backs the `router bgp tracing { ... }` (instance-wide) and
// `router bgp neighbor <addr> tracing { ... }` (per-neighbor) config
// trees defined in zebra-bgp-tracing.yang. The config callbacks below
// write it; the gated `bgp_*_trace!` macros that READ it (with
// `should_trace_*` accessors) land in a follow-up. Until those readers
// exist the fields are written-only, so the data structs and the
// `tracing` fields on `Bgp` / `Peer` carry `#[allow(dead_code)]`.

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

/// Per-message-type tracing toggle. `enabled` is the presence of the
/// `packet <type>` container; `detail` and `direction` are its optional
/// refinements.
#[allow(dead_code)] // read side (bgp_*_trace! macros) lands in a follow-up
#[derive(Debug, Clone, Copy, Default)]
pub struct PacketConfig {
    pub enabled: bool,
    pub detail: bool,
    pub direction: Direction,
}

/// Per-message-type tracing block. `all` is a catch-all applied on top
/// of the individual per-type toggles.
#[allow(dead_code)] // read side (bgp_*_trace! macros) lands in a follow-up
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
#[allow(dead_code)] // read side (bgp_*_trace! macros) lands in a follow-up
#[derive(Debug, Clone, Default)]
pub struct BgpTracing {
    pub all: bool,
    pub fsm: bool,
    pub packet: PacketTracing,
    pub label: bool,
    pub adj_in: bool,
    pub adj_out: bool,
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
        apply_tracing(&mut bgp.tracing, rest, &mut args, op)
    } else {
        None
    }
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
}
