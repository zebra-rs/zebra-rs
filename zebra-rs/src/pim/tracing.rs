//! PIM conditional tracing — consistent with IS-IS (`zebra-isis-tracing`),
//! OSPF (`zebra-ospf-tracing`) and BGP (`zebra-bgp-tracing`).
//!
//! The `router pim tracing { ... }` config tree (defined in
//! `zebra-pim-tracing.yang`) is written through [`config_tracing_dispatch`]
//! into the typed [`PimTracing`] block held on each `Pim<A>` instance; the
//! gated [`pim_trace!`] macro consults it via [`PimTracing::should_trace`]
//! before emitting a `proto="pim"` `tracing::info!` event, so PIM's
//! informational logging can be turned on per category at runtime without a
//! rebuild. With no `tracing` config every category is silent.
//!
//! Unlike IS-IS/OSPF, the PIM `tracing::info!` sites are protocol *events*
//! rather than per-PDU send/receive points, so each category is a bare
//! presence toggle (`type empty`) with no direction/level refinement. The
//! categories partition every info-level site in the module: adjacency
//! (`neighbor`), interface enable/disable (`interface`), IGMP/MLD
//! membership (`membership`), the (S,G)/(*,G) tree state (`tib`),
//! Join/Prune processing (`join-prune`), the assert FSM (`assert`), PIM
//! Register (`register`), the Bootstrap Router / RP-set (`bsr`), the kernel
//! MRT/MIF/MFC datapath (`mroute`), and instance lifecycle (`event`).

use super::af::PimAf;
use super::inst::Pim;
use crate::config::ConfigOp;

// ============================================================
// Tracing categories
// ============================================================

/// A PIM tracing category, selected at a trace site. Each maps to one
/// presence toggle in the `tracing` block; `as_str` is the structured
/// `category` field value and the YANG node name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceCategory {
    /// PIM neighbor (adjacency) up / down / restart.
    Neighbor,
    /// PIM / IGMP / MLD interface enable / disable.
    Interface,
    /// IGMP / MLD group-membership (querier election, group expiry).
    Membership,
    /// (S,G) / (*,G) tree state: create, delete, RPF change, retarget,
    /// upstream join / prune, SPT-bit.
    Tib,
    /// Join/Prune message processing (overhear, prune-override).
    JoinPrune,
    /// PIM assert FSM transitions.
    Assert,
    /// PIM Register / Register-Stop (FHR encapsulation path).
    Register,
    /// Bootstrap Router election and Candidate-RP advertisement (RFC 5059).
    Bsr,
    /// Kernel multicast-routing datapath (VIF/MIF add / delete).
    Mroute,
    /// Instance lifecycle: per-VRF and default-table IPv6 child spawn /
    /// despawn.
    Event,
}

impl TraceCategory {
    /// The category's YANG node name and structured `category` field value.
    pub const fn as_str(&self) -> &'static str {
        match self {
            TraceCategory::Neighbor => "neighbor",
            TraceCategory::Interface => "interface",
            TraceCategory::Membership => "membership",
            TraceCategory::Tib => "tib",
            TraceCategory::JoinPrune => "join-prune",
            TraceCategory::Assert => "assert",
            TraceCategory::Register => "register",
            TraceCategory::Bsr => "bsr",
            TraceCategory::Mroute => "mroute",
            TraceCategory::Event => "event",
        }
    }
}

/// Conditional PIM tracing configuration. One instance lives on each
/// `Pim<A>` (default IPv4, default-table IPv6 child, and each per-VRF
/// child); `router pim tracing` writes the default instance's block and
/// the same lines are forwarded live to any running children.
#[derive(Debug, Clone, Default)]
pub struct PimTracing {
    /// Master switch — when set, every category is traced regardless of
    /// its individual toggle.
    pub all: bool,
    pub neighbor: bool,
    pub interface: bool,
    pub membership: bool,
    pub tib: bool,
    pub join_prune: bool,
    pub assert: bool,
    pub register: bool,
    pub bsr: bool,
    pub mroute: bool,
    pub event: bool,
}

impl PimTracing {
    /// Whether `cat` should be traced. The `all` master switch applies on
    /// top of the per-category toggle.
    pub fn should_trace(&self, cat: TraceCategory) -> bool {
        if self.all {
            return true;
        }
        match cat {
            TraceCategory::Neighbor => self.neighbor,
            TraceCategory::Interface => self.interface,
            TraceCategory::Membership => self.membership,
            TraceCategory::Tib => self.tib,
            TraceCategory::JoinPrune => self.join_prune,
            TraceCategory::Assert => self.assert,
            TraceCategory::Register => self.register,
            TraceCategory::Bsr => self.bsr,
            TraceCategory::Mroute => self.mroute,
            TraceCategory::Event => self.event,
        }
    }
}

// ============================================================
// Config dispatch
// ============================================================

/// Apply one committed `…/tracing/<rest>` config line to a [`PimTracing`].
/// `rest` is the path tail after the `tracing` node (e.g. `/all`,
/// `/neighbor`, `/join-prune`). Each category is a bare presence toggle,
/// so Set enables and Delete disables; there are no values to read.
/// Returns `None` (ignored) for an unknown category — only reachable on a
/// malformed path, since the YANG constrains the leaf set.
fn apply_tracing(t: &mut PimTracing, rest: &str, op: ConfigOp) -> Option<()> {
    let set = op.is_set();
    match rest.strip_prefix('/')? {
        "all" => t.all = set,
        "neighbor" => t.neighbor = set,
        "interface" => t.interface = set,
        "membership" => t.membership = set,
        "tib" => t.tib = set,
        "join-prune" => t.join_prune = set,
        "assert" => t.assert = set,
        "register" => t.register = set,
        "bsr" => t.bsr = set,
        "mroute" => t.mroute = set,
        "event" => t.event = set,
        _ => return None,
    }
    Some(())
}

/// Dispatch a committed `/router/pim/tracing/…` Set/Delete path to this
/// instance's [`PimTracing`] and apply it.
///
/// Called from `Pim::process_cm_msg` for paths the regular callback table
/// does not claim. The category names are YANG presence leaves, so the
/// category lives in the *path*, not in `args`; a single parser handles
/// the whole subtree. Returns `None` (ignored) for non-tracing paths and
/// malformed tails.
pub fn config_tracing_dispatch<A: PimAf>(pim: &mut Pim<A>, path: &str, op: ConfigOp) -> Option<()> {
    let rest = path.strip_prefix("/router/pim/tracing")?;
    apply_tracing(&mut pim.tracing, rest, op)
}

// ============================================================
// Gated category macro
// ============================================================

/// Conditional PIM info trace. `$tracing` resolves to a [`PimTracing`] (or
/// `&PimTracing`) — normally `self.tracing`; `$cat` is a [`TraceCategory`]
/// variant. Emits a `proto="pim"`, `category=<cat>` `tracing::info!` event
/// only when the category (or the `all` master switch) is enabled.
#[macro_export]
macro_rules! pim_trace {
    ($tracing:expr, $cat:ident, $($arg:tt)*) => {{
        let __t = &$tracing;
        if __t.should_trace($crate::pim::tracing::TraceCategory::$cat) {
            tracing::info!(
                proto = "pim",
                category = $crate::pim::tracing::TraceCategory::$cat.as_str(),
                $($arg)*
            );
        }
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn master_all_traces_every_category() {
        let mut t = PimTracing::default();
        // Nothing traces by default.
        assert!(!t.should_trace(TraceCategory::Neighbor));
        assert!(!t.should_trace(TraceCategory::Mroute));

        apply_tracing(&mut t, "/all", ConfigOp::Set);
        assert!(t.all);
        for cat in [
            TraceCategory::Neighbor,
            TraceCategory::Interface,
            TraceCategory::Membership,
            TraceCategory::Tib,
            TraceCategory::JoinPrune,
            TraceCategory::Assert,
            TraceCategory::Register,
            TraceCategory::Bsr,
            TraceCategory::Mroute,
            TraceCategory::Event,
        ] {
            assert!(t.should_trace(cat), "all must trace {}", cat.as_str());
        }

        apply_tracing(&mut t, "/all", ConfigOp::Delete);
        assert!(!t.all);
        assert!(!t.should_trace(TraceCategory::Bsr));
    }

    #[test]
    fn individual_toggles_are_independent() {
        let mut t = PimTracing::default();
        apply_tracing(&mut t, "/neighbor", ConfigOp::Set);
        assert!(t.should_trace(TraceCategory::Neighbor));
        // Enabling one category leaves the others silent.
        assert!(!t.should_trace(TraceCategory::Register));

        apply_tracing(&mut t, "/join-prune", ConfigOp::Set);
        assert!(t.should_trace(TraceCategory::JoinPrune));

        apply_tracing(&mut t, "/neighbor", ConfigOp::Delete);
        assert!(!t.should_trace(TraceCategory::Neighbor));
        assert!(t.should_trace(TraceCategory::JoinPrune));
    }

    #[test]
    fn every_category_name_round_trips() {
        // Each category's YANG name must be a settable toggle, and its
        // `as_str()` must match the name the dispatcher accepts.
        for cat in [
            TraceCategory::Neighbor,
            TraceCategory::Interface,
            TraceCategory::Membership,
            TraceCategory::Tib,
            TraceCategory::JoinPrune,
            TraceCategory::Assert,
            TraceCategory::Register,
            TraceCategory::Bsr,
            TraceCategory::Mroute,
            TraceCategory::Event,
        ] {
            let mut t = PimTracing::default();
            let path = format!("/{}", cat.as_str());
            assert_eq!(
                apply_tracing(&mut t, &path, ConfigOp::Set),
                Some(()),
                "{} must be a known category",
                cat.as_str()
            );
            assert!(t.should_trace(cat));
        }
    }

    #[test]
    fn unknown_tail_is_ignored() {
        let mut t = PimTracing::default();
        assert_eq!(apply_tracing(&mut t, "/bogus", ConfigOp::Set), None);
        assert_eq!(apply_tracing(&mut t, "/packet/hello", ConfigOp::Set), None);
    }
}
