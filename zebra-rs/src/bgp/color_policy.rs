//! Color → Flex-Algorithm binding table (zebra-bgp-color-policy.yang).
//!
//! Maps a BGP Color extended community value (RFC 9012 §4.3) to an
//! IS-IS Flex-Algorithm id (RFC 9350) so the color-aware nexthop
//! resolver can pick the correct entry in `Isis::rib_flex_algo`.
//!
//! This module is storage-only on landing — no consumer reads
//! `Bgp::color_policy` yet. Config callbacks stage / commit edits
//! against the live map; the resolver wires in alongside the route-
//! map work in a subsequent PR.

use std::collections::BTreeMap;

use crate::config::{Args, ConfigOp};

use super::Bgp;

/// Live color → flex-algorithm binding table. Wrapped in a struct so
/// future fields (per-entry strict / fallback knobs, source attribution
/// for show output) have a stable home without touching every call
/// site.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ColorPolicy {
    /// Color value (RFC 9012 §4.3, 0..2^32-1) → Flex-Algorithm id
    /// (128..=255 per RFC 9350 §4). Multiple colors may map to the
    /// same algorithm.
    pub bindings: BTreeMap<u32, u8>,
}

impl ColorPolicy {
    pub fn new() -> Self {
        Self::default()
    }

    /// Look up the flex-algorithm currently bound to `color`. Returns
    /// `None` when no binding is configured — the caller decides
    /// whether to fall back (RFC 9256 §2.5) or treat the resolution
    /// as unreachable.
    pub fn flex_algo_for(&self, color: u32) -> Option<u8> {
        self.bindings.get(&color).copied()
    }
}

/// `set router bgp color-policy color <N>` (and `delete ...`).
///
/// The presence of the list entry is what matters; the
/// flex-algorithm leaf below carries the value. A Set with no
/// flex-algorithm leaf simply ensures the slot exists with the
/// default placeholder (no algorithm yet → no resolution).
pub fn config_color(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let color = args.u32()?;
    match op {
        ConfigOp::Set => {
            // Insert-if-missing — preserves any flex-algorithm value
            // set by a separate leaf callback in the same commit.
            bgp.color_policy.bindings.entry(color).or_insert(0);
        }
        ConfigOp::Delete => {
            bgp.color_policy.bindings.remove(&color);
        }
        _ => {}
    }
    Some(())
}

/// `set router bgp color-policy color <N> flex-algorithm <M>` (and
/// `delete ...`).
pub fn config_color_flex_algorithm(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let color = args.u32()?;
    match op {
        ConfigOp::Set => {
            let algo = args.u8()?;
            // YANG already constrains 128..=255 — defensive guard
            // here too so unit tests that bypass YANG don't smuggle
            // out-of-range values into the resolver.
            if !(128..=255).contains(&algo) {
                return None;
            }
            bgp.color_policy.bindings.insert(color, algo);
        }
        ConfigOp::Delete => {
            // Per-leaf delete clears the algorithm but keeps the
            // color slot present (matches how peer-level leaf deletes
            // behave elsewhere). The color slot itself is removed by
            // `config_color` with op=Delete.
            if let Some(slot) = bgp.color_policy.bindings.get_mut(&color) {
                *slot = 0;
            }
        }
        _ => {}
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flex_algo_for_returns_none_when_unbound() {
        let p = ColorPolicy::new();
        assert!(p.flex_algo_for(100).is_none());
    }

    #[test]
    fn flex_algo_for_returns_bound_value() {
        let mut p = ColorPolicy::new();
        p.bindings.insert(100, 128);
        assert_eq!(p.flex_algo_for(100), Some(128));
        assert!(p.flex_algo_for(101).is_none());
    }

    #[test]
    fn multiple_colors_can_map_to_same_algo() {
        let mut p = ColorPolicy::new();
        p.bindings.insert(100, 128);
        p.bindings.insert(200, 128);
        assert_eq!(p.flex_algo_for(100), Some(128));
        assert_eq!(p.flex_algo_for(200), Some(128));
    }
}
