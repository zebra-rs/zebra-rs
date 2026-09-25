use std::collections::BTreeSet;
use std::str::FromStr;

use anyhow::{Result, bail};

/// FAD Metric-Type (RFC 9350 §5.1, IANA registry). The on-the-wire
/// byte is identical across IS-IS and OSPF, so the enum and its
/// `wire()` mapping are protocol-neutral.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum FadMetricType {
    #[default]
    Igp, // FAD Metric-Type 0
    MinUnidirLinkDelay, // FAD Metric-Type 1 (RFC 8570)
    TeDefault,          // FAD Metric-Type 2 (RFC 5305)
}

impl FadMetricType {
    /// FAD Sub-TLV Metric-Type code (RFC 9350 §5.1, IANA registry).
    /// Single source of truth for the on-the-wire byte, consumed by
    /// each protocol's FAD builder at LSP/LSA-build time.
    pub fn wire(self) -> u8 {
        match self {
            Self::Igp => 0,
            Self::MinUnidirLinkDelay => 1,
            Self::TeDefault => 2,
        }
    }

    /// The metric-types this router can compute a path with: IGP and Min
    /// Unidirectional Link Delay. TE-default (2) is not implemented, so a
    /// winning FAD asking for it — or for any unknown metric-type — stops
    /// participation (RFC 9350 §5.3) rather than being computed as IGP.
    pub fn supported(wire: u8) -> Option<Self> {
        match wire {
            0 => Some(Self::Igp),
            1 => Some(Self::MinUnidirLinkDelay),
            _ => None,
        }
    }
}

impl FromStr for FadMetricType {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "igp" => Ok(Self::Igp),
            "min-unidir-link-delay" => Ok(Self::MinUnidirLinkDelay),
            "te-default" => Ok(Self::TeDefault),
            _ => bail!("unknown flex-algo metric-type: {s}"),
        }
    }
}

/// One Flexible Algorithm Definition (RFC 9350) as configured on this
/// router. Mirrors the YANG schema under /router/{isis,ospf}/flex-algo.
/// Protocol-neutral: affinity / SRLG constraints are held as the
/// operator-facing names, resolved to bitmaps by each protocol at
/// origination / SPF time.
#[derive(Debug, Default, Clone)]
pub struct FlexAlgoEntry {
    pub delete: bool,
    pub advertise_definition: Option<bool>,
    pub metric_type: Option<FadMetricType>,
    pub priority: Option<u8>,
    pub prefix_metric: Option<bool>,
    pub dataplane_sr_mpls: Option<bool>,
    pub dataplane_srv6: Option<bool>,
    pub dataplane_ip: Option<bool>,
    pub include_any: BTreeSet<String>,
    pub include_all: BTreeSet<String>,
    pub exclude_any: BTreeSet<String>,
    pub srlg_exclude: BTreeSet<String>,
    /// Per-algorithm fast-reroute OPT-OUT (`flex-algo <n> fast-reroute
    /// disable`). Default `false` means this algorithm inherits the
    /// instance-level TI-LFA setting, matching IOS-XR / Juniper / FRR,
    /// where enabling TI-LFA protects every algorithm the router
    /// participates in rather than algorithm 0 alone.
    pub fast_reroute_disable: bool,
    /// `exclude-max-link-loss`, in micro-percent exactly as configured
    /// (draft-ietf-lsr-flex-algo-link-loss). Advertised as the FAEML
    /// sub-TLV in RFC 8570 units, [`Self::exclude_max_link_loss_units`].
    pub exclude_max_link_loss: Option<u64>,
}

impl FlexAlgoEntry {
    /// The configured maximum link loss in RFC 8570 units, rounded to
    /// nearest — the rounding a measured loss is advertised with, so a link
    /// measuring exactly the configured percentage encodes to the same
    /// integer and, not exceeding it, is kept.
    pub fn exclude_max_link_loss_units(&self) -> Option<u32> {
        self.exclude_max_link_loss.map(micro_pct_to_units_nearest)
    }
}

/// The highest loss RFC 8570 can express, 50.331642 % (2^24 − 2 units), in
/// micro-percent.
pub const MAX_LINK_LOSS_MICRO_PCT: u64 = 50_331_642;

/// Micro-percent (10⁻⁶ %) to RFC 8570 loss units (3 × 10⁻⁶ % each),
/// rounded to nearest: `m / 3 + ½`.
pub fn micro_pct_to_units_nearest(micro_pct: u64) -> u32 {
    ((2 * micro_pct + 3) / 6).min(u64::from(u32::MAX)) as u32
}

/// `flex-algo <n> exclude-max-link-loss`: a percentage with at most six
/// decimal places, up to the 50.331642 % the wire can carry, returned in
/// micro-percent. libyang enforces neither a decimal64 range nor
/// `fraction-digits`, so this runs at commit (`config::check`) as well as
/// in the setter.
pub fn check_max_link_loss(value: &str) -> std::result::Result<u64, String> {
    crate::stamp::session::parse_percent_micro(value)
        .filter(|m| *m <= MAX_LINK_LOSS_MICRO_PCT)
        .ok_or_else(|| "must be 0 to 50.331642 percent, with at most 6 decimal places".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Rounded to nearest, as a measured loss is: 5 % is 1666666.67 units,
    /// so 1666667; the ceiling is exactly 2^24 − 2.
    #[test]
    fn max_link_loss_rounds_to_nearest_unit() {
        for (micro, units) in [
            (0, 0),
            (1, 0),
            (2, 1),
            (3, 1),
            (4, 1),
            (5, 2),
            (5_000_000, 1_666_667),
            (1_000_000, 333_333),
            (MAX_LINK_LOSS_MICRO_PCT, 16_777_214),
        ] {
            assert_eq!(micro_pct_to_units_nearest(micro), units, "{micro}");
        }
    }

    #[test]
    fn max_link_loss_is_checked_at_commit() {
        assert_eq!(check_max_link_loss("5"), Ok(5_000_000));
        assert_eq!(check_max_link_loss("0"), Ok(0));
        assert_eq!(check_max_link_loss("0.000001"), Ok(1));
        assert_eq!(
            check_max_link_loss("50.331642"),
            Ok(MAX_LINK_LOSS_MICRO_PCT)
        );
        for bad in ["50.331643", "51", "100", "1.0000001", "-1", "abc", "1."] {
            assert!(check_max_link_loss(bad).is_err(), "{bad}");
        }
    }
}
