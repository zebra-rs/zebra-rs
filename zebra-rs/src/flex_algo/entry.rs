use std::collections::BTreeSet;
use std::str::FromStr;

use anyhow::{Result, bail};

/// FAD Metric-Type (RFC 9350 §5.1, IANA registry). The on-the-wire
/// byte is identical across IS-IS and OSPF, so the enum and its
/// `wire()` mapping are protocol-neutral.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FadMetricType {
    Igp,                // FAD Metric-Type 0
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
    pub ti_lfa: bool,
}
