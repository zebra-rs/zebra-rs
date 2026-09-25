//! Participation in a Flexible Algorithm (RFC 9350 §5.3): the outcome of
//! selecting the winning Flexible Algorithm Definition and checking that
//! this router supports everything in it. Protocol-neutral; each IGP
//! selects from its own wire FADs and reports through these types.

use std::fmt;

use super::constraint::FadConstraints;

/// Why a router configured for a Flexible Algorithm is not participating
/// in it. RFC 9350 §5.3: "If a node is configured to participate in a
/// particular Flexible Algorithm, but there is no valid Flex-Algorithm
/// Definition available for it or the selected Flex-Algorithm Definition
/// includes calculation-type, metric-type, constraint, flag, or sub-TLV
/// that is not supported by the node, it MUST stop participating".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unsupported {
    /// No router in the area/level advertises a valid definition.
    NoDefinition,
    /// A calculation-type other than SPF (0).
    CalcType(u8),
    /// A metric-type this router cannot compute with (TE-default among
    /// them).
    MetricType(u8),
    /// The M flag: the Flex-Algorithm prefix metric is not implemented.
    PrefixMetric,
    /// A FAD flag bit this router does not know.
    Flag,
    /// Exclude SRLG: advertised, but per-link SRLGs are not read, so the
    /// rule cannot be enforced.
    ExcludeSrlg,
    /// A FAD sub-TLV type this router does not know.
    SubTlv(u16),
    /// A sub-TLV runs past the end of the definition, so the definition
    /// cannot be read in full.
    Truncated,
}

impl fmt::Display for Unsupported {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoDefinition => write!(f, "no definition advertised"),
            Self::CalcType(t) => write!(f, "unsupported calc-type {t}"),
            Self::MetricType(t) => write!(f, "unsupported metric-type {t}"),
            Self::PrefixMetric => write!(f, "unsupported flag: prefix metric (M)"),
            Self::Flag => write!(f, "unsupported flag"),
            Self::ExcludeSrlg => write!(f, "unsupported constraint: exclude SRLG"),
            Self::SubTlv(t) => write!(f, "unsupported sub-TLV {t}"),
            Self::Truncated => write!(f, "truncated definition"),
        }
    }
}

/// Whether this router participates in one Flexible Algorithm, and with
/// which constraints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Participation {
    /// Participating: compute with these, the winning definition's.
    Yes(FadConstraints),
    /// Not participating: advertise no participation, keep no forwarding
    /// state.
    No(Unsupported),
}

impl Participation {
    pub fn constraints(&self) -> Option<&FadConstraints> {
        match self {
            Self::Yes(c) => Some(c),
            Self::No(_) => None,
        }
    }
}
