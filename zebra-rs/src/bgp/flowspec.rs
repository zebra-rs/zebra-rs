//! BGP Flow Specification validation (RFC 9117, revising RFC 8955 §6).
//!
//! A received flow spec is *valid* (feasible) only if it embeds a
//! destination-prefix component AND one of:
//!
//!   * **(b.2)** its AS_PATH is empty or contains only confederation
//!     segments — i.e. it originated inside our AS (iBGP / route
//!     reflector / central BGP controller). RFC 9117 makes this the
//!     default-on relaxation, and
//!   * **(b.1)** the originator of the flow spec matches the originator
//!     of the best-match unicast route for the destination prefix.
//!
//! Phase 2 computes this verdict on demand for `show ip bgp flowspec`;
//! nothing yet *gates* behaviour on it. Stored verdicts, event-driven
//! re-validation when the unicast RIB changes, the more-specific-route
//! check (RFC 8955 rule c), and the per-neighbor disable knob land with
//! the Phase 3 enforcement path (where validity gates re-advertise and,
//! later, install).

use std::fmt;
use std::net::Ipv6Addr;

use bgp_packet::{
    AS_CONFED_SEQ, AS_CONFED_SET, BgpAttr, FlowspecComponent, FlowspecNlri, FlowspecPrefix,
};
use ipnet::{IpNet, Ipv6Net};

use super::inst::Bgp;
use super::route::BgpRib;

/// Outcome of validating a received flow spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowspecValidation {
    /// b.2 — AS_PATH empty / confederation-only (originated in-AS).
    ValidAsPathLocal,
    /// b.1 — originator matches the best-match unicast route.
    ValidOriginatorMatch,
    /// No destination-prefix component (RFC 8955 requires one).
    InvalidNoDestPrefix,
    /// No unicast route covers the destination prefix.
    InvalidNoUnicastRoute,
    /// Originator differs from the best-match unicast route's.
    InvalidOriginatorMismatch,
}

impl FlowspecValidation {
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::ValidAsPathLocal | Self::ValidOriginatorMatch)
    }
}

impl fmt::Display for FlowspecValidation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::ValidAsPathLocal => "valid (as-path local)",
            Self::ValidOriginatorMatch => "valid (originator match)",
            Self::InvalidNoDestPrefix => "invalid (no destination prefix)",
            Self::InvalidNoUnicastRoute => "invalid (no unicast route)",
            Self::InvalidOriginatorMismatch => "invalid (originator mismatch)",
        };
        f.write_str(s)
    }
}

/// True iff the flow spec carries a destination-prefix component.
fn has_dest_prefix(nlri: &FlowspecNlri) -> bool {
    nlri.components
        .iter()
        .any(|c| matches!(c, FlowspecComponent::DestinationPrefix(_)))
}

/// The destination prefix as an `IpNet` for the best-match unicast
/// lookup. `None` when there is no destination component, or it is an
/// IPv6 prefix with a non-zero bit offset (RFC 8956 §3.1) — an
/// offset-matched prefix does not map to a contiguous prefix for
/// longest-prefix matching.
fn dest_ipnet(nlri: &FlowspecNlri) -> Option<IpNet> {
    for c in &nlri.components {
        if let FlowspecComponent::DestinationPrefix(p) = c {
            return match p {
                FlowspecPrefix::V4(net) => Some(IpNet::V4(*net)),
                FlowspecPrefix::V6 {
                    length,
                    offset: 0,
                    pattern,
                } => {
                    let mut octets = [0u8; 16];
                    let n = pattern.len().min(16);
                    octets[..n].copy_from_slice(&pattern[..n]);
                    Ipv6Net::new(Ipv6Addr::from(octets), *length)
                        .ok()
                        .map(IpNet::V6)
                }
                FlowspecPrefix::V6 { .. } => None,
            };
        }
    }
    None
}

/// RFC 9117 condition b.2: the AS_PATH is empty or contains only
/// confederation segments (so the flow spec originated within our AS).
fn aspath_local(attr: &BgpAttr) -> bool {
    match &attr.aspath {
        None => true,
        Some(p) => {
            p.segs.is_empty()
                || p.segs
                    .iter()
                    .all(|s| s.typ == AS_CONFED_SEQ || s.typ == AS_CONFED_SET)
        }
    }
}

/// Whether the flow spec and the best-match unicast route share an
/// originator: identical ORIGINATOR_ID when both carry one (route
/// reflection), otherwise the same advertising peer.
fn originator_matches(unicast: &BgpRib, fs: &BgpRib) -> bool {
    match (
        fs.attr.originator_id.as_ref(),
        unicast.attr.originator_id.as_ref(),
    ) {
        (Some(a), Some(b)) => a.id == b.id,
        _ => unicast.ident == fs.ident,
    }
}

/// Validate one received flow spec against the unicast Loc-RIB per
/// RFC 9117. `rib` is the flow spec's Adj-RIB-In entry, carrying its
/// path attributes and advertising peer.
pub fn flowspec_validate(bgp: &Bgp, nlri: &FlowspecNlri, rib: &BgpRib) -> FlowspecValidation {
    if !has_dest_prefix(nlri) {
        return FlowspecValidation::InvalidNoDestPrefix;
    }
    // b.2 — originated inside our AS (default-on relaxation).
    if aspath_local(&rib.attr) {
        return FlowspecValidation::ValidAsPathLocal;
    }
    // b.1 — originator matches the best-match (longest-prefix) unicast
    // route for the destination prefix.
    let Some(dst) = dest_ipnet(nlri) else {
        return FlowspecValidation::InvalidNoUnicastRoute;
    };
    let best = match dst {
        IpNet::V4(p) => bgp.local_rib.v4.1.get_lpm(&p).map(|(_, r)| r),
        IpNet::V6(p) => bgp.local_rib.v6.1.get_lpm(&p).map(|(_, r)| r),
    };
    match best {
        None => FlowspecValidation::InvalidNoUnicastRoute,
        Some(u) if originator_matches(u, rib) => FlowspecValidation::ValidOriginatorMatch,
        Some(_) => FlowspecValidation::InvalidOriginatorMismatch,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bgp_packet::{Afi, As4Path, As4Segment, FlowspecOp};
    use std::collections::VecDeque;

    fn v4_dst(nlri: &str) -> FlowspecNlri {
        FlowspecNlri::new(
            Afi::Ip,
            vec![FlowspecComponent::DestinationPrefix(FlowspecPrefix::V4(
                nlri.parse().unwrap(),
            ))],
        )
    }

    #[test]
    fn dest_ipnet_v4() {
        let nlri = v4_dst("10.0.0.0/24");
        assert_eq!(dest_ipnet(&nlri), Some("10.0.0.0/24".parse().unwrap()));
        assert!(has_dest_prefix(&nlri));
    }

    #[test]
    fn dest_ipnet_v6_offset_zero() {
        let nlri = FlowspecNlri::new(
            Afi::Ip6,
            vec![FlowspecComponent::DestinationPrefix(FlowspecPrefix::V6 {
                length: 64,
                offset: 0,
                pattern: "2001:db8::".parse::<Ipv6Addr>().unwrap().octets()[..8].to_vec(),
            })],
        );
        assert_eq!(dest_ipnet(&nlri), Some("2001:db8::/64".parse().unwrap()));
    }

    #[test]
    fn dest_ipnet_v6_offset_nonzero_is_none() {
        let nlri = FlowspecNlri::new(
            Afi::Ip6,
            vec![FlowspecComponent::DestinationPrefix(FlowspecPrefix::V6 {
                length: 128,
                offset: 64,
                pattern: vec![0, 0, 0, 0, 0, 0, 0, 1],
            })],
        );
        assert!(has_dest_prefix(&nlri));
        assert_eq!(dest_ipnet(&nlri), None);
    }

    #[test]
    fn no_dest_prefix_when_only_port_component() {
        let nlri = FlowspecNlri::new(
            Afi::Ip,
            vec![FlowspecComponent::DestinationPort(vec![
                FlowspecOp::numeric(false, false, false, true, 80),
            ])],
        );
        assert!(!has_dest_prefix(&nlri));
    }

    fn attr_with_segs(segs: Vec<As4Segment>) -> BgpAttr {
        BgpAttr {
            aspath: Some(As4Path {
                segs: segs.into_iter().collect::<VecDeque<_>>(),
                length: 0,
            }),
            ..Default::default()
        }
    }

    #[test]
    fn aspath_local_empty_is_true() {
        // Default attr carries an empty AS_PATH ⇒ b.2 holds.
        assert!(aspath_local(&BgpAttr::default()));
        assert!(aspath_local(&attr_with_segs(vec![])));
    }

    #[test]
    fn aspath_local_confed_only_is_true() {
        let attr = attr_with_segs(vec![As4Segment {
            typ: AS_CONFED_SEQ,
            asn: vec![65001],
        }]);
        assert!(aspath_local(&attr));
    }

    #[test]
    fn aspath_local_with_real_as_is_false() {
        let attr = attr_with_segs(vec![As4Segment {
            typ: bgp_packet::AS_SEQ,
            asn: vec![65001],
        }]);
        assert!(!aspath_local(&attr));
    }
}
