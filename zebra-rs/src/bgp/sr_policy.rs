//! BGP SR Policy (SAFI 73) headend-consumer database.
//!
//! Received SR Policy NLRI (RFC 9830) plus the candidate-path content
//! carried in the Tunnel Encapsulation attribute (Tunnel-Type 15) are
//! decoded into typed [`bgp_packet::SrPolicyTlvs`] and folded into this
//! database, keyed by the policy identity `<color, endpoint>`
//! (RFC 9256 §2.1). Within each policy, candidate paths are keyed by
//! `<protocol-origin, originator, discriminator>` (RFC 9256 §2.4) and the
//! active path is chosen by the RFC 9256 §2.9 selection ladder.
//!
//! This is control-plane only: it selects and exposes the active path for
//! `show`, but does not install anything in the dataplane or steer
//! traffic yet. The receive plumbing (usability filter, attribute
//! decode) lives in `route.rs`; this module owns the data model and the
//! selection algorithm so they stay unit-testable.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};

use bgp_packet::{
    BgpAttr, BindingSid, CommunityValue, ExtCommunitySubType, SegmentList, SrPolicyTlvs,
    Srv6BindingSid,
};

/// Protocol-Origin value for a BGP-distributed SR Policy candidate path
/// (RFC 9256 §2.3, Table 1).
pub const PROTOCOL_ORIGIN_BGP: u8 = 20;

/// RFC 9256 default Preference when the Preference sub-TLV is absent.
const DEFAULT_PREFERENCE: u32 = 100;
/// RFC 9256 default Priority when the Priority sub-TLV is absent.
const DEFAULT_PRIORITY: u8 = 128;

/// SR Policy identity (RFC 9256 §2.1). The endpoint's address family is
/// the NLRI AFI; a null endpoint (`0.0.0.0` / `::`) is a color-only
/// policy.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SrPolicyKey {
    pub color: u32,
    pub endpoint: IpAddr,
}

/// Candidate-path identity (RFC 9256 §2.4). For a BGP-sourced path the
/// discriminator is the NLRI Distinguisher and the protocol-origin is
/// [`PROTOCOL_ORIGIN_BGP`].
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CandidatePathKey {
    pub protocol_origin: u8,
    /// `<ASN, node-address>` — the originating BGP speaker.
    pub originator: (u32, IpAddr),
    pub discriminator: u32,
}

/// A candidate path learned for a policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandidatePath {
    pub key: CandidatePathKey,
    /// Index of the peer that advertised this path (used to scope
    /// withdrawals — the originator alone is not always reconstructable
    /// from a withdraw).
    pub peer: usize,
    pub preference: u32,
    pub priority: u8,
    pub binding_sid: Option<BindingSid>,
    pub srv6_binding_sid: Option<Srv6BindingSid>,
    pub enlp: Option<u8>,
    pub segment_lists: Vec<SegmentList>,
    pub policy_name: Option<String>,
    pub cp_name: Option<String>,
    /// Codec/structural validity. v1: at least one segment list, each
    /// with at least one segment. (Dataplane resolution is a later
    /// phase.)
    pub valid: bool,
}

/// One SR Policy and its candidate paths.
#[derive(Clone, Debug, Default)]
pub struct SrPolicy {
    pub candidates: BTreeMap<CandidatePathKey, CandidatePath>,
    /// Active candidate path (RFC 9256 §2.9), if any valid path exists.
    pub active: Option<CandidatePathKey>,
}

/// The SR Policy database (one per BGP instance, lives on the Loc-RIB).
#[derive(Clone, Debug, Default)]
pub struct SrPolicyDb {
    pub policies: BTreeMap<SrPolicyKey, SrPolicy>,
}

impl SrPolicyDb {
    /// Insert or replace a candidate path and re-run active selection.
    pub fn insert(&mut self, key: SrPolicyKey, cp: CandidatePath) {
        let policy = self.policies.entry(key).or_default();
        let prev = policy.active.clone();
        policy.candidates.insert(cp.key.clone(), cp);
        policy.active = select_active(&policy.candidates, prev.as_ref());
    }

    /// Remove the candidate path advertised by `peer` for the NLRI
    /// `<color, endpoint, discriminator>` and re-run selection. Drops the
    /// whole policy when its last candidate is withdrawn.
    pub fn withdraw(&mut self, color: u32, endpoint: IpAddr, discriminator: u32, peer: usize) {
        let key = SrPolicyKey { color, endpoint };
        let Some(policy) = self.policies.get_mut(&key) else {
            return;
        };
        let prev = policy.active.clone();
        policy
            .candidates
            .retain(|k, cp| !(k.discriminator == discriminator && cp.peer == peer));
        if policy.candidates.is_empty() {
            self.policies.remove(&key);
        } else {
            policy.active = select_active(&policy.candidates, prev.as_ref());
        }
    }
}

/// RFC 9256 §2.9 active candidate-path selection. Among *valid* paths the
/// winner is, in order: highest Preference, then highest Protocol-Origin,
/// then the currently-active path (stability), then lowest Originator,
/// then highest Discriminator.
fn select_active(
    candidates: &BTreeMap<CandidatePathKey, CandidatePath>,
    current: Option<&CandidatePathKey>,
) -> Option<CandidatePathKey> {
    candidates
        .values()
        .filter(|cp| cp.valid)
        .max_by(|a, b| {
            a.preference
                .cmp(&b.preference)
                .then(a.key.protocol_origin.cmp(&b.key.protocol_origin))
                // prefer the incumbent on a tie (true sorts after false).
                .then((current == Some(&a.key)).cmp(&(current == Some(&b.key))))
                // lower originator wins → reverse the comparison.
                .then(b.key.originator.cmp(&a.key.originator))
                // higher discriminator wins.
                .then(a.key.discriminator.cmp(&b.key.discriminator))
        })
        .map(|cp| cp.key.clone())
}

/// Build a candidate path from decoded SR Policy TLVs. `originator` and
/// `discriminator` form the candidate-path key together with the BGP
/// protocol-origin.
pub fn candidate_path(
    tlvs: &SrPolicyTlvs,
    originator: (u32, IpAddr),
    discriminator: u32,
    peer: usize,
) -> CandidatePath {
    let valid = !tlvs.segment_lists.is_empty()
        && tlvs.segment_lists.iter().all(|sl| !sl.segments.is_empty());
    CandidatePath {
        key: CandidatePathKey {
            protocol_origin: PROTOCOL_ORIGIN_BGP,
            originator,
            discriminator,
        },
        peer,
        preference: tlvs.preference.unwrap_or(DEFAULT_PREFERENCE),
        priority: tlvs.priority.unwrap_or(DEFAULT_PRIORITY),
        binding_sid: tlvs.binding_sid.clone(),
        srv6_binding_sid: tlvs.srv6_binding_sid.clone(),
        enlp: tlvs.enlp,
        segment_lists: tlvs.segment_lists.clone(),
        policy_name: tlvs.policy_name.clone(),
        cp_name: tlvs.cp_name.clone(),
        valid,
    }
}

/// RFC 9830 §4.2 usability verdict for a received SR Policy update.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Usability {
    /// §4.2.1: neither NO_ADVERTISE nor an IPv4-address-format Route
    /// Target — treat as malformed, do not process.
    Malformed,
    /// §4.2.2: well-formed but no Route Target matches our BGP
    /// Identifier — valid (a reflector forwards it) but not consumed
    /// locally.
    NotUsable,
    /// Consumable: NO_ADVERTISE with no RT, or an RT matching our BGP
    /// Identifier.
    Usable,
}

/// Apply the RFC 9830 §4.2 distribution rules. `router_id` is the
/// receiver's BGP Identifier.
pub fn usability(attr: &BgpAttr, router_id: &Ipv4Addr) -> Usability {
    let no_advertise = attr
        .com
        .as_ref()
        .is_some_and(|com| com.contains(&CommunityValue::NO_ADVERTISE.value()));

    let ipv4_rts = ipv4_route_targets(attr);

    if !no_advertise && ipv4_rts.is_empty() {
        return Usability::Malformed;
    }
    if ipv4_rts.is_empty() {
        // NO_ADVERTISE with no Route Target → usable.
        return Usability::Usable;
    }
    if ipv4_rts.iter().any(|rt| rt == router_id) {
        Usability::Usable
    } else {
        Usability::NotUsable
    }
}

/// Collect the IPv4 address portion of every IPv4-address-format Route
/// Target extended community (RFC 4360 §4 type 0x01, sub-type Route
/// Target). These are the RTs RFC 9830 §4.2 matches against the BGP
/// Identifier.
fn ipv4_route_targets(attr: &BgpAttr) -> Vec<Ipv4Addr> {
    // Transitive IPv4-Address-Specific extended community (high type 0x01).
    const EXT_TYPE_IPV4: u8 = 0x01;
    let mut out = Vec::new();
    if let Some(ecom) = &attr.ecom {
        for eval in ecom.0.iter() {
            if eval.high_type == EXT_TYPE_IPV4
                && eval.low_type == ExtCommunitySubType::RouteTarget as u8
            {
                out.push(Ipv4Addr::new(
                    eval.val[0],
                    eval.val[1],
                    eval.val[2],
                    eval.val[3],
                ));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use bgp_packet::Segment;

    fn endpoint(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn cp(proto: u8, originator_ip: &str, disc: u32, pref: u32, valid: bool) -> CandidatePath {
        CandidatePath {
            key: CandidatePathKey {
                protocol_origin: proto,
                originator: (65000, endpoint(originator_ip)),
                discriminator: disc,
            },
            peer: 1,
            preference: pref,
            priority: DEFAULT_PRIORITY,
            binding_sid: None,
            srv6_binding_sid: None,
            enlp: None,
            segment_lists: vec![],
            policy_name: None,
            cp_name: None,
            valid,
        }
    }

    fn select(
        cands: &[CandidatePath],
        current: Option<&CandidatePathKey>,
    ) -> Option<CandidatePathKey> {
        let map: BTreeMap<_, _> = cands.iter().map(|c| (c.key.clone(), c.clone())).collect();
        select_active(&map, current)
    }

    #[test]
    fn selection_skips_invalid() {
        let invalid_high = cp(20, "10.0.0.1", 1, 300, false);
        let valid_low = cp(20, "10.0.0.2", 2, 100, true);
        let win = select(&[invalid_high, valid_low.clone()], None).unwrap();
        assert_eq!(win, valid_low.key);
    }

    #[test]
    fn selection_prefers_higher_preference() {
        let lo = cp(20, "10.0.0.1", 1, 100, true);
        let hi = cp(20, "10.0.0.2", 2, 200, true);
        assert_eq!(select(&[lo, hi.clone()], None).unwrap(), hi.key);
    }

    #[test]
    fn selection_breaks_pref_tie_by_protocol_origin() {
        // Config (30) outranks BGP (20) at equal preference.
        let bgp = cp(20, "10.0.0.1", 1, 200, true);
        let cfg = cp(30, "10.0.0.2", 2, 200, true);
        assert_eq!(select(&[bgp, cfg.clone()], None).unwrap(), cfg.key);
    }

    #[test]
    fn selection_prefers_incumbent_on_tie() {
        // Same pref + proto + ... differ only by originator, so the lower
        // originator would win — but the incumbent rung comes first.
        let a = cp(20, "10.0.0.1", 1, 200, true); // lower originator
        let b = cp(20, "10.0.0.9", 1, 200, true); // higher originator
        // Without an incumbent, lower originator (a) wins.
        assert_eq!(select(&[a.clone(), b.clone()], None).unwrap(), a.key);
        // With b installed, b is retained despite the higher originator.
        assert_eq!(select(&[a, b.clone()], Some(&b.key)).unwrap(), b.key);
    }

    #[test]
    fn selection_breaks_by_lower_originator_then_higher_discriminator() {
        let lower_orig = cp(20, "10.0.0.1", 1, 200, true);
        let higher_orig = cp(20, "10.0.0.9", 5, 200, true);
        assert_eq!(
            select(&[lower_orig.clone(), higher_orig], None).unwrap(),
            lower_orig.key
        );

        // Same originator → higher discriminator wins.
        let d1 = cp(20, "10.0.0.1", 1, 200, true);
        let d9 = cp(20, "10.0.0.1", 9, 200, true);
        assert_eq!(select(&[d1, d9.clone()], None).unwrap(), d9.key);
    }

    #[test]
    fn db_insert_select_and_withdraw() {
        let mut db = SrPolicyDb::default();
        let key = SrPolicyKey {
            color: 100,
            endpoint: endpoint("10.0.0.9"),
        };
        let mut a = cp(20, "10.0.0.1", 1, 100, true);
        a.peer = 1;
        let mut b = cp(20, "10.0.0.2", 2, 200, true);
        b.peer = 2;
        db.insert(key.clone(), a.clone());
        db.insert(key.clone(), b.clone());
        assert_eq!(db.policies[&key].active.as_ref(), Some(&b.key));

        // Withdraw the winner → fall back to a.
        db.withdraw(100, endpoint("10.0.0.9"), 2, 2);
        assert_eq!(db.policies[&key].active.as_ref(), Some(&a.key));

        // Withdraw the last candidate → policy gone.
        db.withdraw(100, endpoint("10.0.0.9"), 1, 1);
        assert!(!db.policies.contains_key(&key));
    }

    #[test]
    fn invalid_only_policy_has_no_active() {
        let mut db = SrPolicyDb::default();
        let key = SrPolicyKey {
            color: 7,
            endpoint: endpoint("::"),
        };
        db.insert(key.clone(), cp(20, "10.0.0.1", 1, 100, false));
        assert!(db.policies[&key].active.is_none());
    }

    #[test]
    fn candidate_path_validity_tracks_segment_lists() {
        let mut tlvs = SrPolicyTlvs {
            preference: Some(200),
            ..Default::default()
        };
        // No segment lists → invalid; defaults applied.
        let cp0 = candidate_path(&tlvs, (65000, endpoint("10.0.0.1")), 1, 3);
        assert!(!cp0.valid);
        assert_eq!(cp0.preference, 200);
        assert_eq!(cp0.priority, DEFAULT_PRIORITY);
        assert_eq!(cp0.key.protocol_origin, PROTOCOL_ORIGIN_BGP);

        // One non-empty segment list → valid.
        tlvs.segment_lists.push(SegmentList {
            weight: None,
            segments: vec![Segment::TypeA {
                flags: 0,
                label: 16001,
            }],
        });
        let cp1 = candidate_path(&tlvs, (65000, endpoint("10.0.0.1")), 1, 3);
        assert!(cp1.valid);

        // An empty segment list makes the whole CP invalid.
        tlvs.segment_lists.push(SegmentList::default());
        let cp2 = candidate_path(&tlvs, (65000, endpoint("10.0.0.1")), 1, 3);
        assert!(!cp2.valid);
    }
}
