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
//! The active path is exposed via `show`, realized in the dataplane (an
//! SRv6 End.B6.Encaps local SID or an SR-MPLS Binding-SID ILM), and used
//! for automated steering of colour-tagged service routes (RFC 9256 §8).
//! The receive plumbing (usability filter, attribute decode), the RIB
//! installs, and the steering hook live in `route.rs`; this module owns
//! the data model, the §2.9 selection, and the install/steer *decisions*
//! so they stay unit-testable.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bgp_packet::{
    BgpAttr, BindingSid, ClusterList, Community, CommunityValue, ExtCommunity, ExtCommunitySubType,
    ExtCommunityValue, Origin, OriginatorId, Segment, SegmentList, SrPolicyNlri, SrPolicyTlvs,
    Srv6BindingSid, TunnelEncap,
};

use crate::config::{Args, ConfigOp};

use super::Bgp;

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
    /// SRv6 Binding SID currently programmed in the FIB for this policy
    /// (the active path's End.B6.Encaps install). Tracked so a change of
    /// active path tears the old one down.
    installed: Option<Srv6Bsid>,
    /// SR-MPLS Binding SID *label* currently programmed in the LFIB (the
    /// active path's ILM). `None` when no MPLS install is live. Unlike
    /// the SRv6 install (immediate), the MPLS ILM is gated on the
    /// endpoint resolving via NHT, so this is set by `mpls_reconcile`.
    installed_mpls: Option<u32>,
}

impl SrPolicy {
    /// The active candidate path, if one is selected.
    pub fn active_cp(&self) -> Option<&CandidatePath> {
        self.active.as_ref().and_then(|k| self.candidates.get(k))
    }

    /// Diff the active path's desired SRv6 Binding-SID install against
    /// what is currently programmed, update the record, and return the
    /// FIB delta the caller applies via the RIB.
    fn reconcile_fib(&mut self) -> SrPolicyFibDelta {
        let desired = self
            .active
            .as_ref()
            .and_then(|k| self.candidates.get(k))
            .and_then(srv6_bsid);
        let mut delta = SrPolicyFibDelta::default();
        match (&self.installed, &desired) {
            // Same Binding SID address: re-install only if its segment
            // list changed (SidAdd is a replace).
            (Some(prev), Some(new)) if prev.bsid == new.bsid => {
                if prev.segments != new.segments {
                    delta.install = Some(new.clone());
                }
            }
            (prev, new) => {
                delta.remove = prev.as_ref().map(|b| b.bsid);
                delta.install = new.clone();
            }
        }
        self.installed = desired;
        delta
    }
}

/// An SRv6 Binding SID install: the BSID address and the segment list
/// (Type-B SIDs in forwarding order) that End.B6.Encaps pushes onto it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Srv6Bsid {
    pub bsid: Ipv6Addr,
    pub segments: Vec<Ipv6Addr>,
}

/// The FIB change produced by an insert/withdraw. The SRv6 Binding SID
/// install is immediate (`remove`/`install`); the SR-MPLS ILM is gated on
/// NHT, so insert/withdraw only report `mpls_remove` — the LFIB label to
/// tear down when a withdraw drops a whole policy (the live install/update
/// is driven by `mpls_reconcile`). All `None` means no dataplane change.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SrPolicyFibDelta {
    pub remove: Option<Ipv6Addr>,
    pub install: Option<Srv6Bsid>,
    pub mpls_remove: Option<u32>,
}

/// An SR-MPLS Binding SID install: the incoming BSID label and the
/// segment list (Type-A labels, top of stack first) the ILM pushes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MplsBsid {
    pub bsid: u32,
    pub segments: Vec<u32>,
}

/// The all-SR-MPLS (Type A) label stack of a candidate path's first
/// segment list — the SID list a headend imposes when steering traffic
/// onto the policy or (with a Binding SID) when building the BSID ILM.
/// `None` unless the path is valid and its first segment list is
/// entirely Type-A.
fn mpls_segments(cp: &CandidatePath) -> Option<Vec<u32>> {
    if !cp.valid {
        return None;
    }
    let first = cp.segment_lists.first()?;
    let segments: Vec<u32> = first
        .segments
        .iter()
        .filter_map(|seg| match seg {
            Segment::TypeA { label, .. } => Some(*label),
            _ => None,
        })
        .collect();
    if segments.is_empty() || segments.len() != first.segments.len() {
        return None;
    }
    Some(segments)
}

/// The SR-MPLS Binding-SID install an active candidate path realizes, or
/// `None` if it isn't an installable SR-MPLS policy (not valid, no MPLS
/// Binding SID, or its first segment list isn't an all-Type-A list).
fn mpls_bsid(cp: &CandidatePath) -> Option<MplsBsid> {
    let bsid = match &cp.binding_sid {
        Some(BindingSid::MplsLabel(label)) => *label,
        _ => return None,
    };
    let segments = mpls_segments(cp)?;
    Some(MplsBsid { bsid, segments })
}

/// The LFIB change `mpls_reconcile` wants applied: remove an old BSID
/// label and/or install a new one. The install is realized by the caller
/// toward the endpoint's NHT-resolved next-hop.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MplsIlmAction {
    pub remove: Option<u32>,
    pub install: Option<MplsBsid>,
}

/// The SRv6 Binding-SID install an active candidate path realizes, or
/// `None` if it isn't an installable SRv6 policy (not valid, no SRv6
/// Binding SID, or its first segment list isn't an all-Type-B list).
fn srv6_bsid(cp: &CandidatePath) -> Option<Srv6Bsid> {
    if !cp.valid {
        return None;
    }
    let bsid = cp
        .srv6_binding_sid
        .as_ref()
        .map(|s| s.sid)
        .or(match &cp.binding_sid {
            Some(BindingSid::Srv6(addr)) => Some(*addr),
            _ => None,
        })?;
    let first = cp.segment_lists.first()?;
    let segments: Vec<Ipv6Addr> = first
        .segments
        .iter()
        .filter_map(|seg| match seg {
            Segment::TypeB { sid, .. } => Some(*sid),
            _ => None,
        })
        .collect();
    // Only an all-SRv6 (Type B) list maps to an End.B6.Encaps push; a
    // mixed or SR-MPLS list is out of scope here (an SR-MPLS Binding SID
    // is the later ILM phase).
    if segments.is_empty() || segments.len() != first.segments.len() {
        return None;
    }
    Some(Srv6Bsid { bsid, segments })
}

/// How the headend imposes an SR Policy on a colour-matched service
/// route (the `steering-mode` knob, zebra-bgp-sr-policy.yang). The wire
/// (SAFI 73 / Color extcomm) is unchanged either way; this only selects
/// the local forwarding encoding.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SteerMode {
    /// Impose the policy's explicit SID list inline on every steered
    /// route (RFC 9256 §8; the original behaviour, kept as the default).
    #[default]
    SegmentList,
    /// Impose only the policy's Binding SID; its own forwarding entry
    /// (the SR-MPLS ILM / SRv6 End.B6.Encaps SID) expands it into the
    /// segment list (RFC 9256 §8.5). Compresses the label stack and
    /// decouples steered routes from policy-path churn. Falls back to the
    /// inline SID list for a matched policy that advertises no BSID.
    BindingSid,
}

/// The SR Policy database (one per BGP instance, lives on the Loc-RIB).
#[derive(Clone, Debug, Default)]
pub struct SrPolicyDb {
    pub policies: BTreeMap<SrPolicyKey, SrPolicy>,
    /// Headend steering mode (`steering-mode` config). Applies to all
    /// colour steering; default keeps the inline SID-list behaviour.
    pub steer_mode: SteerMode,
}

impl SrPolicyDb {
    /// Insert or replace a candidate path, re-run active selection, and
    /// return the resulting FIB delta.
    pub fn insert(&mut self, key: SrPolicyKey, cp: CandidatePath) -> SrPolicyFibDelta {
        let policy = self.policies.entry(key).or_default();
        let prev = policy.active.clone();
        policy.candidates.insert(cp.key.clone(), cp);
        policy.active = select_active(&policy.candidates, prev.as_ref());
        policy.reconcile_fib()
    }

    /// Remove the candidate path advertised by `peer` for the NLRI
    /// `<color, endpoint, discriminator>`, re-run selection, and return
    /// the FIB delta. Drops the whole policy (tearing down any installed
    /// Binding SID) when its last candidate is withdrawn.
    /// Withdraw one candidate path (keyed by `discriminator` + originating
    /// `peer`). Returns `(removed, delta)`: `removed` is `true` only when a
    /// candidate was actually present and dropped — the caller reflects the
    /// withdrawal to RR peers only then, so a no-op withdraw (policy/candidate
    /// already absent) is not re-flooded into a reflection-cycle storm.
    pub fn withdraw(
        &mut self,
        color: u32,
        endpoint: IpAddr,
        discriminator: u32,
        peer: usize,
    ) -> (bool, SrPolicyFibDelta) {
        let key = SrPolicyKey { color, endpoint };
        let Some(policy) = self.policies.get_mut(&key) else {
            return (false, SrPolicyFibDelta::default());
        };
        let prev = policy.active.clone();
        let before = policy.candidates.len();
        policy
            .candidates
            .retain(|k, cp| !(k.discriminator == discriminator && cp.peer == peer));
        let removed = policy.candidates.len() != before;
        if policy.candidates.is_empty() {
            let remove = policy.installed.take().map(|b| b.bsid);
            let mpls_remove = policy.installed_mpls.take();
            self.policies.remove(&key);
            (
                removed,
                SrPolicyFibDelta {
                    remove,
                    install: None,
                    mpls_remove,
                },
            )
        } else {
            policy.active = select_active(&policy.candidates, prev.as_ref());
            (removed, policy.reconcile_fib())
        }
    }

    /// Whether the policy's active path is an installable SR-MPLS policy
    /// (so its endpoint should be NHT-tracked for the ILM install).
    pub fn wants_mpls(&self, color: u32, endpoint: IpAddr) -> bool {
        self.policies
            .get(&SrPolicyKey { color, endpoint })
            .and_then(|p| p.active_cp())
            .and_then(mpls_bsid)
            .is_some()
    }

    /// Steer a service route carrying Color `color` and next-hop
    /// `endpoint` onto an SR-MPLS policy: return the active path's SID
    /// list (the label stack to impose), applying the RFC 9256 §8.8.1
    /// CO-bit endpoint fallback. `None` when no matching SR-MPLS policy
    /// has a usable Type-A path.
    ///
    /// CO bits (RFC 9830 §3): `00` exact `<color, endpoint>` only; `01`
    /// also falls back to the color-only (null-endpoint) policy; `10`
    /// additionally to any policy with this color; `11` is reserved and
    /// treated as `00`. The same-AF / any-AF sub-ordering of §8.8.1 is
    /// simplified to "same-family null endpoint, then any endpoint".
    pub fn steer_mpls(&self, color: u32, endpoint: IpAddr, co_bits: u8) -> Option<Vec<u32>> {
        self.steer_lookup(color, endpoint, co_bits, |p| {
            p.active_cp().and_then(mpls_segments)
        })
    }

    /// Steer to an SR-MPLS policy's *Binding SID* (a single label) instead
    /// of its expanded SID list — the `binding-sid` steering mode. The
    /// BSID's ILM (installed, NHT-gated, by [`Self::mpls_reconcile`])
    /// swaps the single label for the real stack. Returns the BSID label
    /// only when that ILM is actually installed for the active path, so a
    /// steered route never pushes a label with no LFIB entry (a not-yet-
    /// installed BSID falls through to inline steering — reachable, just
    /// uncompressed — until the next re-eval). Same CO-bit endpoint
    /// fallback as [`Self::steer_mpls`].
    pub fn steer_mpls_bsid(&self, color: u32, endpoint: IpAddr, co_bits: u8) -> Option<u32> {
        self.steer_lookup(color, endpoint, co_bits, |p| {
            let active = p.active_cp().and_then(mpls_bsid)?.bsid;
            p.installed_mpls.filter(|inst| *inst == active)
        })
    }

    /// Steer to an SRv6 policy's *Binding SID* (a single SID to H.Encap
    /// toward) instead of its expanded segment list — the `binding-sid`
    /// steering mode. The BSID's End.B6.Encaps local SID (installed
    /// immediately by [`SrPolicy::reconcile_fib`]) expands it. Returns the
    /// currently-installed BSID address, so it tracks the dataplane state.
    /// Same CO-bit endpoint fallback as [`Self::steer_mpls`].
    pub fn steer_srv6_bsid(&self, color: u32, endpoint: IpAddr, co_bits: u8) -> Option<Ipv6Addr> {
        self.steer_lookup(color, endpoint, co_bits, |p| {
            p.installed.as_ref().map(|b| b.bsid)
        })
    }

    /// Shared CO-bit endpoint-fallback ladder (RFC 9256 §8.8.1 / RFC 9830
    /// §3) for the steer helpers. Try the exact `<color, endpoint>`, then
    /// (CO≥01) the same-family null-endpoint colour-only policy, then
    /// (CO≥10) any endpoint of the colour; `11` is reserved and treated as
    /// `00`. `f` extracts the steering target from a matched policy; the
    /// first policy that yields `Some` wins.
    fn steer_lookup<T>(
        &self,
        color: u32,
        endpoint: IpAddr,
        co_bits: u8,
        f: impl Fn(&SrPolicy) -> Option<T>,
    ) -> Option<T> {
        if let Some(v) = self
            .policies
            .get(&SrPolicyKey { color, endpoint })
            .and_then(&f)
        {
            return Some(v);
        }
        let co = if co_bits == 0b11 { 0 } else { co_bits };
        if co >= 0b01 {
            let null = match endpoint {
                IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            };
            if let Some(v) = self
                .policies
                .get(&SrPolicyKey {
                    color,
                    endpoint: null,
                })
                .and_then(&f)
            {
                return Some(v);
            }
        }
        if co >= 0b10 {
            // SrPolicyKey is color-major (derived Ord), so one color's
            // policies are a contiguous range.
            let from = SrPolicyKey {
                color,
                endpoint: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            };
            for (key, policy) in self.policies.range(from..) {
                if key.color != color {
                    break;
                }
                if let Some(v) = f(policy) {
                    return Some(v);
                }
            }
        }
        None
    }

    /// Reconcile the SR-MPLS Binding-SID ILM for a *live* policy against
    /// its active path and the endpoint's reachability, updating the
    /// recorded install. Returns the LFIB action for the caller to apply
    /// (it owns the resolved next-hop). A no-op (and no install) when the
    /// policy is absent — a removed policy's teardown rides
    /// `SrPolicyFibDelta::mpls_remove` instead. `reachable` is whether the
    /// endpoint resolved via NHT.
    pub fn mpls_reconcile(
        &mut self,
        color: u32,
        endpoint: IpAddr,
        reachable: bool,
    ) -> MplsIlmAction {
        let key = SrPolicyKey { color, endpoint };
        let Some(policy) = self.policies.get_mut(&key) else {
            return MplsIlmAction::default();
        };
        let desired = policy.active_cp().and_then(mpls_bsid);
        match desired {
            Some(bsid) if reachable => {
                // Replace whenever reachable (the resolved next-hop or the
                // label stack may have changed); drop a stale label first.
                let remove = policy.installed_mpls.filter(|old| *old != bsid.bsid);
                policy.installed_mpls = Some(bsid.bsid);
                MplsIlmAction {
                    remove,
                    install: Some(bsid),
                }
            }
            _ => MplsIlmAction {
                remove: policy.installed_mpls.take(),
                install: None,
            },
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

// =======================================================================
// Originator: locally-configured SR Policies advertised as SAFI 73.
// =======================================================================

/// Locally-configured SR Policies (zebra-bgp-sr-policy.yang), keyed by
/// the configuration name.
#[derive(Clone, Debug, Default)]
pub struct LocalSrPolicies {
    pub policies: BTreeMap<String, LocalSrPolicy>,
}

/// One configured local SR Policy. Fields are `Option` because the
/// config arrives leaf-by-leaf; a policy is only advertised once
/// [`LocalSrPolicy::advert`] can build a complete NLRI + attribute.
#[derive(Clone, Debug, Default)]
pub struct LocalSrPolicy {
    pub color: Option<u32>,
    pub endpoint: Option<IpAddr>,
    pub preference: Option<u32>,
    pub binding_sid_label: Option<u32>,
    pub binding_sid_sid: Option<Ipv6Addr>,
    pub route_target: Option<Ipv4Addr>,
    pub segments: BTreeMap<u32, LocalSegment>,
}

/// One explicit segment of a local policy (exactly one of the two is set
/// for a usable segment).
#[derive(Clone, Debug, Default)]
pub struct LocalSegment {
    pub mpls_label: Option<u32>,
    pub srv6_sid: Option<Ipv6Addr>,
}

impl LocalSrPolicy {
    /// The NLRI for this policy, if its color and endpoint are set. The
    /// distinguisher is the originating router-id (RFC 9830 §2.1 — it
    /// only needs to make the NLRI unique within `<color, endpoint>`).
    pub fn nlri(&self, router_id: Ipv4Addr) -> Option<SrPolicyNlri> {
        Some(SrPolicyNlri {
            id: 0,
            distinguisher: u32::from(router_id),
            color: self.color?,
            endpoint: self.endpoint?,
        })
    }

    /// Build the `(NLRI, attribute)` to advertise this policy, or `None`
    /// if it isn't complete (needs color, endpoint, and an all-one-type
    /// segment list). The attribute carries the Tunnel-Type-15 encoding
    /// plus, per RFC 9830 §4.1, an IPv4-address Route Target when one is
    /// configured, else the NO_ADVERTISE community.
    pub fn advert(&self, router_id: Ipv4Addr) -> Option<(SrPolicyNlri, BgpAttr)> {
        let nlri = self.nlri(router_id)?;

        // Segments, in ascending index order; reject mixed / empty lists.
        let mut segments = Vec::new();
        for seg in self.segments.values() {
            if let Some(label) = seg.mpls_label {
                segments.push(Segment::TypeA { flags: 0, label });
            } else {
                let sid = seg.srv6_sid?;
                segments.push(Segment::TypeB {
                    flags: 0,
                    sid,
                    structure: None,
                });
            }
        }
        if segments.is_empty() {
            return None;
        }
        let has_a = segments.iter().any(|s| matches!(s, Segment::TypeA { .. }));
        let has_b = segments.iter().any(|s| matches!(s, Segment::TypeB { .. }));
        if has_a && has_b {
            return None;
        }

        let tlvs = SrPolicyTlvs {
            preference: Some(self.preference.unwrap_or(DEFAULT_PREFERENCE)),
            binding_sid: self.binding_sid_label.map(BindingSid::MplsLabel),
            srv6_binding_sid: self.binding_sid_sid.map(|sid| Srv6BindingSid {
                flags: 0,
                sid,
                structure: None,
            }),
            enlp: None,
            priority: None,
            segment_lists: vec![SegmentList {
                weight: None,
                segments,
            }],
            policy_name: None,
            cp_name: None,
            unknown: Vec::new(),
        };

        let mut attr = BgpAttr {
            origin: Some(Origin::Igp),
            tunnel_encap: Some(TunnelEncap {
                tunnels: vec![tlvs.to_tunnel()],
            }),
            ..Default::default()
        };
        // RFC 9830 §4.1: a Route Target identifies the intended
        // headend(s); without one, NO_ADVERTISE keeps the policy local.
        match self.route_target {
            Some(rt) => attr.ecom = Some(ExtCommunity::from([ipv4_route_target(rt)])),
            None => attr.com = Some(Community::from([CommunityValue::NO_ADVERTISE.value()])),
        }
        Some((nlri, attr))
    }
}

/// An IPv4-address-format Route Target extended community (RFC 4360 §4
/// type 0x01, sub-type Route Target) with local-administrator 0.
fn ipv4_route_target(addr: Ipv4Addr) -> ExtCommunityValue {
    let mut val = [0u8; 6];
    val[0..4].copy_from_slice(&addr.octets());
    ExtCommunityValue {
        high_type: 0x01,
        low_type: ExtCommunitySubType::RouteTarget as u8,
        val,
    }
}

// --- config callbacks (zebra-bgp-sr-policy.yang) ---------------------

fn local_policy<'a>(bgp: &'a mut Bgp, name: &str) -> &'a mut LocalSrPolicy {
    bgp.local_rib
        .sr_policy_local
        .policies
        .entry(name.to_string())
        .or_default()
}

/// `set router bgp sr-policy steering-mode segment-list|binding-sid` —
/// choose how colour-matched service routes are steered onto a policy:
/// the whole SID list imposed inline (`segment-list`, the default), or
/// just the policy's Binding SID (`binding-sid`, RFC 9256 §8.5). This is
/// a consumer-side headend behaviour; it takes effect as steered routes
/// are (re)installed. `delete` restores the default.
pub fn config_srp_steering_mode(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let mode = match op {
        ConfigOp::Set => match args.string()?.as_str() {
            "binding-sid" => SteerMode::BindingSid,
            _ => SteerMode::SegmentList,
        },
        ConfigOp::Delete => SteerMode::SegmentList,
        _ => return Some(()),
    };
    bgp.local_rib.sr_policy.steer_mode = mode;
    Some(())
}

/// `set router bgp sr-policy policy <NAME>` — ensure the entry exists;
/// `delete` removes it and withdraws any advertised NLRI.
pub fn config_srp_policy(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    match op {
        ConfigOp::Set => {
            local_policy(bgp, &name);
        }
        ConfigOp::Delete => {
            if let Some(policy) = bgp.local_rib.sr_policy_local.policies.remove(&name)
                && let Some(nlri) = policy.nlri(bgp.router_id)
            {
                super::route::srpolicy_origin_withdraw(bgp, nlri);
            }
        }
        _ => {}
    }
    Some(())
}

/// Generic leaf setter: mutate the named policy, then re-sync the
/// dataplane advertisement.
fn config_srp_leaf<F>(bgp: &mut Bgp, name: &str, f: F) -> Option<()>
where
    F: FnOnce(&mut LocalSrPolicy),
{
    f(local_policy(bgp, name));
    super::route::srpolicy_origin_sync(bgp, name);
    Some(())
}

pub fn config_srp_color(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let value = op.is_set().then(|| args.u32()).flatten();
    config_srp_leaf(bgp, &name, |p| p.color = value)
}

pub fn config_srp_endpoint(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let value = op.is_set().then(|| args.addr()).flatten();
    config_srp_leaf(bgp, &name, |p| p.endpoint = value)
}

pub fn config_srp_preference(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let value = op.is_set().then(|| args.u32()).flatten();
    config_srp_leaf(bgp, &name, |p| p.preference = value)
}

pub fn config_srp_binding_sid_label(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let value = op.is_set().then(|| args.u32()).flatten();
    config_srp_leaf(bgp, &name, |p| p.binding_sid_label = value)
}

pub fn config_srp_binding_sid_sid(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let value = op.is_set().then(|| args.v6addr()).flatten();
    config_srp_leaf(bgp, &name, |p| p.binding_sid_sid = value)
}

pub fn config_srp_route_target(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let value = op.is_set().then(|| args.v4addr()).flatten();
    config_srp_leaf(bgp, &name, |p| p.route_target = value)
}

/// `set router bgp sr-policy policy <NAME> segment <INDEX>` presence.
pub fn config_srp_segment(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let index = args.u32()?;
    match op {
        ConfigOp::Set => {
            local_policy(bgp, &name).segments.entry(index).or_default();
        }
        ConfigOp::Delete => {
            local_policy(bgp, &name).segments.remove(&index);
        }
        _ => {}
    }
    super::route::srpolicy_origin_sync(bgp, &name);
    Some(())
}

pub fn config_srp_segment_mpls_label(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let index = args.u32()?;
    let value = op.is_set().then(|| args.u32()).flatten();
    local_policy(bgp, &name)
        .segments
        .entry(index)
        .or_default()
        .mpls_label = value;
    super::route::srpolicy_origin_sync(bgp, &name);
    Some(())
}

pub fn config_srp_segment_srv6_sid(bgp: &mut Bgp, mut args: Args, op: ConfigOp) -> Option<()> {
    let name = args.string()?;
    let index = args.u32()?;
    let value = op.is_set().then(|| args.v6addr()).flatten();
    local_policy(bgp, &name)
        .segments
        .entry(index)
        .or_default()
        .srv6_sid = value;
    super::route::srpolicy_origin_sync(bgp, &name);
    Some(())
}

// =======================================================================
// Route-reflector pass-through: reflect received SR Policies (SAFI 73).
// =======================================================================

/// The attribute to use when reflecting a received SR Policy update to
/// one destination peer, or `None` if it must not be reflected to that
/// peer.
///
/// - RFC 9830 §4.1: a policy carrying NO_ADVERTISE is never propagated.
/// - RFC 4456: an iBGP-learned policy is reflected to an iBGP peer only
///   if that peer is a route-reflector client.
/// - On an iBGP→iBGP reflection the ORIGINATOR_ID is stamped (with the
///   original advertiser's router-id if absent) and the local router-id
///   is prepended to the CLUSTER_LIST.
/// - On an eBGP egress the iBGP-only attributes are stripped: ORIGINATOR_ID
///   and CLUSTER_LIST (RFC 4456: non-transitive, intra-AS-only) and LOCAL_PREF
///   (RFC 4271 §5.1.5: never sent to external peers).
pub fn reflect_attr(
    attr: &BgpAttr,
    source_ibgp: bool,
    source_router_id: Ipv4Addr,
    dest_ibgp: bool,
    dest_is_client: bool,
    our_router_id: Ipv4Addr,
) -> Option<BgpAttr> {
    if attr
        .com
        .as_ref()
        .is_some_and(|c| c.contains(&CommunityValue::NO_ADVERTISE.value()))
    {
        return None;
    }
    if source_ibgp && dest_ibgp && !dest_is_client {
        return None;
    }
    let mut out = attr.clone();
    if source_ibgp && dest_ibgp {
        if out.originator_id.is_none() {
            out.originator_id = Some(OriginatorId::new(source_router_id));
        }
        match out.cluster_list {
            Some(ref mut cl) => cl.list.insert(0, our_router_id),
            None => {
                let mut cl = ClusterList::new();
                cl.list.push(our_router_id);
                out.cluster_list = Some(cl);
            }
        }
    } else if !dest_ibgp {
        // Strip the iBGP-only attributes before reflecting to an eBGP peer (an
        // iBGP-learned policy carries them through the cloned attr):
        // ORIGINATOR_ID / CLUSTER_LIST are non-transitive intra-AS attributes
        // (RFC 4456) and LOCAL_PREF must not cross an AS boundary (RFC 4271
        // §5.1.5).
        out.originator_id = None;
        out.cluster_list = None;
        out.local_pref = None;
    }
    Some(out)
}

/// Whether a received SR Policy withdrawal should be reflected to a
/// destination peer (RFC 4456 client rule; the NO_ADVERTISE check is
/// moot for a withdraw — reflecting a never-advertised withdraw is a
/// harmless no-op on the peer).
pub fn reflect_withdraw_to(source_ibgp: bool, dest_ibgp: bool, dest_is_client: bool) -> bool {
    !(source_ibgp && dest_ibgp && !dest_is_client)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn v6(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    /// A valid SRv6 candidate path: an SRv6 Binding SID plus a one-hop
    /// Type-B segment list.
    fn srv6_cp(disc: u32, pref: u32, peer: usize, bsid: &str, seg: &str) -> CandidatePath {
        let mut c = cp(20, "10.0.0.1", disc, pref, true);
        c.peer = peer;
        c.srv6_binding_sid = Some(Srv6BindingSid {
            flags: 0,
            sid: v6(bsid),
            structure: None,
        });
        c.segment_lists = vec![SegmentList {
            weight: None,
            segments: vec![Segment::TypeB {
                flags: 0,
                sid: v6(seg),
                structure: None,
            }],
        }];
        c
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

    /// The `removed` flag drives the reflection guard: it is `true` only when
    /// a candidate was actually dropped. A no-op withdraw (absent policy,
    /// absent candidate, or re-withdraw) returns `false`, so the caller does
    /// not reflect it — breaking the SR-Policy withdraw ping-pong.
    #[test]
    fn withdraw_removed_flag_gates_reflection() {
        let mut db = SrPolicyDb::default();
        let key = SrPolicyKey {
            color: 100,
            endpoint: endpoint("10.0.0.9"),
        };
        let mut a = cp(20, "10.0.0.1", 1, 100, true);
        a.peer = 1;
        db.insert(key.clone(), a.clone());

        // Absent policy color → no-op.
        let (removed, _) = db.withdraw(999, endpoint("10.0.0.9"), 1, 1);
        assert!(!removed, "withdraw of an absent policy removes nothing");
        // Policy exists but not this (discriminator, peer) → no-op.
        let (removed, _) = db.withdraw(100, endpoint("10.0.0.9"), 7, 7);
        assert!(!removed, "withdraw of an absent candidate removes nothing");
        // The real candidate → removed.
        let (removed, _) = db.withdraw(100, endpoint("10.0.0.9"), 1, 1);
        assert!(removed, "withdraw of a present candidate removes it");
        // Re-withdraw the now-absent candidate → no-op (breaks the storm).
        let (removed, _) = db.withdraw(100, endpoint("10.0.0.9"), 1, 1);
        assert!(
            !removed,
            "re-withdraw of an already-absent candidate is a no-op"
        );
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

    #[test]
    fn srv6_policy_installs_binding_sid() {
        let mut db = SrPolicyDb::default();
        let key = SrPolicyKey {
            color: 100,
            endpoint: endpoint("10.0.0.9"),
        };
        let delta = db.insert(key, srv6_cp(1, 100, 1, "fc00:0:9::100", "fc00:0:2::"));
        assert_eq!(delta.remove, None);
        let install = delta.install.expect("install");
        assert_eq!(install.bsid, v6("fc00:0:9::100"));
        assert_eq!(install.segments, vec![v6("fc00:0:2::")]);
    }

    #[test]
    fn better_path_swaps_binding_sid_then_falls_back() {
        let mut db = SrPolicyDb::default();
        let ep = endpoint("10.0.0.9");
        let key = SrPolicyKey {
            color: 100,
            endpoint: ep,
        };
        db.insert(key.clone(), srv6_cp(1, 100, 1, "fc00:0:9::1", "fc00:0:2::"));
        // A higher-preference path swaps the installed Binding SID.
        let delta = db.insert(key, srv6_cp(2, 200, 2, "fc00:0:9::2", "fc00:0:3::"));
        assert_eq!(delta.remove, Some(v6("fc00:0:9::1")));
        assert_eq!(delta.install.unwrap().bsid, v6("fc00:0:9::2"));
        // Withdrawing the winner falls back to the remaining path's BSID.
        let (_, delta) = db.withdraw(100, ep, 2, 2);
        assert_eq!(delta.remove, Some(v6("fc00:0:9::2")));
        assert_eq!(delta.install.unwrap().bsid, v6("fc00:0:9::1"));
    }

    #[test]
    fn withdrawing_last_path_removes_binding_sid() {
        let mut db = SrPolicyDb::default();
        let ep = endpoint("10.0.0.9");
        let key = SrPolicyKey {
            color: 5,
            endpoint: ep,
        };
        db.insert(key.clone(), srv6_cp(1, 100, 1, "fc00:0:9::1", "fc00:0:2::"));
        let (_, delta) = db.withdraw(5, ep, 1, 1);
        assert_eq!(delta.remove, Some(v6("fc00:0:9::1")));
        assert_eq!(delta.install, None);
        assert!(!db.policies.contains_key(&key));
    }

    #[test]
    fn sr_mpls_or_no_bsid_does_not_install() {
        let mut db = SrPolicyDb::default();
        let key = SrPolicyKey {
            color: 7,
            endpoint: endpoint("10.0.0.9"),
        };
        // SR-MPLS (Type A) segment, no SRv6 Binding SID → no SRv6 install.
        let mut c = cp(20, "10.0.0.1", 1, 100, true);
        c.segment_lists = vec![SegmentList {
            weight: None,
            segments: vec![Segment::TypeA {
                flags: 0,
                label: 16001,
            }],
        }];
        assert_eq!(db.insert(key, c), SrPolicyFibDelta::default());
    }

    /// A valid SR-MPLS candidate path: an MPLS Binding SID label plus a
    /// one-hop Type-A label stack.
    fn mpls_cp(disc: u32, pref: u32, peer: usize, bsid: u32, label: u32) -> CandidatePath {
        let mut c = cp(20, "10.0.0.1", disc, pref, true);
        c.peer = peer;
        c.binding_sid = Some(BindingSid::MplsLabel(bsid));
        c.segment_lists = vec![SegmentList {
            weight: None,
            segments: vec![Segment::TypeA { flags: 0, label }],
        }];
        c
    }

    #[test]
    fn mpls_reconcile_gates_install_on_reachability() {
        let mut db = SrPolicyDb::default();
        let ep = endpoint("10.0.0.9");
        let key = SrPolicyKey {
            color: 100,
            endpoint: ep,
        };
        db.insert(key, mpls_cp(1, 100, 1, 1000, 16001));

        // Endpoint unresolved → no install yet.
        assert_eq!(db.mpls_reconcile(100, ep, false), MplsIlmAction::default());
        // Endpoint resolves → install the BSID ILM.
        let action = db.mpls_reconcile(100, ep, true);
        assert_eq!(action.remove, None);
        assert_eq!(
            action.install,
            Some(MplsBsid {
                bsid: 1000,
                segments: vec![16001],
            })
        );
        // Endpoint goes unreachable → tear the ILM down.
        let action = db.mpls_reconcile(100, ep, false);
        assert_eq!(action.remove, Some(1000));
        assert_eq!(action.install, None);
    }

    #[test]
    fn mpls_reconcile_swaps_label_when_active_path_changes() {
        let mut db = SrPolicyDb::default();
        let ep = endpoint("10.0.0.9");
        let key = SrPolicyKey {
            color: 100,
            endpoint: ep,
        };
        db.insert(key.clone(), mpls_cp(1, 100, 1, 1000, 16001));
        assert_eq!(db.mpls_reconcile(100, ep, true).install.unwrap().bsid, 1000);
        // A higher-preference path with a different BSID label wins.
        db.insert(key, mpls_cp(2, 200, 2, 2000, 16002));
        let action = db.mpls_reconcile(100, ep, true);
        assert_eq!(action.remove, Some(1000));
        assert_eq!(action.install.unwrap().bsid, 2000);
    }

    #[test]
    fn withdrawing_mpls_policy_reports_label_to_remove() {
        let mut db = SrPolicyDb::default();
        let ep = endpoint("10.0.0.9");
        let key = SrPolicyKey {
            color: 9,
            endpoint: ep,
        };
        db.insert(key, mpls_cp(1, 100, 1, 1000, 16001));
        // Install it (records installed_mpls).
        assert!(db.mpls_reconcile(9, ep, true).install.is_some());
        // Withdrawing the last path reports the LFIB label to tear down.
        let (_, delta) = db.withdraw(9, ep, 1, 1);
        assert_eq!(delta.mpls_remove, Some(1000));
    }

    #[test]
    fn steer_mpls_exact_match() {
        let mut db = SrPolicyDb::default();
        let ep = endpoint("10.0.0.9");
        db.insert(
            SrPolicyKey {
                color: 100,
                endpoint: ep,
            },
            mpls_cp(1, 100, 1, 1000, 16001),
        );
        // Exact <color, endpoint> works regardless of CO bits.
        assert_eq!(db.steer_mpls(100, ep, 0), Some(vec![16001]));
        // Wrong color / wrong endpoint with CO=00 → no steer.
        assert_eq!(db.steer_mpls(200, ep, 0), None);
        assert_eq!(db.steer_mpls(100, endpoint("10.0.0.1"), 0), None);
    }

    #[test]
    fn steer_mpls_co_bit_fallback() {
        let mut db = SrPolicyDb::default();
        let nh = endpoint("10.0.0.9");
        // A color-only (null-endpoint) policy and an unrelated-endpoint one.
        db.insert(
            SrPolicyKey {
                color: 100,
                endpoint: endpoint("0.0.0.0"),
            },
            mpls_cp(1, 100, 1, 1000, 17001),
        );
        db.insert(
            SrPolicyKey {
                color: 200,
                endpoint: endpoint("10.0.0.5"),
            },
            mpls_cp(1, 100, 2, 2000, 18001),
        );
        // CO=00: no exact <100, 10.0.0.9> → no steer.
        assert_eq!(db.steer_mpls(100, nh, 0), None);
        // CO=01: falls back to the null-endpoint color-100 policy.
        assert_eq!(db.steer_mpls(100, nh, 0b01), Some(vec![17001]));
        // CO=10: also reaches any endpoint of color 200.
        assert_eq!(db.steer_mpls(200, nh, 0b10), Some(vec![18001]));
        // CO=01 for color 200 stays strict-or-null only → no match.
        assert_eq!(db.steer_mpls(200, nh, 0b01), None);
        // CO=11 is reserved → treated as 00 (exact only) → no match.
        assert_eq!(db.steer_mpls(100, nh, 0b11), None);
    }

    #[test]
    fn steer_mode_defaults_to_segment_list() {
        assert_eq!(SrPolicyDb::default().steer_mode, SteerMode::SegmentList);
    }

    #[test]
    fn steer_mpls_bsid_gated_on_installed_ilm() {
        let mut db = SrPolicyDb::default();
        let ep = endpoint("10.0.0.9");
        db.insert(
            SrPolicyKey {
                color: 100,
                endpoint: ep,
            },
            mpls_cp(1, 100, 1, 1000, 16001),
        );
        // The BSID ILM isn't installed yet (NHT-gated) → nothing to steer
        // to; the caller falls back to inline SID-list steering.
        assert_eq!(db.steer_mpls_bsid(100, ep, 0), None);
        // Once the endpoint resolves and the ILM installs, steer to the
        // single BSID label instead of the {16001} SID list.
        assert!(db.mpls_reconcile(100, ep, true).install.is_some());
        assert_eq!(db.steer_mpls_bsid(100, ep, 0), Some(1000));
        // The inline steer still yields the full stack (mode is a caller
        // choice; the DB exposes both).
        assert_eq!(db.steer_mpls(100, ep, 0), Some(vec![16001]));
        // Endpoint goes unreachable → ILM torn down → no BSID again.
        db.mpls_reconcile(100, ep, false);
        assert_eq!(db.steer_mpls_bsid(100, ep, 0), None);
    }

    #[test]
    fn steer_mpls_bsid_co_bit_fallback() {
        let mut db = SrPolicyDb::default();
        let nh = endpoint("10.0.0.9");
        let null = endpoint("0.0.0.0");
        db.insert(
            SrPolicyKey {
                color: 100,
                endpoint: null,
            },
            mpls_cp(1, 100, 1, 1000, 17001),
        );
        db.mpls_reconcile(100, null, true);
        // No exact <100, nh>: CO=00 → none; CO=01 → the null-endpoint BSID.
        assert_eq!(db.steer_mpls_bsid(100, nh, 0), None);
        assert_eq!(db.steer_mpls_bsid(100, nh, 0b01), Some(1000));
    }

    #[test]
    fn steer_srv6_bsid_returns_installed_bsid() {
        let mut db = SrPolicyDb::default();
        let ep = endpoint("10.0.0.9");
        // A valid SRv6 policy installs its End.B6.Encaps BSID immediately
        // (NHT-independent), so it is steerable at once — no reconcile.
        db.insert(
            SrPolicyKey {
                color: 100,
                endpoint: ep,
            },
            srv6_cp(1, 100, 1, "fc00:0:9::100", "fc00:0:2::"),
        );
        assert_eq!(db.steer_srv6_bsid(100, ep, 0), Some(v6("fc00:0:9::100")));
        // Wrong colour with CO=00 → none.
        assert_eq!(db.steer_srv6_bsid(200, ep, 0), None);
        // Withdrawing the policy removes the BSID → no steer.
        db.withdraw(100, ep, 1, 1);
        assert_eq!(db.steer_srv6_bsid(100, ep, 0), None);
    }

    #[test]
    fn local_policy_advert_builds_nlri_and_tunnel() {
        let rid: Ipv4Addr = "1.1.1.1".parse().unwrap();
        let mut policy = LocalSrPolicy {
            color: Some(100),
            endpoint: Some(endpoint("10.0.0.9")),
            preference: Some(200),
            binding_sid_label: Some(16100),
            ..Default::default()
        };
        // Incomplete (no segments) → not advertisable.
        assert!(policy.advert(rid).is_none());

        policy.segments.insert(
            1,
            LocalSegment {
                mpls_label: Some(16002),
                srv6_sid: None,
            },
        );
        policy.segments.insert(
            2,
            LocalSegment {
                mpls_label: Some(16009),
                srv6_sid: None,
            },
        );

        let (nlri, attr) = policy.advert(rid).expect("advertisable");
        assert_eq!(nlri.color, 100);
        assert_eq!(nlri.endpoint, endpoint("10.0.0.9"));
        assert_eq!(nlri.distinguisher, u32::from(rid));
        // No route-target → NO_ADVERTISE attached, no ext-comms.
        assert!(
            attr.com
                .as_ref()
                .is_some_and(|c| c.contains(&CommunityValue::NO_ADVERTISE.value()))
        );
        assert!(attr.ecom.is_none());
        // The Tunnel-Type-15 attribute decodes back to the policy content.
        let te = attr.tunnel_encap.expect("tunnel encap");
        let tlvs = bgp_packet::sr_policy_tlvs(&te)
            .expect("type 15")
            .expect("decode");
        assert_eq!(tlvs.preference, Some(200));
        assert_eq!(tlvs.binding_sid, Some(BindingSid::MplsLabel(16100)));
        assert_eq!(tlvs.segment_lists.len(), 1);
        assert_eq!(
            tlvs.segment_lists[0].segments,
            vec![
                Segment::TypeA {
                    flags: 0,
                    label: 16002
                },
                Segment::TypeA {
                    flags: 0,
                    label: 16009
                },
            ]
        );
    }

    #[test]
    fn local_policy_advert_route_target_replaces_no_advertise() {
        let rid: Ipv4Addr = "1.1.1.1".parse().unwrap();
        let policy = LocalSrPolicy {
            color: Some(7),
            endpoint: Some(endpoint("2001:db8::9")),
            route_target: Some("10.0.0.1".parse().unwrap()),
            segments: BTreeMap::from([(
                1,
                LocalSegment {
                    mpls_label: None,
                    srv6_sid: Some("fc00:0:9::".parse().unwrap()),
                },
            )]),
            ..Default::default()
        };
        let (nlri, attr) = policy.advert(rid).expect("advertisable");
        assert_eq!(nlri.afi(), bgp_packet::Afi::Ip6);
        // RT present → no NO_ADVERTISE; one IPv4-address-format RT.
        assert!(attr.com.is_none());
        let ecom = attr.ecom.expect("ext-comm");
        assert_eq!(ecom.0.len(), 1);
        let entry = ecom.0.first().unwrap();
        assert_eq!(entry.high_type, 0x01);
        assert_eq!(entry.low_type, ExtCommunitySubType::RouteTarget as u8);
        assert_eq!(&entry.val[0..4], &[10, 0, 0, 1]);
    }

    #[test]
    fn local_policy_advert_rejects_mixed_segments() {
        let rid: Ipv4Addr = "1.1.1.1".parse().unwrap();
        let policy = LocalSrPolicy {
            color: Some(1),
            endpoint: Some(endpoint("10.0.0.9")),
            segments: BTreeMap::from([
                (
                    1,
                    LocalSegment {
                        mpls_label: Some(16002),
                        srv6_sid: None,
                    },
                ),
                (
                    2,
                    LocalSegment {
                        mpls_label: None,
                        srv6_sid: Some("fc00::1".parse().unwrap()),
                    },
                ),
            ]),
            ..Default::default()
        };
        assert!(policy.advert(rid).is_none());
    }

    fn v4(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn reflect_attr_suppresses_no_advertise() {
        let attr = BgpAttr {
            com: Some(Community::from([CommunityValue::NO_ADVERTISE.value()])),
            ..Default::default()
        };
        // NO_ADVERTISE → never reflected, regardless of peer roles.
        assert!(reflect_attr(&attr, true, v4("2.2.2.2"), true, true, v4("1.1.1.1")).is_none());
        assert!(reflect_attr(&attr, false, v4("2.2.2.2"), true, true, v4("1.1.1.1")).is_none());
    }

    #[test]
    fn reflect_attr_ibgp_requires_client() {
        let attr = BgpAttr::default();
        // iBGP source → iBGP non-client dest: suppressed.
        assert!(reflect_attr(&attr, true, v4("2.2.2.2"), true, false, v4("1.1.1.1")).is_none());
        // iBGP source → iBGP client dest: reflected, with RR attrs stamped.
        let out = reflect_attr(&attr, true, v4("2.2.2.2"), true, true, v4("1.1.1.1")).unwrap();
        assert_eq!(out.originator_id.map(|o| o.id), Some(v4("2.2.2.2")));
        assert_eq!(out.cluster_list.map(|c| c.list), Some(vec![v4("1.1.1.1")]));
    }

    #[test]
    fn reflect_attr_preserves_existing_originator_and_prepends_cluster() {
        let attr = BgpAttr {
            originator_id: Some(OriginatorId::new(v4("9.9.9.9"))),
            cluster_list: Some(ClusterList {
                list: vec![v4("3.3.3.3")],
            }),
            ..Default::default()
        };
        let out = reflect_attr(&attr, true, v4("2.2.2.2"), true, true, v4("1.1.1.1")).unwrap();
        // ORIGINATOR_ID preserved (not overwritten); our id prepended.
        assert_eq!(out.originator_id.map(|o| o.id), Some(v4("9.9.9.9")));
        assert_eq!(
            out.cluster_list.map(|c| c.list),
            Some(vec![v4("1.1.1.1"), v4("3.3.3.3")])
        );
    }

    #[test]
    fn reflect_attr_ebgp_source_no_rr_attrs() {
        let attr = BgpAttr::default();
        // eBGP source → iBGP dest: reflected without ORIGINATOR_ID /
        // CLUSTER_LIST (it's a fresh iBGP advertisement).
        let out = reflect_attr(&attr, false, v4("2.2.2.2"), true, false, v4("1.1.1.1")).unwrap();
        assert!(out.originator_id.is_none());
        assert!(out.cluster_list.is_none());
    }

    #[test]
    fn reflect_attr_strips_ibgp_only_attrs_to_ebgp() {
        // An iBGP-learned policy carries the iBGP-only attributes; when it is
        // advertised to an eBGP peer they MUST be stripped: ORIGINATOR_ID /
        // CLUSTER_LIST (RFC 4456, non-transitive intra-AS) and LOCAL_PREF
        // (RFC 4271 §5.1.5, never sent to external peers).
        let attr = BgpAttr {
            originator_id: Some(OriginatorId::new(v4("9.9.9.9"))),
            cluster_list: Some(ClusterList {
                list: vec![v4("3.3.3.3")],
            }),
            local_pref: Some(bgp_packet::LocalPref::new(200)),
            ..Default::default()
        };
        // source iBGP, dest eBGP (dest_ibgp = false).
        let out = reflect_attr(&attr, true, v4("2.2.2.2"), false, false, v4("1.1.1.1")).unwrap();
        assert!(out.originator_id.is_none());
        assert!(out.cluster_list.is_none());
        assert!(out.local_pref.is_none());
    }

    #[test]
    fn reflect_withdraw_to_follows_client_rule() {
        assert!(!reflect_withdraw_to(true, true, false)); // iBGP→iBGP non-client: no
        assert!(reflect_withdraw_to(true, true, true)); // iBGP→iBGP client: yes
        assert!(reflect_withdraw_to(false, true, false)); // eBGP→iBGP: yes
    }
}
