//! Winning-definition selection and the participation rule (RFC 9350
//! §5.3) over a protocol-neutral view of an advertised Flexible Algorithm
//! Definition. OSPFv2 and OSPFv3 convert their wire FADs into [`Fad`], and
//! the validity, selection and constraint rules are then one
//! implementation. (IS-IS keeps its own, over isis-packet types, which
//! predates this module.)
//!
//! Every router configured for a Flexible Algorithm computes it with the
//! *winning* definition — the one every participant selects from the same
//! LSDB — not with its own configuration, and stops participating when it
//! cannot support everything in that definition. Computing with local
//! config instead lets two routers build different topologies for one
//! algorithm, and Flex-Algo forwarding then loops.

use std::collections::{BTreeMap, BTreeSet};

use packet_utils::ExtAdminGroup;

use super::constraint::FadConstraints;
use super::entry::FadMetricType;
use super::participation::{Participation, Unsupported};

/// One sub-TLV of an advertised definition.
#[derive(Debug, Clone, PartialEq)]
pub enum FadSub {
    ExcludeAny(ExtAdminGroup),
    IncludeAny(ExtAdminGroup),
    IncludeAll(ExtAdminGroup),
    /// The FAD Flags sub-TLV: the M flag, and whether any bit this build
    /// does not know is set (RFC 9350 §6.4: every bit is checked).
    Flags {
        prefix_metric: bool,
        unknown: bool,
    },
    /// Exclude SRLG, with the SRLG values it lists.
    ExcludeSrlg(Vec<u32>),
    /// A sub-TLV this build cannot read: an unknown type, or a known one
    /// whose value it could not parse.
    Unknown(u16),
}

/// An advertised Flexible Algorithm Definition.
#[derive(Debug, Clone, PartialEq)]
pub struct Fad {
    pub algo: u8,
    pub metric_type: u8,
    pub calc_type: u8,
    pub priority: u8,
    pub subs: Vec<FadSub>,
    /// A sub-TLV ran past the end of the definition, which therefore
    /// cannot be read in full.
    pub truncated: bool,
}

/// Whether a definition counts at all. RFC 9350 §5.3: an algorithm outside
/// 128..=255 "MUST be ignored". §6.1–§6.5: each constraint sub-TLV "MUST NOT
/// appear more than once in an OSPF FAD TLV. If it appears more than once,
/// the OSPF FAD TLV MUST be ignored by the receiver."
pub fn fad_valid(fad: &Fad) -> bool {
    if fad.algo < 128 {
        return false;
    }
    let mut seen = [false; 5];
    for sub in &fad.subs {
        let slot = match sub {
            FadSub::ExcludeAny(_) => 0,
            FadSub::IncludeAny(_) => 1,
            FadSub::IncludeAll(_) => 2,
            FadSub::Flags { .. } => 3,
            FadSub::ExcludeSrlg(_) => 4,
            FadSub::Unknown(_) => continue,
        };
        if std::mem::replace(&mut seen[slot], true) {
            return false;
        }
    }
    true
}

/// One router's definitions, in advertisement order, reduced to the one per
/// algorithm that counts: RFC 9350 §5.2, "the receiver MUST use the first
/// occurrence of the TLV", across Router Information LSA instances in
/// ascending Instance ID. A definition that must be ignored is skipped.
pub fn first_fads(fads: impl IntoIterator<Item = Fad>) -> BTreeMap<u8, Fad> {
    let mut out = BTreeMap::new();
    for fad in fads.into_iter().filter(fad_valid) {
        out.entry(fad.algo).or_insert(fad);
    }
    out
}

/// The winning definition for one algorithm and who advertised it.
#[derive(Debug, Clone, PartialEq)]
pub struct FadWinner<Id> {
    pub originator: Id,
    pub fad: Fad,
}

/// RFC 9350 §5.3: among the definitions advertised — this router's own
/// included, when it advertises one — the numerically greatest priority
/// wins, then the numerically greatest Router ID (or System-ID).
/// Deterministic over the LSDB, so every router reaches the same winner.
pub fn winning_fad<Id: Ord + Copy>(
    algo: u8,
    peers: &BTreeMap<Id, BTreeMap<u8, Fad>>,
    own: &BTreeMap<u8, Fad>,
    self_id: Id,
) -> Option<FadWinner<Id>> {
    let peers = peers
        .iter()
        .filter_map(|(id, fads)| fads.get(&algo).map(|f| (*id, f)));
    let local = own.get(&algo).map(|f| (self_id, f));
    peers
        .chain(local)
        .max_by(|(a_id, a), (b_id, b)| (a.priority, a_id).cmp(&(b.priority, b_id)))
        .map(|(originator, fad)| FadWinner {
            originator,
            fad: fad.clone(),
        })
}

/// The constraints to compute with, or the first element of the winning
/// definition this router does not support (RFC 9350 §5.3).
pub fn fad_constraints(fad: &Fad) -> Result<FadConstraints, Unsupported> {
    if fad.truncated {
        return Err(Unsupported::Truncated);
    }
    if fad.calc_type != 0 {
        return Err(Unsupported::CalcType(fad.calc_type));
    }
    let metric_type = FadMetricType::supported(fad.metric_type)
        .ok_or(Unsupported::MetricType(fad.metric_type))?;
    let mut c = FadConstraints {
        metric_type,
        ..Default::default()
    };
    for sub in &fad.subs {
        match sub {
            FadSub::ExcludeAny(g) => c.exclude_any = g.clone(),
            FadSub::IncludeAny(g) => c.include_any = g.clone(),
            FadSub::IncludeAll(g) => c.include_all = g.clone(),
            FadSub::Flags {
                prefix_metric: true,
                ..
            } => return Err(Unsupported::PrefixMetric),
            FadSub::Flags { unknown: true, .. } => return Err(Unsupported::Flag),
            FadSub::Flags { .. } => {}
            // Per-link SRLGs are not read, so the rule cannot be enforced;
            // an empty list excludes nothing.
            FadSub::ExcludeSrlg(srlgs) if !srlgs.is_empty() => {
                return Err(Unsupported::ExcludeSrlg);
            }
            FadSub::ExcludeSrlg(_) => {}
            FadSub::Unknown(t) => return Err(Unsupported::SubTlv(*t)),
        }
    }
    Ok(c)
}

/// One configured algorithm in one area: the winning definition, if any,
/// and whether this router participates.
#[derive(Debug, Clone, PartialEq)]
pub struct FadSelection<Id> {
    pub winner: Option<FadWinner<Id>>,
    pub participation: Participation,
}

/// Selection for every algorithm this router is configured for, from the
/// definitions others advertise in the area (`peers`) and the ones this
/// router advertises there (`own`). Algorithms nobody here is configured
/// for are ignored, as RFC 9350 §5.3 requires.
pub fn fad_selection<Id: Ord + Copy>(
    configured: impl IntoIterator<Item = u8>,
    peers: &BTreeMap<Id, BTreeMap<u8, Fad>>,
    own: &BTreeMap<u8, Fad>,
    self_id: Id,
) -> BTreeMap<u8, FadSelection<Id>> {
    configured
        .into_iter()
        .map(|algo| {
            let winner = winning_fad(algo, peers, own, self_id);
            let participation = match &winner {
                None => Participation::No(Unsupported::NoDefinition),
                Some(w) => match fad_constraints(&w.fad) {
                    Ok(c) => Participation::Yes(c),
                    Err(why) => Participation::No(why),
                },
            };
            (
                algo,
                FadSelection {
                    winner,
                    participation,
                },
            )
        })
        .collect()
}

/// The algorithms a selection participates in.
pub fn participating<Id>(selection: &BTreeMap<u8, FadSelection<Id>>) -> BTreeSet<u8> {
    selection
        .iter()
        .filter(|(_, s)| matches!(s.participation, Participation::Yes(_)))
        .map(|(algo, _)| *algo)
        .collect()
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn fad(algo: u8, priority: u8, subs: Vec<FadSub>) -> Fad {
        Fad {
            algo,
            metric_type: 0,
            calc_type: 0,
            priority,
            subs,
            truncated: false,
        }
    }

    fn rid(n: u8) -> Ipv4Addr {
        Ipv4Addr::new(10, 0, 0, n)
    }

    fn exclude(bit: u16) -> FadSub {
        let mut g = ExtAdminGroup::default();
        g.set(bit);
        FadSub::ExcludeAny(g)
    }

    fn peers(list: &[(u8, Fad)]) -> BTreeMap<Ipv4Addr, BTreeMap<u8, Fad>> {
        let mut map: BTreeMap<Ipv4Addr, BTreeMap<u8, Fad>> = BTreeMap::new();
        for (n, f) in list {
            map.entry(rid(*n)).or_default().insert(f.algo, f.clone());
        }
        map
    }

    /// The greatest priority wins, then the greatest Router ID; this
    /// router's own definition competes like any other. `max_by` picks the
    /// last of two equal maxima, so the tie cases include one where the
    /// right winner comes first.
    #[test]
    fn the_winner_is_greatest_priority_then_router_id() {
        let p = peers(&[(3, fad(128, 200, vec![])), (2, fad(128, 200, vec![]))]);
        let w = winning_fad(128, &p, &BTreeMap::new(), rid(9)).expect("winner");
        assert_eq!(w.originator, rid(3), "tie → greater Router ID");

        let p = peers(&[(3, fad(128, 100, vec![])), (2, fad(128, 200, vec![]))]);
        let w = winning_fad(128, &p, &BTreeMap::new(), rid(9)).expect("winner");
        assert_eq!(w.originator, rid(2), "priority first");

        let own = BTreeMap::from([(128, fad(128, 201, vec![]))]);
        let w = winning_fad(128, &p, &own, rid(1)).expect("winner");
        assert_eq!(w.originator, rid(1), "our own, on priority");

        // Peers come in ascending Router ID and our own definition after
        // them, so a tie with a greater peer puts the right winner first.
        let p = peers(&[(3, fad(128, 200, vec![]))]);
        let own = BTreeMap::from([(128, fad(128, 200, vec![]))]);
        let w = winning_fad(128, &p, &own, rid(1)).expect("winner");
        assert_eq!(w.originator, rid(3), "our own ties, and loses on Router ID");

        assert!(winning_fad(129, &p, &own, rid(1)).is_none());
    }

    /// RFC 9350 §5.3's unsupported list: each stops participation, and
    /// the constraints of a supported winner are what the computation
    /// uses.
    #[test]
    fn an_unsupported_winner_stops_participation() {
        let with = |f: Fad| fad_constraints(&f);
        assert!(with(fad(128, 128, vec![exclude(3)])).is_ok_and(|c| c.exclude_any.get(3)));
        let mut calc = fad(128, 128, vec![]);
        calc.calc_type = 1;
        assert_eq!(with(calc), Err(Unsupported::CalcType(1)));
        let mut te = fad(128, 128, vec![]);
        te.metric_type = 2;
        assert_eq!(with(te), Err(Unsupported::MetricType(2)));
        let mut delay = fad(128, 128, vec![]);
        delay.metric_type = 1;
        assert!(with(delay).is_ok_and(|c| c.metric_type == FadMetricType::MinUnidirLinkDelay));
        let flags = |prefix_metric, unknown| FadSub::Flags {
            prefix_metric,
            unknown,
        };
        assert_eq!(
            with(fad(128, 128, vec![flags(true, false)])),
            Err(Unsupported::PrefixMetric)
        );
        assert_eq!(
            with(fad(128, 128, vec![flags(false, true)])),
            Err(Unsupported::Flag)
        );
        assert!(with(fad(128, 128, vec![flags(false, false)])).is_ok());
        assert_eq!(
            with(fad(128, 128, vec![FadSub::ExcludeSrlg(vec![7])])),
            Err(Unsupported::ExcludeSrlg)
        );
        assert!(with(fad(128, 128, vec![FadSub::ExcludeSrlg(vec![])])).is_ok());
        assert_eq!(
            with(fad(128, 128, vec![FadSub::Unknown(252)])),
            Err(Unsupported::SubTlv(252))
        );
        let mut truncated = fad(128, 128, vec![]);
        truncated.truncated = true;
        assert_eq!(with(truncated), Err(Unsupported::Truncated));
    }

    /// A constraint appearing twice makes the whole definition one to
    /// ignore, and of several valid ones from a router the first counts.
    #[test]
    fn the_first_valid_definition_counts() {
        let twice = fad(128, 250, vec![exclude(1), exclude(2)]);
        assert!(!fad_valid(&twice));
        let first = fad(128, 100, vec![exclude(3)]);
        let second = fad(128, 150, vec![exclude(4)]);
        let got = first_fads([twice, first.clone(), second]);
        assert_eq!(got.get(&128), Some(&first));
        assert!(
            first_fads([fad(127, 100, vec![])]).is_empty(),
            "not a Flex-Algorithm"
        );
    }

    /// Only configured algorithms are selected; no definition anywhere
    /// means no participation, and a peer's definition counts even when
    /// ours differs.
    #[test]
    fn selection_covers_configured_algorithms_only() {
        let p = peers(&[
            (2, fad(128, 200, vec![exclude(7)])),
            (2, fad(130, 200, vec![])),
        ]);
        let own = BTreeMap::from([(128, fad(128, 100, vec![]))]);
        let sel = fad_selection([128, 129], &p, &own, rid(1));
        assert_eq!(sel.keys().copied().collect::<Vec<_>>(), vec![128, 129]);
        let c = sel[&128]
            .participation
            .constraints()
            .expect("participating");
        assert!(c.exclude_any.get(7), "the winner's, not ours");
        assert_eq!(
            sel[&129].participation,
            Participation::No(Unsupported::NoDefinition)
        );
        assert_eq!(participating(&sel), BTreeSet::from([128]));
    }
}
