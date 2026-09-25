use std::collections::{BTreeMap, BTreeSet};

use isis_packet::neigh::IsisSubTlv as NeighSubTlv;
use isis_packet::{
    Algo, ExtAdminGroup, FadSubTlv, IsisSubAdminGrp, IsisSubAsla, IsisSubFadExcludeAg,
    IsisSubFadExcludeSrlg, IsisSubFadFlags, IsisSubFadIncludeAllAg, IsisSubFadIncludeAnyAg,
    IsisSubFlexAlgoDef, IsisSubPrefixSid, IsisTlvExtIsReachEntry, PrefixSidFlags, SidLabelValue,
};

use crate::config::{Args, ConfigOp};

use super::Isis;
use super::affinity_map::AffinityMap;
use super::srlg::SrlgGroup;

// The protocol-neutral flex-algo data model, FAD constraint engine and
// config-staging engine now live in `crate::flex_algo`; re-export so
// existing IS-IS call sites (`super::flex_algo::…` in graph.rs / rib.rs
// / inst.rs) keep resolving. Only the isis-packet wire builders and the
// IS-IS callback shims below stay here.
pub use crate::flex_algo::{
    FadConstraints, FadMetricType, FlexAlgoConfig, FlexAlgoEntry, Participation, Unsupported,
    link_passes_constraints, local_link_affinity,
};
use isis_packet::IsisSysId;

/// Extract per-algorithm Prefix-SIDs from a peer-advertised Ext IP-
/// Reach entry. Yields one (algo, sid) pair for each Prefix-SID
/// sub-TLV (RFC 8667 §2.1) whose Algorithm field is in the
/// flex-algo range (128..=255); algo-0 / algo-1 / unknown algos
/// are skipped. Mirrors the producer-side `build_per_algo_prefix_sids`
/// so the bytes a sender packs are the bytes a receiver unpacks.
pub fn parse_per_algo_prefix_sids(
    entry: &isis_packet::IsisTlvExtIpReachEntry,
) -> impl Iterator<Item = (u8, isis_packet::SidLabelValue)> + '_ {
    entry.subs.iter().filter_map(|sub| match sub {
        isis_packet::prefix::IsisSubTlv::PrefixSid(s) => match s.algo {
            Algo::FlexAlgo(n) => Some((n, s.sid.clone())),
            _ => None,
        },
        _ => None,
    })
}

/// Extract the Extended Admin Group bitmap from a peer-advertised
/// ASLA sub-TLV iff the ASLA's SABM marks it as applying to the
/// Flex-Algorithm application (RFC 9479 §4.2 X-bit). Returns the
/// nested IsisSubAdminGrp's bitmap as an ExtAdminGroup; returns
/// `None` when the SABM byte 0 is missing, the X-bit is clear, or
/// no AdminGrp sub-sub-TLV is present. Mirrors the producer-side
/// `build_link_asla` so SPF gating sees the same bits a sender
/// sets.
pub fn parse_asla_flex_algo_bitmap(asla: &IsisSubAsla) -> Option<ExtAdminGroup> {
    let first = asla.sabm.first()?;
    if first & SABM_FLEX_ALGO == 0 {
        return None;
    }
    for sub in &asla.subs {
        if let NeighSubTlv::AdminGrp(g) = sub {
            return Some(ExtAdminGroup {
                words: g.groups.clone(),
            });
        }
    }
    None
}

/// The Min delay to cost a peer's link at for metric-type 1, or `None`
/// when the link must be pruned (RFC 9350 §15).
///
/// RFC 9350 §12 is strict about where this may come from: Flex-Algorithm
/// link attributes "MUST use the ASLA advertisements ... unless, in the
/// case of IS-IS, the L-flag is set". A legacy inline sub-TLV is
/// therefore *not* a fallback for a peer that simply never emitted an
/// ASLA — that link is pruned, and every conformant router in the domain
/// prunes it identically. Silently accepting the legacy value would give
/// this router a shorter edge than its neighbours compute, which is how
/// delay-based topologies end up forwarding in loops.
///
/// Selecting the applicable advertisements follows RFC 9479 §4.2:
///
/// 1. ASLAs whose non-zero SABM has the X-bit win outright; failing
///    those, ASLAs with zero-length masks apply;
/// 2. the L-flag then decides the source. Set means "use the legacy
///    advertisements for this link"; the flag "MUST be the same in all
///    sub-TLVs for a given link" and, "in cases where this constraint
///    is violated, MUST be considered set", so one L-set advertisement
///    settles it for the whole set;
/// 3. otherwise the answer is the first Min/Max delay across the
///    applicable set, which may be in any of them — attributes for one
///    application may be split across containers. If none of them
///    carries one, the answer is `None`, not a peek at the legacy copy;
/// 4. no applicable ASLA at all means no Flex-Algorithm delay.
pub fn peer_min_delay(entry: &IsisTlvExtIsReachEntry) -> Option<u32> {
    let applicable = applicable_aslas(entry);
    if applicable.is_empty() {
        return None;
    }
    if applicable.iter().any(|a| a.l_flag) {
        return inline_min_delay(entry);
    }
    applicable.into_iter().find_map(nested_min_delay)
}

/// The ASLAs governing Flex-Algorithm on this link, per RFC 9479 §4.2.
///
/// Plural deliberately: "Multiple Application-Specific Link Attributes
/// sub-TLVs for the same link MAY be advertised", and conflicts are
/// resolved per application/attribute pair, not per container. A sender
/// may therefore put this link's affinity in one X-scoped ASLA and its
/// delay in the next, and a reader that locks onto the first container
/// prunes the link — or not, depending on which order they arrived in.
///
/// Explicit X-bit advertisements exclude the zero-length-mask ones
/// entirely: those apply only "when no link attribute advertisements
/// with a non-zero-length Application Identifier Bit Mask and a matching
/// Application Identifier Bit set are present for a given link".
fn applicable_aslas(entry: &IsisTlvExtIsReachEntry) -> Vec<&IsisSubAsla> {
    let mut explicit = Vec::new();
    let mut any_application = Vec::new();
    for sub in &entry.subs {
        let NeighSubTlv::Asla(asla) = sub else {
            continue;
        };
        if asla.sabm.first().is_some_and(|b| b & SABM_FLEX_ALGO != 0) {
            explicit.push(asla);
        } else if asla.sabm.is_empty() && asla.udabm.is_empty() {
            any_application.push(asla);
        }
    }
    if explicit.is_empty() {
        any_application
    } else {
        explicit
    }
}

/// Min field of the Min/Max Link Delay nested in this ASLA.
fn nested_min_delay(asla: &IsisSubAsla) -> Option<u32> {
    asla.subs.iter().find_map(|sub| match sub {
        NeighSubTlv::MinMaxLinkDelay(d) => Some(d.min_delay),
        _ => None,
    })
}

/// Min field of the legacy (inline) Min/Max Link Delay — reachable only
/// via an applicable ASLA with the L-flag set.
fn inline_min_delay(entry: &IsisTlvExtIsReachEntry) -> Option<u32> {
    entry.subs.iter().find_map(|sub| match sub {
        NeighSubTlv::MinMaxLinkDelay(d) => Some(d.min_delay),
        _ => None,
    })
}

/// SABM byte (RFC 9479 §4.2) with the Flex-Algorithm (X-bit) set.
/// Bit layout in the first SABM byte, MSB-first: R(7) S(6) F(5) X(4)
/// reserved(3..0). Used as the Selective Application-specific
/// Attribute Bitmap on a per-link ASLA sub-TLV so receivers know
/// these link attributes apply to flex-algo path computation.
const SABM_FLEX_ALGO: u8 = 0x10;

/// Build the per-link Extended Admin Group bitmap from a set of
/// affinity names by resolving each name to its bit position via the
/// affinity-map and packing the bits into RFC 7308 32-bit words.
/// Names with no matching `/affinity-map/affinity` entry
/// are silently dropped (best-effort emit, matches `build_fad_subs`).
fn link_admin_group_words(affinity: &BTreeSet<String>, am: &AffinityMap) -> Vec<u32> {
    let mut g = ExtAdminGroup::default();
    for name in affinity {
        if let Some(bit) = am.bit(name) {
            g.set(bit);
        }
    }
    g.words
}

/// Build a per-link ASLA sub-TLV (RFC 9479) carrying the link's
/// affinity (Extended Admin Group, RFC 7308) and any RFC 8570 TE
/// metrics (`extra` — delay/jitter/loss sub-TLVs) scoped to the
/// Flex-Algorithm application. Returns `None` only when the ASLA would
/// carry nothing: no affinity bit resolved *and* `extra` is empty.
///
/// The TE metrics are *also* advertised inline in TLV 22 for general
/// RFC 8570 visibility; this copy is the application-specific one
/// Flex-Algorithm consumes (RFC 9350 §6.3 — link attributes used by a
/// Flex-Algorithm must be advertised via ASLA with the Flex-Algorithm
/// application bit set).
///
/// SABM is set to a single byte with only the X-bit (Flex-Algorithm,
/// 0x10) — these link attributes apply to flex-algo SPF only. The
/// L-flag stays cleared (modern non-legacy interpretation per
/// RFC 9479 §4.2). UDABM is left empty: every receiver that
/// understands ASLA understands Flex-Algorithm.
pub fn build_link_asla(
    affinity: &BTreeSet<String>,
    am: &AffinityMap,
    extra: Vec<NeighSubTlv>,
) -> Option<IsisSubAsla> {
    let words = link_admin_group_words(affinity, am);
    let mut subs = Vec::new();
    if !words.is_empty() {
        subs.push(NeighSubTlv::AdminGrp(IsisSubAdminGrp { groups: words }));
    }
    subs.extend(extra);
    if subs.is_empty() {
        return None;
    }
    Some(IsisSubAsla {
        l_flag: false,
        sabm: vec![SABM_FLEX_ALGO],
        udabm: Vec::new(),
        subs,
    })
}

/// Build the per-algorithm Prefix-SID sub-TLVs (RFC 8667 §2.1 +
/// RFC 9350 §7) to attach to one prefix's IP-reach entry. Each map
/// entry produces one additional Prefix-SID sub-TLV with the
/// Algorithm field set to the flex-algo id. Iteration order matches
/// the BTreeMap (ascending algo id) so the wire byte sequence is
/// deterministic.
pub fn build_per_algo_prefix_sids(
    map: &BTreeMap<u8, SidLabelValue>,
    node: bool,
) -> Vec<IsisSubPrefixSid> {
    map.iter()
        .map(|(&algo, sid)| IsisSubPrefixSid {
            // A per-algo Prefix-SID on a host prefix is a node-SID too
            // (RFC 9350 §7 + RFC 8667 §2.1.1): mirror the algo-0 N flag.
            flags: PrefixSidFlags::new().with_n_flag(node),
            algo: Algo::FlexAlgo(algo),
            sid: sid.clone(),
        })
        .collect()
}

/// Build the FAD sub-TLVs (RFC 9350 §5.1) this router will originate
/// inside Router Capability TLV 242. One FAD per
/// `FlexAlgoConfig.config` entry with `advertise_definition == true`;
/// entries with the flag absent or false stay purely local.
///
/// Affinity names are resolved against `affinity_map` to 256-bit
/// Extended Admin Group bit positions (RFC 7308) — names with no
/// matching entry are silently dropped (LSP-gen is best-effort, the
/// operator's mistake doesn't deserve a build failure). SRLG names
/// are resolved against the global SRLG map (`Isis::srlg_groups`)
/// to 32-bit identifiers the same way.
pub fn build_fad_subs(
    fa: &FlexAlgoConfig,
    am: &AffinityMap,
    srlg_groups: &BTreeMap<String, SrlgGroup>,
) -> Vec<IsisSubFlexAlgoDef> {
    fn group_from_names<I: IntoIterator<Item = S>, S: AsRef<str>>(
        am: &AffinityMap,
        names: I,
    ) -> ExtAdminGroup {
        let mut g = ExtAdminGroup::default();
        for n in names {
            if let Some(bit) = am.bit(n.as_ref()) {
                g.set(bit);
            }
        }
        g
    }

    let mut out = Vec::new();
    for (&algo, entry) in &fa.config {
        if entry.advertise_definition != Some(true) {
            continue;
        }
        let metric_type = entry.metric_type.unwrap_or(FadMetricType::Igp).wire();
        let priority = entry.priority.unwrap_or(128);

        let mut subs = Vec::new();

        if !entry.exclude_any.is_empty() {
            let group = group_from_names(am, entry.exclude_any.iter());
            if !group.words.is_empty() {
                subs.push(FadSubTlv::ExcludeAg(IsisSubFadExcludeAg { group }));
            }
        }
        if !entry.include_any.is_empty() {
            let group = group_from_names(am, entry.include_any.iter());
            if !group.words.is_empty() {
                subs.push(FadSubTlv::IncludeAnyAg(IsisSubFadIncludeAnyAg { group }));
            }
        }
        if !entry.include_all.is_empty() {
            let group = group_from_names(am, entry.include_all.iter());
            if !group.words.is_empty() {
                subs.push(FadSubTlv::IncludeAllAg(IsisSubFadIncludeAllAg { group }));
            }
        }
        if entry.prefix_metric == Some(true) {
            subs.push(FadSubTlv::Flags(IsisSubFadFlags {
                m_flag: true,
                other: 0,
                trailing: Vec::new(),
            }));
        }
        if !entry.srlg_exclude.is_empty() {
            let mut ids: Vec<u32> = entry
                .srlg_exclude
                .iter()
                .filter_map(|n| srlg_groups.get(n).map(|g| g.value))
                .collect();
            ids.sort();
            ids.dedup();
            if !ids.is_empty() {
                subs.push(FadSubTlv::ExcludeSrlg(IsisSubFadExcludeSrlg { srlgs: ids }));
            }
        }

        out.push(IsisSubFlexAlgoDef {
            flex_algorithm: algo,
            metric_type,
            calc_type: 0, // Only SPF defined today (RFC 9350 §5.1).
            priority,
            subs,
        });
    }
    out
}

// ── Winning-FAD selection and participation (RFC 9350 §5.3) ───────
//
// Every router configured for a Flexible Algorithm computes it with the
// *winning* definition — the one every participant selects from the same
// LSDB — not with its own configuration, and stops participating when it
// cannot support everything in that definition. Computing with local
// config instead lets two routers build different topologies for one
// algorithm, and Flex-Algo forwarding then loops.

/// Whether one FAD sub-TLV counts at all. RFC 9350 §5.3: an algorithm
/// outside 128..=255 "MUST be ignored". §6.1–§6.5: each constraint
/// sub-TLV "MUST NOT appear more than once in a single IS-IS FAD sub-TLV.
/// If it appears more than once, the IS-IS FAD sub-TLV MUST be ignored".
fn fad_valid(fad: &IsisSubFlexAlgoDef) -> bool {
    if fad.flex_algorithm < 128 {
        return false;
    }
    let mut seen = [false; 5];
    for sub in &fad.subs {
        let slot = match sub {
            FadSubTlv::ExcludeAg(_) => 0,
            FadSubTlv::IncludeAnyAg(_) => 1,
            FadSubTlv::IncludeAllAg(_) => 2,
            FadSubTlv::Flags(_) => 3,
            FadSubTlv::ExcludeSrlg(_) => 4,
            FadSubTlv::Unknown(_) => continue,
        };
        if std::mem::replace(&mut seen[slot], true) {
            return false;
        }
    }
    true
}

/// One router's FAD sub-TLVs, in LSP order (lowest fragment first), merged
/// per algorithm as RFC 9350 §6 requires of "the set of FAD sub-TLVs for a
/// given Flex-Algorithm from a given IS":
///
/// - invalid sub-TLVs ([`fad_valid`]) are ignored;
/// - the first valid one supplies the header (metric-type, calc-type,
///   priority);
/// - for each constraint, "the first occurrence in the lowest-numbered LSP
///   ... MUST be used, and any other occurrences MUST be ignored", except
///   Exclude SRLG, which "MAY appear more than once in the set" and so
///   accumulates;
/// - unknown sub-TLVs are all kept: any one of them stops participation.
pub fn merge_fads<'a>(
    fads: impl IntoIterator<Item = &'a IsisSubFlexAlgoDef>,
) -> BTreeMap<u8, IsisSubFlexAlgoDef> {
    let mut merged: BTreeMap<u8, IsisSubFlexAlgoDef> = BTreeMap::new();
    for fad in fads.into_iter().filter(|f| fad_valid(f)) {
        let Some(into) = merged.get_mut(&fad.flex_algorithm) else {
            merged.insert(fad.flex_algorithm, fad.clone());
            continue;
        };
        for sub in &fad.subs {
            let present = into
                .subs
                .iter()
                .any(|have| std::mem::discriminant(have) == std::mem::discriminant(sub));
            let accumulates = matches!(sub, FadSubTlv::ExcludeSrlg(_) | FadSubTlv::Unknown(_));
            if accumulates || !present {
                into.subs.push(sub.clone());
            }
        }
    }
    merged
}

/// The winning definition for one algorithm and who originated it.
#[derive(Debug, Clone, PartialEq)]
pub struct FadWinner {
    pub originator: IsisSysId,
    pub fad: IsisSubFlexAlgoDef,
}

/// RFC 9350 §5.3: among the definitions advertised in the level — this
/// router's own included, when it advertises one — the numerically
/// greatest priority wins, then the numerically greatest System-ID.
/// Deterministic over the LSDB, so every router reaches the same winner.
pub fn winning_fad(
    algo: u8,
    peer_fad: &BTreeMap<IsisSysId, BTreeMap<u8, IsisSubFlexAlgoDef>>,
    own: &BTreeMap<u8, IsisSubFlexAlgoDef>,
    self_sys_id: &IsisSysId,
) -> Option<FadWinner> {
    let peers = peer_fad
        .iter()
        .filter_map(|(sys_id, fads)| fads.get(&algo).map(|f| (*sys_id, f)));
    let local = own.get(&algo).map(|f| (*self_sys_id, f));
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
pub fn fad_constraints(fad: &IsisSubFlexAlgoDef) -> Result<FadConstraints, Unsupported> {
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
            FadSubTlv::ExcludeAg(v) => c.exclude_any = v.group.clone(),
            FadSubTlv::IncludeAnyAg(v) => c.include_any = v.group.clone(),
            FadSubTlv::IncludeAllAg(v) => c.include_all = v.group.clone(),
            FadSubTlv::Flags(f) if f.m_flag => return Err(Unsupported::PrefixMetric),
            FadSubTlv::Flags(f) if f.has_unknown() => return Err(Unsupported::Flag),
            FadSubTlv::Flags(_) => {}
            // Per-link SRLGs are not read, so the rule cannot be enforced;
            // an empty list excludes nothing.
            FadSubTlv::ExcludeSrlg(v) if !v.srlgs.is_empty() => {
                return Err(Unsupported::ExcludeSrlg);
            }
            FadSubTlv::ExcludeSrlg(_) => {}
            FadSubTlv::Unknown(u) => return Err(Unsupported::SubTlv(u.code.into())),
        }
    }
    Ok(c)
}

/// One configured algorithm at one level: the winning definition, if any,
/// and whether this router participates.
#[derive(Debug, Clone, PartialEq)]
pub struct FadSelection {
    pub winner: Option<FadWinner>,
    pub participation: Participation,
}

/// Selection for every algorithm this router is configured for, at the
/// level whose received definitions are `peer_fad`. Algorithms nobody here
/// is configured for are ignored, as RFC 9350 §5.3 requires.
pub fn fad_selection(
    fa: &FlexAlgoConfig,
    am: &AffinityMap,
    srlg_groups: &BTreeMap<String, SrlgGroup>,
    peer_fad: &BTreeMap<IsisSysId, BTreeMap<u8, IsisSubFlexAlgoDef>>,
    self_sys_id: &IsisSysId,
) -> BTreeMap<u8, FadSelection> {
    let own = merge_fads(&build_fad_subs(fa, am, srlg_groups));
    fa.config
        .keys()
        .map(|&algo| {
            let winner = winning_fad(algo, peer_fad, &own, self_sys_id);
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
pub fn participating(selection: &BTreeMap<u8, FadSelection>) -> BTreeSet<u8> {
    selection
        .iter()
        .filter(|(_, s)| matches!(s.participation, Participation::Yes(_)))
        .map(|(algo, _)| *algo)
        .collect()
}

/// The SR-Algorithm list (RFC 8667 §3.2) for a level: algorithm 0, plus
/// every Flexible Algorithm this router participates in there. Not every
/// configured one: "it MUST NOT announce participation" in an algorithm it
/// cannot support (RFC 9350 §5.3).
pub fn sr_algorithms_participating(participating: &BTreeSet<u8>) -> Vec<Algo> {
    std::iter::once(Algo::Spf)
        .chain(participating.iter().map(|&n| Algo::FlexAlgo(n)))
        .collect()
}

// ── Wiring into the existing IS-IS callback dispatcher ────────────
//
// The IS-IS instance dispatches per-leaf via `Isis::callbacks`, with
// callback signature `fn(&mut Isis, Args, ConfigOp) -> Option<()>`. We
// register one shim per path here; each shim forwards into
// `isis.flex_algo.exec(path, ...)` and then `commit()` so the new value
// is visible synchronously, the way the rest of IS-IS expects.

macro_rules! flex_algo_cb {
    ($name:ident, $path:literal) => {
        fn $name(isis: &mut Isis, args: Args, op: ConfigOp) -> Option<()> {
            isis.flex_algo.exec($path.to_string(), args, op).ok()?;
            isis.flex_algo.commit();
            // Re-originate both levels so FAD changes propagate to
            // peers without waiting for the refresh timer. The
            // process_lsp_originate path filters by `has_level` for
            // single-level instances, so unconditional send is safe.
            let _ = isis
                .tx
                .send(super::Message::LspOriginate(super::Level::L1, None));
            let _ = isis
                .tx
                .send(super::Message::LspOriginate(super::Level::L2, None));
            Some(())
        }
    };
}

flex_algo_cb!(cb_entry, "/router/isis/flex-algo");
flex_algo_cb!(
    cb_advertise_definition,
    "/router/isis/flex-algo/advertise-definition"
);
flex_algo_cb!(cb_metric_type, "/router/isis/flex-algo/metric-type");
flex_algo_cb!(cb_priority, "/router/isis/flex-algo/priority");
flex_algo_cb!(cb_prefix_metric, "/router/isis/flex-algo/prefix-metric");
flex_algo_cb!(cb_dp_sr_mpls, "/router/isis/flex-algo/dataplane/sr-mpls");
flex_algo_cb!(cb_dp_srv6, "/router/isis/flex-algo/dataplane/srv6");
flex_algo_cb!(cb_dp_ip, "/router/isis/flex-algo/dataplane/ip");
flex_algo_cb!(
    cb_affinity_include_any,
    "/router/isis/flex-algo/affinity/include-any"
);
flex_algo_cb!(
    cb_affinity_include_all,
    "/router/isis/flex-algo/affinity/include-all"
);
flex_algo_cb!(
    cb_affinity_exclude_any,
    "/router/isis/flex-algo/affinity/exclude-any"
);
flex_algo_cb!(cb_srlg_exclude, "/router/isis/flex-algo/srlg-exclude");
flex_algo_cb!(
    cb_frr_disable,
    "/router/isis/flex-algo/fast-reroute/disable"
);

pub fn callback_register(isis: &mut Isis) {
    isis.callback_add("/router/isis/flex-algo", cb_entry);
    isis.callback_add(
        "/router/isis/flex-algo/advertise-definition",
        cb_advertise_definition,
    );
    isis.callback_add("/router/isis/flex-algo/metric-type", cb_metric_type);
    isis.callback_add("/router/isis/flex-algo/priority", cb_priority);
    isis.callback_add("/router/isis/flex-algo/prefix-metric", cb_prefix_metric);
    isis.callback_add("/router/isis/flex-algo/dataplane/sr-mpls", cb_dp_sr_mpls);
    isis.callback_add("/router/isis/flex-algo/dataplane/srv6", cb_dp_srv6);
    isis.callback_add("/router/isis/flex-algo/dataplane/ip", cb_dp_ip);
    isis.callback_add(
        "/router/isis/flex-algo/affinity/include-any",
        cb_affinity_include_any,
    );
    isis.callback_add(
        "/router/isis/flex-algo/affinity/include-all",
        cb_affinity_include_all,
    );
    isis.callback_add(
        "/router/isis/flex-algo/affinity/exclude-any",
        cb_affinity_exclude_any,
    );
    isis.callback_add("/router/isis/flex-algo/srlg-exclude", cb_srlg_exclude);
    isis.callback_add(
        "/router/isis/flex-algo/fast-reroute/disable",
        cb_frr_disable,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    fn args(items: &[&str]) -> Args {
        Args(items.iter().map(|s| s.to_string()).collect::<VecDeque<_>>())
    }

    #[test]
    fn build_per_algo_prefix_sids_empty_map_yields_empty_vec() {
        let map: BTreeMap<u8, SidLabelValue> = BTreeMap::new();
        assert!(build_per_algo_prefix_sids(&map, true).is_empty());
    }

    #[test]
    fn build_per_algo_prefix_sids_emits_one_per_algo_in_sorted_order() {
        let mut map: BTreeMap<u8, SidLabelValue> = BTreeMap::new();
        map.insert(129, SidLabelValue::Index(1129));
        map.insert(128, SidLabelValue::Index(1128));
        let sids = build_per_algo_prefix_sids(&map, true);
        assert_eq!(sids.len(), 2);
        // BTreeMap iterates ascending → algo 128 first, 129 second.
        assert_eq!(sids[0].algo, Algo::FlexAlgo(128));
        assert_eq!(sids[0].sid, SidLabelValue::Index(1128));
        assert_eq!(sids[1].algo, Algo::FlexAlgo(129));
        assert_eq!(sids[1].sid, SidLabelValue::Index(1129));
        // Host-prefix per-algo Prefix-SIDs carry the N (Node-SID) flag;
        // a non-host prefix leaves it clear.
        assert!(sids.iter().all(|s| s.flags.n_flag()));
        assert!(
            build_per_algo_prefix_sids(&map, false)
                .iter()
                .all(|s| !s.flags.n_flag())
        );
    }

    #[test]
    fn build_per_algo_prefix_sids_preserves_label_vs_index_form() {
        let mut map: BTreeMap<u8, SidLabelValue> = BTreeMap::new();
        map.insert(128, SidLabelValue::Index(42));
        map.insert(129, SidLabelValue::Label(20128));
        let sids = build_per_algo_prefix_sids(&map, true);
        assert_eq!(sids[0].sid, SidLabelValue::Index(42));
        assert_eq!(sids[1].sid, SidLabelValue::Label(20128));
    }

    fn affinity_set(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn parse_per_algo_prefix_sids_filters_to_flex_algo_range() {
        use ipnet::Ipv4Net;
        use isis_packet::PrefixSidFlags;
        use isis_packet::prefix::{Ipv4ControlInfo, IsisSubTlv as PrefixSubTlv};
        let entry = isis_packet::IsisTlvExtIpReachEntry {
            metric: 10,
            flags: Ipv4ControlInfo::new(),
            prefix: "10.0.0.1/32".parse::<Ipv4Net>().unwrap(),
            subs: vec![
                PrefixSubTlv::PrefixSid(isis_packet::IsisSubPrefixSid {
                    flags: PrefixSidFlags::from(0u8),
                    algo: Algo::Spf,
                    sid: SidLabelValue::Index(1),
                }),
                PrefixSubTlv::PrefixSid(isis_packet::IsisSubPrefixSid {
                    flags: PrefixSidFlags::from(0u8),
                    algo: Algo::FlexAlgo(128),
                    sid: SidLabelValue::Index(1128),
                }),
                PrefixSubTlv::PrefixSid(isis_packet::IsisSubPrefixSid {
                    flags: PrefixSidFlags::from(0u8),
                    algo: Algo::FlexAlgo(129),
                    sid: SidLabelValue::Label(20129),
                }),
                PrefixSubTlv::PrefixSid(isis_packet::IsisSubPrefixSid {
                    flags: PrefixSidFlags::from(0u8),
                    algo: Algo::StrictSpf,
                    sid: SidLabelValue::Index(2),
                }),
            ],
        };
        let out: Vec<_> = parse_per_algo_prefix_sids(&entry).collect();
        // Algo::Spf and Algo::StrictSpf must be skipped.
        assert_eq!(out.len(), 2);
        assert_eq!(out[0], (128, SidLabelValue::Index(1128)));
        assert_eq!(out[1], (129, SidLabelValue::Label(20129)));
    }

    #[test]
    fn parse_per_algo_prefix_sids_round_trips_through_build_per_algo_prefix_sids() {
        use ipnet::Ipv4Net;
        use isis_packet::prefix::{Ipv4ControlInfo, IsisSubTlv as PrefixSubTlv};
        let mut map: BTreeMap<u8, SidLabelValue> = BTreeMap::new();
        map.insert(128, SidLabelValue::Index(1128));
        map.insert(129, SidLabelValue::Label(20129));
        let sids = build_per_algo_prefix_sids(&map, true);
        // Wrap each into the entry, then pull back via the parser.
        let entry = isis_packet::IsisTlvExtIpReachEntry {
            metric: 10,
            flags: Ipv4ControlInfo::new(),
            prefix: "10.0.0.1/32".parse::<Ipv4Net>().unwrap(),
            subs: sids.into_iter().map(PrefixSubTlv::PrefixSid).collect(),
        };
        let out: Vec<_> = parse_per_algo_prefix_sids(&entry).collect();
        assert_eq!(
            out,
            vec![
                (128, SidLabelValue::Index(1128)),
                (129, SidLabelValue::Label(20129)),
            ]
        );
    }

    #[test]
    fn parse_asla_flex_algo_bitmap_returns_none_without_x_bit() {
        // SABM = [0x80] sets R-bit (RSVP-TE) but not X-bit.
        let asla = IsisSubAsla {
            l_flag: false,
            sabm: vec![0x80],
            udabm: vec![],
            subs: vec![NeighSubTlv::AdminGrp(IsisSubAdminGrp {
                groups: vec![0xFF],
            })],
        };
        assert!(parse_asla_flex_algo_bitmap(&asla).is_none());
    }

    #[test]
    fn parse_asla_flex_algo_bitmap_returns_none_with_empty_sabm() {
        let asla = IsisSubAsla {
            l_flag: false,
            sabm: vec![],
            udabm: vec![],
            subs: vec![NeighSubTlv::AdminGrp(IsisSubAdminGrp {
                groups: vec![0xFF],
            })],
        };
        assert!(parse_asla_flex_algo_bitmap(&asla).is_none());
    }

    #[test]
    fn parse_asla_flex_algo_bitmap_returns_none_when_no_admin_grp_nested() {
        let asla = IsisSubAsla {
            l_flag: false,
            sabm: vec![SABM_FLEX_ALGO],
            udabm: vec![],
            subs: vec![],
        };
        assert!(parse_asla_flex_algo_bitmap(&asla).is_none());
    }

    #[test]
    fn parse_asla_flex_algo_bitmap_extracts_admin_grp_when_x_bit_set() {
        // SABM = [0x90] sets R-bit AND X-bit — both are honored; X
        // alone is enough to surface the bitmap.
        let asla = IsisSubAsla {
            l_flag: false,
            sabm: vec![0x90],
            udabm: vec![],
            subs: vec![NeighSubTlv::AdminGrp(IsisSubAdminGrp {
                groups: vec![0x11, 0x80000000],
            })],
        };
        let bitmap = parse_asla_flex_algo_bitmap(&asla).expect("bitmap");
        assert_eq!(bitmap.words, vec![0x11, 0x80000000]);
    }

    fn reach_entry(subs: Vec<NeighSubTlv>) -> IsisTlvExtIsReachEntry {
        IsisTlvExtIsReachEntry {
            neighbor_id: Default::default(),
            metric: 10,
            subs,
        }
    }

    fn min_max(min_delay: u32) -> NeighSubTlv {
        use isis_packet::IsisSubMinMaxLinkDelay;
        NeighSubTlv::MinMaxLinkDelay(IsisSubMinMaxLinkDelay {
            anomalous: false,
            min_delay,
            max_delay: min_delay + 300,
        })
    }

    fn asla(sabm: Vec<u8>, l_flag: bool, subs: Vec<NeighSubTlv>) -> NeighSubTlv {
        NeighSubTlv::Asla(IsisSubAsla {
            l_flag,
            sabm,
            udabm: vec![],
            subs,
        })
    }

    /// The ordinary case: a Flex-Algorithm-scoped ASLA supplies the Min.
    #[test]
    fn peer_min_delay_reads_the_flex_algo_asla() {
        let entry = reach_entry(vec![
            min_max(700), // legacy copy, must be ignored
            asla(vec![SABM_FLEX_ALGO], false, vec![min_max(900)]),
        ]);
        assert_eq!(peer_min_delay(&entry), Some(900));
    }

    /// RFC 9350 §12: without an ASLA there is no Flex-Algorithm link
    /// attribute, so the link is pruned. Reading the legacy value here
    /// would give this router a shorter edge than every conformant
    /// neighbour computes for the same link.
    #[test]
    fn peer_min_delay_does_not_fall_back_to_legacy_without_an_asla() {
        let entry = reach_entry(vec![min_max(700)]);
        assert_eq!(peer_min_delay(&entry), None);
    }

    /// An ASLA scoped to another application does not make its link
    /// attributes available to Flex-Algorithm, and does not license the
    /// legacy copy either.
    #[test]
    fn peer_min_delay_ignores_an_asla_scoped_elsewhere() {
        let rsvp_te = vec![0x80];
        let entry = reach_entry(vec![asla(rsvp_te, false, vec![min_max(900)]), min_max(700)]);
        assert_eq!(peer_min_delay(&entry), None);
    }

    /// An applicable, L-clear ASLA that carries no Min/Max delay means
    /// the peer advertised none *for this application*. That is a prune,
    /// not permission to read the legacy sub-TLV sitting beside it.
    #[test]
    fn peer_min_delay_prunes_when_the_applicable_asla_has_no_delay() {
        let entry = reach_entry(vec![
            asla(vec![SABM_FLEX_ALGO], false, vec![]),
            min_max(700),
        ]);
        assert_eq!(peer_min_delay(&entry), None);
    }

    /// The one sanctioned route to the legacy value: an applicable ASLA
    /// with the L-flag set (RFC 9479 §4.2, RFC 9350 §12).
    #[test]
    fn peer_min_delay_uses_legacy_when_the_l_flag_says_so() {
        let entry = reach_entry(vec![asla(vec![SABM_FLEX_ALGO], true, vec![]), min_max(700)]);
        assert_eq!(peer_min_delay(&entry), Some(700));
    }

    /// Zero-length masks apply to any application that has no more
    /// specific advertisement.
    #[test]
    fn peer_min_delay_accepts_a_zero_length_mask_asla() {
        let entry = reach_entry(vec![asla(vec![], false, vec![min_max(1_100)])]);
        assert_eq!(peer_min_delay(&entry), Some(1_100));
    }

    /// ... but only then: an explicit X-bit advertisement outranks it,
    /// whichever order the two arrive in.
    #[test]
    fn peer_min_delay_prefers_an_explicit_x_bit_asla() {
        let specific = asla(vec![SABM_FLEX_ALGO], false, vec![min_max(900)]);
        let generic = asla(vec![], false, vec![min_max(1_100)]);
        assert_eq!(
            peer_min_delay(&reach_entry(vec![generic.clone(), specific.clone()])),
            Some(900)
        );
        assert_eq!(
            peer_min_delay(&reach_entry(vec![specific, generic])),
            Some(900)
        );
    }

    /// RFC 9479 §4.2 lets one application's attributes be split across
    /// several ASLAs, resolved per application/attribute pair. Reading
    /// only the first container prunes the link — or not, depending on
    /// which order the two arrived in.
    #[test]
    fn peer_min_delay_searches_every_applicable_asla() {
        use isis_packet::IsisSubAdminGrp;
        let affinity_only = asla(
            vec![SABM_FLEX_ALGO],
            false,
            vec![NeighSubTlv::AdminGrp(IsisSubAdminGrp {
                groups: vec![0x0000_0001],
            })],
        );
        let delay_only = asla(vec![SABM_FLEX_ALGO], false, vec![min_max(900)]);
        assert_eq!(
            peer_min_delay(&reach_entry(vec![
                affinity_only.clone(),
                delay_only.clone()
            ])),
            Some(900)
        );
        assert_eq!(
            peer_min_delay(&reach_entry(vec![delay_only, affinity_only])),
            Some(900),
            "and the answer must not depend on the order"
        );
    }

    /// The same applies to zero-length-mask containers.
    #[test]
    fn peer_min_delay_searches_every_zero_mask_asla() {
        let empty = asla(vec![], false, vec![]);
        let carrying = asla(vec![], false, vec![min_max(1_100)]);
        assert_eq!(
            peer_min_delay(&reach_entry(vec![empty, carrying])),
            Some(1_100)
        );
    }

    /// "For a given application, the setting of the L-flag MUST be the
    /// same in all sub-TLVs for a given link. In cases where this
    /// constraint is violated, the L-flag MUST be considered set."
    #[test]
    fn peer_min_delay_treats_a_split_l_flag_as_set() {
        let entry = reach_entry(vec![
            asla(vec![SABM_FLEX_ALGO], false, vec![min_max(900)]),
            asla(vec![SABM_FLEX_ALGO], true, vec![]),
            min_max(700),
        ]);
        assert_eq!(peer_min_delay(&entry), Some(700), "legacy wins the tie");
    }

    #[test]
    fn peer_min_delay_is_none_without_any_delay() {
        assert_eq!(peer_min_delay(&reach_entry(vec![])), None);
    }

    /// Producer nests Min/Max in the flex-algo ASLA; the consumer
    /// recovers the Min bit-for-bit.
    #[test]
    fn peer_min_delay_round_trips_through_build_link_asla() {
        use isis_packet::IsisSubMinMaxLinkDelay;
        let am = AffinityMap::new();
        let extra = vec![NeighSubTlv::MinMaxLinkDelay(IsisSubMinMaxLinkDelay {
            anomalous: false,
            min_delay: 1_500,
            max_delay: 2_000,
        })];
        let built = build_link_asla(&BTreeSet::new(), &am, extra).expect("ASLA");
        let entry = reach_entry(vec![NeighSubTlv::Asla(built)]);
        assert_eq!(peer_min_delay(&entry), Some(1_500));
    }

    #[test]
    fn parse_asla_flex_algo_bitmap_round_trips_through_build_link_asla() {
        // Build an ASLA on the producer side, parse it on the
        // consumer side — the bitmap must round-trip bit-for-bit.
        let mut am = AffinityMap::new();
        for (name, bit) in [("blue", "0"), ("red", "200")] {
            am.exec(
                "/affinity-map/affinity/bit-position".into(),
                args(&[name, bit]),
                ConfigOp::Set,
            )
            .unwrap();
            am.commit();
        }
        let asla = build_link_asla(&affinity_set(&["blue", "red"]), &am, Vec::new()).expect("ASLA");
        let parsed = parse_asla_flex_algo_bitmap(&asla).expect("bitmap");
        // bit 0 in word 0, bit (200 - 6*32 = 8) in word 6.
        assert_eq!(parsed.words.len(), 7);
        assert!(parsed.get(0));
        assert!(parsed.get(200));
        assert!(!parsed.get(1));
    }

    #[test]
    fn build_link_asla_returns_none_for_empty_affinity() {
        let am = AffinityMap::new();
        assert!(build_link_asla(&BTreeSet::new(), &am, Vec::new()).is_none());
    }

    #[test]
    fn build_link_asla_returns_none_when_all_names_unresolved() {
        let am = AffinityMap::new();
        // `blue` is referenced but the affinity-map is empty.
        assert!(build_link_asla(&affinity_set(&["blue"]), &am, Vec::new()).is_none());
    }

    #[test]
    fn build_link_asla_emits_sabm_flex_algo_and_admin_grp() {
        let mut am = AffinityMap::new();
        for (name, bit) in [("blue", "0"), ("low-lat", "4"), ("red", "31")] {
            am.exec(
                "/affinity-map/affinity/bit-position".into(),
                args(&[name, bit]),
                ConfigOp::Set,
            )
            .unwrap();
            am.commit();
        }
        let asla = build_link_asla(&affinity_set(&["blue", "low-lat", "red"]), &am, Vec::new())
            .expect("ASLA expected");
        // L-flag clear, SABM = [0x10] (X-bit only), UDABM empty.
        assert!(!asla.l_flag);
        assert_eq!(asla.sabm, vec![SABM_FLEX_ALGO]);
        assert!(asla.udabm.is_empty());
        // One nested sub-TLV: AdminGrp with bits 0, 4, 31 packed into
        // the first 32-bit word.
        assert_eq!(asla.subs.len(), 1);
        match &asla.subs[0] {
            NeighSubTlv::AdminGrp(ag) => {
                assert_eq!(ag.groups.len(), 1);
                let w = ag.groups[0];
                assert!(w & (1 << 0) != 0, "bit 0 (blue) missing");
                assert!(w & (1 << 4) != 0, "bit 4 (low-lat) missing");
                assert!(w & (1 << 31) != 0, "bit 31 (red) missing");
                // No unexpected bits.
                let expected = (1u32 << 0) | (1u32 << 4) | (1u32 << 31);
                assert_eq!(w, expected);
            }
            other => panic!("expected AdminGrp, got {other:?}"),
        }
    }

    #[test]
    fn build_link_asla_grows_bitmap_to_multiple_words() {
        let mut am = AffinityMap::new();
        for (name, bit) in [("a", "0"), ("b", "32"), ("c", "200")] {
            am.exec(
                "/affinity-map/affinity/bit-position".into(),
                args(&[name, bit]),
                ConfigOp::Set,
            )
            .unwrap();
            am.commit();
        }
        let asla = build_link_asla(&affinity_set(&["a", "b", "c"]), &am, Vec::new()).expect("ASLA");
        match &asla.subs[0] {
            NeighSubTlv::AdminGrp(ag) => {
                // bit 200 lives in word 6 (200/32=6), so we need
                // at least 7 words.
                assert_eq!(ag.groups.len(), 7);
            }
            _ => panic!("expected AdminGrp"),
        }
    }

    #[test]
    fn build_link_asla_nests_te_metrics_without_affinity() {
        use isis_packet::{IsisSubMinMaxLinkDelay, IsisSubUniLinkDelay};

        // No affinity, but delay sub-TLVs present → the ASLA is still
        // emitted, carrying only the TE metrics (no AdminGrp).
        let am = AffinityMap::new();
        let extra = vec![
            NeighSubTlv::UniLinkDelay(IsisSubUniLinkDelay {
                anomalous: false,
                delay: 1_000,
            }),
            NeighSubTlv::MinMaxLinkDelay(IsisSubMinMaxLinkDelay {
                anomalous: false,
                min_delay: 900,
                max_delay: 1_200,
            }),
        ];
        let asla = build_link_asla(&BTreeSet::new(), &am, extra).expect("ASLA");
        assert_eq!(asla.sabm, vec![SABM_FLEX_ALGO]);
        assert!(
            !asla
                .subs
                .iter()
                .any(|s| matches!(s, NeighSubTlv::AdminGrp(_))),
            "no affinity → no AdminGrp"
        );
        assert!(matches!(asla.subs[0], NeighSubTlv::UniLinkDelay(_)));
        assert!(matches!(asla.subs[1], NeighSubTlv::MinMaxLinkDelay(_)));
    }

    #[test]
    fn build_link_asla_combines_affinity_and_te_metrics() {
        use isis_packet::IsisSubMinMaxLinkDelay;

        let mut am = AffinityMap::new();
        am.exec(
            "/affinity-map/affinity/bit-position".into(),
            args(&["blue", "0"]),
            ConfigOp::Set,
        )
        .unwrap();
        am.commit();
        let extra = vec![NeighSubTlv::MinMaxLinkDelay(IsisSubMinMaxLinkDelay {
            anomalous: false,
            min_delay: 900,
            max_delay: 1_200,
        })];
        let asla = build_link_asla(&affinity_set(&["blue"]), &am, extra).expect("ASLA");
        // AdminGrp first (affinity), then the delay sub-TLV.
        assert!(matches!(asla.subs[0], NeighSubTlv::AdminGrp(_)));
        assert!(matches!(asla.subs[1], NeighSubTlv::MinMaxLinkDelay(_)));
    }

    // ── Winning-FAD selection and participation (RFC 9350 §5.3) ──

    fn sys(n: u8) -> IsisSysId {
        IsisSysId {
            id: [0, 0, 0, 0, 0, n],
        }
    }

    fn fad(algo: u8, priority: u8, subs: Vec<FadSubTlv>) -> IsisSubFlexAlgoDef {
        IsisSubFlexAlgoDef {
            flex_algorithm: algo,
            metric_type: 0,
            calc_type: 0,
            priority,
            subs,
        }
    }

    fn exclude(bit: u16) -> FadSubTlv {
        let mut group = ExtAdminGroup::default();
        group.set(bit);
        FadSubTlv::ExcludeAg(IsisSubFadExcludeAg { group })
    }

    fn flags(m_flag: bool, other: u8) -> FadSubTlv {
        FadSubTlv::Flags(IsisSubFadFlags {
            m_flag,
            other,
            trailing: Vec::new(),
        })
    }

    fn peers(
        list: &[(u8, IsisSubFlexAlgoDef)],
    ) -> BTreeMap<IsisSysId, BTreeMap<u8, IsisSubFlexAlgoDef>> {
        let mut map: BTreeMap<IsisSysId, BTreeMap<u8, IsisSubFlexAlgoDef>> = BTreeMap::new();
        for (n, f) in list {
            map.entry(sys(*n))
                .or_default()
                .insert(f.flex_algorithm, f.clone());
        }
        map
    }

    /// RFC 9350 §5.3: the greatest priority wins; a tie goes to the
    /// greatest System-ID; this router's own definition competes like any
    /// other.
    #[test]
    fn the_winning_fad_is_greatest_priority_then_system_id() {
        let own = BTreeMap::from([(128, fad(128, 150, vec![]))]);
        let p = peers(&[(2, fad(128, 200, vec![])), (3, fad(128, 200, vec![]))]);
        let w = winning_fad(128, &p, &own, &sys(9)).expect("winner");
        assert_eq!(
            (w.originator, w.fad.priority),
            (sys(3), 200),
            "tie → greater id"
        );

        let own = BTreeMap::from([(128, fad(128, 200, vec![]))]);
        let w = winning_fad(128, &p, &own, &sys(1)).expect("winner");
        assert_eq!(w.originator, sys(3), "our own ties, and loses on System-ID");

        let own = BTreeMap::from([(128, fad(128, 201, vec![]))]);
        let w = winning_fad(128, &p, &own, &sys(1)).expect("winner");
        assert_eq!(w.originator, sys(1), "our own higher priority wins");

        assert_eq!(
            winning_fad(129, &p, &own, &sys(1)),
            None,
            "nobody defines 129"
        );
    }

    /// RFC 9350 §6: one router's definitions are merged. A FAD sub-TLV
    /// with a constraint twice, or an algorithm below 128, is ignored; the
    /// first header wins; each constraint's first occurrence wins; Exclude
    /// SRLG and unknown sub-TLVs accumulate.
    #[test]
    fn a_routers_fads_merge_as_rfc_9350_section_6_says() {
        let srlg = |id| FadSubTlv::ExcludeSrlg(IsisSubFadExcludeSrlg { srlgs: vec![id] });
        let unknown = |code| {
            FadSubTlv::Unknown(isis_packet::IsisSubTlvUnknown {
                code,
                len: 0,
                data: vec![],
            })
        };
        let merged = merge_fads(&[
            fad(127, 255, vec![]),
            fad(128, 250, vec![exclude(1), exclude(2)]), // invalid: twice
            fad(128, 100, vec![exclude(3), srlg(10), unknown(200)]),
            fad(128, 200, vec![exclude(4), srlg(11), unknown(201)]),
        ]);
        assert!(!merged.contains_key(&127), "algorithm 127 is ignored");
        let m = &merged[&128];
        assert_eq!(m.priority, 100, "the first valid header");
        assert_eq!(
            m.subs,
            vec![exclude(3), srlg(10), unknown(200), srlg(11), unknown(201)]
        );
    }

    /// RFC 9350 §5.3: every element of the winning definition must be
    /// supported, or the router stops participating.
    #[test]
    fn an_unsupported_winning_fad_stops_participation() {
        let base = fad(128, 128, vec![exclude(5)]);
        let c = fad_constraints(&base).expect("supported");
        assert!(c.exclude_any.get(5));
        assert_eq!(c.metric_type, FadMetricType::Igp);

        let with = |f: IsisSubFlexAlgoDef| fad_constraints(&f);
        let mut calc = base.clone();
        calc.calc_type = 1;
        assert_eq!(with(calc), Err(Unsupported::CalcType(1)));
        let mut te = base.clone();
        te.metric_type = 2;
        assert_eq!(with(te), Err(Unsupported::MetricType(2)), "TE-default");
        let mut delay = base.clone();
        delay.metric_type = 1;
        assert_eq!(
            with(delay).map(|c| c.metric_type),
            Ok(FadMetricType::MinUnidirLinkDelay)
        );
        assert_eq!(
            with(fad(128, 128, vec![flags(true, 0)])),
            Err(Unsupported::PrefixMetric)
        );
        assert_eq!(
            with(fad(128, 128, vec![flags(false, 0x01)])),
            Err(Unsupported::Flag)
        );
        assert!(
            with(fad(128, 128, vec![flags(false, 0)])).is_ok(),
            "no flag set"
        );
        let srlg = |ids: Vec<u32>| FadSubTlv::ExcludeSrlg(IsisSubFadExcludeSrlg { srlgs: ids });
        assert_eq!(
            with(fad(128, 128, vec![srlg(vec![7])])),
            Err(Unsupported::ExcludeSrlg)
        );
        assert!(
            with(fad(128, 128, vec![srlg(vec![])])).is_ok(),
            "excludes nothing"
        );
        let unknown = FadSubTlv::Unknown(isis_packet::IsisSubTlvUnknown {
            code: 252,
            len: 3,
            data: vec![0, 0, 1],
        });
        assert_eq!(
            with(fad(128, 128, vec![unknown])),
            Err(Unsupported::SubTlv(252))
        );
    }

    /// Selection covers configured algorithms only, computes with the
    /// *winner's* constraints — not this router's configuration — and an
    /// unadvertised local definition is no candidate: with none advertised
    /// anywhere, the router does not participate.
    #[test]
    fn selection_computes_with_the_winner_not_local_config() {
        let mut fa = FlexAlgoConfig::new("/router/isis/flex-algo");
        for (path, args_) in [
            ("/router/isis/flex-algo/priority", &["128", "100"][..]),
            ("/router/isis/flex-algo/priority", &["129", "100"]),
        ] {
            fa.exec(path.into(), args(args_), ConfigOp::Set).unwrap();
            fa.commit();
        }
        let am = AffinityMap::new();
        let srlg = BTreeMap::new();
        let p = peers(&[
            (2, fad(128, 200, vec![exclude(7)])),
            (2, fad(130, 200, vec![])),
        ]);
        let sel = fad_selection(&fa, &am, &srlg, &p, &sys(1));

        assert_eq!(
            sel.keys().copied().collect::<Vec<_>>(),
            vec![128, 129],
            "130 is not ours"
        );
        let c = sel[&128]
            .participation
            .constraints()
            .expect("participating");
        assert!(c.exclude_any.get(7), "the peer's definition, not ours");
        assert_eq!(
            sel[&128].winner.as_ref().map(|w| w.originator),
            Some(sys(2))
        );
        assert_eq!(
            sel[&129].participation,
            Participation::No(Unsupported::NoDefinition),
            "our definition is not advertised"
        );
        assert_eq!(participating(&sel), BTreeSet::from([128]));
        assert_eq!(
            sr_algorithms_participating(&participating(&sel)),
            vec![Algo::Spf, Algo::FlexAlgo(128)]
        );

        // Advertising it makes it a candidate, and ours is the only one.
        fa.exec(
            "/router/isis/flex-algo/advertise-definition".into(),
            args(&["129", "true"]),
            ConfigOp::Set,
        )
        .unwrap();
        fa.commit();
        let sel = fad_selection(&fa, &am, &srlg, &p, &sys(1));
        assert!(matches!(sel[&129].participation, Participation::Yes(_)));
        assert_eq!(
            sel[&129].winner.as_ref().map(|w| w.originator),
            Some(sys(1))
        );
    }

    #[test]
    fn build_fad_subs_skips_entries_without_advertise_flag() {
        let mut fa = FlexAlgoConfig::new("/router/isis/flex-algo");
        // Algo 128 — advertise-definition NOT set, so should be skipped.
        fa.exec(
            "/router/isis/flex-algo/priority".into(),
            args(&["128", "200"]),
            ConfigOp::Set,
        )
        .unwrap();
        fa.commit();
        // Algo 129 — advertise-definition set, should be emitted.
        fa.exec(
            "/router/isis/flex-algo/advertise-definition".into(),
            args(&["129", "true"]),
            ConfigOp::Set,
        )
        .unwrap();
        fa.commit();

        let am = AffinityMap::new();
        let srlg = BTreeMap::new();
        let subs = build_fad_subs(&fa, &am, &srlg);
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].flex_algorithm, 129);
        // Defaults: igp metric type, priority 128, no nested subs.
        assert_eq!(subs[0].metric_type, FadMetricType::Igp.wire());
        assert_eq!(subs[0].priority, 128);
        assert!(subs[0].subs.is_empty());
    }

    #[test]
    fn build_fad_subs_emits_exclude_ag_and_srlg() {
        let mut fa = FlexAlgoConfig::new("/router/isis/flex-algo");
        for (path, args_) in [
            (
                "/router/isis/flex-algo/advertise-definition",
                &["128", "true"][..],
            ),
            (
                "/router/isis/flex-algo/affinity/exclude-any",
                &["128", "blue"],
            ),
            ("/router/isis/flex-algo/srlg-exclude", &["128", "risk-A"]),
            ("/router/isis/flex-algo/prefix-metric", &["128", "true"]),
        ] {
            fa.exec(path.into(), args(args_), ConfigOp::Set).unwrap();
            fa.commit();
        }

        let mut am = AffinityMap::new();
        am.exec(
            "/affinity-map/affinity/bit-position".into(),
            args(&["blue", "4"]),
            ConfigOp::Set,
        )
        .unwrap();
        am.commit();

        let mut srlg = BTreeMap::new();
        srlg.insert(
            "risk-A".to_string(),
            SrlgGroup {
                name: "risk-A".into(),
                value: 100,
            },
        );

        let subs = build_fad_subs(&fa, &am, &srlg);
        assert_eq!(subs.len(), 1);
        let fad = &subs[0];
        assert_eq!(fad.flex_algorithm, 128);
        // Exactly three nested sub-TLVs: ExcludeAg, Flags (M=1), ExcludeSrlg.
        assert_eq!(fad.subs.len(), 3);
        let mut has_excl = false;
        let mut has_flags = false;
        let mut has_srlg = false;
        for sub in &fad.subs {
            match sub {
                FadSubTlv::ExcludeAg(v) => {
                    has_excl = true;
                    assert!(v.group.get(4));
                }
                FadSubTlv::Flags(v) => {
                    has_flags = true;
                    assert!(v.m_flag);
                }
                FadSubTlv::ExcludeSrlg(v) => {
                    has_srlg = true;
                    assert_eq!(v.srlgs, vec![100]);
                }
                _ => panic!("unexpected sub: {sub:?}"),
            }
        }
        assert!(has_excl && has_flags && has_srlg);
    }

    #[test]
    fn build_fad_subs_drops_unresolved_affinity_names() {
        let mut fa = FlexAlgoConfig::new("/router/isis/flex-algo");
        fa.exec(
            "/router/isis/flex-algo/advertise-definition".into(),
            args(&["128", "true"]),
            ConfigOp::Set,
        )
        .unwrap();
        fa.exec(
            "/router/isis/flex-algo/affinity/exclude-any".into(),
            args(&["128", "ghost"]),
            ConfigOp::Set,
        )
        .unwrap();
        fa.commit();

        // Empty affinity map — `ghost` is referenced but not defined.
        let am = AffinityMap::new();
        let subs = build_fad_subs(&fa, &am, &BTreeMap::new());
        assert_eq!(subs.len(), 1);
        // No ExcludeAg sub-TLV emitted because the bitmap would be
        // empty — a 0-byte sub-TLV is meaningless on the wire.
        assert!(subs[0].subs.is_empty(), "got subs: {:?}", subs[0].subs);
    }
}
