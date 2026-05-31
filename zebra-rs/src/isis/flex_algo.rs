use std::collections::{BTreeMap, BTreeSet};

use isis_packet::neigh::IsisSubTlv as NeighSubTlv;
use isis_packet::{
    Algo, ExtAdminGroup, FadSubTlv, IsisSubAdminGrp, IsisSubAsla, IsisSubFadExcludeAg,
    IsisSubFadExcludeSrlg, IsisSubFadFlags, IsisSubFadIncludeAllAg, IsisSubFadIncludeAnyAg,
    IsisSubFlexAlgoDef, IsisSubPrefixSid, SidLabelValue,
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
    FadMetricType, FlexAlgoConfig, FlexAlgoEntry, link_passes_fad, local_link_affinity,
    sr_algorithms,
};

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

/// Extract the minimum unidirectional link delay (microseconds) from a
/// peer-advertised ASLA sub-TLV iff the SABM marks it for the
/// Flex-Algorithm application (X-bit). The value is the Min field of the
/// nested Min/Max Link Delay sub-TLV (RFC 8570 §4.2) — the RFC 9350 §6
/// metric-type 1 (min-unidir-link-delay) input. Returns `None` when the
/// X-bit is clear or no Min/Max Link Delay sub-TLV is nested. Mirrors
/// `parse_asla_flex_algo_bitmap` so SPF reads the same Min a sender
/// packs via `build_link_asla`.
pub fn parse_asla_min_delay(asla: &IsisSubAsla) -> Option<u32> {
    let first = asla.sabm.first()?;
    if first & SABM_FLEX_ALGO == 0 {
        return None;
    }
    for sub in &asla.subs {
        if let NeighSubTlv::MinMaxLinkDelay(d) = sub {
            return Some(d.min_delay);
        }
    }
    None
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
pub fn build_per_algo_prefix_sids(map: &BTreeMap<u8, SidLabelValue>) -> Vec<IsisSubPrefixSid> {
    map.iter()
        .map(|(&algo, sid)| IsisSubPrefixSid {
            flags: 0.into(),
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
flex_algo_cb!(cb_ti_lfa, "/router/isis/flex-algo/fast-reroute/ti-lfa");

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
    isis.callback_add("/router/isis/flex-algo/fast-reroute/ti-lfa", cb_ti_lfa);
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
        assert!(build_per_algo_prefix_sids(&map).is_empty());
    }

    #[test]
    fn build_per_algo_prefix_sids_emits_one_per_algo_in_sorted_order() {
        let mut map: BTreeMap<u8, SidLabelValue> = BTreeMap::new();
        map.insert(129, SidLabelValue::Index(1129));
        map.insert(128, SidLabelValue::Index(1128));
        let sids = build_per_algo_prefix_sids(&map);
        assert_eq!(sids.len(), 2);
        // BTreeMap iterates ascending → algo 128 first, 129 second.
        assert_eq!(sids[0].algo, Algo::FlexAlgo(128));
        assert_eq!(sids[0].sid, SidLabelValue::Index(1128));
        assert_eq!(sids[1].algo, Algo::FlexAlgo(129));
        assert_eq!(sids[1].sid, SidLabelValue::Index(1129));
    }

    #[test]
    fn build_per_algo_prefix_sids_preserves_label_vs_index_form() {
        let mut map: BTreeMap<u8, SidLabelValue> = BTreeMap::new();
        map.insert(128, SidLabelValue::Index(42));
        map.insert(129, SidLabelValue::Label(20128));
        let sids = build_per_algo_prefix_sids(&map);
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
        let sids = build_per_algo_prefix_sids(&map);
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

    #[test]
    fn parse_asla_min_delay_returns_min_when_x_bit_set() {
        use isis_packet::IsisSubMinMaxLinkDelay;
        let asla = IsisSubAsla {
            l_flag: false,
            sabm: vec![SABM_FLEX_ALGO],
            udabm: vec![],
            subs: vec![NeighSubTlv::MinMaxLinkDelay(IsisSubMinMaxLinkDelay {
                anomalous: false,
                min_delay: 900,
                max_delay: 1_200,
            })],
        };
        assert_eq!(parse_asla_min_delay(&asla), Some(900));
    }

    #[test]
    fn parse_asla_min_delay_returns_none_without_x_bit() {
        use isis_packet::IsisSubMinMaxLinkDelay;
        // SABM = [0x80] sets R-bit (RSVP-TE) but not X-bit.
        let asla = IsisSubAsla {
            l_flag: false,
            sabm: vec![0x80],
            udabm: vec![],
            subs: vec![NeighSubTlv::MinMaxLinkDelay(IsisSubMinMaxLinkDelay {
                anomalous: false,
                min_delay: 900,
                max_delay: 1_200,
            })],
        };
        assert!(parse_asla_min_delay(&asla).is_none());
    }

    #[test]
    fn parse_asla_min_delay_returns_none_without_min_max_sub() {
        // X-bit set but only an AdminGrp nested — no Min/Max delay.
        let asla = IsisSubAsla {
            l_flag: false,
            sabm: vec![SABM_FLEX_ALGO],
            udabm: vec![],
            subs: vec![NeighSubTlv::AdminGrp(IsisSubAdminGrp { groups: vec![0x1] })],
        };
        assert!(parse_asla_min_delay(&asla).is_none());
    }

    #[test]
    fn parse_asla_min_delay_round_trips_through_build_link_asla() {
        use isis_packet::IsisSubMinMaxLinkDelay;
        // Producer nests Min/Max in the flex-algo ASLA; the consumer
        // recovers the Min bit-for-bit.
        let am = AffinityMap::new();
        let extra = vec![NeighSubTlv::MinMaxLinkDelay(IsisSubMinMaxLinkDelay {
            anomalous: false,
            min_delay: 1_500,
            max_delay: 2_000,
        })];
        let asla = build_link_asla(&BTreeSet::new(), &am, extra).expect("ASLA");
        assert_eq!(parse_asla_min_delay(&asla), Some(1_500));
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
