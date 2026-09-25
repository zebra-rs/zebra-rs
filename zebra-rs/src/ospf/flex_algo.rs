//! OSPF Flexible Algorithm (RFC 9350 §6) wire builders. The
//! protocol-neutral config model + constraint engine live in
//! `crate::flex_algo`; this module turns the committed config into the
//! ospf-packet TLV structs that ride in the Router Information and
//! Extended-Link Opaque LSAs. Parallel to `isis::flex_algo`'s
//! isis-packet builders.

use std::collections::{BTreeMap, BTreeSet};

use ospf_packet::{
    ExtAdminGroup, ExtLinkSubTlv, FadFlags, FadSrlg, OSPF_SABM_FLEX_ALGO, OSPFV3_SABM_FLEX_ALGO,
    OspfAslaSubSubTlv, OspfAslaSubTlv, OspfFadSubTlv, Ospfv3AslaSubSubTlv, Ospfv3AslaSubTlv,
    Ospfv3FadSubTlv, Ospfv3FadTlv, Ospfv3SubTlv, RouterInfoTlvFad,
};

use crate::flex_algo::selection::{Fad, FadSub};
use crate::flex_algo::{
    AffinityMap, FadMetricType, FlexAlgoConfig, SrlgGroup, local_link_affinity,
};

/// An OSPFv2 definition as the protocol-neutral selection reads it (see
/// `crate::flex_algo::selection`).
pub fn fad_view(fad: &RouterInfoTlvFad) -> Fad {
    Fad {
        algo: fad.flex_algorithm,
        metric_type: fad.metric_type,
        calc_type: fad.calc_type,
        priority: fad.priority,
        subs: fad
            .subs
            .iter()
            .map(|sub| match sub {
                OspfFadSubTlv::ExcludeAg(g) => FadSub::ExcludeAny(g.clone()),
                OspfFadSubTlv::IncludeAnyAg(g) => FadSub::IncludeAny(g.clone()),
                OspfFadSubTlv::IncludeAllAg(g) => FadSub::IncludeAll(g.clone()),
                OspfFadSubTlv::Flags(f) => FadSub::Flags {
                    prefix_metric: f.m_flag,
                    unknown: f.has_unknown(),
                },
                OspfFadSubTlv::ExcludeSrlg(s) => FadSub::ExcludeSrlg(s.srlgs.clone()),
                OspfFadSubTlv::Unknown(u) => FadSub::Unknown(u.typ),
            })
            .collect(),
        truncated: !fad.trailing.is_empty(),
    }
}

/// Build the OSPF FAD TLVs (RFC 9350 §6.1) this router originates
/// inside the Router Information Opaque LSA — one `RouterInfoTlvFad`
/// per `FlexAlgoConfig.config` entry with `advertise_definition ==
/// true`. Entries with the flag absent or false stay purely local
/// (the router still participates via the SR-Algorithm TLV, but
/// originates no definition).
///
/// Affinity names resolve against `am` to RFC 7308 Extended Admin
/// Group bit positions; SRLG names resolve against `srlg_groups` to
/// 32-bit identifiers. Unresolved names are silently dropped (LSA-gen
/// is best-effort), matching the IS-IS `build_fad_subs`.
pub fn build_fad(
    fa: &FlexAlgoConfig,
    am: &AffinityMap,
    srlg_groups: &BTreeMap<String, SrlgGroup>,
) -> Vec<RouterInfoTlvFad> {
    let mut out = Vec::new();
    for (&algo, entry) in &fa.config {
        if entry.advertise_definition != Some(true) {
            continue;
        }
        let metric_type = entry.metric_type.unwrap_or(FadMetricType::Igp).wire();
        let priority = entry.priority.unwrap_or(128);

        let mut subs = Vec::new();

        if !entry.exclude_any.is_empty() {
            let group = local_link_affinity(&entry.exclude_any, am);
            if !group.words.is_empty() {
                subs.push(OspfFadSubTlv::ExcludeAg(group));
            }
        }
        if !entry.include_any.is_empty() {
            let group = local_link_affinity(&entry.include_any, am);
            if !group.words.is_empty() {
                subs.push(OspfFadSubTlv::IncludeAnyAg(group));
            }
        }
        if !entry.include_all.is_empty() {
            let group = local_link_affinity(&entry.include_all, am);
            if !group.words.is_empty() {
                subs.push(OspfFadSubTlv::IncludeAllAg(group));
            }
        }
        if entry.prefix_metric == Some(true) {
            subs.push(OspfFadSubTlv::Flags(FadFlags {
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
                subs.push(OspfFadSubTlv::ExcludeSrlg(FadSrlg { srlgs: ids }));
            }
        }

        out.push(RouterInfoTlvFad {
            flex_algorithm: algo,
            metric_type,
            calc_type: 0, // Only SPF defined today (RFC 9350 §5.1).
            priority,
            subs,
            trailing: Vec::new(),
        });
    }
    out
}

/// OSPFv3 sibling of `build_fad`: build the FAD TLVs (RFC 9350 §7.1)
/// this router originates inside its E-Router-LSA. Identical constraint
/// logic to the v2 builder — the only difference is the ospf-packet v3
/// wire types (`Ospfv3FadTlv` etc., which use the OSPFv3 codepoints).
pub fn build_fad_v3(
    fa: &FlexAlgoConfig,
    am: &AffinityMap,
    srlg_groups: &BTreeMap<String, SrlgGroup>,
) -> Vec<Ospfv3FadTlv> {
    let mut out = Vec::new();
    for (&algo, entry) in &fa.config {
        if entry.advertise_definition != Some(true) {
            continue;
        }
        let metric_type = entry.metric_type.unwrap_or(FadMetricType::Igp).wire();
        let priority = entry.priority.unwrap_or(128);

        let mut subs = Vec::new();

        if !entry.exclude_any.is_empty() {
            let group = local_link_affinity(&entry.exclude_any, am);
            if !group.words.is_empty() {
                subs.push(Ospfv3FadSubTlv::ExcludeAg(group));
            }
        }
        if !entry.include_any.is_empty() {
            let group = local_link_affinity(&entry.include_any, am);
            if !group.words.is_empty() {
                subs.push(Ospfv3FadSubTlv::IncludeAnyAg(group));
            }
        }
        if !entry.include_all.is_empty() {
            let group = local_link_affinity(&entry.include_all, am);
            if !group.words.is_empty() {
                subs.push(Ospfv3FadSubTlv::IncludeAllAg(group));
            }
        }
        if entry.prefix_metric == Some(true) {
            subs.push(Ospfv3FadSubTlv::Flags(FadFlags {
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
                subs.push(Ospfv3FadSubTlv::ExcludeSrlg(FadSrlg { srlgs: ids }));
            }
        }

        out.push(Ospfv3FadTlv {
            flex_algorithm: algo,
            metric_type,
            calc_type: 0, // Only SPF defined today (RFC 9350 §5.1).
            priority,
            subs,
        });
    }
    out
}

/// Build the per-link ASLA sub-TLV (RFC 9492) carrying this link's
/// affinity (Extended Admin Group, RFC 7308) and any RFC 7471 TE
/// metrics (`extra` — delay/jitter/loss link-attribute sub-sub-TLVs)
/// for the Flexible Algorithm application. Returns `None` only when the
/// ASLA would carry nothing: no affinity name resolves to a bit *and*
/// `extra` is empty — an attribute-less ASLA would be a meaningless wire
/// artifact.
///
/// The SABM is a single 4-octet word with only the Flex-Algorithm
/// X-bit set (`OSPF_SABM_FLEX_ALGO`, RFC 9350 §12); OSPF requires the
/// mask length to be 0/4/8 octets (RFC 9492 §2). UDABM is empty.
pub fn build_link_asla(
    affinity: &BTreeSet<String>,
    am: &AffinityMap,
    extra: Vec<OspfAslaSubSubTlv>,
) -> Option<ExtLinkSubTlv> {
    let group = local_link_affinity(affinity, am);
    let mut subs = Vec::new();
    if !group.words.is_empty() {
        subs.push(OspfAslaSubSubTlv::ExtAdminGroup(group));
    }
    subs.extend(extra);
    if subs.is_empty() {
        return None;
    }
    Some(ExtLinkSubTlv::Asla(OspfAslaSubTlv {
        sabm: vec![OSPF_SABM_FLEX_ALGO, 0, 0, 0],
        udabm: Vec::new(),
        subs,
    }))
}

/// The ASLA advertisements on one link that apply to Flex-Algorithm,
/// and the attributes read out of them — RFC 9492 §5.
///
/// The selection is by *presence*, not by content: zero-length-mask
/// attributes "MUST be used ... when no link attribute advertisements
/// with a non-zero-length Application Identifier Bit Mask and a
/// matching Application Identifier Bit set are present for a given
/// link. Otherwise, such link attribute advertisements MUST NOT be
/// used." So an explicit Flex-Algorithm advertisement carrying only an
/// admin group still excludes a generic one carrying delay: delay is
/// then simply not advertised for this application, and metric-type 1
/// prunes the link. Asking instead "did an explicit ASLA supply this
/// attribute?" quietly borrows the generic value, which is the same
/// mistake as ignoring zero-mask advertisements altogether, in the
/// other direction.
///
/// Selecting the set once and reading every attribute from it also
/// keeps the consumers consistent: delay and affinity must agree about
/// which advertisements apply, or a link can be costed from one ASLA
/// and constrained by another.
macro_rules! asla_readers {
    ($applicable:ident, $delay:ident, $admin_group:ident, $sub:ty, $asla:ty, $variant:path) => {
        fn $applicable(subs: &[$sub]) -> Vec<&$asla> {
            let mut explicit = Vec::new();
            let mut any_application = Vec::new();
            for sub in subs {
                if let $variant(asla) = sub {
                    // RFC 9492 §5: an ASLA whose mask lengths are not
                    // 0, 4 or 8 is ignored outright. It must not count
                    // as an explicit advertisement either — otherwise a
                    // malformed container suppresses a valid zero-mask
                    // one under the presence rule and prunes the link.
                    if !asla.has_valid_masks() {
                        continue;
                    }
                    if asla.is_flex_algo() {
                        explicit.push(asla);
                    } else if asla.is_any_application() {
                        any_application.push(asla);
                    }
                }
            }
            if explicit.is_empty() {
                any_application
            } else {
                explicit
            }
        }

        /// Min unidirectional delay for metric-type 1, or `None` when
        /// the applicable advertisements carry none.
        pub fn $delay(subs: &[$sub]) -> Option<u32> {
            $applicable(subs)
                .into_iter()
                .find_map(|asla| asla.min_unidir_delay())
        }

        /// Extended Admin Group for the FAD constraints, from the same
        /// applicable set.
        pub fn $admin_group(subs: &[$sub]) -> Option<&ExtAdminGroup> {
            $applicable(subs)
                .into_iter()
                .find_map(|asla| asla.ext_admin_group())
        }
    };
}

asla_readers!(
    applicable_aslas_v2,
    asla_min_delay_v2,
    asla_admin_group_v2,
    ExtLinkSubTlv,
    OspfAslaSubTlv,
    ExtLinkSubTlv::Asla
);
asla_readers!(
    applicable_aslas_v3,
    asla_min_delay_v3,
    asla_admin_group_v3,
    Ospfv3SubTlv,
    Ospfv3AslaSubTlv,
    Ospfv3SubTlv::Asla
);

/// OSPFv3 sibling of `build_link_asla`: build the per-link ASLA sub-TLV
/// (RFC 9492) that rides as an `Ospfv3SubTlv::Asla` on the E-Router-LSA
/// Router-Link TLV, carrying this link's affinity and any RFC 7471 TE
/// metrics. Same SABM X-bit framing and same "nothing to say, say
/// nothing" guard as the v2 builder; the wire types differ throughout
/// (OSPFv3 sub-TLV 11, Extended Admin Group 21, performance metrics
/// 13-16).
pub fn build_link_asla_v3(
    affinity: &BTreeSet<String>,
    am: &AffinityMap,
    extra: Vec<Ospfv3AslaSubSubTlv>,
) -> Option<Ospfv3SubTlv> {
    let group = local_link_affinity(affinity, am);
    let mut subs = Vec::new();
    if !group.words.is_empty() {
        subs.push(Ospfv3AslaSubSubTlv::ExtAdminGroup(group));
    }
    subs.extend(extra);
    if subs.is_empty() {
        return None;
    }
    Some(Ospfv3SubTlv::Asla(Ospfv3AslaSubTlv {
        sabm: vec![OSPFV3_SABM_FLEX_ALGO, 0, 0, 0],
        udabm: Vec::new(),
        subs,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Args, ConfigOp};
    use std::collections::VecDeque;

    fn args(items: &[&str]) -> Args {
        Args(items.iter().map(|s| s.to_string()).collect::<VecDeque<_>>())
    }

    fn set(fa: &mut FlexAlgoConfig, leaf: &str, vals: &[&str]) {
        fa.exec(
            format!("/router/ospf/flex-algo{leaf}"),
            args(vals),
            ConfigOp::Set,
        )
        .unwrap();
        fa.commit();
    }

    /// The selection reads an OSPFv2 definition as it was received: each
    /// constraint, the flags — unknown bits included — the SRLGs, any
    /// sub-TLV it could not read, and whether the definition was cut short.
    #[test]
    fn fad_view_keeps_what_selection_needs() {
        use ospf_packet::RouterInfoTlvUnknown;
        let mut g = ExtAdminGroup::default();
        g.set(5);
        let fad = RouterInfoTlvFad {
            flex_algorithm: 130,
            metric_type: 1,
            calc_type: 0,
            priority: 77,
            subs: vec![
                OspfFadSubTlv::ExcludeAg(g.clone()),
                OspfFadSubTlv::IncludeAnyAg(g.clone()),
                OspfFadSubTlv::IncludeAllAg(g.clone()),
                OspfFadSubTlv::Flags(FadFlags {
                    m_flag: false,
                    other: 0x01,
                    trailing: Vec::new(),
                }),
                OspfFadSubTlv::ExcludeSrlg(FadSrlg { srlgs: vec![9] }),
                OspfFadSubTlv::Unknown(RouterInfoTlvUnknown {
                    typ: 1,
                    len: 6,
                    values: vec![0; 6],
                }),
            ],
            trailing: vec![0, 1, 0, 8],
        };
        let view = fad_view(&fad);
        assert_eq!(
            (view.algo, view.metric_type, view.calc_type, view.priority),
            (130, 1, 0, 77)
        );
        assert_eq!(
            view.subs,
            vec![
                FadSub::ExcludeAny(g.clone()),
                FadSub::IncludeAny(g.clone()),
                FadSub::IncludeAll(g),
                FadSub::Flags {
                    prefix_metric: false,
                    unknown: true,
                },
                FadSub::ExcludeSrlg(vec![9]),
                FadSub::Unknown(1),
            ]
        );
        assert!(view.truncated);
    }

    #[test]
    fn build_fad_skips_entries_without_advertise_flag() {
        let mut fa = FlexAlgoConfig::new("/router/ospf/flex-algo");
        // Algo 128 — no advertise-definition, should be skipped.
        set(&mut fa, "/priority", &["128", "200"]);
        // Algo 129 — advertise-definition set, should be emitted.
        set(&mut fa, "/advertise-definition", &["129", "true"]);

        let am = AffinityMap::new();
        let srlg = BTreeMap::new();
        let fads = build_fad(&fa, &am, &srlg);
        assert_eq!(fads.len(), 1);
        assert_eq!(fads[0].flex_algorithm, 129);
        assert_eq!(fads[0].metric_type, FadMetricType::Igp.wire());
        assert_eq!(fads[0].priority, 128);
        assert!(fads[0].subs.is_empty());
    }

    #[test]
    fn build_fad_emits_exclude_ag_and_srlg_and_flags() {
        let mut fa = FlexAlgoConfig::new("/router/ospf/flex-algo");
        set(&mut fa, "/advertise-definition", &["128", "true"]);
        set(&mut fa, "/metric-type", &["128", "min-unidir-link-delay"]);
        set(&mut fa, "/affinity/exclude-any", &["128", "blue"]);
        set(&mut fa, "/srlg-exclude", &["128", "risk-a"]);
        set(&mut fa, "/prefix-metric", &["128", "true"]);

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
            "risk-a".to_string(),
            SrlgGroup {
                name: "risk-a".into(),
                value: 100,
            },
        );

        let fads = build_fad(&fa, &am, &srlg);
        assert_eq!(fads.len(), 1);
        let fad = &fads[0];
        assert_eq!(fad.flex_algorithm, 128);
        assert_eq!(fad.metric_type, FadMetricType::MinUnidirLinkDelay.wire());

        let mut has_excl = false;
        let mut has_flags = false;
        let mut has_srlg = false;
        for sub in &fad.subs {
            match sub {
                OspfFadSubTlv::ExcludeAg(g) => {
                    has_excl = true;
                    assert!(g.get(4));
                }
                OspfFadSubTlv::Flags(f) => {
                    has_flags = true;
                    assert!(f.m_flag);
                }
                OspfFadSubTlv::ExcludeSrlg(s) => {
                    has_srlg = true;
                    assert_eq!(s.srlgs, vec![100]);
                }
                other => panic!("unexpected sub: {other:?}"),
            }
        }
        assert!(has_excl && has_flags && has_srlg);
    }

    #[test]
    fn build_fad_drops_unresolved_affinity_names() {
        let mut fa = FlexAlgoConfig::new("/router/ospf/flex-algo");
        set(&mut fa, "/advertise-definition", &["128", "true"]);
        set(&mut fa, "/affinity/exclude-any", &["128", "ghost"]);

        // Empty affinity map — `ghost` resolves to nothing, so no
        // ExcludeAg sub-TLV (a 0-byte bitmap is meaningless on wire).
        let am = AffinityMap::new();
        let fads = build_fad(&fa, &am, &BTreeMap::new());
        assert_eq!(fads.len(), 1);
        assert!(fads[0].subs.is_empty(), "got subs: {:?}", fads[0].subs);
    }

    fn affinity_set(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn build_link_asla_emits_flex_algo_admin_group() {
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
        let ExtLinkSubTlv::Asla(a) = &asla else {
            panic!("expected Asla, got {asla:?}");
        };
        assert!(a.is_flex_algo(), "SABM X-bit must be set");
        assert_eq!(a.sabm.len(), 4, "OSPF SABM must be 0/4/8 octets");
        let g = a.ext_admin_group().expect("admin group");
        assert!(g.get(0) && g.get(200) && !g.get(1));
    }

    #[test]
    fn build_link_asla_v3_emits_flex_algo_admin_group() {
        use ospf_packet::Ospfv3SubTlv;

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
        let asla =
            build_link_asla_v3(&affinity_set(&["blue", "red"]), &am, Vec::new()).expect("ASLA");
        let Ospfv3SubTlv::Asla(a) = &asla else {
            panic!("expected Asla, got {asla:?}");
        };
        assert!(a.is_flex_algo(), "SABM X-bit must be set");
        assert_eq!(a.sabm.len(), 4, "OSPFv3 SABM must be 0/4/8 octets");
        let g = a.ext_admin_group().expect("admin group");
        assert!(g.get(0) && g.get(200) && !g.get(1));
    }

    /// A link with TE metrics but no affinity still originates the ASLA
    /// — otherwise flex-algo metric-type 1 would have nothing to read.
    fn v3_asla(sabm: Vec<u8>, min_delay: u32) -> Ospfv3SubTlv {
        use ospf_packet::OspfSubMinMaxLinkDelay;
        Ospfv3SubTlv::Asla(Ospfv3AslaSubTlv {
            sabm,
            udabm: Vec::new(),
            subs: vec![Ospfv3AslaSubSubTlv::MinMaxLinkDelay(
                OspfSubMinMaxLinkDelay {
                    anomalous: false,
                    min_delay,
                    max_delay: min_delay + 100,
                },
            )],
        })
    }

    /// The ordinary case: an explicit Flex-Algorithm advertisement.
    #[test]
    fn asla_min_delay_reads_the_explicit_x_bit_advertisement() {
        let subs = vec![v3_asla(vec![OSPFV3_SABM_FLEX_ALGO, 0, 0, 0], 900)];
        assert_eq!(asla_min_delay_v3(&subs), Some(900));
    }

    /// RFC 9492 §5: a zero-length-mask advertisement covers any
    /// application with nothing more specific. Ignoring it prunes the
    /// link from a metric-type-1 topology, which can remove the only
    /// path.
    #[test]
    fn asla_min_delay_accepts_a_zero_length_mask_advertisement() {
        let subs = vec![v3_asla(Vec::new(), 1_100)];
        assert_eq!(asla_min_delay_v3(&subs), Some(1_100));
    }

    /// ... but only when nothing more specific exists, and the answer
    /// must not depend on which arrived first.
    #[test]
    fn asla_min_delay_prefers_the_explicit_advertisement_either_order() {
        let specific = v3_asla(vec![OSPFV3_SABM_FLEX_ALGO, 0, 0, 0], 900);
        let generic = v3_asla(Vec::new(), 1_100);
        assert_eq!(
            asla_min_delay_v3(&[generic.clone(), specific.clone()]),
            Some(900)
        );
        assert_eq!(asla_min_delay_v3(&[specific, generic]), Some(900));
    }

    /// An advertisement scoped to some other application says nothing
    /// about Flex-Algorithm, and does not license the generic one it
    /// isn't.
    #[test]
    fn asla_min_delay_ignores_another_applications_scope() {
        // Bit 0 is RSVP-TE, not the Flex-Algorithm X-bit.
        let subs = vec![v3_asla(vec![0x80, 0, 0, 0], 900)];
        assert_eq!(asla_min_delay_v3(&subs), None);
    }

    /// The OSPFv2 reader follows the same rule.
    fn v3_asla_eag(sabm: Vec<u8>) -> Ospfv3SubTlv {
        Ospfv3SubTlv::Asla(Ospfv3AslaSubTlv {
            sabm,
            udabm: Vec::new(),
            subs: vec![Ospfv3AslaSubSubTlv::ExtAdminGroup(ExtAdminGroup {
                words: vec![0x0000_0001],
            })],
        })
    }

    /// RFC 9492 §5 tests whether a matching advertisement is *present*,
    /// not whether it happens to carry the attribute being read. An
    /// explicit Flex-Algo ASLA carrying only an admin group therefore
    /// excludes a generic one carrying delay: delay is not advertised
    /// for this application, and metric-type 1 must prune the link
    /// rather than borrow the generic value.
    #[test]
    fn explicit_advertisement_without_delay_still_excludes_the_generic_one() {
        let affinity_only = v3_asla_eag(vec![OSPFV3_SABM_FLEX_ALGO, 0, 0, 0]);
        let generic_delay = v3_asla(Vec::new(), 1_100);
        assert_eq!(
            asla_min_delay_v3(&[affinity_only.clone(), generic_delay.clone()]),
            None
        );
        assert_eq!(
            asla_min_delay_v3(&[generic_delay, affinity_only]),
            None,
            "and not by advertisement order"
        );
    }

    /// Delay split across two explicit advertisements is still found —
    /// the exclusion is of the generic set, not of the other explicit
    /// ones.
    #[test]
    fn delay_is_found_across_several_explicit_advertisements() {
        let affinity_only = v3_asla_eag(vec![OSPFV3_SABM_FLEX_ALGO, 0, 0, 0]);
        let with_delay = v3_asla(vec![OSPFV3_SABM_FLEX_ALGO, 0, 0, 0], 900);
        assert_eq!(
            asla_min_delay_v3(&[affinity_only.clone(), with_delay.clone()]),
            Some(900)
        );
        assert_eq!(asla_min_delay_v3(&[with_delay, affinity_only]), Some(900));
    }

    fn v3_asla_masks(sabm: Vec<u8>, udabm: Vec<u8>, min_delay: u32) -> Ospfv3SubTlv {
        use ospf_packet::OspfSubMinMaxLinkDelay;
        Ospfv3SubTlv::Asla(Ospfv3AslaSubTlv {
            sabm,
            udabm,
            subs: vec![Ospfv3AslaSubSubTlv::MinMaxLinkDelay(
                OspfSubMinMaxLinkDelay {
                    anomalous: false,
                    min_delay,
                    max_delay: min_delay + 100,
                },
            )],
        })
    }

    /// RFC 9492 §5: a mask length outside 0/4/8 means the whole ASLA is
    /// ignored. A one-octet SABM with the X-bit set is not a
    /// Flex-Algorithm advertisement, however much it looks like one.
    #[test]
    fn invalid_mask_lengths_make_an_asla_unusable() {
        // Invalid SABM.
        let bad_sabm = v3_asla_masks(vec![OSPFV3_SABM_FLEX_ALGO], Vec::new(), 900);
        assert_eq!(asla_min_delay_v3(&[bad_sabm]), None);
        // Invalid UDABM, valid SABM — checked independently.
        let bad_udabm = v3_asla_masks(
            vec![OSPFV3_SABM_FLEX_ALGO, 0, 0, 0],
            vec![0x01, 0x02, 0x03],
            900,
        );
        assert_eq!(asla_min_delay_v3(&[bad_udabm]), None);
        // 8-octet masks are legal.
        let long_masks = v3_asla_masks(
            vec![OSPFV3_SABM_FLEX_ALGO, 0, 0, 0, 0, 0, 0, 0],
            vec![0; 8],
            900,
        );
        assert_eq!(asla_min_delay_v3(&[long_masks]), Some(900));
    }

    /// And it must not count as "an explicit advertisement is present":
    /// otherwise a malformed container silently suppresses a valid
    /// generic one and the link is pruned.
    #[test]
    fn an_invalid_asla_does_not_suppress_a_valid_generic_one() {
        let bad_explicit = Ospfv3SubTlv::Asla(Ospfv3AslaSubTlv {
            sabm: vec![OSPFV3_SABM_FLEX_ALGO],
            udabm: Vec::new(),
            subs: vec![Ospfv3AslaSubSubTlv::ExtAdminGroup(ExtAdminGroup {
                words: vec![0x0000_0001],
            })],
        });
        let generic_delay = v3_asla(Vec::new(), 1_100);
        assert_eq!(
            asla_min_delay_v3(&[bad_explicit.clone(), generic_delay.clone()]),
            Some(1_100)
        );
        assert_eq!(
            asla_min_delay_v3(&[generic_delay, bad_explicit]),
            Some(1_100),
            "and not by advertisement order"
        );
    }

    /// The OSPFv2 selector applies the same guard.
    #[test]
    fn invalid_mask_lengths_are_rejected_on_v2_too() {
        use ospf_packet::OspfSubMinMaxLinkDelay;
        let asla = |sabm: Vec<u8>| {
            ExtLinkSubTlv::Asla(OspfAslaSubTlv {
                sabm,
                udabm: Vec::new(),
                subs: vec![OspfAslaSubSubTlv::MinMaxLinkDelay(OspfSubMinMaxLinkDelay {
                    anomalous: false,
                    min_delay: 900,
                    max_delay: 1_000,
                })],
            })
        };
        assert_eq!(
            asla_min_delay_v2(&[asla(vec![OSPF_SABM_FLEX_ALGO, 0])]),
            None
        );
        assert_eq!(
            asla_min_delay_v2(&[asla(vec![OSPF_SABM_FLEX_ALGO, 0, 0, 0])]),
            Some(900)
        );
    }

    /// Affinity is read from the same applicable set, so the two
    /// consumers cannot disagree about which ASLA governs a link.
    #[test]
    fn affinity_and_delay_use_the_same_applicable_set() {
        use ospf_packet::OspfSubMinMaxLinkDelay;
        // One zero-mask ASLA carrying both: both readers must take it.
        let both = Ospfv3SubTlv::Asla(Ospfv3AslaSubTlv {
            sabm: Vec::new(),
            udabm: Vec::new(),
            subs: vec![
                Ospfv3AslaSubSubTlv::ExtAdminGroup(ExtAdminGroup {
                    words: vec![0x0000_0001],
                }),
                Ospfv3AslaSubSubTlv::MinMaxLinkDelay(OspfSubMinMaxLinkDelay {
                    anomalous: false,
                    min_delay: 1_100,
                    max_delay: 1_200,
                }),
            ],
        });
        assert_eq!(asla_min_delay_v3(std::slice::from_ref(&both)), Some(1_100));
        assert!(asla_admin_group_v3(std::slice::from_ref(&both)).is_some());

        // An explicit advertisement excludes it for both readers alike.
        let explicit = v3_asla(vec![OSPFV3_SABM_FLEX_ALGO, 0, 0, 0], 900);
        assert_eq!(
            asla_min_delay_v3(&[both.clone(), explicit.clone()]),
            Some(900)
        );
        assert!(
            asla_admin_group_v3(&[both, explicit]).is_none(),
            "the generic colour is out of scope once an explicit ASLA exists"
        );
    }

    #[test]
    fn asla_min_delay_v2_follows_the_same_selection() {
        use ospf_packet::OspfSubMinMaxLinkDelay;
        let asla = |sabm: Vec<u8>, min_delay: u32| {
            ExtLinkSubTlv::Asla(OspfAslaSubTlv {
                sabm,
                udabm: Vec::new(),
                subs: vec![OspfAslaSubSubTlv::MinMaxLinkDelay(OspfSubMinMaxLinkDelay {
                    anomalous: false,
                    min_delay,
                    max_delay: min_delay + 100,
                })],
            })
        };
        assert_eq!(asla_min_delay_v2(&[asla(Vec::new(), 1_100)]), Some(1_100));
        assert_eq!(
            asla_min_delay_v2(&[
                asla(Vec::new(), 1_100),
                asla(vec![OSPF_SABM_FLEX_ALGO, 0, 0, 0], 900)
            ]),
            Some(900)
        );
        assert_eq!(asla_min_delay_v2(&[asla(vec![0x80, 0, 0, 0], 900)]), None);
    }

    #[test]
    fn build_link_asla_v3_emits_te_metrics_without_affinity() {
        use ospf_packet::{OspfSubUniLinkDelay, Ospfv3AslaSubSubTlv};
        let am = AffinityMap::new();
        let extra = vec![Ospfv3AslaSubSubTlv::UniLinkDelay(OspfSubUniLinkDelay {
            anomalous: false,
            delay: 1_000,
        })];
        let asla = build_link_asla_v3(&BTreeSet::new(), &am, extra).expect("ASLA");
        let Ospfv3SubTlv::Asla(a) = &asla else {
            panic!("expected ASLA, got {asla:?}");
        };
        assert!(
            matches!(a.subs.as_slice(), [Ospfv3AslaSubSubTlv::UniLinkDelay(_)]),
            "only the metric, no empty admin group: {:?}",
            a.subs
        );
    }

    #[test]
    fn build_link_asla_v3_none_when_no_affinity_resolves() {
        let am = AffinityMap::new();
        assert!(build_link_asla_v3(&BTreeSet::new(), &am, Vec::new()).is_none());
        assert!(build_link_asla_v3(&affinity_set(&["ghost"]), &am, Vec::new()).is_none());
    }

    #[test]
    fn build_link_asla_none_when_no_affinity_resolves() {
        let am = AffinityMap::new();
        // No names, no extra subs → None.
        assert!(build_link_asla(&BTreeSet::new(), &am, Vec::new()).is_none());
        // Referenced name not in the map and no extra subs → None
        // (empty bitmap).
        assert!(build_link_asla(&affinity_set(&["ghost"]), &am, Vec::new()).is_none());
    }

    #[test]
    fn build_link_asla_emits_te_metrics_without_affinity() {
        use ospf_packet::{OspfAslaSubSubTlv, OspfSubUniLinkDelay};

        let am = AffinityMap::new();
        // No affinity at all, but a TE-metric sub-sub-TLV present: the
        // link must still advertise an ASLA so the metric reaches peers.
        let extra = vec![OspfAslaSubSubTlv::UniLinkDelay(OspfSubUniLinkDelay {
            anomalous: false,
            delay: 1_000,
        })];
        let asla = build_link_asla(&BTreeSet::new(), &am, extra).expect("ASLA");
        let ExtLinkSubTlv::Asla(a) = &asla else {
            panic!("expected Asla, got {asla:?}");
        };
        assert!(a.is_flex_algo(), "SABM X-bit must be set");
        assert!(
            a.ext_admin_group().is_none(),
            "no affinity → no admin group"
        );
        assert!(matches!(
            a.subs.as_slice(),
            [OspfAslaSubSubTlv::UniLinkDelay(_)]
        ));
    }

    #[test]
    fn build_fad_v3_skips_entries_without_advertise_flag() {
        let mut fa = FlexAlgoConfig::new("/router/ospfv3/flex-algo");
        // Algo 128 — no advertise-definition, skipped.
        fa.exec(
            "/router/ospfv3/flex-algo/priority".into(),
            args(&["128", "200"]),
            ConfigOp::Set,
        )
        .unwrap();
        // Algo 129 — advertise-definition set, emitted.
        fa.exec(
            "/router/ospfv3/flex-algo/advertise-definition".into(),
            args(&["129", "true"]),
            ConfigOp::Set,
        )
        .unwrap();
        fa.commit();

        let fads = build_fad_v3(&fa, &AffinityMap::new(), &BTreeMap::new());
        assert_eq!(fads.len(), 1);
        assert_eq!(fads[0].flex_algorithm, 129);
        assert_eq!(fads[0].metric_type, FadMetricType::Igp.wire());
        assert_eq!(fads[0].priority, 128);
        assert!(fads[0].subs.is_empty());
    }

    #[test]
    fn build_fad_v3_emits_exclude_ag_srlg_and_flags() {
        use ospf_packet::Ospfv3FadSubTlv;

        let mut fa = FlexAlgoConfig::new("/router/ospfv3/flex-algo");
        for (leaf, vals) in [
            ("/advertise-definition", &["128", "true"][..]),
            ("/metric-type", &["128", "min-unidir-link-delay"][..]),
            ("/affinity/exclude-any", &["128", "blue"][..]),
            ("/srlg-exclude", &["128", "risk-a"][..]),
            ("/prefix-metric", &["128", "true"][..]),
        ] {
            fa.exec(
                format!("/router/ospfv3/flex-algo{leaf}"),
                args(vals),
                ConfigOp::Set,
            )
            .unwrap();
        }
        fa.commit();

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
            "risk-a".to_string(),
            SrlgGroup {
                name: "risk-a".into(),
                value: 100,
            },
        );

        let fads = build_fad_v3(&fa, &am, &srlg);
        assert_eq!(fads.len(), 1);
        let fad = &fads[0];
        assert_eq!(fad.flex_algorithm, 128);
        assert_eq!(fad.metric_type, FadMetricType::MinUnidirLinkDelay.wire());

        let (mut excl, mut flags, mut srlgs) = (false, false, false);
        for sub in &fad.subs {
            match sub {
                Ospfv3FadSubTlv::ExcludeAg(g) => {
                    excl = true;
                    assert!(g.get(4));
                }
                Ospfv3FadSubTlv::Flags(f) => {
                    flags = true;
                    assert!(f.m_flag);
                }
                Ospfv3FadSubTlv::ExcludeSrlg(s) => {
                    srlgs = true;
                    assert_eq!(s.srlgs, vec![100]);
                }
                other => panic!("unexpected sub: {other:?}"),
            }
        }
        assert!(excl && flags && srlgs);
    }
}
