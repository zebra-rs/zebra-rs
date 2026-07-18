//! OSPF Flexible Algorithm (RFC 9350 §6) wire builders. The
//! protocol-neutral config model + constraint engine live in
//! `crate::flex_algo`; this module turns the committed config into the
//! ospf-packet TLV structs that ride in the Router Information and
//! Extended-Link Opaque LSAs. Parallel to `isis::flex_algo`'s
//! isis-packet builders.

use std::collections::{BTreeMap, BTreeSet};

use ospf_packet::{
    ExtLinkSubTlv, FadFlags, FadSrlg, OSPF_SABM_FLEX_ALGO, OSPFV3_SABM_FLEX_ALGO,
    OspfAslaSubSubTlv, OspfAslaSubTlv, OspfFadSubTlv, Ospfv3AslaSubSubTlv, Ospfv3AslaSubTlv,
    Ospfv3FadSubTlv, Ospfv3FadTlv, Ospfv3SubTlv, RouterInfoTlvFad,
};

use crate::flex_algo::{
    AffinityMap, FadMetricType, FlexAlgoConfig, SrlgGroup, local_link_affinity,
};

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

/// OSPFv3 sibling of `build_link_asla`: build the per-link ASLA sub-TLV
/// (RFC 9492) that rides as an `Ospfv3SubTlv::Asla` on the E-Router-LSA
/// Router-Link TLV. Same SABM X-bit framing and empty-bitmap guard as
/// the v2 builder; only the wire type differs (OSPFv3 sub-TLV 11 with
/// the Extended Admin Group sub-sub-TLV 21).
pub fn build_link_asla_v3(affinity: &BTreeSet<String>, am: &AffinityMap) -> Option<Ospfv3SubTlv> {
    let group = local_link_affinity(affinity, am);
    if group.words.is_empty() {
        return None;
    }
    Some(Ospfv3SubTlv::Asla(Ospfv3AslaSubTlv {
        sabm: vec![OSPFV3_SABM_FLEX_ALGO, 0, 0, 0],
        udabm: Vec::new(),
        subs: vec![Ospfv3AslaSubSubTlv::ExtAdminGroup(group)],
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
        let asla = build_link_asla_v3(&affinity_set(&["blue", "red"]), &am).expect("ASLA");
        let Ospfv3SubTlv::Asla(a) = &asla else {
            panic!("expected Asla, got {asla:?}");
        };
        assert!(a.is_flex_algo(), "SABM X-bit must be set");
        assert_eq!(a.sabm.len(), 4, "OSPFv3 SABM must be 0/4/8 octets");
        let g = a.ext_admin_group().expect("admin group");
        assert!(g.get(0) && g.get(200) && !g.get(1));
    }

    #[test]
    fn build_link_asla_v3_none_when_no_affinity_resolves() {
        let am = AffinityMap::new();
        assert!(build_link_asla_v3(&BTreeSet::new(), &am).is_none());
        assert!(build_link_asla_v3(&affinity_set(&["ghost"]), &am).is_none());
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
