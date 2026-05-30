//! OSPF Flexible Algorithm (RFC 9350 §6) wire builders. The
//! protocol-neutral config model + constraint engine live in
//! `crate::flex_algo`; this module turns the committed config into the
//! ospf-packet TLV structs that ride in the Router Information and
//! Extended-Link Opaque LSAs. Parallel to `isis::flex_algo`'s
//! isis-packet builders.

use std::collections::BTreeMap;

use ospf_packet::{OspfFadExcludeSrlg, OspfFadFlags, OspfFadSubTlv, RouterInfoTlvFad};

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
            subs.push(OspfFadSubTlv::Flags(OspfFadFlags {
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
                subs.push(OspfFadSubTlv::ExcludeSrlg(OspfFadExcludeSrlg {
                    srlgs: ids,
                }));
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
}
