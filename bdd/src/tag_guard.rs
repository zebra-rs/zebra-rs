//! Static guard for the BDD feature-tag concurrency invariant.
//!
//! Every feature scopes its host resources (netns, pid files, bridge,
//! veths) by its first non-special tag, and both the pre-run sweep and
//! `the test environment should be clean` match them by the raw string
//! prefix `<tag>_`. A feature whose tag *extends* another's therefore
//! shares that feature's prefix: `bgp_evpn_vpws_multihoming`'s namespaces
//! and pid files look exactly like `bgp_evpn_vpws` resources.
//!
//! That used to be banned outright, and this module failed the build for
//! any prefix pair. Since `d154dfc` the harness tolerates the pairs
//! instead: `World::sibling_prefixes` lists the features whose tags extend
//! this one's, and all four scans skip names owned by one of them. Banning
//! the pairs on top of that would forbid what the harness now handles —
//! and it did, leaving `cargo test -p bdd --lib` red for the three pairs
//! that legitimately exist.
//!
//! What still needs guarding is that mitigation's precondition. The lookup
//! enumerates the **file stems** under `tests/features`, while the
//! resources it protects are named from each feature's **tag**. Those
//! coincide for most features and deliberately do not for seven — the tag
//! in `isis_tilfa_srv6.feature` is `tilfa_srv6`, and `isis-redist.feature`
//! spells its tag `isis_redist`. So a sibling is only covered when its own
//! file name lines up with its tag; for any other, `sibling_prefixes`
//! yields a prefix that matches none of the sibling's real resource names
//! and leaves it exposed to exactly the clobbering `d154dfc` removed —
//! silently, and only under concurrency.
//!
//! So the invariant enforced here is no longer "no tag prefixes another"
//! but "every tag that prefixes another names a sibling the harness can
//! actually see".

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    struct Feature {
        /// File name without the `.feature` extension — what
        /// `World::sibling_prefixes` matches on.
        stem: String,
        /// First non-special tag — what every resource name is built from.
        tag: String,
    }

    impl Feature {
        fn file(&self) -> String {
            format!("{}.feature", self.stem)
        }
    }

    /// First non-special tag of a `.feature` file — the same selection the
    /// cucumber `before` hook uses for `World::feature_tag`.
    fn feature_tag(text: &str) -> Option<String> {
        text.lines()
            .take_while(|l| l.trim_start().starts_with('@') || l.trim().is_empty())
            .flat_map(|l| l.split_whitespace())
            .filter_map(|w| w.strip_prefix('@'))
            .find(|t| *t != "serial" && *t != "allow.skipped" && *t != "disabled")
            .map(str::to_string)
    }

    fn load_features() -> Vec<Feature> {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/features");
        let mut features = Vec::new();
        for entry in fs::read_dir(&dir).expect("read tests/features") {
            let path = entry.expect("dir entry").path();
            if path.extension().is_some_and(|e| e == "feature") {
                let text = fs::read_to_string(&path).expect("read feature file");
                let tag = feature_tag(&text)
                    .unwrap_or_else(|| panic!("{} has no scoping tag", path.display()));
                features.push(Feature {
                    stem: path.file_stem().unwrap().to_string_lossy().into_owned(),
                    tag,
                });
            }
        }
        assert!(
            !features.is_empty(),
            "no feature files found in {}",
            dir.display()
        );
        features
    }

    /// The prefixes `World::sibling_prefixes` produces for `tag`, mirrored
    /// exactly — filename-based semantics included, since that is the
    /// property under test.
    fn harness_sibling_prefixes(tag: &str, stems: &[&str]) -> Vec<String> {
        let own = format!("{tag}_");
        stems
            .iter()
            .filter(|stem| stem.len() > tag.len() && stem.starts_with(&own))
            .map(|stem| format!("{stem}_"))
            .collect()
    }

    #[test]
    fn every_prefix_sibling_is_visible_to_the_harness() {
        let features = load_features();
        let stems: Vec<&str> = features.iter().map(|f| f.stem.as_str()).collect();

        let mut unprotected = Vec::new();
        for parent in &features {
            let siblings = harness_sibling_prefixes(&parent.tag, &stems);
            for child in &features {
                if child.tag == parent.tag || !child.tag.starts_with(&format!("{}_", parent.tag)) {
                    continue;
                }
                // The child's resources are named `<child.tag>_<logical>`,
                // and the harness skips a name only when it starts with one
                // of `siblings`. Testing `<child.tag>_` covers every such
                // name at once.
                let owned = format!("{}_", child.tag);
                if !siblings.iter().any(|p| owned.starts_with(p.as_str())) {
                    unprotected.push(format!(
                        "tag `{}` ({}) is a prefix of `{}` ({}), but the sweep/clean scans in \
                         `{}` cannot tell them apart: `World::sibling_prefixes` finds siblings \
                         by file name, and `{}` does not match the tag `{}` its resources are \
                         named from. Rename the file to `{}.feature` (or change the tag to \
                         `{}`) so the two agree.",
                        parent.tag,
                        parent.file(),
                        child.tag,
                        child.file(),
                        parent.file(),
                        child.file(),
                        child.tag,
                        child.tag,
                        child.stem,
                    ));
                }
            }
        }
        assert!(
            unprotected.is_empty(),
            "feature-tag prefix collisions the harness cannot defend against:\n{}",
            unprotected.join("\n")
        );
    }

    /// The three pairs that exist today are the reason the blanket ban had
    /// to go; pin that they stay covered, so a future rename of one of
    /// these files fails here rather than as a concurrency flake.
    #[test]
    fn known_prefix_pairs_are_covered() {
        let features = load_features();
        let stems: Vec<&str> = features.iter().map(|f| f.stem.as_str()).collect();
        for (parent, child) in [
            ("bgp_evpn_vpws", "bgp_evpn_vpws_multihoming"),
            ("bgp_adv_interval_zero", "bgp_adv_interval_zero_v6"),
            ("bgp_adv_interval_zero", "bgp_adv_interval_zero_vrf"),
        ] {
            assert!(
                features.iter().any(|f| f.tag == child),
                "expected a feature tagged `{child}`"
            );
            let siblings = harness_sibling_prefixes(parent, &stems);
            assert!(
                siblings.iter().any(|p| format!("{child}_").starts_with(p)),
                "`{parent}` no longer skips `{child}`'s resources; \
                 sibling prefixes were {siblings:?}"
            );
        }
    }

    #[test]
    fn feature_tags_are_unique() {
        let mut seen: std::collections::HashMap<String, String> = Default::default();
        for f in load_features() {
            if let Some(prev) = seen.insert(f.tag.clone(), f.file()) {
                panic!("tag `{}` used by both {prev} and {}", f.tag, f.file());
            }
        }
    }

    #[test]
    fn sibling_prefixes_only_match_a_name_that_matches_the_tag() {
        // A sibling whose file name equals its tag is found...
        let stems = ["a_b", "a_b_c"];
        assert_eq!(harness_sibling_prefixes("a_b", &stems), vec!["a_b_c_"]);
        // ...and the parent itself is never its own sibling.
        assert!(harness_sibling_prefixes("a_b_c", &stems).is_empty());
        // A sibling filed under an unrelated name is invisible — this is
        // the hole `every_prefix_sibling_is_visible_to_the_harness` exists
        // to keep out of the features directory.
        let renamed = ["a_b", "isis_a_b_c"];
        assert!(harness_sibling_prefixes("a_b", &renamed).is_empty());
    }
}
