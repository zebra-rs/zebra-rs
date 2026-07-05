//! Static guard for the BDD feature-tag concurrency invariant.
//!
//! Every feature scopes its host resources (netns, pid files, bridge,
//! veths) by its first non-special tag, and both the pre-run sweep and
//! `the test environment should be clean` match them by the raw string
//! prefix `<tag>_`. If one feature's tag is a prefix of another's, the
//! shorter feature's sweep/clean check matches the longer feature's live
//! resources whenever the two run concurrently — a scheduling-dependent
//! flake (bit `isis_fragmentation` in PR #1193, then `mirror_sid_node`,
//! `ospfv2_nssa`, and `ospfv2_stub` in the 2026-07-04 full-suite run).
//!
//! This unit test fails the build-time `cargo test -p bdd --lib` (and any
//! full BDD run, which compiles the crate) as soon as a new feature tag
//! prefixes an existing one, instead of leaving it to bite as a flake.

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    /// First non-special tag of a `.feature` file — the same selection the
    /// cucumber `before` hook uses for `World::feature_tag`.
    fn feature_tag(text: &str) -> Option<String> {
        text.lines()
            .take_while(|l| l.trim_start().starts_with('@') || l.trim().is_empty())
            .flat_map(|l| l.split_whitespace())
            .filter_map(|w| w.strip_prefix('@'))
            .find(|t| *t != "serial" && *t != "allow.skipped")
            .map(str::to_string)
    }

    #[test]
    fn no_feature_tag_is_a_prefix_of_another() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/features");
        let mut tags = Vec::new();
        for entry in fs::read_dir(&dir).expect("read tests/features") {
            let path = entry.expect("dir entry").path();
            if path.extension().is_some_and(|e| e == "feature") {
                let text = fs::read_to_string(&path).expect("read feature file");
                let tag = feature_tag(&text)
                    .unwrap_or_else(|| panic!("{} has no scoping tag", path.display()));
                tags.push((
                    tag,
                    path.file_name().unwrap().to_string_lossy().into_owned(),
                ));
            }
        }
        assert!(
            !tags.is_empty(),
            "no feature files found in {}",
            dir.display()
        );

        let mut collisions = Vec::new();
        for (a, fa) in &tags {
            for (b, fb) in &tags {
                if a != b && b.starts_with(&format!("{a}_")) {
                    collisions.push(format!(
                        "tag `{a}` ({fa}) is a prefix of `{b}` ({fb}) — \
                         the `{a}_` resource sweep/clean check matches `{b}`'s \
                         namespaces and pid files when both run concurrently"
                    ));
                }
            }
        }
        assert!(
            collisions.is_empty(),
            "feature-tag prefix collisions:\n{}",
            collisions.join("\n")
        );
    }

    #[test]
    fn feature_tags_are_unique() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/features");
        let mut seen: std::collections::HashMap<String, String> = Default::default();
        for entry in fs::read_dir(&dir).expect("read tests/features") {
            let path = entry.expect("dir entry").path();
            if path.extension().is_some_and(|e| e == "feature") {
                let text = fs::read_to_string(&path).expect("read feature file");
                if let Some(tag) = feature_tag(&text) {
                    let name = path.file_name().unwrap().to_string_lossy().into_owned();
                    if let Some(prev) = seen.insert(tag.clone(), name.clone()) {
                        panic!("tag `{tag}` used by both {prev} and {name}");
                    }
                }
            }
        }
    }
}
