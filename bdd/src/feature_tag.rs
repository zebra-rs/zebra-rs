//! The tag a `.feature` file scopes its host resources by.
//!
//! Every feature names its namespaces, pid files, bridge and veths from its
//! first non-special tag, so anything that reasons about another feature's
//! resources has to read that tag out of the file. The file *name* is not a
//! substitute: seven features already declare a tag that differs from their
//! stem (`isis_tilfa_srv6.feature` is `@tilfa_srv6`,
//! `ospfv3_tilfa_srv6.feature` is `@srv6_tilfa_v3`, …).

/// First non-special tag of a `.feature` file's text — the same selection
/// the cucumber `before` hook makes from the parsed feature for
/// `World::feature_tag`.
pub fn parse(text: &str) -> Option<String> {
    text.lines()
        .take_while(|l| l.trim_start().starts_with('@') || l.trim().is_empty())
        .flat_map(|l| l.split_whitespace())
        .filter_map(|w| w.strip_prefix('@'))
        .find(|t| *t != "serial" && *t != "allow.skipped" && *t != "disabled")
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn parses_the_first_non_special_tag() {
        assert_eq!(
            parse("@serial\n@bgp_evpn_vpws\nFeature: x\n"),
            Some("bgp_evpn_vpws".to_string())
        );
        assert_eq!(
            parse("@serial @allow.skipped @isis_redist\nFeature: x\n"),
            Some("isis_redist".to_string())
        );
        // A `@` further down the file belongs to a scenario, not the feature.
        assert_eq!(
            parse("Feature: x\n\n  @scenario_tag\n  Scenario: y\n"),
            None
        );
    }

    /// Two features sharing a tag genuinely collide: their resources are
    /// named identically and nothing can tell them apart. Tags that merely
    /// *prefix* one another are fine — `World::sibling_prefixes` resolves
    /// those (it used to be a hard ban here, which contradicted that fix and
    /// failed on the three prefix pairs the repo now has).
    #[test]
    fn feature_tags_are_unique() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/features");
        let mut seen: HashMap<String, String> = HashMap::new();
        for entry in fs::read_dir(&dir).expect("read tests/features") {
            let path = entry.expect("dir entry").path();
            if path.extension().is_some_and(|e| e == "feature") {
                let text = fs::read_to_string(&path).expect("read feature file");
                let tag =
                    parse(&text).unwrap_or_else(|| panic!("{} has no scoping tag", path.display()));
                let name = path.file_name().unwrap().to_string_lossy().into_owned();
                if let Some(prev) = seen.insert(tag.clone(), name.clone()) {
                    panic!("tag `{tag}` used by both {prev} and {name}");
                }
            }
        }
        assert!(
            !seen.is_empty(),
            "no feature files found in {}",
            dir.display()
        );
    }
}
