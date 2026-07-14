use libyang::Entry;
use marked_yaml::types::{MarkedScalarNode, Node};
use marked_yaml::{LoaderOptions, parse_yaml_with_options};
use std::rc::Rc;

use super::json::{DocError, MapEntry, SpannedValue, spanned_to_list};

/// Walk a YAML config document against the YANG `set` subtree,
/// preserving the source line of every key so a schema-rejection error
/// can point the operator at the exact line in their config file.
///
/// Replaces the old `yaml_parse` → JSON-string → `serde_json` round
/// trip, which discarded every source marker (and `.unwrap()`ed on
/// malformed YAML, panicking the daemon). This parses the original YAML
/// with `marked-yaml`, lowers it into a line-annotated [`SpannedValue`],
/// and shares the JSON [`spanned_to_list`] walk.
pub fn yaml_read(e: Rc<Entry>, source: &str) -> (Vec<String>, Vec<DocError>) {
    let mut lines: Vec<String> = Vec::new();
    let mut errors: Vec<DocError> = Vec::new();
    // `prevent_coercion` so a *quoted* "null"/"true" scalar keeps its
    // string identity — only plain scalars coerce, matching the old
    // serde_yaml semantics. `error_on_duplicate_keys` so a repeated key
    // is reported (with its line) rather than silently last-wins.
    let options = LoaderOptions::default()
        .prevent_coercion(true)
        .error_on_duplicate_keys(true);
    match parse_yaml_with_options(0, source, options) {
        Ok(node) => {
            spanned_to_list(e, Vec::new(), &from_yaml(&node), &mut lines, &mut errors);
        }
        Err(err) => {
            // marked-yaml renders the offending marker as `line:column`
            // inside the message, so the operator still gets a location.
            errors.push(DocError::new(None, format!("invalid document: {err}")));
        }
    }
    (lines, errors)
}

/// Lower a `marked-yaml` node into a line-annotated [`SpannedValue`].
fn from_yaml(node: &Node) -> SpannedValue {
    match node {
        Node::Scalar(s) => {
            if is_null_scalar(s) {
                SpannedValue::Null
            } else {
                SpannedValue::Scalar(s.as_str().to_string())
            }
        }
        Node::Sequence(seq) => SpannedValue::Sequence(seq.iter().map(from_yaml).collect()),
        Node::Mapping(map) => {
            let line = map.span().start().map(|m| m.line());
            let entries = map
                .iter()
                .map(|(key, value)| MapEntry {
                    key: key.as_str().to_string(),
                    line: key.span().start().map(|m| m.line()),
                    value: from_yaml(value),
                })
                .collect();
            SpannedValue::Mapping { line, entries }
        }
    }
}

/// A plain (coerceable) `null`/`~`/empty scalar is YAML null — lowered
/// to [`SpannedValue::Null`] so it emits a bare `set <path>` (the
/// empty-leaf / `type empty` convention). A quoted `"null"` is a real
/// string and is left alone.
fn is_null_scalar(s: &MarkedScalarNode) -> bool {
    s.may_coerce() && matches!(s.as_str(), "" | "~" | "null" | "Null" | "NULL")
}

#[cfg(test)]
mod tests {
    use super::*;
    use libyang::{YangStore, to_entry};

    fn set_entry() -> Rc<Entry> {
        let mut yang = YangStore::new();
        yang.add_path(concat!(env!("CARGO_MANIFEST_DIR"), "/yang"));
        yang.read_with_resolve("configure")
            .expect("configure mode loads");
        yang.identity_resolve();
        let module = yang
            .find_module("configure")
            .expect("configure module present");
        let entry = to_entry(&yang, module);
        entry
            .dir
            .borrow()
            .iter()
            .find(|e| e.name == "set")
            .cloned()
            .expect("set subtree")
    }

    /// The reported failure: an unknown `community-set` leaf under a
    /// policy match must be rejected AND carry the line it sits on.
    #[test]
    fn unknown_key_reports_source_line() {
        let doc = "\
policy:
- name: 198.19.14.192/28
  entry:
  - number: 10
    action: permit
    match:
      community-set: FOO
";
        let (_lines, errors) = yaml_read(set_entry(), doc);
        let err = errors
            .iter()
            .find(|e| e.message.contains("unknown key `community-set`"))
            .unwrap_or_else(|| panic!("expected unknown-key error; errors: {errors:?}"));
        // `community-set:` is on line 7 (1-based) of the document above.
        assert_eq!(err.line, Some(7), "errors: {errors:?}");
    }

    /// A plain `key: null` and a bare `key:` both lower to a bare
    /// `set <path>` line (the `type empty` / empty-leaf convention),
    /// matching the pre-marked-yaml serde_yaml behavior.
    #[test]
    fn null_and_empty_scalar_emit_bare_set() {
        let doc = "\
router:
  bgp:
    neighbor:
    - remote-address: 10.0.0.1
      as-override: null
";
        let (lines, errors) = yaml_read(set_entry(), doc);
        assert!(errors.is_empty(), "errors: {errors:?}");
        assert!(
            lines
                .iter()
                .any(|l| l == "set router bgp neighbor 10.0.0.1 as-override"),
            "`key: null` must emit a bare set; lines: {lines:?}"
        );

        let doc = "\
router:
  bgp:
    neighbor:
    - remote-address: 10.0.0.1
      as-override:
";
        let (lines, errors) = yaml_read(set_entry(), doc);
        assert!(errors.is_empty(), "errors: {errors:?}");
        assert!(
            lines
                .iter()
                .any(|l| l == "set router bgp neighbor 10.0.0.1 as-override"),
            "bare `key:` must emit a bare set; lines: {lines:?}"
        );
    }

    /// A presence container written as `key: {}` restores the bare
    /// `set <path>` line, just like the JSON path.
    #[test]
    fn empty_mapping_restores_presence_container() {
        let doc = "\
router:
  bgp:
    neighbor:
    - remote-address: 10.0.0.1
      as-override: {}
";
        let (lines, errors) = yaml_read(set_entry(), doc);
        assert!(errors.is_empty(), "errors: {errors:?}");
        assert!(
            lines
                .iter()
                .any(|l| l == "set router bgp neighbor 10.0.0.1 as-override"),
            "`key: {{}}` must emit a bare set; lines: {lines:?}"
        );
    }

    /// Numeric and nested values flatten to the same commands the JSON
    /// path produces.
    #[test]
    fn nested_shape_emits_command() {
        let doc = "\
policy:
- name: IN-MED
  entry:
  - number: 10
    action: permit
    match:
      med:
        eq: 999
";
        let (lines, errors) = yaml_read(set_entry(), doc);
        assert!(errors.is_empty(), "errors: {errors:?}");
        assert!(
            lines
                .iter()
                .any(|l| l == "set policy IN-MED entry 10 match med eq 999"),
            "lines: {lines:?}"
        );
    }
}
