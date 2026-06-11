use libyang::Entry;
use serde_json::Value;
use std::rc::Rc;

/// Translate a JSON (or YAML-converted-to-JSON) config document into
/// flat `set …` command lines by walking it against the YANG `set`
/// subtree.
///
/// Returns the command lines plus a list of errors for every part of
/// the document that does NOT correspond to the schema. Errors must
/// reach the operator: this walk used to silently `return` on the
/// first unknown key — dropping that key AND every remaining sibling —
/// which let a misspelled key (e.g. `med-eq:` for the nested
/// `med: { eq: … }`) produce a partial config that *applied* cleanly
/// while testing nothing.
pub fn json_read(e: Rc<Entry>, str: &str) -> (Vec<String>, Vec<String>) {
    let mut lines: Vec<String> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    match serde_json::from_str::<Value>(str) {
        Ok(json) => {
            json_to_list(e, Vec::new(), &json, &mut lines, &mut errors);
        }
        Err(err) => {
            errors.push(format!("invalid document: {err}"));
        }
    }
    (lines, errors)
}

pub fn json_to_list(
    entry: Rc<Entry>,
    p: Vec<String>,
    v: &Value,
    lines: &mut Vec<String>,
    errors: &mut Vec<String>,
) {
    match v {
        Value::Null => {
            lines.push(format!("set {}", p.join(" ")));
        }
        Value::Bool(v) => {
            lines.push(format!("set {} {}", p.join(" "), v));
        }
        Value::Number(v) => {
            lines.push(format!("set {} {}", p.join(" "), v));
        }
        Value::String(v) => {
            lines.push(format!("set {} {}", p.join(" "), v));
        }
        Value::Array(vec) => {
            for v in vec.iter() {
                let p = p.clone();
                json_to_list(entry.clone(), p, v, lines, errors);
            }
        }
        Value::Object(map) => {
            // A childless presence container marshals as `{}`; restore
            // it as the bare `set <path>` (a presence container exists
            // on its own, unlike a plain container which only exists
            // through its children — an empty `{}` there is a no-op).
            if map.is_empty() && entry.presence {
                lines.push(format!("set {}", p.join(" ")));
                return;
            }
            let mut p = p.clone();
            if !entry.key.is_empty() {
                if let Some(value) = map.get(&entry.key[0]) {
                    p.push(value_without_quotes(value));
                    lines.push(format!("set {}", p.join(" ")));
                } else {
                    // A list entry without its key field can't be
                    // addressed at all — report it instead of silently
                    // dropping the whole object.
                    errors.push(format!(
                        "{}: list entry is missing its key `{}`",
                        display_path(&p, &entry.name),
                        entry.key[0]
                    ));
                    return;
                }
            }
            for (key, value) in map.iter() {
                if !entry.key.is_empty() && key == &entry.key[0] {
                    continue;
                }
                match entry_dir(entry.clone(), key) {
                    Some(entry) => {
                        let mut p = p.clone();
                        p.push(key.clone());
                        json_to_list(entry.clone(), p, value, lines, errors);
                    }
                    None => {
                        // Unknown key: record it and KEEP walking the
                        // remaining siblings — aborting here used to
                        // drop everything after the first typo.
                        errors.push(format!(
                            "{}: unknown key `{}`",
                            display_path(&p, &entry.name),
                            key
                        ));
                    }
                }
            }
        }
    }
}

/// Human-readable location for an error: the accumulated command path,
/// or the schema node name when the error fires at the document root.
fn display_path(p: &[String], entry_name: &str) -> String {
    if p.is_empty() {
        entry_name.to_string()
    } else {
        p.join(" ")
    }
}

fn value_without_quotes(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        _ => value.to_string(),
    }
}

fn entry_dir(entry: Rc<Entry>, name: &String) -> Option<Rc<Entry>> {
    for e in entry.dir.borrow().iter() {
        if e.name == *name {
            return Some(e.clone());
        }
    }
    None
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

    /// The nested `med: { eq: … }` shape (matching the YANG `choice`)
    /// produces the expected flat command.
    #[test]
    fn med_nested_shape_emits_command() {
        let doc = r#"{"policy":[{"name":"IN-MED","entry":[{"number":10,"action":"permit","match":{"med":{"eq":999}}}]}]}"#;
        let (lines, errors) = json_read(set_entry(), doc);
        assert!(errors.is_empty(), "errors: {errors:?}");
        assert!(
            lines
                .iter()
                .any(|l| l == "set policy IN-MED entry 10 match med eq 999"),
            "lines: {lines:?}"
        );
    }

    /// An unknown key is reported as an error AND does not abort the
    /// remaining siblings: `action` (sorted after the bogus `a-bogus`
    /// key) must still be emitted. This is the regression shape that
    /// let the BDD's flat `med-eq:` spelling apply cleanly while
    /// configuring nothing.
    #[test]
    fn unknown_key_is_reported_and_siblings_survive() {
        let doc = r#"{"policy":[{"name":"IN-MED","entry":[{"number":10,"a-bogus":1,"action":"permit","match":{"med-eq":999}}]}]}"#;
        let (lines, errors) = json_read(set_entry(), doc);
        assert!(
            errors.iter().any(|e| e.contains("unknown key `med-eq`")),
            "errors: {errors:?}"
        );
        assert!(
            errors.iter().any(|e| e.contains("unknown key `a-bogus`")),
            "errors: {errors:?}"
        );
        assert!(
            lines
                .iter()
                .any(|l| l == "set policy IN-MED entry 10 action permit"),
            "siblings after the unknown key must still apply; lines: {lines:?}"
        );
    }

    /// A childless presence container dumps as `{}` — loading that
    /// shape must restore the bare `set <path>` line, and the legacy
    /// `null` shape (pre-`{}` dumps) must keep loading the same way.
    /// An empty object on a plain (non-presence) container stays a
    /// silent no-op: such a container has no independent existence.
    #[test]
    fn empty_object_restores_presence_container() {
        let doc =
            r#"{"router":{"bgp":{"neighbor":[{"remote-address":"10.0.0.1","as-override":{}}]}}}"#;
        let (lines, errors) = json_read(set_entry(), doc);
        assert!(errors.is_empty(), "errors: {errors:?}");
        assert!(
            lines
                .iter()
                .any(|l| l == "set router bgp neighbor 10.0.0.1 as-override"),
            "lines: {lines:?}"
        );

        let doc =
            r#"{"router":{"bgp":{"neighbor":[{"remote-address":"10.0.0.1","as-override":null}]}}}"#;
        let (lines, errors) = json_read(set_entry(), doc);
        assert!(errors.is_empty(), "errors: {errors:?}");
        assert!(
            lines
                .iter()
                .any(|l| l == "set router bgp neighbor 10.0.0.1 as-override"),
            "legacy null shape must keep loading; lines: {lines:?}"
        );

        let doc = r#"{"router":{"bgp":{}}}"#;
        let (lines, errors) = json_read(set_entry(), doc);
        assert!(errors.is_empty(), "errors: {errors:?}");
        assert!(
            lines.is_empty(),
            "non-presence `{{}}` must not emit a command; lines: {lines:?}"
        );
    }

    /// A list entry whose key field is absent is reported, not dropped.
    #[test]
    fn missing_list_key_is_reported() {
        let doc = r#"{"policy":[{"entry":[{"number":10}]}]}"#;
        let (_lines, errors) = json_read(set_entry(), doc);
        assert!(
            errors.iter().any(|e| e.contains("missing its key `name`")),
            "errors: {errors:?}"
        );
    }
}
