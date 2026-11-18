//! CONFIG_DB into the `sonic` subtree.
//!
//! `docs/design/sonic-junos-style-config.md`, phase 2: the read-only
//! mirror. CONFIG_DB stays the truth of a SONiC device's configuration;
//! what is under `sonic` here is a copy of it, made from the tables as
//! `sonic-cfggen -d --print-data` or `config_db.json` has them:
//!
//! ```json
//! { "PORT":        { "Ethernet0":          { "lanes": "1,2,3,4", "mtu": "9100" } },
//!   "VLAN_MEMBER": { "Vlan100|Ethernet0":  { "tagging_mode": "untagged" } },
//!   "DEVICE_METADATA": { "localhost":      { "hostname": "sonic1" } } }
//! ```
//!
//! [`translate`] turns that into the `set sonic …` lines of the same
//! configuration, by the schema `config::sonic` built from SONiC's
//! models. `ConfigManager::import_config_db` replaces the subtree with
//! them.
//!
//! # How a row is read
//!
//! - **Its list.** A row's key is the keys of its list joined by `|`.
//!   A table with several lists has rows of each (`INTERFACE` has
//!   `Ethernet0` and `Ethernet0|10.0.0.0/31`): a row belongs to the
//!   list with as many keys as it has parts, and where two have, to
//!   the first whose key types take its parts.
//! - **A row with a fixed key** (`DEVICE_METADATA|localhost`) is the
//!   container of that name in the table.
//! - **A leaf-list** is a field whose name ends in `@` with its values
//!   joined by `,`, as Redis holds it, or a JSON array.
//! - **`NULL: NULL`** is how a row with no field is kept, and is no
//!   field.
//!
//! # What is left out, and said
//!
//! A table the models do not have, a row no list of its table takes, a
//! field its list does not have, and a value this configuration cannot
//! hold (empty, or of several lines). The mirror is of everything else:
//! one row that cannot be read does not stop the import.

use std::rc::Rc;

use libyang::Entry;
use serde_json::{Map, Value};

use super::sonic::{EXT_LIST, EXT_TABLE};

/// The key a document is wrapped in to be read as CONFIG_DB:
/// `{"CONFIG_DB": { "PORT": { … }, … }}`. It is how a document given to
/// `vtyctl apply` says it is not a configuration of this daemon in
/// JSON, which it would otherwise be read as.
pub const WRAPPER: &str = "CONFIG_DB";

/// The tables of `document` when it is CONFIG_DB in its wrapper.
pub fn document(document: &str) -> Option<Map<String, Value>> {
    if !document.trim_start().starts_with('{') {
        return None;
    }
    let Value::Object(mut top) = serde_json::from_str(document).ok()? else {
        return None;
    };
    if top.len() != 1 {
        return None;
    }
    match top.remove(WRAPPER)? {
        Value::Object(tables) => Some(tables),
        _ => None,
    }
}

/// The lines CONFIG_DB translates to, and what of it they leave out.
#[derive(Default, Debug)]
pub struct Translation {
    /// `set sonic …` lines, a row's own line ahead of its fields'.
    pub lines: Vec<String>,
    /// What was left out, one line each.
    pub problems: Vec<String>,
    /// The tables that were read, and those the models do not have.
    pub tables: usize,
    pub unmodelled: Vec<String>,
    pub rows: usize,
}

/// Where the rows of a table go under `sonic`.
enum Target {
    /// The rows with this fixed key: a container.
    Row {
        key: String,
        path: Vec<String>,
        entry: Rc<Entry>,
    },
    /// The rows of a list.
    List { path: Vec<String>, entry: Rc<Entry> },
}

fn targets(sonic: &Rc<Entry>, table: &str) -> Vec<Target> {
    let mut targets = Vec::new();
    for entry in sonic.dir.borrow().iter() {
        if entry.extension.get(EXT_TABLE).map(String::as_str) != Some(table) {
            continue;
        }
        if entry.extension.contains_key(EXT_LIST) {
            targets.push(Target::List {
                path: vec![entry.name.clone()],
                entry: entry.clone(),
            });
            continue;
        }
        for child in entry.dir.borrow().iter() {
            let path = vec![entry.name.clone(), child.name.clone()];
            if child.is_list() {
                targets.push(Target::List {
                    path,
                    entry: child.clone(),
                });
            } else if child.is_container() {
                targets.push(Target::Row {
                    key: child.name.clone(),
                    path,
                    entry: child.clone(),
                });
            }
        }
    }
    targets
}

/// One value as it is typed, or why it cannot be.
fn scalar(value: &Value) -> Result<String, &'static str> {
    let text = match value {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        _ => return Err("is not a string, a number or a boolean"),
    };
    if text.trim().is_empty() {
        return Err("is empty");
    }
    if text.contains(['\n', '\r']) {
        return Err("has more than one line");
    }
    Ok(text)
}

/// Translate the tables of CONFIG_DB to `set sonic …` lines.
///
/// `accepts` says whether a line would be taken by the schema. It is
/// asked only to choose between two lists of one table that have the
/// same number of keys.
pub fn translate(
    sonic: &Rc<Entry>,
    tables: &Map<String, Value>,
    accepts: impl Fn(&str) -> bool,
) -> Translation {
    let mut out = Translation::default();
    for (table, rows) in tables.iter() {
        let targets = targets(sonic, table);
        if targets.is_empty() {
            out.unmodelled.push(table.clone());
            continue;
        }
        let Value::Object(rows) = rows else {
            out.problems
                .push(format!("{table}: is not a table of rows"));
            continue;
        };
        out.tables += 1;
        for (key, fields) in rows.iter() {
            let Some((path, entry, is_entry)) = row_target(&targets, key, &accepts) else {
                out.problems.push(format!(
                    "{table}|{key}: no list of the table takes this key"
                ));
                continue;
            };
            out.rows += 1;
            let row = format!("set sonic {}", path.join(" "));
            // A list entry is there by its own line, fields or none. A
            // row with a fixed key is a container, which is there by
            // what is in it.
            if is_entry {
                out.lines.push(row.clone());
            }
            let Value::Object(fields) = fields else {
                out.problems
                    .push(format!("{table}|{key}: is not a row of fields"));
                continue;
            };
            for (field, value) in fields.iter() {
                if field == "NULL" {
                    continue;
                }
                let name = field.strip_suffix('@').unwrap_or(field);
                // A key of the row is in its line already.
                if entry.key.iter().any(|k| k == name) {
                    continue;
                }
                let Some(leaf) = entry.dir.borrow().iter().find(|e| e.name == name).cloned() else {
                    out.problems
                        .push(format!("{table}|{key}: no field `{name}` in the model"));
                    continue;
                };
                let values: Vec<Value> = match value {
                    Value::Array(members) => members.clone(),
                    Value::String(s) if field.ends_with('@') || leaf.is_leaflist() => s
                        .split(',')
                        .filter(|member| !member.is_empty())
                        .map(|member| Value::String(member.to_string()))
                        .collect(),
                    other => vec![other.clone()],
                };
                for value in values.iter() {
                    match scalar(value) {
                        Ok(text) => out.lines.push(format!("{row} {name} {text}")),
                        Err(why) => out
                            .problems
                            .push(format!("{table}|{key}: the value of `{name}` {why}")),
                    }
                }
            }
        }
    }
    out
}

/// The entry a row with `key` is under, the path to the row, and
/// whether the row is an entry of a list.
fn row_target(
    targets: &[Target],
    key: &str,
    accepts: &impl Fn(&str) -> bool,
) -> Option<(Vec<String>, Rc<Entry>, bool)> {
    for target in targets {
        if let Target::Row {
            key: fixed,
            path,
            entry,
        } = target
            && fixed == key
        {
            return Some((path.clone(), entry.clone(), false));
        }
    }
    let parts: Vec<&str> = key.split('|').collect();
    if parts
        .iter()
        .any(|part| part.is_empty() || part.contains(char::is_whitespace))
    {
        return None;
    }
    let mut same_arity = targets.iter().filter_map(|target| match target {
        Target::List { path, entry } if entry.key.len() == parts.len() => {
            let mut path = path.clone();
            path.extend(parts.iter().map(|part| part.to_string()));
            Some((path, entry.clone(), true))
        }
        _ => None,
    });
    let first = same_arity.next()?;
    let Some(second) = same_arity.next() else {
        return Some(first);
    };
    // Two lists with as many keys: the one whose keys these are.
    [first.clone(), second]
        .into_iter()
        .chain(same_arity)
        .find(|(path, _, _)| accepts(&format!("sonic {}", path.join(" "))))
        .or(Some(first))
}
