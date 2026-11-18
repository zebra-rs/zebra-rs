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
//! - **A map** (`DSCP_TO_TC_MAP|AZURE` is `{"0": "1", "8": "0"}`) is a
//!   row whose fields are the entries of the one list its model has
//!   inside it: the field's name is the entry's key, its value the
//!   entry's one leaf ([`map_list`]).
//!
//! # What is left out, and said
//!
//! A table the models do not have, a row no list of its table takes, a
//! field its list does not have, and a value this configuration cannot
//! hold (empty, or of several lines). The mirror is of everything else:
//! one row that cannot be read does not stop the import.

use std::collections::{BTreeMap, BTreeSet};
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
            let map = map_list(&entry);
            for (field, value) in fields.iter() {
                if field == "NULL" {
                    continue;
                }
                let name = field.strip_suffix('@').unwrap_or(field);
                // A key of the row is in its line already.
                if entry.key.iter().any(|k| k == name) {
                    continue;
                }
                let leaf = entry
                    .dir
                    .borrow()
                    .iter()
                    .find(|e| e.name == name && e.is_leaf_entry())
                    .cloned();
                let Some(leaf) = leaf else {
                    // No leaf of the row: an entry of its map, when it
                    // is one.
                    match (&map, scalar(value)) {
                        (None, _) => out
                            .problems
                            .push(format!("{table}|{key}: no field `{name}` in the model")),
                        (Some(_), _) if field.is_empty() || field.contains(char::is_whitespace) => {
                            out.problems
                                .push(format!("{table}|{key}: `{field}` is not one word"))
                        }
                        (Some((list, leaf)), Ok(text)) => out
                            .lines
                            .push(format!("{row} {list} {field} {leaf} {text}")),
                        (Some(_), Err(why)) => out
                            .problems
                            .push(format!("{table}|{key}: the value of `{field}` {why}")),
                    }
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

/// The list inside a row that CONFIG_DB holds as the row's own fields,
/// as (the list, its leaf): SONiC's maps. The model of `DSCP_TO_TC_MAP`
/// is a row `AZURE` with `list DSCP_TO_TC_MAP { key "dscp"; leaf dscp;
/// leaf tc; }` in it, and CONFIG_DB holds `{"0": "1", "8": "0"}`: each
/// field is an entry, its name the key and its value the one leaf
/// besides.
///
/// A row has one such list or none. With two, a field would not say
/// which it is an entry of; with more keys or more leaves, a field and
/// its value would not say all of an entry.
pub(super) fn map_list(row: &Rc<Entry>) -> Option<(String, String)> {
    let dir = row.dir.borrow();
    let mut lists = dir.iter().filter(|e| e.is_list());
    let (list, None) = (lists.next()?, lists.next()) else {
        return None;
    };
    let [key] = list.key.as_slice() else {
        return None;
    };
    let inside = list.dir.borrow();
    let mut leaves = inside.iter().filter(|e| e.name != *key);
    match (leaves.next(), leaves.next()) {
        (Some(leaf), None) if leaf.is_leaf() => Some((list.name.clone(), leaf.name.clone())),
        _ => None,
    }
}

// --- The other way: the `sonic` subtree as CONFIG_DB, and a change of
// it as a patch ---

use super::configs::Config;

/// A `sonic` subtree as the tables of CONFIG_DB it stands for.
#[derive(Default, Debug)]
pub struct Export {
    /// The tables, as `config_db.json` has them: the inverse of
    /// [`translate`]. Every value is a string, as CONFIG_DB holds it; a
    /// leaf-list is an array of them; a row with no field is `{}`.
    pub tables: Map<String, Value>,
    /// The lines of the subtree that no row or field of `tables` stands
    /// for: a leaf with no value, an entry of a map with no value, and
    /// whatever else a model puts under a row that CONFIG_DB has no form
    /// for. A change of one cannot be made in CONFIG_DB by a patch of
    /// `tables`, and whoever makes the patch has to know
    /// (`ConfigManager::config_db_patch`).
    pub unplaced: Vec<String>,
}

impl Export {
    fn put(&mut self, table: &str, key: String, fields: Map<String, Value>) {
        let rows = self
            .tables
            .entry(table.to_string())
            .or_insert_with(|| Value::Object(Map::new()));
        if let Value::Object(rows) = rows {
            rows.insert(key, Value::Object(fields));
        }
    }

    /// The entries of `list`, each a row of `table` under its keys
    /// joined by `|`.
    fn rows(&mut self, table: &str, list: &Rc<Config>, entry: &Rc<Entry>) {
        for (keys, row) in list.entries() {
            let key: Vec<String> = keys.into_iter().map(|(_, value)| value).collect();
            let fields = fields(&row, entry, &mut self.unplaced);
            self.put(table, key.join("|"), fields);
        }
    }
}

/// The lines of `node` and of what is under it.
fn lines_of(node: &Config, lines: &mut Vec<String>) {
    let mut text = String::new();
    node.list(&mut text);
    lines.extend(text.lines().map(str::to_string));
}

/// The tables of CONFIG_DB a `sonic` subtree stands for, and what of
/// the subtree they do not say.
pub fn export(schema: &Rc<Entry>, sonic: Option<&Rc<Config>>) -> Export {
    let mut out = Export::default();
    let Some(sonic) = sonic else {
        return out;
    };
    let entry_of = |parent: &Rc<Entry>, name: &str| {
        parent.dir.borrow().iter().find(|e| e.name == name).cloned()
    };
    for node in sonic.configs.borrow().iter() {
        let Some(entry) = entry_of(schema, &node.name) else {
            lines_of(node, &mut out.unplaced);
            continue;
        };
        let table = entry
            .extension
            .get(EXT_TABLE)
            .cloned()
            .unwrap_or_else(|| node.name.clone());
        if entry.extension.contains_key(EXT_LIST) {
            out.rows(&table, node, &entry);
            continue;
        }
        // The table as it is: rows with fixed keys, and lists by name.
        for child in node.configs.borrow().iter() {
            match entry_of(&entry, &child.name) {
                Some(list) if list.is_list() => out.rows(&table, child, &list),
                Some(row) if row.is_container() => {
                    let fields = fields(child, &row, &mut out.unplaced);
                    out.put(&table, child.name.clone(), fields);
                }
                _ => lines_of(child, &mut out.unplaced),
            }
        }
    }
    out
}

/// The fields of a row: its leaves, its leaf-lists, and the entries of
/// its map ([`map_list`]). What of the row is none of them goes to
/// `unplaced`, as its lines.
fn fields(row: &Rc<Config>, entry: &Rc<Entry>, unplaced: &mut Vec<String>) -> Map<String, Value> {
    let mut out = Map::new();
    let map = map_list(entry);
    for node in row.configs.borrow().iter() {
        if let Some((list, leaf)) = &map
            && node.name == *list
        {
            for (keys, mapping) in node.entries() {
                let value = match mapping.configs.borrow().as_slice() {
                    [only] if only.name == *leaf && !only.has_dir() => only.value.borrow().clone(),
                    _ => String::new(),
                };
                match keys.as_slice() {
                    [(_, key)] if !value.is_empty() => {
                        out.insert(key.clone(), Value::String(value));
                    }
                    _ => lines_of(&mapping, unplaced),
                }
            }
            continue;
        }
        let members = node.list.borrow();
        if !members.is_empty() {
            let members = members.iter().cloned().map(Value::String).collect();
            out.insert(node.name.clone(), Value::Array(members));
        } else if !node.value.borrow().is_empty() && !node.has_dir() {
            out.insert(
                node.name.clone(),
                Value::String(node.value.borrow().clone()),
            );
        } else {
            lines_of(node, unplaced);
        }
    }
    out
}

/// One step of a JSON Pointer (RFC 6901): a row's key has `/` in it
/// when it holds a prefix.
fn pointer(steps: &[&str]) -> String {
    steps
        .iter()
        .map(|step| format!("/{}", step.replace('~', "~0").replace('/', "~1")))
        .collect()
}

/// The rows CONFIG_DB had at its last copy that the `sonic` subtree does
/// not stand for, by table: a row no list of its table takes, one the
/// model refuses, a row with a fixed key and no field that could be
/// read, and every row of a table with no model.
///
/// It is what a patch has to know besides the two subtrees it is
/// between ([`patch`]): the subtree alone does not say whether CONFIG_DB
/// has a table, nor a row.
pub type LeftOut = BTreeMap<String, BTreeSet<String>>;

/// What of `config_db` the tables `mirrored` do not have a row for.
pub fn left_out(config_db: &Map<String, Value>, mirrored: &Map<String, Value>) -> LeftOut {
    let mut out = LeftOut::new();
    for (table, rows) in config_db {
        let Value::Object(rows) = rows else {
            continue;
        };
        let mirrored = match mirrored.get(table) {
            Some(Value::Object(mirrored)) => Some(mirrored),
            _ => None,
        };
        let missing: BTreeSet<String> = rows
            .keys()
            .filter(|key| !mirrored.is_some_and(|mirrored| mirrored.contains_key(*key)))
            .cloned()
            .collect();
        if !missing.is_empty() {
            out.insert(table.clone(), missing);
        }
    }
    out
}

/// What turns the tables `from` into the tables `to`, as a JSON Patch
/// (RFC 6902) on `config_db.json`: the form SONiC's `config apply-patch`
/// takes.
///
/// It says only what differs, field by field. What neither side has is
/// not in it, so what the copy leaves out of CONFIG_DB (a table with no
/// model, a row or a value it cannot hold) is not touched by applying
/// it.
///
/// A table is added with its first row and removed with its last:
/// CONFIG_DB has no table with no row. Which row is the first and which
/// the last is CONFIG_DB's to say, not the subtree's, and `left_out` is
/// what it said at the last copy: a table that has a row there is
/// neither added, which would replace it, nor removed. A row that is
/// there is not added either, for the same reason: its fields are.
pub fn patch(from: &Map<String, Value>, to: &Map<String, Value>, left_out: &LeftOut) -> Vec<Value> {
    let op = |op: &str, path: String, value: Option<&Value>| {
        let mut step = Map::new();
        step.insert("op".to_string(), Value::String(op.to_string()));
        step.insert("path".to_string(), Value::String(path));
        if let Some(value) = value {
            step.insert("value".to_string(), value.clone());
        }
        Value::Object(step)
    };
    let rows = |tables: &'_ Map<String, Value>, table: &str| -> Map<String, Value> {
        match tables.get(table) {
            Some(Value::Object(rows)) => rows.clone(),
            _ => Map::new(),
        }
    };
    let mut names: Vec<&String> = from.keys().chain(to.keys()).collect();
    names.sort();
    names.dedup();

    let none = BTreeSet::new();
    let mut steps = Vec::new();
    for table in names {
        let (old, new) = (rows(from, table), rows(to, table));
        // The rows of the table CONFIG_DB has besides `old`.
        let others = left_out.get(table).unwrap_or(&none);
        if others.is_empty() {
            if new.is_empty() {
                if !old.is_empty() {
                    steps.push(op("remove", pointer(&[table]), None));
                }
                continue;
            }
            if old.is_empty() {
                steps.push(op("add", pointer(&[table]), Some(&Value::Object(new))));
                continue;
            }
        }
        let mut keys: Vec<&String> = old.keys().chain(new.keys()).collect();
        keys.sort();
        keys.dedup();
        let empty = Map::new();
        for key in keys {
            let (was, is) = match (old.get(key), new.get(key)) {
                (Some(_), None) => {
                    steps.push(op("remove", pointer(&[table, key]), None));
                    continue;
                }
                (None, Some(row)) if !others.contains(key) => {
                    steps.push(op("add", pointer(&[table, key]), Some(row)));
                    continue;
                }
                // A row CONFIG_DB has and the subtree did not: what is
                // set in it now is added to what it has.
                (None, Some(Value::Object(is))) => (&empty, is),
                (Some(Value::Object(was)), Some(Value::Object(is))) => (was, is),
                _ => continue,
            };
            let mut fields: Vec<&String> = was.keys().chain(is.keys()).collect();
            fields.sort();
            fields.dedup();
            for field in fields {
                let path = pointer(&[table, key, field]);
                match (was.get(field), is.get(field)) {
                    (Some(_), None) => steps.push(op("remove", path, None)),
                    (None, Some(value)) => steps.push(op("add", path, Some(value))),
                    (Some(a), Some(b)) if a != b => steps.push(op("replace", path, Some(b))),
                    _ => {}
                }
            }
        }
    }
    steps
}
