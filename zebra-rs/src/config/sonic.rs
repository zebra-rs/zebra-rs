//! SONiC's YANG models as a `sonic` subtree of the configuration.
//!
//! `docs/design/sonic-junos-style-config.md`, phase 2. SONiC ships a
//! YANG model of its CONFIG_DB tables (`sonic-yang-models`). With
//! `--feature sonic` they are read from the directory `sonic` under the
//! YANG path, and are the schema of everything under `set sonic`: what
//! may be typed, with which keys, and which values each leaf takes.
//!
//! # The shape of a table
//!
//! A module is `container sonic-vlan { container VLAN { list VLAN_LIST {
//! key "name"; … } } }`: the module's container, the table, and the
//! list of its rows. Neither the module's container nor the word
//! `_LIST` says anything an operator needs, so the tree here is flatter:
//!
//! | In the model | Under `sonic` |
//! |---|---|
//! | A table whose children are lists | Each list, by its name without `_LIST`: `VLAN Vlan100 …`, `INTERFACE Ethernet0`, `INTERFACE_IPPREFIX Ethernet0 10.0.0.0/31` |
//! | A table with containers (rows with fixed keys) | The table as it is: `DEVICE_METADATA localhost hostname …` |
//!
//! A table with both keeps its lists under it, with their own names.
//! Every entry made from a list or a table says where it came from, in
//! the extensions `sonic:table` and `sonic:list`: what the row is in
//! CONFIG_DB is read from there, not from the keyword.
//!
//! # What is changed in a model
//!
//! - **Help.** A node's `description` is its help text; SONiC's models
//!   have no `ext:help`.
//! - **Free text.** A string leaf with no `pattern` takes the rest of
//!   the line as its value. CONFIG_DB holds such values with spaces in
//!   them (`description`), and this CLI has no quoting. A key is always
//!   one word.
//!
//! The `sonic-events-*` modules describe events, not configuration, and
//! are left out.

use std::collections::HashMap;
use std::path::Path;
use std::rc::Rc;

use libyang::{DatadefNode, Entry, EntryKind, ListAttr, YangStore, YangType, to_entry};

/// The table a `sonic` entry is a row (or the whole) of in CONFIG_DB.
pub const EXT_TABLE: &str = "sonic:table";
/// The list of the model an entry made from a list is.
pub const EXT_LIST: &str = "sonic:list";

/// The directory of SONiC's models under the YANG path, when the image
/// has one.
pub fn models_dir(yang_path: &str) -> Option<std::path::PathBuf> {
    yang_path
        .split(':')
        .map(|dir| Path::new(dir).join("sonic"))
        .find(|dir| dir.is_dir())
}

/// The `sonic` entry built from the models in `dir`, and what went
/// wrong on the way. `yang_path` is where the models' imports that are
/// not SONiC's own are found (`ietf-inet-types`, `ietf-yang-types`).
///
/// A module that does not load is reported and left out; the others
/// are still there.
pub fn sonic_entry(yang_path: &str, dir: &Path) -> (Rc<Entry>, Vec<String>) {
    let mut problems = Vec::new();
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .map(|listing| {
            listing
                .filter_map(|e| e.ok()?.file_name().into_string().ok())
                .filter_map(|n| n.strip_suffix(".yang").map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    names.sort();

    let mut store = YangStore::new();
    store.add_path(&format!("{}:{yang_path}", dir.display()));
    let mut loaded = Vec::new();
    for name in &names {
        if store.find_module(name).is_none()
            && let Err(e) = store.read_with_resolve(name)
        {
            problems.push(format!("{name}: {e}"));
            continue;
        }
        loaded.push(name.clone());
    }
    store.identity_resolve();

    let mut children: Vec<Rc<Entry>> = Vec::new();
    // Which module each keyword under `sonic` came from.
    let mut taken: HashMap<String, String> = HashMap::new();
    for name in loaded.iter().filter(|n| !n.starts_with("sonic-events")) {
        let Some(module) = store.find_module(name) else {
            continue;
        };
        let root = to_entry(&store, module);
        for top in root.dir.borrow().iter() {
            let top_doc = Doc::child(Some(&module.d), &top.name);
            for table in top.dir.borrow().iter() {
                let table_doc = Doc::child(top_doc.d, &table.name);
                for entry in table_entries(table, &table_doc) {
                    if let Some(other) = taken.insert(entry.name.clone(), name.clone()) {
                        problems.push(format!(
                            "{name}: `{}` is already defined by {other}; left out",
                            entry.name
                        ));
                        taken.insert(entry.name.clone(), other);
                        continue;
                    }
                    children.push(entry);
                }
            }
        }
    }
    for diag in store.take_diagnostics() {
        problems.push(diag.to_string());
    }

    let mut sonic = Entry::new_dir("sonic".to_string());
    sonic.extension.insert(
        "ext:help".to_string(),
        "SONiC configuration tables".to_string(),
    );
    sonic.dir = std::cell::RefCell::new(children);
    (Rc::new(sonic), problems)
}

/// What a table of a model is under `sonic`: its lists, each by its
/// name without `_LIST`, or the table itself when it has anything that
/// is not a list.
fn table_entries(table: &Rc<Entry>, doc: &Doc) -> Vec<Rc<Entry>> {
    let table_ext = |entry: &mut Entry| {
        entry
            .extension
            .insert(EXT_TABLE.to_string(), table.name.clone());
    };
    let kids = table.dir.borrow();
    if kids.is_empty() || !kids.iter().all(|kid| kid.is_list()) {
        let mut entry = copy(table, doc, false);
        table_ext(&mut entry);
        return vec![Rc::new(entry)];
    }
    kids.iter()
        .map(|list| {
            let list_doc = Doc::child(doc.d, &list.name);
            let mut entry = copy(list, &list_doc, false);
            // A list says little of itself where the table says it.
            if list_doc.description.is_none()
                && let Some(help) = doc.description.and_then(help_text)
            {
                entry.extension.insert("ext:help".to_string(), help);
            }
            entry.name = list
                .name
                .strip_suffix("_LIST")
                .unwrap_or(&list.name)
                .to_string();
            entry
                .extension
                .insert(EXT_LIST.to_string(), list.name.clone());
            table_ext(&mut entry);
            Rc::new(entry)
        })
        .collect()
}

/// Where a node is in a module as it was written: its description, and
/// what is under it. An entry tree has neither the one nor, for what a
/// `uses` brought in, the other; such a node has no description here.
struct Doc<'a> {
    description: Option<&'a str>,
    d: Option<&'a DatadefNode>,
}

impl<'a> Doc<'a> {
    fn child(d: Option<&'a DatadefNode>, name: &str) -> Doc<'a> {
        let none = Doc {
            description: None,
            d: None,
        };
        let Some(d) = d else {
            return none;
        };
        if let Some(c) = d.container.iter().find(|c| c.name == name) {
            return Doc {
                description: c.description.as_deref(),
                d: Some(&c.d),
            };
        }
        if let Some(l) = d.list.iter().find(|l| l.name == name) {
            return Doc {
                description: l.description.as_deref(),
                d: Some(&l.d),
            };
        }
        if let Some(l) = d.leaf.iter().find(|l| l.name == name) {
            return Doc {
                description: l.description.as_deref(),
                d: None,
            };
        }
        if let Some(l) = d.leaf_list.iter().find(|l| l.name == name) {
            return Doc {
                description: l.description.as_deref(),
                d: None,
            };
        }
        // The children of a case are those of the choice's parent in
        // the entry tree.
        for case in d.choice.iter().flat_map(|choice| choice.cases.iter()) {
            let found = Doc::child(Some(&case.d), name);
            if found.description.is_some() || found.d.is_some() {
                return found;
            }
        }
        none
    }
}

/// A description as one line of help: its first line, or sentence.
fn help_text(description: &str) -> Option<String> {
    const MAX: usize = 72;
    let line = description.lines().map(str::trim).find(|l| !l.is_empty())?;
    let line = line.split_once(". ").map_or(line, |(first, _)| first);
    let line = line.trim_end_matches('.');
    let mut help: String = line.chars().take(MAX).collect();
    if line.chars().count() > MAX {
        help.push('…');
    }
    Some(help)
}

/// A copy of `entry` and what is under it, with the changes this module
/// makes to a model. `is_key` says the entry is a key of its list.
fn copy(entry: &Rc<Entry>, doc: &Doc, is_key: bool) -> Entry {
    let mut extension = entry.extension.clone();
    if !extension.contains_key("ext:help")
        && let Some(help) = doc.description.and_then(help_text)
    {
        extension.insert("ext:help".to_string(), help);
    }

    let mut type_node = entry.type_node.clone();
    if let Some(node) = type_node.as_mut()
        && entry.is_leaf()
        && !is_key
        && node.kind == YangType::String
        && node.pattern.is_none()
    {
        node.pattern = Some(".*".to_string());
    }

    let children = entry
        .dir
        .borrow()
        .iter()
        .map(|child| {
            let child_doc = Doc::child(doc.d, &child.name);
            Rc::new(copy(child, &child_doc, entry.key.contains(&child.name)))
        })
        .collect();

    Entry {
        name: entry.name.clone(),
        kind: match entry.kind {
            EntryKind::LeafEntry => EntryKind::LeafEntry,
            EntryKind::DirectoryEntry => EntryKind::DirectoryEntry,
            EntryKind::ChoiceEntry => EntryKind::ChoiceEntry,
            EntryKind::ActionEntry => EntryKind::ActionEntry,
        },
        presence: entry.presence,
        mandatory: entry.mandatory,
        dir: std::cell::RefCell::new(children),
        key: entry.key.clone(),
        extension,
        parent: std::cell::RefCell::new(None),
        type_node,
        list_attr: entry.list_attr.as_ref().map(|attr| ListAttr {
            min_elements: attr.min_elements,
            max_elements: attr.max_elements,
            ordered_by_user: attr.ordered_by_user,
        }),
        choice_cases: entry.choice_cases.clone(),
        choice: std::cell::RefCell::new(entry.choice.borrow().clone()),
        case: std::cell::RefCell::new(entry.case.borrow().clone()),
        choice_defs: std::cell::RefCell::new(entry.choice_defs.borrow().clone()),
    }
}

/// The `sonic` entry of the configure-mode tree, when it has one.
pub fn grafted(configure: &Rc<Entry>) -> Option<Rc<Entry>> {
    let set = configure
        .dir
        .borrow()
        .iter()
        .find(|e| e.name == "set")
        .cloned()?;
    let under_set = set.dir.borrow();
    under_set.iter().find(|e| e.name == "sonic").cloned()
}

/// Put `sonic` under `set` and `delete` of the configure-mode tree.
pub fn graft(configure: &Rc<Entry>, sonic: &Rc<Entry>) {
    for top in configure.dir.borrow().iter() {
        if top.name == "set" || top.name == "delete" {
            top.dir.borrow_mut().push(sonic.clone());
        }
    }
}
