use super::Config;
use super::parse::State;
use super::parse::{entry_is_key, ymatch_complete, ytype_from_typedef};
use super::vty::YangMatch;
use libyang::{Entry, TypeNode, YangType};
use std::collections::HashSet;
use std::rc::Rc;

#[derive(Debug, Default, Clone)]
pub struct Completion {
    pub name: String,
    pub help: String,
    pub ymatch: YangMatch,
}

impl Completion {
    pub fn new(name: &str, help: &str) -> Self {
        Self {
            name: name.to_string(),
            help: help.to_string(),
            ymatch: YangMatch::Leaf,
        }
    }

    pub fn new_name(name: &str) -> Self {
        Self {
            name: name.to_string(),
            ymatch: YangMatch::Leaf,
            ..Default::default()
        }
    }
}

pub fn cname(name: &str) -> Completion {
    Completion {
        name: name.to_string(),
        ymatch: YangMatch::Leaf,
        ..Default::default()
    }
}

pub fn crange(e: &Rc<Entry>, n: &TypeNode) -> Completion {
    let name = if let Some(range) = &n.range {
        range.to_string()
    } else {
        format!("<{}:{}>", e.name.to_owned(), ytype_str(&n.kind))
    };
    Completion::new_name(&name)
}

fn ytype_str(ytype: &YangType) -> &'static str {
    match ytype {
        YangType::Binary => "bianry",
        YangType::Bits => "bits",
        YangType::Boolean => "boolean",
        YangType::Decimal64 => "dicimal64",
        YangType::Empty => "empty",
        YangType::Enumeration => "enumeration",
        YangType::Int8 => "int8",
        YangType::Int16 => "int16",
        YangType::Int32 => "int32",
        YangType::Int64 => "int64",
        YangType::String => "string",
        YangType::Uint8 => "uint8",
        YangType::Uint16 => "uint16",
        YangType::Uint32 => "uint32",
        YangType::Uint64 => "uint64",
        YangType::Union => "union",
        YangType::Leafref => "leafref",
        YangType::Identityref => "identityref",
        YangType::Path => "path",
        YangType::Ipv4Addr => "<A.B.C.D>",
        YangType::Ipv4Prefix => "<A.B.C.D/M>",
        YangType::Ipv6Addr => "<X:X::X:X>",
        YangType::Ipv6Prefix => "<X:X::X:X/M>",
        YangType::MacAddr => "<XX:XX:XX:XX:XX:XX>",
        YangType::NsapAddr => "<XX.XXXX..XXXX.XX>",
    }
}

pub fn centry(entry: &Rc<Entry>) -> Completion {
    let ymatch = if entry.has_key() {
        YangMatch::Key
    } else if entry.is_directory_entry() {
        YangMatch::Dir
    } else {
        YangMatch::Leaf
    };
    Completion {
        name: entry.name.clone(),
        help: comps_help_string(entry).clone(),
        ymatch,
    }
}

pub fn cleaf(entry: &Rc<Entry>) -> Completion {
    let name = if let Some(node) = &entry.type_node {
        if let Some(ytype) = ytype_from_typedef(&node.typedef) {
            ytype_str(&ytype).to_string()
        } else if let Some(range) = &node.range {
            range.to_string()
        } else if node.kind == YangType::Leafref {
            match &node.path {
                Some(path) => format!("<{} -> {}>", entry.name, path),
                None => format!("<{}:leafref>", entry.name),
            }
        } else {
            format!("<{}:{}>", entry.name, ytype_str(&node.kind))
        }
    } else {
        format!("<{}>", entry.name)
    };
    let help = entry.extension.get("ext:help").map_or("", |v| v);
    Completion {
        name: name.to_string(),
        help: help.to_string(),
        ymatch: YangMatch::Leaf,
    }
}

pub fn comps_add_cr(comps: &mut Vec<Completion>) {
    comps.push(Completion::new_name("<cr>"));
}

pub fn comps_append(from: &mut Vec<Completion>, to: &mut Vec<Completion>) {
    let mut existing: HashSet<String> = to.iter().map(|c| c.name.clone()).collect();
    for comp in from.drain(..) {
        if existing.insert(comp.name.clone()) {
            to.push(comp);
        }
    }
}

pub fn comps_help_string(e: &Entry) -> String {
    match e.extension.get("ext:help") {
        Some(help) => String::from(help),
        None => String::from(""),
    }
}

pub fn comps_add_config(
    comps: &mut Vec<Completion>,
    ymatch: YangMatch,
    config: &Option<Rc<Config>>,
) {
    if ymatch == YangMatch::LeafMatched {
        comps_add_cr(comps);
        return;
    }
    if let Some(config) = config {
        if config.has_dir() {
            for config in config.configs.borrow().iter() {
                comps.push(Completion::new_name(&config.name));
            }
            if ymatch == YangMatch::Key {
                for key in config.keys.borrow().iter() {
                    comps.push(Completion::new_name(&key.name));
                }
            }
        } else if config.list.borrow().is_empty() {
            if !config.value.borrow().is_empty() {
                comps.push(Completion::new_name(&config.value.borrow()));
            }
        } else {
            for value in config.list.borrow().iter() {
                comps.push(Completion::new_name(value));
            }
        }
    }
    if ymatch == YangMatch::DirMatched {
        comps_add_cr(comps)
    }
}

pub fn comps_as_key(entry: &Rc<Entry>) -> Completion {
    let mut comp = cleaf(entry);
    comp.ymatch = YangMatch::Key;
    comp
}

fn comps_as_leaf(comps: &mut Vec<Completion>, entry: &Rc<Entry>) {
    if let Some(node) = &entry.type_node {
        if node.kind == YangType::Boolean {
            comps.push(Completion::new_name("true"));
            comps.push(Completion::new_name("false"));
            return;
        }
        if node.kind == YangType::Enumeration {
            for e in node.enum_stmt.iter() {
                comps.push(Completion::new_name(&e.name));
            }
            return;
        }
        if node.kind == YangType::Union {
            // One hint per arm, mirroring how the matcher dispatches:
            // enum arms surface their keywords (`show bgp ipv4 ?` ->
            // `summary`), scalar arms their type hints (`<A.B.C.D>`),
            // instead of an opaque `<value:union>`.
            for n in node.union.iter() {
                comps_push_arm(comps, n);
            }
            return;
        }
    }
    comps.push(comps_as_key(entry));
}

/// Push the completion hint(s) for one union arm: an enumeration arm
/// contributes its keywords, anything else its type hint. Skips names
/// already present so a keyword that also exists as a sibling node
/// (e.g. the `summary` leaf next to the `ipv4` default-child whose key
/// has a `summary` enum arm) is listed once.
fn comps_push_arm(comps: &mut Vec<Completion>, arm: &TypeNode) {
    let mut push_unique = |name: &str| {
        if !comps.iter().any(|c| c.name == name) {
            comps.push(Completion::new_name(name));
        }
    };
    if arm.kind == YangType::Enumeration {
        for e in arm.enum_stmt.iter() {
            push_unique(&e.name);
        }
    } else {
        let kind = ytype_from_typedef(&arm.typedef).unwrap_or(arm.kind);
        push_unique(ytype_str(&kind));
    }
}

/// Emit the positional completion hints contributed by a container's
/// `ext:default-child`. The named child's key may be typed without the
/// child's own keyword (`show bgp <tab>` -> `<A.B.C.D>` / `<A.B.C.D/M>`),
/// so surface that key's type hint(s) next to the child keywords. A
/// union key contributes one hint per arm.
fn comps_default_child_key(comps: &mut Vec<Completion>, parent: &Rc<Entry>) {
    let Some(name) = parent.extension.get("ext:default-child") else {
        return;
    };
    let dir = parent.dir.borrow();
    let Some(child) = dir.iter().find(|e| &e.name == name) else {
        return;
    };
    let Some(key) = child.key.first() else {
        return;
    };
    let child_dir = child.dir.borrow();
    let Some(key_leaf) = child_dir.iter().find(|e| &e.name == key) else {
        return;
    };
    let Some(node) = &key_leaf.type_node else {
        return;
    };
    if node.kind == YangType::Union {
        for n in node.union.iter() {
            comps_push_arm(comps, n);
        }
    } else {
        comps_push_arm(comps, node);
    }
}

pub fn comps_add_all(
    comps: &mut Vec<Completion>,
    ymatch: YangMatch,
    entry: &Rc<Entry>,
    s: &State,
    list_presence: bool,
) {
    // Leaves/keys tagged `ext:no-sort` keep their YANG enum declaration
    // order instead of being alphabetized below (e.g. the BGP afi-safi
    // family list).
    let mut no_sort = false;
    match ymatch {
        YangMatch::Dir | YangMatch::DirMatched => {
            for entry in entry.dir.borrow().iter() {
                comps.push(centry(entry));
            }
            comps_default_child_key(comps, entry);
        }
        YangMatch::KeyMatched => {
            for e in entry.dir.borrow().iter() {
                if !entry_is_key(&e.name, &entry.key) {
                    comps.push(centry(e));
                }
            }
        }
        YangMatch::Key => {
            for key in entry.key.iter() {
                for subent in entry.dir.borrow().iter() {
                    if &subent.name == key {
                        comps_as_leaf(comps, subent);
                        no_sort |= subent.extension.contains_key("ext:no-sort");
                        if let Some(dynamic) = subent.extension.get("ext:dynamic")
                            && let Some(candidates) = s.dynamic.get(dynamic)
                        {
                            for cand in candidates.iter() {
                                comps.push(Completion::new_name(cand));
                            }
                        }
                        if subent.name == "if-name-brief" {
                            comps.push(Completion::new(
                                "brief",
                                "Interface status and configuration summary",
                            ));
                        }
                    }
                }
            }
        }
        YangMatch::LeafMatched => {
            //
        }
        _ => {
            comps_as_leaf(comps, entry);
            no_sort |= entry.extension.contains_key("ext:no-sort");
            if let Some(dynamic) = entry.extension.get("ext:dynamic")
                && let Some(candidates) = s.dynamic.get(dynamic)
            {
                for cand in candidates.iter() {
                    comps.push(Completion::new_name(cand));
                }
            }
        }
    }
    if !no_sort {
        comps.sort_by(|a, b| a.name.cmp(&b.name));
    }

    if ymatch_complete(ymatch, list_presence, s.delete) {
        comps_add_cr(comps);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libyang::EnumNode;

    /// Build an `afi-safi`-style list entry: a list keyed on `name`
    /// whose `name` leaf is an enumeration declared in a deliberately
    /// non-alphabetical order. `tag_no_sort` controls whether the leaf
    /// carries the `ext:no-sort` marker.
    fn afi_safi_list(tag_no_sort: bool) -> Rc<Entry> {
        let mut name_leaf = Entry::new_leaf("name".to_string());
        let mut tn = TypeNode::new("enumeration".to_string(), YangType::Enumeration);
        tn.enum_stmt = ["ipv4", "ipv6", "vpnv4", "vpnv6", "rtcv4", "rtcv6"]
            .iter()
            .map(|n| EnumNode::new((*n).to_string()))
            .collect();
        name_leaf.type_node = Some(tn);
        if tag_no_sort {
            name_leaf
                .extension
                .insert("ext:no-sort".to_string(), "true".to_string());
        }

        let list = Rc::new(Entry::new_list(
            "afi-safi".to_string(),
            vec!["name".to_string()],
        ));
        list.dir.borrow_mut().push(Rc::new(name_leaf));
        list
    }

    fn key_completions(entry: &Rc<Entry>) -> Vec<String> {
        let s = State::new();
        let mut comps = Vec::new();
        comps_add_all(&mut comps, YangMatch::Key, entry, &s, false);
        comps.into_iter().map(|c| c.name).collect()
    }

    /// `ext:no-sort` keeps the enum key completions in their YANG
    /// declaration order (the BGP afi-safi family ordering).
    #[test]
    fn enum_key_no_sort_preserves_declaration_order() {
        assert_eq!(
            key_completions(&afi_safi_list(true)),
            vec!["ipv4", "ipv6", "vpnv4", "vpnv6", "rtcv4", "rtcv6"],
        );
    }

    /// Without the marker the same enum is alphabetized, as before.
    #[test]
    fn enum_key_without_marker_is_alphabetized() {
        assert_eq!(
            key_completions(&afi_safi_list(false)),
            vec!["ipv4", "ipv6", "rtcv4", "rtcv6", "vpnv4", "vpnv6"],
        );
    }
}
