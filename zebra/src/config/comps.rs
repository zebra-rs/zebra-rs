use super::parse::{entry_is_key, entry_preset, ymatch_complete};
use super::parse::{PresetType, State};
use super::vtysh::YangMatch;
use super::Config;
use libyang::{Entry, TypeKind, TypeNode};
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

pub fn comps_from_entry(entry: &Rc<Entry>) -> Completion {
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

fn comps_exists(comps: &[Completion], name: &String) -> bool {
    comps.iter().any(|x| x.name == *name)
}

fn comp_integer_string(e: &Rc<Entry>, n: &TypeNode) -> String {
    if let Some(range) = &n.range {
        range.to_string()
    } else {
        format!("<{}>", e.name.to_owned())
    }
}

pub fn comps_range(e: &Rc<Entry>, n: &TypeNode) -> Completion {
    let name = if let Some(range) = &n.range {
        range.to_string()
    } else {
        format!("<{}>", e.name.to_owned())
    };
    Completion::new_name(&name)
}

pub fn comps_add_cr(comps: &mut Vec<Completion>) {
    comps.push(Completion::new_name("<cr>"));
}

pub fn comps_append(from: &mut Vec<Completion>, to: &mut Vec<Completion>) {
    while let Some(comp) = from.pop() {
        if !comps_exists(to, &comp.name) {
            to.push(comp);
        }
    }
}

pub fn comps_leaf_string(e: &Rc<Entry>) -> String {
    if let Some(typedef) = &e.typedef {
        match entry_preset(typedef.to_string()) {
            PresetType::None => {}
            PresetType::IPv4Address => return String::from("A.B.C.D"),
            PresetType::IPv4Prefix => return String::from("A.B.C.D/M"),
            PresetType::IPv6Address => return String::from("X:X::X:X"),
            PresetType::IPv6Prefix => return String::from("X:X::X:X/M"),
        };
    }
    if let Some(node) = e.type_node.as_ref() {
        match node.kind {
            TypeKind::Yint8
            | TypeKind::Yint16
            | TypeKind::Yint32
            | TypeKind::Yint64
            | TypeKind::Yuint8
            | TypeKind::Yuint16
            | TypeKind::Yuint32
            | TypeKind::Yuint64 => comp_integer_string(e, node),
            _ => {
                format!("<{}>", e.name.to_owned())
            }
        }
    } else {
        format!("<{}>", e.name.to_owned())
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
    Completion {
        name: comps_leaf_string(entry),
        help: comps_help_string(entry),
        ymatch: YangMatch::Key,
    }
}

pub fn comps_add_all(comps: &mut Vec<Completion>, ymatch: YangMatch, entry: &Rc<Entry>, s: &State) {
    match ymatch {
        YangMatch::Dir | YangMatch::DirMatched => {
            for entry in entry.dir.borrow().iter() {
                comps.push(comps_from_entry(entry));
            }
        }
        YangMatch::KeyMatched => {
            for e in entry.dir.borrow().iter() {
                if !entry_is_key(&e.name, &entry.key) {
                    comps.push(comps_from_entry(e));
                }
            }
        }
        YangMatch::Key => {
            for key in entry.key.iter() {
                for entry in entry.dir.borrow().iter() {
                    if &entry.name == key {
                        comps.push(comps_as_key(entry));
                        if entry.name == "interface" {
                            for link in s.links.iter() {
                                comps.push(Completion::new_name(&link));
                            }
                        }
                    }
                }
            }
        }
        YangMatch::LeafMatched => {
            //
        }
        _ => {
            if let Some(node) = &entry.type_node {
                if node.kind == TypeKind::Yboolean {
                    comps.push(Completion::new_name("true"));
                    comps.push(Completion::new_name("false"));
                    return;
                }
                if node.kind == TypeKind::Yenumeration {
                    for e in node.enum_stmt.iter() {
                        comps.push(Completion::new_name(&e.name));
                    }
                    return;
                }
            }
            comps.push(comps_as_key(entry));
        }
    }
    comps.sort_by(|a, b| a.name.cmp(&b.name));

    if ymatch_complete(ymatch) {
        comps_add_cr(comps);
    }
}
