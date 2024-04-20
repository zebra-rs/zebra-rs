use super::parse::State;
use super::parse::{entry_is_key, ymatch_complete, ytype_from_typedef};
use super::vtysh::YangMatch;
use super::Config;
use libyang::{Entry, TypeNode, YangType};
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

// fn ytype_integer(ytype: &YangType) -> bool {
//     match ytype {
//         YangType::Int8
//         | YangType::Int16
//         | YangType::Int32
//         | YangType::Int64
//         | YangType::Uint8
//         | YangType::Uint16
//         | YangType::Uint32
//         | YangType::Uint64 => true,
//         _ => false,
//     }
// }

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
        YangType::Ipv4Addr => "A.B.C.D",
        YangType::Ipv4Prefix => "A.B.C.D/M",
        YangType::Ipv6Addr => "X:X::X:X",
        YangType::Ipv6Prefix => "X:X::X:X/M",
    }
}

pub fn centry(entry: &Rc<Entry>) -> Completion {
    let name = if let Some(ytype) = ytype_from_typedef(&entry.typedef) {
        ytype_str(&ytype).to_string()
    } else if let Some(node) = &entry.type_node {
        if let Some(range) = &node.range {
            range.to_string()
        } else {
            format!("<{}:{}>", entry.name, ytype_str(&node.kind))
        }
    } else {
        format!("<{}>", entry.name)
    };
    let help = entry.extension.get("ext:help").map_or_else(|| "", |v| v);
    Completion {
        name: name.to_string(),
        help: help.to_string(),
        ymatch: YangMatch::Leaf,
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
    let mut comp = centry(entry);
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
    }
    comps.push(comps_as_key(entry));
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
                        comps_as_leaf(comps, entry);
                        if entry.name == "interface" {
                            for link in s.links.iter() {
                                comps.push(Completion::new_name(link));
                            }
                        }
                    }
                }
            }
        }
        YangMatch::LeafMatched => {
            //
        }
        _ => comps_as_leaf(comps, entry),
    }
    comps.sort_by(|a, b| a.name.cmp(&b.name));

    if ymatch_complete(ymatch) {
        comps_add_cr(comps);
    }
}
