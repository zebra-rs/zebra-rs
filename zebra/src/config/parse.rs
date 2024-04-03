use super::comps::{comps_add_cr, comps_append};
use super::configs::config_match;
use super::ip::*;
use super::util::*;
use super::{Completion, Config, Elem, ExecCode};
use libyang::{
    path_split, range_match, Entry, EnumNode, MinMax, RangeExtract, RangeNode, TypeKind, TypeNode,
};
use regex::Regex;
use std::rc::Rc;

#[derive(Debug, PartialEq, Default, Copy, Clone)]
pub enum YangMatch {
    #[default]
    Dir,
    DirMatched,
    Key,
    KeyMatched,
    Leaf,
    LeafMatched,
    LeafList,
    LeafListMatched,
}

#[derive(Default, Debug, PartialEq, PartialOrd)]
pub enum MatchType {
    #[default]
    None,
    Incomplete,
    Partial,
    Exact,
}

#[derive(PartialEq, Debug)]
enum PresetType {
    None,
    IPv4Address,
    IPv4Prefix,
    IPv6Address,
    IPv6Prefix,
}

fn entry_preset(name: String) -> PresetType {
    let (_, name) = path_split(name.clone());
    match name.as_str() {
        "ipv4-address" => PresetType::IPv4Address,
        "ipv4-prefix" => PresetType::IPv4Prefix,
        "ipv6-address" => PresetType::IPv6Address,
        "ipv6-prefix" => PresetType::IPv6Prefix,
        _ => PresetType::None,
    }
}

fn comp_name_string(e: &Rc<Entry>) -> String {
    e.name.to_owned()
}

fn comp_integer_string(e: &Rc<Entry>, n: &TypeNode) -> String {
    if let Some(range) = &n.range {
        range.to_string()
    } else {
        format!("<{}>", e.name.to_owned())
    }
}

fn comp_range(e: &Rc<Entry>, n: &TypeNode) -> Completion {
    let name = if let Some(range) = &n.range {
        range.to_string()
    } else {
        format!("<{}>", e.name.to_owned())
    };
    Completion {
        name,
        help: "".to_owned(),
    }
}

fn comp_leaf_string(e: &Rc<Entry>) -> String {
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

fn comp_help_string(e: &Entry) -> String {
    match e.extension.get("ext:help") {
        Some(help) => String::from(help),
        None => String::from(""),
    }
}

fn comps_add_config(comps: &mut Vec<Completion>, ymatch: YangMatch, config: &Option<Rc<Config>>) {
    if ymatch == YangMatch::LeafMatched {
        comps_add_cr(comps);
        return;
    }
    if let Some(config) = config {
        if config.has_dir() {
            for config in config.configs.borrow().iter() {
                comps.push(Completion {
                    name: config.name.to_owned(),
                    help: "".to_owned(),
                });
            }
            if ymatch == YangMatch::Key {
                for key in config.keys.borrow().iter() {
                    comps.push(Completion {
                        name: key.name.to_owned(),
                        help: "".to_owned(),
                    });
                }
            }
        } else if config.list.borrow().is_empty() {
            comps.push(Completion {
                name: config.value.borrow().clone(),
                help: "".to_owned(),
            });
        } else {
            for value in config.list.borrow().iter() {
                comps.push(Completion {
                    name: value.to_owned(),
                    help: "".to_owned(),
                });
            }
        }
    }
    if ymatch == YangMatch::DirMatched {
        comps_add_cr(comps)
    }
}

fn comps_add_all(comps: &mut Vec<Completion>, ymatch: YangMatch, entry: &Rc<Entry>) {
    match ymatch {
        YangMatch::Dir | YangMatch::DirMatched | YangMatch::KeyMatched => {
            for entry in entry.dir.borrow().iter() {
                comps.push(Completion {
                    name: comp_name_string(entry),
                    help: comp_help_string(entry),
                });
            }
        }
        YangMatch::LeafMatched => {
            //
        }
        _ => {
            if let Some(node) = &entry.type_node {
                if node.kind == TypeKind::Yboolean {
                    comps.push(comp_name("true"));
                    comps.push(comp_name("false"));
                    return;
                }
                if node.kind == TypeKind::Yenumeration {
                    for e in node.enum_stmt.iter() {
                        comps.push(comp_enum(e));
                    }
                    return;
                }
            }
            comps.push(Completion {
                name: comp_leaf_string(entry),
                help: comp_help_string(entry),
            });
        }
    }
    comps.sort_by(|a, b| a.name.cmp(&b.name));

    if ymatch_complete(ymatch) {
        comps_add_cr(comps);
    }
}

pub struct State {
    ymatch: YangMatch,
    index: usize,
    pub set: bool,
    pub delete: bool,
    pub elems: Vec<Elem>,
}

impl State {
    pub fn new() -> Self {
        State {
            ymatch: YangMatch::Dir,
            set: false,
            delete: false,
            elems: Vec::new(),
            index: 0usize,
        }
    }
}

pub fn match_keyword(src: &String, dst: &String) -> (MatchType, usize) {
    let pos = longest_match(src, dst);

    if !is_delimiter(src, pos) {
        return (MatchType::None, pos);
    }
    if is_delimiter(dst, pos) {
        (MatchType::Exact, pos)
    } else {
        (MatchType::Partial, pos)
    }
}

fn match_keyword_str(src: &str, dst: &str) -> (MatchType, usize) {
    let pos = longest_match_str(src, dst);

    if !is_delimiter_str(src, pos) {
        return (MatchType::None, pos);
    }
    if is_delimiter_str(dst, pos) {
        (MatchType::Exact, pos)
    } else {
        (MatchType::Partial, pos)
    }
}

fn match_word(str: &String) -> (MatchType, usize) {
    let mut pos = 0usize;
    while pos < str.len() && !is_whitespace(str, pos) {
        pos += 1;
    }
    (MatchType::Exact, pos)
}

fn match_regexp(s: &str, regstr: &str) -> (MatchType, usize) {
    let pos = 0usize;
    let regex = Regex::new(regstr).unwrap();
    if regex.is_match(s) {
        (MatchType::Exact, pos)
    } else {
        (MatchType::None, pos)
    }
}

fn match_string(s: &String, node: &TypeNode) -> (MatchType, usize) {
    if let Some(pattern) = node.pattern.as_ref() {
        match_regexp(s, pattern)
    } else {
        match_word(s)
    }
}

fn match_range<T: MinMax<T> + PartialOrd + Copy + std::str::FromStr>(
    s: &str,
    node: &TypeNode,
) -> (MatchType, usize)
where
    RangeNode: RangeExtract<T>,
{
    let v = s.parse::<T>();
    if let Ok(v) = v {
        if let Some(range) = &node.range {
            if let Some(range) = range.extract() {
                for r in range.iter() {
                    if range_match(r, v) {
                        return (MatchType::Exact, s.len());
                    }
                }
            }
        }
        (MatchType::Incomplete, s.len())
    } else {
        (MatchType::None, 0usize)
    }
}

#[derive(Debug, Default)]
pub struct Match {
    pub pos: usize,
    pub count: usize,
    pub comps: Vec<Completion>,
    pub matched_entry: Rc<Entry>,
    pub matched_type: MatchType,
    pub matched_config: Rc<Config>,
}

impl Match {
    pub fn new() -> Self {
        Self {
            matched_entry: Rc::new(Entry::new()),
            ..Default::default()
        }
    }

    pub fn process(&mut self, entry: &Rc<Entry>, (m, p): (MatchType, usize), comp: Completion) {
        if m == MatchType::None {
            return;
        }
        if m > self.matched_type {
            self.count = 1;
            self.pos = p;
            self.matched_type = m;
            self.matched_entry = entry.clone();
        } else if m == self.matched_type {
            self.count += 1;
        }
        self.comps.push(comp);
    }

    pub fn match_ipv4_address(&mut self, entry: &Rc<Entry>, s: &String) {
        self.process(entry, match_ipv4_address(s), comp_name("A.B.C.D"));
    }

    pub fn match_ipv4_prefix(&mut self, entry: &Rc<Entry>, s: &String) {
        self.process(entry, match_ipv4_prefix(s), comp_name("A.B.C.D/M"));
    }

    pub fn match_ipv6_address(&mut self, entry: &Rc<Entry>, s: &str) {
        self.process(entry, match_ipv6_address(s), comp_name("X:X::X:X"));
    }

    pub fn match_ipv6_prefix(&mut self, entry: &Rc<Entry>, s: &str) {
        self.process(entry, match_ipv6_prefix(s), comp_name("X:X::X:X/M"));
    }

    pub fn match_string(&mut self, entry: &Rc<Entry>, s: &String, node: &TypeNode) {
        self.process(entry, match_string(s, node), comp_leaf(entry));
    }

    pub fn match_entry_name(&mut self, entry: &Rc<Entry>, s: &str) {
        self.process(entry, match_keyword_str(s, &entry.name), comp_entry(entry));
    }

    pub fn match_enum(&mut self, entry: &Rc<Entry>, node: &TypeNode, s: &String) {
        for n in node.enum_stmt.iter() {
            self.process(entry, match_keyword(s, &n.name), comp_enum(n));
        }
    }

    pub fn match_range<T: MinMax<T> + PartialOrd + Copy + std::str::FromStr>(
        &mut self,
        entry: &Rc<Entry>,
        node: &TypeNode,
        s: &str,
    ) where
        RangeNode: RangeExtract<T>,
    {
        self.process(entry, match_range::<T>(s, node), comp_range(entry, node));
    }

    pub fn match_bool(&mut self, entry: &Rc<Entry>, s: &String) {
        self.process(
            entry,
            match_keyword(s, &"true".to_owned()),
            comp_name("true"),
        );
        self.process(
            entry,
            match_keyword(s, &"false".to_owned()),
            comp_name("false"),
        );
    }
}

fn comp_entry(entry: &Rc<Entry>) -> Completion {
    Completion {
        name: entry.name.to_owned(),
        help: comp_help_string(entry),
    }
}

fn comp_leaf(entry: &Rc<Entry>) -> Completion {
    Completion {
        name: comp_leaf_string(entry),
        help: comp_help_string(entry),
    }
}

fn comp_name(name: &str) -> Completion {
    Completion {
        name: name.to_owned(),
        help: "".to_owned(),
    }
}

fn comp_enum(node: &EnumNode) -> Completion {
    Completion {
        name: node.name.to_owned(),
        help: String::from(""),
    }
}

fn entry_match_type(entry: &Rc<Entry>, s: &String, m: &mut Match) {
    if let Some(typedef) = &entry.typedef {
        match entry_preset(typedef.to_string()) {
            PresetType::None => {}
            PresetType::IPv4Address => {
                m.match_ipv4_address(entry, s);
                return;
            }
            PresetType::IPv4Prefix => {
                m.match_ipv4_prefix(entry, s);
                return;
            }
            PresetType::IPv6Address => {
                m.match_ipv6_address(entry, s);
                return;
            }
            PresetType::IPv6Prefix => {
                m.match_ipv6_prefix(entry, s);
                return;
            }
        }
    }
    if let Some(node) = &entry.type_node {
        match node.kind {
            TypeKind::Yempty => m.match_entry_name(entry, s),
            TypeKind::Ystring => m.match_string(entry, s, node),
            TypeKind::Yboolean => m.match_bool(entry, s),
            TypeKind::Yint8 => m.match_range::<i8>(entry, node, s),
            TypeKind::Yint16 => m.match_range::<i16>(entry, node, s),
            TypeKind::Yint32 => m.match_range::<i32>(entry, node, s),
            TypeKind::Yint64 => m.match_range::<i64>(entry, node, s),
            TypeKind::Yuint8 => m.match_range::<u8>(entry, node, s),
            TypeKind::Yuint16 => m.match_range::<u16>(entry, node, s),
            TypeKind::Yuint32 => m.match_range::<u32>(entry, node, s),
            TypeKind::Yuint64 => m.match_range::<u64>(entry, node, s),
            TypeKind::Yenumeration => m.match_enum(entry, node, s),
            TypeKind::Yunion => m.match_string(entry, s, node),
            _ => m.match_string(entry, s, node),
        }
    }
}

fn entry_match_dir(entry: &Rc<Entry>, str: &str, m: &mut Match) {
    for entry in entry.dir.borrow().iter() {
        m.match_entry_name(entry, str);
    }
}

fn key(entry: &Rc<Entry>, index: usize) -> Option<Rc<Entry>> {
    if entry.key.len() <= index {
        return None;
    }
    let key_name = entry.key[index].clone();
    for e in entry.dir.borrow().iter() {
        if e.name == key_name {
            return Some(e.clone());
        }
    }
    None
}

fn entry_match_key(entry: &Rc<Entry>, str: &String, m: &mut Match, index: usize) {
    let key = key(entry, index);
    if let Some(e) = key {
        entry_match_type(&e, str, m);
    }
}

fn entry_is_key(name: &String, keys: &[String]) -> bool {
    for key in keys.iter() {
        if name == key {
            return true;
        }
    }
    false
}

fn entry_match_key_matched(entry: &Rc<Entry>, str: &str, m: &mut Match) {
    for e in entry.dir.borrow().iter() {
        if !entry_is_key(&e.name, &entry.key) {
            m.match_entry_name(e, str);
        }
    }
}

fn ymatch_next(entry: &Rc<Entry>, ymatch: YangMatch) -> YangMatch {
    match ymatch {
        YangMatch::Dir | YangMatch::DirMatched | YangMatch::KeyMatched => {
            if entry.is_directory_entry() {
                if entry.has_key() {
                    YangMatch::Key
                } else {
                    YangMatch::Dir
                }
            } else if entry.is_leaflist() {
                YangMatch::LeafList
            } else {
                YangMatch::Leaf
            }
        }
        YangMatch::Key => YangMatch::KeyMatched,
        YangMatch::Leaf => YangMatch::LeafMatched,
        YangMatch::LeafList => YangMatch::LeafListMatched,
        YangMatch::LeafMatched | YangMatch::LeafListMatched => ymatch,
    }
}

fn ymatch_complete(ymatch: YangMatch) -> bool {
    ymatch == YangMatch::DirMatched
        || ymatch == YangMatch::KeyMatched
        || ymatch == YangMatch::LeafMatched
        || ymatch == YangMatch::LeafListMatched
}

pub fn parse(
    input: &String,
    entry: Rc<Entry>,
    mut config: Option<Rc<Config>>,
    mut s: State,
) -> (ExecCode, Vec<Completion>, State) {
    // Config match for "set" and "delete".
    let mut cx = Match::new();
    if s.set || s.delete {
        if let Some(ref config) = config {
            config_match(config, input, &mut cx);
        }
        if s.delete {
            if cx.count == 0 {
                return (ExecCode::Nomatch, cx.comps, s);
            }
            if cx.count > 1 {
                return (ExecCode::Ambiguous, cx.comps, s);
            }
        }
        if cx.count == 1 {
            config = Some(cx.matched_config.clone());
        } else {
            config = None;
        }
    }

    // Entry match.
    let mut mx = Match::new();
    match s.ymatch {
        YangMatch::Dir | YangMatch::DirMatched => {
            entry_match_dir(&entry, input, &mut mx);
        }
        YangMatch::Key => {
            entry_match_key(&entry, input, &mut mx, s.index);
        }
        YangMatch::KeyMatched => {
            entry_match_key_matched(&entry, input, &mut mx);
        }
        YangMatch::Leaf | YangMatch::LeafList | YangMatch::LeafListMatched => {
            entry_match_type(&entry, input, &mut mx);
        }
        YangMatch::LeafMatched => {
            // Nothing to do.
        }
    }

    // Eraly return for no match and ambiguous match.
    if mx.count == 0 {
        return (ExecCode::Nomatch, mx.comps, s);
    }
    if mx.count > 1 {
        return (ExecCode::Ambiguous, mx.comps, s);
    }

    // "set" merge config completion to entry completion.
    if s.set {
        comps_append(&mut cx.comps, &mut mx.comps);
    }
    // "delete" overwrite entry completion with config completion.
    if s.delete {
        mx.comps = cx.comps;
    }

    // Transition to next yang match state.
    let mut next = entry.clone();
    // println!("B: {:?} {:?}", s.ymatch, entry.name);
    match s.ymatch {
        YangMatch::Dir | YangMatch::DirMatched | YangMatch::KeyMatched => {
            next = mx.matched_entry.clone();
            s.ymatch = ymatch_next(&mx.matched_entry, s.ymatch);
            if s.ymatch == YangMatch::Key {
                s.index = 0usize;
            }
        }
        YangMatch::Key => {
            s.index += 1;
            if s.index >= entry.key.len() {
                s.ymatch = YangMatch::KeyMatched;
            }
        }
        YangMatch::Leaf => {
            s.ymatch = YangMatch::LeafMatched;
        }
        YangMatch::LeafList => {
            s.ymatch = YangMatch::LeafListMatched;
        }
        YangMatch::LeafMatched | YangMatch::LeafListMatched => {}
    }
    // println!("A: {:?} {:?}", s.ymatch, next.name);

    // Elem for set/delete/exec func.
    let elem = if ymatch_complete(s.ymatch) {
        let sub = &input[0..mx.pos];
        Elem {
            name: sub.to_string(),
            ymatch: s.ymatch,
            key: mx.matched_entry.name.to_owned(),
            presence: next.presence,
        }
    } else {
        Elem {
            name: mx.matched_entry.name.to_owned(),
            ymatch: s.ymatch,
            key: "".to_string(),
            presence: next.presence,
        }
    };
    if elem.name == "set" {
        s.set = true;
    }
    if elem.name == "delete" {
        s.delete = true;
    }
    s.elems.push(elem);

    // Delay YANG match transition to avoid elem type.
    if s.ymatch == YangMatch::Leaf && mx.matched_entry.is_empty_leaf() {
        s.ymatch = YangMatch::LeafMatched;
    }
    if s.ymatch == YangMatch::Dir && mx.matched_entry.presence {
        s.ymatch = YangMatch::DirMatched;
    }

    if ymatch_complete(s.ymatch) && mx.matched_type == MatchType::Exact {
        comps_add_cr(&mut mx.comps);
    }

    // Skip whitespace.
    let start = mx.pos;
    while mx.pos < input.len() && is_whitespace(input, mx.pos) {
        mx.pos += 1;
    }

    // Trailing space.
    if mx.pos != start {
        mx.comps.clear();
        if s.delete {
            comps_add_config(&mut mx.comps, s.ymatch, &config);
        } else {
            comps_add_all(&mut mx.comps, s.ymatch, &next);

            if s.set {
                let mut comps = Vec::new();
                comps_add_config(&mut comps, s.ymatch, &config);
                comps_append(&mut comps, &mut mx.comps);
            }
        }
    }

    let remain = input.clone().split_off(mx.pos);

    if remain.is_empty() {
        if !ymatch_complete(s.ymatch) {
            return (ExecCode::Incomplete, mx.comps, s);
        }
        if mx.matched_type == MatchType::Incomplete {
            return (ExecCode::Incomplete, mx.comps, s);
        }
        (ExecCode::Success, mx.comps, s)
    } else {
        if next.name == "set" {
            s.set = true;
        }
        if next.name == "delete" {
            s.delete = true;
        }
        parse(&remain, next, config.clone(), s)
    }
}
