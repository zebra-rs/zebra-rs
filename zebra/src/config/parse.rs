use super::comps::{
    comps_add_all, comps_add_config, comps_add_cr, comps_append, comps_from_entry,
    comps_help_string, comps_leaf_string, comps_range,
};
use super::configs::config_match;
use super::ip::*;
use super::util::*;
use super::vtysh::{CommandPath, YangMatch};
use super::{Completion, Config, ExecCode};
use libyang::{
    path_split, range_match, Entry, MinMax, RangeExtract, RangeNode, TypeKind, TypeNode,
};
use regex::Regex;
use std::rc::Rc;

#[derive(Default, Debug, PartialEq, PartialOrd)]
pub enum MatchType {
    #[default]
    None,
    Incomplete,
    Partial,
    Exact,
}

#[derive(PartialEq, Debug)]
pub enum PresetType {
    None,
    IPv4Address,
    IPv4Prefix,
    IPv6Address,
    IPv6Prefix,
}

pub fn entry_preset(name: String) -> PresetType {
    let (_, name) = path_split(name.clone());
    match name.as_str() {
        "ipv4-address" => PresetType::IPv4Address,
        "ipv4-prefix" => PresetType::IPv4Prefix,
        "ipv6-address" => PresetType::IPv6Address,
        "ipv6-prefix" => PresetType::IPv6Prefix,
        _ => PresetType::None,
    }
}

pub struct State {
    ymatch: YangMatch,
    index: usize,
    pub set: bool,
    pub delete: bool,
    pub show: bool,
    pub paths: Vec<CommandPath>,
    pub dcomp: bool,
}

impl State {
    pub fn new() -> Self {
        State {
            ymatch: YangMatch::Dir,
            set: false,
            delete: false,
            show: false,
            paths: Vec::new(),
            index: 0usize,
            dcomp: false,
        }
    }
}

pub fn match_keyword(src: &String, dst: &String) -> (MatchType, usize) {
    let pos = longest_match(src, dst);

    match is_delimiter(src, pos) {
        false => (MatchType::None, pos),
        true => {
            if is_delimiter(dst, pos) {
                (MatchType::Exact, pos)
            } else {
                (MatchType::Partial, pos)
            }
        }
    }
}

fn match_keyword_str(src: &str, dst: &str) -> (MatchType, usize) {
    let pos = longest_match_str(src, dst);

    match is_delimiter_str(src, pos) {
        false => (MatchType::None, pos),
        true => {
            if is_delimiter_str(dst, pos) {
                (MatchType::Exact, pos)
            } else {
                (MatchType::Partial, pos)
            }
        }
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
    input: &str,
    node: &TypeNode,
) -> (MatchType, usize)
where
    RangeNode: RangeExtract<T>,
{
    // We need to find space as separator.
    let mut input_mut = input.to_string();
    let pos = input_mut.find(' ');
    let s = if let Some(pos) = pos {
        let _ = input_mut.split_off(pos);
        &input_mut
    } else {
        input
    };

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
            return (MatchType::None, 0usize);
        } else {
            (MatchType::Exact, s.len())
        }
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
        self.process(
            entry,
            match_ipv4_address(s),
            Completion::new_name("A.B.C.D"),
        );
    }

    pub fn match_ipv4_prefix(&mut self, entry: &Rc<Entry>, s: &String) {
        self.process(
            entry,
            match_ipv4_prefix(s),
            Completion::new_name("A.B.C.D/M"),
        );
    }

    pub fn match_ipv6_address(&mut self, entry: &Rc<Entry>, s: &str) {
        self.process(
            entry,
            match_ipv6_address(s),
            Completion::new_name("X:X::X:X"),
        );
    }

    pub fn match_ipv6_prefix(&mut self, entry: &Rc<Entry>, s: &str) {
        self.process(
            entry,
            match_ipv6_prefix(s),
            Completion::new_name("X:X::X:X/M"),
        );
    }

    pub fn match_string(&mut self, entry: &Rc<Entry>, s: &String, node: &TypeNode) {
        self.process(
            entry,
            match_string(s, node),
            Completion::new(&comps_leaf_string(entry), &comps_help_string(entry)),
        );
    }

    pub fn match_entry_name(&mut self, entry: &Rc<Entry>, s: &str) {
        self.process(
            entry,
            match_keyword_str(s, &entry.name),
            comps_from_entry(&entry),
        );
    }

    pub fn match_enum(&mut self, entry: &Rc<Entry>, node: &TypeNode, s: &String) {
        for n in node.enum_stmt.iter() {
            self.process(
                entry,
                match_keyword(s, &n.name),
                Completion::new_name(&n.name),
            );
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
        self.process(entry, match_range::<T>(s, node), comps_range(entry, node));
    }

    pub fn match_bool(&mut self, entry: &Rc<Entry>, s: &String) {
        self.process(
            entry,
            match_keyword(s, &"true".to_owned()),
            Completion::new_name("true"),
        );
        self.process(
            entry,
            match_keyword(s, &"false".to_owned()),
            Completion::new_name("false"),
        );
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

pub fn ymatch_complete(ymatch: YangMatch) -> bool {
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
    s.dcomp = false;
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

    // "delete" overwrite entry completion with config completion.
    if s.delete {
        mx.comps = cx.comps.clone();
    }

    // Eraly return for no match and ambiguous match.
    if mx.count == 0 {
        return (ExecCode::Nomatch, mx.comps, s);
    }
    if mx.count > 1 {
        mx.comps.sort_by(|a, b| a.name.cmp(&b.name));
        return (ExecCode::Ambiguous, mx.comps, s);
    }

    // "set" merge config completion to entry completion.
    if s.set {
        comps_append(&mut cx.comps, &mut mx.comps);
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

    // Delay YANG match transition to avoid elem type.
    if s.ymatch == YangMatch::Leaf && mx.matched_entry.is_empty_leaf() {
        s.ymatch = YangMatch::LeafMatched;
    }
    if s.ymatch == YangMatch::Dir && mx.matched_entry.presence {
        s.ymatch = YangMatch::DirMatched;
    }
    // println!("A: {:?} {:?}", s.ymatch, next.name);

    // Elem for set/delete/exec func.
    let path = if ymatch_complete(s.ymatch) {
        let sub = &input[0..mx.pos];
        CommandPath {
            name: sub.to_string(),
            ymatch: s.ymatch.into(),
            key: mx.matched_entry.name.to_owned(),
        }
    } else {
        CommandPath {
            name: mx.matched_entry.name.to_owned(),
            ymatch: s.ymatch.into(),
            key: "".to_string(),
        }
    };

    if path.name == "set" {
        s.set = true;
    }
    if path.name == "delete" {
        s.delete = true;
    }
    if path.name == "show" {
        s.show = true;
    }
    s.paths.push(path);

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
            comps_add_all(&mut mx.comps, s.ymatch, &next, &mut s);

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
