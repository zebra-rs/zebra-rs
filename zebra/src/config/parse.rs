use super::comps::{
    centry, cleaf, cname, comps_add_all, comps_add_config, comps_add_cr, comps_append, crange,
};
use super::configs::config_match;
use super::ip::*;
use super::util::*;
use super::vtysh::{CommandPath, YangMatch};
use super::{Completion, Config, ExecCode};
use libyang::{range_match, Entry, MinMax, RangeExtract, RangeNode, TypeNode, YangType};
use regex::Regex;
use std::collections::HashMap;
use std::rc::Rc;

pub struct State {
    ymatch: YangMatch,
    index: usize,
    pub set: bool,
    pub delete: bool,
    pub show: bool,
    pub paths: Vec<CommandPath>,
    pub links: Vec<String>,
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
            links: Vec::new(),
        }
    }
}

#[derive(Default, Debug, PartialEq, PartialOrd)]
pub enum MatchType {
    #[default]
    None,
    Incomplete,
    Partial,
    Exact,
}

pub fn match_keyword(src: &str, dst: &str) -> (MatchType, usize) {
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

fn match_word(str: &str) -> (MatchType, usize) {
    let mut pos = 0usize;
    while pos < str.len() && !is_whitespace(str, pos) {
        pos += 1;
    }
    (MatchType::Partial, pos)
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

fn match_string(s: &str, node: &TypeNode) -> (MatchType, usize) {
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
            (MatchType::None, 0usize)
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
    pub last_match: Option<String>,
}

impl Match {
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
        self.last_match = Some(comp.name.clone());
        self.comps.push(comp);
    }

    pub fn match_entry(&mut self, entry: &Rc<Entry>, input: &str) {
        self.process(entry, match_keyword(input, &entry.name), centry(entry));
    }

    pub fn match_keyword(&mut self, entry: &Rc<Entry>, input: &str, keyword: &str) {
        self.process(entry, match_keyword(input, keyword), cname(keyword));
    }
}

type MatchFunc = fn(&mut Match, &Rc<Entry>, &str, &TypeNode);
type MatchMap = HashMap<YangType, MatchFunc>;

#[derive(Default)]
struct MatchBuilder {
    map: MatchMap,
    kind: YangType,
}

impl MatchBuilder {
    pub fn kind(mut self, kind: YangType) -> Self {
        self.kind = kind;
        self
    }

    pub fn exec(mut self, func: MatchFunc) -> Self {
        self.map.insert(self.kind, func);
        self
    }

    pub fn build(self) -> MatchMap {
        self.map
    }
}

fn match_builder() -> MatchMap {
    let builder = MatchBuilder::default();
    builder
        .kind(YangType::Boolean)
        .exec(|m, entry, input, _node| {
            m.process(entry, match_keyword(input, "true"), cname("true"));
            m.process(entry, match_keyword(input, "false"), cname("false"));
        })
        .kind(YangType::Int8)
        .exec(|m, entry, input, node| {
            m.process(entry, match_range::<i8>(input, node), crange(entry, node));
        })
        .kind(YangType::Int16)
        .exec(|m, entry, input, node| {
            m.process(entry, match_range::<i16>(input, node), crange(entry, node));
        })
        .kind(YangType::Int32)
        .exec(|m, entry, input, node| {
            m.process(entry, match_range::<i32>(input, node), crange(entry, node));
        })
        .kind(YangType::Int64)
        .exec(|m, entry, input, node| {
            m.process(entry, match_range::<i64>(input, node), crange(entry, node));
        })
        .kind(YangType::Uint8)
        .exec(|m, entry, input, node| {
            m.process(entry, match_range::<u8>(input, node), crange(entry, node));
        })
        .kind(YangType::Uint16)
        .exec(|m, entry, input, node| {
            m.process(entry, match_range::<u16>(input, node), crange(entry, node));
        })
        .kind(YangType::Uint32)
        .exec(|m, entry, input, node| {
            m.process(entry, match_range::<u32>(input, node), crange(entry, node));
        })
        .kind(YangType::Uint64)
        .exec(|m, entry, input, node| {
            m.process(entry, match_range::<u64>(input, node), crange(entry, node));
        })
        .kind(YangType::Ipv4Addr)
        .exec(|m, entry, input, _node| {
            m.process(entry, match_ipv4_addr(input), cname("A.B.C.D"));
        })
        .kind(YangType::Ipv4Prefix)
        .exec(|m, entry, input, _node| {
            m.process(entry, match_ipv4_net(input), cname("A.B.C.D/M"));
        })
        .kind(YangType::Ipv6Addr)
        .exec(|m, entry, input, _node| {
            m.process(entry, match_ipv6_addr(input), cname("X:X::X:X"));
        })
        .kind(YangType::Ipv6Prefix)
        .exec(|m, entry, input, _node| {
            m.process(entry, match_ipv6_net(input), cname("X:X::X:X/M"));
        })
        .kind(YangType::Enumeration)
        .exec(|m, entry, input, node| {
            for n in node.enum_stmt.iter() {
                m.process(entry, match_keyword(input, &n.name), cname(&n.name));
            }
        })
        .kind(YangType::String)
        .exec(|m, entry, input, node| {
            m.process(entry, match_string(input, node), cleaf(entry));
        })
        .kind(YangType::Union)
        .exec(|m, entry, input, node| {
            m.process(entry, match_string(input, node), cleaf(entry));
        })
        .build()
}

pub fn ytype_from_typedef(typedef: &Option<String>) -> Option<YangType> {
    typedef.as_ref().and_then(|v| match v.as_str() {
        "inet:ipv4-address" => Some(YangType::Ipv4Addr),
        "inet:ipv4-prefix" => Some(YangType::Ipv4Prefix),
        "inet:ipv6-address" => Some(YangType::Ipv6Addr),
        "inet:ipv6-prefix" => Some(YangType::Ipv6Prefix),
        _ => None,
    })
}

fn entry_match_type(entry: &Rc<Entry>, input: &str, m: &mut Match, s: &State) {
    let matcher = match_builder();

    if let Some(node) = &entry.type_node {
        if node.kind == YangType::Union {
            for n in node.union.iter() {
                let kind = ytype_from_typedef(&n.typedef).unwrap_or(n.kind);
                if let Some(f) = matcher.get(&kind) {
                    f(m, entry, input, node);
                }
            }
        }
        let kind = ytype_from_typedef(&node.typedef).unwrap_or(node.kind);
        if let Some(f) = matcher.get(&kind) {
            f(m, entry, input, node);
        }
    }

    if entry.name == "interface" {
        for link in s.links.iter() {
            m.match_keyword(entry, input, link);
        }
    }
}

fn entry_match_dir(entry: &Rc<Entry>, str: &str, m: &mut Match) {
    for entry in entry.dir.borrow().iter() {
        m.match_entry(entry, str);
    }
}

fn entry_key(entry: &Rc<Entry>, index: usize) -> Option<Rc<Entry>> {
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

fn entry_match_key(entry: &Rc<Entry>, input: &str, m: &mut Match, state: &State) {
    let key = entry_key(entry, state.index);
    if let Some(e) = key {
        entry_match_type(&e, input, m, state);
    }
}

pub fn entry_is_key(name: &String, keys: &[String]) -> bool {
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
            m.match_entry(e, str);
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

fn matched_enumeration(mx: &Match) -> Option<String> {
    if let Some(type_node) = &mx.matched_entry.type_node {
        if type_node.kind == YangType::Enumeration {
            if let Some(last_match) = &mx.last_match {
                return Some(last_match.clone());
            }
        }
    }
    None
}

pub fn parse(
    input: &str,
    entry: Rc<Entry>,
    mut config: Option<Rc<Config>>,
    mut s: State,
) -> (ExecCode, Vec<Completion>, State) {
    // Config match for "set" and "delete".
    let mut cx = Match::default();
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
    let mut mx = Match::default();
    match s.ymatch {
        YangMatch::Dir | YangMatch::DirMatched => {
            entry_match_dir(&entry, input, &mut mx);
        }
        YangMatch::Key => {
            entry_match_key(&entry, input, &mut mx, &s);
        }
        YangMatch::KeyMatched => {
            entry_match_key_matched(&entry, input, &mut mx);
        }
        YangMatch::Leaf | YangMatch::LeafList | YangMatch::LeafListMatched => {
            entry_match_type(&entry, input, &mut mx, &s);
        }
        YangMatch::LeafMatched => {
            // Nothing to do.
        }
    }

    // "delete" overwrite entry completion with config completion.
    if s.delete {
        mx.comps.clone_from(&cx.comps);
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

    // Elem for set/delete/exec func.
    let mut mandatory = Vec::<String>::new();
    for entry in mx.matched_entry.dir.borrow().iter() {
        if entry.mandatory {
            mandatory.push(entry.name.clone());
        }
    }
    let path = if ymatch_complete(s.ymatch) {
        let sub = if let Some(sub) = matched_enumeration(&mx) {
            sub
        } else {
            input[0..mx.pos].to_string()
        };
        CommandPath {
            name: sub,
            ymatch: s.ymatch.into(),
            key: mx.matched_entry.name.to_owned(),
            mandatory,
        }
    } else {
        CommandPath {
            name: mx.matched_entry.name.to_owned(),
            ymatch: s.ymatch.into(),
            key: "".to_string(),
            mandatory,
        }
    };

    // Delay YANG match transition to avoid elem type.
    if s.ymatch == YangMatch::Leaf && mx.matched_entry.is_empty_leaf() {
        s.ymatch = YangMatch::LeafMatched;
    }
    if s.ymatch == YangMatch::Dir && mx.matched_entry.presence {
        s.ymatch = YangMatch::DirMatched;
    }
    // println!("A: {:?} {:?}", s.ymatch, next.name);

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
            comps_add_all(&mut mx.comps, s.ymatch, &next, &s);

            if s.set {
                let mut comps = Vec::new();
                comps_add_config(&mut comps, s.ymatch, &config);
                comps_append(&mut comps, &mut mx.comps);
            }
        }
    }

    let remain = input.to_string().split_off(mx.pos);

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
