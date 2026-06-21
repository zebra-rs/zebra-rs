use super::comps::{
    centry, cleaf, cname, comps_add_all, comps_add_config, comps_add_cr, comps_append, crange,
};
use super::configs::config_match;
use super::ip::*;
use super::mac::match_mac_addr;
use super::nsap::match_nsap_addr;
use super::util::*;
use super::vty::{CommandPath, YangMatch};
use super::{Completion, Config, ExecCode};
use libyang::{Entry, MinMax, RangeExtract, RangeNode, TypeNode, YangType, range_match};
use regex::Regex;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::{LazyLock, Mutex};

static REGEX_CACHE: LazyLock<Mutex<HashMap<String, Regex>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub struct State {
    ymatch: YangMatch,
    index: usize,
    pub set: bool,
    pub delete: bool,
    pub show: bool,
    pub clear: bool,
    pub paths: Vec<CommandPath>,
    pub _links: Vec<String>,
    pub dynamic: HashMap<String, Vec<String>>,
    pub choice_states: HashMap<String, String>, // choice_name -> active_case_name
}

impl State {
    pub fn new() -> Self {
        State {
            ymatch: YangMatch::Dir,
            set: false,
            delete: false,
            show: false,
            clear: false,
            paths: Vec::new(),
            index: 0usize,
            _links: Vec::new(),
            dynamic: HashMap::new(),
            choice_states: HashMap::new(),
        }
    }

    pub fn set_active_choice_case(&mut self, choice_name: &str, case_name: &str) {
        self.choice_states
            .insert(choice_name.to_string(), case_name.to_string());
    }

    pub fn get_active_choice_case(&self, choice_name: &str) -> Option<&String> {
        self.choice_states.get(choice_name)
    }

    pub fn clear_choice_case(&mut self, choice_name: &str) {
        self.choice_states.remove(choice_name);
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

/// Apply a YANG `pattern` regex to the entire remaining input line.
///
/// A `type string { pattern '...'; }` leaf consumes the rest of the
/// command line — values may contain whitespace (FRR-style
/// `neighbor X description LINE`). The pattern itself decides what's
/// valid: the matcher requires a full anchored match against the
/// trimmed remainder, so a permissive `'.*'` accepts everything but a
/// strict `'[a-z]+'` rejects inputs containing anything outside the
/// class. Trailing whitespace is trimmed so an operator can type a
/// trailing space without invalidating the value; empty input is
/// rejected so a `.*` pattern never silently accepts a missing value.
fn match_regexp(s: &str, regstr: &str) -> (MatchType, usize) {
    let trimmed_len = s.trim_end().len();
    if trimmed_len == 0 {
        return (MatchType::None, 0);
    }
    let trimmed = &s[..trimmed_len];

    {
        let cache = REGEX_CACHE.lock().unwrap();
        if let Some(regex) = cache.get(regstr) {
            return regex_match_full(regex, trimmed, trimmed_len);
        }
    }

    let Ok(regex) = Regex::new(regstr) else {
        return (MatchType::None, 0);
    };
    let result = regex_match_full(&regex, trimmed, trimmed_len);
    REGEX_CACHE
        .lock()
        .unwrap()
        .insert(regstr.to_string(), regex);
    result
}

/// Helper for `match_regexp`: full anchored match of the trimmed
/// remainder against the compiled regex. Partial / interior matches
/// are rejected so an under-specified pattern can't silently leak past
/// the value into later command tokens.
fn regex_match_full(regex: &Regex, trimmed: &str, pos: usize) -> (MatchType, usize) {
    if let Some(m) = regex.find(trimmed)
        && m.start() == 0
        && m.end() == trimmed.len()
    {
        (MatchType::Exact, pos)
    } else {
        (MatchType::None, 0)
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
            self.last_match = Some(comp.name.clone());
        } else if m == self.matched_type {
            self.count += 1;
        }
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
            m.process(entry, match_ipv4_addr(input), cname("<A.B.C.D>"));
        })
        .kind(YangType::Ipv4Prefix)
        .exec(|m, entry, input, _node| {
            m.process(entry, match_ipv4_net(input), cname("<A.B.C.D/M>"));
        })
        .kind(YangType::Ipv6Addr)
        .exec(|m, entry, input, _node| {
            m.process(entry, match_ipv6_addr(input), cname("<X:X::X:X>"));
        })
        .kind(YangType::Ipv6Prefix)
        .exec(|m, entry, input, _node| {
            m.process(entry, match_ipv6_net(input), cname("<X:X::X:X/M>"));
        })
        .kind(YangType::MacAddr)
        .exec(|m, entry, input, _node| {
            m.process(entry, match_mac_addr(input), cname("<XX:XX:XX:XX:XX:XX>"));
        })
        .kind(YangType::NsapAddr)
        .exec(|m, entry, input, _node| {
            m.process(entry, match_nsap_addr(input), cname("<XX.XXXX..XXXX.XX>"));
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
        .kind(YangType::Leafref)
        .exec(|m, entry, input, node| {
            // Accept any non-empty word; the target is resolved at
            // commit time. A future enhancement will enumerate valid
            // values from the candidate config via `TypeNode.path`.
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
        "yang:mac-address" => Some(YangType::MacAddr),
        "isis:net" => Some(YangType::NsapAddr),
        _ => None,
    })
}

fn is_choice_case(entry: &Rc<Entry>) -> Option<(String, String)> {
    // Choice/case metadata is set by libyang when flattening case
    // children into the choice's parent `dir` (see libyang's
    // `choice_entry`). Both must be present.
    let choice = entry.choice.borrow().clone()?;
    let case = entry.case.borrow().clone()?;
    Some((choice, case))
}

fn entry_match_type(entry: &Rc<Entry>, input: &str, m: &mut Match, s: &mut State) {
    let matcher = match_builder();

    // Handle choice case logic
    if let Some((choice_name, case_name)) = is_choice_case(entry) {
        if let Some(active_case) = s.get_active_choice_case(&choice_name)
            && active_case != &case_name
        {
            // Different case is active, clear it
            s.clear_choice_case(&choice_name);
        }
        // Set this case as active
        s.set_active_choice_case(&choice_name, &case_name);
    }

    if let Some(node) = &entry.type_node {
        if node.kind == YangType::Union {
            // Match every arm into a side `Match`, then fold the best
            // result into `m` as a single candidate. Arms of one union
            // leaf are alternative spellings of the same command
            // position, so two arms accepting the same token must not
            // read as an ambiguous command — an address input matches
            // both its address arm and a catch-all `string` arm (both
            // Partial; the scalar matchers never return Exact), which
            // per-arm counting would reject as Ambiguous. `last_match`
            // carries the winning arm's comp name so an enum arm still
            // canonicalizes abbreviations via `matched_enumeration`,
            // and every matching arm's completion hint is kept for
            // interactive display.
            let mut um = Match::default();
            for n in node.union.iter() {
                let kind = ytype_from_typedef(&n.typedef).unwrap_or(n.kind);
                if let Some(f) = matcher.get(&kind) {
                    f(&mut um, entry, input, n);
                }
            }
            if um.matched_type > MatchType::None {
                if um.matched_type > m.matched_type {
                    m.count = 1;
                    m.pos = um.pos;
                    m.matched_type = um.matched_type;
                    m.matched_entry = entry.clone();
                    m.last_match = um.last_match.clone();
                } else if um.matched_type == m.matched_type {
                    m.count += 1;
                }
                m.comps.append(&mut um.comps);
            }
        } else {
            let kind = ytype_from_typedef(&node.typedef).unwrap_or(node.kind);
            if let Some(f) = matcher.get(&kind) {
                f(m, entry, input, node);
            }
        }
    }

    if let Some(dynamics) = entry.extension.get("ext:dynamic")
        && let Some(candidates) = s.dynamic.get(dynamics)
    {
        for candidate in candidates.iter() {
            m.match_keyword(entry, input, candidate);
        }
    }

    if entry.name == "if-name-brief" {
        m.match_keyword(entry, input, "brief");
    }
}

fn entry_match_dir(entry: &Rc<Entry>, str: &str, m: &mut Match, state: &State) {
    for entry in entry.dir.borrow().iter() {
        // Check if this entry is part of a choice
        if let Some((choice_name, case_name)) = is_choice_case(entry) {
            // Only include if this case is active or no case is active yet
            if let Some(active_case) = state.get_active_choice_case(&choice_name)
                && active_case != &case_name
            {
                continue; // Skip inactive choice case
            }
        }
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

fn entry_match_key(entry: &Rc<Entry>, input: &str, m: &mut Match, state: &mut State) {
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

/// Resolve a container's `ext:default-child` to the child entry it
/// names. That child's key may be supplied positionally — without
/// typing the child's own keyword (see [`parse`]).
fn default_child_entry(entry: &Rc<Entry>) -> Option<Rc<Entry>> {
    let name = entry.extension.get("ext:default-child")?;
    entry.dir.borrow().iter().find(|e| &e.name == name).cloned()
}

/// Type-match `input` against the first key of `child` (the
/// `ext:default-child`), recording the match and its completion hints
/// in `m`. Used both to decide a positional descent and to surface the
/// key's hints (`<A.B.C.D>`, …) during completion.
fn entry_match_default_key(child: &Rc<Entry>, input: &str, m: &mut Match, s: &mut State) {
    if let Some(key_leaf) = entry_key(child, 0) {
        entry_match_type(&key_leaf, input, m, s);
    }
}

fn ymatch_next(entry: &Rc<Entry>, ymatch: YangMatch) -> YangMatch {
    match ymatch {
        YangMatch::Dir | YangMatch::DirMatched | YangMatch::KeyMatched => {
            if entry.is_directory_entry() {
                if entry.has_key() {
                    YangMatch::Key
                } else if entry.presence {
                    // Presence containers settle into DirMatched right
                    // here so the CommandPath the caller builds carries
                    // the correct ymatch — otherwise downstream set()
                    // can't tell a presence container apart from a
                    // plain transient Dir on the way to a leaf, and
                    // the running config tree never marks the node as
                    // presence. That in turn causes list() to skip the
                    // node when emitting diffs, so the per-protocol
                    // handler for the presence path never fires.
                    YangMatch::DirMatched
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

pub fn ymatch_complete(ymatch: YangMatch, list_presence: bool, is_delete: bool) -> bool {
    (ymatch == YangMatch::Key && list_presence)
        || ymatch == YangMatch::DirMatched
        || ymatch == YangMatch::KeyMatched
        || ymatch == YangMatch::LeafMatched
        || ymatch == YangMatch::LeafListMatched
        || (is_delete && ymatch == YangMatch::LeafList)
}

fn matched_enumeration(mx: &Match) -> Option<String> {
    let type_node = mx.matched_entry.type_node.as_ref()?;
    let last_match = mx.last_match.as_ref()?;
    if type_node.kind == YangType::Enumeration {
        return Some(last_match.clone());
    }
    // A union with an inline enumeration arm (e.g. the `show bgp ipv4`
    // key: address | prefix | `summary`). The winner was the enum
    // keyword iff `last_match` names one of the arm's enums — the
    // scalar arms record type hints like `<A.B.C.D>` instead — and
    // returning the canonical name here is what lets an abbreviated
    // keyword (`show bgp ipv4 summ`) reach the handler as `summary`.
    if type_node.kind == YangType::Union
        && type_node.union.iter().any(|arm| {
            arm.kind == YangType::Enumeration && arm.enum_stmt.iter().any(|e| &e.name == last_match)
        })
    {
        return Some(last_match.clone());
    }
    None
}

pub fn is_entry_presence(entry: &Rc<Entry>) -> bool {
    entry.extension.contains_key("ext:presence")
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
            entry_match_dir(&entry, input, &mut mx, &s);
        }
        YangMatch::Key => {
            entry_match_key(&entry, input, &mut mx, &mut s);
        }
        YangMatch::KeyMatched => {
            entry_match_key_matched(&entry, input, &mut mx);
        }
        YangMatch::Leaf | YangMatch::LeafList | YangMatch::LeafListMatched => {
            entry_match_type(&entry, input, &mut mx, &mut s);
        }
        YangMatch::LeafMatched => {
            // Nothing to do.
        }
    }

    // `ext:default-child` positional value. A container (or a list
    // entry, once its key is matched) may name a child whose key can be
    // typed without the child's own keyword (`show bgp 10.0.0.1` ==
    // `show bgp ipv4 10.0.0.1`; `show bgp vrf X 10.0.0.1` == `show bgp
    // vrf X ipv4 10.0.0.1`). Probe that child's key in a side `Match`
    // so the normal transition below is left untouched, then either
    // descend into the child (the value is the winner) or fold the
    // key's completion hints into `mx` (so `show bgp <tab>` still
    // advertises <A.B.C.D> / <A.B.C.D/M>). `KeyMatched` covers the
    // list-entry case: after `vrf X` the parser sits on the list node
    // with the key consumed, so the positional value attaches to the
    // entry's `ext:default-child`. IP literals never collide with the
    // sibling keywords, so this can only fire on the value branch — no
    // existing command regresses.
    if !s.set
        && !s.delete
        && matches!(
            s.ymatch,
            YangMatch::Dir | YangMatch::DirMatched | YangMatch::KeyMatched
        )
        && let Some(child) = default_child_entry(&entry)
    {
        let mut pmx = Match::default();
        entry_match_default_key(&child, input, &mut pmx, &mut s);
        if pmx.matched_type >= MatchType::Partial && pmx.matched_type > mx.matched_type {
            // Inject a zero-width synthetic step for the child name (no
            // input consumed) and re-parse the same token as the child's
            // key. The resulting path/args are identical to the explicit
            // `... <child> <value>` form.
            s.paths.push(CommandPath {
                name: child.name.clone(),
                ymatch: YangMatch::Key.into(),
                ..Default::default()
            });
            s.ymatch = YangMatch::Key;
            s.index = 0;
            return parse(input, child, config, s);
        }
        comps_append(&mut pmx.comps, &mut mx.comps);
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
    let mut key_presence = false;
    match s.ymatch {
        YangMatch::Dir | YangMatch::DirMatched | YangMatch::KeyMatched => {
            next = mx.matched_entry.clone();
            key_presence = is_entry_presence(&mx.matched_entry);
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
    //
    // A `mandatory true` leaf nested under `choice`/`case` is only
    // required when its case is selected (RFC 7950 §7.6.5). libyang
    // flattens cases into the parent `dir` but tags each entry with
    // its choice/case names — skip those here so the validator does
    // not demand sibling cases that the user did not select.
    let mut mandatory = Vec::<String>::new();
    for entry in mx.matched_entry.dir.borrow().iter() {
        if entry.mandatory && entry.choice.borrow().is_none() {
            mandatory.push(entry.name.clone());
        }
    }
    let sort_priority = mx
        .matched_entry
        .extension
        .get("ext:sort")
        .map_or_else(|| 0, |v| v.parse::<i32>().unwrap_or(0));

    let path = if ymatch_complete(s.ymatch, mx.matched_entry.presence, s.delete) {
        // KeyMatched / LeafMatched / LeafListMatched carry the user-
        // typed value (the list key, the leaf value, ...). DirMatched
        // for a presence container has no user-typed value — the
        // "name" must be the canonical entry name so path_from_command
        // builds e.g. `/show/ip/route` and not `/sh/ip/route` when
        // the operator typed an abbreviation.
        let sub = if let Some(sub) = matched_enumeration(&mx) {
            sub
        } else if s.ymatch == YangMatch::DirMatched {
            mx.matched_entry.name.to_owned()
        } else {
            input[0..mx.pos].to_string()
        };
        CommandPath {
            name: sub,
            ymatch: s.ymatch.into(),
            key: mx.matched_entry.name.to_owned(),
            mandatory,
            sort_priority,
        }
    } else {
        CommandPath {
            name: mx.matched_entry.name.to_owned(),
            ymatch: s.ymatch.into(),
            key: "".to_string(),
            mandatory,
            sort_priority,
        }
    };

    // Delay YANG match transition to avoid elem type.
    if s.ymatch == YangMatch::Leaf && mx.matched_entry.is_empty_leaf() {
        s.ymatch = YangMatch::LeafMatched;
    }
    // (presence-container Dir → DirMatched used to live here, but it
    // was settled too late: the CommandPath was already built with the
    // wrong ymatch. ymatch_next now handles it directly.)

    if path.name == "set" {
        s.set = true;
    }
    if path.name == "delete" {
        s.delete = true;
    }
    if path.name == "show" {
        s.show = true;
    }
    if path.name == "clear" {
        s.clear = true;
    }
    s.paths.push(path);

    if ymatch_complete(s.ymatch, mx.matched_entry.presence, s.delete)
        && mx.matched_type == MatchType::Exact
    {
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
        } else if mx.matched_type != MatchType::Incomplete {
            comps_add_all(
                &mut mx.comps,
                s.ymatch,
                &next,
                &s,
                mx.matched_entry.presence,
            );
            if s.set {
                let mut comps = Vec::new();
                comps_add_config(&mut comps, s.ymatch, &config);
                comps_append(&mut comps, &mut mx.comps);
            }
        }
    }

    let remain = input.to_string().split_off(mx.pos);

    if remain.is_empty() {
        if key_presence {
            return (ExecCode::Success, mx.comps, s);
        }
        if !ymatch_complete(s.ymatch, mx.matched_entry.presence, s.delete) {
            return (ExecCode::Incomplete, mx.comps, s);
        }
        if mx.matched_type == MatchType::Incomplete {
            return (ExecCode::Incomplete, mx.comps, s);
        }
        (ExecCode::Success, mx.comps, s)
    } else {
        if mx.matched_type == MatchType::Incomplete {
            return (ExecCode::Incomplete, mx.comps, s);
        }
        if next.name == "set" {
            s.set = true;
        }
        if next.name == "delete" {
            s.delete = true;
        }
        parse(&remain, next, config.clone(), s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A patterned string leaf consumes the entire trimmed remainder
    /// of the line. With a fully-matching value the helper reports
    /// `Exact` and `pos = value length`, so the parser splits off
    /// `remain = ""` and parsing completes.
    #[test]
    fn match_regexp_returns_consumed_length() {
        // openconfig-isis-types `net` pattern: 1-octet AFI, 3-9 4-hex
        // groups, 1-octet NSEL — also exercised by the BDD SRv6 fixture
        // that surfaced the original bug.
        let pat = r"[a-fA-F0-9]{2}(\.[a-fA-F0-9]{4}){3,9}\.[a-fA-F0-9]{2}";

        let (m, pos) = match_regexp("49.0000.0000.0000.0001.00", pat);
        assert_eq!(m, MatchType::Exact);
        assert_eq!(pos, 25);
    }

    /// Multi-word values: a permissive `.*` pattern accepts an entire
    /// rest-of-line value, embedded whitespace included. This is the
    /// FRR-style `neighbor X description LINE` case.
    #[test]
    fn match_regexp_accepts_multi_word_value() {
        let pat = r".*";
        let (m, pos) = match_regexp("abc def ghi", pat);
        assert_eq!(m, MatchType::Exact);
        assert_eq!(pos, 11);
    }

    /// Trailing whitespace is trimmed before matching so an operator
    /// can type a stray trailing space without invalidating the value.
    #[test]
    fn match_regexp_trims_trailing_whitespace() {
        let pat = r"[a-z]+";
        let (m, pos) = match_regexp("hello   ", pat);
        assert_eq!(m, MatchType::Exact);
        assert_eq!(pos, 5);
    }

    /// Empty input (or whitespace-only) is rejected even for `.*` so
    /// that a missing leaf value can't silently slip through.
    #[test]
    fn match_regexp_rejects_empty_input() {
        let pat = r".*";
        let (m, pos) = match_regexp("", pat);
        assert_eq!(m, MatchType::None);
        assert_eq!(pos, 0);
        let (m, pos) = match_regexp("   ", pat);
        assert_eq!(m, MatchType::None);
        assert_eq!(pos, 0);
    }

    /// Interior matches don't count — a leaf value must satisfy the
    /// pattern in full. `[0-9]+` would otherwise leak past the digits.
    #[test]
    fn match_regexp_rejects_partial_match() {
        let pat = r"[0-9]+";
        let (m, pos) = match_regexp("12abc", pat);
        assert_eq!(m, MatchType::None);
        assert_eq!(pos, 0);
    }

    #[test]
    fn match_regexp_rejects_non_matching_input() {
        let pat = r"[a-fA-F0-9]{2}(\.[a-fA-F0-9]{4}){3,9}\.[a-fA-F0-9]{2}";
        let (m, _) = match_regexp("not-an-nsap", pat);
        assert_eq!(m, MatchType::None);
    }

    /// Build the operational-mode (`exec`) entry tree from the real
    /// YANG so the positional `show bgp …` grammar is exercised end to
    /// end — the `ext:default-child` matcher feature plus the schema.
    fn exec_entry() -> Rc<Entry> {
        use libyang::{YangStore, to_entry};
        let mut yang = YangStore::new();
        yang.add_path(concat!(env!("CARGO_MANIFEST_DIR"), "/yang"));
        yang.read_with_resolve("exec").expect("exec mode loads");
        yang.identity_resolve();
        let module = yang.find_module("exec").expect("exec module present");
        to_entry(&yang, module)
    }

    fn configure_entry() -> Rc<Entry> {
        use libyang::{YangStore, to_entry};
        let mut yang = YangStore::new();
        yang.add_path(concat!(env!("CARGO_MANIFEST_DIR"), "/yang"));
        yang.read_with_resolve("configure")
            .expect("configure mode loads");
        yang.identity_resolve();
        let module = yang
            .find_module("configure")
            .expect("configure module present");
        to_entry(&yang, module)
    }

    /// `ext:default-child "neighbor"` on the per-AFI clear containers
    /// lets the peer address (or `all`) be typed straight after the AFI
    /// — FRR's `clear bgp ipv4 <peer> [soft [in|out]]` spelling — and
    /// resolves to the same path + args as the explicit `neighbor`
    /// keyword form. Pinned with parse() tests because the vtyctl clear
    /// surface is garbage-tolerant: an unwired grammar silently no-ops
    /// instead of erroring.
    #[test]
    fn clear_bgp_grammar() {
        use crate::config::path_from_command;
        let entry = configure_entry();

        let cases: Vec<(&str, &str, Vec<&str>)> = vec![
            (
                "clear bgp ipv4 192.168.0.1",
                "/clear/bgp/ipv4/neighbor",
                vec!["192.168.0.1"],
            ),
            (
                "clear bgp ipv4 neighbor 192.168.0.1",
                "/clear/bgp/ipv4/neighbor",
                vec!["192.168.0.1"],
            ),
            (
                "clear bgp ipv4 all",
                "/clear/bgp/ipv4/neighbor",
                vec!["all"],
            ),
            (
                "clear bgp ipv4 192.168.0.1 soft",
                "/clear/bgp/ipv4/neighbor/soft",
                vec!["192.168.0.1"],
            ),
            (
                "clear bgp ipv4 neighbor 192.168.0.1 soft out",
                "/clear/bgp/ipv4/neighbor/soft/out",
                vec!["192.168.0.1"],
            ),
            (
                "clear bgp ipv4 192.168.0.1 soft out",
                "/clear/bgp/ipv4/neighbor/soft/out",
                vec!["192.168.0.1"],
            ),
            (
                "clear bgp ipv4 neighbor all soft out",
                "/clear/bgp/ipv4/neighbor/soft/out",
                vec!["all"],
            ),
            (
                "clear bgp ipv4 all soft out",
                "/clear/bgp/ipv4/neighbor/soft/out",
                vec!["all"],
            ),
            (
                "clear bgp ipv4 192.168.0.1 soft in",
                "/clear/bgp/ipv4/neighbor/soft/in",
                vec!["192.168.0.1"],
            ),
            (
                "clear bgp ipv6 2001:db8::1",
                "/clear/bgp/ipv6/neighbor",
                vec!["2001:db8::1"],
            ),
            (
                "clear bgp vpnv4 10.0.0.1 soft out",
                "/clear/bgp/vpnv4/neighbor/soft/out",
                vec!["10.0.0.1"],
            ),
            (
                "clear bgp evpn all",
                "/clear/bgp/evpn/neighbor",
                vec!["all"],
            ),
            // Interface-neighbor names (IPv6 unnumbered peers have no
            // typeable address). The pattern-less string arm of
            // `peer-id-or-all` must word-match a single token, so the
            // walk continues into `soft out`; `all` and address
            // spellings above pin that the new arm doesn't shadow them.
            (
                "clear bgp ipv4 neighbor i1",
                "/clear/bgp/ipv4/neighbor",
                vec!["i1"],
            ),
            (
                "clear bgp ipv4 i1 soft out",
                "/clear/bgp/ipv4/neighbor/soft/out",
                vec!["i1"],
            ),
            // AFI-less form — `clear bgp {<peer>|all} [soft [in|out]]`
            // routes positionally into the `neighbor` list directly
            // under /clear/bgp (no AFI/SAFI filter at runtime). The
            // `clear bgp ipv4 …` cases above pin that the AFI keyword
            // children still win over the positional key.
            ("clear bgp all", "/clear/bgp/neighbor", vec!["all"]),
            (
                "clear bgp 192.168.0.1",
                "/clear/bgp/neighbor",
                vec!["192.168.0.1"],
            ),
            (
                "clear bgp 2001:db8::1",
                "/clear/bgp/neighbor",
                vec!["2001:db8::1"],
            ),
            ("clear bgp i1", "/clear/bgp/neighbor", vec!["i1"]),
            (
                "clear bgp neighbor 192.168.0.1",
                "/clear/bgp/neighbor",
                vec!["192.168.0.1"],
            ),
            (
                "clear bgp 192.168.0.1 soft",
                "/clear/bgp/neighbor/soft",
                vec!["192.168.0.1"],
            ),
            (
                "clear bgp all soft out",
                "/clear/bgp/neighbor/soft/out",
                vec!["all"],
            ),
            (
                "clear bgp i1 soft in",
                "/clear/bgp/neighbor/soft/in",
                vec!["i1"],
            ),
        ];

        for &(cmd, want_path, ref want_args) in &cases {
            let (code, _comps, state) = parse(cmd, entry.clone(), None, State::new());
            assert_eq!(code, ExecCode::Success, "parse `{cmd}`");
            let (path, args) = path_from_command(&state.paths);
            assert_eq!(path, want_path, "path for `{cmd}`");
            let got: Vec<&str> = args.0.iter().map(|s| s.as_str()).collect();
            assert_eq!(&got, want_args, "args for `{cmd}`");
        }
    }

    /// `ext:default-child "ipv4"` lets an address/prefix be typed right
    /// after `show bgp`; the explicit `show bgp ipv4 …` form parses to
    /// the very same path + args. `longer-prefix` rides along as a
    /// trailing keyword, and keyword children (`update-group`) are not
    /// swallowed by the positional fallback.
    #[test]
    fn show_bgp_positional_default_child() {
        use crate::config::path_from_command;
        let entry = exec_entry();

        let cases: Vec<(&str, &str, Vec<&str>)> = vec![
            ("show bgp", "/show/bgp", vec![]),
            ("show bgp ipv4", "/show/bgp/ipv4", vec![]),
            ("show bgp ipv4 10.0.0.1", "/show/bgp/ipv4", vec!["10.0.0.1"]),
            ("show bgp 10.0.0.1", "/show/bgp/ipv4", vec!["10.0.0.1"]),
            (
                "show bgp 10.0.0.0/24",
                "/show/bgp/ipv4",
                vec!["10.0.0.0/24"],
            ),
            (
                "show bgp 10.0.0.0/24 longer-prefix",
                "/show/bgp/ipv4/longer-prefix",
                vec!["10.0.0.0/24"],
            ),
            (
                "show bgp ipv6 2001:db8::1",
                "/show/bgp/ipv6",
                vec!["2001:db8::1"],
            ),
            (
                "show bgp ipv6 2001:db8::/48 longer-prefix",
                "/show/bgp/ipv6/longer-prefix",
                vec!["2001:db8::/48"],
            ),
            ("show bgp update-group", "/show/bgp/update-group", vec![]),
            ("show bgp vpnv4", "/show/bgp/vpnv4", vec![]),
            (
                "show bgp vpnv4 10.0.0.1",
                "/show/bgp/vpnv4",
                vec!["10.0.0.1"],
            ),
            (
                "show bgp vpnv4 10.0.0.0/24",
                "/show/bgp/vpnv4",
                vec!["10.0.0.0/24"],
            ),
            ("show bgp evpn", "/show/bgp/evpn", vec![]),
            (
                "show bgp evpn route-type per-region-imet",
                "/show/bgp/evpn/route-type",
                vec!["per-region-imet"],
            ),
            (
                "show bgp evpn route-type s-pmsi",
                "/show/bgp/evpn/route-type",
                vec!["s-pmsi"],
            ),
            (
                "show bgp evpn route-type leaf",
                "/show/bgp/evpn/route-type",
                vec!["leaf"],
            ),
        ];

        for &(cmd, want_path, ref want_args) in &cases {
            let (code, _comps, state) = parse(cmd, entry.clone(), None, State::new());
            assert_eq!(code, ExecCode::Success, "parse `{cmd}`");
            let (path, args) = path_from_command(&state.paths);
            assert_eq!(path, want_path, "path for `{cmd}`");
            let got: Vec<&str> = args.0.iter().map(|s| s.as_str()).collect();
            assert_eq!(&got, want_args, "args for `{cmd}`");
        }
    }

    /// Pin the `show ipv6 nd` grammar: three spellings — bare summary,
    /// all-interfaces detail, single-interface detail — must parse to the
    /// expected paths and arg vectors.
    #[test]
    fn show_ipv6_nd_grammar() {
        use crate::config::path_from_command;
        let entry = exec_entry();

        let cases: Vec<(&str, &str, Vec<&str>)> = vec![
            ("show ipv6 nd", "/show/ipv6/nd", vec![]),
            ("show ipv6 nd interface", "/show/ipv6/nd/interface", vec![]),
            (
                "show ipv6 nd interface eth0",
                "/show/ipv6/nd/interface",
                vec!["eth0"],
            ),
        ];

        for &(cmd, want_path, ref want_args) in &cases {
            let (code, _comps, state) = parse(cmd, entry.clone(), None, State::new());
            assert_eq!(code, ExecCode::Success, "parse `{cmd}`");
            let (path, args) = path_from_command(&state.paths);
            assert_eq!(path, want_path, "path for `{cmd}`");
            let got: Vec<&str> = args.0.iter().map(|s| s.as_str()).collect();
            assert_eq!(&got, want_args, "args for `{cmd}`");
        }
    }

    /// The BGP RIB views moved off the legacy `show ip bgp` tree onto
    /// `show bgp …`; the whole `show ip bgp` subtree is gone, so every
    /// old spelling must no longer parse and each `show bgp …` twin must.
    /// Covers the earlier VPNv4/EVPN/neighbor move plus the final cutover
    /// (labeled-unicast, flowspec, sr-policy, attributes, link-state,
    /// neighbor-group, vrf, and the bare `show ip bgp`).
    #[test]
    fn show_ip_bgp_vpnv4_evpn_moved() {
        let entry = exec_entry();
        for cmd in [
            "show ip bgp",
            "show ip bgp vpnv4",
            "show ip bgp vpnv4 route 10.0.0.1",
            "show ip bgp evpn",
            "show ip bgp neighbor 10.0.0.1",
            "show ip bgp neighbor 10.0.0.1 advertised-routes vpnv4",
            "show ip bgp labeled-unicast",
            "show ip bgp flowspec",
            "show ip bgp flowspec ipv6",
            "show ip bgp sr-policy",
            "show ip bgp attributes",
            "show ip bgp link-state",
            "show ip bgp route 10.0.0.1",
            "show ip bgp vrf",
            "show ip bgp vrf blue neighbor",
            "show ip bgp neighbor-group g1",
        ] {
            let (code, _comps, _state) = parse(cmd, entry.clone(), None, State::new());
            assert_ne!(code, ExecCode::Success, "`{cmd}` must not be a command");
        }
        for cmd in [
            "show bgp neighbor 10.0.0.1 advertised-routes vpnv4",
            "show bgp neighbor 10.0.0.1 received-routes evpn",
            "show bgp labeled-unicast",
            "show bgp flowspec",
            "show bgp flowspec ipv6",
            "show bgp sr-policy",
            "show bgp sr-policy ipv6",
            "show bgp attributes",
            "show bgp link-state",
            "show bgp vrf blue neighbor",
            "show bgp neighbor-group g1",
        ] {
            let (code, _comps, _state) = parse(cmd, entry.clone(), None, State::new());
            assert_eq!(code, ExecCode::Success, "`{cmd}` must parse");
        }
    }

    /// `show bgp neighbor <X>` accepts an `interface-neighbor` name
    /// — IPv6 unnumbered peers are keyed by interface, and the
    /// `bgp:neighbor` dynamic completion offers those names, so the
    /// execute path (which never sees dynamic candidates) must parse
    /// them through the key's string arm. The arm is pattern-less so it
    /// word-matches one token: trailing keywords like
    /// `advertised-routes` must keep parsing. Address spellings keep
    /// resolving because the union folds its arms into a single match
    /// candidate — an address tying the catch-all string arm (both
    /// Partial) is one leaf match, not an ambiguous command.
    #[test]
    fn show_bgp_neighbors_interface_name() {
        use crate::config::path_from_command;
        let entry = exec_entry();

        let cases: Vec<(&str, &str, Vec<&str>)> = vec![
            // The bare (all-peers) form rides on the list's
            // `ext:presence`; the BDD session-state steps poll it.
            ("show bgp neighbor", "/show/bgp/neighbor", vec![]),
            ("show bgp neighbor i1", "/show/bgp/neighbor", vec!["i1"]),
            (
                "show bgp neighbor i1 advertised-routes",
                "/show/bgp/neighbor/advertised-routes",
                vec!["i1"],
            ),
            (
                "show bgp neighbor 10.0.0.1",
                "/show/bgp/neighbor",
                vec!["10.0.0.1"],
            ),
            (
                "show bgp neighbor 2001:db8::1",
                "/show/bgp/neighbor",
                vec!["2001:db8::1"],
            ),
            // The v6-unicast Adj-RIB views: an `ipv6` leaf under each of
            // the `advertised-routes` / `received-routes` containers. The
            // neighbor key keeps the peer (a v6 address or interface name)
            // as the only arg; `ipv6` is a child path element, not an arg.
            (
                "show bgp neighbor 2001:db8::1 advertised-routes ipv6",
                "/show/bgp/neighbor/advertised-routes/ipv6",
                vec!["2001:db8::1"],
            ),
            (
                "show bgp neighbor 2001:db8::1 received-routes ipv6",
                "/show/bgp/neighbor/received-routes/ipv6",
                vec!["2001:db8::1"],
            ),
            (
                "show bgp neighbor i1 received-routes ipv6",
                "/show/bgp/neighbor/received-routes/ipv6",
                vec!["i1"],
            ),
        ];

        for &(cmd, want_path, ref want_args) in &cases {
            let (code, _comps, state) = parse(cmd, entry.clone(), None, State::new());
            assert_eq!(code, ExecCode::Success, "parse `{cmd}`");
            let (path, args) = path_from_command(&state.paths);
            assert_eq!(path, want_path, "path for `{cmd}`");
            let got: Vec<&str> = args.0.iter().map(|s| s.as_str()).collect();
            assert_eq!(&got, want_args, "args for `{cmd}`");
        }
    }

    /// The neighbor summary moved from `show ip bgp summary` to `show
    /// bgp summary`, and grew per-AFI forms. ipv4/ipv6/vpnv4 carry
    /// `summary` as an enum arm of the key union, so it arrives as an
    /// arg of the RIB path; the EVPN form is a child path of the
    /// `evpn` presence container; the VRF forms ride the existing
    /// redirect. An abbreviated keyword canonicalizes (`summ` ->
    /// `summary`) via the union-aware `matched_enumeration`.
    #[test]
    fn show_bgp_summary_grammar() {
        use crate::config::path_from_command;
        let entry = exec_entry();

        let cases: Vec<(&str, &str, Vec<&str>)> = vec![
            ("show bgp summary", "/show/bgp/summary", vec![]),
            ("show bgp ipv4 summary", "/show/bgp/ipv4", vec!["summary"]),
            ("show bgp ipv4 summ", "/show/bgp/ipv4", vec!["summary"]),
            ("show bgp ipv6 summary", "/show/bgp/ipv6", vec!["summary"]),
            ("show bgp vpnv4 summary", "/show/bgp/vpnv4", vec!["summary"]),
            ("show bgp evpn summary", "/show/bgp/evpn/summary", vec![]),
            (
                "show bgp mobile-uplane summary",
                "/show/bgp/mobile-uplane/summary",
                vec![],
            ),
            (
                "show bgp mobile-uplane summ",
                "/show/bgp/mobile-uplane/summary",
                vec![],
            ),
            (
                "show bgp vrf blue summary",
                "/show/bgp/vrf/summary",
                vec!["blue"],
            ),
            (
                "show bgp vrf blue ipv4 summary",
                "/show/bgp/vrf/ipv4",
                vec!["blue", "summary"],
            ),
        ];

        for &(cmd, want_path, ref want_args) in &cases {
            let (code, _comps, state) = parse(cmd, entry.clone(), None, State::new());
            assert_eq!(code, ExecCode::Success, "parse `{cmd}`");
            let (path, args) = path_from_command(&state.paths);
            assert_eq!(path, want_path, "path for `{cmd}`");
            let got: Vec<&str> = args.0.iter().map(|s| s.as_str()).collect();
            assert_eq!(&got, want_args, "args for `{cmd}`");
        }

        // The whole legacy `show ip bgp` subtree is gone, including the
        // per-VRF leaf — both spellings must no longer parse.
        for cmd in ["show ip bgp summary", "show ip bgp vrf v1 summary"] {
            let (code, _comps, _state) = parse(cmd, entry.clone(), None, State::new());
            assert_ne!(code, ExecCode::Success, "`{cmd}` must not be a command");
        }
    }

    /// The OSPFv2 show tree moved from `show ip ospf …` to a
    /// top-level `show ospf …` (matching `show isis`); the legacy
    /// `ip` spellings must no longer parse. Pinned with parse()
    /// tests because the vtyctl show surface is garbage-tolerant:
    /// an unwired grammar returns empty output instead of erroring.
    #[test]
    fn show_ospf_moved_out_of_show_ip() {
        use crate::config::path_from_command;
        let entry = exec_entry();

        let cases: Vec<(&str, &str, Vec<&str>)> = vec![
            ("show ospf", "/show/ospf", vec![]),
            ("show ospf interface", "/show/ospf/interface", vec![]),
            ("show ospf neighbor", "/show/ospf/neighbor", vec![]),
            (
                "show ospf neighbor detail",
                "/show/ospf/neighbor/detail",
                vec![],
            ),
            ("show ospf database", "/show/ospf/database", vec![]),
            ("show ospf route", "/show/ospf/route", vec![]),
            ("show ospf ti-lfa", "/show/ospf/ti-lfa", vec![]),
            (
                "show ospf graceful-restart",
                "/show/ospf/graceful-restart",
                vec![],
            ),
            ("show ospf vrf blue", "/show/ospf/vrf", vec!["blue"]),
            (
                "show ospf vrf blue route",
                "/show/ospf/vrf/route",
                vec!["blue"],
            ),
        ];

        for &(cmd, want_path, ref want_args) in &cases {
            let (code, _comps, state) = parse(cmd, entry.clone(), None, State::new());
            assert_eq!(code, ExecCode::Success, "parse `{cmd}`");
            let (path, args) = path_from_command(&state.paths);
            assert_eq!(path, want_path, "path for `{cmd}`");
            let got: Vec<&str> = args.0.iter().map(|s| s.as_str()).collect();
            assert_eq!(&got, want_args, "args for `{cmd}`");
        }

        // The legacy `show ip ospf …` spellings are gone.
        for cmd in [
            "show ip ospf",
            "show ip ospf neighbor",
            "show ip ospf route",
            "show ip ospf vrf blue",
        ] {
            let (code, _comps, _state) = parse(cmd, entry.clone(), None, State::new());
            assert_ne!(code, ExecCode::Success, "`{cmd}` must not be a command");
        }
    }

    /// The OSPFv3 show tree moved the same way: `show ipv6 ospf …`
    /// became a top-level `show ospfv3 …` (the container is renamed,
    /// so the dispatch segment is `ospfv3`, never colliding with
    /// v2's `ospf`). The legacy `ipv6` spellings must no longer
    /// parse; v2's `show ospf` is untouched.
    #[test]
    fn show_ospfv3_moved_out_of_show_ipv6() {
        use crate::config::path_from_command;
        let entry = exec_entry();

        let cases: Vec<(&str, &str, Vec<&str>)> = vec![
            ("show ospfv3", "/show/ospfv3", vec![]),
            ("show ospfv3 interface", "/show/ospfv3/interface", vec![]),
            ("show ospfv3 neighbor", "/show/ospfv3/neighbor", vec![]),
            (
                "show ospfv3 neighbor detail",
                "/show/ospfv3/neighbor/detail",
                vec![],
            ),
            ("show ospfv3 database", "/show/ospfv3/database", vec![]),
            ("show ospfv3 route", "/show/ospfv3/route", vec![]),
            ("show ospfv3 ti-lfa", "/show/ospfv3/ti-lfa", vec![]),
            ("show ospfv3 vrf blue", "/show/ospfv3/vrf", vec!["blue"]),
            (
                "show ospfv3 vrf blue route",
                "/show/ospfv3/vrf/route",
                vec!["blue"],
            ),
        ];

        for &(cmd, want_path, ref want_args) in &cases {
            let (code, _comps, state) = parse(cmd, entry.clone(), None, State::new());
            assert_eq!(code, ExecCode::Success, "parse `{cmd}`");
            let (path, args) = path_from_command(&state.paths);
            assert_eq!(path, want_path, "path for `{cmd}`");
            let got: Vec<&str> = args.0.iter().map(|s| s.as_str()).collect();
            assert_eq!(&got, want_args, "args for `{cmd}`");
        }

        // The legacy `show ipv6 ospf …` spellings are gone.
        for cmd in [
            "show ipv6 ospf",
            "show ipv6 ospf neighbor",
            "show ipv6 ospf route",
            "show ipv6 ospf vrf blue",
        ] {
            let (code, _comps, _state) = parse(cmd, entry.clone(), None, State::new());
            assert_ne!(code, ExecCode::Success, "`{cmd}` must not be a command");
        }

        // v2 (`show ospf`) and the other `show ipv6` trees survive.
        for cmd in ["show ospf neighbor", "show ipv6 route", "show ipv6 nd"] {
            let (code, _comps, _state) = parse(cmd, entry.clone(), None, State::new());
            assert_eq!(code, ExecCode::Success, "`{cmd}` must still parse");
        }
    }

    /// `show bgp ipv4 <tab>` surfaces the union arms of the key —
    /// the value hints and the `summary` keyword — instead of an
    /// opaque `<value:union>` hint.
    #[test]
    fn show_bgp_ipv4_completion_offers_union_arms() {
        let entry = exec_entry();
        let (_code, comps, _state) = parse("show bgp ipv4 ", entry, None, State::new());
        let names: Vec<&str> = comps.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"<A.B.C.D>"), "comps: {names:?}");
        assert!(names.contains(&"<A.B.C.D/M>"), "comps: {names:?}");
        assert!(names.contains(&"summary"), "comps: {names:?}");
    }

    /// The positional shortcut is IPv4-only (`ext:default-child
    /// "ipv4"`): a bare IPv6 literal after `show bgp` is not a command —
    /// IPv6 must be reached through the explicit `ipv6` keyword.
    #[test]
    fn show_bgp_positional_is_ipv4_only() {
        let entry = exec_entry();
        for cmd in ["show bgp 2001:db8::1", "show bgp 2001:db8::/48"] {
            let (code, _comps, _state) = parse(cmd, entry.clone(), None, State::new());
            assert_ne!(code, ExecCode::Success, "`{cmd}` must not be a command");
        }
    }

    /// `show bgp <tab>` advertises both the AFI keywords and the
    /// positional value hints contributed by `ext:default-child`. The
    /// `summary` keyword exists twice in the schema (the leaf and the
    /// ipv4 key's enum arm) but must be listed once.
    #[test]
    fn show_bgp_completion_offers_positional_hint() {
        let entry = exec_entry();
        let (_code, comps, _state) = parse("show bgp ", entry, None, State::new());
        let names: Vec<&str> = comps.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"ipv4"), "comps: {names:?}");
        assert!(names.contains(&"ipv6"), "comps: {names:?}");
        assert!(names.contains(&"<A.B.C.D>"), "comps: {names:?}");
        assert!(names.contains(&"<A.B.C.D/M>"), "comps: {names:?}");
        assert_eq!(
            names.iter().filter(|n| **n == "summary").count(),
            1,
            "comps: {names:?}"
        );
    }

    /// `show bgp vrf <name> …` mirrors the default-VRF tree: the `vrf`
    /// list carries its own `ext:default-child "ipv4"`, so a bare
    /// address/prefix typed after the VRF name routes into `ipv4` (the
    /// matcher applies the positional shortcut after a list key as well
    /// as on a plain container).
    #[test]
    fn show_bgp_vrf_positional_default_child() {
        use crate::config::path_from_command;
        let entry = exec_entry();

        let cases: Vec<(&str, &str, Vec<&str>)> = vec![
            ("show bgp vrf", "/show/bgp/vrf", vec![]),
            ("show bgp vrf blue", "/show/bgp/vrf", vec!["blue"]),
            ("show bgp vrf blue ipv4", "/show/bgp/vrf/ipv4", vec!["blue"]),
            (
                "show bgp vrf blue ipv4 10.0.0.1",
                "/show/bgp/vrf/ipv4",
                vec!["blue", "10.0.0.1"],
            ),
            (
                "show bgp vrf blue 10.0.0.1",
                "/show/bgp/vrf/ipv4",
                vec!["blue", "10.0.0.1"],
            ),
            (
                "show bgp vrf blue 10.0.0.0/24",
                "/show/bgp/vrf/ipv4",
                vec!["blue", "10.0.0.0/24"],
            ),
            (
                "show bgp vrf blue 10.0.0.0/24 longer-prefix",
                "/show/bgp/vrf/ipv4/longer-prefix",
                vec!["blue", "10.0.0.0/24"],
            ),
            (
                "show bgp vrf blue ipv4 10.0.0.0/24 longer-prefix",
                "/show/bgp/vrf/ipv4/longer-prefix",
                vec!["blue", "10.0.0.0/24"],
            ),
            ("show bgp vrf blue ipv6", "/show/bgp/vrf/ipv6", vec!["blue"]),
            (
                "show bgp vrf blue ipv6 2001:db8::1",
                "/show/bgp/vrf/ipv6",
                vec!["blue", "2001:db8::1"],
            ),
            (
                "show bgp vrf blue ipv6 2001:db8::/48 longer-prefix",
                "/show/bgp/vrf/ipv6/longer-prefix",
                vec!["blue", "2001:db8::/48"],
            ),
        ];

        for &(cmd, want_path, ref want_args) in &cases {
            let (code, _comps, state) = parse(cmd, entry.clone(), None, State::new());
            assert_eq!(code, ExecCode::Success, "parse `{cmd}`");
            let (path, args) = path_from_command(&state.paths);
            assert_eq!(path, want_path, "path for `{cmd}`");
            let got: Vec<&str> = args.0.iter().map(|s| s.as_str()).collect();
            assert_eq!(&got, want_args, "args for `{cmd}`");
        }
    }

    /// After the manager strips the `vrf <name>` selector, the per-VRF
    /// BGP task sees exactly the default-VRF `/show/bgp/…` path + value,
    /// which is what [`crate::bgp::show::process_vrf_show`] dispatches on.
    #[test]
    fn show_bgp_vrf_redirect_strips_selector() {
        use crate::config::{path_from_command, vrf_redirect_split};
        let entry = exec_entry();

        let cases: Vec<(&str, &str, Vec<&str>)> = vec![
            ("show bgp vrf blue", "/show/bgp", vec![]),
            ("show bgp vrf blue ipv4", "/show/bgp/ipv4", vec![]),
            (
                "show bgp vrf blue 10.0.0.1",
                "/show/bgp/ipv4",
                vec!["10.0.0.1"],
            ),
            (
                "show bgp vrf blue 10.0.0.0/24 longer-prefix",
                "/show/bgp/ipv4/longer-prefix",
                vec!["10.0.0.0/24"],
            ),
            (
                "show bgp vrf blue ipv6 2001:db8::/48 longer-prefix",
                "/show/bgp/ipv6/longer-prefix",
                vec!["2001:db8::/48"],
            ),
            ("show bgp vrf blue summary", "/show/bgp/summary", vec![]),
            (
                "show bgp vrf blue ipv4 summary",
                "/show/bgp/ipv4",
                vec!["summary"],
            ),
        ];

        for &(cmd, want_path, ref want_args) in &cases {
            let (code, _comps, state) = parse(cmd, entry.clone(), None, State::new());
            assert_eq!(code, ExecCode::Success, "parse `{cmd}`");
            let (name, rewritten) =
                vrf_redirect_split(&state.paths).expect("vrf selector should split");
            assert_eq!(name, "blue", "vrf name for `{cmd}`");
            let (path, args) = path_from_command(&rewritten);
            assert_eq!(path, want_path, "redirected path for `{cmd}`");
            let got: Vec<&str> = args.0.iter().map(|s| s.as_str()).collect();
            assert_eq!(&got, want_args, "redirected args for `{cmd}`");
        }
    }
}
