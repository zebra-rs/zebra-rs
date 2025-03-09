use bgp_packet::{Afi, AfiSafi, Safi};

use super::parse::match_keyword;
use super::parse::{Match, MatchType};
use super::vtysh::{CommandPath, YangMatch};
use super::Completion;

use ipnet::{Ipv4Net, Ipv6Net};
use std::collections::VecDeque;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::{cell::RefCell, rc::Rc};

const INDENT_LEVEL: usize = 2;

#[derive(Clone)]
pub struct Args(pub VecDeque<String>);

macro_rules! arg_parse_type {
    ($self:expr, $typ:ty) => {
        let item = $self.0.pop_front()?;
        match item.parse::<$typ>() {
            Ok(arg) => {
                return Some(arg);
            }
            Err(_) => {
                $self.0.push_front(item);
                return None;
            }
        }
    };
}

#[allow(dead_code)]
impl Args {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn string(&mut self) -> Option<String> {
        self.0.pop_front()
    }

    pub fn u8(&mut self) -> Option<u8> {
        arg_parse_type!(self, u8);
    }

    pub fn u16(&mut self) -> Option<u16> {
        arg_parse_type!(self, u16);
    }

    pub fn u32(&mut self) -> Option<u32> {
        arg_parse_type!(self, u32);
    }

    pub fn v4addr(&mut self) -> Option<Ipv4Addr> {
        arg_parse_type!(self, Ipv4Addr);
    }

    pub fn v4net(&mut self) -> Option<Ipv4Net> {
        arg_parse_type!(self, Ipv4Net);
    }

    pub fn v6addr(&mut self) -> Option<Ipv6Addr> {
        arg_parse_type!(self, Ipv6Addr);
    }

    pub fn v6net(&mut self) -> Option<Ipv6Net> {
        arg_parse_type!(self, Ipv6Net);
    }

    pub fn boolean(&mut self) -> Option<bool> {
        arg_parse_type!(self, bool);
    }

    pub fn afi_safi(&mut self) -> Option<AfiSafi> {
        let item = self.0.pop_front()?;
        match item.as_str() {
            "ipv4-unicast" => Some(AfiSafi::new(Afi::Ip, Safi::Unicast)),
            "ipv4-labeled-unicast" => Some(AfiSafi::new(Afi::Ip, Safi::MplsLabel)),
            "l3vpn-ipv4-unicast" => Some(AfiSafi::new(Afi::Ip, Safi::MplsVpn)),
            "ipv6-unicast" => Some(AfiSafi::new(Afi::Ip6, Safi::Unicast)),
            "ipv6-labeled-unicast" => Some(AfiSafi::new(Afi::Ip6, Safi::MplsLabel)),
            "l3vpn-ipv6-unicast" => Some(AfiSafi::new(Afi::Ip, Safi::MplsVpn)),
            _ => None,
        }
    }
}

#[derive(Default, Debug)]
pub struct Config {
    pub name: String,
    pub prefix: String,
    pub value: RefCell<String>,
    pub list: RefCell<Vec<String>>,
    pub configs: RefCell<Vec<Rc<Config>>>,
    pub keys: RefCell<Vec<Rc<Config>>>,
    pub presence: bool,
    pub parent: Option<Rc<Config>>,
    pub mandatory: Vec<String>,
}

impl Config {
    pub fn new(name: String, parent: Option<Rc<Config>>) -> Self {
        Config {
            name,
            parent,
            ..Default::default()
        }
    }

    pub fn has_dir(&self) -> bool {
        !self.configs.borrow().is_empty() || !self.keys.borrow().is_empty()
    }

    pub fn lookup(&self, name: &String) -> Option<Rc<Config>> {
        for config in self.configs.borrow().iter() {
            if config.name == *name {
                return Some(config.clone());
            }
        }
        None
    }

    pub fn lookup_key(&self, name: &String) -> Option<Rc<Config>> {
        for key in self.keys.borrow().iter() {
            if key.name == *name {
                return Some(key.clone());
            }
        }
        None
    }

    pub fn prefix_write(&self, out: &mut String) {
        if self.prefix.is_empty() {
            return;
        }

        if let Some(parent) = self.parent.as_ref() {
            if !parent.prefix.is_empty() {
                parent.prefix_write(out);
            }
            out.push_str(&format!("{} ", parent.name));
        }
    }

    pub fn display_entry(&self) -> bool {
        self.keys.borrow().is_empty()
    }

    pub fn quote(&self) -> bool {
        // if c.Entry.Type.Kind == yang.Ystring {
        //     if len(c.Entry.Type.Pattern) == 0 {
        //         return true
        //     }
        // }
        false
    }

    pub fn write(&self, depth: usize, out: &mut String) {
        let configs = self.configs.borrow();
        let brace = !configs.is_empty();

        if self.display_entry() {
            if depth != 0 {
                out.push_str(&" ".repeat(depth * INDENT_LEVEL).to_string());
            }
            self.prefix_write(out);

            out.push_str(&self.name.to_string());

            if !self.value.borrow().is_empty() {
                if self.quote() {
                    out.push_str(&format!(" \"{}\"", self.value.borrow()));
                } else {
                    out.push_str(&format!(" {}", self.value.borrow()));
                }
            }

            if !self.list.borrow().is_empty() {
                for value in self.list.borrow().iter() {
                    if self.quote() {
                        out.push_str(&format!("\"{}\"", value));
                    } else {
                        out.push(' ');
                        out.push_str(&value.to_string());
                    }
                }
            }
            if brace {
                out.push_str(" {\n");
            } else {
                out.push_str(";\n");
            }
        }

        for key in self.keys.borrow().iter() {
            key.write(depth, out);
        }

        for config in configs.iter() {
            config.write(depth + 1, out);
        }

        if self.display_entry() && brace {
            if depth != 0 {
                out.push_str(&" ".repeat(depth * INDENT_LEVEL).to_string());
            }
            out.push_str("}\n");
        }
    }

    pub fn format(&self, out: &mut String) {
        for config in self.configs.borrow().iter() {
            config.write(0usize, out);
        }
    }

    pub fn has_prefix(&self) -> bool {
        !self.prefix.is_empty()
    }

    pub fn json_marshal(&self, pos: usize, out: &mut String) {
        if pos != 0 {
            out.push(',');
        }

        if !self.keys.borrow().is_empty() {
            out.push_str(&format!("\"{}\": [", self.name));
        } else if self.has_prefix() {
            out.push('{');
            out.push_str(&format!("\"{}\":\"{}\"", self.prefix, self.name));
        } else {
            let value = self.value.borrow();
            if !value.is_empty() {
                out.push_str(&format!("\"{}\":\"{}\"", self.name, value));
            } else {
                let value_list = self.list.borrow();
                if value_list.len() > 0 {
                    let value_list: Vec<String> =
                        value_list.iter().map(|x| format!("\"{}\"", x)).collect();
                    let leaf_list = value_list.join(",");
                    out.push_str(&format!("\"{}\": [{}]", self.name, leaf_list));
                } else {
                    out.push_str(&format!("\"{}\":", self.name));
                }
            }
        }

        let keys = self.keys.borrow();
        for (pos, n) in keys.iter().enumerate() {
            // if n.key_only_config {
            //     n.json_marshal(pos + 1, out);
            // } else {
            n.json_marshal(pos, out);
            // }
        }

        let configs = self.configs.borrow();
        if configs.len() > 0 {
            if !self.has_prefix() {
                out.push('{');
            }
            for (pos, n) in configs.iter().enumerate() {
                if self.has_prefix() {
                    n.json_marshal(pos + 1, out)
                } else {
                    n.json_marshal(pos, out)
                }
            }
            out.push('}');
        } else if self.has_prefix() && keys.is_empty() {
            out.push('}');
        }

        if keys.is_empty() && configs.is_empty() && self.presence {
            out.push_str("{}");
        }

        if !self.keys.borrow().is_empty() {
            out.push(']');
        }
    }

    pub fn json(&self, out: &mut String) {
        let keys = self.keys.borrow();
        if keys.len() > 0 {
            out.push('[');
            for (pos, key) in keys.iter().enumerate() {
                if pos != 0 {
                    out.push(',');
                }
                key.json_marshal(0, out);
            }
            out.push(']');
            return;
        }

        out.push('{');
        let configs = self.configs.borrow();
        for (pos, config) in configs.iter().enumerate() {
            if pos != 0 {
                out.push(',');
            }
            config.json_marshal(0, out);
        }
        out.push('}');
    }

    pub fn yaml(&self, out: &mut String) {
        let mut json = String::new();
        self.json(&mut json);
        let json_value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let yaml_str = serde_yaml::to_string(&json_value).unwrap();
        out.push_str(&yaml_str);
    }

    pub fn list_command(&self) -> Vec<String> {
        let mut commands = Vec::new();
        if let Some(parent) = self.parent.as_ref() {
            for com in parent.list_command().iter() {
                commands.push(com.clone());
            }
            commands.push(self.name.clone());
            if !self.value.borrow().is_empty() {
                commands.push(self.value.borrow().clone());
            }
            for list in self.list.borrow().iter() {
                commands.push(list.clone());
            }
        }
        commands
    }

    pub fn list(&self, output: &mut String) {
        if !self.has_dir() || self.presence || !self.prefix.is_empty() {
            let commands = self.list_command();
            if !commands.is_empty() {
                output.push_str(&commands.join(" "));
                output.push('\n');
            }
        }
        for key in self.keys.borrow().iter() {
            key.list(output);
        }
        for config in self.configs.borrow().iter() {
            config.list(output);
        }
    }

    fn has_mandatory(&self, mandatory: &String) -> bool {
        for config in self.configs.borrow().iter() {
            if config.name == *mandatory {
                return true;
            }
        }
        false
    }

    pub fn parents(&self, p: &mut VecDeque<String>) {
        if let Some(parent) = &self.parent {
            if !parent.name.is_empty() {
                p.push_front(parent.name.clone());
            }
            parent.parents(p);
        }
    }

    pub fn validate(&self, errors: &mut Vec<String>) {
        for m in self.mandatory.iter() {
            for key in self.keys.borrow().iter() {
                if !key.has_mandatory(m) {
                    let mut parents = VecDeque::<String>::new();
                    self.parents(&mut parents);
                    parents.push_back(self.name.clone());
                    parents.push_back(key.name.clone());
                    let parents = Vec::from(parents);
                    let parents = parents.join(" ");
                    errors.push(format!("'{}' missing mandatory node '{}'", parents, m));
                }
            }
            if !self.configs.borrow().is_empty() && !self.has_mandatory(m) {
                let mut parents = VecDeque::<String>::new();
                self.parents(&mut parents);
                parents.push_back(self.name.clone());
                let parents = Vec::from(parents);
                let parents = parents.join(" ");
                errors.push(format!("'{}' missing mandatory node '{}'", parents, m));
            }
        }
        for key in self.keys.borrow().iter() {
            key.validate(errors);
        }
        for config in self.configs.borrow().iter() {
            config.validate(errors);
        }
    }
}

pub fn carbon_copy(conf: &Rc<Config>, parent: Option<Rc<Config>>) -> Rc<Config> {
    let p = Rc::new(Config {
        name: conf.name.clone(),
        prefix: conf.prefix.clone(),
        value: conf.value.clone(),
        list: conf.list.clone(),
        presence: conf.presence,
        mandatory: conf.mandatory.clone(),
        parent,
        ..Default::default()
    });
    for conf in conf.configs.borrow().iter() {
        let c = carbon_copy(&conf.clone(), Some(p.clone()));
        p.configs.borrow_mut().push(c);
    }
    for key in conf.keys.borrow().iter() {
        let k = carbon_copy(&key.clone(), Some(p.clone()));
        p.keys.borrow_mut().push(k);
    }
    p
}

// Config set.
fn config_set_dir(config: &Rc<Config>, cpath: &CommandPath) -> Rc<Config> {
    let find = config.lookup(&cpath.name);
    match find {
        Some(find) => find,
        None => {
            let n = Rc::new(Config {
                name: cpath.name.clone(),
                parent: Some(config.clone()),
                presence: (ymatch_enum(cpath.ymatch) == YangMatch::DirMatched),
                mandatory: cpath.mandatory.clone(),
                ..Default::default()
            });
            config.configs.borrow_mut().push(n.clone());
            config
                .configs
                .borrow_mut()
                .sort_by(|a, b| a.name.cmp(&b.name));
            n.clone()
        }
    }
}

fn config_set_key(config: &Rc<Config>, cpath: &CommandPath) -> Rc<Config> {
    let find = config.lookup_key(&cpath.name);
    match find {
        Some(find) => find,
        None => {
            let n = Rc::new(Config {
                name: cpath.name.clone(),
                parent: Some(config.clone()),
                prefix: cpath.key.clone(),
                mandatory: cpath.mandatory.clone(),
                ..Default::default()
            });
            config.keys.borrow_mut().push(n.clone());
            config
                .keys
                .borrow_mut()
                .sort_by(|a, b| alphanumeric_sort::compare_str(&a.name, &b.name));
            n.clone()
        }
    }
}

fn config_set_value(config: &Rc<Config>, cpath: &CommandPath) {
    config.value.replace(cpath.name.to_owned());
}

fn config_set_list_value(config: &mut Rc<Config>, cpath: &CommandPath) {
    config.list.borrow_mut().push(cpath.name.clone());
}

pub fn ymatch_enum(ymatch: i32) -> YangMatch {
    match ymatch {
        0 => YangMatch::Dir,
        1 => YangMatch::DirMatched,
        2 => YangMatch::Key,
        3 => YangMatch::KeyMatched,
        4 => YangMatch::Leaf,
        5 => YangMatch::LeafMatched,
        6 => YangMatch::LeafList,
        _ => YangMatch::LeafListMatched,
    }
}

pub fn set(paths: Vec<CommandPath>, mut config: Rc<Config>) {
    for path in paths.iter() {
        match ymatch_enum(path.ymatch) {
            YangMatch::Dir
            | YangMatch::DirMatched
            | YangMatch::Key
            | YangMatch::Leaf
            | YangMatch::LeafList => {
                config = config_set_dir(&config, path);
            }
            YangMatch::KeyMatched => {
                config = config_set_key(&config, path);
            }
            YangMatch::LeafMatched => {
                config_set_value(&config, path);
            }
            YangMatch::LeafListMatched => {
                config_set_list_value(&mut config, path);
            }
        }
    }
}

fn config_delete(config: Rc<Config>, name: &String) {
    let mut configs = config.configs.borrow_mut();
    if let Some(remove_index) = configs.iter().position(|x| *x.name == *name) {
        configs.remove(remove_index);
    }
    let mut keys = config.keys.borrow_mut();
    if let Some(remove_index) = keys.iter().position(|x| *x.name == *name) {
        keys.remove(remove_index);
    }
}

pub fn delete(paths: Vec<CommandPath>, mut config: Rc<Config>) {
    for path in paths.iter() {
        match ymatch_enum(path.ymatch) {
            YangMatch::Dir | YangMatch::DirMatched | YangMatch::Leaf | YangMatch::Key => {
                if let Some(next) = config.lookup(&path.name) {
                    config = next;
                } else {
                    break;
                }
            }
            YangMatch::KeyMatched => {
                if let Some(next) = config.lookup_key(&path.name) {
                    config = next;
                } else {
                    break;
                }
            }
            YangMatch::LeafMatched => {
                if config.value.borrow().as_ref() != path.name {
                    break;
                }
            }
            YangMatch::LeafList => {
                if let Some(next) = config.lookup(&path.name) {
                    config = next;
                } else {
                    break;
                }
            }
            YangMatch::LeafListMatched => {
                let mut lists = config.list.borrow_mut();
                if let Some(remove_index) = lists.iter().position(|x| *x == path.name) {
                    lists.remove(remove_index);
                }
                if !lists.is_empty() {
                    return;
                }
            }
        }
    }

    while let Some(parent) = config.parent.as_ref() {
        config_delete(parent.clone(), &config.name);
        config = parent.clone();
        if config.has_dir() || config.has_prefix() || config.presence {
            break;
        }
    }
}

fn config_match_keyword(config: &Rc<Config>, name: &str, input: &str, mx: &mut Match) {
    let (m, p) = match_keyword(input, name);
    if m == MatchType::None {
        return;
    }
    if m > mx.matched_type {
        mx.count = 1;
        mx.pos = p;
        mx.matched_type = m;
        mx.matched_config = config.clone();
    } else if m == mx.matched_type {
        mx.count += 1;
    }
    mx.comps.push(Completion::new(name, ""));
}

fn config_match_dir(config: &Rc<Config>, input: &str, mx: &mut Match) {
    for config in config.configs.borrow().iter() {
        config_match_keyword(config, &config.name, input, mx);
    }
    for key in config.keys.borrow().iter() {
        config_match_keyword(key, &key.name, input, mx);
    }
}

fn config_match_value(config: &Rc<Config>, input: &str, mx: &mut Match) {
    if config.list.borrow().is_empty() {
        config_match_keyword(config, &config.value.borrow(), input, mx);
    } else {
        for value in config.list.borrow().iter() {
            config_match_keyword(config, value, input, mx);
        }
    }
}

pub fn config_match(config: &Rc<Config>, input: &str, mx: &mut Match) {
    if config.has_dir() {
        config_match_dir(config, input, mx);
    } else {
        config_match_value(config, input, mx);
    }
}
