use super::parse::match_keyword;
use super::parse::{Match, MatchType, YangMatch};
use super::{Completion, Elem};
use std::{cell::RefCell, rc::Rc};

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
                out.push_str(&" ".repeat(depth * 4).to_string());
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
                out.push_str(&" ".repeat(depth * 4).to_string());
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
                    //
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
        if !self.has_dir() || self.presence {
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
}

pub fn carbon_copy(conf: &Rc<Config>, parent: Option<Rc<Config>>) -> Rc<Config> {
    let p = Rc::new(Config {
        name: conf.name.clone(),
        prefix: conf.prefix.clone(),
        value: conf.value.clone(),
        list: conf.list.clone(),
        presence: conf.presence,
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
fn config_set_dir(config: &Rc<Config>, elem: &Elem) -> Rc<Config> {
    let find = config.lookup(&elem.name);
    match find {
        Some(find) => find,
        None => {
            let n = Rc::new(Config {
                name: elem.name.clone(),
                parent: Some(config.clone()),
                presence: elem.presence,
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

fn config_set_key(config: &Rc<Config>, elem: &Elem) -> Rc<Config> {
    let find = config.lookup_key(&elem.name);
    match find {
        Some(find) => find,
        None => {
            let n = Rc::new(Config {
                name: elem.name.clone(),
                parent: Some(config.clone()),
                prefix: elem.key.clone(),
                ..Default::default()
            });
            config.keys.borrow_mut().push(n.clone());
            config.keys.borrow_mut().sort_by(|a, b| a.name.cmp(&b.name));
            n.clone()
        }
    }
}

fn config_set_value(config: &Rc<Config>, elem: &Elem) {
    config.value.replace(elem.name.to_owned());
}

fn config_set_list_value(config: &mut Rc<Config>, elem: &Elem) {
    config.list.borrow_mut().push(elem.name.clone());
}

pub fn config_set(mut elems: Vec<Elem>, mut config: Rc<Config>) {
    if elems[0].name == "set" {
        elems.remove(0);
    }
    for elem in elems.iter() {
        match elem.ymatch {
            YangMatch::Dir
            | YangMatch::DirMatched
            | YangMatch::Key
            | YangMatch::Leaf
            | YangMatch::LeafList => {
                config = config_set_dir(&config, elem);
            }
            YangMatch::KeyMatched => {
                config = config_set_key(&config, elem);
            }
            YangMatch::LeafMatched => {
                config_set_value(&config, elem);
            }
            YangMatch::LeafListMatched => {
                config_set_list_value(&mut config, elem);
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

pub fn delete(mut elems: Vec<Elem>, mut config: Rc<Config>) {
    if elems.is_empty() || elems[0].name != "delete" {
        return;
    }
    elems.remove(0);

    for elem in elems.iter() {
        match elem.ymatch {
            YangMatch::Dir | YangMatch::Leaf | YangMatch::Key => {
                if let Some(next) = config.lookup(&elem.name) {
                    config = next;
                } else {
                    break;
                }
            }
            YangMatch::KeyMatched => {
                if let Some(next) = config.lookup_key(&elem.name) {
                    config = next;
                } else {
                    break;
                }
            }
            YangMatch::LeafMatched => {
                if config.value.borrow().as_ref() != elem.name {
                    break;
                }
            }
            _ => {}
        }
    }

    while let Some(parent) = config.parent.as_ref() {
        config_delete(parent.clone(), &config.name);
        config = parent.clone();
        if config.has_dir() || config.presence {
            break;
        }
    }
}

fn config_match_keyword(config: &Rc<Config>, name: &String, input: &String, mx: &mut Match) {
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

fn config_match_dir(config: &Rc<Config>, input: &String, mx: &mut Match) {
    for config in config.configs.borrow().iter() {
        config_match_keyword(config, &config.name, input, mx);
    }
    for key in config.keys.borrow().iter() {
        config_match_keyword(key, &key.name, input, mx);
    }
}

fn config_match_value(config: &Rc<Config>, input: &String, mx: &mut Match) {
    if config.list.borrow().is_empty() {
        config_match_keyword(config, &config.value.borrow(), input, mx);
    } else {
        for value in config.list.borrow().iter() {
            config_match_keyword(config, value, input, mx);
        }
    }
}

pub fn config_match(config: &Rc<Config>, input: &String, mx: &mut Match) {
    if config.has_dir() {
        config_match_dir(config, input, mx);
    } else {
        config_match_value(config, input, mx);
    }
}
