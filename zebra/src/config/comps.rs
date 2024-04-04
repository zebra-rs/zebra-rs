use super::parse::YangMatch;

#[derive(Debug, Default)]
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

    pub fn new_by_name(name: &str) -> Self {
        Self {
            name: name.to_string(),
            help: "".to_string(),
            ymatch: YangMatch::Leaf,
        }
    }
}

pub fn comps_add_cr(comps: &mut Vec<Completion>) {
    comps.push(Completion::new_by_name("<cr>"));
}

fn comps_exists(comps: &[Completion], name: &String) -> bool {
    comps.iter().any(|x| x.name == *name)
}

pub fn comps_append(from: &mut Vec<Completion>, to: &mut Vec<Completion>) {
    while let Some(comp) = from.pop() {
        if !comps_exists(to, &comp.name) {
            to.push(comp);
        }
    }
}
