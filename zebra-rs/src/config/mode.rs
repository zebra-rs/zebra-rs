use super::manager::ConfigStore;
use super::ExecCode;
use libyang::Entry;
use std::{collections::HashMap, sync::Arc};

type FuncMap = HashMap<String, fn(&ConfigStore) -> (ExecCode, String)>;

#[derive(Debug)]
pub struct Mode {
    pub entry: Arc<Entry>,
    pub fmap: FuncMap,
}

impl Mode {
    pub fn new(entry: Arc<Entry>) -> Self {
        Self {
            entry,
            fmap: HashMap::new(),
        }
    }

    pub fn install_func(&mut self, path: String, f: fn(&ConfigStore) -> (ExecCode, String)) {
        self.fmap.insert(path, f);
    }
}
