use std::collections::BTreeMap;

use isis_packet::IsisSysId;

struct LspTree {
    pub tree: BTreeMap<IsisSysId, usize>,
    pub ids: Vec<Option<IsisSysId>>,
}

impl LspTree {
    pub fn new() -> Self {
        Self {
            tree: BTreeMap::new(),
            ids: Vec::new(),
        }
    }

    /// Returns the index for `sys_id`, inserting if necessary.
    pub fn get(&mut self, sys_id: &IsisSysId) -> usize {
        match self.tree.get(sys_id) {
            Some(&index) => {
                // Ensure `ids[index]` is Some(_).
                if self.ids.get(index).is_some() {
                    index
                } else {
                    self.ids[index] = Some(sys_id.clone());
                    index
                }
            }
            None => {
                let index = self.ids.len();
                self.tree.insert(sys_id.clone(), index);
                self.ids.push(Some(sys_id.clone()));
                index
            }
        }
    }

    /// Returns IsisSysId from id.
    pub fn get_by_id(&self, id: usize) -> Option<&IsisSysId> {
        self.ids.get(id).and_then(|sys_id| sys_id.as_ref())
    }

    /// Remove IsisSysId from id mapping vector.
    pub fn remove(&mut self, sys_id: &IsisSysId) {
        if let Some(&index) = self.tree.get(sys_id) {
            self.ids[index] = None;
        }
    }
}

pub fn lsp_graph() {
    //
}
