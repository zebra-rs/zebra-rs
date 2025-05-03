use std::collections::BTreeMap;

use isis_packet::IsisSysId;

#[derive(Default)]
pub struct Hostname {
    pub map: BTreeMap<IsisSysId, String>,
}

impl Hostname {
    pub fn insert(&mut self, key: IsisSysId, value: String) -> Option<String> {
        self.map.insert(key, value)
    }

    pub fn remove(&mut self, key: &IsisSysId) -> Option<String> {
        self.map.remove(key)
    }
}
