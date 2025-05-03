use std::collections::BTreeMap;
use std::fmt::Write;

use isis_packet::IsisSysId;
use serde::Serialize;

use crate::config::Args;
use crate::isis::{Isis, Level};

#[derive(Default, Serialize)]
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

    pub fn len(&self) -> usize {
        self.map.len()
    }
}

// Helper to convert map key to String
fn map_to_string_map<K: ToString, V: Clone>(map: &BTreeMap<K, V>) -> BTreeMap<String, V> {
    map.iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect()
}

pub fn show(isis: &Isis, _args: Args, json: bool) -> String {
    if json {
        let l1 = map_to_string_map(&isis.hostname.l1.map);
        let l2 = map_to_string_map(&isis.hostname.l2.map);
        return serde_json::to_string(&serde_json::json!({ "l1": l1, "l2": l2 })).unwrap();
    }

    if isis.hostname.l1.len() + isis.hostname.l2.len() == 0 {
        return String::from("% No hostname was found");
    }

    let mut buf = String::from("Level  System ID      Hostname\n");
    for level in &[Level::L1, Level::L2] {
        let label = match level {
            Level::L1 => "L1",
            Level::L2 => "L2",
        };
        for (id, host) in isis.hostname.get(level).map.iter() {
            writeln!(buf, "{:<6} {:<13} {}", label, id, host).unwrap();
        }
    }
    buf
}
