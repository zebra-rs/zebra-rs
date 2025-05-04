use std::collections::BTreeMap;
use std::fmt::Write;

use isis_packet::IsisSysId;
use serde::Serialize;

use crate::config::Args;
use crate::isis::{Isis, Level};

#[derive(Default, Serialize)]
pub struct Hostname {
    // (String, bool) where String=hostname, bool=originate
    pub map: BTreeMap<IsisSysId, (String, bool)>,
}

impl Hostname {
    pub fn insert(&mut self, key: IsisSysId, hostname: String) -> Option<(String, bool)> {
        self.map.insert(key, (hostname, false))
    }

    pub fn insert_originate(&mut self, key: IsisSysId, hostname: String) -> Option<(String, bool)> {
        self.map.insert(key, (hostname, true))
    }

    pub fn remove(&mut self, key: &IsisSysId) -> Option<(String, bool)> {
        self.map.remove(key)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }
}

// Helper to convert map key to String and tuple value to a (String, bool) map
fn map_to_string_map<K: ToString>(
    map: &BTreeMap<K, (String, bool)>,
) -> BTreeMap<String, (String, bool)> {
    map.iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect()
}

pub fn show(isis: &Isis, _args: Args, json: bool) -> String {
    if json {
        let l1 = map_to_string_map(&isis.hostname.l1.map);
        let l2 = map_to_string_map(&isis.hostname.l2.map);
        return serde_json::to_string(&serde_json::json!({
            "l1": l1,
            "l2": l2
        }))
        .unwrap();
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
        for (id, (host, originate)) in isis.hostname.get(level).map.iter() {
            let mark = if *originate { "*" } else { " " };
            writeln!(buf, "{:<5}{} {:<13} {:<15}", label, mark, id, host).unwrap();
        }
    }
    buf
}
