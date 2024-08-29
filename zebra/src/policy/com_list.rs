#![allow(dead_code)]

use std::collections::{BTreeMap, HashMap};

use crate::{
    bgp::attr::Community,
    config::{Args, ConfigOp},
};

#[derive(Debug)]
pub struct CommunityListMap(pub BTreeMap<String, CommunityList>);

impl CommunityListMap {
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }
}

impl CommunityListMap {
    pub fn get_list(&self, name: &String) -> Option<&CommunityList> {
        self.0.get(name)
    }
}

#[derive(Debug)]
pub struct CommunityList {
    name: String,
    entry: BTreeMap<u32, CommunityEntry>,
}

pub enum Action {
    Permit,
    Deny,
}

impl CommunityList {
    pub fn action_set(seq: u32, action: Action) {
        //
    }

    pub fn action_del(seq: u32) {
        //
    }

    pub fn entry_set(seq: u32) {
        //
    }

    pub fn entry_del(seq: u32) {
        //
    }
}

#[derive(Debug)]
pub struct CommunityEntry {
    seq: u32,
    member: CommunityMember,
}

#[derive(Debug)]
pub enum CommunityMember {
    Regexp(String),
    Community(Community),
}

#[derive(Debug)]
pub struct Policy {
    pub clist: HashMap<String, CommunityList>,
}

impl Policy {
    pub fn new() -> Self {
        Self {
            clist: HashMap::new(),
        }
    }
}

// community-list hoge
// community-list hoge seq 5
// community-list hoge seq 5 action permit
// community-list hoge seq 5 member 100:10 20:1

// community-list hoge {
//     seq 5 {
//         action permit;
//         member 100:10 no-export;
//         option additive;
//     }
//     seq 10 {
//         action permit;
//         member 100:10 no-export;
//         option additive;
//     }
// }

// pub fn config_add(_policy: &mut Policy, mut _args: Args, _op: ConfigOp) -> Option<()> {
//     None
// }

// pub fn config_del(_policy: &mut Policy, mut _args: Args, _op: ConfigOp) -> Option<()> {
//     None
// }

// pub fn config_seq(_policy: &mut Policy, mut _args: Args, _op: ConfigOp) -> Option<()> {
//     None
// }

// pub fn config_action(_policy: &mut Policy, mut _args: Args, _op: ConfigOp) -> Option<()> {
//     None
// }

// pub fn config_member(_policy: &mut Policy, mut _args: Args, _op: ConfigOp) -> Option<()> {
//     None
// }

// #[cfg(test)]
// mod test {
//     use super::*;

//     #[test]
//     fn clist_regexp() {
//         // When it failed, treat it as regexp.
//         let com = Community::new();
//     }
// }
