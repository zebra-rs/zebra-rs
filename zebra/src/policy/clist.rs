use std::collections::HashMap;

use crate::{
    bgp::attr::Community,
    config::{Args, ConfigOp},
};

#[derive(Debug)]
pub struct CommunityList {
    name: String,
    entry: Vec<CommunityEntry>,
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
// community-list hoge seq 5 member b c

pub fn config_entry(_policy: &mut Policy, mut _args: Args, _op: ConfigOp) -> Option<()> {
    None
}

pub fn config_seq(_policy: &mut Policy, mut _args: Args, _op: ConfigOp) -> Option<()> {
    None
}

pub fn config_action(_policy: &mut Policy, mut _args: Args, _op: ConfigOp) -> Option<()> {
    None
}

pub fn config_member(_policy: &mut Policy, mut _args: Args, _op: ConfigOp) -> Option<()> {
    None
}

// #[cfg(test)]
// mod test {
//     use super::*;

//     #[test]
//     fn clist_regexp() {
//         // When it failed, treat it as regexp.
//         let com = Community::new();
//     }
// }
