use std::collections::HashMap;

use crate::{
    bgp::packet::CommunityAttr,
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
    Community(CommunityAttr),
}

#[derive(Debug)]
pub struct Policy {
    pub clist: HashMap<String, CommunityList>,
}

// community-list hoge
// community-list hoge seq 5
// community-list hoge seq 5 action permit
// community-list hoge seq 5 member b c

pub fn config_entry(policy: &mut Policy, mut args: Args, op: ConfigOp) -> Option<()> {
    None
}

pub fn config_seq(policy: &mut Policy, mut args: Args, op: ConfigOp) -> Option<()> {
    None
}

pub fn config_action(policy: &mut Policy, mut args: Args, op: ConfigOp) -> Option<()> {
    None
}

pub fn config_member(policy: &mut Policy, mut args: Args, op: ConfigOp) -> Option<()> {
    None
}
