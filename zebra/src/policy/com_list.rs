#![allow(dead_code)]

use std::collections::BTreeMap;

use crate::bgp::packet::Community;
use crate::config::{Args, ConfigOp};

use super::Action;

#[derive(Debug)]
pub struct CommunityListMap(pub BTreeMap<String, CommunityList>);

impl CommunityListMap {
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }
}

impl CommunityListMap {
    pub fn ensure(&mut self, name: &str) {
        if self.lookup(name).is_some() {
            return;
        }
        let clist = CommunityList::new(name);
        self.0.insert(name.to_string(), clist);
    }

    pub fn lookup(&self, name: &str) -> Option<&CommunityList> {
        self.0.get(name)
    }

    pub fn action_test(&mut self, name: &str, seq: u32, action: Action) {
        self.ensure(name);
        let clist = self.0.get_mut(name).unwrap();
        clist.ensure(seq);
        let entry = clist.get_mut(seq).unwrap();
        entry.action = Some(action);
    }
}

#[derive(Debug)]
pub struct CommunityList {
    pub name: String,
    pub entry: BTreeMap<u32, CommunityEntry>,
}

impl CommunityList {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            entry: BTreeMap::new(),
        }
    }

    pub fn ensure(&mut self, seq: u32) {
        if self.entry.contains_key(&seq) {
            return;
        }
        let entry = CommunityEntry::new(seq);
        self.entry.insert(seq, entry);
    }

    pub fn get_mut(&mut self, seq: u32) -> Option<&mut CommunityEntry> {
        self.entry.get_mut(&seq)
    }
}

#[derive(Debug)]
pub struct CommunityEntry {
    pub seq: u32,
    pub action: Option<Action>,
    pub member: CommunityMember,
}

impl CommunityEntry {
    pub fn new(seq: u32) -> Self {
        Self {
            seq,
            action: None,
            member: CommunityMember::None,
        }
    }
}

#[derive(Debug)]
pub enum CommunityMember {
    None,
    Regexp(String),
    Community(Community),
}

pub fn config_com_list(clist: &mut CommunityListMap, mut args: Args, _op: ConfigOp) -> Option<()> {
    if let Some(name) = args.string() {
        clist.ensure(&name);
    }
    Some(())
}

pub fn config_com_list_seq(
    clist: &mut CommunityListMap,
    mut args: Args,
    _op: ConfigOp,
) -> Option<()> {
    if let Some(name) = args.string() {
        clist.ensure(&name);
        let clist = clist.0.get_mut(&name).unwrap();
        if let Some(seq) = args.u32() {
            clist.ensure(seq);
        }
    }
    Some(())
}

pub fn config_com_list_action(
    clist: &mut CommunityListMap,
    mut args: Args,
    _op: ConfigOp,
) -> Option<()> {
    if let Some(name) = args.string() {
        clist.ensure(&name);
        let clist = clist.0.get_mut(&name).unwrap();
        if let Some(seq) = args.u32() {
            clist.ensure(seq);
            if let Some(action) = args.string() {
                let entry = clist.get_mut(seq).unwrap();
                if action == "permit" {
                    entry.action = Some(Action::Permit);
                } else {
                    entry.action = Some(Action::Deny);
                }
            }
        }
    }
    Some(())
}
