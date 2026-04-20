// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2025-2026 Kunihiro Ishiguro

use std::collections::BTreeMap;

use crate::config::{Args, ConfigOp};

use super::Action;

#[derive(Debug, Default)]
pub struct CommunityListMap(pub BTreeMap<String, CommunityList>);

impl CommunityListMap {
    pub fn ensure(&mut self, name: &str) {
        if self.lookup(name).is_some() {
            return;
        }
        let clist = CommunityList::new();
        self.0.insert(name.to_string(), clist);
    }

    pub fn lookup(&self, name: &str) -> Option<&CommunityList> {
        self.0.get(name)
    }
}

#[derive(Debug)]
pub struct CommunityList {
    pub entry: BTreeMap<u32, CommunityEntry>,
}

impl CommunityList {
    pub fn new() -> Self {
        Self {
            entry: BTreeMap::new(),
        }
    }

    pub fn ensure(&mut self, seq: u32) {
        if self.entry.contains_key(&seq) {
            return;
        }
        let entry = CommunityEntry::new();
        self.entry.insert(seq, entry);
    }

    pub fn get_mut(&mut self, seq: u32) -> Option<&mut CommunityEntry> {
        self.entry.get_mut(&seq)
    }
}

#[derive(Debug)]
pub struct CommunityEntry {
    pub action: Option<Action>,
}

impl CommunityEntry {
    pub fn new() -> Self {
        Self { action: None }
    }
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
