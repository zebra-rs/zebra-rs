// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2025-2026 Kunihiro Ishiguro

use std::collections::BTreeMap;

#[derive(Debug, Default, PartialEq, Clone)]
pub struct LabelBlock {
    pub start: u32,
    pub end: u32,
}

impl LabelBlock {
    pub fn new(start: u32, range: u32) -> Self {
        Self {
            start,
            end: start + range,
        }
    }
}

#[derive(Debug, Default, PartialEq, Clone)]
pub struct LabelConfig {
    pub global: LabelBlock,
    pub local: Option<LabelBlock>,
}

#[derive(Debug)]
pub struct LabelMap<T: Ord> {
    map: BTreeMap<T, LabelConfig>,
}

impl<T: Ord> Default for LabelMap<T> {
    fn default() -> Self {
        Self {
            map: BTreeMap::new(),
        }
    }
}

impl<T: Ord> LabelMap<T> {
    pub fn get(&self, key: &T) -> Option<&LabelConfig> {
        self.map.get(key)
    }

    pub fn insert(&mut self, key: T, value: LabelConfig) -> Option<LabelConfig> {
        self.map.insert(key, value)
    }

    pub fn remove(&mut self, key: &T) -> Option<LabelConfig> {
        self.map.remove(key)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&T, &LabelConfig)> {
        self.map.iter()
    }
}
