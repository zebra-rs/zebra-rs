// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2025-2026 Kunihiro Ishiguro

use std::collections::BTreeMap;

use ipnet::Ipv4Net;
use ospf_packet::ExtPrefixSubTlv;

#[derive(Default)]
pub struct ReachMap {
    map: BTreeMap<Ipv4Net, Vec<ExtPrefixSubTlv>>,
}

impl ReachMap {
    pub fn get(&self, key: &Ipv4Net) -> Option<&Vec<ExtPrefixSubTlv>> {
        self.map.get(key)
    }

    pub fn insert(
        &mut self,
        key: Ipv4Net,
        value: Vec<ExtPrefixSubTlv>,
    ) -> Option<Vec<ExtPrefixSubTlv>> {
        self.map.insert(key, value)
    }
}
