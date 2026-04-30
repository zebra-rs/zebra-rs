// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2025-2026 Kunihiro Ishiguro

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use super::{Link, Rib};

fn router_id(links: &BTreeMap<u32, Link>) -> Option<Ipv4Addr> {
    fn find_router_id(links: &BTreeMap<u32, Link>, loopback: bool) -> Option<Ipv4Addr> {
        links
            .values()
            .filter(|link| link.is_loopback() == loopback)
            .flat_map(|link| &link.addr4)
            .filter_map(|laddr| match laddr.addr {
                ipnet::IpNet::V4(v4net) => Some(v4net.addr()),
                _ => None,
            })
            .find(|&addr| addr != Ipv4Addr::LOCALHOST)
    }

    // Try to find a router ID from up loopback interfaces first, then fallback
    // to non-loopback interfaces.
    find_router_id(links, true).or_else(|| find_router_id(links, false))
}

impl Rib {
    pub fn router_id_update(&mut self) {
        if let Some(router_id) = router_id(&self.links)
            && self.router_id != router_id
        {
            self.router_id = router_id;
            self.api_router_id_update(router_id);
        }
    }
}
