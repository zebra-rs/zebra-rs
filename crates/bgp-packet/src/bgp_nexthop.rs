// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2025-2026 Kunihiro Ishiguro

use std::net::{IpAddr, Ipv4Addr};

use crate::Vpnv4Nexthop;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BgpNexthop {
    Ipv4(Ipv4Addr),
    Vpnv4(Vpnv4Nexthop),
    Evpn(IpAddr),
}
