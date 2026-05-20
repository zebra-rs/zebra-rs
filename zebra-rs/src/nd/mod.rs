//! IPv6 Neighbor Discovery — Router Advertisement / Router Solicitation
//! transport plumbing.
//!
//! This module is the runtime counterpart to the `nd-packet` crate: it
//! brings up a raw `IPPROTO_ICMPV6` socket configured per RFC 4861
//! §6.1 (hop limit = 255 on both send and receive, ICMP6_FILTER scoped
//! to RS + RA only) and provides async read / write tasks that hand
//! parsed packets to the rest of the daemon via channels.
//!
//! Higher-level concerns (per-interface RA send state machine, RIB
//! integration, BGP unnumbered hand-off) live in follow-up PRs. The
//! scaffolding here is deliberately runtime-passive — nothing is
//! spawned from `main.rs` yet — so this PR is shippable on its own.
#![allow(dead_code)]

use std::net::Ipv6Addr;

use nd_packet::{RouterAdvert, RouterSolicit};

pub mod network;
pub mod send;
pub mod socket;

/// Inbound ND messages produced by [`network::read_packet`].
#[derive(Debug)]
pub enum NdRecv {
    RouterAdvert {
        ifindex: u32,
        src: Ipv6Addr,
        ra: RouterAdvert,
    },
    RouterSolicit {
        ifindex: u32,
        src: Ipv6Addr,
        rs: RouterSolicit,
    },
}

/// Outbound ND messages consumed by [`network::write_packet`].
#[derive(Debug)]
pub enum NdSend {
    /// Send a Router Advertisement out `ifindex` to `dst`. For an
    /// unsolicited multicast RA `dst` should be `ff02::1`; for a
    /// solicited reply, the unicast source of the RS.
    RouterAdvert {
        ifindex: u32,
        dst: Ipv6Addr,
        ra: RouterAdvert,
    },
    /// Send a Router Solicitation out `ifindex` to `ff02::2`
    /// (all-routers multicast).
    RouterSolicit { ifindex: u32, rs: RouterSolicit },
}
