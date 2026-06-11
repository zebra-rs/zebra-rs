//! IPv6 Neighbor Discovery — Router Advertisement / Router Solicitation
//! transport plumbing.
//!
//! This module is the runtime counterpart to the `nd-packet` crate: it
//! brings up a raw `IPPROTO_ICMPV6` socket configured per RFC 4861
//! §6.1 (hop limit = 255 on both send and receive, ICMP6_FILTER scoped
//! to RS + RA + NS + NA) and provides async read / write tasks that
//! hand parsed packets to the rest of the daemon via channels.
//!
//! NS (135) and NA (136) are passively observed for counters and
//! diagnostics; the host kernel still owns the NDP cache.
//!
//! Higher-level concerns (per-interface RA send state machine, RIB
//! integration, BGP unnumbered hand-off) live in follow-up PRs. The
//! scaffolding here is deliberately runtime-passive — nothing is
//! spawned from `main.rs` yet — so this PR is shippable on its own.
#![allow(dead_code)]

use std::net::Ipv6Addr;

use nd_packet::{NeighborAdvert, NeighborSolicit, RouterAdvert, RouterSolicit};

pub mod config;
pub mod engine;
pub mod inst;
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
    NeighborSolicit {
        ifindex: u32,
        src: Ipv6Addr,
        ns: NeighborSolicit,
    },
    NeighborAdvert {
        ifindex: u32,
        src: Ipv6Addr,
        na: NeighborAdvert,
    },
    /// A packet failed RFC 4861 receive validation (hop-limit ≠ 255 or
    /// malformed payload) and was dropped. Carried up so the engine can
    /// count drops per interface without touching any atomics in the I/O
    /// task.
    Dropped { ifindex: u32, reason: DropReason },
}

/// Reason a received ICMPv6 ND packet was discarded before delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    /// IPv6 hop limit was not 255 — RFC 4861 §6.1.2 MUST silently
    /// discard.
    HopLimit,
    /// Packet was too short, had a non-zero ICMPv6 code, or an option
    /// was malformed.
    Malformed,
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
